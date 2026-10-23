use super::super::contract::AdapterKind;
use anyhow::Result;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

pub(super) const LOG_LIMIT: usize = 4 * 1024 * 1024;
const LINE_LIMIT: usize = 1024 * 1024;

#[derive(Default)]
pub(super) struct Capture {
    pub session: Option<String>,
    // Only the final active turn can authorize success. Error/denial flags below
    // remain sticky across turns, so later success cannot erase earlier failure.
    pub final_turn_completed: bool,
    pub failed: bool,
    pub denied: bool,
    pub malformed: bool,
    pub truncated: bool,
}

impl Capture {
    fn event(&mut self, adapter: AdapterKind, bytes: &[u8]) {
        if adapter == AdapterKind::Command {
            return;
        }
        let Ok(event) = serde_json::from_slice::<Value>(bytes) else {
            self.malformed = true;
            return;
        };
        let Some(kind) = event.get("type").and_then(Value::as_str) else {
            self.malformed = true;
            return;
        };
        let session = match adapter {
            AdapterKind::Codex if kind == "thread.started" => event.get("thread_id"),
            AdapterKind::Claude => event.get("session_id"),
            _ => None,
        };
        if let Some(session) = session {
            if let Some(session) = session.as_str().filter(|value| {
                !value.is_empty()
                    && value.len() <= 256
                    && value
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
            }) {
                if self
                    .session
                    .as_ref()
                    .is_some_and(|previous| previous != session)
                {
                    self.malformed = true;
                } else {
                    self.session = Some(session.into());
                }
            } else {
                self.malformed = true;
            }
        }
        match adapter {
            AdapterKind::Codex => {
                // Codex documents turn/item events, but no trailing reporting-only
                // events. New or unknown activity needs a subsequent terminal.
                self.final_turn_completed = kind == "turn.completed";
                if matches!(kind, "turn.failed" | "error") {
                    self.failed = true;
                }
            }
            AdapterKind::Claude => {
                if kind == "result" {
                    self.final_turn_completed = false;
                    match (
                        event.get("subtype").and_then(Value::as_str),
                        event.get("is_error").and_then(Value::as_bool),
                    ) {
                        (Some("success"), Some(false)) => self.final_turn_completed = true,
                        (Some(_), Some(_)) => self.failed = true,
                        _ => self.malformed = true,
                    }
                    if event
                        .get("permission_denials")
                        .and_then(Value::as_array)
                        .is_some_and(|denials| !denials.is_empty())
                    {
                        self.denied = true;
                    }
                } else if !claude_metadata(kind, &event) {
                    // Assistant/user/tool/partial-stream events may follow an
                    // earlier result (for example another background-work turn).
                    // Unknown events are retained but cannot preserve success.
                    self.final_turn_completed = false;
                }
                if kind == "error"
                    || (kind == "system"
                        && event.get("subtype").and_then(Value::as_str) == Some("api_error"))
                {
                    self.failed = true;
                }
                if kind == "system"
                    && event.get("subtype").and_then(Value::as_str) == Some("permission_denied")
                {
                    self.denied = true;
                }
            }
            AdapterKind::Command => {}
        }
    }
}

/// Reporting events documented by the Claude SDK or present in the installed
/// CLI schema do not start work. Keep this allowlist narrow: summaries and idle
/// status are metadata, but tool progress, compaction and pending tasks are not.
fn claude_metadata(kind: &str, event: &Value) -> bool {
    match kind {
        "rate_limit_event" | "tool_use_summary" => true,
        "system" => match event.get("subtype").and_then(Value::as_str) {
            Some("post_turn_summary") => true,
            Some("status") => event.get("status") == Some(&Value::Null),
            Some("turn_duration") => ["pending_background_agent_count", "pending_workflow_count"]
                .iter()
                .all(|field| {
                    event
                        .get(*field)
                        .is_none_or(|value| value.as_u64() == Some(0))
                }),
            _ => false,
        },
        _ => false,
    }
}

/// The caller owns a trusted executable. Redaction prevents straightforward
/// accidental credential echo; it cannot detect encoded secrets or arbitrary
/// task data. Logs are private retained task artifacts, not safe-to-share output.
pub(super) async fn capture(
    mut reader: impl AsyncRead + Unpin,
    file: std::fs::File,
    adapter: AdapterKind,
    secrets: &[String],
) -> Result<Capture> {
    let mut log = tokio::fs::File::from_std(file);
    let mut state = Capture::default();
    let mut pending = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut written = 0;
    let mut dropping_line = false;
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        for byte in &buffer[..read] {
            if dropping_line {
                if *byte == b'\n' {
                    dropping_line = false;
                }
                continue;
            }
            pending.push(*byte);
            if pending.len() > LINE_LIMIT {
                state.truncated = true;
                state.malformed |= adapter != AdapterKind::Command;
                pending.clear();
                dropping_line = *byte != b'\n';
                continue;
            }
            if *byte == b'\n' {
                state.event(adapter, &pending);
                write_line(&mut log, &pending, secrets, &mut written, &mut state).await?;
                pending.clear();
            }
        }
    }
    if !pending.is_empty() {
        state.event(adapter, &pending);
        write_line(&mut log, &pending, secrets, &mut written, &mut state).await?;
    }
    log.flush().await?;
    log.sync_all().await?;
    Ok(state)
}

async fn write_line(
    log: &mut tokio::fs::File,
    bytes: &[u8],
    secrets: &[String],
    written: &mut usize,
    state: &mut Capture,
) -> Result<()> {
    let mut text = String::from_utf8_lossy(bytes).into_owned();
    for value in secrets {
        if !value.is_empty() {
            text = text.replace(value, "[REDACTED]");
        }
    }
    let take = (LOG_LIMIT - *written).min(text.len());
    log.write_all(&text.as_bytes()[..take]).await?;
    *written += take;
    state.truncated |= take < text.len();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_codex_turn_requires_its_own_terminal_result() {
        for activity in [
            "turn.started",
            "item.started",
            "item.updated",
            "item.completed",
            "future.event",
        ] {
            let mut state = Capture::default();
            state.event(AdapterKind::Codex, br#"{"type":"turn.completed"}"#);
            state.event(
                AdapterKind::Codex,
                serde_json::json!({"type": activity}).to_string().as_bytes(),
            );
            assert!(
                !state.final_turn_completed,
                "an earlier turn cannot complete later {activity}"
            );
            state.event(AdapterKind::Codex, br#"{"type":"turn.completed"}"#);
            assert!(state.final_turn_completed);
        }
    }

    #[test]
    fn a_new_claude_assistant_requires_its_own_terminal_result() {
        for activity in [
            serde_json::json!({"type":"assistant","message":{"role":"assistant","content":[]}}),
            serde_json::json!({"type":"user"}),
            serde_json::json!({"type":"tool_progress"}),
            serde_json::json!({"type":"stream_event","event":{"type":"message_start"}}),
            serde_json::json!({"type":"stream_event","event":{"type":"message_stop"}}),
            serde_json::json!({"type":"system","subtype":"api_retry"}),
            serde_json::json!({"type":"system","subtype":"status","status":"compacting"}),
            serde_json::json!({"type":"system","subtype":"turn_duration","pending_background_agent_count":1}),
            serde_json::json!({"type":"system","subtype":"turn_duration","pending_workflow_count":1}),
            serde_json::json!({"type":"future.event"}),
        ] {
            let mut state = Capture::default();
            let terminal = br#"{"type":"result","subtype":"success","is_error":false}"#;
            state.event(AdapterKind::Claude, terminal);
            state.event(AdapterKind::Claude, activity.to_string().as_bytes());
            assert!(
                !state.final_turn_completed,
                "an earlier result cannot complete later {activity}"
            );
            state.event(AdapterKind::Claude, terminal);
            assert!(state.final_turn_completed);
        }
    }

    #[test]
    fn reporting_metadata_neither_starts_nor_completes_a_claude_turn() {
        for metadata in [
            serde_json::json!({"type":"rate_limit_event","rate_limit_info":{"status":"allowed"}}),
            serde_json::json!({"type":"tool_use_summary","summary":"Finished reading","preceding_tool_use_ids":["tool-1"]}),
            serde_json::json!({"type":"system","subtype":"post_turn_summary","summarizes_uuid":"message-1"}),
            serde_json::json!({"type":"system","subtype":"status","status":null}),
            serde_json::json!({"type":"system","subtype":"turn_duration","duration_ms":1,"pending_background_agent_count":0,"pending_workflow_count":0}),
        ] {
            let mut state = Capture::default();
            let bytes = metadata.to_string();
            state.event(AdapterKind::Claude, bytes.as_bytes());
            assert!(
                !state.final_turn_completed,
                "metadata is not a terminal result: {metadata}"
            );
            state.event(
                AdapterKind::Claude,
                br#"{"type":"result","subtype":"success","is_error":false}"#,
            );
            state.event(AdapterKind::Claude, bytes.as_bytes());
            assert!(
                state.final_turn_completed,
                "reporting metadata must not create a new turn: {metadata}"
            );
        }
    }

    #[tokio::test]
    async fn terminal_errors_override_completed_and_secrets_are_redacted() {
        let temp = tempfile::tempdir().unwrap();
        let data = b"{\"type\":\"turn.completed\"}\n{\"type\":\"error\",\"message\":\"secret-credential\"}\n";
        let path = temp.path().join("output.log");
        let result = capture(
            &data[..],
            crate::files::new_file(&path).unwrap(),
            AdapterKind::Codex,
            &["secret-credential".into()],
        )
        .await
        .unwrap();
        assert!(!result.final_turn_completed && result.failed);
        assert!(
            !std::fs::read_to_string(path)
                .unwrap()
                .contains("secret-credential")
        );
    }

    #[tokio::test]
    async fn a_success_subtype_with_error_is_not_success() {
        let temp = tempfile::tempdir().unwrap();
        let data = b"{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":true}\n";
        let result = capture(
            &data[..],
            crate::files::new_file(&temp.path().join("output.log")).unwrap(),
            AdapterKind::Claude,
            &[],
        )
        .await
        .unwrap();
        assert!(result.failed && !result.final_turn_completed);
    }

    #[tokio::test]
    async fn logs_and_unterminated_lines_are_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let data = vec![b'x'; LINE_LIMIT + 100];
        let path = temp.path().join("output.log");
        let result = capture(
            &data[..],
            crate::files::new_file(&path).unwrap(),
            AdapterKind::Codex,
            &[],
        )
        .await
        .unwrap();
        assert!(result.truncated && result.malformed);
        assert!(std::fs::metadata(path).unwrap().len() <= LOG_LIMIT as u64);
    }
}
