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
                    // SDKResultSuccess can finish this turn while announcing
                    // queued user work. Only a later result with no queued work
                    // can complete the run. Older producers omit this field.
                    let queued = match event.get("queued_turn_count") {
                        None => Some(0),
                        Some(value) => value.as_u64(),
                    };
                    if queued.is_none() {
                        self.malformed = true;
                    }
                    match (
                        event.get("subtype").and_then(Value::as_str),
                        event.get("is_error").and_then(Value::as_bool),
                    ) {
                        (Some("success"), Some(false)) => {
                            self.final_turn_completed = queued == Some(0)
                        }
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
                if claude_failure(kind, &event) {
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
/// CLI schema do not start work. Reporting can preserve completion, never create
/// it. Progress, compaction and live nonambient tasks still require a result.
/// SDKResultMessage and SDKSessionStateChangedMessage in Anthropic's SDK 0.3.301
/// explicitly allow informational messages after the turn's terminal result.
/// Unlike the SDK's generic ignore-unknown advice, this unattended runner treats
/// unknown trailing types/subtypes as activity until their meaning is supported.
fn claude_metadata(kind: &str, event: &Value) -> bool {
    match kind {
        "keep_alive" | "rate_limit_event" | "tool_use_summary" => true,
        "active_goal" => event.get("value") == Some(&Value::Null),
        "prompt_suggestion" => event.get("suggestion").is_some_and(Value::is_string),
        "auth_status" => {
            event.get("isAuthenticating") == Some(&Value::Bool(false))
                && event
                    .get("output")
                    .and_then(Value::as_array)
                    .is_some_and(|lines| lines.iter().all(Value::is_string))
                && event.get("error").is_none()
        }
        "system" => match event.get("subtype").and_then(Value::as_str) {
            Some("post_turn_summary") => true,
            Some("informational") => {
                // prevent_continuation is a controlled stop, not an error. It
                // cannot clear queued/unfinished work or synthesize completion.
                matches!(
                    event.get("level").and_then(Value::as_str),
                    Some("info" | "notice" | "suggestion" | "warning")
                ) && string_fields(event, &["content"])
                    && event
                        .get("prevent_continuation")
                        .is_none_or(Value::is_boolean)
                    && ["tag", "tool_use_id"]
                        .iter()
                        .all(|field| event.get(*field).is_none_or(Value::is_string))
            }
            Some("local_command_output") => string_fields(event, &["content"]),
            Some("notification") => {
                string_fields(event, &["key", "text"])
                    && matches!(
                        event.get("priority").and_then(Value::as_str),
                        Some("low" | "medium" | "high" | "immediate")
                    )
            }
            Some("commands_changed") => event.get("commands").is_some_and(Value::is_array),
            Some("worker_shutting_down") => string_fields(event, &["reason"]),
            Some("plugin_install") => {
                event.get("status").and_then(Value::as_str) == Some("completed")
                    && event.get("error").is_none()
            }
            Some("elicitation_complete") => {
                string_fields(event, &["mcp_server_name", "elicitation_id"])
            }
            Some("hook_response") => {
                string_fields(
                    event,
                    &[
                        "hook_id",
                        "hook_name",
                        "hook_event",
                        "output",
                        "stdout",
                        "stderr",
                    ],
                ) && event.get("outcome").and_then(Value::as_str) == Some("success")
                    && event
                        .get("exit_code")
                        .is_none_or(|value| value.as_i64() == Some(0))
            }
            Some("files_persisted") => {
                string_fields(event, &["processed_at"])
                    && event
                        .get("files")
                        .and_then(Value::as_array)
                        .is_some_and(|files| {
                            files
                                .iter()
                                .all(|file| string_fields(file, &["filename", "file_id"]))
                        })
                    && event
                        .get("failed")
                        .and_then(Value::as_array)
                        .is_some_and(Vec::is_empty)
            }
            Some("background_tasks_changed") => event
                .get("tasks")
                .and_then(Value::as_array)
                .is_some_and(|tasks| {
                    tasks.iter().all(|task| {
                        string_fields(task, &["task_id", "task_type", "description"])
                            && task.get("ambient") == Some(&Value::Bool(true))
                    })
                }),
            Some("task_updated") => {
                string_fields(event, &["task_id"])
                    && event.get("patch").is_some_and(|patch| {
                        patch.is_object()
                            && patch.get("status").is_none_or(|status| {
                                matches!(status.as_str(), Some("completed" | "failed" | "killed"))
                            })
                    })
            }
            Some("status") => event.get("status") == Some(&Value::Null),
            Some("session_state_changed") => {
                event.get("state").and_then(Value::as_str) == Some("idle")
            }
            Some("task_notification") => {
                // A notification reports a separate task's terminal outcome; it
                // neither starts nor completes the main conversation's turn.
                matches!(
                    event.get("status").and_then(Value::as_str),
                    Some("completed" | "failed" | "stopped")
                ) && ["task_id", "output_file", "summary"]
                    .iter()
                    .all(|field| event.get(*field).is_some_and(Value::is_string))
            }
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

fn string_fields(event: &Value, fields: &[&str]) -> bool {
    fields
        .iter()
        .all(|field| event.get(*field).is_some_and(Value::is_string))
}

/// MaxIO conservatively retains explicit local-operation failure evidence even
/// if a later main-turn result succeeds. The SDK describes those outcomes, but
/// does not itself require this whole-execution failure policy. Separate-task
/// notifications/patches retain their own outcome without failing the main turn.
fn claude_failure(kind: &str, event: &Value) -> bool {
    match kind {
        "error" => true,
        "auth_status" => event.get("error").is_some_and(Value::is_string),
        "system" => match event.get("subtype").and_then(Value::as_str) {
            Some("api_error") => true,
            Some("hook_response") => {
                matches!(
                    event.get("outcome").and_then(Value::as_str),
                    Some("error" | "cancelled")
                ) || event
                    .get("exit_code")
                    .and_then(Value::as_i64)
                    .is_some_and(|code| code != 0)
            }
            Some("files_persisted") => event
                .get("failed")
                .and_then(Value::as_array)
                .is_some_and(|files| !files.is_empty()),
            Some("plugin_install") => {
                event.get("status").and_then(Value::as_str) == Some("failed")
                    || event.get("error").is_some_and(Value::is_string)
            }
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
    fn claude_documented_reporting_tails_preserve_completed_turn() {
        for metadata in [
            serde_json::json!({"type":"system","subtype":"informational","level":"info","content":"Completed work"}),
            serde_json::json!({"type":"keep_alive"}),
        ] {
            let mut state = Capture::default();
            state.event(
                AdapterKind::Claude,
                br#"{"type":"result","subtype":"success","is_error":false,"queued_turn_count":0}"#,
            );
            state.event(AdapterKind::Claude, metadata.to_string().as_bytes());
            assert!(
                state.final_turn_completed,
                "a documented reporting tail must preserve completion: {metadata}"
            );
        }
    }

    #[test]
    fn claude_explicit_reporting_failures_remain_sticky() {
        for failure in [
            serde_json::json!({"type":"auth_status","isAuthenticating":false,"output":[],"error":"Authentication failed"}),
            serde_json::json!({"type":"system","subtype":"hook_response","outcome":"error"}),
            serde_json::json!({"type":"system","subtype":"hook_response","outcome":"cancelled"}),
            serde_json::json!({"type":"system","subtype":"hook_response","outcome":"success","exit_code":1}),
            serde_json::json!({"type":"system","subtype":"files_persisted","failed":[{"filename":"result.txt","error":"Upload failed"}]}),
            serde_json::json!({"type":"system","subtype":"plugin_install","status":"failed","error":"Install failed"}),
        ] {
            let mut state = Capture::default();
            state.event(AdapterKind::Claude, failure.to_string().as_bytes());
            state.event(
                AdapterKind::Claude,
                br#"{"type":"result","subtype":"success","is_error":false,"queued_turn_count":0}"#,
            );
            state.event(AdapterKind::Claude, br#"{"type":"keep_alive"}"#);
            assert!(state.failed, "later completion cannot erase {failure}");
        }
    }

    #[test]
    fn claude_idle_after_a_result_preserves_turn_completion() {
        let mut state = Capture::default();
        state.event(
            AdapterKind::Claude,
            br#"{"type":"result","subtype":"success","is_error":false}"#,
        );
        state.event(
            AdapterKind::Claude,
            br#"{"type":"system","subtype":"session_state_changed","state":"idle"}"#,
        );
        assert!(
            state.final_turn_completed,
            "the SDK emits idle after flushing the completed turn's result"
        );
    }

    #[test]
    fn claude_queued_turns_require_a_later_terminal_result() {
        let success = br#"{"type":"result","subtype":"success","is_error":false}"#;
        let idle = br#"{"type":"system","subtype":"session_state_changed","state":"idle"}"#;
        for count in [1, 2] {
            let mut state = Capture::default();
            state.event(AdapterKind::Claude, success);
            state.event(
                AdapterKind::Claude,
                serde_json::json!({"type":"result","subtype":"success","is_error":false,"queued_turn_count":count})
                    .to_string()
                    .as_bytes(),
            );
            assert!(
                !state.final_turn_completed,
                "a result with {count} queued turns cannot complete the run"
            );
            state.event(AdapterKind::Claude, idle);
            assert!(
                !state.final_turn_completed,
                "idle cannot finish queued work"
            );
            state.event(
                AdapterKind::Claude,
                br#"{"type":"result","subtype":"success","is_error":false,"queued_turn_count":0}"#,
            );
            assert!(state.final_turn_completed && !state.malformed);
        }
    }

    #[test]
    fn claude_invalid_present_queued_count_is_malformed() {
        for count in [
            serde_json::json!(-1),
            serde_json::json!(0.5),
            serde_json::json!("0"),
            serde_json::json!(null),
            serde_json::json!(false),
            serde_json::json!([]),
            serde_json::json!({}),
        ] {
            let mut state = Capture::default();
            state.event(
                AdapterKind::Claude,
                serde_json::json!({"type":"result","subtype":"success","is_error":false,"queued_turn_count":count})
                    .to_string()
                    .as_bytes(),
            );
            assert!(
                state.malformed && !state.final_turn_completed,
                "invalid queued_turn_count must be rejected: {count}"
            );
            state.event(
                AdapterKind::Claude,
                br#"{"type":"result","subtype":"success","is_error":false}"#,
            );
            assert!(
                state.malformed,
                "a later result cannot erase malformed input"
            );
        }
    }

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
            serde_json::json!({"type":"system","subtype":"status","status":"requesting"}),
            serde_json::json!({"type":"system","subtype":"session_state_changed","state":"running"}),
            serde_json::json!({"type":"system","subtype":"session_state_changed","state":"requires_action"}),
            serde_json::json!({"type":"system","subtype":"session_state_changed","state":"future_state"}),
            serde_json::json!({"type":"system","subtype":"task_started","task_id":"task-1"}),
            serde_json::json!({"type":"system","subtype":"task_progress","task_id":"task-1"}),
            serde_json::json!({"type":"system","subtype":"thinking_tokens","count":5}),
            serde_json::json!({"type":"active_goal","value":{"condition":"Continue working"}}),
            serde_json::json!({"type":"active_goal"}),
            serde_json::json!({"type":"active_goal","value":false}),
            serde_json::json!({"type":"system","subtype":"control_request_progress"}),
            serde_json::json!({"type":"system","subtype":"hook_started","hook_id":"hook-1"}),
            serde_json::json!({"type":"system","subtype":"hook_progress","hook_id":"hook-1"}),
            serde_json::json!({"type":"system","subtype":"plugin_install","status":"started"}),
            serde_json::json!({"type":"system","subtype":"plugin_install","status":"installed","name":"example"}),
            serde_json::json!({"type":"system","subtype":"task_updated","task_id":"task-1","patch":{"status":"pending"}}),
            serde_json::json!({"type":"system","subtype":"task_updated","task_id":"task-1","patch":{"status":"running"}}),
            serde_json::json!({"type":"system","subtype":"task_updated","task_id":"task-1","patch":{"status":"paused"}}),
            serde_json::json!({"type":"auth_status","isAuthenticating":true,"output":[]}),
            serde_json::json!({"type":"system","subtype":"background_tasks_changed","tasks":[{"task_id":"task-1","task_type":"local_agent","description":"Still working"}]}),
            serde_json::json!({"type":"system","subtype":"informational","level":"info","content":"Invalid flag","prevent_continuation":"false"}),
            serde_json::json!({"type":"system","subtype":"informational","level":"future_level","content":"Unknown level"}),
            serde_json::json!({"type":"system","subtype":"informational","level":"info","content":null}),
            serde_json::json!({"type":"system","subtype":"notification","key":"notice","text":"Unknown priority","priority":"future_priority"}),
            serde_json::json!({"type":"system","subtype":"task_notification","status":"future_status","task_id":"task-1","output_file":"task.log","summary":"Unknown"}),
            serde_json::json!({"type":"prompt_suggestion","suggestion":null}),
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
            serde_json::json!({"type":"keep_alive"}),
            serde_json::json!({"type":"active_goal","value":null}),
            serde_json::json!({"type":"system","subtype":"informational","level":"info","content":"Information"}),
            serde_json::json!({"type":"system","subtype":"informational","level":"notice","content":"Notice","prevent_continuation":false}),
            serde_json::json!({"type":"system","subtype":"informational","level":"suggestion","content":"Suggestion","tag":"unknown-feature","tool_use_id":"tool-1"}),
            serde_json::json!({"type":"system","subtype":"informational","level":"warning","content":"Controlled stop","prevent_continuation":true}),
            serde_json::json!({"type":"system","subtype":"local_command_output","content":"Usage summary"}),
            serde_json::json!({"type":"system","subtype":"notification","key":"notice","text":"Completed","priority":"high"}),
            serde_json::json!({"type":"system","subtype":"commands_changed","commands":[]}),
            serde_json::json!({"type":"system","subtype":"worker_shutting_down","reason":"Worker replacement"}),
            serde_json::json!({"type":"system","subtype":"plugin_install","status":"completed"}),
            serde_json::json!({"type":"system","subtype":"task_updated","task_id":"task-1","patch":{"description":"Renamed task"}}),
            serde_json::json!({"type":"system","subtype":"task_updated","task_id":"task-1","patch":{"status":"completed"}}),
            serde_json::json!({"type":"system","subtype":"task_updated","task_id":"task-1","patch":{"status":"failed","error":"Separate task failed"}}),
            serde_json::json!({"type":"system","subtype":"task_updated","task_id":"task-1","patch":{"status":"killed"}}),
            serde_json::json!({"type":"auth_status","isAuthenticating":false,"output":[]}),
            serde_json::json!({"type":"system","subtype":"hook_response","hook_id":"hook-1","hook_name":"Stop","hook_event":"Stop","output":"","stdout":"","stderr":"","outcome":"success","exit_code":0}),
            serde_json::json!({"type":"system","subtype":"files_persisted","files":[{"filename":"result.txt","file_id":"file-1"}],"failed":[],"processed_at":"2026-10-23T00:00:00Z"}),
            serde_json::json!({"type":"system","subtype":"elicitation_complete","mcp_server_name":"example","elicitation_id":"elicitation-1"}),
            serde_json::json!({"type":"system","subtype":"background_tasks_changed","tasks":[]}),
            serde_json::json!({"type":"system","subtype":"background_tasks_changed","tasks":[{"task_id":"task-1","task_type":"local_agent","description":"Ambient watcher","ambient":true}]}),
            serde_json::json!({"type":"rate_limit_event","rate_limit_info":{"status":"allowed"}}),
            serde_json::json!({"type":"tool_use_summary","summary":"Finished reading","preceding_tool_use_ids":["tool-1"]}),
            serde_json::json!({"type":"system","subtype":"post_turn_summary","summarizes_uuid":"message-1"}),
            serde_json::json!({"type":"system","subtype":"status","status":null}),
            serde_json::json!({"type":"system","subtype":"session_state_changed","state":"idle"}),
            serde_json::json!({"type":"prompt_suggestion","suggestion":"Inspect the result"}),
            serde_json::json!({"type":"system","subtype":"task_notification","task_id":"task-1","status":"completed","output_file":"task.log","summary":"Task ended"}),
            serde_json::json!({"type":"system","subtype":"task_notification","task_id":"task-1","status":"failed","output_file":"task.log","summary":"Background task failed"}),
            serde_json::json!({"type":"system","subtype":"task_notification","task_id":"task-1","status":"stopped","output_file":"task.log","summary":"Background task stopped"}),
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
            state.event(
                AdapterKind::Claude,
                br#"{"type":"result","subtype":"success","is_error":false,"queued_turn_count":1}"#,
            );
            state.event(AdapterKind::Claude, bytes.as_bytes());
            assert!(
                !state.final_turn_completed,
                "reporting metadata must not complete queued work: {metadata}"
            );
            state.event(
                AdapterKind::Claude,
                br#"{"type":"result","subtype":"success","is_error":false}"#,
            );
            state.event(
                AdapterKind::Claude,
                br#"{"type":"assistant","message":{"role":"assistant","content":[]}}"#,
            );
            state.event(AdapterKind::Claude, bytes.as_bytes());
            assert!(
                !state.final_turn_completed,
                "metadata must not complete unfinished later work: {metadata}"
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
