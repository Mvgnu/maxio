use super::super::contract::{AdapterKind, PermissionMode, RunRequest};
use anyhow::{Result, ensure};
use std::collections::BTreeMap;
use std::path::Path;

pub(super) fn validate_environment(request: &RunRequest, source: &Path) -> Result<Vec<String>> {
    let mut secrets = Vec::new();
    for (name, value) in &request.environment {
        ensure!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
                && !name.as_bytes()[0].is_ascii_digit(),
            "invalid environment name"
        );
        ensure!(
            value.len() <= 16384 && !value.chars().any(char::is_control),
            "environment value contains controls or exceeds 16 KiB"
        );
        ensure!(
            !name.starts_with("MAXIO_")
                && !name.starts_with("AWS_")
                && !name.starts_with("S3_")
                && !name.starts_with("MINIO_")
                && !name.starts_with("R2_")
                && !name.starts_with("B2_")
                && !name.starts_with("RCLONE_")
                && !name.contains("STORAGE")
                && !matches!(
                    name.as_str(),
                    "GOOGLE_APPLICATION_CREDENTIALS" | "AZURE_CLIENT_SECRET"
                ),
            "storage credentials and configuration cannot be passed to execution"
        );
        ensure!(
            !matches!(
                name.as_str(),
                "HOME" | "PWD" | "TMPDIR" | "TMP" | "TEMP" | "SHELL" | "BASH_ENV" | "ENV"
            ) && !name.starts_with("LD_")
                && !name.starts_with("DYLD_")
                && !name.starts_with("PYTHON"),
            "runtime environment override is not supported"
        );
        let allowed = match request.adapter {
            AdapterKind::Codex => matches!(
                name.as_str(),
                "CODEX_HOME" | "CODEX_API_KEY" | "OPENAI_API_KEY" | "PATH"
            ),
            AdapterKind::Claude => matches!(
                name.as_str(),
                "CLAUDE_CONFIG_DIR" | "ANTHROPIC_API_KEY" | "CLAUDE_CODE_OAUTH_TOKEN" | "PATH"
            ),
            AdapterKind::Command => {
                !name.starts_with("CODEX_")
                    && !name.starts_with("CLAUDE_")
                    && !name.starts_with("ANTHROPIC_")
                    && !name.starts_with("OPENAI_")
            }
        };
        ensure!(
            allowed,
            "environment variable is not allowed by the selected adapter: {name}"
        );
        if matches!(name.as_str(), "CODEX_HOME" | "CLAUDE_CONFIG_DIR") {
            let home = super::files::root(Path::new(value))?;
            ensure!(
                !home.starts_with(source) && !source.starts_with(&home),
                "provider credential directory and source tree must be separate"
            );
        } else if name != "PATH" && !value.is_empty() {
            secrets.push(value.clone());
        }
    }
    if request.adapter != AdapterKind::Command {
        ensure!(
            request.args.is_empty(),
            "provider adapters do not accept arbitrary command-line flags"
        );
        ensure!(
            request
                .prompt
                .as_ref()
                .is_some_and(|value| !value.trim().is_empty()),
            "provider execution requires a nonempty prompt"
        );
        ensure!(
            request
                .prompt
                .as_ref()
                .is_none_or(|value| value.len() <= 1024 * 1024),
            "provider prompt exceeds 1 MiB"
        );
        let home_name = match request.adapter {
            AdapterKind::Codex => "CODEX_HOME",
            AdapterKind::Claude => "CLAUDE_CONFIG_DIR",
            AdapterKind::Command => unreachable!(),
        };
        let credential_name = match request.adapter {
            AdapterKind::Codex => ["CODEX_API_KEY", "OPENAI_API_KEY"].as_slice(),
            AdapterKind::Claude => ["ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"].as_slice(),
            AdapterKind::Command => &[],
        };
        ensure!(
            request.environment.contains_key(home_name)
                || credential_name
                    .iter()
                    .any(|name| request.environment.contains_key(*name)),
            "provider execution requires an explicit provider home or selected credential variable"
        );
    }
    secrets.sort_by_key(|value| std::cmp::Reverse(value.len()));
    Ok(secrets)
}

pub(super) fn argv(request: &RunRequest, workspace: &Path) -> Vec<String> {
    match request.adapter {
        AdapterKind::Command => request.args.clone(),
        AdapterKind::Codex => vec![
            "--ask-for-approval".into(),
            "never".into(),
            "exec".into(),
            "--sandbox".into(),
            match request.permission {
                PermissionMode::ReadOnly => "read-only",
                PermissionMode::WorkspaceWrite => "workspace-write",
            }
            .into(),
            "--json".into(),
            "--color".into(),
            "never".into(),
            "--cd".into(),
            workspace.to_string_lossy().into_owned(),
            // Inputs are deliberately copied without Git internals. This is a
            // fresh, owner-selected task directory, not a source checkout.
            "--skip-git-repo-check".into(),
            "-".into(),
        ],
        AdapterKind::Claude => {
            let mut arguments: Vec<String> = [
                "--restricted",
                "--print",
                "--output-format",
                "stream-json",
                "--verbose",
                "--permission-mode",
                "dontAsk",
                "--permission-prompts",
                "none",
                "--disallowedTools",
                "mcp__*",
                "--tools",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect();
            arguments.push(
                match request.permission {
                    PermissionMode::ReadOnly => "Read,Glob,Grep",
                    PermissionMode::WorkspaceWrite => "Read,Glob,Grep,Edit,Write",
                }
                .into(),
            );
            if request.permission == PermissionMode::WorkspaceWrite {
                arguments.extend(["--allowedTools".into(), "Read,Edit,Write".into()]);
            }
            arguments
        }
    }
}

pub(super) fn capabilities(adapter: AdapterKind, version: &str, help: &str) -> Result<()> {
    let required: &[&str] = match adapter {
        AdapterKind::Command => &[],
        AdapterKind::Codex => &[
            "--ask-for-approval",
            "never",
            "--sandbox",
            "read-only",
            "workspace-write",
            "--json",
            "--cd",
            "--color",
            "--skip-git-repo-check",
        ],
        AdapterKind::Claude => &[
            "--restricted",
            "--print",
            "--output-format",
            "stream-json",
            "--verbose",
            "--permission-mode",
            "dontAsk",
            "--permission-prompts",
            "--tools",
            "--allowedTools",
            "--disallowedTools",
        ],
    };
    for flag in required {
        ensure!(
            help.contains(flag),
            "required safe CLI capability is absent: {flag}"
        );
    }
    if adapter == AdapterKind::Claude {
        let number = version.split_whitespace().find_map(|word| {
            let word = word.trim_start_matches('v');
            let parts: Vec<_> = word.split('.').collect();
            if parts.len() != 3 {
                return None;
            }
            Some((
                parts[0].parse::<u64>().ok()?,
                parts[1].parse::<u64>().ok()?,
                parts[2].split('-').next()?.parse::<u64>().ok()?,
            ))
        });
        ensure!(
            number.is_some_and(|version| version >= (2, 1, 259)),
            "Claude Code 2.1.259 or newer is required for restricted unattended execution"
        );
    }
    Ok(())
}

pub(super) fn baseline(home: &Path, temp: &Path) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()),
        ("HOME".into(), home.to_string_lossy().into_owned()),
        ("TMPDIR".into(), temp.to_string_lossy().into_owned()),
        ("LANG".into(), "C.UTF-8".into()),
        ("TERM".into(), "dumb".into()),
        ("NO_COLOR".into(), "1".into()),
    ])
}
