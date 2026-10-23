use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use maxio::execution::{AdapterKind, PermissionMode, RunRecord, RunRequest, doctor, run};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "maxio-agent",
    about = "Run a trusted local command or configured coding CLI with selected inputs",
    long_about = "Optional local execution with retained workspaces and records. No remote dispatch, automatic publication or source merge. Ordinary executables run with the owner's OS permissions; cwd and environment filtering are not an OS sandbox. Codex keeps its native sandbox. Claude currently exposes file tools only. Logs may contain sensitive task data."
)]
struct Args {
    #[command(subcommand)]
    command: Operation,
}

#[derive(Subcommand)]
enum Operation {
    /// Check executable availability and safe CLI flags, without login/model calls.
    Doctor {
        #[arg(long, value_parser = adapter)]
        adapter: AdapterKind,
        #[arg(long)]
        executable: PathBuf,
    },
    /// Execute once and keep the complete run directory regardless of outcome.
    Run(Box<RunArgs>),
    /// Read a retained record. Preparing/running is unconfirmed work, never implied success.
    Inspect {
        #[arg(long = "run")]
        directory: PathBuf,
    },
    /// Record a cancellation request; inspect the run for its confirmed outcome.
    Cancel {
        #[arg(long = "run")]
        directory: PathBuf,
    },
}

#[derive(clap::Args)]
struct RunArgs {
    #[arg(long, value_parser = adapter, default_value = "command")]
    adapter: AdapterKind,
    /// Absolute path to an already installed owner-selected executable.
    #[arg(long)]
    executable: PathBuf,
    #[arg(long)]
    source: PathBuf,
    /// Explicit file/directory; repeat for several. No inputs means an empty workspace.
    #[arg(long = "input")]
    inputs: Vec<String>,
    /// Output candidate allowlist. Missing outputs are allowed; no files are published.
    #[arg(long = "output")]
    outputs: Vec<String>,
    /// Retained run directories are created here, outside the source tree.
    #[arg(long)]
    records: PathBuf,
    /// UTF-8 prompt/stdin, at most 1 MiB; its contents are not stored in the record.
    #[arg(long)]
    prompt_file: Option<PathBuf>,
    /// Execution deadline, excluding bounded doctor probes and input preparation.
    #[arg(long, default_value_t = 900)]
    timeout_seconds: u64,
    /// Copy only this named variable from this process. Values never enter records.
    #[arg(long = "env")]
    environment: Vec<String>,
    /// Explicit trusted CODEX_HOME or CLAUDE_CONFIG_DIR; outside the source tree.
    #[arg(long)]
    provider_home: Option<PathBuf>,
    /// read-only or workspace-write. Providers default to read-only; commands to workspace-write.
    #[arg(long, value_parser = permission)]
    permission: Option<PermissionMode>,
    /// Literal command arguments after --. Provider adapters reject arbitrary flags.
    #[arg(last = true)]
    args: Vec<String>,
}

fn adapter(value: &str) -> std::result::Result<AdapterKind, String> {
    match value {
        "command" => Ok(AdapterKind::Command),
        "codex" => Ok(AdapterKind::Codex),
        "claude" => Ok(AdapterKind::Claude),
        _ => Err("adapter must be command, codex or claude".into()),
    }
}

fn permission(value: &str) -> std::result::Result<PermissionMode, String> {
    match value {
        "read-only" => Ok(PermissionMode::ReadOnly),
        "workspace-write" => Ok(PermissionMode::WorkspaceWrite),
        _ => Err("permission must be read-only or workspace-write".into()),
    }
}

fn absolute(path: PathBuf) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

#[tokio::main]
async fn main() -> Result<ExitCode> {
    match Args::parse().command {
        Operation::Doctor {
            adapter,
            executable,
        } => {
            let report = doctor(adapter, &executable).await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(if report.supported {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        Operation::Run(arguments) => {
            let RunArgs {
                adapter,
                executable,
                source,
                inputs,
                outputs,
                records,
                prompt_file,
                timeout_seconds,
                environment,
                provider_home,
                permission,
                args,
            } = *arguments;
            let mut selected = BTreeMap::new();
            for name in environment {
                let value = std::env::var(&name).with_context(|| {
                    format!("selected environment variable is unset or not UTF-8: {name}")
                })?;
                ensure!(
                    selected.insert(name, value).is_none(),
                    "duplicate --env selection"
                );
            }
            if let Some(home) = provider_home {
                let name = match adapter {
                    AdapterKind::Codex => "CODEX_HOME",
                    AdapterKind::Claude => "CLAUDE_CONFIG_DIR",
                    AdapterKind::Command => {
                        anyhow::bail!("--provider-home is only supported for codex/claude")
                    }
                };
                let home = absolute(home)?;
                ensure!(
                    selected
                        .insert(
                            name.into(),
                            home.to_str().context("provider home is not UTF-8")?.into()
                        )
                        .is_none(),
                    "choose --provider-home or its --env equivalent, not both"
                );
            }
            let prompt = if let Some(file) = prompt_file {
                ensure!(
                    std::fs::metadata(&file)?.len() <= 1024 * 1024,
                    "prompt file exceeds 1 MiB"
                );
                Some(std::fs::read_to_string(file).context("read prompt file")?)
            } else {
                None
            };
            let record = run(RunRequest {
                adapter,
                executable,
                source: absolute(source)?,
                inputs,
                outputs,
                records: absolute(records)?,
                prompt,
                args,
                timeout_seconds,
                environment: selected,
                permission: permission.unwrap_or(if adapter == AdapterKind::Command {
                    PermissionMode::WorkspaceWrite
                } else {
                    PermissionMode::ReadOnly
                }),
            })
            .await?;
            println!("{}", serde_json::to_string_pretty(&record)?);
            Ok(match record.status.as_str() {
                "succeeded" => ExitCode::SUCCESS,
                "cancelled" => ExitCode::from(130),
                "timed_out" => ExitCode::from(124),
                _ => ExitCode::FAILURE,
            })
        }
        Operation::Inspect { directory } => {
            let path = directory.join("record.json");
            ensure!(
                std::fs::metadata(&path)?.len() <= 16 * 1024 * 1024,
                "run record exceeds 16 MiB"
            );
            let record: RunRecord = serde_json::from_reader(std::fs::File::open(path)?)?;
            if matches!(record.status.as_str(), "preparing" | "running") {
                eprintln!(
                    "This record has no confirmed completion. Inspect retained work; it may be active or abandoned. No process is killed or resumed."
                );
            }
            println!("{}", serde_json::to_string_pretty(&record)?);
            Ok(ExitCode::SUCCESS)
        }
        Operation::Cancel { directory } => {
            let id = maxio::execution::runner::request_cancel(&absolute(directory)?)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "run_id": id,
                    "cancellation_requested": true,
                    "completed": false,
                    "detail": "Request recorded. Inspect record.json for the live runner's confirmed terminal state."
                }))?
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}
