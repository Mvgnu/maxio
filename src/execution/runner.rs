//! Trusted local execution. Working directories are not an OS security boundary.
use super::contract::*;
use anyhow::{Context, Result, ensure};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

mod adapters;
mod files;
mod output;

const CANCEL_REQUEST: &str = "cancel.request";

/// Request cancellation of a local run. This is only a durable request receipt;
/// the live runner must confirm `cancelled` in its record. No saved PID is used.
pub fn request_cancel(directory: &Path) -> Result<String> {
    let directory = files::root(directory)?;
    let path = directory.join("record.json");
    let metadata = std::fs::symlink_metadata(&path)?;
    ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.len() <= 16 * 1024 * 1024,
        "invalid or oversized run record"
    );
    let record: RunRecord = serde_json::from_reader(std::fs::File::open(path)?)?;
    ensure!(
        record.format == 1 && uuid::Uuid::parse_str(&record.id).is_ok(),
        "unsupported run record"
    );
    ensure!(
        directory.file_name().and_then(|name| name.to_str()) == Some(record.id.as_str())
            && record.workspace == directory.join("workspace"),
        "run record belongs to a different directory"
    );
    ensure!(
        matches!(record.status.as_str(), "preparing" | "running"),
        "run is already terminal; cancellation was not requested"
    );
    let marker = directory.join(CANCEL_REQUEST);
    match crate::files::new_file(&marker) {
        Ok(file) => file.sync_all()?,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::AlreadyExists) =>
        {
            let metadata = std::fs::symlink_metadata(&marker)?;
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "invalid cancellation request path"
            );
        }
        Err(error) => return Err(error),
    }
    crate::files::sync_directory(&directory)?;
    Ok(record.id)
}

fn cancellation_requested(root: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(root.join(CANCEL_REQUEST)) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "invalid cancellation marker"
            );
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
async fn wait_for_cancellation(root: &Path) -> Result<()> {
    loop {
        if cancellation_requested(root)? {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn executable(path: &Path) -> Result<PathBuf> {
    ensure!(
        path.is_absolute(),
        "executable must be an absolute owner-selected path"
    );
    let path = std::fs::canonicalize(path).context("executable is unavailable")?;
    let metadata = std::fs::metadata(&path)?;
    ensure!(metadata.is_file(), "executable is not a regular file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o111 != 0,
            "selected file is not executable"
        );
    }
    Ok(path)
}

#[cfg(unix)]
struct OwnedGroup(i32, bool);

#[cfg(unix)]
impl OwnedGroup {
    fn signal(&self, signal: i32) {
        if !self.1 {
            return;
        }
        // SAFETY: this is the positive PID obtained from the child we just
        // started in a new process group, never a PID loaded from a record.
        unsafe {
            libc::kill(-self.0, signal);
        }
    }

    async fn terminate(&mut self) {
        self.signal(libc::SIGTERM);
        tokio::time::sleep(Duration::from_millis(100)).await;
        self.signal(libc::SIGKILL);
        self.1 = false;
    }
}

#[cfg(unix)]
impl Drop for OwnedGroup {
    fn drop(&mut self) {
        self.signal(libc::SIGKILL);
    }
}

#[cfg(unix)]
fn own_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.as_std_mut().process_group(0);
    command.kill_on_drop(true);
}

#[cfg(unix)]
async fn probe(
    path: &Path,
    arguments: &[&str],
    home: &Path,
    runtime_path: Option<&str>,
) -> Result<String> {
    const LIMIT: u64 = 256 * 1024;
    let mut command = Command::new(path);
    command
        .args(arguments)
        .current_dir(home)
        .env_clear()
        .envs(adapters::baseline(home, home))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(runtime_path) = runtime_path {
        command.env("PATH", runtime_path);
    }
    own_group(&mut command);
    let mut child = command
        .spawn()
        .context("start read-only CLI capability probe")?;
    let mut group = OwnedGroup(
        i32::try_from(child.id().context("probe has no process ID")?)?,
        true,
    );
    let stdout = child.stdout.take().context("probe stdout unavailable")?;
    let stderr = child.stderr.take().context("probe stderr unavailable")?;
    let read = |stream: Box<dyn tokio::io::AsyncRead + Unpin + Send>| async move {
        let mut output = Vec::new();
        stream.take(LIMIT + 1).read_to_end(&mut output).await?;
        Ok::<_, std::io::Error>(output)
    };
    let result = tokio::time::timeout(Duration::from_secs(8), async {
        let (stdout, stderr, status) =
            tokio::join!(read(Box::new(stdout)), read(Box::new(stderr)), child.wait());
        Ok::<_, anyhow::Error>((stdout?, stderr?, status?))
    })
    .await;
    group.terminate().await;
    let (stdout, stderr, status) = match result {
        Ok(result) => result?,
        Err(_) => {
            let _ = child.wait().await;
            anyhow::bail!("CLI capability probe exceeded 8 seconds");
        }
    };
    ensure!(
        status.success(),
        "CLI capability probe returned {status}: {}",
        String::from_utf8_lossy(&stderr)
            .chars()
            .take(400)
            .collect::<String>()
    );
    ensure!(
        stdout.len() <= LIMIT as usize && stderr.len() <= LIMIT as usize,
        "CLI capability probe exceeded output limit"
    );
    Ok(format!(
        "{}\n{}",
        String::from_utf8(stdout).context("CLI help is not UTF-8")?,
        String::from_utf8(stderr).context("CLI help is not UTF-8")?
    ))
}

/// Inspect an existing executable. This never installs, logs in or sends a prompt.
pub async fn doctor(adapter: AdapterKind, selected: &Path) -> Result<DoctorReport> {
    doctor_with_path(adapter, selected, None).await
}

async fn doctor_with_path(
    adapter: AdapterKind,
    selected: &Path,
    runtime_path: Option<&str>,
) -> Result<DoctorReport> {
    #[cfg(not(unix))]
    {
        let _ = (adapter, selected, runtime_path);
        anyhow::bail!("local process supervision currently requires Unix");
    }
    #[cfg(unix)]
    {
        let path = executable(selected)?;
        let mut report = DoctorReport {
            adapter,
            executable: path.to_string_lossy().into_owned(),
            version: "not probed (ordinary executable)".into(),
            supported: true,
            detail: "Trusted owner-selected command; no filesystem confinement is implied.".into(),
        };
        if adapter == AdapterKind::Command {
            report.version = format!("sha256:{}", crate::files::hash_file(&path)?.0);
            return Ok(report);
        }
        let temp = tempfile::tempdir()?;
        let result = async {
            let version = probe(&path, &["--version"], temp.path(), runtime_path).await?;
            report.version = version
                .lines()
                .find(|line| !line.is_empty())
                .context("CLI version output is empty")?
                .chars()
                .take(256)
                .collect();
            let mut help = probe(&path, &["--help"], temp.path(), runtime_path).await?;
            if adapter == AdapterKind::Codex {
                help.push_str(&probe(&path, &["exec", "--help"], temp.path(), runtime_path).await?);
            }
            adapters::capabilities(adapter, &report.version, &help)
        }
        .await;
        match result {
            Ok(()) => report.detail = "Required safe CLI flags are advertised. Authentication and live model execution have NOT been verified.".into(),
            Err(error) => { report.supported = false; report.detail = format!("CLI capability check failed: {error:#}"); }
        }
        Ok(report)
    }
}

fn detail(record: &mut RunRecord, text: &str) {
    let previous = record.detail.take().unwrap_or_default();
    record.detail = Some(if previous.is_empty() {
        text.into()
    } else {
        format!("{previous}; {text}")
    });
}

/// Retain every prepared run, including failed/cancelled work. Publication is a
/// separate authority and is never performed by this function.
pub async fn run(request: RunRequest) -> Result<RunRecord> {
    #[cfg(not(unix))]
    {
        let _ = request;
        anyhow::bail!("local process supervision currently requires Unix");
    }
    #[cfg(unix)]
    {
        ensure!(
            (1..=86400).contains(&request.timeout_seconds),
            "timeout must be between 1 and 86400 seconds"
        );
        ensure!(
            request.adapter != AdapterKind::Command
                || request.permission == PermissionMode::WorkspaceWrite,
            "ordinary command execution cannot enforce read-only; select workspace-write for trusted local execution"
        );
        let selected = executable(&request.executable)?;
        let source = files::root(&request.source)?;
        for selector in request.inputs.iter().chain(request.outputs.iter()) {
            files::validate_selector(selector)?;
        }
        let secrets = adapters::validate_environment(&request, &source)?;
        let paths = files::create_run(&request.records)?;
        ensure!(
            !paths.root.starts_with(&source),
            "records must be outside the source directory"
        );
        let mut record = RunRecord {
            format: 1,
            id: paths.id.clone(),
            adapter: request.adapter,
            executable: selected.to_string_lossy().into_owned(),
            executable_version: "not yet checked".into(),
            status: "preparing".into(),
            workspace: paths.workspace.clone(),
            stdout_log: paths.root.join("stdout.log"),
            stderr_log: paths.root.join("stderr.log"),
            input_files: Vec::new(),
            output_files: Vec::new(),
            environment_names: request.environment.keys().cloned().collect(),
            started_at: chrono::Utc::now().to_rfc3339(),
            finished_at: None,
            exit_code: None,
            provider_session_id: None,
            detail: None,
            published: false,
        };
        files::persist(&record, &paths.root)?;
        let result = execute(&request, &source, &selected, &paths, &secrets, &mut record).await;
        if let Err(error) = result {
            record.status = "failed".into();
            let mut message = format!("{error:#}");
            for secret in &secrets {
                message = message.replace(secret, "[REDACTED]");
            }
            detail(&mut record, &message.chars().take(2048).collect::<String>());
        }
        match files::outputs(&paths.workspace, &request.outputs) {
            Ok(outputs) => record.output_files = outputs,
            Err(_) => {
                if record.status == "succeeded" {
                    record.status = "failed".into();
                }
                detail(
                    &mut record,
                    "Output inspection refused an unsafe or unreadable path; retained workspace requires inspection.",
                );
            }
        }
        record.finished_at = Some(chrono::Utc::now().to_rfc3339());
        files::persist(&record, &paths.root).with_context(|| {
            format!(
                "cannot persist terminal record; retained run: {}",
                paths.root.display()
            )
        })?;
        Ok(record)
    }
}

#[cfg(unix)]
async fn execute(
    request: &RunRequest,
    source: &Path,
    selected: &Path,
    paths: &files::RunPaths,
    secrets: &[String],
    record: &mut RunRecord,
) -> Result<()> {
    let stdout_file = crate::files::new_file(&record.stdout_log)?;
    let stderr_file = crate::files::new_file(&record.stderr_log)?;
    let report = doctor_with_path(
        request.adapter,
        selected,
        request.environment.get("PATH").map(String::as_str),
    )
    .await?;
    record.executable_version = report.version;
    ensure!(report.supported, "{}", report.detail);
    if cancellation_requested(&paths.root)? {
        record.status = "cancelled".into();
        return Ok(());
    }
    record.input_files = files::copy_inputs(source, &paths.workspace, &request.inputs)?;
    files::persist(record, &paths.root)?;
    if cancellation_requested(&paths.root)? {
        record.status = "cancelled".into();
        return Ok(());
    }
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut command = Command::new(selected);
    command
        .args(adapters::argv(request, &paths.workspace))
        .current_dir(&paths.workspace)
        .env_clear()
        .envs(adapters::baseline(&paths.home, &paths.temp))
        .envs(&request.environment)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    own_group(&mut command);
    let mut child = command.spawn().context("start selected executable")?;
    let mut group = OwnedGroup(
        i32::try_from(child.id().context("child has no process ID")?)?,
        true,
    );
    record.status = "running".into();
    files::persist(record, &paths.root)?;
    let stdout = child.stdout.take().context("child stdout unavailable")?;
    let stderr = child.stderr.take().context("child stderr unavailable")?;
    let mut stdin = child.stdin.take().context("child stdin unavailable")?;
    let input = request.prompt.clone().unwrap_or_default();
    let input_task = tokio::spawn(async move {
        stdin.write_all(input.as_bytes()).await?;
        stdin.shutdown().await
    });
    let adapter = request.adapter;
    let output_secrets = secrets.to_vec();
    let error_secrets = secrets.to_vec();
    let mut stdout_task = tokio::spawn(async move {
        output::capture(stdout, stdout_file, adapter, &output_secrets).await
    });
    let mut stderr_task = tokio::spawn(async move {
        output::capture(stderr, stderr_file, AdapterKind::Command, &error_secrets).await
    });
    let waited = tokio::select! {
        result = child.wait() => Some(result),
        _ = tokio::time::sleep(Duration::from_secs(request.timeout_seconds)) => { record.status = "timed_out".into(); None },
        _ = interrupt.recv() => { record.status = "cancelled".into(); None },
        _ = terminate.recv() => { record.status = "cancelled".into(); None },
        result = wait_for_cancellation(&paths.root) => { result?; record.status = "cancelled".into(); None },
    };
    group.terminate().await;
    let status = match waited {
        Some(status) => status?,
        None => tokio::time::timeout(Duration::from_secs(2), child.wait())
            .await
            .context("terminated process did not exit")??,
    };
    record.exit_code = status.code();
    if let Some(signal) = std::os::unix::process::ExitStatusExt::signal(&status) {
        detail(record, &format!("Process terminated by signal {signal}."));
    }
    let input_result = input_task.await.context("stdin task failed")?;
    let capture = tokio::time::timeout(Duration::from_secs(2), async {
        let (stdout, stderr) = tokio::join!(&mut stdout_task, &mut stderr_task);
        Ok::<_, anyhow::Error>((stdout??, stderr??))
    })
    .await;
    let (stdout, stderr) = match capture {
        Ok(result) => result?,
        Err(_) => {
            stdout_task.abort();
            stderr_task.abort();
            anyhow::bail!("output streams remained open after owned process group termination");
        }
    };
    record.provider_session_id = stdout.session.clone();
    if stdout.truncated || stderr.truncated {
        detail(
            record,
            "Logs truncated at 4 MiB per stream or a 1 MiB line; retained logs may contain sensitive task data.",
        );
    }
    if matches!(record.status.as_str(), "cancelled" | "timed_out") {
        return Ok(());
    }
    if !status.success() {
        record.status = "failed".into();
        detail(record, "Executable returned an unsuccessful exit status.");
    } else if input_result.is_err() {
        record.status = "failed".into();
        detail(record, "Prompt/stdin was not fully delivered.");
    } else if stdout.failed || stdout.denied {
        record.status = "failed".into();
        detail(
            record,
            if stdout.denied {
                "Provider reported permission denial; inspect retained logs."
            } else {
                "Provider reported an error; inspect retained logs."
            },
        );
    } else if request.adapter != AdapterKind::Command
        && (stdout.malformed || !stdout.final_turn_completed || stdout.session.is_none())
    {
        record.status = "protocol_failed".into();
        detail(
            record,
            "Provider output was malformed or the final active turn lacked a valid successful terminal event.",
        );
    } else {
        record.status = "succeeded".into();
    }
    Ok(())
}
