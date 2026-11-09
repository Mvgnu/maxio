//! A single-slot managed worker. This composes the existing runner; the
//! coordinator remains the only job, lease and publication authority.
use super::cache::PrivateCache;
use super::client::FabricClient;
use super::contract::*;
use crate::execution::{AdapterKind, PermissionMode, RunFile, RunRecord, RunRequest};
use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::watch;

mod attempt;
mod local;
mod logs;

/// Trusted owner-local configuration, never serialized or sent to the authority.
/// The existing runner validates its environment and provider flags again.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionProfile {
    pub name: String,
    pub adapter: AdapterKind,
    pub executable: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
    pub permission: PermissionMode,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
}

pub struct WorkerOptions {
    pub root: PathBuf,
    pub worker_id: String,
    pub display_name: String,
    pub profiles: Vec<ExecutionProfile>,
    pub resources: Resources,
    pub poll_interval: Duration,
    pub renewal_interval: Duration,
    pub lease_seconds: u64,
    /// Keep polling until one job is completed, then stop. Never retry a job.
    pub once: bool,
}

/// Validate local profile identity without authentication, installations or model
/// calls. Provider capability and environment checks remain in the actual runner.
pub fn validate_profiles(profiles: &[ExecutionProfile]) -> Result<()> {
    ensure!(
        !profiles.is_empty() && profiles.len() <= 64,
        "select between 1 and 64 local execution profiles"
    );
    let mut names = BTreeSet::new();
    for profile in profiles {
        ensure!(
            !profile.name.is_empty()
                && profile.name.len() <= 64
                && profile
                    .name
                    .bytes()
                    .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_')),
            "invalid local profile name"
        );
        ensure!(names.insert(&profile.name), "duplicate local profile name");
        ensure!(
            profile.executable.is_absolute(),
            "profile executable must be an absolute owner-selected path"
        );
        let metadata =
            std::fs::metadata(&profile.executable).context("profile executable is unavailable")?;
        ensure!(
            metadata.is_file(),
            "profile executable must be a regular file"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                metadata.permissions().mode() & 0o111 != 0,
                "profile executable is not executable"
            );
        }
        ensure!(
            profile.args.len() <= 256
                && profile
                    .args
                    .iter()
                    .all(|arg| arg.len() <= 16 * 1024 && !arg.contains('\0')),
            "profile argument limit exceeded"
        );
        if profile.adapter == AdapterKind::Command {
            ensure!(
                profile.permission == PermissionMode::WorkspaceWrite,
                "ordinary command profiles cannot enforce read-only execution"
            );
        } else {
            ensure!(
                profile.args.is_empty(),
                "provider profiles cannot supply arbitrary command arguments"
            );
        }
        ensure!(
            profile.environment.len() <= 64,
            "too many local profile environment entries"
        );
    }
    Ok(())
}

pub(crate) fn expected_inputs(claimed: &ClaimedJob) -> Result<Vec<RunFile>> {
    crate::workspace::validate_id(&claimed.attempt.job_id)?;
    crate::workspace::validate_id(&claimed.attempt.attempt_id)?;
    crate::workspace::validate_id(&claimed.attempt.worker_id)?;
    crate::workspace::validate_id(&claimed.attempt.worker_incarnation)?;
    ensure!(
        claimed.attempt.job_id == claimed.job.job_id,
        "assignment job/attempt identity mismatch"
    );
    ensure!(
        claimed.job.inputs.len() <= crate::workspace::MAX_ENTRIES,
        "too many selected inputs"
    );
    let mut seen = BTreeSet::new();
    let mut expected = Vec::new();
    for input in &claimed.job.inputs {
        crate::files::validate_workspace_relative(&input.path)?;
        crate::workspace::validate_id(&input.revision.revision)?;
        crate::workspace::validate_hash(&input.revision.sha256)?;
        crate::workspace::validate_file_version(&input.version)?;
        ensure!(
            seen.insert(input.path.clone()),
            "duplicate selected input path"
        );
        expected.push(RunFile {
            path: input.path.clone(),
            sha256: input.version.sha256.clone(),
            size: input.version.size,
        });
    }
    crate::files::validate_workspace_paths(seen.iter())?;
    expected.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(expected)
}

pub(crate) fn output_selectors(scopes: &[PathScope]) -> Result<Vec<String>> {
    ensure!(
        scopes.len() <= crate::workspace::MAX_ENTRIES,
        "too many output scopes"
    );
    let mut result = BTreeSet::new();
    for scope in scopes {
        match scope {
            PathScope::Workspace => {
                result.insert(".".into());
            }
            PathScope::Exact { path } | PathScope::Tree { path } => {
                crate::files::validate_workspace_relative(path)?;
                result.insert(path.clone());
            }
        }
    }
    Ok(result.into_iter().collect())
}

/// Trusted local bridge used by the worker after admission and cache preparation.
/// Input identities and literal profile arguments reach the same implementation
/// used by maxio-agent. This function does not grant or publish remote authority.
pub async fn execute_prepared(
    profile: &ExecutionProfile,
    claimed: &ClaimedJob,
    source: &Path,
    records: &Path,
    mut cancelled: watch::Receiver<bool>,
) -> Result<RunRecord> {
    validate_profiles(std::slice::from_ref(profile))?;
    ensure!(
        profile.name == claimed.job.profile,
        "assignment does not name this local execution profile"
    );
    ensure!(
        !*cancelled.borrow() && !claimed.job.cancel_requested,
        "attempt cancelled before local execution"
    );
    let expected = expected_inputs(claimed)?;
    let request = RunRequest {
        adapter: profile.adapter,
        executable: profile.executable.clone(),
        source: source.to_path_buf(),
        inputs: expected.iter().map(|file| file.path.clone()).collect(),
        outputs: output_selectors(&claimed.job.output_selectors)?,
        records: records.to_path_buf(),
        prompt: claimed.prompt.clone(),
        args: profile.args.clone(),
        timeout_seconds: claimed.job.timeout_seconds,
        environment: profile.environment.clone(),
        permission: profile.permission,
    };
    let execution = crate::execution::run_verified(request, &expected);
    tokio::pin!(execution);
    let mut check = tokio::time::interval(Duration::from_millis(50));
    let mut stop = false;
    loop {
        tokio::select! {
            result = &mut execution => return result,
            changed = cancelled.changed(), if !stop => {
                stop = changed.is_err() || *cancelled.borrow();
            }
            _ = check.tick() => {
                if stop || *cancelled.borrow() {
                    stop = true;
                    local::cancel_owned_run(records)?;
                }
            }
        }
    }
}

pub(crate) async fn control(
    client: &FabricClient,
    request: &ControlRequest,
) -> Result<ControlResponse> {
    // Retrying the identical request is safe: mutation IDs are durable. Never
    // create a fresh request ID to retry an uncertain acknowledged operation.
    match client.control(request).await {
        Ok(response) => Ok(response),
        Err(error) => {
            if error
                .downcast_ref::<FabricError>()
                .is_some_and(|error| !matches!(error.code, ErrorCode::Unavailable))
            {
                return Err(error);
            }
            client.control(request).await
        }
    }
}

async fn advertise(
    client: &FabricClient,
    cache: &PrivateCache,
    options: &WorkerOptions,
    incarnation: &str,
) -> Result<()> {
    let advertisement = WorkerAdvertisement {
        worker_id: options.worker_id.clone(),
        incarnation: incarnation.into(),
        display_name: options.display_name.clone(),
        profiles: options
            .profiles
            .iter()
            .map(|profile| ProfileAdvertisement {
                name: profile.name.clone(),
                adapter: profile.adapter,
                permission: profile.permission,
            })
            .collect(),
        resources: options.resources,
        cached_files: cache.inventory(true)?.cached_files,
    };
    match control(
        client,
        &ControlRequest::AdvertiseWorker {
            request_id: local::id(),
            advertisement,
        },
    )
    .await?
    {
        ControlResponse::Worker { worker }
            if worker.advertisement.worker_id == options.worker_id
                && worker.advertisement.incarnation == incarnation =>
        {
            Ok(())
        }
        _ => bail!("authority returned a different worker advertisement"),
    }
}

/// Run one independently owned worker process. No task is retried automatically.
pub async fn serve(client: FabricClient, options: WorkerOptions) -> Result<()> {
    validate_profiles(&options.profiles)?;
    crate::workspace::validate_id(&options.worker_id)?;
    ensure!(
        !options.display_name.is_empty()
            && options.display_name.len() <= 128
            && !options.display_name.chars().any(char::is_control),
        "invalid worker display name"
    );
    ensure!(
        (1..=300).contains(&options.lease_seconds),
        "attempt lease must be between 1 and 300 seconds"
    );
    ensure!(
        options.poll_interval >= Duration::from_millis(100)
            && options.poll_interval <= Duration::from_secs(30),
        "poll interval must be between 100 ms and 30 seconds"
    );
    ensure!(
        options.renewal_interval >= Duration::from_millis(100)
            && options.renewal_interval < Duration::from_secs(options.lease_seconds) / 2,
        "renewal interval must be at least 100 ms and less than half the lease duration"
    );
    let info = match control(&client, &ControlRequest::Info).await? {
        ControlResponse::Info { info } => info,
        _ => bail!("authority info response has the wrong type"),
    };
    let mut cache = PrivateCache::open(&options.root, &info, &options.worker_id)?;
    let root = cache.root().to_path_buf();
    local::private_directory(&root.join("attempts"))?;
    let incarnation = local::id();
    advertise(&client, &cache, &options, &incarnation).await?;
    attempt::reconcile(&client, &mut cache, &info).await?;
    eprintln!(
        "{}",
        serde_json::json!({"event":"worker_ready", "worker_id":options.worker_id, "incarnation":incarnation, "root":root})
    );
    let (shutdown_tx, mut shutdown) = watch::channel(false);
    let signals = tokio::spawn(async move {
        #[cfg(unix)]
        {
            if let (Ok(mut interrupt), Ok(mut terminate)) = (
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()),
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()),
            ) {
                tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {} }
                let _ = shutdown_tx.send(true);
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            let _ = shutdown_tx.send(true);
        }
    });
    let result = async {
        loop {
            if *shutdown.borrow() {
                return Ok(());
            }
            advertise(&client, &cache, &options, &incarnation).await?;
            let claimed = match control(
                &client,
                &ControlRequest::ClaimJob {
                    request_id: local::id(),
                    worker_id: options.worker_id.clone(),
                    incarnation: incarnation.clone(),
                },
            )
            .await?
            {
                ControlResponse::Claim { claimed } => claimed,
                _ => bail!("authority claim response has the wrong type"),
            };
            if let Some(claimed) = claimed {
                ensure!(
                    claimed.attempt.worker_id == options.worker_id
                        && claimed.attempt.worker_incarnation == incarnation,
                    "authority assigned work to a different worker incarnation"
                );
                ensure!(
                    claimed.job.base.authority_id == info.authority_id,
                    "assignment belongs to a different authority"
                );
                let profile = options
                    .profiles
                    .iter()
                    .find(|profile| profile.name == claimed.job.profile)
                    .context("authority selected an unavailable local profile")?;
                attempt::perform(
                    &client,
                    &mut cache,
                    &info,
                    &options,
                    profile,
                    claimed,
                    shutdown.clone(),
                )
                .await?;
                if options.once || *shutdown.borrow() {
                    return Ok(());
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(options.poll_interval) => {},
                _ = shutdown.changed() => {},
            }
        }
    }
    .await;
    signals.abort();
    result
}
