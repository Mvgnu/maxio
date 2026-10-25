use super::super::{cache::PrivateCache, client::FabricClient, contract::*};
use super::{
    ExecutionProfile, WorkerOptions, control, execute_prepared, expected_inputs, local, logs,
};
use anyhow::{Context, Result, bail, ensure};
use std::fs;
use std::time::Duration;
use tokio::sync::watch;

struct Monitor {
    stop: watch::Sender<bool>,
    stopped: watch::Receiver<bool>,
    lease: watch::Receiver<Option<WriteLease>>,
    reason: watch::Receiver<Option<String>>,
    reason_sender: watch::Sender<Option<String>>,
    task: tokio::task::JoinHandle<()>,
}

impl Monitor {
    fn start(
        client: FabricClient,
        claimed: &ClaimedJob,
        options: &WorkerOptions,
        mut shutdown: watch::Receiver<bool>,
    ) -> Self {
        let (stop, stopped) = watch::channel(false);
        let (lease_tx, lease) = watch::channel(claimed.lease.clone());
        // A watch channel keeps stop diagnostics separate from task control;
        // there is no poisonable shared mutex that could panic during cancellation.
        let (reason_sender, reason) = watch::channel(None);
        let task_reason = reason_sender.clone();
        let task_stop = stop.clone();
        let binding = claimed.attempt.clone();
        let initial_token = claimed.lease.as_ref().map(|lease| lease.token.clone());
        let ttl = options.lease_seconds;
        let interval = options.renewal_interval;
        let task = tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            let mut shutdown_seen = false;
            loop {
                tokio::select! {
                    changed = shutdown.changed(), if !shutdown_seen => {
                        if changed.is_err() || *shutdown.borrow() {
                            shutdown_seen = true;
                            let _ = task_stop.send(true);
                            let _ = task_reason.send_replace(Some("worker shutdown requested".into()));
                        }
                    }
                    _ = tick.tick() => {
                        let request = ControlRequest::RenewAttempt { request_id: local::id(), attempt: binding.clone(), lease: initial_token.clone(), ttl_seconds: ttl };
                        match control(&client, &request).await {
                            Ok(ControlResponse::Heartbeat { heartbeat }) if heartbeat.attempt == binding && heartbeat.lease.as_ref().map(|lease| &lease.token) == initial_token.as_ref() => {
                                let terminal = matches!(heartbeat.state, AttemptState::Abandoned | AttemptState::Cancelled | AttemptState::Failed | AttemptState::TimedOut | AttemptState::ProtocolFailed);
                                let _ = lease_tx.send(heartbeat.lease);
                                if heartbeat.cancel_requested || terminal {
                                    let _ = task_stop.send(true);
                                    let _ = task_reason.send_replace(Some(if heartbeat.cancel_requested { "authority cancellation requested" } else { "authority attempt is no longer active" }.into()));
                                    if terminal { break; }
                                }
                            }
                            _ => {
                                // Authentication, revocation, expiry, network loss
                                // and a changed epoch all stop further publication.
                                let _ = task_stop.send(true);
                                let _ = task_reason.send_replace(Some("authority renewal failed or changed attempt authority".into()));
                                break;
                            }
                        }
                    }
                }
            }
        });
        Self {
            stop,
            stopped,
            lease,
            reason,
            reason_sender,
            task,
        }
    }
    fn request_stop(&self, reason: &str) {
        let _ = self.stop.send(true);
        let _ = self.reason_sender.send_replace(Some(reason.into()));
    }
    fn detail(&self) -> Option<String> {
        self.reason.borrow().clone()
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn allowed(scopes: &[PathScope], path: &str) -> bool {
    scopes.iter().any(|scope| match scope {
        PathScope::Workspace => true,
        PathScope::Exact { path: selected } => path == selected,
        PathScope::Tree { path: selected } => {
            path == selected
                || path
                    .strip_prefix(selected)
                    .is_some_and(|tail| tail.starts_with('/'))
        }
    })
}

fn safe_detail(error: &anyhow::Error, profile: &ExecutionProfile) -> String {
    let mut text = format!("{error:#}");
    let mut values: Vec<_> = profile
        .environment
        .values()
        .filter(|value| !value.is_empty())
        .collect();
    values.sort_by_key(|value| std::cmp::Reverse(value.len()));
    for value in values {
        text = text.replace(value, "[REDACTED]");
    }
    text.chars().take(2048).collect()
}

pub(super) async fn perform(
    client: &FabricClient,
    cache: &mut PrivateCache,
    info: &AuthorityInfo,
    options: &WorkerOptions,
    profile: &ExecutionProfile,
    claimed: ClaimedJob,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    expected_inputs(&claimed)?;
    ensure!(
        claimed.job.workspace_id == claimed.job.base.workspace_id,
        "assignment workspace identity mismatch"
    );
    let root = cache
        .root()
        .join("attempts")
        .join(&claimed.attempt.attempt_id);
    ensure!(
        !root.try_exists()?,
        "attempt already has local work; reconcile instead of executing again"
    );
    local::private_directory(&root)?;
    for directory in ["source", "runs", "outputs"] {
        local::private_directory(&root.join(directory))?;
    }
    let mut state = local::LocalAttempt::new(info, &claimed);
    state.persist(&root)?;
    let inputs = local::retained_inputs(&claimed.job);
    if !inputs.is_empty() {
        cache.protect(&claimed.attempt.attempt_id, &inputs)?;
    }
    let monitor = Monitor::start(client.clone(), &claimed, options, shutdown);
    let mut stop = monitor.stopped.clone();
    let transfer_before = client.stats();
    let result = async {
        if !inputs.is_empty() {
            let hydration = tokio::select! {
                result = cache.hydrate(client, &inputs, Some(&claimed.attempt)) => result?,
                _ = stop.changed() => bail!("attempt stopped during hydration; incomplete stages retained"),
            };
            local::write_json(&root.join("hydration.json"), &hydration)?;
            ensure!(!*stop.borrow(), "attempt stopped before preparing input copies");
            cache.copy_to(&inputs, &root.join("source"))?;
        }
        ensure!(!*stop.borrow(), "attempt stopped before local execution");
        state.phase = "running".into();
        state.persist(&root)?;
        let source = root.join("source");
        let runs = root.join("runs");
        let local_profile = profile.clone();
        let local_claim = claimed.clone();
        let local_stop = stop.clone();
        // Poll cancellation independently of potentially slow log/control I/O.
        let mut execution = tokio::spawn(async move {
            execute_prepared(&local_profile, &local_claim, &source, &runs, local_stop).await
        });
        let mut log_tick = tokio::time::interval(Duration::from_secs(1));
        let record = loop {
            tokio::select! {
                result = &mut execution => break result.context("local runner task stopped without a terminal result")??,
                _ = log_tick.tick() => {
                    if let Err(error) = logs::sync(client, &claimed.attempt, &root).await {
                        monitor.request_stop("log forwarding failed; local logs retained");
                        state.detail = Some(safe_detail(&error, profile));
                    }
                }
            }
        };
        state.run = Some(record.clone());
        state.cancellation_requested = *stop.borrow();
        state.lease = monitor.lease.borrow().clone();
        state.phase = "finishing".into();
        if let Some(reason) = monitor.detail() { state.detail = Some(reason); }
        state.persist(&root)?;
        // Every task receives independent copies, and its terminal record is now
        // durable; releasing cache use does not remove any retained attempt bytes.
        if !inputs.is_empty() { cache.release(&claimed.attempt.attempt_id)?; }
        logs::sync(client, &claimed.attempt, &root).await?;
        let publish = record.status == "succeeded" && claimed.job.output_policy == OutputPolicy::Publish && !record.output_files.is_empty();
        let base_catalog = if publish {
            ensure!(!*stop.borrow(), "attempt stopped before output publication; candidates retained");
            match control(client, &ControlRequest::Revision { workspace_id: claimed.job.workspace_id.clone(), revision: claimed.job.base.revision.clone() }).await? {
                ControlResponse::Catalog { catalog } => {
                    crate::workspace::validate_snapshot(&catalog.snapshot)?;
                    ensure!(catalog.snapshot.manifest.workspace_id == claimed.job.workspace_id && catalog.snapshot.manifest.revision == claimed.job.base.revision.revision && catalog.snapshot.manifest_sha256 == claimed.job.base.revision.sha256, "output base catalog identity mismatch");
                    Some(catalog)
                }
                _ => bail!("authority returned the wrong output-base response"),
            }
        } else { None };
        if publish {
            let lease = state.lease.as_ref().context("publication has no attempt write lease")?;
            for file in &record.output_files {
                ensure!(allowed(&claimed.job.output_selectors, &file.path), "runner proposed an output outside the admitted scopes");
                crate::files::validate_workspace_relative(&file.path)?;
                let stage_name = local::id();
                let request = UploadRequest {
                    request_id: local::id(), workspace_id: claimed.job.workspace_id.clone(), path: file.path.clone(),
                    sha256: file.sha256.clone(), size: file.size, lease: lease.token.clone(), attempt: Some(claimed.attempt.clone()),
                };
                state.outputs.push(local::OutputStage { file: file.clone(), stage_name: stage_name.clone(), request, prepared: None });
                // Persist the intended stage and request before its first write.
                state.persist(&root)?;
                let source = crate::files::checked_path(&record.workspace, &file.path, false)?;
                local::copy_verified(&source, &root.join("outputs").join(stage_name), file)?;
            }
            for index in 0..state.outputs.len() {
                ensure!(!*stop.borrow(), "attempt stopped while staging outputs; candidates retained");
                let output = &state.outputs[index];
                let source = root.join("outputs").join(&output.stage_name);
                let prepared = match client.upload(&output.request, &source).await {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        if error.downcast_ref::<FabricError>().is_some_and(|error| error.code != ErrorCode::Unavailable) { return Err(error); }
                        client.upload(&output.request, &source).await?
                    }
                };
                ensure!(prepared.workspace_id == claimed.job.workspace_id && prepared.path == output.file.path && prepared.version.sha256 == output.file.sha256 && prepared.version.size == output.file.size && prepared.attempt.as_ref() == Some(&claimed.attempt), "prepared upload identity mismatch");
                state.outputs[index].prepared = Some(prepared);
                state.persist(&root)?;
            }
        }
        let upload_ids = state.outputs.iter().filter_map(|output| output.prepared.as_ref().map(|prepared| prepared.upload_id.clone())).collect();
        let finished = control(client, &ControlRequest::FinishAttempt {
            request_id: state.finish_request_id.clone(), attempt: state.binding.clone(),
            lease: state.lease.as_ref().map(|lease| lease.token.clone()), run: record.clone(), upload_ids,
        }).await;
        let job = match finished {
            Ok(ControlResponse::Job { job }) => job,
            Ok(_) => bail!("authority returned the wrong finish response"),
            Err(error) => {
                match control(client, &ControlRequest::JobStatus { job_id: state.binding.job_id.clone() }).await {
                    Ok(ControlResponse::Job { job }) if job.attempts.iter().any(|attempt| attempt.binding == state.binding && attempt.run.as_ref().is_some_and(|run| run.id == record.id && run.status == record.status)) => job,
                    _ => return Err(error.context("finish outcome unconfirmed; retained terminal run must be reconciled")),
                }
            }
        };
        ensure!(job.job_id == state.binding.job_id && job.attempts.iter().any(|attempt| attempt.binding == state.binding && attempt.run.as_ref().is_some_and(|run| run.id == record.id && run.status == record.status)), "finish response does not confirm this exact local run");
        state.job = job;
        state.persist(&root)?;
        if publish {
            ensure!(!*stop.borrow(), "attempt stopped before final publication; prepared outputs retained");
            state.phase = "publishing".into();
            state.persist(&root)?;
            let catalog = base_catalog.as_ref().context("output publication base missing")?;
            let changes = state.outputs.iter().map(|output| Ok(PublicationChange::Put {
                path: output.file.path.clone(), upload_id: output.prepared.as_ref().context("output not prepared")?.upload_id.clone(),
                expected: catalog.snapshot.manifest.files.get(&output.file.path).cloned(),
            })).collect::<Result<Vec<_>>>()?;
            let request = ControlRequest::Publish { publication: PublishRequest {
                context: PublicationContext { request_id: state.publication_request_id.clone(), workspace_id: state.job.workspace_id.clone(), base: claimed.job.base.clone(), lease: state.lease.as_ref().context("publication lease missing")?.token.clone(), attempt: Some(state.binding.clone()) },
                changes,
            }};
            let receipt = match control(client, &request).await {
                Ok(ControlResponse::Publication { receipt }) => receipt,
                Ok(_) => bail!("authority returned the wrong publication response"),
                Err(error) => match control(client, &ControlRequest::PublicationStatus { request_id: state.publication_request_id.clone() }).await {
                    Ok(ControlResponse::Publication { receipt }) => receipt,
                    _ => return Err(error.context("publication outcome unconfirmed; candidates and request identity retained")),
                },
            };
            ensure!(receipt.request_id == state.publication_request_id && receipt.attempt.as_ref() == Some(&state.binding) && receipt.authority_id == info.authority_id && receipt.workspace_id == state.job.workspace_id, "publication receipt identity mismatch");
            state.publication = Some(receipt);
        }
        state.phase = "complete".into();
        state.transfer = transfer_delta(transfer_before, client.stats());
        state.persist(&root)?;
        eprintln!("{}", serde_json::json!({"event":"attempt_complete", "job_id":state.binding.job_id, "attempt_id":state.binding.attempt_id, "run_status":record.status, "published":state.publication.is_some(), "retained_at":root}));
        Ok(())
    }.await;
    if let Err(error) = result {
        monitor
            .request_stop("attempt orchestration stopped; retained work requires reconciliation");
        let _ = local::cancel_owned_run(&root.join("runs"));
        state.phase = "retained".into();
        state.cancellation_requested = *monitor.stopped.borrow();
        state.detail = Some(safe_detail(&error, profile));
        state.transfer = transfer_delta(transfer_before, client.stats());
        if state.run.is_none() {
            state.run = local::owned_run(&root.join("runs"))?.map(|(_, record)| record);
        }
        state.persist(&root)?;
        return Err(anyhow::anyhow!(
            "worker attempt retained at {}: {}",
            root.display(),
            state.detail.as_deref().unwrap_or("unconfirmed failure")
        ));
    }
    Ok(())
}

fn transfer_delta(
    before: crate::workspace::TransferStats,
    after: crate::workspace::TransferStats,
) -> crate::workspace::TransferStats {
    crate::workspace::TransferStats {
        payload_uploaded: after
            .payload_uploaded
            .saturating_sub(before.payload_uploaded),
        payload_downloaded: after
            .payload_downloaded
            .saturating_sub(before.payload_downloaded),
        metadata_uploaded: after
            .metadata_uploaded
            .saturating_sub(before.metadata_uploaded),
        metadata_downloaded: after
            .metadata_downloaded
            .saturating_sub(before.metadata_downloaded),
    }
}

/// A fresh incarnation has already been registered. Reconciliation observes old
/// receipts and requests local cancellation; it never restarts a process or
/// signals a persisted PID. Failed/ambiguous bytes are retained in every case.
pub(super) async fn reconcile(
    client: &FabricClient,
    cache: &mut PrivateCache,
    info: &AuthorityInfo,
) -> Result<()> {
    let attempts = cache.root().join("attempts");
    for entry in fs::read_dir(attempts)? {
        let entry = entry?;
        let root = entry.path();
        let metadata = fs::symlink_metadata(&root)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "unsafe retained attempt directory"
        );
        let mut state = local::LocalAttempt::load(&root, info)?;
        if state.phase == "complete" {
            continue;
        }
        local::cancel_owned_run(&root.join("runs"))?;
        if let Some((_, run)) = local::owned_run(&root.join("runs"))? {
            state.run = Some(run);
        }
        let job = match control(
            client,
            &ControlRequest::JobStatus {
                job_id: state.binding.job_id.clone(),
            },
        )
        .await?
        {
            ControlResponse::Job { job } => job,
            _ => bail!("authority returned the wrong reconciliation response"),
        };
        let attempt = job
            .attempts
            .iter()
            .find(|attempt| attempt.binding == state.binding)
            .context("retained local attempt is absent from authoritative job")?;
        if let Some(receipt) = &attempt.publication {
            ensure!(
                receipt.attempt.as_ref() == Some(&state.binding)
                    && receipt.authority_id == info.authority_id,
                "recovered publication belongs to another attempt"
            );
            state.publication = Some(receipt.clone());
            state.phase = "complete".into();
            state.detail = Some(
                "Recovered the authoritative publication receipt; no execution was repeated."
                    .into(),
            );
        } else if matches!(
            attempt.state,
            AttemptState::Succeeded
                | AttemptState::Failed
                | AttemptState::Cancelled
                | AttemptState::TimedOut
                | AttemptState::ProtocolFailed
        ) {
            state.phase = "complete".into();
            state.detail = Some(
                "Recovered the authoritative terminal attempt; retained local work was not rerun."
                    .into(),
            );
        } else {
            ensure!(
                attempt.state == AttemptState::Abandoned,
                "old incarnation still has authoritative work; refusing a concurrent local claim"
            );
            state.phase = "abandoned".into();
            state.detail = Some("Old worker incarnation is abandoned. Local cancellation was requested where possible; termination is not assumed. Retry requires an explicit authority request.".into());
        }
        state.job = job;
        state.persist(&root)?;
        // No task ever receives a cache inode or descriptor. Inspecting the
        // authoritative abandonment plus retained run copies resolves this local
        // guard without deleting those copies or claiming process termination.
        if !state.job.inputs.is_empty() {
            cache.release(&state.binding.attempt_id)?;
        }
    }
    Ok(())
}
