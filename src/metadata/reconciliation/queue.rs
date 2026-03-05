use std::cell::RefCell;
use std::fs::File;
use std::io::ErrorKind;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use super::*;

pub fn enqueue_pending_metadata_repair_plan(
    queue: &mut PendingMetadataRepairQueue,
    pending_plan: PendingMetadataRepairPlan,
) -> PendingMetadataRepairEnqueueOutcome {
    if queue
        .plans
        .iter()
        .any(|existing| existing.repair_id == pending_plan.repair_id)
    {
        return PendingMetadataRepairEnqueueOutcome::AlreadyTracked;
    }
    queue.plans.push(pending_plan);
    PendingMetadataRepairEnqueueOutcome::Inserted
}

pub fn acknowledge_pending_metadata_repair_plan(
    queue: &mut PendingMetadataRepairQueue,
    repair_id: &str,
) -> PendingMetadataRepairAcknowledgeOutcome {
    let repair_id = repair_id.trim();
    if repair_id.is_empty() {
        return PendingMetadataRepairAcknowledgeOutcome::NotFound;
    }

    let Some(index) = queue
        .plans
        .iter()
        .position(|plan| plan.repair_id == repair_id)
    else {
        return PendingMetadataRepairAcknowledgeOutcome::NotFound;
    };
    queue.plans.remove(index);
    PendingMetadataRepairAcknowledgeOutcome::Acknowledged
}

pub fn record_pending_metadata_repair_failure(
    queue: &mut PendingMetadataRepairQueue,
    repair_id: &str,
    error: Option<&str>,
) -> PendingMetadataRepairFailureOutcome {
    let repair_id = repair_id.trim();
    if repair_id.is_empty() {
        return PendingMetadataRepairFailureOutcome::NotFound;
    }

    let Some(plan) = queue
        .plans
        .iter_mut()
        .find(|existing| existing.repair_id == repair_id)
    else {
        return PendingMetadataRepairFailureOutcome::NotFound;
    };

    plan.attempts = plan.attempts.saturating_add(1);
    plan.last_error = error
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    PendingMetadataRepairFailureOutcome::Updated {
        attempts: plan.attempts,
    }
}

pub fn pending_metadata_repair_candidates(
    queue: &PendingMetadataRepairQueue,
    now_unix_ms: u64,
    max_candidates: usize,
) -> Vec<PendingMetadataRepairCandidate> {
    if max_candidates == 0 {
        return Vec::new();
    }
    let mut candidates = queue
        .plans
        .iter()
        .filter(|plan| {
            plan.next_retry_at_unix_ms
                .is_none_or(|next_retry_at_unix_ms| next_retry_at_unix_ms <= now_unix_ms)
        })
        .map(|plan| PendingMetadataRepairCandidate {
            repair_id: plan.repair_id.clone(),
            source_view_id: plan.plan.source_view_id.clone(),
            target_view_id: plan.plan.target_view_id.clone(),
            attempts: plan.attempts,
            created_at_unix_ms: plan.created_at_unix_ms,
            next_retry_at_unix_ms: plan.next_retry_at_unix_ms,
        })
        .collect::<Vec<_>>();

    candidates.sort_by(|left, right| {
        (
            left.next_retry_at_unix_ms.unwrap_or(0),
            left.created_at_unix_ms,
            left.repair_id.as_str(),
        )
            .cmp(&(
                right.next_retry_at_unix_ms.unwrap_or(0),
                right.created_at_unix_ms,
                right.repair_id.as_str(),
            ))
    });
    candidates.truncate(max_candidates);
    candidates
}

pub fn lease_pending_metadata_repair_plan_for_execution(
    queue: &mut PendingMetadataRepairQueue,
    repair_id: &str,
    now_unix_ms: u64,
    lease_ms: u64,
) -> PendingMetadataRepairLeaseOutcome {
    let repair_id = repair_id.trim();
    if repair_id.is_empty() {
        return PendingMetadataRepairLeaseOutcome::NotFound;
    }

    let Some(plan) = queue
        .plans
        .iter_mut()
        .find(|existing| existing.repair_id == repair_id)
    else {
        return PendingMetadataRepairLeaseOutcome::NotFound;
    };

    if let Some(next_retry_at_unix_ms) = plan.next_retry_at_unix_ms {
        if next_retry_at_unix_ms > now_unix_ms {
            return PendingMetadataRepairLeaseOutcome::NotDue {
                next_retry_at_unix_ms,
            };
        }
    }

    let lease_expires_at_unix_ms = now_unix_ms.saturating_add(lease_ms.max(1));
    plan.next_retry_at_unix_ms = Some(lease_expires_at_unix_ms);
    PendingMetadataRepairLeaseOutcome::Updated {
        attempts: plan.attempts,
        lease_expires_at_unix_ms,
    }
}

pub fn metadata_repair_retry_backoff_ms(
    base_delay_ms: u64,
    max_delay_ms: u64,
    attempts: u32,
) -> u64 {
    let normalized_base = base_delay_ms.max(1);
    let normalized_max = max_delay_ms.max(normalized_base);
    let shift = attempts.saturating_sub(1).min(20);
    let multiplier = 1_u64 << shift;
    normalized_base
        .saturating_mul(multiplier)
        .min(normalized_max)
}

pub fn record_pending_metadata_repair_failure_with_backoff(
    queue: &mut PendingMetadataRepairQueue,
    repair_id: &str,
    error: Option<&str>,
    now_unix_ms: u64,
    base_delay_ms: u64,
    max_delay_ms: u64,
) -> PendingMetadataRepairFailureWithBackoffOutcome {
    let failure_outcome = record_pending_metadata_repair_failure(queue, repair_id, error);
    let PendingMetadataRepairFailureOutcome::Updated { attempts } = failure_outcome else {
        return PendingMetadataRepairFailureWithBackoffOutcome::NotFound;
    };
    let repair_id = repair_id.trim();
    let Some(plan) = queue
        .plans
        .iter_mut()
        .find(|existing| existing.repair_id == repair_id)
    else {
        return PendingMetadataRepairFailureWithBackoffOutcome::NotFound;
    };

    let retry_delay_ms = metadata_repair_retry_backoff_ms(base_delay_ms, max_delay_ms, attempts);
    let next_retry_at_unix_ms = now_unix_ms.saturating_add(retry_delay_ms);
    plan.next_retry_at_unix_ms = Some(next_retry_at_unix_ms);
    PendingMetadataRepairFailureWithBackoffOutcome::Updated {
        attempts,
        next_retry_at_unix_ms,
    }
}

pub fn summarize_pending_metadata_repair_queue(
    queue: &PendingMetadataRepairQueue,
    now_unix_ms: u64,
) -> PendingMetadataRepairQueueSummary {
    let mut summary = PendingMetadataRepairQueueSummary {
        plans: queue.plans.len(),
        ..PendingMetadataRepairQueueSummary::default()
    };
    for plan in &queue.plans {
        summary.oldest_created_at_unix_ms = match summary.oldest_created_at_unix_ms {
            Some(existing) => Some(existing.min(plan.created_at_unix_ms)),
            None => Some(plan.created_at_unix_ms),
        };
        if plan.last_error.is_some() {
            summary.failed_plans += 1;
        }
        if plan
            .next_retry_at_unix_ms
            .is_none_or(|next_retry_at_unix_ms| next_retry_at_unix_ms <= now_unix_ms)
        {
            summary.due_plans += 1;
        }
        summary.max_attempts = summary.max_attempts.max(plan.attempts);
    }
    summary
}

pub fn replay_pending_metadata_repairs_once_with_apply_fn<F>(
    path: &Path,
    now_unix_ms: u64,
    max_candidates: usize,
    lease_ms: u64,
    backoff_base_ms: u64,
    backoff_max_ms: u64,
    mut apply_fn: F,
) -> std::io::Result<PendingMetadataRepairReplayCycleOutcome>
where
    F: FnMut(&PendingMetadataRepairPlan) -> Result<(), String>,
{
    replay_pending_metadata_repairs_once_with_classified_apply_fn(
        path,
        now_unix_ms,
        max_candidates,
        lease_ms,
        backoff_base_ms,
        backoff_max_ms,
        |pending_plan| apply_fn(pending_plan).map_err(PendingMetadataRepairApplyFailure::transient),
    )
}

pub fn replay_pending_metadata_repairs_once_with_classified_apply_fn<F>(
    path: &Path,
    now_unix_ms: u64,
    max_candidates: usize,
    lease_ms: u64,
    backoff_base_ms: u64,
    backoff_max_ms: u64,
    mut apply_fn: F,
) -> std::io::Result<PendingMetadataRepairReplayCycleOutcome>
where
    F: FnMut(&PendingMetadataRepairPlan) -> Result<(), PendingMetadataRepairApplyFailure>,
{
    if max_candidates == 0 {
        return Ok(PendingMetadataRepairReplayCycleOutcome::default());
    }

    let queue = load_pending_metadata_repair_queue(path)?;
    let candidates = pending_metadata_repair_candidates(&queue, now_unix_ms, max_candidates);
    let mut outcome = PendingMetadataRepairReplayCycleOutcome::default();

    for candidate in candidates {
        outcome.scanned_plans = outcome.scanned_plans.saturating_add(1);

        let lease_outcome = lease_pending_metadata_repair_plan_for_execution_persisted(
            path,
            candidate.repair_id.as_str(),
            now_unix_ms,
            lease_ms,
        )?;
        if !matches!(
            lease_outcome,
            PendingMetadataRepairLeaseOutcome::Updated { .. }
        ) {
            outcome.skipped_plans = outcome.skipped_plans.saturating_add(1);
            continue;
        }
        outcome.leased_plans = outcome.leased_plans.saturating_add(1);

        let pending_plan = load_pending_metadata_repair_plan_from_disk(path, &candidate.repair_id)?
            .filter(|plan| plan.repair_id == candidate.repair_id);
        let Some(pending_plan) = pending_plan else {
            outcome.skipped_plans = outcome.skipped_plans.saturating_add(1);
            continue;
        };

        match apply_fn(&pending_plan) {
            Ok(()) => {
                let ack_outcome =
                    acknowledge_pending_metadata_repair_plan_persisted(path, &candidate.repair_id)?;
                if matches!(
                    ack_outcome,
                    PendingMetadataRepairAcknowledgeOutcome::Acknowledged
                ) {
                    outcome.acknowledged_plans = outcome.acknowledged_plans.saturating_add(1);
                } else {
                    outcome.skipped_plans = outcome.skipped_plans.saturating_add(1);
                }
            }
            Err(error) if error.is_permanent() => {
                let acknowledge_outcome =
                    acknowledge_pending_metadata_repair_plan_persisted(path, &candidate.repair_id)?;
                if matches!(
                    acknowledge_outcome,
                    PendingMetadataRepairAcknowledgeOutcome::Acknowledged
                ) {
                    outcome.dropped_plans = outcome.dropped_plans.saturating_add(1);
                } else {
                    outcome.skipped_plans = outcome.skipped_plans.saturating_add(1);
                }
            }
            Err(error) => {
                let failure_outcome =
                    record_pending_metadata_repair_failure_with_backoff_persisted(
                        path,
                        candidate.repair_id.as_str(),
                        error.message(),
                        now_unix_ms,
                        backoff_base_ms,
                        backoff_max_ms,
                    )?;
                if matches!(
                    failure_outcome,
                    PendingMetadataRepairFailureWithBackoffOutcome::Updated { .. }
                ) {
                    outcome.failed_plans = outcome.failed_plans.saturating_add(1);
                } else {
                    outcome.skipped_plans = outcome.skipped_plans.saturating_add(1);
                }
            }
        }
    }

    Ok(outcome)
}

pub fn replay_pending_metadata_repairs_once_with_persisted_state_apply(
    queue_path: &Path,
    metadata_state_path: &Path,
    now_unix_ms: u64,
    max_candidates: usize,
    lease_ms: u64,
    backoff_base_ms: u64,
    backoff_max_ms: u64,
) -> std::io::Result<PendingMetadataRepairReplayCycleOutcome> {
    let replay = PendingMetadataRepairReplayExecutionConfig {
        now_unix_ms,
        max_candidates,
        lease_ms,
        backoff_base_ms,
        backoff_max_ms,
    };
    replay_pending_metadata_repairs_once_with_persisted_state_apply_and_observer(
        queue_path,
        metadata_state_path,
        replay,
        |_| {},
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingMetadataRepairReplayExecutionConfig {
    pub now_unix_ms: u64,
    pub max_candidates: usize,
    pub lease_ms: u64,
    pub backoff_base_ms: u64,
    pub backoff_max_ms: u64,
}

pub fn replay_pending_metadata_repairs_once_with_persisted_state_apply_and_observer<ObserverFn>(
    queue_path: &Path,
    metadata_state_path: &Path,
    replay: PendingMetadataRepairReplayExecutionConfig,
    on_permanent_failure: ObserverFn,
) -> std::io::Result<PendingMetadataRepairReplayCycleOutcome>
where
    ObserverFn: FnMut(&PendingMetadataRepairApplyFailure),
{
    let on_permanent_failure = RefCell::new(on_permanent_failure);
    replay_pending_metadata_repairs_once_with_classified_apply_fn(
        queue_path,
        replay.now_unix_ms,
        replay.max_candidates,
        replay.lease_ms,
        replay.backoff_base_ms,
        replay.backoff_max_ms,
        |pending_plan| {
            apply_pending_metadata_repair_plan_to_persisted_state_classified(
                metadata_state_path,
                pending_plan,
            )
            .inspect_err(|error| {
                if error.is_permanent() {
                    on_permanent_failure.borrow_mut()(error);
                }
            })
            .map(|_| ())
        },
    )
}

fn load_pending_metadata_repair_plan_from_disk(
    path: &Path,
    repair_id: &str,
) -> std::io::Result<Option<PendingMetadataRepairPlan>> {
    let repair_id = repair_id.trim();
    if repair_id.is_empty() {
        return Ok(None);
    }
    let queue = load_pending_metadata_repair_queue(path)?;
    Ok(queue
        .plans
        .into_iter()
        .find(|plan| plan.repair_id == repair_id))
}

pub fn load_pending_metadata_repair_queue(
    path: &Path,
) -> std::io::Result<PendingMetadataRepairQueue> {
    match std::fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str::<PendingMetadataRepairQueue>(&raw)
            .map_err(|error| std::io::Error::new(ErrorKind::InvalidData, error)),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            Ok(PendingMetadataRepairQueue::default())
        }
        Err(error) => Err(error),
    }
}

pub fn persist_pending_metadata_repair_queue(
    path: &Path,
    queue: &PendingMetadataRepairQueue,
) -> std::io::Result<()> {
    let Some(parent) = path.parent() else {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "metadata repair queue path must include parent directory",
        ));
    };
    std::fs::create_dir_all(parent)?;
    let payload = serde_json::to_vec_pretty(queue)
        .map_err(|error| std::io::Error::new(ErrorKind::InvalidData, error))?;
    let nanos_since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let temp_file_name = format!(
        ".{}.tmp-{}-{}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("pending-metadata-repair"),
        std::process::id(),
        nanos_since_epoch
    );
    let temp_path = parent.join(temp_file_name);
    let mut temp_file = File::create(&temp_path)?;
    temp_file.write_all(payload.as_slice())?;
    temp_file.sync_all()?;
    drop(temp_file);
    if let Err(error) = std::fs::rename(&temp_path, path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(error);
    }
    Ok(())
}

pub fn enqueue_pending_metadata_repair_plan_persisted(
    path: &Path,
    pending_plan: PendingMetadataRepairPlan,
) -> std::io::Result<PendingMetadataRepairEnqueueOutcome> {
    let mut queue = load_pending_metadata_repair_queue(path)?;
    let outcome = enqueue_pending_metadata_repair_plan(&mut queue, pending_plan);
    if matches!(outcome, PendingMetadataRepairEnqueueOutcome::Inserted) {
        persist_pending_metadata_repair_queue(path, &queue)?;
    }
    Ok(outcome)
}

pub fn acknowledge_pending_metadata_repair_plan_persisted(
    path: &Path,
    repair_id: &str,
) -> std::io::Result<PendingMetadataRepairAcknowledgeOutcome> {
    let mut queue = load_pending_metadata_repair_queue(path)?;
    let outcome = acknowledge_pending_metadata_repair_plan(&mut queue, repair_id);
    if matches!(
        outcome,
        PendingMetadataRepairAcknowledgeOutcome::Acknowledged
    ) {
        persist_pending_metadata_repair_queue(path, &queue)?;
    }
    Ok(outcome)
}

pub fn record_pending_metadata_repair_failure_with_backoff_persisted(
    path: &Path,
    repair_id: &str,
    error: Option<&str>,
    now_unix_ms: u64,
    base_delay_ms: u64,
    max_delay_ms: u64,
) -> std::io::Result<PendingMetadataRepairFailureWithBackoffOutcome> {
    let mut queue = load_pending_metadata_repair_queue(path)?;
    let outcome = record_pending_metadata_repair_failure_with_backoff(
        &mut queue,
        repair_id,
        error,
        now_unix_ms,
        base_delay_ms,
        max_delay_ms,
    );
    if matches!(
        outcome,
        PendingMetadataRepairFailureWithBackoffOutcome::Updated { .. }
    ) {
        persist_pending_metadata_repair_queue(path, &queue)?;
    }
    Ok(outcome)
}

pub fn lease_pending_metadata_repair_plan_for_execution_persisted(
    path: &Path,
    repair_id: &str,
    now_unix_ms: u64,
    lease_ms: u64,
) -> std::io::Result<PendingMetadataRepairLeaseOutcome> {
    let mut queue = load_pending_metadata_repair_queue(path)?;
    let outcome = lease_pending_metadata_repair_plan_for_execution(
        &mut queue,
        repair_id,
        now_unix_ms,
        lease_ms,
    );
    if matches!(outcome, PendingMetadataRepairLeaseOutcome::Updated { .. }) {
        persist_pending_metadata_repair_queue(path, &queue)?;
    }
    Ok(outcome)
}

pub fn pending_metadata_repair_candidates_from_disk(
    path: &Path,
    now_unix_ms: u64,
    max_candidates: usize,
) -> std::io::Result<Vec<PendingMetadataRepairCandidate>> {
    let queue = load_pending_metadata_repair_queue(path)?;
    Ok(pending_metadata_repair_candidates(
        &queue,
        now_unix_ms,
        max_candidates,
    ))
}

pub fn summarize_pending_metadata_repair_queue_from_disk(
    path: &Path,
    now_unix_ms: u64,
) -> std::io::Result<PendingMetadataRepairQueueSummary> {
    let queue = load_pending_metadata_repair_queue(path)?;
    Ok(summarize_pending_metadata_repair_queue(&queue, now_unix_ms))
}
