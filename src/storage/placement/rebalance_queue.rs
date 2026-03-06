use super::*;

fn normalize_rebalance_transfer_from(from: Option<&str>) -> Option<String> {
    from.map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn rebalance_transfer_matches(
    transfer: &PendingRebalanceTransferState,
    from: &Option<String>,
    to: &str,
) -> bool {
    transfer.to == to && &transfer.from == from
}

/// Insert a pending rebalance operation unless it is already tracked by rebalance id.
pub fn enqueue_pending_rebalance_operation(
    queue: &mut PendingRebalanceQueue,
    operation: PendingRebalanceOperation,
) -> PendingRebalanceEnqueueOutcome {
    if queue
        .operations
        .iter()
        .any(|existing| existing.rebalance_id == operation.rebalance_id)
    {
        return PendingRebalanceEnqueueOutcome::AlreadyTracked;
    }
    queue.operations.push(operation);
    PendingRebalanceEnqueueOutcome::Inserted
}

/// Mark a rebalance transfer as complete and prune completed operations.
pub fn acknowledge_pending_rebalance_transfer(
    queue: &mut PendingRebalanceQueue,
    rebalance_id: &str,
    from_node: Option<&str>,
    to_node: &str,
) -> PendingRebalanceAcknowledgeOutcome {
    let rebalance_id = rebalance_id.trim();
    let to_node = to_node.trim();
    if rebalance_id.is_empty() || to_node.is_empty() {
        return PendingRebalanceAcknowledgeOutcome::NotFound;
    }
    let from_node = normalize_rebalance_transfer_from(from_node);

    let Some(op_index) = queue
        .operations
        .iter()
        .position(|op| op.rebalance_id == rebalance_id)
    else {
        return PendingRebalanceAcknowledgeOutcome::NotFound;
    };

    let Some(transfer_index) = queue.operations[op_index]
        .transfers
        .iter()
        .position(|transfer| rebalance_transfer_matches(transfer, &from_node, to_node))
    else {
        return PendingRebalanceAcknowledgeOutcome::TransferNotTracked;
    };

    let transfer = &mut queue.operations[op_index].transfers[transfer_index];
    if transfer.completed {
        return PendingRebalanceAcknowledgeOutcome::AlreadyCompleted;
    }
    transfer.completed = true;
    transfer.last_error = None;

    let remaining_transfers = queue.operations[op_index]
        .transfers
        .iter()
        .filter(|candidate| !candidate.completed)
        .count();
    if remaining_transfers == 0 {
        queue.operations.remove(op_index);
        return PendingRebalanceAcknowledgeOutcome::Updated {
            remaining_transfers: 0,
            completed: true,
        };
    }

    PendingRebalanceAcknowledgeOutcome::Updated {
        remaining_transfers,
        completed: false,
    }
}

/// Record a failed rebalance transfer attempt.
pub fn record_pending_rebalance_failure(
    queue: &mut PendingRebalanceQueue,
    rebalance_id: &str,
    from_node: Option<&str>,
    to_node: &str,
    error: Option<&str>,
) -> PendingRebalanceFailureOutcome {
    let rebalance_id = rebalance_id.trim();
    let to_node = to_node.trim();
    if rebalance_id.is_empty() || to_node.is_empty() {
        return PendingRebalanceFailureOutcome::NotFound;
    }
    let from_node = normalize_rebalance_transfer_from(from_node);

    let Some(operation) = queue
        .operations
        .iter_mut()
        .find(|operation| operation.rebalance_id == rebalance_id)
    else {
        return PendingRebalanceFailureOutcome::NotFound;
    };

    let Some(transfer) = operation
        .transfers
        .iter_mut()
        .find(|transfer| rebalance_transfer_matches(transfer, &from_node, to_node))
    else {
        return PendingRebalanceFailureOutcome::TransferNotTracked;
    };

    transfer.attempts = transfer.attempts.saturating_add(1);
    transfer.completed = false;
    transfer.last_error = error
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    PendingRebalanceFailureOutcome::Updated {
        attempts: transfer.attempts,
    }
}

/// Select due pending rebalance transfers in stable order for executor workers.
pub fn pending_rebalance_candidates(
    queue: &PendingRebalanceQueue,
    now_unix_ms: u64,
    max_candidates: usize,
) -> Vec<PendingRebalanceCandidate> {
    if max_candidates == 0 {
        return Vec::new();
    }

    let mut candidates = queue
        .operations
        .iter()
        .flat_map(|operation| {
            operation
                .transfers
                .iter()
                .filter(|transfer| !transfer.completed)
                .filter(|transfer| {
                    transfer
                        .next_retry_at_unix_ms
                        .is_none_or(|retry_at| retry_at <= now_unix_ms)
                })
                .map(|transfer| PendingRebalanceCandidate {
                    rebalance_id: operation.rebalance_id.clone(),
                    bucket: operation.bucket.clone(),
                    key: operation.key.clone(),
                    scope: operation.scope.clone(),
                    coordinator_node: operation.coordinator_node.clone(),
                    placement_epoch: operation.placement_epoch,
                    placement_view_id: operation.placement_view_id.clone(),
                    created_at_unix_ms: operation.created_at_unix_ms,
                    from: transfer.from.clone(),
                    to: transfer.to.clone(),
                    attempts: transfer.attempts,
                    next_retry_at_unix_ms: transfer.next_retry_at_unix_ms,
                })
        })
        .collect::<Vec<_>>();

    candidates.sort_by(|left, right| {
        (
            left.next_retry_at_unix_ms.unwrap_or(0),
            left.created_at_unix_ms,
            left.rebalance_id.as_str(),
            left.from.as_deref().unwrap_or(""),
            left.to.as_str(),
        )
            .cmp(&(
                right.next_retry_at_unix_ms.unwrap_or(0),
                right.created_at_unix_ms,
                right.rebalance_id.as_str(),
                right.from.as_deref().unwrap_or(""),
                right.to.as_str(),
            ))
    });
    candidates.truncate(max_candidates);
    candidates
}

/// Lease a due rebalance transfer for execution processing.
pub fn lease_pending_rebalance_transfer_for_execution(
    queue: &mut PendingRebalanceQueue,
    rebalance_id: &str,
    from_node: Option<&str>,
    to_node: &str,
    now_unix_ms: u64,
    lease_ms: u64,
) -> PendingRebalanceLeaseOutcome {
    let rebalance_id = rebalance_id.trim();
    let to_node = to_node.trim();
    if rebalance_id.is_empty() || to_node.is_empty() {
        return PendingRebalanceLeaseOutcome::NotFound;
    }
    let from_node = normalize_rebalance_transfer_from(from_node);

    let Some(operation) = queue
        .operations
        .iter_mut()
        .find(|operation| operation.rebalance_id == rebalance_id)
    else {
        return PendingRebalanceLeaseOutcome::NotFound;
    };

    let Some(transfer) = operation
        .transfers
        .iter_mut()
        .find(|transfer| rebalance_transfer_matches(transfer, &from_node, to_node))
    else {
        return PendingRebalanceLeaseOutcome::TransferNotTracked;
    };

    if transfer.completed {
        return PendingRebalanceLeaseOutcome::AlreadyCompleted;
    }

    if let Some(next_retry_at_unix_ms) = transfer.next_retry_at_unix_ms
        && next_retry_at_unix_ms > now_unix_ms
    {
        return PendingRebalanceLeaseOutcome::NotDue {
            next_retry_at_unix_ms,
        };
    }

    let lease_expires_at_unix_ms = now_unix_ms.saturating_add(lease_ms.max(1));
    transfer.next_retry_at_unix_ms = Some(lease_expires_at_unix_ms);
    PendingRebalanceLeaseOutcome::Updated {
        lease_expires_at_unix_ms,
        attempts: transfer.attempts,
    }
}

/// Record a failed rebalance transfer attempt and schedule exponential-backoff retry.
pub fn record_pending_rebalance_failure_with_backoff(
    queue: &mut PendingRebalanceQueue,
    rebalance_id: &str,
    from_node: Option<&str>,
    to_node: &str,
    error: Option<&str>,
    now_unix_ms: u64,
    policy: PendingReplicationRetryPolicy,
) -> PendingRebalanceFailureWithBackoffOutcome {
    let outcome = record_pending_rebalance_failure(queue, rebalance_id, from_node, to_node, error);
    let PendingRebalanceFailureOutcome::Updated { attempts } = outcome else {
        return match outcome {
            PendingRebalanceFailureOutcome::NotFound => {
                PendingRebalanceFailureWithBackoffOutcome::NotFound
            }
            PendingRebalanceFailureOutcome::TransferNotTracked => {
                PendingRebalanceFailureWithBackoffOutcome::TransferNotTracked
            }
            PendingRebalanceFailureOutcome::Updated { .. } => {
                PendingRebalanceFailureWithBackoffOutcome::NotFound
            }
        };
    };

    let rebalance_id = rebalance_id.trim();
    let to_node = to_node.trim();
    let from_node = normalize_rebalance_transfer_from(from_node);

    let Some(transfer) = queue
        .operations
        .iter_mut()
        .find(|operation| operation.rebalance_id == rebalance_id)
        .and_then(|operation| {
            operation
                .transfers
                .iter_mut()
                .find(|transfer| rebalance_transfer_matches(transfer, &from_node, to_node))
        })
    else {
        return PendingRebalanceFailureWithBackoffOutcome::NotFound;
    };

    let retry_delay_ms = pending_replication_retry_backoff_ms(attempts, policy);
    let next_retry_at_unix_ms = now_unix_ms.saturating_add(retry_delay_ms);
    transfer.next_retry_at_unix_ms = Some(next_retry_at_unix_ms);

    PendingRebalanceFailureWithBackoffOutcome::Updated {
        attempts,
        next_retry_at_unix_ms,
    }
}

/// Build bounded, deterministic pending-rebalance diagnostics for runtime/console metrics.
pub fn summarize_pending_rebalance_queue(
    queue: &PendingRebalanceQueue,
) -> PendingRebalanceQueueSummary {
    let mut summary = PendingRebalanceQueueSummary {
        operations: queue.operations.len(),
        ..PendingRebalanceQueueSummary::default()
    };

    for operation in &queue.operations {
        summary.oldest_created_at_unix_ms = match summary.oldest_created_at_unix_ms {
            Some(existing) => Some(existing.min(operation.created_at_unix_ms)),
            None => Some(operation.created_at_unix_ms),
        };

        for transfer in &operation.transfers {
            if !transfer.completed {
                summary.pending_transfers += 1;
            }
            if transfer.last_error.is_some() {
                summary.failed_transfers += 1;
            }
            summary.max_attempts = summary.max_attempts.max(transfer.attempts);
        }
    }

    summary
}

/// Replay due pending rebalance transfers once with persisted queue state.
///
/// The caller provides the transfer application function so runtime executors can
/// supply transfer transport behavior while queue durability/state transitions stay
/// centralized in placement.
pub fn replay_pending_rebalance_transfers_once_with_apply_fn<F>(
    path: &Path,
    now_unix_ms: u64,
    max_candidates: usize,
    lease_ms: u64,
    retry_policy: PendingReplicationRetryPolicy,
    mut apply_fn: F,
) -> std::io::Result<PendingRebalanceReplayCycleOutcome>
where
    F: FnMut(&PendingRebalanceCandidate) -> Result<(), String>,
{
    if max_candidates == 0 {
        return Ok(PendingRebalanceReplayCycleOutcome::default());
    }

    let candidates = pending_rebalance_candidates_from_disk(path, now_unix_ms, max_candidates)?;
    let mut outcome = PendingRebalanceReplayCycleOutcome::default();

    for candidate in candidates {
        outcome.scanned_transfers = outcome.scanned_transfers.saturating_add(1);
        let lease_outcome = lease_pending_rebalance_transfer_for_execution_persisted(
            path,
            candidate.rebalance_id.as_str(),
            candidate.from.as_deref(),
            candidate.to.as_str(),
            now_unix_ms,
            lease_ms,
        )?;
        if !matches!(lease_outcome, PendingRebalanceLeaseOutcome::Updated { .. }) {
            outcome.skipped_transfers = outcome.skipped_transfers.saturating_add(1);
            continue;
        }
        outcome.leased_transfers = outcome.leased_transfers.saturating_add(1);

        match apply_fn(&candidate) {
            Ok(()) => {
                let ack_outcome = acknowledge_pending_rebalance_transfer_persisted(
                    path,
                    candidate.rebalance_id.as_str(),
                    candidate.from.as_deref(),
                    candidate.to.as_str(),
                )?;
                if matches!(
                    ack_outcome,
                    PendingRebalanceAcknowledgeOutcome::Updated { .. }
                ) {
                    outcome.acknowledged_transfers =
                        outcome.acknowledged_transfers.saturating_add(1);
                } else {
                    outcome.skipped_transfers = outcome.skipped_transfers.saturating_add(1);
                }
            }
            Err(error) => {
                let failure_outcome = record_pending_rebalance_failure_with_backoff_persisted(
                    path,
                    candidate.rebalance_id.as_str(),
                    candidate.from.as_deref(),
                    candidate.to.as_str(),
                    Some(error.as_str()),
                    now_unix_ms,
                    retry_policy,
                )?;
                if matches!(
                    failure_outcome,
                    PendingRebalanceFailureWithBackoffOutcome::Updated { .. }
                ) {
                    outcome.failed_transfers = outcome.failed_transfers.saturating_add(1);
                } else {
                    outcome.skipped_transfers = outcome.skipped_transfers.saturating_add(1);
                }
            }
        }
    }

    Ok(outcome)
}

/// Load the pending rebalance queue snapshot from disk.
///
/// Missing files are treated as an empty queue.
pub fn load_pending_rebalance_queue(path: &Path) -> std::io::Result<PendingRebalanceQueue> {
    match std::fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str::<PendingRebalanceQueue>(&raw)
            .map_err(|error| std::io::Error::new(ErrorKind::InvalidData, error)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(PendingRebalanceQueue::default()),
        Err(error) => Err(error),
    }
}

/// Persist the pending rebalance queue snapshot using atomic replace semantics.
pub fn persist_pending_rebalance_queue(
    path: &Path,
    queue: &PendingRebalanceQueue,
) -> std::io::Result<()> {
    let Some(parent) = path.parent() else {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "rebalance queue path must include parent directory",
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
            .unwrap_or("pending-rebalance"),
        std::process::id(),
        nanos_since_epoch
    );
    let temp_path = parent.join(temp_file_name);
    std::fs::write(&temp_path, payload)?;
    if let Err(error) = std::fs::rename(&temp_path, path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(error);
    }
    Ok(())
}

/// Insert a pending rebalance operation with persisted queue state.
pub fn enqueue_pending_rebalance_operation_persisted(
    path: &Path,
    operation: PendingRebalanceOperation,
) -> std::io::Result<PendingRebalanceEnqueueOutcome> {
    let mut queue = load_pending_rebalance_queue(path)?;
    let outcome = enqueue_pending_rebalance_operation(&mut queue, operation);
    if matches!(outcome, PendingRebalanceEnqueueOutcome::Inserted) {
        persist_pending_rebalance_queue(path, &queue)?;
    }
    Ok(outcome)
}

/// Acknowledge a pending rebalance transfer with persisted queue state.
pub fn acknowledge_pending_rebalance_transfer_persisted(
    path: &Path,
    rebalance_id: &str,
    from_node: Option<&str>,
    to_node: &str,
) -> std::io::Result<PendingRebalanceAcknowledgeOutcome> {
    let mut queue = load_pending_rebalance_queue(path)?;
    let outcome =
        acknowledge_pending_rebalance_transfer(&mut queue, rebalance_id, from_node, to_node);
    if matches!(outcome, PendingRebalanceAcknowledgeOutcome::Updated { .. }) {
        persist_pending_rebalance_queue(path, &queue)?;
    }
    Ok(outcome)
}

/// Record a rebalance transfer failure with persisted queue state.
pub fn record_pending_rebalance_failure_persisted(
    path: &Path,
    rebalance_id: &str,
    from_node: Option<&str>,
    to_node: &str,
    error: Option<&str>,
) -> std::io::Result<PendingRebalanceFailureOutcome> {
    let mut queue = load_pending_rebalance_queue(path)?;
    let outcome =
        record_pending_rebalance_failure(&mut queue, rebalance_id, from_node, to_node, error);
    if matches!(outcome, PendingRebalanceFailureOutcome::Updated { .. }) {
        persist_pending_rebalance_queue(path, &queue)?;
    }
    Ok(outcome)
}

/// Lease a due pending rebalance transfer with persisted queue state.
pub fn lease_pending_rebalance_transfer_for_execution_persisted(
    path: &Path,
    rebalance_id: &str,
    from_node: Option<&str>,
    to_node: &str,
    now_unix_ms: u64,
    lease_ms: u64,
) -> std::io::Result<PendingRebalanceLeaseOutcome> {
    let mut queue = load_pending_rebalance_queue(path)?;
    let outcome = lease_pending_rebalance_transfer_for_execution(
        &mut queue,
        rebalance_id,
        from_node,
        to_node,
        now_unix_ms,
        lease_ms,
    );
    if matches!(outcome, PendingRebalanceLeaseOutcome::Updated { .. }) {
        persist_pending_rebalance_queue(path, &queue)?;
    }
    Ok(outcome)
}

/// Record a failed rebalance transfer attempt with backoff scheduling using persisted queue state.
pub fn record_pending_rebalance_failure_with_backoff_persisted(
    path: &Path,
    rebalance_id: &str,
    from_node: Option<&str>,
    to_node: &str,
    error: Option<&str>,
    now_unix_ms: u64,
    policy: PendingReplicationRetryPolicy,
) -> std::io::Result<PendingRebalanceFailureWithBackoffOutcome> {
    let mut queue = load_pending_rebalance_queue(path)?;
    let outcome = record_pending_rebalance_failure_with_backoff(
        &mut queue,
        rebalance_id,
        from_node,
        to_node,
        error,
        now_unix_ms,
        policy,
    );
    if matches!(
        outcome,
        PendingRebalanceFailureWithBackoffOutcome::Updated { .. }
    ) {
        persist_pending_rebalance_queue(path, &queue)?;
    }
    Ok(outcome)
}

/// Load persisted rebalance queue state and select due execution candidates in stable order.
pub fn pending_rebalance_candidates_from_disk(
    path: &Path,
    now_unix_ms: u64,
    max_candidates: usize,
) -> std::io::Result<Vec<PendingRebalanceCandidate>> {
    let queue = load_pending_rebalance_queue(path)?;
    Ok(pending_rebalance_candidates(
        &queue,
        now_unix_ms,
        max_candidates,
    ))
}

/// Load persisted rebalance queue state and project deterministic queue diagnostics.
pub fn summarize_pending_rebalance_queue_from_disk(
    path: &Path,
) -> std::io::Result<PendingRebalanceQueueSummary> {
    let queue = load_pending_rebalance_queue(path)?;
    Ok(summarize_pending_rebalance_queue(&queue))
}
