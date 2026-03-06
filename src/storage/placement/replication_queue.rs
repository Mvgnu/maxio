use super::*;

#[derive(Debug, Clone)]
pub struct PendingReplicationFromQuorumInput<'a> {
    pub operation: ReplicationMutationOperation,
    pub idempotency_key: &'a str,
    pub bucket: &'a str,
    pub key: &'a str,
    pub version_id: Option<&'a str>,
    pub coordinator_node: &'a str,
    pub placement: &'a PlacementViewState,
    pub outcome: &'a ObjectWriteQuorumOutcome,
    pub created_at_unix_ms: u64,
}

pub fn pending_replication_operation_from_quorum_outcome(
    input: PendingReplicationFromQuorumInput<'_>,
) -> Option<PendingReplicationOperation> {
    let mut target_nodes = input.outcome.pending_nodes.clone();
    for node in &input.outcome.rejected_nodes {
        if !target_nodes.iter().any(|pending| pending == node) {
            target_nodes.push(node.clone());
        }
    }

    PendingReplicationOperation::new(
        input.idempotency_key,
        input.operation,
        input.bucket,
        input.key,
        input.version_id,
        input.coordinator_node,
        input.placement,
        target_nodes.as_slice(),
        input.created_at_unix_ms,
    )
}

/// Insert a pending replication operation unless it is already tracked by idempotency key.
pub fn enqueue_pending_replication_operation(
    queue: &mut PendingReplicationQueue,
    operation: PendingReplicationOperation,
) -> PendingReplicationEnqueueOutcome {
    if queue
        .operations
        .iter()
        .any(|existing| existing.idempotency_key == operation.idempotency_key)
    {
        return PendingReplicationEnqueueOutcome::AlreadyTracked;
    }
    queue.operations.push(operation);
    PendingReplicationEnqueueOutcome::Inserted
}

/// Mark a replication target as acknowledged and prune completed operations.
pub fn acknowledge_pending_replication_target(
    queue: &mut PendingReplicationQueue,
    idempotency_key: &str,
    target_node: &str,
) -> PendingReplicationAcknowledgeOutcome {
    let idempotency_key = idempotency_key.trim();
    let target_node = target_node.trim();
    if idempotency_key.is_empty() || target_node.is_empty() {
        return PendingReplicationAcknowledgeOutcome::NotFound;
    }

    let Some(op_index) = queue
        .operations
        .iter()
        .position(|op| op.idempotency_key == idempotency_key)
    else {
        return PendingReplicationAcknowledgeOutcome::NotFound;
    };

    let Some(target_index) = queue.operations[op_index]
        .targets
        .iter()
        .position(|target| target.node == target_node)
    else {
        return PendingReplicationAcknowledgeOutcome::TargetNotTracked;
    };

    let target = &mut queue.operations[op_index].targets[target_index];
    if target.acked {
        return PendingReplicationAcknowledgeOutcome::AlreadyAcked;
    }
    target.acked = true;
    target.last_error = None;

    let remaining_targets = queue.operations[op_index]
        .targets
        .iter()
        .filter(|candidate| !candidate.acked)
        .count();
    if remaining_targets == 0 {
        queue.operations.remove(op_index);
        return PendingReplicationAcknowledgeOutcome::Updated {
            remaining_targets: 0,
            completed: true,
        };
    }

    PendingReplicationAcknowledgeOutcome::Updated {
        remaining_targets,
        completed: false,
    }
}

/// Record a failed replication attempt for a tracked target.
pub fn record_pending_replication_failure(
    queue: &mut PendingReplicationQueue,
    idempotency_key: &str,
    target_node: &str,
    error: Option<&str>,
) -> PendingReplicationFailureOutcome {
    let idempotency_key = idempotency_key.trim();
    let target_node = target_node.trim();
    if idempotency_key.is_empty() || target_node.is_empty() {
        return PendingReplicationFailureOutcome::NotFound;
    }

    let Some(operation) = queue
        .operations
        .iter_mut()
        .find(|op| op.idempotency_key == idempotency_key)
    else {
        return PendingReplicationFailureOutcome::NotFound;
    };

    let Some(target) = operation
        .targets
        .iter_mut()
        .find(|candidate| candidate.node == target_node)
    else {
        return PendingReplicationFailureOutcome::TargetNotTracked;
    };

    target.attempts = target.attempts.saturating_add(1);
    target.acked = false;
    target.last_error = error
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    PendingReplicationFailureOutcome::Updated {
        attempts: target.attempts,
    }
}

/// Compute exponential backoff delay for pending replication retries.
pub fn pending_replication_retry_backoff_ms(
    attempts: u32,
    policy: PendingReplicationRetryPolicy,
) -> u64 {
    let policy = policy.normalized();
    let shift = attempts.saturating_sub(1).min(20);
    let multiplier = 1_u64 << shift;
    policy
        .base_delay_ms
        .saturating_mul(multiplier)
        .min(policy.max_delay_ms)
}

/// Select due pending replication targets in stable order for replay workers.
pub fn pending_replication_replay_candidates(
    queue: &PendingReplicationQueue,
    now_unix_ms: u64,
    max_candidates: usize,
) -> Vec<PendingReplicationReplayCandidate> {
    if max_candidates == 0 {
        return Vec::new();
    }

    let mut candidates = queue
        .operations
        .iter()
        .flat_map(|operation| {
            operation
                .targets
                .iter()
                .filter(|target| !target.acked)
                .filter(|target| {
                    target
                        .next_retry_at_unix_ms
                        .is_none_or(|retry_at| retry_at <= now_unix_ms)
                })
                .map(|target| PendingReplicationReplayCandidate {
                    idempotency_key: operation.idempotency_key.clone(),
                    operation: operation.operation,
                    bucket: operation.bucket.clone(),
                    key: operation.key.clone(),
                    version_id: operation.version_id.clone(),
                    coordinator_node: operation.coordinator_node.clone(),
                    placement_epoch: operation.placement_epoch,
                    placement_view_id: operation.placement_view_id.clone(),
                    created_at_unix_ms: operation.created_at_unix_ms,
                    target_node: target.node.clone(),
                    attempts: target.attempts,
                    next_retry_at_unix_ms: target.next_retry_at_unix_ms,
                })
        })
        .collect::<Vec<_>>();

    candidates.sort_by(|left, right| {
        (
            left.next_retry_at_unix_ms.unwrap_or(0),
            left.created_at_unix_ms,
            left.idempotency_key.as_str(),
            left.target_node.as_str(),
        )
            .cmp(&(
                right.next_retry_at_unix_ms.unwrap_or(0),
                right.created_at_unix_ms,
                right.idempotency_key.as_str(),
                right.target_node.as_str(),
            ))
    });
    candidates.truncate(max_candidates);
    candidates
}

/// Lease a due pending replication target for replay processing.
pub fn lease_pending_replication_target_for_replay(
    queue: &mut PendingReplicationQueue,
    idempotency_key: &str,
    target_node: &str,
    now_unix_ms: u64,
    lease_ms: u64,
) -> PendingReplicationReplayLeaseOutcome {
    let idempotency_key = idempotency_key.trim();
    let target_node = target_node.trim();
    if idempotency_key.is_empty() || target_node.is_empty() {
        return PendingReplicationReplayLeaseOutcome::NotFound;
    }

    let Some(operation) = queue
        .operations
        .iter_mut()
        .find(|operation| operation.idempotency_key == idempotency_key)
    else {
        return PendingReplicationReplayLeaseOutcome::NotFound;
    };

    let Some(target) = operation
        .targets
        .iter_mut()
        .find(|target| target.node == target_node)
    else {
        return PendingReplicationReplayLeaseOutcome::TargetNotTracked;
    };

    if target.acked {
        return PendingReplicationReplayLeaseOutcome::AlreadyAcked;
    }

    if let Some(next_retry_at_unix_ms) = target.next_retry_at_unix_ms
        && next_retry_at_unix_ms > now_unix_ms
    {
        return PendingReplicationReplayLeaseOutcome::NotDue {
            next_retry_at_unix_ms,
        };
    }

    let lease_expires_at_unix_ms = now_unix_ms.saturating_add(lease_ms.max(1));
    target.next_retry_at_unix_ms = Some(lease_expires_at_unix_ms);
    PendingReplicationReplayLeaseOutcome::Updated {
        lease_expires_at_unix_ms,
        attempts: target.attempts,
    }
}

/// Record a failed replication attempt and schedule exponential-backoff retry.
pub fn record_pending_replication_failure_with_backoff(
    queue: &mut PendingReplicationQueue,
    idempotency_key: &str,
    target_node: &str,
    error: Option<&str>,
    now_unix_ms: u64,
    policy: PendingReplicationRetryPolicy,
) -> PendingReplicationFailureWithBackoffOutcome {
    let outcome = record_pending_replication_failure(queue, idempotency_key, target_node, error);
    let PendingReplicationFailureOutcome::Updated { attempts } = outcome else {
        return match outcome {
            PendingReplicationFailureOutcome::NotFound => {
                PendingReplicationFailureWithBackoffOutcome::NotFound
            }
            PendingReplicationFailureOutcome::TargetNotTracked => {
                PendingReplicationFailureWithBackoffOutcome::TargetNotTracked
            }
            PendingReplicationFailureOutcome::Updated { .. } => {
                PendingReplicationFailureWithBackoffOutcome::NotFound
            }
        };
    };

    let idempotency_key = idempotency_key.trim();
    let target_node = target_node.trim();
    let Some(target) = queue
        .operations
        .iter_mut()
        .find(|operation| operation.idempotency_key == idempotency_key)
        .and_then(|operation| {
            operation
                .targets
                .iter_mut()
                .find(|target| target.node == target_node)
        })
    else {
        return PendingReplicationFailureWithBackoffOutcome::NotFound;
    };

    let retry_delay_ms = pending_replication_retry_backoff_ms(attempts, policy);
    let next_retry_at_unix_ms = now_unix_ms.saturating_add(retry_delay_ms);
    target.next_retry_at_unix_ms = Some(next_retry_at_unix_ms);

    PendingReplicationFailureWithBackoffOutcome::Updated {
        attempts,
        next_retry_at_unix_ms,
    }
}

/// Build bounded, deterministic queue diagnostics for runtime/console metrics.
pub fn summarize_pending_replication_queue(
    queue: &PendingReplicationQueue,
) -> PendingReplicationQueueSummary {
    let mut summary = PendingReplicationQueueSummary {
        operations: queue.operations.len(),
        ..PendingReplicationQueueSummary::default()
    };

    for operation in &queue.operations {
        summary.oldest_created_at_unix_ms = match summary.oldest_created_at_unix_ms {
            Some(existing) => Some(existing.min(operation.created_at_unix_ms)),
            None => Some(operation.created_at_unix_ms),
        };

        for target in &operation.targets {
            if !target.acked {
                summary.pending_targets += 1;
            }
            if target.last_error.is_some() {
                summary.failed_targets += 1;
            }
            summary.max_attempts = summary.max_attempts.max(target.attempts);
        }
    }

    summary
}

/// Load the pending replication queue snapshot from disk.
///
/// Missing files are treated as an empty queue.
pub fn load_pending_replication_queue(path: &Path) -> std::io::Result<PendingReplicationQueue> {
    match std::fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str::<PendingReplicationQueue>(&raw)
            .map_err(|error| std::io::Error::new(ErrorKind::InvalidData, error)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(PendingReplicationQueue::default()),
        Err(error) => Err(error),
    }
}

/// Persist the pending replication queue snapshot using atomic replace semantics.
pub fn persist_pending_replication_queue(
    path: &Path,
    queue: &PendingReplicationQueue,
) -> std::io::Result<()> {
    let Some(parent) = path.parent() else {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "queue path must include parent directory",
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
            .unwrap_or("pending-replication"),
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

/// Insert a pending replication operation with persisted queue state.
pub fn enqueue_pending_replication_operation_persisted(
    path: &Path,
    operation: PendingReplicationOperation,
) -> std::io::Result<PendingReplicationEnqueueOutcome> {
    let mut queue = load_pending_replication_queue(path)?;
    let outcome = enqueue_pending_replication_operation(&mut queue, operation);
    if matches!(outcome, PendingReplicationEnqueueOutcome::Inserted) {
        persist_pending_replication_queue(path, &queue)?;
    }
    Ok(outcome)
}

/// Acknowledge a pending replication target with persisted queue state.
pub fn acknowledge_pending_replication_target_persisted(
    path: &Path,
    idempotency_key: &str,
    target_node: &str,
) -> std::io::Result<PendingReplicationAcknowledgeOutcome> {
    let mut queue = load_pending_replication_queue(path)?;
    let outcome = acknowledge_pending_replication_target(&mut queue, idempotency_key, target_node);
    if matches!(
        outcome,
        PendingReplicationAcknowledgeOutcome::Updated { .. }
    ) {
        persist_pending_replication_queue(path, &queue)?;
    }
    Ok(outcome)
}

/// Record a replication failure with persisted queue state.
pub fn record_pending_replication_failure_persisted(
    path: &Path,
    idempotency_key: &str,
    target_node: &str,
    error: Option<&str>,
) -> std::io::Result<PendingReplicationFailureOutcome> {
    let mut queue = load_pending_replication_queue(path)?;
    let outcome =
        record_pending_replication_failure(&mut queue, idempotency_key, target_node, error);
    if matches!(outcome, PendingReplicationFailureOutcome::Updated { .. }) {
        persist_pending_replication_queue(path, &queue)?;
    }
    Ok(outcome)
}

/// Lease a due pending replication target for replay processing with persisted queue state.
pub fn lease_pending_replication_target_for_replay_persisted(
    path: &Path,
    idempotency_key: &str,
    target_node: &str,
    now_unix_ms: u64,
    lease_ms: u64,
) -> std::io::Result<PendingReplicationReplayLeaseOutcome> {
    let mut queue = load_pending_replication_queue(path)?;
    let outcome = lease_pending_replication_target_for_replay(
        &mut queue,
        idempotency_key,
        target_node,
        now_unix_ms,
        lease_ms,
    );
    if matches!(
        outcome,
        PendingReplicationReplayLeaseOutcome::Updated { .. }
    ) {
        persist_pending_replication_queue(path, &queue)?;
    }
    Ok(outcome)
}

/// Record a failed replication attempt with backoff scheduling using persisted queue state.
pub fn record_pending_replication_failure_with_backoff_persisted(
    path: &Path,
    idempotency_key: &str,
    target_node: &str,
    error: Option<&str>,
    now_unix_ms: u64,
    policy: PendingReplicationRetryPolicy,
) -> std::io::Result<PendingReplicationFailureWithBackoffOutcome> {
    let mut queue = load_pending_replication_queue(path)?;
    let outcome = record_pending_replication_failure_with_backoff(
        &mut queue,
        idempotency_key,
        target_node,
        error,
        now_unix_ms,
        policy,
    );
    if matches!(
        outcome,
        PendingReplicationFailureWithBackoffOutcome::Updated { .. }
    ) {
        persist_pending_replication_queue(path, &queue)?;
    }
    Ok(outcome)
}

/// Load persisted queue state and select due replay candidates in stable order.
pub fn pending_replication_replay_candidates_from_disk(
    path: &Path,
    now_unix_ms: u64,
    max_candidates: usize,
) -> std::io::Result<Vec<PendingReplicationReplayCandidate>> {
    let queue = load_pending_replication_queue(path)?;
    Ok(pending_replication_replay_candidates(
        &queue,
        now_unix_ms,
        max_candidates,
    ))
}

/// Load persisted queue state and project deterministic queue diagnostics.
pub fn summarize_pending_replication_queue_from_disk(
    path: &Path,
) -> std::io::Result<PendingReplicationQueueSummary> {
    let queue = load_pending_replication_queue(path)?;
    Ok(summarize_pending_replication_queue(&queue))
}
