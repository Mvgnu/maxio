use super::*;

pub fn spawn_pending_replication_replay_worker(state: AppState) {
    if state.active_cluster_peers().is_empty() {
        return;
    }

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(
            PENDING_REPLICATION_REPLAY_INTERVAL_SECS,
        ));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;
            match replay_pending_replication_backlog_once(
                &state,
                PENDING_REPLICATION_REPLAY_BATCH_SIZE,
                PENDING_REPLICATION_REPLAY_LEASE_MS,
            )
            .await
            {
                Ok(summary) => {
                    state.pending_replication_replay_counters.record_success(
                        summary.scanned,
                        summary.leased,
                        summary.acknowledged,
                        summary.failed,
                        summary.skipped,
                    );
                    if summary.scanned > 0 {
                        tracing::info!(
                            scanned = summary.scanned,
                            leased = summary.leased,
                            acknowledged = summary.acknowledged,
                            failed = summary.failed,
                            skipped = summary.skipped,
                            "Pending replication replay cycle completed"
                        );
                    }
                }
                Err(error) => {
                    state.pending_replication_replay_counters.record_failure();
                    tracing::warn!(
                        error = ?error,
                        "Pending replication replay cycle failed"
                    );
                }
            }
        }
    });
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PendingRebalanceReplaySummary {
    pub(crate) scanned: usize,
    pub(crate) leased: usize,
    pub(crate) acknowledged: usize,
    pub(crate) failed: usize,
    pub(crate) skipped: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingRebalanceApplyOutcome {
    Applied,
    Dropped,
}

pub fn spawn_pending_rebalance_replay_worker(state: AppState) {
    if state.active_cluster_peers().is_empty() {
        return;
    }

    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_secs(PENDING_REBALANCE_REPLAY_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;
            match replay_pending_rebalance_backlog_once(
                &state,
                PENDING_REBALANCE_REPLAY_BATCH_SIZE,
                PENDING_REBALANCE_REPLAY_LEASE_MS,
            )
            .await
            {
                Ok(summary) => {
                    state.pending_rebalance_replay_counters.record_success(
                        summary.scanned,
                        summary.leased,
                        summary.acknowledged,
                        summary.failed,
                        summary.skipped,
                    );
                    if summary.scanned > 0 {
                        tracing::info!(
                            scanned = summary.scanned,
                            leased = summary.leased,
                            acknowledged = summary.acknowledged,
                            failed = summary.failed,
                            skipped = summary.skipped,
                            "Pending rebalance replay cycle completed"
                        );
                    }
                }
                Err(error) => {
                    state.pending_rebalance_replay_counters.record_failure();
                    tracing::warn!(
                        error = ?error,
                        "Pending rebalance replay cycle failed"
                    );
                }
            }
        }
    });
}

async fn replay_pending_rebalance_backlog_once(
    state: &AppState,
    max_candidates: usize,
    lease_ms: u64,
) -> std::io::Result<PendingRebalanceReplaySummary> {
    if max_candidates == 0 {
        return Ok(PendingRebalanceReplaySummary::default());
    }

    let queue_path = pending_rebalance_queue_path(state.config.data_dir.as_str());
    let now_unix_ms = unix_ms_now();
    let candidates =
        pending_rebalance_candidates_from_disk(queue_path.as_path(), now_unix_ms, max_candidates)?;
    let mut summary = PendingRebalanceReplaySummary {
        scanned: candidates.len(),
        ..PendingRebalanceReplaySummary::default()
    };

    for candidate in candidates {
        let lease_outcome = lease_pending_rebalance_transfer_for_execution_persisted(
            queue_path.as_path(),
            candidate.rebalance_id.as_str(),
            candidate.from.as_deref(),
            candidate.to.as_str(),
            unix_ms_now(),
            lease_ms,
        )?;
        if !matches!(lease_outcome, PendingRebalanceLeaseOutcome::Updated { .. }) {
            summary.skipped = summary.skipped.saturating_add(1);
            continue;
        }
        summary.leased = summary.leased.saturating_add(1);

        match replay_pending_rebalance_candidate(state, &candidate).await {
            Ok(replay_outcome) => {
                let acknowledge_outcome = acknowledge_pending_rebalance_transfer_persisted(
                    queue_path.as_path(),
                    candidate.rebalance_id.as_str(),
                    candidate.from.as_deref(),
                    candidate.to.as_str(),
                )?;
                match acknowledge_outcome {
                    PendingRebalanceAcknowledgeOutcome::Updated { .. }
                    | PendingRebalanceAcknowledgeOutcome::AlreadyCompleted => {
                        summary.acknowledged = summary.acknowledged.saturating_add(1);
                    }
                    PendingRebalanceAcknowledgeOutcome::NotFound
                    | PendingRebalanceAcknowledgeOutcome::TransferNotTracked => {
                        summary.skipped = summary.skipped.saturating_add(1);
                    }
                }
                if matches!(replay_outcome, PendingRebalanceApplyOutcome::Dropped) {
                    summary.skipped = summary.skipped.saturating_add(1);
                }
            }
            Err(error) => {
                summary.failed = summary.failed.saturating_add(1);
                let failure_outcome = record_pending_rebalance_failure_with_backoff_persisted(
                    queue_path.as_path(),
                    candidate.rebalance_id.as_str(),
                    candidate.from.as_deref(),
                    candidate.to.as_str(),
                    Some(error.as_str()),
                    unix_ms_now(),
                    PendingReplicationRetryPolicy::default(),
                )?;
                tracing::warn!(
                    rebalance_id = candidate.rebalance_id.as_str(),
                    bucket = candidate.bucket.as_str(),
                    key = candidate.key.as_str(),
                    from_node = ?candidate.from,
                    to_node = candidate.to.as_str(),
                    error = error.as_str(),
                    failure_outcome = ?failure_outcome,
                    "Pending rebalance replay attempt failed"
                );
            }
        }
    }

    Ok(summary)
}

async fn replay_pending_rebalance_candidate(
    state: &AppState,
    candidate: &PendingRebalanceCandidate,
) -> Result<PendingRebalanceApplyOutcome, String> {
    if !matches!(candidate.scope, RebalanceObjectScope::Object) {
        return Ok(PendingRebalanceApplyOutcome::Dropped);
    }
    if !pending_rebalance_target_is_current_owner(state, candidate) {
        tracing::debug!(
            rebalance_id = candidate.rebalance_id.as_str(),
            bucket = candidate.bucket.as_str(),
            key = candidate.key.as_str(),
            to_node = candidate.to.as_str(),
            "Skipping pending rebalance replay because target is outside current owner set"
        );
        return Ok(PendingRebalanceApplyOutcome::Dropped);
    }

    let local_node_id = state.node_id.as_ref();
    if peer_identity_eq(candidate.to.as_str(), local_node_id) {
        return replay_pending_rebalance_receive(state, candidate).await;
    }
    if candidate
        .from
        .as_deref()
        .is_some_and(|from| peer_identity_eq(from, local_node_id))
    {
        return replay_pending_rebalance_send(state, candidate).await;
    }

    Ok(PendingRebalanceApplyOutcome::Dropped)
}

pub(super) fn pending_rebalance_target_is_current_owner(
    state: &AppState,
    candidate: &PendingRebalanceCandidate,
) -> bool {
    let peers = state.active_cluster_peers();
    let replica_count = peers
        .len()
        .saturating_add(1)
        .min(DISTRIBUTED_REBALANCE_REPLICA_TARGET);
    if replica_count == 0 {
        return false;
    }

    let owners = select_object_owners_with_self(
        candidate.key.as_str(),
        state.node_id.as_ref(),
        peers.as_slice(),
        replica_count,
    );
    owners
        .iter()
        .any(|owner| peer_identity_eq(owner.as_str(), candidate.to.as_str()))
}

async fn replay_pending_rebalance_send(
    state: &AppState,
    candidate: &PendingRebalanceCandidate,
) -> Result<PendingRebalanceApplyOutcome, String> {
    let read_result = state
        .storage
        .get_object(candidate.bucket.as_str(), candidate.key.as_str())
        .await;
    let (mut reader, meta) = match read_result {
        Ok(value) => value,
        Err(StorageError::NotFound(_)) => return Ok(PendingRebalanceApplyOutcome::Dropped),
        Err(error) => {
            return Err(format!(
                "failed to read rebalance source object payload: {error}"
            ));
        }
    };

    let mut body = Vec::new();
    reader
        .read_to_end(&mut body)
        .await
        .map_err(|error| format!("failed to read rebalance source object body: {error}"))?;

    let path_and_query = presigned_rebalance_path_and_query(
        state,
        "PUT",
        candidate.to.as_str(),
        candidate.bucket.as_str(),
        candidate.key.as_str(),
        &[],
    )
    .ok_or_else(|| "failed to build presigned rebalance replica PUT path".to_string())?;

    let mut headers = HeaderMap::new();
    if let Ok(content_type) = HeaderValue::from_str(meta.content_type.as_str()) {
        headers.insert(header::CONTENT_TYPE, content_type);
    }
    let envelope = rebalance_forwarded_write_envelope(state, candidate);
    let response = forward_replica_put_to_target(
        state,
        candidate.to.as_str(),
        path_and_query.as_str(),
        &headers,
        body,
        None,
        &envelope,
    )
    .await
    .map_err(|error| format!("rebalance replica PUT forward failed: {error:?}"))?;
    if response.status().is_success() {
        return Ok(PendingRebalanceApplyOutcome::Applied);
    }

    Err(format!(
        "rebalance replica PUT returned non-success status {}",
        response.status().as_u16()
    ))
}

async fn replay_pending_rebalance_receive(
    state: &AppState,
    candidate: &PendingRebalanceCandidate,
) -> Result<PendingRebalanceApplyOutcome, String> {
    let Some(source_node) = candidate.from.as_deref() else {
        return Ok(PendingRebalanceApplyOutcome::Dropped);
    };
    let path_and_query = presigned_rebalance_path_and_query(
        state,
        "GET",
        source_node,
        candidate.bucket.as_str(),
        candidate.key.as_str(),
        &[],
    )
    .ok_or_else(|| "failed to build presigned rebalance source GET path".to_string())?;
    let transport = build_peer_http_transport(Some(state.config.as_ref()), Duration::from_secs(10))
        .map_err(|error| format!("failed to initialize rebalance source client: {error}"))?;
    attest_peer_http_target(
        Some(state.config.as_ref()),
        source_node,
        Duration::from_secs(10),
    )
    .map_err(|error| format!("rebalance source peer attestation failed: {error}"))?;
    let source_url = format!("{}://{source_node}{path_and_query}", transport.scheme);
    let source_response = transport
        .client
        .get(source_url.as_str())
        .send()
        .await
        .map_err(|error| format!("rebalance source GET failed: {error}"))?;
    let source_status = source_response.status();
    if source_status == StatusCode::NOT_FOUND {
        return Ok(PendingRebalanceApplyOutcome::Dropped);
    }
    if !source_status.is_success() {
        return Err(format!(
            "rebalance source GET returned non-success status {}",
            source_status.as_u16()
        ));
    }

    let source_content_type = source_response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| "application/octet-stream".to_string());
    let body = source_response
        .bytes()
        .await
        .map_err(|error| format!("failed to read rebalance source payload: {error}"))?;
    state
        .storage
        .put_object(
            candidate.bucket.as_str(),
            candidate.key.as_str(),
            source_content_type.as_str(),
            Box::pin(std::io::Cursor::new(body.to_vec())),
            None,
        )
        .await
        .map_err(|error| format!("failed to apply rebalance payload locally: {error}"))?;

    Ok(PendingRebalanceApplyOutcome::Applied)
}

pub(super) fn rebalance_forwarded_write_envelope(
    state: &AppState,
    candidate: &PendingRebalanceCandidate,
) -> ForwardedWriteEnvelope {
    let placement = PlacementViewState::from_membership(
        state.placement_epoch(),
        state.node_id.as_ref(),
        state.active_cluster_peers().as_slice(),
    );
    let mut envelope = ForwardedWriteEnvelope::new(
        ForwardedWriteOperation::ReplicatePutObject,
        candidate.bucket.as_str(),
        candidate.key.as_str(),
        state.node_id.as_ref(),
        state.node_id.as_ref(),
        candidate.rebalance_id.as_str(),
        &placement,
    );
    envelope.visited_nodes = vec![state.node_id.to_string()];
    envelope.hop_count = 1;
    envelope
}

pub(super) fn presigned_rebalance_path_and_query(
    state: &AppState,
    method: &'static str,
    target_node: &str,
    bucket: &str,
    key: &str,
    extra_query_params: &[(&str, &str)],
) -> Option<String> {
    let url = generate_presigned_url(PresignRequest {
        method,
        scheme: "http",
        host: target_node,
        path: &format!("/{bucket}/{key}"),
        extra_query_params,
        access_key: state.config.access_key.as_str(),
        secret_key: state.config.secret_key.as_str(),
        region: state.config.region.as_str(),
        now: chrono::Utc::now(),
        expires_secs: 60,
    })
    .ok()?;
    let parsed = reqwest::Url::parse(&url).ok()?;
    let mut path = parsed.path().to_string();
    if let Some(query) = parsed.query() {
        path.push('?');
        path.push_str(query);
    }
    Some(path)
}

pub fn spawn_pending_metadata_repair_replay_worker(state: AppState) {
    if state.active_cluster_peers().is_empty() {
        return;
    }

    let queue_path = pending_metadata_repair_queue_path(state.config.data_dir.as_str());
    let metadata_state_path = persisted_metadata_state_path(state.config.data_dir.as_str());
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(
            PENDING_METADATA_REPAIR_REPLAY_INTERVAL_SECS,
        ));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;
            let now_unix_ms = unix_ms_now();
            match replay_pending_metadata_repairs_once_with_persisted_state_apply(
                queue_path.as_path(),
                metadata_state_path.as_path(),
                now_unix_ms,
                PENDING_METADATA_REPAIR_REPLAY_BATCH_SIZE,
                PENDING_METADATA_REPAIR_REPLAY_LEASE_MS,
                PENDING_METADATA_REPAIR_REPLAY_BACKOFF_BASE_MS,
                PENDING_METADATA_REPAIR_REPLAY_BACKOFF_MAX_MS,
            ) {
                Ok(outcome) => {
                    let skipped_plans = outcome.skipped_plans.saturating_add(outcome.dropped_plans);
                    state
                        .pending_metadata_repair_replay_counters
                        .record_success(
                            outcome.scanned_plans,
                            outcome.leased_plans,
                            outcome.acknowledged_plans,
                            outcome.failed_plans,
                            skipped_plans,
                        );
                    if outcome.scanned_plans > 0 {
                        tracing::info!(
                            scanned_plans = outcome.scanned_plans,
                            leased_plans = outcome.leased_plans,
                            acknowledged_plans = outcome.acknowledged_plans,
                            failed_plans = outcome.failed_plans,
                            dropped_plans = outcome.dropped_plans,
                            skipped_plans = skipped_plans,
                            "Pending metadata repair replay cycle completed"
                        );
                    }
                }
                Err(error) => {
                    state
                        .pending_metadata_repair_replay_counters
                        .record_failure();
                    tracing::warn!(
                        error = ?error,
                        "Pending metadata repair replay cycle failed"
                    );
                }
            }
        }
    });
}

pub fn spawn_membership_convergence_probe_worker(state: AppState) {
    let membership_status = state.membership_engine.status();
    let convergence_seed = seeded_membership_convergence(
        state.membership_protocol,
        membership_status.ready,
        state.active_cluster_peers().as_slice(),
        membership_status.converged,
    );
    record_membership_convergence(&state, convergence_seed);

    if state.active_cluster_peers().is_empty() {
        return;
    }
    if !membership_protocol_uses_probe_convergence(
        state.membership_protocol,
        membership_status.ready,
    ) {
        return;
    }

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(
            MEMBERSHIP_CONVERGENCE_PROBE_INTERVAL_SECS,
        ));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;
            let mut topology = runtime_topology_snapshot(&state);
            if !topology.is_distributed() {
                record_membership_convergence(&state, true);
                continue;
            }
            let peer_connectivity_probe = probe_peer_connectivity(
                topology.cluster_peers.as_slice(),
                Some(state.config.as_ref()),
            )
            .await;
            match derive_membership_discovery_cluster_peers(&topology, &peer_connectivity_probe) {
                Ok(Some(next_cluster_peers)) => {
                    let previous_topology = topology.clone();
                    match state.apply_membership_peers(next_cluster_peers).await {
                        Ok(outcome) if outcome.changed => {
                            let updated_topology = runtime_topology_snapshot(&state);
                            spawn_rebalance_queue_population(
                                &state,
                                &previous_topology,
                                &updated_topology,
                            );
                            spawn_membership_update_propagation(
                                state.config.clone(),
                                &previous_topology,
                                &updated_topology,
                                state.config.cluster_auth_token(),
                            );
                            tracing::info!(
                                membership_view_id = outcome.membership_view_id,
                                placement_epoch = outcome.placement_epoch,
                                "Applied discovered membership peers from convergence probe"
                            );
                            topology = updated_topology;
                        }
                        Ok(_) => {}
                        Err(error) => {
                            tracing::warn!(
                                error = ?error,
                                "Failed to apply discovered membership peers from probe"
                            );
                        }
                    }
                }
                Ok(None) => {}
                Err(reason) => {
                    tracing::warn!(
                        reason = reason.as_str(),
                        "Skipped discovered membership peer update due to invalid probe snapshot"
                    );
                }
            }
            let stale_targets = derive_gossip_stale_peer_reconciliation_targets(
                &topology,
                &peer_connectivity_probe,
            );
            if !stale_targets.is_empty() {
                spawn_gossip_stale_peer_reconciliation(
                    state.config.clone(),
                    &topology,
                    stale_targets.as_slice(),
                    state.config.cluster_auth_token(),
                );
            }
            let membership_convergence_probe = probe_membership_convergence(
                &topology,
                &topology.membership_status,
                &peer_connectivity_probe,
            );
            let membership_last_update_unix_ms = effective_membership_last_update_unix_ms(
                &topology.membership_status,
                &membership_convergence_probe,
            );
            record_membership_last_update(&state, membership_last_update_unix_ms);
            record_membership_convergence(&state, membership_convergence_probe.converged);
        }
    });
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HealthChecksPayload {
    pub(crate) data_dir_accessible: bool,
    pub(crate) data_dir_writable: bool,
    pub(crate) storage_data_path_readable: bool,
    pub(crate) disk_headroom_sufficient: bool,
    pub(crate) pending_replication_queue_readable: bool,
    pub(crate) pending_rebalance_queue_readable: bool,
    pub(crate) pending_membership_propagation_queue_readable: bool,
    pub(crate) pending_metadata_repair_queue_readable: bool,
    pub(crate) metadata_state_queryable: bool,
    pub(crate) peer_connectivity_ready: bool,
    pub(crate) cluster_peer_auth_configured: bool,
    pub(crate) cluster_peer_auth_identity_bound: bool,
    pub(crate) cluster_peer_auth_transport_ready: bool,
    pub(crate) cluster_peer_auth_transport_required: bool,
    pub(crate) cluster_peer_auth_sender_allowlist_bound: bool,
    pub(crate) cluster_join_auth_ready: bool,
    pub(crate) metadata_list_cluster_authoritative: bool,
    pub(crate) metadata_list_ready: bool,
    pub(crate) membership_protocol_ready: bool,
    pub(crate) membership_converged: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HealthPayload {
    pub(crate) ok: bool,
    pub(crate) status: String,
    pub(crate) version: String,
    pub(crate) uptime_seconds: f64,
    pub(crate) mode: String,
    pub(crate) node_id: String,
    pub(crate) cluster_id: String,
    pub(crate) cluster_peer_count: usize,
    pub(crate) cluster_peers: Vec<String>,
    pub(crate) membership_node_count: usize,
    pub(crate) membership_nodes: Vec<String>,
    pub(crate) cluster_auth_mode: String,
    pub(crate) cluster_auth_trust_model: String,
    pub(crate) cluster_auth_transport_identity: String,
    pub(crate) cluster_auth_transport_reason: String,
    pub(crate) cluster_auth_transport_required: bool,
    pub(crate) cluster_join_auth_mode: String,
    pub(crate) cluster_join_auth_reason: String,
    pub(crate) membership_protocol: String,
    pub(crate) write_durability_mode: String,
    pub(crate) metadata_listing_strategy: String,
    pub(crate) metadata_listing_gap: Option<String>,
    pub(crate) metadata_listing_snapshot_id: String,
    pub(crate) metadata_listing_expected_nodes: usize,
    pub(crate) metadata_listing_responded_nodes: usize,
    pub(crate) metadata_listing_missing_nodes: usize,
    pub(crate) metadata_listing_unexpected_nodes: usize,
    pub(crate) membership_engine: String,
    pub(crate) membership_convergence_reason: String,
    pub(crate) membership_last_update_unix_ms: u64,
    pub(crate) membership_view_id: String,
    pub(crate) placement_epoch: u64,
    pub(crate) pending_replication_backlog_operations: usize,
    pub(crate) pending_replication_backlog_pending_targets: usize,
    pub(crate) pending_replication_backlog_due_targets: usize,
    pub(crate) pending_replication_backlog_due_targets_capped: bool,
    pub(crate) pending_replication_backlog_failed_targets: usize,
    pub(crate) pending_replication_backlog_max_attempts: u32,
    pub(crate) pending_replication_backlog_oldest_created_at_unix_ms: Option<u64>,
    pub(crate) pending_replication_replay_cycles_total: u64,
    pub(crate) pending_replication_replay_cycles_succeeded: u64,
    pub(crate) pending_replication_replay_cycles_failed: u64,
    pub(crate) pending_replication_replay_last_cycle_unix_ms: u64,
    pub(crate) pending_replication_replay_last_success_unix_ms: u64,
    pub(crate) pending_replication_replay_last_failure_unix_ms: u64,
    pub(crate) pending_rebalance_backlog_operations: usize,
    pub(crate) pending_rebalance_backlog_pending_transfers: usize,
    pub(crate) pending_rebalance_backlog_due_transfers: usize,
    pub(crate) pending_rebalance_backlog_due_transfers_capped: bool,
    pub(crate) pending_rebalance_backlog_failed_transfers: usize,
    pub(crate) pending_rebalance_backlog_max_attempts: u32,
    pub(crate) pending_rebalance_backlog_oldest_created_at_unix_ms: Option<u64>,
    pub(crate) pending_rebalance_replay_cycles_total: u64,
    pub(crate) pending_rebalance_replay_cycles_succeeded: u64,
    pub(crate) pending_rebalance_replay_cycles_failed: u64,
    pub(crate) pending_rebalance_replay_last_cycle_unix_ms: u64,
    pub(crate) pending_rebalance_replay_last_success_unix_ms: u64,
    pub(crate) pending_rebalance_replay_last_failure_unix_ms: u64,
    pub(crate) pending_membership_propagation_backlog_operations: usize,
    pub(crate) pending_membership_propagation_backlog_due_operations: usize,
    pub(crate) pending_membership_propagation_backlog_due_operations_capped: bool,
    pub(crate) pending_membership_propagation_backlog_failed_operations: usize,
    pub(crate) pending_membership_propagation_backlog_max_attempts: u32,
    pub(crate) pending_membership_propagation_backlog_oldest_created_at_unix_ms: Option<u64>,
    pub(crate) pending_membership_propagation_replay_cycles_total: u64,
    pub(crate) pending_membership_propagation_replay_cycles_succeeded: u64,
    pub(crate) pending_membership_propagation_replay_cycles_failed: u64,
    pub(crate) pending_membership_propagation_replay_last_cycle_unix_ms: u64,
    pub(crate) pending_membership_propagation_replay_last_success_unix_ms: u64,
    pub(crate) pending_membership_propagation_replay_last_failure_unix_ms: u64,
    pub(crate) pending_metadata_repair_backlog_plans: usize,
    pub(crate) pending_metadata_repair_backlog_due_plans: usize,
    pub(crate) pending_metadata_repair_backlog_due_plans_capped: bool,
    pub(crate) pending_metadata_repair_backlog_failed_plans: usize,
    pub(crate) pending_metadata_repair_backlog_max_attempts: u32,
    pub(crate) pending_metadata_repair_backlog_oldest_created_at_unix_ms: Option<u64>,
    pub(crate) pending_metadata_repair_replay_cycles_total: u64,
    pub(crate) pending_metadata_repair_replay_cycles_succeeded: u64,
    pub(crate) pending_metadata_repair_replay_cycles_failed: u64,
    pub(crate) pending_metadata_repair_replay_last_cycle_unix_ms: u64,
    pub(crate) pending_metadata_repair_replay_last_success_unix_ms: u64,
    pub(crate) pending_metadata_repair_replay_last_failure_unix_ms: u64,
    pub(crate) metadata_state_view_id: String,
    pub(crate) metadata_state_bucket_rows: usize,
    pub(crate) metadata_state_object_rows: usize,
    pub(crate) metadata_state_object_version_rows: usize,
    pub(crate) checks: HealthChecksPayload,
    pub(crate) warnings: Vec<String>,
}
