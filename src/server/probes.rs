use super::*;

pub(super) fn probe_data_dir(path: &str) -> DataDirProbeResult {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) => {
            return DataDirProbeResult {
                accessible: false,
                writable: false,
                warning: Some(format!("Data directory metadata probe failed: {err}")),
            };
        }
    };

    if !metadata.is_dir() {
        return DataDirProbeResult {
            accessible: false,
            writable: false,
            warning: Some("Configured data directory is not a directory".to_string()),
        };
    }

    let probe_path = Path::new(path).join(format!(".maxio-health-probe-{}", uuid::Uuid::new_v4()));
    let file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe_path)
    {
        Ok(file) => file,
        Err(err) => {
            return DataDirProbeResult {
                accessible: true,
                writable: false,
                warning: Some(format!("Data directory write probe failed: {err}")),
            };
        }
    };
    drop(file);

    if let Err(err) = std::fs::remove_file(&probe_path) {
        return DataDirProbeResult {
            accessible: true,
            writable: true,
            warning: Some(format!(
                "Data directory probe cleanup failed for {}: {err}",
                probe_path.display()
            )),
        };
    }

    DataDirProbeResult {
        accessible: true,
        writable: true,
        warning: None,
    }
}

pub fn membership_protocol_readiness(protocol: MembershipProtocol) -> (bool, Option<String>) {
    let status = MembershipEngine::for_protocol(protocol).status();
    (status.ready, status.warning)
}

pub(super) fn membership_protocol_uses_probe_convergence(
    membership_protocol: MembershipProtocol,
    membership_engine_ready: bool,
) -> bool {
    match membership_protocol {
        MembershipProtocol::StaticBootstrap => true,
        MembershipProtocol::Gossip => membership_engine_ready,
        MembershipProtocol::Raft => false,
    }
}

pub(super) async fn probe_storage_data_path(
    storage: &FilesystemStorage,
) -> StorageDataPathProbeResult {
    match storage.list_buckets().await {
        Ok(_) => StorageDataPathProbeResult {
            readable: true,
            warning: None,
        },
        Err(err) => StorageDataPathProbeResult {
            readable: false,
            warning: Some(format!("Storage data-path probe failed: {err}")),
        },
    }
}

pub(super) fn probe_disk_headroom(path: &str, required_free_bytes: u64) -> DiskHeadroomProbeResult {
    if required_free_bytes == 0 {
        return DiskHeadroomProbeResult {
            sufficient: true,
            warning: None,
        };
    }

    match fs2::available_space(path) {
        Ok(free_bytes) if free_bytes >= required_free_bytes => DiskHeadroomProbeResult {
            sufficient: true,
            warning: None,
        },
        Ok(free_bytes) => DiskHeadroomProbeResult {
            sufficient: false,
            warning: Some(format!(
                "Disk headroom below threshold: available {free_bytes} bytes, required {required_free_bytes} bytes."
            )),
        },
        Err(err) => DiskHeadroomProbeResult {
            sufficient: false,
            warning: Some(format!("Disk headroom probe failed: {err}")),
        },
    }
}

pub(super) fn pending_replication_queue_path(data_dir: &str) -> PathBuf {
    Path::new(data_dir)
        .join(PLACEMENT_STATE_DIR)
        .join(PENDING_REPLICATION_QUEUE_FILE)
}

pub(super) fn pending_rebalance_queue_path(data_dir: &str) -> PathBuf {
    Path::new(data_dir)
        .join(PLACEMENT_STATE_DIR)
        .join(PENDING_REBALANCE_QUEUE_FILE)
}

pub(super) fn pending_membership_propagation_queue_path(data_dir: &str) -> PathBuf {
    Path::new(data_dir)
        .join(PLACEMENT_STATE_DIR)
        .join(PENDING_MEMBERSHIP_PROPAGATION_QUEUE_FILE)
}

pub(super) fn pending_metadata_repair_queue_path(data_dir: &str) -> PathBuf {
    Path::new(data_dir)
        .join(PLACEMENT_STATE_DIR)
        .join(PENDING_METADATA_REPAIR_QUEUE_FILE)
}

pub(super) fn persisted_metadata_state_path(data_dir: &str) -> PathBuf {
    Path::new(data_dir)
        .join(PLACEMENT_STATE_DIR)
        .join(PERSISTED_METADATA_STATE_FILE)
}

pub(super) async fn load_pending_membership_propagation_queue(
    path: &Path,
) -> std::io::Result<PendingMembershipPropagationQueue> {
    match tokio::fs::read(path).await {
        Ok(bytes) => {
            serde_json::from_slice::<PendingMembershipPropagationQueue>(&bytes).map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(PendingMembershipPropagationQueue::default())
        }
        Err(error) => Err(error),
    }
}

pub(super) async fn persist_pending_membership_propagation_queue(
    path: &Path,
    queue: &PendingMembershipPropagationQueue,
) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let payload = serde_json::to_vec_pretty(queue)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let temp_path = placement_state_temp_path(path);
    let mut temp_file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(temp_path.as_path())
        .await?;
    temp_file.write_all(&payload).await?;
    temp_file.sync_all().await?;
    drop(temp_file);

    if let Err(error) = rename_placement_state(temp_path.as_path(), path).await {
        let _ = tokio::fs::remove_file(temp_path.as_path()).await;
        return Err(error);
    }
    Ok(())
}

pub(super) fn upsert_pending_membership_propagation_operation(
    queue: &mut PendingMembershipPropagationQueue,
    peer: &str,
    request: &ClusterMembershipUpdateRequest,
    error: Option<&str>,
    now_unix_ms: u64,
) {
    let normalized_peer = peer.trim().to_string();
    if normalized_peer.is_empty() {
        return;
    }

    if let Some(existing) = queue
        .operations
        .iter_mut()
        .find(|operation| peer_identity_eq(operation.peer.as_str(), normalized_peer.as_str()))
    {
        existing.peer = normalized_peer;
        existing.request = request.clone();
        existing.attempts = existing.attempts.saturating_add(1);
        existing.updated_at_unix_ms = now_unix_ms;
        existing.last_error = error.map(str::to_string);
        existing.next_retry_at_unix_ms = Some(
            now_unix_ms.saturating_add(membership_propagation_retry_delay_ms(existing.attempts)),
        );
        return;
    }

    queue
        .operations
        .push(PendingMembershipPropagationOperation {
            peer: normalized_peer,
            request: request.clone(),
            attempts: 1,
            created_at_unix_ms: now_unix_ms,
            updated_at_unix_ms: now_unix_ms,
            next_retry_at_unix_ms: Some(
                now_unix_ms.saturating_add(membership_propagation_retry_delay_ms(1)),
            ),
            last_error: error.map(str::to_string),
        });
}

pub(super) async fn record_pending_membership_propagation_failure(
    data_dir: &str,
    peer: &str,
    request: &ClusterMembershipUpdateRequest,
    error: Option<&str>,
) -> std::io::Result<()> {
    let queue_path = pending_membership_propagation_queue_path(data_dir);
    let mut queue = load_pending_membership_propagation_queue(queue_path.as_path()).await?;
    upsert_pending_membership_propagation_operation(
        &mut queue,
        peer,
        request,
        error,
        unix_ms_now(),
    );
    queue
        .operations
        .sort_by(|left, right| left.peer.cmp(&right.peer));
    persist_pending_membership_propagation_queue(queue_path.as_path(), &queue).await
}

pub(super) fn load_pending_membership_propagation_queue_from_disk(
    path: &Path,
) -> std::io::Result<PendingMembershipPropagationQueue> {
    match std::fs::read(path) {
        Ok(bytes) => {
            serde_json::from_slice::<PendingMembershipPropagationQueue>(&bytes).map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(PendingMembershipPropagationQueue::default())
        }
        Err(error) => Err(error),
    }
}

pub(super) fn probe_pending_membership_propagation_queue(
    data_dir: &str,
) -> PendingMembershipPropagationQueueProbeResult {
    let queue_path = pending_membership_propagation_queue_path(data_dir);
    match load_pending_membership_propagation_queue_from_disk(queue_path.as_path()) {
        Ok(queue) => {
            let now_unix_ms = unix_ms_now();
            let due_operations_full = queue
                .operations
                .iter()
                .filter(|operation| {
                    operation
                        .next_retry_at_unix_ms
                        .is_none_or(|next_retry| next_retry <= now_unix_ms)
                })
                .count();
            let due_operations =
                due_operations_full.min(PENDING_MEMBERSHIP_PROPAGATION_DUE_OPERATION_SCAN_LIMIT);
            let due_operations_capped =
                due_operations_full > PENDING_MEMBERSHIP_PROPAGATION_DUE_OPERATION_SCAN_LIMIT;
            let summary = PendingMembershipPropagationQueueProbeSummary {
                operations: queue.operations.len(),
                failed_operations: queue
                    .operations
                    .iter()
                    .filter(|operation| operation.last_error.is_some())
                    .count(),
                max_attempts: queue
                    .operations
                    .iter()
                    .map(|operation| operation.attempts)
                    .max()
                    .unwrap_or(0),
                oldest_created_at_unix_ms: queue
                    .operations
                    .iter()
                    .map(|operation| operation.created_at_unix_ms)
                    .min(),
            };

            PendingMembershipPropagationQueueProbeResult {
                readable: true,
                summary,
                due_operations,
                due_operations_capped,
                warning: None,
            }
        }
        Err(err) => PendingMembershipPropagationQueueProbeResult {
            readable: false,
            summary: PendingMembershipPropagationQueueProbeSummary {
                operations: 0,
                failed_operations: 0,
                max_attempts: 0,
                oldest_created_at_unix_ms: None,
            },
            due_operations: 0,
            due_operations_capped: false,
            warning: Some(format!(
                "Pending membership propagation queue probe failed for '{}': {err}",
                queue_path.display()
            )),
        },
    }
}

pub(super) fn probe_pending_replication_queue(
    data_dir: &str,
) -> PendingReplicationQueueProbeResult {
    let queue_path = pending_replication_queue_path(data_dir);
    match load_pending_replication_queue(queue_path.as_path()) {
        Ok(queue) => {
            let summary = summarize_pending_replication_queue(&queue);
            let due_candidates = pending_replication_replay_candidates(
                &queue,
                unix_ms_now(),
                PENDING_REPLICATION_DUE_TARGET_SCAN_LIMIT.saturating_add(1),
            );
            let due_targets = due_candidates
                .len()
                .min(PENDING_REPLICATION_DUE_TARGET_SCAN_LIMIT);
            let due_targets_capped =
                due_candidates.len() > PENDING_REPLICATION_DUE_TARGET_SCAN_LIMIT;
            PendingReplicationQueueProbeResult {
                readable: true,
                summary,
                due_targets,
                due_targets_capped,
                warning: None,
            }
        }
        Err(err) => PendingReplicationQueueProbeResult {
            readable: false,
            summary: PendingReplicationQueueSummary::default(),
            due_targets: 0,
            due_targets_capped: false,
            warning: Some(format!(
                "Pending replication queue probe failed for '{}': {err}",
                queue_path.display()
            )),
        },
    }
}

pub(super) fn probe_pending_rebalance_queue(data_dir: &str) -> PendingRebalanceQueueProbeResult {
    let queue_path = pending_rebalance_queue_path(data_dir);
    match summarize_pending_rebalance_queue_from_disk(queue_path.as_path()) {
        Ok(summary) => {
            let due_candidates = pending_rebalance_candidates_from_disk(
                queue_path.as_path(),
                unix_ms_now(),
                PENDING_REBALANCE_DUE_TRANSFER_SCAN_LIMIT.saturating_add(1),
            );
            match due_candidates {
                Ok(candidates) => {
                    let due_transfers = candidates
                        .len()
                        .min(PENDING_REBALANCE_DUE_TRANSFER_SCAN_LIMIT);
                    let due_transfers_capped =
                        candidates.len() > PENDING_REBALANCE_DUE_TRANSFER_SCAN_LIMIT;
                    PendingRebalanceQueueProbeResult {
                        readable: true,
                        summary,
                        due_transfers,
                        due_transfers_capped,
                        warning: None,
                    }
                }
                Err(err) => PendingRebalanceQueueProbeResult {
                    readable: false,
                    summary: PendingRebalanceQueueSummary::default(),
                    due_transfers: 0,
                    due_transfers_capped: false,
                    warning: Some(format!(
                        "Pending rebalance queue candidate probe failed for '{}': {err}",
                        queue_path.display()
                    )),
                },
            }
        }
        Err(err) => PendingRebalanceQueueProbeResult {
            readable: false,
            summary: PendingRebalanceQueueSummary::default(),
            due_transfers: 0,
            due_transfers_capped: false,
            warning: Some(format!(
                "Pending rebalance queue probe failed for '{}': {err}",
                queue_path.display()
            )),
        },
    }
}

pub(super) fn probe_pending_metadata_repair_queue(
    data_dir: &str,
) -> PendingMetadataRepairQueueProbeResult {
    let queue_path = pending_metadata_repair_queue_path(data_dir);
    let now_unix_ms = unix_ms_now();
    match summarize_pending_metadata_repair_queue_from_disk(queue_path.as_path(), now_unix_ms) {
        Ok(summary) => {
            let due_candidates = pending_metadata_repair_candidates_from_disk(
                queue_path.as_path(),
                now_unix_ms,
                PENDING_METADATA_REPAIR_DUE_PLAN_SCAN_LIMIT.saturating_add(1),
            );
            match due_candidates {
                Ok(candidates) => {
                    let due_plans = candidates
                        .len()
                        .min(PENDING_METADATA_REPAIR_DUE_PLAN_SCAN_LIMIT);
                    let due_plans_capped =
                        candidates.len() > PENDING_METADATA_REPAIR_DUE_PLAN_SCAN_LIMIT;
                    PendingMetadataRepairQueueProbeResult {
                        readable: true,
                        summary,
                        due_plans,
                        due_plans_capped,
                        warning: None,
                    }
                }
                Err(err) => PendingMetadataRepairQueueProbeResult {
                    readable: false,
                    summary: PendingMetadataRepairQueueSummary::default(),
                    due_plans: 0,
                    due_plans_capped: false,
                    warning: Some(format!(
                        "Pending metadata repair queue candidate probe failed for '{}': {err}",
                        queue_path.display()
                    )),
                },
            }
        }
        Err(err) => PendingMetadataRepairQueueProbeResult {
            readable: false,
            summary: PendingMetadataRepairQueueSummary::default(),
            due_plans: 0,
            due_plans_capped: false,
            warning: Some(format!(
                "Pending metadata repair queue probe failed for '{}': {err}",
                queue_path.display()
            )),
        },
    }
}

pub(super) fn probe_persisted_metadata_state(data_dir: &str) -> PersistedMetadataStateProbeResult {
    let state_path = persisted_metadata_state_path(data_dir);
    match load_persisted_metadata_state(state_path.as_path()) {
        Ok(state) => {
            let bucket_rows = state.buckets.len();
            let object_rows = state.objects.len();
            let object_version_rows = state.object_versions.len();
            let view_id = state.view_id.trim().to_string();
            match build_queryable_metadata_index_from_persisted_state(&state) {
                Ok(_) => PersistedMetadataStateProbeResult {
                    readable: true,
                    queryable: true,
                    view_id,
                    bucket_rows,
                    object_rows,
                    object_version_rows,
                    warning: None,
                },
                Err(err) => PersistedMetadataStateProbeResult {
                    readable: true,
                    queryable: false,
                    view_id,
                    bucket_rows,
                    object_rows,
                    object_version_rows,
                    warning: Some(format!(
                        "Persisted metadata state '{}' is not queryable: {err:?}",
                        state_path.display()
                    )),
                },
            }
        }
        Err(err) => PersistedMetadataStateProbeResult {
            readable: false,
            queryable: false,
            view_id: String::new(),
            bucket_rows: 0,
            object_rows: 0,
            object_version_rows: 0,
            warning: Some(format!(
                "Persisted metadata state probe failed for '{}': {err}",
                state_path.display()
            )),
        },
    }
}

pub(super) async fn probe_peer_connectivity(
    peers: &[String],
    config: Option<&Config>,
) -> PeerConnectivityProbeResult {
    if peers.is_empty() {
        return PeerConnectivityProbeResult {
            ready: true,
            warning: None,
            peer_views: Vec::new(),
            failed_peers: Vec::new(),
        };
    }

    let transport = match build_peer_http_transport(
        config,
        Duration::from_secs(PEER_CONNECTIVITY_PROBE_TIMEOUT_SECS),
    ) {
        Ok(transport) => transport,
        Err(err) => {
            return PeerConnectivityProbeResult {
                ready: false,
                warning: Some(format!(
                    "Peer connectivity probe client initialization failed: {err}"
                )),
                peer_views: Vec::new(),
                failed_peers: peers.to_vec(),
            };
        }
    };
    let client = transport.client;
    let scheme = transport.scheme;

    let mut failures = Vec::new();
    let mut peer_views = Vec::new();
    let mut failed_peers = Vec::new();
    for peer in peers {
        if let Err(error) = attest_peer_http_target(
            config,
            peer.as_str(),
            Duration::from_secs(PEER_CONNECTIVITY_PROBE_TIMEOUT_SECS),
        ) {
            failures.push(format!("{peer} ({error})"));
            failed_peers.push(peer.clone());
            continue;
        }

        let url = format!("{scheme}://{peer}/healthz");
        match client.get(url).send().await {
            Ok(response) if response.status().is_success() => {
                let (view_id, placement_epoch, cluster_id, cluster_peers) =
                    match response.text().await {
                        Ok(body) => match serde_json::from_str::<PeerHealthProbePayload>(&body) {
                            Ok(payload) => {
                                let view_id = payload
                                    .membership_view_id
                                    .as_deref()
                                    .map(str::trim)
                                    .filter(|value| !value.is_empty())
                                    .map(str::to_string);
                                let cluster_id = payload
                                    .cluster_id
                                    .as_deref()
                                    .map(str::trim)
                                    .filter(|value| !value.is_empty())
                                    .map(str::to_string);
                                let placement_epoch = payload.placement_epoch;
                                let cluster_peers = payload
                                    .cluster_peers
                                    .into_iter()
                                    .map(|value| value.trim().to_string())
                                    .filter(|value| !value.is_empty())
                                    .collect::<Vec<_>>();
                                (view_id, placement_epoch, cluster_id, cluster_peers)
                            }
                            Err(_) => (None, None, None, Vec::new()),
                        },
                        Err(_) => (None, None, None, Vec::new()),
                    };
                peer_views.push(PeerViewObservation {
                    peer: peer.clone(),
                    membership_view_id: view_id,
                    placement_epoch,
                    cluster_id,
                    cluster_peers,
                });
            }
            Ok(response) => {
                failures.push(format!("{peer} (status {})", response.status()));
                failed_peers.push(peer.clone());
            }
            Err(err) => {
                failures.push(format!("{peer} ({err})"));
                failed_peers.push(peer.clone());
            }
        }
    }

    if failures.is_empty() {
        PeerConnectivityProbeResult {
            ready: true,
            warning: None,
            peer_views,
            failed_peers: Vec::new(),
        }
    } else {
        PeerConnectivityProbeResult {
            ready: false,
            warning: Some(format!(
                "Peer connectivity probe failed for {} configured peer(s): {}",
                failures.len(),
                failures.join(", ")
            )),
            peer_views,
            failed_peers,
        }
    }
}

pub(super) fn derive_membership_discovery_cluster_peers(
    topology: &RuntimeTopologySnapshot,
    peer_connectivity_probe: &PeerConnectivityProbeResult,
) -> Result<Option<Vec<String>>, String> {
    if !topology.is_distributed() {
        return Ok(None);
    }
    if !membership_protocol_uses_probe_convergence(
        topology.membership_protocol,
        topology.membership_status.ready,
    ) {
        return Ok(None);
    }
    if peer_connectivity_probe.peer_views.is_empty() {
        return Ok(None);
    }

    let mut candidate_peers = topology.cluster_peers.clone();
    for peer_view in &peer_connectivity_probe.peer_views {
        let cluster_id = peer_view
            .cluster_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                format!(
                    "peer '{}' omitted cluster id in /healthz payload",
                    peer_view.peer
                )
            })?;
        if cluster_id != topology.cluster_id {
            return Err(format!(
                "peer '{}' reported mismatched cluster id '{}' (expected '{}')",
                peer_view.peer, cluster_id, topology.cluster_id
            ));
        }
        peer_view
            .membership_view_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                format!(
                    "peer '{}' omitted membership view id in /healthz payload",
                    peer_view.peer
                )
            })?;
        candidate_peers.extend(peer_view.cluster_peers.iter().cloned());
    }
    prune_gossip_failed_discovery_peers(topology, peer_connectivity_probe, &mut candidate_peers);

    let normalized = normalize_cluster_peers_for_membership_update(
        topology.node_id.as_str(),
        candidate_peers.as_slice(),
    )
    .map_err(|error| format!("discovered peer set normalization failed: {error}"))?;

    if normalized == topology.cluster_peers {
        Ok(None)
    } else {
        Ok(Some(normalized))
    }
}

pub(super) fn prune_gossip_failed_discovery_peers(
    topology: &RuntimeTopologySnapshot,
    peer_connectivity_probe: &PeerConnectivityProbeResult,
    candidate_peers: &mut Vec<String>,
) {
    if topology.membership_protocol != MembershipProtocol::Gossip
        || peer_connectivity_probe.failed_peers.is_empty()
    {
        return;
    }

    let local_view_id = topology.membership_view_id.as_str();
    let all_successful_views_match_local =
        peer_connectivity_probe.peer_views.iter().all(|peer_view| {
            peer_view
                .membership_view_id
                .as_deref()
                .is_some_and(|view_id| view_id == local_view_id)
        });
    if !all_successful_views_match_local {
        return;
    }

    let mut observed_peers = Vec::new();
    for peer_view in &peer_connectivity_probe.peer_views {
        observed_peers.push(peer_view.peer.clone());
        observed_peers.extend(peer_view.cluster_peers.iter().cloned());
    }
    if observed_peers.is_empty() {
        return;
    }

    candidate_peers.retain(|candidate| {
        !peer_connectivity_probe
            .failed_peers
            .iter()
            .any(|failed_peer| {
                peer_identity_eq(candidate.as_str(), failed_peer.as_str())
                    && !observed_peers
                        .iter()
                        .any(|observed| peer_identity_eq(observed.as_str(), failed_peer.as_str()))
            })
    });
}

pub(super) fn derive_gossip_stale_peer_reconciliation_targets(
    topology: &RuntimeTopologySnapshot,
    peer_connectivity_probe: &PeerConnectivityProbeResult,
) -> Vec<GossipStalePeerReconciliationTarget> {
    if topology.membership_protocol != MembershipProtocol::Gossip
        || !topology.membership_status.ready
        || !topology.is_distributed()
    {
        return Vec::new();
    }

    let local_view_id = topology.membership_view_id.as_str();
    let mut targets: Vec<GossipStalePeerReconciliationTarget> = Vec::new();
    for peer_view in &peer_connectivity_probe.peer_views {
        if peer_identity_eq(peer_view.peer.as_str(), topology.node_id.as_str()) {
            continue;
        }

        let Some(peer_cluster_id) = peer_view
            .cluster_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if peer_cluster_id != topology.cluster_id {
            continue;
        }

        let Some(peer_view_id) = peer_view
            .membership_view_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if peer_view_id == local_view_id {
            continue;
        }

        let Some(peer_epoch) = peer_view.placement_epoch else {
            continue;
        };
        if targets
            .iter()
            .any(|target| peer_identity_eq(target.peer.as_str(), peer_view.peer.as_str()))
        {
            continue;
        }

        targets.push(GossipStalePeerReconciliationTarget {
            peer: peer_view.peer.clone(),
            expected_membership_view_id: peer_view_id.to_string(),
            expected_placement_epoch: peer_epoch,
        });
    }

    targets
}

pub(super) fn probe_membership_convergence(
    topology: &RuntimeTopologySnapshot,
    membership_status: &MembershipEngineStatus,
    peer_connectivity_probe: &PeerConnectivityProbeResult,
) -> MembershipConvergenceProbeResult {
    let observed_at_unix_ms = unix_ms_now();

    if !membership_status.ready {
        return MembershipConvergenceProbeResult {
            converged: false,
            reason: "engine-not-converged",
            warning: None,
            observed_at_unix_ms,
        };
    }

    let requires_peer_probe = topology.is_distributed()
        && membership_protocol_uses_probe_convergence(
            topology.membership_protocol,
            membership_status.ready,
        );
    if !requires_peer_probe {
        return MembershipConvergenceProbeResult {
            converged: true,
            reason: "not-required",
            warning: None,
            observed_at_unix_ms,
        };
    }

    if !peer_connectivity_probe.ready {
        return MembershipConvergenceProbeResult {
            converged: false,
            reason: "peer-connectivity-failed",
            warning: Some(
                "Membership convergence cannot be confirmed while peer connectivity checks are failing."
                    .to_string(),
            ),
            observed_at_unix_ms,
        };
    }

    let mut mismatches = Vec::new();
    for observation in &peer_connectivity_probe.peer_views {
        match observation.membership_view_id.as_deref() {
            Some(peer_view_id) if peer_view_id == topology.membership_view_id => {}
            Some(peer_view_id) => mismatches.push(format!(
                "{} (peer view '{}', local '{}')",
                observation.peer, peer_view_id, topology.membership_view_id
            )),
            None => mismatches.push(format!(
                "{} (missing membershipViewId in /healthz payload)",
                observation.peer
            )),
        }
    }

    if mismatches.is_empty() {
        MembershipConvergenceProbeResult {
            converged: true,
            reason: "converged",
            warning: None,
            observed_at_unix_ms,
        }
    } else {
        MembershipConvergenceProbeResult {
            converged: false,
            reason: "membership-view-mismatch",
            warning: Some(format!(
                "Membership view mismatch detected for {} peer(s): {}",
                mismatches.len(),
                mismatches.join(", ")
            )),
            observed_at_unix_ms,
        }
    }
}

pub(super) fn effective_membership_last_update_unix_ms(
    membership_status: &MembershipEngineStatus,
    membership_convergence_probe: &MembershipConvergenceProbeResult,
) -> u64 {
    membership_status
        .last_update_unix_ms
        .max(membership_convergence_probe.observed_at_unix_ms)
}

pub(super) fn record_membership_last_update(state: &AppState, observed_last_update_unix_ms: u64) {
    state
        .membership_last_update_unix_ms
        .fetch_max(observed_last_update_unix_ms, Ordering::Relaxed);
}

pub(super) fn record_membership_convergence(state: &AppState, converged: bool) {
    state
        .membership_converged
        .store(if converged { 1 } else { 0 }, Ordering::Relaxed);
}

pub(super) fn seeded_membership_convergence(
    membership_protocol: MembershipProtocol,
    membership_engine_ready: bool,
    cluster_peers: &[String],
    engine_converged: bool,
) -> bool {
    if membership_protocol_uses_probe_convergence(membership_protocol, membership_engine_ready)
        && !cluster_peers.is_empty()
    {
        return false;
    }
    engine_converged
}

pub(super) fn probe_cluster_peer_auth_status(
    config: &Config,
    topology: &RuntimeTopologySnapshot,
) -> ClusterPeerAuthStatus {
    let expected_node_id = config
        .cluster_auth_token()
        .map(|_| topology.node_id.as_str());
    let transport_identity_status =
        probe_peer_transport_identity_with_cert_sha256_pin_and_node_id_binding(
            config.cluster_peer_tls_cert_path(),
            config.cluster_peer_tls_key_path(),
            config.cluster_peer_tls_ca_path(),
            config.cluster_peer_tls_cert_sha256(),
            expected_node_id,
        );
    let transport_warning = transport_identity_status.warning.clone();
    let transport_identity = transport_identity_status.mode.as_str();
    let transport_reason = transport_identity_status.reason.as_str();
    let transport_ready = transport_identity_status.transport_ready;
    let cluster_auth_token = config.cluster_auth_token();

    if let Some(token) = cluster_auth_token {
        let binding_status = SharedTokenPeerAuthenticator::binding_status(
            token,
            &topology.node_id,
            &topology.cluster_peers,
        );
        let sender_allowlist_bound = binding_status.is_bound();
        let warning = if topology.is_distributed() {
            match binding_status {
                SharedTokenBindingStatus::Bound { trusted_peer_count } => {
                    if transport_ready {
                        Some(format!(
                            "Cluster peer auth uses shared-token header trust with sender allowlist binding ({trusted_peer_count} trusted peer(s)); mTLS transport identity files are configured/readable but cryptographic peer identity enforcement is not active yet."
                        ))
                    } else {
                        Some(format!(
                            "Cluster peer auth uses shared-token header trust with sender allowlist binding ({trusted_peer_count} trusted peer(s)); per-node cryptographic transport identity is not configured/ready (reason: {}).",
                            transport_reason
                        ))
                    }
                }
                SharedTokenBindingStatus::UnboundNoTrustedPeers => Some(
                    "Cluster peer auth uses shared-token header trust but sender allowlist binding is not active; verify node and peer identity configuration."
                        .to_string(),
                ),
                SharedTokenBindingStatus::InvalidToken => Some(
                    "Cluster peer auth token is invalid after normalization; sender allowlist binding is not active."
                        .to_string(),
                ),
                SharedTokenBindingStatus::InvalidLocalNodeId => Some(
                    "Local node id is invalid for shared-token peer-auth binding; sender allowlist binding is not active."
                        .to_string(),
                ),
            }
        } else {
            None
        };

        let warning = if warning.is_none() {
            transport_warning
        } else {
            warning
        };

        return ClusterPeerAuthStatus {
            configured: true,
            mode: "shared-token",
            trust_model: "forwarded-by-marker+shared-token",
            transport_identity,
            transport_reason,
            transport_ready,
            identity_bound: false,
            sender_allowlist_bound,
            warning,
        };
    }

    let warning = if topology.is_distributed() {
        Some(
            "Cluster peer auth token is not configured; internal forwarding trust is running in compatibility mode."
                .to_string(),
        )
    } else {
        transport_warning
    };

    ClusterPeerAuthStatus {
        configured: false,
        mode: "compatibility-no-token",
        trust_model: "forwarded-by-marker-only",
        transport_identity,
        transport_reason,
        transport_ready,
        identity_bound: false,
        sender_allowlist_bound: false,
        warning,
    }
}

pub(super) fn cluster_peer_auth_transport_required(
    config: &Config,
    topology: &RuntimeTopologySnapshot,
    auth_status: &ClusterPeerAuthStatus,
) -> bool {
    if !topology.is_distributed() || !auth_status.configured {
        return false;
    }
    if config.cluster_peer_transport_required() {
        return true;
    }
    auth_status.transport_identity == "mtls-path"
}

pub(super) fn probe_cluster_join_auth_status(
    state: &AppState,
    topology: &RuntimeTopologySnapshot,
) -> ClusterJoinAuthStatus {
    let mode = if state.config.cluster_auth_token().is_some() {
        "shared_token"
    } else {
        "compatibility_no_token"
    };
    if topology.is_distributed() && !topology.membership_status.ready {
        return ClusterJoinAuthStatus {
            mode,
            ready: false,
            reason: JOIN_AUTHORIZE_REASON_MEMBERSHIP_ENGINE_NOT_READY,
            warning: Some(
                "Cluster join authorization is unavailable while the configured membership engine is not ready."
                    .to_string(),
            ),
        };
    }
    if topology.is_distributed() && state.config.cluster_auth_token().is_none() {
        return ClusterJoinAuthStatus {
            mode,
            ready: false,
            reason: JOIN_AUTHORIZE_REASON_CLUSTER_AUTH_TOKEN_NOT_CONFIGURED,
            warning: Some(
                "Cluster join authorization requires shared-token peer auth in distributed mode; configure MAXIO_CLUSTER_AUTH_TOKEN."
                    .to_string(),
            ),
        };
    }

    let cluster_peer_auth_status = probe_cluster_peer_auth_status(state.config.as_ref(), topology);
    if cluster_peer_auth_transport_required(
        state.config.as_ref(),
        topology,
        &cluster_peer_auth_status,
    ) && !cluster_peer_auth_status.transport_ready
    {
        return ClusterJoinAuthStatus {
            mode,
            ready: false,
            reason: JOIN_AUTHORIZE_REASON_CLUSTER_PEER_TRANSPORT_NOT_READY,
            warning: Some(format!(
                "Cluster join authorization requires ready peer transport identity in current mode (reason: {}).",
                cluster_peer_auth_status.transport_reason
            )),
        };
    }

    let now_unix_ms = unix_ms_now();
    let mut headers = HeaderMap::new();

    let cluster_id = topology.cluster_id.trim();
    if let Ok(value) = HeaderValue::from_str(cluster_id) {
        headers.insert(JOIN_CLUSTER_ID_HEADER, value);
    }

    if let Ok(value) = HeaderValue::from_str("join-auth-probe-peer") {
        headers.insert(JOIN_NODE_ID_HEADER, value);
    }

    if let Ok(value) = HeaderValue::from_str(now_unix_ms.to_string().as_str()) {
        headers.insert(JOIN_TIMESTAMP_HEADER, value);
    }

    if let Ok(value) = HeaderValue::from_str("join-auth-probe-nonce") {
        headers.insert(JOIN_NONCE_HEADER, value);
    }

    if let Some(token) = state.config.cluster_auth_token() {
        if let Ok(value) = HeaderValue::from_str(token) {
            headers.insert(crate::cluster::security::INTERNAL_AUTH_TOKEN_HEADER, value);
        }
    }

    let result = authorize_join_request(
        &headers,
        cluster_id,
        state.config.cluster_auth_token(),
        topology.node_id.as_str(),
        now_unix_ms,
        DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
        None,
    );

    let ready = result.authorized;
    let reason = result.reject_reason();
    let warning = if ready {
        None
    } else {
        Some(format!(
            "Cluster join authorization readiness check failed: {reason}."
        ))
    };

    ClusterJoinAuthStatus {
        mode: result.mode.as_str(),
        ready,
        reason,
        warning,
    }
}
