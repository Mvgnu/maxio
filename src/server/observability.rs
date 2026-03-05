use super::*;

pub(super) fn health_payload(
    state: &AppState,
    topology: &RuntimeTopologySnapshot,
    uptime_seconds: f64,
    storage_probe: StorageDataPathProbeResult,
    peer_connectivity_probe: PeerConnectivityProbeResult,
) -> HealthPayload {
    let data_dir_probe = probe_data_dir(&state.config.data_dir);
    let disk_headroom_probe =
        probe_disk_headroom(&state.config.data_dir, state.config.min_disk_headroom_bytes);
    let pending_replication_queue_probe = probe_pending_replication_queue(&state.config.data_dir);
    let pending_rebalance_queue_probe = probe_pending_rebalance_queue(&state.config.data_dir);
    let pending_membership_propagation_queue_probe =
        probe_pending_membership_propagation_queue(&state.config.data_dir);
    let pending_metadata_repair_queue_probe =
        probe_pending_metadata_repair_queue(&state.config.data_dir);
    let persisted_metadata_state_probe = probe_persisted_metadata_state(&state.config.data_dir);
    let membership_status = topology.membership_status.clone();
    let cluster_peer_auth_status = probe_cluster_peer_auth_status(&state.config, topology);
    let cluster_peer_transport_policy = cluster_peer_auth_transport_policy_assessment(
        state.config.as_ref(),
        topology,
        &cluster_peer_auth_status,
    );
    let cluster_join_auth_status = probe_cluster_join_auth_status(state, topology);
    let cluster_peer_auth_transport_required = cluster_peer_transport_policy.required;
    let cluster_peer_auth_transport_ready = if cluster_peer_auth_transport_required {
        cluster_peer_transport_policy.is_ready()
    } else {
        cluster_peer_auth_status.transport_ready
    };
    let metadata_snapshot =
        metadata_snapshot_for_topology(topology, state.metadata_listing_strategy);
    let metadata_readiness =
        runtime_metadata_listing_readiness_for_topology(state, topology, &metadata_snapshot);
    let replay_counters = state.pending_replication_replay_counters.snapshot();
    let pending_rebalance_replay_counters = state.pending_rebalance_replay_counters.snapshot();
    let pending_membership_propagation_replay_counters = state
        .pending_membership_propagation_replay_counters
        .snapshot();
    let pending_metadata_repair_replay_counters =
        state.pending_metadata_repair_replay_counters.snapshot();

    let self_peer_misconfigured = topology
        .cluster_peers
        .iter()
        .any(|peer| peer_identity_eq(peer.as_str(), topology.node_id.as_str()));

    let mut warnings = Vec::new();
    if let Some(warning) = data_dir_probe.warning {
        warnings.push(warning);
    }
    if let Some(warning) = membership_status.warning.clone() {
        warnings.push(warning);
    }
    if let Some(warning) = storage_probe.warning {
        warnings.push(warning);
    }
    if let Some(warning) = disk_headroom_probe.warning {
        warnings.push(warning);
    }
    if let Some(warning) = pending_replication_queue_probe.warning.clone() {
        warnings.push(warning);
    }
    if let Some(warning) = pending_rebalance_queue_probe.warning.clone() {
        warnings.push(warning);
    }
    if let Some(warning) = pending_membership_propagation_queue_probe.warning.clone() {
        warnings.push(warning);
    }
    if pending_membership_propagation_queue_probe.readable
        && pending_membership_propagation_queue_probe.due_operations
            > PENDING_MEMBERSHIP_PROPAGATION_REPLAY_BATCH_SIZE
    {
        warnings.push(format!(
            "Pending membership propagation backlog has {} due operations, exceeding replay batch size {}.",
            pending_membership_propagation_queue_probe.due_operations,
            PENDING_MEMBERSHIP_PROPAGATION_REPLAY_BATCH_SIZE
        ));
    }
    if let Some(warning) = pending_metadata_repair_queue_probe.warning.clone() {
        warnings.push(warning);
    }
    if let Some(warning) = persisted_metadata_state_probe.warning.clone() {
        warnings.push(warning);
    }
    if let Some(warning) = peer_connectivity_probe.warning.clone() {
        warnings.push(warning);
    }
    if let Some(warning) = cluster_peer_auth_status.warning.clone() {
        warnings.push(warning);
    }
    if cluster_peer_auth_transport_required && !cluster_peer_auth_transport_ready {
        let reason = peer_transport_policy_reject_reason(&cluster_peer_transport_policy)
            .unwrap_or(cluster_peer_transport_policy.enforcement.reason);
        warnings.push(format!(
            "Cluster peer auth requires mTLS transport identity readiness under current runtime policy (reason: {}).",
            reason.as_str()
        ));
    }
    if let Some(warning) = cluster_join_auth_status.warning.clone() {
        warnings.push(warning);
    }
    let metadata_listing_required = topology.is_distributed();
    if metadata_listing_required && !metadata_readiness.ready {
        warnings.push(format!(
            "Metadata listing strategy '{}' is not ready for distributed cluster-authoritative listing (gap: {}).",
            state.metadata_listing_strategy.as_str(),
            metadata_readiness
                .gap
                .as_deref()
                .unwrap_or("unknown")
        ));
    }
    let membership_convergence_probe =
        probe_membership_convergence(topology, &membership_status, &peer_connectivity_probe);
    let membership_last_update_unix_ms =
        effective_membership_last_update_unix_ms(&membership_status, &membership_convergence_probe);
    record_membership_last_update(state, membership_last_update_unix_ms);
    record_membership_convergence(state, membership_convergence_probe.converged);
    if let Some(warning) = membership_convergence_probe.warning {
        warnings.push(warning);
    }
    if self_peer_misconfigured {
        warnings.push(format!(
            "Cluster peer configuration includes local node id '{}' which can cause split-brain or forwarding loops.",
            topology.node_id
        ));
    }

    let checks = HealthChecksPayload {
        data_dir_accessible: data_dir_probe.accessible,
        data_dir_writable: data_dir_probe.writable,
        storage_data_path_readable: storage_probe.readable,
        disk_headroom_sufficient: disk_headroom_probe.sufficient,
        pending_replication_queue_readable: pending_replication_queue_probe.readable,
        pending_rebalance_queue_readable: pending_rebalance_queue_probe.readable,
        pending_membership_propagation_queue_readable: pending_membership_propagation_queue_probe
            .readable,
        pending_metadata_repair_queue_readable: pending_metadata_repair_queue_probe.readable,
        metadata_state_queryable: persisted_metadata_state_probe.queryable,
        peer_connectivity_ready: peer_connectivity_probe.ready && !self_peer_misconfigured,
        cluster_peer_auth_configured: cluster_peer_auth_status.configured,
        cluster_peer_auth_identity_bound: cluster_peer_auth_status.identity_bound,
        cluster_peer_auth_transport_ready,
        cluster_peer_auth_transport_required,
        cluster_peer_auth_sender_allowlist_bound: cluster_peer_auth_status.sender_allowlist_bound,
        cluster_join_auth_ready: cluster_join_auth_status.ready,
        metadata_list_cluster_authoritative: metadata_readiness.cluster_authoritative,
        metadata_list_ready: !metadata_listing_required || metadata_readiness.ready,
        membership_protocol_ready: membership_status.ready,
        membership_converged: membership_convergence_probe.converged,
    };
    let cluster_peer_auth_required = topology.is_distributed();
    let cluster_join_auth_required = topology.is_distributed();
    let peer_connectivity_required = topology.is_distributed()
        && membership_protocol_uses_probe_convergence(
            topology.membership_protocol,
            membership_status.ready,
        );
    let membership_convergence_required = peer_connectivity_required;
    let metadata_listing_required = topology.is_distributed();
    let metadata_state_queryable_required = topology.is_distributed()
        && state.metadata_listing_strategy == ClusterMetadataListingStrategy::ConsensusIndex;
    let pending_replication_queue_required = topology.is_distributed()
        && state.write_durability_mode == WriteDurabilityMode::DegradedSuccess;
    let pending_membership_propagation_queue_required = topology.is_distributed();
    let ok = checks.data_dir_accessible
        && checks.data_dir_writable
        && checks.storage_data_path_readable
        && checks.disk_headroom_sufficient
        && (!metadata_state_queryable_required || checks.metadata_state_queryable)
        && (!pending_replication_queue_required || checks.pending_replication_queue_readable)
        && (!pending_membership_propagation_queue_required
            || checks.pending_membership_propagation_queue_readable)
        && (!cluster_peer_auth_transport_required || checks.cluster_peer_auth_transport_ready)
        && (!cluster_peer_auth_required || checks.cluster_peer_auth_sender_allowlist_bound)
        && (!cluster_join_auth_required || checks.cluster_join_auth_ready)
        && (!metadata_listing_required || checks.metadata_list_ready)
        && (!peer_connectivity_required || checks.peer_connectivity_ready)
        && (!membership_convergence_required || checks.membership_converged)
        && checks.membership_protocol_ready;
    let status = if ok { "ok" } else { "degraded" };

    HealthPayload {
        ok,
        status: status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds,
        mode: topology.mode.as_str().to_string(),
        node_id: topology.node_id.clone(),
        cluster_id: topology.cluster_id.clone(),
        cluster_peer_count: topology.cluster_peer_count(),
        cluster_peers: topology.cluster_peers.clone(),
        membership_node_count: topology.membership_node_count(),
        membership_nodes: topology.membership_nodes.clone(),
        cluster_auth_mode: cluster_peer_auth_status.mode.to_string(),
        cluster_auth_trust_model: cluster_peer_auth_status.trust_model.to_string(),
        cluster_auth_transport_identity: cluster_peer_auth_status
            .transport_identity
            .as_str()
            .to_string(),
        cluster_auth_transport_reason: if cluster_peer_transport_policy.required {
            cluster_peer_transport_policy.enforcement.reason
        } else {
            cluster_peer_auth_status.transport_reason
        }
        .as_str()
        .to_string(),
        cluster_auth_transport_required: cluster_peer_auth_transport_required,
        cluster_join_auth_mode: cluster_join_auth_status.mode.to_string(),
        cluster_join_auth_reason: cluster_join_auth_status.reason.to_string(),
        membership_protocol: topology.membership_protocol.as_str().to_string(),
        write_durability_mode: state.write_durability_mode.as_str().to_string(),
        metadata_listing_strategy: state.metadata_listing_strategy.as_str().to_string(),
        metadata_listing_gap: metadata_readiness.gap.clone(),
        metadata_listing_snapshot_id: metadata_snapshot.snapshot_id.clone(),
        metadata_listing_expected_nodes: metadata_snapshot.coverage_assessment.expected_nodes,
        metadata_listing_responded_nodes: metadata_snapshot.coverage_assessment.responded_nodes,
        metadata_listing_missing_nodes: metadata_snapshot.coverage_assessment.missing_nodes,
        metadata_listing_unexpected_nodes: metadata_snapshot.coverage_assessment.unexpected_nodes,
        membership_engine: membership_status.engine,
        membership_convergence_reason: membership_convergence_probe.reason.to_string(),
        membership_last_update_unix_ms,
        membership_view_id: topology.membership_view_id.clone(),
        placement_epoch: topology.placement_epoch,
        pending_replication_backlog_operations: pending_replication_queue_probe.summary.operations,
        pending_replication_backlog_pending_targets: pending_replication_queue_probe
            .summary
            .pending_targets,
        pending_replication_backlog_due_targets: pending_replication_queue_probe.due_targets,
        pending_replication_backlog_due_targets_capped: pending_replication_queue_probe
            .due_targets_capped,
        pending_replication_backlog_failed_targets: pending_replication_queue_probe
            .summary
            .failed_targets,
        pending_replication_backlog_max_attempts: pending_replication_queue_probe
            .summary
            .max_attempts,
        pending_replication_backlog_oldest_created_at_unix_ms: pending_replication_queue_probe
            .summary
            .oldest_created_at_unix_ms,
        pending_replication_replay_cycles_total: replay_counters.cycles_total,
        pending_replication_replay_cycles_succeeded: replay_counters.cycles_succeeded,
        pending_replication_replay_cycles_failed: replay_counters.cycles_failed,
        pending_replication_replay_last_cycle_unix_ms: replay_counters.last_cycle_unix_ms,
        pending_replication_replay_last_success_unix_ms: replay_counters.last_success_unix_ms,
        pending_replication_replay_last_failure_unix_ms: replay_counters.last_failure_unix_ms,
        pending_rebalance_backlog_operations: pending_rebalance_queue_probe.summary.operations,
        pending_rebalance_backlog_pending_transfers: pending_rebalance_queue_probe
            .summary
            .pending_transfers,
        pending_rebalance_backlog_due_transfers: pending_rebalance_queue_probe.due_transfers,
        pending_rebalance_backlog_due_transfers_capped: pending_rebalance_queue_probe
            .due_transfers_capped,
        pending_rebalance_backlog_failed_transfers: pending_rebalance_queue_probe
            .summary
            .failed_transfers,
        pending_rebalance_backlog_max_attempts: pending_rebalance_queue_probe.summary.max_attempts,
        pending_rebalance_backlog_oldest_created_at_unix_ms: pending_rebalance_queue_probe
            .summary
            .oldest_created_at_unix_ms,
        pending_rebalance_replay_cycles_total: pending_rebalance_replay_counters.cycles_total,
        pending_rebalance_replay_cycles_succeeded: pending_rebalance_replay_counters
            .cycles_succeeded,
        pending_rebalance_replay_cycles_failed: pending_rebalance_replay_counters.cycles_failed,
        pending_rebalance_replay_last_cycle_unix_ms: pending_rebalance_replay_counters
            .last_cycle_unix_ms,
        pending_rebalance_replay_last_success_unix_ms: pending_rebalance_replay_counters
            .last_success_unix_ms,
        pending_rebalance_replay_last_failure_unix_ms: pending_rebalance_replay_counters
            .last_failure_unix_ms,
        pending_membership_propagation_backlog_operations:
            pending_membership_propagation_queue_probe
                .summary
                .operations,
        pending_membership_propagation_backlog_due_operations:
            pending_membership_propagation_queue_probe.due_operations,
        pending_membership_propagation_backlog_due_operations_capped:
            pending_membership_propagation_queue_probe.due_operations_capped,
        pending_membership_propagation_backlog_failed_operations:
            pending_membership_propagation_queue_probe
                .summary
                .failed_operations,
        pending_membership_propagation_backlog_max_attempts:
            pending_membership_propagation_queue_probe
                .summary
                .max_attempts,
        pending_membership_propagation_backlog_oldest_created_at_unix_ms:
            pending_membership_propagation_queue_probe
                .summary
                .oldest_created_at_unix_ms,
        pending_membership_propagation_replay_cycles_total:
            pending_membership_propagation_replay_counters.cycles_total,
        pending_membership_propagation_replay_cycles_succeeded:
            pending_membership_propagation_replay_counters.cycles_succeeded,
        pending_membership_propagation_replay_cycles_failed:
            pending_membership_propagation_replay_counters.cycles_failed,
        pending_membership_propagation_replay_last_cycle_unix_ms:
            pending_membership_propagation_replay_counters.last_cycle_unix_ms,
        pending_membership_propagation_replay_last_success_unix_ms:
            pending_membership_propagation_replay_counters.last_success_unix_ms,
        pending_membership_propagation_replay_last_failure_unix_ms:
            pending_membership_propagation_replay_counters.last_failure_unix_ms,
        pending_metadata_repair_backlog_plans: pending_metadata_repair_queue_probe.summary.plans,
        pending_metadata_repair_backlog_due_plans: pending_metadata_repair_queue_probe.due_plans,
        pending_metadata_repair_backlog_due_plans_capped: pending_metadata_repair_queue_probe
            .due_plans_capped,
        pending_metadata_repair_backlog_failed_plans: pending_metadata_repair_queue_probe
            .summary
            .failed_plans,
        pending_metadata_repair_backlog_max_attempts: pending_metadata_repair_queue_probe
            .summary
            .max_attempts,
        pending_metadata_repair_backlog_oldest_created_at_unix_ms:
            pending_metadata_repair_queue_probe
                .summary
                .oldest_created_at_unix_ms,
        pending_metadata_repair_replay_cycles_total: pending_metadata_repair_replay_counters
            .cycles_total,
        pending_metadata_repair_replay_cycles_succeeded: pending_metadata_repair_replay_counters
            .cycles_succeeded,
        pending_metadata_repair_replay_cycles_failed: pending_metadata_repair_replay_counters
            .cycles_failed,
        pending_metadata_repair_replay_last_cycle_unix_ms: pending_metadata_repair_replay_counters
            .last_cycle_unix_ms,
        pending_metadata_repair_replay_last_success_unix_ms:
            pending_metadata_repair_replay_counters.last_success_unix_ms,
        pending_metadata_repair_replay_last_failure_unix_ms:
            pending_metadata_repair_replay_counters.last_failure_unix_ms,
        metadata_state_view_id: persisted_metadata_state_probe.view_id,
        metadata_state_bucket_rows: persisted_metadata_state_probe.bucket_rows,
        metadata_state_object_rows: persisted_metadata_state_probe.object_rows,
        metadata_state_object_version_rows: persisted_metadata_state_probe.object_version_rows,
        checks,
        warnings,
    }
}

pub(crate) async fn runtime_health_payload(state: &AppState) -> HealthPayload {
    let uptime_seconds = state.started_at.elapsed().as_secs_f64();
    let topology = runtime_topology_snapshot(state);
    let storage_probe = probe_storage_data_path(&state.storage).await;
    let peer_connectivity_probe = probe_peer_connectivity(
        topology.cluster_peers.as_slice(),
        Some(state.config.as_ref()),
    )
    .await;
    health_payload(
        state,
        &topology,
        uptime_seconds,
        storage_probe,
        peer_connectivity_probe,
    )
}

pub(super) async fn metrics_handler(State(state): State<AppState>) -> Response {
    let topology = runtime_topology_snapshot(&state);
    let request_count = state.request_count.load(Ordering::Relaxed);
    let uptime = state.started_at.elapsed().as_secs_f64();
    let distributed_mode = if topology.is_distributed() { 1 } else { 0 };
    let cluster_peer_count = topology.cluster_peer_count();
    let membership_node_count = topology.membership_node_count();
    let membership_protocol = topology.membership_protocol.as_str();
    let write_durability_mode = state.write_durability_mode.as_str();
    let metadata_listing_strategy = state.metadata_listing_strategy.as_str();
    let metadata_snapshot =
        metadata_snapshot_for_topology(&topology, state.metadata_listing_strategy);
    let metadata_readiness =
        runtime_metadata_listing_readiness_for_topology(&state, &topology, &metadata_snapshot);
    let metadata_list_cluster_authoritative = if metadata_readiness.cluster_authoritative {
        1
    } else {
        0
    };
    let metadata_list_ready = if !topology.is_distributed() || metadata_readiness.ready {
        1
    } else {
        0
    };
    let metadata_listing_gap = metadata_readiness.gap.as_deref().unwrap_or("none");
    let metadata_listing_expected_nodes = metadata_snapshot.coverage_assessment.expected_nodes;
    let metadata_listing_responded_nodes = metadata_snapshot.coverage_assessment.responded_nodes;
    let metadata_listing_missing_nodes = metadata_snapshot.coverage_assessment.missing_nodes;
    let metadata_listing_unexpected_nodes = metadata_snapshot.coverage_assessment.unexpected_nodes;
    let membership_engine = topology.membership_status.engine.as_str();
    let cluster_peer_auth_status = probe_cluster_peer_auth_status(&state.config, &topology);
    let cluster_peer_transport_policy = cluster_peer_auth_transport_policy_assessment(
        state.config.as_ref(),
        &topology,
        &cluster_peer_auth_status,
    );
    let cluster_join_auth_status = probe_cluster_join_auth_status(&state, &topology);
    let cluster_id = topology.cluster_id.as_str();
    let cluster_auth_mode = cluster_peer_auth_status.mode;
    let cluster_auth_trust_model = cluster_peer_auth_status.trust_model;
    let cluster_auth_transport_identity = cluster_peer_auth_status.transport_identity.as_str();
    let cluster_auth_transport_reason = if cluster_peer_transport_policy.required {
        peer_transport_policy_reject_reason(&cluster_peer_transport_policy)
            .unwrap_or(cluster_peer_transport_policy.enforcement.reason)
            .as_str()
    } else {
        cluster_peer_auth_status.transport_reason.as_str()
    };
    let cluster_join_auth_mode = cluster_join_auth_status.mode;
    let cluster_join_auth_ready = if cluster_join_auth_status.ready { 1 } else { 0 };
    let cluster_join_auth_reason = cluster_join_auth_status.reason;
    let cluster_peer_auth_configured = if cluster_peer_auth_status.configured {
        1
    } else {
        0
    };
    let cluster_peer_auth_identity_bound = if cluster_peer_auth_status.identity_bound {
        1
    } else {
        0
    };
    let cluster_peer_auth_sender_allowlist_bound =
        if cluster_peer_auth_status.sender_allowlist_bound {
            1
        } else {
            0
        };
    let cluster_peer_auth_transport_ready_value = if cluster_peer_transport_policy.required {
        cluster_peer_transport_policy.is_ready()
    } else {
        cluster_peer_auth_status.transport_ready
    };
    let cluster_peer_auth_transport_ready = if cluster_peer_auth_transport_ready_value {
        1
    } else {
        0
    };
    let cluster_peer_auth_transport_required = if cluster_peer_transport_policy.required {
        1
    } else {
        0
    };
    let membership_protocol_ready = if topology.membership_status.ready {
        1
    } else {
        0
    };
    let peer_connectivity_probe = probe_peer_connectivity(
        topology.cluster_peers.as_slice(),
        Some(state.config.as_ref()),
    )
    .await;
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
    let membership_converged = if membership_convergence_probe.converged {
        1
    } else {
        0
    };
    let membership_convergence_reason = membership_convergence_probe.reason;
    let peer_auth_reject_counters = peer_auth_reject_counters_snapshot();
    let join_authorize_counters = state.cluster_join_authorize_counters.snapshot();
    let join_counters = state.cluster_join_counters.snapshot();
    let membership_update_counters = state.cluster_membership_update_counters.snapshot();
    let runtime_internal_reject_dimensions =
        state.runtime_internal_header_reject_dimensions.snapshot();
    let placement_epoch = topology.placement_epoch;
    let pending_replication_queue_probe = probe_pending_replication_queue(&state.config.data_dir);
    let pending_replication_queue_readable = if pending_replication_queue_probe.readable {
        1
    } else {
        0
    };
    let pending_replication_backlog_due_targets_capped =
        if pending_replication_queue_probe.due_targets_capped {
            1
        } else {
            0
        };
    let pending_replication_backlog_oldest_created_at_unix_ms = pending_replication_queue_probe
        .summary
        .oldest_created_at_unix_ms
        .unwrap_or(0);
    let pending_replication_replay_counters = state.pending_replication_replay_counters.snapshot();
    let pending_rebalance_queue_probe = probe_pending_rebalance_queue(&state.config.data_dir);
    let pending_rebalance_queue_readable = if pending_rebalance_queue_probe.readable {
        1
    } else {
        0
    };
    let pending_rebalance_backlog_due_transfers_capped =
        if pending_rebalance_queue_probe.due_transfers_capped {
            1
        } else {
            0
        };
    let pending_rebalance_backlog_oldest_created_at_unix_ms = pending_rebalance_queue_probe
        .summary
        .oldest_created_at_unix_ms
        .unwrap_or(0);
    let pending_rebalance_replay_counters = state.pending_rebalance_replay_counters.snapshot();
    let pending_membership_propagation_queue_probe =
        probe_pending_membership_propagation_queue(&state.config.data_dir);
    let pending_membership_propagation_queue_readable =
        if pending_membership_propagation_queue_probe.readable {
            1
        } else {
            0
        };
    let pending_membership_propagation_backlog_due_operations_capped =
        if pending_membership_propagation_queue_probe.due_operations_capped {
            1
        } else {
            0
        };
    let pending_membership_propagation_backlog_oldest_created_at_unix_ms =
        pending_membership_propagation_queue_probe
            .summary
            .oldest_created_at_unix_ms
            .unwrap_or(0);
    let pending_membership_propagation_replay_counters = state
        .pending_membership_propagation_replay_counters
        .snapshot();
    let pending_metadata_repair_queue_probe =
        probe_pending_metadata_repair_queue(&state.config.data_dir);
    let persisted_metadata_state_probe = probe_persisted_metadata_state(&state.config.data_dir);
    let pending_metadata_repair_queue_readable = if pending_metadata_repair_queue_probe.readable {
        1
    } else {
        0
    };
    let metadata_state_readable = if persisted_metadata_state_probe.readable {
        1
    } else {
        0
    };
    let metadata_state_queryable = if persisted_metadata_state_probe.queryable {
        1
    } else {
        0
    };
    let pending_metadata_repair_backlog_due_plans_capped =
        if pending_metadata_repair_queue_probe.due_plans_capped {
            1
        } else {
            0
        };
    let pending_metadata_repair_backlog_oldest_created_at_unix_ms =
        pending_metadata_repair_queue_probe
            .summary
            .oldest_created_at_unix_ms
            .unwrap_or(0);
    let pending_metadata_repair_replay_counters =
        state.pending_metadata_repair_replay_counters.snapshot();

    let mut body = format!(
        "# HELP maxio_requests_total Total HTTP requests observed by MaxIO.\n\
         # TYPE maxio_requests_total counter\n\
         maxio_requests_total {}\n\
         # HELP maxio_uptime_seconds MaxIO process uptime in seconds.\n\
         # TYPE maxio_uptime_seconds gauge\n\
         maxio_uptime_seconds {:.3}\n\
         # HELP maxio_build_info Build and version information for MaxIO.\n\
         # TYPE maxio_build_info gauge\n\
         maxio_build_info{{version=\"{}\"}} 1\n\
         # HELP maxio_distributed_mode Whether MaxIO is running with configured cluster peers (1=true, 0=false).\n\
         # TYPE maxio_distributed_mode gauge\n\
         maxio_distributed_mode {}\n\
         # HELP maxio_cluster_peers_total Number of configured cluster peers.\n\
         # TYPE maxio_cluster_peers_total gauge\n\
         maxio_cluster_peers_total {}\n\
         # HELP maxio_cluster_identity_info Stable runtime cluster identity used by join authorization checks.\n\
         # TYPE maxio_cluster_identity_info gauge\n\
         maxio_cluster_identity_info{{cluster_id=\"{}\"}} 1\n\
         # HELP maxio_membership_nodes_total Number of nodes in the normalized runtime membership view (self + peers).\n\
         # TYPE maxio_membership_nodes_total gauge\n\
         maxio_membership_nodes_total {}\n\
         # HELP maxio_cluster_peer_auth_mode_info Cluster peer auth mode for trusted node-to-node traffic.\n\
         # TYPE maxio_cluster_peer_auth_mode_info gauge\n\
         maxio_cluster_peer_auth_mode_info{{mode=\"{}\"}} 1\n\
         # HELP maxio_cluster_peer_auth_configured Whether cluster peer auth is configured (1=true, 0=compatibility mode).\n\
         # TYPE maxio_cluster_peer_auth_configured gauge\n\
         maxio_cluster_peer_auth_configured {}\n\
         # HELP maxio_cluster_peer_auth_trust_model_info Cluster internal-header trust model used for node-to-node traffic.\n\
         # TYPE maxio_cluster_peer_auth_trust_model_info gauge\n\
         maxio_cluster_peer_auth_trust_model_info{{model=\"{}\"}} 1\n\
         # HELP maxio_cluster_peer_auth_identity_bound Whether peer auth is bound to cryptographic node identity (1=true, 0=header/token-only).\n\
         # TYPE maxio_cluster_peer_auth_identity_bound gauge\n\
         maxio_cluster_peer_auth_identity_bound {}\n\
         # HELP maxio_cluster_peer_auth_sender_allowlist_bound Whether peer auth enforces direct sender membership allowlist binding (1=true, 0=false).\n\
         # TYPE maxio_cluster_peer_auth_sender_allowlist_bound gauge\n\
         maxio_cluster_peer_auth_sender_allowlist_bound {}\n\
         # HELP maxio_cluster_peer_auth_transport_identity_info Internal transport identity mode used for peer auth readiness checks.\n\
         # TYPE maxio_cluster_peer_auth_transport_identity_info gauge\n\
         maxio_cluster_peer_auth_transport_identity_info{{identity=\"{}\"}} 1\n\
         # HELP maxio_cluster_peer_auth_transport_ready Whether peer-transport identity configuration is ready (1=true, 0=false).\n\
         # TYPE maxio_cluster_peer_auth_transport_ready gauge\n\
         maxio_cluster_peer_auth_transport_ready {}\n\
         # HELP maxio_cluster_peer_auth_transport_required Whether mTLS peer transport readiness is required by current cluster peer transport policy (1=true, 0=false).\n\
         # TYPE maxio_cluster_peer_auth_transport_required gauge\n\
         maxio_cluster_peer_auth_transport_required {}\n\
         # HELP maxio_cluster_peer_auth_transport_reason_info Peer-transport identity readiness reason label for current runtime configuration.\n\
         # TYPE maxio_cluster_peer_auth_transport_reason_info gauge\n\
         maxio_cluster_peer_auth_transport_reason_info{{reason=\"{}\"}} 1\n\
         # HELP maxio_cluster_join_auth_mode_info Join authorization mode for membership control requests.\n\
         # TYPE maxio_cluster_join_auth_mode_info gauge\n\
         maxio_cluster_join_auth_mode_info{{mode=\"{}\"}} 1\n\
         # HELP maxio_cluster_join_auth_ready Whether join authorization boundary is ready for runtime use (1=true, 0=false).\n\
         # TYPE maxio_cluster_join_auth_ready gauge\n\
         maxio_cluster_join_auth_ready {}\n\
         # HELP maxio_cluster_join_auth_readiness_reason_info Join authorization readiness result reason for current runtime state.\n\
         # TYPE maxio_cluster_join_auth_readiness_reason_info gauge\n\
         maxio_cluster_join_auth_readiness_reason_info{{reason=\"{}\"}} 1\n\
         # HELP maxio_cluster_peer_auth_reject_total Total number of untrusted forwarded-request header sets rejected post-authentication.\n\
         # TYPE maxio_cluster_peer_auth_reject_total counter\n\
         maxio_cluster_peer_auth_reject_total {}\n\
         # HELP maxio_cluster_peer_auth_reject_reason_total Rejected forwarded-request counts by peer-auth reject reason.\n\
         # TYPE maxio_cluster_peer_auth_reject_reason_total counter\n\
         maxio_cluster_peer_auth_reject_reason_total{{reason=\"missing_or_malformed_forwarded_by\"}} {}\n\
         maxio_cluster_peer_auth_reject_reason_total{{reason=\"malformed_forwarded_by_chain\"}} {}\n\
         maxio_cluster_peer_auth_reject_reason_total{{reason=\"forwarded_by_hop_limit_exceeded\"}} {}\n\
         maxio_cluster_peer_auth_reject_reason_total{{reason=\"forwarded_by_duplicate_peer_hop\"}} {}\n\
         maxio_cluster_peer_auth_reject_reason_total{{reason=\"auth_token_mismatch\"}} {}\n\
         maxio_cluster_peer_auth_reject_reason_total{{reason=\"missing_or_malformed_auth_token\"}} {}\n\
         maxio_cluster_peer_auth_reject_reason_total{{reason=\"duplicate_auth_token_headers\"}} {}\n\
         maxio_cluster_peer_auth_reject_reason_total{{reason=\"missing_sender_identity\"}} {}\n\
         maxio_cluster_peer_auth_reject_reason_total{{reason=\"sender_matches_local_node\"}} {}\n\
         maxio_cluster_peer_auth_reject_reason_total{{reason=\"sender_not_in_allowlist\"}} {}\n\
         maxio_cluster_peer_auth_reject_reason_total{{reason=\"invalid_authenticator_configuration\"}} {}\n\
         maxio_cluster_peer_auth_reject_reason_total{{reason=\"unknown\"}} {}\n\
         # HELP maxio_runtime_internal_header_reject_total Total rejected untrusted internal-header requests observed on runtime/console routes.\n\
         # TYPE maxio_runtime_internal_header_reject_total counter\n\
         maxio_runtime_internal_header_reject_total {}\n\
         # HELP maxio_runtime_internal_header_reject_endpoint_total Runtime internal-header rejects grouped by endpoint family.\n\
         # TYPE maxio_runtime_internal_header_reject_endpoint_total counter\n\
         maxio_runtime_internal_header_reject_endpoint_total{{endpoint=\"api\"}} {}\n\
         maxio_runtime_internal_header_reject_endpoint_total{{endpoint=\"healthz\"}} {}\n\
         maxio_runtime_internal_header_reject_endpoint_total{{endpoint=\"metrics\"}} {}\n\
         maxio_runtime_internal_header_reject_endpoint_total{{endpoint=\"ui\"}} {}\n\
         maxio_runtime_internal_header_reject_endpoint_total{{endpoint=\"other\"}} {}\n\
         # HELP maxio_runtime_internal_header_reject_sender_total Runtime internal-header rejects grouped by direct forwarded sender category.\n\
         # TYPE maxio_runtime_internal_header_reject_sender_total counter\n\
         maxio_runtime_internal_header_reject_sender_total{{sender=\"known_peer\"}} {}\n\
         maxio_runtime_internal_header_reject_sender_total{{sender=\"local_node\"}} {}\n\
         maxio_runtime_internal_header_reject_sender_total{{sender=\"unknown_peer\"}} {}\n\
         maxio_runtime_internal_header_reject_sender_total{{sender=\"missing_or_invalid\"}} {}\n\
         # HELP maxio_membership_protocol_info Membership protocol configuration for runtime topology convergence.\n\
         # TYPE maxio_membership_protocol_info gauge\n\
         maxio_membership_protocol_info{{protocol=\"{}\"}} 1\n\
         # HELP maxio_write_durability_mode_info Distributed write durability contract mode.\n\
         # TYPE maxio_write_durability_mode_info gauge\n\
         maxio_write_durability_mode_info{{mode=\"{}\"}} 1\n\
         # HELP maxio_metadata_listing_strategy_info Distributed metadata listing strategy contract mode.\n\
         # TYPE maxio_metadata_listing_strategy_info gauge\n\
         maxio_metadata_listing_strategy_info{{strategy=\"{}\"}} 1\n\
         # HELP maxio_metadata_listing_cluster_authoritative Whether configured metadata listing strategy is cluster-authoritative (1=true, 0=false).\n\
         # TYPE maxio_metadata_listing_cluster_authoritative gauge\n\
         maxio_metadata_listing_cluster_authoritative {}\n\
         # HELP maxio_metadata_listing_ready Whether metadata listing is ready for current runtime mode (1=true, 0=false).\n\
         # TYPE maxio_metadata_listing_ready gauge\n\
         maxio_metadata_listing_ready {}\n\
         # HELP maxio_metadata_listing_gap_info Metadata listing readiness gap for current runtime mode.\n\
         # TYPE maxio_metadata_listing_gap_info gauge\n\
         maxio_metadata_listing_gap_info{{gap=\"{}\"}} 1\n\
         # HELP maxio_membership_engine_info Membership engine implementation currently active at runtime.\n\
         # TYPE maxio_membership_engine_info gauge\n\
         maxio_membership_engine_info{{engine=\"{}\"}} 1\n\
         # HELP maxio_membership_protocol_ready Membership protocol readiness (1=implemented/active, 0=placeholder/unimplemented).\n\
         # TYPE maxio_membership_protocol_ready gauge\n\
         maxio_membership_protocol_ready {}\n\
         # HELP maxio_membership_converged Membership convergence status (1=converged, 0=not converged).\n\
         # TYPE maxio_membership_converged gauge\n\
         maxio_membership_converged {}\n\
         # HELP maxio_membership_convergence_reason_info Membership convergence probe outcome reason.\n\
         # TYPE maxio_membership_convergence_reason_info gauge\n\
         maxio_membership_convergence_reason_info{{reason=\"{}\"}} 1\n\
         # HELP maxio_membership_last_update_unix_ms Membership status observation timestamp in Unix milliseconds.\n\
         # TYPE maxio_membership_last_update_unix_ms gauge\n\
         maxio_membership_last_update_unix_ms {}\n\
         # HELP maxio_placement_epoch Current placement epoch for the active runtime membership view.\n\
         # TYPE maxio_placement_epoch gauge\n\
         maxio_placement_epoch {}\n\
         # HELP maxio_pending_replication_queue_readable Whether pending replication queue diagnostics are readable from runtime state (1=true, 0=false).\n\
         # TYPE maxio_pending_replication_queue_readable gauge\n\
         maxio_pending_replication_queue_readable {}\n\
         # HELP maxio_pending_replication_backlog_operations Pending replication backlog operation count.\n\
         # TYPE maxio_pending_replication_backlog_operations gauge\n\
         maxio_pending_replication_backlog_operations {}\n\
         # HELP maxio_pending_replication_backlog_pending_targets Pending replication backlog target count awaiting ack.\n\
         # TYPE maxio_pending_replication_backlog_pending_targets gauge\n\
         maxio_pending_replication_backlog_pending_targets {}\n\
         # HELP maxio_pending_replication_backlog_due_targets Pending replication backlog targets currently due for replay execution.\n\
         # TYPE maxio_pending_replication_backlog_due_targets gauge\n\
         maxio_pending_replication_backlog_due_targets {}\n\
         # HELP maxio_pending_replication_backlog_due_targets_capped Whether due target count reached probe cap (1=true, 0=false).\n\
         # TYPE maxio_pending_replication_backlog_due_targets_capped gauge\n\
         maxio_pending_replication_backlog_due_targets_capped {}\n\
         # HELP maxio_pending_replication_backlog_failed_targets Pending replication backlog target count with last_error set.\n\
         # TYPE maxio_pending_replication_backlog_failed_targets gauge\n\
         maxio_pending_replication_backlog_failed_targets {}\n\
         # HELP maxio_pending_replication_backlog_max_attempts Maximum retry attempts recorded across pending replication targets.\n\
         # TYPE maxio_pending_replication_backlog_max_attempts gauge\n\
         maxio_pending_replication_backlog_max_attempts {}\n\
         # HELP maxio_pending_replication_backlog_oldest_created_at_unix_ms Oldest pending replication backlog operation creation timestamp in Unix milliseconds (0 when queue is empty).\n\
         # TYPE maxio_pending_replication_backlog_oldest_created_at_unix_ms gauge\n\
         maxio_pending_replication_backlog_oldest_created_at_unix_ms {}\n\
         # HELP maxio_pending_rebalance_queue_readable Whether pending rebalance queue diagnostics are readable from runtime state (1=true, 0=false).\n\
         # TYPE maxio_pending_rebalance_queue_readable gauge\n\
         maxio_pending_rebalance_queue_readable {}\n\
         # HELP maxio_pending_rebalance_backlog_operations Pending rebalance backlog operation count.\n\
         # TYPE maxio_pending_rebalance_backlog_operations gauge\n\
         maxio_pending_rebalance_backlog_operations {}\n\
         # HELP maxio_pending_rebalance_backlog_pending_transfers Pending rebalance backlog transfer count awaiting completion.\n\
         # TYPE maxio_pending_rebalance_backlog_pending_transfers gauge\n\
         maxio_pending_rebalance_backlog_pending_transfers {}\n\
         # HELP maxio_pending_rebalance_backlog_due_transfers Pending rebalance backlog transfers currently due for execution.\n\
         # TYPE maxio_pending_rebalance_backlog_due_transfers gauge\n\
         maxio_pending_rebalance_backlog_due_transfers {}\n\
         # HELP maxio_pending_rebalance_backlog_due_transfers_capped Whether due rebalance transfer count reached probe cap (1=true, 0=false).\n\
         # TYPE maxio_pending_rebalance_backlog_due_transfers_capped gauge\n\
         maxio_pending_rebalance_backlog_due_transfers_capped {}\n\
         # HELP maxio_pending_rebalance_backlog_failed_transfers Pending rebalance backlog transfer count with last_error set.\n\
         # TYPE maxio_pending_rebalance_backlog_failed_transfers gauge\n\
         maxio_pending_rebalance_backlog_failed_transfers {}\n\
         # HELP maxio_pending_rebalance_backlog_max_attempts Maximum retry attempts recorded across pending rebalance transfers.\n\
         # TYPE maxio_pending_rebalance_backlog_max_attempts gauge\n\
         maxio_pending_rebalance_backlog_max_attempts {}\n\
         # HELP maxio_pending_rebalance_backlog_oldest_created_at_unix_ms Oldest pending rebalance backlog operation creation timestamp in Unix milliseconds (0 when queue is empty).\n\
         # TYPE maxio_pending_rebalance_backlog_oldest_created_at_unix_ms gauge\n\
         maxio_pending_rebalance_backlog_oldest_created_at_unix_ms {}\n\
         # HELP maxio_pending_membership_propagation_queue_readable Whether pending membership propagation queue diagnostics are readable from runtime state (1=true, 0=false).\n\
         # TYPE maxio_pending_membership_propagation_queue_readable gauge\n\
         maxio_pending_membership_propagation_queue_readable {}\n\
         # HELP maxio_pending_membership_propagation_backlog_operations Pending membership propagation backlog operation count.\n\
         # TYPE maxio_pending_membership_propagation_backlog_operations gauge\n\
         maxio_pending_membership_propagation_backlog_operations {}\n\
         # HELP maxio_pending_membership_propagation_backlog_due_operations Pending membership propagation operations currently due for replay execution.\n\
         # TYPE maxio_pending_membership_propagation_backlog_due_operations gauge\n\
         maxio_pending_membership_propagation_backlog_due_operations {}\n\
         # HELP maxio_pending_membership_propagation_backlog_due_operations_capped Whether due membership propagation operation count reached probe cap (1=true, 0=false).\n\
         # TYPE maxio_pending_membership_propagation_backlog_due_operations_capped gauge\n\
         maxio_pending_membership_propagation_backlog_due_operations_capped {}\n\
         # HELP maxio_pending_membership_propagation_backlog_failed_operations Pending membership propagation operations with last_error set.\n\
         # TYPE maxio_pending_membership_propagation_backlog_failed_operations gauge\n\
         maxio_pending_membership_propagation_backlog_failed_operations {}\n\
         # HELP maxio_pending_membership_propagation_backlog_max_attempts Maximum retry attempts recorded across pending membership propagation operations.\n\
         # TYPE maxio_pending_membership_propagation_backlog_max_attempts gauge\n\
         maxio_pending_membership_propagation_backlog_max_attempts {}\n\
         # HELP maxio_pending_membership_propagation_backlog_oldest_created_at_unix_ms Oldest pending membership propagation operation creation timestamp in Unix milliseconds (0 when queue is empty).\n\
         # TYPE maxio_pending_membership_propagation_backlog_oldest_created_at_unix_ms gauge\n\
         maxio_pending_membership_propagation_backlog_oldest_created_at_unix_ms {}\n",
        request_count,
        uptime,
        env!("CARGO_PKG_VERSION"),
        distributed_mode,
        cluster_peer_count,
        cluster_id,
        membership_node_count,
        cluster_auth_mode,
        cluster_peer_auth_configured,
        cluster_auth_trust_model,
        cluster_peer_auth_identity_bound,
        cluster_peer_auth_sender_allowlist_bound,
        cluster_auth_transport_identity,
        cluster_peer_auth_transport_ready,
        cluster_peer_auth_transport_required,
        cluster_auth_transport_reason,
        cluster_join_auth_mode,
        cluster_join_auth_ready,
        cluster_join_auth_reason,
        peer_auth_reject_counters.total,
        peer_auth_reject_counters.missing_or_malformed_forwarded_by,
        peer_auth_reject_counters.malformed_forwarded_by_chain,
        peer_auth_reject_counters.forwarded_by_hop_limit_exceeded,
        peer_auth_reject_counters.forwarded_by_duplicate_peer_hop,
        peer_auth_reject_counters.auth_token_mismatch,
        peer_auth_reject_counters.missing_or_malformed_auth_token,
        peer_auth_reject_counters.duplicate_auth_token_headers,
        peer_auth_reject_counters.missing_sender_identity,
        peer_auth_reject_counters.sender_matches_local_node,
        peer_auth_reject_counters.sender_not_in_allowlist,
        peer_auth_reject_counters.invalid_authenticator_configuration,
        peer_auth_reject_counters.unknown,
        runtime_internal_reject_dimensions.total,
        runtime_internal_reject_dimensions.endpoint_api,
        runtime_internal_reject_dimensions.endpoint_healthz,
        runtime_internal_reject_dimensions.endpoint_metrics,
        runtime_internal_reject_dimensions.endpoint_ui,
        runtime_internal_reject_dimensions.endpoint_other,
        runtime_internal_reject_dimensions.sender_known_peer,
        runtime_internal_reject_dimensions.sender_local_node,
        runtime_internal_reject_dimensions.sender_unknown_peer,
        runtime_internal_reject_dimensions.sender_missing_or_invalid,
        membership_protocol,
        write_durability_mode,
        metadata_listing_strategy,
        metadata_list_cluster_authoritative,
        metadata_list_ready,
        metadata_listing_gap,
        membership_engine,
        membership_protocol_ready,
        membership_converged,
        membership_convergence_reason,
        membership_last_update_unix_ms,
        placement_epoch,
        pending_replication_queue_readable,
        pending_replication_queue_probe.summary.operations,
        pending_replication_queue_probe.summary.pending_targets,
        pending_replication_queue_probe.due_targets,
        pending_replication_backlog_due_targets_capped,
        pending_replication_queue_probe.summary.failed_targets,
        pending_replication_queue_probe.summary.max_attempts,
        pending_replication_backlog_oldest_created_at_unix_ms,
        pending_rebalance_queue_readable,
        pending_rebalance_queue_probe.summary.operations,
        pending_rebalance_queue_probe.summary.pending_transfers,
        pending_rebalance_queue_probe.due_transfers,
        pending_rebalance_backlog_due_transfers_capped,
        pending_rebalance_queue_probe.summary.failed_transfers,
        pending_rebalance_queue_probe.summary.max_attempts,
        pending_rebalance_backlog_oldest_created_at_unix_ms,
        pending_membership_propagation_queue_readable,
        pending_membership_propagation_queue_probe
            .summary
            .operations,
        pending_membership_propagation_queue_probe.due_operations,
        pending_membership_propagation_backlog_due_operations_capped,
        pending_membership_propagation_queue_probe
            .summary
            .failed_operations,
        pending_membership_propagation_queue_probe
            .summary
            .max_attempts,
        pending_membership_propagation_backlog_oldest_created_at_unix_ms
    );
    body.push_str(
        format!(
            "# HELP maxio_pending_replication_replay_cycles_total Total replay-worker cycles executed.\n\
             # TYPE maxio_pending_replication_replay_cycles_total counter\n\
             maxio_pending_replication_replay_cycles_total {}\n\
             # HELP maxio_pending_replication_replay_cycles_succeeded_total Total replay-worker cycles completed without top-level error.\n\
             # TYPE maxio_pending_replication_replay_cycles_succeeded_total counter\n\
             maxio_pending_replication_replay_cycles_succeeded_total {}\n\
             # HELP maxio_pending_replication_replay_cycles_failed_total Total replay-worker cycles that failed at top-level execution.\n\
             # TYPE maxio_pending_replication_replay_cycles_failed_total counter\n\
             maxio_pending_replication_replay_cycles_failed_total {}\n\
             # HELP maxio_pending_replication_replay_scanned_total Total pending-replication targets scanned by replay worker.\n\
             # TYPE maxio_pending_replication_replay_scanned_total counter\n\
             maxio_pending_replication_replay_scanned_total {}\n\
             # HELP maxio_pending_replication_replay_leased_total Total pending-replication targets leased by replay worker.\n\
             # TYPE maxio_pending_replication_replay_leased_total counter\n\
             maxio_pending_replication_replay_leased_total {}\n\
             # HELP maxio_pending_replication_replay_acknowledged_total Total pending-replication targets acknowledged by replay worker.\n\
             # TYPE maxio_pending_replication_replay_acknowledged_total counter\n\
             maxio_pending_replication_replay_acknowledged_total {}\n\
             # HELP maxio_pending_replication_replay_failed_total Total pending-replication targets that failed replay attempts.\n\
             # TYPE maxio_pending_replication_replay_failed_total counter\n\
             maxio_pending_replication_replay_failed_total {}\n\
             # HELP maxio_pending_replication_replay_skipped_total Total pending-replication targets skipped by replay worker.\n\
             # TYPE maxio_pending_replication_replay_skipped_total counter\n\
             maxio_pending_replication_replay_skipped_total {}\n\
             # HELP maxio_pending_replication_replay_last_cycle_unix_ms Unix milliseconds of the last replay-worker cycle (0 when no cycle has run).\n\
             # TYPE maxio_pending_replication_replay_last_cycle_unix_ms gauge\n\
             maxio_pending_replication_replay_last_cycle_unix_ms {}\n\
             # HELP maxio_pending_replication_replay_last_success_unix_ms Unix milliseconds of the last successful replay-worker cycle (0 when never successful).\n\
             # TYPE maxio_pending_replication_replay_last_success_unix_ms gauge\n\
             maxio_pending_replication_replay_last_success_unix_ms {}\n\
             # HELP maxio_pending_replication_replay_last_failure_unix_ms Unix milliseconds of the last failed replay-worker cycle (0 when never failed).\n\
             # TYPE maxio_pending_replication_replay_last_failure_unix_ms gauge\n\
             maxio_pending_replication_replay_last_failure_unix_ms {}\n\
             ",
            pending_replication_replay_counters.cycles_total,
            pending_replication_replay_counters.cycles_succeeded,
            pending_replication_replay_counters.cycles_failed,
            pending_replication_replay_counters.scanned_total,
            pending_replication_replay_counters.leased_total,
            pending_replication_replay_counters.acknowledged_total,
            pending_replication_replay_counters.failed_total,
            pending_replication_replay_counters.skipped_total,
            pending_replication_replay_counters.last_cycle_unix_ms,
            pending_replication_replay_counters.last_success_unix_ms,
            pending_replication_replay_counters.last_failure_unix_ms,
        )
        .as_str(),
    );

    body.push_str(
        format!(
            "# HELP maxio_pending_rebalance_replay_cycles_total Total rebalance replay-worker cycles executed.\n\
             # TYPE maxio_pending_rebalance_replay_cycles_total counter\n\
             maxio_pending_rebalance_replay_cycles_total {}\n\
             # HELP maxio_pending_rebalance_replay_cycles_succeeded_total Total rebalance replay-worker cycles completed without top-level error.\n\
             # TYPE maxio_pending_rebalance_replay_cycles_succeeded_total counter\n\
             maxio_pending_rebalance_replay_cycles_succeeded_total {}\n\
             # HELP maxio_pending_rebalance_replay_cycles_failed_total Total rebalance replay-worker cycles that failed at top-level execution.\n\
             # TYPE maxio_pending_rebalance_replay_cycles_failed_total counter\n\
             maxio_pending_rebalance_replay_cycles_failed_total {}\n\
             # HELP maxio_pending_rebalance_replay_scanned_transfers_total Total pending rebalance transfers scanned by replay worker.\n\
             # TYPE maxio_pending_rebalance_replay_scanned_transfers_total counter\n\
             maxio_pending_rebalance_replay_scanned_transfers_total {}\n\
             # HELP maxio_pending_rebalance_replay_leased_transfers_total Total pending rebalance transfers leased by replay worker.\n\
             # TYPE maxio_pending_rebalance_replay_leased_transfers_total counter\n\
             maxio_pending_rebalance_replay_leased_transfers_total {}\n\
             # HELP maxio_pending_rebalance_replay_acknowledged_transfers_total Total pending rebalance transfers acknowledged by replay worker.\n\
             # TYPE maxio_pending_rebalance_replay_acknowledged_transfers_total counter\n\
             maxio_pending_rebalance_replay_acknowledged_transfers_total {}\n\
             # HELP maxio_pending_rebalance_replay_failed_transfers_total Total pending rebalance transfers that failed replay attempts.\n\
             # TYPE maxio_pending_rebalance_replay_failed_transfers_total counter\n\
             maxio_pending_rebalance_replay_failed_transfers_total {}\n\
             # HELP maxio_pending_rebalance_replay_skipped_transfers_total Total pending rebalance transfers skipped by replay worker.\n\
             # TYPE maxio_pending_rebalance_replay_skipped_transfers_total counter\n\
             maxio_pending_rebalance_replay_skipped_transfers_total {}\n\
             # HELP maxio_pending_rebalance_replay_last_cycle_unix_ms Unix milliseconds of the last rebalance replay-worker cycle (0 when no cycle has run).\n\
             # TYPE maxio_pending_rebalance_replay_last_cycle_unix_ms gauge\n\
             maxio_pending_rebalance_replay_last_cycle_unix_ms {}\n\
             # HELP maxio_pending_rebalance_replay_last_success_unix_ms Unix milliseconds of the last successful rebalance replay-worker cycle (0 when never successful).\n\
             # TYPE maxio_pending_rebalance_replay_last_success_unix_ms gauge\n\
             maxio_pending_rebalance_replay_last_success_unix_ms {}\n\
             # HELP maxio_pending_rebalance_replay_last_failure_unix_ms Unix milliseconds of the last failed rebalance replay-worker cycle (0 when never failed).\n\
             # TYPE maxio_pending_rebalance_replay_last_failure_unix_ms gauge\n\
             maxio_pending_rebalance_replay_last_failure_unix_ms {}\n",
            pending_rebalance_replay_counters.cycles_total,
            pending_rebalance_replay_counters.cycles_succeeded,
            pending_rebalance_replay_counters.cycles_failed,
            pending_rebalance_replay_counters.scanned_total,
            pending_rebalance_replay_counters.leased_total,
            pending_rebalance_replay_counters.acknowledged_total,
            pending_rebalance_replay_counters.failed_total,
            pending_rebalance_replay_counters.skipped_total,
            pending_rebalance_replay_counters.last_cycle_unix_ms,
            pending_rebalance_replay_counters.last_success_unix_ms,
            pending_rebalance_replay_counters.last_failure_unix_ms
        )
        .as_str(),
    );

    body.push_str(
        format!(
            "# HELP maxio_pending_membership_propagation_replay_cycles_total Total membership propagation replay-worker cycles executed.\n\
             # TYPE maxio_pending_membership_propagation_replay_cycles_total counter\n\
             maxio_pending_membership_propagation_replay_cycles_total {}\n\
             # HELP maxio_pending_membership_propagation_replay_cycles_succeeded_total Total membership propagation replay-worker cycles completed without top-level error.\n\
             # TYPE maxio_pending_membership_propagation_replay_cycles_succeeded_total counter\n\
             maxio_pending_membership_propagation_replay_cycles_succeeded_total {}\n\
             # HELP maxio_pending_membership_propagation_replay_cycles_failed_total Total membership propagation replay-worker cycles that failed at top-level execution.\n\
             # TYPE maxio_pending_membership_propagation_replay_cycles_failed_total counter\n\
             maxio_pending_membership_propagation_replay_cycles_failed_total {}\n\
             # HELP maxio_pending_membership_propagation_replay_scanned_operations_total Total pending membership propagation operations scanned by replay worker.\n\
             # TYPE maxio_pending_membership_propagation_replay_scanned_operations_total counter\n\
             maxio_pending_membership_propagation_replay_scanned_operations_total {}\n\
             # HELP maxio_pending_membership_propagation_replay_replayed_operations_total Total pending membership propagation operations replay-attempted by replay worker.\n\
             # TYPE maxio_pending_membership_propagation_replay_replayed_operations_total counter\n\
             maxio_pending_membership_propagation_replay_replayed_operations_total {}\n\
             # HELP maxio_pending_membership_propagation_replay_deferred_operations_total Total due pending membership propagation operations deferred by replay budget caps.\n\
             # TYPE maxio_pending_membership_propagation_replay_deferred_operations_total counter\n\
             maxio_pending_membership_propagation_replay_deferred_operations_total {}\n\
             # HELP maxio_pending_membership_propagation_replay_acknowledged_operations_total Total pending membership propagation operations acknowledged by replay worker.\n\
             # TYPE maxio_pending_membership_propagation_replay_acknowledged_operations_total counter\n\
             maxio_pending_membership_propagation_replay_acknowledged_operations_total {}\n\
             # HELP maxio_pending_membership_propagation_replay_failed_operations_total Total pending membership propagation operations that failed replay attempts.\n\
             # TYPE maxio_pending_membership_propagation_replay_failed_operations_total counter\n\
             maxio_pending_membership_propagation_replay_failed_operations_total {}\n\
             # HELP maxio_pending_membership_propagation_replay_last_cycle_unix_ms Unix milliseconds of the last membership propagation replay-worker cycle (0 when no cycle has run).\n\
             # TYPE maxio_pending_membership_propagation_replay_last_cycle_unix_ms gauge\n\
             maxio_pending_membership_propagation_replay_last_cycle_unix_ms {}\n\
             # HELP maxio_pending_membership_propagation_replay_last_success_unix_ms Unix milliseconds of the last successful membership propagation replay-worker cycle (0 when never successful).\n\
             # TYPE maxio_pending_membership_propagation_replay_last_success_unix_ms gauge\n\
             maxio_pending_membership_propagation_replay_last_success_unix_ms {}\n\
             # HELP maxio_pending_membership_propagation_replay_last_failure_unix_ms Unix milliseconds of the last failed membership propagation replay-worker cycle (0 when never failed).\n\
             # TYPE maxio_pending_membership_propagation_replay_last_failure_unix_ms gauge\n\
             maxio_pending_membership_propagation_replay_last_failure_unix_ms {}\n",
            pending_membership_propagation_replay_counters.cycles_total,
            pending_membership_propagation_replay_counters.cycles_succeeded,
            pending_membership_propagation_replay_counters.cycles_failed,
            pending_membership_propagation_replay_counters.scanned_operations_total,
            pending_membership_propagation_replay_counters.replayed_operations_total,
            pending_membership_propagation_replay_counters.deferred_operations_total,
            pending_membership_propagation_replay_counters.acknowledged_operations_total,
            pending_membership_propagation_replay_counters.failed_operations_total,
            pending_membership_propagation_replay_counters.last_cycle_unix_ms,
            pending_membership_propagation_replay_counters.last_success_unix_ms,
            pending_membership_propagation_replay_counters.last_failure_unix_ms,
        )
        .as_str(),
    );

    body.push_str(
        format!(
            "# HELP maxio_pending_metadata_repair_queue_readable Whether pending metadata repair queue diagnostics are readable from runtime state (1=true, 0=false).\n\
             # TYPE maxio_pending_metadata_repair_queue_readable gauge\n\
             maxio_pending_metadata_repair_queue_readable {}\n\
             # HELP maxio_pending_metadata_repair_backlog_plans Pending metadata repair backlog plan count.\n\
             # TYPE maxio_pending_metadata_repair_backlog_plans gauge\n\
             maxio_pending_metadata_repair_backlog_plans {}\n\
             # HELP maxio_pending_metadata_repair_backlog_due_plans Pending metadata repair plans currently due for replay execution.\n\
             # TYPE maxio_pending_metadata_repair_backlog_due_plans gauge\n\
             maxio_pending_metadata_repair_backlog_due_plans {}\n\
             # HELP maxio_pending_metadata_repair_backlog_due_plans_capped Whether due metadata plan count reached probe cap (1=true, 0=false).\n\
             # TYPE maxio_pending_metadata_repair_backlog_due_plans_capped gauge\n\
             maxio_pending_metadata_repair_backlog_due_plans_capped {}\n\
             # HELP maxio_pending_metadata_repair_backlog_failed_plans Pending metadata repair plans with last_error set.\n\
             # TYPE maxio_pending_metadata_repair_backlog_failed_plans gauge\n\
             maxio_pending_metadata_repair_backlog_failed_plans {}\n\
             # HELP maxio_pending_metadata_repair_backlog_max_attempts Maximum retry attempts recorded across pending metadata repair plans.\n\
             # TYPE maxio_pending_metadata_repair_backlog_max_attempts gauge\n\
             maxio_pending_metadata_repair_backlog_max_attempts {}\n\
             # HELP maxio_pending_metadata_repair_backlog_oldest_created_at_unix_ms Oldest pending metadata repair plan creation timestamp in Unix milliseconds (0 when queue is empty).\n\
             # TYPE maxio_pending_metadata_repair_backlog_oldest_created_at_unix_ms gauge\n\
             maxio_pending_metadata_repair_backlog_oldest_created_at_unix_ms {}\n\
             # HELP maxio_pending_metadata_repair_replay_cycles_total Total metadata repair replay-worker cycles executed.\n\
             # TYPE maxio_pending_metadata_repair_replay_cycles_total counter\n\
             maxio_pending_metadata_repair_replay_cycles_total {}\n\
             # HELP maxio_pending_metadata_repair_replay_cycles_succeeded_total Total metadata repair replay-worker cycles completed without top-level error.\n\
             # TYPE maxio_pending_metadata_repair_replay_cycles_succeeded_total counter\n\
             maxio_pending_metadata_repair_replay_cycles_succeeded_total {}\n\
             # HELP maxio_pending_metadata_repair_replay_cycles_failed_total Total metadata repair replay-worker cycles that failed at top-level execution.\n\
             # TYPE maxio_pending_metadata_repair_replay_cycles_failed_total counter\n\
             maxio_pending_metadata_repair_replay_cycles_failed_total {}\n\
             # HELP maxio_pending_metadata_repair_replay_scanned_plans_total Total pending metadata repair plans scanned by replay worker.\n\
             # TYPE maxio_pending_metadata_repair_replay_scanned_plans_total counter\n\
             maxio_pending_metadata_repair_replay_scanned_plans_total {}\n\
             # HELP maxio_pending_metadata_repair_replay_leased_plans_total Total pending metadata repair plans leased by replay worker.\n\
             # TYPE maxio_pending_metadata_repair_replay_leased_plans_total counter\n\
             maxio_pending_metadata_repair_replay_leased_plans_total {}\n\
             # HELP maxio_pending_metadata_repair_replay_acknowledged_plans_total Total pending metadata repair plans acknowledged by replay worker.\n\
             # TYPE maxio_pending_metadata_repair_replay_acknowledged_plans_total counter\n\
             maxio_pending_metadata_repair_replay_acknowledged_plans_total {}\n\
             # HELP maxio_pending_metadata_repair_replay_failed_plans_total Total pending metadata repair plans that failed replay attempts.\n\
             # TYPE maxio_pending_metadata_repair_replay_failed_plans_total counter\n\
             maxio_pending_metadata_repair_replay_failed_plans_total {}\n\
             # HELP maxio_pending_metadata_repair_replay_skipped_plans_total Total pending metadata repair plans skipped by replay worker.\n\
             # TYPE maxio_pending_metadata_repair_replay_skipped_plans_total counter\n\
             maxio_pending_metadata_repair_replay_skipped_plans_total {}\n\
             # HELP maxio_pending_metadata_repair_replay_last_cycle_unix_ms Unix milliseconds of the last metadata repair replay-worker cycle (0 when no cycle has run).\n\
             # TYPE maxio_pending_metadata_repair_replay_last_cycle_unix_ms gauge\n\
             maxio_pending_metadata_repair_replay_last_cycle_unix_ms {}\n\
             # HELP maxio_pending_metadata_repair_replay_last_success_unix_ms Unix milliseconds of the last successful metadata repair replay-worker cycle (0 when never successful).\n\
             # TYPE maxio_pending_metadata_repair_replay_last_success_unix_ms gauge\n\
             maxio_pending_metadata_repair_replay_last_success_unix_ms {}\n\
             # HELP maxio_pending_metadata_repair_replay_last_failure_unix_ms Unix milliseconds of the last failed metadata repair replay-worker cycle (0 when never failed).\n\
             # TYPE maxio_pending_metadata_repair_replay_last_failure_unix_ms gauge\n\
             maxio_pending_metadata_repair_replay_last_failure_unix_ms {}\n",
            pending_metadata_repair_queue_readable,
            pending_metadata_repair_queue_probe.summary.plans,
            pending_metadata_repair_queue_probe.due_plans,
            pending_metadata_repair_backlog_due_plans_capped,
            pending_metadata_repair_queue_probe.summary.failed_plans,
            pending_metadata_repair_queue_probe.summary.max_attempts,
            pending_metadata_repair_backlog_oldest_created_at_unix_ms,
            pending_metadata_repair_replay_counters.cycles_total,
            pending_metadata_repair_replay_counters.cycles_succeeded,
            pending_metadata_repair_replay_counters.cycles_failed,
            pending_metadata_repair_replay_counters.scanned_plans_total,
            pending_metadata_repair_replay_counters.leased_plans_total,
            pending_metadata_repair_replay_counters.acknowledged_plans_total,
            pending_metadata_repair_replay_counters.failed_plans_total,
            pending_metadata_repair_replay_counters.skipped_plans_total,
            pending_metadata_repair_replay_counters.last_cycle_unix_ms,
            pending_metadata_repair_replay_counters.last_success_unix_ms,
            pending_metadata_repair_replay_counters.last_failure_unix_ms
        )
        .as_str(),
    );

    body.push_str(
        format!(
            "# HELP maxio_metadata_listing_expected_nodes Expected node fan-in cardinality for current metadata strategy/runtime view.\n\
             # TYPE maxio_metadata_listing_expected_nodes gauge\n\
             maxio_metadata_listing_expected_nodes {}\n\
             # HELP maxio_metadata_listing_responded_nodes Responded node fan-in cardinality observed in current runtime metadata snapshot.\n\
             # TYPE maxio_metadata_listing_responded_nodes gauge\n\
             maxio_metadata_listing_responded_nodes {}\n\
             # HELP maxio_metadata_listing_missing_nodes Missing expected node fan-in cardinality in current runtime metadata snapshot.\n\
             # TYPE maxio_metadata_listing_missing_nodes gauge\n\
             maxio_metadata_listing_missing_nodes {}\n\
             # HELP maxio_metadata_listing_unexpected_nodes Unexpected responder node fan-in cardinality in current runtime metadata snapshot.\n\
             # TYPE maxio_metadata_listing_unexpected_nodes gauge\n\
             maxio_metadata_listing_unexpected_nodes {}\n",
            metadata_listing_expected_nodes,
            metadata_listing_responded_nodes,
            metadata_listing_missing_nodes,
            metadata_listing_unexpected_nodes
        )
        .as_str(),
    );

    body.push_str(
        format!(
            "# HELP maxio_metadata_state_readable Whether persisted metadata state snapshot can be read from runtime state (1=true, 0=false).\n\
             # TYPE maxio_metadata_state_readable gauge\n\
             maxio_metadata_state_readable {}\n\
             # HELP maxio_metadata_state_queryable Whether persisted metadata state satisfies queryability invariants (1=true, 0=false).\n\
             # TYPE maxio_metadata_state_queryable gauge\n\
             maxio_metadata_state_queryable {}\n\
             # HELP maxio_metadata_state_bucket_rows Persisted metadata state bucket row count.\n\
             # TYPE maxio_metadata_state_bucket_rows gauge\n\
             maxio_metadata_state_bucket_rows {}\n\
             # HELP maxio_metadata_state_object_rows Persisted metadata state object-head row count.\n\
             # TYPE maxio_metadata_state_object_rows gauge\n\
             maxio_metadata_state_object_rows {}\n\
             # HELP maxio_metadata_state_object_version_rows Persisted metadata state object-version row count.\n\
             # TYPE maxio_metadata_state_object_version_rows gauge\n\
             maxio_metadata_state_object_version_rows {}\n",
            metadata_state_readable,
            metadata_state_queryable,
            persisted_metadata_state_probe.bucket_rows,
            persisted_metadata_state_probe.object_rows,
            persisted_metadata_state_probe.object_version_rows
        )
        .as_str(),
    );

    body.push_str(
        format!(
            "# HELP maxio_cluster_join_authorize_requests_total Total join authorization requests handled by runtime endpoint.\n\
             # TYPE maxio_cluster_join_authorize_requests_total counter\n\
             maxio_cluster_join_authorize_requests_total {}\n\
             # HELP maxio_cluster_join_authorize_status_total Join authorization request counts by status.\n\
             # TYPE maxio_cluster_join_authorize_status_total counter\n\
             maxio_cluster_join_authorize_status_total{{status=\"authorized\"}} {}\n\
             maxio_cluster_join_authorize_status_total{{status=\"rejected\"}} {}\n\
             maxio_cluster_join_authorize_status_total{{status=\"misconfigured\"}} {}\n\
             # HELP maxio_cluster_join_authorize_reason_total Join authorization request counts by reject/accept reason.\n\
             # TYPE maxio_cluster_join_authorize_reason_total counter\n\
             maxio_cluster_join_authorize_reason_total{{reason=\"authorized\"}} {}\n\
             maxio_cluster_join_authorize_reason_total{{reason=\"invalid_configuration\"}} {}\n\
             maxio_cluster_join_authorize_reason_total{{reason=\"missing_or_malformed_cluster_id\"}} {}\n\
             maxio_cluster_join_authorize_reason_total{{reason=\"cluster_id_mismatch\"}} {}\n\
             maxio_cluster_join_authorize_reason_total{{reason=\"missing_or_malformed_node_id\"}} {}\n\
             maxio_cluster_join_authorize_reason_total{{reason=\"invalid_node_identity\"}} {}\n\
             maxio_cluster_join_authorize_reason_total{{reason=\"node_matches_local_node\"}} {}\n\
             maxio_cluster_join_authorize_reason_total{{reason=\"missing_or_malformed_join_timestamp\"}} {}\n\
             maxio_cluster_join_authorize_reason_total{{reason=\"join_timestamp_skew_exceeded\"}} {}\n\
             maxio_cluster_join_authorize_reason_total{{reason=\"missing_or_malformed_join_nonce\"}} {}\n\
             maxio_cluster_join_authorize_reason_total{{reason=\"invalid_join_nonce\"}} {}\n\
             maxio_cluster_join_authorize_reason_total{{reason=\"join_nonce_replay_detected\"}} {}\n\
             maxio_cluster_join_authorize_reason_total{{reason=\"missing_or_malformed_auth_token\"}} {}\n\
             maxio_cluster_join_authorize_reason_total{{reason=\"auth_token_mismatch\"}} {}\n\
             maxio_cluster_join_authorize_reason_total{{reason=\"distributed_mode_disabled\"}} {}\n\
             maxio_cluster_join_authorize_reason_total{{reason=\"membership_engine_not_ready\"}} {}\n\
             maxio_cluster_join_authorize_reason_total{{reason=\"cluster_auth_token_not_configured\"}} {}\n\
             maxio_cluster_join_authorize_reason_total{{reason=\"unknown\"}} {}\n",
            join_authorize_counters.total,
            join_authorize_counters.status_authorized,
            join_authorize_counters.status_rejected,
            join_authorize_counters.status_misconfigured,
            join_authorize_counters.reason_authorized,
            join_authorize_counters.reason_invalid_configuration,
            join_authorize_counters.reason_missing_or_malformed_cluster_id,
            join_authorize_counters.reason_cluster_id_mismatch,
            join_authorize_counters.reason_missing_or_malformed_node_id,
            join_authorize_counters.reason_invalid_node_identity,
            join_authorize_counters.reason_node_matches_local_node,
            join_authorize_counters.reason_missing_or_malformed_join_timestamp,
            join_authorize_counters.reason_join_timestamp_skew_exceeded,
            join_authorize_counters.reason_missing_or_malformed_join_nonce,
            join_authorize_counters.reason_invalid_join_nonce,
            join_authorize_counters.reason_join_nonce_replay_detected,
            join_authorize_counters.reason_missing_or_malformed_auth_token,
            join_authorize_counters.reason_auth_token_mismatch,
            join_authorize_counters.reason_distributed_mode_disabled,
            join_authorize_counters.reason_membership_engine_not_ready,
            join_authorize_counters.reason_cluster_auth_token_not_configured,
            join_authorize_counters.reason_unknown,
        )
        .as_str(),
    );

    body.push_str(
        format!(
            "# HELP maxio_cluster_join_requests_total Total authenticated join-apply requests handled by runtime endpoint.\n\
             # TYPE maxio_cluster_join_requests_total counter\n\
             maxio_cluster_join_requests_total {}\n\
             # HELP maxio_cluster_join_status_total Join-apply request counts by status.\n\
             # TYPE maxio_cluster_join_status_total counter\n\
             maxio_cluster_join_status_total{{status=\"applied\"}} {}\n\
             maxio_cluster_join_status_total{{status=\"rejected\"}} {}\n\
             maxio_cluster_join_status_total{{status=\"misconfigured\"}} {}\n\
             # HELP maxio_cluster_join_reason_total Join-apply request counts by reason.\n\
             # TYPE maxio_cluster_join_reason_total counter\n\
             maxio_cluster_join_reason_total{{reason=\"applied\"}} {}\n\
             maxio_cluster_join_reason_total{{reason=\"invalid_payload\"}} {}\n\
             maxio_cluster_join_reason_total{{reason=\"precondition_failed\"}} {}\n\
             maxio_cluster_join_reason_total{{reason=\"unauthorized\"}} {}\n\
             maxio_cluster_join_reason_total{{reason=\"distributed_mode_disabled\"}} {}\n\
             maxio_cluster_join_reason_total{{reason=\"membership_engine_not_ready\"}} {}\n\
             maxio_cluster_join_reason_total{{reason=\"cluster_auth_token_not_configured\"}} {}\n\
             maxio_cluster_join_reason_total{{reason=\"state_persist_failed\"}} {}\n\
             maxio_cluster_join_reason_total{{reason=\"unknown\"}} {}\n",
            join_counters.total,
            join_counters.status_applied,
            join_counters.status_rejected,
            join_counters.status_misconfigured,
            join_counters.reason_applied,
            join_counters.reason_invalid_payload,
            join_counters.reason_precondition_failed,
            join_counters.reason_unauthorized,
            join_counters.reason_distributed_mode_disabled,
            join_counters.reason_membership_engine_not_ready,
            join_counters.reason_cluster_auth_token_not_configured,
            join_counters.reason_state_persist_failed,
            join_counters.reason_unknown,
        )
        .as_str(),
    );

    body.push_str(
        format!(
            "# HELP maxio_cluster_membership_update_requests_total Total membership-update requests handled by runtime endpoint.\n\
             # TYPE maxio_cluster_membership_update_requests_total counter\n\
             maxio_cluster_membership_update_requests_total {}\n\
             # HELP maxio_cluster_membership_update_status_total Membership-update request counts by status.\n\
             # TYPE maxio_cluster_membership_update_status_total counter\n\
             maxio_cluster_membership_update_status_total{{status=\"applied\"}} {}\n\
             maxio_cluster_membership_update_status_total{{status=\"rejected\"}} {}\n\
             maxio_cluster_membership_update_status_total{{status=\"misconfigured\"}} {}\n\
             # HELP maxio_cluster_membership_update_reason_total Membership-update request counts by reason.\n\
             # TYPE maxio_cluster_membership_update_reason_total counter\n\
             maxio_cluster_membership_update_reason_total{{reason=\"applied\"}} {}\n\
             maxio_cluster_membership_update_reason_total{{reason=\"invalid_payload\"}} {}\n\
             maxio_cluster_membership_update_reason_total{{reason=\"cluster_id_mismatch\"}} {}\n\
             maxio_cluster_membership_update_reason_total{{reason=\"precondition_failed\"}} {}\n\
             maxio_cluster_membership_update_reason_total{{reason=\"unauthorized\"}} {}\n\
             maxio_cluster_membership_update_reason_total{{reason=\"distributed_mode_disabled\"}} {}\n\
             maxio_cluster_membership_update_reason_total{{reason=\"membership_engine_not_ready\"}} {}\n\
             maxio_cluster_membership_update_reason_total{{reason=\"cluster_auth_token_not_configured\"}} {}\n\
             maxio_cluster_membership_update_reason_total{{reason=\"state_persist_failed\"}} {}\n\
             maxio_cluster_membership_update_reason_total{{reason=\"unknown\"}} {}\n",
            membership_update_counters.total,
            membership_update_counters.status_applied,
            membership_update_counters.status_rejected,
            membership_update_counters.status_misconfigured,
            membership_update_counters.reason_applied,
            membership_update_counters.reason_invalid_payload,
            membership_update_counters.reason_cluster_id_mismatch,
            membership_update_counters.reason_precondition_failed,
            membership_update_counters.reason_unauthorized,
            membership_update_counters.reason_distributed_mode_disabled,
            membership_update_counters.reason_membership_engine_not_ready,
            membership_update_counters.reason_cluster_auth_token_not_configured,
            membership_update_counters.reason_state_persist_failed,
            membership_update_counters.reason_unknown,
        )
        .as_str(),
    );

    response_with_content_type(
        StatusCode::OK,
        HeaderValue::from_static("text/plain; version=0.0.4"),
        axum::body::Body::from(body),
    )
}

pub(super) async fn health_handler(State(state): State<AppState>) -> Response {
    let body = runtime_health_payload(&state).await;

    response_with_content_type(
        StatusCode::OK,
        HeaderValue::from_static("application/json"),
        json_body_or_fallback(
            &body,
            b"{\"ok\":false,\"status\":\"degraded\"}",
            "health_handler",
        ),
    )
}
