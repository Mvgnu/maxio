use std::collections::HashMap;
use std::sync::atomic::Ordering;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Serialize;

use crate::api::console::response;
use crate::server::{
    AppState, HealthPayload as RuntimeHealthPayload, RuntimeTopologySnapshot,
    runtime_health_payload, runtime_topology_snapshot,
};
use crate::storage::StorageError;
use crate::storage::placement::{
    chunk_forward_target_with_self, chunk_rebalance_plan, local_rebalance_actions,
    membership_fingerprint, membership_with_self, object_forward_target_with_self,
    object_rebalance_plan, primary_chunk_owner_with_self, primary_object_owner_with_self,
    quorum_size, select_chunk_owners_with_self, select_object_owners_with_self,
};
use crate::storage::validation::validate_key;

const WRITE_ACK_POLICY_MAJORITY: &str = "majority";
const NON_OWNER_MUTATION_POLICY_FORWARD_SINGLE_WRITE: &str = "forward-single-write";
const NON_OWNER_READ_POLICY_FORWARD_SINGLE_READ: &str = "forward-single-read";
const NON_OWNER_BATCH_MUTATION_POLICY_FORWARD_MULTI_TARGET_BATCH: &str =
    "forward-multi-target-batch";
const MIXED_OWNER_BATCH_MUTATION_POLICY_FORWARD_MIXED_OWNER_BATCH: &str =
    "forward-mixed-owner-batch";
const BATCH_MUTATION_POLICY_EXECUTE_LOCAL: &str = "execute-local";
const REPLICA_FANOUT_OPERATION_PUT_OBJECT: &str = "put-object";
const REPLICA_FANOUT_OPERATION_COPY_OBJECT: &str = "copy-object";
const REPLICA_FANOUT_OPERATION_DELETE_OBJECT: &str = "delete-object";
const REPLICA_FANOUT_OPERATION_DELETE_OBJECT_VERSION: &str = "delete-object-version";
const REPLICA_FANOUT_OPERATION_COMPLETE_MULTIPART_UPLOAD: &str = "complete-multipart-upload";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TopologyPayload {
    mode: String,
    node_id: String,
    cluster_peer_count: usize,
    cluster_peers: Vec<String>,
    membership_protocol: String,
    membership_engine: String,
    placement_epoch: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MembershipNodePayload {
    node_id: String,
    role: String,
    status: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MembershipPayload {
    mode: String,
    protocol: String,
    view_id: String,
    leader_node_id: Option<String>,
    coordinator_node_id: String,
    nodes: Vec<MembershipNodePayload>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MetricsPayload {
    requests_total: u64,
    uptime_seconds: f64,
    version: String,
    membership_protocol_ready: bool,
    membership_converged: bool,
    membership_convergence_reason: String,
    membership_last_update_age_ms: u64,
    cluster_peer_auth_production_ready: bool,
    cluster_auth_production_reason: String,
    write_durability_mode: String,
    metadata_listing_strategy: String,
    metadata_listing_ready: bool,
    pending_replication_backlog_operations: usize,
    pending_replication_backlog_due_targets: usize,
    pending_replication_replay_cycles_total: u64,
    pending_rebalance_backlog_operations: usize,
    pending_rebalance_replay_cycles_total: u64,
    pending_membership_propagation_backlog_operations: usize,
    pending_membership_propagation_replay_cycles_total: u64,
    pending_metadata_repair_backlog_plans: usize,
    pending_metadata_repair_replay_cycles_total: u64,
    pending_due_warning_threshold_overrides: PendingDueWarningThresholdOverridesPayload,
    #[serde(flatten)]
    topology: TopologyPayload,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PlacementPayload {
    key: String,
    chunk_index: Option<u32>,
    replica_count_requested: usize,
    replica_count_applied: usize,
    owners: Vec<String>,
    primary_owner: Option<String>,
    forward_target: Option<String>,
    is_local_primary_owner: bool,
    is_local_replica_owner: bool,
    write_quorum_size: usize,
    write_ack_policy: String,
    non_owner_mutation_policy: String,
    non_owner_read_policy: String,
    non_owner_batch_mutation_policy: String,
    mixed_owner_batch_mutation_policy: String,
    replica_fanout_operations: Vec<String>,
    pending_replica_fanout_operations: Vec<String>,
    replica_fanout_execution: ReplicaFanoutExecutionPayload,
    #[serde(flatten)]
    topology: TopologyPayload,
    membership_view_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplicaFanoutExecutionPayload {
    write_durability_mode: String,
    pending_replication_queue_readable: bool,
    pending_replication_backlog_operations: usize,
    pending_replication_backlog_pending_targets: usize,
    pending_replication_backlog_due_targets: usize,
    pending_replication_backlog_failed_targets: usize,
    pending_replication_replay_cycles_total: u64,
    pending_replication_replay_cycles_succeeded: u64,
    pending_replication_replay_cycles_failed: u64,
    pending_replication_replay_last_success_unix_ms: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RebalanceMembershipPayload {
    node_id: String,
    cluster_peer_count: usize,
    cluster_peers: Vec<String>,
    membership_view_id: String,
    membership_nodes: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RebalanceTransferPayload {
    from: Option<String>,
    to: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RebalanceLocalActionPayload {
    action: String,
    from: Option<String>,
    to: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RebalancePlanPayload {
    previous_owners: Vec<String>,
    next_owners: Vec<String>,
    retained_owners: Vec<String>,
    removed_owners: Vec<String>,
    added_owners: Vec<String>,
    transfer_count: usize,
    local_actions: Vec<RebalanceLocalActionPayload>,
    transfers: Vec<RebalanceTransferPayload>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RebalancePayload {
    key: String,
    chunk_index: Option<u32>,
    replica_count_requested: usize,
    replica_count_applied: usize,
    operation: String,
    operation_peer: String,
    source: RebalanceMembershipPayload,
    target: RebalanceMembershipPayload,
    plan: RebalancePlanPayload,
    #[serde(flatten)]
    topology: TopologyPayload,
    membership_view_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SummaryMetricsPayload {
    requests_total: u64,
    uptime_seconds: f64,
    version: String,
    membership_protocol_ready: bool,
    membership_converged: bool,
    membership_convergence_reason: String,
    membership_last_update_age_ms: u64,
    cluster_peer_auth_production_ready: bool,
    cluster_auth_production_reason: String,
    write_durability_mode: String,
    metadata_listing_strategy: String,
    metadata_listing_ready: bool,
    pending_replication_backlog_operations: usize,
    pending_replication_backlog_due_targets: usize,
    pending_replication_replay_cycles_total: u64,
    pending_rebalance_backlog_operations: usize,
    pending_rebalance_replay_cycles_total: u64,
    pending_membership_propagation_backlog_operations: usize,
    pending_membership_propagation_replay_cycles_total: u64,
    pending_metadata_repair_backlog_plans: usize,
    pending_metadata_repair_replay_cycles_total: u64,
    pending_due_warning_threshold_overrides: PendingDueWarningThresholdOverridesPayload,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PendingDueWarningThresholdOverridesPayload {
    replication_due_targets: Option<usize>,
    rebalance_due_transfers: Option<usize>,
    membership_propagation_due_operations: Option<usize>,
    metadata_repair_due_plans: Option<usize>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SummaryPayload {
    health: RuntimeHealthPayload,
    metrics: SummaryMetricsPayload,
    topology: TopologyPayload,
    membership: MembershipPayload,
}

fn topology_payload(topology: &RuntimeTopologySnapshot) -> TopologyPayload {
    TopologyPayload {
        mode: topology.mode.as_str().to_string(),
        node_id: topology.node_id.clone(),
        cluster_peer_count: topology.cluster_peer_count(),
        cluster_peers: topology.cluster_peers.clone(),
        membership_protocol: topology.membership_protocol.as_str().to_string(),
        membership_engine: topology.membership_status.engine.clone(),
        placement_epoch: topology.placement_epoch,
    }
}

fn membership_payload(topology: &RuntimeTopologySnapshot) -> MembershipPayload {
    let self_node_id = topology.node_id.clone();
    let membership_nodes =
        membership_with_self(self_node_id.as_str(), topology.cluster_peers.as_slice());

    let nodes = membership_nodes
        .iter()
        .map(|node_id| {
            let role = if node_id == &self_node_id {
                "self"
            } else {
                "peer"
            };
            let status = if node_id == &self_node_id {
                "alive"
            } else {
                "configured"
            };
            MembershipNodePayload {
                node_id: node_id.clone(),
                role: role.to_string(),
                status: status.to_string(),
            }
        })
        .collect::<Vec<_>>();

    MembershipPayload {
        mode: topology.mode.as_str().to_string(),
        protocol: topology.membership_protocol.as_str().to_string(),
        view_id: topology.membership_view_id.clone(),
        leader_node_id: if topology.is_distributed() {
            None
        } else {
            Some(self_node_id.clone())
        },
        coordinator_node_id: self_node_id,
        nodes,
    }
}

fn metrics_payload(
    topology: &RuntimeTopologySnapshot,
    requests_total: u64,
    uptime_seconds: f64,
    health: &RuntimeHealthPayload,
    pending_due_warning_threshold_overrides: PendingDueWarningThresholdOverridesPayload,
) -> MetricsPayload {
    MetricsPayload {
        requests_total,
        uptime_seconds,
        version: env!("CARGO_PKG_VERSION").to_string(),
        membership_protocol_ready: health.membership_protocol_ready(),
        membership_converged: health.membership_converged(),
        membership_convergence_reason: health.membership_convergence_reason().to_string(),
        membership_last_update_age_ms: health.membership_last_update_age_ms,
        cluster_peer_auth_production_ready: health.checks.cluster_peer_auth_production_ready,
        cluster_auth_production_reason: health.cluster_auth_production_reason.clone(),
        write_durability_mode: health.write_durability_mode.clone(),
        metadata_listing_strategy: health.metadata_listing_strategy.clone(),
        metadata_listing_ready: health.checks.metadata_list_ready,
        pending_replication_backlog_operations: health.pending_replication_backlog_operations,
        pending_replication_backlog_due_targets: health.pending_replication_backlog_due_targets,
        pending_replication_replay_cycles_total: health.pending_replication_replay_cycles_total,
        pending_rebalance_backlog_operations: health.pending_rebalance_backlog_operations,
        pending_rebalance_replay_cycles_total: health.pending_rebalance_replay_cycles_total,
        pending_membership_propagation_backlog_operations: health
            .pending_membership_propagation_backlog_operations,
        pending_membership_propagation_replay_cycles_total: health
            .pending_membership_propagation_replay_cycles_total,
        pending_metadata_repair_backlog_plans: health.pending_metadata_repair_backlog_plans,
        pending_metadata_repair_replay_cycles_total: health
            .pending_metadata_repair_replay_cycles_total,
        pending_due_warning_threshold_overrides,
        topology: topology_payload(topology),
    }
}

fn pending_due_warning_threshold_overrides_payload(
    state: &AppState,
) -> PendingDueWarningThresholdOverridesPayload {
    PendingDueWarningThresholdOverridesPayload {
        replication_due_targets: state.config.pending_replication_due_warning_threshold,
        rebalance_due_transfers: state.config.pending_rebalance_due_warning_threshold,
        membership_propagation_due_operations: state
            .config
            .pending_membership_propagation_due_warning_threshold,
        metadata_repair_due_plans: state.config.pending_metadata_repair_due_warning_threshold,
    }
}

fn replica_fanout_operations() -> Vec<String> {
    vec![
        REPLICA_FANOUT_OPERATION_PUT_OBJECT.to_string(),
        REPLICA_FANOUT_OPERATION_COPY_OBJECT.to_string(),
        REPLICA_FANOUT_OPERATION_DELETE_OBJECT.to_string(),
        REPLICA_FANOUT_OPERATION_DELETE_OBJECT_VERSION.to_string(),
        REPLICA_FANOUT_OPERATION_COMPLETE_MULTIPART_UPLOAD.to_string(),
    ]
}

fn pending_replica_fanout_operations() -> Vec<String> {
    Vec::new()
}

pub(super) async fn get_health(State(state): State<AppState>) -> impl IntoResponse {
    let payload = runtime_health_payload(&state).await;
    response::json(StatusCode::OK, payload)
}

pub(super) async fn get_metrics(State(state): State<AppState>) -> impl IntoResponse {
    let requests_total = state.request_count.load(Ordering::Relaxed);
    let uptime_seconds = state.started_at.elapsed().as_secs_f64();
    let topology = runtime_topology_snapshot(&state);
    let health = runtime_health_payload(&state).await;
    let pending_due_warning_threshold_overrides =
        pending_due_warning_threshold_overrides_payload(&state);

    response::json(
        StatusCode::OK,
        metrics_payload(
            &topology,
            requests_total,
            uptime_seconds,
            &health,
            pending_due_warning_threshold_overrides,
        ),
    )
}

pub(super) async fn get_topology(State(state): State<AppState>) -> impl IntoResponse {
    let topology = runtime_topology_snapshot(&state);
    response::json(StatusCode::OK, topology_payload(&topology))
}

pub(super) async fn get_membership(State(state): State<AppState>) -> impl IntoResponse {
    let topology = runtime_topology_snapshot(&state);
    response::json(StatusCode::OK, membership_payload(&topology))
}

pub(super) async fn get_placement(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let query = match parse_placement_query(&params) {
        Ok(query) => query,
        Err(message) => return response::error(StatusCode::BAD_REQUEST, message),
    };
    let topology = runtime_topology_snapshot(&state);
    let health = runtime_health_payload(&state).await;
    let local_node = topology.node_id.as_str();
    let peers = topology.cluster_peers.as_slice();

    let (owners, primary_owner, forward_target) = match query.chunk_index {
        Some(chunk_index) => (
            select_chunk_owners_with_self(
                query.key.as_str(),
                chunk_index,
                local_node,
                peers,
                query.replica_count,
            ),
            primary_chunk_owner_with_self(query.key.as_str(), chunk_index, local_node, peers),
            chunk_forward_target_with_self(query.key.as_str(), chunk_index, local_node, peers),
        ),
        None => (
            select_object_owners_with_self(
                query.key.as_str(),
                local_node,
                peers,
                query.replica_count,
            ),
            primary_object_owner_with_self(query.key.as_str(), local_node, peers),
            object_forward_target_with_self(query.key.as_str(), local_node, peers),
        ),
    };

    let is_local_primary_owner = primary_owner.as_deref() == Some(local_node);
    let is_local_replica_owner = owners.iter().any(|owner| owner == local_node);
    let write_quorum_size = quorum_size(owners.len());
    let (non_owner_read_policy, non_owner_batch_mutation_policy, mixed_owner_batch_mutation_policy) =
        if topology.is_distributed() {
            (
                NON_OWNER_READ_POLICY_FORWARD_SINGLE_READ,
                NON_OWNER_BATCH_MUTATION_POLICY_FORWARD_MULTI_TARGET_BATCH,
                MIXED_OWNER_BATCH_MUTATION_POLICY_FORWARD_MIXED_OWNER_BATCH,
            )
        } else {
            (
                BATCH_MUTATION_POLICY_EXECUTE_LOCAL,
                BATCH_MUTATION_POLICY_EXECUTE_LOCAL,
                BATCH_MUTATION_POLICY_EXECUTE_LOCAL,
            )
        };
    let payload = PlacementPayload {
        key: query.key,
        chunk_index: query.chunk_index,
        replica_count_requested: query.replica_count,
        replica_count_applied: owners.len(),
        owners,
        primary_owner,
        forward_target,
        is_local_primary_owner,
        is_local_replica_owner,
        write_quorum_size,
        write_ack_policy: WRITE_ACK_POLICY_MAJORITY.to_string(),
        non_owner_mutation_policy: NON_OWNER_MUTATION_POLICY_FORWARD_SINGLE_WRITE.to_string(),
        non_owner_read_policy: non_owner_read_policy.to_string(),
        non_owner_batch_mutation_policy: non_owner_batch_mutation_policy.to_string(),
        mixed_owner_batch_mutation_policy: mixed_owner_batch_mutation_policy.to_string(),
        replica_fanout_operations: replica_fanout_operations(),
        pending_replica_fanout_operations: pending_replica_fanout_operations(),
        replica_fanout_execution: ReplicaFanoutExecutionPayload {
            write_durability_mode: health.write_durability_mode.clone(),
            pending_replication_queue_readable: health.checks.pending_replication_queue_readable,
            pending_replication_backlog_operations: health.pending_replication_backlog_operations,
            pending_replication_backlog_pending_targets: health
                .pending_replication_backlog_pending_targets,
            pending_replication_backlog_due_targets: health.pending_replication_backlog_due_targets,
            pending_replication_backlog_failed_targets: health
                .pending_replication_backlog_failed_targets,
            pending_replication_replay_cycles_total: health.pending_replication_replay_cycles_total,
            pending_replication_replay_cycles_succeeded: health
                .pending_replication_replay_cycles_succeeded,
            pending_replication_replay_cycles_failed: health
                .pending_replication_replay_cycles_failed,
            pending_replication_replay_last_success_unix_ms: health
                .pending_replication_replay_last_success_unix_ms,
        },
        topology: topology_payload(&topology),
        membership_view_id: topology.membership_view_id.clone(),
    };

    response::json(StatusCode::OK, payload)
}

pub(super) async fn get_rebalance(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let topology = runtime_topology_snapshot(&state);
    let query = match parse_rebalance_query(&params, &topology) {
        Ok(query) => query,
        Err(message) => return response::error(StatusCode::BAD_REQUEST, message),
    };

    let mut target_peers = topology.cluster_peers.clone();
    let (operation, operation_peer) = match &query.operation {
        RebalanceOperation::Join { peer } => {
            target_peers.push(peer.clone());
            ("join", peer.as_str())
        }
        RebalanceOperation::Leave { peer } => {
            target_peers.retain(|candidate| candidate != peer);
            ("leave", peer.as_str())
        }
    };

    let local_node = topology.node_id.as_str();
    let source_membership_nodes =
        membership_with_self(local_node, topology.cluster_peers.as_slice());
    let target_membership_nodes = membership_with_self(local_node, target_peers.as_slice());
    let target_view_id = membership_fingerprint(&target_membership_nodes);

    let plan = match query.chunk_index {
        Some(chunk_index) => chunk_rebalance_plan(
            query.key.as_str(),
            chunk_index,
            &source_membership_nodes,
            &target_membership_nodes,
            query.replica_count,
        ),
        None => object_rebalance_plan(
            query.key.as_str(),
            &source_membership_nodes,
            &target_membership_nodes,
            query.replica_count,
        ),
    };

    let transfer_count = plan.transfers.len();
    let local_actions = local_rebalance_actions(&plan, local_node)
        .into_iter()
        .map(|action| match action {
            crate::storage::placement::LocalRebalanceAction::Receive { from, to } => {
                RebalanceLocalActionPayload {
                    action: "receive".to_string(),
                    from,
                    to,
                }
            }
            crate::storage::placement::LocalRebalanceAction::Send { from, to } => {
                RebalanceLocalActionPayload {
                    action: "send".to_string(),
                    from: Some(from),
                    to,
                }
            }
        })
        .collect::<Vec<_>>();
    let transfers = plan
        .transfers
        .iter()
        .map(|transfer| RebalanceTransferPayload {
            from: transfer.from.clone(),
            to: transfer.to.clone(),
        })
        .collect::<Vec<_>>();

    let payload = RebalancePayload {
        key: query.key,
        chunk_index: query.chunk_index,
        replica_count_requested: query.replica_count,
        replica_count_applied: plan.next_owners.len(),
        operation: operation.to_string(),
        operation_peer: operation_peer.to_string(),
        source: RebalanceMembershipPayload {
            node_id: topology.node_id.clone(),
            cluster_peer_count: topology.cluster_peer_count(),
            cluster_peers: topology.cluster_peers.clone(),
            membership_view_id: topology.membership_view_id.clone(),
            membership_nodes: source_membership_nodes,
        },
        target: RebalanceMembershipPayload {
            node_id: local_node.to_string(),
            cluster_peer_count: target_peers.len(),
            cluster_peers: target_peers,
            membership_view_id: target_view_id,
            membership_nodes: target_membership_nodes,
        },
        plan: RebalancePlanPayload {
            previous_owners: plan.previous_owners,
            next_owners: plan.next_owners,
            retained_owners: plan.retained_owners,
            removed_owners: plan.removed_owners,
            added_owners: plan.added_owners,
            transfer_count,
            local_actions,
            transfers,
        },
        topology: topology_payload(&topology),
        membership_view_id: topology.membership_view_id.clone(),
    };

    response::json(StatusCode::OK, payload)
}

pub(super) async fn get_summary(State(state): State<AppState>) -> impl IntoResponse {
    let requests_total = state.request_count.load(Ordering::Relaxed);
    let uptime_seconds = state.started_at.elapsed().as_secs_f64();
    let topology = runtime_topology_snapshot(&state);
    let health = runtime_health_payload(&state).await;
    let pending_due_warning_threshold_overrides =
        pending_due_warning_threshold_overrides_payload(&state);
    let membership_protocol_ready = health.membership_protocol_ready();
    let membership_converged = health.membership_converged();
    let membership_convergence_reason = health.membership_convergence_reason().to_string();
    let metrics = SummaryMetricsPayload {
        requests_total,
        uptime_seconds,
        version: env!("CARGO_PKG_VERSION").to_string(),
        membership_protocol_ready,
        membership_converged,
        membership_convergence_reason,
        membership_last_update_age_ms: health.membership_last_update_age_ms,
        cluster_peer_auth_production_ready: health.checks.cluster_peer_auth_production_ready,
        cluster_auth_production_reason: health.cluster_auth_production_reason.clone(),
        write_durability_mode: health.write_durability_mode.clone(),
        metadata_listing_strategy: health.metadata_listing_strategy.clone(),
        metadata_listing_ready: health.checks.metadata_list_ready,
        pending_replication_backlog_operations: health.pending_replication_backlog_operations,
        pending_replication_backlog_due_targets: health.pending_replication_backlog_due_targets,
        pending_replication_replay_cycles_total: health.pending_replication_replay_cycles_total,
        pending_rebalance_backlog_operations: health.pending_rebalance_backlog_operations,
        pending_rebalance_replay_cycles_total: health.pending_rebalance_replay_cycles_total,
        pending_membership_propagation_backlog_operations: health
            .pending_membership_propagation_backlog_operations,
        pending_membership_propagation_replay_cycles_total: health
            .pending_membership_propagation_replay_cycles_total,
        pending_metadata_repair_backlog_plans: health.pending_metadata_repair_backlog_plans,
        pending_metadata_repair_replay_cycles_total: health
            .pending_metadata_repair_replay_cycles_total,
        pending_due_warning_threshold_overrides,
    };

    let payload = SummaryPayload {
        health,
        metrics,
        topology: topology_payload(&topology),
        membership: membership_payload(&topology),
    };
    response::json(StatusCode::OK, payload)
}

struct PlacementQuery {
    key: String,
    chunk_index: Option<u32>,
    replica_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RebalanceOperation {
    Join { peer: String },
    Leave { peer: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RebalanceQuery {
    key: String,
    chunk_index: Option<u32>,
    replica_count: usize,
    operation: RebalanceOperation,
}

fn parse_placement_query(params: &HashMap<String, String>) -> Result<PlacementQuery, String> {
    let raw_key = params
        .get("key")
        .map(String::as_str)
        .ok_or_else(|| "Missing required query parameter: key".to_string())?;
    if raw_key.trim().is_empty() {
        return Err("Missing required query parameter: key".to_string());
    }
    let key = raw_key.to_string();
    if let Err(StorageError::InvalidKey(message)) = validate_key(&key) {
        return Err(format!("Invalid key query parameter: {message}"));
    }

    let replica_count = match params.get("replicaCount").map(String::as_str) {
        Some(raw_value) => raw_value
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| "Invalid replicaCount query parameter".to_string())?,
        None => 1,
    };

    let chunk_index = match params.get("chunkIndex").map(String::as_str) {
        Some(raw_value) => Some(
            raw_value
                .trim()
                .parse::<u32>()
                .map_err(|_| "Invalid chunkIndex query parameter".to_string())?,
        ),
        None => None,
    };

    Ok(PlacementQuery {
        key,
        chunk_index,
        replica_count,
    })
}

fn parse_rebalance_query(
    params: &HashMap<String, String>,
    topology: &RuntimeTopologySnapshot,
) -> Result<RebalanceQuery, String> {
    let placement = parse_placement_query(params)?;
    let add_peer = parse_optional_peer_param(params, "addPeer")?;
    let remove_peer = parse_optional_peer_param(params, "removePeer")?;

    let operation = match (add_peer, remove_peer) {
        (Some(_), Some(_)) => {
            return Err("Provide only one of addPeer or removePeer".to_string());
        }
        (None, None) => {
            return Err("Missing required query parameter: addPeer or removePeer".to_string());
        }
        (Some(peer), None) => {
            if peer == topology.node_id
                || topology
                    .cluster_peers
                    .iter()
                    .any(|current| current == &peer)
            {
                return Err(
                    "addPeer must reference a new peer not already in membership".to_string(),
                );
            }
            RebalanceOperation::Join { peer }
        }
        (None, Some(peer)) => {
            if peer == topology.node_id {
                return Err("removePeer cannot reference the local node".to_string());
            }
            if !topology
                .cluster_peers
                .iter()
                .any(|current| current == &peer)
            {
                return Err("removePeer must reference an existing cluster peer".to_string());
            }
            RebalanceOperation::Leave { peer }
        }
    };

    Ok(RebalanceQuery {
        key: placement.key,
        chunk_index: placement.chunk_index,
        replica_count: placement.replica_count,
        operation,
    })
}

fn parse_optional_peer_param(
    params: &HashMap<String, String>,
    name: &str,
) -> Result<Option<String>, String> {
    let Some(raw_peer) = params.get(name).map(String::as_str) else {
        return Ok(None);
    };

    let peer = raw_peer.trim();
    if peer.is_empty() {
        return Err(format!("Invalid {name} query parameter"));
    }
    validate_peer_endpoint(peer, name)?;
    Ok(Some(peer.to_string()))
}

fn validate_peer_endpoint(peer: &str, field_name: &str) -> Result<(), String> {
    let (host, port) = peer
        .rsplit_once(':')
        .ok_or_else(|| format!("Invalid {field_name} query parameter: expected host:port"))?;
    if host.trim().is_empty() {
        return Err(format!(
            "Invalid {field_name} query parameter: expected host:port"
        ));
    }
    let parsed_port = port
        .parse::<u16>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("Invalid {field_name} query parameter: invalid port"))?;
    let _ = parsed_port;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        PlacementPayload, RebalanceOperation, membership_payload, parse_placement_query,
        parse_rebalance_query, topology_payload,
    };
    use crate::config::MembershipProtocol;
    use crate::membership::MembershipEngineStatus;
    use crate::server::{RuntimeMode, RuntimeTopologySnapshot};
    use std::collections::HashMap;

    fn topology(node_id: &str, peers: &[&str]) -> RuntimeTopologySnapshot {
        RuntimeTopologySnapshot {
            mode: if peers.is_empty() {
                RuntimeMode::Standalone
            } else {
                RuntimeMode::Distributed
            },
            node_id: node_id.to_string(),
            cluster_id: "cluster-1".to_string(),
            cluster_peers: peers.iter().map(|value| value.to_string()).collect(),
            membership_view_id: "view-1".to_string(),
            membership_protocol: MembershipProtocol::StaticBootstrap,
            membership_status: MembershipEngineStatus {
                engine: "static-bootstrap".to_string(),
                protocol: MembershipProtocol::StaticBootstrap.as_str().to_string(),
                ready: true,
                converged: true,
                last_update_unix_ms: 0,
                warning: None,
            },
            placement_epoch: 0,
            membership_nodes: std::iter::once(node_id.to_string())
                .chain(peers.iter().map(|value| value.to_string()))
                .collect(),
        }
    }

    #[test]
    fn parse_placement_query_accepts_key_and_defaults_replica_count() {
        let mut params = HashMap::new();
        params.insert("key".to_string(), "docs/readme.txt".to_string());

        let parsed = parse_placement_query(&params).expect("query should parse");
        assert_eq!(parsed.key, "docs/readme.txt");
        assert_eq!(parsed.chunk_index, None);
        assert_eq!(parsed.replica_count, 1);
    }

    #[test]
    fn parse_placement_query_accepts_chunk_index_and_replica_count() {
        let mut params = HashMap::new();
        params.insert("key".to_string(), "videos/movie.mp4".to_string());
        params.insert("chunkIndex".to_string(), "7".to_string());
        params.insert("replicaCount".to_string(), "3".to_string());

        let parsed = parse_placement_query(&params).expect("query should parse");
        assert_eq!(parsed.key, "videos/movie.mp4");
        assert_eq!(parsed.chunk_index, Some(7));
        assert_eq!(parsed.replica_count, 3);
    }

    #[test]
    fn parse_placement_query_accepts_trimmed_numeric_values() {
        let mut params = HashMap::new();
        params.insert("key".to_string(), "videos/movie.mp4".to_string());
        params.insert("chunkIndex".to_string(), " 7 ".to_string());
        params.insert("replicaCount".to_string(), " 3 ".to_string());

        let parsed = parse_placement_query(&params).expect("query should parse");
        assert_eq!(parsed.chunk_index, Some(7));
        assert_eq!(parsed.replica_count, 3);
    }

    #[test]
    fn parse_placement_query_rejects_invalid_key() {
        let mut params = HashMap::new();
        params.insert("key".to_string(), "/absolute/path".to_string());

        let err = match parse_placement_query(&params) {
            Ok(_) => panic!("invalid key should fail"),
            Err(err) => err,
        };
        assert!(err.contains("Invalid key"));
    }

    #[test]
    fn parse_placement_query_rejects_missing_key() {
        let params = HashMap::<String, String>::new();
        let err = match parse_placement_query(&params) {
            Ok(_) => panic!("missing key should fail"),
            Err(err) => err,
        };
        assert!(err.contains("key"));
    }

    #[test]
    fn parse_placement_query_rejects_invalid_replica_count() {
        let mut params = HashMap::new();
        params.insert("key".to_string(), "docs/readme.txt".to_string());
        params.insert("replicaCount".to_string(), "0".to_string());

        let err = match parse_placement_query(&params) {
            Ok(_) => panic!("invalid replica count should fail"),
            Err(err) => err,
        };
        assert!(err.contains("replicaCount"));
    }

    #[test]
    fn parse_placement_query_rejects_invalid_chunk_index() {
        let mut params = HashMap::new();
        params.insert("key".to_string(), "docs/readme.txt".to_string());
        params.insert("chunkIndex".to_string(), "abc".to_string());

        let err = match parse_placement_query(&params) {
            Ok(_) => panic!("invalid chunk index should fail"),
            Err(err) => err,
        };
        assert!(err.contains("chunkIndex"));
    }

    #[test]
    fn parse_rebalance_query_accepts_add_peer_join_operation() {
        let mut params = HashMap::new();
        params.insert("key".to_string(), "docs/readme.txt".to_string());
        params.insert("replicaCount".to_string(), "2".to_string());
        params.insert("addPeer".to_string(), "node-b.internal:9000".to_string());

        let parsed = parse_rebalance_query(&params, &topology("node-a.internal:9000", &[]))
            .expect("rebalance query should parse");
        assert_eq!(parsed.key, "docs/readme.txt");
        assert_eq!(parsed.replica_count, 2);
        match parsed.operation {
            RebalanceOperation::Join { peer } => assert_eq!(peer, "node-b.internal:9000"),
            RebalanceOperation::Leave { .. } => panic!("expected join operation"),
        }
    }

    #[test]
    fn parse_rebalance_query_accepts_remove_peer_leave_operation() {
        let mut params = HashMap::new();
        params.insert("key".to_string(), "docs/readme.txt".to_string());
        params.insert("removePeer".to_string(), "node-b.internal:9000".to_string());

        let parsed = parse_rebalance_query(
            &params,
            &topology("node-a.internal:9000", &["node-b.internal:9000"]),
        )
        .expect("rebalance query should parse");
        match parsed.operation {
            RebalanceOperation::Join { .. } => panic!("expected leave operation"),
            RebalanceOperation::Leave { peer } => assert_eq!(peer, "node-b.internal:9000"),
        }
    }

    #[test]
    fn parse_rebalance_query_rejects_missing_operation() {
        let mut params = HashMap::new();
        params.insert("key".to_string(), "docs/readme.txt".to_string());

        let err = parse_rebalance_query(&params, &topology("node-a.internal:9000", &[]))
            .expect_err("missing operation should fail");
        assert!(err.contains("addPeer or removePeer"));
    }

    #[test]
    fn parse_rebalance_query_rejects_both_operation_params() {
        let mut params = HashMap::new();
        params.insert("key".to_string(), "docs/readme.txt".to_string());
        params.insert("addPeer".to_string(), "node-b.internal:9000".to_string());
        params.insert("removePeer".to_string(), "node-c.internal:9000".to_string());

        let err = parse_rebalance_query(
            &params,
            &topology(
                "node-a.internal:9000",
                &["node-b.internal:9000", "node-c.internal:9000"],
            ),
        )
        .expect_err("both operation params should fail");
        assert!(err.contains("only one"));
    }

    #[test]
    fn parse_rebalance_query_rejects_invalid_peer_endpoint() {
        let mut params = HashMap::new();
        params.insert("key".to_string(), "docs/readme.txt".to_string());
        params.insert("addPeer".to_string(), "invalid-peer".to_string());

        let err = parse_rebalance_query(&params, &topology("node-a.internal:9000", &[]))
            .expect_err("invalid peer endpoint should fail");
        assert!(err.contains("host:port"));
    }

    #[test]
    fn parse_rebalance_query_rejects_unknown_remove_peer() {
        let mut params = HashMap::new();
        params.insert("key".to_string(), "docs/readme.txt".to_string());
        params.insert("removePeer".to_string(), "node-c.internal:9000".to_string());

        let err = parse_rebalance_query(
            &params,
            &topology("node-a.internal:9000", &["node-b.internal:9000"]),
        )
        .expect_err("unknown remove peer should fail");
        assert!(err.contains("existing cluster peer"));
    }

    #[test]
    fn membership_payload_uses_null_leader_in_distributed_mode() {
        let payload =
            membership_payload(&topology("node-a.internal:9000", &["node-b.internal:9000"]));
        let value = serde_json::to_value(payload).expect("payload should serialize");

        assert!(value["leaderNodeId"].is_null());
        assert_eq!(value["coordinatorNodeId"], "node-a.internal:9000");
        assert_eq!(value["mode"], "distributed");
    }

    #[test]
    fn topology_payload_uses_expected_camel_case_contract() {
        let payload =
            topology_payload(&topology("node-a.internal:9000", &["node-b.internal:9000"]));
        let value = serde_json::to_value(payload).expect("payload should serialize");

        assert_eq!(value["nodeId"], "node-a.internal:9000");
        assert_eq!(value["clusterPeerCount"], 1);
        assert_eq!(
            value["clusterPeers"],
            serde_json::to_value(vec!["node-b.internal:9000"]).expect("array should serialize")
        );
        assert_eq!(value["membershipProtocol"], "static-bootstrap");
        assert_eq!(value["placementEpoch"], 0);
    }

    #[test]
    fn placement_payload_uses_expected_camel_case_contract() {
        let payload = PlacementPayload {
            key: "docs/readme.txt".to_string(),
            chunk_index: None,
            replica_count_requested: 2,
            replica_count_applied: 1,
            owners: vec!["node-a.internal:9000".to_string()],
            primary_owner: Some("node-a.internal:9000".to_string()),
            forward_target: None,
            is_local_primary_owner: true,
            is_local_replica_owner: true,
            write_quorum_size: 1,
            write_ack_policy: "majority".to_string(),
            non_owner_mutation_policy: "forward-single-write".to_string(),
            non_owner_read_policy: "execute-local".to_string(),
            non_owner_batch_mutation_policy: "execute-local".to_string(),
            mixed_owner_batch_mutation_policy: "execute-local".to_string(),
            replica_fanout_operations: super::replica_fanout_operations(),
            pending_replica_fanout_operations: super::pending_replica_fanout_operations(),
            replica_fanout_execution: super::ReplicaFanoutExecutionPayload {
                write_durability_mode: "degraded-success".to_string(),
                pending_replication_queue_readable: true,
                pending_replication_backlog_operations: 0,
                pending_replication_backlog_pending_targets: 0,
                pending_replication_backlog_due_targets: 0,
                pending_replication_backlog_failed_targets: 0,
                pending_replication_replay_cycles_total: 0,
                pending_replication_replay_cycles_succeeded: 0,
                pending_replication_replay_cycles_failed: 0,
                pending_replication_replay_last_success_unix_ms: 0,
            },
            topology: topology_payload(&topology("node-a.internal:9000", &[])),
            membership_view_id: "view-1".to_string(),
        };
        let value = serde_json::to_value(payload).expect("payload should serialize");

        assert_eq!(value["nonOwnerMutationPolicy"], "forward-single-write");
        assert_eq!(value["nonOwnerReadPolicy"], "execute-local");
        assert_eq!(value["nonOwnerBatchMutationPolicy"], "execute-local");
        assert_eq!(value["mixedOwnerBatchMutationPolicy"], "execute-local");
        assert_eq!(value["writeAckPolicy"], "majority");
        assert_eq!(value["writeQuorumSize"], 1);
        assert_eq!(
            value["replicaFanoutOperations"],
            serde_json::json!([
                "put-object",
                "copy-object",
                "delete-object",
                "delete-object-version",
                "complete-multipart-upload"
            ])
        );
        assert_eq!(
            value["pendingReplicaFanoutOperations"],
            serde_json::json!([])
        );
        assert_eq!(
            value["replicaFanoutExecution"]["writeDurabilityMode"],
            "degraded-success"
        );
        assert_eq!(
            value["replicaFanoutExecution"]["pendingReplicationQueueReadable"],
            true
        );
    }
}
