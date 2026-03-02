use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Normalize a membership view into a sorted, unique node list.
pub fn normalize_nodes(nodes: &[String]) -> Vec<String> {
    nodes
        .iter()
        .map(|node| node.trim())
        .filter(|node| !node.is_empty())
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Stable fingerprint for a membership view.
pub fn membership_fingerprint(nodes: &[String]) -> String {
    let normalized = normalize_nodes(nodes);
    let mut hasher = Sha256::new();
    for node in normalized {
        hasher.update(node.as_bytes());
        hasher.update([0]);
    }
    hex::encode(hasher.finalize())
}

/// Normalize membership peers plus the local node id into a single view.
pub fn membership_with_self(node_id: &str, peers: &[String]) -> Vec<String> {
    let mut nodes = peers.to_vec();
    nodes.push(node_id.to_string());
    normalize_nodes(&nodes)
}

/// Stable fingerprint for membership peers plus the local node id.
pub fn membership_view_id_with_self(node_id: &str, peers: &[String]) -> String {
    membership_fingerprint(&membership_with_self(node_id, peers))
}

/// Required acknowledgements for quorum on a replica set.
///
/// Returns `0` when no replicas are selected.
pub fn quorum_size(replica_count: usize) -> usize {
    if replica_count == 0 {
        0
    } else {
        (replica_count / 2) + 1
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectWritePlan {
    pub owners: Vec<String>,
    pub primary_owner: Option<String>,
    pub forward_target: Option<String>,
    pub is_local_primary_owner: bool,
    pub is_local_replica_owner: bool,
    pub quorum_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteAckObservation {
    pub node: String,
    pub acked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectWriteQuorumOutcome {
    pub acked_nodes: Vec<String>,
    pub rejected_nodes: Vec<String>,
    pub pending_nodes: Vec<String>,
    pub ack_count: usize,
    pub quorum_size: usize,
    pub quorum_reached: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaObservation {
    pub node: String,
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectReadRepairPlan {
    pub replica_count: usize,
    pub quorum_size: usize,
    pub chosen_version: Option<String>,
    pub chosen_count: usize,
    pub quorum_reached: bool,
    pub stale_nodes: Vec<String>,
    pub missing_nodes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadRepairAction {
    UpsertVersion { node: String, version: String },
    DeleteReplica { node: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectReadRepairExecutionPlan {
    pub plan: ObjectReadRepairPlan,
    pub actions: Vec<ReadRepairAction>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadRepairExecutionPolicy {
    Quorum,
    PrimaryAuthoritative,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebalanceTransfer {
    pub from: Option<String>,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectRebalancePlan {
    pub previous_owners: Vec<String>,
    pub next_owners: Vec<String>,
    pub retained_owners: Vec<String>,
    pub removed_owners: Vec<String>,
    pub added_owners: Vec<String>,
    pub transfers: Vec<RebalanceTransfer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementViewState {
    pub epoch: u64,
    pub node_id: String,
    pub members: Vec<String>,
    pub view_id: String,
}

impl PlacementViewState {
    /// Build a typed placement view from local node + peers and a persisted epoch.
    pub fn from_membership(epoch: u64, node_id: &str, peers: &[String]) -> Self {
        let node_id = node_id.trim().to_string();
        let members = membership_with_self(&node_id, peers);
        let view_id = membership_fingerprint(&members);
        Self {
            epoch,
            node_id,
            members,
            view_id,
        }
    }

    /// Build an object-write plan against this placement view.
    pub fn object_write_plan(&self, key: &str, replica_count: usize) -> ObjectWritePlan {
        object_write_plan_for_membership(key, self.node_id.as_str(), &self.members, replica_count)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardEpochStatus {
    Current,
    Stale,
    Future,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementHandoffRole {
    StableOwner,
    IncomingOwner,
    OutgoingOwner,
    Unowned,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementHandoffPlan {
    pub previous_epoch: u64,
    pub next_epoch: u64,
    pub previous_view_id: String,
    pub next_view_id: String,
    pub local_role: PlacementHandoffRole,
    pub transfer_required: bool,
    pub rebalance: ObjectRebalancePlan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardedWriteOperation {
    PutObject,
    CreateMultipartUpload,
    UploadMultipartPart,
    CompleteMultipartUpload,
    AbortMultipartUpload,
    ReplicatePutObject,
    ReplicateDeleteObject,
    ReplicateHeadObject,
    CopyObject,
    DeleteObject,
    DeleteObjectVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardedWriteEnvelope {
    pub operation: ForwardedWriteOperation,
    pub bucket: String,
    pub key: String,
    pub coordinator_node: String,
    pub origin_node: String,
    pub placement_epoch: u64,
    pub placement_view_id: String,
    pub idempotency_key: String,
    pub visited_nodes: Vec<String>,
    pub hop_count: u8,
    pub max_hops: u8,
}

impl ForwardedWriteEnvelope {
    /// Build a forwarded-write envelope for a specific placement view.
    pub fn new(
        operation: ForwardedWriteOperation,
        bucket: &str,
        key: &str,
        coordinator_node: &str,
        origin_node: &str,
        idempotency_key: &str,
        placement: &PlacementViewState,
    ) -> Self {
        Self {
            operation,
            bucket: bucket.trim().to_string(),
            key: key.trim().to_string(),
            coordinator_node: coordinator_node.trim().to_string(),
            origin_node: origin_node.trim().to_string(),
            placement_epoch: placement.epoch,
            placement_view_id: placement.view_id.clone(),
            idempotency_key: idempotency_key.trim().to_string(),
            visited_nodes: Vec::new(),
            hop_count: 0,
            max_hops: 8,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardedWriteRejectReason {
    MissingPrimaryOwner,
    MissingForwardTarget,
    StaleEpoch {
        local_epoch: u64,
        request_epoch: u64,
    },
    FutureEpoch {
        local_epoch: u64,
        request_epoch: u64,
    },
    ViewIdMismatch {
        local_view_id: String,
        request_view_id: String,
    },
    ForwardLoop {
        node: String,
    },
    HopLimitExceeded {
        hop_count: u8,
        max_hops: u8,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardedWriteResolution {
    ExecuteLocal {
        primary_owner: String,
        quorum_size: usize,
    },
    ForwardToPrimary {
        target: String,
        envelope: ForwardedWriteEnvelope,
    },
    Reject {
        reason: ForwardedWriteRejectReason,
    },
}

/// Select owners for an object key using rendezvous hashing.
///
/// The returned list is ordered by priority (`owners[0]` is the primary owner).
pub fn select_object_owners(key: &str, nodes: &[String], replica_count: usize) -> Vec<String> {
    select_owners(key.as_bytes(), nodes, replica_count)
}

/// Select the primary owner for an object key using rendezvous hashing.
pub fn primary_object_owner(key: &str, nodes: &[String]) -> Option<String> {
    select_object_owners(key, nodes, 1).into_iter().next()
}

/// Select owners for an object key from a local-node + peers membership view.
pub fn select_object_owners_with_self(
    key: &str,
    node_id: &str,
    peers: &[String],
    replica_count: usize,
) -> Vec<String> {
    let membership = membership_with_self(node_id, peers);
    select_object_owners(key, &membership, replica_count)
}

/// Select the primary owner for an object key from a local-node + peers membership view.
pub fn primary_object_owner_with_self(
    key: &str,
    node_id: &str,
    peers: &[String],
) -> Option<String> {
    select_object_owners_with_self(key, node_id, peers, 1)
        .into_iter()
        .next()
}

/// Select owners for an object chunk using rendezvous hashing.
pub fn select_chunk_owners(
    object_key: &str,
    chunk_index: u32,
    nodes: &[String],
    replica_count: usize,
) -> Vec<String> {
    let mut key = object_key.as_bytes().to_vec();
    key.push(0);
    key.extend_from_slice(&chunk_index.to_be_bytes());
    select_owners(&key, nodes, replica_count)
}

/// Select the primary owner for an object chunk using rendezvous hashing.
pub fn primary_chunk_owner(object_key: &str, chunk_index: u32, nodes: &[String]) -> Option<String> {
    select_chunk_owners(object_key, chunk_index, nodes, 1)
        .into_iter()
        .next()
}

/// Select owners for an object chunk from a local-node + peers membership view.
pub fn select_chunk_owners_with_self(
    object_key: &str,
    chunk_index: u32,
    node_id: &str,
    peers: &[String],
    replica_count: usize,
) -> Vec<String> {
    let membership = membership_with_self(node_id, peers);
    select_chunk_owners(object_key, chunk_index, &membership, replica_count)
}

/// Select the primary owner for an object chunk from a local-node + peers membership view.
pub fn primary_chunk_owner_with_self(
    object_key: &str,
    chunk_index: u32,
    node_id: &str,
    peers: &[String],
) -> Option<String> {
    select_chunk_owners_with_self(object_key, chunk_index, node_id, peers, 1)
        .into_iter()
        .next()
}

/// Whether the local node is selected as an owner for an object key.
pub fn is_local_object_owner(
    key: &str,
    node_id: &str,
    peers: &[String],
    replica_count: usize,
) -> bool {
    let node_id = node_id.trim();
    if node_id.is_empty() || replica_count == 0 {
        return false;
    }
    select_object_owners_with_self(key, node_id, peers, replica_count)
        .iter()
        .any(|owner| owner == node_id)
}

/// Determine whether an object operation should be forwarded and return the target primary owner.
///
/// Returns `None` when the local node is already the primary owner or the local node id is empty.
pub fn object_forward_target_with_self(
    key: &str,
    node_id: &str,
    peers: &[String],
) -> Option<String> {
    let node_id = node_id.trim();
    if node_id.is_empty() {
        return None;
    }

    let owner = primary_object_owner_with_self(key, node_id, peers)?;
    if owner == node_id { None } else { Some(owner) }
}

/// Build an object-write placement plan with owner/forwarding/quorum diagnostics.
pub fn object_write_plan_with_self(
    key: &str,
    node_id: &str,
    peers: &[String],
    replica_count: usize,
) -> ObjectWritePlan {
    let membership = membership_with_self(node_id, peers);
    object_write_plan_for_membership(key, node_id, &membership, replica_count)
}

/// Evaluate a write-ack quorum outcome against an object write plan.
///
/// Only plan owners are considered for quorum accounting. Unknown observation nodes are ignored.
/// Duplicate node observations are collapsed with "any ack wins" semantics.
pub fn object_write_quorum_outcome(
    plan: &ObjectWritePlan,
    observations: &[WriteAckObservation],
) -> ObjectWriteQuorumOutcome {
    let mut observation_map = BTreeMap::<String, bool>::new();
    for observation in observations {
        let node = observation.node.trim();
        if node.is_empty() {
            continue;
        }
        observation_map
            .entry(node.to_string())
            .and_modify(|acked| *acked |= observation.acked)
            .or_insert(observation.acked);
    }

    let mut acked_nodes = Vec::<String>::new();
    let mut rejected_nodes = Vec::<String>::new();
    let mut pending_nodes = Vec::<String>::new();
    for owner in &plan.owners {
        match observation_map.get(owner) {
            Some(true) => acked_nodes.push(owner.clone()),
            Some(false) => rejected_nodes.push(owner.clone()),
            None => pending_nodes.push(owner.clone()),
        }
    }

    let ack_count = acked_nodes.len();
    let quorum_size = plan.quorum_size;
    let quorum_reached = quorum_size > 0 && ack_count >= quorum_size;

    ObjectWriteQuorumOutcome {
        ack_count,
        quorum_size,
        quorum_reached,
        acked_nodes,
        rejected_nodes,
        pending_nodes,
    }
}

/// Build a deterministic read/repair plan from observed replica versions.
///
/// The chosen version is selected by highest observed count; ties prefer present versions
/// over missing entries, then lexicographically higher version ids.
pub fn object_read_repair_plan(
    observations: &[ReplicaObservation],
    replica_count: usize,
) -> ObjectReadRepairPlan {
    let quorum = quorum_size(replica_count);
    let normalized = normalize_observations(observations);

    let mut counts = BTreeMap::<Option<String>, usize>::new();
    for version in normalized.values() {
        *counts.entry(version.clone()).or_insert(0) += 1;
    }

    let (chosen_version, chosen_count) =
        counts.into_iter().fold((None, 0usize), |best, candidate| {
            if is_better_version_candidate(&candidate, &best) {
                candidate
            } else {
                best
            }
        });

    let mut stale_nodes = Vec::<String>::new();
    let mut missing_nodes = Vec::<String>::new();
    for (node, version) in normalized {
        if version == chosen_version {
            continue;
        }
        if version.is_none() && chosen_version.is_some() {
            missing_nodes.push(node);
        } else {
            stale_nodes.push(node);
        }
    }

    ObjectReadRepairPlan {
        replica_count,
        quorum_size: quorum,
        quorum_reached: chosen_count >= quorum,
        chosen_version,
        chosen_count,
        stale_nodes,
        missing_nodes,
    }
}

/// Build a deterministic execution plan from replica observations.
///
/// Repair actions are only emitted when the chosen version reaches quorum.
pub fn object_read_repair_execution_plan(
    observations: &[ReplicaObservation],
    replica_count: usize,
) -> ObjectReadRepairExecutionPlan {
    object_read_repair_execution_plan_with_policy(
        observations,
        replica_count,
        ReadRepairExecutionPolicy::Quorum,
    )
}

/// Build a deterministic execution plan from replica observations using explicit policy controls.
///
/// `Quorum` only emits actions when a chosen version reaches quorum.
/// `PrimaryAuthoritative` emits actions based on the chosen version without quorum gating.
pub fn object_read_repair_execution_plan_with_policy(
    observations: &[ReplicaObservation],
    replica_count: usize,
    policy: ReadRepairExecutionPolicy,
) -> ObjectReadRepairExecutionPlan {
    let normalized = normalize_observations(observations);
    let plan = object_read_repair_plan(observations, replica_count);
    let emit_actions = match policy {
        ReadRepairExecutionPolicy::Quorum => plan.quorum_reached,
        ReadRepairExecutionPolicy::PrimaryAuthoritative => plan.chosen_count > 0,
    };
    if !emit_actions || normalized.is_empty() {
        return ObjectReadRepairExecutionPlan {
            plan,
            actions: Vec::new(),
        };
    }

    let mut actions = Vec::<ReadRepairAction>::new();
    for (node, observed_version) in normalized {
        if observed_version == plan.chosen_version {
            continue;
        }

        match &plan.chosen_version {
            Some(version) => actions.push(ReadRepairAction::UpsertVersion {
                node,
                version: version.clone(),
            }),
            None => {
                if observed_version.is_some() {
                    actions.push(ReadRepairAction::DeleteReplica { node });
                }
            }
        }
    }

    ObjectReadRepairExecutionPlan { plan, actions }
}

/// Build a deterministic rebalance plan for an object key between two membership views.
///
/// Owner transitions and transfer pairing are deterministic and ordered by owner priority.
pub fn object_rebalance_plan(
    key: &str,
    previous_nodes: &[String],
    next_nodes: &[String],
    replica_count: usize,
) -> ObjectRebalancePlan {
    build_rebalance_plan(
        select_object_owners(key, previous_nodes, replica_count),
        select_object_owners(key, next_nodes, replica_count),
    )
}

/// Build a deterministic rebalance plan for a chunk key between two membership views.
pub fn chunk_rebalance_plan(
    object_key: &str,
    chunk_index: u32,
    previous_nodes: &[String],
    next_nodes: &[String],
    replica_count: usize,
) -> ObjectRebalancePlan {
    build_rebalance_plan(
        select_chunk_owners(object_key, chunk_index, previous_nodes, replica_count),
        select_chunk_owners(object_key, chunk_index, next_nodes, replica_count),
    )
}

/// Whether the local node is selected as an owner for an object chunk.
pub fn is_local_chunk_owner(
    object_key: &str,
    chunk_index: u32,
    node_id: &str,
    peers: &[String],
    replica_count: usize,
) -> bool {
    let node_id = node_id.trim();
    if node_id.is_empty() || replica_count == 0 {
        return false;
    }
    select_chunk_owners_with_self(object_key, chunk_index, node_id, peers, replica_count)
        .iter()
        .any(|owner| owner == node_id)
}

/// Determine whether a chunk operation should be forwarded and return the target primary owner.
///
/// Returns `None` when the local node is already the primary owner or the local node id is empty.
pub fn chunk_forward_target_with_self(
    object_key: &str,
    chunk_index: u32,
    node_id: &str,
    peers: &[String],
) -> Option<String> {
    let node_id = node_id.trim();
    if node_id.is_empty() {
        return None;
    }

    let owner = primary_chunk_owner_with_self(object_key, chunk_index, node_id, peers)?;
    if owner == node_id { None } else { Some(owner) }
}

/// Compare a forwarded write epoch against the current local placement epoch.
pub fn compare_forward_epoch(local_epoch: u64, request_epoch: u64) -> ForwardEpochStatus {
    if request_epoch == local_epoch {
        ForwardEpochStatus::Current
    } else if request_epoch < local_epoch {
        ForwardEpochStatus::Stale
    } else {
        ForwardEpochStatus::Future
    }
}

/// Build deterministic object handoff coordination state between two placement views.
pub fn object_handoff_plan_for_transition(
    key: &str,
    local_node: &str,
    previous: &PlacementViewState,
    next: &PlacementViewState,
    replica_count: usize,
) -> PlacementHandoffPlan {
    let rebalance = object_rebalance_plan(key, &previous.members, &next.members, replica_count);
    handoff_plan_from_rebalance(local_node, previous, next, rebalance)
}

/// Build deterministic chunk handoff coordination state between two placement views.
pub fn chunk_handoff_plan_for_transition(
    object_key: &str,
    chunk_index: u32,
    local_node: &str,
    previous: &PlacementViewState,
    next: &PlacementViewState,
    replica_count: usize,
) -> PlacementHandoffPlan {
    let rebalance = chunk_rebalance_plan(
        object_key,
        chunk_index,
        &previous.members,
        &next.members,
        replica_count,
    );
    handoff_plan_from_rebalance(local_node, previous, next, rebalance)
}

/// Resolve whether a forwarded write can execute locally, should be forwarded, or must be rejected.
pub fn resolve_forwarded_write_envelope(
    envelope: &ForwardedWriteEnvelope,
    local_node: &str,
    placement: &PlacementViewState,
    replica_count: usize,
) -> ForwardedWriteResolution {
    match compare_forward_epoch(placement.epoch, envelope.placement_epoch) {
        ForwardEpochStatus::Current => {}
        ForwardEpochStatus::Stale => {
            return ForwardedWriteResolution::Reject {
                reason: ForwardedWriteRejectReason::StaleEpoch {
                    local_epoch: placement.epoch,
                    request_epoch: envelope.placement_epoch,
                },
            };
        }
        ForwardEpochStatus::Future => {
            return ForwardedWriteResolution::Reject {
                reason: ForwardedWriteRejectReason::FutureEpoch {
                    local_epoch: placement.epoch,
                    request_epoch: envelope.placement_epoch,
                },
            };
        }
    }

    if envelope.placement_view_id != placement.view_id {
        return ForwardedWriteResolution::Reject {
            reason: ForwardedWriteRejectReason::ViewIdMismatch {
                local_view_id: placement.view_id.clone(),
                request_view_id: envelope.placement_view_id.clone(),
            },
        };
    }

    let local_node = local_node.trim();
    let route = normalize_route_nodes(&envelope.visited_nodes);
    if route.iter().any(|node| node == local_node) {
        return ForwardedWriteResolution::Reject {
            reason: ForwardedWriteRejectReason::ForwardLoop {
                node: local_node.to_string(),
            },
        };
    }

    if envelope.hop_count >= envelope.max_hops {
        return ForwardedWriteResolution::Reject {
            reason: ForwardedWriteRejectReason::HopLimitExceeded {
                hop_count: envelope.hop_count,
                max_hops: envelope.max_hops,
            },
        };
    }

    let plan = placement.object_write_plan(&envelope.key, replica_count);
    let Some(primary_owner) = plan.primary_owner.clone() else {
        return ForwardedWriteResolution::Reject {
            reason: ForwardedWriteRejectReason::MissingPrimaryOwner,
        };
    };

    if matches!(
        envelope.operation,
        ForwardedWriteOperation::ReplicatePutObject
            | ForwardedWriteOperation::ReplicateDeleteObject
            | ForwardedWriteOperation::ReplicateHeadObject
    ) {
        if plan.is_local_replica_owner {
            return ForwardedWriteResolution::ExecuteLocal {
                primary_owner,
                quorum_size: plan.quorum_size,
            };
        }
        return ForwardedWriteResolution::Reject {
            reason: ForwardedWriteRejectReason::MissingForwardTarget,
        };
    }

    if plan.is_local_primary_owner {
        return ForwardedWriteResolution::ExecuteLocal {
            primary_owner,
            quorum_size: plan.quorum_size,
        };
    }

    let Some(target) = plan.forward_target.clone() else {
        return ForwardedWriteResolution::Reject {
            reason: ForwardedWriteRejectReason::MissingForwardTarget,
        };
    };

    if route.iter().any(|node| node == &target) {
        return ForwardedWriteResolution::Reject {
            reason: ForwardedWriteRejectReason::ForwardLoop { node: target },
        };
    }

    let mut next_envelope = envelope.clone();
    if !local_node.is_empty() {
        next_envelope.visited_nodes.push(local_node.to_string());
    }
    next_envelope.visited_nodes = normalize_route_nodes(&next_envelope.visited_nodes);
    next_envelope.hop_count = next_envelope.hop_count.saturating_add(1);

    ForwardedWriteResolution::ForwardToPrimary {
        target,
        envelope: next_envelope,
    }
}

fn select_owners(key: &[u8], nodes: &[String], replica_count: usize) -> Vec<String> {
    let normalized = normalize_nodes(nodes);
    if normalized.is_empty() || replica_count == 0 {
        return Vec::new();
    }

    let target_count = replica_count.min(normalized.len());
    let mut scored_nodes: Vec<(u64, String)> = normalized
        .iter()
        .map(|node| (rendezvous_score(key, node.as_bytes()), node.clone()))
        .collect();

    scored_nodes.sort_by(|left, right| {
        // Higher score first, then lexical node id for deterministic tie-breaks.
        right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1))
    });

    scored_nodes
        .into_iter()
        .take(target_count)
        .map(|(_, node)| node)
        .collect()
}

fn rendezvous_score(key: &[u8], node: &[u8]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update([0xff]);
    hasher.update(node);
    let digest = hasher.finalize();
    let mut score_bytes = [0u8; 8];
    score_bytes.copy_from_slice(&digest[0..8]);
    u64::from_be_bytes(score_bytes)
}

fn is_better_version_candidate(
    candidate: &(Option<String>, usize),
    best: &(Option<String>, usize),
) -> bool {
    if candidate.1 != best.1 {
        return candidate.1 > best.1;
    }

    match (&candidate.0, &best.0) {
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (Some(left), Some(right)) => left > right,
        (None, None) => false,
    }
}

fn build_rebalance_plan(
    previous_owners: Vec<String>,
    next_owners: Vec<String>,
) -> ObjectRebalancePlan {
    let previous_set: BTreeSet<String> = previous_owners.iter().cloned().collect();
    let next_set: BTreeSet<String> = next_owners.iter().cloned().collect();

    let retained_owners: Vec<String> = next_owners
        .iter()
        .filter(|owner| previous_set.contains(*owner))
        .cloned()
        .collect();
    let removed_owners: Vec<String> = previous_owners
        .iter()
        .filter(|owner| !next_set.contains(*owner))
        .cloned()
        .collect();
    let added_owners: Vec<String> = next_owners
        .iter()
        .filter(|owner| !previous_set.contains(*owner))
        .cloned()
        .collect();

    let transfers = added_owners
        .iter()
        .enumerate()
        .map(|(index, to)| RebalanceTransfer {
            from: removed_owners.get(index).cloned(),
            to: to.clone(),
        })
        .collect();

    ObjectRebalancePlan {
        previous_owners,
        next_owners,
        retained_owners,
        removed_owners,
        added_owners,
        transfers,
    }
}

fn object_write_plan_for_membership(
    key: &str,
    local_node_id: &str,
    membership: &[String],
    replica_count: usize,
) -> ObjectWritePlan {
    let local_node_id = local_node_id.trim();
    let owners = select_object_owners(key, membership, replica_count);
    let primary_owner = owners.first().cloned();
    let is_local_primary_owner =
        !local_node_id.is_empty() && primary_owner.as_deref() == Some(local_node_id);
    let is_local_replica_owner =
        !local_node_id.is_empty() && owners.iter().any(|owner| owner == local_node_id);
    let forward_target = if is_local_primary_owner || local_node_id.is_empty() {
        None
    } else {
        primary_owner.clone()
    };

    ObjectWritePlan {
        quorum_size: quorum_size(owners.len()),
        owners,
        primary_owner,
        forward_target,
        is_local_primary_owner,
        is_local_replica_owner,
    }
}

fn handoff_plan_from_rebalance(
    local_node: &str,
    previous: &PlacementViewState,
    next: &PlacementViewState,
    rebalance: ObjectRebalancePlan,
) -> PlacementHandoffPlan {
    let local_node = local_node.trim();
    let was_owner = rebalance
        .previous_owners
        .iter()
        .any(|owner| owner == local_node);
    let is_owner = rebalance
        .next_owners
        .iter()
        .any(|owner| owner == local_node);
    let local_role = match (was_owner, is_owner) {
        (true, true) => PlacementHandoffRole::StableOwner,
        (false, true) => PlacementHandoffRole::IncomingOwner,
        (true, false) => PlacementHandoffRole::OutgoingOwner,
        (false, false) => PlacementHandoffRole::Unowned,
    };
    let transfer_required = match local_role {
        PlacementHandoffRole::IncomingOwner => rebalance
            .transfers
            .iter()
            .any(|transfer| transfer.to == local_node),
        PlacementHandoffRole::OutgoingOwner => rebalance
            .transfers
            .iter()
            .any(|transfer| transfer.from.as_deref() == Some(local_node)),
        PlacementHandoffRole::StableOwner | PlacementHandoffRole::Unowned => false,
    };

    PlacementHandoffPlan {
        previous_epoch: previous.epoch,
        next_epoch: next.epoch,
        previous_view_id: previous.view_id.clone(),
        next_view_id: next.view_id.clone(),
        local_role,
        transfer_required,
        rebalance,
    }
}

fn normalize_route_nodes(nodes: &[String]) -> Vec<String> {
    let mut normalized = Vec::<String>::new();
    let mut seen = BTreeSet::<String>::new();
    for node in nodes {
        let node = node.trim();
        if node.is_empty() {
            continue;
        }
        let owned = node.to_string();
        if seen.insert(owned.clone()) {
            normalized.push(owned);
        }
    }
    normalized
}

fn normalize_observations(observations: &[ReplicaObservation]) -> BTreeMap<String, Option<String>> {
    let mut normalized = BTreeMap::<String, Option<String>>::new();
    for observation in observations {
        let node = observation.node.trim();
        if node.is_empty() {
            continue;
        }

        let version = observation
            .version
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        normalized.insert(node.to_string(), version);
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_nodes() -> Vec<String> {
        vec![
            "node-c:9000".to_string(),
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
            "node-b:9000".to_string(),
        ]
    }

    #[test]
    fn normalize_nodes_sorts_and_deduplicates() {
        assert_eq!(
            normalize_nodes(&test_nodes()),
            vec![
                "node-a:9000".to_string(),
                "node-b:9000".to_string(),
                "node-c:9000".to_string(),
            ]
        );
    }

    #[test]
    fn membership_fingerprint_is_order_insensitive() {
        let a = vec![
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
            "node-c:9000".to_string(),
        ];
        let b = vec![
            "node-c:9000".to_string(),
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
        ];
        assert_eq!(membership_fingerprint(&a), membership_fingerprint(&b));
    }

    #[test]
    fn membership_with_self_adds_self_and_normalizes() {
        let peers = vec![
            "node-c:9000".to_string(),
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
            "node-b:9000".to_string(),
        ];

        assert_eq!(
            membership_with_self("node-self:9000", &peers),
            vec![
                "node-a:9000".to_string(),
                "node-b:9000".to_string(),
                "node-c:9000".to_string(),
                "node-self:9000".to_string(),
            ]
        );
    }

    #[test]
    fn membership_view_id_with_self_is_order_insensitive() {
        let peers_a = vec![
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
            "node-c:9000".to_string(),
        ];
        let peers_b = vec![
            "node-c:9000".to_string(),
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
        ];

        assert_eq!(
            membership_view_id_with_self("node-self:9000", &peers_a),
            membership_view_id_with_self("node-self:9000", &peers_b)
        );
    }

    #[test]
    fn quorum_size_matches_majority_contract() {
        assert_eq!(quorum_size(0), 0);
        assert_eq!(quorum_size(1), 1);
        assert_eq!(quorum_size(2), 2);
        assert_eq!(quorum_size(3), 2);
        assert_eq!(quorum_size(4), 3);
    }

    #[test]
    fn select_object_owners_is_deterministic_and_unique() {
        let owners_a = select_object_owners("videos/2026/launch.mp4", &test_nodes(), 2);
        let owners_b = select_object_owners("videos/2026/launch.mp4", &test_nodes(), 2);
        assert_eq!(owners_a, owners_b);
        assert_eq!(owners_a.len(), 2);
        assert_ne!(owners_a[0], owners_a[1]);
    }

    #[test]
    fn select_object_owners_clamps_replica_count_to_membership_size() {
        let owners = select_object_owners("docs/guide.pdf", &test_nodes(), 8);
        assert_eq!(owners.len(), 3);
    }

    #[test]
    fn primary_owner_helpers_match_owner_selection() {
        let nodes = test_nodes();
        let key = "docs/guide.pdf";
        assert_eq!(
            primary_object_owner(key, &nodes),
            select_object_owners(key, &nodes, 1).into_iter().next()
        );
        assert_eq!(
            primary_chunk_owner(key, 4, &nodes),
            select_chunk_owners(key, 4, &nodes, 1).into_iter().next()
        );
    }

    #[test]
    fn select_object_owners_with_self_matches_explicit_membership_selection() {
        let peers = vec![
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
            "node-c:9000".to_string(),
        ];
        let with_self =
            select_object_owners_with_self("docs/guide.pdf", "node-self:9000", &peers, 3);
        let explicit = select_object_owners(
            "docs/guide.pdf",
            &membership_with_self("node-self:9000", &peers),
            3,
        );
        assert_eq!(with_self, explicit);
    }

    #[test]
    fn forward_target_helpers_match_primary_ownership() {
        let peers = vec![
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
            "node-c:9000".to_string(),
        ];
        let local = "node-self:9000";
        let key = "logs/2026-03-01/system.log";

        let object_primary = primary_object_owner_with_self(key, local, &peers)
            .expect("primary object owner should exist");
        assert_eq!(
            object_forward_target_with_self(key, local, &peers),
            if object_primary == local {
                None
            } else {
                Some(object_primary)
            }
        );

        let chunk_primary = primary_chunk_owner_with_self(key, 2, local, &peers)
            .expect("primary chunk owner should exist");
        assert_eq!(
            chunk_forward_target_with_self(key, 2, local, &peers),
            if chunk_primary == local {
                None
            } else {
                Some(chunk_primary)
            }
        );

        assert_eq!(object_forward_target_with_self(key, "  ", &peers), None);
        assert_eq!(chunk_forward_target_with_self(key, 2, "", &peers), None);
    }

    #[test]
    fn object_write_plan_with_self_shapes_forwarding_and_quorum() {
        let peers = vec![
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
            "node-c:9000".to_string(),
        ];
        let local = "node-self:9000";
        let key = "logs/2026-03-02/system.log";

        let plan = object_write_plan_with_self(key, local, &peers, 3);
        assert_eq!(plan.owners.len(), 3);
        assert_eq!(plan.primary_owner, plan.owners.first().cloned());
        assert_eq!(plan.quorum_size, quorum_size(plan.owners.len()));
        assert_eq!(
            plan.is_local_primary_owner,
            plan.primary_owner.as_deref() == Some(local)
        );
        assert_eq!(
            plan.is_local_replica_owner,
            plan.owners.iter().any(|owner| owner == local)
        );
        if plan.is_local_primary_owner {
            assert_eq!(plan.forward_target, None);
        } else {
            assert_eq!(plan.forward_target, plan.primary_owner);
        }
    }

    #[test]
    fn object_write_plan_with_self_handles_empty_local_node_and_zero_replication() {
        let peers = vec![
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
            "node-c:9000".to_string(),
        ];
        let key = "logs/2026-03-02/system.log";

        let empty_local_plan = object_write_plan_with_self(key, "   ", &peers, 2);
        assert_eq!(empty_local_plan.owners.len(), 2);
        assert!(!empty_local_plan.is_local_primary_owner);
        assert!(!empty_local_plan.is_local_replica_owner);
        assert_eq!(empty_local_plan.forward_target, None);
        assert_eq!(empty_local_plan.quorum_size, 2);

        let zero_replica_plan = object_write_plan_with_self(key, "node-a:9000", &peers, 0);
        assert_eq!(zero_replica_plan.owners, Vec::<String>::new());
        assert_eq!(zero_replica_plan.primary_owner, None);
        assert_eq!(zero_replica_plan.forward_target, None);
        assert!(!zero_replica_plan.is_local_primary_owner);
        assert!(!zero_replica_plan.is_local_replica_owner);
        assert_eq!(zero_replica_plan.quorum_size, 0);
    }

    #[test]
    fn object_write_quorum_outcome_reaches_quorum_on_majority_ack() {
        let plan = ObjectWritePlan {
            owners: vec![
                "node-a:9000".to_string(),
                "node-b:9000".to_string(),
                "node-c:9000".to_string(),
            ],
            primary_owner: Some("node-a:9000".to_string()),
            forward_target: None,
            is_local_primary_owner: true,
            is_local_replica_owner: true,
            quorum_size: 2,
        };
        let outcome = object_write_quorum_outcome(
            &plan,
            &[
                WriteAckObservation {
                    node: "node-a:9000".to_string(),
                    acked: true,
                },
                WriteAckObservation {
                    node: "node-b:9000".to_string(),
                    acked: true,
                },
                WriteAckObservation {
                    node: "node-c:9000".to_string(),
                    acked: false,
                },
            ],
        );

        assert_eq!(outcome.ack_count, 2);
        assert_eq!(outcome.quorum_size, 2);
        assert!(outcome.quorum_reached);
        assert_eq!(
            outcome.acked_nodes,
            vec!["node-a:9000".to_string(), "node-b:9000".to_string()]
        );
        assert_eq!(outcome.rejected_nodes, vec!["node-c:9000".to_string()]);
        assert_eq!(outcome.pending_nodes, Vec::<String>::new());
    }

    #[test]
    fn object_write_quorum_outcome_collapses_duplicates_and_ignores_unknown_nodes() {
        let plan = ObjectWritePlan {
            owners: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
            primary_owner: Some("node-a:9000".to_string()),
            forward_target: None,
            is_local_primary_owner: true,
            is_local_replica_owner: true,
            quorum_size: 2,
        };
        let outcome = object_write_quorum_outcome(
            &plan,
            &[
                WriteAckObservation {
                    node: "node-a:9000".to_string(),
                    acked: false,
                },
                WriteAckObservation {
                    node: "node-a:9000".to_string(),
                    acked: true,
                },
                WriteAckObservation {
                    node: "node-c:9000".to_string(),
                    acked: true,
                },
            ],
        );

        assert_eq!(outcome.acked_nodes, vec!["node-a:9000".to_string()]);
        assert_eq!(outcome.rejected_nodes, Vec::<String>::new());
        assert_eq!(outcome.pending_nodes, vec!["node-b:9000".to_string()]);
        assert_eq!(outcome.ack_count, 1);
        assert!(!outcome.quorum_reached);
    }

    #[test]
    fn object_write_quorum_outcome_does_not_reach_quorum_for_empty_plan() {
        let plan = ObjectWritePlan {
            owners: Vec::new(),
            primary_owner: None,
            forward_target: None,
            is_local_primary_owner: false,
            is_local_replica_owner: false,
            quorum_size: 0,
        };
        let outcome = object_write_quorum_outcome(&plan, &[]);
        assert_eq!(outcome.ack_count, 0);
        assert_eq!(outcome.quorum_size, 0);
        assert!(!outcome.quorum_reached);
    }

    #[test]
    fn object_read_repair_plan_prefers_majority_and_tracks_missing_and_stale() {
        let observations = vec![
            ReplicaObservation {
                node: "node-a:9000".to_string(),
                version: Some("v2".to_string()),
            },
            ReplicaObservation {
                node: "node-b:9000".to_string(),
                version: Some("v2".to_string()),
            },
            ReplicaObservation {
                node: "node-c:9000".to_string(),
                version: Some("v1".to_string()),
            },
            ReplicaObservation {
                node: "node-d:9000".to_string(),
                version: None,
            },
        ];

        let plan = object_read_repair_plan(&observations, 4);
        assert_eq!(plan.replica_count, 4);
        assert_eq!(plan.quorum_size, 3);
        assert_eq!(plan.chosen_version.as_deref(), Some("v2"));
        assert_eq!(plan.chosen_count, 2);
        assert!(!plan.quorum_reached);
        assert_eq!(plan.stale_nodes, vec!["node-c:9000".to_string()]);
        assert_eq!(plan.missing_nodes, vec!["node-d:9000".to_string()]);
    }

    #[test]
    fn object_read_repair_plan_tie_breakers_are_deterministic() {
        let tie_some_vs_some = vec![
            ReplicaObservation {
                node: "node-a:9000".to_string(),
                version: Some("v1".to_string()),
            },
            ReplicaObservation {
                node: "node-b:9000".to_string(),
                version: Some("v2".to_string()),
            },
        ];
        let plan = object_read_repair_plan(&tie_some_vs_some, 2);
        assert_eq!(plan.chosen_version.as_deref(), Some("v2"));

        let tie_some_vs_none = vec![
            ReplicaObservation {
                node: "node-a:9000".to_string(),
                version: None,
            },
            ReplicaObservation {
                node: "node-b:9000".to_string(),
                version: Some("v1".to_string()),
            },
        ];
        let plan = object_read_repair_plan(&tie_some_vs_none, 2);
        assert_eq!(plan.chosen_version.as_deref(), Some("v1"));
        assert_eq!(plan.missing_nodes, vec!["node-a:9000".to_string()]);
    }

    #[test]
    fn object_read_repair_plan_handles_majority_missing_and_duplicate_nodes() {
        let observations = vec![
            ReplicaObservation {
                node: "node-a:9000".to_string(),
                version: Some("v3".to_string()),
            },
            ReplicaObservation {
                node: "node-b:9000".to_string(),
                version: None,
            },
            ReplicaObservation {
                node: "node-b:9000".to_string(),
                version: None,
            },
            ReplicaObservation {
                node: "node-c:9000".to_string(),
                version: None,
            },
        ];

        let plan = object_read_repair_plan(&observations, 3);
        assert_eq!(plan.chosen_version, None);
        assert_eq!(plan.chosen_count, 2);
        assert!(plan.quorum_reached);
        assert_eq!(plan.stale_nodes, vec!["node-a:9000".to_string()]);
        assert_eq!(plan.missing_nodes, Vec::<String>::new());
    }

    #[test]
    fn select_object_owners_empty_inputs_return_empty() {
        assert!(select_object_owners("x", &[], 1).is_empty());
        assert!(select_object_owners("x", &test_nodes(), 0).is_empty());
    }

    #[test]
    fn select_chunk_owners_is_deterministic_per_chunk() {
        let chunk0_a = select_chunk_owners("archive.tar", 0, &test_nodes(), 2);
        let chunk0_b = select_chunk_owners("archive.tar", 0, &test_nodes(), 2);
        let chunk1_a = select_chunk_owners("archive.tar", 1, &test_nodes(), 2);
        let chunk1_b = select_chunk_owners("archive.tar", 1, &test_nodes(), 2);

        assert_eq!(chunk0_a, chunk0_b);
        assert_eq!(chunk1_a, chunk1_b);
        assert_eq!(chunk0_a.len(), 2);
        assert_eq!(chunk1_a.len(), 2);
    }

    #[test]
    fn is_local_owner_helpers_match_owner_sets() {
        let peers = vec![
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
            "node-c:9000".to_string(),
        ];
        let node = "node-self:9000";

        let object_owners = select_object_owners_with_self("archive.tar", node, &peers, 2);
        assert_eq!(
            is_local_object_owner("archive.tar", node, &peers, 2),
            object_owners.iter().any(|owner| owner == node)
        );

        let chunk_owners = select_chunk_owners_with_self("archive.tar", 1, node, &peers, 2);
        assert_eq!(
            is_local_chunk_owner("archive.tar", 1, node, &peers, 2),
            chunk_owners.iter().any(|owner| owner == node)
        );
    }

    #[test]
    fn is_local_owner_helpers_return_false_for_empty_node_or_zero_replication() {
        let peers = vec!["node-a:9000".to_string()];
        assert!(!is_local_object_owner("docs/guide.pdf", "", &peers, 1));
        assert!(!is_local_chunk_owner("docs/guide.pdf", 0, "", &peers, 1));
        assert!(!is_local_object_owner(
            "docs/guide.pdf",
            "node-a:9000",
            &peers,
            0
        ));
        assert!(!is_local_chunk_owner(
            "docs/guide.pdf",
            0,
            "node-a:9000",
            &peers,
            0
        ));
    }

    #[test]
    fn rendezvous_primary_owner_monotonic_when_joining_node() {
        let old_nodes = vec![
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
            "node-c:9000".to_string(),
        ];
        let joining_node = "node-d:9000".to_string();
        let mut new_nodes = old_nodes.clone();
        new_nodes.push(joining_node.clone());

        let mut changed = 0usize;
        for i in 0..1024 {
            let key = format!("objects/{i}.bin");
            let old_owner = primary_object_owner(&key, &old_nodes).expect("old owner should exist");
            let new_owner = primary_object_owner(&key, &new_nodes).expect("new owner should exist");
            if old_owner != new_owner {
                changed += 1;
                assert_eq!(new_owner, joining_node);
            }
        }

        assert!(
            changed > 0,
            "expected at least one key to move to joining node"
        );
    }

    #[test]
    fn rendezvous_primary_owner_stable_when_removing_non_owner() {
        let full_nodes = vec![
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
            "node-c:9000".to_string(),
            "node-d:9000".to_string(),
        ];
        let reduced_nodes = vec![
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
            "node-c:9000".to_string(),
        ];
        let removed_node = "node-d:9000";

        let (candidate_key, old_owner) = (0..4096)
            .find_map(|i| {
                let key = format!("objects/{i}.bin");
                let owner = primary_object_owner(&key, &full_nodes)?;
                if owner != removed_node {
                    Some((key, owner))
                } else {
                    None
                }
            })
            .expect("should find key whose primary owner is not the removed node");

        let new_owner =
            primary_object_owner(&candidate_key, &reduced_nodes).expect("new owner should exist");
        assert_eq!(new_owner, old_owner);
    }

    #[test]
    fn chunk_score_changes_with_chunk_index() {
        let mut chunk0 = b"archive.tar".to_vec();
        chunk0.push(0);
        chunk0.extend_from_slice(&0u32.to_be_bytes());

        let mut chunk1 = b"archive.tar".to_vec();
        chunk1.push(0);
        chunk1.extend_from_slice(&1u32.to_be_bytes());

        let node = b"node-a:9000";
        assert_ne!(
            rendezvous_score(&chunk0, node),
            rendezvous_score(&chunk1, node)
        );
    }

    #[test]
    fn object_rebalance_plan_is_stable_for_equivalent_membership_views() {
        let previous_nodes = vec![
            "node-c:9000".to_string(),
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
            "node-b:9000".to_string(),
        ];
        let next_nodes = vec![
            "node-b:9000".to_string(),
            "node-a:9000".to_string(),
            "node-c:9000".to_string(),
        ];

        let plan = object_rebalance_plan(
            "objects/reports/2026-03-02.json",
            &previous_nodes,
            &next_nodes,
            2,
        );
        assert_eq!(plan.previous_owners, plan.next_owners);
        assert_eq!(plan.retained_owners, plan.next_owners);
        assert_eq!(plan.added_owners, Vec::<String>::new());
        assert_eq!(plan.removed_owners, Vec::<String>::new());
        assert_eq!(plan.transfers, Vec::<RebalanceTransfer>::new());
    }

    #[test]
    fn object_rebalance_plan_on_join_transfers_to_joining_owner() {
        let previous_nodes = vec![
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
            "node-c:9000".to_string(),
        ];
        let joining_node = "node-d:9000".to_string();
        let mut next_nodes = previous_nodes.clone();
        next_nodes.push(joining_node.clone());

        let plan = (0..4096)
            .find_map(|i| {
                let key = format!("objects/{i}.bin");
                let candidate = object_rebalance_plan(&key, &previous_nodes, &next_nodes, 2);
                if candidate.added_owners.contains(&joining_node) {
                    Some(candidate)
                } else {
                    None
                }
            })
            .expect("expected at least one key to move ownership to joining node");

        assert!(plan.added_owners.iter().all(|owner| owner == &joining_node));
        assert_eq!(plan.added_owners.len(), plan.removed_owners.len());
        assert_eq!(plan.transfers.len(), plan.added_owners.len());
        assert!(
            plan.transfers
                .iter()
                .all(|transfer| transfer.from.is_some() && transfer.to == joining_node)
        );
    }

    #[test]
    fn object_rebalance_plan_on_leave_marks_removed_owner() {
        let leaving_node = "node-d:9000".to_string();
        let previous_nodes = vec![
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
            "node-c:9000".to_string(),
            leaving_node.clone(),
        ];
        let next_nodes = vec![
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
            "node-c:9000".to_string(),
        ];

        let plan = (0..4096)
            .find_map(|i| {
                let key = format!("objects/{i}.bin");
                let candidate = object_rebalance_plan(&key, &previous_nodes, &next_nodes, 2);
                if candidate.removed_owners.contains(&leaving_node) {
                    Some(candidate)
                } else {
                    None
                }
            })
            .expect("expected at least one key to require ownership replacement for leaving node");

        assert!(plan.removed_owners.contains(&leaving_node));
        assert_eq!(plan.added_owners.len(), plan.removed_owners.len());
        assert_eq!(plan.transfers.len(), plan.added_owners.len());
        assert!(
            plan.transfers
                .iter()
                .any(|transfer| transfer.from.as_deref() == Some(leaving_node.as_str()))
        );
    }

    #[test]
    fn object_rebalance_plan_bootstrap_marks_empty_sources() {
        let previous_nodes = Vec::<String>::new();
        let next_nodes = vec![
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
            "node-c:9000".to_string(),
        ];
        let plan = object_rebalance_plan("objects/bootstrap.bin", &previous_nodes, &next_nodes, 2);

        assert_eq!(plan.previous_owners, Vec::<String>::new());
        assert_eq!(plan.next_owners.len(), 2);
        assert_eq!(plan.retained_owners, Vec::<String>::new());
        assert_eq!(plan.removed_owners, Vec::<String>::new());
        assert_eq!(plan.added_owners, plan.next_owners);
        assert!(
            plan.transfers
                .iter()
                .all(|transfer| transfer.from.is_none())
        );
    }

    #[test]
    fn chunk_rebalance_plan_matches_chunk_owner_selection() {
        let previous_nodes = vec![
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
            "node-c:9000".to_string(),
        ];
        let next_nodes = vec![
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
            "node-c:9000".to_string(),
            "node-d:9000".to_string(),
        ];

        let plan = chunk_rebalance_plan("objects/chunked.bin", 3, &previous_nodes, &next_nodes, 2);
        assert_eq!(
            plan.previous_owners,
            select_chunk_owners("objects/chunked.bin", 3, &previous_nodes, 2)
        );
        assert_eq!(
            plan.next_owners,
            select_chunk_owners("objects/chunked.bin", 3, &next_nodes, 2)
        );
        assert_eq!(plan.transfers.len(), plan.added_owners.len());
    }

    #[test]
    fn object_read_repair_execution_plan_upserts_when_version_quorum_is_reached() {
        let observations = vec![
            ReplicaObservation {
                node: "node-a:9000".to_string(),
                version: Some("v2".to_string()),
            },
            ReplicaObservation {
                node: "node-b:9000".to_string(),
                version: Some("v2".to_string()),
            },
            ReplicaObservation {
                node: "node-c:9000".to_string(),
                version: Some("v1".to_string()),
            },
            ReplicaObservation {
                node: "node-d:9000".to_string(),
                version: None,
            },
        ];

        let execution = object_read_repair_execution_plan(&observations, 3);
        assert!(execution.plan.quorum_reached);
        assert_eq!(execution.plan.chosen_version.as_deref(), Some("v2"));
        assert_eq!(
            execution.actions,
            vec![
                ReadRepairAction::UpsertVersion {
                    node: "node-c:9000".to_string(),
                    version: "v2".to_string(),
                },
                ReadRepairAction::UpsertVersion {
                    node: "node-d:9000".to_string(),
                    version: "v2".to_string(),
                },
            ]
        );
    }

    #[test]
    fn object_read_repair_execution_plan_deletes_replicas_when_missing_quorum_is_reached() {
        let observations = vec![
            ReplicaObservation {
                node: "node-a:9000".to_string(),
                version: Some("v3".to_string()),
            },
            ReplicaObservation {
                node: "node-b:9000".to_string(),
                version: None,
            },
            ReplicaObservation {
                node: "node-c:9000".to_string(),
                version: None,
            },
        ];

        let execution = object_read_repair_execution_plan(&observations, 3);
        assert!(execution.plan.quorum_reached);
        assert_eq!(execution.plan.chosen_version, None);
        assert_eq!(
            execution.actions,
            vec![ReadRepairAction::DeleteReplica {
                node: "node-a:9000".to_string(),
            }]
        );
    }

    #[test]
    fn object_read_repair_execution_plan_skips_actions_without_quorum() {
        let observations = vec![
            ReplicaObservation {
                node: "node-a:9000".to_string(),
                version: Some("v1".to_string()),
            },
            ReplicaObservation {
                node: "node-b:9000".to_string(),
                version: Some("v2".to_string()),
            },
            ReplicaObservation {
                node: "node-c:9000".to_string(),
                version: None,
            },
        ];

        let execution = object_read_repair_execution_plan(&observations, 3);
        assert!(!execution.plan.quorum_reached);
        assert_eq!(execution.actions, Vec::<ReadRepairAction>::new());
    }

    #[test]
    fn object_read_repair_execution_plan_primary_authoritative_repairs_without_quorum() {
        let observations = vec![
            ReplicaObservation {
                node: "node-a:9000".to_string(),
                version: Some("v1".to_string()),
            },
            ReplicaObservation {
                node: "node-b:9000".to_string(),
                version: None,
            },
        ];

        let execution = object_read_repair_execution_plan_with_policy(
            &observations,
            2,
            ReadRepairExecutionPolicy::PrimaryAuthoritative,
        );
        assert!(!execution.plan.quorum_reached);
        assert_eq!(
            execution.actions,
            vec![ReadRepairAction::UpsertVersion {
                node: "node-b:9000".to_string(),
                version: "v1".to_string(),
            }]
        );
    }

    #[test]
    fn placement_view_state_from_membership_is_deterministic() {
        let peers_a = vec![
            "node-b:9000".to_string(),
            "node-c:9000".to_string(),
            "node-a:9000".to_string(),
        ];
        let peers_b = vec![
            "node-c:9000".to_string(),
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
        ];

        let state_a = PlacementViewState::from_membership(7, "node-self:9000", &peers_a);
        let state_b = PlacementViewState::from_membership(7, "node-self:9000", &peers_b);
        assert_eq!(state_a.epoch, 7);
        assert_eq!(state_a.members, state_b.members);
        assert_eq!(state_a.view_id, state_b.view_id);
    }

    #[test]
    fn compare_forward_epoch_classifies_relative_epochs() {
        assert_eq!(compare_forward_epoch(5, 5), ForwardEpochStatus::Current);
        assert_eq!(compare_forward_epoch(5, 4), ForwardEpochStatus::Stale);
        assert_eq!(compare_forward_epoch(5, 6), ForwardEpochStatus::Future);
    }

    #[test]
    fn handoff_plan_marks_incoming_and_transfer_required_for_join() {
        let previous_peers = vec!["node-b:9000".to_string(), "node-c:9000".to_string()];
        let previous = PlacementViewState::from_membership(3, "node-a:9000", &previous_peers);
        let next_peers = vec![
            "node-b:9000".to_string(),
            "node-c:9000".to_string(),
            "node-d:9000".to_string(),
        ];
        let next = PlacementViewState::from_membership(4, "node-a:9000", &next_peers);

        let plan = (0..4096)
            .find_map(|idx| {
                let key = format!("handoff/incoming-{idx}.txt");
                let candidate =
                    object_handoff_plan_for_transition(&key, "node-d:9000", &previous, &next, 2);
                if candidate.local_role == PlacementHandoffRole::IncomingOwner {
                    Some(candidate)
                } else {
                    None
                }
            })
            .expect("expected at least one key with incoming ownership");

        assert_eq!(plan.previous_epoch, 3);
        assert_eq!(plan.next_epoch, 4);
        assert_eq!(plan.local_role, PlacementHandoffRole::IncomingOwner);
        assert!(plan.transfer_required);
    }

    #[test]
    fn handoff_plan_marks_outgoing_for_leave_transition() {
        let previous_peers = vec![
            "node-b:9000".to_string(),
            "node-c:9000".to_string(),
            "node-d:9000".to_string(),
        ];
        let previous = PlacementViewState::from_membership(9, "node-a:9000", &previous_peers);
        let next_peers = vec!["node-b:9000".to_string(), "node-c:9000".to_string()];
        let next = PlacementViewState::from_membership(10, "node-a:9000", &next_peers);

        let plan = (0..4096)
            .find_map(|idx| {
                let key = format!("handoff/outgoing-{idx}.txt");
                let candidate =
                    object_handoff_plan_for_transition(&key, "node-d:9000", &previous, &next, 2);
                if candidate.local_role == PlacementHandoffRole::OutgoingOwner {
                    Some(candidate)
                } else {
                    None
                }
            })
            .expect("expected at least one key with outgoing ownership");

        assert_eq!(plan.local_role, PlacementHandoffRole::OutgoingOwner);
        assert!(plan.transfer_required);
    }

    #[test]
    fn resolve_forwarded_write_rejects_epoch_and_view_mismatch() {
        let peers = vec!["node-b:9000".to_string(), "node-c:9000".to_string()];
        let placement = PlacementViewState::from_membership(12, "node-a:9000", &peers);
        let mut envelope = ForwardedWriteEnvelope::new(
            ForwardedWriteOperation::PutObject,
            "bucket-a",
            "docs/file.txt",
            "node-z:9000",
            "client-1",
            "idem-1",
            &placement,
        );
        envelope.placement_epoch = 11;
        assert_eq!(
            resolve_forwarded_write_envelope(&envelope, "node-a:9000", &placement, 2),
            ForwardedWriteResolution::Reject {
                reason: ForwardedWriteRejectReason::StaleEpoch {
                    local_epoch: 12,
                    request_epoch: 11,
                },
            }
        );

        envelope.placement_epoch = 12;
        envelope.placement_view_id = "wrong-view".to_string();
        assert_eq!(
            resolve_forwarded_write_envelope(&envelope, "node-a:9000", &placement, 2),
            ForwardedWriteResolution::Reject {
                reason: ForwardedWriteRejectReason::ViewIdMismatch {
                    local_view_id: placement.view_id.clone(),
                    request_view_id: "wrong-view".to_string(),
                },
            }
        );
    }

    #[test]
    fn resolve_forwarded_write_rejects_loop_and_hop_limit() {
        let peers = vec!["node-b:9000".to_string(), "node-c:9000".to_string()];
        let placement = PlacementViewState::from_membership(4, "node-a:9000", &peers);
        let mut envelope = ForwardedWriteEnvelope::new(
            ForwardedWriteOperation::DeleteObject,
            "bucket-a",
            "docs/file.txt",
            "node-z:9000",
            "client-1",
            "idem-2",
            &placement,
        );
        envelope.visited_nodes = vec!["node-a:9000".to_string()];
        assert_eq!(
            resolve_forwarded_write_envelope(&envelope, "node-a:9000", &placement, 2),
            ForwardedWriteResolution::Reject {
                reason: ForwardedWriteRejectReason::ForwardLoop {
                    node: "node-a:9000".to_string(),
                },
            }
        );

        envelope.visited_nodes = Vec::new();
        envelope.hop_count = 8;
        envelope.max_hops = 8;
        assert_eq!(
            resolve_forwarded_write_envelope(&envelope, "node-a:9000", &placement, 2),
            ForwardedWriteResolution::Reject {
                reason: ForwardedWriteRejectReason::HopLimitExceeded {
                    hop_count: 8,
                    max_hops: 8,
                },
            }
        );
    }

    #[test]
    fn resolve_forwarded_write_forwards_to_primary_with_updated_envelope() {
        let peers = vec!["node-b:9000".to_string(), "node-c:9000".to_string()];
        let placement = PlacementViewState::from_membership(21, "node-a:9000", &peers);

        let (key, expected_target) = (0..4096)
            .find_map(|idx| {
                let key = format!("forward/non-owner-{idx}.txt");
                let plan = placement.object_write_plan(&key, 2);
                match (plan.is_local_primary_owner, plan.forward_target) {
                    (false, Some(target)) => Some((key, target)),
                    _ => None,
                }
            })
            .expect("expected at least one non-primary key");

        let envelope = ForwardedWriteEnvelope::new(
            ForwardedWriteOperation::PutObject,
            "bucket-a",
            &key,
            "node-z:9000",
            "client-1",
            "idem-3",
            &placement,
        );

        let resolved = resolve_forwarded_write_envelope(&envelope, "node-a:9000", &placement, 2);
        match resolved {
            ForwardedWriteResolution::ForwardToPrimary { target, envelope } => {
                assert_eq!(target, expected_target);
                assert_eq!(envelope.hop_count, 1);
                assert_eq!(envelope.visited_nodes, vec!["node-a:9000".to_string()]);
            }
            other => panic!("expected forward resolution, got {other:?}"),
        }
    }

    #[test]
    fn resolve_forwarded_write_executes_locally_when_primary() {
        let peers = vec!["node-b:9000".to_string(), "node-c:9000".to_string()];
        let placement = PlacementViewState::from_membership(21, "node-a:9000", &peers);

        let key = (0..4096)
            .map(|idx| format!("forward/primary-{idx}.txt"))
            .find(|candidate| {
                placement
                    .object_write_plan(candidate, 2)
                    .is_local_primary_owner
            })
            .expect("expected at least one local-primary key");
        let primary_owner = placement
            .object_write_plan(&key, 2)
            .primary_owner
            .expect("primary owner should exist");

        let envelope = ForwardedWriteEnvelope::new(
            ForwardedWriteOperation::CopyObject,
            "bucket-a",
            &key,
            "node-z:9000",
            "client-1",
            "idem-4",
            &placement,
        );

        assert_eq!(
            resolve_forwarded_write_envelope(&envelope, "node-a:9000", &placement, 2),
            ForwardedWriteResolution::ExecuteLocal {
                primary_owner,
                quorum_size: 2,
            }
        );
    }

    #[test]
    fn resolve_forwarded_replica_write_executes_locally_when_node_is_replica_owner() {
        let peers = vec!["node-b:9000".to_string(), "node-c:9000".to_string()];
        let placement = PlacementViewState::from_membership(21, "node-a:9000", &peers);

        let key = (0..4096)
            .map(|idx| format!("forward/replica-owner-{idx}.txt"))
            .find(|candidate| {
                let plan = placement.object_write_plan(candidate, 2);
                plan.is_local_replica_owner && !plan.is_local_primary_owner
            })
            .expect("expected at least one local-replica key");
        let primary_owner = placement
            .object_write_plan(&key, 2)
            .primary_owner
            .expect("primary owner should exist");

        let envelope = ForwardedWriteEnvelope::new(
            ForwardedWriteOperation::ReplicatePutObject,
            "bucket-a",
            &key,
            "node-z:9000",
            "client-1",
            "idem-5",
            &placement,
        );

        assert_eq!(
            resolve_forwarded_write_envelope(&envelope, "node-a:9000", &placement, 2),
            ForwardedWriteResolution::ExecuteLocal {
                primary_owner,
                quorum_size: 2,
            }
        );
    }

    #[test]
    fn resolve_forwarded_replica_write_rejects_when_node_is_not_replica_owner() {
        let peers = vec!["node-b:9000".to_string(), "node-c:9000".to_string()];
        let placement = PlacementViewState::from_membership(21, "node-a:9000", &peers);
        let key = (0..4096)
            .map(|idx| format!("forward/replica-miss-{idx}.txt"))
            .find(|candidate| {
                let plan = placement.object_write_plan(candidate, 2);
                !plan.is_local_replica_owner
            })
            .expect("expected at least one non-owner key");
        let envelope = ForwardedWriteEnvelope::new(
            ForwardedWriteOperation::ReplicatePutObject,
            "bucket-a",
            &key,
            "node-z:9000",
            "client-1",
            "idem-6",
            &placement,
        );

        assert_eq!(
            resolve_forwarded_write_envelope(&envelope, "node-a:9000", &placement, 2),
            ForwardedWriteResolution::Reject {
                reason: ForwardedWriteRejectReason::MissingForwardTarget,
            }
        );
    }

    #[test]
    fn resolve_forwarded_replica_delete_executes_locally_when_node_is_replica_owner() {
        let peers = vec!["node-b:9000".to_string(), "node-c:9000".to_string()];
        let placement = PlacementViewState::from_membership(21, "node-a:9000", &peers);
        let key = (0..4096)
            .map(|idx| format!("forward/replica-delete-{idx}.txt"))
            .find(|candidate| {
                let plan = placement.object_write_plan(candidate, 2);
                plan.is_local_replica_owner && !plan.is_local_primary_owner
            })
            .expect("expected at least one local-replica key");
        let primary_owner = placement
            .object_write_plan(&key, 2)
            .primary_owner
            .expect("primary owner should exist");
        let envelope = ForwardedWriteEnvelope::new(
            ForwardedWriteOperation::ReplicateDeleteObject,
            "bucket-a",
            &key,
            "node-z:9000",
            "client-1",
            "idem-delete-1",
            &placement,
        );

        assert_eq!(
            resolve_forwarded_write_envelope(&envelope, "node-a:9000", &placement, 2),
            ForwardedWriteResolution::ExecuteLocal {
                primary_owner,
                quorum_size: 2,
            }
        );
    }

    #[test]
    fn resolve_forwarded_replica_head_executes_locally_when_node_is_replica_owner() {
        let peers = vec!["node-b:9000".to_string(), "node-c:9000".to_string()];
        let placement = PlacementViewState::from_membership(21, "node-a:9000", &peers);
        let key = (0..4096)
            .map(|idx| format!("forward/replica-head-{idx}.txt"))
            .find(|candidate| {
                let plan = placement.object_write_plan(candidate, 2);
                plan.is_local_replica_owner && !plan.is_local_primary_owner
            })
            .expect("expected at least one local-replica key");
        let primary_owner = placement
            .object_write_plan(&key, 2)
            .primary_owner
            .expect("primary owner should exist");
        let envelope = ForwardedWriteEnvelope::new(
            ForwardedWriteOperation::ReplicateHeadObject,
            "bucket-a",
            &key,
            "node-z:9000",
            "client-1",
            "idem-head-1",
            &placement,
        );

        assert_eq!(
            resolve_forwarded_write_envelope(&envelope, "node-a:9000", &placement, 2),
            ForwardedWriteResolution::ExecuteLocal {
                primary_owner,
                quorum_size: 2,
            }
        );
    }
}
