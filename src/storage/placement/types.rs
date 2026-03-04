use super::*;

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
pub enum LocalRebalanceAction {
    Receive { from: Option<String>, to: String },
    Send { from: String, to: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RebalanceObjectScope {
    Object,
    Chunk { chunk_index: u32 },
}

impl RebalanceObjectScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Object => "object",
            Self::Chunk { .. } => "chunk",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRebalanceTransferState {
    pub from: Option<String>,
    pub to: String,
    pub attempts: u32,
    pub completed: bool,
    pub last_error: Option<String>,
    pub next_retry_at_unix_ms: Option<u64>,
}

impl PendingRebalanceTransferState {
    fn pending(from: Option<&str>, to: &str) -> Option<Self> {
        let from = from
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let to = to.trim();
        if to.is_empty() {
            return None;
        }
        if from.as_deref() == Some(to) {
            return None;
        }
        Some(Self {
            from,
            to: to.to_string(),
            attempts: 0,
            completed: false,
            last_error: None,
            next_retry_at_unix_ms: None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRebalanceOperation {
    pub rebalance_id: String,
    pub bucket: String,
    pub key: String,
    pub scope: RebalanceObjectScope,
    pub coordinator_node: String,
    pub placement_epoch: u64,
    pub placement_view_id: String,
    pub created_at_unix_ms: u64,
    pub transfers: Vec<PendingRebalanceTransferState>,
}

impl PendingRebalanceOperation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rebalance_id: &str,
        bucket: &str,
        key: &str,
        scope: RebalanceObjectScope,
        coordinator_node: &str,
        placement: &PlacementViewState,
        transfers: &[RebalanceTransfer],
        created_at_unix_ms: u64,
    ) -> Option<Self> {
        let rebalance_id = rebalance_id.trim();
        let bucket = bucket.trim();
        let key = key.trim();
        let coordinator_node = coordinator_node.trim();
        let placement_view_id = placement.view_id.trim();
        if rebalance_id.is_empty()
            || bucket.is_empty()
            || key.is_empty()
            || coordinator_node.is_empty()
            || placement_view_id.is_empty()
        {
            return None;
        }

        let mut seen = BTreeSet::<(Option<String>, String)>::new();
        let transfers = transfers
            .iter()
            .filter_map(|transfer| {
                PendingRebalanceTransferState::pending(
                    transfer.from.as_deref(),
                    transfer.to.as_str(),
                )
            })
            .filter(|transfer| seen.insert((transfer.from.clone(), transfer.to.clone())))
            .collect::<Vec<_>>();
        if transfers.is_empty() {
            return None;
        }

        Some(Self {
            rebalance_id: rebalance_id.to_string(),
            bucket: bucket.to_string(),
            key: key.to_string(),
            scope,
            coordinator_node: coordinator_node.to_string(),
            placement_epoch: placement.epoch,
            placement_view_id: placement_view_id.to_string(),
            created_at_unix_ms,
            transfers,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PendingRebalanceQueue {
    pub operations: Vec<PendingRebalanceOperation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingRebalanceEnqueueOutcome {
    Inserted,
    AlreadyTracked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingRebalanceAcknowledgeOutcome {
    Updated {
        remaining_transfers: usize,
        completed: bool,
    },
    NotFound,
    TransferNotTracked,
    AlreadyCompleted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingRebalanceFailureOutcome {
    Updated { attempts: u32 },
    NotFound,
    TransferNotTracked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingRebalanceLeaseOutcome {
    Updated {
        lease_expires_at_unix_ms: u64,
        attempts: u32,
    },
    NotFound,
    TransferNotTracked,
    AlreadyCompleted,
    NotDue {
        next_retry_at_unix_ms: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingRebalanceFailureWithBackoffOutcome {
    Updated {
        attempts: u32,
        next_retry_at_unix_ms: u64,
    },
    NotFound,
    TransferNotTracked,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PendingRebalanceQueueSummary {
    pub operations: usize,
    pub pending_transfers: usize,
    pub failed_transfers: usize,
    pub max_attempts: u32,
    pub oldest_created_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRebalanceCandidate {
    pub rebalance_id: String,
    pub bucket: String,
    pub key: String,
    pub scope: RebalanceObjectScope,
    pub coordinator_node: String,
    pub placement_epoch: u64,
    pub placement_view_id: String,
    pub created_at_unix_ms: u64,
    pub from: Option<String>,
    pub to: String,
    pub attempts: u32,
    pub next_retry_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PendingRebalanceReplayCycleOutcome {
    pub scanned_transfers: usize,
    pub leased_transfers: usize,
    pub acknowledged_transfers: usize,
    pub failed_transfers: usize,
    pub skipped_transfers: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplicationMutationOperation {
    PutObject,
    CopyObject,
    DeleteObject,
    DeleteObjectVersion,
    CompleteMultipartUpload,
}

impl ReplicationMutationOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PutObject => "put-object",
            Self::CopyObject => "copy-object",
            Self::DeleteObject => "delete-object",
            Self::DeleteObjectVersion => "delete-object-version",
            Self::CompleteMultipartUpload => "complete-multipart-upload",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingReplicationTargetState {
    pub node: String,
    pub attempts: u32,
    pub acked: bool,
    pub last_error: Option<String>,
    pub next_retry_at_unix_ms: Option<u64>,
}

impl PendingReplicationTargetState {
    fn pending(node: &str) -> Option<Self> {
        let node = node.trim();
        if node.is_empty() {
            return None;
        }
        Some(Self {
            node: node.to_string(),
            attempts: 0,
            acked: false,
            last_error: None,
            next_retry_at_unix_ms: None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingReplicationOperation {
    pub idempotency_key: String,
    pub operation: ReplicationMutationOperation,
    pub bucket: String,
    pub key: String,
    pub version_id: Option<String>,
    pub coordinator_node: String,
    pub placement_epoch: u64,
    pub placement_view_id: String,
    pub created_at_unix_ms: u64,
    pub targets: Vec<PendingReplicationTargetState>,
}

impl PendingReplicationOperation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        idempotency_key: &str,
        operation: ReplicationMutationOperation,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        coordinator_node: &str,
        placement: &PlacementViewState,
        target_nodes: &[String],
        created_at_unix_ms: u64,
    ) -> Option<Self> {
        let idempotency_key = idempotency_key.trim();
        let bucket = bucket.trim();
        let key = key.trim();
        let coordinator_node = coordinator_node.trim();
        let placement_view_id = placement.view_id.trim();
        if idempotency_key.is_empty()
            || bucket.is_empty()
            || key.is_empty()
            || coordinator_node.is_empty()
            || placement_view_id.is_empty()
        {
            return None;
        }

        let mut seen = BTreeSet::<String>::new();
        let targets = target_nodes
            .iter()
            .filter_map(|node| PendingReplicationTargetState::pending(node))
            .filter(|target| seen.insert(target.node.clone()))
            .collect::<Vec<_>>();
        if targets.is_empty() {
            return None;
        }

        let version_id = version_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);

        Some(Self {
            idempotency_key: idempotency_key.to_string(),
            operation,
            bucket: bucket.to_string(),
            key: key.to_string(),
            version_id,
            coordinator_node: coordinator_node.to_string(),
            placement_epoch: placement.epoch,
            placement_view_id: placement_view_id.to_string(),
            created_at_unix_ms,
            targets,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PendingReplicationQueue {
    pub operations: Vec<PendingReplicationOperation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingReplicationEnqueueOutcome {
    Inserted,
    AlreadyTracked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingReplicationAcknowledgeOutcome {
    Updated {
        remaining_targets: usize,
        completed: bool,
    },
    NotFound,
    TargetNotTracked,
    AlreadyAcked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingReplicationFailureOutcome {
    Updated { attempts: u32 },
    NotFound,
    TargetNotTracked,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PendingReplicationQueueSummary {
    pub operations: usize,
    pub pending_targets: usize,
    pub failed_targets: usize,
    pub max_attempts: u32,
    pub oldest_created_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingReplicationRetryPolicy {
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
}

impl PendingReplicationRetryPolicy {
    pub const DEFAULT_BASE_DELAY_MS: u64 = 1_000;
    pub const DEFAULT_MAX_DELAY_MS: u64 = 300_000;

    pub fn normalized(self) -> Self {
        let base_delay_ms = self.base_delay_ms.max(1);
        let max_delay_ms = self.max_delay_ms.max(base_delay_ms);
        Self {
            base_delay_ms,
            max_delay_ms,
        }
    }
}

impl Default for PendingReplicationRetryPolicy {
    fn default() -> Self {
        Self {
            base_delay_ms: Self::DEFAULT_BASE_DELAY_MS,
            max_delay_ms: Self::DEFAULT_MAX_DELAY_MS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingReplicationReplayCandidate {
    pub idempotency_key: String,
    pub operation: ReplicationMutationOperation,
    pub bucket: String,
    pub key: String,
    pub version_id: Option<String>,
    pub coordinator_node: String,
    pub placement_epoch: u64,
    pub placement_view_id: String,
    pub created_at_unix_ms: u64,
    pub target_node: String,
    pub attempts: u32,
    pub next_retry_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingReplicationReplayOwnerAlignment {
    pub owners: Vec<String>,
    pub local_is_owner: bool,
    pub target_is_owner: bool,
}

impl PendingReplicationReplayOwnerAlignment {
    pub const fn should_replay(&self) -> bool {
        self.local_is_owner && self.target_is_owner
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingReplicationReplayLeaseOutcome {
    Updated {
        lease_expires_at_unix_ms: u64,
        attempts: u32,
    },
    NotFound,
    TargetNotTracked,
    AlreadyAcked,
    NotDue {
        next_retry_at_unix_ms: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingReplicationFailureWithBackoffOutcome {
    Updated {
        attempts: u32,
        next_retry_at_unix_ms: u64,
    },
    NotFound,
    TargetNotTracked,
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
    GetObject,
    HeadObject,
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
