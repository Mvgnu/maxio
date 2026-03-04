use axum::Router;
use axum::extract::{Json, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::Response;
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::time::Duration;

mod cluster_handlers;
mod middleware;
mod observability;
mod persistence;
mod probes;
mod replay_workers;

use cluster_handlers::*;
use middleware::*;
use observability::*;
use persistence::*;
use probes::*;
use replay_workers::*;

pub(crate) use observability::runtime_health_payload;
pub use probes::membership_protocol_readiness;
pub(crate) use replay_workers::HealthPayload;
pub use replay_workers::{
    spawn_membership_convergence_probe_worker, spawn_pending_metadata_repair_replay_worker,
    spawn_pending_rebalance_replay_worker, spawn_pending_replication_replay_worker,
};

use crate::api::console::{LoginRateLimiter, console_router};
use crate::api::object::{forward_replica_put_to_target, replay_pending_replication_backlog_once};
use crate::api::router::s3_router;
use crate::auth::middleware::auth_middleware;
use crate::auth::signature_v4::{PresignRequest, generate_presigned_url};
use crate::cluster::authenticator::{
    FORWARDED_BY_HEADER, INTERNAL_MEMBERSHIP_PROPAGATED_HEADER, PeerAuthenticationError,
    SharedTokenBindingStatus, SharedTokenPeerAuthenticator, authenticate_forwarded_request,
    peer_auth_reject_counters_snapshot, record_peer_auth_rejection,
    strip_untrusted_internal_forwarding_headers,
};
use crate::cluster::internal_transport::parse_forwarded_by_chain;
use crate::cluster::join_authorization::{
    DEFAULT_JOIN_MAX_CLOCK_SKEW_MS, InMemoryJoinNonceReplayGuard, JOIN_CLUSTER_ID_HEADER,
    JOIN_NODE_ID_HEADER, JOIN_NONCE_HEADER, JOIN_TIMESTAMP_HEADER, JoinAuthorizationError,
    authorize_join_request,
};
use crate::cluster::security::INTERNAL_AUTH_TOKEN_HEADER;
use crate::cluster::transport_identity::{
    attest_peer_transport_identity_with_mtls,
    probe_peer_transport_identity_with_cert_sha256_pin_and_node_id_binding,
};
use crate::config::{Config, MembershipProtocol, WriteDurabilityMode};
use crate::embedded::ui_handler;
use crate::membership::{MembershipEngine, MembershipEngineStatus, unix_ms_now};
use crate::metadata::{
    ClusterMetadataListingStrategy, ClusterMetadataSnapshotAssessment,
    PendingMetadataRepairApplyError, PendingMetadataRepairApplyFailure,
    PendingMetadataRepairQueueSummary, apply_pending_metadata_repair_plan_to_persisted_state,
    assess_cluster_metadata_snapshot_for_topology_responders,
    assess_cluster_metadata_snapshot_for_topology_single_responder,
    build_queryable_metadata_index_from_persisted_state, load_persisted_metadata_state,
    pending_metadata_repair_candidates_from_disk,
    replay_pending_metadata_repairs_once_with_classified_apply_fn,
    summarize_pending_metadata_repair_queue_from_disk,
};
use crate::storage::StorageError;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::placement::{
    ForwardedWriteEnvelope, ForwardedWriteOperation, LocalRebalanceAction,
    PendingRebalanceAcknowledgeOutcome, PendingRebalanceCandidate, PendingRebalanceEnqueueOutcome,
    PendingRebalanceLeaseOutcome, PendingRebalanceOperation, PendingRebalanceQueueSummary,
    PendingReplicationQueueSummary, PendingReplicationRetryPolicy, PlacementViewState,
    RebalanceObjectScope, RebalanceTransfer, acknowledge_pending_rebalance_transfer_persisted,
    enqueue_pending_rebalance_operation_persisted,
    lease_pending_rebalance_transfer_for_execution_persisted, load_pending_replication_queue,
    local_rebalance_actions, membership_view_id_with_self, membership_with_self,
    object_rebalance_plan, pending_rebalance_candidates_from_disk,
    pending_replication_replay_candidates, record_pending_rebalance_failure_with_backoff_persisted,
    select_object_owners_with_self, summarize_pending_rebalance_queue_from_disk,
    summarize_pending_replication_queue,
};

const CORS_ALLOW_HEADERS_BASELINE: &str = "authorization,content-type,x-amz-date,x-amz-content-sha256,x-amz-security-token,x-amz-user-agent,x-amz-checksum-algorithm,x-amz-checksum-crc32,x-amz-checksum-crc32c,x-amz-checksum-sha1,x-amz-checksum-sha256,range";
const PLACEMENT_STATE_DIR: &str = ".maxio-runtime";
const PLACEMENT_STATE_FILE: &str = "placement-state.json";
const CLUSTER_ID_STATE_FILE: &str = "cluster-identity.json";
const PENDING_REPLICATION_QUEUE_FILE: &str = "pending-replication-queue.json";
const PENDING_REBALANCE_QUEUE_FILE: &str = "pending-rebalance-queue.json";
const PENDING_MEMBERSHIP_PROPAGATION_QUEUE_FILE: &str = "pending-membership-propagation-queue.json";
const PENDING_METADATA_REPAIR_QUEUE_FILE: &str = "pending-metadata-repair-queue.json";
const PERSISTED_METADATA_STATE_FILE: &str = "cluster-metadata-state.json";
const PENDING_REPLICATION_DUE_TARGET_SCAN_LIMIT: usize = 10_000;
const PENDING_REBALANCE_DUE_TRANSFER_SCAN_LIMIT: usize = 10_000;
const PENDING_MEMBERSHIP_PROPAGATION_DUE_OPERATION_SCAN_LIMIT: usize = 10_000;
const PENDING_METADATA_REPAIR_DUE_PLAN_SCAN_LIMIT: usize = 10_000;
const DISTRIBUTED_REBALANCE_REPLICA_TARGET: usize = 2;
const PENDING_REPLICATION_REPLAY_INTERVAL_SECS: u64 = 5;
const PENDING_REPLICATION_REPLAY_BATCH_SIZE: usize = 128;
const PENDING_REPLICATION_REPLAY_LEASE_MS: u64 = 30_000;
const PENDING_REBALANCE_REPLAY_INTERVAL_SECS: u64 = 5;
const PENDING_REBALANCE_REPLAY_BATCH_SIZE: usize = 128;
const PENDING_REBALANCE_REPLAY_LEASE_MS: u64 = 30_000;
const PENDING_MEMBERSHIP_PROPAGATION_REPLAY_INTERVAL_SECS: u64 = 5;
const PENDING_MEMBERSHIP_PROPAGATION_REPLAY_BATCH_SIZE: usize = 128;
const PENDING_METADATA_REPAIR_REPLAY_INTERVAL_SECS: u64 = 5;
const PENDING_METADATA_REPAIR_REPLAY_BATCH_SIZE: usize = 128;
const PENDING_METADATA_REPAIR_REPLAY_LEASE_MS: u64 = 30_000;
const PENDING_METADATA_REPAIR_REPLAY_BACKOFF_BASE_MS: u64 = 1_000;
const PENDING_METADATA_REPAIR_REPLAY_BACKOFF_MAX_MS: u64 = 60_000;
const MEMBERSHIP_CONVERGENCE_PROBE_INTERVAL_SECS: u64 = 10;
const PEER_CONNECTIVITY_PROBE_TIMEOUT_SECS: u64 = 2;
const MEMBERSHIP_UPDATE_PROPAGATION_TIMEOUT_SECS: u64 = 2;
const MEMBERSHIP_UPDATE_PROPAGATION_MAX_ATTEMPTS: u32 = 3;
const MEMBERSHIP_UPDATE_PROPAGATION_RETRY_BASE_MS: u64 = 100;
const MEMBERSHIP_UPDATE_PROPAGATION_RETRY_MAX_MS: u64 = 1_000;
const MEMBERSHIP_UPDATE_PROPAGATION_HEADER_VALUE: &str = "1";
const JOIN_NONCE_REPLAY_GUARD_TTL_MS: u64 = DEFAULT_JOIN_MAX_CLOCK_SKEW_MS * 2;
const JOIN_NONCE_REPLAY_GUARD_MAX_ENTRIES: usize = 65_536;
const JOIN_AUTHORIZE_REASON_DISTRIBUTED_MODE_DISABLED: &str = "distributed_mode_disabled";
const JOIN_AUTHORIZE_REASON_MEMBERSHIP_ENGINE_NOT_READY: &str = "membership_engine_not_ready";
const JOIN_AUTHORIZE_REASON_CLUSTER_AUTH_TOKEN_NOT_CONFIGURED: &str =
    "cluster_auth_token_not_configured";
const JOIN_AUTHORIZE_REASON_CLUSTER_PEER_TRANSPORT_NOT_READY: &str =
    "cluster_peer_transport_not_ready";
const MEMBERSHIP_UPDATE_REASON_INVALID_PAYLOAD: &str = "invalid_payload";
const MEMBERSHIP_UPDATE_REASON_CLUSTER_ID_MISMATCH: &str = "cluster_id_mismatch";
const MEMBERSHIP_UPDATE_REASON_PRECONDITION_FAILED: &str = "precondition_failed";
const MEMBERSHIP_UPDATE_REASON_UNAUTHORIZED: &str = "unauthorized";
const MEMBERSHIP_UPDATE_REASON_APPLIED: &str = "applied";
const MEMBERSHIP_UPDATE_REASON_STATE_PERSIST_FAILED: &str = "state_persist_failed";
const CORS_ALLOW_HEADERS_BASELINE_FIELDS: &[&str] = &[
    "authorization",
    "content-type",
    "x-amz-date",
    "x-amz-content-sha256",
    "x-amz-security-token",
    "x-amz-user-agent",
    "x-amz-checksum-algorithm",
    "x-amz-checksum-crc32",
    "x-amz-checksum-crc32c",
    "x-amz-checksum-sha1",
    "x-amz-checksum-sha256",
    "range",
];

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<FilesystemStorage>,
    pub config: Arc<Config>,
    pub credentials: Arc<HashMap<String, String>>,
    pub node_id: Arc<String>,
    pub cluster_id: Arc<String>,
    pub membership_peers: Arc<RwLock<Vec<String>>>,
    pub membership_view_id: Arc<RwLock<String>>,
    pub cluster_peers: Arc<Vec<String>>,
    pub membership_protocol: MembershipProtocol,
    pub write_durability_mode: WriteDurabilityMode,
    pub metadata_listing_strategy: ClusterMetadataListingStrategy,
    pub membership_engine: MembershipEngine,
    pub membership_last_update_unix_ms: Arc<AtomicU64>,
    pub membership_converged: Arc<AtomicU64>,
    pub join_nonce_replay_guard: Arc<InMemoryJoinNonceReplayGuard>,
    pub cluster_join_authorize_counters: Arc<ClusterJoinAuthorizeCounters>,
    pub cluster_join_counters: Arc<ClusterJoinCounters>,
    pub cluster_membership_update_counters: Arc<ClusterMembershipUpdateCounters>,
    pub pending_replication_replay_counters: Arc<PendingReplicationReplayCounters>,
    pub pending_rebalance_replay_counters: Arc<PendingRebalanceReplayCounters>,
    pub pending_membership_propagation_replay_counters:
        Arc<PendingMembershipPropagationReplayCounters>,
    pub pending_metadata_repair_replay_counters: Arc<PendingMetadataRepairReplayCounters>,
    pub placement_epoch: Arc<AtomicU64>,
    pub runtime_internal_header_reject_dimensions: Arc<RuntimeInternalHeaderRejectDimensions>,
    pub login_rate_limiter: Arc<LoginRateLimiter>,
    pub request_count: Arc<AtomicU64>,
    pub started_at: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeMode {
    Standalone,
    Distributed,
}

impl RuntimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standalone => "standalone",
            Self::Distributed => "distributed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeTopologySnapshot {
    pub mode: RuntimeMode,
    pub node_id: String,
    pub cluster_id: String,
    pub cluster_peers: Vec<String>,
    pub membership_nodes: Vec<String>,
    pub membership_protocol: MembershipProtocol,
    pub membership_status: MembershipEngineStatus,
    pub membership_view_id: String,
    pub placement_epoch: u64,
}

#[derive(Debug)]
pub struct RuntimeInternalHeaderRejectDimensions {
    total: AtomicU64,
    endpoint_api: AtomicU64,
    endpoint_healthz: AtomicU64,
    endpoint_metrics: AtomicU64,
    endpoint_ui: AtomicU64,
    endpoint_other: AtomicU64,
    sender_known_peer: AtomicU64,
    sender_local_node: AtomicU64,
    sender_unknown_peer: AtomicU64,
    sender_missing_or_invalid: AtomicU64,
}

impl Default for RuntimeInternalHeaderRejectDimensions {
    fn default() -> Self {
        Self {
            total: AtomicU64::new(0),
            endpoint_api: AtomicU64::new(0),
            endpoint_healthz: AtomicU64::new(0),
            endpoint_metrics: AtomicU64::new(0),
            endpoint_ui: AtomicU64::new(0),
            endpoint_other: AtomicU64::new(0),
            sender_known_peer: AtomicU64::new(0),
            sender_local_node: AtomicU64::new(0),
            sender_unknown_peer: AtomicU64::new(0),
            sender_missing_or_invalid: AtomicU64::new(0),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RuntimeInternalHeaderRejectEndpoint {
    Api,
    Healthz,
    Metrics,
    Ui,
    Other,
}

impl RuntimeInternalHeaderRejectEndpoint {
    fn for_path(path: &str) -> Self {
        if path == "/api" || path.starts_with("/api/") {
            return Self::Api;
        }
        if path == "/healthz" {
            return Self::Healthz;
        }
        if path == "/metrics" {
            return Self::Metrics;
        }
        if path == "/ui" || path == "/ui/" || path.starts_with("/ui/") {
            return Self::Ui;
        }
        Self::Other
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum RuntimeInternalHeaderRejectSender {
    KnownPeer,
    LocalNode,
    UnknownPeer,
    MissingOrInvalid,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct RuntimeInternalHeaderRejectDimensionsSnapshot {
    total: u64,
    endpoint_api: u64,
    endpoint_healthz: u64,
    endpoint_metrics: u64,
    endpoint_ui: u64,
    endpoint_other: u64,
    sender_known_peer: u64,
    sender_local_node: u64,
    sender_unknown_peer: u64,
    sender_missing_or_invalid: u64,
}

#[derive(Debug)]
pub struct ClusterJoinAuthorizeCounters {
    total: AtomicU64,
    status_authorized: AtomicU64,
    status_rejected: AtomicU64,
    status_misconfigured: AtomicU64,
    reason_authorized: AtomicU64,
    reason_invalid_configuration: AtomicU64,
    reason_missing_or_malformed_cluster_id: AtomicU64,
    reason_cluster_id_mismatch: AtomicU64,
    reason_missing_or_malformed_node_id: AtomicU64,
    reason_invalid_node_identity: AtomicU64,
    reason_node_matches_local_node: AtomicU64,
    reason_missing_or_malformed_join_timestamp: AtomicU64,
    reason_join_timestamp_skew_exceeded: AtomicU64,
    reason_missing_or_malformed_join_nonce: AtomicU64,
    reason_invalid_join_nonce: AtomicU64,
    reason_join_nonce_replay_detected: AtomicU64,
    reason_missing_or_malformed_auth_token: AtomicU64,
    reason_auth_token_mismatch: AtomicU64,
    reason_distributed_mode_disabled: AtomicU64,
    reason_membership_engine_not_ready: AtomicU64,
    reason_cluster_auth_token_not_configured: AtomicU64,
    reason_unknown: AtomicU64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct ClusterJoinAuthorizeCountersSnapshot {
    total: u64,
    status_authorized: u64,
    status_rejected: u64,
    status_misconfigured: u64,
    reason_authorized: u64,
    reason_invalid_configuration: u64,
    reason_missing_or_malformed_cluster_id: u64,
    reason_cluster_id_mismatch: u64,
    reason_missing_or_malformed_node_id: u64,
    reason_invalid_node_identity: u64,
    reason_node_matches_local_node: u64,
    reason_missing_or_malformed_join_timestamp: u64,
    reason_join_timestamp_skew_exceeded: u64,
    reason_missing_or_malformed_join_nonce: u64,
    reason_invalid_join_nonce: u64,
    reason_join_nonce_replay_detected: u64,
    reason_missing_or_malformed_auth_token: u64,
    reason_auth_token_mismatch: u64,
    reason_distributed_mode_disabled: u64,
    reason_membership_engine_not_ready: u64,
    reason_cluster_auth_token_not_configured: u64,
    reason_unknown: u64,
}

#[derive(Debug)]
pub struct ClusterJoinCounters {
    total: AtomicU64,
    status_applied: AtomicU64,
    status_rejected: AtomicU64,
    status_misconfigured: AtomicU64,
    reason_applied: AtomicU64,
    reason_invalid_payload: AtomicU64,
    reason_precondition_failed: AtomicU64,
    reason_unauthorized: AtomicU64,
    reason_distributed_mode_disabled: AtomicU64,
    reason_membership_engine_not_ready: AtomicU64,
    reason_cluster_auth_token_not_configured: AtomicU64,
    reason_state_persist_failed: AtomicU64,
    reason_unknown: AtomicU64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct ClusterJoinCountersSnapshot {
    total: u64,
    status_applied: u64,
    status_rejected: u64,
    status_misconfigured: u64,
    reason_applied: u64,
    reason_invalid_payload: u64,
    reason_precondition_failed: u64,
    reason_unauthorized: u64,
    reason_distributed_mode_disabled: u64,
    reason_membership_engine_not_ready: u64,
    reason_cluster_auth_token_not_configured: u64,
    reason_state_persist_failed: u64,
    reason_unknown: u64,
}

#[derive(Debug)]
pub struct ClusterMembershipUpdateCounters {
    total: AtomicU64,
    status_applied: AtomicU64,
    status_rejected: AtomicU64,
    status_misconfigured: AtomicU64,
    reason_applied: AtomicU64,
    reason_invalid_payload: AtomicU64,
    reason_cluster_id_mismatch: AtomicU64,
    reason_precondition_failed: AtomicU64,
    reason_unauthorized: AtomicU64,
    reason_distributed_mode_disabled: AtomicU64,
    reason_membership_engine_not_ready: AtomicU64,
    reason_cluster_auth_token_not_configured: AtomicU64,
    reason_state_persist_failed: AtomicU64,
    reason_unknown: AtomicU64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct ClusterMembershipUpdateCountersSnapshot {
    total: u64,
    status_applied: u64,
    status_rejected: u64,
    status_misconfigured: u64,
    reason_applied: u64,
    reason_invalid_payload: u64,
    reason_cluster_id_mismatch: u64,
    reason_precondition_failed: u64,
    reason_unauthorized: u64,
    reason_distributed_mode_disabled: u64,
    reason_membership_engine_not_ready: u64,
    reason_cluster_auth_token_not_configured: u64,
    reason_state_persist_failed: u64,
    reason_unknown: u64,
}

#[derive(Debug)]
pub struct PendingReplicationReplayCounters {
    cycles_total: AtomicU64,
    cycles_succeeded: AtomicU64,
    cycles_failed: AtomicU64,
    scanned_total: AtomicU64,
    leased_total: AtomicU64,
    acknowledged_total: AtomicU64,
    failed_total: AtomicU64,
    skipped_total: AtomicU64,
    last_cycle_unix_ms: AtomicU64,
    last_success_unix_ms: AtomicU64,
    last_failure_unix_ms: AtomicU64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct PendingReplicationReplayCountersSnapshot {
    cycles_total: u64,
    cycles_succeeded: u64,
    cycles_failed: u64,
    scanned_total: u64,
    leased_total: u64,
    acknowledged_total: u64,
    failed_total: u64,
    skipped_total: u64,
    last_cycle_unix_ms: u64,
    last_success_unix_ms: u64,
    last_failure_unix_ms: u64,
}

#[derive(Debug)]
pub struct PendingRebalanceReplayCounters {
    cycles_total: AtomicU64,
    cycles_succeeded: AtomicU64,
    cycles_failed: AtomicU64,
    scanned_total: AtomicU64,
    leased_total: AtomicU64,
    acknowledged_total: AtomicU64,
    failed_total: AtomicU64,
    skipped_total: AtomicU64,
    last_cycle_unix_ms: AtomicU64,
    last_success_unix_ms: AtomicU64,
    last_failure_unix_ms: AtomicU64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct PendingRebalanceReplayCountersSnapshot {
    cycles_total: u64,
    cycles_succeeded: u64,
    cycles_failed: u64,
    scanned_total: u64,
    leased_total: u64,
    acknowledged_total: u64,
    failed_total: u64,
    skipped_total: u64,
    last_cycle_unix_ms: u64,
    last_success_unix_ms: u64,
    last_failure_unix_ms: u64,
}

#[derive(Debug)]
pub struct PendingMembershipPropagationReplayCounters {
    cycles_total: AtomicU64,
    cycles_succeeded: AtomicU64,
    cycles_failed: AtomicU64,
    scanned_operations_total: AtomicU64,
    replayed_operations_total: AtomicU64,
    deferred_operations_total: AtomicU64,
    acknowledged_operations_total: AtomicU64,
    failed_operations_total: AtomicU64,
    last_cycle_unix_ms: AtomicU64,
    last_success_unix_ms: AtomicU64,
    last_failure_unix_ms: AtomicU64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct PendingMembershipPropagationReplayCountersSnapshot {
    cycles_total: u64,
    cycles_succeeded: u64,
    cycles_failed: u64,
    scanned_operations_total: u64,
    replayed_operations_total: u64,
    deferred_operations_total: u64,
    acknowledged_operations_total: u64,
    failed_operations_total: u64,
    last_cycle_unix_ms: u64,
    last_success_unix_ms: u64,
    last_failure_unix_ms: u64,
}

#[derive(Debug)]
pub struct PendingMetadataRepairReplayCounters {
    cycles_total: AtomicU64,
    cycles_succeeded: AtomicU64,
    cycles_failed: AtomicU64,
    scanned_plans_total: AtomicU64,
    leased_plans_total: AtomicU64,
    acknowledged_plans_total: AtomicU64,
    failed_plans_total: AtomicU64,
    skipped_plans_total: AtomicU64,
    last_cycle_unix_ms: AtomicU64,
    last_success_unix_ms: AtomicU64,
    last_failure_unix_ms: AtomicU64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct PendingMetadataRepairReplayCountersSnapshot {
    cycles_total: u64,
    cycles_succeeded: u64,
    cycles_failed: u64,
    scanned_plans_total: u64,
    leased_plans_total: u64,
    acknowledged_plans_total: u64,
    failed_plans_total: u64,
    skipped_plans_total: u64,
    last_cycle_unix_ms: u64,
    last_success_unix_ms: u64,
    last_failure_unix_ms: u64,
}

impl Default for ClusterJoinAuthorizeCounters {
    fn default() -> Self {
        Self {
            total: AtomicU64::new(0),
            status_authorized: AtomicU64::new(0),
            status_rejected: AtomicU64::new(0),
            status_misconfigured: AtomicU64::new(0),
            reason_authorized: AtomicU64::new(0),
            reason_invalid_configuration: AtomicU64::new(0),
            reason_missing_or_malformed_cluster_id: AtomicU64::new(0),
            reason_cluster_id_mismatch: AtomicU64::new(0),
            reason_missing_or_malformed_node_id: AtomicU64::new(0),
            reason_invalid_node_identity: AtomicU64::new(0),
            reason_node_matches_local_node: AtomicU64::new(0),
            reason_missing_or_malformed_join_timestamp: AtomicU64::new(0),
            reason_join_timestamp_skew_exceeded: AtomicU64::new(0),
            reason_missing_or_malformed_join_nonce: AtomicU64::new(0),
            reason_invalid_join_nonce: AtomicU64::new(0),
            reason_join_nonce_replay_detected: AtomicU64::new(0),
            reason_missing_or_malformed_auth_token: AtomicU64::new(0),
            reason_auth_token_mismatch: AtomicU64::new(0),
            reason_distributed_mode_disabled: AtomicU64::new(0),
            reason_membership_engine_not_ready: AtomicU64::new(0),
            reason_cluster_auth_token_not_configured: AtomicU64::new(0),
            reason_unknown: AtomicU64::new(0),
        }
    }
}

impl Default for ClusterMembershipUpdateCounters {
    fn default() -> Self {
        Self {
            total: AtomicU64::new(0),
            status_applied: AtomicU64::new(0),
            status_rejected: AtomicU64::new(0),
            status_misconfigured: AtomicU64::new(0),
            reason_applied: AtomicU64::new(0),
            reason_invalid_payload: AtomicU64::new(0),
            reason_cluster_id_mismatch: AtomicU64::new(0),
            reason_precondition_failed: AtomicU64::new(0),
            reason_unauthorized: AtomicU64::new(0),
            reason_distributed_mode_disabled: AtomicU64::new(0),
            reason_membership_engine_not_ready: AtomicU64::new(0),
            reason_cluster_auth_token_not_configured: AtomicU64::new(0),
            reason_state_persist_failed: AtomicU64::new(0),
            reason_unknown: AtomicU64::new(0),
        }
    }
}

impl Default for ClusterJoinCounters {
    fn default() -> Self {
        Self {
            total: AtomicU64::new(0),
            status_applied: AtomicU64::new(0),
            status_rejected: AtomicU64::new(0),
            status_misconfigured: AtomicU64::new(0),
            reason_applied: AtomicU64::new(0),
            reason_invalid_payload: AtomicU64::new(0),
            reason_precondition_failed: AtomicU64::new(0),
            reason_unauthorized: AtomicU64::new(0),
            reason_distributed_mode_disabled: AtomicU64::new(0),
            reason_membership_engine_not_ready: AtomicU64::new(0),
            reason_cluster_auth_token_not_configured: AtomicU64::new(0),
            reason_state_persist_failed: AtomicU64::new(0),
            reason_unknown: AtomicU64::new(0),
        }
    }
}

impl Default for PendingReplicationReplayCounters {
    fn default() -> Self {
        Self {
            cycles_total: AtomicU64::new(0),
            cycles_succeeded: AtomicU64::new(0),
            cycles_failed: AtomicU64::new(0),
            scanned_total: AtomicU64::new(0),
            leased_total: AtomicU64::new(0),
            acknowledged_total: AtomicU64::new(0),
            failed_total: AtomicU64::new(0),
            skipped_total: AtomicU64::new(0),
            last_cycle_unix_ms: AtomicU64::new(0),
            last_success_unix_ms: AtomicU64::new(0),
            last_failure_unix_ms: AtomicU64::new(0),
        }
    }
}

impl Default for PendingMetadataRepairReplayCounters {
    fn default() -> Self {
        Self {
            cycles_total: AtomicU64::new(0),
            cycles_succeeded: AtomicU64::new(0),
            cycles_failed: AtomicU64::new(0),
            scanned_plans_total: AtomicU64::new(0),
            leased_plans_total: AtomicU64::new(0),
            acknowledged_plans_total: AtomicU64::new(0),
            failed_plans_total: AtomicU64::new(0),
            skipped_plans_total: AtomicU64::new(0),
            last_cycle_unix_ms: AtomicU64::new(0),
            last_success_unix_ms: AtomicU64::new(0),
            last_failure_unix_ms: AtomicU64::new(0),
        }
    }
}

impl Default for PendingRebalanceReplayCounters {
    fn default() -> Self {
        Self {
            cycles_total: AtomicU64::new(0),
            cycles_succeeded: AtomicU64::new(0),
            cycles_failed: AtomicU64::new(0),
            scanned_total: AtomicU64::new(0),
            leased_total: AtomicU64::new(0),
            acknowledged_total: AtomicU64::new(0),
            failed_total: AtomicU64::new(0),
            skipped_total: AtomicU64::new(0),
            last_cycle_unix_ms: AtomicU64::new(0),
            last_success_unix_ms: AtomicU64::new(0),
            last_failure_unix_ms: AtomicU64::new(0),
        }
    }
}

impl Default for PendingMembershipPropagationReplayCounters {
    fn default() -> Self {
        Self {
            cycles_total: AtomicU64::new(0),
            cycles_succeeded: AtomicU64::new(0),
            cycles_failed: AtomicU64::new(0),
            scanned_operations_total: AtomicU64::new(0),
            replayed_operations_total: AtomicU64::new(0),
            deferred_operations_total: AtomicU64::new(0),
            acknowledged_operations_total: AtomicU64::new(0),
            failed_operations_total: AtomicU64::new(0),
            last_cycle_unix_ms: AtomicU64::new(0),
            last_success_unix_ms: AtomicU64::new(0),
            last_failure_unix_ms: AtomicU64::new(0),
        }
    }
}

impl ClusterJoinCounters {
    fn record(&self, status_label: &str, reason: &str) {
        self.total.fetch_add(1, Ordering::Relaxed);
        match status_label {
            "applied" => {
                self.status_applied.fetch_add(1, Ordering::Relaxed);
            }
            "rejected" => {
                self.status_rejected.fetch_add(1, Ordering::Relaxed);
            }
            "misconfigured" => {
                self.status_misconfigured.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }

        match reason {
            MEMBERSHIP_UPDATE_REASON_APPLIED => {
                self.reason_applied.fetch_add(1, Ordering::Relaxed);
            }
            MEMBERSHIP_UPDATE_REASON_INVALID_PAYLOAD => {
                self.reason_invalid_payload.fetch_add(1, Ordering::Relaxed);
            }
            MEMBERSHIP_UPDATE_REASON_PRECONDITION_FAILED => {
                self.reason_precondition_failed
                    .fetch_add(1, Ordering::Relaxed);
            }
            MEMBERSHIP_UPDATE_REASON_UNAUTHORIZED => {
                self.reason_unauthorized.fetch_add(1, Ordering::Relaxed);
            }
            JOIN_AUTHORIZE_REASON_DISTRIBUTED_MODE_DISABLED => {
                self.reason_distributed_mode_disabled
                    .fetch_add(1, Ordering::Relaxed);
            }
            JOIN_AUTHORIZE_REASON_MEMBERSHIP_ENGINE_NOT_READY => {
                self.reason_membership_engine_not_ready
                    .fetch_add(1, Ordering::Relaxed);
            }
            JOIN_AUTHORIZE_REASON_CLUSTER_AUTH_TOKEN_NOT_CONFIGURED => {
                self.reason_cluster_auth_token_not_configured
                    .fetch_add(1, Ordering::Relaxed);
            }
            MEMBERSHIP_UPDATE_REASON_STATE_PERSIST_FAILED => {
                self.reason_state_persist_failed
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.reason_unknown.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn snapshot(&self) -> ClusterJoinCountersSnapshot {
        ClusterJoinCountersSnapshot {
            total: self.total.load(Ordering::Relaxed),
            status_applied: self.status_applied.load(Ordering::Relaxed),
            status_rejected: self.status_rejected.load(Ordering::Relaxed),
            status_misconfigured: self.status_misconfigured.load(Ordering::Relaxed),
            reason_applied: self.reason_applied.load(Ordering::Relaxed),
            reason_invalid_payload: self.reason_invalid_payload.load(Ordering::Relaxed),
            reason_precondition_failed: self.reason_precondition_failed.load(Ordering::Relaxed),
            reason_unauthorized: self.reason_unauthorized.load(Ordering::Relaxed),
            reason_distributed_mode_disabled: self
                .reason_distributed_mode_disabled
                .load(Ordering::Relaxed),
            reason_membership_engine_not_ready: self
                .reason_membership_engine_not_ready
                .load(Ordering::Relaxed),
            reason_cluster_auth_token_not_configured: self
                .reason_cluster_auth_token_not_configured
                .load(Ordering::Relaxed),
            reason_state_persist_failed: self.reason_state_persist_failed.load(Ordering::Relaxed),
            reason_unknown: self.reason_unknown.load(Ordering::Relaxed),
        }
    }
}

impl ClusterJoinAuthorizeCounters {
    fn record(&self, status_label: &str, reason: &str) {
        self.total.fetch_add(1, Ordering::Relaxed);
        match status_label {
            "authorized" => {
                self.status_authorized.fetch_add(1, Ordering::Relaxed);
            }
            "rejected" => {
                self.status_rejected.fetch_add(1, Ordering::Relaxed);
            }
            "misconfigured" => {
                self.status_misconfigured.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }

        match reason {
            "authorized" => {
                self.reason_authorized.fetch_add(1, Ordering::Relaxed);
            }
            "invalid_configuration" => {
                self.reason_invalid_configuration
                    .fetch_add(1, Ordering::Relaxed);
            }
            "missing_or_malformed_cluster_id" => {
                self.reason_missing_or_malformed_cluster_id
                    .fetch_add(1, Ordering::Relaxed);
            }
            "cluster_id_mismatch" => {
                self.reason_cluster_id_mismatch
                    .fetch_add(1, Ordering::Relaxed);
            }
            "missing_or_malformed_node_id" => {
                self.reason_missing_or_malformed_node_id
                    .fetch_add(1, Ordering::Relaxed);
            }
            "invalid_node_identity" => {
                self.reason_invalid_node_identity
                    .fetch_add(1, Ordering::Relaxed);
            }
            "node_matches_local_node" => {
                self.reason_node_matches_local_node
                    .fetch_add(1, Ordering::Relaxed);
            }
            "missing_or_malformed_join_timestamp" => {
                self.reason_missing_or_malformed_join_timestamp
                    .fetch_add(1, Ordering::Relaxed);
            }
            "join_timestamp_skew_exceeded" => {
                self.reason_join_timestamp_skew_exceeded
                    .fetch_add(1, Ordering::Relaxed);
            }
            "missing_or_malformed_join_nonce" => {
                self.reason_missing_or_malformed_join_nonce
                    .fetch_add(1, Ordering::Relaxed);
            }
            "invalid_join_nonce" => {
                self.reason_invalid_join_nonce
                    .fetch_add(1, Ordering::Relaxed);
            }
            "join_nonce_replay_detected" => {
                self.reason_join_nonce_replay_detected
                    .fetch_add(1, Ordering::Relaxed);
            }
            "missing_or_malformed_auth_token" => {
                self.reason_missing_or_malformed_auth_token
                    .fetch_add(1, Ordering::Relaxed);
            }
            "auth_token_mismatch" => {
                self.reason_auth_token_mismatch
                    .fetch_add(1, Ordering::Relaxed);
            }
            JOIN_AUTHORIZE_REASON_DISTRIBUTED_MODE_DISABLED => {
                self.reason_distributed_mode_disabled
                    .fetch_add(1, Ordering::Relaxed);
            }
            JOIN_AUTHORIZE_REASON_MEMBERSHIP_ENGINE_NOT_READY => {
                self.reason_membership_engine_not_ready
                    .fetch_add(1, Ordering::Relaxed);
            }
            JOIN_AUTHORIZE_REASON_CLUSTER_AUTH_TOKEN_NOT_CONFIGURED => {
                self.reason_cluster_auth_token_not_configured
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.reason_unknown.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn snapshot(&self) -> ClusterJoinAuthorizeCountersSnapshot {
        ClusterJoinAuthorizeCountersSnapshot {
            total: self.total.load(Ordering::Relaxed),
            status_authorized: self.status_authorized.load(Ordering::Relaxed),
            status_rejected: self.status_rejected.load(Ordering::Relaxed),
            status_misconfigured: self.status_misconfigured.load(Ordering::Relaxed),
            reason_authorized: self.reason_authorized.load(Ordering::Relaxed),
            reason_invalid_configuration: self.reason_invalid_configuration.load(Ordering::Relaxed),
            reason_missing_or_malformed_cluster_id: self
                .reason_missing_or_malformed_cluster_id
                .load(Ordering::Relaxed),
            reason_cluster_id_mismatch: self.reason_cluster_id_mismatch.load(Ordering::Relaxed),
            reason_missing_or_malformed_node_id: self
                .reason_missing_or_malformed_node_id
                .load(Ordering::Relaxed),
            reason_invalid_node_identity: self.reason_invalid_node_identity.load(Ordering::Relaxed),
            reason_node_matches_local_node: self
                .reason_node_matches_local_node
                .load(Ordering::Relaxed),
            reason_missing_or_malformed_join_timestamp: self
                .reason_missing_or_malformed_join_timestamp
                .load(Ordering::Relaxed),
            reason_join_timestamp_skew_exceeded: self
                .reason_join_timestamp_skew_exceeded
                .load(Ordering::Relaxed),
            reason_missing_or_malformed_join_nonce: self
                .reason_missing_or_malformed_join_nonce
                .load(Ordering::Relaxed),
            reason_invalid_join_nonce: self.reason_invalid_join_nonce.load(Ordering::Relaxed),
            reason_join_nonce_replay_detected: self
                .reason_join_nonce_replay_detected
                .load(Ordering::Relaxed),
            reason_missing_or_malformed_auth_token: self
                .reason_missing_or_malformed_auth_token
                .load(Ordering::Relaxed),
            reason_auth_token_mismatch: self.reason_auth_token_mismatch.load(Ordering::Relaxed),
            reason_distributed_mode_disabled: self
                .reason_distributed_mode_disabled
                .load(Ordering::Relaxed),
            reason_membership_engine_not_ready: self
                .reason_membership_engine_not_ready
                .load(Ordering::Relaxed),
            reason_cluster_auth_token_not_configured: self
                .reason_cluster_auth_token_not_configured
                .load(Ordering::Relaxed),
            reason_unknown: self.reason_unknown.load(Ordering::Relaxed),
        }
    }
}

impl ClusterMembershipUpdateCounters {
    fn record(&self, status_label: &str, reason: &str) {
        self.total.fetch_add(1, Ordering::Relaxed);
        match status_label {
            "applied" => {
                self.status_applied.fetch_add(1, Ordering::Relaxed);
            }
            "rejected" => {
                self.status_rejected.fetch_add(1, Ordering::Relaxed);
            }
            "misconfigured" => {
                self.status_misconfigured.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }

        match reason {
            MEMBERSHIP_UPDATE_REASON_APPLIED => {
                self.reason_applied.fetch_add(1, Ordering::Relaxed);
            }
            MEMBERSHIP_UPDATE_REASON_INVALID_PAYLOAD => {
                self.reason_invalid_payload.fetch_add(1, Ordering::Relaxed);
            }
            MEMBERSHIP_UPDATE_REASON_CLUSTER_ID_MISMATCH => {
                self.reason_cluster_id_mismatch
                    .fetch_add(1, Ordering::Relaxed);
            }
            MEMBERSHIP_UPDATE_REASON_PRECONDITION_FAILED => {
                self.reason_precondition_failed
                    .fetch_add(1, Ordering::Relaxed);
            }
            MEMBERSHIP_UPDATE_REASON_UNAUTHORIZED => {
                self.reason_unauthorized.fetch_add(1, Ordering::Relaxed);
            }
            JOIN_AUTHORIZE_REASON_DISTRIBUTED_MODE_DISABLED => {
                self.reason_distributed_mode_disabled
                    .fetch_add(1, Ordering::Relaxed);
            }
            JOIN_AUTHORIZE_REASON_MEMBERSHIP_ENGINE_NOT_READY => {
                self.reason_membership_engine_not_ready
                    .fetch_add(1, Ordering::Relaxed);
            }
            JOIN_AUTHORIZE_REASON_CLUSTER_AUTH_TOKEN_NOT_CONFIGURED => {
                self.reason_cluster_auth_token_not_configured
                    .fetch_add(1, Ordering::Relaxed);
            }
            MEMBERSHIP_UPDATE_REASON_STATE_PERSIST_FAILED => {
                self.reason_state_persist_failed
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.reason_unknown.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn snapshot(&self) -> ClusterMembershipUpdateCountersSnapshot {
        ClusterMembershipUpdateCountersSnapshot {
            total: self.total.load(Ordering::Relaxed),
            status_applied: self.status_applied.load(Ordering::Relaxed),
            status_rejected: self.status_rejected.load(Ordering::Relaxed),
            status_misconfigured: self.status_misconfigured.load(Ordering::Relaxed),
            reason_applied: self.reason_applied.load(Ordering::Relaxed),
            reason_invalid_payload: self.reason_invalid_payload.load(Ordering::Relaxed),
            reason_cluster_id_mismatch: self.reason_cluster_id_mismatch.load(Ordering::Relaxed),
            reason_precondition_failed: self.reason_precondition_failed.load(Ordering::Relaxed),
            reason_unauthorized: self.reason_unauthorized.load(Ordering::Relaxed),
            reason_distributed_mode_disabled: self
                .reason_distributed_mode_disabled
                .load(Ordering::Relaxed),
            reason_membership_engine_not_ready: self
                .reason_membership_engine_not_ready
                .load(Ordering::Relaxed),
            reason_cluster_auth_token_not_configured: self
                .reason_cluster_auth_token_not_configured
                .load(Ordering::Relaxed),
            reason_state_persist_failed: self.reason_state_persist_failed.load(Ordering::Relaxed),
            reason_unknown: self.reason_unknown.load(Ordering::Relaxed),
        }
    }
}

impl PendingReplicationReplayCounters {
    fn record_success(
        &self,
        scanned: usize,
        leased: usize,
        acknowledged: usize,
        failed: usize,
        skipped: usize,
    ) {
        let observed_at_unix_ms = unix_ms_now();
        self.cycles_total.fetch_add(1, Ordering::Relaxed);
        self.cycles_succeeded.fetch_add(1, Ordering::Relaxed);
        self.scanned_total
            .fetch_add(scanned as u64, Ordering::Relaxed);
        self.leased_total
            .fetch_add(leased as u64, Ordering::Relaxed);
        self.acknowledged_total
            .fetch_add(acknowledged as u64, Ordering::Relaxed);
        self.failed_total
            .fetch_add(failed as u64, Ordering::Relaxed);
        self.skipped_total
            .fetch_add(skipped as u64, Ordering::Relaxed);
        self.last_cycle_unix_ms
            .fetch_max(observed_at_unix_ms, Ordering::Relaxed);
        self.last_success_unix_ms
            .fetch_max(observed_at_unix_ms, Ordering::Relaxed);
    }

    fn record_failure(&self) {
        let observed_at_unix_ms = unix_ms_now();
        self.cycles_total.fetch_add(1, Ordering::Relaxed);
        self.cycles_failed.fetch_add(1, Ordering::Relaxed);
        self.last_cycle_unix_ms
            .fetch_max(observed_at_unix_ms, Ordering::Relaxed);
        self.last_failure_unix_ms
            .fetch_max(observed_at_unix_ms, Ordering::Relaxed);
    }

    fn snapshot(&self) -> PendingReplicationReplayCountersSnapshot {
        PendingReplicationReplayCountersSnapshot {
            cycles_total: self.cycles_total.load(Ordering::Relaxed),
            cycles_succeeded: self.cycles_succeeded.load(Ordering::Relaxed),
            cycles_failed: self.cycles_failed.load(Ordering::Relaxed),
            scanned_total: self.scanned_total.load(Ordering::Relaxed),
            leased_total: self.leased_total.load(Ordering::Relaxed),
            acknowledged_total: self.acknowledged_total.load(Ordering::Relaxed),
            failed_total: self.failed_total.load(Ordering::Relaxed),
            skipped_total: self.skipped_total.load(Ordering::Relaxed),
            last_cycle_unix_ms: self.last_cycle_unix_ms.load(Ordering::Relaxed),
            last_success_unix_ms: self.last_success_unix_ms.load(Ordering::Relaxed),
            last_failure_unix_ms: self.last_failure_unix_ms.load(Ordering::Relaxed),
        }
    }
}

impl PendingRebalanceReplayCounters {
    fn record_success(
        &self,
        scanned: usize,
        leased: usize,
        acknowledged: usize,
        failed: usize,
        skipped: usize,
    ) {
        let observed_at_unix_ms = unix_ms_now();
        self.cycles_total.fetch_add(1, Ordering::Relaxed);
        self.cycles_succeeded.fetch_add(1, Ordering::Relaxed);
        self.scanned_total
            .fetch_add(scanned as u64, Ordering::Relaxed);
        self.leased_total
            .fetch_add(leased as u64, Ordering::Relaxed);
        self.acknowledged_total
            .fetch_add(acknowledged as u64, Ordering::Relaxed);
        self.failed_total
            .fetch_add(failed as u64, Ordering::Relaxed);
        self.skipped_total
            .fetch_add(skipped as u64, Ordering::Relaxed);
        self.last_cycle_unix_ms
            .fetch_max(observed_at_unix_ms, Ordering::Relaxed);
        self.last_success_unix_ms
            .fetch_max(observed_at_unix_ms, Ordering::Relaxed);
    }

    fn record_failure(&self) {
        let observed_at_unix_ms = unix_ms_now();
        self.cycles_total.fetch_add(1, Ordering::Relaxed);
        self.cycles_failed.fetch_add(1, Ordering::Relaxed);
        self.last_cycle_unix_ms
            .fetch_max(observed_at_unix_ms, Ordering::Relaxed);
        self.last_failure_unix_ms
            .fetch_max(observed_at_unix_ms, Ordering::Relaxed);
    }

    fn snapshot(&self) -> PendingRebalanceReplayCountersSnapshot {
        PendingRebalanceReplayCountersSnapshot {
            cycles_total: self.cycles_total.load(Ordering::Relaxed),
            cycles_succeeded: self.cycles_succeeded.load(Ordering::Relaxed),
            cycles_failed: self.cycles_failed.load(Ordering::Relaxed),
            scanned_total: self.scanned_total.load(Ordering::Relaxed),
            leased_total: self.leased_total.load(Ordering::Relaxed),
            acknowledged_total: self.acknowledged_total.load(Ordering::Relaxed),
            failed_total: self.failed_total.load(Ordering::Relaxed),
            skipped_total: self.skipped_total.load(Ordering::Relaxed),
            last_cycle_unix_ms: self.last_cycle_unix_ms.load(Ordering::Relaxed),
            last_success_unix_ms: self.last_success_unix_ms.load(Ordering::Relaxed),
            last_failure_unix_ms: self.last_failure_unix_ms.load(Ordering::Relaxed),
        }
    }
}

impl PendingMetadataRepairReplayCounters {
    fn record_success(
        &self,
        scanned_plans: usize,
        leased_plans: usize,
        acknowledged_plans: usize,
        failed_plans: usize,
        skipped_plans: usize,
    ) {
        let observed_at_unix_ms = unix_ms_now();
        self.cycles_total.fetch_add(1, Ordering::Relaxed);
        self.cycles_succeeded.fetch_add(1, Ordering::Relaxed);
        self.scanned_plans_total
            .fetch_add(scanned_plans as u64, Ordering::Relaxed);
        self.leased_plans_total
            .fetch_add(leased_plans as u64, Ordering::Relaxed);
        self.acknowledged_plans_total
            .fetch_add(acknowledged_plans as u64, Ordering::Relaxed);
        self.failed_plans_total
            .fetch_add(failed_plans as u64, Ordering::Relaxed);
        self.skipped_plans_total
            .fetch_add(skipped_plans as u64, Ordering::Relaxed);
        self.last_cycle_unix_ms
            .fetch_max(observed_at_unix_ms, Ordering::Relaxed);
        self.last_success_unix_ms
            .fetch_max(observed_at_unix_ms, Ordering::Relaxed);
    }

    fn record_failure(&self) {
        let observed_at_unix_ms = unix_ms_now();
        self.cycles_total.fetch_add(1, Ordering::Relaxed);
        self.cycles_failed.fetch_add(1, Ordering::Relaxed);
        self.last_cycle_unix_ms
            .fetch_max(observed_at_unix_ms, Ordering::Relaxed);
        self.last_failure_unix_ms
            .fetch_max(observed_at_unix_ms, Ordering::Relaxed);
    }

    fn snapshot(&self) -> PendingMetadataRepairReplayCountersSnapshot {
        PendingMetadataRepairReplayCountersSnapshot {
            cycles_total: self.cycles_total.load(Ordering::Relaxed),
            cycles_succeeded: self.cycles_succeeded.load(Ordering::Relaxed),
            cycles_failed: self.cycles_failed.load(Ordering::Relaxed),
            scanned_plans_total: self.scanned_plans_total.load(Ordering::Relaxed),
            leased_plans_total: self.leased_plans_total.load(Ordering::Relaxed),
            acknowledged_plans_total: self.acknowledged_plans_total.load(Ordering::Relaxed),
            failed_plans_total: self.failed_plans_total.load(Ordering::Relaxed),
            skipped_plans_total: self.skipped_plans_total.load(Ordering::Relaxed),
            last_cycle_unix_ms: self.last_cycle_unix_ms.load(Ordering::Relaxed),
            last_success_unix_ms: self.last_success_unix_ms.load(Ordering::Relaxed),
            last_failure_unix_ms: self.last_failure_unix_ms.load(Ordering::Relaxed),
        }
    }
}

impl PendingMembershipPropagationReplayCounters {
    fn record_success(
        &self,
        scanned_operations: usize,
        replayed_operations: usize,
        deferred_operations: usize,
        acknowledged_operations: usize,
        failed_operations: usize,
    ) {
        let observed_at_unix_ms = unix_ms_now();
        self.cycles_total.fetch_add(1, Ordering::Relaxed);
        self.cycles_succeeded.fetch_add(1, Ordering::Relaxed);
        self.scanned_operations_total
            .fetch_add(scanned_operations as u64, Ordering::Relaxed);
        self.replayed_operations_total
            .fetch_add(replayed_operations as u64, Ordering::Relaxed);
        self.deferred_operations_total
            .fetch_add(deferred_operations as u64, Ordering::Relaxed);
        self.acknowledged_operations_total
            .fetch_add(acknowledged_operations as u64, Ordering::Relaxed);
        self.failed_operations_total
            .fetch_add(failed_operations as u64, Ordering::Relaxed);
        self.last_cycle_unix_ms
            .fetch_max(observed_at_unix_ms, Ordering::Relaxed);
        self.last_success_unix_ms
            .fetch_max(observed_at_unix_ms, Ordering::Relaxed);
    }

    fn record_failure(&self) {
        let observed_at_unix_ms = unix_ms_now();
        self.cycles_total.fetch_add(1, Ordering::Relaxed);
        self.cycles_failed.fetch_add(1, Ordering::Relaxed);
        self.last_cycle_unix_ms
            .fetch_max(observed_at_unix_ms, Ordering::Relaxed);
        self.last_failure_unix_ms
            .fetch_max(observed_at_unix_ms, Ordering::Relaxed);
    }

    fn snapshot(&self) -> PendingMembershipPropagationReplayCountersSnapshot {
        PendingMembershipPropagationReplayCountersSnapshot {
            cycles_total: self.cycles_total.load(Ordering::Relaxed),
            cycles_succeeded: self.cycles_succeeded.load(Ordering::Relaxed),
            cycles_failed: self.cycles_failed.load(Ordering::Relaxed),
            scanned_operations_total: self.scanned_operations_total.load(Ordering::Relaxed),
            replayed_operations_total: self.replayed_operations_total.load(Ordering::Relaxed),
            deferred_operations_total: self.deferred_operations_total.load(Ordering::Relaxed),
            acknowledged_operations_total: self
                .acknowledged_operations_total
                .load(Ordering::Relaxed),
            failed_operations_total: self.failed_operations_total.load(Ordering::Relaxed),
            last_cycle_unix_ms: self.last_cycle_unix_ms.load(Ordering::Relaxed),
            last_success_unix_ms: self.last_success_unix_ms.load(Ordering::Relaxed),
            last_failure_unix_ms: self.last_failure_unix_ms.load(Ordering::Relaxed),
        }
    }
}

impl RuntimeInternalHeaderRejectDimensions {
    fn record(
        &self,
        endpoint: RuntimeInternalHeaderRejectEndpoint,
        sender: RuntimeInternalHeaderRejectSender,
    ) {
        self.total.fetch_add(1, Ordering::Relaxed);
        match endpoint {
            RuntimeInternalHeaderRejectEndpoint::Api => {
                self.endpoint_api.fetch_add(1, Ordering::Relaxed);
            }
            RuntimeInternalHeaderRejectEndpoint::Healthz => {
                self.endpoint_healthz.fetch_add(1, Ordering::Relaxed);
            }
            RuntimeInternalHeaderRejectEndpoint::Metrics => {
                self.endpoint_metrics.fetch_add(1, Ordering::Relaxed);
            }
            RuntimeInternalHeaderRejectEndpoint::Ui => {
                self.endpoint_ui.fetch_add(1, Ordering::Relaxed);
            }
            RuntimeInternalHeaderRejectEndpoint::Other => {
                self.endpoint_other.fetch_add(1, Ordering::Relaxed);
            }
        }
        match sender {
            RuntimeInternalHeaderRejectSender::KnownPeer => {
                self.sender_known_peer.fetch_add(1, Ordering::Relaxed);
            }
            RuntimeInternalHeaderRejectSender::LocalNode => {
                self.sender_local_node.fetch_add(1, Ordering::Relaxed);
            }
            RuntimeInternalHeaderRejectSender::UnknownPeer => {
                self.sender_unknown_peer.fetch_add(1, Ordering::Relaxed);
            }
            RuntimeInternalHeaderRejectSender::MissingOrInvalid => {
                self.sender_missing_or_invalid
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn snapshot(&self) -> RuntimeInternalHeaderRejectDimensionsSnapshot {
        RuntimeInternalHeaderRejectDimensionsSnapshot {
            total: self.total.load(Ordering::Relaxed),
            endpoint_api: self.endpoint_api.load(Ordering::Relaxed),
            endpoint_healthz: self.endpoint_healthz.load(Ordering::Relaxed),
            endpoint_metrics: self.endpoint_metrics.load(Ordering::Relaxed),
            endpoint_ui: self.endpoint_ui.load(Ordering::Relaxed),
            endpoint_other: self.endpoint_other.load(Ordering::Relaxed),
            sender_known_peer: self.sender_known_peer.load(Ordering::Relaxed),
            sender_local_node: self.sender_local_node.load(Ordering::Relaxed),
            sender_unknown_peer: self.sender_unknown_peer.load(Ordering::Relaxed),
            sender_missing_or_invalid: self.sender_missing_or_invalid.load(Ordering::Relaxed),
        }
    }
}

impl RuntimeTopologySnapshot {
    pub fn cluster_peer_count(&self) -> usize {
        self.cluster_peers.len()
    }

    pub fn membership_node_count(&self) -> usize {
        self.membership_nodes.len()
    }

    pub fn is_distributed(&self) -> bool {
        self.mode == RuntimeMode::Distributed
    }
}

fn membership_apply_serialization_lock() -> &'static tokio::sync::Mutex<()> {
    static MEMBERSHIP_APPLY_SERIALIZATION_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    MEMBERSHIP_APPLY_SERIALIZATION_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

impl AppState {
    pub fn active_cluster_peers(&self) -> Vec<String> {
        match self.membership_peers.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    pub fn active_membership_view_id(&self) -> String {
        match self.membership_view_id.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    pub fn placement_epoch(&self) -> u64 {
        self.placement_epoch.load(Ordering::Relaxed)
    }

    pub async fn apply_membership_peers(
        &self,
        next_cluster_peers: Vec<String>,
    ) -> anyhow::Result<MembershipUpdateApplyOutcome> {
        // Serialize in-process membership applies so placement epoch/view persistence is monotonic.
        let _membership_apply_guard = membership_apply_serialization_lock().lock().await;
        let normalized_view_id =
            membership_view_id_with_self(self.node_id.as_str(), next_cluster_peers.as_slice());
        let previous_view_id = self.active_membership_view_id();
        let changed = normalized_view_id != previous_view_id;
        let placement_epoch =
            load_or_bootstrap_placement_epoch(self.config.data_dir.as_str(), &normalized_view_id)
                .await?;
        let membership_status = self.membership_engine.status();
        let convergence_seed = seeded_membership_convergence(
            self.membership_protocol,
            membership_status.ready,
            next_cluster_peers.as_slice(),
            membership_status.converged,
        );
        self.placement_epoch
            .store(placement_epoch, Ordering::Relaxed);
        match self.membership_peers.write() {
            Ok(mut guard) => {
                *guard = next_cluster_peers;
            }
            Err(poisoned) => {
                *poisoned.into_inner() = next_cluster_peers;
            }
        }
        match self.membership_view_id.write() {
            Ok(mut guard) => {
                *guard = normalized_view_id.clone();
            }
            Err(poisoned) => {
                *poisoned.into_inner() = normalized_view_id.clone();
            }
        }
        let observed_last_update_unix_ms = unix_ms_now();
        self.membership_last_update_unix_ms
            .fetch_max(observed_last_update_unix_ms, Ordering::Relaxed);
        record_membership_convergence(self, convergence_seed);
        Ok(MembershipUpdateApplyOutcome {
            changed,
            placement_epoch,
            membership_view_id: normalized_view_id,
            membership_last_update_unix_ms: observed_last_update_unix_ms,
        })
    }

    /// Construct the shared runtime state from a parsed config.
    pub async fn from_config(config: Config) -> anyhow::Result<Self> {
        let credentials = config.credential_map().map_err(anyhow::Error::msg)?;
        let cluster_peers = config.parsed_cluster_peers().map_err(anyhow::Error::msg)?;
        let configured_cluster_id = config.configured_cluster_id().map_err(anyhow::Error::msg)?;
        let node_id = config.node_id.clone();
        let membership_view_id = membership_view_id_with_self(node_id.as_str(), &cluster_peers);
        let cluster_id_seed = configured_cluster_id
            .as_deref()
            .unwrap_or(membership_view_id.as_str());
        let cluster_id =
            load_or_bootstrap_cluster_id(config.data_dir.as_str(), cluster_id_seed).await?;
        validate_cluster_id_binding(cluster_id.as_str(), configured_cluster_id.as_deref())?;
        let placement_epoch =
            load_or_bootstrap_placement_epoch(config.data_dir.as_str(), &membership_view_id)
                .await?;
        let membership_protocol = config.membership_protocol;
        let write_durability_mode = config.write_durability_mode;
        let metadata_listing_strategy = config.metadata_listing_strategy;
        let membership_engine = MembershipEngine::for_protocol(membership_protocol);
        let membership_status = membership_engine.status();
        let membership_last_update_unix_ms =
            Arc::new(AtomicU64::new(membership_status.last_update_unix_ms));
        let membership_converged = Arc::new(AtomicU64::new(
            if seeded_membership_convergence(
                membership_protocol,
                membership_status.ready,
                cluster_peers.as_slice(),
                membership_status.converged,
            ) {
                1
            } else {
                0
            },
        ));
        let storage = FilesystemStorage::new(
            &config.data_dir,
            config.erasure_coding,
            config.chunk_size,
            config.parity_shards,
        )
        .await?;

        Ok(Self {
            storage: Arc::new(storage),
            config: Arc::new(config),
            credentials: Arc::new(credentials),
            node_id: Arc::new(node_id),
            cluster_id: Arc::new(cluster_id),
            membership_peers: Arc::new(RwLock::new(cluster_peers.clone())),
            membership_view_id: Arc::new(RwLock::new(membership_view_id)),
            cluster_peers: Arc::new(cluster_peers),
            membership_protocol,
            write_durability_mode,
            metadata_listing_strategy,
            membership_engine,
            membership_last_update_unix_ms,
            membership_converged,
            join_nonce_replay_guard: Arc::new(InMemoryJoinNonceReplayGuard::new(
                JOIN_NONCE_REPLAY_GUARD_TTL_MS,
                JOIN_NONCE_REPLAY_GUARD_MAX_ENTRIES,
            )),
            cluster_join_authorize_counters: Arc::new(ClusterJoinAuthorizeCounters::default()),
            cluster_join_counters: Arc::new(ClusterJoinCounters::default()),
            cluster_membership_update_counters: Arc::new(ClusterMembershipUpdateCounters::default()),
            pending_replication_replay_counters: Arc::new(
                PendingReplicationReplayCounters::default(),
            ),
            pending_rebalance_replay_counters: Arc::new(PendingRebalanceReplayCounters::default()),
            pending_membership_propagation_replay_counters: Arc::new(
                PendingMembershipPropagationReplayCounters::default(),
            ),
            pending_metadata_repair_replay_counters: Arc::new(
                PendingMetadataRepairReplayCounters::default(),
            ),
            placement_epoch: Arc::new(AtomicU64::new(placement_epoch)),
            runtime_internal_header_reject_dimensions: Arc::new(
                RuntimeInternalHeaderRejectDimensions::default(),
            ),
            login_rate_limiter: Arc::new(LoginRateLimiter::new()),
            request_count: Arc::new(AtomicU64::new(0)),
            started_at: Instant::now(),
        })
    }
}

pub fn runtime_topology_snapshot(state: &AppState) -> RuntimeTopologySnapshot {
    let node_id = state.node_id.as_ref().clone();
    let cluster_peers = state.active_cluster_peers();
    let membership_nodes = membership_with_self(node_id.as_str(), &cluster_peers);
    let mode = if cluster_peers.is_empty() {
        RuntimeMode::Standalone
    } else {
        RuntimeMode::Distributed
    };
    let membership_view_id = state.active_membership_view_id();
    let placement_epoch = state.placement_epoch();
    let observed_membership_last_update_unix_ms =
        state.membership_last_update_unix_ms.load(Ordering::Relaxed);
    let mut membership_status = state
        .membership_engine
        .status_with_last_update(observed_membership_last_update_unix_ms);
    if membership_protocol_uses_probe_convergence(
        state.membership_protocol,
        membership_status.ready,
    ) {
        membership_status.converged = state.membership_converged.load(Ordering::Relaxed) > 0;
    }

    RuntimeTopologySnapshot {
        mode,
        node_id,
        cluster_id: state.cluster_id.as_ref().clone(),
        cluster_peers,
        membership_nodes,
        membership_protocol: state.membership_protocol,
        membership_status,
        membership_view_id,
        placement_epoch,
    }
}

fn s3_routes(state: AppState) -> Router<AppState> {
    s3_router().layer(axum::middleware::from_fn_with_state(state, auth_middleware))
}

fn platform_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .nest("/api", console_router(state.clone()))
        .route("/healthz", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .route("/ui", get(ui_handler))
        .route("/ui/", get(ui_handler))
        .route("/ui/{*path}", get(ui_handler))
        .layer(axum::middleware::from_fn_with_state(
            state,
            internal_forwarding_sanitization_middleware,
        ))
}

fn internal_cluster_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/internal/cluster/join/authorize",
            post(cluster_join_authorize_handler),
        )
        .route("/internal/cluster/join", post(cluster_join_handler))
        .route(
            "/internal/cluster/membership/update",
            post(cluster_membership_update_handler),
        )
}

fn apply_runtime_middleware(state: AppState, routes: Router<AppState>) -> Router {
    routes
        .layer(axum::middleware::from_fn(cors_middleware))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            request_id_middleware,
        ))
        .with_state(state)
}

pub fn build_public_router(state: AppState) -> Router {
    let routes = Router::new()
        .merge(platform_routes(state.clone()))
        .merge(s3_routes(state.clone()));
    apply_runtime_middleware(state, routes)
}

pub fn build_internal_router(state: AppState) -> Router {
    apply_runtime_middleware(state, internal_cluster_routes())
}

pub fn build_router(state: AppState) -> Router {
    let routes = Router::new()
        .merge(platform_routes(state.clone()))
        .merge(internal_cluster_routes())
        .merge(s3_routes(state.clone()));
    apply_runtime_middleware(state, routes)
}

impl HealthPayload {
    pub(crate) fn membership_protocol_ready(&self) -> bool {
        self.checks.membership_protocol_ready
    }

    pub(crate) fn membership_converged(&self) -> bool {
        self.checks.membership_converged
    }

    pub(crate) fn membership_convergence_reason(&self) -> &str {
        self.membership_convergence_reason.as_str()
    }
}

#[derive(Debug)]
struct DataDirProbeResult {
    accessible: bool,
    writable: bool,
    warning: Option<String>,
}

#[derive(Debug)]
struct StorageDataPathProbeResult {
    readable: bool,
    warning: Option<String>,
}

#[derive(Debug)]
struct DiskHeadroomProbeResult {
    sufficient: bool,
    warning: Option<String>,
}

#[derive(Debug)]
struct PendingReplicationQueueProbeResult {
    readable: bool,
    summary: PendingReplicationQueueSummary,
    due_targets: usize,
    due_targets_capped: bool,
    warning: Option<String>,
}

#[derive(Debug)]
struct PendingRebalanceQueueProbeResult {
    readable: bool,
    summary: PendingRebalanceQueueSummary,
    due_transfers: usize,
    due_transfers_capped: bool,
    warning: Option<String>,
}

#[derive(Debug)]
struct PendingMembershipPropagationQueueProbeSummary {
    operations: usize,
    failed_operations: usize,
    max_attempts: u32,
    oldest_created_at_unix_ms: Option<u64>,
}

#[derive(Debug)]
struct PendingMembershipPropagationQueueProbeResult {
    readable: bool,
    summary: PendingMembershipPropagationQueueProbeSummary,
    due_operations: usize,
    due_operations_capped: bool,
    warning: Option<String>,
}

#[derive(Debug)]
struct PendingMetadataRepairQueueProbeResult {
    readable: bool,
    summary: PendingMetadataRepairQueueSummary,
    due_plans: usize,
    due_plans_capped: bool,
    warning: Option<String>,
}

#[derive(Debug)]
struct PersistedMetadataStateProbeResult {
    readable: bool,
    queryable: bool,
    view_id: String,
    bucket_rows: usize,
    object_rows: usize,
    object_version_rows: usize,
    warning: Option<String>,
}

#[derive(Debug)]
struct PeerConnectivityProbeResult {
    ready: bool,
    warning: Option<String>,
    peer_views: Vec<PeerViewObservation>,
    failed_peers: Vec<String>,
}

#[derive(Debug, Clone)]
struct PeerViewObservation {
    peer: String,
    membership_view_id: Option<String>,
    placement_epoch: Option<u64>,
    cluster_id: Option<String>,
    cluster_peers: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct GossipStalePeerReconciliationTarget {
    peer: String,
    expected_membership_view_id: String,
    expected_placement_epoch: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PeerHealthProbePayload {
    membership_view_id: Option<String>,
    placement_epoch: Option<u64>,
    cluster_id: Option<String>,
    #[serde(default)]
    cluster_peers: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default)]
struct RebalanceQueuePopulationSummary {
    scanned_buckets: usize,
    scanned_objects: usize,
    inserted_operations: usize,
    already_tracked_operations: usize,
    failed_operations: usize,
}

#[derive(Debug)]
struct MembershipConvergenceProbeResult {
    converged: bool,
    reason: &'static str,
    warning: Option<String>,
    observed_at_unix_ms: u64,
}

#[derive(Debug)]
struct ClusterPeerAuthStatus {
    configured: bool,
    mode: &'static str,
    trust_model: &'static str,
    transport_identity: &'static str,
    transport_reason: &'static str,
    transport_ready: bool,
    identity_bound: bool,
    sender_allowlist_bound: bool,
    warning: Option<String>,
}

#[derive(Debug)]
struct ClusterJoinAuthStatus {
    mode: &'static str,
    ready: bool,
    reason: &'static str,
    warning: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClusterJoinAuthorizePayload {
    authorized: bool,
    status: String,
    mode: String,
    reason: String,
    peer_node_id: Option<String>,
    cluster_id: String,
    membership_view_id: String,
    local_node_id: String,
    placement_epoch: u64,
}

#[derive(Debug, Clone)]
pub struct MembershipUpdateApplyOutcome {
    pub changed: bool,
    pub placement_epoch: u64,
    pub membership_view_id: String,
    pub membership_last_update_unix_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClusterJoinRequest {
    #[serde(default)]
    expected_membership_view_id: Option<String>,
    #[serde(default)]
    expected_placement_epoch: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
struct ClusterMembershipUpdateRequest {
    cluster_id: String,
    cluster_peers: Vec<String>,
    #[serde(default)]
    expected_membership_view_id: Option<String>,
    #[serde(default)]
    expected_placement_epoch: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
struct PendingMembershipPropagationOperation {
    peer: String,
    request: ClusterMembershipUpdateRequest,
    attempts: u32,
    created_at_unix_ms: u64,
    updated_at_unix_ms: u64,
    #[serde(default)]
    next_retry_at_unix_ms: Option<u64>,
    #[serde(default)]
    last_error: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
struct PendingMembershipPropagationQueue {
    #[serde(default)]
    operations: Vec<PendingMembershipPropagationOperation>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
struct PendingMembershipPropagationReplaySummary {
    scanned: usize,
    replayed: usize,
    deferred: usize,
    acknowledged: usize,
    failed: usize,
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
struct PendingMembershipPropagationReplayWorkset {
    replay_due_operations: Vec<PendingMembershipPropagationOperation>,
    retained_operations: Vec<PendingMembershipPropagationOperation>,
    scanned_operations: usize,
    deferred_due_operations: usize,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum PendingMembershipPropagationReplayOperationOutcome {
    Acknowledged {
        original: PendingMembershipPropagationOperation,
    },
    Failed {
        original: PendingMembershipPropagationOperation,
        retry: PendingMembershipPropagationOperation,
    },
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct MembershipPropagationPeerResult {
    peer: String,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClusterMembershipUpdatePayload {
    status: String,
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_reason: Option<String>,
    mode: String,
    updated: bool,
    cluster_id: String,
    local_node_id: String,
    cluster_peers: Vec<String>,
    membership_view_id: String,
    placement_epoch: u64,
    membership_last_update_unix_ms: u64,
}

fn membership_update_response(
    state: &AppState,
    status: StatusCode,
    payload: ClusterMembershipUpdatePayload,
) -> Response {
    state
        .cluster_membership_update_counters
        .record(payload.status.as_str(), payload.reason.as_str());
    response_with_content_type(
        status,
        HeaderValue::from_static("application/json"),
        axum::body::Body::from(
            serde_json::to_vec(&payload)
                .unwrap_or_else(|_| b"{\"status\":\"degraded\",\"updated\":false}".to_vec()),
        ),
    )
}

fn cluster_join_response(
    state: &AppState,
    status: StatusCode,
    payload: ClusterMembershipUpdatePayload,
) -> Response {
    state
        .cluster_join_counters
        .record(payload.status.as_str(), payload.reason.as_str());
    response_with_content_type(
        status,
        HeaderValue::from_static("application/json"),
        axum::body::Body::from(
            serde_json::to_vec(&payload)
                .unwrap_or_else(|_| b"{\"status\":\"degraded\",\"updated\":false}".to_vec()),
        ),
    )
}

fn peer_identity_eq(lhs: &str, rhs: &str) -> bool {
    lhs.trim().eq_ignore_ascii_case(rhs.trim())
}

fn normalize_cluster_peers_for_membership_update(
    local_node_id: &str,
    peers: &[String],
) -> Result<Vec<String>, String> {
    let mut normalized: Vec<String> = Vec::new();
    for peer in peers {
        let value = peer.trim();
        if value.is_empty() {
            continue;
        }
        let (host, port) = value
            .rsplit_once(':')
            .ok_or_else(|| format!("Invalid cluster peer '{}': expected host:port", value))?;
        let host = host.trim();
        let port = port.trim();
        if host.is_empty() {
            return Err(format!(
                "Invalid cluster peer '{}': host must be non-empty",
                value
            ));
        }
        let parsed_port = port
            .parse::<u16>()
            .map_err(|_| format!("Invalid cluster peer '{}': invalid port", value))?;
        if parsed_port == 0 {
            return Err(format!(
                "Invalid cluster peer '{}': port must be between 1 and 65535",
                value
            ));
        }
        let normalized_peer = format!("{host}:{parsed_port}");
        if peer_identity_eq(normalized_peer.as_str(), local_node_id) {
            return Err(format!(
                "Invalid cluster peer '{}': peer must not match local node id",
                normalized_peer
            ));
        }
        if !normalized
            .iter()
            .any(|entry| peer_identity_eq(entry.as_str(), normalized_peer.as_str()))
        {
            normalized.push(normalized_peer);
        }
    }
    Ok(normalized)
}

fn membership_update_precondition_failed(
    topology: &RuntimeTopologySnapshot,
    expected_membership_view_id: Option<&str>,
    expected_placement_epoch: Option<u64>,
) -> bool {
    expected_membership_view_id
        .is_some_and(|expected| expected != topology.membership_view_id.as_str())
        || expected_placement_epoch.is_some_and(|expected| expected != topology.placement_epoch)
}

struct PeerHttpTransport {
    client: reqwest::Client,
    scheme: &'static str,
}

fn build_peer_http_transport(
    config: Option<&Config>,
    timeout: Duration,
) -> Result<PeerHttpTransport, String> {
    let mut builder = reqwest::Client::builder().timeout(timeout);
    let mut scheme = "http";

    if let Some(config) = config {
        let expected_node_id = config.cluster_auth_token().map(|_| config.node_id.as_str());
        let identity_status =
            probe_peer_transport_identity_with_cert_sha256_pin_and_node_id_binding(
                config.cluster_peer_tls_cert_path(),
                config.cluster_peer_tls_key_path(),
                config.cluster_peer_tls_ca_path(),
                config.cluster_peer_tls_cert_sha256(),
                expected_node_id,
            );
        if identity_status.mode.as_str() == "mtls-path" {
            if !identity_status.transport_ready {
                let warning = identity_status.warning.as_deref().unwrap_or(
                    "mTLS peer transport identity is not ready with current configuration",
                );
                return Err(format!(
                    "mTLS peer transport is not ready ({}): {}",
                    identity_status.reason.as_str(),
                    warning
                ));
            }

            let ca_path = config.cluster_peer_tls_ca_path().ok_or_else(|| {
                "mTLS peer transport requires cluster peer CA trust-store path".to_string()
            })?;

            let ca_bytes = std::fs::read(ca_path).map_err(|err| {
                format!(
                    "failed to read mTLS peer trust store '{}': {}",
                    ca_path, err
                )
            })?;
            let ca_certificate = reqwest::Certificate::from_pem(&ca_bytes)
                .map_err(|err| format!("failed to parse mTLS trust-store PEM: {err}"))?;
            let cert_path = config.cluster_peer_tls_cert_path().ok_or_else(|| {
                "mTLS peer transport requires cluster peer certificate path".to_string()
            })?;
            let key_path = config.cluster_peer_tls_key_path().ok_or_else(|| {
                "mTLS peer transport requires cluster peer private key path".to_string()
            })?;
            let cert_pem = std::fs::read(cert_path).map_err(|err| {
                format!(
                    "failed to read mTLS peer certificate '{}': {}",
                    cert_path, err
                )
            })?;
            let key_pem = std::fs::read(key_path).map_err(|err| {
                format!(
                    "failed to read mTLS peer private key '{}': {}",
                    key_path, err
                )
            })?;
            let identity =
                reqwest::Identity::from_pkcs8_pem(cert_pem.as_slice(), key_pem.as_slice())
                    .map_err(|err| {
                        format!("failed to parse mTLS certificate/key identity PEM: {err}")
                    })?;

            builder = builder.add_root_certificate(ca_certificate);
            builder = builder.identity(identity);
            scheme = "https";
        }
    }

    let client = builder
        .build()
        .map_err(|err| format!("peer HTTP client initialization failed: {err}"))?;

    Ok(PeerHttpTransport { client, scheme })
}

fn attest_peer_http_target(
    config: Option<&Config>,
    peer: &str,
    timeout: Duration,
) -> Result<(), String> {
    let Some(config) = config else {
        return Ok(());
    };

    let expected_node_id = config.cluster_auth_token().map(|_| config.node_id.as_str());
    let identity_status = probe_peer_transport_identity_with_cert_sha256_pin_and_node_id_binding(
        config.cluster_peer_tls_cert_path(),
        config.cluster_peer_tls_key_path(),
        config.cluster_peer_tls_ca_path(),
        config.cluster_peer_tls_cert_sha256(),
        expected_node_id,
    );
    if identity_status.mode.as_str() != "mtls-path" {
        return Ok(());
    }
    if !identity_status.transport_ready {
        let warning = identity_status
            .warning
            .as_deref()
            .unwrap_or("mTLS peer transport identity is not ready with current configuration");
        return Err(format!(
            "mTLS peer transport is not ready ({}): {}",
            identity_status.reason.as_str(),
            warning
        ));
    }

    let cert_path = config
        .cluster_peer_tls_cert_path()
        .ok_or_else(|| "mTLS peer transport requires cluster peer certificate path".to_string())?;
    let key_path = config
        .cluster_peer_tls_key_path()
        .ok_or_else(|| "mTLS peer transport requires cluster peer private key path".to_string())?;
    let trust_store_path = config.cluster_peer_tls_ca_path().ok_or_else(|| {
        "mTLS peer transport requires cluster peer CA trust-store path".to_string()
    })?;

    attest_peer_transport_identity_with_mtls(
        peer,
        peer,
        cert_path,
        key_path,
        trust_store_path,
        timeout,
    )
    .map_err(|error| {
        format!(
            "mTLS peer attestation to '{}' failed ({})",
            peer,
            error.as_str()
        )
    })
}

fn is_membership_update_propagation_request(headers: &HeaderMap) -> bool {
    headers
        .get(INTERNAL_MEMBERSHIP_PROPAGATED_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim() == MEMBERSHIP_UPDATE_PROPAGATION_HEADER_VALUE)
}

fn spawn_membership_update_propagation(
    config: Arc<Config>,
    previous_topology: &RuntimeTopologySnapshot,
    updated_topology: &RuntimeTopologySnapshot,
    cluster_auth_token: Option<&str>,
) {
    let Some(cluster_auth_token) = cluster_auth_token.map(str::to_string) else {
        return;
    };
    let target_peers = membership_propagation_target_peers(
        previous_topology,
        updated_topology,
        &updated_topology.node_id,
    );
    if target_peers.is_empty() {
        return;
    }

    let request = ClusterMembershipUpdateRequest {
        cluster_id: updated_topology.cluster_id.clone(),
        cluster_peers: updated_topology.cluster_peers.clone(),
        expected_membership_view_id: Some(previous_topology.membership_view_id.clone()),
        expected_placement_epoch: Some(previous_topology.placement_epoch),
    };
    let local_node_id = updated_topology.node_id.clone();
    let cluster_id = updated_topology.cluster_id.clone();

    tokio::spawn(async move {
        let results = propagate_membership_update_to_peers(
            config.as_ref(),
            local_node_id.as_str(),
            cluster_id.as_str(),
            cluster_auth_token.as_str(),
            target_peers.as_slice(),
            &request,
        )
        .await;
        for result in results {
            if let Some(error) = result.error.as_deref() {
                if let Err(queue_error) = record_pending_membership_propagation_failure(
                    config.data_dir.as_str(),
                    result.peer.as_str(),
                    &request,
                    Some(error),
                )
                .await
                {
                    tracing::warn!(
                        peer = result.peer.as_str(),
                        error = ?queue_error,
                        "Failed to persist pending membership propagation operation"
                    );
                }
            }
        }
    });
}

fn spawn_gossip_stale_peer_reconciliation(
    config: Arc<Config>,
    topology: &RuntimeTopologySnapshot,
    stale_targets: &[GossipStalePeerReconciliationTarget],
    cluster_auth_token: Option<&str>,
) {
    let Some(cluster_auth_token) = cluster_auth_token.map(str::to_string) else {
        return;
    };
    if stale_targets.is_empty() {
        return;
    }

    let local_node_id = topology.node_id.clone();
    let cluster_id = topology.cluster_id.clone();
    let cluster_peers = topology.cluster_peers.clone();
    let stale_targets = stale_targets.to_vec();

    tokio::spawn(async move {
        let transport = match build_peer_http_transport(
            Some(config.as_ref()),
            Duration::from_secs(MEMBERSHIP_UPDATE_PROPAGATION_TIMEOUT_SECS),
        ) {
            Ok(transport) => transport,
            Err(error) => {
                tracing::warn!(
                    "Gossip stale-peer reconciliation client initialization failed: {}",
                    error
                );
                return;
            }
        };
        let context = MembershipPropagationContext {
            config: Some(config.as_ref()),
            client: &transport.client,
            scheme: transport.scheme,
            local_node_id: local_node_id.as_str(),
            cluster_id: cluster_id.as_str(),
            cluster_auth_token: cluster_auth_token.as_str(),
        };
        for target in stale_targets {
            let request = ClusterMembershipUpdateRequest {
                cluster_id: cluster_id.clone(),
                cluster_peers: cluster_peers.clone(),
                expected_membership_view_id: Some(target.expected_membership_view_id.clone()),
                expected_placement_epoch: Some(target.expected_placement_epoch),
            };
            if let Err(error) =
                propagate_membership_update_to_peer(&context, target.peer.as_str(), &request).await
            {
                tracing::warn!(
                    peer = target.peer.as_str(),
                    expected_view = target.expected_membership_view_id.as_str(),
                    expected_epoch = target.expected_placement_epoch,
                    error,
                    "Gossip stale-peer reconciliation update failed"
                );
            }
        }
    });
}

fn membership_propagation_target_peers(
    previous_topology: &RuntimeTopologySnapshot,
    updated_topology: &RuntimeTopologySnapshot,
    local_node_id: &str,
) -> Vec<String> {
    let mut target_peers: Vec<String> = Vec::new();
    for peer in updated_topology
        .cluster_peers
        .iter()
        .chain(previous_topology.cluster_peers.iter())
    {
        if peer.trim().is_empty() || peer_identity_eq(peer.as_str(), local_node_id) {
            continue;
        }
        if target_peers
            .iter()
            .any(|existing| peer_identity_eq(existing.as_str(), peer.as_str()))
        {
            continue;
        }
        target_peers.push(peer.clone());
    }
    target_peers
}

async fn propagate_membership_update_to_peers(
    config: &Config,
    local_node_id: &str,
    cluster_id: &str,
    cluster_auth_token: &str,
    target_peers: &[String],
    request: &ClusterMembershipUpdateRequest,
) -> Vec<MembershipPropagationPeerResult> {
    let target_peers = target_peers
        .iter()
        .filter(|peer| !peer_identity_eq(peer.as_str(), local_node_id))
        .cloned()
        .collect::<Vec<_>>();
    if target_peers.is_empty() {
        return Vec::new();
    }

    let transport = match build_peer_http_transport(
        Some(config),
        Duration::from_secs(MEMBERSHIP_UPDATE_PROPAGATION_TIMEOUT_SECS),
    ) {
        Ok(transport) => transport,
        Err(err) => {
            tracing::warn!(
                "Membership propagation client initialization failed: {}",
                err
            );
            return target_peers
                .into_iter()
                .map(|peer| MembershipPropagationPeerResult {
                    peer,
                    error: Some(err.clone()),
                })
                .collect();
        }
    };
    let mut results = Vec::with_capacity(target_peers.len());
    let propagation_context = MembershipPropagationContext {
        config: Some(config),
        client: &transport.client,
        scheme: transport.scheme,
        local_node_id,
        cluster_id,
        cluster_auth_token,
    };
    for peer in target_peers {
        match propagate_membership_update_to_peer(&propagation_context, peer.as_str(), request)
            .await
        {
            Ok(()) => results.push(MembershipPropagationPeerResult { peer, error: None }),
            Err(error) => results.push(MembershipPropagationPeerResult {
                peer,
                error: Some(error),
            }),
        }
    }
    results
}

struct MembershipPropagationContext<'a> {
    config: Option<&'a Config>,
    client: &'a reqwest::Client,
    scheme: &'a str,
    local_node_id: &'a str,
    cluster_id: &'a str,
    cluster_auth_token: &'a str,
}

async fn propagate_membership_update_to_peer(
    context: &MembershipPropagationContext<'_>,
    peer: &str,
    request: &ClusterMembershipUpdateRequest,
) -> Result<(), String> {
    attest_peer_http_target(
        context.config,
        peer,
        Duration::from_secs(MEMBERSHIP_UPDATE_PROPAGATION_TIMEOUT_SECS),
    )
    .map_err(|error| {
        format!(
            "membership propagation preflight failed for '{}': {}",
            peer, error
        )
    })?;

    let url = format!(
        "{}://{peer}/internal/cluster/membership/update",
        context.scheme
    );
    for attempt in 1..=MEMBERSHIP_UPDATE_PROPAGATION_MAX_ATTEMPTS {
        let timestamp = unix_ms_now().to_string();
        let nonce = uuid::Uuid::new_v4().to_string();
        let response = context
            .client
            .post(url.as_str())
            .header(FORWARDED_BY_HEADER, context.local_node_id)
            .header(INTERNAL_AUTH_TOKEN_HEADER, context.cluster_auth_token)
            .header(JOIN_CLUSTER_ID_HEADER, context.cluster_id)
            .header(JOIN_NODE_ID_HEADER, context.local_node_id)
            .header(JOIN_TIMESTAMP_HEADER, timestamp.as_str())
            .header(JOIN_NONCE_HEADER, nonce.as_str())
            .header(
                INTERNAL_MEMBERSHIP_PROPAGATED_HEADER,
                MEMBERSHIP_UPDATE_PROPAGATION_HEADER_VALUE,
            )
            .json(request)
            .send()
            .await;
        match response {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) => {
                let status = response.status();
                if should_retry_membership_propagation_status(status)
                    && attempt < MEMBERSHIP_UPDATE_PROPAGATION_MAX_ATTEMPTS
                {
                    let retry_delay_ms = membership_propagation_retry_delay_ms(attempt);
                    tracing::warn!(
                        peer,
                        attempt,
                        max_attempts = MEMBERSHIP_UPDATE_PROPAGATION_MAX_ATTEMPTS,
                        status = status.as_u16(),
                        retry_delay_ms,
                        "Membership propagation attempt failed; retrying"
                    );
                    tokio::time::sleep(Duration::from_millis(retry_delay_ms)).await;
                    continue;
                }

                tracing::warn!(
                    peer,
                    attempt,
                    max_attempts = MEMBERSHIP_UPDATE_PROPAGATION_MAX_ATTEMPTS,
                    status = status.as_u16(),
                    "Membership propagation failed"
                );
                return Err(format!(
                    "membership propagation to peer '{}' failed with HTTP status {}",
                    peer,
                    status.as_u16()
                ));
            }
            Err(error) => {
                if attempt < MEMBERSHIP_UPDATE_PROPAGATION_MAX_ATTEMPTS {
                    let retry_delay_ms = membership_propagation_retry_delay_ms(attempt);
                    tracing::warn!(
                        peer,
                        attempt,
                        max_attempts = MEMBERSHIP_UPDATE_PROPAGATION_MAX_ATTEMPTS,
                        retry_delay_ms,
                        error = ?error,
                        "Membership propagation transport attempt failed; retrying"
                    );
                    tokio::time::sleep(Duration::from_millis(retry_delay_ms)).await;
                    continue;
                }

                tracing::warn!(
                    peer,
                    attempt,
                    max_attempts = MEMBERSHIP_UPDATE_PROPAGATION_MAX_ATTEMPTS,
                    error = ?error,
                    "Membership propagation failed after retries"
                );
                return Err(format!(
                    "membership propagation to peer '{}' failed after retries: {}",
                    peer, error
                ));
            }
        }
    }
    Err(format!(
        "membership propagation to peer '{}' did not complete",
        peer
    ))
}

async fn replay_pending_membership_propagation_backlog_once(
    state: &AppState,
) -> std::io::Result<PendingMembershipPropagationReplaySummary> {
    if state.active_cluster_peers().is_empty() {
        return Ok(PendingMembershipPropagationReplaySummary::default());
    }
    let Some(cluster_auth_token) = state.config.cluster_auth_token() else {
        return Ok(PendingMembershipPropagationReplaySummary::default());
    };

    let queue_path = pending_membership_propagation_queue_path(state.config.data_dir.as_str());
    let queue = load_pending_membership_propagation_queue(queue_path.as_path()).await?;
    if queue.operations.is_empty() {
        return Ok(PendingMembershipPropagationReplaySummary::default());
    }

    let transport = build_peer_http_transport(
        Some(state.config.as_ref()),
        Duration::from_secs(MEMBERSHIP_UPDATE_PROPAGATION_TIMEOUT_SECS),
    )
    .map_err(std::io::Error::other)?;
    let now_unix_ms = unix_ms_now();
    let workset = build_pending_membership_propagation_replay_workset(
        queue.operations,
        now_unix_ms,
        PENDING_MEMBERSHIP_PROPAGATION_REPLAY_BATCH_SIZE,
    );
    let mut summary = PendingMembershipPropagationReplaySummary {
        scanned: workset.scanned_operations,
        replayed: workset.replay_due_operations.len(),
        deferred: workset.deferred_due_operations,
        ..PendingMembershipPropagationReplaySummary::default()
    };
    let mut replay_outcomes = Vec::with_capacity(workset.replay_due_operations.len());
    let propagation_context = MembershipPropagationContext {
        config: Some(state.config.as_ref()),
        client: &transport.client,
        scheme: transport.scheme,
        local_node_id: state.node_id.as_str(),
        cluster_id: state.cluster_id.as_str(),
        cluster_auth_token,
    };

    for mut operation in workset.replay_due_operations {
        let original_operation = operation.clone();
        match propagate_membership_update_to_peer(
            &propagation_context,
            operation.peer.as_str(),
            &operation.request,
        )
        .await
        {
            Ok(()) => {
                summary.acknowledged = summary.acknowledged.saturating_add(1);
                replay_outcomes.push(
                    PendingMembershipPropagationReplayOperationOutcome::Acknowledged {
                        original: original_operation,
                    },
                );
            }
            Err(error) => {
                summary.failed = summary.failed.saturating_add(1);
                operation.attempts = operation.attempts.saturating_add(1);
                operation.updated_at_unix_ms = now_unix_ms;
                operation.last_error = Some(error);
                operation.next_retry_at_unix_ms = Some(
                    now_unix_ms
                        .saturating_add(membership_propagation_retry_delay_ms(operation.attempts)),
                );
                replay_outcomes.push(PendingMembershipPropagationReplayOperationOutcome::Failed {
                    original: original_operation,
                    retry: operation,
                });
            }
        }
    }

    // Reload latest queue state before persisting replay results so concurrent enqueue/update
    // operations are not clobbered by a stale snapshot.
    let mut latest_queue = load_pending_membership_propagation_queue(queue_path.as_path()).await?;
    latest_queue.operations = apply_pending_membership_propagation_replay_outcomes(
        latest_queue.operations,
        replay_outcomes,
    );
    persist_pending_membership_propagation_queue(queue_path.as_path(), &latest_queue).await?;
    Ok(summary)
}

fn apply_pending_membership_propagation_replay_outcomes(
    mut operations: Vec<PendingMembershipPropagationOperation>,
    replay_outcomes: Vec<PendingMembershipPropagationReplayOperationOutcome>,
) -> Vec<PendingMembershipPropagationOperation> {
    for outcome in replay_outcomes {
        match outcome {
            PendingMembershipPropagationReplayOperationOutcome::Acknowledged { original } => {
                if let Some(index) = operations.iter().position(|operation| {
                    peer_identity_eq(operation.peer.as_str(), original.peer.as_str())
                }) {
                    if operations[index] == original {
                        operations.remove(index);
                    }
                }
            }
            PendingMembershipPropagationReplayOperationOutcome::Failed { original, retry } => {
                if let Some(index) = operations.iter().position(|operation| {
                    peer_identity_eq(operation.peer.as_str(), original.peer.as_str())
                }) {
                    if operations[index] == original {
                        operations[index] = retry;
                    }
                }
            }
        }
    }

    operations.sort_by(|left, right| {
        left.next_retry_at_unix_ms
            .unwrap_or(0)
            .cmp(&right.next_retry_at_unix_ms.unwrap_or(0))
            .then_with(|| left.attempts.cmp(&right.attempts))
            .then_with(|| left.created_at_unix_ms.cmp(&right.created_at_unix_ms))
            .then_with(|| left.peer.cmp(&right.peer))
    });
    operations
}

fn build_pending_membership_propagation_replay_workset(
    operations: Vec<PendingMembershipPropagationOperation>,
    now_unix_ms: u64,
    replay_batch_size: usize,
) -> PendingMembershipPropagationReplayWorkset {
    if operations.is_empty() {
        return PendingMembershipPropagationReplayWorkset::default();
    }

    let mut replay_due_operations = Vec::new();
    let mut retained_operations = Vec::new();
    for operation in operations {
        if operation
            .next_retry_at_unix_ms
            .is_some_and(|next_retry| next_retry > now_unix_ms)
        {
            retained_operations.push(operation);
            continue;
        }
        replay_due_operations.push(operation);
    }

    replay_due_operations.sort_by(|left, right| {
        left.attempts
            .cmp(&right.attempts)
            .then_with(|| {
                left.next_retry_at_unix_ms
                    .unwrap_or(0)
                    .cmp(&right.next_retry_at_unix_ms.unwrap_or(0))
            })
            .then_with(|| left.created_at_unix_ms.cmp(&right.created_at_unix_ms))
            .then_with(|| left.peer.cmp(&right.peer))
    });

    let mut deferred_due_operations = 0;
    if replay_due_operations.len() > replay_batch_size {
        let deferred_due = replay_due_operations.split_off(replay_batch_size);
        deferred_due_operations = deferred_due.len();
        retained_operations.extend(deferred_due);
    }

    PendingMembershipPropagationReplayWorkset {
        scanned_operations: replay_due_operations.len() + retained_operations.len(),
        replay_due_operations,
        retained_operations,
        deferred_due_operations,
    }
}

pub fn spawn_pending_membership_propagation_replay_worker(state: AppState) {
    if state.active_cluster_peers().is_empty() {
        return;
    }

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(
            PENDING_MEMBERSHIP_PROPAGATION_REPLAY_INTERVAL_SECS,
        ));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;
            match replay_pending_membership_propagation_backlog_once(&state).await {
                Ok(summary) => {
                    state
                        .pending_membership_propagation_replay_counters
                        .record_success(
                            summary.scanned,
                            summary.replayed,
                            summary.deferred,
                            summary.acknowledged,
                            summary.failed,
                        );
                    if summary.replayed > 0 {
                        tracing::info!(
                            scanned = summary.scanned,
                            replayed = summary.replayed,
                            deferred = summary.deferred,
                            acknowledged = summary.acknowledged,
                            failed = summary.failed,
                            "Pending membership propagation replay cycle completed"
                        );
                    }
                }
                Err(error) => {
                    state
                        .pending_membership_propagation_replay_counters
                        .record_failure();
                    tracing::warn!(
                        error = ?error,
                        "Pending membership propagation replay cycle failed"
                    );
                }
            }
        }
    });
}

fn should_retry_membership_propagation_status(status: StatusCode) -> bool {
    status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

fn membership_propagation_retry_delay_ms(attempt: u32) -> u64 {
    let shift = attempt.saturating_sub(1).min(20);
    let multiplier = 1_u64 << shift;
    MEMBERSHIP_UPDATE_PROPAGATION_RETRY_BASE_MS
        .saturating_mul(multiplier)
        .min(MEMBERSHIP_UPDATE_PROPAGATION_RETRY_MAX_MS)
}

fn spawn_rebalance_queue_population(
    state: &AppState,
    previous_topology: &RuntimeTopologySnapshot,
    updated_topology: &RuntimeTopologySnapshot,
) {
    if !updated_topology.is_distributed()
        || previous_topology.membership_view_id == updated_topology.membership_view_id
    {
        return;
    }

    let state = state.clone();
    let previous_topology = previous_topology.clone();
    let updated_topology = updated_topology.clone();
    tokio::spawn(async move {
        match enqueue_pending_rebalance_for_membership_transition(
            &state,
            &previous_topology,
            &updated_topology,
        )
        .await
        {
            Ok(summary) => {
                if summary.inserted_operations > 0 || summary.failed_operations > 0 {
                    tracing::info!(
                        scanned_buckets = summary.scanned_buckets,
                        scanned_objects = summary.scanned_objects,
                        inserted_operations = summary.inserted_operations,
                        already_tracked_operations = summary.already_tracked_operations,
                        failed_operations = summary.failed_operations,
                        membership_view_id = updated_topology.membership_view_id.as_str(),
                        placement_epoch = updated_topology.placement_epoch,
                        "Queued rebalance operations for membership transition"
                    );
                }
            }
            Err(error) => {
                tracing::warn!(
                    error = error.as_str(),
                    membership_view_id = updated_topology.membership_view_id.as_str(),
                    placement_epoch = updated_topology.placement_epoch,
                    "Failed to queue rebalance operations for membership transition"
                );
            }
        }
    });
}

async fn enqueue_pending_rebalance_for_membership_transition(
    state: &AppState,
    previous_topology: &RuntimeTopologySnapshot,
    updated_topology: &RuntimeTopologySnapshot,
) -> Result<RebalanceQueuePopulationSummary, String> {
    let replica_count = updated_topology
        .membership_nodes
        .len()
        .min(DISTRIBUTED_REBALANCE_REPLICA_TARGET);
    if replica_count == 0 {
        return Ok(RebalanceQueuePopulationSummary::default());
    }

    let placement = PlacementViewState {
        epoch: updated_topology.placement_epoch,
        node_id: updated_topology.node_id.clone(),
        members: updated_topology.membership_nodes.clone(),
        view_id: updated_topology.membership_view_id.clone(),
    };
    let queue_path = pending_rebalance_queue_path(state.config.data_dir.as_str());

    let mut summary = RebalanceQueuePopulationSummary::default();
    let buckets =
        state.storage.list_buckets().await.map_err(|error| {
            format!("list_buckets failed during rebalance queue planning: {error}")
        })?;
    for bucket in buckets {
        summary.scanned_buckets = summary.scanned_buckets.saturating_add(1);
        let objects = match state.storage.list_objects(bucket.name.as_str(), "").await {
            Ok(objects) => objects,
            Err(error) => {
                tracing::warn!(
                    bucket = bucket.name.as_str(),
                    error = ?error,
                    "Skipping rebalance planning for bucket after list_objects failure"
                );
                continue;
            }
        };

        for object in objects {
            summary.scanned_objects = summary.scanned_objects.saturating_add(1);
            let plan = object_rebalance_plan(
                object.key.as_str(),
                previous_topology.membership_nodes.as_slice(),
                updated_topology.membership_nodes.as_slice(),
                replica_count,
            );
            let local_actions = local_rebalance_actions(&plan, updated_topology.node_id.as_str());
            if local_actions.is_empty() {
                continue;
            }

            let transfers = local_actions
                .iter()
                .map(|action| match action {
                    LocalRebalanceAction::Receive { from, to } => RebalanceTransfer {
                        from: from.clone(),
                        to: to.clone(),
                    },
                    LocalRebalanceAction::Send { from, to } => RebalanceTransfer {
                        from: Some(from.clone()),
                        to: to.clone(),
                    },
                })
                .collect::<Vec<_>>();
            let rebalance_id = format!(
                "rebalance:{}:{}:{}:{}",
                updated_topology.placement_epoch,
                updated_topology.membership_view_id,
                bucket.name,
                object.key
            );
            let created_at_unix_ms = unix_ms_now();
            let Some(operation) = PendingRebalanceOperation::new(
                rebalance_id.as_str(),
                bucket.name.as_str(),
                object.key.as_str(),
                RebalanceObjectScope::Object,
                updated_topology.node_id.as_str(),
                &placement,
                transfers.as_slice(),
                created_at_unix_ms,
            ) else {
                continue;
            };

            match enqueue_pending_rebalance_operation_persisted(queue_path.as_path(), operation) {
                Ok(PendingRebalanceEnqueueOutcome::Inserted) => {
                    summary.inserted_operations = summary.inserted_operations.saturating_add(1);
                }
                Ok(PendingRebalanceEnqueueOutcome::AlreadyTracked) => {
                    summary.already_tracked_operations =
                        summary.already_tracked_operations.saturating_add(1);
                }
                Err(error) => {
                    summary.failed_operations = summary.failed_operations.saturating_add(1);
                    tracing::warn!(
                        bucket = bucket.name.as_str(),
                        key = object.key.as_str(),
                        error = ?error,
                        "Failed to persist pending rebalance operation"
                    );
                }
            }
        }
    }

    Ok(summary)
}

fn metadata_snapshot_for_topology(
    topology: &RuntimeTopologySnapshot,
    strategy: ClusterMetadataListingStrategy,
) -> ClusterMetadataSnapshotAssessment {
    let responder_nodes = [topology.node_id.clone()];
    assess_cluster_metadata_snapshot_for_topology_responders(
        strategy,
        Some(topology.membership_view_id.as_str()),
        topology.node_id.as_str(),
        topology.membership_nodes.as_slice(),
        responder_nodes.as_slice(),
    )
    .unwrap_or_else(|_| {
        assess_cluster_metadata_snapshot_for_topology_single_responder(
            strategy,
            Some(topology.membership_view_id.as_str()),
            topology.node_id.as_str(),
            topology.membership_nodes.as_slice(),
            topology.node_id.as_str(),
        )
    })
}

#[derive(Debug, Clone)]
struct RuntimeMetadataListingReadiness {
    cluster_authoritative: bool,
    ready: bool,
    gap: Option<String>,
}

fn runtime_metadata_listing_readiness_for_topology(
    state: &AppState,
    topology: &RuntimeTopologySnapshot,
    metadata_snapshot: &ClusterMetadataSnapshotAssessment,
) -> RuntimeMetadataListingReadiness {
    let readiness = &metadata_snapshot.readiness_assessment;
    let mut effective_ready = readiness.ready;
    let mut effective_gap = readiness.gap.map(|gap| gap.as_str().to_string());

    let consensus_peer_fan_in_transport_missing = topology.is_distributed()
        && state.metadata_listing_strategy == ClusterMetadataListingStrategy::ConsensusIndex
        && state
            .config
            .cluster_auth_token()
            .is_none_or(|value| value.trim().is_empty());
    if consensus_peer_fan_in_transport_missing {
        effective_ready = false;
        effective_gap = Some("consensus-index-peer-fan-in-auth-token-missing".to_string());
    }

    RuntimeMetadataListingReadiness {
        cluster_authoritative: readiness.cluster_authoritative,
        ready: effective_ready,
        gap: effective_gap,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use std::time::Instant;
    use tower::ServiceExt;

    use crate::cluster::join_authorization::InMemoryJoinNonceReplayGuard;
    use crate::config::{Config, MembershipProtocol, WriteDurabilityMode};
    use crate::membership::{MembershipEngine, MembershipEngineStatus};
    use crate::metadata::{
        ClusterMetadataListingStrategy, MetadataReconcileAction, MetadataRepairPlan,
        PendingMetadataRepairPlan, enqueue_pending_metadata_repair_plan_persisted,
    };
    use crate::storage::filesystem::FilesystemStorage;

    fn test_config() -> Config {
        Config {
            port: 9000,
            address: "127.0.0.1".to_string(),
            internal_bind_addr: None,
            data_dir: "./data".to_string(),
            access_key: "root".to_string(),
            secret_key: "root-secret".to_string(),
            additional_credentials: Vec::new(),
            region: "us-east-1".to_string(),
            node_id: "maxio-test-node".to_string(),
            cluster_peers: Vec::new(),
            membership_protocol: MembershipProtocol::StaticBootstrap,
            write_durability_mode: WriteDurabilityMode::DegradedSuccess,
            metadata_listing_strategy: ClusterMetadataListingStrategy::LocalNodeOnly,
            erasure_coding: false,
            chunk_size: 10 * 1024 * 1024,
            parity_shards: 0,
            min_disk_headroom_bytes: 268_435_456,
            cluster_auth_token: None,
            cluster_peer_tls_cert_path: None,
            cluster_peer_tls_key_path: None,
            cluster_peer_tls_ca_path: None,
            cluster_peer_tls_cert_sha256: None,
        }
    }

    #[test]
    fn merge_vary_headers_deduplicates_and_preserves_existing_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::VARY,
            HeaderValue::from_static("Accept-Encoding, Origin"),
        );

        merge_vary_headers(
            &mut headers,
            &[
                "Origin",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers",
            ],
        );

        let vary = headers
            .get(header::VARY)
            .and_then(|v| v.to_str().ok())
            .expect("vary should be set");
        assert_eq!(
            vary,
            "Accept-Encoding, Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
        );
    }

    #[test]
    fn response_with_content_type_sets_status_and_header() {
        let response = response_with_content_type(
            StatusCode::CREATED,
            HeaderValue::from_static("application/json"),
            axum::body::Body::from("{}"),
        );
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
    }

    #[tokio::test]
    async fn build_public_router_excludes_internal_cluster_routes() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let mut config = test_config();
        config.data_dir = temp.path().to_string_lossy().into_owned();
        let state = AppState::from_config(config)
            .await
            .expect("state bootstrap should succeed");
        let app = build_public_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/internal/cluster/join/authorize")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn build_internal_router_exposes_only_control_plane_routes() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let mut config = test_config();
        config.data_dir = temp.path().to_string_lossy().into_owned();
        let state = AppState::from_config(config)
            .await
            .expect("state bootstrap should succeed");
        let app = build_internal_router(state);

        let health_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/healthz")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");
        assert_eq!(health_response.status(), StatusCode::NOT_FOUND);

        let internal_response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/internal/cluster/join/authorize")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");
        assert_eq!(internal_response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn apply_cors_headers_reflected_origin_sets_allow_credentials() {
        let mut request_headers = HeaderMap::new();
        request_headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://example.com"),
        );
        let mut response_headers = HeaderMap::new();

        apply_cors_headers(&mut response_headers, &request_headers);

        assert_eq!(
            response_headers
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok()),
            Some("https://example.com")
        );
        assert_eq!(
            response_headers
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .and_then(|v| v.to_str().ok()),
            Some("true")
        );
    }

    #[test]
    fn apply_cors_headers_without_origin_uses_wildcard_without_credentials() {
        let request_headers = HeaderMap::new();
        let mut response_headers = HeaderMap::new();

        apply_cors_headers(&mut response_headers, &request_headers);

        assert_eq!(
            response_headers
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok()),
            Some("*")
        );
        assert!(
            response_headers
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none()
        );
    }

    #[test]
    fn build_allow_headers_adds_requested_headers_once() {
        let mut request_headers = HeaderMap::new();
        request_headers.insert(
            header::ACCESS_CONTROL_REQUEST_HEADERS,
            HeaderValue::from_static(
                "X-Amz-Date, X-Custom-Trace, x custom invalid, x-custom-trace",
            ),
        );

        let allow_header_value = build_allow_headers(&request_headers);
        let allow_headers = allow_header_value
            .to_str()
            .expect("allow headers should be valid utf-8");
        let values: Vec<&str> = allow_headers.split(',').collect();

        assert!(values.contains(&"x-amz-date"));
        assert!(values.contains(&"x-custom-trace"));
        assert!(!values.contains(&"x custom invalid"));
        assert_eq!(
            values
                .iter()
                .filter(|entry| entry.eq_ignore_ascii_case("x-custom-trace"))
                .count(),
            1
        );
    }

    #[test]
    fn membership_protocol_readiness_reports_gossip_as_ready_and_raft_as_not_ready() {
        let (static_ready, static_warning) =
            membership_protocol_readiness(MembershipProtocol::StaticBootstrap);
        assert!(static_ready);
        assert!(static_warning.is_none());

        let (gossip_ready, gossip_warning) =
            membership_protocol_readiness(MembershipProtocol::Gossip);
        assert!(gossip_ready);
        assert!(
            gossip_warning
                .as_deref()
                .is_some_and(|warning| warning.contains("experimental"))
        );

        let (raft_ready, raft_warning) = membership_protocol_readiness(MembershipProtocol::Raft);
        assert!(!raft_ready);
        assert!(
            raft_warning
                .as_deref()
                .is_some_and(|warning| warning.contains("not implemented"))
        );
    }

    #[test]
    fn membership_propagation_retry_delay_is_bounded_and_exponential() {
        assert_eq!(membership_propagation_retry_delay_ms(1), 100);
        assert_eq!(membership_propagation_retry_delay_ms(2), 200);
        assert_eq!(membership_propagation_retry_delay_ms(3), 400);
        assert_eq!(membership_propagation_retry_delay_ms(10), 1_000);
    }

    #[test]
    fn membership_propagation_retries_only_for_transient_statuses() {
        assert!(should_retry_membership_propagation_status(
            StatusCode::REQUEST_TIMEOUT
        ));
        assert!(should_retry_membership_propagation_status(
            StatusCode::TOO_MANY_REQUESTS
        ));
        assert!(should_retry_membership_propagation_status(
            StatusCode::SERVICE_UNAVAILABLE
        ));
        assert!(!should_retry_membership_propagation_status(
            StatusCode::FORBIDDEN
        ));
        assert!(!should_retry_membership_propagation_status(
            StatusCode::CONFLICT
        ));
    }

    #[tokio::test]
    async fn pending_rebalance_target_is_current_owner_uses_active_membership_projection() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let data_dir = temp
            .path()
            .to_str()
            .expect("path should be utf8")
            .to_string();
        let mut config = test_config();
        config.data_dir = data_dir;
        config.node_id = "node-a.internal:9000".to_string();
        config.cluster_peers = vec!["node-b.internal:9000".to_string()];
        let state = AppState::from_config(config)
            .await
            .expect("state bootstrap should succeed");

        let owner_candidate = PendingRebalanceCandidate {
            rebalance_id: "rebalance-owner".to_string(),
            bucket: "photos".to_string(),
            key: "docs/report.txt".to_string(),
            scope: RebalanceObjectScope::Object,
            coordinator_node: "node-a.internal:9000".to_string(),
            placement_epoch: 0,
            placement_view_id: "view-a".to_string(),
            created_at_unix_ms: 1,
            from: Some("node-a.internal:9000".to_string()),
            to: "node-b.internal:9000".to_string(),
            attempts: 0,
            next_retry_at_unix_ms: None,
        };
        assert!(pending_rebalance_target_is_current_owner(
            &state,
            &owner_candidate
        ));

        let mut non_owner_candidate = owner_candidate.clone();
        non_owner_candidate.to = "node-c.internal:9000".to_string();
        assert!(!pending_rebalance_target_is_current_owner(
            &state,
            &non_owner_candidate
        ));
    }

    fn metadata_test_topology(node_id: &str) -> RuntimeTopologySnapshot {
        RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: node_id.to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b:9000".to_string(), "node-c:9000".to_string()],
            membership_nodes: vec![
                "node-a:9000".to_string(),
                "node-b:9000".to_string(),
                "node-c:9000".to_string(),
            ],
            membership_protocol: MembershipProtocol::StaticBootstrap,
            membership_status: MembershipEngine::for_protocol(MembershipProtocol::StaticBootstrap)
                .status(),
            membership_view_id: "view-a".to_string(),
            placement_epoch: 0,
        }
    }

    #[test]
    fn metadata_readiness_uses_strategy_expected_nodes_for_local_and_consensus_modes() {
        let topology = metadata_test_topology("node-a:9000");
        let local_snapshot = metadata_snapshot_for_topology(
            &topology,
            ClusterMetadataListingStrategy::LocalNodeOnly,
        );
        let local_readiness = local_snapshot.readiness_assessment;
        assert!(!local_readiness.cluster_authoritative);
        assert!(!local_readiness.ready);
        assert_eq!(
            local_readiness.gap,
            Some(crate::metadata::ClusterMetadataReadinessGap::StrategyNotClusterAuthoritative)
        );

        let consensus_snapshot = metadata_snapshot_for_topology(
            &topology,
            ClusterMetadataListingStrategy::ConsensusIndex,
        );
        let consensus_readiness = consensus_snapshot.readiness_assessment;
        assert!(consensus_readiness.cluster_authoritative);
        assert!(!consensus_readiness.ready);
        assert_eq!(
            consensus_readiness.gap,
            Some(crate::metadata::ClusterMetadataReadinessGap::MissingExpectedNodes)
        );
    }

    #[test]
    fn metadata_readiness_keeps_authoritative_strategies_not_ready_until_cluster_fan_in_exists() {
        let topology = metadata_test_topology("node-a:9000");
        let aggregation_snapshot = metadata_snapshot_for_topology(
            &topology,
            ClusterMetadataListingStrategy::RequestTimeAggregation,
        );
        let aggregation_readiness = aggregation_snapshot.readiness_assessment;
        assert!(aggregation_readiness.cluster_authoritative);
        assert!(!aggregation_readiness.ready);
        assert_eq!(
            aggregation_readiness.gap,
            Some(crate::metadata::ClusterMetadataReadinessGap::MissingExpectedNodes)
        );

        let full_replication_snapshot = metadata_snapshot_for_topology(
            &topology,
            ClusterMetadataListingStrategy::FullReplication,
        );
        let full_replication_readiness = full_replication_snapshot.readiness_assessment;
        assert!(full_replication_readiness.cluster_authoritative);
        assert!(!full_replication_readiness.ready);
        assert_eq!(
            full_replication_readiness.gap,
            Some(crate::metadata::ClusterMetadataReadinessGap::MissingExpectedNodes)
        );
    }

    #[test]
    fn membership_update_precondition_failed_detects_view_or_epoch_mismatch() {
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "node-a:9000".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b:9000".to_string()],
            membership_nodes: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
            membership_protocol: MembershipProtocol::StaticBootstrap,
            membership_status: MembershipEngine::for_protocol(MembershipProtocol::StaticBootstrap)
                .status(),
            membership_view_id: "view-current".to_string(),
            placement_epoch: 42,
        };

        assert!(!membership_update_precondition_failed(
            &topology,
            Some("view-current"),
            Some(42),
        ));
        assert!(membership_update_precondition_failed(
            &topology,
            Some("view-stale"),
            Some(42),
        ));
        assert!(membership_update_precondition_failed(
            &topology,
            Some("view-current"),
            Some(41),
        ));
        assert!(membership_update_precondition_failed(
            &topology,
            Some("view-stale"),
            Some(41),
        ));
        assert!(!membership_update_precondition_failed(
            &topology, None, None
        ));
    }

    #[test]
    fn normalize_cluster_peers_for_membership_update_rejects_local_node_case_variants() {
        let result = normalize_cluster_peers_for_membership_update(
            "Node-A.Internal:9000",
            &["node-a.internal:9000".to_string()],
        );
        assert!(result.is_err());
    }

    #[test]
    fn normalize_cluster_peers_for_membership_update_dedupes_case_variant_peers() {
        let peers = normalize_cluster_peers_for_membership_update(
            "node-a.internal:9000",
            &[
                "Node-B.Internal:9001".to_string(),
                "node-b.internal:9001".to_string(),
            ],
        )
        .expect("peer normalization should succeed");
        assert_eq!(peers.len(), 1);
    }

    #[tokio::test]
    async fn apply_membership_peers_serializes_concurrent_transitions_and_preserves_epoch_monotonicity()
     {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let data_dir = temp
            .path()
            .to_str()
            .expect("path should be utf8")
            .to_string();
        let mut config = test_config();
        config.data_dir = data_dir.clone();
        config.node_id = "node-a.internal:9000".to_string();
        config.cluster_peers = vec!["node-b.internal:9001".to_string()];
        let state = AppState::from_config(config)
            .await
            .expect("state bootstrap should succeed");

        let initial_topology = runtime_topology_snapshot(&state);
        assert_eq!(initial_topology.placement_epoch, 0);

        let state_a = state.clone();
        let state_b = state.clone();
        let apply_a = tokio::spawn(async move {
            state_a
                .apply_membership_peers(vec!["node-c.internal:9002".to_string()])
                .await
                .expect("first membership apply should succeed")
        });
        let apply_b = tokio::spawn(async move {
            state_b
                .apply_membership_peers(vec!["node-d.internal:9003".to_string()])
                .await
                .expect("second membership apply should succeed")
        });
        let _ = apply_a
            .await
            .expect("first membership task should complete");
        let _ = apply_b
            .await
            .expect("second membership task should complete");

        let updated_topology = runtime_topology_snapshot(&state);
        assert_eq!(updated_topology.placement_epoch, 2);

        let persisted = read_persisted_placement_state(&placement_state_path(data_dir.as_str()))
            .await
            .expect("state read should succeed")
            .expect("state should exist");
        assert_eq!(persisted.epoch, 2);
    }

    #[tokio::test]
    async fn placement_epoch_bootstrap_initializes_state_file_when_missing() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let data_dir = temp.path().to_str().expect("path should be utf8");

        let epoch = load_or_bootstrap_placement_epoch(data_dir, "view-a")
            .await
            .expect("bootstrap should succeed");
        assert_eq!(epoch, 0);

        let persisted = read_persisted_placement_state(&placement_state_path(data_dir))
            .await
            .expect("state read should succeed")
            .expect("state should exist");
        assert_eq!(persisted.epoch, 0);
        assert_eq!(persisted.view_id, "view-a");
    }

    #[tokio::test]
    async fn placement_epoch_bootstrap_reuses_epoch_for_same_view() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let data_dir = temp.path().to_str().expect("path should be utf8");
        let path = placement_state_path(data_dir);
        write_persisted_placement_state(
            &path,
            &PersistedPlacementState {
                epoch: 9,
                view_id: "stable-view".to_string(),
            },
        )
        .await
        .expect("state write should succeed");

        let epoch = load_or_bootstrap_placement_epoch(data_dir, "stable-view")
            .await
            .expect("bootstrap should succeed");
        assert_eq!(epoch, 9);

        let persisted = read_persisted_placement_state(&path)
            .await
            .expect("state read should succeed")
            .expect("state should exist");
        assert_eq!(persisted.epoch, 9);
        assert_eq!(persisted.view_id, "stable-view");
    }

    #[tokio::test]
    async fn placement_epoch_bootstrap_increments_epoch_for_new_view() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let data_dir = temp.path().to_str().expect("path should be utf8");
        let path = placement_state_path(data_dir);
        write_persisted_placement_state(
            &path,
            &PersistedPlacementState {
                epoch: 4,
                view_id: "old-view".to_string(),
            },
        )
        .await
        .expect("state write should succeed");

        let epoch = load_or_bootstrap_placement_epoch(data_dir, "new-view")
            .await
            .expect("bootstrap should succeed");
        assert_eq!(epoch, 5);

        let persisted = read_persisted_placement_state(&path)
            .await
            .expect("state read should succeed")
            .expect("state should exist");
        assert_eq!(persisted.epoch, 5);
        assert_eq!(persisted.view_id, "new-view");
    }

    #[tokio::test]
    async fn cluster_id_bootstrap_initializes_state_when_missing() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let data_dir = temp.path().to_str().expect("path should be utf8");

        let cluster_id = load_or_bootstrap_cluster_id(data_dir, "cluster-seed-a")
            .await
            .expect("cluster id bootstrap should succeed");
        assert_eq!(cluster_id, "cluster-seed-a");

        let persisted =
            read_persisted_cluster_identity_state(&cluster_identity_state_path(data_dir))
                .await
                .expect("cluster identity state read should succeed")
                .expect("cluster identity state should exist");
        assert_eq!(persisted.cluster_id, "cluster-seed-a");
    }

    #[tokio::test]
    async fn cluster_id_bootstrap_remains_stable_across_seed_changes() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let data_dir = temp.path().to_str().expect("path should be utf8");

        let cluster_id_a = load_or_bootstrap_cluster_id(data_dir, "cluster-seed-a")
            .await
            .expect("cluster id bootstrap should succeed");
        let cluster_id_b = load_or_bootstrap_cluster_id(data_dir, "cluster-seed-b")
            .await
            .expect("cluster id reload should succeed");

        assert_eq!(cluster_id_a, "cluster-seed-a");
        assert_eq!(cluster_id_b, cluster_id_a);
    }

    #[test]
    fn validate_cluster_id_binding_accepts_matching_configured_identity() {
        assert!(validate_cluster_id_binding("cluster-main", Some("cluster-main")).is_ok());
        assert!(validate_cluster_id_binding("cluster-main", None).is_ok());
    }

    #[test]
    fn validate_cluster_id_binding_rejects_mismatched_configured_identity() {
        let err = validate_cluster_id_binding("cluster-seed-a", Some("cluster-override"))
            .expect_err("binding should reject mismatched configured identity");
        assert!(
            err.to_string().contains("Configured cluster id"),
            "unexpected mismatch error: {err}"
        );
    }

    #[tokio::test]
    async fn write_persisted_placement_state_replaces_state_without_temp_artifacts() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let data_dir = temp.path().to_str().expect("path should be utf8");
        let path = placement_state_path(data_dir);

        write_persisted_placement_state(
            &path,
            &PersistedPlacementState {
                epoch: 1,
                view_id: "view-initial".to_string(),
            },
        )
        .await
        .expect("initial write should succeed");
        write_persisted_placement_state(
            &path,
            &PersistedPlacementState {
                epoch: 2,
                view_id: "view-next".to_string(),
            },
        )
        .await
        .expect("replacement write should succeed");

        let persisted = read_persisted_placement_state(&path)
            .await
            .expect("state read should succeed")
            .expect("state should exist");
        assert_eq!(persisted.epoch, 2);
        assert_eq!(persisted.view_id, "view-next");

        let parent = path.parent().expect("placement-state path has parent");
        let temp_prefix = format!("{}.tmp-", PLACEMENT_STATE_FILE);
        for entry in std::fs::read_dir(parent).expect("state directory should be readable") {
            let file_name = entry
                .expect("directory entry should be readable")
                .file_name()
                .to_string_lossy()
                .to_string();
            assert!(
                !file_name.starts_with(&temp_prefix),
                "found leaked placement state temp artifact: {file_name}"
            );
        }
    }

    #[tokio::test]
    async fn probe_storage_data_path_reports_readable_for_healthy_storage() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let storage = FilesystemStorage::new(
            temp.path().to_str().expect("path should be utf8"),
            false,
            1024,
            0,
        )
        .await
        .expect("storage should initialize");

        let probe = probe_storage_data_path(&storage).await;
        assert!(probe.readable);
        assert!(probe.warning.is_none());
    }

    #[tokio::test]
    async fn probe_storage_data_path_reports_warning_on_storage_io_error() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let storage = FilesystemStorage::new(
            temp.path().to_str().expect("path should be utf8"),
            false,
            1024,
            0,
        )
        .await
        .expect("storage should initialize");

        std::fs::remove_dir_all(temp.path().join("buckets"))
            .expect("buckets directory should be removable");
        let probe = probe_storage_data_path(&storage).await;
        assert!(!probe.readable);
        assert!(
            probe
                .warning
                .as_deref()
                .is_some_and(|warning| warning.contains("Storage data-path probe failed"))
        );
    }

    #[test]
    fn probe_disk_headroom_reports_sufficient_when_threshold_disabled() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let path = temp.path().to_str().expect("path should be utf8");

        let probe = probe_disk_headroom(path, 0);
        assert!(probe.sufficient);
        assert!(probe.warning.is_none());
    }

    #[test]
    fn probe_disk_headroom_reports_warning_when_threshold_not_met() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let path = temp.path().to_str().expect("path should be utf8");
        let free_bytes = fs2::available_space(path).expect("available space probe should succeed");
        if free_bytes == u64::MAX {
            // Some filesystems report an effectively unbounded free-space sentinel.
            // In that environment we cannot construct a strictly larger threshold.
            return;
        }
        // Use a fixed maximal threshold so the assertion is stable even if free space
        // changes between probe calls in CI/containerized filesystems.
        let required = u64::MAX;

        let probe = probe_disk_headroom(path, required);
        assert!(!probe.sufficient);
        assert!(
            probe
                .warning
                .as_deref()
                .is_some_and(|warning| warning.contains("Disk headroom below threshold"))
        );
    }

    #[test]
    fn probe_pending_replication_queue_reports_readable_for_missing_queue_file() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let data_dir = temp.path().to_str().expect("path should be utf8");

        let probe = probe_pending_replication_queue(data_dir);
        assert!(probe.readable);
        assert_eq!(probe.summary.operations, 0);
        assert_eq!(probe.summary.pending_targets, 0);
        assert_eq!(probe.summary.failed_targets, 0);
        assert_eq!(probe.summary.max_attempts, 0);
        assert_eq!(probe.summary.oldest_created_at_unix_ms, None);
        assert_eq!(probe.due_targets, 0);
        assert!(!probe.due_targets_capped);
        assert!(probe.warning.is_none());
    }

    #[test]
    fn probe_pending_replication_queue_reports_warning_for_invalid_queue_payload() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let data_dir = temp.path().to_str().expect("path should be utf8");
        let queue_path = pending_replication_queue_path(data_dir);
        std::fs::create_dir_all(
            queue_path
                .parent()
                .expect("pending replication queue path should have a parent"),
        )
        .expect("pending replication runtime directory should be creatable");
        std::fs::write(&queue_path, b"{invalid-json")
            .expect("invalid queue payload should be written");

        let probe = probe_pending_replication_queue(data_dir);
        assert!(!probe.readable);
        assert_eq!(probe.summary.operations, 0);
        assert_eq!(probe.summary.pending_targets, 0);
        assert_eq!(probe.summary.failed_targets, 0);
        assert_eq!(probe.summary.max_attempts, 0);
        assert_eq!(probe.summary.oldest_created_at_unix_ms, None);
        assert_eq!(probe.due_targets, 0);
        assert!(!probe.due_targets_capped);
        assert!(
            probe
                .warning
                .as_deref()
                .is_some_and(|warning| warning.contains("Pending replication queue probe failed"))
        );
    }

    #[test]
    fn probe_pending_rebalance_queue_reports_readable_for_missing_queue_file() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let data_dir = temp.path().to_str().expect("path should be utf8");

        let probe = probe_pending_rebalance_queue(data_dir);
        assert!(probe.readable);
        assert_eq!(probe.summary.operations, 0);
        assert_eq!(probe.summary.pending_transfers, 0);
        assert_eq!(probe.summary.failed_transfers, 0);
        assert_eq!(probe.summary.max_attempts, 0);
        assert_eq!(probe.summary.oldest_created_at_unix_ms, None);
        assert_eq!(probe.due_transfers, 0);
        assert!(!probe.due_transfers_capped);
        assert!(probe.warning.is_none());
    }

    #[test]
    fn probe_pending_rebalance_queue_reports_warning_for_invalid_queue_payload() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let data_dir = temp.path().to_str().expect("path should be utf8");
        let queue_path = pending_rebalance_queue_path(data_dir);
        std::fs::create_dir_all(
            queue_path
                .parent()
                .expect("pending rebalance queue path should have a parent"),
        )
        .expect("pending rebalance runtime directory should be creatable");
        std::fs::write(&queue_path, b"{invalid-json")
            .expect("invalid queue payload should be written");

        let probe = probe_pending_rebalance_queue(data_dir);
        assert!(!probe.readable);
        assert_eq!(probe.summary.operations, 0);
        assert_eq!(probe.summary.pending_transfers, 0);
        assert_eq!(probe.summary.failed_transfers, 0);
        assert_eq!(probe.summary.max_attempts, 0);
        assert_eq!(probe.summary.oldest_created_at_unix_ms, None);
        assert_eq!(probe.due_transfers, 0);
        assert!(!probe.due_transfers_capped);
        assert!(
            probe
                .warning
                .as_deref()
                .is_some_and(|warning| warning.contains("Pending rebalance queue probe failed"))
        );
    }

    #[test]
    fn probe_pending_metadata_repair_queue_reports_readable_for_missing_queue_file() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let data_dir = temp.path().to_str().expect("path should be utf8");

        let probe = probe_pending_metadata_repair_queue(data_dir);
        assert!(probe.readable);
        assert_eq!(probe.summary.plans, 0);
        assert_eq!(probe.summary.due_plans, 0);
        assert_eq!(probe.summary.failed_plans, 0);
        assert_eq!(probe.summary.max_attempts, 0);
        assert_eq!(probe.summary.oldest_created_at_unix_ms, None);
        assert_eq!(probe.due_plans, 0);
        assert!(!probe.due_plans_capped);
        assert!(probe.warning.is_none());
    }

    #[test]
    fn probe_pending_metadata_repair_queue_reports_warning_for_invalid_queue_payload() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let data_dir = temp.path().to_str().expect("path should be utf8");
        let queue_path = pending_metadata_repair_queue_path(data_dir);
        std::fs::create_dir_all(
            queue_path
                .parent()
                .expect("pending metadata repair queue path should have a parent"),
        )
        .expect("pending metadata repair runtime directory should be creatable");
        std::fs::write(&queue_path, b"{invalid-json")
            .expect("invalid queue payload should be written");

        let probe = probe_pending_metadata_repair_queue(data_dir);
        assert!(!probe.readable);
        assert_eq!(probe.summary.plans, 0);
        assert_eq!(probe.summary.due_plans, 0);
        assert_eq!(probe.summary.failed_plans, 0);
        assert_eq!(probe.summary.max_attempts, 0);
        assert_eq!(probe.summary.oldest_created_at_unix_ms, None);
        assert_eq!(probe.due_plans, 0);
        assert!(!probe.due_plans_capped);
        assert!(probe.warning.as_deref().is_some_and(|warning| {
            warning.contains("Pending metadata repair queue probe failed")
        }));
    }

    #[test]
    fn probe_pending_metadata_repair_queue_reports_due_plan_counts() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let data_dir = temp.path().to_str().expect("path should be utf8");
        let queue_path = pending_metadata_repair_queue_path(data_dir);
        let pending_plan = PendingMetadataRepairPlan::new(
            "repair-server-probe-test",
            1,
            MetadataRepairPlan {
                source_view_id: "view-source".to_string(),
                target_view_id: "view-target".to_string(),
                actions: vec![MetadataReconcileAction::UpsertBucket {
                    bucket: "photos".to_string(),
                    versioning_enabled: false,
                    lifecycle_enabled: false,
                }],
            },
        )
        .expect("pending metadata repair plan should be valid");
        enqueue_pending_metadata_repair_plan_persisted(queue_path.as_path(), pending_plan)
            .expect("pending metadata repair plan should enqueue");

        let probe = probe_pending_metadata_repair_queue(data_dir);
        assert!(probe.readable);
        assert_eq!(probe.summary.plans, 1);
        assert_eq!(probe.summary.due_plans, 1);
        assert_eq!(probe.due_plans, 1);
        assert!(!probe.due_plans_capped);
        assert!(probe.warning.is_none());
    }

    #[tokio::test]
    async fn probe_peer_connectivity_reports_ready_when_no_peers_configured() {
        let result = probe_peer_connectivity(&[], None).await;
        assert!(result.ready);
        assert!(result.warning.is_none());
    }

    #[tokio::test]
    async fn probe_peer_connectivity_reports_warning_for_unreachable_peers() {
        let peers = vec!["127.0.0.1:1".to_string()];
        let result = probe_peer_connectivity(peers.as_slice(), None).await;
        assert!(!result.ready);
        assert!(result.peer_views.is_empty());
        assert!(
            result
                .warning
                .as_deref()
                .is_some_and(|warning| warning.contains("Peer connectivity probe failed"))
        );
    }

    #[tokio::test]
    async fn probe_peer_connectivity_reports_warning_when_mtls_transport_not_ready() {
        let peers = vec!["127.0.0.1:1".to_string()];
        let mut config = test_config();
        config.cluster_peer_tls_cert_path = Some("/tmp/maxio-missing-peer-cert.pem".to_string());
        config.cluster_peer_tls_key_path = Some("/tmp/maxio-missing-peer-key.pem".to_string());
        config.cluster_peer_tls_ca_path = Some("/tmp/maxio-missing-peer-ca.pem".to_string());

        let result = probe_peer_connectivity(peers.as_slice(), Some(&config)).await;
        assert!(!result.ready);
        assert!(result.peer_views.is_empty());
        assert!(
            result
                .warning
                .as_deref()
                .is_some_and(|warning| { warning.contains("mTLS peer transport is not ready") })
        );
    }

    #[test]
    fn build_peer_http_transport_uses_https_when_mtls_identity_is_configured() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let cert_path = temp.path().join("peer.crt");
        let key_path = temp.path().join("peer.key");
        let ca_path = temp.path().join("ca.pem");
        let cert_pem_raw = "-----BEGIN CERTIFICATE-----\n\
                        MIIDCzCCAfOgAwIBAgIUPOKbengZvjN7BnSjSz/oe2BLSbwwDQYJKoZIhvcNAQEL\n\
                        BQAwFTETMBEGA1UEAwwKbWF4aW8tcGVlcjAeFw0yNjAzMDQwMzAzNDBaFw0yNjAz\n\
                        MDUwMzAzNDBaMBUxEzARBgNVBAMMCm1heGlvLXBlZXIwggEiMA0GCSqGSIb3DQEB\n\
                        AQUAA4IBDwAwggEKAoIBAQDf5rw0lS10aDNinDqYXdbMp/GdlYcCD4fJk4P3g9vL\n\
                        HS16uRlcfYodqd1w+51m0G1bL+GlcDa1wU14JqZwH0sEWjA42K6+bG6CpX2DDzVS\n\
                        zFmeYA+gf3ilQrePmNY3JnpBL/ECx3BYUtU+b7YX43/hNpg4SUOY4lHiuROU5Ww/\n\
                        KrJYgdSdMV2bTWs3l/ST64Szh51GQ0VOcUuo0+GM3V/vfMvqrpiOFitvnVTma2b2\n\
                        RehAXb5TSVggzmuT1hPWYYf8ApIdGkDQBtQgVbB5xNKxfJ1M7h8xnQ/Y/tnCQhiX\n\
                        Od5zK0hgh0W8ZZrF2Ldxbc+VDFqhEXkOG5Hp8iFmkCfnAgMBAAGjUzBRMB0GA1Ud\n\
                        DgQWBBT9/nYCZRDqrcC+tZugthzMo0B0pTAfBgNVHSMEGDAWgBT9/nYCZRDqrcC+\n\
                        tZugthzMo0B0pTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAd\n\
                        xQfs11Igte6/B7IkIQW9ifMEW4qRdYuEoeIDUsyZ9II49A3zDMw/KZ8cVnQgF8WE\n\
                        3N3x6lB5yaJOVTyLRQYO9LbPjos2m3clLfQxIPRPv8R+udoNPrIUtihCHSNKXPP4\n\
                        GEEt5qzQAeUBGASPR/BjvNWa2fu3UvHdHtOuq3Ys17su2eT45+eCPuQ5ZcDQmeaE\n\
                        wJS1LCaQIi3qw0U1cQkGhNez/sXjDldLKk7zpO9iVjlOSNwxOyF+Rbov6YWqOzZV\n\
                        rXiiU6jNPRKFI6Yn8c5NTlvuslsgBs6IeQnfeTKUFtt0RcrCPbT/o5mrIijxXdto\n\
                        hq/amvoK6ySEVmQ7bEYj\n\
                        -----END CERTIFICATE-----\n";
        let key_pem_raw = "-----BEGIN PRIVATE KEY-----\n\
                       MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDf5rw0lS10aDNi\n\
                       nDqYXdbMp/GdlYcCD4fJk4P3g9vLHS16uRlcfYodqd1w+51m0G1bL+GlcDa1wU14\n\
                       JqZwH0sEWjA42K6+bG6CpX2DDzVSzFmeYA+gf3ilQrePmNY3JnpBL/ECx3BYUtU+\n\
                       b7YX43/hNpg4SUOY4lHiuROU5Ww/KrJYgdSdMV2bTWs3l/ST64Szh51GQ0VOcUuo\n\
                       0+GM3V/vfMvqrpiOFitvnVTma2b2RehAXb5TSVggzmuT1hPWYYf8ApIdGkDQBtQg\n\
                       VbB5xNKxfJ1M7h8xnQ/Y/tnCQhiXOd5zK0hgh0W8ZZrF2Ldxbc+VDFqhEXkOG5Hp\n\
                       8iFmkCfnAgMBAAECggEAM3vNS/P/azRomGSfDpkJQq7dXmRbEmy6xu2OGzRtLkOr\n\
                       yPvV6pANWavM+OVKeLE1bBHS+2UVl25230lX3RE9ASexzeh5Kd0p/g2Kkj/FfZ/y\n\
                       fXnOLhQRjEKOjczReQX2d5XL/90XJqAJW515S/3qUkFo+AxUqEtmE9GFwKeOX+mF\n\
                       y38tcWD3tGc31ib2fAAftUNkiL+fRuhsnfF3KKnjvWoKwYcs/CGxL5Cs7IYYPsMC\n\
                       z84gzwvD/1FYR/Ocxn8o/4av2VKQ1vjHexktI3P82KytcnapAyoJ742kL5YijHoY\n\
                       N9fCA4rHuw2ey4HNjE13S/bvXmOqvqhHRjtKTUMnZQKBgQD16NpcxOaeJbQMKLX2\n\
                       ocOnLLjwGu/O6HbZsifkCWt4yZmH+6LqGrPEgUEKOw+WgWD7pCu51zk99AGcttxg\n\
                       rGUYuu1/a605WDOgE3sfQLBVyXoN2Yj4Go+m+Q9vfEtSjQtWJnZtgIfc01NNeUyU\n\
                       NNkx0R0ydEIKSrGokcVicZPBrQKBgQDpFrJ8YTU7MX7mZ0QahTFxaJ42l0X5P2DU\n\
                       xrjQgG3Cbo60dfcTKJmzcu/XO5pihYENAmEDRFuuUSpZvkEluG5hop2SyDd4zXWT\n\
                       M6soin4fV6Vcw8nvJKirXTHRJgM9jn+fAU5K6fken/u8bG6g7cGU6nNRTCCBYpco\n\
                       +yxSFrmKYwKBgQD0ETaZmLwj/tvirY1cylU8WYD8nl+hhsxfaRl6lXbbnYwKkVCy\n\
                       9emygW8iTlg8UxEE8X6MpvajbMkk18GHGdQFZZJPQ3ncTpR+rpcm/7eEjcHceSoe\n\
                       xY4KdWxChKTlvCOiT+5+5HD0VbJ6VIgTGRjw/tHxv73EJTqLSpMUEBJMyQKBgQDo\n\
                       AtGzAMeNnhzklpGxnDa03h/t0vGxwaZO5Wd9Evkt+gJOGsXO6jDj8FpP8WIhAyaL\n\
                       nnyWVeq0PtJa9ge+1i/5O3aBbo3YzxpjZaDO/9u+su1EwxYz1leWC3PU7XN4SGk8\n\
                       Cn62DuML2s8mpQARa9eutRgIKjCI2WwBPNLG+xvAZQKBgGoiOjNP3QVvI23xriPJ\n\
                       kJS/EGdo5BMJ5iOBXDENbI+HYHdTwLjb7VGPE4PoPFAM4VQ2HgtCjec5DLP1/xOo\n\
                       weiHVMpIPHJpcQSuSa9X7ji+7D4zwF/5bo350j99aySVI0DyIx2bYR4nGGTJOitw\n\
                       yPgr8n4j1X1HMlM6ArjKekjY\n\
                       -----END PRIVATE KEY-----\n";
        let cert_pem = cert_pem_raw
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let key_pem = key_pem_raw
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&cert_path, cert_pem.as_bytes()).expect("cert fixture should write");
        std::fs::write(&key_path, key_pem.as_bytes()).expect("key fixture should write");
        std::fs::write(&ca_path, cert_pem.as_bytes()).expect("ca fixture should write");

        let mut config = test_config();
        config.cluster_peer_tls_cert_path = Some(
            cert_path
                .to_str()
                .expect("cert path should be utf8")
                .to_string(),
        );
        config.cluster_peer_tls_key_path = Some(
            key_path
                .to_str()
                .expect("key path should be utf8")
                .to_string(),
        );
        config.cluster_peer_tls_ca_path = Some(
            ca_path
                .to_str()
                .expect("ca path should be utf8")
                .to_string(),
        );

        let transport = build_peer_http_transport(Some(&config), Duration::from_secs(1))
            .expect("mTLS transport should initialize with parseable cert/key identity");
        assert_eq!(transport.scheme, "https");
    }

    #[test]
    fn probe_membership_convergence_reports_false_for_static_bootstrap_view_mismatch() {
        let membership_status = MembershipEngineStatus {
            engine: "static-bootstrap".to_string(),
            protocol: MembershipProtocol::StaticBootstrap.as_str().to_string(),
            ready: true,
            converged: true,
            last_update_unix_ms: 1234,
            warning: None,
        };
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "node-a".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b".to_string()],
            membership_nodes: vec!["node-a".to_string(), "node-b".to_string()],
            membership_protocol: MembershipProtocol::StaticBootstrap,
            membership_status: membership_status.clone(),
            membership_view_id: "view-local".to_string(),
            placement_epoch: 3,
        };
        let peer_probe = PeerConnectivityProbeResult {
            ready: true,
            warning: None,
            peer_views: vec![PeerViewObservation {
                peer: "node-b".to_string(),
                membership_view_id: Some("view-other".to_string()),
                placement_epoch: None,
                cluster_id: None,
                cluster_peers: Vec::new(),
            }],
            failed_peers: Vec::new(),
        };

        let convergence = probe_membership_convergence(&topology, &membership_status, &peer_probe);
        assert!(!convergence.converged);
        assert!(
            convergence
                .warning
                .as_deref()
                .is_some_and(|warning| warning.contains("Membership view mismatch detected"))
        );
    }

    #[test]
    fn probe_membership_convergence_reports_true_for_matching_static_bootstrap_views() {
        let membership_status = MembershipEngineStatus {
            engine: "static-bootstrap".to_string(),
            protocol: MembershipProtocol::StaticBootstrap.as_str().to_string(),
            ready: true,
            converged: true,
            last_update_unix_ms: 1234,
            warning: None,
        };
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "node-a".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b".to_string()],
            membership_nodes: vec!["node-a".to_string(), "node-b".to_string()],
            membership_protocol: MembershipProtocol::StaticBootstrap,
            membership_status: membership_status.clone(),
            membership_view_id: "view-local".to_string(),
            placement_epoch: 3,
        };
        let peer_probe = PeerConnectivityProbeResult {
            ready: true,
            warning: None,
            peer_views: vec![PeerViewObservation {
                peer: "node-b".to_string(),
                membership_view_id: Some("view-local".to_string()),
                placement_epoch: None,
                cluster_id: None,
                cluster_peers: Vec::new(),
            }],
            failed_peers: Vec::new(),
        };

        let convergence = probe_membership_convergence(&topology, &membership_status, &peer_probe);
        assert!(convergence.converged);
        assert!(convergence.warning.is_none());
    }

    #[test]
    fn probe_membership_convergence_rechecks_static_bootstrap_after_cached_non_converged_state() {
        let membership_status = MembershipEngineStatus {
            engine: "static-bootstrap".to_string(),
            protocol: MembershipProtocol::StaticBootstrap.as_str().to_string(),
            ready: true,
            converged: false,
            last_update_unix_ms: 1234,
            warning: None,
        };
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "node-a".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b".to_string()],
            membership_nodes: vec!["node-a".to_string(), "node-b".to_string()],
            membership_protocol: MembershipProtocol::StaticBootstrap,
            membership_status: membership_status.clone(),
            membership_view_id: "view-local".to_string(),
            placement_epoch: 3,
        };
        let peer_probe = PeerConnectivityProbeResult {
            ready: true,
            warning: None,
            peer_views: vec![PeerViewObservation {
                peer: "node-b".to_string(),
                membership_view_id: Some("view-local".to_string()),
                placement_epoch: None,
                cluster_id: None,
                cluster_peers: Vec::new(),
            }],
            failed_peers: Vec::new(),
        };

        let convergence = probe_membership_convergence(&topology, &membership_status, &peer_probe);
        assert!(convergence.converged);
        assert!(convergence.warning.is_none());
    }

    #[test]
    fn probe_membership_convergence_requires_peer_probe_for_gossip_when_distributed() {
        let membership_status = MembershipEngine::for_protocol(MembershipProtocol::Gossip).status();
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "node-a".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b".to_string()],
            membership_nodes: vec!["node-a".to_string(), "node-b".to_string()],
            membership_protocol: MembershipProtocol::Gossip,
            membership_status: membership_status.clone(),
            membership_view_id: "view-local".to_string(),
            placement_epoch: 3,
        };
        let peer_probe = PeerConnectivityProbeResult {
            ready: false,
            warning: Some("node-b probe failed".to_string()),
            peer_views: Vec::new(),
            failed_peers: vec!["node-b".to_string()],
        };

        let convergence = probe_membership_convergence(&topology, &membership_status, &peer_probe);
        assert!(!convergence.converged);
        assert_eq!(convergence.reason, "peer-connectivity-failed");
    }

    #[test]
    fn derive_membership_discovery_cluster_peers_returns_updated_union_for_matching_cluster() {
        let membership_status = MembershipEngineStatus {
            engine: "static-bootstrap".to_string(),
            protocol: MembershipProtocol::StaticBootstrap.as_str().to_string(),
            ready: true,
            converged: true,
            last_update_unix_ms: 1234,
            warning: None,
        };
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "node-a:9000".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b:9000".to_string()],
            membership_nodes: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
            membership_protocol: MembershipProtocol::StaticBootstrap,
            membership_status,
            membership_view_id: "view-local".to_string(),
            placement_epoch: 3,
        };
        let peer_probe = PeerConnectivityProbeResult {
            ready: true,
            warning: None,
            peer_views: vec![PeerViewObservation {
                peer: "node-b:9000".to_string(),
                membership_view_id: Some("view-local".to_string()),
                placement_epoch: None,
                cluster_id: Some("cluster-a".to_string()),
                cluster_peers: vec!["node-c:9000".to_string()],
            }],
            failed_peers: Vec::new(),
        };

        let discovered = derive_membership_discovery_cluster_peers(&topology, &peer_probe)
            .expect("matching cluster id snapshot should be accepted");
        assert_eq!(
            discovered,
            Some(vec!["node-b:9000".to_string(), "node-c:9000".to_string()])
        );
    }

    #[test]
    fn derive_membership_discovery_cluster_peers_accepts_gossip_when_engine_ready() {
        let membership_status = MembershipEngine::for_protocol(MembershipProtocol::Gossip).status();
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "node-a:9000".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b:9000".to_string()],
            membership_nodes: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
            membership_protocol: MembershipProtocol::Gossip,
            membership_status,
            membership_view_id: "view-local".to_string(),
            placement_epoch: 3,
        };
        let peer_probe = PeerConnectivityProbeResult {
            ready: true,
            warning: None,
            peer_views: vec![PeerViewObservation {
                peer: "node-b:9000".to_string(),
                membership_view_id: Some("view-local".to_string()),
                placement_epoch: None,
                cluster_id: Some("cluster-a".to_string()),
                cluster_peers: vec!["node-c:9000".to_string()],
            }],
            failed_peers: Vec::new(),
        };

        let discovered = derive_membership_discovery_cluster_peers(&topology, &peer_probe)
            .expect("matching cluster id snapshot should be accepted");
        assert_eq!(
            discovered,
            Some(vec!["node-b:9000".to_string(), "node-c:9000".to_string()])
        );
    }

    #[test]
    fn derive_membership_discovery_cluster_peers_prunes_failed_gossip_peer_when_not_observed() {
        let membership_status = MembershipEngine::for_protocol(MembershipProtocol::Gossip).status();
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "node-a:9000".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b:9000".to_string(), "node-c:9000".to_string()],
            membership_nodes: vec![
                "node-a:9000".to_string(),
                "node-b:9000".to_string(),
                "node-c:9000".to_string(),
            ],
            membership_protocol: MembershipProtocol::Gossip,
            membership_status,
            membership_view_id: "view-local".to_string(),
            placement_epoch: 3,
        };
        let peer_probe = PeerConnectivityProbeResult {
            ready: false,
            warning: Some("node-c:9000 probe failed".to_string()),
            peer_views: vec![PeerViewObservation {
                peer: "node-b:9000".to_string(),
                membership_view_id: Some("view-local".to_string()),
                placement_epoch: None,
                cluster_id: Some("cluster-a".to_string()),
                cluster_peers: vec!["node-b:9000".to_string()],
            }],
            failed_peers: vec!["node-c:9000".to_string()],
        };

        let discovered = derive_membership_discovery_cluster_peers(&topology, &peer_probe)
            .expect("matching cluster id snapshot should be accepted");
        assert_eq!(discovered, Some(vec!["node-b:9000".to_string()]));
    }

    #[test]
    fn derive_membership_discovery_cluster_peers_keeps_failed_gossip_peer_when_still_observed() {
        let membership_status = MembershipEngine::for_protocol(MembershipProtocol::Gossip).status();
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "node-a:9000".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b:9000".to_string(), "node-c:9000".to_string()],
            membership_nodes: vec![
                "node-a:9000".to_string(),
                "node-b:9000".to_string(),
                "node-c:9000".to_string(),
            ],
            membership_protocol: MembershipProtocol::Gossip,
            membership_status,
            membership_view_id: "view-local".to_string(),
            placement_epoch: 3,
        };
        let peer_probe = PeerConnectivityProbeResult {
            ready: false,
            warning: Some("node-c:9000 probe failed".to_string()),
            peer_views: vec![PeerViewObservation {
                peer: "node-b:9000".to_string(),
                membership_view_id: Some("view-local".to_string()),
                placement_epoch: None,
                cluster_id: Some("cluster-a".to_string()),
                cluster_peers: vec!["node-c:9000".to_string()],
            }],
            failed_peers: vec!["node-c:9000".to_string()],
        };

        let discovered = derive_membership_discovery_cluster_peers(&topology, &peer_probe)
            .expect("matching cluster id snapshot should be accepted");
        assert_eq!(discovered, None);
    }

    #[test]
    fn derive_gossip_stale_peer_reconciliation_targets_returns_stale_peer_with_epoch() {
        let membership_status = MembershipEngine::for_protocol(MembershipProtocol::Gossip).status();
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "node-a:9000".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b:9000".to_string()],
            membership_nodes: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
            membership_protocol: MembershipProtocol::Gossip,
            membership_status,
            membership_view_id: "view-local".to_string(),
            placement_epoch: 11,
        };
        let peer_probe = PeerConnectivityProbeResult {
            ready: true,
            warning: None,
            peer_views: vec![PeerViewObservation {
                peer: "node-b:9000".to_string(),
                membership_view_id: Some("view-stale".to_string()),
                placement_epoch: Some(7),
                cluster_id: Some("cluster-a".to_string()),
                cluster_peers: vec!["node-a:9000".to_string()],
            }],
            failed_peers: Vec::new(),
        };

        let targets = derive_gossip_stale_peer_reconciliation_targets(&topology, &peer_probe);
        assert_eq!(
            targets,
            vec![GossipStalePeerReconciliationTarget {
                peer: "node-b:9000".to_string(),
                expected_membership_view_id: "view-stale".to_string(),
                expected_placement_epoch: 7,
            }]
        );
    }

    #[test]
    fn derive_gossip_stale_peer_reconciliation_targets_ignores_non_actionable_peer_views() {
        let membership_status = MembershipEngine::for_protocol(MembershipProtocol::Gossip).status();
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "node-a:9000".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b:9000".to_string(), "node-c:9000".to_string()],
            membership_nodes: vec![
                "node-a:9000".to_string(),
                "node-b:9000".to_string(),
                "node-c:9000".to_string(),
            ],
            membership_protocol: MembershipProtocol::Gossip,
            membership_status,
            membership_view_id: "view-local".to_string(),
            placement_epoch: 11,
        };
        let peer_probe = PeerConnectivityProbeResult {
            ready: true,
            warning: None,
            peer_views: vec![
                PeerViewObservation {
                    peer: "node-b:9000".to_string(),
                    membership_view_id: Some("view-local".to_string()),
                    placement_epoch: Some(7),
                    cluster_id: Some("cluster-a".to_string()),
                    cluster_peers: Vec::new(),
                },
                PeerViewObservation {
                    peer: "node-c:9000".to_string(),
                    membership_view_id: Some("view-stale".to_string()),
                    placement_epoch: None,
                    cluster_id: Some("cluster-a".to_string()),
                    cluster_peers: Vec::new(),
                },
                PeerViewObservation {
                    peer: "node-d:9000".to_string(),
                    membership_view_id: Some("view-stale".to_string()),
                    placement_epoch: Some(3),
                    cluster_id: Some("cluster-other".to_string()),
                    cluster_peers: Vec::new(),
                },
            ],
            failed_peers: Vec::new(),
        };

        let targets = derive_gossip_stale_peer_reconciliation_targets(&topology, &peer_probe);
        assert!(targets.is_empty());
    }

    #[test]
    fn derive_membership_discovery_cluster_peers_returns_none_when_union_is_unchanged() {
        let membership_status = MembershipEngineStatus {
            engine: "static-bootstrap".to_string(),
            protocol: MembershipProtocol::StaticBootstrap.as_str().to_string(),
            ready: true,
            converged: true,
            last_update_unix_ms: 1234,
            warning: None,
        };
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "node-a:9000".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b:9000".to_string()],
            membership_nodes: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
            membership_protocol: MembershipProtocol::StaticBootstrap,
            membership_status,
            membership_view_id: "view-local".to_string(),
            placement_epoch: 3,
        };
        let peer_probe = PeerConnectivityProbeResult {
            ready: true,
            warning: None,
            peer_views: vec![PeerViewObservation {
                peer: "node-b:9000".to_string(),
                membership_view_id: Some("view-local".to_string()),
                placement_epoch: None,
                cluster_id: Some("cluster-a".to_string()),
                cluster_peers: vec!["node-b:9000".to_string()],
            }],
            failed_peers: Vec::new(),
        };

        assert_eq!(
            derive_membership_discovery_cluster_peers(&topology, &peer_probe)
                .expect("matching cluster id snapshot should be accepted"),
            None
        );
    }

    #[test]
    fn derive_membership_discovery_cluster_peers_rejects_mismatched_cluster_id() {
        let membership_status = MembershipEngineStatus {
            engine: "static-bootstrap".to_string(),
            protocol: MembershipProtocol::StaticBootstrap.as_str().to_string(),
            ready: true,
            converged: true,
            last_update_unix_ms: 1234,
            warning: None,
        };
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "node-a:9000".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b:9000".to_string()],
            membership_nodes: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
            membership_protocol: MembershipProtocol::StaticBootstrap,
            membership_status,
            membership_view_id: "view-local".to_string(),
            placement_epoch: 3,
        };
        let peer_probe = PeerConnectivityProbeResult {
            ready: true,
            warning: None,
            peer_views: vec![PeerViewObservation {
                peer: "node-b:9000".to_string(),
                membership_view_id: Some("view-local".to_string()),
                placement_epoch: None,
                cluster_id: Some("cluster-z".to_string()),
                cluster_peers: vec!["node-c:9000".to_string()],
            }],
            failed_peers: Vec::new(),
        };

        let error = derive_membership_discovery_cluster_peers(&topology, &peer_probe)
            .expect_err("cluster id mismatch should fail closed");
        assert!(error.contains("mismatched cluster id"));
    }

    #[test]
    fn derive_membership_discovery_cluster_peers_rejects_missing_cluster_id() {
        let membership_status = MembershipEngineStatus {
            engine: "static-bootstrap".to_string(),
            protocol: MembershipProtocol::StaticBootstrap.as_str().to_string(),
            ready: true,
            converged: true,
            last_update_unix_ms: 1234,
            warning: None,
        };
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "node-a:9000".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b:9000".to_string()],
            membership_nodes: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
            membership_protocol: MembershipProtocol::StaticBootstrap,
            membership_status,
            membership_view_id: "view-local".to_string(),
            placement_epoch: 3,
        };
        let peer_probe = PeerConnectivityProbeResult {
            ready: true,
            warning: None,
            peer_views: vec![PeerViewObservation {
                peer: "node-b:9000".to_string(),
                membership_view_id: Some("view-local".to_string()),
                placement_epoch: None,
                cluster_id: None,
                cluster_peers: vec!["node-c:9000".to_string()],
            }],
            failed_peers: Vec::new(),
        };

        let error = derive_membership_discovery_cluster_peers(&topology, &peer_probe)
            .expect_err("missing cluster id should fail closed");
        assert!(error.contains("omitted cluster id"));
    }

    #[test]
    fn derive_membership_discovery_cluster_peers_rejects_missing_membership_view_id() {
        let membership_status = MembershipEngineStatus {
            engine: "static-bootstrap".to_string(),
            protocol: MembershipProtocol::StaticBootstrap.as_str().to_string(),
            ready: true,
            converged: true,
            last_update_unix_ms: 1234,
            warning: None,
        };
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "node-a:9000".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b:9000".to_string()],
            membership_nodes: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
            membership_protocol: MembershipProtocol::StaticBootstrap,
            membership_status,
            membership_view_id: "view-local".to_string(),
            placement_epoch: 3,
        };
        let peer_probe = PeerConnectivityProbeResult {
            ready: true,
            warning: None,
            peer_views: vec![PeerViewObservation {
                peer: "node-b:9000".to_string(),
                membership_view_id: None,
                placement_epoch: None,
                cluster_id: Some("cluster-a".to_string()),
                cluster_peers: vec!["node-c:9000".to_string()],
            }],
            failed_peers: Vec::new(),
        };

        let error = derive_membership_discovery_cluster_peers(&topology, &peer_probe)
            .expect_err("missing membership view id should fail closed");
        assert!(error.contains("omitted membership view id"));
    }

    #[test]
    fn derive_membership_discovery_cluster_peers_uses_successful_peer_views_when_probe_not_ready() {
        let membership_status = MembershipEngineStatus {
            engine: "static-bootstrap".to_string(),
            protocol: MembershipProtocol::StaticBootstrap.as_str().to_string(),
            ready: true,
            converged: true,
            last_update_unix_ms: 1234,
            warning: None,
        };
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "node-a:9000".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b:9000".to_string()],
            membership_nodes: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
            membership_protocol: MembershipProtocol::StaticBootstrap,
            membership_status,
            membership_view_id: "view-local".to_string(),
            placement_epoch: 3,
        };
        let peer_probe = PeerConnectivityProbeResult {
            ready: false,
            warning: Some("node-c:9000 unreachable".to_string()),
            peer_views: vec![PeerViewObservation {
                peer: "node-b:9000".to_string(),
                membership_view_id: Some("view-local".to_string()),
                placement_epoch: None,
                cluster_id: Some("cluster-a".to_string()),
                cluster_peers: vec!["node-c:9000".to_string()],
            }],
            failed_peers: vec!["node-c:9000".to_string()],
        };

        let discovered = derive_membership_discovery_cluster_peers(&topology, &peer_probe)
            .expect("matching cluster id snapshot should be accepted");
        assert_eq!(
            discovered,
            Some(vec!["node-b:9000".to_string(), "node-c:9000".to_string()])
        );
    }

    #[test]
    fn derive_membership_discovery_cluster_peers_returns_none_without_successful_peer_views() {
        let membership_status = MembershipEngineStatus {
            engine: "static-bootstrap".to_string(),
            protocol: MembershipProtocol::StaticBootstrap.as_str().to_string(),
            ready: true,
            converged: true,
            last_update_unix_ms: 1234,
            warning: None,
        };
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "node-a:9000".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b:9000".to_string()],
            membership_nodes: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
            membership_protocol: MembershipProtocol::StaticBootstrap,
            membership_status,
            membership_view_id: "view-local".to_string(),
            placement_epoch: 3,
        };
        let peer_probe = PeerConnectivityProbeResult {
            ready: false,
            warning: Some("all peers unreachable".to_string()),
            peer_views: Vec::new(),
            failed_peers: vec!["node-b:9000".to_string()],
        };

        assert_eq!(
            derive_membership_discovery_cluster_peers(&topology, &peer_probe)
                .expect("empty peer-view snapshots should be accepted"),
            None
        );
    }

    #[tokio::test]
    async fn runtime_topology_snapshot_reports_standalone_mode() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let storage = FilesystemStorage::new(
            temp.path().to_str().expect("path should be utf8"),
            false,
            1024,
            0,
        )
        .await
        .expect("storage should initialize");
        let membership_view_id = membership_view_id_with_self("node-a", &[]);
        let state = AppState {
            storage: Arc::new(storage),
            config: Arc::new(test_config()),
            credentials: Arc::new(HashMap::new()),
            node_id: Arc::new("node-a".to_string()),
            cluster_id: Arc::new("cluster-a".to_string()),
            membership_peers: Arc::new(RwLock::new(Vec::new())),
            membership_view_id: Arc::new(RwLock::new(membership_view_id)),
            cluster_peers: Arc::new(Vec::new()),
            membership_protocol: MembershipProtocol::Gossip,
            write_durability_mode: WriteDurabilityMode::DegradedSuccess,
            metadata_listing_strategy: ClusterMetadataListingStrategy::LocalNodeOnly,
            membership_engine: MembershipEngine::for_protocol(MembershipProtocol::Gossip),
            membership_last_update_unix_ms: Arc::new(AtomicU64::new(unix_ms_now())),
            membership_converged: Arc::new(AtomicU64::new(0)),
            join_nonce_replay_guard: Arc::new(InMemoryJoinNonceReplayGuard::new(
                JOIN_NONCE_REPLAY_GUARD_TTL_MS,
                JOIN_NONCE_REPLAY_GUARD_MAX_ENTRIES,
            )),
            cluster_join_authorize_counters: Arc::new(ClusterJoinAuthorizeCounters::default()),
            cluster_join_counters: Arc::new(ClusterJoinCounters::default()),
            cluster_membership_update_counters: Arc::new(ClusterMembershipUpdateCounters::default()),
            pending_replication_replay_counters: Arc::new(
                PendingReplicationReplayCounters::default(),
            ),
            pending_rebalance_replay_counters: Arc::new(PendingRebalanceReplayCounters::default()),
            pending_membership_propagation_replay_counters: Arc::new(
                PendingMembershipPropagationReplayCounters::default(),
            ),
            pending_metadata_repair_replay_counters: Arc::new(
                PendingMetadataRepairReplayCounters::default(),
            ),
            placement_epoch: Arc::new(AtomicU64::new(7)),
            runtime_internal_header_reject_dimensions: Arc::new(
                RuntimeInternalHeaderRejectDimensions::default(),
            ),
            login_rate_limiter: Arc::new(LoginRateLimiter::new()),
            request_count: Arc::new(AtomicU64::new(0)),
            started_at: Instant::now(),
        };

        let snapshot = runtime_topology_snapshot(&state);
        assert_eq!(snapshot.mode, RuntimeMode::Standalone);
        assert!(!snapshot.is_distributed());
        assert_eq!(snapshot.node_id, "node-a");
        assert_eq!(snapshot.cluster_id, "cluster-a");
        assert_eq!(snapshot.cluster_peer_count(), 0);
        assert_eq!(snapshot.cluster_peers, Vec::<String>::new());
        assert_eq!(snapshot.membership_node_count(), 1);
        assert_eq!(snapshot.membership_nodes, vec!["node-a"]);
        assert_eq!(snapshot.membership_protocol, MembershipProtocol::Gossip);
        assert!(snapshot.membership_status.ready);
        assert!(!snapshot.membership_status.converged);
        assert_eq!(snapshot.placement_epoch, 7);
    }

    #[tokio::test]
    async fn runtime_topology_snapshot_reports_distributed_mode_and_view_id() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let storage = FilesystemStorage::new(
            temp.path().to_str().expect("path should be utf8"),
            false,
            1024,
            0,
        )
        .await
        .expect("storage should initialize");
        let membership_peers = vec!["node-b".to_string(), "node-c".to_string()];
        let membership_view_id = membership_view_id_with_self("node-a", &membership_peers);
        let state = AppState {
            storage: Arc::new(storage),
            config: Arc::new(test_config()),
            credentials: Arc::new(HashMap::new()),
            node_id: Arc::new("node-a".to_string()),
            cluster_id: Arc::new("cluster-a".to_string()),
            membership_peers: Arc::new(RwLock::new(membership_peers.clone())),
            membership_view_id: Arc::new(RwLock::new(membership_view_id.clone())),
            cluster_peers: Arc::new(membership_peers),
            membership_protocol: MembershipProtocol::Raft,
            write_durability_mode: WriteDurabilityMode::DegradedSuccess,
            metadata_listing_strategy: ClusterMetadataListingStrategy::LocalNodeOnly,
            membership_engine: MembershipEngine::for_protocol(MembershipProtocol::Raft),
            membership_last_update_unix_ms: Arc::new(AtomicU64::new(unix_ms_now())),
            membership_converged: Arc::new(AtomicU64::new(0)),
            join_nonce_replay_guard: Arc::new(InMemoryJoinNonceReplayGuard::new(
                JOIN_NONCE_REPLAY_GUARD_TTL_MS,
                JOIN_NONCE_REPLAY_GUARD_MAX_ENTRIES,
            )),
            cluster_join_authorize_counters: Arc::new(ClusterJoinAuthorizeCounters::default()),
            cluster_join_counters: Arc::new(ClusterJoinCounters::default()),
            cluster_membership_update_counters: Arc::new(ClusterMembershipUpdateCounters::default()),
            pending_replication_replay_counters: Arc::new(
                PendingReplicationReplayCounters::default(),
            ),
            pending_rebalance_replay_counters: Arc::new(PendingRebalanceReplayCounters::default()),
            pending_membership_propagation_replay_counters: Arc::new(
                PendingMembershipPropagationReplayCounters::default(),
            ),
            pending_metadata_repair_replay_counters: Arc::new(
                PendingMetadataRepairReplayCounters::default(),
            ),
            placement_epoch: Arc::new(AtomicU64::new(11)),
            runtime_internal_header_reject_dimensions: Arc::new(
                RuntimeInternalHeaderRejectDimensions::default(),
            ),
            login_rate_limiter: Arc::new(LoginRateLimiter::new()),
            request_count: Arc::new(AtomicU64::new(0)),
            started_at: Instant::now(),
        };

        let snapshot = runtime_topology_snapshot(&state);
        assert_eq!(snapshot.mode, RuntimeMode::Distributed);
        assert!(snapshot.is_distributed());
        assert_eq!(snapshot.node_id, "node-a");
        assert_eq!(snapshot.cluster_id, "cluster-a");
        assert_eq!(snapshot.cluster_peer_count(), 2);
        assert_eq!(snapshot.cluster_peers, vec!["node-b", "node-c"]);
        assert_eq!(snapshot.membership_node_count(), 3);
        assert_eq!(
            snapshot.membership_nodes,
            vec!["node-a", "node-b", "node-c"]
        );
        assert_eq!(snapshot.membership_protocol, MembershipProtocol::Raft);
        assert!(!snapshot.membership_status.ready);
        assert!(!snapshot.membership_status.converged);
        assert!(!snapshot.membership_view_id.is_empty());
        assert_eq!(snapshot.placement_epoch, 11);
    }

    #[tokio::test]
    async fn runtime_topology_snapshot_uses_observed_membership_last_update_timestamp() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let storage = FilesystemStorage::new(
            temp.path().to_str().expect("path should be utf8"),
            false,
            1024,
            0,
        )
        .await
        .expect("storage should initialize");
        let membership_peers = vec!["node-b".to_string()];
        let membership_view_id = membership_view_id_with_self("node-a", &membership_peers);
        let state = AppState {
            storage: Arc::new(storage),
            config: Arc::new(test_config()),
            credentials: Arc::new(HashMap::new()),
            node_id: Arc::new("node-a".to_string()),
            cluster_id: Arc::new("cluster-a".to_string()),
            membership_peers: Arc::new(RwLock::new(membership_peers.clone())),
            membership_view_id: Arc::new(RwLock::new(membership_view_id)),
            cluster_peers: Arc::new(membership_peers),
            membership_protocol: MembershipProtocol::StaticBootstrap,
            write_durability_mode: WriteDurabilityMode::DegradedSuccess,
            metadata_listing_strategy: ClusterMetadataListingStrategy::LocalNodeOnly,
            membership_engine: MembershipEngine::for_protocol(MembershipProtocol::StaticBootstrap),
            membership_last_update_unix_ms: Arc::new(AtomicU64::new(10)),
            membership_converged: Arc::new(AtomicU64::new(0)),
            join_nonce_replay_guard: Arc::new(InMemoryJoinNonceReplayGuard::new(
                JOIN_NONCE_REPLAY_GUARD_TTL_MS,
                JOIN_NONCE_REPLAY_GUARD_MAX_ENTRIES,
            )),
            cluster_join_authorize_counters: Arc::new(ClusterJoinAuthorizeCounters::default()),
            cluster_join_counters: Arc::new(ClusterJoinCounters::default()),
            cluster_membership_update_counters: Arc::new(ClusterMembershipUpdateCounters::default()),
            pending_replication_replay_counters: Arc::new(
                PendingReplicationReplayCounters::default(),
            ),
            pending_rebalance_replay_counters: Arc::new(PendingRebalanceReplayCounters::default()),
            pending_membership_propagation_replay_counters: Arc::new(
                PendingMembershipPropagationReplayCounters::default(),
            ),
            pending_metadata_repair_replay_counters: Arc::new(
                PendingMetadataRepairReplayCounters::default(),
            ),
            placement_epoch: Arc::new(AtomicU64::new(1)),
            runtime_internal_header_reject_dimensions: Arc::new(
                RuntimeInternalHeaderRejectDimensions::default(),
            ),
            login_rate_limiter: Arc::new(LoginRateLimiter::new()),
            request_count: Arc::new(AtomicU64::new(0)),
            started_at: Instant::now(),
        };

        let baseline = state.membership_engine.last_update_unix_ms();
        let bumped = baseline.saturating_add(5000);
        record_membership_last_update(&state, bumped);
        record_membership_last_update(&state, baseline.saturating_add(1));

        let snapshot = runtime_topology_snapshot(&state);
        assert_eq!(snapshot.membership_status.last_update_unix_ms, bumped);
    }

    #[tokio::test]
    async fn runtime_topology_snapshot_uses_observed_static_bootstrap_convergence_state() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let storage = FilesystemStorage::new(
            temp.path().to_str().expect("path should be utf8"),
            false,
            1024,
            0,
        )
        .await
        .expect("storage should initialize");
        let membership_peers = vec!["node-b".to_string()];
        let membership_view_id = membership_view_id_with_self("node-a", &membership_peers);
        let state = AppState {
            storage: Arc::new(storage),
            config: Arc::new(test_config()),
            credentials: Arc::new(HashMap::new()),
            node_id: Arc::new("node-a".to_string()),
            cluster_id: Arc::new("cluster-a".to_string()),
            membership_peers: Arc::new(RwLock::new(membership_peers.clone())),
            membership_view_id: Arc::new(RwLock::new(membership_view_id)),
            cluster_peers: Arc::new(membership_peers),
            membership_protocol: MembershipProtocol::StaticBootstrap,
            write_durability_mode: WriteDurabilityMode::DegradedSuccess,
            metadata_listing_strategy: ClusterMetadataListingStrategy::LocalNodeOnly,
            membership_engine: MembershipEngine::for_protocol(MembershipProtocol::StaticBootstrap),
            membership_last_update_unix_ms: Arc::new(AtomicU64::new(10)),
            membership_converged: Arc::new(AtomicU64::new(0)),
            join_nonce_replay_guard: Arc::new(InMemoryJoinNonceReplayGuard::new(
                JOIN_NONCE_REPLAY_GUARD_TTL_MS,
                JOIN_NONCE_REPLAY_GUARD_MAX_ENTRIES,
            )),
            cluster_join_authorize_counters: Arc::new(ClusterJoinAuthorizeCounters::default()),
            cluster_join_counters: Arc::new(ClusterJoinCounters::default()),
            cluster_membership_update_counters: Arc::new(ClusterMembershipUpdateCounters::default()),
            pending_replication_replay_counters: Arc::new(
                PendingReplicationReplayCounters::default(),
            ),
            pending_rebalance_replay_counters: Arc::new(PendingRebalanceReplayCounters::default()),
            pending_membership_propagation_replay_counters: Arc::new(
                PendingMembershipPropagationReplayCounters::default(),
            ),
            pending_metadata_repair_replay_counters: Arc::new(
                PendingMetadataRepairReplayCounters::default(),
            ),
            placement_epoch: Arc::new(AtomicU64::new(1)),
            runtime_internal_header_reject_dimensions: Arc::new(
                RuntimeInternalHeaderRejectDimensions::default(),
            ),
            login_rate_limiter: Arc::new(LoginRateLimiter::new()),
            request_count: Arc::new(AtomicU64::new(0)),
            started_at: Instant::now(),
        };

        let non_converged_snapshot = runtime_topology_snapshot(&state);
        assert!(!non_converged_snapshot.membership_status.converged);

        record_membership_convergence(&state, true);
        let converged_snapshot = runtime_topology_snapshot(&state);
        assert!(converged_snapshot.membership_status.converged);
    }

    #[test]
    fn runtime_internal_header_reject_endpoint_classification_is_bounded() {
        assert_eq!(
            RuntimeInternalHeaderRejectEndpoint::for_path("/api/auth/check"),
            RuntimeInternalHeaderRejectEndpoint::Api
        );
        assert_eq!(
            RuntimeInternalHeaderRejectEndpoint::for_path("/healthz"),
            RuntimeInternalHeaderRejectEndpoint::Healthz
        );
        assert_eq!(
            RuntimeInternalHeaderRejectEndpoint::for_path("/metrics"),
            RuntimeInternalHeaderRejectEndpoint::Metrics
        );
        assert_eq!(
            RuntimeInternalHeaderRejectEndpoint::for_path("/ui/bucket"),
            RuntimeInternalHeaderRejectEndpoint::Ui
        );
        assert_eq!(
            RuntimeInternalHeaderRejectEndpoint::for_path("/unknown"),
            RuntimeInternalHeaderRejectEndpoint::Other
        );
    }

    #[test]
    fn classify_runtime_internal_header_reject_sender_resolves_sender_categories() {
        let mut known_peer_headers = HeaderMap::new();
        known_peer_headers.insert(FORWARDED_BY_HEADER, "node-b:9000".parse().expect("header"));
        assert_eq!(
            classify_runtime_internal_header_reject_sender(
                &known_peer_headers,
                "node-a:9000",
                &[String::from("node-b:9000")],
            ),
            RuntimeInternalHeaderRejectSender::KnownPeer
        );

        let mut local_sender_headers = HeaderMap::new();
        local_sender_headers.insert(FORWARDED_BY_HEADER, "node-a:9000".parse().expect("header"));
        assert_eq!(
            classify_runtime_internal_header_reject_sender(
                &local_sender_headers,
                "node-a:9000",
                &[String::from("node-b:9000")],
            ),
            RuntimeInternalHeaderRejectSender::LocalNode
        );

        let mut unknown_peer_headers = HeaderMap::new();
        unknown_peer_headers.insert(FORWARDED_BY_HEADER, "node-x:9000".parse().expect("header"));
        assert_eq!(
            classify_runtime_internal_header_reject_sender(
                &unknown_peer_headers,
                "node-a:9000",
                &[String::from("node-b:9000")],
            ),
            RuntimeInternalHeaderRejectSender::UnknownPeer
        );

        let mut multi_hop_headers = HeaderMap::new();
        multi_hop_headers.insert(
            FORWARDED_BY_HEADER,
            "node-x:9000,node-b:9000".parse().expect("header"),
        );
        assert_eq!(
            classify_runtime_internal_header_reject_sender(
                &multi_hop_headers,
                "node-a:9000",
                &[String::from("node-b:9000")],
            ),
            RuntimeInternalHeaderRejectSender::KnownPeer
        );
    }

    #[test]
    fn classify_runtime_internal_header_reject_sender_handles_missing_or_invalid_chains() {
        let empty_headers = HeaderMap::new();
        assert_eq!(
            classify_runtime_internal_header_reject_sender(&empty_headers, "node-a:9000", &[]),
            RuntimeInternalHeaderRejectSender::MissingOrInvalid
        );

        let mut malformed_headers = HeaderMap::new();
        malformed_headers.insert(
            FORWARDED_BY_HEADER,
            "node-a:9000,node-a:9000".parse().expect("header"),
        );
        assert_eq!(
            classify_runtime_internal_header_reject_sender(&malformed_headers, "node-a:9000", &[]),
            RuntimeInternalHeaderRejectSender::MissingOrInvalid
        );
    }

    #[test]
    fn cluster_join_authorize_counters_track_status_and_reason_labels() {
        let counters = ClusterJoinAuthorizeCounters::default();
        counters.record("authorized", "authorized");
        counters.record("rejected", "join_nonce_replay_detected");
        counters.record("misconfigured", "invalid_configuration");
        counters.record(
            "misconfigured",
            JOIN_AUTHORIZE_REASON_DISTRIBUTED_MODE_DISABLED,
        );
        counters.record(
            "misconfigured",
            JOIN_AUTHORIZE_REASON_MEMBERSHIP_ENGINE_NOT_READY,
        );
        counters.record(
            "misconfigured",
            JOIN_AUTHORIZE_REASON_CLUSTER_AUTH_TOKEN_NOT_CONFIGURED,
        );
        counters.record("rejected", "unexpected-reason");

        let snapshot = counters.snapshot();
        assert_eq!(snapshot.total, 7);
        assert_eq!(snapshot.status_authorized, 1);
        assert_eq!(snapshot.status_rejected, 2);
        assert_eq!(snapshot.status_misconfigured, 4);
        assert_eq!(snapshot.reason_authorized, 1);
        assert_eq!(snapshot.reason_join_nonce_replay_detected, 1);
        assert_eq!(snapshot.reason_invalid_configuration, 1);
        assert_eq!(snapshot.reason_distributed_mode_disabled, 1);
        assert_eq!(snapshot.reason_membership_engine_not_ready, 1);
        assert_eq!(snapshot.reason_cluster_auth_token_not_configured, 1);
        assert_eq!(snapshot.reason_unknown, 1);
    }

    #[test]
    fn cluster_join_counters_track_status_and_reason_labels() {
        let counters = ClusterJoinCounters::default();
        counters.record("applied", MEMBERSHIP_UPDATE_REASON_APPLIED);
        counters.record("rejected", MEMBERSHIP_UPDATE_REASON_INVALID_PAYLOAD);
        counters.record("rejected", MEMBERSHIP_UPDATE_REASON_PRECONDITION_FAILED);
        counters.record("rejected", MEMBERSHIP_UPDATE_REASON_UNAUTHORIZED);
        counters.record(
            "misconfigured",
            JOIN_AUTHORIZE_REASON_DISTRIBUTED_MODE_DISABLED,
        );
        counters.record(
            "misconfigured",
            JOIN_AUTHORIZE_REASON_MEMBERSHIP_ENGINE_NOT_READY,
        );
        counters.record(
            "misconfigured",
            JOIN_AUTHORIZE_REASON_CLUSTER_AUTH_TOKEN_NOT_CONFIGURED,
        );
        counters.record(
            "misconfigured",
            MEMBERSHIP_UPDATE_REASON_STATE_PERSIST_FAILED,
        );
        counters.record("rejected", "unexpected-reason");

        let snapshot = counters.snapshot();
        assert_eq!(snapshot.total, 9);
        assert_eq!(snapshot.status_applied, 1);
        assert_eq!(snapshot.status_rejected, 4);
        assert_eq!(snapshot.status_misconfigured, 4);
        assert_eq!(snapshot.reason_applied, 1);
        assert_eq!(snapshot.reason_invalid_payload, 1);
        assert_eq!(snapshot.reason_precondition_failed, 1);
        assert_eq!(snapshot.reason_unauthorized, 1);
        assert_eq!(snapshot.reason_distributed_mode_disabled, 1);
        assert_eq!(snapshot.reason_membership_engine_not_ready, 1);
        assert_eq!(snapshot.reason_cluster_auth_token_not_configured, 1);
        assert_eq!(snapshot.reason_state_persist_failed, 1);
        assert_eq!(snapshot.reason_unknown, 1);
    }

    #[test]
    fn cluster_membership_update_counters_track_status_and_reason_labels() {
        let counters = ClusterMembershipUpdateCounters::default();
        counters.record("applied", MEMBERSHIP_UPDATE_REASON_APPLIED);
        counters.record("rejected", MEMBERSHIP_UPDATE_REASON_INVALID_PAYLOAD);
        counters.record("rejected", MEMBERSHIP_UPDATE_REASON_CLUSTER_ID_MISMATCH);
        counters.record("rejected", MEMBERSHIP_UPDATE_REASON_PRECONDITION_FAILED);
        counters.record("rejected", MEMBERSHIP_UPDATE_REASON_UNAUTHORIZED);
        counters.record(
            "misconfigured",
            JOIN_AUTHORIZE_REASON_DISTRIBUTED_MODE_DISABLED,
        );
        counters.record(
            "misconfigured",
            JOIN_AUTHORIZE_REASON_MEMBERSHIP_ENGINE_NOT_READY,
        );
        counters.record(
            "misconfigured",
            JOIN_AUTHORIZE_REASON_CLUSTER_AUTH_TOKEN_NOT_CONFIGURED,
        );
        counters.record(
            "misconfigured",
            MEMBERSHIP_UPDATE_REASON_STATE_PERSIST_FAILED,
        );
        counters.record("rejected", "unexpected-reason");

        let snapshot = counters.snapshot();
        assert_eq!(snapshot.total, 10);
        assert_eq!(snapshot.status_applied, 1);
        assert_eq!(snapshot.status_rejected, 5);
        assert_eq!(snapshot.status_misconfigured, 4);
        assert_eq!(snapshot.reason_applied, 1);
        assert_eq!(snapshot.reason_invalid_payload, 1);
        assert_eq!(snapshot.reason_cluster_id_mismatch, 1);
        assert_eq!(snapshot.reason_precondition_failed, 1);
        assert_eq!(snapshot.reason_unauthorized, 1);
        assert_eq!(snapshot.reason_distributed_mode_disabled, 1);
        assert_eq!(snapshot.reason_membership_engine_not_ready, 1);
        assert_eq!(snapshot.reason_cluster_auth_token_not_configured, 1);
        assert_eq!(snapshot.reason_state_persist_failed, 1);
        assert_eq!(snapshot.reason_unknown, 1);
    }

    #[test]
    fn pending_replication_replay_counters_track_success_and_failure_cycles() {
        let counters = PendingReplicationReplayCounters::default();
        counters.record_success(3, 2, 1, 1, 1);
        counters.record_failure();

        let snapshot = counters.snapshot();
        assert_eq!(snapshot.cycles_total, 2);
        assert_eq!(snapshot.cycles_succeeded, 1);
        assert_eq!(snapshot.cycles_failed, 1);
        assert_eq!(snapshot.scanned_total, 3);
        assert_eq!(snapshot.leased_total, 2);
        assert_eq!(snapshot.acknowledged_total, 1);
        assert_eq!(snapshot.failed_total, 1);
        assert_eq!(snapshot.skipped_total, 1);
        assert!(snapshot.last_cycle_unix_ms > 0);
        assert!(snapshot.last_success_unix_ms > 0);
        assert!(snapshot.last_failure_unix_ms > 0);
    }

    #[test]
    fn pending_rebalance_replay_counters_track_success_and_failure_cycles() {
        let counters = PendingRebalanceReplayCounters::default();
        counters.record_success(6, 5, 3, 1, 2);
        counters.record_failure();

        let snapshot = counters.snapshot();
        assert_eq!(snapshot.cycles_total, 2);
        assert_eq!(snapshot.cycles_succeeded, 1);
        assert_eq!(snapshot.cycles_failed, 1);
        assert_eq!(snapshot.scanned_total, 6);
        assert_eq!(snapshot.leased_total, 5);
        assert_eq!(snapshot.acknowledged_total, 3);
        assert_eq!(snapshot.failed_total, 1);
        assert_eq!(snapshot.skipped_total, 2);
        assert!(snapshot.last_cycle_unix_ms > 0);
        assert!(snapshot.last_success_unix_ms > 0);
        assert!(snapshot.last_failure_unix_ms > 0);
    }

    #[test]
    fn pending_metadata_repair_replay_counters_track_success_and_failure_cycles() {
        let counters = PendingMetadataRepairReplayCounters::default();
        counters.record_success(4, 3, 0, 3, 1);
        counters.record_failure();

        let snapshot = counters.snapshot();
        assert_eq!(snapshot.cycles_total, 2);
        assert_eq!(snapshot.cycles_succeeded, 1);
        assert_eq!(snapshot.cycles_failed, 1);
        assert_eq!(snapshot.scanned_plans_total, 4);
        assert_eq!(snapshot.leased_plans_total, 3);
        assert_eq!(snapshot.acknowledged_plans_total, 0);
        assert_eq!(snapshot.failed_plans_total, 3);
        assert_eq!(snapshot.skipped_plans_total, 1);
        assert!(snapshot.last_cycle_unix_ms > 0);
        assert!(snapshot.last_success_unix_ms > 0);
        assert!(snapshot.last_failure_unix_ms > 0);
    }

    #[test]
    fn pending_membership_propagation_replay_counters_track_success_and_failure_cycles() {
        let counters = PendingMembershipPropagationReplayCounters::default();
        counters.record_success(5, 4, 2, 3, 1);
        counters.record_failure();

        let snapshot = counters.snapshot();
        assert_eq!(snapshot.cycles_total, 2);
        assert_eq!(snapshot.cycles_succeeded, 1);
        assert_eq!(snapshot.cycles_failed, 1);
        assert_eq!(snapshot.scanned_operations_total, 5);
        assert_eq!(snapshot.replayed_operations_total, 4);
        assert_eq!(snapshot.deferred_operations_total, 2);
        assert_eq!(snapshot.acknowledged_operations_total, 3);
        assert_eq!(snapshot.failed_operations_total, 1);
        assert!(snapshot.last_cycle_unix_ms > 0);
        assert!(snapshot.last_success_unix_ms > 0);
        assert!(snapshot.last_failure_unix_ms > 0);
    }

    #[test]
    fn build_pending_membership_propagation_replay_workset_caps_and_prioritizes_due_operations() {
        let request = ClusterMembershipUpdateRequest {
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b.internal:9000".to_string()],
            expected_membership_view_id: None,
            expected_placement_epoch: None,
        };
        let operation = |peer: &str, attempts: u32, created_at: u64, next_retry: Option<u64>| {
            PendingMembershipPropagationOperation {
                peer: peer.to_string(),
                request: request.clone(),
                attempts,
                created_at_unix_ms: created_at,
                updated_at_unix_ms: created_at,
                next_retry_at_unix_ms: next_retry,
                last_error: None,
            }
        };

        let now_unix_ms = 5_000;
        let workset = build_pending_membership_propagation_replay_workset(
            vec![
                operation("node-c.internal:9000", 3, 1_000, Some(4_000)),
                operation("node-a.internal:9000", 1, 2_000, Some(4_500)),
                operation("node-b.internal:9000", 1, 3_000, Some(4_600)),
                operation("node-z.internal:9000", 1, 4_000, Some(now_unix_ms + 2_000)),
            ],
            now_unix_ms,
            2,
        );

        assert_eq!(workset.scanned_operations, 4);
        assert_eq!(workset.replay_due_operations.len(), 2);
        assert_eq!(workset.deferred_due_operations, 1);
        assert_eq!(
            workset
                .replay_due_operations
                .iter()
                .map(|operation| operation.peer.as_str())
                .collect::<Vec<_>>(),
            vec!["node-a.internal:9000", "node-b.internal:9000"]
        );
        assert_eq!(workset.retained_operations.len(), 2);
        assert!(
            workset
                .retained_operations
                .iter()
                .any(|operation| operation.peer == "node-c.internal:9000")
        );
        assert!(
            workset
                .retained_operations
                .iter()
                .any(|operation| operation.peer == "node-z.internal:9000")
        );
    }

    #[test]
    fn apply_pending_membership_propagation_replay_outcomes_acknowledges_and_retries() {
        let request = ClusterMembershipUpdateRequest {
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b.internal:9000".to_string()],
            expected_membership_view_id: None,
            expected_placement_epoch: None,
        };
        let operation = |peer: &str, attempts: u32, created_at: u64, next_retry: Option<u64>| {
            PendingMembershipPropagationOperation {
                peer: peer.to_string(),
                request: request.clone(),
                attempts,
                created_at_unix_ms: created_at,
                updated_at_unix_ms: created_at,
                next_retry_at_unix_ms: next_retry,
                last_error: None,
            }
        };

        let acked_original = operation("node-a.internal:9000", 1, 1_000, Some(2_000));
        let failed_original = operation("node-b.internal:9000", 1, 2_000, Some(2_500));
        let mut failed_retry = failed_original.clone();
        failed_retry.attempts = 2;
        failed_retry.updated_at_unix_ms = 3_000;
        failed_retry.next_retry_at_unix_ms = Some(4_000);
        failed_retry.last_error = Some("transport failure".to_string());
        let untouched = operation("node-c.internal:9000", 1, 3_000, Some(5_000));

        let merged = apply_pending_membership_propagation_replay_outcomes(
            vec![
                acked_original.clone(),
                failed_original.clone(),
                untouched.clone(),
            ],
            vec![
                PendingMembershipPropagationReplayOperationOutcome::Acknowledged {
                    original: acked_original,
                },
                PendingMembershipPropagationReplayOperationOutcome::Failed {
                    original: failed_original,
                    retry: failed_retry.clone(),
                },
            ],
        );

        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0], failed_retry);
        assert_eq!(merged[1], untouched);
    }

    #[test]
    fn apply_pending_membership_propagation_replay_outcomes_preserves_concurrent_peer_updates() {
        let request = ClusterMembershipUpdateRequest {
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b.internal:9000".to_string()],
            expected_membership_view_id: None,
            expected_placement_epoch: None,
        };
        let operation = |peer: &str, attempts: u32, created_at: u64, next_retry: Option<u64>| {
            PendingMembershipPropagationOperation {
                peer: peer.to_string(),
                request: request.clone(),
                attempts,
                created_at_unix_ms: created_at,
                updated_at_unix_ms: created_at,
                next_retry_at_unix_ms: next_retry,
                last_error: None,
            }
        };

        let acked_original = operation("node-a.internal:9000", 1, 1_000, Some(2_000));
        let failed_original = operation("node-b.internal:9000", 1, 2_000, Some(2_500));
        let mut failed_retry = failed_original.clone();
        failed_retry.attempts = 2;
        failed_retry.updated_at_unix_ms = 3_000;
        failed_retry.next_retry_at_unix_ms = Some(4_000);
        failed_retry.last_error = Some("transport failure".to_string());

        // Simulate concurrent queue mutations that happened after the replay worker loaded
        // its initial snapshot.
        let mut concurrent_acked_peer_update = acked_original.clone();
        concurrent_acked_peer_update.attempts = 5;
        concurrent_acked_peer_update.updated_at_unix_ms = 4_200;
        concurrent_acked_peer_update.next_retry_at_unix_ms = Some(6_000);
        let mut concurrent_failed_peer_update = failed_original.clone();
        concurrent_failed_peer_update.attempts = 4;
        concurrent_failed_peer_update.updated_at_unix_ms = 4_300;
        concurrent_failed_peer_update.next_retry_at_unix_ms = Some(6_100);
        concurrent_failed_peer_update.last_error = Some("newer update".to_string());

        let merged = apply_pending_membership_propagation_replay_outcomes(
            vec![
                concurrent_acked_peer_update.clone(),
                concurrent_failed_peer_update.clone(),
            ],
            vec![
                PendingMembershipPropagationReplayOperationOutcome::Acknowledged {
                    original: acked_original,
                },
                PendingMembershipPropagationReplayOperationOutcome::Failed {
                    original: failed_original,
                    retry: failed_retry,
                },
            ],
        );

        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0], concurrent_acked_peer_update);
        assert_eq!(merged[1], concurrent_failed_peer_update);
    }
}
