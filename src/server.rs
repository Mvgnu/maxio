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
mod metadata_probe;
mod middleware;
mod observability;
mod persistence;
mod probes;
mod replay_workers;

use cluster_handlers::*;
use metadata_probe::*;
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
    DEFAULT_JOIN_MAX_CLOCK_SKEW_MS, DurableJoinNonceReplayGuard, JOIN_CLUSTER_ID_HEADER,
    JOIN_NODE_ID_HEADER, JOIN_NONCE_HEADER, JOIN_TIMESTAMP_HEADER, JoinAuthorizationError,
    JoinNonceReplayGuard, authorize_join_request,
};
use crate::cluster::peer_identity::canonical_peer_identity;
use crate::cluster::security::INTERNAL_AUTH_TOKEN_HEADER;
use crate::cluster::transport_identity::{
    PeerCertificatePolicy, PeerTransportEnforcementMode, PeerTransportIdentityMode,
    PeerTransportIdentityReadinessReason, PeerTransportIdentityStatus,
    PeerTransportPolicyAssessment, assess_cluster_peer_auth_production_readiness,
    assess_peer_transport_policy_with_context,
    attest_peer_transport_identity_with_mtls_with_policy, peer_transport_policy_effective_reason,
    probe_peer_transport_identity_with_certificate_policy_and_node_id_binding,
};
use crate::config::{
    Config, MembershipProtocol, WriteDurabilityMode, parse_cluster_peer_addresses,
};
use crate::embedded::ui_handler;
use crate::membership::{MembershipEngine, MembershipEngineStatus, unix_ms_now};
use crate::metadata::reconciliation::{
    PendingMetadataRepairReplayExecutionConfig,
    replay_pending_metadata_repairs_once_with_persisted_state_apply_and_observer,
};
use crate::metadata::{
    ClusterMetadataListingStrategy, ClusterMetadataSnapshotAssessment,
    PendingMetadataRepairQueueSummary, assess_cluster_metadata_snapshot_for_topology_responders,
    assess_cluster_metadata_snapshot_for_topology_single_responder,
    build_queryable_metadata_index_from_persisted_state,
    cluster_metadata_fan_in_auth_token_reject_reason, load_persisted_metadata_state,
    pending_metadata_repair_candidates_from_disk,
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
    select_chunk_owners_with_self, select_object_owners_with_self,
    summarize_pending_rebalance_queue_from_disk, summarize_pending_replication_queue,
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
const JOIN_NONCE_REPLAY_STATE_FILE: &str = "join-nonce-replay.json";
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
    pub join_nonce_replay_guard: Arc<dyn JoinNonceReplayGuard + Send + Sync>,
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
    endpoint_internal: AtomicU64,
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
            endpoint_internal: AtomicU64::new(0),
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
    Internal,
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
        if path == "/internal" || path.starts_with("/internal/") {
            return Self::Internal;
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
    endpoint_internal: u64,
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
    dropped_plans_total: AtomicU64,
    skipped_plans_total: AtomicU64,
    terminal_failure_reason_totals: RwLock<HashMap<String, u64>>,
    last_cycle_unix_ms: AtomicU64,
    last_success_unix_ms: AtomicU64,
    last_failure_unix_ms: AtomicU64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct PendingMetadataRepairReplayCountersSnapshot {
    cycles_total: u64,
    cycles_succeeded: u64,
    cycles_failed: u64,
    scanned_plans_total: u64,
    leased_plans_total: u64,
    acknowledged_plans_total: u64,
    failed_plans_total: u64,
    dropped_plans_total: u64,
    skipped_plans_total: u64,
    terminal_failure_reason_totals: Vec<(String, u64)>,
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
            dropped_plans_total: AtomicU64::new(0),
            skipped_plans_total: AtomicU64::new(0),
            terminal_failure_reason_totals: RwLock::new(HashMap::new()),
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
    fn record_terminal_failure_reason(&self, reason: &str) {
        let reason = reason.trim();
        if reason.is_empty() {
            return;
        }
        let mut guard = match self.terminal_failure_reason_totals.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let counter = guard.entry(reason.to_string()).or_insert(0);
        *counter = counter.saturating_add(1);
    }

    fn record_success(
        &self,
        scanned_plans: usize,
        leased_plans: usize,
        acknowledged_plans: usize,
        failed_plans: usize,
        dropped_plans: usize,
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
        self.dropped_plans_total
            .fetch_add(dropped_plans as u64, Ordering::Relaxed);
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
        let terminal_failure_reason_totals = match self.terminal_failure_reason_totals.read() {
            Ok(guard) => {
                let mut values = guard
                    .iter()
                    .map(|(reason, total)| (reason.clone(), *total))
                    .collect::<Vec<_>>();
                values.sort_by(|left, right| left.0.cmp(&right.0));
                values
            }
            Err(poisoned) => {
                let mut values = poisoned
                    .into_inner()
                    .iter()
                    .map(|(reason, total)| (reason.clone(), *total))
                    .collect::<Vec<_>>();
                values.sort_by(|left, right| left.0.cmp(&right.0));
                values
            }
        };
        PendingMetadataRepairReplayCountersSnapshot {
            cycles_total: self.cycles_total.load(Ordering::Relaxed),
            cycles_succeeded: self.cycles_succeeded.load(Ordering::Relaxed),
            cycles_failed: self.cycles_failed.load(Ordering::Relaxed),
            scanned_plans_total: self.scanned_plans_total.load(Ordering::Relaxed),
            leased_plans_total: self.leased_plans_total.load(Ordering::Relaxed),
            acknowledged_plans_total: self.acknowledged_plans_total.load(Ordering::Relaxed),
            failed_plans_total: self.failed_plans_total.load(Ordering::Relaxed),
            dropped_plans_total: self.dropped_plans_total.load(Ordering::Relaxed),
            skipped_plans_total: self.skipped_plans_total.load(Ordering::Relaxed),
            terminal_failure_reason_totals,
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
            RuntimeInternalHeaderRejectEndpoint::Internal => {
                self.endpoint_internal.fetch_add(1, Ordering::Relaxed);
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
            endpoint_internal: self.endpoint_internal.load(Ordering::Relaxed),
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
        let next_cluster_peers = normalize_cluster_peers_for_membership_update(
            self.node_id.as_str(),
            &next_cluster_peers,
        )
        .map_err(anyhow::Error::msg)?;
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
    pub async fn from_config(mut config: Config) -> anyhow::Result<Self> {
        let credentials = config.credential_map().map_err(anyhow::Error::msg)?;
        let cluster_peers = config.parsed_cluster_peers().map_err(anyhow::Error::msg)?;
        // Programmatic Config callers retain invalid-identity health diagnostics;
        // CLI parsing rejects invalid IDs before startup. Valid IDs always use the
        // same canonical spelling for transport authentication and placement.
        if let Some(node_id) = canonical_peer_identity(&config.node_id) {
            config.node_id = node_id;
        }
        config.cluster_peers = cluster_peers.clone();
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
        let join_nonce_replay_state_path = join_nonce_replay_state_path(config.data_dir.as_str());

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
            join_nonce_replay_guard: Arc::new(DurableJoinNonceReplayGuard::new(
                join_nonce_replay_state_path,
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

fn join_nonce_replay_state_path(data_dir: &str) -> PathBuf {
    Path::new(data_dir)
        .join(PLACEMENT_STATE_DIR)
        .join(JOIN_NONCE_REPLAY_STATE_FILE)
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

fn internal_cluster_routes(state: AppState) -> Router<AppState> {
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
        .layer(axum::middleware::from_fn_with_state(
            state,
            internal_forwarding_sanitization_middleware,
        ))
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
    apply_runtime_middleware(state.clone(), internal_cluster_routes(state))
}

pub fn build_router(state: AppState) -> Router {
    let routes = Router::new()
        .merge(platform_routes(state.clone()))
        .merge(internal_cluster_routes(state.clone()))
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
    transport_identity: PeerTransportIdentityMode,
    transport_reason: PeerTransportIdentityReadinessReason,
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
    Dropped {
        original: PendingMembershipPropagationOperation,
    },
    Failed {
        original: PendingMembershipPropagationOperation,
        retry: PendingMembershipPropagationOperation,
    },
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct MembershipPropagationFailure {
    message: String,
    retryable: bool,
}

impl MembershipPropagationFailure {
    fn retryable(message: String) -> Self {
        Self {
            message,
            retryable: true,
        }
    }

    fn terminal(message: String) -> Self {
        Self {
            message,
            retryable: false,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct MembershipPropagationPeerResult {
    peer: String,
    failure: Option<MembershipPropagationFailure>,
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
        json_body_or_fallback(
            &payload,
            b"{\"status\":\"degraded\",\"updated\":false}",
            "membership_update_response",
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
        json_body_or_fallback(
            &payload,
            b"{\"status\":\"degraded\",\"updated\":false}",
            "cluster_join_response",
        ),
    )
}

fn peer_identity_eq(lhs: &str, rhs: &str) -> bool {
    match (canonical_peer_identity(lhs), canonical_peer_identity(rhs)) {
        (Some(lhs), Some(rhs)) => lhs == rhs,
        _ => lhs.trim().eq_ignore_ascii_case(rhs.trim()),
    }
}

fn normalize_cluster_peers_for_membership_update(
    local_node_id: &str,
    peers: &[String],
) -> Result<Vec<String>, String> {
    let normalized = parse_cluster_peer_addresses(peers)?;
    for normalized_peer in &normalized {
        if peer_identity_eq(normalized_peer.as_str(), local_node_id) {
            return Err(format!(
                "Invalid cluster peer '{}': peer must not match local node id",
                normalized_peer
            ));
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

fn runtime_peer_transport_has_cluster_peers(config: &Config) -> bool {
    match config.parsed_cluster_peers() {
        Ok(peers) => !peers.is_empty(),
        Err(_) => true,
    }
}

fn runtime_peer_transport_policy_assessment(
    config: &Config,
    status: &PeerTransportIdentityStatus,
) -> PeerTransportPolicyAssessment {
    let enforcement_mode = if config.cluster_peer_transport_required() {
        PeerTransportEnforcementMode::StrictMtlsIdentityBound
    } else {
        PeerTransportEnforcementMode::Compatibility
    };
    let has_cluster_peers = runtime_peer_transport_has_cluster_peers(config);
    let auth_configured = config.cluster_auth_token().is_some();
    assess_peer_transport_policy_with_context(
        status,
        enforcement_mode,
        has_cluster_peers,
        auth_configured,
        has_cluster_peers,
    )
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
            probe_peer_transport_identity_with_certificate_policy_and_node_id_binding(
                config.cluster_peer_tls_cert_path(),
                config.cluster_peer_tls_key_path(),
                config.cluster_peer_tls_ca_path(),
                PeerCertificatePolicy {
                    sha256_pin: config.cluster_peer_tls_cert_sha256(),
                    sha256_revocations: config.cluster_peer_tls_cert_sha256_revocations(),
                },
                expected_node_id,
            );
        let policy = runtime_peer_transport_policy_assessment(config, &identity_status);
        let readiness_reason = peer_transport_policy_effective_reason(&policy).as_str();
        if policy.required && !policy.is_ready() {
            return Err(format!(
                "mTLS peer transport policy requires ready peer transport identity in current mode ({readiness_reason})"
            ));
        }

        if identity_status.mode.as_str() == "mtls-path" {
            if !identity_status.transport_ready {
                let warning = identity_status.warning.as_deref().unwrap_or(
                    "mTLS peer transport identity is not ready with current configuration",
                );
                return Err(format!(
                    "mTLS peer transport is not ready ({}): {}",
                    readiness_reason, warning
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
    let identity_status = probe_peer_transport_identity_with_certificate_policy_and_node_id_binding(
        config.cluster_peer_tls_cert_path(),
        config.cluster_peer_tls_key_path(),
        config.cluster_peer_tls_ca_path(),
        PeerCertificatePolicy {
            sha256_pin: config.cluster_peer_tls_cert_sha256(),
            sha256_revocations: config.cluster_peer_tls_cert_sha256_revocations(),
        },
        expected_node_id,
    );
    let policy = runtime_peer_transport_policy_assessment(config, &identity_status);
    let readiness_reason = peer_transport_policy_effective_reason(&policy).as_str();
    if policy.required && !policy.is_ready() {
        return Err(format!(
            "mTLS peer transport policy requires ready peer transport identity in current mode ({readiness_reason})"
        ));
    }
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
            readiness_reason, warning
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

    attest_peer_transport_identity_with_mtls_with_policy(
        peer,
        peer,
        cert_path,
        key_path,
        trust_store_path,
        PeerCertificatePolicy {
            sha256_pin: None,
            sha256_revocations: config.cluster_peer_tls_cert_sha256_revocations(),
        },
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
            if let Some(failure) = result.failure {
                persist_membership_propagation_failure_if_retryable(
                    config.as_ref(),
                    result.peer.as_str(),
                    &request,
                    &failure,
                    "membership propagation",
                )
                .await;
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
                    retryable = error.retryable,
                    error = error.message.as_str(),
                    "Gossip stale-peer reconciliation update failed"
                );
                persist_membership_propagation_failure_if_retryable(
                    config.as_ref(),
                    target.peer.as_str(),
                    &request,
                    &error,
                    "gossip stale-peer reconciliation",
                )
                .await;
            }
        }
    });
}

async fn persist_membership_propagation_failure_if_retryable(
    config: &Config,
    peer: &str,
    request: &ClusterMembershipUpdateRequest,
    failure: &MembershipPropagationFailure,
    context: &str,
) {
    if !failure.retryable {
        tracing::warn!(
            peer,
            error = failure.message.as_str(),
            "Skipping persistence of terminal {} failure",
            context
        );
        return;
    }

    if let Err(queue_error) = record_pending_membership_propagation_failure(
        config.data_dir.as_str(),
        peer,
        request,
        Some(failure.message.as_str()),
    )
    .await
    {
        tracing::warn!(
            peer,
            error = ?queue_error,
            "Failed to persist pending {} operation",
            context
        );
    }
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
                    failure: Some(MembershipPropagationFailure::terminal(err.clone())),
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
            Ok(()) => results.push(MembershipPropagationPeerResult {
                peer,
                failure: None,
            }),
            Err(failure) => results.push(MembershipPropagationPeerResult {
                peer,
                failure: Some(failure),
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
) -> Result<(), MembershipPropagationFailure> {
    attest_peer_http_target(
        context.config,
        peer,
        Duration::from_secs(MEMBERSHIP_UPDATE_PROPAGATION_TIMEOUT_SECS),
    )
    .map_err(|error| {
        MembershipPropagationFailure::terminal(format!(
            "membership propagation preflight failed for '{}': {}",
            peer, error
        ))
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
                let message = format!(
                    "membership propagation to peer '{}' failed with HTTP status {}",
                    peer,
                    status.as_u16()
                );
                if should_retry_membership_propagation_status(status) {
                    return Err(MembershipPropagationFailure::retryable(message));
                }
                return Err(MembershipPropagationFailure::terminal(message));
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
                return Err(MembershipPropagationFailure::retryable(format!(
                    "membership propagation to peer '{}' failed after retries: {}",
                    peer, error
                )));
            }
        }
    }
    Err(MembershipPropagationFailure::terminal(format!(
        "membership propagation to peer '{}' did not complete",
        peer
    )))
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
            Err(failure) => {
                if !failure.retryable {
                    summary.acknowledged = summary.acknowledged.saturating_add(1);
                    tracing::warn!(
                        peer = original_operation.peer.as_str(),
                        error = failure.message.as_str(),
                        "Dropping pending membership propagation operation after terminal failure"
                    );
                    replay_outcomes.push(
                        PendingMembershipPropagationReplayOperationOutcome::Dropped {
                            original: original_operation,
                        },
                    );
                    continue;
                }
                summary.failed = summary.failed.saturating_add(1);
                operation.attempts = operation.attempts.saturating_add(1);
                operation.updated_at_unix_ms = now_unix_ms;
                operation.last_error = Some(failure.message);
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
            PendingMembershipPropagationReplayOperationOutcome::Acknowledged { original }
            | PendingMembershipPropagationReplayOperationOutcome::Dropped { original } => {
                if let Some(index) = operations.iter().position(|operation| {
                    peer_identity_eq(operation.peer.as_str(), original.peer.as_str())
                }) && operations[index] == original
                {
                    operations.remove(index);
                }
            }
            PendingMembershipPropagationReplayOperationOutcome::Failed { original, retry } => {
                if let Some(index) = operations.iter().position(|operation| {
                    peer_identity_eq(operation.peer.as_str(), original.peer.as_str())
                }) && operations[index] == original
                {
                    operations[index] = retry;
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

    let has_cluster_auth_token = state
        .config
        .cluster_auth_token()
        .is_some_and(|value| !value.trim().is_empty());
    if topology.is_distributed()
        && let Some(reason) = cluster_metadata_fan_in_auth_token_reject_reason(
            state.metadata_listing_strategy,
            has_cluster_auth_token,
        )
    {
        effective_ready = false;
        effective_gap = Some(reason.to_string());
    }

    RuntimeMetadataListingReadiness {
        cluster_authoritative: readiness.cluster_authoritative,
        ready: effective_ready,
        gap: effective_gap,
    }
}

#[cfg(test)]
mod tests;
