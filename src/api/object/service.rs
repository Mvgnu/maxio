use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::Response,
};
use chrono::DateTime;
use futures::TryStreamExt;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncReadExt};

use super::parsing::to_http_date;
use super::peer_transport::{
    attest_internal_peer_target, build_internal_peer_http_client, internal_peer_transport_scheme,
};
use crate::auth::signature_v4::{PresignRequest, generate_presigned_url};
use crate::cluster::authenticator::{
    FORWARDED_BY_HEADER, INTERNAL_FORWARDING_PROTOCOL_HEADERS, authenticate_forwarded_request,
};
use crate::cluster::security::INTERNAL_AUTH_TOKEN_HEADER;
use crate::error::S3Error;
use crate::membership::unix_ms_now;
use crate::server::AppState;
use crate::storage::placement::{
    ForwardedWriteEnvelope, ForwardedWriteOperation, ForwardedWriteRejectReason,
    ForwardedWriteResolution, ObjectWriteQuorumOutcome, PendingReplicationAcknowledgeOutcome,
    PendingReplicationEnqueueOutcome, PendingReplicationFailureWithBackoffOutcome,
    PendingReplicationFromQuorumInput, PendingReplicationReplayCandidate,
    PendingReplicationReplayLeaseOutcome, PendingReplicationRetryPolicy, PlacementViewState,
    ReplicationMutationOperation, acknowledge_pending_replication_target_persisted,
    enqueue_pending_replication_operation_persisted,
    lease_pending_replication_target_for_replay_persisted, object_forward_target_with_self,
    pending_replication_operation_from_quorum_outcome,
    pending_replication_replay_candidates_from_disk, pending_replication_replay_owner_alignment,
    primary_object_owner_with_self, record_pending_replication_failure_with_backoff_persisted,
    resolve_forwarded_write_envelope,
};
use crate::storage::{ChecksumAlgorithm, ObjectMeta, PutResult, StorageError};

const INTERNAL_FORWARD_EPOCH_HEADER: &str = "x-maxio-forwarded-write-epoch";
const INTERNAL_FORWARD_VIEW_ID_HEADER: &str = "x-maxio-forwarded-write-view-id";
const INTERNAL_FORWARD_HOP_COUNT_HEADER: &str = "x-maxio-forwarded-write-hop-count";
const INTERNAL_FORWARD_MAX_HOPS_HEADER: &str = "x-maxio-forwarded-write-max-hops";
const INTERNAL_FORWARD_IDEMPOTENCY_KEY_HEADER: &str = "x-maxio-forwarded-write-idempotency-key";
const INTERNAL_TRUSTED_FORWARD_EPOCH_HEADER: &str = "x-maxio-internal-forwarded-write-epoch";
const INTERNAL_TRUSTED_FORWARD_VIEW_ID_HEADER: &str = "x-maxio-internal-forwarded-write-view-id";
const INTERNAL_TRUSTED_FORWARD_HOP_COUNT_HEADER: &str =
    "x-maxio-internal-forwarded-write-hop-count";
const INTERNAL_TRUSTED_FORWARD_MAX_HOPS_HEADER: &str = "x-maxio-internal-forwarded-write-max-hops";
const INTERNAL_TRUSTED_FORWARD_IDEMPOTENCY_KEY_HEADER: &str =
    "x-maxio-internal-forwarded-write-idempotency-key";
const INTERNAL_TRUSTED_FORWARD_OPERATION_HEADER: &str =
    "x-maxio-internal-forwarded-write-operation";
const INTERNAL_TRUSTED_FORWARD_VERSION_ID_HEADER: &str =
    "x-maxio-internal-forwarded-write-version-id";
const INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_PUT: &str = "replicate-put-object";
const INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_DELETE: &str = "replicate-delete-object";
const INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_HEAD: &str = "replicate-head-object";
const FORWARD_MAX_HOPS_DEFAULT: u8 = 8;
const DISTRIBUTED_WRITE_REPLICA_TARGET: usize = 2;
const RUNTIME_STATE_DIR: &str = ".maxio-runtime";
const PENDING_REPLICATION_QUEUE_FILE: &str = "pending-replication-queue.json";
const INITIAL_REPLICA_FAILURE_REASON: &str = "initial_replica_fanout_not_acked";
const PENDING_REPLICATION_REPLAY_FAILURE_REASON_RETRY: &str = "replay_attempt_failed";
const PENDING_REPLICATION_REPLAY_FAILURE_REASON_SOURCE_UNAVAILABLE: &str =
    "replay_source_unavailable";
const S3_PATH_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b'/');
const S3_QUERY_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

pub(crate) async fn ensure_bucket_exists(state: &AppState, bucket: &str) -> Result<(), S3Error> {
    match state.storage.head_bucket(bucket).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(S3Error::no_such_bucket(bucket)),
        Err(err) => Err(S3Error::internal(err)),
    }
}

/// Extract checksum algorithm and optional expected value from request headers.
pub(crate) fn extract_checksum(headers: &HeaderMap) -> Option<(ChecksumAlgorithm, Option<String>)> {
    let pairs = [
        ("x-amz-checksum-crc32", ChecksumAlgorithm::CRC32),
        ("x-amz-checksum-crc32c", ChecksumAlgorithm::CRC32C),
        ("x-amz-checksum-sha1", ChecksumAlgorithm::SHA1),
        ("x-amz-checksum-sha256", ChecksumAlgorithm::SHA256),
    ];

    // Check for a value header first (implies the algorithm).
    for (header, algo) in &pairs {
        if let Some(val) = headers.get(*header).and_then(|v| v.to_str().ok()) {
            return Some((*algo, Some(val.to_string())));
        }
    }

    // Fall back to algorithm-only header (compute but don't validate).
    headers
        .get("x-amz-checksum-algorithm")
        .and_then(|v| v.to_str().ok())
        .and_then(ChecksumAlgorithm::from_header_str)
        .map(|algo| (algo, None))
}

pub(crate) fn add_checksum_header(
    builder: http::response::Builder,
    meta: &ObjectMeta,
) -> http::response::Builder {
    if let (Some(algo), Some(val)) = (&meta.checksum_algorithm, &meta.checksum_value) {
        builder.header(algo.header_name(), val.as_str())
    } else {
        builder
    }
}

pub(crate) fn object_response(
    meta: &ObjectMeta,
    status: StatusCode,
    body: Body,
    content_length: u64,
    content_range: Option<(u64, u64, u64)>,
) -> Result<Response<Body>, S3Error> {
    let mut builder = Response::builder()
        .status(status)
        .header("Content-Type", &meta.content_type)
        .header("Content-Length", content_length.to_string())
        .header("Accept-Ranges", "bytes")
        .header("ETag", &meta.etag)
        .header("Last-Modified", to_http_date(&meta.last_modified));

    if let Some((start, end, total)) = content_range {
        builder = builder.header(
            "Content-Range",
            format!("bytes {}-{}/{}", start, end, total),
        );
    }

    if let Some(vid) = &meta.version_id {
        builder = builder.header("x-amz-version-id", vid.as_str());
    }

    builder = add_checksum_header(builder, meta);
    builder.body(body).map_err(S3Error::internal)
}

pub(crate) enum DeleteObjectsOutcome {
    Deleted {
        key: String,
        version_id: Option<String>,
        is_delete_marker: bool,
    },
    Error {
        key: String,
        code: &'static str,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ObjectWriteRoutingHint {
    pub distributed: bool,
    pub primary_owner: Option<String>,
    pub forward_target: Option<String>,
    pub is_local_primary_owner: bool,
}

pub(crate) fn object_write_routing_hint(
    key: &str,
    node_id: &str,
    peers: &[String],
) -> ObjectWriteRoutingHint {
    let local_node = node_id.trim();
    let primary_owner = primary_object_owner_with_self(key, local_node, peers);
    let forward_target = object_forward_target_with_self(key, local_node, peers);

    ObjectWriteRoutingHint {
        distributed: !peers.is_empty(),
        primary_owner: primary_owner.clone(),
        forward_target,
        is_local_primary_owner: primary_owner.as_deref() == Some(local_node),
    }
}

fn non_owner_write_message(routing_hint: &ObjectWriteRoutingHint) -> String {
    let primary = routing_hint
        .primary_owner
        .as_deref()
        .unwrap_or("unknown-primary-owner");
    let target = routing_hint.forward_target.as_deref().unwrap_or(primary);
    format!("Write request reached non-owner node. Retry against primary owner: {target}")
}

pub(crate) fn ensure_local_write_owner(
    routing_hint: &ObjectWriteRoutingHint,
) -> Result<(), S3Error> {
    if !routing_hint.distributed || routing_hint.is_local_primary_owner {
        return Ok(());
    }
    Err(S3Error::service_unavailable(&non_owner_write_message(
        routing_hint,
    )))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn write_forward_target(
    bucket: &str,
    key: &str,
    operation: ForwardedWriteOperation,
    routing_hint: &ObjectWriteRoutingHint,
    headers: &HeaderMap,
    node_id: &str,
    placement: &PlacementViewState,
    cluster_auth_token: Option<&str>,
) -> Result<Option<ForwardWriteTarget>, S3Error> {
    if !routing_hint.distributed {
        return Ok(None);
    }

    let envelope = forwarded_write_envelope_from_headers(
        headers,
        operation,
        bucket,
        key,
        node_id,
        placement,
        cluster_auth_token,
    );
    let replica_count = write_replica_count_for_membership_count(placement.members.len());
    match resolve_forwarded_write_envelope(&envelope, node_id, placement, replica_count) {
        ForwardedWriteResolution::ExecuteLocal { .. } => Ok(None),
        ForwardedWriteResolution::ForwardToPrimary { target, envelope } => {
            Ok(Some(ForwardWriteTarget { target, envelope }))
        }
        ForwardedWriteResolution::Reject { reason } => match reason {
            ForwardedWriteRejectReason::MissingPrimaryOwner
            | ForwardedWriteRejectReason::MissingForwardTarget => Err(
                S3Error::service_unavailable(&non_owner_write_message(routing_hint)),
            ),
            ForwardedWriteRejectReason::StaleEpoch {
                local_epoch,
                request_epoch,
            } => Err(S3Error::service_unavailable(&format!(
                "Write forwarding rejected due to stale placement epoch (local={local_epoch}, request={request_epoch})"
            ))),
            ForwardedWriteRejectReason::FutureEpoch {
                local_epoch,
                request_epoch,
            } => Err(S3Error::service_unavailable(&format!(
                "Write forwarding rejected due to future placement epoch (local={local_epoch}, request={request_epoch})"
            ))),
            ForwardedWriteRejectReason::ViewIdMismatch {
                local_view_id,
                request_view_id,
            } => Err(S3Error::service_unavailable(&format!(
                "Write forwarding rejected due to placement view mismatch (local={local_view_id}, request={request_view_id})"
            ))),
            ForwardedWriteRejectReason::ForwardLoop { node } => Err(S3Error::service_unavailable(
                &format!("Write forwarding loop detected while routing request (node={node})"),
            )),
            ForwardedWriteRejectReason::HopLimitExceeded {
                hop_count,
                max_hops,
            } => Err(S3Error::service_unavailable(&format!(
                "Write forwarding hop limit exceeded ({hop_count}/{max_hops})"
            ))),
        },
    }
}

pub(crate) fn write_replica_count_for_membership_count(membership_count: usize) -> usize {
    if membership_count <= 1 {
        1
    } else {
        membership_count.min(DISTRIBUTED_WRITE_REPLICA_TARGET)
    }
}

pub(crate) fn pending_replication_queue_path(data_dir: &str) -> PathBuf {
    PathBuf::from(data_dir)
        .join(RUNTIME_STATE_DIR)
        .join(PENDING_REPLICATION_QUEUE_FILE)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn persist_pending_replication_from_quorum_outcome(
    state: &AppState,
    operation: ReplicationMutationOperation,
    idempotency_key: &str,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    placement: &PlacementViewState,
    outcome: &ObjectWriteQuorumOutcome,
) {
    let created_at_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default();
    let Some(pending_operation) =
        pending_replication_operation_from_quorum_outcome(PendingReplicationFromQuorumInput {
            operation,
            idempotency_key,
            bucket,
            key,
            version_id,
            coordinator_node: state.node_id.as_ref(),
            placement,
            outcome,
            created_at_unix_ms,
        })
    else {
        return;
    };

    let queue_path = pending_replication_queue_path(state.config.data_dir.as_str());
    let pending_idempotency_key = pending_operation.idempotency_key.clone();
    match enqueue_pending_replication_operation_persisted(queue_path.as_path(), pending_operation) {
        Ok(PendingReplicationEnqueueOutcome::Inserted) => {
            tracing::warn!(
                operation = %operation.as_str(),
                bucket = %bucket,
                key = %key,
                pending_targets = outcome.pending_nodes.len(),
                rejected_targets = outcome.rejected_nodes.len(),
                "Persisted pending replication operation after partial replica acknowledgements"
            );
        }
        Ok(PendingReplicationEnqueueOutcome::AlreadyTracked) => {
            tracing::debug!(
                operation = %operation.as_str(),
                bucket = %bucket,
                key = %key,
                idempotency_key = %pending_idempotency_key,
                "Pending replication operation already tracked"
            );
        }
        Err(error) => {
            tracing::warn!(
                operation = %operation.as_str(),
                bucket = %bucket,
                key = %key,
                error = ?error,
                "Failed to persist pending replication operation"
            );
            return;
        }
    }

    for target in &outcome.rejected_nodes {
        match record_pending_replication_failure_with_backoff_persisted(
            queue_path.as_path(),
            pending_idempotency_key.as_str(),
            target,
            Some(INITIAL_REPLICA_FAILURE_REASON),
            created_at_unix_ms,
            PendingReplicationRetryPolicy::default(),
        ) {
            Ok(PendingReplicationFailureWithBackoffOutcome::Updated {
                attempts,
                next_retry_at_unix_ms,
            }) => {
                tracing::debug!(
                    operation = %operation.as_str(),
                    bucket = %bucket,
                    key = %key,
                    target_node = %target,
                    attempts,
                    next_retry_at_unix_ms,
                    "Recorded initial pending replication target failure"
                );
            }
            Ok(PendingReplicationFailureWithBackoffOutcome::NotFound)
            | Ok(PendingReplicationFailureWithBackoffOutcome::TargetNotTracked) => {}
            Err(error) => {
                tracing::warn!(
                    operation = %operation.as_str(),
                    bucket = %bucket,
                    key = %key,
                    target_node = %target,
                    error = ?error,
                    "Failed to record pending replication target failure"
                );
            }
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PendingReplicationReplaySummary {
    pub scanned: usize,
    pub leased: usize,
    pub acknowledged: usize,
    pub failed: usize,
    pub skipped: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingReplicationReplayOutcome {
    Applied,
    Dropped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingReplicationReplayError {
    message: String,
    retryable: bool,
}

impl PendingReplicationReplayError {
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

pub(crate) async fn replay_pending_replication_backlog_once(
    state: &AppState,
    max_candidates: usize,
    lease_ms: u64,
) -> std::io::Result<PendingReplicationReplaySummary> {
    if max_candidates == 0 {
        return Ok(PendingReplicationReplaySummary::default());
    }

    let queue_path = pending_replication_queue_path(state.config.data_dir.as_str());
    let now_unix_ms = unix_ms_now();
    let candidates = pending_replication_replay_candidates_from_disk(
        queue_path.as_path(),
        now_unix_ms,
        max_candidates,
    )?;
    let mut summary = PendingReplicationReplaySummary {
        scanned: candidates.len(),
        ..PendingReplicationReplaySummary::default()
    };

    for candidate in candidates {
        let lease_outcome = lease_pending_replication_target_for_replay_persisted(
            queue_path.as_path(),
            candidate.idempotency_key.as_str(),
            candidate.target_node.as_str(),
            unix_ms_now(),
            lease_ms,
        )?;
        if !matches!(
            lease_outcome,
            PendingReplicationReplayLeaseOutcome::Updated { .. }
        ) {
            summary.skipped += 1;
            continue;
        }
        summary.leased += 1;

        match replay_pending_replication_candidate(state, &candidate).await {
            Ok(replay_outcome) => {
                let ack_outcome = acknowledge_pending_replication_target_persisted(
                    queue_path.as_path(),
                    candidate.idempotency_key.as_str(),
                    candidate.target_node.as_str(),
                )?;
                match ack_outcome {
                    PendingReplicationAcknowledgeOutcome::Updated { .. }
                    | PendingReplicationAcknowledgeOutcome::AlreadyAcked => {
                        summary.acknowledged += 1;
                    }
                    PendingReplicationAcknowledgeOutcome::NotFound
                    | PendingReplicationAcknowledgeOutcome::TargetNotTracked => {
                        summary.skipped += 1;
                    }
                }
                if matches!(replay_outcome, PendingReplicationReplayOutcome::Dropped) {
                    summary.skipped += 1;
                }
            }
            Err(error) => {
                if error.retryable {
                    summary.failed += 1;
                    let record_outcome = record_pending_replication_failure_with_backoff_persisted(
                        queue_path.as_path(),
                        candidate.idempotency_key.as_str(),
                        candidate.target_node.as_str(),
                        Some(error.message.as_str()),
                        unix_ms_now(),
                        PendingReplicationRetryPolicy::default(),
                    )?;
                    tracing::warn!(
                        operation = %candidate.operation.as_str(),
                        bucket = %candidate.bucket,
                        key = %candidate.key,
                        target_node = %candidate.target_node,
                        error = %error.message,
                        failure_outcome = ?record_outcome,
                        "Pending replication replay attempt failed"
                    );
                    continue;
                }

                let ack_outcome = acknowledge_pending_replication_target_persisted(
                    queue_path.as_path(),
                    candidate.idempotency_key.as_str(),
                    candidate.target_node.as_str(),
                )?;
                match ack_outcome {
                    PendingReplicationAcknowledgeOutcome::Updated { .. }
                    | PendingReplicationAcknowledgeOutcome::AlreadyAcked => {
                        summary.acknowledged += 1;
                    }
                    PendingReplicationAcknowledgeOutcome::NotFound
                    | PendingReplicationAcknowledgeOutcome::TargetNotTracked => {}
                }
                summary.skipped += 1;
                tracing::warn!(
                    operation = %candidate.operation.as_str(),
                    bucket = %candidate.bucket,
                    key = %candidate.key,
                    target_node = %candidate.target_node,
                    error = %error.message,
                    ack_outcome = ?ack_outcome,
                    "Dropping pending replication replay target after terminal failure"
                );
            }
        }
    }

    Ok(summary)
}

async fn replay_pending_replication_candidate(
    state: &AppState,
    candidate: &PendingReplicationReplayCandidate,
) -> Result<PendingReplicationReplayOutcome, PendingReplicationReplayError> {
    if !pending_replication_target_is_current_owner(state, candidate) {
        tracing::debug!(
            operation = %candidate.operation.as_str(),
            bucket = %candidate.bucket,
            key = %candidate.key,
            target_node = %candidate.target_node,
            "Skipping pending replication replay for target outside current owner set"
        );
        return Ok(PendingReplicationReplayOutcome::Dropped);
    }

    match candidate.operation {
        ReplicationMutationOperation::PutObject
        | ReplicationMutationOperation::CopyObject
        | ReplicationMutationOperation::CompleteMultipartUpload => {
            replay_pending_replication_put(state, candidate).await
        }
        ReplicationMutationOperation::DeleteObject
        | ReplicationMutationOperation::DeleteObjectVersion => {
            replay_pending_replication_delete(state, candidate).await
        }
    }
}

fn pending_replication_target_is_current_owner(
    state: &AppState,
    candidate: &PendingReplicationReplayCandidate,
) -> bool {
    let peers = state.active_cluster_peers();
    let membership_count = peers.len().saturating_add(1);
    let replica_count = write_replica_count_for_membership_count(membership_count);
    let alignment = pending_replication_replay_owner_alignment(
        candidate.key.as_str(),
        state.node_id.as_ref(),
        peers.as_slice(),
        candidate.target_node.as_str(),
        replica_count,
    );
    if !alignment.local_is_owner {
        tracing::debug!(
            operation = %candidate.operation.as_str(),
            bucket = %candidate.bucket,
            key = %candidate.key,
            local_node = %state.node_id,
            target_node = %candidate.target_node,
            current_owners = ?alignment.owners,
            "Skipping pending replication replay because local node is outside current owner set"
        );
        return false;
    }

    alignment.target_is_owner
}

async fn replay_pending_replication_put(
    state: &AppState,
    candidate: &PendingReplicationReplayCandidate,
) -> Result<PendingReplicationReplayOutcome, PendingReplicationReplayError> {
    let read_result = if let Some(version_id) = candidate.version_id.as_deref() {
        state
            .storage
            .get_object_version(
                candidate.bucket.as_str(),
                candidate.key.as_str(),
                version_id,
            )
            .await
    } else {
        state
            .storage
            .get_object(candidate.bucket.as_str(), candidate.key.as_str())
            .await
    };
    let (mut reader, meta) = match read_result {
        Ok(value) => value,
        Err(StorageError::NotFound(_)) => {
            tracing::debug!(
                operation = %candidate.operation.as_str(),
                bucket = %candidate.bucket,
                key = %candidate.key,
                version_id = ?candidate.version_id,
                target_node = %candidate.target_node,
                reason = PENDING_REPLICATION_REPLAY_FAILURE_REASON_SOURCE_UNAVAILABLE,
                "Skipping pending replication replay because source object is no longer available"
            );
            return Ok(PendingReplicationReplayOutcome::Dropped);
        }
        Err(error) => {
            return Err(PendingReplicationReplayError::retryable(format!(
                "{}: failed to read source object for replay: {error}",
                PENDING_REPLICATION_REPLAY_FAILURE_REASON_SOURCE_UNAVAILABLE
            )));
        }
    };

    let mut body = Vec::new();
    reader.read_to_end(&mut body).await.map_err(|error| {
        PendingReplicationReplayError::retryable(format!(
            "failed to read source object payload for replay: {error}"
        ))
    })?;

    let path_and_query = presigned_replica_path_and_query(
        state,
        "PUT",
        candidate.target_node.as_str(),
        candidate.bucket.as_str(),
        candidate.key.as_str(),
        &[],
    )
    .ok_or_else(|| {
        PendingReplicationReplayError::terminal(
            "failed to build presigned replay path for replica PUT".to_string(),
        )
    })?;

    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(meta.content_type.as_str()) {
        headers.insert(header::CONTENT_TYPE, value);
    }
    if let (Some(algorithm), Some(value)) = (meta.checksum_algorithm, meta.checksum_value.as_ref())
    {
        headers.insert(
            header::HeaderName::from_static("x-amz-checksum-algorithm"),
            HeaderValue::from_static(checksum_algorithm_header_value(algorithm)),
        );
        if let Ok(header_value) = HeaderValue::from_str(value) {
            headers.insert(
                header::HeaderName::from_static(algorithm.header_name()),
                header_value,
            );
        }
    }

    let envelope = replay_forwarded_write_envelope(
        state,
        candidate,
        ForwardedWriteOperation::ReplicatePutObject,
    );
    let response = forward_replica_put_to_target_for_replay(
        state,
        candidate.target_node.as_str(),
        path_and_query.as_str(),
        &headers,
        body,
        candidate.version_id.as_deref(),
        &envelope,
    )
    .await
    .map_err(|error| {
        PendingReplicationReplayError::retryable(format!(
            "{PENDING_REPLICATION_REPLAY_FAILURE_REASON_RETRY}: {error:?}"
        ))
    })?;
    if response.status().is_success() {
        return Ok(PendingReplicationReplayOutcome::Applied);
    }

    let status = response.status();
    let message = format!(
        "{PENDING_REPLICATION_REPLAY_FAILURE_REASON_RETRY}: replica PUT replay returned status {}",
        status.as_u16()
    );
    if pending_replication_replay_status_is_retryable(status) {
        Err(PendingReplicationReplayError::retryable(message))
    } else {
        Err(PendingReplicationReplayError::terminal(message))
    }
}

async fn replay_pending_replication_delete(
    state: &AppState,
    candidate: &PendingReplicationReplayCandidate,
) -> Result<PendingReplicationReplayOutcome, PendingReplicationReplayError> {
    if should_drop_non_version_delete_replay(state, candidate).await {
        tracing::debug!(
            operation = %candidate.operation.as_str(),
            bucket = %candidate.bucket,
            key = %candidate.key,
            target_node = %candidate.target_node,
            reason = "non_version_delete_replay_stale_or_unsafe",
            "Dropping pending replication replay for non-versioned delete"
        );
        return Ok(PendingReplicationReplayOutcome::Dropped);
    }

    let mut extra_query = Vec::<(&str, &str)>::new();
    if let Some(version_id) = candidate.version_id.as_deref() {
        extra_query.push(("versionId", version_id));
    }
    let path_and_query = presigned_replica_path_and_query(
        state,
        "DELETE",
        candidate.target_node.as_str(),
        candidate.bucket.as_str(),
        candidate.key.as_str(),
        extra_query.as_slice(),
    )
    .ok_or_else(|| {
        PendingReplicationReplayError::terminal(
            "failed to build presigned replay path for replica DELETE".to_string(),
        )
    })?;
    let headers = HeaderMap::new();
    let envelope = replay_forwarded_write_envelope(
        state,
        candidate,
        ForwardedWriteOperation::ReplicateDeleteObject,
    );
    let response = forward_replica_delete_to_target_for_replay(
        state,
        candidate.target_node.as_str(),
        path_and_query.as_str(),
        &headers,
        &envelope,
    )
    .await
    .map_err(|error| {
        PendingReplicationReplayError::retryable(format!(
            "{PENDING_REPLICATION_REPLAY_FAILURE_REASON_RETRY}: {error:?}"
        ))
    })?;
    if response.status().is_success() {
        return Ok(PendingReplicationReplayOutcome::Applied);
    }

    let status = response.status();
    let message = format!(
        "{PENDING_REPLICATION_REPLAY_FAILURE_REASON_RETRY}: replica DELETE replay returned status {}",
        status.as_u16()
    );
    if pending_replication_replay_status_is_retryable(status) {
        Err(PendingReplicationReplayError::retryable(message))
    } else {
        Err(PendingReplicationReplayError::terminal(message))
    }
}

fn pending_replication_replay_status_is_retryable(status: StatusCode) -> bool {
    status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

async fn should_drop_non_version_delete_replay(
    state: &AppState,
    candidate: &PendingReplicationReplayCandidate,
) -> bool {
    if !matches!(
        candidate.operation,
        ReplicationMutationOperation::DeleteObject
    ) || candidate.version_id.is_some()
    {
        return false;
    }

    match state
        .storage
        .head_object(candidate.bucket.as_str(), candidate.key.as_str())
        .await
    {
        Ok(meta) => {
            // Conservative safety posture: if we cannot prove that the pending delete is newer
            // than the local current object, drop replay to avoid deleting data written later.
            let Some(last_modified_unix_ms) =
                object_last_modified_unix_ms(meta.last_modified.as_str())
            else {
                return true;
            };
            // Equal timestamps are also unsafe: storage timestamp precision may collide for a
            // delete operation and a subsequent recreate in the same millisecond.
            last_modified_unix_ms >= candidate.created_at_unix_ms
        }
        Err(StorageError::NotFound(_)) => false,
        Err(_) => false,
    }
}

fn object_last_modified_unix_ms(last_modified: &str) -> Option<u64> {
    DateTime::parse_from_rfc3339(last_modified)
        .map(|value| value.timestamp_millis() as u64)
        .or_else(|_| {
            DateTime::parse_from_rfc2822(last_modified).map(|value| value.timestamp_millis() as u64)
        })
        .ok()
}

fn replay_forwarded_write_envelope(
    state: &AppState,
    candidate: &PendingReplicationReplayCandidate,
    operation: ForwardedWriteOperation,
) -> ForwardedWriteEnvelope {
    let placement = PlacementViewState::from_membership(
        state.placement_epoch(),
        state.node_id.as_ref(),
        state.active_cluster_peers().as_slice(),
    );
    let mut envelope = ForwardedWriteEnvelope::new(
        operation,
        candidate.bucket.as_str(),
        candidate.key.as_str(),
        state.node_id.as_ref(),
        state.node_id.as_ref(),
        candidate.idempotency_key.as_str(),
        &placement,
    );
    envelope.visited_nodes = vec![state.node_id.to_string()];
    envelope.hop_count = 1;
    envelope
}

fn presigned_replica_path_and_query(
    state: &AppState,
    method: &'static str,
    target_node: &str,
    bucket: &str,
    key: &str,
    extra_query_params: &[(&str, &str)],
) -> Option<String> {
    let scheme = internal_peer_transport_scheme(state).ok()?;
    let url = generate_presigned_url(PresignRequest {
        method,
        scheme,
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

fn checksum_algorithm_header_value(algorithm: ChecksumAlgorithm) -> &'static str {
    match algorithm {
        ChecksumAlgorithm::CRC32 => "CRC32",
        ChecksumAlgorithm::CRC32C => "CRC32C",
        ChecksumAlgorithm::SHA1 => "SHA1",
        ChecksumAlgorithm::SHA256 => "SHA256",
    }
}

pub(crate) fn object_path_and_query(
    bucket: &str,
    key: &str,
    params: &HashMap<String, String>,
) -> String {
    let bucket = utf8_percent_encode(bucket, S3_PATH_ENCODE_SET);
    let key = utf8_percent_encode(key, S3_PATH_ENCODE_SET);
    let mut path = format!("/{bucket}/{key}");
    let query = canonical_query_string(params);
    if !query.is_empty() {
        path.push('?');
        path.push_str(&query);
    }
    path
}

pub(crate) fn bucket_path_and_query(bucket: &str, params: &HashMap<String, String>) -> String {
    let bucket = utf8_percent_encode(bucket, S3_PATH_ENCODE_SET);
    let mut path = format!("/{bucket}");
    let query = canonical_query_string(params);
    if !query.is_empty() {
        path.push('?');
        path.push_str(&query);
    }
    path
}

fn canonical_query_string(params: &HashMap<String, String>) -> String {
    if params.is_empty() {
        return String::new();
    }

    let mut pairs: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| {
            (
                utf8_percent_encode(k, S3_QUERY_ENCODE_SET).to_string(),
                utf8_percent_encode(v, S3_QUERY_ENCODE_SET).to_string(),
            )
        })
        .collect();
    pairs.sort();

    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn forward_write_to_target(
    state: &AppState,
    method: Method,
    target: &str,
    path_and_query: &str,
    headers: &HeaderMap,
    body: Vec<u8>,
    treat_auth_reject_as_transport_error: bool,
    envelope: &ForwardedWriteEnvelope,
) -> Result<Response<Body>, S3Error> {
    let transport =
        build_internal_peer_http_client(state, None, std::time::Duration::from_secs(10))?;
    attest_internal_peer_target(state, target, std::time::Duration::from_secs(10))?;
    let url = format!("{}://{target}{path_and_query}", transport.scheme);
    let client = transport.client;
    let mut request_builder = client.request(method, &url);

    for (name, value) in headers {
        if should_skip_forwarded_request_header(name) {
            continue;
        }
        request_builder = request_builder.header(name, value);
    }
    request_builder = request_builder.header(FORWARDED_BY_HEADER, envelope.visited_nodes.join(","));
    if !headers.contains_key(INTERNAL_FORWARD_EPOCH_HEADER) {
        request_builder = request_builder.header(
            INTERNAL_FORWARD_EPOCH_HEADER,
            envelope.placement_epoch.to_string(),
        );
    }
    if !headers.contains_key(INTERNAL_FORWARD_VIEW_ID_HEADER) {
        request_builder =
            request_builder.header(INTERNAL_FORWARD_VIEW_ID_HEADER, &envelope.placement_view_id);
    }
    if !headers.contains_key(INTERNAL_FORWARD_HOP_COUNT_HEADER) {
        request_builder = request_builder.header(
            INTERNAL_FORWARD_HOP_COUNT_HEADER,
            envelope.hop_count.to_string(),
        );
    }
    if !headers.contains_key(INTERNAL_FORWARD_MAX_HOPS_HEADER) {
        request_builder = request_builder.header(
            INTERNAL_FORWARD_MAX_HOPS_HEADER,
            envelope.max_hops.to_string(),
        );
    }
    if !headers.contains_key(INTERNAL_FORWARD_IDEMPOTENCY_KEY_HEADER) {
        request_builder = request_builder.header(
            INTERNAL_FORWARD_IDEMPOTENCY_KEY_HEADER,
            &envelope.idempotency_key,
        );
    }
    request_builder = request_builder.header(
        INTERNAL_TRUSTED_FORWARD_EPOCH_HEADER,
        envelope.placement_epoch.to_string(),
    );
    request_builder = request_builder.header(
        INTERNAL_TRUSTED_FORWARD_VIEW_ID_HEADER,
        &envelope.placement_view_id,
    );
    request_builder = request_builder.header(
        INTERNAL_TRUSTED_FORWARD_HOP_COUNT_HEADER,
        envelope.hop_count.to_string(),
    );
    request_builder = request_builder.header(
        INTERNAL_TRUSTED_FORWARD_MAX_HOPS_HEADER,
        envelope.max_hops.to_string(),
    );
    request_builder = request_builder.header(
        INTERNAL_TRUSTED_FORWARD_IDEMPOTENCY_KEY_HEADER,
        &envelope.idempotency_key,
    );
    if let Some(token) = state
        .config
        .cluster_auth_token()
        .filter(|token| !token.trim().is_empty())
    {
        request_builder = request_builder.header(INTERNAL_AUTH_TOKEN_HEADER, token);
    }

    if !body.is_empty() {
        request_builder = request_builder.body(body);
    }

    let forwarded = request_builder.send().await.map_err(|err| {
        S3Error::service_unavailable(&format!(
            "Write forwarding to primary owner failed ({target}): {err}"
        ))
    })?;
    let status = forwarded.status();
    if treat_auth_reject_as_transport_error
        && is_internal_forwarding_transport_reject_status(status)
    {
        return Err(S3Error::service_unavailable(&format!(
            "Write forwarding to primary owner failed ({target}): upstream peer rejected internal forwarding request with status {}",
            status.as_u16()
        )));
    }
    let forwarded_headers = forwarded.headers().clone();
    let forwarded_body = forwarded.bytes().await.map_err(S3Error::internal)?;

    let mut response = Response::new(Body::from(forwarded_body.to_vec()));
    *response.status_mut() = status;
    for (name, value) in &forwarded_headers {
        if should_skip_forwarded_response_header(name) {
            continue;
        }
        response.headers_mut().append(name.clone(), value.clone());
    }
    Ok(response)
}

fn is_internal_forwarding_transport_reject_status(status: StatusCode) -> bool {
    matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
}

pub(crate) async fn forward_replica_put_to_target(
    state: &AppState,
    target: &str,
    path_and_query: &str,
    headers: &HeaderMap,
    body: Vec<u8>,
    replica_version_id: Option<&str>,
    envelope: &ForwardedWriteEnvelope,
) -> Result<Response<Body>, S3Error> {
    let mut replica_headers = headers.clone();
    replica_headers.insert(
        header::HeaderName::from_static(INTERNAL_TRUSTED_FORWARD_OPERATION_HEADER),
        HeaderValue::from_static(INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_PUT),
    );
    if let Some(version_id) = replica_version_id
        && let Ok(value) = HeaderValue::from_str(version_id)
    {
        replica_headers.insert(
            header::HeaderName::from_static(INTERNAL_TRUSTED_FORWARD_VERSION_ID_HEADER),
            value,
        );
    }
    forward_write_to_target(
        state,
        Method::PUT,
        target,
        path_and_query,
        &replica_headers,
        body,
        true,
        envelope,
    )
    .await
}

pub(crate) async fn forward_replica_delete_to_target(
    state: &AppState,
    target: &str,
    path_and_query: &str,
    headers: &HeaderMap,
    envelope: &ForwardedWriteEnvelope,
) -> Result<Response<Body>, S3Error> {
    let mut replica_headers = headers.clone();
    replica_headers.insert(
        header::HeaderName::from_static(INTERNAL_TRUSTED_FORWARD_OPERATION_HEADER),
        HeaderValue::from_static(INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_DELETE),
    );
    forward_write_to_target(
        state,
        Method::DELETE,
        target,
        path_and_query,
        &replica_headers,
        Vec::new(),
        true,
        envelope,
    )
    .await
}

pub(crate) async fn forward_replica_head_to_target(
    state: &AppState,
    target: &str,
    path_and_query: &str,
    headers: &HeaderMap,
    envelope: &ForwardedWriteEnvelope,
) -> Result<Response<Body>, S3Error> {
    let mut replica_headers = headers.clone();
    replica_headers.insert(
        header::HeaderName::from_static(INTERNAL_TRUSTED_FORWARD_OPERATION_HEADER),
        HeaderValue::from_static(INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_HEAD),
    );
    forward_write_to_target(
        state,
        Method::HEAD,
        target,
        path_and_query,
        &replica_headers,
        Vec::new(),
        true,
        envelope,
    )
    .await
}

async fn forward_replica_put_to_target_for_replay(
    state: &AppState,
    target: &str,
    path_and_query: &str,
    headers: &HeaderMap,
    body: Vec<u8>,
    replica_version_id: Option<&str>,
    envelope: &ForwardedWriteEnvelope,
) -> Result<Response<Body>, S3Error> {
    let mut replica_headers = headers.clone();
    replica_headers.insert(
        header::HeaderName::from_static(INTERNAL_TRUSTED_FORWARD_OPERATION_HEADER),
        HeaderValue::from_static(INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_PUT),
    );
    if let Some(version_id) = replica_version_id
        && let Ok(value) = HeaderValue::from_str(version_id)
    {
        replica_headers.insert(
            header::HeaderName::from_static(INTERNAL_TRUSTED_FORWARD_VERSION_ID_HEADER),
            value,
        );
    }
    forward_write_to_target(
        state,
        Method::PUT,
        target,
        path_and_query,
        &replica_headers,
        body,
        false,
        envelope,
    )
    .await
}

async fn forward_replica_delete_to_target_for_replay(
    state: &AppState,
    target: &str,
    path_and_query: &str,
    headers: &HeaderMap,
    envelope: &ForwardedWriteEnvelope,
) -> Result<Response<Body>, S3Error> {
    let mut replica_headers = headers.clone();
    replica_headers.insert(
        header::HeaderName::from_static(INTERNAL_TRUSTED_FORWARD_OPERATION_HEADER),
        HeaderValue::from_static(INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_DELETE),
    );
    forward_write_to_target(
        state,
        Method::DELETE,
        target,
        path_and_query,
        &replica_headers,
        Vec::new(),
        false,
        envelope,
    )
    .await
}

pub(crate) fn is_internal_replica_put_request(
    headers: &HeaderMap,
    cluster_auth_token: Option<&str>,
    local_node_id: &str,
    cluster_peers: &[String],
) -> bool {
    is_internal_replica_operation_request(
        headers,
        INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_PUT,
        cluster_auth_token,
        local_node_id,
        cluster_peers,
    )
}

pub(crate) fn is_internal_replica_delete_request(
    headers: &HeaderMap,
    cluster_auth_token: Option<&str>,
    local_node_id: &str,
    cluster_peers: &[String],
) -> bool {
    is_internal_replica_operation_request(
        headers,
        INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_DELETE,
        cluster_auth_token,
        local_node_id,
        cluster_peers,
    )
}

pub(crate) fn internal_replica_version_id(
    headers: &HeaderMap,
    cluster_auth_token: Option<&str>,
    local_node_id: &str,
    cluster_peers: &[String],
) -> Option<String> {
    if !is_internal_replica_put_request(headers, cluster_auth_token, local_node_id, cluster_peers) {
        return None;
    }
    parse_last_header_string(headers, INTERNAL_TRUSTED_FORWARD_VERSION_ID_HEADER)
}

fn is_internal_replica_operation_request(
    headers: &HeaderMap,
    operation: &str,
    cluster_auth_token: Option<&str>,
    local_node_id: &str,
    cluster_peers: &[String],
) -> bool {
    if !internal_forward_request_is_trusted(
        headers,
        cluster_auth_token,
        local_node_id,
        cluster_peers,
    ) {
        return false;
    }
    parse_last_header_string(headers, INTERNAL_TRUSTED_FORWARD_OPERATION_HEADER)
        .map(|value| value.eq_ignore_ascii_case(operation))
        .unwrap_or(false)
}

fn should_skip_forwarded_request_header(name: &header::HeaderName) -> bool {
    name == header::CONNECTION
        || name == header::TRANSFER_ENCODING
        || name == header::CONTENT_LENGTH
        || name.as_str().eq_ignore_ascii_case(FORWARDED_BY_HEADER)
        || name
            .as_str()
            .eq_ignore_ascii_case(INTERNAL_AUTH_TOKEN_HEADER)
}

fn should_skip_forwarded_response_header(name: &header::HeaderName) -> bool {
    name == header::TRANSFER_ENCODING
        || name == header::CONNECTION
        || is_internal_forwarding_protocol_header(name)
}

fn is_internal_forwarding_protocol_header(name: &header::HeaderName) -> bool {
    INTERNAL_FORWARDING_PROTOCOL_HEADERS
        .iter()
        .any(|header_name| name.as_str().eq_ignore_ascii_case(header_name))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ForwardWriteTarget {
    pub target: String,
    pub envelope: ForwardedWriteEnvelope,
}

fn forwarded_write_envelope_from_headers(
    headers: &HeaderMap,
    operation: ForwardedWriteOperation,
    bucket: &str,
    key: &str,
    node_id: &str,
    placement: &PlacementViewState,
    cluster_auth_token: Option<&str>,
) -> ForwardedWriteEnvelope {
    let is_forwarded_request = internal_forward_request_is_trusted(
        headers,
        cluster_auth_token,
        node_id,
        placement.members.as_slice(),
    );
    let mut envelope = ForwardedWriteEnvelope::new(
        operation,
        bucket,
        key,
        node_id,
        node_id,
        &forward_idempotency_key(headers, is_forwarded_request),
        placement,
    );
    if let Some(operation) = parse_internal_forwarded_operation(headers, is_forwarded_request) {
        envelope.operation = operation;
    }
    if is_forwarded_request {
        envelope.visited_nodes = header_forwarded_by_nodes(headers);
        if let Some(value) = parse_last_header_u64(headers, INTERNAL_TRUSTED_FORWARD_EPOCH_HEADER)
            .or_else(|| parse_header_u64(headers, INTERNAL_FORWARD_EPOCH_HEADER))
        {
            envelope.placement_epoch = value;
        }
        if let Some(value) =
            parse_last_header_string(headers, INTERNAL_TRUSTED_FORWARD_VIEW_ID_HEADER)
                .or_else(|| parse_header_string(headers, INTERNAL_FORWARD_VIEW_ID_HEADER))
        {
            envelope.placement_view_id = value;
        }
        if let Some(value) =
            parse_last_header_u8(headers, INTERNAL_TRUSTED_FORWARD_HOP_COUNT_HEADER)
                .or_else(|| parse_header_u8(headers, INTERNAL_FORWARD_HOP_COUNT_HEADER))
        {
            envelope.hop_count = value;
        }
        if let Some(value) = parse_last_header_u8(headers, INTERNAL_TRUSTED_FORWARD_MAX_HOPS_HEADER)
            .or_else(|| parse_header_u8(headers, INTERNAL_FORWARD_MAX_HOPS_HEADER))
        {
            envelope.max_hops = value.max(1);
        } else {
            envelope.max_hops = FORWARD_MAX_HOPS_DEFAULT;
        }
    }
    envelope
}

fn internal_forward_request_is_trusted(
    headers: &HeaderMap,
    cluster_auth_token: Option<&str>,
    local_node_id: &str,
    cluster_peers: &[String],
) -> bool {
    authenticate_forwarded_request(
        headers,
        FORWARDED_BY_HEADER,
        cluster_auth_token,
        local_node_id,
        cluster_peers,
    )
    .trusted
}

fn parse_internal_forwarded_operation(
    headers: &HeaderMap,
    is_forwarded_request: bool,
) -> Option<ForwardedWriteOperation> {
    if !is_forwarded_request {
        return None;
    }
    let value = parse_last_header_string(headers, INTERNAL_TRUSTED_FORWARD_OPERATION_HEADER)?;
    if value.eq_ignore_ascii_case(INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_PUT) {
        Some(ForwardedWriteOperation::ReplicatePutObject)
    } else if value.eq_ignore_ascii_case(INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_DELETE) {
        Some(ForwardedWriteOperation::ReplicateDeleteObject)
    } else if value.eq_ignore_ascii_case(INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_HEAD) {
        Some(ForwardedWriteOperation::ReplicateHeadObject)
    } else {
        None
    }
}

fn forward_idempotency_key(headers: &HeaderMap, is_forwarded_request: bool) -> String {
    let payload_hash = parse_header_string(headers, "x-amz-content-sha256");
    if is_forwarded_request {
        parse_last_header_string(headers, INTERNAL_TRUSTED_FORWARD_IDEMPOTENCY_KEY_HEADER)
            .or_else(|| parse_header_string(headers, INTERNAL_FORWARD_IDEMPOTENCY_KEY_HEADER))
            .or(payload_hash)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
    } else {
        payload_hash.unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
    }
}

fn header_forwarded_by_nodes(headers: &HeaderMap) -> Vec<String> {
    headers
        .get(FORWARDED_BY_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|node| !node.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn parse_header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn parse_last_header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .next_back()
}

fn parse_header_u64(headers: &HeaderMap, name: &str) -> Option<u64> {
    parse_header_string(headers, name).and_then(|value| value.parse::<u64>().ok())
}

fn parse_header_u8(headers: &HeaderMap, name: &str) -> Option<u8> {
    parse_header_string(headers, name).and_then(|value| value.parse::<u8>().ok())
}

fn parse_last_header_u64(headers: &HeaderMap, name: &str) -> Option<u64> {
    parse_last_header_string(headers, name).and_then(|value| value.parse::<u64>().ok())
}

fn parse_last_header_u8(headers: &HeaderMap, name: &str) -> Option<u8> {
    parse_last_header_string(headers, name).and_then(|value| value.parse::<u8>().ok())
}

fn add_write_routing_headers(
    mut builder: http::response::Builder,
    routing_hint: &ObjectWriteRoutingHint,
) -> http::response::Builder {
    if !routing_hint.distributed {
        return builder;
    }

    if let Some(primary_owner) = &routing_hint.primary_owner {
        builder = builder.header("x-maxio-primary-owner", primary_owner);
    }
    if let Some(forward_target) = &routing_hint.forward_target {
        builder = builder.header("x-maxio-forward-target", forward_target);
    }
    builder.header(
        "x-maxio-routing-local-primary-owner",
        if routing_hint.is_local_primary_owner {
            "true"
        } else {
            "false"
        },
    )
}

pub(super) fn map_delete_storage_err(bucket: &str, err: StorageError) -> S3Error {
    match err {
        StorageError::NotFound(_) => S3Error::no_such_bucket(bucket),
        StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
        _ => S3Error::internal(err),
    }
}

pub(super) fn map_object_get_err(key: &str, err: StorageError) -> S3Error {
    match err {
        StorageError::NotFound(_) => S3Error::no_such_key(key),
        StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
        _ => S3Error::internal(err),
    }
}

pub(super) fn map_object_version_get_err(
    key: &str,
    version_id: &str,
    err: StorageError,
) -> S3Error {
    match err {
        StorageError::VersionNotFound(_) => S3Error::no_such_version(version_id),
        StorageError::NotFound(_) => S3Error::no_such_key(key),
        StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
        _ => S3Error::internal(err),
    }
}

pub(super) fn map_object_put_err(bucket: &str, err: StorageError) -> S3Error {
    match err {
        StorageError::NotFound(_) => S3Error::no_such_bucket(bucket),
        StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
        StorageError::ChecksumMismatch(_) => S3Error::bad_checksum("x-amz-checksum"),
        _ => S3Error::internal(err),
    }
}

pub(super) fn map_object_version_delete_err(
    bucket: &str,
    version_id: &str,
    err: StorageError,
) -> S3Error {
    match err {
        StorageError::VersionNotFound(_) => S3Error::no_such_version(version_id),
        _ => map_delete_storage_err(bucket, err),
    }
}

pub(super) fn map_delete_objects_err(
    bucket: &str,
    key: String,
    err: StorageError,
) -> DeleteObjectsOutcome {
    match err {
        StorageError::InvalidKey(msg) => DeleteObjectsOutcome::Error {
            key,
            code: "InvalidArgument",
            message: msg,
        },
        StorageError::NotFound(_) => DeleteObjectsOutcome::Error {
            key,
            code: "NoSuchBucket",
            message: format!("The specified bucket does not exist: {bucket}"),
        },
        _ => DeleteObjectsOutcome::Error {
            key,
            code: "InternalError",
            message: err.to_string(),
        },
    }
}

pub(super) fn build_delete_objects_response_xml(
    outcomes: &[DeleteObjectsOutcome],
    quiet: bool,
) -> String {
    let mut deleted_xml = String::new();
    let mut error_xml = String::new();

    for outcome in outcomes {
        match outcome {
            DeleteObjectsOutcome::Deleted {
                key,
                version_id,
                is_delete_marker,
            } => {
                if quiet {
                    continue;
                }
                let mut entry = format!("<Deleted><Key>{}</Key>", quick_xml::escape::escape(key));
                if let Some(vid) = version_id {
                    entry.push_str(&format!(
                        "<VersionId>{}</VersionId>",
                        quick_xml::escape::escape(vid)
                    ));
                }
                if *is_delete_marker {
                    entry.push_str("<DeleteMarker>true</DeleteMarker>");
                }
                entry.push_str("</Deleted>");
                deleted_xml.push_str(&entry);
            }
            DeleteObjectsOutcome::Error { key, code, message } => {
                error_xml.push_str(&format!(
                    "<Error><Key>{}</Key><Code>{}</Code><Message>{}</Message></Error>",
                    quick_xml::escape::escape(key),
                    code,
                    quick_xml::escape::escape(message)
                ));
            }
        }
    }

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{}{}</DeleteResult>",
        deleted_xml, error_xml
    )
}

pub(super) fn put_object_response(
    result: &PutResult,
    routing_hint: &ObjectWriteRoutingHint,
) -> Result<Response<Body>, S3Error> {
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("ETag", &result.etag)
        .header("Content-Length", result.size.to_string());
    if let Some(vid) = &result.version_id {
        builder = builder.header("x-amz-version-id", vid.as_str());
    }
    if let (Some(algo), Some(val)) = (&result.checksum_algorithm, &result.checksum_value) {
        builder = builder.header(algo.header_name(), val.as_str());
    }
    builder = add_write_routing_headers(builder, routing_hint);
    builder.body(Body::empty()).map_err(S3Error::internal)
}

pub(super) fn no_content_delete_response(
    version_id: Option<&str>,
    is_delete_marker: bool,
    routing_hint: &ObjectWriteRoutingHint,
) -> Result<Response<Body>, S3Error> {
    let mut builder = Response::builder().status(StatusCode::NO_CONTENT);
    if let Some(version_id) = version_id {
        builder = builder.header("x-amz-version-id", version_id);
    }
    if is_delete_marker {
        builder = builder.header("x-amz-delete-marker", "true");
    }
    builder = add_write_routing_headers(builder, routing_hint);
    builder.body(Body::empty()).map_err(S3Error::internal)
}

pub(super) fn copy_object_response(
    xml: String,
    source_version_id: Option<&str>,
    version_id: Option<&str>,
    routing_hint: &ObjectWriteRoutingHint,
) -> Result<Response<Body>, S3Error> {
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml");
    if let Some(source_version_id) = source_version_id {
        builder = builder.header("x-amz-copy-source-version-id", source_version_id);
    }
    if let Some(version_id) = version_id {
        builder = builder.header("x-amz-version-id", version_id);
    }
    builder = add_write_routing_headers(builder, routing_hint);
    builder.body(Body::from(xml)).map_err(S3Error::internal)
}

pub(super) fn delete_objects_xml_response(xml: String) -> Result<Response<Body>, S3Error> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/xml")
        .body(Body::from(xml))
        .map_err(S3Error::internal)
}

pub(crate) async fn body_to_reader(
    headers: &HeaderMap,
    body: Body,
) -> Result<std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>, S3Error> {
    let is_aws_chunked = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        == Some("STREAMING-AWS4-HMAC-SHA256-PAYLOAD");

    let stream = body.into_data_stream();
    let raw_reader = tokio_util::io::StreamReader::new(stream.map_err(std::io::Error::other));

    if is_aws_chunked {
        let framing_err = || S3Error::invalid_argument("invalid aws-chunked payload framing");
        let mut buf_reader = tokio::io::BufReader::new(raw_reader);
        let mut decoded = Vec::new();
        let mut saw_final_chunk = false;
        loop {
            let mut line = String::new();
            let n = buf_reader
                .read_line(&mut line)
                .await
                .map_err(S3Error::internal)?;
            if n == 0 {
                break;
            }
            let line = line.trim_end_matches(['\r', '\n']);
            let size_str = line.split(';').next().unwrap_or("0");
            let chunk_size =
                usize::from_str_radix(size_str.trim(), 16).map_err(|_| framing_err())?;
            if chunk_size == 0 {
                saw_final_chunk = true;
                break;
            }
            let mut chunk = vec![0u8; chunk_size];
            buf_reader
                .read_exact(&mut chunk)
                .await
                .map_err(|_| framing_err())?;
            decoded.extend_from_slice(&chunk);
            let mut crlf = [0u8; 2];
            buf_reader
                .read_exact(&mut crlf)
                .await
                .map_err(|_| framing_err())?;
            if crlf != *b"\r\n" {
                return Err(framing_err());
            }
        }
        if !saw_final_chunk {
            return Err(framing_err());
        }
        Ok(Box::pin(std::io::Cursor::new(decoded)))
    } else {
        Ok(Box::pin(raw_reader))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use tempfile::TempDir;
    use tokio::io::AsyncReadExt;

    use crate::config::{
        ClusterPeerTransportMode, Config, MembershipProtocol, WriteDurabilityMode,
    };
    use crate::metadata::ClusterMetadataListingStrategy;
    use crate::server::AppState;
    use crate::storage::BucketMeta;
    use crate::storage::placement::{
        PendingReplicationOperation, PendingReplicationQueue, load_pending_replication_queue,
        persist_pending_replication_queue,
    };

    const TEST_PLACEMENT_EPOCH: u64 = 42;

    fn standalone_routing_hint() -> ObjectWriteRoutingHint {
        ObjectWriteRoutingHint {
            distributed: false,
            primary_owner: None,
            forward_target: None,
            is_local_primary_owner: true,
        }
    }

    fn distributed_forwarding_hint() -> ObjectWriteRoutingHint {
        ObjectWriteRoutingHint {
            distributed: true,
            primary_owner: Some("node-b:9000".to_string()),
            forward_target: Some("node-b:9000".to_string()),
            is_local_primary_owner: false,
        }
    }

    #[test]
    fn extract_checksum_prefers_explicit_value_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-checksum-algorithm", "SHA1".parse().unwrap());
        headers.insert("x-amz-checksum-sha256", "abc123=".parse().unwrap());

        let checksum = extract_checksum(&headers).expect("checksum should be extracted");
        assert_eq!(checksum.0, ChecksumAlgorithm::SHA256);
        assert_eq!(checksum.1.as_deref(), Some("abc123="));
    }

    #[test]
    fn extract_checksum_supports_algorithm_only_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-checksum-algorithm", "CRC32C".parse().unwrap());

        let checksum = extract_checksum(&headers).expect("checksum should be extracted");
        assert_eq!(checksum.0, ChecksumAlgorithm::CRC32C);
        assert_eq!(checksum.1, None);
    }

    #[test]
    fn add_checksum_header_adds_header_for_known_checksum() {
        let meta = ObjectMeta {
            key: "a.txt".to_string(),
            size: 1,
            etag: "\"etag\"".to_string(),
            content_type: "text/plain".to_string(),
            last_modified: "2026-03-01T00:00:00Z".to_string(),
            version_id: None,
            is_delete_marker: false,
            storage_format: None,
            checksum_algorithm: Some(ChecksumAlgorithm::SHA256),
            checksum_value: Some("value==".to_string()),
        };

        let response = add_checksum_header(http::Response::builder(), &meta)
            .status(200)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            response
                .headers()
                .get("x-amz-checksum-sha256")
                .and_then(|v| v.to_str().ok()),
            Some("value==")
        );
    }

    #[tokio::test]
    async fn body_to_reader_decodes_streaming_chunked_payload() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".parse().unwrap(),
        );
        let encoded =
            b"5;chunk-signature=a\r\nhello\r\n6;chunk-signature=b\r\n world\r\n0;chunk-signature=c\r\n\r\n";
        let mut reader = body_to_reader(&headers, Body::from(encoded.as_slice()))
            .await
            .expect("chunked payload should decode");
        let mut decoded = Vec::new();
        reader.read_to_end(&mut decoded).await.unwrap();
        assert_eq!(decoded, b"hello world");
    }

    #[tokio::test]
    async fn body_to_reader_keeps_regular_payload_unchanged() {
        let headers = HeaderMap::new();
        let expected = b"plain payload bytes";
        let mut reader = body_to_reader(&headers, Body::from(expected.as_slice()))
            .await
            .expect("plain payload should be readable");
        let mut actual = Vec::new();
        reader.read_to_end(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn body_to_reader_rejects_chunked_payload_without_final_chunk() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".parse().unwrap(),
        );
        let encoded = b"5;chunk-signature=a\r\nhello\r\n";
        let err = match body_to_reader(&headers, Body::from(encoded.as_slice())).await {
            Ok(_) => panic!("payload without final chunk should fail"),
            Err(err) => err,
        };
        assert_eq!(err.code.as_str(), "InvalidArgument");
    }

    #[tokio::test]
    async fn body_to_reader_rejects_chunked_payload_with_invalid_size() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".parse().unwrap(),
        );
        let encoded = b"zz;chunk-signature=a\r\nhello\r\n0;chunk-signature=b\r\n\r\n";
        let err = match body_to_reader(&headers, Body::from(encoded.as_slice())).await {
            Ok(_) => panic!("payload with invalid chunk size should fail"),
            Err(err) => err,
        };
        assert_eq!(err.code.as_str(), "InvalidArgument");
    }

    #[test]
    fn build_delete_objects_response_xml_includes_deleted_and_error_entries() {
        let xml = build_delete_objects_response_xml(
            &[
                DeleteObjectsOutcome::Deleted {
                    key: "a&b.txt".to_string(),
                    version_id: Some("v1".to_string()),
                    is_delete_marker: true,
                },
                DeleteObjectsOutcome::Error {
                    key: "bad<key>.txt".to_string(),
                    code: "InternalError",
                    message: "failed > reason".to_string(),
                },
            ],
            false,
        );

        assert!(xml.contains("<Deleted><Key>a&amp;b.txt</Key>"));
        assert!(xml.contains("<VersionId>v1</VersionId>"));
        assert!(xml.contains("<DeleteMarker>true</DeleteMarker>"));
        assert!(xml.contains("<Error><Key>bad&lt;key&gt;.txt</Key>"));
        assert!(xml.contains("<Code>InternalError</Code>"));
        assert!(xml.contains("<Message>failed &gt; reason</Message>"));
    }

    #[test]
    fn build_delete_objects_response_xml_honors_quiet_mode() {
        let xml = build_delete_objects_response_xml(
            &[DeleteObjectsOutcome::Deleted {
                key: "a.txt".to_string(),
                version_id: None,
                is_delete_marker: false,
            }],
            true,
        );

        assert!(!xml.contains("<Deleted>"));
        assert!(xml.contains("<DeleteResult"));
    }

    #[test]
    fn map_delete_storage_err_maps_invalid_key_to_invalid_argument() {
        let err = map_delete_storage_err("bucket", StorageError::InvalidKey("bad key".into()));
        assert_eq!(err.code.as_str(), "InvalidArgument");
        assert_eq!(err.message, "bad key");
    }

    #[test]
    fn map_delete_objects_err_maps_invalid_key_to_invalid_argument_entry() {
        let outcome = map_delete_objects_err(
            "bucket",
            "../oops.txt".to_string(),
            StorageError::InvalidKey("bad key".into()),
        );
        match outcome {
            DeleteObjectsOutcome::Error { code, message, .. } => {
                assert_eq!(code, "InvalidArgument");
                assert_eq!(message, "bad key");
            }
            _ => panic!("expected error outcome"),
        }
    }

    #[test]
    fn map_object_get_err_maps_not_found_and_invalid_key() {
        let key_err = map_object_get_err("docs/a.txt", StorageError::NotFound("x".into()));
        assert_eq!(key_err.code.as_str(), "NoSuchKey");

        let invalid_err =
            map_object_get_err("docs/a.txt", StorageError::InvalidKey("bad key".into()));
        assert_eq!(invalid_err.code.as_str(), "InvalidArgument");
        assert_eq!(invalid_err.message, "bad key");
    }

    #[test]
    fn map_object_version_get_err_maps_missing_version_and_key() {
        let version_err = map_object_version_get_err(
            "docs/a.txt",
            "v123",
            StorageError::VersionNotFound("v123".into()),
        );
        assert_eq!(version_err.code.as_str(), "NoSuchVersion");

        let key_err =
            map_object_version_get_err("docs/a.txt", "v123", StorageError::NotFound("x".into()));
        assert_eq!(key_err.code.as_str(), "NoSuchKey");
    }

    #[test]
    fn map_object_put_err_maps_bucket_invalid_and_checksum_errors() {
        let bucket_err = map_object_put_err("bucket", StorageError::NotFound("x".into()));
        assert_eq!(bucket_err.code.as_str(), "NoSuchBucket");

        let invalid_err = map_object_put_err("bucket", StorageError::InvalidKey("bad key".into()));
        assert_eq!(invalid_err.code.as_str(), "InvalidArgument");

        let checksum_err = map_object_put_err(
            "bucket",
            StorageError::ChecksumMismatch("digest mismatch".into()),
        );
        assert_eq!(checksum_err.code.as_str(), "BadDigest");
    }

    #[test]
    fn map_object_version_delete_err_maps_missing_version() {
        let err = map_object_version_delete_err(
            "bucket",
            "v-1",
            StorageError::VersionNotFound("v-1".into()),
        );
        assert_eq!(err.code.as_str(), "NoSuchVersion");
    }

    #[test]
    fn put_object_response_sets_headers() {
        let result = PutResult {
            size: 12,
            etag: "\"etag\"".to_string(),
            version_id: Some("v2".to_string()),
            checksum_algorithm: Some(ChecksumAlgorithm::SHA256),
            checksum_value: Some("checksum==".to_string()),
        };
        let response = put_object_response(&result, &standalone_routing_hint())
            .expect("response should build");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok()),
            Some("12")
        );
        assert_eq!(
            response.headers().get("etag").and_then(|v| v.to_str().ok()),
            Some("\"etag\"")
        );
        assert_eq!(
            response
                .headers()
                .get("x-amz-version-id")
                .and_then(|v| v.to_str().ok()),
            Some("v2")
        );
        assert_eq!(
            response
                .headers()
                .get("x-amz-checksum-sha256")
                .and_then(|v| v.to_str().ok()),
            Some("checksum==")
        );
        assert!(response.headers().get("x-maxio-primary-owner").is_none());
    }

    #[test]
    fn put_object_response_sets_distributed_routing_headers() {
        let result = PutResult {
            size: 12,
            etag: "\"etag\"".to_string(),
            version_id: None,
            checksum_algorithm: None,
            checksum_value: None,
        };
        let response = put_object_response(&result, &distributed_forwarding_hint())
            .expect("response should build");
        assert_eq!(
            response
                .headers()
                .get("x-maxio-primary-owner")
                .and_then(|v| v.to_str().ok()),
            Some("node-b:9000")
        );
        assert_eq!(
            response
                .headers()
                .get("x-maxio-forward-target")
                .and_then(|v| v.to_str().ok()),
            Some("node-b:9000")
        );
        assert_eq!(
            response
                .headers()
                .get("x-maxio-routing-local-primary-owner")
                .and_then(|v| v.to_str().ok()),
            Some("false")
        );
    }

    #[test]
    fn no_content_delete_response_sets_optional_headers() {
        let response = no_content_delete_response(Some("v1"), true, &distributed_forwarding_hint())
            .expect("response should build");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            response
                .headers()
                .get("x-amz-version-id")
                .and_then(|v| v.to_str().ok()),
            Some("v1")
        );
        assert_eq!(
            response
                .headers()
                .get("x-amz-delete-marker")
                .and_then(|v| v.to_str().ok()),
            Some("true")
        );
        assert_eq!(
            response
                .headers()
                .get("x-maxio-primary-owner")
                .and_then(|v| v.to_str().ok()),
            Some("node-b:9000")
        );
    }

    #[tokio::test]
    async fn copy_object_response_sets_headers_and_body() {
        let response = copy_object_response(
            "<CopyObjectResult />".to_string(),
            Some("src-v1"),
            Some("dst-v2"),
            &distributed_forwarding_hint(),
        )
        .expect("response should build");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/xml")
        );
        assert_eq!(
            response
                .headers()
                .get("x-amz-copy-source-version-id")
                .and_then(|v| v.to_str().ok()),
            Some("src-v1")
        );
        assert_eq!(
            response
                .headers()
                .get("x-amz-version-id")
                .and_then(|v| v.to_str().ok()),
            Some("dst-v2")
        );
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        assert_eq!(body.as_ref(), b"<CopyObjectResult />");
    }

    #[test]
    fn object_write_routing_hint_shapes_distributed_forwarding_state() {
        let peers = ["node-b:9000".to_string()];
        let hint = object_write_routing_hint("docs/object.txt", "node-a:9000", &peers);
        assert!(hint.distributed);
        assert!(hint.primary_owner.is_some());
        assert_eq!(
            hint.forward_target,
            if hint.is_local_primary_owner {
                None
            } else {
                hint.primary_owner.clone()
            }
        );
    }

    #[test]
    fn object_write_routing_hint_is_local_primary_for_standalone() {
        let hint = object_write_routing_hint("docs/object.txt", "node-a:9000", &[]);
        assert!(!hint.distributed);
        assert_eq!(hint.primary_owner.as_deref(), Some("node-a:9000"));
        assert_eq!(hint.forward_target, None);
        assert!(hint.is_local_primary_owner);
    }

    #[test]
    fn ensure_local_write_owner_accepts_local_primary_writes() {
        let hint = ObjectWriteRoutingHint {
            distributed: true,
            primary_owner: Some("node-a:9000".to_string()),
            forward_target: None,
            is_local_primary_owner: true,
        };
        assert!(ensure_local_write_owner(&hint).is_ok());
    }

    #[test]
    fn ensure_local_write_owner_rejects_non_owner_writes_with_forward_target() {
        let err = ensure_local_write_owner(&distributed_forwarding_hint())
            .expect_err("non-owner writes should be rejected");
        assert_eq!(err.code.as_str(), "ServiceUnavailable");
        assert!(err.message.contains("non-owner node"));
        assert!(err.message.contains("node-b:9000"));
    }

    #[test]
    fn should_skip_forwarded_request_header_skips_transport_loop_and_auth_headers() {
        assert!(should_skip_forwarded_request_header(&header::CONNECTION));
        assert!(should_skip_forwarded_request_header(
            &header::TRANSFER_ENCODING
        ));
        assert!(should_skip_forwarded_request_header(
            &header::CONTENT_LENGTH
        ));
        assert!(should_skip_forwarded_request_header(
            &header::HeaderName::from_static(FORWARDED_BY_HEADER)
        ));
        assert!(should_skip_forwarded_request_header(
            &header::HeaderName::from_static(INTERNAL_AUTH_TOKEN_HEADER)
        ));
        assert!(!should_skip_forwarded_request_header(
            &header::HeaderName::from_static(INTERNAL_FORWARD_EPOCH_HEADER)
        ));
        assert!(!should_skip_forwarded_request_header(
            &header::HeaderName::from_static(INTERNAL_FORWARD_VIEW_ID_HEADER)
        ));
        assert!(!should_skip_forwarded_request_header(
            &header::HeaderName::from_static(INTERNAL_FORWARD_HOP_COUNT_HEADER)
        ));
        assert!(!should_skip_forwarded_request_header(
            &header::HeaderName::from_static(INTERNAL_FORWARD_MAX_HOPS_HEADER)
        ));
        assert!(!should_skip_forwarded_request_header(
            &header::HeaderName::from_static(INTERNAL_FORWARD_IDEMPOTENCY_KEY_HEADER)
        ));
        assert!(!should_skip_forwarded_request_header(
            &header::HeaderName::from_static("x-amz-date")
        ));
    }

    #[test]
    fn should_skip_forwarded_response_header_hides_internal_forwarding_protocol_headers() {
        assert!(should_skip_forwarded_response_header(&header::CONNECTION));
        assert!(should_skip_forwarded_response_header(
            &header::TRANSFER_ENCODING
        ));
        assert!(should_skip_forwarded_response_header(
            &header::HeaderName::from_static(FORWARDED_BY_HEADER)
        ));
        assert!(should_skip_forwarded_response_header(
            &header::HeaderName::from_static(INTERNAL_FORWARD_EPOCH_HEADER)
        ));
        assert!(should_skip_forwarded_response_header(
            &header::HeaderName::from_static(INTERNAL_FORWARD_VIEW_ID_HEADER)
        ));
        assert!(should_skip_forwarded_response_header(
            &header::HeaderName::from_static(INTERNAL_FORWARD_HOP_COUNT_HEADER)
        ));
        assert!(should_skip_forwarded_response_header(
            &header::HeaderName::from_static(INTERNAL_FORWARD_MAX_HOPS_HEADER)
        ));
        assert!(should_skip_forwarded_response_header(
            &header::HeaderName::from_static(INTERNAL_FORWARD_IDEMPOTENCY_KEY_HEADER)
        ));
        assert!(should_skip_forwarded_response_header(
            &header::HeaderName::from_static(INTERNAL_TRUSTED_FORWARD_EPOCH_HEADER)
        ));
        assert!(should_skip_forwarded_response_header(
            &header::HeaderName::from_static(INTERNAL_TRUSTED_FORWARD_VIEW_ID_HEADER)
        ));
        assert!(should_skip_forwarded_response_header(
            &header::HeaderName::from_static(INTERNAL_TRUSTED_FORWARD_HOP_COUNT_HEADER)
        ));
        assert!(should_skip_forwarded_response_header(
            &header::HeaderName::from_static(INTERNAL_TRUSTED_FORWARD_MAX_HOPS_HEADER)
        ));
        assert!(should_skip_forwarded_response_header(
            &header::HeaderName::from_static(INTERNAL_TRUSTED_FORWARD_IDEMPOTENCY_KEY_HEADER)
        ));
        assert!(should_skip_forwarded_response_header(
            &header::HeaderName::from_static(INTERNAL_TRUSTED_FORWARD_OPERATION_HEADER)
        ));
        assert!(should_skip_forwarded_response_header(
            &header::HeaderName::from_static(INTERNAL_AUTH_TOKEN_HEADER)
        ));
        assert!(!should_skip_forwarded_response_header(
            &header::HeaderName::from_static("etag")
        ));
    }

    #[test]
    fn internal_forwarding_transport_reject_status_identifies_auth_rejects() {
        assert!(is_internal_forwarding_transport_reject_status(
            StatusCode::UNAUTHORIZED
        ));
        assert!(is_internal_forwarding_transport_reject_status(
            StatusCode::FORBIDDEN
        ));
        assert!(!is_internal_forwarding_transport_reject_status(
            StatusCode::NOT_FOUND
        ));
        assert!(!is_internal_forwarding_transport_reject_status(
            StatusCode::SERVICE_UNAVAILABLE
        ));
    }

    #[test]
    fn forwarded_write_envelope_ignores_untrusted_protocol_headers_without_internal_forward_marker()
    {
        let mut headers = HeaderMap::new();
        headers.insert(
            INTERNAL_FORWARD_EPOCH_HEADER,
            "999".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_FORWARD_VIEW_ID_HEADER,
            "tampered-view".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_FORWARD_HOP_COUNT_HEADER,
            "7".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_FORWARD_MAX_HOPS_HEADER,
            "9".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_FORWARD_IDEMPOTENCY_KEY_HEADER,
            "tampered-idempotency".parse().expect("header"),
        );

        let peers = ["node-b:9000".to_string()];
        let placement =
            PlacementViewState::from_membership(TEST_PLACEMENT_EPOCH, "node-a:9000", &peers);
        let envelope = forwarded_write_envelope_from_headers(
            &headers,
            ForwardedWriteOperation::PutObject,
            "bucket",
            "docs/object.txt",
            "node-a:9000",
            &placement,
            None,
        );

        assert_eq!(envelope.placement_epoch, TEST_PLACEMENT_EPOCH);
        assert_eq!(envelope.placement_view_id, placement.view_id);
        assert_eq!(envelope.hop_count, 0);
        assert_eq!(envelope.max_hops, FORWARD_MAX_HOPS_DEFAULT);
        assert_ne!(envelope.idempotency_key, "tampered-idempotency");
    }

    #[test]
    fn write_forward_target_rejects_looped_non_owner_request() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_BY_HEADER, "node-a:9000".parse().unwrap());
        let peers = ["node-b:9000".to_string()];
        let placement =
            PlacementViewState::from_membership(TEST_PLACEMENT_EPOCH, "node-a:9000", &peers);

        let err = write_forward_target(
            "bucket",
            "docs/object.txt",
            ForwardedWriteOperation::PutObject,
            &distributed_forwarding_hint(),
            &headers,
            "node-a:9000",
            &placement,
            None,
        )
        .expect_err("forward loop should be rejected");
        assert_eq!(err.code.as_str(), "ServiceUnavailable");
        assert!(err.message.contains("loop"));
    }

    #[test]
    fn write_forward_target_returns_envelope_for_non_primary_owner() {
        let headers = HeaderMap::new();
        let peers = ["node-b:9000".to_string(), "node-c:9000".to_string()];
        let local_node = "node-a:9000";

        let (key, hint) = (0..4096)
            .find_map(|idx| {
                let key = format!("forward/hint-{idx}.txt");
                let hint = object_write_routing_hint(&key, local_node, &peers);
                if hint.distributed && !hint.is_local_primary_owner {
                    Some((key, hint))
                } else {
                    None
                }
            })
            .expect("expected at least one non-primary key");
        let placement =
            PlacementViewState::from_membership(TEST_PLACEMENT_EPOCH, local_node, &peers);

        let primary_owner = hint.primary_owner.clone().expect("primary should exist");
        for operation in [
            ForwardedWriteOperation::PutObject,
            ForwardedWriteOperation::GetObject,
            ForwardedWriteOperation::HeadObject,
        ] {
            let target = write_forward_target(
                "bucket-a",
                &key,
                operation.clone(),
                &hint,
                &headers,
                local_node,
                &placement,
                None,
            )
            .expect("forward target resolution should succeed")
            .expect("non-primary key should return forward target");

            assert_eq!(target.target, primary_owner);
            assert_eq!(target.envelope.operation, operation);
            assert_eq!(target.envelope.bucket, "bucket-a");
            assert_eq!(target.envelope.key, key);
            assert_eq!(target.envelope.hop_count, 1);
            assert_eq!(target.envelope.max_hops, FORWARD_MAX_HOPS_DEFAULT);
            assert_eq!(target.envelope.visited_nodes, vec![local_node.to_string()]);
            assert_eq!(target.envelope.placement_epoch, TEST_PLACEMENT_EPOCH);
            assert!(!target.envelope.placement_view_id.is_empty());
            assert!(!target.envelope.idempotency_key.is_empty());
        }
    }

    #[test]
    fn write_forward_target_rejects_view_mismatch() {
        let peers = ["node-b:9000".to_string(), "node-c:9000".to_string()];
        let local_node = "node-a:9000";
        let (key, hint) = (0..4096)
            .find_map(|idx| {
                let key = format!("forward/mismatch-{idx}.txt");
                let hint = object_write_routing_hint(&key, local_node, &peers);
                if hint.distributed && !hint.is_local_primary_owner {
                    Some((key, hint))
                } else {
                    None
                }
            })
            .expect("expected at least one non-primary key");

        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_BY_HEADER, "node-x:9000".parse().unwrap());
        headers.insert(
            INTERNAL_FORWARD_VIEW_ID_HEADER,
            "wrong-view".parse().unwrap(),
        );
        let placement =
            PlacementViewState::from_membership(TEST_PLACEMENT_EPOCH, local_node, &peers);
        let err = write_forward_target(
            "bucket-a",
            &key,
            ForwardedWriteOperation::DeleteObject,
            &hint,
            &headers,
            local_node,
            &placement,
            None,
        )
        .expect_err("view mismatch should be rejected");
        assert_eq!(err.code.as_str(), "ServiceUnavailable");
        assert!(err.message.contains("view mismatch"));
    }

    #[test]
    fn forwarded_write_envelope_prefers_trusted_internal_headers_for_forwarded_requests() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_BY_HEADER, "node-a:9000".parse().expect("header"));
        headers.insert(
            INTERNAL_FORWARD_EPOCH_HEADER,
            "999".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_FORWARD_VIEW_ID_HEADER,
            "legacy-tampered-view".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_FORWARD_HOP_COUNT_HEADER,
            "7".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_FORWARD_MAX_HOPS_HEADER,
            "9".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_FORWARD_IDEMPOTENCY_KEY_HEADER,
            "legacy-idempotency".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_EPOCH_HEADER,
            "42".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_VIEW_ID_HEADER,
            "trusted-view".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_HOP_COUNT_HEADER,
            "2".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_MAX_HOPS_HEADER,
            "6".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_IDEMPOTENCY_KEY_HEADER,
            "trusted-idempotency".parse().expect("header"),
        );

        let placement = PlacementViewState::from_membership(
            TEST_PLACEMENT_EPOCH,
            "node-a:9000",
            &["node-b:9000".to_string()],
        );
        let envelope = forwarded_write_envelope_from_headers(
            &headers,
            ForwardedWriteOperation::PutObject,
            "bucket",
            "docs/object.txt",
            "node-a:9000",
            &placement,
            None,
        );

        assert_eq!(envelope.placement_epoch, 42);
        assert_eq!(envelope.placement_view_id, "trusted-view");
        assert_eq!(envelope.hop_count, 2);
        assert_eq!(envelope.max_hops, 6);
        assert_eq!(envelope.idempotency_key, "trusted-idempotency");
    }

    #[test]
    fn forwarded_write_envelope_ignores_forwarded_metadata_when_auth_token_is_missing() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_BY_HEADER, "node-a:9000".parse().expect("header"));
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_EPOCH_HEADER,
            "42".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_VIEW_ID_HEADER,
            "trusted-view".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_HOP_COUNT_HEADER,
            "2".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_MAX_HOPS_HEADER,
            "6".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_IDEMPOTENCY_KEY_HEADER,
            "trusted-idempotency".parse().expect("header"),
        );

        let placement = PlacementViewState::from_membership(
            TEST_PLACEMENT_EPOCH,
            "node-a:9000",
            &["node-b:9000".to_string()],
        );
        let envelope = forwarded_write_envelope_from_headers(
            &headers,
            ForwardedWriteOperation::PutObject,
            "bucket",
            "docs/object.txt",
            "node-a:9000",
            &placement,
            Some("shared-secret"),
        );

        assert_eq!(envelope.placement_epoch, TEST_PLACEMENT_EPOCH);
        assert_eq!(envelope.placement_view_id, placement.view_id);
        assert_eq!(envelope.hop_count, 0);
        assert_eq!(envelope.max_hops, FORWARD_MAX_HOPS_DEFAULT);
        assert_ne!(envelope.idempotency_key, "trusted-idempotency");
    }

    #[test]
    fn forwarded_write_envelope_uses_forwarded_metadata_when_auth_token_matches() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_BY_HEADER, "node-b:9000".parse().expect("header"));
        headers.insert(
            INTERNAL_AUTH_TOKEN_HEADER,
            "shared-secret".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_EPOCH_HEADER,
            "42".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_VIEW_ID_HEADER,
            "trusted-view".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_HOP_COUNT_HEADER,
            "2".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_MAX_HOPS_HEADER,
            "6".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_IDEMPOTENCY_KEY_HEADER,
            "trusted-idempotency".parse().expect("header"),
        );

        let placement = PlacementViewState::from_membership(
            TEST_PLACEMENT_EPOCH,
            "node-a:9000",
            &["node-b:9000".to_string()],
        );
        let envelope = forwarded_write_envelope_from_headers(
            &headers,
            ForwardedWriteOperation::PutObject,
            "bucket",
            "docs/object.txt",
            "node-a:9000",
            &placement,
            Some("shared-secret"),
        );

        assert_eq!(envelope.placement_epoch, 42);
        assert_eq!(envelope.placement_view_id, "trusted-view");
        assert_eq!(envelope.hop_count, 2);
        assert_eq!(envelope.max_hops, 6);
        assert_eq!(envelope.idempotency_key, "trusted-idempotency");
    }

    #[test]
    fn forwarded_write_envelope_ignores_forwarded_metadata_when_sender_not_in_peer_allowlist() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_BY_HEADER, "node-x:9000".parse().expect("header"));
        headers.insert(
            INTERNAL_AUTH_TOKEN_HEADER,
            "shared-secret".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_EPOCH_HEADER,
            "42".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_VIEW_ID_HEADER,
            "trusted-view".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_HOP_COUNT_HEADER,
            "2".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_MAX_HOPS_HEADER,
            "6".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_IDEMPOTENCY_KEY_HEADER,
            "trusted-idempotency".parse().expect("header"),
        );

        let placement = PlacementViewState::from_membership(
            TEST_PLACEMENT_EPOCH,
            "node-a:9000",
            &["node-b:9000".to_string()],
        );
        let envelope = forwarded_write_envelope_from_headers(
            &headers,
            ForwardedWriteOperation::PutObject,
            "bucket",
            "docs/object.txt",
            "node-a:9000",
            &placement,
            Some("shared-secret"),
        );

        assert_eq!(envelope.placement_epoch, TEST_PLACEMENT_EPOCH);
        assert_eq!(envelope.placement_view_id, placement.view_id);
        assert_eq!(envelope.hop_count, 0);
        assert_eq!(envelope.max_hops, FORWARD_MAX_HOPS_DEFAULT);
        assert_ne!(envelope.idempotency_key, "trusted-idempotency");
    }

    #[test]
    fn forwarded_write_envelope_ignores_forwarded_metadata_when_chain_has_duplicate_hops() {
        let mut headers = HeaderMap::new();
        headers.insert(
            FORWARDED_BY_HEADER,
            "node-a:9000,node-a:9000".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_AUTH_TOKEN_HEADER,
            "shared-secret".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_EPOCH_HEADER,
            "42".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_VIEW_ID_HEADER,
            "trusted-view".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_HOP_COUNT_HEADER,
            "2".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_MAX_HOPS_HEADER,
            "6".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_IDEMPOTENCY_KEY_HEADER,
            "trusted-idempotency".parse().expect("header"),
        );

        let placement = PlacementViewState::from_membership(
            TEST_PLACEMENT_EPOCH,
            "node-a:9000",
            &["node-b:9000".to_string()],
        );
        let envelope = forwarded_write_envelope_from_headers(
            &headers,
            ForwardedWriteOperation::PutObject,
            "bucket",
            "docs/object.txt",
            "node-a:9000",
            &placement,
            Some("shared-secret"),
        );

        assert_eq!(envelope.placement_epoch, TEST_PLACEMENT_EPOCH);
        assert_eq!(envelope.placement_view_id, placement.view_id);
        assert_eq!(envelope.hop_count, 0);
        assert_eq!(envelope.max_hops, FORWARD_MAX_HOPS_DEFAULT);
        assert_ne!(envelope.idempotency_key, "trusted-idempotency");
    }

    #[test]
    fn forwarded_write_envelope_uses_trusted_internal_operation_for_replica_writes() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_BY_HEADER, "node-a:9000".parse().expect("header"));
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_OPERATION_HEADER,
            INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_PUT
                .parse()
                .expect("header"),
        );

        let placement = PlacementViewState::from_membership(
            TEST_PLACEMENT_EPOCH,
            "node-a:9000",
            &["node-b:9000".to_string()],
        );
        let envelope = forwarded_write_envelope_from_headers(
            &headers,
            ForwardedWriteOperation::PutObject,
            "bucket",
            "docs/object.txt",
            "node-a:9000",
            &placement,
            None,
        );

        assert_eq!(
            envelope.operation,
            ForwardedWriteOperation::ReplicatePutObject
        );
    }

    #[test]
    fn forwarded_write_envelope_uses_trusted_internal_operation_for_replica_heads() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_BY_HEADER, "node-a:9000".parse().expect("header"));
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_OPERATION_HEADER,
            INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_HEAD
                .parse()
                .expect("header"),
        );

        let placement = PlacementViewState::from_membership(
            TEST_PLACEMENT_EPOCH,
            "node-a:9000",
            &["node-b:9000".to_string()],
        );
        let envelope = forwarded_write_envelope_from_headers(
            &headers,
            ForwardedWriteOperation::PutObject,
            "bucket",
            "docs/object.txt",
            "node-a:9000",
            &placement,
            None,
        );

        assert_eq!(
            envelope.operation,
            ForwardedWriteOperation::ReplicateHeadObject
        );
    }

    #[test]
    fn is_internal_replica_put_request_requires_forwarded_marker_and_trusted_operation() {
        let mut headers = HeaderMap::new();
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_OPERATION_HEADER,
            INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_PUT
                .parse()
                .expect("header"),
        );
        let peers = ["node-b:9000".to_string()];
        assert!(!is_internal_replica_put_request(
            &headers,
            None,
            "node-a:9000",
            &peers,
        ));

        headers.insert(FORWARDED_BY_HEADER, "node-a:9000".parse().expect("header"));
        assert!(is_internal_replica_put_request(
            &headers,
            None,
            "node-a:9000",
            &peers,
        ));
        assert!(!is_internal_replica_delete_request(
            &headers,
            None,
            "node-a:9000",
            &peers,
        ));
    }

    #[test]
    fn is_internal_replica_delete_request_requires_forwarded_marker_and_trusted_operation() {
        let mut headers = HeaderMap::new();
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_OPERATION_HEADER,
            INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_DELETE
                .parse()
                .expect("header"),
        );
        let peers = ["node-b:9000".to_string()];
        assert!(!is_internal_replica_delete_request(
            &headers,
            None,
            "node-a:9000",
            &peers,
        ));

        headers.insert(FORWARDED_BY_HEADER, "node-a:9000".parse().expect("header"));
        assert!(is_internal_replica_delete_request(
            &headers,
            None,
            "node-a:9000",
            &peers,
        ));
        assert!(!is_internal_replica_put_request(
            &headers,
            None,
            "node-a:9000",
            &peers,
        ));
    }

    #[test]
    fn write_replica_count_for_membership_count_caps_to_two_nodes() {
        assert_eq!(write_replica_count_for_membership_count(0), 1);
        assert_eq!(write_replica_count_for_membership_count(1), 1);
        assert_eq!(write_replica_count_for_membership_count(2), 2);
        assert_eq!(write_replica_count_for_membership_count(3), 2);
    }

    #[test]
    fn object_path_and_query_encodes_path_and_sorts_query_keys() {
        let mut params = HashMap::new();
        params.insert("X-Amz-Date".to_string(), "20260302T101010Z".to_string());
        params.insert("versionId".to_string(), "v1 / part".to_string());

        let path = object_path_and_query("bucket", "docs/Jan 2026/cafe+notes.txt", &params);
        assert!(path.starts_with("/bucket/docs/Jan%202026/cafe%2Bnotes.txt?"));
        assert!(path.contains("X-Amz-Date=20260302T101010Z"));
        assert!(path.contains("versionId=v1%20%2F%20part"));
        assert!(
            path.find("X-Amz-Date").expect("query should contain date")
                < path
                    .find("versionId")
                    .expect("query should contain version"),
            "query parameters should be sorted"
        );
    }

    #[test]
    fn bucket_path_and_query_encodes_path_and_sorts_query_keys() {
        let mut params = HashMap::new();
        params.insert("delete".to_string(), String::new());
        params.insert("X-Amz-Date".to_string(), "20260302T101010Z".to_string());

        let path = bucket_path_and_query("my bucket", &params);
        assert!(path.starts_with("/my%20bucket?"));
        assert!(path.contains("X-Amz-Date=20260302T101010Z"));
        assert!(path.contains("delete="));
        assert!(
            path.find("X-Amz-Date").expect("query should contain date")
                < path.find("delete").expect("query should contain delete"),
            "query parameters should be sorted"
        );
    }

    #[tokio::test]
    async fn delete_objects_xml_response_sets_status_and_content_type() {
        let response = delete_objects_xml_response("<DeleteResult />".to_string())
            .expect("response should build");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/xml")
        );
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        assert_eq!(body.as_ref(), b"<DeleteResult />");
    }

    #[test]
    fn object_response_sets_common_headers_for_ok_response() {
        let meta = ObjectMeta {
            key: "docs/readme.txt".to_string(),
            size: 42,
            etag: "\"etag\"".to_string(),
            content_type: "text/plain".to_string(),
            last_modified: "2026-03-01T00:00:00Z".to_string(),
            version_id: Some("v1".to_string()),
            is_delete_marker: false,
            storage_format: None,
            checksum_algorithm: Some(ChecksumAlgorithm::SHA256),
            checksum_value: Some("checksum==".to_string()),
        };

        let response = object_response(&meta, StatusCode::OK, Body::empty(), meta.size, None)
            .expect("response should build");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok()),
            Some("42")
        );
        assert_eq!(
            response
                .headers()
                .get("x-amz-version-id")
                .and_then(|v| v.to_str().ok()),
            Some("v1")
        );
        assert_eq!(
            response
                .headers()
                .get("x-amz-checksum-sha256")
                .and_then(|v| v.to_str().ok()),
            Some("checksum==")
        );
        assert_eq!(
            response
                .headers()
                .get("accept-ranges")
                .and_then(|v| v.to_str().ok()),
            Some("bytes")
        );
    }

    #[test]
    fn object_response_sets_content_range_for_partial_response() {
        let meta = ObjectMeta {
            key: "docs/readme.txt".to_string(),
            size: 42,
            etag: "\"etag\"".to_string(),
            content_type: "text/plain".to_string(),
            last_modified: "2026-03-01T00:00:00Z".to_string(),
            version_id: None,
            is_delete_marker: false,
            storage_format: None,
            checksum_algorithm: None,
            checksum_value: None,
        };

        let response = object_response(
            &meta,
            StatusCode::PARTIAL_CONTENT,
            Body::empty(),
            10,
            Some((5, 14, 42)),
        )
        .expect("response should build");

        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            response
                .headers()
                .get("content-range")
                .and_then(|v| v.to_str().ok()),
            Some("bytes 5-14/42")
        );
        assert_eq!(
            response
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok()),
            Some("10")
        );
    }

    #[test]
    fn object_last_modified_unix_ms_parses_supported_formats() {
        let rfc3339 = object_last_modified_unix_ms("2026-03-03T12:34:56Z");
        assert!(rfc3339.is_some());

        let rfc2822 = object_last_modified_unix_ms("Tue, 03 Mar 2026 12:34:56 +0000");
        assert!(rfc2822.is_some());
    }

    #[test]
    fn object_last_modified_unix_ms_rejects_invalid_values() {
        assert!(object_last_modified_unix_ms("not-a-date").is_none());
        assert!(object_last_modified_unix_ms("").is_none());
    }

    async fn distributed_replay_test_state() -> (TempDir, AppState) {
        let temp_dir = TempDir::new().expect("tempdir should be creatable");
        let config = Config {
            port: 0,
            address: "127.0.0.1".to_string(),
            internal_bind_addr: None,
            data_dir: temp_dir.path().to_string_lossy().to_string(),
            access_key: "minioadmin".to_string(),
            secret_key: "minioadmin".to_string(),
            additional_credentials: Vec::new(),
            region: "us-east-1".to_string(),
            node_id: "node-a:9000".to_string(),
            cluster_peers: vec!["node-b:9000".to_string()],
            membership_protocol: MembershipProtocol::StaticBootstrap,
            write_durability_mode: WriteDurabilityMode::DegradedSuccess,
            metadata_listing_strategy: ClusterMetadataListingStrategy::LocalNodeOnly,
            cluster_auth_token: None,
            cluster_peer_tls_cert_path: None,
            cluster_peer_tls_key_path: None,
            cluster_peer_tls_ca_path: None,
            cluster_peer_tls_cert_sha256: None,
            cluster_peer_tls_cert_sha256_revocations: None,
            cluster_peer_transport_mode: ClusterPeerTransportMode::Compatibility,
            erasure_coding: false,
            chunk_size: 10 * 1024 * 1024,
            parity_shards: 0,
            min_disk_headroom_bytes: 0,
            pending_replication_due_warning_threshold: None,
            pending_rebalance_due_warning_threshold: None,
            pending_membership_propagation_due_warning_threshold: None,
            pending_metadata_repair_due_warning_threshold: None,
        };
        let state = AppState::from_config(config)
            .await
            .expect("app state should be creatable");
        let bucket = BucketMeta {
            name: "photos".to_string(),
            created_at: "2026-03-03T00:00:00.000Z".to_string(),
            region: "us-east-1".to_string(),
            versioning: false,
        };
        state
            .storage
            .create_bucket(&bucket)
            .await
            .expect("bucket create should succeed");
        (temp_dir, state)
    }

    fn persist_single_pending_replication_target(
        state: &AppState,
        idempotency_key: &str,
        operation: ReplicationMutationOperation,
        key: &str,
        target_node: &str,
        version_id: Option<&str>,
        created_at_unix_ms: u64,
    ) {
        let queue_path = pending_replication_queue_path(state.config.data_dir.as_str());
        let peers = state.active_cluster_peers();
        let placement = PlacementViewState::from_membership(
            state.placement_epoch(),
            state.node_id.as_ref(),
            peers.as_slice(),
        );
        let pending_operation = PendingReplicationOperation::new(
            idempotency_key,
            operation,
            "photos",
            key,
            version_id,
            state.node_id.as_ref(),
            &placement,
            &[target_node.to_string()],
            created_at_unix_ms,
        )
        .expect("pending operation should be created");
        let queue = PendingReplicationQueue {
            operations: vec![pending_operation],
        };
        persist_pending_replication_queue(queue_path.as_path(), &queue)
            .expect("queue should persist");
    }

    #[tokio::test]
    async fn replay_pending_replication_backlog_drops_stale_non_version_delete() {
        let (_temp_dir, state) = distributed_replay_test_state().await;
        state
            .storage
            .put_object(
                "photos",
                "docs/stale-delete.txt",
                "text/plain",
                Box::pin(std::io::Cursor::new(b"current-data".to_vec())),
                None,
            )
            .await
            .expect("seed object write should succeed");
        persist_single_pending_replication_target(
            &state,
            "replay-delete-stale",
            ReplicationMutationOperation::DeleteObject,
            "docs/stale-delete.txt",
            "node-b:9000",
            None,
            0,
        );

        let summary = replay_pending_replication_backlog_once(&state, 16, 30_000)
            .await
            .expect("replay cycle should succeed");
        assert_eq!(
            summary,
            PendingReplicationReplaySummary {
                scanned: 1,
                leased: 1,
                acknowledged: 1,
                failed: 0,
                skipped: 1,
            }
        );

        let queue_path = pending_replication_queue_path(state.config.data_dir.as_str());
        let queue =
            load_pending_replication_queue(queue_path.as_path()).expect("queue should load");
        assert!(queue.operations.is_empty());
    }

    #[tokio::test]
    async fn replay_pending_replication_backlog_drops_non_version_delete_when_timestamp_equals_current_object()
     {
        let (_temp_dir, state) = distributed_replay_test_state().await;
        state
            .storage
            .put_object(
                "photos",
                "docs/equal-timestamp-delete.txt",
                "text/plain",
                Box::pin(std::io::Cursor::new(b"current-data".to_vec())),
                None,
            )
            .await
            .expect("seed object write should succeed");
        let current_meta = state
            .storage
            .head_object("photos", "docs/equal-timestamp-delete.txt")
            .await
            .expect("seed object metadata should be readable");
        let current_last_modified_unix_ms =
            object_last_modified_unix_ms(current_meta.last_modified.as_str())
                .expect("seed object timestamp should parse");

        persist_single_pending_replication_target(
            &state,
            "replay-delete-equal-timestamp",
            ReplicationMutationOperation::DeleteObject,
            "docs/equal-timestamp-delete.txt",
            "node-b:9000",
            None,
            current_last_modified_unix_ms,
        );

        let summary = replay_pending_replication_backlog_once(&state, 16, 30_000)
            .await
            .expect("replay cycle should succeed");
        assert_eq!(
            summary,
            PendingReplicationReplaySummary {
                scanned: 1,
                leased: 1,
                acknowledged: 1,
                failed: 0,
                skipped: 1,
            }
        );

        let queue_path = pending_replication_queue_path(state.config.data_dir.as_str());
        let queue =
            load_pending_replication_queue(queue_path.as_path()).expect("queue should load");
        assert!(queue.operations.is_empty());
    }

    #[tokio::test]
    async fn replay_pending_replication_backlog_drops_put_when_source_object_is_missing() {
        let (_temp_dir, state) = distributed_replay_test_state().await;
        persist_single_pending_replication_target(
            &state,
            "replay-put-missing-source",
            ReplicationMutationOperation::PutObject,
            "docs/missing-source.txt",
            "node-b:9000",
            None,
            0,
        );

        let summary = replay_pending_replication_backlog_once(&state, 16, 30_000)
            .await
            .expect("replay cycle should succeed");
        assert_eq!(
            summary,
            PendingReplicationReplaySummary {
                scanned: 1,
                leased: 1,
                acknowledged: 1,
                failed: 0,
                skipped: 1,
            }
        );

        let queue_path = pending_replication_queue_path(state.config.data_dir.as_str());
        let queue =
            load_pending_replication_queue(queue_path.as_path()).expect("queue should load");
        assert!(queue.operations.is_empty());
    }

    fn find_key_with_target_owner_and_local_excluded(
        local_node_id: &str,
        peers: &[String],
        target_node: &str,
    ) -> String {
        let membership_count = peers.len().saturating_add(1);
        let replica_count = write_replica_count_for_membership_count(membership_count);
        for attempt in 0..10_000 {
            let key = format!("docs/replay-topology-shift-{attempt}.txt");
            let plan = crate::storage::placement::object_write_plan_with_self(
                &key,
                local_node_id,
                peers,
                replica_count,
            );
            let local_is_owner = plan.owners.iter().any(|owner| owner == local_node_id);
            let target_is_owner = plan.owners.iter().any(|owner| owner == target_node);
            if !local_is_owner && target_is_owner {
                return key;
            }
        }
        panic!("failed to find key where local node is excluded from owner set");
    }

    #[tokio::test]
    async fn replay_pending_replication_backlog_drops_when_local_node_is_no_longer_owner() {
        let (_temp_dir, state) = distributed_replay_test_state().await;
        let shifted_peers = vec!["node-b:9000".to_string(), "node-c:9000".to_string()];
        let key = find_key_with_target_owner_and_local_excluded(
            state.node_id.as_ref(),
            shifted_peers.as_slice(),
            "node-b:9000",
        );
        state
            .storage
            .put_object(
                "photos",
                key.as_str(),
                "text/plain",
                Box::pin(std::io::Cursor::new(b"replay-payload".to_vec())),
                None,
            )
            .await
            .expect("seed object write should succeed");
        persist_single_pending_replication_target(
            &state,
            "replay-local-not-owner",
            ReplicationMutationOperation::PutObject,
            key.as_str(),
            "node-b:9000",
            None,
            unix_ms_now(),
        );
        state
            .apply_membership_peers(shifted_peers)
            .await
            .expect("membership transition should succeed");

        let summary = replay_pending_replication_backlog_once(&state, 16, 30_000)
            .await
            .expect("replay cycle should succeed");
        assert_eq!(
            summary,
            PendingReplicationReplaySummary {
                scanned: 1,
                leased: 1,
                acknowledged: 1,
                failed: 0,
                skipped: 1,
            }
        );

        let queue_path = pending_replication_queue_path(state.config.data_dir.as_str());
        let queue =
            load_pending_replication_queue(queue_path.as_path()).expect("queue should load");
        assert!(queue.operations.is_empty());
    }

    #[test]
    fn pending_replication_replay_status_retry_policy_matches_contract() {
        assert!(pending_replication_replay_status_is_retryable(
            StatusCode::REQUEST_TIMEOUT
        ));
        assert!(pending_replication_replay_status_is_retryable(
            StatusCode::TOO_MANY_REQUESTS
        ));
        assert!(pending_replication_replay_status_is_retryable(
            StatusCode::SERVICE_UNAVAILABLE
        ));
        assert!(!pending_replication_replay_status_is_retryable(
            StatusCode::FORBIDDEN
        ));
        assert!(!pending_replication_replay_status_is_retryable(
            StatusCode::NOT_FOUND
        ));
    }
}
