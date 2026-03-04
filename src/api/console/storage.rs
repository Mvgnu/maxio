use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::Response;
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::path::{Component, Path};
use std::time::Duration;

use super::response;
use crate::api::object::peer_transport::{
    attest_internal_peer_target, build_internal_peer_http_client,
};
use crate::auth::signature_v4::{PresignRequest, generate_presigned_url};
use crate::cluster::authenticator::{FORWARDED_BY_HEADER, authenticate_forwarded_request};
use crate::cluster::security::INTERNAL_AUTH_TOKEN_HEADER;
use crate::metadata::{
    BucketMetadataOperation, BucketMetadataOperationError, BucketMetadataState,
    ClusterBucketMetadataConvergenceAssessment, ClusterBucketMetadataConvergenceInputError,
    ClusterBucketMetadataResponderState, ClusterMetadataListingStrategy, MetadataQuery,
    MetadataVersionsQuery, ObjectMetadataOperation, ObjectMetadataOperationError,
    ObjectMetadataState, ObjectVersionMetadataOperation, ObjectVersionMetadataOperationError,
    ObjectVersionMetadataState, PersistedBucketMetadataOperationError,
    PersistedBucketMetadataReadResolution, PersistedMetadataQueryError,
    PersistedObjectMetadataOperationError, PersistedObjectVersionMetadataOperationError,
    apply_bucket_metadata_operation_to_persisted_state,
    apply_object_metadata_operation_to_persisted_state,
    apply_object_version_metadata_operation_to_persisted_state,
    assess_cluster_bucket_metadata_convergence_for_responder_states,
    assess_cluster_metadata_snapshot_for_topology_responders,
    assess_cluster_metadata_snapshot_for_topology_single_responder,
    cluster_metadata_fan_in_execution_strategy, cluster_metadata_readiness_reject_reason,
    list_buckets_from_persisted_state_with_view_id, list_object_versions_page_from_persisted_state,
    list_objects_page_from_persisted_state, load_persisted_metadata_state,
    resolve_bucket_metadata_from_persisted_state,
};
use crate::server::{AppState, RuntimeTopologySnapshot, runtime_topology_snapshot};
use crate::storage::StorageError;

pub(super) const INTERNAL_METADATA_SCOPE_QUERY_PARAM: &str = "x-maxio-internal-metadata-scope";
pub(super) const INTERNAL_METADATA_SCOPE_LOCAL_ONLY: &str = "local-node-only";
const PERSISTED_METADATA_STATE_FILE: &str = "cluster-metadata-state.json";
const CONSENSUS_LISTING_PAGE_SIZE: usize = 1_000;
const PERSISTED_BUCKET_TOMBSTONE_RETENTION_MS: u64 = 5 * 60 * 1000;

pub(super) async fn ensure_bucket_exists(state: &AppState, bucket: &str) -> Result<(), Response> {
    match state.storage.head_bucket(bucket).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(bucket_not_found()),
        Err(err) => Err(internal_err(err)),
    }
}

pub(super) fn bucket_not_found() -> Response {
    response::error(StatusCode::NOT_FOUND, "Bucket not found")
}

pub(super) fn version_not_found() -> Response {
    response::error(StatusCode::NOT_FOUND, "Version not found")
}

pub(super) fn invalid_key(message: impl Into<String>) -> Response {
    response::error(StatusCode::BAD_REQUEST, message.into())
}

pub(super) fn internal_err(err: impl std::fmt::Display) -> Response {
    response::error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

pub(super) fn map_bucket_storage_err(err: StorageError) -> Response {
    match err {
        StorageError::NotFound(_) => bucket_not_found(),
        StorageError::InvalidKey(message) => invalid_key(message),
        other => internal_err(other),
    }
}

pub(super) fn map_version_delete_err(err: StorageError) -> Response {
    match err {
        StorageError::VersionNotFound(_) | StorageError::NotFound(_) => version_not_found(),
        StorageError::InvalidKey(message) => invalid_key(message),
        other => internal_err(other),
    }
}

pub(super) fn validate_list_prefix(prefix: &str) -> Option<Response> {
    if prefix.is_empty() {
        return None;
    }
    if prefix.len() > 1024 {
        return Some(invalid_key("Key must not exceed 1024 bytes"));
    }
    for component in Path::new(prefix).components() {
        match component {
            Component::ParentDir => {
                return Some(invalid_key("Key must not contain '..' path components"));
            }
            Component::RootDir => {
                return Some(invalid_key("Key must not be an absolute path"));
            }
            _ => {}
        }
    }
    None
}

pub(super) fn validate_list_delimiter(delimiter: &str) -> Option<Response> {
    if delimiter.is_empty() {
        return Some(invalid_key("Delimiter must not be empty"));
    }
    None
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MetadataCoverageDto {
    pub(super) complete: bool,
    pub(super) expected_nodes: usize,
    pub(super) responded_nodes: usize,
    pub(super) missing_nodes: usize,
    pub(super) unexpected_nodes: usize,
    pub(super) snapshot_id: String,
    pub(super) source: &'static str,
    pub(super) strategy_cluster_authoritative: bool,
    pub(super) strategy_ready: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) strategy_gap: Option<&'static str>,
    #[serde(skip)]
    pub(super) strategy_reject_reason: Option<&'static str>,
}

pub(super) fn list_metadata_coverage(state: &AppState) -> Option<MetadataCoverageDto> {
    let topology = runtime_topology_snapshot(state);
    let responder_nodes = [topology.node_id.clone()];
    list_metadata_coverage_for_responders(state, responder_nodes.as_slice())
}

pub(super) fn list_metadata_coverage_for_responders(
    state: &AppState,
    responder_nodes: &[String],
) -> Option<MetadataCoverageDto> {
    list_metadata_coverage_for_responders_with_execution_strategy(
        state,
        responder_nodes,
        state.metadata_listing_strategy,
    )
}

pub(super) fn list_metadata_coverage_for_responders_with_execution_strategy(
    state: &AppState,
    responder_nodes: &[String],
    execution_strategy: ClusterMetadataListingStrategy,
) -> Option<MetadataCoverageDto> {
    let topology = runtime_topology_snapshot(state);
    if !topology.is_distributed() {
        return None;
    }
    let snapshot_assessment = assess_cluster_metadata_snapshot_for_topology_responders(
        execution_strategy,
        Some(topology.membership_view_id.as_str()),
        topology.node_id.as_str(),
        topology.membership_nodes.as_slice(),
        responder_nodes,
    )
    .unwrap_or_else(|_| {
        assess_cluster_metadata_snapshot_for_topology_single_responder(
            execution_strategy,
            Some(topology.membership_view_id.as_str()),
            topology.node_id.as_str(),
            topology.membership_nodes.as_slice(),
            topology.node_id.as_str(),
        )
    });
    let strategy_assessment = snapshot_assessment.readiness_assessment;
    let coverage = snapshot_assessment.coverage;

    Some(MetadataCoverageDto {
        complete: coverage.complete,
        expected_nodes: coverage.expected_nodes.len(),
        responded_nodes: coverage.responded_nodes.len(),
        missing_nodes: coverage.missing_nodes.len(),
        unexpected_nodes: coverage.unexpected_nodes.len(),
        snapshot_id: snapshot_assessment.snapshot_id,
        source: state.metadata_listing_strategy.as_str(),
        strategy_cluster_authoritative: strategy_assessment.cluster_authoritative,
        strategy_ready: strategy_assessment.ready,
        strategy_gap: strategy_assessment.gap.map(|gap| gap.as_str()),
        strategy_reject_reason: cluster_metadata_readiness_reject_reason(&strategy_assessment)
            .map(|gap| gap.as_str()),
    })
}

pub(super) fn list_metadata_fan_in_coverage_for_responders(
    state: &AppState,
    responder_nodes: &[String],
) -> Option<MetadataCoverageDto> {
    list_metadata_coverage_for_responders_with_execution_strategy(
        state,
        responder_nodes,
        cluster_metadata_fan_in_execution_strategy(state.metadata_listing_strategy),
    )
}

pub(super) fn reject_unready_metadata_listing(
    metadata_coverage: Option<&MetadataCoverageDto>,
) -> Option<Response> {
    let coverage = metadata_coverage?;
    let reason = coverage.strategy_reject_reason?;
    let message =
        format!("Distributed metadata listing strategy is not ready for this request ({reason})");
    Some(response::error(StatusCode::SERVICE_UNAVAILABLE, message))
}

pub(super) fn reject_unready_bucket_metadata_operation(
    state: &AppState,
    operation: &str,
) -> Option<Response> {
    let topology = runtime_topology_snapshot(state);
    let responder_nodes = [topology.node_id.clone()];
    reject_unready_bucket_metadata_operation_for_responders(
        state,
        operation,
        responder_nodes.as_slice(),
    )
}

pub(super) fn reject_unready_bucket_metadata_operation_for_responders(
    state: &AppState,
    operation: &str,
    responder_nodes: &[String],
) -> Option<Response> {
    let metadata_coverage = list_metadata_coverage_for_responders(state, responder_nodes)?;
    let reason = metadata_coverage.strategy_reject_reason?;
    let message = format!(
        "Distributed metadata strategy is not ready for bucket metadata operation '{}' ({reason})",
        operation
    );
    Some(response::error(StatusCode::SERVICE_UNAVAILABLE, message))
}

pub(super) fn assess_bucket_metadata_operation_convergence<T: Clone + Eq>(
    state: &AppState,
    topology: &RuntimeTopologySnapshot,
    operation: &str,
    responded_nodes: &[String],
    states: &[ClusterBucketMetadataResponderState<T>],
) -> Result<ClusterBucketMetadataConvergenceAssessment<T>, String> {
    assess_cluster_bucket_metadata_convergence_for_responder_states(
        state.metadata_listing_strategy,
        Some(topology.membership_view_id.as_str()),
        topology.node_id.as_str(),
        topology.membership_nodes.as_slice(),
        responded_nodes,
        states,
    )
    .map_err(|error| match error {
        ClusterBucketMetadataConvergenceInputError::ResponderStateCardinalityMismatch => {
            format!(
                "Distributed bucket metadata operation '{}' responder/state fan-in cardinality mismatch",
                operation
            )
        }
        ClusterBucketMetadataConvergenceInputError::InvalidResponderTopology(_) => {
            format!(
                "Failed to assess distributed bucket metadata convergence for operation '{}'",
                operation
            )
        }
    })
}

pub(super) fn should_attempt_cluster_bucket_metadata_fan_in(
    state: &AppState,
    topology: &RuntimeTopologySnapshot,
    internal_local_only: bool,
) -> bool {
    if internal_local_only || !topology.is_distributed() {
        return false;
    }
    let Some(token) = state.config.cluster_auth_token() else {
        return false;
    };
    if token.trim().is_empty() {
        return false;
    }
    matches!(
        state.metadata_listing_strategy,
        ClusterMetadataListingStrategy::RequestTimeAggregation
            | ClusterMetadataListingStrategy::FullReplication
    )
}

pub(super) fn should_attempt_cluster_object_listing_fan_in(
    state: &AppState,
    topology: &RuntimeTopologySnapshot,
    internal_local_only: bool,
) -> bool {
    if internal_local_only || !topology.is_distributed() {
        return false;
    }
    let Some(token) = state.config.cluster_auth_token() else {
        return false;
    };
    if token.trim().is_empty() {
        return false;
    }
    matches!(
        state.metadata_listing_strategy,
        ClusterMetadataListingStrategy::RequestTimeAggregation
            | ClusterMetadataListingStrategy::ConsensusIndex
            | ClusterMetadataListingStrategy::FullReplication
    )
}

pub(super) fn reject_consensus_index_peer_fan_in_transport_unready(
    state: &AppState,
    topology: &RuntimeTopologySnapshot,
    internal_local_only: bool,
) -> Option<Response> {
    if internal_local_only
        || !topology.is_distributed()
        || state.metadata_listing_strategy != ClusterMetadataListingStrategy::ConsensusIndex
    {
        return None;
    }

    let has_cluster_auth_token = state
        .config
        .cluster_auth_token()
        .is_some_and(|value| !value.trim().is_empty());
    if has_cluster_auth_token {
        return None;
    }

    Some(response::error(
        StatusCode::SERVICE_UNAVAILABLE,
        "Distributed metadata listing strategy is not ready for this request (consensus-index-peer-fan-in-auth-token-missing)",
    ))
}

pub(super) fn should_use_consensus_index_bucket_metadata_state(
    state: &AppState,
    topology: &RuntimeTopologySnapshot,
    internal_local_only: bool,
) -> bool {
    !internal_local_only
        && topology.is_distributed()
        && state.metadata_listing_strategy == ClusterMetadataListingStrategy::ConsensusIndex
}

fn persisted_metadata_state_path(data_dir: &str) -> PathBuf {
    PathBuf::from(data_dir)
        .join(".maxio-runtime")
        .join(PERSISTED_METADATA_STATE_FILE)
}

pub(super) fn current_unix_ms_u64() -> u64 {
    u64::try_from(Utc::now().timestamp_millis()).map_or(0, |value| value)
}

pub(super) fn persisted_bucket_tombstone_retention_ms() -> u64 {
    PERSISTED_BUCKET_TOMBSTONE_RETENTION_MS
}

pub(super) fn persist_bucket_metadata_operation(
    state: &AppState,
    topology: &RuntimeTopologySnapshot,
    operation_name: &str,
    operation: &BucketMetadataOperation,
) -> Result<(), Box<Response>> {
    let state_path = persisted_metadata_state_path(state.config.data_dir.as_str());
    let apply_result = apply_bucket_metadata_operation_to_persisted_state(
        state_path.as_path(),
        topology.membership_view_id.as_str(),
        operation,
    );
    if matches!(
        (&apply_result, operation),
        (
            Err(PersistedBucketMetadataOperationError::Operation(
                BucketMetadataOperationError::BucketAlreadyExists
            )),
            BucketMetadataOperation::CreateBucket { .. }
        )
    ) {
        return Ok(());
    }

    apply_result.map(|_| ()).map_err(|error| {
        let message = match error {
            PersistedBucketMetadataOperationError::InvalidExpectedViewId => format!(
                "Distributed bucket metadata operation '{}' cannot update persisted metadata state: invalid expected metadata view id",
                operation_name
            ),
            PersistedBucketMetadataOperationError::StateLoad(io_error) => format!(
                "Distributed bucket metadata operation '{}' cannot load persisted metadata state: {}",
                operation_name, io_error
            ),
            PersistedBucketMetadataOperationError::StatePersist(io_error) => format!(
                "Distributed bucket metadata operation '{}' cannot persist metadata state: {}",
                operation_name, io_error
            ),
            PersistedBucketMetadataOperationError::ViewIdMismatch {
                expected_view_id,
                persisted_view_id,
            } => format!(
                "Distributed bucket metadata operation '{}' cannot update persisted metadata state: persisted metadata view mismatch (expected='{}', persisted='{}')",
                operation_name, expected_view_id, persisted_view_id
            ),
            PersistedBucketMetadataOperationError::InvalidPersistedState(reason) => format!(
                "Distributed bucket metadata operation '{}' cannot update persisted metadata state: invalid persisted metadata state ({:?})",
                operation_name, reason
            ),
            PersistedBucketMetadataOperationError::Operation(reason) => format!(
                "Distributed bucket metadata operation '{}' cannot update persisted metadata state: {}",
                operation_name,
                reason.as_str()
            ),
        };
        Box::new(response::error(StatusCode::SERVICE_UNAVAILABLE, message))
    })
}

fn should_persist_consensus_object_metadata(
    state: &AppState,
    topology: &RuntimeTopologySnapshot,
) -> bool {
    topology.is_distributed()
        && state.metadata_listing_strategy == ClusterMetadataListingStrategy::ConsensusIndex
}

pub(super) fn persist_object_metadata_operation(
    state: &AppState,
    topology: &RuntimeTopologySnapshot,
    operation_name: &str,
    operation: &ObjectMetadataOperation,
) -> Result<(), Box<Response>> {
    if !should_persist_consensus_object_metadata(state, topology) {
        return Ok(());
    }

    let state_path = persisted_metadata_state_path(state.config.data_dir.as_str());
    let apply_result = apply_object_metadata_operation_to_persisted_state(
        state_path.as_path(),
        topology.membership_view_id.as_str(),
        operation,
    );
    if matches!(
        (&apply_result, operation),
        (
            Err(PersistedObjectMetadataOperationError::Operation(
                ObjectMetadataOperationError::ObjectNotFound
            )),
            ObjectMetadataOperation::DeleteCurrent { .. }
        )
    ) {
        return Ok(());
    }

    apply_result.map(|_| ()).map_err(|error| {
        let message = match error {
            PersistedObjectMetadataOperationError::InvalidExpectedViewId => format!(
                "Distributed object metadata operation '{}' cannot update persisted metadata state: invalid expected metadata view id",
                operation_name
            ),
            PersistedObjectMetadataOperationError::StateLoad(io_error) => format!(
                "Distributed object metadata operation '{}' cannot load persisted metadata state: {}",
                operation_name, io_error
            ),
            PersistedObjectMetadataOperationError::StatePersist(io_error) => format!(
                "Distributed object metadata operation '{}' cannot persist metadata state: {}",
                operation_name, io_error
            ),
            PersistedObjectMetadataOperationError::ViewIdMismatch {
                expected_view_id,
                persisted_view_id,
            } => format!(
                "Distributed object metadata operation '{}' cannot update persisted metadata state: persisted metadata view mismatch (expected='{}', persisted='{}')",
                operation_name, expected_view_id, persisted_view_id
            ),
            PersistedObjectMetadataOperationError::InvalidPersistedState(reason) => format!(
                "Distributed object metadata operation '{}' cannot update persisted metadata state: invalid persisted metadata state ({:?})",
                operation_name, reason
            ),
            PersistedObjectMetadataOperationError::Operation(reason) => format!(
                "Distributed object metadata operation '{}' cannot update persisted metadata state: {}",
                operation_name,
                reason.as_str()
            ),
        };
        Box::new(response::error(StatusCode::SERVICE_UNAVAILABLE, message))
    })
}

pub(super) fn persist_object_version_metadata_operation(
    state: &AppState,
    topology: &RuntimeTopologySnapshot,
    operation_name: &str,
    operation: &ObjectVersionMetadataOperation,
) -> Result<(), Box<Response>> {
    if !should_persist_consensus_object_metadata(state, topology) {
        return Ok(());
    }

    let state_path = persisted_metadata_state_path(state.config.data_dir.as_str());
    let apply_result = apply_object_version_metadata_operation_to_persisted_state(
        state_path.as_path(),
        topology.membership_view_id.as_str(),
        operation,
    );
    if matches!(
        (&apply_result, operation),
        (
            Err(PersistedObjectVersionMetadataOperationError::Operation(
                ObjectVersionMetadataOperationError::VersionNotFound
            )),
            ObjectVersionMetadataOperation::DeleteVersion { .. }
        )
    ) {
        return Ok(());
    }

    apply_result.map(|_| ()).map_err(|error| {
        let message = match error {
            PersistedObjectVersionMetadataOperationError::InvalidExpectedViewId => format!(
                "Distributed object-version metadata operation '{}' cannot update persisted metadata state: invalid expected metadata view id",
                operation_name
            ),
            PersistedObjectVersionMetadataOperationError::StateLoad(io_error) => format!(
                "Distributed object-version metadata operation '{}' cannot load persisted metadata state: {}",
                operation_name, io_error
            ),
            PersistedObjectVersionMetadataOperationError::StatePersist(io_error) => format!(
                "Distributed object-version metadata operation '{}' cannot persist metadata state: {}",
                operation_name, io_error
            ),
            PersistedObjectVersionMetadataOperationError::ViewIdMismatch {
                expected_view_id,
                persisted_view_id,
            } => format!(
                "Distributed object-version metadata operation '{}' cannot update persisted metadata state: persisted metadata view mismatch (expected='{}', persisted='{}')",
                operation_name, expected_view_id, persisted_view_id
            ),
            PersistedObjectVersionMetadataOperationError::InvalidPersistedState(reason) => format!(
                "Distributed object-version metadata operation '{}' cannot update persisted metadata state: invalid persisted metadata state ({:?})",
                operation_name, reason
            ),
            PersistedObjectVersionMetadataOperationError::Operation(reason) => format!(
                "Distributed object-version metadata operation '{}' cannot update persisted metadata state: {}",
                operation_name,
                reason.as_str()
            ),
        };
        Box::new(response::error(StatusCode::SERVICE_UNAVAILABLE, message))
    })
}

pub(super) fn persist_current_object_metadata_state(
    state: &AppState,
    topology: &RuntimeTopologySnapshot,
    bucket: &str,
    key: &str,
    latest_version_id: Option<&str>,
    is_delete_marker: bool,
) -> Result<(), Box<Response>> {
    persist_object_metadata_operation(
        state,
        topology,
        "UpsertObjectCurrent",
        &ObjectMetadataOperation::UpsertCurrent {
            bucket: bucket.to_string(),
            key: key.to_string(),
            latest_version_id: latest_version_id.map(ToOwned::to_owned),
            is_delete_marker,
        },
    )?;

    if let Some(version_id) = latest_version_id {
        persist_object_version_metadata_operation(
            state,
            topology,
            "UpsertObjectVersion",
            &ObjectVersionMetadataOperation::UpsertVersion {
                bucket: bucket.to_string(),
                key: key.to_string(),
                version_id: version_id.to_string(),
                is_delete_marker,
                is_latest: true,
            },
        )?;
    }

    Ok(())
}

pub(super) fn persist_deleted_current_object_metadata_state(
    state: &AppState,
    topology: &RuntimeTopologySnapshot,
    bucket: &str,
    key: &str,
) -> Result<(), Box<Response>> {
    persist_object_metadata_operation(
        state,
        topology,
        "DeleteObjectCurrent",
        &ObjectMetadataOperation::DeleteCurrent {
            bucket: bucket.to_string(),
            key: key.to_string(),
        },
    )
}

pub(super) async fn persist_object_metadata_after_version_delete(
    state: &AppState,
    topology: &RuntimeTopologySnapshot,
    bucket: &str,
    key: &str,
    deleted_version_id: &str,
) -> Result<(), Box<Response>> {
    persist_object_version_metadata_operation(
        state,
        topology,
        "DeleteObjectVersion",
        &ObjectVersionMetadataOperation::DeleteVersion {
            bucket: bucket.to_string(),
            key: key.to_string(),
            version_id: deleted_version_id.to_string(),
        },
    )?;

    match state.storage.head_object(bucket, key).await {
        Ok(meta) => persist_current_object_metadata_state(
            state,
            topology,
            bucket,
            key,
            meta.version_id.as_deref(),
            meta.is_delete_marker,
        ),
        Err(StorageError::NotFound(_)) => {
            persist_deleted_current_object_metadata_state(state, topology, bucket, key)
        }
        Err(err) => Err(Box::new(response::error(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "Distributed object metadata operation 'DeleteObjectVersion' cannot refresh persisted metadata state from storage: {}",
                err
            ),
        ))),
    }
}

pub(super) fn load_consensus_bucket_metadata_rows(
    state: &AppState,
    topology: &RuntimeTopologySnapshot,
    operation: &str,
) -> Result<Vec<BucketMetadataState>, Box<Response>> {
    let state_path = persisted_metadata_state_path(state.config.data_dir.as_str());
    let persisted_state = load_persisted_metadata_state(state_path.as_path()).map_err(|err| {
        Box::new(response::error(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "Distributed bucket metadata operation '{}' cannot load consensus metadata state: {}",
                operation, err
            ),
        ))
    })?;
    list_buckets_from_persisted_state_with_view_id(
        &persisted_state,
        Some(topology.membership_view_id.as_str()),
    )
    .map_err(|err| match err {
        PersistedMetadataQueryError::ViewIdMismatch {
            expected_view_id,
            persisted_view_id,
        } => Box::new(response::error(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "Distributed bucket metadata operation '{}' cannot query consensus metadata state: persisted metadata view mismatch (expected='{}', persisted='{}')",
                operation, expected_view_id, persisted_view_id
            ),
        )),
        _ => Box::new(response::error(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "Distributed bucket metadata operation '{}' cannot query consensus metadata state: {:?}",
                operation, err
            ),
        )),
    })
}

pub(super) fn load_consensus_object_metadata_rows_for_prefix(
    state: &AppState,
    topology: &RuntimeTopologySnapshot,
    bucket: &str,
    prefix: &str,
    operation: &str,
) -> Result<Vec<ObjectMetadataState>, Box<Response>> {
    let state_path = persisted_metadata_state_path(state.config.data_dir.as_str());
    let persisted_state = load_persisted_metadata_state(state_path.as_path()).map_err(|err| {
        Box::new(response::error(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "Distributed metadata listing operation '{}' cannot load consensus metadata state: {}",
                operation, err
            ),
        ))
    })?;

    let mut query = MetadataQuery::new(bucket);
    if !prefix.is_empty() {
        query.prefix = Some(prefix.to_string());
    }
    query.view_id = Some(topology.membership_view_id.clone());
    query.max_keys = CONSENSUS_LISTING_PAGE_SIZE;

    let mut rows = Vec::new();
    let mut seen_tokens = HashSet::<String>::new();

    loop {
        let page = list_objects_page_from_persisted_state(&persisted_state, &query)
            .map_err(|err| map_persisted_metadata_query_error(operation, err))?;
        rows.extend(page.objects);

        if !page.is_truncated {
            break;
        }

        let token = page
            .next_continuation_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                Box::new(response::error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!(
                        "Distributed metadata listing operation '{}' cannot query consensus metadata state: truncated page missing continuation token",
                        operation
                    ),
                ))
            })?;
        if !seen_tokens.insert(token.clone()) {
            return Err(Box::new(response::error(
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "Distributed metadata listing operation '{}' cannot query consensus metadata state: continuation loop detected",
                    operation
                ),
            )));
        }
        query.continuation_token = Some(token);
    }

    Ok(rows)
}

pub(super) fn load_consensus_object_version_metadata_rows_for_prefix(
    state: &AppState,
    topology: &RuntimeTopologySnapshot,
    bucket: &str,
    prefix: &str,
    operation: &str,
) -> Result<Vec<ObjectVersionMetadataState>, Box<Response>> {
    let state_path = persisted_metadata_state_path(state.config.data_dir.as_str());
    let persisted_state = load_persisted_metadata_state(state_path.as_path()).map_err(|err| {
        Box::new(response::error(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "Distributed metadata listing operation '{}' cannot load consensus metadata state: {}",
                operation, err
            ),
        ))
    })?;

    let mut query = MetadataVersionsQuery::new(bucket);
    if !prefix.is_empty() {
        query.prefix = Some(prefix.to_string());
    }
    query.view_id = Some(topology.membership_view_id.clone());
    query.max_keys = CONSENSUS_LISTING_PAGE_SIZE;

    let mut rows = Vec::new();
    let mut seen_tokens = HashSet::<String>::new();

    loop {
        let page = list_object_versions_page_from_persisted_state(&persisted_state, &query)
            .map_err(|err| map_persisted_metadata_query_error(operation, err))?;
        rows.extend(page.versions);

        if !page.is_truncated {
            break;
        }

        let token = page
            .next_continuation_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                Box::new(response::error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!(
                        "Distributed metadata listing operation '{}' cannot query consensus metadata state: truncated page missing continuation token",
                        operation
                    ),
                ))
            })?;
        if !seen_tokens.insert(token.clone()) {
            return Err(Box::new(response::error(
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "Distributed metadata listing operation '{}' cannot query consensus metadata state: continuation loop detected",
                    operation
                ),
            )));
        }
        query.continuation_token = Some(token);
    }

    Ok(rows)
}

pub(super) fn consensus_bucket_metadata_state_for_bucket(
    state: &AppState,
    topology: &RuntimeTopologySnapshot,
    bucket: &str,
    operation: &str,
) -> Result<BucketMetadataState, Box<Response>> {
    let state_path = persisted_metadata_state_path(state.config.data_dir.as_str());
    let persisted_state = load_persisted_metadata_state(state_path.as_path()).map_err(|err| {
        Box::new(response::error(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "Distributed bucket metadata operation '{}' cannot load consensus metadata state: {}",
                operation, err
            ),
        ))
    })?;

    match resolve_bucket_metadata_from_persisted_state(
        &persisted_state,
        bucket,
        Some(topology.membership_view_id.as_str()),
    ) {
        Ok(PersistedBucketMetadataReadResolution::Present(bucket_state)) => Ok(bucket_state),
        Ok(PersistedBucketMetadataReadResolution::Missing) => Err(Box::new(bucket_not_found())),
        Err(PersistedMetadataQueryError::ViewIdMismatch {
            expected_view_id,
            persisted_view_id,
        }) => Err(Box::new(response::error(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "Distributed bucket metadata operation '{}' cannot query consensus metadata state: persisted metadata view mismatch (expected='{}', persisted='{}')",
                operation, expected_view_id, persisted_view_id
            ),
        ))),
        Err(err) => Err(Box::new(response::error(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "Distributed bucket metadata operation '{}' cannot query consensus metadata state: {:?}",
                operation, err
            ),
        ))),
    }
}

fn map_persisted_metadata_query_error(
    operation: &str,
    err: PersistedMetadataQueryError,
) -> Box<Response> {
    match err {
        PersistedMetadataQueryError::ViewIdMismatch {
            expected_view_id,
            persisted_view_id,
        } => Box::new(response::error(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "Distributed metadata listing operation '{}' cannot query consensus metadata state: persisted metadata view mismatch (expected='{}', persisted='{}')",
                operation, expected_view_id, persisted_view_id
            ),
        )),
        _ => Box::new(response::error(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "Distributed metadata listing operation '{}' cannot query consensus metadata state: {:?}",
                operation, err
            ),
        )),
    }
}

pub(super) fn is_trusted_internal_local_metadata_scope_request(
    state: &AppState,
    headers: &HeaderMap,
    params: &HashMap<String, String>,
) -> bool {
    let Some(scope) = params.get(INTERNAL_METADATA_SCOPE_QUERY_PARAM) else {
        return false;
    };
    if scope != INTERNAL_METADATA_SCOPE_LOCAL_ONLY {
        return false;
    }

    let active_cluster_peers = state.active_cluster_peers();
    let auth_result = authenticate_forwarded_request(
        headers,
        FORWARDED_BY_HEADER,
        state.config.cluster_auth_token(),
        state.node_id.as_ref(),
        active_cluster_peers.as_slice(),
    );
    auth_result.trusted
}

pub(super) async fn send_internal_peer_get(
    state: &AppState,
    peer: &str,
    path: &str,
    extra_query_params: &[(&str, &str)],
) -> Result<reqwest::Response, String> {
    send_internal_peer_request(state, peer, Method::GET, path, extra_query_params, None).await
}

pub(super) async fn send_internal_peer_request(
    state: &AppState,
    peer: &str,
    method: Method,
    path: &str,
    extra_query_params: &[(&str, &str)],
    body: Option<Vec<u8>>,
) -> Result<reqwest::Response, String> {
    attest_internal_peer_target(state, peer, Duration::from_secs(2)).map_err(|err| err.message)?;
    let transport = build_internal_peer_http_client(
        state,
        Some(Duration::from_secs(2)),
        Duration::from_secs(10),
    )
    .map_err(|err| err.message)?;
    let presigned_url = generate_presigned_url(PresignRequest {
        method: method.as_str(),
        scheme: transport.scheme,
        host: peer,
        path,
        extra_query_params,
        access_key: state.config.access_key.as_str(),
        secret_key: state.config.secret_key.as_str(),
        region: state.config.region.as_str(),
        now: Utc::now(),
        expires_secs: 30,
    })
    .map_err(|err| err.to_string())?;

    let mut request = transport
        .client
        .request(method, presigned_url)
        .header(FORWARDED_BY_HEADER, state.node_id.as_ref());
    if let Some(token) = state
        .config
        .cluster_auth_token()
        .filter(|token| !token.trim().is_empty())
    {
        request = request.header(INTERNAL_AUTH_TOKEN_HEADER, token);
    }
    if let Some(payload) = body {
        request = request.body(payload);
    }

    request.send().await.map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, MembershipProtocol, WriteDurabilityMode};
    use crate::metadata::ClusterMetadataListingStrategy;
    use crate::server::AppState;
    use tempfile::TempDir;

    fn test_config(data_dir: String) -> Config {
        Config {
            port: 9000,
            address: "127.0.0.1".to_string(),
            internal_bind_addr: None,
            data_dir,
            access_key: "admin".to_string(),
            secret_key: "password".to_string(),
            additional_credentials: Vec::new(),
            region: "us-east-1".to_string(),
            node_id: "node-a.internal:9000".to_string(),
            cluster_peers: Vec::new(),
            membership_protocol: MembershipProtocol::StaticBootstrap,
            write_durability_mode: WriteDurabilityMode::DegradedSuccess,
            metadata_listing_strategy: ClusterMetadataListingStrategy::LocalNodeOnly,
            cluster_auth_token: None,
            cluster_peer_tls_cert_path: None,
            cluster_peer_tls_key_path: None,
            cluster_peer_tls_ca_path: None,
            cluster_peer_tls_cert_sha256: None,
            erasure_coding: false,
            chunk_size: 10 * 1024 * 1024,
            parity_shards: 0,
            min_disk_headroom_bytes: 0,
        }
    }

    fn response_status(response: Response) -> StatusCode {
        response.status()
    }

    #[test]
    fn map_bucket_storage_err_maps_not_found_to_404() {
        let status = response_status(map_bucket_storage_err(StorageError::NotFound(
            "bucket".to_string(),
        )));
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn map_bucket_storage_err_maps_invalid_key_to_400() {
        let status = response_status(map_bucket_storage_err(StorageError::InvalidKey(
            "bad".to_string(),
        )));
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn map_bucket_storage_err_maps_internal_errors_to_500() {
        let status = response_status(map_bucket_storage_err(StorageError::Io(
            std::io::Error::other("io"),
        )));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn map_version_delete_err_maps_not_found_to_404() {
        let status = response_status(map_version_delete_err(StorageError::VersionNotFound(
            "missing".to_string(),
        )));
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn map_version_delete_err_maps_invalid_key_to_400() {
        let status = response_status(map_version_delete_err(StorageError::InvalidKey(
            "bad".to_string(),
        )));
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn map_version_delete_err_maps_internal_errors_to_500() {
        let status = response_status(map_version_delete_err(StorageError::Io(
            std::io::Error::other("io"),
        )));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn validate_list_prefix_rejects_parent_dir_and_absolute_prefixes() {
        assert!(validate_list_prefix("../escape").is_some());
        assert!(validate_list_prefix("/absolute").is_some());
        assert!(validate_list_prefix(&"a".repeat(1025)).is_some());
    }

    #[test]
    fn validate_list_prefix_accepts_empty_and_regular_prefixes() {
        assert!(validate_list_prefix("").is_none());
        assert!(validate_list_prefix("docs/").is_none());
    }

    #[test]
    fn validate_list_delimiter_rejects_empty_values() {
        assert!(validate_list_delimiter("").is_some());
        assert!(validate_list_delimiter("/").is_none());
    }

    #[tokio::test]
    async fn list_metadata_coverage_none_for_standalone() {
        let tmp = TempDir::new().expect("tempdir");
        let data_dir = tmp.path().to_string_lossy().to_string();
        let config = test_config(data_dir);

        let state = AppState::from_config(config)
            .await
            .expect("state should initialize");
        assert!(list_metadata_coverage(&state).is_none());
    }

    #[tokio::test]
    async fn list_metadata_coverage_reports_distributed_partial_fan_in() {
        let tmp = TempDir::new().expect("tempdir");
        let data_dir = tmp.path().to_string_lossy().to_string();
        let mut config = test_config(data_dir);
        config.node_id = "node-a.internal:9000".to_string();
        config.cluster_peers = vec!["node-b.internal:9000".to_string()];
        config.membership_protocol = MembershipProtocol::StaticBootstrap;

        let state = AppState::from_config(config)
            .await
            .expect("state should initialize");
        let coverage =
            list_metadata_coverage(&state).expect("distributed state should expose coverage");
        assert_eq!(coverage.expected_nodes, 1);
        assert_eq!(coverage.responded_nodes, 1);
        assert_eq!(coverage.missing_nodes, 0);
        assert!(coverage.complete);
        assert_eq!(coverage.snapshot_id.len(), 64);
        assert_eq!(coverage.source, "local-node-only");
        assert!(!coverage.strategy_cluster_authoritative);
        assert!(!coverage.strategy_ready);
        assert_eq!(
            coverage.strategy_gap,
            Some("strategy-not-cluster-authoritative")
        );
        assert_eq!(coverage.strategy_reject_reason, None);
    }

    #[tokio::test]
    async fn list_metadata_coverage_reports_strategy_readiness_for_consensus_index() {
        let tmp = TempDir::new().expect("tempdir");
        let data_dir = tmp.path().to_string_lossy().to_string();
        let mut config = test_config(data_dir);
        config.node_id = "node-a.internal:9000".to_string();
        config.cluster_peers = vec!["node-b.internal:9000".to_string()];
        config.membership_protocol = MembershipProtocol::StaticBootstrap;
        config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;

        let state = AppState::from_config(config)
            .await
            .expect("state should initialize");
        let coverage =
            list_metadata_coverage(&state).expect("distributed state should expose coverage");
        assert_eq!(coverage.expected_nodes, 2);
        assert_eq!(coverage.responded_nodes, 1);
        assert_eq!(coverage.missing_nodes, 1);
        assert!(!coverage.complete);
        assert_eq!(coverage.snapshot_id.len(), 64);
        assert_eq!(coverage.source, "consensus-index");
        assert!(coverage.strategy_cluster_authoritative);
        assert!(!coverage.strategy_ready);
        assert_eq!(coverage.strategy_gap, Some("missing-expected-nodes"));
        assert_eq!(
            coverage.strategy_reject_reason,
            Some("missing-expected-nodes")
        );
    }

    #[tokio::test]
    async fn list_metadata_coverage_for_consensus_fallback_uses_cluster_execution_readiness() {
        let tmp = TempDir::new().expect("tempdir");
        let data_dir = tmp.path().to_string_lossy().to_string();
        let mut config = test_config(data_dir);
        config.node_id = "node-a.internal:9000".to_string();
        config.cluster_peers = vec!["node-b.internal:9000".to_string()];
        config.membership_protocol = MembershipProtocol::StaticBootstrap;
        config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
        config.cluster_auth_token = Some("shared-token".to_string());

        let state = AppState::from_config(config)
            .await
            .expect("state should initialize");
        let responders = vec![
            "node-a.internal:9000".to_string(),
            "node-b.internal:9000".to_string(),
        ];
        let coverage = list_metadata_fan_in_coverage_for_responders(&state, responders.as_slice())
            .expect("distributed state should expose coverage");
        assert_eq!(coverage.expected_nodes, 2);
        assert_eq!(coverage.responded_nodes, 2);
        assert_eq!(coverage.missing_nodes, 0);
        assert_eq!(coverage.unexpected_nodes, 0);
        assert!(coverage.complete);
        assert_eq!(coverage.source, "consensus-index");
        assert!(coverage.strategy_cluster_authoritative);
        assert!(coverage.strategy_ready);
        assert_eq!(coverage.strategy_gap, None);
        assert_eq!(coverage.strategy_reject_reason, None);
    }

    #[test]
    fn reject_unready_metadata_listing_is_noop_for_non_rejecting_coverage() {
        let coverage = MetadataCoverageDto {
            complete: false,
            expected_nodes: 2,
            responded_nodes: 1,
            missing_nodes: 1,
            unexpected_nodes: 0,
            snapshot_id: "snapshot-local".to_string(),
            source: "local-node-only",
            strategy_cluster_authoritative: false,
            strategy_ready: false,
            strategy_gap: Some("strategy-not-cluster-authoritative"),
            strategy_reject_reason: None,
        };

        assert!(reject_unready_metadata_listing(Some(&coverage)).is_none());
    }

    #[test]
    fn reject_unready_metadata_listing_returns_503_for_authoritative_unready_modes() {
        let coverage = MetadataCoverageDto {
            complete: false,
            expected_nodes: 2,
            responded_nodes: 1,
            missing_nodes: 1,
            unexpected_nodes: 0,
            snapshot_id: "snapshot-aggregation".to_string(),
            source: "request-time-aggregation",
            strategy_cluster_authoritative: true,
            strategy_ready: false,
            strategy_gap: Some("missing-expected-nodes"),
            strategy_reject_reason: Some("missing-expected-nodes"),
        };

        let response = reject_unready_metadata_listing(Some(&coverage))
            .expect("authoritative unready coverage should reject");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn reject_consensus_index_peer_fan_in_transport_unready_returns_503_when_token_missing() {
        let tmp = TempDir::new().expect("tempdir");
        let data_dir = tmp.path().to_string_lossy().to_string();
        let mut config = test_config(data_dir);
        config.node_id = "node-a.internal:9000".to_string();
        config.cluster_peers = vec!["node-b.internal:9000".to_string()];
        config.membership_protocol = MembershipProtocol::StaticBootstrap;
        config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
        config.cluster_auth_token = None;

        let state = AppState::from_config(config)
            .await
            .expect("state should initialize");
        let topology = runtime_topology_snapshot(&state);
        let response =
            reject_consensus_index_peer_fan_in_transport_unready(&state, &topology, false)
                .expect("consensus listing should fail closed when token missing");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
