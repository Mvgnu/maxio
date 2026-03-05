use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use quick_xml::de::from_str;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::api::console::objects::sanitize_filename;
use crate::api::console::response;
use crate::api::console::storage;
use crate::metadata::{
    BucketMetadataOperation, ClusterBucketMetadataMutationPreconditionFailureDisposition,
    ClusterBucketMetadataMutationPreconditionGap, ClusterBucketMetadataResponderState,
    ClusterMetadataListingStrategy, ClusterResponderMembershipView, ObjectVersionMetadataState,
    cluster_bucket_metadata_mutation_precondition_gap_is_no_responder_values,
    cluster_bucket_metadata_mutation_precondition_gap_is_strategy_unready,
    cluster_bucket_metadata_mutation_precondition_reject_details,
};
use crate::server::{AppState, runtime_topology_snapshot};
use crate::storage::{ObjectMeta, StorageError};

#[derive(Debug, Serialize)]
struct VersioningResponse {
    enabled: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VersionSummary {
    version_id: Option<String>,
    last_modified: String,
    size: u64,
    etag: String,
    is_delete_marker: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ListVersionsResponse {
    versions: Vec<VersionSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata_coverage: Option<storage::MetadataCoverageDto>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename = "VersioningConfiguration")]
struct PeerVersioningConfiguration {
    #[serde(rename = "Status")]
    status: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename = "Error")]
struct PeerErrorResponse {
    #[serde(rename = "Code")]
    code: Option<String>,
}

struct ClusterBucketVersioningFanIn {
    responded_nodes: Vec<String>,
    versioning_states: Vec<ClusterBucketMetadataResponderState<bool>>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename = "ListVersionsResult")]
struct PeerListVersionsResult {
    #[serde(rename = "IsTruncated")]
    is_truncated: bool,
    #[serde(rename = "NextKeyMarker")]
    next_key_marker: Option<String>,
    #[serde(rename = "NextVersionIdMarker")]
    next_version_id_marker: Option<String>,
    #[serde(rename = "Version", default)]
    versions: Vec<PeerVersionEntry>,
    #[serde(rename = "DeleteMarker", default)]
    delete_markers: Vec<PeerDeleteMarkerEntry>,
}

#[derive(Debug, serde::Deserialize)]
struct PeerVersionEntry {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "VersionId")]
    version_id: Option<String>,
    #[serde(rename = "LastModified")]
    last_modified: String,
    #[serde(rename = "ETag")]
    etag: String,
    #[serde(rename = "Size")]
    size: u64,
}

#[derive(Debug, serde::Deserialize)]
struct PeerDeleteMarkerEntry {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "VersionId")]
    version_id: Option<String>,
    #[serde(rename = "LastModified")]
    last_modified: String,
}

struct ClusterObjectVersionListingFanIn {
    responded_nodes: Vec<String>,
    responder_membership_views: Vec<ClusterResponderMembershipView>,
    versions: Vec<ObjectMeta>,
}

struct PeerObjectVersionsFanInResult {
    membership_view_id: String,
    versions: Vec<ObjectMeta>,
}

pub(super) async fn get_versioning(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let topology = runtime_topology_snapshot(&state);
    let internal_local_only =
        storage::is_trusted_internal_local_metadata_scope_request(&state, &headers, &params);
    let use_consensus_bucket_metadata = storage::should_use_consensus_index_bucket_metadata_state(
        &state,
        &topology,
        internal_local_only,
    );
    let should_fan_in = storage::should_attempt_cluster_bucket_metadata_fan_in(
        &state,
        &topology,
        internal_local_only,
    );
    if should_fan_in
        && let Some(resp) = storage::reject_cluster_authoritative_peer_fan_in_transport_unready(
            &state,
            &topology,
            internal_local_only,
        )
    {
        return resp;
    }

    let enabled = if should_fan_in {
        let fan_in = match fetch_cluster_bucket_versioning_fan_in(&state, &topology, &bucket).await
        {
            Ok(fan_in) => fan_in,
            Err(err) => return storage::map_bucket_storage_err(err),
        };
        if let Some(err) = storage::reject_unready_bucket_metadata_operation_for_responders(
            &state,
            "GetBucketVersioning",
            fan_in.responded_nodes.as_slice(),
        ) {
            return err;
        }
        match resolve_cluster_bucket_versioning_state(
            &state,
            &topology,
            "GetBucketVersioning",
            &bucket,
            fan_in.responded_nodes.as_slice(),
            fan_in.versioning_states.as_slice(),
        ) {
            Ok(enabled) => enabled,
            Err(err) => return response::error(StatusCode::SERVICE_UNAVAILABLE, err),
        }
    } else {
        if !internal_local_only
            && !use_consensus_bucket_metadata
            && let Some(err) =
                storage::reject_unready_bucket_metadata_operation(&state, "GetBucketVersioning")
        {
            return err;
        }
        if use_consensus_bucket_metadata {
            match storage::consensus_bucket_metadata_state_for_bucket(
                &state,
                &topology,
                &bucket,
                "GetBucketVersioning",
            ) {
                Ok(bucket_state) => bucket_state.versioning_enabled,
                Err(err) => return *err,
            }
        } else {
            match state.storage.is_versioned(&bucket).await {
                Ok(enabled) => enabled,
                Err(err) => return storage::map_bucket_storage_err(err),
            }
        }
    };

    response::json(StatusCode::OK, VersioningResponse { enabled })
}

async fn fetch_cluster_bucket_versioning_fan_in(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    bucket: &str,
) -> Result<ClusterBucketVersioningFanIn, StorageError> {
    let local_versioned = state.storage.is_versioned(bucket).await?;
    let mut responded_nodes = vec![topology.node_id.clone()];
    let mut versioning_states = vec![ClusterBucketMetadataResponderState::Present(
        local_versioned,
    )];

    for peer in &topology.cluster_peers {
        match fetch_peer_bucket_versioning_state(state, peer, bucket).await {
            Ok(peer_state) => {
                responded_nodes.push(peer.clone());
                versioning_states.push(peer_state);
            }
            Err(err) => {
                tracing::warn!(
                    peer = %peer,
                    bucket,
                    error = %err,
                    "Console bucket versioning fan-in peer request failed"
                );
            }
        }
    }

    Ok(ClusterBucketVersioningFanIn {
        responded_nodes,
        versioning_states,
    })
}

async fn fetch_peer_bucket_versioning_state(
    state: &AppState,
    peer: &str,
    bucket: &str,
) -> Result<ClusterBucketMetadataResponderState<bool>, String> {
    let path = format!("/{}", bucket);
    let response = storage::send_internal_peer_get(
        state,
        peer,
        path.as_str(),
        &[
            ("versioning", ""),
            (
                storage::INTERNAL_METADATA_SCOPE_QUERY_PARAM,
                storage::INTERNAL_METADATA_SCOPE_LOCAL_ONLY,
            ),
        ],
    )
    .await?;
    let status = response.status();
    let body = response.text().await.map_err(|err| err.to_string())?;

    if status.is_success() {
        let parsed =
            from_str::<PeerVersioningConfiguration>(&body).map_err(|err| err.to_string())?;
        return Ok(ClusterBucketMetadataResponderState::Present(
            parsed.status.as_deref() == Some("Enabled"),
        ));
    }
    if status == StatusCode::NOT_FOUND {
        let code = parse_peer_error_code(body.as_str());
        if code.as_deref() == Some("NoSuchBucket") {
            return Ok(ClusterBucketMetadataResponderState::MissingBucket);
        }
    }

    Err(format!("peer bucket versioning status {}", status.as_u16()))
}

fn resolve_cluster_bucket_versioning_state(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    operation: &str,
    bucket: &str,
    responded_nodes: &[String],
    states: &[ClusterBucketMetadataResponderState<bool>],
) -> Result<bool, String> {
    let assessment = storage::assess_bucket_metadata_operation_preconditions(
        state,
        topology,
        operation,
        responded_nodes,
        states,
    )?;
    ensure_cluster_bucket_metadata_operation_ready(operation, assessment.gap)?;
    if assessment
        .gap
        .is_some_and(cluster_bucket_metadata_mutation_precondition_gap_is_no_responder_values)
    {
        return Err(
            "Distributed bucket metadata fan-in did not include any versioning responders"
                .to_string(),
        );
    }

    match cluster_bucket_metadata_mutation_precondition_reject_details(assessment.gap) {
        Some(details)
            if details.failure_disposition
                == ClusterBucketMetadataMutationPreconditionFailureDisposition::NoSuchBucket =>
        {
            Err(format!(
                "Distributed bucket metadata is inconsistent for '{}' ({}; class={})",
                bucket,
                details.reason,
                details.failure_class.as_str()
            ))
        }
        Some(details)
            if assessment.gap
                == Some(
                    ClusterBucketMetadataMutationPreconditionGap::InconsistentResponderValues,
                ) =>
        {
            Err(format!(
                "Distributed bucket versioning state is inconsistent across responder nodes for '{}' ({}; class={})",
                bucket,
                details.reason,
                details.failure_class.as_str()
            ))
        }
        Some(details) => Err(format!(
            "Distributed bucket metadata fan-in for '{}' is not ready ({}; class={})",
            operation,
            details.reason,
            details.failure_class.as_str()
        )),
        None => assessment.current_value.ok_or_else(|| {
            "Distributed bucket metadata fan-in did not include any versioning responders"
                .to_string()
        }),
    }
}

fn ensure_cluster_bucket_metadata_operation_ready(
    operation: &str,
    gap: Option<ClusterBucketMetadataMutationPreconditionGap>,
) -> Result<(), String> {
    match gap
        .filter(|gap| cluster_bucket_metadata_mutation_precondition_gap_is_strategy_unready(*gap))
    {
        Some(gap) => Err(format!(
            "Distributed metadata strategy is not ready for bucket metadata operation '{}' ({})",
            operation,
            gap.as_str()
        )),
        None => Ok(()),
    }
}

fn parse_peer_error_code(xml: &str) -> Option<String> {
    from_str::<PeerErrorResponse>(xml).ok()?.code
}

fn versioning_configuration_xml(enabled: bool) -> String {
    let status = if enabled { "Enabled" } else { "Suspended" };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>{status}</Status></VersioningConfiguration>"#
    )
}

async fn fan_out_bucket_versioning_mutation_to_peers(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    bucket: &str,
    enabled: bool,
) -> Result<Vec<String>, String> {
    let path = format!("/{}", bucket);
    let query = [
        ("versioning", ""),
        (
            storage::INTERNAL_METADATA_SCOPE_QUERY_PARAM,
            storage::INTERNAL_METADATA_SCOPE_LOCAL_ONLY,
        ),
    ];
    let body = versioning_configuration_xml(enabled).into_bytes();
    let mut responded_nodes = vec![topology.node_id.clone()];

    for peer in &topology.cluster_peers {
        let response = storage::send_internal_peer_request(
            state,
            peer,
            Method::PUT,
            path.as_str(),
            &query,
            Some(body.clone()),
        )
        .await
        .map_err(|err| {
            format!(
                "Distributed bucket metadata mutation 'SetBucketVersioning' failed while contacting responder node '{}': {}",
                peer, err
            )
        })?;
        let status = response.status();
        if status.is_success() {
            responded_nodes.push(peer.clone());
            continue;
        }
        let body = response.text().await.map_err(|err| {
            format!(
                "Distributed bucket metadata mutation 'SetBucketVersioning' failed while reading responder error payload from node '{}': {}",
                peer, err
            )
        })?;
        if status == StatusCode::NOT_FOUND
            && parse_peer_error_code(body.as_str()).as_deref() == Some("NoSuchBucket")
        {
            return Err(format!(
                "Distributed bucket metadata mutation 'SetBucketVersioning' failed because bucket '{}' is missing on responder node '{}'",
                bucket, peer
            ));
        }
        return Err(format!(
            "Distributed bucket metadata mutation 'SetBucketVersioning' failed on responder node '{}' with status {}",
            peer,
            status.as_u16()
        ));
    }

    Ok(responded_nodes)
}

#[derive(serde::Deserialize)]
pub(super) struct SetVersioningRequest {
    enabled: bool,
}

pub(super) async fn set_versioning(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    Json(body): Json<SetVersioningRequest>,
) -> impl IntoResponse {
    let topology = runtime_topology_snapshot(&state);
    let internal_local_only =
        storage::is_trusted_internal_local_metadata_scope_request(&state, &headers, &params);
    let should_fan_in = storage::should_attempt_cluster_bucket_metadata_fan_in(
        &state,
        &topology,
        internal_local_only,
    );
    let use_consensus_bucket_metadata = storage::should_use_consensus_index_bucket_metadata_state(
        &state,
        &topology,
        internal_local_only,
    );
    if should_fan_in
        && let Some(err) = storage::reject_cluster_authoritative_peer_fan_in_transport_unready(
            &state,
            &topology,
            internal_local_only,
        )
    {
        return err;
    }
    if !internal_local_only
        && !should_fan_in
        && !use_consensus_bucket_metadata
        && let Some(err) =
            storage::reject_unready_bucket_metadata_operation(&state, "SetBucketVersioning")
    {
        return err;
    }
    if use_consensus_bucket_metadata {
        if let Err(resp) = storage::ensure_consensus_index_versioning_mutation_preconditions(
            &state,
            &topology,
            &bucket,
            "SetBucketVersioning",
        ) {
            return *resp;
        }
    } else if let Err(resp) = storage::ensure_bucket_exists(&state, &bucket).await {
        return resp;
    }

    if let Err(err) = state.storage.set_versioning(&bucket, body.enabled).await {
        return storage::map_bucket_storage_err(err);
    }

    if let Err(err) = storage::persist_bucket_metadata_operation(
        &state,
        &topology,
        "SetBucketVersioning",
        &BucketMetadataOperation::SetVersioning {
            bucket: bucket.clone(),
            enabled: body.enabled,
        },
    ) {
        return *err;
    }

    if should_fan_in {
        let responder_nodes = match fan_out_bucket_versioning_mutation_to_peers(
            &state,
            &topology,
            &bucket,
            body.enabled,
        )
        .await
        {
            Ok(nodes) => nodes,
            Err(err) => return response::error(StatusCode::SERVICE_UNAVAILABLE, err),
        };
        if let Some(err) = storage::reject_unready_bucket_metadata_operation_for_responders(
            &state,
            "SetBucketVersioning",
            responder_nodes.as_slice(),
        ) {
            return err;
        }
        let fan_in = match fetch_cluster_bucket_versioning_fan_in(&state, &topology, &bucket).await
        {
            Ok(fan_in) => fan_in,
            Err(err) => return storage::map_bucket_storage_err(err),
        };
        if let Some(err) = storage::reject_unready_bucket_metadata_operation_for_responders(
            &state,
            "SetBucketVersioning",
            fan_in.responded_nodes.as_slice(),
        ) {
            return err;
        }
        let converged = match resolve_cluster_bucket_versioning_state(
            &state,
            &topology,
            "SetBucketVersioning",
            &bucket,
            fan_in.responded_nodes.as_slice(),
            fan_in.versioning_states.as_slice(),
        ) {
            Ok(enabled) => enabled,
            Err(err) => return response::error(StatusCode::SERVICE_UNAVAILABLE, err),
        };
        if converged != body.enabled {
            return response::error(
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "Distributed bucket versioning mutation did not converge for '{}'",
                    bucket
                ),
            );
        }
    }

    response::ok()
}

#[derive(serde::Deserialize)]
pub(super) struct ListVersionsParams {
    key: String,
    #[serde(rename = "x-maxio-internal-metadata-scope")]
    internal_metadata_scope: Option<String>,
}

pub(super) async fn list_versions(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<ListVersionsParams>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = storage::ensure_bucket_exists(&state, &bucket).await {
        return resp;
    }
    if let Some(resp) = storage::validate_list_prefix(&params.key) {
        return resp;
    }

    let mut strategy_params = HashMap::new();
    if let Some(scope) = params.internal_metadata_scope.as_deref() {
        strategy_params.insert(
            storage::INTERNAL_METADATA_SCOPE_QUERY_PARAM.to_string(),
            scope.to_string(),
        );
    }
    let topology = runtime_topology_snapshot(&state);
    let internal_local_only = storage::is_trusted_internal_local_metadata_scope_request(
        &state,
        &headers,
        &strategy_params,
    );
    if let Some(resp) = storage::reject_cluster_authoritative_peer_fan_in_transport_unready(
        &state,
        &topology,
        internal_local_only,
    ) {
        return resp;
    }
    let should_fan_in = storage::should_attempt_cluster_object_listing_fan_in(
        &state,
        &topology,
        internal_local_only,
    );

    let (all, metadata_coverage) = if should_fan_in {
        let fan_in = match fetch_cluster_object_version_listing_fan_in(
            &state,
            &topology,
            &bucket,
            params.key.as_str(),
        )
        .await
        {
            Ok(fan_in) => fan_in,
            Err(err) => return storage::map_bucket_storage_err(err),
        };
        if let Some(resp) = storage::reject_unready_metadata_fan_in_preflight_for_responders(
            &topology,
            state.metadata_listing_strategy,
            "ListConsoleObjectVersions",
            fan_in.responder_membership_views.as_slice(),
            state
                .config
                .cluster_auth_token()
                .is_some_and(|value| !value.trim().is_empty()),
        ) {
            return resp;
        }
        let coverage = storage::list_metadata_fan_in_coverage_for_responders(
            &state,
            fan_in.responded_nodes.as_slice(),
        );
        let merged = merge_object_versions(fan_in.versions);
        if state.metadata_listing_strategy == ClusterMetadataListingStrategy::ConsensusIndex
            && !internal_local_only
        {
            let canonical_rows =
                match storage::load_consensus_object_version_metadata_rows_for_prefix(
                    &state,
                    &topology,
                    &bucket,
                    params.key.as_str(),
                    "ListConsoleObjectVersions",
                ) {
                    Ok(rows) => rows,
                    Err(err) => return *err,
                };
            let canonical = match hydrate_versions_from_consensus_states(
                "ListConsoleObjectVersions",
                merged.as_slice(),
                canonical_rows.as_slice(),
            ) {
                Ok(versions) => versions,
                Err(message) => return response::error(StatusCode::SERVICE_UNAVAILABLE, message),
            };
            (canonical, coverage)
        } else {
            (merged, coverage)
        }
    } else {
        let all = match state
            .storage
            .list_object_versions(&bucket, &params.key)
            .await
        {
            Ok(v) => v,
            Err(e) => return storage::map_bucket_storage_err(e),
        };
        (all, storage::list_metadata_coverage(&state))
    };
    if !internal_local_only
        && let Some(resp) = storage::reject_unready_metadata_listing(metadata_coverage.as_ref())
    {
        return resp;
    }

    let versions = all
        .into_iter()
        .filter(|version| version.key == params.key)
        .map(|version| VersionSummary {
            version_id: version.version_id,
            last_modified: version.last_modified,
            size: version.size,
            etag: version.etag,
            is_delete_marker: version.is_delete_marker,
        })
        .collect::<Vec<_>>();

    response::json(
        StatusCode::OK,
        ListVersionsResponse {
            versions,
            metadata_coverage,
        },
    )
}

async fn fetch_cluster_object_version_listing_fan_in(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    bucket: &str,
    key: &str,
) -> Result<ClusterObjectVersionListingFanIn, StorageError> {
    let local_versions = state.storage.list_object_versions(bucket, key).await?;
    let mut responded_nodes = vec![topology.node_id.clone()];
    let mut responder_membership_views = Vec::<ClusterResponderMembershipView>::new();
    let mut versions = local_versions;

    for peer in &topology.cluster_peers {
        match fetch_peer_local_object_versions(state, peer, bucket, key).await {
            Ok(peer_listing) => {
                responded_nodes.push(peer.clone());
                responder_membership_views.push(ClusterResponderMembershipView {
                    node_id: peer.clone(),
                    membership_view_id: Some(peer_listing.membership_view_id),
                });
                versions.extend(peer_listing.versions);
            }
            Err(err) => {
                tracing::warn!(
                    peer = %peer,
                    bucket,
                    key,
                    error = %err,
                    "Console object version fan-in peer request failed"
                );
            }
        }
    }

    Ok(ClusterObjectVersionListingFanIn {
        responded_nodes,
        responder_membership_views,
        versions,
    })
}

async fn fetch_peer_local_object_versions(
    state: &AppState,
    peer: &str,
    bucket: &str,
    key: &str,
) -> Result<PeerObjectVersionsFanInResult, String> {
    let path = format!("/{bucket}");
    let mut collected = Vec::new();
    let mut next_key_marker: Option<String> = None;
    let mut next_version_id_marker: Option<String> = None;
    let mut seen_markers = HashSet::<String>::new();
    let mut responder_membership_view_id: Option<String> = None;

    loop {
        let mut query = vec![
            ("versions", ""),
            ("max-keys", "1000"),
            ("prefix", key),
            (
                storage::INTERNAL_METADATA_SCOPE_QUERY_PARAM,
                storage::INTERNAL_METADATA_SCOPE_LOCAL_ONLY,
            ),
        ];
        if let Some(marker) = next_key_marker.as_deref() {
            query.push(("key-marker", marker));
        }
        if let Some(marker) = next_version_id_marker.as_deref() {
            query.push(("version-id-marker", marker));
        }

        let response =
            storage::send_internal_peer_get(state, peer, path.as_str(), query.as_slice()).await?;
        if !response.status().is_success() {
            return Err(format!(
                "peer object version list status {}",
                response.status().as_u16()
            ));
        }
        let observed_membership_view_id = storage::extract_internal_peer_membership_view_id(
            response.headers(),
            peer,
            "ListConsoleObjectVersions",
        )?;
        storage::ensure_stable_internal_peer_membership_view_id(
            &mut responder_membership_view_id,
            observed_membership_view_id.as_str(),
            peer,
            "ListConsoleObjectVersions",
        )?;

        let body = response.text().await.map_err(|err| err.to_string())?;
        let parsed = from_str::<PeerListVersionsResult>(&body).map_err(|err| err.to_string())?;

        for version in parsed.versions {
            collected.push(ObjectMeta {
                key: version.key,
                size: version.size,
                etag: version.etag,
                content_type: "application/octet-stream".to_string(),
                last_modified: version.last_modified,
                version_id: normalize_version_id(version.version_id),
                is_delete_marker: false,
                storage_format: None,
                checksum_algorithm: None,
                checksum_value: None,
            });
        }
        for marker in parsed.delete_markers {
            collected.push(ObjectMeta {
                key: marker.key,
                size: 0,
                etag: String::new(),
                content_type: "application/octet-stream".to_string(),
                last_modified: marker.last_modified,
                version_id: normalize_version_id(marker.version_id),
                is_delete_marker: true,
                storage_format: None,
                checksum_algorithm: None,
                checksum_value: None,
            });
        }

        if !parsed.is_truncated {
            break;
        }

        let key_marker = parsed
            .next_key_marker
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                "Peer object versions pagination failed (missing key marker)".to_string()
            })?;
        let version_id_marker = parsed
            .next_version_id_marker
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let loop_marker = format!(
            "{}\u{1f}{}",
            key_marker,
            version_id_marker.as_deref().unwrap_or_default()
        );
        if !seen_markers.insert(loop_marker) {
            return Err(
                "Peer object versions pagination failed (marker loop detected)".to_string(),
            );
        }

        next_key_marker = Some(key_marker);
        next_version_id_marker = version_id_marker;
    }

    let membership_view_id = responder_membership_view_id.ok_or_else(|| {
        format!(
            "Peer metadata fan-in response for 'ListConsoleObjectVersions' from '{peer}' did not yield a responder membership view id",
        )
    })?;
    Ok(PeerObjectVersionsFanInResult {
        membership_view_id,
        versions: collected,
    })
}

fn normalize_version_id(version_id: Option<String>) -> Option<String> {
    version_id
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty() && value != "null")
}

fn merge_object_versions(versions: Vec<ObjectMeta>) -> Vec<ObjectMeta> {
    let mut dedup = BTreeMap::<(String, Option<String>, bool), ObjectMeta>::new();
    for version in versions {
        let key = (
            version.key.clone(),
            version.version_id.clone(),
            version.is_delete_marker,
        );
        match dedup.get_mut(&key) {
            Some(current) => {
                if version.last_modified > current.last_modified {
                    *current = version;
                }
            }
            None => {
                dedup.insert(key, version);
            }
        }
    }

    let mut merged = dedup.into_values().collect::<Vec<_>>();
    merged.sort_by(|a, b| {
        let key_cmp = a.key.cmp(&b.key);
        if key_cmp != std::cmp::Ordering::Equal {
            return key_cmp;
        }
        let a_version = a.version_id.as_deref().unwrap_or("null");
        let b_version = b.version_id.as_deref().unwrap_or("null");
        b_version.cmp(a_version)
    });
    merged
}

fn hydrate_versions_from_consensus_states(
    operation: &str,
    versions: &[ObjectMeta],
    states: &[ObjectVersionMetadataState],
) -> Result<Vec<ObjectMeta>, String> {
    let mut by_key_and_version = BTreeMap::<(String, String, bool), ObjectMeta>::new();
    for version in versions {
        let version_id = version.version_id.as_deref().unwrap_or("null").to_string();
        by_key_and_version
            .entry((version.key.clone(), version_id, version.is_delete_marker))
            .or_insert_with(|| version.clone());
    }

    let mut page = Vec::with_capacity(states.len());
    for state in states {
        let key = state.key.clone();
        let version_id = state.version_id.clone();
        let hydrated = by_key_and_version
            .get(&(key.clone(), version_id.clone(), state.is_delete_marker))
            .cloned()
            .ok_or_else(|| {
                format!(
                    "Distributed metadata listing operation '{}' cannot hydrate canonical metadata row for key '{}' version '{}'",
                    operation, key, version_id
                )
            })?;
        page.push(hydrated);
    }

    Ok(page)
}

pub(super) async fn delete_version(
    State(state): State<AppState>,
    Path((bucket, version_id, key)): Path<(String, String, String)>,
) -> impl IntoResponse {
    let topology = runtime_topology_snapshot(&state);
    if let Err(resp) = storage::ensure_bucket_exists(&state, &bucket).await {
        return resp;
    }
    if let Err(err) = storage::ensure_consensus_index_object_mutation_preconditions(
        &state,
        &topology,
        &bucket,
        "DeleteConsoleObjectVersion",
    ) {
        return *err;
    }

    match state
        .storage
        .delete_object_version(&bucket, &key, &version_id)
        .await
    {
        Ok(_) => {
            if let Err(err) = storage::persist_object_metadata_after_version_delete(
                &state,
                &topology,
                &bucket,
                &key,
                &version_id,
            )
            .await
            {
                return *err;
            }
            response::ok()
        }
        Err(e) => storage::map_version_delete_err(e),
    }
}

pub(super) async fn download_version(
    State(state): State<AppState>,
    Path((bucket, version_id, key)): Path<(String, String, String)>,
) -> Response {
    if let Err(resp) = storage::ensure_bucket_exists(&state, &bucket).await {
        return resp;
    }
    let topology = runtime_topology_snapshot(&state);
    if let Err(err) = storage::ensure_consensus_index_object_read_authority(
        &state,
        &topology,
        &bucket,
        &key,
        Some(version_id.as_str()),
        "DownloadConsoleObjectVersion",
    ) {
        return *err;
    }

    let (reader, meta) = match state
        .storage
        .get_object_version(&bucket, &key, &version_id)
        .await
    {
        Ok(r) => r,
        Err(StorageError::VersionNotFound(_) | StorageError::NotFound(_)) => {
            return storage::version_not_found();
        }
        Err(StorageError::InvalidKey(message)) => return storage::invalid_key(message),
        Err(err) => return storage::internal_err(err),
    };

    let filename = key.rsplit('/').next().unwrap_or(&key);
    let safe_filename = sanitize_filename(filename);
    let stream = tokio_util::io::ReaderStream::new(reader);
    let body = axum::body::Body::from_stream(stream);

    response::download(body, &meta.content_type, meta.size, &safe_filename)
}
