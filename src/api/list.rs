mod response;
mod service;

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, Method},
    response::Response,
};
use chrono::Utc;
use http::StatusCode;
use quick_xml::de::from_str;
use serde::Deserialize;

use super::multipart;
use crate::api::object::peer_transport::{
    attest_internal_peer_target, build_internal_peer_http_client,
};
use crate::auth::signature_v4::{PresignRequest, generate_presigned_url};
use crate::cluster::authenticator::{FORWARDED_BY_HEADER, authenticate_forwarded_request};
use crate::cluster::security::INTERNAL_AUTH_TOKEN_HEADER;
use crate::error::S3Error;
use crate::metadata::{
    ClusterMetadataListingStrategy, ClusterResponderMembershipView,
    assess_cluster_responder_membership_views,
};
use crate::server::{AppState, runtime_topology_snapshot};
use crate::storage::ObjectMeta;
use crate::xml::types::*;
use response::{apply_metadata_coverage_headers, bucket_location_response, xml_response};

const INTERNAL_METADATA_SCOPE_QUERY_PARAM: &str = "x-maxio-internal-metadata-scope";
const INTERNAL_METADATA_SCOPE_LOCAL_ONLY: &str = "local-node-only";
const INTERNAL_MEMBERSHIP_VIEW_ID_HEADER: &str = "x-maxio-internal-membership-view-id";
const MAX_INTERNAL_LIST_PAGE_KEYS: usize = 1000;

struct ClusterObjectListingFanIn {
    responded_nodes: Vec<String>,
    objects: Vec<ObjectMeta>,
}

struct ClusterVersionListingFanIn {
    responded_nodes: Vec<String>,
    versions: Vec<ObjectMeta>,
}

struct PeerObjectListingFanInResult {
    membership_view_id: String,
    objects: Vec<ObjectMeta>,
}

struct PeerVersionListingFanInResult {
    membership_view_id: String,
    versions: Vec<ObjectMeta>,
}

#[derive(Deserialize)]
#[serde(rename = "ListBucketResult")]
struct PeerListBucketResultV2 {
    #[serde(rename = "IsTruncated")]
    is_truncated: bool,
    #[serde(rename = "NextContinuationToken")]
    next_continuation_token: Option<String>,
    #[serde(rename = "Contents", default)]
    contents: Vec<PeerObjectEntry>,
}

#[derive(Deserialize)]
struct PeerObjectEntry {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "LastModified")]
    last_modified: String,
    #[serde(rename = "ETag")]
    etag: String,
    #[serde(rename = "Size")]
    size: u64,
}

#[derive(Deserialize)]
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

#[derive(Deserialize)]
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

#[derive(Deserialize)]
struct PeerDeleteMarkerEntry {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "VersionId")]
    version_id: Option<String>,
    #[serde(rename = "LastModified")]
    last_modified: String,
}

pub async fn handle_bucket_get(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response<Body>, S3Error> {
    tracing::debug!("GET /{} params={:?}", bucket, params);

    let topology = runtime_topology_snapshot(&state);
    let internal_local_only =
        is_trusted_internal_local_metadata_scope_request(&state, &headers, &params);
    let should_check_cluster_bucket_presence =
        should_check_bucket_presence_via_cluster_metadata(&state, &topology, internal_local_only);
    if should_check_cluster_bucket_presence {
        super::bucket::head_bucket(
            State(state.clone()),
            Path(bucket.clone()),
            Query(params.clone()),
            headers.clone(),
        )
        .await?;
    } else {
        service::ensure_bucket_exists(&state, &bucket).await?;
    }

    match service::resolve_bucket_get_operation(&params)? {
        service::BucketGetOperation::ListUploads => {
            multipart::list_multipart_uploads(State(state), Path(bucket)).await
        }
        service::BucketGetOperation::GetVersioning => {
            super::bucket::get_bucket_versioning(state, bucket, &params, &headers).await
        }
        service::BucketGetOperation::GetLifecycle => {
            super::bucket::get_bucket_lifecycle(state, bucket, &params, &headers).await
        }
        service::BucketGetOperation::ListVersions => {
            list_object_versions(state, bucket, params, &headers).await
        }
        service::BucketGetOperation::GetLocation => {
            tracing::debug!("GetBucketLocation for {}", bucket);
            bucket_location_response(&state.config.region)
        }
        service::BucketGetOperation::ListV2 => {
            list_objects_v2(state, bucket, params, &headers).await
        }
        service::BucketGetOperation::ListV1 => {
            list_objects_v1(state, bucket, params, &headers).await
        }
    }
}

async fn list_objects_v2(
    state: AppState,
    bucket: String,
    params: HashMap<String, String>,
    headers: &HeaderMap,
) -> Result<Response<Body>, S3Error> {
    let topology = runtime_topology_snapshot(&state);
    let internal_local_only =
        is_trusted_internal_local_metadata_scope_request(&state, headers, &params);
    let prefix = params.get("prefix").cloned().unwrap_or_default();
    service::validate_prefix(&prefix)?;
    service::ensure_consensus_index_peer_fan_in_transport_ready(
        &state,
        &topology,
        internal_local_only,
    )?;

    let should_fan_in =
        should_attempt_cluster_object_metadata_fan_in(&state, &topology, internal_local_only);
    let (all_objects, metadata_coverage) = if should_fan_in {
        let fan_in =
            fetch_cluster_object_listing_fan_in(&state, &topology, &bucket, prefix.as_str())
                .await?;
        let coverage = service::metadata_coverage_for_topology_responders(
            &topology,
            state.metadata_listing_strategy,
            fan_in.responded_nodes.as_slice(),
        );
        (fan_in.objects, coverage)
    } else {
        let objects = state
            .storage
            .list_objects(&bucket, prefix.as_str())
            .await
            .map_err(|e| service::map_bucket_storage_err(&bucket, e))?;
        let coverage =
            service::metadata_coverage_for_topology(&topology, state.metadata_listing_strategy);
        (objects, coverage)
    };

    if !internal_local_only {
        service::ensure_distributed_listing_strategy_ready(metadata_coverage.as_ref())?;
    }

    let query = service::ListV2Query::from_params(
        &params,
        metadata_coverage
            .as_ref()
            .map(|coverage| coverage.snapshot_id.as_str()),
    )?;

    let use_consensus_index_persisted_state =
        service::should_use_consensus_index_persisted_object_listing_state(
            &state,
            &topology,
            internal_local_only,
        );
    let (page, is_truncated) = if use_consensus_index_persisted_state {
        service::paginate_objects_v2_from_consensus_index_persisted_state(
            &state,
            &topology,
            &bucket,
            &query,
            all_objects.as_slice(),
            metadata_coverage
                .as_ref()
                .map(|coverage| coverage.snapshot_id.as_str()),
        )?
    } else {
        service::paginate_objects_v2_for_topology(
            &topology,
            state.metadata_listing_strategy,
            &bucket,
            &query,
            all_objects.as_slice(),
        )?
    };
    let page_refs: Vec<_> = page.iter().collect();
    let (contents, common_prefixes) =
        service::split_by_delimiter(&page_refs, &query.prefix, query.delimiter.as_deref());

    let next_token = if is_truncated {
        page.last().map(|meta| {
            service::encode_continuation_token_with_snapshot(
                &meta.key,
                metadata_coverage
                    .as_ref()
                    .map(|coverage| coverage.snapshot_id.as_str()),
            )
        })
    } else {
        None
    };

    let result = ListBucketResult {
        name: bucket,
        prefix: query.prefix,
        key_count: contents.len() as i32 + common_prefixes.len() as i32,
        max_keys: query.max_keys as i32,
        is_truncated,
        contents,
        common_prefixes,
        continuation_token: query.continuation_token,
        next_continuation_token: next_token,
        delimiter: query.delimiter,
        start_after: query.start_after,
    };

    let mut response = xml_response(StatusCode::OK, &result)?;
    apply_metadata_coverage_headers(response.headers_mut(), metadata_coverage.as_ref());
    apply_internal_membership_view_header(response.headers_mut(), &topology, internal_local_only);
    Ok(response)
}

async fn list_objects_v1(
    state: AppState,
    bucket: String,
    params: HashMap<String, String>,
    headers: &HeaderMap,
) -> Result<Response<Body>, S3Error> {
    let topology = runtime_topology_snapshot(&state);
    let internal_local_only =
        is_trusted_internal_local_metadata_scope_request(&state, headers, &params);
    let prefix = params.get("prefix").cloned().unwrap_or_default();
    service::validate_prefix(&prefix)?;
    service::ensure_consensus_index_peer_fan_in_transport_ready(
        &state,
        &topology,
        internal_local_only,
    )?;

    let should_fan_in =
        should_attempt_cluster_object_metadata_fan_in(&state, &topology, internal_local_only);
    let (all_objects, metadata_coverage) = if should_fan_in {
        let fan_in =
            fetch_cluster_object_listing_fan_in(&state, &topology, &bucket, prefix.as_str())
                .await?;
        let coverage = service::metadata_coverage_for_topology_responders(
            &topology,
            state.metadata_listing_strategy,
            fan_in.responded_nodes.as_slice(),
        );
        (fan_in.objects, coverage)
    } else {
        let objects = state
            .storage
            .list_objects(&bucket, prefix.as_str())
            .await
            .map_err(|e| service::map_bucket_storage_err(&bucket, e))?;
        let coverage =
            service::metadata_coverage_for_topology(&topology, state.metadata_listing_strategy);
        (objects, coverage)
    };

    if !internal_local_only {
        service::ensure_distributed_listing_strategy_ready(metadata_coverage.as_ref())?;
    }

    let query = service::ListV1Query::from_params(&params)?;

    let use_consensus_index_persisted_state =
        service::should_use_consensus_index_persisted_object_listing_state(
            &state,
            &topology,
            internal_local_only,
        );
    let (page, is_truncated) = if use_consensus_index_persisted_state {
        service::paginate_objects_v1_from_consensus_index_persisted_state(
            &state,
            &topology,
            &bucket,
            &query,
            all_objects.as_slice(),
            metadata_coverage
                .as_ref()
                .map(|coverage| coverage.snapshot_id.as_str()),
        )?
    } else {
        service::paginate_objects_v1_for_topology(
            &topology,
            state.metadata_listing_strategy,
            &bucket,
            &query,
            all_objects.as_slice(),
        )?
    };
    let page_refs: Vec<_> = page.iter().collect();
    let (contents, common_prefixes) =
        service::split_by_delimiter(&page_refs, &query.prefix, query.delimiter.as_deref());

    let next_marker = if is_truncated {
        page.last().map(|meta| meta.key.clone())
    } else {
        None
    };

    let result = ListBucketResultV1 {
        name: bucket,
        prefix: query.prefix,
        marker: query.marker.unwrap_or_default(),
        next_marker,
        max_keys: query.max_keys as i32,
        is_truncated,
        contents,
        common_prefixes,
        delimiter: query.delimiter,
    };

    let mut response = xml_response(StatusCode::OK, &result)?;
    apply_metadata_coverage_headers(response.headers_mut(), metadata_coverage.as_ref());
    apply_internal_membership_view_header(response.headers_mut(), &topology, internal_local_only);
    Ok(response)
}

async fn list_object_versions(
    state: AppState,
    bucket: String,
    params: HashMap<String, String>,
    headers: &HeaderMap,
) -> Result<Response<Body>, S3Error> {
    let topology = runtime_topology_snapshot(&state);
    let internal_local_only =
        is_trusted_internal_local_metadata_scope_request(&state, headers, &params);
    let prefix = params.get("prefix").cloned().unwrap_or_default();
    service::validate_prefix(&prefix)?;
    service::ensure_consensus_index_peer_fan_in_transport_ready(
        &state,
        &topology,
        internal_local_only,
    )?;

    let should_fan_in =
        should_attempt_cluster_object_metadata_fan_in(&state, &topology, internal_local_only);
    let (all_versions, metadata_coverage) = if should_fan_in {
        let fan_in =
            fetch_cluster_version_listing_fan_in(&state, &topology, &bucket, prefix.as_str())
                .await?;
        let coverage = service::metadata_coverage_for_topology_responders(
            &topology,
            state.metadata_listing_strategy,
            fan_in.responded_nodes.as_slice(),
        );
        (fan_in.versions, coverage)
    } else {
        let versions = state
            .storage
            .list_object_versions(&bucket, prefix.as_str())
            .await
            .map_err(|e| service::map_bucket_storage_err(&bucket, e))?;
        let coverage =
            service::metadata_coverage_for_topology(&topology, state.metadata_listing_strategy);
        (versions, coverage)
    };

    if !internal_local_only {
        service::ensure_distributed_listing_strategy_ready(metadata_coverage.as_ref())?;
    }

    let query = service::ListVersionsQuery::from_params(&params)?;

    let latest_per_key = service::latest_version_per_key(&all_versions);
    let use_consensus_index_persisted_state =
        service::should_use_consensus_index_persisted_object_listing_state(
            &state,
            &topology,
            internal_local_only,
        );
    let (page_owned, is_truncated, next_markers) = if use_consensus_index_persisted_state {
        service::paginate_versions_from_consensus_index_persisted_state(
            &state,
            &topology,
            &bucket,
            &query,
            all_versions.as_slice(),
            metadata_coverage
                .as_ref()
                .map(|coverage| coverage.snapshot_id.as_str()),
        )?
    } else {
        service::paginate_versions_for_topology(
            &topology,
            state.metadata_listing_strategy,
            &bucket,
            &query,
            all_versions.as_slice(),
        )?
    };
    let (versions, delete_markers) = service::split_version_entries(&page_owned, &latest_per_key);

    let result = ListVersionsResult {
        name: bucket,
        prefix: query.prefix,
        key_marker: query.key_marker.unwrap_or_default(),
        version_id_marker: query.version_id_marker.unwrap_or_default(),
        next_key_marker: next_markers.as_ref().map(|(key, _)| key.clone()),
        next_version_id_marker: next_markers.map(|(_, version_id)| version_id),
        max_keys: query.max_keys as i32,
        is_truncated,
        versions,
        delete_markers,
    };

    let mut response = xml_response(StatusCode::OK, &result)?;
    apply_metadata_coverage_headers(response.headers_mut(), metadata_coverage.as_ref());
    apply_internal_membership_view_header(response.headers_mut(), &topology, internal_local_only);
    Ok(response)
}

fn should_attempt_cluster_object_metadata_fan_in(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    internal_local_only: bool,
) -> bool {
    if internal_local_only || !topology.is_distributed() {
        return false;
    }
    if state.config.cluster_auth_token().is_none() {
        return false;
    }
    matches!(
        state.metadata_listing_strategy,
        ClusterMetadataListingStrategy::RequestTimeAggregation
            | ClusterMetadataListingStrategy::ConsensusIndex
            | ClusterMetadataListingStrategy::FullReplication
    )
}

fn should_check_bucket_presence_via_cluster_metadata(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    internal_local_only: bool,
) -> bool {
    should_attempt_cluster_object_metadata_fan_in(state, topology, internal_local_only)
        || (!internal_local_only
            && topology.is_distributed()
            && state.metadata_listing_strategy == ClusterMetadataListingStrategy::ConsensusIndex)
}

fn is_trusted_internal_local_metadata_scope_request(
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

async fn fetch_cluster_object_listing_fan_in(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    bucket: &str,
    prefix: &str,
) -> Result<ClusterObjectListingFanIn, S3Error> {
    let local_objects = state
        .storage
        .list_objects(bucket, prefix)
        .await
        .map_err(|e| service::map_bucket_storage_err(bucket, e))?;

    let mut responded_nodes = vec![topology.node_id.clone()];
    let mut objects = local_objects;
    let mut responder_views = Vec::<ClusterResponderMembershipView>::new();
    for peer in &topology.cluster_peers {
        match fetch_peer_local_object_listing(state, peer, bucket, prefix).await {
            Ok(peer_listing) => {
                responded_nodes.push(peer.clone());
                responder_views.push(ClusterResponderMembershipView {
                    node_id: peer.clone(),
                    membership_view_id: Some(peer_listing.membership_view_id),
                });
                objects.extend(peer_listing.objects);
            }
            Err(err) => {
                tracing::warn!(
                    peer = %peer,
                    bucket,
                    error = ?err,
                    "Failed to fetch peer object listing for distributed metadata fan-in"
                );
            }
        }
    }
    ensure_peer_responder_membership_views_consistent("ListObjectsV2", responder_views.as_slice())?;

    Ok(ClusterObjectListingFanIn {
        responded_nodes,
        objects,
    })
}

async fn fetch_peer_local_object_listing(
    state: &AppState,
    peer: &str,
    bucket: &str,
    prefix: &str,
) -> Result<PeerObjectListingFanInResult, S3Error> {
    let path = format!("/{bucket}");
    let mut collected = Vec::new();
    let mut next_continuation_token: Option<String> = None;
    let mut seen_tokens = HashSet::<String>::new();
    let mut observed_membership_view_id: Option<String> = None;

    loop {
        let mut query_params = vec![
            ("list-type".to_string(), "2".to_string()),
            (
                "max-keys".to_string(),
                MAX_INTERNAL_LIST_PAGE_KEYS.to_string(),
            ),
            (
                INTERNAL_METADATA_SCOPE_QUERY_PARAM.to_string(),
                INTERNAL_METADATA_SCOPE_LOCAL_ONLY.to_string(),
            ),
        ];
        if !prefix.is_empty() {
            query_params.push(("prefix".to_string(), prefix.to_string()));
        }
        if let Some(token) = next_continuation_token.as_ref() {
            query_params.push(("continuation-token".to_string(), token.clone()));
        }

        let response =
            send_internal_peer_get(state, peer, path.as_str(), query_params.as_slice()).await?;
        if !response.status().is_success() {
            return Err(S3Error::service_unavailable(
                "Peer object listing request failed",
            ));
        }
        let responder_membership_view_id =
            extract_internal_peer_membership_view_id(response.headers(), peer, "ListObjectsV2")?;
        ensure_stable_internal_peer_membership_view_id(
            &mut observed_membership_view_id,
            responder_membership_view_id.as_str(),
            peer,
            "ListObjectsV2",
        )?;
        let body = response.text().await.map_err(S3Error::internal)?;
        let parsed = from_str::<PeerListBucketResultV2>(&body)
            .map_err(|_| S3Error::internal("Invalid XML"))?;

        for object in parsed.contents {
            collected.push(ObjectMeta {
                key: object.key,
                size: object.size,
                etag: object.etag,
                content_type: "application/octet-stream".to_string(),
                last_modified: object.last_modified,
                version_id: None,
                is_delete_marker: false,
                storage_format: None,
                checksum_algorithm: None,
                checksum_value: None,
            });
        }

        if !parsed.is_truncated {
            break;
        }

        let token = parsed
            .next_continuation_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                S3Error::service_unavailable(
                    "Peer object listing pagination failed (missing continuation token)",
                )
            })?;
        if !seen_tokens.insert(token.clone()) {
            return Err(S3Error::service_unavailable(
                "Peer object listing pagination failed (continuation loop detected)",
            ));
        }
        next_continuation_token = Some(token);
    }

    let membership_view_id = observed_membership_view_id.ok_or_else(|| {
        S3Error::service_unavailable(
            "Peer object listing request did not yield a responder membership view id",
        )
    })?;
    Ok(PeerObjectListingFanInResult {
        membership_view_id,
        objects: collected,
    })
}

async fn fetch_cluster_version_listing_fan_in(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    bucket: &str,
    prefix: &str,
) -> Result<ClusterVersionListingFanIn, S3Error> {
    let local_versions = state
        .storage
        .list_object_versions(bucket, prefix)
        .await
        .map_err(|e| service::map_bucket_storage_err(bucket, e))?;

    let mut responded_nodes = vec![topology.node_id.clone()];
    let mut versions = local_versions;
    let mut responder_views = Vec::<ClusterResponderMembershipView>::new();
    for peer in &topology.cluster_peers {
        match fetch_peer_local_version_listing(state, peer, bucket, prefix).await {
            Ok(peer_listing) => {
                responded_nodes.push(peer.clone());
                responder_views.push(ClusterResponderMembershipView {
                    node_id: peer.clone(),
                    membership_view_id: Some(peer_listing.membership_view_id),
                });
                versions.extend(peer_listing.versions);
            }
            Err(err) => {
                tracing::warn!(
                    peer = %peer,
                    bucket,
                    error = ?err,
                    "Failed to fetch peer object versions for distributed metadata fan-in"
                );
            }
        }
    }
    ensure_peer_responder_membership_views_consistent(
        "ListObjectVersions",
        responder_views.as_slice(),
    )?;

    versions.sort_by(|a, b| {
        let key_cmp = a.key.cmp(&b.key);
        if key_cmp != std::cmp::Ordering::Equal {
            return key_cmp;
        }
        let a_version = a.version_id.as_deref().unwrap_or("null");
        let b_version = b.version_id.as_deref().unwrap_or("null");
        b_version.cmp(a_version)
    });

    Ok(ClusterVersionListingFanIn {
        responded_nodes,
        versions,
    })
}

async fn fetch_peer_local_version_listing(
    state: &AppState,
    peer: &str,
    bucket: &str,
    prefix: &str,
) -> Result<PeerVersionListingFanInResult, S3Error> {
    let path = format!("/{bucket}");
    let mut collected = Vec::new();
    let mut next_key_marker: Option<String> = None;
    let mut next_version_id_marker: Option<String> = None;
    let mut seen_markers = HashSet::<String>::new();
    let mut observed_membership_view_id: Option<String> = None;

    loop {
        let mut query_params = vec![
            ("versions".to_string(), String::new()),
            (
                "max-keys".to_string(),
                MAX_INTERNAL_LIST_PAGE_KEYS.to_string(),
            ),
            (
                INTERNAL_METADATA_SCOPE_QUERY_PARAM.to_string(),
                INTERNAL_METADATA_SCOPE_LOCAL_ONLY.to_string(),
            ),
        ];
        if !prefix.is_empty() {
            query_params.push(("prefix".to_string(), prefix.to_string()));
        }
        if let Some(key_marker) = next_key_marker.as_ref() {
            query_params.push(("key-marker".to_string(), key_marker.clone()));
        }
        if let Some(version_id_marker) = next_version_id_marker.as_ref() {
            query_params.push(("version-id-marker".to_string(), version_id_marker.clone()));
        }

        let response =
            send_internal_peer_get(state, peer, path.as_str(), query_params.as_slice()).await?;
        if !response.status().is_success() {
            return Err(S3Error::service_unavailable(
                "Peer object versions request failed",
            ));
        }
        let responder_membership_view_id = extract_internal_peer_membership_view_id(
            response.headers(),
            peer,
            "ListObjectVersions",
        )?;
        ensure_stable_internal_peer_membership_view_id(
            &mut observed_membership_view_id,
            responder_membership_view_id.as_str(),
            peer,
            "ListObjectVersions",
        )?;
        let body = response.text().await.map_err(S3Error::internal)?;
        let parsed = from_str::<PeerListVersionsResult>(&body)
            .map_err(|_| S3Error::internal("Invalid XML"))?;

        for version in parsed.versions {
            let normalized_version_id = normalize_version_id(version.version_id);
            collected.push(ObjectMeta {
                key: version.key,
                size: version.size,
                etag: version.etag,
                content_type: "application/octet-stream".to_string(),
                last_modified: version.last_modified,
                version_id: normalized_version_id,
                is_delete_marker: false,
                storage_format: None,
                checksum_algorithm: None,
                checksum_value: None,
            });
        }
        for marker in parsed.delete_markers {
            let normalized_version_id = normalize_version_id(marker.version_id);
            collected.push(ObjectMeta {
                key: marker.key,
                size: 0,
                etag: String::new(),
                content_type: "application/octet-stream".to_string(),
                last_modified: marker.last_modified,
                version_id: normalized_version_id,
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
                S3Error::service_unavailable(
                    "Peer object versions pagination failed (missing key marker)",
                )
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
            return Err(S3Error::service_unavailable(
                "Peer object versions pagination failed (marker loop detected)",
            ));
        }

        next_key_marker = Some(key_marker);
        next_version_id_marker = version_id_marker;
    }

    let membership_view_id = observed_membership_view_id.ok_or_else(|| {
        S3Error::service_unavailable(
            "Peer object versions request did not yield a responder membership view id",
        )
    })?;
    Ok(PeerVersionListingFanInResult {
        membership_view_id,
        versions: collected,
    })
}

fn normalize_version_id(version_id: Option<String>) -> Option<String> {
    version_id
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty() && value != "null")
}

fn apply_internal_membership_view_header(
    headers: &mut HeaderMap,
    topology: &crate::server::RuntimeTopologySnapshot,
    internal_local_only: bool,
) {
    if !internal_local_only {
        return;
    }

    if let Ok(value) = HeaderValue::from_str(topology.membership_view_id.as_str()) {
        headers.insert(INTERNAL_MEMBERSHIP_VIEW_ID_HEADER, value);
    }
}

fn extract_internal_peer_membership_view_id(
    headers: &reqwest::header::HeaderMap,
    peer: &str,
    operation: &str,
) -> Result<String, S3Error> {
    headers
        .get(INTERNAL_MEMBERSHIP_VIEW_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            S3Error::service_unavailable(&format!(
                "Peer metadata fan-in response for '{operation}' from '{peer}' is missing internal membership view id header",
            ))
        })
}

fn ensure_stable_internal_peer_membership_view_id(
    observed_membership_view_id: &mut Option<String>,
    responder_membership_view_id: &str,
    peer: &str,
    operation: &str,
) -> Result<(), S3Error> {
    match observed_membership_view_id {
        None => {
            *observed_membership_view_id = Some(responder_membership_view_id.to_string());
            Ok(())
        }
        Some(observed) if observed == responder_membership_view_id => Ok(()),
        Some(observed) => Err(S3Error::service_unavailable(&format!(
            "Peer metadata fan-in response for '{operation}' from '{peer}' changed membership view id from '{}' to '{}' during pagination",
            observed, responder_membership_view_id
        ))),
    }
}

fn ensure_peer_responder_membership_views_consistent(
    operation: &str,
    responders: &[ClusterResponderMembershipView],
) -> Result<(), S3Error> {
    if responders.is_empty() {
        return Ok(());
    }
    let assessment = assess_cluster_responder_membership_views(None, responders);
    if assessment.consistent {
        return Ok(());
    }

    let reason = assessment
        .gap
        .map(|gap| gap.as_str())
        .unwrap_or("unknown-membership-view-gap");
    Err(S3Error::service_unavailable(&format!(
        "Distributed metadata fan-in for '{operation}' observed inconsistent peer membership view ids ({reason})",
    )))
}

async fn send_internal_peer_get(
    state: &AppState,
    peer: &str,
    path: &str,
    query_params: &[(String, String)],
) -> Result<reqwest::Response, S3Error> {
    attest_internal_peer_target(state, peer, Duration::from_secs(2))?;
    let transport = build_internal_peer_http_client(
        state,
        Some(Duration::from_secs(2)),
        Duration::from_secs(10),
    )?;
    let query_refs = query_params
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    let presigned_url = generate_presigned_url(PresignRequest {
        method: Method::GET.as_str(),
        scheme: transport.scheme,
        host: peer,
        path,
        extra_query_params: query_refs.as_slice(),
        access_key: state.config.access_key.as_str(),
        secret_key: state.config.secret_key.as_str(),
        region: state.config.region.as_str(),
        now: Utc::now(),
        expires_secs: 30,
    })
    .map_err(S3Error::internal)?;

    let mut request = transport
        .client
        .request(Method::GET, presigned_url)
        .header(FORWARDED_BY_HEADER, state.node_id.as_ref());
    if let Some(token) = state
        .config
        .cluster_auth_token()
        .filter(|value| !value.trim().is_empty())
    {
        request = request.header(INTERNAL_AUTH_TOKEN_HEADER, token);
    }

    request.send().await.map_err(S3Error::internal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::S3ErrorCode;
    use crate::storage::StorageError;

    #[test]
    fn map_bucket_storage_err_maps_not_found_to_no_such_bucket() {
        let err = service::map_bucket_storage_err(
            "missing",
            StorageError::NotFound("missing".to_string()),
        );
        assert!(matches!(err.code, S3ErrorCode::NoSuchBucket));
    }

    #[test]
    fn map_bucket_storage_err_maps_invalid_key_to_invalid_argument() {
        let err = service::map_bucket_storage_err(
            "bucket",
            StorageError::InvalidKey("invalid prefix".to_string()),
        );
        assert!(matches!(err.code, S3ErrorCode::InvalidArgument));
    }

    #[test]
    fn extract_internal_peer_membership_view_id_accepts_matching_view() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            INTERNAL_MEMBERSHIP_VIEW_ID_HEADER,
            reqwest::header::HeaderValue::from_static("view-1"),
        );

        assert!(
            extract_internal_peer_membership_view_id(&headers, "node-b:9000", "ListV2").is_ok()
        );
    }

    #[test]
    fn extract_internal_peer_membership_view_id_rejects_missing_header() {
        let headers = reqwest::header::HeaderMap::new();
        let err = extract_internal_peer_membership_view_id(&headers, "node-b:9000", "ListV2")
            .expect_err("missing view header must fail closed");
        assert!(matches!(err.code, S3ErrorCode::ServiceUnavailable));
        assert!(
            err.message
                .contains("missing internal membership view id header")
        );
    }

    #[test]
    fn ensure_stable_internal_peer_membership_view_id_rejects_mid_pagination_view_change() {
        let mut observed = Some("view-a".to_string());
        let err = ensure_stable_internal_peer_membership_view_id(
            &mut observed,
            "view-b",
            "node-b:9000",
            "ListV2",
        )
        .expect_err("view change during pagination must fail closed");
        assert!(matches!(err.code, S3ErrorCode::ServiceUnavailable));
        assert!(err.message.contains("changed membership view id"));
    }

    #[test]
    fn ensure_peer_responder_membership_views_consistent_rejects_inconsistent_views() {
        let responders = vec![
            ClusterResponderMembershipView {
                node_id: "node-b:9000".to_string(),
                membership_view_id: Some("view-a".to_string()),
            },
            ClusterResponderMembershipView {
                node_id: "node-c:9000".to_string(),
                membership_view_id: Some("view-b".to_string()),
            },
        ];
        let err = ensure_peer_responder_membership_views_consistent(
            "ListObjectsV2",
            responders.as_slice(),
        )
        .expect_err("inconsistent responder views must fail");
        assert!(matches!(err.code, S3ErrorCode::ServiceUnavailable));
        assert!(
            err.message
                .contains("inconsistent peer membership view ids")
        );
    }
}
