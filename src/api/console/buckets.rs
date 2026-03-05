use axum::{
    Json,
    extract::{Path, Query, State},
    http::HeaderMap,
    http::{Method, StatusCode},
    response::IntoResponse,
};
use quick_xml::de::from_str;
use serde::Serialize;
use std::collections::HashMap;

use super::{response, storage};
use crate::metadata::{
    BucketMetadataOperation, BucketMetadataState, ClusterBucketMetadataConsistencyGap,
    ClusterBucketMetadataResponderState, ClusterBucketPresenceConvergenceExpectation,
    ClusterResponderMembershipView, MetadataNodeBucketsPage,
    assess_cluster_bucket_metadata_consistency, assess_cluster_bucket_presence_convergence,
    cluster_metadata_readiness_reject_reason,
    merge_cluster_list_buckets_page_with_topology_snapshot,
};
use crate::server::{AppState, runtime_topology_snapshot};
use crate::storage::{BucketMeta, StorageError};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BucketSummary {
    name: String,
    created_at: String,
    versioning: bool,
}

#[derive(Debug, Serialize)]
struct ListBucketsResponse {
    buckets: Vec<BucketSummary>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename = "ListAllMyBucketsResult")]
struct PeerListAllMyBucketsResult {
    #[serde(rename = "Buckets")]
    buckets: PeerBuckets,
}

#[derive(Debug, serde::Deserialize)]
struct PeerBuckets {
    #[serde(rename = "Bucket", default)]
    bucket: Vec<PeerBucketEntry>,
}

#[derive(Debug, serde::Deserialize)]
struct PeerBucketEntry {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "CreationDate")]
    creation_date: String,
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

struct ClusterBucketListingNodePage {
    node_id: String,
    buckets: Vec<BucketSummary>,
}

struct ClusterBucketListingFanIn {
    bucket_pages: Vec<ClusterBucketListingNodePage>,
    responder_membership_views: Vec<ClusterResponderMembershipView>,
}

struct PeerBucketSummariesFanInResult {
    membership_view_id: String,
    buckets: Vec<BucketSummary>,
}

struct ClusterBucketPresenceFanIn {
    responded_nodes: Vec<String>,
    bucket_presence_states: Vec<ClusterBucketMetadataResponderState<bool>>,
}

const CONSENSUS_INDEX_CREATION_DATE_FALLBACK: &str = "1970-01-01T00:00:00.000Z";

impl ClusterBucketListingFanIn {
    fn responded_nodes(&self) -> Vec<String> {
        self.bucket_pages
            .iter()
            .map(|page| page.node_id.clone())
            .collect()
    }
}

pub(super) async fn list_buckets(
    State(state): State<AppState>,
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

    if storage::should_attempt_cluster_bucket_metadata_fan_in(
        &state,
        &topology,
        internal_local_only,
    ) {
        match fetch_cluster_bucket_listing_fan_in(&state, &topology).await {
            Ok(fan_in) => {
                if let Some(error_response) =
                    storage::reject_unready_metadata_fan_in_preflight_for_responders(
                        &topology,
                        state.metadata_listing_strategy,
                        "ListConsoleBuckets",
                        fan_in.responder_membership_views.as_slice(),
                    )
                {
                    return error_response;
                }
                let responded_nodes = fan_in.responded_nodes();
                let metadata_coverage = storage::list_metadata_coverage_for_responders(
                    &state,
                    responded_nodes.as_slice(),
                );
                if let Some(error_response) =
                    storage::reject_unready_metadata_listing(metadata_coverage.as_ref())
                {
                    return error_response;
                }
                let merged_buckets = match merge_cluster_bucket_summaries_with_topology_snapshot(
                    &state, &topology, fan_in,
                ) {
                    Ok(merged_buckets) => merged_buckets,
                    Err(err) => return response::error(StatusCode::SERVICE_UNAVAILABLE, err),
                };
                return response::json(
                    StatusCode::OK,
                    ListBucketsResponse {
                        buckets: merged_buckets,
                    },
                );
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "Console bucket fan-in failed; falling back to local storage bucket listing"
                );
            }
        }
    }

    let metadata_coverage = storage::list_metadata_coverage(&state);
    if !internal_local_only && !use_consensus_bucket_metadata {
        if let Some(error_response) =
            storage::reject_unready_metadata_listing(metadata_coverage.as_ref())
        {
            return error_response;
        }
    }

    if use_consensus_bucket_metadata {
        return match storage::load_consensus_bucket_metadata_rows(&state, &topology, "ListBuckets")
        {
            Ok(rows) => response::json(
                StatusCode::OK,
                ListBucketsResponse {
                    buckets: rows
                        .into_iter()
                        .map(|bucket| BucketSummary {
                            name: bucket.bucket,
                            created_at: CONSENSUS_INDEX_CREATION_DATE_FALLBACK.to_string(),
                            versioning: bucket.versioning_enabled,
                        })
                        .collect::<Vec<_>>(),
                },
            ),
            Err(err) => *err,
        };
    }

    match state.storage.list_buckets().await {
        Ok(buckets) => response::json(
            StatusCode::OK,
            ListBucketsResponse {
                buckets: buckets
                    .into_iter()
                    .map(|bucket| BucketSummary {
                        name: bucket.name,
                        created_at: bucket.created_at,
                        versioning: bucket.versioning,
                    })
                    .collect::<Vec<_>>(),
            },
        ),
        Err(err) => response::error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

async fn fetch_cluster_bucket_listing_fan_in(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
) -> Result<ClusterBucketListingFanIn, String> {
    let local_buckets = state
        .storage
        .list_buckets()
        .await
        .map_err(|err| err.to_string())?
        .into_iter()
        .map(|bucket| BucketSummary {
            name: bucket.name,
            created_at: bucket.created_at,
            versioning: bucket.versioning,
        })
        .collect::<Vec<_>>();
    let mut bucket_pages = vec![ClusterBucketListingNodePage {
        node_id: topology.node_id.clone(),
        buckets: local_buckets,
    }];
    let mut responder_membership_views = Vec::<ClusterResponderMembershipView>::new();

    for peer in &topology.cluster_peers {
        match fetch_peer_bucket_summaries(state, peer).await {
            Ok(peer_summaries) => {
                bucket_pages.push(ClusterBucketListingNodePage {
                    node_id: peer.clone(),
                    buckets: peer_summaries.buckets,
                });
                responder_membership_views.push(ClusterResponderMembershipView {
                    node_id: peer.clone(),
                    membership_view_id: Some(peer_summaries.membership_view_id),
                });
            }
            Err(err) => {
                tracing::warn!(
                    peer = %peer,
                    error = %err,
                    "Console bucket fan-in peer request failed"
                );
            }
        }
    }

    Ok(ClusterBucketListingFanIn {
        bucket_pages,
        responder_membership_views,
    })
}

async fn fetch_peer_bucket_summaries(
    state: &AppState,
    peer: &str,
) -> Result<PeerBucketSummariesFanInResult, String> {
    let list_response = storage::send_internal_peer_get(
        state,
        peer,
        "/",
        &[(
            storage::INTERNAL_METADATA_SCOPE_QUERY_PARAM,
            storage::INTERNAL_METADATA_SCOPE_LOCAL_ONLY,
        )],
    )
    .await?;
    if !list_response.status().is_success() {
        return Err(format!(
            "peer bucket list status {}",
            list_response.status().as_u16()
        ));
    }
    let mut responder_membership_view_id = None::<String>;
    let observed_membership_view_id = storage::extract_internal_peer_membership_view_id(
        list_response.headers(),
        peer,
        "ListConsoleBuckets",
    )?;
    storage::ensure_stable_internal_peer_membership_view_id(
        &mut responder_membership_view_id,
        observed_membership_view_id.as_str(),
        peer,
        "ListConsoleBuckets",
    )?;

    let list_body = list_response.text().await.map_err(|err| err.to_string())?;
    let peer_listing =
        from_str::<PeerListAllMyBucketsResult>(&list_body).map_err(|err| err.to_string())?;

    let mut buckets = Vec::with_capacity(peer_listing.buckets.bucket.len());
    for bucket in peer_listing.buckets.bucket {
        let versioning = fetch_peer_bucket_versioning(
            state,
            peer,
            bucket.name.as_str(),
            &mut responder_membership_view_id,
        )
        .await?;
        buckets.push(BucketSummary {
            name: bucket.name,
            created_at: bucket.creation_date,
            versioning,
        });
    }

    let membership_view_id = responder_membership_view_id.ok_or_else(|| {
        format!(
            "Peer metadata fan-in response for 'ListConsoleBuckets' from '{peer}' did not yield a responder membership view id",
        )
    })?;
    Ok(PeerBucketSummariesFanInResult {
        membership_view_id,
        buckets,
    })
}

async fn fetch_peer_bucket_versioning(
    state: &AppState,
    peer: &str,
    bucket: &str,
    responder_membership_view_id: &mut Option<String>,
) -> Result<bool, String> {
    let path = format!("/{}", bucket);
    let versioning_response = storage::send_internal_peer_get(
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
    if !versioning_response.status().is_success() {
        return Err(format!(
            "peer bucket versioning status {}",
            versioning_response.status().as_u16()
        ));
    }
    let observed_membership_view_id = storage::extract_internal_peer_membership_view_id(
        versioning_response.headers(),
        peer,
        "ListConsoleBuckets",
    )?;
    storage::ensure_stable_internal_peer_membership_view_id(
        responder_membership_view_id,
        observed_membership_view_id.as_str(),
        peer,
        "ListConsoleBuckets",
    )?;

    let versioning_body = versioning_response
        .text()
        .await
        .map_err(|err| err.to_string())?;
    let parsed =
        from_str::<PeerVersioningConfiguration>(&versioning_body).map_err(|err| err.to_string())?;
    Ok(parsed.status.as_deref() == Some("Enabled"))
}

fn merge_cluster_bucket_summaries_with_topology_snapshot(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    fan_in: ClusterBucketListingFanIn,
) -> Result<Vec<BucketSummary>, String> {
    let node_pages = fan_in
        .bucket_pages
        .iter()
        .map(|node_page| MetadataNodeBucketsPage {
            node_id: node_page.node_id.clone(),
            buckets: node_page
                .buckets
                .iter()
                .map(|bucket| BucketMetadataState::new(bucket.name.clone()))
                .collect(),
        })
        .collect::<Vec<_>>();
    let merged = merge_cluster_list_buckets_page_with_topology_snapshot(
        Some(topology.membership_view_id.as_str()),
        state.metadata_listing_strategy,
        topology.node_id.as_str(),
        topology.membership_nodes.as_slice(),
        node_pages.as_slice(),
    )
    .map_err(|_| "Distributed bucket metadata fan-in merge failed".to_string())?;
    if let Some(reason) =
        cluster_metadata_readiness_reject_reason(&merged.snapshot.readiness_assessment)
    {
        return Err(format!(
            "Distributed metadata listing strategy is not ready for this request ({})",
            reason.as_str()
        ));
    }

    let mut bucket_summaries = Vec::with_capacity(merged.buckets.len());
    for bucket_state in merged.buckets {
        let mut creation_date = None::<String>;
        let mut versioning_states = Vec::with_capacity(fan_in.bucket_pages.len());
        for node_page in fan_in.bucket_pages.as_slice() {
            let page_bucket = node_page
                .buckets
                .iter()
                .find(|bucket| bucket.name == bucket_state.bucket);
            if let Some(bucket) = page_bucket {
                versioning_states.push(ClusterBucketMetadataResponderState::Present(
                    bucket.versioning,
                ));
                if creation_date
                    .as_ref()
                    .is_none_or(|current| bucket.created_at < *current)
                {
                    creation_date = Some(bucket.created_at.clone());
                }
            }
        }

        if versioning_states.is_empty() {
            return Err(format!(
                "Distributed bucket metadata fan-in did not include any versioning responders for '{}'",
                bucket_state.bucket
            ));
        }
        let versioning_assessment =
            assess_cluster_bucket_metadata_consistency(versioning_states.as_slice());
        let versioning = match versioning_assessment.gap {
            Some(ClusterBucketMetadataConsistencyGap::InconsistentResponderValues) => {
                return Err(format!(
                    "Distributed bucket versioning state is inconsistent across responder nodes for '{}'",
                    bucket_state.bucket
                ));
            }
            Some(ClusterBucketMetadataConsistencyGap::MissingBucketOnResponder)
            | Some(ClusterBucketMetadataConsistencyGap::NoResponderValues)
            | None => {
                versioning_assessment.value.ok_or_else(|| {
                    format!(
                        "Distributed bucket metadata fan-in did not include any versioning responders for '{}'",
                        bucket_state.bucket
                    )
                })?
            }
        };
        let created_at = creation_date.ok_or_else(|| {
            format!(
                "Distributed bucket metadata fan-in did not include creation-date state for '{}'",
                bucket_state.bucket
            )
        })?;
        bucket_summaries.push(BucketSummary {
            name: bucket_state.bucket,
            created_at,
            versioning,
        });
    }
    Ok(bucket_summaries)
}

#[derive(serde::Deserialize)]
pub(super) struct CreateBucketRequest {
    name: String,
}

pub(super) async fn create_bucket(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    Json(body): Json<CreateBucketRequest>,
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
    if !internal_local_only && !should_fan_in && !use_consensus_bucket_metadata {
        if let Some(err) = storage::reject_unready_bucket_metadata_operation(&state, "CreateBucket")
        {
            return err;
        }
    }
    if use_consensus_bucket_metadata {
        if let Err(err) = storage::ensure_consensus_index_create_bucket_preconditions(
            &state,
            &topology,
            body.name.as_str(),
            "CreateBucket",
        ) {
            return *err;
        }
    }

    let now = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();
    let meta = BucketMeta {
        name: body.name.clone(),
        created_at: now,
        region: state.config.region.clone(),
        versioning: false,
    };

    match state.storage.create_bucket(&meta).await {
        Ok(true) => {}
        Ok(false) => return response::error(StatusCode::CONFLICT, "Bucket already exists"),
        Err(e) => return response::error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }

    if let Err(err) = storage::persist_bucket_metadata_operation(
        &state,
        &topology,
        "CreateBucket",
        &BucketMetadataOperation::CreateBucket {
            bucket: body.name.clone(),
            at_unix_ms: storage::current_unix_ms_u64(),
        },
    ) {
        return *err;
    }

    if should_fan_in {
        let responder_nodes =
            match fan_out_create_bucket_mutation_to_peers(&state, &topology, body.name.as_str())
                .await
            {
                Ok(nodes) => nodes,
                Err(err) => return response::error(StatusCode::SERVICE_UNAVAILABLE, err),
            };
        if let Some(err) = storage::reject_unready_bucket_metadata_operation_for_responders(
            &state,
            "CreateBucket",
            responder_nodes.as_slice(),
        ) {
            return err;
        }
        let fan_in =
            match fetch_cluster_bucket_presence_fan_in(&state, &topology, body.name.as_str()).await
            {
                Ok(fan_in) => fan_in,
                Err(err) => return response::error(StatusCode::SERVICE_UNAVAILABLE, err),
            };
        if let Some(err) = storage::reject_unready_bucket_metadata_operation_for_responders(
            &state,
            "CreateBucket",
            fan_in.responded_nodes.as_slice(),
        ) {
            return err;
        }
        if let Err(err) = ensure_cluster_bucket_presence_converged(
            body.name.as_str(),
            "CreateBucket",
            true,
            fan_in.bucket_presence_states.as_slice(),
        ) {
            return response::error(StatusCode::SERVICE_UNAVAILABLE, err);
        }
    }

    response::ok()
}

pub(super) async fn delete_bucket_api(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
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
    if !internal_local_only && !should_fan_in && !use_consensus_bucket_metadata {
        if let Some(err) = storage::reject_unready_bucket_metadata_operation(&state, "DeleteBucket")
        {
            return err;
        }
    }
    if use_consensus_bucket_metadata {
        if let Err(err) = storage::ensure_consensus_index_delete_bucket_preconditions(
            &state,
            &topology,
            bucket.as_str(),
            "DeleteBucket",
        ) {
            return *err;
        }
    }

    match state.storage.delete_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return response::error(StatusCode::NOT_FOUND, "Bucket not found"),
        Err(StorageError::BucketNotEmpty) => {
            return response::error(StatusCode::CONFLICT, "Bucket is not empty");
        }
        Err(e) => return response::error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }

    if let Err(err) = storage::persist_bucket_metadata_operation(
        &state,
        &topology,
        "DeleteBucket",
        &BucketMetadataOperation::DeleteBucket {
            bucket: bucket.clone(),
            deleted_at_unix_ms: storage::current_unix_ms_u64(),
            retain_tombstone_for_ms: storage::persisted_bucket_tombstone_retention_ms(),
        },
    ) {
        return *err;
    }

    if should_fan_in {
        let responder_nodes =
            match fan_out_delete_bucket_mutation_to_peers(&state, &topology, bucket.as_str()).await
            {
                Ok(nodes) => nodes,
                Err(err) => return response::error(StatusCode::SERVICE_UNAVAILABLE, err),
            };
        if let Some(err) = storage::reject_unready_bucket_metadata_operation_for_responders(
            &state,
            "DeleteBucket",
            responder_nodes.as_slice(),
        ) {
            return err;
        }
        let fan_in =
            match fetch_cluster_bucket_presence_fan_in(&state, &topology, bucket.as_str()).await {
                Ok(fan_in) => fan_in,
                Err(err) => return response::error(StatusCode::SERVICE_UNAVAILABLE, err),
            };
        if let Some(err) = storage::reject_unready_bucket_metadata_operation_for_responders(
            &state,
            "DeleteBucket",
            fan_in.responded_nodes.as_slice(),
        ) {
            return err;
        }
        if let Err(err) = ensure_cluster_bucket_presence_converged(
            bucket.as_str(),
            "DeleteBucket",
            false,
            fan_in.bucket_presence_states.as_slice(),
        ) {
            return response::error(StatusCode::SERVICE_UNAVAILABLE, err);
        }
    }

    response::ok()
}

fn parse_peer_error_code(xml: &str) -> Option<String> {
    from_str::<PeerErrorResponse>(xml).ok()?.code
}

async fn fan_out_create_bucket_mutation_to_peers(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    bucket: &str,
) -> Result<Vec<String>, String> {
    let mut responded_nodes = vec![topology.node_id.clone()];
    let path = format!("/{}", bucket);
    let query = [(
        storage::INTERNAL_METADATA_SCOPE_QUERY_PARAM,
        storage::INTERNAL_METADATA_SCOPE_LOCAL_ONLY,
    )];

    for peer in &topology.cluster_peers {
        let response =
            storage::send_internal_peer_request(state, peer, Method::PUT, path.as_str(), &query, None)
                .await
                .map_err(|err| {
                    format!(
                        "Distributed bucket metadata mutation 'CreateBucket' failed while contacting responder node '{}': {}",
                        peer, err
                    )
                })?;
        let status = response.status();
        if status.is_success() || status == StatusCode::CONFLICT {
            responded_nodes.push(peer.clone());
            continue;
        }

        return Err(format!(
            "Distributed bucket metadata mutation 'CreateBucket' failed on responder node '{}' with status {}",
            peer,
            status.as_u16()
        ));
    }

    Ok(responded_nodes)
}

async fn fan_out_delete_bucket_mutation_to_peers(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    bucket: &str,
) -> Result<Vec<String>, String> {
    let mut responded_nodes = vec![topology.node_id.clone()];
    let path = format!("/{}", bucket);
    let query = [(
        storage::INTERNAL_METADATA_SCOPE_QUERY_PARAM,
        storage::INTERNAL_METADATA_SCOPE_LOCAL_ONLY,
    )];

    for peer in &topology.cluster_peers {
        let response = storage::send_internal_peer_request(
            state,
            peer,
            Method::DELETE,
            path.as_str(),
            &query,
            None,
        )
        .await
        .map_err(|err| {
            format!(
                "Distributed bucket metadata mutation 'DeleteBucket' failed while contacting responder node '{}': {}",
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
                "Distributed bucket metadata mutation 'DeleteBucket' failed while reading responder error payload from node '{}': {}",
                peer, err
            )
        })?;
        if status == StatusCode::NOT_FOUND
            && parse_peer_error_code(body.as_str()).as_deref() == Some("NoSuchBucket")
        {
            responded_nodes.push(peer.clone());
            continue;
        }
        if status == StatusCode::CONFLICT
            && parse_peer_error_code(body.as_str()).as_deref() == Some("BucketNotEmpty")
        {
            return Err(format!(
                "Distributed bucket metadata mutation 'DeleteBucket' failed because bucket '{}' is not empty on responder node '{}'",
                bucket, peer
            ));
        }
        return Err(format!(
            "Distributed bucket metadata mutation 'DeleteBucket' failed on responder node '{}' with status {}",
            peer,
            status.as_u16()
        ));
    }

    Ok(responded_nodes)
}

async fn fetch_cluster_bucket_presence_fan_in(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    bucket: &str,
) -> Result<ClusterBucketPresenceFanIn, String> {
    let local_exists = state
        .storage
        .head_bucket(bucket)
        .await
        .map_err(|err| err.to_string())?;
    let local_state = if local_exists {
        ClusterBucketMetadataResponderState::Present(true)
    } else {
        ClusterBucketMetadataResponderState::MissingBucket
    };

    let mut responded_nodes = vec![topology.node_id.clone()];
    let mut bucket_presence_states = vec![local_state];
    for peer in &topology.cluster_peers {
        match fetch_peer_bucket_presence_state(state, peer, bucket).await {
            Ok(peer_state) => {
                responded_nodes.push(peer.clone());
                bucket_presence_states.push(peer_state);
            }
            Err(err) => {
                tracing::warn!(
                    peer = %peer,
                    bucket,
                    error = %err,
                    "Console bucket presence fan-in peer request failed"
                );
            }
        }
    }

    Ok(ClusterBucketPresenceFanIn {
        responded_nodes,
        bucket_presence_states,
    })
}

async fn fetch_peer_bucket_presence_state(
    state: &AppState,
    peer: &str,
    bucket: &str,
) -> Result<ClusterBucketMetadataResponderState<bool>, String> {
    let path = format!("/{}", bucket);
    let query = [(
        storage::INTERNAL_METADATA_SCOPE_QUERY_PARAM,
        storage::INTERNAL_METADATA_SCOPE_LOCAL_ONLY,
    )];
    let response =
        storage::send_internal_peer_request(state, peer, Method::HEAD, path.as_str(), &query, None)
            .await?;
    let status = response.status();
    if status.is_success() {
        return Ok(ClusterBucketMetadataResponderState::Present(true));
    }
    if status == StatusCode::NOT_FOUND {
        return Ok(ClusterBucketMetadataResponderState::MissingBucket);
    }

    Err(format!("peer bucket presence status {}", status.as_u16()))
}

fn ensure_cluster_bucket_presence_converged(
    bucket: &str,
    operation: &str,
    expect_present: bool,
    states: &[ClusterBucketMetadataResponderState<bool>],
) -> Result<(), String> {
    let expectation = if expect_present {
        ClusterBucketPresenceConvergenceExpectation::Present
    } else {
        ClusterBucketPresenceConvergenceExpectation::Missing
    };
    if assess_cluster_bucket_presence_convergence(states, expectation).converged {
        return Ok(());
    }

    Err(format!(
        "Distributed bucket metadata mutation '{}' did not converge for '{}'",
        operation, bucket
    ))
}
