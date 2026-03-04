mod service;
mod validation;

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::time::Duration;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::Response,
};
use chrono::Utc;
use quick_xml::de::from_str;
use serde::Deserialize;

use crate::api::object::peer_transport::{
    attest_internal_peer_target, build_internal_peer_http_client,
};
use crate::auth::signature_v4::{PresignRequest, generate_presigned_url};
use crate::cluster::authenticator::{FORWARDED_BY_HEADER, authenticate_forwarded_request};
use crate::cluster::security::INTERNAL_AUTH_TOKEN_HEADER;
use crate::error::{S3Error, S3ErrorCode};
use crate::metadata::{
    BucketMetadataOperation, BucketMetadataOperationError, BucketMetadataState,
    ClusterBucketMetadataConvergenceAssessment, ClusterBucketMetadataConvergenceGap,
    ClusterBucketMetadataConvergenceInputError, ClusterBucketMetadataReadResolution,
    ClusterBucketMetadataResponderState, ClusterBucketPresenceConvergenceExpectation,
    ClusterBucketPresenceReadResolution, ClusterMetadataListingStrategy,
    ClusterResponderMembershipView, MetadataNodeBucketsPage, PersistedBucketMetadataOperationError,
    PersistedBucketMutationPreconditionResolution, PersistedMetadataQueryError,
    apply_bucket_metadata_operation_to_persisted_state,
    assess_cluster_bucket_metadata_convergence_for_responder_states,
    assess_cluster_bucket_presence_convergence,
    assess_cluster_metadata_snapshot_for_topology_responders,
    assess_cluster_metadata_snapshot_for_topology_single_responder,
    assess_cluster_responder_membership_views, cluster_metadata_readiness_reject_reason,
    list_buckets_from_persisted_state_with_view_id, load_persisted_metadata_state,
    merge_cluster_list_buckets_page_with_topology_snapshot,
    resolve_bucket_metadata_from_persisted_state,
    resolve_bucket_mutation_preconditions_from_persisted_state,
    resolve_cluster_bucket_metadata_for_read, resolve_cluster_bucket_presence_for_read,
};
use crate::server::{AppState, runtime_topology_snapshot};
use crate::storage::{BucketMeta, StorageError, lifecycle::LifecycleRule as StorageLifecycleRule};
use crate::xml::types::*;
use service::{
    empty_response, ensure_bucket_exists, map_bucket_storage_err, map_lifecycle_storage_err,
    xml_response,
};
use validation::{
    parse_lifecycle_rules, parse_versioning_status, serialize_lifecycle_rules, validate_bucket_name,
};

const INTERNAL_METADATA_SCOPE_QUERY_PARAM: &str = "x-maxio-internal-metadata-scope";
const INTERNAL_METADATA_SCOPE_LOCAL_ONLY: &str = "local-node-only";
const INTERNAL_MEMBERSHIP_VIEW_ID_HEADER: &str = "x-maxio-internal-membership-view-id";
const PERSISTED_METADATA_STATE_FILE: &str = "cluster-metadata-state.json";
const CONSENSUS_INDEX_CREATION_DATE_FALLBACK: &str = "1970-01-01T00:00:00.000Z";
const PERSISTED_BUCKET_TOMBSTONE_RETENTION_MS: u64 = 5 * 60 * 1000;

struct ClusterBucketListingFanIn {
    bucket_pages: Vec<MetadataNodeBucketsPage>,
    bucket_creation_dates: BTreeMap<String, String>,
}

struct ClusterBucketPresenceFanIn {
    responded_nodes: Vec<String>,
    bucket_presence_states: Vec<ClusterBucketMetadataResponderState<bool>>,
}

struct ClusterBucketVersioningFanIn {
    responded_nodes: Vec<String>,
    versioning_states: Vec<ClusterBucketMetadataResponderState<bool>>,
}

struct ClusterBucketLifecycleFanIn {
    responded_nodes: Vec<String>,
    lifecycle_states: Vec<ClusterBucketMetadataResponderState<BucketLifecycleResponderValue>>,
}

struct PeerBucketEntriesFanInResult {
    membership_view_id: String,
    entries: Vec<BucketEntry>,
}

struct PeerBucketPresenceStateFanInResult {
    membership_view_id: Option<String>,
    state: ClusterBucketMetadataResponderState<bool>,
}

struct PeerBucketVersioningStateFanInResult {
    membership_view_id: Option<String>,
    state: ClusterBucketMetadataResponderState<bool>,
}

struct PeerBucketLifecycleStateFanInResult {
    membership_view_id: Option<String>,
    state: ClusterBucketMetadataResponderState<BucketLifecycleResponderValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BucketLifecycleResponderValue {
    NoLifecycleConfiguration,
    Rules(Vec<StorageLifecycleRule>),
}

#[derive(Deserialize)]
#[serde(rename = "VersioningConfiguration")]
struct PeerVersioningConfiguration {
    #[serde(rename = "Status")]
    status: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename = "Error")]
struct PeerErrorResponse {
    #[serde(rename = "Code")]
    code: Option<String>,
}

pub async fn list_buckets(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response<Body>, S3Error> {
    let topology = runtime_topology_snapshot(&state);
    let internal_local_only =
        is_trusted_internal_local_metadata_scope_request(&state, &headers, &params);
    let buckets =
        if should_attempt_cluster_bucket_metadata_fan_in(&state, &topology, internal_local_only) {
            let fan_in = fetch_cluster_bucket_listing_fan_in(&state, &topology).await?;
            merge_cluster_bucket_entries_with_topology_snapshot(&state, &topology, fan_in)?
        } else {
            let use_consensus_persisted_metadata =
                should_use_consensus_index_persisted_metadata_state(
                    &state,
                    &topology,
                    internal_local_only,
                );
            if !internal_local_only && !use_consensus_persisted_metadata {
                ensure_distributed_bucket_listing_strategy_ready(&state)?;
            }
            if use_consensus_persisted_metadata {
                load_persisted_bucket_metadata_state(&state, "ListBuckets")?
                    .into_iter()
                    .map(|bucket| BucketEntry {
                        name: bucket.bucket,
                        creation_date: CONSENSUS_INDEX_CREATION_DATE_FALLBACK.to_string(),
                    })
                    .collect::<Vec<_>>()
            } else {
                state
                    .storage
                    .list_buckets()
                    .await
                    .map_err(S3Error::internal)?
                    .into_iter()
                    .map(|bucket| BucketEntry {
                        name: bucket.name,
                        creation_date: bucket.created_at,
                    })
                    .collect::<Vec<_>>()
            }
        };

    let result = ListAllMyBucketsResult {
        owner: Owner {
            id: "maxio".to_string(),
            display_name: "maxio".to_string(),
        },
        buckets: Buckets { bucket: buckets },
    };

    let mut response = xml_response(StatusCode::OK, &result)?;
    apply_internal_membership_view_header(response.headers_mut(), &topology, internal_local_only);
    Ok(response)
}

fn ensure_distributed_bucket_listing_strategy_ready(state: &AppState) -> Result<(), S3Error> {
    let topology = runtime_topology_snapshot(state);
    let responder_nodes = [topology.node_id.clone()];
    ensure_distributed_bucket_listing_strategy_ready_for_responders(
        state,
        &topology,
        responder_nodes.as_slice(),
    )
}

fn ensure_distributed_bucket_metadata_operation_strategy_ready(
    state: &AppState,
    operation: &str,
) -> Result<(), S3Error> {
    let topology = runtime_topology_snapshot(state);
    let responder_nodes = [topology.node_id.clone()];
    ensure_distributed_bucket_metadata_operation_strategy_ready_for_responders(
        state,
        &topology,
        operation,
        responder_nodes.as_slice(),
    )
}

fn ensure_distributed_bucket_listing_strategy_ready_for_responders(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    responder_nodes: &[String],
) -> Result<(), S3Error> {
    if !topology.is_distributed() {
        return Ok(());
    }
    let snapshot_assessment = assess_cluster_metadata_snapshot_for_topology_responders(
        state.metadata_listing_strategy,
        Some(topology.membership_view_id.as_str()),
        topology.node_id.as_str(),
        topology.membership_nodes.as_slice(),
        responder_nodes,
    )
    .unwrap_or_else(|_| {
        assess_cluster_metadata_snapshot_for_topology_single_responder(
            state.metadata_listing_strategy,
            Some(topology.membership_view_id.as_str()),
            topology.node_id.as_str(),
            topology.membership_nodes.as_slice(),
            topology.node_id.as_str(),
        )
    });
    if let Some(reason) =
        cluster_metadata_readiness_reject_reason(&snapshot_assessment.readiness_assessment)
    {
        let message = format!(
            "Distributed metadata listing strategy is not ready for this request ({})",
            reason.as_str()
        );
        return Err(S3Error::service_unavailable(message.as_str()));
    }
    Ok(())
}

fn ensure_distributed_bucket_metadata_operation_strategy_ready_for_responders(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    operation: &str,
    responder_nodes: &[String],
) -> Result<(), S3Error> {
    if !topology.is_distributed() {
        return Ok(());
    }
    let snapshot_assessment = assess_cluster_metadata_snapshot_for_topology_responders(
        state.metadata_listing_strategy,
        Some(topology.membership_view_id.as_str()),
        topology.node_id.as_str(),
        topology.membership_nodes.as_slice(),
        responder_nodes,
    )
    .unwrap_or_else(|_| {
        assess_cluster_metadata_snapshot_for_topology_single_responder(
            state.metadata_listing_strategy,
            Some(topology.membership_view_id.as_str()),
            topology.node_id.as_str(),
            topology.membership_nodes.as_slice(),
            topology.node_id.as_str(),
        )
    });
    if let Some(reason) =
        cluster_metadata_readiness_reject_reason(&snapshot_assessment.readiness_assessment)
    {
        let message = format!(
            "Distributed metadata strategy is not ready for bucket metadata operation '{}' ({})",
            operation,
            reason.as_str()
        );
        return Err(S3Error::service_unavailable(message.as_str()));
    }
    Ok(())
}

fn should_attempt_cluster_bucket_metadata_fan_in(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    internal_local_only: bool,
) -> bool {
    if internal_local_only || !topology.is_distributed() {
        return false;
    }
    if !cluster_auth_token_configured(state) {
        return false;
    }
    matches!(
        state.metadata_listing_strategy,
        ClusterMetadataListingStrategy::RequestTimeAggregation
            | ClusterMetadataListingStrategy::FullReplication
    )
}

fn cluster_auth_token_configured(state: &AppState) -> bool {
    state
        .config
        .cluster_auth_token()
        .is_some_and(|value| !value.trim().is_empty())
}

fn should_use_consensus_index_persisted_metadata_state(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
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

fn current_unix_ms_u64() -> u64 {
    u64::try_from(Utc::now().timestamp_millis()).map_or(0, |value| value)
}

fn persist_bucket_metadata_operation(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    operation_name: &str,
    operation: &BucketMetadataOperation,
) -> Result<(), S3Error> {
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
        S3Error::service_unavailable(message.as_str())
    })
}

fn load_persisted_bucket_metadata_state(
    state: &AppState,
    operation: &str,
) -> Result<Vec<BucketMetadataState>, S3Error> {
    let topology = runtime_topology_snapshot(state);
    let state_path = persisted_metadata_state_path(state.config.data_dir.as_str());
    let persisted_state = load_persisted_metadata_state(state_path.as_path()).map_err(|err| {
        S3Error::service_unavailable(&format!(
            "Distributed bucket metadata operation '{}' cannot load consensus metadata state: {}",
            operation, err
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
        } => S3Error::service_unavailable(&format!(
            "Distributed bucket metadata operation '{}' cannot query consensus metadata state: persisted metadata view mismatch (expected='{}', persisted='{}')",
            operation, expected_view_id, persisted_view_id
        )),
        _ => S3Error::service_unavailable(&format!(
            "Distributed bucket metadata operation '{}' cannot query consensus metadata state: {:?}",
            operation, err
        )),
    })
}

fn bucket_metadata_state_from_consensus_index(
    state: &AppState,
    bucket: &str,
    operation: &str,
) -> Result<BucketMetadataState, S3Error> {
    let topology = runtime_topology_snapshot(state);
    let state_path = persisted_metadata_state_path(state.config.data_dir.as_str());
    let persisted_state = load_persisted_metadata_state(state_path.as_path()).map_err(|err| {
        S3Error::service_unavailable(&format!(
            "Distributed bucket metadata operation '{}' cannot load consensus metadata state: {}",
            operation, err
        ))
    })?;

    match resolve_bucket_metadata_from_persisted_state(
        &persisted_state,
        bucket,
        Some(topology.membership_view_id.as_str()),
    ) {
        Ok(crate::metadata::PersistedBucketMetadataReadResolution::Present(bucket_state)) => {
            Ok(bucket_state)
        }
        Ok(crate::metadata::PersistedBucketMetadataReadResolution::Missing) => {
            Err(S3Error::no_such_bucket(bucket))
        }
        Err(PersistedMetadataQueryError::ViewIdMismatch {
            expected_view_id,
            persisted_view_id,
        }) => Err(S3Error::service_unavailable(&format!(
            "Distributed bucket metadata operation '{}' cannot query consensus metadata state: persisted metadata view mismatch (expected='{}', persisted='{}')",
            operation, expected_view_id, persisted_view_id
        ))),
        Err(err) => Err(S3Error::service_unavailable(&format!(
            "Distributed bucket metadata operation '{}' cannot query consensus metadata state: {:?}",
            operation, err
        ))),
    }
}

fn ensure_consensus_index_create_bucket_preconditions(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    bucket: &str,
    operation: &str,
) -> Result<(), S3Error> {
    let state_path = persisted_metadata_state_path(state.config.data_dir.as_str());
    let persisted_state = load_persisted_metadata_state(state_path.as_path()).map_err(|err| {
        S3Error::service_unavailable(&format!(
            "Distributed bucket metadata operation '{}' cannot load consensus metadata state: {}",
            operation, err
        ))
    })?;

    match resolve_bucket_mutation_preconditions_from_persisted_state(
        &persisted_state,
        bucket,
        Some(topology.membership_view_id.as_str()),
        current_unix_ms_u64(),
    ) {
        Ok(PersistedBucketMutationPreconditionResolution::Present(_)) => {
            Err(S3Error::bucket_already_owned(bucket))
        }
        Ok(PersistedBucketMutationPreconditionResolution::Tombstoned {
            retention_active: true,
            ..
        }) => Err(S3Error::service_unavailable(&format!(
            "Distributed bucket metadata operation '{}' rejected create for '{}' because tombstone retention is still active",
            operation, bucket
        ))),
        Ok(PersistedBucketMutationPreconditionResolution::Tombstoned {
            retention_active: false,
            ..
        })
        | Ok(PersistedBucketMutationPreconditionResolution::Missing) => Ok(()),
        Err(PersistedMetadataQueryError::ViewIdMismatch {
            expected_view_id,
            persisted_view_id,
        }) => Err(S3Error::service_unavailable(&format!(
            "Distributed bucket metadata operation '{}' cannot query consensus metadata state: persisted metadata view mismatch (expected='{}', persisted='{}')",
            operation, expected_view_id, persisted_view_id
        ))),
        Err(err) => Err(S3Error::service_unavailable(&format!(
            "Distributed bucket metadata operation '{}' cannot query consensus metadata state: {:?}",
            operation, err
        ))),
    }
}

fn ensure_consensus_index_delete_bucket_preconditions(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    bucket: &str,
    operation: &str,
) -> Result<(), S3Error> {
    let state_path = persisted_metadata_state_path(state.config.data_dir.as_str());
    let persisted_state = load_persisted_metadata_state(state_path.as_path()).map_err(|err| {
        S3Error::service_unavailable(&format!(
            "Distributed bucket metadata operation '{}' cannot load consensus metadata state: {}",
            operation, err
        ))
    })?;

    match resolve_bucket_mutation_preconditions_from_persisted_state(
        &persisted_state,
        bucket,
        Some(topology.membership_view_id.as_str()),
        current_unix_ms_u64(),
    ) {
        Ok(PersistedBucketMutationPreconditionResolution::Present(_)) => Ok(()),
        Ok(PersistedBucketMutationPreconditionResolution::Tombstoned { .. })
        | Ok(PersistedBucketMutationPreconditionResolution::Missing) => {
            Err(S3Error::no_such_bucket(bucket))
        }
        Err(PersistedMetadataQueryError::ViewIdMismatch {
            expected_view_id,
            persisted_view_id,
        }) => Err(S3Error::service_unavailable(&format!(
            "Distributed bucket metadata operation '{}' cannot query consensus metadata state: persisted metadata view mismatch (expected='{}', persisted='{}')",
            operation, expected_view_id, persisted_view_id
        ))),
        Err(err) => Err(S3Error::service_unavailable(&format!(
            "Distributed bucket metadata operation '{}' cannot query consensus metadata state: {:?}",
            operation, err
        ))),
    }
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

async fn fetch_cluster_bucket_listing_fan_in(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
) -> Result<ClusterBucketListingFanIn, S3Error> {
    let local_entries = state
        .storage
        .list_buckets()
        .await
        .map_err(S3Error::internal)?
        .into_iter()
        .map(|bucket| BucketEntry {
            name: bucket.name,
            creation_date: bucket.created_at,
        })
        .collect::<Vec<_>>();

    let mut bucket_pages = vec![MetadataNodeBucketsPage {
        node_id: topology.node_id.clone(),
        buckets: bucket_entries_to_metadata_states(local_entries.as_slice()),
    }];
    let mut bucket_creation_dates = merge_bucket_creation_dates(local_entries, BTreeMap::new());
    let mut responder_views = Vec::<ClusterResponderMembershipView>::new();
    for peer in &topology.cluster_peers {
        match fetch_peer_bucket_entries(state, peer).await {
            Ok(peer_entries) => {
                bucket_pages.push(MetadataNodeBucketsPage {
                    node_id: peer.clone(),
                    buckets: bucket_entries_to_metadata_states(peer_entries.entries.as_slice()),
                });
                bucket_creation_dates =
                    merge_bucket_creation_dates(peer_entries.entries, bucket_creation_dates);
                responder_views.push(ClusterResponderMembershipView {
                    node_id: peer.clone(),
                    membership_view_id: Some(peer_entries.membership_view_id),
                });
            }
            Err(err) => {
                tracing::warn!(
                    peer = %peer,
                    error = ?err,
                    "Failed to fetch peer bucket list for distributed metadata fan-in"
                );
            }
        }
    }
    ensure_peer_responder_membership_views_consistent("ListBuckets", responder_views.as_slice())?;

    Ok(ClusterBucketListingFanIn {
        bucket_pages,
        bucket_creation_dates,
    })
}

async fn fetch_peer_bucket_entries(
    state: &AppState,
    peer: &str,
) -> Result<PeerBucketEntriesFanInResult, S3Error> {
    let local_scope_query = [(
        INTERNAL_METADATA_SCOPE_QUERY_PARAM,
        INTERNAL_METADATA_SCOPE_LOCAL_ONLY,
    )];
    let response = send_internal_peer_get(state, peer, "/", &local_scope_query).await?;
    if !response.status().is_success() {
        return Err(S3Error::service_unavailable(
            "Peer bucket listing request failed",
        ));
    }
    let membership_view_id =
        extract_internal_peer_membership_view_id(response.headers(), peer, "ListBuckets")?;
    let body = response.text().await.map_err(S3Error::internal)?;
    let parsed =
        from_str::<ListAllMyBucketsResult>(&body).map_err(|_| S3Error::internal("Invalid XML"))?;
    Ok(PeerBucketEntriesFanInResult {
        membership_view_id,
        entries: parsed.buckets.bucket,
    })
}

async fn send_internal_peer_get(
    state: &AppState,
    peer: &str,
    path: &str,
    extra_query_params: &[(&str, &str)],
) -> Result<reqwest::Response, S3Error> {
    send_internal_peer_request(state, peer, Method::GET, path, extra_query_params, None).await
}

async fn send_internal_peer_request(
    state: &AppState,
    peer: &str,
    method: Method,
    path: &str,
    extra_query_params: &[(&str, &str)],
    body: Option<Vec<u8>>,
) -> Result<reqwest::Response, S3Error> {
    attest_internal_peer_target(state, peer, Duration::from_secs(2))?;
    let transport = build_internal_peer_http_client(
        state,
        Some(Duration::from_secs(2)),
        Duration::from_secs(10),
    )?;
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
    .map_err(S3Error::internal)?;

    let mut request = transport
        .client
        .request(method, presigned_url)
        .header(FORWARDED_BY_HEADER, state.node_id.as_ref());
    if let Some(token) = state
        .config
        .cluster_auth_token()
        .filter(|value| !value.trim().is_empty())
    {
        request = request.header(INTERNAL_AUTH_TOKEN_HEADER, token);
    }
    if let Some(payload) = body {
        request = request.body(payload);
    }

    request.send().await.map_err(S3Error::internal)
}

async fn fan_out_bucket_metadata_mutation_to_peers(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    bucket: &str,
    method: Method,
    operation: &str,
    query_flag: &str,
    body: Option<Vec<u8>>,
) -> Result<Vec<String>, S3Error> {
    let mut responded_nodes = vec![topology.node_id.clone()];
    let path = format!("/{}", bucket);
    let query = [
        (query_flag, ""),
        (
            INTERNAL_METADATA_SCOPE_QUERY_PARAM,
            INTERNAL_METADATA_SCOPE_LOCAL_ONLY,
        ),
    ];

    for peer in &topology.cluster_peers {
        let response = send_internal_peer_request(
            state,
            peer,
            method.clone(),
            path.as_str(),
            &query,
            body.clone(),
        )
        .await
        .map_err(|_| {
            S3Error::service_unavailable(&format!(
                "Distributed bucket metadata mutation '{}' failed while contacting responder node '{}'",
                operation, peer
            ))
        })?;
        let status = response.status();
        if status.is_success() {
            responded_nodes.push(peer.clone());
            continue;
        }

        let body = response.text().await.unwrap_or_default();
        if status == StatusCode::NOT_FOUND
            && parse_peer_error_code(body.as_str()).as_deref() == Some("NoSuchBucket")
        {
            return Err(S3Error::service_unavailable(&format!(
                "Distributed bucket metadata mutation '{}' failed because bucket '{}' is missing on responder node '{}'",
                operation, bucket, peer
            )));
        }

        return Err(S3Error::service_unavailable(&format!(
            "Distributed bucket metadata mutation '{}' failed on responder node '{}' with status {}",
            operation,
            peer,
            status.as_u16()
        )));
    }

    Ok(responded_nodes)
}

async fn fetch_cluster_bucket_versioning_fan_in(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    bucket: &str,
) -> Result<ClusterBucketVersioningFanIn, S3Error> {
    let local_versioned = state
        .storage
        .is_versioned(bucket)
        .await
        .map_err(|err| map_bucket_storage_err(bucket, err))?;
    let mut responded_nodes = vec![topology.node_id.clone()];
    let mut versioning_states = vec![ClusterBucketMetadataResponderState::Present(
        local_versioned,
    )];
    let mut responder_views = Vec::<ClusterResponderMembershipView>::new();

    for peer in &topology.cluster_peers {
        match fetch_peer_bucket_versioning_state(state, peer, bucket).await {
            Ok(peer_response) => {
                responded_nodes.push(peer.clone());
                versioning_states.push(peer_response.state);
                if let Some(membership_view_id) = peer_response.membership_view_id {
                    responder_views.push(ClusterResponderMembershipView {
                        node_id: peer.clone(),
                        membership_view_id: Some(membership_view_id),
                    });
                }
            }
            Err(err) => {
                tracing::warn!(
                    peer = %peer,
                    bucket,
                    error = ?err,
                    "Failed to fetch peer bucket versioning for distributed metadata fan-in"
                );
            }
        }
    }
    ensure_peer_responder_membership_views_consistent(
        "GetBucketVersioning",
        responder_views.as_slice(),
    )?;

    Ok(ClusterBucketVersioningFanIn {
        responded_nodes,
        versioning_states,
    })
}

async fn fetch_peer_bucket_versioning_state(
    state: &AppState,
    peer: &str,
    bucket: &str,
) -> Result<PeerBucketVersioningStateFanInResult, S3Error> {
    let path = format!("/{}", bucket);
    let query = [
        ("versioning", ""),
        (
            INTERNAL_METADATA_SCOPE_QUERY_PARAM,
            INTERNAL_METADATA_SCOPE_LOCAL_ONLY,
        ),
    ];
    let response = send_internal_peer_get(state, peer, path.as_str(), &query).await?;
    let status = response.status();
    let response_headers = response.headers().clone();
    let body = response.text().await.map_err(S3Error::internal)?;

    if status.is_success() {
        let membership_view_id = extract_internal_peer_membership_view_id(
            &response_headers,
            peer,
            "GetBucketVersioning",
        )?;
        let parsed = from_str::<PeerVersioningConfiguration>(&body)
            .map_err(|_| S3Error::internal("Invalid XML"))?;
        return Ok(PeerBucketVersioningStateFanInResult {
            membership_view_id: Some(membership_view_id),
            state: ClusterBucketMetadataResponderState::Present(
                parsed.status.as_deref() == Some("Enabled"),
            ),
        });
    }
    if status == StatusCode::NOT_FOUND {
        let code = parse_peer_error_code(body.as_str());
        if code.as_deref() == Some("NoSuchBucket") {
            return Ok(PeerBucketVersioningStateFanInResult {
                membership_view_id: None,
                state: ClusterBucketMetadataResponderState::MissingBucket,
            });
        }
    }

    Err(S3Error::service_unavailable(
        "Peer bucket versioning request failed",
    ))
}

fn resolve_cluster_bucket_versioning_state(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    operation: &str,
    bucket: &str,
    responded_nodes: &[String],
    states: &[ClusterBucketMetadataResponderState<bool>],
) -> Result<bool, S3Error> {
    let assessment = assess_cluster_bucket_metadata_operation_convergence(
        state,
        topology,
        operation,
        responded_nodes,
        states,
    )?;
    ensure_cluster_bucket_metadata_operation_ready(operation, assessment.gap)?;
    if assessment.gap == Some(ClusterBucketMetadataConvergenceGap::NoResponderValues) {
        return Err(S3Error::service_unavailable(
            "Distributed bucket metadata fan-in did not include any versioning responders",
        ));
    }

    match resolve_cluster_bucket_metadata_for_read(states) {
        ClusterBucketMetadataReadResolution::Present(versioned) => Ok(versioned),
        ClusterBucketMetadataReadResolution::Missing => {
            Err(S3Error::service_unavailable(&format!(
                "Distributed bucket metadata is inconsistent for '{}' (bucket missing on one or more responder nodes)",
                bucket
            )))
        }
        ClusterBucketMetadataReadResolution::Inconsistent => {
            Err(S3Error::service_unavailable(&format!(
                "Distributed bucket versioning state is inconsistent across responder nodes for '{}'",
                bucket
            )))
        }
    }
}

fn assess_cluster_bucket_metadata_operation_convergence<T: Clone + Eq>(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    operation: &str,
    responded_nodes: &[String],
    states: &[ClusterBucketMetadataResponderState<T>],
) -> Result<ClusterBucketMetadataConvergenceAssessment<T>, S3Error> {
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
            S3Error::service_unavailable(&format!(
                "Distributed bucket metadata operation '{}' responder/state fan-in cardinality mismatch",
                operation
            ))
        }
        ClusterBucketMetadataConvergenceInputError::InvalidResponderTopology(_) => {
            S3Error::service_unavailable(&format!(
                "Failed to assess distributed bucket metadata convergence for operation '{}'",
                operation
            ))
        }
    })
}

fn ensure_cluster_bucket_metadata_operation_ready(
    operation: &str,
    gap: Option<ClusterBucketMetadataConvergenceGap>,
) -> Result<(), S3Error> {
    match gap {
        Some(ClusterBucketMetadataConvergenceGap::StrategyNotClusterAuthoritative)
        | Some(ClusterBucketMetadataConvergenceGap::MissingExpectedNodes)
        | Some(ClusterBucketMetadataConvergenceGap::UnexpectedResponderNodes)
        | Some(ClusterBucketMetadataConvergenceGap::MissingAndUnexpectedNodes) => {
            let reason = gap
                .map(ClusterBucketMetadataConvergenceGap::as_str)
                .unwrap_or("unknown");
            Err(S3Error::service_unavailable(&format!(
                "Distributed metadata strategy is not ready for bucket metadata operation '{}' ({})",
                operation, reason
            )))
        }
        _ => Ok(()),
    }
}

async fn fetch_cluster_bucket_lifecycle_fan_in(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    bucket: &str,
) -> Result<ClusterBucketLifecycleFanIn, S3Error> {
    let local_rules = state
        .storage
        .get_lifecycle_rules(bucket)
        .await
        .map_err(|err| map_bucket_storage_err(bucket, err))?;
    let local_state = if local_rules.is_empty() {
        ClusterBucketMetadataResponderState::Present(
            BucketLifecycleResponderValue::NoLifecycleConfiguration,
        )
    } else {
        ClusterBucketMetadataResponderState::Present(BucketLifecycleResponderValue::Rules(
            canonicalize_lifecycle_rules(local_rules),
        ))
    };

    let mut responded_nodes = vec![topology.node_id.clone()];
    let mut lifecycle_states = vec![local_state];
    let mut responder_views = Vec::<ClusterResponderMembershipView>::new();
    for peer in &topology.cluster_peers {
        match fetch_peer_bucket_lifecycle_state(state, peer, bucket).await {
            Ok(peer_response) => {
                responded_nodes.push(peer.clone());
                lifecycle_states.push(peer_response.state);
                if let Some(membership_view_id) = peer_response.membership_view_id {
                    responder_views.push(ClusterResponderMembershipView {
                        node_id: peer.clone(),
                        membership_view_id: Some(membership_view_id),
                    });
                }
            }
            Err(err) => {
                tracing::warn!(
                    peer = %peer,
                    bucket,
                    error = ?err,
                    "Failed to fetch peer bucket lifecycle for distributed metadata fan-in"
                );
            }
        }
    }
    ensure_peer_responder_membership_views_consistent(
        "GetBucketLifecycle",
        responder_views.as_slice(),
    )?;

    Ok(ClusterBucketLifecycleFanIn {
        responded_nodes,
        lifecycle_states,
    })
}

async fn fetch_peer_bucket_lifecycle_state(
    state: &AppState,
    peer: &str,
    bucket: &str,
) -> Result<PeerBucketLifecycleStateFanInResult, S3Error> {
    let path = format!("/{}", bucket);
    let query = [
        ("lifecycle", ""),
        (
            INTERNAL_METADATA_SCOPE_QUERY_PARAM,
            INTERNAL_METADATA_SCOPE_LOCAL_ONLY,
        ),
    ];
    let response = send_internal_peer_get(state, peer, path.as_str(), &query).await?;
    let status = response.status();
    let response_headers = response.headers().clone();
    let body = response.text().await.map_err(S3Error::internal)?;

    if status.is_success() {
        let membership_view_id = extract_internal_peer_membership_view_id(
            &response_headers,
            peer,
            "GetBucketLifecycle",
        )?;
        let rules = parse_lifecycle_rules(body.as_str())?;
        if rules.is_empty() {
            return Ok(PeerBucketLifecycleStateFanInResult {
                membership_view_id: Some(membership_view_id),
                state: ClusterBucketMetadataResponderState::Present(
                    BucketLifecycleResponderValue::NoLifecycleConfiguration,
                ),
            });
        }
        return Ok(PeerBucketLifecycleStateFanInResult {
            membership_view_id: Some(membership_view_id),
            state: ClusterBucketMetadataResponderState::Present(
                BucketLifecycleResponderValue::Rules(canonicalize_lifecycle_rules(rules)),
            ),
        });
    }

    if status == StatusCode::NOT_FOUND {
        let code = parse_peer_error_code(body.as_str());
        return match code.as_deref() {
            Some("NoSuchLifecycleConfiguration") => Ok(PeerBucketLifecycleStateFanInResult {
                membership_view_id: None,
                state: ClusterBucketMetadataResponderState::Present(
                    BucketLifecycleResponderValue::NoLifecycleConfiguration,
                ),
            }),
            Some("NoSuchBucket") => Ok(PeerBucketLifecycleStateFanInResult {
                membership_view_id: None,
                state: ClusterBucketMetadataResponderState::MissingBucket,
            }),
            _ => Err(S3Error::service_unavailable(
                "Peer bucket lifecycle request failed",
            )),
        };
    }

    Err(S3Error::service_unavailable(
        "Peer bucket lifecycle request failed",
    ))
}

fn resolve_cluster_bucket_lifecycle_state(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    operation: &str,
    bucket: &str,
    responded_nodes: &[String],
    states: &[ClusterBucketMetadataResponderState<BucketLifecycleResponderValue>],
) -> Result<Vec<StorageLifecycleRule>, S3Error> {
    let assessment = assess_cluster_bucket_metadata_operation_convergence(
        state,
        topology,
        operation,
        responded_nodes,
        states,
    )?;
    ensure_cluster_bucket_metadata_operation_ready(operation, assessment.gap)?;
    if assessment.gap == Some(ClusterBucketMetadataConvergenceGap::NoResponderValues) {
        return Err(S3Error::service_unavailable(
            "Distributed bucket metadata fan-in did not include any lifecycle responders",
        ));
    }

    match resolve_cluster_bucket_metadata_for_read(states) {
        ClusterBucketMetadataReadResolution::Present(
            BucketLifecycleResponderValue::NoLifecycleConfiguration,
        ) => Err(S3Error::no_such_lifecycle_configuration(bucket)),
        ClusterBucketMetadataReadResolution::Present(BucketLifecycleResponderValue::Rules(
            rules,
        )) => Ok(rules),
        ClusterBucketMetadataReadResolution::Missing => {
            Err(S3Error::service_unavailable(&format!(
                "Distributed bucket metadata is inconsistent for '{}' (bucket missing on one or more responder nodes)",
                bucket
            )))
        }
        ClusterBucketMetadataReadResolution::Inconsistent => {
            Err(S3Error::service_unavailable(&format!(
                "Distributed bucket lifecycle state is inconsistent across responder nodes for '{}'",
                bucket
            )))
        }
    }
}

fn canonicalize_lifecycle_rules(mut rules: Vec<StorageLifecycleRule>) -> Vec<StorageLifecycleRule> {
    rules.sort_by(|a, b| {
        (
            a.id.as_str(),
            a.prefix.as_str(),
            a.expiration_days,
            a.enabled,
        )
            .cmp(&(
                b.id.as_str(),
                b.prefix.as_str(),
                b.expiration_days,
                b.enabled,
            ))
    });
    rules
}

fn parse_peer_error_code(xml: &str) -> Option<String> {
    from_str::<PeerErrorResponse>(xml).ok()?.code
}

fn bucket_entries_to_metadata_states(entries: &[BucketEntry]) -> Vec<BucketMetadataState> {
    entries
        .iter()
        .map(|entry| BucketMetadataState::new(entry.name.clone()))
        .collect()
}

fn merge_bucket_creation_dates(
    entries: Vec<BucketEntry>,
    mut by_bucket_name: BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    for entry in entries {
        match by_bucket_name.get_mut(entry.name.as_str()) {
            Some(existing) => {
                if entry.creation_date < *existing {
                    *existing = entry.creation_date;
                }
            }
            None => {
                by_bucket_name.insert(entry.name, entry.creation_date);
            }
        }
    }
    by_bucket_name
}

fn merge_cluster_bucket_entries_with_topology_snapshot(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    fan_in: ClusterBucketListingFanIn,
) -> Result<Vec<BucketEntry>, S3Error> {
    let merged = merge_cluster_list_buckets_page_with_topology_snapshot(
        Some(topology.membership_view_id.as_str()),
        state.metadata_listing_strategy,
        topology.node_id.as_str(),
        topology.membership_nodes.as_slice(),
        fan_in.bucket_pages.as_slice(),
    )
    .map_err(|_| {
        S3Error::service_unavailable("Failed to merge distributed bucket listing metadata snapshot")
    })?;
    if let Some(reason) =
        cluster_metadata_readiness_reject_reason(&merged.snapshot.readiness_assessment)
    {
        let message = format!(
            "Distributed metadata listing strategy is not ready for this request ({})",
            reason.as_str()
        );
        return Err(S3Error::service_unavailable(message.as_str()));
    }

    let mut buckets = Vec::with_capacity(merged.buckets.len());
    for bucket_state in merged.buckets {
        let Some(creation_date) = fan_in
            .bucket_creation_dates
            .get(bucket_state.bucket.as_str())
            .cloned()
        else {
            return Err(S3Error::service_unavailable(
                "Distributed bucket listing merge produced unresolved bucket metadata",
            ));
        };
        buckets.push(BucketEntry {
            name: bucket_state.bucket,
            creation_date,
        });
    }
    Ok(buckets)
}

pub async fn create_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> Result<Response<Body>, S3Error> {
    create_bucket_with_context(State(state), Path(bucket), HashMap::new(), HeaderMap::new()).await
}

async fn create_bucket_with_context(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    params: HashMap<String, String>,
    headers: HeaderMap,
) -> Result<Response<Body>, S3Error> {
    validate_bucket_name(&bucket)?;
    let topology = runtime_topology_snapshot(&state);
    let internal_local_only =
        is_trusted_internal_local_metadata_scope_request(&state, &headers, &params);
    let should_fan_in =
        should_attempt_cluster_bucket_metadata_fan_in(&state, &topology, internal_local_only);
    let use_consensus_persisted_metadata =
        should_use_consensus_index_persisted_metadata_state(&state, &topology, internal_local_only);
    if !internal_local_only && !should_fan_in && !use_consensus_persisted_metadata {
        ensure_distributed_bucket_metadata_operation_strategy_ready(&state, "CreateBucket")?;
    }
    if use_consensus_persisted_metadata {
        ensure_consensus_index_create_bucket_preconditions(
            &state,
            &topology,
            bucket.as_str(),
            "CreateBucket",
        )?;
    }

    let now = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();

    let meta = BucketMeta {
        name: bucket.clone(),
        created_at: now,
        region: state.config.region.clone(),
        versioning: false,
    };

    let created = state
        .storage
        .create_bucket(&meta)
        .await
        .map_err(S3Error::internal)?;

    if !created {
        return Err(S3Error::bucket_already_owned(&bucket));
    }

    persist_bucket_metadata_operation(
        &state,
        &topology,
        "CreateBucket",
        &BucketMetadataOperation::CreateBucket {
            bucket: bucket.clone(),
            at_unix_ms: current_unix_ms_u64(),
        },
    )?;

    if should_fan_in {
        let responded_nodes =
            fan_out_create_bucket_mutation_to_peers(&state, &topology, bucket.as_str()).await?;
        ensure_distributed_bucket_metadata_operation_strategy_ready_for_responders(
            &state,
            &topology,
            "CreateBucket",
            responded_nodes.as_slice(),
        )?;
        let fan_in =
            fetch_cluster_bucket_presence_fan_in(&state, &topology, bucket.as_str()).await?;
        ensure_distributed_bucket_metadata_operation_strategy_ready_for_responders(
            &state,
            &topology,
            "CreateBucket",
            fan_in.responded_nodes.as_slice(),
        )?;
        ensure_cluster_bucket_presence_converged(
            bucket.as_str(),
            "CreateBucket",
            true,
            fan_in.bucket_presence_states.as_slice(),
        )?;
    }

    Response::builder()
        .status(StatusCode::OK)
        .header("Location", format!("/{}", bucket))
        .body(Body::empty())
        .map_err(S3Error::internal)
}

pub async fn head_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response<Body>, S3Error> {
    let topology = runtime_topology_snapshot(&state);
    let internal_local_only =
        is_trusted_internal_local_metadata_scope_request(&state, &headers, &params);
    let should_fan_in =
        should_attempt_cluster_bucket_metadata_fan_in(&state, &topology, internal_local_only);

    if should_fan_in {
        let fan_in =
            fetch_cluster_bucket_presence_fan_in(&state, &topology, bucket.as_str()).await?;
        ensure_distributed_bucket_metadata_operation_strategy_ready_for_responders(
            &state,
            &topology,
            "HeadBucket",
            fan_in.responded_nodes.as_slice(),
        )?;
        match resolve_cluster_bucket_presence_for_read(fan_in.bucket_presence_states.as_slice()) {
            ClusterBucketPresenceReadResolution::Present => {}
            ClusterBucketPresenceReadResolution::Missing => {
                return Err(S3Error::no_such_bucket(&bucket));
            }
            ClusterBucketPresenceReadResolution::Inconsistent => {
                return Err(S3Error::service_unavailable(&format!(
                    "Distributed bucket metadata read 'HeadBucket' is inconsistent for '{}'",
                    bucket
                )));
            }
        }
    } else {
        let use_consensus_persisted_metadata = should_use_consensus_index_persisted_metadata_state(
            &state,
            &topology,
            internal_local_only,
        );
        if !internal_local_only && !use_consensus_persisted_metadata {
            ensure_distributed_bucket_metadata_operation_strategy_ready(&state, "HeadBucket")?;
        }
        if use_consensus_persisted_metadata {
            bucket_metadata_state_from_consensus_index(&state, &bucket, "HeadBucket")?;
        } else {
            match state.storage.head_bucket(&bucket).await {
                Ok(true) => {}
                Ok(false) => return Err(S3Error::no_such_bucket(&bucket)),
                Err(e) => return Err(S3Error::internal(e)),
            }
        }
    }

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header("x-amz-bucket-region", &*state.config.region)
        .body(Body::empty())
        .map_err(S3Error::internal)?;
    apply_internal_membership_view_header(response.headers_mut(), &topology, internal_local_only);
    Ok(response)
}

pub async fn delete_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> Result<Response<Body>, S3Error> {
    delete_bucket_with_context(State(state), Path(bucket), HashMap::new(), HeaderMap::new()).await
}

async fn delete_bucket_with_context(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    params: HashMap<String, String>,
    headers: HeaderMap,
) -> Result<Response<Body>, S3Error> {
    let topology = runtime_topology_snapshot(&state);
    let internal_local_only =
        is_trusted_internal_local_metadata_scope_request(&state, &headers, &params);
    let should_fan_in =
        should_attempt_cluster_bucket_metadata_fan_in(&state, &topology, internal_local_only);
    let use_consensus_persisted_metadata =
        should_use_consensus_index_persisted_metadata_state(&state, &topology, internal_local_only);
    if !internal_local_only && !should_fan_in && !use_consensus_persisted_metadata {
        ensure_distributed_bucket_metadata_operation_strategy_ready(&state, "DeleteBucket")?;
    }
    if use_consensus_persisted_metadata {
        ensure_consensus_index_delete_bucket_preconditions(
            &state,
            &topology,
            bucket.as_str(),
            "DeleteBucket",
        )?;
    }

    match state.storage.delete_bucket(&bucket).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(S3Error::no_such_bucket(&bucket)),
        Err(StorageError::BucketNotEmpty) => Err(S3Error::bucket_not_empty(&bucket)),
        Err(e) => Err(S3Error::internal(e)),
    }?;

    persist_bucket_metadata_operation(
        &state,
        &topology,
        "DeleteBucket",
        &BucketMetadataOperation::DeleteBucket {
            bucket: bucket.clone(),
            deleted_at_unix_ms: current_unix_ms_u64(),
            retain_tombstone_for_ms: PERSISTED_BUCKET_TOMBSTONE_RETENTION_MS,
        },
    )?;

    if should_fan_in {
        let responded_nodes =
            fan_out_delete_bucket_mutation_to_peers(&state, &topology, bucket.as_str()).await?;
        ensure_distributed_bucket_metadata_operation_strategy_ready_for_responders(
            &state,
            &topology,
            "DeleteBucket",
            responded_nodes.as_slice(),
        )?;
        let fan_in =
            fetch_cluster_bucket_presence_fan_in(&state, &topology, bucket.as_str()).await?;
        ensure_distributed_bucket_metadata_operation_strategy_ready_for_responders(
            &state,
            &topology,
            "DeleteBucket",
            fan_in.responded_nodes.as_slice(),
        )?;
        ensure_cluster_bucket_presence_converged(
            bucket.as_str(),
            "DeleteBucket",
            false,
            fan_in.bucket_presence_states.as_slice(),
        )?;
    }

    empty_response(StatusCode::NO_CONTENT)
}

pub async fn handle_bucket_delete(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response<Body>, S3Error> {
    if params.contains_key("lifecycle") {
        return delete_bucket_lifecycle(State(state), Path(bucket), params, headers).await;
    }
    delete_bucket_with_context(State(state), Path(bucket), params, headers).await
}

pub async fn handle_bucket_put(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    if params.contains_key("versioning") {
        return put_bucket_versioning(State(state), Path(bucket), params, headers, body).await;
    }
    if params.contains_key("lifecycle") {
        return put_bucket_lifecycle(State(state), Path(bucket), params, headers, body).await;
    }
    create_bucket_with_context(State(state), Path(bucket), params, headers).await
}

async fn fan_out_create_bucket_mutation_to_peers(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    bucket: &str,
) -> Result<Vec<String>, S3Error> {
    let mut responded_nodes = vec![topology.node_id.clone()];
    let path = format!("/{}", bucket);
    let query = [(
        INTERNAL_METADATA_SCOPE_QUERY_PARAM,
        INTERNAL_METADATA_SCOPE_LOCAL_ONLY,
    )];

    for peer in &topology.cluster_peers {
        let response = send_internal_peer_request(state, peer, Method::PUT, path.as_str(), &query, None)
            .await
            .map_err(|_| {
                S3Error::service_unavailable(&format!(
                    "Distributed bucket metadata mutation 'CreateBucket' failed while contacting responder node '{}'",
                    peer
                ))
            })?;
        let status = response.status();
        if status.is_success() {
            responded_nodes.push(peer.clone());
            continue;
        }

        if status == StatusCode::CONFLICT {
            responded_nodes.push(peer.clone());
            continue;
        }

        return Err(S3Error::service_unavailable(&format!(
            "Distributed bucket metadata mutation 'CreateBucket' failed on responder node '{}' with status {}",
            peer,
            status.as_u16()
        )));
    }

    Ok(responded_nodes)
}

async fn fan_out_delete_bucket_mutation_to_peers(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    bucket: &str,
) -> Result<Vec<String>, S3Error> {
    let mut responded_nodes = vec![topology.node_id.clone()];
    let path = format!("/{}", bucket);
    let query = [(
        INTERNAL_METADATA_SCOPE_QUERY_PARAM,
        INTERNAL_METADATA_SCOPE_LOCAL_ONLY,
    )];

    for peer in &topology.cluster_peers {
        let response = send_internal_peer_request(
            state,
            peer,
            Method::DELETE,
            path.as_str(),
            &query,
            None,
        )
        .await
        .map_err(|_| {
            S3Error::service_unavailable(&format!(
                "Distributed bucket metadata mutation 'DeleteBucket' failed while contacting responder node '{}'",
                peer
            ))
        })?;
        let status = response.status();
        if status.is_success() {
            responded_nodes.push(peer.clone());
            continue;
        }

        let body = response.text().await.unwrap_or_default();
        if status == StatusCode::NOT_FOUND
            && parse_peer_error_code(body.as_str()).as_deref() == Some("NoSuchBucket")
        {
            responded_nodes.push(peer.clone());
            continue;
        }
        if status == StatusCode::CONFLICT
            && parse_peer_error_code(body.as_str()).as_deref() == Some("BucketNotEmpty")
        {
            return Err(S3Error::bucket_not_empty(bucket));
        }

        return Err(S3Error::service_unavailable(&format!(
            "Distributed bucket metadata mutation 'DeleteBucket' failed on responder node '{}' with status {}",
            peer,
            status.as_u16()
        )));
    }

    Ok(responded_nodes)
}

async fn fetch_cluster_bucket_presence_fan_in(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    bucket: &str,
) -> Result<ClusterBucketPresenceFanIn, S3Error> {
    let local_exists = state
        .storage
        .head_bucket(bucket)
        .await
        .map_err(|err| map_bucket_storage_err(bucket, err))?;
    let local_state = if local_exists {
        ClusterBucketMetadataResponderState::Present(true)
    } else {
        ClusterBucketMetadataResponderState::MissingBucket
    };

    let mut responded_nodes = vec![topology.node_id.clone()];
    let mut bucket_presence_states = vec![local_state];
    let mut responder_views = Vec::<ClusterResponderMembershipView>::new();
    for peer in &topology.cluster_peers {
        match fetch_peer_bucket_presence_state(state, peer, bucket).await {
            Ok(peer_response) => {
                responded_nodes.push(peer.clone());
                bucket_presence_states.push(peer_response.state);
                if let Some(membership_view_id) = peer_response.membership_view_id {
                    responder_views.push(ClusterResponderMembershipView {
                        node_id: peer.clone(),
                        membership_view_id: Some(membership_view_id),
                    });
                }
            }
            Err(err) => {
                tracing::warn!(
                    peer = %peer,
                    bucket,
                    error = ?err,
                    "Failed to fetch peer bucket presence for distributed metadata fan-in"
                );
            }
        }
    }
    ensure_peer_responder_membership_views_consistent("HeadBucket", responder_views.as_slice())?;

    Ok(ClusterBucketPresenceFanIn {
        responded_nodes,
        bucket_presence_states,
    })
}

async fn fetch_peer_bucket_presence_state(
    state: &AppState,
    peer: &str,
    bucket: &str,
) -> Result<PeerBucketPresenceStateFanInResult, S3Error> {
    let path = format!("/{}", bucket);
    let query = [(
        INTERNAL_METADATA_SCOPE_QUERY_PARAM,
        INTERNAL_METADATA_SCOPE_LOCAL_ONLY,
    )];
    let response =
        send_internal_peer_request(state, peer, Method::HEAD, path.as_str(), &query, None).await?;
    let status = response.status();
    if status.is_success() {
        let membership_view_id =
            extract_internal_peer_membership_view_id(response.headers(), peer, "HeadBucket")?;
        return Ok(PeerBucketPresenceStateFanInResult {
            membership_view_id: Some(membership_view_id),
            state: ClusterBucketMetadataResponderState::Present(true),
        });
    }
    if status == StatusCode::NOT_FOUND {
        return Ok(PeerBucketPresenceStateFanInResult {
            membership_view_id: None,
            state: ClusterBucketMetadataResponderState::MissingBucket,
        });
    }

    Err(S3Error::service_unavailable(
        "Peer bucket presence request failed",
    ))
}

fn ensure_cluster_bucket_presence_converged(
    bucket: &str,
    operation: &str,
    expect_present: bool,
    states: &[ClusterBucketMetadataResponderState<bool>],
) -> Result<(), S3Error> {
    let expectation = if expect_present {
        ClusterBucketPresenceConvergenceExpectation::Present
    } else {
        ClusterBucketPresenceConvergenceExpectation::Missing
    };
    if assess_cluster_bucket_presence_convergence(states, expectation).converged {
        return Ok(());
    }

    Err(S3Error::service_unavailable(&format!(
        "Distributed bucket metadata mutation '{}' did not converge for '{}'",
        operation, bucket
    )))
}

async fn put_bucket_versioning(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    params: HashMap<String, String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    let topology = runtime_topology_snapshot(&state);
    let internal_local_only =
        is_trusted_internal_local_metadata_scope_request(&state, &headers, &params);
    let should_fan_in =
        should_attempt_cluster_bucket_metadata_fan_in(&state, &topology, internal_local_only);
    let use_consensus_persisted_metadata =
        should_use_consensus_index_persisted_metadata_state(&state, &topology, internal_local_only);
    if !internal_local_only && !should_fan_in && !use_consensus_persisted_metadata {
        ensure_distributed_bucket_metadata_operation_strategy_ready(&state, "PutBucketVersioning")?;
    }
    ensure_bucket_exists(&state.storage, &bucket).await?;

    let body_bytes = axum::body::to_bytes(body, 1024 * 64)
        .await
        .map_err(S3Error::internal)?;
    let body_str = String::from_utf8_lossy(&body_bytes);
    let enabled = parse_versioning_status(&body_str)?;

    state
        .storage
        .set_versioning(&bucket, enabled)
        .await
        .map_err(|e| map_bucket_storage_err(&bucket, e))?;

    persist_bucket_metadata_operation(
        &state,
        &topology,
        "PutBucketVersioning",
        &BucketMetadataOperation::SetVersioning {
            bucket: bucket.clone(),
            enabled,
        },
    )?;

    if should_fan_in {
        let responded_nodes = fan_out_bucket_metadata_mutation_to_peers(
            &state,
            &topology,
            &bucket,
            Method::PUT,
            "PutBucketVersioning",
            "versioning",
            Some(body_bytes.to_vec()),
        )
        .await?;
        ensure_distributed_bucket_metadata_operation_strategy_ready_for_responders(
            &state,
            &topology,
            "PutBucketVersioning",
            responded_nodes.as_slice(),
        )?;
        let fan_in = fetch_cluster_bucket_versioning_fan_in(&state, &topology, &bucket).await?;
        ensure_distributed_bucket_metadata_operation_strategy_ready_for_responders(
            &state,
            &topology,
            "PutBucketVersioning",
            fan_in.responded_nodes.as_slice(),
        )?;
        let converged_state = resolve_cluster_bucket_versioning_state(
            &state,
            &topology,
            "PutBucketVersioning",
            &bucket,
            fan_in.responded_nodes.as_slice(),
            fan_in.versioning_states.as_slice(),
        )?;
        if converged_state != enabled {
            return Err(S3Error::service_unavailable(&format!(
                "Distributed bucket versioning mutation did not converge for '{}'",
                bucket
            )));
        }
    }

    empty_response(StatusCode::OK)
}

async fn put_bucket_lifecycle(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    params: HashMap<String, String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    let topology = runtime_topology_snapshot(&state);
    let internal_local_only =
        is_trusted_internal_local_metadata_scope_request(&state, &headers, &params);
    let should_fan_in =
        should_attempt_cluster_bucket_metadata_fan_in(&state, &topology, internal_local_only);
    let use_consensus_persisted_metadata =
        should_use_consensus_index_persisted_metadata_state(&state, &topology, internal_local_only);
    if !internal_local_only && !should_fan_in && !use_consensus_persisted_metadata {
        ensure_distributed_bucket_metadata_operation_strategy_ready(&state, "PutBucketLifecycle")?;
    }
    ensure_bucket_exists(&state.storage, &bucket).await?;

    let body_bytes = axum::body::to_bytes(body, 1024 * 256)
        .await
        .map_err(S3Error::internal)?;
    let body_str = String::from_utf8_lossy(&body_bytes);
    let rules = parse_lifecycle_rules(&body_str)?;
    let expected_rules = canonicalize_lifecycle_rules(rules.clone());

    state
        .storage
        .set_lifecycle_rules(&bucket, &rules)
        .await
        .map_err(|e| map_lifecycle_storage_err(&bucket, e))?;

    persist_bucket_metadata_operation(
        &state,
        &topology,
        "PutBucketLifecycle",
        &BucketMetadataOperation::SetLifecycle {
            bucket: bucket.clone(),
            enabled: !expected_rules.is_empty(),
        },
    )?;

    if should_fan_in {
        let responded_nodes = fan_out_bucket_metadata_mutation_to_peers(
            &state,
            &topology,
            &bucket,
            Method::PUT,
            "PutBucketLifecycle",
            "lifecycle",
            Some(body_bytes.to_vec()),
        )
        .await?;
        ensure_distributed_bucket_metadata_operation_strategy_ready_for_responders(
            &state,
            &topology,
            "PutBucketLifecycle",
            responded_nodes.as_slice(),
        )?;
        let fan_in = fetch_cluster_bucket_lifecycle_fan_in(&state, &topology, &bucket).await?;
        ensure_distributed_bucket_metadata_operation_strategy_ready_for_responders(
            &state,
            &topology,
            "PutBucketLifecycle",
            fan_in.responded_nodes.as_slice(),
        )?;
        let converged_state = resolve_cluster_bucket_lifecycle_state(
            &state,
            &topology,
            "PutBucketLifecycle",
            &bucket,
            fan_in.responded_nodes.as_slice(),
            fan_in.lifecycle_states.as_slice(),
        )?;
        if canonicalize_lifecycle_rules(converged_state) != expected_rules {
            return Err(S3Error::service_unavailable(&format!(
                "Distributed bucket lifecycle mutation did not converge for '{}'",
                bucket
            )));
        }
    }

    empty_response(StatusCode::OK)
}

async fn delete_bucket_lifecycle(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    params: HashMap<String, String>,
    headers: HeaderMap,
) -> Result<Response<Body>, S3Error> {
    let topology = runtime_topology_snapshot(&state);
    let internal_local_only =
        is_trusted_internal_local_metadata_scope_request(&state, &headers, &params);
    let should_fan_in =
        should_attempt_cluster_bucket_metadata_fan_in(&state, &topology, internal_local_only);
    if !internal_local_only && !should_fan_in {
        ensure_distributed_bucket_metadata_operation_strategy_ready(
            &state,
            "DeleteBucketLifecycle",
        )?;
    }
    ensure_bucket_exists(&state.storage, &bucket).await?;

    state
        .storage
        .set_lifecycle_rules(&bucket, &[])
        .await
        .map_err(|e| map_lifecycle_storage_err(&bucket, e))?;

    persist_bucket_metadata_operation(
        &state,
        &topology,
        "DeleteBucketLifecycle",
        &BucketMetadataOperation::SetLifecycle {
            bucket: bucket.clone(),
            enabled: false,
        },
    )?;

    if should_fan_in {
        let responded_nodes = fan_out_bucket_metadata_mutation_to_peers(
            &state,
            &topology,
            &bucket,
            Method::DELETE,
            "DeleteBucketLifecycle",
            "lifecycle",
            None,
        )
        .await?;
        ensure_distributed_bucket_metadata_operation_strategy_ready_for_responders(
            &state,
            &topology,
            "DeleteBucketLifecycle",
            responded_nodes.as_slice(),
        )?;
        let fan_in = fetch_cluster_bucket_lifecycle_fan_in(&state, &topology, &bucket).await?;
        ensure_distributed_bucket_metadata_operation_strategy_ready_for_responders(
            &state,
            &topology,
            "DeleteBucketLifecycle",
            fan_in.responded_nodes.as_slice(),
        )?;
        match resolve_cluster_bucket_lifecycle_state(
            &state,
            &topology,
            "DeleteBucketLifecycle",
            &bucket,
            fan_in.responded_nodes.as_slice(),
            fan_in.lifecycle_states.as_slice(),
        ) {
            Err(S3Error {
                code: S3ErrorCode::NoSuchLifecycleConfiguration,
                ..
            }) => {}
            Ok(_) => {
                return Err(S3Error::service_unavailable(&format!(
                    "Distributed bucket lifecycle delete did not converge for '{}'",
                    bucket
                )));
            }
            Err(err) => return Err(err),
        }
    }

    empty_response(StatusCode::NO_CONTENT)
}

pub async fn get_bucket_versioning(
    state: AppState,
    bucket: String,
    params: &HashMap<String, String>,
    headers: &HeaderMap,
) -> Result<Response<Body>, S3Error> {
    let topology = runtime_topology_snapshot(&state);
    let internal_local_only =
        is_trusted_internal_local_metadata_scope_request(&state, headers, params);
    let versioned =
        if should_attempt_cluster_bucket_metadata_fan_in(&state, &topology, internal_local_only) {
            let fan_in = fetch_cluster_bucket_versioning_fan_in(&state, &topology, &bucket).await?;
            ensure_distributed_bucket_metadata_operation_strategy_ready_for_responders(
                &state,
                &topology,
                "GetBucketVersioning",
                fan_in.responded_nodes.as_slice(),
            )?;
            resolve_cluster_bucket_versioning_state(
                &state,
                &topology,
                "GetBucketVersioning",
                &bucket,
                fan_in.responded_nodes.as_slice(),
                fan_in.versioning_states.as_slice(),
            )?
        } else {
            let use_consensus_persisted_metadata =
                should_use_consensus_index_persisted_metadata_state(
                    &state,
                    &topology,
                    internal_local_only,
                );
            if !internal_local_only && !use_consensus_persisted_metadata {
                ensure_distributed_bucket_metadata_operation_strategy_ready(
                    &state,
                    "GetBucketVersioning",
                )?;
            }
            if use_consensus_persisted_metadata {
                bucket_metadata_state_from_consensus_index(&state, &bucket, "GetBucketVersioning")?
                    .versioning_enabled
            } else {
                state
                    .storage
                    .is_versioned(&bucket)
                    .await
                    .map_err(|e| map_bucket_storage_err(&bucket, e))?
            }
        };

    let result = VersioningConfiguration {
        status: if versioned {
            Some("Enabled".to_string())
        } else {
            None
        },
    };

    let mut response = xml_response(StatusCode::OK, &result)?;
    apply_internal_membership_view_header(response.headers_mut(), &topology, internal_local_only);
    Ok(response)
}

pub async fn get_bucket_lifecycle(
    state: AppState,
    bucket: String,
    params: &HashMap<String, String>,
    headers: &HeaderMap,
) -> Result<Response<Body>, S3Error> {
    let topology = runtime_topology_snapshot(&state);
    let internal_local_only =
        is_trusted_internal_local_metadata_scope_request(&state, headers, params);
    let rules = if should_attempt_cluster_bucket_metadata_fan_in(
        &state,
        &topology,
        internal_local_only,
    ) {
        let fan_in = fetch_cluster_bucket_lifecycle_fan_in(&state, &topology, &bucket).await?;
        ensure_distributed_bucket_metadata_operation_strategy_ready_for_responders(
            &state,
            &topology,
            "GetBucketLifecycle",
            fan_in.responded_nodes.as_slice(),
        )?;
        resolve_cluster_bucket_lifecycle_state(
            &state,
            &topology,
            "GetBucketLifecycle",
            &bucket,
            fan_in.responded_nodes.as_slice(),
            fan_in.lifecycle_states.as_slice(),
        )?
    } else {
        let use_consensus_persisted_metadata = should_use_consensus_index_persisted_metadata_state(
            &state,
            &topology,
            internal_local_only,
        );
        if !internal_local_only && !use_consensus_persisted_metadata {
            ensure_distributed_bucket_metadata_operation_strategy_ready(
                &state,
                "GetBucketLifecycle",
            )?;
        }
        if use_consensus_persisted_metadata {
            let bucket_state =
                bucket_metadata_state_from_consensus_index(&state, &bucket, "GetBucketLifecycle")?;
            if !bucket_state.lifecycle_enabled {
                return Err(S3Error::no_such_lifecycle_configuration(&bucket));
            }
            if !cluster_auth_token_configured(&state) {
                return Err(S3Error::service_unavailable(
                    "Distributed metadata strategy is not ready for bucket metadata operation 'GetBucketLifecycle' (consensus-index-peer-fan-in-auth-token-missing)",
                ));
            }
            let fan_in = fetch_cluster_bucket_lifecycle_fan_in(&state, &topology, &bucket).await?;
            ensure_distributed_bucket_metadata_operation_strategy_ready_for_responders(
                &state,
                &topology,
                "GetBucketLifecycle",
                fan_in.responded_nodes.as_slice(),
            )?;
            resolve_cluster_bucket_lifecycle_state(
                &state,
                &topology,
                "GetBucketLifecycle",
                &bucket,
                fan_in.responded_nodes.as_slice(),
                fan_in.lifecycle_states.as_slice(),
            )?
        } else {
            let local_rules = state
                .storage
                .get_lifecycle_rules(&bucket)
                .await
                .map_err(|e| map_bucket_storage_err(&bucket, e))?;
            if local_rules.is_empty() {
                return Err(S3Error::no_such_lifecycle_configuration(&bucket));
            }
            local_rules
        }
    };

    let result = serialize_lifecycle_rules(rules);
    let mut response = xml_response(StatusCode::OK, &result)?;
    apply_internal_membership_view_header(response.headers_mut(), &topology, internal_local_only);
    Ok(response)
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
        "Distributed bucket metadata fan-in for '{operation}' observed inconsistent peer membership view ids ({reason})",
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::S3ErrorCode;

    #[test]
    fn extract_internal_peer_membership_view_id_rejects_missing_header() {
        let headers = reqwest::header::HeaderMap::new();
        let err = extract_internal_peer_membership_view_id(&headers, "node-b:9000", "ListBuckets")
            .expect_err("missing membership view header must fail closed");
        assert!(matches!(err.code, S3ErrorCode::ServiceUnavailable));
        assert!(
            err.message
                .contains("missing internal membership view id header")
        );
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
            "GetBucketVersioning",
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
