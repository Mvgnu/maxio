use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use futures::TryStreamExt;
use quick_xml::de::from_str;

use super::{response, storage};
use crate::metadata::{
    ClusterMetadataListingStrategy, ClusterResponderMembershipView, ObjectMetadataState,
};
use crate::server::{AppState, runtime_topology_snapshot};
use crate::storage::{ObjectMeta, StorageError};

#[derive(serde::Deserialize)]
#[serde(rename = "ListBucketResult")]
struct PeerListBucketResultV2 {
    #[serde(rename = "IsTruncated")]
    is_truncated: bool,
    #[serde(rename = "NextContinuationToken")]
    next_continuation_token: Option<String>,
    #[serde(rename = "Contents", default)]
    contents: Vec<PeerObjectEntry>,
}

#[derive(serde::Deserialize)]
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

struct ClusterObjectListingFanIn {
    responded_nodes: Vec<String>,
    responder_membership_views: Vec<ClusterResponderMembershipView>,
    objects: Vec<ObjectMeta>,
}

struct PeerObjectListingFanInResult {
    membership_view_id: String,
    objects: Vec<ObjectMeta>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ObjectListFileDto {
    key: String,
    size: u64,
    last_modified: String,
    etag: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ListObjectsResponse {
    files: Vec<ObjectListFileDto>,
    prefixes: Vec<String>,
    empty_prefixes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata_coverage: Option<storage::MetadataCoverageDto>,
}

#[derive(serde::Serialize)]
struct UploadObjectResponse {
    ok: bool,
    etag: String,
    size: u64,
}

#[derive(serde::Deserialize)]
pub(super) struct ListObjectsParams {
    prefix: Option<String>,
    delimiter: Option<String>,
    #[serde(rename = "x-maxio-internal-metadata-scope")]
    internal_metadata_scope: Option<String>,
}

pub(super) async fn list_objects(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<ListObjectsParams>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = storage::ensure_bucket_exists(&state, &bucket).await {
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
    let prefix = params.prefix.unwrap_or_default();
    let delimiter = params.delimiter.unwrap_or_else(|| "/".to_string());
    if let Some(resp) = storage::validate_list_prefix(&prefix) {
        return resp;
    }
    if let Some(resp) = storage::validate_list_delimiter(&delimiter) {
        return resp;
    }

    let should_fan_in = storage::should_attempt_cluster_object_listing_fan_in(
        &state,
        &topology,
        internal_local_only,
    );
    let (all_objects, metadata_coverage) = if should_fan_in {
        let fan_in =
            match fetch_cluster_object_listing_fan_in(&state, &topology, &bucket, &prefix).await {
                Ok(fan_in) => fan_in,
                Err(err) => return storage::map_bucket_storage_err(err),
            };
        if let Some(resp) = storage::reject_unready_metadata_fan_in_preflight_for_responders(
            &topology,
            state.metadata_listing_strategy,
            "ListConsoleObjects",
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
        if state.metadata_listing_strategy == ClusterMetadataListingStrategy::ConsensusIndex
            && !internal_local_only
        {
            let canonical_rows = match storage::load_consensus_object_metadata_rows_for_prefix(
                &state,
                &topology,
                &bucket,
                prefix.as_str(),
                "ListConsoleObjects",
            ) {
                Ok(rows) => rows,
                Err(err) => return *err,
            };
            let canonical = match hydrate_objects_from_consensus_states(
                "ListConsoleObjects",
                fan_in.objects.as_slice(),
                canonical_rows.as_slice(),
            ) {
                Ok(objects) => objects,
                Err(message) => return response::error(StatusCode::SERVICE_UNAVAILABLE, message),
            };
            (canonical, coverage)
        } else {
            (merge_object_listing_objects(fan_in.objects), coverage)
        }
    } else {
        let objects = match state.storage.list_objects(&bucket, &prefix).await {
            Ok(objects) => objects,
            Err(e) => return storage::map_bucket_storage_err(e),
        };
        (objects, storage::list_metadata_coverage(&state))
    };
    if !internal_local_only
        && let Some(resp) = storage::reject_unready_metadata_listing(metadata_coverage.as_ref())
    {
        return resp;
    }

    let mut files = Vec::new();
    let mut prefix_set = BTreeSet::new();

    for obj in &all_objects {
        let suffix = &obj.key[prefix.len()..];
        if let Some(pos) = suffix.find(delimiter.as_str()) {
            let common = format!("{}{}", prefix, &suffix[..pos + delimiter.len()]);
            prefix_set.insert(common);
        } else if !obj.key.ends_with('/') {
            files.push(ObjectListFileDto {
                key: obj.key.clone(),
                size: obj.size,
                last_modified: obj.last_modified.clone(),
                etag: obj.etag.clone(),
            });
        }
    }

    let mut empty_prefixes: Vec<String> = Vec::new();
    for p in &prefix_set {
        let has_children = all_objects
            .iter()
            .any(|obj| obj.key.starts_with(p.as_str()) && obj.key != *p);
        if !has_children {
            empty_prefixes.push(p.clone());
        }
    }

    let prefixes: Vec<String> = prefix_set.into_iter().collect();

    response::json(
        StatusCode::OK,
        ListObjectsResponse {
            files,
            prefixes,
            empty_prefixes,
            metadata_coverage,
        },
    )
}

async fn fetch_cluster_object_listing_fan_in(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    bucket: &str,
    prefix: &str,
) -> Result<ClusterObjectListingFanIn, StorageError> {
    let local_objects = state.storage.list_objects(bucket, prefix).await?;
    let mut responded_nodes = vec![topology.node_id.clone()];
    let mut responder_membership_views = Vec::<ClusterResponderMembershipView>::new();
    let mut objects = local_objects;

    for peer in &topology.cluster_peers {
        match fetch_peer_local_object_listing(state, peer, bucket, prefix).await {
            Ok(peer_listing) => {
                responded_nodes.push(peer.clone());
                responder_membership_views.push(ClusterResponderMembershipView {
                    node_id: peer.clone(),
                    membership_view_id: Some(peer_listing.membership_view_id),
                });
                objects.extend(peer_listing.objects);
            }
            Err(err) => {
                tracing::warn!(
                    peer = %peer,
                    bucket,
                    error = %err,
                    "Console object list fan-in peer request failed"
                );
            }
        }
    }

    Ok(ClusterObjectListingFanIn {
        responded_nodes,
        responder_membership_views,
        objects,
    })
}

async fn fetch_peer_local_object_listing(
    state: &AppState,
    peer: &str,
    bucket: &str,
    prefix: &str,
) -> Result<PeerObjectListingFanInResult, String> {
    let path = format!("/{bucket}");
    let mut collected = Vec::new();
    let mut next_continuation_token: Option<String> = None;
    let mut seen_tokens = HashSet::<String>::new();
    let mut responder_membership_view_id: Option<String> = None;

    loop {
        let mut query = vec![
            ("list-type", "2"),
            ("max-keys", "1000"),
            (
                storage::INTERNAL_METADATA_SCOPE_QUERY_PARAM,
                storage::INTERNAL_METADATA_SCOPE_LOCAL_ONLY,
            ),
        ];
        if !prefix.is_empty() {
            query.push(("prefix", prefix));
        }
        if let Some(token) = next_continuation_token.as_deref() {
            query.push(("continuation-token", token));
        }

        let response =
            storage::send_internal_peer_get(state, peer, path.as_str(), query.as_slice()).await?;
        if !response.status().is_success() {
            return Err(format!(
                "peer object list status {}",
                response.status().as_u16()
            ));
        }
        let observed_membership_view_id = storage::extract_internal_peer_membership_view_id(
            response.headers(),
            peer,
            "ListConsoleObjects",
        )?;
        storage::ensure_stable_internal_peer_membership_view_id(
            &mut responder_membership_view_id,
            observed_membership_view_id.as_str(),
            peer,
            "ListConsoleObjects",
        )?;

        let body = response.text().await.map_err(|err| err.to_string())?;
        let parsed = from_str::<PeerListBucketResultV2>(&body).map_err(|err| err.to_string())?;

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
                "Peer object listing pagination failed (missing continuation token)".to_string()
            })?;
        if !seen_tokens.insert(token.clone()) {
            return Err(
                "Peer object listing pagination failed (continuation loop detected)".to_string(),
            );
        }
        next_continuation_token = Some(token);
    }

    let membership_view_id = responder_membership_view_id.ok_or_else(|| {
        format!(
            "Peer metadata fan-in response for 'ListConsoleObjects' from '{peer}' did not yield a responder membership view id",
        )
    })?;
    Ok(PeerObjectListingFanInResult {
        membership_view_id,
        objects: collected,
    })
}

fn hydrate_objects_from_consensus_states(
    operation: &str,
    objects: &[ObjectMeta],
    states: &[ObjectMetadataState],
) -> Result<Vec<ObjectMeta>, String> {
    let mut by_key_and_version = BTreeMap::<(String, String), ObjectMeta>::new();
    let mut by_key = BTreeMap::<String, ObjectMeta>::new();
    for object in objects {
        let version_id = object.version_id.as_deref().unwrap_or("null").to_string();
        by_key_and_version
            .entry((object.key.clone(), version_id))
            .or_insert_with(|| object.clone());
        by_key
            .entry(object.key.clone())
            .or_insert_with(|| object.clone());
    }

    let mut page = Vec::with_capacity(states.len());
    for state in states {
        let version_id = state
            .latest_version_id
            .as_deref()
            .unwrap_or("null")
            .to_string();
        let key = state.key.clone();
        let hydrated = by_key_and_version
            .get(&(key.clone(), version_id))
            .cloned()
            // Peer ListObjects payloads can omit version ids while canonical metadata rows
            // remain version-aware; fall back to key-only hydration for current-object pages.
            .or_else(|| by_key.get(&key).cloned())
            .ok_or_else(|| {
                format!(
                    "Distributed metadata listing operation '{}' cannot hydrate canonical metadata row for key '{}'",
                    operation, key
                )
            })?;
        page.push(hydrated);
    }

    Ok(page)
}

fn merge_object_listing_objects(objects: Vec<ObjectMeta>) -> Vec<ObjectMeta> {
    let mut dedup = BTreeMap::<String, ObjectMeta>::new();
    for object in objects {
        match dedup.get_mut(&object.key) {
            Some(current) => {
                if object.last_modified > current.last_modified {
                    *current = object;
                }
            }
            None => {
                dedup.insert(object.key.clone(), object);
            }
        }
    }
    dedup.into_values().collect::<Vec<_>>()
}

pub(super) async fn upload_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> impl IntoResponse {
    let topology = runtime_topology_snapshot(&state);
    if let Err(resp) = storage::ensure_bucket_exists(&state, &bucket).await {
        return resp;
    }
    if let Err(err) = storage::ensure_consensus_index_object_mutation_preconditions(
        &state,
        &topology,
        &bucket,
        "UploadConsoleObject",
    ) {
        return *err;
    }

    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");

    let stream = body.into_data_stream();
    let reader = tokio_util::io::StreamReader::new(stream.map_err(std::io::Error::other));

    match state
        .storage
        .put_object(&bucket, &key, content_type, Box::pin(reader), None)
        .await
    {
        Ok(result) => {
            if let Err(err) = storage::persist_current_object_metadata_state(
                &state,
                &topology,
                &bucket,
                &key,
                result.version_id.as_deref(),
                false,
            ) {
                return *err;
            }

            response::json(
                StatusCode::OK,
                UploadObjectResponse {
                    ok: true,
                    etag: result.etag,
                    size: result.size,
                },
            )
        }
        Err(e) => storage::map_bucket_storage_err(e),
    }
}

pub(super) async fn delete_object_api(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
) -> impl IntoResponse {
    let topology = runtime_topology_snapshot(&state);
    if let Err(resp) = storage::ensure_bucket_exists(&state, &bucket).await {
        return resp;
    }
    if let Err(err) = storage::ensure_consensus_index_object_mutation_preconditions(
        &state,
        &topology,
        &bucket,
        "DeleteConsoleObject",
    ) {
        return *err;
    }

    match state.storage.delete_object(&bucket, &key).await {
        Ok(result) => {
            let persist_result = if let Some(version_id) = result.version_id.as_deref() {
                storage::persist_current_object_metadata_state(
                    &state,
                    &topology,
                    &bucket,
                    &key,
                    Some(version_id),
                    result.is_delete_marker,
                )
            } else {
                storage::persist_deleted_current_object_metadata_state(
                    &state, &topology, &bucket, &key,
                )
            };
            if let Err(err) = persist_result {
                return *err;
            }

            response::ok()
        }
        Err(e) => storage::map_bucket_storage_err(e),
    }
}

pub(super) async fn download_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
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
        None,
        "DownloadConsoleObject",
    ) {
        return *err;
    }

    let (reader, meta) = match state.storage.get_object(&bucket, &key).await {
        Ok(r) => r,
        Err(crate::storage::StorageError::NotFound(_)) => {
            return response::error(StatusCode::NOT_FOUND, "Object not found");
        }
        Err(crate::storage::StorageError::InvalidKey(message)) => {
            return storage::invalid_key(message);
        }
        Err(err) => return storage::internal_err(err),
    };

    let filename = key.rsplit('/').next().unwrap_or(&key);
    let safe_filename = sanitize_filename(filename);
    let stream = tokio_util::io::ReaderStream::new(reader);
    let body = axum::body::Body::from_stream(stream);

    response::download(body, &meta.content_type, meta.size, &safe_filename)
}

pub(super) fn sanitize_filename(name: &str) -> String {
    name.chars()
        .filter(|c| *c != '"' && *c != '\\' && *c != '\r' && *c != '\n')
        .collect()
}

#[derive(serde::Deserialize)]
pub(super) struct CreateFolderRequest {
    name: String,
}

pub(super) async fn create_folder(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Json(body): Json<CreateFolderRequest>,
) -> impl IntoResponse {
    let topology = runtime_topology_snapshot(&state);
    if let Err(resp) = storage::ensure_bucket_exists(&state, &bucket).await {
        return resp;
    }
    if let Err(err) = storage::ensure_consensus_index_object_mutation_preconditions(
        &state,
        &topology,
        &bucket,
        "CreateConsoleFolder",
    ) {
        return *err;
    }

    let name = body.name.trim().trim_matches('/');
    if name.is_empty() {
        return response::error(StatusCode::BAD_REQUEST, "Folder name is required");
    }

    let key = format!("{}/", name);
    match state
        .storage
        .put_object(
            &bucket,
            &key,
            "application/x-directory",
            Box::pin(tokio::io::empty()),
            None,
        )
        .await
    {
        Ok(result) => {
            if let Err(err) = storage::persist_current_object_metadata_state(
                &state,
                &topology,
                &bucket,
                &key,
                result.version_id.as_deref(),
                false,
            ) {
                return *err;
            }
            response::ok()
        }
        Err(e) => storage::map_bucket_storage_err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object_meta(key: &str, version_id: Option<&str>, last_modified: &str) -> ObjectMeta {
        ObjectMeta {
            key: key.to_string(),
            size: 1,
            etag: "\"etag\"".to_string(),
            content_type: "application/octet-stream".to_string(),
            last_modified: last_modified.to_string(),
            version_id: version_id.map(ToOwned::to_owned),
            is_delete_marker: false,
            storage_format: None,
            checksum_algorithm: None,
            checksum_value: None,
        }
    }

    #[test]
    fn hydrate_objects_from_consensus_states_prefers_key_and_version_match() {
        let objects = vec![
            object_meta("docs/a.txt", Some("old"), "2026-03-05T10:00:00Z"),
            object_meta("docs/a.txt", Some("new"), "2026-03-05T10:01:00Z"),
        ];
        let states = vec![ObjectMetadataState {
            bucket: "bucket".to_string(),
            key: "docs/a.txt".to_string(),
            latest_version_id: Some("new".to_string()),
            is_delete_marker: false,
        }];

        let hydrated = hydrate_objects_from_consensus_states(
            "ListConsoleObjects",
            objects.as_slice(),
            states.as_slice(),
        )
        .expect("canonical row should hydrate");

        assert_eq!(hydrated.len(), 1);
        assert_eq!(hydrated[0].version_id.as_deref(), Some("new"));
        assert_eq!(hydrated[0].last_modified, "2026-03-05T10:01:00Z");
    }

    #[test]
    fn hydrate_objects_from_consensus_states_falls_back_to_key_when_version_id_missing() {
        let objects = vec![object_meta("docs/a.txt", None, "2026-03-05T10:00:00Z")];
        let states = vec![ObjectMetadataState {
            bucket: "bucket".to_string(),
            key: "docs/a.txt".to_string(),
            latest_version_id: Some("v1".to_string()),
            is_delete_marker: false,
        }];

        let hydrated = hydrate_objects_from_consensus_states(
            "ListConsoleObjects",
            objects.as_slice(),
            states.as_slice(),
        )
        .expect("canonical row should hydrate with key-only fallback");

        assert_eq!(hydrated.len(), 1);
        assert_eq!(hydrated[0].key, "docs/a.txt");
    }
}
