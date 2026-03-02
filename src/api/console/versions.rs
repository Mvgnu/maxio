use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::api::console::objects::sanitize_filename;
use crate::api::console::response;
use crate::api::console::storage;
use crate::server::AppState;
use crate::storage::StorageError;

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
struct ListVersionsResponse {
    versions: Vec<VersionSummary>,
}

pub(super) async fn get_versioning(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> impl IntoResponse {
    match state.storage.is_versioned(&bucket).await {
        Ok(enabled) => response::json(StatusCode::OK, VersioningResponse { enabled }),
        Err(e) => storage::map_bucket_storage_err(e),
    }
}

#[derive(serde::Deserialize)]
pub(super) struct SetVersioningRequest {
    enabled: bool,
}

pub(super) async fn set_versioning(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Json(body): Json<SetVersioningRequest>,
) -> impl IntoResponse {
    match state.storage.set_versioning(&bucket, body.enabled).await {
        Ok(()) => response::ok(),
        Err(e) => storage::map_bucket_storage_err(e),
    }
}

#[derive(serde::Deserialize)]
pub(super) struct ListVersionsParams {
    key: String,
}

pub(super) async fn list_versions(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<ListVersionsParams>,
) -> impl IntoResponse {
    if let Err(resp) = storage::ensure_bucket_exists(&state, &bucket).await {
        return resp;
    }
    if let Some(resp) = storage::validate_list_prefix(&params.key) {
        return resp;
    }

    let all = match state
        .storage
        .list_object_versions(&bucket, &params.key)
        .await
    {
        Ok(v) => v,
        Err(e) => return storage::map_bucket_storage_err(e),
    };

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

    response::json(StatusCode::OK, ListVersionsResponse { versions })
}

pub(super) async fn delete_version(
    State(state): State<AppState>,
    Path((bucket, version_id, key)): Path<(String, String, String)>,
) -> impl IntoResponse {
    match state
        .storage
        .delete_object_version(&bucket, &key, &version_id)
        .await
    {
        Ok(_) => response::ok(),
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
