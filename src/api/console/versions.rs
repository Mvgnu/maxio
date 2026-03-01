use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::api::console::objects::sanitize_filename;
use crate::api::console::response;
use crate::api::console::storage;
use crate::server::AppState;
use crate::storage::StorageError;

pub(super) async fn get_versioning(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> impl IntoResponse {
    match state.storage.is_versioned(&bucket).await {
        Ok(enabled) => response::json(StatusCode::OK, serde_json::json!({"enabled": enabled})),
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

    let all = match state
        .storage
        .list_object_versions(&bucket, &params.key)
        .await
    {
        Ok(v) => v,
        Err(e) => return storage::map_bucket_storage_err(e),
    };

    let versions: Vec<serde_json::Value> = all
        .into_iter()
        .filter(|v| v.key == params.key)
        .map(|v| {
            serde_json::json!({
                "versionId": v.version_id,
                "lastModified": v.last_modified,
                "size": v.size,
                "etag": v.etag,
                "isDeleteMarker": v.is_delete_marker,
            })
        })
        .collect();

    response::json(StatusCode::OK, serde_json::json!({"versions": versions}))
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
        Err(err) => return storage::internal_err(err),
    };

    let filename = key.rsplit('/').next().unwrap_or(&key);
    let safe_filename = sanitize_filename(filename);
    let stream = tokio_util::io::ReaderStream::new(reader);
    let body = axum::body::Body::from_stream(stream);

    response::download(body, &meta.content_type, meta.size, &safe_filename)
}
