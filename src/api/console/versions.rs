use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::api::console::objects::sanitize_filename;
use crate::api::console::response;
use crate::server::AppState;
use crate::storage::StorageError;

pub(super) async fn get_versioning(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> impl IntoResponse {
    match state.storage.is_versioned(&bucket).await {
        Ok(enabled) => response::json(StatusCode::OK, serde_json::json!({"enabled": enabled})),
        Err(StorageError::NotFound(_)) => response::error(StatusCode::NOT_FOUND, "Bucket not found"),
        Err(e) => response::error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
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
        Err(StorageError::NotFound(_)) => response::error(StatusCode::NOT_FOUND, "Bucket not found"),
        Err(e) => response::error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
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
    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return response::error(StatusCode::NOT_FOUND, "Bucket not found"),
        Err(e) => return response::error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }

    let all = match state
        .storage
        .list_object_versions(&bucket, &params.key)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            return response::error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
        }
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
        Err(StorageError::VersionNotFound(_) | StorageError::NotFound(_)) => {
            response::error(StatusCode::NOT_FOUND, "Version not found")
        }
        Err(e) => response::error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub(super) async fn download_version(
    State(state): State<AppState>,
    Path((bucket, version_id, key)): Path<(String, String, String)>,
) -> Response {
    let (reader, meta) = match state
        .storage
        .get_object_version(&bucket, &key, &version_id)
        .await
    {
        Ok(r) => r,
        Err(_) => return response::error(StatusCode::NOT_FOUND, "Version not found"),
    };

    let filename = key.rsplit('/').next().unwrap_or(&key);
    let safe_filename = sanitize_filename(filename);
    let stream = tokio_util::io::ReaderStream::new(reader);
    let body = axum::body::Body::from_stream(stream);

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", &meta.content_type)
        .header("Content-Length", meta.size.to_string())
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", safe_filename),
        )
        .body(body)
        .unwrap()
        .into_response()
}
