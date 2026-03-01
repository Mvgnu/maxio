use std::collections::BTreeSet;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use futures::TryStreamExt;

use super::response;
use crate::server::AppState;

#[derive(serde::Deserialize)]
pub(super) struct ListObjectsParams {
    prefix: Option<String>,
    delimiter: Option<String>,
}

pub(super) async fn list_objects(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<ListObjectsParams>,
) -> impl IntoResponse {
    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return response::error(StatusCode::NOT_FOUND, "Bucket not found"),
        Err(e) => return response::error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }

    let prefix = params.prefix.unwrap_or_default();
    let delimiter = params.delimiter.unwrap_or_else(|| "/".to_string());

    let all_objects = match state.storage.list_objects(&bucket, &prefix).await {
        Ok(objects) => objects,
        Err(e) => return response::error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    let mut files = Vec::new();
    let mut prefix_set = BTreeSet::new();

    for obj in &all_objects {
        let suffix = &obj.key[prefix.len()..];
        if let Some(pos) = suffix.find(delimiter.as_str()) {
            let common = format!("{}{}", prefix, &suffix[..pos + delimiter.len()]);
            prefix_set.insert(common);
        } else if !obj.key.ends_with('/') {
            files.push(serde_json::json!({
                "key": obj.key,
                "size": obj.size,
                "lastModified": obj.last_modified,
                "etag": obj.etag,
            }));
        }
    }

    let mut empty_prefixes: Vec<&String> = Vec::new();
    for p in &prefix_set {
        let has_children = all_objects
            .iter()
            .any(|obj| obj.key.starts_with(p.as_str()) && obj.key != *p);
        if !has_children {
            empty_prefixes.push(p);
        }
    }

    let prefixes: Vec<&String> = prefix_set.iter().collect();

    response::json(
        StatusCode::OK,
        serde_json::json!({
            "files": files,
            "prefixes": prefixes,
            "emptyPrefixes": empty_prefixes,
        }),
    )
}

pub(super) async fn upload_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> impl IntoResponse {
    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return response::error(StatusCode::NOT_FOUND, "Bucket not found"),
        Err(e) => return response::error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }

    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");

    let stream = body.into_data_stream();
    let reader = tokio_util::io::StreamReader::new(
        stream.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)),
    );

    match state
        .storage
        .put_object(&bucket, &key, content_type, Box::pin(reader), None)
        .await
    {
        Ok(result) => response::json(
            StatusCode::OK,
            serde_json::json!({
                "ok": true,
                "etag": result.etag,
                "size": result.size,
            }),
        ),
        Err(e) => response::error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub(super) async fn delete_object_api(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return response::error(StatusCode::NOT_FOUND, "Bucket not found"),
        Err(e) => return response::error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }

    match state.storage.delete_object(&bucket, &key).await {
        Ok(_) => response::ok(),
        Err(e) => response::error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub(super) async fn download_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
) -> Response {
    let (reader, meta) = match state.storage.get_object(&bucket, &key).await {
        Ok(r) => r,
        Err(_) => return response::error(StatusCode::NOT_FOUND, "Object not found"),
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
    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return response::error(StatusCode::NOT_FOUND, "Bucket not found"),
        Err(e) => return response::error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
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
        Ok(_) => response::ok(),
        Err(e) => response::error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}
