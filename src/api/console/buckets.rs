use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Serialize;

use super::response;
use crate::server::AppState;
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

pub(super) async fn list_buckets(State(state): State<AppState>) -> impl IntoResponse {
    match state.storage.list_buckets().await {
        Ok(buckets) => {
            let list = buckets
                .into_iter()
                .map(|bucket| BucketSummary {
                    name: bucket.name,
                    created_at: bucket.created_at,
                    versioning: bucket.versioning,
                })
                .collect::<Vec<_>>();
            response::json(StatusCode::OK, ListBucketsResponse { buckets: list })
        }
        Err(e) => response::error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

#[derive(serde::Deserialize)]
pub(super) struct CreateBucketRequest {
    name: String,
}

pub(super) async fn create_bucket(
    State(state): State<AppState>,
    Json(body): Json<CreateBucketRequest>,
) -> impl IntoResponse {
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
        Ok(true) => response::ok(),
        Ok(false) => response::error(StatusCode::CONFLICT, "Bucket already exists"),
        Err(e) => response::error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub(super) async fn delete_bucket_api(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> impl IntoResponse {
    match state.storage.delete_bucket(&bucket).await {
        Ok(true) => response::ok(),
        Ok(false) => response::error(StatusCode::NOT_FOUND, "Bucket not found"),
        Err(StorageError::BucketNotEmpty) => {
            response::error(StatusCode::CONFLICT, "Bucket is not empty")
        }
        Err(e) => response::error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}
