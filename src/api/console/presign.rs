use axum::{
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};

use super::response;
use super::{auth::ConsolePrincipal, storage};
use crate::auth::signature_v4;
use crate::metadata::ClusterMetadataListingStrategy;
use crate::server::{AppState, runtime_topology_snapshot};
use crate::storage::StorageError;

#[derive(serde::Deserialize)]
pub(super) struct PresignParams {
    expires: Option<u64>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct PresignResponse {
    url: String,
    expires_in: u64,
}

pub(super) async fn presign_object(
    State(state): State<AppState>,
    Extension(principal): Extension<ConsolePrincipal>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<PresignParams>,
    headers: HeaderMap,
) -> impl IntoResponse {
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
        "PresignConsoleObject",
    ) {
        return *err;
    }

    if !topology.is_distributed()
        || state.metadata_listing_strategy != ClusterMetadataListingStrategy::ConsensusIndex
    {
        match state.storage.head_object(&bucket, &key).await {
            Ok(_) => {}
            Err(StorageError::NotFound(_)) => {
                return response::error(StatusCode::NOT_FOUND, "Object not found");
            }
            Err(err) => return storage::internal_err(err),
        }
    }

    let expires_secs = params.expires.unwrap_or(3600).min(604800);

    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:9000");

    let scheme = if headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "https")
        .unwrap_or(false)
    {
        "https"
    } else {
        "http"
    };

    let path = format!("/{}/{}", bucket, key);
    let Some(secret_key) = state.credentials.get(&principal.access_key) else {
        return response::error(StatusCode::UNAUTHORIZED, "Not authenticated");
    };

    let presigned_url = match signature_v4::generate_presigned_url(signature_v4::PresignRequest {
        method: "GET",
        scheme,
        host,
        path: &path,
        extra_query_params: &[],
        access_key: &principal.access_key,
        secret_key,
        region: &state.config.region,
        now: chrono::Utc::now(),
        expires_secs,
    }) {
        Ok(url) => url,
        Err(msg) => {
            return response::error(StatusCode::BAD_REQUEST, msg);
        }
    };

    response::json(
        StatusCode::OK,
        PresignResponse {
            url: presigned_url,
            expires_in: expires_secs,
        },
    )
}
