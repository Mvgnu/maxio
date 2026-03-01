use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};

use crate::api::console::response;
use crate::server::AppState;
use crate::storage::{StorageError, lifecycle::LifecycleRule};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct LifecycleRuleDto {
    id: String,
    prefix: String,
    expiration_days: u32,
    enabled: bool,
}

impl From<LifecycleRule> for LifecycleRuleDto {
    fn from(rule: LifecycleRule) -> Self {
        Self {
            id: rule.id,
            prefix: rule.prefix,
            expiration_days: rule.expiration_days,
            enabled: rule.enabled,
        }
    }
}

impl From<LifecycleRuleDto> for LifecycleRule {
    fn from(rule: LifecycleRuleDto) -> Self {
        Self {
            id: rule.id,
            prefix: rule.prefix,
            expiration_days: rule.expiration_days,
            enabled: rule.enabled,
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SetLifecycleRequest {
    rules: Vec<LifecycleRuleDto>,
}

pub(super) async fn get_lifecycle(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> impl IntoResponse {
    match state.storage.get_lifecycle_rules(&bucket).await {
        Ok(rules) => response::json(
            StatusCode::OK,
            serde_json::json!({
                "rules": rules.into_iter().map(LifecycleRuleDto::from).collect::<Vec<_>>()
            }),
        ),
        Err(StorageError::NotFound(_)) => {
            response::error(StatusCode::NOT_FOUND, "Bucket not found")
        }
        Err(e) => response::error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub(super) async fn set_lifecycle(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Json(body): Json<SetLifecycleRequest>,
) -> impl IntoResponse {
    let rules: Vec<LifecycleRule> = body.rules.into_iter().map(LifecycleRule::from).collect();
    match state.storage.set_lifecycle_rules(&bucket, &rules).await {
        Ok(()) => response::ok(),
        Err(StorageError::NotFound(_)) => {
            response::error(StatusCode::NOT_FOUND, "Bucket not found")
        }
        Err(StorageError::InvalidKey(msg)) => response::error(StatusCode::BAD_REQUEST, msg),
        Err(e) => response::error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}
