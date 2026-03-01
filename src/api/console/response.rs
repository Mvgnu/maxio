use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

pub(super) fn json(status: StatusCode, value: serde_json::Value) -> Response {
    (status, Json(value)).into_response()
}

pub(super) fn ok() -> Response {
    json(StatusCode::OK, serde_json::json!({"ok": true}))
}

pub(super) fn error(status: StatusCode, message: impl Into<String>) -> Response {
    json(status, serde_json::json!({ "error": message.into() }))
}
