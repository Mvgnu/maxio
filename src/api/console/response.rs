use axum::{
    Json,
    body::Body,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Serialize)]
pub(super) struct OkResponse {
    pub(super) ok: bool,
}

#[derive(Serialize)]
pub(super) struct ErrorResponse {
    pub(super) error: String,
}

pub(super) fn json<T: Serialize>(status: StatusCode, payload: T) -> Response {
    (status, Json(payload)).into_response()
}

pub(super) fn ok() -> Response {
    json(StatusCode::OK, OkResponse { ok: true })
}

pub(super) fn error(status: StatusCode, message: impl Into<String>) -> Response {
    json(
        status,
        ErrorResponse {
            error: message.into(),
        },
    )
}

pub(super) fn download(
    body: Body,
    content_type: &str,
    content_length: u64,
    filename: &str,
) -> Response {
    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::OK;

    let headers = response.headers_mut();
    let content_type_header = HeaderValue::from_str(content_type)
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
    headers.insert(header::CONTENT_TYPE, content_type_header);

    if let Ok(content_length_header) = HeaderValue::from_str(&content_length.to_string()) {
        headers.insert(header::CONTENT_LENGTH, content_length_header);
    }

    let content_disposition = format!("attachment; filename=\"{}\"", filename);
    if let Ok(content_disposition_header) = HeaderValue::from_str(&content_disposition) {
        headers.insert(header::CONTENT_DISPOSITION, content_disposition_header);
    } else {
        headers.insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("attachment"),
        );
    }

    response
}

#[cfg(test)]
mod tests {
    use super::download;

    #[test]
    fn download_falls_back_for_invalid_headers() {
        let response = download(
            axum::body::Body::empty(),
            "text/plain\r\nx-bad: yes",
            123,
            "bad\nname.txt",
        );
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let headers = response.headers();
        assert_eq!(
            headers
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/octet-stream")
        );
        assert_eq!(
            headers
                .get(axum::http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            Some("123")
        );
        assert_eq!(
            headers
                .get(axum::http::header::CONTENT_DISPOSITION)
                .and_then(|v| v.to_str().ok()),
            Some("attachment")
        );
    }
}
