use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::Response;
use axum::routing::get;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::api::console::{LoginRateLimiter, console_router};
use crate::api::router::s3_router;
use crate::auth::middleware::auth_middleware;
use crate::config::Config;
use crate::embedded::ui_handler;
use crate::storage::filesystem::FilesystemStorage;

const CORS_ALLOW_HEADERS_BASELINE: &str = "authorization,content-type,x-amz-date,x-amz-content-sha256,x-amz-security-token,x-amz-user-agent,x-amz-checksum-algorithm,x-amz-checksum-crc32,x-amz-checksum-crc32c,x-amz-checksum-sha1,x-amz-checksum-sha256,range";
const CORS_ALLOW_HEADERS_BASELINE_FIELDS: &[&str] = &[
    "authorization",
    "content-type",
    "x-amz-date",
    "x-amz-content-sha256",
    "x-amz-security-token",
    "x-amz-user-agent",
    "x-amz-checksum-algorithm",
    "x-amz-checksum-crc32",
    "x-amz-checksum-crc32c",
    "x-amz-checksum-sha1",
    "x-amz-checksum-sha256",
    "range",
];

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<FilesystemStorage>,
    pub config: Arc<Config>,
    pub credentials: Arc<HashMap<String, String>>,
    pub node_id: Arc<String>,
    pub cluster_peers: Arc<Vec<String>>,
    pub login_rate_limiter: Arc<LoginRateLimiter>,
    pub request_count: Arc<AtomicU64>,
    pub started_at: Instant,
}

impl AppState {
    /// Construct the shared runtime state from a parsed config.
    pub async fn from_config(config: Config) -> anyhow::Result<Self> {
        let credentials = config.credential_map().map_err(anyhow::Error::msg)?;
        let cluster_peers = config.parsed_cluster_peers().map_err(anyhow::Error::msg)?;
        let node_id = config.node_id.clone();
        let storage = FilesystemStorage::new(
            &config.data_dir,
            config.erasure_coding,
            config.chunk_size,
            config.parity_shards,
        )
        .await?;

        Ok(Self {
            storage: Arc::new(storage),
            config: Arc::new(config),
            credentials: Arc::new(credentials),
            node_id: Arc::new(node_id),
            cluster_peers: Arc::new(cluster_peers),
            login_rate_limiter: Arc::new(LoginRateLimiter::new()),
            request_count: Arc::new(AtomicU64::new(0)),
            started_at: Instant::now(),
        })
    }
}

pub fn build_router(state: AppState) -> Router {
    let s3_routes = s3_router().layer(axum::middleware::from_fn_with_state(
        state.clone(),
        auth_middleware,
    ));

    Router::new()
        .nest("/api", console_router(state.clone()))
        .route("/healthz", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .route("/ui", get(ui_handler))
        .route("/ui/", get(ui_handler))
        .route("/ui/{*path}", get(ui_handler))
        .merge(s3_routes)
        .layer(axum::middleware::from_fn(cors_middleware))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            request_id_middleware,
        ))
        .with_state(state)
}

async fn metrics_handler(State(state): State<AppState>) -> Response {
    let request_count = state.request_count.load(Ordering::Relaxed);
    let uptime = state.started_at.elapsed().as_secs_f64();
    let distributed_mode = if state.cluster_peers.is_empty() { 0 } else { 1 };
    let cluster_peer_count = state.cluster_peers.len();

    let body = format!(
        "# HELP maxio_requests_total Total HTTP requests observed by MaxIO.\n\
         # TYPE maxio_requests_total counter\n\
         maxio_requests_total {}\n\
         # HELP maxio_uptime_seconds MaxIO process uptime in seconds.\n\
         # TYPE maxio_uptime_seconds gauge\n\
         maxio_uptime_seconds {:.3}\n\
         # HELP maxio_build_info Build and version information for MaxIO.\n\
         # TYPE maxio_build_info gauge\n\
         maxio_build_info{{version=\"{}\"}} 1\n\
         # HELP maxio_distributed_mode Whether MaxIO is running with configured cluster peers (1=true, 0=false).\n\
         # TYPE maxio_distributed_mode gauge\n\
         maxio_distributed_mode {}\n\
         # HELP maxio_cluster_peers_total Number of configured cluster peers.\n\
         # TYPE maxio_cluster_peers_total gauge\n\
         maxio_cluster_peers_total {}\n",
        request_count,
        uptime,
        env!("CARGO_PKG_VERSION"),
        distributed_mode,
        cluster_peer_count
    );

    response_with_content_type(
        StatusCode::OK,
        HeaderValue::from_static("text/plain; version=0.0.4"),
        axum::body::Body::from(body),
    )
}

async fn health_handler(State(state): State<AppState>) -> Response {
    let uptime_seconds = state.started_at.elapsed().as_secs_f64();
    let distributed_mode = !state.cluster_peers.is_empty();
    let body = serde_json::json!({
        "ok": true,
        "version": env!("CARGO_PKG_VERSION"),
        "uptimeSeconds": uptime_seconds,
        "mode": if distributed_mode { "distributed" } else { "standalone" },
        "nodeId": state.node_id.as_str(),
        "clusterPeerCount": state.cluster_peers.len(),
        "clusterPeers": state.cluster_peers.as_ref(),
    });

    response_with_content_type(
        StatusCode::OK,
        HeaderValue::from_static("application/json"),
        axum::body::Body::from(body.to_string()),
    )
}

fn response_with_content_type(
    status: StatusCode,
    content_type: HeaderValue,
    body: axum::body::Body,
) -> Response {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    response
}

fn apply_cors_headers(response_headers: &mut HeaderMap, request_headers: &HeaderMap) {
    let origin = request_headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty());

    if let Some(origin) = origin {
        if let Ok(value) = HeaderValue::from_str(origin) {
            response_headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
            response_headers.insert(
                header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
        }
    } else {
        response_headers.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
        response_headers.remove(header::ACCESS_CONTROL_ALLOW_CREDENTIALS);
    }
    response_headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, PUT, POST, DELETE, HEAD, OPTIONS"),
    );
    response_headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        build_allow_headers(request_headers),
    );
    response_headers.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static(
            "etag,x-amz-request-id,x-amz-version-id,x-amz-delete-marker,x-amz-checksum-crc32,x-amz-checksum-crc32c,x-amz-checksum-sha1,x-amz-checksum-sha256,content-length,content-type,last-modified,accept-ranges,content-range,location",
        ),
    );
    response_headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("86400"),
    );
    let mut vary_fields = vec!["Origin"];
    if request_headers.contains_key(header::ACCESS_CONTROL_REQUEST_METHOD) {
        vary_fields.push("Access-Control-Request-Method");
    }
    if request_headers.contains_key(header::ACCESS_CONTROL_REQUEST_HEADERS) {
        vary_fields.push("Access-Control-Request-Headers");
    }
    merge_vary_headers(response_headers, &vary_fields);
}

fn build_allow_headers(request_headers: &HeaderMap) -> HeaderValue {
    let mut allow_headers: Vec<String> = CORS_ALLOW_HEADERS_BASELINE_FIELDS
        .iter()
        .map(|v| (*v).to_string())
        .collect();

    if let Some(requested_headers) = request_headers
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .and_then(|v| v.to_str().ok())
    {
        for token in requested_headers.split(',').map(str::trim) {
            if token.is_empty() || !is_valid_header_name_token(token) {
                continue;
            }
            let normalized = token.to_ascii_lowercase();
            if !allow_headers
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(&normalized))
            {
                allow_headers.push(normalized);
            }
        }
    }

    HeaderValue::from_str(&allow_headers.join(","))
        .unwrap_or_else(|_| HeaderValue::from_static(CORS_ALLOW_HEADERS_BASELINE))
}

fn is_valid_header_name_token(token: &str) -> bool {
    token.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^'
                    | b'_' | b'`' | b'|' | b'~'
            )
    })
}

fn merge_vary_headers(response_headers: &mut HeaderMap, values: &[&str]) {
    let mut combined = Vec::<String>::new();

    if let Some(existing) = response_headers
        .get(header::VARY)
        .and_then(|v| v.to_str().ok())
    {
        for part in existing.split(',') {
            let token = part.trim();
            if !token.is_empty()
                && !combined
                    .iter()
                    .any(|entry| entry.eq_ignore_ascii_case(token))
            {
                combined.push(token.to_string());
            }
        }
    }

    for value in values {
        if !combined
            .iter()
            .any(|entry| entry.eq_ignore_ascii_case(value))
        {
            combined.push((*value).to_string());
        }
    }

    if let Ok(vary) = HeaderValue::from_str(&combined.join(", ")) {
        response_headers.insert(header::VARY, vary);
    }
}

async fn cors_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let request_headers = request.headers().clone();

    if request.method() == Method::OPTIONS {
        let mut response = Response::new(axum::body::Body::empty());
        *response.status_mut() = StatusCode::NO_CONTENT;
        apply_cors_headers(response.headers_mut(), &request_headers);
        return response;
    }

    let mut response = next.run(request).await;
    apply_cors_headers(response.headers_mut(), &request_headers);
    response
}

async fn request_id_middleware(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    state.request_count.fetch_add(1, Ordering::Relaxed);
    let request_id = uuid::Uuid::new_v4().to_string();
    let mut response = next.run(request).await;
    if let Ok(value) = request_id.parse() {
        response.headers_mut().insert("x-amz-request-id", value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_vary_headers_deduplicates_and_preserves_existing_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::VARY,
            HeaderValue::from_static("Accept-Encoding, Origin"),
        );

        merge_vary_headers(
            &mut headers,
            &[
                "Origin",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers",
            ],
        );

        let vary = headers
            .get(header::VARY)
            .and_then(|v| v.to_str().ok())
            .expect("vary should be set");
        assert_eq!(
            vary,
            "Accept-Encoding, Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
        );
    }

    #[test]
    fn response_with_content_type_sets_status_and_header() {
        let response = response_with_content_type(
            StatusCode::CREATED,
            HeaderValue::from_static("application/json"),
            axum::body::Body::from("{}"),
        );
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
    }

    #[test]
    fn apply_cors_headers_reflected_origin_sets_allow_credentials() {
        let mut request_headers = HeaderMap::new();
        request_headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://example.com"),
        );
        let mut response_headers = HeaderMap::new();

        apply_cors_headers(&mut response_headers, &request_headers);

        assert_eq!(
            response_headers
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok()),
            Some("https://example.com")
        );
        assert_eq!(
            response_headers
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .and_then(|v| v.to_str().ok()),
            Some("true")
        );
    }

    #[test]
    fn apply_cors_headers_without_origin_uses_wildcard_without_credentials() {
        let request_headers = HeaderMap::new();
        let mut response_headers = HeaderMap::new();

        apply_cors_headers(&mut response_headers, &request_headers);

        assert_eq!(
            response_headers
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok()),
            Some("*")
        );
        assert!(
            response_headers
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none()
        );
    }

    #[test]
    fn build_allow_headers_adds_requested_headers_once() {
        let mut request_headers = HeaderMap::new();
        request_headers.insert(
            header::ACCESS_CONTROL_REQUEST_HEADERS,
            HeaderValue::from_static("X-Amz-Date, X-Custom-Trace, x custom invalid, x-custom-trace"),
        );

        let allow_header_value = build_allow_headers(&request_headers);
        let allow_headers = allow_header_value
            .to_str()
            .expect("allow headers should be valid utf-8");
        let values: Vec<&str> = allow_headers.split(',').collect();

        assert!(values.contains(&"x-amz-date"));
        assert!(values.contains(&"x-custom-trace"));
        assert!(!values.contains(&"x custom invalid"));
        assert_eq!(
            values
                .iter()
                .filter(|entry| entry.eq_ignore_ascii_case(&"x-custom-trace"))
                .count(),
            1
        );
    }
}
