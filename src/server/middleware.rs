use super::*;
use crate::cluster::transport_identity::VerifiedPeerIdentity;

/// Run before any header sanitization or S3 handler. In secure peer mode,
/// merely removing an untrusted forwarding header could turn a rejected
/// replication request into an ordinary write, so reject the request itself.
pub(super) async fn peer_connection_identity_middleware(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let peer_tls = state.config.cluster_peer_transport_required()
        || state.config.cluster_peer_tls_cert_path.is_some()
        || state.config.cluster_peer_tls_key_path.is_some()
        || state.config.cluster_peer_tls_ca_path.is_some();
    let internal = request.uri().path() == "/internal"
        || request.uri().path().starts_with("/internal/")
        || request.headers().keys().any(|name| {
            name.as_str().starts_with("x-maxio-internal-")
                || name.as_str().starts_with("x-maxio-forwarded-")
                || name.as_str().starts_with("x-maxio-join-")
        });
    if peer_tls
        && internal
        && let Err(reason) = check_peer_connection_identity(&state, &request)
    {
        let endpoint = RuntimeInternalHeaderRejectEndpoint::for_path(request.uri().path());
        let sender = classify_runtime_internal_header_reject_sender(
            request.headers(),
            state.node_id.as_str(),
            &state.active_cluster_peers(),
        );
        state
            .runtime_internal_header_reject_dimensions
            .record(endpoint, sender);
        tracing::warn!(
            reason,
            "Rejected internal request without matching peer TLS identity"
        );
        return response_with_content_type(
            StatusCode::FORBIDDEN,
            HeaderValue::from_static("application/json"),
            axum::body::Body::from(
                serde_json::json!({
                    "error": "peer_tls_identity_required", "reason": reason,
                })
                .to_string(),
            ),
        );
    }
    next.run(request).await
}

fn check_peer_connection_identity(
    state: &AppState,
    request: &axum::extract::Request,
) -> Result<(), &'static str> {
    let peer = request
        .extensions()
        .get::<VerifiedPeerIdentity>()
        .ok_or("a verified client certificate is required for internal requests")?;
    if peer.node_id() == state.node_id.as_str() {
        return Err("the local node certificate cannot authenticate a remote peer");
    }
    if !state
        .active_cluster_peers()
        .iter()
        .any(|allowed| allowed == peer.node_id())
    {
        return Err("the certificate node identity is not a configured peer");
    }
    for name in [
        FORWARDED_BY_HEADER,
        JOIN_NODE_ID_HEADER,
        INTERNAL_AUTH_TOKEN_HEADER,
    ] {
        if request.headers().get_all(name).iter().count() > 1 {
            return Err("duplicate internal identity or authentication headers");
        }
    }
    let authentication = authenticate_forwarded_request(
        request.headers(),
        FORWARDED_BY_HEADER,
        state.config.cluster_auth_token(),
        state.node_id.as_str(),
        &state.active_cluster_peers(),
    );
    if !authentication.trusted {
        record_peer_auth_rejection(&authentication);
        return Err("internal forwarding marker or shared-token authorization failed");
    }
    if let Some(value) = request.headers().get(FORWARDED_BY_HEADER) {
        let chain = value
            .to_str()
            .ok()
            .and_then(|value| parse_forwarded_by_chain(value).ok())
            .ok_or("invalid forwarded peer chain")?;
        if chain.last().map(String::as_str) != Some(peer.node_id()) {
            return Err(
                "the last forwarding hop does not match the client certificate node identity",
            );
        }
    }
    if let Some(value) = request.headers().get(JOIN_NODE_ID_HEADER) {
        let claimed = value
            .to_str()
            .ok()
            .and_then(canonical_peer_identity)
            .ok_or("invalid join node identity")?;
        if claimed != peer.node_id() {
            return Err("the join node claim does not match the client certificate node identity");
        }
    }
    Ok(())
}

pub(super) fn response_with_content_type(
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

pub(super) fn json_body_or_fallback<T: serde::Serialize>(
    payload: &T,
    fallback: &'static [u8],
    context: &str,
) -> axum::body::Body {
    match serde_json::to_vec(payload) {
        Ok(body) => axum::body::Body::from(body),
        Err(err) => {
            tracing::error!(
                error = %err,
                context = context,
                "Failed to serialize runtime JSON payload"
            );
            axum::body::Body::from(fallback.to_vec())
        }
    }
}

pub(super) fn apply_cors_headers(response_headers: &mut HeaderMap, request_headers: &HeaderMap) {
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

pub(super) fn build_allow_headers(request_headers: &HeaderMap) -> HeaderValue {
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

pub(super) fn is_valid_header_name_token(token: &str) -> bool {
    token.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            )
    })
}

pub(super) fn merge_vary_headers(response_headers: &mut HeaderMap, values: &[&str]) {
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

pub(super) async fn cors_middleware(
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

pub(super) async fn request_id_middleware(
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

pub(super) async fn internal_forwarding_sanitization_middleware(
    State(state): State<AppState>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let active_cluster_peers = state.active_cluster_peers();
    let reject_endpoint = RuntimeInternalHeaderRejectEndpoint::for_path(request.uri().path());
    let reject_sender = classify_runtime_internal_header_reject_sender(
        request.headers(),
        state.node_id.as_str(),
        active_cluster_peers.as_slice(),
    );
    let peer_auth_result = strip_untrusted_internal_forwarding_headers(
        request.headers_mut(),
        state.config.cluster_auth_token(),
        state.node_id.as_str(),
        active_cluster_peers.as_slice(),
    );
    if !peer_auth_result.trusted {
        record_peer_auth_rejection(&peer_auth_result);
        state
            .runtime_internal_header_reject_dimensions
            .record(reject_endpoint, reject_sender);
    }

    next.run(request).await
}

pub(super) fn classify_runtime_internal_header_reject_sender(
    headers: &HeaderMap,
    local_node_id: &str,
    cluster_peers: &[String],
) -> RuntimeInternalHeaderRejectSender {
    let Some(forwarded_by) = headers
        .get(FORWARDED_BY_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return RuntimeInternalHeaderRejectSender::MissingOrInvalid;
    };

    let Ok(chain) = parse_forwarded_by_chain(forwarded_by) else {
        return RuntimeInternalHeaderRejectSender::MissingOrInvalid;
    };
    let Some(sender) = chain.last().map(String::as_str) else {
        return RuntimeInternalHeaderRejectSender::MissingOrInvalid;
    };

    if sender == local_node_id {
        return RuntimeInternalHeaderRejectSender::LocalNode;
    }
    if cluster_peers.iter().any(|peer| peer == sender) {
        return RuntimeInternalHeaderRejectSender::KnownPeer;
    }
    RuntimeInternalHeaderRejectSender::UnknownPeer
}
