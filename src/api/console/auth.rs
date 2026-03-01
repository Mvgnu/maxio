use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use axum::{
    Json,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::response;
use crate::server::AppState;

type HmacSha256 = Hmac<Sha256>;

const COOKIE_NAME: &str = "maxio_session";
const TOKEN_MAX_AGE_SECS: i64 = 7 * 24 * 60 * 60;

const RATE_LIMIT_MAX: u32 = 10;
const RATE_LIMIT_WINDOW_SECS: u64 = 300;

#[derive(Clone, Debug)]
pub(super) struct ConsolePrincipal {
    pub access_key: String,
    pub session_issued_at: i64,
    pub session_expires_at: i64,
}

struct Bucket {
    count: u32,
    window_start: Instant,
}

pub struct LoginRateLimiter {
    buckets: std::sync::Mutex<HashMap<String, Bucket>>,
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Returns `Some(retry_after_secs)` if the IP is rate-limited, `None` if allowed.
    /// Increments the counter on every call (success and failure both count).
    pub fn check_and_increment(&self, ip: &str) -> Option<u64> {
        let mut map = match self.buckets.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();

        map.retain(|_, b| {
            now.duration_since(b.window_start).as_secs() < RATE_LIMIT_WINDOW_SECS * 2
        });

        let bucket = map.entry(ip.to_string()).or_insert(Bucket {
            count: 0,
            window_start: now,
        });

        if now.duration_since(bucket.window_start).as_secs() >= RATE_LIMIT_WINDOW_SECS {
            bucket.count = 0;
            bucket.window_start = now;
        }

        bucket.count += 1;

        if bucket.count > RATE_LIMIT_MAX {
            let remaining = RATE_LIMIT_WINDOW_SECS
                .saturating_sub(now.duration_since(bucket.window_start).as_secs());
            Some(remaining.max(1))
        } else {
            None
        }
    }
}

fn extract_client_ip(headers: &HeaderMap, addr: &SocketAddr) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| addr.ip().to_string())
}

fn generate_token(access_key: &str, secret_key: &str, issued_at: i64) -> Option<String> {
    let issued_hex = format!("{:x}", issued_at);
    let mut mac = HmacSha256::new_from_slice(secret_key.as_bytes()).ok()?;
    mac.update(format!("{}:{}", access_key, issued_hex).as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    Some(format!("{}.{}.{}", access_key, issued_hex, sig))
}

#[derive(Clone, Debug)]
struct AuthenticatedSession {
    access_key: String,
    issued_at: i64,
    expires_at: i64,
}

fn authenticated_session(
    token: &str,
    credentials: &HashMap<String, String>,
) -> Option<AuthenticatedSession> {
    let mut parts = token.splitn(3, '.');
    let Some(access_key) = parts.next() else {
        return None;
    };
    let Some(issued_hex) = parts.next() else {
        return None;
    };
    let Some(signature) = parts.next() else {
        return None;
    };

    let Some(secret_key) = credentials.get(access_key) else {
        return None;
    };

    let Ok(issued_at) = i64::from_str_radix(issued_hex, 16) else {
        return None;
    };

    let now = chrono::Utc::now().timestamp();
    if now - issued_at > TOKEN_MAX_AGE_SECS || issued_at > now + 60 {
        return None;
    }
    let expires_at = issued_at + TOKEN_MAX_AGE_SECS;

    let mut mac = HmacSha256::new_from_slice(secret_key.as_bytes()).ok()?;
    mac.update(format!("{}:{}", access_key, issued_hex).as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    if constant_time_eq(signature.as_bytes(), expected.as_bytes()) {
        Some(AuthenticatedSession {
            access_key: access_key.to_string(),
            issued_at,
            expires_at,
        })
    } else {
        None
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn extract_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .map(|c| c.trim())
                .find(|c| c.starts_with(&format!("{}=", COOKIE_NAME)))
                .map(|c| c[COOKIE_NAME.len() + 1..].to_string())
        })
}

fn make_cookie(value: &str, max_age: i64, request_headers: &HeaderMap) -> String {
    let is_secure = request_headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "https")
        .unwrap_or(false);

    let secure_flag = if is_secure { "; Secure" } else { "" };

    format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
        COOKIE_NAME, value, max_age, secure_flag
    )
}

fn set_cookie_header(headers: &mut HeaderMap, cookie: &str) -> bool {
    let Ok(value) = cookie.parse() else {
        return false;
    };
    headers.insert("Set-Cookie", value);
    true
}

pub(super) async fn console_auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let authenticated_session = extract_cookie(request.headers())
        .and_then(|token| authenticated_session(&token, &state.credentials));

    let Some(session) = authenticated_session else {
        return response::error(StatusCode::UNAUTHORIZED, "Not authenticated");
    };

    request.extensions_mut().insert(ConsolePrincipal {
        access_key: session.access_key,
        session_issued_at: session.issued_at,
        session_expires_at: session.expires_at,
    });
    next.run(request).await
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct LoginRequest {
    access_key: String,
    secret_key: String,
}

pub(super) async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Response {
    let ip = extract_client_ip(&headers, &addr);

    if let Some(retry_after) = state.login_rate_limiter.check_and_increment(&ip) {
        return axum::response::IntoResponse::into_response((
            StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, retry_after.to_string())],
            Json(serde_json::json!({"error": "Too many login attempts. Try again later."})),
        ));
    }

    let Some(secret_key) = state.credentials.get(&body.access_key) else {
        return response::error(StatusCode::UNAUTHORIZED, "Invalid credentials");
    };

    let secret_match = constant_time_eq(body.secret_key.as_bytes(), secret_key.as_bytes());
    if !secret_match {
        return response::error(StatusCode::UNAUTHORIZED, "Invalid credentials");
    }

    let now = chrono::Utc::now().timestamp();
    let Some(token) = generate_token(&body.access_key, secret_key, now) else {
        return response::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error");
    };
    let cookie = make_cookie(&token, TOKEN_MAX_AGE_SECS, &headers);
    let expires_at = now + TOKEN_MAX_AGE_SECS;

    let mut resp_headers = HeaderMap::new();
    if !set_cookie_header(&mut resp_headers, &cookie) {
        return response::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error");
    }

    axum::response::IntoResponse::into_response((
        StatusCode::OK,
        resp_headers,
        Json(serde_json::json!({
            "ok": true,
            "accessKey": body.access_key,
            "sessionIssuedAt": now,
            "sessionExpiresAt": expires_at
        })),
    ))
}

pub(super) async fn check(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(session) =
        extract_cookie(&headers).and_then(|token| authenticated_session(&token, &state.credentials))
    {
        response::json(
            StatusCode::OK,
            serde_json::json!({
                "ok": true,
                "accessKey": session.access_key,
                "sessionIssuedAt": session.issued_at,
                "sessionExpiresAt": session.expires_at
            }),
        )
    } else {
        response::error(StatusCode::UNAUTHORIZED, "Not authenticated")
    }
}

pub(super) async fn logout(headers: HeaderMap) -> Response {
    let cookie = make_cookie("", 0, &headers);
    let mut resp_headers = HeaderMap::new();
    if !set_cookie_header(&mut resp_headers, &cookie) {
        return response::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error");
    }
    axum::response::IntoResponse::into_response((
        StatusCode::OK,
        resp_headers,
        Json(serde_json::json!({"ok": true})),
    ))
}

pub(super) async fn me(request: Request) -> Response {
    let Some(principal) = request.extensions().get::<ConsolePrincipal>() else {
        return response::error(StatusCode::UNAUTHORIZED, "Not authenticated");
    };

    response::json(
        StatusCode::OK,
        serde_json::json!({
            "accessKey": principal.access_key,
            "sessionIssuedAt": principal.session_issued_at,
            "sessionExpiresAt": principal.session_expires_at
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_cookie_header_rejects_invalid_header_value() {
        let mut headers = HeaderMap::new();
        assert!(!set_cookie_header(&mut headers, "bad\r\ncookie"));
        assert!(headers.get("set-cookie").is_none());
    }

    #[test]
    fn generate_token_roundtrip_authenticates_session() {
        let mut credentials = HashMap::new();
        credentials.insert("ak".to_string(), "sk".to_string());

        let issued_at = chrono::Utc::now().timestamp();
        let token = generate_token("ak", "sk", issued_at).expect("token should be generated");
        let session = authenticated_session(&token, &credentials).expect("session should validate");
        assert_eq!(session.access_key, "ak");
        assert_eq!(session.issued_at, issued_at);
        assert_eq!(session.expires_at, issued_at + TOKEN_MAX_AGE_SECS);
    }

    #[test]
    fn authenticated_session_rejects_future_issued_timestamp() {
        let mut credentials = HashMap::new();
        credentials.insert("ak".to_string(), "sk".to_string());

        let issued_at = chrono::Utc::now().timestamp() + 120;
        let token = generate_token("ak", "sk", issued_at).expect("token should be generated");
        assert!(authenticated_session(&token, &credentials).is_none());
    }
}
