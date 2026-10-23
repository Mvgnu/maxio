use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use super::response;
use super::sessions::{SESSION_MAX_AGE_SECS, SessionIssueError};
use crate::server::{AppState, TlsConnection};
use axum::{
    Extension, Json,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};

const COOKIE_NAME: &str = "maxio_session";
const RATE_LIMIT_MAX: u32 = 10;
const RATE_LIMIT_WINDOW_SECS: u64 = 300;
const RATE_LIMIT_MAX_BUCKETS: usize = 4096;

#[derive(Clone, Debug)]
pub(super) struct ConsolePrincipal {
    pub access_key: String,
    pub session_issued_at: i64,
    pub session_expires_at: i64,
    session_verifier: [u8; 32],
}

struct Bucket {
    count: u32,
    window_start: Instant,
}

pub struct LoginRateLimiter {
    buckets: std::sync::Mutex<HashMap<IpAddr, Bucket>>,
}

impl Default for LoginRateLimiter {
    fn default() -> Self {
        Self::new()
    }
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
        let Ok(ip) = ip.parse::<IpAddr>() else {
            return Some(RATE_LIMIT_WINDOW_SECS);
        };
        let mut map = match self.buckets.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();

        map.retain(|_, b| now.duration_since(b.window_start).as_secs() < RATE_LIMIT_WINDOW_SECS);

        // New source IPs cannot grow memory without bound or evict a blocked IP.
        if map.len() >= RATE_LIMIT_MAX_BUCKETS && !map.contains_key(&ip) {
            return Some(
                map.values()
                    .map(|bucket| {
                        RATE_LIMIT_WINDOW_SECS
                            .saturating_sub(now.duration_since(bucket.window_start).as_secs())
                            .max(1)
                    })
                    .min()
                    .unwrap_or(RATE_LIMIT_WINDOW_SECS),
            );
        }
        let bucket = map.entry(ip).or_insert(Bucket {
            count: 0,
            window_start: now,
        });

        if now.duration_since(bucket.window_start).as_secs() >= RATE_LIMIT_WINDOW_SECS {
            bucket.count = 0;
            bucket.window_start = now;
        }

        bucket.count = bucket.count.saturating_add(1);

        if bucket.count > RATE_LIMIT_MAX {
            let remaining = RATE_LIMIT_WINDOW_SECS
                .saturating_sub(now.duration_since(bucket.window_start).as_secs());
            Some(remaining.max(1))
        } else {
            None
        }
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

fn extract_cookie(headers: &HeaderMap) -> Option<&str> {
    let mut token = None;
    for header in headers.get_all("cookie") {
        for cookie in header.to_str().ok()?.split(';') {
            if let Some((COOKIE_NAME, value)) = cookie.trim().split_once('=') {
                // Ambiguous duplicates must not authenticate different sessions
                // in middleware and logout. Token validation bounds its length.
                if token.replace(value).is_some() {
                    return None;
                }
            }
        }
    }
    token
}

fn make_cookie(value: &str, max_age: i64, request_headers: &HeaderMap, native_tls: bool) -> String {
    let is_secure = native_tls
        || request_headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(|v| v.trim())
            .is_some_and(|v| v.eq_ignore_ascii_case("https"));

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
    let authenticated_session = extract_cookie(request.headers()).and_then(|token| {
        state
            .console_sessions
            .authenticate(token, &state.credentials)
    });

    let Some(session) = authenticated_session else {
        return response::error(StatusCode::UNAUTHORIZED, "Not authenticated");
    };

    request.extensions_mut().insert(ConsolePrincipal {
        access_key: session.access_key,
        session_issued_at: session.issued_at,
        session_expires_at: session.expires_at,
        session_verifier: session.verifier,
    });
    next.run(request).await
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct LoginRequest {
    access_key: String,
    secret_key: String,
}

#[derive(serde::Serialize)]
struct LoginRateLimitErrorResponse {
    error: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionAuthResponse {
    ok: bool,
    access_key: String,
    session_issued_at: i64,
    session_expires_at: i64,
}

#[derive(serde::Serialize)]
struct LogoutResponse {
    ok: bool,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentityResponse {
    access_key: String,
    session_issued_at: i64,
    session_expires_at: i64,
}

pub(super) async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    tls: Option<Extension<TlsConnection>>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Response {
    let ip = addr.ip().to_string();

    if let Some(retry_after) = state.login_rate_limiter.check_and_increment(&ip) {
        return axum::response::IntoResponse::into_response((
            StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, retry_after.to_string())],
            Json(LoginRateLimitErrorResponse {
                error: "Too many login attempts. Try again later.".to_string(),
            }),
        ));
    }

    let Some(secret_key) = state.credentials.get(&body.access_key) else {
        return response::error(StatusCode::UNAUTHORIZED, "Invalid credentials");
    };

    let secret_match = constant_time_eq(body.secret_key.as_bytes(), secret_key.as_bytes());
    if !secret_match {
        return response::error(StatusCode::UNAUTHORIZED, "Invalid credentials");
    }

    let issued = match state
        .console_sessions
        .issue(&body.access_key, &state.credentials)
    {
        Ok(issued) => issued,
        Err(SessionIssueError::Full) => {
            return response::error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Console session limit reached. Sign out an existing session and retry.",
            );
        }
        Err(SessionIssueError::Unavailable) => {
            return response::error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Session registry unavailable",
            );
        }
    };
    let cookie = make_cookie(&issued.token, SESSION_MAX_AGE_SECS, &headers, tls.is_some());
    let session = issued.session;

    let mut resp_headers = HeaderMap::new();
    if !set_cookie_header(&mut resp_headers, &cookie) {
        state.console_sessions.revoke(&session.verifier);
        return response::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error");
    }

    axum::response::IntoResponse::into_response((
        StatusCode::OK,
        resp_headers,
        Json(SessionAuthResponse {
            ok: true,
            access_key: session.access_key,
            session_issued_at: session.issued_at,
            session_expires_at: session.expires_at,
        }),
    ))
}

pub(super) async fn check(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(session) = extract_cookie(&headers).and_then(|token| {
        state
            .console_sessions
            .authenticate(token, &state.credentials)
    }) {
        response::json(
            StatusCode::OK,
            SessionAuthResponse {
                ok: true,
                access_key: session.access_key,
                session_issued_at: session.issued_at,
                session_expires_at: session.expires_at,
            },
        )
    } else {
        response::error(StatusCode::UNAUTHORIZED, "Not authenticated")
    }
}

pub(super) async fn logout(State(state): State<AppState>, request: Request) -> Response {
    let Some(principal) = request.extensions().get::<ConsolePrincipal>() else {
        return response::error(StatusCode::UNAUTHORIZED, "Not authenticated");
    };
    if !state.console_sessions.revoke(&principal.session_verifier) {
        return response::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Session registry unavailable",
        );
    }
    let cookie = make_cookie(
        "",
        0,
        request.headers(),
        request.extensions().get::<TlsConnection>().is_some(),
    );
    let mut resp_headers = HeaderMap::new();
    if !set_cookie_header(&mut resp_headers, &cookie) {
        return response::error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error");
    }
    axum::response::IntoResponse::into_response((
        StatusCode::OK,
        resp_headers,
        Json(LogoutResponse { ok: true }),
    ))
}

pub(super) async fn me(request: Request) -> Response {
    let Some(principal) = request.extensions().get::<ConsolePrincipal>() else {
        return response::error(StatusCode::UNAUTHORIZED, "Not authenticated");
    };

    response::json(
        StatusCode::OK,
        IdentityResponse {
            access_key: principal.access_key.clone(),
            session_issued_at: principal.session_issued_at,
            session_expires_at: principal.session_expires_at,
        },
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
    fn make_cookie_sets_secure_for_https_forwarded_proto() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        let cookie = make_cookie("token", SESSION_MAX_AGE_SECS, &headers, false);
        assert!(cookie.contains("; Secure"));
    }

    #[test]
    fn make_cookie_sets_secure_for_first_forwarded_proto_value_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", " HTTPS, http ".parse().unwrap());
        let cookie = make_cookie("token", SESSION_MAX_AGE_SECS, &headers, false);
        assert!(cookie.contains("; Secure"));
    }

    #[test]
    fn make_cookie_omits_secure_for_non_https_forwarded_proto() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", "http,https".parse().unwrap());
        let cookie = make_cookie("token", SESSION_MAX_AGE_SECS, &headers, false);
        assert!(!cookie.contains("; Secure"));
    }

    #[test]
    fn native_tls_always_sets_secure_even_with_http_forwarded_proto() {
        let mut headers = HeaderMap::new();
        for forwarded in [None, Some("http"), Some("http,https")] {
            if let Some(value) = forwarded {
                headers.insert("x-forwarded-proto", value.parse().unwrap());
            }
            for (token, max_age) in [("token", SESSION_MAX_AGE_SECS), ("", 0)] {
                assert!(make_cookie(token, max_age, &headers, true).contains("; Secure"));
            }
        }
    }

    #[test]
    fn duplicate_session_cookies_are_rejected() {
        let mut headers = HeaderMap::new();
        headers.append(
            "cookie",
            "maxio_session=first; unrelated=value".parse().unwrap(),
        );
        assert_eq!(extract_cookie(&headers), Some("first"));
        headers.append("cookie", "maxio_session=second".parse().unwrap());
        assert_eq!(extract_cookie(&headers), None);
    }

    #[test]
    fn rate_limiter_is_bounded_without_evicting_blocked_addresses() {
        let limiter = LoginRateLimiter::new();
        let now = Instant::now();
        {
            let mut buckets = limiter.buckets.lock().unwrap();
            for address in 0..RATE_LIMIT_MAX_BUCKETS as u32 {
                buckets.insert(
                    IpAddr::V4(address.into()),
                    Bucket {
                        count: RATE_LIMIT_MAX,
                        window_start: now,
                    },
                );
            }
        }
        assert!(limiter.check_and_increment("203.0.113.1").is_some());
        assert!(limiter.check_and_increment("0.0.0.0").is_some());
        assert_eq!(
            limiter.buckets.lock().unwrap().len(),
            RATE_LIMIT_MAX_BUCKETS
        );
    }
}
