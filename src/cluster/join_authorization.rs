use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::cluster::authenticator::FORWARDED_BY_HEADER;
use crate::cluster::constant_time::constant_time_str_eq;
use crate::cluster::internal_transport::parse_forwarded_by_chain;
use crate::cluster::peer_identity::is_valid_peer_identity;
use crate::cluster::security::INTERNAL_AUTH_TOKEN_HEADER;

pub const JOIN_CLUSTER_ID_HEADER: &str = "x-maxio-join-cluster-id";
pub const JOIN_NODE_ID_HEADER: &str = "x-maxio-join-node-id";
pub const JOIN_TIMESTAMP_HEADER: &str = "x-maxio-join-unix-ms";
pub const JOIN_NONCE_HEADER: &str = "x-maxio-join-nonce";
pub const DEFAULT_JOIN_MAX_CLOCK_SKEW_MS: u64 = 60_000;
const JOIN_NONCE_MIN_LENGTH: usize = 8;
const JOIN_NONCE_MAX_LENGTH: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinAuthMode {
    CompatibilityNoToken,
    SharedToken,
}

impl JoinAuthMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CompatibilityNoToken => "compatibility_no_token",
            Self::SharedToken => "shared_token",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinAuthorizationError {
    InvalidConfiguration,
    MissingOrMalformedClusterId,
    ClusterIdMismatch,
    MissingOrMalformedNodeId,
    InvalidNodeIdentity,
    NodeMatchesLocalNode,
    MissingOrMalformedForwardedBy,
    ForwardedByNodeIdMismatch,
    MissingOrMalformedJoinTimestamp,
    JoinTimestampSkewExceeded,
    MissingOrMalformedJoinNonce,
    InvalidJoinNonce,
    JoinNonceReplayDetected,
    MissingOrMalformedAuthToken,
    AuthTokenMismatch,
}

impl JoinAuthorizationError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "invalid_configuration",
            Self::MissingOrMalformedClusterId => "missing_or_malformed_cluster_id",
            Self::ClusterIdMismatch => "cluster_id_mismatch",
            Self::MissingOrMalformedNodeId => "missing_or_malformed_node_id",
            Self::InvalidNodeIdentity => "invalid_node_identity",
            Self::NodeMatchesLocalNode => "node_matches_local_node",
            Self::MissingOrMalformedForwardedBy => "missing_or_malformed_forwarded_by",
            Self::ForwardedByNodeIdMismatch => "forwarded_by_node_id_mismatch",
            Self::MissingOrMalformedJoinTimestamp => "missing_or_malformed_join_timestamp",
            Self::JoinTimestampSkewExceeded => "join_timestamp_skew_exceeded",
            Self::MissingOrMalformedJoinNonce => "missing_or_malformed_join_nonce",
            Self::InvalidJoinNonce => "invalid_join_nonce",
            Self::JoinNonceReplayDetected => "join_nonce_replay_detected",
            Self::MissingOrMalformedAuthToken => "missing_or_malformed_auth_token",
            Self::AuthTokenMismatch => "auth_token_mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinAuthorizationResult {
    pub authorized: bool,
    pub mode: JoinAuthMode,
    pub peer_node_id: Option<String>,
    pub error: Option<JoinAuthorizationError>,
}

impl JoinAuthorizationResult {
    fn authorized(mode: JoinAuthMode, peer_node_id: String) -> Self {
        Self {
            authorized: true,
            mode,
            peer_node_id: Some(peer_node_id),
            error: None,
        }
    }

    fn rejected(mode: JoinAuthMode, error: JoinAuthorizationError) -> Self {
        Self {
            authorized: false,
            mode,
            peer_node_id: None,
            error: Some(error),
        }
    }

    pub fn reject_reason(&self) -> &'static str {
        self.error
            .as_ref()
            .map(JoinAuthorizationError::as_str)
            .unwrap_or("authorized")
    }
}

pub trait JoinNonceReplayGuard {
    fn register_nonce(
        &self,
        peer_node_id: &str,
        nonce: &str,
        issued_at_unix_ms: u64,
        now_unix_ms: u64,
    ) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DurableJoinNonceReplaySnapshot {
    entries: HashMap<String, u64>,
}

#[derive(Debug)]
pub struct InMemoryJoinNonceReplayGuard {
    ttl_ms: u64,
    max_entries: usize,
    entries: Mutex<HashMap<String, u64>>,
}

impl InMemoryJoinNonceReplayGuard {
    pub fn new(ttl_ms: u64, max_entries: usize) -> Self {
        Self {
            ttl_ms: ttl_ms.max(1),
            max_entries: max_entries.max(1),
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn nonce_key(peer_node_id: &str, nonce: &str) -> String {
        format!("{}:{}", peer_node_id.trim().to_ascii_lowercase(), nonce)
    }

    fn evict_oldest(entries: &mut HashMap<String, u64>) {
        let Some((oldest_key, _)) = entries
            .iter()
            .min_by_key(|(_, timestamp)| *timestamp)
            .map(|(key, timestamp)| (key.clone(), *timestamp))
        else {
            return;
        };
        entries.remove(oldest_key.as_str());
    }
}

impl JoinNonceReplayGuard for InMemoryJoinNonceReplayGuard {
    fn register_nonce(
        &self,
        peer_node_id: &str,
        nonce: &str,
        _issued_at_unix_ms: u64,
        now_unix_ms: u64,
    ) -> bool {
        let Some(mut entries) = self.entries.lock().ok() else {
            return false;
        };
        let ttl_ms = self.ttl_ms;
        entries.retain(|_, seen_at| now_unix_ms.saturating_sub(*seen_at) <= ttl_ms);

        let key = Self::nonce_key(peer_node_id, nonce);
        if let Some(previous_seen_at) = entries.get(key.as_str()) {
            if now_unix_ms.saturating_sub(*previous_seen_at) <= ttl_ms {
                return false;
            }
        }

        entries.insert(key, now_unix_ms);
        while entries.len() > self.max_entries {
            Self::evict_oldest(&mut entries);
        }
        true
    }
}

#[derive(Debug)]
pub struct DurableJoinNonceReplayGuard {
    ttl_ms: u64,
    max_entries: usize,
    state_path: PathBuf,
    entries: Mutex<Option<HashMap<String, u64>>>,
}

impl DurableJoinNonceReplayGuard {
    pub fn new(state_path: impl Into<PathBuf>, ttl_ms: u64, max_entries: usize) -> Self {
        let state_path = state_path.into();
        let entries = Self::load_entries(state_path.as_path()).ok();
        Self {
            ttl_ms: ttl_ms.max(1),
            max_entries: max_entries.max(1),
            state_path,
            entries: Mutex::new(entries),
        }
    }

    fn load_entries(path: &Path) -> io::Result<HashMap<String, u64>> {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(HashMap::new());
            }
            Err(err) => return Err(err),
        };

        let snapshot =
            serde_json::from_slice::<DurableJoinNonceReplaySnapshot>(bytes.as_slice())
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        Ok(snapshot.entries)
    }

    fn persist_entries(&self, entries: &HashMap<String, u64>) -> io::Result<()> {
        let Some(parent) = self.state_path.parent() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "join nonce replay state path must include parent directory",
            ));
        };
        fs::create_dir_all(parent)?;

        let snapshot = DurableJoinNonceReplaySnapshot {
            entries: entries.clone(),
        };
        let payload = serde_json::to_vec_pretty(&snapshot)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        let tmp_file_name = self
            .state_path
            .file_name()
            .and_then(|value| value.to_str())
            .map(|value| format!(".{value}.tmp"))
            .unwrap_or_else(|| ".pending-join-nonce-replay.tmp".to_string());
        let tmp_path = self.state_path.with_file_name(tmp_file_name);
        fs::write(tmp_path.as_path(), payload)?;
        fs::rename(tmp_path.as_path(), self.state_path.as_path())?;
        Ok(())
    }
}

impl JoinNonceReplayGuard for DurableJoinNonceReplayGuard {
    fn register_nonce(
        &self,
        peer_node_id: &str,
        nonce: &str,
        _issued_at_unix_ms: u64,
        now_unix_ms: u64,
    ) -> bool {
        let Some(mut entries_guard) = self.entries.lock().ok() else {
            return false;
        };
        let Some(entries) = entries_guard.as_mut() else {
            return false;
        };

        let ttl_ms = self.ttl_ms;
        entries.retain(|_, seen_at| now_unix_ms.saturating_sub(*seen_at) <= ttl_ms);

        let key = InMemoryJoinNonceReplayGuard::nonce_key(peer_node_id, nonce);
        if let Some(previous_seen_at) = entries.get(key.as_str()) {
            if now_unix_ms.saturating_sub(*previous_seen_at) <= ttl_ms {
                return false;
            }
        }

        entries.insert(key, now_unix_ms);
        while entries.len() > self.max_entries {
            InMemoryJoinNonceReplayGuard::evict_oldest(entries);
        }
        if self.persist_entries(entries).is_err() {
            *entries_guard = None;
            return false;
        }
        true
    }
}

fn parse_single_non_empty_header(headers: &HeaderMap, name: &str) -> Option<String> {
    parse_optional_single_non_empty_header(headers, name)
        .ok()
        .flatten()
}

fn parse_optional_single_non_empty_header(
    headers: &HeaderMap,
    name: &str,
) -> Result<Option<String>, ()> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?.trim();
    if value.is_empty() {
        return Err(());
    }
    Ok(Some(value.to_string()))
}

fn normalize_non_empty(value: &str) -> Option<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized.to_string())
    }
}

fn join_nonce_is_valid(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.len() >= JOIN_NONCE_MIN_LENGTH
        && trimmed.len() <= JOIN_NONCE_MAX_LENGTH
        && trimmed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

pub fn authorize_join_request(
    headers: &HeaderMap,
    expected_cluster_id: &str,
    cluster_auth_token: Option<&str>,
    local_node_id: &str,
    now_unix_ms: u64,
    max_clock_skew_ms: u64,
    replay_guard: Option<&dyn JoinNonceReplayGuard>,
) -> JoinAuthorizationResult {
    let mode = if cluster_auth_token.is_some() {
        JoinAuthMode::SharedToken
    } else {
        JoinAuthMode::CompatibilityNoToken
    };
    let max_clock_skew_ms = max_clock_skew_ms.max(1);

    let Some(expected_cluster_id) = normalize_non_empty(expected_cluster_id) else {
        return JoinAuthorizationResult::rejected(
            mode,
            JoinAuthorizationError::InvalidConfiguration,
        );
    };
    let Some(local_node_id) = normalize_non_empty(local_node_id) else {
        return JoinAuthorizationResult::rejected(
            mode,
            JoinAuthorizationError::InvalidConfiguration,
        );
    };
    if !is_valid_peer_identity(local_node_id.as_str()) {
        return JoinAuthorizationResult::rejected(
            mode,
            JoinAuthorizationError::InvalidConfiguration,
        );
    }

    let Some(cluster_id) = parse_single_non_empty_header(headers, JOIN_CLUSTER_ID_HEADER) else {
        return JoinAuthorizationResult::rejected(
            mode,
            JoinAuthorizationError::MissingOrMalformedClusterId,
        );
    };
    if cluster_id != expected_cluster_id {
        return JoinAuthorizationResult::rejected(mode, JoinAuthorizationError::ClusterIdMismatch);
    }

    let Some(peer_node_id) = parse_single_non_empty_header(headers, JOIN_NODE_ID_HEADER) else {
        return JoinAuthorizationResult::rejected(
            mode,
            JoinAuthorizationError::MissingOrMalformedNodeId,
        );
    };
    if !is_valid_peer_identity(peer_node_id.as_str()) {
        return JoinAuthorizationResult::rejected(
            mode,
            JoinAuthorizationError::InvalidNodeIdentity,
        );
    }
    if peer_node_id.eq_ignore_ascii_case(local_node_id.as_str()) {
        return JoinAuthorizationResult::rejected(
            mode,
            JoinAuthorizationError::NodeMatchesLocalNode,
        );
    }
    match parse_optional_single_non_empty_header(headers, FORWARDED_BY_HEADER) {
        Ok(Some(forwarded_by)) => {
            let Ok(chain) = parse_forwarded_by_chain(forwarded_by.as_str()) else {
                return JoinAuthorizationResult::rejected(
                    mode,
                    JoinAuthorizationError::MissingOrMalformedForwardedBy,
                );
            };
            let Some(direct_sender) = chain.last() else {
                return JoinAuthorizationResult::rejected(
                    mode,
                    JoinAuthorizationError::MissingOrMalformedForwardedBy,
                );
            };
            if !direct_sender.eq_ignore_ascii_case(peer_node_id.as_str()) {
                return JoinAuthorizationResult::rejected(
                    mode,
                    JoinAuthorizationError::ForwardedByNodeIdMismatch,
                );
            }
        }
        Ok(None) => {}
        Err(_) => {
            return JoinAuthorizationResult::rejected(
                mode,
                JoinAuthorizationError::MissingOrMalformedForwardedBy,
            );
        }
    }

    let Some(timestamp_str) = parse_single_non_empty_header(headers, JOIN_TIMESTAMP_HEADER) else {
        return JoinAuthorizationResult::rejected(
            mode,
            JoinAuthorizationError::MissingOrMalformedJoinTimestamp,
        );
    };
    let Ok(issued_at_unix_ms) = timestamp_str.parse::<u64>() else {
        return JoinAuthorizationResult::rejected(
            mode,
            JoinAuthorizationError::MissingOrMalformedJoinTimestamp,
        );
    };
    if issued_at_unix_ms.abs_diff(now_unix_ms) > max_clock_skew_ms {
        return JoinAuthorizationResult::rejected(
            mode,
            JoinAuthorizationError::JoinTimestampSkewExceeded,
        );
    }

    let Some(nonce) = parse_single_non_empty_header(headers, JOIN_NONCE_HEADER) else {
        return JoinAuthorizationResult::rejected(
            mode,
            JoinAuthorizationError::MissingOrMalformedJoinNonce,
        );
    };
    if !join_nonce_is_valid(nonce.as_str()) {
        return JoinAuthorizationResult::rejected(mode, JoinAuthorizationError::InvalidJoinNonce);
    }

    if let Some(configured_token) = cluster_auth_token {
        let Some(configured_token) = normalize_non_empty(configured_token) else {
            return JoinAuthorizationResult::rejected(
                mode,
                JoinAuthorizationError::InvalidConfiguration,
            );
        };
        let Some(request_token) =
            parse_single_non_empty_header(headers, INTERNAL_AUTH_TOKEN_HEADER)
        else {
            return JoinAuthorizationResult::rejected(
                mode,
                JoinAuthorizationError::MissingOrMalformedAuthToken,
            );
        };
        if !constant_time_str_eq(request_token.as_str(), configured_token.as_str()) {
            return JoinAuthorizationResult::rejected(
                mode,
                JoinAuthorizationError::AuthTokenMismatch,
            );
        }
    }

    if let Some(replay_guard) = replay_guard {
        if !replay_guard.register_nonce(
            peer_node_id.as_str(),
            nonce.as_str(),
            issued_at_unix_ms,
            now_unix_ms,
        ) {
            return JoinAuthorizationResult::rejected(
                mode,
                JoinAuthorizationError::JoinNonceReplayDetected,
            );
        }
    }

    JoinAuthorizationResult::authorized(mode, peer_node_id)
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};
    use std::fs;
    use tempfile::tempdir;

    use super::{
        DEFAULT_JOIN_MAX_CLOCK_SKEW_MS, DurableJoinNonceReplayGuard, InMemoryJoinNonceReplayGuard,
        JOIN_CLUSTER_ID_HEADER, JOIN_NODE_ID_HEADER, JOIN_NONCE_HEADER, JOIN_TIMESTAMP_HEADER,
        JoinAuthMode, JoinAuthorizationError, JoinNonceReplayGuard, authorize_join_request,
    };
    use crate::cluster::authenticator::FORWARDED_BY_HEADER;
    use crate::cluster::security::INTERNAL_AUTH_TOKEN_HEADER;

    fn valid_join_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(JOIN_CLUSTER_ID_HEADER, "cluster-main".parse().unwrap());
        headers.insert(JOIN_NODE_ID_HEADER, "node-b:9000".parse().unwrap());
        headers.insert(JOIN_TIMESTAMP_HEADER, "100000".parse().unwrap());
        headers.insert(JOIN_NONCE_HEADER, "nonce-123".parse().unwrap());
        headers
    }

    #[test]
    fn authorize_join_request_accepts_shared_token_request() {
        let mut headers = valid_join_headers();
        headers.insert(INTERNAL_AUTH_TOKEN_HEADER, "secret".parse().unwrap());
        let replay_guard = InMemoryJoinNonceReplayGuard::new(60_000, 64);

        let result = authorize_join_request(
            &headers,
            "cluster-main",
            Some("secret"),
            "node-a:9000",
            100000,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            Some(&replay_guard),
        );

        assert!(result.authorized);
        assert_eq!(result.mode, JoinAuthMode::SharedToken);
        assert_eq!(result.peer_node_id.as_deref(), Some("node-b:9000"));
        assert_eq!(result.reject_reason(), "authorized");
    }

    #[test]
    fn authorize_join_request_accepts_compatibility_mode_without_token() {
        let headers = valid_join_headers();
        let replay_guard = InMemoryJoinNonceReplayGuard::new(60_000, 64);

        let result = authorize_join_request(
            &headers,
            "cluster-main",
            None,
            "node-a:9000",
            100000,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            Some(&replay_guard),
        );

        assert!(result.authorized);
        assert_eq!(result.mode, JoinAuthMode::CompatibilityNoToken);
    }

    #[test]
    fn authorize_join_request_rejects_cluster_id_mismatch() {
        let headers = valid_join_headers();

        let result = authorize_join_request(
            &headers,
            "cluster-alt",
            None,
            "node-a:9000",
            100000,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            None,
        );

        assert!(!result.authorized);
        assert_eq!(
            result.error,
            Some(JoinAuthorizationError::ClusterIdMismatch)
        );
    }

    #[test]
    fn authorize_join_request_rejects_missing_token_when_configured() {
        let headers = valid_join_headers();

        let result = authorize_join_request(
            &headers,
            "cluster-main",
            Some("secret"),
            "node-a:9000",
            100000,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            None,
        );

        assert!(!result.authorized);
        assert_eq!(
            result.error,
            Some(JoinAuthorizationError::MissingOrMalformedAuthToken)
        );
    }

    #[test]
    fn authorize_join_request_rejects_token_mismatch() {
        let mut headers = valid_join_headers();
        headers.insert(INTERNAL_AUTH_TOKEN_HEADER, "wrong".parse().unwrap());

        let result = authorize_join_request(
            &headers,
            "cluster-main",
            Some("secret"),
            "node-a:9000",
            100000,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            None,
        );

        assert!(!result.authorized);
        assert_eq!(
            result.error,
            Some(JoinAuthorizationError::AuthTokenMismatch)
        );
    }

    #[test]
    fn authorize_join_request_rejects_duplicate_token_headers() {
        let mut headers = valid_join_headers();
        headers.append(INTERNAL_AUTH_TOKEN_HEADER, "secret".parse().unwrap());
        headers.append(INTERNAL_AUTH_TOKEN_HEADER, "secret".parse().unwrap());

        let result = authorize_join_request(
            &headers,
            "cluster-main",
            Some("secret"),
            "node-a:9000",
            100000,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            None,
        );

        assert!(!result.authorized);
        assert_eq!(
            result.error,
            Some(JoinAuthorizationError::MissingOrMalformedAuthToken)
        );
    }

    #[test]
    fn authorize_join_request_rejects_duplicate_token_headers_with_empty_value() {
        let mut headers = valid_join_headers();
        headers.insert(
            INTERNAL_AUTH_TOKEN_HEADER,
            HeaderValue::from_static("secret"),
        );
        headers.append(INTERNAL_AUTH_TOKEN_HEADER, HeaderValue::from_static(""));

        let result = authorize_join_request(
            &headers,
            "cluster-main",
            Some("secret"),
            "node-a:9000",
            100000,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            None,
        );

        assert!(!result.authorized);
        assert_eq!(
            result.error,
            Some(JoinAuthorizationError::MissingOrMalformedAuthToken)
        );
    }

    #[test]
    fn authorize_join_request_rejects_duplicate_cluster_id_headers() {
        let mut headers = valid_join_headers();
        headers.append(JOIN_CLUSTER_ID_HEADER, "cluster-main".parse().unwrap());
        headers.append(JOIN_CLUSTER_ID_HEADER, "cluster-main".parse().unwrap());

        let result = authorize_join_request(
            &headers,
            "cluster-main",
            None,
            "node-a:9000",
            100000,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            None,
        );

        assert!(!result.authorized);
        assert_eq!(
            result.error,
            Some(JoinAuthorizationError::MissingOrMalformedClusterId)
        );
    }

    #[test]
    fn authorize_join_request_rejects_duplicate_nonce_headers() {
        let mut headers = valid_join_headers();
        headers.append(JOIN_NONCE_HEADER, "nonce-123".parse().unwrap());
        headers.append(JOIN_NONCE_HEADER, "nonce-123".parse().unwrap());

        let result = authorize_join_request(
            &headers,
            "cluster-main",
            None,
            "node-a:9000",
            100000,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            None,
        );

        assert!(!result.authorized);
        assert_eq!(
            result.error,
            Some(JoinAuthorizationError::MissingOrMalformedJoinNonce)
        );
    }

    #[test]
    fn authorize_join_request_rejects_short_nonce() {
        let mut headers = valid_join_headers();
        headers.insert(JOIN_NONCE_HEADER, "n-123".parse().unwrap());

        let result = authorize_join_request(
            &headers,
            "cluster-main",
            None,
            "node-a:9000",
            100000,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            None,
        );

        assert!(!result.authorized);
        assert_eq!(result.error, Some(JoinAuthorizationError::InvalidJoinNonce));
    }

    #[test]
    fn authorize_join_request_rejects_duplicate_node_id_headers() {
        let mut headers = valid_join_headers();
        headers.append(JOIN_NODE_ID_HEADER, "node-b:9000".parse().unwrap());
        headers.append(JOIN_NODE_ID_HEADER, "node-b:9000".parse().unwrap());

        let result = authorize_join_request(
            &headers,
            "cluster-main",
            None,
            "node-a:9000",
            100000,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            None,
        );

        assert!(!result.authorized);
        assert_eq!(
            result.error,
            Some(JoinAuthorizationError::MissingOrMalformedNodeId)
        );
    }

    #[test]
    fn authorize_join_request_rejects_duplicate_timestamp_headers() {
        let mut headers = valid_join_headers();
        headers.append(JOIN_TIMESTAMP_HEADER, "100000".parse().unwrap());
        headers.append(JOIN_TIMESTAMP_HEADER, "100000".parse().unwrap());

        let result = authorize_join_request(
            &headers,
            "cluster-main",
            None,
            "node-a:9000",
            100000,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            None,
        );

        assert!(!result.authorized);
        assert_eq!(
            result.error,
            Some(JoinAuthorizationError::MissingOrMalformedJoinTimestamp)
        );
    }

    #[test]
    fn authorize_join_request_rejects_invalid_peer_identity() {
        let mut headers = valid_join_headers();
        headers.insert(JOIN_NODE_ID_HEADER, "node/b:9000".parse().unwrap());

        let result = authorize_join_request(
            &headers,
            "cluster-main",
            None,
            "node-a:9000",
            100000,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            None,
        );

        assert!(!result.authorized);
        assert_eq!(
            result.error,
            Some(JoinAuthorizationError::InvalidNodeIdentity)
        );
    }

    #[test]
    fn authorize_join_request_rejects_non_utf8_nonce_header() {
        let mut headers = valid_join_headers();
        let non_utf8 = HeaderValue::from_bytes(&[0x80, b'n', b'o', b'n', b'c', b'e'])
            .expect("obs-text header value should parse");
        headers.insert(JOIN_NONCE_HEADER, non_utf8);

        let result = authorize_join_request(
            &headers,
            "cluster-main",
            None,
            "node-a:9000",
            100000,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            None,
        );

        assert!(!result.authorized);
        assert_eq!(
            result.error,
            Some(JoinAuthorizationError::MissingOrMalformedJoinNonce)
        );
    }

    #[test]
    fn authorize_join_request_rejects_local_node_replay() {
        let headers = valid_join_headers();

        let result = authorize_join_request(
            &headers,
            "cluster-main",
            None,
            "node-b:9000",
            100000,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            None,
        );

        assert!(!result.authorized);
        assert_eq!(
            result.error,
            Some(JoinAuthorizationError::NodeMatchesLocalNode)
        );
    }

    #[test]
    fn authorize_join_request_rejects_local_node_replay_with_case_variant() {
        let headers = valid_join_headers();

        let result = authorize_join_request(
            &headers,
            "cluster-main",
            None,
            "NODE-B:9000",
            100000,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            None,
        );

        assert!(!result.authorized);
        assert_eq!(
            result.error,
            Some(JoinAuthorizationError::NodeMatchesLocalNode)
        );
    }

    #[test]
    fn authorize_join_request_accepts_case_variant_forwarded_sender_matching_node_id() {
        let mut headers = valid_join_headers();
        headers.insert(FORWARDED_BY_HEADER, "NODE-B:9000".parse().unwrap());

        let result = authorize_join_request(
            &headers,
            "cluster-main",
            None,
            "node-a:9000",
            100000,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            None,
        );

        assert!(result.authorized);
    }

    #[test]
    fn authorize_join_request_rejects_forwarded_sender_node_id_mismatch() {
        let mut headers = valid_join_headers();
        headers.insert(FORWARDED_BY_HEADER, "node-c:9000".parse().unwrap());

        let result = authorize_join_request(
            &headers,
            "cluster-main",
            None,
            "node-a:9000",
            100000,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            None,
        );

        assert!(!result.authorized);
        assert_eq!(
            result.error,
            Some(JoinAuthorizationError::ForwardedByNodeIdMismatch)
        );
    }

    #[test]
    fn authorize_join_request_accepts_forwarded_multi_hop_when_direct_sender_matches_node_id() {
        let mut headers = valid_join_headers();
        headers.insert(
            FORWARDED_BY_HEADER,
            "node-c:9000,node-b:9000".parse().unwrap(),
        );

        let result = authorize_join_request(
            &headers,
            "cluster-main",
            None,
            "node-a:9000",
            100000,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            None,
        );

        assert!(result.authorized);
    }

    #[test]
    fn authorize_join_request_rejects_forwarded_multi_hop_when_only_origin_matches_node_id() {
        let mut headers = valid_join_headers();
        headers.insert(
            FORWARDED_BY_HEADER,
            "node-b:9000,node-c:9000".parse().unwrap(),
        );

        let result = authorize_join_request(
            &headers,
            "cluster-main",
            None,
            "node-a:9000",
            100000,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            None,
        );

        assert!(!result.authorized);
        assert_eq!(
            result.error,
            Some(JoinAuthorizationError::ForwardedByNodeIdMismatch)
        );
    }

    #[test]
    fn authorize_join_request_rejects_malformed_forwarded_by_header() {
        let mut headers = valid_join_headers();
        headers.insert(FORWARDED_BY_HEADER, "../node-b".parse().unwrap());

        let result = authorize_join_request(
            &headers,
            "cluster-main",
            None,
            "node-a:9000",
            100000,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            None,
        );

        assert!(!result.authorized);
        assert_eq!(
            result.error,
            Some(JoinAuthorizationError::MissingOrMalformedForwardedBy)
        );
    }

    #[test]
    fn authorize_join_request_rejects_timestamp_skew_exceeded() {
        let headers = valid_join_headers();

        let result = authorize_join_request(
            &headers,
            "cluster-main",
            None,
            "node-a:9000",
            200000,
            1000,
            None,
        );

        assert!(!result.authorized);
        assert_eq!(
            result.error,
            Some(JoinAuthorizationError::JoinTimestampSkewExceeded)
        );
    }

    #[test]
    fn authorize_join_request_rejects_nonce_replay() {
        let mut headers = valid_join_headers();
        headers.insert(INTERNAL_AUTH_TOKEN_HEADER, "secret".parse().unwrap());
        let replay_guard = InMemoryJoinNonceReplayGuard::new(60_000, 64);

        let first = authorize_join_request(
            &headers,
            "cluster-main",
            Some("secret"),
            "node-a:9000",
            100000,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            Some(&replay_guard),
        );
        assert!(first.authorized);

        let second = authorize_join_request(
            &headers,
            "cluster-main",
            Some("secret"),
            "node-a:9000",
            100001,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            Some(&replay_guard),
        );
        assert!(!second.authorized);
        assert_eq!(
            second.error,
            Some(JoinAuthorizationError::JoinNonceReplayDetected)
        );
    }

    #[test]
    fn in_memory_join_nonce_replay_guard_allows_reuse_after_ttl_window() {
        let mut headers = valid_join_headers();
        headers.insert(INTERNAL_AUTH_TOKEN_HEADER, "secret".parse().unwrap());
        let replay_guard = InMemoryJoinNonceReplayGuard::new(10, 64);

        let first = authorize_join_request(
            &headers,
            "cluster-main",
            Some("secret"),
            "node-a:9000",
            100000,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            Some(&replay_guard),
        );
        assert!(first.authorized);

        let second = authorize_join_request(
            &headers,
            "cluster-main",
            Some("secret"),
            "node-a:9000",
            100020,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            Some(&replay_guard),
        );
        assert!(second.authorized);
    }

    #[test]
    fn in_memory_join_nonce_replay_guard_ttl_is_bound_to_arrival_time() {
        let mut headers = valid_join_headers();
        headers.insert(JOIN_TIMESTAMP_HEADER, "100009".parse().unwrap());
        headers.insert(INTERNAL_AUTH_TOKEN_HEADER, "secret".parse().unwrap());
        let replay_guard = InMemoryJoinNonceReplayGuard::new(10, 64);

        let first = authorize_join_request(
            &headers,
            "cluster-main",
            Some("secret"),
            "node-a:9000",
            100000,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            Some(&replay_guard),
        );
        assert!(first.authorized);

        let second = authorize_join_request(
            &headers,
            "cluster-main",
            Some("secret"),
            "node-a:9000",
            100011,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            Some(&replay_guard),
        );
        assert!(second.authorized);
    }

    #[test]
    fn in_memory_join_nonce_replay_guard_rejects_case_variant_peer_identity_replay() {
        let mut headers = valid_join_headers();
        headers.insert(INTERNAL_AUTH_TOKEN_HEADER, "secret".parse().unwrap());
        let replay_guard = InMemoryJoinNonceReplayGuard::new(60_000, 64);

        let first = authorize_join_request(
            &headers,
            "cluster-main",
            Some("secret"),
            "node-a:9000",
            100000,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            Some(&replay_guard),
        );
        assert!(first.authorized);

        let mut second_headers = valid_join_headers();
        second_headers.insert(JOIN_NODE_ID_HEADER, "NODE-B:9000".parse().unwrap());
        second_headers.insert(INTERNAL_AUTH_TOKEN_HEADER, "secret".parse().unwrap());
        let second = authorize_join_request(
            &second_headers,
            "cluster-main",
            Some("secret"),
            "node-a:9000",
            100001,
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            Some(&replay_guard),
        );
        assert!(!second.authorized);
        assert_eq!(
            second.error,
            Some(JoinAuthorizationError::JoinNonceReplayDetected)
        );
    }

    #[test]
    fn durable_join_nonce_replay_guard_persists_replay_protection_across_restarts() {
        let dir = tempdir().expect("tempdir should be available");
        let state_path = dir.path().join("join-nonce-replay.json");

        {
            let guard = DurableJoinNonceReplayGuard::new(state_path.clone(), 60_000, 64);
            assert!(guard.register_nonce("node-b:9000", "nonce-123", 100000, 100000));
        }

        let guard = DurableJoinNonceReplayGuard::new(state_path, 60_000, 64);
        assert!(!guard.register_nonce("node-b:9000", "nonce-123", 100001, 100001));
    }

    #[test]
    fn durable_join_nonce_replay_guard_allows_reuse_after_ttl_across_restarts() {
        let dir = tempdir().expect("tempdir should be available");
        let state_path = dir.path().join("join-nonce-replay.json");

        {
            let guard = DurableJoinNonceReplayGuard::new(state_path.clone(), 10, 64);
            assert!(guard.register_nonce("node-b:9000", "nonce-123", 100000, 100000));
        }

        let guard = DurableJoinNonceReplayGuard::new(state_path, 10, 64);
        assert!(guard.register_nonce("node-b:9000", "nonce-123", 100020, 100020));
    }

    #[test]
    fn durable_join_nonce_replay_guard_rejects_when_state_payload_is_corrupt() {
        let dir = tempdir().expect("tempdir should be available");
        let state_path = dir.path().join("join-nonce-replay.json");
        fs::write(state_path.as_path(), b"{\"entries\":")
            .expect("corrupt replay payload should write");

        let guard = DurableJoinNonceReplayGuard::new(state_path, 60_000, 64);
        assert!(!guard.register_nonce("node-b:9000", "nonce-123", 100000, 100000));
    }
}
