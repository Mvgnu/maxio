use axum::http::HeaderMap;
use std::collections::BTreeSet;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::cluster::internal_transport::parse_forwarded_by_chain;
use crate::cluster::peer_identity::is_valid_peer_identity;
use crate::cluster::security::INTERNAL_AUTH_TOKEN_HEADER;
use crate::cluster::wire_auth::{InternalForwardTrustError, evaluate_internal_forward_trust};

pub const FORWARDED_BY_HEADER: &str = "x-maxio-forwarded-by";
pub const INTERNAL_MEMBERSHIP_PROPAGATED_HEADER: &str = "x-maxio-internal-membership-propagated";
pub const INTERNAL_FORWARDING_PROTOCOL_HEADERS: &[&str] = &[
    FORWARDED_BY_HEADER,
    INTERNAL_MEMBERSHIP_PROPAGATED_HEADER,
    "x-maxio-forwarded-write-epoch",
    "x-maxio-forwarded-write-view-id",
    "x-maxio-forwarded-write-hop-count",
    "x-maxio-forwarded-write-max-hops",
    "x-maxio-forwarded-write-idempotency-key",
    "x-maxio-internal-forwarded-write-epoch",
    "x-maxio-internal-forwarded-write-view-id",
    "x-maxio-internal-forwarded-write-hop-count",
    "x-maxio-internal-forwarded-write-max-hops",
    "x-maxio-internal-forwarded-write-idempotency-key",
    "x-maxio-internal-forwarded-write-operation",
    "x-maxio-internal-forwarded-write-version-id",
    INTERNAL_AUTH_TOKEN_HEADER,
];

const LEGACY_INTERNAL_FORWARDING_PROTOCOL_HEADERS: &[&str] = &[
    "x-maxio-forwarded-write-epoch",
    "x-maxio-forwarded-write-view-id",
    "x-maxio-forwarded-write-hop-count",
    "x-maxio-forwarded-write-max-hops",
    "x-maxio-forwarded-write-idempotency-key",
];

const INTERNAL_FORWARDING_TRUST_HEADERS: &[&str] = &[
    FORWARDED_BY_HEADER,
    INTERNAL_MEMBERSHIP_PROPAGATED_HEADER,
    "x-maxio-internal-forwarded-write-epoch",
    "x-maxio-internal-forwarded-write-view-id",
    "x-maxio-internal-forwarded-write-hop-count",
    "x-maxio-internal-forwarded-write-max-hops",
    "x-maxio-internal-forwarded-write-idempotency-key",
    "x-maxio-internal-forwarded-write-operation",
    "x-maxio-internal-forwarded-write-version-id",
    INTERNAL_AUTH_TOKEN_HEADER,
];

pub fn contains_internal_forwarding_protocol_headers(headers: &HeaderMap) -> bool {
    INTERNAL_FORWARDING_TRUST_HEADERS
        .iter()
        .any(|header_name| headers.contains_key(*header_name))
}

pub fn contains_legacy_internal_forwarding_headers(headers: &HeaderMap) -> bool {
    LEGACY_INTERNAL_FORWARDING_PROTOCOL_HEADERS
        .iter()
        .any(|header_name| headers.contains_key(*header_name))
}

#[derive(Debug)]
struct PeerAuthRejectCounters {
    total: AtomicU64,
    missing_or_malformed_forwarded_by: AtomicU64,
    malformed_forwarded_by_chain: AtomicU64,
    forwarded_by_hop_limit_exceeded: AtomicU64,
    forwarded_by_duplicate_peer_hop: AtomicU64,
    auth_token_mismatch: AtomicU64,
    missing_or_malformed_auth_token: AtomicU64,
    duplicate_auth_token_headers: AtomicU64,
    missing_sender_identity: AtomicU64,
    sender_matches_local_node: AtomicU64,
    sender_not_in_allowlist: AtomicU64,
    invalid_authenticator_configuration: AtomicU64,
    unknown: AtomicU64,
}

impl Default for PeerAuthRejectCounters {
    fn default() -> Self {
        Self {
            total: AtomicU64::new(0),
            missing_or_malformed_forwarded_by: AtomicU64::new(0),
            malformed_forwarded_by_chain: AtomicU64::new(0),
            forwarded_by_hop_limit_exceeded: AtomicU64::new(0),
            forwarded_by_duplicate_peer_hop: AtomicU64::new(0),
            auth_token_mismatch: AtomicU64::new(0),
            missing_or_malformed_auth_token: AtomicU64::new(0),
            duplicate_auth_token_headers: AtomicU64::new(0),
            missing_sender_identity: AtomicU64::new(0),
            sender_matches_local_node: AtomicU64::new(0),
            sender_not_in_allowlist: AtomicU64::new(0),
            invalid_authenticator_configuration: AtomicU64::new(0),
            unknown: AtomicU64::new(0),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerAuthRejectCountersSnapshot {
    pub total: u64,
    pub missing_or_malformed_forwarded_by: u64,
    pub malformed_forwarded_by_chain: u64,
    pub forwarded_by_hop_limit_exceeded: u64,
    pub forwarded_by_duplicate_peer_hop: u64,
    pub auth_token_mismatch: u64,
    pub missing_or_malformed_auth_token: u64,
    pub duplicate_auth_token_headers: u64,
    pub missing_sender_identity: u64,
    pub sender_matches_local_node: u64,
    pub sender_not_in_allowlist: u64,
    pub invalid_authenticator_configuration: u64,
    pub unknown: u64,
}

static PEER_AUTH_REJECT_COUNTERS: OnceLock<PeerAuthRejectCounters> = OnceLock::new();

fn peer_auth_reject_counters() -> &'static PeerAuthRejectCounters {
    PEER_AUTH_REJECT_COUNTERS.get_or_init(PeerAuthRejectCounters::default)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerAuthMode {
    Compatibility,
    SharedTokenAllowlist,
}

impl PeerAuthMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Compatibility => "compatibility",
            Self::SharedTokenAllowlist => "shared_token_allowlist",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerAuthenticationError {
    ForwardTrustRejected(InternalForwardTrustError),
    MissingSenderIdentity,
    SenderMatchesLocalNode,
    SenderNotInAllowlist,
    InvalidAuthenticatorConfiguration,
}

impl PeerAuthenticationError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ForwardTrustRejected(error) => error.as_str(),
            Self::MissingSenderIdentity => "missing_sender_identity",
            Self::SenderMatchesLocalNode => "sender_matches_local_node",
            Self::SenderNotInAllowlist => "sender_not_in_allowlist",
            Self::InvalidAuthenticatorConfiguration => "invalid_authenticator_configuration",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAuthenticationResult {
    pub trusted: bool,
    pub mode: PeerAuthMode,
    pub sender: Option<String>,
    pub error: Option<PeerAuthenticationError>,
}

impl PeerAuthenticationResult {
    fn trusted(mode: PeerAuthMode, sender: String) -> Self {
        Self {
            trusted: true,
            mode,
            sender: Some(sender),
            error: None,
        }
    }

    fn rejected(mode: PeerAuthMode, error: PeerAuthenticationError) -> Self {
        Self {
            trusted: false,
            mode,
            sender: None,
            error: Some(error),
        }
    }

    fn not_applicable(mode: PeerAuthMode) -> Self {
        Self {
            trusted: true,
            mode,
            sender: None,
            error: None,
        }
    }

    pub fn reject_reason(&self) -> &'static str {
        self.error
            .as_ref()
            .map(PeerAuthenticationError::as_str)
            .unwrap_or("trusted")
    }
}

pub trait PeerAuthenticator {
    fn mode(&self) -> PeerAuthMode;

    fn authenticate_forwarded_request(
        &self,
        headers: &HeaderMap,
        forwarded_by_header: &str,
    ) -> PeerAuthenticationResult;
}

pub fn authenticate_forwarded_request(
    headers: &HeaderMap,
    forwarded_by_header: &str,
    cluster_auth_token: Option<&str>,
    local_node_id: &str,
    cluster_peers: &[String],
) -> PeerAuthenticationResult {
    if let Some(token) = cluster_auth_token {
        let mode = PeerAuthMode::SharedTokenAllowlist;
        let Some(authenticator) =
            SharedTokenPeerAuthenticator::new(token, local_node_id, cluster_peers)
        else {
            return PeerAuthenticationResult::rejected(
                mode,
                PeerAuthenticationError::InvalidAuthenticatorConfiguration,
            );
        };
        return authenticator.authenticate_forwarded_request(headers, forwarded_by_header);
    }

    CompatibilityPeerAuthenticator.authenticate_forwarded_request(headers, forwarded_by_header)
}

pub fn strip_untrusted_internal_forwarding_headers(
    headers: &mut HeaderMap,
    cluster_auth_token: Option<&str>,
    local_node_id: &str,
    cluster_peers: &[String],
) -> PeerAuthenticationResult {
    let has_trust_scoped_internal_headers = contains_internal_forwarding_protocol_headers(headers);
    let has_legacy_internal_headers = contains_legacy_internal_forwarding_headers(headers);
    let enforce_legacy_header_trust_boundary =
        cluster_auth_token.is_some() && has_legacy_internal_headers;

    if !has_trust_scoped_internal_headers && !enforce_legacy_header_trust_boundary {
        let mode = if cluster_auth_token.is_some() {
            PeerAuthMode::SharedTokenAllowlist
        } else {
            PeerAuthMode::Compatibility
        };
        return PeerAuthenticationResult::not_applicable(mode);
    }

    let auth_result = authenticate_forwarded_request(
        headers,
        FORWARDED_BY_HEADER,
        cluster_auth_token,
        local_node_id,
        cluster_peers,
    );
    if auth_result.trusted {
        return auth_result;
    }

    for header_name in INTERNAL_FORWARDING_PROTOCOL_HEADERS {
        headers.remove(*header_name);
    }

    auth_result
}

pub fn record_peer_auth_rejection(result: &PeerAuthenticationResult) {
    if result.trusted {
        return;
    }
    let counters = peer_auth_reject_counters();
    counters.total.fetch_add(1, Ordering::Relaxed);

    match result.reject_reason() {
        "missing_or_malformed_forwarded_by" => {
            counters
                .missing_or_malformed_forwarded_by
                .fetch_add(1, Ordering::Relaxed);
        }
        "malformed_forwarded_by_chain" => {
            counters
                .malformed_forwarded_by_chain
                .fetch_add(1, Ordering::Relaxed);
        }
        "forwarded_by_hop_limit_exceeded" => {
            counters
                .forwarded_by_hop_limit_exceeded
                .fetch_add(1, Ordering::Relaxed);
        }
        "forwarded_by_duplicate_peer_hop" => {
            counters
                .forwarded_by_duplicate_peer_hop
                .fetch_add(1, Ordering::Relaxed);
        }
        "auth_token_mismatch" => {
            counters.auth_token_mismatch.fetch_add(1, Ordering::Relaxed);
        }
        "missing_or_malformed_auth_token" => {
            counters
                .missing_or_malformed_auth_token
                .fetch_add(1, Ordering::Relaxed);
        }
        "duplicate_auth_token_headers" => {
            counters
                .duplicate_auth_token_headers
                .fetch_add(1, Ordering::Relaxed);
        }
        "missing_sender_identity" => {
            counters
                .missing_sender_identity
                .fetch_add(1, Ordering::Relaxed);
        }
        "sender_matches_local_node" => {
            counters
                .sender_matches_local_node
                .fetch_add(1, Ordering::Relaxed);
        }
        "sender_not_in_allowlist" => {
            counters
                .sender_not_in_allowlist
                .fetch_add(1, Ordering::Relaxed);
        }
        "invalid_authenticator_configuration" => {
            counters
                .invalid_authenticator_configuration
                .fetch_add(1, Ordering::Relaxed);
        }
        _ => {
            counters.unknown.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub fn peer_auth_reject_counters_snapshot() -> PeerAuthRejectCountersSnapshot {
    let counters = peer_auth_reject_counters();
    PeerAuthRejectCountersSnapshot {
        total: counters.total.load(Ordering::Relaxed),
        missing_or_malformed_forwarded_by: counters
            .missing_or_malformed_forwarded_by
            .load(Ordering::Relaxed),
        malformed_forwarded_by_chain: counters
            .malformed_forwarded_by_chain
            .load(Ordering::Relaxed),
        forwarded_by_hop_limit_exceeded: counters
            .forwarded_by_hop_limit_exceeded
            .load(Ordering::Relaxed),
        forwarded_by_duplicate_peer_hop: counters
            .forwarded_by_duplicate_peer_hop
            .load(Ordering::Relaxed),
        auth_token_mismatch: counters.auth_token_mismatch.load(Ordering::Relaxed),
        missing_or_malformed_auth_token: counters
            .missing_or_malformed_auth_token
            .load(Ordering::Relaxed),
        duplicate_auth_token_headers: counters
            .duplicate_auth_token_headers
            .load(Ordering::Relaxed),
        missing_sender_identity: counters.missing_sender_identity.load(Ordering::Relaxed),
        sender_matches_local_node: counters.sender_matches_local_node.load(Ordering::Relaxed),
        sender_not_in_allowlist: counters.sender_not_in_allowlist.load(Ordering::Relaxed),
        invalid_authenticator_configuration: counters
            .invalid_authenticator_configuration
            .load(Ordering::Relaxed),
        unknown: counters.unknown.load(Ordering::Relaxed),
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CompatibilityPeerAuthenticator;

impl PeerAuthenticator for CompatibilityPeerAuthenticator {
    fn mode(&self) -> PeerAuthMode {
        PeerAuthMode::Compatibility
    }

    fn authenticate_forwarded_request(
        &self,
        headers: &HeaderMap,
        forwarded_by_header: &str,
    ) -> PeerAuthenticationResult {
        let mode = self.mode();
        let trust_decision = evaluate_internal_forward_trust(
            headers,
            forwarded_by_header,
            INTERNAL_AUTH_TOKEN_HEADER,
            None,
        );
        if !trust_decision.trusted {
            return PeerAuthenticationResult::rejected(
                mode,
                PeerAuthenticationError::ForwardTrustRejected(
                    trust_decision
                        .error
                        .unwrap_or(InternalForwardTrustError::MissingOrMalformedForwardedBy),
                ),
            );
        }

        let Some(sender) = direct_sender_identity(headers, forwarded_by_header) else {
            return PeerAuthenticationResult::rejected(
                mode,
                PeerAuthenticationError::MissingSenderIdentity,
            );
        };
        PeerAuthenticationResult::trusted(mode, sender)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedTokenPeerAuthenticator {
    token: String,
    local_node_id: String,
    trusted_peers: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharedTokenBindingStatus {
    Bound { trusted_peer_count: usize },
    UnboundNoTrustedPeers,
    InvalidToken,
    InvalidLocalNodeId,
}

impl SharedTokenBindingStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Bound { .. } => "bound",
            Self::UnboundNoTrustedPeers => "unbound_no_trusted_peers",
            Self::InvalidToken => "invalid_token",
            Self::InvalidLocalNodeId => "invalid_local_node_id",
        }
    }

    pub fn is_bound(&self) -> bool {
        matches!(self, Self::Bound { .. })
    }

    pub fn trusted_peer_count(&self) -> usize {
        match self {
            Self::Bound { trusted_peer_count } => *trusted_peer_count,
            _ => 0,
        }
    }
}

impl SharedTokenPeerAuthenticator {
    pub fn new(token: &str, local_node_id: &str, trusted_peers: &[String]) -> Option<Self> {
        let token = normalize_token(token)?;
        let local_node_id = normalize_peer_identity(local_node_id)?;
        if !is_valid_peer_identity(local_node_id.as_str()) {
            return None;
        }

        Some(Self {
            token,
            local_node_id: local_node_id.clone(),
            trusted_peers: normalize_peer_identity_set(trusted_peers)
                .into_iter()
                .filter(|peer| peer != &local_node_id)
                .filter(|peer| is_valid_peer_identity(peer.as_str()))
                .collect(),
        })
    }

    pub fn trusted_peer_count(&self) -> usize {
        self.trusted_peers.len()
    }

    pub fn binding_status(
        token: &str,
        local_node_id: &str,
        trusted_peers: &[String],
    ) -> SharedTokenBindingStatus {
        if normalize_token(token).is_none() {
            return SharedTokenBindingStatus::InvalidToken;
        }
        let Some(local_node_id) = normalize_peer_identity(local_node_id) else {
            return SharedTokenBindingStatus::InvalidLocalNodeId;
        };
        if !is_valid_peer_identity(local_node_id.as_str()) {
            return SharedTokenBindingStatus::InvalidLocalNodeId;
        }

        let trusted_peer_count = normalize_peer_identity_set(trusted_peers)
            .into_iter()
            .filter(|peer| peer != &local_node_id)
            .filter(|peer| is_valid_peer_identity(peer.as_str()))
            .count();

        if trusted_peer_count == 0 {
            SharedTokenBindingStatus::UnboundNoTrustedPeers
        } else {
            SharedTokenBindingStatus::Bound { trusted_peer_count }
        }
    }
}

impl PeerAuthenticator for SharedTokenPeerAuthenticator {
    fn mode(&self) -> PeerAuthMode {
        PeerAuthMode::SharedTokenAllowlist
    }

    fn authenticate_forwarded_request(
        &self,
        headers: &HeaderMap,
        forwarded_by_header: &str,
    ) -> PeerAuthenticationResult {
        let mode = self.mode();
        let trust_decision = evaluate_internal_forward_trust(
            headers,
            forwarded_by_header,
            INTERNAL_AUTH_TOKEN_HEADER,
            Some(self.token.as_str()),
        );
        if !trust_decision.trusted {
            return PeerAuthenticationResult::rejected(
                mode,
                PeerAuthenticationError::ForwardTrustRejected(
                    trust_decision
                        .error
                        .unwrap_or(InternalForwardTrustError::MissingOrMalformedForwardedBy),
                ),
            );
        }

        let Some(forward_chain) = forwarded_chain_identities(headers, forwarded_by_header) else {
            return PeerAuthenticationResult::rejected(
                mode,
                PeerAuthenticationError::MissingSenderIdentity,
            );
        };

        if forward_chain.iter().any(|hop| hop == &self.local_node_id) {
            return PeerAuthenticationResult::rejected(
                mode,
                PeerAuthenticationError::SenderMatchesLocalNode,
            );
        }

        if forward_chain
            .iter()
            .any(|hop| !self.trusted_peers.contains(hop.as_str()))
        {
            return PeerAuthenticationResult::rejected(
                mode,
                PeerAuthenticationError::SenderNotInAllowlist,
            );
        }

        let Some(sender) = forward_chain.last().cloned() else {
            return PeerAuthenticationResult::rejected(
                mode,
                PeerAuthenticationError::MissingSenderIdentity,
            );
        };

        PeerAuthenticationResult::trusted(mode, sender)
    }
}

fn parse_single_non_empty_header(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let value = value.to_str().ok()?.trim();
    if value.is_empty() {
        return None;
    }
    Some(value.to_string())
}

fn direct_sender_identity(headers: &HeaderMap, forwarded_by_header: &str) -> Option<String> {
    forwarded_chain_identities(headers, forwarded_by_header)?
        .last()
        .cloned()
}

fn forwarded_chain_identities(
    headers: &HeaderMap,
    forwarded_by_header: &str,
) -> Option<Vec<String>> {
    let value = parse_single_non_empty_header(headers, forwarded_by_header)?;
    let chain = parse_forwarded_by_chain(value.as_str()).ok()?;
    let mut canonical_chain = Vec::with_capacity(chain.len());
    for hop in chain {
        let canonical_hop = normalize_peer_identity(hop.as_str())?;
        if !is_valid_peer_identity(canonical_hop.as_str()) {
            return None;
        }
        canonical_chain.push(canonical_hop);
    }
    if canonical_chain.is_empty() {
        None
    } else {
        Some(canonical_chain)
    }
}

fn normalize_token(value: &str) -> Option<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized.to_string())
    }
}

fn normalize_peer_identity(value: &str) -> Option<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized.to_ascii_lowercase())
    }
}

fn normalize_peer_identity_set(values: &[String]) -> BTreeSet<String> {
    values
        .iter()
        .filter_map(|value| normalize_peer_identity(value))
        .collect()
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::{
        CompatibilityPeerAuthenticator, FORWARDED_BY_HEADER, INTERNAL_MEMBERSHIP_PROPAGATED_HEADER,
        PeerAuthMode, PeerAuthenticationError, PeerAuthenticationResult, PeerAuthenticator,
        SharedTokenBindingStatus, SharedTokenPeerAuthenticator, authenticate_forwarded_request,
        contains_internal_forwarding_protocol_headers, contains_legacy_internal_forwarding_headers,
        peer_auth_reject_counters_snapshot, record_peer_auth_rejection,
        strip_untrusted_internal_forwarding_headers,
    };
    use crate::cluster::security::INTERNAL_AUTH_TOKEN_HEADER;

    #[test]
    fn compatibility_authenticator_accepts_forwarded_sender_without_token() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_BY_HEADER, "node-a:9000".parse().unwrap());
        let authenticator = CompatibilityPeerAuthenticator;

        let result = authenticator.authenticate_forwarded_request(&headers, FORWARDED_BY_HEADER);
        assert!(result.trusted);
        assert_eq!(result.mode, PeerAuthMode::Compatibility);
        assert_eq!(result.sender.as_deref(), Some("node-a:9000"));
        assert_eq!(result.error, None);
    }

    #[test]
    fn compatibility_authenticator_rejects_missing_forwarded_marker() {
        let headers = HeaderMap::new();
        let authenticator = CompatibilityPeerAuthenticator;

        let result = authenticator.authenticate_forwarded_request(&headers, FORWARDED_BY_HEADER);
        assert!(!result.trusted);
        assert_eq!(
            result.error,
            Some(PeerAuthenticationError::ForwardTrustRejected(
                crate::cluster::wire_auth::InternalForwardTrustError::MissingOrMalformedForwardedBy
            ))
        );
    }

    #[test]
    fn shared_token_authenticator_new_rejects_invalid_inputs() {
        assert!(
            SharedTokenPeerAuthenticator::new("", "node-a:9000", &["node-b:9000".to_string()])
                .is_none()
        );
        assert!(
            SharedTokenPeerAuthenticator::new("secret", "", &["node-b:9000".to_string()]).is_none()
        );
    }

    #[test]
    fn shared_token_authenticator_accepts_sender_in_allowlist() {
        let mut headers = HeaderMap::new();
        headers.insert(
            FORWARDED_BY_HEADER,
            "node-b:9000,node-a:9000".parse().unwrap(),
        );
        headers.insert(INTERNAL_AUTH_TOKEN_HEADER, "secret".parse().unwrap());
        let authenticator = SharedTokenPeerAuthenticator::new(
            "secret",
            "node-c:9000",
            &["node-a:9000".to_string(), "node-b:9000".to_string()],
        )
        .expect("authenticator should be created");

        let result = authenticator.authenticate_forwarded_request(&headers, FORWARDED_BY_HEADER);
        assert!(result.trusted);
        assert_eq!(result.mode, PeerAuthMode::SharedTokenAllowlist);
        assert_eq!(result.sender.as_deref(), Some("node-a:9000"));
        assert_eq!(authenticator.trusted_peer_count(), 2);
    }

    #[test]
    fn shared_token_authenticator_matches_sender_allowlist_case_insensitively() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_BY_HEADER, "Node-A:9000".parse().unwrap());
        headers.insert(INTERNAL_AUTH_TOKEN_HEADER, "secret".parse().unwrap());
        let authenticator = SharedTokenPeerAuthenticator::new(
            "secret",
            "node-c:9000",
            &["NODE-A:9000".to_string()],
        )
        .expect("authenticator should be created");

        let result = authenticator.authenticate_forwarded_request(&headers, FORWARDED_BY_HEADER);
        assert!(result.trusted);
        assert_eq!(result.sender.as_deref(), Some("node-a:9000"));
    }

    #[test]
    fn shared_token_authenticator_rejects_sender_not_in_allowlist() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_BY_HEADER, "node-x:9000".parse().unwrap());
        headers.insert(INTERNAL_AUTH_TOKEN_HEADER, "secret".parse().unwrap());
        let authenticator = SharedTokenPeerAuthenticator::new(
            "secret",
            "node-c:9000",
            &["node-a:9000".to_string()],
        )
        .expect("authenticator should be created");

        let result = authenticator.authenticate_forwarded_request(&headers, FORWARDED_BY_HEADER);
        assert!(!result.trusted);
        assert_eq!(
            result.error,
            Some(PeerAuthenticationError::SenderNotInAllowlist)
        );
        assert_eq!(result.reject_reason(), "sender_not_in_allowlist");
    }

    #[test]
    fn shared_token_authenticator_rejects_untrusted_intermediate_hop_in_forward_chain() {
        let mut headers = HeaderMap::new();
        headers.insert(
            FORWARDED_BY_HEADER,
            "node-x:9000,node-a:9000".parse().unwrap(),
        );
        headers.insert(INTERNAL_AUTH_TOKEN_HEADER, "secret".parse().unwrap());
        let authenticator = SharedTokenPeerAuthenticator::new(
            "secret",
            "node-c:9000",
            &["node-a:9000".to_string(), "node-b:9000".to_string()],
        )
        .expect("authenticator should be created");

        let result = authenticator.authenticate_forwarded_request(&headers, FORWARDED_BY_HEADER);
        assert!(!result.trusted);
        assert_eq!(
            result.error,
            Some(PeerAuthenticationError::SenderNotInAllowlist)
        );
    }

    #[test]
    fn shared_token_authenticator_rejects_sender_matching_local_node() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_BY_HEADER, "node-c:9000".parse().unwrap());
        headers.insert(INTERNAL_AUTH_TOKEN_HEADER, "secret".parse().unwrap());
        let authenticator = SharedTokenPeerAuthenticator::new(
            "secret",
            "node-c:9000",
            &["node-c:9000".to_string()],
        )
        .expect("authenticator should be created");

        let result = authenticator.authenticate_forwarded_request(&headers, FORWARDED_BY_HEADER);
        assert!(!result.trusted);
        assert_eq!(
            result.error,
            Some(PeerAuthenticationError::SenderMatchesLocalNode)
        );
    }

    #[test]
    fn shared_token_authenticator_rejects_forward_chain_containing_local_node_hop() {
        let mut headers = HeaderMap::new();
        headers.insert(
            FORWARDED_BY_HEADER,
            "node-c:9000,node-a:9000".parse().unwrap(),
        );
        headers.insert(INTERNAL_AUTH_TOKEN_HEADER, "secret".parse().unwrap());
        let authenticator = SharedTokenPeerAuthenticator::new(
            "secret",
            "node-c:9000",
            &["node-a:9000".to_string(), "node-c:9000".to_string()],
        )
        .expect("authenticator should be created");

        let result = authenticator.authenticate_forwarded_request(&headers, FORWARDED_BY_HEADER);
        assert!(!result.trusted);
        assert_eq!(
            result.error,
            Some(PeerAuthenticationError::SenderMatchesLocalNode)
        );
    }

    #[test]
    fn shared_token_authenticator_rejects_sender_matching_local_node_case_insensitively() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_BY_HEADER, "NODE-C:9000".parse().unwrap());
        headers.insert(INTERNAL_AUTH_TOKEN_HEADER, "secret".parse().unwrap());
        let authenticator = SharedTokenPeerAuthenticator::new(
            "secret",
            "node-c:9000",
            &["node-d:9000".to_string()],
        )
        .expect("authenticator should be created");

        let result = authenticator.authenticate_forwarded_request(&headers, FORWARDED_BY_HEADER);
        assert!(!result.trusted);
        assert_eq!(
            result.error,
            Some(PeerAuthenticationError::SenderMatchesLocalNode)
        );
    }

    #[test]
    fn shared_token_authenticator_rejects_invalid_token_before_allowlist() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_BY_HEADER, "node-a:9000".parse().unwrap());
        headers.insert(INTERNAL_AUTH_TOKEN_HEADER, "wrong".parse().unwrap());
        let authenticator = SharedTokenPeerAuthenticator::new(
            "secret",
            "node-c:9000",
            &["node-a:9000".to_string()],
        )
        .expect("authenticator should be created");

        let result = authenticator.authenticate_forwarded_request(&headers, FORWARDED_BY_HEADER);
        assert!(!result.trusted);
        assert_eq!(result.reject_reason(), "auth_token_mismatch");
    }

    #[test]
    fn shared_token_authenticator_rejects_duplicate_token_headers_with_empty_value() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_BY_HEADER, "node-a:9000".parse().unwrap());
        headers.insert(INTERNAL_AUTH_TOKEN_HEADER, "secret".parse().unwrap());
        headers.append(INTERNAL_AUTH_TOKEN_HEADER, HeaderValue::from_static(""));
        let authenticator = SharedTokenPeerAuthenticator::new(
            "secret",
            "node-c:9000",
            &["node-a:9000".to_string()],
        )
        .expect("authenticator should be created");

        let result = authenticator.authenticate_forwarded_request(&headers, FORWARDED_BY_HEADER);
        assert!(!result.trusted);
        assert_eq!(result.reject_reason(), "duplicate_auth_token_headers");
    }

    #[test]
    fn compatibility_authenticator_rejects_non_utf8_forwarded_marker() {
        let mut headers = HeaderMap::new();
        let non_utf8 = HeaderValue::from_bytes(&[0x80, b'n', b'o', b'd', b'e', b'-', b'a'])
            .expect("obs-text header value should parse");
        headers.insert(FORWARDED_BY_HEADER, non_utf8);
        let authenticator = CompatibilityPeerAuthenticator;

        let result = authenticator.authenticate_forwarded_request(&headers, FORWARDED_BY_HEADER);
        assert!(!result.trusted);
        assert_eq!(result.reject_reason(), "missing_or_malformed_forwarded_by");
    }

    #[test]
    fn peer_auth_mode_and_error_labels_are_stable() {
        assert_eq!(PeerAuthMode::Compatibility.as_str(), "compatibility");
        assert_eq!(
            PeerAuthMode::SharedTokenAllowlist.as_str(),
            "shared_token_allowlist"
        );
        assert_eq!(
            PeerAuthenticationError::MissingSenderIdentity.as_str(),
            "missing_sender_identity"
        );
        assert_eq!(
            PeerAuthenticationError::SenderMatchesLocalNode.as_str(),
            "sender_matches_local_node"
        );
        assert_eq!(
            PeerAuthenticationError::SenderNotInAllowlist.as_str(),
            "sender_not_in_allowlist"
        );
        assert_eq!(
            PeerAuthenticationError::InvalidAuthenticatorConfiguration.as_str(),
            "invalid_authenticator_configuration"
        );
        assert_eq!(
            SharedTokenBindingStatus::InvalidToken.as_str(),
            "invalid_token"
        );
        assert_eq!(
            SharedTokenBindingStatus::InvalidLocalNodeId.as_str(),
            "invalid_local_node_id"
        );
        assert_eq!(
            SharedTokenBindingStatus::UnboundNoTrustedPeers.as_str(),
            "unbound_no_trusted_peers"
        );
        assert_eq!(
            SharedTokenBindingStatus::Bound {
                trusted_peer_count: 1
            }
            .as_str(),
            "bound"
        );
    }

    #[test]
    fn shared_token_binding_status_reports_invalid_token_and_local_node() {
        assert_eq!(
            SharedTokenPeerAuthenticator::binding_status("", "node-a:9000", &[]),
            SharedTokenBindingStatus::InvalidToken
        );
        assert_eq!(
            SharedTokenPeerAuthenticator::binding_status("secret", "", &[]),
            SharedTokenBindingStatus::InvalidLocalNodeId
        );
        assert_eq!(
            SharedTokenPeerAuthenticator::binding_status("secret", "node/a", &[]),
            SharedTokenBindingStatus::InvalidLocalNodeId
        );
    }

    #[test]
    fn shared_token_binding_status_reports_unbound_when_no_valid_trusted_peers() {
        let status = SharedTokenPeerAuthenticator::binding_status(
            "secret",
            "node-a:9000",
            &["node-a:9000".to_string(), "node/b:9000".to_string()],
        );
        assert_eq!(status, SharedTokenBindingStatus::UnboundNoTrustedPeers);
        assert!(!status.is_bound());
        assert_eq!(status.trusted_peer_count(), 0);
    }

    #[test]
    fn shared_token_binding_status_reports_bound_peer_count() {
        let status = SharedTokenPeerAuthenticator::binding_status(
            "secret",
            "node-a:9000",
            &[
                "node-a:9000".to_string(),
                "node-b:9000".to_string(),
                "node-c:9000".to_string(),
                "node-c:9000".to_string(),
            ],
        );
        assert_eq!(
            status,
            SharedTokenBindingStatus::Bound {
                trusted_peer_count: 2
            }
        );
        assert!(status.is_bound());
        assert_eq!(status.trusted_peer_count(), 2);
    }

    #[test]
    fn shared_token_binding_status_deduplicates_case_variants() {
        let status = SharedTokenPeerAuthenticator::binding_status(
            "secret",
            "node-a:9000",
            &[
                "NODE-B:9000".to_string(),
                "node-b:9000".to_string(),
                "Node-B:9000".to_string(),
            ],
        );
        assert_eq!(
            status,
            SharedTokenBindingStatus::Bound {
                trusted_peer_count: 1
            }
        );
    }

    #[test]
    fn authenticate_forwarded_request_uses_compatibility_mode_when_token_is_unset() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_BY_HEADER, "node-a:9000".parse().unwrap());

        let result =
            authenticate_forwarded_request(&headers, FORWARDED_BY_HEADER, None, "node-z:9000", &[]);
        assert!(result.trusted);
        assert_eq!(result.mode, PeerAuthMode::Compatibility);
        assert_eq!(result.sender.as_deref(), Some("node-a:9000"));
    }

    #[test]
    fn authenticate_forwarded_request_rejects_invalid_shared_token_configuration() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_BY_HEADER, "node-a:9000".parse().unwrap());
        headers.insert(INTERNAL_AUTH_TOKEN_HEADER, "secret".parse().unwrap());

        let peers = vec!["node-a:9000".to_string()];
        let result = authenticate_forwarded_request(
            &headers,
            FORWARDED_BY_HEADER,
            Some("secret"),
            "node/invalid",
            peers.as_slice(),
        );
        assert!(!result.trusted);
        assert_eq!(result.mode, PeerAuthMode::SharedTokenAllowlist);
        assert_eq!(
            result.error,
            Some(PeerAuthenticationError::InvalidAuthenticatorConfiguration)
        );
        assert_eq!(
            result.reject_reason(),
            "invalid_authenticator_configuration"
        );
    }

    #[test]
    fn strip_untrusted_internal_forwarding_headers_removes_internal_protocol_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_BY_HEADER, "node-z:9000".parse().unwrap());
        headers.insert(INTERNAL_MEMBERSHIP_PROPAGATED_HEADER, "1".parse().unwrap());
        headers.insert(INTERNAL_AUTH_TOKEN_HEADER, "secret".parse().unwrap());
        headers.insert("x-maxio-forwarded-write-epoch", "7".parse().unwrap());
        headers.insert(
            "x-maxio-internal-forwarded-write-operation",
            "replicate-put-object".parse().unwrap(),
        );

        let peers = [String::from("node-b:9000")];
        let result = strip_untrusted_internal_forwarding_headers(
            &mut headers,
            Some("secret"),
            "node-a:9000",
            &peers,
        );

        assert!(!result.trusted);
        assert_eq!(result.reject_reason(), "sender_not_in_allowlist");
        assert!(headers.get(FORWARDED_BY_HEADER).is_none());
        assert!(headers.get(INTERNAL_MEMBERSHIP_PROPAGATED_HEADER).is_none());
        assert!(headers.get(INTERNAL_AUTH_TOKEN_HEADER).is_none());
        assert!(headers.get("x-maxio-forwarded-write-epoch").is_none());
        assert!(
            headers
                .get("x-maxio-internal-forwarded-write-operation")
                .is_none()
        );
    }

    #[test]
    fn strip_untrusted_internal_forwarding_headers_is_noop_without_internal_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-meta-user", "example".parse().unwrap());

        let result =
            strip_untrusted_internal_forwarding_headers(&mut headers, None, "node-z:9000", &[]);

        assert!(result.trusted);
        assert_eq!(result.sender, None);
        assert!(headers.contains_key("x-amz-meta-user"));
    }

    #[test]
    fn strip_untrusted_internal_forwarding_headers_preserves_trusted_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_BY_HEADER, "node-b:9000".parse().unwrap());
        headers.insert(INTERNAL_AUTH_TOKEN_HEADER, "secret".parse().unwrap());
        headers.insert("x-maxio-forwarded-write-epoch", "2".parse().unwrap());

        let peers = [String::from("node-b:9000")];
        let result = strip_untrusted_internal_forwarding_headers(
            &mut headers,
            Some("secret"),
            "node-a:9000",
            &peers,
        );

        assert!(result.trusted);
        assert_eq!(result.reject_reason(), "trusted");
        assert_eq!(
            headers
                .get(FORWARDED_BY_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("node-b:9000")
        );
        assert_eq!(
            headers
                .get("x-maxio-forwarded-write-epoch")
                .and_then(|value| value.to_str().ok()),
            Some("2")
        );
    }

    #[test]
    fn contains_internal_forwarding_protocol_headers_detects_known_headers() {
        let mut headers = HeaderMap::new();
        assert!(!contains_internal_forwarding_protocol_headers(&headers));

        headers.insert(INTERNAL_MEMBERSHIP_PROPAGATED_HEADER, "1".parse().unwrap());
        assert!(contains_internal_forwarding_protocol_headers(&headers));

        headers.remove(INTERNAL_MEMBERSHIP_PROPAGATED_HEADER);
        headers.insert(
            "x-maxio-internal-forwarded-write-operation",
            "replicate-put-object".parse().unwrap(),
        );
        assert!(contains_internal_forwarding_protocol_headers(&headers));
    }

    #[test]
    fn contains_internal_forwarding_protocol_headers_ignores_legacy_headers() {
        let mut legacy_only_headers = HeaderMap::new();
        legacy_only_headers.insert("x-maxio-forwarded-write-epoch", "9".parse().unwrap());
        assert!(!contains_internal_forwarding_protocol_headers(
            &legacy_only_headers
        ));
    }

    #[test]
    fn contains_legacy_internal_forwarding_headers_detects_legacy_headers() {
        let mut legacy_only_headers = HeaderMap::new();
        assert!(!contains_legacy_internal_forwarding_headers(
            &legacy_only_headers
        ));
        legacy_only_headers.insert("x-maxio-forwarded-write-epoch", "9".parse().unwrap());
        assert!(contains_legacy_internal_forwarding_headers(
            &legacy_only_headers
        ));
        legacy_only_headers.insert("x-maxio-forwarded-write-view-id", "view".parse().unwrap());
        assert!(contains_legacy_internal_forwarding_headers(
            &legacy_only_headers
        ));
    }

    #[test]
    fn strip_untrusted_internal_forwarding_headers_ignores_legacy_headers_without_trust_markers_in_compatibility_mode(
    ) {
        let mut headers = HeaderMap::new();
        headers.insert("x-maxio-forwarded-write-epoch", "7".parse().unwrap());
        headers.insert(
            "x-maxio-forwarded-write-idempotency-key",
            "legacy-key".parse().unwrap(),
        );

        let result = strip_untrusted_internal_forwarding_headers(
            &mut headers,
            None,
            "node-a:9000",
            &[String::from("node-b:9000")],
        );

        assert!(result.trusted);
        assert_eq!(result.sender, None);
        assert!(!contains_internal_forwarding_protocol_headers(&headers));
        assert!(contains_legacy_internal_forwarding_headers(&headers));
    }

    #[test]
    fn strip_untrusted_internal_forwarding_headers_rejects_legacy_headers_without_trust_markers_in_shared_token_mode(
    ) {
        let mut headers = HeaderMap::new();
        headers.insert("x-maxio-forwarded-write-epoch", "7".parse().unwrap());
        headers.insert(
            "x-maxio-forwarded-write-idempotency-key",
            "legacy-key".parse().unwrap(),
        );

        let result = strip_untrusted_internal_forwarding_headers(
            &mut headers,
            Some("secret"),
            "node-a:9000",
            &[String::from("node-b:9000")],
        );

        assert!(!result.trusted);
        assert_eq!(result.reject_reason(), "missing_or_malformed_forwarded_by");
        assert!(!contains_internal_forwarding_protocol_headers(&headers));
        assert!(!contains_legacy_internal_forwarding_headers(&headers));
    }

    #[test]
    fn record_peer_auth_rejection_tracks_reason_counters() {
        let before = peer_auth_reject_counters_snapshot();
        let result = PeerAuthenticationResult::rejected(
            PeerAuthMode::SharedTokenAllowlist,
            PeerAuthenticationError::SenderNotInAllowlist,
        );
        record_peer_auth_rejection(&result);
        let after = peer_auth_reject_counters_snapshot();

        assert_eq!(after.total, before.total + 1);
        assert_eq!(
            after.sender_not_in_allowlist,
            before.sender_not_in_allowlist + 1
        );
    }
}
