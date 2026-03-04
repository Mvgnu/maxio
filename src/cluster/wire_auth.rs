use axum::http::HeaderMap;

use crate::cluster::constant_time::constant_time_str_eq;
use crate::cluster::internal_transport::{ForwardedByParseError, parse_forwarded_by_chain};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InternalForwardTrustError {
    MissingOrMalformedForwardedBy,
    MalformedForwardedByChain,
    ForwardedByDuplicatePeerHop,
    ForwardedByHopLimitExceeded,
    MissingOrMalformedAuthToken,
    DuplicateAuthTokenHeaders,
    AuthTokenMismatch,
}

impl InternalForwardTrustError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MissingOrMalformedForwardedBy => "missing_or_malformed_forwarded_by",
            Self::MalformedForwardedByChain => "malformed_forwarded_by_chain",
            Self::ForwardedByDuplicatePeerHop => "forwarded_by_duplicate_peer_hop",
            Self::ForwardedByHopLimitExceeded => "forwarded_by_hop_limit_exceeded",
            Self::MissingOrMalformedAuthToken => "missing_or_malformed_auth_token",
            Self::DuplicateAuthTokenHeaders => "duplicate_auth_token_headers",
            Self::AuthTokenMismatch => "auth_token_mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalForwardTrustDecision {
    pub trusted: bool,
    pub error: Option<InternalForwardTrustError>,
}

impl InternalForwardTrustDecision {
    pub fn trusted() -> Self {
        Self {
            trusted: true,
            error: None,
        }
    }

    pub fn rejected(error: InternalForwardTrustError) -> Self {
        Self {
            trusted: false,
            error: Some(error),
        }
    }

    pub fn reject_reason(&self) -> &'static str {
        self.error
            .as_ref()
            .map(InternalForwardTrustError::as_str)
            .unwrap_or("trusted")
    }
}

pub fn evaluate_internal_forward_trust(
    headers: &HeaderMap,
    forwarded_by_header: &str,
    internal_auth_header: &str,
    configured_token: Option<&str>,
) -> InternalForwardTrustDecision {
    let forwarded_header = parse_single_non_empty_header(headers, forwarded_by_header);
    let forwarded_by = match forwarded_header {
        Ok(value) => match parse_forwarded_by_chain(value.as_str()) {
            Ok(chain) if !chain.is_empty() => Some(chain),
            Err(ForwardedByParseError::InvalidPeerIdentity) => {
                return InternalForwardTrustDecision::rejected(
                    InternalForwardTrustError::MalformedForwardedByChain,
                );
            }
            Err(ForwardedByParseError::DuplicatePeerHop) => {
                return InternalForwardTrustDecision::rejected(
                    InternalForwardTrustError::ForwardedByDuplicatePeerHop,
                );
            }
            Err(ForwardedByParseError::HopLimitExceeded) => {
                return InternalForwardTrustDecision::rejected(
                    InternalForwardTrustError::ForwardedByHopLimitExceeded,
                );
            }
            _ => None,
        },
        Err(_) => None,
    };

    if forwarded_by.is_none() {
        return InternalForwardTrustDecision::rejected(
            InternalForwardTrustError::MissingOrMalformedForwardedBy,
        );
    }

    let Some(expected_token) = normalize_token(configured_token) else {
        return InternalForwardTrustDecision::trusted();
    };

    let provided_token = match parse_single_non_empty_header(headers, internal_auth_header) {
        Ok(value) => value,
        Err(SingleHeaderParseError::Duplicate) => {
            return InternalForwardTrustDecision::rejected(
                InternalForwardTrustError::DuplicateAuthTokenHeaders,
            );
        }
        Err(SingleHeaderParseError::Missing | SingleHeaderParseError::Malformed) => {
            return InternalForwardTrustDecision::rejected(
                InternalForwardTrustError::MissingOrMalformedAuthToken,
            );
        }
    };

    if constant_time_str_eq(provided_token.as_str(), expected_token) {
        InternalForwardTrustDecision::trusted()
    } else {
        InternalForwardTrustDecision::rejected(InternalForwardTrustError::AuthTokenMismatch)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SingleHeaderParseError {
    Missing,
    Duplicate,
    Malformed,
}

fn parse_single_non_empty_header(
    headers: &HeaderMap,
    name: &str,
) -> Result<String, SingleHeaderParseError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(SingleHeaderParseError::Missing)?;
    if values.next().is_some() {
        return Err(SingleHeaderParseError::Duplicate);
    }
    let value = value
        .to_str()
        .map_err(|_| SingleHeaderParseError::Malformed)?;
    let value = value.trim();
    if value.is_empty() {
        return Err(SingleHeaderParseError::Malformed);
    }
    Ok(value.to_string())
}

fn normalize_token(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|token| !token.is_empty())
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::{InternalForwardTrustError, evaluate_internal_forward_trust};

    const FORWARDED_BY: &str = "x-maxio-forwarded-by";
    const AUTH_TOKEN: &str = "x-maxio-internal-auth-token";

    #[test]
    fn trust_rejects_missing_or_malformed_forwarded_by() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTH_TOKEN, "secret".parse().expect("header should parse"));
        let decision =
            evaluate_internal_forward_trust(&headers, FORWARDED_BY, AUTH_TOKEN, Some("secret"));
        assert!(!decision.trusted);
        assert_eq!(
            decision.error,
            Some(InternalForwardTrustError::MissingOrMalformedForwardedBy)
        );
    }

    #[test]
    fn trust_rejects_malformed_forwarded_by_chain() {
        let mut headers = HeaderMap::new();
        headers.insert(
            FORWARDED_BY,
            "node-a.internal:9000,../node-b"
                .parse()
                .expect("header should parse"),
        );
        headers.insert(AUTH_TOKEN, "secret".parse().expect("header should parse"));
        let decision =
            evaluate_internal_forward_trust(&headers, FORWARDED_BY, AUTH_TOKEN, Some("secret"));
        assert!(!decision.trusted);
        assert_eq!(
            decision.error,
            Some(InternalForwardTrustError::MalformedForwardedByChain)
        );
    }

    #[test]
    fn trust_rejects_token_mismatch_when_configured() {
        let mut headers = HeaderMap::new();
        headers.insert(
            FORWARDED_BY,
            "node-a.internal:9000".parse().expect("header should parse"),
        );
        headers.insert(AUTH_TOKEN, "wrong".parse().expect("header should parse"));
        let decision =
            evaluate_internal_forward_trust(&headers, FORWARDED_BY, AUTH_TOKEN, Some("secret"));
        assert!(!decision.trusted);
        assert_eq!(
            decision.error,
            Some(InternalForwardTrustError::AuthTokenMismatch)
        );
    }

    #[test]
    fn trust_rejects_duplicate_auth_token_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            FORWARDED_BY,
            "node-a.internal:9000".parse().expect("header should parse"),
        );
        headers.append(AUTH_TOKEN, "secret".parse().expect("header should parse"));
        headers.append(AUTH_TOKEN, "secret".parse().expect("header should parse"));
        let decision =
            evaluate_internal_forward_trust(&headers, FORWARDED_BY, AUTH_TOKEN, Some("secret"));
        assert!(!decision.trusted);
        assert_eq!(
            decision.error,
            Some(InternalForwardTrustError::DuplicateAuthTokenHeaders)
        );
    }

    #[test]
    fn trust_rejects_duplicate_auth_token_values_with_empty_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            FORWARDED_BY,
            "node-a.internal:9000".parse().expect("header should parse"),
        );
        headers.insert(AUTH_TOKEN, "secret".parse().expect("header should parse"));
        headers.append(AUTH_TOKEN, HeaderValue::from_static(""));
        let decision =
            evaluate_internal_forward_trust(&headers, FORWARDED_BY, AUTH_TOKEN, Some("secret"));
        assert!(!decision.trusted);
        assert_eq!(
            decision.error,
            Some(InternalForwardTrustError::DuplicateAuthTokenHeaders)
        );
    }

    #[test]
    fn trust_accepts_forwarded_marker_without_token_in_compat_mode() {
        let mut headers = HeaderMap::new();
        headers.insert(
            FORWARDED_BY,
            "node-a.internal:9000,node-b.internal:9000"
                .parse()
                .expect("header should parse"),
        );
        let decision = evaluate_internal_forward_trust(&headers, FORWARDED_BY, AUTH_TOKEN, None);
        assert!(decision.trusted);
        assert_eq!(decision.error, None);
    }

    #[test]
    fn trust_rejects_forwarded_by_chain_above_hop_limit() {
        let mut headers = HeaderMap::new();
        let chain = (0..=8)
            .map(|idx| format!("node-{idx}.internal:9000"))
            .collect::<Vec<_>>()
            .join(",");
        headers.insert(
            FORWARDED_BY,
            chain.parse().expect("forwarded-by chain should parse"),
        );
        let decision =
            evaluate_internal_forward_trust(&headers, FORWARDED_BY, AUTH_TOKEN, Some("secret"));
        assert!(!decision.trusted);
        assert_eq!(
            decision.error,
            Some(InternalForwardTrustError::ForwardedByHopLimitExceeded)
        );
    }

    #[test]
    fn trust_rejects_forwarded_by_chain_with_duplicate_hops() {
        let mut headers = HeaderMap::new();
        headers.insert(
            FORWARDED_BY,
            "node-a.internal:9000,node-a.internal:9000"
                .parse()
                .expect("header should parse"),
        );
        headers.insert(AUTH_TOKEN, "secret".parse().expect("header should parse"));
        let decision =
            evaluate_internal_forward_trust(&headers, FORWARDED_BY, AUTH_TOKEN, Some("secret"));
        assert!(!decision.trusted);
        assert_eq!(
            decision.error,
            Some(InternalForwardTrustError::ForwardedByDuplicatePeerHop)
        );
    }

    #[test]
    fn trust_error_reason_labels_are_stable() {
        assert_eq!(
            InternalForwardTrustError::MissingOrMalformedForwardedBy.as_str(),
            "missing_or_malformed_forwarded_by"
        );
        assert_eq!(
            InternalForwardTrustError::MalformedForwardedByChain.as_str(),
            "malformed_forwarded_by_chain"
        );
        assert_eq!(
            InternalForwardTrustError::ForwardedByDuplicatePeerHop.as_str(),
            "forwarded_by_duplicate_peer_hop"
        );
        assert_eq!(
            InternalForwardTrustError::ForwardedByHopLimitExceeded.as_str(),
            "forwarded_by_hop_limit_exceeded"
        );
        assert_eq!(
            InternalForwardTrustError::MissingOrMalformedAuthToken.as_str(),
            "missing_or_malformed_auth_token"
        );
        assert_eq!(
            InternalForwardTrustError::DuplicateAuthTokenHeaders.as_str(),
            "duplicate_auth_token_headers"
        );
        assert_eq!(
            InternalForwardTrustError::AuthTokenMismatch.as_str(),
            "auth_token_mismatch"
        );
    }
}
