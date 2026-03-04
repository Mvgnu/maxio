use axum::http::HeaderMap;

use crate::cluster::wire_auth::{InternalForwardTrustDecision, evaluate_internal_forward_trust};

pub const INTERNAL_AUTH_TOKEN_HEADER: &str = "x-maxio-internal-auth-token";

pub fn internal_forward_trust_decision(
    headers: &HeaderMap,
    forwarded_by_header: &str,
    configured_token: Option<&str>,
) -> InternalForwardTrustDecision {
    evaluate_internal_forward_trust(
        headers,
        forwarded_by_header,
        INTERNAL_AUTH_TOKEN_HEADER,
        configured_token,
    )
}

pub fn internal_forward_headers_are_trusted(
    headers: &HeaderMap,
    forwarded_by_header: &str,
    configured_token: Option<&str>,
) -> bool {
    internal_forward_trust_decision(headers, forwarded_by_header, configured_token).trusted
}

#[cfg(test)]
mod tests {
    use super::{
        INTERNAL_AUTH_TOKEN_HEADER, internal_forward_headers_are_trusted,
        internal_forward_trust_decision,
    };
    use axum::http::HeaderMap;

    const FORWARDED_BY_HEADER: &str = "x-maxio-forwarded-by";

    #[test]
    fn internal_headers_require_forwarded_marker() {
        let mut headers = HeaderMap::new();
        headers.insert(INTERNAL_AUTH_TOKEN_HEADER, "secret".parse().unwrap());
        assert!(!internal_forward_headers_are_trusted(
            &headers,
            FORWARDED_BY_HEADER,
            Some("secret"),
        ));
    }

    #[test]
    fn internal_headers_accept_token_match_when_configured() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_BY_HEADER, "node-a:9000".parse().unwrap());
        headers.insert(INTERNAL_AUTH_TOKEN_HEADER, "secret".parse().unwrap());
        assert!(internal_forward_headers_are_trusted(
            &headers,
            FORWARDED_BY_HEADER,
            Some("secret"),
        ));
    }

    #[test]
    fn internal_headers_reject_token_mismatch_when_configured() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_BY_HEADER, "node-a:9000".parse().unwrap());
        headers.insert(INTERNAL_AUTH_TOKEN_HEADER, "wrong".parse().unwrap());
        assert!(!internal_forward_headers_are_trusted(
            &headers,
            FORWARDED_BY_HEADER,
            Some("secret"),
        ));
    }

    #[test]
    fn internal_headers_allow_compat_mode_without_token_configuration() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_BY_HEADER, "node-a:9000".parse().unwrap());
        assert!(internal_forward_headers_are_trusted(
            &headers,
            FORWARDED_BY_HEADER,
            None,
        ));
    }

    #[test]
    fn internal_headers_reject_duplicate_auth_token_values() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_BY_HEADER, "node-a:9000".parse().unwrap());
        headers.append(INTERNAL_AUTH_TOKEN_HEADER, "secret".parse().unwrap());
        headers.append(INTERNAL_AUTH_TOKEN_HEADER, "secret".parse().unwrap());
        assert!(!internal_forward_headers_are_trusted(
            &headers,
            FORWARDED_BY_HEADER,
            Some("secret"),
        ));
    }

    #[test]
    fn internal_headers_reject_malformed_forwarded_chain() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_BY_HEADER, "node-a:9000,../evil".parse().unwrap());
        headers.insert(INTERNAL_AUTH_TOKEN_HEADER, "secret".parse().unwrap());
        assert!(!internal_forward_headers_are_trusted(
            &headers,
            FORWARDED_BY_HEADER,
            Some("secret"),
        ));
    }

    #[test]
    fn internal_headers_reject_forwarded_chain_with_duplicate_hops() {
        let mut headers = HeaderMap::new();
        headers.insert(
            FORWARDED_BY_HEADER,
            "node-a:9000,node-a:9000".parse().unwrap(),
        );
        headers.insert(INTERNAL_AUTH_TOKEN_HEADER, "secret".parse().unwrap());
        assert!(!internal_forward_headers_are_trusted(
            &headers,
            FORWARDED_BY_HEADER,
            Some("secret"),
        ));
    }

    #[test]
    fn internal_headers_reject_forwarded_chain_above_hop_limit() {
        let mut headers = HeaderMap::new();
        let chain = (0..=8)
            .map(|idx| format!("node-{idx}.internal:9000"))
            .collect::<Vec<_>>()
            .join(",");
        headers.insert(FORWARDED_BY_HEADER, chain.parse().unwrap());
        headers.insert(INTERNAL_AUTH_TOKEN_HEADER, "secret".parse().unwrap());
        assert!(!internal_forward_headers_are_trusted(
            &headers,
            FORWARDED_BY_HEADER,
            Some("secret"),
        ));
    }

    #[test]
    fn internal_headers_expose_reject_reason_labels_for_observability() {
        let mut headers = HeaderMap::new();
        headers.insert(FORWARDED_BY_HEADER, "node-a:9000".parse().unwrap());
        headers.insert(INTERNAL_AUTH_TOKEN_HEADER, "wrong".parse().unwrap());
        let decision =
            internal_forward_trust_decision(&headers, FORWARDED_BY_HEADER, Some("secret"));
        assert!(!decision.trusted);
        assert_eq!(decision.reject_reason(), "auth_token_mismatch");
    }
}
