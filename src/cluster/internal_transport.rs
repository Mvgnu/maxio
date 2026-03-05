use crate::cluster::peer_identity::canonical_peer_identity;
use std::collections::HashSet;

pub const MAX_FORWARDED_BY_HOPS: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardedByParseError {
    InvalidPeerIdentity,
    DuplicatePeerHop,
    HopLimitExceeded,
}

pub fn parse_forwarded_by_chain(header_value: &str) -> Result<Vec<String>, ForwardedByParseError> {
    let mut parsed = Vec::new();
    let mut seen = HashSet::new();

    for segment in header_value.split(',') {
        let canonical =
            canonical_peer_identity(segment).ok_or(ForwardedByParseError::InvalidPeerIdentity)?;
        if !seen.insert(canonical.clone()) {
            return Err(ForwardedByParseError::DuplicatePeerHop);
        }
        parsed.push(canonical);
        if parsed.len() > MAX_FORWARDED_BY_HOPS {
            return Err(ForwardedByParseError::HopLimitExceeded);
        }
    }

    if parsed.is_empty() {
        Err(ForwardedByParseError::InvalidPeerIdentity)
    } else {
        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::{ForwardedByParseError, parse_forwarded_by_chain};

    #[test]
    fn parse_forwarded_by_chain_accepts_single_and_multi_hop_values() {
        assert_eq!(
            parse_forwarded_by_chain("node-a.internal:9000"),
            Ok(vec!["node-a.internal:9000".to_string()])
        );
        assert_eq!(
            parse_forwarded_by_chain("node-a.internal:9000,node-b.internal:9000"),
            Ok(vec![
                "node-a.internal:9000".to_string(),
                "node-b.internal:9000".to_string()
            ])
        );
    }

    #[test]
    fn parse_forwarded_by_chain_rejects_invalid_segments() {
        assert_eq!(
            parse_forwarded_by_chain(""),
            Err(ForwardedByParseError::InvalidPeerIdentity)
        );
        assert_eq!(
            parse_forwarded_by_chain("node-a.internal:9000,"),
            Err(ForwardedByParseError::InvalidPeerIdentity)
        );
        assert_eq!(
            parse_forwarded_by_chain("node-a.internal:9000,../node-b"),
            Err(ForwardedByParseError::InvalidPeerIdentity)
        );
    }

    #[test]
    fn parse_forwarded_by_chain_rejects_duplicate_hops() {
        assert_eq!(
            parse_forwarded_by_chain("node-a.internal:9000,node-a.internal:9000"),
            Err(ForwardedByParseError::DuplicatePeerHop)
        );
        assert_eq!(
            parse_forwarded_by_chain("Node-A.internal:9000,node-a.internal:9000"),
            Err(ForwardedByParseError::DuplicatePeerHop)
        );
        assert_eq!(
            parse_forwarded_by_chain(
                "[2001:db8::1]:9000,[2001:0db8:0000:0000:0000:0000:0000:0001]:9000"
            ),
            Err(ForwardedByParseError::DuplicatePeerHop)
        );
    }

    #[test]
    fn parse_forwarded_by_chain_rejects_hop_count_above_limit() {
        let chain = (0..=8)
            .map(|idx| format!("node-{idx}.internal:9000"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            parse_forwarded_by_chain(chain.as_str()),
            Err(ForwardedByParseError::HopLimitExceeded)
        );
    }
}
