use std::net::Ipv6Addr;

pub fn is_valid_peer_identity(value: &str) -> bool {
    parse_peer_identity(value).is_some()
}

pub(crate) fn parse_peer_identity(value: &str) -> Option<(String, Option<u16>)> {
    let normalized = value.trim();
    if normalized.is_empty() || normalized.len() > 255 {
        return None;
    }

    if let Some(bracketed) = normalized.strip_prefix('[') {
        let (host, remainder) = bracketed.split_once(']')?;
        if host.parse::<Ipv6Addr>().is_err() {
            return None;
        }

        if remainder.is_empty() {
            return Some((host.to_ascii_lowercase(), None));
        }
        let port = remainder.strip_prefix(':').and_then(parse_peer_port)?;
        return Some((host.to_ascii_lowercase(), Some(port)));
    }

    if normalized.matches(':').count() > 1 {
        return None;
    }
    if !normalized
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'-' | b'_'))
    {
        return None;
    }

    match normalized.split_once(':') {
        Some((host, port)) if is_valid_peer_host(host) => {
            parse_peer_port(port).map(|parsed| (host.to_ascii_lowercase(), Some(parsed)))
        }
        Some(_) => None,
        None if is_valid_peer_host(normalized) => Some((normalized.to_ascii_lowercase(), None)),
        None => None,
    }
}

fn is_valid_peer_host(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }

    host.split('.').all(is_valid_peer_host_label)
}

fn is_valid_peer_host_label(label: &str) -> bool {
    if label.is_empty() {
        return false;
    }

    let bytes = label.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return false;
    }

    bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn is_valid_peer_port(port: &str) -> bool {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }

    match port.parse::<u16>() {
        Ok(parsed) => parsed > 0,
        Err(_) => false,
    }
}

fn parse_peer_port(port: &str) -> Option<u16> {
    if !is_valid_peer_port(port) {
        return None;
    }
    port.parse::<u16>().ok()
}

#[cfg(test)]
mod tests {
    use super::{is_valid_peer_identity, parse_peer_identity};

    #[test]
    fn valid_peer_identity_accepts_expected_chars() {
        assert!(is_valid_peer_identity("node-a.internal:9000"));
        assert!(is_valid_peer_identity("node_a-01"));
        assert!(is_valid_peer_identity("[2001:db8::1]:9000"));
        assert!(is_valid_peer_identity("[2001:db8::1]"));
    }

    #[test]
    fn valid_peer_identity_rejects_empty_or_whitespace() {
        assert!(!is_valid_peer_identity(""));
        assert!(!is_valid_peer_identity("   "));
    }

    #[test]
    fn valid_peer_identity_rejects_unsafe_chars() {
        assert!(!is_valid_peer_identity("node-a/internal:9000"));
        assert!(!is_valid_peer_identity("node-a.internal:9000?x=1"));
    }

    #[test]
    fn valid_peer_identity_rejects_malformed_host_and_port_shapes() {
        assert!(!is_valid_peer_identity("node-a.internal:"));
        assert!(!is_valid_peer_identity("node-a.internal:not-a-port"));
        assert!(!is_valid_peer_identity("node-a.internal:0"));
        assert!(!is_valid_peer_identity("node-a.internal:65536"));
        assert!(!is_valid_peer_identity("node-a.internal:80:90"));
        assert!(!is_valid_peer_identity("2001:db8::1:9000"));
        assert!(!is_valid_peer_identity("[2001:db8::1:9000"));
        assert!(!is_valid_peer_identity("[2001:db8::zz]:9000"));
        assert!(!is_valid_peer_identity("[2001:db8::1]:0"));
        assert!(!is_valid_peer_identity(".node-a.internal:9000"));
        assert!(!is_valid_peer_identity("node-a.internal.:9000"));
        assert!(!is_valid_peer_identity("node..a.internal:9000"));
        assert!(!is_valid_peer_identity("-node-a.internal:9000"));
        assert!(!is_valid_peer_identity("node-a.internal-:9000"));
    }

    #[test]
    fn parse_peer_identity_extracts_host_and_port() {
        assert_eq!(
            parse_peer_identity("Node-A.Internal:9000"),
            Some(("node-a.internal".to_string(), Some(9000)))
        );
        assert_eq!(
            parse_peer_identity("[2001:DB8::1]:9000"),
            Some(("2001:db8::1".to_string(), Some(9000)))
        );
        assert_eq!(
            parse_peer_identity("[2001:DB8::1]"),
            Some(("2001:db8::1".to_string(), None))
        );
    }
}
