use clap::{Parser, ValueEnum};
use std::collections::HashMap;
use std::env;

use crate::metadata::ClusterMetadataListingStrategy;

fn first_env_value(keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| env::var(key).ok().filter(|value| !value.trim().is_empty()))
}

fn default_access_key() -> String {
    first_env_value(&["MINIO_ROOT_USER", "MINIO_ACCESS_KEY"])
        .unwrap_or_else(|| "minioadmin".to_string())
}

fn default_secret_key() -> String {
    first_env_value(&["MINIO_ROOT_PASSWORD", "MINIO_SECRET_KEY"])
        .unwrap_or_else(|| "minioadmin".to_string())
}

fn default_region() -> String {
    first_env_value(&["MINIO_REGION_NAME", "MINIO_REGION"])
        .unwrap_or_else(|| "us-east-1".to_string())
}

fn default_node_id() -> String {
    first_env_value(&["MAXIO_NODE_ID", "HOSTNAME"]).unwrap_or_else(|| "maxio-node".to_string())
}

fn parse_cluster_id(value: &str) -> Result<String, String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err("Invalid cluster id: value must be non-empty".to_string());
    }
    if normalized.len() > 128 {
        return Err(format!(
            "Invalid cluster id '{}': length must be <= 128 characters",
            normalized
        ));
    }
    if !normalized
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(format!(
            "Invalid cluster id '{}': only [A-Za-z0-9-_.:] are allowed",
            normalized
        ));
    }
    Ok(normalized.to_string())
}

fn parse_metadata_listing_strategy(value: &str) -> Result<ClusterMetadataListingStrategy, String> {
    match value.trim() {
        "local-node-only" => Ok(ClusterMetadataListingStrategy::LocalNodeOnly),
        "request-time-aggregation" => Ok(ClusterMetadataListingStrategy::RequestTimeAggregation),
        "consensus-index" => Ok(ClusterMetadataListingStrategy::ConsensusIndex),
        "full-replication" => Ok(ClusterMetadataListingStrategy::FullReplication),
        _ => Err(format!(
            "Invalid metadata listing strategy '{}': expected one of local-node-only, request-time-aggregation, consensus-index, full-replication",
            value
        )),
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum MembershipProtocol {
    StaticBootstrap,
    Gossip,
    Raft,
}

impl MembershipProtocol {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StaticBootstrap => "static-bootstrap",
            Self::Gossip => "gossip",
            Self::Raft => "raft",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum WriteDurabilityMode {
    DegradedSuccess,
    StrictQuorum,
}

impl WriteDurabilityMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DegradedSuccess => "degraded-success",
            Self::StrictQuorum => "strict-quorum",
        }
    }

    pub const fn is_strict_quorum(self) -> bool {
        matches!(self, Self::StrictQuorum)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum ClusterPeerTransportMode {
    Compatibility,
    Required,
}

impl ClusterPeerTransportMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Compatibility => "compatibility",
            Self::Required => "required",
        }
    }

    pub const fn is_required(self) -> bool {
        matches!(self, Self::Required)
    }
}

#[derive(Parser, Debug, Clone)]
#[command(name = "maxio", about = "S3-compatible object storage server", version = env!("MAXIO_VERSION"))]
pub struct Config {
    /// Port to listen on
    #[arg(long, env = "MAXIO_PORT", default_value = "9000")]
    pub port: u16,

    /// Address to bind to
    #[arg(long, env = "MAXIO_ADDRESS", default_value = "0.0.0.0")]
    pub address: String,

    /// Optional dedicated internal control-plane listener address (`host:port`).
    /// When set, `/internal/cluster/*` routes are served only on this listener.
    #[arg(long, env = "MAXIO_INTERNAL_BIND_ADDR")]
    pub internal_bind_addr: Option<String>,

    /// Root data directory
    #[arg(long, env = "MAXIO_DATA_DIR", default_value = "./data")]
    pub data_dir: String,

    /// Access key (MAXIO_ACCESS_KEY, MINIO_ROOT_USER, MINIO_ACCESS_KEY)
    #[arg(long, env = "MAXIO_ACCESS_KEY", default_value_t = default_access_key())]
    pub access_key: String,

    /// Secret key (MAXIO_SECRET_KEY, MINIO_ROOT_PASSWORD, MINIO_SECRET_KEY)
    #[arg(long, env = "MAXIO_SECRET_KEY", default_value_t = default_secret_key())]
    pub secret_key: String,

    /// Additional credentials as comma-separated access:secret pairs.
    /// Example: "user1:secret1,user2:secret2"
    #[arg(long, env = "MAXIO_ADDITIONAL_CREDENTIALS", value_delimiter = ',')]
    pub additional_credentials: Vec<String>,

    /// Default region (MAXIO_REGION, MINIO_REGION_NAME, MINIO_REGION)
    #[arg(long, env = "MAXIO_REGION", default_value_t = default_region())]
    pub region: String,

    /// Stable node identifier for future distributed mode coordination.
    #[arg(long, env = "MAXIO_NODE_ID", default_value_t = default_node_id())]
    pub node_id: String,

    /// Comma-separated cluster peer addresses (host:port) for distributed bootstrap wiring.
    #[arg(long, env = "MAXIO_CLUSTER_PEERS", value_delimiter = ',')]
    pub cluster_peers: Vec<String>,

    /// Membership protocol strategy for distributed node liveness/convergence contracts.
    #[arg(
        long,
        env = "MAXIO_MEMBERSHIP_PROTOCOL",
        value_enum,
        default_value_t = MembershipProtocol::StaticBootstrap
    )]
    pub membership_protocol: MembershipProtocol,

    /// Write durability contract for distributed primary-owner writes.
    /// - degraded-success: acknowledge primary write and expose quorum diagnostics headers.
    /// - strict-quorum: fail writes when quorum acknowledgements are not reached.
    #[arg(
        long,
        env = "MAXIO_WRITE_DURABILITY_MODE",
        value_enum,
        default_value_t = WriteDurabilityMode::DegradedSuccess
    )]
    pub write_durability_mode: WriteDurabilityMode,

    /// Distributed metadata/listing authority strategy contract.
    #[arg(
        long,
        env = "MAXIO_METADATA_LISTING_STRATEGY",
        default_value = "local-node-only",
        value_parser = parse_metadata_listing_strategy
    )]
    pub metadata_listing_strategy: ClusterMetadataListingStrategy,

    /// Shared internal auth token for trusted node-to-node forwarding/replication traffic.
    /// When unset, MaxIO keeps compatibility mode and trusts internal headers by forwarded marker.
    #[arg(long, env = "MAXIO_CLUSTER_AUTH_TOKEN")]
    pub cluster_auth_token: Option<String>,

    /// Optional mTLS certificate path for internal node-to-node transport identity.
    #[arg(long, env = "MAXIO_CLUSTER_PEER_TLS_CERT_PATH")]
    pub cluster_peer_tls_cert_path: Option<String>,

    /// Optional mTLS private-key path for internal node-to-node transport identity.
    #[arg(long, env = "MAXIO_CLUSTER_PEER_TLS_KEY_PATH")]
    pub cluster_peer_tls_key_path: Option<String>,

    /// Optional mTLS trust-store/CA path for internal node-to-node transport identity.
    #[arg(long, env = "MAXIO_CLUSTER_PEER_TLS_CA_PATH")]
    pub cluster_peer_tls_ca_path: Option<String>,

    /// Optional SHA-256 fingerprint pin for local peer mTLS certificate identity binding.
    /// Accepts lowercase/uppercase hex with optional `sha256:` prefix and optional `:` separators.
    #[arg(long, env = "MAXIO_CLUSTER_PEER_TLS_CERT_SHA256")]
    pub cluster_peer_tls_cert_sha256: Option<String>,

    /// Optional comma-separated SHA-256 fingerprint revocation set for peer mTLS certificates.
    /// Accepts the same fingerprint format as `MAXIO_CLUSTER_PEER_TLS_CERT_SHA256`.
    #[arg(long, env = "MAXIO_CLUSTER_PEER_TLS_CERT_SHA256_REVOCATIONS")]
    pub cluster_peer_tls_cert_sha256_revocations: Option<String>,

    /// Peer transport enforcement policy for internal node-to-node requests.
    /// - compatibility: require mTLS transport only when mTLS paths are configured.
    /// - required: fail closed in distributed shared-token mode when peer mTLS transport is not ready.
    #[arg(
        long,
        env = "MAXIO_CLUSTER_PEER_TRANSPORT_MODE",
        value_enum,
        default_value_t = ClusterPeerTransportMode::Compatibility
    )]
    pub cluster_peer_transport_mode: ClusterPeerTransportMode,

    /// Enable erasure coding with per-chunk integrity checksums
    #[arg(long, env = "MAXIO_ERASURE_CODING", default_value = "false")]
    pub erasure_coding: bool,

    /// Chunk size in bytes for erasure coding (default 10MB)
    #[arg(long, env = "MAXIO_CHUNK_SIZE", default_value = "10485760")]
    pub chunk_size: u64,

    /// Number of parity shards for erasure coding (0 = no parity, requires --erasure-coding)
    #[arg(long, env = "MAXIO_PARITY_SHARDS", default_value = "0")]
    pub parity_shards: u32,

    /// Minimum required free bytes in the data-dir filesystem for `/healthz` readiness.
    /// Set to `0` to disable disk-headroom gating.
    #[arg(
        long,
        env = "MAXIO_MIN_DISK_HEADROOM_BYTES",
        default_value = "268435456"
    )]
    pub min_disk_headroom_bytes: u64,
}

impl Config {
    pub fn configured_cluster_id(&self) -> Result<Option<String>, String> {
        first_env_value(&["MAXIO_CLUSTER_ID"])
            .map(|value| parse_cluster_id(value.as_str()))
            .transpose()
    }

    pub fn cluster_auth_token(&self) -> Option<&str> {
        self.cluster_auth_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub fn internal_bind_addr(&self) -> Option<&str> {
        self.internal_bind_addr
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub fn cluster_peer_tls_cert_path(&self) -> Option<&str> {
        self.cluster_peer_tls_cert_path
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub fn cluster_peer_tls_key_path(&self) -> Option<&str> {
        self.cluster_peer_tls_key_path
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub fn cluster_peer_tls_ca_path(&self) -> Option<&str> {
        self.cluster_peer_tls_ca_path
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub fn cluster_peer_tls_cert_sha256(&self) -> Option<&str> {
        self.cluster_peer_tls_cert_sha256
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub fn cluster_peer_tls_cert_sha256_revocations(&self) -> Option<&str> {
        self.cluster_peer_tls_cert_sha256_revocations
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    pub fn cluster_peer_transport_required(&self) -> bool {
        self.cluster_peer_transport_mode.is_required()
    }

    pub fn credential_map(&self) -> Result<HashMap<String, String>, String> {
        let mut credentials = HashMap::new();
        credentials.insert(self.access_key.clone(), self.secret_key.clone());

        for entry in &self.additional_credentials {
            let trimmed = entry.trim();
            let (access_key, secret_key) = trimmed.split_once(':').ok_or_else(|| {
                format!(
                    "Invalid additional credential '{}': expected access:secret",
                    trimmed
                )
            })?;
            let access_key = access_key.trim();
            let secret_key = secret_key.trim();

            if access_key.is_empty() || secret_key.is_empty() {
                return Err(format!(
                    "Invalid additional credential '{}': access and secret must be non-empty",
                    trimmed
                ));
            }

            if let Some(existing) = credentials.get(access_key) {
                if existing != secret_key {
                    return Err(format!(
                        "Conflicting secret for access key '{}'",
                        access_key
                    ));
                }
                continue;
            }

            credentials.insert(access_key.to_string(), secret_key.to_string());
        }

        Ok(credentials)
    }

    pub fn parsed_cluster_peers(&self) -> Result<Vec<String>, String> {
        let mut peers = Vec::new();
        for entry in &self.cluster_peers {
            let peer = entry.trim();
            if peer.is_empty() {
                continue;
            }

            let (host, port) = peer
                .rsplit_once(':')
                .ok_or_else(|| format!("Invalid cluster peer '{}': expected host:port", peer))?;
            let host = host.trim();
            let port = port.trim();

            if host.is_empty() {
                return Err(format!(
                    "Invalid cluster peer '{}': host must be non-empty",
                    peer
                ));
            }

            let parsed_port = port
                .parse::<u16>()
                .map_err(|_| format!("Invalid cluster peer '{}': invalid port", peer))?;
            if parsed_port == 0 {
                return Err(format!(
                    "Invalid cluster peer '{}': port must be between 1 and 65535",
                    peer
                ));
            }

            let normalized = format!("{}:{}", host, parsed_port);
            if !peers.iter().any(|p| p == &normalized) {
                peers.push(normalized);
            }
        }
        Ok(peers)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClusterPeerTransportMode, Config, MembershipProtocol, WriteDurabilityMode,
        parse_cluster_id, parse_metadata_listing_strategy,
    };
    use crate::metadata::ClusterMetadataListingStrategy;

    fn base_config() -> Config {
        Config {
            port: 9000,
            address: "127.0.0.1".to_string(),
            internal_bind_addr: None,
            data_dir: "./data".to_string(),
            access_key: "root".to_string(),
            secret_key: "root-secret".to_string(),
            additional_credentials: Vec::new(),
            region: "us-east-1".to_string(),
            node_id: "maxio-test-node".to_string(),
            cluster_peers: Vec::new(),
            membership_protocol: MembershipProtocol::StaticBootstrap,
            write_durability_mode: WriteDurabilityMode::DegradedSuccess,
            metadata_listing_strategy: ClusterMetadataListingStrategy::LocalNodeOnly,
            cluster_auth_token: None,
            cluster_peer_tls_cert_path: None,
            cluster_peer_tls_key_path: None,
            cluster_peer_tls_ca_path: None,
            cluster_peer_tls_cert_sha256: None,
            cluster_peer_tls_cert_sha256_revocations: None,
            cluster_peer_transport_mode: ClusterPeerTransportMode::Compatibility,
            erasure_coding: false,
            chunk_size: 10 * 1024 * 1024,
            parity_shards: 0,
            min_disk_headroom_bytes: 268_435_456,
        }
    }

    #[test]
    fn credential_map_includes_primary_and_additional_credentials() {
        let mut config = base_config();
        config.additional_credentials =
            vec!["user1:secret1".to_string(), " user2 : secret2 ".to_string()];

        let map = config.credential_map().unwrap();
        assert_eq!(map.get("root").map(String::as_str), Some("root-secret"));
        assert_eq!(map.get("user1").map(String::as_str), Some("secret1"));
        assert_eq!(map.get("user2").map(String::as_str), Some("secret2"));
    }

    #[test]
    fn credential_map_rejects_invalid_entries() {
        let mut config = base_config();
        config.additional_credentials = vec!["invalid".to_string()];
        assert!(config.credential_map().is_err());

        config.additional_credentials = vec!["user1:".to_string()];
        assert!(config.credential_map().is_err());
    }

    #[test]
    fn credential_map_rejects_conflicting_access_keys() {
        let mut config = base_config();
        config.additional_credentials = vec!["root:different".to_string()];
        assert!(config.credential_map().is_err());
    }

    #[test]
    fn parsed_cluster_peers_normalizes_and_deduplicates() {
        let mut config = base_config();
        config.cluster_peers = vec![
            "node-a.internal:9000".to_string(),
            " node-b.internal : 9010 ".to_string(),
            "node-a.internal:9000".to_string(),
        ];

        let peers = config.parsed_cluster_peers().unwrap();
        assert_eq!(
            peers,
            vec![
                "node-a.internal:9000".to_string(),
                "node-b.internal:9010".to_string()
            ]
        );
        assert!(!peers.is_empty());
    }

    #[test]
    fn parsed_cluster_peers_rejects_invalid_entries() {
        let mut config = base_config();
        config.cluster_peers = vec!["missing-port".to_string()];
        assert!(config.parsed_cluster_peers().is_err());

        config.cluster_peers = vec![":9000".to_string()];
        assert!(config.parsed_cluster_peers().is_err());

        config.cluster_peers = vec!["node-a:0".to_string()];
        assert!(config.parsed_cluster_peers().is_err());
    }

    #[test]
    fn membership_protocol_as_str_matches_contract() {
        assert_eq!(
            MembershipProtocol::StaticBootstrap.as_str(),
            "static-bootstrap"
        );
        assert_eq!(MembershipProtocol::Gossip.as_str(), "gossip");
        assert_eq!(MembershipProtocol::Raft.as_str(), "raft");
    }

    #[test]
    fn write_durability_mode_as_str_matches_contract() {
        assert_eq!(
            WriteDurabilityMode::DegradedSuccess.as_str(),
            "degraded-success"
        );
        assert_eq!(WriteDurabilityMode::StrictQuorum.as_str(), "strict-quorum");
        assert!(!WriteDurabilityMode::DegradedSuccess.is_strict_quorum());
        assert!(WriteDurabilityMode::StrictQuorum.is_strict_quorum());
    }

    #[test]
    fn cluster_auth_token_filters_empty_values() {
        let mut config = base_config();
        assert_eq!(config.cluster_auth_token(), None);

        config.cluster_auth_token = Some("   ".to_string());
        assert_eq!(config.cluster_auth_token(), None);

        config.cluster_auth_token = Some("shared-secret".to_string());
        assert_eq!(config.cluster_auth_token(), Some("shared-secret"));
    }

    #[test]
    fn internal_bind_addr_filters_empty_values() {
        let mut config = base_config();
        assert_eq!(config.internal_bind_addr(), None);

        config.internal_bind_addr = Some("   ".to_string());
        assert_eq!(config.internal_bind_addr(), None);

        config.internal_bind_addr = Some("127.0.0.1:9100".to_string());
        assert_eq!(config.internal_bind_addr(), Some("127.0.0.1:9100"));
    }

    #[test]
    fn cluster_peer_tls_paths_filter_empty_values() {
        let mut config = base_config();
        assert_eq!(config.cluster_peer_tls_cert_path(), None);
        assert_eq!(config.cluster_peer_tls_key_path(), None);
        assert_eq!(config.cluster_peer_tls_ca_path(), None);
        assert_eq!(config.cluster_peer_tls_cert_sha256(), None);

        config.cluster_peer_tls_cert_path = Some("   ".to_string());
        config.cluster_peer_tls_key_path = Some("\n\t".to_string());
        config.cluster_peer_tls_ca_path = Some("".to_string());
        config.cluster_peer_tls_cert_sha256 = Some(" ".to_string());
        assert_eq!(config.cluster_peer_tls_cert_path(), None);
        assert_eq!(config.cluster_peer_tls_key_path(), None);
        assert_eq!(config.cluster_peer_tls_ca_path(), None);
        assert_eq!(config.cluster_peer_tls_cert_sha256(), None);

        config.cluster_peer_tls_cert_path = Some("/etc/maxio/peer.crt".to_string());
        config.cluster_peer_tls_key_path = Some("/etc/maxio/peer.key".to_string());
        config.cluster_peer_tls_ca_path = Some("/etc/maxio/ca.pem".to_string());
        config.cluster_peer_tls_cert_sha256 = Some(
            "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".to_string(),
        );
        assert_eq!(
            config.cluster_peer_tls_cert_path(),
            Some("/etc/maxio/peer.crt")
        );
        assert_eq!(
            config.cluster_peer_tls_key_path(),
            Some("/etc/maxio/peer.key")
        );
        assert_eq!(config.cluster_peer_tls_ca_path(), Some("/etc/maxio/ca.pem"));
        assert_eq!(
            config.cluster_peer_tls_cert_sha256(),
            Some("sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
        );
    }

    #[test]
    fn cluster_peer_transport_mode_flags_required_policy() {
        let mut config = base_config();
        assert_eq!(config.cluster_peer_transport_mode.as_str(), "compatibility");
        assert!(!config.cluster_peer_transport_required());

        config.cluster_peer_transport_mode = ClusterPeerTransportMode::Required;
        assert_eq!(config.cluster_peer_transport_mode.as_str(), "required");
        assert!(config.cluster_peer_transport_required());
    }

    #[test]
    fn parse_metadata_listing_strategy_accepts_known_values() {
        assert_eq!(
            parse_metadata_listing_strategy("local-node-only").unwrap(),
            ClusterMetadataListingStrategy::LocalNodeOnly
        );
        assert_eq!(
            parse_metadata_listing_strategy("request-time-aggregation").unwrap(),
            ClusterMetadataListingStrategy::RequestTimeAggregation
        );
        assert_eq!(
            parse_metadata_listing_strategy("consensus-index").unwrap(),
            ClusterMetadataListingStrategy::ConsensusIndex
        );
        assert_eq!(
            parse_metadata_listing_strategy("full-replication").unwrap(),
            ClusterMetadataListingStrategy::FullReplication
        );
        assert!(parse_metadata_listing_strategy("unknown-strategy").is_err());
    }

    #[test]
    fn parse_cluster_id_accepts_valid_values() {
        assert_eq!(
            parse_cluster_id(" cluster-main.01 ").expect("cluster id should parse"),
            "cluster-main.01".to_string()
        );
        assert_eq!(
            parse_cluster_id("maxio:prod_eu").expect("cluster id should parse"),
            "maxio:prod_eu".to_string()
        );
    }

    #[test]
    fn parse_cluster_id_rejects_invalid_values() {
        assert!(parse_cluster_id("   ").is_err());
        assert!(parse_cluster_id("cluster id with spaces").is_err());
        assert!(parse_cluster_id("cluster/id").is_err());
        assert!(parse_cluster_id(&"a".repeat(129)).is_err());
    }
}
