use clap::Parser;
use std::collections::HashMap;
use std::env;

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

#[derive(Parser, Debug, Clone)]
#[command(name = "maxio", about = "S3-compatible object storage server", version = env!("MAXIO_VERSION"))]
pub struct Config {
    /// Port to listen on
    #[arg(long, env = "MAXIO_PORT", default_value = "9000")]
    pub port: u16,

    /// Address to bind to
    #[arg(long, env = "MAXIO_ADDRESS", default_value = "0.0.0.0")]
    pub address: String,

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

    /// Enable erasure coding with per-chunk integrity checksums
    #[arg(long, env = "MAXIO_ERASURE_CODING", default_value = "false")]
    pub erasure_coding: bool,

    /// Chunk size in bytes for erasure coding (default 10MB)
    #[arg(long, env = "MAXIO_CHUNK_SIZE", default_value = "10485760")]
    pub chunk_size: u64,

    /// Number of parity shards for erasure coding (0 = no parity, requires --erasure-coding)
    #[arg(long, env = "MAXIO_PARITY_SHARDS", default_value = "0")]
    pub parity_shards: u32,
}

impl Config {
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
    use super::Config;

    fn base_config() -> Config {
        Config {
            port: 9000,
            address: "127.0.0.1".to_string(),
            data_dir: "./data".to_string(),
            access_key: "root".to_string(),
            secret_key: "root-secret".to_string(),
            additional_credentials: Vec::new(),
            region: "us-east-1".to_string(),
            node_id: "maxio-test-node".to_string(),
            cluster_peers: Vec::new(),
            erasure_coding: false,
            chunk_size: 10 * 1024 * 1024,
            parity_shards: 0,
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
}
