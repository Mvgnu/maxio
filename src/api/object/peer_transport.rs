use std::fs;
use std::time::Duration;

use crate::cluster::transport_identity::{
    PeerTransportIdentityMode, attest_peer_transport_identity_with_mtls,
    probe_peer_transport_identity_with_cert_sha256_pin_and_node_id_binding,
};
use crate::config::Config;
use crate::error::S3Error;
use crate::server::AppState;

pub(crate) struct InternalPeerHttpClient {
    pub(crate) client: reqwest::Client,
    pub(crate) scheme: &'static str,
}

#[derive(Debug)]
struct ResolvedInternalPeerTransport {
    scheme: &'static str,
    ca_path: Option<String>,
}

fn resolve_internal_peer_transport(
    config: &Config,
) -> Result<ResolvedInternalPeerTransport, S3Error> {
    let has_configured_cluster_peers = config
        .cluster_peers
        .iter()
        .any(|peer| !peer.trim().is_empty());
    let strict_transport_required = config.cluster_peer_transport_required()
        && config.cluster_auth_token().is_some()
        && has_configured_cluster_peers;
    let expected_node_id = config.cluster_auth_token().map(|_| config.node_id.as_str());
    let status = probe_peer_transport_identity_with_cert_sha256_pin_and_node_id_binding(
        config.cluster_peer_tls_cert_path(),
        config.cluster_peer_tls_key_path(),
        config.cluster_peer_tls_ca_path(),
        config.cluster_peer_tls_cert_sha256(),
        expected_node_id,
    );

    match status.mode {
        PeerTransportIdentityMode::None if strict_transport_required => {
            Err(S3Error::service_unavailable(
                "Internal peer transport policy requires mTLS identity in distributed shared-token mode, but no peer TLS configuration is present",
            ))
        }
        PeerTransportIdentityMode::None => Ok(ResolvedInternalPeerTransport {
            scheme: "http",
            ca_path: None,
        }),
        PeerTransportIdentityMode::MtlsPath if !status.transport_ready => {
            let warning = status
                .warning
                .as_deref()
                .unwrap_or("mTLS peer transport identity is not ready with current configuration");
            Err(S3Error::service_unavailable(&format!(
                "Internal peer transport is not ready ({}): {}",
                status.reason.as_str(),
                warning
            )))
        }
        PeerTransportIdentityMode::MtlsPath => {
            let ca_path = config.cluster_peer_tls_ca_path().ok_or_else(|| {
                S3Error::service_unavailable(
                    "Internal peer transport mTLS mode requires cluster peer CA trust store path",
                )
            })?;
            Ok(ResolvedInternalPeerTransport {
                scheme: "https",
                ca_path: Some(ca_path.to_string()),
            })
        }
    }
}

pub(crate) fn internal_peer_transport_scheme(state: &AppState) -> Result<&'static str, S3Error> {
    resolve_internal_peer_transport(state.config.as_ref()).map(|resolved| resolved.scheme)
}

pub(crate) fn build_internal_peer_http_client(
    state: &AppState,
    connect_timeout: Option<Duration>,
    timeout: Duration,
) -> Result<InternalPeerHttpClient, S3Error> {
    let transport = resolve_internal_peer_transport(state.config.as_ref())?;

    let mut builder = reqwest::Client::builder().timeout(timeout);
    if let Some(connect_timeout) = connect_timeout {
        builder = builder.connect_timeout(connect_timeout);
    }

    if let Some(ca_path) = transport.ca_path.as_deref() {
        let ca_bytes = fs::read(ca_path).map_err(|err| {
            S3Error::service_unavailable(&format!(
                "Internal peer transport could not read trust store '{}': {}",
                ca_path, err
            ))
        })?;
        let ca_certificate = reqwest::Certificate::from_pem(&ca_bytes).map_err(|err| {
            S3Error::service_unavailable(&format!(
                "Internal peer transport trust store '{}' is not valid PEM: {}",
                ca_path, err
            ))
        })?;
        let identity = load_internal_peer_client_identity(state.config.as_ref())?;
        builder = builder.add_root_certificate(ca_certificate);
        builder = builder.identity(identity);
    }

    let client = builder.build().map_err(S3Error::internal)?;
    Ok(InternalPeerHttpClient {
        client,
        scheme: transport.scheme,
    })
}

pub(crate) fn attest_internal_peer_target(
    state: &AppState,
    target: &str,
    timeout: Duration,
) -> Result<(), S3Error> {
    let transport = resolve_internal_peer_transport(state.config.as_ref())?;
    if transport.scheme != "https" {
        return Ok(());
    }

    let cert_path = state.config.cluster_peer_tls_cert_path().ok_or_else(|| {
        S3Error::service_unavailable(
            "Internal peer transport mTLS mode requires cluster peer certificate path",
        )
    })?;
    let key_path = state.config.cluster_peer_tls_key_path().ok_or_else(|| {
        S3Error::service_unavailable(
            "Internal peer transport mTLS mode requires cluster peer private key path",
        )
    })?;
    let trust_store_path = state.config.cluster_peer_tls_ca_path().ok_or_else(|| {
        S3Error::service_unavailable(
            "Internal peer transport mTLS mode requires cluster peer CA trust store path",
        )
    })?;

    attest_peer_transport_identity_with_mtls(
        target,
        target,
        cert_path,
        key_path,
        trust_store_path,
        timeout,
    )
    .map_err(|error| {
        S3Error::service_unavailable(&format!(
            "Internal peer transport attestation failed for '{target}' ({}).",
            error.as_str()
        ))
    })
}

fn load_internal_peer_client_identity(config: &Config) -> Result<reqwest::Identity, S3Error> {
    let cert_path = config.cluster_peer_tls_cert_path().ok_or_else(|| {
        S3Error::service_unavailable(
            "Internal peer transport mTLS mode requires cluster peer certificate path",
        )
    })?;
    let key_path = config.cluster_peer_tls_key_path().ok_or_else(|| {
        S3Error::service_unavailable(
            "Internal peer transport mTLS mode requires cluster peer private key path",
        )
    })?;
    let cert_pem = fs::read(cert_path).map_err(|err| {
        S3Error::service_unavailable(&format!(
            "Internal peer transport could not read certificate '{}': {}",
            cert_path, err
        ))
    })?;
    let key_pem = fs::read(key_path).map_err(|err| {
        S3Error::service_unavailable(&format!(
            "Internal peer transport could not read private key '{}': {}",
            key_path, err
        ))
    })?;
    reqwest::Identity::from_pkcs8_pem(cert_pem.as_slice(), key_pem.as_slice()).map_err(|err| {
        S3Error::service_unavailable(&format!(
            "Internal peer transport certificate/key pair is invalid: {}",
            err
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::{load_internal_peer_client_identity, resolve_internal_peer_transport};
    use crate::config::{
        ClusterPeerTransportMode, Config, MembershipProtocol, WriteDurabilityMode,
    };
    use crate::metadata::ClusterMetadataListingStrategy;

    fn test_config() -> Config {
        Config {
            port: 9000,
            address: "127.0.0.1".to_string(),
            internal_bind_addr: None,
            data_dir: "./data".to_string(),
            access_key: "root".to_string(),
            secret_key: "root-secret".to_string(),
            additional_credentials: Vec::new(),
            region: "us-east-1".to_string(),
            node_id: "node-a.internal:9000".to_string(),
            cluster_peers: Vec::new(),
            membership_protocol: MembershipProtocol::StaticBootstrap,
            write_durability_mode: WriteDurabilityMode::DegradedSuccess,
            metadata_listing_strategy: ClusterMetadataListingStrategy::LocalNodeOnly,
            erasure_coding: false,
            chunk_size: 10 * 1024 * 1024,
            parity_shards: 0,
            min_disk_headroom_bytes: 0,
            cluster_auth_token: None,
            cluster_peer_tls_cert_path: None,
            cluster_peer_tls_key_path: None,
            cluster_peer_tls_ca_path: None,
            cluster_peer_tls_cert_sha256: None,
            cluster_peer_transport_mode: ClusterPeerTransportMode::Compatibility,
        }
    }

    #[test]
    fn resolve_internal_peer_transport_uses_http_when_mtls_is_not_configured() {
        let config = test_config();
        let resolved = resolve_internal_peer_transport(&config).expect("transport should resolve");
        assert_eq!(resolved.scheme, "http");
        assert!(resolved.ca_path.is_none());
    }

    #[test]
    fn resolve_internal_peer_transport_rejects_missing_mtls_when_policy_requires_transport() {
        let mut config = test_config();
        config.cluster_auth_token = Some("shared-secret".to_string());
        config.cluster_peers = vec!["node-b.internal:9000".to_string()];
        config.cluster_peer_transport_mode = ClusterPeerTransportMode::Required;

        let err = resolve_internal_peer_transport(&config).expect_err("should fail closed");
        assert!(err.message.contains("requires mTLS identity"));
    }

    #[test]
    fn resolve_internal_peer_transport_rejects_unready_mtls_configuration() {
        let mut config = test_config();
        config.cluster_peer_tls_cert_path = Some("/tmp/maxio-missing-cert.pem".to_string());
        config.cluster_peer_tls_key_path = Some("/tmp/maxio-missing-key.pem".to_string());
        config.cluster_peer_tls_ca_path = Some("/tmp/maxio-missing-ca.pem".to_string());

        let err = resolve_internal_peer_transport(&config).expect_err("should fail closed");
        assert!(err.message.contains("Internal peer transport is not ready"));
    }

    #[test]
    fn resolve_internal_peer_transport_rejects_unpinned_mtls_when_shared_token_trust_is_enabled() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("peer.crt");
        let key_path = dir.path().join("peer.key");
        let trust_store_path = dir.path().join("ca.pem");
        std::fs::write(
            &cert_path,
            "-----BEGIN CERTIFICATE-----\n\
             dGVzdA==\n\
             -----END CERTIFICATE-----\n",
        )
        .expect("write cert");
        std::fs::write(
            &key_path,
            "-----BEGIN PRIVATE KEY-----\n\
             dGVzdA==\n\
             -----END PRIVATE KEY-----\n",
        )
        .expect("write key");
        std::fs::write(
            &trust_store_path,
            "-----BEGIN CERTIFICATE-----\n\
             dGVzdA==\n\
             -----END CERTIFICATE-----\n",
        )
        .expect("write ca");

        let mut config = test_config();
        config.cluster_auth_token = Some("shared-secret".to_string());
        config.cluster_peer_tls_cert_path = Some(cert_path.to_string_lossy().to_string());
        config.cluster_peer_tls_key_path = Some(key_path.to_string_lossy().to_string());
        config.cluster_peer_tls_ca_path = Some(trust_store_path.to_string_lossy().to_string());
        config.cluster_peer_tls_cert_sha256 = None;

        let err = resolve_internal_peer_transport(&config).expect_err("should fail closed");
        assert!(err.message.contains("Internal peer transport is not ready"));
        assert!(
            err.message.contains("node_identity_binding_pin_required")
                || err.message.contains("certificate")
                || err.message.contains("private key")
        );
    }

    #[test]
    fn load_internal_peer_client_identity_rejects_invalid_certificate_key_pair() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("peer.crt");
        let key_path = dir.path().join("peer.key");
        std::fs::write(
            &cert_path,
            "-----BEGIN CERTIFICATE-----\n\
             dGVzdA==\n\
             -----END CERTIFICATE-----\n",
        )
        .expect("write cert");
        std::fs::write(
            &key_path,
            "-----BEGIN PRIVATE KEY-----\n\
             dGVzdA==\n\
             -----END PRIVATE KEY-----\n",
        )
        .expect("write key");

        let mut config = test_config();
        config.cluster_peer_tls_cert_path = Some(cert_path.to_string_lossy().to_string());
        config.cluster_peer_tls_key_path = Some(key_path.to_string_lossy().to_string());

        let err =
            load_internal_peer_client_identity(&config).expect_err("identity should fail closed");
        assert!(err.message.contains("certificate/key pair is invalid"));
    }
}
