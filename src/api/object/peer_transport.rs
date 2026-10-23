use std::time::Duration;

use crate::cluster::transport_identity::{
    PeerCertificatePolicy, PeerTlsConfig, PeerTransportEnforcementMode, PeerTransportIdentityMode,
    assess_peer_transport_policy_with_context, build_peer_mtls_http_client,
    peer_transport_policy_effective_reason,
    probe_peer_transport_identity_with_certificate_policy_and_node_id_binding,
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

fn resolve_internal_peer_transport_with_cluster_peer_presence(
    config: &Config,
    has_cluster_peers: bool,
) -> Result<ResolvedInternalPeerTransport, S3Error> {
    let transport_policy_mode = if config.cluster_peer_transport_required() {
        PeerTransportEnforcementMode::StrictMtlsIdentityBound
    } else {
        PeerTransportEnforcementMode::Compatibility
    };
    let auth_configured = config.cluster_auth_token().is_some();
    let expected_node_id = Some(config.node_id.as_str());
    let status = probe_peer_transport_identity_with_certificate_policy_and_node_id_binding(
        config.cluster_peer_tls_cert_path(),
        config.cluster_peer_tls_key_path(),
        config.cluster_peer_tls_ca_path(),
        PeerCertificatePolicy {
            sha256_pin: config.cluster_peer_tls_cert_sha256(),
            sha256_revocations: config.cluster_peer_tls_cert_sha256_revocations(),
        },
        expected_node_id,
    );
    let policy = assess_peer_transport_policy_with_context(
        &status,
        transport_policy_mode,
        has_cluster_peers,
        auth_configured,
        has_cluster_peers,
    );
    let readiness_reason = peer_transport_policy_effective_reason(&policy).as_str();

    match status.mode {
        PeerTransportIdentityMode::None if policy.required => {
            Err(S3Error::service_unavailable(&format!(
                "Internal peer transport policy requires mTLS identity in distributed shared-token mode ({readiness_reason}), but no peer TLS configuration is present"
            )))
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
                readiness_reason, warning
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
    let has_active_cluster_peers = !state.active_cluster_peers().is_empty();
    resolve_internal_peer_transport_with_cluster_peer_presence(
        state.config.as_ref(),
        has_active_cluster_peers,
    )
    .map(|resolved| resolved.scheme)
}

/// Construct a client whose TLS handshake binds the actual request to this target.
/// A probe on another socket cannot authorize forwarding headers or payload bytes.
pub(crate) fn build_internal_peer_http_client(
    state: &AppState,
    target: &str,
    connect_timeout: Option<Duration>,
    timeout: Duration,
) -> Result<InternalPeerHttpClient, S3Error> {
    let config = state.config.as_ref();
    let transport = resolve_internal_peer_transport_with_cluster_peer_presence(
        config,
        !state.active_cluster_peers().is_empty(),
    )?;
    let client = if let Some(ca_path) = transport.ca_path.as_deref() {
        let cert_path = config.cluster_peer_tls_cert_path().ok_or_else(|| {
            S3Error::service_unavailable("Internal peer transport requires a certificate path")
        })?;
        let key_path = config.cluster_peer_tls_key_path().ok_or_else(|| {
            S3Error::service_unavailable("Internal peer transport requires a private key path")
        })?;
        build_peer_mtls_http_client(
            PeerTlsConfig {
                node_id: state.node_id.as_str(),
                cert_path,
                key_path,
                ca_path,
                certificate_policy: PeerCertificatePolicy {
                    sha256_pin: config.cluster_peer_tls_cert_sha256(),
                    sha256_revocations: config.cluster_peer_tls_cert_sha256_revocations(),
                },
            },
            target,
            connect_timeout,
            timeout,
        )
        .map_err(|error| {
            S3Error::service_unavailable(&format!(
                "Internal peer transport for '{target}' is not ready: {error}"
            ))
        })?
    } else {
        // Even compatibility traffic must not leak its internal token to a proxy
        // or a redirect target that is not the configured peer.
        let mut builder = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy();
        if let Some(connect_timeout) = connect_timeout {
            builder = builder.connect_timeout(connect_timeout);
        }
        builder.build().map_err(S3Error::internal)?
    };
    Ok(InternalPeerHttpClient {
        client,
        scheme: transport.scheme,
    })
}

#[cfg(test)]
mod tests {
    use super::resolve_internal_peer_transport_with_cluster_peer_presence;
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
            pending_replication_due_warning_threshold: None,
            pending_rebalance_due_warning_threshold: None,
            pending_membership_propagation_due_warning_threshold: None,
            pending_metadata_repair_due_warning_threshold: None,
            cluster_auth_token: None,
            tls_cert_path: None,
            tls_key_path: None,
            cluster_peer_tls_cert_path: None,
            cluster_peer_tls_key_path: None,
            cluster_peer_tls_ca_path: None,
            cluster_peer_tls_cert_sha256: None,
            cluster_peer_tls_cert_sha256_revocations: None,
            cluster_peer_transport_mode: ClusterPeerTransportMode::Compatibility,
        }
    }

    #[test]
    fn resolve_internal_peer_transport_uses_http_when_mtls_is_not_configured() {
        let config = test_config();
        let resolved = resolve_internal_peer_transport_with_cluster_peer_presence(
            &config,
            config
                .cluster_peers
                .iter()
                .any(|peer| !peer.trim().is_empty()),
        )
        .expect("transport should resolve");
        assert_eq!(resolved.scheme, "http");
        assert!(resolved.ca_path.is_none());
    }

    #[test]
    fn resolve_internal_peer_transport_rejects_missing_mtls_when_policy_requires_transport() {
        let mut config = test_config();
        config.cluster_auth_token = Some("shared-secret".to_string());
        config.cluster_peers = vec!["node-b.internal:9000".to_string()];
        config.cluster_peer_transport_mode = ClusterPeerTransportMode::Required;

        let err = resolve_internal_peer_transport_with_cluster_peer_presence(
            &config,
            config
                .cluster_peers
                .iter()
                .any(|peer| !peer.trim().is_empty()),
        )
        .expect_err("should fail closed");
        assert!(err.message.contains("requires mTLS identity"));
        assert!(err.message.contains("(not_configured)"));
    }

    #[test]
    fn resolve_internal_peer_transport_does_not_require_mtls_without_active_cluster_peers() {
        let mut config = test_config();
        config.cluster_auth_token = Some("shared-secret".to_string());
        config.cluster_peer_transport_mode = ClusterPeerTransportMode::Required;

        let resolved = resolve_internal_peer_transport_with_cluster_peer_presence(&config, false)
            .expect("transport should resolve");
        assert_eq!(resolved.scheme, "http");
        assert!(resolved.ca_path.is_none());
    }

    #[test]
    fn resolve_internal_peer_transport_rejects_missing_mtls_when_runtime_peers_exist() {
        let mut config = test_config();
        config.cluster_auth_token = Some("shared-secret".to_string());
        config.cluster_peer_transport_mode = ClusterPeerTransportMode::Required;

        let err = resolve_internal_peer_transport_with_cluster_peer_presence(&config, true)
            .expect_err("should fail closed");
        assert!(err.message.contains("requires mTLS identity"));
        assert!(err.message.contains("(not_configured)"));
    }

    #[test]
    fn resolve_internal_peer_transport_rejects_unready_mtls_configuration() {
        let mut config = test_config();
        config.cluster_peer_tls_cert_path = Some("/tmp/maxio-missing-cert.pem".to_string());
        config.cluster_peer_tls_key_path = Some("/tmp/maxio-missing-key.pem".to_string());
        config.cluster_peer_tls_ca_path = Some("/tmp/maxio-missing-ca.pem".to_string());

        let err = resolve_internal_peer_transport_with_cluster_peer_presence(
            &config,
            config
                .cluster_peers
                .iter()
                .any(|peer| !peer.trim().is_empty()),
        )
        .expect_err("should fail closed");
        assert!(err.message.contains("Internal peer transport is not ready"));
    }

    #[test]
    fn resolve_internal_peer_transport_rejects_invalid_pem_even_without_a_local_pin() {
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

        let err = resolve_internal_peer_transport_with_cluster_peer_presence(
            &config,
            config
                .cluster_peers
                .iter()
                .any(|peer| !peer.trim().is_empty()),
        )
        .expect_err("should fail closed");
        assert!(err.message.contains("Internal peer transport is not ready"));
        assert!(err.message.contains("certificate") || err.message.contains("private key"));
    }
}
