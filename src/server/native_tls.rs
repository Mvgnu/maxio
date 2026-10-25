//! Native listener TLS. Request identity is evidence from the accepted socket;
//! no HTTP header can create either of the connection extensions below.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::Request;
use axum::extract::connect_info::{ConnectInfo, Connected};
use axum::middleware::Next;
use axum::response::Response;
use axum::serve::{IncomingStream, Listener};
use openssl::asn1::Asn1Time;
use openssl::pkey::PKey;
use openssl::ssl::{Ssl, SslAcceptor, SslMethod, SslVerifyMode, SslVersion};
use openssl::x509::X509;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_openssl::SslStream;

use crate::cluster::transport_identity::{
    PeerCertificatePolicy, PeerTlsConfig, VerifiedPeerIdentity, build_peer_tls_acceptor,
    verified_peer_identity_from_tls,
};
use crate::config::Config;

use super::TlsConnection;

const MAX_PENDING_HANDSHAKES: usize = 64;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Validated once before storage initialization. Clones share the immutable
/// acceptor, while each listener has its own bounded pending handshakes.
#[derive(Clone)]
pub struct ServerTls {
    acceptor: Option<Arc<SslAcceptor>>,
    peer_tls: bool,
    revocations: Option<Arc<str>>,
}

impl ServerTls {
    /// Reuse the native verified HTTPS listener for optional upper-layer services.
    /// This constructor has no S3 configuration or peer identity dependency.
    pub fn standalone(cert_path: &str, key_path: &str) -> Result<Self, String> {
        Ok(Self {
            acceptor: Some(Arc::new(build_server_acceptor(cert_path, key_path)?)),
            peer_tls: false,
            revocations: None,
        })
    }

    pub fn from_config(config: &Config) -> Result<Self, String> {
        let peers = config.parsed_cluster_peers()?;
        let generic_configured = config.tls_cert_path.is_some() || config.tls_key_path.is_some();
        let peer = peer_tls_config(config)?;
        let peer_tls = peer.is_some();
        if generic_configured && peer.is_some() {
            return Err("standalone TLS certificate/key and cluster peer TLS triplet are mutually exclusive".into());
        }
        if generic_configured && !peers.is_empty() {
            return Err("standalone TLS cannot be used with cluster peers; use the cluster peer TLS certificate/key/CA triplet".into());
        }

        let acceptor = if let Some(peer) = peer {
            Some(build_peer_tls_acceptor(peer)?)
        } else if generic_configured {
            let cert = config
                .tls_cert_path
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let key = config
                .tls_key_path
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let (Some(cert), Some(key)) = (cert, key) else {
                return Err("native HTTPS requires both --tls-cert-path and --tls-key-path".into());
            };
            Some(build_server_acceptor(cert, key)?)
        } else {
            None
        };
        Ok(Self {
            acceptor: acceptor.map(Arc::new),
            peer_tls,
            revocations: config
                .cluster_peer_tls_cert_sha256_revocations()
                .map(Arc::from),
        })
    }

    pub fn scheme(&self) -> &'static str {
        if self.acceptor.is_some() {
            "https"
        } else {
            "http"
        }
    }
}

/// The same complete configuration is used for native inbound TLS and every
/// outbound target-bound client. This validation is intentionally independent
/// of whether peers happen to be configured at this instant.
pub(super) fn peer_tls_config(config: &Config) -> Result<Option<PeerTlsConfig<'_>>, String> {
    let configured = config.cluster_peer_tls_cert_path.is_some()
        || config.cluster_peer_tls_key_path.is_some()
        || config.cluster_peer_tls_ca_path.is_some()
        || config.cluster_peer_tls_cert_sha256.is_some()
        || config.cluster_peer_tls_cert_sha256_revocations.is_some();
    if config.cluster_peer_transport_required() && config.cluster_auth_token().is_none() {
        return Err("required peer transport needs a non-empty --cluster-auth-token".into());
    }
    if !configured {
        if config.cluster_peer_transport_required() {
            return Err("required peer transport requires ready peer transport identity (not_configured): configure the complete cluster peer TLS certificate/key/CA triplet".into());
        }
        return Ok(None);
    }
    let (Some(cert_path), Some(key_path), Some(ca_path)) = (
        config.cluster_peer_tls_cert_path(),
        config.cluster_peer_tls_key_path(),
        config.cluster_peer_tls_ca_path(),
    ) else {
        return Err("mTLS peer transport is not ready: configure all three cluster peer TLS certificate/key/CA paths".into());
    };
    if config.tls_cert_path.is_some() || config.tls_key_path.is_some() {
        return Err(
            "standalone TLS certificate/key and cluster peer TLS triplet are mutually exclusive"
                .into(),
        );
    }
    Ok(Some(PeerTlsConfig {
        node_id: config.node_id.as_str(),
        cert_path,
        key_path,
        ca_path,
        certificate_policy: PeerCertificatePolicy {
            sha256_pin: config.cluster_peer_tls_cert_sha256(),
            sha256_revocations: config.cluster_peer_tls_cert_sha256_revocations(),
        },
    }))
}

fn build_server_acceptor(cert_path: &str, key_path: &str) -> Result<SslAcceptor, String> {
    let build = || -> Result<SslAcceptor, Box<dyn std::error::Error>> {
        let pem = std::fs::read(cert_path)?;
        let certificates = X509::stack_from_pem(&pem)?;
        if certificates.is_empty() {
            return Err("certificate chain is empty".into());
        }
        let now = Asn1Time::days_from_now(0)?;
        for certificate in &certificates {
            if certificate.not_before() > now.as_ref() || certificate.not_after() < now.as_ref() {
                return Err(
                    "certificate chain contains an expired or not-yet-valid certificate".into(),
                );
            }
        }
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_certificate_chain_file(cert_path)?;
        let key_pem = std::fs::read(key_path)?;
        if String::from_utf8_lossy(&key_pem).contains("ENCRYPTED") {
            return Err("encrypted native HTTPS private keys are not supported".into());
        }
        let key = PKey::private_key_from_pem_passphrase(&key_pem, b"")?;
        builder.set_private_key(&key)?;
        builder.check_private_key()?;
        Ok(builder.build())
    };
    build().map_err(|error| format!("invalid native HTTPS certificate/key: {error}"))
}

#[derive(Clone, Debug)]
struct NativeConnectionInfo {
    address: SocketAddr,
    peer: Option<VerifiedPeerIdentity>,
}

struct TlsListener {
    listener: TcpListener,
    acceptor: Arc<SslAcceptor>,
    peer_tls: bool,
    require_peer: bool,
    revocations: Option<Arc<str>>,
    pending: JoinSet<Result<(SslStream<TcpStream>, NativeConnectionInfo), String>>,
}

impl Listener for TlsListener {
    type Io = SslStream<TcpStream>;
    type Addr = NativeConnectionInfo;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            tokio::select! {
                // Prefer completed handshakes so a busy accept queue cannot
                // starve requests whose TLS handshake has already succeeded.
                biased;
                Some(result) = self.pending.join_next(), if !self.pending.is_empty() => {
                    match result {
                        Ok(Ok(connection)) => return connection,
                        Ok(Err(error)) => tracing::debug!(%error, "Rejected TLS connection"),
                        Err(error) => tracing::warn!(%error, "TLS handshake task failed"),
                    }
                }
                accepted = self.listener.accept(), if self.pending.len() < MAX_PENDING_HANDSHAKES => {
                    let (stream, address) = match accepted {
                        Ok(connection) => connection,
                        Err(error) => {
                            tracing::warn!(%error, "TLS listener accept failed");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    };
                    let acceptor = self.acceptor.clone();
                    let require_peer = self.require_peer;
                    let peer_tls = self.peer_tls;
                    let revocations = self.revocations.clone();
                    self.pending.spawn(async move {
                        let mut ssl = Ssl::new(acceptor.context()).map_err(|e| e.to_string())?;
                        if require_peer {
                            ssl.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
                        }
                        let mut stream = SslStream::new(ssl, stream).map_err(|e| e.to_string())?;
                        tokio::time::timeout(HANDSHAKE_TIMEOUT, std::pin::Pin::new(&mut stream).accept())
                            .await
                            .map_err(|_| "TLS handshake timed out".to_string())?
                            .map_err(|e| e.to_string())?;
                        let peer = if peer_tls {
                            verified_peer_identity_from_tls(stream.ssl(), revocations.as_deref())?
                        } else {
                            None
                        };
                        if require_peer && peer.is_none() {
                            return Err("internal listener requires a verified peer certificate".into());
                        }
                        Ok((stream, NativeConnectionInfo { address, peer }))
                    });
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(NativeConnectionInfo {
            address: self.listener.local_addr()?,
            peer: None,
        })
    }
}

impl Connected<IncomingStream<'_, TlsListener>> for NativeConnectionInfo {
    fn connect_info(stream: IncomingStream<'_, TlsListener>) -> Self {
        stream.remote_addr().clone()
    }
}

async fn install_connection_metadata(mut request: Request, next: Next) -> Response {
    // Only this listener's private Connected implementation can install this
    // type. Keep SocketAddr available for console login throttling.
    if let Some(ConnectInfo(connection)) = request
        .extensions()
        .get::<ConnectInfo<NativeConnectionInfo>>()
        .cloned()
    {
        request.extensions_mut().insert(TlsConnection);
        request
            .extensions_mut()
            .insert(ConnectInfo(connection.address));
        if let Some(peer) = connection.peer {
            request.extensions_mut().insert(peer);
        }
    }
    next.run(request).await
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow_and_update() {
            return;
        }
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

/// Serve either HTTP or HTTPS through Axum's normal graceful connection drain.
/// Dropping a TLS listener also aborts all unfinished handshake tasks.
pub async fn serve_listener(
    listener: TcpListener,
    app: Router,
    tls: ServerTls,
    internal: bool,
    shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    if let Some(acceptor) = tls.acceptor {
        let listener = TlsListener {
            listener,
            acceptor,
            peer_tls: tls.peer_tls,
            require_peer: internal && tls.peer_tls,
            revocations: tls.revocations,
            pending: JoinSet::new(),
        };
        axum::serve(
            listener,
            app.layer(axum::middleware::from_fn(install_connection_metadata))
                .into_make_service_with_connect_info::<NativeConnectionInfo>(),
        )
        .with_graceful_shutdown(wait_for_shutdown(shutdown))
        .await
    } else {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(wait_for_shutdown(shutdown))
        .await
    }
}
