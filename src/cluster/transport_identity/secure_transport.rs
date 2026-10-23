//! Native peer TLS. Identity restrictions run on the connection carrying the
//! request, in addition to the TLS library's chain and handshake verification.

use super::{
    PeerCertificatePolicy, certificate_node_identity, contains_encrypted_private_key_pem,
    ensure_certificate_valid_now, normalize_path, normalize_sha256_fingerprint_set,
    peer_certificate_sha256_hex, peer_node_identity_uri,
};
use foreign_types::ForeignTypeRef;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{SslAcceptor, SslMethod, SslRef, SslVerifyMode, SslVersion};
use openssl::stack::Stack;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::verify::{X509CheckFlags, X509VerifyParam};
use openssl::x509::{X509, X509PurposeId, X509Ref, X509StoreContext, X509VerifyResult};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::{PemObject, SectionKind};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::fs;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
pub struct PeerTlsConfig<'a> {
    pub node_id: &'a str,
    pub cert_path: &'a str,
    pub key_path: &'a str,
    pub ca_path: &'a str,
    pub certificate_policy: PeerCertificatePolicy<'a>,
}

/// This value is derived from a completed, verified TLS connection. Request
/// headers and arbitrary strings cannot construct a trusted peer principal.
#[derive(Clone, Debug)]
pub struct VerifiedPeerIdentity {
    node_id: String,
}

impl VerifiedPeerIdentity {
    pub fn node_id(&self) -> &str {
        &self.node_id
    }
}

struct PeerTlsMaterial {
    certificates: Vec<X509>,
    key: PKey<Private>,
    authorities: Vec<X509>,
    revocations: Vec<String>,
}

impl PeerTlsMaterial {
    fn load(config: PeerTlsConfig<'_>) -> Result<Self, String> {
        let expected_uri = peer_node_identity_uri(config.node_id)?;
        let certificates = read_certificates(config.cert_path, "peer certificate")?;
        let certificate = &certificates[0];
        ensure_certificate_valid_now(certificate)?;
        if format!("maxio://{}", certificate_node_identity(certificate)?) != expected_uri {
            return Err(
                "local peer certificate URI does not match configured node identity".to_owned(),
            );
        }
        let key_bytes = fs::read(config.key_path)
            .map_err(|error| format!("cannot read peer private key: {error}"))?;
        if contains_encrypted_private_key_pem(&key_bytes) {
            return Err("encrypted peer private keys are not supported".to_owned());
        }
        // An explicit empty passphrase prevents OpenSSL's default interactive
        // password callback from blocking startup on encrypted key material.
        let key = PKey::private_key_from_pem_passphrase(&key_bytes, b"")
            .map_err(|error| format!("invalid or encrypted peer private key: {error}"))?;
        if !certificate
            .public_key()
            .map_err(|error| error.to_string())?
            .public_eq(&key)
        {
            return Err("peer certificate does not match its private key".to_owned());
        }
        let authorities = read_certificates(config.ca_path, "peer CA bundle")?;
        let revocations =
            fingerprint_set(config.certificate_policy.sha256_revocations, "revocation")?;
        let fingerprint = peer_certificate_sha256_hex(certificate)?;
        reject_revoked(&fingerprint, &revocations)?;
        let pins = fingerprint_set(config.certificate_policy.sha256_pin, "local pin")?;
        if !pins.is_empty() && !pins.contains(&fingerprint) {
            return Err(
                "local peer certificate does not match configured fingerprint pin".to_owned(),
            );
        }
        let material = Self {
            certificates,
            key,
            authorities,
            revocations,
        };
        // A node uses this identity as both TLS server and TLS client. Validate
        // the configured chain and usages at startup, before opening listeners.
        material.verify_local_chain(config.node_id, X509PurposeId::SSL_SERVER)?;
        material.verify_local_chain(config.node_id, X509PurposeId::SSL_CLIENT)?;
        Ok(material)
    }

    fn trust_store(&self) -> Result<X509Store, String> {
        let mut builder = X509StoreBuilder::new().map_err(|error| error.to_string())?;
        for authority in &self.authorities {
            builder
                .add_cert(authority.clone())
                .map_err(|error| error.to_string())?;
        }
        // No default system paths or public roots are added to this store.
        Ok(builder.build())
    }

    fn verify_local_chain(&self, node_id: &str, purpose: X509PurposeId) -> Result<(), String> {
        let mut store = X509StoreBuilder::new().map_err(|error| error.to_string())?;
        for authority in &self.authorities {
            store
                .add_cert(authority.clone())
                .map_err(|error| error.to_string())?;
        }
        let (host, _) = crate::cluster::peer_identity::parse_peer_identity(node_id)
            .ok_or_else(|| "invalid local node identity".to_owned())?;
        let mut parameters = X509VerifyParam::new().map_err(|error| error.to_string())?;
        parameters
            .set_purpose(purpose)
            .map_err(|error| error.to_string())?;
        parameters.set_hostflags(X509CheckFlags::NEVER_CHECK_SUBJECT);
        if let Ok(ip) = host.parse::<IpAddr>() {
            parameters.set_ip(ip).map_err(|error| error.to_string())?;
        } else {
            parameters
                .set_host(&host)
                .map_err(|error| error.to_string())?;
        }
        store
            .set_param(&parameters)
            .map_err(|error| error.to_string())?;
        let store = store.build();
        let mut chain = Stack::new().map_err(|error| error.to_string())?;
        for certificate in self.certificates.iter().skip(1) {
            chain
                .push(certificate.clone())
                .map_err(|error| error.to_string())?;
        }
        let mut context = X509StoreContext::new().map_err(|error| error.to_string())?;
        let (verified, reason) = context
            .init(&store, &self.certificates[0], &chain, |context| {
                let verified = context.verify_cert()?;
                Ok((verified, context.error()))
            })
            .map_err(|error| error.to_string())?;
        if !verified {
            return Err(format!(
                "local peer certificate chain, usage or DNS/IP SAN is invalid: {reason}"
            ));
        }
        Ok(())
    }
}

fn read_certificates(path: &str, label: &str) -> Result<Vec<X509>, String> {
    let bytes = fs::read(path).map_err(|error| format!("cannot read {label}: {error}"))?;
    if String::from_utf8_lossy(&bytes).lines().any(|line| {
        let line = line.trim();
        line.starts_with("-----BEGIN ") && line.ends_with("PRIVATE KEY-----")
    }) {
        return Err(format!("{label} must not contain private key material"));
    }
    let certificates = <(SectionKind, Vec<u8>)>::pem_slice_iter(&bytes)
        .map(|section| {
            let (kind, der) = section.map_err(|error| format!("invalid {label}: {error}"))?;
            if kind != SectionKind::Certificate {
                return Err(format!(
                    "{label} must contain only certificate PEM sections"
                ));
            }
            X509::from_der(&der).map_err(|error| format!("invalid {label}: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        return Err(format!("{label} contains no certificates"));
    }
    Ok(certificates)
}

fn fingerprint_set(value: Option<&str>, label: &str) -> Result<Vec<String>, String> {
    match normalize_path(value) {
        None => Ok(Vec::new()),
        Some(value) => normalize_sha256_fingerprint_set(value)
            .ok_or_else(|| format!("invalid peer certificate {label} fingerprint set")),
    }
}

fn reject_revoked(fingerprint: &str, revocations: &[String]) -> Result<(), String> {
    if revocations.iter().any(|revoked| revoked == fingerprint) {
        return Err("peer certificate fingerprint is revoked".to_owned());
    }
    Ok(())
}

// The TLS handshake already verifies the chain, usages and key possession.
// This additional name-only check binds the URI's host to a normal DNS/IP SAN.
fn verify_node_identity_host_san(certificate: &X509Ref, node_id: &str) -> Result<(), String> {
    let (host, _) = crate::cluster::peer_identity::parse_peer_identity(node_id)
        .ok_or_else(|| "peer certificate URI contains an invalid node host".to_owned())?;
    let check_ip = |octets: &[u8]| {
        // SAFETY: certificate is a live borrowed X509. The slice stays live for
        // the call and contains exactly 4 or 16 network-order bytes from IpAddr.
        // OpenSSL only reads these buffers and retains neither pointer.
        unsafe {
            openssl_sys::X509_check_ip(certificate.as_ptr(), octets.as_ptr(), octets.len(), 0)
        }
    };
    let result = match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => check_ip(&ip.octets()),
        Ok(IpAddr::V6(ip)) => check_ip(&ip.octets()),
        Err(_) => {
            // SAFETY: certificate and host remain live for the call. The parsed
            // host is nonempty ASCII without NULs; its explicit byte length is
            // passed, so no terminator is needed. A null peername requests no
            // allocated output. OpenSSL retains neither input pointer.
            unsafe {
                openssl_sys::X509_check_host(
                    certificate.as_ptr(),
                    host.as_ptr().cast(),
                    host.len(),
                    openssl_sys::X509_CHECK_FLAG_NEVER_CHECK_SUBJECT,
                    std::ptr::null_mut(),
                )
            }
        }
    };
    match result {
        1 => Ok(()),
        0 => Err(format!(
            "peer certificate DNS/IP SAN does not match node URI host {host}"
        )),
        result => Err(format!(
            "peer certificate DNS/IP SAN validation failed for node URI host {host} (OpenSSL result {result})"
        )),
    }
}

/// Build the native node listener. Public S3/console clients may omit a client
/// certificate; any supplied certificate must verify. Runtime requires a
/// VerifiedPeerIdentity for internal requests and may require certificates at
/// handshake on its dedicated internal listener.
pub fn build_peer_tls_acceptor(config: PeerTlsConfig<'_>) -> Result<SslAcceptor, String> {
    let material = PeerTlsMaterial::load(config)?;
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
        .map_err(|error| error.to_string())?;
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|error| error.to_string())?;
    builder.set_verify(SslVerifyMode::PEER);
    builder
        .set_verify_cert_store(material.trust_store()?)
        .map_err(|error| error.to_string())?;
    builder
        .set_certificate(&material.certificates[0])
        .map_err(|error| error.to_string())?;
    builder
        .set_private_key(&material.key)
        .map_err(|error| error.to_string())?;
    for certificate in material.certificates.iter().skip(1) {
        builder
            .add_extra_chain_cert(certificate.clone())
            .map_err(|error| error.to_string())?;
    }
    builder
        .check_private_key()
        .map_err(|error| error.to_string())?;
    Ok(builder.build())
}

/// Extract identity only after the actual TLS handshake has verified possession
/// of the certified key. This does not grant membership: runtime still checks
/// the allowlist, local-node exclusion, forwarding last hop and join claims.
pub fn verified_peer_identity_from_tls(
    ssl: &SslRef,
    sha256_revocations: Option<&str>,
) -> Result<Option<VerifiedPeerIdentity>, String> {
    if !ssl.is_init_finished() {
        return Err("peer TLS handshake has not completed".to_owned());
    }
    if !ssl.verify_mode().contains(SslVerifyMode::PEER) {
        return Err("peer TLS connection did not enable certificate verification".to_owned());
    }
    if ssl.verify_result() != X509VerifyResult::OK {
        return Err(format!(
            "peer TLS certificate verification failed: {}",
            ssl.verify_result()
        ));
    }
    let revocations = fingerprint_set(sha256_revocations, "revocation")?;
    let Some(certificate) = ssl.peer_certificate() else {
        return Ok(None);
    };
    ensure_certificate_valid_now(&certificate)?;
    reject_revoked(&peer_certificate_sha256_hex(&certificate)?, &revocations)?;
    let node_id = certificate_node_identity(&certificate)?;
    verify_node_identity_host_san(&certificate, &node_id)?;
    Ok(Some(VerifiedPeerIdentity { node_id }))
}

#[derive(Debug)]
struct ExpectedPeerVerifier {
    standard: Arc<WebPkiServerVerifier>,
    expected_node_id: String,
    revocations: Vec<String>,
}

impl ServerCertVerifier for ExpectedPeerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verified = self.standard.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let certificate = X509::from_der(end_entity.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        let identity = certificate_node_identity(&certificate).map_err(rustls::Error::General)?;
        if identity != self.expected_node_id {
            return Err(rustls::Error::General(
                "peer certificate URI does not match destination node identity".to_owned(),
            ));
        }
        let fingerprint =
            peer_certificate_sha256_hex(&certificate).map_err(rustls::Error::General)?;
        reject_revoked(&fingerprint, &self.revocations).map_err(rustls::Error::General)?;
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.standard.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.standard.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.standard.supported_verify_schemes()
    }
}

/// Build a client for exactly one node identity. A different port on the same
/// hostname is a different identity and requires a different client.
pub fn build_peer_mtls_http_client(
    config: PeerTlsConfig<'_>,
    expected_peer_node_id: &str,
    connect_timeout: Option<Duration>,
    timeout: Duration,
) -> Result<reqwest::Client, String> {
    let expected_uri = peer_node_identity_uri(expected_peer_node_id)?;
    let expected_node_id = expected_uri.trim_start_matches("maxio://").to_owned();
    let material = PeerTlsMaterial::load(config)?;
    let mut roots = RootCertStore::empty();
    for authority in &material.authorities {
        roots
            .add(CertificateDer::from(
                authority.to_der().map_err(|error| error.to_string())?,
            ))
            .map_err(|error| error.to_string())?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let standard = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|error| error.to_string())?;
    let verifier = Arc::new(ExpectedPeerVerifier {
        standard,
        expected_node_id,
        revocations: material.revocations,
    });
    let certificates = material
        .certificates
        .iter()
        .map(|cert| {
            cert.to_der()
                .map(CertificateDer::from)
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        material
            .key
            .private_key_to_pkcs8()
            .map_err(|error| error.to_string())?,
    ));
    let tls = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(certificates, key)
        .map_err(|error| error.to_string())?;
    let mut client = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(timeout);
    if let Some(timeout) = connect_timeout {
        client = client.connect_timeout(timeout);
    }
    client.build().map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests;
