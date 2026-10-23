use super::PeerCertificatePolicy;
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use openssl::x509::{X509, X509NameBuilder};
use std::fs;
use std::sync::atomic::{AtomicU32, Ordering};
use tempfile::{TempDir, tempdir};

pub(super) struct TestCa {
    pub cert: X509,
    key: PKey<Private>,
    dir: TempDir,
    serial: AtomicU32,
}

pub(super) struct TestIdentity {
    pub node_id: String,
    pub cert_path: String,
    pub key_path: String,
    pub ca_path: String,
    pub cert: X509,
}

fn key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("P-256 group");
    PKey::from_ec_key(EcKey::generate(&group).expect("generate test key")).expect("test key")
}

fn serial(number: u32) -> Asn1Integer {
    BigNum::from_u32(number)
        .expect("serial number")
        .to_asn1_integer()
        .expect("ASN.1 serial")
}

impl TestCa {
    pub fn new() -> Self {
        let key = key();
        let mut name = X509NameBuilder::new().expect("CA name");
        name.append_entry_by_text("CN", "MaxIO test authority")
            .expect("CA common name");
        let name = name.build();
        let mut builder = X509::builder().expect("CA builder");
        builder.set_version(2).expect("CA version");
        builder.set_serial_number(&serial(1)).expect("CA serial");
        builder.set_subject_name(&name).expect("CA subject");
        builder.set_issuer_name(&name).expect("CA issuer");
        builder.set_pubkey(&key).expect("CA public key");
        builder
            .set_not_before(&Asn1Time::days_from_now(0).expect("CA not before"))
            .expect("CA not before");
        builder
            .set_not_after(&Asn1Time::days_from_now(7).expect("CA expiry"))
            .expect("CA expiry");
        builder
            .append_extension(
                BasicConstraints::new()
                    .critical()
                    .ca()
                    .build()
                    .expect("CA constraints"),
            )
            .expect("CA constraints");
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .expect("CA key usage"),
            )
            .expect("CA key usage");
        let subject_key = SubjectKeyIdentifier::new()
            .build(&builder.x509v3_context(None, None))
            .expect("CA subject key identifier");
        builder
            .append_extension(subject_key)
            .expect("CA subject key identifier");
        builder
            .sign(&key, MessageDigest::sha256())
            .expect("sign CA");
        let cert = builder.build();
        let dir = tempdir().expect("PKI directory");
        fs::write(dir.path().join("ca.pem"), cert.to_pem().expect("CA PEM"))
            .expect("write test CA");
        Self {
            cert,
            key,
            dir,
            serial: AtomicU32::new(2),
        }
    }

    pub fn issue(&self, node_id: &str) -> TestIdentity {
        self.issue_with_sans(node_id, &[format!("maxio://{node_id}")], None)
    }

    pub fn issue_with_sans(
        &self,
        node_id: &str,
        uris: &[String],
        hostname: Option<&str>,
    ) -> TestIdentity {
        self.issue_certificate(node_id, uris, hostname, false, true)
    }

    pub fn issue_expired(&self, node_id: &str) -> TestIdentity {
        self.issue_certificate(node_id, &[format!("maxio://{node_id}")], None, true, true)
    }

    pub fn issue_without_dns_ip_san(&self, node_id: &str) -> TestIdentity {
        self.issue_certificate(node_id, &[format!("maxio://{node_id}")], None, false, false)
    }

    fn issue_certificate(
        &self,
        node_id: &str,
        uris: &[String],
        hostname: Option<&str>,
        expired: bool,
        include_host_san: bool,
    ) -> TestIdentity {
        let key = key();
        let number = self.serial.fetch_add(1, Ordering::Relaxed);
        let (node_host, _) = crate::cluster::peer_identity::parse_peer_identity(node_id)
            .expect("test node identity");
        let mut name = X509NameBuilder::new().expect("peer name");
        name.append_entry_by_text("CN", &node_host)
            .expect("peer common name");
        let name = name.build();
        let mut builder = X509::builder().expect("peer builder");
        builder.set_version(2).expect("peer version");
        builder
            .set_serial_number(&serial(number))
            .expect("peer serial");
        builder.set_subject_name(&name).expect("peer subject");
        builder
            .set_issuer_name(self.cert.subject_name())
            .expect("peer issuer");
        builder.set_pubkey(&key).expect("peer public key");
        let (not_before, not_after) = if expired {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            (
                Asn1Time::from_unix(now - 3600).unwrap(),
                Asn1Time::from_unix(now - 60).unwrap(),
            )
        } else {
            (
                Asn1Time::days_from_now(0).unwrap(),
                Asn1Time::days_from_now(2).unwrap(),
            )
        };
        builder
            .set_not_before(&not_before)
            .expect("peer not before");
        builder.set_not_after(&not_after).expect("peer expiry");
        builder
            .append_extension(
                BasicConstraints::new()
                    .critical()
                    .build()
                    .expect("peer constraints"),
            )
            .expect("peer constraints");
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .digital_signature()
                    .build()
                    .expect("peer usage"),
            )
            .expect("peer usage");
        builder
            .append_extension(
                ExtendedKeyUsage::new()
                    .server_auth()
                    .client_auth()
                    .build()
                    .expect("peer EKU"),
            )
            .expect("peer EKU");
        let hostname = hostname.unwrap_or(&node_host);
        let mut san = SubjectAlternativeName::new();
        if include_host_san {
            if hostname.parse::<std::net::IpAddr>().is_ok() {
                san.ip(hostname);
            } else {
                san.dns(hostname);
            }
        }
        for uri in uris {
            san.uri(uri);
        }
        let san = san
            .build(&builder.x509v3_context(Some(&self.cert), None))
            .expect("peer SAN");
        builder.append_extension(san).expect("peer SAN");
        let authority_key = AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&builder.x509v3_context(Some(&self.cert), None))
            .expect("peer authority key identifier");
        builder
            .append_extension(authority_key)
            .expect("peer authority key identifier");
        builder
            .sign(&self.key, MessageDigest::sha256())
            .expect("sign peer");
        let cert = builder.build();
        let cert_path = self.dir.path().join(format!("peer-{number}.pem"));
        let key_path = self.dir.path().join(format!("peer-{number}.key"));
        fs::write(&cert_path, cert.to_pem().expect("peer PEM")).expect("write peer cert");
        fs::write(
            &key_path,
            key.private_key_to_pem_pkcs8().expect("peer private PEM"),
        )
        .expect("write peer key");
        TestIdentity {
            node_id: node_id.to_owned(),
            cert_path: cert_path.to_string_lossy().into_owned(),
            key_path: key_path.to_string_lossy().into_owned(),
            ca_path: self
                .dir
                .path()
                .join("ca.pem")
                .to_string_lossy()
                .into_owned(),
            cert,
        }
    }
}

impl TestIdentity {
    pub fn config(&self) -> super::PeerTlsConfig<'_> {
        super::PeerTlsConfig {
            node_id: &self.node_id,
            cert_path: &self.cert_path,
            key_path: &self.key_path,
            ca_path: &self.ca_path,
            certificate_policy: self.policy(),
        }
    }

    pub fn policy(&self) -> PeerCertificatePolicy<'_> {
        PeerCertificatePolicy {
            sha256_pin: None,
            sha256_revocations: None,
        }
    }

    pub fn fingerprint(&self) -> String {
        super::peer_certificate_sha256_hex(&self.cert).expect("test leaf fingerprint")
    }
}
