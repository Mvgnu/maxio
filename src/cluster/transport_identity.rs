use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::fs;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::net::TcpStream;
use std::net::ToSocketAddrs;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTransportIdentityMode {
    None,
    MtlsPath,
}

impl PeerTransportIdentityMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::MtlsPath => "mtls-path",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTransportIdentityReadinessReason {
    NotConfigured,
    IncompleteConfiguration,
    CertificatePathUnreadable,
    CertificatePemInvalid,
    KeyPathUnreadable,
    KeyPemInvalid,
    KeyPemEncryptedUnsupported,
    TrustStorePathUnreadable,
    TrustStorePemInvalid,
    TrustStoreContainsPrivateKeyPem,
    CertificateValidityWindowInvalid,
    CertificateFingerprintPinInvalid,
    CertificateFingerprintPinMismatch,
    CertificateFingerprintRevocationInvalid,
    CertificateFingerprintRevoked,
    CertificateKeyPairInvalid,
    NodeIdentityInvalid,
    NodeIdentityBindingPinRequired,
    NodeIdentityCertificateMismatch,
    Ready,
}

impl PeerTransportIdentityReadinessReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::IncompleteConfiguration => "incomplete_configuration",
            Self::CertificatePathUnreadable => "certificate_path_unreadable",
            Self::CertificatePemInvalid => "certificate_pem_invalid",
            Self::KeyPathUnreadable => "key_path_unreadable",
            Self::KeyPemInvalid => "key_pem_invalid",
            Self::KeyPemEncryptedUnsupported => "key_pem_encrypted_unsupported",
            Self::TrustStorePathUnreadable => "trust_store_path_unreadable",
            Self::TrustStorePemInvalid => "trust_store_pem_invalid",
            Self::TrustStoreContainsPrivateKeyPem => "trust_store_contains_private_key_pem",
            Self::CertificateValidityWindowInvalid => "certificate_validity_window_invalid",
            Self::CertificateFingerprintPinInvalid => "certificate_fingerprint_pin_invalid",
            Self::CertificateFingerprintPinMismatch => "certificate_fingerprint_pin_mismatch",
            Self::CertificateFingerprintRevocationInvalid => {
                "certificate_fingerprint_revocation_invalid"
            }
            Self::CertificateFingerprintRevoked => "certificate_fingerprint_revoked",
            Self::CertificateKeyPairInvalid => "certificate_key_pair_invalid",
            Self::NodeIdentityInvalid => "node_identity_invalid",
            Self::NodeIdentityBindingPinRequired => "node_identity_binding_pin_required",
            Self::NodeIdentityCertificateMismatch => "node_identity_certificate_mismatch",
            Self::Ready => "ready",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerTransportIdentityStatus {
    pub mode: PeerTransportIdentityMode,
    pub transport_ready: bool,
    pub identity_bound: bool,
    pub reason: PeerTransportIdentityReadinessReason,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTransportEnforcementMode {
    Compatibility,
    StrictMtlsIdentityBound,
}

impl PeerTransportEnforcementMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Compatibility => "compatibility",
            Self::StrictMtlsIdentityBound => "strict_mtls_identity_bound",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerTransportEnforcementAssessment {
    pub mode: PeerTransportEnforcementMode,
    pub ready: bool,
    pub reason: PeerTransportIdentityReadinessReason,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerTransportPolicyAssessment {
    pub required: bool,
    pub enforcement: PeerTransportEnforcementAssessment,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerTransportPolicyDiagnostics {
    pub required: bool,
    pub ready: bool,
    pub enforcement_mode: PeerTransportEnforcementMode,
    pub enforcement_ready: bool,
    pub effective_reason: PeerTransportIdentityReadinessReason,
    pub reject_reason: Option<PeerTransportIdentityReadinessReason>,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterPeerAuthProductionReadinessReason {
    NotRequiredStandalone,
    ClusterAuthTokenNotConfigured,
    SenderAllowlistNotBound,
    TransportPolicyNotRequired,
    TransportNotReady,
    IdentityNotBound,
    Ready,
}

impl ClusterPeerAuthProductionReadinessReason {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotRequiredStandalone => "not-required-standalone",
            Self::ClusterAuthTokenNotConfigured => "cluster-auth-token-not-configured",
            Self::SenderAllowlistNotBound => "sender-allowlist-not-bound",
            Self::TransportPolicyNotRequired => "transport-policy-not-required",
            Self::TransportNotReady => "transport-not-ready",
            Self::IdentityNotBound => "identity-not-bound",
            Self::Ready => "ready",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClusterPeerAuthProductionReadinessAssessment {
    pub ready: bool,
    pub reason: ClusterPeerAuthProductionReadinessReason,
}

impl PeerTransportPolicyAssessment {
    pub const fn is_ready(&self) -> bool {
        !self.required || self.enforcement.ready
    }

    pub const fn gap(&self) -> Option<PeerTransportIdentityReadinessReason> {
        if self.is_ready() {
            None
        } else {
            Some(self.enforcement.reason)
        }
    }
}

pub const fn peer_transport_policy_effective_reason(
    assessment: &PeerTransportPolicyAssessment,
) -> PeerTransportIdentityReadinessReason {
    if assessment.required {
        match assessment.gap() {
            Some(reason) => reason,
            None => PeerTransportIdentityReadinessReason::Ready,
        }
    } else {
        assessment.enforcement.reason
    }
}

pub const fn peer_transport_policy_reject_reason(
    assessment: &PeerTransportPolicyAssessment,
) -> Option<PeerTransportIdentityReadinessReason> {
    assessment.gap()
}

pub fn peer_transport_policy_diagnostics(
    assessment: &PeerTransportPolicyAssessment,
) -> PeerTransportPolicyDiagnostics {
    PeerTransportPolicyDiagnostics {
        required: assessment.required,
        ready: assessment.is_ready(),
        enforcement_mode: assessment.enforcement.mode,
        enforcement_ready: assessment.enforcement.ready,
        effective_reason: peer_transport_policy_effective_reason(assessment),
        reject_reason: peer_transport_policy_reject_reason(assessment),
        warning: assessment.enforcement.warning.clone(),
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerCertificatePolicy<'a> {
    pub sha256_pin: Option<&'a str>,
    pub sha256_revocations: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTransportPeerAttestationError {
    InvalidPeerEndpoint,
    InvalidExpectedNodeIdentity,
    CertificatePathUnreadable,
    CertificatePemInvalid,
    KeyPathUnreadable,
    KeyPemInvalid,
    KeyPemEncryptedUnsupported,
    TrustStorePathUnreadable,
    TrustStorePemInvalid,
    TrustStoreContainsPrivateKeyPem,
    CertificateValidityWindowInvalid,
    PeerConnectFailed,
    TlsHandshakeFailed,
    PeerCertificateMissing,
    PeerCertificateValidityWindowInvalid,
    PeerCertificateFingerprintPinInvalid,
    PeerCertificateFingerprintPinMismatch,
    PeerCertificateFingerprintRevocationInvalid,
    PeerCertificateFingerprintRevoked,
    PeerCertificateNodeIdentityMismatch,
}

impl PeerTransportPeerAttestationError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidPeerEndpoint => "invalid_peer_endpoint",
            Self::InvalidExpectedNodeIdentity => "invalid_expected_node_identity",
            Self::CertificatePathUnreadable => "certificate_path_unreadable",
            Self::CertificatePemInvalid => "certificate_pem_invalid",
            Self::KeyPathUnreadable => "key_path_unreadable",
            Self::KeyPemInvalid => "key_pem_invalid",
            Self::KeyPemEncryptedUnsupported => "key_pem_encrypted_unsupported",
            Self::TrustStorePathUnreadable => "trust_store_path_unreadable",
            Self::TrustStorePemInvalid => "trust_store_pem_invalid",
            Self::TrustStoreContainsPrivateKeyPem => "trust_store_contains_private_key_pem",
            Self::CertificateValidityWindowInvalid => "certificate_validity_window_invalid",
            Self::PeerConnectFailed => "peer_connect_failed",
            Self::TlsHandshakeFailed => "tls_handshake_failed",
            Self::PeerCertificateMissing => "peer_certificate_missing",
            Self::PeerCertificateValidityWindowInvalid => {
                "peer_certificate_validity_window_invalid"
            }
            Self::PeerCertificateFingerprintPinInvalid => {
                "peer_certificate_fingerprint_pin_invalid"
            }
            Self::PeerCertificateFingerprintPinMismatch => {
                "peer_certificate_fingerprint_pin_mismatch"
            }
            Self::PeerCertificateFingerprintRevocationInvalid => {
                "peer_certificate_fingerprint_revocation_invalid"
            }
            Self::PeerCertificateFingerprintRevoked => "peer_certificate_fingerprint_revoked",
            Self::PeerCertificateNodeIdentityMismatch => "peer_certificate_node_identity_mismatch",
        }
    }
}

pub fn probe_peer_transport_identity(
    cert_path: Option<&str>,
    key_path: Option<&str>,
    trust_store_path: Option<&str>,
) -> PeerTransportIdentityStatus {
    probe_peer_transport_identity_with_cert_sha256_pin(cert_path, key_path, trust_store_path, None)
}

pub fn probe_peer_transport_identity_with_cert_sha256_pin(
    cert_path: Option<&str>,
    key_path: Option<&str>,
    trust_store_path: Option<&str>,
    cert_sha256_pin: Option<&str>,
) -> PeerTransportIdentityStatus {
    probe_peer_transport_identity_with_cert_sha256_pin_and_revocations(
        cert_path,
        key_path,
        trust_store_path,
        cert_sha256_pin,
        None,
    )
}

pub fn probe_peer_transport_identity_with_cert_sha256_pin_and_revocations(
    cert_path: Option<&str>,
    key_path: Option<&str>,
    trust_store_path: Option<&str>,
    cert_sha256_pin: Option<&str>,
    cert_sha256_revocations: Option<&str>,
) -> PeerTransportIdentityStatus {
    let cert_path = normalize_path(cert_path);
    let key_path = normalize_path(key_path);
    let trust_store_path = normalize_path(trust_store_path);

    if cert_path.is_none() && key_path.is_none() && trust_store_path.is_none() {
        return PeerTransportIdentityStatus {
            mode: PeerTransportIdentityMode::None,
            transport_ready: false,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::NotConfigured,
            warning: None,
        };
    }

    if cert_path.is_none() || key_path.is_none() || trust_store_path.is_none() {
        let mut missing_fields = Vec::new();
        if cert_path.is_none() {
            missing_fields.push("cert_path");
        }
        if key_path.is_none() {
            missing_fields.push("key_path");
        }
        if trust_store_path.is_none() {
            missing_fields.push("trust_store_path");
        }
        return PeerTransportIdentityStatus {
            mode: PeerTransportIdentityMode::MtlsPath,
            transport_ready: false,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::IncompleteConfiguration,
            warning: Some(format!(
                "mTLS peer transport identity configuration is incomplete; missing {}.",
                missing_fields.join(", ")
            )),
        };
    }

    let cert_path = cert_path.unwrap_or_default();
    let cert_bytes = match fs::read(cert_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            return PeerTransportIdentityStatus {
                mode: PeerTransportIdentityMode::MtlsPath,
                transport_ready: false,
                identity_bound: false,
                reason: PeerTransportIdentityReadinessReason::CertificatePathUnreadable,
                warning: Some(format!(
                    "mTLS certificate path '{}' is not readable: {}.",
                    cert_path, err
                )),
            };
        }
    };
    let cert = match X509::from_pem(cert_bytes.as_slice()) {
        Ok(cert) => cert,
        Err(_) => {
            return PeerTransportIdentityStatus {
                mode: PeerTransportIdentityMode::MtlsPath,
                transport_ready: false,
                identity_bound: false,
                reason: PeerTransportIdentityReadinessReason::CertificatePemInvalid,
                warning: Some(format!(
                    "mTLS certificate path '{}' does not contain a parseable PEM certificate.",
                    cert_path
                )),
            };
        }
    };
    if let Err(error) = ensure_certificate_valid_now(&cert) {
        return PeerTransportIdentityStatus {
            mode: PeerTransportIdentityMode::MtlsPath,
            transport_ready: false,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::CertificateValidityWindowInvalid,
            warning: Some(format!(
                "mTLS certificate path '{}' has an invalid validity window for current time: {}.",
                cert_path, error
            )),
        };
    }
    if !contains_valid_pem_block(&cert_bytes, "CERTIFICATE") {
        return PeerTransportIdentityStatus {
            mode: PeerTransportIdentityMode::MtlsPath,
            transport_ready: false,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::CertificatePemInvalid,
            warning: Some(format!(
                "mTLS certificate path '{}' does not contain a valid PEM certificate block.",
                cert_path
            )),
        };
    }

    let key_path = key_path.unwrap_or_default();
    let key_bytes = match fs::read(key_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            return PeerTransportIdentityStatus {
                mode: PeerTransportIdentityMode::MtlsPath,
                transport_ready: false,
                identity_bound: false,
                reason: PeerTransportIdentityReadinessReason::KeyPathUnreadable,
                warning: Some(format!(
                    "mTLS private key path '{}' is not readable: {}.",
                    key_path, err
                )),
            };
        }
    };
    if contains_valid_pem_block(&key_bytes, "ENCRYPTED PRIVATE KEY") {
        return PeerTransportIdentityStatus {
            mode: PeerTransportIdentityMode::MtlsPath,
            transport_ready: false,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::KeyPemEncryptedUnsupported,
            warning: Some(format!(
                "mTLS private key path '{}' contains an encrypted private key block; encrypted key PEM is not supported by runtime transport readiness checks.",
                key_path
            )),
        };
    }
    if !contains_valid_private_key_pem_block(&key_bytes) {
        return PeerTransportIdentityStatus {
            mode: PeerTransportIdentityMode::MtlsPath,
            transport_ready: false,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::KeyPemInvalid,
            warning: Some(format!(
                "mTLS private key path '{}' does not contain a valid PEM private key block.",
                key_path
            )),
        };
    }

    let trust_store_path = trust_store_path.unwrap_or_default();
    let trust_store_bytes = match fs::read(trust_store_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            return PeerTransportIdentityStatus {
                mode: PeerTransportIdentityMode::MtlsPath,
                transport_ready: false,
                identity_bound: false,
                reason: PeerTransportIdentityReadinessReason::TrustStorePathUnreadable,
                warning: Some(format!(
                    "mTLS trust store path '{}' is not readable: {}.",
                    trust_store_path, err
                )),
            };
        }
    };
    if count_valid_pem_blocks(&trust_store_bytes, "CERTIFICATE") == 0 {
        return PeerTransportIdentityStatus {
            mode: PeerTransportIdentityMode::MtlsPath,
            transport_ready: false,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::TrustStorePemInvalid,
            warning: Some(format!(
                "mTLS trust store path '{}' does not contain a valid PEM certificate block.",
                trust_store_path
            )),
        };
    }
    if contains_any_private_key_pem_block(&trust_store_bytes) {
        return PeerTransportIdentityStatus {
            mode: PeerTransportIdentityMode::MtlsPath,
            transport_ready: false,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::TrustStoreContainsPrivateKeyPem,
            warning: Some(format!(
                "mTLS trust store path '{}' contains private key PEM blocks; trust stores must only contain CA certificates.",
                trust_store_path
            )),
        };
    }

    let Some(observed_cert_fingerprint) =
        first_valid_pem_block_sha256_hex(&cert_bytes, "CERTIFICATE")
    else {
        return PeerTransportIdentityStatus {
            mode: PeerTransportIdentityMode::MtlsPath,
            transport_ready: false,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::CertificatePemInvalid,
            warning: Some(format!(
                "mTLS certificate path '{}' does not contain a decodable PEM certificate block.",
                cert_path
            )),
        };
    };

    if let Some(cert_sha256_revocations) = normalize_path(cert_sha256_revocations) {
        let Some(normalized_revocations) =
            normalize_sha256_fingerprint_set(cert_sha256_revocations)
        else {
            return PeerTransportIdentityStatus {
                mode: PeerTransportIdentityMode::MtlsPath,
                transport_ready: false,
                identity_bound: false,
                reason: PeerTransportIdentityReadinessReason::CertificateFingerprintRevocationInvalid,
                warning: Some(
                    "mTLS certificate fingerprint revocation set is invalid; expected one or more comma-separated SHA-256 fingerprints (64 hex chars each), optionally prefixed with sha256: and separated by ':' or '-'.".to_string(),
                ),
            };
        };
        if normalized_revocations
            .iter()
            .any(|pin| pin == &observed_cert_fingerprint)
        {
            return PeerTransportIdentityStatus {
                mode: PeerTransportIdentityMode::MtlsPath,
                transport_ready: false,
                identity_bound: false,
                reason: PeerTransportIdentityReadinessReason::CertificateFingerprintRevoked,
                warning: Some(format!(
                    "mTLS certificate fingerprint for '{}' is explicitly revoked.",
                    cert_path
                )),
            };
        }
    }

    if let Some(cert_sha256_pin) = normalize_path(cert_sha256_pin) {
        let Some(normalized_pins) = normalize_sha256_fingerprint_set(cert_sha256_pin) else {
            return PeerTransportIdentityStatus {
                mode: PeerTransportIdentityMode::MtlsPath,
                transport_ready: false,
                identity_bound: false,
                reason: PeerTransportIdentityReadinessReason::CertificateFingerprintPinInvalid,
                warning: Some(
                    "mTLS certificate fingerprint pin is invalid; expected one or more comma-separated SHA-256 fingerprints (64 hex chars each), optionally prefixed with sha256: and separated by ':' or '-'.".to_string(),
                ),
            };
        };
        if !normalized_pins
            .iter()
            .any(|pin| pin == &observed_cert_fingerprint)
        {
            return PeerTransportIdentityStatus {
                mode: PeerTransportIdentityMode::MtlsPath,
                transport_ready: false,
                identity_bound: false,
                reason: PeerTransportIdentityReadinessReason::CertificateFingerprintPinMismatch,
                warning: Some(format!(
                    "mTLS certificate fingerprint mismatch: configured pin does not match certificate at '{}'.",
                    cert_path
                )),
            };
        }
        if let Err(error) = validate_certificate_private_key_pair(&cert_bytes, &key_bytes) {
            return PeerTransportIdentityStatus {
                mode: PeerTransportIdentityMode::MtlsPath,
                transport_ready: false,
                identity_bound: false,
                reason: PeerTransportIdentityReadinessReason::CertificateKeyPairInvalid,
                warning: Some(format!(
                    "mTLS certificate/private-key identity material is not parseable as a PKCS#8 pair for '{}': {}.",
                    cert_path, error
                )),
            };
        }
        return PeerTransportIdentityStatus {
            mode: PeerTransportIdentityMode::MtlsPath,
            transport_ready: true,
            identity_bound: true,
            reason: PeerTransportIdentityReadinessReason::Ready,
            warning: None,
        };
    }

    PeerTransportIdentityStatus {
        mode: PeerTransportIdentityMode::MtlsPath,
        transport_ready: true,
        identity_bound: false,
        reason: PeerTransportIdentityReadinessReason::Ready,
        warning: Some(
            "mTLS transport files are configured/readable, but certificate fingerprint pinning is not configured; cryptographic peer identity binding is not enforced yet."
                .to_string(),
        ),
    }
}

pub fn assess_peer_transport_enforcement(
    status: &PeerTransportIdentityStatus,
    mode: PeerTransportEnforcementMode,
) -> PeerTransportEnforcementAssessment {
    match mode {
        PeerTransportEnforcementMode::Compatibility => {
            if status.mode == PeerTransportIdentityMode::None {
                return PeerTransportEnforcementAssessment {
                    mode,
                    ready: true,
                    reason: PeerTransportIdentityReadinessReason::NotConfigured,
                    warning: Some(
                        "peer transport identity is not configured; compatibility mode permits non-identity-bound internal transport.".to_string(),
                    ),
                };
            }

            PeerTransportEnforcementAssessment {
                mode,
                ready: status.transport_ready,
                reason: status.reason,
                warning: status.warning.clone(),
            }
        }
        PeerTransportEnforcementMode::StrictMtlsIdentityBound => {
            if status.mode == PeerTransportIdentityMode::None {
                return PeerTransportEnforcementAssessment {
                    mode,
                    ready: false,
                    reason: PeerTransportIdentityReadinessReason::NotConfigured,
                    warning: Some(
                        "strict mTLS identity-bound enforcement requires peer transport certificate, key, and trust-store configuration.".to_string(),
                    ),
                };
            }

            if !status.transport_ready {
                return PeerTransportEnforcementAssessment {
                    mode,
                    ready: false,
                    reason: status.reason,
                    warning: status.warning.clone(),
                };
            }

            if !status.identity_bound {
                let reason = if status.reason == PeerTransportIdentityReadinessReason::Ready {
                    PeerTransportIdentityReadinessReason::NodeIdentityBindingPinRequired
                } else {
                    status.reason
                };
                return PeerTransportEnforcementAssessment {
                    mode,
                    ready: false,
                    reason,
                    warning: Some(
                        "strict mTLS identity-bound enforcement requires certificate fingerprint pinning and node-identity certificate binding."
                            .to_string(),
                    ),
                };
            }

            PeerTransportEnforcementAssessment {
                mode,
                ready: true,
                reason: PeerTransportIdentityReadinessReason::Ready,
                warning: None,
            }
        }
    }
}

pub fn assess_peer_transport_policy(
    status: &PeerTransportIdentityStatus,
    mode: PeerTransportEnforcementMode,
) -> PeerTransportPolicyAssessment {
    let enforcement = assess_peer_transport_enforcement(status, mode);
    let required = match mode {
        PeerTransportEnforcementMode::StrictMtlsIdentityBound => true,
        PeerTransportEnforcementMode::Compatibility => {
            status.mode == PeerTransportIdentityMode::MtlsPath
        }
    };
    PeerTransportPolicyAssessment {
        required,
        enforcement,
    }
}

pub fn assess_peer_transport_policy_with_context(
    status: &PeerTransportIdentityStatus,
    mode: PeerTransportEnforcementMode,
    is_distributed: bool,
    auth_configured: bool,
    has_cluster_peers: bool,
) -> PeerTransportPolicyAssessment {
    let mut assessment = assess_peer_transport_policy(status, mode);
    if !is_distributed || !auth_configured || !has_cluster_peers {
        assessment.required = false;
    }
    assessment
}

pub const fn assess_cluster_peer_auth_production_readiness(
    is_distributed: bool,
    cluster_auth_configured: bool,
    cluster_auth_sender_allowlist_bound: bool,
    transport_policy: &PeerTransportPolicyAssessment,
    cluster_auth_identity_bound: bool,
) -> ClusterPeerAuthProductionReadinessAssessment {
    let reason = if !is_distributed {
        ClusterPeerAuthProductionReadinessReason::NotRequiredStandalone
    } else if !cluster_auth_configured {
        ClusterPeerAuthProductionReadinessReason::ClusterAuthTokenNotConfigured
    } else if !cluster_auth_sender_allowlist_bound {
        ClusterPeerAuthProductionReadinessReason::SenderAllowlistNotBound
    } else if !transport_policy.required {
        ClusterPeerAuthProductionReadinessReason::TransportPolicyNotRequired
    } else if !transport_policy.is_ready() {
        ClusterPeerAuthProductionReadinessReason::TransportNotReady
    } else if !cluster_auth_identity_bound {
        ClusterPeerAuthProductionReadinessReason::IdentityNotBound
    } else {
        ClusterPeerAuthProductionReadinessReason::Ready
    };

    ClusterPeerAuthProductionReadinessAssessment {
        ready: matches!(reason, ClusterPeerAuthProductionReadinessReason::Ready),
        reason,
    }
}

pub fn probe_peer_transport_identity_with_cert_sha256_pin_and_node_id_binding(
    cert_path: Option<&str>,
    key_path: Option<&str>,
    trust_store_path: Option<&str>,
    cert_sha256_pin: Option<&str>,
    expected_node_id: Option<&str>,
) -> PeerTransportIdentityStatus {
    probe_peer_transport_identity_with_certificate_policy_and_node_id_binding(
        cert_path,
        key_path,
        trust_store_path,
        PeerCertificatePolicy {
            sha256_pin: cert_sha256_pin,
            sha256_revocations: None,
        },
        expected_node_id,
    )
}

pub fn probe_peer_transport_identity_with_certificate_policy_and_node_id_binding(
    cert_path: Option<&str>,
    key_path: Option<&str>,
    trust_store_path: Option<&str>,
    certificate_policy: PeerCertificatePolicy<'_>,
    expected_node_id: Option<&str>,
) -> PeerTransportIdentityStatus {
    let mut status = probe_peer_transport_identity_with_cert_sha256_pin_and_revocations(
        cert_path,
        key_path,
        trust_store_path,
        certificate_policy.sha256_pin,
        certificate_policy.sha256_revocations,
    );

    let Some(expected_node_id) = normalize_path(expected_node_id) else {
        return status;
    };
    if !status.transport_ready {
        return status;
    }
    let Some(expected_node_host) = normalize_peer_node_host(expected_node_id) else {
        return PeerTransportIdentityStatus {
            mode: status.mode,
            transport_ready: false,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::NodeIdentityInvalid,
            warning: Some(format!(
                "mTLS node-identity binding cannot parse host from node id '{}'.",
                expected_node_id
            )),
        };
    };

    if !status.identity_bound {
        return PeerTransportIdentityStatus {
            mode: status.mode,
            transport_ready: false,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::NodeIdentityBindingPinRequired,
            warning: Some(format!(
                "mTLS node-identity binding for '{}' requires a certificate fingerprint pin.",
                expected_node_id
            )),
        };
    }

    let Some(cert_path) = normalize_path(cert_path) else {
        return PeerTransportIdentityStatus {
            mode: status.mode,
            transport_ready: false,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::NodeIdentityCertificateMismatch,
            warning: Some(
                "mTLS node-identity binding requires a readable certificate path.".to_string(),
            ),
        };
    };
    let cert_bytes = match fs::read(cert_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return PeerTransportIdentityStatus {
                mode: status.mode,
                transport_ready: false,
                identity_bound: false,
                reason: PeerTransportIdentityReadinessReason::NodeIdentityCertificateMismatch,
                warning: Some(format!(
                    "mTLS node-identity binding could not read certificate '{}': {}.",
                    cert_path, error
                )),
            };
        }
    };
    let matches = match certificate_matches_expected_node_host(
        cert_bytes.as_slice(),
        expected_node_host.as_str(),
    ) {
        Ok(matches) => matches,
        Err(error) => {
            return PeerTransportIdentityStatus {
                mode: status.mode,
                transport_ready: false,
                identity_bound: false,
                reason: PeerTransportIdentityReadinessReason::NodeIdentityCertificateMismatch,
                warning: Some(format!(
                    "mTLS node-identity binding failed to parse certificate identity from '{}': {}.",
                    cert_path, error
                )),
            };
        }
    };

    if !matches {
        return PeerTransportIdentityStatus {
            mode: status.mode,
            transport_ready: false,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::NodeIdentityCertificateMismatch,
            warning: Some(format!(
                "mTLS node-identity binding mismatch: certificate identity at '{}' does not match expected node host '{}'.",
                cert_path, expected_node_host
            )),
        };
    }

    status.warning = None;
    status
}

pub fn attest_peer_transport_identity_with_mtls(
    peer_endpoint: &str,
    expected_node_id: &str,
    cert_path: &str,
    key_path: &str,
    trust_store_path: &str,
    timeout: Duration,
) -> Result<(), PeerTransportPeerAttestationError> {
    attest_peer_transport_identity_with_mtls_and_cert_sha256_pin(
        peer_endpoint,
        expected_node_id,
        cert_path,
        key_path,
        trust_store_path,
        None,
        timeout,
    )
}

pub fn attest_peer_transport_identity_with_mtls_and_cert_sha256_pin(
    peer_endpoint: &str,
    expected_node_id: &str,
    cert_path: &str,
    key_path: &str,
    trust_store_path: &str,
    peer_cert_sha256_pin: Option<&str>,
    timeout: Duration,
) -> Result<(), PeerTransportPeerAttestationError> {
    attest_peer_transport_identity_with_mtls_with_policy(
        peer_endpoint,
        expected_node_id,
        cert_path,
        key_path,
        trust_store_path,
        PeerCertificatePolicy {
            sha256_pin: peer_cert_sha256_pin,
            sha256_revocations: None,
        },
        timeout,
    )
}

pub fn attest_peer_transport_identity_with_mtls_with_policy(
    peer_endpoint: &str,
    expected_node_id: &str,
    cert_path: &str,
    key_path: &str,
    trust_store_path: &str,
    peer_certificate_policy: PeerCertificatePolicy<'_>,
    timeout: Duration,
) -> Result<(), PeerTransportPeerAttestationError> {
    let Some((peer_host, peer_port)) =
        crate::cluster::peer_identity::parse_peer_identity(peer_endpoint)
    else {
        return Err(PeerTransportPeerAttestationError::InvalidPeerEndpoint);
    };
    let Some(expected_node_host) = normalize_peer_node_host(expected_node_id) else {
        return Err(PeerTransportPeerAttestationError::InvalidExpectedNodeIdentity);
    };

    let cert_bytes = fs::read(cert_path)
        .map_err(|_| PeerTransportPeerAttestationError::CertificatePathUnreadable)?;
    let cert = X509::from_pem(cert_bytes.as_slice())
        .map_err(|_| PeerTransportPeerAttestationError::CertificatePemInvalid)?;
    ensure_certificate_valid_now(&cert)
        .map_err(|_| PeerTransportPeerAttestationError::CertificateValidityWindowInvalid)?;

    let key_bytes =
        fs::read(key_path).map_err(|_| PeerTransportPeerAttestationError::KeyPathUnreadable)?;
    if contains_valid_pem_block(key_bytes.as_slice(), "ENCRYPTED PRIVATE KEY") {
        return Err(PeerTransportPeerAttestationError::KeyPemEncryptedUnsupported);
    }
    let key = PKey::private_key_from_pem(key_bytes.as_slice())
        .map_err(|_| PeerTransportPeerAttestationError::KeyPemInvalid)?;

    let trust_store_bytes = fs::read(trust_store_path)
        .map_err(|_| PeerTransportPeerAttestationError::TrustStorePathUnreadable)?;
    if trust_store_bytes.is_empty() {
        return Err(PeerTransportPeerAttestationError::TrustStorePemInvalid);
    }
    if contains_any_private_key_pem_block(trust_store_bytes.as_slice()) {
        return Err(PeerTransportPeerAttestationError::TrustStoreContainsPrivateKeyPem);
    }

    let mut builder = SslConnector::builder(SslMethod::tls_client())
        .map_err(|_| PeerTransportPeerAttestationError::TlsHandshakeFailed)?;
    builder.set_verify(SslVerifyMode::PEER);
    builder
        .set_ca_file(trust_store_path)
        .map_err(|_| PeerTransportPeerAttestationError::TrustStorePemInvalid)?;
    builder
        .set_certificate(&cert)
        .map_err(|_| PeerTransportPeerAttestationError::CertificatePemInvalid)?;
    builder
        .set_private_key(&key)
        .map_err(|_| PeerTransportPeerAttestationError::KeyPemInvalid)?;
    builder
        .check_private_key()
        .map_err(|_| PeerTransportPeerAttestationError::KeyPemInvalid)?;
    let connector = builder.build();

    let peer_port = peer_port.unwrap_or(443);
    let connect_target = socket_target(peer_host.as_str(), peer_port);
    let stream = connect_tcp_with_timeout(connect_target.as_str(), timeout)
        .map_err(|_| PeerTransportPeerAttestationError::PeerConnectFailed)?;

    let mut config = connector
        .configure()
        .map_err(|_| PeerTransportPeerAttestationError::TlsHandshakeFailed)?;
    config.set_verify_hostname(false);
    let tls_stream = config
        .connect(peer_host.as_str(), stream)
        .map_err(|_| PeerTransportPeerAttestationError::TlsHandshakeFailed)?;

    let peer_certificate = tls_stream
        .ssl()
        .peer_certificate()
        .ok_or(PeerTransportPeerAttestationError::PeerCertificateMissing)?;
    ensure_certificate_valid_now(&peer_certificate)
        .map_err(|_| PeerTransportPeerAttestationError::PeerCertificateValidityWindowInvalid)?;

    if let Some(peer_cert_sha256_revocations) =
        normalize_path(peer_certificate_policy.sha256_revocations)
    {
        let Some(normalized_revocations) =
            normalize_sha256_fingerprint_set(peer_cert_sha256_revocations)
        else {
            return Err(
                PeerTransportPeerAttestationError::PeerCertificateFingerprintRevocationInvalid,
            );
        };
        let observed_peer_cert_fingerprint = peer_certificate_sha256_hex(&peer_certificate)
            .map_err(|_| {
                PeerTransportPeerAttestationError::PeerCertificateFingerprintPinMismatch
            })?;
        if normalized_revocations
            .iter()
            .any(|pin| pin == &observed_peer_cert_fingerprint)
        {
            return Err(PeerTransportPeerAttestationError::PeerCertificateFingerprintRevoked);
        }
    }

    if let Some(peer_cert_sha256_pin) = normalize_path(peer_certificate_policy.sha256_pin) {
        let Some(normalized_pins) = normalize_sha256_fingerprint_set(peer_cert_sha256_pin) else {
            return Err(PeerTransportPeerAttestationError::PeerCertificateFingerprintPinInvalid);
        };
        let observed_peer_cert_fingerprint = peer_certificate_sha256_hex(&peer_certificate)
            .map_err(|_| {
                PeerTransportPeerAttestationError::PeerCertificateFingerprintPinMismatch
            })?;
        if !normalized_pins
            .iter()
            .any(|pin| pin == &observed_peer_cert_fingerprint)
        {
            return Err(PeerTransportPeerAttestationError::PeerCertificateFingerprintPinMismatch);
        }
    }

    let matches = certificate_matches_expected_node_host_in_x509(
        &peer_certificate,
        expected_node_host.as_str(),
    )
    .map_err(|_| PeerTransportPeerAttestationError::PeerCertificateNodeIdentityMismatch)?;
    if !matches {
        return Err(PeerTransportPeerAttestationError::PeerCertificateNodeIdentityMismatch);
    }

    Ok(())
}

fn connect_tcp_with_timeout(target: &str, timeout: Duration) -> std::io::Result<TcpStream> {
    let timeout = if timeout.is_zero() {
        Duration::from_millis(1)
    } else {
        timeout
    };

    let mut last_error = None;
    for socket_addr in target.to_socket_addrs()? {
        match TcpStream::connect_timeout(&socket_addr, timeout) {
            Ok(stream) => {
                let _ = stream.set_read_timeout(Some(timeout));
                let _ = stream.set_write_timeout(Some(timeout));
                return Ok(stream);
            }
            Err(err) => {
                last_error = Some(err);
            }
        }
    }

    Err(last_error
        .unwrap_or_else(|| std::io::Error::new(ErrorKind::AddrNotAvailable, "no socket address")))
}

fn socket_target(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn normalize_path(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn peer_certificate_sha256_hex(peer_certificate: &X509) -> Result<String, String> {
    let peer_der = peer_certificate
        .to_der()
        .map_err(|error| error.to_string())?;
    let digest = Sha256::digest(peer_der.as_slice());
    Ok(hex::encode(digest))
}

fn normalize_peer_node_host(node_id: &str) -> Option<String> {
    let (host, _) = crate::cluster::peer_identity::parse_peer_identity(node_id)?;
    Some(host.trim_end_matches('.').to_ascii_lowercase())
}

fn certificate_matches_expected_node_host(
    cert_pem_bytes: &[u8],
    expected_node_host: &str,
) -> Result<bool, String> {
    let cert_der = first_valid_pem_block_der_bytes(cert_pem_bytes, "CERTIFICATE")
        .ok_or_else(|| "no decodable certificate PEM block found".to_string())?;
    let cert = X509::from_der(cert_der.as_slice()).map_err(|error| error.to_string())?;
    certificate_matches_expected_node_host_in_x509(&cert, expected_node_host)
}

fn certificate_matches_expected_node_host_in_x509(
    cert: &X509,
    expected_node_host: &str,
) -> Result<bool, String> {
    let expected_node_host = expected_node_host
        .trim_end_matches('.')
        .to_ascii_lowercase();

    if expected_node_host.is_empty() {
        return Ok(false);
    }

    if let Ok(expected_ip) = expected_node_host.parse::<IpAddr>() {
        if let Some(alt_names) = cert.subject_alt_names() {
            for alt_name in alt_names {
                if let Some(ip_address) = alt_name.ipaddress()
                    && ip_address_matches(expected_ip, ip_address)
                {
                    return Ok(true);
                }
            }
        }
        return Ok(false);
    }

    let mut has_dns_san_entries = false;
    if let Some(alt_names) = cert.subject_alt_names() {
        for alt_name in alt_names {
            if let Some(dns_name) = alt_name.dnsname() {
                has_dns_san_entries = true;
                if dns_name_matches(dns_name, expected_node_host.as_str()) {
                    return Ok(true);
                }
            }
        }
    }
    if has_dns_san_entries {
        return Ok(false);
    }

    for entry in cert.subject_name().entries_by_nid(Nid::COMMONNAME) {
        let cn = entry
            .data()
            .as_utf8()
            .map_err(|error| error.to_string())?
            .to_string();
        if dns_name_matches(cn.as_str(), expected_node_host.as_str()) {
            return Ok(true);
        }
    }

    Ok(false)
}

fn ip_address_matches(expected: IpAddr, candidate: &[u8]) -> bool {
    match expected {
        IpAddr::V4(ipv4) => candidate == ipv4.octets().as_slice(),
        IpAddr::V6(ipv6) => candidate == ipv6.octets().as_slice(),
    }
}

fn dns_name_matches(candidate: &str, expected: &str) -> bool {
    let candidate = candidate.trim().trim_end_matches('.').to_ascii_lowercase();
    if candidate.is_empty() {
        return false;
    }
    // Wildcard certificate identities are intentionally rejected to preserve
    // strict per-node cryptographic binding.
    candidate == expected
}

fn contains_valid_pem_block(data: &[u8], label: &str) -> bool {
    count_valid_pem_blocks(data, label) > 0
}

fn contains_valid_private_key_pem_block(data: &[u8]) -> bool {
    const PRIVATE_KEY_LABELS: [&str; 3] = ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"];

    PRIVATE_KEY_LABELS
        .iter()
        .any(|label| contains_valid_pem_block(data, label))
}

fn contains_any_private_key_pem_block(data: &[u8]) -> bool {
    const PRIVATE_KEY_LABELS: [&str; 4] = [
        "PRIVATE KEY",
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
    ];

    PRIVATE_KEY_LABELS
        .iter()
        .any(|label| contains_valid_pem_block(data, label))
}

fn count_valid_pem_blocks(data: &[u8], label: &str) -> usize {
    let text = match std::str::from_utf8(data) {
        Ok(text) => text,
        Err(_) => return 0,
    };

    let begin_marker = format!("-----BEGIN {label}-----");
    let end_marker = format!("-----END {label}-----");
    let mut cursor = 0usize;
    let mut count = 0usize;

    while let Some(begin_rel) = text[cursor..].find(begin_marker.as_str()) {
        let begin = cursor + begin_rel + begin_marker.len();
        let rest = &text[begin..];
        let Some(end_rel) = rest.find(end_marker.as_str()) else {
            return 0;
        };
        let end = begin + end_rel;
        let payload = &text[begin..end];
        if !pem_payload_is_valid_base64(payload) {
            return 0;
        }
        count = count.saturating_add(1);
        cursor = end + end_marker.len();
    }

    count
}

fn first_valid_pem_block_der_bytes(data: &[u8], label: &str) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(data).ok()?;
    let begin_marker = format!("-----BEGIN {label}-----");
    let end_marker = format!("-----END {label}-----");
    let begin_rel = text.find(begin_marker.as_str())?;
    let begin = begin_rel + begin_marker.len();
    let rest = &text[begin..];
    let end_rel = rest.find(end_marker.as_str())?;
    let end = begin + end_rel;
    let payload = &text[begin..end];

    decode_pem_payload(payload)
}

fn first_valid_pem_block_sha256_hex(data: &[u8], label: &str) -> Option<String> {
    let der = first_valid_pem_block_der_bytes(data, label)?;
    let digest = Sha256::digest(der.as_slice());
    Some(hex::encode(digest))
}

fn decode_pem_payload(payload: &str) -> Option<Vec<u8>> {
    let mut encoded = String::new();
    for line in payload.lines().map(str::trim) {
        if line.is_empty() || line.contains(':') {
            continue;
        }
        encoded.push_str(line);
    }

    if encoded.is_empty() {
        return None;
    }

    BASE64_STANDARD.decode(encoded.as_bytes()).ok()
}

fn normalize_sha256_fingerprint(value: &str) -> Option<String> {
    let mut normalized = value.trim().to_ascii_lowercase();
    if let Some(rest) = normalized.strip_prefix("sha256:") {
        normalized = rest.to_string();
    }
    normalized = normalized
        .chars()
        .filter(|ch| !matches!(ch, ':' | '-' | ' '))
        .collect();
    if normalized.len() != 64 || !normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    Some(normalized)
}

fn normalize_sha256_fingerprint_set(value: &str) -> Option<Vec<String>> {
    let mut normalized = Vec::new();
    for token in value.split(',') {
        let pin = normalize_sha256_fingerprint(token)?;
        if !normalized.iter().any(|existing| existing == &pin) {
            normalized.push(pin);
        }
    }
    if normalized.is_empty() {
        return None;
    }
    Some(normalized)
}

fn pem_payload_is_valid_base64(payload: &str) -> bool {
    decode_pem_payload(payload).is_some()
}

fn validate_certificate_private_key_pair(
    cert_bytes: &[u8],
    key_bytes: &[u8],
) -> Result<(), String> {
    reqwest::Identity::from_pkcs8_pem(cert_bytes, key_bytes)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn ensure_certificate_valid_now(cert: &X509) -> Result<(), String> {
    let now = Asn1Time::days_from_now(0).map_err(|error| error.to_string())?;
    ensure_certificate_valid_at_reference(cert, now.as_ref())
}

fn ensure_certificate_valid_at_reference(
    cert: &X509,
    reference: &Asn1TimeRef,
) -> Result<(), String> {
    let not_before_cmp = cert
        .not_before()
        .compare(reference)
        .map_err(|error| error.to_string())?;
    if not_before_cmp == Ordering::Greater {
        return Err("certificate is not yet valid".to_string());
    }
    let not_after_cmp = cert
        .not_after()
        .compare(reference)
        .map_err(|error| error.to_string())?;
    if not_after_cmp == Ordering::Less {
        return Err("certificate has expired".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ClusterPeerAuthProductionReadinessReason, PeerCertificatePolicy,
        PeerTransportEnforcementMode, PeerTransportIdentityMode,
        PeerTransportIdentityReadinessReason, PeerTransportIdentityStatus,
        PeerTransportPeerAttestationError, assess_cluster_peer_auth_production_readiness,
        assess_peer_transport_enforcement, assess_peer_transport_policy,
        assess_peer_transport_policy_with_context, attest_peer_transport_identity_with_mtls,
        attest_peer_transport_identity_with_mtls_and_cert_sha256_pin,
        attest_peer_transport_identity_with_mtls_with_policy,
        ensure_certificate_valid_at_reference, peer_transport_policy_diagnostics,
        peer_transport_policy_effective_reason, peer_transport_policy_reject_reason,
        probe_peer_transport_identity, probe_peer_transport_identity_with_cert_sha256_pin,
        probe_peer_transport_identity_with_cert_sha256_pin_and_node_id_binding,
        probe_peer_transport_identity_with_cert_sha256_pin_and_revocations,
        probe_peer_transport_identity_with_certificate_policy_and_node_id_binding,
    };
    use openssl::asn1::Asn1Time;
    use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
    use openssl::x509::X509;
    use std::fs;
    use std::io::Write;
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;
    use tempfile::tempdir;

    fn write_valid_fixture(dir: &tempfile::TempDir) -> (String, String, String) {
        let (cert_path, key_path, trust_store_path, _) = write_valid_identity_fixture(dir);
        (cert_path, key_path, trust_store_path)
    }

    fn write_valid_identity_fixture(dir: &tempfile::TempDir) -> (String, String, String, String) {
        let cert_path = dir.path().join("peer.crt");
        let key_path = dir.path().join("peer.key");
        let trust_store_path = dir.path().join("ca.pem");
        let cert_pem_raw = "-----BEGIN CERTIFICATE-----\n\
                        MIIDKDCCAhCgAwIBAgIUSQnaqIrYDWiCpyUekIzvcQ4BPZwwDQYJKoZIhvcNAQEL\n\
                        BQAwFTETMBEGA1UEAwwKbWF4aW8tcGVlcjAeFw0yNjAzMDQxNTQyMzdaFw0zNjAz\n\
                        MDExNTQyMzdaMBUxEzARBgNVBAMMCm1heGlvLXBlZXIwggEiMA0GCSqGSIb3DQEB\n\
                        AQUAA4IBDwAwggEKAoIBAQDjI1gmjkZivK7EEVdJokcPHPrW9MdiQqvVdRkA9i8q\n\
                        BeCWeo9TW/il4EKddPeergUh6NTpNBVeBQZZKjGIUbJAMQqaNrFnCksC1XoCTL+2\n\
                        CCfdDjY3SRQR7wvCznWSLBskJyPqDswttb+CU1XDydXTda43O2fdGdjkiXAtXwPa\n\
                        cA1Gj/izc+eumExGVWLNy+EghnKqaEUMudp0PEQXGzwFiNbOMHoL98qIBHONP1U1\n\
                        xu+WUbgf4NPUEj6j2YY8p/cP7F2ibeY+dgdGMHjWYB9Ybp8ZI9jsr11GaL+7Qoxh\n\
                        nD3ZKHhSsTgES1haTiT1b/Don/b6gwztsAAgzgCiGhs9AgMBAAGjcDBuMB0GA1Ud\n\
                        DgQWBBSaCWCIhdoL7L27bd8T6GAEID2tSTAfBgNVHSMEGDAWgBSaCWCIhdoL7L27\n\
                        bd8T6GAEID2tSTAPBgNVHRMBAf8EBTADAQH/MBsGA1UdEQQUMBKCCm1heGlvLXBl\n\
                        ZXKHBH8AAAEwDQYJKoZIhvcNAQELBQADggEBAHYxBWftqrZHKRVvzFyHRwX9vXh8\n\
                        uAlC1T5zR599gjP78Zq1KZWfHPw9UQdmhpjgl8kkDIvBp7QHfbT35eHegv/wLhQW\n\
                        RbqS1CWpKNLeyDR93BHLl4mTan7M8fIGfwecCLvf/pbjL4gcO1BYcxC0o+3sn0CC\n\
                        MuMFGbzFcasZ05jhk9cHsU7YfH3V60oTfn8VUSVUD7IIaSc/TmAMNWNoJbvVy7Xf\n\
                        gtwaVdL8f4WDaLdUrO1RvSAhECW7mSdSRqDu99WH4ON3hh31BfU2cogIQ6hA1n07\n\
                        wbJcBbcynFXmQPDYiafFrVFEmC5EOuCyyNExf2kYibSefxtPWM57/g7sG6g=\n\
                        -----END CERTIFICATE-----\n";
        let key_pem_raw = "-----BEGIN PRIVATE KEY-----\n\
                       MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDjI1gmjkZivK7E\n\
                       EVdJokcPHPrW9MdiQqvVdRkA9i8qBeCWeo9TW/il4EKddPeergUh6NTpNBVeBQZZ\n\
                       KjGIUbJAMQqaNrFnCksC1XoCTL+2CCfdDjY3SRQR7wvCznWSLBskJyPqDswttb+C\n\
                       U1XDydXTda43O2fdGdjkiXAtXwPacA1Gj/izc+eumExGVWLNy+EghnKqaEUMudp0\n\
                       PEQXGzwFiNbOMHoL98qIBHONP1U1xu+WUbgf4NPUEj6j2YY8p/cP7F2ibeY+dgdG\n\
                       MHjWYB9Ybp8ZI9jsr11GaL+7QoxhnD3ZKHhSsTgES1haTiT1b/Don/b6gwztsAAg\n\
                       zgCiGhs9AgMBAAECggEAKm8zPArHEBG/lc5GkDFi1Ko9m7Sh3lPl3exxRip4H8H2\n\
                       1i4iAjkTwEugLmIIk+rfdxkUU9gg6M6IA9b754OZyV/QIwT2SjGUV3xx/aWAiH3I\n\
                       Esahrtz2hK4z9IpVUUBvtqagUU0/7IdAttSiWIBn9AhPiq6MxjQavwGFRVizs9Zy\n\
                       rR8WtLcTseYq9Jicjp7hj03ResLeSektvLl0jcA4HZZdPdezbMNHrG6QJdu3Zk0T\n\
                       ic3uTRmQsAs8LUTy8Vk4BQifqrOXSB1m6Y1l7cuBkkr7mmhk4sliU9wH2jVZlHmO\n\
                       bwda43GDqnUIaWiq+PQb9nxzNPTSxDpQXguzTiu3OQKBgQDz65orCSVtSRViZ8pQ\n\
                       PtTmUHZO9hisdofN0hSWK1RSmNAxkubSbScQrJdMDPFIwDuSntoGCFH4UFYdL8qh\n\
                       ThRupxQfAwpHy9KIic55EpCWnLgq/hJkk3TiGV8/kvEpKSjvkx3mykmj9rFIXnFn\n\
                       HXDgEojbHqLhQoH0iJQ5OATRaQKBgQDuYvpy3lDqdPHfmlaBR8xekbSjLBAjJx0n\n\
                       PzTEgNQyYliFh6BWGocDk5cAUfAHEyd0YwcEUd1SUKwi3VXxTGPSdm6sOrLA0pBH\n\
                       ixQ5gAFfZAFPAByeaF8AO7vOEYijSHFSQ+8V+OfPBBxAs8CBx/qHxI4TKweliexK\n\
                       eEVK0pQstQKBgF24b+MLP5svEo1d7clJawoXbm3GdxKE9IcrqgdNHLgjyRLTK+c8\n\
                       U18/wV5SNr9KRVl/uavJtJ0hWQUb4NJ7qrQddEi6JVASy5D0yiWQ8Yc9LjIuryh/\n\
                       09AwCX3m2syC6RysPTf5D7R1TAbPaulA0ab22CjBK7o7kK1BcRpPIOLJAoGAIMx7\n\
                       evx9k5Sdhs9cYZM4Wjaf7OduHPgPucunffXfvELtvQmJFO+3bdWLrB6Z8M9A2XGa\n\
                       kIyW7/Frjax4W6fQADANUCMPXxpZgY5wLO0gwzgmOfFg/qaLk6OkVljxPM4F0XTJ\n\
                       W3OQqVn+bSSOMw0Juk5f4eFEvxD38tMTbZUFkBUCgYAo2Hjmt46jJsKvOW6nqBGW\n\
                       RZTxRHHUWdzDfsSogg50dRvx6JFp5Y5DlQ5A0qgHoyaKZ+tMxvlQ9UoTGWRimRJn\n\
                       ti3O/aSCL8f19MvfdFLPB8dMqmZ//+CCdRv5IxB1SQNZXLwlS7eY0RGDqO6ai3L0\n\
                       2LC+Q4XHvuze/HVPrw/QRQ==\n\
                       -----END PRIVATE KEY-----\n";
        let cert_pem = cert_pem_raw
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let key_pem = key_pem_raw
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";

        fs::write(&cert_path, cert_pem.as_bytes()).expect("write cert");
        fs::write(&key_path, key_pem.as_bytes()).expect("write key");
        fs::write(&trust_store_path, cert_pem.as_bytes()).expect("write ca");

        let cert_bytes = fs::read(&cert_path).expect("read cert");
        let cert_sha256_pin = super::first_valid_pem_block_sha256_hex(&cert_bytes, "CERTIFICATE")
            .expect("cert fingerprint should parse");

        (
            cert_path.to_string_lossy().to_string(),
            key_path.to_string_lossy().to_string(),
            trust_store_path.to_string_lossy().to_string(),
            cert_sha256_pin,
        )
    }

    #[test]
    fn transport_enforcement_compatibility_allows_unconfigured_identity() {
        let status = PeerTransportIdentityStatus {
            mode: PeerTransportIdentityMode::None,
            transport_ready: false,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::NotConfigured,
            warning: None,
        };

        let assessment =
            assess_peer_transport_enforcement(&status, PeerTransportEnforcementMode::Compatibility);
        assert!(assessment.ready);
        assert_eq!(
            assessment.reason,
            PeerTransportIdentityReadinessReason::NotConfigured
        );
        assert!(assessment.warning.is_some());
    }

    #[test]
    fn transport_enforcement_strict_rejects_unconfigured_identity() {
        let status = PeerTransportIdentityStatus {
            mode: PeerTransportIdentityMode::None,
            transport_ready: false,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::NotConfigured,
            warning: None,
        };

        let assessment = assess_peer_transport_enforcement(
            &status,
            PeerTransportEnforcementMode::StrictMtlsIdentityBound,
        );
        assert!(!assessment.ready);
        assert_eq!(
            assessment.reason,
            PeerTransportIdentityReadinessReason::NotConfigured
        );
        assert!(assessment.warning.is_some());
    }

    #[test]
    fn transport_enforcement_strict_requires_identity_binding_when_transport_is_ready() {
        let status = PeerTransportIdentityStatus {
            mode: PeerTransportIdentityMode::MtlsPath,
            transport_ready: true,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::Ready,
            warning: Some("pin not configured".to_string()),
        };

        let assessment = assess_peer_transport_enforcement(
            &status,
            PeerTransportEnforcementMode::StrictMtlsIdentityBound,
        );
        assert!(!assessment.ready);
        assert_eq!(
            assessment.reason,
            PeerTransportIdentityReadinessReason::NodeIdentityBindingPinRequired
        );
        assert!(assessment.warning.is_some());
    }

    #[test]
    fn transport_enforcement_strict_accepts_identity_bound_ready_status() {
        let status = PeerTransportIdentityStatus {
            mode: PeerTransportIdentityMode::MtlsPath,
            transport_ready: true,
            identity_bound: true,
            reason: PeerTransportIdentityReadinessReason::Ready,
            warning: None,
        };

        let assessment = assess_peer_transport_enforcement(
            &status,
            PeerTransportEnforcementMode::StrictMtlsIdentityBound,
        );
        assert!(assessment.ready);
        assert_eq!(
            assessment.reason,
            PeerTransportIdentityReadinessReason::Ready
        );
        assert!(assessment.warning.is_none());
    }

    #[test]
    fn transport_policy_assessment_compatibility_none_is_not_required() {
        let status = PeerTransportIdentityStatus {
            mode: PeerTransportIdentityMode::None,
            transport_ready: false,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::NotConfigured,
            warning: None,
        };

        let assessment =
            assess_peer_transport_policy(&status, PeerTransportEnforcementMode::Compatibility);
        assert!(!assessment.required);
        assert!(assessment.is_ready());
        assert_eq!(assessment.gap(), None);
        assert!(assessment.enforcement.ready);
        assert_eq!(
            assessment.enforcement.reason,
            PeerTransportIdentityReadinessReason::NotConfigured
        );
        assert_eq!(peer_transport_policy_reject_reason(&assessment), None);
        assert_eq!(
            peer_transport_policy_effective_reason(&assessment),
            PeerTransportIdentityReadinessReason::NotConfigured
        );
    }

    #[test]
    fn transport_policy_assessment_compatibility_mtls_is_required() {
        let status = PeerTransportIdentityStatus {
            mode: PeerTransportIdentityMode::MtlsPath,
            transport_ready: true,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::Ready,
            warning: Some("pin not configured".to_string()),
        };

        let assessment =
            assess_peer_transport_policy(&status, PeerTransportEnforcementMode::Compatibility);
        assert!(assessment.required);
        assert!(assessment.is_ready());
        assert_eq!(assessment.gap(), None);
        assert!(assessment.enforcement.ready);
        assert_eq!(
            assessment.enforcement.reason,
            PeerTransportIdentityReadinessReason::Ready
        );
        assert_eq!(peer_transport_policy_reject_reason(&assessment), None);
        assert_eq!(
            peer_transport_policy_effective_reason(&assessment),
            PeerTransportIdentityReadinessReason::Ready
        );
    }

    #[test]
    fn transport_policy_assessment_strict_always_requires_transport() {
        let status = PeerTransportIdentityStatus {
            mode: PeerTransportIdentityMode::None,
            transport_ready: false,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::NotConfigured,
            warning: None,
        };

        let assessment = assess_peer_transport_policy(
            &status,
            PeerTransportEnforcementMode::StrictMtlsIdentityBound,
        );
        assert!(assessment.required);
        assert!(!assessment.is_ready());
        assert_eq!(
            assessment.gap(),
            Some(PeerTransportIdentityReadinessReason::NotConfigured)
        );
        assert!(!assessment.enforcement.ready);
        assert_eq!(
            assessment.enforcement.reason,
            PeerTransportIdentityReadinessReason::NotConfigured
        );
        assert_eq!(
            peer_transport_policy_reject_reason(&assessment),
            Some(PeerTransportIdentityReadinessReason::NotConfigured)
        );
        assert_eq!(
            peer_transport_policy_effective_reason(&assessment),
            PeerTransportIdentityReadinessReason::NotConfigured
        );
    }

    #[test]
    fn transport_policy_assessment_compatibility_mtls_unready_sets_gap_reason() {
        let status = PeerTransportIdentityStatus {
            mode: PeerTransportIdentityMode::MtlsPath,
            transport_ready: false,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::CertificatePathUnreadable,
            warning: Some("missing cert".to_string()),
        };

        let assessment =
            assess_peer_transport_policy(&status, PeerTransportEnforcementMode::Compatibility);
        assert!(assessment.required);
        assert!(!assessment.is_ready());
        assert_eq!(
            assessment.gap(),
            Some(PeerTransportIdentityReadinessReason::CertificatePathUnreadable)
        );
        assert_eq!(
            peer_transport_policy_reject_reason(&assessment),
            Some(PeerTransportIdentityReadinessReason::CertificatePathUnreadable)
        );
        assert_eq!(
            peer_transport_policy_effective_reason(&assessment),
            PeerTransportIdentityReadinessReason::CertificatePathUnreadable
        );
    }

    #[test]
    fn transport_policy_with_context_disables_requirement_without_cluster_peers() {
        let status = PeerTransportIdentityStatus {
            mode: PeerTransportIdentityMode::MtlsPath,
            transport_ready: false,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::CertificatePathUnreadable,
            warning: Some("missing cert".to_string()),
        };

        let assessment = assess_peer_transport_policy_with_context(
            &status,
            PeerTransportEnforcementMode::StrictMtlsIdentityBound,
            true,
            true,
            false,
        );
        assert!(!assessment.required);
        assert!(assessment.is_ready());
        assert_eq!(assessment.gap(), None);
        assert_eq!(peer_transport_policy_reject_reason(&assessment), None);
        assert_eq!(
            peer_transport_policy_effective_reason(&assessment),
            PeerTransportIdentityReadinessReason::CertificatePathUnreadable
        );
    }

    #[test]
    fn transport_policy_with_context_enforces_strict_mode_for_distributed_shared_token_peers() {
        let status = PeerTransportIdentityStatus {
            mode: PeerTransportIdentityMode::MtlsPath,
            transport_ready: false,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::CertificatePathUnreadable,
            warning: Some("missing cert".to_string()),
        };

        let assessment = assess_peer_transport_policy_with_context(
            &status,
            PeerTransportEnforcementMode::StrictMtlsIdentityBound,
            true,
            true,
            true,
        );
        assert!(assessment.required);
        assert!(!assessment.is_ready());
        assert_eq!(
            assessment.gap(),
            Some(PeerTransportIdentityReadinessReason::CertificatePathUnreadable)
        );
        assert_eq!(
            peer_transport_policy_reject_reason(&assessment),
            Some(PeerTransportIdentityReadinessReason::CertificatePathUnreadable)
        );
        assert_eq!(
            peer_transport_policy_effective_reason(&assessment),
            PeerTransportIdentityReadinessReason::CertificatePathUnreadable
        );
    }

    #[test]
    fn peer_transport_policy_diagnostics_reports_required_unready_state() {
        let status = PeerTransportIdentityStatus {
            mode: PeerTransportIdentityMode::MtlsPath,
            transport_ready: false,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::CertificatePathUnreadable,
            warning: Some("missing cert".to_string()),
        };

        let assessment = assess_peer_transport_policy(
            &status,
            PeerTransportEnforcementMode::StrictMtlsIdentityBound,
        );
        let diagnostics = peer_transport_policy_diagnostics(&assessment);

        assert!(diagnostics.required);
        assert!(!diagnostics.ready);
        assert_eq!(
            diagnostics.enforcement_mode,
            PeerTransportEnforcementMode::StrictMtlsIdentityBound
        );
        assert!(!diagnostics.enforcement_ready);
        assert_eq!(
            diagnostics.effective_reason,
            PeerTransportIdentityReadinessReason::CertificatePathUnreadable
        );
        assert_eq!(
            diagnostics.reject_reason,
            Some(PeerTransportIdentityReadinessReason::CertificatePathUnreadable)
        );
        assert_eq!(diagnostics.warning, Some("missing cert".to_string()));
    }

    #[test]
    fn peer_transport_policy_diagnostics_reports_optional_ready_state() {
        let status = PeerTransportIdentityStatus {
            mode: PeerTransportIdentityMode::None,
            transport_ready: false,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::NotConfigured,
            warning: None,
        };

        let assessment =
            assess_peer_transport_policy(&status, PeerTransportEnforcementMode::Compatibility);
        let diagnostics = peer_transport_policy_diagnostics(&assessment);

        assert!(!diagnostics.required);
        assert!(diagnostics.ready);
        assert_eq!(
            diagnostics.enforcement_mode,
            PeerTransportEnforcementMode::Compatibility
        );
        assert!(diagnostics.enforcement_ready);
        assert_eq!(
            diagnostics.effective_reason,
            PeerTransportIdentityReadinessReason::NotConfigured
        );
        assert_eq!(diagnostics.reject_reason, None);
    }

    #[test]
    fn cluster_peer_auth_production_readiness_reports_not_required_for_standalone() {
        let transport_status = PeerTransportIdentityStatus {
            mode: PeerTransportIdentityMode::None,
            transport_ready: false,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::NotConfigured,
            warning: None,
        };
        let transport_policy = assess_peer_transport_policy_with_context(
            &transport_status,
            PeerTransportEnforcementMode::StrictMtlsIdentityBound,
            false,
            false,
            false,
        );

        let assessment = assess_cluster_peer_auth_production_readiness(
            false,
            false,
            false,
            &transport_policy,
            false,
        );
        assert!(!assessment.ready);
        assert_eq!(
            assessment.reason,
            ClusterPeerAuthProductionReadinessReason::NotRequiredStandalone
        );
        assert_eq!(assessment.reason.as_str(), "not-required-standalone");
    }

    #[test]
    fn cluster_peer_auth_production_readiness_reports_transport_policy_not_required() {
        let transport_status = PeerTransportIdentityStatus {
            mode: PeerTransportIdentityMode::None,
            transport_ready: false,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::NotConfigured,
            warning: None,
        };
        let transport_policy = assess_peer_transport_policy_with_context(
            &transport_status,
            PeerTransportEnforcementMode::Compatibility,
            true,
            true,
            true,
        );

        let assessment = assess_cluster_peer_auth_production_readiness(
            true,
            true,
            true,
            &transport_policy,
            false,
        );
        assert!(!assessment.ready);
        assert_eq!(
            assessment.reason,
            ClusterPeerAuthProductionReadinessReason::TransportPolicyNotRequired
        );
        assert_eq!(assessment.reason.as_str(), "transport-policy-not-required");
    }

    #[test]
    fn cluster_peer_auth_production_readiness_reports_transport_not_ready() {
        let transport_status = PeerTransportIdentityStatus {
            mode: PeerTransportIdentityMode::MtlsPath,
            transport_ready: false,
            identity_bound: false,
            reason: PeerTransportIdentityReadinessReason::CertificatePathUnreadable,
            warning: Some("missing cert".to_string()),
        };
        let transport_policy = assess_peer_transport_policy_with_context(
            &transport_status,
            PeerTransportEnforcementMode::StrictMtlsIdentityBound,
            true,
            true,
            true,
        );

        let assessment = assess_cluster_peer_auth_production_readiness(
            true,
            true,
            true,
            &transport_policy,
            false,
        );
        assert!(!assessment.ready);
        assert_eq!(
            assessment.reason,
            ClusterPeerAuthProductionReadinessReason::TransportNotReady
        );
        assert_eq!(assessment.reason.as_str(), "transport-not-ready");
    }

    #[test]
    fn cluster_peer_auth_production_readiness_reports_ready_when_all_guards_hold() {
        let transport_status = PeerTransportIdentityStatus {
            mode: PeerTransportIdentityMode::MtlsPath,
            transport_ready: true,
            identity_bound: true,
            reason: PeerTransportIdentityReadinessReason::Ready,
            warning: None,
        };
        let transport_policy = assess_peer_transport_policy_with_context(
            &transport_status,
            PeerTransportEnforcementMode::StrictMtlsIdentityBound,
            true,
            true,
            true,
        );

        let assessment = assess_cluster_peer_auth_production_readiness(
            true,
            true,
            true,
            &transport_policy,
            true,
        );
        assert!(assessment.ready);
        assert_eq!(
            assessment.reason,
            ClusterPeerAuthProductionReadinessReason::Ready
        );
        assert_eq!(assessment.reason.as_str(), "ready");
    }

    fn spawn_tls_server(cert_path: &str, key_path: &str) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind tls listener");
        let addr = listener.local_addr().expect("tls listener local addr");
        let cert_path = cert_path.to_string();
        let key_path = key_path.to_string();

        let handle = thread::spawn(move || {
            let mut acceptor =
                SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).expect("acceptor");
            acceptor
                .set_certificate_chain_file(cert_path.as_str())
                .expect("set server cert");
            acceptor
                .set_private_key_file(key_path.as_str(), SslFiletype::PEM)
                .expect("set server key");
            acceptor.check_private_key().expect("server key pair");
            let acceptor = acceptor.build();

            let (stream, _) = listener.accept().expect("accept client");
            let _ = acceptor.accept(stream).map(|mut tls_stream| {
                let _ = tls_stream.write_all(b"ok");
            });
        });

        (format!("127.0.0.1:{}", addr.port()), handle)
    }

    fn load_cert_from_path(path: &str) -> X509 {
        let cert_pem = fs::read(path).expect("read cert");
        X509::from_pem(cert_pem.as_slice()).expect("parse cert")
    }

    #[test]
    fn certificate_validity_reference_rejects_before_not_before_window() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, _, _, _) = write_valid_identity_fixture(&dir);
        let cert = load_cert_from_path(cert_path.as_str());
        let reference = Asn1Time::from_unix(946_684_800).expect("reference time");

        let result = ensure_certificate_valid_at_reference(&cert, reference.as_ref());
        assert_eq!(result, Err("certificate is not yet valid".to_string()));
    }

    #[test]
    fn certificate_validity_reference_accepts_time_inside_window() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, _, _, _) = write_valid_identity_fixture(&dir);
        let cert = load_cert_from_path(cert_path.as_str());
        let reference = Asn1Time::from_unix(1_893_456_000).expect("reference time");

        let result = ensure_certificate_valid_at_reference(&cert, reference.as_ref());
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn certificate_validity_reference_rejects_after_not_after_window() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, _, _, _) = write_valid_identity_fixture(&dir);
        let cert = load_cert_from_path(cert_path.as_str());
        let reference = Asn1Time::from_unix(4_102_444_800).expect("reference time");

        let result = ensure_certificate_valid_at_reference(&cert, reference.as_ref());
        assert_eq!(result, Err("certificate has expired".to_string()));
    }

    #[test]
    fn transport_identity_reports_not_configured_when_all_paths_are_missing() {
        let status = probe_peer_transport_identity(None, None, None);
        assert_eq!(status.mode, PeerTransportIdentityMode::None);
        assert!(!status.transport_ready);
        assert!(!status.identity_bound);
        assert_eq!(
            status.reason,
            PeerTransportIdentityReadinessReason::NotConfigured
        );
        assert!(status.warning.is_none());
    }

    #[test]
    fn dns_name_matching_requires_exact_identity_and_rejects_wildcards() {
        assert!(super::dns_name_matches(
            "node-a.cluster.internal",
            "node-a.cluster.internal"
        ));
        assert!(!super::dns_name_matches(
            "*.cluster.internal",
            "node-a.cluster.internal"
        ));
    }

    #[test]
    fn transport_identity_reports_incomplete_configuration_when_any_path_is_missing() {
        let status =
            probe_peer_transport_identity(Some("/tmp/cert.pem"), None, Some("/tmp/ca.pem"));
        assert_eq!(status.mode, PeerTransportIdentityMode::MtlsPath);
        assert!(!status.transport_ready);
        assert!(!status.identity_bound);
        assert_eq!(
            status.reason,
            PeerTransportIdentityReadinessReason::IncompleteConfiguration
        );
        assert!(status.warning.is_some());
    }

    #[test]
    fn transport_identity_reports_ready_when_all_paths_are_readable() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path) = write_valid_fixture(&dir);

        let status = probe_peer_transport_identity(
            Some(cert_path.as_str()),
            Some(key_path.as_str()),
            Some(trust_store_path.as_str()),
        );
        assert_eq!(status.mode, PeerTransportIdentityMode::MtlsPath);
        assert!(status.transport_ready);
        assert!(!status.identity_bound);
        assert_eq!(status.reason, PeerTransportIdentityReadinessReason::Ready);
        assert!(status.warning.is_some());
    }

    #[test]
    fn transport_identity_reports_identity_bound_when_certificate_pin_matches() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path, cert_sha256_pin) =
            write_valid_identity_fixture(&dir);

        let status = probe_peer_transport_identity_with_cert_sha256_pin(
            Some(cert_path.as_str()),
            Some(key_path.as_str()),
            Some(trust_store_path.as_str()),
            Some(cert_sha256_pin.as_str()),
        );
        assert!(status.transport_ready);
        assert!(status.identity_bound);
        assert_eq!(status.reason, PeerTransportIdentityReadinessReason::Ready);
        assert!(status.warning.is_none());
    }

    #[test]
    fn transport_identity_reports_identity_bound_when_any_certificate_pin_matches() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path, cert_sha256_pin) =
            write_valid_identity_fixture(&dir);
        let pin_set = format!(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,{}",
            cert_sha256_pin
        );

        let status = probe_peer_transport_identity_with_cert_sha256_pin(
            Some(cert_path.as_str()),
            Some(key_path.as_str()),
            Some(trust_store_path.as_str()),
            Some(pin_set.as_str()),
        );
        assert!(status.transport_ready);
        assert!(status.identity_bound);
        assert_eq!(status.reason, PeerTransportIdentityReadinessReason::Ready);
        assert!(status.warning.is_none());
    }

    #[test]
    fn transport_identity_reports_pin_mismatch_when_certificate_pin_differs() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path) = write_valid_fixture(&dir);

        let status = probe_peer_transport_identity_with_cert_sha256_pin(
            Some(cert_path.as_str()),
            Some(key_path.as_str()),
            Some(trust_store_path.as_str()),
            Some("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        );
        assert!(!status.transport_ready);
        assert!(!status.identity_bound);
        assert_eq!(
            status.reason,
            PeerTransportIdentityReadinessReason::CertificateFingerprintPinMismatch
        );
        assert!(status.warning.is_some());
    }

    #[test]
    fn transport_identity_reports_invalid_pin_shape() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path) = write_valid_fixture(&dir);

        let status = probe_peer_transport_identity_with_cert_sha256_pin(
            Some(cert_path.as_str()),
            Some(key_path.as_str()),
            Some(trust_store_path.as_str()),
            Some("invalid-pin"),
        );
        assert!(!status.transport_ready);
        assert!(!status.identity_bound);
        assert_eq!(
            status.reason,
            PeerTransportIdentityReadinessReason::CertificateFingerprintPinInvalid
        );
        assert!(status.warning.is_some());
    }

    #[test]
    fn transport_identity_reports_invalid_pin_shape_when_any_pin_is_invalid() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path, cert_sha256_pin) =
            write_valid_identity_fixture(&dir);
        let pin_set = format!("{cert_sha256_pin},invalid-pin");

        let status = probe_peer_transport_identity_with_cert_sha256_pin(
            Some(cert_path.as_str()),
            Some(key_path.as_str()),
            Some(trust_store_path.as_str()),
            Some(pin_set.as_str()),
        );
        assert!(!status.transport_ready);
        assert!(!status.identity_bound);
        assert_eq!(
            status.reason,
            PeerTransportIdentityReadinessReason::CertificateFingerprintPinInvalid
        );
        assert!(status.warning.is_some());
    }

    #[test]
    fn transport_identity_reports_invalid_revocation_set_shape_when_any_pin_is_invalid() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path, cert_sha256_pin) =
            write_valid_identity_fixture(&dir);
        let revocation_set = format!("{cert_sha256_pin},invalid-pin");

        let status = probe_peer_transport_identity_with_cert_sha256_pin_and_revocations(
            Some(cert_path.as_str()),
            Some(key_path.as_str()),
            Some(trust_store_path.as_str()),
            Some(cert_sha256_pin.as_str()),
            Some(revocation_set.as_str()),
        );
        assert!(!status.transport_ready);
        assert!(!status.identity_bound);
        assert_eq!(
            status.reason,
            PeerTransportIdentityReadinessReason::CertificateFingerprintRevocationInvalid
        );
        assert!(status.warning.is_some());
    }

    #[test]
    fn transport_identity_reports_revoked_certificate_when_revocation_set_matches() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path, cert_sha256_pin) =
            write_valid_identity_fixture(&dir);

        let status = probe_peer_transport_identity_with_cert_sha256_pin_and_revocations(
            Some(cert_path.as_str()),
            Some(key_path.as_str()),
            Some(trust_store_path.as_str()),
            Some(cert_sha256_pin.as_str()),
            Some(cert_sha256_pin.as_str()),
        );
        assert!(!status.transport_ready);
        assert!(!status.identity_bound);
        assert_eq!(
            status.reason,
            PeerTransportIdentityReadinessReason::CertificateFingerprintRevoked
        );
        assert!(status.warning.is_some());
    }

    #[test]
    fn transport_identity_reports_encrypted_private_key_as_unsupported() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, _, trust_store_path, _) = write_valid_identity_fixture(&dir);
        let key_path = dir.path().join("peer.key");
        fs::write(
            &key_path,
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\n\
             dGVzdA==\n\
             -----END ENCRYPTED PRIVATE KEY-----\n",
        )
        .expect("write key");

        let status = probe_peer_transport_identity(
            Some(cert_path.as_str()),
            Some(key_path.to_string_lossy().as_ref()),
            Some(trust_store_path.as_str()),
        );
        assert_eq!(
            status.reason,
            PeerTransportIdentityReadinessReason::KeyPemEncryptedUnsupported
        );
        assert!(!status.transport_ready);
        assert!(!status.identity_bound);
    }

    #[test]
    fn transport_identity_reports_private_key_material_in_trust_store() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, _, _) = write_valid_identity_fixture(&dir);
        let trust_store_path = dir.path().join("ca.pem");
        fs::write(
            &trust_store_path,
            "-----BEGIN CERTIFICATE-----\n\
             dGVzdA==\n\
             -----END CERTIFICATE-----\n\
             -----BEGIN PRIVATE KEY-----\n\
             dGVzdA==\n\
             -----END PRIVATE KEY-----\n",
        )
        .expect("write ca");

        let status = probe_peer_transport_identity(
            Some(cert_path.as_str()),
            Some(key_path.as_str()),
            Some(trust_store_path.to_string_lossy().as_ref()),
        );
        assert_eq!(
            status.reason,
            PeerTransportIdentityReadinessReason::TrustStoreContainsPrivateKeyPem
        );
        assert!(!status.transport_ready);
        assert!(!status.identity_bound);
    }

    #[test]
    fn transport_identity_trims_whitespace_inputs_before_validation() {
        let status = probe_peer_transport_identity(Some("   "), Some(""), Some("\n\t"));
        assert_eq!(status.mode, PeerTransportIdentityMode::None);
        assert_eq!(
            status.reason,
            PeerTransportIdentityReadinessReason::NotConfigured
        );
    }

    #[test]
    fn node_binding_requires_valid_node_identity() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path, cert_sha256_pin) =
            write_valid_identity_fixture(&dir);

        let status = probe_peer_transport_identity_with_cert_sha256_pin_and_node_id_binding(
            Some(cert_path.as_str()),
            Some(key_path.as_str()),
            Some(trust_store_path.as_str()),
            Some(cert_sha256_pin.as_str()),
            Some(":9000"),
        );

        assert_eq!(
            status.reason,
            PeerTransportIdentityReadinessReason::NodeIdentityInvalid
        );
        assert!(!status.transport_ready);
        assert!(!status.identity_bound);
    }

    #[test]
    fn node_binding_rejects_unbracketed_ipv6_identity_with_port() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path, cert_sha256_pin) =
            write_valid_identity_fixture(&dir);

        let status = probe_peer_transport_identity_with_cert_sha256_pin_and_node_id_binding(
            Some(cert_path.as_str()),
            Some(key_path.as_str()),
            Some(trust_store_path.as_str()),
            Some(cert_sha256_pin.as_str()),
            Some("2001:db8::1:9000"),
        );

        assert_eq!(
            status.reason,
            PeerTransportIdentityReadinessReason::NodeIdentityInvalid
        );
        assert!(!status.transport_ready);
        assert!(!status.identity_bound);
    }

    #[test]
    fn node_binding_accepts_bracketed_ipv6_identity_shape() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path, cert_sha256_pin) =
            write_valid_identity_fixture(&dir);

        let status = probe_peer_transport_identity_with_cert_sha256_pin_and_node_id_binding(
            Some(cert_path.as_str()),
            Some(key_path.as_str()),
            Some(trust_store_path.as_str()),
            Some(cert_sha256_pin.as_str()),
            Some("[2001:db8::1]:9000"),
        );

        assert_eq!(
            status.reason,
            PeerTransportIdentityReadinessReason::NodeIdentityCertificateMismatch
        );
        assert!(!status.transport_ready);
        assert!(!status.identity_bound);
    }

    #[test]
    fn node_binding_requires_fingerprint_pin_when_node_identity_is_set() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path) = write_valid_fixture(&dir);

        let status = probe_peer_transport_identity_with_cert_sha256_pin_and_node_id_binding(
            Some(cert_path.as_str()),
            Some(key_path.as_str()),
            Some(trust_store_path.as_str()),
            None,
            Some("node-a.internal:9000"),
        );

        assert_eq!(
            status.reason,
            PeerTransportIdentityReadinessReason::NodeIdentityBindingPinRequired
        );
        assert!(!status.transport_ready);
        assert!(!status.identity_bound);
    }

    #[test]
    fn node_binding_reports_identity_bound_when_pin_and_node_identity_are_valid() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path, cert_sha256_pin) =
            write_valid_identity_fixture(&dir);

        let status = probe_peer_transport_identity_with_cert_sha256_pin_and_node_id_binding(
            Some(cert_path.as_str()),
            Some(key_path.as_str()),
            Some(trust_store_path.as_str()),
            Some(cert_sha256_pin.as_str()),
            Some("maxio-peer:9000"),
        );

        assert_eq!(status.reason, PeerTransportIdentityReadinessReason::Ready);
        assert!(status.transport_ready);
        assert!(status.identity_bound);
        assert!(status.warning.is_none());
    }

    #[test]
    fn node_binding_reports_revoked_when_certificate_policy_revocation_matches() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path, cert_sha256_pin) =
            write_valid_identity_fixture(&dir);

        let status = probe_peer_transport_identity_with_certificate_policy_and_node_id_binding(
            Some(cert_path.as_str()),
            Some(key_path.as_str()),
            Some(trust_store_path.as_str()),
            PeerCertificatePolicy {
                sha256_pin: Some(cert_sha256_pin.as_str()),
                sha256_revocations: Some(cert_sha256_pin.as_str()),
            },
            Some("maxio-peer:9000"),
        );

        assert_eq!(
            status.reason,
            PeerTransportIdentityReadinessReason::CertificateFingerprintRevoked
        );
        assert!(!status.transport_ready);
        assert!(!status.identity_bound);
    }

    #[test]
    fn node_binding_reports_certificate_mismatch_when_node_identity_does_not_match_certificate() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path, cert_sha256_pin) =
            write_valid_identity_fixture(&dir);

        let status = probe_peer_transport_identity_with_cert_sha256_pin_and_node_id_binding(
            Some(cert_path.as_str()),
            Some(key_path.as_str()),
            Some(trust_store_path.as_str()),
            Some(cert_sha256_pin.as_str()),
            Some("node-a.internal:9000"),
        );

        assert_eq!(
            status.reason,
            PeerTransportIdentityReadinessReason::NodeIdentityCertificateMismatch
        );
        assert!(!status.transport_ready);
        assert!(!status.identity_bound);
        assert!(status.warning.is_some());
    }

    #[test]
    fn transport_identity_reports_invalid_cert_key_pair_when_pin_matches() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path, cert_sha256_pin) =
            write_valid_identity_fixture(&dir);
        fs::write(
            key_path.as_str(),
            "-----BEGIN PRIVATE KEY-----\n\
             MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCjzcowhBhX8pr0\n\
             +u++6FZVqDaaPXLCucbKYX4LWpbnTXrO4LP1bE17G5Qmhp3NaN1CPGbILWal0L2H\n\
             SKwhFg61Oeiaa1GtF9lBPv1O9U2D5K2Jzc7S/aJLz8vjiIwAnUAyP/xo34MGcRyh\n\
             o3OB7fVgqvjB3DTrzUy8QTHoIEkQ7Wq19e3HhnHgK/PGFjljmHwndivMPrhnu+i+\n\
             nXQRJJDY5Xhm6H1D/isq0eX3Kr96ee2xy55JvFIhmrk4dTV/g0opbQgBECK83Wrt\n\
             HlQRYXp1Bkha0BYGzcv66Y7wFNR0dEOP5BJbHUgiwn44y+RhN+Zn/OAog0Asrxg4\n\
             zwkNofKdAgMBAAECggEABX2kTZcH996+hKrADEQJLNWMKwRsoIwOAVeznBl9Hc4c\n\
             6UANWD3j+lX00+EcULfh/tKRLBxK02ZutqZgJWXHYsTJABrL10O0OSSC5OQtJS2D\n\
             sa8FQ/uo4TtbHXVEzXp380HuKe0gHRWqkjKCmzQzpE9m3PIO5hPw2A35aHYN7PQd\n\
             VpsQB7BhlcNci/RqaYjPWqNB2V1oR8gJM+aBKfNsGduCizoe3SRsuJd6p1X9e8d+\n\
             6V7jrxhCgEa6cjOeNN98c/H8kcI9Cpr5P9HCRlGTAfW30TS/GjhgJ5/4nw0NXNgB\n\
             czPW5AgGcrbjDWf/tG5TH8BdzRQ0ZayrAemqGKpNYwKBgQDU2UIf+joNLR4Jr+J7\n\
             eCba7B48+l8ofDz0Q7kotFF+Yc1dOOQ6DaSmpbCvP/QMBdvo/ZoVmco8MbF0aaj5\n\
             e8OMrQh2LVbL7EaA0vdgYEl3Vte3PtxoS7n/zYWkmttfaIPM5ZQRZ461CDTI8yQe\n\
             JS9x2qYW0GmuyZNATlbsyDkyfwKBgQDFAyFixwQcqo3Ff3QpDoNp8Zrhtxl2Gwru\n\
             MdxX5RkQBjh5e/n1VrY3AV4hjEZHa0IhbM1oXwByXJu17diPAWVZ/ttVM7+xplha\n\
             oyc7d0/U3tIgCzPo5MxR9IwSEUkt+YD8iRsvSaUCYfe4dkMs6CV8DzvXmy6zpFvW\n\
             N37tLGfU4wKBgQCm/Kv8Gnxgyfy+7NZqt6EEMCqo/GSbhpzrphYl8RHebSyI7pFf\n\
             WkTK2UL8utfkdtRIvm2cdMNM5k+qXRrMYGTSgQ4aaQenhP7rIpghbGk2z1L92Lti\n\
             t8Z9AejPcw6Yk46Tuamo3e3/6ShAX0D+xX2rfTbAv1GqZ0q3ML7RlWQKUQKBgAnZ\n\
             GjYh1KbKL8QLlvbmbtNA7IkT6gXpXCaD/4u1PAd9CB2qgNguuXUOcHIk3O59AhVB\n\
             pxLsjM0qq+3wMb8URsi04KnlqFNtCUWemjtyv17YtJA9fx7JMR13p/jPPGU776Kw\n\
             B9fZSpJP614hK0J3aEhHSqqAa1k3gg+3PnUEnzwZAoGAW1wS4hzXbS0oHy+lbcxA\n\
             fjNehjWuOPWdt1pxlXVU0uEqZCd7/KiSq1BwUa4xpYLa/iSSMbkW4Myivymz7rZR\n\
             +Fr8ngYFQtoTjkoT4AH6gZAuAfIg0OebvIt3ied30DIsU4y0x947uJL4rwd3EsO4\n\
             oGjj+BmCqMqJT01ru2WrFpA=\n\
             -----END PRIVATE KEY-----\n",
        )
        .expect("write mismatched key");

        let status = probe_peer_transport_identity_with_cert_sha256_pin(
            Some(cert_path.as_str()),
            Some(key_path.as_str()),
            Some(trust_store_path.as_str()),
            Some(cert_sha256_pin.as_str()),
        );
        assert!(!status.transport_ready);
        assert!(!status.identity_bound);
        assert_eq!(
            status.reason,
            PeerTransportIdentityReadinessReason::CertificateKeyPairInvalid
        );
        assert!(status.warning.is_some());
    }

    #[test]
    fn peer_attestation_rejects_invalid_peer_endpoint() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path, _) = write_valid_identity_fixture(&dir);

        let result = attest_peer_transport_identity_with_mtls(
            ":9000",
            "maxio-peer:9000",
            cert_path.as_str(),
            key_path.as_str(),
            trust_store_path.as_str(),
            Duration::from_secs(1),
        );
        assert_eq!(
            result,
            Err(PeerTransportPeerAttestationError::InvalidPeerEndpoint)
        );
    }

    #[test]
    fn peer_attestation_rejects_invalid_expected_node_identity() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path, _) = write_valid_identity_fixture(&dir);

        let result = attest_peer_transport_identity_with_mtls(
            "127.0.0.1:9000",
            "node/invalid",
            cert_path.as_str(),
            key_path.as_str(),
            trust_store_path.as_str(),
            Duration::from_secs(1),
        );
        assert_eq!(
            result,
            Err(PeerTransportPeerAttestationError::InvalidExpectedNodeIdentity)
        );
    }

    #[test]
    fn peer_attestation_rejects_encrypted_private_key_as_unsupported() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, _, trust_store_path, _) = write_valid_identity_fixture(&dir);
        let key_path = dir.path().join("peer.key");
        fs::write(
            &key_path,
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\n\
             dGVzdA==\n\
             -----END ENCRYPTED PRIVATE KEY-----\n",
        )
        .expect("write key");

        let result = attest_peer_transport_identity_with_mtls(
            "127.0.0.1:9000",
            "maxio-peer:9000",
            cert_path.as_str(),
            key_path.to_string_lossy().as_ref(),
            trust_store_path.as_str(),
            Duration::from_secs(1),
        );
        assert_eq!(
            result,
            Err(PeerTransportPeerAttestationError::KeyPemEncryptedUnsupported)
        );
    }

    #[test]
    fn peer_attestation_rejects_trust_store_with_private_key_material() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, _, _) = write_valid_identity_fixture(&dir);
        let trust_store_path = dir.path().join("ca.pem");
        fs::write(
            &trust_store_path,
            "-----BEGIN CERTIFICATE-----\n\
             dGVzdA==\n\
             -----END CERTIFICATE-----\n\
             -----BEGIN PRIVATE KEY-----\n\
             dGVzdA==\n\
             -----END PRIVATE KEY-----\n",
        )
        .expect("write ca");

        let result = attest_peer_transport_identity_with_mtls(
            "127.0.0.1:9000",
            "maxio-peer:9000",
            cert_path.as_str(),
            key_path.as_str(),
            trust_store_path.to_string_lossy().as_ref(),
            Duration::from_secs(1),
        );
        assert_eq!(
            result,
            Err(PeerTransportPeerAttestationError::TrustStoreContainsPrivateKeyPem)
        );
    }

    #[test]
    fn peer_attestation_succeeds_for_tls_peer_with_matching_expected_node_identity() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path, _) = write_valid_identity_fixture(&dir);
        let (peer_endpoint, handle) = spawn_tls_server(cert_path.as_str(), key_path.as_str());
        let port = peer_endpoint
            .rsplit(':')
            .next()
            .expect("peer endpoint should include port");
        let expected_node_id = format!("maxio-peer:{port}");

        let result = attest_peer_transport_identity_with_mtls(
            peer_endpoint.as_str(),
            expected_node_id.as_str(),
            cert_path.as_str(),
            key_path.as_str(),
            trust_store_path.as_str(),
            Duration::from_secs(2),
        );
        handle.join().expect("tls server thread");

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn peer_attestation_with_pin_succeeds_when_peer_fingerprint_matches() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path, cert_sha256_pin) =
            write_valid_identity_fixture(&dir);
        let (peer_endpoint, handle) = spawn_tls_server(cert_path.as_str(), key_path.as_str());
        let port = peer_endpoint
            .rsplit(':')
            .next()
            .expect("peer endpoint should include port");
        let expected_node_id = format!("maxio-peer:{port}");

        let result = attest_peer_transport_identity_with_mtls_and_cert_sha256_pin(
            peer_endpoint.as_str(),
            expected_node_id.as_str(),
            cert_path.as_str(),
            key_path.as_str(),
            trust_store_path.as_str(),
            Some(cert_sha256_pin.as_str()),
            Duration::from_secs(2),
        );
        handle.join().expect("tls server thread");

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn peer_attestation_with_pin_rejects_invalid_pin_shape() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path, _) = write_valid_identity_fixture(&dir);
        let (peer_endpoint, handle) = spawn_tls_server(cert_path.as_str(), key_path.as_str());
        let port = peer_endpoint
            .rsplit(':')
            .next()
            .expect("peer endpoint should include port");
        let expected_node_id = format!("maxio-peer:{port}");

        let result = attest_peer_transport_identity_with_mtls_and_cert_sha256_pin(
            peer_endpoint.as_str(),
            expected_node_id.as_str(),
            cert_path.as_str(),
            key_path.as_str(),
            trust_store_path.as_str(),
            Some("invalid-pin"),
            Duration::from_secs(2),
        );
        handle.join().expect("tls server thread");

        assert_eq!(
            result,
            Err(PeerTransportPeerAttestationError::PeerCertificateFingerprintPinInvalid)
        );
    }

    #[test]
    fn peer_attestation_with_pin_rejects_mismatched_fingerprint() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path, _) = write_valid_identity_fixture(&dir);
        let (peer_endpoint, handle) = spawn_tls_server(cert_path.as_str(), key_path.as_str());
        let port = peer_endpoint
            .rsplit(':')
            .next()
            .expect("peer endpoint should include port");
        let expected_node_id = format!("maxio-peer:{port}");

        let result = attest_peer_transport_identity_with_mtls_and_cert_sha256_pin(
            peer_endpoint.as_str(),
            expected_node_id.as_str(),
            cert_path.as_str(),
            key_path.as_str(),
            trust_store_path.as_str(),
            Some("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            Duration::from_secs(2),
        );
        handle.join().expect("tls server thread");

        assert_eq!(
            result,
            Err(PeerTransportPeerAttestationError::PeerCertificateFingerprintPinMismatch)
        );
    }

    #[test]
    fn peer_attestation_with_revocations_rejects_invalid_revocation_set_shape() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path, cert_sha256_pin) =
            write_valid_identity_fixture(&dir);
        let (peer_endpoint, handle) = spawn_tls_server(cert_path.as_str(), key_path.as_str());
        let port = peer_endpoint
            .rsplit(':')
            .next()
            .expect("peer endpoint should include port");
        let expected_node_id = format!("maxio-peer:{port}");
        let revocation_set = format!("{cert_sha256_pin},invalid-pin");

        let result = attest_peer_transport_identity_with_mtls_with_policy(
            peer_endpoint.as_str(),
            expected_node_id.as_str(),
            cert_path.as_str(),
            key_path.as_str(),
            trust_store_path.as_str(),
            PeerCertificatePolicy {
                sha256_pin: Some(cert_sha256_pin.as_str()),
                sha256_revocations: Some(revocation_set.as_str()),
            },
            Duration::from_secs(2),
        );
        handle.join().expect("tls server thread");

        assert_eq!(
            result,
            Err(PeerTransportPeerAttestationError::PeerCertificateFingerprintRevocationInvalid)
        );
    }

    #[test]
    fn peer_attestation_with_revocations_rejects_revoked_peer_certificate() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path, cert_sha256_pin) =
            write_valid_identity_fixture(&dir);
        let (peer_endpoint, handle) = spawn_tls_server(cert_path.as_str(), key_path.as_str());
        let port = peer_endpoint
            .rsplit(':')
            .next()
            .expect("peer endpoint should include port");
        let expected_node_id = format!("maxio-peer:{port}");

        let result = attest_peer_transport_identity_with_mtls_with_policy(
            peer_endpoint.as_str(),
            expected_node_id.as_str(),
            cert_path.as_str(),
            key_path.as_str(),
            trust_store_path.as_str(),
            PeerCertificatePolicy {
                sha256_pin: Some(cert_sha256_pin.as_str()),
                sha256_revocations: Some(cert_sha256_pin.as_str()),
            },
            Duration::from_secs(2),
        );
        handle.join().expect("tls server thread");

        assert_eq!(
            result,
            Err(PeerTransportPeerAttestationError::PeerCertificateFingerprintRevoked)
        );
    }

    #[test]
    fn peer_attestation_rejects_tls_peer_when_expected_node_identity_mismatches_certificate() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path, _) = write_valid_identity_fixture(&dir);
        let (peer_endpoint, handle) = spawn_tls_server(cert_path.as_str(), key_path.as_str());
        let port = peer_endpoint
            .rsplit(':')
            .next()
            .expect("peer endpoint should include port");
        let expected_node_id = format!("node-a.internal:{port}");

        let result = attest_peer_transport_identity_with_mtls(
            peer_endpoint.as_str(),
            expected_node_id.as_str(),
            cert_path.as_str(),
            key_path.as_str(),
            trust_store_path.as_str(),
            Duration::from_secs(2),
        );
        handle.join().expect("tls server thread");

        assert_eq!(
            result,
            Err(PeerTransportPeerAttestationError::PeerCertificateNodeIdentityMismatch)
        );
    }

    #[test]
    fn peer_attestation_rejects_non_tls_peer_with_handshake_failure() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path, _) = write_valid_identity_fixture(&dir);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind plain listener");
        let addr = listener.local_addr().expect("plain listener addr");
        let peer_endpoint = format!("127.0.0.1:{}", addr.port());
        let handle = thread::spawn(move || {
            let _ = listener.accept();
        });

        let result = attest_peer_transport_identity_with_mtls(
            peer_endpoint.as_str(),
            peer_endpoint.as_str(),
            cert_path.as_str(),
            key_path.as_str(),
            trust_store_path.as_str(),
            Duration::from_secs(2),
        );
        handle.join().expect("plain server thread");

        assert_eq!(
            result,
            Err(PeerTransportPeerAttestationError::TlsHandshakeFailed)
        );
    }

    #[test]
    fn peer_attestation_rejects_when_peer_connection_fails() {
        let dir = tempdir().expect("tempdir");
        let (cert_path, key_path, trust_store_path, _) = write_valid_identity_fixture(&dir);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral listener");
        let port = listener.local_addr().expect("listener addr").port();
        drop(listener);
        let peer_endpoint = format!("127.0.0.1:{port}");

        let result = attest_peer_transport_identity_with_mtls(
            peer_endpoint.as_str(),
            peer_endpoint.as_str(),
            cert_path.as_str(),
            key_path.as_str(),
            trust_store_path.as_str(),
            Duration::from_millis(200),
        );

        assert_eq!(
            result,
            Err(PeerTransportPeerAttestationError::PeerConnectFailed)
        );
    }
}
