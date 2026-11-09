//! PM-owned workspace wire and cross-domain contracts. Format 1 is additive only.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub const FORMAT_VERSION: u32 = 1;
pub const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 20_000;
pub const STATE_DIRECTORY: &str = ".maxio-workspace";

/// Explicit credentials are never serialized, logged, or passed to an agent.
pub struct RemoteConfig {
    pub endpoint: String,
    pub bucket: String,
    pub name: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
    pub ca_cert: Option<PathBuf>,
    pub allow_http: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileVersion {
    /// SHA-256 of the complete file, independent of a provider ETag.
    pub sha256: String,
    pub size: u64,
    /// Fresh unique key; never reused by the workspace protocol.
    pub blob: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionRef {
    pub revision: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: u32,
    pub workspace_id: String,
    pub revision: String,
    pub parent: Option<RevisionRef>,
    pub files: BTreeMap<String, FileVersion>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub manifest: Manifest,
    pub manifest_sha256: String,
    /// Only the current head can be a publication base. Historical reads omit it.
    pub head_etag: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Publication {
    pub path: String,
    /// Private, fsynced immutable staging file, not the mutable working copy.
    pub source: PathBuf,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct TransferStats {
    /// Application payload bytes, excluding HTTP/TLS framing and SDK retries.
    pub payload_uploaded: u64,
    pub payload_downloaded: u64,
    pub metadata_uploaded: u64,
    pub metadata_downloaded: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkspaceRow {
    pub path: String,
    pub reference: String,
    pub size: u64,
    pub sha256: String,
    /// absent, present_unverified, clean, stale, or dirty. Stale matches its old baseline.
    pub local_state: String,
    pub pinned: bool,
}

pub fn validate_id(value: &str) -> Result<()> {
    let id = uuid::Uuid::parse_str(value)?;
    ensure!(
        !id.is_nil() && id.to_string() == value,
        "invalid canonical workspace UUID"
    );
    Ok(())
}

pub fn validate_hash(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid workspace SHA-256"
    );
    Ok(())
}

pub fn validate_name(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 63
            && value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !value.starts_with('-')
            && !value.ends_with('-'),
        "workspace name must be 1-63 lowercase letters, digits or internal hyphens"
    );
    Ok(())
}

pub fn validate_file_version(file: &FileVersion) -> Result<()> {
    validate_hash(&file.sha256)?;
    let parts: Vec<_> = file.blob.split('/').collect();
    ensure!(
        parts.len() == 4 && parts[0] == "maxio-workspaces" && parts[2] == "blobs",
        "invalid workspace blob key"
    );
    validate_name(parts[1])?;
    validate_id(parts[3])
}

/// Canonical format-1 manifests use serde's compact struct serialization.
pub fn manifest_hash(manifest: &Manifest) -> Result<String> {
    let bytes = serde_json::to_vec(manifest)?;
    ensure!(
        bytes.len() <= MAX_MANIFEST_BYTES,
        "workspace manifest exceeds 8 MiB"
    );
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub fn validate_snapshot(snapshot: &Snapshot) -> Result<()> {
    let manifest = &snapshot.manifest;
    ensure!(
        manifest.format == FORMAT_VERSION,
        "unsupported workspace format"
    );
    validate_id(&manifest.workspace_id)?;
    validate_id(&manifest.revision)?;
    validate_hash(&snapshot.manifest_sha256)?;
    ensure!(
        snapshot.manifest_sha256 == manifest_hash(manifest)?,
        "workspace manifest content identity mismatch"
    );
    ensure!(
        manifest.files.len() <= MAX_ENTRIES,
        "workspace exceeds 20,000 files"
    );
    crate::files::validate_workspace_paths(manifest.files.keys())?;
    for file in manifest.files.values() {
        validate_file_version(file)?;
    }
    if let Some(parent) = &manifest.parent {
        validate_id(&parent.revision)?;
        validate_hash(&parent.sha256)?;
        ensure!(
            parent.revision != manifest.revision,
            "workspace revision references itself"
        );
    }
    if let Some(etag) = &snapshot.head_etag {
        ensure!(
            !etag.is_empty() && etag.len() <= 1024 && etag.bytes().all(|b| (32..127).contains(&b)),
            "invalid workspace head ETag"
        );
    }
    Ok(())
}

pub fn reference(snapshot: &Snapshot, path: &str) -> Result<String> {
    ensure!(
        snapshot.manifest.files.contains_key(path),
        "path is not published in this revision"
    );
    reference_at(
        &snapshot.manifest.workspace_id,
        &snapshot.manifest.revision,
        path,
    )
}

/// Stable logical reference for an exact published or retained baseline version.
/// This formats identity only; it grants no access and asserts no availability.
pub fn reference_at(workspace_id: &str, revision: &str, path: &str) -> Result<String> {
    validate_id(workspace_id)?;
    validate_id(revision)?;
    crate::files::validate_workspace_relative(path)?;
    const COMPONENT: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~');
    let path = path
        .split('/')
        .map(|part| percent_encoding::utf8_percent_encode(part, COMPONENT).to_string())
        .collect::<Vec<_>>()
        .join("/");
    Ok(format!(
        "maxio-workspace://{workspace_id}/{path}?revision={revision}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(path: &str) -> Snapshot {
        let manifest = Manifest {
            format: FORMAT_VERSION,
            workspace_id: uuid::Uuid::new_v4().to_string(),
            revision: uuid::Uuid::new_v4().to_string(),
            parent: None,
            files: BTreeMap::from([(
                path.to_string(),
                FileVersion {
                    sha256: "a".repeat(64),
                    size: 7,
                    blob: format!("maxio-workspaces/projects/blobs/{}", uuid::Uuid::new_v4()),
                },
            )]),
        };
        Snapshot {
            manifest_sha256: manifest_hash(&manifest).unwrap(),
            manifest,
            head_etag: Some("\"condition-token\"".into()),
        }
    }

    #[test]
    fn catalog_identity_and_local_control_paths_are_not_trusted_blindly() {
        let mut valid = snapshot("src/file.rs");
        assert!(validate_snapshot(&valid).is_ok());
        valid.manifest.files.get_mut("src/file.rs").unwrap().size += 1;
        assert!(validate_snapshot(&valid).is_err());
        for path in [
            "../escape",
            ".maxio-workspace/journal.json",
            ".git/config",
            "docs/AUX.txt",
        ] {
            assert!(validate_snapshot(&snapshot(path)).is_err(), "{path}");
        }
        let mut invalid = snapshot("src/file.rs");
        invalid.head_etag = Some("bad\r\nheader".into());
        assert!(validate_snapshot(&invalid).is_err());
    }

    #[test]
    fn version_reference_encodes_names_without_becoming_a_download_url() {
        let snapshot = snapshot("docs/café + #%.md");
        let uri = reference(&snapshot, "docs/café + #%.md").unwrap();
        assert!(uri.starts_with("maxio-workspace://"));
        assert!(uri.contains("/docs/caf%C3%A9%20%2B%20%23%25.md?revision="));
        assert!(reference(&snapshot, "absent").is_err());
    }
}

// Explicit optional authority envelopes. Direct-S3 format 1 and ETags are unchanged.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedTarget {
    pub authority_id: String,
    pub vault_id: String,
    pub workspace_id: String,
    /// Canonical HTTPS origin; no userinfo, path, query or fragment.
    pub origin: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedHead {
    pub authority_id: String,
    pub workspace_id: String,
    pub generation: u64,
    pub revision: RevisionRef,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCatalog {
    /// Canonical existing shape. head_etag MUST be None in managed mode.
    pub snapshot: Snapshot,
    /// Some only for the current managed publication base; None for history.
    pub head: Option<ManagedHead>,
}

/// Selective hydration source. Catalog/version identity stays canonical; adapters
/// implement only transport and authorization. Editable baselines stay local.
pub trait WorkspaceReader: Send + Sync {
    fn target_id(&self) -> String;
    fn download_at<'a>(
        &'a self,
        snapshot: &'a Snapshot,
        path: &'a str,
        destination: &'a std::path::Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;
}

pub fn managed_target_id(target: &ManagedTarget) -> Result<String> {
    validate_id(&target.authority_id)?;
    validate_id(&target.vault_id)?;
    validate_id(&target.workspace_id)?;
    let origin = reqwest::Url::parse(&target.origin)?;
    ensure!(
        origin.scheme() == "https"
            && origin.host_str().is_some()
            && origin.username().is_empty()
            && origin.password().is_none()
            && origin.path() == "/"
            && origin.query().is_none()
            && origin.fragment().is_none()
            && origin.origin().ascii_serialization() == target.origin,
        "managed target must have a canonical HTTPS origin"
    );
    Ok(format!(
        "managed:{}:{}:{}:{}",
        target.authority_id, target.vault_id, target.workspace_id, target.origin
    ))
}
