//! Selective workspace publication over an explicitly configured S3 endpoint.
//!
//! Unique immutable objects precede one conditional head update. A successful
//! readback proves content availability, not retention or physical durability.
use super::contract::*;
use anyhow::{Context, Result, bail, ensure};
use object_store::{ObjectStore, PutMode, UpdateVersion};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::OnceCell;
use uuid::Uuid;

#[cfg(test)]
mod tests;
mod transport;

const MAX_HEAD_BYTES: usize = 4096;
const MAX_HISTORY_REVISIONS: usize = 256;
const MAX_HISTORY_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    format: u32,
    workspace_id: String,
    current: RevisionRef,
}

/// Contains credentials through the SDK; deliberately neither Debug nor Serialize.
pub struct WorkspaceRemote {
    store: Arc<dyn ObjectStore>,
    target: String,
    prefix: String,
    counters: transport::Counters,
    conditional_verified: OnceCell<()>,
}

impl WorkspaceRemote {
    pub fn connect(config: RemoteConfig) -> Result<Self> {
        let (store, target, prefix) = transport::connect(config)?;
        Ok(Self {
            store,
            target,
            prefix,
            counters: transport::Counters::default(),
            conditional_verified: OnceCell::new(),
        })
    }

    pub fn target_id(&self) -> String {
        self.target.clone()
    }

    pub fn stats(&self) -> TransferStats {
        self.counters.snapshot()
    }

    pub async fn initialize(&self) -> Result<Snapshot> {
        match self.read_metadata(&self.head_key(), MAX_HEAD_BYTES).await {
            Ok(_) => bail!("workspace already exists; refresh it instead of initializing"),
            Err(error) if transport::not_found(&error) => {}
            Err(error) => return Err(error.context("cannot establish that workspace is absent")),
        }
        self.check_conditions().await?;
        let manifest = Manifest {
            format: FORMAT_VERSION,
            workspace_id: Uuid::new_v4().to_string(),
            revision: Uuid::new_v4().to_string(),
            parent: None,
            files: BTreeMap::new(),
        };
        let snapshot = self.write_revision(manifest).await?;
        self.commit_head(snapshot, PutMode::Create).await
    }

    pub async fn latest(&self) -> Result<Snapshot> {
        let (head, etag) = self.read_head().await?;
        let (mut snapshot, _) = self
            .read_revision(&head.current, &head.workspace_id)
            .await?;
        snapshot.head_etag = Some(etag);
        validate_snapshot(&snapshot)?;
        Ok(snapshot)
    }

    /// Only revisions reachable from the current authoritative head are visible.
    pub async fn revision(&self, revision: &str) -> Result<Snapshot> {
        validate_id(revision)?;
        let (head, _) = self.read_head().await?;
        let mut next = Some(head.current);
        let mut visited = BTreeSet::new();
        let mut bytes = 0usize;
        while let Some(reference) = next {
            ensure!(
                visited.len() < MAX_HISTORY_REVISIONS,
                "history traversal exceeds 256 revisions; older history is retained but not resolved"
            );
            ensure!(
                visited.insert(reference.revision.clone()),
                "workspace history contains a cycle"
            );
            ensure!(
                bytes < MAX_HISTORY_BYTES,
                "history traversal exceeds 64 MiB; older history is retained but not resolved"
            );
            let remaining = MAX_MANIFEST_BYTES.min(MAX_HISTORY_BYTES - bytes);
            let (snapshot, length) = self
                .read_revision_with_limit(&reference, &head.workspace_id, remaining)
                .await?;
            bytes = bytes.checked_add(length).context("history size overflow")?;
            ensure!(
                bytes <= MAX_HISTORY_BYTES,
                "history traversal exceeds 64 MiB; older history is retained but not resolved"
            );
            if snapshot.manifest.revision == revision {
                return Ok(snapshot);
            }
            next = snapshot.manifest.parent;
        }
        bail!("revision is not reachable from the published workspace head")
    }

    pub async fn publish(&self, base: &Snapshot, files: &[Publication]) -> Result<Snapshot> {
        self.validate_scoped_snapshot(base)?;
        let etag = base.head_etag.as_ref().context(
            "historical snapshots cannot be publication bases; refresh the current head",
        )?;
        ensure!(
            !files.is_empty(),
            "publication requires at least one selected file"
        );
        let mut manifest = Manifest {
            format: FORMAT_VERSION,
            workspace_id: base.manifest.workspace_id.clone(),
            revision: Uuid::new_v4().to_string(),
            parent: Some(RevisionRef {
                revision: base.manifest.revision.clone(),
                sha256: base.manifest_sha256.clone(),
            }),
            files: base.manifest.files.clone(),
        };
        let mut paths = BTreeSet::new();
        let mut versions = Vec::with_capacity(files.len());
        for file in files {
            crate::files::validate_workspace_relative(&file.path)?;
            validate_hash(&file.sha256)?;
            ensure!(
                paths.insert(&file.path),
                "publication contains a duplicate path"
            );
            transport::validate_source(file).await?;
            let version = FileVersion {
                sha256: file.sha256.clone(),
                size: file.size,
                blob: format!("{}blobs/{}", self.prefix, Uuid::new_v4()),
            };
            manifest.files.insert(file.path.clone(), version.clone());
            versions.push(version);
        }
        self.validate_scoped_snapshot(&Snapshot {
            manifest_sha256: manifest_hash(&manifest)?,
            manifest: manifest.clone(),
            head_etag: None,
        })?;
        let current = self.latest().await?;
        ensure!(
            same_revision(&current, base) && current.head_etag == base.head_etag,
            "publication conflict: base is stale; refresh and reconcile; staged files are retained"
        );
        self.check_conditions().await?;
        for (file, version) in files.iter().zip(&versions) {
            self.upload_blob(file, version).await?;
            self.read_blob(version, None)
                .await
                .context("uploaded content could not be verified; staged files are retained")?;
        }
        let snapshot = self.write_revision(manifest).await?;
        self.commit_head(
            snapshot,
            PutMode::Update(UpdateVersion {
                e_tag: Some(etag.clone()),
                version: None,
            }),
        )
        .await
    }

    /// Creates a fresh staging file. Any failed partial file is retained for recovery.
    pub async fn download(&self, file: &FileVersion, destination: &Path) -> Result<()> {
        self.validate_blob(file)?;
        let staging = crate::files::new_file(destination)
            .context("download requires a new, nonexistent staging file")?;
        let mut staging = tokio::fs::File::from_std(staging);
        let transfer = self.read_blob(file, Some(&mut staging)).await;
        // Tokio files buffer a pending write. Drain it even after a hash/network
        // failure so that the retained stage contains the bytes actually received.
        let persisted = staging.sync_all().await;
        let parent_synced = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(crate::files::sync_directory)
            .transpose();
        if let Err(error) = transfer {
            let mut error =
                error.context("download incomplete or unverified; staging file retained");
            if let Err(sync_error) = persisted {
                error = error.context(format!(
                    "partial staging file could not be fsynced: {sync_error}"
                ));
            }
            if let Err(sync_error) = parent_synced {
                error = error.context(format!(
                    "staging directory could not be fsynced: {sync_error}"
                ));
            }
            return Err(error);
        }
        persisted.context("cannot fsync downloaded staging file")?;
        parent_synced?;
        Ok(())
    }

    fn head_key(&self) -> String {
        format!("{}head.json", self.prefix)
    }

    fn revision_key(&self, revision: &str) -> String {
        format!("{}revisions/{revision}.json", self.prefix)
    }

    fn validate_blob(&self, file: &FileVersion) -> Result<()> {
        validate_file_version(file)?;
        ensure!(
            file.blob.starts_with(&format!("{}blobs/", self.prefix)),
            "blob is outside the configured workspace"
        );
        Ok(())
    }

    fn validate_scoped_snapshot(&self, snapshot: &Snapshot) -> Result<()> {
        validate_snapshot(snapshot)?;
        for file in snapshot.manifest.files.values() {
            self.validate_blob(file)?;
        }
        Ok(())
    }

    async fn read_head(&self) -> Result<(Head, String)> {
        let (bytes, etag) = self.read_metadata(&self.head_key(), MAX_HEAD_BYTES).await?;
        let head: Head = serde_json::from_slice(&bytes).context("invalid workspace head")?;
        ensure!(
            head.format == FORMAT_VERSION,
            "unsupported workspace head format"
        );
        validate_id(&head.workspace_id)?;
        validate_id(&head.current.revision)?;
        validate_hash(&head.current.sha256)?;
        Ok((head, transport::required_etag(etag)?))
    }

    async fn read_revision(
        &self,
        reference: &RevisionRef,
        workspace: &str,
    ) -> Result<(Snapshot, usize)> {
        self.read_revision_with_limit(reference, workspace, MAX_MANIFEST_BYTES)
            .await
    }

    async fn read_revision_with_limit(
        &self,
        reference: &RevisionRef,
        workspace: &str,
        limit: usize,
    ) -> Result<(Snapshot, usize)> {
        validate_id(&reference.revision)?;
        validate_hash(&reference.sha256)?;
        let (bytes, _) = self
            .read_metadata(&self.revision_key(&reference.revision), limit)
            .await?;
        ensure!(
            transport::hash_bytes(&bytes) == reference.sha256,
            "published manifest SHA-256 mismatch"
        );
        let manifest: Manifest =
            serde_json::from_slice(&bytes).context("invalid workspace manifest")?;
        ensure!(
            manifest.workspace_id == workspace && manifest.revision == reference.revision,
            "manifest does not match its published workspace/revision identity"
        );
        let snapshot = Snapshot {
            manifest,
            manifest_sha256: reference.sha256.clone(),
            head_etag: None,
        };
        self.validate_scoped_snapshot(&snapshot)?;
        Ok((snapshot, bytes.len()))
    }

    async fn write_revision(&self, manifest: Manifest) -> Result<Snapshot> {
        let snapshot = Snapshot {
            manifest_sha256: manifest_hash(&manifest)?,
            manifest,
            head_etag: None,
        };
        self.validate_scoped_snapshot(&snapshot)?;
        let reference = RevisionRef {
            revision: snapshot.manifest.revision.clone(),
            sha256: snapshot.manifest_sha256.clone(),
        };
        let bytes = serde_json::to_vec(&snapshot.manifest)?;
        let written = self
            .put_metadata(
                &self.revision_key(&reference.revision),
                bytes,
                PutMode::Create,
            )
            .await;
        // An unknown PUT acknowledgment is recoverable only after exact readback.
        match self.read_revision(&reference, &snapshot.manifest.workspace_id).await {
            Ok((verified, _)) => Ok(verified),
            Err(read_error) => match written {
                Ok(_) => Err(read_error.context("manifest readback failed; staged files are retained")),
                Err(write_error) => Err(write_error.context(format!(
                    "manifest publication outcome unverified; staged files retained; readback: {read_error:#}"))),
            },
        }
    }

    async fn commit_head(&self, mut snapshot: Snapshot, mode: PutMode) -> Result<Snapshot> {
        let head = Head {
            format: FORMAT_VERSION,
            workspace_id: snapshot.manifest.workspace_id.clone(),
            current: RevisionRef {
                revision: snapshot.manifest.revision.clone(),
                sha256: snapshot.manifest_sha256.clone(),
            },
        };
        let written = self
            .put_metadata(&self.head_key(), serde_json::to_vec(&head)?, mode)
            .await;
        if let Ok(Some(etag)) = &written
            && transport::required_etag(Some(etag.clone())).is_ok()
        {
            snapshot.head_etag = Some(etag.clone());
            return Ok(snapshot);
        }
        // The conditional PUT may have committed before the connection failed.
        // A later writer can already have advanced the head, so consult ancestry too.
        if let Ok(current) = self.latest().await {
            if same_revision(&current, &snapshot) {
                return Ok(current);
            }
            if current.manifest.workspace_id == snapshot.manifest.workspace_id
                && let Ok(committed) = self.revision(&snapshot.manifest.revision).await
                && same_revision(&committed, &snapshot)
            {
                bail!(
                    "revision {} was published, but another writer has since advanced the head; refresh and recover before recording local publication; staged files are retained",
                    snapshot.manifest.revision
                );
            }
        }
        match written {
            Err(error) if transport::condition_failed(&error) => Err(error.context(format!(
                "publication conflict or unresolved acknowledgment for revision {}; refresh and reconcile; staged files are retained",
                snapshot.manifest.revision))),
            Err(error) => Err(error.context(format!(
                "publication outcome unknown for revision {}; refresh and reconcile before retrying; staged files are retained",
                snapshot.manifest.revision))),
            Ok(_) => bail!("head acknowledgment has no usable token and reconciliation failed for revision {}; staged files are retained",
                snapshot.manifest.revision),
        }
    }
}

fn same_revision(left: &Snapshot, right: &Snapshot) -> bool {
    left.manifest.workspace_id == right.manifest.workspace_id
        && left.manifest.revision == right.manifest.revision
        && left.manifest_sha256 == right.manifest_sha256
}
