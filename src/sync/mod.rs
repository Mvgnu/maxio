//! Additive, explicitly paired folder synchronization over ordinary S3.
//!
//! This is a polling MVP, not a distributed filesystem. The peer must enforce
//! conditional PUTs. It never propagates deletions, follows symlinks, discovers
//! devices, or contacts a relay. Every replacement retains the previous local
//! inode under `.maxio-sync/<scope>/history/`; operators manage that history.
//! The local directory is trusted: hostile concurrent parent/symlink replacement
//! requires an OS capability-based filesystem boundary beyond this MVP.

mod local;
mod peer;

use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use local::{Baseline, Journal};
use peer::Peer;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Connection secrets are deliberately excluded from Debug and serialization.
pub struct SyncOptions {
    pub local: PathBuf,
    pub endpoint: String,
    /// Optional explicit PEM roots for a private HTTPS peer; system trust otherwise.
    pub ca_cert: Option<PathBuf>,
    pub bucket: String,
    pub prefix: String,
    pub access_key: String,
    pub secret_key: String,
    pub region: String,
    /// Whole-file memory bound; large-file multipart/delta sync is not implemented.
    pub max_file_bytes: u64,
}

#[derive(Default, Debug, Serialize)]
pub struct SyncReport {
    pub uploaded: usize,
    pub downloaded: usize,
    pub unchanged: usize,
    pub conflicts: usize,
}

pub struct Synchronizer {
    root: PathBuf,
    state: PathBuf,
    journal_path: PathBuf,
    journal: Journal,
    peer: Peer,
    max_file_bytes: u64,
    conditional_writes_verified: bool,
    _lock: File,
}

impl Synchronizer {
    pub fn open(options: SyncOptions) -> Result<Self> {
        ensure!(
            options.max_file_bytes > 0,
            "file size limit must be positive"
        );
        let metadata =
            fs::symlink_metadata(&options.local).context("local folder must already exist")?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "local folder must be a directory, not a symlink"
        );
        let root = fs::canonicalize(&options.local)?;
        ensure!(
            !root.join(".maxio-runtime").exists(),
            "choose an ordinary folder, not a MaxIO server data directory"
        );
        let peer = Peer::new(&options)?;
        let scope = peer.scope(root.to_str().context("local root must be valid UTF-8")?);
        let control = root.join(local::STATE_DIRECTORY);
        local::directory(&control)?;
        let lock_path = control.join("lock");
        if let Ok(metadata) = fs::symlink_metadata(&lock_path) {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "sync lock must be a regular file"
            );
        }
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)?;
        FileExt::try_lock_exclusive(&lock)
            .context("another synchronizer is already using this local folder")?;
        let state = control.join(local::digest(scope.as_bytes()));
        local::directory(&state)?;
        let journal_path = state.join("journal.json");
        let journal = match fs::symlink_metadata(&journal_path) {
            Ok(metadata) => {
                ensure!(
                    metadata.is_file() && !metadata.file_type().is_symlink(),
                    "sync journal must be a regular file"
                );
                ensure!(
                    metadata.len() <= 32 * 1024 * 1024,
                    "sync journal exceeds supported size"
                );
                let mut bytes = Vec::new();
                File::open(&journal_path)?
                    .take(32 * 1024 * 1024 + 1)
                    .read_to_end(&mut bytes)?;
                let journal: Journal = serde_json::from_slice(&bytes)
                    .context("invalid sync journal; refusing to forget the baseline")?;
                ensure!(
                    journal.version == 1 && journal.scope == scope,
                    "sync journal version or peer/root identity mismatch"
                );
                local::validate_path_set(journal.entries.keys())?;
                for entry in journal.entries.values() {
                    ensure!(
                        entry.sha256.len() == 64
                            && entry.sha256.bytes().all(|b| b.is_ascii_hexdigit())
                            && !entry.remote_etag.is_empty(),
                        "invalid sync journal baseline"
                    );
                }
                journal
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Journal {
                version: 1,
                scope,
                entries: BTreeMap::new(),
            },
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            root,
            state,
            journal_path,
            journal,
            peer,
            max_file_bytes: options.max_file_bytes,
            conditional_writes_verified: false,
            _lock: lock,
        })
    }

    pub fn journal_path(&self) -> &Path {
        &self.journal_path
    }

    fn unchanged_local_bytes(&self, key: &str, expected_hash: &str) -> Result<Vec<u8>> {
        let bytes = local::read(&self.root, key, self.max_file_bytes)?;
        ensure!(
            local::digest(&bytes) == expected_hash,
            "local file changed after scan: {key:?}; retry"
        );
        Ok(bytes)
    }

    fn record(&mut self, key: &str, sha256: String, remote_etag: String) -> Result<()> {
        self.journal.entries.insert(
            key.to_string(),
            Baseline {
                sha256,
                remote_etag,
            },
        );
        local::save_journal(&self.journal_path, &self.journal)
    }

    pub async fn run_once(&mut self) -> Result<SyncReport> {
        // Complete both scans before any remote probe or user-data mutation. A
        // truncated/error response is never interpreted as a missing object.
        let local_files = local::scan(&self.root, self.max_file_bytes)?;
        let remote_files = self.peer.list().await?;
        let keys: BTreeSet<_> = local_files
            .keys()
            .chain(remote_files.keys())
            .cloned()
            .collect();
        local::validate_path_set(keys.iter())?;
        if !self.conditional_writes_verified {
            self.peer.verify_conditional_writes().await?;
            self.conditional_writes_verified = true;
        }
        let mut report = SyncReport::default();
        for key in keys {
            match (local_files.get(&key), remote_files.get(&key)) {
                (Some(hash), None) => {
                    // A remote deletion does not delete the local survivor.
                    let bytes = self.unchanged_local_bytes(&key, hash)?;
                    let etag = self.peer.put(&key, &bytes, None).await?;
                    self.record(&key, hash.clone(), etag)?;
                    report.uploaded += 1;
                }
                (None, Some(remote)) => {
                    // A local deletion does not delete the remote survivor.
                    let bytes = self.peer.get(&key, &remote.etag).await?;
                    local::install(
                        &self.root,
                        &self.state,
                        &key,
                        &bytes,
                        None,
                        self.max_file_bytes,
                    )?;
                    self.record(&key, local::digest(&bytes), remote.etag.clone())?;
                    report.downloaded += 1;
                }
                (Some(hash), Some(remote)) => {
                    let baseline = self.journal.entries.get(&key);
                    let local_unchanged = baseline.is_some_and(|b| b.sha256 == *hash);
                    let remote_unchanged = baseline.is_some_and(|b| b.remote_etag == remote.etag);
                    if local_unchanged && remote_unchanged {
                        report.unchanged += 1;
                        continue;
                    }
                    if remote_unchanged {
                        let bytes = self.unchanged_local_bytes(&key, hash)?;
                        let etag = self.peer.put(&key, &bytes, Some(&remote.etag)).await?;
                        self.record(&key, hash.clone(), etag)?;
                        report.uploaded += 1;
                        continue;
                    }
                    let remote_bytes = self.peer.get(&key, &remote.etag).await?;
                    let remote_hash = local::digest(&remote_bytes);
                    if remote_hash == *hash {
                        self.record(&key, hash.clone(), remote.etag.clone())?;
                        report.unchanged += 1;
                        continue;
                    }
                    if !local_unchanged {
                        // First contact with different contents is also a conflict.
                        // Preserve and publish the local bytes under a deterministic
                        // sibling name before accepting the peer's main pathname.
                        let bytes = self.unchanged_local_bytes(&key, hash)?;
                        let sibling = local::conflict_key(&key, hash);
                        local::validate_relative(&sibling)?;
                        let sibling_path = local::checked_path(&self.root, &sibling, true)?;
                        if sibling_path.exists() {
                            ensure!(
                                local::digest(&local::read(
                                    &self.root,
                                    &sibling,
                                    self.max_file_bytes
                                )?) == *hash,
                                "conflict sibling already contains different bytes: {sibling:?}"
                            );
                        } else {
                            local::install(
                                &self.root,
                                &self.state,
                                &sibling,
                                &bytes,
                                None,
                                self.max_file_bytes,
                            )?;
                        }
                        let sibling_etag = if let Some(existing) = remote_files.get(&sibling) {
                            ensure!(
                                local::digest(&self.peer.get(&sibling, &existing.etag).await?)
                                    == *hash,
                                "peer conflict sibling already contains different bytes: {sibling:?}"
                            );
                            existing.etag.clone()
                        } else {
                            let etag = self.peer.put(&sibling, &bytes, None).await?;
                            report.uploaded += 1;
                            etag
                        };
                        self.record(&sibling, hash.clone(), sibling_etag)?;
                        report.conflicts += 1;
                    }
                    local::install(
                        &self.root,
                        &self.state,
                        &key,
                        &remote_bytes,
                        Some(hash),
                        self.max_file_bytes,
                    )?;
                    self.record(&key, remote_hash, remote.etag.clone())?;
                    report.downloaded += 1;
                }
                (None, None) => {}
            }
        }
        Ok(report)
    }
}
