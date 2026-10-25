//! Private immutable managed inputs, separate from editable workspaces and runs.
//!
//! One cooperating owner holds the manager lock. Task/user copies get independent
//! inodes. Hash/inode checks are not race protection against a malicious same UID.
mod fs;
#[cfg(test)]
mod tests;

use super::{client::FabricClient, contract::*};
use crate::execution::RunFile;
use crate::workspace::{TransferStats, validate_file_version, validate_hash, validate_id};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const MAX_STATE_BYTES: usize = 32 * 1024 * 1024;
const MAX_ENTRIES: usize = 20_000;
const MAX_GUARDS: usize = 1024;
const ROOT_MARKER: &[u8] = b"MaxIO private worker cache v1\n";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheRow {
    pub key: String,
    pub references: Vec<RetainedFile>,
    /// verified, present_unverified, missing, or modified; only verified is advertised.
    pub state: String,
    pub pinned: bool,
    pub active_attempts: Vec<String>,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheInventory {
    pub entries: Vec<CacheRow>,
    pub cached_files: Vec<CachedContent>,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HydrationReport {
    pub hydrated: Vec<RetainedFile>,
    pub reused: Vec<RetainedFile>,
    pub transfer: TransferStats,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvictionReport {
    pub operation_id: String,
    pub removed: Vec<RetainedFile>,
    pub logical_bytes_removed: u64,
    pub allocated_bytes_unlinked: u64,
    pub available_bytes_before: u64,
    pub available_bytes_after: u64,
    /// Actual observed free-space change; concurrent filesystem use may add noise.
    pub observed_available_delta: i64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    references: Vec<RetainedFile>,
    fingerprint: fs::Fingerprint,
    pins: BTreeSet<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvictionIntent {
    operation_id: String,
    entries: BTreeMap<String, fs::Fingerprint>,
    verification: RetentionVerification,
    available_before: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    format: u32,
    root: PathBuf,
    authority_id: String,
    vault_id: String,
    device_id: String,
    last_epoch: u64,
    retention_policy_version: u32,
    entries: BTreeMap<String, Entry>,
    active: BTreeMap<String, BTreeSet<String>>,
    pending: Option<EvictionIntent>,
}

/// A lifetime-locked manager of immutable inputs. Never adopts an editable root.
pub struct PrivateCache {
    root: PathBuf,
    state: State,
    _lock: File,
    poisoned: bool,
}

fn now_ms() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis()
        .try_into()
        .context("clock overflow")
}

fn validate_reference(file: &RetainedFile) -> Result<()> {
    validate_id(&file.workspace_id)?;
    validate_id(&file.revision.revision)?;
    validate_hash(&file.revision.sha256)?;
    crate::files::validate_workspace_relative(&file.path)?;
    validate_file_version(&file.version)
}

fn key(file: &RetainedFile) -> String {
    format!(
        "{}-{}-{}",
        file.workspace_id, file.version.sha256, file.version.size
    )
}

fn reference_id(file: &RetainedFile) -> Result<String> {
    // This is a bounded metadata identity, not a pathname or capability.
    Ok(serde_json::to_string(file)?)
}

fn selected(files: &[RetainedFile]) -> Result<Vec<RetainedFile>> {
    ensure!(
        !files.is_empty() && files.len() <= MAX_ENTRIES,
        "select 1 to 20,000 explicit managed files"
    );
    let mut unique = BTreeMap::new();
    for file in files {
        validate_reference(file)?;
        unique.insert(reference_id(file)?, file.clone());
    }
    Ok(unique.into_values().collect())
}

fn validate_state(state: &State) -> Result<()> {
    ensure!(
        state.format == FABRIC_FORMAT,
        "unsupported private cache format"
    );
    for id in [&state.authority_id, &state.vault_id, &state.device_id] {
        validate_id(id)?;
    }
    ensure!(
        state.root.is_absolute() && state.last_epoch > 0 && state.retention_policy_version > 0,
        "invalid private cache authority binding"
    );
    ensure!(
        state.entries.len() <= MAX_ENTRIES && state.active.len() <= MAX_GUARDS,
        "private cache capacity exceeded"
    );
    let mut references = 0usize;
    for (stored_key, entry) in &state.entries {
        ensure!(
            !entry.references.is_empty(),
            "cache entry has no provenance"
        );
        let mut identities = BTreeSet::new();
        for file in &entry.references {
            validate_reference(file)?;
            ensure!(
                &key(file) == stored_key,
                "cache content key does not match provenance"
            );
            ensure!(
                file.version.size == entry.fingerprint.size,
                "cache fingerprint length mismatch"
            );
            ensure!(
                identities.insert(reference_id(file)?),
                "duplicate cache provenance"
            );
        }
        ensure!(
            entry.pins.is_subset(&identities),
            "cache pin has no provenance"
        );
        references = references
            .checked_add(entry.references.len())
            .context("cache reference overflow")?;
    }
    ensure!(
        references <= MAX_ENTRIES,
        "cache provenance capacity exceeded"
    );
    for (attempt, keys) in &state.active {
        validate_id(attempt)?;
        ensure!(
            keys.len() <= MAX_ENTRIES,
            "active cache guard capacity exceeded"
        );
        for key in keys {
            crate::files::validate_relative(key)?;
        }
    }
    if let Some(intent) = &state.pending {
        validate_id(&intent.operation_id)?;
        ensure!(!intent.entries.is_empty(), "empty eviction intent");
        for (key, fingerprint) in &intent.entries {
            let entry = state
                .entries
                .get(key)
                .context("eviction intent has no indexed entry")?;
            ensure!(
                &entry.fingerprint == fingerprint,
                "eviction intent fingerprint differs from index"
            );
        }
    }
    Ok(())
}

impl PrivateCache {
    pub fn open(root: &Path, authority: &AuthorityInfo, device_id: &str) -> Result<Self> {
        ensure!(
            authority.format == FABRIC_FORMAT
                && authority.epoch > 0
                && authority.retention_policy_version > 0,
            "invalid managed authority metadata"
        );
        for id in [
            authority.authority_id.as_str(),
            authority.vault_id.as_str(),
            device_id,
        ] {
            validate_id(id)?;
        }
        Self::open_inner(root, Some((authority, device_id)))
    }

    /// Inspect and manage already retained local bytes without contacting authority.
    /// An offline open cannot initialize a root or mint retention permission.
    pub fn open_offline(root: &Path) -> Result<Self> {
        let metadata =
            std::fs::symlink_metadata(root).context("offline cache root must already exist")?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "offline cache root is not an ordinary directory"
        );
        Self::open_inner(root, None)
    }

    fn open_inner(root: &Path, binding: Option<(&AuthorityInfo, &str)>) -> Result<Self> {
        let root = fs::cache_root(root)?;
        let lock_path = root.join("manager.lock");
        if let Ok(meta) = std::fs::symlink_metadata(&lock_path) {
            ensure!(
                meta.is_file() && !meta.file_type().is_symlink(),
                "invalid cache manager lock"
            );
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let lock = options.open(lock_path)?;
        fs2::FileExt::try_lock_exclusive(&lock)
            .context("another manager owns this private cache")?;
        let state_path = root.join("cache/state.json");
        let created = !state_path.try_exists()?;
        let marker_path = root.join(".maxio-worker");
        if !created {
            let before = fs::fingerprint(&marker_path)
                .context("private cache type marker is missing or invalid; preserve this root")?;
            ensure!(
                before.size == ROOT_MARKER.len() as u64 && before.links == 1,
                "invalid private cache type marker; preserve this root"
            );
            let mut bytes = vec![0; ROOT_MARKER.len()];
            File::open(&marker_path)?.read_exact(&mut bytes)?;
            ensure!(
                bytes == ROOT_MARKER && fs::fingerprint(&marker_path)? == before,
                "private cache type marker changed; preserve this root"
            );
        }
        let mut state: State = if created {
            let (authority, device_id) = binding
                .context("offline cache has no persisted binding; initialize it online first")?;
            for entry in std::fs::read_dir(&root)? {
                ensure!(
                    entry?.file_name() == "manager.lock",
                    "nonempty root without private cache state; preserve it rather than adopt/reset"
                );
            }
            let mut marker = crate::files::new_file(&marker_path)?;
            marker.write_all(ROOT_MARKER)?;
            marker.sync_all()?;
            crate::files::sync_directory(&root)?;
            fs::directory(&root.join("cache"))?;
            for name in ["objects", "staging", "receipts"] {
                fs::directory(&root.join("cache").join(name))?;
            }
            State {
                format: FABRIC_FORMAT,
                root: root.clone(),
                authority_id: authority.authority_id.clone(),
                vault_id: authority.vault_id.clone(),
                device_id: device_id.into(),
                last_epoch: authority.epoch,
                retention_policy_version: authority.retention_policy_version,
                entries: BTreeMap::new(),
                active: BTreeMap::new(),
                pending: None,
            }
        } else {
            for name in ["cache", "cache/objects", "cache/staging", "cache/receipts"] {
                fs::directory(&root.join(name))?;
            }
            fs::read_json(&state_path, MAX_STATE_BYTES)?
        };
        validate_state(&state)?;
        ensure!(
            state.root == root,
            "private cache belongs to a different local root"
        );
        if let Some((authority, device_id)) = binding {
            ensure!(
                state.authority_id == authority.authority_id
                    && state.vault_id == authority.vault_id
                    && state.device_id == device_id,
                "private cache belongs to a different authority, vault or device"
            );
            ensure!(
                authority.epoch >= state.last_epoch
                    && authority.retention_policy_version == state.retention_policy_version,
                "authority epoch/policy regressed or changed; preserve cache for explicit recovery"
            );
            state.last_epoch = authority.epoch;
        }
        let mut cache = Self {
            root,
            state,
            _lock: lock,
            poisoned: false,
        };
        if cache.state.pending.is_some() {
            cache.recover_pending()?;
        }
        let state = cache.state.clone();
        cache.save(state)?;
        Ok(cache)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn object(&self, key: &str) -> PathBuf {
        self.root.join("cache/objects").join(key)
    }

    fn check_layout(&self) -> Result<()> {
        for directory in [
            self.root.clone(),
            self.root.join("cache"),
            self.root.join("cache/objects"),
            self.root.join("cache/staging"),
            self.root.join("cache/receipts"),
        ] {
            let meta = std::fs::symlink_metadata(directory)?;
            ensure!(
                meta.is_dir() && !meta.file_type().is_symlink(),
                "private cache directory changed; preserve it"
            );
        }
        Ok(())
    }

    fn mutable(&self) -> Result<()> {
        self.check_layout()?;
        ensure!(
            !self.poisoned && self.state.pending.is_none(),
            "cache mutation is uncertain; close and reopen for recovery"
        );
        Ok(())
    }

    fn save(&mut self, next: State) -> Result<()> {
        validate_state(&next)?;
        match fs::json(&self.root.join("cache/state.json"), &next, MAX_STATE_BYTES) {
            Ok(()) => {
                self.state = next;
                Ok(())
            }
            Err(error) => {
                self.poisoned = true;
                Err(error.context("cache persistence uncertain; retained files require reopen"))
            }
        }
    }

    fn verified(&self, key: &str, entry: &Entry) -> Result<fs::Fingerprint> {
        let file = &entry.references[0];
        let fingerprint = fs::verify(&self.object(key), &file.version.sha256, file.version.size)?;
        ensure!(
            fingerprint == entry.fingerprint,
            "cache inode differs from its committed index; preserve it"
        );
        Ok(fingerprint)
    }

    pub fn inventory(&self, verify: bool) -> Result<CacheInventory> {
        self.check_layout()?;
        let mut report = CacheInventory {
            entries: Vec::new(),
            cached_files: Vec::new(),
            logical_bytes: 0,
            allocated_bytes: 0,
        };
        for (key, entry) in &self.state.entries {
            let actual = fs::fingerprint(&self.object(key));
            let state = match &actual {
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
                {
                    "missing"
                }
                Err(_) => "modified",
                Ok(fingerprint) if fingerprint != &entry.fingerprint || fingerprint.links != 1 => {
                    "modified"
                }
                Ok(_) if !verify => "present_unverified",
                Ok(_) if self.verified(key, entry).is_ok() => "verified",
                Ok(_) => "modified",
            };
            let allocated = actual
                .as_ref()
                .map(|fingerprint| fingerprint.allocated_bytes)
                .unwrap_or_default();
            let size = actual
                .as_ref()
                .map(|fingerprint| fingerprint.size)
                .unwrap_or_default();
            report.logical_bytes = report
                .logical_bytes
                .checked_add(size)
                .context("inventory size overflow")?;
            report.allocated_bytes = report
                .allocated_bytes
                .checked_add(allocated)
                .context("inventory allocation overflow")?;
            if state == "verified" {
                // Authority locality is keyed by workspace/hash/size, as is this cache.
                let file = &entry.references[0];
                report.cached_files.push(CachedContent {
                    workspace_id: file.workspace_id.clone(),
                    version: file.version.clone(),
                });
            }
            report.entries.push(CacheRow {
                key: key.clone(),
                references: entry.references.clone(),
                state: state.into(),
                pinned: !entry.pins.is_empty(),
                active_attempts: self
                    .state
                    .active
                    .iter()
                    .filter(|(_, keys)| keys.contains(key))
                    .map(|(id, _)| id.clone())
                    .collect(),
                logical_bytes: size,
                allocated_bytes: allocated,
            });
        }
        Ok(report)
    }

    fn remember(&mut self, file: &RetainedFile) -> Result<()> {
        let mut next = self.state.clone();
        let entry = next
            .entries
            .get_mut(&key(file))
            .context("cache content is absent")?;
        let identity = reference_id(file)?;
        if !entry
            .references
            .iter()
            .any(|known| reference_id(known).ok().as_ref() == Some(&identity))
        {
            entry.references.push(file.clone());
            self.save(next)?;
        }
        Ok(())
    }

    fn stage(&self) -> Result<PathBuf> {
        let directory = self
            .root
            .join("cache/staging")
            .join(uuid::Uuid::new_v4().to_string());
        fs::directory(&directory)?;
        Ok(directory.join("payload"))
    }

    fn install(&mut self, file: &RetainedFile, stage: &Path) -> Result<()> {
        let key = key(file);
        let fingerprint = fs::verify(stage, &file.version.sha256, file.version.size)?;
        ensure!(
            !self.object(&key).try_exists()?,
            "unindexed cache path already exists; preserve it"
        );
        ensure!(
            self.state.entries.len() < MAX_ENTRIES,
            "private cache entry capacity exceeded"
        );
        let mut next = self.state.clone();
        next.entries.insert(
            key.clone(),
            Entry {
                references: vec![file.clone()],
                fingerprint,
                pins: BTreeSet::new(),
            },
        );
        validate_state(&next)?;
        ensure!(
            serde_json::to_vec(&next)?.len() <= MAX_STATE_BYTES,
            "private cache metadata capacity exceeded"
        );
        // No cooperating writer can create this path while the manager owns its lock.
        std::fs::rename(stage, self.object(&key))?;
        self.poisoned = true;
        let installed = (|| -> Result<()> {
            crate::files::sync_directory(&self.root.join("cache/objects"))?;
            // Rename may change inode ctime; record the installed identity.
            next.entries
                .get_mut(&key)
                .context("installed cache entry is absent from the prepared index; preserve bytes for recovery")?
                .fingerprint =
                fs::verify(&self.object(&key), &file.version.sha256, file.version.size)?;
            self.save(next)
        })();
        if installed.is_ok() {
            self.poisoned = false;
        }
        installed
    }

    pub fn import(&mut self, file: &RetainedFile, source: &Path) -> Result<()> {
        self.mutable()?;
        validate_reference(file)?;
        let key = key(file);
        if let Some(entry) = self.state.entries.get(&key) {
            self.verified(&key, entry)?;
            return self.remember(file);
        }
        let stage = self.stage()?;
        fs::json(&stage.with_extension("json"), file, MAX_STATE_BYTES)?;
        fs::copy_verified(source, &stage, &file.version.sha256, file.version.size).with_context(
            || format!("cache import failed; stage retained at {}", stage.display()),
        )?;
        self.install(file, &stage)
    }

    pub async fn hydrate(
        &mut self,
        client: &FabricClient,
        files: &[RetainedFile],
        attempt: Option<&AttemptBinding>,
    ) -> Result<HydrationReport> {
        self.mutable()?;
        let files = selected(files)?;
        let before = client.stats();
        let mut report = HydrationReport {
            hydrated: Vec::new(),
            reused: Vec::new(),
            transfer: TransferStats::default(),
        };
        for file in files {
            let key = key(&file);
            if let Some(entry) = self.state.entries.get(&key) {
                self.verified(&key, entry)?;
                self.remember(&file)?;
                report.reused.push(file);
                continue;
            }
            let stage = self.stage()?;
            fs::json(&stage.with_extension("json"), &file, MAX_STATE_BYTES)?;
            client
                .download(
                    &FileRequest {
                        workspace_id: file.workspace_id.clone(),
                        revision: file.revision.clone(),
                        path: file.path.clone(),
                        expected: file.version.clone(),
                        attempt: attempt.cloned(),
                    },
                    &stage,
                )
                .await
                .with_context(|| {
                    format!(
                        "cache hydration incomplete; stage retained at {}",
                        stage.display()
                    )
                })?;
            self.install(&file, &stage)?;
            report.hydrated.push(file);
        }
        let after = client.stats();
        report.transfer = TransferStats {
            payload_uploaded: after
                .payload_uploaded
                .saturating_sub(before.payload_uploaded),
            payload_downloaded: after
                .payload_downloaded
                .saturating_sub(before.payload_downloaded),
            metadata_uploaded: after
                .metadata_uploaded
                .saturating_sub(before.metadata_uploaded),
            metadata_downloaded: after
                .metadata_downloaded
                .saturating_sub(before.metadata_downloaded),
        };
        Ok(report)
    }

    pub fn copy_to(&self, files: &[RetainedFile], destination: &Path) -> Result<Vec<RunFile>> {
        self.check_layout()?;
        ensure!(
            !self.poisoned,
            "cache persistence is uncertain; reopen before use"
        );
        let files = selected(files)?;
        let paths: Vec<_> = files.iter().map(|file| file.path.clone()).collect();
        crate::files::validate_workspace_paths(paths.iter())?;
        ensure!(
            paths.iter().collect::<BTreeSet<_>>().len() == paths.len(),
            "selected inputs reuse a logical path"
        );
        let destination = fs::root(destination)?;
        ensure!(
            destination != self.root && !destination.starts_with(self.root.join("cache")),
            "task/user destination overlaps private cache controls"
        );
        for file in &files {
            let key = key(file);
            let entry = self
                .state
                .entries
                .get(&key)
                .context("selected cache content is absent")?;
            self.verified(&key, entry)?;
            let target = crate::files::checked_path(&destination, &file.path, false)?;
            ensure!(
                !target.try_exists()?,
                "destination already exists; preserve its possible unpublished bytes"
            );
        }
        let mut copied = Vec::new();
        for file in files {
            let target = crate::files::checked_path(&destination, &file.path, true)?;
            fs::copy_verified(
                &self.object(&key(&file)),
                &target,
                &file.version.sha256,
                file.version.size,
            )?;
            copied.push(RunFile {
                path: file.path,
                sha256: file.version.sha256,
                size: file.version.size,
            });
        }
        crate::files::sync_directory(&destination)?;
        copied.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(copied)
    }

    pub fn pin(&mut self, files: &[RetainedFile], value: bool) -> Result<()> {
        self.mutable()?;
        let files = selected(files)?;
        for file in &files {
            let key = key(file);
            let entry = self
                .state
                .entries
                .get(&key)
                .context("hydrate/import selected content before pinning")?;
            self.verified(&key, entry)?;
        }
        let mut next = self.state.clone();
        for file in &files {
            let entry = next.entries.get_mut(&key(file)).context(
                "validated pin target is absent from the prepared index; cache bytes preserved",
            )?;
            let id = reference_id(file)?;
            if value {
                if !entry
                    .references
                    .iter()
                    .any(|known| reference_id(known).ok().as_ref() == Some(&id))
                {
                    entry.references.push(file.clone());
                }
                entry.pins.insert(id);
            } else {
                entry.pins.remove(&id);
            }
        }
        self.save(next)
    }

    pub fn protect(&mut self, attempt_id: &str, files: &[RetainedFile]) -> Result<()> {
        self.mutable()?;
        validate_id(attempt_id)?;
        let keys = if files.is_empty() {
            BTreeSet::new()
        } else {
            selected(files)?.iter().map(key).collect()
        };
        let mut next = self.state.clone();
        if let Some(existing) = next.active.get(attempt_id) {
            ensure!(existing == &keys, "attempt cache selection cannot change");
            return Ok(());
        }
        ensure!(
            next.active.len() < MAX_GUARDS,
            "active-use guard capacity exceeded"
        );
        next.active.insert(attempt_id.into(), keys);
        self.save(next)
    }

    /// Caller first confirms terminal execution or reconciles retained abandoned copies.
    pub fn release(&mut self, attempt_id: &str) -> Result<()> {
        self.mutable()?;
        validate_id(attempt_id)?;
        let mut next = self.state.clone();
        next.active.remove(attempt_id);
        self.save(next)
    }

    fn evictable(&self, files: &[RetainedFile]) -> Result<BTreeMap<String, fs::Fingerprint>> {
        self.mutable()?;
        let mut candidates = BTreeMap::new();
        for file in files {
            let key = key(file);
            let entry = self
                .state
                .entries
                .get(&key)
                .context("selected eviction entry is absent")?;
            ensure!(entry.pins.is_empty(), "selected cache content is pinned");
            ensure!(
                !self.state.active.values().any(|keys| keys.contains(&key)),
                "selected cache content has active or unreconciled attempt use"
            );
            candidates.insert(key.clone(), self.verified(&key, entry)?);
        }
        Ok(candidates)
    }

    pub async fn evict(
        &mut self,
        client: &FabricClient,
        files: &[RetainedFile],
    ) -> Result<EvictionReport> {
        let files = selected(files)?;
        self.evictable(&files)?;
        let proof = client
            .verify_retention(&files)
            .await
            .context("fresh retained-vault verification unavailable; local cache preserved")?;
        self.evict_verified(&files, proof)
    }

    fn check_proof(&self, files: &[RetainedFile], proof: &RetentionVerification) -> Result<()> {
        let now = now_ms()?;
        ensure!(
            proof.authority_id == self.state.authority_id
                && proof.vault_id == self.state.vault_id
                && proof.epoch >= self.state.last_epoch,
            "retention proof belongs to a different or stale authority/vault"
        );
        ensure!(
            !proof.challenge.is_empty() && proof.challenge.len() <= 1024,
            "invalid retention challenge binding"
        );
        ensure!(
            proof.verified_at_unix_ms <= now && now < proof.valid_until_unix_ms,
            "retention proof expired or is not yet valid"
        );
        let expected: BTreeSet<_> = files.iter().map(reference_id).collect::<Result<_>>()?;
        let mut actual = BTreeSet::new();
        for receipt in &proof.receipts {
            ensure!(
                receipt.authority_id == self.state.authority_id
                    && receipt.vault_id == self.state.vault_id
                    && receipt.policy == RetentionPolicy::AppendOnlyNoGc
                    && receipt.policy_version == self.state.retention_policy_version,
                "retention receipt has different authority/vault/policy"
            );
            validate_reference(&receipt.file)?;
            ensure!(
                receipt.committed_generation > 0 && !receipt.recovery_reference.is_empty(),
                "retention receipt lacks committed recovery identity"
            );
            ensure!(
                actual.insert(reference_id(&receipt.file)?),
                "duplicate retained proof selection"
            );
        }
        ensure!(
            actual == expected,
            "retention proof does not cover the exact eviction selection"
        );
        Ok(())
    }

    fn evict_verified(
        &mut self,
        files: &[RetainedFile],
        proof: VerifiedRetention,
    ) -> Result<EvictionReport> {
        let verification = proof.into_verification();
        self.check_proof(files, &verification)?;
        let entries = self.evictable(files)?;
        let intent = EvictionIntent {
            operation_id: uuid::Uuid::new_v4().to_string(),
            entries,
            verification,
            available_before: fs::available(&self.root)?,
        };
        let receipt_path = self
            .root
            .join("cache/receipts")
            .join(format!("{}.json", intent.operation_id));
        fs::json(
            &receipt_path,
            &serde_json::json!({"state":"pending", "intent":intent}),
            MAX_STATE_BYTES,
        )?;
        let mut next = self.state.clone();
        next.last_epoch = next.last_epoch.max(intent.verification.epoch);
        next.pending = Some(intent.clone());
        self.save(next)?;
        self.poisoned = true;
        for (key, fingerprint) in &intent.entries {
            self.check_proof(files, &intent.verification)?;
            let entry = self
                .state
                .entries
                .get(key)
                .context("pending entry disappeared")?;
            ensure!(
                entry.pins.is_empty() && !self.state.active.values().any(|keys| keys.contains(key)),
                "cache protection changed during eviction"
            );
            ensure!(
                &self.verified(key, entry)? == fingerprint,
                "cache inode changed before removal"
            );
            std::fs::remove_file(self.object(key))?;
            crate::files::sync_directory(&self.root.join("cache/objects"))?;
        }
        self.finish_intent(&intent, "evicted")
    }

    fn finish_intent(&mut self, intent: &EvictionIntent, outcome: &str) -> Result<EvictionReport> {
        let mut next = self.state.clone();
        let mut report = EvictionReport {
            operation_id: intent.operation_id.clone(),
            removed: Vec::new(),
            logical_bytes_removed: 0,
            allocated_bytes_unlinked: 0,
            available_bytes_before: intent.available_before,
            available_bytes_after: fs::available(&self.root)?,
            observed_available_delta: 0,
        };
        for (key, fingerprint) in &intent.entries {
            match std::fs::symlink_metadata(self.object(key)) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let entry = next
                        .entries
                        .remove(key)
                        .context("evicted content missing from index")?;
                    report.removed.extend(entry.references);
                    report.logical_bytes_removed = report
                        .logical_bytes_removed
                        .checked_add(fingerprint.size)
                        .context("removed size overflow")?;
                    report.allocated_bytes_unlinked = report
                        .allocated_bytes_unlinked
                        .checked_add(fingerprint.allocated_bytes)
                        .context("removed allocation overflow")?;
                }
                Ok(_) => {
                    let entry = next
                        .entries
                        .get(key)
                        .context("retained eviction entry missing from index")?;
                    ensure!(
                        &self.verified(key, entry)? == fingerprint,
                        "pending eviction entry changed; preserve for manual recovery"
                    );
                }
                Err(error) => return Err(error.into()),
            }
        }
        report.observed_available_delta =
            (i128::from(report.available_bytes_after) - i128::from(report.available_bytes_before))
                .clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;
        fs::json(
            &self
                .root
                .join("cache/receipts")
                .join(format!("{}.json", intent.operation_id)),
            &serde_json::json!({"state":outcome, "intent":intent, "report":report}),
            MAX_STATE_BYTES,
        )?;
        next.pending = None;
        self.save(next)?;
        self.poisoned = false;
        Ok(report)
    }

    fn recover_pending(&mut self) -> Result<()> {
        let intent = self
            .state
            .pending
            .clone()
            .context("missing pending eviction")?;
        self.poisoned = true;
        self.finish_intent(&intent, "interrupted_reconciled")?;
        Ok(())
    }
}
