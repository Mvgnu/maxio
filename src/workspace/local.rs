//! Selective, recoverable local working copies of published workspace files.
//!
//! Discovery and per-path working baselines are deliberately separate. Refreshing
//! a catalog can never turn an unpublished local edit into a published baseline.
mod staging;
#[cfg(test)]
mod tests;

use super::{WorkspaceRemote, contract::*};
use crate::files;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_STATE_BYTES: usize = MAX_MANIFEST_BYTES * 4;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Baseline {
    revision: String,
    file: FileVersion,
    pinned: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalState {
    format: u32,
    root: PathBuf,
    target_id: String,
    observed: Option<Snapshot>,
    baselines: BTreeMap<String, Baseline>,
}

pub struct LocalWorkspace {
    root: PathBuf,
    control: PathBuf,
    state: LocalState,
    _lock: File,
}

impl LocalWorkspace {
    pub fn open(root: &Path, target_id: &str) -> Result<Self> {
        ensure!(
            !target_id.is_empty()
                && target_id.len() <= 8192
                && !target_id.chars().any(char::is_control),
            "invalid workspace storage target identity"
        );
        Self::open_inner(root, Some(target_id))
    }

    /// Inspect an initialized root without storage credentials or network access.
    pub fn open_offline(root: &Path) -> Result<Self> {
        Self::open_inner(root, None)
    }

    fn open_inner(root: &Path, target_id: Option<&str>) -> Result<Self> {
        let meta = fs::symlink_metadata(root).context("workspace root must already exist")?;
        ensure!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "workspace root must be a regular directory, not a symlink"
        );
        let root = fs::canonicalize(root)?;
        ensure!(
            !root.join(".maxio-runtime").try_exists()?,
            "a MaxIO server data directory cannot be a workspace root"
        );
        for entry in fs::read_dir(&root)? {
            let name = entry?.file_name();
            if let Some(name) = name.to_str() {
                ensure!(
                    !name.eq_ignore_ascii_case(STATE_DIRECTORY) || name == STATE_DIRECTORY,
                    "case-colliding workspace control directory"
                );
            }
        }
        let control = root.join(STATE_DIRECTORY);
        if target_id.is_none() {
            let meta = fs::symlink_metadata(&control)
                .context("workspace is not initialized; initialize or refresh it online first")?;
            ensure!(
                meta.is_dir() && !meta.file_type().is_symlink(),
                "workspace control directory is not a regular directory"
            );
        } else {
            files::directory(&control)?;
        }
        let lock_path = control.join("lock");
        if let Ok(meta) = fs::symlink_metadata(&lock_path) {
            ensure!(
                meta.is_file() && !meta.file_type().is_symlink(),
                "workspace lock is not a regular file"
            );
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(&lock_path)?;
        fs2::FileExt::try_lock_exclusive(&lock)
            .context("another MaxIO operation owns this workspace root")?;
        let state_path = control.join("state.json");
        let (state, created) = match fs::symlink_metadata(&state_path) {
            Ok(meta) => {
                ensure!(
                    meta.is_file() && !meta.file_type().is_symlink(),
                    "workspace state is not a regular file"
                );
                ensure!(
                    meta.len() <= MAX_STATE_BYTES as u64,
                    "workspace state exceeds the size limit"
                );
                let mut bytes = Vec::new();
                File::open(&state_path)?
                    .take(MAX_STATE_BYTES as u64 + 1)
                    .read_to_end(&mut bytes)?;
                ensure!(
                    bytes.len() <= MAX_STATE_BYTES,
                    "workspace state grew beyond its limit"
                );
                let state: LocalState = serde_json::from_slice(&bytes).context(
                    "invalid workspace state; preserve it for recovery instead of resetting",
                )?;
                validate_state(&state)?;
                ensure!(
                    state.root == root,
                    "workspace state belongs to a different local root"
                );
                if let Some(target_id) = target_id {
                    ensure!(
                        state.target_id == target_id,
                        "workspace root is bound to a different storage target"
                    );
                } else {
                    ensure!(
                        state.observed.is_some(),
                        "workspace has no published catalog; refresh it online first"
                    );
                }
                (state, false)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let target_id = target_id.context("workspace is not initialized")?;
                (
                    LocalState {
                        format: FORMAT_VERSION,
                        root: root.clone(),
                        target_id: target_id.into(),
                        observed: None,
                        baselines: BTreeMap::new(),
                    },
                    true,
                )
            }
            Err(error) => return Err(error.into()),
        };
        let local = Self {
            root,
            control,
            state,
            _lock: lock,
        };
        if created {
            local.save(&local.state)?;
        }
        Ok(local)
    }

    fn save(&self, state: &LocalState) -> Result<()> {
        validate_state(state)?;
        let bytes = serde_json::to_vec(state)?;
        ensure!(
            bytes.len() <= MAX_STATE_BYTES,
            "workspace state exceeds the size limit"
        );
        staging::atomic_json(&self.control.join("state.json"), &bytes)
    }

    fn replace_state(&mut self, next: LocalState) -> Result<()> {
        self.save(&next)?;
        self.state = next;
        Ok(())
    }

    fn validate_identity(&self, snapshot: &Snapshot) -> Result<()> {
        validate_snapshot(snapshot)?;
        if let Some(observed) = &self.state.observed {
            ensure!(
                observed.manifest.workspace_id == snapshot.manifest.workspace_id,
                "remote workspace identity changed; refusing to rebind this working copy"
            );
        }
        Ok(())
    }

    pub fn observe(&mut self, snapshot: Snapshot) -> Result<()> {
        self.validate_identity(&snapshot)?;
        ensure!(
            snapshot.head_etag.is_some(),
            "a historical revision cannot become the current observed publication base"
        );
        let mut next = self.state.clone();
        next.observed = Some(snapshot);
        self.replace_state(next)
    }

    pub fn snapshot(&self) -> Result<Snapshot> {
        self.state
            .observed
            .clone()
            .context("workspace has no observed catalog; refresh it first")
    }

    pub fn prepare_publish(&mut self, selectors: &[String]) -> Result<Vec<Publication>> {
        let snapshot = self.snapshot()?;
        let selected = staging::selected_local_files(&self.root, selectors)?;
        let mut keys: BTreeSet<String> = snapshot.manifest.files.keys().cloned().collect();
        keys.extend(self.state.baselines.keys().cloned());
        keys.extend(selected.iter().cloned());
        files::validate_workspace_paths(keys.iter())?;
        ensure!(keys.len() <= MAX_ENTRIES, "workspace exceeds 20,000 files");
        for path in &selected {
            if let Some(published) = snapshot.manifest.files.get(path) {
                let baseline = self.state.baselines.get(path).with_context(|| {
                    format!("untracked local file cannot overwrite published path {path:?}; recover or move it first")
                })?;
                ensure!(
                    baseline.file == *published,
                    "publication conflict at {path:?}: working baseline differs from the observed published version; preserve and reconcile the edit"
                );
            } else {
                ensure!(
                    !self.state.baselines.contains_key(path),
                    "previously published path {path:?} is absent from this catalog; absence is not permission to recreate or delete it"
                );
            }
        }
        let stage = staging::operation_directory(&self.control, "publish")?;
        let mut publications = Vec::new();
        for path in selected {
            let source = staging::checked_file(&self.root, &path, false)?;
            let private = stage.join(format!("{}.data", uuid::Uuid::new_v4()));
            let note = private.with_extension("json");
            staging::write_receipt(
                &note,
                &serde_json::json!({
                    "format": FORMAT_VERSION, "operation": "publish", "path": path,
                    "base_revision": snapshot.manifest.revision, "stage": private.file_name(), "complete": false,
                }),
            )?;
            let (sha256, size) = staging::copy_verified(&source, &private).with_context(|| {
                format!(
                    "publication staging failed for {path:?}; recoverable files are in {}",
                    stage.display()
                )
            })?;
            staging::write_receipt(
                &note,
                &serde_json::json!({
                    "format": FORMAT_VERSION, "operation": "publish", "path": path,
                    "base_revision": snapshot.manifest.revision, "stage": private.file_name(),
                    "sha256": sha256, "size": size, "complete": true,
                }),
            )?;
            publications.push(Publication {
                path,
                source: private,
                sha256,
                size,
            });
        }
        Ok(publications)
    }

    pub fn accept_publication(
        &mut self,
        snapshot: Snapshot,
        publications: &[Publication],
    ) -> Result<()> {
        self.validate_identity(&snapshot)?;
        ensure!(
            snapshot.head_etag.is_some(),
            "published result has no authoritative head"
        );
        ensure!(
            !publications.is_empty(),
            "publication contains no selected files"
        );
        let previous = self.snapshot()?;
        ensure!(
            snapshot.manifest.parent.as_ref().is_some_and(|parent| {
                parent.revision == previous.manifest.revision
                    && parent.sha256 == previous.manifest_sha256
            }) || (snapshot.manifest.revision == previous.manifest.revision
                && snapshot.manifest_sha256 == previous.manifest_sha256),
            "publication result does not descend from the observed base"
        );
        let mut next = self.state.clone();
        let mut seen = BTreeSet::new();
        for publication in publications {
            files::validate_workspace_relative(&publication.path)?;
            ensure!(seen.insert(&publication.path), "duplicate publication path");
            ensure!(
                publication.source.starts_with(self.control.join("staging")),
                "publication source is not a private staging file"
            );
            let (sha256, size) = files::hash_file(&publication.source)?;
            ensure!(
                sha256 == publication.sha256 && size == publication.size,
                "publication staging changed; preserve it for recovery"
            );
            let file = snapshot
                .manifest
                .files
                .get(&publication.path)
                .context("published snapshot omitted a selected file")?;
            ensure!(
                file.sha256 == publication.sha256 && file.size == publication.size,
                "published version does not match selected staging bytes"
            );
            let pinned = next
                .baselines
                .get(&publication.path)
                .is_some_and(|base| base.pinned);
            next.baselines.insert(
                publication.path.clone(),
                Baseline {
                    revision: snapshot.manifest.revision.clone(),
                    file: file.clone(),
                    pinned,
                },
            );
        }
        next.observed = Some(snapshot);
        // The live file may have changed during upload. Only status checks it.
        self.replace_state(next)
    }

    fn current_local(&self, path: &str) -> Result<Option<(String, u64)>> {
        let destination = staging::checked_file(&self.root, path, false)?;
        match fs::symlink_metadata(&destination) {
            Ok(_) => Ok(Some(files::hash_file(&destination)?)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn replacement_baseline(&self, path: &str) -> Result<Option<(String, u64)>> {
        let current = self.current_local(path)?;
        if let Some((sha256, size)) = &current {
            let baseline = self.state.baselines.get(path).with_context(|| {
                format!("untracked local file at {path:?}; refusing hydration over it")
            })?;
            ensure!(
                baseline.file.sha256 == *sha256 && baseline.file.size == *size,
                "dirty local file at {path:?}; hydration preserves it and refuses replacement"
            );
        }
        Ok(current)
    }

    fn install_download(
        &mut self,
        snapshot: &Snapshot,
        path: &str,
        stage: &Path,
        expected: Option<&(String, u64)>,
    ) -> Result<()> {
        let file = snapshot
            .manifest
            .files
            .get(path)
            .context("download path is not in the revision")?;
        let (sha256, size) = files::hash_file(stage)?;
        ensure!(
            sha256 == file.sha256 && size == file.size,
            "download staging failed content verification"
        );
        staging::install(&self.root, &self.control, path, stage, expected)?;
        let mut next = self.state.clone();
        let pinned = next.baselines.get(path).is_some_and(|base| base.pinned);
        next.baselines.insert(
            path.into(),
            Baseline {
                revision: snapshot.manifest.revision.clone(),
                file: file.clone(),
                pinned,
            },
        );
        // Historical hydration never changes the observed catalog/publication base.
        self.replace_state(next)
    }

    pub async fn pull(
        &mut self,
        remote: &WorkspaceRemote,
        snapshot: &Snapshot,
        selectors: &[String],
    ) -> Result<Vec<String>> {
        self.snapshot()?;
        self.validate_identity(snapshot)?;
        ensure!(
            remote.target_id() == self.state.target_id,
            "download target differs from this workspace binding"
        );
        let selected = files::select_paths(snapshot.manifest.files.keys(), selectors)?;
        let mut keys: BTreeSet<String> = self.state.baselines.keys().cloned().collect();
        keys.extend(selected.iter().cloned());
        files::validate_workspace_paths(keys.iter())?;
        // Reject known conflicts before downloading any payload.
        let expected: BTreeMap<_, _> = selected
            .iter()
            .map(|path| {
                self.replacement_baseline(path)
                    .map(|base| (path.clone(), base))
            })
            .collect::<Result<_>>()?;
        let stage = staging::operation_directory(&self.control, "pull")?;
        for path in &selected {
            let file = &snapshot.manifest.files[path];
            if let Some(Some((sha256, size))) = expected.get(path)
                && *sha256 == file.sha256
                && *size == file.size
            {
                let mut next = self.state.clone();
                let pinned = next.baselines.get(path).is_some_and(|base| base.pinned);
                next.baselines.insert(
                    path.clone(),
                    Baseline {
                        revision: snapshot.manifest.revision.clone(),
                        file: file.clone(),
                        pinned,
                    },
                );
                self.replace_state(next)?;
                continue;
            }
            let destination = stage.join(format!("{}.data", uuid::Uuid::new_v4()));
            staging::write_receipt(
                &destination.with_extension("json"),
                &serde_json::json!({
                    "format": FORMAT_VERSION, "operation": "pull", "path": path,
                    "revision": snapshot.manifest.revision, "file": file, "stage": destination.file_name(),
                }),
            )?;
            remote.download(file, &destination).await.with_context(|| {
                format!(
                    "download incomplete for {path:?}; staging is retained at {}",
                    destination.display()
                )
            })?;
            self.install_download(snapshot, path, &destination, expected[path].as_ref())
                .with_context(|| {
                    format!(
                        "hydration incomplete for {path:?}; staging is retained at {}",
                        destination.display()
                    )
                })?;
        }
        Ok(selected)
    }

    pub fn describe(&self, verify_local: bool) -> Result<Vec<WorkspaceRow>> {
        let snapshot = self.snapshot()?;
        snapshot
            .manifest
            .files
            .iter()
            .map(|(path, file)| {
                let destination = staging::checked_file(&self.root, path, false)?;
                let present = match fs::symlink_metadata(&destination) {
                    Ok(_) => true,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                    Err(error) => return Err(error.into()),
                };
                let baseline = self.state.baselines.get(path);
                let state = if !present {
                    "absent"
                } else if !verify_local {
                    "present_unverified"
                } else {
                    let (sha256, size) = files::hash_file(&destination)?;
                    match baseline {
                        Some(base) if base.file.sha256 == sha256 && base.file.size == size => {
                            if base.file == *file {
                                "clean"
                            } else {
                                "stale"
                            }
                        }
                        _ => "dirty",
                    }
                };
                Ok(WorkspaceRow {
                    path: path.clone(),
                    reference: reference(&snapshot, path)?,
                    size: file.size,
                    sha256: file.sha256.clone(),
                    local_state: state.into(),
                    pinned: baseline.is_some_and(|base| base.pinned),
                })
            })
            .collect()
    }

    pub fn pin(&mut self, selectors: &[String], value: bool) -> Result<Vec<String>> {
        let snapshot = self.snapshot()?;
        let selected = files::select_paths(snapshot.manifest.files.keys(), selectors)?;
        let mut next = self.state.clone();
        for path in &selected {
            if value {
                let file = &snapshot.manifest.files[path];
                let baseline = next
                    .baselines
                    .get_mut(path)
                    .with_context(|| format!("hydrate {path:?} successfully before pinning it"))?;
                ensure!(
                    baseline.file == *file,
                    "hydrate the observed version of {path:?} before pinning it"
                );
                ensure!(
                    self.current_local(path)? == Some((file.sha256.clone(), file.size)),
                    "cannot pin absent, dirty or unverified bytes at {path:?}"
                );
                baseline.pinned = true;
            } else if let Some(baseline) = next.baselines.get_mut(path) {
                baseline.pinned = false;
            }
        }
        self.replace_state(next)?;
        Ok(selected)
    }
}

fn validate_state(state: &LocalState) -> Result<()> {
    ensure!(
        state.format == FORMAT_VERSION,
        "unsupported local workspace state format"
    );
    ensure!(
        state.root.is_absolute(),
        "workspace state root is not absolute"
    );
    ensure!(
        !state.target_id.is_empty()
            && state.target_id.len() <= 8192
            && !state.target_id.chars().any(char::is_control),
        "invalid persisted workspace target"
    );
    ensure!(
        state.baselines.len() <= MAX_ENTRIES,
        "too many local workspace baselines"
    );
    files::validate_workspace_paths(state.baselines.keys())?;
    for baseline in state.baselines.values() {
        validate_id(&baseline.revision)?;
        validate_file_version(&baseline.file)?;
    }
    if let Some(snapshot) = &state.observed {
        validate_snapshot(snapshot)?;
        ensure!(
            snapshot.head_etag.is_some(),
            "persisted catalog cannot be a historical publication base"
        );
        let mut keys: BTreeSet<String> = snapshot.manifest.files.keys().cloned().collect();
        keys.extend(state.baselines.keys().cloned());
        files::validate_workspace_paths(keys.iter())?;
    } else if !state.baselines.is_empty() {
        bail!("working baselines exist without an observed workspace identity");
    }
    Ok(())
}
