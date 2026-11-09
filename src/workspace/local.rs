//! Selective, recoverable local working copies of published workspace files.
//!
//! Discovery and per-path working baselines are deliberately separate. Refreshing
//! a catalog can never turn an unpublished local edit into a published baseline.
mod staging;
#[cfg(test)]
mod tests;

use super::contract::*;
use crate::files;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_STATE_BYTES: usize = MAX_MANIFEST_BYTES * 4;
const MANAGED_STATE_FORMAT: u32 = 2;

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
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_managed_field"
    )]
    managed_target: Option<ManagedTarget>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_managed_field"
    )]
    managed_head: Option<ManagedHead>,
}

// Direct format 1 continues rejecting the new field names, including nulls.
// An omitted managed field is distinct from a present but malformed value.
fn present_managed_field<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

enum OpenTarget<'a> {
    Direct(&'a str),
    Managed(&'a ManagedTarget),
}

impl OpenTarget<'_> {
    fn target_id(&self) -> Result<String> {
        match self {
            Self::Direct(target_id) => Ok((*target_id).into()),
            Self::Managed(target) => managed_target_id(target),
        }
    }

    fn managed(&self) -> Option<&ManagedTarget> {
        match self {
            Self::Direct(_) => None,
            Self::Managed(target) => Some(target),
        }
    }
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
        Self::open_inner(root, Some(OpenTarget::Direct(target_id)))
    }

    /// Bind a new format-2 root to one explicit managed authority and vault.
    /// Existing direct or differently bound roots are never migrated implicitly.
    pub fn open_managed(root: &Path, target: &ManagedTarget) -> Result<Self> {
        managed_target_id(target)?;
        Self::open_inner(root, Some(OpenTarget::Managed(target)))
    }

    /// Inspect an initialized root without storage credentials or network access.
    pub fn open_offline(root: &Path) -> Result<Self> {
        Self::open_inner(root, None)
    }

    fn open_inner(root: &Path, target: Option<OpenTarget<'_>>) -> Result<Self> {
        let meta = fs::symlink_metadata(root).context("workspace root must already exist")?;
        ensure!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "workspace root must be a regular directory, not a symlink"
        );
        let root = fs::canonicalize(root)?;
        staging::reject_private_ancestors(&root)?;
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
        if target.is_none() {
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
                if let Some(target) = &target {
                    ensure!(
                        state.target_id == target.target_id()?
                            && state.managed_target.as_ref() == target.managed(),
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
                let target = target.context("workspace is not initialized")?;
                (
                    LocalState {
                        format: if target.managed().is_some() {
                            MANAGED_STATE_FORMAT
                        } else {
                            FORMAT_VERSION
                        },
                        root: root.clone(),
                        target_id: target.target_id()?,
                        observed: None,
                        baselines: BTreeMap::new(),
                        managed_target: target.managed().cloned(),
                        managed_head: None,
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
        if let Some(target) = &self.state.managed_target {
            ensure!(
                snapshot.manifest.workspace_id == target.workspace_id,
                "remote workspace identity differs from the managed target"
            );
            ensure!(
                snapshot.head_etag.is_none(),
                "managed snapshots cannot contain an S3 head ETag"
            );
        }
        if let Some(observed) = &self.state.observed {
            ensure!(
                observed.manifest.workspace_id == snapshot.manifest.workspace_id,
                "remote workspace identity changed; refusing to rebind this working copy"
            );
        }
        Ok(())
    }

    pub fn observe(&mut self, snapshot: Snapshot) -> Result<()> {
        ensure!(
            self.state.managed_target.is_none(),
            "managed workspace requires observe_managed"
        );
        self.validate_identity(&snapshot)?;
        ensure!(
            snapshot.head_etag.is_some(),
            "a historical revision cannot become the current observed publication base"
        );
        let mut next = self.state.clone();
        next.observed = Some(snapshot);
        self.replace_state(next)
    }

    fn validate_managed_catalog(&self, catalog: &ManagedCatalog) -> Result<ManagedHead> {
        let target = self
            .state
            .managed_target
            .as_ref()
            .context("direct workspace cannot accept a managed catalog")?;
        self.validate_identity(&catalog.snapshot)?;
        let head = catalog
            .head
            .as_ref()
            .context("a historical revision cannot become the managed publication base")?;
        validate_managed_head(target, &catalog.snapshot, head)?;
        if let Some(previous) = &self.state.managed_head {
            ensure!(
                head.generation > previous.generation || head == previous,
                "managed head conflicts with or predates the observed publication base"
            );
            ensure!(
                head.revision != previous.revision || head == previous,
                "managed revision changed its authoritative generation"
            );
        }
        Ok(head.clone())
    }

    /// Refresh discovery without advancing any editable file's working baseline.
    pub fn observe_managed(&mut self, catalog: &ManagedCatalog) -> Result<()> {
        let head = self.validate_managed_catalog(catalog)?;
        let mut next = self.state.clone();
        next.observed = Some(catalog.snapshot.clone());
        next.managed_head = Some(head);
        self.replace_state(next)
    }

    pub fn managed_head(&self) -> Result<ManagedHead> {
        ensure!(
            self.state.managed_target.is_some(),
            "direct workspace has no managed publication base"
        );
        self.state
            .managed_head
            .clone()
            .context("workspace has no observed managed catalog; refresh it first")
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
                if self.state.managed_target.is_some() && self.state.baselines.contains_key(path) {
                    bail!(
                        "publication conflict at {path:?}: the working baseline was removed remotely; preserve the bytes and make an explicit recovery decision before republishing"
                    );
                }
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
        ensure!(
            self.state.managed_target.is_none(),
            "managed workspace requires accept_managed_publication"
        );
        self.validate_identity(&snapshot)?;
        ensure!(
            snapshot.head_etag.is_some(),
            "published result has no authoritative head"
        );
        self.accept_publication_inner(&snapshot, publications, None)
    }

    pub fn accept_managed_publication(
        &mut self,
        catalog: &ManagedCatalog,
        publications: &[Publication],
    ) -> Result<()> {
        let head = self.validate_managed_catalog(catalog)?;
        self.accept_publication_inner(&catalog.snapshot, publications, Some(head))
    }

    fn accept_publication_inner(
        &mut self,
        snapshot: &Snapshot,
        publications: &[Publication],
        managed_head: Option<ManagedHead>,
    ) -> Result<()> {
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
        next.observed = Some(snapshot.clone());
        next.managed_head = managed_head;
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

    pub async fn pull<R: WorkspaceReader + ?Sized>(
        &mut self,
        remote: &R,
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
            remote
                .download_at(snapshot, path, &destination)
                .await
                .with_context(|| {
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
        let mut visible: BTreeMap<_, _> = snapshot
            .manifest
            .files
            .iter()
            .map(|(path, file)| (path, (file, snapshot.manifest.revision.as_str())))
            .collect();
        // Logical removal never discards an editable copy or its recovery identity.
        // Direct mode retains its original current-catalog-only listing behavior.
        if self.state.managed_target.is_some() {
            for (path, baseline) in &self.state.baselines {
                visible
                    .entry(path)
                    .or_insert((&baseline.file, &baseline.revision));
            }
        }
        visible
            .into_iter()
            .map(|(path, (file, revision))| {
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
                            if snapshot.manifest.files.get(path) == Some(&base.file) {
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
                    reference: reference_at(&snapshot.manifest.workspace_id, revision, path)?,
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
        let mut candidates: BTreeSet<_> = snapshot.manifest.files.keys().collect();
        if !value && self.state.managed_target.is_some() {
            candidates.extend(self.state.baselines.keys());
        }
        let selected = files::select_paths(candidates.into_iter(), selectors)?;
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
    match state.format {
        FORMAT_VERSION => ensure!(
            state.managed_target.is_none() && state.managed_head.is_none(),
            "direct state cannot contain a managed target or head"
        ),
        MANAGED_STATE_FORMAT => {
            let target = state
                .managed_target
                .as_ref()
                .context("managed state has no explicit target")?;
            ensure!(
                state.target_id == managed_target_id(target)?,
                "managed target identity differs from the persisted binding"
            );
            match (&state.observed, &state.managed_head) {
                (Some(snapshot), Some(head)) => validate_managed_head(target, snapshot, head)?,
                (None, None) => (),
                _ => bail!("managed state must persist its observed catalog and head together"),
            }
        }
        _ => bail!("unsupported local workspace state format"),
    }
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
        if state.managed_target.is_none() {
            ensure!(
                snapshot.head_etag.is_some(),
                "persisted catalog cannot be a historical publication base"
            );
        }
        let mut keys: BTreeSet<String> = snapshot.manifest.files.keys().cloned().collect();
        keys.extend(state.baselines.keys().cloned());
        files::validate_workspace_paths(keys.iter())?;
    } else if !state.baselines.is_empty() {
        bail!("working baselines exist without an observed workspace identity");
    }
    Ok(())
}

fn validate_managed_head(
    target: &ManagedTarget,
    snapshot: &Snapshot,
    head: &ManagedHead,
) -> Result<()> {
    ensure!(
        snapshot.head_etag.is_none(),
        "managed snapshots cannot contain an S3 head ETag"
    );
    ensure!(
        head.authority_id == target.authority_id
            && head.workspace_id == target.workspace_id
            && snapshot.manifest.workspace_id == target.workspace_id,
        "managed catalog identity differs from the bound authority or workspace"
    );
    ensure!(
        head.generation > 0,
        "managed head generation must be positive"
    );
    ensure!(
        head.revision.revision == snapshot.manifest.revision
            && head.revision.sha256 == snapshot.manifest_sha256,
        "managed head does not identify the observed manifest"
    );
    Ok(())
}
