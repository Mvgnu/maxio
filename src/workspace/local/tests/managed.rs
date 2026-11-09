use super::*;
use std::sync::Mutex;

fn target() -> ManagedTarget {
    ManagedTarget {
        authority_id: uuid::Uuid::new_v4().to_string(),
        vault_id: uuid::Uuid::new_v4().to_string(),
        workspace_id: uuid::Uuid::new_v4().to_string(),
        origin: "https://coordinator.example:9443".into(),
    }
}

fn catalog(
    target: &ManagedTarget,
    generation: u64,
    parent: Option<&ManagedCatalog>,
    entries: &[(&str, &[u8])],
) -> ManagedCatalog {
    let manifest = Manifest {
        format: FORMAT_VERSION,
        workspace_id: target.workspace_id.clone(),
        revision: uuid::Uuid::new_v4().to_string(),
        parent: parent.map(|catalog| RevisionRef {
            revision: catalog.snapshot.manifest.revision.clone(),
            sha256: catalog.snapshot.manifest_sha256.clone(),
        }),
        files: entries
            .iter()
            .map(|(path, bytes)| {
                (
                    (*path).into(),
                    FileVersion {
                        sha256: hex::encode(Sha256::digest(bytes)),
                        size: bytes.len() as u64,
                        blob: format!("maxio-workspaces/test/blobs/{}", uuid::Uuid::new_v4()),
                    },
                )
            })
            .collect(),
    };
    let snapshot = Snapshot {
        manifest_sha256: manifest_hash(&manifest).unwrap(),
        manifest,
        head_etag: None,
    };
    ManagedCatalog {
        head: Some(ManagedHead {
            authority_id: target.authority_id.clone(),
            workspace_id: target.workspace_id.clone(),
            generation,
            revision: RevisionRef {
                revision: snapshot.manifest.revision.clone(),
                sha256: snapshot.manifest_sha256.clone(),
            },
        }),
        snapshot,
    }
}

/// A real-file hydration fixture, deliberately separate from any authority or
/// retention claim. The local manager must verify whatever bytes it supplies.
struct FileReader {
    target_id: String,
    root: TempDir,
    fetched: Mutex<Vec<(RevisionRef, String)>>,
    fail_after_copy: bool,
}

impl FileReader {
    fn new(target: &ManagedTarget) -> Self {
        Self {
            target_id: managed_target_id(target).unwrap(),
            root: TempDir::new().unwrap(),
            fetched: Mutex::new(Vec::new()),
            fail_after_copy: false,
        }
    }

    fn put(&self, catalog: &ManagedCatalog, path: &str, bytes: &[u8]) {
        let file = &catalog.snapshot.manifest.files[path];
        let source = self.root.path().join(&file.blob);
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::write(source, bytes).unwrap();
    }

    fn fetched(&self) -> Vec<(RevisionRef, String)> {
        self.fetched.lock().unwrap().clone()
    }
}

impl WorkspaceReader for FileReader {
    fn target_id(&self) -> String {
        self.target_id.clone()
    }

    fn download_at<'a>(
        &'a self,
        snapshot: &'a Snapshot,
        path: &'a str,
        destination: &'a Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.fetched.lock().unwrap().push((
                RevisionRef {
                    revision: snapshot.manifest.revision.clone(),
                    sha256: snapshot.manifest_sha256.clone(),
                },
                path.into(),
            ));
            let version = snapshot
                .manifest
                .files
                .get(path)
                .context("fixture path is not in the selected revision")?;
            let mut source = File::open(self.root.path().join(&version.blob))?;
            let mut output = files::new_file(destination)?;
            std::io::copy(&mut source, &mut output)?;
            output.sync_all()?;
            ensure!(!self.fail_after_copy, "fixture interrupted hydration");
            Ok(())
        })
    }
}

fn data_files(directory: &Path) -> Vec<PathBuf> {
    fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "data")
        })
        .collect()
}

#[test]
fn managed_binding_is_explicit_and_direct_state_keeps_its_original_shape() {
    let target = target();
    let root = TempDir::new().unwrap();
    let mut local = LocalWorkspace::open_managed(root.path(), &target).unwrap();
    assert!(local.managed_head().is_err());
    assert!(local.snapshot().is_err());
    let current = catalog(&target, 1, None, &[]);
    local.observe_managed(&current).unwrap();
    let state_path = local.control.join("state.json");
    let saved = fs::read(&state_path).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&saved).unwrap();
    assert_eq!(value["format"], 2);
    assert_eq!(
        value["managed_target"],
        serde_json::to_value(&target).unwrap()
    );
    assert!(value["observed"]["head_etag"].is_null());
    assert!(LocalWorkspace::open_offline(root.path()).is_err());
    drop(local);

    let offline = LocalWorkspace::open_offline(root.path()).unwrap();
    assert_eq!(
        offline.managed_head().unwrap(),
        current.head.clone().unwrap()
    );
    drop(offline);
    assert!(LocalWorkspace::open(root.path(), &managed_target_id(&target).unwrap()).is_err());
    for altered in [
        ManagedTarget {
            authority_id: uuid::Uuid::new_v4().to_string(),
            ..target.clone()
        },
        ManagedTarget {
            vault_id: uuid::Uuid::new_v4().to_string(),
            ..target.clone()
        },
        ManagedTarget {
            workspace_id: uuid::Uuid::new_v4().to_string(),
            ..target.clone()
        },
        ManagedTarget {
            origin: "https://other.example:9443".into(),
            ..target.clone()
        },
    ] {
        assert!(LocalWorkspace::open_managed(root.path(), &altered).is_err());
        assert_eq!(fs::read(&state_path).unwrap(), saved);
    }

    let direct_root = TempDir::new().unwrap();
    let (direct, direct_snapshot) = hydrated(direct_root.path(), b"direct bytes");
    assert!(direct.managed_head().is_err());
    let direct_path = direct.control.join("state.json");
    let direct_bytes = fs::read(&direct_path).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&direct_bytes).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "format": 1,
            "root": fs::canonicalize(direct_root.path()).unwrap(),
            "target_id": "test-target",
            "observed": direct_snapshot,
            "baselines": {
                "notes.txt": {
                    "revision": direct_snapshot.manifest.revision,
                    "file": direct_snapshot.manifest.files["notes.txt"],
                    "pinned": false,
                }
            }
        })
    );
    drop(direct);
    assert!(LocalWorkspace::open_managed(direct_root.path(), &target).is_err());
    let mut direct = LocalWorkspace::open_offline(direct_root.path()).unwrap();
    assert!(direct.observe_managed(&current).is_err());
    assert!(direct.accept_managed_publication(&current, &[]).is_err());
    assert_eq!(fs::read(&direct_path).unwrap(), direct_bytes);
    assert_eq!(direct.describe(true).unwrap()[0].local_state, "clean");
    drop(direct);
    for field in ["managed_target", "managed_head"] {
        let mut malformed: serde_json::Value = serde_json::from_slice(&direct_bytes).unwrap();
        malformed[field] = serde_json::Value::Null;
        let bytes = serde_json::to_vec(&malformed).unwrap();
        fs::write(&direct_path, &bytes).unwrap();
        assert!(LocalWorkspace::open_offline(direct_root.path()).is_err());
        assert_eq!(fs::read(&direct_path).unwrap(), bytes);
    }

    let empty = TempDir::new().unwrap();
    let invalid = ManagedTarget {
        origin: "http://coordinator.example".into(),
        ..target
    };
    assert!(LocalWorkspace::open_managed(empty.path(), &invalid).is_err());
    assert!(!empty.path().join(STATE_DIRECTORY).exists());
}

#[test]
fn managed_catalog_cannot_rebind_rewind_or_mix_head_identities() {
    let target = target();
    let root = TempDir::new().unwrap();
    let mut local = LocalWorkspace::open_managed(root.path(), &target).unwrap();
    let original = catalog(&target, 10, None, &[("notes.txt", b"old")]);
    local.observe_managed(&original).unwrap();
    let saved = fs::read(local.control.join("state.json")).unwrap();
    let next = catalog(&target, 20, Some(&original), &[("notes.txt", b"new")]);
    let mut invalid = Vec::new();
    let mut bad = next.clone();
    bad.head = None;
    invalid.push(bad);
    let mut bad = next.clone();
    bad.snapshot.head_etag = Some("\"not-a-managed-token\"".into());
    invalid.push(bad);
    let mut bad = next.clone();
    bad.head.as_mut().unwrap().authority_id = uuid::Uuid::new_v4().to_string();
    invalid.push(bad);
    let mut bad = next.clone();
    bad.head.as_mut().unwrap().workspace_id = uuid::Uuid::new_v4().to_string();
    invalid.push(bad);
    let mut bad = next.clone();
    bad.head.as_mut().unwrap().revision.revision = uuid::Uuid::new_v4().to_string();
    invalid.push(bad);
    let mut bad = next.clone();
    bad.head.as_mut().unwrap().revision.sha256 = "a".repeat(64);
    invalid.push(bad);
    let mut bad = next.clone();
    bad.snapshot
        .manifest
        .files
        .get_mut("notes.txt")
        .unwrap()
        .size += 1;
    invalid.push(bad);
    for generation in [0, 9, 10] {
        let mut bad = next.clone();
        bad.head.as_mut().unwrap().generation = generation;
        invalid.push(bad);
    }
    let mut bad = original.clone();
    bad.head.as_mut().unwrap().generation = 11;
    invalid.push(bad);
    invalid.push(catalog(&self::target(), 30, None, &[]));
    for bad in invalid {
        assert!(local.observe_managed(&bad).is_err());
        assert_eq!(
            local.managed_head().unwrap(),
            original.head.clone().unwrap()
        );
        assert_eq!(fs::read(local.control.join("state.json")).unwrap(), saved);
    }
    let mut direct = original.snapshot.clone();
    direct.head_etag = Some("\"direct\"".into());
    assert!(local.observe(direct.clone()).is_err());
    assert!(local.accept_publication(direct, &[]).is_err());
    local.observe_managed(&next).unwrap();
    assert_eq!(local.managed_head().unwrap(), next.head.unwrap());
}

#[tokio::test]
async fn managed_reader_selects_exact_revisions_and_retains_old_editable_inodes() {
    let target = target();
    let root = TempDir::new().unwrap();
    let old = catalog(
        &target,
        1,
        None,
        &[("notes.txt", b"old bytes"), ("data/other", b"unrelated")],
    );
    let latest = catalog(
        &target,
        4,
        Some(&old),
        &[("notes.txt", b"new bytes"), ("data/other", b"unrelated")],
    );
    let reader = FileReader::new(&target);
    reader.put(&old, "notes.txt", b"old bytes");
    reader.put(&latest, "notes.txt", b"new bytes");
    reader.put(&latest, "data/other", b"unrelated");
    let mut local = LocalWorkspace::open_managed(root.path(), &target).unwrap();
    local.observe_managed(&old).unwrap();
    let source: &dyn WorkspaceReader = &reader;
    local
        .pull(source, &old.snapshot, &["notes.txt".into()])
        .await
        .unwrap();
    local.pin(&["notes.txt".into()], true).unwrap();
    let mut editor = OpenOptions::new()
        .write(true)
        .open(root.path().join("notes.txt"))
        .unwrap();
    local.observe_managed(&latest).unwrap();
    assert_eq!(
        fs::read(root.path().join("notes.txt")).unwrap(),
        b"old bytes"
    );
    local
        .pull(source, &latest.snapshot, &["notes.txt".into()])
        .await
        .unwrap();
    editor.write_all(b"late edit").unwrap();
    editor.sync_all().unwrap();
    assert_eq!(
        fs::read(root.path().join("notes.txt")).unwrap(),
        b"new bytes"
    );
    let histories = data_files(&local.control.join("history"));
    assert_eq!(histories.len(), 1);
    assert_eq!(fs::read(&histories[0]).unwrap(), b"late edit");
    let mut historical = old.clone();
    historical.head = None;
    assert!(local.observe_managed(&historical).is_err());
    local
        .pull(source, &historical.snapshot, &["notes.txt".into()])
        .await
        .unwrap();
    assert_eq!(local.managed_head().unwrap(), latest.head.clone().unwrap());
    assert_eq!(
        local.snapshot().unwrap().manifest.revision,
        latest.snapshot.manifest.revision
    );
    assert_eq!(
        local.state.baselines["notes.txt"].revision,
        old.snapshot.manifest.revision
    );
    assert!(local.prepare_publish(&["notes.txt".into()]).is_err());
    assert!(!root.path().join("data").exists());
    assert_eq!(
        reader.fetched(),
        vec![
            (old.head.clone().unwrap().revision, "notes.txt".into()),
            (latest.head.clone().unwrap().revision, "notes.txt".into()),
            (old.head.clone().unwrap().revision, "notes.txt".into()),
        ]
    );
    drop(local);
    let offline = LocalWorkspace::open_offline(root.path()).unwrap();
    assert_eq!(offline.managed_head().unwrap(), latest.head.unwrap());
    let row = offline
        .describe(true)
        .unwrap()
        .into_iter()
        .find(|row| row.path == "notes.txt")
        .unwrap();
    assert_eq!(row.local_state, "stale");
    assert!(row.pinned);
}

#[tokio::test]
async fn managed_tombstone_preserves_dirty_bytes_pin_and_historical_reference_offline() {
    let target = target();
    let root = TempDir::new().unwrap();
    let original = catalog(&target, 1, None, &[("notes.txt", b"original")]);
    let deleted = catalog(&target, 2, Some(&original), &[]);
    let reader = FileReader::new(&target);
    reader.put(&original, "notes.txt", b"original");
    let mut local = LocalWorkspace::open_managed(root.path(), &target).unwrap();
    local.observe_managed(&original).unwrap();
    local
        .pull(&reader, &original.snapshot, &["notes.txt".into()])
        .await
        .unwrap();
    local.pin(&["notes.txt".into()], true).unwrap();
    fs::write(root.path().join("notes.txt"), b"unpublished local edit").unwrap();
    local.observe_managed(&deleted).unwrap();
    assert!(
        local
            .pull(&reader, &deleted.snapshot, &["notes.txt".into()])
            .await
            .is_err()
    );
    assert_eq!(
        fs::read(root.path().join("notes.txt")).unwrap(),
        b"unpublished local edit"
    );
    assert_eq!(reader.fetched().len(), 1);
    drop(local);
    let mut offline = LocalWorkspace::open_offline(root.path()).unwrap();
    let row = &offline.describe(true).unwrap()[0];
    assert_eq!(row.local_state, "dirty");
    assert!(row.pinned);
    assert_eq!(
        row.reference,
        reference(&original.snapshot, "notes.txt").unwrap()
    );
    let error = offline.prepare_publish(&["notes.txt".into()]).unwrap_err();
    assert!(error.to_string().contains("publication conflict"));
    assert!(offline.pin(&["notes.txt".into()], true).is_err());
    offline.pin(&["notes.txt".into()], false).unwrap();
    assert!(!offline.describe(false).unwrap()[0].pinned);
    assert_eq!(
        fs::read(root.path().join("notes.txt")).unwrap(),
        b"unpublished local edit"
    );

    // An explicit authority restore is the recovery decision. Reusing the exact
    // retained version must not be blocked by a second local deletion authority.
    let mut restored = catalog(&target, 3, Some(&deleted), &[]);
    restored.snapshot.manifest.files = original.snapshot.manifest.files.clone();
    restored.snapshot.manifest_sha256 = manifest_hash(&restored.snapshot.manifest).unwrap();
    restored.head.as_mut().unwrap().revision.sha256 = restored.snapshot.manifest_sha256.clone();
    offline.observe_managed(&restored).unwrap();
    let recovered = offline.prepare_publish(&["notes.txt".into()]).unwrap();
    assert_eq!(
        fs::read(&recovered[0].source).unwrap(),
        b"unpublished local edit"
    );
    assert_eq!(offline.describe(true).unwrap()[0].local_state, "dirty");
}

#[tokio::test]
async fn managed_reader_binding_failure_and_bad_download_leave_bytes_and_baselines() {
    let target = target();
    let root = TempDir::new().unwrap();
    let original = catalog(&target, 1, None, &[("notes.txt", b"original")]);
    let latest = catalog(
        &target,
        2,
        Some(&original),
        &[("notes.txt", b"complete replacement")],
    );
    let mut reader = FileReader::new(&target);
    reader.put(&original, "notes.txt", b"original");
    let mut local = LocalWorkspace::open_managed(root.path(), &target).unwrap();
    local.observe_managed(&original).unwrap();
    local
        .pull(&reader, &original.snapshot, &["notes.txt".into()])
        .await
        .unwrap();
    local.observe_managed(&latest).unwrap();
    let saved = fs::read(local.control.join("state.json")).unwrap();
    reader.target_id = "wrong-target".into();
    assert!(
        local
            .pull(&reader, &latest.snapshot, &["notes.txt".into()])
            .await
            .is_err()
    );
    assert_eq!(reader.fetched().len(), 1);
    reader.target_id = managed_target_id(&target).unwrap();
    let mut mixed = latest.snapshot.clone();
    mixed.head_etag = Some("\"unexpected\"".into());
    assert!(
        local
            .pull(&reader, &mixed, &["notes.txt".into()])
            .await
            .is_err()
    );
    assert_eq!(reader.fetched().len(), 1);
    reader.put(&latest, "notes.txt", b"partial");
    assert!(
        local
            .pull(&reader, &latest.snapshot, &["notes.txt".into()])
            .await
            .is_err()
    );
    reader.put(&latest, "notes.txt", b"complete replacement");
    reader.fail_after_copy = true;
    assert!(
        local
            .pull(&reader, &latest.snapshot, &["notes.txt".into()])
            .await
            .is_err()
    );
    assert_eq!(
        fs::read(root.path().join("notes.txt")).unwrap(),
        b"original"
    );
    assert_eq!(
        local.state.baselines["notes.txt"].file,
        original.snapshot.manifest.files["notes.txt"]
    );
    assert_eq!(fs::read(local.control.join("state.json")).unwrap(), saved);
    let retained: Vec<_> = fs::read_dir(local.control.join("staging"))
        .unwrap()
        .flat_map(|entry| data_files(&entry.unwrap().path()))
        .map(|path| fs::read(path).unwrap())
        .collect();
    assert!(retained.contains(&b"partial".to_vec()));
    assert!(retained.contains(&b"complete replacement".to_vec()));
    reader.fail_after_copy = false;
    fs::write(root.path().join("notes.txt"), b"dirty edit").unwrap();
    assert!(
        local
            .pull(&reader, &latest.snapshot, &["notes.txt".into()])
            .await
            .is_err()
    );
    assert_eq!(
        reader.fetched().len(),
        3,
        "dirty copies must be refused before download"
    );
    assert_eq!(
        fs::read(root.path().join("notes.txt")).unwrap(),
        b"dirty edit"
    );
}

#[test]
fn managed_publication_commits_head_and_stage_baselines_without_blessing_later_edits() {
    let target = target();
    let root = TempDir::new().unwrap();
    let original = catalog(&target, 1, None, &[]);
    let mut local = LocalWorkspace::open_managed(root.path(), &target).unwrap();
    local.observe_managed(&original).unwrap();
    fs::write(root.path().join("notes.txt"), b"selected edit").unwrap();
    fs::write(root.path().join("unrelated.txt"), b"unselected").unwrap();
    let publications = local.prepare_publish(&["notes.txt".into()]).unwrap();
    assert_eq!(publications.len(), 1);
    let published = catalog(
        &target,
        8,
        Some(&original),
        &[("notes.txt", b"selected edit")],
    );
    let unrelated_parent = catalog(&target, 8, None, &[("notes.txt", b"selected edit")]);
    assert!(
        local
            .accept_managed_publication(&unrelated_parent, &publications)
            .is_err()
    );
    fs::write(root.path().join("notes.txt"), b"later edit").unwrap();
    local
        .accept_managed_publication(&published, &publications)
        .unwrap();
    local
        .accept_managed_publication(&published, &publications)
        .unwrap();
    assert_eq!(
        local.managed_head().unwrap(),
        published.head.clone().unwrap()
    );
    assert_eq!(local.describe(true).unwrap()[0].local_state, "dirty");
    assert_eq!(fs::read(&publications[0].source).unwrap(), b"selected edit");
    assert_eq!(
        fs::read(root.path().join("notes.txt")).unwrap(),
        b"later edit"
    );
    assert_eq!(
        fs::read(root.path().join("unrelated.txt")).unwrap(),
        b"unselected"
    );
    drop(local);
    let local = LocalWorkspace::open_offline(root.path()).unwrap();
    assert_eq!(local.managed_head().unwrap(), published.head.unwrap());
    assert_eq!(
        local.state.baselines["notes.txt"].file,
        published.snapshot.manifest.files["notes.txt"]
    );
    assert_eq!(local.describe(true).unwrap()[0].local_state, "dirty");
}

#[test]
fn failed_managed_publication_save_preserves_old_head_and_recoverable_staging() {
    let target = target();
    let root = TempDir::new().unwrap();
    let original = catalog(&target, 1, None, &[]);
    let mut local = LocalWorkspace::open_managed(root.path(), &target).unwrap();
    local.observe_managed(&original).unwrap();
    fs::write(root.path().join("notes.txt"), b"recoverable").unwrap();
    let publications = local.prepare_publish(&["notes.txt".into()]).unwrap();
    let published = catalog(
        &target,
        2,
        Some(&original),
        &[("notes.txt", b"recoverable")],
    );
    let state = local.control.join("state.json");
    let previous = local.control.join("state.saved");
    fs::rename(&state, &previous).unwrap();
    fs::create_dir(&state).unwrap();
    assert!(
        local
            .accept_managed_publication(&published, &publications)
            .is_err()
    );
    assert_eq!(
        local.managed_head().unwrap(),
        original.head.clone().unwrap()
    );
    assert!(local.state.baselines.is_empty());
    assert_eq!(fs::read(&publications[0].source).unwrap(), b"recoverable");
    assert_eq!(
        fs::read(root.path().join("notes.txt")).unwrap(),
        b"recoverable"
    );
    fs::remove_dir(&state).unwrap();
    fs::rename(&previous, &state).unwrap();
    drop(local);
    let mut local = LocalWorkspace::open_offline(root.path()).unwrap();
    assert_eq!(local.managed_head().unwrap(), original.head.unwrap());
    local
        .accept_managed_publication(&published, &publications)
        .unwrap();
    assert_eq!(local.managed_head().unwrap(), published.head.unwrap());
}

#[test]
fn inconsistent_managed_state_is_rejected_without_resetting_or_touching_working_bytes() {
    let target = target();
    let root = TempDir::new().unwrap();
    let original = catalog(&target, 1, None, &[]);
    let mut local = LocalWorkspace::open_managed(root.path(), &target).unwrap();
    local.observe_managed(&original).unwrap();
    let state_path = local.control.join("state.json");
    let original: serde_json::Value =
        serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
    fs::write(root.path().join("keep.txt"), b"unpublished").unwrap();
    drop(local);
    for (field, value) in [
        ("format", serde_json::json!(1)),
        ("managed_target", serde_json::Value::Null),
        ("managed_head", serde_json::Value::Null),
        ("observed", serde_json::Value::Null),
        ("target_id", serde_json::json!("wrong-target")),
    ] {
        let mut invalid = original.clone();
        invalid[field] = value;
        let bytes = serde_json::to_vec(&invalid).unwrap();
        fs::write(&state_path, &bytes).unwrap();
        assert!(LocalWorkspace::open_managed(root.path(), &target).is_err());
        assert!(LocalWorkspace::open_offline(root.path()).is_err());
        assert_eq!(fs::read(&state_path).unwrap(), bytes);
        assert_eq!(
            fs::read(root.path().join("keep.txt")).unwrap(),
            b"unpublished"
        );
    }
}
