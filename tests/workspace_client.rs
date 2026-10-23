use maxio::workspace::{
    FORMAT_VERSION, FileVersion, LocalWorkspace, Manifest, Publication, RevisionRef, Snapshot,
    manifest_hash,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use tempfile::TempDir;

fn version(bytes: &[u8]) -> FileVersion {
    FileVersion {
        sha256: hex::encode(Sha256::digest(bytes)),
        size: bytes.len() as u64,
        blob: format!("maxio-workspaces/test/blobs/{}", uuid::Uuid::new_v4()),
    }
}

fn snapshot(workspace_id: &str, files: &[(&str, FileVersion)]) -> Snapshot {
    let manifest = Manifest {
        format: FORMAT_VERSION,
        workspace_id: workspace_id.to_owned(),
        revision: uuid::Uuid::new_v4().to_string(),
        parent: None,
        files: files
            .iter()
            .map(|(p, v)| (p.to_string(), v.clone()))
            .collect(),
    };
    Snapshot {
        manifest_sha256: manifest_hash(&manifest).unwrap(),
        manifest,
        head_etag: Some("\"head\"".into()),
    }
}

fn published(local: &LocalWorkspace, changes: &[Publication]) -> Snapshot {
    let base = local.snapshot().unwrap();
    let mut files = base.manifest.files.clone();
    for change in changes {
        files.insert(
            change.path.clone(),
            FileVersion {
                sha256: change.sha256.clone(),
                size: change.size,
                blob: format!("maxio-workspaces/test/blobs/{}", uuid::Uuid::new_v4()),
            },
        );
    }
    let manifest = Manifest {
        format: FORMAT_VERSION,
        workspace_id: base.manifest.workspace_id,
        revision: uuid::Uuid::new_v4().to_string(),
        parent: Some(RevisionRef {
            revision: base.manifest.revision,
            sha256: base.manifest_sha256,
        }),
        files,
    };
    Snapshot {
        manifest_sha256: manifest_hash(&manifest).unwrap(),
        manifest,
        head_etag: Some("\"next-head\"".into()),
    }
}

fn publish_file(local: &mut LocalWorkspace, path: &str) -> Snapshot {
    let changes = local.prepare_publish(&[path.into()]).unwrap();
    let next = published(local, &changes);
    local.accept_publication(next.clone(), &changes).unwrap();
    next
}

#[test]
fn catalog_is_metadata_only_and_survives_restart() {
    let root = TempDir::new().unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let remote = snapshot(&id, &[("data/large.bin", version(b"not downloaded"))]);
    let revision = remote.manifest.revision.clone();
    {
        let mut local = LocalWorkspace::open(root.path(), "test-target").unwrap();
        local.observe(remote).unwrap();
        let rows = local.describe(false).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].local_state, "absent");
        assert!(!root.path().join("data").exists());
        assert!(LocalWorkspace::open(root.path(), "test-target").is_err());
    }
    let local = LocalWorkspace::open(root.path(), "test-target").unwrap();
    assert_eq!(local.snapshot().unwrap().manifest.revision, revision);
    drop(local);
    assert!(LocalWorkspace::open(root.path(), "another-target").is_err());
}

#[test]
fn publication_selects_only_requested_files_and_never_overwrites_untracked_remote_paths() {
    let root = TempDir::new().unwrap();
    fs::create_dir(root.path().join("src")).unwrap();
    fs::create_dir(root.path().join("data")).unwrap();
    fs::write(root.path().join("src/main.txt"), b"selected").unwrap();
    fs::write(root.path().join("data/other.bin"), b"unselected").unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let mut local = LocalWorkspace::open(root.path(), "test-target").unwrap();
    local.observe(snapshot(&id, &[])).unwrap();
    let files = local.prepare_publish(&["src".into()]).unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].path, "src/main.txt");
    assert_eq!(fs::read(&files[0].source).unwrap(), b"selected");
    assert_eq!(files[0].size, 8);
    assert!(local.prepare_publish(&["missing".into()]).is_err());
    assert!(local.prepare_publish(&[".maxio-workspace".into()]).is_err());
    local
        .observe(snapshot(&id, &[("src/main.txt", version(b"remote"))]))
        .unwrap();
    assert!(local.prepare_publish(&["src".into()]).is_err());
    assert_eq!(
        fs::read(root.path().join("src/main.txt")).unwrap(),
        b"selected"
    );
}

#[test]
fn imported_catalog_requires_valid_identity_and_a_current_head() {
    let root = TempDir::new().unwrap();
    let mut local = LocalWorkspace::open(root.path(), "test-target").unwrap();
    assert!(local.snapshot().is_err());
    let id = uuid::Uuid::new_v4().to_string();
    let original = snapshot(&id, &[]);
    local.observe(original.clone()).unwrap();
    let mut historical = original.clone();
    historical.head_etag = None;
    assert!(local.observe(historical).is_err());
    assert!(
        local
            .observe(snapshot(&uuid::Uuid::new_v4().to_string(), &[]))
            .is_err()
    );
    let mut invalid = original.clone();
    invalid.manifest.files = BTreeMap::from([("../escape".into(), version(b"bad"))]);
    invalid.manifest_sha256 = manifest_hash(&invalid.manifest).unwrap();
    assert!(local.observe(invalid).is_err());
    assert_eq!(
        local.snapshot().unwrap().manifest.revision,
        original.manifest.revision
    );
}

#[test]
fn refresh_never_blesses_dirty_bytes_or_advances_their_publication_baseline() {
    let root = TempDir::new().unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let mut local = LocalWorkspace::open(root.path(), "test-target").unwrap();
    local.observe(snapshot(&id, &[])).unwrap();
    fs::write(root.path().join("notes.txt"), b"old").unwrap();
    publish_file(&mut local, "notes.txt");
    fs::write(root.path().join("notes.txt"), b"local unpublished").unwrap();
    local
        .observe(snapshot(&id, &[("notes.txt", version(b"remote update"))]))
        .unwrap();
    assert_eq!(
        local.describe(false).unwrap()[0].local_state,
        "present_unverified"
    );
    assert_eq!(local.describe(true).unwrap()[0].local_state, "dirty");
    assert!(local.prepare_publish(&["notes.txt".into()]).is_err());
    assert_eq!(
        fs::read(root.path().join("notes.txt")).unwrap(),
        b"local unpublished"
    );
}

#[test]
fn published_stage_does_not_certify_live_bytes_edited_during_upload() {
    let root = TempDir::new().unwrap();
    let mut local = LocalWorkspace::open(root.path(), "test-target").unwrap();
    local
        .observe(snapshot(&uuid::Uuid::new_v4().to_string(), &[]))
        .unwrap();
    fs::write(root.path().join("notes.txt"), b"staged edit").unwrap();
    let changes = local.prepare_publish(&["notes.txt".into()]).unwrap();
    let next = published(&local, &changes);
    fs::write(root.path().join("notes.txt"), b"later edit").unwrap();
    local.accept_publication(next, &changes).unwrap();
    assert_eq!(local.describe(true).unwrap()[0].local_state, "dirty");
    assert_eq!(fs::read(&changes[0].source).unwrap(), b"staged edit");
    assert_eq!(
        fs::read(root.path().join("notes.txt")).unwrap(),
        b"later edit"
    );
}

#[test]
fn clean_older_baselines_are_stale_and_cannot_publish_over_new_versions() {
    let root = TempDir::new().unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let mut local = LocalWorkspace::open(root.path(), "test-target").unwrap();
    local.observe(snapshot(&id, &[])).unwrap();
    fs::write(root.path().join("notes.txt"), b"old").unwrap();
    publish_file(&mut local, "notes.txt");
    local
        .observe(snapshot(&id, &[("notes.txt", version(b"new"))]))
        .unwrap();
    assert_eq!(local.describe(true).unwrap()[0].local_state, "stale");
    assert!(local.prepare_publish(&["notes.txt".into()]).is_err());
    assert!(local.pin(&["notes.txt".into()], true).is_err());
}

#[test]
fn pin_requires_verified_baseline_and_is_exact_not_a_future_directory_policy() {
    let root = TempDir::new().unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let mut local = LocalWorkspace::open(root.path(), "test-target").unwrap();
    local
        .observe(snapshot(&id, &[("missing.txt", version(b"missing"))]))
        .unwrap();
    assert!(local.pin(&["missing.txt".into()], true).is_err());
    fs::create_dir(root.path().join("src")).unwrap();
    fs::write(root.path().join("src/a.txt"), b"a").unwrap();
    publish_file(&mut local, "src");
    assert_eq!(local.pin(&["src".into()], true).unwrap(), vec!["src/a.txt"]);
    fs::write(root.path().join("src/b.txt"), b"b").unwrap();
    publish_file(&mut local, "src/b.txt");
    let rows = local.describe(true).unwrap();
    assert!(
        rows.iter()
            .find(|row| row.path == "src/a.txt")
            .unwrap()
            .pinned
    );
    assert!(
        !rows
            .iter()
            .find(|row| row.path == "src/b.txt")
            .unwrap()
            .pinned
    );
    fs::write(root.path().join("src/a.txt"), b"dirty").unwrap();
    assert!(local.pin(&["src/a.txt".into()], true).is_err());
    local.pin(&["src/a.txt".into()], false).unwrap();
    assert!(
        !local
            .describe(false)
            .unwrap()
            .iter()
            .find(|row| row.path == "src/a.txt")
            .unwrap()
            .pinned
    );
}

#[test]
fn current_directory_selection_skips_control_data_and_git() {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join("ordinary.txt"), b"ordinary").unwrap();
    fs::create_dir(root.path().join(".git")).unwrap();
    fs::write(root.path().join(".git/config"), b"private").unwrap();
    let mut local = LocalWorkspace::open(root.path(), "test-target").unwrap();
    local
        .observe(snapshot(&uuid::Uuid::new_v4().to_string(), &[]))
        .unwrap();
    let changes = local.prepare_publish(&[".".into()]).unwrap();
    assert_eq!(
        changes.iter().map(|p| p.path.as_str()).collect::<Vec<_>>(),
        vec!["ordinary.txt"]
    );
}

#[cfg(unix)]
#[test]
fn symlinks_and_case_aliases_are_rejected_without_touching_their_target() {
    use std::os::unix::fs::symlink;
    let root = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    fs::write(outside.path().join("important"), b"keep").unwrap();
    symlink(outside.path().join("important"), root.path().join("link")).unwrap();
    fs::write(root.path().join("A.txt"), b"upper").unwrap();
    fs::write(root.path().join("a.txt"), b"lower").unwrap();
    let mut local = LocalWorkspace::open(root.path(), "test-target").unwrap();
    local
        .observe(snapshot(&uuid::Uuid::new_v4().to_string(), &[]))
        .unwrap();
    assert!(local.prepare_publish(&["link".into()]).is_err());
    assert!(local.prepare_publish(&["A.txt".into()]).is_err());
    assert_eq!(fs::read(outside.path().join("important")).unwrap(), b"keep");
}
