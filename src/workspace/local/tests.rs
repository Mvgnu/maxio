use super::*;
use sha2::{Digest, Sha256};
use std::io::{Seek, SeekFrom, Write};
use tempfile::TempDir;

fn snapshot(workspace_id: &str, bytes: &[u8]) -> Snapshot {
    let manifest = Manifest {
        format: FORMAT_VERSION,
        workspace_id: workspace_id.into(),
        revision: uuid::Uuid::new_v4().to_string(),
        parent: None,
        files: BTreeMap::from([(
            "notes.txt".into(),
            FileVersion {
                sha256: hex::encode(Sha256::digest(bytes)),
                size: bytes.len() as u64,
                blob: format!("maxio-workspaces/test/blobs/{}", uuid::Uuid::new_v4()),
            },
        )]),
    };
    Snapshot {
        manifest_sha256: manifest_hash(&manifest).unwrap(),
        manifest,
        head_etag: Some("\"head\"".into()),
    }
}

fn stage(local: &LocalWorkspace, bytes: &[u8]) -> PathBuf {
    let dir = staging::operation_directory(&local.control, "test").unwrap();
    let path = dir.join("bytes.data");
    let mut file = files::new_file(&path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    path
}

fn hydrated(root: &Path, bytes: &[u8]) -> (LocalWorkspace, Snapshot) {
    let mut local = LocalWorkspace::open(root, "test-target").unwrap();
    let snap = snapshot(&uuid::Uuid::new_v4().to_string(), bytes);
    local.observe(snap.clone()).unwrap();
    let bytes = stage(&local, bytes);
    local
        .install_download(&snap, "notes.txt", &bytes, None)
        .unwrap();
    (local, snap)
}

#[test]
fn historical_hydration_preserves_current_catalog_and_retains_actual_baseline() {
    let root = TempDir::new().unwrap();
    let (mut local, mut old) = hydrated(root.path(), b"old");
    let latest = snapshot(&old.manifest.workspace_id, b"new");
    local.observe(latest.clone()).unwrap();
    let expected = local.replacement_baseline("notes.txt").unwrap();
    let new = stage(&local, b"new");
    local
        .install_download(&latest, "notes.txt", &new, expected.as_ref())
        .unwrap();
    old.head_etag = None;
    let expected = local.replacement_baseline("notes.txt").unwrap();
    let old_bytes = stage(&local, b"old");
    local
        .install_download(&old, "notes.txt", &old_bytes, expected.as_ref())
        .unwrap();
    assert_eq!(
        local.snapshot().unwrap().manifest.revision,
        latest.manifest.revision
    );
    assert_eq!(
        local.state.baselines["notes.txt"].revision,
        old.manifest.revision
    );
    assert_eq!(local.describe(true).unwrap()[0].local_state, "stale");
    assert!(local.prepare_publish(&["notes.txt".into()]).is_err());
    drop(local);
    let local = LocalWorkspace::open_offline(root.path()).unwrap();
    assert_eq!(
        local.snapshot().unwrap().manifest.revision,
        latest.manifest.revision
    );
    assert_eq!(
        local.state.baselines["notes.txt"].revision,
        old.manifest.revision
    );
}

#[test]
fn late_open_descriptor_writes_remain_in_history_after_replacement() {
    let root = TempDir::new().unwrap();
    let (mut local, old) = hydrated(root.path(), b"old bytes");
    let mut editor = OpenOptions::new()
        .write(true)
        .open(root.path().join("notes.txt"))
        .unwrap();
    let latest = snapshot(&old.manifest.workspace_id, b"new bytes");
    local.observe(latest.clone()).unwrap();
    let expected = local.replacement_baseline("notes.txt").unwrap();
    let new = stage(&local, b"new bytes");
    local
        .install_download(&latest, "notes.txt", &new, expected.as_ref())
        .unwrap();
    editor.seek(SeekFrom::Start(0)).unwrap();
    editor.write_all(b"late edit").unwrap();
    editor.sync_all().unwrap();
    assert_eq!(
        fs::read(root.path().join("notes.txt")).unwrap(),
        b"new bytes"
    );
    let histories: Vec<_> = fs::read_dir(local.control.join("history"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "data"))
        .collect();
    assert_eq!(histories.len(), 1);
    assert_eq!(fs::read(&histories[0]).unwrap(), b"late edit");
}

#[test]
fn changed_local_file_and_untracked_arrivals_reject_hydration_and_keep_stage() {
    let root = TempDir::new().unwrap();
    let (mut local, old) = hydrated(root.path(), b"old");
    let latest = snapshot(&old.manifest.workspace_id, b"new");
    let expected = local.replacement_baseline("notes.txt").unwrap();
    fs::write(root.path().join("notes.txt"), b"unpublished").unwrap();
    assert!(local.replacement_baseline("notes.txt").is_err());
    let new = stage(&local, b"new");
    assert!(
        local
            .install_download(&latest, "notes.txt", &new, expected.as_ref())
            .is_err()
    );
    assert_eq!(
        fs::read(root.path().join("notes.txt")).unwrap(),
        b"unpublished"
    );
    assert_eq!(fs::read(&new).unwrap(), b"new");
    assert!(
        local
            .install_download(&latest, "notes.txt", &new, None)
            .is_err()
    );
    assert_eq!(
        local.state.baselines["notes.txt"].file,
        old.manifest.files["notes.txt"]
    );
}

#[test]
fn corrupt_or_partial_download_cannot_replace_prior_content_or_baseline() {
    let root = TempDir::new().unwrap();
    let (mut local, old) = hydrated(root.path(), b"old");
    let latest = snapshot(&old.manifest.workspace_id, b"whole new content");
    let expected = local.replacement_baseline("notes.txt").unwrap();
    let partial = stage(&local, b"whole");
    assert!(
        local
            .install_download(&latest, "notes.txt", &partial, expected.as_ref())
            .is_err()
    );
    assert_eq!(fs::read(root.path().join("notes.txt")).unwrap(), b"old");
    assert_eq!(fs::read(&partial).unwrap(), b"whole");
    assert_eq!(
        local.state.baselines["notes.txt"].file,
        old.manifest.files["notes.txt"]
    );
}

#[test]
fn failed_state_save_preserves_installed_bytes_stage_and_previous_inode() {
    let root = TempDir::new().unwrap();
    let (mut local, old) = hydrated(root.path(), b"old");
    let latest = snapshot(&old.manifest.workspace_id, b"new");
    let expected = local.replacement_baseline("notes.txt").unwrap();
    let new = stage(&local, b"new");
    fs::rename(
        local.control.join("state.json"),
        local.control.join("state.saved"),
    )
    .unwrap();
    fs::create_dir(local.control.join("state.json")).unwrap();
    assert!(
        local
            .install_download(&latest, "notes.txt", &new, expected.as_ref())
            .is_err()
    );
    assert_eq!(fs::read(root.path().join("notes.txt")).unwrap(), b"new");
    assert_eq!(fs::read(&new).unwrap(), b"new");
    assert_eq!(
        local.state.baselines["notes.txt"].file,
        old.manifest.files["notes.txt"]
    );
    let histories: Vec<_> = fs::read_dir(local.control.join("history"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "data"))
        .collect();
    assert_eq!(fs::read(&histories[0]).unwrap(), b"old");
}

#[test]
fn corrupt_or_oversized_state_is_not_silently_reset() {
    let root = TempDir::new().unwrap();
    let (local, _) = hydrated(root.path(), b"keep");
    let state_path = local.control.join("state.json");
    drop(local);
    fs::write(&state_path, b"{broken").unwrap();
    assert!(LocalWorkspace::open(root.path(), "test-target").is_err());
    assert_eq!(fs::read(&state_path).unwrap(), b"{broken");
    let file = OpenOptions::new().write(true).open(&state_path).unwrap();
    file.set_len(MAX_STATE_BYTES as u64 + 1).unwrap();
    drop(file);
    assert!(LocalWorkspace::open_offline(root.path()).is_err());
    assert_eq!(
        fs::metadata(&state_path).unwrap().len(),
        MAX_STATE_BYTES as u64 + 1
    );
    assert_eq!(fs::read(root.path().join("notes.txt")).unwrap(), b"keep");
}

#[test]
fn offline_inspection_needs_no_credentials_and_never_initializes_an_empty_root() {
    let empty = TempDir::new().unwrap();
    assert!(LocalWorkspace::open_offline(empty.path()).is_err());
    assert!(!empty.path().join(STATE_DIRECTORY).exists());
    let root = TempDir::new().unwrap();
    let (mut local, snapshot) = hydrated(root.path(), b"offline");
    local.pin(&["notes.txt".into()], true).unwrap();
    drop(local);
    let mut offline = LocalWorkspace::open_offline(root.path()).unwrap();
    assert_eq!(
        offline.snapshot().unwrap().manifest.revision,
        snapshot.manifest.revision
    );
    assert_eq!(offline.describe(true).unwrap()[0].local_state, "clean");
    assert!(offline.describe(false).unwrap()[0].pinned);
    offline.pin(&["notes.txt".into()], false).unwrap();
}

#[cfg(unix)]
#[test]
fn symlinked_control_or_source_ancestor_is_rejected() {
    use std::os::unix::fs::symlink;
    let root = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    symlink(outside.path(), root.path().join(STATE_DIRECTORY)).unwrap();
    assert!(LocalWorkspace::open(root.path(), "test-target").is_err());
    fs::remove_file(root.path().join(STATE_DIRECTORY)).unwrap();
    fs::write(outside.path().join("source.txt"), b"private").unwrap();
    symlink(outside.path(), root.path().join("linked")).unwrap();
    let (mut local, _) = hydrated(root.path(), b"local");
    assert!(
        local
            .prepare_publish(&["linked/source.txt".into()])
            .is_err()
    );
    assert!(local.prepare_publish(&["linked".into()]).is_err());
    assert_eq!(
        fs::read(outside.path().join("source.txt")).unwrap(),
        b"private"
    );
}
