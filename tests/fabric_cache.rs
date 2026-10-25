use maxio::fabric::cache::PrivateCache;
use maxio::fabric::contract::{AuthorityInfo, RetainedFile};
use maxio::workspace::{FileVersion, RevisionRef};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

fn authority() -> AuthorityInfo {
    AuthorityInfo {
        format: 1,
        authority_id: uuid::Uuid::new_v4().to_string(),
        vault_id: uuid::Uuid::new_v4().to_string(),
        epoch: 1,
        generation: 1,
        retention_policy_version: 1,
    }
}

fn reference(bytes: &[u8]) -> RetainedFile {
    RetainedFile {
        workspace_id: uuid::Uuid::new_v4().to_string(),
        revision: RevisionRef {
            revision: uuid::Uuid::new_v4().to_string(),
            sha256: "a".repeat(64),
        },
        path: "data/input.bin".into(),
        version: FileVersion {
            sha256: hex::encode(Sha256::digest(bytes)),
            size: bytes.len() as u64,
            blob: format!("maxio-workspaces/test/blobs/{}", uuid::Uuid::new_v4()),
        },
    }
}

fn source(root: &Path, bytes: &[u8]) -> std::path::PathBuf {
    let path = root.join("source.bin");
    fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn selected_copy_has_independent_inode_and_preserves_unpublished_edits() {
    let temp = tempfile::tempdir().unwrap();
    let info = authority();
    let device = uuid::Uuid::new_v4().to_string();
    let bytes = b"immutable original";
    let file = reference(bytes);
    let mut cache = PrivateCache::open(&temp.path().join("cache-root"), &info, &device).unwrap();
    cache.import(&file, &source(temp.path(), bytes)).unwrap();
    let target = temp.path().join("working");
    fs::create_dir(&target).unwrap();
    let copied = cache.copy_to(std::slice::from_ref(&file), &target).unwrap();
    assert_eq!(copied[0].sha256, file.version.sha256);
    fs::write(target.join(&file.path), b"unpublished edit").unwrap();
    assert!(cache.copy_to(std::slice::from_ref(&file), &target).is_err());
    assert_eq!(
        fs::read(target.join(&file.path)).unwrap(),
        b"unpublished edit"
    );
    let inventory = cache.inventory(true).unwrap();
    assert_eq!(inventory.cached_files.len(), 1);
    assert_eq!(inventory.entries[0].state, "verified");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let object = cache
            .root()
            .join("cache/objects")
            .join(&inventory.entries[0].key);
        assert_ne!(
            fs::metadata(object).unwrap().ino(),
            fs::metadata(target.join(&file.path)).unwrap().ino()
        );
    }
}

#[test]
fn locks_pins_active_guards_and_binding_survive_restart() {
    let temp = tempfile::tempdir().unwrap();
    let info = authority();
    let device = uuid::Uuid::new_v4().to_string();
    let root = temp.path().join("private");
    let bytes = b"retained";
    let file = reference(bytes);
    let attempt = uuid::Uuid::new_v4().to_string();
    {
        let mut cache = PrivateCache::open(&root, &info, &device).unwrap();
        assert!(PrivateCache::open(&root, &info, &device).is_err());
        cache.import(&file, &source(temp.path(), bytes)).unwrap();
        cache.pin(std::slice::from_ref(&file), true).unwrap();
        cache
            .protect(&attempt, std::slice::from_ref(&file))
            .unwrap();
    }
    let mut cache = PrivateCache::open_offline(&root).unwrap();
    let row = &cache.inventory(true).unwrap().entries[0];
    assert!(row.pinned);
    assert_eq!(row.active_attempts, vec![attempt.clone()]);
    cache.pin(std::slice::from_ref(&file), false).unwrap();
    cache.release(&attempt).unwrap();
    assert!(!cache.inventory(true).unwrap().entries[0].pinned);
    drop(cache);
    let changed = authority();
    assert!(PrivateCache::open(&root, &changed, &device).is_err());
    assert!(PrivateCache::open_offline(&temp.path().join("missing")).is_err());
}

#[test]
fn corrupt_entry_is_never_advertised_copied_or_silently_replaced() {
    let temp = tempfile::tempdir().unwrap();
    let info = authority();
    let device = uuid::Uuid::new_v4().to_string();
    let bytes = b"original";
    let file = reference(bytes);
    let src = source(temp.path(), bytes);
    let mut cache = PrivateCache::open(&temp.path().join("cache-root"), &info, &device).unwrap();
    cache.import(&file, &src).unwrap();
    let inventory = cache.inventory(true).unwrap();
    let object = cache
        .root()
        .join("cache/objects")
        .join(&inventory.entries[0].key);
    fs::write(&object, b"tampered").unwrap();
    let inventory = cache.inventory(true).unwrap();
    assert!(inventory.cached_files.is_empty());
    assert_eq!(inventory.entries[0].state, "modified");
    assert!(cache.import(&file, &src).is_err());
    let target = temp.path().join("new-working");
    fs::create_dir(&target).unwrap();
    assert!(cache.copy_to(&[file], &target).is_err());
    assert_eq!(fs::read(object).unwrap(), b"tampered");
}

#[test]
fn editable_workspace_is_not_adopted_and_bad_import_stays_unverified() {
    let temp = tempfile::tempdir().unwrap();
    let info = authority();
    let device = uuid::Uuid::new_v4().to_string();
    let editable = temp.path().join("editable");
    fs::create_dir(&editable).unwrap();
    fs::create_dir(editable.join(".maxio-workspace")).unwrap();
    assert!(PrivateCache::open(&editable, &info, &device).is_err());
    let mut cache = PrivateCache::open(&temp.path().join("private"), &info, &device).unwrap();
    assert!(
        cache
            .import(&reference(b"expected"), &source(temp.path(), b"wrong"))
            .is_err()
    );
    assert!(cache.inventory(true).unwrap().cached_files.is_empty());
    assert!(
        fs::read_dir(cache.root().join("cache/staging"))
            .unwrap()
            .next()
            .is_some()
    );
}

#[test]
fn private_cache_has_a_durable_type_marker_and_refuses_private_ancestors() {
    let temp = tempfile::tempdir().unwrap();
    let info = authority();
    let device = uuid::Uuid::new_v4().to_string();
    let root = temp.path().join("private");
    let cache = PrivateCache::open(&root, &info, &device).unwrap();
    assert_eq!(
        fs::read(root.join(".maxio-worker")).unwrap(),
        b"MaxIO private worker cache v1\n"
    );
    drop(cache);
    assert!(PrivateCache::open_offline(&root).is_ok());
    assert!(PrivateCache::open(&root.join("nested"), &info, &device).is_err());
    let authority_root = temp.path().join("authority");
    fs::create_dir(&authority_root).unwrap();
    fs::write(
        authority_root.join(".maxio-fabric"),
        b"retained authority marker",
    )
    .unwrap();
    assert!(PrivateCache::open(&authority_root, &info, &device).is_err());
    assert!(!authority_root.join("manager.lock").exists());
    assert!(PrivateCache::open(&authority_root.join("vault"), &info, &device).is_err());
    assert_eq!(
        fs::read(authority_root.join(".maxio-fabric")).unwrap(),
        b"retained authority marker"
    );
    fs::write(root.join(".maxio-worker"), b"changed marker").unwrap();
    assert!(PrivateCache::open_offline(&root).is_err());
    assert!(root.join("cache/state.json").exists());
}
