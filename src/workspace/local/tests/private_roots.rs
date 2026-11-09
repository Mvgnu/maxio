use super::*;

fn managed_target() -> ManagedTarget {
    ManagedTarget {
        authority_id: uuid::Uuid::new_v4().to_string(),
        vault_id: uuid::Uuid::new_v4().to_string(),
        workspace_id: uuid::Uuid::new_v4().to_string(),
        origin: "https://coordinator.example:9443".into(),
    }
}

#[test]
fn private_authority_root_is_not_adopted_or_mutated_by_editable_workspace_open() {
    let root = TempDir::new().unwrap();
    let marker = root.path().join(".maxio-fabric");
    let marker_bytes = b"MaxIO managed authority v1\n";
    fs::write(&marker, marker_bytes).unwrap();
    fs::create_dir(root.path().join("vault")).unwrap();
    let payload = root.path().join("vault/immutable.data");
    fs::write(&payload, b"retained authority bytes").unwrap();
    let opened = LocalWorkspace::open(root.path(), "test-target");
    let accepted = opened.is_ok();
    drop(opened);

    assert_eq!(fs::read(&marker).unwrap(), marker_bytes);
    assert_eq!(fs::read(&payload).unwrap(), b"retained authority bytes");
    assert!(
        !root.path().join(STATE_DIRECTORY).exists(),
        "editable workspace admission created control state inside an authority root"
    );
    assert!(
        !accepted,
        "authority root was admitted as an editable workspace"
    );
}

#[test]
fn direct_and_managed_roots_refuse_private_markers_and_their_descendants() {
    for marker_name in [".maxio-runtime", ".maxio-fabric", ".maxio-worker"] {
        for managed in [false, true] {
            for nested in [false, true] {
                let private = TempDir::new().unwrap();
                let marker = private.path().join(marker_name);
                fs::write(&marker, b"private root marker").unwrap();
                let payload = private.path().join("retained.data");
                fs::write(&payload, b"private bytes").unwrap();
                let root = if nested {
                    let nested = private.path().join("vault/objects");
                    fs::create_dir_all(&nested).unwrap();
                    nested
                } else {
                    private.path().to_path_buf()
                };
                let result = if managed {
                    LocalWorkspace::open_managed(&root, &managed_target())
                } else {
                    LocalWorkspace::open(&root, "test-target")
                };
                assert!(
                    result.is_err(),
                    "admitted {marker_name}; managed={managed}, nested={nested}"
                );
                assert!(!root.join(STATE_DIRECTORY).exists());
                assert_eq!(fs::read(&marker).unwrap(), b"private root marker");
                assert_eq!(fs::read(&payload).unwrap(), b"private bytes");
            }
        }
    }
}

#[test]
fn adding_a_private_marker_blocks_offline_reopen_without_rewriting_saved_state() {
    for marker_name in [".maxio-fabric", ".maxio-worker"] {
        let root = TempDir::new().unwrap();
        let (local, _) = hydrated(root.path(), b"keep local bytes");
        let state_path = local.control.join("state.json");
        let saved = fs::read(&state_path).unwrap();
        drop(local);
        fs::write(root.path().join(marker_name), b"private root marker").unwrap();
        assert!(LocalWorkspace::open_offline(root.path()).is_err());
        assert_eq!(fs::read(&state_path).unwrap(), saved);
        assert_eq!(
            fs::read(root.path().join("notes.txt")).unwrap(),
            b"keep local bytes"
        );
    }
}

#[test]
fn an_independent_clean_source_beside_private_roots_is_still_admitted() {
    let parent = TempDir::new().unwrap();
    let private = parent.path().join("authority");
    fs::create_dir(&private).unwrap();
    fs::write(private.join(".maxio-fabric"), b"private root marker").unwrap();
    for managed in [false, true] {
        let source = parent.path().join(if managed {
            "managed-source"
        } else {
            "direct-source"
        });
        fs::create_dir(&source).unwrap();
        fs::write(source.join("ordinary.txt"), b"editable source").unwrap();
        let local = if managed {
            LocalWorkspace::open_managed(&source, &managed_target())
        } else {
            LocalWorkspace::open(&source, "test-target")
        }
        .unwrap();
        assert_eq!(
            fs::read(source.join("ordinary.txt")).unwrap(),
            b"editable source"
        );
        assert!(local.control.join("state.json").exists());
    }
}

#[test]
fn selecting_private_nested_sources_refuses_before_publication_or_hydration_staging() {
    for marker_name in [".maxio-runtime", ".maxio-fabric", ".maxio-worker"] {
        let root = TempDir::new().unwrap();
        let (mut local, _) = hydrated(root.path(), b"ordinary editable bytes");
        let private = root.path().join("nested/private");
        fs::create_dir_all(private.join("vault/objects")).unwrap();
        let marker = private.join(marker_name);
        fs::write(&marker, b"private root marker").unwrap();
        let payload = private.join("vault/objects/retained.data");
        fs::write(&payload, b"private retained bytes").unwrap();
        let state = fs::read(local.control.join("state.json")).unwrap();
        let stage_count = fs::read_dir(local.control.join("staging")).unwrap().count();
        for selector in [
            ".",
            "nested",
            "nested/private",
            "nested/private/vault/objects/retained.data",
        ] {
            assert!(
                local.prepare_publish(&[selector.into()]).is_err(),
                "selected {selector} in {marker_name}"
            );
            assert_eq!(
                fs::read_dir(local.control.join("staging")).unwrap().count(),
                stage_count
            );
        }
        assert!(
            local
                .replacement_baseline("nested/private/vault/objects/retained.data")
                .is_err()
        );
        assert!(staging::checked_file(root.path(), "nested/private/new/file", true).is_err());
        assert!(!private.join("new").exists());
        assert_eq!(fs::read(&marker).unwrap(), b"private root marker");
        assert_eq!(fs::read(&payload).unwrap(), b"private retained bytes");
        assert_eq!(fs::read(local.control.join("state.json")).unwrap(), state);
        let clean = local.prepare_publish(&["notes.txt".into()]).unwrap();
        assert_eq!(
            fs::read(&clean[0].source).unwrap(),
            b"ordinary editable bytes"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_dangling_private_marker_is_not_followed_or_ignored() {
    use std::os::unix::fs::symlink;
    let root = TempDir::new().unwrap();
    let marker = root.path().join(".maxio-worker");
    let missing = root.path().join("missing-marker-target");
    symlink(&missing, &marker).unwrap();
    assert!(LocalWorkspace::open(root.path(), "test-target").is_err());
    assert!(
        fs::symlink_metadata(&marker)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(!missing.exists());
    assert!(!root.path().join(STATE_DIRECTORY).exists());
}
