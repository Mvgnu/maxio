use base64::{Engine, engine::general_purpose::STANDARD};
use maxio::fabric::authority::Authority;
use maxio::fabric::contract::{BootstrapOwner, ErrorCode, FabricError};

fn bootstrap() -> BootstrapOwner {
    BootstrapOwner {
        device_id: uuid::Uuid::new_v4().to_string(),
        display_name: "Owner".into(),
        public_key: STANDARD.encode([42u8; 32]),
    }
}

#[test]
fn exclusive_root_restart_epoch_and_owner_identity_survive() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("vault");
    let owner = bootstrap();
    let id = owner.device_id.clone();
    let first = Authority::initialize(&root, owner).unwrap();
    let info = first.info();
    let error = match Authority::open(&root) {
        Ok(_) => panic!("second coordinator acquired root"),
        Err(error) => error,
    };
    assert_eq!(
        error.downcast_ref::<FabricError>().unwrap().code,
        ErrorCode::Conflict
    );
    drop(first);
    let reopened = Authority::open(&root).unwrap();
    let after = reopened.info();
    assert_eq!(after.authority_id, info.authority_id);
    assert_eq!(after.vault_id, info.vault_id);
    assert!(after.epoch > info.epoch);
    assert!(after.generation > info.generation);
    assert_eq!(reopened.device(&id).unwrap().device_id, id);
    drop(reopened);
    assert!(Authority::initialize(&root, bootstrap()).is_err());
}

#[test]
fn corrupt_state_is_preserved_and_never_replaced_by_blank_authority() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("vault");
    drop(Authority::initialize(&root, bootstrap()).unwrap());
    let state = root.join("state.json");
    std::fs::write(&state, b"{broken-state").unwrap();
    assert!(Authority::open(&root).is_err());
    assert_eq!(std::fs::read(&state).unwrap(), b"{broken-state");
    assert!(Authority::initialize(&root, bootstrap()).is_err());
    assert_eq!(std::fs::read(&state).unwrap(), b"{broken-state");
}

#[cfg(unix)]
#[test]
fn symlink_root_cannot_alias_another_authority() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("vault");
    drop(Authority::initialize(&root, bootstrap()).unwrap());
    let alias = temporary.path().join("alias");
    std::os::unix::fs::symlink(&root, &alias).unwrap();
    assert!(Authority::open(&alias).is_err());
}
