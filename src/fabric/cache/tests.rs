use super::*;
use crate::workspace::{FileVersion, RevisionRef};
use sha2::{Digest, Sha256};

struct Fixture {
    _temp: tempfile::TempDir,
    authority: AuthorityInfo,
    device: String,
    cache: PrivateCache,
    file: RetainedFile,
    bytes: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let authority = AuthorityInfo {
            format: FABRIC_FORMAT,
            authority_id: uuid::Uuid::new_v4().to_string(),
            vault_id: uuid::Uuid::new_v4().to_string(),
            epoch: 1,
            generation: 1,
            retention_policy_version: 1,
        };
        let device = uuid::Uuid::new_v4().to_string();
        let bytes: Vec<_> = (0..4 * 1024 * 1024)
            .map(|index| (index % 251) as u8)
            .collect();
        let file = RetainedFile {
            workspace_id: uuid::Uuid::new_v4().to_string(),
            revision: RevisionRef {
                revision: uuid::Uuid::new_v4().to_string(),
                sha256: "a".repeat(64),
            },
            path: "dataset/input.bin".into(),
            version: FileVersion {
                sha256: hex::encode(Sha256::digest(&bytes)),
                size: bytes.len() as u64,
                blob: format!("maxio-workspaces/test/blobs/{}", uuid::Uuid::new_v4()),
            },
        };
        let mut cache =
            PrivateCache::open(&temp.path().join("private"), &authority, &device).unwrap();
        let source = temp.path().join("original");
        std::fs::write(&source, &bytes).unwrap();
        cache.import(&file, &source).unwrap();
        Self {
            _temp: temp,
            authority,
            device,
            cache,
            file,
            bytes,
        }
    }

    fn proof(&self, files: &[RetainedFile]) -> RetentionVerification {
        let now = now_ms().unwrap();
        RetentionVerification {
            challenge: uuid::Uuid::new_v4().to_string(),
            authority_id: self.authority.authority_id.clone(),
            vault_id: self.authority.vault_id.clone(),
            epoch: self.authority.epoch,
            verified_at_unix_ms: now,
            valid_until_unix_ms: now + 60_000,
            receipts: files
                .iter()
                .map(|file| RetentionReceipt {
                    authority_id: self.authority.authority_id.clone(),
                    vault_id: self.authority.vault_id.clone(),
                    policy: RetentionPolicy::AppendOnlyNoGc,
                    policy_version: 1,
                    committed_generation: 1,
                    file: file.clone(),
                    recovery_reference: format!(
                        "maxio-workspace://{}/{}?revision={}",
                        file.workspace_id, file.path, file.revision.revision
                    ),
                })
                .collect(),
        }
    }
}

#[test]
fn fresh_exact_proof_removes_only_cache_inode_and_measures_the_observation() {
    let mut f = Fixture::new();
    let attempt = f.cache.root().join("attempts/retained");
    std::fs::create_dir_all(&attempt).unwrap();
    f.cache
        .copy_to(std::slice::from_ref(&f.file), &attempt)
        .unwrap();
    let dirty = attempt.join("unpublished.txt");
    std::fs::write(&dirty, b"unfinished work survives").unwrap();
    let proof =
        VerifiedRetention::from_authenticated_response(f.proof(std::slice::from_ref(&f.file)));
    let report = f
        .cache
        .evict_verified(std::slice::from_ref(&f.file), proof)
        .unwrap();
    assert_eq!(report.logical_bytes_removed, f.bytes.len() as u64);
    assert!(report.allocated_bytes_unlinked > 0);
    assert_eq!(
        report.observed_available_delta,
        (i128::from(report.available_bytes_after) - i128::from(report.available_bytes_before))
            as i64
    );
    assert!(f.cache.inventory(true).unwrap().entries.is_empty());
    assert_eq!(std::fs::read(attempt.join(&f.file.path)).unwrap(), f.bytes);
    assert_eq!(std::fs::read(dirty).unwrap(), b"unfinished work survives");
    let receipt = f
        .cache
        .root()
        .join("cache/receipts")
        .join(format!("{}.json", report.operation_id));
    let saved: serde_json::Value = fs::read_json(&receipt, MAX_STATE_BYTES).unwrap();
    assert_eq!(saved["state"], "evicted");
    assert_eq!(
        saved["report"]["logical_bytes_removed"],
        f.bytes.len() as u64
    );
}

#[test]
fn stale_wrong_missing_and_policy_proofs_preserve_bytes() {
    let mut f = Fixture::new();
    for variant in 0..5 {
        let mut proof = f.proof(std::slice::from_ref(&f.file));
        match variant {
            0 => proof.valid_until_unix_ms = 0,
            1 => proof.vault_id = uuid::Uuid::new_v4().to_string(),
            2 => proof.receipts.clear(),
            3 => proof.receipts[0].policy_version += 1,
            _ => proof.receipts[0].file.revision.revision = uuid::Uuid::new_v4().to_string(),
        }
        assert!(
            f.cache
                .evict_verified(
                    std::slice::from_ref(&f.file),
                    VerifiedRetention::from_authenticated_response(proof)
                )
                .is_err()
        );
        assert_eq!(
            std::fs::read(f.cache.object(&key(&f.file))).unwrap(),
            f.bytes
        );
        assert!(f.cache.state.pending.is_none());
    }
}

#[test]
fn pins_active_use_and_identical_content_inode_replacement_block_eviction() {
    let mut f = Fixture::new();
    f.cache.pin(std::slice::from_ref(&f.file), true).unwrap();
    let proof =
        VerifiedRetention::from_authenticated_response(f.proof(std::slice::from_ref(&f.file)));
    assert!(
        f.cache
            .evict_verified(std::slice::from_ref(&f.file), proof)
            .is_err()
    );
    f.cache.pin(std::slice::from_ref(&f.file), false).unwrap();
    let attempt = uuid::Uuid::new_v4().to_string();
    f.cache
        .protect(&attempt, std::slice::from_ref(&f.file))
        .unwrap();
    let proof =
        VerifiedRetention::from_authenticated_response(f.proof(std::slice::from_ref(&f.file)));
    assert!(
        f.cache
            .evict_verified(std::slice::from_ref(&f.file), proof)
            .is_err()
    );
    f.cache.release(&attempt).unwrap();
    let replacement = f.cache.root().join("replacement");
    std::fs::write(&replacement, &f.bytes).unwrap();
    std::fs::rename(replacement, f.cache.object(&key(&f.file))).unwrap();
    let proof =
        VerifiedRetention::from_authenticated_response(f.proof(std::slice::from_ref(&f.file)));
    assert!(
        f.cache
            .evict_verified(std::slice::from_ref(&f.file), proof)
            .is_err()
    );
    assert_eq!(
        std::fs::read(f.cache.object(&key(&f.file))).unwrap(),
        f.bytes
    );
}

#[test]
fn hardlink_alias_is_retained_and_not_advertised() {
    let mut f = Fixture::new();
    let alias = f.cache.root().join("outside-cache-alias");
    std::fs::hard_link(f.cache.object(&key(&f.file)), &alias).unwrap();
    assert!(f.cache.inventory(true).unwrap().cached_files.is_empty());
    let proof =
        VerifiedRetention::from_authenticated_response(f.proof(std::slice::from_ref(&f.file)));
    assert!(
        f.cache
            .evict_verified(std::slice::from_ref(&f.file), proof)
            .is_err()
    );
    assert_eq!(std::fs::read(alias).unwrap(), f.bytes);
}

#[test]
fn deduplicated_content_keeps_other_reference_pin() {
    let mut f = Fixture::new();
    let mut other = f.file.clone();
    other.path = "another/input.bin".into();
    other.revision.revision = uuid::Uuid::new_v4().to_string();
    other.version.blob = format!("maxio-workspaces/test/blobs/{}", uuid::Uuid::new_v4());
    let source = f._temp.path().join("original");
    f.cache.import(&other, &source).unwrap();
    f.cache.pin(std::slice::from_ref(&f.file), true).unwrap();
    f.cache.pin(std::slice::from_ref(&other), false).unwrap();
    let inventory = f.cache.inventory(true).unwrap();
    assert_eq!(inventory.entries.len(), 1);
    assert_eq!(inventory.cached_files.len(), 1);
    assert_eq!(inventory.logical_bytes, f.bytes.len() as u64);
    let proof =
        VerifiedRetention::from_authenticated_response(f.proof(std::slice::from_ref(&other)));
    assert!(f.cache.evict_verified(&[other], proof).is_err());
}

#[test]
fn interrupted_eviction_reconciles_missing_entry_without_deleting_survivor() {
    let mut f = Fixture::new();
    let mut second = f.file.clone();
    second.workspace_id = uuid::Uuid::new_v4().to_string();
    f.cache
        .import(&second, &f._temp.path().join("original"))
        .unwrap();
    let files = vec![f.file.clone(), second.clone()];
    let intent = EvictionIntent {
        operation_id: uuid::Uuid::new_v4().to_string(),
        entries: f.cache.evictable(&files).unwrap(),
        verification: f.proof(&files),
        available_before: fs::available(f.cache.root()).unwrap(),
    };
    let root = f.cache.root().to_path_buf();
    let mut state = f.cache.state.clone();
    state.pending = Some(intent.clone());
    f.cache.save(state).unwrap();
    std::fs::remove_file(f.cache.object(&key(&f.file))).unwrap();
    drop(f.cache);
    let cache = PrivateCache::open(&root, &f.authority, &f.device).unwrap();
    assert!(cache.state.pending.is_none());
    let inventory = cache.inventory(true).unwrap();
    assert_eq!(inventory.entries.len(), 1);
    assert_eq!(inventory.cached_files[0].workspace_id, second.workspace_id);
    assert_eq!(std::fs::read(cache.object(&key(&second))).unwrap(), f.bytes);
    let receipt: serde_json::Value = fs::read_json(
        &root
            .join("cache/receipts")
            .join(format!("{}.json", intent.operation_id)),
        MAX_STATE_BYTES,
    )
    .unwrap();
    assert_eq!(receipt["state"], "interrupted_reconciled");
    assert_eq!(
        receipt["report"]["logical_bytes_removed"],
        f.bytes.len() as u64
    );
}

#[test]
fn corrupt_state_never_resets_pins_or_adopts_existing_bytes() {
    let mut f = Fixture::new();
    f.cache.pin(std::slice::from_ref(&f.file), true).unwrap();
    let root = f.cache.root().to_path_buf();
    let object = f.cache.object(&key(&f.file));
    drop(f.cache);
    std::fs::write(root.join("cache/state.json"), b"corrupt").unwrap();
    assert!(PrivateCache::open(&root, &f.authority, &f.device).is_err());
    assert_eq!(
        std::fs::read(root.join("cache/state.json")).unwrap(),
        b"corrupt"
    );
    assert_eq!(std::fs::read(object).unwrap(), f.bytes);
}
