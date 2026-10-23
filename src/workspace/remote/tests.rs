use super::*;
use object_store::memory::InMemory;
use object_store::path::Path as ObjectPath;
use tempfile::TempDir;

fn memory() -> WorkspaceRemote {
    WorkspaceRemote {
        store: Arc::new(InMemory::new()),
        target: "memory-test".into(),
        prefix: "maxio-workspaces/test/".into(),
        counters: transport::Counters::default(),
        conditional_verified: OnceCell::new(),
    }
}

fn config(endpoint: &str) -> RemoteConfig {
    RemoteConfig {
        endpoint: endpoint.into(),
        bucket: "workspace-tests".into(),
        name: "test".into(),
        region: "us-east-1".into(),
        access_key: "test-access".into(),
        secret_key: "test-secret".into(),
        session_token: None,
        ca_cert: None,
        allow_http: false,
    }
}

#[test]
fn explicit_configuration_rejects_ambiguous_or_insecure_targets() {
    for endpoint in [
        "http://localhost:9000",
        "https://user:pass@example.com",
        "https://example.com/path",
        "https://example.com/?query=1",
        "https://example.com/#fragment",
    ] {
        assert!(
            WorkspaceRemote::connect(config(endpoint)).is_err(),
            "{endpoint}"
        );
    }
    let mut empty = config("https://example.com");
    empty.access_key.clear();
    assert!(WorkspaceRemote::connect(empty).is_err());
    let mut ca_over_http = config("http://localhost:9000");
    ca_over_http.allow_http = true;
    ca_over_http.ca_cert = Some("unused.pem".into());
    assert!(WorkspaceRemote::connect(ca_over_http).is_err());
}

#[tokio::test]
async fn history_never_exposes_uncommitted_revisions() {
    let remote = memory();
    let published = remote.initialize().await.unwrap();
    let mut orphan = published.manifest.clone();
    orphan.revision = Uuid::new_v4().to_string();
    orphan.parent = Some(RevisionRef {
        revision: published.manifest.revision.clone(),
        sha256: published.manifest_sha256.clone(),
    });
    let orphan = remote.write_revision(orphan).await.unwrap();
    assert!(remote.revision(&orphan.manifest.revision).await.is_err());
    assert_eq!(
        remote.latest().await.unwrap().manifest.revision,
        published.manifest.revision
    );
    let exact = remote.revision(&published.manifest.revision).await.unwrap();
    assert!(exact.head_etag.is_none());
}

#[tokio::test]
async fn corrupt_blobs_leave_a_recoverable_stage_and_existing_files_intact() {
    let remote = memory();
    let key = format!("{}blobs/{}", remote.prefix, Uuid::new_v4());
    remote
        .store
        .put(
            &ObjectPath::from(key.clone()),
            bytes::Bytes::from_static(b"wrong").into(),
        )
        .await
        .unwrap();
    let file = FileVersion {
        sha256: transport::hash_bytes(b"right"),
        size: 5,
        blob: key,
    };
    let temp = TempDir::new().unwrap();
    let target = temp.path().join("stage");
    assert!(remote.download(&file, &target).await.is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"wrong");
    assert!(remote.download(&file, &target).await.is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"wrong");
    assert_eq!(remote.stats().payload_downloaded, 5);
}

#[tokio::test]
async fn metadata_readback_rejects_corruption_and_cross_workspace_blobs() {
    let remote = memory();
    let initial = remote.initialize().await.unwrap();
    remote
        .store
        .put(
            &ObjectPath::from(remote.revision_key(&initial.manifest.revision)),
            bytes::Bytes::from_static(b"{}").into(),
        )
        .await
        .unwrap();
    assert!(remote.latest().await.is_err());
    let wrong = FileVersion {
        sha256: transport::hash_bytes(b"x"),
        size: 1,
        blob: format!("maxio-workspaces/other/blobs/{}", Uuid::new_v4()),
    };
    assert!(remote.validate_blob(&wrong).is_err());
}

#[tokio::test]
async fn committed_revision_is_recovered_after_an_ambiguous_retried_cas() {
    let remote = memory();
    let base = remote.initialize().await.unwrap();
    let mode = PutMode::Update(UpdateVersion {
        e_tag: base.head_etag.clone(),
        version: None,
    });
    let mut manifest = base.manifest.clone();
    manifest.revision = Uuid::new_v4().to_string();
    manifest.parent = Some(RevisionRef {
        revision: base.manifest.revision.clone(),
        sha256: base.manifest_sha256.clone(),
    });
    let attempt = remote.write_revision(manifest).await.unwrap();
    let committed = remote
        .commit_head(attempt.clone(), mode.clone())
        .await
        .unwrap();
    // A lost acknowledgment followed by the SDK retry reaches this same stale
    // conditional request. Finding our unique revision makes its outcome known.
    let recovered = remote
        .commit_head(attempt.clone(), mode.clone())
        .await
        .unwrap();
    assert!(same_revision(&recovered, &committed));
    assert!(recovered.head_etag.is_some());

    let mut later = committed.manifest.clone();
    later.revision = Uuid::new_v4().to_string();
    later.parent = Some(RevisionRef {
        revision: committed.manifest.revision.clone(),
        sha256: committed.manifest_sha256.clone(),
    });
    let later = remote.write_revision(later).await.unwrap();
    let newest = remote
        .commit_head(
            later,
            PutMode::Update(UpdateVersion {
                e_tag: committed.head_etag.clone(),
                version: None,
            }),
        )
        .await
        .unwrap();
    let error = remote.commit_head(attempt, mode).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("was published, but another writer")
    );
    assert!(error.to_string().contains("staged files are retained"));
    assert!(same_revision(&remote.latest().await.unwrap(), &newest));
}

#[tokio::test]
async fn history_limit_refuses_old_resolution_without_deleting_history() {
    let remote = memory();
    let first = remote.initialize().await.unwrap();
    let mut current = first.clone();
    for _ in 0..MAX_HISTORY_REVISIONS {
        let mut next = current.manifest.clone();
        next.revision = Uuid::new_v4().to_string();
        next.parent = Some(RevisionRef {
            revision: current.manifest.revision.clone(),
            sha256: current.manifest_sha256.clone(),
        });
        let next = remote.write_revision(next).await.unwrap();
        current = remote
            .commit_head(
                next,
                PutMode::Update(UpdateVersion {
                    e_tag: current.head_etag.clone(),
                    version: None,
                }),
            )
            .await
            .unwrap();
    }
    let error = remote.revision(&first.manifest.revision).await.unwrap_err();
    assert!(error.to_string().contains("exceeds 256 revisions"));
    assert!(
        remote
            .store
            .head(&ObjectPath::from(
                remote.revision_key(&first.manifest.revision)
            ))
            .await
            .is_ok()
    );
    assert!(same_revision(
        &remote.revision(&current.manifest.revision).await.unwrap(),
        &current
    ));
}
