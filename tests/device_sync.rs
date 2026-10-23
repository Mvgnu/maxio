use clap::Parser;
use maxio::config::Config;
use maxio::server::{self, AppState};
use maxio::storage::BucketMeta;
use maxio::sync::{SyncOptions, Synchronizer};
use std::net::SocketAddr;
use std::path::Path;
use tempfile::TempDir;

async fn peer() -> (String, TempDir, tokio::task::JoinHandle<()>) {
    let data = TempDir::new().unwrap();
    let config = Config::parse_from([
        "maxio",
        "--data-dir",
        data.path().to_str().unwrap(),
        "--access-key",
        "sync-test",
        "--secret-key",
        "sync-test-secret",
        "--min-disk-headroom-bytes",
        "0",
    ]);
    let state = AppState::from_config(config).await.unwrap();
    state
        .storage
        .create_bucket(&BucketMeta {
            name: "device-files".into(),
            created_at: chrono::Utc::now().to_rfc3339(),
            region: "us-east-1".into(),
            versioning: false,
        })
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            server::build_router(state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (endpoint, data, task)
}

fn options(root: &Path, endpoint: &str) -> SyncOptions {
    SyncOptions {
        local: root.into(),
        endpoint: endpoint.into(),
        bucket: "device-files".into(),
        prefix: "shared/".into(),
        access_key: "sync-test".into(),
        secret_key: "sync-test-secret".into(),
        region: "us-east-1".into(),
        max_file_bytes: 64 * 1024 * 1024,
    }
}

#[tokio::test]
async fn two_devices_roundtrip_nested_unicode_files_and_resume() {
    let (endpoint, _data, server) = peer().await;
    let a = TempDir::new().unwrap();
    let b = TempDir::new().unwrap();
    std::fs::create_dir(a.path().join("photos")).unwrap();
    let key = "photos/café + #%.txt";
    std::fs::write(a.path().join(key), b"from device A").unwrap();
    let mut first = Synchronizer::open(options(a.path(), &endpoint)).unwrap();
    assert_eq!(first.run_once().await.unwrap().uploaded, 1);
    let mut second = Synchronizer::open(options(b.path(), &endpoint)).unwrap();
    assert_eq!(second.run_once().await.unwrap().downloaded, 1);
    assert_eq!(std::fs::read(b.path().join(key)).unwrap(), b"from device A");
    std::fs::write(b.path().join(key), b"edited on B").unwrap();
    assert_eq!(second.run_once().await.unwrap().uploaded, 1);
    drop(first);
    let mut resumed = Synchronizer::open(options(a.path(), &endpoint)).unwrap();
    assert_eq!(resumed.run_once().await.unwrap().downloaded, 1);
    assert_eq!(std::fs::read(a.path().join(key)).unwrap(), b"edited on B");
    assert_eq!(resumed.run_once().await.unwrap().unchanged, 1);
    server.abort();
}

#[tokio::test]
async fn simultaneous_edits_preserve_local_conflict_and_remote_main() {
    let (endpoint, _data, server) = peer().await;
    let a = TempDir::new().unwrap();
    let b = TempDir::new().unwrap();
    std::fs::write(a.path().join("notes.txt"), b"original").unwrap();
    let mut first = Synchronizer::open(options(a.path(), &endpoint)).unwrap();
    let mut second = Synchronizer::open(options(b.path(), &endpoint)).unwrap();
    first.run_once().await.unwrap();
    second.run_once().await.unwrap();
    std::fs::write(a.path().join("notes.txt"), b"A offline edit").unwrap();
    std::fs::write(b.path().join("notes.txt"), b"B offline edit").unwrap();
    first.run_once().await.unwrap();
    assert_eq!(second.run_once().await.unwrap().conflicts, 1);
    assert_eq!(
        std::fs::read(b.path().join("notes.txt")).unwrap(),
        b"A offline edit"
    );
    let conflict = std::fs::read_dir(b.path())
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .contains(".maxio-conflict-")
        })
        .expect("conflicting bytes must remain visible beside original");
    assert_eq!(std::fs::read(conflict.path()).unwrap(), b"B offline edit");
    first.run_once().await.unwrap();
    assert_eq!(
        std::fs::read(a.path().join(conflict.file_name())).unwrap(),
        b"B offline edit"
    );
    server.abort();
}

#[tokio::test]
async fn missing_local_copy_is_restored_without_deleting_remote() {
    let (endpoint, _data, server) = peer().await;
    let local = TempDir::new().unwrap();
    std::fs::write(local.path().join("keep.txt"), b"keep me").unwrap();
    let mut sync = Synchronizer::open(options(local.path(), &endpoint)).unwrap();
    sync.run_once().await.unwrap();
    std::fs::remove_file(local.path().join("keep.txt")).unwrap();
    assert_eq!(sync.run_once().await.unwrap().downloaded, 1);
    assert_eq!(
        std::fs::read(local.path().join("keep.txt")).unwrap(),
        b"keep me"
    );
    server.abort();
}

#[test]
fn one_process_per_local_root_and_corrupt_journal_fails_closed() {
    let local = TempDir::new().unwrap();
    let endpoint = "http://127.0.0.1:9010";
    let first = Synchronizer::open(options(local.path(), endpoint)).unwrap();
    assert!(Synchronizer::open(options(local.path(), endpoint)).is_err());
    let journal = first.journal_path().to_path_buf();
    drop(first);
    std::fs::write(journal, b"not json").unwrap();
    assert!(Synchronizer::open(options(local.path(), endpoint)).is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_source_is_rejected_before_contacting_peer() {
    let local = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    std::fs::write(outside.path().join("private"), b"secret").unwrap();
    std::os::unix::fs::symlink(outside.path().join("private"), local.path().join("leak")).unwrap();
    let mut sync = Synchronizer::open(options(local.path(), "http://127.0.0.1:1")).unwrap();
    let error = sync.run_once().await.unwrap_err().to_string();
    assert!(error.contains("symlink"), "{error}");
    assert!(!sync.journal_path().exists());
}

#[tokio::test]
async fn failed_or_incomplete_listing_does_not_upload_local_files() {
    use axum::{Router, routing::get};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/device-files",
                get(|| async {
                    "<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>"
                }),
            ),
        )
        .await
        .unwrap();
    });
    let local = TempDir::new().unwrap();
    std::fs::write(local.path().join("notes.txt"), b"preserve").unwrap();
    let mut sync = Synchronizer::open(options(local.path(), &endpoint)).unwrap();
    assert!(
        sync.run_once()
            .await
            .unwrap_err()
            .to_string()
            .contains("continuation")
    );
    assert!(!sync.journal_path().exists());
    assert_eq!(
        std::fs::read(local.path().join("notes.txt")).unwrap(),
        b"preserve"
    );
    task.abort();
}

#[tokio::test]
async fn peer_ignoring_conditions_is_refused_before_uploading_user_files() {
    use axum::{
        Router,
        extract::{Path, State},
        http::{HeaderMap, StatusCode},
        routing::{get, put},
    };
    use std::sync::{Arc, Mutex};
    let writes = Arc::new(Mutex::new(Vec::<String>::new()));
    let app = Router::new()
        .route("/device-files", get(|| async { "<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>" }))
        .route("/device-files/{*key}", put(|Path(key): Path<String>, State(writes): State<Arc<Mutex<Vec<String>>>>| async move {
            writes.lock().unwrap().push(key);
            let mut headers = HeaderMap::new();
            headers.insert("etag", "\"ignored-conditional\"".parse().unwrap());
            (StatusCode::OK, headers)
        }).delete(|| async { StatusCode::NO_CONTENT }))
        .with_state(writes.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let local = TempDir::new().unwrap();
    std::fs::write(local.path().join("precious.txt"), b"keep local").unwrap();
    let mut sync = Synchronizer::open(options(local.path(), &endpoint)).unwrap();
    let error = sync.run_once().await.unwrap_err().to_string();
    assert!(error.contains("If-None-Match"), "{error}");
    let writes = writes.lock().unwrap();
    assert_eq!(writes.len(), 2);
    assert!(
        writes
            .iter()
            .all(|key| key.starts_with("shared/.maxio-sync/probes/"))
    );
    assert_eq!(
        std::fs::read(local.path().join("precious.txt")).unwrap(),
        b"keep local"
    );
    assert!(!sync.journal_path().exists());
    task.abort();
}

#[tokio::test]
async fn first_contact_with_different_content_preserves_both_versions() {
    let (endpoint, _data, server) = peer().await;
    let a = TempDir::new().unwrap();
    let b = TempDir::new().unwrap();
    std::fs::write(a.path().join("same.txt"), b"existing remote").unwrap();
    std::fs::write(b.path().join("same.txt"), b"existing local").unwrap();
    Synchronizer::open(options(a.path(), &endpoint))
        .unwrap()
        .run_once()
        .await
        .unwrap();
    let mut second = Synchronizer::open(options(b.path(), &endpoint)).unwrap();
    assert_eq!(second.run_once().await.unwrap().conflicts, 1);
    assert_eq!(
        std::fs::read(b.path().join("same.txt")).unwrap(),
        b"existing remote"
    );
    let conflict = std::fs::read_dir(b.path())
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .contains(".maxio-conflict-")
        })
        .unwrap();
    assert_eq!(std::fs::read(conflict.path()).unwrap(), b"existing local");
    server.abort();
}
