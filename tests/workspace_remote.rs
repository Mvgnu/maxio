//! Catalog acceptance against the real signed S3 router, without a process-level claim.
use clap::Parser;
use maxio::config::Config;
use maxio::server::{self, AppState};
use maxio::storage::BucketMeta;
use maxio::workspace::{Publication, RemoteConfig, WorkspaceRemote};
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
        "workspace-test",
        "--secret-key",
        "workspace-test-secret",
        "--min-disk-headroom-bytes",
        "0",
    ]);
    let state = AppState::from_config(config).await.unwrap();
    state
        .storage
        .create_bucket(&BucketMeta {
            name: "workspace-files".into(),
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

fn remote(endpoint: &str) -> WorkspaceRemote {
    WorkspaceRemote::connect(RemoteConfig {
        endpoint: endpoint.into(),
        bucket: "workspace-files".into(),
        name: "project".into(),
        region: "us-east-1".into(),
        access_key: "workspace-test".into(),
        secret_key: "workspace-test-secret".into(),
        session_token: None,
        ca_cert: None,
        allow_http: true,
    })
    .unwrap()
}

fn staged(root: &Path, path: &str, contents: &[u8]) -> Publication {
    let source = root.join(uuid::Uuid::new_v4().to_string());
    std::fs::write(&source, contents).unwrap();
    std::fs::File::open(&source).unwrap().sync_all().unwrap();
    let (sha256, size) = maxio::files::hash_file(&source).unwrap();
    Publication {
        path: path.into(),
        source,
        sha256,
        size,
    }
}

#[tokio::test]
async fn selective_publication_streams_and_preserves_exact_history() {
    let (endpoint, _data, server) = peer().await;
    let stages = TempDir::new().unwrap();
    let client = remote(&endpoint);
    let initial = client.initialize().await.unwrap();
    assert!(client.initialize().await.is_err());
    let source = staged(stages.path(), "src/café + #%.txt", b"first revision");
    let large_bytes = vec![0x5a; 9 * 1024 * 1024 + 17];
    let dataset = staged(stages.path(), "data/offers.bin", &large_bytes);
    let empty = staged(stages.path(), "src/empty.txt", b"");
    let first = client
        .publish(&initial, &[source.clone(), dataset.clone(), empty.clone()])
        .await
        .unwrap();
    assert_eq!(client.stats().payload_uploaded, source.size + dataset.size);
    assert_eq!(
        client.stats().payload_downloaded,
        source.size + dataset.size
    );
    let before = client.stats();
    let observed = remote(&endpoint).latest().await.unwrap();
    assert_eq!(observed.manifest.files.len(), 3);
    assert_eq!(client.stats().payload_downloaded, before.payload_downloaded);
    let updated = staged(stages.path(), &source.path, b"second revision");
    let second = client
        .publish(&first, std::slice::from_ref(&updated))
        .await
        .unwrap();
    assert_eq!(
        second.manifest.files[&dataset.path],
        first.manifest.files[&dataset.path]
    );
    let historic = client.revision(&first.manifest.revision).await.unwrap();
    assert!(historic.head_etag.is_none());
    assert_eq!(
        historic.manifest.files[&source.path],
        first.manifest.files[&source.path]
    );
    let download = stages.path().join("downloaded");
    client
        .download(&historic.manifest.files[&source.path], &download)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&download).unwrap(), b"first revision");
    assert!(
        client
            .download(&historic.manifest.files[&source.path], &download)
            .await
            .is_err()
    );
    assert!(client.publish(&historic, &[updated]).await.is_err());
    assert_eq!(std::fs::read(source.source).unwrap(), b"first revision");
    let empty_target = stages.path().join("empty-download");
    client
        .download(&first.manifest.files[&empty.path], &empty_target)
        .await
        .unwrap();
    assert_eq!(std::fs::metadata(empty_target).unwrap().len(), 0);
    server.abort();
}

#[tokio::test]
async fn concurrent_publication_rejects_one_writer_without_losing_its_source() {
    let (endpoint, _data, server) = peer().await;
    let stages = TempDir::new().unwrap();
    let a = remote(&endpoint);
    let b = remote(&endpoint);
    let base = a.initialize().await.unwrap();
    let edit_a = staged(stages.path(), "notes.txt", b"A's edit");
    let edit_b = staged(stages.path(), "notes.txt", b"B's edit");
    let aa = [edit_a.clone()];
    let bb = [edit_b.clone()];
    let (left, right) = tokio::join!(a.publish(&base, &aa), b.publish(&base, &bb));
    assert_ne!(
        left.is_ok(),
        right.is_ok(),
        "exactly one CAS writer must publish"
    );
    assert_eq!(std::fs::read(&edit_a.source).unwrap(), b"A's edit");
    assert_eq!(std::fs::read(&edit_b.source).unwrap(), b"B's edit");
    let winner = left.or(right).unwrap();
    let latest = a.latest().await.unwrap();
    assert_eq!(latest.manifest.revision, winner.manifest.revision);
    let target = stages.path().join("winner");
    b.download(&latest.manifest.files["notes.txt"], &target)
        .await
        .unwrap();
    assert_eq!(
        maxio::files::hash_file(&target).unwrap().0,
        latest.manifest.files["notes.txt"].sha256
    );
    assert!(a.publish(&base, &[edit_a]).await.is_err());
    server.abort();
}

#[tokio::test]
async fn changed_staging_content_and_wrong_hash_never_advance_head() {
    let (endpoint, _data, server) = peer().await;
    let stages = TempDir::new().unwrap();
    let client = remote(&endpoint);
    let base = client.initialize().await.unwrap();
    let file = staged(stages.path(), "notes.txt", b"before");
    std::fs::write(&file.source, b"mutate").unwrap();
    assert!(
        client
            .publish(&base, std::slice::from_ref(&file))
            .await
            .is_err()
    );
    assert_eq!(
        client.latest().await.unwrap().manifest.revision,
        base.manifest.revision
    );
    assert_eq!(std::fs::read(file.source).unwrap(), b"mutate");
    server.abort();
}

#[tokio::test]
async fn backend_ignoring_create_conditions_cannot_initialize() {
    use axum::{
        body::Body,
        extract::State,
        http::{Method, Request, Response, StatusCode},
    };
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    async fn ignores_conditions(
        State(head_writes): State<Arc<AtomicU64>>,
        request: Request<Body>,
    ) -> Response<Body> {
        if request.method() == Method::PUT {
            if request.uri().path().ends_with("/head.json") {
                head_writes.fetch_add(1, Ordering::Relaxed);
            }
            return Response::builder()
                .header("etag", "\"ignored-conditions\"")
                .body(Body::empty())
                .unwrap();
        }
        if request.method() == Method::DELETE {
            return Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Body::empty())
                .unwrap();
        }
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from(
                "<Error><Code>NoSuchKey</Code><Message>missing</Message></Error>",
            ))
            .unwrap()
    }
    let head_writes = Arc::new(AtomicU64::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let router = axum::Router::new()
        .fallback(ignores_conditions)
        .with_state(head_writes.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let error = remote(&endpoint).initialize().await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("does not enforce create-only writes"),
        "{error:#}"
    );
    assert_eq!(head_writes.load(Ordering::Relaxed), 0);
    server.abort();
}
