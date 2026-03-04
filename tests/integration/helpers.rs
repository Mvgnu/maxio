use maxio::config::{Config, MembershipProtocol, WriteDurabilityMode};
use maxio::metadata::{
    BucketMetadataState, BucketMetadataTombstoneState, ClusterMetadataListingStrategy,
    ObjectMetadataState, ObjectVersionMetadataState, PersistedMetadataState,
    persist_persisted_metadata_state,
};
use maxio::server;
use maxio::storage::{BucketMeta, ObjectMeta, filesystem::FilesystemStorage};
use std::net::SocketAddr;
use std::path::Path;
use tempfile::TempDir;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

pub(crate) type HmacSha256 = Hmac<Sha256>;

pub(crate) const ACCESS_KEY: &str = "minioadmin";
pub(crate) const SECRET_KEY: &str = "minioadmin";
pub(crate) const SECONDARY_ACCESS_KEY: &str = "secondary-admin";
pub(crate) const SECONDARY_SECRET_KEY: &str = "secondary-secret";
pub(crate) const REGION: &str = "us-east-1";

pub(crate) fn make_test_config(
    data_dir: String,
    erasure_coding: bool,
    chunk_size: u64,
    parity_shards: u32,
) -> Config {
    Config {
        port: 0,
        address: "127.0.0.1".to_string(),
        internal_bind_addr: None,
        data_dir,
        access_key: ACCESS_KEY.to_string(),
        secret_key: SECRET_KEY.to_string(),
        additional_credentials: Vec::new(),
        region: REGION.to_string(),
        node_id: "maxio-test-node".to_string(),
        cluster_peers: Vec::new(),
        membership_protocol: MembershipProtocol::StaticBootstrap,
        write_durability_mode: WriteDurabilityMode::DegradedSuccess,
        metadata_listing_strategy: ClusterMetadataListingStrategy::LocalNodeOnly,
        cluster_auth_token: None,
        cluster_peer_tls_cert_path: None,
        cluster_peer_tls_key_path: None,
        cluster_peer_tls_ca_path: None,
        cluster_peer_tls_cert_sha256: None,
        erasure_coding,
        chunk_size,
        parity_shards,
        min_disk_headroom_bytes: 268_435_456,
    }
}

pub(crate) fn make_test_config_with_secondary_credential(
    data_dir: String,
    erasure_coding: bool,
    chunk_size: u64,
    parity_shards: u32,
) -> Config {
    let mut config = make_test_config(data_dir, erasure_coding, chunk_size, parity_shards);
    config.additional_credentials =
        vec![format!("{}:{}", SECONDARY_ACCESS_KEY, SECONDARY_SECRET_KEY)];
    config
}

pub(crate) async fn start_server_with_config(config: Config, tmp: TempDir) -> (String, TempDir) {
    let state = server::AppState::from_config(config).await.unwrap();
    let app = server::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    (base_url, tmp)
}

pub(crate) async fn start_server_with_config_and_replay_worker(
    config: Config,
    tmp: TempDir,
) -> (String, TempDir) {
    let state = server::AppState::from_config(config).await.unwrap();
    server::spawn_pending_replication_replay_worker(state.clone());
    let app = server::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    (base_url, tmp)
}

pub(crate) async fn start_server_with_config_and_rebalance_replay_worker(
    config: Config,
    tmp: TempDir,
) -> (String, TempDir) {
    let state = server::AppState::from_config(config).await.unwrap();
    server::spawn_pending_rebalance_replay_worker(state.clone());
    let app = server::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    (base_url, tmp)
}

pub(crate) async fn start_server_with_config_and_membership_propagation_replay_worker(
    config: Config,
    tmp: TempDir,
) -> (String, TempDir) {
    let state = server::AppState::from_config(config).await.unwrap();
    server::spawn_pending_membership_propagation_replay_worker(state.clone());
    let app = server::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    (base_url, tmp)
}

pub(crate) async fn start_server_with_config_and_convergence_worker(
    config: Config,
    tmp: TempDir,
) -> (String, TempDir) {
    let state = server::AppState::from_config(config).await.unwrap();
    server::spawn_membership_convergence_probe_worker(state.clone());
    let app = server::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    (base_url, tmp)
}

pub(crate) async fn start_server_with_config_and_metadata_repair_replay_worker(
    config: Config,
    tmp: TempDir,
) -> (String, TempDir) {
    let state = server::AppState::from_config(config).await.unwrap();
    server::spawn_pending_metadata_repair_replay_worker(state.clone());
    let app = server::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    (base_url, tmp)
}

pub(crate) async fn start_server_with_split_internal_listener(
    config: Config,
    tmp: TempDir,
) -> (String, String, TempDir) {
    let state = server::AppState::from_config(config).await.unwrap();
    let public_app = server::build_public_router(state.clone());
    let internal_app = server::build_internal_router(state);

    let public_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public_addr = public_listener.local_addr().unwrap();
    let public_base_url = format!("http://{}", public_addr);

    let internal_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let internal_addr = internal_listener.local_addr().unwrap();
    let internal_base_url = format!("http://{}", internal_addr);

    tokio::spawn(async move {
        axum::serve(
            public_listener,
            public_app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    tokio::spawn(async move {
        axum::serve(
            internal_listener,
            internal_app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    (public_base_url, internal_base_url, tmp)
}

/// Spin up a test server on a random port, return the base URL.
pub(crate) async fn start_server() -> (String, TempDir) {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    start_server_with_config(config, tmp).await
}

pub(crate) async fn seed_bucket_in_data_dir(data_dir: &str, bucket: &str) {
    let storage = FilesystemStorage::new(data_dir, false, 10 * 1024 * 1024, 0)
        .await
        .unwrap();
    let created = storage
        .create_bucket(&BucketMeta {
            name: bucket.to_string(),
            created_at: chrono::Utc::now()
                .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                .to_string(),
            region: REGION.to_string(),
            versioning: false,
        })
        .await
        .unwrap();
    assert!(created, "expected seeded bucket '{}' to be created", bucket);
}

pub(crate) fn seed_consensus_metadata_buckets(
    data_dir: &str,
    view_id: &str,
    buckets: &[BucketMetadataState],
) {
    seed_consensus_metadata_bucket_state(data_dir, view_id, buckets, &[]);
}

pub(crate) fn seed_consensus_metadata_bucket_state(
    data_dir: &str,
    view_id: &str,
    buckets: &[BucketMetadataState],
    bucket_tombstones: &[BucketMetadataTombstoneState],
) {
    let state = PersistedMetadataState {
        view_id: view_id.to_string(),
        buckets: buckets.to_vec(),
        bucket_tombstones: bucket_tombstones.to_vec(),
        objects: Vec::new(),
        object_versions: Vec::new(),
    };
    let state_path = Path::new(data_dir)
        .join(".maxio-runtime")
        .join("cluster-metadata-state.json");
    std::fs::create_dir_all(
        state_path
            .parent()
            .expect("consensus metadata state path should have parent"),
    )
    .expect("consensus metadata runtime dir should be creatable");
    persist_persisted_metadata_state(state_path.as_path(), &state)
        .expect("consensus metadata state should persist");
}

pub(crate) fn seed_consensus_metadata_object_rows(
    data_dir: &str,
    view_id: &str,
    buckets: &[BucketMetadataState],
    objects: &[ObjectMetadataState],
) {
    let state = PersistedMetadataState {
        view_id: view_id.to_string(),
        buckets: buckets.to_vec(),
        bucket_tombstones: Vec::new(),
        objects: objects.to_vec(),
        object_versions: Vec::new(),
    };
    let state_path = Path::new(data_dir)
        .join(".maxio-runtime")
        .join("cluster-metadata-state.json");
    std::fs::create_dir_all(
        state_path
            .parent()
            .expect("consensus metadata state path should have parent"),
    )
    .expect("consensus metadata runtime dir should be creatable");
    persist_persisted_metadata_state(state_path.as_path(), &state)
        .expect("consensus metadata state should persist");
}

pub(crate) fn seed_consensus_metadata_object_version_rows(
    data_dir: &str,
    view_id: &str,
    buckets: &[BucketMetadataState],
    object_versions: &[ObjectVersionMetadataState],
) {
    let state = PersistedMetadataState {
        view_id: view_id.to_string(),
        buckets: buckets.to_vec(),
        bucket_tombstones: Vec::new(),
        objects: Vec::new(),
        object_versions: object_versions.to_vec(),
    };
    let state_path = Path::new(data_dir)
        .join(".maxio-runtime")
        .join("cluster-metadata-state.json");
    std::fs::create_dir_all(
        state_path
            .parent()
            .expect("consensus metadata state path should have parent"),
    )
    .expect("consensus metadata runtime dir should be creatable");
    persist_persisted_metadata_state(state_path.as_path(), &state)
        .expect("consensus metadata state should persist");
}

pub(crate) async fn seed_object_in_data_dir(
    data_dir: &str,
    bucket: &str,
    key: &str,
    body: &[u8],
    versioning: bool,
) {
    let storage = FilesystemStorage::new(data_dir, false, 10 * 1024 * 1024, 0)
        .await
        .expect("storage should initialize");
    let _ = storage
        .create_bucket(&BucketMeta {
            name: bucket.to_string(),
            created_at: chrono::Utc::now()
                .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                .to_string(),
            region: REGION.to_string(),
            versioning: false,
        })
        .await
        .expect("bucket seed should succeed");

    if versioning {
        storage
            .set_versioning(bucket, true)
            .await
            .expect("versioning seed should succeed");
    }

    storage
        .put_object(
            bucket,
            key,
            "application/octet-stream",
            Box::pin(std::io::Cursor::new(body.to_vec())),
            None,
        )
        .await
        .expect("object seed should succeed");
}

pub(crate) async fn list_object_versions_from_data_dir(
    data_dir: &str,
    bucket: &str,
    key: &str,
) -> Vec<ObjectMeta> {
    let storage = FilesystemStorage::new(data_dir, false, 10 * 1024 * 1024, 0)
        .await
        .expect("storage should initialize");
    storage
        .list_object_versions(bucket, key)
        .await
        .expect("object versions should list")
}

/// Start a server with erasure coding enabled (small chunk size for testing).
pub(crate) async fn start_server_ec() -> (String, TempDir) {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let config = make_test_config(data_dir, true, 1024, 0);
    start_server_with_config(config, tmp).await
}

/// Sign a request with AWS Signature V4.
pub(crate) fn sign_request(
    method: &str,
    url: &str,
    headers: &mut Vec<(String, String)>,
    body: &[u8],
) {
    sign_request_with_credentials(method, url, headers, body, ACCESS_KEY, SECRET_KEY, REGION);
}

pub(crate) fn sign_request_with_credentials(
    method: &str,
    url: &str,
    headers: &mut Vec<(String, String)>,
    body: &[u8],
    access_key: &str,
    secret_key: &str,
    region: &str,
) {
    for (name, _) in headers.iter_mut() {
        *name = name.to_ascii_lowercase();
    }

    let parsed = reqwest::Url::parse(url).unwrap();
    let host = parsed.host_str().unwrap();
    let port = parsed.port().unwrap();
    let host_header = format!("{}:{}", host, port);
    let path = parsed.path();
    let query = parsed.query().unwrap_or("");

    let now = chrono::Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

    let payload_hash = hex::encode(Sha256::digest(body));

    headers.push(("host".to_string(), host_header.clone()));
    headers.push(("x-amz-date".to_string(), amz_date.clone()));
    headers.push(("x-amz-content-sha256".to_string(), payload_hash.clone()));

    // Sort signed headers
    headers.sort_by(|a, b| a.0.cmp(&b.0));

    let signed_headers: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
    let signed_headers_str = signed_headers.join(";");

    let canonical_headers: String = headers
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
        .collect();

    // Normalize query string: sort params and ensure key=value format
    let canonical_qs = if query.is_empty() {
        String::new()
    } else {
        let mut pairs: Vec<(String, String)> = query
            .split('&')
            .filter(|s| !s.is_empty())
            .map(|pair| {
                let mut parts = pair.splitn(2, '=');
                let key = parts.next().unwrap_or("").to_string();
                let val = parts.next().unwrap_or("").to_string();
                (key, val)
            })
            .collect();
        pairs.sort();
        pairs
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&")
    };

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, path, canonical_qs, canonical_headers, signed_headers_str, payload_hash
    );

    let scope = format!("{}/{}/s3/aws4_request", date_stamp, region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date,
        scope,
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    // Derive signing key
    let key = format!("AWS4{}", secret_key);
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
    mac.update(date_stamp.as_bytes());
    let date_key = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(&date_key).unwrap();
    mac.update(region.as_bytes());
    let date_region_key = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(&date_region_key).unwrap();
    mac.update(b"s3");
    let date_region_service_key = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(&date_region_service_key).unwrap();
    mac.update(b"aws4_request");
    let signing_key = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(&signing_key).unwrap();
    mac.update(string_to_sign.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        access_key, scope, signed_headers_str, signature
    );
    headers.push(("authorization".to_string(), auth));
}

pub(crate) fn client() -> reqwest::Client {
    reqwest::Client::new()
}

/// Sign a request using comma-only separators (no spaces), like mc does.
pub(crate) fn sign_request_compact(
    method: &str,
    url: &str,
    headers: &mut Vec<(String, String)>,
    body: &[u8],
) {
    for (name, _) in headers.iter_mut() {
        *name = name.to_ascii_lowercase();
    }

    // Reuse the same signing logic but produce compact auth header
    let parsed = reqwest::Url::parse(url).unwrap();
    let host = parsed.host_str().unwrap();
    let port = parsed.port().unwrap();
    let host_header = format!("{}:{}", host, port);
    let path = parsed.path();
    let query = parsed.query().unwrap_or("");

    let now = chrono::Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

    let payload_hash = hex::encode(Sha256::digest(body));

    headers.push(("host".to_string(), host_header.clone()));
    headers.push(("x-amz-date".to_string(), amz_date.clone()));
    headers.push(("x-amz-content-sha256".to_string(), payload_hash.clone()));

    headers.sort_by(|a, b| a.0.cmp(&b.0));

    let signed_headers: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
    let signed_headers_str = signed_headers.join(";");

    let canonical_headers: String = headers
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
        .collect();

    let canonical_qs = if query.is_empty() {
        String::new()
    } else {
        let mut pairs: Vec<(String, String)> = query
            .split('&')
            .filter(|s| !s.is_empty())
            .map(|pair| {
                let mut parts = pair.splitn(2, '=');
                let key = parts.next().unwrap_or("").to_string();
                let val = parts.next().unwrap_or("").to_string();
                (key, val)
            })
            .collect();
        pairs.sort();
        pairs
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&")
    };

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, path, canonical_qs, canonical_headers, signed_headers_str, payload_hash
    );

    let scope = format!("{}/{}/s3/aws4_request", date_stamp, REGION);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date,
        scope,
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    let key = format!("AWS4{}", SECRET_KEY);
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
    mac.update(date_stamp.as_bytes());
    let date_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&date_key).unwrap();
    mac.update(REGION.as_bytes());
    let date_region_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&date_region_key).unwrap();
    mac.update(b"s3");
    let date_region_service_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&date_region_service_key).unwrap();
    mac.update(b"aws4_request");
    let signing_key = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(&signing_key).unwrap();
    mac.update(string_to_sign.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    // Compact format: no spaces after commas (like mc sends)
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders={},Signature={}",
        ACCESS_KEY, scope, signed_headers_str, signature
    );
    headers.push(("authorization".to_string(), auth));
}

/// Build a signed request and send it.
pub(crate) async fn s3_request(method: &str, url: &str, body: Vec<u8>) -> reqwest::Response {
    let mut headers = Vec::new();
    sign_request(method, url, &mut headers, &body);

    let client = client();
    let mut builder = match method {
        "GET" => client.get(url),
        "PUT" => client.put(url),
        "HEAD" => client.head(url),
        "DELETE" => client.delete(url),
        "POST" => client.post(url),
        _ => panic!("unsupported method"),
    };

    for (k, v) in &headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    if !body.is_empty() {
        builder = builder.body(body);
    }

    builder.send().await.unwrap()
}

pub(crate) async fn s3_request_with_credentials(
    method: &str,
    url: &str,
    body: Vec<u8>,
    access_key: &str,
    secret_key: &str,
) -> reqwest::Response {
    let mut headers = Vec::new();
    sign_request_with_credentials(
        method,
        url,
        &mut headers,
        &body,
        access_key,
        secret_key,
        REGION,
    );

    let client = client();
    let mut builder = match method {
        "GET" => client.get(url),
        "PUT" => client.put(url),
        "HEAD" => client.head(url),
        "DELETE" => client.delete(url),
        "POST" => client.post(url),
        _ => panic!("unsupported method"),
    };

    for (k, v) in &headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    if !body.is_empty() {
        builder = builder.body(body);
    }

    builder.send().await.unwrap()
}

/// Like s3_request but returns Result instead of panicking on send errors.
pub(crate) async fn s3_request_result(
    method: &str,
    url: &str,
    body: Vec<u8>,
) -> Result<reqwest::Response, reqwest::Error> {
    let mut headers = Vec::new();
    sign_request(method, url, &mut headers, &body);

    let client = client();
    let mut builder = match method {
        "GET" => client.get(url),
        "PUT" => client.put(url),
        "HEAD" => client.head(url),
        "DELETE" => client.delete(url),
        "POST" => client.post(url),
        _ => panic!("unsupported method"),
    };

    for (k, v) in &headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    if !body.is_empty() {
        builder = builder.body(body);
    }

    builder.send().await
}

/// Sign and send a request with extra headers (e.g. x-amz-copy-source).
pub(crate) async fn s3_request_with_headers(
    method: &str,
    url: &str,
    body: Vec<u8>,
    extra_headers: Vec<(&str, &str)>,
) -> reqwest::Response {
    let mut headers: Vec<(String, String)> = extra_headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    sign_request(method, url, &mut headers, &body);

    let client = client();
    let mut builder = match method {
        "GET" => client.get(url),
        "PUT" => client.put(url),
        "HEAD" => client.head(url),
        "DELETE" => client.delete(url),
        "POST" => client.post(url),
        _ => panic!("unsupported method"),
    };

    for (k, v) in &headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    if !body.is_empty() {
        builder = builder.body(body);
    }

    builder.send().await.unwrap()
}

/// Build a signed request with compact auth header (no spaces after commas).
pub(crate) async fn s3_request_compact(
    method: &str,
    url: &str,
    body: Vec<u8>,
) -> reqwest::Response {
    let mut headers = Vec::new();
    sign_request_compact(method, url, &mut headers, &body);

    let client = client();
    let mut builder = match method {
        "GET" => client.get(url),
        "PUT" => client.put(url),
        "HEAD" => client.head(url),
        "DELETE" => client.delete(url),
        "POST" => client.post(url),
        _ => panic!("unsupported method"),
    };

    for (k, v) in &headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    if !body.is_empty() {
        builder = builder.body(body);
    }

    builder.send().await.unwrap()
}

/// Build a PUT request with STREAMING-AWS4-HMAC-SHA256-PAYLOAD (AWS chunked encoding).
pub(crate) async fn s3_put_chunked(url: &str, data: &[u8]) -> reqwest::Response {
    let parsed = reqwest::Url::parse(url).unwrap();
    let host = parsed.host_str().unwrap();
    let port = parsed.port().unwrap();
    let host_header = format!("{}:{}", host, port);
    let path = parsed.path();
    let query = parsed.query().unwrap_or("");

    let now = chrono::Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

    // For streaming, the payload hash is the literal string
    let payload_hash = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";

    let mut sign_headers = [
        ("host".to_string(), host_header.clone()),
        ("x-amz-content-sha256".to_string(), payload_hash.to_string()),
        ("x-amz-date".to_string(), amz_date.clone()),
        (
            "x-amz-decoded-content-length".to_string(),
            data.len().to_string(),
        ),
    ];
    sign_headers.sort_by(|a, b| a.0.cmp(&b.0));

    let signed_headers: Vec<&str> = sign_headers.iter().map(|(k, _)| k.as_str()).collect();
    let signed_headers_str = signed_headers.join(";");

    let canonical_headers: String = sign_headers
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
        .collect();

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        "PUT", path, query, canonical_headers, signed_headers_str, payload_hash
    );

    let scope = format!("{}/{}/s3/aws4_request", date_stamp, REGION);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date,
        scope,
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    let key = format!("AWS4{}", SECRET_KEY);
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
    mac.update(date_stamp.as_bytes());
    let date_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&date_key).unwrap();
    mac.update(REGION.as_bytes());
    let date_region_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&date_region_key).unwrap();
    mac.update(b"s3");
    let date_region_service_key = mac.finalize().into_bytes();
    let mut mac = HmacSha256::new_from_slice(&date_region_service_key).unwrap();
    mac.update(b"aws4_request");
    let signing_key = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(&signing_key).unwrap();
    mac.update(string_to_sign.as_bytes());
    let seed_signature = hex::encode(mac.finalize().into_bytes());

    // Compact auth header (no spaces)
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders={},Signature={}",
        ACCESS_KEY, scope, signed_headers_str, seed_signature
    );

    // Build AWS chunked body: "<hex_size>;chunk-signature=<sig>\r\n<data>\r\n0;chunk-signature=<sig>\r\n"
    // For simplicity, compute chunk signatures with a dummy (real mc would chain them)
    let chunk_sig = "0".repeat(64); // placeholder — server doesn't verify chunk sigs
    let mut chunked_body = Vec::new();
    chunked_body.extend_from_slice(
        format!("{:x};chunk-signature={}\r\n", data.len(), chunk_sig).as_bytes(),
    );
    chunked_body.extend_from_slice(data);
    chunked_body.extend_from_slice(b"\r\n");
    chunked_body.extend_from_slice(format!("0;chunk-signature={}\r\n", chunk_sig).as_bytes());

    client()
        .put(url)
        .header("host", &host_header)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", payload_hash)
        .header("x-amz-decoded-content-length", data.len().to_string())
        .header("authorization", &auth)
        .header("content-type", "application/octet-stream")
        .body(chunked_body)
        .send()
        .await
        .unwrap()
}

pub(crate) fn extract_xml_tag(body: &str, tag: &str) -> Option<String> {
    let start = format!("<{}>", tag);
    let end = format!("</{}>", tag);
    let from = body.find(&start)? + start.len();
    let to = body[from..].find(&end)? + from;
    Some(body[from..to].to_string())
}
