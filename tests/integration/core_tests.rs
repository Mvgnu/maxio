use super::*;
use base64::Engine;
use hmac::Mac;
use maxio::storage::placement::primary_object_owner_with_self;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const DISTRIBUTED_LOCAL_NODE: &str = "node-a.internal:9000";
const DISTRIBUTED_PEER_NODE: &str = "127.0.0.1:39001";

struct ForwardingPair {
    coordinator_url: String,
    owner_url: String,
    owner_peer: String,
    _coordinator_tmp: TempDir,
    _owner_tmp: TempDir,
}

fn distributed_local_owner_key(seed: &str) -> String {
    let peers = vec![DISTRIBUTED_PEER_NODE.to_string()];
    distributed_local_owner_key_for(seed, DISTRIBUTED_LOCAL_NODE, &peers)
}

fn distributed_local_owner_key_for(seed: &str, local_node: &str, peers: &[String]) -> String {
    for idx in 0..1024 {
        let key = format!("{seed}-local-{idx}.txt");
        let owner = primary_object_owner_with_self(&key, local_node, peers);
        if owner.as_deref() == Some(local_node) {
            return key;
        }
    }
    panic!("unable to find local-owner key for distributed test");
}

fn distributed_non_owner_key(seed: &str) -> String {
    let peers = vec![DISTRIBUTED_PEER_NODE.to_string()];
    distributed_non_owner_key_for(seed, DISTRIBUTED_LOCAL_NODE, &peers)
}

fn distributed_non_owner_key_for(seed: &str, local_node: &str, peers: &[String]) -> String {
    for idx in 0..1024 {
        let key = format!("{seed}-forward-{idx}.txt");
        let owner = primary_object_owner_with_self(&key, local_node, peers);
        if owner.as_deref() != Some(local_node) {
            return key;
        }
    }
    panic!("unable to find non-owner key for distributed test");
}

fn host_port_from_base_url(base_url: &str) -> String {
    let parsed = reqwest::Url::parse(base_url).expect("base url should parse");
    let host = parsed.host_str().expect("base url should have host");
    let port = parsed.port().expect("base url should have explicit port");
    format!("{host}:{port}")
}

async fn start_forwarding_pair() -> ForwardingPair {
    let (owner_url, owner_tmp) = start_server().await;
    let owner_peer = host_port_from_base_url(&owner_url);

    let coordinator_tmp = TempDir::new().expect("tempdir");
    let data_dir = coordinator_tmp.path().to_string_lossy().to_string();
    let mut coordinator_config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    coordinator_config.node_id = DISTRIBUTED_LOCAL_NODE.to_string();
    coordinator_config.cluster_peers = vec![owner_peer.clone()];
    let (coordinator_url, coordinator_tmp) =
        start_server_with_config(coordinator_config, coordinator_tmp).await;

    ForwardingPair {
        coordinator_url,
        owner_url,
        owner_peer,
        _coordinator_tmp: coordinator_tmp,
        _owner_tmp: owner_tmp,
    }
}

#[tokio::test]
async fn test_create_bucket() {
    let (base_url, _tmp) = start_server().await;

    // Create bucket
    let resp = s3_request("PUT", &format!("{}/test-bucket", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);

    // Head bucket should succeed
    let resp = s3_request("HEAD", &format!("{}/test-bucket", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_put_object_standalone_omits_routing_headers() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/routing-standalone", base_url), vec![]).await;

    let put = s3_request(
        "PUT",
        &format!("{}/routing-standalone/docs/a.txt", base_url),
        b"hello".to_vec(),
    )
    .await;
    assert_eq!(put.status(), 200);
    assert!(put.headers().get("x-maxio-primary-owner").is_none());
    assert!(put.headers().get("x-maxio-forward-target").is_none());
    assert!(
        put.headers()
            .get("x-maxio-routing-local-primary-owner")
            .is_none()
    );
}

#[tokio::test]
async fn test_put_object_distributed_sets_routing_headers() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = DISTRIBUTED_LOCAL_NODE.to_string();
    config.cluster_peers = vec![DISTRIBUTED_PEER_NODE.to_string()];

    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    s3_request("PUT", &format!("{}/routing-distributed", base_url), vec![]).await;

    let key = distributed_local_owner_key("routing-distributed");
    let put = s3_request(
        "PUT",
        &format!("{}/routing-distributed/{}", base_url, key),
        b"hello".to_vec(),
    )
    .await;
    assert_eq!(put.status(), 200);

    let primary_owner = put
        .headers()
        .get("x-maxio-primary-owner")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-maxio-primary-owner")
        .to_string();
    let local_primary = put
        .headers()
        .get("x-maxio-routing-local-primary-owner")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-maxio-routing-local-primary-owner");

    assert!(local_primary == "true" || local_primary == "false");
    if local_primary == "false" {
        assert_eq!(
            put.headers()
                .get("x-maxio-forward-target")
                .and_then(|v| v.to_str().ok()),
            Some(primary_owner.as_str())
        );
    } else {
        assert!(put.headers().get("x-maxio-forward-target").is_none());
    }
}

#[tokio::test]
async fn test_copy_object_distributed_sets_routing_headers() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = DISTRIBUTED_LOCAL_NODE.to_string();
    config.cluster_peers = vec![DISTRIBUTED_PEER_NODE.to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    s3_request("PUT", &format!("{}/routing-copy", base_url), vec![]).await;
    let source_key = distributed_local_owner_key("routing-copy-src");
    let destination_key = distributed_local_owner_key("routing-copy-dst");
    s3_request(
        "PUT",
        &format!("{}/routing-copy/{}", base_url, source_key),
        b"copy me".to_vec(),
    )
    .await;
    let copy_source = format!("/routing-copy/{}", source_key);

    let copy = s3_request_with_headers(
        "PUT",
        &format!("{}/routing-copy/{}", base_url, destination_key),
        vec![],
        vec![("x-amz-copy-source", copy_source.as_str())],
    )
    .await;
    assert_eq!(copy.status(), 200);

    let primary_owner = copy
        .headers()
        .get("x-maxio-primary-owner")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-maxio-primary-owner")
        .to_string();
    let local_primary = copy
        .headers()
        .get("x-maxio-routing-local-primary-owner")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-maxio-routing-local-primary-owner");

    assert!(local_primary == "true" || local_primary == "false");
    if local_primary == "false" {
        assert_eq!(
            copy.headers()
                .get("x-maxio-forward-target")
                .and_then(|v| v.to_str().ok()),
            Some(primary_owner.as_str())
        );
    } else {
        assert!(copy.headers().get("x-maxio-forward-target").is_none());
    }
}

#[tokio::test]
async fn test_delete_object_distributed_sets_routing_headers() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = DISTRIBUTED_LOCAL_NODE.to_string();
    config.cluster_peers = vec![DISTRIBUTED_PEER_NODE.to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    s3_request("PUT", &format!("{}/routing-delete", base_url), vec![]).await;
    let key = distributed_local_owner_key("routing-delete");
    s3_request(
        "PUT",
        &format!("{}/routing-delete/{}", base_url, key),
        b"delete me".to_vec(),
    )
    .await;

    let delete = s3_request(
        "DELETE",
        &format!("{}/routing-delete/{}", base_url, key),
        vec![],
    )
    .await;
    assert_eq!(delete.status(), 204);

    let primary_owner = delete
        .headers()
        .get("x-maxio-primary-owner")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-maxio-primary-owner")
        .to_string();
    let local_primary = delete
        .headers()
        .get("x-maxio-routing-local-primary-owner")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-maxio-routing-local-primary-owner");

    assert!(local_primary == "true" || local_primary == "false");
    if local_primary == "false" {
        assert_eq!(
            delete
                .headers()
                .get("x-maxio-forward-target")
                .and_then(|v| v.to_str().ok()),
            Some(primary_owner.as_str())
        );
    } else {
        assert!(delete.headers().get("x-maxio-forward-target").is_none());
    }
}

#[tokio::test]
async fn test_put_object_distributed_non_owner_write_returns_access_denied_when_forward_target_unreachable()
 {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = DISTRIBUTED_LOCAL_NODE.to_string();
    config.cluster_peers = vec![DISTRIBUTED_PEER_NODE.to_string()];

    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    s3_request("PUT", &format!("{}/routing-reject-put", base_url), vec![]).await;

    let key = distributed_non_owner_key("routing-reject-put");
    let put = s3_request(
        "PUT",
        &format!("{}/routing-reject-put/{}", base_url, key),
        b"hello".to_vec(),
    )
    .await;
    assert_eq!(put.status(), 403);
    let body = put.text().await.unwrap();
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("Write forwarding to primary owner failed"));
}

#[tokio::test]
async fn test_put_object_distributed_forwards_non_owner_write_to_primary_owner() {
    let pair = start_forwarding_pair().await;
    s3_request(
        "PUT",
        &format!("{}/routing-forward-put", pair.coordinator_url),
        vec![],
    )
    .await;
    s3_request(
        "PUT",
        &format!("{}/routing-forward-put", pair.owner_url),
        vec![],
    )
    .await;

    let key = distributed_non_owner_key_for(
        "routing-forward-put",
        DISTRIBUTED_LOCAL_NODE,
        std::slice::from_ref(&pair.owner_peer),
    );
    let put = s3_request(
        "PUT",
        &format!("{}/routing-forward-put/{}", pair.coordinator_url, key),
        b"forwarded-payload".to_vec(),
    )
    .await;
    assert_eq!(put.status(), 200);

    let get_from_owner = s3_request(
        "GET",
        &format!("{}/routing-forward-put/{}", pair.owner_url, key),
        vec![],
    )
    .await;
    assert_eq!(get_from_owner.status(), 200);
    assert_eq!(
        get_from_owner.bytes().await.unwrap().as_ref(),
        b"forwarded-payload"
    );
}

#[tokio::test]
async fn test_put_object_distributed_primary_write_reports_quorum_headers_when_replica_acks() {
    let pair = start_forwarding_pair().await;
    s3_request(
        "PUT",
        &format!("{}/routing-forward-put-quorum", pair.coordinator_url),
        vec![],
    )
    .await;
    s3_request(
        "PUT",
        &format!("{}/routing-forward-put-quorum", pair.owner_url),
        vec![],
    )
    .await;

    let key = distributed_local_owner_key_for(
        "routing-forward-put-quorum",
        DISTRIBUTED_LOCAL_NODE,
        std::slice::from_ref(&pair.owner_peer),
    );
    let put = s3_request(
        "PUT",
        &format!(
            "{}/routing-forward-put-quorum/{}",
            pair.coordinator_url, key
        ),
        b"quorum-payload".to_vec(),
    )
    .await;
    assert_eq!(put.status(), 200);
    assert_eq!(
        put.headers()
            .get("x-maxio-write-ack-count")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );
    assert_eq!(
        put.headers()
            .get("x-maxio-write-quorum-size")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );
    assert_eq!(
        put.headers()
            .get("x-maxio-write-quorum-reached")
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );
}

#[tokio::test]
async fn test_put_object_distributed_primary_write_reports_degraded_quorum_when_replica_unreachable()
 {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = DISTRIBUTED_LOCAL_NODE.to_string();
    config.cluster_peers = vec![DISTRIBUTED_PEER_NODE.to_string()];

    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    s3_request(
        "PUT",
        &format!("{}/routing-replica-unreachable", base_url),
        vec![],
    )
    .await;

    let key = distributed_local_owner_key("routing-replica-unreachable");
    let put = s3_request(
        "PUT",
        &format!("{}/routing-replica-unreachable/{}", base_url, key),
        b"quorum-degraded".to_vec(),
    )
    .await;
    assert_eq!(put.status(), 200);
    assert_eq!(
        put.headers()
            .get("x-maxio-write-ack-count")
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
    assert_eq!(
        put.headers()
            .get("x-maxio-write-quorum-size")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );
    assert_eq!(
        put.headers()
            .get("x-maxio-write-quorum-reached")
            .and_then(|value| value.to_str().ok()),
        Some("false")
    );
}

#[tokio::test]
async fn test_put_object_distributed_non_owner_write_ignores_untrusted_forward_protocol_headers() {
    let pair = start_forwarding_pair().await;
    s3_request(
        "PUT",
        &format!("{}/routing-forward-untrusted-headers", pair.coordinator_url),
        vec![],
    )
    .await;
    s3_request(
        "PUT",
        &format!("{}/routing-forward-untrusted-headers", pair.owner_url),
        vec![],
    )
    .await;

    let key = distributed_non_owner_key_for(
        "routing-forward-untrusted-headers",
        DISTRIBUTED_LOCAL_NODE,
        std::slice::from_ref(&pair.owner_peer),
    );
    let put = s3_request_with_headers(
        "PUT",
        &format!(
            "{}/routing-forward-untrusted-headers/{}",
            pair.coordinator_url, key
        ),
        b"forwarded-untrusted".to_vec(),
        vec![
            ("x-maxio-forwarded-write-epoch", "999"),
            ("x-maxio-forwarded-write-view-id", "tampered-view"),
            ("x-maxio-forwarded-write-hop-count", "7"),
        ],
    )
    .await;
    assert_eq!(
        put.status(),
        200,
        "external untrusted forwarding headers must not block coordinator forwarding"
    );

    let get_from_owner = s3_request(
        "GET",
        &format!(
            "{}/routing-forward-untrusted-headers/{}",
            pair.owner_url, key
        ),
        vec![],
    )
    .await;
    assert_eq!(get_from_owner.status(), 200);
    assert_eq!(
        get_from_owner.bytes().await.unwrap().as_ref(),
        b"forwarded-untrusted"
    );
}

#[tokio::test]
async fn test_copy_object_distributed_forwards_non_owner_destination_write_to_primary_owner() {
    let pair = start_forwarding_pair().await;
    s3_request(
        "PUT",
        &format!("{}/routing-forward-copy", pair.coordinator_url),
        vec![],
    )
    .await;
    s3_request(
        "PUT",
        &format!("{}/routing-forward-copy", pair.owner_url),
        vec![],
    )
    .await;

    let source_key = "routing-forward-copy-src.txt";
    s3_request(
        "PUT",
        &format!("{}/routing-forward-copy/{}", pair.owner_url, source_key),
        b"copy me".to_vec(),
    )
    .await;

    let destination_key = distributed_non_owner_key_for(
        "routing-forward-copy-dst",
        DISTRIBUTED_LOCAL_NODE,
        std::slice::from_ref(&pair.owner_peer),
    );
    let copy_source = format!("/routing-forward-copy/{}", source_key);
    let copy = s3_request_with_headers(
        "PUT",
        &format!(
            "{}/routing-forward-copy/{}",
            pair.coordinator_url, destination_key
        ),
        vec![],
        vec![("x-amz-copy-source", copy_source.as_str())],
    )
    .await;
    assert_eq!(copy.status(), 200);

    let copied = s3_request(
        "GET",
        &format!(
            "{}/routing-forward-copy/{}",
            pair.owner_url, destination_key
        ),
        vec![],
    )
    .await;
    assert_eq!(copied.status(), 200);
    assert_eq!(copied.bytes().await.unwrap().as_ref(), b"copy me");
}

#[tokio::test]
async fn test_copy_object_distributed_primary_write_reports_quorum_headers_when_replica_acks() {
    let pair = start_forwarding_pair().await;
    s3_request(
        "PUT",
        &format!("{}/routing-forward-copy-quorum", pair.coordinator_url),
        vec![],
    )
    .await;
    s3_request(
        "PUT",
        &format!("{}/routing-forward-copy-quorum", pair.owner_url),
        vec![],
    )
    .await;

    let source_key = distributed_local_owner_key_for(
        "routing-forward-copy-quorum-src",
        DISTRIBUTED_LOCAL_NODE,
        std::slice::from_ref(&pair.owner_peer),
    );
    let destination_key = distributed_local_owner_key_for(
        "routing-forward-copy-quorum-dst",
        DISTRIBUTED_LOCAL_NODE,
        std::slice::from_ref(&pair.owner_peer),
    );

    let source_put = s3_request_with_headers(
        "PUT",
        &format!(
            "{}/routing-forward-copy-quorum/{}",
            pair.coordinator_url, source_key
        ),
        b"copy-quorum-payload".to_vec(),
        vec![("content-type", "text/markdown")],
    )
    .await;
    assert_eq!(source_put.status(), 200);

    let copy_source = format!("/routing-forward-copy-quorum/{source_key}");
    let copy = s3_request_with_headers(
        "PUT",
        &format!(
            "{}/routing-forward-copy-quorum/{}",
            pair.coordinator_url, destination_key
        ),
        vec![],
        vec![("x-amz-copy-source", copy_source.as_str())],
    )
    .await;
    assert_eq!(copy.status(), 200);
    assert_eq!(
        copy.headers()
            .get("x-maxio-write-ack-count")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );
    assert_eq!(
        copy.headers()
            .get("x-maxio-write-quorum-size")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );
    assert_eq!(
        copy.headers()
            .get("x-maxio-write-quorum-reached")
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );

    let copied = s3_request(
        "GET",
        &format!(
            "{}/routing-forward-copy-quorum/{}",
            pair.owner_url, destination_key
        ),
        vec![],
    )
    .await;
    assert_eq!(copied.status(), 200);
    assert_eq!(
        copied.bytes().await.unwrap().as_ref(),
        b"copy-quorum-payload"
    );

    let copied_head = s3_request(
        "HEAD",
        &format!(
            "{}/routing-forward-copy-quorum/{}",
            pair.owner_url, destination_key
        ),
        vec![],
    )
    .await;
    assert_eq!(copied_head.status(), 200);
    assert_eq!(
        copied_head
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/markdown")
    );
}

#[tokio::test]
async fn test_copy_object_distributed_primary_write_reports_degraded_quorum_when_replica_unreachable()
 {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = DISTRIBUTED_LOCAL_NODE.to_string();
    config.cluster_peers = vec![DISTRIBUTED_PEER_NODE.to_string()];

    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    s3_request(
        "PUT",
        &format!("{}/routing-replica-unreachable-copy", base_url),
        vec![],
    )
    .await;

    let source_key = distributed_local_owner_key("routing-replica-unreachable-copy-src");
    let destination_key = distributed_local_owner_key("routing-replica-unreachable-copy-dst");
    let source_put = s3_request(
        "PUT",
        &format!(
            "{}/routing-replica-unreachable-copy/{}",
            base_url, source_key
        ),
        b"copy-unreachable-source".to_vec(),
    )
    .await;
    assert_eq!(source_put.status(), 200);

    let copy_source = format!("/routing-replica-unreachable-copy/{source_key}");
    let copy = s3_request_with_headers(
        "PUT",
        &format!(
            "{}/routing-replica-unreachable-copy/{}",
            base_url, destination_key
        ),
        vec![],
        vec![("x-amz-copy-source", copy_source.as_str())],
    )
    .await;
    assert_eq!(copy.status(), 200);
    assert_eq!(
        copy.headers()
            .get("x-maxio-write-ack-count")
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
    assert_eq!(
        copy.headers()
            .get("x-maxio-write-quorum-size")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );
    assert_eq!(
        copy.headers()
            .get("x-maxio-write-quorum-reached")
            .and_then(|value| value.to_str().ok()),
        Some("false")
    );
}

#[tokio::test]
async fn test_delete_object_distributed_forwards_non_owner_write_to_primary_owner() {
    let pair = start_forwarding_pair().await;

    s3_request(
        "PUT",
        &format!("{}/routing-forward-delete", pair.coordinator_url),
        vec![],
    )
    .await;
    s3_request(
        "PUT",
        &format!("{}/routing-forward-delete", pair.owner_url),
        vec![],
    )
    .await;

    let key = distributed_non_owner_key_for(
        "routing-forward-delete",
        DISTRIBUTED_LOCAL_NODE,
        std::slice::from_ref(&pair.owner_peer),
    );
    s3_request(
        "PUT",
        &format!("{}/routing-forward-delete/{}", pair.owner_url, key),
        b"delete-me".to_vec(),
    )
    .await;

    let delete = s3_request(
        "DELETE",
        &format!("{}/routing-forward-delete/{}", pair.coordinator_url, key),
        vec![],
    )
    .await;
    assert_eq!(delete.status(), 204);

    let missing = s3_request(
        "GET",
        &format!("{}/routing-forward-delete/{}", pair.owner_url, key),
        vec![],
    )
    .await;
    assert_eq!(missing.status(), 404);
}

#[tokio::test]
async fn test_delete_object_distributed_primary_write_reports_quorum_headers_when_replica_acks() {
    let pair = start_forwarding_pair().await;

    s3_request(
        "PUT",
        &format!("{}/routing-forward-delete-quorum", pair.coordinator_url),
        vec![],
    )
    .await;
    s3_request(
        "PUT",
        &format!("{}/routing-forward-delete-quorum", pair.owner_url),
        vec![],
    )
    .await;

    let key = distributed_local_owner_key_for(
        "routing-forward-delete-quorum",
        DISTRIBUTED_LOCAL_NODE,
        std::slice::from_ref(&pair.owner_peer),
    );
    let put = s3_request(
        "PUT",
        &format!(
            "{}/routing-forward-delete-quorum/{}",
            pair.coordinator_url, key
        ),
        b"delete-quorum".to_vec(),
    )
    .await;
    assert_eq!(put.status(), 200);

    let delete = s3_request(
        "DELETE",
        &format!(
            "{}/routing-forward-delete-quorum/{}",
            pair.coordinator_url, key
        ),
        vec![],
    )
    .await;
    assert_eq!(delete.status(), 204);
    assert_eq!(
        delete
            .headers()
            .get("x-maxio-write-ack-count")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );
    assert_eq!(
        delete
            .headers()
            .get("x-maxio-write-quorum-size")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );
    assert_eq!(
        delete
            .headers()
            .get("x-maxio-write-quorum-reached")
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );
}

#[tokio::test]
async fn test_delete_object_distributed_primary_write_reports_degraded_quorum_when_replica_unreachable()
 {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = DISTRIBUTED_LOCAL_NODE.to_string();
    config.cluster_peers = vec![DISTRIBUTED_PEER_NODE.to_string()];

    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    s3_request(
        "PUT",
        &format!("{}/routing-replica-unreachable-delete", base_url),
        vec![],
    )
    .await;

    let key = distributed_local_owner_key("routing-replica-unreachable-delete");
    let put = s3_request(
        "PUT",
        &format!("{}/routing-replica-unreachable-delete/{}", base_url, key),
        b"delete-unreachable".to_vec(),
    )
    .await;
    assert_eq!(put.status(), 200);

    let delete = s3_request(
        "DELETE",
        &format!("{}/routing-replica-unreachable-delete/{}", base_url, key),
        vec![],
    )
    .await;
    assert_eq!(delete.status(), 204);
    assert_eq!(
        delete
            .headers()
            .get("x-maxio-write-ack-count")
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
    assert_eq!(
        delete
            .headers()
            .get("x-maxio-write-quorum-size")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );
    assert_eq!(
        delete
            .headers()
            .get("x-maxio-write-quorum-reached")
            .and_then(|value| value.to_str().ok()),
        Some("false")
    );
}

#[tokio::test]
async fn test_get_object_distributed_forwards_non_owner_read_to_primary_owner() {
    let pair = start_forwarding_pair().await;
    s3_request(
        "PUT",
        &format!("{}/routing-forward-get", pair.coordinator_url),
        vec![],
    )
    .await;
    s3_request(
        "PUT",
        &format!("{}/routing-forward-get", pair.owner_url),
        vec![],
    )
    .await;

    let key = distributed_non_owner_key_for(
        "routing-forward-get",
        DISTRIBUTED_LOCAL_NODE,
        std::slice::from_ref(&pair.owner_peer),
    );
    s3_request(
        "PUT",
        &format!("{}/routing-forward-get/{}", pair.owner_url, key),
        b"forwarded-read-payload".to_vec(),
    )
    .await;

    let get = s3_request(
        "GET",
        &format!("{}/routing-forward-get/{}", pair.coordinator_url, key),
        vec![],
    )
    .await;
    assert_eq!(get.status(), 200);
    assert_eq!(
        get.bytes().await.unwrap().as_ref(),
        b"forwarded-read-payload"
    );
}

#[tokio::test]
async fn test_head_object_distributed_forwards_non_owner_read_to_primary_owner() {
    let pair = start_forwarding_pair().await;
    s3_request(
        "PUT",
        &format!("{}/routing-forward-head", pair.coordinator_url),
        vec![],
    )
    .await;
    s3_request(
        "PUT",
        &format!("{}/routing-forward-head", pair.owner_url),
        vec![],
    )
    .await;

    let key = distributed_non_owner_key_for(
        "routing-forward-head",
        DISTRIBUTED_LOCAL_NODE,
        std::slice::from_ref(&pair.owner_peer),
    );
    s3_request(
        "PUT",
        &format!("{}/routing-forward-head/{}", pair.owner_url, key),
        b"head-forwarded".to_vec(),
    )
    .await;

    let head = s3_request(
        "HEAD",
        &format!("{}/routing-forward-head/{}", pair.coordinator_url, key),
        vec![],
    )
    .await;
    assert_eq!(head.status(), 200);
    assert_eq!(
        head.headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok()),
        Some("14")
    );
    assert!(
        head.headers().get("etag").is_some(),
        "forwarded HEAD response should preserve object headers"
    );
}

#[tokio::test]
async fn test_get_object_distributed_primary_read_repairs_missing_replica() {
    let pair = start_forwarding_pair().await;
    s3_request(
        "PUT",
        &format!("{}/routing-read-repair-get", pair.coordinator_url),
        vec![],
    )
    .await;
    s3_request(
        "PUT",
        &format!("{}/routing-read-repair-get", pair.owner_url),
        vec![],
    )
    .await;

    let versioning_xml =
        br#"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"#.to_vec();
    let versioning = s3_request(
        "PUT",
        &format!(
            "{}/routing-read-repair-get?versioning",
            pair.coordinator_url
        ),
        versioning_xml,
    )
    .await;
    assert_eq!(versioning.status(), 200);
    let key = distributed_local_owner_key_for(
        "routing-read-repair-get",
        DISTRIBUTED_LOCAL_NODE,
        std::slice::from_ref(&pair.owner_peer),
    );
    let put = s3_request(
        "PUT",
        &format!("{}/routing-read-repair-get/{}", pair.coordinator_url, key),
        b"repair-on-read-get".to_vec(),
    )
    .await;
    assert_eq!(put.status(), 200);
    assert!(
        put.headers()
            .get("x-amz-version-id")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| !value.is_empty())
    );

    let owner_delete = s3_request(
        "DELETE",
        &format!("{}/routing-read-repair-get/{}", pair.owner_url, key),
        vec![],
    )
    .await;
    assert_eq!(owner_delete.status(), 204);

    let owner_missing_before = s3_request(
        "GET",
        &format!("{}/routing-read-repair-get/{}", pair.owner_url, key),
        vec![],
    )
    .await;
    assert_eq!(owner_missing_before.status(), 404);

    let get = s3_request(
        "GET",
        &format!("{}/routing-read-repair-get/{}", pair.coordinator_url, key),
        vec![],
    )
    .await;
    assert_eq!(get.status(), 200);
    assert_eq!(get.bytes().await.unwrap().as_ref(), b"repair-on-read-get");

    let owner_repaired = s3_request(
        "GET",
        &format!("{}/routing-read-repair-get/{}", pair.owner_url, key),
        vec![],
    )
    .await;
    assert_eq!(owner_repaired.status(), 200);
    assert_eq!(
        owner_repaired.bytes().await.unwrap().as_ref(),
        b"repair-on-read-get"
    );
}

#[tokio::test]
async fn test_head_object_distributed_primary_read_repairs_missing_replica() {
    let pair = start_forwarding_pair().await;
    s3_request(
        "PUT",
        &format!("{}/routing-read-repair-head", pair.coordinator_url),
        vec![],
    )
    .await;
    s3_request(
        "PUT",
        &format!("{}/routing-read-repair-head", pair.owner_url),
        vec![],
    )
    .await;

    let versioning_xml =
        br#"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"#.to_vec();
    let versioning = s3_request(
        "PUT",
        &format!(
            "{}/routing-read-repair-head?versioning",
            pair.coordinator_url
        ),
        versioning_xml,
    )
    .await;
    assert_eq!(versioning.status(), 200);

    let key = distributed_local_owner_key_for(
        "routing-read-repair-head",
        DISTRIBUTED_LOCAL_NODE,
        std::slice::from_ref(&pair.owner_peer),
    );
    let put = s3_request(
        "PUT",
        &format!("{}/routing-read-repair-head/{}", pair.coordinator_url, key),
        b"repair-on-read-head".to_vec(),
    )
    .await;
    assert_eq!(put.status(), 200);
    assert!(
        put.headers()
            .get("x-amz-version-id")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| !value.is_empty())
    );

    let owner_delete = s3_request(
        "DELETE",
        &format!("{}/routing-read-repair-head/{}", pair.owner_url, key),
        vec![],
    )
    .await;
    assert_eq!(owner_delete.status(), 204);

    let owner_missing_before = s3_request(
        "HEAD",
        &format!("{}/routing-read-repair-head/{}", pair.owner_url, key),
        vec![],
    )
    .await;
    assert_eq!(owner_missing_before.status(), 404);

    let head = s3_request(
        "HEAD",
        &format!("{}/routing-read-repair-head/{}", pair.coordinator_url, key),
        vec![],
    )
    .await;
    assert_eq!(head.status(), 200);

    let owner_repaired = s3_request(
        "GET",
        &format!("{}/routing-read-repair-head/{}", pair.owner_url, key),
        vec![],
    )
    .await;
    assert_eq!(owner_repaired.status(), 200);
    assert_eq!(
        owner_repaired.bytes().await.unwrap().as_ref(),
        b"repair-on-read-head"
    );
}

#[tokio::test]
async fn test_get_object_version_distributed_primary_read_repairs_missing_replica() {
    let pair = start_forwarding_pair().await;
    s3_request(
        "PUT",
        &format!("{}/routing-read-repair-version-get", pair.coordinator_url),
        vec![],
    )
    .await;
    s3_request(
        "PUT",
        &format!("{}/routing-read-repair-version-get", pair.owner_url),
        vec![],
    )
    .await;

    let versioning_xml =
        br#"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"#.to_vec();
    let versioning = s3_request(
        "PUT",
        &format!(
            "{}/routing-read-repair-version-get?versioning",
            pair.coordinator_url
        ),
        versioning_xml,
    )
    .await;
    assert_eq!(versioning.status(), 200);

    let key = distributed_local_owner_key_for(
        "routing-read-repair-version-get",
        DISTRIBUTED_LOCAL_NODE,
        std::slice::from_ref(&pair.owner_peer),
    );

    let put_v1 = s3_request(
        "PUT",
        &format!(
            "{}/routing-read-repair-version-get/{}",
            pair.coordinator_url, key
        ),
        b"repair-on-read-version-old".to_vec(),
    )
    .await;
    assert_eq!(put_v1.status(), 200);
    let version_id_v1 = put_v1
        .headers()
        .get("x-amz-version-id")
        .and_then(|value| value.to_str().ok())
        .expect("version id should be present")
        .to_string();
    let put_v2 = s3_request(
        "PUT",
        &format!(
            "{}/routing-read-repair-version-get/{}",
            pair.coordinator_url, key
        ),
        b"repair-on-read-version-new".to_vec(),
    )
    .await;
    assert_eq!(put_v2.status(), 200);

    let owner_delete = s3_request(
        "DELETE",
        &format!("{}/routing-read-repair-version-get/{}", pair.owner_url, key),
        vec![],
    )
    .await;
    assert_eq!(owner_delete.status(), 204);

    let owner_missing_before = s3_request(
        "GET",
        &format!("{}/routing-read-repair-version-get/{}", pair.owner_url, key),
        vec![],
    )
    .await;
    assert_eq!(owner_missing_before.status(), 404);

    let get = s3_request(
        "GET",
        &format!(
            "{}/routing-read-repair-version-get/{}?versionId={}",
            pair.coordinator_url, key, version_id_v1
        ),
        vec![],
    )
    .await;
    assert_eq!(get.status(), 200);
    assert_eq!(
        get.bytes().await.unwrap().as_ref(),
        b"repair-on-read-version-old"
    );

    let owner_repaired = s3_request(
        "GET",
        &format!("{}/routing-read-repair-version-get/{}", pair.owner_url, key),
        vec![],
    )
    .await;
    assert_eq!(owner_repaired.status(), 200);
    assert_eq!(
        owner_repaired.bytes().await.unwrap().as_ref(),
        b"repair-on-read-version-old"
    );
}

#[tokio::test]
async fn test_head_object_version_distributed_primary_read_repairs_missing_replica() {
    let pair = start_forwarding_pair().await;
    s3_request(
        "PUT",
        &format!("{}/routing-read-repair-version-head", pair.coordinator_url),
        vec![],
    )
    .await;
    s3_request(
        "PUT",
        &format!("{}/routing-read-repair-version-head", pair.owner_url),
        vec![],
    )
    .await;

    let versioning_xml =
        br#"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"#.to_vec();
    let versioning = s3_request(
        "PUT",
        &format!(
            "{}/routing-read-repair-version-head?versioning",
            pair.coordinator_url
        ),
        versioning_xml,
    )
    .await;
    assert_eq!(versioning.status(), 200);

    let key = distributed_local_owner_key_for(
        "routing-read-repair-version-head",
        DISTRIBUTED_LOCAL_NODE,
        std::slice::from_ref(&pair.owner_peer),
    );

    let put_v1 = s3_request(
        "PUT",
        &format!(
            "{}/routing-read-repair-version-head/{}",
            pair.coordinator_url, key
        ),
        b"repair-on-read-version-head-old".to_vec(),
    )
    .await;
    assert_eq!(put_v1.status(), 200);
    let version_id_v1 = put_v1
        .headers()
        .get("x-amz-version-id")
        .and_then(|value| value.to_str().ok())
        .expect("version id should be present")
        .to_string();
    let put_v2 = s3_request(
        "PUT",
        &format!(
            "{}/routing-read-repair-version-head/{}",
            pair.coordinator_url, key
        ),
        b"repair-on-read-version-head-new".to_vec(),
    )
    .await;
    assert_eq!(put_v2.status(), 200);

    let owner_delete = s3_request(
        "DELETE",
        &format!(
            "{}/routing-read-repair-version-head/{}",
            pair.owner_url, key
        ),
        vec![],
    )
    .await;
    assert_eq!(owner_delete.status(), 204);

    let owner_missing_before = s3_request(
        "HEAD",
        &format!(
            "{}/routing-read-repair-version-head/{}",
            pair.owner_url, key
        ),
        vec![],
    )
    .await;
    assert_eq!(owner_missing_before.status(), 404);

    let head = s3_request(
        "HEAD",
        &format!(
            "{}/routing-read-repair-version-head/{}?versionId={}",
            pair.coordinator_url, key, version_id_v1
        ),
        vec![],
    )
    .await;
    assert_eq!(head.status(), 200);

    let owner_repaired = s3_request(
        "GET",
        &format!(
            "{}/routing-read-repair-version-head/{}",
            pair.owner_url, key
        ),
        vec![],
    )
    .await;
    assert_eq!(owner_repaired.status(), 200);
    assert_eq!(
        owner_repaired.bytes().await.unwrap().as_ref(),
        b"repair-on-read-version-head-old"
    );
}

#[tokio::test]
async fn test_get_object_distributed_non_owner_read_returns_access_denied_when_forward_target_unreachable()
 {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = DISTRIBUTED_LOCAL_NODE.to_string();
    config.cluster_peers = vec![DISTRIBUTED_PEER_NODE.to_string()];

    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let key = distributed_non_owner_key("routing-reject-get");
    let get = s3_request(
        "GET",
        &format!("{}/routing-reject-get/{}", base_url, key),
        vec![],
    )
    .await;
    assert_eq!(get.status(), 403);
    let body = get.text().await.unwrap();
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("forwarding to primary owner failed"));
}

#[tokio::test]
async fn test_create_bucket_duplicate() {
    let (base_url, _tmp) = start_server().await;

    let resp = s3_request("PUT", &format!("{}/test-bucket", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);

    // Creating same bucket again should fail
    let resp = s3_request("PUT", &format!("{}/test-bucket", base_url), vec![]).await;
    assert_eq!(resp.status(), 409);
}

#[tokio::test]
async fn test_bucket_versioning_enable_and_suspend() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/versioning-bucket", base_url), vec![]).await;

    let enable_xml =
        br#"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"#.to_vec();
    let resp = s3_request(
        "PUT",
        &format!("{}/versioning-bucket?versioning", base_url),
        enable_xml,
    )
    .await;
    assert_eq!(resp.status(), 200);

    let resp = s3_request(
        "GET",
        &format!("{}/versioning-bucket?versioning", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("<Status>Enabled</Status>"),
        "versioning should be enabled, body: {}",
        body
    );

    let suspend_xml =
        br#"<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>"#
            .to_vec();
    let resp = s3_request(
        "PUT",
        &format!("{}/versioning-bucket?versioning", base_url),
        suspend_xml,
    )
    .await;
    assert_eq!(resp.status(), 200);

    let resp = s3_request(
        "GET",
        &format!("{}/versioning-bucket?versioning", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        !body.contains("<Status>Enabled</Status>"),
        "versioning should be suspended, body: {}",
        body
    );
}

#[tokio::test]
async fn test_bucket_versioning_invalid_status_rejected() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/versioning-bucket", base_url), vec![]).await;

    let invalid_xml =
        br#"<VersioningConfiguration><Status>Invalid</Status></VersioningConfiguration>"#.to_vec();
    let resp = s3_request(
        "PUT",
        &format!("{}/versioning-bucket?versioning", base_url),
        invalid_xml,
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert_eq!(
        extract_xml_tag(&body, "Code").as_deref(),
        Some("InvalidArgument")
    );
}

#[tokio::test]
async fn test_bucket_versioning_suspend_preserves_existing_versions() {
    let (base_url, _tmp) = start_server().await;
    let bucket = "versioning-suspend-preserve";
    let key = "file.txt";
    s3_request("PUT", &format!("{}/{}", base_url, bucket), vec![]).await;

    let enable_xml =
        br#"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"#.to_vec();
    let resp = s3_request(
        "PUT",
        &format!("{}/{}?versioning", base_url, bucket),
        enable_xml,
    )
    .await;
    assert_eq!(resp.status(), 200);

    let put_v1 = s3_request(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, key),
        b"version-one".to_vec(),
    )
    .await;
    assert_eq!(put_v1.status(), 200);
    let version_1 = put_v1
        .headers()
        .get("x-amz-version-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing version id for v1")
        .to_string();

    let put_v2 = s3_request(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, key),
        b"version-two".to_vec(),
    )
    .await;
    assert_eq!(put_v2.status(), 200);
    let version_2 = put_v2
        .headers()
        .get("x-amz-version-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing version id for v2")
        .to_string();

    let suspend_xml =
        br#"<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>"#
            .to_vec();
    let resp = s3_request(
        "PUT",
        &format!("{}/{}?versioning", base_url, bucket),
        suspend_xml,
    )
    .await;
    assert_eq!(resp.status(), 200);

    let list_versions = s3_request(
        "GET",
        &format!("{}/{}?versions=&prefix={}", base_url, bucket, key),
        vec![],
    )
    .await;
    assert_eq!(list_versions.status(), 200);
    let body = list_versions.text().await.unwrap();
    assert!(body.contains(&format!("<VersionId>{}</VersionId>", version_1)));
    assert!(body.contains(&format!("<VersionId>{}</VersionId>", version_2)));

    let get_v1 = s3_request(
        "GET",
        &format!("{}/{}/{}?versionId={}", base_url, bucket, key, version_1),
        vec![],
    )
    .await;
    assert_eq!(get_v1.status(), 200);
    assert_eq!(get_v1.bytes().await.unwrap().as_ref(), b"version-one");
}

#[tokio::test]
async fn test_object_version_roundtrip_and_specific_version_delete() {
    let (base_url, _tmp) = start_server().await;
    let bucket = "versioned-objects";
    let key = "docs/file.txt";
    s3_request("PUT", &format!("{}/{}", base_url, bucket), vec![]).await;

    let enable_xml =
        br#"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"#.to_vec();
    let enable = s3_request(
        "PUT",
        &format!("{}/{}?versioning", base_url, bucket),
        enable_xml,
    )
    .await;
    assert_eq!(enable.status(), 200);

    let put_v1 = s3_request(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, key),
        b"version-one".to_vec(),
    )
    .await;
    assert_eq!(put_v1.status(), 200);
    let version_1 = put_v1
        .headers()
        .get("x-amz-version-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing version id for v1")
        .to_string();

    let put_v2 = s3_request(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, key),
        b"version-two".to_vec(),
    )
    .await;
    assert_eq!(put_v2.status(), 200);
    let version_2 = put_v2
        .headers()
        .get("x-amz-version-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing version id for v2")
        .to_string();

    let current = s3_request("GET", &format!("{}/{}/{}", base_url, bucket, key), vec![]).await;
    assert_eq!(current.status(), 200);
    assert_eq!(current.bytes().await.unwrap().as_ref(), b"version-two");

    let list_versions = s3_request(
        "GET",
        &format!(
            "{}/{}?versions=&prefix={}",
            base_url,
            bucket,
            key.replace('/', "%2F")
        ),
        vec![],
    )
    .await;
    assert_eq!(list_versions.status(), 200);
    let versions_body = list_versions.text().await.unwrap();
    assert!(versions_body.contains(&format!("<VersionId>{}</VersionId>", version_1)));
    assert!(versions_body.contains(&format!("<VersionId>{}</VersionId>", version_2)));

    let get_v1 = s3_request(
        "GET",
        &format!("{}/{}/{}?versionId={}", base_url, bucket, key, version_1),
        vec![],
    )
    .await;
    assert_eq!(get_v1.status(), 200);
    assert_eq!(get_v1.bytes().await.unwrap().as_ref(), b"version-one");

    let delete_v2 = s3_request(
        "DELETE",
        &format!("{}/{}/{}?versionId={}", base_url, bucket, key, version_2),
        vec![],
    )
    .await;
    assert_eq!(delete_v2.status(), 204);
    assert_eq!(
        delete_v2
            .headers()
            .get("x-amz-version-id")
            .and_then(|v| v.to_str().ok()),
        Some(version_2.as_str())
    );

    let after_delete = s3_request("GET", &format!("{}/{}/{}", base_url, bucket, key), vec![]).await;
    assert_eq!(after_delete.status(), 200);
    assert_eq!(after_delete.bytes().await.unwrap().as_ref(), b"version-one");

    let missing_version = s3_request(
        "GET",
        &format!("{}/{}/{}?versionId=does-not-exist", base_url, bucket, key),
        vec![],
    )
    .await;
    assert_eq!(missing_version.status(), 404);
    let body = missing_version.text().await.unwrap();
    assert!(body.contains("<Code>NoSuchVersion</Code>"));
}

#[tokio::test]
async fn test_get_object_range_with_version_id_reads_specific_version() {
    let (base_url, _tmp) = start_server().await;
    let bucket = "versioned-range";
    let key = "docs/range.txt";
    s3_request("PUT", &format!("{}/{}", base_url, bucket), vec![]).await;

    let enable_xml =
        br#"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"#.to_vec();
    let enable = s3_request(
        "PUT",
        &format!("{}/{}?versioning", base_url, bucket),
        enable_xml,
    )
    .await;
    assert_eq!(enable.status(), 200);

    let put_v1 = s3_request(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, key),
        b"abcdefghij".to_vec(),
    )
    .await;
    assert_eq!(put_v1.status(), 200);
    let version_1 = put_v1
        .headers()
        .get("x-amz-version-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing version id for v1")
        .to_string();

    let put_v2 = s3_request(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, key),
        b"0123456789".to_vec(),
    )
    .await;
    assert_eq!(put_v2.status(), 200);

    let ranged = s3_request_with_headers(
        "GET",
        &format!("{}/{}/{}?versionId={}", base_url, bucket, key, version_1),
        vec![],
        vec![("range", "bytes=2-5")],
    )
    .await;
    assert_eq!(ranged.status(), 206);
    assert_eq!(ranged.headers()["content-length"], "4");
    assert_eq!(ranged.headers()["content-range"], "bytes 2-5/10");
    assert_eq!(
        ranged
            .headers()
            .get("x-amz-version-id")
            .and_then(|v| v.to_str().ok()),
        Some(version_1.as_str())
    );
    assert_eq!(ranged.bytes().await.unwrap().as_ref(), b"cdef");
}

#[tokio::test]
async fn test_get_object_range_without_version_id_returns_current_version_header() {
    let (base_url, _tmp) = start_server().await;
    let bucket = "versioned-range-current";
    let key = "docs/current.txt";
    s3_request("PUT", &format!("{}/{}", base_url, bucket), vec![]).await;

    let enable_xml =
        br#"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"#.to_vec();
    let enable = s3_request(
        "PUT",
        &format!("{}/{}?versioning", base_url, bucket),
        enable_xml,
    )
    .await;
    assert_eq!(enable.status(), 200);

    let put_v1 = s3_request(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, key),
        b"version-one".to_vec(),
    )
    .await;
    assert_eq!(put_v1.status(), 200);

    let put_v2 = s3_request(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, key),
        b"version-two".to_vec(),
    )
    .await;
    assert_eq!(put_v2.status(), 200);
    let version_2 = put_v2
        .headers()
        .get("x-amz-version-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing version id for v2")
        .to_string();

    let ranged = s3_request_with_headers(
        "GET",
        &format!("{}/{}/{}", base_url, bucket, key),
        vec![],
        vec![("range", "bytes=0-6")],
    )
    .await;
    assert_eq!(ranged.status(), 206);
    assert_eq!(
        ranged
            .headers()
            .get("x-amz-version-id")
            .and_then(|v| v.to_str().ok()),
        Some(version_2.as_str())
    );
    assert_eq!(ranged.bytes().await.unwrap().as_ref(), b"version");
}

fn extract_xml_tag_value(body: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&close)? + start;
    Some(body[start..end].to_string())
}

#[tokio::test]
async fn test_list_object_versions_supports_max_keys_and_markers() {
    use std::time::Duration;

    let (base_url, _tmp) = start_server().await;
    let bucket = "version-paging";
    s3_request("PUT", &format!("{}/{}", base_url, bucket), vec![]).await;

    let enable_xml =
        br#"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"#.to_vec();
    let enable = s3_request(
        "PUT",
        &format!("{}/{}?versioning", base_url, bucket),
        enable_xml,
    )
    .await;
    assert_eq!(enable.status(), 200);

    let put_a_v1 = s3_request(
        "PUT",
        &format!("{}/{}/a.txt", base_url, bucket),
        b"a-v1".to_vec(),
    )
    .await;
    assert_eq!(put_a_v1.status(), 200);
    let a_v1 = put_a_v1
        .headers()
        .get("x-amz-version-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing version id for a-v1")
        .to_string();

    tokio::time::sleep(Duration::from_millis(2)).await;

    let put_a_v2 = s3_request(
        "PUT",
        &format!("{}/{}/a.txt", base_url, bucket),
        b"a-v2".to_vec(),
    )
    .await;
    assert_eq!(put_a_v2.status(), 200);
    let a_v2 = put_a_v2
        .headers()
        .get("x-amz-version-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing version id for a-v2")
        .to_string();

    tokio::time::sleep(Duration::from_millis(2)).await;

    let put_b_v1 = s3_request(
        "PUT",
        &format!("{}/{}/b.txt", base_url, bucket),
        b"b-v1".to_vec(),
    )
    .await;
    assert_eq!(put_b_v1.status(), 200);
    let b_v1 = put_b_v1
        .headers()
        .get("x-amz-version-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing version id for b-v1")
        .to_string();

    let first_page = s3_request(
        "GET",
        &format!("{}/{}?versions=&max-keys=2", base_url, bucket),
        vec![],
    )
    .await;
    assert_eq!(first_page.status(), 200);
    let first_body = first_page.text().await.unwrap();
    assert!(first_body.contains("<IsTruncated>true</IsTruncated>"));
    assert!(first_body.contains(&format!("<VersionId>{}</VersionId>", a_v2)));
    assert!(first_body.contains(&format!("<VersionId>{}</VersionId>", a_v1)));
    assert!(!first_body.contains(&format!("<VersionId>{}</VersionId>", b_v1)));

    let next_key_marker =
        extract_xml_tag_value(&first_body, "NextKeyMarker").expect("missing NextKeyMarker");
    let next_version_marker = extract_xml_tag_value(&first_body, "NextVersionIdMarker")
        .expect("missing NextVersionIdMarker");
    assert_eq!(next_key_marker, "a.txt");
    assert_eq!(next_version_marker, a_v1);

    let second_page = s3_request(
        "GET",
        &format!(
            "{}/{}?versions=&max-keys=2&key-marker={}&version-id-marker={}",
            base_url, bucket, next_key_marker, next_version_marker
        ),
        vec![],
    )
    .await;
    assert_eq!(second_page.status(), 200);
    let second_body = second_page.text().await.unwrap();
    assert!(second_body.contains("<IsTruncated>false</IsTruncated>"));
    assert!(second_body.contains(&format!("<VersionId>{}</VersionId>", b_v1)));
    assert!(!second_body.contains("<NextKeyMarker>"));
    assert!(!second_body.contains("<NextVersionIdMarker>"));
}

#[tokio::test]
async fn test_delete_marker_stays_current_after_deleting_older_version() {
    let (base_url, _tmp) = start_server().await;
    let bucket = "versioned-delete-marker";
    let key = "docs/tombstone.txt";
    s3_request("PUT", &format!("{}/{}", base_url, bucket), vec![]).await;

    let enable_xml =
        br#"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"#.to_vec();
    let enable = s3_request(
        "PUT",
        &format!("{}/{}?versioning", base_url, bucket),
        enable_xml,
    )
    .await;
    assert_eq!(enable.status(), 200);

    let put_v1 = s3_request(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, key),
        b"version-one".to_vec(),
    )
    .await;
    assert_eq!(put_v1.status(), 200);
    let version_1 = put_v1
        .headers()
        .get("x-amz-version-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing version id for v1")
        .to_string();

    let put_v2 = s3_request(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, key),
        b"version-two".to_vec(),
    )
    .await;
    assert_eq!(put_v2.status(), 200);
    let version_2 = put_v2
        .headers()
        .get("x-amz-version-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing version id for v2")
        .to_string();

    // Without versionId this should create a delete marker.
    let delete_current = s3_request(
        "DELETE",
        &format!("{}/{}/{}", base_url, bucket, key),
        vec![],
    )
    .await;
    assert_eq!(delete_current.status(), 204);
    assert_eq!(
        delete_current
            .headers()
            .get("x-amz-delete-marker")
            .and_then(|v| v.to_str().ok()),
        Some("true")
    );

    // Current object is deleted because latest version is delete marker.
    let get_after_marker =
        s3_request("GET", &format!("{}/{}/{}", base_url, bucket, key), vec![]).await;
    assert_eq!(get_after_marker.status(), 404);

    // Deleting an older concrete version must not resurrect current object.
    let delete_v2 = s3_request(
        "DELETE",
        &format!("{}/{}/{}?versionId={}", base_url, bucket, key, version_2),
        vec![],
    )
    .await;
    assert_eq!(delete_v2.status(), 204);

    let get_after_old_delete =
        s3_request("GET", &format!("{}/{}/{}", base_url, bucket, key), vec![]).await;
    assert_eq!(get_after_old_delete.status(), 404);
    let body = get_after_old_delete.text().await.unwrap();
    assert_eq!(extract_xml_tag(&body, "Code").as_deref(), Some("NoSuchKey"));

    // Older retained versions should still be retrievable by explicit versionId.
    let get_v1 = s3_request(
        "GET",
        &format!("{}/{}/{}?versionId={}", base_url, bucket, key, version_1),
        vec![],
    )
    .await;
    assert_eq!(get_v1.status(), 200);
    assert_eq!(get_v1.bytes().await.unwrap().as_ref(), b"version-one");
}

#[tokio::test]
async fn test_bucket_lifecycle_put_and_get() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/lifecycle-s3-bucket", base_url), vec![]).await;

    let lifecycle_xml = br#"
      <LifecycleConfiguration>
        <Rule>
          <ID>expire-logs</ID>
          <Status>Enabled</Status>
          <Filter><Prefix>logs/</Prefix></Filter>
          <Expiration><Days>7</Days></Expiration>
        </Rule>
      </LifecycleConfiguration>
    "#
    .to_vec();

    let resp = s3_request(
        "PUT",
        &format!("{}/lifecycle-s3-bucket?lifecycle", base_url),
        lifecycle_xml,
    )
    .await;
    assert_eq!(resp.status(), 200);

    let resp = s3_request(
        "GET",
        &format!("{}/lifecycle-s3-bucket?lifecycle", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<LifecycleConfiguration>"));
    assert!(body.contains("<ID>expire-logs</ID>"));
    assert!(body.contains("<Status>Enabled</Status>"));
    assert!(body.contains("<Prefix>logs/</Prefix>"));
    assert!(body.contains("<Days>7</Days>"));
}

#[tokio::test]
async fn test_bucket_lifecycle_get_missing_returns_not_found_code() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/lifecycle-empty", base_url), vec![]).await;

    let resp = s3_request(
        "GET",
        &format!("{}/lifecycle-empty?lifecycle", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 404);
    let body = resp.text().await.unwrap();
    assert_eq!(
        extract_xml_tag(&body, "Code").as_deref(),
        Some("NoSuchLifecycleConfiguration")
    );
}

#[tokio::test]
async fn test_bucket_lifecycle_invalid_status_rejected() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/lifecycle-invalid", base_url), vec![]).await;

    let lifecycle_xml = br#"
      <LifecycleConfiguration>
        <Rule>
          <ID>bad-status</ID>
          <Status>Suspended</Status>
          <Expiration><Days>7</Days></Expiration>
        </Rule>
      </LifecycleConfiguration>
    "#
    .to_vec();

    let resp = s3_request(
        "PUT",
        &format!("{}/lifecycle-invalid?lifecycle", base_url),
        lifecycle_xml,
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert_eq!(
        extract_xml_tag(&body, "Code").as_deref(),
        Some("InvalidArgument")
    );
}

#[tokio::test]
async fn test_bucket_lifecycle_delete_configuration() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/lifecycle-delete", base_url), vec![]).await;

    let lifecycle_xml = br#"
      <LifecycleConfiguration>
        <Rule>
          <ID>expire-logs</ID>
          <Status>Enabled</Status>
          <Filter><Prefix>logs/</Prefix></Filter>
          <Expiration><Days>7</Days></Expiration>
        </Rule>
      </LifecycleConfiguration>
    "#
    .to_vec();
    let resp = s3_request(
        "PUT",
        &format!("{}/lifecycle-delete?lifecycle", base_url),
        lifecycle_xml,
    )
    .await;
    assert_eq!(resp.status(), 200);

    let resp = s3_request(
        "DELETE",
        &format!("{}/lifecycle-delete?lifecycle", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 204);

    let resp = s3_request(
        "GET",
        &format!("{}/lifecycle-delete?lifecycle", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 404);
    let body = resp.text().await.unwrap();
    assert_eq!(
        extract_xml_tag(&body, "Code").as_deref(),
        Some("NoSuchLifecycleConfiguration")
    );
}

#[tokio::test]
async fn test_head_bucket_not_found() {
    let (base_url, _tmp) = start_server().await;

    let resp = s3_request("HEAD", &format!("{}/nonexistent", base_url), vec![]).await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_list_buckets() {
    let (base_url, _tmp) = start_server().await;

    // Create two buckets
    s3_request("PUT", &format!("{}/alpha", base_url), vec![]).await;
    s3_request("PUT", &format!("{}/beta", base_url), vec![]).await;

    // List
    let resp = s3_request("GET", &format!("{}/", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Name>alpha</Name>"));
    assert!(body.contains("<Name>beta</Name>"));
}

#[tokio::test]
async fn test_delete_bucket() {
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/to-delete", base_url), vec![]).await;

    let resp = s3_request("DELETE", &format!("{}/to-delete", base_url), vec![]).await;
    assert_eq!(resp.status(), 204);

    // Should be gone
    let resp = s3_request("HEAD", &format!("{}/to-delete", base_url), vec![]).await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_put_and_get_object() {
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let data = b"hello maxio".to_vec();
    let resp = s3_request(
        "PUT",
        &format!("{}/mybucket/test.txt", base_url),
        data.clone(),
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().contains_key("etag"));

    // Get it back
    let resp = s3_request("GET", &format!("{}/mybucket/test.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), b"hello maxio");
}

#[tokio::test]
async fn test_head_object() {
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/mybucket/file.txt", base_url),
        b"data".to_vec(),
    )
    .await;

    let resp = s3_request("HEAD", &format!("{}/mybucket/file.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("content-length").unwrap(), "4");
}

#[tokio::test]
async fn test_get_object_missing_bucket_returns_no_such_bucket() {
    let (base_url, _tmp) = start_server().await;

    let resp = s3_request(
        "GET",
        &format!("{}/missing-bucket/file.txt", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 404);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>NoSuchBucket</Code>"));
}

#[tokio::test]
async fn test_head_object_missing_bucket_returns_no_such_bucket() {
    let (base_url, _tmp) = start_server().await;

    let resp = s3_request(
        "HEAD",
        &format!("{}/missing-bucket/file.txt", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_delete_object() {
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/mybucket/file.txt", base_url),
        b"data".to_vec(),
    )
    .await;

    let resp = s3_request("DELETE", &format!("{}/mybucket/file.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 204);

    // Should be gone
    let resp = s3_request("GET", &format!("{}/mybucket/file.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_delete_object_missing_bucket_returns_no_such_bucket() {
    let (base_url, _tmp) = start_server().await;

    let resp = s3_request(
        "DELETE",
        &format!("{}/missing-bucket/file.txt", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 404);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>NoSuchBucket</Code>"));
}

#[tokio::test]
async fn test_delete_object_version_missing_bucket_returns_no_such_bucket() {
    let (base_url, _tmp) = start_server().await;

    let resp = s3_request(
        "DELETE",
        &format!(
            "{}/missing-bucket/file.txt?versionId=does-not-exist",
            base_url
        ),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 404);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>NoSuchBucket</Code>"));
}

#[tokio::test]
async fn test_delete_object_version_distributed_sets_routing_headers() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = DISTRIBUTED_LOCAL_NODE.to_string();
    config.cluster_peers = vec![DISTRIBUTED_PEER_NODE.to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let bucket = "routing-delete-version";
    let key = distributed_local_owner_key("routing-delete-version");
    s3_request("PUT", &format!("{}/{}", base_url, bucket), vec![]).await;

    let enable_xml =
        br#"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"#.to_vec();
    let enable = s3_request(
        "PUT",
        &format!("{}/{}?versioning", base_url, bucket),
        enable_xml,
    )
    .await;
    assert_eq!(enable.status(), 200);

    let put = s3_request(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, key),
        b"delete me".to_vec(),
    )
    .await;
    assert_eq!(put.status(), 200);
    let version_id = put
        .headers()
        .get("x-amz-version-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-amz-version-id on versioned put")
        .to_string();

    let delete = s3_request(
        "DELETE",
        &format!("{}/{}/{}?versionId={}", base_url, bucket, key, version_id),
        vec![],
    )
    .await;
    assert_eq!(delete.status(), 204);
    assert_eq!(
        delete
            .headers()
            .get("x-amz-version-id")
            .and_then(|v| v.to_str().ok()),
        Some(version_id.as_str())
    );

    let primary_owner = delete
        .headers()
        .get("x-maxio-primary-owner")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-maxio-primary-owner")
        .to_string();
    let local_primary = delete
        .headers()
        .get("x-maxio-routing-local-primary-owner")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-maxio-routing-local-primary-owner");

    assert!(local_primary == "true" || local_primary == "false");
    if local_primary == "false" {
        assert_eq!(
            delete
                .headers()
                .get("x-maxio-forward-target")
                .and_then(|v| v.to_str().ok()),
            Some(primary_owner.as_str())
        );
    } else {
        assert!(delete.headers().get("x-maxio-forward-target").is_none());
    }
}

#[tokio::test]
async fn test_delete_object_version_distributed_primary_write_reports_quorum_headers_when_replica_acks()
 {
    let pair = start_forwarding_pair().await;
    let bucket = "routing-delete-version-quorum";
    let key = distributed_local_owner_key_for(
        "routing-delete-version-quorum",
        DISTRIBUTED_LOCAL_NODE,
        std::slice::from_ref(&pair.owner_peer),
    );

    s3_request(
        "PUT",
        &format!("{}/{}", pair.coordinator_url, bucket),
        vec![],
    )
    .await;
    s3_request("PUT", &format!("{}/{}", pair.owner_url, bucket), vec![]).await;

    let enable_xml =
        br#"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"#.to_vec();
    let enable_coordinator = s3_request(
        "PUT",
        &format!("{}/{}?versioning", pair.coordinator_url, bucket),
        enable_xml.clone(),
    )
    .await;
    assert_eq!(enable_coordinator.status(), 200);
    let enable_owner = s3_request(
        "PUT",
        &format!("{}/{}?versioning", pair.owner_url, bucket),
        enable_xml,
    )
    .await;
    assert_eq!(enable_owner.status(), 200);

    let put = s3_request(
        "PUT",
        &format!("{}/{}/{}", pair.coordinator_url, bucket, key),
        b"delete-version-quorum".to_vec(),
    )
    .await;
    assert_eq!(put.status(), 200);
    let version_id = put
        .headers()
        .get("x-amz-version-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-amz-version-id on versioned put")
        .to_string();

    let delete = s3_request(
        "DELETE",
        &format!(
            "{}/{}/{}?versionId={}",
            pair.coordinator_url, bucket, key, version_id
        ),
        vec![],
    )
    .await;
    assert_eq!(delete.status(), 204);
    assert_eq!(
        delete
            .headers()
            .get("x-maxio-write-ack-count")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );
    assert_eq!(
        delete
            .headers()
            .get("x-maxio-write-quorum-size")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );
    assert_eq!(
        delete
            .headers()
            .get("x-maxio-write-quorum-reached")
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );
}

#[tokio::test]
async fn test_delete_object_version_distributed_primary_write_reports_degraded_quorum_when_replica_unreachable()
 {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = DISTRIBUTED_LOCAL_NODE.to_string();
    config.cluster_peers = vec![DISTRIBUTED_PEER_NODE.to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let bucket = "routing-delete-version-replica-unreachable";
    s3_request("PUT", &format!("{}/{}", base_url, bucket), vec![]).await;

    let enable_xml =
        br#"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"#.to_vec();
    let enable = s3_request(
        "PUT",
        &format!("{}/{}?versioning", base_url, bucket),
        enable_xml,
    )
    .await;
    assert_eq!(enable.status(), 200);

    let key = distributed_local_owner_key("routing-delete-version-replica-unreachable");
    let put = s3_request(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, key),
        b"delete-version-replica-unreachable".to_vec(),
    )
    .await;
    assert_eq!(put.status(), 200);
    let version_id = put
        .headers()
        .get("x-amz-version-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-amz-version-id on versioned put")
        .to_string();

    let delete = s3_request(
        "DELETE",
        &format!("{}/{}/{}?versionId={}", base_url, bucket, key, version_id),
        vec![],
    )
    .await;
    assert_eq!(delete.status(), 204);
    assert_eq!(
        delete
            .headers()
            .get("x-maxio-write-ack-count")
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
    assert_eq!(
        delete
            .headers()
            .get("x-maxio-write-quorum-size")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );
    assert_eq!(
        delete
            .headers()
            .get("x-maxio-write-quorum-reached")
            .and_then(|value| value.to_str().ok()),
        Some("false")
    );
}

#[tokio::test]
async fn test_list_objects() {
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/mybucket/a.txt", base_url),
        b"aaa".to_vec(),
    )
    .await;
    s3_request(
        "PUT",
        &format!("{}/mybucket/b.txt", base_url),
        b"bbb".to_vec(),
    )
    .await;

    let resp = s3_request("GET", &format!("{}/mybucket?list-type=2", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Key>a.txt</Key>"));
    assert!(body.contains("<Key>b.txt</Key>"));
    assert!(body.contains("<KeyCount>2</KeyCount>"));
}

#[tokio::test]
async fn test_list_objects_invalid_prefix_returns_invalid_argument() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let invalid_prefix = "a".repeat(1025);

    let resp = s3_request(
        "GET",
        &format!(
            "{}/mybucket?list-type=2&prefix={}",
            base_url, invalid_prefix
        ),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert_eq!(
        extract_xml_tag(&body, "Code").as_deref(),
        Some("InvalidArgument")
    );
}

#[tokio::test]
async fn test_list_objects_invalid_max_keys_returns_invalid_argument() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let resp = s3_request(
        "GET",
        &format!("{}/mybucket?list-type=2&max-keys=abc", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert_eq!(
        extract_xml_tag(&body, "Code").as_deref(),
        Some("InvalidArgument")
    );
}

#[tokio::test]
async fn test_list_objects_invalid_continuation_token_returns_invalid_argument() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let resp = s3_request(
        "GET",
        &format!(
            "{}/mybucket?list-type=2&continuation-token=not-base64",
            base_url
        ),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert_eq!(
        extract_xml_tag(&body, "Code").as_deref(),
        Some("InvalidArgument")
    );
}

#[tokio::test]
async fn test_list_objects_v2_empty_delimiter_returns_invalid_argument() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let resp = s3_request(
        "GET",
        &format!("{}/mybucket?list-type=2&delimiter=", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert_eq!(
        extract_xml_tag(&body, "Code").as_deref(),
        Some("InvalidArgument")
    );
}

#[tokio::test]
async fn test_list_objects_v1_empty_delimiter_returns_invalid_argument() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let resp = s3_request("GET", &format!("{}/mybucket?delimiter=", base_url), vec![]).await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert_eq!(
        extract_xml_tag(&body, "Code").as_deref(),
        Some("InvalidArgument")
    );
}

#[tokio::test]
async fn test_list_objects_invalid_list_type_returns_invalid_argument() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let resp = s3_request("GET", &format!("{}/mybucket?list-type=1", base_url), vec![]).await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert_eq!(
        extract_xml_tag(&body, "Code").as_deref(),
        Some("InvalidArgument")
    );
}

#[tokio::test]
async fn test_list_object_versions_invalid_prefix_returns_invalid_argument() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let invalid_prefix = "a".repeat(1025);

    let resp = s3_request(
        "GET",
        &format!("{}/mybucket?versions=&prefix={}", base_url, invalid_prefix),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert_eq!(
        extract_xml_tag(&body, "Code").as_deref(),
        Some("InvalidArgument")
    );
}

#[tokio::test]
async fn test_list_object_versions_invalid_max_keys_returns_invalid_argument() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let resp = s3_request(
        "GET",
        &format!("{}/mybucket?versions=&max-keys=abc", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert_eq!(
        extract_xml_tag(&body, "Code").as_deref(),
        Some("InvalidArgument")
    );
}

#[tokio::test]
async fn test_list_object_versions_orphaned_version_id_marker_returns_invalid_argument() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let resp = s3_request(
        "GET",
        &format!("{}/mybucket?versions=&version-id-marker=v1", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert_eq!(
        extract_xml_tag(&body, "Code").as_deref(),
        Some("InvalidArgument")
    );
}

#[tokio::test]
async fn test_last_modified_http_date_format() {
    // Last-Modified header must be RFC 7231 format: "Tue, 17 Feb 2026 22:17:45 GMT"
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/mybucket/file.txt", base_url),
        b"data".to_vec(),
    )
    .await;

    // HEAD should return RFC 7231 Last-Modified
    let resp = s3_request("HEAD", &format!("{}/mybucket/file.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let last_modified = resp
        .headers()
        .get("last-modified")
        .unwrap()
        .to_str()
        .unwrap();
    // Should match pattern like "Mon, 17 Feb 2026 22:17:45 GMT"
    assert!(
        last_modified.ends_with(" GMT"),
        "Last-Modified should end with GMT: {}",
        last_modified
    );
    assert!(
        last_modified.contains(", "),
        "Last-Modified should contain comma-space: {}",
        last_modified
    );
    // Must NOT be ISO 8601 (no "T" between date and time digits)
    assert!(
        !last_modified.contains("T0"),
        "Last-Modified must not be ISO 8601: {}",
        last_modified
    );
    assert!(
        !last_modified.contains("T1"),
        "Last-Modified must not be ISO 8601: {}",
        last_modified
    );
    assert!(
        !last_modified.contains("T2"),
        "Last-Modified must not be ISO 8601: {}",
        last_modified
    );

    // GET should also return RFC 7231 Last-Modified
    let resp = s3_request("GET", &format!("{}/mybucket/file.txt", base_url), vec![]).await;
    let last_modified = resp
        .headers()
        .get("last-modified")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(last_modified.ends_with(" GMT"));
    // Verify it parses as HTTP date (day-of-week, DD Mon YYYY HH:MM:SS GMT)
    assert!(
        last_modified.len() > 25,
        "Last-Modified should be full HTTP date: {}",
        last_modified
    );
}

#[tokio::test]
async fn test_put_object_aws_chunked_encoding() {
    // mc sends uploads with x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD
    // and the body is in AWS chunked format
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let data = b"hello chunked world";
    let resp = s3_put_chunked(&format!("{}/mybucket/chunked.txt", base_url), data).await;
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().contains_key("etag"));

    // Verify the stored content is decoded (no chunk framing)
    let resp = s3_request("GET", &format!("{}/mybucket/chunked.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(
        body.as_ref(),
        data,
        "Chunked upload content should be decoded"
    );
}

#[tokio::test]
async fn test_put_object_response_headers() {
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    // PUT should return ETag
    let resp = s3_request(
        "PUT",
        &format!("{}/mybucket/file.txt", base_url),
        b"test data".to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let etag = resp.headers().get("etag").unwrap().to_str().unwrap();
    assert!(
        etag.starts_with('"') && etag.ends_with('"'),
        "ETag should be quoted: {}",
        etag
    );

    // HEAD should return Content-Type, Content-Length, ETag, Last-Modified
    let resp = s3_request("HEAD", &format!("{}/mybucket/file.txt", base_url), vec![]).await;
    assert!(resp.headers().contains_key("content-type"));
    assert!(resp.headers().contains_key("content-length"));
    assert!(resp.headers().contains_key("etag"));
    assert!(resp.headers().contains_key("last-modified"));
    assert_eq!(resp.headers().get("content-length").unwrap(), "9");

    // GET should also have these headers
    let resp = s3_request("GET", &format!("{}/mybucket/file.txt", base_url), vec![]).await;
    assert!(resp.headers().contains_key("content-type"));
    assert!(resp.headers().contains_key("content-length"));
    assert!(resp.headers().contains_key("etag"));
    assert!(resp.headers().contains_key("last-modified"));
}

#[tokio::test]
async fn test_delete_objects_batch() {
    // mc uses POST /{bucket}?delete to delete objects (DeleteObjects API)
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/mybucket/a.txt", base_url),
        b"aaa".to_vec(),
    )
    .await;
    s3_request(
        "PUT",
        &format!("{}/mybucket/b.txt", base_url),
        b"bbb".to_vec(),
    )
    .await;
    s3_request(
        "PUT",
        &format!("{}/mybucket/c.txt", base_url),
        b"ccc".to_vec(),
    )
    .await;

    // Batch delete a.txt and b.txt
    let delete_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<Delete>
  <Object><Key>a.txt</Key></Object>
  <Object><Key>b.txt</Key></Object>
</Delete>"#;

    let resp = s3_request(
        "POST",
        &format!("{}/mybucket?delete", base_url),
        delete_xml.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("<Deleted>"),
        "Response should contain Deleted elements"
    );
    assert!(body.contains("<Key>a.txt</Key>"));
    assert!(body.contains("<Key>b.txt</Key>"));

    // Verify a.txt and b.txt are gone
    let resp = s3_request("GET", &format!("{}/mybucket/a.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 404);
    let resp = s3_request("GET", &format!("{}/mybucket/b.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 404);

    // c.txt should still exist
    let resp = s3_request("GET", &format!("{}/mybucket/c.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_delete_objects_batch_quiet_mode_suppresses_deleted_entries() {
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/mybucket/a.txt", base_url),
        b"aaa".to_vec(),
    )
    .await;
    s3_request(
        "PUT",
        &format!("{}/mybucket/b.txt", base_url),
        b"bbb".to_vec(),
    )
    .await;

    let delete_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<Delete>
  <Quiet>true</Quiet>
  <Object><Key>a.txt</Key></Object>
  <Object><Key>b.txt</Key></Object>
</Delete>"#;

    let resp = s3_request(
        "POST",
        &format!("{}/mybucket?delete", base_url),
        delete_xml.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        !body.contains("<Deleted>"),
        "Quiet mode response must not include Deleted entries"
    );
    assert!(
        !body.contains("<Error>"),
        "Quiet mode response should remain empty for successful deletes"
    );

    let resp = s3_request("GET", &format!("{}/mybucket/a.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 404);
    let resp = s3_request("GET", &format!("{}/mybucket/b.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_delete_objects_batch_distributed_reports_access_denied_when_forward_target_unreachable()
 {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = DISTRIBUTED_LOCAL_NODE.to_string();
    config.cluster_peers = vec![DISTRIBUTED_PEER_NODE.to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let local_key = distributed_local_owner_key("routing-reject-delete-batch-local");
    let non_owner_key = distributed_non_owner_key("routing-reject-delete-batch-forward");

    s3_request(
        "PUT",
        &format!("{}/mybucket/{}", base_url, local_key),
        b"aaa".to_vec(),
    )
    .await;

    let delete_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Delete>
  <Object><Key>{}</Key></Object>
  <Object><Key>{}</Key></Object>
</Delete>"#,
        local_key, non_owner_key
    );

    let resp = s3_request(
        "POST",
        &format!("{}/mybucket?delete", base_url),
        delete_xml.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains(&format!("<Key>{}</Key>", local_key)));
    assert!(body.contains(&format!("<Key>{}</Key>", non_owner_key)));
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("Write forwarding to primary owner failed"));

    let local_get = s3_request(
        "GET",
        &format!("{}/mybucket/{}", base_url, local_key),
        vec![],
    )
    .await;
    assert_eq!(local_get.status(), 404);
}

#[tokio::test]
async fn test_delete_objects_batch_distributed_forwards_non_owner_batch_to_primary_owner() {
    let pair = start_forwarding_pair().await;

    s3_request(
        "PUT",
        &format!("{}/routing-forward-delete-batch", pair.coordinator_url),
        vec![],
    )
    .await;
    s3_request(
        "PUT",
        &format!("{}/routing-forward-delete-batch", pair.owner_url),
        vec![],
    )
    .await;

    let key_a = distributed_non_owner_key_for(
        "routing-forward-delete-batch-a",
        DISTRIBUTED_LOCAL_NODE,
        std::slice::from_ref(&pair.owner_peer),
    );
    let key_b = distributed_non_owner_key_for(
        "routing-forward-delete-batch-b",
        DISTRIBUTED_LOCAL_NODE,
        std::slice::from_ref(&pair.owner_peer),
    );

    s3_request(
        "PUT",
        &format!("{}/routing-forward-delete-batch/{}", pair.owner_url, key_a),
        b"delete-me-a".to_vec(),
    )
    .await;
    s3_request(
        "PUT",
        &format!("{}/routing-forward-delete-batch/{}", pair.owner_url, key_b),
        b"delete-me-b".to_vec(),
    )
    .await;

    let delete_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Delete>
  <Object><Key>{}</Key></Object>
  <Object><Key>{}</Key></Object>
</Delete>"#,
        key_a, key_b
    );

    let resp = s3_request(
        "POST",
        &format!(
            "{}/routing-forward-delete-batch?delete",
            pair.coordinator_url
        ),
        delete_xml.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains(&format!("<Key>{}</Key>", key_a)));
    assert!(body.contains(&format!("<Key>{}</Key>", key_b)));
    assert!(!body.contains("<Code>AccessDenied</Code>"));

    let missing_a = s3_request(
        "GET",
        &format!("{}/routing-forward-delete-batch/{}", pair.owner_url, key_a),
        vec![],
    )
    .await;
    assert_eq!(missing_a.status(), 404);
    let missing_b = s3_request(
        "GET",
        &format!("{}/routing-forward-delete-batch/{}", pair.owner_url, key_b),
        vec![],
    )
    .await;
    assert_eq!(missing_b.status(), 404);
}

#[tokio::test]
async fn test_delete_objects_batch_distributed_forwards_mixed_owner_entries() {
    let pair = start_forwarding_pair().await;

    s3_request(
        "PUT",
        &format!(
            "{}/routing-forward-delete-batch-mixed",
            pair.coordinator_url
        ),
        vec![],
    )
    .await;
    s3_request(
        "PUT",
        &format!("{}/routing-forward-delete-batch-mixed", pair.owner_url),
        vec![],
    )
    .await;

    let local_key = distributed_local_owner_key_for(
        "routing-forward-delete-batch-mixed-local",
        DISTRIBUTED_LOCAL_NODE,
        std::slice::from_ref(&pair.owner_peer),
    );
    let forwarded_key = distributed_non_owner_key_for(
        "routing-forward-delete-batch-mixed-forward",
        DISTRIBUTED_LOCAL_NODE,
        std::slice::from_ref(&pair.owner_peer),
    );

    s3_request(
        "PUT",
        &format!(
            "{}/routing-forward-delete-batch-mixed/{}",
            pair.coordinator_url, local_key
        ),
        b"delete-local".to_vec(),
    )
    .await;
    s3_request(
        "PUT",
        &format!(
            "{}/routing-forward-delete-batch-mixed/{}",
            pair.owner_url, forwarded_key
        ),
        b"delete-forwarded".to_vec(),
    )
    .await;

    let delete_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Delete>
  <Object><Key>{}</Key></Object>
  <Object><Key>{}</Key></Object>
</Delete>"#,
        local_key, forwarded_key
    );

    let response = s3_request(
        "POST",
        &format!(
            "{}/routing-forward-delete-batch-mixed?delete",
            pair.coordinator_url
        ),
        delete_xml.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response
            .headers()
            .get("x-maxio-write-ack-count")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );
    assert_eq!(
        response
            .headers()
            .get("x-maxio-write-quorum-size")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );
    assert_eq!(
        response
            .headers()
            .get("x-maxio-write-quorum-reached")
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );

    let body = response.text().await.unwrap();
    assert!(body.contains(&format!("<Key>{}</Key>", local_key)));
    assert!(body.contains(&format!("<Key>{}</Key>", forwarded_key)));
    assert!(!body.contains("<Code>AccessDenied</Code>"));

    let local_missing = s3_request(
        "GET",
        &format!(
            "{}/routing-forward-delete-batch-mixed/{}",
            pair.coordinator_url, local_key
        ),
        vec![],
    )
    .await;
    assert_eq!(local_missing.status(), 404);

    let forwarded_missing = s3_request(
        "GET",
        &format!(
            "{}/routing-forward-delete-batch-mixed/{}",
            pair.owner_url, forwarded_key
        ),
        vec![],
    )
    .await;
    assert_eq!(forwarded_missing.status(), 404);
}

#[tokio::test]
async fn test_delete_objects_batch_missing_bucket_returns_no_such_bucket() {
    let (base_url, _tmp) = start_server().await;

    let delete_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<Delete>
  <Object><Key>a.txt</Key></Object>
</Delete>"#;

    let resp = s3_request(
        "POST",
        &format!("{}/missing-bucket?delete", base_url),
        delete_xml.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 404);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>NoSuchBucket</Code>"));
}

#[tokio::test]
async fn test_delete_object_invalid_key_returns_invalid_argument() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let invalid_key = "a".repeat(1025);

    let resp = s3_request(
        "DELETE",
        &format!("{}/mybucket/{}", base_url, invalid_key),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert_eq!(
        extract_xml_tag(&body, "Code").as_deref(),
        Some("InvalidArgument")
    );
}

#[tokio::test]
async fn test_delete_objects_batch_invalid_key_returns_invalid_argument_entry() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/mybucket/a.txt", base_url),
        b"aaa".to_vec(),
    )
    .await;
    let invalid_key = "a".repeat(1025);

    let delete_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Delete>
  <Object><Key>{}</Key></Object>
  <Object><Key>a.txt</Key></Object>
</Delete>"#,
        invalid_key
    );

    let resp = s3_request(
        "POST",
        &format!("{}/mybucket?delete", base_url),
        delete_xml.into_bytes(),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>InvalidArgument</Code>"));
    assert!(body.contains("<Deleted><Key>a.txt</Key>"));

    let deleted = s3_request("GET", &format!("{}/mybucket/a.txt", base_url), vec![]).await;
    assert_eq!(deleted.status(), 404);
}

#[tokio::test]
async fn test_delete_objects_batch_rejects_invalid_escaped_xml_content() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let delete_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<Delete>
  <Object><Key>bad&amp</Key></Object>
</Delete>"#;

    let resp = s3_request(
        "POST",
        &format!("{}/mybucket?delete", base_url),
        delete_xml.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert_eq!(
        extract_xml_tag(&body, "Code").as_deref(),
        Some("MalformedXML")
    );
}

#[tokio::test]
async fn test_delete_objects_batch_rejects_more_than_1000_keys() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let mut delete_xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Delete>");
    for i in 0..1001 {
        delete_xml.push_str(&format!("<Object><Key>k-{i}</Key></Object>"));
    }
    delete_xml.push_str("</Delete>");

    let resp = s3_request(
        "POST",
        &format!("{}/mybucket?delete", base_url),
        delete_xml.into_bytes(),
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert_eq!(
        extract_xml_tag(&body, "Code").as_deref(),
        Some("MalformedXML")
    );
}

#[tokio::test]
async fn test_delete_objects_batch_rejects_invalid_xml_structure() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let delete_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<Delete>
  <Key>a.txt</Key>
</Delete>"#;

    let resp = s3_request(
        "POST",
        &format!("{}/mybucket?delete", base_url),
        delete_xml.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert_eq!(
        extract_xml_tag(&body, "Code").as_deref(),
        Some("MalformedXML")
    );
}

#[tokio::test]
async fn test_trailing_slash_bucket_routes() {
    // mc sends PUT /bucket/ (with trailing slash)
    let (base_url, _tmp) = start_server().await;

    // Create with trailing slash
    let resp = s3_request("PUT", &format!("{}/mybucket/", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);

    // HEAD with trailing slash
    let resp = s3_request("HEAD", &format!("{}/mybucket/", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);

    // GET (list) with trailing slash
    let resp = s3_request(
        "GET",
        &format!("{}/mybucket/?list-type=2", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 200);

    // DELETE with trailing slash
    let resp = s3_request("DELETE", &format!("{}/mybucket/", base_url), vec![]).await;
    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn test_chunked_upload_interrupted_then_retry() {
    // Simulate: send a truncated/incomplete chunked upload, then retry with a valid one.
    // The server should not leave corrupt data from the partial upload, and the retry
    // should succeed with correct content.
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let url = format!("{}/mybucket/interrupted.txt", base_url);

    // Build a truncated chunked body: valid first chunk header but missing data/terminator.
    // This simulates a client that starts uploading and then drops the connection.
    let parsed = reqwest::Url::parse(&url).unwrap();
    let host = parsed.host_str().unwrap();
    let port = parsed.port().unwrap();
    let host_header = format!("{}:{}", host, port);
    let path = parsed.path();

    let now = chrono::Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let payload_hash = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";

    let mut sign_headers = [
        ("host".to_string(), host_header.clone()),
        ("x-amz-content-sha256".to_string(), payload_hash.to_string()),
        ("x-amz-date".to_string(), amz_date.clone()),
        (
            "x-amz-decoded-content-length".to_string(),
            "1000".to_string(),
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
        "PUT", path, "", canonical_headers, signed_headers_str, payload_hash
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

    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders={},Signature={}",
        ACCESS_KEY, scope, signed_headers_str, signature
    );

    // Send a truncated chunked body: claims 1000 bytes but only sends a partial chunk
    let chunk_sig = "0".repeat(64);
    let truncated_body = format!("3e8;chunk-signature={}\r\npartial data only", chunk_sig);

    // This request should fail (connection reset / error) since we promised 1000 bytes
    // but sent far fewer. We don't care about the exact error, just that it doesn't
    // leave the server in a broken state.
    let _ = client()
        .put(&url)
        .header("host", &host_header)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", payload_hash)
        .header("x-amz-decoded-content-length", "1000")
        .header("authorization", &auth)
        .header("content-type", "application/octet-stream")
        .body(truncated_body.into_bytes())
        .send()
        .await;

    // Small delay to let server finish processing
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Now do a proper chunked upload to the same key — this MUST succeed
    let good_data = b"hello after interrupted upload";
    let resp = s3_put_chunked(&url, good_data).await;
    assert_eq!(
        resp.status(),
        200,
        "Retry upload after interrupted should succeed"
    );

    // Verify content is from the successful retry, not the partial upload
    let resp = s3_request("GET", &url, vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(
        body.as_ref(),
        good_data,
        "Content should be from the retry, not the interrupted upload"
    );
}

#[tokio::test]
async fn test_chunked_upload_multi_chunk() {
    // Test chunked upload with multiple chunks (not just one chunk + terminator)
    let (base_url, _tmp) = start_server().await;

    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let url = format!("{}/mybucket/multichunk.txt", base_url);
    let parsed = reqwest::Url::parse(&url).unwrap();
    let host = parsed.host_str().unwrap();
    let port = parsed.port().unwrap();
    let host_header = format!("{}:{}", host, port);
    let path = parsed.path();

    let chunk1 = b"first chunk data ";
    let chunk2 = b"second chunk data ";
    let chunk3 = b"third chunk data";
    let total_len = chunk1.len() + chunk2.len() + chunk3.len();

    let now = chrono::Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let payload_hash = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";

    let mut sign_headers = [
        ("host".to_string(), host_header.clone()),
        ("x-amz-content-sha256".to_string(), payload_hash.to_string()),
        ("x-amz-date".to_string(), amz_date.clone()),
        (
            "x-amz-decoded-content-length".to_string(),
            total_len.to_string(),
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
        "PUT", path, "", canonical_headers, signed_headers_str, payload_hash
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

    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders={},Signature={}",
        ACCESS_KEY, scope, signed_headers_str, signature
    );

    // Build multi-chunk body
    let chunk_sig = "0".repeat(64);
    let mut chunked_body = Vec::new();
    for chunk_data in [&chunk1[..], &chunk2[..], &chunk3[..]] {
        chunked_body.extend_from_slice(
            format!("{:x};chunk-signature={}\r\n", chunk_data.len(), chunk_sig).as_bytes(),
        );
        chunked_body.extend_from_slice(chunk_data);
        chunked_body.extend_from_slice(b"\r\n");
    }
    // Terminating chunk
    chunked_body.extend_from_slice(format!("0;chunk-signature={}\r\n", chunk_sig).as_bytes());

    let resp = client()
        .put(&url)
        .header("host", &host_header)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", payload_hash)
        .header("x-amz-decoded-content-length", total_len.to_string())
        .header("authorization", &auth)
        .header("content-type", "application/octet-stream")
        .body(chunked_body)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    // Verify all chunks were concatenated correctly
    let resp = s3_request("GET", &url, vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    let expected = b"first chunk data second chunk data third chunk data";
    assert_eq!(
        body.as_ref(),
        expected,
        "Multi-chunk content should be concatenated"
    );

    // Verify content-length matches
    let resp = s3_request("HEAD", &url, vec![]).await;
    assert_eq!(
        resp.headers().get("content-length").unwrap(),
        &total_len.to_string()
    );
}

#[tokio::test]
async fn test_multipart_create_upload() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let resp = s3_request(
        "POST",
        &format!("{}/mybucket/large.bin?uploads=", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    let upload_id = extract_xml_tag(&body, "UploadId").unwrap();
    assert!(!upload_id.is_empty());
}

#[tokio::test]
async fn test_multipart_create_upload_missing_bucket_returns_no_such_bucket() {
    let (base_url, _tmp) = start_server().await;

    let resp = s3_request(
        "POST",
        &format!("{}/missing-bucket/large.bin?uploads=", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 404);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>NoSuchBucket</Code>"));
}

#[tokio::test]
async fn test_multipart_upload_part() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request(
        "POST",
        &format!("{}/mybucket/large.bin?uploads=", base_url),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let resp = s3_request(
        "PUT",
        &format!(
            "{}/mybucket/large.bin?partNumber=1&uploadId={}",
            base_url, upload_id
        ),
        b"part-one".to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let etag = resp.headers().get("etag").unwrap().to_str().unwrap();
    assert!(etag.starts_with('"') && etag.ends_with('"'));
}

#[tokio::test]
async fn test_multipart_upload_part_missing_bucket_returns_no_such_bucket() {
    let (base_url, _tmp) = start_server().await;

    let resp = s3_request(
        "PUT",
        &format!(
            "{}/missing-bucket/large.bin?partNumber=1&uploadId=some-upload-id",
            base_url
        ),
        b"part-one".to_vec(),
    )
    .await;
    assert_eq!(resp.status(), 404);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>NoSuchBucket</Code>"));
}

#[tokio::test]
async fn test_multipart_upload_part_rejects_out_of_range_part_number() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request(
        "POST",
        &format!("{}/mybucket/large.bin?uploads=", base_url),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    for part_number in ["0", "10001"] {
        let resp = s3_request(
            "PUT",
            &format!(
                "{}/mybucket/large.bin?partNumber={}&uploadId={}",
                base_url, part_number, upload_id
            ),
            b"part-data".to_vec(),
        )
        .await;
        assert_eq!(resp.status(), 400);
        let body = resp.text().await.unwrap();
        assert!(body.contains("<Code>InvalidPart</Code>"));
    }
}

#[tokio::test]
async fn test_multipart_complete() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request(
        "POST",
        &format!("{}/mybucket/large.bin?uploads=", base_url),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let p1 = vec![b'a'; 5 * 1024 * 1024];
    let p2 = b"tail".to_vec();
    let r1 = s3_request(
        "PUT",
        &format!(
            "{}/mybucket/large.bin?partNumber=1&uploadId={}",
            base_url, upload_id
        ),
        p1.clone(),
    )
    .await;
    let e1 = r1
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let r2 = s3_request(
        "PUT",
        &format!(
            "{}/mybucket/large.bin?partNumber=2&uploadId={}",
            base_url, upload_id
        ),
        p2.clone(),
    )
    .await;
    let e2 = r2
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part><Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        e1, e2
    );
    let complete = s3_request(
        "POST",
        &format!("{}/mybucket/large.bin?uploadId={}", base_url, upload_id),
        complete_xml.into_bytes(),
    )
    .await;
    assert_eq!(complete.status(), 200);

    let get = s3_request("GET", &format!("{}/mybucket/large.bin", base_url), vec![]).await;
    assert_eq!(get.status(), 200);
    let body = get.bytes().await.unwrap();
    let mut expected = p1;
    expected.extend_from_slice(&p2);
    assert_eq!(body.as_ref(), expected.as_slice());
}

#[tokio::test]
async fn test_multipart_complete_distributed_non_owner_write_forwards_to_primary_owner() {
    let pair = start_forwarding_pair().await;
    let bucket = "routing-multipart-forward-complete";
    s3_request(
        "PUT",
        &format!("{}/{}", pair.coordinator_url, bucket),
        vec![],
    )
    .await;
    s3_request("PUT", &format!("{}/{}", pair.owner_url, bucket), vec![]).await;

    let key = distributed_non_owner_key_for(
        "routing-multipart-forward-complete",
        DISTRIBUTED_LOCAL_NODE,
        std::slice::from_ref(&pair.owner_peer),
    );

    let create = s3_request(
        "POST",
        &format!("{}/{}/{}?uploads=", pair.coordinator_url, bucket, key),
        vec![],
    )
    .await;
    assert_eq!(create.status(), 200);
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let payload = b"multipart-forwarded-payload".to_vec();
    let part = s3_request(
        "PUT",
        &format!(
            "{}/{}/{}?partNumber=1&uploadId={}",
            pair.coordinator_url, bucket, key, upload_id
        ),
        payload.clone(),
    )
    .await;
    assert_eq!(part.status(), 200);
    let etag = part
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .expect("missing part etag")
        .to_string();

    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        etag
    );
    let complete = s3_request(
        "POST",
        &format!(
            "{}/{}/{}?uploadId={}",
            pair.coordinator_url, bucket, key, upload_id
        ),
        complete_xml.into_bytes(),
    )
    .await;
    assert_eq!(complete.status(), 200);

    let get_owner = s3_request(
        "GET",
        &format!("{}/{}/{}", pair.owner_url, bucket, key),
        vec![],
    )
    .await;
    assert_eq!(get_owner.status(), 200);
    assert_eq!(
        get_owner.bytes().await.unwrap().as_ref(),
        payload.as_slice()
    );
}

#[tokio::test]
async fn test_multipart_complete_distributed_primary_write_reports_quorum_headers_when_replica_acks()
 {
    let pair = start_forwarding_pair().await;
    let bucket = "routing-multipart-complete-quorum";
    s3_request(
        "PUT",
        &format!("{}/{}", pair.coordinator_url, bucket),
        vec![],
    )
    .await;
    s3_request("PUT", &format!("{}/{}", pair.owner_url, bucket), vec![]).await;

    let key = distributed_local_owner_key_for(
        "routing-multipart-complete-quorum",
        DISTRIBUTED_LOCAL_NODE,
        std::slice::from_ref(&pair.owner_peer),
    );

    let create = s3_request(
        "POST",
        &format!("{}/{}/{}?uploads=", pair.coordinator_url, bucket, key),
        vec![],
    )
    .await;
    assert_eq!(create.status(), 200);
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let payload = b"multipart-complete-quorum-payload".to_vec();
    let part = s3_request(
        "PUT",
        &format!(
            "{}/{}/{}?partNumber=1&uploadId={}",
            pair.coordinator_url, bucket, key, upload_id
        ),
        payload.clone(),
    )
    .await;
    assert_eq!(part.status(), 200);
    let etag = part
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .expect("missing part etag")
        .to_string();

    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        etag
    );
    let complete = s3_request(
        "POST",
        &format!(
            "{}/{}/{}?uploadId={}",
            pair.coordinator_url, bucket, key, upload_id
        ),
        complete_xml.into_bytes(),
    )
    .await;
    assert_eq!(complete.status(), 200);
    assert_eq!(
        complete
            .headers()
            .get("x-maxio-write-ack-count")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );
    assert_eq!(
        complete
            .headers()
            .get("x-maxio-write-quorum-size")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );
    assert_eq!(
        complete
            .headers()
            .get("x-maxio-write-quorum-reached")
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );

    let get_owner = s3_request(
        "GET",
        &format!("{}/{}/{}", pair.owner_url, bucket, key),
        vec![],
    )
    .await;
    assert_eq!(get_owner.status(), 200);
    assert_eq!(
        get_owner.bytes().await.unwrap().as_ref(),
        payload.as_slice()
    );
}

#[tokio::test]
async fn test_multipart_complete_distributed_primary_write_reports_degraded_quorum_when_replica_unreachable()
 {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = DISTRIBUTED_LOCAL_NODE.to_string();
    config.cluster_peers = vec![DISTRIBUTED_PEER_NODE.to_string()];

    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let bucket = "routing-multipart-complete-replica-unreachable";
    s3_request("PUT", &format!("{}/{}", base_url, bucket), vec![]).await;
    let key = distributed_local_owner_key("routing-multipart-complete-replica-unreachable");

    let create = s3_request(
        "POST",
        &format!("{}/{}/{}?uploads=", base_url, bucket, key),
        vec![],
    )
    .await;
    assert_eq!(create.status(), 200);
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let payload = b"multipart-complete-replica-unreachable".to_vec();
    let part = s3_request(
        "PUT",
        &format!(
            "{}/{}/{}?partNumber=1&uploadId={}",
            base_url, bucket, key, upload_id
        ),
        payload,
    )
    .await;
    assert_eq!(part.status(), 200);
    let etag = part
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .expect("missing part etag")
        .to_string();

    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        etag
    );
    let complete = s3_request(
        "POST",
        &format!("{}/{}/{}?uploadId={}", base_url, bucket, key, upload_id),
        complete_xml.into_bytes(),
    )
    .await;
    assert_eq!(complete.status(), 200);
    assert_eq!(
        complete
            .headers()
            .get("x-maxio-write-ack-count")
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
    assert_eq!(
        complete
            .headers()
            .get("x-maxio-write-quorum-size")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );
    assert_eq!(
        complete
            .headers()
            .get("x-maxio-write-quorum-reached")
            .and_then(|value| value.to_str().ok()),
        Some("false")
    );
}

#[tokio::test]
async fn test_multipart_complete_missing_bucket_returns_no_such_bucket() {
    let (base_url, _tmp) = start_server().await;
    let complete_xml = br#"
        <CompleteMultipartUpload>
            <Part><PartNumber>1</PartNumber><ETag>\"etag-one\"</ETag></Part>
        </CompleteMultipartUpload>
    "#
    .to_vec();

    let resp = s3_request(
        "POST",
        &format!(
            "{}/missing-bucket/large.bin?uploadId=some-upload-id",
            base_url
        ),
        complete_xml,
    )
    .await;
    assert_eq!(resp.status(), 404);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>NoSuchBucket</Code>"));
}

#[tokio::test]
async fn test_multipart_complete_rejects_non_ascending_part_order() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request(
        "POST",
        &format!("{}/mybucket/ordered.bin?uploads=", base_url),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let complete_xml = r#"
        <CompleteMultipartUpload>
            <Part><PartNumber>2</PartNumber><ETag>"etag-two"</ETag></Part>
            <Part><PartNumber>1</PartNumber><ETag>"etag-one"</ETag></Part>
        </CompleteMultipartUpload>
    "#;
    let complete = s3_request(
        "POST",
        &format!("{}/mybucket/ordered.bin?uploadId={}", base_url, upload_id),
        complete_xml.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(complete.status(), 400);
    let body = complete.text().await.unwrap();
    assert!(body.contains("<Code>InvalidPart</Code>"));
    assert!(body.contains("strictly ascending"));
}

#[tokio::test]
async fn test_multipart_complete_rejects_malformed_xml() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request(
        "POST",
        &format!("{}/mybucket/bad-xml.bin?uploads=", base_url),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let complete = s3_request(
        "POST",
        &format!("{}/mybucket/bad-xml.bin?uploadId={}", base_url, upload_id),
        b"<CompleteMultipartUpload><Part><ETag>no-part-number</ETag></Part></CompleteMultipartUpload>".to_vec(),
    )
    .await;
    assert_eq!(complete.status(), 400);
    let body = complete.text().await.unwrap();
    assert!(body.contains("<Code>MalformedXML</Code>"));
}

#[tokio::test]
async fn test_multipart_complete_part_too_small() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request(
        "POST",
        &format!("{}/mybucket/large.bin?uploads=", base_url),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let r1 = s3_request(
        "PUT",
        &format!(
            "{}/mybucket/large.bin?partNumber=1&uploadId={}",
            base_url, upload_id
        ),
        b"tiny".to_vec(),
    )
    .await;
    let e1 = r1
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let r2 = s3_request(
        "PUT",
        &format!(
            "{}/mybucket/large.bin?partNumber=2&uploadId={}",
            base_url, upload_id
        ),
        b"tail".to_vec(),
    )
    .await;
    let e2 = r2
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part><Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        e1, e2
    );
    let complete = s3_request(
        "POST",
        &format!("{}/mybucket/large.bin?uploadId={}", base_url, upload_id),
        complete_xml.into_bytes(),
    )
    .await;
    assert_eq!(complete.status(), 400);
    let body = complete.text().await.unwrap();
    assert!(body.contains("<Code>EntityTooSmall</Code>"));
}

#[tokio::test]
async fn test_multipart_abort() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request(
        "POST",
        &format!("{}/mybucket/large.bin?uploads=", base_url),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let abort = s3_request(
        "DELETE",
        &format!("{}/mybucket/large.bin?uploadId={}", base_url, upload_id),
        vec![],
    )
    .await;
    assert_eq!(abort.status(), 204);
}

#[tokio::test]
async fn test_multipart_list_parts_missing_bucket_returns_no_such_bucket() {
    let (base_url, _tmp) = start_server().await;

    let list = s3_request(
        "GET",
        &format!(
            "{}/missing-bucket/large.bin?uploadId=some-upload-id",
            base_url
        ),
        vec![],
    )
    .await;
    assert_eq!(list.status(), 404);
    let body = list.text().await.unwrap();
    assert!(body.contains("<Code>NoSuchBucket</Code>"));
}

#[tokio::test]
async fn test_multipart_list_parts() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request(
        "POST",
        &format!("{}/mybucket/large.bin?uploads=", base_url),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    s3_request(
        "PUT",
        &format!(
            "{}/mybucket/large.bin?partNumber=1&uploadId={}",
            base_url, upload_id
        ),
        b"part-one".to_vec(),
    )
    .await;

    let list = s3_request(
        "GET",
        &format!("{}/mybucket/large.bin?uploadId={}", base_url, upload_id),
        vec![],
    )
    .await;
    assert_eq!(list.status(), 200);
    let body = list.text().await.unwrap();
    assert!(body.contains("<PartNumber>1</PartNumber>"));
}

#[tokio::test]
async fn test_multipart_list_parts_supports_max_parts_and_marker() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request(
        "POST",
        &format!("{}/mybucket/large.bin?uploads=", base_url),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    for (part_number, payload) in [(1, "part-one"), (2, "part-two"), (3, "part-three")] {
        s3_request(
            "PUT",
            &format!(
                "{}/mybucket/large.bin?partNumber={}&uploadId={}",
                base_url, part_number, upload_id
            ),
            payload.as_bytes().to_vec(),
        )
        .await;
    }

    let first_page = s3_request(
        "GET",
        &format!(
            "{}/mybucket/large.bin?uploadId={}&max-parts=2",
            base_url, upload_id
        ),
        vec![],
    )
    .await;
    assert_eq!(first_page.status(), 200);
    let first_body = first_page.text().await.unwrap();
    assert!(first_body.contains("<IsTruncated>true</IsTruncated>"));
    assert!(first_body.contains("<PartNumberMarker>0</PartNumberMarker>"));
    assert!(first_body.contains("<NextPartNumberMarker>2</NextPartNumberMarker>"));
    assert!(first_body.contains("<MaxParts>2</MaxParts>"));
    assert!(first_body.contains("<PartNumber>1</PartNumber>"));
    assert!(first_body.contains("<PartNumber>2</PartNumber>"));
    assert!(!first_body.contains("<PartNumber>3</PartNumber>"));

    let second_page = s3_request(
        "GET",
        &format!(
            "{}/mybucket/large.bin?uploadId={}&part-number-marker=2&max-parts=2",
            base_url, upload_id
        ),
        vec![],
    )
    .await;
    assert_eq!(second_page.status(), 200);
    let second_body = second_page.text().await.unwrap();
    assert!(second_body.contains("<IsTruncated>false</IsTruncated>"));
    assert!(second_body.contains("<PartNumberMarker>2</PartNumberMarker>"));
    assert!(!second_body.contains("<NextPartNumberMarker>"));
    assert!(second_body.contains("<PartNumber>3</PartNumber>"));
}

#[tokio::test]
async fn test_multipart_list_parts_invalid_max_parts_returns_invalid_argument() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request(
        "POST",
        &format!("{}/mybucket/large.bin?uploads=", base_url),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let resp = s3_request(
        "GET",
        &format!(
            "{}/mybucket/large.bin?uploadId={}&max-parts=abc",
            base_url, upload_id
        ),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert_eq!(
        extract_xml_tag(&body, "Code").as_deref(),
        Some("InvalidArgument")
    );
}

#[tokio::test]
async fn test_multipart_list_parts_invalid_part_number_marker_returns_invalid_argument() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request(
        "POST",
        &format!("{}/mybucket/large.bin?uploads=", base_url),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let resp = s3_request(
        "GET",
        &format!(
            "{}/mybucket/large.bin?uploadId={}&part-number-marker=abc",
            base_url, upload_id
        ),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert_eq!(
        extract_xml_tag(&body, "Code").as_deref(),
        Some("InvalidArgument")
    );
}

#[tokio::test]
async fn test_multipart_list_uploads() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request(
        "POST",
        &format!("{}/mybucket/large.bin?uploads=", base_url),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let list = s3_request("GET", &format!("{}/mybucket?uploads=", base_url), vec![]).await;
    assert_eq!(list.status(), 200);
    let body = list.text().await.unwrap();
    assert!(body.contains(&upload_id));
    assert!(body.contains("<Key>large.bin</Key>"));
}

#[tokio::test]
async fn test_multipart_list_uploads_missing_bucket_returns_no_such_bucket() {
    let (base_url, _tmp) = start_server().await;

    let list = s3_request(
        "GET",
        &format!("{}/missing-bucket?uploads=", base_url),
        vec![],
    )
    .await;
    assert_eq!(list.status(), 404);
    let body = list.text().await.unwrap();
    assert!(body.contains("<Code>NoSuchBucket</Code>"));
}

#[tokio::test]
async fn test_multipart_no_such_upload() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let resp = s3_request(
        "GET",
        &format!("{}/mybucket/missing.bin?uploadId=does-not-exist", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 404);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>NoSuchUpload</Code>"));
}

#[tokio::test]
async fn test_multipart_excluded_from_list_objects() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request(
        "POST",
        &format!("{}/mybucket/in-progress.bin?uploads=", base_url),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();
    s3_request(
        "PUT",
        &format!(
            "{}/mybucket/in-progress.bin?partNumber=1&uploadId={}",
            base_url, upload_id
        ),
        b"partial".to_vec(),
    )
    .await;

    let list = s3_request("GET", &format!("{}/mybucket?list-type=2", base_url), vec![]).await;
    assert_eq!(list.status(), 200);
    let body = list.text().await.unwrap();
    assert!(!body.contains("in-progress.bin"));
}

#[tokio::test]
async fn test_multipart_etag_format() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    let create = s3_request(
        "POST",
        &format!("{}/mybucket/etag.bin?uploads=", base_url),
        vec![],
    )
    .await;
    let upload_id = extract_xml_tag(&create.text().await.unwrap(), "UploadId").unwrap();

    let p1 = vec![b'a'; 5 * 1024 * 1024];
    let p2 = b"tail".to_vec();
    let r1 = s3_request(
        "PUT",
        &format!(
            "{}/mybucket/etag.bin?partNumber=1&uploadId={}",
            base_url, upload_id
        ),
        p1,
    )
    .await;
    let e1 = r1
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let r2 = s3_request(
        "PUT",
        &format!(
            "{}/mybucket/etag.bin?partNumber=2&uploadId={}",
            base_url, upload_id
        ),
        p2,
    )
    .await;
    let e2 = r2
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let complete_xml = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part><Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
        e1, e2
    );
    let complete = s3_request(
        "POST",
        &format!("{}/mybucket/etag.bin?uploadId={}", base_url, upload_id),
        complete_xml.into_bytes(),
    )
    .await;
    let body = complete.text().await.unwrap();
    let etag = extract_xml_tag(&body, "ETag").unwrap();
    assert!(etag.starts_with('"') && etag.ends_with('"'));
    assert!(etag.contains("-2"));
}

#[tokio::test]
async fn test_copy_object_basic() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    // Upload source object
    s3_request(
        "PUT",
        &format!("{}/mybucket/src.txt", base_url),
        b"copy me".to_vec(),
    )
    .await;

    // Copy to new key in same bucket
    let resp = s3_request_with_headers(
        "PUT",
        &format!("{}/mybucket/dst.txt", base_url),
        vec![],
        vec![("x-amz-copy-source", "/mybucket/src.txt")],
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<CopyObjectResult>"));
    assert!(body.contains("<ETag>"));
    assert!(body.contains("<LastModified>"));

    // Verify destination content matches source
    let resp = s3_request("GET", &format!("{}/mybucket/dst.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let content = resp.bytes().await.unwrap();
    assert_eq!(content.as_ref(), b"copy me");
}

#[tokio::test]
async fn test_copy_object_cross_bucket() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/src-bucket", base_url), vec![]).await;
    s3_request("PUT", &format!("{}/dst-bucket", base_url), vec![]).await;

    s3_request(
        "PUT",
        &format!("{}/src-bucket/file.txt", base_url),
        b"cross bucket".to_vec(),
    )
    .await;

    let resp = s3_request_with_headers(
        "PUT",
        &format!("{}/dst-bucket/file.txt", base_url),
        vec![],
        vec![("x-amz-copy-source", "/src-bucket/file.txt")],
    )
    .await;
    assert_eq!(resp.status(), 200);

    let resp = s3_request("GET", &format!("{}/dst-bucket/file.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"cross bucket");
}

#[tokio::test]
async fn test_copy_object_metadata_copy() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    // Upload with specific content-type
    s3_request_with_headers(
        "PUT",
        &format!("{}/mybucket/src.txt", base_url),
        b"hello".to_vec(),
        vec![("content-type", "text/plain")],
    )
    .await;

    // Copy with default COPY directive
    s3_request_with_headers(
        "PUT",
        &format!("{}/mybucket/dst.txt", base_url),
        vec![],
        vec![("x-amz-copy-source", "/mybucket/src.txt")],
    )
    .await;

    // HEAD destination — content-type should be preserved
    let resp = s3_request("HEAD", &format!("{}/mybucket/dst.txt", base_url), vec![]).await;
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "text/plain"
    );
}

#[tokio::test]
async fn test_copy_object_metadata_replace() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    s3_request_with_headers(
        "PUT",
        &format!("{}/mybucket/src.txt", base_url),
        b"hello".to_vec(),
        vec![("content-type", "text/plain")],
    )
    .await;

    // Copy with REPLACE directive and new content-type
    s3_request_with_headers(
        "PUT",
        &format!("{}/mybucket/dst.txt", base_url),
        vec![],
        vec![
            ("x-amz-copy-source", "/mybucket/src.txt"),
            ("x-amz-metadata-directive", "REPLACE"),
            ("content-type", "application/json"),
        ],
    )
    .await;

    let resp = s3_request("HEAD", &format!("{}/mybucket/dst.txt", base_url), vec![]).await;
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/json"
    );
}

#[tokio::test]
async fn test_copy_object_metadata_directive_is_case_insensitive() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    s3_request_with_headers(
        "PUT",
        &format!("{}/mybucket/src.txt", base_url),
        b"hello".to_vec(),
        vec![("content-type", "text/plain")],
    )
    .await;

    // Lowercase metadata directive should be treated as REPLACE.
    s3_request_with_headers(
        "PUT",
        &format!("{}/mybucket/dst.txt", base_url),
        vec![],
        vec![
            ("x-amz-copy-source", "/mybucket/src.txt"),
            ("x-amz-metadata-directive", "replace"),
            ("content-type", "application/xml"),
        ],
    )
    .await;

    let resp = s3_request("HEAD", &format!("{}/mybucket/dst.txt", base_url), vec![]).await;
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/xml"
    );
}

#[tokio::test]
async fn test_copy_object_can_target_specific_source_version() {
    let (base_url, _tmp) = start_server().await;
    let bucket = "copy-source-version";
    let source_key = "src.txt";
    let destination_key = "dst.txt";
    s3_request("PUT", &format!("{}/{}", base_url, bucket), vec![]).await;

    let enable_xml =
        br#"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>"#.to_vec();
    let enable = s3_request(
        "PUT",
        &format!("{}/{}?versioning", base_url, bucket),
        enable_xml,
    )
    .await;
    assert_eq!(enable.status(), 200);

    let put_v1 = s3_request(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, source_key),
        b"version-one".to_vec(),
    )
    .await;
    assert_eq!(put_v1.status(), 200);
    let version_1 = put_v1
        .headers()
        .get("x-amz-version-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing version id for v1")
        .to_string();

    let put_v2 = s3_request(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, source_key),
        b"version-two".to_vec(),
    )
    .await;
    assert_eq!(put_v2.status(), 200);

    let copy_source_header = format!("/{}/{}?versionId={}", bucket, source_key, version_1);
    let copy = s3_request_with_headers(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, destination_key),
        vec![],
        vec![("x-amz-copy-source", &copy_source_header)],
    )
    .await;
    assert_eq!(copy.status(), 200);
    assert_eq!(
        copy.headers()
            .get("x-amz-copy-source-version-id")
            .and_then(|v| v.to_str().ok()),
        Some(version_1.as_str())
    );

    let destination = s3_request(
        "GET",
        &format!("{}/{}/{}", base_url, bucket, destination_key),
        vec![],
    )
    .await;
    assert_eq!(destination.status(), 200);
    assert_eq!(destination.bytes().await.unwrap().as_ref(), b"version-one");
}

#[tokio::test]
async fn test_copy_object_source_not_found() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let resp = s3_request_with_headers(
        "PUT",
        &format!("{}/mybucket/dst.txt", base_url),
        vec![],
        vec![("x-amz-copy-source", "/mybucket/nonexistent.txt")],
    )
    .await;
    assert_eq!(resp.status(), 404);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>NoSuchKey</Code>"));
}

#[tokio::test]
async fn test_copy_object_missing_source_bucket_returns_no_such_bucket() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/dst-bucket", base_url), vec![]).await;

    let resp = s3_request_with_headers(
        "PUT",
        &format!("{}/dst-bucket/dst.txt", base_url),
        vec![],
        vec![("x-amz-copy-source", "/missing-source/src.txt")],
    )
    .await;
    assert_eq!(resp.status(), 404);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>NoSuchBucket</Code>"));
}

#[tokio::test]
async fn test_copy_object_missing_destination_bucket_returns_no_such_bucket() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/src-bucket", base_url), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/src-bucket/src.txt", base_url),
        b"copy me".to_vec(),
    )
    .await;

    let resp = s3_request_with_headers(
        "PUT",
        &format!("{}/missing-dst/dst.txt", base_url),
        vec![],
        vec![("x-amz-copy-source", "/src-bucket/src.txt")],
    )
    .await;
    assert_eq!(resp.status(), 404);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>NoSuchBucket</Code>"));
}

#[tokio::test]
async fn test_copy_object_no_leading_slash() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/mybucket/src.txt", base_url),
        b"no slash".to_vec(),
    )
    .await;

    // Copy source without leading slash
    let resp = s3_request_with_headers(
        "PUT",
        &format!("{}/mybucket/dst.txt", base_url),
        vec![],
        vec![("x-amz-copy-source", "mybucket/src.txt")],
    )
    .await;
    assert_eq!(resp.status(), 200);

    let resp = s3_request("GET", &format!("{}/mybucket/dst.txt", base_url), vec![]).await;
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"no slash");
}

#[tokio::test]
async fn test_copy_object_rejects_empty_source_key() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    let resp = s3_request_with_headers(
        "PUT",
        &format!("{}/mybucket/dst.txt", base_url),
        vec![],
        vec![("x-amz-copy-source", "/mybucket/")],
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>InvalidArgument</Code>"));
}

#[tokio::test]
async fn test_copy_object_rejects_empty_source_bucket() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    // Decodes to "/key", which implies an empty source bucket.
    let resp = s3_request_with_headers(
        "PUT",
        &format!("{}/mybucket/dst.txt", base_url),
        vec![],
        vec![("x-amz-copy-source", "/%2Fkey")],
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>InvalidArgument</Code>"));
}

#[tokio::test]
async fn test_copy_object_rejects_double_leading_slash_source() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;
    s3_request(
        "PUT",
        &format!("{}/mybucket/src.txt", base_url),
        b"payload".to_vec(),
    )
    .await;

    let resp = s3_request_with_headers(
        "PUT",
        &format!("{}/mybucket/dst.txt", base_url),
        vec![],
        vec![("x-amz-copy-source", "//mybucket/src.txt")],
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>InvalidArgument</Code>"));
}

// ── Range request tests ──────────────────────────────────────────────

#[tokio::test]
async fn test_get_object_range_first_bytes() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/range-bucket", base_url), vec![]).await;

    let content: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
    s3_request_with_headers(
        "PUT",
        &format!("{}/range-bucket/file.bin", base_url),
        content.clone(),
        vec![],
    )
    .await;

    let resp = s3_request_with_headers(
        "GET",
        &format!("{}/range-bucket/file.bin", base_url),
        vec![],
        vec![("range", "bytes=0-499")],
    )
    .await;

    assert_eq!(resp.status(), 206);
    assert_eq!(resp.headers()["content-length"], "500");
    assert_eq!(resp.headers()["content-range"], "bytes 0-499/1000");
    assert_eq!(resp.headers()["accept-ranges"], "bytes");
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), &content[0..500]);
}

#[tokio::test]
async fn test_get_object_range_middle_bytes() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/range-mid-bucket", base_url), vec![]).await;

    let content: Vec<u8> = (0..100).map(|i| (i % 256) as u8).collect();
    s3_request_with_headers(
        "PUT",
        &format!("{}/range-mid-bucket/file.bin", base_url),
        content.clone(),
        vec![],
    )
    .await;

    let resp = s3_request_with_headers(
        "GET",
        &format!("{}/range-mid-bucket/file.bin", base_url),
        vec![],
        vec![("range", "bytes=10-19")],
    )
    .await;

    assert_eq!(resp.status(), 206);
    assert_eq!(resp.headers()["content-length"], "10");
    assert_eq!(resp.headers()["content-range"], "bytes 10-19/100");
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), &content[10..20]);
}

#[tokio::test]
async fn test_get_object_range_suffix() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/range-sfx-bucket", base_url), vec![]).await;

    let content: Vec<u8> = (0u16..1000).map(|i| (i % 256) as u8).collect();
    s3_request_with_headers(
        "PUT",
        &format!("{}/range-sfx-bucket/file.bin", base_url),
        content.clone(),
        vec![],
    )
    .await;

    let resp = s3_request_with_headers(
        "GET",
        &format!("{}/range-sfx-bucket/file.bin", base_url),
        vec![],
        vec![("range", "bytes=-100")],
    )
    .await;

    assert_eq!(resp.status(), 206);
    assert_eq!(resp.headers()["content-length"], "100");
    assert_eq!(resp.headers()["content-range"], "bytes 900-999/1000");
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), &content[900..1000]);
}

#[tokio::test]
async fn test_get_object_range_open_end() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/range-open-bucket", base_url), vec![]).await;

    let content: Vec<u8> = (0u16..1000).map(|i| (i % 256) as u8).collect();
    s3_request_with_headers(
        "PUT",
        &format!("{}/range-open-bucket/file.bin", base_url),
        content.clone(),
        vec![],
    )
    .await;

    let resp = s3_request_with_headers(
        "GET",
        &format!("{}/range-open-bucket/file.bin", base_url),
        vec![],
        vec![("range", "bytes=500-")],
    )
    .await;

    assert_eq!(resp.status(), 206);
    assert_eq!(resp.headers()["content-length"], "500");
    assert_eq!(resp.headers()["content-range"], "bytes 500-999/1000");
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), &content[500..1000]);
}

#[tokio::test]
async fn test_get_object_range_clamp_beyond_end() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/range-clamp-bucket", base_url), vec![]).await;

    let content: Vec<u8> = (0..100).map(|i| (i % 256) as u8).collect();
    s3_request_with_headers(
        "PUT",
        &format!("{}/range-clamp-bucket/file.bin", base_url),
        content.clone(),
        vec![],
    )
    .await;

    let resp = s3_request_with_headers(
        "GET",
        &format!("{}/range-clamp-bucket/file.bin", base_url),
        vec![],
        vec![("range", "bytes=0-9999")],
    )
    .await;

    assert_eq!(resp.status(), 206);
    assert_eq!(resp.headers()["content-length"], "100");
    assert_eq!(resp.headers()["content-range"], "bytes 0-99/100");
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), &content[..]);
}

#[tokio::test]
async fn test_get_object_range_invalid_416() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/range-416-bucket", base_url), vec![]).await;

    let content: Vec<u8> = (0..100).map(|i| (i % 256) as u8).collect();
    s3_request_with_headers(
        "PUT",
        &format!("{}/range-416-bucket/file.bin", base_url),
        content,
        vec![],
    )
    .await;

    let resp = s3_request_with_headers(
        "GET",
        &format!("{}/range-416-bucket/file.bin", base_url),
        vec![],
        vec![("range", "bytes=5000-6000")],
    )
    .await;

    assert_eq!(resp.status(), 416);
}

#[tokio::test]
async fn test_get_object_no_range_has_accept_ranges() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/range-ar-bucket", base_url), vec![]).await;

    s3_request_with_headers(
        "PUT",
        &format!("{}/range-ar-bucket/file.txt", base_url),
        b"hello".to_vec(),
        vec![],
    )
    .await;

    let resp = s3_request_with_headers(
        "GET",
        &format!("{}/range-ar-bucket/file.txt", base_url),
        vec![],
        vec![],
    )
    .await;

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["accept-ranges"], "bytes");
}

#[tokio::test]
async fn test_get_object_range_preserves_headers() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/range-hdr-bucket", base_url), vec![]).await;

    s3_request_with_headers(
        "PUT",
        &format!("{}/range-hdr-bucket/file.txt", base_url),
        b"hello world".to_vec(),
        vec![("content-type", "text/plain")],
    )
    .await;

    let resp = s3_request_with_headers(
        "GET",
        &format!("{}/range-hdr-bucket/file.txt", base_url),
        vec![],
        vec![("range", "bytes=0-4")],
    )
    .await;

    assert_eq!(resp.status(), 206);
    assert!(resp.headers().contains_key("etag"));
    assert!(resp.headers().contains_key("last-modified"));
    assert!(resp.headers().contains_key("content-type"));
}

#[tokio::test]
async fn test_get_object_range_preserves_checksum_header() {
    let (base_url, _tmp) = start_server().await;
    s3_request(
        "PUT",
        &format!("{}/range-checksum-bucket", base_url),
        vec![],
    )
    .await;

    let body = b"hello checksum range";
    let crc = crc32fast::hash(body);
    let crc_b64 = base64::engine::general_purpose::STANDARD.encode(crc.to_be_bytes());

    let put = s3_request_with_headers(
        "PUT",
        &format!("{}/range-checksum-bucket/file.txt", base_url),
        body.to_vec(),
        vec![("x-amz-checksum-crc32", &crc_b64)],
    )
    .await;
    assert_eq!(put.status(), 200);

    let resp = s3_request_with_headers(
        "GET",
        &format!("{}/range-checksum-bucket/file.txt", base_url),
        vec![],
        vec![("range", "bytes=0-4")],
    )
    .await;

    assert_eq!(resp.status(), 206);
    assert_eq!(
        resp.headers()
            .get("x-amz-checksum-crc32")
            .and_then(|v| v.to_str().ok()),
        Some(crc_b64.as_str())
    );
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"hello");
}

#[tokio::test]
async fn test_head_object_accept_ranges() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/range-head-bucket", base_url), vec![]).await;

    s3_request_with_headers(
        "PUT",
        &format!("{}/range-head-bucket/file.txt", base_url),
        b"hello".to_vec(),
        vec![],
    )
    .await;

    let resp = s3_request_with_headers(
        "HEAD",
        &format!("{}/range-head-bucket/file.txt", base_url),
        vec![],
        vec![],
    )
    .await;

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["accept-ranges"], "bytes");
}

#[tokio::test]
async fn test_put_folder_marker() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    // Create folder marker via PutObject with trailing slash
    let resp = s3_request("PUT", &format!("{}/mybucket/photos/", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);

    // Folder should appear in ListObjectsV2 as a CommonPrefix
    let resp = s3_request(
        "GET",
        &format!("{}/mybucket?list-type=2&delimiter=%2F", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Prefix>photos/</Prefix>"), "body: {}", body);

    // HeadObject on the folder marker should return 200
    let resp = s3_request("HEAD", &format!("{}/mybucket/photos/", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_folder_marker_with_children() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    // Create folder marker
    s3_request("PUT", &format!("{}/mybucket/docs/", base_url), vec![]).await;

    // Upload object inside it
    s3_request_with_headers(
        "PUT",
        &format!("{}/mybucket/docs/readme.txt", base_url),
        b"hello".to_vec(),
        vec![],
    )
    .await;

    // List at root — should see "docs/" as CommonPrefix
    let resp = s3_request(
        "GET",
        &format!("{}/mybucket?list-type=2&delimiter=%2F", base_url),
        vec![],
    )
    .await;
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Prefix>docs/</Prefix>"), "body: {}", body);
    assert!(
        !body.contains("readme.txt"),
        "readme.txt should not appear at root"
    );

    // List inside docs/ — should see readme.txt
    let resp = s3_request(
        "GET",
        &format!(
            "{}/mybucket?list-type=2&prefix=docs%2F&delimiter=%2F",
            base_url
        ),
        vec![],
    )
    .await;
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("<Key>docs/readme.txt</Key>"),
        "body: {}",
        body
    );

    // Delete folder marker — the child object should still exist
    s3_request("DELETE", &format!("{}/mybucket/docs/", base_url), vec![]).await;
    let resp = s3_request(
        "GET",
        &format!("{}/mybucket/docs/readme.txt", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_delete_folder_marker() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/mybucket", base_url), vec![]).await;

    // Create and then delete folder marker
    s3_request("PUT", &format!("{}/mybucket/empty-dir/", base_url), vec![]).await;
    s3_request(
        "DELETE",
        &format!("{}/mybucket/empty-dir/", base_url),
        vec![],
    )
    .await;

    // HeadObject should now return 404
    let resp = s3_request("HEAD", &format!("{}/mybucket/empty-dir/", base_url), vec![]).await;
    assert_eq!(resp.status(), 404);
}
