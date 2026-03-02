use super::*;
use maxio::config::MembershipProtocol;
use maxio::server::AppState;

#[tokio::test]
async fn test_request_id_header_present_on_s3_auth_failure() {
    let (base_url, _tmp) = start_server().await;
    let resp = client().get(format!("{}/", base_url)).send().await.unwrap();
    assert_eq!(resp.status(), 403);

    let request_id = resp
        .headers()
        .get("x-amz-request-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-amz-request-id");
    uuid::Uuid::parse_str(request_id).expect("request id should be a valid uuid");
}

fn metric_value(metrics: &str, name: &str) -> Option<f64> {
    metrics.lines().find_map(|line| {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || !trimmed.starts_with(name) {
            return None;
        }
        let value = trimmed.split_whitespace().nth(1)?;
        value.parse::<f64>().ok()
    })
}

#[tokio::test]
async fn test_metrics_endpoint_reports_distributed_gauges_when_cluster_peers_configured() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    config.membership_protocol = MembershipProtocol::Gossip;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let resp = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();

    assert_eq!(metric_value(&body, "maxio_distributed_mode"), Some(1.0));
    assert_eq!(metric_value(&body, "maxio_cluster_peers_total"), Some(1.0));
    assert_eq!(
        metric_value(&body, "maxio_membership_nodes_total"),
        Some(2.0)
    );
    assert!(body.contains("maxio_membership_protocol_info{protocol=\"gossip\"} 1"));
    assert_eq!(metric_value(&body, "maxio_placement_epoch"), Some(0.0));
}

#[tokio::test]
async fn test_console_route_bypasses_sigv4_and_has_request_id() {
    let (base_url, _tmp) = start_server().await;
    let resp = client()
        .get(format!("{}/api/auth/check", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "/api routes should not require SigV4");

    let request_id = resp
        .headers()
        .get("x-amz-request-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-amz-request-id");
    uuid::Uuid::parse_str(request_id).expect("request id should be a valid uuid");
}

#[tokio::test]
async fn test_metrics_endpoint_exposes_runtime_counters() {
    let (base_url, _tmp) = start_server().await;

    let resp = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "text/plain; version=0.0.4"
    );

    let body = resp.text().await.unwrap();
    assert!(
        body.contains("maxio_requests_total"),
        "metrics output missing request counter"
    );
    assert!(
        body.contains("maxio_uptime_seconds"),
        "metrics output missing uptime gauge"
    );
    assert!(
        body.contains("maxio_build_info"),
        "metrics output missing build info"
    );
    assert!(
        body.contains("maxio_distributed_mode"),
        "metrics output missing distributed-mode gauge"
    );
    assert!(
        body.contains("maxio_cluster_peers_total"),
        "metrics output missing cluster-peer count gauge"
    );
    assert!(
        body.contains("maxio_membership_nodes_total"),
        "metrics output missing membership-node count gauge"
    );
    assert!(
        body.contains("maxio_membership_protocol_info"),
        "metrics output missing membership protocol info gauge"
    );
    assert!(
        body.contains("maxio_placement_epoch"),
        "metrics output missing placement epoch gauge"
    );
}

#[tokio::test]
async fn test_healthz_endpoint_reports_runtime_status() {
    let (base_url, _tmp) = start_server().await;
    let resp = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/json"
    );

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert!(body["uptimeSeconds"].as_f64().is_some());
    assert_eq!(body["mode"], "standalone");
    assert!(body["nodeId"].as_str().is_some_and(|v| !v.is_empty()));
    assert_eq!(body["clusterPeerCount"], 0);
    assert_eq!(body["clusterPeers"], serde_json::json!([]));
    assert_eq!(body["membershipNodeCount"], 1);
    assert_eq!(
        body["membershipNodes"],
        serde_json::json!(["maxio-test-node"])
    );
    assert_eq!(body["membershipProtocol"], "static-bootstrap");
    assert!(
        body["membershipViewId"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );
    assert_eq!(body["placementEpoch"], 0);
    assert_eq!(body["checks"]["dataDirAccessible"], true);
    assert_eq!(body["checks"]["dataDirWritable"], true);
    assert_eq!(body["checks"]["storageDataPathReadable"], true);
    assert_eq!(body["checks"]["diskHeadroomSufficient"], true);
    assert_eq!(body["checks"]["peerConnectivityReady"], true);
    assert_eq!(body["checks"]["membershipProtocolReady"], true);
    assert_eq!(body["warnings"], serde_json::json!([]));
}

#[tokio::test]
async fn test_healthz_reports_distributed_mode_when_cluster_peers_configured() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["127.0.0.1:1".to_string()];
    config.membership_protocol = MembershipProtocol::Gossip;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let resp = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["status"], "degraded");
    assert_eq!(body["mode"], "distributed");
    assert_eq!(body["clusterPeerCount"], 1);
    assert_eq!(body["clusterPeers"], serde_json::json!(["127.0.0.1:1"]));
    assert_eq!(body["membershipNodeCount"], 2);
    assert_eq!(
        body["membershipNodes"],
        serde_json::json!(["127.0.0.1:1", "maxio-test-node"])
    );
    assert_eq!(body["membershipProtocol"], "gossip");
    assert!(
        body["membershipViewId"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );
    assert_eq!(body["placementEpoch"], 0);
    assert_eq!(body["checks"]["dataDirAccessible"], true);
    assert_eq!(body["checks"]["dataDirWritable"], true);
    assert_eq!(body["checks"]["storageDataPathReadable"], true);
    assert_eq!(body["checks"]["diskHeadroomSufficient"], true);
    assert_eq!(body["checks"]["peerConnectivityReady"], false);
    assert_eq!(body["checks"]["membershipProtocolReady"], false);
    assert!(
        body["warnings"]
            .as_array()
            .is_some_and(|warnings| !warnings.is_empty())
    );
}

#[tokio::test]
async fn test_healthz_reports_degraded_when_storage_data_path_probe_fails() {
    let (base_url, tmp) = start_server().await;
    tokio::fs::remove_dir_all(tmp.path().join("buckets"))
        .await
        .expect("buckets directory should be removable");

    let resp = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["status"], "degraded");
    assert_eq!(body["checks"]["dataDirAccessible"], true);
    assert_eq!(body["checks"]["dataDirWritable"], true);
    assert_eq!(body["checks"]["storageDataPathReadable"], false);
    assert_eq!(body["checks"]["diskHeadroomSufficient"], true);
    assert_eq!(body["checks"]["peerConnectivityReady"], true);
    assert_eq!(body["checks"]["membershipProtocolReady"], true);
    assert!(
        body["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.iter().any(|warning| warning
                .as_str()
                .is_some_and(|msg| msg.contains("Storage data-path probe failed"))))
    );
}

#[tokio::test]
async fn test_healthz_reports_degraded_when_disk_headroom_threshold_not_met() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.min_disk_headroom_bytes = u64::MAX;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let resp = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["status"], "degraded");
    assert_eq!(body["checks"]["dataDirAccessible"], true);
    assert_eq!(body["checks"]["dataDirWritable"], true);
    assert_eq!(body["checks"]["storageDataPathReadable"], true);
    assert_eq!(body["checks"]["diskHeadroomSufficient"], false);
    assert_eq!(body["checks"]["peerConnectivityReady"], true);
    assert_eq!(body["checks"]["membershipProtocolReady"], true);
    assert!(
        body["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.iter().any(|warning| warning
                .as_str()
                .is_some_and(|msg| msg.contains("Disk headroom below threshold"))))
    );
}

#[tokio::test]
async fn test_healthz_reports_degraded_when_static_peer_connectivity_probe_fails() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["127.0.0.1:1".to_string()];
    config.membership_protocol = MembershipProtocol::StaticBootstrap;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let resp = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["status"], "degraded");
    assert_eq!(body["checks"]["membershipProtocolReady"], true);
    assert_eq!(body["checks"]["peerConnectivityReady"], false);
    assert!(
        body["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.iter().any(|warning| warning
                .as_str()
                .is_some_and(|msg| msg.contains("Peer connectivity probe failed"))))
    );
}

#[tokio::test]
async fn test_healthz_reports_degraded_when_cluster_peers_include_local_node_id() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = "127.0.0.1:1".to_string();
    config.cluster_peers = vec!["127.0.0.1:1".to_string()];
    config.membership_protocol = MembershipProtocol::StaticBootstrap;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let resp = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["status"], "degraded");
    assert_eq!(body["checks"]["membershipProtocolReady"], true);
    assert_eq!(body["checks"]["peerConnectivityReady"], false);
    assert!(
        body["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.iter().any(|warning| warning
                .as_str()
                .is_some_and(|msg| msg.contains("includes local node id"))))
    );
}

#[tokio::test]
async fn test_placement_epoch_persists_and_increments_when_membership_view_changes() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();

    let config_a = make_test_config(data_dir.clone(), false, 10 * 1024 * 1024, 0);
    let state_a = AppState::from_config(config_a)
        .await
        .expect("state A should initialize");
    assert_eq!(state_a.placement_epoch(), 0);
    drop(state_a);

    let mut config_b = make_test_config(data_dir.clone(), false, 10 * 1024 * 1024, 0);
    config_b.cluster_peers = vec!["node-b.internal:9000".to_string()];
    let state_b = AppState::from_config(config_b)
        .await
        .expect("state B should initialize");
    assert_eq!(state_b.placement_epoch(), 1);
    drop(state_b);

    let mut config_c = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config_c.cluster_peers = vec!["node-b.internal:9000".to_string()];
    let state_c = AppState::from_config(config_c)
        .await
        .expect("state C should initialize");
    assert_eq!(state_c.placement_epoch(), 1);
}

#[tokio::test]
async fn test_cors_preflight_s3_without_auth() {
    let (base_url, _tmp) = start_server().await;
    let origin = "https://example.com";
    let resp = client()
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/mybucket/object.txt", base_url),
        )
        .header("origin", origin)
        .header("access-control-request-method", "PUT")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .unwrap()
            .to_str()
            .unwrap(),
        origin
    );
    assert!(
        resp.headers()
            .get("access-control-allow-methods")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("PUT")
    );
    assert_eq!(
        resp.headers()
            .get("access-control-allow-credentials")
            .unwrap()
            .to_str()
            .unwrap(),
        "true"
    );
}

#[tokio::test]
async fn test_cors_preflight_without_origin_uses_wildcard_without_credentials() {
    let (base_url, _tmp) = start_server().await;
    let resp = client()
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/mybucket/object.txt", base_url),
        )
        .header("access-control-request-method", "PUT")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .unwrap()
            .to_str()
            .unwrap(),
        "*"
    );
    assert!(
        resp.headers()
            .get("access-control-allow-credentials")
            .is_none()
    );
}

#[tokio::test]
async fn test_cors_preflight_console_route_without_auth() {
    let (base_url, _tmp) = start_server().await;
    let origin = "https://console.example.com";
    let resp = client()
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/api/auth/check", base_url),
        )
        .header("origin", origin)
        .header("access-control-request-method", "GET")
        .header("access-control-request-headers", "content-type")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .unwrap()
            .to_str()
            .unwrap(),
        origin
    );
    assert_eq!(
        resp.headers()
            .get("access-control-allow-credentials")
            .unwrap()
            .to_str()
            .unwrap(),
        "true"
    );
    let request_id = resp
        .headers()
        .get("x-amz-request-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-amz-request-id");
    uuid::Uuid::parse_str(request_id).expect("request id should be a valid uuid");
}

#[tokio::test]
async fn test_cors_preflight_includes_vary_origin_and_request_id() {
    let (base_url, _tmp) = start_server().await;
    let origin = "https://example.com";
    let resp = client()
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/mybucket/object.txt", base_url),
        )
        .header("origin", origin)
        .header("access-control-request-method", "GET")
        .header(
            "access-control-request-headers",
            "x-amz-date,x-amz-content-sha256",
        )
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);
    let vary = resp.headers().get("vary").unwrap().to_str().unwrap();
    let vary_values: Vec<&str> = vary.split(',').map(|v| v.trim()).collect();
    assert!(vary_values.contains(&"Origin"));
    assert!(vary_values.contains(&"Access-Control-Request-Method"));
    assert!(vary_values.contains(&"Access-Control-Request-Headers"));
    let request_id = resp
        .headers()
        .get("x-amz-request-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-amz-request-id");
    uuid::Uuid::parse_str(request_id).expect("request id should be a valid uuid");
}

#[tokio::test]
async fn test_cors_preflight_reflects_requested_allow_headers() {
    let (base_url, _tmp) = start_server().await;
    let resp = client()
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/api/auth/check", base_url),
        )
        .header("origin", "https://example.com")
        .header("access-control-request-method", "GET")
        .header(
            "access-control-request-headers",
            "x-amz-date, X-Amz-Meta-Filename, X-Custom-Trace",
        )
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);
    let allow_headers = resp
        .headers()
        .get("access-control-allow-headers")
        .and_then(|v| v.to_str().ok())
        .expect("missing access-control-allow-headers");
    let allow_header_values: Vec<&str> = allow_headers.split(',').collect();
    assert!(allow_header_values.contains(&"x-amz-date"));
    assert!(allow_header_values.contains(&"x-amz-meta-filename"));
    assert!(allow_header_values.contains(&"x-custom-trace"));
}

#[tokio::test]
async fn test_cors_headers_present_on_s3_error_response() {
    let (base_url, _tmp) = start_server().await;
    let origin = "https://example.com";
    let resp = client()
        .get(format!("{}/", base_url))
        .header("origin", origin)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .unwrap()
            .to_str()
            .unwrap(),
        origin
    );
    assert_eq!(
        resp.headers()
            .get("access-control-allow-credentials")
            .unwrap()
            .to_str()
            .unwrap(),
        "true"
    );
    assert!(
        resp.headers()
            .get("access-control-expose-headers")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("x-amz-request-id")
    );
}

#[tokio::test]
async fn test_cors_origin_reflection_on_successful_s3_response() {
    let (base_url, _tmp) = start_server().await;
    let origin = "https://example.com";

    let resp = s3_request_with_headers(
        "GET",
        &format!("{}/", base_url),
        vec![],
        vec![("origin", origin)],
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .unwrap()
            .to_str()
            .unwrap(),
        origin
    );
    assert_eq!(
        resp.headers()
            .get("access-control-allow-credentials")
            .unwrap()
            .to_str()
            .unwrap(),
        "true"
    );

    let request_id = resp
        .headers()
        .get("x-amz-request-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-amz-request-id");
    uuid::Uuid::parse_str(request_id).expect("request id should be a valid uuid");
}
