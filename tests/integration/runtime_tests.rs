use super::*;

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
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert!(body["uptimeSeconds"].as_f64().is_some());
    assert_eq!(body["mode"], "standalone");
    assert!(body["nodeId"].as_str().is_some_and(|v| !v.is_empty()));
    assert_eq!(body["clusterPeerCount"], 0);
    assert_eq!(body["clusterPeers"], serde_json::json!([]));
}

#[tokio::test]
async fn test_healthz_reports_distributed_mode_when_cluster_peers_configured() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let resp = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["mode"], "distributed");
    assert_eq!(body["clusterPeerCount"], 1);
    assert_eq!(
        body["clusterPeers"],
        serde_json::json!(["node-b.internal:9000"])
    );
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

    let request_id = resp
        .headers()
        .get("x-amz-request-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-amz-request-id");
    uuid::Uuid::parse_str(request_id).expect("request id should be a valid uuid");
}
