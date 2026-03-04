use super::*;
use hmac::Mac;
use serde_json::json;
use sha2::{Digest, Sha256};

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

fn metric_labeled_value(metrics: &str, metric_with_labels: &str) -> Option<f64> {
    metrics.lines().find_map(|line| {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || !trimmed.starts_with(metric_with_labels) {
            return None;
        }
        let value = trimmed.split_whitespace().nth(1)?;
        value.parse::<f64>().ok()
    })
}

#[tokio::test]
async fn test_auth_rejects_bad_key() {
    let (base_url, _tmp) = start_server().await;

    // Request with no auth header
    let resp = client().get(&base_url).send().await.unwrap();
    assert_eq!(resp.status(), 403);

    // Request with garbage auth
    let resp = client()
        .get(&base_url)
        .header("authorization", "garbage")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_auth_accepts_valid_signature() {
    let (base_url, _tmp) = start_server().await;
    let resp = s3_request("GET", &format!("{}/", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_auth_accepts_signed_requests_with_custom_forwarding_like_headers() {
    let (base_url, _tmp) = start_server().await;
    let bucket = "auth-custom-forwarding-headers";
    let key = "docs/a.txt";

    let create = s3_request("PUT", &format!("{}/{}", base_url, bucket), vec![]).await;
    assert_eq!(create.status(), 200);

    let put = s3_request_with_headers(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, key),
        b"auth-custom-header-payload".to_vec(),
        vec![
            ("x-maxio-forwarded-write-epoch", "7"),
            ("x-maxio-forwarded-write-view-id", "external-client-view"),
            ("x-maxio-forwarded-write-hop-count", "1"),
        ],
    )
    .await;
    assert_eq!(put.status(), 200);

    let get = s3_request("GET", &format!("{}/{}/{}", base_url, bucket, key), vec![]).await;
    assert_eq!(get.status(), 200);
    assert_eq!(
        get.bytes().await.unwrap().as_ref(),
        b"auth-custom-header-payload"
    );
}

#[tokio::test]
async fn test_auth_rejects_internal_operation_headers_without_forwarded_by_marker() {
    let (base_url, _tmp) = start_server().await;
    let bucket = "auth-internal-operation-header-sanitization";
    let key = "docs/a.txt";

    let create = s3_request("PUT", &format!("{}/{}", base_url, bucket), vec![]).await;
    assert_eq!(create.status(), 200);

    let before_metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let before_total =
        metric_value(&before_metrics, "maxio_cluster_peer_auth_reject_total").unwrap_or(0.0);
    let before_reason = metric_labeled_value(
        &before_metrics,
        "maxio_cluster_peer_auth_reject_reason_total{reason=\"missing_or_malformed_forwarded_by\"}",
    )
    .unwrap_or(0.0);

    let put = s3_request_with_headers(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, key),
        b"auth-internal-header-payload".to_vec(),
        vec![
            (
                "x-maxio-internal-forwarded-write-operation",
                "replicate-put-object",
            ),
            (
                "x-maxio-internal-forwarded-write-idempotency-key",
                "spoofed-idempotency",
            ),
        ],
    )
    .await;
    assert_eq!(put.status(), 200);

    let get = s3_request("GET", &format!("{}/{}/{}", base_url, bucket, key), vec![]).await;
    assert_eq!(get.status(), 200);
    assert_eq!(
        get.bytes().await.unwrap().as_ref(),
        b"auth-internal-header-payload"
    );

    let after_metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let after_total =
        metric_value(&after_metrics, "maxio_cluster_peer_auth_reject_total").unwrap_or(0.0);
    let after_reason = metric_labeled_value(
        &after_metrics,
        "maxio_cluster_peer_auth_reject_reason_total{reason=\"missing_or_malformed_forwarded_by\"}",
    )
    .unwrap_or(0.0);

    assert!(
        after_total >= before_total + 1.0,
        "expected reject_total to increase for spoofed internal operation header"
    );
    assert!(
        after_reason >= before_reason + 1.0,
        "expected missing_or_malformed_forwarded_by reason counter to increase"
    );
}

#[tokio::test]
async fn test_auth_internal_header_trust_uses_live_runtime_membership_peers() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["peer-a.internal:9000".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let before_metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let before_allowlist_rejects = metric_labeled_value(
        &before_metrics,
        "maxio_cluster_peer_auth_reject_reason_total{reason=\"sender_not_in_allowlist\"}",
    )
    .unwrap_or(0.0);

    let get_untrusted_sender = s3_request_with_headers(
        "GET",
        &format!("{}/", base_url),
        Vec::new(),
        vec![
            ("x-maxio-forwarded-by", "peer-b.internal:9000"),
            ("x-maxio-internal-auth-token", "shared-secret"),
            (
                "x-maxio-internal-forwarded-write-operation",
                "replicate-put-object",
            ),
        ],
    )
    .await;
    assert_eq!(get_untrusted_sender.status(), 200);

    let after_untrusted_metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let after_untrusted_allowlist_rejects = metric_labeled_value(
        &after_untrusted_metrics,
        "maxio_cluster_peer_auth_reject_reason_total{reason=\"sender_not_in_allowlist\"}",
    )
    .unwrap_or(0.0);
    assert!(
        after_untrusted_allowlist_rejects >= before_allowlist_rejects + 1.0,
        "expected sender_not_in_allowlist to increment before live membership update"
    );

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    let cluster_id = health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present");

    let membership_update = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "peer-control.internal:9000")
        .header("x-maxio-forwarded-by", "peer-a.internal:9000")
        .header(
            "x-maxio-join-unix-ms",
            chrono::Utc::now().timestamp_millis().to_string(),
        )
        .header("x-maxio-join-nonce", "auth-live-membership-update-1")
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": ["peer-b.internal:9000"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(membership_update.status(), 200);

    let get_trusted_sender = s3_request_with_headers(
        "GET",
        &format!("{}/", base_url),
        Vec::new(),
        vec![
            ("x-maxio-forwarded-by", "peer-b.internal:9000"),
            ("x-maxio-internal-auth-token", "shared-secret"),
            (
                "x-maxio-internal-forwarded-write-operation",
                "replicate-put-object",
            ),
        ],
    )
    .await;
    assert_eq!(get_trusted_sender.status(), 200);

    let after_trusted_metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let after_trusted_allowlist_rejects = metric_labeled_value(
        &after_trusted_metrics,
        "maxio_cluster_peer_auth_reject_reason_total{reason=\"sender_not_in_allowlist\"}",
    )
    .unwrap_or(0.0);
    assert_eq!(
        after_trusted_allowlist_rejects, after_untrusted_allowlist_rejects,
        "expected sender_not_in_allowlist to stop increasing after live membership update"
    );
}

#[tokio::test]
async fn test_auth_rejects_multiple_authorization_headers() {
    let (base_url, _tmp) = start_server().await;
    let url = format!("{}/", base_url);

    let mut headers = Vec::new();
    sign_request("GET", &url, &mut headers, &[]);

    let mut req = client().get(&url);
    for (name, value) in &headers {
        req = req.header(name, value);
    }
    req = req.header("authorization", "AWS4-HMAC-SHA256 garbage");

    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("Multiple Authorization headers are not allowed"));
}

#[tokio::test]
async fn test_auth_rejects_invalid_credential_scope_service() {
    let (base_url, _tmp) = start_server().await;
    let url = format!("{}/", base_url);
    let mut headers = Vec::new();
    sign_request("GET", &url, &mut headers, &[]);

    for (name, value) in &mut headers {
        if name == "authorization" {
            *value = value.replace("/s3/aws4_request", "/ec2/aws4_request");
        }
    }

    let mut req = client().get(&url);
    for (name, value) in &headers {
        req = req.header(name, value);
    }

    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>AccessDenied</Code>"));
}

#[tokio::test]
async fn test_auth_accepts_secondary_configured_credentials() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let config = make_test_config_with_secondary_credential(data_dir, false, 10 * 1024 * 1024, 0);
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let resp = s3_request_with_credentials(
        "GET",
        &format!("{}/", base_url),
        vec![],
        SECONDARY_ACCESS_KEY,
        SECONDARY_SECRET_KEY,
    )
    .await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_auth_credential_matrix_primary_secondary_and_unknown() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let config = make_test_config_with_secondary_credential(data_dir, false, 10 * 1024 * 1024, 0);
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let primary = s3_request_with_credentials(
        "GET",
        &format!("{}/", base_url),
        vec![],
        ACCESS_KEY,
        SECRET_KEY,
    )
    .await;
    assert_eq!(primary.status(), 200);

    let secondary = s3_request_with_credentials(
        "GET",
        &format!("{}/", base_url),
        vec![],
        SECONDARY_ACCESS_KEY,
        SECONDARY_SECRET_KEY,
    )
    .await;
    assert_eq!(secondary.status(), 200);

    let unknown = s3_request_with_credentials(
        "GET",
        &format!("{}/", base_url),
        vec![],
        "unknown-access",
        "unknown-secret",
    )
    .await;
    assert_eq!(unknown.status(), 403);
}

#[tokio::test]
async fn test_presigned_rejects_invalid_credential_scope_service() {
    let (base_url, _tmp) = start_server().await;
    let presigned = presign_url(&base_url, "GET", "/", 300);
    let invalid_scope = presigned.replace("%2Fs3%2Faws4_request", "%2Fec2%2Faws4_request");

    let resp = client().get(&invalid_scope).send().await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>AccessDenied</Code>"));
}

#[tokio::test]
async fn test_presigned_rejects_multiple_authorization_headers() {
    let (base_url, _tmp) = start_server().await;
    let presigned = presign_url(&base_url, "GET", "/", 300);

    let resp = client()
        .get(&presigned)
        .header("authorization", "AWS4-HMAC-SHA256 foo")
        .header("authorization", "AWS4-HMAC-SHA256 bar")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("Multiple Authorization headers are not allowed"));
}

#[tokio::test]
async fn test_auth_compact_header_no_spaces() {
    // mc sends Authorization header with commas but no spaces:
    // Credential=...,SignedHeaders=...,Signature=...
    let (base_url, _tmp) = start_server().await;

    let resp = s3_request_compact("GET", &format!("{}/", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);

    // Also test PUT bucket with compact header
    let resp = s3_request_compact("PUT", &format!("{}/compact-bucket", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_auth_rejects_duplicate_authorization_components() {
    let (base_url, _tmp) = start_server().await;
    let url = format!("{}/", base_url);

    let mut headers = Vec::new();
    sign_request("GET", &url, &mut headers, &[]);

    let mut saw_auth = false;
    for (name, value) in &mut headers {
        if name == "authorization" {
            value.push_str(", Signature=deadbeef");
            saw_auth = true;
        }
    }
    assert!(
        saw_auth,
        "signed request should include authorization header"
    );

    let mut req = client().get(&url);
    for (name, value) in &headers {
        req = req.header(name, value);
    }

    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("Duplicate Signature"));
}

#[tokio::test]
async fn test_auth_rejects_unknown_authorization_component() {
    let (base_url, _tmp) = start_server().await;
    let url = format!("{}/", base_url);

    let mut headers = Vec::new();
    sign_request("GET", &url, &mut headers, &[]);

    let mut saw_auth = false;
    for (name, value) in &mut headers {
        if name == "authorization" {
            value.push_str(", Foo=bar");
            saw_auth = true;
        }
    }
    assert!(
        saw_auth,
        "signed request should include authorization header"
    );

    let mut req = client().get(&url);
    for (name, value) in &headers {
        req = req.header(name, value);
    }

    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("Invalid auth component"));
}

#[tokio::test]
async fn test_auth_rejects_signed_headers_without_host() {
    let (base_url, _tmp) = start_server().await;
    let url = format!("{}/", base_url);

    let mut headers = Vec::new();
    sign_request("GET", &url, &mut headers, &[]);

    let mut saw_auth = false;
    for (name, value) in &mut headers {
        if name == "authorization" {
            *value = value.replace(
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date",
                "SignedHeaders=x-amz-date",
            );
            saw_auth = true;
        }
    }
    assert!(
        saw_auth,
        "signed request should include authorization header"
    );

    let mut req = client().get(&url);
    for (name, value) in &headers {
        req = req.header(name, value);
    }

    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("SignedHeaders must include host"));
}

#[tokio::test]
async fn test_auth_rejects_duplicate_signed_headers_entries() {
    let (base_url, _tmp) = start_server().await;
    let url = format!("{}/", base_url);

    let mut headers = Vec::new();
    sign_request("GET", &url, &mut headers, &[]);

    let mut saw_auth = false;
    for (name, value) in &mut headers {
        if name == "authorization" {
            *value = value.replace(
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date",
                "SignedHeaders=host;host",
            );
            saw_auth = true;
        }
    }
    assert!(
        saw_auth,
        "signed request should include authorization header"
    );

    let mut req = client().get(&url);
    for (name, value) in &headers {
        req = req.header(name, value);
    }

    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("Duplicate SignedHeaders entry"));
}

#[tokio::test]
async fn test_auth_rejects_signed_headers_with_invalid_token() {
    let (base_url, _tmp) = start_server().await;
    let url = format!("{}/", base_url);

    let mut headers = Vec::new();
    sign_request("GET", &url, &mut headers, &[]);

    let mut saw_auth = false;
    for (name, value) in &mut headers {
        if name == "authorization" {
            *value = value.replace(
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date",
                "SignedHeaders=host;bad header",
            );
            saw_auth = true;
        }
    }
    assert!(
        saw_auth,
        "signed request should include authorization header"
    );

    let mut req = client().get(&url);
    for (name, value) in &headers {
        req = req.header(name, value);
    }

    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("Invalid SignedHeaders"));
}

#[tokio::test]
async fn test_auth_rejects_missing_signed_header_value() {
    let (base_url, _tmp) = start_server().await;
    let url = format!("{}/", base_url);

    // Include an empty signed header during signature construction, then omit it
    // from the actual HTTP request.
    let mut headers = vec![("x-amz-meta-probe".to_string(), String::new())];
    sign_request("GET", &url, &mut headers, &[]);
    headers.retain(|(name, _)| name != "x-amz-meta-probe");

    let mut req = client().get(&url);
    for (name, value) in &headers {
        req = req.header(name, value);
    }

    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"));
}

/// Generate a presigned URL for the given method/path.
fn presign_url(base_url: &str, method: &str, path: &str, expires_secs: u64) -> String {
    presign_url_with_credentials(base_url, method, path, expires_secs, ACCESS_KEY, SECRET_KEY)
}

/// Generate a presigned URL with explicit access/secret credentials.
fn presign_url_with_credentials(
    base_url: &str,
    method: &str,
    path: &str,
    expires_secs: u64,
    access_key: &str,
    secret_key: &str,
) -> String {
    presign_url_with_credentials_at(
        base_url,
        method,
        path,
        expires_secs,
        access_key,
        secret_key,
        chrono::Utc::now(),
    )
}

fn presign_url_with_credentials_at(
    base_url: &str,
    method: &str,
    path: &str,
    expires_secs: u64,
    access_key: &str,
    secret_key: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    let parsed = reqwest::Url::parse(&format!("{}{}", base_url, path)).unwrap();
    let host = parsed.host_str().unwrap();
    let port = parsed.port().unwrap();
    let host_header = format!("{}:{}", host, port);

    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let credential = format!("{}/{}/{}/s3/aws4_request", access_key, date_stamp, REGION);

    let mut qs_params = vec![
        (
            "X-Amz-Algorithm".to_string(),
            "AWS4-HMAC-SHA256".to_string(),
        ),
        ("X-Amz-Credential".to_string(), credential.clone()),
        ("X-Amz-Date".to_string(), amz_date.clone()),
        ("X-Amz-Expires".to_string(), expires_secs.to_string()),
        ("X-Amz-SignedHeaders".to_string(), "host".to_string()),
    ];
    qs_params.sort();

    let canonical_qs: String = qs_params
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode_s3(k), percent_encode_s3(v)))
        .collect::<Vec<_>>()
        .join("&");

    let canonical_headers = format!("host:{}\n", host_header);
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\nhost\nUNSIGNED-PAYLOAD",
        method, path, canonical_qs, canonical_headers
    );

    let scope = format!("{}/{}/s3/aws4_request", date_stamp, REGION);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date,
        scope,
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    let key = format!("AWS4{}", secret_key);
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

    format!(
        "{}{}?{}&X-Amz-Signature={}",
        base_url, path, canonical_qs, signature
    )
}

fn presign_url_with_missing_signed_header(
    base_url: &str,
    method: &str,
    path: &str,
    expires_secs: u64,
) -> String {
    let parsed = reqwest::Url::parse(&format!("{}{}", base_url, path)).unwrap();
    let host = parsed.host_str().unwrap();
    let port = parsed.port().unwrap();
    let host_header = format!("{}:{}", host, port);

    let now = chrono::Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let credential = format!("{}/{}/{}/s3/aws4_request", ACCESS_KEY, date_stamp, REGION);
    let signed_headers = "host;x-amz-meta-probe";

    let mut qs_params = vec![
        (
            "X-Amz-Algorithm".to_string(),
            "AWS4-HMAC-SHA256".to_string(),
        ),
        ("X-Amz-Credential".to_string(), credential.clone()),
        ("X-Amz-Date".to_string(), amz_date.clone()),
        ("X-Amz-Expires".to_string(), expires_secs.to_string()),
        (
            "X-Amz-SignedHeaders".to_string(),
            signed_headers.to_string(),
        ),
    ];
    qs_params.sort();

    let canonical_qs: String = qs_params
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode_s3(k), percent_encode_s3(v)))
        .collect::<Vec<_>>()
        .join("&");

    let canonical_request = format!(
        "{}\n{}\n{}\nhost:{}\nx-amz-meta-probe:\n\n{}\nUNSIGNED-PAYLOAD",
        method, path, canonical_qs, host_header, signed_headers
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

    format!(
        "{}{}?{}&X-Amz-Signature={}",
        base_url, path, canonical_qs, signature
    )
}

fn percent_encode_s3(input: &str) -> String {
    const S3_URI_ENCODE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~');
    percent_encoding::utf8_percent_encode(input, S3_URI_ENCODE).to_string()
}

#[tokio::test]
async fn test_presigned_get_object() {
    let (base_url, _tmp) = start_server().await;

    let url = format!("{}/presign-bucket", base_url);
    s3_request("PUT", &url, vec![]).await;

    let body = b"presigned test content";
    let url = format!("{}/presign-bucket/test.txt", base_url);
    s3_request("PUT", &url, body.to_vec()).await;

    let presigned = presign_url(&base_url, "GET", "/presign-bucket/test.txt", 300);
    let resp = client().get(&presigned).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), body);
}

#[tokio::test]
async fn test_presigned_rejects_future_timestamp_skew() {
    let (base_url, _tmp) = start_server().await;

    let url = format!("{}/presign-skew-bucket", base_url);
    s3_request("PUT", &url, vec![]).await;

    let body = b"presigned skew test";
    let object_url = format!("{}/presign-skew-bucket/test.txt", base_url);
    s3_request("PUT", &object_url, body.to_vec()).await;

    let future = chrono::Utc::now() + chrono::Duration::minutes(20);
    let presigned = presign_url_with_credentials_at(
        &base_url,
        "GET",
        "/presign-skew-bucket/test.txt",
        300,
        ACCESS_KEY,
        SECRET_KEY,
        future,
    );

    let resp = client().get(&presigned).send().await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("RequestTimeTooSkewed"));
}

#[tokio::test]
async fn test_presigned_put_object() {
    let (base_url, _tmp) = start_server().await;

    let url = format!("{}/presign-put-bucket", base_url);
    s3_request("PUT", &url, vec![]).await;

    let presigned = presign_url(&base_url, "PUT", "/presign-put-bucket/uploaded.txt", 300);
    let body = b"uploaded via presigned PUT";
    let resp = client()
        .put(&presigned)
        .body(body.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let url = format!("{}/presign-put-bucket/uploaded.txt", base_url);
    let resp = s3_request("GET", &url, vec![]).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), body);
}

#[tokio::test]
async fn test_presigned_head_object() {
    let (base_url, _tmp) = start_server().await;

    let url = format!("{}/presign-head-bucket", base_url);
    s3_request("PUT", &url, vec![]).await;

    let url = format!("{}/presign-head-bucket/test.txt", base_url);
    s3_request("PUT", &url, b"head test".to_vec()).await;

    let presigned = presign_url(&base_url, "HEAD", "/presign-head-bucket/test.txt", 300);
    let resp = client().head(&presigned).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-length")
            .unwrap()
            .to_str()
            .unwrap(),
        "9"
    );
}

#[tokio::test]
async fn test_presigned_get_object_with_secondary_credentials() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let config = make_test_config_with_secondary_credential(data_dir, false, 10 * 1024 * 1024, 0);
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let bucket_url = format!("{}/presign-secondary-bucket", base_url);
    s3_request("PUT", &bucket_url, vec![]).await;

    let body = b"presigned secondary content";
    let object_url = format!("{}/presign-secondary-bucket/test.txt", base_url);
    s3_request("PUT", &object_url, body.to_vec()).await;

    let presigned = presign_url_with_credentials(
        &base_url,
        "GET",
        "/presign-secondary-bucket/test.txt",
        300,
        SECONDARY_ACCESS_KEY,
        SECONDARY_SECRET_KEY,
    );
    let resp = client().get(&presigned).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), body);
}

#[tokio::test]
async fn test_presigned_accepts_percent_encoded_signature_query_key() {
    let (base_url, _tmp) = start_server().await;

    let bucket_url = format!("{}/presign-encoded-sig-key-bucket", base_url);
    s3_request("PUT", &bucket_url, vec![]).await;
    let object_url = format!("{}/presign-encoded-sig-key-bucket/test.txt", base_url);
    let expected_body = b"encoded signature key";
    s3_request("PUT", &object_url, expected_body.to_vec()).await;

    let presigned = presign_url(
        &base_url,
        "GET",
        "/presign-encoded-sig-key-bucket/test.txt",
        300,
    );
    let encoded_signature_key = presigned.replacen("X-Amz-Signature=", "%58-Amz-Signature=", 1);

    let resp = client().get(&encoded_signature_key).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), expected_body);
}

#[tokio::test]
async fn test_presigned_rejects_missing_signed_header_value() {
    let (base_url, _tmp) = start_server().await;

    let bucket_url = format!("{}/presign-missing-header-bucket", base_url);
    s3_request("PUT", &bucket_url, vec![]).await;
    let object_url = format!("{}/presign-missing-header-bucket/test.txt", base_url);
    s3_request("PUT", &object_url, b"data".to_vec()).await;

    let presigned = presign_url_with_missing_signed_header(
        &base_url,
        "GET",
        "/presign-missing-header-bucket/test.txt",
        300,
    );

    let resp = client().get(&presigned).send().await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"));
}

#[tokio::test]
async fn test_presigned_rejects_unknown_access_key() {
    let (base_url, _tmp) = start_server().await;

    let bucket_url = format!("{}/presign-unknown-key-bucket", base_url);
    s3_request("PUT", &bucket_url, vec![]).await;

    let object_url = format!("{}/presign-unknown-key-bucket/test.txt", base_url);
    s3_request("PUT", &object_url, b"data".to_vec()).await;

    let presigned = presign_url_with_credentials(
        &base_url,
        "GET",
        "/presign-unknown-key-bucket/test.txt",
        300,
        "unknown-access-key",
        "unknown-secret-key",
    );

    let resp = client().get(&presigned).send().await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>InvalidAccessKeyId</Code>"));
}

#[tokio::test]
async fn test_presigned_rejects_zero_expires() {
    let (base_url, _tmp) = start_server().await;

    let bucket_url = format!("{}/presign-zero-expires-bucket", base_url);
    s3_request("PUT", &bucket_url, vec![]).await;
    let object_url = format!("{}/presign-zero-expires-bucket/test.txt", base_url);
    s3_request("PUT", &object_url, b"data".to_vec()).await;

    let presigned = presign_url(&base_url, "GET", "/presign-zero-expires-bucket/test.txt", 0);

    let resp = client().get(&presigned).send().await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("X-Amz-Expires must be greater than 0 seconds"));
}

#[tokio::test]
async fn test_presigned_expired_url() {
    let (base_url, _tmp) = start_server().await;

    let url = format!("{}/presign-expire-bucket", base_url);
    s3_request("PUT", &url, vec![]).await;
    let url = format!("{}/presign-expire-bucket/test.txt", base_url);
    s3_request("PUT", &url, b"data".to_vec()).await;

    // Manually craft a presigned URL with a timestamp from 2 hours ago
    let parsed =
        reqwest::Url::parse(&format!("{}/presign-expire-bucket/test.txt", base_url)).unwrap();
    let host = parsed.host_str().unwrap();
    let port = parsed.port().unwrap();
    let host_header = format!("{}:{}", host, port);

    let past = chrono::Utc::now() - chrono::Duration::hours(2);
    let date_stamp = past.format("%Y%m%d").to_string();
    let amz_date = past.format("%Y%m%dT%H%M%SZ").to_string();
    let credential = format!("{}/{}/{}/s3/aws4_request", ACCESS_KEY, date_stamp, REGION);

    let mut qs_params = vec![
        (
            "X-Amz-Algorithm".to_string(),
            "AWS4-HMAC-SHA256".to_string(),
        ),
        ("X-Amz-Credential".to_string(), credential.clone()),
        ("X-Amz-Date".to_string(), amz_date.clone()),
        ("X-Amz-Expires".to_string(), "60".to_string()),
        ("X-Amz-SignedHeaders".to_string(), "host".to_string()),
    ];
    qs_params.sort();
    let canonical_qs: String = qs_params
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode_s3(k), percent_encode_s3(v)))
        .collect::<Vec<_>>()
        .join("&");

    let canonical_request = format!(
        "GET\n/presign-expire-bucket/test.txt\n{}\nhost:{}\n\nhost\nUNSIGNED-PAYLOAD",
        canonical_qs, host_header
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

    let presigned = format!(
        "{}/presign-expire-bucket/test.txt?{}&X-Amz-Signature={}",
        base_url, canonical_qs, signature
    );

    let resp = client().get(&presigned).send().await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("Request has expired"));
}

#[tokio::test]
async fn test_presigned_bad_signature() {
    let (base_url, _tmp) = start_server().await;

    let url = format!("{}/presign-bad-sig-bucket", base_url);
    s3_request("PUT", &url, vec![]).await;

    let mut presigned = presign_url(&base_url, "GET", "/presign-bad-sig-bucket/test.txt", 300);
    let last = presigned.pop().unwrap();
    presigned.push(if last == 'a' { 'b' } else { 'a' });

    let resp = client().get(&presigned).send().await.unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_presigned_rejects_duplicate_auth_query_components() {
    let (base_url, _tmp) = start_server().await;

    let bucket_url = format!("{}/presign-duplicate-query-bucket", base_url);
    s3_request("PUT", &bucket_url, vec![]).await;
    let object_url = format!("{}/presign-duplicate-query-bucket/test.txt", base_url);
    s3_request("PUT", &object_url, b"data".to_vec()).await;

    let presigned = presign_url(
        &base_url,
        "GET",
        "/presign-duplicate-query-bucket/test.txt",
        300,
    );
    let duplicated = format!("{presigned}&X-Amz-Date=20260101T000000Z");

    let resp = client().get(&duplicated).send().await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("Duplicate X-Amz-Date"));
}

#[tokio::test]
async fn test_presigned_rejects_signed_headers_without_host() {
    let (base_url, _tmp) = start_server().await;

    let bucket_url = format!("{}/presign-missing-host-header-bucket", base_url);
    s3_request("PUT", &bucket_url, vec![]).await;
    let object_url = format!("{}/presign-missing-host-header-bucket/test.txt", base_url);
    s3_request("PUT", &object_url, b"data".to_vec()).await;

    let presigned = presign_url(
        &base_url,
        "GET",
        "/presign-missing-host-header-bucket/test.txt",
        300,
    );
    let mutated = presigned.replace("X-Amz-SignedHeaders=host", "X-Amz-SignedHeaders=x-amz-date");

    let resp = client().get(&mutated).send().await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("SignedHeaders must include host"));
}

#[tokio::test]
async fn test_presigned_rejects_duplicate_signed_headers_entries() {
    let (base_url, _tmp) = start_server().await;

    let bucket_url = format!("{}/presign-duplicate-signed-headers-bucket", base_url);
    s3_request("PUT", &bucket_url, vec![]).await;
    let object_url = format!(
        "{}/presign-duplicate-signed-headers-bucket/test.txt",
        base_url
    );
    s3_request("PUT", &object_url, b"data".to_vec()).await;

    let presigned = presign_url(
        &base_url,
        "GET",
        "/presign-duplicate-signed-headers-bucket/test.txt",
        300,
    );
    let mutated = presigned.replace(
        "X-Amz-SignedHeaders=host",
        "X-Amz-SignedHeaders=host%3Bhost",
    );

    let resp = client().get(&mutated).send().await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("Duplicate SignedHeaders entry"));
}

#[tokio::test]
async fn test_presigned_rejects_signed_headers_with_invalid_token() {
    let (base_url, _tmp) = start_server().await;

    let bucket_url = format!("{}/presign-invalid-signed-headers-bucket", base_url);
    s3_request("PUT", &bucket_url, vec![]).await;
    let object_url = format!(
        "{}/presign-invalid-signed-headers-bucket/test.txt",
        base_url
    );
    s3_request("PUT", &object_url, b"data".to_vec()).await;

    let presigned = presign_url(
        &base_url,
        "GET",
        "/presign-invalid-signed-headers-bucket/test.txt",
        300,
    );
    let mutated = presigned.replace(
        "X-Amz-SignedHeaders=host",
        "X-Amz-SignedHeaders=host%3Bbad%20header",
    );

    let resp = client().get(&mutated).send().await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("Invalid SignedHeaders"));
}
