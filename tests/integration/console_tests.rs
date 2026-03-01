use super::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[tokio::test]
async fn test_console_auth_login_check_logout_flow() {
    let (base_url, _tmp) = start_server().await;
    let client = client();

    // Not authenticated initially
    let resp = client
        .get(format!("{}/api/auth/check", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Login with valid credentials
    let resp = client
        .post(format!("{}/api/auth/login", base_url))
        .header("content-type", "application/json")
        .json(&serde_json::json!({
            "accessKey": ACCESS_KEY,
            "secretKey": SECRET_KEY
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let set_cookie = resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .expect("missing set-cookie")
        .to_string();
    assert!(set_cookie.contains("maxio_session="));
    assert!(set_cookie.contains("HttpOnly"));
    let login_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(login_body["ok"], true);
    assert_eq!(login_body["accessKey"], ACCESS_KEY);
    assert!(login_body["sessionIssuedAt"].as_i64().is_some());
    assert!(login_body["sessionExpiresAt"].as_i64().is_some());

    // Auth check with cookie should pass
    let resp = client
        .get(format!("{}/api/auth/check", base_url))
        .header("cookie", &set_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let check_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(check_body["ok"], true);
    assert_eq!(check_body["accessKey"], ACCESS_KEY);
    assert!(check_body["sessionIssuedAt"].as_i64().is_some());
    assert!(check_body["sessionExpiresAt"].as_i64().is_some());

    // Protected endpoint should succeed with cookie
    let resp = client
        .get(format!("{}/api/buckets", base_url))
        .header("cookie", &set_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Logout returns a clearing cookie
    let resp = client
        .post(format!("{}/api/auth/logout", base_url))
        .header("cookie", &set_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let logout_cookie = resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .expect("missing logout set-cookie");
    assert!(logout_cookie.contains("maxio_session="));
    assert!(logout_cookie.contains("Max-Age=0"));

    // No cookie means unauthenticated again
    let resp = client
        .get(format!("{}/api/auth/check", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_console_auth_secondary_credentials_login_flow() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let config = make_test_config_with_secondary_credential(data_dir, false, 10 * 1024 * 1024, 0);
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let client = client();

    let resp = client
        .post(format!("{}/api/auth/login", base_url))
        .header("content-type", "application/json")
        .json(&serde_json::json!({
            "accessKey": SECONDARY_ACCESS_KEY,
            "secretKey": SECONDARY_SECRET_KEY
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let set_cookie = resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .expect("missing set-cookie")
        .to_string();
    let login_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(login_body["ok"], true);
    assert_eq!(login_body["accessKey"], SECONDARY_ACCESS_KEY);
    assert!(login_body["sessionIssuedAt"].as_i64().is_some());
    assert!(login_body["sessionExpiresAt"].as_i64().is_some());

    let resp = client
        .get(format!("{}/api/auth/check", base_url))
        .header("cookie", &set_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let check_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(check_body["ok"], true);
    assert_eq!(check_body["accessKey"], SECONDARY_ACCESS_KEY);
    assert!(check_body["sessionIssuedAt"].as_i64().is_some());
    assert!(check_body["sessionExpiresAt"].as_i64().is_some());

    let resp = client
        .get(format!("{}/api/system/metrics", base_url))
        .header("cookie", &set_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_console_auth_credential_matrix_primary_secondary_and_unknown() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let config = make_test_config_with_secondary_credential(data_dir, false, 10 * 1024 * 1024, 0);
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let client = client();

    let primary = client
        .post(format!("{}/api/auth/login", base_url))
        .header("content-type", "application/json")
        .json(&serde_json::json!({
            "accessKey": ACCESS_KEY,
            "secretKey": SECRET_KEY
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(primary.status(), 200);

    let secondary = client
        .post(format!("{}/api/auth/login", base_url))
        .header("content-type", "application/json")
        .json(&serde_json::json!({
            "accessKey": SECONDARY_ACCESS_KEY,
            "secretKey": SECONDARY_SECRET_KEY
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(secondary.status(), 200);

    let unknown = client
        .post(format!("{}/api/auth/login", base_url))
        .header("content-type", "application/json")
        .json(&serde_json::json!({
            "accessKey": "unknown-access-key",
            "secretKey": SECRET_KEY
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 401);
}

#[tokio::test]
async fn test_console_auth_me_returns_authenticated_access_key() {
    let (base_url, _tmp) = start_server().await;
    let client = client();

    let unauthorized = client
        .get(format!("{}/api/auth/me", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), 401);

    let cookie = console_login_cookie(&base_url).await;
    let resp = client
        .get(format!("{}/api/auth/me", base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["accessKey"], ACCESS_KEY);
    assert!(body["sessionIssuedAt"].as_i64().is_some());
    assert!(body["sessionExpiresAt"].as_i64().is_some());
}

#[tokio::test]
async fn test_console_auth_me_supports_secondary_credentials() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let config = make_test_config_with_secondary_credential(data_dir, false, 10 * 1024 * 1024, 0);
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let client = client();

    let login = client
        .post(format!("{}/api/auth/login", base_url))
        .header("content-type", "application/json")
        .json(&serde_json::json!({
            "accessKey": SECONDARY_ACCESS_KEY,
            "secretKey": SECONDARY_SECRET_KEY
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), 200);
    let cookie = login
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .expect("missing set-cookie")
        .to_string();

    let resp = client
        .get(format!("{}/api/auth/me", base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["accessKey"], SECONDARY_ACCESS_KEY);
    assert!(body["sessionIssuedAt"].as_i64().is_some());
    assert!(body["sessionExpiresAt"].as_i64().is_some());
}

#[tokio::test]
async fn test_console_auth_invalid_credentials() {
    let (base_url, _tmp) = start_server().await;
    let resp = client()
        .post(format!("{}/api/auth/login", base_url))
        .header("content-type", "application/json")
        .json(&serde_json::json!({
            "accessKey": ACCESS_KEY,
            "secretKey": "wrong-secret"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_console_protected_route_requires_cookie() {
    let (base_url, _tmp) = start_server().await;
    let resp = client()
        .get(format!("{}/api/buckets", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_console_protected_route_rejects_tampered_cookie() {
    let (base_url, _tmp) = start_server().await;
    let valid_set_cookie = console_login_cookie(&base_url).await;
    let raw_cookie = valid_set_cookie
        .split(';')
        .next()
        .expect("set-cookie should include key=value")
        .to_string();

    let mut tampered = raw_cookie.into_bytes();
    if let Some(last) = tampered.last_mut() {
        *last = if *last == b'a' { b'b' } else { b'a' };
    }
    let tampered_cookie = String::from_utf8(tampered).expect("cookie should remain valid utf8");

    let resp = client()
        .get(format!("{}/api/buckets", base_url))
        .header("cookie", &tampered_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().is_some_and(|v| !v.is_empty()));
}

fn forge_console_session_cookie(access_key: &str, secret_key: &str, issued_at: i64) -> String {
    let issued_hex = format!("{:x}", issued_at);
    let mut mac =
        HmacSha256::new_from_slice(secret_key.as_bytes()).expect("HMAC can take key of any size");
    mac.update(format!("{access_key}:{issued_hex}").as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    format!("maxio_session={access_key}.{issued_hex}.{sig}")
}

#[tokio::test]
async fn test_console_protected_route_rejects_expired_cookie() {
    let (base_url, _tmp) = start_server().await;
    // TOKEN_MAX_AGE_SECS in auth middleware is 7 days.
    let issued_at = chrono::Utc::now().timestamp() - (8 * 24 * 60 * 60);
    let expired_cookie = forge_console_session_cookie(ACCESS_KEY, SECRET_KEY, issued_at);

    let resp = client()
        .get(format!("{}/api/buckets", base_url))
        .header("cookie", expired_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_console_protected_route_rejects_future_dated_cookie() {
    let (base_url, _tmp) = start_server().await;
    // Middleware allows max +60 seconds skew.
    let issued_at = chrono::Utc::now().timestamp() + 120;
    let future_cookie = forge_console_session_cookie(ACCESS_KEY, SECRET_KEY, issued_at);

    let resp = client()
        .get(format!("{}/api/buckets", base_url))
        .header("cookie", future_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_console_login_rate_limit_enforced() {
    let (base_url, _tmp) = start_server().await;
    let client = client();
    let mut last_status = reqwest::StatusCode::OK;
    let mut retry_after = None;

    for _ in 0..11 {
        let resp = client
            .post(format!("{}/api/auth/login", base_url))
            .header("content-type", "application/json")
            .json(&serde_json::json!({
                "accessKey": ACCESS_KEY,
                "secretKey": "wrong-secret"
            }))
            .send()
            .await
            .unwrap();
        last_status = resp.status();
        if let Some(v) = resp.headers().get("retry-after") {
            retry_after = v.to_str().ok().map(|s| s.to_string());
        }
    }

    assert_eq!(last_status, reqwest::StatusCode::TOO_MANY_REQUESTS);
    assert!(retry_after.is_some(), "expected Retry-After header");
}

async fn console_login_cookie(base_url: &str) -> String {
    let resp = client()
        .post(format!("{}/api/auth/login", base_url))
        .header("content-type", "application/json")
        .json(&serde_json::json!({
            "accessKey": ACCESS_KEY,
            "secretKey": SECRET_KEY
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    resp.headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .expect("missing set-cookie")
        .to_string()
}

#[tokio::test]
async fn test_console_presign_uses_authenticated_session_identity() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let config = make_test_config_with_secondary_credential(data_dir, false, 10 * 1024 * 1024, 0);
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let client = client();

    s3_request(
        "PUT",
        &format!("{}/presign-console-bucket", base_url),
        vec![],
    )
    .await;
    let object_body = b"console presign data".to_vec();
    s3_request(
        "PUT",
        &format!("{}/presign-console-bucket/reports/2026-03-01.txt", base_url),
        object_body.clone(),
    )
    .await;

    let login = client
        .post(format!("{}/api/auth/login", base_url))
        .header("content-type", "application/json")
        .json(&serde_json::json!({
            "accessKey": SECONDARY_ACCESS_KEY,
            "secretKey": SECONDARY_SECRET_KEY
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), 200);
    let cookie = login
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .expect("missing set-cookie")
        .to_string();

    let resp = client
        .get(format!(
            "{}/api/buckets/presign-console-bucket/presign/reports/2026-03-01.txt?expires=120",
            base_url
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["expiresIn"], 120);
    let presigned_url = body["url"]
        .as_str()
        .expect("console presign response should include url");

    let parsed = reqwest::Url::parse(presigned_url).unwrap();
    let credential = parsed
        .query_pairs()
        .find(|(k, _)| k == "X-Amz-Credential")
        .map(|(_, v)| v.into_owned())
        .expect("presigned url should include X-Amz-Credential");
    assert!(
        credential.starts_with(&format!("{}/", SECONDARY_ACCESS_KEY)),
        "credential should be signed with authenticated access key, got: {credential}"
    );

    let download = client.get(presigned_url).send().await.unwrap();
    assert_eq!(download.status(), 200);
    assert_eq!(
        download.bytes().await.unwrap().as_ref(),
        object_body.as_slice()
    );
}

#[tokio::test]
async fn test_console_lifecycle_roundtrip() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/lifecycle-bucket", base_url), vec![]).await;
    let cookie = console_login_cookie(&base_url).await;

    let resp = client()
        .get(format!(
            "{}/api/buckets/lifecycle-bucket/lifecycle",
            base_url
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["rules"], serde_json::json!([]));

    let resp = client()
        .put(format!(
            "{}/api/buckets/lifecycle-bucket/lifecycle",
            base_url
        ))
        .header("cookie", &cookie)
        .header("content-type", "application/json")
        .json(&serde_json::json!({
            "rules": [
                { "id": "expire-logs", "prefix": "logs/", "expirationDays": 7, "enabled": true }
            ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client()
        .get(format!(
            "{}/api/buckets/lifecycle-bucket/lifecycle",
            base_url
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["rules"][0]["id"], "expire-logs");
    assert_eq!(body["rules"][0]["prefix"], "logs/");
    assert_eq!(body["rules"][0]["expirationDays"], 7);
    assert_eq!(body["rules"][0]["enabled"], true);
}

#[tokio::test]
async fn test_console_lifecycle_rejects_invalid_rules() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/lifecycle-bucket", base_url), vec![]).await;
    let cookie = console_login_cookie(&base_url).await;

    let resp = client()
        .put(format!(
            "{}/api/buckets/lifecycle-bucket/lifecycle",
            base_url
        ))
        .header("cookie", &cookie)
        .header("content-type", "application/json")
        .json(&serde_json::json!({
            "rules": [
                { "id": "invalid", "prefix": "", "expirationDays": 0, "enabled": true }
            ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("expiration_days > 0")
    );
}

#[tokio::test]
async fn test_console_metrics_endpoint_requires_auth_and_returns_json() {
    let (base_url, _tmp) = start_server().await;

    let unauthorized = client()
        .get(format!("{}/api/system/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), 401);

    let cookie = console_login_cookie(&base_url).await;
    let authorized = client()
        .get(format!("{}/api/system/metrics", base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(authorized.status(), 200);

    let body: serde_json::Value = authorized.json().await.unwrap();
    assert!(body["requestsTotal"].as_u64().is_some());
    assert!(body["uptimeSeconds"].as_f64().is_some());
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["mode"], "standalone");
    assert!(body["nodeId"].as_str().is_some_and(|v| !v.is_empty()));
    assert_eq!(body["clusterPeerCount"], 0);
    assert_eq!(body["clusterPeers"], serde_json::json!([]));
}

#[tokio::test]
async fn test_console_metrics_endpoint_reports_distributed_mode_when_configured() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let cookie = console_login_cookie(&base_url).await;
    let response = client()
        .get(format!("{}/api/system/metrics", base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["mode"], "distributed");
    assert_eq!(body["clusterPeerCount"], 1);
    assert_eq!(
        body["clusterPeers"],
        serde_json::json!(["node-b.internal:9000"])
    );
}

#[tokio::test]
async fn test_console_health_endpoint_requires_auth_and_returns_json() {
    let (base_url, _tmp) = start_server().await;

    let unauthorized = client()
        .get(format!("{}/api/system/health", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), 401);

    let cookie = console_login_cookie(&base_url).await;
    let authorized = client()
        .get(format!("{}/api/system/health", base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(authorized.status(), 200);

    let body: serde_json::Value = authorized.json().await.unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert!(body["uptimeSeconds"].as_f64().is_some());
    assert_eq!(body["mode"], "standalone");
    assert!(body["nodeId"].as_str().is_some_and(|v| !v.is_empty()));
    assert_eq!(body["clusterPeerCount"], 0);
    assert_eq!(body["clusterPeers"], serde_json::json!([]));
}

#[tokio::test]
async fn test_console_health_endpoint_reports_distributed_mode_when_configured() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let cookie = console_login_cookie(&base_url).await;
    let response = client()
        .get(format!("{}/api/system/health", base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["mode"], "distributed");
    assert_eq!(body["clusterPeerCount"], 1);
    assert_eq!(
        body["clusterPeers"],
        serde_json::json!(["node-b.internal:9000"])
    );
}

#[tokio::test]
async fn test_console_topology_endpoint_requires_auth_and_returns_json() {
    let (base_url, _tmp) = start_server().await;

    let unauthorized = client()
        .get(format!("{}/api/system/topology", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), 401);

    let cookie = console_login_cookie(&base_url).await;
    let authorized = client()
        .get(format!("{}/api/system/topology", base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(authorized.status(), 200);

    let body: serde_json::Value = authorized.json().await.unwrap();
    assert_eq!(body["mode"], "standalone");
    assert!(body["nodeId"].as_str().is_some_and(|v| !v.is_empty()));
    assert_eq!(body["clusterPeerCount"], 0);
    assert_eq!(body["clusterPeers"], serde_json::json!([]));
}

#[tokio::test]
async fn test_console_topology_endpoint_reports_distributed_mode_when_configured() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let cookie = console_login_cookie(&base_url).await;
    let response = client()
        .get(format!("{}/api/system/topology", base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["mode"], "distributed");
    assert_eq!(body["clusterPeerCount"], 1);
    assert_eq!(
        body["clusterPeers"],
        serde_json::json!(["node-b.internal:9000"])
    );
}

#[tokio::test]
async fn test_console_buckets_and_objects_json_contract_shapes() {
    let (base_url, _tmp) = start_server().await;
    let cookie = console_login_cookie(&base_url).await;
    let http = client();

    let create_bucket = http
        .post(format!("{}/api/buckets", base_url))
        .header("cookie", &cookie)
        .header("content-type", "application/json")
        .json(&serde_json::json!({ "name": "contract-bucket" }))
        .send()
        .await
        .unwrap();
    assert_eq!(create_bucket.status(), 200);
    let create_bucket_body: serde_json::Value = create_bucket.json().await.unwrap();
    assert_eq!(create_bucket_body, serde_json::json!({ "ok": true }));

    let list_buckets = http
        .get(format!("{}/api/buckets", base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(list_buckets.status(), 200);
    let list_buckets_body: serde_json::Value = list_buckets.json().await.unwrap();
    let buckets = list_buckets_body["buckets"]
        .as_array()
        .expect("buckets should be an array");
    let bucket = buckets
        .iter()
        .find(|bucket| bucket["name"] == "contract-bucket")
        .expect("missing contract-bucket in list");
    assert!(bucket["createdAt"].as_str().is_some_and(|v| !v.is_empty()));
    assert_eq!(bucket["versioning"], false);

    let create_folder = http
        .post(format!("{}/api/buckets/contract-bucket/folders", base_url))
        .header("cookie", &cookie)
        .header("content-type", "application/json")
        .json(&serde_json::json!({ "name": "docs" }))
        .send()
        .await
        .unwrap();
    assert_eq!(create_folder.status(), 200);
    let create_folder_body: serde_json::Value = create_folder.json().await.unwrap();
    assert_eq!(create_folder_body, serde_json::json!({ "ok": true }));

    let upload = http
        .put(format!(
            "{}/api/buckets/contract-bucket/upload/docs/readme.txt",
            base_url
        ))
        .header("cookie", &cookie)
        .header("content-type", "text/plain")
        .body("hello console contract")
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), 200);
    let upload_body: serde_json::Value = upload.json().await.unwrap();
    assert_eq!(upload_body["ok"], true);
    assert!(upload_body["etag"].as_str().is_some_and(|v| !v.is_empty()));
    assert_eq!(upload_body["size"], 22);

    let list_objects = http
        .get(format!(
            "{}/api/buckets/contract-bucket/objects?prefix=docs/&delimiter=/",
            base_url
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(list_objects.status(), 200);
    let list_objects_body: serde_json::Value = list_objects.json().await.unwrap();
    let files = list_objects_body["files"]
        .as_array()
        .expect("files should be an array");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["key"], "docs/readme.txt");
    assert_eq!(files[0]["size"], 22);
    assert!(files[0]["etag"].as_str().is_some_and(|v| !v.is_empty()));
    assert!(
        files[0]["lastModified"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );
    let prefixes = list_objects_body["prefixes"]
        .as_array()
        .expect("prefixes should be an array");
    assert!(prefixes.is_empty());
    let empty_prefixes = list_objects_body["emptyPrefixes"]
        .as_array()
        .expect("emptyPrefixes should be an array");
    assert!(empty_prefixes.is_empty());
}

#[tokio::test]
async fn test_console_error_contract_shape_for_auth_failures() {
    let (base_url, _tmp) = start_server().await;
    let http = client();

    let invalid_login = http
        .post(format!("{}/api/auth/login", base_url))
        .header("content-type", "application/json")
        .json(&serde_json::json!({
            "accessKey": ACCESS_KEY,
            "secretKey": "definitely-wrong"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(invalid_login.status(), 401);
    let invalid_login_body: serde_json::Value = invalid_login.json().await.unwrap();
    assert!(
        invalid_login_body["error"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );

    let protected_without_cookie = http
        .get(format!("{}/api/buckets", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(protected_without_cookie.status(), 401);
    let protected_without_cookie_body: serde_json::Value =
        protected_without_cookie.json().await.unwrap();
    assert!(
        protected_without_cookie_body["error"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );
}
