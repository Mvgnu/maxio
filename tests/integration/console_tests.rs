use super::*;
use hmac::{Hmac, Mac};
use maxio::metadata::{
    BucketMetadataState, BucketMetadataTombstoneState, ClusterMetadataListingStrategy,
    ObjectMetadataState, ObjectVersionMetadataState,
};
use maxio::storage::placement::membership_view_id_with_self;
use sha2::Sha256;
use tempfile::TempDir;

type HmacSha256 = Hmac<Sha256>;

fn consensus_membership_view_id(node_id: &str, peers: &[String]) -> String {
    membership_view_id_with_self(node_id, peers)
}

fn assert_object_has_keys(value: &serde_json::Value, expected_keys: &[&str]) {
    let obj = value
        .as_object()
        .expect("expected JSON object for contract assertion");
    for key in expected_keys {
        assert!(
            obj.contains_key(*key),
            "expected contract key '{}' in object: {:?}",
            key,
            obj.keys().collect::<Vec<_>>()
        );
    }
}

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

#[tokio::test]
async fn test_console_auth_check_rejects_tampered_cookie() {
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
        .get(format!("{}/api/auth/check", base_url))
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
async fn test_console_auth_me_rejects_expired_cookie() {
    let (base_url, _tmp) = start_server().await;
    // TOKEN_MAX_AGE_SECS in auth middleware is 7 days.
    let issued_at = chrono::Utc::now().timestamp() - (8 * 24 * 60 * 60);
    let expired_cookie = forge_console_session_cookie(ACCESS_KEY, SECRET_KEY, issued_at);

    let resp = client()
        .get(format!("{}/api/auth/me", base_url))
        .header("cookie", expired_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_console_auth_me_rejects_future_dated_cookie() {
    let (base_url, _tmp) = start_server().await;
    // Middleware allows max +60 seconds skew.
    let issued_at = chrono::Utc::now().timestamp() + 120;
    let future_cookie = forge_console_session_cookie(ACCESS_KEY, SECRET_KEY, issued_at);

    let resp = client()
        .get(format!("{}/api/auth/me", base_url))
        .header("cookie", future_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_console_auth_me_rejects_unknown_access_key_cookie() {
    let (base_url, _tmp) = start_server().await;
    let issued_at = chrono::Utc::now().timestamp();
    let unknown_cookie = forge_console_session_cookie("unknown-access-key", SECRET_KEY, issued_at);

    let resp = client()
        .get(format!("{}/api/auth/me", base_url))
        .header("cookie", unknown_cookie)
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

fn host_port_from_base_url(base_url: &str) -> String {
    let parsed = reqwest::Url::parse(base_url).expect("base url should parse");
    let host = parsed.host_str().expect("base url should have host");
    let port = parsed.port().expect("base url should have explicit port");
    format!("{host}:{port}")
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
async fn test_console_presign_encodes_object_keys_with_spaces_and_utf8() {
    let (base_url, _tmp) = start_server().await;
    let cookie = console_login_cookie(&base_url).await;

    let create_bucket = s3_request(
        "PUT",
        &format!("{}/presign-encoding-bucket", base_url),
        vec![],
    )
    .await;
    assert_eq!(create_bucket.status(), 200);

    let object_body = b"encoded-key-content".to_vec();
    let upload = client()
        .put(format!(
            "{}/api/buckets/presign-encoding-bucket/upload/reports/Jan%202026/%C3%A7a%2Bt.txt",
            base_url
        ))
        .header("cookie", &cookie)
        .header("content-type", "text/plain")
        .body(object_body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), 200);

    let resp = client()
        .get(format!(
            "{}/api/buckets/presign-encoding-bucket/presign/reports/Jan%202026/%C3%A7a%2Bt.txt",
            base_url
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let presigned_url = body["url"]
        .as_str()
        .expect("console presign response should include url");
    assert!(
        presigned_url.contains("/reports/Jan%202026/%C3%A7a%2Bt.txt"),
        "presigned URL path should remain percent-encoded: {presigned_url}"
    );

    let download = client().get(presigned_url).send().await.unwrap();
    assert_eq!(download.status(), 200);
    assert_eq!(
        download.bytes().await.unwrap().as_ref(),
        object_body.as_slice()
    );
}

#[tokio::test]
async fn test_console_presign_returns_not_found_for_missing_bucket() {
    let (base_url, _tmp) = start_server().await;
    let cookie = console_login_cookie(&base_url).await;

    let resp = client()
        .get(format!(
            "{}/api/buckets/missing-bucket/presign/reports/2026-03-01.txt",
            base_url
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "Bucket not found");
}

#[tokio::test]
async fn test_console_presign_returns_not_found_for_missing_object() {
    let (base_url, _tmp) = start_server().await;
    s3_request(
        "PUT",
        &format!("{}/presign-missing-object", base_url),
        vec![],
    )
    .await;
    let cookie = console_login_cookie(&base_url).await;

    let resp = client()
        .get(format!(
            "{}/api/buckets/presign-missing-object/presign/reports/does-not-exist.txt",
            base_url
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "Object not found");
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
    assert_eq!(body["membershipProtocol"], "static-bootstrap");
    assert_eq!(body["membershipProtocolReady"], true);
    assert_eq!(body["membershipConverged"], true);
    assert_eq!(body["membershipConvergenceReason"], "not-required");
}

#[tokio::test]
async fn test_console_metrics_endpoint_reports_distributed_mode_when_configured() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    config.membership_protocol = maxio::config::MembershipProtocol::Gossip;
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
    assert_eq!(body["membershipProtocol"], "gossip");
    assert_eq!(body["membershipProtocolReady"], true);
    assert_eq!(body["membershipConverged"], false);
    assert_eq!(
        body["membershipConvergenceReason"],
        "peer-connectivity-failed"
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
    assert_eq!(body["membershipProtocol"], "static-bootstrap");
    assert!(
        body["membershipViewId"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );
    assert_eq!(body["placementEpoch"], 0);
}

#[tokio::test]
async fn test_console_health_endpoint_reports_distributed_mode_when_configured() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["127.0.0.1:1".to_string()];
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
    assert_eq!(body["ok"], false);
    assert_eq!(body["status"], "degraded");
    assert_eq!(body["mode"], "distributed");
    assert_eq!(body["clusterPeerCount"], 1);
    assert_eq!(body["clusterPeers"], serde_json::json!(["127.0.0.1:1"]));
    assert_eq!(body["membershipProtocol"], "static-bootstrap");
    assert!(
        body["membershipViewId"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );
    assert_eq!(body["placementEpoch"], 0);
    assert_eq!(body["checks"]["peerConnectivityReady"], false);
}

#[tokio::test]
async fn test_console_health_endpoint_reports_degraded_when_storage_data_path_probe_fails() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let config = make_test_config(data_dir.clone(), false, 10 * 1024 * 1024, 0);
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let buckets_dir = std::path::Path::new(&data_dir).join("buckets");
    tokio::fs::remove_dir_all(&buckets_dir)
        .await
        .expect("remove buckets directory");

    let cookie = console_login_cookie(&base_url).await;
    let response = client()
        .get(format!("{}/api/system/health", base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["status"], "degraded");
    assert_eq!(body["checks"]["storageDataPathReadable"], false);
    assert_eq!(body["checks"]["diskHeadroomSufficient"], true);
    assert_eq!(body["checks"]["peerConnectivityReady"], true);
    assert!(
        body["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.iter().any(|entry| {
                entry
                    .as_str()
                    .is_some_and(|msg| msg.contains("Storage data-path probe failed"))
            }))
    );
}

#[tokio::test]
async fn test_console_health_endpoint_reports_degraded_when_disk_headroom_threshold_not_met() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.min_disk_headroom_bytes = u64::MAX;
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
    assert_eq!(body["ok"], false);
    assert_eq!(body["status"], "degraded");
    assert_eq!(body["checks"]["storageDataPathReadable"], true);
    assert_eq!(body["checks"]["diskHeadroomSufficient"], false);
    assert!(
        body["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.iter().any(|entry| {
                entry
                    .as_str()
                    .is_some_and(|msg| msg.contains("Disk headroom below threshold"))
            }))
    );
}

#[tokio::test]
async fn test_console_health_endpoint_reports_degraded_when_cluster_peers_include_local_node_id() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = "127.0.0.1:1".to_string();
    config.cluster_peers = vec!["127.0.0.1:1".to_string()];
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
    assert_eq!(body["ok"], false);
    assert_eq!(body["status"], "degraded");
    assert_eq!(body["checks"]["membershipProtocolReady"], true);
    assert_eq!(body["checks"]["peerConnectivityReady"], false);
    assert!(
        body["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.iter().any(|entry| {
                entry
                    .as_str()
                    .is_some_and(|msg| msg.contains("includes local node id"))
            }))
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
    assert_eq!(body["membershipProtocol"], "static-bootstrap");
    assert_eq!(body["placementEpoch"], 0);
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
    assert_eq!(body["membershipProtocol"], "static-bootstrap");
    assert_eq!(body["placementEpoch"], 0);
}

#[tokio::test]
async fn test_console_membership_endpoint_requires_auth_and_returns_json() {
    let (base_url, _tmp) = start_server().await;

    let unauthorized = client()
        .get(format!("{}/api/system/membership", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), 401);

    let cookie = console_login_cookie(&base_url).await;
    let authorized = client()
        .get(format!("{}/api/system/membership", base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(authorized.status(), 200);

    let body: serde_json::Value = authorized.json().await.unwrap();
    assert_eq!(body["mode"], "standalone");
    assert_eq!(body["protocol"], "static-bootstrap");
    assert!(body["viewId"].as_str().is_some_and(|v| !v.is_empty()));
    assert!(body["leaderNodeId"].as_str().is_some_and(|v| !v.is_empty()));
    assert!(
        body["coordinatorNodeId"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );
    let nodes = body["nodes"]
        .as_array()
        .expect("membership response should include nodes array");
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0]["role"], "self");
    assert_eq!(nodes[0]["status"], "alive");
}

#[tokio::test]
async fn test_console_membership_endpoint_reports_distributed_mode_when_configured() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let cookie = console_login_cookie(&base_url).await;
    let response = client()
        .get(format!("{}/api/system/membership", base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["mode"], "distributed");
    assert_eq!(body["protocol"], "static-bootstrap");
    assert!(body["viewId"].as_str().is_some_and(|v| !v.is_empty()));
    assert_eq!(body["leaderNodeId"], serde_json::Value::Null);
    assert!(
        body["coordinatorNodeId"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );

    let nodes = body["nodes"]
        .as_array()
        .expect("membership response should include nodes array");
    assert_eq!(nodes.len(), 2);
    assert!(
        nodes
            .iter()
            .any(|node| node["nodeId"] == "node-b.internal:9000"
                && node["role"] == "peer"
                && node["status"] == "configured")
    );
    assert!(
        nodes
            .iter()
            .any(|node| node["role"] == "self" && node["status"] == "alive")
    );
}

#[tokio::test]
async fn test_console_placement_endpoint_requires_auth_and_returns_json() {
    let (base_url, _tmp) = start_server().await;

    let unauthorized = client()
        .get(format!(
            "{}/api/system/placement?key=docs/readme.txt",
            base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), 401);

    let cookie = console_login_cookie(&base_url).await;
    let authorized = client()
        .get(format!(
            "{}/api/system/placement?key=docs/readme.txt&replicaCount=2",
            base_url
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(authorized.status(), 200);

    let body: serde_json::Value = authorized.json().await.unwrap();
    assert_eq!(body["key"], "docs/readme.txt");
    assert_eq!(body["chunkIndex"], serde_json::Value::Null);
    assert_eq!(body["replicaCountRequested"], 2);
    assert_eq!(body["replicaCountApplied"], 1);
    assert_eq!(body["mode"], "standalone");
    assert_eq!(body["clusterPeerCount"], 0);
    assert_eq!(body["clusterPeers"], serde_json::json!([]));
    assert_eq!(body["membershipProtocol"], "static-bootstrap");
    assert!(body["nodeId"].as_str().is_some_and(|v| !v.is_empty()));
    assert!(
        body["membershipViewId"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );
    assert_eq!(body["owners"].as_array().map(Vec::len), Some(1));
    assert_eq!(body["primaryOwner"], body["nodeId"]);
    assert_eq!(body["forwardTarget"], serde_json::Value::Null);
    assert_eq!(body["isLocalPrimaryOwner"], true);
    assert_eq!(body["isLocalReplicaOwner"], true);
    assert_eq!(body["writeQuorumSize"], 1);
    assert_eq!(body["writeAckPolicy"], "majority");
    assert_eq!(body["nonOwnerMutationPolicy"], "forward-single-write");
    assert_eq!(body["nonOwnerReadPolicy"], "execute-local");
    assert_eq!(body["nonOwnerBatchMutationPolicy"], "execute-local");
    assert_eq!(body["mixedOwnerBatchMutationPolicy"], "execute-local");
    assert_eq!(
        body["replicaFanoutOperations"],
        serde_json::json!([
            "put-object",
            "copy-object",
            "delete-object",
            "delete-object-version",
            "complete-multipart-upload"
        ])
    );
    assert_eq!(
        body["pendingReplicaFanoutOperations"],
        serde_json::json!([])
    );
}

#[tokio::test]
async fn test_console_placement_endpoint_reports_distributed_chunk_owners() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let cookie = console_login_cookie(&base_url).await;
    let response = client()
        .get(format!(
            "{}/api/system/placement?key=videos/movie.mp4&chunkIndex=3&replicaCount=2",
            base_url
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["mode"], "distributed");
    assert_eq!(body["key"], "videos/movie.mp4");
    assert_eq!(body["chunkIndex"], 3);
    assert_eq!(body["replicaCountRequested"], 2);
    assert_eq!(body["replicaCountApplied"], 2);
    assert_eq!(body["writeQuorumSize"], 2);
    assert_eq!(body["writeAckPolicy"], "majority");
    assert_eq!(body["nonOwnerMutationPolicy"], "forward-single-write");
    assert_eq!(body["nonOwnerReadPolicy"], "forward-single-read");
    assert_eq!(
        body["nonOwnerBatchMutationPolicy"],
        "forward-multi-target-batch"
    );
    assert_eq!(
        body["mixedOwnerBatchMutationPolicy"],
        "forward-mixed-owner-batch"
    );
    assert_eq!(
        body["replicaFanoutOperations"],
        serde_json::json!([
            "put-object",
            "copy-object",
            "delete-object",
            "delete-object-version",
            "complete-multipart-upload"
        ])
    );
    assert_eq!(
        body["pendingReplicaFanoutOperations"],
        serde_json::json!([])
    );
    assert_eq!(body["clusterPeerCount"], 1);
    assert_eq!(
        body["clusterPeers"],
        serde_json::json!(["node-b.internal:9000"])
    );
    assert_eq!(body["membershipProtocol"], "static-bootstrap");
    assert!(
        body["membershipViewId"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );
    let owners = body["owners"]
        .as_array()
        .expect("placement response should include owners array");
    assert_eq!(owners.len(), 2);
    assert!(
        owners
            .iter()
            .any(|owner| owner.as_str() == Some("node-b.internal:9000"))
    );
    let primary_owner = body["primaryOwner"]
        .as_str()
        .expect("placement response should include primary owner");
    assert!(
        owners
            .iter()
            .any(|owner| owner.as_str() == Some(primary_owner))
    );

    let node_id = body["nodeId"]
        .as_str()
        .expect("placement response should include node id");
    let is_local_primary = body["isLocalPrimaryOwner"]
        .as_bool()
        .expect("placement response should include local primary flag");
    let is_local_replica = body["isLocalReplicaOwner"]
        .as_bool()
        .expect("placement response should include local replica flag");
    let owners_contains_local = owners.iter().any(|owner| owner.as_str() == Some(node_id));

    assert_eq!(is_local_primary, primary_owner == node_id);
    assert_eq!(is_local_replica, owners_contains_local);

    if is_local_primary {
        assert_eq!(body["forwardTarget"], serde_json::Value::Null);
    } else {
        assert_eq!(
            body["forwardTarget"].as_str(),
            Some(primary_owner),
            "forward target should point at primary owner when local is not primary"
        );
    }
}

#[tokio::test]
async fn test_console_placement_endpoint_rejects_invalid_query() {
    let (base_url, _tmp) = start_server().await;
    let cookie = console_login_cookie(&base_url).await;

    let missing_key = client()
        .get(format!("{}/api/system/placement", base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(missing_key.status(), 400);
    let missing_key_body: serde_json::Value = missing_key.json().await.unwrap();
    assert!(
        missing_key_body["error"]
            .as_str()
            .is_some_and(|msg| msg.contains("key"))
    );

    let invalid_replica = client()
        .get(format!(
            "{}/api/system/placement?key=docs/readme.txt&replicaCount=0",
            base_url
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(invalid_replica.status(), 400);
    let invalid_replica_body: serde_json::Value = invalid_replica.json().await.unwrap();
    assert!(
        invalid_replica_body["error"]
            .as_str()
            .is_some_and(|msg| msg.contains("replicaCount"))
    );

    let invalid_key = client()
        .get(format!(
            "{}/api/system/placement?key=/absolute/path",
            base_url
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(invalid_key.status(), 400);
    let invalid_key_body: serde_json::Value = invalid_key.json().await.unwrap();
    assert!(
        invalid_key_body["error"]
            .as_str()
            .is_some_and(|msg| msg.contains("Invalid key"))
    );

    let invalid_chunk_index = client()
        .get(format!(
            "{}/api/system/placement?key=docs/readme.txt&chunkIndex=abc",
            base_url
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(invalid_chunk_index.status(), 400);
    let invalid_chunk_index_body: serde_json::Value = invalid_chunk_index.json().await.unwrap();
    assert!(
        invalid_chunk_index_body["error"]
            .as_str()
            .is_some_and(|msg| msg.contains("chunkIndex"))
    );
}

#[tokio::test]
async fn test_console_placement_endpoint_contract_shape_is_stable() {
    let (base_url, _tmp) = start_server().await;
    let cookie = console_login_cookie(&base_url).await;

    let response = client()
        .get(format!(
            "{}/api/system/placement?key=docs/readme.txt&replicaCount=2",
            base_url
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_object_has_keys(
        &body,
        &[
            "key",
            "chunkIndex",
            "replicaCountRequested",
            "replicaCountApplied",
            "owners",
            "primaryOwner",
            "forwardTarget",
            "isLocalPrimaryOwner",
            "isLocalReplicaOwner",
            "writeQuorumSize",
            "writeAckPolicy",
            "nonOwnerMutationPolicy",
            "nonOwnerReadPolicy",
            "nonOwnerBatchMutationPolicy",
            "mixedOwnerBatchMutationPolicy",
            "replicaFanoutOperations",
            "pendingReplicaFanoutOperations",
            "mode",
            "nodeId",
            "clusterPeerCount",
            "clusterPeers",
            "membershipProtocol",
            "placementEpoch",
            "membershipViewId",
        ],
    );
    assert!(body["owners"].is_array());
    assert!(body["clusterPeers"].is_array());
}

#[tokio::test]
async fn test_console_rebalance_endpoint_requires_auth_and_reports_join_preview() {
    let (base_url, _tmp) = start_server().await;

    let unauthorized = client()
        .get(format!(
            "{}/api/system/rebalance?key=docs/readme.txt&addPeer=node-b.internal:9000",
            base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), 401);

    let cookie = console_login_cookie(&base_url).await;
    let authorized = client()
        .get(format!(
            "{}/api/system/rebalance?key=docs/readme.txt&replicaCount=2&addPeer=node-b.internal:9000",
            base_url
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(authorized.status(), 200);

    let body: serde_json::Value = authorized.json().await.unwrap();
    assert_eq!(body["operation"], "join");
    assert_eq!(body["operationPeer"], "node-b.internal:9000");
    assert_eq!(body["chunkIndex"], serde_json::Value::Null);
    assert_eq!(body["replicaCountRequested"], 2);
    assert_eq!(body["source"]["clusterPeerCount"], 0);
    assert_eq!(
        body["target"]["clusterPeers"],
        serde_json::json!(["node-b.internal:9000"])
    );
    assert_eq!(body["target"]["clusterPeerCount"], 1);
    assert!(
        body["target"]["membershipViewId"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );
    let transfers = body["plan"]["transfers"]
        .as_array()
        .expect("rebalance response should include transfers array");
    let local_actions = body["plan"]["localActions"]
        .as_array()
        .expect("rebalance response should include localActions array");
    assert_eq!(
        body["plan"]["transferCount"].as_u64(),
        Some(transfers.len() as u64)
    );
    assert!(local_actions.iter().all(|entry| {
        entry["action"]
            .as_str()
            .is_some_and(|value| value == "send" || value == "receive")
            && entry["to"].as_str().is_some_and(|value| !value.is_empty())
    }));
}

#[tokio::test]
async fn test_console_rebalance_endpoint_reports_distributed_leave_preview() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let cookie = console_login_cookie(&base_url).await;
    let response = client()
        .get(format!(
            "{}/api/system/rebalance?key=videos/movie.mp4&chunkIndex=2&replicaCount=2&removePeer=node-b.internal:9000",
            base_url
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["operation"], "leave");
    assert_eq!(body["operationPeer"], "node-b.internal:9000");
    assert_eq!(body["chunkIndex"], 2);
    assert_eq!(body["source"]["clusterPeerCount"], 1);
    assert_eq!(body["target"]["clusterPeerCount"], 0);
    assert_eq!(body["target"]["clusterPeers"], serde_json::json!([]));
    assert_eq!(body["mode"], "distributed");

    assert!(body["plan"]["previousOwners"].is_array());
    assert!(body["plan"]["nextOwners"].is_array());
    assert!(body["plan"]["removedOwners"].is_array());
    assert!(body["plan"]["addedOwners"].is_array());
    let local_actions = body["plan"]["localActions"]
        .as_array()
        .expect("rebalance response should include localActions array");
    assert!(local_actions.iter().all(|entry| {
        entry["action"]
            .as_str()
            .is_some_and(|value| value == "send" || value == "receive")
            && entry["to"].as_str().is_some_and(|value| !value.is_empty())
    }));
}

#[tokio::test]
async fn test_console_rebalance_endpoint_rejects_invalid_query() {
    let (base_url, _tmp) = start_server().await;
    let cookie = console_login_cookie(&base_url).await;

    let missing_operation = client()
        .get(format!(
            "{}/api/system/rebalance?key=docs/readme.txt",
            base_url
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(missing_operation.status(), 400);
    let missing_operation_body: serde_json::Value = missing_operation.json().await.unwrap();
    assert!(
        missing_operation_body["error"]
            .as_str()
            .is_some_and(|msg| msg.contains("addPeer or removePeer"))
    );

    let conflicting_operation = client()
        .get(format!(
            "{}/api/system/rebalance?key=docs/readme.txt&addPeer=node-b.internal:9000&removePeer=node-c.internal:9000",
            base_url
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(conflicting_operation.status(), 400);
    let conflicting_operation_body: serde_json::Value = conflicting_operation.json().await.unwrap();
    assert!(
        conflicting_operation_body["error"]
            .as_str()
            .is_some_and(|msg| msg.contains("only one"))
    );
}

#[tokio::test]
async fn test_console_rebalance_endpoint_contract_shape_is_stable() {
    let (base_url, _tmp) = start_server().await;
    let cookie = console_login_cookie(&base_url).await;

    let response = client()
        .get(format!(
            "{}/api/system/rebalance?key=docs/readme.txt&replicaCount=2&addPeer=node-b.internal:9000",
            base_url
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_object_has_keys(
        &body,
        &[
            "key",
            "chunkIndex",
            "replicaCountRequested",
            "replicaCountApplied",
            "operation",
            "operationPeer",
            "source",
            "target",
            "plan",
            "mode",
            "nodeId",
            "clusterPeerCount",
            "clusterPeers",
            "membershipProtocol",
            "placementEpoch",
            "membershipViewId",
        ],
    );
    assert!(body["clusterPeers"].is_array());
    assert!(body["source"].is_object());
    assert!(body["target"].is_object());
    assert!(body["plan"].is_object());

    assert_object_has_keys(
        &body["source"],
        &[
            "nodeId",
            "clusterPeerCount",
            "clusterPeers",
            "membershipViewId",
            "membershipNodes",
        ],
    );
    assert_object_has_keys(
        &body["target"],
        &[
            "nodeId",
            "clusterPeerCount",
            "clusterPeers",
            "membershipViewId",
            "membershipNodes",
        ],
    );
    assert!(body["source"]["clusterPeers"].is_array());
    assert!(body["target"]["clusterPeers"].is_array());
    assert!(body["source"]["membershipNodes"].is_array());
    assert!(body["target"]["membershipNodes"].is_array());

    assert_object_has_keys(
        &body["plan"],
        &[
            "previousOwners",
            "nextOwners",
            "retainedOwners",
            "removedOwners",
            "addedOwners",
            "transferCount",
            "localActions",
            "transfers",
        ],
    );
    let local_actions = body["plan"]["localActions"]
        .as_array()
        .expect("rebalance response should include localActions array");
    let transfers = body["plan"]["transfers"]
        .as_array()
        .expect("rebalance response should include transfers array");
    assert_eq!(
        body["plan"]["transferCount"].as_u64(),
        Some(transfers.len() as u64)
    );
    assert!(local_actions.iter().all(|entry| {
        entry["action"]
            .as_str()
            .is_some_and(|value| value == "send" || value == "receive")
            && entry["to"].as_str().is_some_and(|value| !value.is_empty())
    }));
}

#[tokio::test]
async fn test_console_summary_endpoint_requires_auth_and_returns_json() {
    let (base_url, _tmp) = start_server().await;

    let unauthorized = client()
        .get(format!("{}/api/system/summary", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), 401);

    let cookie = console_login_cookie(&base_url).await;
    let authorized = client()
        .get(format!("{}/api/system/summary", base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(authorized.status(), 200);

    let body: serde_json::Value = authorized.json().await.unwrap();
    assert_eq!(body["health"]["ok"], true);
    assert_eq!(body["health"]["version"], env!("CARGO_PKG_VERSION"));
    assert!(body["health"]["uptimeSeconds"].as_f64().is_some());
    assert_eq!(body["health"]["mode"], "standalone");
    assert!(
        body["health"]["nodeId"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );
    assert_eq!(body["health"]["clusterPeerCount"], 0);
    assert_eq!(body["health"]["clusterPeers"], serde_json::json!([]));
    assert_eq!(body["health"]["membershipProtocol"], "static-bootstrap");
    assert!(
        body["health"]["membershipViewId"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );
    assert_eq!(body["health"]["placementEpoch"], 0);
    assert!(body["metrics"]["requestsTotal"].as_u64().is_some());
    assert_eq!(body["metrics"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["metrics"]["membershipProtocolReady"], true);
    assert_eq!(body["topology"]["mode"], "standalone");
    assert!(
        body["topology"]["nodeId"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );
    assert_eq!(body["topology"]["clusterPeerCount"], 0);
    assert_eq!(body["topology"]["clusterPeers"], serde_json::json!([]));
    assert_eq!(body["topology"]["membershipProtocol"], "static-bootstrap");
    assert_eq!(body["topology"]["placementEpoch"], 0);
    assert_eq!(body["membership"]["mode"], "standalone");
    assert_eq!(body["membership"]["protocol"], "static-bootstrap");
    assert!(
        body["membership"]["viewId"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );
    assert!(
        body["membership"]["coordinatorNodeId"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );
    assert!(
        body["membership"]["leaderNodeId"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );
    assert_eq!(
        body["membership"]["nodes"].as_array().map(Vec::len),
        Some(1)
    );
}

#[tokio::test]
async fn test_console_summary_endpoint_reports_distributed_mode_when_configured() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["127.0.0.1:1".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let cookie = console_login_cookie(&base_url).await;
    let response = client()
        .get(format!("{}/api/system/summary", base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["health"]["ok"], false);
    assert_eq!(body["health"]["status"], "degraded");
    assert_eq!(body["health"]["mode"], "distributed");
    assert_eq!(body["health"]["clusterPeerCount"], 1);
    assert_eq!(
        body["health"]["clusterPeers"],
        serde_json::json!(["127.0.0.1:1"])
    );
    assert_eq!(body["health"]["membershipProtocol"], "static-bootstrap");
    assert!(
        body["health"]["membershipViewId"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );
    assert_eq!(body["health"]["placementEpoch"], 0);
    assert_eq!(body["health"]["checks"]["peerConnectivityReady"], false);
    assert_eq!(body["metrics"]["membershipProtocolReady"], true);
    assert_eq!(body["metrics"]["membershipConverged"], false);
    assert_eq!(
        body["metrics"]["membershipConvergenceReason"],
        "peer-connectivity-failed"
    );
    assert_eq!(body["topology"]["mode"], "distributed");
    assert_eq!(body["topology"]["clusterPeerCount"], 1);
    assert_eq!(
        body["topology"]["clusterPeers"],
        serde_json::json!(["127.0.0.1:1"])
    );
    assert_eq!(body["topology"]["membershipProtocol"], "static-bootstrap");
    assert_eq!(body["topology"]["placementEpoch"], 0);
    assert_eq!(body["membership"]["mode"], "distributed");
    assert_eq!(body["membership"]["protocol"], "static-bootstrap");
    assert_eq!(body["membership"]["leaderNodeId"], serde_json::Value::Null);
    assert!(
        body["membership"]["coordinatorNodeId"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );
    assert_eq!(
        body["membership"]["nodes"].as_array().map(Vec::len),
        Some(2)
    );
}

#[tokio::test]
async fn test_console_summary_endpoint_reports_degraded_health_when_storage_data_path_probe_fails()
{
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let config = make_test_config(data_dir.clone(), false, 10 * 1024 * 1024, 0);
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let buckets_dir = std::path::Path::new(&data_dir).join("buckets");
    tokio::fs::remove_dir_all(&buckets_dir)
        .await
        .expect("remove buckets directory");

    let cookie = console_login_cookie(&base_url).await;
    let response = client()
        .get(format!("{}/api/system/summary", base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["health"]["ok"], false);
    assert_eq!(body["health"]["status"], "degraded");
    assert_eq!(body["health"]["checks"]["storageDataPathReadable"], false);
    assert_eq!(body["health"]["checks"]["diskHeadroomSufficient"], true);
    assert_eq!(body["health"]["checks"]["peerConnectivityReady"], true);
    assert!(
        body["health"]["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.iter().any(|entry| {
                entry
                    .as_str()
                    .is_some_and(|msg| msg.contains("Storage data-path probe failed"))
            }))
    );
}

#[tokio::test]
async fn test_console_summary_endpoint_reports_degraded_health_when_cluster_peers_include_local_node_id()
 {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = "127.0.0.1:1".to_string();
    config.cluster_peers = vec!["127.0.0.1:1".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let cookie = console_login_cookie(&base_url).await;
    let response = client()
        .get(format!("{}/api/system/summary", base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["health"]["ok"], false);
    assert_eq!(body["health"]["status"], "degraded");
    assert_eq!(body["health"]["checks"]["membershipProtocolReady"], true);
    assert_eq!(body["health"]["checks"]["peerConnectivityReady"], false);
    assert!(
        body["health"]["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.iter().any(|entry| {
                entry
                    .as_str()
                    .is_some_and(|msg| msg.contains("includes local node id"))
            }))
    );
}

#[tokio::test]
async fn test_console_health_endpoint_contract_shape_is_stable() {
    let (base_url, _tmp) = start_server().await;
    let cookie = console_login_cookie(&base_url).await;

    let response = client()
        .get(format!("{}/api/system/health", base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_object_has_keys(
        &body,
        &[
            "ok",
            "status",
            "version",
            "uptimeSeconds",
            "mode",
            "nodeId",
            "clusterPeerCount",
            "clusterPeers",
            "membershipNodeCount",
            "membershipNodes",
            "membershipProtocol",
            "membershipViewId",
            "placementEpoch",
            "checks",
            "warnings",
        ],
    );
    assert!(body["clusterPeers"].is_array());
    assert!(body["membershipNodes"].is_array());
    assert!(body["warnings"].is_array());
    assert!(body["uptimeSeconds"].as_f64().is_some());

    assert_object_has_keys(
        &body["checks"],
        &[
            "dataDirAccessible",
            "dataDirWritable",
            "storageDataPathReadable",
            "diskHeadroomSufficient",
            "peerConnectivityReady",
            "membershipProtocolReady",
        ],
    );
}

#[tokio::test]
async fn test_console_summary_endpoint_contract_shape_is_stable() {
    let (base_url, _tmp) = start_server().await;
    let cookie = console_login_cookie(&base_url).await;

    let response = client()
        .get(format!("{}/api/system/summary", base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_object_has_keys(&body, &["health", "metrics", "topology", "membership"]);

    assert_object_has_keys(
        &body["health"],
        &[
            "ok",
            "status",
            "version",
            "uptimeSeconds",
            "mode",
            "nodeId",
            "clusterPeerCount",
            "clusterPeers",
            "membershipNodeCount",
            "membershipNodes",
            "membershipProtocol",
            "membershipViewId",
            "placementEpoch",
            "checks",
            "warnings",
        ],
    );
    assert_object_has_keys(
        &body["health"]["checks"],
        &[
            "dataDirAccessible",
            "dataDirWritable",
            "storageDataPathReadable",
            "diskHeadroomSufficient",
            "peerConnectivityReady",
            "membershipProtocolReady",
        ],
    );
    assert_object_has_keys(
        &body["metrics"],
        &[
            "requestsTotal",
            "uptimeSeconds",
            "version",
            "membershipProtocolReady",
            "membershipConvergenceReason",
        ],
    );
    assert_object_has_keys(
        &body["topology"],
        &[
            "mode",
            "nodeId",
            "clusterPeerCount",
            "clusterPeers",
            "membershipProtocol",
            "placementEpoch",
        ],
    );
    assert_object_has_keys(
        &body["membership"],
        &[
            "mode",
            "protocol",
            "viewId",
            "leaderNodeId",
            "coordinatorNodeId",
            "nodes",
        ],
    );

    let nodes = body["membership"]["nodes"]
        .as_array()
        .expect("membership.nodes should be an array");
    assert!(!nodes.is_empty(), "membership.nodes should not be empty");
    assert_object_has_keys(&nodes[0], &["nodeId", "role", "status"]);
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
async fn test_console_download_object_returns_expected_headers_and_body() {
    let (base_url, _tmp) = start_server().await;
    let cookie = console_login_cookie(&base_url).await;
    let bucket = "console-download-bucket";
    let key = "docs/report.txt";
    let payload = b"console download payload".to_vec();

    let create_bucket = s3_request("PUT", &format!("{}/{}", base_url, bucket), vec![]).await;
    assert_eq!(create_bucket.status(), 200);

    let upload = client()
        .put(format!(
            "{}/api/buckets/{}/upload/{}",
            base_url, bucket, key
        ))
        .header("cookie", &cookie)
        .header("content-type", "text/plain")
        .body(payload.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), 200);

    let download = client()
        .get(format!(
            "{}/api/buckets/{}/download/{}",
            base_url, bucket, key
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(download.status(), 200);
    let expected_len = payload.len().to_string();
    assert_eq!(
        download
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("text/plain")
    );
    assert_eq!(
        download
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok()),
        Some(expected_len.as_str())
    );
    assert_eq!(
        download
            .headers()
            .get("content-disposition")
            .and_then(|v| v.to_str().ok()),
        Some("attachment; filename=\"report.txt\"")
    );
    assert_eq!(download.bytes().await.unwrap().as_ref(), payload.as_slice());
}

#[tokio::test]
async fn test_console_list_objects_reports_distributed_metadata_coverage() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = "node-a.internal:9000".to_string();
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let cookie = console_login_cookie(&base_url).await;
    let bucket = "console-distributed-list";

    let create_bucket = s3_request("PUT", &format!("{}/{}", base_url, bucket), vec![]).await;
    assert_eq!(create_bucket.status(), 200);
    let put_object = s3_request(
        "PUT",
        &format!("{}/{}/docs/readme.txt", base_url, bucket),
        b"hello".to_vec(),
    )
    .await;
    assert_eq!(put_object.status(), 200);

    let list = client()
        .get(format!(
            "{}/api/buckets/{}/objects?prefix=docs/&delimiter=/",
            base_url, bucket
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), 200);
    let body: serde_json::Value = list.json().await.unwrap();
    assert_eq!(body["metadataCoverage"]["complete"], true);
    assert_eq!(body["metadataCoverage"]["expectedNodes"], 1);
    assert_eq!(body["metadataCoverage"]["respondedNodes"], 1);
    assert_eq!(body["metadataCoverage"]["missingNodes"], 0);
    assert_eq!(body["metadataCoverage"]["unexpectedNodes"], 0);
    let snapshot_id = body["metadataCoverage"]["snapshotId"]
        .as_str()
        .unwrap_or_default();
    assert_eq!(snapshot_id.len(), 64);
    assert_eq!(body["metadataCoverage"]["source"], "local-node-only");
    assert_eq!(
        body["metadataCoverage"]["strategyClusterAuthoritative"],
        false
    );
    assert_eq!(body["metadataCoverage"]["strategyReady"], false);
    assert_eq!(
        body["metadataCoverage"]["strategyGap"],
        "strategy-not-cluster-authoritative"
    );
}

#[tokio::test]
async fn test_console_list_versions_reports_distributed_metadata_coverage() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = "node-a.internal:9000".to_string();
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let cookie = console_login_cookie(&base_url).await;
    let bucket = "console-distributed-versions";
    let key = "docs/readme.txt";

    let create_bucket = s3_request("PUT", &format!("{}/{}", base_url, bucket), vec![]).await;
    assert_eq!(create_bucket.status(), 200);
    let enable_versioning = s3_request(
        "PUT",
        &format!("{}/{}?versioning=", base_url, bucket),
        br#"<?xml version="1.0" encoding="UTF-8"?>
<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
</VersioningConfiguration>"#
            .to_vec(),
    )
    .await;
    assert_eq!(enable_versioning.status(), 200);
    let put_object = s3_request(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, key),
        b"hello".to_vec(),
    )
    .await;
    assert_eq!(put_object.status(), 200);

    let list = client()
        .get(format!(
            "{}/api/buckets/{}/versions?key={}",
            base_url, bucket, key
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), 200);
    let body: serde_json::Value = list.json().await.unwrap();
    assert_eq!(body["metadataCoverage"]["complete"], true);
    assert_eq!(body["metadataCoverage"]["expectedNodes"], 1);
    assert_eq!(body["metadataCoverage"]["respondedNodes"], 1);
    assert_eq!(body["metadataCoverage"]["missingNodes"], 0);
    assert_eq!(body["metadataCoverage"]["unexpectedNodes"], 0);
    let snapshot_id = body["metadataCoverage"]["snapshotId"]
        .as_str()
        .unwrap_or_default();
    assert_eq!(snapshot_id.len(), 64);
    assert_eq!(body["metadataCoverage"]["source"], "local-node-only");
    assert_eq!(
        body["metadataCoverage"]["strategyClusterAuthoritative"],
        false
    );
    assert_eq!(body["metadataCoverage"]["strategyReady"], false);
    assert_eq!(
        body["metadataCoverage"]["strategyGap"],
        "strategy-not-cluster-authoritative"
    );
}

#[tokio::test]
async fn test_console_list_objects_reports_metadata_strategy_for_consensus_index() {
    let shared_token = "console-object-listing-consensus-shared-token";
    let bucket = "console-distributed-list-consensus-index";
    let owner_node_id = "127.0.0.1:39243";
    let owner_cluster_peers = vec!["node-a.internal:9000".to_string()];
    let owner_membership_view_id =
        consensus_membership_view_id(owner_node_id, owner_cluster_peers.as_slice());

    let owner_tmp = TempDir::new().unwrap();
    let owner_data_dir = owner_tmp.path().to_string_lossy().to_string();
    let bucket_state = BucketMetadataState {
        bucket: bucket.to_string(),
        versioning_enabled: false,
        lifecycle_enabled: false,
    };
    seed_consensus_metadata_buckets(
        &owner_data_dir,
        owner_membership_view_id.as_str(),
        std::slice::from_ref(&bucket_state),
    );
    seed_object_in_data_dir(
        &owner_data_dir,
        bucket,
        "docs/peer-only.txt",
        b"peer-only",
        false,
    )
    .await;
    let mut owner_config = make_test_config(owner_data_dir, false, 10 * 1024 * 1024, 0);
    owner_config.node_id = owner_node_id.to_string();
    owner_config.cluster_peers = owner_cluster_peers;
    owner_config.cluster_auth_token = Some(shared_token.to_string());
    owner_config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    let (owner_url, _owner_tmp) = start_server_with_config(owner_config, owner_tmp).await;

    let peer_endpoint = host_port_from_base_url(&owner_url);
    let coordinator_node_id = "node-a.internal:9000";
    let coordinator_cluster_peers = vec![peer_endpoint.clone()];
    let coordinator_membership_view_id =
        consensus_membership_view_id(coordinator_node_id, coordinator_cluster_peers.as_slice());
    let coordinator_tmp = TempDir::new().unwrap();
    let coordinator_data_dir = coordinator_tmp.path().to_string_lossy().to_string();
    seed_consensus_metadata_buckets(
        &coordinator_data_dir,
        coordinator_membership_view_id.as_str(),
        std::slice::from_ref(&bucket_state),
    );
    seed_object_in_data_dir(
        &coordinator_data_dir,
        bucket,
        "docs/local-only.txt",
        b"local-only",
        false,
    )
    .await;
    seed_consensus_metadata_object_rows(
        &coordinator_data_dir,
        coordinator_membership_view_id.as_str(),
        std::slice::from_ref(&bucket_state),
        &[ObjectMetadataState {
            bucket: bucket.to_string(),
            key: "docs/peer-only.txt".to_string(),
            latest_version_id: None,
            is_delete_marker: false,
        }],
    );
    let mut coordinator_config = make_test_config(coordinator_data_dir, false, 10 * 1024 * 1024, 0);
    coordinator_config.node_id = coordinator_node_id.to_string();
    coordinator_config.cluster_peers = coordinator_cluster_peers;
    coordinator_config.cluster_auth_token = Some(shared_token.to_string());
    coordinator_config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    let (base_url, _coordinator_tmp) =
        start_server_with_config(coordinator_config, coordinator_tmp).await;
    let cookie = console_login_cookie(&base_url).await;

    let list = client()
        .get(format!(
            "{}/api/buckets/{}/objects?prefix=docs/&delimiter=/",
            base_url, bucket
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), 200);
    let body: serde_json::Value = list.json().await.unwrap();
    let files = body["files"].as_array().expect("files should be an array");
    let keys = files
        .iter()
        .filter_map(|entry| entry["key"].as_str())
        .collect::<Vec<_>>();
    assert!(
        keys.contains(&"docs/peer-only.txt"),
        "unexpected files response: {body}"
    );
    assert!(
        !keys.contains(&"docs/local-only.txt"),
        "unexpected files response: {body}"
    );
    assert_eq!(body["metadataCoverage"]["complete"], true);
    assert_eq!(body["metadataCoverage"]["expectedNodes"], 2);
    assert_eq!(body["metadataCoverage"]["respondedNodes"], 2);
    assert_eq!(body["metadataCoverage"]["missingNodes"], 0);
    assert_eq!(body["metadataCoverage"]["unexpectedNodes"], 0);
    let snapshot_id = body["metadataCoverage"]["snapshotId"]
        .as_str()
        .unwrap_or_default();
    assert_eq!(snapshot_id.len(), 64);
    assert_eq!(body["metadataCoverage"]["source"], "consensus-index");
    assert_eq!(
        body["metadataCoverage"]["strategyClusterAuthoritative"],
        true
    );
    assert_eq!(body["metadataCoverage"]["strategyReady"], true);
    assert_eq!(
        body["metadataCoverage"]["strategyGap"],
        serde_json::Value::Null
    );
}

#[tokio::test]
async fn test_console_list_objects_consensus_index_returns_service_unavailable_when_token_missing()
{
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let bucket = "console-consensus-object-list-missing-token";
    let node_id = "node-a.internal:9000";
    let cluster_peers = vec!["node-b.internal:9000".to_string()];
    let membership_view_id = consensus_membership_view_id(node_id, cluster_peers.as_slice());
    seed_consensus_metadata_buckets(
        &data_dir,
        membership_view_id.as_str(),
        &[BucketMetadataState {
            bucket: bucket.to_string(),
            versioning_enabled: false,
            lifecycle_enabled: false,
        }],
    );
    seed_object_in_data_dir(&data_dir, bucket, "docs/readme.txt", b"hello", false).await;

    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = node_id.to_string();
    config.cluster_peers = cluster_peers;
    config.cluster_auth_token = Some("shared-token".to_string());
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    config.cluster_auth_token = None;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let cookie = console_login_cookie(&base_url).await;

    let list = client()
        .get(format!(
            "{}/api/buckets/{}/objects?prefix=docs/&delimiter=/",
            base_url, bucket
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), 503);
    let body: serde_json::Value = list.json().await.unwrap();
    assert_eq!(
        body["error"],
        "Distributed metadata listing strategy is not ready for this request (consensus-index-peer-fan-in-auth-token-missing)"
    );
}

#[tokio::test]
async fn test_console_list_objects_consensus_index_returns_service_unavailable_when_peer_fan_in_incomplete()
 {
    let shared_token = "console-consensus-object-list-incomplete-shared-token";
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let bucket = "console-consensus-object-list-incomplete";
    let node_id = "node-a.internal:9000";
    let cluster_peers = vec!["node-b.internal:9000".to_string()];
    let membership_view_id = consensus_membership_view_id(node_id, cluster_peers.as_slice());
    seed_consensus_metadata_buckets(
        &data_dir,
        membership_view_id.as_str(),
        &[BucketMetadataState {
            bucket: bucket.to_string(),
            versioning_enabled: false,
            lifecycle_enabled: false,
        }],
    );
    seed_object_in_data_dir(&data_dir, bucket, "docs/readme.txt", b"hello", false).await;

    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = node_id.to_string();
    config.cluster_peers = cluster_peers;
    config.cluster_auth_token = Some("shared-token".to_string());
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    config.cluster_auth_token = Some(shared_token.to_string());
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let cookie = console_login_cookie(&base_url).await;

    let list = client()
        .get(format!(
            "{}/api/buckets/{}/objects?prefix=docs/&delimiter=/",
            base_url, bucket
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), 503);
    let body: serde_json::Value = list.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|message| message.contains("missing-expected-nodes")),
        "unexpected body: {body}"
    );
}

#[tokio::test]
async fn test_console_list_buckets_request_time_aggregation_merges_peer_bucket_state_when_ready() {
    let shared_token = "console-bucket-listing-shared-token";
    let coordinator_node_id = "node-a.internal:9000";

    let owner_tmp = TempDir::new().unwrap();
    let owner_data_dir = owner_tmp.path().to_string_lossy().to_string();
    let peer_bucket = "console-bucket-peer";
    seed_bucket_in_data_dir(&owner_data_dir, peer_bucket).await;
    let mut owner_config = make_test_config(owner_data_dir, false, 10 * 1024 * 1024, 0);
    owner_config.node_id = "127.0.0.1:39101".to_string();
    owner_config.cluster_peers = vec![coordinator_node_id.to_string()];
    owner_config.cluster_auth_token = Some(shared_token.to_string());
    owner_config.metadata_listing_strategy = ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (owner_url, _owner_tmp) = start_server_with_config(owner_config, owner_tmp).await;

    let peer_endpoint = host_port_from_base_url(&owner_url);
    let coordinator_tmp = TempDir::new().unwrap();
    let coordinator_data_dir = coordinator_tmp.path().to_string_lossy().to_string();
    let mut coordinator_config = make_test_config(coordinator_data_dir, false, 10 * 1024 * 1024, 0);
    coordinator_config.node_id = coordinator_node_id.to_string();
    coordinator_config.cluster_peers = vec![peer_endpoint.clone()];
    coordinator_config.cluster_auth_token = Some(shared_token.to_string());
    coordinator_config.metadata_listing_strategy =
        ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (coordinator_url, _coordinator_tmp) =
        start_server_with_config(coordinator_config, coordinator_tmp).await;

    let coordinator_cookie = console_login_cookie(&coordinator_url).await;

    let coordinator_bucket = "console-bucket-local";
    let create_local = s3_request(
        "PUT",
        &format!("{}/{}", coordinator_url, coordinator_bucket),
        vec![],
    )
    .await;
    assert_eq!(create_local.status(), 200);

    let list = client()
        .get(format!("{}/api/buckets", coordinator_url))
        .header("cookie", &coordinator_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), 200);
    let body: serde_json::Value = list.json().await.unwrap();

    let buckets = body["buckets"]
        .as_array()
        .expect("buckets should be an array");
    let bucket_names = buckets
        .iter()
        .filter_map(|bucket| bucket["name"].as_str())
        .collect::<Vec<_>>();
    assert!(
        bucket_names.contains(&coordinator_bucket),
        "unexpected list response: {body}"
    );
    assert!(
        bucket_names.contains(&peer_bucket),
        "unexpected list response: {body}"
    );
}

#[tokio::test]
async fn test_console_list_buckets_request_time_aggregation_rejects_inconsistent_peer_versioning_state()
 {
    let shared_token = "console-bucket-listing-versioning-inconsistent-token";
    let coordinator_node_id = "node-a.internal:9000";

    let owner_tmp = TempDir::new().unwrap();
    let owner_data_dir = owner_tmp.path().to_string_lossy().to_string();
    let bucket = "console-bucket-versioning-inconsistent";
    seed_bucket_in_data_dir(&owner_data_dir, bucket).await;
    let mut owner_config = make_test_config(owner_data_dir, false, 10 * 1024 * 1024, 0);
    owner_config.node_id = "127.0.0.1:39141".to_string();
    owner_config.cluster_peers = vec![coordinator_node_id.to_string()];
    owner_config.cluster_auth_token = Some(shared_token.to_string());
    owner_config.metadata_listing_strategy = ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (owner_url, _owner_tmp) = start_server_with_config(owner_config, owner_tmp).await;

    let peer_endpoint = host_port_from_base_url(&owner_url);
    let coordinator_tmp = TempDir::new().unwrap();
    let coordinator_data_dir = coordinator_tmp.path().to_string_lossy().to_string();
    seed_bucket_in_data_dir(&coordinator_data_dir, bucket).await;
    let mut coordinator_config = make_test_config(coordinator_data_dir, false, 10 * 1024 * 1024, 0);
    coordinator_config.node_id = coordinator_node_id.to_string();
    coordinator_config.cluster_peers = vec![peer_endpoint.clone()];
    coordinator_config.cluster_auth_token = Some(shared_token.to_string());
    coordinator_config.metadata_listing_strategy =
        ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (coordinator_url, _coordinator_tmp) =
        start_server_with_config(coordinator_config, coordinator_tmp).await;

    let coordinator_cookie = console_login_cookie(&coordinator_url).await;

    let enable_versioning_on_owner = s3_request(
        "PUT",
        &format!("{}/{}?versioning=", owner_url, bucket),
        br#"<?xml version="1.0" encoding="UTF-8"?>
<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
</VersioningConfiguration>"#
            .to_vec(),
    )
    .await;
    assert!(
        enable_versioning_on_owner.status() == 200 || enable_versioning_on_owner.status() == 503
    );

    let list = client()
        .get(format!("{}/api/buckets", coordinator_url))
        .header("cookie", &coordinator_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), 503);
    let body: serde_json::Value = list.json().await.unwrap();
    assert!(
        body["error"].as_str().is_some_and(|message| {
            message.contains("Distributed bucket versioning state is inconsistent")
                || message
                    .contains("Distributed metadata fan-in for 'ListConsoleBuckets' is not ready")
        }),
        "unexpected body: {body}"
    );
}

#[tokio::test]
async fn test_console_list_buckets_consensus_index_uses_persisted_metadata_state() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let node_id = "node-a.internal:9000";
    let cluster_peers = vec!["node-b.internal:9000".to_string()];
    let membership_view_id = consensus_membership_view_id(node_id, cluster_peers.as_slice());
    seed_consensus_metadata_buckets(
        &data_dir,
        membership_view_id.as_str(),
        &[
            BucketMetadataState {
                bucket: "console-consensus-bucket-a".to_string(),
                versioning_enabled: false,
                lifecycle_enabled: false,
            },
            BucketMetadataState {
                bucket: "console-consensus-bucket-b".to_string(),
                versioning_enabled: true,
                lifecycle_enabled: false,
            },
        ],
    );
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = node_id.to_string();
    config.cluster_peers = cluster_peers;
    config.cluster_auth_token = Some("shared-token".to_string());
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let cookie = console_login_cookie(&base_url).await;

    let list = client()
        .get(format!("{}/api/buckets", base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), 200);
    let body: serde_json::Value = list.json().await.unwrap();

    let buckets = body["buckets"]
        .as_array()
        .expect("buckets should be an array");
    let mut bucket_versioning = std::collections::HashMap::new();
    for bucket in buckets {
        let name = bucket["name"]
            .as_str()
            .expect("bucket name should be a string")
            .to_string();
        let versioning = bucket["versioning"]
            .as_bool()
            .expect("bucket versioning should be a bool");
        bucket_versioning.insert(name, versioning);
    }
    assert_eq!(
        bucket_versioning.get("console-consensus-bucket-a"),
        Some(&false)
    );
    assert_eq!(
        bucket_versioning.get("console-consensus-bucket-b"),
        Some(&true)
    );
}

#[tokio::test]
async fn test_console_list_buckets_consensus_index_persists_local_create_into_consensus_state() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let node_id = "node-a.internal:9000";
    let cluster_peers = vec!["node-b.internal:9000".to_string()];
    let membership_view_id = consensus_membership_view_id(node_id, cluster_peers.as_slice());
    seed_consensus_metadata_buckets(&data_dir, membership_view_id.as_str(), &[]);
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = node_id.to_string();
    config.cluster_peers = cluster_peers;
    config.cluster_auth_token = Some("shared-token".to_string());
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let cookie = console_login_cookie(&base_url).await;

    let create = s3_request(
        "PUT",
        &format!("{}/{}", base_url, "console-consensus-local-only"),
        vec![],
    )
    .await;
    assert_eq!(create.status(), 200);

    let list = client()
        .get(format!("{}/api/buckets", base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), 200);
    let body: serde_json::Value = list.json().await.unwrap();
    let buckets = body["buckets"]
        .as_array()
        .expect("buckets should be an array");
    assert!(
        buckets
            .iter()
            .filter_map(|bucket| bucket["name"].as_str())
            .any(|name| name == "console-consensus-local-only"),
        "unexpected body: {body}"
    );
}

#[tokio::test]
async fn test_console_create_bucket_consensus_index_rejects_existing_persisted_bucket_without_local_side_effect()
 {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let node_id = "node-a.internal:9000";
    let cluster_peers = vec!["node-b.internal:9000".to_string()];
    let membership_view_id = consensus_membership_view_id(node_id, cluster_peers.as_slice());
    let bucket = "console-consensus-persisted-present";
    seed_consensus_metadata_buckets(
        &data_dir,
        membership_view_id.as_str(),
        &[BucketMetadataState {
            bucket: bucket.to_string(),
            versioning_enabled: false,
            lifecycle_enabled: false,
        }],
    );
    let mut config = make_test_config(data_dir.clone(), false, 10 * 1024 * 1024, 0);
    config.node_id = node_id.to_string();
    config.cluster_peers = cluster_peers;
    config.cluster_auth_token = Some("shared-token".to_string());
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let cookie = console_login_cookie(&base_url).await;

    let create = client()
        .post(format!("{}/api/buckets", base_url))
        .header("cookie", &cookie)
        .header("content-type", "application/json")
        .json(&serde_json::json!({ "name": bucket }))
        .send()
        .await
        .unwrap();
    assert_eq!(create.status(), 409);
    let body: serde_json::Value = create.json().await.unwrap();
    assert_eq!(body["error"], "Bucket already exists");

    let storage =
        maxio::storage::filesystem::FilesystemStorage::new(&data_dir, false, 10 * 1024 * 1024, 0)
            .await
            .expect("storage should initialize");
    let exists = storage
        .head_bucket(bucket)
        .await
        .expect("head bucket should succeed");
    assert!(
        !exists,
        "expected no local side effect for persisted-present create rejection"
    );
}

#[tokio::test]
async fn test_console_create_bucket_consensus_index_rejects_active_tombstone_without_local_side_effect()
 {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let node_id = "node-a.internal:9000";
    let cluster_peers = vec!["node-b.internal:9000".to_string()];
    let membership_view_id = consensus_membership_view_id(node_id, cluster_peers.as_slice());
    let bucket = "console-consensus-active-tombstone";
    let now_ms = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0);
    seed_consensus_metadata_bucket_state(
        &data_dir,
        membership_view_id.as_str(),
        &[],
        &[BucketMetadataTombstoneState {
            bucket: bucket.to_string(),
            deleted_at_unix_ms: now_ms.saturating_sub(1_000),
            retain_until_unix_ms: now_ms.saturating_add(120_000),
        }],
    );
    let mut config = make_test_config(data_dir.clone(), false, 10 * 1024 * 1024, 0);
    config.node_id = node_id.to_string();
    config.cluster_peers = cluster_peers;
    config.cluster_auth_token = Some("shared-token".to_string());
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let cookie = console_login_cookie(&base_url).await;

    let create = client()
        .post(format!("{}/api/buckets", base_url))
        .header("cookie", &cookie)
        .header("content-type", "application/json")
        .json(&serde_json::json!({ "name": bucket }))
        .send()
        .await
        .unwrap();
    assert_eq!(create.status(), 503);
    let body: serde_json::Value = create.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|message| message.contains("tombstone retention is still active")),
        "unexpected body: {body}"
    );

    let storage =
        maxio::storage::filesystem::FilesystemStorage::new(&data_dir, false, 10 * 1024 * 1024, 0)
            .await
            .expect("storage should initialize");
    let exists = storage
        .head_bucket(bucket)
        .await
        .expect("head bucket should succeed");
    assert!(
        !exists,
        "expected no local side effect for active tombstone create rejection"
    );
}

#[tokio::test]
async fn test_console_delete_bucket_consensus_index_rejects_missing_persisted_bucket_without_local_side_effect()
 {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let node_id = "node-a.internal:9000";
    let cluster_peers = vec!["node-b.internal:9000".to_string()];
    let membership_view_id = consensus_membership_view_id(node_id, cluster_peers.as_slice());
    let bucket = "console-consensus-delete-missing";
    seed_consensus_metadata_buckets(&data_dir, membership_view_id.as_str(), &[]);
    seed_bucket_in_data_dir(&data_dir, bucket).await;

    let mut config = make_test_config(data_dir.clone(), false, 10 * 1024 * 1024, 0);
    config.node_id = node_id.to_string();
    config.cluster_peers = cluster_peers;
    config.cluster_auth_token = Some("shared-token".to_string());
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let cookie = console_login_cookie(&base_url).await;

    let delete = client()
        .delete(format!("{}/api/buckets/{}", base_url, bucket))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), 404);
    let body: serde_json::Value = delete.json().await.unwrap();
    assert_eq!(body["error"], "Bucket not found");

    let storage =
        maxio::storage::filesystem::FilesystemStorage::new(&data_dir, false, 10 * 1024 * 1024, 0)
            .await
            .expect("storage should initialize");
    let exists = storage
        .head_bucket(bucket)
        .await
        .expect("head bucket should succeed");
    assert!(
        exists,
        "expected local bucket to remain when persisted consensus metadata marks it missing"
    );
}

#[tokio::test]
async fn test_console_delete_bucket_consensus_index_rejects_tombstoned_persisted_bucket_without_local_side_effect()
 {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let node_id = "node-a.internal:9000";
    let cluster_peers = vec!["node-b.internal:9000".to_string()];
    let membership_view_id = consensus_membership_view_id(node_id, cluster_peers.as_slice());
    let bucket = "console-consensus-delete-tombstoned";
    let now_ms = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0);
    seed_consensus_metadata_bucket_state(
        &data_dir,
        membership_view_id.as_str(),
        &[],
        &[BucketMetadataTombstoneState {
            bucket: bucket.to_string(),
            deleted_at_unix_ms: now_ms.saturating_sub(1_000),
            retain_until_unix_ms: now_ms.saturating_add(120_000),
        }],
    );
    seed_bucket_in_data_dir(&data_dir, bucket).await;

    let mut config = make_test_config(data_dir.clone(), false, 10 * 1024 * 1024, 0);
    config.node_id = node_id.to_string();
    config.cluster_peers = cluster_peers;
    config.cluster_auth_token = Some("shared-token".to_string());
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let cookie = console_login_cookie(&base_url).await;

    let delete = client()
        .delete(format!("{}/api/buckets/{}", base_url, bucket))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), 404);
    let body: serde_json::Value = delete.json().await.unwrap();
    assert_eq!(body["error"], "Bucket not found");

    let storage =
        maxio::storage::filesystem::FilesystemStorage::new(&data_dir, false, 10 * 1024 * 1024, 0)
            .await
            .expect("storage should initialize");
    let exists = storage
        .head_bucket(bucket)
        .await
        .expect("head bucket should succeed");
    assert!(
        exists,
        "expected local bucket to remain when persisted consensus metadata marks it tombstoned"
    );
}

#[tokio::test]
async fn test_console_list_buckets_consensus_index_rejects_persisted_view_mismatch() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let node_id = "node-a.internal:9000";
    let cluster_peers = vec!["node-b.internal:9000".to_string()];
    seed_consensus_metadata_buckets(
        &data_dir,
        "view-console-consensus-mismatch",
        &[BucketMetadataState {
            bucket: "console-consensus-view-mismatch".to_string(),
            versioning_enabled: false,
            lifecycle_enabled: false,
        }],
    );
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = node_id.to_string();
    config.cluster_peers = cluster_peers;
    config.cluster_auth_token = Some("shared-token".to_string());
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let cookie = console_login_cookie(&base_url).await;

    let list = client()
        .get(format!("{}/api/buckets", base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), 503);
    let body: serde_json::Value = list.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|message| message.contains("persisted metadata view mismatch")),
        "unexpected body: {body}"
    );
}

#[tokio::test]
async fn test_console_list_objects_request_time_aggregation_merges_peer_object_state_when_ready() {
    let shared_token = "console-object-listing-shared-token";
    let bucket = "console-object-listing-aggregate";
    let coordinator_node_id = "node-a.internal:9000";

    let owner_tmp = TempDir::new().unwrap();
    let owner_data_dir = owner_tmp.path().to_string_lossy().to_string();
    seed_object_in_data_dir(
        &owner_data_dir,
        bucket,
        "docs/peer-only.txt",
        b"peer-only",
        false,
    )
    .await;
    let mut owner_config = make_test_config(owner_data_dir, false, 10 * 1024 * 1024, 0);
    owner_config.node_id = "127.0.0.1:39241".to_string();
    owner_config.cluster_peers = vec![coordinator_node_id.to_string()];
    owner_config.cluster_auth_token = Some(shared_token.to_string());
    owner_config.metadata_listing_strategy = ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (owner_url, _owner_tmp) = start_server_with_config(owner_config, owner_tmp).await;

    let peer_endpoint = host_port_from_base_url(&owner_url);
    let coordinator_tmp = TempDir::new().unwrap();
    let coordinator_data_dir = coordinator_tmp.path().to_string_lossy().to_string();
    seed_object_in_data_dir(
        &coordinator_data_dir,
        bucket,
        "docs/local-only.txt",
        b"local-only",
        false,
    )
    .await;
    let mut coordinator_config = make_test_config(coordinator_data_dir, false, 10 * 1024 * 1024, 0);
    coordinator_config.node_id = coordinator_node_id.to_string();
    coordinator_config.cluster_peers = vec![peer_endpoint];
    coordinator_config.cluster_auth_token = Some(shared_token.to_string());
    coordinator_config.metadata_listing_strategy =
        ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (coordinator_url, _coordinator_tmp) =
        start_server_with_config(coordinator_config, coordinator_tmp).await;

    let cookie = console_login_cookie(&coordinator_url).await;
    let list = client()
        .get(format!(
            "{}/api/buckets/{}/objects?prefix=docs/&delimiter=/",
            coordinator_url, bucket
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), 200);
    let body: serde_json::Value = list.json().await.unwrap();

    let files = body["files"].as_array().expect("files should be an array");
    let keys = files
        .iter()
        .filter_map(|entry| entry["key"].as_str())
        .collect::<Vec<_>>();
    assert!(
        keys.contains(&"docs/local-only.txt"),
        "unexpected files response: {body}"
    );
    assert!(
        keys.contains(&"docs/peer-only.txt"),
        "unexpected files response: {body}"
    );
    assert_eq!(body["metadataCoverage"]["expectedNodes"], 2);
    assert_eq!(body["metadataCoverage"]["respondedNodes"], 2);
    assert_eq!(body["metadataCoverage"]["missingNodes"], 0);
    assert_eq!(body["metadataCoverage"]["unexpectedNodes"], 0);
    assert_eq!(body["metadataCoverage"]["complete"], true);
    assert_eq!(
        body["metadataCoverage"]["source"],
        "request-time-aggregation"
    );
}

#[tokio::test]
async fn test_console_list_versions_request_time_aggregation_merges_peer_state_when_ready() {
    let shared_token = "console-versions-listing-shared-token";
    let bucket = "console-versions-listing-aggregate";
    let key = "docs/readme.txt";
    let coordinator_node_id = "node-a.internal:9000";

    let owner_tmp = TempDir::new().unwrap();
    let owner_data_dir = owner_tmp.path().to_string_lossy().to_string();
    seed_object_in_data_dir(&owner_data_dir, bucket, key, b"peer-version", true).await;
    let mut owner_config = make_test_config(owner_data_dir, false, 10 * 1024 * 1024, 0);
    owner_config.node_id = "127.0.0.1:39242".to_string();
    owner_config.cluster_peers = vec![coordinator_node_id.to_string()];
    owner_config.cluster_auth_token = Some(shared_token.to_string());
    owner_config.metadata_listing_strategy = ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (owner_url, _owner_tmp) = start_server_with_config(owner_config, owner_tmp).await;

    let peer_endpoint = host_port_from_base_url(&owner_url);
    let coordinator_tmp = TempDir::new().unwrap();
    let coordinator_data_dir = coordinator_tmp.path().to_string_lossy().to_string();
    seed_object_in_data_dir(&coordinator_data_dir, bucket, key, b"local-version", true).await;
    let mut coordinator_config = make_test_config(coordinator_data_dir, false, 10 * 1024 * 1024, 0);
    coordinator_config.node_id = coordinator_node_id.to_string();
    coordinator_config.cluster_peers = vec![peer_endpoint];
    coordinator_config.cluster_auth_token = Some(shared_token.to_string());
    coordinator_config.metadata_listing_strategy =
        ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (coordinator_url, _coordinator_tmp) =
        start_server_with_config(coordinator_config, coordinator_tmp).await;

    let cookie = console_login_cookie(&coordinator_url).await;
    let list = client()
        .get(format!(
            "{}/api/buckets/{}/versions?key={}",
            coordinator_url, bucket, key
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), 200);
    let body: serde_json::Value = list.json().await.unwrap();

    let versions = body["versions"]
        .as_array()
        .expect("versions should be an array");
    let version_ids = versions
        .iter()
        .filter_map(|entry| entry["versionId"].as_str())
        .collect::<Vec<_>>();
    assert!(
        version_ids.len() >= 2,
        "expected at least two merged versions, got response: {body}"
    );
    assert_eq!(body["metadataCoverage"]["expectedNodes"], 2);
    assert_eq!(body["metadataCoverage"]["respondedNodes"], 2);
    assert_eq!(body["metadataCoverage"]["missingNodes"], 0);
    assert_eq!(body["metadataCoverage"]["unexpectedNodes"], 0);
    assert_eq!(body["metadataCoverage"]["complete"], true);
    assert_eq!(
        body["metadataCoverage"]["source"],
        "request-time-aggregation"
    );
}

#[tokio::test]
async fn test_console_list_versions_consensus_index_merges_peer_state_when_ready() {
    let shared_token = "console-versions-listing-consensus-shared-token";
    let bucket = "console-versions-listing-consensus";
    let key = "docs/readme.txt";
    let owner_node_id = "127.0.0.1:39244";
    let owner_cluster_peers = vec!["node-a.internal:9000".to_string()];
    let owner_membership_view_id =
        consensus_membership_view_id(owner_node_id, owner_cluster_peers.as_slice());

    let owner_tmp = TempDir::new().unwrap();
    let owner_data_dir = owner_tmp.path().to_string_lossy().to_string();
    let bucket_state = BucketMetadataState {
        bucket: bucket.to_string(),
        versioning_enabled: true,
        lifecycle_enabled: false,
    };
    seed_consensus_metadata_buckets(
        &owner_data_dir,
        owner_membership_view_id.as_str(),
        std::slice::from_ref(&bucket_state),
    );
    seed_object_in_data_dir(&owner_data_dir, bucket, key, b"peer-version", true).await;
    let owner_versions = list_object_versions_from_data_dir(&owner_data_dir, bucket, key).await;
    let mut owner_config = make_test_config(owner_data_dir, false, 10 * 1024 * 1024, 0);
    owner_config.node_id = owner_node_id.to_string();
    owner_config.cluster_peers = owner_cluster_peers;
    owner_config.cluster_auth_token = Some(shared_token.to_string());
    owner_config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    let (owner_url, _owner_tmp) = start_server_with_config(owner_config, owner_tmp).await;

    let peer_endpoint = host_port_from_base_url(&owner_url);
    let coordinator_node_id = "node-a.internal:9000";
    let coordinator_cluster_peers = vec![peer_endpoint.clone()];
    let coordinator_membership_view_id =
        consensus_membership_view_id(coordinator_node_id, coordinator_cluster_peers.as_slice());
    let coordinator_tmp = TempDir::new().unwrap();
    let coordinator_data_dir = coordinator_tmp.path().to_string_lossy().to_string();
    seed_consensus_metadata_buckets(
        &coordinator_data_dir,
        coordinator_membership_view_id.as_str(),
        std::slice::from_ref(&bucket_state),
    );
    seed_object_in_data_dir(&coordinator_data_dir, bucket, key, b"local-version", true).await;
    let coordinator_versions =
        list_object_versions_from_data_dir(&coordinator_data_dir, bucket, key).await;
    let mut canonical_versions = owner_versions
        .iter()
        .chain(coordinator_versions.iter())
        .filter_map(|version| {
            version
                .version_id
                .as_ref()
                .map(|version_id| ObjectVersionMetadataState {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                    version_id: version_id.clone(),
                    is_delete_marker: version.is_delete_marker,
                    is_latest: false,
                })
        })
        .collect::<Vec<_>>();
    if let Some(first) = canonical_versions.first_mut() {
        first.is_latest = true;
    }
    seed_consensus_metadata_object_version_rows(
        &coordinator_data_dir,
        coordinator_membership_view_id.as_str(),
        std::slice::from_ref(&bucket_state),
        canonical_versions.as_slice(),
    );
    let mut coordinator_config = make_test_config(coordinator_data_dir, false, 10 * 1024 * 1024, 0);
    coordinator_config.node_id = coordinator_node_id.to_string();
    coordinator_config.cluster_peers = coordinator_cluster_peers;
    coordinator_config.cluster_auth_token = Some(shared_token.to_string());
    coordinator_config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    let (coordinator_url, _coordinator_tmp) =
        start_server_with_config(coordinator_config, coordinator_tmp).await;

    let cookie = console_login_cookie(&coordinator_url).await;
    let list = client()
        .get(format!(
            "{}/api/buckets/{}/versions?key={}",
            coordinator_url, bucket, key
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), 200);
    let body: serde_json::Value = list.json().await.unwrap();

    let versions = body["versions"]
        .as_array()
        .expect("versions should be an array");
    let version_ids = versions
        .iter()
        .filter_map(|entry| entry["versionId"].as_str())
        .collect::<Vec<_>>();
    assert!(
        version_ids.len() >= 2,
        "expected at least two merged versions, got response: {body}"
    );
    assert_eq!(body["metadataCoverage"]["expectedNodes"], 2);
    assert_eq!(body["metadataCoverage"]["respondedNodes"], 2);
    assert_eq!(body["metadataCoverage"]["missingNodes"], 0);
    assert_eq!(body["metadataCoverage"]["unexpectedNodes"], 0);
    assert_eq!(body["metadataCoverage"]["complete"], true);
    assert_eq!(body["metadataCoverage"]["source"], "consensus-index");
}

#[tokio::test]
async fn test_console_list_versions_consensus_index_does_not_fallback_to_local_storage() {
    let shared_token = "console-versions-listing-consensus-authoritative-token";
    let bucket = "console-versions-listing-consensus-authoritative";
    let key = "docs/readme.txt";
    let owner_node_id = "127.0.0.1:39246";
    let owner_cluster_peers = vec!["node-a.internal:9000".to_string()];
    let owner_membership_view_id =
        consensus_membership_view_id(owner_node_id, owner_cluster_peers.as_slice());

    let bucket_state = BucketMetadataState {
        bucket: bucket.to_string(),
        versioning_enabled: true,
        lifecycle_enabled: false,
    };

    let owner_tmp = TempDir::new().unwrap();
    let owner_data_dir = owner_tmp.path().to_string_lossy().to_string();
    seed_consensus_metadata_buckets(
        &owner_data_dir,
        owner_membership_view_id.as_str(),
        std::slice::from_ref(&bucket_state),
    );
    seed_object_in_data_dir(&owner_data_dir, bucket, key, b"peer-version", true).await;
    let mut owner_config = make_test_config(owner_data_dir, false, 10 * 1024 * 1024, 0);
    owner_config.node_id = owner_node_id.to_string();
    owner_config.cluster_peers = owner_cluster_peers;
    owner_config.cluster_auth_token = Some(shared_token.to_string());
    owner_config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    let (owner_url, _owner_tmp) = start_server_with_config(owner_config, owner_tmp).await;

    let peer_endpoint = host_port_from_base_url(&owner_url);
    let coordinator_node_id = "node-a.internal:9000";
    let coordinator_cluster_peers = vec![peer_endpoint.clone()];
    let coordinator_membership_view_id =
        consensus_membership_view_id(coordinator_node_id, coordinator_cluster_peers.as_slice());
    let coordinator_tmp = TempDir::new().unwrap();
    let coordinator_data_dir = coordinator_tmp.path().to_string_lossy().to_string();
    seed_consensus_metadata_buckets(
        &coordinator_data_dir,
        coordinator_membership_view_id.as_str(),
        std::slice::from_ref(&bucket_state),
    );
    seed_object_in_data_dir(&coordinator_data_dir, bucket, key, b"local-version", true).await;
    seed_consensus_metadata_object_version_rows(
        &coordinator_data_dir,
        coordinator_membership_view_id.as_str(),
        std::slice::from_ref(&bucket_state),
        &[],
    );
    let mut coordinator_config = make_test_config(coordinator_data_dir, false, 10 * 1024 * 1024, 0);
    coordinator_config.node_id = coordinator_node_id.to_string();
    coordinator_config.cluster_peers = coordinator_cluster_peers;
    coordinator_config.cluster_auth_token = Some(shared_token.to_string());
    coordinator_config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    let (coordinator_url, _coordinator_tmp) =
        start_server_with_config(coordinator_config, coordinator_tmp).await;

    let cookie = console_login_cookie(&coordinator_url).await;
    let list = client()
        .get(format!(
            "{}/api/buckets/{}/versions?key={}",
            coordinator_url, bucket, key
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), 200);
    let body: serde_json::Value = list.json().await.unwrap();
    let versions = body["versions"]
        .as_array()
        .expect("versions should be an array");
    assert!(versions.is_empty(), "unexpected response body: {body}");
    assert_eq!(body["metadataCoverage"]["expectedNodes"], 2);
    assert_eq!(body["metadataCoverage"]["respondedNodes"], 2);
    assert_eq!(body["metadataCoverage"]["missingNodes"], 0);
    assert_eq!(body["metadataCoverage"]["unexpectedNodes"], 0);
    assert_eq!(body["metadataCoverage"]["complete"], true);
    assert_eq!(body["metadataCoverage"]["source"], "consensus-index");
}

#[tokio::test]
async fn test_console_list_versions_consensus_index_returns_service_unavailable_when_token_missing()
{
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let bucket = "console-consensus-versions-list-missing-token";
    let key = "docs/readme.txt";
    let node_id = "node-a.internal:9000";
    let cluster_peers = vec!["node-b.internal:9000".to_string()];
    let membership_view_id = consensus_membership_view_id(node_id, cluster_peers.as_slice());
    seed_consensus_metadata_buckets(
        &data_dir,
        membership_view_id.as_str(),
        &[BucketMetadataState {
            bucket: bucket.to_string(),
            versioning_enabled: true,
            lifecycle_enabled: false,
        }],
    );
    seed_object_in_data_dir(&data_dir, bucket, key, b"hello", true).await;

    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = node_id.to_string();
    config.cluster_peers = cluster_peers;
    config.cluster_auth_token = Some("shared-token".to_string());
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    config.cluster_auth_token = None;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let cookie = console_login_cookie(&base_url).await;

    let list = client()
        .get(format!(
            "{}/api/buckets/{}/versions?key={}",
            base_url, bucket, key
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), 503);
    let body: serde_json::Value = list.json().await.unwrap();
    assert_eq!(
        body["error"],
        "Distributed metadata listing strategy is not ready for this request (consensus-index-peer-fan-in-auth-token-missing)"
    );
}

#[tokio::test]
async fn test_console_list_versions_consensus_index_returns_service_unavailable_when_peer_fan_in_incomplete()
 {
    let shared_token = "console-consensus-versions-list-incomplete-shared-token";
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let bucket = "console-consensus-versions-list-incomplete";
    let key = "docs/readme.txt";
    let node_id = "node-a.internal:9000";
    let cluster_peers = vec!["node-b.internal:9000".to_string()];
    let membership_view_id = consensus_membership_view_id(node_id, cluster_peers.as_slice());
    seed_consensus_metadata_buckets(
        &data_dir,
        membership_view_id.as_str(),
        &[BucketMetadataState {
            bucket: bucket.to_string(),
            versioning_enabled: true,
            lifecycle_enabled: false,
        }],
    );
    seed_object_in_data_dir(&data_dir, bucket, key, b"hello", true).await;

    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = node_id.to_string();
    config.cluster_peers = cluster_peers;
    config.cluster_auth_token = Some("shared-token".to_string());
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    config.cluster_auth_token = Some(shared_token.to_string());
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let cookie = console_login_cookie(&base_url).await;

    let list = client()
        .get(format!(
            "{}/api/buckets/{}/versions?key={}",
            base_url, bucket, key
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), 503);
    let body: serde_json::Value = list.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|message| message.contains("missing-expected-nodes")),
        "unexpected body: {body}"
    );
}

#[tokio::test]
async fn test_console_create_bucket_request_time_aggregation_converges_peer_state_when_ready() {
    let shared_token = "console-bucket-create-shared-token";

    let owner_tmp = TempDir::new().unwrap();
    let owner_data_dir = owner_tmp.path().to_string_lossy().to_string();
    let mut owner_config = make_test_config(owner_data_dir, false, 10 * 1024 * 1024, 0);
    owner_config.node_id = "127.0.0.1:39110".to_string();
    owner_config.cluster_peers = vec!["node-a.internal:9000".to_string()];
    owner_config.cluster_auth_token = Some(shared_token.to_string());
    owner_config.metadata_listing_strategy = ClusterMetadataListingStrategy::LocalNodeOnly;
    let (owner_url, _owner_tmp) = start_server_with_config(owner_config, owner_tmp).await;

    let peer_endpoint = host_port_from_base_url(&owner_url);
    let coordinator_tmp = TempDir::new().unwrap();
    let coordinator_data_dir = coordinator_tmp.path().to_string_lossy().to_string();
    let mut coordinator_config = make_test_config(coordinator_data_dir, false, 10 * 1024 * 1024, 0);
    coordinator_config.node_id = "node-a.internal:9000".to_string();
    coordinator_config.cluster_peers = vec![peer_endpoint.clone()];
    coordinator_config.cluster_auth_token = Some(shared_token.to_string());
    coordinator_config.metadata_listing_strategy =
        ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (coordinator_url, _coordinator_tmp) =
        start_server_with_config(coordinator_config, coordinator_tmp).await;

    let coordinator_cookie = console_login_cookie(&coordinator_url).await;
    let bucket = "console-bucket-create-aggregate";
    let create = client()
        .post(format!("{}/api/buckets", coordinator_url))
        .header("cookie", &coordinator_cookie)
        .header("content-type", "application/json")
        .json(&serde_json::json!({ "name": bucket }))
        .send()
        .await
        .unwrap();
    assert_eq!(create.status(), 200);
    let body: serde_json::Value = create.json().await.unwrap();
    assert_eq!(body, serde_json::json!({ "ok": true }));

    let owner_head = s3_request("HEAD", &format!("{}/{}", owner_url, bucket), vec![]).await;
    assert_eq!(owner_head.status(), 200);
}

#[tokio::test]
async fn test_console_create_bucket_request_time_aggregation_succeeds_when_peer_already_has_bucket()
{
    let shared_token = "console-bucket-create-peer-existing-shared-token";

    let owner_tmp = TempDir::new().unwrap();
    let owner_data_dir = owner_tmp.path().to_string_lossy().to_string();
    let mut owner_config = make_test_config(owner_data_dir, false, 10 * 1024 * 1024, 0);
    owner_config.node_id = "127.0.0.1:39111".to_string();
    owner_config.cluster_peers = vec!["node-a.internal:9000".to_string()];
    owner_config.cluster_auth_token = Some(shared_token.to_string());
    owner_config.metadata_listing_strategy = ClusterMetadataListingStrategy::LocalNodeOnly;
    let (owner_url, _owner_tmp) = start_server_with_config(owner_config, owner_tmp).await;

    let peer_endpoint = host_port_from_base_url(&owner_url);
    let coordinator_tmp = TempDir::new().unwrap();
    let coordinator_data_dir = coordinator_tmp.path().to_string_lossy().to_string();
    let mut coordinator_config = make_test_config(coordinator_data_dir, false, 10 * 1024 * 1024, 0);
    coordinator_config.node_id = "node-a.internal:9000".to_string();
    coordinator_config.cluster_peers = vec![peer_endpoint];
    coordinator_config.cluster_auth_token = Some(shared_token.to_string());
    coordinator_config.metadata_listing_strategy =
        ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (coordinator_url, _coordinator_tmp) =
        start_server_with_config(coordinator_config, coordinator_tmp).await;

    let coordinator_cookie = console_login_cookie(&coordinator_url).await;
    let bucket = "console-bucket-create-peer-existing";
    let create_peer = s3_request("PUT", &format!("{}/{}", owner_url, bucket), vec![]).await;
    assert_eq!(create_peer.status(), 200);

    let create = client()
        .post(format!("{}/api/buckets", coordinator_url))
        .header("cookie", &coordinator_cookie)
        .header("content-type", "application/json")
        .json(&serde_json::json!({ "name": bucket }))
        .send()
        .await
        .unwrap();
    assert_eq!(create.status(), 200);
    let body: serde_json::Value = create.json().await.unwrap();
    assert_eq!(body, serde_json::json!({ "ok": true }));

    let coordinator_head =
        s3_request("HEAD", &format!("{}/{}", coordinator_url, bucket), vec![]).await;
    assert_eq!(coordinator_head.status(), 200);
}

#[tokio::test]
async fn test_console_delete_bucket_request_time_aggregation_converges_peer_state_when_ready() {
    let shared_token = "console-bucket-delete-shared-token";

    let owner_tmp = TempDir::new().unwrap();
    let owner_data_dir = owner_tmp.path().to_string_lossy().to_string();
    let mut owner_config = make_test_config(owner_data_dir, false, 10 * 1024 * 1024, 0);
    owner_config.node_id = "127.0.0.1:39112".to_string();
    owner_config.cluster_peers = vec!["node-a.internal:9000".to_string()];
    owner_config.cluster_auth_token = Some(shared_token.to_string());
    owner_config.metadata_listing_strategy = ClusterMetadataListingStrategy::LocalNodeOnly;
    let (owner_url, _owner_tmp) = start_server_with_config(owner_config, owner_tmp).await;

    let peer_endpoint = host_port_from_base_url(&owner_url);
    let coordinator_tmp = TempDir::new().unwrap();
    let coordinator_data_dir = coordinator_tmp.path().to_string_lossy().to_string();
    let mut coordinator_config = make_test_config(coordinator_data_dir, false, 10 * 1024 * 1024, 0);
    coordinator_config.node_id = "node-a.internal:9000".to_string();
    coordinator_config.cluster_peers = vec![peer_endpoint.clone()];
    coordinator_config.cluster_auth_token = Some(shared_token.to_string());
    coordinator_config.metadata_listing_strategy =
        ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (coordinator_url, _coordinator_tmp) =
        start_server_with_config(coordinator_config, coordinator_tmp).await;

    let coordinator_cookie = console_login_cookie(&coordinator_url).await;
    let bucket = "console-bucket-delete-aggregate";
    let create = s3_request("PUT", &format!("{}/{}", coordinator_url, bucket), vec![]).await;
    assert_eq!(create.status(), 200);

    let delete = client()
        .delete(format!("{}/api/buckets/{}", coordinator_url, bucket))
        .header("cookie", &coordinator_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), 200);
    let body: serde_json::Value = delete.json().await.unwrap();
    assert_eq!(body, serde_json::json!({ "ok": true }));

    let coordinator_head =
        s3_request("HEAD", &format!("{}/{}", coordinator_url, bucket), vec![]).await;
    assert_eq!(coordinator_head.status(), 404);
    let owner_head = s3_request("HEAD", &format!("{}/{}", owner_url, bucket), vec![]).await;
    assert_eq!(owner_head.status(), 404);
}

#[tokio::test]
async fn test_console_get_bucket_versioning_request_time_aggregation_merges_peer_state_when_ready()
{
    let shared_token = "console-versioning-read-shared-token";
    let coordinator_node_id = "node-a.internal:9000";

    let owner_tmp = TempDir::new().unwrap();
    let owner_data_dir = owner_tmp.path().to_string_lossy().to_string();
    let mut owner_config = make_test_config(owner_data_dir, false, 10 * 1024 * 1024, 0);
    owner_config.node_id = "127.0.0.1:39102".to_string();
    owner_config.cluster_peers = vec![coordinator_node_id.to_string()];
    owner_config.cluster_auth_token = Some(shared_token.to_string());
    owner_config.metadata_listing_strategy = ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (owner_url, _owner_tmp) = start_server_with_config(owner_config, owner_tmp).await;

    let peer_endpoint = host_port_from_base_url(&owner_url);
    let coordinator_tmp = TempDir::new().unwrap();
    let coordinator_data_dir = coordinator_tmp.path().to_string_lossy().to_string();
    let mut coordinator_config = make_test_config(coordinator_data_dir, false, 10 * 1024 * 1024, 0);
    coordinator_config.node_id = coordinator_node_id.to_string();
    coordinator_config.cluster_peers = vec![peer_endpoint];
    coordinator_config.cluster_auth_token = Some(shared_token.to_string());
    coordinator_config.metadata_listing_strategy =
        ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (coordinator_url, _coordinator_tmp) =
        start_server_with_config(coordinator_config, coordinator_tmp).await;

    let coordinator_cookie = console_login_cookie(&coordinator_url).await;
    let bucket = "console-versioning-aggregate";
    let create_local = s3_request("PUT", &format!("{}/{}", coordinator_url, bucket), vec![]).await;
    assert_eq!(create_local.status(), 200);

    let set_local = client()
        .put(format!(
            "{}/api/buckets/{}/versioning",
            coordinator_url, bucket
        ))
        .header("cookie", &coordinator_cookie)
        .header("content-type", "application/json")
        .json(&serde_json::json!({ "enabled": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(set_local.status(), 200);

    let get = client()
        .get(format!(
            "{}/api/buckets/{}/versioning",
            coordinator_url, bucket
        ))
        .header("cookie", &coordinator_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 200);
    let body: serde_json::Value = get.json().await.unwrap();
    assert_eq!(body["enabled"], true);
}

#[tokio::test]
async fn test_console_get_bucket_versioning_request_time_aggregation_rejects_inconsistent_peer_state()
 {
    let shared_token = "console-versioning-inconsistent-shared-token";

    let owner_tmp = TempDir::new().unwrap();
    let owner_data_dir = owner_tmp.path().to_string_lossy().to_string();
    let mut owner_config = make_test_config(owner_data_dir, false, 10 * 1024 * 1024, 0);
    owner_config.node_id = "127.0.0.1:39103".to_string();
    owner_config.cluster_peers = vec!["node-a.internal:9000".to_string()];
    owner_config.cluster_auth_token = Some(shared_token.to_string());
    owner_config.metadata_listing_strategy = ClusterMetadataListingStrategy::LocalNodeOnly;
    let (owner_url, _owner_tmp) = start_server_with_config(owner_config, owner_tmp).await;

    let peer_endpoint = host_port_from_base_url(&owner_url);
    let coordinator_tmp = TempDir::new().unwrap();
    let coordinator_data_dir = coordinator_tmp.path().to_string_lossy().to_string();
    let mut coordinator_config = make_test_config(coordinator_data_dir, false, 10 * 1024 * 1024, 0);
    coordinator_config.node_id = "node-a.internal:9000".to_string();
    coordinator_config.cluster_peers = vec![peer_endpoint];
    coordinator_config.cluster_auth_token = Some(shared_token.to_string());
    coordinator_config.metadata_listing_strategy =
        ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (coordinator_url, _coordinator_tmp) =
        start_server_with_config(coordinator_config, coordinator_tmp).await;

    let coordinator_cookie = console_login_cookie(&coordinator_url).await;
    let owner_cookie = console_login_cookie(&owner_url).await;
    let bucket = "console-versioning-inconsistent";
    let create_local = s3_request("PUT", &format!("{}/{}", coordinator_url, bucket), vec![]).await;
    assert_eq!(create_local.status(), 200);
    let create_peer = s3_request("PUT", &format!("{}/{}", owner_url, bucket), vec![]).await;
    assert!(
        matches!(create_peer.status().as_u16(), 200 | 409),
        "expected peer create to return 200 or 409, got {}",
        create_peer.status().as_u16()
    );

    let set_local = client()
        .put(format!(
            "{}/api/buckets/{}/versioning",
            coordinator_url, bucket
        ))
        .header("cookie", &coordinator_cookie)
        .header("content-type", "application/json")
        .json(&serde_json::json!({ "enabled": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(set_local.status(), 200);
    let set_peer = client()
        .put(format!("{}/api/buckets/{}/versioning", owner_url, bucket))
        .header("cookie", &owner_cookie)
        .header("content-type", "application/json")
        .json(&serde_json::json!({ "enabled": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(set_peer.status(), 200);

    let get = client()
        .get(format!(
            "{}/api/buckets/{}/versioning",
            coordinator_url, bucket
        ))
        .header("cookie", &coordinator_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 503);
    let body: serde_json::Value = get.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|message| message.contains("inconsistent")),
        "unexpected body: {body}"
    );
}

#[tokio::test]
async fn test_console_get_bucket_lifecycle_request_time_aggregation_merges_peer_state_when_ready() {
    let shared_token = "console-lifecycle-read-shared-token";

    let owner_tmp = TempDir::new().unwrap();
    let owner_data_dir = owner_tmp.path().to_string_lossy().to_string();
    let mut owner_config = make_test_config(owner_data_dir, false, 10 * 1024 * 1024, 0);
    owner_config.node_id = "127.0.0.1:39104".to_string();
    owner_config.cluster_peers = vec!["node-a.internal:9000".to_string()];
    owner_config.cluster_auth_token = Some(shared_token.to_string());
    owner_config.metadata_listing_strategy = ClusterMetadataListingStrategy::LocalNodeOnly;
    let (owner_url, _owner_tmp) = start_server_with_config(owner_config, owner_tmp).await;

    let peer_endpoint = host_port_from_base_url(&owner_url);
    let coordinator_tmp = TempDir::new().unwrap();
    let coordinator_data_dir = coordinator_tmp.path().to_string_lossy().to_string();
    let mut coordinator_config = make_test_config(coordinator_data_dir, false, 10 * 1024 * 1024, 0);
    coordinator_config.node_id = "node-a.internal:9000".to_string();
    coordinator_config.cluster_peers = vec![peer_endpoint];
    coordinator_config.cluster_auth_token = Some(shared_token.to_string());
    coordinator_config.metadata_listing_strategy =
        ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (coordinator_url, _coordinator_tmp) =
        start_server_with_config(coordinator_config, coordinator_tmp).await;

    let coordinator_cookie = console_login_cookie(&coordinator_url).await;
    let owner_cookie = console_login_cookie(&owner_url).await;
    let bucket = "console-lifecycle-aggregate";
    let create_local = s3_request("PUT", &format!("{}/{}", coordinator_url, bucket), vec![]).await;
    assert_eq!(create_local.status(), 200);
    let create_peer = s3_request("PUT", &format!("{}/{}", owner_url, bucket), vec![]).await;
    assert!(
        matches!(create_peer.status().as_u16(), 200 | 409),
        "expected peer create to return 200 or 409, got {}",
        create_peer.status().as_u16()
    );

    let lifecycle_payload = serde_json::json!({
        "rules": [{
            "id": "expire-cache",
            "prefix": "cache/",
            "expirationDays": 7,
            "enabled": true
        }]
    });
    let set_local = client()
        .put(format!(
            "{}/api/buckets/{}/lifecycle",
            coordinator_url, bucket
        ))
        .header("cookie", &coordinator_cookie)
        .header("content-type", "application/json")
        .json(&lifecycle_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(set_local.status(), 200);
    let set_peer = client()
        .put(format!("{}/api/buckets/{}/lifecycle", owner_url, bucket))
        .header("cookie", &owner_cookie)
        .header("content-type", "application/json")
        .json(&lifecycle_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(set_peer.status(), 200);

    let get = client()
        .get(format!(
            "{}/api/buckets/{}/lifecycle",
            coordinator_url, bucket
        ))
        .header("cookie", &coordinator_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 200);
    let body: serde_json::Value = get.json().await.unwrap();
    let rules = body["rules"].as_array().expect("rules should be an array");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["id"], "expire-cache");
    assert_eq!(rules[0]["prefix"], "cache/");
    assert_eq!(rules[0]["expirationDays"], 7);
    assert_eq!(rules[0]["enabled"], true);
}

#[tokio::test]
async fn test_console_get_bucket_lifecycle_request_time_aggregation_rejects_inconsistent_peer_state()
 {
    let shared_token = "console-lifecycle-inconsistent-shared-token";

    let owner_tmp = TempDir::new().unwrap();
    let owner_data_dir = owner_tmp.path().to_string_lossy().to_string();
    let mut owner_config = make_test_config(owner_data_dir, false, 10 * 1024 * 1024, 0);
    owner_config.node_id = "127.0.0.1:39105".to_string();
    owner_config.cluster_peers = vec!["node-a.internal:9000".to_string()];
    owner_config.cluster_auth_token = Some(shared_token.to_string());
    owner_config.metadata_listing_strategy = ClusterMetadataListingStrategy::LocalNodeOnly;
    let (owner_url, _owner_tmp) = start_server_with_config(owner_config, owner_tmp).await;

    let peer_endpoint = host_port_from_base_url(&owner_url);
    let coordinator_tmp = TempDir::new().unwrap();
    let coordinator_data_dir = coordinator_tmp.path().to_string_lossy().to_string();
    let mut coordinator_config = make_test_config(coordinator_data_dir, false, 10 * 1024 * 1024, 0);
    coordinator_config.node_id = "node-a.internal:9000".to_string();
    coordinator_config.cluster_peers = vec![peer_endpoint];
    coordinator_config.cluster_auth_token = Some(shared_token.to_string());
    coordinator_config.metadata_listing_strategy =
        ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (coordinator_url, _coordinator_tmp) =
        start_server_with_config(coordinator_config, coordinator_tmp).await;

    let coordinator_cookie = console_login_cookie(&coordinator_url).await;
    let owner_cookie = console_login_cookie(&owner_url).await;
    let bucket = "console-lifecycle-inconsistent";
    let create_local = s3_request("PUT", &format!("{}/{}", coordinator_url, bucket), vec![]).await;
    assert_eq!(create_local.status(), 200);
    let create_peer = s3_request("PUT", &format!("{}/{}", owner_url, bucket), vec![]).await;
    assert!(
        matches!(create_peer.status().as_u16(), 200 | 409),
        "expected peer create to return 200 or 409, got {}",
        create_peer.status().as_u16()
    );

    let set_local = client()
        .put(format!(
            "{}/api/buckets/{}/lifecycle",
            coordinator_url, bucket
        ))
        .header("cookie", &coordinator_cookie)
        .header("content-type", "application/json")
        .json(&serde_json::json!({
            "rules": [{
                "id": "expire-cache",
                "prefix": "cache/",
                "expirationDays": 7,
                "enabled": true
            }]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(set_local.status(), 200);
    let set_peer = client()
        .put(format!("{}/api/buckets/{}/lifecycle", owner_url, bucket))
        .header("cookie", &owner_cookie)
        .header("content-type", "application/json")
        .json(&serde_json::json!({
            "rules": []
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(set_peer.status(), 200);

    let get = client()
        .get(format!(
            "{}/api/buckets/{}/lifecycle",
            coordinator_url, bucket
        ))
        .header("cookie", &coordinator_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 503);
    let body: serde_json::Value = get.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|message| message.contains("inconsistent")),
        "unexpected body: {body}"
    );
}

#[tokio::test]
async fn test_console_set_bucket_versioning_request_time_aggregation_converges_peer_state_when_ready()
 {
    let shared_token = "console-versioning-write-shared-token";

    let owner_tmp = TempDir::new().unwrap();
    let owner_data_dir = owner_tmp.path().to_string_lossy().to_string();
    let mut owner_config = make_test_config(owner_data_dir, false, 10 * 1024 * 1024, 0);
    owner_config.node_id = "127.0.0.1:39106".to_string();
    owner_config.cluster_peers = vec!["node-a.internal:9000".to_string()];
    owner_config.cluster_auth_token = Some(shared_token.to_string());
    owner_config.metadata_listing_strategy = ClusterMetadataListingStrategy::LocalNodeOnly;
    let (owner_url, _owner_tmp) = start_server_with_config(owner_config, owner_tmp).await;

    let peer_endpoint = host_port_from_base_url(&owner_url);
    let coordinator_tmp = TempDir::new().unwrap();
    let coordinator_data_dir = coordinator_tmp.path().to_string_lossy().to_string();
    let mut coordinator_config = make_test_config(coordinator_data_dir, false, 10 * 1024 * 1024, 0);
    coordinator_config.node_id = "node-a.internal:9000".to_string();
    coordinator_config.cluster_peers = vec![peer_endpoint];
    coordinator_config.cluster_auth_token = Some(shared_token.to_string());
    coordinator_config.metadata_listing_strategy =
        ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (coordinator_url, _coordinator_tmp) =
        start_server_with_config(coordinator_config, coordinator_tmp).await;

    let coordinator_cookie = console_login_cookie(&coordinator_url).await;
    let owner_cookie = console_login_cookie(&owner_url).await;
    let bucket = "console-versioning-write-aggregate";

    let create_local = s3_request("PUT", &format!("{}/{}", coordinator_url, bucket), vec![]).await;
    assert_eq!(create_local.status(), 200);
    let create_peer = s3_request("PUT", &format!("{}/{}", owner_url, bucket), vec![]).await;
    assert!(
        matches!(create_peer.status().as_u16(), 200 | 409),
        "expected peer create to return 200 or 409, got {}",
        create_peer.status().as_u16()
    );

    let set = client()
        .put(format!(
            "{}/api/buckets/{}/versioning",
            coordinator_url, bucket
        ))
        .header("cookie", &coordinator_cookie)
        .header("content-type", "application/json")
        .json(&serde_json::json!({ "enabled": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(set.status(), 200);

    let peer_get = client()
        .get(format!("{}/api/buckets/{}/versioning", owner_url, bucket))
        .header("cookie", &owner_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(peer_get.status(), 200);
    let body: serde_json::Value = peer_get.json().await.unwrap();
    assert_eq!(body["enabled"], true);
}

#[tokio::test]
async fn test_console_set_bucket_versioning_request_time_aggregation_returns_service_unavailable_when_peer_missing_bucket()
 {
    let shared_token = "console-versioning-write-missing-bucket-shared-token";

    let owner_tmp = TempDir::new().unwrap();
    let owner_data_dir = owner_tmp.path().to_string_lossy().to_string();
    let mut owner_config = make_test_config(owner_data_dir, false, 10 * 1024 * 1024, 0);
    owner_config.node_id = "127.0.0.1:39107".to_string();
    owner_config.cluster_peers = vec!["node-a.internal:9000".to_string()];
    owner_config.cluster_auth_token = Some(shared_token.to_string());
    owner_config.metadata_listing_strategy = ClusterMetadataListingStrategy::LocalNodeOnly;
    let (owner_url, _owner_tmp) = start_server_with_config(owner_config, owner_tmp).await;

    let peer_endpoint = host_port_from_base_url(&owner_url);
    let coordinator_tmp = TempDir::new().unwrap();
    let coordinator_data_dir = coordinator_tmp.path().to_string_lossy().to_string();
    let mut coordinator_config = make_test_config(coordinator_data_dir, false, 10 * 1024 * 1024, 0);
    coordinator_config.node_id = "node-a.internal:9000".to_string();
    coordinator_config.cluster_peers = vec![peer_endpoint];
    coordinator_config.cluster_auth_token = Some(shared_token.to_string());
    coordinator_config.metadata_listing_strategy =
        ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (coordinator_url, _coordinator_tmp) =
        start_server_with_config(coordinator_config, coordinator_tmp).await;

    let coordinator_cookie = console_login_cookie(&coordinator_url).await;
    let bucket = "console-versioning-write-missing-bucket";

    let create_local = s3_request("PUT", &format!("{}/{}", coordinator_url, bucket), vec![]).await;
    assert_eq!(create_local.status(), 200);
    let owner_delete = s3_request_with_headers(
        "DELETE",
        &format!("{owner_url}/{bucket}?x-maxio-internal-metadata-scope=local-node-only"),
        vec![],
        vec![
            ("x-maxio-forwarded-by", "node-a.internal:9000"),
            ("x-maxio-internal-auth-token", shared_token),
        ],
    )
    .await;
    assert_eq!(owner_delete.status(), 204);

    let set = client()
        .put(format!(
            "{}/api/buckets/{}/versioning",
            coordinator_url, bucket
        ))
        .header("cookie", &coordinator_cookie)
        .header("content-type", "application/json")
        .json(&serde_json::json!({ "enabled": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(set.status(), 503);
    let body: serde_json::Value = set.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|message| message.contains("SetBucketVersioning")),
        "unexpected body: {body}"
    );
}

#[tokio::test]
async fn test_console_set_bucket_lifecycle_request_time_aggregation_converges_peer_state_when_ready()
 {
    let shared_token = "console-lifecycle-write-shared-token";

    let owner_tmp = TempDir::new().unwrap();
    let owner_data_dir = owner_tmp.path().to_string_lossy().to_string();
    let mut owner_config = make_test_config(owner_data_dir, false, 10 * 1024 * 1024, 0);
    owner_config.node_id = "127.0.0.1:39108".to_string();
    owner_config.cluster_peers = vec!["node-a.internal:9000".to_string()];
    owner_config.cluster_auth_token = Some(shared_token.to_string());
    owner_config.metadata_listing_strategy = ClusterMetadataListingStrategy::LocalNodeOnly;
    let (owner_url, _owner_tmp) = start_server_with_config(owner_config, owner_tmp).await;

    let peer_endpoint = host_port_from_base_url(&owner_url);
    let coordinator_tmp = TempDir::new().unwrap();
    let coordinator_data_dir = coordinator_tmp.path().to_string_lossy().to_string();
    let mut coordinator_config = make_test_config(coordinator_data_dir, false, 10 * 1024 * 1024, 0);
    coordinator_config.node_id = "node-a.internal:9000".to_string();
    coordinator_config.cluster_peers = vec![peer_endpoint];
    coordinator_config.cluster_auth_token = Some(shared_token.to_string());
    coordinator_config.metadata_listing_strategy =
        ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (coordinator_url, _coordinator_tmp) =
        start_server_with_config(coordinator_config, coordinator_tmp).await;

    let coordinator_cookie = console_login_cookie(&coordinator_url).await;
    let owner_cookie = console_login_cookie(&owner_url).await;
    let bucket = "console-lifecycle-write-aggregate";

    let create_local = s3_request("PUT", &format!("{}/{}", coordinator_url, bucket), vec![]).await;
    assert_eq!(create_local.status(), 200);
    let create_peer = s3_request("PUT", &format!("{}/{}", owner_url, bucket), vec![]).await;
    assert!(
        matches!(create_peer.status().as_u16(), 200 | 409),
        "expected peer create to return 200 or 409, got {}",
        create_peer.status().as_u16()
    );

    let payload = serde_json::json!({
        "rules": [{
            "id": "expire-cache",
            "prefix": "cache/",
            "expirationDays": 7,
            "enabled": true
        }]
    });
    let set = client()
        .put(format!(
            "{}/api/buckets/{}/lifecycle",
            coordinator_url, bucket
        ))
        .header("cookie", &coordinator_cookie)
        .header("content-type", "application/json")
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(set.status(), 200);

    let peer_get = client()
        .get(format!("{}/api/buckets/{}/lifecycle", owner_url, bucket))
        .header("cookie", &owner_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(peer_get.status(), 200);
    let body: serde_json::Value = peer_get.json().await.unwrap();
    let rules = body["rules"].as_array().expect("rules should be an array");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["id"], "expire-cache");
    assert_eq!(rules[0]["prefix"], "cache/");
    assert_eq!(rules[0]["expirationDays"], 7);
    assert_eq!(rules[0]["enabled"], true);
}

#[tokio::test]
async fn test_console_set_bucket_lifecycle_request_time_aggregation_delete_converges_peer_state_when_ready()
 {
    let shared_token = "console-lifecycle-delete-write-shared-token";

    let owner_tmp = TempDir::new().unwrap();
    let owner_data_dir = owner_tmp.path().to_string_lossy().to_string();
    let mut owner_config = make_test_config(owner_data_dir, false, 10 * 1024 * 1024, 0);
    owner_config.node_id = "127.0.0.1:39109".to_string();
    owner_config.cluster_peers = vec!["node-a.internal:9000".to_string()];
    owner_config.cluster_auth_token = Some(shared_token.to_string());
    owner_config.metadata_listing_strategy = ClusterMetadataListingStrategy::LocalNodeOnly;
    let (owner_url, _owner_tmp) = start_server_with_config(owner_config, owner_tmp).await;

    let peer_endpoint = host_port_from_base_url(&owner_url);
    let coordinator_tmp = TempDir::new().unwrap();
    let coordinator_data_dir = coordinator_tmp.path().to_string_lossy().to_string();
    let mut coordinator_config = make_test_config(coordinator_data_dir, false, 10 * 1024 * 1024, 0);
    coordinator_config.node_id = "node-a.internal:9000".to_string();
    coordinator_config.cluster_peers = vec![peer_endpoint];
    coordinator_config.cluster_auth_token = Some(shared_token.to_string());
    coordinator_config.metadata_listing_strategy =
        ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (coordinator_url, _coordinator_tmp) =
        start_server_with_config(coordinator_config, coordinator_tmp).await;

    let coordinator_cookie = console_login_cookie(&coordinator_url).await;
    let owner_cookie = console_login_cookie(&owner_url).await;
    let bucket = "console-lifecycle-delete-write-aggregate";

    let create_local = s3_request("PUT", &format!("{}/{}", coordinator_url, bucket), vec![]).await;
    assert_eq!(create_local.status(), 200);
    let create_peer = s3_request("PUT", &format!("{}/{}", owner_url, bucket), vec![]).await;
    assert!(
        matches!(create_peer.status().as_u16(), 200 | 409),
        "expected peer create to return 200 or 409, got {}",
        create_peer.status().as_u16()
    );

    let set = client()
        .put(format!(
            "{}/api/buckets/{}/lifecycle",
            coordinator_url, bucket
        ))
        .header("cookie", &coordinator_cookie)
        .header("content-type", "application/json")
        .json(&serde_json::json!({
            "rules": [{
                "id": "expire-cache",
                "prefix": "cache/",
                "expirationDays": 7,
                "enabled": true
            }]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(set.status(), 200);

    let clear = client()
        .put(format!(
            "{}/api/buckets/{}/lifecycle",
            coordinator_url, bucket
        ))
        .header("cookie", &coordinator_cookie)
        .header("content-type", "application/json")
        .json(&serde_json::json!({ "rules": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(clear.status(), 200);

    let peer_get = client()
        .get(format!("{}/api/buckets/{}/lifecycle", owner_url, bucket))
        .header("cookie", &owner_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(peer_get.status(), 200);
    let body: serde_json::Value = peer_get.json().await.unwrap();
    assert_eq!(body["rules"], serde_json::json!([]));
}

#[tokio::test]
async fn test_console_get_bucket_versioning_rejects_unready_authoritative_metadata_strategy() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let bucket = "console-get-versioning-unready";
    seed_bucket_in_data_dir(&data_dir, bucket).await;
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = "node-a.internal:9000".to_string();
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let cookie = console_login_cookie(&base_url).await;

    let get = client()
        .get(format!("{}/api/buckets/{}/versioning", base_url, bucket))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 503);
    let body: serde_json::Value = get.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|message| message.contains("GetBucketVersioning")),
        "unexpected body: {body}"
    );
}

#[tokio::test]
async fn test_console_get_bucket_versioning_consensus_index_uses_persisted_metadata_state() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let bucket = "console-consensus-versioning-persisted";
    let node_id = "node-a.internal:9000";
    let cluster_peers = vec!["node-b.internal:9000".to_string()];
    let membership_view_id = consensus_membership_view_id(node_id, cluster_peers.as_slice());
    seed_consensus_metadata_buckets(
        &data_dir,
        membership_view_id.as_str(),
        &[BucketMetadataState {
            bucket: bucket.to_string(),
            versioning_enabled: true,
            lifecycle_enabled: false,
        }],
    );
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = node_id.to_string();
    config.cluster_peers = cluster_peers;
    config.cluster_auth_token = Some("shared-token".to_string());
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let cookie = console_login_cookie(&base_url).await;

    let get = client()
        .get(format!("{}/api/buckets/{}/versioning", base_url, bucket))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 200);
    let body: serde_json::Value = get.json().await.unwrap();
    assert_eq!(body["enabled"], true);
}

#[tokio::test]
async fn test_console_get_bucket_versioning_consensus_index_rejects_persisted_view_mismatch() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let bucket = "console-consensus-versioning-view-mismatch";
    let node_id = "node-a.internal:9000";
    let cluster_peers = vec!["node-b.internal:9000".to_string()];
    seed_consensus_metadata_buckets(
        &data_dir,
        "view-console-consensus-versioning-mismatch",
        &[BucketMetadataState {
            bucket: bucket.to_string(),
            versioning_enabled: true,
            lifecycle_enabled: false,
        }],
    );
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = node_id.to_string();
    config.cluster_peers = cluster_peers;
    config.cluster_auth_token = Some("shared-token".to_string());
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let cookie = console_login_cookie(&base_url).await;

    let get = client()
        .get(format!("{}/api/buckets/{}/versioning", base_url, bucket))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 503);
    let body: serde_json::Value = get.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|message| message.contains("persisted metadata view mismatch")),
        "unexpected body: {body}"
    );
}

#[tokio::test]
async fn test_console_get_bucket_versioning_consensus_index_persists_local_mutation_state() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let node_id = "node-a.internal:9000";
    let cluster_peers = vec!["node-b.internal:9000".to_string()];
    let membership_view_id = consensus_membership_view_id(node_id, cluster_peers.as_slice());
    seed_consensus_metadata_buckets(&data_dir, membership_view_id.as_str(), &[]);
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = node_id.to_string();
    config.cluster_peers = cluster_peers;
    config.cluster_auth_token = Some("shared-token".to_string());
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let cookie = console_login_cookie(&base_url).await;

    let create = s3_request("PUT", &format!("{}/consensus-local-only", base_url), vec![]).await;
    assert_eq!(create.status(), 200);

    let get = client()
        .get(format!(
            "{}/api/buckets/{}/versioning",
            base_url, "consensus-local-only"
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 200);
    let body: serde_json::Value = get.json().await.unwrap();
    assert_eq!(body["enabled"], false);
}

#[tokio::test]
async fn test_console_get_bucket_lifecycle_consensus_index_returns_empty_rules_when_disabled() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let bucket = "console-consensus-lifecycle-disabled";
    let node_id = "node-a.internal:9000";
    let cluster_peers = vec!["node-b.internal:9000".to_string()];
    let membership_view_id = consensus_membership_view_id(node_id, cluster_peers.as_slice());
    seed_consensus_metadata_buckets(
        &data_dir,
        membership_view_id.as_str(),
        &[BucketMetadataState {
            bucket: bucket.to_string(),
            versioning_enabled: false,
            lifecycle_enabled: false,
        }],
    );
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = node_id.to_string();
    config.cluster_peers = cluster_peers;
    config.cluster_auth_token = Some("shared-token".to_string());
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let cookie = console_login_cookie(&base_url).await;

    let get = client()
        .get(format!("{}/api/buckets/{}/lifecycle", base_url, bucket))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 200);
    let body: serde_json::Value = get.json().await.unwrap();
    assert_eq!(body["rules"], serde_json::json!([]));
}

#[tokio::test]
async fn test_console_get_bucket_lifecycle_consensus_index_persists_local_mutation_state() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let node_id = "node-a.internal:9000";
    let cluster_peers = vec!["node-b.internal:9000".to_string()];
    let membership_view_id = consensus_membership_view_id(node_id, cluster_peers.as_slice());
    seed_consensus_metadata_buckets(&data_dir, membership_view_id.as_str(), &[]);
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = node_id.to_string();
    config.cluster_peers = cluster_peers;
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let cookie = console_login_cookie(&base_url).await;

    let create = s3_request(
        "PUT",
        &format!("{}/console-consensus-local-only", base_url),
        vec![],
    )
    .await;
    assert_eq!(create.status(), 200);

    let lifecycle_xml = br#"
      <LifecycleConfiguration>
        <Rule>
          <ID>expire-local</ID>
          <Status>Enabled</Status>
          <Filter><Prefix>logs/</Prefix></Filter>
          <Expiration><Days>7</Days></Expiration>
        </Rule>
      </LifecycleConfiguration>
    "#
    .to_vec();
    let put = s3_request(
        "PUT",
        &format!("{}/console-consensus-local-only?lifecycle", base_url),
        lifecycle_xml,
    )
    .await;
    assert_eq!(put.status(), 200);

    let get = client()
        .get(format!(
            "{}/api/buckets/{}/lifecycle",
            base_url, "console-consensus-local-only"
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 503);
    let body: serde_json::Value = get.json().await.unwrap();
    assert!(
        body["error"].as_str().is_some_and(
            |message| message.contains("consensus-index-peer-fan-in-auth-token-missing")
        ),
        "unexpected body: {body}"
    );
}

#[tokio::test]
async fn test_console_get_bucket_lifecycle_consensus_index_returns_service_unavailable_when_token_missing_for_enabled_rules()
 {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let bucket = "console-consensus-lifecycle-enabled";
    let node_id = "node-a.internal:9000";
    let cluster_peers = vec!["node-b.internal:9000".to_string()];
    let membership_view_id = consensus_membership_view_id(node_id, cluster_peers.as_slice());
    seed_consensus_metadata_buckets(
        &data_dir,
        membership_view_id.as_str(),
        &[BucketMetadataState {
            bucket: bucket.to_string(),
            versioning_enabled: false,
            lifecycle_enabled: true,
        }],
    );
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = node_id.to_string();
    config.cluster_peers = cluster_peers;
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let cookie = console_login_cookie(&base_url).await;

    let get = client()
        .get(format!("{}/api/buckets/{}/lifecycle", base_url, bucket))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 503);
    let body: serde_json::Value = get.json().await.unwrap();
    assert!(
        body["error"].as_str().is_some_and(
            |message| message.contains("consensus-index-peer-fan-in-auth-token-missing")
        ),
        "unexpected body: {body}"
    );
}

#[tokio::test]
async fn test_console_get_bucket_lifecycle_consensus_index_merges_peer_state_when_token_configured()
{
    let shared_token = "console-consensus-lifecycle-fan-in-shared-token";
    let bucket = "console-consensus-lifecycle-fan-in";
    let seeded_buckets = vec![BucketMetadataState {
        bucket: bucket.to_string(),
        versioning_enabled: false,
        lifecycle_enabled: true,
    }];
    let owner_node_id = "127.0.0.1:39112";
    let owner_cluster_peers = vec!["node-a.internal:9000".to_string()];
    let owner_membership_view_id =
        consensus_membership_view_id(owner_node_id, owner_cluster_peers.as_slice());

    let owner_tmp = TempDir::new().unwrap();
    let owner_data_dir = owner_tmp.path().to_string_lossy().to_string();
    seed_bucket_in_data_dir(&owner_data_dir, bucket).await;
    seed_consensus_metadata_buckets(
        &owner_data_dir,
        owner_membership_view_id.as_str(),
        seeded_buckets.as_slice(),
    );
    let mut owner_config = make_test_config(owner_data_dir, false, 10 * 1024 * 1024, 0);
    owner_config.node_id = owner_node_id.to_string();
    owner_config.cluster_peers = owner_cluster_peers;
    owner_config.cluster_auth_token = Some(shared_token.to_string());
    owner_config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    let (owner_url, _owner_tmp) = start_server_with_config(owner_config, owner_tmp).await;

    let peer_endpoint = host_port_from_base_url(&owner_url);
    let coordinator_node_id = "node-a.internal:9000";
    let coordinator_cluster_peers = vec![peer_endpoint.clone()];
    let coordinator_membership_view_id =
        consensus_membership_view_id(coordinator_node_id, coordinator_cluster_peers.as_slice());
    let coordinator_tmp = TempDir::new().unwrap();
    let coordinator_data_dir = coordinator_tmp.path().to_string_lossy().to_string();
    seed_bucket_in_data_dir(&coordinator_data_dir, bucket).await;
    seed_consensus_metadata_buckets(
        &coordinator_data_dir,
        coordinator_membership_view_id.as_str(),
        seeded_buckets.as_slice(),
    );
    let mut coordinator_config = make_test_config(coordinator_data_dir, false, 10 * 1024 * 1024, 0);
    coordinator_config.node_id = coordinator_node_id.to_string();
    coordinator_config.cluster_peers = coordinator_cluster_peers;
    coordinator_config.cluster_auth_token = Some(shared_token.to_string());
    coordinator_config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    let (coordinator_url, _coordinator_tmp) =
        start_server_with_config(coordinator_config, coordinator_tmp).await;

    let coordinator_cookie = console_login_cookie(&coordinator_url).await;

    let lifecycle_xml = br#"
      <LifecycleConfiguration>
        <Rule>
          <ID>console-consensus-fan-in-expiry</ID>
          <Status>Enabled</Status>
          <Filter><Prefix>logs/</Prefix></Filter>
          <Expiration><Days>7</Days></Expiration>
        </Rule>
      </LifecycleConfiguration>
    "#
    .to_vec();
    let coordinator_put = s3_request(
        "PUT",
        &format!("{}/{}?lifecycle", coordinator_url, bucket),
        lifecycle_xml.clone(),
    )
    .await;
    assert_eq!(coordinator_put.status(), 200);
    let owner_put = s3_request_with_headers(
        "PUT",
        &format!("{owner_url}/{bucket}?lifecycle&x-maxio-internal-metadata-scope=local-node-only"),
        lifecycle_xml,
        vec![
            ("x-maxio-forwarded-by", "node-a.internal:9000"),
            ("x-maxio-internal-auth-token", shared_token),
        ],
    )
    .await;
    assert_eq!(owner_put.status(), 200);

    let get = client()
        .get(format!(
            "{}/api/buckets/{}/lifecycle",
            coordinator_url, bucket
        ))
        .header("cookie", &coordinator_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 200);
    let body: serde_json::Value = get.json().await.unwrap();
    let rules = body["rules"].as_array().expect("rules should be an array");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["id"], "console-consensus-fan-in-expiry");
}

#[tokio::test]
async fn test_console_get_bucket_lifecycle_rejects_unready_authoritative_metadata_strategy() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let bucket = "console-get-lifecycle-unready";
    seed_bucket_in_data_dir(&data_dir, bucket).await;
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = "node-a.internal:9000".to_string();
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let cookie = console_login_cookie(&base_url).await;

    let get = client()
        .get(format!("{}/api/buckets/{}/lifecycle", base_url, bucket))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), 503);
    let body: serde_json::Value = get.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|message| message.contains("GetBucketLifecycle")),
        "unexpected body: {body}"
    );
}

#[tokio::test]
async fn test_console_list_buckets_rejects_unready_authoritative_metadata_strategy() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let bucket = "console-buckets-aggregation-unready";
    seed_bucket_in_data_dir(&data_dir, bucket).await;
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = "node-a.internal:9000".to_string();
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let cookie = console_login_cookie(&base_url).await;

    let list = client()
        .get(format!("{}/api/buckets", base_url))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), 503);
    let body: serde_json::Value = list.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|message| message.contains("missing-expected-nodes")),
        "unexpected body: {body}"
    );
}

#[tokio::test]
async fn test_console_create_bucket_rejects_unready_authoritative_metadata_strategy() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = "node-a.internal:9000".to_string();
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let cookie = console_login_cookie(&base_url).await;
    let bucket = "console-create-bucket-unready";

    let create = client()
        .post(format!("{}/api/buckets", base_url))
        .header("cookie", &cookie)
        .header("content-type", "application/json")
        .json(&serde_json::json!({ "name": bucket }))
        .send()
        .await
        .unwrap();
    assert_eq!(create.status(), 503);
    let body: serde_json::Value = create.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|message| message.contains("CreateBucket")),
        "unexpected body: {body}"
    );

    let head = s3_request("HEAD", &format!("{}/{}", base_url, bucket), vec![]).await;
    assert_eq!(head.status(), 503);
}

#[tokio::test]
async fn test_console_delete_bucket_rejects_unready_authoritative_metadata_strategy() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let bucket = "console-delete-bucket-unready";
    seed_bucket_in_data_dir(&data_dir, bucket).await;
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = "node-a.internal:9000".to_string();
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let cookie = console_login_cookie(&base_url).await;

    let delete = client()
        .delete(format!("{}/api/buckets/{}", base_url, bucket))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), 503);
    let body: serde_json::Value = delete.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|message| message.contains("DeleteBucket")),
        "unexpected body: {body}"
    );

    let head = s3_request("HEAD", &format!("{}/{}", base_url, bucket), vec![]).await;
    assert_eq!(head.status(), 503);
}

#[tokio::test]
async fn test_console_list_objects_rejects_unready_authoritative_metadata_strategy() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let bucket = "console-distributed-list-aggregation-unready";
    seed_bucket_in_data_dir(&data_dir, bucket).await;
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = "node-a.internal:9000".to_string();
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let cookie = console_login_cookie(&base_url).await;
    let put_object = s3_request(
        "PUT",
        &format!("{}/{}/docs/readme.txt", base_url, bucket),
        b"hello".to_vec(),
    )
    .await;
    assert_eq!(put_object.status(), 200);

    let list = client()
        .get(format!(
            "{}/api/buckets/{}/objects?prefix=docs/&delimiter=/",
            base_url, bucket
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), 503);
    let body: serde_json::Value = list.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|message| message.contains("missing-expected-nodes")),
        "unexpected body: {body}"
    );
}

#[tokio::test]
async fn test_console_list_versions_rejects_unready_authoritative_metadata_strategy() {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_string_lossy().to_string();
    let bucket = "console-distributed-versions-aggregation-unready";
    seed_bucket_in_data_dir(&data_dir, bucket).await;
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = "node-a.internal:9000".to_string();
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::RequestTimeAggregation;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let cookie = console_login_cookie(&base_url).await;
    let key = "docs/readme.txt";
    let enable_versioning = s3_request(
        "PUT",
        &format!("{}/{}?versioning=", base_url, bucket),
        br#"<?xml version="1.0" encoding="UTF-8"?>
<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
</VersioningConfiguration>"#
            .to_vec(),
    )
    .await;
    assert_eq!(enable_versioning.status(), 503);
    let put_object = s3_request(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, key),
        b"hello".to_vec(),
    )
    .await;
    assert_eq!(put_object.status(), 200);

    let list = client()
        .get(format!(
            "{}/api/buckets/{}/versions?key={}",
            base_url, bucket, key
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), 503);
    let body: serde_json::Value = list.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|message| message.contains("missing-expected-nodes")),
        "unexpected body: {body}"
    );
}

#[tokio::test]
async fn test_console_object_routes_support_percent_encoded_key_path() {
    let (base_url, _tmp) = start_server().await;
    let cookie = console_login_cookie(&base_url).await;
    let bucket = "console-download-encoded-bucket";
    let encoded_key = "reports/Jan%202026/qa%2Bnotes%20%231.txt";
    let decoded_key = "reports/Jan 2026/qa+notes #1.txt";
    let payload = b"console encoded payload".to_vec();

    let create_bucket = s3_request("PUT", &format!("{}/{}", base_url, bucket), vec![]).await;
    assert_eq!(create_bucket.status(), 200);

    let upload = client()
        .put(format!(
            "{}/api/buckets/{}/upload/{}",
            base_url, bucket, encoded_key
        ))
        .header("cookie", &cookie)
        .header("content-type", "text/plain")
        .body(payload.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), 200);

    let list = client()
        .get(format!(
            "{}/api/buckets/{}/objects?prefix=reports/Jan%202026/&delimiter=/",
            base_url, bucket
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), 200);
    let list_body: serde_json::Value = list.json().await.unwrap();
    let files = list_body["files"]
        .as_array()
        .expect("files should be an array");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["key"], decoded_key);

    let download = client()
        .get(format!(
            "{}/api/buckets/{}/download/{}",
            base_url, bucket, encoded_key
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(download.status(), 200);
    assert_eq!(download.bytes().await.unwrap().as_ref(), payload.as_slice());

    let delete = client()
        .delete(format!(
            "{}/api/buckets/{}/objects/{}",
            base_url, bucket, encoded_key
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), 200);
    let delete_body: serde_json::Value = delete.json().await.unwrap();
    assert_eq!(delete_body, serde_json::json!({ "ok": true }));

    let redownload = client()
        .get(format!(
            "{}/api/buckets/{}/download/{}",
            base_url, bucket, encoded_key
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(redownload.status(), 404);
    let redownload_body: serde_json::Value = redownload.json().await.unwrap();
    assert_eq!(redownload_body["error"], "Object not found");
}

#[tokio::test]
async fn test_console_download_version_returns_expected_headers_and_body() {
    let (base_url, _tmp) = start_server().await;
    let cookie = console_login_cookie(&base_url).await;
    let bucket = "console-version-download-bucket";
    let key = "docs/versioned.txt";

    let create_bucket = s3_request("PUT", &format!("{}/{}", base_url, bucket), vec![]).await;
    assert_eq!(create_bucket.status(), 200);

    let enable_versioning = s3_request(
        "PUT",
        &format!("{}/{}?versioning=", base_url, bucket),
        br#"<?xml version="1.0" encoding="UTF-8"?>
<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
</VersioningConfiguration>"#
            .to_vec(),
    )
    .await;
    assert_eq!(enable_versioning.status(), 200);

    let first_payload = b"v1-body".to_vec();
    let put_v1 = s3_request(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, key),
        first_payload.clone(),
    )
    .await;
    assert_eq!(put_v1.status(), 200);
    let v1_id = put_v1
        .headers()
        .get("x-amz-version-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing version id on first upload")
        .to_string();

    let put_v2 = s3_request(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, key),
        b"v2-body".to_vec(),
    )
    .await;
    assert_eq!(put_v2.status(), 200);

    let download = client()
        .get(format!(
            "{}/api/buckets/{}/versions/{}/download/{}",
            base_url, bucket, v1_id, key
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(download.status(), 200);
    let expected_len = first_payload.len().to_string();
    assert_eq!(
        download
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/octet-stream")
    );
    assert_eq!(
        download
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok()),
        Some(expected_len.as_str())
    );
    assert_eq!(
        download
            .headers()
            .get("content-disposition")
            .and_then(|v| v.to_str().ok()),
        Some("attachment; filename=\"versioned.txt\"")
    );
    assert_eq!(
        download.bytes().await.unwrap().as_ref(),
        first_payload.as_slice()
    );
}

#[tokio::test]
async fn test_console_download_version_supports_percent_encoded_key_path() {
    let (base_url, _tmp) = start_server().await;
    let cookie = console_login_cookie(&base_url).await;
    let bucket = "console-version-encoded-bucket";
    let encoded_key = "reports/Jan%202026/qa%2Bnotes%20%231.txt";
    let decoded_key = "reports/Jan 2026/qa+notes #1.txt";

    let create_bucket = s3_request("PUT", &format!("{}/{}", base_url, bucket), vec![]).await;
    assert_eq!(create_bucket.status(), 200);

    let enable_versioning = s3_request(
        "PUT",
        &format!("{}/{}?versioning=", base_url, bucket),
        br#"<?xml version="1.0" encoding="UTF-8"?>
<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
</VersioningConfiguration>"#
            .to_vec(),
    )
    .await;
    assert_eq!(enable_versioning.status(), 200);

    let first_payload = b"encoded-v1".to_vec();
    let put_v1 = s3_request(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, encoded_key),
        first_payload.clone(),
    )
    .await;
    assert_eq!(put_v1.status(), 200);
    let v1_id = put_v1
        .headers()
        .get("x-amz-version-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing version id on first upload")
        .to_string();

    let put_v2 = s3_request(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, encoded_key),
        b"encoded-v2".to_vec(),
    )
    .await;
    assert_eq!(put_v2.status(), 200);

    let versions_response = client()
        .get(format!(
            "{}/api/buckets/{}/versions?key={}",
            base_url, bucket, encoded_key
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(versions_response.status(), 200);
    let versions_body: serde_json::Value = versions_response.json().await.unwrap();
    let versions = versions_body["versions"]
        .as_array()
        .expect("versions should be an array");
    assert_eq!(versions.len(), 2);

    let download = client()
        .get(format!(
            "{}/api/buckets/{}/versions/{}/download/{}",
            base_url, bucket, v1_id, encoded_key
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(download.status(), 200);
    assert_eq!(
        download
            .headers()
            .get("content-disposition")
            .and_then(|v| v.to_str().ok()),
        Some("attachment; filename=\"qa+notes #1.txt\"")
    );
    assert_eq!(
        download.bytes().await.unwrap().as_ref(),
        first_payload.as_slice()
    );

    assert!(
        versions
            .iter()
            .all(|entry| entry["versionId"].is_string() && entry["size"].as_u64().is_some()),
        "versions should include typed entries for decoded key path: {decoded_key}"
    );
}

#[tokio::test]
async fn test_console_versions_list_remains_available_after_versioning_suspend() {
    let (base_url, _tmp) = start_server().await;
    let cookie = console_login_cookie(&base_url).await;
    let bucket = "console-version-suspend-bucket";
    let key = "docs/readme.txt";

    let create_bucket = s3_request("PUT", &format!("{}/{}", base_url, bucket), vec![]).await;
    assert_eq!(create_bucket.status(), 200);

    let enable_versioning = s3_request(
        "PUT",
        &format!("{}/{}?versioning=", base_url, bucket),
        br#"<?xml version="1.0" encoding="UTF-8"?>
<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
</VersioningConfiguration>"#
            .to_vec(),
    )
    .await;
    assert_eq!(enable_versioning.status(), 200);

    let put_v1 = s3_request(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, key),
        b"first".to_vec(),
    )
    .await;
    assert_eq!(put_v1.status(), 200);

    let put_v2 = s3_request(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, key),
        b"second".to_vec(),
    )
    .await;
    assert_eq!(put_v2.status(), 200);

    let suspend_versioning = s3_request(
        "PUT",
        &format!("{}/{}?versioning=", base_url, bucket),
        br#"<?xml version="1.0" encoding="UTF-8"?>
<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
</VersioningConfiguration>"#
            .to_vec(),
    )
    .await;
    assert_eq!(suspend_versioning.status(), 200);

    let versioning_state = client()
        .get(format!("{}/api/buckets/{}/versioning", base_url, bucket))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(versioning_state.status(), 200);
    let versioning_body: serde_json::Value = versioning_state.json().await.unwrap();
    assert_eq!(versioning_body["enabled"], false);

    let versions_response = client()
        .get(format!(
            "{}/api/buckets/{}/versions?key={}",
            base_url, bucket, key
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(versions_response.status(), 200);
    let versions_body: serde_json::Value = versions_response.json().await.unwrap();
    let versions = versions_body["versions"]
        .as_array()
        .expect("versions should be an array");
    assert_eq!(versions.len(), 2);
    assert!(versions.iter().all(|entry| entry["versionId"].is_string()));
}

#[tokio::test]
async fn test_console_versioning_endpoints_return_not_found_for_missing_bucket() {
    let (base_url, _tmp) = start_server().await;
    let cookie = console_login_cookie(&base_url).await;
    let http = client();

    let get_resp = http
        .get(format!(
            "{}/api/buckets/missing-bucket/versioning",
            base_url
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp.status(), 404);

    let put_resp = http
        .put(format!(
            "{}/api/buckets/missing-bucket/versioning",
            base_url
        ))
        .header("cookie", &cookie)
        .header("content-type", "application/json")
        .json(&serde_json::json!({ "enabled": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(put_resp.status(), 404);
}

#[tokio::test]
async fn test_console_list_versions_returns_not_found_for_missing_bucket() {
    let (base_url, _tmp) = start_server().await;
    let cookie = console_login_cookie(&base_url).await;

    let resp = client()
        .get(format!(
            "{}/api/buckets/missing-bucket/versions?key=docs/readme.txt",
            base_url
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_console_list_objects_returns_bad_request_for_invalid_prefix() {
    let (base_url, _tmp) = start_server().await;
    let cookie = console_login_cookie(&base_url).await;
    let bucket = "console-invalid-prefix";
    let create_bucket = s3_request("PUT", &format!("{}/{}", base_url, bucket), vec![]).await;
    assert_eq!(create_bucket.status(), 200);

    let resp = client()
        .get(format!("{}/api/buckets/{}/objects", base_url, bucket))
        .query(&[("prefix", "../escape"), ("delimiter", "/")])
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("Key must not contain '..'")
    );
}

#[tokio::test]
async fn test_console_list_objects_returns_bad_request_for_empty_delimiter() {
    let (base_url, _tmp) = start_server().await;
    let cookie = console_login_cookie(&base_url).await;
    let bucket = "console-invalid-delimiter";
    let create_bucket = s3_request("PUT", &format!("{}/{}", base_url, bucket), vec![]).await;
    assert_eq!(create_bucket.status(), 200);

    let resp = client()
        .get(format!("{}/api/buckets/{}/objects", base_url, bucket))
        .query(&[("prefix", "docs/"), ("delimiter", "")])
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "Delimiter must not be empty");
}

#[tokio::test]
async fn test_console_list_versions_returns_bad_request_for_invalid_key() {
    let (base_url, _tmp) = start_server().await;
    let cookie = console_login_cookie(&base_url).await;
    let bucket = "console-invalid-version-key";
    let create_bucket = s3_request("PUT", &format!("{}/{}", base_url, bucket), vec![]).await;
    assert_eq!(create_bucket.status(), 200);

    let resp = client()
        .get(format!("{}/api/buckets/{}/versions", base_url, bucket))
        .query(&[("key", "../escape.txt")])
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("Key must not contain '..'")
    );
}

#[tokio::test]
async fn test_console_delete_version_returns_not_found_for_missing_version() {
    let (base_url, _tmp) = start_server().await;
    let cookie = console_login_cookie(&base_url).await;
    let bucket = "console-delete-missing-version";
    let key = "docs/readme.txt";

    let create_bucket = s3_request("PUT", &format!("{}/{}", base_url, bucket), vec![]).await;
    assert_eq!(create_bucket.status(), 200);

    let enable_versioning = s3_request(
        "PUT",
        &format!("{}/{}?versioning=", base_url, bucket),
        br#"<?xml version="1.0" encoding="UTF-8"?>
<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
</VersioningConfiguration>"#
            .to_vec(),
    )
    .await;
    assert_eq!(enable_versioning.status(), 200);

    let put_object = s3_request(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, key),
        b"data".to_vec(),
    )
    .await;
    assert_eq!(put_object.status(), 200);

    let resp = client()
        .delete(format!(
            "{}/api/buckets/{}/versions/does-not-exist/objects/{}",
            base_url, bucket, key
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "Version not found");
}

#[tokio::test]
async fn test_console_create_folder_returns_not_found_for_missing_bucket() {
    let (base_url, _tmp) = start_server().await;
    let cookie = console_login_cookie(&base_url).await;

    let resp = client()
        .post(format!("{}/api/buckets/missing-bucket/folders", base_url))
        .header("cookie", &cookie)
        .header("content-type", "application/json")
        .json(&serde_json::json!({ "name": "docs" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_console_delete_object_returns_not_found_for_missing_bucket() {
    let (base_url, _tmp) = start_server().await;
    let cookie = console_login_cookie(&base_url).await;

    let resp = client()
        .delete(format!(
            "{}/api/buckets/missing-bucket/objects/docs/readme.txt",
            base_url
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_console_download_object_returns_not_found_for_missing_bucket() {
    let (base_url, _tmp) = start_server().await;
    let cookie = console_login_cookie(&base_url).await;

    let resp = client()
        .get(format!(
            "{}/api/buckets/missing-bucket/download/docs/readme.txt",
            base_url
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "Bucket not found");
}

#[tokio::test]
async fn test_console_download_version_returns_not_found_for_missing_bucket() {
    let (base_url, _tmp) = start_server().await;
    let cookie = console_login_cookie(&base_url).await;

    let resp = client()
        .get(format!(
            "{}/api/buckets/missing-bucket/versions/version-123/download/docs/readme.txt",
            base_url
        ))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "Bucket not found");
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
