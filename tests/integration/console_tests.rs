use super::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

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
    assert_eq!(body["membershipProtocol"], "static-bootstrap");
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
    assert_eq!(
        body["plan"]["transferCount"].as_u64(),
        Some(transfers.len() as u64)
    );
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
        &["requestsTotal", "uptimeSeconds", "version"],
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
