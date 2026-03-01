use super::*;
use hmac::Mac;
use sha2::{Digest, Sha256};

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
    assert!(saw_auth, "signed request should include authorization header");

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
    assert!(saw_auth, "signed request should include authorization header");

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
    let encoded_signature_key =
        presigned.replacen("X-Amz-Signature=", "%58-Amz-Signature=", 1);

    let resp = client().get(&encoded_signature_key).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), expected_body);
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
