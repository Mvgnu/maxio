use super::*;
use base64::Engine;

// --- Checksum tests ---

#[tokio::test]
async fn test_put_object_with_crc32_checksum() {
    let (base_url, _tmp) = start_server().await;

    // Create bucket
    s3_request("PUT", &format!("{}/checksum-bucket", base_url), vec![]).await;

    // Compute CRC32 of body
    let body = b"hello checksum world";
    let crc = crc32fast::hash(body);
    let crc_b64 = base64::engine::general_purpose::STANDARD.encode(crc.to_be_bytes());

    // PUT with correct checksum
    let resp = s3_request_with_headers(
        "PUT",
        &format!("{}/checksum-bucket/test.txt", base_url),
        body.to_vec(),
        vec![("x-amz-checksum-crc32", &crc_b64)],
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("x-amz-checksum-crc32")
            .unwrap()
            .to_str()
            .unwrap(),
        crc_b64
    );

    // GET should return the checksum header
    let resp = s3_request(
        "GET",
        &format!("{}/checksum-bucket/test.txt", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("x-amz-checksum-crc32")
            .unwrap()
            .to_str()
            .unwrap(),
        crc_b64
    );

    // HEAD should also return it
    let resp = s3_request(
        "HEAD",
        &format!("{}/checksum-bucket/test.txt", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("x-amz-checksum-crc32")
            .unwrap()
            .to_str()
            .unwrap(),
        crc_b64
    );
}

#[tokio::test]
async fn test_put_object_with_wrong_checksum() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/checksum-bucket", base_url), vec![]).await;

    // Send a wrong CRC32 value
    let resp = s3_request_with_headers(
        "PUT",
        &format!("{}/checksum-bucket/bad.txt", base_url),
        b"some data".to_vec(),
        vec![("x-amz-checksum-crc32", "AAAAAAAA")],
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("BadDigest"),
        "expected BadDigest error: {}",
        body
    );

    // Failed checksum uploads must not leave persisted object data behind.
    let resp = s3_request(
        "GET",
        &format!("{}/checksum-bucket/bad.txt", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_put_object_with_algorithm_only() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/checksum-bucket", base_url), vec![]).await;

    let body_bytes = b"compute my checksum please";

    // Send only the algorithm header, no value — server should compute
    let resp = s3_request_with_headers(
        "PUT",
        &format!("{}/checksum-bucket/algo-only.txt", base_url),
        body_bytes.to_vec(),
        vec![("x-amz-checksum-algorithm", "CRC32C")],
    )
    .await;
    assert_eq!(resp.status(), 200);

    // Verify a CRC32C header was returned
    let checksum = resp
        .headers()
        .get("x-amz-checksum-crc32c")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(!checksum.is_empty());

    // Verify it's the correct value
    let expected_crc = crc32c::crc32c(body_bytes);
    let expected_b64 = base64::engine::general_purpose::STANDARD.encode(expected_crc.to_be_bytes());
    assert_eq!(checksum, expected_b64);
}

#[tokio::test]
async fn test_put_object_no_checksum_backward_compat() {
    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/checksum-bucket", base_url), vec![]).await;

    let resp = s3_request_with_headers(
        "PUT",
        &format!("{}/checksum-bucket/no-checksum.txt", base_url),
        b"plain old upload".to_vec(),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 200);

    // No checksum headers should be in the response
    assert!(resp.headers().get("x-amz-checksum-crc32").is_none());
    assert!(resp.headers().get("x-amz-checksum-crc32c").is_none());
    assert!(resp.headers().get("x-amz-checksum-sha1").is_none());
    assert!(resp.headers().get("x-amz-checksum-sha256").is_none());
}

#[tokio::test]
async fn test_put_object_with_sha256_checksum() {
    use base64::Engine;

    let (base_url, _tmp) = start_server().await;
    s3_request("PUT", &format!("{}/checksum-bucket", base_url), vec![]).await;

    let body = b"sha256 test data";
    let hash = <sha2::Sha256 as sha2::Digest>::digest(body);
    let hash_b64 = base64::engine::general_purpose::STANDARD.encode(hash);

    let resp = s3_request_with_headers(
        "PUT",
        &format!("{}/checksum-bucket/sha256.txt", base_url),
        body.to_vec(),
        vec![("x-amz-checksum-sha256", &hash_b64)],
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("x-amz-checksum-sha256")
            .unwrap()
            .to_str()
            .unwrap(),
        hash_b64
    );
}
