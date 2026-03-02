use super::*;

// --- Erasure Coding Tests ---

#[tokio::test]
async fn test_ec_put_and_get_object() {
    let (base_url, _tmp) = start_server_ec().await;
    s3_request("PUT", &format!("{}/testbucket", base_url), vec![]).await;

    // Upload 3KB of data (should create 3 chunks with 1KB chunk size)
    let data = vec![0x42u8; 3 * 1024];
    s3_request_with_headers(
        "PUT",
        &format!("{}/testbucket/bigfile.bin", base_url),
        data.clone(),
        vec![],
    )
    .await;

    // GET should return identical data
    let resp = s3_request(
        "GET",
        &format!("{}/testbucket/bigfile.bin", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.len(), 3 * 1024);
    assert_eq!(&body[..], &data[..]);
}

#[tokio::test]
async fn test_ec_small_object() {
    let (base_url, _tmp) = start_server_ec().await;
    s3_request("PUT", &format!("{}/testbucket", base_url), vec![]).await;

    // Upload less than one chunk
    let data = b"small data".to_vec();
    s3_request_with_headers(
        "PUT",
        &format!("{}/testbucket/small.txt", base_url),
        data.clone(),
        vec![],
    )
    .await;

    let resp = s3_request("GET", &format!("{}/testbucket/small.txt", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(&body[..], &data[..]);
}

#[tokio::test]
async fn test_ec_range_request() {
    let (base_url, _tmp) = start_server_ec().await;
    s3_request("PUT", &format!("{}/testbucket", base_url), vec![]).await;

    // 3KB of sequential bytes so we can verify exact ranges
    let data: Vec<u8> = (0..3072).map(|i| (i % 256) as u8).collect();
    s3_request_with_headers(
        "PUT",
        &format!("{}/testbucket/rangetest.bin", base_url),
        data.clone(),
        vec![],
    )
    .await;

    // Range spanning chunk boundary (bytes 500-1500, crosses from chunk 0 to chunk 1)
    let resp = s3_request_with_headers(
        "GET",
        &format!("{}/testbucket/rangetest.bin", base_url),
        vec![],
        vec![("Range", "bytes=500-1499")],
    )
    .await;
    assert_eq!(resp.status(), 206);
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.len(), 1000);
    assert_eq!(&body[..], &data[500..1500]);
}

#[tokio::test]
async fn test_ec_get_object_range_with_version_id_reads_selected_version() {
    let (base_url, _tmp) = start_server_ec().await;
    let bucket = "ec-versioned-range";
    let key = "docs/chunked-range.bin";
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
        vec![0x11; 1536],
    )
    .await;
    assert_eq!(put_v1.status(), 200);
    let version_1 = put_v1
        .headers()
        .get("x-amz-version-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing version id for first write")
        .to_string();

    let put_v2 = s3_request(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, key),
        vec![0x22; 1536],
    )
    .await;
    assert_eq!(put_v2.status(), 200);

    let range_resp = s3_request_with_headers(
        "GET",
        &format!("{}/{}/{}?versionId={}", base_url, bucket, key, version_1),
        vec![],
        vec![("Range", "bytes=512-767")],
    )
    .await;
    assert_eq!(range_resp.status(), 206);
    assert_eq!(
        range_resp
            .headers()
            .get("x-amz-version-id")
            .and_then(|v| v.to_str().ok()),
        Some(version_1.as_str())
    );

    let body = range_resp.bytes().await.unwrap();
    assert_eq!(body.len(), 256);
    assert!(body.iter().all(|b| *b == 0x11));
}

#[tokio::test]
async fn test_ec_delete_object() {
    let (base_url, tmp) = start_server_ec().await;
    s3_request("PUT", &format!("{}/testbucket", base_url), vec![]).await;

    s3_request_with_headers(
        "PUT",
        &format!("{}/testbucket/todelete.txt", base_url),
        b"delete me".to_vec(),
        vec![],
    )
    .await;

    // Verify .ec directory exists
    let ec_dir = tmp.path().join("buckets/testbucket/todelete.txt.ec");
    assert!(ec_dir.exists(), "EC dir should exist after PUT");

    s3_request(
        "DELETE",
        &format!("{}/testbucket/todelete.txt", base_url),
        vec![],
    )
    .await;

    assert!(!ec_dir.exists(), "EC dir should be removed after DELETE");
    let resp = s3_request(
        "GET",
        &format!("{}/testbucket/todelete.txt", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_ec_etag_matches_flat_file() {
    // Verify that EC objects produce the same ETag as flat-file objects
    let (base_url_flat, _tmp1) = start_server().await;
    let (base_url_ec, _tmp2) = start_server_ec().await;

    for base in [&base_url_flat, &base_url_ec] {
        s3_request("PUT", &format!("{}/testbucket", base), vec![]).await;
    }

    let data = b"hello world etag test".to_vec();
    let resp_flat = s3_request_with_headers(
        "PUT",
        &format!("{}/testbucket/etagtest.txt", base_url_flat),
        data.clone(),
        vec![],
    )
    .await;
    let resp_ec = s3_request_with_headers(
        "PUT",
        &format!("{}/testbucket/etagtest.txt", base_url_ec),
        data.clone(),
        vec![],
    )
    .await;

    let etag_flat = resp_flat
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let etag_ec = resp_ec
        .headers()
        .get("etag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        etag_flat, etag_ec,
        "ETags should match between flat and EC storage"
    );
}

#[tokio::test]
async fn test_ec_bitrot_detection() {
    let (base_url, tmp) = start_server_ec().await;
    s3_request("PUT", &format!("{}/testbucket", base_url), vec![]).await;

    s3_request_with_headers(
        "PUT",
        &format!("{}/testbucket/corrupt.bin", base_url),
        vec![0xAA; 2048],
        vec![],
    )
    .await;

    // Corrupt chunk 0 on disk
    let chunk_path = tmp.path().join("buckets/testbucket/corrupt.bin.ec/000000");
    std::fs::write(&chunk_path, vec![0xFF; 1024]).unwrap();

    // GET should fail — either a 500 response or a connection error
    // (the error may occur mid-stream after headers are sent)
    let url = format!("{}/testbucket/corrupt.bin", base_url);
    let result = s3_request_result("GET", &url, vec![]).await;
    match result {
        Ok(resp) => {
            // If we get a response, reading the body should fail or status should be 500
            if resp.status() == 200 {
                let body_result = resp.bytes().await;
                assert!(
                    body_result.is_err() || body_result.unwrap() != vec![0xAA; 2048],
                    "Should not return original uncorrupted data"
                );
            }
        }
        Err(_) => {
            // Connection error is expected — chunk verification failed mid-stream
        }
    }
}

#[tokio::test]
async fn test_ec_list_objects() {
    let (base_url, _tmp) = start_server_ec().await;
    s3_request("PUT", &format!("{}/testbucket", base_url), vec![]).await;

    s3_request_with_headers(
        "PUT",
        &format!("{}/testbucket/file1.txt", base_url),
        b"one".to_vec(),
        vec![],
    )
    .await;
    s3_request_with_headers(
        "PUT",
        &format!("{}/testbucket/file2.txt", base_url),
        b"two".to_vec(),
        vec![],
    )
    .await;

    let resp = s3_request(
        "GET",
        &format!("{}/testbucket?list-type=2", base_url),
        vec![],
    )
    .await;
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Key>file1.txt</Key>"), "body: {}", body);
    assert!(body.contains("<Key>file2.txt</Key>"), "body: {}", body);
    // .ec directories should NOT appear as objects
    assert!(
        !body.contains(".ec"),
        "body should not contain .ec: {}",
        body
    );
}

#[tokio::test]
async fn test_ec_delete_marker_stays_current_after_deleting_older_version() {
    let (base_url, _tmp) = start_server_ec().await;
    let bucket = "ec-versioned-delete-marker";
    let key = "logs/chunked.bin";
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
        vec![0x11; 1536],
    )
    .await;
    assert_eq!(put_v1.status(), 200);

    let put_v2 = s3_request(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, key),
        vec![0x22; 1536],
    )
    .await;
    assert_eq!(put_v2.status(), 200);
    let version_2 = put_v2
        .headers()
        .get("x-amz-version-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing version id for v2")
        .to_string();

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

    let get_after_marker =
        s3_request("GET", &format!("{}/{}/{}", base_url, bucket, key), vec![]).await;
    assert_eq!(get_after_marker.status(), 404);

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
}

#[tokio::test]
async fn test_ec_deleting_latest_version_restores_previous_current_version() {
    let (base_url, _tmp) = start_server_ec().await;
    let bucket = "ec-versioned-restore";
    let key = "logs/recover.bin";
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
        vec![0xAA; 1536],
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
        vec![0xBB; 1536],
    )
    .await;
    assert_eq!(put_v2.status(), 200);
    let version_2 = put_v2
        .headers()
        .get("x-amz-version-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing version id for v2")
        .to_string();

    let delete_v2 = s3_request(
        "DELETE",
        &format!("{}/{}/{}?versionId={}", base_url, bucket, key, version_2),
        vec![],
    )
    .await;
    assert_eq!(delete_v2.status(), 204);

    let current = s3_request("GET", &format!("{}/{}/{}", base_url, bucket, key), vec![]).await;
    assert_eq!(current.status(), 200);
    assert_eq!(
        current
            .headers()
            .get("x-amz-version-id")
            .and_then(|v| v.to_str().ok()),
        Some(version_1.as_str())
    );
    let body = current.bytes().await.unwrap();
    assert_eq!(body.len(), 1536);
    assert!(body.iter().all(|b| *b == 0xAA));
}
