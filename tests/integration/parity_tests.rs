use super::*;
use tempfile::TempDir;

// --- Parity / Reed-Solomon Tests ---

/// Start a server with erasure coding + parity enabled (small chunks for testing).
async fn start_server_parity(parity_shards: u32) -> (String, TempDir) {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let config = make_test_config(data_dir, true, 100, parity_shards);
    start_server_with_config(config, tmp).await
}

#[tokio::test]
async fn test_parity_write_creates_parity_chunks() {
    let (base_url, tmp) = start_server_parity(2).await;

    // Create bucket
    s3_request("PUT", &format!("{}/parity-test", base_url), vec![]).await;

    // Write 350 bytes → 4 data chunks (100+100+100+50) + 2 parity
    let data = vec![0xABu8; 350];
    s3_request("PUT", &format!("{}/parity-test/file.bin", base_url), data).await;

    // Check the .ec directory
    let ec_dir = tmp.path().join("buckets/parity-test/file.bin.ec");
    assert!(ec_dir.is_dir());

    // Should have 6 chunk files + manifest.json = 7 entries
    let entries: Vec<_> = std::fs::read_dir(&ec_dir).unwrap().collect();
    assert_eq!(entries.len(), 7, "expected 4 data + 2 parity + 1 manifest");

    // Verify manifest
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(ec_dir.join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["version"], 2);
    assert_eq!(manifest["chunk_count"], 4);
    assert_eq!(manifest["parity_shards"], 2);
    assert_eq!(manifest["chunks"].as_array().unwrap().len(), 6);

    // Verify parity chunks have kind: "parity"
    let chunks = manifest["chunks"].as_array().unwrap();
    for chunk in chunks.iter().take(4) {
        // data chunks should not have "kind" field (skipped when data) or be "data"
        let kind = chunk.get("kind");
        assert!(kind.is_none() || kind.unwrap() == "data");
    }
    assert_eq!(chunks[4]["kind"], "parity");
    assert_eq!(chunks[5]["kind"], "parity");
}

#[tokio::test]
async fn test_parity_read_healthy() {
    let (base_url, _tmp) = start_server_parity(2).await;

    s3_request("PUT", &format!("{}/parity-test", base_url), vec![]).await;

    let data = vec![0xCDu8; 350];
    s3_request(
        "PUT",
        &format!("{}/parity-test/file.bin", base_url),
        data.clone(),
    )
    .await;

    let resp = s3_request("GET", &format!("{}/parity-test/file.bin", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), &data[..]);
}

#[tokio::test]
async fn test_parity_recovery_corrupted_chunk() {
    let (base_url, tmp) = start_server_parity(2).await;

    s3_request("PUT", &format!("{}/parity-test", base_url), vec![]).await;

    let data = vec![0xEFu8; 350];
    s3_request(
        "PUT",
        &format!("{}/parity-test/file.bin", base_url),
        data.clone(),
    )
    .await;

    // Corrupt data chunk 1 (overwrite with zeros)
    let chunk_path = tmp.path().join("buckets/parity-test/file.bin.ec/000001");
    std::fs::write(&chunk_path, vec![0u8; 100]).unwrap();

    // Read should still succeed via RS recovery
    let resp = s3_request("GET", &format!("{}/parity-test/file.bin", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), &data[..]);
}

#[tokio::test]
async fn test_parity_recovery_missing_chunk() {
    let (base_url, tmp) = start_server_parity(2).await;

    s3_request("PUT", &format!("{}/parity-test", base_url), vec![]).await;

    let data = vec![0x42u8; 350];
    s3_request(
        "PUT",
        &format!("{}/parity-test/file.bin", base_url),
        data.clone(),
    )
    .await;

    // Delete data chunk 0
    let chunk_path = tmp.path().join("buckets/parity-test/file.bin.ec/000000");
    std::fs::remove_file(&chunk_path).unwrap();

    let resp = s3_request("GET", &format!("{}/parity-test/file.bin", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), &data[..]);
}

#[tokio::test]
async fn test_parity_too_many_failures() {
    let (base_url, tmp) = start_server_parity(2).await;

    s3_request("PUT", &format!("{}/parity-test", base_url), vec![]).await;

    let data = vec![0x77u8; 350];
    s3_request("PUT", &format!("{}/parity-test/file.bin", base_url), data).await;

    // Delete 3 chunks (more than m=2 parity can handle)
    for i in 0..3 {
        let chunk_path = tmp
            .path()
            .join(format!("buckets/parity-test/file.bin.ec/{:06}", i));
        std::fs::remove_file(&chunk_path).unwrap();
    }

    // The server will return an error or drop the connection when RS recovery fails.
    // Since the object is streamed, the error may manifest as a connection reset
    // rather than a clean HTTP error status.
    let result =
        s3_request_result("GET", &format!("{}/parity-test/file.bin", base_url), vec![]).await;
    match result {
        Err(_) => {} // Connection error — expected
        Ok(resp) => {
            // Either a server error status, or streaming started but body will be incomplete
            if resp.status() == 200 {
                let body_result = resp.bytes().await;
                assert!(body_result.is_err() || body_result.unwrap().len() != 350);
            } else {
                assert!(resp.status().is_server_error());
            }
        }
    }
}

#[tokio::test]
async fn test_parity_range_read_degraded() {
    let (base_url, tmp) = start_server_parity(2).await;

    s3_request("PUT", &format!("{}/parity-test", base_url), vec![]).await;

    // Create data with distinct bytes per chunk for easy verification
    let mut data = Vec::new();
    for i in 0u8..4 {
        let chunk_len = if i < 3 { 100 } else { 50 };
        data.extend(std::iter::repeat_n(i + 1, chunk_len));
    }
    assert_eq!(data.len(), 350);
    s3_request(
        "PUT",
        &format!("{}/parity-test/file.bin", base_url),
        data.clone(),
    )
    .await;

    // Corrupt chunk 1
    let chunk_path = tmp.path().join("buckets/parity-test/file.bin.ec/000001");
    std::fs::write(&chunk_path, vec![0u8; 100]).unwrap();

    // Range read spanning chunk 0 and chunk 1 (bytes 50-149)
    let resp = s3_request_with_headers(
        "GET",
        &format!("{}/parity-test/file.bin", base_url),
        vec![],
        vec![("range", "bytes=50-149")],
    )
    .await;
    assert_eq!(resp.status(), 206);
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), &data[50..150]);
}

#[tokio::test]
async fn test_parity_backward_compat_v1_manifest() {
    // EC without parity should still work (v1 manifest, no parity fields)
    let (base_url, _tmp) = start_server_ec().await;

    s3_request("PUT", &format!("{}/compat-test", base_url), vec![]).await;

    let data = vec![0xAAu8; 2048];
    s3_request(
        "PUT",
        &format!("{}/compat-test/file.bin", base_url),
        data.clone(),
    )
    .await;

    let resp = s3_request("GET", &format!("{}/compat-test/file.bin", base_url), vec![]).await;
    assert_eq!(resp.status(), 200);
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), &data[..]);
}

#[tokio::test]
async fn test_parity_empty_object() {
    let (base_url, tmp) = start_server_parity(2).await;

    s3_request("PUT", &format!("{}/parity-test", base_url), vec![]).await;

    // Empty object — should skip parity
    s3_request(
        "PUT",
        &format!("{}/parity-test/empty.bin", base_url),
        vec![],
    )
    .await;

    let ec_dir = tmp.path().join("buckets/parity-test/empty.bin.ec");
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(ec_dir.join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["version"], 1); // no parity for empty
    assert!(manifest.get("parity_shards").is_none() || manifest["parity_shards"].is_null());

    let resp = s3_request(
        "GET",
        &format!("{}/parity-test/empty.bin", base_url),
        vec![],
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().len(), 0);
}
