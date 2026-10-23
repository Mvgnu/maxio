//! Signed bytes must be authenticated before a handler can mutate storage.
#[allow(dead_code)]
#[path = "integration/helpers.rs"]
mod helpers;

use reqwest::{Method, Response, StatusCode};

async fn send_signed(
    method: Method,
    url: &str,
    signed_body: &[u8],
    transmitted_body: &[u8],
) -> Response {
    let mut headers = vec![("content-type".into(), "application/octet-stream".into())];
    helpers::sign_request(method.as_str(), url, &mut headers, signed_body);
    send_headers(method, url, &headers, transmitted_body).await
}

async fn send_headers(
    method: Method,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Response {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let mut request = client.request(method, url).body(body.to_vec());
    for (name, value) in headers {
        request = request.header(name, value);
    }
    request.send().await.unwrap()
}

async fn server(erasure: bool) -> (String, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().unwrap();
    let config = helpers::make_test_config(
        tmp.path().to_str().unwrap().to_owned(),
        erasure,
        1024,
        u32::from(erasure),
    );
    let (base, tmp) = helpers::start_server_with_config(config, tmp).await;
    let response = send_signed(Method::PUT, &format!("{base}/auth-proof"), b"", b"").await;
    assert_eq!(response.status(), StatusCode::OK);
    (base, tmp)
}

async fn get_bytes(url: &str) -> Vec<u8> {
    let response = send_signed(Method::GET, url, b"", b"").await;
    assert_eq!(response.status(), StatusCode::OK);
    response.bytes().await.unwrap().to_vec()
}

#[tokio::test]
async fn signed_payload_mismatch_preserves_flat_and_erasure_objects() {
    for erasure in [false, true] {
        let (base, _tmp) = server(erasure).await;
        let url = format!("{base}/auth-proof/object");
        let original = b"previous complete contents";
        let response = send_signed(Method::PUT, &url, original, original).await;
        assert_eq!(response.status(), StatusCode::OK);
        let etag = response.headers()["etag"].to_str().unwrap().to_owned();
        let mismatch = send_signed(
            Method::PUT,
            &url,
            b"signed-payload-original",
            b"tampered-body-different",
        )
        .await;
        assert_eq!(mismatch.status(), StatusCode::BAD_REQUEST);
        assert!(
            mismatch
                .text()
                .await
                .unwrap()
                .contains("<Code>BadDigest</Code>")
        );
        assert_eq!(get_bytes(&url).await, original);
        let after = send_signed(Method::HEAD, &url, b"", b"").await;
        assert_eq!(after.headers()["etag"], etag);
        assert_eq!(after.headers()["content-type"], "application/octet-stream");
    }
}

#[tokio::test]
async fn signed_payload_is_verified_even_when_handler_ignores_body() {
    let (base, _tmp) = server(false).await;
    let url = format!("{base}/auth-proof/object");
    assert_eq!(
        send_signed(Method::PUT, &url, b"keep", b"keep")
            .await
            .status(),
        StatusCode::OK
    );
    let response = send_signed(Method::DELETE, &url, b"", b"unsigned extra bytes").await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(get_bytes(&url).await, b"keep");
}

#[tokio::test]
async fn large_signed_payload_round_trips_and_rejects_late_tampering() {
    let (base, _tmp) = server(false).await;
    let url = format!("{base}/auth-proof/large");
    let original: Vec<u8> = (0..192 * 1024).map(|i| (i % 251) as u8).collect();
    assert_eq!(
        send_signed(Method::PUT, &url, &original, &original)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(get_bytes(&url).await, original);
    let mut tampered = original.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert_eq!(
        send_signed(Method::PUT, &url, &original, &tampered)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(get_bytes(&url).await, original);
}

#[tokio::test]
async fn presigned_unsigned_payload_remains_supported_and_explicit_digest_is_checked() {
    let (base, _tmp) = server(false).await;
    let host = base.strip_prefix("http://").unwrap();
    let url = maxio::auth::signature_v4::generate_presigned_url(
        maxio::auth::signature_v4::PresignRequest {
            method: "PUT",
            scheme: "http",
            host,
            path: "/auth-proof/presigned",
            extra_query_params: &[],
            access_key: helpers::ACCESS_KEY,
            secret_key: helpers::SECRET_KEY,
            region: helpers::REGION,
            now: chrono::Utc::now(),
            expires_secs: 60,
        },
    )
    .unwrap();
    assert_eq!(
        send_headers(Method::PUT, &url, &[], b"unsigned-by-design")
            .await
            .status(),
        StatusCode::OK
    );
    let headers = [("x-amz-content-sha256".into(), "0".repeat(64))];
    assert_eq!(
        send_headers(Method::PUT, &url, &headers, b"wrong-digest")
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        get_bytes(&format!("{base}/auth-proof/presigned")).await,
        b"unsigned-by-design"
    );
}

#[tokio::test]
async fn signed_chunks_authenticate_data_chain_and_final_signature_before_publish() {
    let (base, _tmp) = server(false).await;
    let url = format!("{base}/auth-proof/chunks");
    let first = vec![b'a'; 96 * 1024];
    let second = b"last part";
    let chunks = [first.as_slice(), &second[..]];
    let expected = chunks.concat();
    let (headers, encoded) = helpers::signed_chunked_request(&url, &chunks);
    assert_eq!(
        send_headers(Method::PUT, &url, &headers, &encoded)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(get_bytes(&url).await, expected);

    let mut tampered_data = encoded.clone();
    let data_start = encoded.windows(2).position(|w| w == b"\r\n").unwrap() + 2;
    tampered_data[data_start + first.len() - 1] ^= 1;
    assert_eq!(
        send_headers(Method::PUT, &url, &headers, &tampered_data)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(get_bytes(&url).await, expected);

    let mut tampered_final = encoded.clone();
    let final_start = encoded
        .windows(18)
        .rposition(|w| w == b"0;chunk-signature=")
        .unwrap()
        + 18;
    tampered_final[final_start] = if tampered_final[final_start] == b'0' {
        b'1'
    } else {
        b'0'
    };
    assert_eq!(
        send_headers(Method::PUT, &url, &headers, &tampered_final)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(get_bytes(&url).await, expected);
}

#[tokio::test]
async fn unsigned_chunk_trailer_mode_is_explicitly_unsupported() {
    let (base, _tmp) = server(false).await;
    let host = base.strip_prefix("http://").unwrap();
    let url = maxio::auth::signature_v4::generate_presigned_url(
        maxio::auth::signature_v4::PresignRequest {
            method: "PUT",
            scheme: "http",
            host,
            path: "/auth-proof/unsupported",
            extra_query_params: &[],
            access_key: helpers::ACCESS_KEY,
            secret_key: helpers::SECRET_KEY,
            region: helpers::REGION,
            now: chrono::Utc::now(),
            expires_secs: 60,
        },
    )
    .unwrap();
    let headers = [(
        "x-amz-content-sha256".into(),
        "STREAMING-UNSIGNED-PAYLOAD-TRAILER".into(),
    )];
    let response = send_headers(Method::PUT, &url, &headers, b"encoded-but-unverified").await;
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(
        send_signed(
            Method::GET,
            &format!("{base}/auth-proof/unsupported"),
            b"",
            b""
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
}
