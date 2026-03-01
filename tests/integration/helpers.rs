use maxio::config::Config;
use maxio::server;
use std::net::SocketAddr;
use tempfile::TempDir;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

pub(crate) type HmacSha256 = Hmac<Sha256>;

pub(crate) const ACCESS_KEY: &str = "minioadmin";
pub(crate) const SECRET_KEY: &str = "minioadmin";
pub(crate) const SECONDARY_ACCESS_KEY: &str = "secondary-admin";
pub(crate) const SECONDARY_SECRET_KEY: &str = "secondary-secret";
pub(crate) const REGION: &str = "us-east-1";

pub(crate) fn make_test_config(
    data_dir: String,
    erasure_coding: bool,
    chunk_size: u64,
    parity_shards: u32,
) -> Config {
    Config {
        port: 0,
        address: "127.0.0.1".to_string(),
        data_dir,
        access_key: ACCESS_KEY.to_string(),
        secret_key: SECRET_KEY.to_string(),
        additional_credentials: Vec::new(),
        region: REGION.to_string(),
        node_id: "maxio-test-node".to_string(),
        cluster_peers: Vec::new(),
        erasure_coding,
        chunk_size,
        parity_shards,
    }
}

pub(crate) fn make_test_config_with_secondary_credential(
    data_dir: String,
    erasure_coding: bool,
    chunk_size: u64,
    parity_shards: u32,
) -> Config {
    let mut config = make_test_config(data_dir, erasure_coding, chunk_size, parity_shards);
    config.additional_credentials =
        vec![format!("{}:{}", SECONDARY_ACCESS_KEY, SECONDARY_SECRET_KEY)];
    config
}

pub(crate) async fn start_server_with_config(config: Config, tmp: TempDir) -> (String, TempDir) {
    let state = server::AppState::from_config(config).await.unwrap();
    let app = server::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    (base_url, tmp)
}

/// Spin up a test server on a random port, return the base URL.
pub(crate) async fn start_server() -> (String, TempDir) {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    start_server_with_config(config, tmp).await
}

/// Start a server with erasure coding enabled (small chunk size for testing).
pub(crate) async fn start_server_ec() -> (String, TempDir) {
    let tmp = TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let config = make_test_config(data_dir, true, 1024, 0);
    start_server_with_config(config, tmp).await
}

/// Sign a request with AWS Signature V4.
pub(crate) fn sign_request(
    method: &str,
    url: &str,
    headers: &mut Vec<(String, String)>,
    body: &[u8],
) {
    sign_request_with_credentials(method, url, headers, body, ACCESS_KEY, SECRET_KEY, REGION);
}

pub(crate) fn sign_request_with_credentials(
    method: &str,
    url: &str,
    headers: &mut Vec<(String, String)>,
    body: &[u8],
    access_key: &str,
    secret_key: &str,
    region: &str,
) {
    let parsed = reqwest::Url::parse(url).unwrap();
    let host = parsed.host_str().unwrap();
    let port = parsed.port().unwrap();
    let host_header = format!("{}:{}", host, port);
    let path = parsed.path();
    let query = parsed.query().unwrap_or("");

    let now = chrono::Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

    let payload_hash = hex::encode(Sha256::digest(body));

    headers.push(("host".to_string(), host_header.clone()));
    headers.push(("x-amz-date".to_string(), amz_date.clone()));
    headers.push(("x-amz-content-sha256".to_string(), payload_hash.clone()));

    // Sort signed headers
    headers.sort_by(|a, b| a.0.cmp(&b.0));

    let signed_headers: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
    let signed_headers_str = signed_headers.join(";");

    let canonical_headers: String = headers
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
        .collect();

    // Normalize query string: sort params and ensure key=value format
    let canonical_qs = if query.is_empty() {
        String::new()
    } else {
        let mut pairs: Vec<(String, String)> = query
            .split('&')
            .filter(|s| !s.is_empty())
            .map(|pair| {
                let mut parts = pair.splitn(2, '=');
                let key = parts.next().unwrap_or("").to_string();
                let val = parts.next().unwrap_or("").to_string();
                (key, val)
            })
            .collect();
        pairs.sort();
        pairs
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&")
    };

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, path, canonical_qs, canonical_headers, signed_headers_str, payload_hash
    );

    let scope = format!("{}/{}/s3/aws4_request", date_stamp, region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date,
        scope,
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    // Derive signing key
    let key = format!("AWS4{}", secret_key);
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
    mac.update(date_stamp.as_bytes());
    let date_key = mac.finalize().into_bytes();

    let mut mac = HmacSha256::new_from_slice(&date_key).unwrap();
    mac.update(region.as_bytes());
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

    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        access_key, scope, signed_headers_str, signature
    );
    headers.push(("authorization".to_string(), auth));
}

pub(crate) fn client() -> reqwest::Client {
    reqwest::Client::new()
}

/// Sign a request using comma-only separators (no spaces), like mc does.
pub(crate) fn sign_request_compact(
    method: &str,
    url: &str,
    headers: &mut Vec<(String, String)>,
    body: &[u8],
) {
    // Reuse the same signing logic but produce compact auth header
    let parsed = reqwest::Url::parse(url).unwrap();
    let host = parsed.host_str().unwrap();
    let port = parsed.port().unwrap();
    let host_header = format!("{}:{}", host, port);
    let path = parsed.path();
    let query = parsed.query().unwrap_or("");

    let now = chrono::Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

    let payload_hash = hex::encode(Sha256::digest(body));

    headers.push(("host".to_string(), host_header.clone()));
    headers.push(("x-amz-date".to_string(), amz_date.clone()));
    headers.push(("x-amz-content-sha256".to_string(), payload_hash.clone()));

    headers.sort_by(|a, b| a.0.cmp(&b.0));

    let signed_headers: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
    let signed_headers_str = signed_headers.join(";");

    let canonical_headers: String = headers
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
        .collect();

    let canonical_qs = if query.is_empty() {
        String::new()
    } else {
        let mut pairs: Vec<(String, String)> = query
            .split('&')
            .filter(|s| !s.is_empty())
            .map(|pair| {
                let mut parts = pair.splitn(2, '=');
                let key = parts.next().unwrap_or("").to_string();
                let val = parts.next().unwrap_or("").to_string();
                (key, val)
            })
            .collect();
        pairs.sort();
        pairs
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&")
    };

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, path, canonical_qs, canonical_headers, signed_headers_str, payload_hash
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

    // Compact format: no spaces after commas (like mc sends)
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders={},Signature={}",
        ACCESS_KEY, scope, signed_headers_str, signature
    );
    headers.push(("authorization".to_string(), auth));
}

/// Build a signed request and send it.
pub(crate) async fn s3_request(method: &str, url: &str, body: Vec<u8>) -> reqwest::Response {
    let mut headers = Vec::new();
    sign_request(method, url, &mut headers, &body);

    let client = client();
    let mut builder = match method {
        "GET" => client.get(url),
        "PUT" => client.put(url),
        "HEAD" => client.head(url),
        "DELETE" => client.delete(url),
        "POST" => client.post(url),
        _ => panic!("unsupported method"),
    };

    for (k, v) in &headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    if !body.is_empty() {
        builder = builder.body(body);
    }

    builder.send().await.unwrap()
}

pub(crate) async fn s3_request_with_credentials(
    method: &str,
    url: &str,
    body: Vec<u8>,
    access_key: &str,
    secret_key: &str,
) -> reqwest::Response {
    let mut headers = Vec::new();
    sign_request_with_credentials(
        method,
        url,
        &mut headers,
        &body,
        access_key,
        secret_key,
        REGION,
    );

    let client = client();
    let mut builder = match method {
        "GET" => client.get(url),
        "PUT" => client.put(url),
        "HEAD" => client.head(url),
        "DELETE" => client.delete(url),
        "POST" => client.post(url),
        _ => panic!("unsupported method"),
    };

    for (k, v) in &headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    if !body.is_empty() {
        builder = builder.body(body);
    }

    builder.send().await.unwrap()
}

/// Like s3_request but returns Result instead of panicking on send errors.
pub(crate) async fn s3_request_result(
    method: &str,
    url: &str,
    body: Vec<u8>,
) -> Result<reqwest::Response, reqwest::Error> {
    let mut headers = Vec::new();
    sign_request(method, url, &mut headers, &body);

    let client = client();
    let mut builder = match method {
        "GET" => client.get(url),
        "PUT" => client.put(url),
        "HEAD" => client.head(url),
        "DELETE" => client.delete(url),
        "POST" => client.post(url),
        _ => panic!("unsupported method"),
    };

    for (k, v) in &headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    if !body.is_empty() {
        builder = builder.body(body);
    }

    builder.send().await
}

/// Sign and send a request with extra headers (e.g. x-amz-copy-source).
pub(crate) async fn s3_request_with_headers(
    method: &str,
    url: &str,
    body: Vec<u8>,
    extra_headers: Vec<(&str, &str)>,
) -> reqwest::Response {
    let mut headers: Vec<(String, String)> = extra_headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    sign_request(method, url, &mut headers, &body);

    let client = client();
    let mut builder = match method {
        "GET" => client.get(url),
        "PUT" => client.put(url),
        "HEAD" => client.head(url),
        "DELETE" => client.delete(url),
        "POST" => client.post(url),
        _ => panic!("unsupported method"),
    };

    for (k, v) in &headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    if !body.is_empty() {
        builder = builder.body(body);
    }

    builder.send().await.unwrap()
}

/// Build a signed request with compact auth header (no spaces after commas).
pub(crate) async fn s3_request_compact(
    method: &str,
    url: &str,
    body: Vec<u8>,
) -> reqwest::Response {
    let mut headers = Vec::new();
    sign_request_compact(method, url, &mut headers, &body);

    let client = client();
    let mut builder = match method {
        "GET" => client.get(url),
        "PUT" => client.put(url),
        "HEAD" => client.head(url),
        "DELETE" => client.delete(url),
        "POST" => client.post(url),
        _ => panic!("unsupported method"),
    };

    for (k, v) in &headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    if !body.is_empty() {
        builder = builder.body(body);
    }

    builder.send().await.unwrap()
}

/// Build a PUT request with STREAMING-AWS4-HMAC-SHA256-PAYLOAD (AWS chunked encoding).
pub(crate) async fn s3_put_chunked(url: &str, data: &[u8]) -> reqwest::Response {
    let parsed = reqwest::Url::parse(url).unwrap();
    let host = parsed.host_str().unwrap();
    let port = parsed.port().unwrap();
    let host_header = format!("{}:{}", host, port);
    let path = parsed.path();
    let query = parsed.query().unwrap_or("");

    let now = chrono::Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

    // For streaming, the payload hash is the literal string
    let payload_hash = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";

    let mut sign_headers = [
        ("host".to_string(), host_header.clone()),
        ("x-amz-content-sha256".to_string(), payload_hash.to_string()),
        ("x-amz-date".to_string(), amz_date.clone()),
        (
            "x-amz-decoded-content-length".to_string(),
            data.len().to_string(),
        ),
    ];
    sign_headers.sort_by(|a, b| a.0.cmp(&b.0));

    let signed_headers: Vec<&str> = sign_headers.iter().map(|(k, _)| k.as_str()).collect();
    let signed_headers_str = signed_headers.join(";");

    let canonical_headers: String = sign_headers
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
        .collect();

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        "PUT", path, query, canonical_headers, signed_headers_str, payload_hash
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
    let seed_signature = hex::encode(mac.finalize().into_bytes());

    // Compact auth header (no spaces)
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders={},Signature={}",
        ACCESS_KEY, scope, signed_headers_str, seed_signature
    );

    // Build AWS chunked body: "<hex_size>;chunk-signature=<sig>\r\n<data>\r\n0;chunk-signature=<sig>\r\n"
    // For simplicity, compute chunk signatures with a dummy (real mc would chain them)
    let chunk_sig = "0".repeat(64); // placeholder — server doesn't verify chunk sigs
    let mut chunked_body = Vec::new();
    chunked_body.extend_from_slice(
        format!("{:x};chunk-signature={}\r\n", data.len(), chunk_sig).as_bytes(),
    );
    chunked_body.extend_from_slice(data);
    chunked_body.extend_from_slice(b"\r\n");
    chunked_body.extend_from_slice(format!("0;chunk-signature={}\r\n", chunk_sig).as_bytes());

    client()
        .put(url)
        .header("host", &host_header)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", payload_hash)
        .header("x-amz-decoded-content-length", data.len().to_string())
        .header("authorization", &auth)
        .header("content-type", "application/octet-stream")
        .body(chunked_body)
        .send()
        .await
        .unwrap()
}

pub(crate) fn extract_xml_tag(body: &str, tag: &str) -> Option<String> {
    let start = format!("<{}>", tag);
    let end = format!("</{}>", tag);
    let from = body.find(&start)? + start.len();
    let to = body[from..].find(&end)? + from;
    Some(body[from..to].to_string())
}
