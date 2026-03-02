//! SigV4 compatibility envelope (current implementation).
//!
//! Supported:
//! - Header-based `Authorization: AWS4-HMAC-SHA256 ...` signatures.
//! - Presigned URL signatures with `X-Amz-*` query parameters.
//! - Canonical query normalization by decode -> sort -> re-encode.
//! - Canonical header handling for duplicate values (`v1,v2`) with whitespace collapse.
//! - `x-amz-content-sha256` payload hash and `UNSIGNED-PAYLOAD`.
//!
//! Intentionally not modeled here:
//! - IAM/policy evaluation and fine-grained authorization policy decisions.
//! - SigV4a / region-agnostic signing variants.
//! - Chunk-signature streaming semantics beyond request-level signature verification.

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use http::HeaderMap;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Characters that do NOT get percent-encoded in S3 SigV4 canonical URI.
/// Per AWS spec: A-Z, a-z, 0-9, '-', '_', '.', '~'
const S3_URI_ENCODE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

pub struct ParsedAuth {
    pub access_key: String,
    pub date: String,
    pub region: String,
    pub signed_headers: Vec<String>,
    pub signature: String,
}

fn is_valid_header_name_token(token: &str) -> bool {
    !token.is_empty()
        && token.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn parse_signed_headers(value: &str) -> Result<Vec<String>, &'static str> {
    let mut signed_headers = Vec::<String>::new();

    for raw_token in value.split(';') {
        let token = raw_token.trim().to_ascii_lowercase();
        if token.is_empty() || !is_valid_header_name_token(&token) {
            return Err("Invalid SignedHeaders");
        }
        if signed_headers.iter().any(|h| h == &token) {
            return Err("Duplicate SignedHeaders entry");
        }
        signed_headers.push(token);
    }

    if !signed_headers.iter().any(|header| header == "host") {
        return Err("SignedHeaders must include host");
    }

    Ok(signed_headers)
}

fn decode_query_component(input: &str) -> Result<String, &'static str> {
    percent_encoding::percent_decode_str(input)
        .decode_utf8()
        .map(|v| v.into_owned())
        .map_err(|_| "Invalid query encoding")
}

fn query_pair_has_key(pair: &str, expected_key: &str) -> bool {
    let raw_key = pair.split('=').next().unwrap_or("");
    if raw_key == expected_key {
        return true;
    }
    decode_query_component(raw_key)
        .map(|decoded| decoded == expected_key)
        .unwrap_or(false)
}

pub fn has_presigned_signature_query_param(query: &str) -> bool {
    query
        .split('&')
        .any(|pair| query_pair_has_key(pair, "X-Amz-Signature"))
}

pub fn parse_authorization_header(header: &str) -> Result<ParsedAuth, &'static str> {
    let header = header
        .strip_prefix("AWS4-HMAC-SHA256 ")
        .ok_or("Invalid auth algorithm")?;

    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;

    // Split on "," — some clients use ", " (with space), others use "," (no space)
    for part in header.split(',') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("Credential=") {
            if credential.replace(val).is_some() {
                return Err("Duplicate Credential");
            }
        } else if let Some(val) = part.strip_prefix("SignedHeaders=") {
            if signed_headers.replace(val).is_some() {
                return Err("Duplicate SignedHeaders");
            }
        } else if let Some(val) = part.strip_prefix("Signature=") {
            if signature.replace(val).is_some() {
                return Err("Duplicate Signature");
            }
        } else {
            return Err("Invalid auth component");
        }
    }

    let credential = credential.ok_or("Missing Credential")?;
    let signed_headers = signed_headers.ok_or("Missing SignedHeaders")?;
    let signature = signature.ok_or("Missing Signature")?;

    let cred_parts: Vec<&str> = credential.splitn(5, '/').collect();
    if cred_parts.len() != 5 {
        return Err("Invalid Credential format");
    }
    validate_credential_scope_parts(&cred_parts)?;

    let signed_headers = parse_signed_headers(signed_headers)?;

    Ok(ParsedAuth {
        access_key: cred_parts[0].to_string(),
        date: cred_parts[1].to_string(),
        region: cred_parts[2].to_string(),
        signed_headers,
        signature: signature.to_string(),
    })
}

pub fn verify_signature(
    method: &str,
    uri: &str,
    query_string: &str,
    headers: &HeaderMap,
    parsed: &ParsedAuth,
    secret_key: &str,
) -> bool {
    let canonical_request =
        match build_canonical_request(method, uri, query_string, headers, parsed) {
            Some(request) => request,
            None => return false,
        };

    tracing::debug!("Canonical request:\n{}", canonical_request);

    let timestamp = headers
        .get("x-amz-date")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let string_to_sign = build_string_to_sign(&canonical_request, timestamp, parsed);

    tracing::debug!("String to sign:\n{}", string_to_sign);

    let signing_key = derive_signing_key(secret_key, &parsed.date, &parsed.region);
    if signing_key.is_empty() {
        return false;
    }
    let computed = match hmac_sha256_hex(&signing_key, string_to_sign.as_bytes()) {
        Some(signature) => signature,
        None => return false,
    };

    tracing::debug!("Computed signature: {}", computed);
    tracing::debug!("Provided signature: {}", parsed.signature);

    constant_time_eq(computed.as_bytes(), parsed.signature.as_bytes())
}

/// Parse presigned URL query parameters into auth components.
/// Returns (ParsedAuth, timestamp, expires_seconds).
pub fn parse_presigned_query(query: &str) -> Result<(ParsedAuth, String, u64), &'static str> {
    let mut algorithm = None;
    let mut credential = None;
    let mut date = None;
    let mut expires = None;
    let mut signed_headers = None;
    let mut signature = None;

    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let raw_key = parts.next().unwrap_or("");
        let raw_val = parts.next().unwrap_or("");
        let key = decode_query_component(raw_key)?;
        let val = decode_query_component(raw_val)?;
        match key.as_str() {
            "X-Amz-Algorithm" => {
                if algorithm.replace(val).is_some() {
                    return Err("Duplicate X-Amz-Algorithm");
                }
            }
            "X-Amz-Credential" => {
                if credential.replace(val).is_some() {
                    return Err("Duplicate X-Amz-Credential");
                }
            }
            "X-Amz-Date" => {
                if date.replace(val).is_some() {
                    return Err("Duplicate X-Amz-Date");
                }
            }
            "X-Amz-Expires" => {
                if expires.replace(val).is_some() {
                    return Err("Duplicate X-Amz-Expires");
                }
            }
            "X-Amz-SignedHeaders" => {
                if signed_headers.replace(val).is_some() {
                    return Err("Duplicate X-Amz-SignedHeaders");
                }
            }
            "X-Amz-Signature" => {
                if signature.replace(val).is_some() {
                    return Err("Duplicate X-Amz-Signature");
                }
            }
            _ => {}
        }
    }

    let algorithm = algorithm.ok_or("Missing X-Amz-Algorithm")?;
    if algorithm != "AWS4-HMAC-SHA256" {
        return Err("Invalid X-Amz-Algorithm");
    }

    let credential = credential.ok_or("Missing X-Amz-Credential")?;
    let timestamp = date.ok_or("Missing X-Amz-Date")?.to_string();
    let expires_str = expires.ok_or("Missing X-Amz-Expires")?;
    let signed_headers = signed_headers.ok_or("Missing X-Amz-SignedHeaders")?;
    let signature = signature.ok_or("Missing X-Amz-Signature")?;

    let expires_secs: u64 = expires_str.parse().map_err(|_| "Invalid X-Amz-Expires")?;
    if expires_secs == 0 {
        return Err("X-Amz-Expires must be greater than 0 seconds");
    }
    if expires_secs > 604800 {
        return Err("X-Amz-Expires exceeds maximum of 604800 seconds");
    }

    // Credential value is normalized via percent-decoding during query parsing.
    let cred_parts: Vec<&str> = credential.splitn(5, '/').collect();
    if cred_parts.len() != 5 {
        return Err("Invalid Credential format");
    }
    validate_credential_scope_parts(&cred_parts)?;

    let signed_headers = parse_signed_headers(&signed_headers)?;

    let parsed = ParsedAuth {
        access_key: cred_parts[0].to_string(),
        date: cred_parts[1].to_string(),
        region: cred_parts[2].to_string(),
        signed_headers,
        signature: signature.to_string(),
    };

    Ok((parsed, timestamp, expires_secs))
}

fn validate_credential_scope_parts(cred_parts: &[&str]) -> Result<(), &'static str> {
    let access_key = cred_parts[0];
    let date = cred_parts[1];
    let service = cred_parts[3];
    let terminator = cred_parts[4];

    if access_key.is_empty() {
        return Err("Invalid Credential format");
    }
    if date.len() != 8 || !date.chars().all(|c| c.is_ascii_digit()) {
        return Err("Invalid credential date");
    }
    if service != "s3" {
        return Err("Invalid service in credential scope");
    }
    if terminator != "aws4_request" {
        return Err("Invalid credential scope terminator");
    }

    Ok(())
}

/// Verify a presigned URL signature.
pub fn verify_presigned_signature(
    method: &str,
    uri: &str,
    query_string: &str,
    headers: &HeaderMap,
    parsed: &ParsedAuth,
    timestamp: &str,
    secret_key: &str,
) -> bool {
    // Build canonical query string excluding X-Amz-Signature
    let filtered_qs: String = query_string
        .split('&')
        .filter(|pair| !query_pair_has_key(pair, "X-Amz-Signature"))
        .collect::<Vec<_>>()
        .join("&");

    let canonical_uri = canonical_uri(uri);
    let canonical_qs = canonical_query_string(&filtered_qs);
    let canonical_hdrs = match canonical_headers(headers, &parsed.signed_headers) {
        Some(headers) => headers,
        None => return false,
    };
    let signed_headers = parsed.signed_headers.join(";");

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\nUNSIGNED-PAYLOAD",
        method, canonical_uri, canonical_qs, canonical_hdrs, signed_headers
    );

    tracing::debug!("Presigned canonical request:\n{}", canonical_request);

    let string_to_sign = build_string_to_sign(&canonical_request, timestamp, parsed);

    tracing::debug!("Presigned string to sign:\n{}", string_to_sign);

    let signing_key = derive_signing_key(secret_key, &parsed.date, &parsed.region);
    if signing_key.is_empty() {
        return false;
    }
    let computed = match hmac_sha256_hex(&signing_key, string_to_sign.as_bytes()) {
        Some(signature) => signature,
        None => return false,
    };

    tracing::debug!("Computed signature: {}", computed);
    tracing::debug!("Provided signature: {}", parsed.signature);

    constant_time_eq(computed.as_bytes(), parsed.signature.as_bytes())
}

pub struct PresignRequest<'a> {
    pub method: &'a str,
    pub scheme: &'a str,
    pub host: &'a str,
    pub path: &'a str,
    pub extra_query_params: &'a [(&'a str, &'a str)],
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub region: &'a str,
    pub now: DateTime<Utc>,
    pub expires_secs: u64,
}

/// Generate a SigV4 presigned URL for a single request.
pub fn generate_presigned_url(request: PresignRequest<'_>) -> Result<String, &'static str> {
    let PresignRequest {
        method,
        scheme,
        host,
        path,
        extra_query_params,
        access_key,
        secret_key,
        region,
        now,
        expires_secs,
    } = request;

    if expires_secs == 0 {
        return Err("X-Amz-Expires must be greater than 0 seconds");
    }
    if expires_secs > 604800 {
        return Err("X-Amz-Expires exceeds maximum of 604800 seconds");
    }

    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let credential = format!("{}/{}/{}/s3/aws4_request", access_key, date_stamp, region);

    let mut params = vec![
        (
            "X-Amz-Algorithm".to_string(),
            "AWS4-HMAC-SHA256".to_string(),
        ),
        ("X-Amz-Credential".to_string(), credential),
        ("X-Amz-Date".to_string(), amz_date.clone()),
        ("X-Amz-Expires".to_string(), expires_secs.to_string()),
        ("X-Amz-SignedHeaders".to_string(), "host".to_string()),
    ];
    for (key, value) in extra_query_params {
        params.push(((*key).to_string(), (*value).to_string()));
    }
    params.sort_by(|a, b| a.0.cmp(&b.0));

    let canonical_qs = params
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                percent_encoding::utf8_percent_encode(k, S3_URI_ENCODE),
                percent_encoding::utf8_percent_encode(v, S3_URI_ENCODE)
            )
        })
        .collect::<Vec<_>>()
        .join("&");

    let canonical_path = canonical_uri(path);
    let canonical_headers = format!("host:{}\n", host);
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\nhost\nUNSIGNED-PAYLOAD",
        method, canonical_path, canonical_qs, canonical_headers
    );

    let parsed = ParsedAuth {
        access_key: access_key.to_string(),
        date: date_stamp.clone(),
        region: region.to_string(),
        signed_headers: vec!["host".to_string()],
        signature: String::new(),
    };
    let string_to_sign = build_string_to_sign(&canonical_request, &amz_date, &parsed);

    let signing_key = derive_signing_key(secret_key, &date_stamp, region);
    if signing_key.is_empty() {
        return Err("Failed to derive signing key");
    }
    let signature =
        hmac_sha256_hex(&signing_key, string_to_sign.as_bytes()).ok_or("Failed to sign request")?;

    Ok(format!(
        "{}://{}{}?{}&X-Amz-Signature={}",
        scheme, host, canonical_path, canonical_qs, signature
    ))
}

fn build_canonical_request(
    method: &str,
    uri: &str,
    query_string: &str,
    headers: &HeaderMap,
    parsed: &ParsedAuth,
) -> Option<String> {
    let canonical_uri = canonical_uri(uri);
    let canonical_qs = canonical_query_string(query_string);
    let canonical_headers = canonical_headers(headers, &parsed.signed_headers)?;
    let signed_headers = parsed.signed_headers.join(";");

    let payload_hash = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("UNSIGNED-PAYLOAD");

    Some(format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, canonical_uri, canonical_qs, canonical_headers, signed_headers, payload_hash
    ))
}

fn canonical_uri(uri: &str) -> String {
    let path = uri.split('?').next().unwrap_or("/");
    if path.is_empty() || path == "/" {
        return "/".to_string();
    }
    // Decode then re-encode each segment to avoid double-encoding and to
    // normalize already-encoded incoming request URIs.
    let segments: Vec<String> = path
        .split('/')
        .map(|s| {
            let decoded = percent_encoding::percent_decode_str(s)
                .decode_utf8_lossy()
                .into_owned();
            percent_encoding::utf8_percent_encode(&decoded, S3_URI_ENCODE).to_string()
        })
        .collect();
    segments.join("/")
}

fn canonical_query_string(qs: &str) -> String {
    if qs.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(String, String)> = qs
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next().unwrap_or("").to_string();
            let val = parts.next().unwrap_or("").to_string();
            // Decode first (values arrive already percent-encoded from HTTP),
            // then re-encode to normalize per AWS SigV4 spec.
            let key_decoded = percent_encoding::percent_decode_str(&key)
                .decode_utf8_lossy()
                .into_owned();
            let val_decoded = percent_encoding::percent_decode_str(&val)
                .decode_utf8_lossy()
                .into_owned();
            (key_decoded, val_decoded)
        })
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                percent_encoding::utf8_percent_encode(k, S3_URI_ENCODE),
                percent_encoding::utf8_percent_encode(v, S3_URI_ENCODE)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn canonical_headers(headers: &HeaderMap, signed_headers: &[String]) -> Option<String> {
    let mut result = String::new();
    for name in signed_headers {
        // Collect all values for this header (there can be multiple).
        // SigV4 requires every signed header to be present in the request.
        let values = headers.get_all(name.as_str());
        let mut normalized_values = Vec::<String>::new();
        for value in values {
            let value = value.to_str().ok()?;
            normalized_values.push(normalize_header_value(value));
        }

        if normalized_values.is_empty() {
            return None;
        }

        result.push_str(name);
        result.push(':');
        result.push_str(&normalized_values.join(","));
        result.push('\n');
    }
    Some(result)
}

fn normalize_header_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn build_string_to_sign(canonical_request: &str, timestamp: &str, parsed: &ParsedAuth) -> String {
    let scope = format!("{}/{}/s3/aws4_request", parsed.date, parsed.region);

    let hash = Sha256::digest(canonical_request.as_bytes());
    let canonical_hash = hex::encode(hash);

    format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        timestamp, scope, canonical_hash
    )
}

pub fn derive_signing_key(secret_key: &str, date: &str, region: &str) -> Vec<u8> {
    let key = format!("AWS4{}", secret_key);
    let Some(date_key) = hmac_sha256(key.as_bytes(), date.as_bytes()) else {
        return Vec::new();
    };
    let Some(date_region_key) = hmac_sha256(&date_key, region.as_bytes()) else {
        return Vec::new();
    };
    let Some(date_region_service_key) = hmac_sha256(&date_region_key, b"s3") else {
        return Vec::new();
    };
    hmac_sha256(&date_region_service_key, b"aws4_request").unwrap_or_default()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).ok()?;
    mac.update(data);
    Some(mac.finalize().into_bytes().to_vec())
}

fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> Option<String> {
    hmac_sha256(key, data).map(hex::encode)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;
    use std::str::FromStr;

    #[test]
    fn parse_authorization_header_accepts_spaces_and_compact_format() {
        let header = "AWS4-HMAC-SHA256 Signature=abc123,Credential=minioadmin/20260301/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date";
        let parsed = parse_authorization_header(header).unwrap();

        assert_eq!(parsed.access_key, "minioadmin");
        assert_eq!(parsed.date, "20260301");
        assert_eq!(parsed.region, "us-east-1");
        assert_eq!(parsed.signature, "abc123");
        assert_eq!(parsed.signed_headers, vec!["host", "x-amz-date"]);
    }

    #[test]
    fn canonical_uri_encodes_segments_but_preserves_slashes() {
        assert_eq!(canonical_uri(""), "/");
        assert_eq!(canonical_uri("/"), "/");
        assert_eq!(
            canonical_uri("/photos/Jan 2026/ça+t"),
            "/photos/Jan%202026/%C3%A7a%2Bt"
        );
        assert_eq!(
            canonical_uri("/photos/Jan%202026/%C3%A7a%2Bt"),
            "/photos/Jan%202026/%C3%A7a%2Bt"
        );
    }

    #[test]
    fn canonical_query_string_sorts_and_normalizes_pairs() {
        let qs = "b=two&a=1&z=%7E&a=0&space=hello%20world&plus=a+b";
        let canonical = canonical_query_string(qs);
        assert_eq!(
            canonical,
            "a=0&a=1&b=two&plus=a%2Bb&space=hello%20world&z=~"
        );
    }

    #[test]
    fn canonical_headers_merges_duplicate_values_and_normalizes_whitespace() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-meta-foo",
            HeaderValue::from_str("  one\t two  ").unwrap(),
        );
        headers.append(
            "x-amz-meta-foo",
            HeaderValue::from_str("three   four").unwrap(),
        );

        let signed = vec!["x-amz-meta-foo".to_string()];
        let canonical = canonical_headers(&headers, &signed).expect("canonical headers");
        assert_eq!(canonical, "x-amz-meta-foo:one two,three four\n");
    }

    #[test]
    fn canonical_headers_rejects_missing_signed_header() {
        let headers = HeaderMap::new();
        let signed = vec!["x-amz-meta-missing".to_string()];
        assert!(canonical_headers(&headers, &signed).is_none());
    }

    #[test]
    fn verify_signature_rejects_missing_signed_header() {
        let method = "GET";
        let uri = "/bucket/object";
        let query_string = "";

        let mut full_headers = HeaderMap::new();
        full_headers.insert("host", HeaderValue::from_static("localhost:9000"));
        full_headers.insert("x-amz-date", HeaderValue::from_static("20260301T120000Z"));
        full_headers.insert(
            "x-amz-content-sha256",
            HeaderValue::from_static("UNSIGNED-PAYLOAD"),
        );
        full_headers.insert("x-amz-meta-probe", HeaderValue::from_static(""));

        let mut parsed = ParsedAuth {
            access_key: "minioadmin".to_string(),
            date: "20260301".to_string(),
            region: "us-east-1".to_string(),
            signed_headers: vec![
                "host".to_string(),
                "x-amz-content-sha256".to_string(),
                "x-amz-date".to_string(),
                "x-amz-meta-probe".to_string(),
            ],
            signature: String::new(),
        };

        let canonical_request =
            build_canonical_request(method, uri, query_string, &full_headers, &parsed)
                .expect("full signed headers should canonicalize");
        let timestamp = full_headers
            .get("x-amz-date")
            .and_then(|v| v.to_str().ok())
            .expect("x-amz-date should be present");
        let string_to_sign = build_string_to_sign(&canonical_request, timestamp, &parsed);
        let signing_key = derive_signing_key("minioadmin", &parsed.date, &parsed.region);
        parsed.signature = hmac_sha256_hex(&signing_key, string_to_sign.as_bytes())
            .expect("signature should compute");

        assert!(verify_signature(
            method,
            uri,
            query_string,
            &full_headers,
            &parsed,
            "minioadmin"
        ));

        let mut missing_headers = full_headers.clone();
        missing_headers.remove("x-amz-meta-probe");
        assert!(!verify_signature(
            method,
            uri,
            query_string,
            &missing_headers,
            &parsed,
            "minioadmin"
        ));
    }

    #[test]
    fn verify_presigned_signature_rejects_missing_signed_header() {
        let method = "GET";
        let path = "/bucket/object";
        let timestamp = "20260301T120000Z";
        let mut parsed = ParsedAuth {
            access_key: "minioadmin".to_string(),
            date: "20260301".to_string(),
            region: "us-east-1".to_string(),
            signed_headers: vec!["host".to_string(), "x-amz-meta-probe".to_string()],
            signature: String::new(),
        };

        let filtered_qs = concat!(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&",
            "X-Amz-Credential=minioadmin%2F20260301%2Fus-east-1%2Fs3%2Faws4_request&",
            "X-Amz-Date=20260301T120000Z&",
            "X-Amz-Expires=300&",
            "X-Amz-SignedHeaders=host%3Bx-amz-meta-probe"
        );

        let mut full_headers = HeaderMap::new();
        full_headers.insert("host", HeaderValue::from_static("localhost:9000"));
        full_headers.insert("x-amz-meta-probe", HeaderValue::from_static(""));

        let canonical_uri = canonical_uri(path);
        let canonical_qs = canonical_query_string(filtered_qs);
        let canonical_hdrs = canonical_headers(&full_headers, &parsed.signed_headers)
            .expect("full signed headers should canonicalize");
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\nUNSIGNED-PAYLOAD",
            method,
            canonical_uri,
            canonical_qs,
            canonical_hdrs,
            parsed.signed_headers.join(";")
        );
        let string_to_sign = build_string_to_sign(&canonical_request, timestamp, &parsed);
        let signing_key = derive_signing_key("minioadmin", &parsed.date, &parsed.region);
        let signature = hmac_sha256_hex(&signing_key, string_to_sign.as_bytes())
            .expect("signature should compute");
        parsed.signature = signature.clone();
        let query = format!("{}&X-Amz-Signature={}", filtered_qs, signature);

        assert!(verify_presigned_signature(
            method,
            path,
            &query,
            &full_headers,
            &parsed,
            timestamp,
            "minioadmin"
        ));

        let mut missing_headers = full_headers.clone();
        missing_headers.remove("x-amz-meta-probe");
        assert!(!verify_presigned_signature(
            method,
            path,
            &query,
            &missing_headers,
            &parsed,
            timestamp,
            "minioadmin"
        ));
    }

    #[test]
    fn parse_presigned_query_rejects_expires_over_max() {
        let query = concat!(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&",
            "X-Amz-Credential=minioadmin%2F20260301%2Fus-east-1%2Fs3%2Faws4_request&",
            "X-Amz-Date=20260301T120000Z&",
            "X-Amz-Expires=604801&",
            "X-Amz-SignedHeaders=host&",
            "X-Amz-Signature=deadbeef"
        );
        assert!(parse_presigned_query(query).is_err());
    }

    #[test]
    fn parse_presigned_query_rejects_zero_expires() {
        let query = concat!(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&",
            "X-Amz-Credential=minioadmin%2F20260301%2Fus-east-1%2Fs3%2Faws4_request&",
            "X-Amz-Date=20260301T120000Z&",
            "X-Amz-Expires=0&",
            "X-Amz-SignedHeaders=host&",
            "X-Amz-Signature=deadbeef"
        );
        assert!(parse_presigned_query(query).is_err());
    }

    #[test]
    fn parse_authorization_header_rejects_invalid_scope_parts() {
        let bad_service = "AWS4-HMAC-SHA256 Credential=minioadmin/20260301/us-east-1/ec2/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc123";
        assert!(parse_authorization_header(bad_service).is_err());

        let bad_terminator = "AWS4-HMAC-SHA256 Credential=minioadmin/20260301/us-east-1/s3/aws4_bad, SignedHeaders=host;x-amz-date, Signature=abc123";
        assert!(parse_authorization_header(bad_terminator).is_err());

        let bad_date = "AWS4-HMAC-SHA256 Credential=minioadmin/2026AA01/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc123";
        assert!(parse_authorization_header(bad_date).is_err());
    }

    #[test]
    fn parse_authorization_header_rejects_duplicate_components() {
        let duplicate_credential = "AWS4-HMAC-SHA256 Credential=minioadmin/20260301/us-east-1/s3/aws4_request, Credential=minioadmin/20260301/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc123";
        assert!(parse_authorization_header(duplicate_credential).is_err());
    }

    #[test]
    fn parse_authorization_header_rejects_unrecognized_components() {
        let with_unknown = "AWS4-HMAC-SHA256 Credential=minioadmin/20260301/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc123, Foo=bar";
        assert!(parse_authorization_header(with_unknown).is_err());
    }

    #[test]
    fn parse_authorization_header_rejects_invalid_signed_headers() {
        let duplicate = "AWS4-HMAC-SHA256 Credential=minioadmin/20260301/us-east-1/s3/aws4_request, SignedHeaders=host;host, Signature=abc123";
        assert!(parse_authorization_header(duplicate).is_err());

        let missing_host = "AWS4-HMAC-SHA256 Credential=minioadmin/20260301/us-east-1/s3/aws4_request, SignedHeaders=x-amz-date, Signature=abc123";
        assert!(parse_authorization_header(missing_host).is_err());

        let invalid_token = "AWS4-HMAC-SHA256 Credential=minioadmin/20260301/us-east-1/s3/aws4_request, SignedHeaders=host;bad header, Signature=abc123";
        assert!(parse_authorization_header(invalid_token).is_err());
    }

    #[test]
    fn parse_presigned_query_rejects_invalid_scope_parts() {
        let bad_service = concat!(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&",
            "X-Amz-Credential=minioadmin%2F20260301%2Fus-east-1%2Fec2%2Faws4_request&",
            "X-Amz-Date=20260301T120000Z&",
            "X-Amz-Expires=60&",
            "X-Amz-SignedHeaders=host&",
            "X-Amz-Signature=deadbeef"
        );
        assert!(parse_presigned_query(bad_service).is_err());

        let bad_terminator = concat!(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&",
            "X-Amz-Credential=minioadmin%2F20260301%2Fus-east-1%2Fs3%2Faws4_bad&",
            "X-Amz-Date=20260301T120000Z&",
            "X-Amz-Expires=60&",
            "X-Amz-SignedHeaders=host&",
            "X-Amz-Signature=deadbeef"
        );
        assert!(parse_presigned_query(bad_terminator).is_err());
    }

    #[test]
    fn parse_presigned_query_rejects_duplicate_components() {
        let duplicate_date = concat!(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&",
            "X-Amz-Credential=minioadmin%2F20260301%2Fus-east-1%2Fs3%2Faws4_request&",
            "X-Amz-Date=20260301T120000Z&",
            "X-Amz-Date=20260301T120500Z&",
            "X-Amz-Expires=60&",
            "X-Amz-SignedHeaders=host&",
            "X-Amz-Signature=deadbeef"
        );
        assert!(parse_presigned_query(duplicate_date).is_err());
    }

    #[test]
    fn parse_presigned_query_rejects_invalid_signed_headers() {
        let duplicate_signed_headers = concat!(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&",
            "X-Amz-Credential=minioadmin%2F20260301%2Fus-east-1%2Fs3%2Faws4_request&",
            "X-Amz-Date=20260301T120000Z&",
            "X-Amz-Expires=60&",
            "X-Amz-SignedHeaders=host%3Bhost&",
            "X-Amz-Signature=deadbeef",
        );
        assert!(parse_presigned_query(duplicate_signed_headers).is_err());

        let missing_host = concat!(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&",
            "X-Amz-Credential=minioadmin%2F20260301%2Fus-east-1%2Fs3%2Faws4_request&",
            "X-Amz-Date=20260301T120000Z&",
            "X-Amz-Expires=60&",
            "X-Amz-SignedHeaders=x-amz-date&",
            "X-Amz-Signature=deadbeef",
        );
        assert!(parse_presigned_query(missing_host).is_err());

        let invalid_token = concat!(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&",
            "X-Amz-Credential=minioadmin%2F20260301%2Fus-east-1%2Fs3%2Faws4_request&",
            "X-Amz-Date=20260301T120000Z&",
            "X-Amz-Expires=60&",
            "X-Amz-SignedHeaders=host%3Bbad%20header&",
            "X-Amz-Signature=deadbeef",
        );
        assert!(parse_presigned_query(invalid_token).is_err());
    }

    #[test]
    fn parse_presigned_query_decodes_percent_encoded_values() {
        let query = concat!(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&",
            "X-Amz-Credential=minioadmin%2F20260301%2Fus-east-1%2Fs3%2Faws4_request&",
            "X-Amz-Date=20260301T120000Z&",
            "X-Amz-Expires=60&",
            "X-Amz-SignedHeaders=host%3Bx-amz-date&",
            "X-Amz-Signature=deadbeef",
        );
        let (parsed, timestamp, expires) =
            parse_presigned_query(query).expect("query should parse");
        assert_eq!(parsed.access_key, "minioadmin");
        assert_eq!(parsed.date, "20260301");
        assert_eq!(parsed.region, "us-east-1");
        assert_eq!(parsed.signed_headers, vec!["host", "x-amz-date"]);
        assert_eq!(timestamp, "20260301T120000Z");
        assert_eq!(expires, 60);
    }

    #[test]
    fn parse_presigned_query_rejects_invalid_utf8_encoded_values() {
        let query = concat!(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&",
            "X-Amz-Credential=minioadmin%2F20260301%2Fus-east-1%2Fs3%2Faws4_request&",
            "X-Amz-Date=20260301T120000Z&",
            "X-Amz-Expires=60&",
            "X-Amz-SignedHeaders=host&",
            "X-Amz-Signature=%FF",
        );
        assert!(parse_presigned_query(query).is_err());
    }

    #[test]
    fn has_presigned_signature_query_param_detects_encoded_key() {
        let query_with_encoded_key = concat!(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&",
            "%58-Amz-Signature=deadbeef"
        );
        assert!(has_presigned_signature_query_param(query_with_encoded_key));
        assert!(!has_presigned_signature_query_param(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20260301T120000Z"
        ));
    }

    #[test]
    fn generate_presigned_url_rejects_expires_over_max() {
        let now = DateTime::<Utc>::from_str("2026-03-01T12:00:00Z").unwrap();
        let res = generate_presigned_url(PresignRequest {
            method: "GET",
            scheme: "http",
            host: "localhost:9000",
            path: "/bucket/object",
            extra_query_params: &[],
            access_key: "minioadmin",
            secret_key: "minioadmin",
            region: "us-east-1",
            now,
            expires_secs: 604801,
        });
        assert!(res.is_err());
    }

    #[test]
    fn generate_presigned_url_rejects_zero_expires() {
        let now = DateTime::<Utc>::from_str("2026-03-01T12:00:00Z").unwrap();
        let res = generate_presigned_url(PresignRequest {
            method: "GET",
            scheme: "http",
            host: "localhost:9000",
            path: "/bucket/object",
            extra_query_params: &[],
            access_key: "minioadmin",
            secret_key: "minioadmin",
            region: "us-east-1",
            now,
            expires_secs: 0,
        });
        assert!(res.is_err());
    }

    #[test]
    fn presigned_roundtrip_verifies_signature() {
        let now = DateTime::<Utc>::from_str("2026-03-01T12:00:00Z").unwrap();
        let path = "/bucket/object name.txt";
        let url = generate_presigned_url(PresignRequest {
            method: "GET",
            scheme: "http",
            host: "localhost:9000",
            path,
            extra_query_params: &[],
            access_key: "minioadmin",
            secret_key: "minioadmin",
            region: "us-east-1",
            now,
            expires_secs: 300,
        })
        .unwrap();

        let query = url.split('?').nth(1).unwrap();
        let (parsed, timestamp, _expires) = parse_presigned_query(query).unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("localhost:9000"));

        assert!(verify_presigned_signature(
            "GET",
            path,
            query,
            &headers,
            &parsed,
            &timestamp,
            "minioadmin"
        ));
    }

    #[test]
    fn presigned_roundtrip_with_extra_query_params_verifies_signature() {
        let now = DateTime::<Utc>::from_str("2026-03-01T12:00:00Z").unwrap();
        let path = "/bucket/object.txt";
        let url = generate_presigned_url(PresignRequest {
            method: "HEAD",
            scheme: "http",
            host: "localhost:9000",
            path,
            extra_query_params: &[("versionId", "ver-123")],
            access_key: "minioadmin",
            secret_key: "minioadmin",
            region: "us-east-1",
            now,
            expires_secs: 300,
        })
        .unwrap();

        let query = url.split('?').nth(1).unwrap();
        assert!(query.contains("versionId=ver-123"));
        let (parsed, timestamp, _expires) = parse_presigned_query(query).unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("localhost:9000"));

        assert!(verify_presigned_signature(
            "HEAD",
            path,
            query,
            &headers,
            &parsed,
            &timestamp,
            "minioadmin"
        ));
    }
}
