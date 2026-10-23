//! Direct, path-style S3 transport. Redirects and environment proxies are disabled.
use super::{SyncOptions, local};
use crate::auth::signature_v4::{PresignRequest, generate_presigned_url};
use anyhow::{Context, Result, bail, ensure};
use reqwest::{Client, Method, Response, StatusCode, Url};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

pub struct Peer {
    client: Client,
    endpoint: Url,
    bucket: String,
    prefix: String,
    access_key: String,
    secret_key: String,
    region: String,
    limit: u64,
}

#[derive(Clone, Debug)]
pub struct RemoteFile {
    pub etag: String,
}

#[derive(Deserialize)]
#[serde(rename = "ListBucketResult")]
struct Listing {
    #[serde(rename = "IsTruncated")]
    truncated: bool,
    #[serde(rename = "Contents", default)]
    contents: Vec<ListedObject>,
    #[serde(rename = "NextContinuationToken")]
    next: Option<String>,
    #[serde(rename = "EncodingType")]
    encoding: Option<String>,
}

#[derive(Deserialize)]
struct ListedObject {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "ETag")]
    etag: String,
    #[serde(rename = "Size")]
    size: u64,
}

impl Peer {
    pub fn new(options: &SyncOptions) -> Result<Self> {
        let endpoint = Url::parse(&options.endpoint).context("invalid peer endpoint")?;
        ensure!(
            matches!(endpoint.scheme(), "http" | "https") && endpoint.host_str().is_some(),
            "peer endpoint must be an HTTP(S) origin"
        );
        ensure!(
            endpoint.username().is_empty()
                && endpoint.password().is_none()
                && endpoint.query().is_none()
                && endpoint.fragment().is_none()
                && matches!(endpoint.path(), "" | "/"),
            "peer endpoint must be an origin without credentials, path, query, or fragment"
        );
        ensure!(
            !options.bucket.is_empty()
                && options.bucket.len() <= 63
                && options.bucket.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == b'-'
                    || b == b'.'),
            "invalid bucket name"
        );
        ensure!(
            !options.access_key.is_empty() && !options.secret_key.is_empty(),
            "S3 credentials are required"
        );
        ensure!(
            !options.prefix.starts_with('/'),
            "sync prefix must be relative"
        );
        let prefix = options.prefix.trim_end_matches('/');
        if !prefix.is_empty() {
            local::validate_relative(prefix)?;
        }
        let mut client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(120));
        if let Some(path) = &options.ca_cert {
            ensure!(
                endpoint.scheme() == "https",
                "--ca-cert requires an HTTPS endpoint"
            );
            let pem = std::fs::read(path).context("cannot read sync CA bundle")?;
            let certificates = reqwest::Certificate::from_pem_bundle(&pem)
                .context("sync CA bundle contains an invalid certificate")?;
            ensure!(
                !certificates.is_empty(),
                "sync CA bundle contains no certificates"
            );
            client = client.tls_built_in_root_certs(false);
            for certificate in certificates {
                client = client.add_root_certificate(certificate);
            }
        }
        Ok(Self {
            client: client
                .build()
                .context("cannot configure direct peer transport")?,
            endpoint,
            bucket: options.bucket.clone(),
            prefix: if prefix.is_empty() {
                String::new()
            } else {
                format!("{prefix}/")
            },
            access_key: options.access_key.clone(),
            secret_key: options.secret_key.clone(),
            region: options.region.clone(),
            limit: options.max_file_bytes,
        })
    }

    pub fn scope(&self, root: &str) -> String {
        // Credentials deliberately do not enter the journal or its identity.
        serde_json::json!({"root": root, "endpoint": self.endpoint.as_str(), "bucket": self.bucket, "prefix": self.prefix}).to_string()
    }

    fn request(
        &self,
        method: Method,
        key: Option<&str>,
        query: &[(&str, &str)],
    ) -> Result<reqwest::RequestBuilder> {
        let host = self
            .endpoint
            .as_str()
            .split_once("://")
            .context("peer origin is missing its scheme")?
            .1
            .trim_end_matches('/');
        let path = key.map_or_else(
            || format!("/{}", self.bucket),
            |key| format!("/{}/{}{}", self.bucket, self.prefix, key),
        );
        // Encode each raw key segment once before the shared signer canonicalizes it.
        const ENCODE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
            .remove(b'-')
            .remove(b'_')
            .remove(b'.')
            .remove(b'~');
        let encoded = path
            .split('/')
            .map(|segment| percent_encoding::utf8_percent_encode(segment, ENCODE).to_string())
            .collect::<Vec<_>>()
            .join("/");
        let url = generate_presigned_url(PresignRequest {
            method: method.as_str(),
            scheme: self.endpoint.scheme(),
            host,
            path: &encoded,
            extra_query_params: query,
            access_key: &self.access_key,
            secret_key: &self.secret_key,
            region: &self.region,
            now: chrono::Utc::now(),
            expires_secs: 300,
        })
        .map_err(anyhow::Error::msg)?;
        Ok(self.client.request(method, url))
    }

    async fn send(request: reqwest::RequestBuilder) -> Result<Response> {
        // Never log the presigned URL (it contains a temporary bearer signature).
        request
            .send()
            .await
            .map_err(|error| anyhow::Error::new(error.without_url()))
            .context("direct peer request failed")
    }

    async fn bounded_body(mut response: Response, limit: u64) -> Result<Vec<u8>> {
        ensure!(
            response.content_length().is_none_or(|n| n <= limit),
            "peer response exceeds configured size limit"
        );
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| anyhow::Error::new(e.without_url()))?
        {
            ensure!(
                (body.len() as u64).saturating_add(chunk.len() as u64) <= limit,
                "peer response exceeds configured size limit"
            );
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    pub async fn list(&self) -> Result<BTreeMap<String, RemoteFile>> {
        let mut files = BTreeMap::new();
        let mut token: Option<String> = None;
        let mut seen = BTreeSet::new();
        loop {
            let mut query = vec![
                ("list-type", "2"),
                ("prefix", self.prefix.as_str()),
                ("max-keys", "1000"),
            ];
            if let Some(ref token) = token {
                query.push(("continuation-token", token.as_str()));
            }
            let response = Self::send(self.request(Method::GET, None, &query)?).await?;
            ensure!(
                response.status() == StatusCode::OK,
                "peer listing failed: HTTP {} (bucket must already exist)",
                response.status()
            );
            let body = Self::bounded_body(response, 16 * 1024 * 1024).await?;
            let text = std::str::from_utf8(&body).context("peer listing is not UTF-8 XML")?;
            let mut reader = quick_xml::Reader::from_str(text);
            loop {
                match reader.read_event()? {
                    quick_xml::events::Event::Start(event) => {
                        ensure!(
                            event.local_name().as_ref() == b"ListBucketResult",
                            "unexpected peer listing document"
                        );
                        break;
                    }
                    quick_xml::events::Event::Eof => bail!("empty peer listing document"),
                    _ => {}
                }
            }
            let page: Listing =
                quick_xml::de::from_str(text).context("invalid or incomplete peer listing XML")?;
            ensure!(
                page.encoding.is_none(),
                "unexpected encoded peer listing; refusing ambiguous filenames"
            );
            for item in page.contents {
                let key = item
                    .key
                    .strip_prefix(&self.prefix)
                    .context("peer returned a key outside selected prefix")?;
                if key.starts_with(".maxio-sync/") {
                    continue;
                }
                if key.ends_with('/') && item.size == 0 {
                    continue;
                }
                local::validate_relative(key)?;
                ensure!(
                    item.size <= self.limit,
                    "remote file exceeds --max-file-mib: {key:?}"
                );
                ensure!(
                    !item.etag.is_empty(),
                    "peer listing omitted object ETag: {key:?}"
                );
                ensure!(
                    files
                        .insert(key.to_string(), RemoteFile { etag: item.etag })
                        .is_none(),
                    "duplicate key in paginated peer listing: {key:?}"
                );
            }
            if !page.truncated {
                break;
            }
            let next = page
                .next
                .filter(|s| !s.is_empty())
                .context("truncated peer listing has no continuation token")?;
            ensure!(
                seen.insert(next.clone()),
                "peer listing repeated a continuation token"
            );
            token = Some(next);
        }
        local::validate_path_set(files.keys())?;
        Ok(files)
    }

    pub async fn get(&self, key: &str, expected_etag: &str) -> Result<Vec<u8>> {
        let response = Self::send(
            self.request(Method::GET, Some(key), &[])?
                .header("if-match", expected_etag),
        )
        .await?;
        ensure!(
            response.status() == StatusCode::OK,
            "peer download failed or changed: {key:?}, HTTP {}",
            response.status()
        );
        ensure!(
            etag(&response)? == expected_etag,
            "peer object changed after listing: {key:?}; retry"
        );
        Self::bounded_body(response, self.limit).await
    }

    async fn put_response(
        &self,
        key: &str,
        bytes: &[u8],
        expected: Option<&str>,
    ) -> Result<Response> {
        let request = self
            .request(Method::PUT, Some(key), &[])?
            .header("content-type", "application/octet-stream")
            .body(bytes.to_vec());
        let request = if let Some(etag) = expected {
            request.header("if-match", etag)
        } else {
            request.header("if-none-match", "*")
        };
        Self::send(request).await
    }

    pub async fn put(&self, key: &str, bytes: &[u8], expected: Option<&str>) -> Result<String> {
        let response = self.put_response(key, bytes, expected).await?;
        ensure!(
            response.status() == StatusCode::OK,
            "conditional upload rejected: {key:?}, HTTP {}; retry to reconcile concurrent changes",
            response.status()
        );
        etag(&response)
    }

    /// Probe only a new random object in the reserved namespace. An S3-like
    /// endpoint that ignores conditions must never receive user-data uploads.
    pub async fn verify_conditional_writes(&self) -> Result<()> {
        let key = format!(".maxio-sync/probes/{}", uuid::Uuid::new_v4());
        let created = self.put(&key, b"maxio-sync-probe-a", None).await?;
        let outcome = async {
            let rejected = self.put_response(&key, b"maxio-sync-probe-b", None).await?;
            ensure!(
                rejected.status() == StatusCode::PRECONDITION_FAILED,
                "peer does not enforce If-None-Match; refusing sync writes"
            );
            let rejected = self
                .put_response(
                    &key,
                    b"maxio-sync-probe-c",
                    Some("\"maxio-sync-stale-etag\""),
                )
                .await?;
            ensure!(
                rejected.status() == StatusCode::PRECONDITION_FAILED,
                "peer does not enforce If-Match; refusing sync writes"
            );
            let updated = self
                .put(&key, b"maxio-sync-probe-d", Some(&created))
                .await?;
            ensure!(
                self.get(&key, &updated).await? == b"maxio-sync-probe-d",
                "peer conditional write probe returned incorrect bytes"
            );
            Ok(())
        }
        .await;
        let cleanup = Self::send(self.request(Method::DELETE, Some(&key), &[])?).await?;
        ensure!(
            cleanup.status().is_success(),
            "could not remove reserved capability probe: HTTP {}",
            cleanup.status()
        );
        outcome
    }
}

fn etag(response: &Response) -> Result<String> {
    let value = response
        .headers()
        .get("etag")
        .context("peer response omitted ETag")?
        .to_str()
        .context("peer returned invalid ETag")?;
    ensure!(!value.is_empty(), "peer returned empty ETag");
    Ok(value.to_string())
}
