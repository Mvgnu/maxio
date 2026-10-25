//! Bounded transfers and deliberately explicit transport configuration.
use super::WorkspaceRemote;
use crate::workspace::contract::*;
use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use futures::{StreamExt, TryStreamExt, stream::FuturesUnordered};
use object_store::aws::{AmazonS3Builder, S3ConditionalPut};
use object_store::client::{HttpClient, HttpConnector};
use object_store::path::Path as ObjectPath;
use object_store::{ClientOptions, ObjectStore, PutMode, RetryConfig, UpdateVersion, UploadPart};
use sha2::{Digest, Sha256};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

const PART_BYTES: usize = 8 * 1024 * 1024;
const PARTS_IN_FLIGHT: usize = 2;
const MAX_UPLOAD_BYTES: u64 = PART_BYTES as u64 * 10_000;

#[derive(Default)]
pub(super) struct Counters {
    uploaded: AtomicU64,
    downloaded: AtomicU64,
    metadata_up: AtomicU64,
    metadata_down: AtomicU64,
}

impl Counters {
    pub(super) fn snapshot(&self) -> TransferStats {
        TransferStats {
            payload_uploaded: self.uploaded.load(Ordering::Relaxed),
            payload_downloaded: self.downloaded.load(Ordering::Relaxed),
            metadata_uploaded: self.metadata_up.load(Ordering::Relaxed),
            metadata_downloaded: self.metadata_down.load(Ordering::Relaxed),
        }
    }
}

fn count(counter: &AtomicU64, bytes: usize) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(bytes as u64))
    });
}

#[derive(Debug)]
struct DirectConnector(reqwest::Client);

impl HttpConnector for DirectConnector {
    fn connect(&self, _options: &ClientOptions) -> object_store::Result<HttpClient> {
        Ok(HttpClient::new(self.0.clone()))
    }
}

pub(super) fn connect(config: RemoteConfig) -> Result<(Arc<dyn ObjectStore>, String, String)> {
    validate_name(&config.name)?;
    let endpoint = reqwest::Url::parse(&config.endpoint).context("invalid S3 endpoint")?;
    ensure!(
        matches!(endpoint.scheme(), "http" | "https")
            && endpoint.host_str().is_some()
            && endpoint.username().is_empty()
            && endpoint.password().is_none()
            && endpoint.query().is_none()
            && endpoint.fragment().is_none()
            && matches!(endpoint.path(), "" | "/"),
        "S3 endpoint must be an HTTP(S) origin without credentials, path, query or fragment"
    );
    ensure!(
        endpoint.scheme() == "https" || config.allow_http,
        "HTTP S3 endpoints require explicit allow_http"
    );
    ensure!(
        !config.bucket.is_empty()
            && config.bucket.len() <= 63
            && config
                .bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
            && !config.bucket.starts_with('.')
            && !config.bucket.ends_with('.')
            && !config.bucket.contains(".."),
        "invalid S3 bucket name"
    );
    ensure!(
        !config.access_key.is_empty() && !config.secret_key.is_empty(),
        "workspace storage requires explicit access key and secret key"
    );
    ensure!(
        !config.region.is_empty()
            && config.region.len() <= 128
            && config
                .region
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "invalid explicit S3 region"
    );
    ensure!(
        config
            .session_token
            .as_ref()
            .is_none_or(|token| !token.is_empty()),
        "empty S3 session token"
    );
    let mut client = reqwest::Client::builder()
        .use_rustls_tls()
        .https_only(!config.allow_http)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .read_timeout(Duration::from_secs(60))
        .no_gzip()
        .no_brotli()
        .no_zstd()
        .no_deflate();
    if let Some(path) = &config.ca_cert {
        ensure!(
            endpoint.scheme() == "https",
            "private CA requires an HTTPS endpoint"
        );
        let pem = std::fs::read(path).context("cannot read configured S3 CA certificate")?;
        let certificates =
            reqwest::Certificate::from_pem_bundle(&pem).context("invalid S3 CA PEM bundle")?;
        ensure!(!certificates.is_empty(), "S3 CA PEM bundle is empty");
        client = client.tls_built_in_root_certs(false);
        for certificate in certificates {
            client = client.add_root_certificate(certificate);
        }
    }
    let origin = endpoint.as_str().trim_end_matches('/').to_owned();
    let target =
        serde_json::json!({"endpoint": origin, "bucket": config.bucket, "name": config.name})
            .to_string();
    let prefix = format!("maxio-workspaces/{}/", config.name);
    let mut builder = AmazonS3Builder::new()
        .with_endpoint(origin)
        .with_bucket_name(config.bucket)
        .with_region(config.region)
        .with_access_key_id(config.access_key)
        .with_secret_access_key(config.secret_key)
        .with_allow_http(config.allow_http)
        .with_virtual_hosted_style_request(false)
        .with_conditional_put(S3ConditionalPut::ETagMatch)
        .with_retry(RetryConfig {
            max_retries: 2,
            retry_timeout: Duration::from_secs(20),
            ..Default::default()
        })
        .with_http_connector(DirectConnector(
            client.build().context("cannot configure S3 HTTP client")?,
        ));
    if let Some(token) = config.session_token {
        builder = builder.with_token(token);
    }
    Ok((
        Arc::new(builder.build().context("cannot configure S3 storage")?),
        target,
        prefix,
    ))
}

pub(super) fn hash_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(super) fn required_etag(etag: Option<String>) -> Result<String> {
    let etag = etag.context("S3 backend returned no ETag; safe publication unavailable")?;
    ensure!(
        !etag.is_empty() && etag.len() <= 1024 && etag.bytes().all(|b| (32..127).contains(&b)),
        "S3 backend returned an invalid conditional-write ETag"
    );
    Ok(etag)
}

pub(super) fn not_found(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<object_store::Error>(),
        Some(object_store::Error::NotFound { .. })
    )
}

pub(super) fn condition_failed(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<object_store::Error>(),
        Some(object_store::Error::Precondition { .. } | object_store::Error::AlreadyExists { .. })
    )
}

pub(super) async fn validate_source(file: &Publication) -> Result<()> {
    let metadata = tokio::fs::symlink_metadata(&file.source)
        .await
        .context("cannot inspect publication staging file")?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "publication source must be a regular staging file"
    );
    ensure!(
        metadata.len() == file.size,
        "publication staging size changed; local work is retained"
    );
    ensure!(
        file.size <= MAX_UPLOAD_BYTES,
        "file exceeds current 10,000 by 8 MiB multipart limit"
    );
    Ok(())
}

impl WorkspaceRemote {
    pub(super) async fn read_metadata(
        &self,
        key: &str,
        limit: usize,
    ) -> Result<(Vec<u8>, Option<String>)> {
        let result = self.store.get(&ObjectPath::from(key)).await?;
        ensure!(
            result.meta.size <= limit as u64,
            "workspace metadata exceeds configured bound"
        );
        let expected = result.meta.size;
        let etag = result.meta.e_tag.clone();
        let mut stream = result.into_stream();
        let mut bytes = Vec::with_capacity(expected as usize);
        while let Some(chunk) = stream.try_next().await? {
            count(&self.counters.metadata_down, chunk.len());
            ensure!(
                chunk.len() <= limit.saturating_sub(bytes.len()),
                "workspace metadata body exceeds configured bound"
            );
            bytes.extend_from_slice(&chunk);
        }
        ensure!(
            bytes.len() as u64 == expected,
            "workspace metadata body is truncated"
        );
        Ok((bytes, etag))
    }

    pub(super) async fn put_metadata(
        &self,
        key: &str,
        bytes: Vec<u8>,
        mode: PutMode,
    ) -> Result<Option<String>> {
        ensure!(
            bytes.len() <= MAX_MANIFEST_BYTES,
            "workspace metadata exceeds 8 MiB"
        );
        count(&self.counters.metadata_up, bytes.len());
        Ok(self
            .store
            .put_opts(
                &ObjectPath::from(key),
                Bytes::from(bytes).into(),
                mode.into(),
            )
            .await?
            .e_tag)
    }

    pub(super) async fn read_blob(
        &self,
        file: &FileVersion,
        mut destination: Option<&mut tokio::fs::File>,
    ) -> Result<()> {
        self.validate_blob(file)?;
        let result = self
            .store
            .get(&ObjectPath::from(file.blob.as_str()))
            .await?;
        ensure!(
            result.meta.size == file.size,
            "remote blob length differs from published version"
        );
        let mut stream = result.into_stream();
        let mut hash = Sha256::new();
        let mut length = 0u64;
        while let Some(chunk) = stream.try_next().await? {
            count(&self.counters.downloaded, chunk.len());
            length = length
                .checked_add(chunk.len() as u64)
                .context("blob length overflow")?;
            ensure!(
                length <= file.size,
                "remote blob body is longer than published version"
            );
            hash.update(&chunk);
            if let Some(target) = &mut destination {
                target.write_all(&chunk).await?;
            }
        }
        ensure!(length == file.size, "remote blob body is truncated");
        ensure!(
            hex::encode(hash.finalize()) == file.sha256,
            "remote blob SHA-256 verification failed"
        );
        Ok(())
    }

    pub(super) async fn upload_blob(
        &self,
        file: &Publication,
        version: &FileVersion,
    ) -> Result<()> {
        validate_source(file).await?;
        let mut source = tokio::fs::File::open(&file.source)
            .await
            .context("cannot open publication staging file")?;
        let mut upload = self
            .store
            .put_multipart(&ObjectPath::from(version.blob.as_str()))
            .await?;
        let mut pending: FuturesUnordered<UploadPart> = FuturesUnordered::new();
        let outcome: Result<()> = async {
            let mut hash = Sha256::new();
            let mut length = 0u64;
            let mut parts = 0usize;
            loop {
                while pending.len() >= PARTS_IN_FLIGHT {
                    pending
                        .next()
                        .await
                        .context("multipart task disappeared")??;
                }
                let mut buffer = vec![0u8; PART_BYTES];
                let mut filled = 0;
                while filled < PART_BYTES {
                    let read = source.read(&mut buffer[filled..]).await?;
                    if read == 0 {
                        break;
                    }
                    filled += read;
                }
                if filled == 0 && parts != 0 {
                    break;
                }
                buffer.truncate(filled);
                length = length
                    .checked_add(filled as u64)
                    .context("staging file size overflow")?;
                ensure!(
                    length <= file.size,
                    "publication staging file grew during upload; local work is retained"
                );
                hash.update(&buffer);
                count(&self.counters.uploaded, filled);
                pending.push(upload.put_part(Bytes::from(buffer).into()));
                parts += 1;
                if filled < PART_BYTES {
                    break;
                }
            }
            ensure!(
                length == file.size && hex::encode(hash.finalize()) == file.sha256,
                "publication staging file changed during upload; local work is retained"
            );
            while let Some(part) = pending.next().await {
                part?;
            }
            upload.complete().await?;
            Ok(())
        }
        .await;
        if let Err(error) = outcome {
            drop(pending);
            return match upload.abort().await {
                Ok(()) => {
                    Err(error
                        .context("multipart upload failed and was aborted; staging file retained"))
                }
                Err(abort) => Err(error.context(format!(
                    "multipart upload failed; staging file retained; abort also failed: {abort}"
                ))),
            };
        }
        Ok(())
    }

    pub(super) async fn check_conditions(&self) -> Result<()> {
        self.conditional_verified
            .get_or_try_init(|| self.probe_conditions())
            .await?;
        Ok(())
    }

    async fn probe_conditions(&self) -> Result<()> {
        let key = format!("{}probes/{}", self.prefix, Uuid::new_v4());
        let probe: Result<()> = async {
            let initial = required_etag(self.put_metadata(&key, b"initial".to_vec(), PutMode::Create).await?)?;
            let duplicate = self.put_metadata(&key, b"wrong-create".to_vec(), PutMode::Create).await;
            ensure!(matches!(&duplicate, Err(error) if condition_failed(error)),
                "backend does not enforce create-only writes; workspace publication disabled");
            let stale = self.put_metadata(&key, b"wrong-update".to_vec(), PutMode::Update(UpdateVersion {
                e_tag: Some(format!("\"{}\"", Uuid::new_v4())), version: None,
            })).await;
            ensure!(matches!(&stale, Err(error) if condition_failed(error)),
                "backend does not reject stale conditional writes; workspace publication disabled");
            let matched = required_etag(self.put_metadata(&key, b"matched".to_vec(), PutMode::Update(UpdateVersion {
                e_tag: Some(initial), version: None,
            })).await?)?;
            let mode = PutMode::Update(UpdateVersion { e_tag: Some(matched), version: None });
            let (a, b) = tokio::join!(
                self.put_metadata(&key, b"race-a".to_vec(), mode.clone()),
                self.put_metadata(&key, b"race-b".to_vec(), mode),
            );
            let (expected, winner) = match (a, b) {
                (Ok(etag), Err(error)) if condition_failed(&error) => (b"race-a", required_etag(etag)?),
                (Err(error), Ok(etag)) if condition_failed(&error) => (b"race-b", required_etag(etag)?),
                _ => bail!("backend failed one-winner conditional-write race; workspace publication disabled"),
            };
            let (bytes, etag) = self.read_metadata(&key, 1024).await?;
            ensure!(bytes == expected && etag.as_deref() == Some(winner.as_str()),
                "backend conditional-write readback disagrees with the winning writer");
            Ok(())
        }.await;
        // The only protocol objects ever deleted are disposable capability probes.
        let cleanup = self.store.delete(&ObjectPath::from(key)).await;
        match probe {
            Err(error) => Err(error),
            Ok(()) => cleanup
                .context("conditional probe passed but its disposable object could not be removed"),
        }
    }
}
