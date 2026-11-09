//! Authenticated HTTPS client for the optional managed authority.
use super::contract::*;
use super::transport::identity::{DeviceKey, now_ms, random_secret};
use super::transport::{
    Challenge, ChallengeRequest, ErrorEnvelope, MAX_CONTROL_BYTES, SessionRequest, SessionResponse,
};
use crate::workspace::contract::{
    Snapshot, TransferStats, WorkspaceReader, managed_target_id, validate_id, validate_snapshot,
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures::StreamExt;
use reqwest::header::HeaderValue;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tokio_util::io::ReaderStream;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub endpoint: String,
    pub authority_id: String,
    pub vault_id: String,
    pub device_id: String,
    pub key_path: PathBuf,
    pub ca_cert: Option<PathBuf>,
}

#[derive(Default)]
struct Counters {
    uploaded: AtomicU64,
    downloaded: AtomicU64,
    metadata_uploaded: AtomicU64,
    metadata_downloaded: AtomicU64,
}
struct Session {
    header: HeaderValue,
    deadline: Instant,
}
struct Inner {
    config: ClientConfig,
    key: DeviceKey,
    http: reqwest::Client,
    session: Mutex<Option<Session>>,
    counters: Counters,
}

#[derive(Clone)]
pub struct FabricClient {
    inner: Arc<Inner>,
}

impl FabricClient {
    pub async fn connect(config: ClientConfig) -> Result<Self> {
        validate_id(&config.authority_id)?;
        validate_id(&config.vault_id)?;
        validate_id(&config.device_id)?;
        let url = reqwest::Url::parse(&config.endpoint)?;
        ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.path() == "/"
                && config.endpoint == url.origin().ascii_serialization(),
            "managed endpoint must be a canonical HTTPS origin without path, credentials, query or fragment"
        );
        let key = DeviceKey::load(&config.key_path)?;
        let mut http = reqwest::Client::builder()
            .use_rustls_tls()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(60))
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate();
        if let Some(path) = &config.ca_cert {
            let pem = std::fs::read(path).context("read configured authority CA")?;
            let certs = reqwest::Certificate::from_pem_bundle(&pem)?;
            ensure!(!certs.is_empty(), "authority CA bundle is empty");
            http = http.tls_built_in_root_certs(false);
            for cert in certs {
                http = http.add_root_certificate(cert);
            }
        }
        let client = Self {
            inner: Arc::new(Inner {
                config,
                key,
                http: http.build()?,
                session: Mutex::new(None),
                counters: Counters::default(),
            }),
        };
        client.session_header().await?;
        match client.control(&ControlRequest::Info).await? {
            ControlResponse::Info { info } => client.check_authority(&info)?,
            _ => anyhow::bail!("unexpected authority identity response"),
        }
        Ok(client)
    }

    pub fn config(&self) -> &ClientConfig {
        &self.inner.config
    }
    pub fn stats(&self) -> TransferStats {
        let c = &self.inner.counters;
        TransferStats {
            payload_uploaded: c.uploaded.load(Ordering::Relaxed),
            payload_downloaded: c.downloaded.load(Ordering::Relaxed),
            metadata_uploaded: c.metadata_uploaded.load(Ordering::Relaxed),
            metadata_downloaded: c.metadata_downloaded.load(Ordering::Relaxed),
        }
    }
    fn check_authority(&self, info: &AuthorityInfo) -> Result<()> {
        ensure!(
            info.format == FABRIC_FORMAT
                && info.authority_id == self.inner.config.authority_id
                && info.vault_id == self.inner.config.vault_id,
            "authority or retained vault identity changed; explicit reconfiguration is required"
        );
        Ok(())
    }
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.inner.config.endpoint)
    }

    async fn receive<T: DeserializeOwned>(&self, mut response: reqwest::Response) -> Result<T> {
        let status = response.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .context("managed response interrupted; outcome may require receipt lookup")?
        {
            self.inner
                .counters
                .metadata_downloaded
                .fetch_add(chunk.len() as u64, Ordering::Relaxed);
            ensure!(
                bytes.len().saturating_add(chunk.len()) <= MAX_CONTROL_BYTES,
                "managed response exceeds 16 MiB"
            );
            bytes.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            if let Ok(error) = serde_json::from_slice::<ErrorEnvelope>(&bytes) {
                return Err(error.error.into());
            }
            anyhow::bail!(
                "managed endpoint returned HTTP {status}; no successful outcome is assumed"
            );
        }
        serde_json::from_slice(&bytes).context("invalid managed response")
    }
    async fn raw_json<T: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        path: &str,
        request: &T,
        header: Option<HeaderValue>,
    ) -> Result<R> {
        let body = serde_json::to_vec(request)?;
        ensure!(
            body.len() <= MAX_CONTROL_BYTES,
            "managed request exceeds 16 MiB"
        );
        self.inner
            .counters
            .metadata_uploaded
            .fetch_add(body.len() as u64, Ordering::Relaxed);
        let mut request = self
            .inner
            .http
            .post(self.url(path))
            .header("content-type", "application/json")
            .body(body);
        if let Some(header) = header {
            request = request.header("authorization", header);
        }
        self.receive(request.send().await.context(
            "managed request failed; use its request ID to resolve an uncertain mutation",
        )?)
        .await
    }
    async fn session_header(&self) -> Result<HeaderValue> {
        let mut session = self.inner.session.lock().await;
        if let Some(current) = session.as_ref().filter(|s| s.deadline > Instant::now()) {
            return Ok(current.header.clone());
        }
        let challenge: Challenge = self
            .raw_json(
                "/v1/auth/challenge",
                &ChallengeRequest {
                    device_id: self.inner.config.device_id.clone(),
                },
                None,
            )
            .await?;
        self.check_authority(&challenge.authority)?;
        ensure!(
            challenge.device_id == self.inner.config.device_id && challenge.key_generation > 0,
            "device challenge belongs to a different identity"
        );
        validate_id(&challenge.challenge_id)?;
        ensure!(
            challenge.nonce.len() == 64 && challenge.nonce.bytes().all(|c| c.is_ascii_hexdigit()),
            "invalid device challenge nonce"
        );
        let signature = self.inner.key.sign(&challenge)?;
        let issued: SessionResponse = self
            .raw_json(
                "/v1/auth/session",
                &SessionRequest {
                    device_id: challenge.device_id,
                    challenge_id: challenge.challenge_id,
                    signature,
                },
                None,
            )
            .await?;
        ensure!(
            issued.token.len() == 64
                && issued.token.bytes().all(|c| c.is_ascii_hexdigit())
                && (10..=600).contains(&issued.expires_in_seconds),
            "invalid device session response"
        );
        let mut header = HeaderValue::from_str(&format!("Bearer {}", issued.token))?;
        header.set_sensitive(true);
        *session = Some(Session {
            header: header.clone(),
            deadline: Instant::now() + Duration::from_secs(issued.expires_in_seconds - 5),
        });
        Ok(header)
    }
    async fn invalidate_session(&self) {
        *self.inner.session.lock().await = None;
    }

    pub async fn control(&self, request: &ControlRequest) -> Result<ControlResponse> {
        let result = self
            .raw_json("/v1/control", request, Some(self.session_header().await?))
            .await;
        let response = if result
            .as_ref()
            .err()
            .and_then(|e| e.downcast_ref::<FabricError>())
            .is_some_and(|e| e.code == ErrorCode::Unauthenticated)
        {
            // A 401 is rejection before dispatch, unlike an interrupted response.
            self.invalidate_session().await;
            self.raw_json("/v1/control", request, Some(self.session_header().await?))
                .await?
        } else {
            result?
        };
        match (request, &response) {
            (ControlRequest::Info, ControlResponse::Info { info }) => self.check_authority(info)?,
            (ControlRequest::Current { workspace_id }, ControlResponse::Catalog { catalog }) => {
                self.check_catalog(catalog, workspace_id)?;
                ensure!(
                    catalog.head.is_some(),
                    "current managed catalog omitted its publication head"
                );
            }
            (
                ControlRequest::Revision {
                    workspace_id,
                    revision,
                },
                ControlResponse::Catalog { catalog },
            ) => {
                self.check_catalog(catalog, workspace_id)?;
                ensure!(
                    catalog.head.is_none()
                        && catalog.snapshot.manifest.revision == revision.revision
                        && catalog.snapshot.manifest_sha256 == revision.sha256,
                    "exact historical revision response did not match its reference"
                );
            }
            _ => {}
        }
        Ok(response)
    }
    fn check_catalog(&self, catalog: &ManagedCatalog, workspace_id: &str) -> Result<()> {
        validate_snapshot(&catalog.snapshot)?;
        ensure!(
            catalog.snapshot.head_etag.is_none()
                && catalog.snapshot.manifest.workspace_id == workspace_id,
            "invalid managed catalog binding"
        );
        if let Some(head) = &catalog.head {
            ensure!(
                head.authority_id == self.inner.config.authority_id
                    && head.workspace_id == workspace_id
                    && head.revision.revision == catalog.snapshot.manifest.revision
                    && head.revision.sha256 == catalog.snapshot.manifest_sha256,
                "managed publication head does not identify this catalog"
            );
        }
        Ok(())
    }

    pub async fn download(&self, request: &FileRequest, new_destination: &Path) -> Result<()> {
        ensure!(
            new_destination.is_absolute(),
            "download stage must be absolute"
        );
        let body = serde_json::to_vec(request)?;
        self.inner
            .counters
            .metadata_uploaded
            .fetch_add(body.len() as u64, Ordering::Relaxed);
        let mut response = self
            .inner
            .http
            .post(self.url("/v1/file/read"))
            .header("authorization", self.session_header().await?)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .context("managed file request failed")?;
        if !response.status().is_success() {
            let _: serde_json::Value = self.receive(response).await?;
            anyhow::bail!("unexpected file error response");
        }
        ensure!(
            response.content_length() == Some(request.expected.size),
            "file response length differs from immutable reference"
        );
        ensure!(
            response
                .headers()
                .get("x-maxio-sha256")
                .and_then(|v| v.to_str().ok())
                == Some(request.expected.sha256.as_str()),
            "file response identity differs from immutable reference"
        );
        let mut file = tokio::fs::File::from_std(crate::files::new_file(new_destination)?);
        let mut hash = Sha256::new();
        let mut size = 0u64;
        let result: Result<()> = async {
            while let Some(chunk) = response
                .chunk()
                .await
                .context("download interrupted; private partial stage retained")?
            {
                self.inner
                    .counters
                    .downloaded
                    .fetch_add(chunk.len() as u64, Ordering::Relaxed);
                size = size
                    .checked_add(chunk.len() as u64)
                    .context("file length overflow")?;
                ensure!(
                    size <= request.expected.size,
                    "file response exceeded immutable length"
                );
                file.write_all(&chunk).await?;
                hash.update(&chunk);
            }
            ensure!(
                size == request.expected.size
                    && hex::encode(hash.finalize()) == request.expected.sha256,
                "download did not match immutable length/hash; unverified stage retained"
            );
            Ok(())
        }
        .await;
        file.sync_all().await?;
        crate::files::sync_directory(new_destination.parent().context("stage has no parent")?)?;
        result
    }

    pub async fn upload(
        &self,
        request: &UploadRequest,
        private_source: &Path,
    ) -> Result<PreparedUpload> {
        ensure!(
            private_source.is_absolute(),
            "upload stage must be absolute"
        );
        let meta = std::fs::symlink_metadata(private_source)?;
        ensure!(
            meta.is_file() && !meta.file_type().is_symlink() && meta.len() == request.size,
            "invalid upload stage or changed length"
        );
        let (hash, size) = crate::files::hash_file(private_source)?;
        ensure!(
            hash == request.sha256 && size == request.size,
            "upload stage differs from admitted content"
        );
        let encoded = STANDARD.encode(serde_json::to_vec(request)?);
        ensure!(encoded.len() <= 16 * 1024, "upload metadata is too large");
        self.inner
            .counters
            .metadata_uploaded
            .fetch_add(encoded.len() as u64, Ordering::Relaxed);
        let source = tokio::fs::File::open(private_source).await?;
        let counters = self.inner.clone();
        let stream = ReaderStream::new(source).inspect(move |chunk| {
            if let Ok(bytes) = chunk {
                counters
                    .counters
                    .uploaded
                    .fetch_add(bytes.len() as u64, Ordering::Relaxed);
            }
        });
        let response = self
            .inner
            .http
            .post(self.url("/v1/file/upload"))
            .header("authorization", self.session_header().await?)
            .header("x-maxio-upload", encoded)
            .header("content-length", request.size)
            .header("content-type", "application/octet-stream")
            .body(reqwest::Body::wrap_stream(stream))
            .send()
            .await
            .context("upload failed; staged local bytes remain recoverable")?;
        let prepared: PreparedUpload = self.receive(response).await?;
        ensure!(
            prepared.workspace_id == request.workspace_id
                && prepared.path == request.path
                && prepared.version.sha256 == request.sha256
                && prepared.version.size == request.size
                && prepared.prepared_by == self.inner.config.device_id
                && prepared.attempt == request.attempt,
            "prepared upload receipt does not identify the uploaded bytes and actor"
        );
        crate::workspace::contract::validate_file_version(&prepared.version)?;
        Ok(prepared)
    }

    pub async fn verify_retention(&self, files: &[RetainedFile]) -> Result<VerifiedRetention> {
        ensure!(
            !files.is_empty() && files.len() <= 256,
            "retention verification selects 1–256 exact files"
        );
        let challenge = random_secret()?;
        let started = Instant::now();
        let response = self
            .control(&ControlRequest::VerifyRetention {
                challenge: challenge.clone(),
                files: files.to_vec(),
            })
            .await?;
        let ControlResponse::Retention { verification } = response else {
            anyhow::bail!("unexpected retention response");
        };
        ensure!(
            started.elapsed() <= Duration::from_secs(30)
                && verification.challenge == challenge
                && verification.authority_id == self.inner.config.authority_id
                && verification.vault_id == self.inner.config.vault_id
                && verification.epoch > 0
                && verification.verified_at_unix_ms <= verification.valid_until_unix_ms
                && verification
                    .valid_until_unix_ms
                    .saturating_sub(verification.verified_at_unix_ms)
                    <= 60_000
                && verification.valid_until_unix_ms > now_ms()?,
            "retention verification is stale or belongs to another authority"
        );
        let selected = files
            .iter()
            .map(serde_json::to_string)
            .collect::<std::result::Result<BTreeSet<_>, _>>()?;
        ensure!(
            selected.len() == files.len() && verification.receipts.len() == files.len(),
            "duplicate or incomplete retention selection"
        );
        let actual = verification
            .receipts
            .iter()
            .map(|receipt| {
                ensure!(
                    receipt.authority_id == self.inner.config.authority_id
                        && receipt.vault_id == self.inner.config.vault_id
                        && receipt.policy == RetentionPolicy::AppendOnlyNoGc
                        && receipt.policy_version == 1,
                    "unsupported retention policy or vault binding"
                );
                Ok(serde_json::to_string(&receipt.file)?)
            })
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(
            selected == actual,
            "retention evidence does not cover the exact selected versions"
        );
        Ok(VerifiedRetention::from_authenticated_response(verification))
    }
}

/// Adapter for the existing editable LocalWorkspace manager, not another baseline store.
pub struct ManagedReader {
    client: FabricClient,
    target: ManagedTarget,
}
impl ManagedReader {
    pub fn new(client: FabricClient, target: ManagedTarget) -> Result<Self> {
        managed_target_id(&target)?;
        ensure!(
            target.authority_id == client.config().authority_id
                && target.vault_id == client.config().vault_id
                && target.origin == client.config().endpoint,
            "managed reader target differs from authenticated client"
        );
        Ok(Self { client, target })
    }
}
impl WorkspaceReader for ManagedReader {
    fn target_id(&self) -> String {
        // Constructor validates all fields; no mutable access to this target exists.
        format!(
            "managed:{}:{}:{}:{}",
            self.target.authority_id,
            self.target.vault_id,
            self.target.workspace_id,
            self.target.origin
        )
    }
    fn download_at<'a>(
        &'a self,
        snapshot: &'a Snapshot,
        path: &'a str,
        destination: &'a Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            validate_snapshot(snapshot)?;
            ensure!(
                snapshot.manifest.workspace_id == self.target.workspace_id
                    && snapshot.head_etag.is_none(),
                "managed reader received another workspace snapshot"
            );
            let expected = snapshot
                .manifest
                .files
                .get(path)
                .context("selected path is not published")?
                .clone();
            self.client
                .download(
                    &FileRequest {
                        workspace_id: self.target.workspace_id.clone(),
                        revision: crate::workspace::contract::RevisionRef {
                            revision: snapshot.manifest.revision.clone(),
                            sha256: snapshot.manifest_sha256.clone(),
                        },
                        path: path.into(),
                        expected,
                        attempt: None,
                    },
                    destination,
                )
                .await
        })
    }
}
