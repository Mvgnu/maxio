//! Optional HTTPS service. Device proof is separate from peer/S3 authentication.
pub mod identity;
mod sessions;

use super::authority::Authority;
use super::contract::*;
use anyhow::{Context, Result, ensure};
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio_util::io::ReaderStream;

pub const MAX_CONTROL_BYTES: usize = 16 * 1024 * 1024;
const MAX_UPLOAD_BYTES: u64 = 1024 * 1024 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeRequest {
    pub device_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub authority: AuthorityInfo,
    pub device_id: String,
    pub key_generation: u64,
    pub challenge_id: String,
    pub nonce: String,
    pub expires_at_unix_ms: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRequest {
    pub device_id: String,
    pub challenge_id: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionResponse {
    pub token: String,
    pub expires_in_seconds: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorEnvelope {
    pub error: FabricError,
}

pub(crate) fn protocol_error(code: ErrorCode, message: impl Into<String>) -> anyhow::Error {
    FabricError {
        code,
        message: message.into(),
    }
    .into()
}

pub(crate) struct HttpError(anyhow::Error);
impl From<anyhow::Error> for HttpError {
    fn from(error: anyhow::Error) -> Self {
        Self(error)
    }
}
impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let error = self.0.chain().find_map(|e| e.downcast_ref::<FabricError>()).cloned()
            .unwrap_or_else(|| {
                tracing::warn!(error = %self.0, "managed operation failed");
                FabricError { code: ErrorCode::Unavailable, message: "managed operation failed; retained work can be inspected on the coordinator".into() }
            });
        let status = match error.code {
            ErrorCode::Unauthenticated => StatusCode::UNAUTHORIZED,
            ErrorCode::Forbidden => StatusCode::FORBIDDEN,
            ErrorCode::Conflict => StatusCode::CONFLICT,
            ErrorCode::NotFound => StatusCode::NOT_FOUND,
            ErrorCode::Invalid => StatusCode::BAD_REQUEST,
            ErrorCode::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::Capacity => StatusCode::TOO_MANY_REQUESTS,
        };
        (status, Json(ErrorEnvelope { error })).into_response()
    }
}

struct Service {
    authority: Arc<Authority>,
    sessions: sessions::Sessions,
    spool: PathBuf,
    uploads: Arc<Semaphore>,
}

/// Serve only native HTTPS on the supplied listener. The caller owns shutdown.
pub async fn serve(
    authority: Arc<Authority>,
    listener: TcpListener,
    tls: crate::server::ServerTls,
    spool: PathBuf,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    ensure!(
        tls.scheme() == "https",
        "managed device transport requires native HTTPS"
    );
    ensure!(
        spool.is_absolute(),
        "upload spool must be an absolute private path"
    );
    crate::files::directory(&spool)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&spool, std::fs::Permissions::from_mode(0o700))?;
    }
    let state = Arc::new(Service {
        authority,
        sessions: sessions::Sessions::new(),
        spool,
        uploads: Arc::new(Semaphore::new(4)),
    });
    let app = Router::new()
        .route("/v1/auth/challenge", post(challenge))
        .route("/v1/auth/session", post(session))
        .route("/v1/control", post(control))
        .route("/v1/file/read", post(read_file))
        .layer(DefaultBodyLimit::max(MAX_CONTROL_BYTES))
        .route("/v1/file/upload", post(upload))
        .with_state(state);
    crate::server::serve_listener(listener, app, tls, false, shutdown).await?;
    Ok(())
}

fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body)
        .map_err(|_| protocol_error(ErrorCode::Invalid, "invalid or unsupported request fields"))
}

async fn challenge(
    State(state): State<Arc<Service>>,
    body: Bytes,
) -> Result<Json<Challenge>, HttpError> {
    let request: ChallengeRequest = decode(&body)?;
    Ok(Json(
        state
            .sessions
            .challenge(&state.authority, &request.device_id)?,
    ))
}

async fn session(
    State(state): State<Arc<Service>>,
    body: Bytes,
) -> Result<Json<SessionResponse>, HttpError> {
    let request: SessionRequest = decode(&body)?;
    Ok(Json(state.sessions.complete(&state.authority, request)?))
}

async fn control(
    State(state): State<Arc<Service>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ControlResponse>, HttpError> {
    let actor = state.sessions.actor(&state.authority, &headers)?;
    let request: ControlRequest = decode(&body)?;
    let authority = state.authority.clone();
    let response = tokio::task::spawn_blocking(move || authority.control(&actor, &request))
        .await
        .context("authority control task stopped")??;
    Ok(Json(response))
}

async fn read_file(
    State(state): State<Arc<Service>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, HttpError> {
    let actor = state.sessions.actor(&state.authority, &headers)?;
    let request: FileRequest = decode(&body)?;
    let authority = state.authority.clone();
    let opened = tokio::task::spawn_blocking(move || authority.read(&actor, &request))
        .await
        .context("authority read task stopped")??;
    let length = opened.version.size;
    let body = Body::from_stream(ReaderStream::new(tokio::fs::File::from_std(opened.file)));
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/octet-stream")
        .header("content-length", length.to_string())
        .header("x-maxio-sha256", opened.version.sha256)
        .body(body)
        .context("build file response")
        .map_err(Into::into)
}

async fn upload(
    State(state): State<Arc<Service>>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<PreparedUpload>, HttpError> {
    let actor = state.sessions.actor(&state.authority, &headers)?;
    if headers.get_all("x-maxio-upload").iter().count() != 1 {
        return Err(
            protocol_error(ErrorCode::Invalid, "one upload metadata header is required").into(),
        );
    }
    let encoded = headers
        .get("x-maxio-upload")
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() <= 16 * 1024)
        .ok_or_else(|| protocol_error(ErrorCode::Invalid, "invalid upload metadata header"))?;
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| protocol_error(ErrorCode::Invalid, "invalid upload metadata encoding"))?;
    let request: UploadRequest = decode(&bytes)?;
    if request.size > MAX_UPLOAD_BYTES {
        return Err(protocol_error(
            ErrorCode::Capacity,
            "upload exceeds the 1 TiB per-file limit",
        )
        .into());
    }
    if headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        != Some(request.size)
    {
        return Err(protocol_error(
            ErrorCode::Invalid,
            "upload Content-Length must equal the declared file length",
        )
        .into());
    }
    let authority = state.authority.clone();
    let actor_check = actor.clone();
    let request_check = request.clone();
    tokio::task::spawn_blocking(move || authority.check_upload(&actor_check, &request_check))
        .await
        .context("authority admission task stopped")??;
    let _permit = state.uploads.clone().try_acquire_owned().map_err(|_| {
        protocol_error(
            ErrorCode::Capacity,
            "four uploads are already active; retry with the same request ID",
        )
    })?;
    let operation = state.spool.join(uuid::Uuid::new_v4().to_string());
    crate::files::directory(&operation)?;
    let metadata = serde_json::json!({"device_id": actor.device_id(), "upload": request});
    let mut receipt = crate::files::new_file(&operation.join("request.json"))?;
    std::io::Write::write_all(
        &mut receipt,
        &serde_json::to_vec(&metadata).context("encode upload recovery metadata")?,
    )
    .context("write upload recovery metadata")?;
    receipt.sync_all().context("sync upload metadata")?;
    crate::files::sync_directory(&operation)?;
    crate::files::sync_directory(&state.spool)?;
    let path = operation.join("body");
    let mut file = tokio::fs::File::from_std(crate::files::new_file(&path)?);
    let mut stream = body.into_data_stream();
    let mut size = 0u64;
    let received: Result<()> = async {
        while let Some(chunk) =
            tokio::time::timeout(std::time::Duration::from_secs(60), stream.next())
                .await
                .context("upload stalled")?
        {
            let chunk = chunk.context("upload interrupted; private partial stage retained")?;
            size = size
                .checked_add(chunk.len() as u64)
                .context("upload size overflow")?;
            ensure!(size <= request.size, "upload exceeds declared length");
            file.write_all(&chunk).await?;
        }
        ensure!(
            size == request.size,
            "upload was truncated; private partial stage retained"
        );
        Ok(())
    }
    .await;
    file.sync_all()
        .await
        .context("sync received upload bytes")?;
    received?;
    drop(file);
    let authority = state.authority.clone();
    let prepared = tokio::task::spawn_blocking(move || authority.upload(&actor, &request, &path))
        .await
        .context("authority upload task stopped")??;
    // Stages remain inspectable in this first version; no implicit GC of uploads.
    let mut receipt = crate::files::new_file(&operation.join("prepared.json"))?;
    std::io::Write::write_all(
        &mut receipt,
        &serde_json::to_vec(&prepared).context("encode prepared upload")?,
    )
    .context("write prepared upload")?;
    receipt.sync_all().context("sync prepared receipt")?;
    crate::files::sync_directory(&operation)?;
    Ok(Json(prepared))
}
