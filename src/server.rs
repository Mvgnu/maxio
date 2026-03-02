use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::Response;
use axum::routing::get;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use tokio::time::Duration;

use crate::api::console::{LoginRateLimiter, console_router};
use crate::api::router::s3_router;
use crate::auth::middleware::auth_middleware;
use crate::config::{Config, MembershipProtocol};
use crate::embedded::ui_handler;
use crate::storage::filesystem::FilesystemStorage;
use crate::storage::placement::{membership_view_id_with_self, membership_with_self};

const CORS_ALLOW_HEADERS_BASELINE: &str = "authorization,content-type,x-amz-date,x-amz-content-sha256,x-amz-security-token,x-amz-user-agent,x-amz-checksum-algorithm,x-amz-checksum-crc32,x-amz-checksum-crc32c,x-amz-checksum-sha1,x-amz-checksum-sha256,range";
const PLACEMENT_STATE_DIR: &str = ".maxio-runtime";
const PLACEMENT_STATE_FILE: &str = "placement-state.json";
const PEER_CONNECTIVITY_PROBE_TIMEOUT_SECS: u64 = 2;
const CORS_ALLOW_HEADERS_BASELINE_FIELDS: &[&str] = &[
    "authorization",
    "content-type",
    "x-amz-date",
    "x-amz-content-sha256",
    "x-amz-security-token",
    "x-amz-user-agent",
    "x-amz-checksum-algorithm",
    "x-amz-checksum-crc32",
    "x-amz-checksum-crc32c",
    "x-amz-checksum-sha1",
    "x-amz-checksum-sha256",
    "range",
];

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<FilesystemStorage>,
    pub config: Arc<Config>,
    pub credentials: Arc<HashMap<String, String>>,
    pub node_id: Arc<String>,
    pub cluster_peers: Arc<Vec<String>>,
    pub membership_protocol: MembershipProtocol,
    pub placement_epoch: Arc<AtomicU64>,
    pub login_rate_limiter: Arc<LoginRateLimiter>,
    pub request_count: Arc<AtomicU64>,
    pub started_at: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeMode {
    Standalone,
    Distributed,
}

impl RuntimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standalone => "standalone",
            Self::Distributed => "distributed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeTopologySnapshot {
    pub mode: RuntimeMode,
    pub node_id: String,
    pub cluster_peers: Vec<String>,
    pub membership_nodes: Vec<String>,
    pub membership_protocol: MembershipProtocol,
    pub membership_view_id: String,
    pub placement_epoch: u64,
}

impl RuntimeTopologySnapshot {
    pub fn cluster_peer_count(&self) -> usize {
        self.cluster_peers.len()
    }

    pub fn membership_node_count(&self) -> usize {
        self.membership_nodes.len()
    }

    pub fn is_distributed(&self) -> bool {
        self.mode == RuntimeMode::Distributed
    }
}

impl AppState {
    pub fn placement_epoch(&self) -> u64 {
        self.placement_epoch.load(Ordering::Relaxed)
    }

    /// Construct the shared runtime state from a parsed config.
    pub async fn from_config(config: Config) -> anyhow::Result<Self> {
        let credentials = config.credential_map().map_err(anyhow::Error::msg)?;
        let cluster_peers = config.parsed_cluster_peers().map_err(anyhow::Error::msg)?;
        let node_id = config.node_id.clone();
        let membership_view_id = membership_view_id_with_self(node_id.as_str(), &cluster_peers);
        let placement_epoch =
            load_or_bootstrap_placement_epoch(config.data_dir.as_str(), &membership_view_id)
                .await?;
        let membership_protocol = config.membership_protocol;
        let storage = FilesystemStorage::new(
            &config.data_dir,
            config.erasure_coding,
            config.chunk_size,
            config.parity_shards,
        )
        .await?;

        Ok(Self {
            storage: Arc::new(storage),
            config: Arc::new(config),
            credentials: Arc::new(credentials),
            node_id: Arc::new(node_id),
            cluster_peers: Arc::new(cluster_peers),
            membership_protocol,
            placement_epoch: Arc::new(AtomicU64::new(placement_epoch)),
            login_rate_limiter: Arc::new(LoginRateLimiter::new()),
            request_count: Arc::new(AtomicU64::new(0)),
            started_at: Instant::now(),
        })
    }
}

pub fn runtime_topology_snapshot(state: &AppState) -> RuntimeTopologySnapshot {
    let node_id = state.node_id.as_ref().clone();
    let cluster_peers = state.cluster_peers.as_ref().clone();
    let membership_nodes = membership_with_self(node_id.as_str(), &cluster_peers);
    let mode = if cluster_peers.is_empty() {
        RuntimeMode::Standalone
    } else {
        RuntimeMode::Distributed
    };
    let membership_view_id = membership_view_id_with_self(node_id.as_str(), &cluster_peers);
    let placement_epoch = state.placement_epoch();

    RuntimeTopologySnapshot {
        mode,
        node_id,
        cluster_peers,
        membership_nodes,
        membership_protocol: state.membership_protocol,
        membership_view_id,
        placement_epoch,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
struct PersistedPlacementState {
    epoch: u64,
    view_id: String,
}

fn placement_state_path(data_dir: &str) -> PathBuf {
    Path::new(data_dir)
        .join(PLACEMENT_STATE_DIR)
        .join(PLACEMENT_STATE_FILE)
}

fn placement_state_temp_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(PLACEMENT_STATE_FILE);
    path.with_file_name(format!("{}.tmp-{}", file_name, uuid::Uuid::new_v4()))
}

#[cfg(not(target_os = "windows"))]
async fn rename_placement_state(temp_path: &Path, path: &Path) -> std::io::Result<()> {
    tokio::fs::rename(temp_path, path).await
}

#[cfg(target_os = "windows")]
async fn rename_placement_state(temp_path: &Path, path: &Path) -> std::io::Result<()> {
    match tokio::fs::rename(temp_path, path).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            tokio::fs::remove_file(path).await?;
            tokio::fs::rename(temp_path, path).await
        }
        Err(err) => Err(err),
    }
}

async fn read_persisted_placement_state(
    path: &Path,
) -> anyhow::Result<Option<PersistedPlacementState>> {
    match tokio::fs::read(path).await {
        Ok(bytes) => {
            let state =
                serde_json::from_slice::<PersistedPlacementState>(&bytes).map_err(|err| {
                    anyhow::anyhow!(
                        "Failed to parse placement state '{}': {err}",
                        path.display()
                    )
                })?;
            Ok(Some(state))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(anyhow::anyhow!(
            "Failed to read placement state '{}': {err}",
            path.display()
        )),
    }
}

async fn write_persisted_placement_state(
    path: &Path,
    state: &PersistedPlacementState,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|err| {
            anyhow::anyhow!(
                "Failed to create placement state directory '{}': {err}",
                parent.display()
            )
        })?;
    }

    let payload = serde_json::to_vec_pretty(state).map_err(|err| {
        anyhow::anyhow!(
            "Failed to serialize placement state '{}': {err}",
            path.display()
        )
    })?;
    let temp_path = placement_state_temp_path(path);
    let mut temp_file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp_path)
        .await
        .map_err(|err| {
            anyhow::anyhow!(
                "Failed to create placement state temp file '{}': {err}",
                temp_path.display()
            )
        })?;
    temp_file.write_all(&payload).await.map_err(|err| {
        anyhow::anyhow!(
            "Failed to write placement state temp file '{}': {err}",
            temp_path.display()
        )
    })?;
    temp_file.sync_all().await.map_err(|err| {
        anyhow::anyhow!(
            "Failed to sync placement state temp file '{}': {err}",
            temp_path.display()
        )
    })?;
    drop(temp_file);

    if let Err(err) = rename_placement_state(temp_path.as_path(), path).await {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(anyhow::anyhow!(
            "Failed to atomically persist placement state '{}' via temp '{}': {err}",
            path.display(),
            temp_path.display()
        ));
    }

    Ok(())
}

async fn load_or_bootstrap_placement_epoch(
    data_dir: &str,
    current_view_id: &str,
) -> anyhow::Result<u64> {
    let path = placement_state_path(data_dir);
    let persisted = read_persisted_placement_state(path.as_path()).await?;
    let next_state = match persisted {
        Some(mut state) => {
            if state.view_id != current_view_id {
                state.epoch = state.epoch.saturating_add(1);
                state.view_id = current_view_id.to_string();
                write_persisted_placement_state(path.as_path(), &state).await?;
            }
            state
        }
        None => {
            let state = PersistedPlacementState {
                epoch: 0,
                view_id: current_view_id.to_string(),
            };
            write_persisted_placement_state(path.as_path(), &state).await?;
            state
        }
    };

    Ok(next_state.epoch)
}

pub fn build_router(state: AppState) -> Router {
    let s3_routes = s3_router().layer(axum::middleware::from_fn_with_state(
        state.clone(),
        auth_middleware,
    ));

    Router::new()
        .nest("/api", console_router(state.clone()))
        .route("/healthz", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .route("/ui", get(ui_handler))
        .route("/ui/", get(ui_handler))
        .route("/ui/{*path}", get(ui_handler))
        .merge(s3_routes)
        .layer(axum::middleware::from_fn(cors_middleware))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            request_id_middleware,
        ))
        .with_state(state)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HealthChecksPayload {
    data_dir_accessible: bool,
    data_dir_writable: bool,
    storage_data_path_readable: bool,
    disk_headroom_sufficient: bool,
    peer_connectivity_ready: bool,
    membership_protocol_ready: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HealthPayload {
    ok: bool,
    status: String,
    version: String,
    uptime_seconds: f64,
    mode: String,
    node_id: String,
    cluster_peer_count: usize,
    cluster_peers: Vec<String>,
    membership_node_count: usize,
    membership_nodes: Vec<String>,
    membership_protocol: String,
    membership_view_id: String,
    placement_epoch: u64,
    checks: HealthChecksPayload,
    warnings: Vec<String>,
}

#[derive(Debug)]
struct DataDirProbeResult {
    accessible: bool,
    writable: bool,
    warning: Option<String>,
}

#[derive(Debug)]
struct StorageDataPathProbeResult {
    readable: bool,
    warning: Option<String>,
}

#[derive(Debug)]
struct DiskHeadroomProbeResult {
    sufficient: bool,
    warning: Option<String>,
}

#[derive(Debug)]
struct PeerConnectivityProbeResult {
    ready: bool,
    warning: Option<String>,
}

fn probe_data_dir(path: &str) -> DataDirProbeResult {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) => {
            return DataDirProbeResult {
                accessible: false,
                writable: false,
                warning: Some(format!("Data directory metadata probe failed: {err}")),
            };
        }
    };

    if !metadata.is_dir() {
        return DataDirProbeResult {
            accessible: false,
            writable: false,
            warning: Some("Configured data directory is not a directory".to_string()),
        };
    }

    let probe_path = Path::new(path).join(format!(".maxio-health-probe-{}", uuid::Uuid::new_v4()));
    let file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe_path)
    {
        Ok(file) => file,
        Err(err) => {
            return DataDirProbeResult {
                accessible: true,
                writable: false,
                warning: Some(format!("Data directory write probe failed: {err}")),
            };
        }
    };
    drop(file);

    if let Err(err) = std::fs::remove_file(&probe_path) {
        return DataDirProbeResult {
            accessible: true,
            writable: true,
            warning: Some(format!(
                "Data directory probe cleanup failed for {}: {err}",
                probe_path.display()
            )),
        };
    }

    DataDirProbeResult {
        accessible: true,
        writable: true,
        warning: None,
    }
}

pub fn membership_protocol_readiness(protocol: MembershipProtocol) -> (bool, Option<String>) {
    match protocol {
        MembershipProtocol::StaticBootstrap => (true, None),
        MembershipProtocol::Gossip | MembershipProtocol::Raft => (
            false,
            Some(format!(
                "Membership protocol '{}' is configured but not implemented yet; runtime currently uses static-bootstrap semantics.",
                protocol.as_str()
            )),
        ),
    }
}

async fn probe_storage_data_path(storage: &FilesystemStorage) -> StorageDataPathProbeResult {
    match storage.list_buckets().await {
        Ok(_) => StorageDataPathProbeResult {
            readable: true,
            warning: None,
        },
        Err(err) => StorageDataPathProbeResult {
            readable: false,
            warning: Some(format!("Storage data-path probe failed: {err}")),
        },
    }
}

fn probe_disk_headroom(path: &str, required_free_bytes: u64) -> DiskHeadroomProbeResult {
    if required_free_bytes == 0 {
        return DiskHeadroomProbeResult {
            sufficient: true,
            warning: None,
        };
    }

    match fs2::available_space(path) {
        Ok(free_bytes) if free_bytes >= required_free_bytes => DiskHeadroomProbeResult {
            sufficient: true,
            warning: None,
        },
        Ok(free_bytes) => DiskHeadroomProbeResult {
            sufficient: false,
            warning: Some(format!(
                "Disk headroom below threshold: available {free_bytes} bytes, required {required_free_bytes} bytes."
            )),
        },
        Err(err) => DiskHeadroomProbeResult {
            sufficient: false,
            warning: Some(format!("Disk headroom probe failed: {err}")),
        },
    }
}

async fn probe_peer_connectivity(peers: &[String]) -> PeerConnectivityProbeResult {
    if peers.is_empty() {
        return PeerConnectivityProbeResult {
            ready: true,
            warning: None,
        };
    }

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(PEER_CONNECTIVITY_PROBE_TIMEOUT_SECS))
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            return PeerConnectivityProbeResult {
                ready: false,
                warning: Some(format!(
                    "Peer connectivity probe client initialization failed: {err}"
                )),
            };
        }
    };

    let mut failures = Vec::new();
    for peer in peers {
        let url = format!("http://{peer}/healthz");
        match client.get(url).send().await {
            Ok(response) if response.status().is_success() => {}
            Ok(response) => failures.push(format!("{peer} (status {})", response.status())),
            Err(err) => failures.push(format!("{peer} ({err})")),
        }
    }

    if failures.is_empty() {
        PeerConnectivityProbeResult {
            ready: true,
            warning: None,
        }
    } else {
        PeerConnectivityProbeResult {
            ready: false,
            warning: Some(format!(
                "Peer connectivity probe failed for {} configured peer(s): {}",
                failures.len(),
                failures.join(", ")
            )),
        }
    }
}

fn health_payload(
    state: &AppState,
    topology: &RuntimeTopologySnapshot,
    uptime_seconds: f64,
    storage_probe: StorageDataPathProbeResult,
    peer_connectivity_probe: PeerConnectivityProbeResult,
) -> HealthPayload {
    let data_dir_probe = probe_data_dir(&state.config.data_dir);
    let disk_headroom_probe =
        probe_disk_headroom(&state.config.data_dir, state.config.min_disk_headroom_bytes);
    let (membership_protocol_ready, protocol_warning) =
        membership_protocol_readiness(topology.membership_protocol);

    let self_peer_misconfigured = topology
        .cluster_peers
        .iter()
        .any(|peer| peer.trim() == topology.node_id.trim());

    let mut warnings = Vec::new();
    if let Some(warning) = data_dir_probe.warning {
        warnings.push(warning);
    }
    if let Some(warning) = protocol_warning {
        warnings.push(warning);
    }
    if let Some(warning) = storage_probe.warning {
        warnings.push(warning);
    }
    if let Some(warning) = disk_headroom_probe.warning {
        warnings.push(warning);
    }
    if let Some(warning) = peer_connectivity_probe.warning {
        warnings.push(warning);
    }
    if self_peer_misconfigured {
        warnings.push(format!(
            "Cluster peer configuration includes local node id '{}' which can cause split-brain or forwarding loops.",
            topology.node_id
        ));
    }

    let checks = HealthChecksPayload {
        data_dir_accessible: data_dir_probe.accessible,
        data_dir_writable: data_dir_probe.writable,
        storage_data_path_readable: storage_probe.readable,
        disk_headroom_sufficient: disk_headroom_probe.sufficient,
        peer_connectivity_ready: peer_connectivity_probe.ready && !self_peer_misconfigured,
        membership_protocol_ready,
    };
    let peer_connectivity_required = topology.is_distributed()
        && topology.membership_protocol == MembershipProtocol::StaticBootstrap;
    let ok = checks.data_dir_accessible
        && checks.data_dir_writable
        && checks.storage_data_path_readable
        && checks.disk_headroom_sufficient
        && (!peer_connectivity_required || checks.peer_connectivity_ready)
        && checks.membership_protocol_ready;
    let status = if ok { "ok" } else { "degraded" };

    HealthPayload {
        ok,
        status: status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds,
        mode: topology.mode.as_str().to_string(),
        node_id: topology.node_id.clone(),
        cluster_peer_count: topology.cluster_peer_count(),
        cluster_peers: topology.cluster_peers.clone(),
        membership_node_count: topology.membership_node_count(),
        membership_nodes: topology.membership_nodes.clone(),
        membership_protocol: topology.membership_protocol.as_str().to_string(),
        membership_view_id: topology.membership_view_id.clone(),
        placement_epoch: topology.placement_epoch,
        checks,
        warnings,
    }
}

pub(crate) async fn runtime_health_payload(state: &AppState) -> HealthPayload {
    let uptime_seconds = state.started_at.elapsed().as_secs_f64();
    let topology = runtime_topology_snapshot(state);
    let storage_probe = probe_storage_data_path(&state.storage).await;
    let peer_connectivity_probe = probe_peer_connectivity(topology.cluster_peers.as_slice()).await;
    health_payload(
        state,
        &topology,
        uptime_seconds,
        storage_probe,
        peer_connectivity_probe,
    )
}

async fn metrics_handler(State(state): State<AppState>) -> Response {
    let topology = runtime_topology_snapshot(&state);
    let request_count = state.request_count.load(Ordering::Relaxed);
    let uptime = state.started_at.elapsed().as_secs_f64();
    let distributed_mode = if topology.is_distributed() { 1 } else { 0 };
    let cluster_peer_count = topology.cluster_peer_count();
    let membership_node_count = topology.membership_node_count();
    let membership_protocol = topology.membership_protocol.as_str();
    let placement_epoch = topology.placement_epoch;

    let body = format!(
        "# HELP maxio_requests_total Total HTTP requests observed by MaxIO.\n\
         # TYPE maxio_requests_total counter\n\
         maxio_requests_total {}\n\
         # HELP maxio_uptime_seconds MaxIO process uptime in seconds.\n\
         # TYPE maxio_uptime_seconds gauge\n\
         maxio_uptime_seconds {:.3}\n\
         # HELP maxio_build_info Build and version information for MaxIO.\n\
         # TYPE maxio_build_info gauge\n\
         maxio_build_info{{version=\"{}\"}} 1\n\
         # HELP maxio_distributed_mode Whether MaxIO is running with configured cluster peers (1=true, 0=false).\n\
         # TYPE maxio_distributed_mode gauge\n\
         maxio_distributed_mode {}\n\
         # HELP maxio_cluster_peers_total Number of configured cluster peers.\n\
         # TYPE maxio_cluster_peers_total gauge\n\
         maxio_cluster_peers_total {}\n\
         # HELP maxio_membership_nodes_total Number of nodes in the normalized runtime membership view (self + peers).\n\
         # TYPE maxio_membership_nodes_total gauge\n\
         maxio_membership_nodes_total {}\n\
         # HELP maxio_membership_protocol_info Membership protocol configuration for runtime topology convergence.\n\
         # TYPE maxio_membership_protocol_info gauge\n\
         maxio_membership_protocol_info{{protocol=\"{}\"}} 1\n\
         # HELP maxio_placement_epoch Current placement epoch for the active runtime membership view.\n\
         # TYPE maxio_placement_epoch gauge\n\
         maxio_placement_epoch {}\n",
        request_count,
        uptime,
        env!("CARGO_PKG_VERSION"),
        distributed_mode,
        cluster_peer_count,
        membership_node_count,
        membership_protocol,
        placement_epoch
    );

    response_with_content_type(
        StatusCode::OK,
        HeaderValue::from_static("text/plain; version=0.0.4"),
        axum::body::Body::from(body),
    )
}

async fn health_handler(State(state): State<AppState>) -> Response {
    let body = runtime_health_payload(&state).await;

    response_with_content_type(
        StatusCode::OK,
        HeaderValue::from_static("application/json"),
        axum::body::Body::from(
            serde_json::to_vec(&body)
                .unwrap_or_else(|_| b"{\"ok\":false,\"status\":\"degraded\"}".to_vec()),
        ),
    )
}

fn response_with_content_type(
    status: StatusCode,
    content_type: HeaderValue,
    body: axum::body::Body,
) -> Response {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    response
}

fn apply_cors_headers(response_headers: &mut HeaderMap, request_headers: &HeaderMap) {
    let origin = request_headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty());

    if let Some(origin) = origin {
        if let Ok(value) = HeaderValue::from_str(origin) {
            response_headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
            response_headers.insert(
                header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
        }
    } else {
        response_headers.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
        response_headers.remove(header::ACCESS_CONTROL_ALLOW_CREDENTIALS);
    }
    response_headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, PUT, POST, DELETE, HEAD, OPTIONS"),
    );
    response_headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        build_allow_headers(request_headers),
    );
    response_headers.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static(
            "etag,x-amz-request-id,x-amz-version-id,x-amz-delete-marker,x-amz-checksum-crc32,x-amz-checksum-crc32c,x-amz-checksum-sha1,x-amz-checksum-sha256,content-length,content-type,last-modified,accept-ranges,content-range,location",
        ),
    );
    response_headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("86400"),
    );
    let mut vary_fields = vec!["Origin"];
    if request_headers.contains_key(header::ACCESS_CONTROL_REQUEST_METHOD) {
        vary_fields.push("Access-Control-Request-Method");
    }
    if request_headers.contains_key(header::ACCESS_CONTROL_REQUEST_HEADERS) {
        vary_fields.push("Access-Control-Request-Headers");
    }
    merge_vary_headers(response_headers, &vary_fields);
}

fn build_allow_headers(request_headers: &HeaderMap) -> HeaderValue {
    let mut allow_headers: Vec<String> = CORS_ALLOW_HEADERS_BASELINE_FIELDS
        .iter()
        .map(|v| (*v).to_string())
        .collect();

    if let Some(requested_headers) = request_headers
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .and_then(|v| v.to_str().ok())
    {
        for token in requested_headers.split(',').map(str::trim) {
            if token.is_empty() || !is_valid_header_name_token(token) {
                continue;
            }
            let normalized = token.to_ascii_lowercase();
            if !allow_headers
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(&normalized))
            {
                allow_headers.push(normalized);
            }
        }
    }

    HeaderValue::from_str(&allow_headers.join(","))
        .unwrap_or_else(|_| HeaderValue::from_static(CORS_ALLOW_HEADERS_BASELINE))
}

fn is_valid_header_name_token(token: &str) -> bool {
    token.bytes().all(|b| {
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

fn merge_vary_headers(response_headers: &mut HeaderMap, values: &[&str]) {
    let mut combined = Vec::<String>::new();

    if let Some(existing) = response_headers
        .get(header::VARY)
        .and_then(|v| v.to_str().ok())
    {
        for part in existing.split(',') {
            let token = part.trim();
            if !token.is_empty()
                && !combined
                    .iter()
                    .any(|entry| entry.eq_ignore_ascii_case(token))
            {
                combined.push(token.to_string());
            }
        }
    }

    for value in values {
        if !combined
            .iter()
            .any(|entry| entry.eq_ignore_ascii_case(value))
        {
            combined.push((*value).to_string());
        }
    }

    if let Ok(vary) = HeaderValue::from_str(&combined.join(", ")) {
        response_headers.insert(header::VARY, vary);
    }
}

async fn cors_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let request_headers = request.headers().clone();

    if request.method() == Method::OPTIONS {
        let mut response = Response::new(axum::body::Body::empty());
        *response.status_mut() = StatusCode::NO_CONTENT;
        apply_cors_headers(response.headers_mut(), &request_headers);
        return response;
    }

    let mut response = next.run(request).await;
    apply_cors_headers(response.headers_mut(), &request_headers);
    response
}

async fn request_id_middleware(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    state.request_count.fetch_add(1, Ordering::Relaxed);
    let request_id = uuid::Uuid::new_v4().to_string();
    let mut response = next.run(request).await;
    if let Ok(value) = request_id.parse() {
        response.headers_mut().insert("x-amz-request-id", value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use std::time::Instant;

    use crate::config::{Config, MembershipProtocol};
    use crate::storage::filesystem::FilesystemStorage;

    fn test_config() -> Config {
        Config {
            port: 9000,
            address: "127.0.0.1".to_string(),
            data_dir: "./data".to_string(),
            access_key: "root".to_string(),
            secret_key: "root-secret".to_string(),
            additional_credentials: Vec::new(),
            region: "us-east-1".to_string(),
            node_id: "maxio-test-node".to_string(),
            cluster_peers: Vec::new(),
            membership_protocol: MembershipProtocol::StaticBootstrap,
            erasure_coding: false,
            chunk_size: 10 * 1024 * 1024,
            parity_shards: 0,
            min_disk_headroom_bytes: 268_435_456,
        }
    }

    #[test]
    fn merge_vary_headers_deduplicates_and_preserves_existing_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::VARY,
            HeaderValue::from_static("Accept-Encoding, Origin"),
        );

        merge_vary_headers(
            &mut headers,
            &[
                "Origin",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers",
            ],
        );

        let vary = headers
            .get(header::VARY)
            .and_then(|v| v.to_str().ok())
            .expect("vary should be set");
        assert_eq!(
            vary,
            "Accept-Encoding, Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
        );
    }

    #[test]
    fn response_with_content_type_sets_status_and_header() {
        let response = response_with_content_type(
            StatusCode::CREATED,
            HeaderValue::from_static("application/json"),
            axum::body::Body::from("{}"),
        );
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
    }

    #[test]
    fn apply_cors_headers_reflected_origin_sets_allow_credentials() {
        let mut request_headers = HeaderMap::new();
        request_headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://example.com"),
        );
        let mut response_headers = HeaderMap::new();

        apply_cors_headers(&mut response_headers, &request_headers);

        assert_eq!(
            response_headers
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok()),
            Some("https://example.com")
        );
        assert_eq!(
            response_headers
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .and_then(|v| v.to_str().ok()),
            Some("true")
        );
    }

    #[test]
    fn apply_cors_headers_without_origin_uses_wildcard_without_credentials() {
        let request_headers = HeaderMap::new();
        let mut response_headers = HeaderMap::new();

        apply_cors_headers(&mut response_headers, &request_headers);

        assert_eq!(
            response_headers
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok()),
            Some("*")
        );
        assert!(
            response_headers
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none()
        );
    }

    #[test]
    fn build_allow_headers_adds_requested_headers_once() {
        let mut request_headers = HeaderMap::new();
        request_headers.insert(
            header::ACCESS_CONTROL_REQUEST_HEADERS,
            HeaderValue::from_static(
                "X-Amz-Date, X-Custom-Trace, x custom invalid, x-custom-trace",
            ),
        );

        let allow_header_value = build_allow_headers(&request_headers);
        let allow_headers = allow_header_value
            .to_str()
            .expect("allow headers should be valid utf-8");
        let values: Vec<&str> = allow_headers.split(',').collect();

        assert!(values.contains(&"x-amz-date"));
        assert!(values.contains(&"x-custom-trace"));
        assert!(!values.contains(&"x custom invalid"));
        assert_eq!(
            values
                .iter()
                .filter(|entry| entry.eq_ignore_ascii_case("x-custom-trace"))
                .count(),
            1
        );
    }

    #[test]
    fn membership_protocol_readiness_reports_unimplemented_protocols_as_not_ready() {
        let (static_ready, static_warning) =
            membership_protocol_readiness(MembershipProtocol::StaticBootstrap);
        assert!(static_ready);
        assert!(static_warning.is_none());

        let (gossip_ready, gossip_warning) =
            membership_protocol_readiness(MembershipProtocol::Gossip);
        assert!(!gossip_ready);
        assert!(
            gossip_warning
                .as_deref()
                .is_some_and(|warning| warning.contains("not implemented"))
        );

        let (raft_ready, raft_warning) = membership_protocol_readiness(MembershipProtocol::Raft);
        assert!(!raft_ready);
        assert!(
            raft_warning
                .as_deref()
                .is_some_and(|warning| warning.contains("not implemented"))
        );
    }

    #[tokio::test]
    async fn placement_epoch_bootstrap_initializes_state_file_when_missing() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let data_dir = temp.path().to_str().expect("path should be utf8");

        let epoch = load_or_bootstrap_placement_epoch(data_dir, "view-a")
            .await
            .expect("bootstrap should succeed");
        assert_eq!(epoch, 0);

        let persisted = read_persisted_placement_state(&placement_state_path(data_dir))
            .await
            .expect("state read should succeed")
            .expect("state should exist");
        assert_eq!(persisted.epoch, 0);
        assert_eq!(persisted.view_id, "view-a");
    }

    #[tokio::test]
    async fn placement_epoch_bootstrap_reuses_epoch_for_same_view() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let data_dir = temp.path().to_str().expect("path should be utf8");
        let path = placement_state_path(data_dir);
        write_persisted_placement_state(
            &path,
            &PersistedPlacementState {
                epoch: 9,
                view_id: "stable-view".to_string(),
            },
        )
        .await
        .expect("state write should succeed");

        let epoch = load_or_bootstrap_placement_epoch(data_dir, "stable-view")
            .await
            .expect("bootstrap should succeed");
        assert_eq!(epoch, 9);

        let persisted = read_persisted_placement_state(&path)
            .await
            .expect("state read should succeed")
            .expect("state should exist");
        assert_eq!(persisted.epoch, 9);
        assert_eq!(persisted.view_id, "stable-view");
    }

    #[tokio::test]
    async fn placement_epoch_bootstrap_increments_epoch_for_new_view() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let data_dir = temp.path().to_str().expect("path should be utf8");
        let path = placement_state_path(data_dir);
        write_persisted_placement_state(
            &path,
            &PersistedPlacementState {
                epoch: 4,
                view_id: "old-view".to_string(),
            },
        )
        .await
        .expect("state write should succeed");

        let epoch = load_or_bootstrap_placement_epoch(data_dir, "new-view")
            .await
            .expect("bootstrap should succeed");
        assert_eq!(epoch, 5);

        let persisted = read_persisted_placement_state(&path)
            .await
            .expect("state read should succeed")
            .expect("state should exist");
        assert_eq!(persisted.epoch, 5);
        assert_eq!(persisted.view_id, "new-view");
    }

    #[tokio::test]
    async fn write_persisted_placement_state_replaces_state_without_temp_artifacts() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let data_dir = temp.path().to_str().expect("path should be utf8");
        let path = placement_state_path(data_dir);

        write_persisted_placement_state(
            &path,
            &PersistedPlacementState {
                epoch: 1,
                view_id: "view-initial".to_string(),
            },
        )
        .await
        .expect("initial write should succeed");
        write_persisted_placement_state(
            &path,
            &PersistedPlacementState {
                epoch: 2,
                view_id: "view-next".to_string(),
            },
        )
        .await
        .expect("replacement write should succeed");

        let persisted = read_persisted_placement_state(&path)
            .await
            .expect("state read should succeed")
            .expect("state should exist");
        assert_eq!(persisted.epoch, 2);
        assert_eq!(persisted.view_id, "view-next");

        let parent = path.parent().expect("placement-state path has parent");
        let temp_prefix = format!("{}.tmp-", PLACEMENT_STATE_FILE);
        for entry in std::fs::read_dir(parent).expect("state directory should be readable") {
            let file_name = entry
                .expect("directory entry should be readable")
                .file_name()
                .to_string_lossy()
                .to_string();
            assert!(
                !file_name.starts_with(&temp_prefix),
                "found leaked placement state temp artifact: {file_name}"
            );
        }
    }

    #[tokio::test]
    async fn probe_storage_data_path_reports_readable_for_healthy_storage() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let storage = FilesystemStorage::new(
            temp.path().to_str().expect("path should be utf8"),
            false,
            1024,
            0,
        )
        .await
        .expect("storage should initialize");

        let probe = probe_storage_data_path(&storage).await;
        assert!(probe.readable);
        assert!(probe.warning.is_none());
    }

    #[tokio::test]
    async fn probe_storage_data_path_reports_warning_on_storage_io_error() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let storage = FilesystemStorage::new(
            temp.path().to_str().expect("path should be utf8"),
            false,
            1024,
            0,
        )
        .await
        .expect("storage should initialize");

        std::fs::remove_dir_all(temp.path().join("buckets"))
            .expect("buckets directory should be removable");
        let probe = probe_storage_data_path(&storage).await;
        assert!(!probe.readable);
        assert!(
            probe
                .warning
                .as_deref()
                .is_some_and(|warning| warning.contains("Storage data-path probe failed"))
        );
    }

    #[test]
    fn probe_disk_headroom_reports_sufficient_when_threshold_disabled() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let path = temp.path().to_str().expect("path should be utf8");

        let probe = probe_disk_headroom(path, 0);
        assert!(probe.sufficient);
        assert!(probe.warning.is_none());
    }

    #[test]
    fn probe_disk_headroom_reports_warning_when_threshold_not_met() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let path = temp.path().to_str().expect("path should be utf8");
        let free_bytes = fs2::available_space(path).expect("available space probe should succeed");
        if free_bytes == u64::MAX {
            // Some filesystems report an effectively unbounded free-space sentinel.
            // In that environment we cannot construct a strictly larger threshold.
            return;
        }
        let required = free_bytes.saturating_add(1);

        let probe = probe_disk_headroom(path, required);
        assert!(!probe.sufficient);
        assert!(
            probe
                .warning
                .as_deref()
                .is_some_and(|warning| warning.contains("Disk headroom below threshold"))
        );
    }

    #[tokio::test]
    async fn probe_peer_connectivity_reports_ready_when_no_peers_configured() {
        let result = probe_peer_connectivity(&[]).await;
        assert!(result.ready);
        assert!(result.warning.is_none());
    }

    #[tokio::test]
    async fn probe_peer_connectivity_reports_warning_for_unreachable_peers() {
        let peers = vec!["127.0.0.1:1".to_string()];
        let result = probe_peer_connectivity(peers.as_slice()).await;
        assert!(!result.ready);
        assert!(
            result
                .warning
                .as_deref()
                .is_some_and(|warning| warning.contains("Peer connectivity probe failed"))
        );
    }

    #[tokio::test]
    async fn runtime_topology_snapshot_reports_standalone_mode() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let storage = FilesystemStorage::new(
            temp.path().to_str().expect("path should be utf8"),
            false,
            1024,
            0,
        )
        .await
        .expect("storage should initialize");
        let state = AppState {
            storage: Arc::new(storage),
            config: Arc::new(test_config()),
            credentials: Arc::new(HashMap::new()),
            node_id: Arc::new("node-a".to_string()),
            cluster_peers: Arc::new(Vec::new()),
            membership_protocol: MembershipProtocol::Gossip,
            placement_epoch: Arc::new(AtomicU64::new(7)),
            login_rate_limiter: Arc::new(LoginRateLimiter::new()),
            request_count: Arc::new(AtomicU64::new(0)),
            started_at: Instant::now(),
        };

        let snapshot = runtime_topology_snapshot(&state);
        assert_eq!(snapshot.mode, RuntimeMode::Standalone);
        assert!(!snapshot.is_distributed());
        assert_eq!(snapshot.node_id, "node-a");
        assert_eq!(snapshot.cluster_peer_count(), 0);
        assert_eq!(snapshot.cluster_peers, Vec::<String>::new());
        assert_eq!(snapshot.membership_node_count(), 1);
        assert_eq!(snapshot.membership_nodes, vec!["node-a"]);
        assert_eq!(snapshot.membership_protocol, MembershipProtocol::Gossip);
        assert_eq!(snapshot.placement_epoch, 7);
    }

    #[tokio::test]
    async fn runtime_topology_snapshot_reports_distributed_mode_and_view_id() {
        let temp = tempfile::tempdir().expect("temp dir should create");
        let storage = FilesystemStorage::new(
            temp.path().to_str().expect("path should be utf8"),
            false,
            1024,
            0,
        )
        .await
        .expect("storage should initialize");
        let state = AppState {
            storage: Arc::new(storage),
            config: Arc::new(test_config()),
            credentials: Arc::new(HashMap::new()),
            node_id: Arc::new("node-a".to_string()),
            cluster_peers: Arc::new(vec!["node-b".to_string(), "node-c".to_string()]),
            membership_protocol: MembershipProtocol::Raft,
            placement_epoch: Arc::new(AtomicU64::new(11)),
            login_rate_limiter: Arc::new(LoginRateLimiter::new()),
            request_count: Arc::new(AtomicU64::new(0)),
            started_at: Instant::now(),
        };

        let snapshot = runtime_topology_snapshot(&state);
        assert_eq!(snapshot.mode, RuntimeMode::Distributed);
        assert!(snapshot.is_distributed());
        assert_eq!(snapshot.node_id, "node-a");
        assert_eq!(snapshot.cluster_peer_count(), 2);
        assert_eq!(snapshot.cluster_peers, vec!["node-b", "node-c"]);
        assert_eq!(snapshot.membership_node_count(), 3);
        assert_eq!(
            snapshot.membership_nodes,
            vec!["node-a", "node-b", "node-c"]
        );
        assert_eq!(snapshot.membership_protocol, MembershipProtocol::Raft);
        assert!(!snapshot.membership_view_id.is_empty());
        assert_eq!(snapshot.placement_epoch, 11);
    }
}
