use super::*;
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use maxio::config::{ClusterPeerTransportMode, MembershipProtocol, WriteDurabilityMode};
use maxio::metadata::{
    ClusterMetadataListingStrategy, MetadataReconcileAction, MetadataRepairPlan,
    PendingMetadataRepairPlan, PersistedMetadataState,
    enqueue_pending_metadata_repair_plan_persisted, persist_persisted_metadata_state,
};
use maxio::server::AppState;
use maxio::storage::placement::{
    PendingRebalanceOperation, PendingReplicationOperation, PlacementViewState,
    RebalanceObjectScope, RebalanceTransfer, ReplicationMutationOperation,
    enqueue_pending_rebalance_operation_persisted, enqueue_pending_replication_operation_persisted,
    local_rebalance_actions, membership_view_id_with_self, membership_with_self,
    object_rebalance_plan,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

#[derive(Clone)]
struct PeerHealthStubState {
    membership_view_id: String,
    cluster_id: Option<String>,
    cluster_peers: Vec<String>,
    placement_epoch: Option<u64>,
}

async fn peer_healthz_handler(
    axum::extract::State(state): axum::extract::State<PeerHealthStubState>,
) -> axum::Json<serde_json::Value> {
    axum::Json(json!({
        "ok": true,
        "status": "ok",
        "membershipViewId": state.membership_view_id,
        "clusterId": state.cluster_id,
        "clusterPeers": state.cluster_peers,
        "placementEpoch": state.placement_epoch,
    }))
}

async fn start_peer_healthz_stub(membership_view_id: &str) -> String {
    start_peer_healthz_stub_with_snapshot(membership_view_id, None, Vec::new()).await
}

async fn start_peer_healthz_stub_with_snapshot(
    membership_view_id: &str,
    cluster_id: Option<String>,
    cluster_peers: Vec<String>,
) -> String {
    let app = axum::Router::new()
        .route("/healthz", axum::routing::get(peer_healthz_handler))
        .with_state(PeerHealthStubState {
            membership_view_id: membership_view_id.to_string(),
            cluster_id,
            cluster_peers,
            placement_epoch: None,
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("peer healthz listener should bind");
    let addr = listener
        .local_addr()
        .expect("peer healthz listener should expose local address");
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .expect("peer healthz stub should serve");
    });
    addr.to_string()
}

async fn start_peer_healthz_stub_with_matching_single_peer_view(node_id: &str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("peer healthz listener should bind");
    let addr = listener
        .local_addr()
        .expect("peer healthz listener should expose local address");
    let peer = addr.to_string();
    let membership_view_id = membership_view_id_with_self(node_id, std::slice::from_ref(&peer));
    let app = axum::Router::new()
        .route("/healthz", axum::routing::get(peer_healthz_handler))
        .with_state(PeerHealthStubState {
            membership_view_id,
            cluster_id: None,
            cluster_peers: Vec::new(),
            placement_epoch: None,
        });
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .expect("peer healthz stub should serve");
    });
    peer
}

async fn start_peer_healthz_stub_with_discovery_snapshot(
    local_node_id: &str,
    membership_view_id: &str,
    cluster_peers: Vec<String>,
) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("peer healthz listener should bind");
    let addr = listener
        .local_addr()
        .expect("peer healthz listener should expose local address");
    let peer = addr.to_string();
    let cluster_id =
        membership_view_id_with_self(local_node_id, std::slice::from_ref(&peer)).to_string();
    let app = axum::Router::new()
        .route("/healthz", axum::routing::get(peer_healthz_handler))
        .with_state(PeerHealthStubState {
            membership_view_id: membership_view_id.to_string(),
            cluster_id: Some(cluster_id),
            cluster_peers,
            placement_epoch: None,
        });
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .expect("peer healthz stub should serve");
    });
    peer
}

#[derive(Clone)]
struct GossipStaleReconciliationRetryStubState {
    membership_view_id: String,
    cluster_id: String,
    cluster_peers: Vec<String>,
    placement_epoch: u64,
    retry: MembershipPropagationRetryCaptureState,
}

async fn gossip_stale_reconciliation_retry_healthz_handler(
    axum::extract::State(state): axum::extract::State<GossipStaleReconciliationRetryStubState>,
) -> axum::Json<serde_json::Value> {
    axum::Json(json!({
        "ok": true,
        "status": "ok",
        "membershipViewId": state.membership_view_id,
        "clusterId": state.cluster_id,
        "clusterPeers": state.cluster_peers,
        "placementEpoch": state.placement_epoch,
    }))
}

async fn gossip_stale_reconciliation_retry_membership_update_handler(
    axum::extract::State(state): axum::extract::State<GossipStaleReconciliationRetryStubState>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<serde_json::Value>,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    let propagation_header = headers
        .get("x-maxio-internal-membership-propagated")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let forwarded_by = headers
        .get("x-maxio-forwarded-by")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    {
        let mut records = state.retry.records.lock().await;
        records.push(MembershipPropagationCapture {
            propagation_header,
            forwarded_by,
            payload,
        });
    }

    let status = {
        let mut statuses = state.retry.response_statuses.lock().await;
        statuses.pop_front().unwrap_or(StatusCode::OK)
    };
    {
        let mut served = state.retry.served_statuses.lock().await;
        served.push(status.as_u16());
    }
    (
        status,
        axum::Json(json!({
            "status": "applied",
            "reason": "applied",
            "mode": "shared_token",
            "updated": true,
        })),
    )
}

async fn start_gossip_stale_reconciliation_retry_stub(
    local_node_id: &str,
    membership_view_id: &str,
    cluster_peers: Vec<String>,
    placement_epoch: u64,
    response_statuses: Vec<StatusCode>,
) -> (String, MembershipPropagationRetryCaptureState) {
    let retry = MembershipPropagationRetryCaptureState::new(response_statuses);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("gossip stale reconciliation retry stub listener should bind");
    let addr = listener
        .local_addr()
        .expect("gossip stale reconciliation retry stub should expose local address");
    let peer = addr.to_string();
    let cluster_id =
        membership_view_id_with_self(local_node_id, std::slice::from_ref(&peer)).to_string();
    let app = axum::Router::new()
        .route(
            "/healthz",
            axum::routing::get(gossip_stale_reconciliation_retry_healthz_handler),
        )
        .route(
            "/internal/cluster/membership/update",
            axum::routing::post(gossip_stale_reconciliation_retry_membership_update_handler),
        )
        .with_state(GossipStaleReconciliationRetryStubState {
            membership_view_id: membership_view_id.to_string(),
            cluster_id,
            cluster_peers,
            placement_epoch,
            retry: retry.clone(),
        });
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .expect("gossip stale reconciliation retry stub should serve");
    });
    (peer, retry)
}

async fn start_gossip_stale_reconciliation_retry_stub_with_local_view(
    local_node_id: &str,
    cluster_peers: Vec<String>,
    placement_epoch: u64,
    response_statuses: Vec<StatusCode>,
) -> (String, String, MembershipPropagationRetryCaptureState) {
    let retry = MembershipPropagationRetryCaptureState::new(response_statuses);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("gossip stale reconciliation retry stub listener should bind");
    let addr = listener
        .local_addr()
        .expect("gossip stale reconciliation retry stub should expose local address");
    let peer = addr.to_string();
    let membership_view_id =
        membership_view_id_with_self(local_node_id, std::slice::from_ref(&peer)).to_string();
    let cluster_id = membership_view_id.clone();
    let app = axum::Router::new()
        .route(
            "/healthz",
            axum::routing::get(gossip_stale_reconciliation_retry_healthz_handler),
        )
        .route(
            "/internal/cluster/membership/update",
            axum::routing::post(gossip_stale_reconciliation_retry_membership_update_handler),
        )
        .with_state(GossipStaleReconciliationRetryStubState {
            membership_view_id: membership_view_id.clone(),
            cluster_id,
            cluster_peers,
            placement_epoch,
            retry: retry.clone(),
        });
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .expect("gossip stale reconciliation retry stub should serve");
    });
    (peer, membership_view_id, retry)
}

fn decode_first_pem_block(payload: &str, label: &str) -> Option<Vec<u8>> {
    let begin_marker = format!("-----BEGIN {label}-----");
    let end_marker = format!("-----END {label}-----");
    let begin = payload.find(begin_marker.as_str())? + begin_marker.len();
    let end = payload[begin..].find(end_marker.as_str())? + begin;
    let body = &payload[begin..end];
    let mut encoded = String::new();
    for line in body.lines().map(str::trim) {
        if line.is_empty() || line.contains(':') {
            continue;
        }
        encoded.push_str(line);
    }
    if encoded.is_empty() {
        return None;
    }
    BASE64_STANDARD.decode(encoded.as_bytes()).ok()
}

fn write_valid_mtls_identity_fixture(
    tmp: &tempfile::TempDir,
) -> (
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
    String,
) {
    let cert_path = tmp.path().join("peer.crt");
    let key_path = tmp.path().join("peer.key");
    let ca_path = tmp.path().join("ca.pem");
    let cert_pem_raw = "-----BEGIN CERTIFICATE-----\n\
                    MIIDKDCCAhCgAwIBAgIUSQnaqIrYDWiCpyUekIzvcQ4BPZwwDQYJKoZIhvcNAQEL\n\
                    BQAwFTETMBEGA1UEAwwKbWF4aW8tcGVlcjAeFw0yNjAzMDQxNTQyMzdaFw0zNjAz\n\
                    MDExNTQyMzdaMBUxEzARBgNVBAMMCm1heGlvLXBlZXIwggEiMA0GCSqGSIb3DQEB\n\
                    AQUAA4IBDwAwggEKAoIBAQDjI1gmjkZivK7EEVdJokcPHPrW9MdiQqvVdRkA9i8q\n\
                    BeCWeo9TW/il4EKddPeergUh6NTpNBVeBQZZKjGIUbJAMQqaNrFnCksC1XoCTL+2\n\
                    CCfdDjY3SRQR7wvCznWSLBskJyPqDswttb+CU1XDydXTda43O2fdGdjkiXAtXwPa\n\
                    cA1Gj/izc+eumExGVWLNy+EghnKqaEUMudp0PEQXGzwFiNbOMHoL98qIBHONP1U1\n\
                    xu+WUbgf4NPUEj6j2YY8p/cP7F2ibeY+dgdGMHjWYB9Ybp8ZI9jsr11GaL+7Qoxh\n\
                    nD3ZKHhSsTgES1haTiT1b/Don/b6gwztsAAgzgCiGhs9AgMBAAGjcDBuMB0GA1Ud\n\
                    DgQWBBSaCWCIhdoL7L27bd8T6GAEID2tSTAfBgNVHSMEGDAWgBSaCWCIhdoL7L27\n\
                    bd8T6GAEID2tSTAPBgNVHRMBAf8EBTADAQH/MBsGA1UdEQQUMBKCCm1heGlvLXBl\n\
                    ZXKHBH8AAAEwDQYJKoZIhvcNAQELBQADggEBAHYxBWftqrZHKRVvzFyHRwX9vXh8\n\
                    uAlC1T5zR599gjP78Zq1KZWfHPw9UQdmhpjgl8kkDIvBp7QHfbT35eHegv/wLhQW\n\
                    RbqS1CWpKNLeyDR93BHLl4mTan7M8fIGfwecCLvf/pbjL4gcO1BYcxC0o+3sn0CC\n\
                    MuMFGbzFcasZ05jhk9cHsU7YfH3V60oTfn8VUSVUD7IIaSc/TmAMNWNoJbvVy7Xf\n\
                    gtwaVdL8f4WDaLdUrO1RvSAhECW7mSdSRqDu99WH4ON3hh31BfU2cogIQ6hA1n07\n\
                    wbJcBbcynFXmQPDYiafFrVFEmC5EOuCyyNExf2kYibSefxtPWM57/g7sG6g=\n\
                    -----END CERTIFICATE-----\n";
    let key_pem_raw = "-----BEGIN PRIVATE KEY-----\n\
                   MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDjI1gmjkZivK7E\n\
                   EVdJokcPHPrW9MdiQqvVdRkA9i8qBeCWeo9TW/il4EKddPeergUh6NTpNBVeBQZZ\n\
                   KjGIUbJAMQqaNrFnCksC1XoCTL+2CCfdDjY3SRQR7wvCznWSLBskJyPqDswttb+C\n\
                   U1XDydXTda43O2fdGdjkiXAtXwPacA1Gj/izc+eumExGVWLNy+EghnKqaEUMudp0\n\
                   PEQXGzwFiNbOMHoL98qIBHONP1U1xu+WUbgf4NPUEj6j2YY8p/cP7F2ibeY+dgdG\n\
                   MHjWYB9Ybp8ZI9jsr11GaL+7QoxhnD3ZKHhSsTgES1haTiT1b/Don/b6gwztsAAg\n\
                   zgCiGhs9AgMBAAECggEAKm8zPArHEBG/lc5GkDFi1Ko9m7Sh3lPl3exxRip4H8H2\n\
                   1i4iAjkTwEugLmIIk+rfdxkUU9gg6M6IA9b754OZyV/QIwT2SjGUV3xx/aWAiH3I\n\
                   Esahrtz2hK4z9IpVUUBvtqagUU0/7IdAttSiWIBn9AhPiq6MxjQavwGFRVizs9Zy\n\
                   rR8WtLcTseYq9Jicjp7hj03ResLeSektvLl0jcA4HZZdPdezbMNHrG6QJdu3Zk0T\n\
                   ic3uTRmQsAs8LUTy8Vk4BQifqrOXSB1m6Y1l7cuBkkr7mmhk4sliU9wH2jVZlHmO\n\
                   bwda43GDqnUIaWiq+PQb9nxzNPTSxDpQXguzTiu3OQKBgQDz65orCSVtSRViZ8pQ\n\
                   PtTmUHZO9hisdofN0hSWK1RSmNAxkubSbScQrJdMDPFIwDuSntoGCFH4UFYdL8qh\n\
                   ThRupxQfAwpHy9KIic55EpCWnLgq/hJkk3TiGV8/kvEpKSjvkx3mykmj9rFIXnFn\n\
                   HXDgEojbHqLhQoH0iJQ5OATRaQKBgQDuYvpy3lDqdPHfmlaBR8xekbSjLBAjJx0n\n\
                   PzTEgNQyYliFh6BWGocDk5cAUfAHEyd0YwcEUd1SUKwi3VXxTGPSdm6sOrLA0pBH\n\
                   ixQ5gAFfZAFPAByeaF8AO7vOEYijSHFSQ+8V+OfPBBxAs8CBx/qHxI4TKweliexK\n\
                   eEVK0pQstQKBgF24b+MLP5svEo1d7clJawoXbm3GdxKE9IcrqgdNHLgjyRLTK+c8\n\
                   U18/wV5SNr9KRVl/uavJtJ0hWQUb4NJ7qrQddEi6JVASy5D0yiWQ8Yc9LjIuryh/\n\
                   09AwCX3m2syC6RysPTf5D7R1TAbPaulA0ab22CjBK7o7kK1BcRpPIOLJAoGAIMx7\n\
                   evx9k5Sdhs9cYZM4Wjaf7OduHPgPucunffXfvELtvQmJFO+3bdWLrB6Z8M9A2XGa\n\
                   kIyW7/Frjax4W6fQADANUCMPXxpZgY5wLO0gwzgmOfFg/qaLk6OkVljxPM4F0XTJ\n\
                   W3OQqVn+bSSOMw0Juk5f4eFEvxD38tMTbZUFkBUCgYAo2Hjmt46jJsKvOW6nqBGW\n\
                   RZTxRHHUWdzDfsSogg50dRvx6JFp5Y5DlQ5A0qgHoyaKZ+tMxvlQ9UoTGWRimRJn\n\
                   ti3O/aSCL8f19MvfdFLPB8dMqmZ//+CCdRv5IxB1SQNZXLwlS7eY0RGDqO6ai3L0\n\
                   2LC+Q4XHvuze/HVPrw/QRQ==\n\
                   -----END PRIVATE KEY-----\n";
    let cert_pem = cert_pem_raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let key_pem = key_pem_raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";

    std::fs::write(&cert_path, cert_pem.as_bytes()).expect("cert fixture should write");
    std::fs::write(&key_path, key_pem.as_bytes()).expect("key fixture should write");
    std::fs::write(&ca_path, cert_pem.as_bytes()).expect("ca fixture should write");

    let cert_der =
        decode_first_pem_block(cert_pem.as_str(), "CERTIFICATE").expect("cert block should parse");
    let cert_sha256_pin = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(cert_der.as_slice()))
    );
    (cert_path, key_path, ca_path, cert_sha256_pin)
}

#[derive(Clone, Debug)]
struct MembershipPropagationCapture {
    propagation_header: Option<String>,
    forwarded_by: Option<String>,
    payload: serde_json::Value,
}

#[derive(Clone, Default)]
struct MembershipPropagationCaptureState {
    records: Arc<Mutex<Vec<MembershipPropagationCapture>>>,
}

#[derive(Clone)]
struct MembershipPropagationRetryCaptureState {
    records: Arc<Mutex<Vec<MembershipPropagationCapture>>>,
    response_statuses: Arc<Mutex<VecDeque<StatusCode>>>,
    served_statuses: Arc<Mutex<Vec<u16>>>,
}

impl MembershipPropagationRetryCaptureState {
    fn new(response_statuses: Vec<StatusCode>) -> Self {
        Self {
            records: Arc::new(Mutex::new(Vec::new())),
            response_statuses: Arc::new(Mutex::new(VecDeque::from(response_statuses))),
            served_statuses: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

async fn membership_propagation_capture_handler(
    axum::extract::State(state): axum::extract::State<MembershipPropagationCaptureState>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    let propagation_header = headers
        .get("x-maxio-internal-membership-propagated")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let forwarded_by = headers
        .get("x-maxio-forwarded-by")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let mut records = state.records.lock().await;
    records.push(MembershipPropagationCapture {
        propagation_header,
        forwarded_by,
        payload,
    });
    axum::Json(json!({
        "status": "applied",
        "reason": "applied",
        "mode": "shared_token",
        "updated": true,
    }))
}

async fn start_membership_propagation_capture_stub() -> (String, MembershipPropagationCaptureState)
{
    let state = MembershipPropagationCaptureState::default();
    let app = axum::Router::new()
        .route(
            "/internal/cluster/membership/update",
            axum::routing::post(membership_propagation_capture_handler),
        )
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("capture stub listener should bind");
    let addr = listener
        .local_addr()
        .expect("capture stub listener should expose local address");
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .expect("capture stub should serve");
    });
    (addr.to_string(), state)
}

async fn membership_propagation_retry_capture_handler(
    axum::extract::State(state): axum::extract::State<MembershipPropagationRetryCaptureState>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<serde_json::Value>,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    let propagation_header = headers
        .get("x-maxio-internal-membership-propagated")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let forwarded_by = headers
        .get("x-maxio-forwarded-by")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    {
        let mut records = state.records.lock().await;
        records.push(MembershipPropagationCapture {
            propagation_header,
            forwarded_by,
            payload,
        });
    }

    let status = {
        let mut statuses = state.response_statuses.lock().await;
        statuses.pop_front().unwrap_or(StatusCode::OK)
    };
    {
        let mut served = state.served_statuses.lock().await;
        served.push(status.as_u16());
    }
    (
        status,
        axum::Json(json!({
            "status": "applied",
            "reason": "applied",
            "mode": "shared_token",
            "updated": true,
        })),
    )
}

async fn start_membership_propagation_retry_stub(
    response_statuses: Vec<StatusCode>,
) -> (String, MembershipPropagationRetryCaptureState) {
    let state = MembershipPropagationRetryCaptureState::new(response_statuses);
    let app = axum::Router::new()
        .route(
            "/internal/cluster/membership/update",
            axum::routing::post(membership_propagation_retry_capture_handler),
        )
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("retry capture stub listener should bind");
    let addr = listener
        .local_addr()
        .expect("retry capture stub listener should expose local address");
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .expect("retry capture stub should serve");
    });
    (addr.to_string(), state)
}

#[derive(Clone, Debug)]
struct RebalanceTransferCapture {
    path_and_query: String,
    forwarded_by: Option<String>,
    auth_token: Option<String>,
    trusted_operation: Option<String>,
}

#[derive(Clone, Default)]
struct RebalanceTransferCaptureState {
    records: Arc<Mutex<Vec<RebalanceTransferCapture>>>,
}

#[derive(Clone, Debug)]
struct ReplicationReplayCapture {
    path_and_query: String,
    method: String,
    forwarded_by: Option<String>,
    auth_token: Option<String>,
    trusted_operation: Option<String>,
}

#[derive(Clone)]
struct ReplicationReplayCaptureState {
    records: Arc<Mutex<Vec<ReplicationReplayCapture>>>,
    status: StatusCode,
}

impl ReplicationReplayCaptureState {
    fn new(status: StatusCode) -> Self {
        Self {
            records: Arc::new(Mutex::new(Vec::new())),
            status,
        }
    }
}

async fn rebalance_transfer_capture_put_handler(
    axum::extract::State(state): axum::extract::State<RebalanceTransferCaptureState>,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
    _body: axum::body::Bytes,
) -> StatusCode {
    let path_and_query = uri
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| uri.path().to_string());
    let forwarded_by = headers
        .get("x-maxio-forwarded-by")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let auth_token = headers
        .get("x-maxio-internal-auth-token")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let trusted_operation = headers
        .get("x-maxio-internal-forwarded-write-operation")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let mut records = state.records.lock().await;
    records.push(RebalanceTransferCapture {
        path_and_query,
        forwarded_by,
        auth_token,
        trusted_operation,
    });
    StatusCode::OK
}

async fn start_rebalance_transfer_capture_stub() -> (String, RebalanceTransferCaptureState) {
    let state = RebalanceTransferCaptureState::default();
    let app = axum::Router::new()
        .route(
            "/{bucket}/{*key}",
            axum::routing::put(rebalance_transfer_capture_put_handler),
        )
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("rebalance capture stub listener should bind");
    let addr = listener
        .local_addr()
        .expect("rebalance capture stub listener should expose local address");
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .expect("rebalance capture stub should serve");
    });
    (addr.to_string(), state)
}

async fn replication_replay_capture_handler(
    axum::extract::State(state): axum::extract::State<ReplicationReplayCaptureState>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
    _body: axum::body::Bytes,
) -> StatusCode {
    let path_and_query = uri
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| uri.path().to_string());
    let forwarded_by = headers
        .get("x-maxio-forwarded-by")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let auth_token = headers
        .get("x-maxio-internal-auth-token")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let trusted_operation = headers
        .get("x-maxio-internal-forwarded-write-operation")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let mut records = state.records.lock().await;
    records.push(ReplicationReplayCapture {
        path_and_query,
        method: method.as_str().to_string(),
        forwarded_by,
        auth_token,
        trusted_operation,
    });
    state.status
}

async fn start_replication_replay_capture_stub(
    status: StatusCode,
) -> (String, ReplicationReplayCaptureState) {
    let state = ReplicationReplayCaptureState::new(status);
    let app = axum::Router::new()
        .route(
            "/{bucket}/{*key}",
            axum::routing::put(replication_replay_capture_handler)
                .delete(replication_replay_capture_handler),
        )
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("replication replay capture stub listener should bind");
    let addr = listener
        .local_addr()
        .expect("replication replay capture stub should expose local address");
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .expect("replication replay capture stub should serve");
    });
    (addr.to_string(), state)
}

fn unix_ms_now_string() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

fn seed_pending_metadata_repair_queue(data_dir: &str) {
    let queue_path = Path::new(data_dir)
        .join(".maxio-runtime")
        .join("pending-metadata-repair-queue.json");
    let plan = PendingMetadataRepairPlan::new(
        "repair-runtime-test-1",
        1,
        MetadataRepairPlan {
            source_view_id: "source-view".to_string(),
            target_view_id: "target-view".to_string(),
            actions: vec![MetadataReconcileAction::UpsertBucket {
                bucket: "photos".to_string(),
                versioning_enabled: false,
                lifecycle_enabled: false,
            }],
        },
    )
    .expect("pending metadata repair plan should be valid");
    let enqueue_outcome =
        enqueue_pending_metadata_repair_plan_persisted(queue_path.as_path(), plan);
    assert!(
        enqueue_outcome.is_ok(),
        "pending metadata repair plan should enqueue: {enqueue_outcome:?}"
    );
}

fn seed_pending_metadata_repair_queue_with_stale_target_view(data_dir: &str) {
    let runtime_dir = Path::new(data_dir).join(".maxio-runtime");
    let queue_path = runtime_dir.join("pending-metadata-repair-queue.json");
    let metadata_state_path = runtime_dir.join("cluster-metadata-state.json");
    persist_persisted_metadata_state(
        metadata_state_path.as_path(),
        &PersistedMetadataState {
            view_id: "persisted-view".to_string(),
            ..PersistedMetadataState::default()
        },
    )
    .expect("persisted metadata state should be writable");
    let plan = PendingMetadataRepairPlan::new(
        "repair-runtime-stale-view-test",
        1,
        MetadataRepairPlan {
            source_view_id: "source-view".to_string(),
            target_view_id: "target-view".to_string(),
            actions: vec![MetadataReconcileAction::UpsertBucket {
                bucket: "photos".to_string(),
                versioning_enabled: false,
                lifecycle_enabled: false,
            }],
        },
    )
    .expect("pending metadata repair plan should be valid");
    let enqueue_outcome =
        enqueue_pending_metadata_repair_plan_persisted(queue_path.as_path(), plan);
    assert!(
        enqueue_outcome.is_ok(),
        "pending metadata repair stale-view plan should enqueue: {enqueue_outcome:?}"
    );
}

#[tokio::test]
async fn test_request_id_header_present_on_s3_auth_failure() {
    let (base_url, _tmp) = start_server().await;
    let resp = client().get(format!("{}/", base_url)).send().await.unwrap();
    assert_eq!(resp.status(), 403);

    let request_id = resp
        .headers()
        .get("x-amz-request-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-amz-request-id");
    uuid::Uuid::parse_str(request_id).expect("request id should be a valid uuid");
}

fn metric_value(metrics: &str, name: &str) -> Option<f64> {
    metrics.lines().find_map(|line| {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || !trimmed.starts_with(name) {
            return None;
        }
        let value = trimmed.split_whitespace().nth(1)?;
        value.parse::<f64>().ok()
    })
}

fn metric_labeled_value(metrics: &str, metric_with_labels: &str) -> Option<f64> {
    metrics.lines().find_map(|line| {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || !trimmed.starts_with(metric_with_labels) {
            return None;
        }
        let value = trimmed.split_whitespace().nth(1)?;
        value.parse::<f64>().ok()
    })
}

#[tokio::test]
async fn test_metrics_endpoint_reports_distributed_gauges_when_cluster_peers_configured() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    config.membership_protocol = MembershipProtocol::Gossip;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let resp = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();

    assert_eq!(metric_value(&body, "maxio_distributed_mode"), Some(1.0));
    assert_eq!(metric_value(&body, "maxio_cluster_peers_total"), Some(1.0));
    assert!(body.contains("maxio_cluster_identity_info{cluster_id=\""));
    assert_eq!(
        metric_value(&body, "maxio_membership_nodes_total"),
        Some(2.0)
    );
    assert!(body.contains("maxio_cluster_peer_auth_mode_info{mode=\"compatibility-no-token\"} 1"));
    assert_eq!(
        metric_value(&body, "maxio_cluster_peer_auth_configured"),
        Some(0.0)
    );
    assert!(body.contains(
        "maxio_cluster_peer_auth_trust_model_info{model=\"forwarded-by-marker-only\"} 1"
    ));
    assert_eq!(
        metric_value(&body, "maxio_cluster_peer_auth_identity_bound"),
        Some(0.0)
    );
    assert_eq!(
        metric_value(&body, "maxio_cluster_peer_auth_sender_allowlist_bound"),
        Some(0.0)
    );
    assert!(body.contains("maxio_cluster_join_auth_mode_info{mode=\"compatibility_no_token\"} 1"));
    assert_eq!(
        metric_value(&body, "maxio_cluster_join_auth_ready"),
        Some(0.0)
    );
    assert!(body.contains(
        "maxio_cluster_join_auth_readiness_reason_info{reason=\"cluster_auth_token_not_configured\"} 1"
    ));
    assert!(
        metric_value(&body, "maxio_cluster_peer_auth_reject_total")
            .is_some_and(|value| value >= 0.0)
    );
    assert!(
        metric_labeled_value(
            &body,
            "maxio_cluster_peer_auth_reject_reason_total{reason=\"sender_not_in_allowlist\"}"
        )
        .is_some_and(|value| value >= 0.0)
    );
    assert!(body.contains("maxio_membership_protocol_info{protocol=\"gossip\"} 1"));
    assert!(body.contains("maxio_write_durability_mode_info{mode=\"degraded-success\"} 1"));
    assert!(body.contains("maxio_metadata_listing_strategy_info{strategy=\"local-node-only\"} 1"));
    assert_eq!(
        metric_value(&body, "maxio_metadata_listing_cluster_authoritative"),
        Some(0.0)
    );
    assert_eq!(
        metric_value(&body, "maxio_metadata_listing_ready"),
        Some(0.0)
    );
    assert!(
        body.contains(
            "maxio_metadata_listing_gap_info{gap=\"strategy-not-cluster-authoritative\"} 1"
        )
    );
    assert_eq!(
        metric_value(&body, "maxio_membership_protocol_ready"),
        Some(1.0)
    );
    assert_eq!(metric_value(&body, "maxio_membership_converged"), Some(0.0));
    assert!(body.contains(
        "maxio_membership_convergence_reason_info{reason=\"peer-connectivity-failed\"} 1"
    ));
    assert!(
        metric_value(&body, "maxio_membership_last_update_unix_ms")
            .is_some_and(|value| value > 0.0)
    );
    assert_eq!(metric_value(&body, "maxio_placement_epoch"), Some(0.0));
    assert_eq!(
        metric_value(&body, "maxio_pending_replication_queue_readable"),
        Some(1.0)
    );
    assert_eq!(
        metric_value(&body, "maxio_pending_replication_backlog_operations"),
        Some(0.0)
    );
    assert_eq!(
        metric_value(&body, "maxio_pending_replication_backlog_pending_targets"),
        Some(0.0)
    );
    assert_eq!(
        metric_value(&body, "maxio_pending_replication_backlog_due_targets"),
        Some(0.0)
    );
    assert_eq!(
        metric_value(
            &body,
            "maxio_pending_replication_backlog_due_targets_capped"
        ),
        Some(0.0)
    );
    assert_eq!(
        metric_value(&body, "maxio_pending_replication_backlog_failed_targets"),
        Some(0.0)
    );
    assert_eq!(
        metric_value(&body, "maxio_pending_replication_backlog_max_attempts"),
        Some(0.0)
    );
    assert_eq!(
        metric_value(
            &body,
            "maxio_pending_replication_backlog_oldest_created_at_unix_ms"
        ),
        Some(0.0)
    );
}

#[tokio::test]
async fn test_metrics_membership_converged_reflects_peer_probe_for_static_bootstrap() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["127.0.0.1:1".to_string()];
    config.membership_protocol = MembershipProtocol::StaticBootstrap;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let resp = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();

    assert_eq!(
        metric_value(&body, "maxio_membership_protocol_ready"),
        Some(1.0)
    );
    assert_eq!(metric_value(&body, "maxio_membership_converged"), Some(0.0));
    assert!(body.contains(
        "maxio_membership_convergence_reason_info{reason=\"peer-connectivity-failed\"} 1"
    ));
    assert!(
        metric_value(&body, "maxio_membership_last_update_unix_ms")
            .is_some_and(|value| value > 0.0)
    );
}

#[tokio::test]
async fn test_metrics_pending_replication_replay_counters_increment_in_distributed_mode() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    config.membership_protocol = MembershipProtocol::StaticBootstrap;
    let (base_url, _tmp) = start_server_with_config_and_replay_worker(config, tmp).await;

    let mut observed = None;
    for _ in 0..130 {
        let response = client()
            .get(format!("{}/metrics", base_url))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = response.text().await.unwrap();

        let cycles_total = metric_value(&body, "maxio_pending_replication_replay_cycles_total");
        let cycles_succeeded = metric_value(
            &body,
            "maxio_pending_replication_replay_cycles_succeeded_total",
        );
        let cycles_failed = metric_value(
            &body,
            "maxio_pending_replication_replay_cycles_failed_total",
        );
        let last_cycle_unix_ms =
            metric_value(&body, "maxio_pending_replication_replay_last_cycle_unix_ms");
        let last_success_unix_ms = metric_value(
            &body,
            "maxio_pending_replication_replay_last_success_unix_ms",
        );
        let last_failure_unix_ms = metric_value(
            &body,
            "maxio_pending_replication_replay_last_failure_unix_ms",
        );

        if let (Some(total), Some(succeeded), Some(failed), Some(last_cycle), Some(last_success)) = (
            cycles_total,
            cycles_succeeded,
            cycles_failed,
            last_cycle_unix_ms,
            last_success_unix_ms,
        ) {
            if total >= 1.0 {
                observed = Some((
                    total,
                    succeeded,
                    failed,
                    last_cycle,
                    last_success,
                    last_failure_unix_ms,
                ));
                break;
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let (cycles_total, cycles_succeeded, cycles_failed, last_cycle, last_success, last_failure) =
        observed.expect("replay worker metrics should report at least one executed cycle");
    assert!(cycles_total >= 1.0);
    assert!(cycles_succeeded >= 1.0);
    assert!(cycles_total >= cycles_succeeded + cycles_failed);
    assert!(last_cycle > 0.0);
    assert!(last_success > 0.0);
    assert_eq!(last_failure, Some(0.0));
}

#[tokio::test]
async fn test_metrics_pending_membership_propagation_replay_counters_increment_in_distributed_mode()
{
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.membership_protocol = MembershipProtocol::StaticBootstrap;
    let (base_url, _tmp) =
        start_server_with_config_and_membership_propagation_replay_worker(config, tmp).await;

    let mut observed = None;
    for _ in 0..130 {
        let response = client()
            .get(format!("{}/metrics", base_url))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = response.text().await.unwrap();

        let cycles_total = metric_value(
            &body,
            "maxio_pending_membership_propagation_replay_cycles_total",
        );
        let cycles_succeeded = metric_value(
            &body,
            "maxio_pending_membership_propagation_replay_cycles_succeeded_total",
        );
        let cycles_failed = metric_value(
            &body,
            "maxio_pending_membership_propagation_replay_cycles_failed_total",
        );
        let deferred_operations_total = metric_value(
            &body,
            "maxio_pending_membership_propagation_replay_deferred_operations_total",
        );
        let last_cycle_unix_ms = metric_value(
            &body,
            "maxio_pending_membership_propagation_replay_last_cycle_unix_ms",
        );
        let last_success_unix_ms = metric_value(
            &body,
            "maxio_pending_membership_propagation_replay_last_success_unix_ms",
        );
        let last_failure_unix_ms = metric_value(
            &body,
            "maxio_pending_membership_propagation_replay_last_failure_unix_ms",
        );

        if let (Some(total), Some(succeeded), Some(failed), Some(last_cycle), Some(last_success)) = (
            cycles_total,
            cycles_succeeded,
            cycles_failed,
            last_cycle_unix_ms,
            last_success_unix_ms,
        ) {
            if total >= 1.0 {
                observed = Some((
                    total,
                    succeeded,
                    failed,
                    deferred_operations_total,
                    last_cycle,
                    last_success,
                    last_failure_unix_ms,
                ));
                break;
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let (
        cycles_total,
        cycles_succeeded,
        cycles_failed,
        deferred_operations_total,
        last_cycle,
        last_success,
        last_failure,
    ) = observed.expect(
        "membership propagation replay worker metrics should report at least one executed cycle",
    );
    assert!(cycles_total >= 1.0);
    assert!(cycles_succeeded >= 1.0);
    assert!(cycles_total >= cycles_succeeded + cycles_failed);
    assert!(deferred_operations_total.is_some());
    assert!(last_cycle > 0.0);
    assert!(last_success > 0.0);
    assert_eq!(last_failure, Some(0.0));
}

#[tokio::test]
async fn test_pending_rebalance_replay_worker_forwards_due_send_transfer_and_drains_queue() {
    let (capture_peer, capture_state) = start_rebalance_transfer_capture_stub().await;

    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let local_node_id = "node-a.internal:9000";
    seed_object_in_data_dir(
        data_dir.as_str(),
        "rebalance-bucket",
        "docs/replay-object.txt",
        b"rebalance-payload",
        false,
    )
    .await;

    let queue_path = Path::new(data_dir.as_str())
        .join(".maxio-runtime")
        .join("pending-rebalance-queue.json");
    let placement = PlacementViewState::from_membership(1, local_node_id, &[capture_peer.clone()]);
    let operation = PendingRebalanceOperation::new(
        "rebalance-replay-runtime-test",
        "rebalance-bucket",
        "docs/replay-object.txt",
        RebalanceObjectScope::Object,
        local_node_id,
        &placement,
        &[RebalanceTransfer {
            from: Some(local_node_id.to_string()),
            to: capture_peer.clone(),
        }],
        1,
    )
    .expect("pending rebalance operation should be valid");
    let enqueue_outcome =
        enqueue_pending_rebalance_operation_persisted(queue_path.as_path(), operation);
    assert!(
        enqueue_outcome.is_ok(),
        "pending rebalance operation should enqueue: {enqueue_outcome:?}"
    );

    let mut config = make_test_config(data_dir.clone(), false, 10 * 1024 * 1024, 0);
    config.node_id = local_node_id.to_string();
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec![capture_peer.clone()];
    let (_base_url, _tmp) = start_server_with_config_and_rebalance_replay_worker(config, tmp).await;

    let mut queue_drained = false;
    for _ in 0..130 {
        let queue_is_empty = tokio::fs::read_to_string(queue_path.as_path())
            .await
            .ok()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
            .and_then(|value| {
                value["operations"]
                    .as_array()
                    .map(|operations| operations.is_empty())
            })
            .unwrap_or(false);
        let has_capture = !capture_state.records.lock().await.is_empty();
        if queue_is_empty && has_capture {
            queue_drained = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        queue_drained,
        "pending rebalance replay worker should forward transfer and drain queue"
    );

    let records = capture_state.records.lock().await;
    let record = records
        .first()
        .expect("rebalance transfer capture should record at least one forwarded request");
    assert_eq!(record.forwarded_by.as_deref(), Some(local_node_id));
    assert_eq!(record.auth_token.as_deref(), Some("shared-secret"));
    assert_eq!(
        record.trusted_operation.as_deref(),
        Some("replicate-put-object")
    );
    assert!(
        record.path_and_query.contains("X-Amz-Signature="),
        "rebalance transfer should use presigned query auth"
    );
}

#[tokio::test]
async fn test_pending_rebalance_replay_worker_drops_chunk_scope_without_forwarding() {
    let (capture_peer, capture_state) = start_rebalance_transfer_capture_stub().await;

    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let local_node_id = "node-a.internal:9000";
    seed_object_in_data_dir(
        data_dir.as_str(),
        "rebalance-bucket",
        "docs/replay-object.txt",
        b"rebalance-payload",
        false,
    )
    .await;

    let queue_path = Path::new(data_dir.as_str())
        .join(".maxio-runtime")
        .join("pending-rebalance-queue.json");
    let placement = PlacementViewState::from_membership(1, local_node_id, &[capture_peer.clone()]);
    let operation = PendingRebalanceOperation::new(
        "rebalance-replay-chunk-runtime-test",
        "rebalance-bucket",
        "docs/replay-object.txt",
        RebalanceObjectScope::Chunk { chunk_index: 3 },
        local_node_id,
        &placement,
        &[RebalanceTransfer {
            from: Some(local_node_id.to_string()),
            to: capture_peer.clone(),
        }],
        1,
    )
    .expect("pending rebalance operation should be valid");
    let enqueue_outcome =
        enqueue_pending_rebalance_operation_persisted(queue_path.as_path(), operation);
    assert!(
        enqueue_outcome.is_ok(),
        "pending rebalance operation should enqueue: {enqueue_outcome:?}"
    );

    let mut config = make_test_config(data_dir.clone(), false, 10 * 1024 * 1024, 0);
    config.node_id = local_node_id.to_string();
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec![capture_peer.clone()];
    let (_base_url, _tmp) = start_server_with_config_and_rebalance_replay_worker(config, tmp).await;

    let mut queue_drained = false;
    for _ in 0..130 {
        let queue_is_empty = tokio::fs::read_to_string(queue_path.as_path())
            .await
            .ok()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
            .and_then(|value| {
                value["operations"]
                    .as_array()
                    .map(|operations| operations.is_empty())
            })
            .unwrap_or(false);
        if queue_is_empty {
            queue_drained = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        queue_drained,
        "pending rebalance replay worker should drain dropped chunk-scope operation"
    );

    let records = capture_state.records.lock().await;
    assert!(
        records.is_empty(),
        "chunk-scope rebalance replay should not forward object transport requests"
    );
}

#[tokio::test]
async fn test_pending_replication_replay_worker_drops_terminal_replica_failure_without_retry() {
    let (capture_peer, capture_state) =
        start_replication_replay_capture_stub(StatusCode::FORBIDDEN).await;

    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let local_node_id = "node-a.internal:9000";
    seed_object_in_data_dir(
        data_dir.as_str(),
        "replay-bucket",
        "docs/replay-object.txt",
        b"replication-replay-payload",
        false,
    )
    .await;

    let queue_path = Path::new(data_dir.as_str())
        .join(".maxio-runtime")
        .join("pending-replication-queue.json");
    let placement = PlacementViewState::from_membership(1, local_node_id, &[capture_peer.clone()]);
    let operation = PendingReplicationOperation::new(
        "pending-replication-terminal-status-test",
        ReplicationMutationOperation::PutObject,
        "replay-bucket",
        "docs/replay-object.txt",
        None,
        local_node_id,
        &placement,
        std::slice::from_ref(&capture_peer),
        1,
    )
    .expect("pending replication operation should be valid");
    let enqueue_outcome =
        enqueue_pending_replication_operation_persisted(queue_path.as_path(), operation);
    assert!(
        enqueue_outcome.is_ok(),
        "pending replication operation should enqueue: {enqueue_outcome:?}"
    );

    let mut config = make_test_config(data_dir.clone(), false, 10 * 1024 * 1024, 0);
    config.node_id = local_node_id.to_string();
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec![capture_peer.clone()];
    let (base_url, _tmp) = start_server_with_config_and_replay_worker(config, tmp).await;

    let mut queue_drained = false;
    for _ in 0..130 {
        let queue_is_empty = tokio::fs::read_to_string(queue_path.as_path())
            .await
            .ok()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
            .and_then(|value| {
                value["operations"]
                    .as_array()
                    .map(|operations| operations.is_empty())
            })
            .unwrap_or(false);
        let has_capture = !capture_state.records.lock().await.is_empty();
        if queue_is_empty && has_capture {
            queue_drained = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let final_queue_is_empty = tokio::fs::read_to_string(queue_path.as_path())
        .await
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|value| {
            value["operations"]
                .as_array()
                .map(|operations| operations.is_empty())
        })
        .unwrap_or(false);
    let final_record_count = capture_state.records.lock().await.len();
    assert!(
        queue_drained,
        "pending replication replay worker should drop terminal replica status and drain queue (final_queue_empty={final_queue_is_empty}, capture_count={final_record_count})"
    );

    // Wait longer than one replay interval to ensure no retry loop is scheduled.
    tokio::time::sleep(Duration::from_millis(5500)).await;

    let records = capture_state.records.lock().await;
    assert_eq!(
        records.len(),
        1,
        "terminal replay failure should be dropped instead of retried"
    );
    let record = records
        .first()
        .expect("replication replay capture should contain one request");
    assert_eq!(record.method, "PUT");
    assert_eq!(record.forwarded_by.as_deref(), Some(local_node_id));
    assert_eq!(record.auth_token.as_deref(), Some("shared-secret"));
    assert_eq!(
        record.trusted_operation.as_deref(),
        Some("replicate-put-object")
    );
    assert!(
        record.path_and_query.contains("X-Amz-Signature="),
        "replication replay should use presigned query auth"
    );

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .expect("metrics request should succeed");
    assert_eq!(metrics.status(), StatusCode::OK);
    let metrics_body = metrics.text().await.expect("metrics payload should decode");
    assert_eq!(
        metric_value(
            &metrics_body,
            "maxio_pending_replication_replay_acknowledged_total",
        ),
        Some(1.0),
        "terminal replay drop should acknowledge exactly one queued target"
    );
    assert_eq!(
        metric_value(
            &metrics_body,
            "maxio_pending_replication_replay_skipped_total"
        ),
        Some(1.0),
        "terminal replay drop should count one skipped replay candidate"
    );
    assert_eq!(
        metric_value(
            &metrics_body,
            "maxio_pending_replication_replay_failed_total"
        ),
        Some(0.0),
        "terminal replay drop should not be recorded as retryable failure"
    );
}

#[tokio::test]
async fn test_metrics_pending_rebalance_replay_counters_increment_in_distributed_mode() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    config.membership_protocol = MembershipProtocol::StaticBootstrap;
    let (base_url, _tmp) = start_server_with_config_and_rebalance_replay_worker(config, tmp).await;

    let mut observed = None;
    for _ in 0..130 {
        let response = client()
            .get(format!("{}/metrics", base_url))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = response.text().await.unwrap();

        let cycles_total = metric_value(&body, "maxio_pending_rebalance_replay_cycles_total");
        let cycles_succeeded = metric_value(
            &body,
            "maxio_pending_rebalance_replay_cycles_succeeded_total",
        );
        let cycles_failed =
            metric_value(&body, "maxio_pending_rebalance_replay_cycles_failed_total");
        let last_cycle_unix_ms =
            metric_value(&body, "maxio_pending_rebalance_replay_last_cycle_unix_ms");
        let last_success_unix_ms =
            metric_value(&body, "maxio_pending_rebalance_replay_last_success_unix_ms");
        let last_failure_unix_ms =
            metric_value(&body, "maxio_pending_rebalance_replay_last_failure_unix_ms");

        if let (Some(total), Some(succeeded), Some(failed), Some(last_cycle), Some(last_success)) = (
            cycles_total,
            cycles_succeeded,
            cycles_failed,
            last_cycle_unix_ms,
            last_success_unix_ms,
        ) {
            if total >= 1.0 {
                observed = Some((
                    total,
                    succeeded,
                    failed,
                    last_cycle,
                    last_success,
                    last_failure_unix_ms,
                ));
                break;
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let (cycles_total, cycles_succeeded, cycles_failed, last_cycle, last_success, last_failure) =
        observed
            .expect("rebalance replay worker metrics should report at least one executed cycle");
    assert!(cycles_total >= 1.0);
    assert!(cycles_succeeded >= 1.0);
    assert!(cycles_total >= cycles_succeeded + cycles_failed);
    assert!(last_cycle > 0.0);
    assert!(last_success > 0.0);
    assert_eq!(last_failure, Some(0.0));
}

#[tokio::test]
async fn test_metrics_pending_metadata_repair_replay_counters_increment_in_distributed_mode() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    seed_pending_metadata_repair_queue(data_dir.as_str());
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    config.membership_protocol = MembershipProtocol::StaticBootstrap;
    let (base_url, _tmp) =
        start_server_with_config_and_metadata_repair_replay_worker(config, tmp).await;

    let mut observed = None;
    for _ in 0..130 {
        let response = client()
            .get(format!("{}/metrics", base_url))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = response.text().await.unwrap();

        let cycles_total = metric_value(&body, "maxio_pending_metadata_repair_replay_cycles_total");
        let cycles_succeeded = metric_value(
            &body,
            "maxio_pending_metadata_repair_replay_cycles_succeeded_total",
        );
        let cycles_failed = metric_value(
            &body,
            "maxio_pending_metadata_repair_replay_cycles_failed_total",
        );
        let failed_plans = metric_value(
            &body,
            "maxio_pending_metadata_repair_replay_failed_plans_total",
        );
        let acknowledged_plans = metric_value(
            &body,
            "maxio_pending_metadata_repair_replay_acknowledged_plans_total",
        );
        let last_cycle_unix_ms = metric_value(
            &body,
            "maxio_pending_metadata_repair_replay_last_cycle_unix_ms",
        );
        let last_success_unix_ms = metric_value(
            &body,
            "maxio_pending_metadata_repair_replay_last_success_unix_ms",
        );
        let last_failure_unix_ms = metric_value(
            &body,
            "maxio_pending_metadata_repair_replay_last_failure_unix_ms",
        );

        if let (
            Some(total),
            Some(succeeded),
            Some(failed),
            Some(failed_plans_total),
            Some(acknowledged_plans_total),
            Some(last_cycle),
            Some(last_success),
        ) = (
            cycles_total,
            cycles_succeeded,
            cycles_failed,
            failed_plans,
            acknowledged_plans,
            last_cycle_unix_ms,
            last_success_unix_ms,
        ) {
            if total >= 1.0 && acknowledged_plans_total >= 1.0 {
                observed = Some((
                    total,
                    succeeded,
                    failed,
                    failed_plans_total,
                    acknowledged_plans_total,
                    last_cycle,
                    last_success,
                    last_failure_unix_ms,
                ));
                break;
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let (
        cycles_total,
        cycles_succeeded,
        cycles_failed,
        failed_plans,
        acknowledged_plans,
        last_cycle,
        last_success,
        last_failure,
    ) = observed.expect("metadata repair replay worker metrics should report at least one cycle");
    assert!(cycles_total >= 1.0);
    assert!(cycles_succeeded >= 1.0);
    assert!(cycles_total >= cycles_succeeded + cycles_failed);
    assert!(acknowledged_plans >= 1.0);
    assert_eq!(failed_plans, 0.0);
    assert!(last_cycle > 0.0);
    assert!(last_success > 0.0);
    assert_eq!(last_failure, Some(0.0));
}

#[tokio::test]
async fn test_pending_metadata_repair_replay_worker_drops_stale_view_plans_without_retry_backoff() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    seed_pending_metadata_repair_queue_with_stale_target_view(data_dir.as_str());
    let queue_path = Path::new(data_dir.as_str())
        .join(".maxio-runtime")
        .join("pending-metadata-repair-queue.json");

    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    config.membership_protocol = MembershipProtocol::StaticBootstrap;
    let (base_url, _tmp) =
        start_server_with_config_and_metadata_repair_replay_worker(config, tmp).await;

    let mut queue_drained = false;
    for _ in 0..130 {
        let queue_is_empty = tokio::fs::read_to_string(queue_path.as_path())
            .await
            .ok()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
            .and_then(|value| value["plans"].as_array().map(|plans| plans.is_empty()))
            .unwrap_or(false);
        if queue_is_empty {
            queue_drained = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        queue_drained,
        "metadata replay worker should drop stale-view terminal plans from queue"
    );

    let mut observed = None;
    for _ in 0..130 {
        let response = client()
            .get(format!("{}/metrics", base_url))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = response.text().await.unwrap();
        let skipped_plans = metric_value(
            &body,
            "maxio_pending_metadata_repair_replay_skipped_plans_total",
        );
        let failed_plans = metric_value(
            &body,
            "maxio_pending_metadata_repair_replay_failed_plans_total",
        );
        let cycles_failed = metric_value(
            &body,
            "maxio_pending_metadata_repair_replay_cycles_failed_total",
        );

        if let (Some(skipped), Some(failed), Some(cycles_failed_total)) =
            (skipped_plans, failed_plans, cycles_failed)
        {
            if skipped >= 1.0 {
                observed = Some((skipped, failed, cycles_failed_total));
                break;
            }
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let (skipped_plans, failed_plans, cycles_failed) =
        observed.expect("metadata replay metrics should reflect dropped terminal-plan execution");
    assert!(skipped_plans >= 1.0);
    assert_eq!(failed_plans, 0.0);
    assert_eq!(cycles_failed, 0.0);
}

#[tokio::test]
async fn test_console_route_bypasses_sigv4_and_has_request_id() {
    let (base_url, _tmp) = start_server().await;
    let resp = client()
        .get(format!("{}/api/auth/check", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "/api routes should not require SigV4");

    let request_id = resp
        .headers()
        .get("x-amz-request-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-amz-request-id");
    uuid::Uuid::parse_str(request_id).expect("request id should be a valid uuid");
}

#[tokio::test]
async fn test_split_internal_listener_isolates_control_plane_routes() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    config.membership_protocol = MembershipProtocol::StaticBootstrap;

    let (public_base_url, internal_base_url, _tmp) =
        start_server_with_split_internal_listener(config, tmp).await;

    let public_internal_resp = client()
        .post(format!(
            "{}/internal/cluster/join/authorize",
            public_base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(public_internal_resp.status(), 403);

    let internal_internal_resp = client()
        .post(format!(
            "{}/internal/cluster/join/authorize",
            internal_base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(internal_internal_resp.status(), 503);

    let public_health_resp = client()
        .get(format!("{}/healthz", public_base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(public_health_resp.status(), 200);

    let internal_health_resp = client()
        .get(format!("{}/healthz", internal_base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(internal_health_resp.status(), 404);
}

#[tokio::test]
async fn test_metrics_endpoint_exposes_runtime_counters() {
    let (base_url, _tmp) = start_server().await;

    let resp = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "text/plain; version=0.0.4"
    );

    let body = resp.text().await.unwrap();
    assert!(
        body.contains("maxio_requests_total"),
        "metrics output missing request counter"
    );
    assert!(
        body.contains("maxio_uptime_seconds"),
        "metrics output missing uptime gauge"
    );
    assert!(
        body.contains("maxio_build_info"),
        "metrics output missing build info"
    );
    assert!(
        body.contains("maxio_distributed_mode"),
        "metrics output missing distributed-mode gauge"
    );
    assert!(
        body.contains("maxio_cluster_peers_total"),
        "metrics output missing cluster-peer count gauge"
    );
    assert!(
        body.contains("maxio_cluster_identity_info"),
        "metrics output missing cluster identity gauge"
    );
    assert!(
        body.contains("maxio_membership_nodes_total"),
        "metrics output missing membership-node count gauge"
    );
    assert!(
        body.contains("maxio_membership_last_update_unix_ms"),
        "metrics output missing membership last-update gauge"
    );
    assert!(
        body.contains("maxio_cluster_peer_auth_mode_info"),
        "metrics output missing cluster peer auth mode gauge"
    );
    assert!(
        body.contains("maxio_cluster_peer_auth_configured"),
        "metrics output missing cluster peer auth configured gauge"
    );
    assert!(
        body.contains("maxio_cluster_peer_auth_trust_model_info"),
        "metrics output missing cluster peer auth trust model gauge"
    );
    assert!(
        body.contains("maxio_cluster_peer_auth_identity_bound"),
        "metrics output missing cluster peer auth identity-bound gauge"
    );
    assert!(
        body.contains("maxio_cluster_peer_auth_sender_allowlist_bound"),
        "metrics output missing cluster peer auth sender-allowlist gauge"
    );
    assert!(
        body.contains("maxio_cluster_peer_auth_reject_total"),
        "metrics output missing cluster peer auth reject total counter"
    );
    assert!(
        body.contains("maxio_cluster_peer_auth_reject_reason_total"),
        "metrics output missing cluster peer auth reject reason counter"
    );
    assert!(body.contains("maxio_cluster_peer_auth_mode_info{mode=\"compatibility-no-token\"} 1"));
    assert_eq!(
        metric_value(&body, "maxio_cluster_peer_auth_configured"),
        Some(0.0)
    );
    assert!(body.contains(
        "maxio_cluster_peer_auth_trust_model_info{model=\"forwarded-by-marker-only\"} 1"
    ));
    assert_eq!(
        metric_value(&body, "maxio_cluster_peer_auth_identity_bound"),
        Some(0.0)
    );
    assert_eq!(
        metric_value(&body, "maxio_cluster_peer_auth_sender_allowlist_bound"),
        Some(0.0)
    );
    assert!(
        metric_value(&body, "maxio_cluster_peer_auth_reject_total")
            .is_some_and(|value| value >= 0.0)
    );
    assert!(
        metric_labeled_value(
            &body,
            "maxio_cluster_peer_auth_reject_reason_total{reason=\"sender_not_in_allowlist\"}"
        )
        .is_some_and(|value| value >= 0.0)
    );
    assert!(
        body.contains("maxio_membership_protocol_info"),
        "metrics output missing membership protocol info gauge"
    );
    assert!(
        body.contains("maxio_write_durability_mode_info"),
        "metrics output missing write durability mode gauge"
    );
    assert!(body.contains("maxio_write_durability_mode_info{mode=\"degraded-success\"} 1"));
    assert!(
        body.contains("maxio_metadata_listing_strategy_info"),
        "metrics output missing metadata listing strategy gauge"
    );
    assert!(
        body.contains("maxio_metadata_listing_cluster_authoritative"),
        "metrics output missing metadata listing authoritative gauge"
    );
    assert!(
        body.contains("maxio_metadata_listing_ready"),
        "metrics output missing metadata listing readiness gauge"
    );
    assert!(
        body.contains("maxio_metadata_listing_gap_info"),
        "metrics output missing metadata listing gap info gauge"
    );
    assert!(
        body.contains("maxio_membership_protocol_ready"),
        "metrics output missing membership protocol readiness gauge"
    );
    assert!(
        body.contains("maxio_membership_convergence_reason_info"),
        "metrics output missing membership convergence reason gauge"
    );
    assert_eq!(
        metric_value(&body, "maxio_membership_protocol_ready"),
        Some(1.0)
    );
    assert!(
        body.contains("maxio_placement_epoch"),
        "metrics output missing placement epoch gauge"
    );
    assert!(
        body.contains("maxio_pending_replication_queue_readable"),
        "metrics output missing pending replication queue readable gauge"
    );
    assert!(
        body.contains("maxio_pending_replication_backlog_operations"),
        "metrics output missing pending replication backlog operations gauge"
    );
    assert!(
        body.contains("maxio_pending_replication_backlog_pending_targets"),
        "metrics output missing pending replication backlog pending-targets gauge"
    );
    assert!(
        body.contains("maxio_pending_replication_backlog_failed_targets"),
        "metrics output missing pending replication backlog failed-targets gauge"
    );
    assert!(
        body.contains("maxio_pending_replication_backlog_max_attempts"),
        "metrics output missing pending replication backlog max-attempts gauge"
    );
    assert!(
        body.contains("maxio_pending_replication_backlog_oldest_created_at_unix_ms"),
        "metrics output missing pending replication backlog oldest-created-at gauge"
    );
    assert!(
        body.contains("maxio_pending_replication_replay_cycles_total"),
        "metrics output missing pending replication replay cycles counter"
    );
    assert!(
        body.contains("maxio_pending_replication_replay_cycles_succeeded_total"),
        "metrics output missing pending replication replay success counter"
    );
    assert!(
        body.contains("maxio_pending_replication_replay_cycles_failed_total"),
        "metrics output missing pending replication replay failure counter"
    );
    assert!(
        body.contains("maxio_pending_replication_replay_last_success_unix_ms"),
        "metrics output missing pending replication replay last-success gauge"
    );
    assert!(
        body.contains("maxio_pending_replication_replay_last_failure_unix_ms"),
        "metrics output missing pending replication replay last-failure gauge"
    );
    assert!(
        body.contains("maxio_pending_rebalance_replay_cycles_total"),
        "metrics output missing pending rebalance replay cycles counter"
    );
    assert!(
        body.contains("maxio_pending_rebalance_replay_cycles_succeeded_total"),
        "metrics output missing pending rebalance replay success counter"
    );
    assert!(
        body.contains("maxio_pending_rebalance_replay_cycles_failed_total"),
        "metrics output missing pending rebalance replay failure counter"
    );
    assert!(
        body.contains("maxio_pending_rebalance_replay_last_success_unix_ms"),
        "metrics output missing pending rebalance replay last-success gauge"
    );
    assert!(
        body.contains("maxio_pending_rebalance_replay_last_failure_unix_ms"),
        "metrics output missing pending rebalance replay last-failure gauge"
    );
    assert!(
        body.contains("maxio_pending_metadata_repair_queue_readable"),
        "metrics output missing pending metadata repair queue readable gauge"
    );
    assert!(
        body.contains("maxio_pending_metadata_repair_backlog_plans"),
        "metrics output missing pending metadata repair backlog plans gauge"
    );
    assert!(
        body.contains("maxio_pending_metadata_repair_backlog_due_plans"),
        "metrics output missing pending metadata repair backlog due-plans gauge"
    );
    assert!(
        body.contains("maxio_pending_metadata_repair_backlog_failed_plans"),
        "metrics output missing pending metadata repair backlog failed-plans gauge"
    );
    assert!(
        body.contains("maxio_pending_metadata_repair_replay_cycles_total"),
        "metrics output missing pending metadata repair replay cycles counter"
    );
    assert!(
        body.contains("maxio_pending_metadata_repair_replay_cycles_succeeded_total"),
        "metrics output missing pending metadata repair replay success counter"
    );
    assert!(
        body.contains("maxio_pending_metadata_repair_replay_cycles_failed_total"),
        "metrics output missing pending metadata repair replay failure counter"
    );
    assert!(
        body.contains("maxio_pending_metadata_repair_replay_last_success_unix_ms"),
        "metrics output missing pending metadata repair replay last-success gauge"
    );
    assert!(
        body.contains("maxio_pending_metadata_repair_replay_last_failure_unix_ms"),
        "metrics output missing pending metadata repair replay last-failure gauge"
    );
    assert!(
        body.contains("maxio_cluster_join_requests_total"),
        "metrics output missing cluster-join request counter"
    );
    assert!(
        body.contains("maxio_cluster_join_status_total"),
        "metrics output missing cluster-join status counter"
    );
    assert!(
        body.contains("maxio_cluster_join_reason_total"),
        "metrics output missing cluster-join reason counter"
    );
    assert_eq!(
        metric_value(&body, "maxio_pending_replication_queue_readable"),
        Some(1.0)
    );
    assert_eq!(
        metric_value(&body, "maxio_pending_replication_replay_cycles_total"),
        Some(0.0)
    );
    assert_eq!(
        metric_value(
            &body,
            "maxio_pending_replication_replay_cycles_succeeded_total"
        ),
        Some(0.0)
    );
    assert_eq!(
        metric_value(
            &body,
            "maxio_pending_replication_replay_cycles_failed_total"
        ),
        Some(0.0)
    );
    assert_eq!(
        metric_value(&body, "maxio_pending_replication_replay_last_cycle_unix_ms"),
        Some(0.0)
    );
    assert_eq!(
        metric_value(
            &body,
            "maxio_pending_replication_replay_last_success_unix_ms"
        ),
        Some(0.0)
    );
    assert_eq!(
        metric_value(
            &body,
            "maxio_pending_replication_replay_last_failure_unix_ms"
        ),
        Some(0.0)
    );
    assert_eq!(
        metric_value(&body, "maxio_pending_rebalance_replay_cycles_total"),
        Some(0.0)
    );
    assert_eq!(
        metric_value(
            &body,
            "maxio_pending_rebalance_replay_cycles_succeeded_total"
        ),
        Some(0.0)
    );
    assert_eq!(
        metric_value(&body, "maxio_pending_rebalance_replay_cycles_failed_total"),
        Some(0.0)
    );
    assert_eq!(
        metric_value(&body, "maxio_pending_rebalance_replay_last_cycle_unix_ms"),
        Some(0.0)
    );
    assert_eq!(
        metric_value(&body, "maxio_pending_rebalance_replay_last_success_unix_ms"),
        Some(0.0)
    );
    assert_eq!(
        metric_value(&body, "maxio_pending_rebalance_replay_last_failure_unix_ms"),
        Some(0.0)
    );
    assert_eq!(
        metric_value(&body, "maxio_pending_metadata_repair_queue_readable"),
        Some(1.0)
    );
    assert_eq!(
        metric_value(&body, "maxio_pending_metadata_repair_replay_cycles_total"),
        Some(0.0)
    );
    assert_eq!(
        metric_value(
            &body,
            "maxio_pending_metadata_repair_replay_cycles_succeeded_total"
        ),
        Some(0.0)
    );
    assert_eq!(
        metric_value(
            &body,
            "maxio_pending_metadata_repair_replay_cycles_failed_total"
        ),
        Some(0.0)
    );
    assert_eq!(
        metric_value(
            &body,
            "maxio_pending_metadata_repair_replay_last_cycle_unix_ms"
        ),
        Some(0.0)
    );
    assert_eq!(
        metric_value(
            &body,
            "maxio_pending_metadata_repair_replay_last_success_unix_ms"
        ),
        Some(0.0)
    );
    assert_eq!(
        metric_value(
            &body,
            "maxio_pending_metadata_repair_replay_last_failure_unix_ms"
        ),
        Some(0.0)
    );
}

#[tokio::test]
async fn test_metrics_peer_auth_reject_reason_counter_increments_when_forwarded_headers_rejected() {
    let (base_url, _tmp) = start_server().await;
    let bucket = "metrics-peer-auth-reject-reason";
    let key = "docs/a.txt";

    let create = s3_request("PUT", &format!("{}/{}", base_url, bucket), vec![]).await;
    assert_eq!(create.status(), 200);

    let put = s3_request_with_headers(
        "PUT",
        &format!("{}/{}/{}", base_url, bucket, key),
        b"payload".to_vec(),
        vec![
            ("x-maxio-forwarded-by", "node-a:9000,node-a:9000"),
            ("x-maxio-forwarded-write-epoch", "7"),
        ],
    )
    .await;
    assert_eq!(put.status(), 200);

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let body = metrics.text().await.unwrap();

    assert!(
        metric_value(&body, "maxio_cluster_peer_auth_reject_total")
            .is_some_and(|value| value >= 1.0)
    );
    assert!(metric_labeled_value(
        &body,
        "maxio_cluster_peer_auth_reject_reason_total{reason=\"forwarded_by_duplicate_peer_hop\"}"
    )
    .is_some_and(|value| value >= 1.0));
}

#[tokio::test]
async fn test_metrics_peer_auth_reject_reason_counter_increments_for_runtime_endpoint_headers() {
    let (base_url, _tmp) = start_server().await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .header("x-maxio-forwarded-by", "node-a:9000,node-a:9000")
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let body = metrics.text().await.unwrap();

    assert!(
        metric_value(&body, "maxio_cluster_peer_auth_reject_total")
            .is_some_and(|value| value >= 1.0)
    );
    assert!(metric_labeled_value(
        &body,
        "maxio_cluster_peer_auth_reject_reason_total{reason=\"forwarded_by_duplicate_peer_hop\"}"
    )
    .is_some_and(|value| value >= 1.0));
    assert!(
        metric_labeled_value(
            &body,
            "maxio_runtime_internal_header_reject_endpoint_total{endpoint=\"healthz\"}"
        )
        .is_some_and(|value| value >= 1.0)
    );
    assert!(
        metric_labeled_value(
            &body,
            "maxio_runtime_internal_header_reject_sender_total{sender=\"missing_or_invalid\"}"
        )
        .is_some_and(|value| value >= 1.0)
    );
}

#[tokio::test]
async fn test_metrics_runtime_internal_header_reject_dimensions_track_api_unknown_sender() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["node-b:9000".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let response = client()
        .get(format!("{}/api/auth/check", base_url))
        .header("x-maxio-forwarded-by", "node-x:9000")
        .header("x-maxio-internal-auth-token", "shared-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let body = metrics.text().await.unwrap();

    assert!(
        metric_labeled_value(
            &body,
            "maxio_runtime_internal_header_reject_endpoint_total{endpoint=\"api\"}"
        )
        .is_some_and(|value| value >= 1.0)
    );
    assert!(
        metric_labeled_value(
            &body,
            "maxio_runtime_internal_header_reject_sender_total{sender=\"unknown_peer\"}"
        )
        .is_some_and(|value| value >= 1.0)
    );
    assert!(
        metric_labeled_value(
            &body,
            "maxio_cluster_peer_auth_reject_reason_total{reason=\"sender_not_in_allowlist\"}"
        )
        .is_some_and(|value| value >= 1.0)
    );
}

#[tokio::test]
async fn test_metrics_runtime_internal_header_reject_dimensions_track_api_known_sender_token_mismatch()
 {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["node-b:9000".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let response = client()
        .get(format!("{}/api/auth/check", base_url))
        .header("x-maxio-forwarded-by", "node-b:9000")
        .header("x-maxio-internal-auth-token", "wrong-shared-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let body = metrics.text().await.unwrap();

    assert!(
        metric_labeled_value(
            &body,
            "maxio_runtime_internal_header_reject_endpoint_total{endpoint=\"api\"}"
        )
        .is_some_and(|value| value >= 1.0)
    );
    assert!(
        metric_labeled_value(
            &body,
            "maxio_runtime_internal_header_reject_sender_total{sender=\"known_peer\"}"
        )
        .is_some_and(|value| value >= 1.0)
    );
    assert!(
        metric_labeled_value(
            &body,
            "maxio_cluster_peer_auth_reject_reason_total{reason=\"auth_token_mismatch\"}"
        )
        .is_some_and(|value| value >= 1.0)
    );
}

#[tokio::test]
async fn test_healthz_endpoint_reports_runtime_status() {
    let (base_url, _tmp) = start_server().await;
    let resp = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/json"
    );

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert!(body["uptimeSeconds"].as_f64().is_some());
    assert_eq!(body["mode"], "standalone");
    assert!(body["nodeId"].as_str().is_some_and(|v| !v.is_empty()));
    assert!(body["clusterId"].as_str().is_some_and(|v| !v.is_empty()));
    assert_eq!(body["clusterPeerCount"], 0);
    assert_eq!(body["clusterPeers"], serde_json::json!([]));
    assert_eq!(body["membershipNodeCount"], 1);
    assert_eq!(body["clusterAuthMode"], "compatibility-no-token");
    assert_eq!(body["clusterAuthTrustModel"], "forwarded-by-marker-only");
    assert_eq!(body["clusterAuthTransportIdentity"], "none");
    assert_eq!(body["clusterJoinAuthMode"], "compatibility_no_token");
    assert_eq!(body["clusterJoinAuthReason"], "authorized");
    assert_eq!(
        body["membershipNodes"],
        serde_json::json!(["maxio-test-node"])
    );
    assert_eq!(body["membershipProtocol"], "static-bootstrap");
    assert_eq!(body["writeDurabilityMode"], "degraded-success");
    assert_eq!(body["metadataListingStrategy"], "local-node-only");
    assert_eq!(
        body["metadataListingGap"],
        "strategy-not-cluster-authoritative"
    );
    assert!(
        body["membershipViewId"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );
    assert_eq!(body["placementEpoch"], 0);
    assert_eq!(body["pendingReplicationBacklogOperations"], 0);
    assert_eq!(body["pendingReplicationBacklogPendingTargets"], 0);
    assert_eq!(body["pendingReplicationBacklogFailedTargets"], 0);
    assert_eq!(body["pendingReplicationBacklogMaxAttempts"], 0);
    assert_eq!(body["pendingReplicationReplayCyclesTotal"], 0);
    assert_eq!(body["pendingReplicationReplayCyclesSucceeded"], 0);
    assert_eq!(body["pendingReplicationReplayCyclesFailed"], 0);
    assert_eq!(body["pendingReplicationReplayLastCycleUnixMs"], 0);
    assert_eq!(body["pendingReplicationReplayLastSuccessUnixMs"], 0);
    assert_eq!(body["pendingReplicationReplayLastFailureUnixMs"], 0);
    assert_eq!(body["pendingRebalanceBacklogOperations"], 0);
    assert_eq!(body["pendingRebalanceBacklogPendingTransfers"], 0);
    assert_eq!(body["pendingRebalanceBacklogDueTransfers"], 0);
    assert_eq!(body["pendingRebalanceBacklogDueTransfersCapped"], false);
    assert_eq!(body["pendingRebalanceBacklogFailedTransfers"], 0);
    assert_eq!(body["pendingRebalanceBacklogMaxAttempts"], 0);
    assert_eq!(body["pendingRebalanceReplayCyclesTotal"], 0);
    assert_eq!(body["pendingRebalanceReplayCyclesSucceeded"], 0);
    assert_eq!(body["pendingRebalanceReplayCyclesFailed"], 0);
    assert_eq!(body["pendingRebalanceReplayLastCycleUnixMs"], 0);
    assert_eq!(body["pendingRebalanceReplayLastSuccessUnixMs"], 0);
    assert_eq!(body["pendingRebalanceReplayLastFailureUnixMs"], 0);
    assert_eq!(body["pendingMembershipPropagationBacklogOperations"], 0);
    assert_eq!(body["pendingMembershipPropagationBacklogDueOperations"], 0);
    assert_eq!(
        body["pendingMembershipPropagationBacklogDueOperationsCapped"],
        false
    );
    assert_eq!(
        body["pendingMembershipPropagationBacklogFailedOperations"],
        0
    );
    assert_eq!(body["pendingMembershipPropagationBacklogMaxAttempts"], 0);
    assert_eq!(body["pendingMembershipPropagationReplayCyclesTotal"], 0);
    assert_eq!(body["pendingMembershipPropagationReplayCyclesSucceeded"], 0);
    assert_eq!(body["pendingMembershipPropagationReplayCyclesFailed"], 0);
    assert_eq!(body["pendingMembershipPropagationReplayLastCycleUnixMs"], 0);
    assert_eq!(
        body["pendingMembershipPropagationReplayLastSuccessUnixMs"],
        0
    );
    assert_eq!(
        body["pendingMembershipPropagationReplayLastFailureUnixMs"],
        0
    );
    assert_eq!(body["pendingMetadataRepairBacklogPlans"], 0);
    assert_eq!(body["pendingMetadataRepairBacklogDuePlans"], 0);
    assert_eq!(body["pendingMetadataRepairBacklogDuePlansCapped"], false);
    assert_eq!(body["pendingMetadataRepairBacklogFailedPlans"], 0);
    assert_eq!(body["pendingMetadataRepairBacklogMaxAttempts"], 0);
    assert_eq!(body["pendingMetadataRepairReplayCyclesTotal"], 0);
    assert_eq!(body["pendingMetadataRepairReplayCyclesSucceeded"], 0);
    assert_eq!(body["pendingMetadataRepairReplayCyclesFailed"], 0);
    assert_eq!(body["pendingMetadataRepairReplayLastCycleUnixMs"], 0);
    assert_eq!(body["pendingMetadataRepairReplayLastSuccessUnixMs"], 0);
    assert_eq!(body["pendingMetadataRepairReplayLastFailureUnixMs"], 0);
    assert_eq!(
        body["pendingReplicationBacklogOldestCreatedAtUnixMs"],
        serde_json::Value::Null
    );
    assert_eq!(
        body["pendingMembershipPropagationBacklogOldestCreatedAtUnixMs"],
        serde_json::Value::Null
    );
    assert_eq!(
        body["pendingRebalanceBacklogOldestCreatedAtUnixMs"],
        serde_json::Value::Null
    );
    assert_eq!(
        body["pendingMetadataRepairBacklogOldestCreatedAtUnixMs"],
        serde_json::Value::Null
    );
    assert_eq!(body["checks"]["dataDirAccessible"], true);
    assert_eq!(body["checks"]["dataDirWritable"], true);
    assert_eq!(body["checks"]["storageDataPathReadable"], true);
    assert_eq!(body["checks"]["diskHeadroomSufficient"], true);
    assert_eq!(body["checks"]["pendingReplicationQueueReadable"], true);
    assert_eq!(body["checks"]["pendingRebalanceQueueReadable"], true);
    assert_eq!(
        body["checks"]["pendingMembershipPropagationQueueReadable"],
        true
    );
    assert_eq!(body["checks"]["pendingMetadataRepairQueueReadable"], true);
    assert_eq!(body["checks"]["peerConnectivityReady"], true);
    assert_eq!(body["checks"]["clusterPeerAuthConfigured"], false);
    assert_eq!(body["checks"]["clusterPeerAuthIdentityBound"], false);
    assert_eq!(body["checks"]["clusterPeerAuthTransportRequired"], false);
    assert_eq!(body["checks"]["clusterPeerAuthSenderAllowlistBound"], false);
    assert_eq!(body["checks"]["clusterJoinAuthReady"], true);
    assert_eq!(body["checks"]["metadataListClusterAuthoritative"], false);
    assert_eq!(body["checks"]["metadataListReady"], true);
    assert_eq!(body["checks"]["membershipProtocolReady"], true);
    assert_eq!(body["warnings"], serde_json::json!([]));
}

#[tokio::test]
async fn test_healthz_reports_distributed_mode_when_cluster_peers_configured() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["127.0.0.1:1".to_string()];
    config.membership_protocol = MembershipProtocol::Gossip;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let resp = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["status"], "degraded");
    assert_eq!(body["mode"], "distributed");
    assert_eq!(body["clusterPeerCount"], 1);
    assert!(body["clusterId"].as_str().is_some_and(|v| !v.is_empty()));
    assert_eq!(body["clusterPeers"], serde_json::json!(["127.0.0.1:1"]));
    assert_eq!(body["membershipNodeCount"], 2);
    assert_eq!(body["clusterAuthMode"], "compatibility-no-token");
    assert_eq!(body["clusterAuthTrustModel"], "forwarded-by-marker-only");
    assert_eq!(body["clusterAuthTransportIdentity"], "none");
    assert_eq!(body["clusterJoinAuthMode"], "compatibility_no_token");
    assert_eq!(
        body["clusterJoinAuthReason"],
        "cluster_auth_token_not_configured"
    );
    assert_eq!(
        body["membershipNodes"],
        serde_json::json!(["127.0.0.1:1", "maxio-test-node"])
    );
    assert_eq!(body["membershipProtocol"], "gossip");
    assert_eq!(body["writeDurabilityMode"], "degraded-success");
    assert_eq!(body["metadataListingStrategy"], "local-node-only");
    assert_eq!(
        body["metadataListingGap"],
        "strategy-not-cluster-authoritative"
    );
    assert!(
        body["membershipViewId"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );
    assert_eq!(body["placementEpoch"], 0);
    assert_eq!(body["checks"]["dataDirAccessible"], true);
    assert_eq!(body["checks"]["dataDirWritable"], true);
    assert_eq!(body["checks"]["storageDataPathReadable"], true);
    assert_eq!(body["checks"]["diskHeadroomSufficient"], true);
    assert_eq!(body["checks"]["pendingReplicationQueueReadable"], true);
    assert_eq!(
        body["checks"]["pendingMembershipPropagationQueueReadable"],
        true
    );
    assert_eq!(body["checks"]["pendingMetadataRepairQueueReadable"], true);
    assert_eq!(body["checks"]["peerConnectivityReady"], false);
    assert_eq!(body["checks"]["clusterPeerAuthConfigured"], false);
    assert_eq!(body["checks"]["clusterPeerAuthIdentityBound"], false);
    assert_eq!(body["checks"]["clusterPeerAuthSenderAllowlistBound"], false);
    assert_eq!(body["checks"]["clusterJoinAuthReady"], false);
    assert_eq!(body["checks"]["metadataListClusterAuthoritative"], false);
    assert_eq!(body["checks"]["metadataListReady"], false);
    assert_eq!(body["checks"]["membershipProtocolReady"], true);
    assert!(
        body["warnings"]
            .as_array()
            .is_some_and(|warnings| !warnings.is_empty())
    );
}

#[tokio::test]
async fn test_healthz_and_metrics_report_shared_token_cluster_auth_mode_when_configured() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["127.0.0.1:1".to_string()];
    config.membership_protocol = MembershipProtocol::Gossip;
    config.cluster_auth_token = Some("shared-secret".to_string());
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    assert_eq!(health_body["clusterAuthMode"], "shared-token");
    assert_eq!(
        health_body["clusterAuthTrustModel"],
        "forwarded-by-marker+shared-token"
    );
    assert_eq!(health_body["clusterAuthTransportIdentity"], "none");
    assert_eq!(health_body["clusterJoinAuthMode"], "shared_token");
    assert_eq!(health_body["clusterJoinAuthReason"], "authorized");
    assert_eq!(health_body["writeDurabilityMode"], "degraded-success");
    assert_eq!(health_body["checks"]["clusterPeerAuthConfigured"], true);
    assert_eq!(health_body["checks"]["clusterPeerAuthIdentityBound"], false);
    assert_eq!(
        health_body["checks"]["clusterPeerAuthTransportRequired"],
        false
    );
    assert_eq!(
        health_body["checks"]["clusterPeerAuthTransportReady"],
        false
    );
    assert_eq!(
        health_body["checks"]["clusterPeerAuthSenderAllowlistBound"],
        true
    );
    assert_eq!(health_body["checks"]["clusterJoinAuthReady"], true);
    assert!(
        !health_body["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.iter().any(|warning| warning
                .as_str()
                .is_some_and(|msg| msg.contains("compatibility mode"))))
    );

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let metrics_body = metrics.text().await.unwrap();
    assert!(metrics_body.contains("maxio_cluster_peer_auth_mode_info{mode=\"shared-token\"} 1"));
    assert_eq!(
        metric_value(&metrics_body, "maxio_cluster_peer_auth_configured"),
        Some(1.0)
    );
    assert!(metrics_body.contains(
        "maxio_cluster_peer_auth_trust_model_info{model=\"forwarded-by-marker+shared-token\"} 1"
    ));
    assert_eq!(
        metric_value(&metrics_body, "maxio_cluster_peer_auth_identity_bound"),
        Some(0.0)
    );
    assert_eq!(
        metric_value(&metrics_body, "maxio_cluster_peer_auth_transport_required"),
        Some(0.0)
    );
    assert_eq!(
        metric_value(
            &metrics_body,
            "maxio_cluster_peer_auth_sender_allowlist_bound"
        ),
        Some(1.0)
    );
    assert!(metrics_body.contains("maxio_cluster_join_auth_mode_info{mode=\"shared_token\"} 1"));
    assert_eq!(
        metric_value(&metrics_body, "maxio_cluster_join_auth_ready"),
        Some(1.0)
    );
    assert!(
        metrics_body
            .contains("maxio_cluster_join_auth_readiness_reason_info{reason=\"authorized\"} 1")
    );
    assert!(metrics_body.contains("maxio_write_durability_mode_info{mode=\"degraded-success\"} 1"));
}

#[tokio::test]
async fn test_healthz_and_metrics_report_required_peer_transport_mode_when_configured() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["127.0.0.1:1".to_string()];
    config.membership_protocol = MembershipProtocol::Gossip;
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peer_transport_mode = ClusterPeerTransportMode::Required;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    assert_eq!(health_body["clusterAuthMode"], "shared-token");
    assert_eq!(health_body["clusterAuthTransportIdentity"], "none");
    assert_eq!(
        health_body["checks"]["clusterPeerAuthTransportRequired"],
        true
    );
    assert_eq!(
        health_body["checks"]["clusterPeerAuthTransportReady"],
        false
    );
    assert_eq!(health_body["checks"]["clusterJoinAuthReady"], false);
    assert_eq!(
        health_body["clusterJoinAuthReason"],
        "cluster_peer_transport_not_ready"
    );

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let metrics_body = metrics.text().await.unwrap();
    assert_eq!(
        metric_value(&metrics_body, "maxio_cluster_peer_auth_transport_required"),
        Some(1.0)
    );
    assert!(
        metrics_body
            .contains("maxio_cluster_join_auth_readiness_reason_info{reason=\"cluster_peer_transport_not_ready\"} 1")
    );
}

#[tokio::test]
async fn test_healthz_and_metrics_require_certificate_pin_for_mtls_node_id_binding() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let (cert_path, key_path, ca_path, _) = write_valid_mtls_identity_fixture(&tmp);

    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["127.0.0.1:1".to_string()];
    config.membership_protocol = MembershipProtocol::Gossip;
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peer_tls_cert_path = Some(cert_path.to_string_lossy().to_string());
    config.cluster_peer_tls_key_path = Some(key_path.to_string_lossy().to_string());
    config.cluster_peer_tls_ca_path = Some(ca_path.to_string_lossy().to_string());
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    assert_eq!(health_body["clusterAuthTransportIdentity"], "mtls-path");
    assert_eq!(
        health_body["clusterAuthTransportReason"],
        "node_identity_binding_pin_required"
    );
    assert_eq!(
        health_body["checks"]["clusterPeerAuthTransportReady"],
        false
    );
    assert_eq!(health_body["checks"]["clusterPeerAuthIdentityBound"], false);

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let metrics_body = metrics.text().await.unwrap();
    assert!(
        metrics_body
            .contains("maxio_cluster_peer_auth_transport_identity_info{identity=\"mtls-path\"} 1")
    );
    assert_eq!(
        metric_value(&metrics_body, "maxio_cluster_peer_auth_transport_ready"),
        Some(0.0)
    );
    assert!(metrics_body.contains(
        "maxio_cluster_peer_auth_transport_reason_info{reason=\"node_identity_binding_pin_required\"} 1"
    ));
}

#[tokio::test]
async fn test_healthz_and_metrics_report_mtls_transport_ready_when_pin_matches() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let (cert_path, key_path, ca_path, cert_sha256_pin) = write_valid_mtls_identity_fixture(&tmp);

    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["127.0.0.1:1".to_string()];
    config.membership_protocol = MembershipProtocol::Gossip;
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peer_tls_cert_path = Some(cert_path.to_string_lossy().to_string());
    config.cluster_peer_tls_key_path = Some(key_path.to_string_lossy().to_string());
    config.cluster_peer_tls_ca_path = Some(ca_path.to_string_lossy().to_string());
    config.cluster_peer_tls_cert_sha256 = Some(cert_sha256_pin);
    config.node_id = "maxio-peer:9000".to_string();
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    assert_eq!(health_body["clusterAuthTransportIdentity"], "mtls-path");
    assert_eq!(health_body["clusterAuthTransportReason"], "ready");
    assert_eq!(health_body["checks"]["clusterPeerAuthTransportReady"], true);
    assert_eq!(health_body["checks"]["clusterPeerAuthIdentityBound"], false);

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let metrics_body = metrics.text().await.unwrap();
    assert!(
        metrics_body
            .contains("maxio_cluster_peer_auth_transport_identity_info{identity=\"mtls-path\"} 1")
    );
    assert_eq!(
        metric_value(&metrics_body, "maxio_cluster_peer_auth_transport_ready"),
        Some(1.0)
    );
    assert!(
        metrics_body.contains("maxio_cluster_peer_auth_transport_reason_info{reason=\"ready\"} 1")
    );
}

#[tokio::test]
async fn test_healthz_and_metrics_report_mtls_transport_unready_when_node_identity_mismatches_certificate()
 {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let (cert_path, key_path, ca_path, cert_sha256_pin) = write_valid_mtls_identity_fixture(&tmp);

    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["127.0.0.1:1".to_string()];
    config.membership_protocol = MembershipProtocol::Gossip;
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peer_tls_cert_path = Some(cert_path.to_string_lossy().to_string());
    config.cluster_peer_tls_key_path = Some(key_path.to_string_lossy().to_string());
    config.cluster_peer_tls_ca_path = Some(ca_path.to_string_lossy().to_string());
    config.cluster_peer_tls_cert_sha256 = Some(cert_sha256_pin);
    config.node_id = "node-a.internal:9000".to_string();
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    assert_eq!(health_body["clusterAuthTransportIdentity"], "mtls-path");
    assert_eq!(
        health_body["clusterAuthTransportReason"],
        "node_identity_certificate_mismatch"
    );
    assert_eq!(
        health_body["checks"]["clusterPeerAuthTransportReady"],
        false
    );

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let metrics_body = metrics.text().await.unwrap();
    assert_eq!(
        metric_value(&metrics_body, "maxio_cluster_peer_auth_transport_ready"),
        Some(0.0)
    );
    assert!(metrics_body.contains(
        "maxio_cluster_peer_auth_transport_reason_info{reason=\"node_identity_certificate_mismatch\"} 1"
    ));
}

#[tokio::test]
async fn test_healthz_and_metrics_report_mtls_transport_pin_mismatch_as_unready() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let (cert_path, key_path, ca_path, _) = write_valid_mtls_identity_fixture(&tmp);

    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["127.0.0.1:1".to_string()];
    config.membership_protocol = MembershipProtocol::Gossip;
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peer_tls_cert_path = Some(cert_path.to_string_lossy().to_string());
    config.cluster_peer_tls_key_path = Some(key_path.to_string_lossy().to_string());
    config.cluster_peer_tls_ca_path = Some(ca_path.to_string_lossy().to_string());
    config.cluster_peer_tls_cert_sha256 =
        Some("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string());
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    assert_eq!(health_body["clusterAuthTransportIdentity"], "mtls-path");
    assert_eq!(
        health_body["clusterAuthTransportReason"],
        "certificate_fingerprint_pin_mismatch"
    );
    assert_eq!(
        health_body["checks"]["clusterPeerAuthTransportReady"],
        false
    );

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let metrics_body = metrics.text().await.unwrap();
    assert_eq!(
        metric_value(&metrics_body, "maxio_cluster_peer_auth_transport_ready"),
        Some(0.0)
    );
    assert!(metrics_body.contains(
        "maxio_cluster_peer_auth_transport_reason_info{reason=\"certificate_fingerprint_pin_mismatch\"} 1"
    ));
}

#[tokio::test]
async fn test_healthz_and_metrics_report_mtls_transport_revoked_certificate_as_unready() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let (cert_path, key_path, ca_path, cert_sha256_pin) = write_valid_mtls_identity_fixture(&tmp);

    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["127.0.0.1:1".to_string()];
    config.membership_protocol = MembershipProtocol::Gossip;
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peer_tls_cert_path = Some(cert_path.to_string_lossy().to_string());
    config.cluster_peer_tls_key_path = Some(key_path.to_string_lossy().to_string());
    config.cluster_peer_tls_ca_path = Some(ca_path.to_string_lossy().to_string());
    config.cluster_peer_tls_cert_sha256 = Some(cert_sha256_pin.clone());
    config.cluster_peer_tls_cert_sha256_revocations = Some(cert_sha256_pin);
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    assert_eq!(health_body["clusterAuthTransportIdentity"], "mtls-path");
    assert_eq!(
        health_body["clusterAuthTransportReason"],
        "certificate_fingerprint_revoked"
    );
    assert_eq!(
        health_body["checks"]["clusterPeerAuthTransportReady"],
        false
    );

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let metrics_body = metrics.text().await.unwrap();
    assert_eq!(
        metric_value(&metrics_body, "maxio_cluster_peer_auth_transport_ready"),
        Some(0.0)
    );
    assert!(metrics_body.contains(
        "maxio_cluster_peer_auth_transport_reason_info{reason=\"certificate_fingerprint_revoked\"} 1"
    ));
}

#[tokio::test]
async fn test_cluster_join_authorize_endpoint_accepts_and_rejects_nonce_replay() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    let cluster_id = health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present");

    let request_url = format!("{}/internal/cluster/join/authorize", base_url);
    let request_timestamp = unix_ms_now_string();
    let request_nonce = "join-probe-1";

    let accepted = client()
        .post(request_url.clone())
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "peer-node-a")
        .header("x-maxio-join-unix-ms", request_timestamp.as_str())
        .header("x-maxio-join-nonce", request_nonce)
        .header("x-maxio-internal-auth-token", "shared-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(accepted.status(), 200);
    let accepted_body: serde_json::Value = accepted.json().await.unwrap();
    assert_eq!(accepted_body["authorized"], true);
    assert_eq!(accepted_body["status"], "authorized");
    assert_eq!(accepted_body["mode"], "shared_token");
    assert_eq!(accepted_body["reason"], "authorized");
    assert_eq!(accepted_body["peerNodeId"], "peer-node-a");
    assert_eq!(accepted_body["clusterId"], cluster_id);

    let replayed = client()
        .post(request_url)
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "peer-node-a")
        .header("x-maxio-join-unix-ms", request_timestamp.as_str())
        .header("x-maxio-join-nonce", request_nonce)
        .header("x-maxio-internal-auth-token", "shared-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(replayed.status(), 403);
    let replayed_body: serde_json::Value = replayed.json().await.unwrap();
    assert_eq!(replayed_body["authorized"], false);
    assert_eq!(replayed_body["status"], "rejected");
    assert_eq!(replayed_body["reason"], "join_nonce_replay_detected");

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let metrics_body = metrics.text().await.unwrap();
    assert_eq!(
        metric_value(&metrics_body, "maxio_cluster_join_authorize_requests_total"),
        Some(2.0)
    );
    assert_eq!(
        metric_labeled_value(
            &metrics_body,
            "maxio_cluster_join_authorize_status_total{status=\"authorized\"}"
        ),
        Some(1.0)
    );
    assert_eq!(
        metric_labeled_value(
            &metrics_body,
            "maxio_cluster_join_authorize_status_total{status=\"rejected\"}"
        ),
        Some(1.0)
    );
    assert_eq!(
        metric_labeled_value(
            &metrics_body,
            "maxio_cluster_join_authorize_reason_total{reason=\"authorized\"}"
        ),
        Some(1.0)
    );
    assert_eq!(
        metric_labeled_value(
            &metrics_body,
            "maxio_cluster_join_authorize_reason_total{reason=\"join_nonce_replay_detected\"}"
        ),
        Some(1.0)
    );
}

#[tokio::test]
async fn test_cluster_join_authorize_endpoint_persists_nonce_replay_guard_across_restart() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir.clone(), false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    let (base_url, tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    let cluster_id = health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present");

    let request_timestamp = unix_ms_now_string();
    let request_nonce = "join-probe-persisted";
    let accepted = client()
        .post(format!("{}/internal/cluster/join/authorize", base_url))
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "peer-node-a")
        .header("x-maxio-join-unix-ms", request_timestamp.as_str())
        .header("x-maxio-join-nonce", request_nonce)
        .header("x-maxio-internal-auth-token", "shared-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(accepted.status(), 200);

    let mut restarted_config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    restarted_config.cluster_auth_token = Some("shared-secret".to_string());
    restarted_config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    let (restarted_base_url, _tmp) = start_server_with_config(restarted_config, tmp).await;

    let replayed = client()
        .post(format!(
            "{}/internal/cluster/join/authorize",
            restarted_base_url
        ))
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "peer-node-a")
        .header("x-maxio-join-unix-ms", request_timestamp.as_str())
        .header("x-maxio-join-nonce", request_nonce)
        .header("x-maxio-internal-auth-token", "shared-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(replayed.status(), 403);
    let replayed_body: serde_json::Value = replayed.json().await.unwrap();
    assert_eq!(replayed_body["authorized"], false);
    assert_eq!(replayed_body["status"], "rejected");
    assert_eq!(replayed_body["reason"], "join_nonce_replay_detected");
}

#[tokio::test]
async fn test_cluster_join_authorize_endpoint_rejects_missing_auth_token_in_shared_mode() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    let cluster_id = health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present");

    let rejected = client()
        .post(format!("{}/internal/cluster/join/authorize", base_url))
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "peer-node-b")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header("x-maxio-join-nonce", "join-probe-2")
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 403);
    let rejected_body: serde_json::Value = rejected.json().await.unwrap();
    assert_eq!(rejected_body["authorized"], false);
    assert_eq!(rejected_body["status"], "rejected");
    assert_eq!(rejected_body["mode"], "shared_token");
    assert_eq!(rejected_body["reason"], "missing_or_malformed_auth_token");

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let metrics_body = metrics.text().await.unwrap();
    assert_eq!(
        metric_labeled_value(
            &metrics_body,
            "maxio_cluster_join_authorize_reason_total{reason=\"missing_or_malformed_auth_token\"}"
        ),
        Some(1.0)
    );
}

#[tokio::test]
async fn test_cluster_join_authorize_endpoint_rejects_invalid_peer_node_identity() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    let cluster_id = health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present");

    let rejected = client()
        .post(format!("{}/internal/cluster/join/authorize", base_url))
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "peer/node-b")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header("x-maxio-join-nonce", "join-probe-invalid-node")
        .header("x-maxio-internal-auth-token", "shared-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 403);
    let rejected_body: serde_json::Value = rejected.json().await.unwrap();
    assert_eq!(rejected_body["authorized"], false);
    assert_eq!(rejected_body["status"], "rejected");
    assert_eq!(rejected_body["mode"], "shared_token");
    assert_eq!(rejected_body["reason"], "invalid_node_identity");

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let metrics_body = metrics.text().await.unwrap();
    assert_eq!(
        metric_labeled_value(
            &metrics_body,
            "maxio_cluster_join_authorize_reason_total{reason=\"invalid_node_identity\"}"
        ),
        Some(1.0)
    );
}

#[tokio::test]
async fn test_cluster_join_authorize_endpoint_returns_service_unavailable_for_invalid_local_node_identity_configuration()
 {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = "node/invalid".to_string();
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    let cluster_id = health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present");

    let rejected = client()
        .post(format!("{}/internal/cluster/join/authorize", base_url))
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "peer-node-b")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header("x-maxio-join-nonce", "join-probe-invalid-config")
        .header("x-maxio-internal-auth-token", "shared-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 503);
    let rejected_body: serde_json::Value = rejected.json().await.unwrap();
    assert_eq!(rejected_body["authorized"], false);
    assert_eq!(rejected_body["status"], "misconfigured");
    assert_eq!(rejected_body["mode"], "shared_token");
    assert_eq!(rejected_body["reason"], "invalid_configuration");

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let metrics_body = metrics.text().await.unwrap();
    assert_eq!(
        metric_labeled_value(
            &metrics_body,
            "maxio_cluster_join_authorize_reason_total{reason=\"invalid_configuration\"}"
        ),
        Some(1.0)
    );
}

#[tokio::test]
async fn test_cluster_join_authorize_endpoint_returns_service_unavailable_when_not_distributed() {
    let (base_url, _tmp) = start_server().await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    let cluster_id = health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present");

    let rejected = client()
        .post(format!("{}/internal/cluster/join/authorize", base_url))
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "peer-node-standalone")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header("x-maxio-join-nonce", "join-probe-standalone")
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 503);
    let rejected_body: serde_json::Value = rejected.json().await.unwrap();
    assert_eq!(rejected_body["authorized"], false);
    assert_eq!(rejected_body["status"], "misconfigured");
    assert_eq!(rejected_body["mode"], "compatibility_no_token");
    assert_eq!(rejected_body["reason"], "distributed_mode_disabled");

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let metrics_body = metrics.text().await.unwrap();
    assert_eq!(
        metric_labeled_value(
            &metrics_body,
            "maxio_cluster_join_authorize_reason_total{reason=\"distributed_mode_disabled\"}"
        ),
        Some(1.0)
    );
}

#[tokio::test]
async fn test_cluster_join_authorize_endpoint_returns_service_unavailable_when_membership_engine_not_ready()
 {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["127.0.0.1:1".to_string()];
    config.membership_protocol = MembershipProtocol::Gossip;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    let cluster_id = health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present");

    let rejected = client()
        .post(format!("{}/internal/cluster/join/authorize", base_url))
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "peer-node-gossip")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header("x-maxio-join-nonce", "join-probe-gossip")
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 503);
    let rejected_body: serde_json::Value = rejected.json().await.unwrap();
    assert_eq!(rejected_body["authorized"], false);
    assert_eq!(rejected_body["status"], "misconfigured");
    assert_eq!(rejected_body["mode"], "compatibility_no_token");
    assert_eq!(rejected_body["reason"], "cluster_auth_token_not_configured");

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let metrics_body = metrics.text().await.unwrap();
    assert_eq!(
        metric_labeled_value(
            &metrics_body,
            "maxio_cluster_join_authorize_reason_total{reason=\"cluster_auth_token_not_configured\"}"
        ),
        Some(1.0)
    );
}

#[tokio::test]
async fn test_cluster_join_authorize_endpoint_returns_service_unavailable_when_cluster_auth_token_not_configured_in_distributed_mode()
 {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["127.0.0.1:30401".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    let cluster_id = health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present");
    assert_eq!(health_body["checks"]["clusterJoinAuthReady"], false);
    assert_eq!(
        health_body["clusterJoinAuthReason"],
        "cluster_auth_token_not_configured"
    );

    let rejected = client()
        .post(format!("{}/internal/cluster/join/authorize", base_url))
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "peer-node-static-bootstrap")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header("x-maxio-join-nonce", "join-probe-no-shared-token")
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 503);
    let rejected_body: serde_json::Value = rejected.json().await.unwrap();
    assert_eq!(rejected_body["authorized"], false);
    assert_eq!(rejected_body["status"], "misconfigured");
    assert_eq!(rejected_body["mode"], "compatibility_no_token");
    assert_eq!(rejected_body["reason"], "cluster_auth_token_not_configured");

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let metrics_body = metrics.text().await.unwrap();
    assert_eq!(
        metric_labeled_value(
            &metrics_body,
            "maxio_cluster_join_authorize_reason_total{reason=\"cluster_auth_token_not_configured\"}"
        ),
        Some(1.0)
    );
}

#[tokio::test]
async fn test_cluster_join_authorize_endpoint_returns_service_unavailable_when_cluster_peer_transport_mtls_not_ready()
 {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["127.0.0.1:30431".to_string()];
    config.cluster_peer_tls_cert_path = Some("/tmp/maxio-missing-cert.pem".to_string());
    config.cluster_peer_tls_key_path = Some("/tmp/maxio-missing-key.pem".to_string());
    config.cluster_peer_tls_ca_path = Some("/tmp/maxio-missing-ca.pem".to_string());
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    let cluster_id = health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present");

    let rejected = client()
        .post(format!("{}/internal/cluster/join/authorize", base_url))
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "peer-node-static-bootstrap")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header("x-maxio-join-nonce", "join-probe-transport-not-ready")
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 503);
    let rejected_body: serde_json::Value = rejected.json().await.unwrap();
    assert_eq!(rejected_body["authorized"], false);
    assert_eq!(rejected_body["status"], "misconfigured");
    assert_eq!(rejected_body["mode"], "shared_token");
    assert_eq!(rejected_body["reason"], "cluster_peer_transport_not_ready");
}

#[tokio::test]
async fn test_cluster_join_authorize_endpoint_returns_service_unavailable_when_cluster_peer_transport_required_without_mtls()
 {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["127.0.0.1:30432".to_string()];
    config.cluster_peer_transport_mode = ClusterPeerTransportMode::Required;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    let cluster_id = health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present");

    let rejected = client()
        .post(format!("{}/internal/cluster/join/authorize", base_url))
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "peer-node-static-bootstrap")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header("x-maxio-join-nonce", "join-probe-required-transport")
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 503);
    let rejected_body: serde_json::Value = rejected.json().await.unwrap();
    assert_eq!(rejected_body["authorized"], false);
    assert_eq!(rejected_body["status"], "misconfigured");
    assert_eq!(rejected_body["mode"], "shared_token");
    assert_eq!(rejected_body["reason"], "cluster_peer_transport_not_ready");
}

#[tokio::test]
async fn test_cluster_join_endpoint_applies_membership_for_authorized_peer() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["127.0.0.1:30501".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let initial_health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(initial_health.status(), 200);
    let initial_health_body: serde_json::Value = initial_health.json().await.unwrap();
    let cluster_id = initial_health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present")
        .to_string();
    let initial_view_id = initial_health_body["membershipViewId"]
        .as_str()
        .expect("membershipViewId should be present")
        .to_string();
    let initial_epoch = initial_health_body["placementEpoch"]
        .as_u64()
        .expect("placementEpoch should be present");

    let joined = client()
        .post(format!("{}/internal/cluster/join", base_url))
        .header("x-maxio-join-cluster-id", cluster_id.as_str())
        .header("x-maxio-join-node-id", "127.0.0.1:30502")
        .header("x-maxio-forwarded-by", "127.0.0.1:30501")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header("x-maxio-join-nonce", "join-apply-membership")
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({
            "expectedMembershipViewId": initial_view_id,
            "expectedPlacementEpoch": initial_epoch
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(joined.status(), 200);
    let joined_body: serde_json::Value = joined.json().await.unwrap();
    assert_eq!(joined_body["status"], "applied");
    assert_eq!(joined_body["reason"], "applied");
    assert_eq!(joined_body["mode"], "shared_token_allowlist");
    assert_eq!(joined_body["updated"], true);
    assert_eq!(joined_body["clusterId"], cluster_id);
    assert!(
        joined_body["clusterPeers"]
            .as_array()
            .is_some_and(|peers| peers.iter().any(|peer| peer == "127.0.0.1:30502"))
    );

    let updated_health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(updated_health.status(), 200);
    let updated_health_body: serde_json::Value = updated_health.json().await.unwrap();
    assert_eq!(updated_health_body["clusterPeerCount"], 2);
    assert_eq!(updated_health_body["membershipNodeCount"], 3);
    assert_ne!(updated_health_body["membershipViewId"], initial_view_id);
    assert!(
        updated_health_body["placementEpoch"]
            .as_u64()
            .is_some_and(|epoch| epoch > initial_epoch)
    );
}

#[tokio::test]
async fn test_cluster_join_endpoint_is_idempotent_for_existing_peer() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["127.0.0.1:30511".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let initial_health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(initial_health.status(), 200);
    let initial_health_body: serde_json::Value = initial_health.json().await.unwrap();
    let cluster_id = initial_health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present")
        .to_string();
    let initial_view_id = initial_health_body["membershipViewId"]
        .as_str()
        .expect("membershipViewId should be present")
        .to_string();
    let initial_epoch = initial_health_body["placementEpoch"]
        .as_u64()
        .expect("placementEpoch should be present");

    let joined = client()
        .post(format!("{}/internal/cluster/join", base_url))
        .header("x-maxio-join-cluster-id", cluster_id.as_str())
        .header("x-maxio-join-node-id", "127.0.0.1:30511")
        .header("x-maxio-forwarded-by", "127.0.0.1:30511")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header("x-maxio-join-nonce", "join-apply-existing-peer")
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({
            "expectedMembershipViewId": initial_view_id,
            "expectedPlacementEpoch": initial_epoch
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(joined.status(), 200);
    let joined_body: serde_json::Value = joined.json().await.unwrap();
    assert_eq!(joined_body["status"], "applied");
    assert_eq!(joined_body["reason"], "applied");
    assert_eq!(joined_body["updated"], false);
    assert_eq!(joined_body["membershipViewId"], initial_view_id);
    assert_eq!(joined_body["placementEpoch"], initial_epoch);
    assert_eq!(joined_body["clusterPeers"], json!(["127.0.0.1:30511"]));
}

#[tokio::test]
async fn test_cluster_join_endpoint_rejects_stale_precondition() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["127.0.0.1:30521".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let initial_health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(initial_health.status(), 200);
    let initial_health_body: serde_json::Value = initial_health.json().await.unwrap();
    let cluster_id = initial_health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present")
        .to_string();
    let initial_epoch = initial_health_body["placementEpoch"]
        .as_u64()
        .expect("placementEpoch should be present");

    let rejected = client()
        .post(format!("{}/internal/cluster/join", base_url))
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "127.0.0.1:30522")
        .header("x-maxio-forwarded-by", "127.0.0.1:30521")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header("x-maxio-join-nonce", "join-apply-stale-precondition")
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({
            "expectedMembershipViewId": "stale-membership-view-id",
            "expectedPlacementEpoch": initial_epoch
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 409);
    let rejected_body: serde_json::Value = rejected.json().await.unwrap();
    assert_eq!(rejected_body["status"], "rejected");
    assert_eq!(rejected_body["reason"], "precondition_failed");
    assert_eq!(rejected_body["updated"], false);
}

#[tokio::test]
async fn test_cluster_join_endpoint_rejects_propagated_request_without_preconditions() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["127.0.0.1:30526".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let initial_health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(initial_health.status(), 200);
    let initial_health_body: serde_json::Value = initial_health.json().await.unwrap();
    let cluster_id = initial_health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present")
        .to_string();

    let rejected = client()
        .post(format!("{}/internal/cluster/join", base_url))
        .header("x-maxio-join-cluster-id", cluster_id.as_str())
        .header("x-maxio-join-node-id", "127.0.0.1:30526")
        .header("x-maxio-forwarded-by", "127.0.0.1:30526")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header("x-maxio-join-nonce", "join-apply-propagated-missing-preconditions")
        .header("x-maxio-internal-auth-token", "shared-secret")
        .header("x-maxio-internal-membership-propagated", "1")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 409);
    let rejected_body: serde_json::Value = rejected.json().await.unwrap();
    assert_eq!(rejected_body["status"], "rejected");
    assert_eq!(rejected_body["reason"], "precondition_failed");
    assert_eq!(rejected_body["updated"], false);
}

#[tokio::test]
async fn test_cluster_join_endpoint_rejects_forwarded_sender_not_in_allowlist() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["127.0.0.1:30541".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let initial_health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(initial_health.status(), 200);
    let initial_health_body: serde_json::Value = initial_health.json().await.unwrap();
    let cluster_id = initial_health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present")
        .to_string();

    let rejected = client()
        .post(format!("{}/internal/cluster/join", base_url))
        .header("x-maxio-join-cluster-id", cluster_id.as_str())
        .header("x-maxio-join-node-id", "127.0.0.1:30599")
        .header("x-maxio-forwarded-by", "127.0.0.1:30599")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header(
            "x-maxio-join-nonce",
            "join-apply-forwarded-sender-not-in-allowlist",
        )
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 403);
    let rejected_body: serde_json::Value = rejected.json().await.unwrap();
    assert_eq!(rejected_body["status"], "rejected");
    assert_eq!(rejected_body["reason"], "unauthorized");
    assert_eq!(rejected_body["authReason"], "sender_not_in_allowlist");
    assert_eq!(rejected_body["updated"], false);
}

#[tokio::test]
async fn test_cluster_join_endpoint_rejects_known_sender_with_token_mismatch() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["127.0.0.1:30561".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let initial_health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(initial_health.status(), 200);
    let initial_health_body: serde_json::Value = initial_health.json().await.unwrap();
    let cluster_id = initial_health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present")
        .to_string();

    let rejected = client()
        .post(format!("{}/internal/cluster/join", base_url))
        .header("x-maxio-join-cluster-id", cluster_id.as_str())
        .header("x-maxio-join-node-id", "127.0.0.1:30561")
        .header("x-maxio-forwarded-by", "127.0.0.1:30561")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header(
            "x-maxio-join-nonce",
            "join-apply-known-sender-token-mismatch",
        )
        .header("x-maxio-internal-auth-token", "wrong-shared-secret")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 403);
    let rejected_body: serde_json::Value = rejected.json().await.unwrap();
    assert_eq!(rejected_body["status"], "rejected");
    assert_eq!(rejected_body["reason"], "unauthorized");
    assert_eq!(rejected_body["authReason"], "auth_token_mismatch");
    assert_eq!(rejected_body["updated"], false);
}

#[tokio::test]
async fn test_cluster_join_endpoint_rejects_forwarded_sender_node_id_mismatch() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["127.0.0.1:30571".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let initial_health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(initial_health.status(), 200);
    let initial_health_body: serde_json::Value = initial_health.json().await.unwrap();
    let cluster_id = initial_health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present")
        .to_string();

    let rejected = client()
        .post(format!("{}/internal/cluster/join", base_url))
        .header("x-maxio-join-cluster-id", cluster_id.as_str())
        .header("x-maxio-join-node-id", "127.0.0.1:30572")
        .header("x-maxio-forwarded-by", "127.0.0.1:30571")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header(
            "x-maxio-join-nonce",
            "join-apply-forwarded-node-id-mismatch",
        )
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 403);
    let rejected_body: serde_json::Value = rejected.json().await.unwrap();
    assert_eq!(rejected_body["status"], "rejected");
    assert_eq!(rejected_body["reason"], "unauthorized");
    assert_eq!(rejected_body["authReason"], "forwarded_by_node_id_mismatch");
    assert_eq!(rejected_body["updated"], false);
}

#[tokio::test]
async fn test_cluster_join_endpoint_rejects_multi_hop_forwarded_origin_spoofing() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["127.0.0.1:30581".to_string(), "127.0.0.1:30582".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let initial_health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(initial_health.status(), 200);
    let initial_health_body: serde_json::Value = initial_health.json().await.unwrap();
    let cluster_id = initial_health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present")
        .to_string();

    let rejected = client()
        .post(format!("{}/internal/cluster/join", base_url))
        .header("x-maxio-join-cluster-id", cluster_id.as_str())
        .header("x-maxio-join-node-id", "127.0.0.1:30581")
        .header("x-maxio-forwarded-by", "127.0.0.1:30581,127.0.0.1:30582")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header(
            "x-maxio-join-nonce",
            "join-apply-forwarded-origin-spoofed-by-multihop",
        )
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 403);
    let rejected_body: serde_json::Value = rejected.json().await.unwrap();
    assert_eq!(rejected_body["status"], "rejected");
    assert_eq!(rejected_body["reason"], "unauthorized");
    assert_eq!(rejected_body["authReason"], "forwarded_by_node_id_mismatch");
    assert_eq!(rejected_body["updated"], false);
}

#[tokio::test]
async fn test_cluster_join_endpoint_metrics_track_status_and_reason_labels() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["127.0.0.1:30531".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let initial_health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(initial_health.status(), 200);
    let initial_health_body: serde_json::Value = initial_health.json().await.unwrap();
    let cluster_id = initial_health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present")
        .to_string();
    let initial_view_id = initial_health_body["membershipViewId"]
        .as_str()
        .expect("membershipViewId should be present")
        .to_string();
    let initial_epoch = initial_health_body["placementEpoch"]
        .as_u64()
        .expect("placementEpoch should be present");

    let applied = client()
        .post(format!("{}/internal/cluster/join", base_url))
        .header("x-maxio-join-cluster-id", cluster_id.as_str())
        .header("x-maxio-join-node-id", "127.0.0.1:30532")
        .header("x-maxio-forwarded-by", "127.0.0.1:30531")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header("x-maxio-join-nonce", "join-apply-metrics-applied")
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({
            "expectedMembershipViewId": initial_view_id,
            "expectedPlacementEpoch": initial_epoch
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(applied.status(), 200);

    let unauthorized = client()
        .post(format!("{}/internal/cluster/join", base_url))
        .header("x-maxio-join-cluster-id", cluster_id.as_str())
        .header("x-maxio-join-node-id", "127.0.0.1:30533")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header("x-maxio-join-nonce", "join-apply-metrics-unauthorized")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), 403);

    let invalid_payload = client()
        .post(format!("{}/internal/cluster/join", base_url))
        .header("x-maxio-join-cluster-id", cluster_id.as_str())
        .header("x-maxio-join-node-id", "127.0.0.1:30534")
        .header("x-maxio-forwarded-by", "127.0.0.1:30531")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header("x-maxio-join-nonce", "join-apply-metrics-invalid-payload")
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({ "expectedMembershipViewId": "   " }))
        .send()
        .await
        .unwrap();
    assert_eq!(invalid_payload.status(), 400);

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let metrics_body = metrics.text().await.unwrap();

    assert_eq!(
        metric_value(&metrics_body, "maxio_cluster_join_requests_total"),
        Some(3.0)
    );
    assert_eq!(
        metric_labeled_value(
            &metrics_body,
            "maxio_cluster_join_status_total{status=\"applied\"}"
        ),
        Some(1.0)
    );
    assert_eq!(
        metric_labeled_value(
            &metrics_body,
            "maxio_cluster_join_status_total{status=\"rejected\"}"
        ),
        Some(2.0)
    );
    assert_eq!(
        metric_labeled_value(
            &metrics_body,
            "maxio_cluster_join_reason_total{reason=\"applied\"}"
        ),
        Some(1.0)
    );
    assert_eq!(
        metric_labeled_value(
            &metrics_body,
            "maxio_cluster_join_reason_total{reason=\"unauthorized\"}"
        ),
        Some(1.0)
    );
    assert_eq!(
        metric_labeled_value(
            &metrics_body,
            "maxio_cluster_join_reason_total{reason=\"invalid_payload\"}"
        ),
        Some(1.0)
    );
}

#[tokio::test]
async fn test_cluster_membership_update_endpoint_applies_live_view_and_epoch() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["127.0.0.1:30101".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let initial_health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(initial_health.status(), 200);
    let initial_health_body: serde_json::Value = initial_health.json().await.unwrap();
    let cluster_id = initial_health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present")
        .to_string();
    let initial_view_id = initial_health_body["membershipViewId"]
        .as_str()
        .expect("membershipViewId should be present")
        .to_string();
    let initial_epoch = initial_health_body["placementEpoch"]
        .as_u64()
        .expect("placementEpoch should be present");

    let updated_peers = vec!["127.0.0.1:30102".to_string(), "127.0.0.1:30103".to_string()];
    let update = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .header("x-maxio-join-cluster-id", cluster_id.as_str())
        .header("x-maxio-join-node-id", "peer-node-membership-update")
        .header("x-maxio-forwarded-by", "127.0.0.1:30101")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header("x-maxio-join-nonce", "membership-update-1")
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": updated_peers,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(update.status(), 200);
    let update_body: serde_json::Value = update.json().await.unwrap();
    assert_eq!(update_body["status"], "applied");
    assert_eq!(update_body["reason"], "applied");
    assert_eq!(update_body["updated"], true);

    let expected_view_id = membership_view_id_with_self(
        "maxio-test-node",
        &["127.0.0.1:30102".to_string(), "127.0.0.1:30103".to_string()],
    );
    assert_eq!(update_body["membershipViewId"], expected_view_id);
    assert_eq!(update_body["placementEpoch"], initial_epoch + 1);

    let updated_health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(updated_health.status(), 200);
    let updated_health_body: serde_json::Value = updated_health.json().await.unwrap();
    assert_ne!(updated_health_body["membershipViewId"], initial_view_id);
    assert_eq!(updated_health_body["membershipViewId"], expected_view_id);
    assert_eq!(updated_health_body["placementEpoch"], initial_epoch + 1);
    assert_eq!(updated_health_body["clusterPeerCount"], 2);
    let updated_cluster_peers = updated_health_body["clusterPeers"]
        .as_array()
        .expect("clusterPeers should be array")
        .iter()
        .filter_map(|value| value.as_str().map(str::to_string))
        .collect::<Vec<_>>();
    assert_eq!(
        updated_cluster_peers,
        vec!["127.0.0.1:30102".to_string(), "127.0.0.1:30103".to_string()]
    );
}

#[tokio::test]
async fn test_cluster_membership_update_endpoint_propagates_updates_to_peer_control_plane() {
    let (capture_peer, capture_state) = start_membership_propagation_capture_stub().await;

    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = "node-a.internal:9000".to_string();
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let initial_health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(initial_health.status(), 200);
    let initial_health_body: serde_json::Value = initial_health.json().await.unwrap();
    let cluster_id = initial_health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present")
        .to_string();
    let initial_view_id = initial_health_body["membershipViewId"]
        .as_str()
        .expect("membershipViewId should be present")
        .to_string();
    let initial_epoch = initial_health_body["placementEpoch"]
        .as_u64()
        .expect("placementEpoch should be present");

    let update = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .header("x-maxio-join-cluster-id", cluster_id.as_str())
        .header("x-maxio-join-node-id", "node-b.internal:9000")
        .header("x-maxio-forwarded-by", "node-b.internal:9000")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header("x-maxio-join-nonce", "membership-update-propagation")
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": [capture_peer.as_str()],
            "expectedMembershipViewId": initial_view_id,
            "expectedPlacementEpoch": initial_epoch,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(update.status(), 200);
    let update_body: serde_json::Value = update.json().await.unwrap();
    assert_eq!(update_body["status"], "applied");
    assert_eq!(update_body["reason"], "applied");
    assert_eq!(update_body["updated"], true);

    let mut propagated = None;
    for _ in 0..20 {
        {
            let records = capture_state.records.lock().await;
            if let Some(record) = records.first() {
                propagated = Some(record.clone());
            }
        }
        if propagated.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let propagated = propagated.expect("membership update should be propagated to peer endpoint");
    assert_eq!(propagated.propagation_header.as_deref(), Some("1"));
    assert_eq!(
        propagated.forwarded_by.as_deref(),
        Some("node-a.internal:9000")
    );
    assert_eq!(propagated.payload["clusterId"], cluster_id);
    assert_eq!(propagated.payload["clusterPeers"], json!([capture_peer]));
    assert_eq!(
        propagated.payload["expectedMembershipViewId"],
        serde_json::Value::String(initial_view_id)
    );
    assert_eq!(
        propagated.payload["expectedPlacementEpoch"],
        serde_json::Value::Number(initial_epoch.into())
    );
}

#[tokio::test]
async fn test_cluster_membership_update_endpoint_propagates_updates_to_removed_peers() {
    let (removed_peer, removed_peer_state) = start_membership_propagation_capture_stub().await;
    let (next_peer, next_peer_state) = start_membership_propagation_capture_stub().await;

    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = "node-a.internal:9000".to_string();
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec![removed_peer.clone()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let initial_health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(initial_health.status(), 200);
    let initial_health_body: serde_json::Value = initial_health.json().await.unwrap();
    let cluster_id = initial_health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present")
        .to_string();

    let update = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .header("x-maxio-join-cluster-id", cluster_id.as_str())
        .header("x-maxio-join-node-id", removed_peer.as_str())
        .header("x-maxio-forwarded-by", removed_peer.as_str())
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header(
            "x-maxio-join-nonce",
            "membership-update-propagation-removed-peer-fanout",
        )
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": [next_peer.as_str()],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(update.status(), 200);

    let mut removed_peer_propagated = false;
    let mut next_peer_propagated = false;
    for _ in 0..40 {
        {
            removed_peer_propagated = !removed_peer_state.records.lock().await.is_empty();
            next_peer_propagated = !next_peer_state.records.lock().await.is_empty();
        }
        if removed_peer_propagated && next_peer_propagated {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert!(
        removed_peer_propagated,
        "removed peer should receive membership update propagation"
    );
    assert!(
        next_peer_propagated,
        "next peer should receive membership update propagation"
    );

    let removed_records = removed_peer_state.records.lock().await;
    let next_records = next_peer_state.records.lock().await;
    assert_eq!(
        removed_records[0].propagation_header.as_deref(),
        Some("1"),
        "removed peer propagation should carry loop-guard marker"
    );
    assert_eq!(
        next_records[0].propagation_header.as_deref(),
        Some("1"),
        "next peer propagation should carry loop-guard marker"
    );
    assert_eq!(
        removed_records[0].payload["clusterPeers"],
        json!([next_peer]),
        "removed peer receives the post-update peer set"
    );
    assert_eq!(
        next_records[0].payload["clusterPeers"],
        json!([next_peer]),
        "next peer receives the post-update peer set"
    );
}

#[tokio::test]
async fn test_cluster_membership_update_endpoint_skips_fanout_for_propagated_requests() {
    let (capture_peer, capture_state) = start_membership_propagation_capture_stub().await;

    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = "node-a.internal:9000".to_string();
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let initial_health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(initial_health.status(), 200);
    let initial_health_body: serde_json::Value = initial_health.json().await.unwrap();
    let cluster_id = initial_health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present")
        .to_string();
    let initial_view_id = initial_health_body["membershipViewId"]
        .as_str()
        .expect("membershipViewId should be present")
        .to_string();
    let initial_epoch = initial_health_body["placementEpoch"]
        .as_u64()
        .expect("placementEpoch should be present");

    let update = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .header("x-maxio-join-cluster-id", cluster_id.as_str())
        .header("x-maxio-join-node-id", "node-b.internal:9000")
        .header("x-maxio-forwarded-by", "node-b.internal:9000")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header(
            "x-maxio-join-nonce",
            "membership-update-propagated-loop-guard",
        )
        .header("x-maxio-internal-auth-token", "shared-secret")
        .header("x-maxio-internal-membership-propagated", "1")
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": [capture_peer.as_str()],
            "expectedMembershipViewId": initial_view_id,
            "expectedPlacementEpoch": initial_epoch,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(update.status(), 200);
    let update_body: serde_json::Value = update.json().await.unwrap();
    assert_eq!(update_body["status"], "applied");
    assert_eq!(update_body["reason"], "applied");
    assert_eq!(update_body["updated"], true);

    tokio::time::sleep(Duration::from_millis(200)).await;
    let records = capture_state.records.lock().await;
    assert!(
        records.is_empty(),
        "propagated requests should not trigger secondary fanout"
    );
}

#[tokio::test]
async fn test_cluster_membership_update_endpoint_rejects_propagated_request_without_preconditions()
{
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = "node-a.internal:9000".to_string();
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let initial_health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(initial_health.status(), 200);
    let initial_health_body: serde_json::Value = initial_health.json().await.unwrap();
    let cluster_id = initial_health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present")
        .to_string();

    let update = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .header("x-maxio-join-cluster-id", cluster_id.as_str())
        .header("x-maxio-join-node-id", "node-b.internal:9000")
        .header("x-maxio-forwarded-by", "node-b.internal:9000")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header(
            "x-maxio-join-nonce",
            "membership-update-propagated-missing-preconditions",
        )
        .header("x-maxio-internal-auth-token", "shared-secret")
        .header("x-maxio-internal-membership-propagated", "1")
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": ["node-b.internal:9000"],
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(update.status(), 409);
    let update_body: serde_json::Value = update.json().await.unwrap();
    assert_eq!(update_body["status"], "rejected");
    assert_eq!(update_body["reason"], "precondition_failed");
    assert_eq!(update_body["updated"], false);
}

#[tokio::test]
async fn test_cluster_membership_update_endpoint_queues_rebalance_operations_for_local_objects() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let local_node_id = "node-a.internal:9000";
    let previous_membership_nodes = membership_with_self(
        local_node_id,
        &[
            "node-b.internal:9000".to_string(),
            "node-c.internal:9000".to_string(),
        ],
    );
    let next_membership_nodes = membership_with_self(
        local_node_id,
        &[
            "node-b.internal:9000".to_string(),
            "node-d.internal:9000".to_string(),
        ],
    );
    let moving_key = (0..2048)
        .map(|idx| format!("docs/rebalance-{idx}.txt"))
        .find(|key| {
            let plan =
                object_rebalance_plan(key, &previous_membership_nodes, &next_membership_nodes, 2);
            !local_rebalance_actions(&plan, local_node_id).is_empty()
        })
        .expect("expected at least one key to require local rebalance action");
    seed_object_in_data_dir(
        data_dir.as_str(),
        "rebalance-bucket",
        moving_key.as_str(),
        b"hello",
        false,
    )
    .await;
    let mut config = make_test_config(data_dir.clone(), false, 10 * 1024 * 1024, 0);
    config.node_id = local_node_id.to_string();
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec![
        "node-b.internal:9000".to_string(),
        "node-c.internal:9000".to_string(),
    ];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let initial_health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(initial_health.status(), 200);
    let initial_health_body: serde_json::Value = initial_health.json().await.unwrap();
    let cluster_id = initial_health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present")
        .to_string();

    let update = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .header("x-maxio-join-cluster-id", cluster_id.as_str())
        .header("x-maxio-join-node-id", "node-b.internal:9000")
        .header("x-maxio-forwarded-by", "node-b.internal:9000")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header("x-maxio-join-nonce", "membership-update-queue-rebalance")
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": ["node-b.internal:9000", "node-d.internal:9000"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(update.status(), 200);
    let update_body: serde_json::Value = update.json().await.unwrap();
    assert_eq!(update_body["status"], "applied");
    assert_eq!(update_body["updated"], true);

    let queue_path = Path::new(data_dir.as_str())
        .join(".maxio-runtime")
        .join("pending-rebalance-queue.json");
    let mut queued_payload = None;
    for _ in 0..40 {
        if let Some(value) = tokio::fs::read_to_string(queue_path.as_path())
            .await
            .ok()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        {
            let has_operations = value["operations"]
                .as_array()
                .is_some_and(|operations| !operations.is_empty());
            if has_operations {
                queued_payload = Some(value);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let queued_payload =
        queued_payload.expect("membership update should enqueue pending rebalance operations");
    let operations = queued_payload["operations"]
        .as_array()
        .expect("operations should be array");
    assert!(
        operations.iter().any(|operation| {
            operation["bucket"] == "rebalance-bucket" && operation["key"] == moving_key
        }),
        "queued rebalance operations should include seeded object key"
    );
}

#[tokio::test]
async fn test_cluster_membership_update_endpoint_retries_propagation_on_transient_peer_failure() {
    let (capture_peer, capture_state) = start_membership_propagation_retry_stub(vec![
        StatusCode::SERVICE_UNAVAILABLE,
        StatusCode::OK,
    ])
    .await;

    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = "node-a.internal:9000".to_string();
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let initial_health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(initial_health.status(), 200);
    let initial_health_body: serde_json::Value = initial_health.json().await.unwrap();
    let cluster_id = initial_health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present")
        .to_string();

    let update = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .header("x-maxio-join-cluster-id", cluster_id.as_str())
        .header("x-maxio-join-node-id", "node-b.internal:9000")
        .header("x-maxio-forwarded-by", "node-b.internal:9000")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header("x-maxio-join-nonce", "membership-update-propagation-retry")
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": [capture_peer.as_str()],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(update.status(), 200);

    let mut served_statuses = Vec::new();
    for _ in 0..40 {
        {
            served_statuses = capture_state.served_statuses.lock().await.clone();
        }
        if served_statuses.len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        served_statuses.len() >= 2,
        "expected propagation retry attempts, got statuses: {served_statuses:?}"
    );
    assert_eq!(served_statuses[0], 503);
    assert_eq!(served_statuses[1], 200);

    let records = capture_state.records.lock().await;
    assert!(
        records.len() >= 2,
        "expected at least two propagation attempts"
    );
    assert_eq!(records[0].propagation_header.as_deref(), Some("1"));
    assert_eq!(records[1].propagation_header.as_deref(), Some("1"));
    assert_eq!(
        records[0].forwarded_by.as_deref(),
        Some("node-a.internal:9000")
    );
}

#[tokio::test]
async fn test_cluster_membership_update_endpoint_does_not_queue_terminal_propagation_failure() {
    let (terminal_peer, terminal_state) =
        start_membership_propagation_retry_stub(vec![StatusCode::CONFLICT]).await;
    let (stable_peer, _stable_state) = start_membership_propagation_capture_stub().await;

    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir.clone(), false, 10 * 1024 * 1024, 0);
    config.node_id = "node-a.internal:9000".to_string();
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec![stable_peer.clone()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let initial_health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(initial_health.status(), 200);
    let initial_health_body: serde_json::Value = initial_health.json().await.unwrap();
    let cluster_id = initial_health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present")
        .to_string();

    let update = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .header("x-maxio-join-cluster-id", cluster_id.as_str())
        .header("x-maxio-join-node-id", stable_peer.as_str())
        .header("x-maxio-forwarded-by", stable_peer.as_str())
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header(
            "x-maxio-join-nonce",
            "membership-update-propagation-terminal-failure",
        )
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": [terminal_peer.as_str()],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(update.status(), 200);

    let mut served_statuses = Vec::new();
    for _ in 0..30 {
        served_statuses = terminal_state.served_statuses.lock().await.clone();
        if !served_statuses.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        served_statuses,
        vec![StatusCode::CONFLICT.as_u16()],
        "terminal propagation failure should not retry"
    );

    tokio::time::sleep(Duration::from_millis(150)).await;
    let queue_path = Path::new(data_dir.as_str())
        .join(".maxio-runtime")
        .join("pending-membership-propagation-queue.json");
    if queue_path.exists() {
        let payload = std::fs::read_to_string(queue_path.as_path())
            .expect("pending membership propagation queue should be readable");
        let parsed: serde_json::Value =
            serde_json::from_str(payload.as_str()).expect("queue payload should parse");
        let operations = parsed["operations"]
            .as_array()
            .expect("queue operations should be an array");
        assert!(
            operations.is_empty(),
            "terminal propagation failure should not be persisted for replay"
        );
    }
}

#[tokio::test]
async fn test_cluster_membership_update_endpoint_replays_failed_propagation_from_persisted_queue() {
    let (capture_peer, capture_state) = start_membership_propagation_retry_stub(vec![
        StatusCode::SERVICE_UNAVAILABLE,
        StatusCode::SERVICE_UNAVAILABLE,
        StatusCode::SERVICE_UNAVAILABLE,
        StatusCode::OK,
    ])
    .await;
    let (stable_peer, _stable_peer_state) = start_membership_propagation_capture_stub().await;

    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir.clone(), false, 10 * 1024 * 1024, 0);
    config.node_id = "node-a.internal:9000".to_string();
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec![capture_peer.clone(), stable_peer.clone()];
    let (base_url, _tmp) =
        start_server_with_config_and_membership_propagation_replay_worker(config, tmp).await;

    let initial_health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(initial_health.status(), 200);
    let initial_health_body: serde_json::Value = initial_health.json().await.unwrap();
    let cluster_id = initial_health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present")
        .to_string();

    let update = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .header("x-maxio-join-cluster-id", cluster_id.as_str())
        .header("x-maxio-join-node-id", stable_peer.as_str())
        .header("x-maxio-forwarded-by", stable_peer.as_str())
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header(
            "x-maxio-join-nonce",
            "membership-update-propagation-persisted-replay",
        )
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": [stable_peer.as_str()],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(update.status(), 200);

    let mut served_statuses = Vec::new();
    for _ in 0..160 {
        served_statuses = capture_state.served_statuses.lock().await.clone();
        if served_statuses.len() >= 4 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        served_statuses.len() >= 4,
        "expected persisted replay attempt after initial propagation failures, got statuses: {served_statuses:?}"
    );
    assert_eq!(served_statuses[0], 503);
    assert_eq!(served_statuses[1], 503);
    assert_eq!(served_statuses[2], 503);
    assert_eq!(served_statuses[3], 200);

    let queue_path = Path::new(data_dir.as_str())
        .join(".maxio-runtime")
        .join("pending-membership-propagation-queue.json");
    for _ in 0..80 {
        let queue = tokio::fs::read_to_string(queue_path.as_path())
            .await
            .ok()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok());
        if queue
            .as_ref()
            .and_then(|value| value["operations"].as_array())
            .is_some_and(|operations| operations.is_empty())
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let queue_payload: serde_json::Value = tokio::fs::read_to_string(queue_path.as_path())
        .await
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .expect("expected persisted membership propagation queue payload");
    assert_eq!(queue_payload["operations"], json!([]));
}

#[tokio::test]
async fn test_cluster_membership_update_endpoint_allows_transition_to_standalone() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["127.0.0.1:30121".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let initial_health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(initial_health.status(), 200);
    let initial_health_body: serde_json::Value = initial_health.json().await.unwrap();
    let cluster_id = initial_health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present")
        .to_string();
    let initial_view_id = initial_health_body["membershipViewId"]
        .as_str()
        .expect("membershipViewId should be present")
        .to_string();
    let initial_epoch = initial_health_body["placementEpoch"]
        .as_u64()
        .expect("placementEpoch should be present");

    let update = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .header("x-maxio-join-cluster-id", cluster_id.as_str())
        .header(
            "x-maxio-join-node-id",
            "peer-node-membership-update-standalone",
        )
        .header("x-maxio-forwarded-by", "127.0.0.1:30121")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header("x-maxio-join-nonce", "membership-update-to-standalone")
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": [],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(update.status(), 200);
    let update_body: serde_json::Value = update.json().await.unwrap();
    assert_eq!(update_body["status"], "applied");
    assert_eq!(update_body["reason"], "applied");
    assert_eq!(update_body["updated"], true);
    assert_eq!(update_body["clusterPeers"], serde_json::json!([]));
    assert_eq!(
        update_body["membershipViewId"],
        membership_view_id_with_self("maxio-test-node", &[])
    );
    assert_eq!(update_body["placementEpoch"], initial_epoch + 1);

    let updated_health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(updated_health.status(), 200);
    let updated_health_body: serde_json::Value = updated_health.json().await.unwrap();
    assert_eq!(updated_health_body["mode"], "standalone");
    assert_eq!(updated_health_body["clusterPeerCount"], 0);
    assert_eq!(updated_health_body["clusterPeers"], serde_json::json!([]));
    assert_ne!(updated_health_body["membershipViewId"], initial_view_id);
    assert_eq!(
        updated_health_body["membershipViewId"],
        membership_view_id_with_self("maxio-test-node", &[])
    );
    assert_eq!(updated_health_body["placementEpoch"], initial_epoch + 1);
}

#[tokio::test]
async fn test_cluster_membership_update_endpoint_rejects_unauthorized_requests() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["127.0.0.1:30201".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    let cluster_id = health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present");

    let rejected = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": ["127.0.0.1:30202"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 403);
    let rejected_body: serde_json::Value = rejected.json().await.unwrap();
    assert_eq!(rejected_body["status"], "rejected");
    assert_eq!(rejected_body["reason"], "unauthorized");
    assert_eq!(
        rejected_body["authReason"],
        "missing_or_malformed_cluster_id"
    );
    assert_eq!(rejected_body["updated"], false);
}

#[tokio::test]
async fn test_cluster_membership_update_endpoint_rejects_invalid_payload() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = "Node-A.Internal:30300".to_string();
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["127.0.0.1:30301".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    let cluster_id = health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present");

    let rejected = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "peer-node-membership-update")
        .header("x-maxio-forwarded-by", "127.0.0.1:30301")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header("x-maxio-join-nonce", "membership-update-invalid-payload")
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": ["maxio-test-node"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 400);
    let rejected_body: serde_json::Value = rejected.json().await.unwrap();
    assert_eq!(rejected_body["status"], "rejected");
    assert_eq!(rejected_body["reason"], "invalid_payload");
    assert_eq!(rejected_body["updated"], false);

    let case_variant_local_peer = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "peer-node-membership-update")
        .header("x-maxio-forwarded-by", "127.0.0.1:30301")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header(
            "x-maxio-join-nonce",
            "membership-update-invalid-local-peer-case-variant",
        )
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": ["node-a.internal:30300"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(case_variant_local_peer.status(), 400);
    let case_variant_local_peer_body: serde_json::Value =
        case_variant_local_peer.json().await.unwrap();
    assert_eq!(case_variant_local_peer_body["status"], "rejected");
    assert_eq!(case_variant_local_peer_body["reason"], "invalid_payload");
    assert_eq!(case_variant_local_peer_body["updated"], false);
}

#[tokio::test]
async fn test_cluster_membership_update_endpoint_rejects_whitespace_only_peer_payload() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["127.0.0.1:30321".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    let cluster_id = health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present");

    let rejected = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "peer-node-membership-update")
        .header("x-maxio-forwarded-by", "127.0.0.1:30321")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header(
            "x-maxio-join-nonce",
            "membership-update-whitespace-only-peers",
        )
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": ["   "],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 400);
    let rejected_body: serde_json::Value = rejected.json().await.unwrap();
    assert_eq!(rejected_body["status"], "rejected");
    assert_eq!(rejected_body["reason"], "invalid_payload");
    assert_eq!(rejected_body["updated"], false);
}

#[tokio::test]
async fn test_cluster_membership_update_endpoint_rejects_stale_membership_precondition() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["127.0.0.1:30341".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    let cluster_id = health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present");
    let placement_epoch = health_body["placementEpoch"]
        .as_u64()
        .expect("placementEpoch should be present");
    let membership_view_id = health_body["membershipViewId"]
        .as_str()
        .expect("membershipViewId should be present");

    let rejected = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "peer-node-membership-update")
        .header("x-maxio-forwarded-by", "127.0.0.1:30341")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header("x-maxio-join-nonce", "membership-update-stale-precondition")
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": ["127.0.0.1:30342"],
            "expectedMembershipViewId": format!("{membership_view_id}-stale"),
            "expectedPlacementEpoch": placement_epoch,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 409);
    let rejected_body: serde_json::Value = rejected.json().await.unwrap();
    assert_eq!(rejected_body["status"], "rejected");
    assert_eq!(rejected_body["reason"], "precondition_failed");
    assert_eq!(rejected_body["updated"], false);
    assert_eq!(rejected_body["placementEpoch"], placement_epoch);
    assert_eq!(rejected_body["membershipViewId"], membership_view_id);

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let metrics_body = metrics.text().await.unwrap();
    assert_eq!(
        metric_labeled_value(
            &metrics_body,
            "maxio_cluster_membership_update_reason_total{reason=\"precondition_failed\"}"
        ),
        Some(1.0)
    );
}

#[tokio::test]
async fn test_cluster_membership_update_endpoint_rejects_stale_epoch_precondition() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["127.0.0.1:30361".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    let cluster_id = health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present");
    let placement_epoch = health_body["placementEpoch"]
        .as_u64()
        .expect("placementEpoch should be present");
    let membership_view_id = health_body["membershipViewId"]
        .as_str()
        .expect("membershipViewId should be present");

    let rejected = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "peer-node-membership-update")
        .header("x-maxio-forwarded-by", "127.0.0.1:30361")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header(
            "x-maxio-join-nonce",
            "membership-update-stale-epoch-precondition",
        )
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": ["127.0.0.1:30362"],
            "expectedMembershipViewId": membership_view_id,
            "expectedPlacementEpoch": placement_epoch + 1,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 409);
    let rejected_body: serde_json::Value = rejected.json().await.unwrap();
    assert_eq!(rejected_body["status"], "rejected");
    assert_eq!(rejected_body["reason"], "precondition_failed");
    assert_eq!(rejected_body["updated"], false);
    assert_eq!(rejected_body["placementEpoch"], placement_epoch);
    assert_eq!(rejected_body["membershipViewId"], membership_view_id);
}

#[tokio::test]
async fn test_cluster_membership_update_endpoint_metrics_track_status_and_reason_labels() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["127.0.0.1:30421".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    let cluster_id = health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present");

    let applied = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "peer-node-membership-update")
        .header("x-maxio-forwarded-by", "127.0.0.1:30421")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header("x-maxio-join-nonce", "membership-update-metrics-applied")
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": ["127.0.0.1:30422"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(applied.status(), 200);
    let applied_body: serde_json::Value = applied.json().await.unwrap();
    assert_eq!(applied_body["status"], "applied");
    assert_eq!(applied_body["reason"], "applied");

    let invalid_payload = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "peer-node-membership-update")
        .header("x-maxio-forwarded-by", "127.0.0.1:30422")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header(
            "x-maxio-join-nonce",
            "membership-update-metrics-invalid-payload",
        )
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": ["maxio-test-node"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(invalid_payload.status(), 400);
    let invalid_payload_body: serde_json::Value = invalid_payload.json().await.unwrap();
    assert_eq!(invalid_payload_body["status"], "rejected");
    assert_eq!(invalid_payload_body["reason"], "invalid_payload");

    let unauthorized = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": ["127.0.0.1:30423"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), 403);
    let unauthorized_body: serde_json::Value = unauthorized.json().await.unwrap();
    assert_eq!(unauthorized_body["status"], "rejected");
    assert_eq!(unauthorized_body["reason"], "unauthorized");

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let metrics_body = metrics.text().await.unwrap();

    assert_eq!(
        metric_value(
            &metrics_body,
            "maxio_cluster_membership_update_requests_total"
        ),
        Some(3.0)
    );
    assert_eq!(
        metric_labeled_value(
            &metrics_body,
            "maxio_cluster_membership_update_status_total{status=\"applied\"}"
        ),
        Some(1.0)
    );
    assert_eq!(
        metric_labeled_value(
            &metrics_body,
            "maxio_cluster_membership_update_status_total{status=\"rejected\"}"
        ),
        Some(2.0)
    );
    assert_eq!(
        metric_labeled_value(
            &metrics_body,
            "maxio_cluster_membership_update_status_total{status=\"misconfigured\"}"
        ),
        Some(0.0)
    );
    assert_eq!(
        metric_labeled_value(
            &metrics_body,
            "maxio_cluster_membership_update_reason_total{reason=\"applied\"}"
        ),
        Some(1.0)
    );
    assert_eq!(
        metric_labeled_value(
            &metrics_body,
            "maxio_cluster_membership_update_reason_total{reason=\"invalid_payload\"}"
        ),
        Some(1.0)
    );
    assert_eq!(
        metric_labeled_value(
            &metrics_body,
            "maxio_cluster_membership_update_reason_total{reason=\"unauthorized\"}"
        ),
        Some(1.0)
    );
}

#[tokio::test]
async fn test_cluster_join_endpoint_returns_service_unavailable_when_cluster_peer_transport_mtls_not_ready()
 {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["127.0.0.1:30541".to_string()];
    config.cluster_peer_tls_cert_path = Some("/tmp/maxio-missing-cert.pem".to_string());
    config.cluster_peer_tls_key_path = Some("/tmp/maxio-missing-key.pem".to_string());
    config.cluster_peer_tls_ca_path = Some("/tmp/maxio-missing-ca.pem".to_string());
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    let cluster_id = health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present")
        .to_string();

    let response = client()
        .post(format!("{}/internal/cluster/join", base_url))
        .header("x-maxio-join-cluster-id", cluster_id.as_str())
        .header("x-maxio-join-node-id", "127.0.0.1:30541")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header("x-maxio-join-nonce", "join-transport-not-ready")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["status"], "misconfigured");
    assert_eq!(body["reason"], "cluster_peer_transport_not_ready");
    assert_eq!(body["authReason"], serde_json::Value::Null);
    assert_eq!(body["mode"], "shared_token");
    assert_eq!(body["updated"], false);
}

#[tokio::test]
async fn test_cluster_membership_update_endpoint_returns_service_unavailable_when_membership_engine_not_ready()
 {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["127.0.0.1:30431".to_string()];
    config.membership_protocol = MembershipProtocol::Gossip;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    let cluster_id = health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present");
    assert_eq!(health_body["checks"]["membershipProtocolReady"], true);

    let rejected = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "peer-node-membership-update")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header(
            "x-maxio-join-nonce",
            "membership-update-membership-engine-not-ready",
        )
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": ["127.0.0.1:30432"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 403);
    let rejected_body: serde_json::Value = rejected.json().await.unwrap();
    assert_eq!(rejected_body["status"], "rejected");
    assert_eq!(rejected_body["reason"], "unauthorized");
    assert_eq!(
        rejected_body["authReason"],
        "missing_or_malformed_forwarded_by"
    );
    assert_eq!(rejected_body["mode"], "shared_token_allowlist");
    assert_eq!(rejected_body["updated"], false);

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let metrics_body = metrics.text().await.unwrap();
    assert_eq!(
        metric_labeled_value(
            &metrics_body,
            "maxio_cluster_membership_update_reason_total{reason=\"unauthorized\"}"
        ),
        Some(1.0)
    );
}

#[tokio::test]
async fn test_cluster_membership_update_endpoint_returns_service_unavailable_when_cluster_peer_transport_mtls_not_ready()
 {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["127.0.0.1:30441".to_string()];
    config.cluster_peer_tls_cert_path = Some("/tmp/maxio-missing-cert.pem".to_string());
    config.cluster_peer_tls_key_path = Some("/tmp/maxio-missing-key.pem".to_string());
    config.cluster_peer_tls_ca_path = Some("/tmp/maxio-missing-ca.pem".to_string());
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    let cluster_id = health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present");

    let rejected = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "peer-node-membership-update")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header(
            "x-maxio-join-nonce",
            "membership-update-transport-not-ready",
        )
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": ["127.0.0.1:30442"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 503);
    let rejected_body: serde_json::Value = rejected.json().await.unwrap();
    assert_eq!(rejected_body["status"], "misconfigured");
    assert_eq!(rejected_body["reason"], "cluster_peer_transport_not_ready");
    assert_eq!(rejected_body["authReason"], serde_json::Value::Null);
    assert_eq!(rejected_body["mode"], "shared_token");
    assert_eq!(rejected_body["updated"], false);
}

#[tokio::test]
async fn test_cluster_membership_update_endpoint_returns_service_unavailable_when_cluster_auth_token_not_configured_in_distributed_mode()
 {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["127.0.0.1:30411".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    let cluster_id = health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present");

    let rejected = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "peer-node-membership-update")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header("x-maxio-join-nonce", "membership-update-no-shared-token")
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": ["127.0.0.1:30412"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 503);
    let rejected_body: serde_json::Value = rejected.json().await.unwrap();
    assert_eq!(rejected_body["status"], "misconfigured");
    assert_eq!(rejected_body["reason"], "cluster_auth_token_not_configured");
    assert_eq!(rejected_body["authReason"], serde_json::Value::Null);
    assert_eq!(rejected_body["mode"], "compatibility_no_token");
    assert_eq!(rejected_body["updated"], false);
}

#[tokio::test]
async fn test_cluster_membership_update_endpoint_rejects_forwarded_sender_not_in_allowlist() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["127.0.0.1:30451".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    let cluster_id = health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present");

    let rejected = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "127.0.0.1:30499")
        .header("x-maxio-forwarded-by", "127.0.0.1:30499")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header(
            "x-maxio-join-nonce",
            "membership-update-sender-not-in-allowlist",
        )
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": ["127.0.0.1:30452"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 403);
    let rejected_body: serde_json::Value = rejected.json().await.unwrap();
    assert_eq!(rejected_body["status"], "rejected");
    assert_eq!(rejected_body["reason"], "unauthorized");
    assert_eq!(rejected_body["authReason"], "sender_not_in_allowlist");
    assert_eq!(rejected_body["updated"], false);
}

#[tokio::test]
async fn test_cluster_membership_update_endpoint_rejects_known_sender_with_token_mismatch() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["127.0.0.1:30461".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    let cluster_id = health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present");

    let rejected = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "127.0.0.1:30461")
        .header("x-maxio-forwarded-by", "127.0.0.1:30461")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header(
            "x-maxio-join-nonce",
            "membership-update-known-sender-token-mismatch",
        )
        .header("x-maxio-internal-auth-token", "wrong-shared-secret")
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": ["127.0.0.1:30462"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 403);
    let rejected_body: serde_json::Value = rejected.json().await.unwrap();
    assert_eq!(rejected_body["status"], "rejected");
    assert_eq!(rejected_body["reason"], "unauthorized");
    assert_eq!(rejected_body["authReason"], "auth_token_mismatch");
    assert_eq!(rejected_body["updated"], false);
}

#[tokio::test]
async fn test_cluster_membership_update_endpoint_rejects_forwarded_sender_node_id_mismatch() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["127.0.0.1:30471".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    let cluster_id = health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present");

    let rejected = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "127.0.0.1:30472")
        .header("x-maxio-forwarded-by", "127.0.0.1:30471")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header(
            "x-maxio-join-nonce",
            "membership-update-forwarded-node-id-mismatch",
        )
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": ["127.0.0.1:30472"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 403);
    let rejected_body: serde_json::Value = rejected.json().await.unwrap();
    assert_eq!(rejected_body["status"], "rejected");
    assert_eq!(rejected_body["reason"], "unauthorized");
    assert_eq!(rejected_body["authReason"], "forwarded_by_node_id_mismatch");
    assert_eq!(rejected_body["updated"], false);
}

#[tokio::test]
async fn test_cluster_membership_update_endpoint_rejects_multi_hop_forwarded_origin_spoofing() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec!["127.0.0.1:30481".to_string(), "127.0.0.1:30482".to_string()];
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    let cluster_id = health_body["clusterId"]
        .as_str()
        .expect("clusterId should be present");

    let rejected = client()
        .post(format!("{}/internal/cluster/membership/update", base_url))
        .header("x-maxio-join-cluster-id", cluster_id)
        .header("x-maxio-join-node-id", "127.0.0.1:30481")
        .header("x-maxio-forwarded-by", "127.0.0.1:30481,127.0.0.1:30482")
        .header("x-maxio-join-unix-ms", unix_ms_now_string())
        .header(
            "x-maxio-join-nonce",
            "membership-update-forwarded-origin-spoofed-by-multihop",
        )
        .header("x-maxio-internal-auth-token", "shared-secret")
        .json(&json!({
            "clusterId": cluster_id,
            "clusterPeers": ["127.0.0.1:30481"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 403);
    let rejected_body: serde_json::Value = rejected.json().await.unwrap();
    assert_eq!(rejected_body["status"], "rejected");
    assert_eq!(rejected_body["reason"], "unauthorized");
    assert_eq!(rejected_body["authReason"], "forwarded_by_node_id_mismatch");
    assert_eq!(rejected_body["updated"], false);
}

#[tokio::test]
async fn test_healthz_and_metrics_report_strict_quorum_write_durability_mode_when_configured() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.write_durability_mode = WriteDurabilityMode::StrictQuorum;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    assert_eq!(health_body["writeDurabilityMode"], "strict-quorum");

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let metrics_body = metrics.text().await.unwrap();
    assert!(metrics_body.contains("maxio_write_durability_mode_info{mode=\"strict-quorum\"} 1"));
}

#[tokio::test]
async fn test_healthz_and_metrics_report_consensus_index_metadata_listing_strategy_when_configured()
{
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    assert_eq!(health_body["metadataListingStrategy"], "consensus-index");
    assert_eq!(health_body["metadataListingGap"], serde_json::Value::Null);
    assert_eq!(
        health_body["checks"]["metadataListClusterAuthoritative"],
        true
    );
    assert_eq!(health_body["checks"]["metadataListReady"], true);

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let metrics_body = metrics.text().await.unwrap();
    assert!(
        metrics_body
            .contains("maxio_metadata_listing_strategy_info{strategy=\"consensus-index\"} 1")
    );
    assert_eq!(
        metric_value(
            &metrics_body,
            "maxio_metadata_listing_cluster_authoritative"
        ),
        Some(1.0)
    );
    assert_eq!(
        metric_value(&metrics_body, "maxio_metadata_listing_ready"),
        Some(1.0)
    );
    assert!(metrics_body.contains("maxio_metadata_listing_gap_info{gap=\"none\"} 1"));
}

#[tokio::test]
async fn test_healthz_and_metrics_report_consensus_index_metadata_listing_strategy_as_unready_when_shared_token_missing()
 {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    let peer =
        start_peer_healthz_stub_with_matching_single_peer_view(config.node_id.as_str()).await;
    config.cluster_peers = vec![peer];
    config.membership_protocol = MembershipProtocol::StaticBootstrap;

    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    assert_eq!(health_body["metadataListingStrategy"], "consensus-index");
    assert_eq!(
        health_body["metadataListingGap"],
        "consensus-index-peer-fan-in-auth-token-missing"
    );
    assert_eq!(
        health_body["checks"]["metadataListClusterAuthoritative"],
        true
    );
    assert_eq!(health_body["checks"]["metadataListReady"], false);

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let metrics_body = metrics.text().await.unwrap();
    assert!(
        metrics_body
            .contains("maxio_metadata_listing_strategy_info{strategy=\"consensus-index\"} 1")
    );
    assert_eq!(
        metric_value(&metrics_body, "maxio_metadata_listing_ready"),
        Some(0.0)
    );
    assert!(metrics_body.contains(
        "maxio_metadata_listing_gap_info{gap=\"consensus-index-peer-fan-in-auth-token-missing\"} 1"
    ));
}

#[tokio::test]
async fn test_healthz_reports_degraded_when_consensus_metadata_state_is_not_queryable() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir.clone(), false, 10 * 1024 * 1024, 0);
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.membership_protocol = MembershipProtocol::StaticBootstrap;
    let peer =
        start_peer_healthz_stub_with_matching_single_peer_view(config.node_id.as_str()).await;
    config.cluster_peers = vec![peer];

    let runtime_dir = tmp.path().join(".maxio-runtime");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    let metadata_state_path = runtime_dir.join("cluster-metadata-state.json");
    let invalid_state = serde_json::json!({
        "view_id": "view-consensus",
        "buckets": [{
            "bucket": "photos",
            "versioning_enabled": false,
            "lifecycle_enabled": false
        }],
        "bucket_tombstones": [{
            "bucket": "photos",
            "deleted_at_unix_ms": 1,
            "retain_until_unix_ms": 2
        }],
        "objects": [],
        "object_versions": []
    });
    std::fs::write(
        metadata_state_path,
        serde_json::to_vec(&invalid_state).unwrap(),
    )
    .unwrap();

    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    assert_eq!(health_body["ok"], false);
    assert_eq!(health_body["status"], "degraded");
    assert_eq!(health_body["metadataListingStrategy"], "consensus-index");
    assert_eq!(health_body["checks"]["metadataListReady"], false);
    assert_eq!(health_body["metadataListingGap"], "missing-expected-nodes");
    assert_eq!(health_body["checks"]["metadataStateQueryable"], false);
    assert_eq!(health_body["metadataStateViewId"], "view-consensus");
    assert_eq!(health_body["metadataStateBucketRows"], 1);
    assert_eq!(health_body["metadataStateObjectRows"], 0);
    assert_eq!(health_body["metadataStateObjectVersionRows"], 0);
    assert!(
        health_body["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.iter().any(|warning| warning
                .as_str()
                .is_some_and(|msg| msg.contains("is not queryable"))))
    );

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let metrics_body = metrics.text().await.unwrap();
    assert_eq!(
        metric_value(&metrics_body, "maxio_metadata_state_readable"),
        Some(1.0)
    );
    assert_eq!(
        metric_value(&metrics_body, "maxio_metadata_state_queryable"),
        Some(0.0)
    );
    assert_eq!(
        metric_value(&metrics_body, "maxio_metadata_state_bucket_rows"),
        Some(1.0)
    );
}

#[tokio::test]
async fn test_healthz_and_metrics_report_request_time_aggregation_metadata_listing_strategy_as_unready_when_distributed()
 {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::RequestTimeAggregation;
    let peer =
        start_peer_healthz_stub_with_matching_single_peer_view(config.node_id.as_str()).await;
    config.cluster_peers = vec![peer];
    config.membership_protocol = MembershipProtocol::StaticBootstrap;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let health = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
    let health_body: serde_json::Value = health.json().await.unwrap();
    assert_eq!(
        health_body["metadataListingStrategy"],
        "request-time-aggregation"
    );
    assert_eq!(health_body["metadataListingGap"], "missing-expected-nodes");
    assert!(
        health_body["metadataListingSnapshotId"]
            .as_str()
            .is_some_and(|snapshot_id| !snapshot_id.is_empty())
    );
    assert_eq!(health_body["metadataListingExpectedNodes"], 2);
    assert_eq!(health_body["metadataListingRespondedNodes"], 1);
    assert_eq!(health_body["metadataListingMissingNodes"], 1);
    assert_eq!(health_body["metadataListingUnexpectedNodes"], 0);
    assert_eq!(
        health_body["checks"]["metadataListClusterAuthoritative"],
        true
    );
    assert_eq!(health_body["checks"]["metadataListReady"], false);

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let metrics_body = metrics.text().await.unwrap();
    assert!(
        metrics_body.contains(
            "maxio_metadata_listing_strategy_info{strategy=\"request-time-aggregation\"} 1"
        )
    );
    assert_eq!(
        metric_value(
            &metrics_body,
            "maxio_metadata_listing_cluster_authoritative"
        ),
        Some(1.0)
    );
    assert_eq!(
        metric_value(&metrics_body, "maxio_metadata_listing_ready"),
        Some(0.0)
    );
    assert!(
        metrics_body.contains("maxio_metadata_listing_gap_info{gap=\"missing-expected-nodes\"} 1")
    );
    assert_eq!(
        metric_value(&metrics_body, "maxio_metadata_listing_expected_nodes"),
        Some(2.0)
    );
    assert_eq!(
        metric_value(&metrics_body, "maxio_metadata_listing_responded_nodes"),
        Some(1.0)
    );
    assert_eq!(
        metric_value(&metrics_body, "maxio_metadata_listing_missing_nodes"),
        Some(1.0)
    );
    assert_eq!(
        metric_value(&metrics_body, "maxio_metadata_listing_unexpected_nodes"),
        Some(0.0)
    );
}

#[tokio::test]
async fn test_healthz_reports_warning_for_invalid_local_node_id_in_shared_token_binding() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = "node/invalid".to_string();
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    config.membership_protocol = MembershipProtocol::Gossip;
    config.cluster_auth_token = Some("shared-secret".to_string());
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let resp = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();

    assert_eq!(body["checks"]["clusterPeerAuthConfigured"], true);
    assert_eq!(body["checks"]["clusterPeerAuthSenderAllowlistBound"], false);
    assert!(
        body["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings
                .iter()
                .any(|warning| warning.as_str().is_some_and(|msg| msg
                    .contains("Local node id is invalid for shared-token peer-auth binding"))))
    );
}

#[tokio::test]
async fn test_healthz_reports_degraded_when_distributed_peer_auth_sender_allowlist_not_bound() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    let peer =
        start_peer_healthz_stub_with_matching_single_peer_view(config.node_id.as_str()).await;
    config.cluster_peers = vec![peer];
    config.membership_protocol = MembershipProtocol::StaticBootstrap;

    let (base_url, _tmp) = start_server_with_config(config, tmp).await;
    let resp = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["status"], "degraded");
    assert_eq!(body["checks"]["peerConnectivityReady"], true);
    assert_eq!(body["checks"]["membershipConverged"], true);
    assert_eq!(body["membershipConvergenceReason"], "converged");
    assert_eq!(body["checks"]["clusterPeerAuthConfigured"], false);
    assert_eq!(body["checks"]["clusterPeerAuthSenderAllowlistBound"], false);
    assert!(
        body["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.iter().any(|warning| warning
                .as_str()
                .is_some_and(|msg| msg.contains("compatibility mode"))))
    );
}

#[tokio::test]
async fn test_healthz_reports_degraded_when_storage_data_path_probe_fails() {
    let (base_url, tmp) = start_server().await;
    tokio::fs::remove_dir_all(tmp.path().join("buckets"))
        .await
        .expect("buckets directory should be removable");

    let resp = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["status"], "degraded");
    assert_eq!(body["checks"]["dataDirAccessible"], true);
    assert_eq!(body["checks"]["dataDirWritable"], true);
    assert_eq!(body["checks"]["storageDataPathReadable"], false);
    assert_eq!(body["checks"]["diskHeadroomSufficient"], true);
    assert_eq!(body["checks"]["peerConnectivityReady"], true);
    assert_eq!(body["checks"]["membershipProtocolReady"], true);
    assert!(
        body["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.iter().any(|warning| warning
                .as_str()
                .is_some_and(|msg| msg.contains("Storage data-path probe failed"))))
    );
}

#[tokio::test]
async fn test_healthz_reports_degraded_when_pending_replication_queue_probe_fails_in_distributed_degraded_mode()
 {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir.clone(), false, 10 * 1024 * 1024, 0);
    let peer =
        start_peer_healthz_stub_with_matching_single_peer_view(config.node_id.as_str()).await;
    config.cluster_peers = vec![peer];
    config.membership_protocol = MembershipProtocol::StaticBootstrap;
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::ConsensusIndex;
    config.write_durability_mode = WriteDurabilityMode::DegradedSuccess;

    let queue_path = tmp
        .path()
        .join(".maxio-runtime")
        .join("pending-replication-queue.json");
    std::fs::create_dir_all(
        queue_path
            .parent()
            .expect("pending replication queue path should have a parent"),
    )
    .expect("runtime state directory should be creatable");
    std::fs::write(&queue_path, b"{invalid-json")
        .expect("invalid pending replication queue payload should be written");

    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let resp = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["status"], "degraded");
    assert_eq!(body["checks"]["peerConnectivityReady"], true);
    assert_eq!(body["checks"]["membershipConverged"], true);
    assert_eq!(body["checks"]["clusterJoinAuthReady"], true);
    assert_eq!(body["checks"]["pendingReplicationQueueReadable"], false);
    assert_eq!(body["checks"]["pendingMetadataRepairQueueReadable"], true);
    assert!(
        body["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.iter().any(|warning| warning
                .as_str()
                .is_some_and(|msg| msg.contains("Pending replication queue probe failed"))))
    );

    let metrics = client()
        .get(format!("{}/metrics", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), 200);
    let metrics_body = metrics.text().await.unwrap();
    assert_eq!(
        metric_value(&metrics_body, "maxio_pending_replication_queue_readable"),
        Some(0.0)
    );
}

#[tokio::test]
async fn test_healthz_reports_degraded_when_disk_headroom_threshold_not_met() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.min_disk_headroom_bytes = u64::MAX;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let resp = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["status"], "degraded");
    assert_eq!(body["checks"]["dataDirAccessible"], true);
    assert_eq!(body["checks"]["dataDirWritable"], true);
    assert_eq!(body["checks"]["storageDataPathReadable"], true);
    assert_eq!(body["checks"]["diskHeadroomSufficient"], false);
    assert_eq!(body["checks"]["peerConnectivityReady"], true);
    assert_eq!(body["checks"]["membershipProtocolReady"], true);
    assert!(
        body["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.iter().any(|warning| warning
                .as_str()
                .is_some_and(|msg| msg.contains("Disk headroom below threshold"))))
    );
}

#[tokio::test]
async fn test_healthz_warns_when_pending_membership_propagation_due_backlog_exceeds_replay_batch_size()
 {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);

    let queue_path = tmp
        .path()
        .join(".maxio-runtime")
        .join("pending-membership-propagation-queue.json");
    std::fs::create_dir_all(
        queue_path
            .parent()
            .expect("pending membership propagation queue path should have a parent"),
    )
    .expect("runtime state directory should be creatable");

    let operations = (0..1024)
        .map(|index| {
            json!({
                "peer": format!("node-{}.internal:9000", index),
                "request": {
                    "clusterId": "cluster-a",
                    "clusterPeers": ["node-a.internal:9000"],
                },
                "attempts": 0,
                "createdAtUnixMs": 1,
                "updatedAtUnixMs": 1,
                "nextRetryAtUnixMs": 0,
                "lastError": null,
            })
        })
        .collect::<Vec<_>>();
    std::fs::write(
        &queue_path,
        serde_json::to_vec_pretty(&json!({ "operations": operations }))
            .expect("pending membership propagation queue should serialize"),
    )
    .expect("pending membership propagation queue should persist");

    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let resp = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["status"], "ok");
    assert!(
        body["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings
                .iter()
                .any(|warning| warning.as_str().is_some_and(|msg| msg
                    .contains("Pending membership propagation backlog has")
                    && msg.contains("exceeding replay batch size"))))
    );
}

#[tokio::test]
async fn test_healthz_reports_degraded_when_static_peer_connectivity_probe_fails() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec!["127.0.0.1:1".to_string()];
    config.membership_protocol = MembershipProtocol::StaticBootstrap;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let resp = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["status"], "degraded");
    assert_eq!(body["checks"]["membershipProtocolReady"], true);
    assert_eq!(body["checks"]["peerConnectivityReady"], false);
    assert_eq!(
        body["membershipConvergenceReason"],
        "peer-connectivity-failed"
    );
    assert!(
        body["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.iter().any(|warning| warning
                .as_str()
                .is_some_and(|msg| msg.contains("Peer connectivity probe failed"))))
    );
}

#[tokio::test]
async fn test_healthz_reports_degraded_when_cluster_peers_include_local_node_id() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = "Node-A.Internal:9000".to_string();
    config.cluster_peers = vec!["node-a.internal:9000".to_string()];
    config.membership_protocol = MembershipProtocol::StaticBootstrap;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let resp = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["status"], "degraded");
    assert_eq!(body["checks"]["membershipProtocolReady"], true);
    assert_eq!(body["checks"]["peerConnectivityReady"], false);
    assert!(
        body["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.iter().any(|warning| warning
                .as_str()
                .is_some_and(|msg| msg.contains("includes local node id"))))
    );
}

#[tokio::test]
async fn test_healthz_reports_degraded_when_static_peer_membership_view_mismatches() {
    let peer = start_peer_healthz_stub("peer-mismatched-view").await;
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = "maxio-node-a".to_string();
    config.cluster_peers = vec![peer];
    config.membership_protocol = MembershipProtocol::StaticBootstrap;
    let (base_url, _tmp) = start_server_with_config(config, tmp).await;

    let resp = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["status"], "degraded");
    assert_eq!(body["checks"]["membershipProtocolReady"], true);
    assert_eq!(body["checks"]["peerConnectivityReady"], true);
    assert_eq!(body["checks"]["membershipConverged"], false);
    assert_eq!(
        body["membershipConvergenceReason"],
        "membership-view-mismatch"
    );
    assert!(
        body["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.iter().any(|warning| warning
                .as_str()
                .is_some_and(|msg| msg.contains("Membership view mismatch detected"))))
    );
}

#[tokio::test]
async fn test_static_bootstrap_convergence_worker_applies_discovered_peers_from_peer_healthz() {
    let peer = "127.0.0.1:31501".to_string();
    let discovered_peer = "127.0.0.1:31502".to_string();
    let peer_view =
        membership_view_id_with_self("maxio-node-b", &[peer.clone(), discovered_peer.clone()]);
    let local_node_id = "maxio-test-node";
    let healthz_peer = start_peer_healthz_stub_with_discovery_snapshot(
        local_node_id,
        peer_view.as_str(),
        vec![discovered_peer.clone()],
    )
    .await;

    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = local_node_id.to_string();
    config.cluster_peers = vec![healthz_peer];
    config.membership_protocol = MembershipProtocol::StaticBootstrap;
    let (base_url, _tmp) = start_server_with_config_and_convergence_worker(config, tmp).await;

    let mut observed: Option<serde_json::Value> = None;
    for _ in 0..40 {
        let resp = client()
            .get(format!("{}/healthz", base_url))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        observed = Some(body.clone());
        if body["clusterPeerCount"].as_u64() == Some(2)
            && body["clusterPeers"].as_array().is_some_and(|peers| {
                peers
                    .iter()
                    .any(|value| value.as_str() == Some(discovered_peer.as_str()))
            })
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let body = observed.expect("health payload should be observed");
    assert_eq!(body["clusterPeerCount"].as_u64(), Some(2));
    assert!(body["clusterPeers"].as_array().is_some_and(|peers| {
        peers
            .iter()
            .any(|value| value.as_str() == Some(discovered_peer.as_str()))
    }));
    assert_eq!(body["checks"]["membershipProtocolReady"], true);
}

#[tokio::test]
async fn test_static_bootstrap_convergence_worker_propagates_discovered_peers_to_control_plane() {
    let (capture_peer, capture_state) = start_membership_propagation_capture_stub().await;
    let peer = "127.0.0.1:31701".to_string();
    let peer_view =
        membership_view_id_with_self("maxio-node-b", &[peer.clone(), capture_peer.clone()]);
    let local_node_id = "node-a.internal:9000";
    let healthz_peer = start_peer_healthz_stub_with_discovery_snapshot(
        local_node_id,
        peer_view.as_str(),
        vec![capture_peer.clone()],
    )
    .await;

    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = local_node_id.to_string();
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec![healthz_peer.clone()];
    config.membership_protocol = MembershipProtocol::StaticBootstrap;
    let (_base_url, _tmp) = start_server_with_config_and_convergence_worker(config, tmp).await;

    let mut propagated = None;
    for _ in 0..60 {
        {
            let records = capture_state.records.lock().await;
            if let Some(record) = records.first() {
                propagated = Some(record.clone());
            }
        }
        if propagated.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let propagated =
        propagated.expect("discovered membership update should be propagated to capture peer");
    assert_eq!(propagated.propagation_header.as_deref(), Some("1"));
    assert_eq!(
        propagated.forwarded_by.as_deref(),
        Some("node-a.internal:9000")
    );
    let propagated_peers = propagated.payload["clusterPeers"]
        .as_array()
        .expect("clusterPeers should be present");
    assert!(
        propagated_peers
            .iter()
            .any(|value| value.as_str() == Some(capture_peer.as_str())),
        "propagated topology should include discovered peer"
    );
    assert!(
        propagated_peers
            .iter()
            .any(|value| value.as_str() == Some(healthz_peer.as_str())),
        "propagated topology should include existing probe peer"
    );
}

#[tokio::test]
async fn test_gossip_convergence_worker_persists_retryable_stale_peer_reconciliation_failure() {
    let local_node_id = "node-a.internal:9000";
    let stale_peer_view = "peer-stale-view";
    let stale_peer_epoch = 17_u64;
    let (stale_peer, stale_peer_state) = start_gossip_stale_reconciliation_retry_stub(
        local_node_id,
        stale_peer_view,
        Vec::new(),
        stale_peer_epoch,
        vec![
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::SERVICE_UNAVAILABLE,
        ],
    )
    .await;

    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir.clone(), false, 10 * 1024 * 1024, 0);
    config.node_id = local_node_id.to_string();
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec![stale_peer.clone()];
    config.membership_protocol = MembershipProtocol::Gossip;
    let (_base_url, _tmp) = start_server_with_config_and_convergence_worker(config, tmp).await;

    let queue_path = Path::new(data_dir.as_str())
        .join(".maxio-runtime")
        .join("pending-membership-propagation-queue.json");
    let mut queued_payload = None;
    for _ in 0..100 {
        if let Ok(payload) = tokio::fs::read_to_string(queue_path.as_path()).await {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(payload.as_str()) {
                let has_expected_operation =
                    parsed["operations"].as_array().is_some_and(|operations| {
                        operations.iter().any(|operation| {
                            operation["peer"].as_str() == Some(stale_peer.as_str())
                                && operation["request"]["expectedMembershipViewId"].as_str()
                                    == Some(stale_peer_view)
                                && operation["request"]["expectedPlacementEpoch"].as_u64()
                                    == Some(stale_peer_epoch)
                        })
                    });
                if has_expected_operation {
                    queued_payload = Some(parsed);
                    break;
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let queued_payload =
        queued_payload.expect("expected stale-peer reconciliation failure to be queued for replay");
    let queued_operation = queued_payload["operations"]
        .as_array()
        .and_then(|operations| {
            operations
                .iter()
                .find(|operation| operation["peer"].as_str() == Some(stale_peer.as_str()))
        })
        .expect("queued stale-peer operation should be present");
    assert_eq!(
        queued_operation["request"]["expectedMembershipViewId"],
        stale_peer_view
    );
    assert_eq!(
        queued_operation["request"]["expectedPlacementEpoch"],
        stale_peer_epoch
    );

    let served_statuses = stale_peer_state.served_statuses.lock().await.clone();
    assert!(
        !served_statuses.is_empty(),
        "stale peer reconciliation stub should receive update attempts"
    );
    assert!(
        served_statuses
            .iter()
            .all(|status| *status == StatusCode::SERVICE_UNAVAILABLE.as_u16()),
        "expected retryable stale-peer reconciliation statuses, got {served_statuses:?}"
    );
}

#[tokio::test]
async fn test_gossip_convergence_worker_reconciles_same_view_peer_missing_local_node() {
    let local_node_id = "node-a.internal:9000";
    let peer_epoch = 21_u64;
    let (peer, local_view_id, peer_state) =
        start_gossip_stale_reconciliation_retry_stub_with_local_view(
            local_node_id,
            Vec::new(),
            peer_epoch,
            vec![StatusCode::OK],
        )
        .await;

    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = local_node_id.to_string();
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peers = vec![peer.clone()];
    config.membership_protocol = MembershipProtocol::Gossip;
    let (_base_url, _tmp) = start_server_with_config_and_convergence_worker(config, tmp).await;

    let mut propagated = None;
    for _ in 0..60 {
        {
            let records = peer_state.records.lock().await;
            if let Some(record) = records.first() {
                propagated = Some(record.clone());
            }
        }
        if propagated.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let propagated = propagated
        .expect("expected same-view missing-local-node drift to trigger stale-peer reconciliation");
    assert_eq!(
        propagated.payload["expectedMembershipViewId"], local_view_id,
        "same-view drift reconciliation should bind to observed peer view id"
    );
    assert_eq!(
        propagated.payload["expectedPlacementEpoch"], peer_epoch,
        "same-view drift reconciliation should bind to observed peer epoch"
    );
    assert_eq!(propagated.forwarded_by.as_deref(), Some(local_node_id));

    let served_statuses = peer_state.served_statuses.lock().await.clone();
    assert!(
        served_statuses
            .iter()
            .any(|status| *status == StatusCode::OK.as_u16()),
        "expected stale-peer reconciliation update dispatch, got {served_statuses:?}"
    );
}

#[tokio::test]
async fn test_static_bootstrap_convergence_worker_rejects_discovered_peers_on_cluster_id_mismatch()
{
    let peer = "127.0.0.1:31601".to_string();
    let discovered_peer = "127.0.0.1:31602".to_string();
    let peer_view =
        membership_view_id_with_self("maxio-node-b", &[peer.clone(), discovered_peer.clone()]);
    let healthz_peer = start_peer_healthz_stub_with_snapshot(
        peer_view.as_str(),
        Some("cluster-mismatch".to_string()),
        vec![discovered_peer.clone()],
    )
    .await;

    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec![healthz_peer];
    config.membership_protocol = MembershipProtocol::StaticBootstrap;
    let (base_url, _tmp) = start_server_with_config_and_convergence_worker(config, tmp).await;

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let resp = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["clusterPeerCount"].as_u64(), Some(1));
    assert!(body["clusterPeers"].as_array().is_some_and(|peers| {
        peers
            .iter()
            .all(|value| value.as_str() != Some(discovered_peer.as_str()))
    }));
}

#[tokio::test]
async fn test_static_bootstrap_convergence_worker_rejects_discovered_peers_when_cluster_id_missing()
{
    let peer = "127.0.0.1:31611".to_string();
    let discovered_peer = "127.0.0.1:31612".to_string();
    let peer_view =
        membership_view_id_with_self("maxio-node-b", &[peer.clone(), discovered_peer.clone()]);
    let healthz_peer = start_peer_healthz_stub_with_snapshot(
        peer_view.as_str(),
        None,
        vec![discovered_peer.clone()],
    )
    .await;

    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.cluster_peers = vec![healthz_peer];
    config.membership_protocol = MembershipProtocol::StaticBootstrap;
    let (base_url, _tmp) = start_server_with_config_and_convergence_worker(config, tmp).await;

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let resp = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["clusterPeerCount"].as_u64(), Some(1));
    assert!(body["clusterPeers"].as_array().is_some_and(|peers| {
        peers
            .iter()
            .all(|value| value.as_str() != Some(discovered_peer.as_str()))
    }));
}

#[tokio::test]
async fn test_static_bootstrap_convergence_worker_rejects_discovered_peers_when_membership_view_id_missing()
 {
    let discovered_peer = "127.0.0.1:31622".to_string();
    let local_node_id = "maxio-test-node";
    let healthz_peer = start_peer_healthz_stub_with_discovery_snapshot(
        local_node_id,
        "",
        vec![discovered_peer.clone()],
    )
    .await;

    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut config = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config.node_id = local_node_id.to_string();
    config.cluster_peers = vec![healthz_peer];
    config.membership_protocol = MembershipProtocol::StaticBootstrap;
    let (base_url, _tmp) = start_server_with_config_and_convergence_worker(config, tmp).await;

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    let resp = client()
        .get(format!("{}/healthz", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["clusterPeerCount"].as_u64(), Some(1));
    assert!(body["clusterPeers"].as_array().is_some_and(|peers| {
        peers
            .iter()
            .all(|value| value.as_str() != Some(discovered_peer.as_str()))
    }));
}

#[tokio::test]
async fn test_placement_epoch_persists_and_increments_when_membership_view_changes() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();

    let config_a = make_test_config(data_dir.clone(), false, 10 * 1024 * 1024, 0);
    let state_a = AppState::from_config(config_a)
        .await
        .expect("state A should initialize");
    assert_eq!(state_a.placement_epoch(), 0);
    drop(state_a);

    let mut config_b = make_test_config(data_dir.clone(), false, 10 * 1024 * 1024, 0);
    config_b.cluster_peers = vec!["node-b.internal:9000".to_string()];
    let state_b = AppState::from_config(config_b)
        .await
        .expect("state B should initialize");
    assert_eq!(state_b.placement_epoch(), 1);
    drop(state_b);

    let mut config_c = make_test_config(data_dir, false, 10 * 1024 * 1024, 0);
    config_c.cluster_peers = vec!["node-b.internal:9000".to_string()];
    let state_c = AppState::from_config(config_c)
        .await
        .expect("state C should initialize");
    assert_eq!(state_c.placement_epoch(), 1);
}

#[tokio::test]
async fn test_cluster_id_persists_when_membership_view_changes() {
    let tmp = tempfile::TempDir::new().unwrap();
    let data_dir = tmp.path().to_str().unwrap().to_string();

    let config_a = make_test_config(data_dir.clone(), false, 10 * 1024 * 1024, 0);
    let state_a = AppState::from_config(config_a)
        .await
        .expect("state A should initialize");
    let cluster_id_a = state_a.cluster_id.as_ref().clone();
    let membership_view_id_a = membership_view_id_with_self("maxio-test-node", &[]);
    assert_eq!(cluster_id_a, membership_view_id_a);
    drop(state_a);

    let mut config_b = make_test_config(data_dir.clone(), false, 10 * 1024 * 1024, 0);
    config_b.cluster_peers = vec!["node-b.internal:9000".to_string()];
    let state_b = AppState::from_config(config_b)
        .await
        .expect("state B should initialize");
    let cluster_id_b = state_b.cluster_id.as_ref().clone();
    let membership_view_id_b =
        membership_view_id_with_self("maxio-test-node", &["node-b.internal:9000".to_string()]);
    assert_ne!(membership_view_id_a, membership_view_id_b);
    assert_eq!(cluster_id_b, cluster_id_a);
}

#[tokio::test]
async fn test_cors_preflight_s3_without_auth() {
    let (base_url, _tmp) = start_server().await;
    let origin = "https://example.com";
    let resp = client()
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/mybucket/object.txt", base_url),
        )
        .header("origin", origin)
        .header("access-control-request-method", "PUT")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .unwrap()
            .to_str()
            .unwrap(),
        origin
    );
    assert!(
        resp.headers()
            .get("access-control-allow-methods")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("PUT")
    );
    assert_eq!(
        resp.headers()
            .get("access-control-allow-credentials")
            .unwrap()
            .to_str()
            .unwrap(),
        "true"
    );
}

#[tokio::test]
async fn test_cors_preflight_without_origin_uses_wildcard_without_credentials() {
    let (base_url, _tmp) = start_server().await;
    let resp = client()
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/mybucket/object.txt", base_url),
        )
        .header("access-control-request-method", "PUT")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .unwrap()
            .to_str()
            .unwrap(),
        "*"
    );
    assert!(
        resp.headers()
            .get("access-control-allow-credentials")
            .is_none()
    );
}

#[tokio::test]
async fn test_cors_preflight_console_route_without_auth() {
    let (base_url, _tmp) = start_server().await;
    let origin = "https://console.example.com";
    let resp = client()
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/api/auth/check", base_url),
        )
        .header("origin", origin)
        .header("access-control-request-method", "GET")
        .header("access-control-request-headers", "content-type")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .unwrap()
            .to_str()
            .unwrap(),
        origin
    );
    assert_eq!(
        resp.headers()
            .get("access-control-allow-credentials")
            .unwrap()
            .to_str()
            .unwrap(),
        "true"
    );
    let request_id = resp
        .headers()
        .get("x-amz-request-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-amz-request-id");
    uuid::Uuid::parse_str(request_id).expect("request id should be a valid uuid");
}

#[tokio::test]
async fn test_cors_preflight_includes_vary_origin_and_request_id() {
    let (base_url, _tmp) = start_server().await;
    let origin = "https://example.com";
    let resp = client()
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/mybucket/object.txt", base_url),
        )
        .header("origin", origin)
        .header("access-control-request-method", "GET")
        .header(
            "access-control-request-headers",
            "x-amz-date,x-amz-content-sha256",
        )
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);
    let vary = resp.headers().get("vary").unwrap().to_str().unwrap();
    let vary_values: Vec<&str> = vary.split(',').map(|v| v.trim()).collect();
    assert!(vary_values.contains(&"Origin"));
    assert!(vary_values.contains(&"Access-Control-Request-Method"));
    assert!(vary_values.contains(&"Access-Control-Request-Headers"));
    let request_id = resp
        .headers()
        .get("x-amz-request-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-amz-request-id");
    uuid::Uuid::parse_str(request_id).expect("request id should be a valid uuid");
}

#[tokio::test]
async fn test_cors_preflight_reflects_requested_allow_headers() {
    let (base_url, _tmp) = start_server().await;
    let resp = client()
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/api/auth/check", base_url),
        )
        .header("origin", "https://example.com")
        .header("access-control-request-method", "GET")
        .header(
            "access-control-request-headers",
            "x-amz-date, X-Amz-Meta-Filename, X-Custom-Trace",
        )
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);
    let allow_headers = resp
        .headers()
        .get("access-control-allow-headers")
        .and_then(|v| v.to_str().ok())
        .expect("missing access-control-allow-headers");
    let allow_header_values: Vec<&str> = allow_headers.split(',').collect();
    assert!(allow_header_values.contains(&"x-amz-date"));
    assert!(allow_header_values.contains(&"x-amz-meta-filename"));
    assert!(allow_header_values.contains(&"x-custom-trace"));
}

#[tokio::test]
async fn test_cors_headers_present_on_s3_error_response() {
    let (base_url, _tmp) = start_server().await;
    let origin = "https://example.com";
    let resp = client()
        .get(format!("{}/", base_url))
        .header("origin", origin)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .unwrap()
            .to_str()
            .unwrap(),
        origin
    );
    assert_eq!(
        resp.headers()
            .get("access-control-allow-credentials")
            .unwrap()
            .to_str()
            .unwrap(),
        "true"
    );
    assert!(
        resp.headers()
            .get("access-control-expose-headers")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("x-amz-request-id")
    );
}

#[tokio::test]
async fn test_cors_origin_reflection_on_successful_s3_response() {
    let (base_url, _tmp) = start_server().await;
    let origin = "https://example.com";

    let resp = s3_request_with_headers(
        "GET",
        &format!("{}/", base_url),
        vec![],
        vec![("origin", origin)],
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .unwrap()
            .to_str()
            .unwrap(),
        origin
    );
    assert_eq!(
        resp.headers()
            .get("access-control-allow-credentials")
            .unwrap()
            .to_str()
            .unwrap(),
        "true"
    );

    let request_id = resp
        .headers()
        .get("x-amz-request-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-amz-request-id");
    uuid::Uuid::parse_str(request_id).expect("request id should be a valid uuid");
}
