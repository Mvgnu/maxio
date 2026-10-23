use super::*;
use axum::body::Body;
use axum::http::Request;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Instant;
use tower::ServiceExt;

use crate::cluster::join_authorization::InMemoryJoinNonceReplayGuard;
use crate::cluster::transport_identity::{
    PeerTransportIdentityMode, PeerTransportIdentityReadinessReason,
};
use crate::config::{ClusterPeerTransportMode, Config, MembershipProtocol, WriteDurabilityMode};
use crate::membership::{MembershipEngine, MembershipEngineStatus};
use crate::metadata::{
    ClusterMetadataListingStrategy, MetadataReconcileAction, MetadataRepairPlan,
    PendingMetadataRepairPlan, enqueue_pending_metadata_repair_plan_persisted,
};
use crate::storage::filesystem::FilesystemStorage;

fn test_config() -> Config {
    Config {
        port: 9000,
        address: "127.0.0.1".to_string(),
        internal_bind_addr: None,
        data_dir: "./data".to_string(),
        access_key: "root".to_string(),
        secret_key: "root-secret".to_string(),
        additional_credentials: Vec::new(),
        region: "us-east-1".to_string(),
        node_id: "maxio-test-node".to_string(),
        cluster_peers: Vec::new(),
        membership_protocol: MembershipProtocol::StaticBootstrap,
        write_durability_mode: WriteDurabilityMode::DegradedSuccess,
        metadata_listing_strategy: ClusterMetadataListingStrategy::LocalNodeOnly,
        erasure_coding: false,
        chunk_size: 10 * 1024 * 1024,
        parity_shards: 0,
        min_disk_headroom_bytes: 268_435_456,
        pending_replication_due_warning_threshold: None,
        pending_rebalance_due_warning_threshold: None,
        pending_membership_propagation_due_warning_threshold: None,
        pending_metadata_repair_due_warning_threshold: None,
        cluster_auth_token: None,
        tls_cert_path: None,
        tls_key_path: None,
        cluster_peer_tls_cert_path: None,
        cluster_peer_tls_key_path: None,
        cluster_peer_tls_ca_path: None,
        cluster_peer_tls_cert_sha256: None,
        cluster_peer_tls_cert_sha256_revocations: None,
        cluster_peer_transport_mode: ClusterPeerTransportMode::Compatibility,
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

fn distributed_topology_fixture() -> RuntimeTopologySnapshot {
    RuntimeTopologySnapshot {
        mode: RuntimeMode::Distributed,
        node_id: "node-a:9000".to_string(),
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b:9000".to_string()],
        membership_nodes: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
        membership_protocol: MembershipProtocol::StaticBootstrap,
        membership_status: MembershipEngineStatus {
            engine: "static-bootstrap".to_string(),
            protocol: MembershipProtocol::StaticBootstrap.as_str().to_string(),
            ready: true,
            converged: true,
            last_update_unix_ms: 0,
            warning: None,
        },
        membership_view_id: "view-a".to_string(),
        placement_epoch: 1,
    }
}

fn configured_cluster_auth_status(
    transport_identity: PeerTransportIdentityMode,
    transport_ready: bool,
    reason: PeerTransportIdentityReadinessReason,
) -> ClusterPeerAuthStatus {
    ClusterPeerAuthStatus {
        configured: true,
        mode: "shared-token",
        trust_model: "forwarded-by-marker+shared-token",
        transport_identity,
        transport_reason: reason,
        transport_ready,
        identity_bound: false,
        sender_allowlist_bound: true,
        warning: None,
    }
}

#[test]
fn cluster_peer_auth_transport_required_compatibility_none_identity_is_not_required() {
    let mut config = test_config();
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peer_transport_mode = ClusterPeerTransportMode::Compatibility;
    let topology = distributed_topology_fixture();
    let auth_status = configured_cluster_auth_status(
        PeerTransportIdentityMode::None,
        false,
        PeerTransportIdentityReadinessReason::NotConfigured,
    );

    assert!(
        !cluster_peer_auth_transport_policy_assessment(&config, &topology, &auth_status).required
    );
}

#[test]
fn cluster_peer_auth_transport_required_compatibility_mtls_is_required() {
    let mut config = test_config();
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peer_transport_mode = ClusterPeerTransportMode::Compatibility;
    let topology = distributed_topology_fixture();
    let auth_status = configured_cluster_auth_status(
        PeerTransportIdentityMode::MtlsPath,
        true,
        PeerTransportIdentityReadinessReason::Ready,
    );

    assert!(
        cluster_peer_auth_transport_policy_assessment(&config, &topology, &auth_status).required
    );
}

#[test]
fn cluster_peer_auth_transport_required_required_mode_always_requires_transport() {
    let mut config = test_config();
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peer_transport_mode = ClusterPeerTransportMode::Required;
    let topology = distributed_topology_fixture();
    let auth_status = configured_cluster_auth_status(
        PeerTransportIdentityMode::None,
        false,
        PeerTransportIdentityReadinessReason::NotConfigured,
    );

    assert!(
        cluster_peer_auth_transport_policy_assessment(&config, &topology, &auth_status).required
    );
}

#[test]
fn cluster_peer_auth_transport_required_not_required_without_cluster_peers() {
    let mut config = test_config();
    config.cluster_auth_token = Some("shared-secret".to_string());
    config.cluster_peer_transport_mode = ClusterPeerTransportMode::Required;
    let mut topology = distributed_topology_fixture();
    topology.cluster_peers.clear();
    topology.membership_nodes = vec!["node-a:9000".to_string()];
    let auth_status = configured_cluster_auth_status(
        PeerTransportIdentityMode::MtlsPath,
        false,
        PeerTransportIdentityReadinessReason::CertificatePathUnreadable,
    );

    assert!(
        !cluster_peer_auth_transport_policy_assessment(&config, &topology, &auth_status).required
    );
}

#[tokio::test]
async fn build_public_router_excludes_internal_cluster_routes() {
    let temp = tempfile::tempdir().expect("temp dir should create");
    let mut config = test_config();
    config.data_dir = temp.path().to_string_lossy().into_owned();
    let state = AppState::from_config(config)
        .await
        .expect("state bootstrap should succeed");
    let app = build_public_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/internal/cluster/join/authorize")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("router should respond");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn build_internal_router_exposes_only_control_plane_routes() {
    let temp = tempfile::tempdir().expect("temp dir should create");
    let mut config = test_config();
    config.data_dir = temp.path().to_string_lossy().into_owned();
    let state = AppState::from_config(config)
        .await
        .expect("state bootstrap should succeed");
    let app = build_internal_router(state);

    let health_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/healthz")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("router should respond");
    assert_eq!(health_response.status(), StatusCode::NOT_FOUND);

    let internal_response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/internal/cluster/join/authorize")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("router should respond");
    assert_eq!(internal_response.status(), StatusCode::SERVICE_UNAVAILABLE);
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
        HeaderValue::from_static("X-Amz-Date, X-Custom-Trace, x custom invalid, x-custom-trace"),
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
fn membership_protocol_readiness_reports_gossip_as_ready_and_raft_as_not_ready() {
    let (static_ready, static_warning) =
        membership_protocol_readiness(MembershipProtocol::StaticBootstrap);
    assert!(static_ready);
    assert!(static_warning.is_none());

    let (gossip_ready, gossip_warning) = membership_protocol_readiness(MembershipProtocol::Gossip);
    assert!(gossip_ready);
    assert!(
        gossip_warning
            .as_deref()
            .is_some_and(|warning| warning.contains("experimental"))
    );

    let (raft_ready, raft_warning) = membership_protocol_readiness(MembershipProtocol::Raft);
    assert!(!raft_ready);
    assert!(
        raft_warning
            .as_deref()
            .is_some_and(|warning| warning.contains("not implemented"))
    );
}

#[test]
fn membership_propagation_retry_delay_is_bounded_and_exponential() {
    assert_eq!(membership_propagation_retry_delay_ms(1), 100);
    assert_eq!(membership_propagation_retry_delay_ms(2), 200);
    assert_eq!(membership_propagation_retry_delay_ms(3), 400);
    assert_eq!(membership_propagation_retry_delay_ms(10), 1_000);
}

#[test]
fn membership_propagation_retries_only_for_transient_statuses() {
    assert!(should_retry_membership_propagation_status(
        StatusCode::REQUEST_TIMEOUT
    ));
    assert!(should_retry_membership_propagation_status(
        StatusCode::TOO_MANY_REQUESTS
    ));
    assert!(should_retry_membership_propagation_status(
        StatusCode::SERVICE_UNAVAILABLE
    ));
    assert!(!should_retry_membership_propagation_status(
        StatusCode::FORBIDDEN
    ));
    assert!(!should_retry_membership_propagation_status(
        StatusCode::CONFLICT
    ));
}

#[tokio::test]
async fn pending_rebalance_target_is_current_owner_uses_active_membership_projection() {
    let temp = tempfile::tempdir().expect("temp dir should create");
    let data_dir = temp
        .path()
        .to_str()
        .expect("path should be utf8")
        .to_string();
    let mut config = test_config();
    config.data_dir = data_dir;
    config.node_id = "node-a.internal:9000".to_string();
    config.cluster_peers = vec![
        "node-b.internal:9000".to_string(),
        "node-c.internal:9000".to_string(),
    ];
    let state = AppState::from_config(config)
        .await
        .expect("state bootstrap should succeed");
    let peers = state.active_cluster_peers();

    let object_owners = select_object_owners_with_self(
        "docs/report.txt",
        state.node_id.as_ref(),
        peers.as_slice(),
        2,
    );
    let object_owner_target = object_owners
        .iter()
        .find(|owner| !peer_identity_eq(owner.as_str(), state.node_id.as_ref()))
        .cloned()
        .unwrap_or_else(|| {
            object_owners
                .first()
                .cloned()
                .expect("object owner set should include at least one node")
        });
    let object_non_owner_target = membership_with_self(state.node_id.as_ref(), peers.as_slice())
        .into_iter()
        .find(|node| {
            !object_owners
                .iter()
                .any(|owner| peer_identity_eq(owner, node))
        })
        .expect("object owner projection should exclude at least one node");

    let owner_candidate = PendingRebalanceCandidate {
        rebalance_id: "rebalance-owner".to_string(),
        bucket: "photos".to_string(),
        key: "docs/report.txt".to_string(),
        scope: RebalanceObjectScope::Object,
        coordinator_node: "node-a.internal:9000".to_string(),
        placement_epoch: 0,
        placement_view_id: "view-a".to_string(),
        created_at_unix_ms: 1,
        from: Some("node-a.internal:9000".to_string()),
        to: object_owner_target,
        attempts: 0,
        next_retry_at_unix_ms: None,
    };
    assert!(pending_rebalance_target_is_current_owner(
        &state,
        &owner_candidate
    ));

    let mut non_owner_candidate = owner_candidate.clone();
    non_owner_candidate.to = object_non_owner_target;
    assert!(!pending_rebalance_target_is_current_owner(
        &state,
        &non_owner_candidate
    ));

    let chunk_owners = select_chunk_owners_with_self(
        "docs/report.txt",
        3,
        state.node_id.as_ref(),
        peers.as_slice(),
        2,
    );
    let chunk_owner_target = chunk_owners
        .iter()
        .find(|owner| !peer_identity_eq(owner.as_str(), state.node_id.as_ref()))
        .cloned()
        .unwrap_or_else(|| {
            chunk_owners
                .first()
                .cloned()
                .expect("chunk owner set should include at least one node")
        });
    let chunk_non_owner_target = membership_with_self(state.node_id.as_ref(), peers.as_slice())
        .into_iter()
        .find(|node| {
            !chunk_owners
                .iter()
                .any(|owner| peer_identity_eq(owner, node))
        })
        .expect("chunk owner projection should exclude at least one node");
    let mut chunk_owner_candidate = owner_candidate.clone();
    chunk_owner_candidate.scope = RebalanceObjectScope::Chunk { chunk_index: 3 };
    chunk_owner_candidate.to = chunk_owner_target;
    assert!(pending_rebalance_target_is_current_owner(
        &state,
        &chunk_owner_candidate
    ));

    chunk_owner_candidate.to = chunk_non_owner_target;
    assert!(!pending_rebalance_target_is_current_owner(
        &state,
        &chunk_owner_candidate
    ));
}

fn metadata_test_topology(node_id: &str) -> RuntimeTopologySnapshot {
    RuntimeTopologySnapshot {
        mode: RuntimeMode::Distributed,
        node_id: node_id.to_string(),
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b:9000".to_string(), "node-c:9000".to_string()],
        membership_nodes: vec![
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
            "node-c:9000".to_string(),
        ],
        membership_protocol: MembershipProtocol::StaticBootstrap,
        membership_status: MembershipEngine::for_protocol(MembershipProtocol::StaticBootstrap)
            .status(),
        membership_view_id: "view-a".to_string(),
        placement_epoch: 0,
    }
}

#[test]
fn metadata_readiness_uses_strategy_expected_nodes_for_local_and_consensus_modes() {
    let topology = metadata_test_topology("node-a:9000");
    let local_snapshot =
        metadata_snapshot_for_topology(&topology, ClusterMetadataListingStrategy::LocalNodeOnly);
    let local_readiness = local_snapshot.readiness_assessment;
    assert!(!local_readiness.cluster_authoritative);
    assert!(!local_readiness.ready);
    assert_eq!(
        local_readiness.gap,
        Some(crate::metadata::ClusterMetadataReadinessGap::StrategyNotClusterAuthoritative)
    );

    let consensus_snapshot =
        metadata_snapshot_for_topology(&topology, ClusterMetadataListingStrategy::ConsensusIndex);
    let consensus_readiness = consensus_snapshot.readiness_assessment;
    assert!(consensus_readiness.cluster_authoritative);
    assert!(!consensus_readiness.ready);
    assert_eq!(
        consensus_readiness.gap,
        Some(crate::metadata::ClusterMetadataReadinessGap::MissingExpectedNodes)
    );
}

#[test]
fn metadata_readiness_keeps_authoritative_strategies_not_ready_until_cluster_fan_in_exists() {
    let topology = metadata_test_topology("node-a:9000");
    let aggregation_snapshot = metadata_snapshot_for_topology(
        &topology,
        ClusterMetadataListingStrategy::RequestTimeAggregation,
    );
    let aggregation_readiness = aggregation_snapshot.readiness_assessment;
    assert!(aggregation_readiness.cluster_authoritative);
    assert!(!aggregation_readiness.ready);
    assert_eq!(
        aggregation_readiness.gap,
        Some(crate::metadata::ClusterMetadataReadinessGap::MissingExpectedNodes)
    );

    let full_replication_snapshot =
        metadata_snapshot_for_topology(&topology, ClusterMetadataListingStrategy::FullReplication);
    let full_replication_readiness = full_replication_snapshot.readiness_assessment;
    assert!(full_replication_readiness.cluster_authoritative);
    assert!(!full_replication_readiness.ready);
    assert_eq!(
        full_replication_readiness.gap,
        Some(crate::metadata::ClusterMetadataReadinessGap::MissingExpectedNodes)
    );
}

#[tokio::test]
async fn metadata_readiness_probe_bounds_hanging_peer_requests() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer = listener.local_addr().unwrap();
    let app = Router::new().route(
        "/",
        get(|| async {
            std::future::pending::<()>().await;
            StatusCode::OK
        }),
    );
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let temp = tempfile::tempdir().unwrap();
    let mut config = test_config();
    config.node_id = "node-a.internal:9000".into();
    config.data_dir = temp.path().to_string_lossy().into_owned();
    config.cluster_peers = vec![peer.to_string()];
    config.cluster_auth_token = Some("readiness-test-token".into());
    config.metadata_listing_strategy = ClusterMetadataListingStrategy::RequestTimeAggregation;
    let state = AppState::from_config(config).await.unwrap();
    let topology = runtime_topology_snapshot(&state);
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        probe_metadata_listing(&state, &topology, true),
    )
    .await
    .expect("readiness must have a total timeout shorter than peer request timeouts");
    server.abort();
    assert_eq!(result.status, "timed-out");
    assert_eq!(result.scope, "list-buckets-fan-in");
    assert_eq!(result.snapshot.coverage_assessment.responded_nodes, 1);
    assert!(!result.snapshot.readiness_assessment.ready);
}

#[test]
fn membership_update_precondition_failed_detects_view_or_epoch_mismatch() {
    let topology = RuntimeTopologySnapshot {
        mode: RuntimeMode::Distributed,
        node_id: "node-a:9000".to_string(),
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b:9000".to_string()],
        membership_nodes: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
        membership_protocol: MembershipProtocol::StaticBootstrap,
        membership_status: MembershipEngine::for_protocol(MembershipProtocol::StaticBootstrap)
            .status(),
        membership_view_id: "view-current".to_string(),
        placement_epoch: 42,
    };

    assert!(!membership_update_precondition_failed(
        &topology,
        Some("view-current"),
        Some(42),
    ));
    assert!(membership_update_precondition_failed(
        &topology,
        Some("view-stale"),
        Some(42),
    ));
    assert!(membership_update_precondition_failed(
        &topology,
        Some("view-current"),
        Some(41),
    ));
    assert!(membership_update_precondition_failed(
        &topology,
        Some("view-stale"),
        Some(41),
    ));
    assert!(!membership_update_precondition_failed(
        &topology, None, None
    ));
}

#[test]
fn normalize_cluster_peers_for_membership_update_rejects_local_node_case_variants() {
    let result = normalize_cluster_peers_for_membership_update(
        "Node-A.Internal:9000",
        &["node-a.internal:9000".to_string()],
    );
    assert!(result.is_err());
}

#[test]
fn normalize_cluster_peers_for_membership_update_dedupes_case_variant_peers() {
    let peers = normalize_cluster_peers_for_membership_update(
        "node-a.internal:9000",
        &[
            "Node-B.Internal:9001".to_string(),
            "node-b.internal:9001".to_string(),
        ],
    )
    .expect("peer normalization should succeed");
    assert_eq!(peers.len(), 1);
}

#[tokio::test]
async fn apply_membership_peers_serializes_concurrent_transitions_and_preserves_epoch_monotonicity()
{
    let temp = tempfile::tempdir().expect("temp dir should create");
    let data_dir = temp
        .path()
        .to_str()
        .expect("path should be utf8")
        .to_string();
    let mut config = test_config();
    config.data_dir = data_dir.clone();
    config.node_id = "node-a.internal:9000".to_string();
    config.cluster_peers = vec!["node-b.internal:9001".to_string()];
    let state = AppState::from_config(config)
        .await
        .expect("state bootstrap should succeed");

    let initial_topology = runtime_topology_snapshot(&state);
    assert_eq!(initial_topology.placement_epoch, 0);

    let state_a = state.clone();
    let state_b = state.clone();
    let apply_a = tokio::spawn(async move {
        state_a
            .apply_membership_peers(vec!["node-c.internal:9002".to_string()])
            .await
            .expect("first membership apply should succeed")
    });
    let apply_b = tokio::spawn(async move {
        state_b
            .apply_membership_peers(vec!["node-d.internal:9003".to_string()])
            .await
            .expect("second membership apply should succeed")
    });
    let _ = apply_a
        .await
        .expect("first membership task should complete");
    let _ = apply_b
        .await
        .expect("second membership task should complete");

    let updated_topology = runtime_topology_snapshot(&state);
    assert_eq!(updated_topology.placement_epoch, 2);

    let persisted = read_persisted_placement_state(&placement_state_path(data_dir.as_str()))
        .await
        .expect("state read should succeed")
        .expect("state should exist");
    assert_eq!(persisted.epoch, 2);
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
async fn cluster_id_bootstrap_initializes_state_when_missing() {
    let temp = tempfile::tempdir().expect("temp dir should create");
    let data_dir = temp.path().to_str().expect("path should be utf8");

    let cluster_id = load_or_bootstrap_cluster_id(data_dir, "cluster-seed-a")
        .await
        .expect("cluster id bootstrap should succeed");
    assert_eq!(cluster_id, "cluster-seed-a");

    let persisted = read_persisted_cluster_identity_state(&cluster_identity_state_path(data_dir))
        .await
        .expect("cluster identity state read should succeed")
        .expect("cluster identity state should exist");
    assert_eq!(persisted.cluster_id, "cluster-seed-a");
}

#[tokio::test]
async fn cluster_id_bootstrap_remains_stable_across_seed_changes() {
    let temp = tempfile::tempdir().expect("temp dir should create");
    let data_dir = temp.path().to_str().expect("path should be utf8");

    let cluster_id_a = load_or_bootstrap_cluster_id(data_dir, "cluster-seed-a")
        .await
        .expect("cluster id bootstrap should succeed");
    let cluster_id_b = load_or_bootstrap_cluster_id(data_dir, "cluster-seed-b")
        .await
        .expect("cluster id reload should succeed");

    assert_eq!(cluster_id_a, "cluster-seed-a");
    assert_eq!(cluster_id_b, cluster_id_a);
}

#[test]
fn validate_cluster_id_binding_accepts_matching_configured_identity() {
    assert!(validate_cluster_id_binding("cluster-main", Some("cluster-main")).is_ok());
    assert!(validate_cluster_id_binding("cluster-main", None).is_ok());
}

#[test]
fn validate_cluster_id_binding_rejects_mismatched_configured_identity() {
    let err = validate_cluster_id_binding("cluster-seed-a", Some("cluster-override"))
        .expect_err("binding should reject mismatched configured identity");
    assert!(
        err.to_string().contains("Configured cluster id"),
        "unexpected mismatch error: {err}"
    );
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
    // Use a fixed maximal threshold so the assertion is stable even if free space
    // changes between probe calls in CI/containerized filesystems.
    let required = u64::MAX;

    let probe = probe_disk_headroom(path, required);
    assert!(!probe.sufficient);
    assert!(
        probe
            .warning
            .as_deref()
            .is_some_and(|warning| warning.contains("Disk headroom below threshold"))
    );
}

#[test]
fn probe_pending_replication_queue_reports_readable_for_missing_queue_file() {
    let temp = tempfile::tempdir().expect("temp dir should create");
    let data_dir = temp.path().to_str().expect("path should be utf8");

    let probe = probe_pending_replication_queue(data_dir);
    assert!(probe.readable);
    assert_eq!(probe.summary.operations, 0);
    assert_eq!(probe.summary.pending_targets, 0);
    assert_eq!(probe.summary.failed_targets, 0);
    assert_eq!(probe.summary.max_attempts, 0);
    assert_eq!(probe.summary.oldest_created_at_unix_ms, None);
    assert_eq!(probe.due_targets, 0);
    assert!(!probe.due_targets_capped);
    assert!(probe.warning.is_none());
}

#[test]
fn probe_pending_replication_queue_reports_warning_for_invalid_queue_payload() {
    let temp = tempfile::tempdir().expect("temp dir should create");
    let data_dir = temp.path().to_str().expect("path should be utf8");
    let queue_path = pending_replication_queue_path(data_dir);
    std::fs::create_dir_all(
        queue_path
            .parent()
            .expect("pending replication queue path should have a parent"),
    )
    .expect("pending replication runtime directory should be creatable");
    std::fs::write(&queue_path, b"{invalid-json").expect("invalid queue payload should be written");

    let probe = probe_pending_replication_queue(data_dir);
    assert!(!probe.readable);
    assert_eq!(probe.summary.operations, 0);
    assert_eq!(probe.summary.pending_targets, 0);
    assert_eq!(probe.summary.failed_targets, 0);
    assert_eq!(probe.summary.max_attempts, 0);
    assert_eq!(probe.summary.oldest_created_at_unix_ms, None);
    assert_eq!(probe.due_targets, 0);
    assert!(!probe.due_targets_capped);
    assert!(
        probe
            .warning
            .as_deref()
            .is_some_and(|warning| warning.contains("Pending replication queue probe failed"))
    );
}

#[test]
fn probe_pending_rebalance_queue_reports_readable_for_missing_queue_file() {
    let temp = tempfile::tempdir().expect("temp dir should create");
    let data_dir = temp.path().to_str().expect("path should be utf8");

    let probe = probe_pending_rebalance_queue(data_dir);
    assert!(probe.readable);
    assert_eq!(probe.summary.operations, 0);
    assert_eq!(probe.summary.pending_transfers, 0);
    assert_eq!(probe.summary.failed_transfers, 0);
    assert_eq!(probe.summary.max_attempts, 0);
    assert_eq!(probe.summary.oldest_created_at_unix_ms, None);
    assert_eq!(probe.due_transfers, 0);
    assert!(!probe.due_transfers_capped);
    assert!(probe.warning.is_none());
}

#[test]
fn probe_pending_rebalance_queue_reports_warning_for_invalid_queue_payload() {
    let temp = tempfile::tempdir().expect("temp dir should create");
    let data_dir = temp.path().to_str().expect("path should be utf8");
    let queue_path = pending_rebalance_queue_path(data_dir);
    std::fs::create_dir_all(
        queue_path
            .parent()
            .expect("pending rebalance queue path should have a parent"),
    )
    .expect("pending rebalance runtime directory should be creatable");
    std::fs::write(&queue_path, b"{invalid-json").expect("invalid queue payload should be written");

    let probe = probe_pending_rebalance_queue(data_dir);
    assert!(!probe.readable);
    assert_eq!(probe.summary.operations, 0);
    assert_eq!(probe.summary.pending_transfers, 0);
    assert_eq!(probe.summary.failed_transfers, 0);
    assert_eq!(probe.summary.max_attempts, 0);
    assert_eq!(probe.summary.oldest_created_at_unix_ms, None);
    assert_eq!(probe.due_transfers, 0);
    assert!(!probe.due_transfers_capped);
    assert!(
        probe
            .warning
            .as_deref()
            .is_some_and(|warning| warning.contains("Pending rebalance queue probe failed"))
    );
}

#[test]
fn probe_pending_metadata_repair_queue_reports_readable_for_missing_queue_file() {
    let temp = tempfile::tempdir().expect("temp dir should create");
    let data_dir = temp.path().to_str().expect("path should be utf8");

    let probe = probe_pending_metadata_repair_queue(data_dir);
    assert!(probe.readable);
    assert_eq!(probe.summary.plans, 0);
    assert_eq!(probe.summary.due_plans, 0);
    assert_eq!(probe.summary.failed_plans, 0);
    assert_eq!(probe.summary.max_attempts, 0);
    assert_eq!(probe.summary.oldest_created_at_unix_ms, None);
    assert_eq!(probe.due_plans, 0);
    assert!(!probe.due_plans_capped);
    assert!(probe.warning.is_none());
}

#[test]
fn probe_pending_metadata_repair_queue_reports_warning_for_invalid_queue_payload() {
    let temp = tempfile::tempdir().expect("temp dir should create");
    let data_dir = temp.path().to_str().expect("path should be utf8");
    let queue_path = pending_metadata_repair_queue_path(data_dir);
    std::fs::create_dir_all(
        queue_path
            .parent()
            .expect("pending metadata repair queue path should have a parent"),
    )
    .expect("pending metadata repair runtime directory should be creatable");
    std::fs::write(&queue_path, b"{invalid-json").expect("invalid queue payload should be written");

    let probe = probe_pending_metadata_repair_queue(data_dir);
    assert!(!probe.readable);
    assert_eq!(probe.summary.plans, 0);
    assert_eq!(probe.summary.due_plans, 0);
    assert_eq!(probe.summary.failed_plans, 0);
    assert_eq!(probe.summary.max_attempts, 0);
    assert_eq!(probe.summary.oldest_created_at_unix_ms, None);
    assert_eq!(probe.due_plans, 0);
    assert!(!probe.due_plans_capped);
    assert!(
        probe.warning.as_deref().is_some_and(|warning| {
            warning.contains("Pending metadata repair queue probe failed")
        })
    );
}

#[test]
fn probe_pending_metadata_repair_queue_reports_due_plan_counts() {
    let temp = tempfile::tempdir().expect("temp dir should create");
    let data_dir = temp.path().to_str().expect("path should be utf8");
    let queue_path = pending_metadata_repair_queue_path(data_dir);
    let pending_plan = PendingMetadataRepairPlan::new(
        "repair-server-probe-test",
        1,
        MetadataRepairPlan {
            source_view_id: "view-source".to_string(),
            target_view_id: "view-target".to_string(),
            actions: vec![MetadataReconcileAction::UpsertBucket {
                bucket: "photos".to_string(),
                versioning_enabled: false,
                lifecycle_enabled: false,
            }],
        },
    )
    .expect("pending metadata repair plan should be valid");
    enqueue_pending_metadata_repair_plan_persisted(queue_path.as_path(), pending_plan)
        .expect("pending metadata repair plan should enqueue");

    let probe = probe_pending_metadata_repair_queue(data_dir);
    assert!(probe.readable);
    assert_eq!(probe.summary.plans, 1);
    assert_eq!(probe.summary.due_plans, 1);
    assert_eq!(probe.due_plans, 1);
    assert!(!probe.due_plans_capped);
    assert!(probe.warning.is_none());
}

#[tokio::test]
async fn probe_peer_connectivity_reports_ready_when_no_peers_configured() {
    let result = probe_peer_connectivity(&[], None).await;
    assert!(result.ready);
    assert!(result.warning.is_none());
}

#[tokio::test]
async fn probe_peer_connectivity_reports_warning_for_unreachable_peers() {
    let peers = vec!["127.0.0.1:1".to_string()];
    let result = probe_peer_connectivity(peers.as_slice(), None).await;
    assert!(!result.ready);
    assert!(result.peer_views.is_empty());
    assert!(
        result
            .warning
            .as_deref()
            .is_some_and(|warning| warning.contains("Peer connectivity probe failed"))
    );
}

#[tokio::test]
async fn probe_peer_connectivity_reports_warning_when_mtls_transport_not_ready() {
    let peers = vec!["127.0.0.1:1".to_string()];
    let mut config = test_config();
    config.cluster_peer_tls_cert_path = Some("/tmp/maxio-missing-peer-cert.pem".to_string());
    config.cluster_peer_tls_key_path = Some("/tmp/maxio-missing-peer-key.pem".to_string());
    config.cluster_peer_tls_ca_path = Some("/tmp/maxio-missing-peer-ca.pem".to_string());

    let result = probe_peer_connectivity(peers.as_slice(), Some(&config)).await;
    assert!(!result.ready);
    assert!(result.peer_views.is_empty());
    assert!(
        result
            .warning
            .as_deref()
            .is_some_and(|warning| { warning.contains("mTLS peer transport is not ready") })
    );
}

#[test]
fn build_peer_http_transport_uses_https_when_mtls_identity_is_configured() {
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::extension::{
        BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    };
    use openssl::x509::{X509, X509NameBuilder};

    let ca_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "MaxIO test CA").unwrap();
    let ca_name = name.build();
    let before = Asn1Time::days_from_now(0).unwrap();
    let after = Asn1Time::days_from_now(1).unwrap();
    let mut ca = X509::builder().unwrap();
    ca.set_version(2).unwrap();
    ca.set_serial_number(
        BigNum::from_u32(1)
            .unwrap()
            .to_asn1_integer()
            .unwrap()
            .as_ref(),
    )
    .unwrap();
    ca.set_subject_name(&ca_name).unwrap();
    ca.set_issuer_name(&ca_name).unwrap();
    ca.set_pubkey(&ca_key).unwrap();
    ca.set_not_before(&before).unwrap();
    ca.set_not_after(&after).unwrap();
    ca.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    ca.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .unwrap(),
    )
    .unwrap();
    ca.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let ca = ca.build();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "MaxIO runtime peer")
        .unwrap();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(
        BigNum::from_u32(2)
            .unwrap()
            .to_asn1_integer()
            .unwrap()
            .as_ref(),
    )
    .unwrap();
    cert.set_subject_name(&name.build()).unwrap();
    cert.set_issuer_name(ca.subject_name()).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&before).unwrap();
    cert.set_not_after(&after).unwrap();
    cert.append_extension(BasicConstraints::new().critical().build().unwrap())
        .unwrap();
    cert.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build()
            .unwrap(),
    )
    .unwrap();
    cert.append_extension(
        ExtendedKeyUsage::new()
            .server_auth()
            .client_auth()
            .build()
            .unwrap(),
    )
    .unwrap();
    let san = SubjectAlternativeName::new()
        .ip("127.0.0.1")
        .uri("maxio://127.0.0.1:9000")
        .build(&cert.x509v3_context(Some(&ca), None))
        .unwrap();
    cert.append_extension(san).unwrap();
    cert.sign(&ca_key, MessageDigest::sha256()).unwrap();

    let temp = tempfile::tempdir().unwrap();
    let cert_path = temp.path().join("peer.crt");
    let key_path = temp.path().join("peer.key");
    let ca_path = temp.path().join("ca.pem");
    std::fs::write(&cert_path, cert.build().to_pem().unwrap()).unwrap();
    std::fs::write(&key_path, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    std::fs::write(&ca_path, ca.to_pem().unwrap()).unwrap();
    let mut config = test_config();
    config.node_id = "127.0.0.1:9000".into();
    config.cluster_peer_tls_cert_path = Some(cert_path.to_string_lossy().into_owned());
    config.cluster_peer_tls_key_path = Some(key_path.to_string_lossy().into_owned());
    config.cluster_peer_tls_ca_path = Some(ca_path.to_string_lossy().into_owned());
    let transport =
        build_peer_http_transport(Some(&config), "127.0.0.1:9001", Duration::from_secs(1))
            .expect("valid peer identity should initialize a target-bound HTTPS client");
    assert_eq!(transport.scheme, "https");
    assert_eq!(ServerTls::from_config(&config).unwrap().scheme(), "https");
}

#[test]
fn build_peer_http_transport_rejects_missing_mtls_when_required_policy_is_active() {
    let mut config = test_config();
    config.cluster_auth_token = Some("shared-token".to_string());
    config.cluster_peer_transport_mode = ClusterPeerTransportMode::Required;
    config.cluster_peers = vec!["node-b.internal:9000".to_string()];
    let err = build_peer_http_transport(
        Some(&config),
        "node-b.internal:9000",
        Duration::from_secs(1),
    )
    .err()
    .expect("required policy must reject missing mTLS");
    assert!(err.contains("requires ready peer transport identity"));
    assert!(err.contains("not_configured"));
}

#[test]
fn required_peer_transport_cannot_hide_behind_empty_peers_or_missing_token() {
    let mut config = test_config();
    config.cluster_peer_transport_mode = ClusterPeerTransportMode::Required;
    let error = ServerTls::from_config(&config)
        .err()
        .expect("token is required even with zero peers");
    assert!(error.contains("--cluster-auth-token"));
    config.cluster_auth_token = Some("shared-token".into());
    let error = ServerTls::from_config(&config)
        .err()
        .expect("TLS is required even with zero peers");
    assert!(error.contains("not_configured"));
}

#[test]
fn native_tls_rejects_partial_conflicting_and_distributed_standalone_settings() {
    assert_eq!(
        ServerTls::from_config(&test_config()).unwrap().scheme(),
        "http"
    );
    let mut config = test_config();
    config.tls_cert_path = Some("missing.crt".into());
    assert!(
        ServerTls::from_config(&config)
            .err()
            .unwrap()
            .contains("both --tls-cert-path")
    );
    config.tls_key_path = Some("missing.key".into());
    assert!(
        ServerTls::from_config(&config)
            .err()
            .unwrap()
            .contains("invalid native HTTPS")
    );
    config.cluster_peers = vec!["node-b:9000".into()];
    assert!(
        ServerTls::from_config(&config)
            .err()
            .unwrap()
            .contains("use the cluster peer TLS")
    );
    config.cluster_peer_tls_cert_path = Some("peer.crt".into());
    config.cluster_peer_tls_key_path = Some("peer.key".into());
    config.cluster_peer_tls_ca_path = Some("ca.pem".into());
    assert!(
        ServerTls::from_config(&config)
            .err()
            .unwrap()
            .contains("mutually exclusive")
    );
    config.tls_cert_path = None;
    config.tls_key_path = None;
    config.cluster_peer_tls_key_path = None;
    assert!(
        ServerTls::from_config(&config)
            .err()
            .unwrap()
            .contains("all three")
    );
}

#[tokio::test]
async fn internal_protocol_headers_cannot_substitute_for_connection_identity() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = test_config();
    config.data_dir = temp.path().to_string_lossy().into_owned();
    config.node_id = "node-a:9000".into();
    config.cluster_peers = vec!["node-b:9000".into()];
    config.cluster_auth_token = Some("shared-token".into());
    config.cluster_peer_tls_cert_path = Some("diagnostic-only-unreadable.crt".into());
    let app = build_router(AppState::from_config(config).await.unwrap());
    for path in [
        "/ui/",
        "/internal/cluster/join/authorize",
        "/guard-bucket/object",
    ] {
        let mut request = Request::builder()
            .method("POST")
            .uri(path)
            .header(FORWARDED_BY_HEADER, "node-b:9000")
            .header(INTERNAL_AUTH_TOKEN_HEADER, "shared-token")
            .header("x-forwarded-proto", "https")
            .body(Body::empty())
            .unwrap();
        // Even a TLS-only marker is not a peer certificate identity.
        request.extensions_mut().insert(TlsConnection);
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
    }
}

#[test]
fn probe_membership_convergence_reports_false_for_static_bootstrap_view_mismatch() {
    let membership_status = MembershipEngineStatus {
        engine: "static-bootstrap".to_string(),
        protocol: MembershipProtocol::StaticBootstrap.as_str().to_string(),
        ready: true,
        converged: true,
        last_update_unix_ms: 1234,
        warning: None,
    };
    let topology = RuntimeTopologySnapshot {
        mode: RuntimeMode::Distributed,
        node_id: "node-a".to_string(),
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b".to_string()],
        membership_nodes: vec!["node-a".to_string(), "node-b".to_string()],
        membership_protocol: MembershipProtocol::StaticBootstrap,
        membership_status: membership_status.clone(),
        membership_view_id: "view-local".to_string(),
        placement_epoch: 3,
    };
    let peer_probe = PeerConnectivityProbeResult {
        ready: true,
        warning: None,
        peer_views: vec![PeerViewObservation {
            peer: "node-b".to_string(),
            membership_view_id: Some("view-other".to_string()),
            placement_epoch: None,
            cluster_id: None,
            cluster_peers: Vec::new(),
        }],
        failed_peers: Vec::new(),
    };

    let convergence = probe_membership_convergence(&topology, &membership_status, &peer_probe);
    assert!(!convergence.converged);
    assert!(
        convergence
            .warning
            .as_deref()
            .is_some_and(|warning| warning.contains("Membership view mismatch detected"))
    );
}

#[test]
fn probe_membership_convergence_reports_true_for_matching_static_bootstrap_views() {
    let membership_status = MembershipEngineStatus {
        engine: "static-bootstrap".to_string(),
        protocol: MembershipProtocol::StaticBootstrap.as_str().to_string(),
        ready: true,
        converged: true,
        last_update_unix_ms: 1234,
        warning: None,
    };
    let topology = RuntimeTopologySnapshot {
        mode: RuntimeMode::Distributed,
        node_id: "node-a".to_string(),
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b".to_string()],
        membership_nodes: vec!["node-a".to_string(), "node-b".to_string()],
        membership_protocol: MembershipProtocol::StaticBootstrap,
        membership_status: membership_status.clone(),
        membership_view_id: "view-local".to_string(),
        placement_epoch: 3,
    };
    let peer_probe = PeerConnectivityProbeResult {
        ready: true,
        warning: None,
        peer_views: vec![PeerViewObservation {
            peer: "node-b".to_string(),
            membership_view_id: Some("view-local".to_string()),
            placement_epoch: None,
            cluster_id: None,
            cluster_peers: Vec::new(),
        }],
        failed_peers: Vec::new(),
    };

    let convergence = probe_membership_convergence(&topology, &membership_status, &peer_probe);
    assert!(convergence.converged);
    assert!(convergence.warning.is_none());
}

#[test]
fn probe_membership_convergence_reports_false_for_static_bootstrap_epoch_mismatch() {
    let membership_status = MembershipEngineStatus {
        engine: "static-bootstrap".to_string(),
        protocol: MembershipProtocol::StaticBootstrap.as_str().to_string(),
        ready: true,
        converged: true,
        last_update_unix_ms: 1234,
        warning: None,
    };
    let topology = RuntimeTopologySnapshot {
        mode: RuntimeMode::Distributed,
        node_id: "node-a".to_string(),
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b".to_string()],
        membership_nodes: vec!["node-a".to_string(), "node-b".to_string()],
        membership_protocol: MembershipProtocol::StaticBootstrap,
        membership_status: membership_status.clone(),
        membership_view_id: "view-local".to_string(),
        placement_epoch: 3,
    };
    let peer_probe = PeerConnectivityProbeResult {
        ready: true,
        warning: None,
        peer_views: vec![PeerViewObservation {
            peer: "node-b".to_string(),
            membership_view_id: Some("view-local".to_string()),
            placement_epoch: Some(9),
            cluster_id: None,
            cluster_peers: Vec::new(),
        }],
        failed_peers: Vec::new(),
    };

    let convergence = probe_membership_convergence(&topology, &membership_status, &peer_probe);
    assert!(!convergence.converged);
    assert_eq!(convergence.reason, "placement-epoch-mismatch");
    assert!(
        convergence
            .warning
            .as_deref()
            .is_some_and(|warning| warning.contains("Placement epoch mismatch detected"))
    );
}

#[test]
fn probe_membership_convergence_rechecks_static_bootstrap_after_cached_non_converged_state() {
    let membership_status = MembershipEngineStatus {
        engine: "static-bootstrap".to_string(),
        protocol: MembershipProtocol::StaticBootstrap.as_str().to_string(),
        ready: true,
        converged: false,
        last_update_unix_ms: 1234,
        warning: None,
    };
    let topology = RuntimeTopologySnapshot {
        mode: RuntimeMode::Distributed,
        node_id: "node-a".to_string(),
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b".to_string()],
        membership_nodes: vec!["node-a".to_string(), "node-b".to_string()],
        membership_protocol: MembershipProtocol::StaticBootstrap,
        membership_status: membership_status.clone(),
        membership_view_id: "view-local".to_string(),
        placement_epoch: 3,
    };
    let peer_probe = PeerConnectivityProbeResult {
        ready: true,
        warning: None,
        peer_views: vec![PeerViewObservation {
            peer: "node-b".to_string(),
            membership_view_id: Some("view-local".to_string()),
            placement_epoch: None,
            cluster_id: None,
            cluster_peers: Vec::new(),
        }],
        failed_peers: Vec::new(),
    };

    let convergence = probe_membership_convergence(&topology, &membership_status, &peer_probe);
    assert!(convergence.converged);
    assert!(convergence.warning.is_none());
}

#[test]
fn probe_membership_convergence_requires_peer_probe_for_gossip_when_distributed() {
    let membership_status = MembershipEngine::for_protocol(MembershipProtocol::Gossip).status();
    let topology = RuntimeTopologySnapshot {
        mode: RuntimeMode::Distributed,
        node_id: "node-a".to_string(),
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b".to_string()],
        membership_nodes: vec!["node-a".to_string(), "node-b".to_string()],
        membership_protocol: MembershipProtocol::Gossip,
        membership_status: membership_status.clone(),
        membership_view_id: "view-local".to_string(),
        placement_epoch: 3,
    };
    let peer_probe = PeerConnectivityProbeResult {
        ready: false,
        warning: Some("node-b probe failed".to_string()),
        peer_views: Vec::new(),
        failed_peers: vec!["node-b".to_string()],
    };

    let convergence = probe_membership_convergence(&topology, &membership_status, &peer_probe);
    assert!(!convergence.converged);
    assert_eq!(convergence.reason, "peer-connectivity-failed");
}

#[test]
fn derive_membership_discovery_cluster_peers_returns_updated_union_for_matching_cluster() {
    let membership_status = MembershipEngineStatus {
        engine: "static-bootstrap".to_string(),
        protocol: MembershipProtocol::StaticBootstrap.as_str().to_string(),
        ready: true,
        converged: true,
        last_update_unix_ms: 1234,
        warning: None,
    };
    let topology = RuntimeTopologySnapshot {
        mode: RuntimeMode::Distributed,
        node_id: "node-a:9000".to_string(),
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b:9000".to_string()],
        membership_nodes: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
        membership_protocol: MembershipProtocol::StaticBootstrap,
        membership_status,
        membership_view_id: "view-local".to_string(),
        placement_epoch: 3,
    };
    let peer_probe = PeerConnectivityProbeResult {
        ready: true,
        warning: None,
        peer_views: vec![PeerViewObservation {
            peer: "node-b:9000".to_string(),
            membership_view_id: Some("view-local".to_string()),
            placement_epoch: None,
            cluster_id: Some("cluster-a".to_string()),
            cluster_peers: vec!["NODE-A:09000".to_string(), "node-c:9000".to_string()],
        }],
        failed_peers: Vec::new(),
    };

    let discovered = derive_membership_discovery_cluster_peers(&topology, &peer_probe)
        .expect("matching cluster id snapshot should be accepted");
    assert_eq!(
        discovered,
        Some(vec!["node-b:9000".to_string(), "node-c:9000".to_string()])
    );
}

#[test]
fn derive_membership_discovery_cluster_peers_accepts_gossip_when_engine_ready() {
    let membership_status = MembershipEngine::for_protocol(MembershipProtocol::Gossip).status();
    let topology = RuntimeTopologySnapshot {
        mode: RuntimeMode::Distributed,
        node_id: "node-a:9000".to_string(),
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b:9000".to_string()],
        membership_nodes: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
        membership_protocol: MembershipProtocol::Gossip,
        membership_status,
        membership_view_id: "view-local".to_string(),
        placement_epoch: 3,
    };
    let peer_probe = PeerConnectivityProbeResult {
        ready: true,
        warning: None,
        peer_views: vec![PeerViewObservation {
            peer: "node-b:9000".to_string(),
            membership_view_id: Some("view-local".to_string()),
            placement_epoch: None,
            cluster_id: Some("cluster-a".to_string()),
            cluster_peers: vec!["node-c:9000".to_string()],
        }],
        failed_peers: Vec::new(),
    };

    let discovered = derive_membership_discovery_cluster_peers(&topology, &peer_probe)
        .expect("matching cluster id snapshot should be accepted");
    assert_eq!(
        discovered,
        Some(vec!["node-b:9000".to_string(), "node-c:9000".to_string()])
    );
}

#[test]
fn derive_membership_discovery_cluster_peers_prunes_failed_gossip_peer_when_not_observed() {
    let membership_status = MembershipEngine::for_protocol(MembershipProtocol::Gossip).status();
    let topology = RuntimeTopologySnapshot {
        mode: RuntimeMode::Distributed,
        node_id: "node-a:9000".to_string(),
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b:9000".to_string(), "node-c:9000".to_string()],
        membership_nodes: vec![
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
            "node-c:9000".to_string(),
        ],
        membership_protocol: MembershipProtocol::Gossip,
        membership_status,
        membership_view_id: "view-local".to_string(),
        placement_epoch: 3,
    };
    let peer_probe = PeerConnectivityProbeResult {
        ready: false,
        warning: Some("node-c:9000 probe failed".to_string()),
        peer_views: vec![PeerViewObservation {
            peer: "node-b:9000".to_string(),
            membership_view_id: Some("view-local".to_string()),
            placement_epoch: None,
            cluster_id: Some("cluster-a".to_string()),
            cluster_peers: vec!["node-b:9000".to_string()],
        }],
        failed_peers: vec!["node-c:9000".to_string()],
    };

    let discovered = derive_membership_discovery_cluster_peers(&topology, &peer_probe)
        .expect("matching cluster id snapshot should be accepted");
    assert_eq!(discovered, Some(vec!["node-b:9000".to_string()]));
}

#[test]
fn derive_membership_discovery_cluster_peers_keeps_failed_gossip_peer_when_still_observed() {
    let membership_status = MembershipEngine::for_protocol(MembershipProtocol::Gossip).status();
    let topology = RuntimeTopologySnapshot {
        mode: RuntimeMode::Distributed,
        node_id: "node-a:9000".to_string(),
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b:9000".to_string(), "node-c:9000".to_string()],
        membership_nodes: vec![
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
            "node-c:9000".to_string(),
        ],
        membership_protocol: MembershipProtocol::Gossip,
        membership_status,
        membership_view_id: "view-local".to_string(),
        placement_epoch: 3,
    };
    let peer_probe = PeerConnectivityProbeResult {
        ready: false,
        warning: Some("node-c:9000 probe failed".to_string()),
        peer_views: vec![PeerViewObservation {
            peer: "node-b:9000".to_string(),
            membership_view_id: Some("view-local".to_string()),
            placement_epoch: None,
            cluster_id: Some("cluster-a".to_string()),
            cluster_peers: vec!["node-c:9000".to_string()],
        }],
        failed_peers: vec!["node-c:9000".to_string()],
    };

    let discovered = derive_membership_discovery_cluster_peers(&topology, &peer_probe)
        .expect("matching cluster id snapshot should be accepted");
    assert_eq!(discovered, None);
}

#[test]
fn derive_gossip_stale_peer_reconciliation_targets_returns_stale_peer_with_epoch() {
    let membership_status = MembershipEngine::for_protocol(MembershipProtocol::Gossip).status();
    let topology = RuntimeTopologySnapshot {
        mode: RuntimeMode::Distributed,
        node_id: "node-a:9000".to_string(),
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b:9000".to_string()],
        membership_nodes: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
        membership_protocol: MembershipProtocol::Gossip,
        membership_status,
        membership_view_id: "view-local".to_string(),
        placement_epoch: 11,
    };
    let peer_probe = PeerConnectivityProbeResult {
        ready: true,
        warning: None,
        peer_views: vec![PeerViewObservation {
            peer: "node-b:9000".to_string(),
            membership_view_id: Some("view-stale".to_string()),
            placement_epoch: Some(7),
            cluster_id: Some("cluster-a".to_string()),
            cluster_peers: vec!["node-a:9000".to_string()],
        }],
        failed_peers: Vec::new(),
    };

    let targets = derive_gossip_stale_peer_reconciliation_targets(&topology, &peer_probe);
    assert_eq!(
        targets,
        vec![GossipStalePeerReconciliationTarget {
            peer: "node-b:9000".to_string(),
            expected_membership_view_id: "view-stale".to_string(),
            expected_placement_epoch: 7,
        }]
    );
}

#[test]
fn derive_gossip_stale_peer_reconciliation_targets_ignores_non_actionable_peer_views() {
    let membership_status = MembershipEngine::for_protocol(MembershipProtocol::Gossip).status();
    let topology = RuntimeTopologySnapshot {
        mode: RuntimeMode::Distributed,
        node_id: "node-a:9000".to_string(),
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b:9000".to_string(), "node-c:9000".to_string()],
        membership_nodes: vec![
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
            "node-c:9000".to_string(),
        ],
        membership_protocol: MembershipProtocol::Gossip,
        membership_status,
        membership_view_id: "view-local".to_string(),
        placement_epoch: 11,
    };
    let peer_probe = PeerConnectivityProbeResult {
        ready: true,
        warning: None,
        peer_views: vec![
            PeerViewObservation {
                peer: "node-b:9000".to_string(),
                membership_view_id: Some("view-local".to_string()),
                placement_epoch: Some(7),
                cluster_id: Some("cluster-a".to_string()),
                cluster_peers: vec!["node-a:9000".to_string()],
            },
            PeerViewObservation {
                peer: "node-c:9000".to_string(),
                membership_view_id: Some("view-stale".to_string()),
                placement_epoch: None,
                cluster_id: Some("cluster-a".to_string()),
                cluster_peers: Vec::new(),
            },
            PeerViewObservation {
                peer: "node-d:9000".to_string(),
                membership_view_id: Some("view-stale".to_string()),
                placement_epoch: Some(3),
                cluster_id: Some("cluster-other".to_string()),
                cluster_peers: Vec::new(),
            },
        ],
        failed_peers: Vec::new(),
    };

    let targets = derive_gossip_stale_peer_reconciliation_targets(&topology, &peer_probe);
    assert!(targets.is_empty());
}

#[test]
fn derive_gossip_stale_peer_reconciliation_targets_returns_peer_missing_local_node() {
    let membership_status = MembershipEngine::for_protocol(MembershipProtocol::Gossip).status();
    let topology = RuntimeTopologySnapshot {
        mode: RuntimeMode::Distributed,
        node_id: "node-a:9000".to_string(),
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b:9000".to_string()],
        membership_nodes: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
        membership_protocol: MembershipProtocol::Gossip,
        membership_status,
        membership_view_id: "view-local".to_string(),
        placement_epoch: 11,
    };
    let peer_probe = PeerConnectivityProbeResult {
        ready: true,
        warning: None,
        peer_views: vec![PeerViewObservation {
            peer: "node-b:9000".to_string(),
            membership_view_id: Some("view-local".to_string()),
            placement_epoch: Some(11),
            cluster_id: Some("cluster-a".to_string()),
            cluster_peers: Vec::new(),
        }],
        failed_peers: Vec::new(),
    };

    let targets = derive_gossip_stale_peer_reconciliation_targets(&topology, &peer_probe);
    assert_eq!(
        targets,
        vec![GossipStalePeerReconciliationTarget {
            peer: "node-b:9000".to_string(),
            expected_membership_view_id: "view-local".to_string(),
            expected_placement_epoch: 11,
        }]
    );
}

#[test]
fn derive_membership_discovery_cluster_peers_returns_none_when_union_is_unchanged() {
    let membership_status = MembershipEngineStatus {
        engine: "static-bootstrap".to_string(),
        protocol: MembershipProtocol::StaticBootstrap.as_str().to_string(),
        ready: true,
        converged: true,
        last_update_unix_ms: 1234,
        warning: None,
    };
    let topology = RuntimeTopologySnapshot {
        mode: RuntimeMode::Distributed,
        node_id: "node-a:9000".to_string(),
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b:9000".to_string()],
        membership_nodes: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
        membership_protocol: MembershipProtocol::StaticBootstrap,
        membership_status,
        membership_view_id: "view-local".to_string(),
        placement_epoch: 3,
    };
    let peer_probe = PeerConnectivityProbeResult {
        ready: true,
        warning: None,
        peer_views: vec![PeerViewObservation {
            peer: "node-b:9000".to_string(),
            membership_view_id: Some("view-local".to_string()),
            placement_epoch: None,
            cluster_id: Some("cluster-a".to_string()),
            cluster_peers: vec!["node-b:9000".to_string()],
        }],
        failed_peers: Vec::new(),
    };

    assert_eq!(
        derive_membership_discovery_cluster_peers(&topology, &peer_probe)
            .expect("matching cluster id snapshot should be accepted"),
        None
    );
}

#[test]
fn derive_membership_discovery_cluster_peers_rejects_mismatched_cluster_id() {
    let membership_status = MembershipEngineStatus {
        engine: "static-bootstrap".to_string(),
        protocol: MembershipProtocol::StaticBootstrap.as_str().to_string(),
        ready: true,
        converged: true,
        last_update_unix_ms: 1234,
        warning: None,
    };
    let topology = RuntimeTopologySnapshot {
        mode: RuntimeMode::Distributed,
        node_id: "node-a:9000".to_string(),
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b:9000".to_string()],
        membership_nodes: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
        membership_protocol: MembershipProtocol::StaticBootstrap,
        membership_status,
        membership_view_id: "view-local".to_string(),
        placement_epoch: 3,
    };
    let peer_probe = PeerConnectivityProbeResult {
        ready: true,
        warning: None,
        peer_views: vec![PeerViewObservation {
            peer: "node-b:9000".to_string(),
            membership_view_id: Some("view-local".to_string()),
            placement_epoch: None,
            cluster_id: Some("cluster-z".to_string()),
            cluster_peers: vec!["node-c:9000".to_string()],
        }],
        failed_peers: Vec::new(),
    };

    let error = derive_membership_discovery_cluster_peers(&topology, &peer_probe)
        .expect_err("cluster id mismatch should fail closed");
    assert!(error.contains("mismatched cluster id"));
}

#[test]
fn derive_membership_discovery_cluster_peers_rejects_missing_cluster_id() {
    let membership_status = MembershipEngineStatus {
        engine: "static-bootstrap".to_string(),
        protocol: MembershipProtocol::StaticBootstrap.as_str().to_string(),
        ready: true,
        converged: true,
        last_update_unix_ms: 1234,
        warning: None,
    };
    let topology = RuntimeTopologySnapshot {
        mode: RuntimeMode::Distributed,
        node_id: "node-a:9000".to_string(),
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b:9000".to_string()],
        membership_nodes: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
        membership_protocol: MembershipProtocol::StaticBootstrap,
        membership_status,
        membership_view_id: "view-local".to_string(),
        placement_epoch: 3,
    };
    let peer_probe = PeerConnectivityProbeResult {
        ready: true,
        warning: None,
        peer_views: vec![PeerViewObservation {
            peer: "node-b:9000".to_string(),
            membership_view_id: Some("view-local".to_string()),
            placement_epoch: None,
            cluster_id: None,
            cluster_peers: vec!["node-c:9000".to_string()],
        }],
        failed_peers: Vec::new(),
    };

    let error = derive_membership_discovery_cluster_peers(&topology, &peer_probe)
        .expect_err("missing cluster id should fail closed");
    assert!(error.contains("omitted cluster id"));
}

#[test]
fn derive_membership_discovery_cluster_peers_rejects_missing_membership_view_id() {
    let membership_status = MembershipEngineStatus {
        engine: "static-bootstrap".to_string(),
        protocol: MembershipProtocol::StaticBootstrap.as_str().to_string(),
        ready: true,
        converged: true,
        last_update_unix_ms: 1234,
        warning: None,
    };
    let topology = RuntimeTopologySnapshot {
        mode: RuntimeMode::Distributed,
        node_id: "node-a:9000".to_string(),
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b:9000".to_string()],
        membership_nodes: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
        membership_protocol: MembershipProtocol::StaticBootstrap,
        membership_status,
        membership_view_id: "view-local".to_string(),
        placement_epoch: 3,
    };
    let peer_probe = PeerConnectivityProbeResult {
        ready: true,
        warning: None,
        peer_views: vec![PeerViewObservation {
            peer: "node-b:9000".to_string(),
            membership_view_id: None,
            placement_epoch: None,
            cluster_id: Some("cluster-a".to_string()),
            cluster_peers: vec!["node-c:9000".to_string()],
        }],
        failed_peers: Vec::new(),
    };

    let error = derive_membership_discovery_cluster_peers(&topology, &peer_probe)
        .expect_err("missing membership view id should fail closed");
    assert!(error.contains("omitted membership view id"));
}

#[test]
fn derive_membership_discovery_cluster_peers_uses_successful_peer_views_when_probe_not_ready() {
    let membership_status = MembershipEngineStatus {
        engine: "static-bootstrap".to_string(),
        protocol: MembershipProtocol::StaticBootstrap.as_str().to_string(),
        ready: true,
        converged: true,
        last_update_unix_ms: 1234,
        warning: None,
    };
    let topology = RuntimeTopologySnapshot {
        mode: RuntimeMode::Distributed,
        node_id: "node-a:9000".to_string(),
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b:9000".to_string()],
        membership_nodes: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
        membership_protocol: MembershipProtocol::StaticBootstrap,
        membership_status,
        membership_view_id: "view-local".to_string(),
        placement_epoch: 3,
    };
    let peer_probe = PeerConnectivityProbeResult {
        ready: false,
        warning: Some("node-c:9000 unreachable".to_string()),
        peer_views: vec![PeerViewObservation {
            peer: "node-b:9000".to_string(),
            membership_view_id: Some("view-local".to_string()),
            placement_epoch: None,
            cluster_id: Some("cluster-a".to_string()),
            cluster_peers: vec!["node-c:9000".to_string()],
        }],
        failed_peers: vec!["node-c:9000".to_string()],
    };

    let discovered = derive_membership_discovery_cluster_peers(&topology, &peer_probe)
        .expect("matching cluster id snapshot should be accepted");
    assert_eq!(
        discovered,
        Some(vec!["node-b:9000".to_string(), "node-c:9000".to_string()])
    );
}

#[test]
fn derive_membership_discovery_cluster_peers_returns_none_without_successful_peer_views() {
    let membership_status = MembershipEngineStatus {
        engine: "static-bootstrap".to_string(),
        protocol: MembershipProtocol::StaticBootstrap.as_str().to_string(),
        ready: true,
        converged: true,
        last_update_unix_ms: 1234,
        warning: None,
    };
    let topology = RuntimeTopologySnapshot {
        mode: RuntimeMode::Distributed,
        node_id: "node-a:9000".to_string(),
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b:9000".to_string()],
        membership_nodes: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
        membership_protocol: MembershipProtocol::StaticBootstrap,
        membership_status,
        membership_view_id: "view-local".to_string(),
        placement_epoch: 3,
    };
    let peer_probe = PeerConnectivityProbeResult {
        ready: false,
        warning: Some("all peers unreachable".to_string()),
        peer_views: Vec::new(),
        failed_peers: vec!["node-b:9000".to_string()],
    };

    assert_eq!(
        derive_membership_discovery_cluster_peers(&topology, &peer_probe)
            .expect("empty peer-view snapshots should be accepted"),
        None
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
    let membership_view_id = membership_view_id_with_self("node-a", &[]);
    let state = AppState {
        storage: Arc::new(storage),
        config: Arc::new(test_config()),
        credentials: Arc::new(HashMap::new()),
        node_id: Arc::new("node-a".to_string()),
        cluster_id: Arc::new("cluster-a".to_string()),
        membership_peers: Arc::new(RwLock::new(Vec::new())),
        membership_view_id: Arc::new(RwLock::new(membership_view_id)),
        cluster_peers: Arc::new(Vec::new()),
        membership_protocol: MembershipProtocol::Gossip,
        write_durability_mode: WriteDurabilityMode::DegradedSuccess,
        metadata_listing_strategy: ClusterMetadataListingStrategy::LocalNodeOnly,
        membership_engine: MembershipEngine::for_protocol(MembershipProtocol::Gossip),
        membership_last_update_unix_ms: Arc::new(AtomicU64::new(unix_ms_now())),
        membership_converged: Arc::new(AtomicU64::new(0)),
        join_nonce_replay_guard: Arc::new(InMemoryJoinNonceReplayGuard::new(
            JOIN_NONCE_REPLAY_GUARD_TTL_MS,
            JOIN_NONCE_REPLAY_GUARD_MAX_ENTRIES,
        )),
        cluster_join_authorize_counters: Arc::new(ClusterJoinAuthorizeCounters::default()),
        cluster_join_counters: Arc::new(ClusterJoinCounters::default()),
        cluster_membership_update_counters: Arc::new(ClusterMembershipUpdateCounters::default()),
        pending_replication_replay_counters: Arc::new(PendingReplicationReplayCounters::default()),
        pending_rebalance_replay_counters: Arc::new(PendingRebalanceReplayCounters::default()),
        pending_membership_propagation_replay_counters: Arc::new(
            PendingMembershipPropagationReplayCounters::default(),
        ),
        pending_metadata_repair_replay_counters: Arc::new(
            PendingMetadataRepairReplayCounters::default(),
        ),
        placement_epoch: Arc::new(AtomicU64::new(7)),
        runtime_internal_header_reject_dimensions: Arc::new(
            RuntimeInternalHeaderRejectDimensions::default(),
        ),
        login_rate_limiter: Arc::new(LoginRateLimiter::new()),
        console_sessions: Arc::new(ConsoleSessionStore::new()),
        request_count: Arc::new(AtomicU64::new(0)),
        started_at: Instant::now(),
    };

    let snapshot = runtime_topology_snapshot(&state);
    assert_eq!(snapshot.mode, RuntimeMode::Standalone);
    assert!(!snapshot.is_distributed());
    assert_eq!(snapshot.node_id, "node-a");
    assert_eq!(snapshot.cluster_id, "cluster-a");
    assert_eq!(snapshot.cluster_peer_count(), 0);
    assert_eq!(snapshot.cluster_peers, Vec::<String>::new());
    assert_eq!(snapshot.membership_node_count(), 1);
    assert_eq!(snapshot.membership_nodes, vec!["node-a"]);
    assert_eq!(snapshot.membership_protocol, MembershipProtocol::Gossip);
    assert!(snapshot.membership_status.ready);
    assert!(!snapshot.membership_status.converged);
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
    let membership_peers = vec!["node-b".to_string(), "node-c".to_string()];
    let membership_view_id = membership_view_id_with_self("node-a", &membership_peers);
    let state = AppState {
        storage: Arc::new(storage),
        config: Arc::new(test_config()),
        credentials: Arc::new(HashMap::new()),
        node_id: Arc::new("node-a".to_string()),
        cluster_id: Arc::new("cluster-a".to_string()),
        membership_peers: Arc::new(RwLock::new(membership_peers.clone())),
        membership_view_id: Arc::new(RwLock::new(membership_view_id.clone())),
        cluster_peers: Arc::new(membership_peers),
        membership_protocol: MembershipProtocol::Raft,
        write_durability_mode: WriteDurabilityMode::DegradedSuccess,
        metadata_listing_strategy: ClusterMetadataListingStrategy::LocalNodeOnly,
        membership_engine: MembershipEngine::for_protocol(MembershipProtocol::Raft),
        membership_last_update_unix_ms: Arc::new(AtomicU64::new(unix_ms_now())),
        membership_converged: Arc::new(AtomicU64::new(0)),
        join_nonce_replay_guard: Arc::new(InMemoryJoinNonceReplayGuard::new(
            JOIN_NONCE_REPLAY_GUARD_TTL_MS,
            JOIN_NONCE_REPLAY_GUARD_MAX_ENTRIES,
        )),
        cluster_join_authorize_counters: Arc::new(ClusterJoinAuthorizeCounters::default()),
        cluster_join_counters: Arc::new(ClusterJoinCounters::default()),
        cluster_membership_update_counters: Arc::new(ClusterMembershipUpdateCounters::default()),
        pending_replication_replay_counters: Arc::new(PendingReplicationReplayCounters::default()),
        pending_rebalance_replay_counters: Arc::new(PendingRebalanceReplayCounters::default()),
        pending_membership_propagation_replay_counters: Arc::new(
            PendingMembershipPropagationReplayCounters::default(),
        ),
        pending_metadata_repair_replay_counters: Arc::new(
            PendingMetadataRepairReplayCounters::default(),
        ),
        placement_epoch: Arc::new(AtomicU64::new(11)),
        runtime_internal_header_reject_dimensions: Arc::new(
            RuntimeInternalHeaderRejectDimensions::default(),
        ),
        login_rate_limiter: Arc::new(LoginRateLimiter::new()),
        console_sessions: Arc::new(ConsoleSessionStore::new()),
        request_count: Arc::new(AtomicU64::new(0)),
        started_at: Instant::now(),
    };

    let snapshot = runtime_topology_snapshot(&state);
    assert_eq!(snapshot.mode, RuntimeMode::Distributed);
    assert!(snapshot.is_distributed());
    assert_eq!(snapshot.node_id, "node-a");
    assert_eq!(snapshot.cluster_id, "cluster-a");
    assert_eq!(snapshot.cluster_peer_count(), 2);
    assert_eq!(snapshot.cluster_peers, vec!["node-b", "node-c"]);
    assert_eq!(snapshot.membership_node_count(), 3);
    assert_eq!(
        snapshot.membership_nodes,
        vec!["node-a", "node-b", "node-c"]
    );
    assert_eq!(snapshot.membership_protocol, MembershipProtocol::Raft);
    assert!(!snapshot.membership_status.ready);
    assert!(!snapshot.membership_status.converged);
    assert!(!snapshot.membership_view_id.is_empty());
    assert_eq!(snapshot.placement_epoch, 11);
}

#[tokio::test]
async fn runtime_topology_snapshot_uses_observed_membership_last_update_timestamp() {
    let temp = tempfile::tempdir().expect("temp dir should create");
    let storage = FilesystemStorage::new(
        temp.path().to_str().expect("path should be utf8"),
        false,
        1024,
        0,
    )
    .await
    .expect("storage should initialize");
    let membership_peers = vec!["node-b".to_string()];
    let membership_view_id = membership_view_id_with_self("node-a", &membership_peers);
    let state = AppState {
        storage: Arc::new(storage),
        config: Arc::new(test_config()),
        credentials: Arc::new(HashMap::new()),
        node_id: Arc::new("node-a".to_string()),
        cluster_id: Arc::new("cluster-a".to_string()),
        membership_peers: Arc::new(RwLock::new(membership_peers.clone())),
        membership_view_id: Arc::new(RwLock::new(membership_view_id)),
        cluster_peers: Arc::new(membership_peers),
        membership_protocol: MembershipProtocol::StaticBootstrap,
        write_durability_mode: WriteDurabilityMode::DegradedSuccess,
        metadata_listing_strategy: ClusterMetadataListingStrategy::LocalNodeOnly,
        membership_engine: MembershipEngine::for_protocol(MembershipProtocol::StaticBootstrap),
        membership_last_update_unix_ms: Arc::new(AtomicU64::new(10)),
        membership_converged: Arc::new(AtomicU64::new(0)),
        join_nonce_replay_guard: Arc::new(InMemoryJoinNonceReplayGuard::new(
            JOIN_NONCE_REPLAY_GUARD_TTL_MS,
            JOIN_NONCE_REPLAY_GUARD_MAX_ENTRIES,
        )),
        cluster_join_authorize_counters: Arc::new(ClusterJoinAuthorizeCounters::default()),
        cluster_join_counters: Arc::new(ClusterJoinCounters::default()),
        cluster_membership_update_counters: Arc::new(ClusterMembershipUpdateCounters::default()),
        pending_replication_replay_counters: Arc::new(PendingReplicationReplayCounters::default()),
        pending_rebalance_replay_counters: Arc::new(PendingRebalanceReplayCounters::default()),
        pending_membership_propagation_replay_counters: Arc::new(
            PendingMembershipPropagationReplayCounters::default(),
        ),
        pending_metadata_repair_replay_counters: Arc::new(
            PendingMetadataRepairReplayCounters::default(),
        ),
        placement_epoch: Arc::new(AtomicU64::new(1)),
        runtime_internal_header_reject_dimensions: Arc::new(
            RuntimeInternalHeaderRejectDimensions::default(),
        ),
        login_rate_limiter: Arc::new(LoginRateLimiter::new()),
        console_sessions: Arc::new(ConsoleSessionStore::new()),
        request_count: Arc::new(AtomicU64::new(0)),
        started_at: Instant::now(),
    };

    let baseline = state.membership_engine.last_update_unix_ms();
    let bumped = baseline.saturating_add(5000);
    record_membership_last_update(&state, bumped);
    record_membership_last_update(&state, baseline.saturating_add(1));

    let snapshot = runtime_topology_snapshot(&state);
    assert_eq!(snapshot.membership_status.last_update_unix_ms, bumped);
}

#[tokio::test]
async fn runtime_topology_snapshot_uses_observed_static_bootstrap_convergence_state() {
    let temp = tempfile::tempdir().expect("temp dir should create");
    let storage = FilesystemStorage::new(
        temp.path().to_str().expect("path should be utf8"),
        false,
        1024,
        0,
    )
    .await
    .expect("storage should initialize");
    let membership_peers = vec!["node-b".to_string()];
    let membership_view_id = membership_view_id_with_self("node-a", &membership_peers);
    let state = AppState {
        storage: Arc::new(storage),
        config: Arc::new(test_config()),
        credentials: Arc::new(HashMap::new()),
        node_id: Arc::new("node-a".to_string()),
        cluster_id: Arc::new("cluster-a".to_string()),
        membership_peers: Arc::new(RwLock::new(membership_peers.clone())),
        membership_view_id: Arc::new(RwLock::new(membership_view_id)),
        cluster_peers: Arc::new(membership_peers),
        membership_protocol: MembershipProtocol::StaticBootstrap,
        write_durability_mode: WriteDurabilityMode::DegradedSuccess,
        metadata_listing_strategy: ClusterMetadataListingStrategy::LocalNodeOnly,
        membership_engine: MembershipEngine::for_protocol(MembershipProtocol::StaticBootstrap),
        membership_last_update_unix_ms: Arc::new(AtomicU64::new(10)),
        membership_converged: Arc::new(AtomicU64::new(0)),
        join_nonce_replay_guard: Arc::new(InMemoryJoinNonceReplayGuard::new(
            JOIN_NONCE_REPLAY_GUARD_TTL_MS,
            JOIN_NONCE_REPLAY_GUARD_MAX_ENTRIES,
        )),
        cluster_join_authorize_counters: Arc::new(ClusterJoinAuthorizeCounters::default()),
        cluster_join_counters: Arc::new(ClusterJoinCounters::default()),
        cluster_membership_update_counters: Arc::new(ClusterMembershipUpdateCounters::default()),
        pending_replication_replay_counters: Arc::new(PendingReplicationReplayCounters::default()),
        pending_rebalance_replay_counters: Arc::new(PendingRebalanceReplayCounters::default()),
        pending_membership_propagation_replay_counters: Arc::new(
            PendingMembershipPropagationReplayCounters::default(),
        ),
        pending_metadata_repair_replay_counters: Arc::new(
            PendingMetadataRepairReplayCounters::default(),
        ),
        placement_epoch: Arc::new(AtomicU64::new(1)),
        runtime_internal_header_reject_dimensions: Arc::new(
            RuntimeInternalHeaderRejectDimensions::default(),
        ),
        login_rate_limiter: Arc::new(LoginRateLimiter::new()),
        console_sessions: Arc::new(ConsoleSessionStore::new()),
        request_count: Arc::new(AtomicU64::new(0)),
        started_at: Instant::now(),
    };

    let non_converged_snapshot = runtime_topology_snapshot(&state);
    assert!(!non_converged_snapshot.membership_status.converged);

    record_membership_convergence(&state, true);
    let converged_snapshot = runtime_topology_snapshot(&state);
    assert!(converged_snapshot.membership_status.converged);
}

#[test]
fn runtime_internal_header_reject_endpoint_classification_is_bounded() {
    assert_eq!(
        RuntimeInternalHeaderRejectEndpoint::for_path("/api/auth/check"),
        RuntimeInternalHeaderRejectEndpoint::Api
    );
    assert_eq!(
        RuntimeInternalHeaderRejectEndpoint::for_path("/healthz"),
        RuntimeInternalHeaderRejectEndpoint::Healthz
    );
    assert_eq!(
        RuntimeInternalHeaderRejectEndpoint::for_path("/internal/cluster/join"),
        RuntimeInternalHeaderRejectEndpoint::Internal
    );
    assert_eq!(
        RuntimeInternalHeaderRejectEndpoint::for_path("/metrics"),
        RuntimeInternalHeaderRejectEndpoint::Metrics
    );
    assert_eq!(
        RuntimeInternalHeaderRejectEndpoint::for_path("/ui/bucket"),
        RuntimeInternalHeaderRejectEndpoint::Ui
    );
    assert_eq!(
        RuntimeInternalHeaderRejectEndpoint::for_path("/unknown"),
        RuntimeInternalHeaderRejectEndpoint::Other
    );
}

#[test]
fn classify_runtime_internal_header_reject_sender_resolves_sender_categories() {
    let mut known_peer_headers = HeaderMap::new();
    known_peer_headers.insert(FORWARDED_BY_HEADER, "node-b:9000".parse().expect("header"));
    assert_eq!(
        classify_runtime_internal_header_reject_sender(
            &known_peer_headers,
            "node-a:9000",
            &[String::from("node-b:9000")],
        ),
        RuntimeInternalHeaderRejectSender::KnownPeer
    );

    let mut local_sender_headers = HeaderMap::new();
    local_sender_headers.insert(FORWARDED_BY_HEADER, "node-a:9000".parse().expect("header"));
    assert_eq!(
        classify_runtime_internal_header_reject_sender(
            &local_sender_headers,
            "node-a:9000",
            &[String::from("node-b:9000")],
        ),
        RuntimeInternalHeaderRejectSender::LocalNode
    );

    let mut unknown_peer_headers = HeaderMap::new();
    unknown_peer_headers.insert(FORWARDED_BY_HEADER, "node-x:9000".parse().expect("header"));
    assert_eq!(
        classify_runtime_internal_header_reject_sender(
            &unknown_peer_headers,
            "node-a:9000",
            &[String::from("node-b:9000")],
        ),
        RuntimeInternalHeaderRejectSender::UnknownPeer
    );

    let mut multi_hop_headers = HeaderMap::new();
    multi_hop_headers.insert(
        FORWARDED_BY_HEADER,
        "node-x:9000,node-b:9000".parse().expect("header"),
    );
    assert_eq!(
        classify_runtime_internal_header_reject_sender(
            &multi_hop_headers,
            "node-a:9000",
            &[String::from("node-b:9000")],
        ),
        RuntimeInternalHeaderRejectSender::KnownPeer
    );
}

#[test]
fn classify_runtime_internal_header_reject_sender_handles_missing_or_invalid_chains() {
    let empty_headers = HeaderMap::new();
    assert_eq!(
        classify_runtime_internal_header_reject_sender(&empty_headers, "node-a:9000", &[]),
        RuntimeInternalHeaderRejectSender::MissingOrInvalid
    );

    let mut malformed_headers = HeaderMap::new();
    malformed_headers.insert(
        FORWARDED_BY_HEADER,
        "node-a:9000,node-a:9000".parse().expect("header"),
    );
    assert_eq!(
        classify_runtime_internal_header_reject_sender(&malformed_headers, "node-a:9000", &[]),
        RuntimeInternalHeaderRejectSender::MissingOrInvalid
    );
}

#[test]
fn cluster_join_authorize_counters_track_status_and_reason_labels() {
    let counters = ClusterJoinAuthorizeCounters::default();
    counters.record("authorized", "authorized");
    counters.record("rejected", "join_nonce_replay_detected");
    counters.record("misconfigured", "invalid_configuration");
    counters.record(
        "misconfigured",
        JOIN_AUTHORIZE_REASON_DISTRIBUTED_MODE_DISABLED,
    );
    counters.record(
        "misconfigured",
        JOIN_AUTHORIZE_REASON_MEMBERSHIP_ENGINE_NOT_READY,
    );
    counters.record(
        "misconfigured",
        JOIN_AUTHORIZE_REASON_CLUSTER_AUTH_TOKEN_NOT_CONFIGURED,
    );
    counters.record("rejected", "unexpected-reason");

    let snapshot = counters.snapshot();
    assert_eq!(snapshot.total, 7);
    assert_eq!(snapshot.status_authorized, 1);
    assert_eq!(snapshot.status_rejected, 2);
    assert_eq!(snapshot.status_misconfigured, 4);
    assert_eq!(snapshot.reason_authorized, 1);
    assert_eq!(snapshot.reason_join_nonce_replay_detected, 1);
    assert_eq!(snapshot.reason_invalid_configuration, 1);
    assert_eq!(snapshot.reason_distributed_mode_disabled, 1);
    assert_eq!(snapshot.reason_membership_engine_not_ready, 1);
    assert_eq!(snapshot.reason_cluster_auth_token_not_configured, 1);
    assert_eq!(snapshot.reason_unknown, 1);
}

#[test]
fn cluster_join_counters_track_status_and_reason_labels() {
    let counters = ClusterJoinCounters::default();
    counters.record("applied", MEMBERSHIP_UPDATE_REASON_APPLIED);
    counters.record("rejected", MEMBERSHIP_UPDATE_REASON_INVALID_PAYLOAD);
    counters.record("rejected", MEMBERSHIP_UPDATE_REASON_PRECONDITION_FAILED);
    counters.record("rejected", MEMBERSHIP_UPDATE_REASON_UNAUTHORIZED);
    counters.record(
        "misconfigured",
        JOIN_AUTHORIZE_REASON_DISTRIBUTED_MODE_DISABLED,
    );
    counters.record(
        "misconfigured",
        JOIN_AUTHORIZE_REASON_MEMBERSHIP_ENGINE_NOT_READY,
    );
    counters.record(
        "misconfigured",
        JOIN_AUTHORIZE_REASON_CLUSTER_AUTH_TOKEN_NOT_CONFIGURED,
    );
    counters.record(
        "misconfigured",
        MEMBERSHIP_UPDATE_REASON_STATE_PERSIST_FAILED,
    );
    counters.record("rejected", "unexpected-reason");

    let snapshot = counters.snapshot();
    assert_eq!(snapshot.total, 9);
    assert_eq!(snapshot.status_applied, 1);
    assert_eq!(snapshot.status_rejected, 4);
    assert_eq!(snapshot.status_misconfigured, 4);
    assert_eq!(snapshot.reason_applied, 1);
    assert_eq!(snapshot.reason_invalid_payload, 1);
    assert_eq!(snapshot.reason_precondition_failed, 1);
    assert_eq!(snapshot.reason_unauthorized, 1);
    assert_eq!(snapshot.reason_distributed_mode_disabled, 1);
    assert_eq!(snapshot.reason_membership_engine_not_ready, 1);
    assert_eq!(snapshot.reason_cluster_auth_token_not_configured, 1);
    assert_eq!(snapshot.reason_state_persist_failed, 1);
    assert_eq!(snapshot.reason_unknown, 1);
}

#[test]
fn cluster_membership_update_counters_track_status_and_reason_labels() {
    let counters = ClusterMembershipUpdateCounters::default();
    counters.record("applied", MEMBERSHIP_UPDATE_REASON_APPLIED);
    counters.record("rejected", MEMBERSHIP_UPDATE_REASON_INVALID_PAYLOAD);
    counters.record("rejected", MEMBERSHIP_UPDATE_REASON_CLUSTER_ID_MISMATCH);
    counters.record("rejected", MEMBERSHIP_UPDATE_REASON_PRECONDITION_FAILED);
    counters.record("rejected", MEMBERSHIP_UPDATE_REASON_UNAUTHORIZED);
    counters.record(
        "misconfigured",
        JOIN_AUTHORIZE_REASON_DISTRIBUTED_MODE_DISABLED,
    );
    counters.record(
        "misconfigured",
        JOIN_AUTHORIZE_REASON_MEMBERSHIP_ENGINE_NOT_READY,
    );
    counters.record(
        "misconfigured",
        JOIN_AUTHORIZE_REASON_CLUSTER_AUTH_TOKEN_NOT_CONFIGURED,
    );
    counters.record(
        "misconfigured",
        MEMBERSHIP_UPDATE_REASON_STATE_PERSIST_FAILED,
    );
    counters.record("rejected", "unexpected-reason");

    let snapshot = counters.snapshot();
    assert_eq!(snapshot.total, 10);
    assert_eq!(snapshot.status_applied, 1);
    assert_eq!(snapshot.status_rejected, 5);
    assert_eq!(snapshot.status_misconfigured, 4);
    assert_eq!(snapshot.reason_applied, 1);
    assert_eq!(snapshot.reason_invalid_payload, 1);
    assert_eq!(snapshot.reason_cluster_id_mismatch, 1);
    assert_eq!(snapshot.reason_precondition_failed, 1);
    assert_eq!(snapshot.reason_unauthorized, 1);
    assert_eq!(snapshot.reason_distributed_mode_disabled, 1);
    assert_eq!(snapshot.reason_membership_engine_not_ready, 1);
    assert_eq!(snapshot.reason_cluster_auth_token_not_configured, 1);
    assert_eq!(snapshot.reason_state_persist_failed, 1);
    assert_eq!(snapshot.reason_unknown, 1);
}

#[test]
fn pending_replication_replay_counters_track_success_and_failure_cycles() {
    let counters = PendingReplicationReplayCounters::default();
    counters.record_success(3, 2, 1, 1, 1);
    counters.record_failure();

    let snapshot = counters.snapshot();
    assert_eq!(snapshot.cycles_total, 2);
    assert_eq!(snapshot.cycles_succeeded, 1);
    assert_eq!(snapshot.cycles_failed, 1);
    assert_eq!(snapshot.scanned_total, 3);
    assert_eq!(snapshot.leased_total, 2);
    assert_eq!(snapshot.acknowledged_total, 1);
    assert_eq!(snapshot.failed_total, 1);
    assert_eq!(snapshot.skipped_total, 1);
    assert!(snapshot.last_cycle_unix_ms > 0);
    assert!(snapshot.last_success_unix_ms > 0);
    assert!(snapshot.last_failure_unix_ms > 0);
}

#[test]
fn pending_rebalance_replay_counters_track_success_and_failure_cycles() {
    let counters = PendingRebalanceReplayCounters::default();
    counters.record_success(6, 5, 3, 1, 2);
    counters.record_failure();

    let snapshot = counters.snapshot();
    assert_eq!(snapshot.cycles_total, 2);
    assert_eq!(snapshot.cycles_succeeded, 1);
    assert_eq!(snapshot.cycles_failed, 1);
    assert_eq!(snapshot.scanned_total, 6);
    assert_eq!(snapshot.leased_total, 5);
    assert_eq!(snapshot.acknowledged_total, 3);
    assert_eq!(snapshot.failed_total, 1);
    assert_eq!(snapshot.skipped_total, 2);
    assert!(snapshot.last_cycle_unix_ms > 0);
    assert!(snapshot.last_success_unix_ms > 0);
    assert!(snapshot.last_failure_unix_ms > 0);
}

#[test]
fn pending_metadata_repair_replay_counters_track_success_and_failure_cycles() {
    let counters = PendingMetadataRepairReplayCounters::default();
    counters.record_success(4, 3, 0, 3, 1, 0);
    counters.record_terminal_failure_reason("target-view-mismatch");
    counters.record_terminal_failure_reason("target-view-mismatch");
    counters.record_terminal_failure_reason("invalid-repair-plan");
    counters.record_failure();

    let snapshot = counters.snapshot();
    assert_eq!(snapshot.cycles_total, 2);
    assert_eq!(snapshot.cycles_succeeded, 1);
    assert_eq!(snapshot.cycles_failed, 1);
    assert_eq!(snapshot.scanned_plans_total, 4);
    assert_eq!(snapshot.leased_plans_total, 3);
    assert_eq!(snapshot.acknowledged_plans_total, 0);
    assert_eq!(snapshot.failed_plans_total, 3);
    assert_eq!(snapshot.dropped_plans_total, 1);
    assert_eq!(snapshot.skipped_plans_total, 0);
    assert_eq!(
        snapshot.terminal_failure_reason_totals,
        vec![
            ("invalid-repair-plan".to_string(), 1),
            ("target-view-mismatch".to_string(), 2),
        ]
    );
    assert!(snapshot.last_cycle_unix_ms > 0);
    assert!(snapshot.last_success_unix_ms > 0);
    assert!(snapshot.last_failure_unix_ms > 0);
}

#[test]
fn pending_membership_propagation_replay_counters_track_success_and_failure_cycles() {
    let counters = PendingMembershipPropagationReplayCounters::default();
    counters.record_success(5, 4, 2, 3, 1);
    counters.record_failure();

    let snapshot = counters.snapshot();
    assert_eq!(snapshot.cycles_total, 2);
    assert_eq!(snapshot.cycles_succeeded, 1);
    assert_eq!(snapshot.cycles_failed, 1);
    assert_eq!(snapshot.scanned_operations_total, 5);
    assert_eq!(snapshot.replayed_operations_total, 4);
    assert_eq!(snapshot.deferred_operations_total, 2);
    assert_eq!(snapshot.acknowledged_operations_total, 3);
    assert_eq!(snapshot.failed_operations_total, 1);
    assert!(snapshot.last_cycle_unix_ms > 0);
    assert!(snapshot.last_success_unix_ms > 0);
    assert!(snapshot.last_failure_unix_ms > 0);
}

#[test]
fn build_pending_membership_propagation_replay_workset_caps_and_prioritizes_due_operations() {
    let request = ClusterMembershipUpdateRequest {
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b.internal:9000".to_string()],
        expected_membership_view_id: None,
        expected_placement_epoch: None,
    };
    let operation = |peer: &str, attempts: u32, created_at: u64, next_retry: Option<u64>| {
        PendingMembershipPropagationOperation {
            peer: peer.to_string(),
            request: request.clone(),
            attempts,
            created_at_unix_ms: created_at,
            updated_at_unix_ms: created_at,
            next_retry_at_unix_ms: next_retry,
            last_error: None,
        }
    };

    let now_unix_ms = 5_000;
    let workset = build_pending_membership_propagation_replay_workset(
        vec![
            operation("node-c.internal:9000", 3, 1_000, Some(4_000)),
            operation("node-a.internal:9000", 1, 2_000, Some(4_500)),
            operation("node-b.internal:9000", 1, 3_000, Some(4_600)),
            operation("node-z.internal:9000", 1, 4_000, Some(now_unix_ms + 2_000)),
        ],
        now_unix_ms,
        2,
    );

    assert_eq!(workset.scanned_operations, 4);
    assert_eq!(workset.replay_due_operations.len(), 2);
    assert_eq!(workset.deferred_due_operations, 1);
    assert_eq!(
        workset
            .replay_due_operations
            .iter()
            .map(|operation| operation.peer.as_str())
            .collect::<Vec<_>>(),
        vec!["node-a.internal:9000", "node-b.internal:9000"]
    );
    assert_eq!(workset.retained_operations.len(), 2);
    assert!(
        workset
            .retained_operations
            .iter()
            .any(|operation| operation.peer == "node-c.internal:9000")
    );
    assert!(
        workset
            .retained_operations
            .iter()
            .any(|operation| operation.peer == "node-z.internal:9000")
    );
}

#[test]
fn apply_pending_membership_propagation_replay_outcomes_acknowledges_and_retries() {
    let request = ClusterMembershipUpdateRequest {
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b.internal:9000".to_string()],
        expected_membership_view_id: None,
        expected_placement_epoch: None,
    };
    let operation = |peer: &str, attempts: u32, created_at: u64, next_retry: Option<u64>| {
        PendingMembershipPropagationOperation {
            peer: peer.to_string(),
            request: request.clone(),
            attempts,
            created_at_unix_ms: created_at,
            updated_at_unix_ms: created_at,
            next_retry_at_unix_ms: next_retry,
            last_error: None,
        }
    };

    let acked_original = operation("node-a.internal:9000", 1, 1_000, Some(2_000));
    let failed_original = operation("node-b.internal:9000", 1, 2_000, Some(2_500));
    let mut failed_retry = failed_original.clone();
    failed_retry.attempts = 2;
    failed_retry.updated_at_unix_ms = 3_000;
    failed_retry.next_retry_at_unix_ms = Some(4_000);
    failed_retry.last_error = Some("transport failure".to_string());
    let untouched = operation("node-c.internal:9000", 1, 3_000, Some(5_000));

    let merged = apply_pending_membership_propagation_replay_outcomes(
        vec![
            acked_original.clone(),
            failed_original.clone(),
            untouched.clone(),
        ],
        vec![
            PendingMembershipPropagationReplayOperationOutcome::Acknowledged {
                original: acked_original,
            },
            PendingMembershipPropagationReplayOperationOutcome::Failed {
                original: failed_original,
                retry: failed_retry.clone(),
            },
        ],
    );

    assert_eq!(merged.len(), 2);
    assert_eq!(merged[0], failed_retry);
    assert_eq!(merged[1], untouched);
}

#[test]
fn apply_pending_membership_propagation_replay_outcomes_drops_terminal_failures() {
    let request = ClusterMembershipUpdateRequest {
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b.internal:9000".to_string()],
        expected_membership_view_id: None,
        expected_placement_epoch: None,
    };
    let operation = |peer: &str| PendingMembershipPropagationOperation {
        peer: peer.to_string(),
        request: request.clone(),
        attempts: 1,
        created_at_unix_ms: 1_000,
        updated_at_unix_ms: 1_000,
        next_retry_at_unix_ms: Some(2_000),
        last_error: None,
    };

    let dropped_original = operation("node-a.internal:9000");
    let untouched = operation("node-b.internal:9000");

    let merged = apply_pending_membership_propagation_replay_outcomes(
        vec![dropped_original.clone(), untouched.clone()],
        vec![
            PendingMembershipPropagationReplayOperationOutcome::Dropped {
                original: dropped_original,
            },
        ],
    );

    assert_eq!(merged, vec![untouched]);
}

#[test]
fn apply_pending_membership_propagation_replay_outcomes_preserves_concurrent_peer_updates() {
    let request = ClusterMembershipUpdateRequest {
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b.internal:9000".to_string()],
        expected_membership_view_id: None,
        expected_placement_epoch: None,
    };
    let operation = |peer: &str, attempts: u32, created_at: u64, next_retry: Option<u64>| {
        PendingMembershipPropagationOperation {
            peer: peer.to_string(),
            request: request.clone(),
            attempts,
            created_at_unix_ms: created_at,
            updated_at_unix_ms: created_at,
            next_retry_at_unix_ms: next_retry,
            last_error: None,
        }
    };

    let acked_original = operation("node-a.internal:9000", 1, 1_000, Some(2_000));
    let failed_original = operation("node-b.internal:9000", 1, 2_000, Some(2_500));
    let mut failed_retry = failed_original.clone();
    failed_retry.attempts = 2;
    failed_retry.updated_at_unix_ms = 3_000;
    failed_retry.next_retry_at_unix_ms = Some(4_000);
    failed_retry.last_error = Some("transport failure".to_string());

    // Simulate concurrent queue mutations that happened after the replay worker loaded
    // its initial snapshot.
    let mut concurrent_acked_peer_update = acked_original.clone();
    concurrent_acked_peer_update.attempts = 5;
    concurrent_acked_peer_update.updated_at_unix_ms = 4_200;
    concurrent_acked_peer_update.next_retry_at_unix_ms = Some(6_000);
    let mut concurrent_failed_peer_update = failed_original.clone();
    concurrent_failed_peer_update.attempts = 4;
    concurrent_failed_peer_update.updated_at_unix_ms = 4_300;
    concurrent_failed_peer_update.next_retry_at_unix_ms = Some(6_100);
    concurrent_failed_peer_update.last_error = Some("newer update".to_string());

    let merged = apply_pending_membership_propagation_replay_outcomes(
        vec![
            concurrent_acked_peer_update.clone(),
            concurrent_failed_peer_update.clone(),
        ],
        vec![
            PendingMembershipPropagationReplayOperationOutcome::Acknowledged {
                original: acked_original,
            },
            PendingMembershipPropagationReplayOperationOutcome::Failed {
                original: failed_original,
                retry: failed_retry,
            },
        ],
    );

    assert_eq!(merged.len(), 2);
    assert_eq!(merged[0], concurrent_acked_peer_update);
    assert_eq!(merged[1], concurrent_failed_peer_update);
}

#[tokio::test]
async fn persist_membership_propagation_failure_if_retryable_persists_retryable_failure() {
    let temp = tempfile::tempdir().expect("temp dir should create");
    let mut config = test_config();
    config.data_dir = temp.path().to_string_lossy().to_string();
    let request = ClusterMembershipUpdateRequest {
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b.internal:9000".to_string()],
        expected_membership_view_id: Some("view-1".to_string()),
        expected_placement_epoch: Some(7),
    };
    let failure = MembershipPropagationFailure::retryable("transport failure".to_string());

    persist_membership_propagation_failure_if_retryable(
        &config,
        "node-b.internal:9000",
        &request,
        &failure,
        "gossip stale-peer reconciliation",
    )
    .await;

    let queue_path = pending_membership_propagation_queue_path(config.data_dir.as_str());
    let queue = load_pending_membership_propagation_queue(queue_path.as_path())
        .await
        .expect("queue should load");
    assert_eq!(queue.operations.len(), 1);
    let persisted = &queue.operations[0];
    assert_eq!(persisted.peer, "node-b.internal:9000");
    assert_eq!(persisted.request, request);
    assert_eq!(persisted.attempts, 1);
    assert_eq!(persisted.last_error.as_deref(), Some("transport failure"));
    assert!(persisted.next_retry_at_unix_ms.is_some());
}

#[tokio::test]
async fn persist_membership_propagation_failure_if_retryable_skips_terminal_failure() {
    let temp = tempfile::tempdir().expect("temp dir should create");
    let mut config = test_config();
    config.data_dir = temp.path().to_string_lossy().to_string();
    let request = ClusterMembershipUpdateRequest {
        cluster_id: "cluster-a".to_string(),
        cluster_peers: vec!["node-b.internal:9000".to_string()],
        expected_membership_view_id: Some("view-1".to_string()),
        expected_placement_epoch: Some(7),
    };
    let failure = MembershipPropagationFailure::terminal("rejected".to_string());

    persist_membership_propagation_failure_if_retryable(
        &config,
        "node-b.internal:9000",
        &request,
        &failure,
        "gossip stale-peer reconciliation",
    )
    .await;

    let queue_path = pending_membership_propagation_queue_path(config.data_dir.as_str());
    let queue = load_pending_membership_propagation_queue(queue_path.as_path())
        .await
        .expect("queue should load");
    assert!(queue.operations.is_empty());
}
