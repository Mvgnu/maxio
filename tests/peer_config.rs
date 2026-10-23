use clap::Parser;
use maxio::{config::Config, server::AppState};

fn config() -> Config {
    Config::parse_from(["maxio", "--node-id", "node-a.internal:9000"])
}

#[test]
fn peer_addresses_use_the_same_identity_as_peer_authentication() {
    let mut config = config();
    config.cluster_peers = vec![
        "Node-B.Internal:09001".into(),
        "node-b.internal:9001".into(),
        " [2001:0DB8:0:0:0:0:0:1] : 09002 ".into(),
        "[2001:db8::1]:9002".into(),
    ];
    assert_eq!(
        config.parsed_cluster_peers().unwrap(),
        ["node-b.internal:9001", "[2001:db8::1]:9002"]
    );
}

#[test]
fn peer_addresses_reject_url_components_and_malformed_hosts() {
    for peer in [
        "http://node-b:9001",
        "user@node-b:9001",
        "node-b/path:9001",
        "node-b?query:9001",
        "node..b:9001",
        "-node-b:9001",
        "2001:db8::1:9001",
        "[not-ipv6]:9001",
        "[2001:db8::1]",
    ] {
        let mut config = config();
        config.cluster_peers = vec![peer.into()];
        assert!(config.parsed_cluster_peers().is_err(), "accepted {peer}");
    }
}

#[test]
fn node_id_is_canonicalized_by_cli_parsing() {
    let config = Config::parse_from(["maxio", "--node-id", "Node-A.Internal:09000"]);
    assert_eq!(config.node_id, "node-a.internal:9000");
    assert!(Config::try_parse_from(["maxio", "--node-id", "http://node-a:9000"]).is_err());
}

#[tokio::test]
async fn runtime_uses_one_canonical_membership_for_auth_and_placement() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = config();
    config.data_dir = temp.path().to_string_lossy().into_owned();
    config.node_id = "Node-A.Internal:09000".into();
    config.cluster_peers = vec!["Node-B.Internal:09001".into()];
    let state = AppState::from_config(config).await.unwrap();
    assert_eq!(state.node_id.as_str(), "node-a.internal:9000");
    assert_eq!(state.config.node_id, *state.node_id);
    assert_eq!(state.active_cluster_peers(), ["node-b.internal:9001"]);
}

#[tokio::test]
async fn membership_updates_share_startup_validation_and_canonicalization() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = config();
    config.data_dir = temp.path().to_string_lossy().into_owned();
    let state = AppState::from_config(config).await.unwrap();
    state
        .apply_membership_peers(vec![
            "Node-B.Internal:09001".into(),
            "node-b.internal:9001".into(),
        ])
        .await
        .unwrap();
    assert_eq!(state.active_cluster_peers(), ["node-b.internal:9001"]);
    let view_before = state.active_membership_view_id();
    assert!(
        state
            .apply_membership_peers(vec!["http://node-b:9001".into()])
            .await
            .is_err()
    );
    assert_eq!(state.active_membership_view_id(), view_before);
}

#[tokio::test]
async fn membership_updates_reject_equivalent_ipv6_self_peers() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = config();
    config.data_dir = temp.path().to_string_lossy().into_owned();
    config.node_id = "[2001:db8::1]:9000".into();
    let state = AppState::from_config(config).await.unwrap();
    assert!(
        state
            .apply_membership_peers(vec!["[2001:0db8:0:0:0:0:0:1]:09000".into()])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn real_peer_health_probes_do_not_recursively_probe_each_other() {
    let temp_a = tempfile::tempdir().unwrap();
    let temp_b = tempfile::tempdir().unwrap();
    let listener_a = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_b = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address_a = listener_a.local_addr().unwrap();
    let address_b = listener_b.local_addr().unwrap();
    let mut config_a = config();
    config_a.node_id = address_a.to_string();
    config_a.cluster_peers = vec![address_b.to_string()];
    config_a.data_dir = temp_a.path().to_string_lossy().into_owned();
    config_a.cluster_auth_token = Some("local-test-token".into());
    let mut config_b = config_a.clone();
    config_b.node_id = address_b.to_string();
    config_b.cluster_peers = vec![address_a.to_string()];
    config_b.data_dir = temp_b.path().to_string_lossy().into_owned();
    let state_a = AppState::from_config(config_a).await.unwrap();
    let state_b = AppState::from_config(config_b).await.unwrap();
    let app_a = maxio::server::build_router(state_a);
    let app_b = maxio::server::build_router(state_b);
    let server_a = tokio::spawn(async move { axum::serve(listener_a, app_a).await.unwrap() });
    let server_b = tokio::spawn(async move { axum::serve(listener_b, app_b).await.unwrap() });
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(1))
        .build()
        .unwrap();
    let result = client
        .get(format!("http://{address_a}/healthz"))
        .send()
        .await;
    server_a.abort();
    server_b.abort();
    let body: serde_json::Value = result
        .expect("health must terminate without recursive peer requests")
        .json()
        .await
        .unwrap();
    assert_eq!(body["checks"]["peerConnectivityReady"], true);
}

#[tokio::test]
async fn metadata_readiness_tracks_real_peer_listing_outage_recovery_and_authentication() {
    use maxio::auth::signature_v4::{PresignRequest, generate_presigned_url};
    use maxio::config::WriteDurabilityMode;
    use maxio::metadata::ClusterMetadataListingStrategy;

    let temp_a = tempfile::tempdir().unwrap();
    let temp_b = tempfile::tempdir().unwrap();
    let listener_a = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_b = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address_a = listener_a.local_addr().unwrap();
    let address_b = listener_b.local_addr().unwrap();
    let mut config_a = config();
    config_a.node_id = address_a.to_string();
    config_a.cluster_peers = vec![address_b.to_string()];
    config_a.data_dir = temp_a.path().to_string_lossy().into_owned();
    config_a.access_key = "readiness-test".into();
    config_a.secret_key = "readiness-secret".into();
    config_a.cluster_auth_token = Some("readiness-peer-token".into());
    config_a.metadata_listing_strategy = ClusterMetadataListingStrategy::RequestTimeAggregation;
    config_a.write_durability_mode = WriteDurabilityMode::StrictQuorum;
    let mut config_b = config_a.clone();
    config_b.node_id = address_b.to_string();
    config_b.cluster_peers = vec![address_a.to_string()];
    config_b.data_dir = temp_b.path().to_string_lossy().into_owned();
    let state_a = AppState::from_config(config_a.clone()).await.unwrap();
    let state_b = AppState::from_config(config_b.clone()).await.unwrap();
    let app_a = maxio::server::build_router(state_a);
    let app_b = maxio::server::build_router(state_b);
    let server_a = tokio::spawn(async move { axum::serve(listener_a, app_a).await.unwrap() });
    let mut server_b = tokio::spawn(async move { axum::serve(listener_b, app_b).await.unwrap() });
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(4))
        .build()
        .unwrap();

    for (phase, expected_ready) in [
        ("up", true),
        ("down", false),
        ("recovered", true),
        ("wrong-secret", false),
    ] {
        if phase == "down" || phase == "wrong-secret" {
            server_b.abort();
            let _ = (&mut server_b).await;
        }
        if phase == "recovered" || phase == "wrong-secret" {
            if phase == "wrong-secret" {
                config_b.secret_key = "different-peer-secret".into();
            }
            let listener = tokio::net::TcpListener::bind(address_b).await.unwrap();
            let state = AppState::from_config(config_b.clone()).await.unwrap();
            let app = maxio::server::build_router(state);
            server_b = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        }
        let url = generate_presigned_url(PresignRequest {
            method: "GET",
            scheme: "http",
            host: &address_a.to_string(),
            path: "/",
            extra_query_params: &[],
            access_key: &config_a.access_key,
            secret_key: &config_a.secret_key,
            region: &config_a.region,
            now: chrono::Utc::now(),
            expires_secs: 30,
        })
        .unwrap();
        let listing = client.get(url).send().await.unwrap();
        assert_eq!(
            listing.status().is_success(),
            expected_ready,
            "listing: {phase}"
        );
        let health: serde_json::Value = client
            .get(format!("http://{address_a}/healthz"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            health["checks"]["metadataListReady"], expected_ready,
            "health: {phase}: {health}"
        );
        assert_eq!(
            health["ok"], expected_ready,
            "aggregate health: {phase}: {health}"
        );
        assert_eq!(health["metadataListingProbeScope"], "list-buckets-fan-in");
        assert_eq!(
            health["metadataListingRespondedNodes"],
            if expected_ready { 2 } else { 1 }
        );
        if phase == "wrong-secret" {
            assert_eq!(health["checks"]["peerConnectivityReady"], true);
        }
        let metrics = client
            .get(format!("http://{address_a}/metrics"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let ready_metric = format!(
            "maxio_metadata_listing_ready {}\n",
            usize::from(expected_ready)
        );
        assert!(
            metrics.contains(&ready_metric),
            "metrics: {phase}: {metrics}"
        );
    }
    server_a.abort();
    server_b.abort();
}
