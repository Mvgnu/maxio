use std::sync::atomic::Ordering;

use axum::{extract::State, http::StatusCode, response::IntoResponse};

use crate::api::console::response;
use crate::server::AppState;

pub(super) async fn get_health(State(state): State<AppState>) -> impl IntoResponse {
    let uptime_seconds = state.started_at.elapsed().as_secs_f64();
    let distributed_mode = !state.cluster_peers.is_empty();

    response::json(
        StatusCode::OK,
        serde_json::json!({
            "ok": true,
            "version": env!("CARGO_PKG_VERSION"),
            "uptimeSeconds": uptime_seconds,
            "mode": if distributed_mode { "distributed" } else { "standalone" },
            "nodeId": state.node_id.as_str(),
            "clusterPeerCount": state.cluster_peers.len(),
            "clusterPeers": state.cluster_peers.as_ref(),
        }),
    )
}

pub(super) async fn get_metrics(State(state): State<AppState>) -> impl IntoResponse {
    let requests_total = state.request_count.load(Ordering::Relaxed);
    let uptime_seconds = state.started_at.elapsed().as_secs_f64();
    let distributed_mode = !state.cluster_peers.is_empty();

    response::json(
        StatusCode::OK,
        serde_json::json!({
            "requestsTotal": requests_total,
            "uptimeSeconds": uptime_seconds,
            "version": env!("CARGO_PKG_VERSION"),
            "mode": if distributed_mode { "distributed" } else { "standalone" },
            "nodeId": state.node_id.as_str(),
            "clusterPeerCount": state.cluster_peers.len(),
            "clusterPeers": state.cluster_peers.as_ref(),
        }),
    )
}

pub(super) async fn get_topology(State(state): State<AppState>) -> impl IntoResponse {
    let distributed_mode = !state.cluster_peers.is_empty();

    response::json(
        StatusCode::OK,
        serde_json::json!({
            "mode": if distributed_mode { "distributed" } else { "standalone" },
            "nodeId": state.node_id.as_str(),
            "clusterPeerCount": state.cluster_peers.len(),
            "clusterPeers": state.cluster_peers.as_ref(),
        }),
    )
}
