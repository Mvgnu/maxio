use super::*;

const METADATA_READINESS_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) struct MetadataListingProbeResult {
    pub(super) snapshot: ClusterMetadataSnapshotAssessment,
    pub(super) scope: &'static str,
    pub(super) status: &'static str,
}

/// Observe a real bucket-listing fan-in, without treating peer liveness as data
/// readiness. A successful request-time ListBuckets already validates every
/// expected responder, credentials, transport policy, and membership view. The
/// response body is discarded; health never exposes bucket names.
pub(super) async fn probe_metadata_listing(
    state: &AppState,
    topology: &RuntimeTopologySnapshot,
    local_storage_readable: bool,
) -> MetadataListingProbeResult {
    let local_responders = if local_storage_readable {
        vec![topology.node_id.clone()]
    } else {
        Vec::new()
    };
    let local_snapshot = assess_cluster_metadata_snapshot_for_topology_responders(
        state.metadata_listing_strategy,
        Some(topology.membership_view_id.as_str()),
        topology.node_id.as_str(),
        topology.membership_nodes.as_slice(),
        local_responders.as_slice(),
    )
    .unwrap_or_else(|_| metadata_snapshot_for_topology(topology, state.metadata_listing_strategy));

    // The consensus-index handler reads its persisted local index. It cannot
    // establish observed peer coverage; keep that limitation explicit rather
    // than manufacturing responders from a successful local read.
    let uses_fan_in = topology.is_distributed()
        && matches!(
            state.metadata_listing_strategy,
            ClusterMetadataListingStrategy::RequestTimeAggregation
                | ClusterMetadataListingStrategy::FullReplication
        );
    if !uses_fan_in || !local_storage_readable {
        return MetadataListingProbeResult {
            snapshot: local_snapshot,
            scope: "local-node-only",
            status: if local_storage_readable {
                "local-observation"
            } else {
                "local-storage-unreadable"
            },
        };
    }

    // Bound the entire fan-in, not each peer independently. Internal peer
    // requests carry local-only metadata scope, so this never recurses through
    // either the health route or another cluster-wide listing.
    let result = tokio::time::timeout(
        METADATA_READINESS_PROBE_TIMEOUT,
        crate::api::bucket::list_buckets(
            State(state.clone()),
            axum::extract::Query(HashMap::new()),
            HeaderMap::new(),
        ),
    )
    .await;
    let status = match result {
        Ok(Ok(response)) if response.status().is_success() => {
            // The handler takes its own topology snapshot. Membership changes
            // during the probe invalidate our attribution of its responders.
            let latest = runtime_topology_snapshot(state);
            if latest.membership_view_id != topology.membership_view_id
                || latest.placement_epoch != topology.placement_epoch
                || latest.membership_nodes != topology.membership_nodes
            {
                "membership-changed"
            } else if let Ok(snapshot) = assess_cluster_metadata_snapshot_for_topology_responders(
                state.metadata_listing_strategy,
                Some(topology.membership_view_id.as_str()),
                topology.node_id.as_str(),
                topology.membership_nodes.as_slice(),
                topology.membership_nodes.as_slice(),
            ) {
                return MetadataListingProbeResult {
                    snapshot,
                    scope: "list-buckets-fan-in",
                    status: "complete",
                };
            } else {
                "invalid-topology"
            }
        }
        Ok(_) => "failed",
        Err(_) => "timed-out",
    };

    // Failed/partial handler results do not expose their responder identities.
    // Count only the separately observed local storage read. In particular, do
    // not relabel healthy TCP peers as successful metadata responders.
    MetadataListingProbeResult {
        snapshot: local_snapshot,
        scope: "list-buckets-fan-in",
        status,
    }
}
