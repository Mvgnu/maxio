use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Component, Path, PathBuf};

use crate::error::S3Error;
use crate::metadata::{
    CLUSTER_METADATA_CONSENSUS_FAN_IN_AUTH_TOKEN_MISSING_REASON, ClusterMetadataListingStrategy,
    MetadataNodeObjectsPage, MetadataNodeVersionsPage, MetadataQuery, MetadataVersionsQuery,
    ObjectMetadataState, ObjectVersionMetadataState,
    assess_cluster_metadata_fan_in_snapshot_for_topology_responders,
    assess_cluster_metadata_fan_in_snapshot_for_topology_single_responder,
    cluster_metadata_fan_in_auth_token_reject_reason, cluster_metadata_readiness_reject_reason,
    list_object_versions_page_from_persisted_state, list_objects_page_from_persisted_state,
    load_persisted_metadata_state, merge_cluster_list_object_versions_page_with_topology_snapshot,
    merge_cluster_list_objects_page_with_topology_snapshot,
    merge_cluster_list_objects_page_with_topology_snapshot_and_marker,
};
use crate::server::{AppState, RuntimeTopologySnapshot};
use crate::storage::{ObjectMeta, StorageError};
use crate::xml::types::{CommonPrefix, DeleteMarkerEntry, ObjectEntry, VersionEntry};

const MAX_KEYS_CAP: usize = 1000;
const PERSISTED_METADATA_STATE_FILE: &str = "cluster-metadata-state.json";
type PaginatedVersionsPage = (Vec<ObjectMeta>, bool, Option<(String, String)>);

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct ListV2ContinuationTokenPayload {
    start_after: String,
    snapshot_id: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct DecodedListV2ContinuationToken {
    start_after: String,
    snapshot_id: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct ListMetadataCoverage {
    pub(super) expected_nodes: usize,
    pub(super) responded_nodes: usize,
    pub(super) missing_nodes: usize,
    pub(super) unexpected_nodes: usize,
    pub(super) complete: bool,
    pub(super) snapshot_id: String,
    pub(super) source: &'static str,
    pub(super) strategy_cluster_authoritative: bool,
    pub(super) strategy_ready: bool,
    pub(super) strategy_gap: Option<&'static str>,
    pub(super) strategy_reject_reason: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BucketGetOperation {
    ListUploads,
    GetVersioning,
    GetLifecycle,
    ListVersions,
    GetLocation,
    ListV2,
    ListV1,
}

pub(super) fn resolve_bucket_get_operation(
    params: &HashMap<String, String>,
) -> Result<BucketGetOperation, S3Error> {
    if params.contains_key("uploads") {
        return Ok(BucketGetOperation::ListUploads);
    }
    if params.contains_key("versioning") {
        return Ok(BucketGetOperation::GetVersioning);
    }
    if params.contains_key("lifecycle") {
        return Ok(BucketGetOperation::GetLifecycle);
    }
    if params.contains_key("versions") {
        return Ok(BucketGetOperation::ListVersions);
    }
    if params.contains_key("location") {
        return Ok(BucketGetOperation::GetLocation);
    }

    if let Some(list_type) = params.get("list-type") {
        if list_type == "2" {
            return Ok(BucketGetOperation::ListV2);
        }
        return Err(S3Error::invalid_argument("Invalid list-type value"));
    }

    Ok(BucketGetOperation::ListV1)
}

pub(super) fn metadata_coverage_for_topology(
    topology: &RuntimeTopologySnapshot,
    strategy: ClusterMetadataListingStrategy,
) -> Option<ListMetadataCoverage> {
    let responder_nodes = [topology.node_id.clone()];
    metadata_coverage_for_topology_responders(topology, strategy, responder_nodes.as_slice())
}

pub(super) fn metadata_coverage_for_topology_responders(
    topology: &RuntimeTopologySnapshot,
    strategy: ClusterMetadataListingStrategy,
    responder_nodes: &[String],
) -> Option<ListMetadataCoverage> {
    if !topology.is_distributed() {
        return None;
    }
    let snapshot_assessment = assess_cluster_metadata_fan_in_snapshot_for_topology_responders(
        strategy,
        Some(topology.membership_view_id.as_str()),
        topology.node_id.as_str(),
        topology.membership_nodes.as_slice(),
        responder_nodes,
    )
    .unwrap_or_else(|_| {
        assess_cluster_metadata_fan_in_snapshot_for_topology_single_responder(
            strategy,
            Some(topology.membership_view_id.as_str()),
            topology.node_id.as_str(),
            topology.membership_nodes.as_slice(),
            topology.node_id.as_str(),
        )
    });
    let readiness = snapshot_assessment.readiness_assessment;
    let coverage = snapshot_assessment.coverage;

    Some(ListMetadataCoverage {
        expected_nodes: coverage.expected_nodes.len(),
        responded_nodes: coverage.responded_nodes.len(),
        missing_nodes: coverage.missing_nodes.len(),
        unexpected_nodes: coverage.unexpected_nodes.len(),
        complete: coverage.complete,
        snapshot_id: snapshot_assessment.snapshot_id,
        source: strategy.as_str(),
        strategy_cluster_authoritative: readiness.cluster_authoritative,
        strategy_ready: readiness.ready,
        strategy_gap: readiness.gap.map(|gap| gap.as_str()),
        strategy_reject_reason: cluster_metadata_readiness_reject_reason(&readiness)
            .map(|gap| gap.as_str()),
    })
}

pub(super) fn ensure_distributed_listing_strategy_ready(
    coverage: Option<&ListMetadataCoverage>,
) -> Result<(), S3Error> {
    let Some(coverage) = coverage else {
        return Ok(());
    };

    if let Some(reason) = coverage.strategy_reject_reason {
        let message = format!(
            "Distributed metadata listing strategy is not ready for this request ({reason})"
        );
        return Err(S3Error::service_unavailable(message.as_str()));
    }

    Ok(())
}

pub(super) fn ensure_consensus_index_peer_fan_in_transport_ready(
    state: &AppState,
    topology: &RuntimeTopologySnapshot,
    internal_local_only: bool,
) -> Result<(), S3Error> {
    if internal_local_only
        || !topology.is_distributed()
        || state.metadata_listing_strategy != ClusterMetadataListingStrategy::ConsensusIndex
    {
        return Ok(());
    }

    let has_cluster_auth_token = state
        .config
        .cluster_auth_token()
        .is_some_and(|value| !value.trim().is_empty());
    if has_cluster_auth_token {
        return Ok(());
    }

    let Some(reason) = cluster_metadata_fan_in_auth_token_reject_reason(
        state.metadata_listing_strategy,
        has_cluster_auth_token,
    ) else {
        return Ok(());
    };
    debug_assert_eq!(
        reason,
        CLUSTER_METADATA_CONSENSUS_FAN_IN_AUTH_TOKEN_MISSING_REASON
    );
    Err(S3Error::service_unavailable(&format!(
        "Distributed metadata listing strategy is not ready for this request ({reason})"
    )))
}

pub(super) fn should_use_consensus_index_persisted_object_listing_state(
    state: &AppState,
    topology: &RuntimeTopologySnapshot,
    internal_local_only: bool,
) -> bool {
    !internal_local_only
        && topology.is_distributed()
        && state.metadata_listing_strategy == ClusterMetadataListingStrategy::ConsensusIndex
}

fn persisted_metadata_state_path(data_dir: &str) -> PathBuf {
    PathBuf::from(data_dir)
        .join(".maxio-runtime")
        .join(PERSISTED_METADATA_STATE_FILE)
}

fn load_consensus_index_persisted_metadata_state(
    state: &AppState,
    operation: &str,
) -> Result<crate::metadata::PersistedMetadataState, S3Error> {
    let state_path = persisted_metadata_state_path(state.config.data_dir.as_str());
    load_persisted_metadata_state(state_path.as_path()).map_err(|err| {
        S3Error::service_unavailable(&format!(
            "Distributed metadata listing operation '{}' cannot load consensus metadata state: {}",
            operation, err
        ))
    })
}

fn build_consensus_v2_query(
    topology: &RuntimeTopologySnapshot,
    bucket: &str,
    query: &ListV2Query,
    snapshot_id: Option<&str>,
) -> MetadataQuery {
    let mut metadata_query = MetadataQuery::new(bucket);
    metadata_query.prefix = (!query.prefix.is_empty()).then_some(query.prefix.clone());
    metadata_query.view_id = Some(topology.membership_view_id.clone());
    metadata_query.snapshot_id = snapshot_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    metadata_query.max_keys = query.max_keys;
    metadata_query.continuation_token = query.continuation_token.clone().or_else(|| {
        query
            .effective_start
            .as_deref()
            .map(|start_after| encode_continuation_token_with_snapshot(start_after, snapshot_id))
    });
    metadata_query
}

fn build_consensus_v1_query(
    topology: &RuntimeTopologySnapshot,
    bucket: &str,
    query: &ListV1Query,
    snapshot_id: Option<&str>,
) -> MetadataQuery {
    let mut metadata_query = MetadataQuery::new(bucket);
    metadata_query.prefix = (!query.prefix.is_empty()).then_some(query.prefix.clone());
    metadata_query.view_id = Some(topology.membership_view_id.clone());
    metadata_query.snapshot_id = snapshot_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    metadata_query.max_keys = query.max_keys;
    metadata_query.continuation_token = query
        .marker
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(|marker| encode_continuation_token_with_snapshot(marker, snapshot_id));
    metadata_query
}

fn build_consensus_versions_query(
    topology: &RuntimeTopologySnapshot,
    bucket: &str,
    query: &ListVersionsQuery,
    snapshot_id: Option<&str>,
) -> MetadataVersionsQuery {
    let mut metadata_query = MetadataVersionsQuery::new(bucket);
    metadata_query.prefix = (!query.prefix.is_empty()).then_some(query.prefix.clone());
    metadata_query.view_id = Some(topology.membership_view_id.clone());
    metadata_query.snapshot_id = snapshot_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    metadata_query.key_marker = query.key_marker.clone();
    metadata_query.version_id_marker = query.version_id_marker.clone();
    metadata_query.max_keys = query.max_keys;
    metadata_query
}

fn hydrate_objects_from_consensus_states(
    operation: &str,
    objects: &[ObjectMeta],
    states: &[ObjectMetadataState],
) -> Result<Vec<ObjectMeta>, S3Error> {
    let mut by_key_and_version = BTreeMap::<(String, String), ObjectMeta>::new();
    let mut by_key = BTreeMap::<String, ObjectMeta>::new();
    for object in objects {
        let version_id = object.version_id.as_deref().unwrap_or("null").to_string();
        by_key_and_version
            .entry((object.key.clone(), version_id))
            .or_insert_with(|| object.clone());
        by_key
            .entry(object.key.clone())
            .or_insert_with(|| object.clone());
    }

    let mut page = Vec::with_capacity(states.len());
    for state in states {
        let version_id = state
            .latest_version_id
            .as_deref()
            .unwrap_or("null")
            .to_string();
        let key = state.key.clone();
        let hydrated = by_key_and_version
            .get(&(key.clone(), version_id))
            .cloned()
            .or_else(|| {
                if state.latest_version_id.is_none() {
                    by_key.get(&key).cloned()
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                S3Error::service_unavailable(&format!(
                    "Distributed metadata listing operation '{}' cannot hydrate canonical metadata row for key '{}'",
                    operation, key
                ))
            })?;
        page.push(hydrated);
    }
    Ok(page)
}

fn hydrate_versions_from_consensus_states(
    operation: &str,
    versions: &[ObjectMeta],
    states: &[ObjectVersionMetadataState],
) -> Result<Vec<ObjectMeta>, S3Error> {
    let mut by_key_and_version = BTreeMap::<(String, String), ObjectMeta>::new();
    for version in versions {
        let version_id = version.version_id.as_deref().unwrap_or("null").to_string();
        by_key_and_version
            .entry((version.key.clone(), version_id))
            .or_insert_with(|| version.clone());
    }

    let mut page = Vec::with_capacity(states.len());
    for state in states {
        let key = state.key.clone();
        let version_id = state.version_id.clone();
        let hydrated = by_key_and_version
            .get(&(key.clone(), version_id.clone()))
            .cloned()
            .ok_or_else(|| {
                S3Error::service_unavailable(&format!(
                    "Distributed metadata listing operation '{}' cannot hydrate canonical metadata row for key '{}' version '{}'",
                    operation, key, version_id
                ))
            })?;
        page.push(hydrated);
    }
    Ok(page)
}

pub(super) fn paginate_objects_v2_from_consensus_index_persisted_state(
    state: &AppState,
    topology: &RuntimeTopologySnapshot,
    bucket: &str,
    query: &ListV2Query,
    all_objects: &[ObjectMeta],
    snapshot_id: Option<&str>,
) -> Result<(Vec<ObjectMeta>, bool), S3Error> {
    let persisted_state = load_consensus_index_persisted_metadata_state(state, "ListObjectsV2")?;
    let metadata_query = build_consensus_v2_query(topology, bucket, query, snapshot_id);
    let canonical_page = list_objects_page_from_persisted_state(&persisted_state, &metadata_query)
        .map_err(|err| {
            S3Error::service_unavailable(&format!(
                "Distributed metadata listing operation 'ListObjectsV2' cannot query consensus metadata state: {:?}",
                err
            ))
        })?;
    let hydrated = hydrate_objects_from_consensus_states(
        "ListObjectsV2",
        all_objects,
        canonical_page.objects.as_slice(),
    )?;
    Ok((hydrated, canonical_page.is_truncated))
}

pub(super) fn paginate_objects_v1_from_consensus_index_persisted_state(
    state: &AppState,
    topology: &RuntimeTopologySnapshot,
    bucket: &str,
    query: &ListV1Query,
    all_objects: &[ObjectMeta],
    snapshot_id: Option<&str>,
) -> Result<(Vec<ObjectMeta>, bool), S3Error> {
    let persisted_state = load_consensus_index_persisted_metadata_state(state, "ListObjectsV1")?;
    let metadata_query = build_consensus_v1_query(topology, bucket, query, snapshot_id);
    let canonical_page = list_objects_page_from_persisted_state(&persisted_state, &metadata_query)
        .map_err(|err| {
            S3Error::service_unavailable(&format!(
                "Distributed metadata listing operation 'ListObjectsV1' cannot query consensus metadata state: {:?}",
                err
            ))
        })?;
    let hydrated = hydrate_objects_from_consensus_states(
        "ListObjectsV1",
        all_objects,
        canonical_page.objects.as_slice(),
    )?;
    Ok((hydrated, canonical_page.is_truncated))
}

pub(super) fn paginate_versions_from_consensus_index_persisted_state(
    state: &AppState,
    topology: &RuntimeTopologySnapshot,
    bucket: &str,
    query: &ListVersionsQuery,
    all_versions: &[ObjectMeta],
    snapshot_id: Option<&str>,
) -> Result<PaginatedVersionsPage, S3Error> {
    let persisted_state =
        load_consensus_index_persisted_metadata_state(state, "ListObjectVersions")?;
    let metadata_query = build_consensus_versions_query(topology, bucket, query, snapshot_id);
    let canonical_page =
        list_object_versions_page_from_persisted_state(&persisted_state, &metadata_query)
            .map_err(|err| {
                S3Error::service_unavailable(&format!(
                    "Distributed metadata listing operation 'ListObjectVersions' cannot query consensus metadata state: {:?}",
                    err
                ))
            })?;
    let hydrated = hydrate_versions_from_consensus_states(
        "ListObjectVersions",
        all_versions,
        canonical_page.versions.as_slice(),
    )?;
    let next_markers = match (
        canonical_page.next_key_marker,
        canonical_page.next_version_id_marker,
    ) {
        (Some(key), Some(version_id)) => Some((key, version_id)),
        _ => None,
    };
    Ok((hydrated, canonical_page.is_truncated, next_markers))
}

pub(super) async fn ensure_bucket_exists(state: &AppState, bucket: &str) -> Result<(), S3Error> {
    match state.storage.head_bucket(bucket).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(S3Error::no_such_bucket(bucket)),
        Err(err) => Err(S3Error::internal(err)),
    }
}

pub(super) fn map_bucket_storage_err(bucket: &str, err: StorageError) -> S3Error {
    match err {
        StorageError::NotFound(_) => S3Error::no_such_bucket(bucket),
        StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
        other => S3Error::internal(other),
    }
}

pub(super) fn validate_prefix(prefix: &str) -> Result<(), S3Error> {
    if prefix.is_empty() {
        return Ok(());
    }
    if prefix.len() > 1024 {
        return Err(S3Error::invalid_argument(
            "Prefix must not exceed 1024 bytes",
        ));
    }

    for component in Path::new(prefix).components() {
        match component {
            Component::ParentDir => {
                return Err(S3Error::invalid_argument(
                    "Prefix must not contain '..' path components",
                ));
            }
            Component::RootDir => {
                return Err(S3Error::invalid_argument(
                    "Prefix must not be an absolute path",
                ));
            }
            _ => {}
        }
    }

    Ok(())
}

pub(super) struct ListV2Query {
    pub(super) prefix: String,
    pub(super) delimiter: Option<String>,
    pub(super) max_keys: usize,
    pub(super) start_after: Option<String>,
    pub(super) continuation_token: Option<String>,
    pub(super) effective_start: Option<String>,
}

impl ListV2Query {
    pub(super) fn from_params(
        params: &HashMap<String, String>,
        expected_snapshot_id: Option<&str>,
    ) -> Result<Self, S3Error> {
        let start_after = params.get("start-after").cloned();
        let continuation_token = params.get("continuation-token").cloned();
        let expected_snapshot_id = expected_snapshot_id
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let effective_start = if let Some(token) = continuation_token.as_deref() {
            let decoded = decode_list_v2_continuation_token(token)
                .ok_or_else(|| S3Error::invalid_argument("Invalid continuation token"))?;
            let decoded_snapshot_id = decoded
                .snapshot_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            if expected_snapshot_id.is_some() && decoded_snapshot_id != expected_snapshot_id {
                return Err(S3Error::invalid_argument("Invalid continuation token"));
            }
            Some(decoded.start_after)
        } else {
            start_after.clone()
        };

        Ok(Self {
            prefix: params.get("prefix").cloned().unwrap_or_default(),
            delimiter: parse_delimiter(params)?,
            max_keys: parse_max_keys(params)?,
            start_after,
            continuation_token,
            effective_start,
        })
    }
}

pub(super) struct ListV1Query {
    pub(super) prefix: String,
    pub(super) delimiter: Option<String>,
    pub(super) max_keys: usize,
    pub(super) marker: Option<String>,
}

pub(super) struct ListVersionsQuery {
    pub(super) prefix: String,
    pub(super) key_marker: Option<String>,
    pub(super) version_id_marker: Option<String>,
    pub(super) max_keys: usize,
}

impl ListVersionsQuery {
    pub(super) fn from_params(params: &HashMap<String, String>) -> Result<Self, S3Error> {
        let key_marker = params
            .get("key-marker")
            .cloned()
            .filter(|value| !value.is_empty());
        let version_id_marker = params
            .get("version-id-marker")
            .cloned()
            .filter(|value| !value.is_empty());
        if version_id_marker.is_some() && key_marker.is_none() {
            return Err(S3Error::invalid_argument(
                "version-id-marker requires key-marker",
            ));
        }

        Ok(Self {
            prefix: params.get("prefix").cloned().unwrap_or_default(),
            key_marker,
            version_id_marker,
            max_keys: parse_max_keys(params)?,
        })
    }
}

impl ListV1Query {
    pub(super) fn from_params(params: &HashMap<String, String>) -> Result<Self, S3Error> {
        Ok(Self {
            prefix: params.get("prefix").cloned().unwrap_or_default(),
            delimiter: parse_delimiter(params)?,
            max_keys: parse_max_keys(params)?,
            marker: params.get("marker").cloned(),
        })
    }
}

fn parse_delimiter(params: &HashMap<String, String>) -> Result<Option<String>, S3Error> {
    match params.get("delimiter") {
        Some(delimiter) if delimiter.is_empty() => {
            Err(S3Error::invalid_argument("Invalid delimiter value"))
        }
        Some(delimiter) => Ok(Some(delimiter.clone())),
        None => Ok(None),
    }
}

fn parse_max_keys(params: &HashMap<String, String>) -> Result<usize, S3Error> {
    let Some(raw_max_keys) = params.get("max-keys").map(String::as_str) else {
        return Ok(MAX_KEYS_CAP);
    };

    let max_keys = raw_max_keys
        .parse::<usize>()
        .map_err(|_| S3Error::invalid_argument("Invalid max-keys value"))?;

    Ok(max_keys.min(MAX_KEYS_CAP))
}

#[cfg(test)]
pub(super) fn decode_continuation_token(token: &str) -> Option<String> {
    decode_list_v2_continuation_token(token).map(|decoded| decoded.start_after)
}

fn decode_list_v2_continuation_token(token: &str) -> Option<DecodedListV2ContinuationToken> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(token)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())?;
    if let Ok(payload) = serde_json::from_str::<ListV2ContinuationTokenPayload>(&decoded) {
        let start_after = payload.start_after.trim();
        if start_after.is_empty() {
            return None;
        }
        return Some(DecodedListV2ContinuationToken {
            start_after: start_after.to_string(),
            snapshot_id: payload
                .snapshot_id
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
        });
    }

    let start_after = decoded.trim();
    if start_after.is_empty() {
        return None;
    }

    Some(DecodedListV2ContinuationToken {
        start_after: start_after.to_string(),
        snapshot_id: None,
    })
}

#[cfg(test)]
pub(super) fn encode_continuation_token(key: &str) -> String {
    encode_continuation_token_with_snapshot(key, None)
}

pub(super) fn encode_continuation_token_with_snapshot(
    key: &str,
    snapshot_id: Option<&str>,
) -> String {
    use base64::Engine;
    let payload = ListV2ContinuationTokenPayload {
        start_after: key.to_string(),
        snapshot_id: snapshot_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
    };
    let encoded_payload = serde_json::to_string(&payload).unwrap_or_else(|_| key.to_string());
    base64::engine::general_purpose::STANDARD.encode(encoded_payload)
}

pub(super) fn filter_objects_after<'a>(
    all_objects: &'a [ObjectMeta],
    start_after: Option<&str>,
) -> Vec<&'a ObjectMeta> {
    all_objects
        .iter()
        .filter(|o| match start_after {
            Some(start) => o.key.as_str() > start,
            None => true,
        })
        .collect()
}

pub(super) fn paginate_objects(
    filtered_objects: Vec<&ObjectMeta>,
    max_keys: usize,
) -> (Vec<&ObjectMeta>, bool) {
    let is_truncated = filtered_objects.len() > max_keys;
    let page = filtered_objects.into_iter().take(max_keys).collect();
    (page, is_truncated)
}

pub(super) fn paginate_objects_v2_for_topology(
    topology: &RuntimeTopologySnapshot,
    strategy: ClusterMetadataListingStrategy,
    bucket: &str,
    query: &ListV2Query,
    all_objects: &[ObjectMeta],
) -> Result<(Vec<ObjectMeta>, bool), S3Error> {
    if !topology.is_distributed() {
        let filtered = filter_objects_after(all_objects, query.effective_start.as_deref());
        let (page, is_truncated) = paginate_objects(filtered, query.max_keys);
        return Ok((page.into_iter().cloned().collect(), is_truncated));
    }

    let filtered_states = all_objects
        .iter()
        .filter(|object| {
            query
                .effective_start
                .as_deref()
                .map(|start| object.key.as_str() > start)
                .unwrap_or(true)
        })
        .map(|object| ObjectMetadataState {
            bucket: bucket.to_string(),
            key: object.key.clone(),
            latest_version_id: object.version_id.clone(),
            is_delete_marker: object.is_delete_marker,
        })
        .collect::<Vec<_>>();

    let mut metadata_query = MetadataQuery::new(bucket);
    metadata_query.prefix = (!query.prefix.is_empty()).then_some(query.prefix.clone());
    metadata_query.view_id = Some(topology.membership_view_id.clone());
    metadata_query.max_keys = query.max_keys;

    let node_pages = vec![MetadataNodeObjectsPage {
        node_id: topology.node_id.clone(),
        objects: filtered_states,
    }];
    let merged = merge_cluster_list_objects_page_with_topology_snapshot(
        &metadata_query,
        strategy,
        topology.node_id.as_str(),
        topology.membership_nodes.as_slice(),
        node_pages.as_slice(),
    )
    .map_err(|_| S3Error::internal("Failed to merge distributed metadata listing page"))?;

    let object_lookup = all_objects
        .iter()
        .cloned()
        .map(|object| (object.key.clone(), object))
        .collect::<std::collections::BTreeMap<_, _>>();
    let page = merged
        .page
        .objects
        .into_iter()
        .filter_map(|object| object_lookup.get(&object.key).cloned())
        .collect::<Vec<_>>();

    Ok((page, merged.page.is_truncated))
}

pub(super) fn paginate_objects_v1_for_topology(
    topology: &RuntimeTopologySnapshot,
    strategy: ClusterMetadataListingStrategy,
    bucket: &str,
    query: &ListV1Query,
    all_objects: &[ObjectMeta],
) -> Result<(Vec<ObjectMeta>, bool), S3Error> {
    if !topology.is_distributed() {
        let filtered = filter_objects_after(all_objects, query.marker.as_deref());
        let (page, is_truncated) = paginate_objects(filtered, query.max_keys);
        return Ok((page.into_iter().cloned().collect(), is_truncated));
    }

    let object_states = all_objects
        .iter()
        .map(|object| ObjectMetadataState {
            bucket: bucket.to_string(),
            key: object.key.clone(),
            latest_version_id: object.version_id.clone(),
            is_delete_marker: object.is_delete_marker,
        })
        .collect::<Vec<_>>();

    let mut metadata_query = MetadataQuery::new(bucket);
    metadata_query.prefix = (!query.prefix.is_empty()).then_some(query.prefix.clone());
    metadata_query.view_id = Some(topology.membership_view_id.clone());
    metadata_query.max_keys = query.max_keys;

    let node_pages = vec![MetadataNodeObjectsPage {
        node_id: topology.node_id.clone(),
        objects: object_states,
    }];
    let merged = merge_cluster_list_objects_page_with_topology_snapshot_and_marker(
        &metadata_query,
        query.marker.as_deref(),
        strategy,
        topology.node_id.as_str(),
        topology.membership_nodes.as_slice(),
        node_pages.as_slice(),
    )
    .map_err(|_| S3Error::internal("Failed to merge distributed metadata listing page"))?;

    let object_lookup = all_objects
        .iter()
        .cloned()
        .map(|object| (object.key.clone(), object))
        .collect::<std::collections::BTreeMap<_, _>>();
    let page = merged
        .page
        .objects
        .into_iter()
        .filter_map(|object| object_lookup.get(&object.key).cloned())
        .collect::<Vec<_>>();

    Ok((page, merged.page.is_truncated))
}

pub(super) fn paginate_versions_for_topology(
    topology: &RuntimeTopologySnapshot,
    strategy: ClusterMetadataListingStrategy,
    bucket: &str,
    query: &ListVersionsQuery,
    all_versions: &[ObjectMeta],
) -> Result<PaginatedVersionsPage, S3Error> {
    if !topology.is_distributed() {
        let filtered = filter_versions_after(
            all_versions,
            query.key_marker.as_deref(),
            query.version_id_marker.as_deref(),
        );
        let (page, is_truncated, next_markers) = paginate_versions(filtered, query.max_keys);
        return Ok((
            page.into_iter().cloned().collect(),
            is_truncated,
            next_markers,
        ));
    }

    let latest_per_key = latest_version_per_key(all_versions);
    let version_states = all_versions
        .iter()
        .map(|version| {
            let version_id = version.version_id.as_deref().unwrap_or("null").to_string();
            let is_latest = latest_per_key
                .get(&version.key)
                .is_some_and(|latest| latest == &version_id);
            ObjectVersionMetadataState {
                bucket: bucket.to_string(),
                key: version.key.clone(),
                version_id,
                is_delete_marker: version.is_delete_marker,
                is_latest,
            }
        })
        .collect::<Vec<_>>();

    let mut metadata_query = MetadataVersionsQuery::new(bucket);
    metadata_query.prefix = (!query.prefix.is_empty()).then_some(query.prefix.clone());
    metadata_query.view_id = Some(topology.membership_view_id.clone());
    metadata_query.key_marker = query.key_marker.clone();
    metadata_query.version_id_marker = query.version_id_marker.clone();
    metadata_query.max_keys = query.max_keys;

    let node_pages = vec![MetadataNodeVersionsPage {
        node_id: topology.node_id.clone(),
        versions: version_states,
    }];
    let merged = merge_cluster_list_object_versions_page_with_topology_snapshot(
        &metadata_query,
        strategy,
        topology.node_id.as_str(),
        topology.membership_nodes.as_slice(),
        node_pages.as_slice(),
    )
    .map_err(|_| S3Error::internal("Failed to merge distributed metadata versions page"))?;

    let version_lookup = all_versions
        .iter()
        .cloned()
        .map(|version| {
            (
                (
                    version.key.clone(),
                    version.version_id.as_deref().unwrap_or("null").to_string(),
                ),
                version,
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let page = merged
        .page
        .versions
        .into_iter()
        .filter_map(|version| {
            version_lookup
                .get(&(version.key, version.version_id))
                .cloned()
        })
        .collect::<Vec<_>>();
    let next_markers = match (
        merged.page.next_key_marker,
        merged.page.next_version_id_marker,
    ) {
        (Some(key), Some(version_id)) => Some((key, version_id)),
        _ => None,
    };

    Ok((page, merged.page.is_truncated, next_markers))
}

pub(super) fn split_by_delimiter(
    page: &[&ObjectMeta],
    prefix: &str,
    delimiter: Option<&str>,
) -> (Vec<ObjectEntry>, Vec<CommonPrefix>) {
    if let Some(delim) = delimiter {
        let mut contents = Vec::new();
        let mut prefix_set = BTreeSet::new();

        for obj in page {
            let suffix = &obj.key[prefix.len()..];
            if let Some(pos) = suffix.find(delim) {
                let common = format!("{}{}", prefix, &suffix[..pos + delim.len()]);
                prefix_set.insert(common);
            } else {
                contents.push(to_object_entry(obj));
            }
        }

        let common_prefixes = prefix_set
            .into_iter()
            .map(|prefix| CommonPrefix { prefix })
            .collect();
        (contents, common_prefixes)
    } else {
        (page.iter().map(|o| to_object_entry(o)).collect(), vec![])
    }
}

fn to_object_entry(meta: &ObjectMeta) -> ObjectEntry {
    ObjectEntry {
        key: meta.key.clone(),
        last_modified: meta.last_modified.clone(),
        etag: meta.etag.clone(),
        size: meta.size,
        storage_class: "STANDARD".to_string(),
    }
}

pub(super) fn latest_version_per_key(versions: &[ObjectMeta]) -> HashMap<String, String> {
    let mut latest = HashMap::new();
    for version in versions {
        if let Some(version_id) = &version.version_id {
            latest
                .entry(version.key.clone())
                .or_insert_with(|| version_id.clone());
        }
    }
    latest
}

pub(super) fn filter_versions_after<'a>(
    all_versions: &'a [ObjectMeta],
    key_marker: Option<&str>,
    version_id_marker: Option<&str>,
) -> Vec<&'a ObjectMeta> {
    all_versions
        .iter()
        .filter(|version| {
            let Some(marker_key) = key_marker else {
                return true;
            };

            if version.key.as_str() > marker_key {
                return true;
            }
            if version.key.as_str() < marker_key {
                return false;
            }

            // Same key as marker key.
            let Some(marker_version_id) = version_id_marker else {
                // Key marker without version marker skips all versions for the marker key.
                return false;
            };
            let candidate_version_id = version.version_id.as_deref().unwrap_or("null");
            // Storage ordering is key asc + version_id desc, so "after marker" means lower version id.
            candidate_version_id < marker_version_id
        })
        .collect()
}

pub(super) fn paginate_versions(
    filtered_versions: Vec<&ObjectMeta>,
    max_keys: usize,
) -> (Vec<&ObjectMeta>, bool, Option<(String, String)>) {
    let is_truncated = filtered_versions.len() > max_keys;
    let page: Vec<&ObjectMeta> = filtered_versions.into_iter().take(max_keys).collect();
    let next_markers = if is_truncated {
        page.last().map(|version| {
            (
                version.key.clone(),
                version.version_id.as_deref().unwrap_or("null").to_string(),
            )
        })
    } else {
        None
    };
    (page, is_truncated, next_markers)
}

pub(super) fn split_version_entries(
    all_versions: &[ObjectMeta],
    latest_per_key: &HashMap<String, String>,
) -> (Vec<VersionEntry>, Vec<DeleteMarkerEntry>) {
    let mut versions = Vec::new();
    let mut delete_markers = Vec::new();

    for version in all_versions {
        let version_id = version.version_id.as_deref().unwrap_or("null");
        let is_latest = latest_per_key
            .get(&version.key)
            .is_some_and(|latest| latest == version_id);

        if version.is_delete_marker {
            delete_markers.push(DeleteMarkerEntry {
                key: version.key.clone(),
                version_id: version_id.to_string(),
                is_latest,
                last_modified: version.last_modified.clone(),
            });
        } else {
            versions.push(VersionEntry {
                key: version.key.clone(),
                version_id: version_id.to_string(),
                is_latest,
                last_modified: version.last_modified.clone(),
                etag: version.etag.clone(),
                size: version.size,
                storage_class: "STANDARD".to_string(),
            });
        }
    }

    (versions, delete_markers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MembershipProtocol;
    use crate::error::S3ErrorCode;
    use crate::membership::MembershipEngineStatus;
    use crate::metadata::ClusterMetadataListingStrategy;
    use crate::server::{RuntimeMode, RuntimeTopologySnapshot};

    fn object_meta(key: &str, version_id: Option<&str>, is_delete_marker: bool) -> ObjectMeta {
        ObjectMeta {
            key: key.to_string(),
            size: 10,
            etag: "\"etag\"".to_string(),
            content_type: "application/octet-stream".to_string(),
            last_modified: "2026-03-01T00:00:00Z".to_string(),
            version_id: version_id.map(ToString::to_string),
            is_delete_marker,
            storage_format: None,
            checksum_algorithm: None,
            checksum_value: None,
        }
    }

    #[test]
    fn continuation_token_roundtrip() {
        let key = "docs/nested/file.txt";
        let token = encode_continuation_token(key);
        assert_eq!(decode_continuation_token(&token), Some(key.to_string()));
    }

    #[test]
    fn continuation_token_with_snapshot_roundtrip() {
        let token = encode_continuation_token_with_snapshot("docs/a.txt", Some("snapshot-1"));
        let decoded = decode_list_v2_continuation_token(&token).expect("token should decode");
        assert_eq!(decoded.start_after, "docs/a.txt");
        assert_eq!(decoded.snapshot_id.as_deref(), Some("snapshot-1"));
    }

    #[test]
    fn continuation_token_legacy_payload_decodes_without_snapshot() {
        let key = "docs/legacy.txt";
        use base64::Engine;
        let legacy_token = base64::engine::general_purpose::STANDARD.encode(key);
        let decoded =
            decode_list_v2_continuation_token(&legacy_token).expect("legacy token should decode");
        assert_eq!(decoded.start_after, key);
        assert!(decoded.snapshot_id.is_none());
    }

    #[test]
    fn continuation_token_invalid_base64_returns_none() {
        assert_eq!(decode_continuation_token("%%%not-base64%%%"), None);
    }

    #[test]
    fn split_by_delimiter_groups_common_prefixes() {
        let objects = [
            object_meta("docs/a.txt", None, false),
            object_meta("docs/folder/one.txt", None, false),
            object_meta("docs/folder/two.txt", None, false),
            object_meta("docs/other/three.txt", None, false),
        ];
        let page: Vec<&ObjectMeta> = objects.iter().collect();

        let (contents, common_prefixes) = split_by_delimiter(&page, "docs/", Some("/"));

        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0].key, "docs/a.txt");
        assert_eq!(common_prefixes.len(), 2);
        assert_eq!(common_prefixes[0].prefix, "docs/folder/");
        assert_eq!(common_prefixes[1].prefix, "docs/other/");
    }

    #[test]
    fn split_by_delimiter_without_delimiter_returns_all_objects() {
        let objects = [
            object_meta("one.txt", None, false),
            object_meta("nested/two.txt", None, false),
        ];
        let page: Vec<&ObjectMeta> = objects.iter().collect();
        let (contents, common_prefixes) = split_by_delimiter(&page, "", None);

        assert_eq!(contents.len(), 2);
        assert!(common_prefixes.is_empty());
    }

    #[test]
    fn validate_prefix_accepts_normal_prefixes() {
        assert!(validate_prefix("").is_ok());
        assert!(validate_prefix("logs/2026/").is_ok());
        assert!(validate_prefix("tenant-a").is_ok());
    }

    #[test]
    fn validate_prefix_rejects_invalid_prefixes() {
        assert!(validate_prefix("../escape").is_err());
        assert!(validate_prefix("/absolute").is_err());
        assert!(validate_prefix(&"a".repeat(1025)).is_err());
    }

    #[test]
    fn split_version_entries_marks_latest_and_delete_markers() {
        let versions = [
            object_meta("a.txt", Some("v3"), true),
            object_meta("a.txt", Some("v2"), false),
            object_meta("a.txt", Some("v1"), false),
            object_meta("b.txt", Some("b2"), false),
            object_meta("b.txt", Some("b1"), true),
        ];

        let latest = latest_version_per_key(&versions);
        let (version_entries, delete_markers) = split_version_entries(&versions, &latest);

        assert_eq!(version_entries.len(), 3);
        assert_eq!(delete_markers.len(), 2);
        assert!(
            delete_markers
                .iter()
                .find(|v| v.key == "a.txt" && v.version_id == "v3")
                .expect("missing a.txt delete marker")
                .is_latest
        );
        assert!(
            !delete_markers
                .iter()
                .find(|v| v.key == "b.txt" && v.version_id == "b1")
                .expect("missing b.txt delete marker")
                .is_latest
        );
    }

    #[test]
    fn filter_versions_after_key_and_version_markers() {
        let versions = [
            object_meta("a.txt", Some("v3"), false),
            object_meta("a.txt", Some("v2"), false),
            object_meta("a.txt", Some("v1"), false),
            object_meta("b.txt", Some("b2"), false),
            object_meta("b.txt", Some("b1"), false),
        ];

        let filtered = filter_versions_after(&versions, Some("a.txt"), Some("v2"));
        let filtered_ids: Vec<_> = filtered
            .iter()
            .map(|version| {
                (
                    version.key.as_str(),
                    version.version_id.as_deref().unwrap_or("null"),
                )
            })
            .collect();
        assert_eq!(
            filtered_ids,
            vec![("a.txt", "v1"), ("b.txt", "b2"), ("b.txt", "b1")]
        );
    }

    #[test]
    fn filter_versions_after_key_marker_without_version_skips_marker_key() {
        let versions = [
            object_meta("a.txt", Some("v2"), false),
            object_meta("a.txt", Some("v1"), false),
            object_meta("b.txt", Some("b1"), false),
        ];

        let filtered = filter_versions_after(&versions, Some("a.txt"), None);
        let filtered_ids: Vec<_> = filtered
            .iter()
            .map(|version| {
                (
                    version.key.as_str(),
                    version.version_id.as_deref().unwrap_or("null"),
                )
            })
            .collect();
        assert_eq!(filtered_ids, vec![("b.txt", "b1")]);
    }

    #[test]
    fn paginate_versions_returns_next_markers_when_truncated() {
        let versions = [
            object_meta("a.txt", Some("v3"), false),
            object_meta("a.txt", Some("v2"), false),
            object_meta("b.txt", Some("b1"), false),
        ];
        let refs: Vec<&ObjectMeta> = versions.iter().collect();
        let (page, is_truncated, next_markers) = paginate_versions(refs, 2);

        assert_eq!(page.len(), 2);
        assert!(is_truncated);
        assert_eq!(next_markers, Some(("a.txt".to_string(), "v2".to_string())));
    }

    #[test]
    fn map_bucket_storage_err_maps_not_found_to_no_such_bucket() {
        let err = map_bucket_storage_err("missing", StorageError::NotFound("missing".to_string()));
        assert!(matches!(err.code, S3ErrorCode::NoSuchBucket));
    }

    #[test]
    fn map_bucket_storage_err_maps_invalid_key_to_invalid_argument() {
        let err = map_bucket_storage_err(
            "bucket",
            StorageError::InvalidKey("invalid prefix".to_string()),
        );
        assert!(matches!(err.code, S3ErrorCode::InvalidArgument));
    }

    #[test]
    fn resolve_bucket_get_operation_defaults_to_list_v1() {
        let params = HashMap::<String, String>::new();
        assert_eq!(
            resolve_bucket_get_operation(&params).expect("default list-v1 should resolve"),
            BucketGetOperation::ListV1
        );
    }

    #[test]
    fn resolve_bucket_get_operation_prefers_uploads_over_other_markers() {
        let mut params = HashMap::<String, String>::new();
        params.insert("uploads".to_string(), String::new());
        params.insert("versioning".to_string(), String::new());
        params.insert("lifecycle".to_string(), String::new());
        params.insert("versions".to_string(), String::new());
        params.insert("location".to_string(), String::new());
        params.insert("list-type".to_string(), "2".to_string());

        assert_eq!(
            resolve_bucket_get_operation(&params).expect("uploads should take precedence"),
            BucketGetOperation::ListUploads
        );
    }

    #[test]
    fn resolve_bucket_get_operation_picks_list_v2_from_query() {
        let mut params = HashMap::<String, String>::new();
        params.insert("list-type".to_string(), "2".to_string());

        assert_eq!(
            resolve_bucket_get_operation(&params).expect("list-type=2 should resolve"),
            BucketGetOperation::ListV2
        );
    }

    #[test]
    fn resolve_bucket_get_operation_rejects_invalid_list_type() {
        let mut params = HashMap::<String, String>::new();
        params.insert("list-type".to_string(), "1".to_string());

        let err = match resolve_bucket_get_operation(&params) {
            Ok(_) => panic!("invalid list-type should fail"),
            Err(err) => err,
        };
        assert!(matches!(
            err.code,
            crate::error::S3ErrorCode::InvalidArgument
        ));
    }

    #[test]
    fn list_v2_query_rejects_invalid_max_keys() {
        let mut params = HashMap::<String, String>::new();
        params.insert("max-keys".to_string(), "abc".to_string());
        let err = match ListV2Query::from_params(&params, None) {
            Ok(_) => panic!("invalid max-keys should fail"),
            Err(err) => err,
        };
        assert!(matches!(
            err.code,
            crate::error::S3ErrorCode::InvalidArgument
        ));
    }

    #[test]
    fn list_v2_query_rejects_invalid_continuation_token() {
        let mut params = HashMap::<String, String>::new();
        params.insert("continuation-token".to_string(), "%%%".to_string());
        let err = match ListV2Query::from_params(&params, None) {
            Ok(_) => panic!("invalid continuation token should fail"),
            Err(err) => err,
        };
        assert!(matches!(
            err.code,
            crate::error::S3ErrorCode::InvalidArgument
        ));
    }

    #[test]
    fn list_v2_query_rejects_empty_delimiter() {
        let mut params = HashMap::<String, String>::new();
        params.insert("delimiter".to_string(), String::new());

        let err = match ListV2Query::from_params(&params, None) {
            Ok(_) => panic!("empty delimiter should fail"),
            Err(err) => err,
        };
        assert!(matches!(
            err.code,
            crate::error::S3ErrorCode::InvalidArgument
        ));
    }

    #[test]
    fn list_v2_query_rejects_snapshot_mismatched_continuation_token() {
        let mut params = HashMap::<String, String>::new();
        params.insert(
            "continuation-token".to_string(),
            encode_continuation_token_with_snapshot("docs/a.txt", Some("snapshot-a")),
        );

        let err = match ListV2Query::from_params(&params, Some("snapshot-b")) {
            Ok(_) => panic!("snapshot-mismatched continuation token should fail"),
            Err(err) => err,
        };
        assert!(matches!(
            err.code,
            crate::error::S3ErrorCode::InvalidArgument
        ));
    }

    #[test]
    fn list_v2_query_accepts_snapshot_matched_continuation_token() {
        let mut params = HashMap::<String, String>::new();
        params.insert(
            "continuation-token".to_string(),
            encode_continuation_token_with_snapshot("docs/a.txt", Some("snapshot-a")),
        );
        let query = ListV2Query::from_params(&params, Some("snapshot-a"))
            .expect("snapshot-bound continuation token should parse");
        assert_eq!(query.effective_start.as_deref(), Some("docs/a.txt"));
    }

    #[test]
    fn paginate_objects_v2_for_topology_distributed_uses_metadata_merge_contract() {
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "node-a.internal:9000".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b.internal:9000".to_string()],
            membership_nodes: vec![
                "node-a.internal:9000".to_string(),
                "node-b.internal:9000".to_string(),
            ],
            membership_protocol: MembershipProtocol::StaticBootstrap,
            membership_status: MembershipEngineStatus {
                engine: "static-bootstrap".to_string(),
                protocol: "static-bootstrap".to_string(),
                ready: true,
                converged: true,
                last_update_unix_ms: 0,
                warning: None,
            },
            membership_view_id: "view-2".to_string(),
            placement_epoch: 2,
        };
        let objects = vec![
            object_meta("docs/a.txt", None, false),
            object_meta("docs/b.txt", None, false),
            object_meta("docs/c.txt", None, false),
        ];
        let query = ListV2Query {
            prefix: "docs/".to_string(),
            delimiter: None,
            max_keys: 2,
            start_after: None,
            continuation_token: None,
            effective_start: None,
        };

        let (page, is_truncated) = paginate_objects_v2_for_topology(
            &topology,
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            "photos",
            &query,
            objects.as_slice(),
        )
        .expect("distributed pagination should succeed");
        assert_eq!(
            page.iter()
                .map(|meta| meta.key.as_str())
                .collect::<Vec<_>>(),
            vec!["docs/a.txt", "docs/b.txt"]
        );
        assert!(is_truncated);
    }

    #[test]
    fn paginate_objects_v2_for_topology_distributed_honors_effective_start() {
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "node-a.internal:9000".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b.internal:9000".to_string()],
            membership_nodes: vec![
                "node-a.internal:9000".to_string(),
                "node-b.internal:9000".to_string(),
            ],
            membership_protocol: MembershipProtocol::StaticBootstrap,
            membership_status: MembershipEngineStatus {
                engine: "static-bootstrap".to_string(),
                protocol: "static-bootstrap".to_string(),
                ready: true,
                converged: true,
                last_update_unix_ms: 0,
                warning: None,
            },
            membership_view_id: "view-2".to_string(),
            placement_epoch: 2,
        };
        let objects = vec![
            object_meta("docs/a.txt", None, false),
            object_meta("docs/b.txt", None, false),
            object_meta("docs/c.txt", None, false),
        ];
        let query = ListV2Query {
            prefix: "docs/".to_string(),
            delimiter: None,
            max_keys: 2,
            start_after: Some("docs/a.txt".to_string()),
            continuation_token: None,
            effective_start: Some("docs/a.txt".to_string()),
        };

        let (page, is_truncated) = paginate_objects_v2_for_topology(
            &topology,
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            "photos",
            &query,
            objects.as_slice(),
        )
        .expect("distributed pagination should succeed");
        assert_eq!(
            page.iter()
                .map(|meta| meta.key.as_str())
                .collect::<Vec<_>>(),
            vec!["docs/b.txt", "docs/c.txt"]
        );
        assert!(!is_truncated);
    }

    #[test]
    fn paginate_objects_v1_for_topology_distributed_uses_metadata_merge_contract() {
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "node-a.internal:9000".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b.internal:9000".to_string()],
            membership_nodes: vec![
                "node-a.internal:9000".to_string(),
                "node-b.internal:9000".to_string(),
            ],
            membership_protocol: MembershipProtocol::StaticBootstrap,
            membership_status: MembershipEngineStatus {
                engine: "static-bootstrap".to_string(),
                protocol: "static-bootstrap".to_string(),
                ready: true,
                converged: true,
                last_update_unix_ms: 0,
                warning: None,
            },
            membership_view_id: "view-2".to_string(),
            placement_epoch: 2,
        };
        let objects = vec![
            object_meta("docs/a.txt", None, false),
            object_meta("docs/b.txt", None, false),
            object_meta("docs/c.txt", None, false),
        ];
        let query = ListV1Query {
            prefix: "docs/".to_string(),
            delimiter: None,
            max_keys: 2,
            marker: Some("docs/a.txt".to_string()),
        };

        let (page, is_truncated) = paginate_objects_v1_for_topology(
            &topology,
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            "photos",
            &query,
            objects.as_slice(),
        )
        .expect("distributed pagination should succeed");
        assert_eq!(
            page.iter()
                .map(|meta| meta.key.as_str())
                .collect::<Vec<_>>(),
            vec!["docs/b.txt", "docs/c.txt"]
        );
        assert!(!is_truncated);
    }

    #[test]
    fn paginate_versions_for_topology_distributed_uses_metadata_merge_contract() {
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "node-a.internal:9000".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b.internal:9000".to_string()],
            membership_nodes: vec![
                "node-a.internal:9000".to_string(),
                "node-b.internal:9000".to_string(),
            ],
            membership_protocol: MembershipProtocol::StaticBootstrap,
            membership_status: MembershipEngineStatus {
                engine: "static-bootstrap".to_string(),
                protocol: "static-bootstrap".to_string(),
                ready: true,
                converged: true,
                last_update_unix_ms: 0,
                warning: None,
            },
            membership_view_id: "view-2".to_string(),
            placement_epoch: 2,
        };
        let versions = vec![
            object_meta("docs/a.txt", Some("v3"), false),
            object_meta("docs/a.txt", Some("v2"), false),
            object_meta("docs/b.txt", Some("v1"), false),
        ];
        let query = ListVersionsQuery {
            prefix: "docs/".to_string(),
            key_marker: None,
            version_id_marker: None,
            max_keys: 2,
        };

        let (page, is_truncated, next_markers) = paginate_versions_for_topology(
            &topology,
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            "photos",
            &query,
            versions.as_slice(),
        )
        .expect("distributed versions pagination should succeed");

        assert_eq!(
            page.iter()
                .map(|meta| {
                    (
                        meta.key.as_str(),
                        meta.version_id.as_deref().unwrap_or("null"),
                    )
                })
                .collect::<Vec<_>>(),
            vec![("docs/a.txt", "v3"), ("docs/a.txt", "v2")]
        );
        assert!(is_truncated);
        assert_eq!(
            next_markers,
            Some(("docs/a.txt".to_string(), "v2".to_string()))
        );
    }

    #[test]
    fn paginate_versions_for_topology_distributed_honors_markers() {
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "node-a.internal:9000".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b.internal:9000".to_string()],
            membership_nodes: vec![
                "node-a.internal:9000".to_string(),
                "node-b.internal:9000".to_string(),
            ],
            membership_protocol: MembershipProtocol::StaticBootstrap,
            membership_status: MembershipEngineStatus {
                engine: "static-bootstrap".to_string(),
                protocol: "static-bootstrap".to_string(),
                ready: true,
                converged: true,
                last_update_unix_ms: 0,
                warning: None,
            },
            membership_view_id: "view-2".to_string(),
            placement_epoch: 2,
        };
        let versions = vec![
            object_meta("docs/a.txt", Some("v3"), false),
            object_meta("docs/a.txt", Some("v2"), false),
            object_meta("docs/a.txt", Some("v1"), false),
            object_meta("docs/b.txt", Some("v2"), false),
        ];
        let query = ListVersionsQuery {
            prefix: "docs/".to_string(),
            key_marker: Some("docs/a.txt".to_string()),
            version_id_marker: Some("v2".to_string()),
            max_keys: 2,
        };

        let (page, is_truncated, next_markers) = paginate_versions_for_topology(
            &topology,
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            "photos",
            &query,
            versions.as_slice(),
        )
        .expect("distributed versions pagination should succeed");

        assert_eq!(
            page.iter()
                .map(|meta| {
                    (
                        meta.key.as_str(),
                        meta.version_id.as_deref().unwrap_or("null"),
                    )
                })
                .collect::<Vec<_>>(),
            vec![("docs/a.txt", "v1"), ("docs/b.txt", "v2")]
        );
        assert!(!is_truncated);
        assert!(next_markers.is_none());
    }

    #[test]
    fn list_v1_query_rejects_empty_delimiter() {
        let mut params = HashMap::<String, String>::new();
        params.insert("delimiter".to_string(), String::new());

        let err = match ListV1Query::from_params(&params) {
            Ok(_) => panic!("empty delimiter should fail"),
            Err(err) => err,
        };
        assert!(matches!(
            err.code,
            crate::error::S3ErrorCode::InvalidArgument
        ));
    }

    #[test]
    fn list_versions_query_rejects_invalid_max_keys() {
        let mut params = HashMap::<String, String>::new();
        params.insert("max-keys".to_string(), "abc".to_string());
        let err = match ListVersionsQuery::from_params(&params) {
            Ok(_) => panic!("invalid max-keys should fail"),
            Err(err) => err,
        };
        assert!(matches!(
            err.code,
            crate::error::S3ErrorCode::InvalidArgument
        ));
    }

    #[test]
    fn list_versions_query_rejects_orphaned_version_id_marker() {
        let mut params = HashMap::<String, String>::new();
        params.insert("version-id-marker".to_string(), "v1".to_string());

        let err = match ListVersionsQuery::from_params(&params) {
            Ok(_) => panic!("version-id-marker without key-marker should fail"),
            Err(err) => err,
        };
        assert!(matches!(
            err.code,
            crate::error::S3ErrorCode::InvalidArgument
        ));
    }

    #[test]
    fn metadata_coverage_for_standalone_topology_is_none() {
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Standalone,
            node_id: "node-a.internal:9000".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec![],
            membership_nodes: vec!["node-a.internal:9000".to_string()],
            membership_protocol: MembershipProtocol::StaticBootstrap,
            membership_status: MembershipEngineStatus {
                engine: "static-bootstrap".to_string(),
                protocol: "static-bootstrap".to_string(),
                ready: true,
                converged: true,
                last_update_unix_ms: 0,
                warning: None,
            },
            membership_view_id: "view-1".to_string(),
            placement_epoch: 1,
        };

        assert!(
            metadata_coverage_for_topology(
                &topology,
                ClusterMetadataListingStrategy::LocalNodeOnly
            )
            .is_none()
        );
    }

    #[test]
    fn metadata_coverage_for_distributed_topology_local_node_only_reports_local_fan_in() {
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "node-a.internal:9000".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b.internal:9000".to_string()],
            membership_nodes: vec![
                "node-a.internal:9000".to_string(),
                "node-b.internal:9000".to_string(),
            ],
            membership_protocol: MembershipProtocol::StaticBootstrap,
            membership_status: MembershipEngineStatus {
                engine: "static-bootstrap".to_string(),
                protocol: "static-bootstrap".to_string(),
                ready: true,
                converged: true,
                last_update_unix_ms: 0,
                warning: None,
            },
            membership_view_id: "view-2".to_string(),
            placement_epoch: 2,
        };

        let coverage = metadata_coverage_for_topology(
            &topology,
            ClusterMetadataListingStrategy::LocalNodeOnly,
        )
        .expect("distributed topology should report coverage");
        assert_eq!(
            coverage,
            ListMetadataCoverage {
                expected_nodes: 1,
                responded_nodes: 1,
                missing_nodes: 0,
                unexpected_nodes: 0,
                complete: true,
                snapshot_id: coverage.snapshot_id.clone(),
                source: "local-node-only",
                strategy_cluster_authoritative: false,
                strategy_ready: false,
                strategy_gap: Some("strategy-not-cluster-authoritative"),
                strategy_reject_reason: None,
            }
        );
    }

    #[test]
    fn metadata_coverage_for_distributed_topology_reports_incomplete_fan_in_for_aggregation() {
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "node-a.internal:9000".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b.internal:9000".to_string()],
            membership_nodes: vec![
                "node-a.internal:9000".to_string(),
                "node-b.internal:9000".to_string(),
            ],
            membership_protocol: MembershipProtocol::StaticBootstrap,
            membership_status: MembershipEngineStatus {
                engine: "static-bootstrap".to_string(),
                protocol: "static-bootstrap".to_string(),
                ready: true,
                converged: true,
                last_update_unix_ms: 0,
                warning: None,
            },
            membership_view_id: "view-2".to_string(),
            placement_epoch: 2,
        };

        let coverage = metadata_coverage_for_topology(
            &topology,
            ClusterMetadataListingStrategy::RequestTimeAggregation,
        )
        .expect("distributed topology should report coverage");
        assert_eq!(
            coverage,
            ListMetadataCoverage {
                expected_nodes: 2,
                responded_nodes: 1,
                missing_nodes: 1,
                unexpected_nodes: 0,
                complete: false,
                snapshot_id: coverage.snapshot_id.clone(),
                source: "request-time-aggregation",
                strategy_cluster_authoritative: true,
                strategy_ready: false,
                strategy_gap: Some("missing-expected-nodes"),
                strategy_reject_reason: Some("missing-expected-nodes"),
            }
        );
    }

    #[test]
    fn metadata_coverage_for_distributed_topology_handles_invalid_local_node_id() {
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "   ".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b.internal:9000".to_string()],
            membership_nodes: vec!["node-a.internal:9000".to_string(), "   ".to_string()],
            membership_protocol: MembershipProtocol::StaticBootstrap,
            membership_status: MembershipEngineStatus {
                engine: "static-bootstrap".to_string(),
                protocol: "static-bootstrap".to_string(),
                ready: true,
                converged: true,
                last_update_unix_ms: 0,
                warning: None,
            },
            membership_view_id: "view-2".to_string(),
            placement_epoch: 2,
        };

        let coverage = metadata_coverage_for_topology(
            &topology,
            ClusterMetadataListingStrategy::ConsensusIndex,
        )
        .expect("distributed topology should report coverage");
        assert_eq!(
            coverage,
            ListMetadataCoverage {
                expected_nodes: 1,
                responded_nodes: 0,
                missing_nodes: 1,
                unexpected_nodes: 0,
                complete: false,
                snapshot_id: coverage.snapshot_id.clone(),
                source: "consensus-index",
                strategy_cluster_authoritative: true,
                strategy_ready: false,
                strategy_gap: Some("missing-expected-nodes"),
                strategy_reject_reason: Some("missing-expected-nodes"),
            }
        );
        assert_eq!(coverage.snapshot_id.len(), 64);
    }

    #[test]
    fn metadata_coverage_snapshot_id_changes_when_strategy_changes() {
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "node-a.internal:9000".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b.internal:9000".to_string()],
            membership_nodes: vec![
                "node-a.internal:9000".to_string(),
                "node-b.internal:9000".to_string(),
            ],
            membership_protocol: MembershipProtocol::StaticBootstrap,
            membership_status: MembershipEngineStatus {
                engine: "static-bootstrap".to_string(),
                protocol: "static-bootstrap".to_string(),
                ready: true,
                converged: true,
                last_update_unix_ms: 0,
                warning: None,
            },
            membership_view_id: "view-2".to_string(),
            placement_epoch: 2,
        };

        let local_only = metadata_coverage_for_topology(
            &topology,
            ClusterMetadataListingStrategy::LocalNodeOnly,
        )
        .expect("distributed topology should report coverage");
        let consensus = metadata_coverage_for_topology(
            &topology,
            ClusterMetadataListingStrategy::ConsensusIndex,
        )
        .expect("distributed topology should report coverage");

        assert_eq!(local_only.snapshot_id.len(), 64);
        assert_eq!(consensus.snapshot_id.len(), 64);
        assert_ne!(local_only.snapshot_id, consensus.snapshot_id);
    }

    #[test]
    fn metadata_coverage_for_consensus_fallback_keeps_source_and_uses_cluster_execution_readiness()
    {
        let topology = RuntimeTopologySnapshot {
            mode: RuntimeMode::Distributed,
            node_id: "node-a.internal:9000".to_string(),
            cluster_id: "cluster-a".to_string(),
            cluster_peers: vec!["node-b.internal:9000".to_string()],
            membership_nodes: vec![
                "node-a.internal:9000".to_string(),
                "node-b.internal:9000".to_string(),
            ],
            membership_protocol: MembershipProtocol::StaticBootstrap,
            membership_status: MembershipEngineStatus {
                engine: "static-bootstrap".to_string(),
                protocol: "static-bootstrap".to_string(),
                ready: true,
                converged: true,
                last_update_unix_ms: 0,
                warning: None,
            },
            membership_view_id: "view-2".to_string(),
            placement_epoch: 2,
        };

        let responders = vec![
            "node-a.internal:9000".to_string(),
            "node-b.internal:9000".to_string(),
        ];
        let coverage = metadata_coverage_for_topology_responders(
            &topology,
            ClusterMetadataListingStrategy::ConsensusIndex,
            responders.as_slice(),
        )
        .expect("distributed topology should report coverage");
        assert_eq!(
            coverage,
            ListMetadataCoverage {
                expected_nodes: 2,
                responded_nodes: 2,
                missing_nodes: 0,
                unexpected_nodes: 0,
                complete: true,
                snapshot_id: coverage.snapshot_id.clone(),
                source: "consensus-index",
                strategy_cluster_authoritative: true,
                strategy_ready: true,
                strategy_gap: None,
                strategy_reject_reason: None,
            }
        );
    }

    #[test]
    fn distributed_listing_strategy_readiness_allows_non_authoritative_local_mode() {
        let coverage = ListMetadataCoverage {
            expected_nodes: 2,
            responded_nodes: 1,
            missing_nodes: 1,
            unexpected_nodes: 0,
            complete: false,
            snapshot_id: "snapshot-local".to_string(),
            source: "local-node-only",
            strategy_cluster_authoritative: false,
            strategy_ready: false,
            strategy_gap: Some("strategy-not-cluster-authoritative"),
            strategy_reject_reason: None,
        };

        let result = ensure_distributed_listing_strategy_ready(Some(&coverage));
        assert!(result.is_ok());
    }

    #[test]
    fn distributed_listing_strategy_readiness_rejects_unready_authoritative_mode() {
        let coverage = ListMetadataCoverage {
            expected_nodes: 2,
            responded_nodes: 1,
            missing_nodes: 1,
            unexpected_nodes: 0,
            complete: false,
            snapshot_id: "snapshot-agg".to_string(),
            source: "request-time-aggregation",
            strategy_cluster_authoritative: true,
            strategy_ready: false,
            strategy_gap: Some("missing-expected-nodes"),
            strategy_reject_reason: Some("missing-expected-nodes"),
        };

        let err = ensure_distributed_listing_strategy_ready(Some(&coverage))
            .expect_err("authoritative distributed listing should fail when not ready");
        assert!(matches!(
            err.code,
            crate::error::S3ErrorCode::ServiceUnavailable
        ));
    }
}
