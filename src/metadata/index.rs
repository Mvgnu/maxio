use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::state::{BucketMetadataState, ObjectMetadataState, ObjectVersionMetadataState};

const METADATA_CONTINUATION_TOKEN_PREFIX: &str = "v1:";
const METADATA_VERSIONS_CONTINUATION_TOKEN_PREFIX: &str = "v1v:";
const METADATA_LIST_MAX_KEYS: usize = 1000;
pub const CLUSTER_METADATA_CONSENSUS_FAN_IN_AUTH_TOKEN_MISSING_REASON: &str =
    "consensus-index-peer-fan-in-auth-token-missing";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataQuery {
    pub bucket: String,
    pub prefix: Option<String>,
    pub view_id: Option<String>,
    pub snapshot_id: Option<String>,
    pub continuation_token: Option<String>,
    pub max_keys: usize,
}

impl MetadataQuery {
    pub fn new(bucket: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            prefix: None,
            view_id: None,
            snapshot_id: None,
            continuation_token: None,
            max_keys: METADATA_LIST_MAX_KEYS,
        }
    }

    fn effective_max_keys(&self) -> usize {
        self.max_keys.clamp(1, METADATA_LIST_MAX_KEYS)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataVersionsQuery {
    pub bucket: String,
    pub prefix: Option<String>,
    pub view_id: Option<String>,
    pub snapshot_id: Option<String>,
    pub continuation_token: Option<String>,
    pub key_marker: Option<String>,
    pub version_id_marker: Option<String>,
    pub max_keys: usize,
}

impl MetadataVersionsQuery {
    pub fn new(bucket: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            prefix: None,
            view_id: None,
            snapshot_id: None,
            continuation_token: None,
            key_marker: None,
            version_id_marker: None,
            max_keys: METADATA_LIST_MAX_KEYS,
        }
    }

    fn effective_max_keys(&self) -> usize {
        self.max_keys.clamp(1, METADATA_LIST_MAX_KEYS)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataQueryError {
    InvalidContinuationToken,
    InvalidVersionsMarker,
    InvalidCoverageNodeId,
    DuplicateCoverageExpectedNode,
    DuplicateCoverageNodeResponse,
    InconsistentBucketMetadataResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataListPage {
    pub objects: Vec<ObjectMetadataState>,
    pub is_truncated: bool,
    pub next_continuation_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataVersionsPage {
    pub versions: Vec<ObjectVersionMetadataState>,
    pub is_truncated: bool,
    pub next_continuation_token: Option<String>,
    pub next_key_marker: Option<String>,
    pub next_version_id_marker: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataNodeObjectsPage {
    pub node_id: String,
    pub objects: Vec<ObjectMetadataState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataNodeVersionsPage {
    pub node_id: String,
    pub versions: Vec<ObjectVersionMetadataState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataNodeBucketsPage {
    pub node_id: String,
    pub buckets: Vec<BucketMetadataState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterMetadataCoverage {
    pub expected_nodes: Vec<String>,
    pub responded_nodes: Vec<String>,
    pub missing_nodes: Vec<String>,
    pub unexpected_nodes: Vec<String>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterMergedObjectsPage {
    pub page: MetadataListPage,
    pub coverage: ClusterMetadataCoverage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterMergedVersionsPage {
    pub page: MetadataVersionsPage,
    pub coverage: ClusterMetadataCoverage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterMergedBucketsPage {
    pub buckets: Vec<BucketMetadataState>,
    pub coverage: ClusterMetadataCoverage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterTopologyMergedObjectsPage {
    pub page: MetadataListPage,
    pub snapshot: ClusterMetadataSnapshotAssessment,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterTopologyMergedVersionsPage {
    pub page: MetadataVersionsPage,
    pub snapshot: ClusterMetadataSnapshotAssessment,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterTopologyMergedBucketsPage {
    pub buckets: Vec<BucketMetadataState>,
    pub snapshot: ClusterMetadataSnapshotAssessment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterMetadataCoverageGap {
    MissingExpectedNodes,
    UnexpectedResponderNodes,
    MissingAndUnexpectedNodes,
}

impl ClusterMetadataCoverageGap {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingExpectedNodes => "missing-expected-nodes",
            Self::UnexpectedResponderNodes => "unexpected-responder-nodes",
            Self::MissingAndUnexpectedNodes => "missing-and-unexpected-nodes",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterMetadataCoverageAssessment {
    pub complete: bool,
    pub gap: Option<ClusterMetadataCoverageGap>,
    pub expected_nodes: usize,
    pub responded_nodes: usize,
    pub missing_nodes: usize,
    pub unexpected_nodes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterMetadataListingStrategy {
    LocalNodeOnly,
    RequestTimeAggregation,
    ConsensusIndex,
    FullReplication,
}

impl ClusterMetadataListingStrategy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalNodeOnly => "local-node-only",
            Self::RequestTimeAggregation => "request-time-aggregation",
            Self::ConsensusIndex => "consensus-index",
            Self::FullReplication => "full-replication",
        }
    }

    pub const fn is_cluster_authoritative(self) -> bool {
        !matches!(self, Self::LocalNodeOnly)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterMetadataReadinessGap {
    StrategyNotClusterAuthoritative,
    MissingExpectedNodes,
    UnexpectedResponderNodes,
    MissingAndUnexpectedNodes,
}

impl ClusterMetadataReadinessGap {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StrategyNotClusterAuthoritative => "strategy-not-cluster-authoritative",
            Self::MissingExpectedNodes => "missing-expected-nodes",
            Self::UnexpectedResponderNodes => "unexpected-responder-nodes",
            Self::MissingAndUnexpectedNodes => "missing-and-unexpected-nodes",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterMetadataReadinessAssessment {
    pub strategy: ClusterMetadataListingStrategy,
    pub cluster_authoritative: bool,
    pub ready: bool,
    pub coverage_complete: bool,
    pub coverage_gap: Option<ClusterMetadataCoverageGap>,
    pub gap: Option<ClusterMetadataReadinessGap>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterMetadataSnapshotAssessment {
    pub strategy: ClusterMetadataListingStrategy,
    pub view_id: Option<String>,
    pub coverage: ClusterMetadataCoverage,
    pub coverage_assessment: ClusterMetadataCoverageAssessment,
    pub readiness_assessment: ClusterMetadataReadinessAssessment,
    pub snapshot_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterResponderMembershipView {
    pub node_id: String,
    pub membership_view_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterResponderMembershipViewGap {
    MissingResponderMembershipViewId,
    InconsistentResponderMembershipViewId,
    MembershipViewIdMismatch,
}

impl ClusterResponderMembershipViewGap {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingResponderMembershipViewId => "missing-responder-membership-view-id",
            Self::InconsistentResponderMembershipViewId => {
                "inconsistent-responder-membership-view-id"
            }
            Self::MembershipViewIdMismatch => "membership-view-id-mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterResponderMembershipViewAssessment {
    pub consistent: bool,
    pub gap: Option<ClusterResponderMembershipViewGap>,
    pub expected_view_id: Option<String>,
    pub observed_view_id: Option<String>,
    pub responders: usize,
    pub missing_nodes: Vec<String>,
    pub mismatched_nodes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterMetadataFanInPreflightGap {
    StrategyNotClusterAuthoritative,
    MissingExpectedNodes,
    UnexpectedResponderNodes,
    MissingAndUnexpectedNodes,
    MissingResponderMembershipViewId,
    InconsistentResponderMembershipViewId,
    MembershipViewIdMismatch,
}

impl ClusterMetadataFanInPreflightGap {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StrategyNotClusterAuthoritative => "strategy-not-cluster-authoritative",
            Self::MissingExpectedNodes => "missing-expected-nodes",
            Self::UnexpectedResponderNodes => "unexpected-responder-nodes",
            Self::MissingAndUnexpectedNodes => "missing-and-unexpected-nodes",
            Self::MissingResponderMembershipViewId => "missing-responder-membership-view-id",
            Self::InconsistentResponderMembershipViewId => {
                "inconsistent-responder-membership-view-id"
            }
            Self::MembershipViewIdMismatch => "membership-view-id-mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterMetadataFanInPreflightAssessment {
    pub ready: bool,
    pub snapshot: ClusterMetadataSnapshotAssessment,
    pub responder_membership_views: ClusterResponderMembershipViewAssessment,
    pub gap: Option<ClusterMetadataFanInPreflightGap>,
}

pub fn cluster_metadata_readiness_reject_reason(
    readiness: &ClusterMetadataReadinessAssessment,
) -> Option<ClusterMetadataReadinessGap> {
    if readiness.cluster_authoritative && !readiness.ready {
        readiness.gap
    } else {
        None
    }
}

pub fn assess_cluster_responder_membership_views(
    expected_view_id: Option<&str>,
    responders: &[ClusterResponderMembershipView],
) -> ClusterResponderMembershipViewAssessment {
    let expected_view_id = expected_view_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);

    let mut missing_nodes = Vec::new();
    let mut mismatched_nodes = Vec::new();
    let mut observed_views = BTreeSet::new();
    for responder in responders {
        let normalized = responder
            .membership_view_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        match normalized {
            Some(view_id) => {
                if let Some(expected) = expected_view_id.as_deref() {
                    if view_id != expected {
                        mismatched_nodes.push(responder.node_id.clone());
                    }
                }
                observed_views.insert(view_id);
            }
            None => {
                missing_nodes.push(responder.node_id.clone());
            }
        }
    }

    let observed_view_id = if observed_views.len() == 1 {
        observed_views.iter().next().cloned()
    } else {
        None
    };
    let gap = if responders.is_empty() || !missing_nodes.is_empty() {
        Some(ClusterResponderMembershipViewGap::MissingResponderMembershipViewId)
    } else if observed_views.len() > 1 {
        Some(ClusterResponderMembershipViewGap::InconsistentResponderMembershipViewId)
    } else if !mismatched_nodes.is_empty() {
        Some(ClusterResponderMembershipViewGap::MembershipViewIdMismatch)
    } else {
        None
    };

    ClusterResponderMembershipViewAssessment {
        consistent: gap.is_none(),
        gap,
        expected_view_id,
        observed_view_id,
        responders: responders.len(),
        missing_nodes,
        mismatched_nodes,
    }
}

pub fn cluster_metadata_fan_in_preflight_reject_reason(
    preflight: &ClusterMetadataFanInPreflightAssessment,
) -> Option<ClusterMetadataFanInPreflightGap> {
    if preflight.ready { None } else { preflight.gap }
}

fn build_cluster_metadata_fan_in_preflight_assessment(
    snapshot: ClusterMetadataSnapshotAssessment,
    responders: &[ClusterResponderMembershipView],
) -> ClusterMetadataFanInPreflightAssessment {
    let responder_membership_views =
        assess_cluster_responder_membership_views(snapshot.view_id.as_deref(), responders);
    let gap = cluster_metadata_readiness_reject_reason(&snapshot.readiness_assessment)
        .map(|readiness_gap| match readiness_gap {
            ClusterMetadataReadinessGap::StrategyNotClusterAuthoritative => {
                ClusterMetadataFanInPreflightGap::StrategyNotClusterAuthoritative
            }
            ClusterMetadataReadinessGap::MissingExpectedNodes => {
                ClusterMetadataFanInPreflightGap::MissingExpectedNodes
            }
            ClusterMetadataReadinessGap::UnexpectedResponderNodes => {
                ClusterMetadataFanInPreflightGap::UnexpectedResponderNodes
            }
            ClusterMetadataReadinessGap::MissingAndUnexpectedNodes => {
                ClusterMetadataFanInPreflightGap::MissingAndUnexpectedNodes
            }
        })
        .or_else(|| {
            responder_membership_views
                .gap
                .map(|membership_gap| match membership_gap {
                    ClusterResponderMembershipViewGap::MissingResponderMembershipViewId => {
                        ClusterMetadataFanInPreflightGap::MissingResponderMembershipViewId
                    }
                    ClusterResponderMembershipViewGap::InconsistentResponderMembershipViewId => {
                        ClusterMetadataFanInPreflightGap::InconsistentResponderMembershipViewId
                    }
                    ClusterResponderMembershipViewGap::MembershipViewIdMismatch => {
                        ClusterMetadataFanInPreflightGap::MembershipViewIdMismatch
                    }
                })
        });

    ClusterMetadataFanInPreflightAssessment {
        ready: gap.is_none(),
        snapshot,
        responder_membership_views,
        gap,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterBucketMetadataConsistencyGap {
    MissingBucketOnResponder,
    InconsistentResponderValues,
    NoResponderValues,
}

impl ClusterBucketMetadataConsistencyGap {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingBucketOnResponder => "missing-bucket-on-responder",
            Self::InconsistentResponderValues => "inconsistent-responder-values",
            Self::NoResponderValues => "no-responder-values",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterBucketMetadataResponderState<T> {
    MissingBucket,
    Present(T),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterBucketMetadataConsistencyAssessment<T> {
    pub consistent: bool,
    pub gap: Option<ClusterBucketMetadataConsistencyGap>,
    pub missing_bucket_responders: usize,
    pub value: Option<T>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterBucketPresenceReadResolution {
    Present,
    Missing,
    Inconsistent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterBucketPresenceConvergenceExpectation {
    Present,
    Missing,
}

impl ClusterBucketPresenceConvergenceExpectation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Missing => "missing",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterBucketPresenceConvergenceGap {
    MissingBucketOnResponder,
    InconsistentResponderValues,
    NoResponderValues,
    UnexpectedResponderPresenceState,
}

impl ClusterBucketPresenceConvergenceGap {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingBucketOnResponder => "missing-bucket-on-responder",
            Self::InconsistentResponderValues => "inconsistent-responder-values",
            Self::NoResponderValues => "no-responder-values",
            Self::UnexpectedResponderPresenceState => "unexpected-responder-presence-state",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterBucketPresenceConvergenceAssessment {
    pub expectation: ClusterBucketPresenceConvergenceExpectation,
    pub converged: bool,
    pub consistency: ClusterBucketMetadataConsistencyAssessment<bool>,
    pub gap: Option<ClusterBucketPresenceConvergenceGap>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterBucketMetadataReadResolution<T> {
    Present(T),
    Missing,
    Inconsistent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterBucketMetadataResponderSnapshot<T> {
    pub node_id: String,
    pub state: ClusterBucketMetadataResponderState<T>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterBucketMetadataConvergenceGap {
    StrategyNotClusterAuthoritative,
    MissingExpectedNodes,
    UnexpectedResponderNodes,
    MissingAndUnexpectedNodes,
    MissingBucketOnResponder,
    InconsistentResponderValues,
    NoResponderValues,
}

impl ClusterBucketMetadataConvergenceGap {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StrategyNotClusterAuthoritative => "strategy-not-cluster-authoritative",
            Self::MissingExpectedNodes => "missing-expected-nodes",
            Self::UnexpectedResponderNodes => "unexpected-responder-nodes",
            Self::MissingAndUnexpectedNodes => "missing-and-unexpected-nodes",
            Self::MissingBucketOnResponder => "missing-bucket-on-responder",
            Self::InconsistentResponderValues => "inconsistent-responder-values",
            Self::NoResponderValues => "no-responder-values",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterBucketMetadataConvergenceAssessment<T> {
    pub ready: bool,
    pub snapshot: ClusterMetadataSnapshotAssessment,
    pub consistency: ClusterBucketMetadataConsistencyAssessment<T>,
    pub gap: Option<ClusterBucketMetadataConvergenceGap>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterBucketMetadataMutationPreconditionGap {
    StrategyNotClusterAuthoritative,
    MissingExpectedNodes,
    UnexpectedResponderNodes,
    MissingAndUnexpectedNodes,
    BucketMissing,
    MissingBucketOnResponder,
    InconsistentResponderValues,
    NoResponderValues,
}

impl ClusterBucketMetadataMutationPreconditionGap {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StrategyNotClusterAuthoritative => "strategy-not-cluster-authoritative",
            Self::MissingExpectedNodes => "missing-expected-nodes",
            Self::UnexpectedResponderNodes => "unexpected-responder-nodes",
            Self::MissingAndUnexpectedNodes => "missing-and-unexpected-nodes",
            Self::BucketMissing => "bucket-missing",
            Self::MissingBucketOnResponder => "missing-bucket-on-responder",
            Self::InconsistentResponderValues => "inconsistent-responder-values",
            Self::NoResponderValues => "no-responder-values",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterBucketMetadataMutationPreconditionAssessment<T> {
    pub ready: bool,
    pub current_value: Option<T>,
    pub convergence: ClusterBucketMetadataConvergenceAssessment<T>,
    pub gap: Option<ClusterBucketMetadataMutationPreconditionGap>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterBucketMetadataConvergenceInputError {
    ResponderStateCardinalityMismatch,
    InvalidResponderTopology(MetadataQueryError),
}

impl ClusterBucketMetadataConvergenceInputError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ResponderStateCardinalityMismatch => "responder-state-cardinality-mismatch",
            Self::InvalidResponderTopology(error) => match error {
                MetadataQueryError::InvalidContinuationToken => "invalid-continuation-token",
                MetadataQueryError::InvalidVersionsMarker => "invalid-versions-marker",
                MetadataQueryError::InvalidCoverageNodeId => "invalid-coverage-node-id",
                MetadataQueryError::DuplicateCoverageExpectedNode => {
                    "duplicate-coverage-expected-node"
                }
                MetadataQueryError::DuplicateCoverageNodeResponse => {
                    "duplicate-coverage-node-response"
                }
                MetadataQueryError::InconsistentBucketMetadataResponse => {
                    "inconsistent-bucket-metadata-response"
                }
            },
        }
    }
}

pub fn assess_cluster_bucket_metadata_consistency<T: Clone + Eq>(
    states: &[ClusterBucketMetadataResponderState<T>],
) -> ClusterBucketMetadataConsistencyAssessment<T> {
    let missing_bucket_responders = states
        .iter()
        .filter(|state| matches!(state, ClusterBucketMetadataResponderState::MissingBucket))
        .count();
    if missing_bucket_responders > 0 {
        return ClusterBucketMetadataConsistencyAssessment {
            consistent: false,
            gap: Some(ClusterBucketMetadataConsistencyGap::MissingBucketOnResponder),
            missing_bucket_responders,
            value: None,
        };
    }

    let mut present_values = states.iter().filter_map(|state| match state {
        ClusterBucketMetadataResponderState::Present(value) => Some(value),
        ClusterBucketMetadataResponderState::MissingBucket => None,
    });
    let Some(first) = present_values.next() else {
        return ClusterBucketMetadataConsistencyAssessment {
            consistent: false,
            gap: Some(ClusterBucketMetadataConsistencyGap::NoResponderValues),
            missing_bucket_responders: 0,
            value: None,
        };
    };

    if present_values.any(|value| value != first) {
        return ClusterBucketMetadataConsistencyAssessment {
            consistent: false,
            gap: Some(ClusterBucketMetadataConsistencyGap::InconsistentResponderValues),
            missing_bucket_responders: 0,
            value: None,
        };
    }

    ClusterBucketMetadataConsistencyAssessment {
        consistent: true,
        gap: None,
        missing_bucket_responders: 0,
        value: Some(first.clone()),
    }
}

pub fn resolve_cluster_bucket_presence_for_read(
    states: &[ClusterBucketMetadataResponderState<bool>],
) -> ClusterBucketPresenceReadResolution {
    match resolve_cluster_bucket_metadata_for_read(states) {
        ClusterBucketMetadataReadResolution::Present(true) => {
            ClusterBucketPresenceReadResolution::Present
        }
        ClusterBucketMetadataReadResolution::Missing => {
            ClusterBucketPresenceReadResolution::Missing
        }
        ClusterBucketMetadataReadResolution::Present(false)
        | ClusterBucketMetadataReadResolution::Inconsistent => {
            ClusterBucketPresenceReadResolution::Inconsistent
        }
    }
}

pub fn resolve_cluster_bucket_metadata_for_read<T: Clone + Eq>(
    states: &[ClusterBucketMetadataResponderState<T>],
) -> ClusterBucketMetadataReadResolution<T> {
    let assessment = assess_cluster_bucket_metadata_consistency(states);
    match (&assessment.gap, assessment.value) {
        (None, Some(value)) => ClusterBucketMetadataReadResolution::Present(value),
        (Some(ClusterBucketMetadataConsistencyGap::MissingBucketOnResponder), None)
            if assessment.missing_bucket_responders == states.len() =>
        {
            ClusterBucketMetadataReadResolution::Missing
        }
        _ => ClusterBucketMetadataReadResolution::Inconsistent,
    }
}

pub fn assess_cluster_bucket_presence_convergence(
    states: &[ClusterBucketMetadataResponderState<bool>],
    expectation: ClusterBucketPresenceConvergenceExpectation,
) -> ClusterBucketPresenceConvergenceAssessment {
    let consistency = assess_cluster_bucket_metadata_consistency(states);
    let converged = match expectation {
        ClusterBucketPresenceConvergenceExpectation::Present => {
            consistency.gap.is_none() && consistency.value == Some(true)
        }
        ClusterBucketPresenceConvergenceExpectation::Missing => {
            consistency.gap == Some(ClusterBucketMetadataConsistencyGap::MissingBucketOnResponder)
                && consistency.missing_bucket_responders == states.len()
                && consistency.value.is_none()
        }
    };

    let gap = if converged {
        None
    } else {
        match consistency.gap {
            Some(ClusterBucketMetadataConsistencyGap::MissingBucketOnResponder) => {
                Some(ClusterBucketPresenceConvergenceGap::MissingBucketOnResponder)
            }
            Some(ClusterBucketMetadataConsistencyGap::InconsistentResponderValues) => {
                Some(ClusterBucketPresenceConvergenceGap::InconsistentResponderValues)
            }
            Some(ClusterBucketMetadataConsistencyGap::NoResponderValues) => {
                Some(ClusterBucketPresenceConvergenceGap::NoResponderValues)
            }
            None => Some(ClusterBucketPresenceConvergenceGap::UnexpectedResponderPresenceState),
        }
    };

    ClusterBucketPresenceConvergenceAssessment {
        expectation,
        converged,
        consistency,
        gap,
    }
}

pub fn assess_cluster_bucket_metadata_convergence<T: Clone + Eq>(
    strategy: ClusterMetadataListingStrategy,
    view_id: Option<&str>,
    local_node_id: &str,
    membership_nodes: &[String],
    responder_states: &[ClusterBucketMetadataResponderSnapshot<T>],
) -> Result<ClusterBucketMetadataConvergenceAssessment<T>, MetadataQueryError> {
    let responded_nodes = responder_states
        .iter()
        .map(|responder| responder.node_id.clone())
        .collect::<Vec<_>>();
    let snapshot = assess_cluster_metadata_snapshot_for_topology_responders(
        strategy,
        view_id,
        local_node_id,
        membership_nodes,
        responded_nodes.as_slice(),
    )?;
    let consistency_states = responder_states
        .iter()
        .map(|responder| responder.state.clone())
        .collect::<Vec<_>>();
    let consistency = assess_cluster_bucket_metadata_consistency(consistency_states.as_slice());

    let gap = match snapshot.readiness_assessment.gap {
        Some(ClusterMetadataReadinessGap::StrategyNotClusterAuthoritative) => {
            Some(ClusterBucketMetadataConvergenceGap::StrategyNotClusterAuthoritative)
        }
        Some(ClusterMetadataReadinessGap::MissingExpectedNodes) => {
            Some(ClusterBucketMetadataConvergenceGap::MissingExpectedNodes)
        }
        Some(ClusterMetadataReadinessGap::UnexpectedResponderNodes) => {
            Some(ClusterBucketMetadataConvergenceGap::UnexpectedResponderNodes)
        }
        Some(ClusterMetadataReadinessGap::MissingAndUnexpectedNodes) => {
            Some(ClusterBucketMetadataConvergenceGap::MissingAndUnexpectedNodes)
        }
        None => match consistency.gap {
            Some(ClusterBucketMetadataConsistencyGap::MissingBucketOnResponder) => {
                Some(ClusterBucketMetadataConvergenceGap::MissingBucketOnResponder)
            }
            Some(ClusterBucketMetadataConsistencyGap::InconsistentResponderValues) => {
                Some(ClusterBucketMetadataConvergenceGap::InconsistentResponderValues)
            }
            Some(ClusterBucketMetadataConsistencyGap::NoResponderValues) => {
                Some(ClusterBucketMetadataConvergenceGap::NoResponderValues)
            }
            None => None,
        },
    };

    Ok(ClusterBucketMetadataConvergenceAssessment {
        ready: gap.is_none(),
        snapshot,
        consistency,
        gap,
    })
}

pub fn assess_cluster_bucket_metadata_convergence_for_responder_states<T: Clone + Eq>(
    strategy: ClusterMetadataListingStrategy,
    view_id: Option<&str>,
    local_node_id: &str,
    membership_nodes: &[String],
    responded_nodes: &[String],
    states: &[ClusterBucketMetadataResponderState<T>],
) -> Result<ClusterBucketMetadataConvergenceAssessment<T>, ClusterBucketMetadataConvergenceInputError>
{
    if responded_nodes.len() != states.len() {
        return Err(ClusterBucketMetadataConvergenceInputError::ResponderStateCardinalityMismatch);
    }

    let responder_states = responded_nodes
        .iter()
        .cloned()
        .zip(states.iter().cloned())
        .map(|(node_id, state)| ClusterBucketMetadataResponderSnapshot { node_id, state })
        .collect::<Vec<_>>();
    assess_cluster_bucket_metadata_convergence(
        strategy,
        view_id,
        local_node_id,
        membership_nodes,
        responder_states.as_slice(),
    )
    .map_err(ClusterBucketMetadataConvergenceInputError::InvalidResponderTopology)
}

pub fn assess_cluster_bucket_metadata_mutation_preconditions<T: Clone + Eq>(
    strategy: ClusterMetadataListingStrategy,
    view_id: Option<&str>,
    local_node_id: &str,
    membership_nodes: &[String],
    responder_states: &[ClusterBucketMetadataResponderSnapshot<T>],
) -> Result<ClusterBucketMetadataMutationPreconditionAssessment<T>, MetadataQueryError> {
    let convergence = assess_cluster_bucket_metadata_convergence(
        strategy,
        view_id,
        local_node_id,
        membership_nodes,
        responder_states,
    )?;
    let all_missing = convergence.gap == Some(ClusterBucketMetadataConvergenceGap::MissingBucketOnResponder)
        && !responder_states.is_empty()
        && convergence.consistency.missing_bucket_responders == responder_states.len();

    let gap = match convergence.gap {
        Some(ClusterBucketMetadataConvergenceGap::StrategyNotClusterAuthoritative) => {
            Some(ClusterBucketMetadataMutationPreconditionGap::StrategyNotClusterAuthoritative)
        }
        Some(ClusterBucketMetadataConvergenceGap::MissingExpectedNodes) => {
            Some(ClusterBucketMetadataMutationPreconditionGap::MissingExpectedNodes)
        }
        Some(ClusterBucketMetadataConvergenceGap::UnexpectedResponderNodes) => {
            Some(ClusterBucketMetadataMutationPreconditionGap::UnexpectedResponderNodes)
        }
        Some(ClusterBucketMetadataConvergenceGap::MissingAndUnexpectedNodes) => {
            Some(ClusterBucketMetadataMutationPreconditionGap::MissingAndUnexpectedNodes)
        }
        Some(ClusterBucketMetadataConvergenceGap::MissingBucketOnResponder) if all_missing => {
            Some(ClusterBucketMetadataMutationPreconditionGap::BucketMissing)
        }
        Some(ClusterBucketMetadataConvergenceGap::MissingBucketOnResponder) => {
            Some(ClusterBucketMetadataMutationPreconditionGap::MissingBucketOnResponder)
        }
        Some(ClusterBucketMetadataConvergenceGap::InconsistentResponderValues) => {
            Some(ClusterBucketMetadataMutationPreconditionGap::InconsistentResponderValues)
        }
        Some(ClusterBucketMetadataConvergenceGap::NoResponderValues) => {
            Some(ClusterBucketMetadataMutationPreconditionGap::NoResponderValues)
        }
        None => None,
    };

    let ready = gap.is_none();
    let current_value = if ready {
        convergence.consistency.value.clone()
    } else {
        None
    };
    Ok(ClusterBucketMetadataMutationPreconditionAssessment {
        ready,
        current_value,
        convergence,
        gap,
    })
}

pub fn build_cluster_metadata_snapshot_id(
    strategy: ClusterMetadataListingStrategy,
    view_id: Option<&str>,
    coverage: &ClusterMetadataCoverage,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"v1");
    hasher.update([0]);
    hasher.update(strategy.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(view_id.map(str::trim).unwrap_or("").as_bytes());
    hasher.update([0]);
    hasher.update(if coverage.complete { b"1" } else { b"0" });
    hasher.update([0]);
    update_snapshot_nodes(&mut hasher, b"expected", &coverage.expected_nodes);
    update_snapshot_nodes(&mut hasher, b"responded", &coverage.responded_nodes);
    update_snapshot_nodes(&mut hasher, b"missing", &coverage.missing_nodes);
    update_snapshot_nodes(&mut hasher, b"unexpected", &coverage.unexpected_nodes);

    format!("{:x}", hasher.finalize())
}

pub fn build_cluster_metadata_expected_nodes(
    strategy: ClusterMetadataListingStrategy,
    local_node_id: &str,
    membership_nodes: &[String],
) -> Vec<String> {
    match strategy {
        ClusterMetadataListingStrategy::LocalNodeOnly => {
            normalize_node_ids(std::iter::once(local_node_id))
        }
        ClusterMetadataListingStrategy::ConsensusIndex
        | ClusterMetadataListingStrategy::RequestTimeAggregation
        | ClusterMetadataListingStrategy::FullReplication => normalize_node_ids(
            std::iter::once(local_node_id).chain(membership_nodes.iter().map(String::as_str)),
        ),
    }
}

/// Resolve the effective execution strategy for distributed metadata fan-in paths.
///
/// `consensus-index` remains the source-of-truth listing strategy while fan-in transport
/// hydration executes under request-time aggregation coverage semantics.
pub const fn cluster_metadata_fan_in_execution_strategy(
    strategy: ClusterMetadataListingStrategy,
) -> ClusterMetadataListingStrategy {
    match strategy {
        ClusterMetadataListingStrategy::ConsensusIndex => {
            ClusterMetadataListingStrategy::RequestTimeAggregation
        }
        other => other,
    }
}

/// Determine whether a source strategy requires shared-token transport auth for fan-in.
///
/// `consensus-index` keeps persisted metadata as canonical source-of-truth and uses
/// authenticated peer fan-in for payload hydration.
pub const fn cluster_metadata_fan_in_requires_auth_token(
    source_strategy: ClusterMetadataListingStrategy,
) -> bool {
    matches!(source_strategy, ClusterMetadataListingStrategy::ConsensusIndex)
}

/// Return canonical transport reject reason for metadata fan-in auth-token readiness.
///
/// Callers provide token availability and can map the reject reason to domain-specific
/// error payloads while keeping the reason label single-sourced.
pub const fn cluster_metadata_fan_in_auth_token_reject_reason(
    source_strategy: ClusterMetadataListingStrategy,
    has_cluster_auth_token: bool,
) -> Option<&'static str> {
    if cluster_metadata_fan_in_requires_auth_token(source_strategy) && !has_cluster_auth_token {
        return Some(CLUSTER_METADATA_CONSENSUS_FAN_IN_AUTH_TOKEN_MISSING_REASON);
    }
    None
}

/// Build a canonical fan-in snapshot assessment from topology inputs.
///
/// Uses `cluster_metadata_fan_in_execution_strategy(...)` to keep fan-in readiness semantics
/// single-sourced across runtime, S3, and console executors.
pub fn assess_cluster_metadata_fan_in_snapshot_for_topology_responders(
    source_strategy: ClusterMetadataListingStrategy,
    view_id: Option<&str>,
    local_node_id: &str,
    membership_nodes: &[String],
    responder_node_ids: &[String],
) -> Result<ClusterMetadataSnapshotAssessment, MetadataQueryError> {
    assess_cluster_metadata_snapshot_for_topology_responders(
        cluster_metadata_fan_in_execution_strategy(source_strategy),
        view_id,
        local_node_id,
        membership_nodes,
        responder_node_ids,
    )
}

/// Build a canonical fan-in preflight assessment from topology + responder-view inputs.
///
/// This composes fan-in snapshot readiness with responder membership-view consistency so
/// runtime/S3/console domains can consume one typed preflight gate.
pub fn assess_cluster_metadata_fan_in_preflight_for_topology_responders(
    source_strategy: ClusterMetadataListingStrategy,
    view_id: Option<&str>,
    local_node_id: &str,
    membership_nodes: &[String],
    responders: &[ClusterResponderMembershipView],
) -> Result<ClusterMetadataFanInPreflightAssessment, MetadataQueryError> {
    let mut responder_node_ids = responders
        .iter()
        .map(|responder| responder.node_id.clone())
        .collect::<Vec<_>>();
    let local_present = responder_node_ids
        .iter()
        .any(|node_id| node_id.trim().eq_ignore_ascii_case(local_node_id.trim()));
    if !local_present {
        responder_node_ids.push(local_node_id.trim().to_string());
    }
    let snapshot = assess_cluster_metadata_fan_in_snapshot_for_topology_responders(
        source_strategy,
        view_id,
        local_node_id,
        membership_nodes,
        responder_node_ids.as_slice(),
    )?;
    Ok(build_cluster_metadata_fan_in_preflight_assessment(
        snapshot, responders,
    ))
}

/// Build a canonical single-responder fan-in snapshot assessment from topology inputs.
///
/// Uses `cluster_metadata_fan_in_execution_strategy(...)` to keep fan-in fallback semantics
/// single-sourced across runtime, S3, and console executors.
pub fn assess_cluster_metadata_fan_in_snapshot_for_topology_single_responder(
    source_strategy: ClusterMetadataListingStrategy,
    view_id: Option<&str>,
    local_node_id: &str,
    membership_nodes: &[String],
    responder_node_id: &str,
) -> ClusterMetadataSnapshotAssessment {
    assess_cluster_metadata_snapshot_for_topology_single_responder(
        cluster_metadata_fan_in_execution_strategy(source_strategy),
        view_id,
        local_node_id,
        membership_nodes,
        responder_node_id,
    )
}

/// Build a canonical single-responder fan-in preflight assessment from topology + responder-view
/// inputs.
///
/// This composes single-responder fan-in snapshot readiness with responder membership-view
/// consistency so callers can consume one typed preflight gate without responder-slice plumbing.
pub fn assess_cluster_metadata_fan_in_preflight_for_topology_single_responder(
    source_strategy: ClusterMetadataListingStrategy,
    view_id: Option<&str>,
    local_node_id: &str,
    membership_nodes: &[String],
    responder_node_id: &str,
    responder_membership_view_id: Option<&str>,
) -> ClusterMetadataFanInPreflightAssessment {
    let snapshot = assess_cluster_metadata_fan_in_snapshot_for_topology_single_responder(
        source_strategy,
        view_id,
        local_node_id,
        membership_nodes,
        responder_node_id,
    );
    let responder = ClusterResponderMembershipView {
        node_id: responder_node_id.trim().to_string(),
        membership_view_id: responder_membership_view_id.map(ToOwned::to_owned),
    };
    build_cluster_metadata_fan_in_preflight_assessment(snapshot, std::slice::from_ref(&responder))
}

/// Build a canonical single-responder metadata snapshot assessment from topology inputs.
///
/// Expected-node projection is strategy-driven with a deterministic membership fallback when the
/// strategy-specific projection is empty.
pub fn assess_cluster_metadata_snapshot_for_topology_single_responder(
    strategy: ClusterMetadataListingStrategy,
    view_id: Option<&str>,
    local_node_id: &str,
    membership_nodes: &[String],
    responder_node_id: &str,
) -> ClusterMetadataSnapshotAssessment {
    let mut expected_nodes =
        build_cluster_metadata_expected_nodes(strategy, local_node_id, membership_nodes);
    if expected_nodes.is_empty() {
        expected_nodes = normalize_node_ids(membership_nodes.iter().map(String::as_str));
    }

    assess_cluster_metadata_snapshot_for_single_responder(
        strategy,
        view_id,
        expected_nodes.as_slice(),
        responder_node_id,
    )
}

/// Build a canonical multi-responder metadata snapshot assessment from topology inputs.
///
/// Expected-node projection is strategy-driven with a deterministic membership fallback when the
/// strategy-specific projection is empty. Responder-node validation stays strict and fail-closed.
pub fn assess_cluster_metadata_snapshot_for_topology_responders(
    strategy: ClusterMetadataListingStrategy,
    view_id: Option<&str>,
    local_node_id: &str,
    membership_nodes: &[String],
    responder_node_ids: &[String],
) -> Result<ClusterMetadataSnapshotAssessment, MetadataQueryError> {
    let mut expected_nodes =
        build_cluster_metadata_expected_nodes(strategy, local_node_id, membership_nodes);
    if expected_nodes.is_empty() {
        expected_nodes = normalize_node_ids(membership_nodes.iter().map(String::as_str));
    }

    assess_cluster_metadata_snapshot(
        strategy,
        view_id,
        expected_nodes.as_slice(),
        responder_node_ids,
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ContinuationTokenPayload {
    version: u8,
    bucket: String,
    prefix: Option<String>,
    view_id: Option<String>,
    snapshot_id: Option<String>,
    key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VersionsContinuationTokenPayload {
    version: u8,
    bucket: String,
    prefix: Option<String>,
    view_id: Option<String>,
    snapshot_id: Option<String>,
    key_marker: String,
    version_id_marker: String,
}

pub trait MetadataIndex {
    fn upsert_bucket(&mut self, state: BucketMetadataState);
    fn get_bucket(&self, bucket: &str) -> Option<&BucketMetadataState>;
    fn upsert_object(&mut self, state: ObjectMetadataState);
    fn upsert_object_version(&mut self, state: ObjectVersionMetadataState);
    fn list_objects_page(
        &self,
        query: &MetadataQuery,
    ) -> Result<MetadataListPage, MetadataQueryError>;
    fn list_object_versions_page(
        &self,
        query: &MetadataVersionsQuery,
    ) -> Result<MetadataVersionsPage, MetadataQueryError>;
    fn list_objects(
        &self,
        query: &MetadataQuery,
    ) -> Result<Vec<ObjectMetadataState>, MetadataQueryError> {
        self.list_objects_page(query).map(|page| page.objects)
    }
    fn list_object_versions(
        &self,
        query: &MetadataVersionsQuery,
    ) -> Result<Vec<ObjectVersionMetadataState>, MetadataQueryError> {
        self.list_object_versions_page(query)
            .map(|page| page.versions)
    }
}

pub fn merge_cluster_list_objects_page(
    query: &MetadataQuery,
    node_objects: &[Vec<ObjectMetadataState>],
) -> Result<MetadataListPage, MetadataQueryError> {
    let mut merged: BTreeMap<(String, String), ObjectMetadataState> = BTreeMap::new();

    for objects in node_objects {
        for candidate in objects {
            let entry_key = (candidate.bucket.clone(), candidate.key.clone());
            match merged.get(&entry_key) {
                Some(current) if !object_state_preferred(candidate, current) => {}
                _ => {
                    merged.insert(entry_key, candidate.clone());
                }
            }
        }
    }

    let objects = merged
        .into_values()
        .filter(|object| !object.is_delete_marker)
        .collect();
    paginate_objects_for_query(query, objects)
}

pub fn merge_cluster_list_object_versions_page(
    query: &MetadataVersionsQuery,
    node_versions: &[Vec<ObjectVersionMetadataState>],
) -> Result<MetadataVersionsPage, MetadataQueryError> {
    let mut merged: BTreeMap<(String, String, String), ObjectVersionMetadataState> =
        BTreeMap::new();

    for versions in node_versions {
        for candidate in versions {
            let entry_key = (
                candidate.bucket.clone(),
                candidate.key.clone(),
                candidate.version_id.clone(),
            );
            match merged.get(&entry_key) {
                Some(current) if !version_state_preferred(candidate, current) => {}
                _ => {
                    merged.insert(entry_key, candidate.clone());
                }
            }
        }
    }

    let versions = merged.into_values().collect();
    paginate_versions_for_query(query, versions)
}

pub fn merge_cluster_list_buckets(
    node_buckets: &[Vec<BucketMetadataState>],
) -> Result<Vec<BucketMetadataState>, MetadataQueryError> {
    let mut merged: BTreeMap<String, BucketMetadataState> = BTreeMap::new();
    for buckets in node_buckets {
        for candidate in buckets {
            match merged.get(candidate.bucket.as_str()) {
                Some(existing) if existing != candidate => {
                    return Err(MetadataQueryError::InconsistentBucketMetadataResponse);
                }
                Some(_) => {}
                None => {
                    merged.insert(candidate.bucket.clone(), candidate.clone());
                }
            }
        }
    }
    Ok(merged.into_values().collect())
}

pub fn merge_cluster_list_objects_page_with_coverage(
    query: &MetadataQuery,
    expected_nodes: &[String],
    node_pages: &[MetadataNodeObjectsPage],
) -> Result<ClusterMergedObjectsPage, MetadataQueryError> {
    let responded_nodes = validate_coverage_node_ids(
        node_pages
            .iter()
            .map(|node_page| node_page.node_id.as_str())
            .collect::<Vec<_>>()
            .as_slice(),
        MetadataQueryError::DuplicateCoverageNodeResponse,
    )?;
    let page = merge_cluster_list_objects_page(
        query,
        node_pages
            .iter()
            .map(|node_page| node_page.objects.clone())
            .collect::<Vec<_>>()
            .as_slice(),
    )?;
    let coverage =
        build_cluster_metadata_coverage_from_responses(expected_nodes, responded_nodes.as_slice())?;
    Ok(ClusterMergedObjectsPage { page, coverage })
}

pub fn merge_cluster_list_buckets_page_with_coverage(
    expected_nodes: &[String],
    node_pages: &[MetadataNodeBucketsPage],
) -> Result<ClusterMergedBucketsPage, MetadataQueryError> {
    let responded_nodes = validate_coverage_node_ids(
        node_pages
            .iter()
            .map(|node_page| node_page.node_id.as_str())
            .collect::<Vec<_>>()
            .as_slice(),
        MetadataQueryError::DuplicateCoverageNodeResponse,
    )?;
    let buckets = merge_cluster_list_buckets(
        node_pages
            .iter()
            .map(|node_page| node_page.buckets.clone())
            .collect::<Vec<_>>()
            .as_slice(),
    )?;
    let coverage =
        build_cluster_metadata_coverage_from_responses(expected_nodes, responded_nodes.as_slice())?;
    Ok(ClusterMergedBucketsPage { buckets, coverage })
}

pub fn merge_cluster_list_objects_page_with_topology_snapshot(
    query: &MetadataQuery,
    strategy: ClusterMetadataListingStrategy,
    local_node_id: &str,
    membership_nodes: &[String],
    node_pages: &[MetadataNodeObjectsPage],
) -> Result<ClusterTopologyMergedObjectsPage, MetadataQueryError> {
    let responder_node_ids = node_pages
        .iter()
        .map(|node_page| node_page.node_id.clone())
        .collect::<Vec<_>>();
    let snapshot = assess_cluster_metadata_snapshot_for_topology_responders(
        strategy,
        query.view_id.as_deref(),
        local_node_id,
        membership_nodes,
        responder_node_ids.as_slice(),
    )?;

    let mut snapshot_bound_query = query.clone();
    snapshot_bound_query.view_id = snapshot.view_id.clone();
    snapshot_bound_query.snapshot_id = Some(snapshot.snapshot_id.clone());

    let page = merge_cluster_list_objects_page(
        &snapshot_bound_query,
        node_pages
            .iter()
            .map(|node_page| node_page.objects.clone())
            .collect::<Vec<_>>()
            .as_slice(),
    )?;
    Ok(ClusterTopologyMergedObjectsPage { page, snapshot })
}

pub fn merge_cluster_list_objects_page_with_topology_snapshot_and_marker(
    query: &MetadataQuery,
    key_marker: Option<&str>,
    strategy: ClusterMetadataListingStrategy,
    local_node_id: &str,
    membership_nodes: &[String],
    node_pages: &[MetadataNodeObjectsPage],
) -> Result<ClusterTopologyMergedObjectsPage, MetadataQueryError> {
    let responder_node_ids = node_pages
        .iter()
        .map(|node_page| node_page.node_id.clone())
        .collect::<Vec<_>>();
    let snapshot = assess_cluster_metadata_snapshot_for_topology_responders(
        strategy,
        query.view_id.as_deref(),
        local_node_id,
        membership_nodes,
        responder_node_ids.as_slice(),
    )?;

    let mut snapshot_bound_query = query.clone();
    snapshot_bound_query.view_id = snapshot.view_id.clone();
    snapshot_bound_query.snapshot_id = Some(snapshot.snapshot_id.clone());

    let key_marker = key_marker.map(str::trim).filter(|value| !value.is_empty());
    if key_marker.is_some() && snapshot_bound_query.continuation_token.is_some() {
        return Err(MetadataQueryError::InvalidContinuationToken);
    }
    if let Some(key_marker) = key_marker {
        snapshot_bound_query.continuation_token = encode_continuation_token(
            snapshot_bound_query.bucket.as_str(),
            snapshot_bound_query.prefix.as_deref(),
            snapshot_bound_query.view_id.as_deref(),
            snapshot_bound_query.snapshot_id.as_deref(),
            key_marker,
        );
    }

    let page = merge_cluster_list_objects_page(
        &snapshot_bound_query,
        node_pages
            .iter()
            .map(|node_page| node_page.objects.clone())
            .collect::<Vec<_>>()
            .as_slice(),
    )?;
    Ok(ClusterTopologyMergedObjectsPage { page, snapshot })
}

pub fn build_cluster_metadata_coverage_from_responses(
    expected_nodes: &[String],
    responded_node_ids: &[String],
) -> Result<ClusterMetadataCoverage, MetadataQueryError> {
    let expected_nodes = validate_coverage_node_ids(
        expected_nodes
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice(),
        MetadataQueryError::DuplicateCoverageExpectedNode,
    )?;
    let responded_nodes = validate_coverage_node_ids(
        responded_node_ids
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice(),
        MetadataQueryError::DuplicateCoverageNodeResponse,
    )?;
    Ok(build_cluster_metadata_coverage(
        expected_nodes.as_slice(),
        responded_nodes.as_slice(),
    ))
}

pub fn build_cluster_metadata_coverage_for_single_responder(
    expected_nodes: &[String],
    responder_node_id: &str,
) -> ClusterMetadataCoverage {
    let responded = vec![responder_node_id.to_string()];
    match build_cluster_metadata_coverage_from_responses(expected_nodes, responded.as_slice()) {
        Ok(coverage) => coverage,
        // Keep fallback deterministic for callers that only have one local responder:
        // invalid responder IDs become "no responders" instead of bubbling validation errors.
        Err(_) => build_cluster_metadata_coverage(expected_nodes, &[]),
    }
}

pub fn assess_cluster_metadata_coverage(
    coverage: &ClusterMetadataCoverage,
) -> ClusterMetadataCoverageAssessment {
    let missing_nodes = coverage.missing_nodes.len();
    let unexpected_nodes = coverage.unexpected_nodes.len();
    let gap = match (missing_nodes == 0, unexpected_nodes == 0) {
        (true, true) => None,
        (false, true) => Some(ClusterMetadataCoverageGap::MissingExpectedNodes),
        (true, false) => Some(ClusterMetadataCoverageGap::UnexpectedResponderNodes),
        (false, false) => Some(ClusterMetadataCoverageGap::MissingAndUnexpectedNodes),
    };

    ClusterMetadataCoverageAssessment {
        complete: gap.is_none(),
        gap,
        expected_nodes: coverage.expected_nodes.len(),
        responded_nodes: coverage.responded_nodes.len(),
        missing_nodes,
        unexpected_nodes,
    }
}

pub fn assess_cluster_metadata_readiness(
    strategy: ClusterMetadataListingStrategy,
    coverage: &ClusterMetadataCoverage,
) -> ClusterMetadataReadinessAssessment {
    let coverage_assessment = assess_cluster_metadata_coverage(coverage);
    build_cluster_metadata_readiness_assessment(strategy, &coverage_assessment)
}

pub fn assess_cluster_metadata_snapshot(
    strategy: ClusterMetadataListingStrategy,
    view_id: Option<&str>,
    expected_nodes: &[String],
    responded_nodes: &[String],
) -> Result<ClusterMetadataSnapshotAssessment, MetadataQueryError> {
    let coverage = build_cluster_metadata_coverage_from_responses(expected_nodes, responded_nodes)?;
    Ok(build_cluster_metadata_snapshot_assessment(
        strategy, view_id, coverage,
    ))
}

pub fn assess_cluster_metadata_snapshot_for_single_responder(
    strategy: ClusterMetadataListingStrategy,
    view_id: Option<&str>,
    expected_nodes: &[String],
    responder_node_id: &str,
) -> ClusterMetadataSnapshotAssessment {
    let coverage =
        build_cluster_metadata_coverage_for_single_responder(expected_nodes, responder_node_id);
    build_cluster_metadata_snapshot_assessment(strategy, view_id, coverage)
}

fn build_cluster_metadata_snapshot_assessment(
    strategy: ClusterMetadataListingStrategy,
    view_id: Option<&str>,
    coverage: ClusterMetadataCoverage,
) -> ClusterMetadataSnapshotAssessment {
    let coverage_assessment = assess_cluster_metadata_coverage(&coverage);
    let readiness_assessment =
        build_cluster_metadata_readiness_assessment(strategy, &coverage_assessment);
    let snapshot_id = build_cluster_metadata_snapshot_id(strategy, view_id, &coverage);
    ClusterMetadataSnapshotAssessment {
        strategy,
        view_id: view_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        coverage,
        coverage_assessment,
        readiness_assessment,
        snapshot_id,
    }
}

fn build_cluster_metadata_readiness_assessment(
    strategy: ClusterMetadataListingStrategy,
    coverage_assessment: &ClusterMetadataCoverageAssessment,
) -> ClusterMetadataReadinessAssessment {
    let coverage_gap = coverage_assessment.gap;

    let gap = match strategy {
        ClusterMetadataListingStrategy::LocalNodeOnly => {
            Some(ClusterMetadataReadinessGap::StrategyNotClusterAuthoritative)
        }
        ClusterMetadataListingStrategy::ConsensusIndex
        | ClusterMetadataListingStrategy::RequestTimeAggregation
        | ClusterMetadataListingStrategy::FullReplication => {
            coverage_gap.map(|coverage_gap| match coverage_gap {
                ClusterMetadataCoverageGap::MissingExpectedNodes => {
                    ClusterMetadataReadinessGap::MissingExpectedNodes
                }
                ClusterMetadataCoverageGap::UnexpectedResponderNodes => {
                    ClusterMetadataReadinessGap::UnexpectedResponderNodes
                }
                ClusterMetadataCoverageGap::MissingAndUnexpectedNodes => {
                    ClusterMetadataReadinessGap::MissingAndUnexpectedNodes
                }
            })
        }
    };

    ClusterMetadataReadinessAssessment {
        strategy,
        cluster_authoritative: strategy.is_cluster_authoritative(),
        ready: gap.is_none(),
        coverage_complete: coverage_assessment.complete,
        coverage_gap,
        gap,
    }
}

pub fn merge_cluster_list_object_versions_page_with_coverage(
    query: &MetadataVersionsQuery,
    expected_nodes: &[String],
    node_pages: &[MetadataNodeVersionsPage],
) -> Result<ClusterMergedVersionsPage, MetadataQueryError> {
    let responded_nodes = validate_coverage_node_ids(
        node_pages
            .iter()
            .map(|node_page| node_page.node_id.as_str())
            .collect::<Vec<_>>()
            .as_slice(),
        MetadataQueryError::DuplicateCoverageNodeResponse,
    )?;
    let page = merge_cluster_list_object_versions_page(
        query,
        node_pages
            .iter()
            .map(|node_page| node_page.versions.clone())
            .collect::<Vec<_>>()
            .as_slice(),
    )?;
    let coverage =
        build_cluster_metadata_coverage_from_responses(expected_nodes, responded_nodes.as_slice())?;
    Ok(ClusterMergedVersionsPage { page, coverage })
}

pub fn merge_cluster_list_object_versions_page_with_topology_snapshot(
    query: &MetadataVersionsQuery,
    strategy: ClusterMetadataListingStrategy,
    local_node_id: &str,
    membership_nodes: &[String],
    node_pages: &[MetadataNodeVersionsPage],
) -> Result<ClusterTopologyMergedVersionsPage, MetadataQueryError> {
    let responder_node_ids = node_pages
        .iter()
        .map(|node_page| node_page.node_id.clone())
        .collect::<Vec<_>>();
    let snapshot = assess_cluster_metadata_snapshot_for_topology_responders(
        strategy,
        query.view_id.as_deref(),
        local_node_id,
        membership_nodes,
        responder_node_ids.as_slice(),
    )?;

    let mut snapshot_bound_query = query.clone();
    snapshot_bound_query.view_id = snapshot.view_id.clone();
    snapshot_bound_query.snapshot_id = Some(snapshot.snapshot_id.clone());

    let page = merge_cluster_list_object_versions_page(
        &snapshot_bound_query,
        node_pages
            .iter()
            .map(|node_page| node_page.versions.clone())
            .collect::<Vec<_>>()
            .as_slice(),
    )?;
    Ok(ClusterTopologyMergedVersionsPage { page, snapshot })
}

pub fn merge_cluster_list_buckets_page_with_topology_snapshot(
    view_id: Option<&str>,
    strategy: ClusterMetadataListingStrategy,
    local_node_id: &str,
    membership_nodes: &[String],
    node_pages: &[MetadataNodeBucketsPage],
) -> Result<ClusterTopologyMergedBucketsPage, MetadataQueryError> {
    let responder_node_ids = node_pages
        .iter()
        .map(|node_page| node_page.node_id.clone())
        .collect::<Vec<_>>();
    let snapshot = assess_cluster_metadata_snapshot_for_topology_responders(
        strategy,
        view_id,
        local_node_id,
        membership_nodes,
        responder_node_ids.as_slice(),
    )?;
    let buckets = merge_cluster_list_buckets(
        node_pages
            .iter()
            .map(|node_page| node_page.buckets.clone())
            .collect::<Vec<_>>()
            .as_slice(),
    )?;
    Ok(ClusterTopologyMergedBucketsPage { buckets, snapshot })
}

#[derive(Debug, Default, Clone)]
pub struct InMemoryMetadataIndex {
    buckets: BTreeMap<String, BucketMetadataState>,
    objects: BTreeMap<(String, String), ObjectMetadataState>,
    object_versions: BTreeMap<(String, String, String), ObjectVersionMetadataState>,
}

impl MetadataIndex for InMemoryMetadataIndex {
    fn upsert_bucket(&mut self, state: BucketMetadataState) {
        self.buckets.insert(state.bucket.clone(), state);
    }

    fn get_bucket(&self, bucket: &str) -> Option<&BucketMetadataState> {
        self.buckets.get(bucket)
    }

    fn upsert_object(&mut self, state: ObjectMetadataState) {
        self.objects
            .insert((state.bucket.clone(), state.key.clone()), state);
    }

    fn upsert_object_version(&mut self, state: ObjectVersionMetadataState) {
        self.object_versions.insert(
            (
                state.bucket.clone(),
                state.key.clone(),
                state.version_id.clone(),
            ),
            state,
        );
    }

    fn list_objects_page(
        &self,
        query: &MetadataQuery,
    ) -> Result<MetadataListPage, MetadataQueryError> {
        let objects = self.objects.values().cloned().collect();
        paginate_objects_for_query(query, objects)
    }

    fn list_object_versions_page(
        &self,
        query: &MetadataVersionsQuery,
    ) -> Result<MetadataVersionsPage, MetadataQueryError> {
        let versions = self.object_versions.values().cloned().collect();
        paginate_versions_for_query(query, versions)
    }
}

fn paginate_objects_for_query(
    query: &MetadataQuery,
    mut objects: Vec<ObjectMetadataState>,
) -> Result<MetadataListPage, MetadataQueryError> {
    let prefix = query.prefix.as_deref();
    let continuation_key = decode_continuation_token(
        query.continuation_token.as_deref(),
        query.bucket.as_str(),
        prefix,
        query.view_id.as_deref(),
        query.snapshot_id.as_deref(),
    )?;
    let continuation_key = continuation_key.as_deref();

    objects.retain(|object| object.bucket == query.bucket);
    objects.retain(|object| {
        prefix
            .map(|value| object.key.starts_with(value))
            .unwrap_or(true)
    });
    objects.retain(|object| {
        continuation_key
            .map(|key| object.key.as_str() > key)
            .unwrap_or(true)
    });
    objects.sort_by(|left, right| left.key.cmp(&right.key));

    let max_keys = query.effective_max_keys();
    let is_truncated = objects.len() > max_keys;
    objects.truncate(max_keys);
    let next_continuation_token = if is_truncated {
        objects.last().and_then(|object| {
            encode_continuation_token(
                query.bucket.as_str(),
                prefix,
                query.view_id.as_deref(),
                query.snapshot_id.as_deref(),
                object.key.as_str(),
            )
        })
    } else {
        None
    };

    Ok(MetadataListPage {
        objects,
        is_truncated,
        next_continuation_token,
    })
}

fn object_state_preferred(candidate: &ObjectMetadataState, current: &ObjectMetadataState) -> bool {
    match (candidate.is_delete_marker, current.is_delete_marker) {
        (false, true) => true,
        (true, false) => false,
        _ => compare_version_rank(
            candidate.latest_version_id.as_deref(),
            current.latest_version_id.as_deref(),
        )
        .is_gt(),
    }
}

fn version_state_preferred(
    candidate: &ObjectVersionMetadataState,
    current: &ObjectVersionMetadataState,
) -> bool {
    match (candidate.is_latest, current.is_latest) {
        (true, false) => return true,
        (false, true) => return false,
        _ => {}
    }
    match (candidate.is_delete_marker, current.is_delete_marker) {
        (false, true) => true,
        (true, false) => false,
        _ => candidate.version_id > current.version_id,
    }
}

fn paginate_versions_for_query(
    query: &MetadataVersionsQuery,
    mut versions: Vec<ObjectVersionMetadataState>,
) -> Result<MetadataVersionsPage, MetadataQueryError> {
    let prefix = query.prefix.as_deref();
    let explicit_key_marker = query
        .key_marker
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let explicit_version_id_marker = query
        .version_id_marker
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let token_markers = decode_versions_continuation_token(
        query.continuation_token.as_deref(),
        query.bucket.as_str(),
        prefix,
        query.view_id.as_deref(),
        query.snapshot_id.as_deref(),
    )?;
    if token_markers.is_some()
        && (explicit_key_marker.is_some() || explicit_version_id_marker.is_some())
    {
        return Err(MetadataQueryError::InvalidVersionsMarker);
    }

    let (effective_key_marker, effective_version_id_marker) = match (
        token_markers,
        explicit_key_marker,
        explicit_version_id_marker,
    ) {
        (Some((key, version_id)), _, _) => (Some(key), Some(version_id)),
        (None, key_marker, version_id_marker) => (
            key_marker.map(ToOwned::to_owned),
            version_id_marker.map(ToOwned::to_owned),
        ),
    };
    if effective_version_id_marker.is_some() && effective_key_marker.is_none() {
        return Err(MetadataQueryError::InvalidVersionsMarker);
    }

    let key_marker = effective_key_marker.as_deref();
    let version_id_marker = effective_version_id_marker.as_deref();

    versions.retain(|version| version.bucket == query.bucket);
    versions.retain(|version| {
        prefix
            .map(|value| version.key.starts_with(value))
            .unwrap_or(true)
    });
    versions.retain(|version| version_is_after_marker(version, key_marker, version_id_marker));
    versions.sort_by(|left, right| {
        left.key
            .cmp(&right.key)
            .then_with(|| right.version_id.cmp(&left.version_id))
    });

    let max_keys = query.effective_max_keys();
    let is_truncated = versions.len() > max_keys;
    versions.truncate(max_keys);
    let (next_continuation_token, next_key_marker, next_version_id_marker) = if is_truncated {
        versions
            .last()
            .map(|entry| {
                (
                    encode_versions_continuation_token(
                        query.bucket.as_str(),
                        prefix,
                        query.view_id.as_deref(),
                        query.snapshot_id.as_deref(),
                        entry.key.as_str(),
                        entry.version_id.as_str(),
                    ),
                    Some(entry.key.clone()),
                    Some(entry.version_id.clone()),
                )
            })
            .unwrap_or((None, None, None))
    } else {
        (None, None, None)
    };

    Ok(MetadataVersionsPage {
        versions,
        is_truncated,
        next_continuation_token,
        next_key_marker,
        next_version_id_marker,
    })
}

fn version_is_after_marker(
    entry: &ObjectVersionMetadataState,
    key_marker: Option<&str>,
    version_id_marker: Option<&str>,
) -> bool {
    let Some(key_marker) = key_marker else {
        return true;
    };

    if entry.key.as_str() > key_marker {
        return true;
    }
    if entry.key.as_str() < key_marker {
        return false;
    }

    match version_id_marker {
        Some(version_marker) => entry.version_id.as_str() < version_marker,
        None => false,
    }
}

fn compare_version_rank(candidate: Option<&str>, current: Option<&str>) -> std::cmp::Ordering {
    match (candidate, current) {
        (Some(left), Some(right)) => left.cmp(right),
        (Some(_), None) => std::cmp::Ordering::Greater,
        (None, Some(_)) => std::cmp::Ordering::Less,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

fn build_cluster_metadata_coverage(
    expected_nodes: &[String],
    responded_nodes: &[String],
) -> ClusterMetadataCoverage {
    let expected = normalize_node_ids(expected_nodes.iter().map(String::as_str));
    let responded = normalize_node_ids(responded_nodes.iter().map(String::as_str));
    let expected_set = expected
        .iter()
        .map(|node| node_identity_key(node))
        .collect::<BTreeSet<_>>();
    let responded_set = responded
        .iter()
        .map(|node| node_identity_key(node))
        .collect::<BTreeSet<_>>();
    let missing_nodes = expected
        .iter()
        .filter(|node| !responded_set.contains(&node_identity_key(node)))
        .cloned()
        .collect::<Vec<_>>();
    let unexpected_nodes = responded
        .iter()
        .filter(|node| !expected_set.contains(&node_identity_key(node)))
        .cloned()
        .collect::<Vec<_>>();
    ClusterMetadataCoverage {
        expected_nodes: expected,
        responded_nodes: responded,
        complete: missing_nodes.is_empty() && unexpected_nodes.is_empty(),
        missing_nodes,
        unexpected_nodes,
    }
}

fn validate_coverage_node_ids(
    node_ids: &[&str],
    duplicate_error: MetadataQueryError,
) -> Result<Vec<String>, MetadataQueryError> {
    let mut seen = BTreeSet::<String>::new();
    let mut normalized = Vec::with_capacity(node_ids.len());

    for node_id in node_ids {
        let node_id = node_id.trim();
        if node_id.is_empty() {
            return Err(MetadataQueryError::InvalidCoverageNodeId);
        }

        let inserted = seen.insert(node_identity_key(node_id));
        if !inserted {
            return Err(duplicate_error);
        }
        normalized.push(node_id.to_string());
    }

    Ok(normalized)
}

fn node_identity_key(node: &str) -> String {
    node.trim().to_ascii_lowercase()
}

fn normalize_node_ids<'a>(nodes: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut normalized = BTreeMap::<String, String>::new();
    for node in nodes {
        let trimmed = node.trim();
        if trimmed.is_empty() {
            continue;
        }

        let key = node_identity_key(trimmed);
        match normalized.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(trimmed.to_string());
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if trimmed < entry.get().as_str() {
                    entry.insert(trimmed.to_string());
                }
            }
        }
    }

    normalized.into_values().collect()
}

fn update_snapshot_nodes(hasher: &mut Sha256, label: &[u8], nodes: &[String]) {
    hasher.update(label);
    hasher.update([0]);
    let mut normalized = BTreeSet::<String>::new();
    for node in nodes {
        let key = node_identity_key(node);
        if key.is_empty() {
            continue;
        }
        normalized.insert(key);
    }
    for node in normalized {
        hasher.update(node.as_bytes());
        hasher.update([0]);
    }
}

fn encode_continuation_token(
    bucket: &str,
    prefix: Option<&str>,
    view_id: Option<&str>,
    snapshot_id: Option<&str>,
    key: &str,
) -> Option<String> {
    let normalized = key.trim();
    if normalized.is_empty() {
        return None;
    }
    let payload = ContinuationTokenPayload {
        version: 1,
        bucket: bucket.trim().to_string(),
        prefix: prefix.map(ToOwned::to_owned),
        view_id: view_id.map(ToOwned::to_owned),
        snapshot_id: snapshot_id.map(ToOwned::to_owned),
        key: normalized.to_string(),
    };
    let payload = serde_json::to_vec(&payload).ok()?;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_slice());
    Some(format!("{METADATA_CONTINUATION_TOKEN_PREFIX}{encoded}"))
}

fn decode_continuation_token(
    token: Option<&str>,
    bucket: &str,
    prefix: Option<&str>,
    view_id: Option<&str>,
    snapshot_id: Option<&str>,
) -> Result<Option<String>, MetadataQueryError> {
    let Some(raw_token) = token.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let token_body = raw_token
        .strip_prefix(METADATA_CONTINUATION_TOKEN_PREFIX)
        .ok_or(MetadataQueryError::InvalidContinuationToken)?;

    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token_body.as_bytes())
        .map_err(|_| MetadataQueryError::InvalidContinuationToken)?;
    let payload = serde_json::from_slice::<ContinuationTokenPayload>(decoded.as_slice())
        .map_err(|_| MetadataQueryError::InvalidContinuationToken)?;
    if payload.version != 1 {
        return Err(MetadataQueryError::InvalidContinuationToken);
    }
    if payload.bucket != bucket.trim() {
        return Err(MetadataQueryError::InvalidContinuationToken);
    }
    if payload.prefix.as_deref() != prefix {
        return Err(MetadataQueryError::InvalidContinuationToken);
    }
    if payload.view_id.as_deref() != view_id {
        return Err(MetadataQueryError::InvalidContinuationToken);
    }
    if payload.snapshot_id.as_deref() != snapshot_id {
        return Err(MetadataQueryError::InvalidContinuationToken);
    }
    let key = payload.key.trim();
    if key.is_empty() {
        return Err(MetadataQueryError::InvalidContinuationToken);
    }
    Ok(Some(key.to_string()))
}

fn encode_versions_continuation_token(
    bucket: &str,
    prefix: Option<&str>,
    view_id: Option<&str>,
    snapshot_id: Option<&str>,
    key_marker: &str,
    version_id_marker: &str,
) -> Option<String> {
    let normalized_key = key_marker.trim();
    let normalized_version = version_id_marker.trim();
    if normalized_key.is_empty() || normalized_version.is_empty() {
        return None;
    }
    let payload = VersionsContinuationTokenPayload {
        version: 1,
        bucket: bucket.trim().to_string(),
        prefix: prefix.map(ToOwned::to_owned),
        view_id: view_id.map(ToOwned::to_owned),
        snapshot_id: snapshot_id.map(ToOwned::to_owned),
        key_marker: normalized_key.to_string(),
        version_id_marker: normalized_version.to_string(),
    };
    let payload = serde_json::to_vec(&payload).ok()?;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_slice());
    Some(format!(
        "{METADATA_VERSIONS_CONTINUATION_TOKEN_PREFIX}{encoded}"
    ))
}

fn decode_versions_continuation_token(
    token: Option<&str>,
    bucket: &str,
    prefix: Option<&str>,
    view_id: Option<&str>,
    snapshot_id: Option<&str>,
) -> Result<Option<(String, String)>, MetadataQueryError> {
    let Some(raw_token) = token.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let token_body = raw_token
        .strip_prefix(METADATA_VERSIONS_CONTINUATION_TOKEN_PREFIX)
        .ok_or(MetadataQueryError::InvalidVersionsMarker)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token_body.as_bytes())
        .map_err(|_| MetadataQueryError::InvalidVersionsMarker)?;
    let payload = serde_json::from_slice::<VersionsContinuationTokenPayload>(decoded.as_slice())
        .map_err(|_| MetadataQueryError::InvalidVersionsMarker)?;
    if payload.version != 1 {
        return Err(MetadataQueryError::InvalidVersionsMarker);
    }
    if payload.bucket != bucket.trim() {
        return Err(MetadataQueryError::InvalidVersionsMarker);
    }
    if payload.prefix.as_deref() != prefix {
        return Err(MetadataQueryError::InvalidVersionsMarker);
    }
    if payload.view_id.as_deref() != view_id {
        return Err(MetadataQueryError::InvalidVersionsMarker);
    }
    if payload.snapshot_id.as_deref() != snapshot_id {
        return Err(MetadataQueryError::InvalidVersionsMarker);
    }
    let key_marker = payload.key_marker.trim();
    let version_id_marker = payload.version_id_marker.trim();
    if key_marker.is_empty() || version_id_marker.is_empty() {
        return Err(MetadataQueryError::InvalidVersionsMarker);
    }
    Ok(Some((
        key_marker.to_string(),
        version_id_marker.to_string(),
    )))
}

#[cfg(test)]
mod tests {
    use super::{
        ClusterBucketMetadataConsistencyGap, ClusterBucketMetadataConvergenceGap,
        ClusterBucketMetadataConvergenceInputError, ClusterBucketMetadataReadResolution,
        ClusterBucketMetadataMutationPreconditionGap,
        ClusterBucketMetadataResponderSnapshot, ClusterBucketMetadataResponderState,
        ClusterBucketPresenceConvergenceExpectation, ClusterBucketPresenceConvergenceGap,
        ClusterBucketPresenceReadResolution, ClusterMetadataCoverageGap,
        ClusterMetadataFanInPreflightGap, ClusterMetadataListingStrategy,
        ClusterMetadataReadinessGap, ClusterResponderMembershipView,
        ClusterResponderMembershipViewGap, InMemoryMetadataIndex, MetadataIndex,
        MetadataNodeBucketsPage, MetadataNodeObjectsPage, MetadataNodeVersionsPage, MetadataQuery,
        MetadataQueryError, MetadataVersionsQuery, assess_cluster_bucket_metadata_consistency,
        assess_cluster_bucket_metadata_convergence,
        assess_cluster_bucket_metadata_convergence_for_responder_states,
        assess_cluster_bucket_metadata_mutation_preconditions,
        assess_cluster_bucket_presence_convergence, assess_cluster_metadata_coverage,
        assess_cluster_metadata_fan_in_preflight_for_topology_responders,
        assess_cluster_metadata_fan_in_preflight_for_topology_single_responder,
        assess_cluster_metadata_fan_in_snapshot_for_topology_responders,
        assess_cluster_metadata_fan_in_snapshot_for_topology_single_responder,
        assess_cluster_metadata_readiness, assess_cluster_metadata_snapshot,
        assess_cluster_metadata_snapshot_for_single_responder,
        assess_cluster_metadata_snapshot_for_topology_responders,
        assess_cluster_metadata_snapshot_for_topology_single_responder,
        assess_cluster_responder_membership_views,
        build_cluster_metadata_coverage_for_single_responder,
        build_cluster_metadata_coverage_from_responses, build_cluster_metadata_expected_nodes,
        build_cluster_metadata_snapshot_id, cluster_metadata_fan_in_execution_strategy,
        cluster_metadata_fan_in_auth_token_reject_reason,
        cluster_metadata_fan_in_requires_auth_token,
        cluster_metadata_fan_in_preflight_reject_reason, cluster_metadata_readiness_reject_reason,
        merge_cluster_list_buckets, merge_cluster_list_buckets_page_with_coverage,
        merge_cluster_list_buckets_page_with_topology_snapshot,
        merge_cluster_list_object_versions_page,
        merge_cluster_list_object_versions_page_with_coverage,
        merge_cluster_list_object_versions_page_with_topology_snapshot,
        merge_cluster_list_objects_page, merge_cluster_list_objects_page_with_coverage,
        merge_cluster_list_objects_page_with_topology_snapshot,
        merge_cluster_list_objects_page_with_topology_snapshot_and_marker,
        resolve_cluster_bucket_metadata_for_read, resolve_cluster_bucket_presence_for_read,
        CLUSTER_METADATA_CONSENSUS_FAN_IN_AUTH_TOKEN_MISSING_REASON,
    };
    use crate::metadata::state::{
        BucketMetadataState, ObjectMetadataState, ObjectVersionMetadataState,
    };

    #[test]
    fn upsert_and_fetch_bucket_state() {
        let mut index = InMemoryMetadataIndex::default();
        index.upsert_bucket(BucketMetadataState::new("photos"));

        let bucket = index.get_bucket("photos").expect("bucket should exist");
        assert_eq!(bucket.bucket, "photos");
    }

    #[test]
    fn list_objects_respects_bucket_prefix_and_max_keys() {
        let mut index = InMemoryMetadataIndex::default();
        index.upsert_object(ObjectMetadataState::new("photos", "a/one.jpg"));
        index.upsert_object(ObjectMetadataState::new("photos", "a/two.jpg"));
        index.upsert_object(ObjectMetadataState::new("photos", "b/three.jpg"));
        index.upsert_object(ObjectMetadataState::new("docs", "a/four.txt"));

        let mut query = MetadataQuery::new("photos");
        query.prefix = Some("a/".to_string());
        query.max_keys = 1;

        let results = index.list_objects(&query).expect("query should parse");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].bucket, "photos");
        assert!(results[0].key.starts_with("a/"));
    }

    #[test]
    fn list_objects_page_emits_stable_continuation_token() {
        let mut index = InMemoryMetadataIndex::default();
        index.upsert_object(ObjectMetadataState::new("photos", "a/one.jpg"));
        index.upsert_object(ObjectMetadataState::new("photos", "a/two.jpg"));
        index.upsert_object(ObjectMetadataState::new("photos", "a/three.jpg"));

        let mut query = MetadataQuery::new("photos");
        query.prefix = Some("a/".to_string());
        query.max_keys = 2;
        let first_page = index.list_objects_page(&query).expect("query should parse");
        assert_eq!(first_page.objects.len(), 2);
        assert!(first_page.is_truncated);
        assert!(first_page.next_continuation_token.is_some());

        query.continuation_token = first_page.next_continuation_token;
        let second_page = index
            .list_objects_page(&query)
            .expect("continuation token should parse");
        assert_eq!(second_page.objects.len(), 1);
        assert!(!second_page.is_truncated);
        assert!(second_page.next_continuation_token.is_none());
    }

    #[test]
    fn list_objects_page_rejects_invalid_continuation_token() {
        let mut index = InMemoryMetadataIndex::default();
        index.upsert_object(ObjectMetadataState::new("photos", "a/one.jpg"));

        let mut query = MetadataQuery::new("photos");
        query.continuation_token = Some("not-base64".to_string());
        let err = index
            .list_objects_page(&query)
            .expect_err("token should be rejected");
        assert_eq!(err, MetadataQueryError::InvalidContinuationToken);
    }

    #[test]
    fn list_objects_page_clamps_max_keys_to_contract_limit() {
        let mut index = InMemoryMetadataIndex::default();
        for i in 0..1100 {
            index.upsert_object(ObjectMetadataState::new("photos", format!("a/{i:04}.jpg")));
        }

        let mut query = MetadataQuery::new("photos");
        query.max_keys = usize::MAX;
        let page = index.list_objects_page(&query).expect("query should parse");
        assert_eq!(page.objects.len(), 1000);
        assert!(page.is_truncated);
    }

    #[test]
    fn list_objects_page_rejects_continuation_token_for_different_bucket_or_prefix() {
        let mut index = InMemoryMetadataIndex::default();
        index.upsert_object(ObjectMetadataState::new("photos", "a/one.jpg"));
        index.upsert_object(ObjectMetadataState::new("photos", "a/two.jpg"));
        index.upsert_object(ObjectMetadataState::new("photos", "a/three.jpg"));

        let mut query = MetadataQuery::new("photos");
        query.prefix = Some("a/".to_string());
        query.max_keys = 1;
        let first_page = index.list_objects_page(&query).expect("query should parse");
        let continuation_token = first_page
            .next_continuation_token
            .expect("truncated page should include continuation token");

        let mut wrong_bucket_query = MetadataQuery::new("docs");
        wrong_bucket_query.continuation_token = Some(continuation_token.clone());
        assert_eq!(
            index
                .list_objects_page(&wrong_bucket_query)
                .expect_err("bucket mismatch must be rejected"),
            MetadataQueryError::InvalidContinuationToken
        );

        let mut wrong_prefix_query = MetadataQuery::new("photos");
        wrong_prefix_query.prefix = Some("b/".to_string());
        wrong_prefix_query.continuation_token = Some(continuation_token);
        assert_eq!(
            index
                .list_objects_page(&wrong_prefix_query)
                .expect_err("prefix mismatch must be rejected"),
            MetadataQueryError::InvalidContinuationToken
        );
    }

    #[test]
    fn merge_cluster_page_prefers_non_delete_marker_and_deduplicates_keys() {
        let query = MetadataQuery::new("photos");
        let node_a = vec![ObjectMetadataState {
            bucket: "photos".to_string(),
            key: "docs/a.txt".to_string(),
            latest_version_id: Some("v2".to_string()),
            is_delete_marker: true,
        }];
        let node_b = vec![ObjectMetadataState {
            bucket: "photos".to_string(),
            key: "docs/a.txt".to_string(),
            latest_version_id: Some("v1".to_string()),
            is_delete_marker: false,
        }];

        let page = merge_cluster_list_objects_page(&query, &[node_a, node_b])
            .expect("merge query should parse");
        assert_eq!(page.objects.len(), 1);
        assert_eq!(page.objects[0].key, "docs/a.txt");
        assert!(!page.objects[0].is_delete_marker);
    }

    #[test]
    fn merge_cluster_page_prefers_higher_version_rank_for_same_object_state_type() {
        let query = MetadataQuery::new("photos");
        let node_a = vec![ObjectMetadataState {
            bucket: "photos".to_string(),
            key: "docs/a.txt".to_string(),
            latest_version_id: Some("v1".to_string()),
            is_delete_marker: false,
        }];
        let node_b = vec![ObjectMetadataState {
            bucket: "photos".to_string(),
            key: "docs/a.txt".to_string(),
            latest_version_id: Some("v3".to_string()),
            is_delete_marker: false,
        }];

        let page = merge_cluster_list_objects_page(&query, &[node_a, node_b])
            .expect("merge query should parse");
        assert_eq!(page.objects.len(), 1);
        assert_eq!(page.objects[0].latest_version_id.as_deref(), Some("v3"));
    }

    #[test]
    fn merge_cluster_page_applies_prefix_and_continuation_pagination() {
        let mut query = MetadataQuery::new("photos");
        query.prefix = Some("docs/".to_string());
        query.view_id = Some("view-a".to_string());
        query.max_keys = 1;

        let node_a = vec![
            ObjectMetadataState::new("photos", "docs/a.txt"),
            ObjectMetadataState::new("photos", "docs/b.txt"),
        ];
        let node_b = vec![ObjectMetadataState::new("photos", "docs/c.txt")];

        let first = merge_cluster_list_objects_page(&query, &[node_a.clone(), node_b.clone()])
            .expect("first page should parse");
        assert_eq!(first.objects.len(), 1);
        assert!(first.is_truncated);
        assert!(first.next_continuation_token.is_some());

        query.continuation_token = first.next_continuation_token;
        let second = merge_cluster_list_objects_page(&query, &[node_a, node_b])
            .expect("second page should parse");
        assert_eq!(second.objects.len(), 1);
    }

    #[test]
    fn merge_cluster_page_with_coverage_reports_missing_expected_nodes() {
        let query = MetadataQuery::new("photos");
        let expected_nodes = vec![
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
            "node-c:9000".to_string(),
        ];
        let node_pages = vec![
            MetadataNodeObjectsPage {
                node_id: "node-a:9000".to_string(),
                objects: vec![ObjectMetadataState::new("photos", "docs/a.txt")],
            },
            MetadataNodeObjectsPage {
                node_id: " node-b:9000 ".to_string(),
                objects: vec![ObjectMetadataState::new("photos", "docs/b.txt")],
            },
        ];

        let merged = merge_cluster_list_objects_page_with_coverage(
            &query,
            expected_nodes.as_slice(),
            node_pages.as_slice(),
        )
        .expect("merge query should parse");

        assert_eq!(merged.page.objects.len(), 2);
        assert!(!merged.coverage.complete);
        assert_eq!(
            merged.coverage.expected_nodes,
            vec![
                "node-a:9000".to_string(),
                "node-b:9000".to_string(),
                "node-c:9000".to_string()
            ]
        );
        assert_eq!(
            merged.coverage.responded_nodes,
            vec!["node-a:9000".to_string(), "node-b:9000".to_string()]
        );
        assert_eq!(
            merged.coverage.missing_nodes,
            vec!["node-c:9000".to_string()]
        );
        assert_eq!(merged.coverage.unexpected_nodes, Vec::<String>::new());
    }

    #[test]
    fn merge_cluster_page_with_coverage_reports_unexpected_nodes() {
        let query = MetadataQuery::new("photos");
        let expected_nodes = vec!["node-a:9000".to_string()];
        let node_pages = vec![
            MetadataNodeObjectsPage {
                node_id: "node-a:9000".to_string(),
                objects: vec![ObjectMetadataState::new("photos", "docs/a.txt")],
            },
            MetadataNodeObjectsPage {
                node_id: "node-z:9000".to_string(),
                objects: vec![ObjectMetadataState::new("photos", "docs/z.txt")],
            },
        ];

        let merged = merge_cluster_list_objects_page_with_coverage(
            &query,
            expected_nodes.as_slice(),
            node_pages.as_slice(),
        )
        .expect("merge query should parse");

        assert!(!merged.coverage.complete);
        assert_eq!(merged.coverage.missing_nodes, Vec::<String>::new());
        assert_eq!(
            merged.coverage.unexpected_nodes,
            vec!["node-z:9000".to_string()]
        );
    }

    #[test]
    fn merge_cluster_page_with_coverage_is_order_independent() {
        let mut query = MetadataQuery::new("photos");
        query.prefix = Some("docs/".to_string());
        query.view_id = Some("view-a".to_string());
        query.max_keys = 2;

        let expected_nodes = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let node_a = MetadataNodeObjectsPage {
            node_id: "node-a:9000".to_string(),
            objects: vec![
                ObjectMetadataState::new("photos", "docs/a.txt"),
                ObjectMetadataState::new("photos", "docs/c.txt"),
            ],
        };
        let node_b = MetadataNodeObjectsPage {
            node_id: "node-b:9000".to_string(),
            objects: vec![
                ObjectMetadataState::new("photos", "docs/b.txt"),
                ObjectMetadataState::new("photos", "docs/d.txt"),
            ],
        };

        let page_ab = merge_cluster_list_objects_page_with_coverage(
            &query,
            expected_nodes.as_slice(),
            &[node_a.clone(), node_b.clone()],
        )
        .expect("merge query should parse");
        let page_ba = merge_cluster_list_objects_page_with_coverage(
            &query,
            expected_nodes.as_slice(),
            &[node_b, node_a],
        )
        .expect("merge query should parse");

        assert_eq!(page_ab.page, page_ba.page);
        assert_eq!(page_ab.coverage, page_ba.coverage);
    }

    #[test]
    fn merge_cluster_page_with_coverage_rejects_duplicate_node_responses() {
        let query = MetadataQuery::new("photos");
        let expected_nodes = vec!["node-a:9000".to_string()];
        let node_pages = vec![
            MetadataNodeObjectsPage {
                node_id: "node-a:9000".to_string(),
                objects: vec![ObjectMetadataState::new("photos", "docs/a.txt")],
            },
            MetadataNodeObjectsPage {
                node_id: " node-a:9000 ".to_string(),
                objects: vec![ObjectMetadataState::new("photos", "docs/duplicate.txt")],
            },
        ];

        assert_eq!(
            merge_cluster_list_objects_page_with_coverage(
                &query,
                expected_nodes.as_slice(),
                node_pages.as_slice(),
            )
            .expect_err("duplicate node responses should be rejected"),
            MetadataQueryError::DuplicateCoverageNodeResponse
        );
    }

    #[test]
    fn merge_cluster_page_with_coverage_rejects_empty_node_id() {
        let query = MetadataQuery::new("photos");
        let expected_nodes = vec!["node-a:9000".to_string()];
        let node_pages = vec![MetadataNodeObjectsPage {
            node_id: "   ".to_string(),
            objects: vec![ObjectMetadataState::new("photos", "docs/a.txt")],
        }];

        assert_eq!(
            merge_cluster_list_objects_page_with_coverage(
                &query,
                expected_nodes.as_slice(),
                node_pages.as_slice(),
            )
            .expect_err("empty coverage node ids should be rejected"),
            MetadataQueryError::InvalidCoverageNodeId
        );
    }

    #[test]
    fn list_objects_page_rejects_continuation_token_for_different_view_id() {
        let mut index = InMemoryMetadataIndex::default();
        index.upsert_object(ObjectMetadataState::new("photos", "a/one.jpg"));
        index.upsert_object(ObjectMetadataState::new("photos", "a/two.jpg"));

        let mut query = MetadataQuery::new("photos");
        query.view_id = Some("view-a".to_string());
        query.max_keys = 1;
        let first_page = index.list_objects_page(&query).expect("query should parse");
        let continuation_token = first_page
            .next_continuation_token
            .expect("truncated page should include continuation token");

        let mut wrong_view_query = MetadataQuery::new("photos");
        wrong_view_query.view_id = Some("view-b".to_string());
        wrong_view_query.continuation_token = Some(continuation_token);
        assert_eq!(
            index
                .list_objects_page(&wrong_view_query)
                .expect_err("view mismatch must be rejected"),
            MetadataQueryError::InvalidContinuationToken
        );
    }

    #[test]
    fn list_objects_page_rejects_continuation_token_for_different_snapshot_id() {
        let mut index = InMemoryMetadataIndex::default();
        index.upsert_object(ObjectMetadataState::new("photos", "a/one.jpg"));
        index.upsert_object(ObjectMetadataState::new("photos", "a/two.jpg"));

        let mut query = MetadataQuery::new("photos");
        query.view_id = Some("view-a".to_string());
        query.snapshot_id = Some("snapshot-a".to_string());
        query.max_keys = 1;
        let first_page = index.list_objects_page(&query).expect("query should parse");
        let continuation_token = first_page
            .next_continuation_token
            .expect("truncated page should include continuation token");

        let mut wrong_snapshot_query = MetadataQuery::new("photos");
        wrong_snapshot_query.view_id = Some("view-a".to_string());
        wrong_snapshot_query.snapshot_id = Some("snapshot-b".to_string());
        wrong_snapshot_query.continuation_token = Some(continuation_token);
        assert_eq!(
            index
                .list_objects_page(&wrong_snapshot_query)
                .expect_err("snapshot mismatch must be rejected"),
            MetadataQueryError::InvalidContinuationToken
        );
    }

    #[test]
    fn list_object_versions_page_rejects_orphaned_version_marker() {
        let index = InMemoryMetadataIndex::default();
        let mut query = MetadataVersionsQuery::new("photos");
        query.version_id_marker = Some("v2".to_string());

        let err = index
            .list_object_versions_page(&query)
            .expect_err("orphaned version marker should be rejected");
        assert_eq!(err, MetadataQueryError::InvalidVersionsMarker);
    }

    #[test]
    fn list_object_versions_page_applies_markers_and_next_markers() {
        let mut index = InMemoryMetadataIndex::default();
        index.upsert_object_version(ObjectVersionMetadataState::new(
            "photos",
            "docs/a.txt",
            "v3",
        ));
        index.upsert_object_version(ObjectVersionMetadataState::new(
            "photos",
            "docs/a.txt",
            "v2",
        ));
        index.upsert_object_version(ObjectVersionMetadataState::new(
            "photos",
            "docs/a.txt",
            "v1",
        ));
        index.upsert_object_version(ObjectVersionMetadataState::new(
            "photos",
            "docs/b.txt",
            "b1",
        ));

        let mut first_query = MetadataVersionsQuery::new("photos");
        first_query.prefix = Some("docs/".to_string());
        first_query.max_keys = 2;
        let first_page = index
            .list_object_versions_page(&first_query)
            .expect("first versions page should parse");

        assert_eq!(first_page.versions.len(), 2);
        assert!(first_page.is_truncated);
        assert_eq!(first_page.versions[0].key, "docs/a.txt");
        assert_eq!(first_page.versions[0].version_id, "v3");
        assert_eq!(first_page.versions[1].key, "docs/a.txt");
        assert_eq!(first_page.versions[1].version_id, "v2");
        assert!(first_page.next_continuation_token.is_some());
        assert_eq!(first_page.next_key_marker.as_deref(), Some("docs/a.txt"));
        assert_eq!(first_page.next_version_id_marker.as_deref(), Some("v2"));

        let mut second_query = MetadataVersionsQuery::new("photos");
        second_query.prefix = Some("docs/".to_string());
        second_query.max_keys = 2;
        second_query.continuation_token = first_page.next_continuation_token.clone();
        let second_page = index
            .list_object_versions_page(&second_query)
            .expect("second versions page should parse");

        assert_eq!(
            second_page
                .versions
                .iter()
                .map(|version| (version.key.as_str(), version.version_id.as_str()))
                .collect::<Vec<_>>(),
            vec![("docs/a.txt", "v1"), ("docs/b.txt", "b1")]
        );
        assert!(!second_page.is_truncated);
        assert_eq!(second_page.next_continuation_token, None);
        assert_eq!(second_page.next_key_marker, None);
        assert_eq!(second_page.next_version_id_marker, None);
    }

    #[test]
    fn list_object_versions_page_rejects_mixed_markers_and_continuation_token() {
        let mut index = InMemoryMetadataIndex::default();
        index.upsert_object_version(ObjectVersionMetadataState::new(
            "photos",
            "docs/a.txt",
            "v2",
        ));
        index.upsert_object_version(ObjectVersionMetadataState::new(
            "photos",
            "docs/a.txt",
            "v1",
        ));

        let mut first_query = MetadataVersionsQuery::new("photos");
        first_query.max_keys = 1;
        let first_page = index
            .list_object_versions_page(&first_query)
            .expect("first versions page should parse");
        let token = first_page
            .next_continuation_token
            .expect("truncated page should include continuation token");

        let mut invalid_query = MetadataVersionsQuery::new("photos");
        invalid_query.continuation_token = Some(token);
        invalid_query.key_marker = Some("docs/a.txt".to_string());
        assert_eq!(
            index
                .list_object_versions_page(&invalid_query)
                .expect_err("mixing markers and continuation token should fail"),
            MetadataQueryError::InvalidVersionsMarker
        );
    }

    #[test]
    fn list_object_versions_page_rejects_continuation_token_for_different_view() {
        let mut index = InMemoryMetadataIndex::default();
        index.upsert_object_version(ObjectVersionMetadataState::new(
            "photos",
            "docs/a.txt",
            "v2",
        ));
        index.upsert_object_version(ObjectVersionMetadataState::new(
            "photos",
            "docs/a.txt",
            "v1",
        ));

        let mut first_query = MetadataVersionsQuery::new("photos");
        first_query.view_id = Some("view-a".to_string());
        first_query.max_keys = 1;
        let first_page = index
            .list_object_versions_page(&first_query)
            .expect("first versions page should parse");
        let continuation_token = first_page
            .next_continuation_token
            .expect("truncated page should include continuation token");

        let mut wrong_view_query = MetadataVersionsQuery::new("photos");
        wrong_view_query.view_id = Some("view-b".to_string());
        wrong_view_query.continuation_token = Some(continuation_token);
        assert_eq!(
            index
                .list_object_versions_page(&wrong_view_query)
                .expect_err("view mismatch must be rejected"),
            MetadataQueryError::InvalidVersionsMarker
        );
    }

    #[test]
    fn list_object_versions_page_rejects_continuation_token_for_different_snapshot() {
        let mut index = InMemoryMetadataIndex::default();
        index.upsert_object_version(ObjectVersionMetadataState::new(
            "photos",
            "docs/a.txt",
            "v2",
        ));
        index.upsert_object_version(ObjectVersionMetadataState::new(
            "photos",
            "docs/a.txt",
            "v1",
        ));

        let mut first_query = MetadataVersionsQuery::new("photos");
        first_query.view_id = Some("view-a".to_string());
        first_query.snapshot_id = Some("snapshot-a".to_string());
        first_query.max_keys = 1;
        let first_page = index
            .list_object_versions_page(&first_query)
            .expect("first versions page should parse");
        let continuation_token = first_page
            .next_continuation_token
            .expect("truncated page should include continuation token");

        let mut wrong_snapshot_query = MetadataVersionsQuery::new("photos");
        wrong_snapshot_query.view_id = Some("view-a".to_string());
        wrong_snapshot_query.snapshot_id = Some("snapshot-b".to_string());
        wrong_snapshot_query.continuation_token = Some(continuation_token);
        assert_eq!(
            index
                .list_object_versions_page(&wrong_snapshot_query)
                .expect_err("snapshot mismatch must be rejected"),
            MetadataQueryError::InvalidVersionsMarker
        );
    }

    #[test]
    fn merge_cluster_versions_page_deduplicates_and_orders_entries() {
        let mut query = MetadataVersionsQuery::new("photos");
        query.prefix = Some("docs/".to_string());
        query.max_keys = 3;

        let node_a = vec![
            ObjectVersionMetadataState::new("photos", "docs/a.txt", "v3"),
            ObjectVersionMetadataState::new("photos", "docs/a.txt", "v2"),
            ObjectVersionMetadataState::new("photos", "docs/b.txt", "b1"),
        ];
        let node_b = vec![
            ObjectVersionMetadataState::new("photos", "docs/a.txt", "v3"),
            ObjectVersionMetadataState::new("photos", "docs/c.txt", "c2"),
            ObjectVersionMetadataState::new("docs", "docs/d.txt", "d1"),
        ];

        let page = merge_cluster_list_object_versions_page(&query, &[node_a, node_b])
            .expect("merge versions page should parse");
        assert_eq!(page.versions.len(), 3);
        assert_eq!(
            page.versions
                .iter()
                .map(|version| (
                    version.bucket.as_str(),
                    version.key.as_str(),
                    version.version_id.as_str()
                ))
                .collect::<Vec<_>>(),
            vec![
                ("photos", "docs/a.txt", "v3"),
                ("photos", "docs/a.txt", "v2"),
                ("photos", "docs/b.txt", "b1"),
            ]
        );
        assert!(page.is_truncated);
        assert!(page.next_continuation_token.is_some());
        assert_eq!(page.next_key_marker.as_deref(), Some("docs/b.txt"));
        assert_eq!(page.next_version_id_marker.as_deref(), Some("b1"));
    }

    #[test]
    fn merge_cluster_versions_page_with_coverage_marks_complete_when_all_expected_nodes_respond() {
        let query = MetadataVersionsQuery::new("photos");
        let expected_nodes = vec![
            "node-a:9000".to_string(),
            "node-b:9000".to_string(),
            "node-c:9000".to_string(),
        ];
        let node_pages = vec![
            MetadataNodeVersionsPage {
                node_id: "node-a:9000".to_string(),
                versions: vec![ObjectVersionMetadataState::new(
                    "photos",
                    "docs/a.txt",
                    "v2",
                )],
            },
            MetadataNodeVersionsPage {
                node_id: "node-b:9000".to_string(),
                versions: vec![ObjectVersionMetadataState::new(
                    "photos",
                    "docs/a.txt",
                    "v1",
                )],
            },
            MetadataNodeVersionsPage {
                node_id: "node-c:9000".to_string(),
                versions: vec![ObjectVersionMetadataState::new(
                    "photos",
                    "docs/b.txt",
                    "b1",
                )],
            },
        ];

        let merged = merge_cluster_list_object_versions_page_with_coverage(
            &query,
            expected_nodes.as_slice(),
            node_pages.as_slice(),
        )
        .expect("merge versions query should parse");

        assert_eq!(merged.page.versions.len(), 3);
        assert!(merged.coverage.complete);
        assert_eq!(merged.coverage.missing_nodes, Vec::<String>::new());
        assert_eq!(merged.coverage.unexpected_nodes, Vec::<String>::new());
        assert_eq!(merged.coverage.responded_nodes.len(), 3);
    }

    #[test]
    fn merge_cluster_versions_page_with_coverage_is_order_independent() {
        let mut query = MetadataVersionsQuery::new("photos");
        query.prefix = Some("docs/".to_string());
        query.view_id = Some("view-a".to_string());
        query.max_keys = 3;

        let expected_nodes = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let node_a = MetadataNodeVersionsPage {
            node_id: "node-a:9000".to_string(),
            versions: vec![
                ObjectVersionMetadataState::new("photos", "docs/a.txt", "v2"),
                ObjectVersionMetadataState::new("photos", "docs/c.txt", "v1"),
            ],
        };
        let node_b = MetadataNodeVersionsPage {
            node_id: "node-b:9000".to_string(),
            versions: vec![
                ObjectVersionMetadataState::new("photos", "docs/a.txt", "v1"),
                ObjectVersionMetadataState::new("photos", "docs/b.txt", "v3"),
            ],
        };

        let page_ab = merge_cluster_list_object_versions_page_with_coverage(
            &query,
            expected_nodes.as_slice(),
            &[node_a.clone(), node_b.clone()],
        )
        .expect("merge versions query should parse");
        let page_ba = merge_cluster_list_object_versions_page_with_coverage(
            &query,
            expected_nodes.as_slice(),
            &[node_b, node_a],
        )
        .expect("merge versions query should parse");

        assert_eq!(page_ab.page, page_ba.page);
        assert_eq!(page_ab.coverage, page_ba.coverage);
    }

    #[test]
    fn merge_cluster_versions_page_with_coverage_rejects_duplicate_node_responses() {
        let query = MetadataVersionsQuery::new("photos");
        let expected_nodes = vec!["node-a:9000".to_string()];
        let node_pages = vec![
            MetadataNodeVersionsPage {
                node_id: "node-a:9000".to_string(),
                versions: vec![ObjectVersionMetadataState::new(
                    "photos",
                    "docs/a.txt",
                    "v2",
                )],
            },
            MetadataNodeVersionsPage {
                node_id: "node-a:9000".to_string(),
                versions: vec![ObjectVersionMetadataState::new(
                    "photos",
                    "docs/a.txt",
                    "v1",
                )],
            },
        ];

        assert_eq!(
            merge_cluster_list_object_versions_page_with_coverage(
                &query,
                expected_nodes.as_slice(),
                node_pages.as_slice(),
            )
            .expect_err("duplicate node responses should be rejected"),
            MetadataQueryError::DuplicateCoverageNodeResponse
        );
    }

    #[test]
    fn build_cluster_metadata_coverage_from_responses_reports_missing_and_unexpected_nodes() {
        let expected = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let responded = vec!["node-a:9000".to_string(), "node-z:9000".to_string()];

        let coverage = build_cluster_metadata_coverage_from_responses(
            expected.as_slice(),
            responded.as_slice(),
        )
        .expect("coverage should build");
        assert!(!coverage.complete);
        assert_eq!(coverage.missing_nodes, vec!["node-b:9000".to_string()]);
        assert_eq!(coverage.unexpected_nodes, vec!["node-z:9000".to_string()]);
    }

    #[test]
    fn build_cluster_metadata_coverage_from_responses_rejects_duplicate_nodes() {
        let expected = vec!["node-a:9000".to_string()];
        let responded = vec!["node-a:9000".to_string(), " node-a:9000 ".to_string()];

        assert_eq!(
            build_cluster_metadata_coverage_from_responses(
                expected.as_slice(),
                responded.as_slice()
            )
            .expect_err("duplicate node responses should fail"),
            MetadataQueryError::DuplicateCoverageNodeResponse
        );
    }

    #[test]
    fn build_cluster_metadata_coverage_from_responses_rejects_duplicate_expected_nodes() {
        let expected = vec!["node-a:9000".to_string(), "NODE-A:9000".to_string()];
        let responded = vec!["node-a:9000".to_string()];

        assert_eq!(
            build_cluster_metadata_coverage_from_responses(
                expected.as_slice(),
                responded.as_slice()
            )
            .expect_err("duplicate expected node ids should fail"),
            MetadataQueryError::DuplicateCoverageExpectedNode
        );
    }

    #[test]
    fn build_cluster_metadata_coverage_from_responses_rejects_empty_nodes() {
        let expected = vec!["node-a:9000".to_string()];
        let responded = vec!["   ".to_string()];

        assert_eq!(
            build_cluster_metadata_coverage_from_responses(
                expected.as_slice(),
                responded.as_slice()
            )
            .expect_err("empty node ids should fail"),
            MetadataQueryError::InvalidCoverageNodeId
        );
    }

    #[test]
    fn build_cluster_metadata_coverage_from_responses_matches_node_ids_case_insensitively() {
        let expected = vec!["Node-A:9000".to_string(), "Node-B:9000".to_string()];
        let responded = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];

        let coverage = build_cluster_metadata_coverage_from_responses(
            expected.as_slice(),
            responded.as_slice(),
        )
        .expect("coverage should build");
        assert!(coverage.complete);
        assert!(coverage.missing_nodes.is_empty());
        assert!(coverage.unexpected_nodes.is_empty());
    }

    #[test]
    fn build_cluster_metadata_coverage_for_single_responder_reports_partial_coverage() {
        let expected = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let coverage = build_cluster_metadata_coverage_for_single_responder(
            expected.as_slice(),
            "node-a:9000",
        );
        assert_eq!(coverage.expected_nodes, expected);
        assert_eq!(coverage.responded_nodes, vec!["node-a:9000".to_string()]);
        assert_eq!(coverage.missing_nodes, vec!["node-b:9000".to_string()]);
        assert!(coverage.unexpected_nodes.is_empty());
        assert!(!coverage.complete);
    }

    #[test]
    fn build_cluster_metadata_coverage_for_single_responder_falls_back_on_invalid_node_id() {
        let expected = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let coverage =
            build_cluster_metadata_coverage_for_single_responder(expected.as_slice(), "   ");
        assert_eq!(coverage.expected_nodes, expected);
        assert!(coverage.responded_nodes.is_empty());
        assert_eq!(
            coverage.missing_nodes,
            vec!["node-a:9000".to_string(), "node-b:9000".to_string()]
        );
        assert!(coverage.unexpected_nodes.is_empty());
        assert!(!coverage.complete);
    }

    #[test]
    fn build_cluster_metadata_expected_nodes_uses_local_node_only_for_local_strategy() {
        let expected = build_cluster_metadata_expected_nodes(
            ClusterMetadataListingStrategy::LocalNodeOnly,
            "node-a:9000",
            &["node-b:9000".to_string(), "node-c:9000".to_string()],
        );
        assert_eq!(expected, vec!["node-a:9000".to_string()]);
    }

    #[test]
    fn build_cluster_metadata_expected_nodes_uses_cluster_members_for_consensus_strategy() {
        let expected = build_cluster_metadata_expected_nodes(
            ClusterMetadataListingStrategy::ConsensusIndex,
            "node-a:9000",
            &["node-b:9000".to_string(), "node-c:9000".to_string()],
        );
        assert_eq!(expected.len(), 3);
        assert!(expected.contains(&"node-a:9000".to_string()));
        assert!(expected.contains(&"node-b:9000".to_string()));
        assert!(expected.contains(&"node-c:9000".to_string()));
    }

    #[test]
    fn build_cluster_metadata_expected_nodes_uses_cluster_members_for_aggregation_strategy() {
        let expected = build_cluster_metadata_expected_nodes(
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            "node-a:9000",
            &[
                "node-b:9000".to_string(),
                "NODE-B:9000".to_string(),
                "node-a:9000".to_string(),
                " ".to_string(),
            ],
        );

        assert_eq!(expected.len(), 2);
        assert!(
            expected
                .iter()
                .any(|node| node.eq_ignore_ascii_case("node-a:9000"))
        );
        assert!(
            expected
                .iter()
                .any(|node| node.eq_ignore_ascii_case("node-b:9000"))
        );
    }

    #[test]
    fn build_cluster_metadata_expected_nodes_uses_cluster_members_for_full_replication_strategy() {
        let expected = build_cluster_metadata_expected_nodes(
            ClusterMetadataListingStrategy::FullReplication,
            "node-a:9000",
            &["node-b:9000".to_string(), "node-c:9000".to_string()],
        );

        assert_eq!(expected.len(), 3);
        assert!(expected.contains(&"node-a:9000".to_string()));
        assert!(expected.contains(&"node-b:9000".to_string()));
        assert!(expected.contains(&"node-c:9000".to_string()));
    }

    #[test]
    fn assess_snapshot_for_topology_single_responder_uses_strategy_expected_nodes() {
        let assessment = assess_cluster_metadata_snapshot_for_topology_single_responder(
            ClusterMetadataListingStrategy::LocalNodeOnly,
            Some("view-a"),
            "node-a:9000",
            &["node-b:9000".to_string(), "node-c:9000".to_string()],
            "node-a:9000",
        );

        assert_eq!(assessment.coverage.expected_nodes, vec!["node-a:9000"]);
        assert_eq!(assessment.coverage.responded_nodes, vec!["node-a:9000"]);
        assert!(assessment.coverage.missing_nodes.is_empty());
        assert!(assessment.coverage.complete);
    }

    #[test]
    fn assess_snapshot_for_topology_single_responder_falls_back_to_membership_on_empty_projection()
    {
        let assessment = assess_cluster_metadata_snapshot_for_topology_single_responder(
            ClusterMetadataListingStrategy::LocalNodeOnly,
            Some("view-b"),
            "   ",
            &["node-b:9000".to_string(), "node-c:9000".to_string()],
            "node-b:9000",
        );

        assert_eq!(
            assessment.coverage.expected_nodes,
            vec!["node-b:9000".to_string(), "node-c:9000".to_string()]
        );
        assert_eq!(
            assessment.coverage.responded_nodes,
            vec!["node-b:9000".to_string()]
        );
        assert_eq!(
            assessment.coverage.missing_nodes,
            vec!["node-c:9000".to_string()]
        );
        assert!(!assessment.coverage.complete);
    }

    #[test]
    fn assess_snapshot_for_topology_responders_uses_strategy_expected_nodes() {
        let responders = vec!["node-a:9000".to_string()];
        let assessment = assess_cluster_metadata_snapshot_for_topology_responders(
            ClusterMetadataListingStrategy::LocalNodeOnly,
            Some("view-a"),
            "node-a:9000",
            &["node-b:9000".to_string(), "node-c:9000".to_string()],
            responders.as_slice(),
        )
        .expect("assessment should build");

        assert_eq!(assessment.coverage.expected_nodes, vec!["node-a:9000"]);
        assert_eq!(assessment.coverage.responded_nodes, responders);
        assert!(assessment.coverage.missing_nodes.is_empty());
        assert!(assessment.coverage.complete);
    }

    #[test]
    fn assess_snapshot_for_topology_responders_falls_back_to_membership_on_empty_projection() {
        let responders = vec!["node-b:9000".to_string()];
        let assessment = assess_cluster_metadata_snapshot_for_topology_responders(
            ClusterMetadataListingStrategy::LocalNodeOnly,
            Some("view-b"),
            "   ",
            &["node-b:9000".to_string(), "node-c:9000".to_string()],
            responders.as_slice(),
        )
        .expect("assessment should build");

        assert_eq!(
            assessment.coverage.expected_nodes,
            vec!["node-b:9000".to_string(), "node-c:9000".to_string()]
        );
        assert_eq!(assessment.coverage.responded_nodes, responders);
        assert_eq!(
            assessment.coverage.missing_nodes,
            vec!["node-c:9000".to_string()]
        );
        assert!(!assessment.coverage.complete);
    }

    #[test]
    fn assess_snapshot_for_topology_responders_rejects_duplicate_responder_ids() {
        let responders = vec!["node-a:9000".to_string(), "NODE-A:9000".to_string()];
        assert_eq!(
            assess_cluster_metadata_snapshot_for_topology_responders(
                ClusterMetadataListingStrategy::RequestTimeAggregation,
                Some("view-c"),
                "node-a:9000",
                &["node-b:9000".to_string()],
                responders.as_slice(),
            )
            .expect_err("duplicate responder ids must fail"),
            MetadataQueryError::DuplicateCoverageNodeResponse
        );
    }

    #[test]
    fn merge_objects_with_topology_snapshot_binds_continuation_to_snapshot_id() {
        let mut query = MetadataQuery::new("photos");
        query.view_id = Some(" view-a ".to_string());
        query.max_keys = 1;

        let node_pages = vec![
            MetadataNodeObjectsPage {
                node_id: "node-a:9000".to_string(),
                objects: vec![
                    ObjectMetadataState::new("photos", "docs/a.txt"),
                    ObjectMetadataState::new("photos", "docs/b.txt"),
                ],
            },
            MetadataNodeObjectsPage {
                node_id: "node-b:9000".to_string(),
                objects: vec![ObjectMetadataState::new("photos", "docs/c.txt")],
            },
        ];

        let first = merge_cluster_list_objects_page_with_topology_snapshot(
            &query,
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            "node-a:9000",
            &["node-b:9000".to_string()],
            node_pages.as_slice(),
        )
        .expect("merge should succeed");
        assert_eq!(first.snapshot.view_id.as_deref(), Some("view-a"));
        assert!(first.page.is_truncated);
        let continuation_token = first
            .page
            .next_continuation_token
            .clone()
            .expect("first page should emit continuation token");

        let mut next_query = query.clone();
        next_query.continuation_token = Some(continuation_token.clone());
        let second = merge_cluster_list_objects_page_with_topology_snapshot(
            &next_query,
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            "node-a:9000",
            &["node-b:9000".to_string()],
            node_pages.as_slice(),
        )
        .expect("continuation token should remain valid on stable snapshot");
        assert_eq!(second.page.objects.len(), 1);

        let reduced_responders = vec![MetadataNodeObjectsPage {
            node_id: "node-a:9000".to_string(),
            objects: vec![
                ObjectMetadataState::new("photos", "docs/a.txt"),
                ObjectMetadataState::new("photos", "docs/b.txt"),
            ],
        }];
        assert_eq!(
            merge_cluster_list_objects_page_with_topology_snapshot(
                &next_query,
                ClusterMetadataListingStrategy::RequestTimeAggregation,
                "node-a:9000",
                &["node-b:9000".to_string()],
                reduced_responders.as_slice(),
            )
            .expect_err("continuation token replay must fail across snapshot changes"),
            MetadataQueryError::InvalidContinuationToken
        );
    }

    #[test]
    fn merge_objects_with_topology_snapshot_rejects_duplicate_responder_ids() {
        let query = MetadataQuery::new("photos");
        let node_pages = vec![
            MetadataNodeObjectsPage {
                node_id: "node-a:9000".to_string(),
                objects: vec![ObjectMetadataState::new("photos", "docs/a.txt")],
            },
            MetadataNodeObjectsPage {
                node_id: "NODE-A:9000".to_string(),
                objects: vec![ObjectMetadataState::new("photos", "docs/b.txt")],
            },
        ];

        assert_eq!(
            merge_cluster_list_objects_page_with_topology_snapshot(
                &query,
                ClusterMetadataListingStrategy::RequestTimeAggregation,
                "node-a:9000",
                &["node-b:9000".to_string()],
                node_pages.as_slice(),
            )
            .expect_err("duplicate responder ids must fail"),
            MetadataQueryError::DuplicateCoverageNodeResponse
        );
    }

    #[test]
    fn merge_objects_with_topology_snapshot_and_marker_applies_marker_pagination() {
        let mut query = MetadataQuery::new("photos");
        query.view_id = Some("view-a".to_string());
        query.prefix = Some("docs/".to_string());
        query.max_keys = 2;

        let node_pages = vec![MetadataNodeObjectsPage {
            node_id: "node-a:9000".to_string(),
            objects: vec![
                ObjectMetadataState::new("photos", "docs/a.txt"),
                ObjectMetadataState::new("photos", "docs/b.txt"),
                ObjectMetadataState::new("photos", "docs/c.txt"),
            ],
        }];

        let merged = merge_cluster_list_objects_page_with_topology_snapshot_and_marker(
            &query,
            Some("docs/a.txt"),
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            "node-a:9000",
            &["node-b:9000".to_string()],
            node_pages.as_slice(),
        )
        .expect("marker-based merge should succeed");

        assert_eq!(
            merged
                .page
                .objects
                .iter()
                .map(|object| object.key.as_str())
                .collect::<Vec<_>>(),
            vec!["docs/b.txt", "docs/c.txt"]
        );
        assert!(!merged.page.is_truncated);
    }

    #[test]
    fn merge_objects_with_topology_snapshot_and_marker_rejects_mixed_marker_and_token() {
        let mut query = MetadataQuery::new("photos");
        query.view_id = Some("view-a".to_string());
        query.continuation_token = Some("v1:placeholder".to_string());
        let node_pages = vec![MetadataNodeObjectsPage {
            node_id: "node-a:9000".to_string(),
            objects: vec![ObjectMetadataState::new("photos", "docs/a.txt")],
        }];

        assert_eq!(
            merge_cluster_list_objects_page_with_topology_snapshot_and_marker(
                &query,
                Some("docs/a.txt"),
                ClusterMetadataListingStrategy::RequestTimeAggregation,
                "node-a:9000",
                &["node-b:9000".to_string()],
                node_pages.as_slice(),
            )
            .expect_err("mixed marker and continuation token must fail"),
            MetadataQueryError::InvalidContinuationToken
        );
    }

    #[test]
    fn merge_versions_with_topology_snapshot_binds_continuation_to_snapshot_id() {
        let mut query = MetadataVersionsQuery::new("photos");
        query.view_id = Some(" view-a ".to_string());
        query.max_keys = 1;

        let node_pages = vec![
            MetadataNodeVersionsPage {
                node_id: "node-a:9000".to_string(),
                versions: vec![
                    ObjectVersionMetadataState::new("photos", "docs/a.txt", "v3"),
                    ObjectVersionMetadataState::new("photos", "docs/a.txt", "v2"),
                ],
            },
            MetadataNodeVersionsPage {
                node_id: "node-b:9000".to_string(),
                versions: vec![ObjectVersionMetadataState::new(
                    "photos",
                    "docs/b.txt",
                    "v1",
                )],
            },
        ];

        let first = merge_cluster_list_object_versions_page_with_topology_snapshot(
            &query,
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            "node-a:9000",
            &["node-b:9000".to_string()],
            node_pages.as_slice(),
        )
        .expect("merge should succeed");
        assert_eq!(first.snapshot.view_id.as_deref(), Some("view-a"));
        assert!(first.page.is_truncated);
        let continuation_token = first
            .page
            .next_continuation_token
            .clone()
            .expect("first page should emit continuation token");

        let mut next_query = query.clone();
        next_query.continuation_token = Some(continuation_token.clone());
        let second = merge_cluster_list_object_versions_page_with_topology_snapshot(
            &next_query,
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            "node-a:9000",
            &["node-b:9000".to_string()],
            node_pages.as_slice(),
        )
        .expect("continuation token should remain valid on stable snapshot");
        assert_eq!(second.page.versions.len(), 1);

        let reduced_responders = vec![MetadataNodeVersionsPage {
            node_id: "node-a:9000".to_string(),
            versions: vec![
                ObjectVersionMetadataState::new("photos", "docs/a.txt", "v3"),
                ObjectVersionMetadataState::new("photos", "docs/a.txt", "v2"),
            ],
        }];
        assert_eq!(
            merge_cluster_list_object_versions_page_with_topology_snapshot(
                &next_query,
                ClusterMetadataListingStrategy::RequestTimeAggregation,
                "node-a:9000",
                &["node-b:9000".to_string()],
                reduced_responders.as_slice(),
            )
            .expect_err("continuation token replay must fail across snapshot changes"),
            MetadataQueryError::InvalidVersionsMarker
        );
    }

    #[test]
    fn merge_cluster_list_buckets_dedupes_and_sorts_bucket_names() {
        let mut photos = BucketMetadataState::new("photos");
        photos.versioning_enabled = true;
        let logs = BucketMetadataState::new("logs");
        let mut expected_photos = BucketMetadataState::new("photos");
        expected_photos.versioning_enabled = true;

        let merged = merge_cluster_list_buckets(
            [vec![photos.clone(), logs.clone()], vec![photos]].as_slice(),
        )
        .expect("bucket merge should succeed");
        assert_eq!(merged, vec![logs, expected_photos]);
    }

    #[test]
    fn merge_cluster_list_buckets_rejects_inconsistent_bucket_state() {
        let mut photos_a = BucketMetadataState::new("photos");
        photos_a.versioning_enabled = true;
        let photos_b = BucketMetadataState::new("photos");

        assert_eq!(
            merge_cluster_list_buckets(&[vec![photos_a], vec![photos_b]])
                .expect_err("inconsistent bucket metadata across responders must fail closed"),
            MetadataQueryError::InconsistentBucketMetadataResponse
        );
    }

    #[test]
    fn merge_cluster_list_buckets_with_coverage_reports_responder_fan_in() {
        let expected = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let node_pages = vec![
            MetadataNodeBucketsPage {
                node_id: "node-a:9000".to_string(),
                buckets: vec![BucketMetadataState::new("photos")],
            },
            MetadataNodeBucketsPage {
                node_id: "node-b:9000".to_string(),
                buckets: vec![BucketMetadataState::new("logs")],
            },
        ];

        let merged =
            merge_cluster_list_buckets_page_with_coverage(expected.as_slice(), &node_pages)
                .expect("bucket merge with coverage should succeed");
        assert_eq!(
            merged
                .buckets
                .iter()
                .map(|bucket| bucket.bucket.as_str())
                .collect::<Vec<_>>(),
            vec!["logs", "photos"]
        );
        assert!(merged.coverage.complete);
        assert_eq!(merged.coverage.expected_nodes.len(), 2);
        assert_eq!(merged.coverage.responded_nodes.len(), 2);
    }

    #[test]
    fn merge_cluster_list_buckets_with_topology_snapshot_exposes_snapshot_context() {
        let node_pages = vec![
            MetadataNodeBucketsPage {
                node_id: "node-a:9000".to_string(),
                buckets: vec![BucketMetadataState::new("photos")],
            },
            MetadataNodeBucketsPage {
                node_id: "node-b:9000".to_string(),
                buckets: vec![BucketMetadataState::new("logs")],
            },
        ];

        let merged = merge_cluster_list_buckets_page_with_topology_snapshot(
            Some(" view-a "),
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            "node-a:9000",
            &["node-b:9000".to_string()],
            node_pages.as_slice(),
        )
        .expect("topology-scoped bucket merge should succeed");
        assert_eq!(merged.snapshot.view_id.as_deref(), Some("view-a"));
        assert!(merged.snapshot.coverage.complete);
        assert_eq!(merged.snapshot.coverage.expected_nodes.len(), 2);
        assert_eq!(
            merged
                .buckets
                .iter()
                .map(|bucket| bucket.bucket.as_str())
                .collect::<Vec<_>>(),
            vec!["logs", "photos"]
        );
    }

    #[test]
    fn merge_cluster_list_buckets_with_topology_snapshot_rejects_duplicate_responders() {
        let node_pages = vec![
            MetadataNodeBucketsPage {
                node_id: "node-a:9000".to_string(),
                buckets: vec![BucketMetadataState::new("photos")],
            },
            MetadataNodeBucketsPage {
                node_id: "node-a:9000".to_string(),
                buckets: vec![BucketMetadataState::new("logs")],
            },
        ];

        assert_eq!(
            merge_cluster_list_buckets_page_with_topology_snapshot(
                Some("view-a"),
                ClusterMetadataListingStrategy::RequestTimeAggregation,
                "node-a:9000",
                &["node-b:9000".to_string()],
                node_pages.as_slice(),
            )
            .expect_err("duplicate responder ids must fail closed"),
            MetadataQueryError::DuplicateCoverageNodeResponse
        );
    }

    #[test]
    fn assess_cluster_metadata_coverage_marks_complete_when_no_gaps_exist() {
        let expected = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let responded = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let coverage = build_cluster_metadata_coverage_from_responses(
            expected.as_slice(),
            responded.as_slice(),
        )
        .expect("coverage should build");

        let assessment = assess_cluster_metadata_coverage(&coverage);
        assert!(assessment.complete);
        assert_eq!(assessment.gap, None);
        assert_eq!(assessment.expected_nodes, 2);
        assert_eq!(assessment.responded_nodes, 2);
        assert_eq!(assessment.missing_nodes, 0);
        assert_eq!(assessment.unexpected_nodes, 0);
    }

    #[test]
    fn assess_cluster_metadata_coverage_reports_missing_expected_nodes_gap() {
        let expected = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let responded = vec!["node-a:9000".to_string()];
        let coverage = build_cluster_metadata_coverage_from_responses(
            expected.as_slice(),
            responded.as_slice(),
        )
        .expect("coverage should build");

        let assessment = assess_cluster_metadata_coverage(&coverage);
        assert!(!assessment.complete);
        assert_eq!(
            assessment.gap,
            Some(ClusterMetadataCoverageGap::MissingExpectedNodes)
        );
        assert_eq!(assessment.missing_nodes, 1);
        assert_eq!(assessment.unexpected_nodes, 0);
    }

    #[test]
    fn assess_cluster_metadata_coverage_reports_unexpected_responder_nodes_gap() {
        let expected = vec!["node-a:9000".to_string()];
        let responded = vec!["node-a:9000".to_string(), "node-z:9000".to_string()];
        let coverage = build_cluster_metadata_coverage_from_responses(
            expected.as_slice(),
            responded.as_slice(),
        )
        .expect("coverage should build");

        let assessment = assess_cluster_metadata_coverage(&coverage);
        assert!(!assessment.complete);
        assert_eq!(
            assessment.gap,
            Some(ClusterMetadataCoverageGap::UnexpectedResponderNodes)
        );
        assert_eq!(assessment.missing_nodes, 0);
        assert_eq!(assessment.unexpected_nodes, 1);
    }

    #[test]
    fn assess_cluster_metadata_coverage_reports_missing_and_unexpected_gap() {
        let expected = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let responded = vec!["node-a:9000".to_string(), "node-z:9000".to_string()];
        let coverage = build_cluster_metadata_coverage_from_responses(
            expected.as_slice(),
            responded.as_slice(),
        )
        .expect("coverage should build");

        let assessment = assess_cluster_metadata_coverage(&coverage);
        assert!(!assessment.complete);
        assert_eq!(
            assessment.gap,
            Some(ClusterMetadataCoverageGap::MissingAndUnexpectedNodes)
        );
        assert_eq!(assessment.missing_nodes, 1);
        assert_eq!(assessment.unexpected_nodes, 1);
        assert_eq!(
            assessment.gap.map(ClusterMetadataCoverageGap::as_str),
            Some("missing-and-unexpected-nodes")
        );
    }

    #[test]
    fn assess_cluster_bucket_metadata_consistency_reports_consistent_present_value() {
        let states = vec![
            ClusterBucketMetadataResponderState::Present(true),
            ClusterBucketMetadataResponderState::Present(true),
        ];
        let assessment = assess_cluster_bucket_metadata_consistency(states.as_slice());
        assert!(assessment.consistent);
        assert_eq!(assessment.gap, None);
        assert_eq!(assessment.missing_bucket_responders, 0);
        assert_eq!(assessment.value, Some(true));
    }

    #[test]
    fn assess_cluster_bucket_metadata_consistency_reports_missing_bucket_gap() {
        let states = vec![
            ClusterBucketMetadataResponderState::Present(true),
            ClusterBucketMetadataResponderState::MissingBucket,
        ];
        let assessment = assess_cluster_bucket_metadata_consistency(states.as_slice());
        assert!(!assessment.consistent);
        assert_eq!(
            assessment.gap,
            Some(ClusterBucketMetadataConsistencyGap::MissingBucketOnResponder)
        );
        assert_eq!(assessment.missing_bucket_responders, 1);
        assert_eq!(assessment.value, None);
        assert_eq!(
            assessment
                .gap
                .map(ClusterBucketMetadataConsistencyGap::as_str),
            Some("missing-bucket-on-responder")
        );
    }

    #[test]
    fn assess_cluster_bucket_metadata_consistency_reports_inconsistent_value_gap() {
        let states = vec![
            ClusterBucketMetadataResponderState::Present(false),
            ClusterBucketMetadataResponderState::Present(true),
        ];
        let assessment = assess_cluster_bucket_metadata_consistency(states.as_slice());
        assert!(!assessment.consistent);
        assert_eq!(
            assessment.gap,
            Some(ClusterBucketMetadataConsistencyGap::InconsistentResponderValues)
        );
        assert_eq!(assessment.missing_bucket_responders, 0);
        assert_eq!(assessment.value, None);
    }

    #[test]
    fn assess_cluster_bucket_metadata_consistency_reports_no_responder_value_gap() {
        let states: Vec<ClusterBucketMetadataResponderState<bool>> = vec![];
        let assessment = assess_cluster_bucket_metadata_consistency(states.as_slice());
        assert!(!assessment.consistent);
        assert_eq!(
            assessment.gap,
            Some(ClusterBucketMetadataConsistencyGap::NoResponderValues)
        );
        assert_eq!(assessment.missing_bucket_responders, 0);
        assert_eq!(assessment.value, None);
        assert_eq!(
            assessment
                .gap
                .map(ClusterBucketMetadataConsistencyGap::as_str),
            Some("no-responder-values")
        );
    }

    #[test]
    fn resolve_cluster_bucket_presence_for_read_reports_present_for_converged_true_state() {
        let states = vec![
            ClusterBucketMetadataResponderState::Present(true),
            ClusterBucketMetadataResponderState::Present(true),
        ];
        assert_eq!(
            resolve_cluster_bucket_presence_for_read(states.as_slice()),
            ClusterBucketPresenceReadResolution::Present
        );
    }

    #[test]
    fn resolve_cluster_bucket_presence_for_read_reports_missing_when_all_responders_missing() {
        let states = vec![
            ClusterBucketMetadataResponderState::MissingBucket,
            ClusterBucketMetadataResponderState::MissingBucket,
        ];
        assert_eq!(
            resolve_cluster_bucket_presence_for_read(states.as_slice()),
            ClusterBucketPresenceReadResolution::Missing
        );
    }

    #[test]
    fn resolve_cluster_bucket_presence_for_read_reports_inconsistent_for_mixed_states() {
        let states = vec![
            ClusterBucketMetadataResponderState::Present(true),
            ClusterBucketMetadataResponderState::MissingBucket,
        ];
        assert_eq!(
            resolve_cluster_bucket_presence_for_read(states.as_slice()),
            ClusterBucketPresenceReadResolution::Inconsistent
        );
    }

    #[test]
    fn assess_cluster_bucket_presence_convergence_reports_converged_when_all_present() {
        let states = vec![
            ClusterBucketMetadataResponderState::Present(true),
            ClusterBucketMetadataResponderState::Present(true),
        ];
        let assessment = assess_cluster_bucket_presence_convergence(
            states.as_slice(),
            ClusterBucketPresenceConvergenceExpectation::Present,
        );
        assert!(assessment.converged);
        assert_eq!(
            assessment.expectation,
            ClusterBucketPresenceConvergenceExpectation::Present
        );
        assert_eq!(assessment.gap, None);
    }

    #[test]
    fn assess_cluster_bucket_presence_convergence_reports_converged_when_all_missing() {
        let states = vec![
            ClusterBucketMetadataResponderState::MissingBucket,
            ClusterBucketMetadataResponderState::MissingBucket,
        ];
        let assessment = assess_cluster_bucket_presence_convergence(
            states.as_slice(),
            ClusterBucketPresenceConvergenceExpectation::Missing,
        );
        assert!(assessment.converged);
        assert_eq!(
            assessment.expectation,
            ClusterBucketPresenceConvergenceExpectation::Missing
        );
        assert_eq!(assessment.gap, None);
    }

    #[test]
    fn assess_cluster_bucket_presence_convergence_surfaces_partial_missing_gap() {
        let states = vec![
            ClusterBucketMetadataResponderState::Present(true),
            ClusterBucketMetadataResponderState::MissingBucket,
        ];
        let assessment = assess_cluster_bucket_presence_convergence(
            states.as_slice(),
            ClusterBucketPresenceConvergenceExpectation::Missing,
        );
        assert!(!assessment.converged);
        assert_eq!(
            assessment.gap,
            Some(ClusterBucketPresenceConvergenceGap::MissingBucketOnResponder)
        );
    }

    #[test]
    fn assess_cluster_bucket_presence_convergence_surfaces_present_when_expecting_missing() {
        let states = vec![
            ClusterBucketMetadataResponderState::Present(true),
            ClusterBucketMetadataResponderState::Present(true),
        ];
        let assessment = assess_cluster_bucket_presence_convergence(
            states.as_slice(),
            ClusterBucketPresenceConvergenceExpectation::Missing,
        );
        assert!(!assessment.converged);
        assert_eq!(
            assessment.gap,
            Some(ClusterBucketPresenceConvergenceGap::UnexpectedResponderPresenceState)
        );
        assert_eq!(
            assessment
                .gap
                .map(ClusterBucketPresenceConvergenceGap::as_str),
            Some("unexpected-responder-presence-state")
        );
    }

    #[test]
    fn resolve_cluster_bucket_metadata_for_read_reports_present_for_converged_value() {
        let states = vec![
            ClusterBucketMetadataResponderState::Present("enabled".to_string()),
            ClusterBucketMetadataResponderState::Present("enabled".to_string()),
        ];
        assert_eq!(
            resolve_cluster_bucket_metadata_for_read(states.as_slice()),
            ClusterBucketMetadataReadResolution::Present("enabled".to_string())
        );
    }

    #[test]
    fn resolve_cluster_bucket_metadata_for_read_reports_missing_when_all_responders_missing() {
        let states = vec![
            ClusterBucketMetadataResponderState::<String>::MissingBucket,
            ClusterBucketMetadataResponderState::<String>::MissingBucket,
        ];
        assert_eq!(
            resolve_cluster_bucket_metadata_for_read(states.as_slice()),
            ClusterBucketMetadataReadResolution::Missing
        );
    }

    #[test]
    fn resolve_cluster_bucket_metadata_for_read_reports_inconsistent_for_mixed_states() {
        let states = vec![
            ClusterBucketMetadataResponderState::Present("enabled".to_string()),
            ClusterBucketMetadataResponderState::MissingBucket,
        ];
        assert_eq!(
            resolve_cluster_bucket_metadata_for_read(states.as_slice()),
            ClusterBucketMetadataReadResolution::Inconsistent
        );
    }

    #[test]
    fn resolve_cluster_bucket_metadata_for_read_reports_inconsistent_for_divergent_values() {
        let states = vec![
            ClusterBucketMetadataResponderState::Present("enabled".to_string()),
            ClusterBucketMetadataResponderState::Present("suspended".to_string()),
        ];
        assert_eq!(
            resolve_cluster_bucket_metadata_for_read(states.as_slice()),
            ClusterBucketMetadataReadResolution::Inconsistent
        );
    }

    #[test]
    fn assess_cluster_metadata_readiness_rejects_local_only_strategy_even_with_full_coverage() {
        let expected = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let responded = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let coverage = build_cluster_metadata_coverage_from_responses(
            expected.as_slice(),
            responded.as_slice(),
        )
        .expect("coverage should build");

        let assessment = assess_cluster_metadata_readiness(
            ClusterMetadataListingStrategy::LocalNodeOnly,
            &coverage,
        );
        assert!(!assessment.ready);
        assert!(!assessment.cluster_authoritative);
        assert_eq!(
            assessment.gap,
            Some(ClusterMetadataReadinessGap::StrategyNotClusterAuthoritative)
        );
        assert_eq!(
            assessment.gap.map(ClusterMetadataReadinessGap::as_str),
            Some("strategy-not-cluster-authoritative")
        );
    }

    #[test]
    fn assess_cluster_metadata_readiness_requires_complete_coverage_for_request_aggregation() {
        let expected = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let responded = vec!["node-a:9000".to_string()];
        let coverage = build_cluster_metadata_coverage_from_responses(
            expected.as_slice(),
            responded.as_slice(),
        )
        .expect("coverage should build");

        let assessment = assess_cluster_metadata_readiness(
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            &coverage,
        );
        assert!(!assessment.ready);
        assert!(assessment.cluster_authoritative);
        assert_eq!(
            assessment.gap,
            Some(ClusterMetadataReadinessGap::MissingExpectedNodes)
        );
        assert_eq!(
            assessment.coverage_gap,
            Some(ClusterMetadataCoverageGap::MissingExpectedNodes)
        );
    }

    #[test]
    fn assess_cluster_metadata_readiness_requires_complete_coverage_for_consensus_index() {
        let expected = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let responded = vec!["node-a:9000".to_string()];
        let coverage = build_cluster_metadata_coverage_from_responses(
            expected.as_slice(),
            responded.as_slice(),
        )
        .expect("coverage should build");

        let assessment = assess_cluster_metadata_readiness(
            ClusterMetadataListingStrategy::ConsensusIndex,
            &coverage,
        );
        assert!(!assessment.ready);
        assert!(assessment.cluster_authoritative);
        assert_eq!(
            assessment.gap,
            Some(ClusterMetadataReadinessGap::MissingExpectedNodes)
        );
        assert_eq!(
            assessment.coverage_gap,
            Some(ClusterMetadataCoverageGap::MissingExpectedNodes)
        );
    }

    #[test]
    fn cluster_metadata_fan_in_execution_strategy_uses_request_time_aggregation_for_consensus() {
        assert_eq!(
            cluster_metadata_fan_in_execution_strategy(
                ClusterMetadataListingStrategy::ConsensusIndex
            ),
            ClusterMetadataListingStrategy::RequestTimeAggregation
        );
        assert_eq!(
            cluster_metadata_fan_in_execution_strategy(
                ClusterMetadataListingStrategy::RequestTimeAggregation
            ),
            ClusterMetadataListingStrategy::RequestTimeAggregation
        );
        assert_eq!(
            cluster_metadata_fan_in_execution_strategy(
                ClusterMetadataListingStrategy::FullReplication
            ),
            ClusterMetadataListingStrategy::FullReplication
        );
    }

    #[test]
    fn cluster_metadata_fan_in_requires_auth_token_only_for_consensus_index() {
        assert!(cluster_metadata_fan_in_requires_auth_token(
            ClusterMetadataListingStrategy::ConsensusIndex
        ));
        assert!(!cluster_metadata_fan_in_requires_auth_token(
            ClusterMetadataListingStrategy::RequestTimeAggregation
        ));
        assert!(!cluster_metadata_fan_in_requires_auth_token(
            ClusterMetadataListingStrategy::FullReplication
        ));
        assert!(!cluster_metadata_fan_in_requires_auth_token(
            ClusterMetadataListingStrategy::LocalNodeOnly
        ));
    }

    #[test]
    fn cluster_metadata_fan_in_auth_token_reject_reason_matches_consensus_contract() {
        assert_eq!(
            cluster_metadata_fan_in_auth_token_reject_reason(
                ClusterMetadataListingStrategy::ConsensusIndex,
                false,
            ),
            Some(CLUSTER_METADATA_CONSENSUS_FAN_IN_AUTH_TOKEN_MISSING_REASON)
        );
        assert_eq!(
            cluster_metadata_fan_in_auth_token_reject_reason(
                ClusterMetadataListingStrategy::ConsensusIndex,
                true,
            ),
            None
        );
        assert_eq!(
            cluster_metadata_fan_in_auth_token_reject_reason(
                ClusterMetadataListingStrategy::RequestTimeAggregation,
                false,
            ),
            None
        );
    }

    #[test]
    fn assess_cluster_metadata_fan_in_snapshot_for_consensus_uses_cluster_coverage_readiness() {
        let membership_nodes = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let responders = vec!["node-a:9000".to_string()];

        let assessment = assess_cluster_metadata_fan_in_snapshot_for_topology_responders(
            ClusterMetadataListingStrategy::ConsensusIndex,
            Some("view-a"),
            "node-a:9000",
            membership_nodes.as_slice(),
            responders.as_slice(),
        )
        .expect("fan-in snapshot should build");

        assert_eq!(
            assessment.strategy,
            ClusterMetadataListingStrategy::RequestTimeAggregation
        );
        assert_eq!(
            assessment.readiness_assessment.gap,
            Some(ClusterMetadataReadinessGap::MissingExpectedNodes)
        );
    }

    #[test]
    fn assess_cluster_metadata_fan_in_snapshot_single_responder_uses_cluster_coverage_readiness() {
        let membership_nodes = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let assessment = assess_cluster_metadata_fan_in_snapshot_for_topology_single_responder(
            ClusterMetadataListingStrategy::ConsensusIndex,
            Some("view-a"),
            "node-a:9000",
            membership_nodes.as_slice(),
            "node-a:9000",
        );

        assert_eq!(
            assessment.strategy,
            ClusterMetadataListingStrategy::RequestTimeAggregation
        );
        assert_eq!(
            assessment.readiness_assessment.gap,
            Some(ClusterMetadataReadinessGap::MissingExpectedNodes)
        );
    }

    #[test]
    fn cluster_metadata_readiness_reject_reason_ignores_non_authoritative_mode() {
        let expected = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let responded = vec!["node-a:9000".to_string()];
        let coverage = build_cluster_metadata_coverage_from_responses(
            expected.as_slice(),
            responded.as_slice(),
        )
        .expect("coverage should build");

        let readiness = assess_cluster_metadata_readiness(
            ClusterMetadataListingStrategy::LocalNodeOnly,
            &coverage,
        );
        assert_eq!(
            readiness.gap,
            Some(ClusterMetadataReadinessGap::StrategyNotClusterAuthoritative)
        );
        assert_eq!(cluster_metadata_readiness_reject_reason(&readiness), None);
    }

    #[test]
    fn cluster_metadata_readiness_reject_reason_returns_gap_for_authoritative_unready_modes() {
        let expected = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let responded = vec!["node-a:9000".to_string()];
        let coverage = build_cluster_metadata_coverage_from_responses(
            expected.as_slice(),
            responded.as_slice(),
        )
        .expect("coverage should build");

        let readiness = assess_cluster_metadata_readiness(
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            &coverage,
        );
        assert_eq!(
            cluster_metadata_readiness_reject_reason(&readiness),
            Some(ClusterMetadataReadinessGap::MissingExpectedNodes)
        );
    }

    #[test]
    fn assess_cluster_metadata_snapshot_returns_canonical_assessment_shape() {
        let expected = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let responded = vec!["node-a:9000".to_string()];
        let assessment = assess_cluster_metadata_snapshot(
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            Some(" view-a "),
            expected.as_slice(),
            responded.as_slice(),
        )
        .expect("snapshot assessment should build");

        assert_eq!(
            assessment.strategy,
            ClusterMetadataListingStrategy::RequestTimeAggregation
        );
        assert_eq!(assessment.view_id.as_deref(), Some("view-a"));
        assert_eq!(
            assessment.coverage.expected_nodes,
            vec!["node-a:9000".to_string(), "node-b:9000".to_string()]
        );
        assert_eq!(
            assessment.coverage.responded_nodes,
            vec!["node-a:9000".to_string()]
        );
        assert_eq!(
            assessment.coverage.missing_nodes,
            vec!["node-b:9000".to_string()]
        );
        assert_eq!(
            assessment.coverage_assessment.gap,
            Some(ClusterMetadataCoverageGap::MissingExpectedNodes)
        );
        assert_eq!(
            assessment.readiness_assessment.gap,
            Some(ClusterMetadataReadinessGap::MissingExpectedNodes)
        );
        assert_eq!(
            assessment.snapshot_id,
            build_cluster_metadata_snapshot_id(
                ClusterMetadataListingStrategy::RequestTimeAggregation,
                Some(" view-a "),
                &assessment.coverage
            )
        );
    }

    #[test]
    fn assess_cluster_metadata_snapshot_rejects_duplicate_expected_nodes() {
        let expected = vec!["node-a:9000".to_string(), "NODE-A:9000".to_string()];
        let responded = vec!["node-a:9000".to_string()];
        assert_eq!(
            assess_cluster_metadata_snapshot(
                ClusterMetadataListingStrategy::RequestTimeAggregation,
                Some("view-a"),
                expected.as_slice(),
                responded.as_slice(),
            )
            .expect_err("duplicate expected nodes must fail"),
            MetadataQueryError::DuplicateCoverageExpectedNode
        );
    }

    #[test]
    fn assess_cluster_metadata_snapshot_for_single_responder_uses_invalid_node_fallback() {
        let expected = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let assessment = assess_cluster_metadata_snapshot_for_single_responder(
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            Some("view-a"),
            expected.as_slice(),
            "   ",
        );
        assert_eq!(assessment.coverage.expected_nodes, expected);
        assert!(assessment.coverage.responded_nodes.is_empty());
        assert_eq!(
            assessment.coverage.missing_nodes,
            vec!["node-a:9000".to_string(), "node-b:9000".to_string()]
        );
        assert_eq!(
            assessment.readiness_assessment.gap,
            Some(ClusterMetadataReadinessGap::MissingExpectedNodes)
        );
        assert_eq!(
            assessment.coverage_assessment.gap,
            Some(ClusterMetadataCoverageGap::MissingExpectedNodes)
        );
    }

    #[test]
    fn build_cluster_metadata_snapshot_id_is_stable_for_identical_inputs() {
        let coverage = super::ClusterMetadataCoverage {
            expected_nodes: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
            responded_nodes: vec!["node-a:9000".to_string()],
            missing_nodes: vec!["node-b:9000".to_string()],
            unexpected_nodes: Vec::new(),
            complete: false,
        };

        let first = build_cluster_metadata_snapshot_id(
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            Some("view-a"),
            &coverage,
        );
        let second = build_cluster_metadata_snapshot_id(
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            Some("view-a"),
            &coverage,
        );

        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn build_cluster_metadata_snapshot_id_changes_on_strategy_view_or_coverage_change() {
        let base = super::ClusterMetadataCoverage {
            expected_nodes: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
            responded_nodes: vec!["node-a:9000".to_string()],
            missing_nodes: vec!["node-b:9000".to_string()],
            unexpected_nodes: Vec::new(),
            complete: false,
        };
        let changed_coverage = super::ClusterMetadataCoverage {
            expected_nodes: base.expected_nodes.clone(),
            responded_nodes: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
            missing_nodes: Vec::new(),
            unexpected_nodes: Vec::new(),
            complete: true,
        };

        let baseline = build_cluster_metadata_snapshot_id(
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            Some("view-a"),
            &base,
        );
        let strategy_change = build_cluster_metadata_snapshot_id(
            ClusterMetadataListingStrategy::ConsensusIndex,
            Some("view-a"),
            &base,
        );
        let view_change = build_cluster_metadata_snapshot_id(
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            Some("view-b"),
            &base,
        );
        let coverage_change = build_cluster_metadata_snapshot_id(
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            Some("view-a"),
            &changed_coverage,
        );

        assert_ne!(baseline, strategy_change);
        assert_ne!(baseline, view_change);
        assert_ne!(baseline, coverage_change);
    }

    #[test]
    fn build_cluster_metadata_snapshot_id_is_case_insensitive_for_node_id_sets() {
        let lower_case = super::ClusterMetadataCoverage {
            expected_nodes: vec!["node-a:9000".to_string(), "node-b:9000".to_string()],
            responded_nodes: vec!["node-a:9000".to_string()],
            missing_nodes: vec!["node-b:9000".to_string()],
            unexpected_nodes: Vec::new(),
            complete: false,
        };
        let mixed_case = super::ClusterMetadataCoverage {
            expected_nodes: vec!["Node-A:9000".to_string(), "NODE-b:9000".to_string()],
            responded_nodes: vec!["node-A:9000".to_string()],
            missing_nodes: vec!["node-B:9000".to_string()],
            unexpected_nodes: Vec::new(),
            complete: false,
        };

        let lower_snapshot = build_cluster_metadata_snapshot_id(
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            Some("view-a"),
            &lower_case,
        );
        let mixed_snapshot = build_cluster_metadata_snapshot_id(
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            Some("view-a"),
            &mixed_case,
        );

        assert_eq!(lower_snapshot, mixed_snapshot);
    }

    #[test]
    fn metadata_listing_strategy_labels_are_stable() {
        assert_eq!(
            ClusterMetadataListingStrategy::LocalNodeOnly.as_str(),
            "local-node-only"
        );
        assert_eq!(
            ClusterMetadataListingStrategy::RequestTimeAggregation.as_str(),
            "request-time-aggregation"
        );
        assert_eq!(
            ClusterMetadataListingStrategy::ConsensusIndex.as_str(),
            "consensus-index"
        );
        assert_eq!(
            ClusterMetadataListingStrategy::FullReplication.as_str(),
            "full-replication"
        );
    }

    #[test]
    fn assess_cluster_bucket_metadata_convergence_reports_ready_for_consistent_snapshot() {
        let membership = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let responders = vec![
            ClusterBucketMetadataResponderSnapshot {
                node_id: "node-a:9000".to_string(),
                state: ClusterBucketMetadataResponderState::Present(true),
            },
            ClusterBucketMetadataResponderSnapshot {
                node_id: "node-b:9000".to_string(),
                state: ClusterBucketMetadataResponderState::Present(true),
            },
        ];
        let assessment = assess_cluster_bucket_metadata_convergence(
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            Some("view-a"),
            "node-a:9000",
            membership.as_slice(),
            responders.as_slice(),
        )
        .expect("convergence assessment should build");

        assert!(assessment.ready);
        assert!(assessment.snapshot.readiness_assessment.ready);
        assert!(assessment.consistency.consistent);
        assert_eq!(assessment.gap, None);
    }

    #[test]
    fn assess_cluster_bucket_metadata_convergence_surfaces_snapshot_coverage_gap() {
        let membership = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let responders = vec![ClusterBucketMetadataResponderSnapshot {
            node_id: "node-a:9000".to_string(),
            state: ClusterBucketMetadataResponderState::Present(true),
        }];
        let assessment = assess_cluster_bucket_metadata_convergence(
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            Some("view-a"),
            "node-a:9000",
            membership.as_slice(),
            responders.as_slice(),
        )
        .expect("convergence assessment should build");

        assert!(!assessment.ready);
        assert_eq!(
            assessment.gap,
            Some(ClusterBucketMetadataConvergenceGap::MissingExpectedNodes)
        );
    }

    #[test]
    fn assess_cluster_bucket_metadata_convergence_surfaces_missing_bucket_gap() {
        let membership = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let responders = vec![
            ClusterBucketMetadataResponderSnapshot {
                node_id: "node-a:9000".to_string(),
                state: ClusterBucketMetadataResponderState::Present(true),
            },
            ClusterBucketMetadataResponderSnapshot {
                node_id: "node-b:9000".to_string(),
                state: ClusterBucketMetadataResponderState::MissingBucket,
            },
        ];
        let assessment = assess_cluster_bucket_metadata_convergence(
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            Some("view-a"),
            "node-a:9000",
            membership.as_slice(),
            responders.as_slice(),
        )
        .expect("convergence assessment should build");

        assert!(!assessment.ready);
        assert_eq!(
            assessment.gap,
            Some(ClusterBucketMetadataConvergenceGap::MissingBucketOnResponder)
        );
    }

    #[test]
    fn assess_cluster_bucket_metadata_convergence_surfaces_inconsistent_value_gap() {
        let membership = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let responders = vec![
            ClusterBucketMetadataResponderSnapshot {
                node_id: "node-a:9000".to_string(),
                state: ClusterBucketMetadataResponderState::Present(true),
            },
            ClusterBucketMetadataResponderSnapshot {
                node_id: "node-b:9000".to_string(),
                state: ClusterBucketMetadataResponderState::Present(false),
            },
        ];
        let assessment = assess_cluster_bucket_metadata_convergence(
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            Some("view-a"),
            "node-a:9000",
            membership.as_slice(),
            responders.as_slice(),
        )
        .expect("convergence assessment should build");

        assert!(!assessment.ready);
        assert_eq!(
            assessment.gap,
            Some(ClusterBucketMetadataConvergenceGap::InconsistentResponderValues)
        );
    }

    #[test]
    fn assess_cluster_bucket_metadata_convergence_surfaces_strategy_gap() {
        let membership = vec!["node-a:9000".to_string()];
        let responders = vec![ClusterBucketMetadataResponderSnapshot {
            node_id: "node-a:9000".to_string(),
            state: ClusterBucketMetadataResponderState::Present(true),
        }];
        let assessment = assess_cluster_bucket_metadata_convergence(
            ClusterMetadataListingStrategy::LocalNodeOnly,
            Some("view-a"),
            "node-a:9000",
            membership.as_slice(),
            responders.as_slice(),
        )
        .expect("convergence assessment should build");

        assert!(!assessment.ready);
        assert_eq!(
            assessment.gap,
            Some(ClusterBucketMetadataConvergenceGap::StrategyNotClusterAuthoritative)
        );
    }

    #[test]
    fn assess_cluster_bucket_metadata_convergence_for_responder_states_reports_ready_snapshot() {
        let membership = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let responded_nodes = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let states = vec![
            ClusterBucketMetadataResponderState::Present(true),
            ClusterBucketMetadataResponderState::Present(true),
        ];
        let assessment = assess_cluster_bucket_metadata_convergence_for_responder_states(
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            Some("view-a"),
            "node-a:9000",
            membership.as_slice(),
            responded_nodes.as_slice(),
            states.as_slice(),
        )
        .expect("convergence assessment should build");

        assert!(assessment.ready);
        assert_eq!(assessment.gap, None);
        assert_eq!(assessment.consistency.value, Some(true));
    }

    #[test]
    fn assess_cluster_bucket_metadata_convergence_for_responder_states_rejects_cardinality_mismatch()
     {
        let membership = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let responded_nodes = vec!["node-a:9000".to_string()];
        let states = vec![
            ClusterBucketMetadataResponderState::Present(true),
            ClusterBucketMetadataResponderState::Present(true),
        ];
        let error = assess_cluster_bucket_metadata_convergence_for_responder_states(
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            Some("view-a"),
            "node-a:9000",
            membership.as_slice(),
            responded_nodes.as_slice(),
            states.as_slice(),
        )
        .expect_err("cardinality mismatch should fail");

        assert_eq!(
            error,
            ClusterBucketMetadataConvergenceInputError::ResponderStateCardinalityMismatch
        );
    }

    #[test]
    fn assess_cluster_bucket_metadata_convergence_for_responder_states_surfaces_topology_errors() {
        let membership = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let responded_nodes = vec!["node-a:9000".to_string(), "node-a:9000".to_string()];
        let states = vec![
            ClusterBucketMetadataResponderState::Present(true),
            ClusterBucketMetadataResponderState::Present(true),
        ];
        let error = assess_cluster_bucket_metadata_convergence_for_responder_states(
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            Some("view-a"),
            "node-a:9000",
            membership.as_slice(),
            responded_nodes.as_slice(),
            states.as_slice(),
        )
        .expect_err("duplicate responders should fail");

        assert_eq!(
            error,
            ClusterBucketMetadataConvergenceInputError::InvalidResponderTopology(
                MetadataQueryError::DuplicateCoverageNodeResponse
            )
        );
    }

    #[test]
    fn assess_cluster_bucket_metadata_mutation_preconditions_reports_ready_with_current_value() {
        let membership = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let responders = vec![
            ClusterBucketMetadataResponderSnapshot {
                node_id: "node-a:9000".to_string(),
                state: ClusterBucketMetadataResponderState::Present(true),
            },
            ClusterBucketMetadataResponderSnapshot {
                node_id: "node-b:9000".to_string(),
                state: ClusterBucketMetadataResponderState::Present(true),
            },
        ];
        let assessment = assess_cluster_bucket_metadata_mutation_preconditions(
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            Some("view-a"),
            "node-a:9000",
            membership.as_slice(),
            responders.as_slice(),
        )
        .expect("mutation preconditions should build");

        assert!(assessment.ready);
        assert_eq!(assessment.current_value, Some(true));
        assert_eq!(assessment.gap, None);
    }

    #[test]
    fn assess_cluster_bucket_metadata_mutation_preconditions_reports_bucket_missing_when_all_missing()
     {
        let membership = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let responders: Vec<ClusterBucketMetadataResponderSnapshot<bool>> = vec![
            ClusterBucketMetadataResponderSnapshot {
                node_id: "node-a:9000".to_string(),
                state: ClusterBucketMetadataResponderState::MissingBucket,
            },
            ClusterBucketMetadataResponderSnapshot {
                node_id: "node-b:9000".to_string(),
                state: ClusterBucketMetadataResponderState::MissingBucket,
            },
        ];
        let assessment = assess_cluster_bucket_metadata_mutation_preconditions(
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            Some("view-a"),
            "node-a:9000",
            membership.as_slice(),
            responders.as_slice(),
        )
        .expect("mutation preconditions should build");

        assert!(!assessment.ready);
        assert_eq!(assessment.current_value, None);
        assert_eq!(
            assessment.gap,
            Some(ClusterBucketMetadataMutationPreconditionGap::BucketMissing)
        );
    }

    #[test]
    fn assess_cluster_bucket_metadata_mutation_preconditions_reports_partial_missing_gap() {
        let membership = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let responders = vec![
            ClusterBucketMetadataResponderSnapshot {
                node_id: "node-a:9000".to_string(),
                state: ClusterBucketMetadataResponderState::Present(true),
            },
            ClusterBucketMetadataResponderSnapshot {
                node_id: "node-b:9000".to_string(),
                state: ClusterBucketMetadataResponderState::MissingBucket,
            },
        ];
        let assessment = assess_cluster_bucket_metadata_mutation_preconditions(
            ClusterMetadataListingStrategy::RequestTimeAggregation,
            Some("view-a"),
            "node-a:9000",
            membership.as_slice(),
            responders.as_slice(),
        )
        .expect("mutation preconditions should build");

        assert!(!assessment.ready);
        assert_eq!(assessment.current_value, None);
        assert_eq!(
            assessment.gap,
            Some(ClusterBucketMetadataMutationPreconditionGap::MissingBucketOnResponder)
        );
    }

    #[test]
    fn assess_cluster_responder_membership_views_reports_consistent_expected_view() {
        let responders = vec![
            ClusterResponderMembershipView {
                node_id: "node-a:9000".to_string(),
                membership_view_id: Some("view-1".to_string()),
            },
            ClusterResponderMembershipView {
                node_id: "node-b:9000".to_string(),
                membership_view_id: Some("view-1".to_string()),
            },
        ];
        let assessment =
            assess_cluster_responder_membership_views(Some("view-1"), responders.as_slice());

        assert!(assessment.consistent);
        assert_eq!(assessment.gap, None);
        assert_eq!(assessment.observed_view_id.as_deref(), Some("view-1"));
        assert!(assessment.missing_nodes.is_empty());
        assert!(assessment.mismatched_nodes.is_empty());
    }

    #[test]
    fn assess_cluster_responder_membership_views_reports_missing_view_gap() {
        let responders = vec![
            ClusterResponderMembershipView {
                node_id: "node-a:9000".to_string(),
                membership_view_id: Some("view-1".to_string()),
            },
            ClusterResponderMembershipView {
                node_id: "node-b:9000".to_string(),
                membership_view_id: None,
            },
        ];
        let assessment =
            assess_cluster_responder_membership_views(Some("view-1"), responders.as_slice());

        assert!(!assessment.consistent);
        assert_eq!(
            assessment.gap,
            Some(ClusterResponderMembershipViewGap::MissingResponderMembershipViewId)
        );
        assert_eq!(assessment.missing_nodes, vec!["node-b:9000".to_string()]);
    }

    #[test]
    fn assess_cluster_responder_membership_views_reports_inconsistent_responder_views() {
        let responders = vec![
            ClusterResponderMembershipView {
                node_id: "node-a:9000".to_string(),
                membership_view_id: Some("view-1".to_string()),
            },
            ClusterResponderMembershipView {
                node_id: "node-b:9000".to_string(),
                membership_view_id: Some("view-2".to_string()),
            },
        ];
        let assessment = assess_cluster_responder_membership_views(None, responders.as_slice());

        assert!(!assessment.consistent);
        assert_eq!(
            assessment.gap,
            Some(ClusterResponderMembershipViewGap::InconsistentResponderMembershipViewId)
        );
        assert_eq!(assessment.observed_view_id, None);
    }

    #[test]
    fn assess_cluster_responder_membership_views_reports_expected_view_mismatch() {
        let responders = vec![
            ClusterResponderMembershipView {
                node_id: "node-a:9000".to_string(),
                membership_view_id: Some("view-2".to_string()),
            },
            ClusterResponderMembershipView {
                node_id: "node-b:9000".to_string(),
                membership_view_id: Some("view-2".to_string()),
            },
        ];
        let assessment =
            assess_cluster_responder_membership_views(Some("view-1"), responders.as_slice());

        assert!(!assessment.consistent);
        assert_eq!(
            assessment.gap,
            Some(ClusterResponderMembershipViewGap::MembershipViewIdMismatch)
        );
        assert_eq!(
            assessment.mismatched_nodes,
            vec!["node-a:9000".to_string(), "node-b:9000".to_string()]
        );
    }

    #[test]
    fn assess_cluster_metadata_fan_in_preflight_is_ready_when_snapshot_and_views_align() {
        let membership = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let responders = vec![
            ClusterResponderMembershipView {
                node_id: "node-a:9000".to_string(),
                membership_view_id: Some("view-1".to_string()),
            },
            ClusterResponderMembershipView {
                node_id: "node-b:9000".to_string(),
                membership_view_id: Some("view-1".to_string()),
            },
        ];

        let assessment = assess_cluster_metadata_fan_in_preflight_for_topology_responders(
            ClusterMetadataListingStrategy::ConsensusIndex,
            Some("view-1"),
            "node-a:9000",
            membership.as_slice(),
            responders.as_slice(),
        )
        .expect("preflight should build");

        assert!(assessment.ready);
        assert_eq!(assessment.gap, None);
        assert_eq!(
            cluster_metadata_fan_in_preflight_reject_reason(&assessment),
            None
        );
        assert!(assessment.responder_membership_views.consistent);
    }

    #[test]
    fn assess_cluster_metadata_fan_in_preflight_prioritizes_snapshot_readiness_gap() {
        let membership = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let responders = vec![ClusterResponderMembershipView {
            node_id: "node-a:9000".to_string(),
            membership_view_id: Some("stale-view".to_string()),
        }];

        let assessment = assess_cluster_metadata_fan_in_preflight_for_topology_responders(
            ClusterMetadataListingStrategy::ConsensusIndex,
            Some("view-1"),
            "node-a:9000",
            membership.as_slice(),
            responders.as_slice(),
        )
        .expect("preflight should build");

        assert!(!assessment.ready);
        assert_eq!(
            assessment.gap,
            Some(ClusterMetadataFanInPreflightGap::MissingExpectedNodes)
        );
        assert_eq!(
            cluster_metadata_fan_in_preflight_reject_reason(&assessment),
            Some(ClusterMetadataFanInPreflightGap::MissingExpectedNodes)
        );
    }

    #[test]
    fn assess_cluster_metadata_fan_in_preflight_reports_membership_view_mismatch_gap() {
        let membership = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let responders = vec![
            ClusterResponderMembershipView {
                node_id: "node-a:9000".to_string(),
                membership_view_id: Some("view-2".to_string()),
            },
            ClusterResponderMembershipView {
                node_id: "node-b:9000".to_string(),
                membership_view_id: Some("view-2".to_string()),
            },
        ];

        let assessment = assess_cluster_metadata_fan_in_preflight_for_topology_responders(
            ClusterMetadataListingStrategy::ConsensusIndex,
            Some("view-1"),
            "node-a:9000",
            membership.as_slice(),
            responders.as_slice(),
        )
        .expect("preflight should build");

        assert!(!assessment.ready);
        assert_eq!(
            assessment.gap,
            Some(ClusterMetadataFanInPreflightGap::MembershipViewIdMismatch)
        );
        assert_eq!(
            cluster_metadata_fan_in_preflight_reject_reason(&assessment),
            Some(ClusterMetadataFanInPreflightGap::MembershipViewIdMismatch)
        );
        assert_eq!(
            assessment.responder_membership_views.mismatched_nodes,
            vec!["node-a:9000".to_string(), "node-b:9000".to_string()]
        );
    }

    #[test]
    fn assess_cluster_metadata_fan_in_preflight_reports_missing_responder_view_gap() {
        let membership = vec!["node-a:9000".to_string(), "node-b:9000".to_string()];
        let responders = vec![
            ClusterResponderMembershipView {
                node_id: "node-a:9000".to_string(),
                membership_view_id: Some("view-1".to_string()),
            },
            ClusterResponderMembershipView {
                node_id: "node-b:9000".to_string(),
                membership_view_id: None,
            },
        ];

        let assessment = assess_cluster_metadata_fan_in_preflight_for_topology_responders(
            ClusterMetadataListingStrategy::ConsensusIndex,
            Some("view-1"),
            "node-a:9000",
            membership.as_slice(),
            responders.as_slice(),
        )
        .expect("preflight should build");

        assert!(!assessment.ready);
        assert_eq!(
            assessment.gap,
            Some(ClusterMetadataFanInPreflightGap::MissingResponderMembershipViewId)
        );
    }

    #[test]
    fn assess_cluster_metadata_fan_in_preflight_single_responder_is_ready_when_snapshot_and_view_align()
     {
        let membership = vec!["node-a:9000".to_string()];

        let assessment = assess_cluster_metadata_fan_in_preflight_for_topology_single_responder(
            ClusterMetadataListingStrategy::ConsensusIndex,
            Some("view-1"),
            "node-a:9000",
            membership.as_slice(),
            "node-a:9000",
            Some("view-1"),
        );

        assert!(assessment.ready);
        assert_eq!(assessment.gap, None);
        assert!(assessment.responder_membership_views.consistent);
        assert_eq!(
            cluster_metadata_fan_in_preflight_reject_reason(&assessment),
            None
        );
    }

    #[test]
    fn assess_cluster_metadata_fan_in_preflight_single_responder_reports_membership_mismatch_gap() {
        let membership = vec!["node-a:9000".to_string()];

        let assessment = assess_cluster_metadata_fan_in_preflight_for_topology_single_responder(
            ClusterMetadataListingStrategy::ConsensusIndex,
            Some("view-1"),
            "node-a:9000",
            membership.as_slice(),
            "node-a:9000",
            Some("view-2"),
        );

        assert!(!assessment.ready);
        assert_eq!(
            assessment.gap,
            Some(ClusterMetadataFanInPreflightGap::MembershipViewIdMismatch)
        );
        assert_eq!(
            cluster_metadata_fan_in_preflight_reject_reason(&assessment),
            Some(ClusterMetadataFanInPreflightGap::MembershipViewIdMismatch)
        );
    }
}
