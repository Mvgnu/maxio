use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::index::{
    InMemoryMetadataIndex, MetadataIndex, MetadataListPage, MetadataQuery, MetadataQueryError,
    MetadataVersionsPage, MetadataVersionsQuery,
};
use super::state::{
    BucketMetadataOperation, BucketMetadataOperationError, BucketMetadataOperationOutcome,
    BucketMetadataState, BucketMetadataTombstoneState, ObjectMetadataOperation,
    ObjectMetadataOperationError, ObjectMetadataOperationOutcome, ObjectMetadataState,
    ObjectVersionMetadataOperation, ObjectVersionMetadataOperationError,
    ObjectVersionMetadataOperationOutcome, ObjectVersionMetadataState,
    apply_bucket_metadata_operation, apply_object_metadata_operation,
    apply_object_version_metadata_operation,
};

mod persisted_state;
mod queue;
pub use persisted_state::*;
pub use queue::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetadataReconcileAction {
    UpsertBucket {
        bucket: String,
        #[serde(default)]
        versioning_enabled: bool,
        #[serde(default)]
        lifecycle_enabled: bool,
    },
    DeleteBucket {
        bucket: String,
    },
    UpsertBucketTombstone {
        bucket: String,
        deleted_at_unix_ms: u64,
        retain_until_unix_ms: u64,
    },
    DeleteBucketTombstone {
        bucket: String,
    },
    UpsertObject {
        bucket: String,
        key: String,
        version_id: Option<String>,
    },
    TombstoneObject {
        bucket: String,
        key: String,
        version_id: Option<String>,
    },
    UpsertObjectVersion {
        bucket: String,
        key: String,
        version_id: String,
        is_delete_marker: bool,
        is_latest: bool,
    },
    DeleteObjectVersion {
        bucket: String,
        key: String,
        version_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MetadataRepairPlan {
    pub source_view_id: String,
    pub target_view_id: String,
    pub actions: Vec<MetadataReconcileAction>,
}

impl MetadataRepairPlan {
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingMetadataRepairPlan {
    pub repair_id: String,
    pub created_at_unix_ms: u64,
    pub attempts: u32,
    pub next_retry_at_unix_ms: Option<u64>,
    pub last_error: Option<String>,
    pub plan: MetadataRepairPlan,
}

impl PendingMetadataRepairPlan {
    pub fn new(repair_id: &str, created_at_unix_ms: u64, plan: MetadataRepairPlan) -> Option<Self> {
        let repair_id = repair_id.trim();
        if repair_id.is_empty()
            || plan.source_view_id.trim().is_empty()
            || plan.target_view_id.trim().is_empty()
        {
            return None;
        }
        if plan.actions.is_empty() {
            return None;
        }
        Some(Self {
            repair_id: repair_id.to_string(),
            created_at_unix_ms,
            attempts: 0,
            next_retry_at_unix_ms: None,
            last_error: None,
            plan,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PendingMetadataRepairQueue {
    pub plans: Vec<PendingMetadataRepairPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingMetadataRepairEnqueueOutcome {
    Inserted,
    AlreadyTracked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingMetadataRepairAcknowledgeOutcome {
    NotFound,
    Acknowledged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingMetadataRepairFailureOutcome {
    NotFound,
    Updated { attempts: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingMetadataRepairLeaseOutcome {
    NotFound,
    NotDue {
        next_retry_at_unix_ms: u64,
    },
    Updated {
        attempts: u32,
        lease_expires_at_unix_ms: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingMetadataRepairFailureWithBackoffOutcome {
    NotFound,
    Updated {
        attempts: u32,
        next_retry_at_unix_ms: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingMetadataRepairCandidate {
    pub repair_id: String,
    pub source_view_id: String,
    pub target_view_id: String,
    pub attempts: u32,
    pub created_at_unix_ms: u64,
    pub next_retry_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PendingMetadataRepairQueueSummary {
    pub plans: usize,
    pub due_plans: usize,
    pub failed_plans: usize,
    pub max_attempts: u32,
    pub oldest_created_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PendingMetadataRepairReplayCycleOutcome {
    pub scanned_plans: usize,
    pub leased_plans: usize,
    pub acknowledged_plans: usize,
    pub failed_plans: usize,
    pub dropped_plans: usize,
    pub skipped_plans: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingMetadataRepairApplyFailure {
    Transient(String),
    Permanent(String),
}

impl PendingMetadataRepairApplyFailure {
    pub fn transient(error: impl Into<String>) -> Self {
        Self::Transient(error.into())
    }

    pub fn permanent(error: impl Into<String>) -> Self {
        Self::Permanent(error.into())
    }

    pub fn message(&self) -> Option<&str> {
        match self {
            Self::Transient(error) | Self::Permanent(error) => {
                let value = error.trim();
                if value.is_empty() { None } else { Some(value) }
            }
        }
    }

    pub fn is_permanent(&self) -> bool {
        matches!(self, Self::Permanent(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MetadataRepairPlanSummary {
    pub total_actions: usize,
    pub upsert_buckets: usize,
    pub delete_buckets: usize,
    pub upsert_bucket_tombstones: usize,
    pub delete_bucket_tombstones: usize,
    pub upsert_objects: usize,
    pub tombstone_objects: usize,
    pub upsert_object_versions: usize,
    pub delete_object_versions: usize,
    pub destructive_actions: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MetadataRepairExecutionOutput {
    pub buckets: Vec<BucketMetadataState>,
    pub bucket_tombstones: Vec<BucketMetadataTombstoneState>,
    pub objects: Vec<ObjectMetadataState>,
    pub object_versions: Vec<ObjectVersionMetadataState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PersistedMetadataState {
    pub view_id: String,
    pub buckets: Vec<BucketMetadataState>,
    pub bucket_tombstones: Vec<BucketMetadataTombstoneState>,
    pub objects: Vec<ObjectMetadataState>,
    pub object_versions: Vec<ObjectVersionMetadataState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistedMetadataQueryableStateError {
    DuplicateBucketState {
        bucket: String,
    },
    DuplicateBucketTombstoneState {
        bucket: String,
    },
    BucketTombstoneConflict {
        bucket: String,
    },
    DuplicateObjectState {
        bucket: String,
        key: String,
    },
    OrphanObjectState {
        bucket: String,
        key: String,
    },
    DuplicateObjectVersionState {
        bucket: String,
        key: String,
        version_id: String,
    },
    OrphanObjectVersionState {
        bucket: String,
        key: String,
        version_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistedMetadataQueryError {
    InvalidPersistedState(PersistedMetadataQueryableStateError),
    ViewIdMismatch {
        expected_view_id: String,
        persisted_view_id: String,
    },
    InvalidQuery(MetadataQueryError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistedBucketMetadataReadResolution {
    Present(BucketMetadataState),
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistedBucketPresenceReadResolution {
    Present(BucketMetadataState),
    Tombstoned(BucketMetadataTombstoneState),
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistedBucketMutationPreconditionResolution {
    Present(BucketMetadataState),
    Tombstoned {
        tombstone: BucketMetadataTombstoneState,
        retention_active: bool,
    },
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistedObjectMetadataReadResolution {
    Present(ObjectMetadataState),
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistedObjectVersionMetadataReadResolution {
    Present(ObjectVersionMetadataState),
    Missing,
}

#[derive(Debug)]
pub enum PendingMetadataRepairApplyError {
    StateLoad(std::io::Error),
    StatePersist(std::io::Error),
    Execution(MetadataRepairExecutionError),
}

impl std::fmt::Display for PendingMetadataRepairApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StateLoad(error) => {
                write!(f, "failed to load persisted metadata state: {error}")
            }
            Self::StatePersist(error) => {
                write!(f, "failed to persist metadata state: {error}")
            }
            Self::Execution(error) => {
                write!(f, "failed to apply metadata repair plan: {error:?}")
            }
        }
    }
}

impl std::error::Error for PendingMetadataRepairApplyError {}

#[derive(Debug)]
pub enum PersistedBucketMetadataOperationError {
    InvalidExpectedViewId,
    StateLoad(std::io::Error),
    StatePersist(std::io::Error),
    ViewIdMismatch {
        expected_view_id: String,
        persisted_view_id: String,
    },
    InvalidPersistedState(PersistedMetadataQueryableStateError),
    Operation(BucketMetadataOperationError),
}

impl std::fmt::Display for PersistedBucketMetadataOperationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidExpectedViewId => {
                write!(f, "expected metadata view id must not be empty")
            }
            Self::StateLoad(error) => {
                write!(f, "failed to load persisted metadata state: {error}")
            }
            Self::StatePersist(error) => {
                write!(f, "failed to persist metadata state: {error}")
            }
            Self::ViewIdMismatch {
                expected_view_id,
                persisted_view_id,
            } => write!(
                f,
                "persisted metadata view id mismatch: expected='{expected_view_id}', persisted='{persisted_view_id}'",
            ),
            Self::InvalidPersistedState(error) => {
                write!(f, "persisted metadata state is not queryable: {error:?}")
            }
            Self::Operation(error) => {
                write!(f, "bucket metadata operation failed: {}", error.as_str())
            }
        }
    }
}

impl std::error::Error for PersistedBucketMetadataOperationError {}

#[derive(Debug)]
pub enum PersistedObjectMetadataOperationError {
    InvalidExpectedViewId,
    StateLoad(std::io::Error),
    StatePersist(std::io::Error),
    ViewIdMismatch {
        expected_view_id: String,
        persisted_view_id: String,
    },
    InvalidPersistedState(PersistedMetadataQueryableStateError),
    Operation(ObjectMetadataOperationError),
}

impl std::fmt::Display for PersistedObjectMetadataOperationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidExpectedViewId => {
                write!(f, "expected metadata view id must not be empty")
            }
            Self::StateLoad(error) => {
                write!(f, "failed to load persisted metadata state: {error}")
            }
            Self::StatePersist(error) => {
                write!(f, "failed to persist metadata state: {error}")
            }
            Self::ViewIdMismatch {
                expected_view_id,
                persisted_view_id,
            } => write!(
                f,
                "persisted metadata view id mismatch: expected='{expected_view_id}', persisted='{persisted_view_id}'",
            ),
            Self::InvalidPersistedState(error) => {
                write!(f, "persisted metadata state is not queryable: {error:?}")
            }
            Self::Operation(error) => {
                write!(f, "object metadata operation failed: {}", error.as_str())
            }
        }
    }
}

impl std::error::Error for PersistedObjectMetadataOperationError {}

#[derive(Debug)]
pub enum PersistedObjectVersionMetadataOperationError {
    InvalidExpectedViewId,
    StateLoad(std::io::Error),
    StatePersist(std::io::Error),
    ViewIdMismatch {
        expected_view_id: String,
        persisted_view_id: String,
    },
    InvalidPersistedState(PersistedMetadataQueryableStateError),
    Operation(ObjectVersionMetadataOperationError),
}

impl std::fmt::Display for PersistedObjectVersionMetadataOperationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidExpectedViewId => {
                write!(f, "expected metadata view id must not be empty")
            }
            Self::StateLoad(error) => {
                write!(f, "failed to load persisted metadata state: {error}")
            }
            Self::StatePersist(error) => {
                write!(f, "failed to persist metadata state: {error}")
            }
            Self::ViewIdMismatch {
                expected_view_id,
                persisted_view_id,
            } => write!(
                f,
                "persisted metadata view id mismatch: expected='{expected_view_id}', persisted='{persisted_view_id}'",
            ),
            Self::InvalidPersistedState(error) => {
                write!(f, "persisted metadata state is not queryable: {error:?}")
            }
            Self::Operation(error) => {
                write!(
                    f,
                    "object-version metadata operation failed: {}",
                    error.as_str()
                )
            }
        }
    }
}

impl std::error::Error for PersistedObjectVersionMetadataOperationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataRepairPlanValidationError {
    ConflictingBucketAction {
        bucket: String,
    },
    ConflictingBucketTombstoneAction {
        bucket: String,
    },
    ConflictingObjectAction {
        bucket: String,
        key: String,
    },
    ConflictingObjectVersionAction {
        bucket: String,
        key: String,
        version_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataRepairExecutionError {
    SourceViewMismatch {
        expected_source_view_id: String,
        plan_source_view_id: String,
    },
    TargetViewMismatch {
        expected_target_view_id: String,
        plan_target_view_id: String,
    },
    MissingSourceBucket {
        bucket: String,
    },
    SourceContainsBucketForDelete {
        bucket: String,
    },
    MissingSourceBucketTombstone {
        bucket: String,
    },
    SourceContainsBucketTombstoneForDelete {
        bucket: String,
    },
    MissingSourceObject {
        bucket: String,
        key: String,
    },
    MissingSourceObjectVersion {
        bucket: String,
        key: String,
        version_id: String,
    },
    SourceContainsObjectVersionForDelete {
        bucket: String,
        key: String,
        version_id: String,
    },
    InvalidSourceObjectStateForUpsert {
        bucket: String,
        key: String,
    },
    InvalidSourceObjectStateForTombstone {
        bucket: String,
        key: String,
    },
    MissingTargetObjectForTombstone {
        bucket: String,
        key: String,
    },
    InvalidPlan {
        reason: MetadataRepairPlanValidationError,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct MetadataRepairInputs<'a> {
    pub source_buckets: &'a [BucketMetadataState],
    pub target_buckets: &'a [BucketMetadataState],
    pub source_bucket_tombstones: &'a [BucketMetadataTombstoneState],
    pub target_bucket_tombstones: &'a [BucketMetadataTombstoneState],
    pub source_objects: &'a [ObjectMetadataState],
    pub target_objects: &'a [ObjectMetadataState],
    pub source_object_versions: &'a [ObjectVersionMetadataState],
    pub target_object_versions: &'a [ObjectVersionMetadataState],
}

pub fn validate_metadata_repair_plan(
    plan: &MetadataRepairPlan,
) -> Result<(), MetadataRepairPlanValidationError> {
    let mut bucket_actions = BTreeSet::new();
    let mut bucket_tombstone_actions = BTreeSet::new();
    let mut object_actions = BTreeSet::new();
    let mut object_version_actions = BTreeSet::new();

    for action in &plan.actions {
        match action {
            MetadataReconcileAction::UpsertBucket { bucket, .. }
            | MetadataReconcileAction::DeleteBucket { bucket } => {
                if !bucket_actions.insert(bucket.clone()) {
                    return Err(MetadataRepairPlanValidationError::ConflictingBucketAction {
                        bucket: bucket.clone(),
                    });
                }
            }
            MetadataReconcileAction::UpsertBucketTombstone { bucket, .. }
            | MetadataReconcileAction::DeleteBucketTombstone { bucket } => {
                if !bucket_tombstone_actions.insert(bucket.clone()) {
                    return Err(
                        MetadataRepairPlanValidationError::ConflictingBucketTombstoneAction {
                            bucket: bucket.clone(),
                        },
                    );
                }
            }
            MetadataReconcileAction::UpsertObject { bucket, key, .. }
            | MetadataReconcileAction::TombstoneObject { bucket, key, .. } => {
                let identity = (bucket.clone(), key.clone());
                if !object_actions.insert(identity.clone()) {
                    return Err(MetadataRepairPlanValidationError::ConflictingObjectAction {
                        bucket: identity.0,
                        key: identity.1,
                    });
                }
            }
            MetadataReconcileAction::UpsertObjectVersion {
                bucket,
                key,
                version_id,
                ..
            }
            | MetadataReconcileAction::DeleteObjectVersion {
                bucket,
                key,
                version_id,
            } => {
                let identity = (bucket.clone(), key.clone(), version_id.clone());
                if !object_version_actions.insert(identity.clone()) {
                    return Err(
                        MetadataRepairPlanValidationError::ConflictingObjectVersionAction {
                            bucket: identity.0,
                            key: identity.1,
                            version_id: identity.2,
                        },
                    );
                }
            }
        }
    }

    Ok(())
}

pub fn build_metadata_repair_plan(
    source_view_id: &str,
    target_view_id: &str,
    inputs: MetadataRepairInputs<'_>,
) -> MetadataRepairPlan {
    let mut actions = Vec::new();

    let source_bucket_map: BTreeMap<&str, &BucketMetadataState> = inputs
        .source_buckets
        .iter()
        .map(|bucket| (bucket.bucket.as_str(), bucket))
        .collect();
    let target_bucket_map: BTreeMap<&str, &BucketMetadataState> = inputs
        .target_buckets
        .iter()
        .map(|bucket| (bucket.bucket.as_str(), bucket))
        .collect();

    for (bucket_name, source_bucket) in &source_bucket_map {
        let needs_upsert = target_bucket_map
            .get(bucket_name)
            .map(|target_bucket| *target_bucket != *source_bucket)
            .unwrap_or(true);
        if needs_upsert {
            actions.push(MetadataReconcileAction::UpsertBucket {
                bucket: (*bucket_name).to_string(),
                versioning_enabled: source_bucket.versioning_enabled,
                lifecycle_enabled: source_bucket.lifecycle_enabled,
            });
        }
    }

    for bucket_name in target_bucket_map.keys() {
        if source_bucket_map.contains_key(bucket_name) {
            continue;
        }
        actions.push(MetadataReconcileAction::DeleteBucket {
            bucket: (*bucket_name).to_string(),
        });
    }

    let source_tombstone_map: BTreeMap<&str, &BucketMetadataTombstoneState> = inputs
        .source_bucket_tombstones
        .iter()
        .map(|tombstone| (tombstone.bucket.as_str(), tombstone))
        .collect();
    let target_tombstone_map: BTreeMap<&str, &BucketMetadataTombstoneState> = inputs
        .target_bucket_tombstones
        .iter()
        .map(|tombstone| (tombstone.bucket.as_str(), tombstone))
        .collect();

    for (bucket_name, source_tombstone) in &source_tombstone_map {
        let needs_upsert = target_tombstone_map
            .get(bucket_name)
            .map(|target_tombstone| *target_tombstone != *source_tombstone)
            .unwrap_or(true);
        if needs_upsert {
            actions.push(MetadataReconcileAction::UpsertBucketTombstone {
                bucket: (*bucket_name).to_string(),
                deleted_at_unix_ms: source_tombstone.deleted_at_unix_ms,
                retain_until_unix_ms: source_tombstone.retain_until_unix_ms,
            });
        }
    }

    for bucket_name in target_tombstone_map.keys() {
        if source_tombstone_map.contains_key(bucket_name) {
            continue;
        }
        actions.push(MetadataReconcileAction::DeleteBucketTombstone {
            bucket: (*bucket_name).to_string(),
        });
    }

    let source_object_map: BTreeMap<(&str, &str), &ObjectMetadataState> = inputs
        .source_objects
        .iter()
        .map(|object| ((object.bucket.as_str(), object.key.as_str()), object))
        .collect();
    let target_object_map: BTreeMap<(&str, &str), &ObjectMetadataState> = inputs
        .target_objects
        .iter()
        .map(|object| ((object.bucket.as_str(), object.key.as_str()), object))
        .collect();

    for ((bucket, key), source_object) in &source_object_map {
        let needs_update = target_object_map
            .get(&(*bucket, *key))
            .map(|target_object| *target_object != *source_object)
            .unwrap_or(true);
        if !needs_update {
            continue;
        }

        if source_object.is_delete_marker {
            actions.push(MetadataReconcileAction::TombstoneObject {
                bucket: (*bucket).to_string(),
                key: (*key).to_string(),
                version_id: source_object.latest_version_id.clone(),
            });
        } else {
            actions.push(MetadataReconcileAction::UpsertObject {
                bucket: (*bucket).to_string(),
                key: (*key).to_string(),
                version_id: source_object.latest_version_id.clone(),
            });
        }
    }

    for ((bucket, key), target_object) in &target_object_map {
        if source_object_map.contains_key(&(*bucket, *key)) {
            continue;
        }
        actions.push(MetadataReconcileAction::TombstoneObject {
            bucket: (*bucket).to_string(),
            key: (*key).to_string(),
            version_id: target_object.latest_version_id.clone(),
        });
    }

    let source_version_map: BTreeMap<(&str, &str, &str), &ObjectVersionMetadataState> = inputs
        .source_object_versions
        .iter()
        .map(|version| {
            (
                (
                    version.bucket.as_str(),
                    version.key.as_str(),
                    version.version_id.as_str(),
                ),
                version,
            )
        })
        .collect();
    let target_version_map: BTreeMap<(&str, &str, &str), &ObjectVersionMetadataState> = inputs
        .target_object_versions
        .iter()
        .map(|version| {
            (
                (
                    version.bucket.as_str(),
                    version.key.as_str(),
                    version.version_id.as_str(),
                ),
                version,
            )
        })
        .collect();

    for ((bucket, key, version_id), source_version) in &source_version_map {
        let needs_update = target_version_map
            .get(&(*bucket, *key, *version_id))
            .map(|target_version| *target_version != *source_version)
            .unwrap_or(true);
        if !needs_update {
            continue;
        }
        actions.push(MetadataReconcileAction::UpsertObjectVersion {
            bucket: (*bucket).to_string(),
            key: (*key).to_string(),
            version_id: (*version_id).to_string(),
            is_delete_marker: source_version.is_delete_marker,
            is_latest: source_version.is_latest,
        });
    }

    for (bucket, key, version_id) in target_version_map.keys() {
        if source_version_map.contains_key(&(*bucket, *key, *version_id)) {
            continue;
        }
        actions.push(MetadataReconcileAction::DeleteObjectVersion {
            bucket: (*bucket).to_string(),
            key: (*key).to_string(),
            version_id: (*version_id).to_string(),
        });
    }

    MetadataRepairPlan {
        source_view_id: source_view_id.to_string(),
        target_view_id: target_view_id.to_string(),
        actions,
    }
}

pub fn summarize_metadata_repair_plan(plan: &MetadataRepairPlan) -> MetadataRepairPlanSummary {
    let mut summary = MetadataRepairPlanSummary {
        total_actions: plan.actions.len(),
        ..MetadataRepairPlanSummary::default()
    };
    for action in &plan.actions {
        match action {
            MetadataReconcileAction::UpsertBucket { .. } => {
                summary.upsert_buckets += 1;
            }
            MetadataReconcileAction::DeleteBucket { .. } => {
                summary.delete_buckets += 1;
                summary.destructive_actions += 1;
            }
            MetadataReconcileAction::UpsertBucketTombstone { .. } => {
                summary.upsert_bucket_tombstones += 1;
            }
            MetadataReconcileAction::DeleteBucketTombstone { .. } => {
                summary.delete_bucket_tombstones += 1;
                summary.destructive_actions += 1;
            }
            MetadataReconcileAction::UpsertObject { .. } => {
                summary.upsert_objects += 1;
            }
            MetadataReconcileAction::TombstoneObject { .. } => {
                summary.tombstone_objects += 1;
                summary.destructive_actions += 1;
            }
            MetadataReconcileAction::UpsertObjectVersion { .. } => {
                summary.upsert_object_versions += 1;
            }
            MetadataReconcileAction::DeleteObjectVersion { .. } => {
                summary.delete_object_versions += 1;
                summary.destructive_actions += 1;
            }
        }
    }
    summary
}

pub fn apply_metadata_repair_plan(
    expected_source_view_id: &str,
    expected_target_view_id: &str,
    plan: &MetadataRepairPlan,
    inputs: MetadataRepairInputs<'_>,
) -> Result<MetadataRepairExecutionOutput, MetadataRepairExecutionError> {
    if let Err(reason) = validate_metadata_repair_plan(plan) {
        return Err(MetadataRepairExecutionError::InvalidPlan { reason });
    }

    if expected_source_view_id != plan.source_view_id {
        return Err(MetadataRepairExecutionError::SourceViewMismatch {
            expected_source_view_id: expected_source_view_id.to_string(),
            plan_source_view_id: plan.source_view_id.clone(),
        });
    }

    if expected_target_view_id != plan.target_view_id {
        return Err(MetadataRepairExecutionError::TargetViewMismatch {
            expected_target_view_id: expected_target_view_id.to_string(),
            plan_target_view_id: plan.target_view_id.clone(),
        });
    }

    let source_bucket_map: BTreeMap<&str, &BucketMetadataState> = inputs
        .source_buckets
        .iter()
        .map(|bucket| (bucket.bucket.as_str(), bucket))
        .collect();
    let source_bucket_tombstone_map: BTreeMap<&str, &BucketMetadataTombstoneState> = inputs
        .source_bucket_tombstones
        .iter()
        .map(|tombstone| (tombstone.bucket.as_str(), tombstone))
        .collect();
    let source_object_map: BTreeMap<(&str, &str), &ObjectMetadataState> = inputs
        .source_objects
        .iter()
        .map(|object| ((object.bucket.as_str(), object.key.as_str()), object))
        .collect();
    let source_object_version_map: BTreeMap<(&str, &str, &str), &ObjectVersionMetadataState> =
        inputs
            .source_object_versions
            .iter()
            .map(|version| {
                (
                    (
                        version.bucket.as_str(),
                        version.key.as_str(),
                        version.version_id.as_str(),
                    ),
                    version,
                )
            })
            .collect();

    let mut bucket_map: BTreeMap<String, BucketMetadataState> = inputs
        .target_buckets
        .iter()
        .map(|bucket| (bucket.bucket.clone(), bucket.clone()))
        .collect();
    let mut bucket_tombstone_map: BTreeMap<String, BucketMetadataTombstoneState> = inputs
        .target_bucket_tombstones
        .iter()
        .map(|tombstone| (tombstone.bucket.clone(), tombstone.clone()))
        .collect();
    let mut object_map: BTreeMap<(String, String), ObjectMetadataState> = inputs
        .target_objects
        .iter()
        .map(|object| ((object.bucket.clone(), object.key.clone()), object.clone()))
        .collect();
    let mut object_version_map: BTreeMap<(String, String, String), ObjectVersionMetadataState> =
        inputs
            .target_object_versions
            .iter()
            .map(|version| {
                (
                    (
                        version.bucket.clone(),
                        version.key.clone(),
                        version.version_id.clone(),
                    ),
                    version.clone(),
                )
            })
            .collect();

    for action in &plan.actions {
        match action {
            MetadataReconcileAction::UpsertBucket { bucket, .. } => {
                let Some(source_bucket) = source_bucket_map.get(bucket.as_str()) else {
                    return Err(MetadataRepairExecutionError::MissingSourceBucket {
                        bucket: bucket.clone(),
                    });
                };
                bucket_map.insert(bucket.clone(), (*source_bucket).clone());
                bucket_tombstone_map.remove(bucket);
            }
            MetadataReconcileAction::DeleteBucket { bucket } => {
                if source_bucket_map.contains_key(bucket.as_str()) {
                    return Err(
                        MetadataRepairExecutionError::SourceContainsBucketForDelete {
                            bucket: bucket.clone(),
                        },
                    );
                }
                bucket_map.remove(bucket);
            }
            MetadataReconcileAction::UpsertBucketTombstone { bucket, .. } => {
                let Some(source_tombstone) = source_bucket_tombstone_map.get(bucket.as_str())
                else {
                    return Err(MetadataRepairExecutionError::MissingSourceBucketTombstone {
                        bucket: bucket.clone(),
                    });
                };
                bucket_tombstone_map.insert(bucket.clone(), (*source_tombstone).clone());
                bucket_map.remove(bucket);
            }
            MetadataReconcileAction::DeleteBucketTombstone { bucket } => {
                if source_bucket_tombstone_map.contains_key(bucket.as_str()) {
                    return Err(
                        MetadataRepairExecutionError::SourceContainsBucketTombstoneForDelete {
                            bucket: bucket.clone(),
                        },
                    );
                }
                bucket_tombstone_map.remove(bucket);
            }
            MetadataReconcileAction::UpsertObject { bucket, key, .. } => {
                let Some(source_object) = source_object_map.get(&(bucket.as_str(), key.as_str()))
                else {
                    return Err(MetadataRepairExecutionError::MissingSourceObject {
                        bucket: bucket.clone(),
                        key: key.clone(),
                    });
                };
                if source_object.is_delete_marker {
                    return Err(
                        MetadataRepairExecutionError::InvalidSourceObjectStateForUpsert {
                            bucket: bucket.clone(),
                            key: key.clone(),
                        },
                    );
                }
                object_map.insert(
                    (bucket.clone(), key.clone()),
                    ObjectMetadataState {
                        bucket: bucket.clone(),
                        key: key.clone(),
                        latest_version_id: source_object.latest_version_id.clone(),
                        is_delete_marker: false,
                    },
                );
            }
            MetadataReconcileAction::TombstoneObject { bucket, key, .. } => {
                let source_object = source_object_map.get(&(bucket.as_str(), key.as_str()));
                let version_id = if let Some(source_object) = source_object {
                    if !source_object.is_delete_marker {
                        return Err(
                            MetadataRepairExecutionError::InvalidSourceObjectStateForTombstone {
                                bucket: bucket.clone(),
                                key: key.clone(),
                            },
                        );
                    }
                    source_object.latest_version_id.clone()
                } else {
                    let Some(target_object) = object_map.get(&(bucket.clone(), key.clone())) else {
                        return Err(
                            MetadataRepairExecutionError::MissingTargetObjectForTombstone {
                                bucket: bucket.clone(),
                                key: key.clone(),
                            },
                        );
                    };
                    target_object.latest_version_id.clone()
                };
                object_map.insert(
                    (bucket.clone(), key.clone()),
                    ObjectMetadataState {
                        bucket: bucket.clone(),
                        key: key.clone(),
                        latest_version_id: version_id,
                        is_delete_marker: true,
                    },
                );
            }
            MetadataReconcileAction::UpsertObjectVersion {
                bucket,
                key,
                version_id,
                ..
            } => {
                let Some(source_version) = source_object_version_map.get(&(
                    bucket.as_str(),
                    key.as_str(),
                    version_id.as_str(),
                )) else {
                    return Err(MetadataRepairExecutionError::MissingSourceObjectVersion {
                        bucket: bucket.clone(),
                        key: key.clone(),
                        version_id: version_id.clone(),
                    });
                };
                object_version_map.insert(
                    (bucket.clone(), key.clone(), version_id.clone()),
                    (*source_version).clone(),
                );
            }
            MetadataReconcileAction::DeleteObjectVersion {
                bucket,
                key,
                version_id,
            } => {
                if source_object_version_map.contains_key(&(
                    bucket.as_str(),
                    key.as_str(),
                    version_id.as_str(),
                )) {
                    return Err(
                        MetadataRepairExecutionError::SourceContainsObjectVersionForDelete {
                            bucket: bucket.clone(),
                            key: key.clone(),
                            version_id: version_id.clone(),
                        },
                    );
                }
                object_version_map.remove(&(bucket.clone(), key.clone(), version_id.clone()));
            }
        }
    }

    Ok(MetadataRepairExecutionOutput {
        buckets: bucket_map.into_values().collect(),
        bucket_tombstones: bucket_tombstone_map.into_values().collect(),
        objects: object_map.into_values().collect(),
        object_versions: object_version_map.into_values().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        MetadataReconcileAction, MetadataRepairExecutionError, MetadataRepairInputs,
        MetadataRepairPlan, MetadataRepairPlanSummary, MetadataRepairPlanValidationError,
        PendingMetadataRepairAcknowledgeOutcome, PendingMetadataRepairApplyError,
        PendingMetadataRepairApplyFailure, PendingMetadataRepairEnqueueOutcome,
        PendingMetadataRepairFailureWithBackoffOutcome, PendingMetadataRepairLeaseOutcome,
        PendingMetadataRepairPlan, PendingMetadataRepairQueue, PendingMetadataRepairQueueSummary,
        PendingMetadataRepairReplayCycleOutcome, PersistedBucketMetadataOperationError,
        PersistedBucketMetadataReadResolution, PersistedBucketMutationPreconditionResolution,
        PersistedBucketPresenceReadResolution, PersistedMetadataQueryError,
        PersistedMetadataQueryableStateError, PersistedMetadataState,
        PersistedObjectMetadataOperationError, PersistedObjectMetadataReadResolution,
        PersistedObjectVersionMetadataOperationError, PersistedObjectVersionMetadataReadResolution,
        acknowledge_pending_metadata_repair_plan,
        apply_bucket_metadata_operation_to_persisted_state, apply_metadata_repair_plan,
        apply_object_metadata_operation_to_persisted_state,
        apply_object_version_metadata_operation_to_persisted_state,
        apply_pending_metadata_repair_plan_to_persisted_state, build_metadata_repair_plan,
        build_queryable_metadata_index_from_persisted_state, enqueue_pending_metadata_repair_plan,
        lease_pending_metadata_repair_plan_for_execution, list_buckets_from_persisted_state,
        list_buckets_from_persisted_state_with_view_id,
        list_object_versions_page_from_persisted_state, list_objects_page_from_persisted_state,
        load_pending_metadata_repair_queue, load_persisted_metadata_state,
        metadata_repair_retry_backoff_ms, pending_metadata_repair_candidates,
        persist_pending_metadata_repair_queue, persist_persisted_metadata_state,
        record_pending_metadata_repair_failure_with_backoff,
        replay_pending_metadata_repairs_once_with_apply_fn,
        replay_pending_metadata_repairs_once_with_classified_apply_fn,
        resolve_bucket_metadata_from_persisted_state, resolve_bucket_presence_from_persisted_state,
        resolve_bucket_mutation_preconditions_from_persisted_state,
        resolve_object_metadata_from_persisted_state,
        resolve_object_version_metadata_from_persisted_state, summarize_metadata_repair_plan,
        summarize_pending_metadata_repair_queue, validate_metadata_repair_plan,
    };
    use crate::metadata::index::{MetadataQuery, MetadataVersionsQuery};
    use crate::metadata::state::{
        BucketMetadataOperation, BucketMetadataOperationError, BucketMetadataState,
        BucketMetadataTombstoneState, ObjectMetadataOperation, ObjectMetadataOperationError,
        ObjectMetadataState, ObjectVersionMetadataOperation, ObjectVersionMetadataOperationError,
        ObjectVersionMetadataState,
    };
    use tempfile::TempDir;

    #[test]
    fn repair_plan_reports_empty_state() {
        let plan = MetadataRepairPlan::default();
        assert!(plan.is_empty());
    }

    #[test]
    fn repair_plan_reports_non_empty_when_actions_exist() {
        let plan = MetadataRepairPlan {
            source_view_id: "view-a".to_string(),
            target_view_id: "view-b".to_string(),
            actions: vec![MetadataReconcileAction::UpsertBucket {
                bucket: "photos".to_string(),
                versioning_enabled: false,
                lifecycle_enabled: false,
            }],
        };
        assert!(!plan.is_empty());
    }

    #[test]
    fn summarize_metadata_repair_plan_counts_actions_by_type() {
        let plan = MetadataRepairPlan {
            source_view_id: "source".to_string(),
            target_view_id: "target".to_string(),
            actions: vec![
                MetadataReconcileAction::UpsertBucket {
                    bucket: "a".to_string(),
                    versioning_enabled: false,
                    lifecycle_enabled: false,
                },
                MetadataReconcileAction::DeleteBucket {
                    bucket: "b".to_string(),
                },
                MetadataReconcileAction::UpsertBucketTombstone {
                    bucket: "a".to_string(),
                    deleted_at_unix_ms: 1,
                    retain_until_unix_ms: 2,
                },
                MetadataReconcileAction::DeleteBucketTombstone {
                    bucket: "c".to_string(),
                },
                MetadataReconcileAction::UpsertObject {
                    bucket: "a".to_string(),
                    key: "k1".to_string(),
                    version_id: Some("v1".to_string()),
                },
                MetadataReconcileAction::TombstoneObject {
                    bucket: "a".to_string(),
                    key: "k2".to_string(),
                    version_id: None,
                },
                MetadataReconcileAction::UpsertObjectVersion {
                    bucket: "a".to_string(),
                    key: "k1".to_string(),
                    version_id: "v1".to_string(),
                    is_delete_marker: false,
                    is_latest: true,
                },
                MetadataReconcileAction::DeleteObjectVersion {
                    bucket: "a".to_string(),
                    key: "k1".to_string(),
                    version_id: "v0".to_string(),
                },
            ],
        };

        let summary = summarize_metadata_repair_plan(&plan);
        assert_eq!(
            summary,
            MetadataRepairPlanSummary {
                total_actions: 8,
                upsert_buckets: 1,
                delete_buckets: 1,
                upsert_bucket_tombstones: 1,
                delete_bucket_tombstones: 1,
                upsert_objects: 1,
                tombstone_objects: 1,
                upsert_object_versions: 1,
                delete_object_versions: 1,
                destructive_actions: 4,
            }
        );
    }

    #[test]
    fn build_metadata_repair_plan_adds_missing_bucket_and_object_updates() {
        let source_buckets = vec![BucketMetadataState::new("photos")];
        let target_buckets = Vec::new();

        let source_objects = vec![ObjectMetadataState {
            bucket: "photos".to_string(),
            key: "a/one.jpg".to_string(),
            latest_version_id: Some("v2".to_string()),
            is_delete_marker: false,
        }];
        let target_objects = vec![ObjectMetadataState {
            bucket: "photos".to_string(),
            key: "a/one.jpg".to_string(),
            latest_version_id: Some("v1".to_string()),
            is_delete_marker: false,
        }];

        let plan = build_metadata_repair_plan(
            "view-a",
            "view-b",
            MetadataRepairInputs {
                source_buckets: &source_buckets,
                target_buckets: &target_buckets,
                source_bucket_tombstones: &[],
                target_bucket_tombstones: &[],
                source_objects: &source_objects,
                target_objects: &target_objects,
                source_object_versions: &[],
                target_object_versions: &[],
            },
        );

        assert_eq!(plan.source_view_id, "view-a");
        assert_eq!(plan.target_view_id, "view-b");
        assert_eq!(
            plan.actions,
            vec![
                MetadataReconcileAction::UpsertBucket {
                    bucket: "photos".to_string(),
                    versioning_enabled: false,
                    lifecycle_enabled: false,
                },
                MetadataReconcileAction::UpsertObject {
                    bucket: "photos".to_string(),
                    key: "a/one.jpg".to_string(),
                    version_id: Some("v2".to_string())
                }
            ]
        );
    }

    #[test]
    fn build_metadata_repair_plan_tombstones_objects_absent_from_source() {
        let source_buckets = vec![BucketMetadataState::new("photos")];
        let target_buckets = vec![BucketMetadataState::new("photos")];

        let source_objects = Vec::new();
        let target_objects = vec![ObjectMetadataState {
            bucket: "photos".to_string(),
            key: "stale/old.jpg".to_string(),
            latest_version_id: Some("v1".to_string()),
            is_delete_marker: false,
        }];

        let plan = build_metadata_repair_plan(
            "view-a",
            "view-b",
            MetadataRepairInputs {
                source_buckets: &source_buckets,
                target_buckets: &target_buckets,
                source_bucket_tombstones: &[],
                target_bucket_tombstones: &[],
                source_objects: &source_objects,
                target_objects: &target_objects,
                source_object_versions: &[],
                target_object_versions: &[],
            },
        );

        assert_eq!(
            plan.actions,
            vec![MetadataReconcileAction::TombstoneObject {
                bucket: "photos".to_string(),
                key: "stale/old.jpg".to_string(),
                version_id: Some("v1".to_string())
            }]
        );
    }

    #[test]
    fn build_metadata_repair_plan_deletes_bucket_absent_from_source() {
        let source_buckets = Vec::new();
        let target_buckets = vec![BucketMetadataState::new("orphaned")];

        let plan = build_metadata_repair_plan(
            "view-a",
            "view-b",
            MetadataRepairInputs {
                source_buckets: &source_buckets,
                target_buckets: &target_buckets,
                source_bucket_tombstones: &[],
                target_bucket_tombstones: &[],
                source_objects: &[],
                target_objects: &[],
                source_object_versions: &[],
                target_object_versions: &[],
            },
        );

        assert_eq!(
            plan.actions,
            vec![MetadataReconcileAction::DeleteBucket {
                bucket: "orphaned".to_string(),
            }]
        );
    }

    #[test]
    fn build_metadata_repair_plan_reconciles_bucket_tombstones() {
        let source_tombstones = vec![BucketMetadataTombstoneState {
            bucket: "photos".to_string(),
            deleted_at_unix_ms: 100,
            retain_until_unix_ms: 500,
        }];
        let target_tombstones = vec![BucketMetadataTombstoneState {
            bucket: "photos".to_string(),
            deleted_at_unix_ms: 100,
            retain_until_unix_ms: 300,
        }];

        let plan = build_metadata_repair_plan(
            "view-a",
            "view-b",
            MetadataRepairInputs {
                source_buckets: &[],
                target_buckets: &[],
                source_bucket_tombstones: &source_tombstones,
                target_bucket_tombstones: &target_tombstones,
                source_objects: &[],
                target_objects: &[],
                source_object_versions: &[],
                target_object_versions: &[],
            },
        );

        assert_eq!(
            plan.actions,
            vec![MetadataReconcileAction::UpsertBucketTombstone {
                bucket: "photos".to_string(),
                deleted_at_unix_ms: 100,
                retain_until_unix_ms: 500,
            }]
        );
    }

    #[test]
    fn build_metadata_repair_plan_deletes_stale_bucket_tombstones() {
        let target_tombstones = vec![BucketMetadataTombstoneState {
            bucket: "stale".to_string(),
            deleted_at_unix_ms: 10,
            retain_until_unix_ms: 20,
        }];

        let plan = build_metadata_repair_plan(
            "view-a",
            "view-b",
            MetadataRepairInputs {
                source_buckets: &[],
                target_buckets: &[],
                source_bucket_tombstones: &[],
                target_bucket_tombstones: &target_tombstones,
                source_objects: &[],
                target_objects: &[],
                source_object_versions: &[],
                target_object_versions: &[],
            },
        );

        assert_eq!(
            plan.actions,
            vec![MetadataReconcileAction::DeleteBucketTombstone {
                bucket: "stale".to_string(),
            }]
        );
    }

    #[test]
    fn build_metadata_repair_plan_reconciles_object_versions() {
        let source_versions = vec![
            ObjectVersionMetadataState {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                version_id: "v2".to_string(),
                is_delete_marker: false,
                is_latest: true,
            },
            ObjectVersionMetadataState {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                version_id: "v1".to_string(),
                is_delete_marker: false,
                is_latest: false,
            },
        ];
        let target_versions = vec![
            ObjectVersionMetadataState {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                version_id: "v2".to_string(),
                is_delete_marker: false,
                is_latest: false,
            },
            ObjectVersionMetadataState {
                bucket: "photos".to_string(),
                key: "docs/old.txt".to_string(),
                version_id: "old-1".to_string(),
                is_delete_marker: false,
                is_latest: true,
            },
        ];
        let plan = build_metadata_repair_plan(
            "view-a",
            "view-b",
            MetadataRepairInputs {
                source_buckets: &[],
                target_buckets: &[],
                source_bucket_tombstones: &[],
                target_bucket_tombstones: &[],
                source_objects: &[],
                target_objects: &[],
                source_object_versions: &source_versions,
                target_object_versions: &target_versions,
            },
        );

        assert_eq!(
            plan.actions,
            vec![
                MetadataReconcileAction::UpsertObjectVersion {
                    bucket: "photos".to_string(),
                    key: "docs/a.txt".to_string(),
                    version_id: "v1".to_string(),
                    is_delete_marker: false,
                    is_latest: false,
                },
                MetadataReconcileAction::UpsertObjectVersion {
                    bucket: "photos".to_string(),
                    key: "docs/a.txt".to_string(),
                    version_id: "v2".to_string(),
                    is_delete_marker: false,
                    is_latest: true,
                },
                MetadataReconcileAction::DeleteObjectVersion {
                    bucket: "photos".to_string(),
                    key: "docs/old.txt".to_string(),
                    version_id: "old-1".to_string(),
                },
            ]
        );
    }

    #[test]
    fn apply_metadata_repair_plan_rejects_target_view_mismatch() {
        let plan = MetadataRepairPlan {
            source_view_id: "view-a".to_string(),
            target_view_id: "view-b".to_string(),
            actions: Vec::new(),
        };

        let result = apply_metadata_repair_plan(
            "view-a",
            "view-c",
            &plan,
            MetadataRepairInputs {
                source_buckets: &[],
                target_buckets: &[],
                source_bucket_tombstones: &[],
                target_bucket_tombstones: &[],
                source_objects: &[],
                target_objects: &[],
                source_object_versions: &[],
                target_object_versions: &[],
            },
        );

        assert_eq!(
            result,
            Err(MetadataRepairExecutionError::TargetViewMismatch {
                expected_target_view_id: "view-c".to_string(),
                plan_target_view_id: "view-b".to_string(),
            })
        );
    }

    #[test]
    fn apply_metadata_repair_plan_rejects_source_view_mismatch() {
        let plan = MetadataRepairPlan {
            source_view_id: "view-a".to_string(),
            target_view_id: "view-b".to_string(),
            actions: Vec::new(),
        };

        let result = apply_metadata_repair_plan(
            "view-z",
            "view-b",
            &plan,
            MetadataRepairInputs {
                source_buckets: &[],
                target_buckets: &[],
                source_bucket_tombstones: &[],
                target_bucket_tombstones: &[],
                source_objects: &[],
                target_objects: &[],
                source_object_versions: &[],
                target_object_versions: &[],
            },
        );

        assert_eq!(
            result,
            Err(MetadataRepairExecutionError::SourceViewMismatch {
                expected_source_view_id: "view-z".to_string(),
                plan_source_view_id: "view-a".to_string(),
            })
        );
    }

    #[test]
    fn apply_metadata_repair_plan_applies_bucket_and_tombstone_updates() {
        let source_buckets = vec![BucketMetadataState {
            bucket: "photos".to_string(),
            versioning_enabled: true,
            lifecycle_enabled: false,
        }];
        let target_buckets = vec![BucketMetadataState {
            bucket: "photos".to_string(),
            versioning_enabled: false,
            lifecycle_enabled: false,
        }];
        let source_tombstones = Vec::new();
        let target_tombstones = vec![BucketMetadataTombstoneState {
            bucket: "photos".to_string(),
            deleted_at_unix_ms: 10,
            retain_until_unix_ms: 20,
        }];

        let plan = build_metadata_repair_plan(
            "view-a",
            "view-b",
            MetadataRepairInputs {
                source_buckets: &source_buckets,
                target_buckets: &target_buckets,
                source_bucket_tombstones: &source_tombstones,
                target_bucket_tombstones: &target_tombstones,
                source_objects: &[],
                target_objects: &[],
                source_object_versions: &[],
                target_object_versions: &[],
            },
        );

        let result = apply_metadata_repair_plan(
            "view-a",
            "view-b",
            &plan,
            MetadataRepairInputs {
                source_buckets: &source_buckets,
                target_buckets: &target_buckets,
                source_bucket_tombstones: &source_tombstones,
                target_bucket_tombstones: &target_tombstones,
                source_objects: &[],
                target_objects: &[],
                source_object_versions: &[],
                target_object_versions: &[],
            },
        )
        .expect("repair execution should succeed");

        assert_eq!(
            result.buckets,
            vec![BucketMetadataState {
                bucket: "photos".to_string(),
                versioning_enabled: true,
                lifecycle_enabled: false,
            }]
        );
        assert!(result.bucket_tombstones.is_empty());
    }

    #[test]
    fn apply_metadata_repair_plan_applies_object_and_version_actions() {
        let source_objects = vec![ObjectMetadataState {
            bucket: "photos".to_string(),
            key: "docs/a.txt".to_string(),
            latest_version_id: Some("v3".to_string()),
            is_delete_marker: false,
        }];
        let target_objects = vec![ObjectMetadataState {
            bucket: "photos".to_string(),
            key: "docs/a.txt".to_string(),
            latest_version_id: Some("v1".to_string()),
            is_delete_marker: true,
        }];
        let source_versions = vec![ObjectVersionMetadataState {
            bucket: "photos".to_string(),
            key: "docs/a.txt".to_string(),
            version_id: "v3".to_string(),
            is_delete_marker: false,
            is_latest: true,
        }];
        let target_versions = vec![
            ObjectVersionMetadataState {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                version_id: "v1".to_string(),
                is_delete_marker: false,
                is_latest: true,
            },
            ObjectVersionMetadataState {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                version_id: "v2".to_string(),
                is_delete_marker: false,
                is_latest: false,
            },
        ];

        let plan = build_metadata_repair_plan(
            "view-a",
            "view-b",
            MetadataRepairInputs {
                source_buckets: &[],
                target_buckets: &[],
                source_bucket_tombstones: &[],
                target_bucket_tombstones: &[],
                source_objects: &source_objects,
                target_objects: &target_objects,
                source_object_versions: &source_versions,
                target_object_versions: &target_versions,
            },
        );

        let result = apply_metadata_repair_plan(
            "view-a",
            "view-b",
            &plan,
            MetadataRepairInputs {
                source_buckets: &[],
                target_buckets: &[],
                source_bucket_tombstones: &[],
                target_bucket_tombstones: &[],
                source_objects: &source_objects,
                target_objects: &target_objects,
                source_object_versions: &source_versions,
                target_object_versions: &target_versions,
            },
        )
        .expect("repair execution should succeed");

        assert_eq!(result.objects, source_objects);
        assert_eq!(result.object_versions, source_versions);
    }

    #[test]
    fn apply_metadata_repair_plan_rejects_missing_source_bucket_for_upsert() {
        let plan = MetadataRepairPlan {
            source_view_id: "view-a".to_string(),
            target_view_id: "view-b".to_string(),
            actions: vec![MetadataReconcileAction::UpsertBucket {
                bucket: "photos".to_string(),
                versioning_enabled: false,
                lifecycle_enabled: false,
            }],
        };
        let result = apply_metadata_repair_plan(
            "view-a",
            "view-b",
            &plan,
            MetadataRepairInputs {
                source_buckets: &[],
                target_buckets: &[],
                source_bucket_tombstones: &[],
                target_bucket_tombstones: &[],
                source_objects: &[],
                target_objects: &[],
                source_object_versions: &[],
                target_object_versions: &[],
            },
        );

        assert_eq!(
            result,
            Err(MetadataRepairExecutionError::MissingSourceBucket {
                bucket: "photos".to_string(),
            })
        );
    }

    #[test]
    fn apply_metadata_repair_plan_rejects_delete_bucket_when_source_still_contains_bucket() {
        let source_buckets = vec![BucketMetadataState::new("photos")];
        let plan = MetadataRepairPlan {
            source_view_id: "view-a".to_string(),
            target_view_id: "view-b".to_string(),
            actions: vec![MetadataReconcileAction::DeleteBucket {
                bucket: "photos".to_string(),
            }],
        };

        let result = apply_metadata_repair_plan(
            "view-a",
            "view-b",
            &plan,
            MetadataRepairInputs {
                source_buckets: &source_buckets,
                target_buckets: &[],
                source_bucket_tombstones: &[],
                target_bucket_tombstones: &[],
                source_objects: &[],
                target_objects: &[],
                source_object_versions: &[],
                target_object_versions: &[],
            },
        );

        assert_eq!(
            result,
            Err(
                MetadataRepairExecutionError::SourceContainsBucketForDelete {
                    bucket: "photos".to_string(),
                }
            )
        );
    }

    #[test]
    fn apply_metadata_repair_plan_rejects_missing_source_bucket_tombstone_for_upsert() {
        let plan = MetadataRepairPlan {
            source_view_id: "view-a".to_string(),
            target_view_id: "view-b".to_string(),
            actions: vec![MetadataReconcileAction::UpsertBucketTombstone {
                bucket: "photos".to_string(),
                deleted_at_unix_ms: 10,
                retain_until_unix_ms: 20,
            }],
        };
        let result = apply_metadata_repair_plan(
            "view-a",
            "view-b",
            &plan,
            MetadataRepairInputs {
                source_buckets: &[],
                target_buckets: &[],
                source_bucket_tombstones: &[],
                target_bucket_tombstones: &[],
                source_objects: &[],
                target_objects: &[],
                source_object_versions: &[],
                target_object_versions: &[],
            },
        );

        assert_eq!(
            result,
            Err(MetadataRepairExecutionError::MissingSourceBucketTombstone {
                bucket: "photos".to_string(),
            })
        );
    }

    #[test]
    fn apply_metadata_repair_plan_rejects_delete_bucket_tombstone_when_source_still_contains_tombstone()
     {
        let source_tombstones = vec![BucketMetadataTombstoneState {
            bucket: "photos".to_string(),
            deleted_at_unix_ms: 10,
            retain_until_unix_ms: 20,
        }];
        let plan = MetadataRepairPlan {
            source_view_id: "view-a".to_string(),
            target_view_id: "view-b".to_string(),
            actions: vec![MetadataReconcileAction::DeleteBucketTombstone {
                bucket: "photos".to_string(),
            }],
        };

        let result = apply_metadata_repair_plan(
            "view-a",
            "view-b",
            &plan,
            MetadataRepairInputs {
                source_buckets: &[],
                target_buckets: &[],
                source_bucket_tombstones: &source_tombstones,
                target_bucket_tombstones: &[],
                source_objects: &[],
                target_objects: &[],
                source_object_versions: &[],
                target_object_versions: &[],
            },
        );

        assert_eq!(
            result,
            Err(
                MetadataRepairExecutionError::SourceContainsBucketTombstoneForDelete {
                    bucket: "photos".to_string(),
                }
            )
        );
    }

    #[test]
    fn apply_metadata_repair_plan_rejects_missing_source_object_for_upsert() {
        let plan = MetadataRepairPlan {
            source_view_id: "view-a".to_string(),
            target_view_id: "view-b".to_string(),
            actions: vec![MetadataReconcileAction::UpsertObject {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                version_id: Some("v1".to_string()),
            }],
        };
        let result = apply_metadata_repair_plan(
            "view-a",
            "view-b",
            &plan,
            MetadataRepairInputs {
                source_buckets: &[],
                target_buckets: &[],
                source_bucket_tombstones: &[],
                target_bucket_tombstones: &[],
                source_objects: &[],
                target_objects: &[],
                source_object_versions: &[],
                target_object_versions: &[],
            },
        );

        assert_eq!(
            result,
            Err(MetadataRepairExecutionError::MissingSourceObject {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
            })
        );
    }

    #[test]
    fn apply_metadata_repair_plan_rejects_missing_source_object_version_for_upsert() {
        let plan = MetadataRepairPlan {
            source_view_id: "view-a".to_string(),
            target_view_id: "view-b".to_string(),
            actions: vec![MetadataReconcileAction::UpsertObjectVersion {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                version_id: "v1".to_string(),
                is_delete_marker: false,
                is_latest: true,
            }],
        };
        let result = apply_metadata_repair_plan(
            "view-a",
            "view-b",
            &plan,
            MetadataRepairInputs {
                source_buckets: &[],
                target_buckets: &[],
                source_bucket_tombstones: &[],
                target_bucket_tombstones: &[],
                source_objects: &[],
                target_objects: &[],
                source_object_versions: &[],
                target_object_versions: &[],
            },
        );

        assert_eq!(
            result,
            Err(MetadataRepairExecutionError::MissingSourceObjectVersion {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                version_id: "v1".to_string(),
            })
        );
    }

    #[test]
    fn apply_metadata_repair_plan_rejects_delete_object_version_when_source_still_contains_version()
    {
        let source_versions = vec![ObjectVersionMetadataState {
            bucket: "photos".to_string(),
            key: "docs/a.txt".to_string(),
            version_id: "v1".to_string(),
            is_delete_marker: false,
            is_latest: true,
        }];
        let plan = MetadataRepairPlan {
            source_view_id: "view-a".to_string(),
            target_view_id: "view-b".to_string(),
            actions: vec![MetadataReconcileAction::DeleteObjectVersion {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                version_id: "v1".to_string(),
            }],
        };

        let result = apply_metadata_repair_plan(
            "view-a",
            "view-b",
            &plan,
            MetadataRepairInputs {
                source_buckets: &[],
                target_buckets: &[],
                source_bucket_tombstones: &[],
                target_bucket_tombstones: &[],
                source_objects: &[],
                target_objects: &[],
                source_object_versions: &source_versions,
                target_object_versions: &[],
            },
        );

        assert_eq!(
            result,
            Err(
                MetadataRepairExecutionError::SourceContainsObjectVersionForDelete {
                    bucket: "photos".to_string(),
                    key: "docs/a.txt".to_string(),
                    version_id: "v1".to_string(),
                }
            )
        );
    }

    #[test]
    fn apply_metadata_repair_plan_rejects_invalid_source_object_state_for_upsert() {
        let source_objects = vec![ObjectMetadataState {
            bucket: "photos".to_string(),
            key: "docs/a.txt".to_string(),
            latest_version_id: Some("v2".to_string()),
            is_delete_marker: true,
        }];
        let plan = MetadataRepairPlan {
            source_view_id: "view-a".to_string(),
            target_view_id: "view-b".to_string(),
            actions: vec![MetadataReconcileAction::UpsertObject {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                version_id: Some("tampered".to_string()),
            }],
        };

        let result = apply_metadata_repair_plan(
            "view-a",
            "view-b",
            &plan,
            MetadataRepairInputs {
                source_buckets: &[],
                target_buckets: &[],
                source_bucket_tombstones: &[],
                target_bucket_tombstones: &[],
                source_objects: &source_objects,
                target_objects: &[],
                source_object_versions: &[],
                target_object_versions: &[],
            },
        );

        assert_eq!(
            result,
            Err(
                MetadataRepairExecutionError::InvalidSourceObjectStateForUpsert {
                    bucket: "photos".to_string(),
                    key: "docs/a.txt".to_string(),
                }
            )
        );
    }

    #[test]
    fn apply_metadata_repair_plan_rejects_invalid_source_object_state_for_tombstone() {
        let source_objects = vec![ObjectMetadataState {
            bucket: "photos".to_string(),
            key: "docs/a.txt".to_string(),
            latest_version_id: Some("v2".to_string()),
            is_delete_marker: false,
        }];
        let plan = MetadataRepairPlan {
            source_view_id: "view-a".to_string(),
            target_view_id: "view-b".to_string(),
            actions: vec![MetadataReconcileAction::TombstoneObject {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                version_id: Some("tampered".to_string()),
            }],
        };

        let result = apply_metadata_repair_plan(
            "view-a",
            "view-b",
            &plan,
            MetadataRepairInputs {
                source_buckets: &[],
                target_buckets: &[],
                source_bucket_tombstones: &[],
                target_bucket_tombstones: &[],
                source_objects: &source_objects,
                target_objects: &[],
                source_object_versions: &[],
                target_object_versions: &[],
            },
        );

        assert_eq!(
            result,
            Err(
                MetadataRepairExecutionError::InvalidSourceObjectStateForTombstone {
                    bucket: "photos".to_string(),
                    key: "docs/a.txt".to_string(),
                }
            )
        );
    }

    #[test]
    fn apply_metadata_repair_plan_rejects_tombstone_action_without_source_or_target_object() {
        let plan = MetadataRepairPlan {
            source_view_id: "view-a".to_string(),
            target_view_id: "view-b".to_string(),
            actions: vec![MetadataReconcileAction::TombstoneObject {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                version_id: Some("tampered".to_string()),
            }],
        };

        let result = apply_metadata_repair_plan(
            "view-a",
            "view-b",
            &plan,
            MetadataRepairInputs {
                source_buckets: &[],
                target_buckets: &[],
                source_bucket_tombstones: &[],
                target_bucket_tombstones: &[],
                source_objects: &[],
                target_objects: &[],
                source_object_versions: &[],
                target_object_versions: &[],
            },
        );

        assert_eq!(
            result,
            Err(
                MetadataRepairExecutionError::MissingTargetObjectForTombstone {
                    bucket: "photos".to_string(),
                    key: "docs/a.txt".to_string(),
                }
            )
        );
    }

    #[test]
    fn apply_metadata_repair_plan_uses_source_state_for_upsert_fields() {
        let source_tombstones = vec![BucketMetadataTombstoneState {
            bucket: "photos".to_string(),
            deleted_at_unix_ms: 111,
            retain_until_unix_ms: 222,
        }];
        let source_objects = vec![ObjectMetadataState {
            bucket: "photos".to_string(),
            key: "docs/a.txt".to_string(),
            latest_version_id: Some("v-source".to_string()),
            is_delete_marker: false,
        }];
        let source_versions = vec![ObjectVersionMetadataState {
            bucket: "photos".to_string(),
            key: "docs/a.txt".to_string(),
            version_id: "v-source".to_string(),
            is_delete_marker: true,
            is_latest: false,
        }];
        let plan = MetadataRepairPlan {
            source_view_id: "view-a".to_string(),
            target_view_id: "view-b".to_string(),
            actions: vec![
                MetadataReconcileAction::UpsertBucketTombstone {
                    bucket: "photos".to_string(),
                    deleted_at_unix_ms: 1,
                    retain_until_unix_ms: 2,
                },
                MetadataReconcileAction::UpsertObject {
                    bucket: "photos".to_string(),
                    key: "docs/a.txt".to_string(),
                    version_id: Some("tampered-object-version".to_string()),
                },
                MetadataReconcileAction::UpsertObjectVersion {
                    bucket: "photos".to_string(),
                    key: "docs/a.txt".to_string(),
                    version_id: "v-source".to_string(),
                    is_delete_marker: false,
                    is_latest: true,
                },
            ],
        };

        let result = apply_metadata_repair_plan(
            "view-a",
            "view-b",
            &plan,
            MetadataRepairInputs {
                source_buckets: &[],
                target_buckets: &[],
                source_bucket_tombstones: &source_tombstones,
                target_bucket_tombstones: &[],
                source_objects: &source_objects,
                target_objects: &[],
                source_object_versions: &source_versions,
                target_object_versions: &[],
            },
        )
        .expect("repair execution should succeed");

        assert_eq!(result.bucket_tombstones, source_tombstones);
        assert_eq!(result.objects, source_objects);
        assert_eq!(result.object_versions, source_versions);
    }

    #[test]
    fn validate_metadata_repair_plan_rejects_conflicting_object_actions() {
        let plan = MetadataRepairPlan {
            source_view_id: "view-a".to_string(),
            target_view_id: "view-b".to_string(),
            actions: vec![
                MetadataReconcileAction::UpsertObject {
                    bucket: "photos".to_string(),
                    key: "docs/a.txt".to_string(),
                    version_id: Some("v1".to_string()),
                },
                MetadataReconcileAction::TombstoneObject {
                    bucket: "photos".to_string(),
                    key: "docs/a.txt".to_string(),
                    version_id: Some("v1".to_string()),
                },
            ],
        };

        assert_eq!(
            validate_metadata_repair_plan(&plan),
            Err(MetadataRepairPlanValidationError::ConflictingObjectAction {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
            })
        );
    }

    #[test]
    fn validate_metadata_repair_plan_accepts_distinct_actions() {
        let plan = MetadataRepairPlan {
            source_view_id: "view-a".to_string(),
            target_view_id: "view-b".to_string(),
            actions: vec![
                MetadataReconcileAction::UpsertBucket {
                    bucket: "photos".to_string(),
                    versioning_enabled: false,
                    lifecycle_enabled: false,
                },
                MetadataReconcileAction::UpsertBucketTombstone {
                    bucket: "archive".to_string(),
                    deleted_at_unix_ms: 10,
                    retain_until_unix_ms: 20,
                },
                MetadataReconcileAction::UpsertObject {
                    bucket: "photos".to_string(),
                    key: "docs/a.txt".to_string(),
                    version_id: Some("v1".to_string()),
                },
                MetadataReconcileAction::UpsertObjectVersion {
                    bucket: "photos".to_string(),
                    key: "docs/a.txt".to_string(),
                    version_id: "v1".to_string(),
                    is_delete_marker: false,
                    is_latest: true,
                },
            ],
        };

        assert_eq!(validate_metadata_repair_plan(&plan), Ok(()));
    }

    #[test]
    fn apply_metadata_repair_plan_rejects_invalid_plan_conflicts() {
        let plan = MetadataRepairPlan {
            source_view_id: "view-a".to_string(),
            target_view_id: "view-b".to_string(),
            actions: vec![
                MetadataReconcileAction::DeleteObjectVersion {
                    bucket: "photos".to_string(),
                    key: "docs/a.txt".to_string(),
                    version_id: "v1".to_string(),
                },
                MetadataReconcileAction::UpsertObjectVersion {
                    bucket: "photos".to_string(),
                    key: "docs/a.txt".to_string(),
                    version_id: "v1".to_string(),
                    is_delete_marker: false,
                    is_latest: true,
                },
            ],
        };

        let result = apply_metadata_repair_plan(
            "view-a",
            "view-b",
            &plan,
            MetadataRepairInputs {
                source_buckets: &[],
                target_buckets: &[],
                source_bucket_tombstones: &[],
                target_bucket_tombstones: &[],
                source_objects: &[],
                target_objects: &[],
                source_object_versions: &[],
                target_object_versions: &[],
            },
        );

        assert_eq!(
            result,
            Err(MetadataRepairExecutionError::InvalidPlan {
                reason: MetadataRepairPlanValidationError::ConflictingObjectVersionAction {
                    bucket: "photos".to_string(),
                    key: "docs/a.txt".to_string(),
                    version_id: "v1".to_string(),
                },
            })
        );
    }

    #[test]
    fn pending_metadata_repair_plan_new_rejects_invalid_inputs() {
        let base_plan = MetadataRepairPlan {
            source_view_id: "view-a".to_string(),
            target_view_id: "view-b".to_string(),
            actions: vec![MetadataReconcileAction::UpsertBucket {
                bucket: "photos".to_string(),
                versioning_enabled: false,
                lifecycle_enabled: false,
            }],
        };
        assert!(PendingMetadataRepairPlan::new("", 1, base_plan.clone()).is_none());

        let mut empty_source = base_plan.clone();
        empty_source.source_view_id = " ".to_string();
        assert!(PendingMetadataRepairPlan::new("repair-1", 1, empty_source).is_none());

        let mut empty_actions = base_plan.clone();
        empty_actions.actions.clear();
        assert!(PendingMetadataRepairPlan::new("repair-1", 1, empty_actions).is_none());

        let pending =
            PendingMetadataRepairPlan::new("repair-1", 42, base_plan).expect("valid pending plan");
        assert_eq!(pending.repair_id, "repair-1");
        assert_eq!(pending.created_at_unix_ms, 42);
        assert_eq!(pending.attempts, 0);
        assert_eq!(pending.next_retry_at_unix_ms, None);
    }

    #[test]
    fn pending_metadata_repair_queue_enqueue_and_ack_are_idempotent() {
        let plan = PendingMetadataRepairPlan::new(
            "repair-queue",
            10,
            MetadataRepairPlan {
                source_view_id: "view-a".to_string(),
                target_view_id: "view-b".to_string(),
                actions: vec![MetadataReconcileAction::UpsertBucket {
                    bucket: "photos".to_string(),
                    versioning_enabled: false,
                    lifecycle_enabled: false,
                }],
            },
        )
        .expect("pending plan should be valid");
        let mut queue = PendingMetadataRepairQueue::default();
        assert_eq!(
            enqueue_pending_metadata_repair_plan(&mut queue, plan.clone()),
            PendingMetadataRepairEnqueueOutcome::Inserted
        );
        assert_eq!(
            enqueue_pending_metadata_repair_plan(&mut queue, plan),
            PendingMetadataRepairEnqueueOutcome::AlreadyTracked
        );
        assert_eq!(
            acknowledge_pending_metadata_repair_plan(&mut queue, "repair-queue"),
            PendingMetadataRepairAcknowledgeOutcome::Acknowledged
        );
        assert_eq!(
            acknowledge_pending_metadata_repair_plan(&mut queue, "repair-queue"),
            PendingMetadataRepairAcknowledgeOutcome::NotFound
        );
    }

    #[test]
    fn pending_metadata_repair_queue_failure_backoff_and_candidates_are_deterministic() {
        let mut queue = PendingMetadataRepairQueue::default();
        let first = PendingMetadataRepairPlan::new(
            "repair-a",
            10,
            MetadataRepairPlan {
                source_view_id: "view-a".to_string(),
                target_view_id: "view-b".to_string(),
                actions: vec![MetadataReconcileAction::UpsertBucket {
                    bucket: "photos".to_string(),
                    versioning_enabled: false,
                    lifecycle_enabled: false,
                }],
            },
        )
        .expect("first plan");
        let second = PendingMetadataRepairPlan::new(
            "repair-b",
            20,
            MetadataRepairPlan {
                source_view_id: "view-a".to_string(),
                target_view_id: "view-c".to_string(),
                actions: vec![MetadataReconcileAction::DeleteBucket {
                    bucket: "archive".to_string(),
                }],
            },
        )
        .expect("second plan");
        enqueue_pending_metadata_repair_plan(&mut queue, first);
        enqueue_pending_metadata_repair_plan(&mut queue, second);

        let lease =
            lease_pending_metadata_repair_plan_for_execution(&mut queue, "repair-a", 100, 15);
        assert_eq!(
            lease,
            PendingMetadataRepairLeaseOutcome::Updated {
                attempts: 0,
                lease_expires_at_unix_ms: 115
            }
        );

        let failed = record_pending_metadata_repair_failure_with_backoff(
            &mut queue,
            "repair-a",
            Some("transport unavailable"),
            120,
            10,
            1000,
        );
        assert_eq!(
            failed,
            PendingMetadataRepairFailureWithBackoffOutcome::Updated {
                attempts: 1,
                next_retry_at_unix_ms: 130
            }
        );

        assert_eq!(metadata_repair_retry_backoff_ms(10, 1000, 1), 10);
        assert_eq!(metadata_repair_retry_backoff_ms(10, 1000, 3), 40);

        let candidates = pending_metadata_repair_candidates(&queue, 125, 10);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].repair_id, "repair-b");

        let summary = summarize_pending_metadata_repair_queue(&queue, 125);
        assert_eq!(
            summary,
            PendingMetadataRepairQueueSummary {
                plans: 2,
                due_plans: 1,
                failed_plans: 1,
                max_attempts: 1,
                oldest_created_at_unix_ms: Some(10),
            }
        );
    }

    #[test]
    fn pending_metadata_repair_queue_persist_roundtrip() {
        let temp_dir = TempDir::new().expect("temp dir");
        let queue_path = temp_dir
            .path()
            .join(".maxio-runtime/pending-metadata-repair.json");
        let pending = PendingMetadataRepairPlan::new(
            "repair-persist",
            111,
            MetadataRepairPlan {
                source_view_id: "view-a".to_string(),
                target_view_id: "view-b".to_string(),
                actions: vec![MetadataReconcileAction::UpsertObject {
                    bucket: "photos".to_string(),
                    key: "docs/a.txt".to_string(),
                    version_id: Some("v1".to_string()),
                }],
            },
        )
        .expect("pending plan");

        let mut queue = PendingMetadataRepairQueue::default();
        enqueue_pending_metadata_repair_plan(&mut queue, pending);
        persist_pending_metadata_repair_queue(queue_path.as_path(), &queue).expect("persist queue");
        let loaded = load_pending_metadata_repair_queue(queue_path.as_path()).expect("load queue");
        assert_eq!(loaded, queue);
    }

    #[test]
    fn replay_pending_metadata_repairs_once_acknowledges_successful_apply() {
        let temp = TempDir::new().expect("temp dir");
        let queue_path = temp.path().join("pending-metadata-repair-queue.json");
        let pending = PendingMetadataRepairPlan::new(
            "repair-success",
            100,
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
        .expect("valid pending plan");
        let mut queue = PendingMetadataRepairQueue::default();
        queue.plans.push(pending);
        persist_pending_metadata_repair_queue(&queue_path, &queue).expect("persist queue");

        let mut applied_ids = Vec::new();
        let mut observed_lease_retry_at = Vec::new();
        let mut observed_attempts = Vec::new();
        let outcome = replay_pending_metadata_repairs_once_with_apply_fn(
            &queue_path,
            100,
            16,
            250,
            500,
            5_000,
            |plan| {
                applied_ids.push(plan.repair_id.clone());
                observed_lease_retry_at.push(plan.next_retry_at_unix_ms);
                observed_attempts.push(plan.attempts);
                Ok(())
            },
        )
        .expect("replay cycle");

        assert_eq!(
            outcome,
            PendingMetadataRepairReplayCycleOutcome {
                scanned_plans: 1,
                leased_plans: 1,
                acknowledged_plans: 1,
                failed_plans: 0,
                dropped_plans: 0,
                skipped_plans: 0,
            }
        );
        assert_eq!(applied_ids, vec!["repair-success".to_string()]);
        assert_eq!(observed_lease_retry_at, vec![Some(350)]);
        assert_eq!(observed_attempts, vec![0]);
        let reloaded = load_pending_metadata_repair_queue(&queue_path).expect("reload queue");
        assert!(reloaded.plans.is_empty());
    }

    #[test]
    fn replay_pending_metadata_repairs_once_records_failure_with_backoff() {
        let temp = TempDir::new().expect("temp dir");
        let queue_path = temp.path().join("pending-metadata-repair-queue.json");
        let pending = PendingMetadataRepairPlan::new(
            "repair-failed",
            1_000,
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
        .expect("valid pending plan");
        let mut queue = PendingMetadataRepairQueue::default();
        queue.plans.push(pending);
        persist_pending_metadata_repair_queue(&queue_path, &queue).expect("persist queue");

        let now_unix_ms = 5_000;
        let outcome = replay_pending_metadata_repairs_once_with_apply_fn(
            &queue_path,
            now_unix_ms,
            16,
            250,
            1_500,
            30_000,
            |_plan| Err("transient-failure".to_string()),
        )
        .expect("replay cycle");

        assert_eq!(
            outcome,
            PendingMetadataRepairReplayCycleOutcome {
                scanned_plans: 1,
                leased_plans: 1,
                acknowledged_plans: 0,
                failed_plans: 1,
                dropped_plans: 0,
                skipped_plans: 0,
            }
        );

        let reloaded = load_pending_metadata_repair_queue(&queue_path).expect("reload queue");
        assert_eq!(reloaded.plans.len(), 1);
        let plan = &reloaded.plans[0];
        assert_eq!(plan.repair_id, "repair-failed");
        assert_eq!(plan.attempts, 1);
        assert_eq!(plan.last_error.as_deref(), Some("transient-failure"));
        assert_eq!(plan.next_retry_at_unix_ms, Some(now_unix_ms + 1_500));
    }

    #[test]
    fn replay_pending_metadata_repairs_once_drops_permanent_apply_failures() {
        let temp = TempDir::new().expect("temp dir");
        let queue_path = temp.path().join("pending-metadata-repair-queue.json");
        let pending = PendingMetadataRepairPlan::new(
            "repair-permanent",
            1_000,
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
        .expect("valid pending plan");
        let mut queue = PendingMetadataRepairQueue::default();
        queue.plans.push(pending);
        persist_pending_metadata_repair_queue(&queue_path, &queue).expect("persist queue");

        let outcome = replay_pending_metadata_repairs_once_with_classified_apply_fn(
            &queue_path,
            5_000,
            16,
            250,
            1_500,
            30_000,
            |_plan| {
                Err(PendingMetadataRepairApplyFailure::permanent(
                    "source_view_mismatch",
                ))
            },
        )
        .expect("replay cycle");

        assert_eq!(
            outcome,
            PendingMetadataRepairReplayCycleOutcome {
                scanned_plans: 1,
                leased_plans: 1,
                acknowledged_plans: 0,
                failed_plans: 0,
                dropped_plans: 1,
                skipped_plans: 0,
            }
        );
        let reloaded = load_pending_metadata_repair_queue(&queue_path).expect("reload queue");
        assert!(reloaded.plans.is_empty());
    }

    #[test]
    fn apply_pending_metadata_repair_plan_to_persisted_state_bootstraps_and_persists() {
        let temp = TempDir::new().expect("temp dir");
        let state_path = temp
            .path()
            .join(".maxio-runtime/cluster-metadata-state.json");
        let pending = PendingMetadataRepairPlan::new(
            "repair-apply",
            1,
            MetadataRepairPlan {
                source_view_id: "view-source".to_string(),
                target_view_id: "view-target".to_string(),
                actions: vec![
                    MetadataReconcileAction::UpsertBucket {
                        bucket: "photos".to_string(),
                        versioning_enabled: true,
                        lifecycle_enabled: false,
                    },
                    MetadataReconcileAction::UpsertObjectVersion {
                        bucket: "photos".to_string(),
                        key: "docs/a.txt".to_string(),
                        version_id: "v1".to_string(),
                        is_delete_marker: false,
                        is_latest: true,
                    },
                    MetadataReconcileAction::UpsertObject {
                        bucket: "photos".to_string(),
                        key: "docs/a.txt".to_string(),
                        version_id: Some("v1".to_string()),
                    },
                ],
            },
        )
        .expect("pending plan should be valid");

        let output =
            apply_pending_metadata_repair_plan_to_persisted_state(state_path.as_path(), &pending)
                .expect("repair application should succeed");
        assert_eq!(
            output.buckets,
            vec![BucketMetadataState {
                bucket: "photos".to_string(),
                versioning_enabled: true,
                lifecycle_enabled: false,
            }]
        );
        assert_eq!(
            output.objects,
            vec![ObjectMetadataState {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                latest_version_id: Some("v1".to_string()),
                is_delete_marker: false,
            }]
        );
        assert_eq!(
            output.object_versions,
            vec![ObjectVersionMetadataState {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                version_id: "v1".to_string(),
                is_delete_marker: false,
                is_latest: true,
            }]
        );

        let persisted = load_persisted_metadata_state(state_path.as_path())
            .expect("persisted state should load");
        assert_eq!(persisted.view_id, "view-source");
        assert_eq!(persisted.buckets, output.buckets);
        assert_eq!(persisted.objects, output.objects);
        assert_eq!(persisted.object_versions, output.object_versions);
    }

    #[test]
    fn apply_pending_metadata_repair_plan_to_persisted_state_rejects_target_view_mismatch() {
        let temp = TempDir::new().expect("temp dir");
        let state_path = temp
            .path()
            .join(".maxio-runtime/cluster-metadata-state.json");
        let persisted = PersistedMetadataState {
            view_id: "view-live".to_string(),
            buckets: Vec::new(),
            bucket_tombstones: Vec::new(),
            objects: Vec::new(),
            object_versions: Vec::new(),
        };
        persist_persisted_metadata_state(state_path.as_path(), &persisted)
            .expect("persisted state should save");
        let pending = PendingMetadataRepairPlan::new(
            "repair-view-mismatch",
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
        .expect("pending plan should be valid");

        let result =
            apply_pending_metadata_repair_plan_to_persisted_state(state_path.as_path(), &pending);
        match result {
            Err(PendingMetadataRepairApplyError::Execution(
                MetadataRepairExecutionError::TargetViewMismatch {
                    expected_target_view_id,
                    plan_target_view_id,
                },
            )) => {
                assert_eq!(expected_target_view_id, "view-live");
                assert_eq!(plan_target_view_id, "view-target");
            }
            other => panic!("expected target view mismatch, got {other:?}"),
        }
    }

    #[test]
    fn apply_bucket_metadata_operation_to_persisted_state_bootstraps_and_persists() {
        let temp = TempDir::new().expect("temp dir");
        let state_path = temp
            .path()
            .join(".maxio-runtime/cluster-metadata-state.json");

        let created = apply_bucket_metadata_operation_to_persisted_state(
            state_path.as_path(),
            "view-a",
            &BucketMetadataOperation::CreateBucket {
                bucket: "photos".to_string(),
                at_unix_ms: 10,
            },
        )
        .expect("bucket create should succeed");
        assert_eq!(
            created,
            crate::metadata::state::BucketMetadataOperationOutcome {
                bucket_state: Some(BucketMetadataState {
                    bucket: "photos".to_string(),
                    versioning_enabled: false,
                    lifecycle_enabled: false,
                }),
                tombstone_state: None,
            }
        );

        apply_bucket_metadata_operation_to_persisted_state(
            state_path.as_path(),
            "view-a",
            &BucketMetadataOperation::SetVersioning {
                bucket: "photos".to_string(),
                enabled: true,
            },
        )
        .expect("set versioning should succeed");

        apply_bucket_metadata_operation_to_persisted_state(
            state_path.as_path(),
            "view-a",
            &BucketMetadataOperation::DeleteBucket {
                bucket: "photos".to_string(),
                deleted_at_unix_ms: 20,
                retain_tombstone_for_ms: 15,
            },
        )
        .expect("delete bucket should succeed");

        let persisted = load_persisted_metadata_state(state_path.as_path())
            .expect("persisted state should load");
        assert_eq!(persisted.view_id, "view-a");
        assert!(persisted.buckets.is_empty());
        assert_eq!(
            persisted.bucket_tombstones,
            vec![BucketMetadataTombstoneState {
                bucket: "photos".to_string(),
                deleted_at_unix_ms: 20,
                retain_until_unix_ms: 35,
            }]
        );
    }

    #[test]
    fn apply_bucket_metadata_operation_to_persisted_state_rejects_view_mismatch() {
        let temp = TempDir::new().expect("temp dir");
        let state_path = temp
            .path()
            .join(".maxio-runtime/cluster-metadata-state.json");
        persist_persisted_metadata_state(
            state_path.as_path(),
            &PersistedMetadataState {
                view_id: "view-live".to_string(),
                buckets: vec![BucketMetadataState::new("photos")],
                bucket_tombstones: Vec::new(),
                objects: Vec::new(),
                object_versions: Vec::new(),
            },
        )
        .expect("persisted state should save");

        let result = apply_bucket_metadata_operation_to_persisted_state(
            state_path.as_path(),
            "view-other",
            &BucketMetadataOperation::SetVersioning {
                bucket: "photos".to_string(),
                enabled: true,
            },
        );
        assert!(matches!(
            result,
            Err(PersistedBucketMetadataOperationError::ViewIdMismatch {
                expected_view_id,
                persisted_view_id,
            }) if expected_view_id == "view-other" && persisted_view_id == "view-live"
        ));
    }

    #[test]
    fn apply_bucket_metadata_operation_to_persisted_state_propagates_operation_errors() {
        let temp = TempDir::new().expect("temp dir");
        let state_path = temp
            .path()
            .join(".maxio-runtime/cluster-metadata-state.json");
        let result = apply_bucket_metadata_operation_to_persisted_state(
            state_path.as_path(),
            "view-a",
            &BucketMetadataOperation::SetVersioning {
                bucket: "missing".to_string(),
                enabled: true,
            },
        );
        assert!(matches!(
            result,
            Err(PersistedBucketMetadataOperationError::Operation(
                BucketMetadataOperationError::BucketNotFound
            ))
        ));
    }

    #[test]
    fn apply_object_metadata_operation_to_persisted_state_upserts_and_deletes() {
        let temp = TempDir::new().expect("temp dir");
        let state_path = temp
            .path()
            .join(".maxio-runtime/cluster-metadata-state.json");
        persist_persisted_metadata_state(
            state_path.as_path(),
            &PersistedMetadataState {
                view_id: "view-a".to_string(),
                buckets: vec![BucketMetadataState::new("photos")],
                bucket_tombstones: Vec::new(),
                objects: Vec::new(),
                object_versions: Vec::new(),
            },
        )
        .expect("persisted state should save");

        let upserted = apply_object_metadata_operation_to_persisted_state(
            state_path.as_path(),
            "view-a",
            &ObjectMetadataOperation::UpsertCurrent {
                bucket: "photos".to_string(),
                key: "docs/readme.txt".to_string(),
                latest_version_id: Some("v1".to_string()),
                is_delete_marker: false,
            },
        )
        .expect("object upsert should succeed");
        assert_eq!(
            upserted.object_state,
            Some(ObjectMetadataState {
                bucket: "photos".to_string(),
                key: "docs/readme.txt".to_string(),
                latest_version_id: Some("v1".to_string()),
                is_delete_marker: false,
            })
        );

        apply_object_metadata_operation_to_persisted_state(
            state_path.as_path(),
            "view-a",
            &ObjectMetadataOperation::DeleteCurrent {
                bucket: "photos".to_string(),
                key: "docs/readme.txt".to_string(),
            },
        )
        .expect("object delete should succeed");

        let persisted = load_persisted_metadata_state(state_path.as_path())
            .expect("persisted state should load");
        assert_eq!(persisted.view_id, "view-a");
        assert!(persisted.objects.is_empty());
    }

    #[test]
    fn apply_object_metadata_operation_to_persisted_state_rejects_view_mismatch() {
        let temp = TempDir::new().expect("temp dir");
        let state_path = temp
            .path()
            .join(".maxio-runtime/cluster-metadata-state.json");
        persist_persisted_metadata_state(
            state_path.as_path(),
            &PersistedMetadataState {
                view_id: "view-live".to_string(),
                buckets: vec![BucketMetadataState::new("photos")],
                bucket_tombstones: Vec::new(),
                objects: vec![ObjectMetadataState {
                    bucket: "photos".to_string(),
                    key: "docs/readme.txt".to_string(),
                    latest_version_id: None,
                    is_delete_marker: false,
                }],
                object_versions: Vec::new(),
            },
        )
        .expect("persisted state should save");

        let result = apply_object_metadata_operation_to_persisted_state(
            state_path.as_path(),
            "view-other",
            &ObjectMetadataOperation::UpsertCurrent {
                bucket: "photos".to_string(),
                key: "docs/readme.txt".to_string(),
                latest_version_id: Some("v2".to_string()),
                is_delete_marker: false,
            },
        );
        assert!(matches!(
            result,
            Err(PersistedObjectMetadataOperationError::ViewIdMismatch {
                expected_view_id,
                persisted_view_id,
            }) if expected_view_id == "view-other" && persisted_view_id == "view-live"
        ));
    }

    #[test]
    fn apply_object_version_metadata_operation_to_persisted_state_updates_latest_marker() {
        let temp = TempDir::new().expect("temp dir");
        let state_path = temp
            .path()
            .join(".maxio-runtime/cluster-metadata-state.json");
        persist_persisted_metadata_state(
            state_path.as_path(),
            &PersistedMetadataState {
                view_id: "view-a".to_string(),
                buckets: vec![BucketMetadataState::new("photos")],
                bucket_tombstones: Vec::new(),
                objects: vec![ObjectMetadataState {
                    bucket: "photos".to_string(),
                    key: "docs/readme.txt".to_string(),
                    latest_version_id: Some("v1".to_string()),
                    is_delete_marker: false,
                }],
                object_versions: vec![ObjectVersionMetadataState {
                    bucket: "photos".to_string(),
                    key: "docs/readme.txt".to_string(),
                    version_id: "v1".to_string(),
                    is_delete_marker: false,
                    is_latest: true,
                }],
            },
        )
        .expect("persisted state should save");

        apply_object_version_metadata_operation_to_persisted_state(
            state_path.as_path(),
            "view-a",
            &ObjectVersionMetadataOperation::UpsertVersion {
                bucket: "photos".to_string(),
                key: "docs/readme.txt".to_string(),
                version_id: "v2".to_string(),
                is_delete_marker: false,
                is_latest: true,
            },
        )
        .expect("object version upsert should succeed");

        let persisted = load_persisted_metadata_state(state_path.as_path())
            .expect("persisted state should load");
        assert_eq!(persisted.object_versions.len(), 2);
        let mut v1_latest = None;
        let mut v2_latest = None;
        for version in persisted.object_versions {
            if version.version_id == "v1" {
                v1_latest = Some(version.is_latest);
            } else if version.version_id == "v2" {
                v2_latest = Some(version.is_latest);
            }
        }
        assert_eq!(v1_latest, Some(false));
        assert_eq!(v2_latest, Some(true));
    }

    #[test]
    fn apply_object_version_metadata_operation_to_persisted_state_propagates_operation_errors() {
        let temp = TempDir::new().expect("temp dir");
        let state_path = temp
            .path()
            .join(".maxio-runtime/cluster-metadata-state.json");
        persist_persisted_metadata_state(
            state_path.as_path(),
            &PersistedMetadataState {
                view_id: "view-a".to_string(),
                buckets: vec![BucketMetadataState::new("photos")],
                bucket_tombstones: Vec::new(),
                objects: vec![ObjectMetadataState {
                    bucket: "photos".to_string(),
                    key: "docs/readme.txt".to_string(),
                    latest_version_id: Some("v1".to_string()),
                    is_delete_marker: false,
                }],
                object_versions: Vec::new(),
            },
        )
        .expect("persisted state should save");

        let result = apply_object_version_metadata_operation_to_persisted_state(
            state_path.as_path(),
            "view-a",
            &ObjectVersionMetadataOperation::DeleteVersion {
                bucket: "photos".to_string(),
                key: "docs/readme.txt".to_string(),
                version_id: "v9".to_string(),
            },
        );
        assert!(matches!(
            result,
            Err(PersistedObjectVersionMetadataOperationError::Operation(
                ObjectVersionMetadataOperationError::VersionNotFound
            ))
        ));

        let object_delete_result = apply_object_metadata_operation_to_persisted_state(
            state_path.as_path(),
            "view-a",
            &ObjectMetadataOperation::DeleteCurrent {
                bucket: "photos".to_string(),
                key: "missing.txt".to_string(),
            },
        );
        assert!(matches!(
            object_delete_result,
            Err(PersistedObjectMetadataOperationError::Operation(
                ObjectMetadataOperationError::ObjectNotFound
            ))
        ));
    }

    #[test]
    fn build_queryable_metadata_index_from_persisted_state_rejects_bucket_tombstone_conflict() {
        let state = PersistedMetadataState {
            view_id: "view-a".to_string(),
            buckets: vec![BucketMetadataState {
                bucket: "photos".to_string(),
                versioning_enabled: false,
                lifecycle_enabled: false,
            }],
            bucket_tombstones: vec![BucketMetadataTombstoneState {
                bucket: "photos".to_string(),
                deleted_at_unix_ms: 1,
                retain_until_unix_ms: 2,
            }],
            objects: Vec::new(),
            object_versions: Vec::new(),
        };

        let result = build_queryable_metadata_index_from_persisted_state(&state);
        assert!(matches!(
            result,
            Err(PersistedMetadataQueryableStateError::BucketTombstoneConflict { bucket })
            if bucket == "photos"
        ));
    }

    #[test]
    fn build_queryable_metadata_index_from_persisted_state_rejects_orphan_object_state() {
        let state = PersistedMetadataState {
            view_id: "view-a".to_string(),
            buckets: vec![BucketMetadataState {
                bucket: "videos".to_string(),
                versioning_enabled: false,
                lifecycle_enabled: false,
            }],
            bucket_tombstones: Vec::new(),
            objects: vec![ObjectMetadataState {
                bucket: "photos".to_string(),
                key: "a.txt".to_string(),
                latest_version_id: Some("v1".to_string()),
                is_delete_marker: false,
            }],
            object_versions: Vec::new(),
        };

        let result = build_queryable_metadata_index_from_persisted_state(&state);
        assert!(matches!(
            result,
            Err(PersistedMetadataQueryableStateError::OrphanObjectState { bucket, key })
            if bucket == "photos" && key == "a.txt"
        ));
    }

    #[test]
    fn list_objects_page_from_persisted_state_returns_query_results_for_valid_state() {
        let state = PersistedMetadataState {
            view_id: "view-a".to_string(),
            buckets: vec![BucketMetadataState {
                bucket: "photos".to_string(),
                versioning_enabled: true,
                lifecycle_enabled: false,
            }],
            bucket_tombstones: Vec::new(),
            objects: vec![
                ObjectMetadataState {
                    bucket: "photos".to_string(),
                    key: "docs/a.txt".to_string(),
                    latest_version_id: Some("v1".to_string()),
                    is_delete_marker: false,
                },
                ObjectMetadataState {
                    bucket: "photos".to_string(),
                    key: "docs/b.txt".to_string(),
                    latest_version_id: Some("v2".to_string()),
                    is_delete_marker: false,
                },
            ],
            object_versions: vec![ObjectVersionMetadataState {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                version_id: "v1".to_string(),
                is_delete_marker: false,
                is_latest: true,
            }],
        };
        let query = MetadataQuery::new("photos");

        let page = list_objects_page_from_persisted_state(&state, &query)
            .expect("valid persisted state should list objects");
        assert_eq!(page.objects.len(), 2);
        assert_eq!(page.objects[0].key, "docs/a.txt");
        assert_eq!(page.objects[1].key, "docs/b.txt");
    }

    #[test]
    fn list_objects_page_from_persisted_state_rejects_view_id_mismatch() {
        let state = PersistedMetadataState {
            view_id: "view-a".to_string(),
            buckets: vec![BucketMetadataState {
                bucket: "photos".to_string(),
                versioning_enabled: true,
                lifecycle_enabled: false,
            }],
            bucket_tombstones: Vec::new(),
            objects: vec![ObjectMetadataState {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                latest_version_id: Some("v1".to_string()),
                is_delete_marker: false,
            }],
            object_versions: Vec::new(),
        };
        let mut query = MetadataQuery::new("photos");
        query.view_id = Some("view-b".to_string());

        let result = list_objects_page_from_persisted_state(&state, &query);
        assert_eq!(
            result,
            Err(PersistedMetadataQueryError::ViewIdMismatch {
                expected_view_id: "view-b".to_string(),
                persisted_view_id: "view-a".to_string(),
            })
        );
    }

    #[test]
    fn list_objects_page_from_persisted_state_rejects_empty_persisted_view_id_for_bound_query() {
        let state = PersistedMetadataState {
            view_id: " ".to_string(),
            buckets: vec![BucketMetadataState {
                bucket: "photos".to_string(),
                versioning_enabled: true,
                lifecycle_enabled: false,
            }],
            bucket_tombstones: Vec::new(),
            objects: vec![ObjectMetadataState {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                latest_version_id: Some("v1".to_string()),
                is_delete_marker: false,
            }],
            object_versions: Vec::new(),
        };
        let mut query = MetadataQuery::new("photos");
        query.view_id = Some("view-a".to_string());

        let result = list_objects_page_from_persisted_state(&state, &query);
        assert_eq!(
            result,
            Err(PersistedMetadataQueryError::ViewIdMismatch {
                expected_view_id: "view-a".to_string(),
                persisted_view_id: String::new(),
            })
        );
    }

    #[test]
    fn list_object_versions_page_from_persisted_state_rejects_invalid_state() {
        let state = PersistedMetadataState {
            view_id: "view-a".to_string(),
            buckets: vec![BucketMetadataState {
                bucket: "photos".to_string(),
                versioning_enabled: false,
                lifecycle_enabled: false,
            }],
            bucket_tombstones: vec![BucketMetadataTombstoneState {
                bucket: "photos".to_string(),
                deleted_at_unix_ms: 1,
                retain_until_unix_ms: 2,
            }],
            objects: Vec::new(),
            object_versions: vec![ObjectVersionMetadataState {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                version_id: "v1".to_string(),
                is_delete_marker: false,
                is_latest: true,
            }],
        };
        let query = MetadataVersionsQuery::new("photos");
        let result = list_object_versions_page_from_persisted_state(&state, &query);
        assert_eq!(
            result,
            Err(PersistedMetadataQueryError::InvalidPersistedState(
                PersistedMetadataQueryableStateError::BucketTombstoneConflict {
                    bucket: "photos".to_string(),
                },
            ))
        );
    }

    #[test]
    fn list_object_versions_page_from_persisted_state_rejects_view_id_mismatch() {
        let state = PersistedMetadataState {
            view_id: "view-a".to_string(),
            buckets: vec![BucketMetadataState {
                bucket: "photos".to_string(),
                versioning_enabled: true,
                lifecycle_enabled: false,
            }],
            bucket_tombstones: Vec::new(),
            objects: vec![ObjectMetadataState {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                latest_version_id: Some("v1".to_string()),
                is_delete_marker: false,
            }],
            object_versions: vec![ObjectVersionMetadataState {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                version_id: "v1".to_string(),
                is_delete_marker: false,
                is_latest: true,
            }],
        };
        let mut query = MetadataVersionsQuery::new("photos");
        query.view_id = Some("view-b".to_string());

        let result = list_object_versions_page_from_persisted_state(&state, &query);
        assert_eq!(
            result,
            Err(PersistedMetadataQueryError::ViewIdMismatch {
                expected_view_id: "view-b".to_string(),
                persisted_view_id: "view-a".to_string(),
            })
        );
    }

    #[test]
    fn list_buckets_from_persisted_state_returns_sorted_bucket_results() {
        let state = PersistedMetadataState {
            view_id: "view-a".to_string(),
            buckets: vec![
                BucketMetadataState {
                    bucket: "zeta".to_string(),
                    versioning_enabled: false,
                    lifecycle_enabled: false,
                },
                BucketMetadataState {
                    bucket: "alpha".to_string(),
                    versioning_enabled: true,
                    lifecycle_enabled: true,
                },
            ],
            bucket_tombstones: Vec::new(),
            objects: Vec::new(),
            object_versions: Vec::new(),
        };

        let buckets = list_buckets_from_persisted_state(&state)
            .expect("valid persisted state should list buckets");
        assert_eq!(buckets.len(), 2);
        assert_eq!(buckets[0].bucket, "alpha");
        assert_eq!(buckets[1].bucket, "zeta");
    }

    #[test]
    fn list_buckets_from_persisted_state_with_view_id_rejects_view_id_mismatch() {
        let state = PersistedMetadataState {
            view_id: "view-a".to_string(),
            buckets: vec![BucketMetadataState {
                bucket: "alpha".to_string(),
                versioning_enabled: false,
                lifecycle_enabled: false,
            }],
            bucket_tombstones: Vec::new(),
            objects: Vec::new(),
            object_versions: Vec::new(),
        };

        let result = list_buckets_from_persisted_state_with_view_id(&state, Some("view-b"));
        assert_eq!(
            result,
            Err(PersistedMetadataQueryError::ViewIdMismatch {
                expected_view_id: "view-b".to_string(),
                persisted_view_id: "view-a".to_string(),
            })
        );
    }

    #[test]
    fn list_buckets_from_persisted_state_with_view_id_rejects_empty_persisted_view_id() {
        let state = PersistedMetadataState {
            view_id: "   ".to_string(),
            buckets: vec![BucketMetadataState {
                bucket: "alpha".to_string(),
                versioning_enabled: false,
                lifecycle_enabled: false,
            }],
            bucket_tombstones: Vec::new(),
            objects: Vec::new(),
            object_versions: Vec::new(),
        };

        let result = list_buckets_from_persisted_state_with_view_id(&state, Some("view-a"));
        assert_eq!(
            result,
            Err(PersistedMetadataQueryError::ViewIdMismatch {
                expected_view_id: "view-a".to_string(),
                persisted_view_id: String::new(),
            })
        );
    }

    #[test]
    fn resolve_bucket_metadata_from_persisted_state_returns_present_state() {
        let state = PersistedMetadataState {
            view_id: "view-a".to_string(),
            buckets: vec![BucketMetadataState {
                bucket: "photos".to_string(),
                versioning_enabled: true,
                lifecycle_enabled: false,
            }],
            bucket_tombstones: Vec::new(),
            objects: Vec::new(),
            object_versions: Vec::new(),
        };

        let result = resolve_bucket_metadata_from_persisted_state(&state, "photos", Some("view-a"))
            .expect("view-bound persisted bucket read should succeed");
        assert_eq!(
            result,
            PersistedBucketMetadataReadResolution::Present(BucketMetadataState {
                bucket: "photos".to_string(),
                versioning_enabled: true,
                lifecycle_enabled: false,
            })
        );
    }

    #[test]
    fn resolve_bucket_metadata_from_persisted_state_returns_missing_for_unknown_or_empty_bucket() {
        let state = PersistedMetadataState {
            view_id: "view-a".to_string(),
            buckets: vec![BucketMetadataState {
                bucket: "photos".to_string(),
                versioning_enabled: true,
                lifecycle_enabled: false,
            }],
            bucket_tombstones: Vec::new(),
            objects: Vec::new(),
            object_versions: Vec::new(),
        };

        let unknown = resolve_bucket_metadata_from_persisted_state(&state, "docs", Some("view-a"))
            .expect("unknown bucket should resolve as missing");
        assert_eq!(unknown, PersistedBucketMetadataReadResolution::Missing);

        let empty = resolve_bucket_metadata_from_persisted_state(&state, "   ", Some("view-a"))
            .expect("empty bucket query should resolve as missing");
        assert_eq!(empty, PersistedBucketMetadataReadResolution::Missing);
    }

    #[test]
    fn resolve_bucket_metadata_from_persisted_state_rejects_view_id_mismatch() {
        let state = PersistedMetadataState {
            view_id: "view-a".to_string(),
            buckets: vec![BucketMetadataState {
                bucket: "photos".to_string(),
                versioning_enabled: true,
                lifecycle_enabled: false,
            }],
            bucket_tombstones: Vec::new(),
            objects: Vec::new(),
            object_versions: Vec::new(),
        };

        let result = resolve_bucket_metadata_from_persisted_state(&state, "photos", Some("view-b"));
        assert_eq!(
            result,
            Err(PersistedMetadataQueryError::ViewIdMismatch {
                expected_view_id: "view-b".to_string(),
                persisted_view_id: "view-a".to_string(),
            })
        );
    }

    #[test]
    fn resolve_bucket_presence_from_persisted_state_returns_present_when_bucket_exists() {
        let state = PersistedMetadataState {
            view_id: "view-a".to_string(),
            buckets: vec![BucketMetadataState {
                bucket: "photos".to_string(),
                versioning_enabled: true,
                lifecycle_enabled: false,
            }],
            bucket_tombstones: vec![BucketMetadataTombstoneState {
                bucket: "archive".to_string(),
                deleted_at_unix_ms: 1,
                retain_until_unix_ms: 2,
            }],
            objects: Vec::new(),
            object_versions: Vec::new(),
        };

        let result = resolve_bucket_presence_from_persisted_state(&state, "photos", Some("view-a"))
            .expect("view-bound persisted bucket presence read should succeed");
        assert_eq!(
            result,
            PersistedBucketPresenceReadResolution::Present(BucketMetadataState {
                bucket: "photos".to_string(),
                versioning_enabled: true,
                lifecycle_enabled: false,
            })
        );
    }

    #[test]
    fn resolve_bucket_presence_from_persisted_state_returns_tombstoned_for_deleted_bucket() {
        let state = PersistedMetadataState {
            view_id: "view-a".to_string(),
            buckets: vec![BucketMetadataState {
                bucket: "photos".to_string(),
                versioning_enabled: true,
                lifecycle_enabled: false,
            }],
            bucket_tombstones: vec![BucketMetadataTombstoneState {
                bucket: "archive".to_string(),
                deleted_at_unix_ms: 111,
                retain_until_unix_ms: 222,
            }],
            objects: Vec::new(),
            object_versions: Vec::new(),
        };

        let result =
            resolve_bucket_presence_from_persisted_state(&state, "archive", Some("view-a"))
                .expect("view-bound persisted tombstone read should succeed");
        assert_eq!(
            result,
            PersistedBucketPresenceReadResolution::Tombstoned(BucketMetadataTombstoneState {
                bucket: "archive".to_string(),
                deleted_at_unix_ms: 111,
                retain_until_unix_ms: 222,
            })
        );
    }

    #[test]
    fn resolve_bucket_presence_from_persisted_state_returns_missing_for_unknown_or_empty_bucket() {
        let state = PersistedMetadataState {
            view_id: "view-a".to_string(),
            buckets: vec![BucketMetadataState {
                bucket: "photos".to_string(),
                versioning_enabled: true,
                lifecycle_enabled: false,
            }],
            bucket_tombstones: vec![BucketMetadataTombstoneState {
                bucket: "archive".to_string(),
                deleted_at_unix_ms: 111,
                retain_until_unix_ms: 222,
            }],
            objects: Vec::new(),
            object_versions: Vec::new(),
        };

        let unknown = resolve_bucket_presence_from_persisted_state(&state, "docs", Some("view-a"))
            .expect("unknown bucket should resolve as missing");
        assert_eq!(unknown, PersistedBucketPresenceReadResolution::Missing);

        let empty = resolve_bucket_presence_from_persisted_state(&state, "   ", Some("view-a"))
            .expect("empty bucket should resolve as missing");
        assert_eq!(empty, PersistedBucketPresenceReadResolution::Missing);
    }

    #[test]
    fn resolve_bucket_presence_from_persisted_state_rejects_view_id_mismatch() {
        let state = PersistedMetadataState {
            view_id: "view-a".to_string(),
            buckets: vec![BucketMetadataState {
                bucket: "photos".to_string(),
                versioning_enabled: true,
                lifecycle_enabled: false,
            }],
            bucket_tombstones: vec![BucketMetadataTombstoneState {
                bucket: "archive".to_string(),
                deleted_at_unix_ms: 111,
                retain_until_unix_ms: 222,
            }],
            objects: Vec::new(),
            object_versions: Vec::new(),
        };

        let result =
            resolve_bucket_presence_from_persisted_state(&state, "archive", Some("view-b"));
        assert_eq!(
            result,
            Err(PersistedMetadataQueryError::ViewIdMismatch {
                expected_view_id: "view-b".to_string(),
                persisted_view_id: "view-a".to_string(),
            })
        );
    }

    #[test]
    fn resolve_bucket_mutation_preconditions_from_persisted_state_resolves_tombstone_retention_state(
    ) {
        let state = PersistedMetadataState {
            view_id: "view-a".to_string(),
            buckets: vec![BucketMetadataState {
                bucket: "present".to_string(),
                versioning_enabled: false,
                lifecycle_enabled: false,
            }],
            bucket_tombstones: vec![
                BucketMetadataTombstoneState {
                    bucket: "active".to_string(),
                    deleted_at_unix_ms: 100,
                    retain_until_unix_ms: 1_000,
                },
                BucketMetadataTombstoneState {
                    bucket: "expired".to_string(),
                    deleted_at_unix_ms: 100,
                    retain_until_unix_ms: 200,
                },
            ],
            objects: Vec::new(),
            object_versions: Vec::new(),
        };

        let present = resolve_bucket_mutation_preconditions_from_persisted_state(
            &state,
            "present",
            Some("view-a"),
            500,
        )
        .expect("present bucket should resolve");
        assert!(matches!(
            present,
            PersistedBucketMutationPreconditionResolution::Present(BucketMetadataState { ref bucket, .. }) if bucket == "present"
        ));

        let active = resolve_bucket_mutation_preconditions_from_persisted_state(
            &state,
            "active",
            Some("view-a"),
            500,
        )
        .expect("active tombstone should resolve");
        assert_eq!(
            active,
            PersistedBucketMutationPreconditionResolution::Tombstoned {
                tombstone: BucketMetadataTombstoneState {
                    bucket: "active".to_string(),
                    deleted_at_unix_ms: 100,
                    retain_until_unix_ms: 1_000,
                },
                retention_active: true,
            }
        );

        let expired = resolve_bucket_mutation_preconditions_from_persisted_state(
            &state,
            "expired",
            Some("view-a"),
            500,
        )
        .expect("expired tombstone should resolve");
        assert_eq!(
            expired,
            PersistedBucketMutationPreconditionResolution::Tombstoned {
                tombstone: BucketMetadataTombstoneState {
                    bucket: "expired".to_string(),
                    deleted_at_unix_ms: 100,
                    retain_until_unix_ms: 200,
                },
                retention_active: false,
            }
        );

        let missing = resolve_bucket_mutation_preconditions_from_persisted_state(
            &state,
            "missing",
            Some("view-a"),
            500,
        )
        .expect("missing bucket should resolve");
        assert_eq!(
            missing,
            PersistedBucketMutationPreconditionResolution::Missing
        );
    }

    #[test]
    fn resolve_bucket_mutation_preconditions_from_persisted_state_rejects_view_id_mismatch() {
        let state = PersistedMetadataState {
            view_id: "view-a".to_string(),
            buckets: Vec::new(),
            bucket_tombstones: vec![BucketMetadataTombstoneState {
                bucket: "archive".to_string(),
                deleted_at_unix_ms: 111,
                retain_until_unix_ms: 222,
            }],
            objects: Vec::new(),
            object_versions: Vec::new(),
        };

        let result = resolve_bucket_mutation_preconditions_from_persisted_state(
            &state,
            "archive",
            Some("view-b"),
            150,
        );
        assert_eq!(
            result,
            Err(PersistedMetadataQueryError::ViewIdMismatch {
                expected_view_id: "view-b".to_string(),
                persisted_view_id: "view-a".to_string(),
            })
        );
    }

    #[test]
    fn resolve_object_metadata_from_persisted_state_returns_present_state() {
        let state = PersistedMetadataState {
            view_id: "view-a".to_string(),
            buckets: vec![BucketMetadataState {
                bucket: "photos".to_string(),
                versioning_enabled: true,
                lifecycle_enabled: false,
            }],
            bucket_tombstones: Vec::new(),
            objects: vec![ObjectMetadataState {
                bucket: "photos".to_string(),
                key: "dog.jpg".to_string(),
                latest_version_id: Some("v3".to_string()),
                is_delete_marker: false,
            }],
            object_versions: Vec::new(),
        };

        let result = resolve_object_metadata_from_persisted_state(
            &state,
            "photos",
            "dog.jpg",
            Some("view-a"),
        )
        .expect("view-bound persisted object read should succeed");
        assert_eq!(
            result,
            PersistedObjectMetadataReadResolution::Present(ObjectMetadataState {
                bucket: "photos".to_string(),
                key: "dog.jpg".to_string(),
                latest_version_id: Some("v3".to_string()),
                is_delete_marker: false,
            })
        );
    }

    #[test]
    fn resolve_object_metadata_from_persisted_state_returns_missing_for_unknown_or_empty_identity()
    {
        let state = PersistedMetadataState {
            view_id: "view-a".to_string(),
            buckets: vec![BucketMetadataState {
                bucket: "photos".to_string(),
                versioning_enabled: true,
                lifecycle_enabled: false,
            }],
            bucket_tombstones: Vec::new(),
            objects: vec![ObjectMetadataState {
                bucket: "photos".to_string(),
                key: "dog.jpg".to_string(),
                latest_version_id: Some("v3".to_string()),
                is_delete_marker: false,
            }],
            object_versions: Vec::new(),
        };

        let unknown = resolve_object_metadata_from_persisted_state(
            &state,
            "photos",
            "cat.jpg",
            Some("view-a"),
        )
        .expect("unknown object should resolve as missing");
        assert_eq!(unknown, PersistedObjectMetadataReadResolution::Missing);

        let empty_key =
            resolve_object_metadata_from_persisted_state(&state, "photos", "   ", Some("view-a"))
                .expect("empty key should resolve as missing");
        assert_eq!(empty_key, PersistedObjectMetadataReadResolution::Missing);
    }

    #[test]
    fn resolve_object_metadata_from_persisted_state_rejects_view_id_mismatch() {
        let state = PersistedMetadataState {
            view_id: "view-a".to_string(),
            buckets: vec![BucketMetadataState {
                bucket: "photos".to_string(),
                versioning_enabled: true,
                lifecycle_enabled: false,
            }],
            bucket_tombstones: Vec::new(),
            objects: vec![ObjectMetadataState {
                bucket: "photos".to_string(),
                key: "dog.jpg".to_string(),
                latest_version_id: Some("v3".to_string()),
                is_delete_marker: false,
            }],
            object_versions: Vec::new(),
        };

        let result = resolve_object_metadata_from_persisted_state(
            &state,
            "photos",
            "dog.jpg",
            Some("view-b"),
        );
        assert_eq!(
            result,
            Err(PersistedMetadataQueryError::ViewIdMismatch {
                expected_view_id: "view-b".to_string(),
                persisted_view_id: "view-a".to_string(),
            })
        );
    }

    #[test]
    fn resolve_object_version_metadata_from_persisted_state_returns_present_state() {
        let state = PersistedMetadataState {
            view_id: "view-a".to_string(),
            buckets: vec![BucketMetadataState {
                bucket: "photos".to_string(),
                versioning_enabled: true,
                lifecycle_enabled: false,
            }],
            bucket_tombstones: Vec::new(),
            objects: vec![ObjectMetadataState {
                bucket: "photos".to_string(),
                key: "dog.jpg".to_string(),
                latest_version_id: Some("v3".to_string()),
                is_delete_marker: false,
            }],
            object_versions: vec![ObjectVersionMetadataState {
                bucket: "photos".to_string(),
                key: "dog.jpg".to_string(),
                version_id: "v3".to_string(),
                is_delete_marker: false,
                is_latest: true,
            }],
        };

        let result = resolve_object_version_metadata_from_persisted_state(
            &state,
            "photos",
            "dog.jpg",
            "v3",
            Some("view-a"),
        )
        .expect("view-bound persisted object-version read should succeed");
        assert_eq!(
            result,
            PersistedObjectVersionMetadataReadResolution::Present(ObjectVersionMetadataState {
                bucket: "photos".to_string(),
                key: "dog.jpg".to_string(),
                version_id: "v3".to_string(),
                is_delete_marker: false,
                is_latest: true,
            })
        );
    }

    #[test]
    fn resolve_object_version_metadata_from_persisted_state_returns_missing_for_unknown_or_empty_identity()
     {
        let state = PersistedMetadataState {
            view_id: "view-a".to_string(),
            buckets: vec![BucketMetadataState {
                bucket: "photos".to_string(),
                versioning_enabled: true,
                lifecycle_enabled: false,
            }],
            bucket_tombstones: Vec::new(),
            objects: vec![ObjectMetadataState {
                bucket: "photos".to_string(),
                key: "dog.jpg".to_string(),
                latest_version_id: Some("v3".to_string()),
                is_delete_marker: false,
            }],
            object_versions: vec![ObjectVersionMetadataState {
                bucket: "photos".to_string(),
                key: "dog.jpg".to_string(),
                version_id: "v3".to_string(),
                is_delete_marker: false,
                is_latest: true,
            }],
        };

        let unknown = resolve_object_version_metadata_from_persisted_state(
            &state,
            "photos",
            "dog.jpg",
            "v2",
            Some("view-a"),
        )
        .expect("unknown object version should resolve as missing");
        assert_eq!(
            unknown,
            PersistedObjectVersionMetadataReadResolution::Missing
        );

        let empty_version = resolve_object_version_metadata_from_persisted_state(
            &state,
            "photos",
            "dog.jpg",
            "   ",
            Some("view-a"),
        )
        .expect("empty version id should resolve as missing");
        assert_eq!(
            empty_version,
            PersistedObjectVersionMetadataReadResolution::Missing
        );
    }

    #[test]
    fn resolve_object_version_metadata_from_persisted_state_rejects_view_id_mismatch() {
        let state = PersistedMetadataState {
            view_id: "view-a".to_string(),
            buckets: vec![BucketMetadataState {
                bucket: "photos".to_string(),
                versioning_enabled: true,
                lifecycle_enabled: false,
            }],
            bucket_tombstones: Vec::new(),
            objects: vec![ObjectMetadataState {
                bucket: "photos".to_string(),
                key: "dog.jpg".to_string(),
                latest_version_id: Some("v3".to_string()),
                is_delete_marker: false,
            }],
            object_versions: vec![ObjectVersionMetadataState {
                bucket: "photos".to_string(),
                key: "dog.jpg".to_string(),
                version_id: "v3".to_string(),
                is_delete_marker: false,
                is_latest: true,
            }],
        };

        let result = resolve_object_version_metadata_from_persisted_state(
            &state,
            "photos",
            "dog.jpg",
            "v3",
            Some("view-b"),
        );
        assert_eq!(
            result,
            Err(PersistedMetadataQueryError::ViewIdMismatch {
                expected_view_id: "view-b".to_string(),
                persisted_view_id: "view-a".to_string(),
            })
        );
    }
}
