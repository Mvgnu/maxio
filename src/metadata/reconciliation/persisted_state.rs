use std::collections::{BTreeMap, BTreeSet};
use std::io::ErrorKind;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use super::*;

fn materialized_source_metadata_from_plan(
    plan: &MetadataRepairPlan,
) -> MetadataRepairExecutionOutput {
    let mut bucket_map: BTreeMap<String, BucketMetadataState> = BTreeMap::new();
    let mut bucket_lifecycle_configuration_map: BTreeMap<
        String,
        BucketLifecycleConfigurationState,
    > = BTreeMap::new();
    let mut bucket_tombstone_map: BTreeMap<String, BucketMetadataTombstoneState> = BTreeMap::new();
    let mut object_map: BTreeMap<(String, String), ObjectMetadataState> = BTreeMap::new();
    let mut object_version_map: BTreeMap<(String, String, String), ObjectVersionMetadataState> =
        BTreeMap::new();

    for action in &plan.actions {
        match action {
            MetadataReconcileAction::UpsertBucket {
                bucket,
                versioning_enabled,
                lifecycle_enabled,
            } => {
                bucket_map.insert(
                    bucket.clone(),
                    BucketMetadataState {
                        bucket: bucket.clone(),
                        versioning_enabled: *versioning_enabled,
                        lifecycle_enabled: *lifecycle_enabled,
                    },
                );
                bucket_tombstone_map.remove(bucket);
            }
            MetadataReconcileAction::DeleteBucket { bucket } => {
                bucket_map.remove(bucket);
                bucket_lifecycle_configuration_map.remove(bucket);
            }
            MetadataReconcileAction::UpsertBucketLifecycleConfiguration {
                bucket,
                configuration_xml,
                updated_at_unix_ms,
            } => {
                bucket_lifecycle_configuration_map.insert(
                    bucket.clone(),
                    BucketLifecycleConfigurationState {
                        bucket: bucket.clone(),
                        configuration_xml: configuration_xml.clone(),
                        updated_at_unix_ms: *updated_at_unix_ms,
                    },
                );
            }
            MetadataReconcileAction::DeleteBucketLifecycleConfiguration { bucket } => {
                bucket_lifecycle_configuration_map.remove(bucket);
            }
            MetadataReconcileAction::UpsertBucketTombstone {
                bucket,
                deleted_at_unix_ms,
                retain_until_unix_ms,
            } => {
                bucket_tombstone_map.insert(
                    bucket.clone(),
                    BucketMetadataTombstoneState {
                        bucket: bucket.clone(),
                        deleted_at_unix_ms: *deleted_at_unix_ms,
                        retain_until_unix_ms: *retain_until_unix_ms,
                    },
                );
                bucket_map.remove(bucket);
                bucket_lifecycle_configuration_map.remove(bucket);
            }
            MetadataReconcileAction::DeleteBucketTombstone { bucket } => {
                bucket_tombstone_map.remove(bucket);
            }
            MetadataReconcileAction::UpsertObject {
                bucket,
                key,
                version_id,
            } => {
                object_map.insert(
                    (bucket.clone(), key.clone()),
                    ObjectMetadataState {
                        bucket: bucket.clone(),
                        key: key.clone(),
                        latest_version_id: version_id.clone(),
                        is_delete_marker: false,
                    },
                );
            }
            MetadataReconcileAction::TombstoneObject {
                bucket,
                key,
                version_id,
            } => {
                object_map.insert(
                    (bucket.clone(), key.clone()),
                    ObjectMetadataState {
                        bucket: bucket.clone(),
                        key: key.clone(),
                        latest_version_id: version_id.clone(),
                        is_delete_marker: true,
                    },
                );
            }
            MetadataReconcileAction::UpsertObjectVersion {
                bucket,
                key,
                version_id,
                is_delete_marker,
                is_latest,
            } => {
                object_version_map.insert(
                    (bucket.clone(), key.clone(), version_id.clone()),
                    ObjectVersionMetadataState {
                        bucket: bucket.clone(),
                        key: key.clone(),
                        version_id: version_id.clone(),
                        is_delete_marker: *is_delete_marker,
                        is_latest: *is_latest,
                    },
                );
            }
            MetadataReconcileAction::DeleteObjectVersion {
                bucket,
                key,
                version_id,
            } => {
                object_version_map.remove(&(bucket.clone(), key.clone(), version_id.clone()));
            }
        }
    }

    MetadataRepairExecutionOutput {
        buckets: bucket_map.into_values().collect(),
        bucket_lifecycle_configurations: bucket_lifecycle_configuration_map.into_values().collect(),
        bucket_tombstones: bucket_tombstone_map.into_values().collect(),
        objects: object_map.into_values().collect(),
        object_versions: object_version_map.into_values().collect(),
    }
}

pub fn apply_pending_metadata_repair_plan_to_persisted_state(
    path: &Path,
    pending_plan: &PendingMetadataRepairPlan,
) -> Result<MetadataRepairExecutionOutput, PendingMetadataRepairApplyError> {
    let mut persisted_state =
        load_persisted_metadata_state(path).map_err(PendingMetadataRepairApplyError::StateLoad)?;
    let source_state = materialized_source_metadata_from_plan(&pending_plan.plan);

    let expected_target_view_id = if persisted_state.view_id.trim().is_empty() {
        pending_plan.plan.target_view_id.as_str()
    } else {
        persisted_state.view_id.as_str()
    };

    let applied = apply_metadata_repair_plan_with_lifecycle_configs(
        pending_plan.plan.source_view_id.as_str(),
        expected_target_view_id,
        &pending_plan.plan,
        MetadataRepairInputs {
            source_buckets: &source_state.buckets,
            target_buckets: &persisted_state.buckets,
            source_bucket_tombstones: &source_state.bucket_tombstones,
            target_bucket_tombstones: &persisted_state.bucket_tombstones,
            source_objects: &source_state.objects,
            target_objects: &persisted_state.objects,
            source_object_versions: &source_state.object_versions,
            target_object_versions: &persisted_state.object_versions,
        },
        &source_state.bucket_lifecycle_configurations,
        &persisted_state.bucket_lifecycle_configurations,
    )
    .map_err(PendingMetadataRepairApplyError::Execution)?;

    persisted_state.view_id = pending_plan.plan.source_view_id.trim().to_string();
    persisted_state.buckets = applied.buckets.clone();
    let valid_buckets: BTreeSet<String> = applied
        .buckets
        .iter()
        .map(|bucket| bucket.bucket.clone())
        .collect();
    persisted_state.bucket_lifecycle_configurations = applied
        .bucket_lifecycle_configurations
        .iter()
        .filter(|entry| valid_buckets.contains(&entry.bucket))
        .cloned()
        .collect();
    persisted_state.bucket_tombstones = applied.bucket_tombstones.clone();
    persisted_state.objects = applied.objects.clone();
    persisted_state.object_versions = applied.object_versions.clone();
    persist_persisted_metadata_state(path, &persisted_state)
        .map_err(PendingMetadataRepairApplyError::StatePersist)?;

    Ok(applied)
}

pub fn classify_pending_metadata_repair_apply_error(
    error: &PendingMetadataRepairApplyError,
) -> PendingMetadataRepairApplyFailure {
    match error {
        PendingMetadataRepairApplyError::StateLoad(source) => {
            PendingMetadataRepairApplyFailure::transient_with_reason(
                "persisted-state-load-failed",
                source.to_string(),
            )
        }
        PendingMetadataRepairApplyError::StatePersist(source) => {
            PendingMetadataRepairApplyFailure::transient_with_reason(
                "persisted-state-persist-failed",
                source.to_string(),
            )
        }
        PendingMetadataRepairApplyError::Execution(source) => {
            PendingMetadataRepairApplyFailure::permanent_with_reason(
                source.canonical_reason(),
                format!("metadata repair execution is not applicable to current state: {source:?}"),
            )
        }
    }
}

pub fn apply_pending_metadata_repair_plan_to_persisted_state_classified(
    path: &Path,
    pending_plan: &PendingMetadataRepairPlan,
) -> Result<MetadataRepairExecutionOutput, PendingMetadataRepairApplyFailure> {
    apply_pending_metadata_repair_plan_to_persisted_state(path, pending_plan)
        .map_err(|error| classify_pending_metadata_repair_apply_error(&error))
}

fn operation_bucket_name(operation: &BucketMetadataOperation) -> &str {
    match operation {
        BucketMetadataOperation::CreateBucket { bucket, .. }
        | BucketMetadataOperation::DeleteBucket { bucket, .. }
        | BucketMetadataOperation::SetVersioning { bucket, .. }
        | BucketMetadataOperation::SetLifecycle { bucket, .. } => bucket.as_str(),
    }
}

fn operation_bucket_lifecycle_configuration_name(
    operation: &BucketLifecycleConfigurationOperation,
) -> &str {
    match operation {
        BucketLifecycleConfigurationOperation::UpsertConfiguration { bucket, .. }
        | BucketLifecycleConfigurationOperation::DeleteConfiguration { bucket } => bucket.as_str(),
    }
}

fn operation_object_identity(operation: &ObjectMetadataOperation) -> (&str, &str) {
    match operation {
        ObjectMetadataOperation::UpsertCurrent { bucket, key, .. }
        | ObjectMetadataOperation::DeleteCurrent { bucket, key } => (bucket.as_str(), key.as_str()),
    }
}

fn operation_object_version_identity(
    operation: &ObjectVersionMetadataOperation,
) -> (&str, &str, &str) {
    match operation {
        ObjectVersionMetadataOperation::UpsertVersion {
            bucket,
            key,
            version_id,
            ..
        }
        | ObjectVersionMetadataOperation::DeleteVersion {
            bucket,
            key,
            version_id,
        } => (bucket.as_str(), key.as_str(), version_id.as_str()),
    }
}

pub fn apply_bucket_metadata_operation_to_persisted_state(
    path: &Path,
    expected_view_id: &str,
    operation: &BucketMetadataOperation,
) -> Result<BucketMetadataOperationOutcome, PersistedBucketMetadataOperationError> {
    let expected_view_id = expected_view_id.trim();
    if expected_view_id.is_empty() {
        return Err(PersistedBucketMetadataOperationError::InvalidExpectedViewId);
    }

    let mut persisted_state = load_persisted_metadata_state(path)
        .map_err(PersistedBucketMetadataOperationError::StateLoad)?;
    validate_persisted_metadata_state_for_query(&persisted_state)
        .map_err(PersistedBucketMetadataOperationError::InvalidPersistedState)?;

    let persisted_view_id = persisted_state.view_id.trim();
    if !persisted_view_id.is_empty() && persisted_view_id != expected_view_id {
        return Err(PersistedBucketMetadataOperationError::ViewIdMismatch {
            expected_view_id: expected_view_id.to_string(),
            persisted_view_id: persisted_view_id.to_string(),
        });
    }

    let mut bucket_map: BTreeMap<String, BucketMetadataState> = persisted_state
        .buckets
        .into_iter()
        .map(|state| (state.bucket.clone(), state))
        .collect();
    let mut lifecycle_configuration_map: BTreeMap<String, BucketLifecycleConfigurationState> =
        persisted_state
            .bucket_lifecycle_configurations
            .into_iter()
            .map(|state| (state.bucket.clone(), state))
            .collect();
    let mut tombstone_map: BTreeMap<String, BucketMetadataTombstoneState> = persisted_state
        .bucket_tombstones
        .into_iter()
        .map(|state| (state.bucket.clone(), state))
        .collect();

    let operation_bucket = operation_bucket_name(operation);
    let outcome = apply_bucket_metadata_operation(
        bucket_map.get(operation_bucket),
        tombstone_map.get(operation_bucket),
        operation,
    )
    .map_err(PersistedBucketMetadataOperationError::Operation)?;

    if let Some(next_bucket_state) = outcome.bucket_state.clone() {
        bucket_map.insert(next_bucket_state.bucket.clone(), next_bucket_state);
    } else {
        bucket_map.remove(operation_bucket);
    }

    if let Some(next_tombstone_state) = outcome.tombstone_state.clone() {
        tombstone_map.insert(next_tombstone_state.bucket.clone(), next_tombstone_state);
    } else {
        tombstone_map.remove(operation_bucket);
    }
    if outcome.bucket_state.is_none() {
        lifecycle_configuration_map.remove(operation_bucket);
    }

    persisted_state.view_id = expected_view_id.to_string();
    persisted_state.buckets = bucket_map.into_values().collect();
    persisted_state.bucket_lifecycle_configurations =
        lifecycle_configuration_map.into_values().collect();
    persisted_state.bucket_tombstones = tombstone_map.into_values().collect();
    persist_persisted_metadata_state(path, &persisted_state)
        .map_err(PersistedBucketMetadataOperationError::StatePersist)?;
    Ok(outcome)
}

pub fn apply_bucket_lifecycle_configuration_operation_to_persisted_state(
    path: &Path,
    expected_view_id: &str,
    operation: &BucketLifecycleConfigurationOperation,
) -> Result<
    BucketLifecycleConfigurationOperationOutcome,
    PersistedBucketLifecycleConfigurationOperationError,
> {
    let expected_view_id = expected_view_id.trim();
    if expected_view_id.is_empty() {
        return Err(PersistedBucketLifecycleConfigurationOperationError::InvalidExpectedViewId);
    }

    let mut persisted_state = load_persisted_metadata_state(path)
        .map_err(PersistedBucketLifecycleConfigurationOperationError::StateLoad)?;
    validate_persisted_metadata_state_for_query(&persisted_state)
        .map_err(PersistedBucketLifecycleConfigurationOperationError::InvalidPersistedState)?;

    let persisted_view_id = persisted_state.view_id.trim();
    if !persisted_view_id.is_empty() && persisted_view_id != expected_view_id {
        return Err(
            PersistedBucketLifecycleConfigurationOperationError::ViewIdMismatch {
                expected_view_id: expected_view_id.to_string(),
                persisted_view_id: persisted_view_id.to_string(),
            },
        );
    }

    let operation_bucket = operation_bucket_lifecycle_configuration_name(operation);
    let bucket_exists = persisted_state
        .buckets
        .iter()
        .any(|state| state.bucket == operation_bucket);
    let current_state = persisted_state
        .bucket_lifecycle_configurations
        .iter()
        .find(|state| state.bucket == operation_bucket);
    let outcome =
        apply_bucket_lifecycle_configuration_operation(current_state, bucket_exists, operation)
            .map_err(PersistedBucketLifecycleConfigurationOperationError::Operation)?;

    match outcome.configuration_state.clone() {
        Some(next_state) => {
            if let Some(existing) = persisted_state
                .bucket_lifecycle_configurations
                .iter_mut()
                .find(|state| state.bucket == operation_bucket)
            {
                *existing = next_state;
            } else {
                persisted_state
                    .bucket_lifecycle_configurations
                    .push(next_state);
            }
        }
        None => {
            persisted_state
                .bucket_lifecycle_configurations
                .retain(|state| state.bucket != operation_bucket);
        }
    }

    persisted_state.view_id = expected_view_id.to_string();
    persist_persisted_metadata_state(path, &persisted_state)
        .map_err(PersistedBucketLifecycleConfigurationOperationError::StatePersist)?;
    Ok(outcome)
}

pub fn apply_object_metadata_operation_to_persisted_state(
    path: &Path,
    expected_view_id: &str,
    operation: &ObjectMetadataOperation,
) -> Result<ObjectMetadataOperationOutcome, PersistedObjectMetadataOperationError> {
    let expected_view_id = expected_view_id.trim();
    if expected_view_id.is_empty() {
        return Err(PersistedObjectMetadataOperationError::InvalidExpectedViewId);
    }

    let mut persisted_state = load_persisted_metadata_state(path)
        .map_err(PersistedObjectMetadataOperationError::StateLoad)?;
    validate_persisted_metadata_state_for_query(&persisted_state)
        .map_err(PersistedObjectMetadataOperationError::InvalidPersistedState)?;

    let persisted_view_id = persisted_state.view_id.trim();
    if !persisted_view_id.is_empty() && persisted_view_id != expected_view_id {
        return Err(PersistedObjectMetadataOperationError::ViewIdMismatch {
            expected_view_id: expected_view_id.to_string(),
            persisted_view_id: persisted_view_id.to_string(),
        });
    }

    let (bucket, key) = operation_object_identity(operation);
    let current_state = persisted_state
        .objects
        .iter()
        .find(|state| state.bucket == bucket && state.key == key);
    let outcome = apply_object_metadata_operation(current_state, operation)
        .map_err(PersistedObjectMetadataOperationError::Operation)?;

    match outcome.object_state.clone() {
        Some(next_state) => {
            if let Some(existing) = persisted_state
                .objects
                .iter_mut()
                .find(|state| state.bucket == bucket && state.key == key)
            {
                *existing = next_state;
            } else {
                persisted_state.objects.push(next_state);
            }
        }
        None => {
            persisted_state
                .objects
                .retain(|state| !(state.bucket == bucket && state.key == key));
        }
    }

    persisted_state.view_id = expected_view_id.to_string();
    persist_persisted_metadata_state(path, &persisted_state)
        .map_err(PersistedObjectMetadataOperationError::StatePersist)?;
    Ok(outcome)
}

pub fn apply_object_version_metadata_operation_to_persisted_state(
    path: &Path,
    expected_view_id: &str,
    operation: &ObjectVersionMetadataOperation,
) -> Result<ObjectVersionMetadataOperationOutcome, PersistedObjectVersionMetadataOperationError> {
    let expected_view_id = expected_view_id.trim();
    if expected_view_id.is_empty() {
        return Err(PersistedObjectVersionMetadataOperationError::InvalidExpectedViewId);
    }

    let mut persisted_state = load_persisted_metadata_state(path)
        .map_err(PersistedObjectVersionMetadataOperationError::StateLoad)?;
    validate_persisted_metadata_state_for_query(&persisted_state)
        .map_err(PersistedObjectVersionMetadataOperationError::InvalidPersistedState)?;

    let persisted_view_id = persisted_state.view_id.trim();
    if !persisted_view_id.is_empty() && persisted_view_id != expected_view_id {
        return Err(
            PersistedObjectVersionMetadataOperationError::ViewIdMismatch {
                expected_view_id: expected_view_id.to_string(),
                persisted_view_id: persisted_view_id.to_string(),
            },
        );
    }

    let (bucket, key, version_id) = operation_object_version_identity(operation);
    let current_state = persisted_state
        .object_versions
        .iter()
        .find(|state| state.bucket == bucket && state.key == key && state.version_id == version_id);
    let outcome = apply_object_version_metadata_operation(current_state, operation)
        .map_err(PersistedObjectVersionMetadataOperationError::Operation)?;

    match outcome.version_state.clone() {
        Some(next_state) => {
            if next_state.is_latest {
                for state in &mut persisted_state.object_versions {
                    if state.bucket == next_state.bucket && state.key == next_state.key {
                        state.is_latest = false;
                    }
                }
            }

            if let Some(existing) = persisted_state.object_versions.iter_mut().find(|state| {
                state.bucket == bucket && state.key == key && state.version_id == version_id
            }) {
                *existing = next_state;
            } else {
                persisted_state.object_versions.push(next_state);
            }
        }
        None => {
            persisted_state.object_versions.retain(|state| {
                !(state.bucket == bucket && state.key == key && state.version_id == version_id)
            });
        }
    }

    persisted_state.view_id = expected_view_id.to_string();
    persist_persisted_metadata_state(path, &persisted_state)
        .map_err(PersistedObjectVersionMetadataOperationError::StatePersist)?;
    Ok(outcome)
}

pub fn load_persisted_metadata_state(path: &Path) -> std::io::Result<PersistedMetadataState> {
    match std::fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str::<PersistedMetadataState>(&raw)
            .map_err(|error| std::io::Error::new(ErrorKind::InvalidData, error)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(PersistedMetadataState::default()),
        Err(error) => Err(error),
    }
}

pub fn persist_persisted_metadata_state(
    path: &Path,
    state: &PersistedMetadataState,
) -> std::io::Result<()> {
    let Some(parent) = path.parent() else {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "persisted metadata state path must include parent directory",
        ));
    };
    std::fs::create_dir_all(parent)?;
    let payload = serde_json::to_vec_pretty(state)
        .map_err(|error| std::io::Error::new(ErrorKind::InvalidData, error))?;
    let nanos_since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let temp_file_name = format!(
        ".{}.tmp-{}-{}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("cluster-metadata-state"),
        std::process::id(),
        nanos_since_epoch
    );
    let temp_path = parent.join(temp_file_name);
    let mut temp_file = std::fs::File::create(&temp_path)?;
    temp_file.write_all(payload.as_slice())?;
    temp_file.sync_all()?;
    drop(temp_file);
    if let Err(error) = std::fs::rename(&temp_path, path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(error);
    }
    Ok(())
}

fn validate_persisted_metadata_state_for_query(
    state: &PersistedMetadataState,
) -> Result<(), PersistedMetadataQueryableStateError> {
    let mut bucket_names = BTreeSet::new();
    for bucket in &state.buckets {
        if !bucket_names.insert(bucket.bucket.clone()) {
            return Err(PersistedMetadataQueryableStateError::DuplicateBucketState {
                bucket: bucket.bucket.clone(),
            });
        }
    }

    let mut tombstoned_bucket_names = BTreeSet::new();
    for tombstone in &state.bucket_tombstones {
        if !tombstoned_bucket_names.insert(tombstone.bucket.clone()) {
            return Err(
                PersistedMetadataQueryableStateError::DuplicateBucketTombstoneState {
                    bucket: tombstone.bucket.clone(),
                },
            );
        }
    }

    for bucket in &bucket_names {
        if tombstoned_bucket_names.contains(bucket) {
            return Err(
                PersistedMetadataQueryableStateError::BucketTombstoneConflict {
                    bucket: bucket.clone(),
                },
            );
        }
    }

    let mut lifecycle_configuration_buckets = BTreeSet::new();
    for configuration in &state.bucket_lifecycle_configurations {
        if !lifecycle_configuration_buckets.insert(configuration.bucket.clone()) {
            return Err(
                PersistedMetadataQueryableStateError::DuplicateBucketLifecycleConfigurationState {
                    bucket: configuration.bucket.clone(),
                },
            );
        }
        if !bucket_names.contains(&configuration.bucket)
            || tombstoned_bucket_names.contains(&configuration.bucket)
        {
            return Err(
                PersistedMetadataQueryableStateError::OrphanBucketLifecycleConfigurationState {
                    bucket: configuration.bucket.clone(),
                },
            );
        }
    }

    let mut object_identity = BTreeSet::new();
    for object in &state.objects {
        let identity = (object.bucket.clone(), object.key.clone());
        if !object_identity.insert(identity.clone()) {
            return Err(PersistedMetadataQueryableStateError::DuplicateObjectState {
                bucket: identity.0,
                key: identity.1,
            });
        }
        if !bucket_names.contains(&object.bucket)
            || tombstoned_bucket_names.contains(&object.bucket)
        {
            return Err(PersistedMetadataQueryableStateError::OrphanObjectState {
                bucket: object.bucket.clone(),
                key: object.key.clone(),
            });
        }
    }

    let mut object_version_identity = BTreeSet::new();
    for version in &state.object_versions {
        let identity = (
            version.bucket.clone(),
            version.key.clone(),
            version.version_id.clone(),
        );
        if !object_version_identity.insert(identity.clone()) {
            return Err(
                PersistedMetadataQueryableStateError::DuplicateObjectVersionState {
                    bucket: identity.0,
                    key: identity.1,
                    version_id: identity.2,
                },
            );
        }
        if !bucket_names.contains(&version.bucket)
            || tombstoned_bucket_names.contains(&version.bucket)
        {
            return Err(
                PersistedMetadataQueryableStateError::OrphanObjectVersionState {
                    bucket: version.bucket.clone(),
                    key: version.key.clone(),
                    version_id: version.version_id.clone(),
                },
            );
        }
    }

    Ok(())
}

pub fn build_queryable_metadata_index_from_persisted_state(
    state: &PersistedMetadataState,
) -> Result<InMemoryMetadataIndex, PersistedMetadataQueryableStateError> {
    validate_persisted_metadata_state_for_query(state)?;

    let mut index = InMemoryMetadataIndex::default();
    for bucket in &state.buckets {
        index.upsert_bucket(bucket.clone());
    }
    for object in &state.objects {
        index.upsert_object(object.clone());
    }
    for version in &state.object_versions {
        index.upsert_object_version(version.clone());
    }
    Ok(index)
}

pub fn list_objects_page_from_persisted_state(
    state: &PersistedMetadataState,
    query: &MetadataQuery,
) -> Result<MetadataListPage, PersistedMetadataQueryError> {
    validate_persisted_query_view_id(state.view_id.as_str(), query.view_id.as_deref())?;
    let index = build_queryable_metadata_index_from_persisted_state(state)
        .map_err(PersistedMetadataQueryError::InvalidPersistedState)?;
    index
        .list_objects_page(query)
        .map_err(PersistedMetadataQueryError::InvalidQuery)
}

pub fn list_object_versions_page_from_persisted_state(
    state: &PersistedMetadataState,
    query: &MetadataVersionsQuery,
) -> Result<MetadataVersionsPage, PersistedMetadataQueryError> {
    validate_persisted_query_view_id(state.view_id.as_str(), query.view_id.as_deref())?;
    let index = build_queryable_metadata_index_from_persisted_state(state)
        .map_err(PersistedMetadataQueryError::InvalidPersistedState)?;
    index
        .list_object_versions_page(query)
        .map_err(PersistedMetadataQueryError::InvalidQuery)
}

fn validate_persisted_query_view_id(
    persisted_view_id: &str,
    expected_view_id: Option<&str>,
) -> Result<(), PersistedMetadataQueryError> {
    let Some(expected_view_id) = expected_view_id else {
        return Ok(());
    };

    let expected_view_id = expected_view_id.trim();
    let persisted_view_id = persisted_view_id.trim();
    if expected_view_id.is_empty()
        || persisted_view_id.is_empty()
        || expected_view_id != persisted_view_id
    {
        return Err(PersistedMetadataQueryError::ViewIdMismatch {
            expected_view_id: expected_view_id.to_string(),
            persisted_view_id: persisted_view_id.to_string(),
        });
    }

    Ok(())
}

pub fn list_buckets_from_persisted_state(
    state: &PersistedMetadataState,
) -> Result<Vec<BucketMetadataState>, PersistedMetadataQueryableStateError> {
    validate_persisted_metadata_state_for_query(state)?;
    let mut buckets = state.buckets.clone();
    buckets.sort_by(|left, right| left.bucket.cmp(&right.bucket));
    Ok(buckets)
}

pub fn list_buckets_from_persisted_state_with_view_id(
    state: &PersistedMetadataState,
    expected_view_id: Option<&str>,
) -> Result<Vec<BucketMetadataState>, PersistedMetadataQueryError> {
    validate_persisted_query_view_id(state.view_id.as_str(), expected_view_id)?;
    list_buckets_from_persisted_state(state)
        .map_err(PersistedMetadataQueryError::InvalidPersistedState)
}

pub fn resolve_bucket_metadata_from_persisted_state(
    state: &PersistedMetadataState,
    bucket: &str,
    expected_view_id: Option<&str>,
) -> Result<PersistedBucketMetadataReadResolution, PersistedMetadataQueryError> {
    validate_persisted_query_view_id(state.view_id.as_str(), expected_view_id)?;
    validate_persisted_metadata_state_for_query(state)
        .map_err(PersistedMetadataQueryError::InvalidPersistedState)?;

    let bucket = bucket.trim();
    if bucket.is_empty() {
        return Ok(PersistedBucketMetadataReadResolution::Missing);
    }

    Ok(state
        .buckets
        .iter()
        .find(|entry| entry.bucket == bucket)
        .cloned()
        .map(PersistedBucketMetadataReadResolution::Present)
        .unwrap_or(PersistedBucketMetadataReadResolution::Missing))
}

pub fn resolve_bucket_lifecycle_configuration_from_persisted_state(
    state: &PersistedMetadataState,
    bucket: &str,
    expected_view_id: Option<&str>,
) -> Result<PersistedBucketLifecycleConfigurationReadResolution, PersistedMetadataQueryError> {
    validate_persisted_query_view_id(state.view_id.as_str(), expected_view_id)?;
    validate_persisted_metadata_state_for_query(state)
        .map_err(PersistedMetadataQueryError::InvalidPersistedState)?;

    let bucket = bucket.trim();
    if bucket.is_empty() {
        return Ok(PersistedBucketLifecycleConfigurationReadResolution::Missing);
    }

    Ok(state
        .bucket_lifecycle_configurations
        .iter()
        .find(|entry| entry.bucket == bucket)
        .cloned()
        .map(PersistedBucketLifecycleConfigurationReadResolution::Present)
        .unwrap_or(PersistedBucketLifecycleConfigurationReadResolution::Missing))
}

pub fn resolve_bucket_presence_from_persisted_state(
    state: &PersistedMetadataState,
    bucket: &str,
    expected_view_id: Option<&str>,
) -> Result<PersistedBucketPresenceReadResolution, PersistedMetadataQueryError> {
    validate_persisted_query_view_id(state.view_id.as_str(), expected_view_id)?;
    validate_persisted_metadata_state_for_query(state)
        .map_err(PersistedMetadataQueryError::InvalidPersistedState)?;

    let bucket = bucket.trim();
    if bucket.is_empty() {
        return Ok(PersistedBucketPresenceReadResolution::Missing);
    }

    if let Some(entry) = state.buckets.iter().find(|entry| entry.bucket == bucket) {
        return Ok(PersistedBucketPresenceReadResolution::Present(
            entry.clone(),
        ));
    }

    if let Some(tombstone) = state
        .bucket_tombstones
        .iter()
        .find(|entry| entry.bucket == bucket)
    {
        return Ok(PersistedBucketPresenceReadResolution::Tombstoned(
            tombstone.clone(),
        ));
    }

    Ok(PersistedBucketPresenceReadResolution::Missing)
}

pub fn resolve_bucket_mutation_preconditions_from_persisted_state(
    state: &PersistedMetadataState,
    bucket: &str,
    expected_view_id: Option<&str>,
    now_unix_ms: u64,
) -> Result<PersistedBucketMutationPreconditionResolution, PersistedMetadataQueryError> {
    let resolution = resolve_bucket_presence_from_persisted_state(state, bucket, expected_view_id)?;
    Ok(match resolution {
        PersistedBucketPresenceReadResolution::Present(bucket_state) => {
            PersistedBucketMutationPreconditionResolution::Present(bucket_state)
        }
        PersistedBucketPresenceReadResolution::Tombstoned(tombstone) => {
            PersistedBucketMutationPreconditionResolution::Tombstoned {
                retention_active: !tombstone.is_expired(now_unix_ms),
                tombstone,
            }
        }
        PersistedBucketPresenceReadResolution::Missing => {
            PersistedBucketMutationPreconditionResolution::Missing
        }
    })
}

pub fn resolve_bucket_lifecycle_mutation_preconditions_from_persisted_state(
    state: &PersistedMetadataState,
    bucket: &str,
    expected_view_id: Option<&str>,
    now_unix_ms: u64,
) -> Result<PersistedBucketLifecycleMutationPreconditionResolution, PersistedMetadataQueryError> {
    let presence_resolution =
        resolve_bucket_presence_from_persisted_state(state, bucket, expected_view_id)?;

    match presence_resolution {
        PersistedBucketPresenceReadResolution::Present(bucket_state) => {
            let lifecycle_resolution = resolve_bucket_lifecycle_configuration_from_persisted_state(
                state,
                bucket_state.bucket.as_str(),
                expected_view_id,
            )?;
            let lifecycle_configuration = match lifecycle_resolution {
                PersistedBucketLifecycleConfigurationReadResolution::Present(configuration) => {
                    Some(configuration)
                }
                PersistedBucketLifecycleConfigurationReadResolution::Missing => None,
            };

            Ok(
                PersistedBucketLifecycleMutationPreconditionResolution::Present {
                    bucket: bucket_state,
                    lifecycle_configuration,
                },
            )
        }
        PersistedBucketPresenceReadResolution::Tombstoned(tombstone) => Ok(
            PersistedBucketLifecycleMutationPreconditionResolution::Tombstoned {
                retention_active: !tombstone.is_expired(now_unix_ms),
                tombstone,
            },
        ),
        PersistedBucketPresenceReadResolution::Missing => {
            Ok(PersistedBucketLifecycleMutationPreconditionResolution::Missing)
        }
    }
}

pub fn resolve_object_metadata_from_persisted_state(
    state: &PersistedMetadataState,
    bucket: &str,
    key: &str,
    expected_view_id: Option<&str>,
) -> Result<PersistedObjectMetadataReadResolution, PersistedMetadataQueryError> {
    validate_persisted_query_view_id(state.view_id.as_str(), expected_view_id)?;
    validate_persisted_metadata_state_for_query(state)
        .map_err(PersistedMetadataQueryError::InvalidPersistedState)?;

    let bucket = bucket.trim();
    let key = key.trim();
    if bucket.is_empty() || key.is_empty() {
        return Ok(PersistedObjectMetadataReadResolution::Missing);
    }

    Ok(state
        .objects
        .iter()
        .find(|entry| entry.bucket == bucket && entry.key == key)
        .cloned()
        .map(PersistedObjectMetadataReadResolution::Present)
        .unwrap_or(PersistedObjectMetadataReadResolution::Missing))
}

pub fn resolve_object_read_preconditions_from_persisted_state(
    state: &PersistedMetadataState,
    bucket: &str,
    key: &str,
    expected_view_id: Option<&str>,
) -> Result<PersistedObjectReadPreconditionResolution, PersistedMetadataQueryError> {
    match resolve_bucket_presence_from_persisted_state(state, bucket, expected_view_id)? {
        PersistedBucketPresenceReadResolution::Present(_) => {
            match resolve_object_metadata_from_persisted_state(
                state,
                bucket,
                key,
                expected_view_id,
            )? {
                PersistedObjectMetadataReadResolution::Present(object) => {
                    Ok(PersistedObjectReadPreconditionResolution::Present(object))
                }
                PersistedObjectMetadataReadResolution::Missing => {
                    Ok(PersistedObjectReadPreconditionResolution::MissingObject)
                }
            }
        }
        PersistedBucketPresenceReadResolution::Tombstoned(tombstone) => Ok(
            PersistedObjectReadPreconditionResolution::TombstonedBucket(tombstone),
        ),
        PersistedBucketPresenceReadResolution::Missing => {
            Ok(PersistedObjectReadPreconditionResolution::MissingBucket)
        }
    }
}

pub fn resolve_object_mutation_preconditions_from_persisted_state(
    state: &PersistedMetadataState,
    bucket: &str,
    key: &str,
    expected_view_id: Option<&str>,
    now_unix_ms: u64,
) -> Result<PersistedObjectMutationPreconditionResolution, PersistedMetadataQueryError> {
    match resolve_bucket_presence_from_persisted_state(state, bucket, expected_view_id)? {
        PersistedBucketPresenceReadResolution::Present(bucket_state) => {
            let object = match resolve_object_metadata_from_persisted_state(
                state,
                bucket,
                key,
                expected_view_id,
            )? {
                PersistedObjectMetadataReadResolution::Present(object) => Some(object),
                PersistedObjectMetadataReadResolution::Missing => None,
            };
            Ok(
                PersistedObjectMutationPreconditionResolution::PresentBucket {
                    bucket: bucket_state,
                    object,
                },
            )
        }
        PersistedBucketPresenceReadResolution::Tombstoned(tombstone) => Ok(
            PersistedObjectMutationPreconditionResolution::TombstonedBucket {
                retention_active: !tombstone.is_expired(now_unix_ms),
                tombstone,
            },
        ),
        PersistedBucketPresenceReadResolution::Missing => {
            Ok(PersistedObjectMutationPreconditionResolution::MissingBucket)
        }
    }
}

pub fn resolve_object_version_metadata_from_persisted_state(
    state: &PersistedMetadataState,
    bucket: &str,
    key: &str,
    version_id: &str,
    expected_view_id: Option<&str>,
) -> Result<PersistedObjectVersionMetadataReadResolution, PersistedMetadataQueryError> {
    validate_persisted_query_view_id(state.view_id.as_str(), expected_view_id)?;
    validate_persisted_metadata_state_for_query(state)
        .map_err(PersistedMetadataQueryError::InvalidPersistedState)?;

    let bucket = bucket.trim();
    let key = key.trim();
    let version_id = version_id.trim();
    if bucket.is_empty() || key.is_empty() || version_id.is_empty() {
        return Ok(PersistedObjectVersionMetadataReadResolution::Missing);
    }

    Ok(state
        .object_versions
        .iter()
        .find(|entry| entry.bucket == bucket && entry.key == key && entry.version_id == version_id)
        .cloned()
        .map(PersistedObjectVersionMetadataReadResolution::Present)
        .unwrap_or(PersistedObjectVersionMetadataReadResolution::Missing))
}

pub fn resolve_object_version_read_preconditions_from_persisted_state(
    state: &PersistedMetadataState,
    bucket: &str,
    key: &str,
    version_id: &str,
    expected_view_id: Option<&str>,
) -> Result<PersistedObjectVersionReadPreconditionResolution, PersistedMetadataQueryError> {
    match resolve_bucket_presence_from_persisted_state(state, bucket, expected_view_id)? {
        PersistedBucketPresenceReadResolution::Present(_) => {
            match resolve_object_version_metadata_from_persisted_state(
                state,
                bucket,
                key,
                version_id,
                expected_view_id,
            )? {
                PersistedObjectVersionMetadataReadResolution::Present(version) => Ok(
                    PersistedObjectVersionReadPreconditionResolution::Present(version),
                ),
                PersistedObjectVersionMetadataReadResolution::Missing => {
                    Ok(PersistedObjectVersionReadPreconditionResolution::MissingVersion)
                }
            }
        }
        PersistedBucketPresenceReadResolution::Tombstoned(tombstone) => {
            Ok(PersistedObjectVersionReadPreconditionResolution::TombstonedBucket(tombstone))
        }
        PersistedBucketPresenceReadResolution::Missing => {
            Ok(PersistedObjectVersionReadPreconditionResolution::MissingBucket)
        }
    }
}

pub fn resolve_object_version_mutation_preconditions_from_persisted_state(
    state: &PersistedMetadataState,
    bucket: &str,
    key: &str,
    version_id: &str,
    expected_view_id: Option<&str>,
    now_unix_ms: u64,
) -> Result<PersistedObjectVersionMutationPreconditionResolution, PersistedMetadataQueryError> {
    match resolve_bucket_presence_from_persisted_state(state, bucket, expected_view_id)? {
        PersistedBucketPresenceReadResolution::Present(bucket_state) => {
            let version = match resolve_object_version_metadata_from_persisted_state(
                state,
                bucket,
                key,
                version_id,
                expected_view_id,
            )? {
                PersistedObjectVersionMetadataReadResolution::Present(version) => Some(version),
                PersistedObjectVersionMetadataReadResolution::Missing => None,
            };
            Ok(
                PersistedObjectVersionMutationPreconditionResolution::PresentBucket {
                    bucket: bucket_state,
                    version,
                },
            )
        }
        PersistedBucketPresenceReadResolution::Tombstoned(tombstone) => Ok(
            PersistedObjectVersionMutationPreconditionResolution::TombstonedBucket {
                retention_active: !tombstone.is_expired(now_unix_ms),
                tombstone,
            },
        ),
        PersistedBucketPresenceReadResolution::Missing => {
            Ok(PersistedObjectVersionMutationPreconditionResolution::MissingBucket)
        }
    }
}
