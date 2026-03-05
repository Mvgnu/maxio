use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketMetadataState {
    pub bucket: String,
    pub versioning_enabled: bool,
    pub lifecycle_enabled: bool,
}

impl BucketMetadataState {
    pub fn new(bucket: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            versioning_enabled: false,
            lifecycle_enabled: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketMetadataTombstoneState {
    pub bucket: String,
    pub deleted_at_unix_ms: u64,
    pub retain_until_unix_ms: u64,
}

impl BucketMetadataTombstoneState {
    pub fn is_expired(&self, now_unix_ms: u64) -> bool {
        now_unix_ms >= self.retain_until_unix_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketLifecycleConfigurationState {
    pub bucket: String,
    pub configuration_xml: String,
    pub updated_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BucketLifecycleConfigurationOperation {
    UpsertConfiguration {
        bucket: String,
        configuration_xml: String,
        updated_at_unix_ms: u64,
    },
    DeleteConfiguration {
        bucket: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BucketLifecycleConfigurationOperationError {
    InvalidBucketName,
    InvalidLifecycleConfiguration,
    BucketNotFound,
    ConfigurationNotFound,
}

impl BucketLifecycleConfigurationOperationError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidBucketName => "invalid-bucket-name",
            Self::InvalidLifecycleConfiguration => "invalid-lifecycle-configuration",
            Self::BucketNotFound => "bucket-not-found",
            Self::ConfigurationNotFound => "lifecycle-configuration-not-found",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketLifecycleConfigurationOperationOutcome {
    pub configuration_state: Option<BucketLifecycleConfigurationState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BucketMetadataOperation {
    CreateBucket {
        bucket: String,
        at_unix_ms: u64,
    },
    DeleteBucket {
        bucket: String,
        deleted_at_unix_ms: u64,
        retain_tombstone_for_ms: u64,
    },
    SetVersioning {
        bucket: String,
        enabled: bool,
    },
    SetLifecycle {
        bucket: String,
        enabled: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BucketMetadataOperationError {
    InvalidBucketName,
    BucketAlreadyExists,
    BucketNotFound,
    TombstoneRetentionActive,
    InvalidRetentionWindow,
}

impl BucketMetadataOperationError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidBucketName => "invalid-bucket-name",
            Self::BucketAlreadyExists => "bucket-already-exists",
            Self::BucketNotFound => "bucket-not-found",
            Self::TombstoneRetentionActive => "tombstone-retention-active",
            Self::InvalidRetentionWindow => "invalid-retention-window",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketMetadataOperationOutcome {
    pub bucket_state: Option<BucketMetadataState>,
    pub tombstone_state: Option<BucketMetadataTombstoneState>,
}

fn normalized_bucket_name(value: &str) -> Option<String> {
    let normalized = value.trim();
    if normalized.is_empty() || normalized.contains('/') || normalized.contains('\\') {
        None
    } else {
        Some(normalized.to_string())
    }
}

fn ensure_matching_bucket_name(
    operation_bucket: &str,
    current_state: Option<&BucketMetadataState>,
    current_tombstone: Option<&BucketMetadataTombstoneState>,
) -> Result<String, BucketMetadataOperationError> {
    let bucket = normalized_bucket_name(operation_bucket)
        .ok_or(BucketMetadataOperationError::InvalidBucketName)?;

    if current_state.is_some_and(|state| state.bucket != bucket) {
        return Err(BucketMetadataOperationError::InvalidBucketName);
    }
    if current_tombstone.is_some_and(|tombstone| tombstone.bucket != bucket) {
        return Err(BucketMetadataOperationError::InvalidBucketName);
    }
    Ok(bucket)
}

pub fn apply_bucket_lifecycle_configuration_operation(
    current_state: Option<&BucketLifecycleConfigurationState>,
    bucket_exists: bool,
    operation: &BucketLifecycleConfigurationOperation,
) -> Result<
    BucketLifecycleConfigurationOperationOutcome,
    BucketLifecycleConfigurationOperationError,
> {
    match operation {
        BucketLifecycleConfigurationOperation::UpsertConfiguration {
            bucket,
            configuration_xml,
            updated_at_unix_ms,
        } => {
            let bucket = normalized_bucket_name(bucket)
                .ok_or(BucketLifecycleConfigurationOperationError::InvalidBucketName)?;
            if current_state.is_some_and(|state| state.bucket != bucket) {
                return Err(BucketLifecycleConfigurationOperationError::InvalidBucketName);
            }
            if !bucket_exists {
                return Err(BucketLifecycleConfigurationOperationError::BucketNotFound);
            }
            let configuration_xml = configuration_xml.trim();
            if configuration_xml.is_empty() {
                return Err(
                    BucketLifecycleConfigurationOperationError::InvalidLifecycleConfiguration,
                );
            }

            Ok(BucketLifecycleConfigurationOperationOutcome {
                configuration_state: Some(BucketLifecycleConfigurationState {
                    bucket,
                    configuration_xml: configuration_xml.to_string(),
                    updated_at_unix_ms: *updated_at_unix_ms,
                }),
            })
        }
        BucketLifecycleConfigurationOperation::DeleteConfiguration { bucket } => {
            let bucket = normalized_bucket_name(bucket)
                .ok_or(BucketLifecycleConfigurationOperationError::InvalidBucketName)?;
            if current_state.is_some_and(|state| state.bucket != bucket) {
                return Err(BucketLifecycleConfigurationOperationError::InvalidBucketName);
            }
            if !bucket_exists {
                return Err(BucketLifecycleConfigurationOperationError::BucketNotFound);
            }
            if current_state.is_none() {
                return Err(BucketLifecycleConfigurationOperationError::ConfigurationNotFound);
            }

            Ok(BucketLifecycleConfigurationOperationOutcome {
                configuration_state: None,
            })
        }
    }
}

pub fn apply_bucket_metadata_operation(
    current_state: Option<&BucketMetadataState>,
    current_tombstone: Option<&BucketMetadataTombstoneState>,
    operation: &BucketMetadataOperation,
) -> Result<BucketMetadataOperationOutcome, BucketMetadataOperationError> {
    match operation {
        BucketMetadataOperation::CreateBucket { bucket, at_unix_ms } => {
            let bucket = ensure_matching_bucket_name(bucket, current_state, current_tombstone)?;
            if current_state.is_some() {
                return Err(BucketMetadataOperationError::BucketAlreadyExists);
            }
            if current_tombstone.is_some_and(|tombstone| !tombstone.is_expired(*at_unix_ms)) {
                return Err(BucketMetadataOperationError::TombstoneRetentionActive);
            }

            Ok(BucketMetadataOperationOutcome {
                bucket_state: Some(BucketMetadataState::new(bucket)),
                tombstone_state: None,
            })
        }
        BucketMetadataOperation::DeleteBucket {
            bucket,
            deleted_at_unix_ms,
            retain_tombstone_for_ms,
        } => {
            let bucket = ensure_matching_bucket_name(bucket, current_state, current_tombstone)?;
            if current_state.is_none() {
                return Err(BucketMetadataOperationError::BucketNotFound);
            }
            let Some(retain_until_unix_ms) =
                deleted_at_unix_ms.checked_add(*retain_tombstone_for_ms)
            else {
                return Err(BucketMetadataOperationError::InvalidRetentionWindow);
            };

            Ok(BucketMetadataOperationOutcome {
                bucket_state: None,
                tombstone_state: Some(BucketMetadataTombstoneState {
                    bucket,
                    deleted_at_unix_ms: *deleted_at_unix_ms,
                    retain_until_unix_ms,
                }),
            })
        }
        BucketMetadataOperation::SetVersioning { bucket, enabled } => {
            let _ = ensure_matching_bucket_name(bucket, current_state, current_tombstone)?;
            let Some(state) = current_state else {
                return Err(BucketMetadataOperationError::BucketNotFound);
            };
            let mut next_state = state.clone();
            next_state.versioning_enabled = *enabled;

            Ok(BucketMetadataOperationOutcome {
                bucket_state: Some(next_state),
                tombstone_state: current_tombstone.cloned(),
            })
        }
        BucketMetadataOperation::SetLifecycle { bucket, enabled } => {
            let _ = ensure_matching_bucket_name(bucket, current_state, current_tombstone)?;
            let Some(state) = current_state else {
                return Err(BucketMetadataOperationError::BucketNotFound);
            };
            let mut next_state = state.clone();
            next_state.lifecycle_enabled = *enabled;

            Ok(BucketMetadataOperationOutcome {
                bucket_state: Some(next_state),
                tombstone_state: current_tombstone.cloned(),
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectMetadataState {
    pub bucket: String,
    pub key: String,
    pub latest_version_id: Option<String>,
    pub is_delete_marker: bool,
}

impl ObjectMetadataState {
    pub fn new(bucket: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            key: key.into(),
            latest_version_id: None,
            is_delete_marker: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectMetadataOperation {
    UpsertCurrent {
        bucket: String,
        key: String,
        latest_version_id: Option<String>,
        is_delete_marker: bool,
    },
    DeleteCurrent {
        bucket: String,
        key: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectMetadataOperationError {
    InvalidBucketName,
    InvalidObjectKey,
    InvalidVersionId,
    ObjectNotFound,
}

impl ObjectMetadataOperationError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidBucketName => "invalid-bucket-name",
            Self::InvalidObjectKey => "invalid-object-key",
            Self::InvalidVersionId => "invalid-version-id",
            Self::ObjectNotFound => "object-not-found",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMetadataOperationOutcome {
    pub object_state: Option<ObjectMetadataState>,
}

fn normalized_object_key(value: &str) -> Option<String> {
    if value.is_empty() || value.contains('\0') {
        None
    } else {
        Some(value.to_string())
    }
}

fn normalized_version_id(value: &str) -> Option<String> {
    if value.trim().is_empty() || value.contains('\0') {
        None
    } else {
        Some(value.to_string())
    }
}

fn ensure_matching_object_identity(
    operation_bucket: &str,
    operation_key: &str,
    current_state: Option<&ObjectMetadataState>,
) -> Result<(String, String), ObjectMetadataOperationError> {
    let bucket = normalized_bucket_name(operation_bucket)
        .ok_or(ObjectMetadataOperationError::InvalidBucketName)?;
    let key = normalized_object_key(operation_key)
        .ok_or(ObjectMetadataOperationError::InvalidObjectKey)?;

    if current_state.is_some_and(|state| state.bucket != bucket || state.key != key) {
        return Err(ObjectMetadataOperationError::InvalidObjectKey);
    }

    Ok((bucket, key))
}

pub fn apply_object_metadata_operation(
    current_state: Option<&ObjectMetadataState>,
    operation: &ObjectMetadataOperation,
) -> Result<ObjectMetadataOperationOutcome, ObjectMetadataOperationError> {
    match operation {
        ObjectMetadataOperation::UpsertCurrent {
            bucket,
            key,
            latest_version_id,
            is_delete_marker,
        } => {
            let (bucket, key) = ensure_matching_object_identity(bucket, key, current_state)?;
            let latest_version_id = latest_version_id
                .as_deref()
                .map(|value| {
                    normalized_version_id(value)
                        .ok_or(ObjectMetadataOperationError::InvalidVersionId)
                })
                .transpose()?;

            Ok(ObjectMetadataOperationOutcome {
                object_state: Some(ObjectMetadataState {
                    bucket,
                    key,
                    latest_version_id,
                    is_delete_marker: *is_delete_marker,
                }),
            })
        }
        ObjectMetadataOperation::DeleteCurrent { bucket, key } => {
            let _ = ensure_matching_object_identity(bucket, key, current_state)?;
            if current_state.is_none() {
                return Err(ObjectMetadataOperationError::ObjectNotFound);
            }

            Ok(ObjectMetadataOperationOutcome { object_state: None })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectVersionMetadataState {
    pub bucket: String,
    pub key: String,
    pub version_id: String,
    pub is_delete_marker: bool,
    pub is_latest: bool,
}

impl ObjectVersionMetadataState {
    pub fn new(
        bucket: impl Into<String>,
        key: impl Into<String>,
        version_id: impl Into<String>,
    ) -> Self {
        Self {
            bucket: bucket.into(),
            key: key.into(),
            version_id: version_id.into(),
            is_delete_marker: false,
            is_latest: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectVersionMetadataOperation {
    UpsertVersion {
        bucket: String,
        key: String,
        version_id: String,
        is_delete_marker: bool,
        is_latest: bool,
    },
    DeleteVersion {
        bucket: String,
        key: String,
        version_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectVersionMetadataOperationError {
    InvalidBucketName,
    InvalidObjectKey,
    InvalidVersionId,
    VersionNotFound,
}

impl ObjectVersionMetadataOperationError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidBucketName => "invalid-bucket-name",
            Self::InvalidObjectKey => "invalid-object-key",
            Self::InvalidVersionId => "invalid-version-id",
            Self::VersionNotFound => "version-not-found",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectVersionMetadataOperationOutcome {
    pub version_state: Option<ObjectVersionMetadataState>,
}

fn ensure_matching_object_version_identity(
    operation_bucket: &str,
    operation_key: &str,
    operation_version_id: &str,
    current_state: Option<&ObjectVersionMetadataState>,
) -> Result<(String, String, String), ObjectVersionMetadataOperationError> {
    let bucket = normalized_bucket_name(operation_bucket)
        .ok_or(ObjectVersionMetadataOperationError::InvalidBucketName)?;
    let key = normalized_object_key(operation_key)
        .ok_or(ObjectVersionMetadataOperationError::InvalidObjectKey)?;
    let version_id = normalized_version_id(operation_version_id)
        .ok_or(ObjectVersionMetadataOperationError::InvalidVersionId)?;

    if current_state.is_some_and(|state| {
        state.bucket != bucket || state.key != key || state.version_id != version_id
    }) {
        return Err(ObjectVersionMetadataOperationError::InvalidVersionId);
    }

    Ok((bucket, key, version_id))
}

pub fn apply_object_version_metadata_operation(
    current_state: Option<&ObjectVersionMetadataState>,
    operation: &ObjectVersionMetadataOperation,
) -> Result<ObjectVersionMetadataOperationOutcome, ObjectVersionMetadataOperationError> {
    match operation {
        ObjectVersionMetadataOperation::UpsertVersion {
            bucket,
            key,
            version_id,
            is_delete_marker,
            is_latest,
        } => {
            let (bucket, key, version_id) =
                ensure_matching_object_version_identity(bucket, key, version_id, current_state)?;

            Ok(ObjectVersionMetadataOperationOutcome {
                version_state: Some(ObjectVersionMetadataState {
                    bucket,
                    key,
                    version_id,
                    is_delete_marker: *is_delete_marker,
                    is_latest: *is_latest,
                }),
            })
        }
        ObjectVersionMetadataOperation::DeleteVersion {
            bucket,
            key,
            version_id,
        } => {
            let _ =
                ensure_matching_object_version_identity(bucket, key, version_id, current_state)?;
            if current_state.is_none() {
                return Err(ObjectVersionMetadataOperationError::VersionNotFound);
            }

            Ok(ObjectVersionMetadataOperationOutcome {
                version_state: None,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BucketLifecycleConfigurationOperation, BucketLifecycleConfigurationOperationError,
        BucketLifecycleConfigurationState,
        BucketMetadataOperation, BucketMetadataOperationError, BucketMetadataState,
        BucketMetadataTombstoneState, ObjectMetadataOperation, ObjectMetadataOperationError,
        ObjectMetadataState, ObjectVersionMetadataOperation, ObjectVersionMetadataOperationError,
        ObjectVersionMetadataState, apply_bucket_lifecycle_configuration_operation,
        apply_bucket_metadata_operation, apply_object_metadata_operation,
        apply_object_version_metadata_operation,
    };

    #[test]
    fn bucket_state_defaults_are_disabled() {
        let state = BucketMetadataState::new("photos");
        assert_eq!(state.bucket, "photos");
        assert!(!state.versioning_enabled);
        assert!(!state.lifecycle_enabled);
    }

    #[test]
    fn object_state_defaults_to_non_deleted_without_version() {
        let state = ObjectMetadataState::new("photos", "docs/a.txt");
        assert_eq!(state.bucket, "photos");
        assert_eq!(state.key, "docs/a.txt");
        assert_eq!(state.latest_version_id, None);
        assert!(!state.is_delete_marker);
    }

    #[test]
    fn object_version_state_defaults_to_non_deleted_non_latest() {
        let state = ObjectVersionMetadataState::new("photos", "docs/a.txt", "v2");
        assert_eq!(state.bucket, "photos");
        assert_eq!(state.key, "docs/a.txt");
        assert_eq!(state.version_id, "v2");
        assert!(!state.is_delete_marker);
        assert!(!state.is_latest);
    }

    #[test]
    fn apply_object_upsert_updates_state() {
        let result = apply_object_metadata_operation(
            None,
            &ObjectMetadataOperation::UpsertCurrent {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                latest_version_id: Some("v1".to_string()),
                is_delete_marker: false,
            },
        )
        .expect("upsert should succeed");

        assert_eq!(
            result.object_state,
            Some(ObjectMetadataState {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                latest_version_id: Some("v1".to_string()),
                is_delete_marker: false,
            })
        );
    }

    #[test]
    fn apply_object_delete_requires_existing_state() {
        let missing = apply_object_metadata_operation(
            None,
            &ObjectMetadataOperation::DeleteCurrent {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
            },
        );
        assert_eq!(missing, Err(ObjectMetadataOperationError::ObjectNotFound));

        let current = ObjectMetadataState {
            bucket: "photos".to_string(),
            key: "docs/a.txt".to_string(),
            latest_version_id: Some("v1".to_string()),
            is_delete_marker: false,
        };
        let deleted = apply_object_metadata_operation(
            Some(&current),
            &ObjectMetadataOperation::DeleteCurrent {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
            },
        )
        .expect("delete should succeed when object exists");
        assert_eq!(deleted.object_state, None);
    }

    #[test]
    fn apply_object_ops_reject_invalid_identity_fields() {
        let invalid_key = apply_object_metadata_operation(
            None,
            &ObjectMetadataOperation::UpsertCurrent {
                bucket: "photos".to_string(),
                key: String::new(),
                latest_version_id: Some("v1".to_string()),
                is_delete_marker: false,
            },
        );
        assert_eq!(
            invalid_key,
            Err(ObjectMetadataOperationError::InvalidObjectKey)
        );

        let invalid_version = apply_object_metadata_operation(
            None,
            &ObjectMetadataOperation::UpsertCurrent {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                latest_version_id: Some("   ".to_string()),
                is_delete_marker: false,
            },
        );
        assert_eq!(
            invalid_version,
            Err(ObjectMetadataOperationError::InvalidVersionId)
        );
    }

    #[test]
    fn object_operation_error_labels_are_stable() {
        assert_eq!(
            ObjectMetadataOperationError::InvalidBucketName.as_str(),
            "invalid-bucket-name"
        );
        assert_eq!(
            ObjectMetadataOperationError::InvalidObjectKey.as_str(),
            "invalid-object-key"
        );
        assert_eq!(
            ObjectMetadataOperationError::InvalidVersionId.as_str(),
            "invalid-version-id"
        );
        assert_eq!(
            ObjectMetadataOperationError::ObjectNotFound.as_str(),
            "object-not-found"
        );
    }

    #[test]
    fn apply_object_version_upsert_and_delete() {
        let upserted = apply_object_version_metadata_operation(
            None,
            &ObjectVersionMetadataOperation::UpsertVersion {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                version_id: "v2".to_string(),
                is_delete_marker: true,
                is_latest: true,
            },
        )
        .expect("version upsert should succeed");
        assert_eq!(
            upserted.version_state,
            Some(ObjectVersionMetadataState {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                version_id: "v2".to_string(),
                is_delete_marker: true,
                is_latest: true,
            })
        );

        let deleted = apply_object_version_metadata_operation(
            upserted.version_state.as_ref(),
            &ObjectVersionMetadataOperation::DeleteVersion {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                version_id: "v2".to_string(),
            },
        )
        .expect("version delete should succeed");
        assert_eq!(deleted.version_state, None);
    }

    #[test]
    fn apply_object_version_delete_requires_existing_version() {
        let result = apply_object_version_metadata_operation(
            None,
            &ObjectVersionMetadataOperation::DeleteVersion {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                version_id: "v1".to_string(),
            },
        );
        assert_eq!(
            result,
            Err(ObjectVersionMetadataOperationError::VersionNotFound)
        );
    }

    #[test]
    fn apply_object_version_ops_reject_invalid_fields() {
        let invalid_bucket = apply_object_version_metadata_operation(
            None,
            &ObjectVersionMetadataOperation::UpsertVersion {
                bucket: "   ".to_string(),
                key: "docs/a.txt".to_string(),
                version_id: "v1".to_string(),
                is_delete_marker: false,
                is_latest: false,
            },
        );
        assert_eq!(
            invalid_bucket,
            Err(ObjectVersionMetadataOperationError::InvalidBucketName)
        );

        let invalid_version = apply_object_version_metadata_operation(
            None,
            &ObjectVersionMetadataOperation::UpsertVersion {
                bucket: "photos".to_string(),
                key: "docs/a.txt".to_string(),
                version_id: String::new(),
                is_delete_marker: false,
                is_latest: false,
            },
        );
        assert_eq!(
            invalid_version,
            Err(ObjectVersionMetadataOperationError::InvalidVersionId)
        );
    }

    #[test]
    fn object_version_operation_error_labels_are_stable() {
        assert_eq!(
            ObjectVersionMetadataOperationError::InvalidBucketName.as_str(),
            "invalid-bucket-name"
        );
        assert_eq!(
            ObjectVersionMetadataOperationError::InvalidObjectKey.as_str(),
            "invalid-object-key"
        );
        assert_eq!(
            ObjectVersionMetadataOperationError::InvalidVersionId.as_str(),
            "invalid-version-id"
        );
        assert_eq!(
            ObjectVersionMetadataOperationError::VersionNotFound.as_str(),
            "version-not-found"
        );
    }

    #[test]
    fn bucket_tombstone_expires_when_now_reaches_retain_until() {
        let tombstone = BucketMetadataTombstoneState {
            bucket: "photos".to_string(),
            deleted_at_unix_ms: 1000,
            retain_until_unix_ms: 2000,
        };

        assert!(!tombstone.is_expired(1999));
        assert!(tombstone.is_expired(2000));
    }

    #[test]
    fn apply_create_bucket_rejects_active_tombstone_retention() {
        let tombstone = BucketMetadataTombstoneState {
            bucket: "photos".to_string(),
            deleted_at_unix_ms: 1000,
            retain_until_unix_ms: 2000,
        };

        let result = apply_bucket_metadata_operation(
            None,
            Some(&tombstone),
            &BucketMetadataOperation::CreateBucket {
                bucket: "photos".to_string(),
                at_unix_ms: 1500,
            },
        );
        assert_eq!(
            result,
            Err(BucketMetadataOperationError::TombstoneRetentionActive)
        );
    }

    #[test]
    fn apply_create_bucket_clears_expired_tombstone_and_creates_bucket() {
        let tombstone = BucketMetadataTombstoneState {
            bucket: "photos".to_string(),
            deleted_at_unix_ms: 1000,
            retain_until_unix_ms: 2000,
        };

        let result = apply_bucket_metadata_operation(
            None,
            Some(&tombstone),
            &BucketMetadataOperation::CreateBucket {
                bucket: "photos".to_string(),
                at_unix_ms: 2000,
            },
        )
        .expect("create should succeed when tombstone retention is expired");
        assert_eq!(
            result.bucket_state,
            Some(BucketMetadataState::new("photos"))
        );
        assert_eq!(result.tombstone_state, None);
    }

    #[test]
    fn apply_delete_bucket_creates_tombstone_with_retention() {
        let current = BucketMetadataState::new("photos");
        let result = apply_bucket_metadata_operation(
            Some(&current),
            None,
            &BucketMetadataOperation::DeleteBucket {
                bucket: "photos".to_string(),
                deleted_at_unix_ms: 5000,
                retain_tombstone_for_ms: 3000,
            },
        )
        .expect("delete should succeed");

        assert_eq!(result.bucket_state, None);
        assert_eq!(
            result.tombstone_state,
            Some(BucketMetadataTombstoneState {
                bucket: "photos".to_string(),
                deleted_at_unix_ms: 5000,
                retain_until_unix_ms: 8000,
            })
        );
    }

    #[test]
    fn apply_delete_bucket_rejects_overflowing_retention_window() {
        let current = BucketMetadataState::new("photos");
        let result = apply_bucket_metadata_operation(
            Some(&current),
            None,
            &BucketMetadataOperation::DeleteBucket {
                bucket: "photos".to_string(),
                deleted_at_unix_ms: u64::MAX,
                retain_tombstone_for_ms: 1,
            },
        );
        assert_eq!(
            result,
            Err(BucketMetadataOperationError::InvalidRetentionWindow)
        );
    }

    #[test]
    fn apply_setters_require_bucket_and_preserve_tombstone() {
        let current = BucketMetadataState {
            bucket: "photos".to_string(),
            versioning_enabled: false,
            lifecycle_enabled: false,
        };
        let tombstone = BucketMetadataTombstoneState {
            bucket: "photos".to_string(),
            deleted_at_unix_ms: 1,
            retain_until_unix_ms: 2,
        };

        let versioned = apply_bucket_metadata_operation(
            Some(&current),
            Some(&tombstone),
            &BucketMetadataOperation::SetVersioning {
                bucket: "photos".to_string(),
                enabled: true,
            },
        )
        .expect("set-versioning should succeed");
        assert!(
            versioned
                .bucket_state
                .as_ref()
                .is_some_and(|state| state.versioning_enabled)
        );
        assert_eq!(versioned.tombstone_state, Some(tombstone.clone()));

        let lifecycle = apply_bucket_metadata_operation(
            versioned.bucket_state.as_ref(),
            versioned.tombstone_state.as_ref(),
            &BucketMetadataOperation::SetLifecycle {
                bucket: "photos".to_string(),
                enabled: true,
            },
        )
        .expect("set-lifecycle should succeed");
        assert!(
            lifecycle
                .bucket_state
                .as_ref()
                .is_some_and(|state| state.lifecycle_enabled)
        );
        assert_eq!(lifecycle.tombstone_state, Some(tombstone));
    }

    #[test]
    fn apply_operations_reject_invalid_bucket_names_and_missing_buckets() {
        let create_result = apply_bucket_metadata_operation(
            None,
            None,
            &BucketMetadataOperation::CreateBucket {
                bucket: "   ".to_string(),
                at_unix_ms: 1,
            },
        );
        assert_eq!(
            create_result,
            Err(BucketMetadataOperationError::InvalidBucketName)
        );

        let set_result = apply_bucket_metadata_operation(
            None,
            None,
            &BucketMetadataOperation::SetVersioning {
                bucket: "photos".to_string(),
                enabled: true,
            },
        );
        assert_eq!(
            set_result,
            Err(BucketMetadataOperationError::BucketNotFound)
        );
    }

    #[test]
    fn lifecycle_configuration_upsert_requires_bucket_and_non_empty_xml() {
        let missing_bucket = apply_bucket_lifecycle_configuration_operation(
            None,
            false,
            &BucketLifecycleConfigurationOperation::UpsertConfiguration {
                bucket: "photos".to_string(),
                configuration_xml: "<LifecycleConfiguration/>".to_string(),
                updated_at_unix_ms: 7,
            },
        );
        assert_eq!(
            missing_bucket,
            Err(BucketLifecycleConfigurationOperationError::BucketNotFound)
        );

        let invalid_xml = apply_bucket_lifecycle_configuration_operation(
            None,
            true,
            &BucketLifecycleConfigurationOperation::UpsertConfiguration {
                bucket: "photos".to_string(),
                configuration_xml: "   ".to_string(),
                updated_at_unix_ms: 8,
            },
        );
        assert_eq!(
            invalid_xml,
            Err(BucketLifecycleConfigurationOperationError::InvalidLifecycleConfiguration)
        );

        let outcome = apply_bucket_lifecycle_configuration_operation(
            None,
            true,
            &BucketLifecycleConfigurationOperation::UpsertConfiguration {
                bucket: "photos".to_string(),
                configuration_xml: "<LifecycleConfiguration><Rule/></LifecycleConfiguration>"
                    .to_string(),
                updated_at_unix_ms: 9,
            },
        )
        .expect("upsert should succeed");
        assert_eq!(
            outcome.configuration_state,
            Some(BucketLifecycleConfigurationState {
                bucket: "photos".to_string(),
                configuration_xml:
                    "<LifecycleConfiguration><Rule/></LifecycleConfiguration>".to_string(),
                updated_at_unix_ms: 9,
            })
        );
    }

    #[test]
    fn lifecycle_configuration_delete_requires_existing_configuration() {
        let missing_configuration = apply_bucket_lifecycle_configuration_operation(
            None,
            true,
            &BucketLifecycleConfigurationOperation::DeleteConfiguration {
                bucket: "photos".to_string(),
            },
        );
        assert_eq!(
            missing_configuration,
            Err(BucketLifecycleConfigurationOperationError::ConfigurationNotFound)
        );

        let existing = BucketLifecycleConfigurationState {
            bucket: "photos".to_string(),
            configuration_xml: "<LifecycleConfiguration><Rule/></LifecycleConfiguration>"
                .to_string(),
            updated_at_unix_ms: 10,
        };
        let deleted = apply_bucket_lifecycle_configuration_operation(
            Some(&existing),
            true,
            &BucketLifecycleConfigurationOperation::DeleteConfiguration {
                bucket: "photos".to_string(),
            },
        )
        .expect("delete should succeed");
        assert_eq!(deleted.configuration_state, None);
    }

    #[test]
    fn lifecycle_configuration_operation_error_labels_are_stable() {
        assert_eq!(
            BucketLifecycleConfigurationOperationError::InvalidBucketName.as_str(),
            "invalid-bucket-name"
        );
        assert_eq!(
            BucketLifecycleConfigurationOperationError::InvalidLifecycleConfiguration.as_str(),
            "invalid-lifecycle-configuration"
        );
        assert_eq!(
            BucketLifecycleConfigurationOperationError::BucketNotFound.as_str(),
            "bucket-not-found"
        );
        assert_eq!(
            BucketLifecycleConfigurationOperationError::ConfigurationNotFound.as_str(),
            "lifecycle-configuration-not-found"
        );
    }

    #[test]
    fn operation_error_labels_are_stable() {
        assert_eq!(
            BucketMetadataOperationError::InvalidBucketName.as_str(),
            "invalid-bucket-name"
        );
        assert_eq!(
            BucketMetadataOperationError::BucketAlreadyExists.as_str(),
            "bucket-already-exists"
        );
        assert_eq!(
            BucketMetadataOperationError::BucketNotFound.as_str(),
            "bucket-not-found"
        );
        assert_eq!(
            BucketMetadataOperationError::TombstoneRetentionActive.as_str(),
            "tombstone-retention-active"
        );
        assert_eq!(
            BucketMetadataOperationError::InvalidRetentionWindow.as_str(),
            "invalid-retention-window"
        );
    }
}
