use std::collections::{BTreeSet, HashMap};
use std::path::{Component, Path};

use crate::error::S3Error;
use crate::server::AppState;
use crate::storage::{ObjectMeta, StorageError};
use crate::xml::types::{CommonPrefix, DeleteMarkerEntry, ObjectEntry, VersionEntry};

const MAX_KEYS_CAP: usize = 1000;

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
    pub(super) fn from_params(params: &HashMap<String, String>) -> Result<Self, S3Error> {
        let start_after = params.get("start-after").cloned();
        let continuation_token = params.get("continuation-token").cloned();
        let effective_start = if let Some(token) = continuation_token.as_deref() {
            Some(
                decode_continuation_token(token)
                    .ok_or_else(|| S3Error::invalid_argument("Invalid continuation token"))?,
            )
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

pub(super) fn decode_continuation_token(token: &str) -> Option<String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(token)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

pub(super) fn encode_continuation_token(key: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(key)
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
    use crate::error::S3ErrorCode;

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
    fn continuation_token_invalid_base64_returns_none() {
        assert_eq!(decode_continuation_token("%%%not-base64%%%"), None);
    }

    #[test]
    fn split_by_delimiter_groups_common_prefixes() {
        let objects = vec![
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
        let objects = vec![
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
        let versions = vec![
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
        let versions = vec![
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
        let versions = vec![
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
        let versions = vec![
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
        let err = match ListV2Query::from_params(&params) {
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
        let err = match ListV2Query::from_params(&params) {
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

        let err = match ListV2Query::from_params(&params) {
            Ok(_) => panic!("empty delimiter should fail"),
            Err(err) => err,
        };
        assert!(matches!(
            err.code,
            crate::error::S3ErrorCode::InvalidArgument
        ));
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
}
