use std::collections::{BTreeSet, HashMap};

use crate::storage::ObjectMeta;
use crate::xml::types::{CommonPrefix, DeleteMarkerEntry, ObjectEntry, VersionEntry};

const MAX_KEYS_CAP: usize = 1000;

pub(super) struct ListV2Query {
    pub(super) prefix: String,
    pub(super) delimiter: Option<String>,
    pub(super) max_keys: usize,
    pub(super) start_after: Option<String>,
    pub(super) continuation_token: Option<String>,
    pub(super) effective_start: Option<String>,
}

impl ListV2Query {
    pub(super) fn from_params(params: &HashMap<String, String>) -> Self {
        let start_after = params.get("start-after").cloned();
        let continuation_token = params.get("continuation-token").cloned();
        let effective_start = continuation_token
            .as_deref()
            .and_then(decode_continuation_token)
            .or_else(|| start_after.clone());

        Self {
            prefix: params.get("prefix").cloned().unwrap_or_default(),
            delimiter: params.get("delimiter").cloned(),
            max_keys: parse_max_keys(params),
            start_after,
            continuation_token,
            effective_start,
        }
    }
}

pub(super) struct ListV1Query {
    pub(super) prefix: String,
    pub(super) delimiter: Option<String>,
    pub(super) max_keys: usize,
    pub(super) marker: Option<String>,
}

impl ListV1Query {
    pub(super) fn from_params(params: &HashMap<String, String>) -> Self {
        Self {
            prefix: params.get("prefix").cloned().unwrap_or_default(),
            delimiter: params.get("delimiter").cloned(),
            max_keys: parse_max_keys(params),
            marker: params.get("marker").cloned(),
        }
    }
}

fn parse_max_keys(params: &HashMap<String, String>) -> usize {
    params
        .get("max-keys")
        .and_then(|v| v.parse().ok())
        .unwrap_or(MAX_KEYS_CAP)
        .min(MAX_KEYS_CAP)
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

pub(super) fn paginate_objects<'a>(
    filtered_objects: Vec<&'a ObjectMeta>,
    max_keys: usize,
) -> (Vec<&'a ObjectMeta>, bool) {
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
}
