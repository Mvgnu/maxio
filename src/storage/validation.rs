use std::path::{Component, Path};

use super::StorageError;

/// Validate that an object key does not contain path traversal components.
pub(crate) fn validate_key(key: &str) -> Result<(), StorageError> {
    if key.is_empty() {
        return Err(StorageError::InvalidKey("Key must not be empty".into()));
    }
    if key.len() > 1024 {
        return Err(StorageError::InvalidKey(
            "Key must not exceed 1024 bytes".into(),
        ));
    }
    if key.contains('\0') || key.contains('\\') {
        return Err(StorageError::InvalidKey(
            "Key contains an unsupported path character".into(),
        ));
    }
    // The legacy on-disk layout shares a namespace with its sidecars. Until a
    // migration to encoded keys exists, reject collisions instead of corrupting
    // bucket settings, another object's metadata, or a multipart/version store.
    for segment in key.strip_suffix('/').unwrap_or(key).split('/') {
        if segment.is_empty() || matches!(segment, "." | "..") {
            return Err(StorageError::InvalidKey(
                "Key must not contain empty or relative path segments".into(),
            ));
        }
        if matches!(
            segment,
            ".bucket.json" | ".lifecycle.json" | ".uploads" | ".versions" | ".folder"
        ) || segment.ends_with(".meta.json")
            || segment.ends_with(".ec")
        {
            return Err(StorageError::InvalidKey(
                "Key collides with reserved storage metadata".into(),
            ));
        }
    }
    let path = Path::new(key);
    for component in path.components() {
        match component {
            Component::ParentDir => {
                return Err(StorageError::InvalidKey(
                    "Key must not contain '..' path components".into(),
                ));
            }
            Component::RootDir => {
                return Err(StorageError::InvalidKey(
                    "Key must not be an absolute path".into(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

pub(crate) fn validate_version_id(version_id: &str) -> Result<(), StorageError> {
    if version_id.is_empty()
        || version_id.len() > 1024
        || matches!(version_id, "." | "..")
        || version_id.contains(['/', '\\', '\0'])
        || !matches!(
            Path::new(version_id).components().next(),
            Some(Component::Normal(_))
        )
    {
        return Err(StorageError::VersionNotFound(version_id.to_string()));
    }
    Ok(())
}

pub(crate) fn validate_upload_id(upload_id: &str) -> Result<(), StorageError> {
    if upload_id.is_empty() {
        return Err(StorageError::UploadNotFound(upload_id.to_string()));
    }
    if upload_id.contains('/') || upload_id.contains('\\') || upload_id.contains("..") {
        return Err(StorageError::UploadNotFound(upload_id.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_key, validate_upload_id};
    use crate::storage::StorageError;

    #[test]
    fn validate_key_accepts_regular_keys() {
        assert!(validate_key("file.txt").is_ok());
        assert!(validate_key("nested/path/file.txt").is_ok());
        assert!(validate_key("folder/").is_ok());
    }

    #[test]
    fn validate_key_rejects_empty_and_traversal() {
        assert!(matches!(validate_key(""), Err(StorageError::InvalidKey(_))));
        assert!(matches!(
            validate_key("../escape.txt"),
            Err(StorageError::InvalidKey(_))
        ));
        assert!(matches!(
            validate_key("a/../../escape.txt"),
            Err(StorageError::InvalidKey(_))
        ));
    }

    #[test]
    fn validate_key_rejects_absolute_and_too_long() {
        assert!(matches!(
            validate_key("/absolute/path.txt"),
            Err(StorageError::InvalidKey(_))
        ));
        let too_long = "a".repeat(1025);
        assert!(matches!(
            validate_key(&too_long),
            Err(StorageError::InvalidKey(_))
        ));
    }

    #[test]
    fn validate_upload_id_accepts_normal_id() {
        assert!(validate_upload_id("123e4567-e89b-12d3-a456-426614174000").is_ok());
    }

    #[test]
    fn validate_upload_id_rejects_empty_and_pathy_values() {
        assert!(matches!(
            validate_upload_id(""),
            Err(StorageError::UploadNotFound(_))
        ));
        assert!(matches!(
            validate_upload_id("../bad"),
            Err(StorageError::UploadNotFound(_))
        ));
        assert!(matches!(
            validate_upload_id("bad/segment"),
            Err(StorageError::UploadNotFound(_))
        ));
        assert!(matches!(
            validate_upload_id(r"bad\segment"),
            Err(StorageError::UploadNotFound(_))
        ));
    }
}
