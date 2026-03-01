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
