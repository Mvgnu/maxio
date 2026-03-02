mod bucket;
mod checksum;
mod multipart;
mod object;
mod versioning;

use super::chunk_reader::VerifiedChunkReader;
use super::layout;
use super::lifecycle;
use super::validation;
use super::{
    BucketMeta, ByteStream, ChecksumAlgorithm, ChunkInfo, ChunkKind, ChunkManifest, DeleteResult,
    MultipartUploadMeta, ObjectMeta, PartMeta, PutResult, StorageError,
};
use base64::Engine;
use checksum::{ChecksumHasher, finalize_checksum};
use md5::{Digest, Md5};
use sha2::Sha256;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};

fn version_id_from_meta<'a>(meta: &'a ObjectMeta, context: &str) -> Result<&'a str, StorageError> {
    meta.version_id.as_deref().ok_or_else(|| {
        StorageError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("missing version_id while {} for key {}", context, meta.key),
        ))
    })
}

pub struct FilesystemStorage {
    buckets_dir: PathBuf,
    erasure_coding: bool,
    chunk_size: u64,
    parity_shards: u32,
}

#[cfg(test)]
mod lifecycle_tests {
    use super::{BucketMeta, ChecksumAlgorithm, FilesystemStorage, StorageError};
    use crate::storage::lifecycle::LifecycleRule;
    use chrono::{TimeZone, Utc};
    use tempfile::TempDir;
    use tokio::fs;

    fn bucket_meta(name: &str) -> BucketMeta {
        BucketMeta {
            name: name.to_string(),
            created_at: "2026-03-01T00:00:00.000Z".to_string(),
            region: "us-east-1".to_string(),
            versioning: false,
        }
    }

    #[tokio::test]
    async fn lifecycle_rules_roundtrip_and_clear() {
        let tmp = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(tmp.path().to_str().unwrap(), false, 1024, 0)
            .await
            .unwrap();
        storage
            .create_bucket(&bucket_meta("lifecycle"))
            .await
            .unwrap();

        let rules = vec![
            LifecycleRule {
                id: "logs-30d".to_string(),
                prefix: "logs/".to_string(),
                expiration_days: 30,
                enabled: true,
            },
            LifecycleRule {
                id: "tmp-7d".to_string(),
                prefix: "tmp/".to_string(),
                expiration_days: 7,
                enabled: false,
            },
        ];

        storage
            .set_lifecycle_rules("lifecycle", &rules)
            .await
            .unwrap();
        let loaded = storage.get_lifecycle_rules("lifecycle").await.unwrap();
        assert_eq!(loaded, rules);

        storage.set_lifecycle_rules("lifecycle", &[]).await.unwrap();
        let cleared = storage.get_lifecycle_rules("lifecycle").await.unwrap();
        assert!(cleared.is_empty());
        assert!(
            !fs::try_exists(storage.lifecycle_path("lifecycle"))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn apply_lifecycle_once_deletes_expired_matching_objects() {
        let tmp = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(tmp.path().to_str().unwrap(), false, 1024, 0)
            .await
            .unwrap();
        storage
            .create_bucket(&bucket_meta("lifecycle"))
            .await
            .unwrap();

        storage
            .put_object(
                "lifecycle",
                "logs/old.txt",
                "text/plain",
                Box::pin(std::io::Cursor::new(b"old".to_vec())),
                None,
            )
            .await
            .unwrap();
        storage
            .put_object(
                "lifecycle",
                "logs/new.txt",
                "text/plain",
                Box::pin(std::io::Cursor::new(b"new".to_vec())),
                None,
            )
            .await
            .unwrap();

        let mut old_meta = storage
            .head_object("lifecycle", "logs/old.txt")
            .await
            .unwrap();
        old_meta.last_modified = "2026-02-20T00:00:00.000Z".to_string();
        fs::write(
            storage.meta_path("lifecycle", "logs/old.txt"),
            serde_json::to_string_pretty(&old_meta).unwrap(),
        )
        .await
        .unwrap();

        let mut new_meta = storage
            .head_object("lifecycle", "logs/new.txt")
            .await
            .unwrap();
        new_meta.last_modified = "2026-02-28T00:00:00.000Z".to_string();
        fs::write(
            storage.meta_path("lifecycle", "logs/new.txt"),
            serde_json::to_string_pretty(&new_meta).unwrap(),
        )
        .await
        .unwrap();

        storage
            .set_lifecycle_rules(
                "lifecycle",
                &[LifecycleRule {
                    id: "logs-7d".to_string(),
                    prefix: "logs/".to_string(),
                    expiration_days: 7,
                    enabled: true,
                }],
            )
            .await
            .unwrap();

        let now = Utc.with_ymd_and_hms(2026, 3, 1, 12, 0, 0).unwrap();
        let deleted = storage
            .apply_lifecycle_once("lifecycle", now)
            .await
            .unwrap();
        assert_eq!(deleted, vec!["logs/old.txt".to_string()]);
        assert!(
            storage
                .head_object("lifecycle", "logs/new.txt")
                .await
                .is_ok()
        );
        assert!(matches!(
            storage.head_object("lifecycle", "logs/old.txt").await,
            Err(StorageError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn lifecycle_rules_missing_bucket_returns_not_found() {
        let tmp = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(tmp.path().to_str().unwrap(), false, 1024, 0)
            .await
            .unwrap();
        assert!(matches!(
            storage.get_lifecycle_rules("missing").await,
            Err(StorageError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn list_paths_missing_bucket_return_not_found() {
        let tmp = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(tmp.path().to_str().unwrap(), false, 1024, 0)
            .await
            .unwrap();

        assert!(matches!(
            storage.list_objects("missing", "").await,
            Err(StorageError::NotFound(ref b)) if b == "missing"
        ));
        assert!(matches!(
            storage.list_object_versions("missing", "").await,
            Err(StorageError::NotFound(ref b)) if b == "missing"
        ));
        assert!(matches!(
            storage.list_multipart_uploads("missing").await,
            Err(StorageError::NotFound(ref b)) if b == "missing"
        ));
    }

    #[tokio::test]
    async fn put_object_missing_bucket_returns_not_found_and_does_not_create_bucket_dir() {
        let tmp = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(tmp.path().to_str().unwrap(), false, 1024, 0)
            .await
            .unwrap();

        let result = storage
            .put_object(
                "missing",
                "orphan.txt",
                "text/plain",
                Box::pin(std::io::Cursor::new(b"orphan".to_vec())),
                None,
            )
            .await;
        assert!(matches!(result, Err(StorageError::NotFound(ref b)) if b == "missing"));
        assert!(
            !fs::try_exists(storage.buckets_dir.join("missing"))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn put_object_chunked_missing_bucket_returns_not_found_and_does_not_create_bucket_dir() {
        let tmp = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(tmp.path().to_str().unwrap(), true, 4, 0)
            .await
            .unwrap();

        let result = storage
            .put_object(
                "missing",
                "orphan-chunked.txt",
                "text/plain",
                Box::pin(std::io::Cursor::new(b"orphan".to_vec())),
                None,
            )
            .await;
        assert!(matches!(result, Err(StorageError::NotFound(ref b)) if b == "missing"));
        assert!(
            !fs::try_exists(storage.buckets_dir.join("missing"))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn create_multipart_upload_missing_bucket_returns_not_found_and_does_not_create_bucket_dir()
     {
        let tmp = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(tmp.path().to_str().unwrap(), false, 1024, 0)
            .await
            .unwrap();

        let result = storage
            .create_multipart_upload("missing", "multipart.txt", "text/plain", None)
            .await;
        assert!(matches!(result, Err(StorageError::NotFound(ref b)) if b == "missing"));
        assert!(
            !fs::try_exists(storage.buckets_dir.join("missing"))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn upload_part_checksum_mismatch_cleans_orphaned_part_files() {
        let tmp = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(tmp.path().to_str().unwrap(), false, 1024, 0)
            .await
            .unwrap();
        storage
            .create_bucket(&bucket_meta("lifecycle"))
            .await
            .unwrap();

        let upload = storage
            .create_multipart_upload("lifecycle", "bad-checksum.txt", "text/plain", None)
            .await
            .unwrap();

        let result = storage
            .upload_part(
                "lifecycle",
                &upload.upload_id,
                1,
                Box::pin(std::io::Cursor::new(b"part-content".to_vec())),
                Some((ChecksumAlgorithm::SHA256, Some("AAAA".to_string()))),
            )
            .await;
        assert!(matches!(result, Err(StorageError::ChecksumMismatch(_))));

        assert!(
            !fs::try_exists(storage.part_path("lifecycle", &upload.upload_id, 1))
                .await
                .unwrap(),
            "part data file should be removed after checksum mismatch"
        );
        assert!(
            !fs::try_exists(storage.part_meta_path("lifecycle", &upload.upload_id, 1))
                .await
                .unwrap(),
            "part metadata file should not exist after checksum mismatch"
        );
    }

    #[tokio::test]
    async fn apply_lifecycle_once_ignores_disabled_rules() {
        let tmp = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(tmp.path().to_str().unwrap(), false, 1024, 0)
            .await
            .unwrap();
        storage
            .create_bucket(&bucket_meta("lifecycle"))
            .await
            .unwrap();

        storage
            .put_object(
                "lifecycle",
                "logs/old.txt",
                "text/plain",
                Box::pin(std::io::Cursor::new(b"old".to_vec())),
                None,
            )
            .await
            .unwrap();

        let mut old_meta = storage
            .head_object("lifecycle", "logs/old.txt")
            .await
            .unwrap();
        old_meta.last_modified = "2026-02-20T00:00:00.000Z".to_string();
        fs::write(
            storage.meta_path("lifecycle", "logs/old.txt"),
            serde_json::to_string_pretty(&old_meta).unwrap(),
        )
        .await
        .unwrap();

        storage
            .set_lifecycle_rules(
                "lifecycle",
                &[LifecycleRule {
                    id: "logs-7d-disabled".to_string(),
                    prefix: "logs/".to_string(),
                    expiration_days: 7,
                    enabled: false,
                }],
            )
            .await
            .unwrap();

        let now = Utc.with_ymd_and_hms(2026, 3, 1, 12, 0, 0).unwrap();
        let deleted = storage
            .apply_lifecycle_once("lifecycle", now)
            .await
            .unwrap();
        assert!(deleted.is_empty(), "disabled rule must not delete objects");
        assert!(
            storage
                .head_object("lifecycle", "logs/old.txt")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn delete_object_missing_bucket_returns_not_found() {
        let tmp = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(tmp.path().to_str().unwrap(), false, 1024, 0)
            .await
            .unwrap();

        let result = storage.delete_object("missing", "nope.txt").await;
        assert!(matches!(result, Err(StorageError::NotFound(ref b)) if b == "missing"));
    }

    #[tokio::test]
    async fn put_object_meta_write_failure_cleans_orphaned_data_file() {
        let tmp = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(tmp.path().to_str().unwrap(), false, 1024, 0)
            .await
            .unwrap();
        storage
            .create_bucket(&bucket_meta("lifecycle"))
            .await
            .unwrap();

        let key = "broken-meta-write.txt";
        let meta_path = storage.meta_path("lifecycle", key);
        if let Some(parent) = meta_path.parent() {
            fs::create_dir_all(parent).await.unwrap();
        }
        // Force fs::write(meta_path, ...) to fail with "Is a directory".
        fs::create_dir_all(&meta_path).await.unwrap();

        let result = storage
            .put_object(
                "lifecycle",
                key,
                "text/plain",
                Box::pin(std::io::Cursor::new(b"content".to_vec())),
                None,
            )
            .await;
        assert!(matches!(result, Err(StorageError::Io(_))));

        // Data file must be cleaned up when metadata persistence fails.
        assert!(
            !fs::try_exists(storage.object_path("lifecycle", key))
                .await
                .unwrap(),
            "object data file should be removed on metadata write failure"
        );
    }

    #[tokio::test]
    async fn put_object_chunked_meta_write_failure_cleans_orphaned_ec_dir() {
        let tmp = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(tmp.path().to_str().unwrap(), true, 4, 0)
            .await
            .unwrap();
        storage
            .create_bucket(&bucket_meta("lifecycle"))
            .await
            .unwrap();

        let key = "broken-chunked-meta-write.txt";
        let meta_path = storage.meta_path("lifecycle", key);
        if let Some(parent) = meta_path.parent() {
            fs::create_dir_all(parent).await.unwrap();
        }
        // Force fs::write(meta_path, ...) to fail with "Is a directory".
        fs::create_dir_all(&meta_path).await.unwrap();

        let result = storage
            .put_object(
                "lifecycle",
                key,
                "text/plain",
                Box::pin(std::io::Cursor::new(b"chunked-content".to_vec())),
                None,
            )
            .await;
        assert!(matches!(result, Err(StorageError::Io(_))));

        assert!(
            !fs::try_exists(storage.ec_dir("lifecycle", key))
                .await
                .unwrap(),
            "chunk directory should be removed on metadata write failure"
        );
    }

    #[tokio::test]
    async fn complete_multipart_meta_write_failure_cleans_orphaned_object_file() {
        let tmp = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(tmp.path().to_str().unwrap(), false, 1024, 0)
            .await
            .unwrap();
        storage
            .create_bucket(&bucket_meta("lifecycle"))
            .await
            .unwrap();

        let key = "multipart-failure.txt";
        let upload = storage
            .create_multipart_upload("lifecycle", key, "text/plain", None)
            .await
            .unwrap();
        let part = storage
            .upload_part(
                "lifecycle",
                &upload.upload_id,
                1,
                Box::pin(std::io::Cursor::new(b"multipart-content".to_vec())),
                None,
            )
            .await
            .unwrap();

        let meta_path = storage.meta_path("lifecycle", key);
        if let Some(parent) = meta_path.parent() {
            fs::create_dir_all(parent).await.unwrap();
        }
        fs::create_dir_all(&meta_path).await.unwrap();

        let result = storage
            .complete_multipart_upload(
                "lifecycle",
                &upload.upload_id,
                &[(part.part_number, part.etag.clone())],
            )
            .await;
        assert!(matches!(result, Err(StorageError::Io(_))));

        assert!(
            !fs::try_exists(storage.object_path("lifecycle", key))
                .await
                .unwrap(),
            "completed object file should be removed when metadata write fails"
        );
        assert!(
            fs::try_exists(storage.upload_dir("lifecycle", &upload.upload_id))
                .await
                .unwrap(),
            "multipart upload directory should remain for retry"
        );
    }

    #[tokio::test]
    async fn complete_multipart_chunked_meta_write_failure_cleans_orphaned_ec_dir() {
        let tmp = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(tmp.path().to_str().unwrap(), true, 4, 0)
            .await
            .unwrap();
        storage
            .create_bucket(&bucket_meta("lifecycle"))
            .await
            .unwrap();

        let key = "multipart-chunked-failure.txt";
        let upload = storage
            .create_multipart_upload("lifecycle", key, "text/plain", None)
            .await
            .unwrap();
        let part = storage
            .upload_part(
                "lifecycle",
                &upload.upload_id,
                1,
                Box::pin(std::io::Cursor::new(b"chunked-multipart-content".to_vec())),
                None,
            )
            .await
            .unwrap();

        let meta_path = storage.meta_path("lifecycle", key);
        if let Some(parent) = meta_path.parent() {
            fs::create_dir_all(parent).await.unwrap();
        }
        fs::create_dir_all(&meta_path).await.unwrap();

        let result = storage
            .complete_multipart_upload(
                "lifecycle",
                &upload.upload_id,
                &[(part.part_number, part.etag.clone())],
            )
            .await;
        assert!(matches!(result, Err(StorageError::Io(_))));

        assert!(
            !fs::try_exists(storage.ec_dir("lifecycle", key))
                .await
                .unwrap(),
            "chunk directory should be removed when metadata write fails"
        );
        assert!(
            fs::try_exists(storage.upload_dir("lifecycle", &upload.upload_id))
                .await
                .unwrap(),
            "multipart upload directory should remain for retry"
        );
    }
}

#[cfg(test)]
mod versioning_tests {
    use super::{BucketMeta, FilesystemStorage, ObjectMeta, StorageError, version_id_from_meta};
    use tempfile::TempDir;
    use tokio::fs;
    use tokio::io::AsyncReadExt;

    fn bucket_meta(name: &str) -> BucketMeta {
        BucketMeta {
            name: name.to_string(),
            created_at: "2026-03-01T00:00:00.000Z".to_string(),
            region: "us-east-1".to_string(),
            versioning: true,
        }
    }

    #[test]
    fn version_id_from_meta_rejects_missing_value() {
        let meta = ObjectMeta {
            key: "docs/readme.txt".to_string(),
            size: 1,
            etag: "\"abc\"".to_string(),
            content_type: "text/plain".to_string(),
            last_modified: "2026-03-01T00:00:00.000Z".to_string(),
            version_id: None,
            is_delete_marker: false,
            storage_format: None,
            checksum_algorithm: None,
            checksum_value: None,
        };

        let err =
            version_id_from_meta(&meta, "testing").expect_err("should reject missing version");
        match err {
            StorageError::Io(io_err) => assert_eq!(io_err.kind(), std::io::ErrorKind::InvalidData),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn delete_object_version_fails_cleanly_when_latest_version_metadata_lacks_version_id() {
        let tmp = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(tmp.path().to_str().unwrap(), false, 1024, 0)
            .await
            .unwrap();
        storage
            .create_bucket(&bucket_meta("versioned"))
            .await
            .unwrap();

        storage
            .put_object(
                "versioned",
                "docs/readme.txt",
                "text/plain",
                Box::pin(std::io::Cursor::new(b"v1".to_vec())),
                None,
            )
            .await
            .unwrap();
        storage
            .put_object(
                "versioned",
                "docs/readme.txt",
                "text/plain",
                Box::pin(std::io::Cursor::new(b"v2".to_vec())),
                None,
            )
            .await
            .unwrap();

        let versions = storage
            .list_object_versions("versioned", "docs/readme.txt")
            .await
            .unwrap();
        assert_eq!(versions.len(), 2);
        let latest_version_id = versions[0]
            .version_id
            .as_ref()
            .expect("latest version should have id")
            .to_string();
        let older_version_id = versions[1]
            .version_id
            .as_ref()
            .expect("older version should have id")
            .to_string();

        let latest_meta_path =
            storage.version_meta_path("versioned", "docs/readme.txt", &latest_version_id);
        let mut latest_json: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&latest_meta_path).await.unwrap()).unwrap();
        latest_json
            .as_object_mut()
            .expect("metadata should be object")
            .remove("version_id");
        fs::write(
            &latest_meta_path,
            serde_json::to_string_pretty(&latest_json).unwrap(),
        )
        .await
        .unwrap();

        let err = storage
            .delete_object_version("versioned", "docs/readme.txt", &older_version_id)
            .await
            .expect_err("corrupt latest metadata should not panic");
        match err {
            StorageError::Io(io_err) => assert_eq!(io_err.kind(), std::io::ErrorKind::InvalidData),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_object_version_range_reads_selected_version_data() {
        let tmp = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(tmp.path().to_str().unwrap(), false, 1024, 0)
            .await
            .unwrap();
        storage
            .create_bucket(&bucket_meta("versioned"))
            .await
            .unwrap();

        storage
            .put_object(
                "versioned",
                "docs/range.txt",
                "text/plain",
                Box::pin(std::io::Cursor::new(b"AAAAAA".to_vec())),
                None,
            )
            .await
            .unwrap();
        storage
            .put_object(
                "versioned",
                "docs/range.txt",
                "text/plain",
                Box::pin(std::io::Cursor::new(b"BBBBBB".to_vec())),
                None,
            )
            .await
            .unwrap();

        let versions = storage
            .list_object_versions("versioned", "docs/range.txt")
            .await
            .unwrap();
        let older_version_id = versions[1]
            .version_id
            .as_ref()
            .expect("older version should have id")
            .to_string();

        let (mut reader, _) = storage
            .get_object_version_range("versioned", "docs/range.txt", &older_version_id, 1, 3)
            .await
            .unwrap();
        let mut body = Vec::new();
        reader.read_to_end(&mut body).await.unwrap();
        assert_eq!(body, b"AAA");
    }

    #[tokio::test]
    async fn get_object_version_range_reads_selected_chunked_version_data() {
        let tmp = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(tmp.path().to_str().unwrap(), true, 4, 0)
            .await
            .unwrap();
        storage
            .create_bucket(&bucket_meta("versioned"))
            .await
            .unwrap();

        storage
            .put_object(
                "versioned",
                "docs/range-chunked.bin",
                "application/octet-stream",
                Box::pin(std::io::Cursor::new(b"AAAAAA".to_vec())),
                None,
            )
            .await
            .unwrap();
        storage
            .put_object(
                "versioned",
                "docs/range-chunked.bin",
                "application/octet-stream",
                Box::pin(std::io::Cursor::new(b"BBBBBB".to_vec())),
                None,
            )
            .await
            .unwrap();

        let versions = storage
            .list_object_versions("versioned", "docs/range-chunked.bin")
            .await
            .unwrap();
        let older_version_id = versions[1]
            .version_id
            .as_ref()
            .expect("older version should have id")
            .to_string();

        let (mut reader, meta) = storage
            .get_object_version_range(
                "versioned",
                "docs/range-chunked.bin",
                &older_version_id,
                1,
                3,
            )
            .await
            .unwrap();
        let mut body = Vec::new();
        reader.read_to_end(&mut body).await.unwrap();
        assert_eq!(body, b"AAA");
        assert_eq!(meta.version_id.as_deref(), Some(older_version_id.as_str()));
        assert_eq!(meta.storage_format.as_deref(), Some("chunked-v1"));
    }

    #[tokio::test]
    async fn write_version_meta_write_failure_cleans_orphaned_version_data_file() {
        let tmp = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(tmp.path().to_str().unwrap(), false, 1024, 0)
            .await
            .unwrap();
        storage
            .create_bucket(&bucket_meta("versioned"))
            .await
            .unwrap();

        let key = "docs/snapshot-failure.txt";
        let version_id = "snapshot-failure-v1";
        let obj_path = storage.object_path("versioned", key);
        if let Some(parent) = obj_path.parent() {
            fs::create_dir_all(parent).await.unwrap();
        }
        fs::write(&obj_path, b"snapshot-data").await.unwrap();

        let meta = ObjectMeta {
            key: key.to_string(),
            size: 13,
            etag: "\"etag\"".to_string(),
            content_type: "text/plain".to_string(),
            last_modified: "2026-03-01T00:00:00.000Z".to_string(),
            version_id: Some(version_id.to_string()),
            is_delete_marker: false,
            storage_format: None,
            checksum_algorithm: None,
            checksum_value: None,
        };

        let version_meta_path = storage.version_meta_path("versioned", key, version_id);
        fs::create_dir_all(&version_meta_path).await.unwrap();

        let err = storage
            .write_version("versioned", key, &meta, &obj_path)
            .await
            .expect_err("version metadata write should fail");
        match err {
            StorageError::Io(io_err) => {
                assert_eq!(io_err.kind(), std::io::ErrorKind::IsADirectory);
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let version_data_path = storage.version_data_path("versioned", key, version_id);
        assert!(
            !fs::try_exists(version_data_path).await.unwrap(),
            "version data file should be cleaned on metadata write failure"
        );
    }

    #[tokio::test]
    async fn write_version_chunked_meta_write_failure_cleans_orphaned_version_ec_dir() {
        let tmp = TempDir::new().unwrap();
        let storage = FilesystemStorage::new(tmp.path().to_str().unwrap(), true, 4, 0)
            .await
            .unwrap();
        storage
            .create_bucket(&bucket_meta("versioned"))
            .await
            .unwrap();

        let key = "docs/chunked-snapshot-failure.bin";
        let version_id = "snapshot-failure-chunked-v1";
        let src_ec_dir = storage.ec_dir("versioned", key);
        fs::create_dir_all(&src_ec_dir).await.unwrap();
        fs::write(src_ec_dir.join("manifest.json"), "{}")
            .await
            .unwrap();
        fs::write(src_ec_dir.join("0.chunk"), b"abcd")
            .await
            .unwrap();

        let meta = ObjectMeta {
            key: key.to_string(),
            size: 4,
            etag: "\"etag\"".to_string(),
            content_type: "application/octet-stream".to_string(),
            last_modified: "2026-03-01T00:00:00.000Z".to_string(),
            version_id: Some(version_id.to_string()),
            is_delete_marker: false,
            storage_format: Some("chunked-v1".to_string()),
            checksum_algorithm: None,
            checksum_value: None,
        };

        let version_meta_path = storage.version_meta_path("versioned", key, version_id);
        fs::create_dir_all(&version_meta_path).await.unwrap();

        let err = storage
            .write_version_chunked("versioned", key, &meta)
            .await
            .expect_err("chunked version metadata write should fail");
        match err {
            StorageError::Io(io_err) => {
                assert_eq!(io_err.kind(), std::io::ErrorKind::IsADirectory);
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let version_ec_dir = storage.version_ec_dir("versioned", key, version_id);
        assert!(
            !fs::try_exists(version_ec_dir).await.unwrap(),
            "copied version chunk directory should be cleaned on metadata write failure"
        );
    }
}

impl FilesystemStorage {
    pub async fn new(
        data_dir: &str,
        erasure_coding: bool,
        chunk_size: u64,
        parity_shards: u32,
    ) -> Result<Self, anyhow::Error> {
        let buckets_dir = Path::new(data_dir).join("buckets");
        fs::create_dir_all(&buckets_dir).await?;
        Ok(Self {
            buckets_dir,
            erasure_coding,
            chunk_size,
            parity_shards,
        })
    }
}
