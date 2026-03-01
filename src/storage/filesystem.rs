use super::chunk_reader::VerifiedChunkReader;
use super::layout;
use super::lifecycle::{self, LifecycleRule};
use super::validation;
use super::{
    BucketMeta, ByteStream, ChecksumAlgorithm, ChunkInfo, ChunkKind, ChunkManifest, DeleteResult,
    MultipartUploadMeta, ObjectMeta, PartMeta, PutResult, StorageError,
};
use base64::Engine;
use md5::{Digest, Md5};
use rand::RngExt;
use sha2::Sha256;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader};

enum ChecksumHasher {
    Crc32(crc32fast::Hasher),
    Crc32c(u32),
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
}

impl ChecksumHasher {
    fn new(algo: ChecksumAlgorithm) -> Self {
        match algo {
            ChecksumAlgorithm::CRC32 => Self::Crc32(crc32fast::Hasher::new()),
            ChecksumAlgorithm::CRC32C => Self::Crc32c(0),
            ChecksumAlgorithm::SHA1 => Self::Sha1(<sha1::Sha1 as Digest>::new()),
            ChecksumAlgorithm::SHA256 => Self::Sha256(<sha2::Sha256 as Digest>::new()),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Crc32(h) => h.update(data),
            Self::Crc32c(v) => *v = crc32c::crc32c_append(*v, data),
            Self::Sha1(h) => Digest::update(h, data),
            Self::Sha256(h) => Digest::update(h, data),
        }
    }

    fn finalize_base64(self) -> String {
        let b64 = base64::engine::general_purpose::STANDARD;
        match self {
            Self::Crc32(h) => b64.encode(h.finalize().to_be_bytes()),
            Self::Crc32c(v) => b64.encode(v.to_be_bytes()),
            Self::Sha1(h) => b64.encode(Digest::finalize(h)),
            Self::Sha256(h) => b64.encode(Digest::finalize(h)),
        }
    }
}

fn finalize_checksum(
    checksum: Option<(ChecksumAlgorithm, Option<String>)>,
    checksum_hasher: Option<ChecksumHasher>,
) -> Result<(Option<ChecksumAlgorithm>, Option<String>), StorageError> {
    match checksum {
        Some((algo, expected)) => {
            let hasher = checksum_hasher.ok_or_else(|| {
                StorageError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "checksum hasher missing for checksum-enabled write",
                ))
            })?;
            let computed = hasher.finalize_base64();
            if let Some(expected_val) = expected {
                if computed != expected_val {
                    return Err(StorageError::ChecksumMismatch(format!(
                        "expected {}, got {}",
                        expected_val, computed
                    )));
                }
            }
            Ok((Some(algo), Some(computed)))
        }
        None => Ok((None, None)),
    }
}

fn version_id_from_meta<'a>(
    meta: &'a ObjectMeta,
    context: &str,
) -> Result<&'a str, StorageError> {
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
    use super::{BucketMeta, FilesystemStorage, StorageError};
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
            !fs::try_exists(storage.ec_dir("lifecycle", key)).await.unwrap(),
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
            !fs::try_exists(storage.ec_dir("lifecycle", key)).await.unwrap(),
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

        let err = version_id_from_meta(&meta, "testing").expect_err("should reject missing version");
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
        let mut latest_json: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&latest_meta_path).await.unwrap(),
        )
        .unwrap();
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

    // --- Bucket operations ---

    pub async fn create_bucket(&self, meta: &BucketMeta) -> Result<bool, StorageError> {
        let bucket_dir = self.buckets_dir.join(&meta.name);
        match fs::create_dir(&bucket_dir).await {
            Ok(()) => {
                let meta_path = bucket_dir.join(".bucket.json");
                let json = serde_json::to_string_pretty(meta)?;
                if let Err(e) = fs::write(&meta_path, json).await {
                    // Clean up the empty directory to avoid a half-created bucket
                    let _ = fs::remove_dir(&bucket_dir).await;
                    return Err(e.into());
                }
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn head_bucket(&self, name: &str) -> Result<bool, StorageError> {
        Ok(fs::try_exists(self.buckets_dir.join(name).join(".bucket.json")).await?)
    }

    pub async fn delete_bucket(&self, name: &str) -> Result<bool, StorageError> {
        let bucket_dir = self.buckets_dir.join(name);
        if !fs::try_exists(&bucket_dir).await? {
            return Ok(false);
        }

        let has_objects = self.has_objects(&bucket_dir).await?;
        if has_objects {
            return Err(StorageError::BucketNotEmpty);
        }

        // Remove metadata and internal dirs before the bucket dir itself.
        // Use remove_dir (not remove_dir_all) for the bucket dir so it fails
        // atomically if a concurrent put_object added files in between.
        let _ = fs::remove_file(bucket_dir.join(".bucket.json")).await;
        let _ = fs::remove_dir_all(bucket_dir.join(".uploads")).await;
        let _ = fs::remove_dir_all(bucket_dir.join(".versions")).await;
        match fs::remove_dir(&bucket_dir).await {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
                // A concurrent write added files — restore bucket metadata
                // and report not empty. Best-effort: if this fails, the bucket
                // is effectively deleted (head_bucket checks .bucket.json).
                let meta = BucketMeta {
                    name: name.to_string(),
                    created_at: chrono::Utc::now()
                        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                        .to_string(),
                    region: String::new(),
                    versioning: false,
                };
                let _ = fs::write(
                    bucket_dir.join(".bucket.json"),
                    serde_json::to_string_pretty(&meta).unwrap_or_default(),
                )
                .await;
                Err(StorageError::BucketNotEmpty)
            }
            Err(e) => Err(e.into()),
        }
    }

    pub async fn list_buckets(&self) -> Result<Vec<BucketMeta>, StorageError> {
        let mut buckets = Vec::new();
        let mut entries = fs::read_dir(&self.buckets_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_dir() {
                let meta_path = entry.path().join(".bucket.json");
                if let Ok(data) = fs::read_to_string(&meta_path).await {
                    if let Ok(meta) = serde_json::from_str::<BucketMeta>(&data) {
                        buckets.push(meta);
                    }
                }
            }
        }
        buckets.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(buckets)
    }

    fn lifecycle_path(&self, bucket: &str) -> PathBuf {
        layout::lifecycle_path(&self.buckets_dir, bucket)
    }

    pub async fn get_lifecycle_rules(
        &self,
        bucket: &str,
    ) -> Result<Vec<LifecycleRule>, StorageError> {
        if !self.head_bucket(bucket).await? {
            return Err(StorageError::NotFound(bucket.to_string()));
        }

        let path = self.lifecycle_path(bucket);
        let data = match fs::read_to_string(&path).await {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let rules: Vec<LifecycleRule> = serde_json::from_str(&data)?;
        lifecycle::validate_rules(&rules).map_err(StorageError::InvalidKey)?;
        Ok(rules)
    }

    pub async fn set_lifecycle_rules(
        &self,
        bucket: &str,
        rules: &[LifecycleRule],
    ) -> Result<(), StorageError> {
        if !self.head_bucket(bucket).await? {
            return Err(StorageError::NotFound(bucket.to_string()));
        }
        lifecycle::validate_rules(rules).map_err(StorageError::InvalidKey)?;

        let path = self.lifecycle_path(bucket);
        if rules.is_empty() {
            let _ = fs::remove_file(&path).await;
            return Ok(());
        }
        fs::write(path, serde_json::to_string_pretty(rules)?).await?;
        Ok(())
    }

    pub async fn apply_lifecycle_once(
        &self,
        bucket: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<String>, StorageError> {
        let rules = self.get_lifecycle_rules(bucket).await?;
        if rules.is_empty() {
            return Ok(Vec::new());
        }

        let objects = self.list_objects(bucket, "").await?;
        let mut deleted = Vec::new();
        for object in objects {
            if lifecycle::should_expire_object(&object.key, &object.last_modified, &rules, now) {
                self.delete_object(bucket, &object.key).await?;
                deleted.push(object.key);
            }
        }

        deleted.sort();
        Ok(deleted)
    }

    // --- Object operations ---

    fn object_path(&self, bucket: &str, key: &str) -> PathBuf {
        layout::object_path(&self.buckets_dir, bucket, key)
    }

    fn meta_path(&self, bucket: &str, key: &str) -> PathBuf {
        layout::meta_path(&self.buckets_dir, bucket, key)
    }

    fn ec_dir(&self, bucket: &str, key: &str) -> PathBuf {
        layout::ec_dir(&self.buckets_dir, bucket, key)
    }

    fn chunk_path(&self, bucket: &str, key: &str, index: u32) -> PathBuf {
        layout::chunk_path(&self.buckets_dir, bucket, key, index)
    }

    fn manifest_path(&self, bucket: &str, key: &str) -> PathBuf {
        layout::manifest_path(&self.buckets_dir, bucket, key)
    }

    async fn is_chunked_path(ec_dir: &Path) -> Result<bool, StorageError> {
        match fs::metadata(ec_dir).await {
            Ok(meta) => Ok(meta.is_dir()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    async fn read_manifest(&self, bucket: &str, key: &str) -> Result<ChunkManifest, StorageError> {
        let path = self.manifest_path(bucket, key);
        let data = fs::read_to_string(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(key.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        Ok(serde_json::from_str(&data)?)
    }

    fn uploads_dir(&self, bucket: &str) -> PathBuf {
        layout::uploads_dir(&self.buckets_dir, bucket)
    }

    fn upload_dir(&self, bucket: &str, upload_id: &str) -> PathBuf {
        layout::upload_dir(&self.buckets_dir, bucket, upload_id)
    }

    fn upload_meta_path(&self, bucket: &str, upload_id: &str) -> PathBuf {
        layout::upload_meta_path(&self.buckets_dir, bucket, upload_id)
    }

    fn part_path(&self, bucket: &str, upload_id: &str, part_number: u32) -> PathBuf {
        layout::part_path(&self.buckets_dir, bucket, upload_id, part_number)
    }

    fn part_meta_path(&self, bucket: &str, upload_id: &str, part_number: u32) -> PathBuf {
        layout::part_meta_path(&self.buckets_dir, bucket, upload_id, part_number)
    }

    pub async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        content_type: &str,
        mut body: ByteStream,
        checksum: Option<(ChecksumAlgorithm, Option<String>)>,
    ) -> Result<PutResult, StorageError> {
        validation::validate_key(key)?;

        // Folder marker: zero-byte object with key ending in /
        if key.ends_with('/') {
            return self.put_folder_marker(bucket, key).await;
        }

        if self.erasure_coding {
            return self
                .put_object_chunked(
                    bucket,
                    key,
                    content_type,
                    body,
                    checksum.as_ref().map(|(a, _)| *a),
                )
                .await;
        }

        let obj_path = self.object_path(bucket, key);
        if let Some(parent) = obj_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        let mut file = fs::File::create(&obj_path).await?;
        let mut hasher = Md5::new();
        let mut checksum_hasher = checksum
            .as_ref()
            .map(|(algo, _)| ChecksumHasher::new(*algo));
        let mut size: u64 = 0;
        let mut buf = vec![0u8; 64 * 1024];

        loop {
            let n = body.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            if let Some(ref mut ch) = checksum_hasher {
                ch.update(&buf[..n]);
            }
            size += n as u64;
            tokio::io::AsyncWriteExt::write_all(&mut file, &buf[..n]).await?;
        }
        file.flush().await?;

        let etag = hex::encode(hasher.finalize());
        let etag_quoted = format!("\"{}\"", etag);

        // Validate and compute checksum
        let (checksum_algorithm, checksum_value) =
            match finalize_checksum(checksum, checksum_hasher) {
                Ok(value) => value,
                Err(err) => {
                    let _ = fs::remove_file(&obj_path).await;
                    return Err(err);
                }
        };

        let now = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        let versioned = self.is_versioned(bucket).await.unwrap_or(false);
        let version_id = if versioned {
            Some(Self::generate_version_id())
        } else {
            None
        };

        let meta = ObjectMeta {
            key: key.to_string(),
            size,
            etag: etag_quoted.clone(),
            content_type: content_type.to_string(),
            last_modified: now,
            version_id: version_id.clone(),
            is_delete_marker: false,
            storage_format: None,
            checksum_algorithm,
            checksum_value: checksum_value.clone(),
        };

        let meta_path = self.meta_path(bucket, key);
        if let Some(parent) = meta_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let json = serde_json::to_string_pretty(&meta)?;
        if let Err(e) = fs::write(&meta_path, json).await {
            // Avoid leaving a data file without metadata if persistence fails.
            let _ = fs::remove_file(&obj_path).await;
            return Err(e.into());
        }

        if versioned {
            self.write_version(bucket, key, &meta, &obj_path).await?;
        }

        Ok(PutResult {
            size,
            etag: etag_quoted,
            version_id,
            checksum_algorithm,
            checksum_value,
        })
    }

    async fn put_object_chunked(
        &self,
        bucket: &str,
        key: &str,
        content_type: &str,
        mut body: ByteStream,
        checksum_algo: Option<ChecksumAlgorithm>,
    ) -> Result<PutResult, StorageError> {
        let ec_dir = self.ec_dir(bucket, key);
        if let Some(parent) = ec_dir.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::create_dir_all(&ec_dir).await?;

        let mut md5_hasher = Md5::new();
        let mut checksum_hasher = checksum_algo.map(ChecksumHasher::new);
        let mut total_size: u64 = 0;
        let mut chunks: Vec<ChunkInfo> = Vec::new();
        let mut chunk_index: u32 = 0;

        let mut read_buf = vec![0u8; 64 * 1024];
        let mut chunk_buf = Vec::with_capacity(self.chunk_size as usize);

        loop {
            let n = body.read(&mut read_buf).await?;
            if n == 0 {
                // Flush remaining chunk_buf
                if !chunk_buf.is_empty() {
                    let ci = self
                        .write_chunk(bucket, key, chunk_index, &chunk_buf)
                        .await?;
                    chunks.push(ci);
                }
                break;
            }

            md5_hasher.update(&read_buf[..n]);
            if let Some(ref mut ch) = checksum_hasher {
                ch.update(&read_buf[..n]);
            }
            total_size += n as u64;
            chunk_buf.extend_from_slice(&read_buf[..n]);

            while chunk_buf.len() >= self.chunk_size as usize {
                let chunk_data: Vec<u8> = chunk_buf.drain(..self.chunk_size as usize).collect();
                let ci = self
                    .write_chunk(bucket, key, chunk_index, &chunk_data)
                    .await?;
                chunks.push(ci);
                chunk_index += 1;
            }
        }

        // Handle empty object (zero chunks)
        if chunks.is_empty() {
            let ci = self.write_chunk(bucket, key, 0, &[]).await?;
            chunks.push(ci);
        }

        let data_chunk_count = chunks.len() as u32;

        // Compute and write parity shards if configured (skip for empty objects)
        let has_parity = self.parity_shards > 0 && total_size > 0;
        if has_parity {
            let parity_infos = self.compute_and_write_parity(bucket, key, &chunks).await?;
            chunks.extend(parity_infos);
        }

        let manifest = ChunkManifest {
            version: if has_parity { 2 } else { 1 },
            total_size,
            chunk_size: self.chunk_size,
            chunk_count: data_chunk_count,
            chunks,
            parity_shards: if has_parity {
                Some(self.parity_shards)
            } else {
                None
            },
            shard_size: if has_parity {
                Some(self.chunk_size)
            } else {
                None
            },
        };
        let manifest_json = serde_json::to_string_pretty(&manifest)?;
        fs::write(self.manifest_path(bucket, key), manifest_json).await?;

        let etag = hex::encode(md5_hasher.finalize());
        let etag_quoted = format!("\"{}\"", etag);
        let checksum_value = checksum_hasher.map(|h| h.finalize_base64());

        let now = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        let versioned = self.is_versioned(bucket).await.unwrap_or(false);
        let version_id = if versioned {
            Some(Self::generate_version_id())
        } else {
            None
        };

        let storage_format = if has_parity {
            "chunked-v2"
        } else {
            "chunked-v1"
        };
        let meta = ObjectMeta {
            key: key.to_string(),
            size: total_size,
            etag: etag_quoted.clone(),
            content_type: content_type.to_string(),
            last_modified: now,
            version_id: version_id.clone(),
            is_delete_marker: false,
            storage_format: Some(storage_format.to_string()),
            checksum_algorithm: checksum_algo,
            checksum_value: checksum_value.clone(),
        };

        let meta_path = self.meta_path(bucket, key);
        if let Some(parent) = meta_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        if let Err(e) = fs::write(&meta_path, serde_json::to_string_pretty(&meta)?).await {
            // Avoid leaving chunk files without metadata if persistence fails.
            let _ = fs::remove_dir_all(&ec_dir).await;
            return Err(e.into());
        }

        if versioned {
            self.write_version_chunked(bucket, key, &meta).await?;
        }

        Ok(PutResult {
            size: total_size,
            etag: etag_quoted,
            version_id,
            checksum_algorithm: checksum_algo,
            checksum_value,
        })
    }

    async fn write_chunk(
        &self,
        bucket: &str,
        key: &str,
        index: u32,
        data: &[u8],
    ) -> Result<ChunkInfo, StorageError> {
        let path = self.chunk_path(bucket, key, index);
        let sha256 = hex::encode(Sha256::digest(data));
        let mut file = fs::File::create(&path).await?;
        file.write_all(data).await?;
        file.flush().await?;
        Ok(ChunkInfo {
            index,
            size: data.len() as u64,
            sha256,
            kind: ChunkKind::Data,
        })
    }

    /// Compute Reed-Solomon parity shards from the data chunks already on disk,
    /// write them as additional chunk files, and return their ChunkInfo entries.
    async fn compute_and_write_parity(
        &self,
        bucket: &str,
        key: &str,
        data_chunks: &[ChunkInfo],
    ) -> Result<Vec<ChunkInfo>, StorageError> {
        use reed_solomon_erasure::galois_8::ReedSolomon;

        let k = data_chunks.len();
        let m = self.parity_shards as usize;

        if k + m > 255 {
            return Err(StorageError::InvalidKey(format!(
                "too many shards: {} data + {} parity = {} > 255 (GF(2^8) limit). Increase --chunk-size",
                k,
                m,
                k + m
            )));
        }

        let shard_size = self.chunk_size as usize;

        // Read data chunks from disk and pad to shard_size
        let mut all_shards: Vec<Vec<u8>> = Vec::with_capacity(k + m);
        for ci in data_chunks {
            let path = self.chunk_path(bucket, key, ci.index);
            let mut data = fs::read(&path).await?;
            data.resize(shard_size, 0u8);
            all_shards.push(data);
        }

        // Allocate empty parity shards
        for _ in 0..m {
            all_shards.push(vec![0u8; shard_size]);
        }

        // Encode parity
        let rs = ReedSolomon::new(k, m)
            .map_err(|e| StorageError::InvalidKey(format!("Reed-Solomon init error: {e}")))?;
        rs.encode(&mut all_shards)
            .map_err(|e| StorageError::InvalidKey(format!("Reed-Solomon encode error: {e}")))?;

        // Write parity chunks to disk
        let mut parity_infos = Vec::with_capacity(m);
        for i in 0..m {
            let parity_index = k as u32 + i as u32;
            let shard = &all_shards[k + i];
            let sha256 = hex::encode(Sha256::digest(shard));
            let path = self.chunk_path(bucket, key, parity_index);
            let mut file = fs::File::create(&path).await?;
            file.write_all(shard).await?;
            file.flush().await?;
            parity_infos.push(ChunkInfo {
                index: parity_index,
                size: shard_size as u64,
                sha256,
                kind: ChunkKind::Parity,
            });
        }

        Ok(parity_infos)
    }

    async fn complete_multipart_chunked(
        &self,
        bucket: &str,
        upload_id: &str,
        upload_meta: &MultipartUploadMeta,
        selected: &[PartMeta],
    ) -> Result<PutResult, StorageError> {
        let key = &upload_meta.key;
        let ec_dir = self.ec_dir(bucket, key);
        if let Some(parent) = ec_dir.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::create_dir_all(&ec_dir).await?;

        let mut total_size = 0u64;
        let mut etag_hasher = Md5::new();
        let mut chunks: Vec<ChunkInfo> = Vec::new();
        let mut chunk_index: u32 = 0;
        let mut chunk_buf = Vec::with_capacity(self.chunk_size as usize);

        for part in selected {
            let mut part_file =
                fs::File::open(self.part_path(bucket, upload_id, part.part_number)).await?;
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = part_file.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                total_size += n as u64;
                chunk_buf.extend_from_slice(&buf[..n]);

                while chunk_buf.len() >= self.chunk_size as usize {
                    let chunk_data: Vec<u8> = chunk_buf.drain(..self.chunk_size as usize).collect();
                    let ci = self
                        .write_chunk(bucket, key, chunk_index, &chunk_data)
                        .await?;
                    chunks.push(ci);
                    chunk_index += 1;
                }
            }

            let raw_md5 = hex::decode(part.etag.trim_matches('"'))
                .map_err(|_| StorageError::InvalidKey("invalid part etag".into()))?;
            etag_hasher.update(raw_md5);
        }

        // Flush remaining
        if !chunk_buf.is_empty() {
            let ci = self
                .write_chunk(bucket, key, chunk_index, &chunk_buf)
                .await?;
            chunks.push(ci);
        }

        if chunks.is_empty() {
            let ci = self.write_chunk(bucket, key, 0, &[]).await?;
            chunks.push(ci);
        }

        let data_chunk_count = chunks.len() as u32;

        // Compute and write parity shards if configured (skip for empty objects)
        let has_parity = self.parity_shards > 0 && total_size > 0;
        if has_parity {
            let parity_infos = self.compute_and_write_parity(bucket, key, &chunks).await?;
            chunks.extend(parity_infos);
        }

        let manifest = ChunkManifest {
            version: if has_parity { 2 } else { 1 },
            total_size,
            chunk_size: self.chunk_size,
            chunk_count: data_chunk_count,
            chunks,
            parity_shards: if has_parity {
                Some(self.parity_shards)
            } else {
                None
            },
            shard_size: if has_parity {
                Some(self.chunk_size)
            } else {
                None
            },
        };
        fs::write(
            self.manifest_path(bucket, key),
            serde_json::to_string_pretty(&manifest)?,
        )
        .await?;

        let etag = format!(
            "\"{}-{}\"",
            hex::encode(etag_hasher.finalize()),
            selected.len()
        );

        // Compute composite checksum if algorithm was specified
        let (checksum_algorithm, checksum_value) =
            if let Some(algo) = upload_meta.checksum_algorithm {
                let b64 = base64::engine::general_purpose::STANDARD;
                let mut raw_checksums = Vec::new();
                for part in selected {
                    if let Some(ref val) = part.checksum_value {
                        if let Ok(raw) = b64.decode(val) {
                            raw_checksums.extend_from_slice(&raw);
                        }
                    }
                }
                if !raw_checksums.is_empty() {
                    let mut composite_hasher = ChecksumHasher::new(algo);
                    composite_hasher.update(&raw_checksums);
                    let composite =
                        format!("{}-{}", composite_hasher.finalize_base64(), selected.len());
                    (Some(algo), Some(composite))
                } else {
                    (Some(algo), None)
                }
            } else {
                (None, None)
            };

        let storage_format = if has_parity {
            "chunked-v2"
        } else {
            "chunked-v1"
        };
        let object_meta = ObjectMeta {
            key: key.to_string(),
            size: total_size,
            etag: etag.clone(),
            content_type: upload_meta.content_type.clone(),
            last_modified: chrono::Utc::now()
                .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                .to_string(),
            version_id: None,
            is_delete_marker: false,
            storage_format: Some(storage_format.to_string()),
            checksum_algorithm,
            checksum_value: checksum_value.clone(),
        };

        let meta_path = self.meta_path(bucket, key);
        if let Some(parent) = meta_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        if let Err(e) = fs::write(&meta_path, serde_json::to_string_pretty(&object_meta)?).await {
            // Keep multipart upload parts for retries, but avoid exposing an object without metadata.
            let _ = fs::remove_dir_all(&ec_dir).await;
            return Err(e.into());
        }
        let _ = fs::remove_dir_all(self.upload_dir(bucket, upload_id)).await;

        Ok(PutResult {
            size: total_size,
            etag,
            version_id: None,
            checksum_algorithm,
            checksum_value,
        })
    }

    async fn put_folder_marker(&self, bucket: &str, key: &str) -> Result<PutResult, StorageError> {
        let folder_dir = self
            .buckets_dir
            .join(bucket)
            .join(key.trim_end_matches('/'));
        fs::create_dir_all(&folder_dir).await?;

        let marker_path = folder_dir.join(".folder");
        fs::write(&marker_path, b"").await?;

        let etag = "\"d41d8cd98f00b204e9800998ecf8427e\"".to_string();
        let now = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        let meta = ObjectMeta {
            key: key.to_string(),
            size: 0,
            etag: etag.clone(),
            content_type: "application/x-directory".to_string(),
            last_modified: now,
            version_id: None,
            is_delete_marker: false,
            storage_format: None,
            checksum_algorithm: None,
            checksum_value: None,
        };

        let meta_path = folder_dir.join(".folder.meta.json");
        let json = serde_json::to_string_pretty(&meta)?;
        fs::write(&meta_path, json).await?;

        Ok(PutResult {
            size: 0,
            etag,
            version_id: None,
            checksum_algorithm: None,
            checksum_value: None,
        })
    }

    pub async fn get_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<(ByteStream, ObjectMeta), StorageError> {
        validation::validate_key(key)?;
        let meta = self.read_object_meta(bucket, key).await?;
        let ec_dir = self.ec_dir(bucket, key);
        if Self::is_chunked_path(&ec_dir).await? {
            let manifest = self.read_manifest(bucket, key).await?;
            let reader = VerifiedChunkReader::new(ec_dir, manifest);
            return Ok((Box::pin(reader), meta));
        }
        let obj_path = self.object_path(bucket, key);
        let file = fs::File::open(&obj_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(key.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        let reader = BufReader::new(file);
        Ok((Box::pin(reader), meta))
    }

    pub async fn get_object_range(
        &self,
        bucket: &str,
        key: &str,
        offset: u64,
        length: u64,
    ) -> Result<(ByteStream, ObjectMeta), StorageError> {
        validation::validate_key(key)?;
        let meta = self.read_object_meta(bucket, key).await?;
        let ec_dir = self.ec_dir(bucket, key);
        if Self::is_chunked_path(&ec_dir).await? {
            let manifest = self.read_manifest(bucket, key).await?;
            let reader = VerifiedChunkReader::with_range(ec_dir, manifest, offset, length);
            return Ok((Box::pin(reader), meta));
        }
        let obj_path = self.object_path(bucket, key);
        let mut file = fs::File::open(&obj_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(key.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(StorageError::Io)?;
        let limited = file.take(length);
        let reader = BufReader::new(limited);
        Ok((Box::pin(reader), meta))
    }

    pub async fn head_object(&self, bucket: &str, key: &str) -> Result<ObjectMeta, StorageError> {
        validation::validate_key(key)?;
        self.read_object_meta(bucket, key).await
    }

    pub async fn delete_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<DeleteResult, StorageError> {
        validation::validate_key(key)?;

        let versioned = self.is_versioned(bucket).await.unwrap_or(false);
        if versioned {
            return self.write_delete_marker(bucket, key).await;
        }

        let obj_path = self.object_path(bucket, key);
        let meta_path = self.meta_path(bucket, key);
        let ec_dir = self.ec_dir(bucket, key);

        let _ = fs::remove_file(&obj_path).await;
        let _ = fs::remove_file(&meta_path).await;
        let _ = fs::remove_dir_all(&ec_dir).await;

        // Clean up empty parent directories (but not the bucket dir itself)
        let bucket_dir = self.buckets_dir.join(bucket);
        let mut dir = obj_path.parent().map(|p| p.to_path_buf());
        while let Some(d) = dir {
            if d == bucket_dir {
                break;
            }
            match fs::remove_dir(&d).await {
                Ok(()) => {}
                Err(_) => break,
            }
            dir = d.parent().map(|p| p.to_path_buf());
        }

        Ok(DeleteResult {
            version_id: None,
            is_delete_marker: false,
        })
    }

    pub async fn list_objects(
        &self,
        bucket: &str,
        prefix: &str,
    ) -> Result<Vec<ObjectMeta>, StorageError> {
        let bucket_dir = self.buckets_dir.join(bucket);
        let mut results = Vec::new();
        self.walk_dir(bucket, &bucket_dir, &bucket_dir, prefix, &mut results)
            .await?;
        results.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(results)
    }

    pub async fn create_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        content_type: &str,
        checksum_algorithm: Option<ChecksumAlgorithm>,
    ) -> Result<MultipartUploadMeta, StorageError> {
        validation::validate_key(key)?;
        let upload_id = uuid::Uuid::new_v4().to_string();
        let upload_dir = self.upload_dir(bucket, &upload_id);
        fs::create_dir_all(&upload_dir).await?;

        let meta = MultipartUploadMeta {
            upload_id: upload_id.clone(),
            bucket: bucket.to_string(),
            key: key.to_string(),
            content_type: content_type.to_string(),
            initiated: chrono::Utc::now()
                .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                .to_string(),
            checksum_algorithm,
        };

        let meta_json = serde_json::to_string_pretty(&meta)?;
        fs::write(self.upload_meta_path(bucket, &upload_id), meta_json).await?;
        Ok(meta)
    }

    pub async fn upload_part(
        &self,
        bucket: &str,
        upload_id: &str,
        part_number: u32,
        mut body: ByteStream,
        checksum: Option<(ChecksumAlgorithm, Option<String>)>,
    ) -> Result<PartMeta, StorageError> {
        validation::validate_upload_id(upload_id)?;
        if part_number == 0 || part_number > 10_000 {
            return Err(StorageError::InvalidKey(
                "part number must be 1..=10000".into(),
            ));
        }
        let upload_dir = self.upload_dir(bucket, upload_id);
        if !fs::try_exists(&upload_dir).await? {
            return Err(StorageError::UploadNotFound(upload_id.to_string()));
        }

        let part_path = self.part_path(bucket, upload_id, part_number);
        let mut file = fs::File::create(&part_path).await?;
        let mut hasher = Md5::new();
        let mut checksum_hasher = checksum
            .as_ref()
            .map(|(algo, _)| ChecksumHasher::new(*algo));
        let mut size: u64 = 0;
        let mut buf = vec![0u8; 64 * 1024];

        loop {
            let n = body.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n]).await?;
            hasher.update(&buf[..n]);
            if let Some(ref mut ch) = checksum_hasher {
                ch.update(&buf[..n]);
            }
            size += n as u64;
        }
        file.flush().await?;

        // Validate and compute checksum
        let (checksum_algorithm, checksum_value) =
            match finalize_checksum(checksum, checksum_hasher) {
                Ok(value) => value,
                Err(err) => {
                    let _ = fs::remove_file(&part_path).await;
                    return Err(err);
                }
        };

        let etag = format!("\"{}\"", hex::encode(hasher.finalize()));
        let meta = PartMeta {
            part_number,
            etag,
            size,
            last_modified: chrono::Utc::now()
                .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                .to_string(),
            checksum_algorithm,
            checksum_value,
        };
        if let Err(e) = fs::write(
            self.part_meta_path(bucket, upload_id, part_number),
            serde_json::to_string_pretty(&meta)?,
        )
        .await
        {
            // Clean up orphaned part file on metadata write failure
            let _ = fs::remove_file(&part_path).await;
            return Err(e.into());
        }
        Ok(meta)
    }

    pub async fn complete_multipart_upload(
        &self,
        bucket: &str,
        upload_id: &str,
        parts: &[(u32, String)],
    ) -> Result<PutResult, StorageError> {
        validation::validate_upload_id(upload_id)?;
        if parts.is_empty() {
            return Err(StorageError::InvalidKey(
                "at least one part is required to complete upload".into(),
            ));
        }

        let upload_meta = self.read_upload_meta(bucket, upload_id).await?;
        let mut selected = Vec::with_capacity(parts.len());
        for (idx, (part_number, requested_etag)) in parts.iter().enumerate() {
            let meta = self.read_part_meta(bucket, upload_id, *part_number).await?;
            if meta.etag != *requested_etag {
                return Err(StorageError::InvalidKey(format!(
                    "etag mismatch for part {}",
                    part_number
                )));
            }
            if idx + 1 < parts.len() && meta.size < 5 * 1024 * 1024 {
                return Err(StorageError::InvalidKey("part too small".into()));
            }
            selected.push(meta);
        }

        if self.erasure_coding {
            return self
                .complete_multipart_chunked(bucket, upload_id, &upload_meta, &selected)
                .await;
        }

        let obj_path = self.object_path(bucket, &upload_meta.key);
        if let Some(parent) = obj_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let mut out = fs::File::create(&obj_path).await?;
        let mut total_size = 0u64;
        let mut etag_hasher = Md5::new();

        for part in &selected {
            let mut part_file =
                fs::File::open(self.part_path(bucket, upload_id, part.part_number)).await?;
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = part_file.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                out.write_all(&buf[..n]).await?;
                total_size += n as u64;
            }

            let raw_md5 = hex::decode(part.etag.trim_matches('"'))
                .map_err(|_| StorageError::InvalidKey("invalid part etag".into()))?;
            etag_hasher.update(raw_md5);
        }
        out.flush().await?;

        let etag = format!(
            "\"{}-{}\"",
            hex::encode(etag_hasher.finalize()),
            selected.len()
        );

        // Compute composite checksum if algorithm was specified
        let (checksum_algorithm, checksum_value) =
            if let Some(algo) = upload_meta.checksum_algorithm {
                let b64 = base64::engine::general_purpose::STANDARD;
                let mut raw_checksums = Vec::new();
                for part in &selected {
                    if let Some(ref val) = part.checksum_value {
                        if let Ok(raw) = b64.decode(val) {
                            raw_checksums.extend_from_slice(&raw);
                        }
                    }
                }
                if !raw_checksums.is_empty() {
                    let mut composite_hasher = ChecksumHasher::new(algo);
                    composite_hasher.update(&raw_checksums);
                    let composite =
                        format!("{}-{}", composite_hasher.finalize_base64(), selected.len());
                    (Some(algo), Some(composite))
                } else {
                    (Some(algo), None)
                }
            } else {
                (None, None)
            };

        let object_meta = ObjectMeta {
            key: upload_meta.key.clone(),
            size: total_size,
            etag: etag.clone(),
            content_type: upload_meta.content_type,
            last_modified: chrono::Utc::now()
                .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                .to_string(),
            version_id: None,
            is_delete_marker: false,
            storage_format: None,
            checksum_algorithm,
            checksum_value: checksum_value.clone(),
        };
        let meta_path = self.meta_path(bucket, &upload_meta.key);
        if let Some(parent) = meta_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        if let Err(e) = fs::write(&meta_path, serde_json::to_string_pretty(&object_meta)?).await {
            // Keep multipart upload parts for retries, but avoid exposing an object without metadata.
            let _ = fs::remove_file(&obj_path).await;
            return Err(e.into());
        }
        let _ = fs::remove_dir_all(self.upload_dir(bucket, upload_id)).await;

        Ok(PutResult {
            size: total_size,
            etag,
            version_id: None,
            checksum_algorithm,
            checksum_value,
        })
    }

    pub async fn abort_multipart_upload(
        &self,
        bucket: &str,
        upload_id: &str,
    ) -> Result<(), StorageError> {
        validation::validate_upload_id(upload_id)?;
        let upload_dir = self.upload_dir(bucket, upload_id);
        if !fs::try_exists(&upload_dir).await? {
            return Err(StorageError::UploadNotFound(upload_id.to_string()));
        }
        fs::remove_dir_all(upload_dir).await?;
        Ok(())
    }

    pub async fn list_parts(
        &self,
        bucket: &str,
        upload_id: &str,
    ) -> Result<(MultipartUploadMeta, Vec<PartMeta>), StorageError> {
        validation::validate_upload_id(upload_id)?;
        let meta = self.read_upload_meta(bucket, upload_id).await?;
        let upload_dir = self.upload_dir(bucket, upload_id);
        let mut entries = fs::read_dir(&upload_dir).await?;
        let mut parts = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".meta.json") || name == ".meta.json" {
                continue;
            }
            let data = fs::read_to_string(entry.path()).await?;
            if let Ok(pm) = serde_json::from_str::<PartMeta>(&data) {
                parts.push(pm);
            }
        }
        parts.sort_by_key(|p| p.part_number);
        Ok((meta, parts))
    }

    pub async fn list_multipart_uploads(
        &self,
        bucket: &str,
    ) -> Result<Vec<MultipartUploadMeta>, StorageError> {
        let uploads_dir = self.uploads_dir(bucket);
        if !fs::try_exists(&uploads_dir).await? {
            return Ok(Vec::new());
        }
        let mut entries = fs::read_dir(&uploads_dir).await?;
        let mut uploads = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            if !entry.file_type().await?.is_dir() {
                continue;
            }
            let upload_id = entry.file_name().to_string_lossy().to_string();
            if let Ok(meta) = self.read_upload_meta(bucket, &upload_id).await {
                uploads.push(meta);
            }
        }
        uploads.sort_by(|a, b| a.initiated.cmp(&b.initiated));
        Ok(uploads)
    }

    // --- Internal helpers ---

    fn has_objects<'a>(
        &'a self,
        dir: &'a Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, StorageError>> + Send + 'a>>
    {
        Box::pin(async move {
            let mut entries = fs::read_dir(dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                let fname = entry.file_name().to_string_lossy().to_string();
                if fname == ".bucket.json"
                    || fname == ".uploads"
                    || fname == ".versions"
                    || fname.ends_with(".meta.json")
                {
                    continue;
                }
                // EC chunk directory counts as an object
                if fname.ends_with(".ec") && entry.file_type().await?.is_dir() {
                    return Ok(true);
                }
                if entry.file_type().await?.is_dir() {
                    if self.has_objects(&entry.path()).await? {
                        return Ok(true);
                    }
                } else {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }

    async fn read_object_meta(&self, bucket: &str, key: &str) -> Result<ObjectMeta, StorageError> {
        let meta_path = self.meta_path(bucket, key);
        let data = fs::read_to_string(&meta_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(key.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        Ok(serde_json::from_str(&data)?)
    }

    fn walk_dir<'a>(
        &'a self,
        bucket: &'a str,
        base: &'a Path,
        dir: &'a Path,
        prefix: &'a str,
        results: &'a mut Vec<ObjectMeta>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), StorageError>> + Send + 'a>>
    {
        Box::pin(async move {
            let mut entries = match fs::read_dir(dir).await {
                Ok(e) => e,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e.into()),
            };

            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                let fname = entry.file_name().to_string_lossy().to_string();

                if fname.ends_with(".meta.json")
                    || fname == ".bucket.json"
                    || fname == ".uploads"
                    || fname == ".versions"
                    || fname == ".folder"
                {
                    continue;
                }

                // EC chunk directory: derive the object key and read its metadata
                if fname.ends_with(".ec") && entry.file_type().await?.is_dir() {
                    if let Ok(rel) = path.strip_prefix(base) {
                        let rel_str = rel.to_string_lossy();
                        // Strip the .ec suffix to get the key
                        let key = rel_str.strip_suffix(".ec").unwrap_or(&rel_str).to_string();
                        if key.starts_with(prefix) {
                            if let Ok(meta) = self.read_object_meta(bucket, &key).await {
                                results.push(meta);
                            }
                        }
                    }
                    continue;
                }

                if entry.file_type().await?.is_dir() {
                    // Check for folder marker inside this directory
                    let marker = path.join(".folder.meta.json");
                    if fs::try_exists(&marker).await.unwrap_or(false) {
                        if let Ok(rel) = path.strip_prefix(base) {
                            let key = format!("{}/", rel.to_string_lossy());
                            if key.starts_with(prefix) {
                                if let Ok(data) = fs::read_to_string(&marker).await {
                                    if let Ok(meta) = serde_json::from_str::<ObjectMeta>(&data) {
                                        results.push(meta);
                                    }
                                }
                            }
                        }
                    }
                    self.walk_dir(bucket, base, &path, prefix, results).await?;
                } else {
                    if let Ok(rel) = path.strip_prefix(base) {
                        let key = rel.to_string_lossy().to_string();
                        if key.starts_with(prefix) {
                            if let Ok(meta) = self.read_object_meta(bucket, &key).await {
                                results.push(meta);
                            }
                        }
                    }
                }
            }
            Ok(())
        })
    }

    async fn read_upload_meta(
        &self,
        bucket: &str,
        upload_id: &str,
    ) -> Result<MultipartUploadMeta, StorageError> {
        let path = self.upload_meta_path(bucket, upload_id);
        let data = fs::read_to_string(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::UploadNotFound(upload_id.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        Ok(serde_json::from_str(&data)?)
    }

    async fn read_part_meta(
        &self,
        bucket: &str,
        upload_id: &str,
        part_number: u32,
    ) -> Result<PartMeta, StorageError> {
        let path = self.part_meta_path(bucket, upload_id, part_number);
        let data = fs::read_to_string(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::InvalidKey(format!("missing part {}", part_number))
            } else {
                StorageError::Io(e)
            }
        })?;
        Ok(serde_json::from_str(&data)?)
    }

    // --- Versioning ---

    fn generate_version_id() -> String {
        let micros = chrono::Utc::now().timestamp_micros() as u64;
        let rand_suffix: u32 = rand::rng().random();
        format!("{:016}-{:08x}", micros, rand_suffix)
    }

    /// Directory holding versions for a given key.
    /// For key `photos/vacation.jpg` → `{bucket}/photos/.versions/vacation.jpg/`
    fn versions_dir(&self, bucket: &str, key: &str) -> PathBuf {
        layout::versions_dir(&self.buckets_dir, bucket, key)
    }

    fn version_data_path(&self, bucket: &str, key: &str, version_id: &str) -> PathBuf {
        layout::version_data_path(&self.buckets_dir, bucket, key, version_id)
    }

    fn version_meta_path(&self, bucket: &str, key: &str, version_id: &str) -> PathBuf {
        layout::version_meta_path(&self.buckets_dir, bucket, key, version_id)
    }

    pub async fn is_versioned(&self, bucket: &str) -> Result<bool, StorageError> {
        let meta_path = self.buckets_dir.join(bucket).join(".bucket.json");
        let data = fs::read_to_string(&meta_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(bucket.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        let meta: BucketMeta = serde_json::from_str(&data)?;
        Ok(meta.versioning)
    }

    pub async fn set_versioning(&self, bucket: &str, enabled: bool) -> Result<(), StorageError> {
        let meta_path = self.buckets_dir.join(bucket).join(".bucket.json");
        let data = fs::read_to_string(&meta_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(bucket.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        let mut meta: BucketMeta = serde_json::from_str(&data)?;
        meta.versioning = enabled;
        fs::write(&meta_path, serde_json::to_string_pretty(&meta)?).await?;
        Ok(())
    }

    /// Write a new version to the `.versions/` directory and update the current (top-level) files.
    async fn write_version(
        &self,
        bucket: &str,
        key: &str,
        meta: &ObjectMeta,
        data_path: &Path,
    ) -> Result<(), StorageError> {
        let version_id = version_id_from_meta(meta, "writing flat version snapshot")?;
        let ver_dir = self.versions_dir(bucket, key);
        fs::create_dir_all(&ver_dir).await?;

        // Copy data to version store
        let ver_data = ver_dir.join(format!("{}.data", version_id));
        fs::copy(data_path, &ver_data).await?;

        // Write version metadata
        let ver_meta = ver_dir.join(format!("{}.meta.json", version_id));
        fs::write(&ver_meta, serde_json::to_string_pretty(meta)?).await?;

        Ok(())
    }

    /// Write a new chunked version: copy .ec/ dir to .versions/{key}/{version_id}.ec/
    async fn write_version_chunked(
        &self,
        bucket: &str,
        key: &str,
        meta: &ObjectMeta,
    ) -> Result<(), StorageError> {
        let version_id = version_id_from_meta(meta, "writing chunked version snapshot")?;
        let ver_dir = self.versions_dir(bucket, key);
        fs::create_dir_all(&ver_dir).await?;

        // Copy the entire .ec/ directory
        let src_ec = self.ec_dir(bucket, key);
        let dst_ec = ver_dir.join(format!("{}.ec", version_id));
        fs::create_dir_all(&dst_ec).await?;
        let mut entries = fs::read_dir(&src_ec).await?;
        while let Some(entry) = entries.next_entry().await? {
            let dest = dst_ec.join(entry.file_name());
            fs::copy(entry.path(), &dest).await?;
        }

        // Write version metadata
        let ver_meta = ver_dir.join(format!("{}.meta.json", version_id));
        fs::write(&ver_meta, serde_json::to_string_pretty(meta)?).await?;

        Ok(())
    }

    /// Write a delete marker version and remove the top-level files.
    async fn write_delete_marker(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<DeleteResult, StorageError> {
        let version_id = Self::generate_version_id();
        let now = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        let marker_meta = ObjectMeta {
            key: key.to_string(),
            size: 0,
            etag: String::new(),
            content_type: String::new(),
            last_modified: now,
            version_id: Some(version_id.clone()),
            is_delete_marker: true,
            storage_format: None,
            checksum_algorithm: None,
            checksum_value: None,
        };

        let ver_dir = self.versions_dir(bucket, key);
        fs::create_dir_all(&ver_dir).await?;
        let ver_meta_path = ver_dir.join(format!("{}.meta.json", version_id));
        fs::write(&ver_meta_path, serde_json::to_string_pretty(&marker_meta)?).await?;

        // Remove top-level current files
        let _ = fs::remove_file(self.object_path(bucket, key)).await;
        let _ = fs::remove_file(self.meta_path(bucket, key)).await;
        let _ = fs::remove_dir_all(self.ec_dir(bucket, key)).await;

        Ok(DeleteResult {
            version_id: Some(version_id),
            is_delete_marker: true,
        })
    }

    /// Scan versions for a key and update the top-level files to reflect the latest non-delete-marker.
    async fn update_current_version(&self, bucket: &str, key: &str) -> Result<(), StorageError> {
        let ver_dir = self.versions_dir(bucket, key);
        if !fs::try_exists(&ver_dir).await.unwrap_or(false) {
            return Ok(());
        }

        // Find the latest non-delete-marker version (lexicographic sort = chronological)
        let mut versions = Vec::new();
        let mut entries = fs::read_dir(&ver_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let fname = entry.file_name().to_string_lossy().to_string();
            if fname.ends_with(".meta.json") {
                versions.push(fname);
            }
        }
        versions.sort();
        versions.reverse(); // newest first

        let latest_meta_fname = match versions.first() {
            Some(name) => name,
            None => {
                let _ = fs::remove_file(self.object_path(bucket, key)).await;
                let _ = fs::remove_file(self.meta_path(bucket, key)).await;
                let _ = fs::remove_dir_all(self.ec_dir(bucket, key)).await;
                return Ok(());
            }
        };

        let latest_meta_path = ver_dir.join(latest_meta_fname);
        let latest_data = fs::read_to_string(&latest_meta_path).await?;
        let latest_meta: ObjectMeta = serde_json::from_str(&latest_data)?;

        if latest_meta.is_delete_marker {
            // Latest version is an explicit tombstone. Keep top-level object deleted.
            let _ = fs::remove_file(self.object_path(bucket, key)).await;
            let _ = fs::remove_file(self.meta_path(bucket, key)).await;
            let _ = fs::remove_dir_all(self.ec_dir(bucket, key)).await;
            return Ok(());
        }

        // Restore latest non-delete-marker version as current.
        let vid = version_id_from_meta(&latest_meta, "restoring current version")?;
        let obj_meta_path = self.meta_path(bucket, key);
        let ver_ec = ver_dir.join(format!("{}.ec", vid));
        if fs::try_exists(&ver_ec).await.unwrap_or(false) {
            let dst_ec = self.ec_dir(bucket, key);
            if let Some(parent) = dst_ec.parent() {
                fs::create_dir_all(parent).await?;
            }
            let _ = fs::remove_dir_all(&dst_ec).await;
            fs::create_dir_all(&dst_ec).await?;
            let mut entries = fs::read_dir(&ver_ec).await?;
            while let Some(entry) = entries.next_entry().await? {
                fs::copy(entry.path(), dst_ec.join(entry.file_name())).await?;
            }
        } else {
            let ver_data = ver_dir.join(format!("{}.data", vid));
            let obj_path = self.object_path(bucket, key);
            if let Some(parent) = obj_path.parent() {
                fs::create_dir_all(parent).await?;
            }
            fs::copy(&ver_data, &obj_path).await?;
        }

        if let Some(parent) = obj_meta_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(&obj_meta_path, serde_json::to_string_pretty(&latest_meta)?).await?;
        Ok(())
    }

    pub async fn get_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<(ByteStream, ObjectMeta), StorageError> {
        validation::validate_key(key)?;
        let ver_meta_path = self.version_meta_path(bucket, key, version_id);
        let data = fs::read_to_string(&ver_meta_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::VersionNotFound(version_id.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        let meta: ObjectMeta = serde_json::from_str(&data)?;

        if meta.is_delete_marker {
            return Err(StorageError::NotFound(key.to_string()));
        }

        // Check for chunked version
        let ver_ec_dir = self
            .versions_dir(bucket, key)
            .join(format!("{}.ec", version_id));
        if fs::try_exists(&ver_ec_dir).await.unwrap_or(false) {
            let manifest_path = ver_ec_dir.join("manifest.json");
            let manifest_data = fs::read_to_string(&manifest_path).await.map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    StorageError::VersionNotFound(version_id.to_string())
                } else {
                    StorageError::Io(e)
                }
            })?;
            let manifest: ChunkManifest = serde_json::from_str(&manifest_data)?;
            let reader = VerifiedChunkReader::new(ver_ec_dir, manifest);
            return Ok((Box::pin(reader), meta));
        }

        let ver_data_path = self.version_data_path(bucket, key, version_id);
        let file = fs::File::open(&ver_data_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::VersionNotFound(version_id.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        Ok((Box::pin(BufReader::new(file)), meta))
    }

    pub async fn head_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<ObjectMeta, StorageError> {
        validation::validate_key(key)?;
        let ver_meta_path = self.version_meta_path(bucket, key, version_id);
        let data = fs::read_to_string(&ver_meta_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::VersionNotFound(version_id.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        let meta: ObjectMeta = serde_json::from_str(&data)?;
        if meta.is_delete_marker {
            return Err(StorageError::NotFound(key.to_string()));
        }
        Ok(meta)
    }

    pub async fn delete_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<ObjectMeta, StorageError> {
        validation::validate_key(key)?;
        let ver_meta_path = self.version_meta_path(bucket, key, version_id);
        let data = fs::read_to_string(&ver_meta_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::VersionNotFound(version_id.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        let meta: ObjectMeta = serde_json::from_str(&data)?;

        // Remove version files
        let _ = fs::remove_file(&ver_meta_path).await;
        let ver_data_path = self.version_data_path(bucket, key, version_id);
        let _ = fs::remove_file(&ver_data_path).await;
        let ver_ec_dir = self
            .versions_dir(bucket, key)
            .join(format!("{}.ec", version_id));
        let _ = fs::remove_dir_all(&ver_ec_dir).await;

        // Clean up empty versions dir
        let ver_dir = self.versions_dir(bucket, key);
        let _ = fs::remove_dir(&ver_dir).await; // only succeeds if empty

        // Update current version (in case we deleted the latest or a delete marker)
        self.update_current_version(bucket, key).await?;

        Ok(meta)
    }

    pub async fn list_object_versions(
        &self,
        bucket: &str,
        prefix: &str,
    ) -> Result<Vec<ObjectMeta>, StorageError> {
        let bucket_dir = self.buckets_dir.join(bucket);
        let mut results = Vec::new();
        self.walk_versions(&bucket_dir, &bucket_dir, prefix, &mut results)
            .await?;
        // Sort by key, then by version_id descending (newest first per key)
        results.sort_by(|a, b| {
            a.key.cmp(&b.key).then_with(|| {
                let va = a.version_id.as_deref().unwrap_or("");
                let vb = b.version_id.as_deref().unwrap_or("");
                vb.cmp(va)
            })
        });
        Ok(results)
    }

    fn walk_versions<'a>(
        &'a self,
        base: &'a Path,
        dir: &'a Path,
        prefix: &'a str,
        results: &'a mut Vec<ObjectMeta>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), StorageError>> + Send + 'a>>
    {
        Box::pin(async move {
            let mut entries = match fs::read_dir(dir).await {
                Ok(e) => e,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e.into()),
            };

            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                let fname = entry.file_name().to_string_lossy().to_string();

                if !entry.file_type().await?.is_dir() {
                    continue;
                }

                if fname == ".versions" {
                    // Scan all key dirs inside .versions
                    let mut key_dirs = match fs::read_dir(&path).await {
                        Ok(e) => e,
                        Err(_) => continue,
                    };
                    while let Some(key_entry) = key_dirs.next_entry().await? {
                        if !key_entry.file_type().await?.is_dir() {
                            continue;
                        }
                        let key_name = key_entry.file_name().to_string_lossy().to_string();
                        // Reconstruct the object key from the directory structure
                        let parent_rel = dir.strip_prefix(base).unwrap_or(Path::new(""));
                        let key = if parent_rel.as_os_str().is_empty() {
                            key_name.clone()
                        } else {
                            format!("{}/{}", parent_rel.to_string_lossy(), key_name)
                        };
                        if !key.starts_with(prefix) {
                            continue;
                        }
                        // Read all version meta files in this key's version dir
                        let key_ver_dir = key_entry.path();
                        let mut ver_entries = match fs::read_dir(&key_ver_dir).await {
                            Ok(e) => e,
                            Err(_) => continue,
                        };
                        while let Some(ve) = ver_entries.next_entry().await? {
                            let vf = ve.file_name().to_string_lossy().to_string();
                            if vf.ends_with(".meta.json") {
                                if let Ok(data) = fs::read_to_string(ve.path()).await {
                                    if let Ok(meta) = serde_json::from_str::<ObjectMeta>(&data) {
                                        results.push(meta);
                                    }
                                }
                            }
                        }
                    }
                } else if fname != ".uploads" && fname != ".bucket.json" {
                    self.walk_versions(base, &path, prefix, results).await?;
                }
            }
            Ok(())
        })
    }
}
