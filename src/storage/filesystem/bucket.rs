use super::*;

impl FilesystemStorage {
    // --- Bucket operations ---

    fn bucket_meta_path(&self, bucket: &str) -> PathBuf {
        self.buckets_dir.join(bucket).join(".bucket.json")
    }

    pub(super) async fn read_bucket_meta(&self, bucket: &str) -> Result<BucketMeta, StorageError> {
        let data = fs::read_to_string(self.bucket_meta_path(bucket))
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    StorageError::NotFound(bucket.to_string())
                } else {
                    StorageError::Io(e)
                }
            })?;
        Ok(serde_json::from_str(&data)?)
    }

    pub(super) async fn write_bucket_meta(
        &self,
        bucket: &str,
        meta: &BucketMeta,
    ) -> Result<(), StorageError> {
        fs::write(
            self.bucket_meta_path(bucket),
            serde_json::to_string_pretty(meta)?,
        )
        .await?;
        Ok(())
    }

    pub async fn create_bucket(&self, meta: &BucketMeta) -> Result<bool, StorageError> {
        let bucket_dir = self.buckets_dir.join(&meta.name);
        match fs::create_dir(&bucket_dir).await {
            Ok(()) => {
                let meta_path = bucket_dir.join(".bucket.json");
                let json = serde_json::to_string_pretty(meta)?;
                if let Err(e) = fs::write(&meta_path, json).await {
                    // Clean up the empty directory to avoid a half-created bucket.
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
        Ok(fs::try_exists(self.bucket_meta_path(name)).await?)
    }

    pub async fn delete_bucket(&self, name: &str) -> Result<bool, StorageError> {
        let bucket_dir = self.buckets_dir.join(name);
        if !fs::try_exists(&bucket_dir).await? {
            return Ok(false);
        }

        let has_objects = Self::has_objects(&bucket_dir).await?;
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
                // A concurrent write added files. Best effort: recreate metadata
                // so head_bucket reflects the bucket still being present.
                let meta = BucketMeta {
                    name: name.to_string(),
                    created_at: chrono::Utc::now()
                        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                        .to_string(),
                    region: String::new(),
                    versioning: false,
                };
                let _ = self.write_bucket_meta(name, &meta).await;
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

    pub(super) fn lifecycle_path(&self, bucket: &str) -> PathBuf {
        layout::lifecycle_path(&self.buckets_dir, bucket)
    }

    pub(super) async fn ensure_bucket_exists(&self, bucket: &str) -> Result<(), StorageError> {
        if !self.head_bucket(bucket).await? {
            return Err(StorageError::NotFound(bucket.to_string()));
        }
        Ok(())
    }

    pub async fn get_lifecycle_rules(
        &self,
        bucket: &str,
    ) -> Result<Vec<lifecycle::LifecycleRule>, StorageError> {
        self.ensure_bucket_exists(bucket).await?;

        let path = self.lifecycle_path(bucket);
        let data = match fs::read_to_string(&path).await {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let rules: Vec<lifecycle::LifecycleRule> = serde_json::from_str(&data)?;
        lifecycle::validate_rules(&rules).map_err(StorageError::InvalidKey)?;
        Ok(rules)
    }

    pub async fn set_lifecycle_rules(
        &self,
        bucket: &str,
        rules: &[lifecycle::LifecycleRule],
    ) -> Result<(), StorageError> {
        self.ensure_bucket_exists(bucket).await?;
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
}
