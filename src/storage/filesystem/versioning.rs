use super::*;
use rand::RngExt;

impl FilesystemStorage {
    pub(super) fn generate_version_id() -> String {
        let micros = chrono::Utc::now().timestamp_micros() as u64;
        let rand_suffix: u32 = rand::rng().random();
        format!("{:016}-{:08x}", micros, rand_suffix)
    }

    /// Directory holding versions for a given key.
    /// For key `photos/vacation.jpg` -> `{bucket}/photos/.versions/vacation.jpg/`
    pub(super) fn versions_dir(&self, bucket: &str, key: &str) -> PathBuf {
        layout::versions_dir(&self.buckets_dir, bucket, key)
    }

    pub(super) fn version_data_path(&self, bucket: &str, key: &str, version_id: &str) -> PathBuf {
        layout::version_data_path(&self.buckets_dir, bucket, key, version_id)
    }

    pub(super) fn version_meta_path(&self, bucket: &str, key: &str, version_id: &str) -> PathBuf {
        layout::version_meta_path(&self.buckets_dir, bucket, key, version_id)
    }

    pub(super) fn version_ec_dir(&self, bucket: &str, key: &str, version_id: &str) -> PathBuf {
        self.versions_dir(bucket, key)
            .join(format!("{}.ec", version_id))
    }

    pub(super) async fn read_version_meta(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<ObjectMeta, StorageError> {
        let ver_meta_path = self.version_meta_path(bucket, key, version_id);
        let data = fs::read_to_string(&ver_meta_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::VersionNotFound(version_id.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        Ok(serde_json::from_str(&data)?)
    }

    pub async fn is_versioned(&self, bucket: &str) -> Result<bool, StorageError> {
        let meta = self.read_bucket_meta(bucket).await?;
        Ok(meta.versioning)
    }

    pub async fn set_versioning(&self, bucket: &str, enabled: bool) -> Result<(), StorageError> {
        let mut meta = self.read_bucket_meta(bucket).await?;
        meta.versioning = enabled;
        self.write_bucket_meta(bucket, &meta).await
    }

    /// Write a new version to the `.versions/` directory and update the current (top-level) files.
    pub(super) async fn write_version(
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
        if let Err(e) = fs::copy(data_path, &ver_data).await {
            let _ = fs::remove_file(&ver_data).await;
            return Err(e.into());
        }

        // Write version metadata
        let ver_meta = ver_dir.join(format!("{}.meta.json", version_id));
        if let Err(e) = fs::write(&ver_meta, serde_json::to_string_pretty(meta)?).await {
            let _ = fs::remove_file(&ver_data).await;
            return Err(e.into());
        }

        Ok(())
    }

    /// Write a new chunked version: copy .ec/ dir to .versions/{key}/{version_id}.ec/
    pub(super) async fn write_version_chunked(
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
            if let Err(e) = fs::copy(entry.path(), &dest).await {
                let _ = fs::remove_dir_all(&dst_ec).await;
                return Err(e.into());
            }
        }

        // Write version metadata
        let ver_meta = ver_dir.join(format!("{}.meta.json", version_id));
        if let Err(e) = fs::write(&ver_meta, serde_json::to_string_pretty(meta)?).await {
            let _ = fs::remove_dir_all(&dst_ec).await;
            return Err(e.into());
        }

        Ok(())
    }

    /// Write a delete marker version and remove the top-level files.
    pub(super) async fn write_delete_marker(
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
    pub(super) async fn update_current_version(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<(), StorageError> {
        let ver_dir = self.versions_dir(bucket, key);
        if !fs::try_exists(&ver_dir).await? {
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
        let ver_ec = self.version_ec_dir(bucket, key, vid);
        if fs::try_exists(&ver_ec).await? {
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

    pub(super) async fn read_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
        range: Option<(u64, u64)>,
    ) -> Result<(ByteStream, ObjectMeta), StorageError> {
        validation::validate_key(key)?;
        let meta = self.read_version_meta(bucket, key, version_id).await?;

        if meta.is_delete_marker {
            return Err(StorageError::NotFound(key.to_string()));
        }

        // Check for chunked version
        let ver_ec_dir = self.version_ec_dir(bucket, key, version_id);
        if fs::try_exists(&ver_ec_dir).await? {
            let manifest_path = ver_ec_dir.join("manifest.json");
            let manifest_data = fs::read_to_string(&manifest_path).await.map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    StorageError::VersionNotFound(version_id.to_string())
                } else {
                    StorageError::Io(e)
                }
            })?;
            let manifest: ChunkManifest = serde_json::from_str(&manifest_data)?;
            let reader = if let Some((offset, length)) = range {
                VerifiedChunkReader::with_range(ver_ec_dir, manifest, offset, length)
            } else {
                VerifiedChunkReader::new(ver_ec_dir, manifest)
            };
            return Ok((Box::pin(reader), meta));
        }

        let ver_data_path = self.version_data_path(bucket, key, version_id);
        let mut file = fs::File::open(&ver_data_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::VersionNotFound(version_id.to_string())
            } else {
                StorageError::Io(e)
            }
        })?;
        let reader: ByteStream = if let Some((offset, length)) = range {
            file.seek(std::io::SeekFrom::Start(offset))
                .await
                .map_err(StorageError::Io)?;
            let limited = file.take(length);
            Box::pin(BufReader::new(limited))
        } else {
            Box::pin(BufReader::new(file))
        };
        Ok((reader, meta))
    }

    pub async fn get_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<(ByteStream, ObjectMeta), StorageError> {
        self.read_object_version(bucket, key, version_id, None)
            .await
    }

    pub async fn get_object_version_range(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
        offset: u64,
        length: u64,
    ) -> Result<(ByteStream, ObjectMeta), StorageError> {
        self.read_object_version(bucket, key, version_id, Some((offset, length)))
            .await
    }

    pub async fn head_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> Result<ObjectMeta, StorageError> {
        validation::validate_key(key)?;
        let meta = self.read_version_meta(bucket, key, version_id).await?;
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
        let meta = self.read_version_meta(bucket, key, version_id).await?;
        let ver_meta_path = self.version_meta_path(bucket, key, version_id);

        // Remove version files
        let _ = fs::remove_file(&ver_meta_path).await;
        let ver_data_path = self.version_data_path(bucket, key, version_id);
        let _ = fs::remove_file(&ver_data_path).await;
        let ver_ec_dir = self.version_ec_dir(bucket, key, version_id);
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
        self.ensure_bucket_exists(bucket).await?;
        let bucket_dir = self.buckets_dir.join(bucket);
        let mut results = Vec::new();
        Self::walk_versions(&bucket_dir, &bucket_dir, prefix, &mut results).await?;
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

    pub(super) fn walk_versions<'a>(
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
                            if !vf.ends_with(".meta.json") {
                                continue;
                            }
                            if let Some(meta) = fs::read_to_string(ve.path())
                                .await
                                .ok()
                                .and_then(|data| serde_json::from_str::<ObjectMeta>(&data).ok())
                            {
                                results.push(meta);
                            }
                        }
                    }
                } else if fname != ".uploads" && fname != ".bucket.json" {
                    Self::walk_versions(base, &path, prefix, results).await?;
                }
            }
            Ok(())
        })
    }
}
