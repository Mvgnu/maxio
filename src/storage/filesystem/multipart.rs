use super::*;

impl FilesystemStorage {
    pub(super) fn uploads_dir(&self, bucket: &str) -> PathBuf {
        layout::uploads_dir(&self.buckets_dir, bucket)
    }

    pub(super) fn upload_dir(&self, bucket: &str, upload_id: &str) -> PathBuf {
        layout::upload_dir(&self.buckets_dir, bucket, upload_id)
    }

    pub(super) fn upload_meta_path(&self, bucket: &str, upload_id: &str) -> PathBuf {
        layout::upload_meta_path(&self.buckets_dir, bucket, upload_id)
    }

    pub(super) fn part_path(&self, bucket: &str, upload_id: &str, part_number: u32) -> PathBuf {
        layout::part_path(&self.buckets_dir, bucket, upload_id, part_number)
    }

    pub(super) fn part_meta_path(
        &self,
        bucket: &str,
        upload_id: &str,
        part_number: u32,
    ) -> PathBuf {
        layout::part_meta_path(&self.buckets_dir, bucket, upload_id, part_number)
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
                    if let Some(ref val) = part.checksum_value
                        && let Ok(raw) = b64.decode(val)
                    {
                        raw_checksums.extend_from_slice(&raw);
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
    pub async fn create_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        content_type: &str,
        checksum_algorithm: Option<ChecksumAlgorithm>,
    ) -> Result<MultipartUploadMeta, StorageError> {
        self.ensure_bucket_exists(bucket).await?;
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
                    if let Some(ref val) = part.checksum_value
                        && let Ok(raw) = b64.decode(val)
                    {
                        raw_checksums.extend_from_slice(&raw);
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
        self.ensure_bucket_exists(bucket).await?;
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
}
