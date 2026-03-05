use super::*;

impl FilesystemStorage {
    pub(super) fn object_path(&self, bucket: &str, key: &str) -> PathBuf {
        layout::object_path(&self.buckets_dir, bucket, key)
    }

    pub(super) fn meta_path(&self, bucket: &str, key: &str) -> PathBuf {
        layout::meta_path(&self.buckets_dir, bucket, key)
    }

    pub(super) fn ec_dir(&self, bucket: &str, key: &str) -> PathBuf {
        layout::ec_dir(&self.buckets_dir, bucket, key)
    }

    pub(super) fn chunk_path(&self, bucket: &str, key: &str, index: u32) -> PathBuf {
        layout::chunk_path(&self.buckets_dir, bucket, key, index)
    }

    pub(super) fn manifest_path(&self, bucket: &str, key: &str) -> PathBuf {
        layout::manifest_path(&self.buckets_dir, bucket, key)
    }

    pub(super) async fn is_chunked_path(ec_dir: &Path) -> Result<bool, StorageError> {
        match fs::metadata(ec_dir).await {
            Ok(meta) => Ok(meta.is_dir()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    pub(super) async fn read_manifest(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<ChunkManifest, StorageError> {
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

    pub async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        content_type: &str,
        body: ByteStream,
        checksum: Option<(ChecksumAlgorithm, Option<String>)>,
    ) -> Result<PutResult, StorageError> {
        self.put_object_with_version_id(bucket, key, content_type, body, checksum, None)
            .await
    }

    pub async fn put_object_with_version_id(
        &self,
        bucket: &str,
        key: &str,
        content_type: &str,
        mut body: ByteStream,
        checksum: Option<(ChecksumAlgorithm, Option<String>)>,
        forced_version_id: Option<&str>,
    ) -> Result<PutResult, StorageError> {
        self.ensure_bucket_exists(bucket).await?;
        validation::validate_key(key)?;

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
                    forced_version_id,
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

        let versioned = self.is_versioned(bucket).await?;
        let version_id = if versioned {
            Some(
                forced_version_id
                    .map(str::to_owned)
                    .unwrap_or_else(Self::generate_version_id),
            )
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
        forced_version_id: Option<&str>,
    ) -> Result<PutResult, StorageError> {
        self.ensure_bucket_exists(bucket).await?;
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

        if chunks.is_empty() {
            let ci = self.write_chunk(bucket, key, 0, &[]).await?;
            chunks.push(ci);
        }

        let data_chunk_count = chunks.len() as u32;
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

        let versioned = self.is_versioned(bucket).await?;
        let version_id = if versioned {
            Some(
                forced_version_id
                    .map(str::to_owned)
                    .unwrap_or_else(Self::generate_version_id),
            )
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

    pub(super) async fn write_chunk(
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

    pub(super) async fn compute_and_write_parity(
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

        let mut all_shards: Vec<Vec<u8>> = Vec::with_capacity(k + m);
        for ci in data_chunks {
            let path = self.chunk_path(bucket, key, ci.index);
            let mut data = fs::read(&path).await?;
            data.resize(shard_size, 0u8);
            all_shards.push(data);
        }

        for _ in 0..m {
            all_shards.push(vec![0u8; shard_size]);
        }

        let rs = ReedSolomon::new(k, m)
            .map_err(|e| StorageError::InvalidKey(format!("Reed-Solomon init error: {e}")))?;
        rs.encode(&mut all_shards)
            .map_err(|e| StorageError::InvalidKey(format!("Reed-Solomon encode error: {e}")))?;

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

    pub async fn get_object_chunk(
        &self,
        bucket: &str,
        key: &str,
        chunk_index: u32,
    ) -> Result<(Vec<u8>, ChunkInfo, ObjectMeta), StorageError> {
        validation::validate_key(key)?;
        let meta = self.read_object_meta(bucket, key).await?;
        let ec_dir = self.ec_dir(bucket, key);
        if !Self::is_chunked_path(&ec_dir).await? {
            return Err(StorageError::InvalidKey(format!(
                "object is not chunked: {key}"
            )));
        }

        let manifest = self.read_manifest(bucket, key).await?;
        let chunk = manifest
            .chunks
            .iter()
            .find(|info| info.index == chunk_index)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(format!("{key}#chunk:{chunk_index}")))?;
        let chunk_path = self.chunk_path(bucket, key, chunk_index);
        let data = fs::read(&chunk_path).await.map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound(format!("{key}#chunk:{chunk_index}"))
            } else {
                StorageError::Io(error)
            }
        })?;
        if data.len() as u64 != chunk.size {
            return Err(StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "chunk {} size mismatch for key {}: expected {}, got {}",
                    chunk_index,
                    key,
                    chunk.size,
                    data.len()
                ),
            )));
        }

        let checksum = hex::encode(Sha256::digest(&data));
        if checksum != chunk.sha256 {
            return Err(StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "chunk {} checksum mismatch for key {}: expected {}, got {}",
                    chunk_index, key, chunk.sha256, checksum
                ),
            )));
        }

        Ok((data, chunk, meta))
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

        let versioned = self.is_versioned(bucket).await?;
        if versioned {
            return self.write_delete_marker(bucket, key).await;
        }

        let obj_path = self.object_path(bucket, key);
        let meta_path = self.meta_path(bucket, key);
        let ec_dir = self.ec_dir(bucket, key);

        let _ = fs::remove_file(&obj_path).await;
        let _ = fs::remove_file(&meta_path).await;
        let _ = fs::remove_dir_all(&ec_dir).await;

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
        self.ensure_bucket_exists(bucket).await?;
        let bucket_dir = self.buckets_dir.join(bucket);
        let mut results = Vec::new();
        self.walk_dir(bucket, &bucket_dir, &bucket_dir, prefix, &mut results)
            .await?;
        results.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(results)
    }

    pub(super) fn has_objects<'a>(
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
                if fname.ends_with(".ec") && entry.file_type().await?.is_dir() {
                    return Ok(true);
                }
                if entry.file_type().await?.is_dir() {
                    if Self::has_objects(&entry.path()).await? {
                        return Ok(true);
                    }
                } else {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }

    pub(super) async fn read_object_meta(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<ObjectMeta, StorageError> {
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

                if fname.ends_with(".ec") && entry.file_type().await?.is_dir() {
                    if let Ok(rel) = path.strip_prefix(base) {
                        let rel_str = rel.to_string_lossy();
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
                    let marker = path.join(".folder.meta.json");
                    if fs::try_exists(&marker).await? {
                        if let Ok(rel) = path.strip_prefix(base) {
                            let key = format!("{}/", rel.to_string_lossy());
                            if !key.starts_with(prefix) {
                                self.walk_dir(bucket, base, &path, prefix, results).await?;
                                continue;
                            }
                            if let Some(meta) = fs::read_to_string(&marker)
                                .await
                                .ok()
                                .and_then(|data| serde_json::from_str::<ObjectMeta>(&data).ok())
                            {
                                results.push(meta);
                            }
                        }
                    }
                    self.walk_dir(bucket, base, &path, prefix, results).await?;
                } else if let Ok(rel) = path.strip_prefix(base) {
                    let key = rel.to_string_lossy().to_string();
                    if key.starts_with(prefix) {
                        if let Ok(meta) = self.read_object_meta(bucket, &key).await {
                            results.push(meta);
                        }
                    }
                }
            }
            Ok(())
        })
    }
}
