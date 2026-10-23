//! Stage and validate replacement bytes before touching a visible object.
//!
//! Publication is serialized and rolls back ordinary filesystem errors. The legacy
//! payload/sidecar layout is still not a crash-atomic transaction: process or power
//! loss during publication needs a future durable commit journal/layout migration.

use super::*;
use std::io;
use tokio::sync::OwnedMutexGuard;

pub(super) struct StagedWrite {
    root: PathBuf,
    pub storage: FilesystemStorage,
    preserve_recovery: bool,
}

struct Entry {
    source: PathBuf,
    destination: PathBuf,
    directory: bool,
}

struct Applied {
    destination: PathBuf,
    backup: Option<PathBuf>,
    installed: bool,
}

fn metadata(path: &Path) -> io::Result<Option<std::fs::Metadata>> {
    match std::fs::symlink_metadata(path) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn remove(path: &Path) -> io::Result<()> {
    match metadata(path)? {
        Some(meta) if meta.is_dir() => std::fs::remove_dir_all(path),
        Some(_) => std::fs::remove_file(path),
        None => Ok(()),
    }
}

impl StagedWrite {
    pub async fn new(target: &FilesystemStorage, bucket: &str) -> Result<Self, StorageError> {
        let meta = target.read_bucket_meta(bucket).await?;
        let root = target
            .uploads_dir(bucket)
            .join(format!(".write-{}", uuid::Uuid::new_v4()));
        let stage = Self {
            storage: FilesystemStorage {
                buckets_dir: root.join("buckets"),
                erasure_coding: target.erasure_coding,
                chunk_size: target.chunk_size,
                parity_shards: target.parity_shards,
                mutation_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            },
            root,
            preserve_recovery: false,
        };
        fs::create_dir_all(&stage.storage.buckets_dir).await?;
        stage.storage.create_bucket(&meta).await?;
        Ok(stage)
    }

    pub async fn finish(
        self,
        target: &FilesystemStorage,
        bucket: &str,
        key: &str,
        result: PutResult,
        guard: OwnedMutexGuard<()>,
    ) -> Result<(PutResult, OwnedMutexGuard<()>), StorageError> {
        let guard = self
            .finish_versioned_mutation(target, bucket, key, result.version_id.as_deref(), guard)
            .await?;
        Ok((result, guard))
    }

    pub async fn finish_delete(
        self,
        target: &FilesystemStorage,
        bucket: &str,
        key: &str,
        result: &DeleteResult,
        guard: OwnedMutexGuard<()>,
    ) -> Result<OwnedMutexGuard<()>, StorageError> {
        self.finish_versioned_mutation(target, bucket, key, result.version_id.as_deref(), guard)
            .await
    }

    async fn finish_versioned_mutation(
        self,
        target: &FilesystemStorage,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        guard: OwnedMutexGuard<()>,
    ) -> Result<OwnedMutexGuard<()>, StorageError> {
        let mut entries = Vec::new();
        if let Some(version_id) = version_id {
            // Existing unversioned bytes remain the null version when versioning
            // is enabled. Stage their snapshot in this same publication so any
            // copy/metadata/publication error leaves the old current object intact.
            if version_id != "null"
                && let Some(meta) = target.current_null_meta(bucket, key).await?
            {
                if FilesystemStorage::is_chunked_path(&target.ec_dir(bucket, key)).await? {
                    self.storage
                        .write_version_chunked_from(target, bucket, key, &meta)
                        .await?;
                } else {
                    self.storage
                        .write_version(bucket, key, &meta, &target.object_path(bucket, key))
                        .await?;
                }
                entries.extend(self.version_entries(target, bucket, key, "null"));
            }
            entries.extend(self.version_entries(target, bucket, key, version_id));
        }
        entries.extend([
            Entry {
                source: self.storage.object_path(bucket, key),
                destination: target.object_path(bucket, key),
                directory: false,
            },
            Entry {
                source: self.storage.ec_dir(bucket, key),
                destination: target.ec_dir(bucket, key),
                directory: true,
            },
            Entry {
                source: self.storage.meta_path(bucket, key),
                destination: target.meta_path(bucket, key),
                directory: false,
            },
        ]);

        self.publish_with_lock(entries, guard).await
    }

    fn version_entries(
        &self,
        target: &FilesystemStorage,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> [Entry; 3] {
        [
            Entry {
                source: self.storage.version_data_path(bucket, key, version_id),
                destination: target.version_data_path(bucket, key, version_id),
                directory: false,
            },
            Entry {
                source: self.storage.version_ec_dir(bucket, key, version_id),
                destination: target.version_ec_dir(bucket, key, version_id),
                directory: true,
            },
            Entry {
                source: self.storage.version_meta_path(bucket, key, version_id),
                destination: target.version_meta_path(bucket, key, version_id),
                directory: false,
            },
        ]
    }

    pub async fn copy_multipart(
        &self,
        target: &FilesystemStorage,
        bucket: &str,
        upload_id: &str,
    ) -> Result<(), StorageError> {
        let destination = self.storage.upload_dir(bucket, upload_id);
        fs::create_dir_all(&destination).await?;
        let mut entries = fs::read_dir(target.upload_dir(bucket, upload_id)).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_file() {
                // Same-filesystem links keep staging cheap; the mutation lock
                // prevents the original part from changing during completion.
                fs::hard_link(entry.path(), destination.join(entry.file_name())).await?;
            }
        }
        Ok(())
    }

    pub async fn finish_part(
        self,
        target: &FilesystemStorage,
        bucket: &str,
        upload_id: &str,
        part_number: u32,
        guard: OwnedMutexGuard<()>,
    ) -> Result<OwnedMutexGuard<()>, StorageError> {
        let entries = vec![
            Entry {
                source: self.storage.part_path(bucket, upload_id, part_number),
                destination: target.part_path(bucket, upload_id, part_number),
                directory: false,
            },
            Entry {
                source: self.storage.part_meta_path(bucket, upload_id, part_number),
                destination: target.part_meta_path(bucket, upload_id, part_number),
                directory: false,
            },
        ];
        self.publish_with_lock(entries, guard).await
    }

    async fn publish_with_lock(
        self,
        entries: Vec<Entry>,
        guard: OwnedMutexGuard<()>,
    ) -> Result<OwnedMutexGuard<()>, StorageError> {
        // The blocking publisher owns the lock. Cancellation of the HTTP request
        // cannot drop the lock mid-publication or delete its rollback files.
        tokio::task::spawn_blocking(move || self.publish(entries).map(|()| guard))
            .await
            .map_err(|error| io::Error::other(format!("object publisher failed: {error}")))?
    }

    fn publish(mut self, entries: Vec<Entry>) -> Result<(), StorageError> {
        let mut planned = Vec::new();
        for entry in entries {
            let source = metadata(&entry.source)?;
            let destination = metadata(&entry.destination)?;
            if source.is_none() && destination.is_none() {
                continue;
            }
            // An existing ordinary prefix directory may share a key's filename.
            // It is never an obsolete object payload and must not be removed.
            if source.is_none()
                && !entry.directory
                && destination.as_ref().is_some_and(|m| m.is_dir())
            {
                continue;
            }
            for meta in [source.as_ref(), destination.as_ref()]
                .into_iter()
                .flatten()
            {
                if meta.file_type().is_symlink() || meta.is_dir() != entry.directory {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Object conflicts with an existing storage path",
                    )
                    .into());
                }
            }
            if let Some(parent) = entry.destination.parent() {
                std::fs::create_dir_all(parent)?;
            }
            planned.push((entry, source.is_some(), destination.is_some()));
        }

        let backup_root = self.root.join("rollback");
        std::fs::create_dir_all(&backup_root)?;
        let mut applied: Vec<Applied> = Vec::new();
        let publication = (|| -> io::Result<()> {
            for (index, (entry, has_source, has_destination)) in planned.iter().enumerate() {
                let backup = has_destination.then(|| backup_root.join(index.to_string()));
                if let Some(path) = &backup {
                    std::fs::rename(&entry.destination, path)?;
                }
                applied.push(Applied {
                    destination: entry.destination.clone(),
                    backup,
                    installed: false,
                });
                if *has_source {
                    std::fs::rename(&entry.source, &entry.destination)?;
                    if let Some(last) = applied.last_mut() {
                        last.installed = true;
                    }
                }
            }
            Ok(())
        })();

        if let Err(error) = publication {
            for entry in applied.into_iter().rev() {
                let rollback = (|| -> io::Result<()> {
                    if entry.installed {
                        remove(&entry.destination)?;
                    }
                    if let Some(backup) = entry.backup {
                        std::fs::rename(backup, &entry.destination)?;
                    }
                    Ok(())
                })();
                if let Err(rollback_error) = rollback {
                    self.preserve_recovery = true;
                    return Err(io::Error::other(format!(
                        "publication failed ({error}); rollback failed ({rollback_error}); recovery files retained at {}",
                        self.root.display()
                    )).into());
                }
            }
            return Err(error.into());
        }
        Ok(())
    }
}

impl Drop for StagedWrite {
    fn drop(&mut self) {
        if !self.preserve_recovery {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}
