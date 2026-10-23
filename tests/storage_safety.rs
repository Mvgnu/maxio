use std::io::{self, Cursor};
use std::pin::Pin;
use std::task::{Context, Poll};

use maxio::storage::filesystem::FilesystemStorage;
use maxio::storage::{
    BucketMeta, ByteStream, ChecksumAlgorithm, ObjectWriteCondition, StorageError,
};
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

async fn storage(erasure: bool) -> (TempDir, FilesystemStorage) {
    let dir = TempDir::new().unwrap();
    let storage = FilesystemStorage::new(dir.path().to_str().unwrap(), erasure, 8, 1)
        .await
        .unwrap();
    storage
        .create_bucket(&BucketMeta {
            name: "safe-bucket".into(),
            created_at: "2026-10-23T00:00:00.000Z".into(),
            region: "us-east-1".into(),
            versioning: false,
        })
        .await
        .unwrap();
    (dir, storage)
}

fn body(bytes: &[u8]) -> ByteStream {
    Box::pin(Cursor::new(bytes.to_vec()))
}

async fn bytes(storage: &FilesystemStorage, key: &str) -> Vec<u8> {
    let (mut reader, _) = storage.get_object("safe-bucket", key).await.unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).await.unwrap();
    bytes
}

#[tokio::test]
async fn rejected_checksum_overwrite_preserves_bytes_and_metadata() {
    for erasure in [false, true] {
        let (_dir, storage) = storage(erasure).await;
        let original = storage
            .put_object(
                "safe-bucket",
                "keep.txt",
                "text/plain",
                body(b"keep these bytes"),
                None,
            )
            .await
            .unwrap();
        let result = storage
            .put_object(
                "safe-bucket",
                "keep.txt",
                "text/plain",
                body(b"bad replacement"),
                Some((ChecksumAlgorithm::SHA256, Some("incorrect-checksum".into()))),
            )
            .await;
        assert!(
            matches!(result, Err(StorageError::ChecksumMismatch(_))),
            "erasure={erasure}"
        );
        assert_eq!(
            bytes(&storage, "keep.txt").await,
            b"keep these bytes",
            "erasure={erasure}"
        );
        let after = storage
            .head_object("safe-bucket", "keep.txt")
            .await
            .unwrap();
        assert_eq!(after.etag, original.etag);
        assert_eq!(after.size, original.size);
    }
}

struct InterruptedBody(bool);

impl AsyncRead for InterruptedBody {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "sender disconnected",
            )));
        }
        buf.put_slice(b"partial");
        self.0 = true;
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn interrupted_overwrite_preserves_the_previous_object() {
    for erasure in [false, true] {
        let (_dir, storage) = storage(erasure).await;
        storage
            .put_object(
                "safe-bucket",
                "keep.txt",
                "text/plain",
                body(b"original"),
                None,
            )
            .await
            .unwrap();
        let result = storage
            .put_object(
                "safe-bucket",
                "keep.txt",
                "text/plain",
                Box::pin(InterruptedBody(false)),
                None,
            )
            .await;
        assert!(matches!(result, Err(StorageError::Io(_))));
        assert_eq!(
            bytes(&storage, "keep.txt").await,
            b"original",
            "erasure={erasure}"
        );
    }
}

#[tokio::test]
async fn version_ids_cannot_escape_the_version_directory() {
    let (_dir, storage) = storage(false).await;
    storage.set_versioning("safe-bucket", true).await.unwrap();
    storage
        .put_object("safe-bucket", "source", "text/plain", body(b"source"), None)
        .await
        .unwrap();
    storage
        .put_object("safe-bucket", "victim", "text/plain", body(b"victim"), None)
        .await
        .unwrap();
    for bad_id in [
        "../../victim",
        "/tmp/victim",
        "..\\..\\victim",
        ".",
        "..",
        "",
    ] {
        assert!(
            storage
                .head_object_version("safe-bucket", "source", bad_id)
                .await
                .is_err(),
            "head accepted {bad_id:?}"
        );
        assert!(
            storage
                .get_object_version("safe-bucket", "source", bad_id)
                .await
                .is_err(),
            "get accepted {bad_id:?}"
        );
        assert!(
            storage
                .delete_object_version("safe-bucket", "source", bad_id)
                .await
                .is_err(),
            "delete accepted {bad_id:?}"
        );
        assert!(
            storage
                .put_object_with_version_id(
                    "safe-bucket",
                    "source",
                    "text/plain",
                    body(b"replacement"),
                    None,
                    Some(bad_id)
                )
                .await
                .is_err(),
            "forced write accepted {bad_id:?}"
        );
    }
    assert_eq!(bytes(&storage, "source").await, b"source");
    assert_eq!(bytes(&storage, "victim").await, b"victim");
}

#[tokio::test]
async fn object_keys_cannot_overwrite_internal_files_or_alias_existing_keys() {
    let (dir, storage) = storage(false).await;
    let bucket_path = dir.path().join("buckets/safe-bucket/.bucket.json");
    let bucket_before = tokio::fs::read(&bucket_path).await.unwrap();
    for key in [
        ".bucket.json",
        ".lifecycle.json",
        ".uploads/x",
        ".versions/x",
        ".folder",
        "victim.meta.json",
        "victim.ec/x",
        "a//b",
        "a/./b",
        "./a",
        ".",
        "a//",
        "a/../b",
        "nested/.bucket.json",
        "nested/.versions/x",
        "null\0byte",
    ] {
        let result = storage
            .put_object("safe-bucket", key, "text/plain", body(b"replacement"), None)
            .await;
        assert!(
            matches!(result, Err(StorageError::InvalidKey(_))),
            "key accepted {key:?}"
        );
    }
    assert_eq!(tokio::fs::read(&bucket_path).await.unwrap(), bucket_before);
    assert!(
        storage
            .list_objects("safe-bucket", "")
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn switching_storage_encoding_does_not_return_old_chunks() {
    let (dir, chunked) = storage(true).await;
    chunked
        .put_object(
            "safe-bucket",
            "switch.txt",
            "text/plain",
            body(b"old chunked bytes"),
            None,
        )
        .await
        .unwrap();
    let flat = FilesystemStorage::new(dir.path().to_str().unwrap(), false, 8, 0)
        .await
        .unwrap();
    flat.put_object(
        "safe-bucket",
        "switch.txt",
        "text/plain",
        body(b"new flat bytes"),
        None,
    )
    .await
    .unwrap();
    assert_eq!(bytes(&flat, "switch.txt").await, b"new flat bytes");
    chunked
        .put_object(
            "safe-bucket",
            "switch.txt",
            "text/plain",
            body(b"new chunked bytes"),
            None,
        )
        .await
        .unwrap();
    assert_eq!(bytes(&chunked, "switch.txt").await, b"new chunked bytes");
}

#[tokio::test]
async fn concurrent_conditional_updates_cannot_both_replace_the_same_etag() {
    let (_dir, storage) = storage(false).await;
    let original = storage
        .put_object(
            "safe-bucket",
            "shared.txt",
            "text/plain",
            body(b"original"),
            None,
        )
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        storage.put_object_conditional(
            "safe-bucket",
            "shared.txt",
            "text/plain",
            body(b"writer a"),
            None,
            ObjectWriteCondition::IfMatch(original.etag.clone())
        ),
        storage.put_object_conditional(
            "safe-bucket",
            "shared.txt",
            "text/plain",
            body(b"writer b"),
            None,
            ObjectWriteCondition::IfMatch(original.etag)
        )
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert_ne!(a.is_some(), b.is_some(), "exactly one writer must win");
    assert_eq!(
        bytes(&storage, "shared.txt").await,
        if a.is_some() {
            b"writer a"
        } else {
            b"writer b"
        }
    );
}

#[tokio::test]
async fn create_only_put_refuses_an_existing_object() {
    let (_dir, storage) = storage(false).await;
    let (a, b) = tokio::join!(
        storage.put_object_conditional(
            "safe-bucket",
            "new.txt",
            "text/plain",
            body(b"writer a"),
            None,
            ObjectWriteCondition::IfAbsent
        ),
        storage.put_object_conditional(
            "safe-bucket",
            "new.txt",
            "text/plain",
            body(b"writer b"),
            None,
            ObjectWriteCondition::IfAbsent
        )
    );
    assert_ne!(a.unwrap().is_some(), b.unwrap().is_some());
}

#[tokio::test]
async fn rejected_part_replacement_preserves_the_accepted_part() {
    let (_dir, storage) = storage(false).await;
    let upload = storage
        .create_multipart_upload("safe-bucket", "parts.txt", "text/plain", None)
        .await
        .unwrap();
    let original = storage
        .upload_part(
            "safe-bucket",
            &upload.upload_id,
            1,
            body(b"accepted part"),
            None,
        )
        .await
        .unwrap();
    let rejected = storage
        .upload_part(
            "safe-bucket",
            &upload.upload_id,
            1,
            body(b"bad replacement"),
            Some((ChecksumAlgorithm::SHA256, Some("wrong".into()))),
        )
        .await;
    assert!(matches!(rejected, Err(StorageError::ChecksumMismatch(_))));
    storage
        .complete_multipart_upload("safe-bucket", &upload.upload_id, &[(1, original.etag)])
        .await
        .unwrap();
    assert_eq!(bytes(&storage, "parts.txt").await, b"accepted part");
}

#[tokio::test]
async fn missing_part_during_completion_does_not_destroy_previous_object() {
    for erasure in [false, true] {
        let (dir, storage) = storage(erasure).await;
        storage
            .put_object(
                "safe-bucket",
                "keep.txt",
                "text/plain",
                body(b"original"),
                None,
            )
            .await
            .unwrap();
        let upload = storage
            .create_multipart_upload("safe-bucket", "keep.txt", "text/plain", None)
            .await
            .unwrap();
        let part = storage
            .upload_part(
                "safe-bucket",
                &upload.upload_id,
                1,
                body(b"replacement"),
                None,
            )
            .await
            .unwrap();
        tokio::fs::remove_file(
            dir.path()
                .join("buckets/safe-bucket/.uploads")
                .join(&upload.upload_id)
                .join("1"),
        )
        .await
        .unwrap();
        assert!(
            storage
                .complete_multipart_upload("safe-bucket", &upload.upload_id, &[(1, part.etag)])
                .await
                .is_err()
        );
        assert_eq!(bytes(&storage, "keep.txt").await, b"original");
    }
}

#[tokio::test]
async fn bucket_deletion_preserves_history_until_every_version_is_removed() {
    for key in ["keep.txt", "nested/keep.txt"] {
        let (_dir, storage) = storage(false).await;
        storage.set_versioning("safe-bucket", true).await.unwrap();
        let original = storage
            .put_object(
                "safe-bucket",
                key,
                "text/plain",
                body(b"retained history"),
                None,
            )
            .await
            .unwrap();
        let marker = storage.delete_object("safe-bucket", key).await.unwrap();
        let rejected = storage.delete_bucket("safe-bucket").await;
        assert!(matches!(rejected, Err(StorageError::BucketNotEmpty)));
        assert!(storage.is_versioned("safe-bucket").await.unwrap());
        let versions = storage
            .list_object_versions("safe-bucket", "")
            .await
            .unwrap();
        assert_eq!(versions.len(), 2);
        let (mut reader, _) = storage
            .get_object_version("safe-bucket", key, original.version_id.as_deref().unwrap())
            .await
            .unwrap();
        let mut retained = Vec::new();
        reader.read_to_end(&mut retained).await.unwrap();
        assert_eq!(retained, b"retained history");
        storage
            .delete_object_version("safe-bucket", key, marker.version_id.as_deref().unwrap())
            .await
            .unwrap();
        storage
            .delete_object_version("safe-bucket", key, original.version_id.as_deref().unwrap())
            .await
            .unwrap();
        assert!(matches!(
            storage.head_object("safe-bucket", key).await,
            Err(StorageError::NotFound(_))
        ));
        assert!(storage.delete_bucket("safe-bucket").await.unwrap());
    }
}

#[tokio::test]
async fn completed_multipart_upload_has_an_independent_version_snapshot() {
    for erasure in [false, true] {
        let (_dir, storage) = storage(erasure).await;
        storage.set_versioning("safe-bucket", true).await.unwrap();
        storage
            .put_object(
                "safe-bucket",
                "versioned.txt",
                "text/plain",
                body(b"first version"),
                None,
            )
            .await
            .unwrap();
        let upload = storage
            .create_multipart_upload("safe-bucket", "versioned.txt", "text/plain", None)
            .await
            .unwrap();
        let part = storage
            .upload_part(
                "safe-bucket",
                &upload.upload_id,
                1,
                body(b"multipart version"),
                None,
            )
            .await
            .unwrap();
        let completed = storage
            .complete_multipart_upload("safe-bucket", &upload.upload_id, &[(1, part.etag)])
            .await
            .unwrap();
        let version_id = completed
            .version_id
            .as_deref()
            .expect("versioned completion must return a version ID");
        assert_eq!(
            storage
                .list_object_versions("safe-bucket", "")
                .await
                .unwrap()
                .len(),
            2
        );
        storage
            .delete_object("safe-bucket", "versioned.txt")
            .await
            .unwrap();
        let (mut reader, meta) = storage
            .get_object_version("safe-bucket", "versioned.txt", version_id)
            .await
            .unwrap();
        let mut retained = Vec::new();
        reader.read_to_end(&mut retained).await.unwrap();
        assert_eq!(retained, b"multipart version");
        assert_eq!(meta.etag, completed.etag);
        assert_eq!(meta.version_id.as_deref(), Some(version_id));
    }
}

#[tokio::test]
async fn folder_marker_versions_do_not_alias_a_same_named_chunked_object() {
    let (_dir, storage) = storage(true).await;
    storage.set_versioning("safe-bucket", true).await.unwrap();
    let object = storage
        .put_object("safe-bucket", "docs", "text/plain", body(b"object"), None)
        .await
        .unwrap();
    let folder = storage
        .put_object(
            "safe-bucket",
            "docs/",
            "text/plain",
            body(b"folder object"),
            None,
        )
        .await
        .unwrap();
    let folder_id = folder.version_id.as_deref().unwrap();
    assert_eq!(
        storage
            .list_object_versions("safe-bucket", "docs/")
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(matches!(
        storage
            .head_object_version("safe-bucket", "docs", folder_id)
            .await,
        Err(StorageError::VersionNotFound(_))
    ));
    storage
        .delete_object_version("safe-bucket", "docs", object.version_id.as_deref().unwrap())
        .await
        .unwrap();
    assert!(matches!(
        storage.head_object("safe-bucket", "docs").await,
        Err(StorageError::NotFound(_))
    ));
    assert_eq!(bytes(&storage, "docs/").await, b"folder object");
}

#[tokio::test]
async fn restoring_an_older_version_switches_storage_encoding() {
    let (dir, flat) = storage(false).await;
    flat.set_versioning("safe-bucket", true).await.unwrap();
    flat.put_object(
        "safe-bucket",
        "format.txt",
        "text/plain",
        body(b"flat version"),
        None,
    )
    .await
    .unwrap();
    let chunked = FilesystemStorage::new(dir.path().to_str().unwrap(), true, 8, 1)
        .await
        .unwrap();
    let newest = chunked
        .put_object(
            "safe-bucket",
            "format.txt",
            "text/plain",
            body(b"chunked version"),
            None,
        )
        .await
        .unwrap();
    flat.delete_object_version(
        "safe-bucket",
        "format.txt",
        newest.version_id.as_deref().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(bytes(&flat, "format.txt").await, b"flat version");
}

async fn version_bytes(storage: &FilesystemStorage, key: &str, version: &str) -> Vec<u8> {
    let (mut reader, _) = storage
        .get_object_version("safe-bucket", key, version)
        .await
        .unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).await.unwrap();
    bytes
}

#[tokio::test]
async fn null_version_survives_enable_overwrites_restart_and_restore() {
    for erasure in [false, true] {
        let (dir, store) = storage(erasure).await;
        let original = store
            .put_object(
                "safe-bucket",
                "item",
                "text/original",
                body(b"original"),
                None,
            )
            .await
            .unwrap();
        store.set_versioning("safe-bucket", true).await.unwrap();
        let null_meta = store
            .head_object_version("safe-bucket", "item", "null")
            .await
            .unwrap();
        assert_eq!(null_meta.version_id.as_deref(), Some("null"));
        assert_eq!(null_meta.etag, original.etag);
        assert_eq!(version_bytes(&store, "item", "null").await, b"original");
        let versions = store.list_object_versions("safe-bucket", "").await.unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version_id.as_deref(), Some("null"));
        let (mut range, _) = store
            .get_object_version_range("safe-bucket", "item", "null", 1, 3)
            .await
            .unwrap();
        let mut selected = Vec::new();
        range.read_to_end(&mut selected).await.unwrap();
        assert_eq!(selected, b"rig");

        let newer = store
            .put_object_conditional(
                "safe-bucket",
                "item",
                "text/new",
                body(b"newer"),
                None,
                ObjectWriteCondition::IfMatch(original.etag.clone()),
            )
            .await
            .unwrap()
            .unwrap();
        let newest = store
            .put_object("safe-bucket", "item", "text/latest", body(b"newest"), None)
            .await
            .unwrap();
        drop(store);
        let store = FilesystemStorage::new(dir.path().to_str().unwrap(), erasure, 8, 1)
            .await
            .unwrap();
        assert_eq!(version_bytes(&store, "item", "null").await, b"original");
        let null_meta = store
            .head_object_version("safe-bucket", "item", "null")
            .await
            .unwrap();
        assert_eq!(null_meta.content_type, "text/original");
        assert_eq!(null_meta.etag, original.etag);
        let versions = store.list_object_versions("safe-bucket", "").await.unwrap();
        let ids: Vec<_> = versions.iter().map(|m| m.version_id.as_deref()).collect();
        assert_eq!(
            ids,
            [
                newest.version_id.as_deref(),
                newer.version_id.as_deref(),
                Some("null")
            ]
        );
        store
            .delete_object_version("safe-bucket", "item", newer.version_id.as_deref().unwrap())
            .await
            .unwrap();
        assert_eq!(bytes(&store, "item").await, b"newest");
        store
            .delete_object_version("safe-bucket", "item", newest.version_id.as_deref().unwrap())
            .await
            .unwrap();
        assert_eq!(bytes(&store, "item").await, b"original");
        store
            .delete_object_version("safe-bucket", "item", "null")
            .await
            .unwrap();
        assert!(matches!(
            store.get_object("safe-bucket", "item").await,
            Err(StorageError::NotFound(_))
        ));
        assert!(
            store
                .list_object_versions("safe-bucket", "")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(store.delete_bucket("safe-bucket").await.unwrap());
    }
}

#[tokio::test]
async fn null_version_survives_first_delete_marker() {
    for erasure in [false, true] {
        let (_dir, store) = storage(erasure).await;
        store
            .put_object(
                "safe-bucket",
                "item",
                "text/plain",
                body(b"before-delete"),
                None,
            )
            .await
            .unwrap();
        store.set_versioning("safe-bucket", true).await.unwrap();
        let marker = store.delete_object("safe-bucket", "item").await.unwrap();
        assert_eq!(
            version_bytes(&store, "item", "null").await,
            b"before-delete"
        );
        let versions = store.list_object_versions("safe-bucket", "").await.unwrap();
        assert_eq!(versions.len(), 2);
        assert!(versions[0].is_delete_marker);
        assert_eq!(versions[1].version_id.as_deref(), Some("null"));
        assert!(matches!(
            store.delete_bucket("safe-bucket").await,
            Err(StorageError::BucketNotEmpty)
        ));
        store
            .delete_object_version("safe-bucket", "item", marker.version_id.as_deref().unwrap())
            .await
            .unwrap();
        assert_eq!(bytes(&store, "item").await, b"before-delete");
        store
            .delete_object_version("safe-bucket", "item", "null")
            .await
            .unwrap();
        assert!(store.delete_bucket("safe-bucket").await.unwrap());
    }
}

#[tokio::test]
async fn null_version_survives_multipart_completion() {
    for erasure in [false, true] {
        let (_dir, store) = storage(erasure).await;
        store
            .put_object(
                "safe-bucket",
                "item",
                "text/original",
                body(b"before-multipart"),
                None,
            )
            .await
            .unwrap();
        store.set_versioning("safe-bucket", true).await.unwrap();
        let upload = store
            .create_multipart_upload("safe-bucket", "item", "text/new", None)
            .await
            .unwrap();
        let part = store
            .upload_part(
                "safe-bucket",
                &upload.upload_id,
                1,
                body(b"multipart-result"),
                None,
            )
            .await
            .unwrap();
        let result = store
            .complete_multipart_upload("safe-bucket", &upload.upload_id, &[(1, part.etag)])
            .await
            .unwrap();
        assert!(result.version_id.is_some());
        assert_eq!(bytes(&store, "item").await, b"multipart-result");
        assert_eq!(
            version_bytes(&store, "item", "null").await,
            b"before-multipart"
        );
        assert_eq!(
            store
                .list_object_versions("safe-bucket", "")
                .await
                .unwrap()
                .len(),
            2
        );
    }
}

#[tokio::test]
async fn null_versions_of_folder_marker_and_chunked_object_do_not_alias() {
    let (_dir, store) = storage(true).await;
    store
        .put_object(
            "safe-bucket",
            "docs",
            "text/plain",
            body(b"object-original"),
            None,
        )
        .await
        .unwrap();
    store
        .put_object(
            "safe-bucket",
            "docs/",
            "text/plain",
            body(b"folder-original"),
            None,
        )
        .await
        .unwrap();
    store.set_versioning("safe-bucket", true).await.unwrap();
    store
        .put_object(
            "safe-bucket",
            "docs",
            "text/plain",
            body(b"object-new"),
            None,
        )
        .await
        .unwrap();
    let marker = store.delete_object("safe-bucket", "docs/").await.unwrap();
    assert_eq!(
        version_bytes(&store, "docs", "null").await,
        b"object-original"
    );
    assert_eq!(
        version_bytes(&store, "docs/", "null").await,
        b"folder-original"
    );
    store
        .delete_object_version("safe-bucket", "docs", "null")
        .await
        .unwrap();
    assert_eq!(bytes(&store, "docs").await, b"object-new");
    assert_eq!(
        version_bytes(&store, "docs/", "null").await,
        b"folder-original"
    );
    store
        .delete_object_version(
            "safe-bucket",
            "docs/",
            marker.version_id.as_deref().unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bytes(&store, "docs/").await, b"folder-original");
    store
        .delete_object_version("safe-bucket", "docs/", "null")
        .await
        .unwrap();
    assert!(
        store
            .list_object_versions("safe-bucket", "docs/")
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn null_snapshot_publication_failure_preserves_current() {
    for erasure in [false, true] {
        let (dir, store) = storage(erasure).await;
        store
            .put_object(
                "safe-bucket",
                "item",
                "text/original",
                body(b"must-survive"),
                None,
            )
            .await
            .unwrap();
        store.set_versioning("safe-bucket", true).await.unwrap();
        let collision = dir
            .path()
            .join("buckets/safe-bucket/.versions/item/null.meta.json");
        tokio::fs::create_dir_all(&collision).await.unwrap();
        assert!(
            store
                .put_object(
                    "safe-bucket",
                    "item",
                    "text/new",
                    body(b"replacement"),
                    None
                )
                .await
                .is_err()
        );
        assert_eq!(bytes(&store, "item").await, b"must-survive");
        assert!(store.delete_object("safe-bucket", "item").await.is_err());
        assert_eq!(bytes(&store, "item").await, b"must-survive");
        assert_eq!(
            store
                .head_object("safe-bucket", "item")
                .await
                .unwrap()
                .content_type,
            "text/original"
        );
    }
}

#[tokio::test]
async fn null_version_can_be_permanently_deleted_before_first_snapshot() {
    for erasure in [false, true] {
        for key in ["item", "nested/item", "folder/"] {
            let (_dir, store) = storage(erasure).await;
            store
                .put_object("safe-bucket", key, "text/plain", body(b"original"), None)
                .await
                .unwrap();
            store.set_versioning("safe-bucket", true).await.unwrap();
            let deleted = store
                .delete_object_version("safe-bucket", key, "null")
                .await
                .unwrap();
            assert_eq!(deleted.version_id.as_deref(), Some("null"));
            assert!(!deleted.is_delete_marker);
            assert!(matches!(
                store.get_object("safe-bucket", key).await,
                Err(StorageError::NotFound(_))
            ));
            assert!(
                store
                    .list_object_versions("safe-bucket", "")
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(
                store.delete_bucket("safe-bucket").await.unwrap(),
                "key={key}, erasure={erasure}"
            );
        }
    }
}
