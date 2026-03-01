use std::path::{Path, PathBuf};

pub(crate) fn lifecycle_path(buckets_dir: &Path, bucket: &str) -> PathBuf {
    buckets_dir.join(bucket).join(".lifecycle.json")
}

pub(crate) fn object_path(buckets_dir: &Path, bucket: &str, key: &str) -> PathBuf {
    if key.ends_with('/') {
        let dir = key.trim_end_matches('/');
        buckets_dir.join(bucket).join(dir).join(".folder")
    } else {
        buckets_dir.join(bucket).join(key)
    }
}

pub(crate) fn meta_path(buckets_dir: &Path, bucket: &str, key: &str) -> PathBuf {
    if key.ends_with('/') {
        let dir = key.trim_end_matches('/');
        buckets_dir.join(bucket).join(dir).join(".folder.meta.json")
    } else {
        buckets_dir.join(bucket).join(format!("{}.meta.json", key))
    }
}

pub(crate) fn ec_dir(buckets_dir: &Path, bucket: &str, key: &str) -> PathBuf {
    buckets_dir.join(bucket).join(format!("{}.ec", key))
}

pub(crate) fn chunk_path(buckets_dir: &Path, bucket: &str, key: &str, index: u32) -> PathBuf {
    ec_dir(buckets_dir, bucket, key).join(format!("{:06}", index))
}

pub(crate) fn manifest_path(buckets_dir: &Path, bucket: &str, key: &str) -> PathBuf {
    ec_dir(buckets_dir, bucket, key).join("manifest.json")
}

pub(crate) fn uploads_dir(buckets_dir: &Path, bucket: &str) -> PathBuf {
    buckets_dir.join(bucket).join(".uploads")
}

pub(crate) fn upload_dir(buckets_dir: &Path, bucket: &str, upload_id: &str) -> PathBuf {
    uploads_dir(buckets_dir, bucket).join(upload_id)
}

pub(crate) fn upload_meta_path(buckets_dir: &Path, bucket: &str, upload_id: &str) -> PathBuf {
    upload_dir(buckets_dir, bucket, upload_id).join(".meta.json")
}

pub(crate) fn part_path(
    buckets_dir: &Path,
    bucket: &str,
    upload_id: &str,
    part_number: u32,
) -> PathBuf {
    upload_dir(buckets_dir, bucket, upload_id).join(part_number.to_string())
}

pub(crate) fn part_meta_path(
    buckets_dir: &Path,
    bucket: &str,
    upload_id: &str,
    part_number: u32,
) -> PathBuf {
    upload_dir(buckets_dir, bucket, upload_id).join(format!("{}.meta.json", part_number))
}

pub(crate) fn versions_dir(buckets_dir: &Path, bucket: &str, key: &str) -> PathBuf {
    let key_path = Path::new(key);
    let parent = key_path.parent().unwrap_or(Path::new(""));
    let name = key_path.file_name().unwrap_or(key.as_ref());
    buckets_dir
        .join(bucket)
        .join(parent)
        .join(".versions")
        .join(name)
}

pub(crate) fn version_data_path(
    buckets_dir: &Path,
    bucket: &str,
    key: &str,
    version_id: &str,
) -> PathBuf {
    versions_dir(buckets_dir, bucket, key).join(format!("{}.data", version_id))
}

pub(crate) fn version_meta_path(
    buckets_dir: &Path,
    bucket: &str,
    key: &str,
    version_id: &str,
) -> PathBuf {
    versions_dir(buckets_dir, bucket, key).join(format!("{}.meta.json", version_id))
}

#[cfg(test)]
mod tests {
    use super::{
        lifecycle_path, meta_path, object_path, part_meta_path, part_path, upload_dir,
        upload_meta_path, uploads_dir, version_data_path, version_meta_path, versions_dir,
    };
    use std::path::Path;

    #[test]
    fn object_and_meta_path_handle_folder_markers() {
        let root = Path::new("/data/buckets");
        assert_eq!(
            object_path(root, "b", "docs/"),
            root.join("b").join("docs").join(".folder")
        );
        assert_eq!(
            meta_path(root, "b", "docs/"),
            root.join("b").join("docs").join(".folder.meta.json")
        );
        assert_eq!(
            meta_path(root, "b", "docs/readme.txt"),
            root.join("b").join("docs/readme.txt.meta.json")
        );
    }

    #[test]
    fn multipart_paths_are_stable() {
        let root = Path::new("/data/buckets");
        assert_eq!(uploads_dir(root, "b"), root.join("b").join(".uploads"));
        assert_eq!(
            upload_dir(root, "b", "u1"),
            root.join("b").join(".uploads").join("u1")
        );
        assert_eq!(
            upload_meta_path(root, "b", "u1"),
            root.join("b")
                .join(".uploads")
                .join("u1")
                .join(".meta.json")
        );
        assert_eq!(
            part_path(root, "b", "u1", 7),
            root.join("b").join(".uploads").join("u1").join("7")
        );
        assert_eq!(
            part_meta_path(root, "b", "u1", 7),
            root.join("b")
                .join(".uploads")
                .join("u1")
                .join("7.meta.json")
        );
    }

    #[test]
    fn lifecycle_and_version_paths_are_stable() {
        let root = Path::new("/data/buckets");
        assert_eq!(
            lifecycle_path(root, "b"),
            root.join("b").join(".lifecycle.json")
        );
        assert_eq!(
            versions_dir(root, "b", "folder/file.txt"),
            root.join("b")
                .join("folder")
                .join(".versions")
                .join("file.txt")
        );
        assert_eq!(
            version_data_path(root, "b", "folder/file.txt", "v1"),
            root.join("b")
                .join("folder")
                .join(".versions")
                .join("file.txt")
                .join("v1.data")
        );
        assert_eq!(
            version_meta_path(root, "b", "folder/file.txt", "v1"),
            root.join("b")
                .join("folder")
                .join(".versions")
                .join("file.txt")
                .join("v1.meta.json")
        );
    }
}
