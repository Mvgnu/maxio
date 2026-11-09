use super::*;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

pub(super) fn lock_root(path: &Path, create: bool) -> Result<(PathBuf, File)> {
    require(
        cfg!(unix),
        ErrorCode::Unavailable,
        "managed fsynced authority is supported only on Unix local filesystems",
    )?;
    require(
        path.is_absolute(),
        ErrorCode::Invalid,
        "authority root must be absolute",
    )?;
    for ancestor in path.ancestors() {
        if ancestor.try_exists()? {
            let meta = fs::symlink_metadata(ancestor)?;
            require(
                meta.is_dir() && !meta.file_type().is_symlink(),
                ErrorCode::Invalid,
                "authority root ancestors must be regular directories",
            )?;
            for marker in [
                ".maxio-workspace",
                ".maxio-runtime",
                ".maxio-runs",
                ".maxio-sync",
            ] {
                require(
                    !ancestor.join(marker).try_exists()?,
                    ErrorCode::Invalid,
                    "authority root overlaps another MaxIO data/control root",
                )?;
            }
        }
    }
    if create {
        private_directory(path)?;
    }
    let root = fs::canonicalize(path)?;
    let meta = fs::symlink_metadata(&root)?;
    require(
        meta.is_dir() && !meta.file_type().is_symlink(),
        ErrorCode::Invalid,
        "authority root must be a directory",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        require(
            meta.permissions().mode() & 0o077 == 0
                || create && fs::read_dir(&root)?.next().is_none(),
            ErrorCode::Invalid,
            "authority root must be private to its owner",
        )?;
        if create {
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let lock = options.open(root.join("lock"))?;
    fs2::FileExt::try_lock_exclusive(&lock).map_err(|_| {
        fail(
            ErrorCode::Conflict,
            "another coordinator owns this authority root",
        )
    })?;
    crate::files::sync_directory(&root)?;
    Ok((root, lock))
}

pub(super) fn private_directory(path: &Path) -> Result<()> {
    if path.try_exists()? {
        let meta = fs::symlink_metadata(path)?;
        require(
            meta.is_dir() && !meta.file_type().is_symlink(),
            ErrorCode::Unavailable,
            "vault directory is not a regular directory",
        )?;
        return Ok(());
    }
    let parent = path
        .parent()
        .ok_or_else(|| fail(ErrorCode::Invalid, "directory has no parent"))?;
    if !parent.try_exists()? {
        private_directory(parent)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    #[cfg(not(unix))]
    fs::create_dir(path)?;
    crate::files::sync_directory(path)?;
    crate::files::sync_directory(parent)
}

pub(super) fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    private_directory(
        path.parent()
            .ok_or_else(|| fail(ErrorCode::Invalid, "file has no parent"))?,
    )?;
    let mut file = crate::files::new_file(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    crate::files::sync_directory(path.parent().ok_or_else(|| {
        fail(
            ErrorCode::Unavailable,
            "required authority invariant is missing",
        )
    })?)
}

fn open_regular(path: &Path) -> Result<File> {
    let metadata = fs::symlink_metadata(path)?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        ErrorCode::Unavailable,
        "vault/source is not a regular file",
    )?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    require(
        file.metadata()?.is_file(),
        ErrorCode::Unavailable,
        "vault/source file changed type",
    )?;
    Ok(file)
}

pub(super) fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let file = open_regular(path)?;
    require(
        file.metadata()?.len() <= maximum as u64,
        ErrorCode::Unavailable,
        "stored metadata exceeds its bound",
    )?;
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    require(
        bytes.len() <= maximum,
        ErrorCode::Unavailable,
        "stored metadata grew beyond its bound",
    )?;
    Ok(bytes)
}

pub(super) fn scoped_version(workspace: &WorkspaceRecord, version: &FileVersion) -> Result<()> {
    crate::workspace::contract::validate_file_version(version)
        .map_err(|_| fail(ErrorCode::Invalid, "invalid immutable file identity"))?;
    require(
        version
            .blob
            .starts_with(&format!("maxio-workspaces/{}/blobs/", workspace.name)),
        ErrorCode::Forbidden,
        "file belongs to another workspace",
    )
}

fn blob_path(root: &Path, version: &FileVersion) -> Result<PathBuf> {
    crate::workspace::contract::validate_file_version(version)?;
    Ok(root.join("vault").join(&version.blob))
}

pub(super) fn copy_blob(root: &Path, version: &FileVersion, source: &Path) -> Result<()> {
    let destination = blob_path(root, version)?;
    private_directory(destination.parent().ok_or_else(|| {
        fail(
            ErrorCode::Unavailable,
            "required authority invariant is missing",
        )
    })?)?;
    let mut source = open_regular(source)?;
    require(
        source.metadata()?.len() == version.size,
        ErrorCode::Invalid,
        "upload size differs from declared size",
    )?;
    let mut output = crate::files::new_file(&destination)?;
    let mut digest = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(count as u64)
            .ok_or_else(|| fail(ErrorCode::Capacity, "upload size overflow"))?;
        require(
            size <= version.size,
            ErrorCode::Invalid,
            "upload grew beyond declared size; partial stage retained",
        )?;
        output.write_all(&buffer[..count])?;
        digest.update(&buffer[..count]);
    }
    output.sync_all()?;
    crate::files::sync_directory(destination.parent().ok_or_else(|| {
        fail(
            ErrorCode::Unavailable,
            "required authority invariant is missing",
        )
    })?)?;
    require(
        size == version.size && hex::encode(digest.finalize()) == version.sha256,
        ErrorCode::Invalid,
        "uploaded bytes do not match declared hash/size; unpublished stage retained",
    )
}

pub(super) fn verified_blob(root: &Path, version: &FileVersion) -> Result<File> {
    let mut file = open_regular(&blob_path(root, version)?)?;
    require(
        file.metadata()?.len() == version.size,
        ErrorCode::Unavailable,
        "retained blob size mismatch",
    )?;
    let mut digest = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size += count as u64;
        require(
            size <= version.size,
            ErrorCode::Unavailable,
            "retained blob grew",
        )?;
        digest.update(&buffer[..count]);
    }
    require(
        size == version.size && hex::encode(digest.finalize()) == version.sha256,
        ErrorCode::Unavailable,
        "retained blob integrity check failed",
    )?;
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

fn manifest_path(root: &Path, workspace: &WorkspaceRecord, revision: &str) -> Result<PathBuf> {
    valid_id(revision)?;
    crate::workspace::contract::validate_name(&workspace.name)?;
    Ok(root
        .join("vault")
        .join("maxio-workspaces")
        .join(&workspace.name)
        .join("revisions")
        .join(format!("{revision}.json")))
}

pub(super) fn write_manifest(
    root: &Path,
    workspace: &WorkspaceRecord,
    manifest: &Manifest,
) -> Result<RevisionRef> {
    let sha256 = crate::workspace::contract::manifest_hash(manifest)?;
    validate_manifest(workspace, manifest, &sha256)?;
    write_new(
        &manifest_path(root, workspace, &manifest.revision)?,
        &serde_json::to_vec(manifest)?,
    )?;
    Ok(RevisionRef {
        revision: manifest.revision.clone(),
        sha256,
    })
}

pub(super) fn manifest(
    root: &Path,
    workspace: &WorkspaceRecord,
    reference: &RevisionRef,
) -> Result<Manifest> {
    let bytes = read_bounded(
        &manifest_path(root, workspace, &reference.revision)?,
        crate::workspace::contract::MAX_MANIFEST_BYTES,
    )?;
    require(
        hash(&bytes) == reference.sha256,
        ErrorCode::Unavailable,
        "immutable manifest checksum mismatch",
    )?;
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    require(
        manifest.revision == reference.revision,
        ErrorCode::Unavailable,
        "immutable revision identity mismatch",
    )?;
    validate_manifest(workspace, &manifest, &reference.sha256)?;
    Ok(manifest)
}

fn validate_manifest(workspace: &WorkspaceRecord, manifest: &Manifest, sha256: &str) -> Result<()> {
    crate::workspace::contract::validate_snapshot(&Snapshot {
        manifest: manifest.clone(),
        manifest_sha256: sha256.into(),
        head_etag: None,
    })?;
    require(
        manifest.workspace_id == workspace.workspace_id,
        ErrorCode::Unavailable,
        "manifest workspace identity mismatch",
    )?;
    for version in manifest.files.values() {
        scoped_version(workspace, version)?;
    }
    Ok(())
}
