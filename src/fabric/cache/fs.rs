//! Filesystem checks assume one cooperating owner of the private manager root.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Fingerprint {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub links: u64,
    pub modified_secs: i64,
    pub modified_nanos: i64,
    pub changed_secs: i64,
    pub changed_nanos: i64,
    pub allocated_bytes: u64,
}

pub(super) fn fingerprint(path: &Path) -> Result<Fingerprint> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink(),
        "cache path is not an ordinary file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(Fingerprint {
            device: meta.dev(),
            inode: meta.ino(),
            size: meta.len(),
            links: meta.nlink(),
            modified_secs: meta.mtime(),
            modified_nanos: meta.mtime_nsec(),
            changed_secs: meta.ctime(),
            changed_nanos: meta.ctime_nsec(),
            allocated_bytes: meta
                .blocks()
                .checked_mul(512)
                .context("allocated size overflow")?,
        })
    }
    #[cfg(not(unix))]
    {
        let modified = meta.modified()?.duration_since(std::time::UNIX_EPOCH)?;
        Ok(Fingerprint {
            device: 0,
            inode: 0,
            size: meta.len(),
            links: 1,
            modified_secs: modified.as_secs().try_into()?,
            modified_nanos: modified.subsec_nanos().into(),
            changed_secs: 0,
            changed_nanos: 0,
            allocated_bytes: meta.len(),
        })
    }
}

pub(super) fn verify(path: &Path, sha256: &str, size: u64) -> Result<Fingerprint> {
    let before = fingerprint(path)?;
    ensure!(
        before.links == 1,
        "cache object has a hardlink alias; preserve it"
    );
    ensure!(
        before.size == size,
        "cache object length changed; preserve it"
    );
    let (actual, length) = crate::files::hash_file(path)?;
    let after = fingerprint(path)?;
    ensure!(
        before == after,
        "cache inode changed during verification; preserve it"
    );
    ensure!(
        actual == sha256 && length == size,
        "cache content changed; preserve it"
    );
    Ok(after)
}

pub(super) fn directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => crate::files::sync_directory(path.parent().context("directory has no parent")?)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error.into()),
    }
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "cache directory is not an ordinary directory"
    );
    Ok(())
}

pub(super) fn root(path: &Path) -> Result<PathBuf> {
    root_inner(path, false)
}

pub(super) fn cache_root(path: &Path) -> Result<PathBuf> {
    root_inner(path, true)
}

fn root_inner(path: &Path, admitting_cache: bool) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    ensure!(
        !absolute
            .components()
            .any(|part| part == std::path::Component::ParentDir),
        "private path contains a parent traversal"
    );
    for ancestor in absolute.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(meta) => ensure!(
                meta.is_dir() && !meta.file_type().is_symlink(),
                "private root or ancestor is not an ordinary directory"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        if !admitting_cache {
            continue;
        }
        for marker in [
            ".maxio-workspace",
            ".maxio-runtime",
            ".maxio-sync",
            ".git",
            ".maxio-fabric",
            ".maxio-worker",
        ] {
            // Only this root's own worker marker may be admitted. Validate its
            // contents separately before reopening the persisted cache.
            if ancestor == absolute && marker == ".maxio-worker" {
                continue;
            }
            // A source repository itself is not a cache, but a parent checkout
            // is not a typed private data root for all of its descendants.
            if ancestor != absolute && marker == ".git" {
                continue;
            }
            match fs::symlink_metadata(ancestor.join(marker)) {
                Ok(_) => anyhow::bail!(
                    "private cache cannot adopt or nest beneath a protected data tree"
                ),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
            }
        }
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&absolute)?;
    Ok(fs::canonicalize(absolute)?)
}

pub(super) fn copy_verified(
    source: &Path,
    destination: &Path,
    sha256: &str,
    size: u64,
) -> Result<()> {
    let before = fingerprint(source)?;
    ensure!(
        before.size == size,
        "source size differs from the admitted immutable input"
    );
    let mut input = File::open(source)?;
    let mut output = crate::files::new_file(destination)?;
    let mut digest = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .context("copy size overflow")?;
        ensure!(
            total <= size,
            "source grew during copy; incomplete stage retained"
        );
        output.write_all(&buffer[..count])?;
        digest.update(&buffer[..count]);
    }
    output.sync_all()?;
    crate::files::sync_directory(
        destination
            .parent()
            .context("copy destination has no parent")?,
    )?;
    ensure!(
        fingerprint(source)? == before,
        "source inode changed during copy; stage retained"
    );
    ensure!(
        total == size && hex::encode(digest.finalize()) == sha256,
        "source content differs from admitted identity; stage retained"
    );
    Ok(())
}

pub(super) fn json<T: Serialize>(path: &Path, value: &T, limit: usize) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() <= limit,
        "private cache metadata exceeds capacity"
    );
    if let Ok(meta) = fs::symlink_metadata(path) {
        ensure!(
            meta.is_file() && !meta.file_type().is_symlink(),
            "private metadata path is not an ordinary file"
        );
    }
    let parent = path.parent().context("metadata path has no parent")?;
    let temporary = parent.join(format!("metadata-{}.tmp", uuid::Uuid::new_v4()));
    let mut output = crate::files::new_file(&temporary)?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    fs::rename(&temporary, path)?;
    crate::files::sync_directory(parent)
}

pub(super) fn read_json<T: serde::de::DeserializeOwned>(path: &Path, limit: usize) -> Result<T> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= limit as u64,
        "invalid or oversized private cache metadata"
    );
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit,
        "private cache metadata grew beyond capacity"
    );
    serde_json::from_slice(&bytes)
        .context("invalid private cache metadata; preserve it for recovery")
}

pub(super) fn available(path: &Path) -> Result<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
        let mut value = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: a NUL-terminated path and writable statvfs storage are supplied.
        let result = unsafe { libc::statvfs(path.as_ptr(), value.as_mut_ptr()) };
        ensure!(
            result == 0,
            "filesystem available-space observation failed: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: successful statvfs initialized the value.
        let value = unsafe { value.assume_init() };
        // statvfs field widths differ across Unix targets. Widen both operands
        // before multiplication, then reject a result our public u64 cannot hold.
        let available = u128::from(value.f_bavail)
            .checked_mul(u128::from(value.f_frsize))
            .context("filesystem available size overflow")?;
        u64::try_from(available).context("filesystem available size exceeds u64")
    }
    #[cfg(not(unix))]
    anyhow::bail!("measured cache eviction currently requires Unix")
}
