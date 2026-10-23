//! Filesystem boundary for the additive synchronizer. Never follow symlinks.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const STATE_DIRECTORY: &str = ".maxio-sync";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Baseline {
    pub sha256: String,
    pub remote_etag: String,
}

#[derive(Serialize, Deserialize)]
pub struct Journal {
    pub version: u32,
    pub scope: String,
    pub entries: BTreeMap<String, Baseline>,
}

pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn validate_relative(key: &str) -> Result<()> {
    ensure!(
        !key.is_empty() && key.len() <= 1024,
        "empty or oversized sync path"
    );
    for component in key.split('/') {
        ensure!(
            !component.is_empty()
                && component != "."
                && component != ".."
                && !component.eq_ignore_ascii_case(STATE_DIRECTORY)
                && component.len() <= 255
                && !component.ends_with(['.', ' '])
                && !component
                    .chars()
                    .any(|c| c.is_control() || "\\:<>|?*".contains(c)),
            "unsafe sync path: {key:?}"
        );
        let stem = component
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        ensure!(
            !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                && !(stem.len() == 4
                    && (stem.starts_with("COM") || stem.starts_with("LPT"))
                    && matches!(stem.as_bytes()[3], b'1'..=b'9')),
            "non-portable sync path: {key:?}"
        );
    }
    Ok(())
}

/// Reject file/directory and case collisions before changing either side.
pub fn validate_path_set<'a>(keys: impl Iterator<Item = &'a String>) -> Result<()> {
    let keys: BTreeSet<_> = keys.cloned().collect();
    let mut folded = BTreeMap::new();
    for key in &keys {
        validate_relative(key)?;
        let lower = key.to_lowercase();
        if let Some(other) = folded.insert(lower, key) {
            ensure!(
                other == key,
                "case-colliding sync paths: {other:?} and {key:?}"
            );
        }
        let mut ancestor = key.as_str();
        while let Some((parent, _)) = ancestor.rsplit_once('/') {
            ensure!(
                !keys.contains(parent),
                "file/directory collision at {parent:?}"
            );
            ancestor = parent;
        }
    }
    // Case-fold every prefix too: A/file and a/other must not merge on another OS.
    let mut directories = BTreeMap::new();
    for key in &keys {
        let mut ancestor = key.as_str();
        while let Some((parent, _)) = ancestor.rsplit_once('/') {
            let folded_parent = parent.to_lowercase();
            ensure!(
                !folded.contains_key(&folded_parent),
                "file/directory collision at {parent:?}"
            );
            if let Some(other) = directories.insert(folded_parent, parent.to_string()) {
                ensure!(
                    other == parent,
                    "case-colliding sync directories: {other:?} and {parent:?}"
                );
            }
            ancestor = parent;
        }
    }
    Ok(())
}

pub fn directory(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error).with_context(|| format!("create directory {}", path.display()));
        }
    }
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        !meta.file_type().is_symlink() && meta.is_dir(),
        "directory is a symlink or not a directory: {}",
        path.display()
    );
    Ok(())
}

pub fn checked_path(root: &Path, key: &str, create_parents: bool) -> Result<PathBuf> {
    validate_relative(key)?;
    let parts: Vec<_> = key.split('/').collect();
    let mut path = root.to_path_buf();
    for (index, component) in parts.iter().enumerate() {
        path.push(component);
        let last = index + 1 == parts.len();
        if !last && create_parents {
            directory(&path)?;
        }
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                ensure!(
                    !meta.file_type().is_symlink(),
                    "symlink is not supported: {}",
                    path.display()
                );
                ensure!(
                    if last { meta.is_file() } else { meta.is_dir() },
                    "non-regular sync path: {}",
                    path.display()
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(path)
}

pub fn read(root: &Path, key: &str, limit: u64) -> Result<Vec<u8>> {
    let path = checked_path(root, key, false)?;
    let file = File::open(&path).with_context(|| format!("read local file {key:?}"))?;
    ensure!(
        file.metadata()?.len() <= limit,
        "local file exceeds --max-file-mib: {key:?}"
    );
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "local file grew beyond --max-file-mib: {key:?}"
    );
    Ok(bytes)
}

pub fn scan(root: &Path, limit: u64) -> Result<BTreeMap<String, String>> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = BTreeMap::new();
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let relative = path
                .strip_prefix(root)?
                .to_str()
                .context("sync paths must be valid UTF-8")?
                .replace(std::path::MAIN_SEPARATOR, "/");
            if relative == STATE_DIRECTORY {
                continue;
            }
            validate_relative(&relative)?;
            let meta = fs::symlink_metadata(&path)?;
            ensure!(
                !meta.file_type().is_symlink(),
                "symlink is not supported: {relative:?}"
            );
            if meta.is_dir() {
                pending.push(path);
            } else if meta.is_file() {
                files.insert(relative.clone(), digest(&read(root, &relative, limit)?));
            } else {
                bail!("non-regular file is not supported: {relative:?}");
            }
        }
    }
    validate_path_set(files.keys())?;
    Ok(files)
}

pub fn new_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

pub fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Keep the old inode in local history before replacement. An application still
/// writing through an open descriptor writes into that retained history file.
/// The final hard link is atomic and fails instead of overwriting a new arrival.
pub fn install(
    root: &Path,
    state: &Path,
    key: &str,
    bytes: &[u8],
    expected: Option<&str>,
    limit: u64,
) -> Result<()> {
    let path = checked_path(root, key, true)?;
    let stage = state.join(format!("stage-{}", uuid::Uuid::new_v4()));
    let mut file = new_file(&stage)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    let outcome = (|| -> Result<()> {
        let current = match fs::symlink_metadata(&path) {
            Ok(_) => Some(digest(&read(root, key, limit)?)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        ensure!(
            current.as_deref() == expected,
            "local file changed during sync; retry preserves it: {key:?}"
        );
        if expected.is_some() {
            let history = state.join("history");
            directory(&history)?;
            let backup = history.join(format!(
                "{}-{}.bak",
                chrono::Utc::now().format("%Y%m%dT%H%M%S"),
                uuid::Uuid::new_v4()
            ));
            // Re-check the path after reading and before moving it.
            checked_path(root, key, false)?;
            // Record the original pathname next to the retained inode.
            let mut note = new_file(&backup.with_extension("json"))?;
            note.write_all(
                serde_json::to_string(
                    &serde_json::json!({"path": key, "expected_sha256": expected}),
                )?
                .as_bytes(),
            )?;
            note.sync_all()?;
            fs::rename(&path, &backup)?;
            sync_directory(&history)?;
            let mut previous_bytes = Vec::new();
            File::open(&backup)?
                .take(limit.saturating_add(1))
                .read_to_end(&mut previous_bytes)?;
            if digest(&previous_bytes) != expected.unwrap_or_default() {
                // Never overwrite a concurrent arrival; keep history even if restoring fails.
                let _ = fs::hard_link(&backup, &path);
                bail!(
                    "local file changed while staging; original retained in {}",
                    backup.display()
                );
            }
        }
        checked_path(root, key, false)?;
        fs::hard_link(&stage, &path).with_context(|| {
            format!("install {key:?} without replacing a concurrent local file")
        })?;
        sync_directory(path.parent().context("sync destination has no parent")?)?;
        Ok(())
    })();
    let _ = fs::remove_file(stage);
    outcome
}

pub fn save_journal(path: &Path, journal: &Journal) -> Result<()> {
    let parent = path.parent().context("journal path has no parent")?;
    let temporary = parent.join(format!("journal-{}.tmp", uuid::Uuid::new_v4()));
    let mut file = new_file(&temporary)?;
    file.write_all(&serde_json::to_vec_pretty(journal)?)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    sync_directory(parent)
}

pub fn conflict_key(key: &str, hash: &str) -> String {
    let (parent, name) = key.rsplit_once('/').map_or(("", key), |(p, n)| (p, n));
    let mut end = name.len().min(160);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    let name = format!("{}.maxio-conflict-{hash}", &name[..end]);
    if parent.is_empty() {
        name
    } else {
        format!("{parent}/{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_traversal_reserved_and_cross_platform_aliases() {
        for key in [
            "../escape",
            "/absolute",
            "x/./y",
            "x//y",
            "x\\y",
            "x/CON.txt",
            ".maxio-sync/state",
            ".MAXIO-SYNC/state",
            "file.",
            "x\u{0000}y",
        ] {
            assert!(validate_relative(key).is_err(), "{key:?}");
        }
        assert!(validate_relative("photos/café + #%.txt").is_ok());
        for keys in [["x", "x/y"], ["A/x", "a/y"], ["A", "a/x"], ["a", "A"]] {
            let keys: Vec<_> = keys.iter().map(|s| s.to_string()).collect();
            assert!(validate_path_set(keys.iter()).is_err());
        }
    }

    #[test]
    fn replacement_refuses_changed_local_file_and_keeps_previous_inode() {
        let root = tempfile::TempDir::new().unwrap();
        let state = root.path().join(STATE_DIRECTORY);
        directory(&state).unwrap();
        fs::write(root.path().join("notes.txt"), b"edited locally").unwrap();
        assert!(
            install(
                root.path(),
                &state,
                "notes.txt",
                b"remote",
                Some(&digest(b"old")),
                1024
            )
            .is_err()
        );
        assert_eq!(
            fs::read(root.path().join("notes.txt")).unwrap(),
            b"edited locally"
        );
        let mut old_handle = OpenOptions::new()
            .write(true)
            .open(root.path().join("notes.txt"))
            .unwrap();
        install(
            root.path(),
            &state,
            "notes.txt",
            b"remote",
            Some(&digest(b"edited locally")),
            1024,
        )
        .unwrap();
        old_handle.write_all(b"late edit").unwrap();
        old_handle.sync_all().unwrap();
        assert_eq!(fs::read(root.path().join("notes.txt")).unwrap(), b"remote");
        let backup = fs::read_dir(state.join("history"))
            .unwrap()
            .filter_map(Result::ok)
            .find(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "bak")
            })
            .unwrap();
        assert!(fs::read(backup.path()).unwrap().starts_with(b"late edit"));
    }
}
