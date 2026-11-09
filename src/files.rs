//! Shared portable filesystem checks. Callers must own and trust the root.
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

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
                && !component.eq_ignore_ascii_case(".maxio-sync")
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

/// Additional reserved control paths for selective workspaces and isolated runs.
pub fn validate_workspace_relative(key: &str) -> Result<()> {
    validate_relative(key)?;
    ensure!(
        !key.split('/').any(|part| [
            ".git",
            ".maxio-workspace",
            ".maxio-runs",
            ".maxio-runtime",
            ".maxio-fabric",
            ".maxio-worker"
        ]
        .iter()
        .any(|reserved| part.eq_ignore_ascii_case(reserved))),
        "reserved workspace path: {key:?}"
    );
    Ok(())
}

pub fn validate_workspace_paths<'a>(keys: impl Iterator<Item = &'a String>) -> Result<()> {
    let keys: Vec<_> = keys.collect();
    validate_path_set(keys.iter().copied())?;
    for key in keys {
        validate_workspace_relative(key)?;
    }
    Ok(())
}

/// Exact file or directory selectors; no glob expansion or implicit all-files mode.
pub fn select_paths<'a>(
    keys: impl Iterator<Item = &'a String>,
    selectors: &[String],
) -> Result<Vec<String>> {
    ensure!(
        !selectors.is_empty(),
        "select at least one explicit file or directory"
    );
    let keys: Vec<_> = keys.collect();
    let mut selected = BTreeSet::new();
    for selector in selectors {
        let selector = selector.strip_suffix('/').unwrap_or(selector);
        if selector != "." {
            validate_workspace_relative(selector)?;
        }
        let matches: Vec<_> = keys
            .iter()
            .filter(|key| {
                selector == "."
                    || key.as_str() == selector
                    || key.starts_with(&format!("{selector}/"))
            })
            .collect();
        ensure!(!matches.is_empty(), "selector has no files: {selector:?}");
        selected.extend(matches.into_iter().map(|key| (*key).clone()));
    }
    Ok(selected.into_iter().collect())
}

/// Streaming SHA-256 with bounded memory; callers perform path/root validation.
pub fn hash_file(path: &Path) -> Result<(String, u64)> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "not a regular file: {}",
        path.display()
    );
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let count = file
            .read(&mut buffer)
            .with_context(|| format!("read {}", path.display()))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
        size = size
            .checked_add(count as u64)
            .context("file size overflow")?;
    }
    Ok((hex::encode(digest.finalize()), size))
}
