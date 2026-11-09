//! Filesystem changes leave failed staging and replacement history recoverable.
use crate::files;
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Editable roots and selected paths must stay outside private server, authority
/// and worker trees. Inspect marker entries without following symlinks, including
/// dangling markers, before creating workspace state or transfer stages.
pub(super) fn reject_private_ancestors(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        for marker in [".maxio-runtime", ".maxio-fabric", ".maxio-worker"] {
            match fs::symlink_metadata(ancestor.join(marker)) {
                Ok(_) => anyhow::bail!(
                    "editable workspace path overlaps a private MaxIO data root at {} ({marker})",
                    ancestor.display()
                ),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

fn check_aliases(root: &Path, key: &str) -> Result<()> {
    let mut parent = root.to_path_buf();
    for part in key.split('/') {
        match fs::read_dir(&parent) {
            Ok(entries) => {
                for entry in entries {
                    let entry = entry?;
                    if let Some(name) = entry.file_name().to_str() {
                        ensure!(
                            name.to_lowercase() != part.to_lowercase() || name == part,
                            "case-colliding local workspace path: {key:?}"
                        );
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(error.into()),
        }
        parent.push(part);
    }
    Ok(())
}

pub(super) fn checked_file(root: &Path, key: &str, create_parents: bool) -> Result<PathBuf> {
    files::validate_workspace_relative(key)?;
    let destination = files::checked_path(root, key, false)?;
    reject_private_ancestors(
        destination
            .parent()
            .context("workspace path has no parent")?,
    )?;
    check_aliases(root, key)?;
    files::checked_path(root, key, create_parents)
}

pub(super) fn selected_local_files(root: &Path, selectors: &[String]) -> Result<Vec<String>> {
    ensure!(
        !selectors.is_empty(),
        "select at least one explicit file or directory"
    );
    let mut found = BTreeSet::new();
    for raw in selectors {
        let selector = raw.strip_suffix('/').unwrap_or(raw);
        let path = if selector == "." {
            root.to_path_buf()
        } else {
            files::validate_workspace_relative(selector)?;
            root.join(selector)
        };
        let mut pending = vec![(
            path,
            if selector == "." {
                String::new()
            } else {
                selector.into()
            },
        )];
        let mut matches = 0usize;
        while let Some((path, relative)) = pending.pop() {
            let meta = fs::symlink_metadata(&path)
                .with_context(|| format!("selected workspace path is missing: {selector:?}"))?;
            ensure!(
                !meta.file_type().is_symlink(),
                "symlink is not supported: {relative:?}"
            );
            if meta.is_file() {
                checked_file(root, &relative, false)?;
                found.insert(relative);
                matches += 1;
            } else {
                ensure!(meta.is_dir(), "non-regular workspace path: {relative:?}");
                if !relative.is_empty() {
                    files::checked_path(root, &format!("{relative}/.maxio-path-check"), false)?;
                    check_aliases(root, &relative)?;
                }
                let mut names = BTreeMap::new();
                for entry in fs::read_dir(&path)? {
                    let entry = entry?;
                    let name = entry.file_name();
                    let name = name
                        .to_str()
                        .context("workspace paths must be valid UTF-8")?;
                    if [
                        ".git",
                        ".maxio-sync",
                        ".maxio-workspace",
                        ".maxio-runs",
                        ".maxio-runtime",
                    ]
                    .iter()
                    .any(|reserved| name.eq_ignore_ascii_case(reserved))
                    {
                        continue;
                    }
                    ensure!(
                        names.insert(name.to_lowercase(), name.to_owned()).is_none(),
                        "case-colliding selected directory entries"
                    );
                    let next = if relative.is_empty() {
                        name.into()
                    } else {
                        format!("{relative}/{name}")
                    };
                    files::validate_workspace_relative(&next)?;
                    pending.push((entry.path(), next));
                }
            }
        }
        ensure!(matches > 0, "selector has no regular files: {selector:?}");
    }
    files::validate_workspace_paths(found.iter())?;
    Ok(found.into_iter().collect())
}

pub(super) fn atomic_json(destination: &Path, bytes: &[u8]) -> Result<()> {
    let parent = destination.parent().context("state path has no parent")?;
    if let Ok(meta) = fs::symlink_metadata(destination) {
        ensure!(
            meta.is_file() && !meta.file_type().is_symlink(),
            "state destination is not a regular file"
        );
    }
    let temporary = parent.join(format!("state-{}.tmp", uuid::Uuid::new_v4()));
    let mut file = files::new_file(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, destination)?;
    files::sync_directory(parent)
}

pub(super) fn write_receipt(path: &Path, receipt: &serde_json::Value) -> Result<()> {
    atomic_json(path, &serde_json::to_vec_pretty(receipt)?)
}

pub(super) fn operation_directory(control: &Path, operation: &str) -> Result<PathBuf> {
    let stages = control.join("staging");
    files::directory(&stages)?;
    let path = stages.join(format!("{operation}-{}", uuid::Uuid::new_v4()));
    files::directory(&path)?;
    files::sync_directory(&stages)?;
    Ok(path)
}

pub(super) fn copy_verified(source: &Path, destination: &Path) -> Result<(String, u64)> {
    let meta = fs::symlink_metadata(source)?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink(),
        "publication source is not a regular file"
    );
    let mut source_file = File::open(source)?;
    let mut stage = files::new_file(destination)?;
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let count = source_file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        stage.write_all(&buffer[..count])?;
        hasher.update(&buffer[..count]);
        size = size
            .checked_add(count as u64)
            .context("staged file size overflow")?;
    }
    stage.sync_all()?;
    drop(stage);
    files::sync_directory(destination.parent().context("staging file has no parent")?)?;
    let sha256 = hex::encode(hasher.finalize());
    ensure!(
        files::hash_file(source)? == (sha256.clone(), size),
        "local source changed while staging; original and stage were preserved"
    );
    Ok((sha256, size))
}

/// The old inode remains in history for late open-descriptor writers. The new
/// name is created with a hard link, so a concurrent arrival is never replaced.
pub(super) fn install(
    root: &Path,
    control: &Path,
    key: &str,
    stage: &Path,
    expected: Option<&(String, u64)>,
) -> Result<()> {
    let destination = checked_file(root, key, true)?;
    let current = match fs::symlink_metadata(&destination) {
        Ok(_) => Some(files::hash_file(&destination)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    ensure!(
        current.as_ref() == expected,
        "local file changed during hydration; refusing replacement of {key:?}"
    );
    if expected.is_some() {
        let history = control.join("history");
        files::directory(&history)?;
        let backup = history.join(format!("{}.data", uuid::Uuid::new_v4()));
        write_receipt(
            &backup.with_extension("json"),
            &serde_json::json!({
                "format": 1, "path": key,
                "expected_sha256": expected.map(|value| &value.0),
                "expected_size": expected.map(|value| value.1),
            }),
        )?;
        checked_file(root, key, false)?;
        fs::rename(&destination, &backup)?;
        files::sync_directory(&history)?;
        files::sync_directory(
            destination
                .parent()
                .context("workspace file has no parent")?,
        )?;
        if Some(&files::hash_file(&backup)?) != expected {
            let _ = fs::hard_link(&backup, &destination);
            anyhow::bail!(
                "local file changed while replacing {key:?}; original retained at {}",
                backup.display()
            );
        }
    }
    checked_file(root, key, false)?;
    fs::hard_link(stage, &destination).with_context(|| {
        format!(
            "could not install {key:?} without replacing a concurrent local arrival; stage retained"
        )
    })?;
    files::sync_directory(
        destination
            .parent()
            .context("workspace file has no parent")?,
    )?;
    Ok(())
}
