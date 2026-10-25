use super::super::contract::{RunFile, RunRecord};
use crate::files;
use anyhow::{Context, Result, ensure};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

pub(super) struct RunPaths {
    pub id: String,
    pub root: PathBuf,
    pub workspace: PathBuf,
    pub home: PathBuf,
    pub temp: PathBuf,
}

pub(super) fn root(path: &Path) -> Result<PathBuf> {
    ensure!(path.is_absolute(), "directory must be an absolute path");
    let meta = fs::symlink_metadata(path).context("inspect selected directory")?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "selected directory must be a real directory, not a symlink"
    );
    Ok(fs::canonicalize(path)?)
}

fn private_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}

pub(super) fn create_run(records: &Path) -> Result<RunPaths> {
    ensure!(records.is_absolute(), "records directory must be absolute");
    // The operator chooses the records root. Canonicalize existing ancestors,
    // then reject a symlink at each newly selected directory component.
    fn create_root(path: &Path) -> Result<PathBuf> {
        match fs::symlink_metadata(path) {
            Ok(_) => root(path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let parent = create_root(path.parent().context("records root has no parent")?)?;
                let path = parent.join(path.file_name().context("invalid records directory")?);
                private_directory(&path)?;
                files::sync_directory(&parent)?;
                root(&path)
            }
            Err(error) => Err(error.into()),
        }
    }
    let records = create_root(records)?;
    let id = uuid::Uuid::new_v4().to_string();
    let run_root = records.join(&id);
    private_directory(&run_root)?;
    let workspace = run_root.join("workspace");
    let home = run_root.join("home");
    let temp = run_root.join("tmp");
    for directory in [&workspace, &home, &temp] {
        private_directory(directory)?;
    }
    files::sync_directory(&run_root)?;
    files::sync_directory(&records)?;
    Ok(RunPaths {
        id,
        root: run_root,
        workspace,
        home,
        temp,
    })
}

pub(super) fn validate_selector(selector: &str) -> Result<&str> {
    let selector = selector.strip_suffix('/').unwrap_or(selector);
    if selector != "." {
        safe_path(selector)?;
    }
    Ok(selector)
}

fn safe_path(path: &str) -> Result<()> {
    files::validate_workspace_relative(path)?;
    ensure!(
        !path
            .split('/')
            .any(|part| [".codex", ".claude", ".aws", ".ssh"]
                .iter()
                .any(|reserved| part.eq_ignore_ascii_case(reserved))),
        "credential or provider control directory is not a task input/output"
    );
    Ok(())
}

fn selected_files(root: &Path, selectors: &[String], missing_ok: bool) -> Result<Vec<String>> {
    fn walk(root: &Path, key: &str, selected: &mut BTreeSet<String>) -> Result<()> {
        if !key.is_empty() {
            safe_path(key)?;
        }
        let path = root.join(key);
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "symlink in selected input/output: {key}"
        );
        if metadata.is_file() {
            selected.insert(key.to_string());
        } else {
            ensure!(
                metadata.is_dir(),
                "non-regular selected input/output: {key}"
            );
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("non-UTF-8 task path"))?;
                let child = if key.is_empty() {
                    name
                } else {
                    format!("{key}/{name}")
                };
                walk(root, &child, selected)?;
            }
        }
        Ok(())
    }
    let mut selected = BTreeSet::new();
    for selector in selectors {
        let selector = validate_selector(selector)?;
        let key = if selector == "." { "" } else { selector };
        // Validate all ancestor components before walking a directory selector.
        let mut current = root.to_path_buf();
        for component in key.split('/').filter(|value| !value.is_empty()) {
            current.push(component);
            match fs::symlink_metadata(&current) {
                Ok(meta) => ensure!(!meta.file_type().is_symlink(), "symlink in selected path"),
                Err(error) if missing_ok && error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => return Err(error).context("selected input does not exist"),
            }
        }
        if missing_ok && !root.join(key).try_exists()? {
            continue;
        }
        let previous = selected.len();
        walk(root, key, &mut selected)?;
        ensure!(
            missing_ok
                || selected.len() > previous
                || selected
                    .iter()
                    .any(|path| path == key || path.starts_with(&format!("{key}/"))),
            "selected input directory contains no regular files"
        );
    }
    files::validate_workspace_paths(selected.iter())?;
    Ok(selected.into_iter().collect())
}

pub(super) fn copy_inputs(
    source: &Path,
    workspace: &Path,
    selectors: &[String],
) -> Result<Vec<RunFile>> {
    let selected = selected_files(source, selectors, false)?;
    let mut result = Vec::with_capacity(selected.len());
    for key in selected {
        let source_path = files::checked_path(source, &key, false)?;
        let destination = files::checked_path(workspace, &key, true)?;
        let mut input = File::open(&source_path)?;
        let mut output = files::new_file(&destination)?;
        std::io::copy(&mut input, &mut output)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let executable_bits = input.metadata()?.permissions().mode() & 0o111;
            output.set_permissions(fs::Permissions::from_mode(0o600 | executable_bits))?;
        }
        output.sync_all()?;
        let (sha256, size) = files::hash_file(&destination)?;
        result.push(RunFile {
            path: key,
            sha256,
            size,
        });
    }
    files::sync_directory(workspace)?;
    Ok(result)
}

pub(super) fn outputs(workspace: &Path, selectors: &[String]) -> Result<Vec<RunFile>> {
    let mut result = Vec::new();
    for key in selected_files(workspace, selectors, true)? {
        let path = files::checked_path(workspace, &key, false)?;
        let (sha256, size) = files::hash_file(&path)?;
        result.push(RunFile {
            path: key,
            sha256,
            size,
        });
    }
    Ok(result)
}

pub(super) fn persist(record: &RunRecord, run_root: &Path) -> Result<()> {
    let temp = run_root.join(format!("record-{}.tmp", uuid::Uuid::new_v4()));
    let mut file = files::new_file(&temp)?;
    serde_json::to_writer_pretty(&mut file, record)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(temp, run_root.join("record.json"))?;
    files::sync_directory(run_root)
}
