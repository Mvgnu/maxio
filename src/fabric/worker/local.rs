use super::super::contract::*;
use crate::execution::{RunFile, RunRecord};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub(super) const MAX_STATE: u64 = 32 * 1024 * 1024;

pub(super) fn id() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub(super) fn private_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => crate::files::sync_directory(path.parent().context("directory has no parent")?)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "worker directory is not an ordinary directory"
    );
    Ok(())
}

pub(super) fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= MAX_STATE,
        "invalid or oversized worker record"
    );
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_STATE + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_STATE,
        "worker record grew beyond its limit"
    );
    serde_json::from_slice(&bytes).context("invalid worker record; preserve it for recovery")
}

pub(super) fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() as u64 <= MAX_STATE,
        "worker record exceeds capacity; retained work was not pruned"
    );
    if let Ok(metadata) = fs::symlink_metadata(path) {
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "unsafe worker record path"
        );
    }
    let parent = path.parent().context("worker record has no parent")?;
    let stage = parent.join(format!("record-{}.tmp", id()));
    let mut file = crate::files::new_file(&stage)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fs::rename(&stage, path)?;
    crate::files::sync_directory(parent)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OutputStage {
    pub file: RunFile,
    pub stage_name: String,
    pub request: UploadRequest,
    pub prepared: Option<PreparedUpload>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LocalAttempt {
    pub format: u32,
    pub authority_id: String,
    pub vault_id: String,
    pub job: JobRecord,
    pub binding: AttemptBinding,
    pub lease: Option<WriteLease>,
    pub phase: String,
    pub cancellation_requested: bool,
    pub run: Option<RunRecord>,
    pub outputs: Vec<OutputStage>,
    pub finish_request_id: String,
    pub publication_request_id: String,
    pub publication: Option<PublicationReceipt>,
    #[serde(default)]
    pub transfer: crate::workspace::TransferStats,
    pub detail: Option<String>,
}

impl LocalAttempt {
    pub(super) fn new(info: &AuthorityInfo, claimed: &ClaimedJob) -> Self {
        Self {
            format: FABRIC_FORMAT,
            authority_id: info.authority_id.clone(),
            vault_id: info.vault_id.clone(),
            job: claimed.job.clone(),
            binding: claimed.attempt.clone(),
            lease: claimed.lease.clone(),
            phase: "preparing".into(),
            cancellation_requested: false,
            run: None,
            outputs: Vec::new(),
            finish_request_id: id(),
            publication_request_id: id(),
            publication: None,
            transfer: crate::workspace::TransferStats::default(),
            detail: None,
        }
    }
    pub(super) fn persist(&self, root: &Path) -> Result<()> {
        ensure!(
            root.file_name().and_then(|name| name.to_str())
                == Some(self.binding.attempt_id.as_str()),
            "attempt belongs to a different directory"
        );
        write_json(&root.join("attempt.json"), self)
    }
    pub(super) fn load(root: &Path, info: &AuthorityInfo) -> Result<Self> {
        let state: Self = read_json(&root.join("attempt.json"))?;
        ensure!(
            state.format == FABRIC_FORMAT
                && state.authority_id == info.authority_id
                && state.vault_id == info.vault_id,
            "attempt authority binding mismatch"
        );
        crate::workspace::validate_id(&state.binding.attempt_id)?;
        crate::workspace::validate_id(&state.binding.job_id)?;
        ensure!(
            root.file_name().and_then(|name| name.to_str())
                == Some(state.binding.attempt_id.as_str())
                && state.job.job_id == state.binding.job_id,
            "attempt directory identity mismatch"
        );
        for output in &state.outputs {
            crate::workspace::validate_id(&output.stage_name)?;
        }
        Ok(state)
    }
}

/// Inspect only the single run inside this attempt's private records root. A
/// record cannot direct recovery to arbitrary log/workspace paths.
pub(super) fn owned_run(records: &Path) -> Result<Option<(PathBuf, RunRecord)>> {
    let entries = match fs::read_dir(records) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut directories = Vec::new();
    for entry in entries {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "unexpected entry in attempt records directory"
        );
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("invalid run directory name"))?;
        crate::workspace::validate_id(&name)?;
        directories.push(entry.path());
    }
    ensure!(
        directories.len() <= 1,
        "multiple local runs exist for one attempt; refusing to guess"
    );
    let Some(root) = directories.pop() else {
        return Ok(None);
    };
    let record: RunRecord = match read_json(&root.join("record.json")) {
        Ok(record) => record,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    ensure!(
        record.format == 1
            && root.file_name().and_then(|name| name.to_str()) == Some(record.id.as_str())
            && record.workspace == root.join("workspace")
            && record.stdout_log == root.join("stdout.log")
            && record.stderr_log == root.join("stderr.log"),
        "local run record identity mismatch"
    );
    ensure!(
        matches!(
            record.status.as_str(),
            "preparing"
                | "running"
                | "succeeded"
                | "failed"
                | "cancelled"
                | "timed_out"
                | "protocol_failed"
        ),
        "unknown local run status"
    );
    ensure!(
        !record.published,
        "local runner record cannot claim publication"
    );
    Ok(Some((root, record)))
}

pub(super) fn cancel_owned_run(records: &Path) -> Result<()> {
    if let Some((root, record)) = owned_run(records)?
        && matches!(record.status.as_str(), "preparing" | "running")
    {
        match crate::execution::runner::request_cancel(&root) {
            Ok(_) => {}
            Err(error) => {
                // The runner can atomically finish between inspection and this
                // request. Its terminal record is the only accepted explanation.
                if owned_run(records)?.is_none_or(|(_, record)| {
                    matches!(record.status.as_str(), "preparing" | "running")
                }) {
                    return Err(error);
                }
            }
        }
    }
    Ok(())
}

pub(super) fn copy_verified(source: &Path, destination: &Path, expected: &RunFile) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "output candidate is not a regular file"
    );
    let mut input = File::open(source)?;
    let mut output = crate::files::new_file(destination)?;
    let mut buffer = [0u8; 65536];
    let mut copied = 0u64;
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        copied = copied
            .checked_add(count as u64)
            .context("output length overflow")?;
        ensure!(
            copied <= expected.size,
            "output changed after the terminal run record; stage retained"
        );
        output.write_all(&buffer[..count])?;
    }
    output.sync_all()?;
    if crate::files::hash_file(destination)? != (expected.sha256.clone(), expected.size) {
        bail!("output content changed after the terminal run record; stage retained");
    }
    crate::files::sync_directory(destination.parent().context("stage has no parent")?)
}

pub(super) fn retained_inputs(job: &JobRecord) -> Vec<RetainedFile> {
    job.inputs
        .iter()
        .map(|input| RetainedFile {
            workspace_id: job.workspace_id.clone(),
            revision: input.revision.clone(),
            path: input.path.clone(),
            version: input.version.clone(),
        })
        .collect()
}
