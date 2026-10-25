//! PM-owned vendor-neutral local execution contract.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdapterKind {
    Command,
    Codex,
    Claude,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PermissionMode {
    ReadOnly,
    WorkspaceWrite,
}

/// Environment values exist only in memory. Persist names, never values.
pub struct RunRequest {
    pub adapter: AdapterKind,
    pub executable: PathBuf,
    /// Trusted source root. Only explicit inputs are copied to the new run workspace.
    pub source: PathBuf,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub records: PathBuf,
    pub prompt: Option<String>,
    pub args: Vec<String>,
    pub timeout_seconds: u64,
    pub environment: BTreeMap<String, String>,
    pub permission: PermissionMode,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunFile {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunRecord {
    pub format: u32,
    pub id: String,
    pub adapter: AdapterKind,
    pub executable: String,
    pub executable_version: String,
    /// preparing, running, succeeded, failed, cancelled, timed_out, protocol_failed.
    pub status: String,
    pub workspace: PathBuf,
    pub stdout_log: PathBuf,
    pub stderr_log: PathBuf,
    pub input_files: Vec<RunFile>,
    pub output_files: Vec<RunFile>,
    pub environment_names: Vec<String>,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub exit_code: Option<i32>,
    pub provider_session_id: Option<String>,
    pub detail: Option<String>,
    /// Always false in this milestone. Success is not storage publication.
    pub published: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DoctorReport {
    pub adapter: AdapterKind,
    pub executable: String,
    pub version: String,
    pub supported: bool,
    pub detail: String,
}
