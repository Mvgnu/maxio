use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RevisionEntry {
    pub reference: RevisionRef,
    pub generation: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub(super) enum Reply {
    Control(Box<ControlResponse>),
    Upload(Box<PreparedUpload>),
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RequestRecord {
    pub hash: String,
    pub reply: Reply,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredJob {
    pub record: JobRecord,
    pub prompt: Option<String>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LogState {
    pub length: u64,
    pub truncated: bool,
    pub chunks: Vec<LogChunk>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LogChunk {
    pub id: String,
    pub offset: u64,
    pub size: u64,
    pub sha256: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    pub info: AuthorityInfo,
    pub fence: u64,
    pub devices: BTreeMap<String, DeviceRecord>,
    pub grants: BTreeMap<String, GrantRecord>,
    pub workspaces: BTreeMap<String, WorkspaceRecord>,
    pub revisions: BTreeMap<String, RevisionEntry>,
    pub leases: BTreeMap<String, WriteLease>,
    pub uploads: BTreeMap<String, PreparedUpload>,
    pub requests: BTreeMap<String, RequestRecord>,
    pub workers: BTreeMap<String, WorkerRecord>,
    /// Retired incarnations never become current again, even with a fresh request ID.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub worker_incarnations: BTreeMap<String, BTreeSet<String>>,
    pub jobs: BTreeMap<String, StoredJob>,
    pub logs: BTreeMap<String, LogState>,
}

impl State {
    pub fn new(owner: DeviceRecord) -> Self {
        Self {
            info: AuthorityInfo {
                format: FABRIC_FORMAT,
                authority_id: new_id(),
                vault_id: new_id(),
                epoch: 1,
                generation: 1,
                retention_policy_version: 1,
            },
            fence: 0,
            devices: BTreeMap::from([(owner.device_id.clone(), owner)]),
            grants: BTreeMap::new(),
            workspaces: BTreeMap::new(),
            revisions: BTreeMap::new(),
            leases: BTreeMap::new(),
            uploads: BTreeMap::new(),
            requests: BTreeMap::new(),
            workers: BTreeMap::new(),
            worker_incarnations: BTreeMap::new(),
            jobs: BTreeMap::new(),
            logs: BTreeMap::new(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        require(
            self.info.format == FABRIC_FORMAT
                && self.info.epoch > 0
                && self.info.generation > 0
                && self.info.retention_policy_version == 1,
            ErrorCode::Unavailable,
            "unsupported or corrupt authority state",
        )?;
        valid_id(&self.info.authority_id)?;
        valid_id(&self.info.vault_id)?;
        require(
            self.devices.len() <= MAX_DEVICES
                && self.workspaces.len() <= MAX_WORKSPACES
                && self.leases.len() <= MAX_LEASES
                && self.uploads.len() <= MAX_UPLOADS
                && self.requests.len() <= MAX_REQUESTS
                && self.revisions.len() <= MAX_REVISIONS
                && self.jobs.len() <= MAX_JOBS
                && self.workers.len() <= MAX_WORKERS,
            ErrorCode::Capacity,
            "authority state exceeds a capacity bound",
        )?;
        require(
            self.devices
                .values()
                .any(|device| device.role == DeviceRole::Owner && !device.revoked),
            ErrorCode::Unavailable,
            "authority requires an active owner",
        )?;
        for (id, device) in &self.devices {
            valid_id(id)?;
            valid_key(&device.public_key)?;
            valid_label(&device.display_name)?;
            require(
                id == &device.device_id && device.key_generation > 0,
                ErrorCode::Unavailable,
                "invalid enrolled device state",
            )?;
        }
        let mut names = BTreeSet::new();
        for (id, workspace) in &self.workspaces {
            valid_id(id)?;
            crate::workspace::contract::validate_name(&workspace.name)?;
            require(
                names.insert(&workspace.name)
                    && id == &workspace.workspace_id
                    && workspace.head.workspace_id == *id
                    && workspace.head.authority_id == self.info.authority_id
                    && workspace.head.generation <= self.info.generation,
                ErrorCode::Unavailable,
                "invalid workspace authority binding",
            )?;
            valid_id(&workspace.head.revision.revision)?;
            valid_hash(&workspace.head.revision.sha256)?;
            require(
                self.revisions
                    .get(&revision_key(id, &workspace.head.revision.revision))
                    .is_some_and(|revision| revision.reference == workspace.head.revision),
                ErrorCode::Unavailable,
                "workspace head not indexed",
            )?;
        }
        for (key, entry) in &self.revisions {
            let (workspace, revision) = key
                .split_once(':')
                .ok_or_else(|| fail(ErrorCode::Unavailable, "invalid revision index key"))?;
            valid_id(workspace)?;
            valid_id(revision)?;
            valid_hash(&entry.reference.sha256)?;
            require(
                self.workspaces.contains_key(workspace)
                    && revision == entry.reference.revision
                    && entry.generation <= self.info.generation,
                ErrorCode::Unavailable,
                "invalid revision index",
            )?;
        }
        for (key, record) in &self.grants {
            let grant = &record.grant;
            require(
                key == &grant_key(&grant.device_id, &grant.workspace_id)
                    && self.devices.contains_key(&grant.device_id)
                    && self.workspaces.contains_key(&grant.workspace_id)
                    && record.generation <= self.info.generation,
                ErrorCode::Unavailable,
                "invalid grant binding",
            )?;
            valid_scopes(&grant.read, true)?;
            valid_scopes(&grant.write, true)?;
        }
        for (id, lease) in &self.leases {
            valid_id(id)?;
            valid_scopes(&lease.scopes, false)?;
            require(
                id == &lease.token.lease_id
                    && lease.token.fence <= self.fence
                    && lease.token.epoch == self.info.epoch
                    && self.devices.contains_key(&lease.holder)
                    && self.workspaces.contains_key(&lease.workspace_id),
                ErrorCode::Unavailable,
                "invalid lease state",
            )?;
        }
        for (id, upload) in &self.uploads {
            valid_id(id)?;
            valid_path(&upload.path)?;
            require(
                id == &upload.upload_id && self.devices.contains_key(&upload.prepared_by),
                ErrorCode::Unavailable,
                "invalid prepared upload identity",
            )?;
            vault::scoped_version(workspace(self, &upload.workspace_id)?, &upload.version)?;
        }
        for (key, request) in &self.requests {
            let (device, id) = key
                .split_once(':')
                .ok_or_else(|| fail(ErrorCode::Unavailable, "invalid request index"))?;
            valid_id(device)?;
            valid_id(id)?;
            valid_hash(&request.hash)?;
            require(
                self.devices.contains_key(device),
                ErrorCode::Unavailable,
                "request actor not enrolled",
            )?;
        }
        for (id, worker) in &self.workers {
            valid_id(id)?;
            valid_id(&worker.advertisement.incarnation)?;
            require(
                id == &worker.advertisement.worker_id && self.devices.contains_key(id),
                ErrorCode::Unavailable,
                "invalid worker identity",
            )?;
        }
        require(
            self.worker_incarnations
                .values()
                .map(BTreeSet::len)
                .sum::<usize>()
                <= MAX_REQUESTS,
            ErrorCode::Capacity,
            "worker incarnation history capacity reached",
        )?;
        for (worker, incarnations) in &self.worker_incarnations {
            require(
                self.workers.contains_key(worker),
                ErrorCode::Unavailable,
                "incarnation history has no enrolled worker",
            )?;
            for incarnation in incarnations {
                valid_id(incarnation)?;
            }
            require(
                incarnations.contains(&self.workers[worker].advertisement.incarnation),
                ErrorCode::Unavailable,
                "current worker incarnation missing from history",
            )?;
        }
        for (id, job) in &self.jobs {
            valid_id(id)?;
            require(
                id == &job.record.job_id
                    && self.devices.contains_key(&job.record.submitted_by)
                    && self.workspaces.contains_key(&job.record.workspace_id)
                    && job.record.attempts.len() <= MAX_ATTEMPTS,
                ErrorCode::Unavailable,
                "invalid job record",
            )?;
            valid_scopes(&job.record.output_selectors, true)?;
            for attempt in &job.record.attempts {
                valid_id(&attempt.binding.attempt_id)?;
                valid_id(&attempt.binding.worker_id)?;
                valid_id(&attempt.binding.worker_incarnation)?;
                require(
                    attempt.binding.job_id == *id,
                    ErrorCode::Unavailable,
                    "attempt/job mismatch",
                )?;
            }
        }
        for (key, log) in &self.logs {
            let parts: Vec<_> = key.split(':').collect();
            require(
                parts.len() == 3 && matches!(parts[2], "stdout" | "stderr"),
                ErrorCode::Unavailable,
                "invalid log identity",
            )?;
            valid_id(parts[0])?;
            valid_id(parts[1])?;
            require(
                log.length <= MAX_LOG_BYTES && log.chunks.len() <= 4096,
                ErrorCode::Capacity,
                "log capacity exceeded",
            )?;
            let mut offset = 0;
            for chunk in &log.chunks {
                valid_id(&chunk.id)?;
                valid_hash(&chunk.sha256)?;
                require(
                    chunk.offset == offset && chunk.size <= MAX_LOG_CHUNK as u64,
                    ErrorCode::Unavailable,
                    "invalid log chunk",
                )?;
                offset += chunk.size;
            }
            require(
                offset == log.length,
                ErrorCode::Unavailable,
                "log length mismatch",
            )?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct Live {
    pub state: State,
    pub leases: BTreeMap<String, Instant>,
    pub attempts: BTreeMap<String, Instant>,
    pub workers: BTreeMap<String, Instant>,
    /// Bounded replay observations, never part of the durable business snapshot.
    pub observations: BTreeMap<String, Observation>,
    pub poisoned: bool,
}
impl Live {
    pub fn new(state: State) -> Self {
        Self {
            state,
            leases: BTreeMap::new(),
            attempts: BTreeMap::new(),
            workers: BTreeMap::new(),
            observations: BTreeMap::new(),
            poisoned: false,
        }
    }
}

#[derive(Clone)]
pub(super) struct Observation {
    pub hash: String,
    pub expires: Instant,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    sha256: String,
    state: State,
}

pub(super) fn persist(root: &Path, state: &State) -> Result<()> {
    state.validate()?;
    let canonical = serde_json::to_vec(state)?;
    require(
        canonical.len() <= MAX_STATE_BYTES - 128,
        ErrorCode::Capacity,
        "authority state exceeds 64 MiB; no records were discarded",
    )?;
    let bytes = serde_json::to_vec(&Envelope {
        sha256: hash(&canonical),
        state: state.clone(),
    })?;
    require(
        bytes.len() <= MAX_STATE_BYTES,
        ErrorCode::Capacity,
        "authority state exceeds 64 MiB",
    )?;
    let temporary = root.join(format!("state-{}.tmp", new_id()));
    vault::write_new(&temporary, &bytes)?;
    std::fs::rename(&temporary, root.join("state.json"))?;
    crate::files::sync_directory(root)?;
    Ok(())
}

pub(super) fn load(root: &Path) -> Result<State> {
    let bytes = vault::read_bounded(&root.join("state.json"), MAX_STATE_BYTES)?;
    let envelope: Envelope = serde_json::from_slice(&bytes).map_err(|_| {
        fail(
            ErrorCode::Unavailable,
            "authority state corrupt; preserve it for recovery, never reset",
        )
    })?;
    require(
        hash(&serde_json::to_vec(&envelope.state)?) == envelope.sha256,
        ErrorCode::Unavailable,
        "authority state checksum mismatch; preserve it for recovery",
    )?;
    Ok(envelope.state)
}
