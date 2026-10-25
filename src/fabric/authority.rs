//! Single-process durable authority. The immutable vault has no destructive API.
//! One state replacement commits authorization, fences, heads and receipts together.
mod control;
mod jobs;
mod state;
#[cfg(test)]
mod tests;
mod vault;

use super::contract::*;
use crate::workspace::contract::{FileVersion, Manifest, RevisionRef, Snapshot};
use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};
use uuid::Uuid;

use state::{Live, Reply, RequestRecord, State};

const MAX_STATE_BYTES: usize = 64 * 1024 * 1024;
const MAX_CONTROL_BYTES: usize = 8 * 1024 * 1024;
const MAX_REQUESTS: usize = 20_000;
const MAX_DEVICES: usize = 1_024;
const MAX_WORKSPACES: usize = 128;
const MAX_LEASES: usize = 4_096;
const MAX_UPLOADS: usize = 20_000;
const MAX_REVISIONS: usize = 40_000;
const MAX_SCOPES: usize = 256;
const MAX_JOBS: usize = 256;
const MAX_ATTEMPTS: usize = 32;
const MAX_WORKERS: usize = 128;
const MAX_LOG_BYTES: u64 = 4 * 1024 * 1024;
const MAX_LOG_CHUNK: usize = 64 * 1024;
const DEFAULT_TTL_SECONDS: u64 = 60;
const MAX_TTL_SECONDS: u64 = 300;
const MAX_UPLOAD_BYTES: u64 = 83_886_080_000;
const MAX_OBSERVATIONS: usize = 1_024;
const OBSERVATION_SECONDS: u64 = 300;

pub struct Authority {
    root: PathBuf,
    _lock: File,
    inner: Mutex<Live>,
}

impl Authority {
    pub fn initialize(root: &Path, owner: BootstrapOwner) -> Result<Self> {
        Self::initialize_inner(root, owner).map_err(storage_error)
    }

    fn initialize_inner(root: &Path, owner: BootstrapOwner) -> Result<Self> {
        valid_id(&owner.device_id)?;
        valid_label(&owner.display_name)?;
        valid_key(&owner.public_key)?;
        let (root, lock) = vault::lock_root(root, true)?;
        require(
            std::fs::read_dir(&root)?
                .all(|entry| entry.is_ok_and(|entry| entry.file_name() == "lock")),
            ErrorCode::Conflict,
            "authority initialization requires an empty root; existing data is never reset",
        )?;
        let now = now_ms();
        let device = DeviceRecord {
            device_id: owner.device_id,
            display_name: owner.display_name,
            public_key: owner.public_key,
            key_generation: 1,
            role: DeviceRole::Owner,
            revoked: false,
            created_at_unix_ms: now,
            revoked_at_unix_ms: None,
        };
        let state = State::new(device);
        vault::private_directory(&root.join("vault"))?;
        vault::private_directory(&root.join("logs"))?;
        vault::write_new(&root.join(".maxio-fabric"), b"MaxIO managed authority v1\n")?;
        state::persist(&root, &state)?;
        Ok(Self {
            root,
            _lock: lock,
            inner: Mutex::new(Live::new(state)),
        })
    }

    pub fn open(root: &Path) -> Result<Self> {
        Self::open_inner(root).map_err(storage_error)
    }

    fn open_inner(root: &Path) -> Result<Self> {
        let (root, lock) = vault::lock_root(root, false)?;
        let mut state = state::load(&root)?;
        state.validate()?;
        // Additive recovery of the first checkpoint's already recorded incarnations.
        // This also ensures a retired process cannot reappear after an upgrade.
        for request in state.requests.values() {
            if let Reply::Control(response) = &request.reply
                && let ControlResponse::Worker { worker } = response.as_ref()
            {
                state
                    .worker_incarnations
                    .entry(worker.advertisement.worker_id.clone())
                    .or_default()
                    .insert(worker.advertisement.incarnation.clone());
            }
        }
        for worker in state.workers.values() {
            state
                .worker_incarnations
                .entry(worker.advertisement.worker_id.clone())
                .or_default()
                .insert(worker.advertisement.incarnation.clone());
        }
        for workspace in state.workspaces.values() {
            let entry = state
                .revisions
                .get(&revision_key(
                    &workspace.workspace_id,
                    &workspace.head.revision.revision,
                ))
                .ok_or_else(|| {
                    fail(
                        ErrorCode::Unavailable,
                        "current revision is absent from retained index",
                    )
                })?;
            require(
                entry.reference == workspace.head.revision,
                ErrorCode::Unavailable,
                "current revision index mismatch",
            )?;
            vault::manifest(&root, workspace, &entry.reference)?;
        }
        state.info.epoch = increment(state.info.epoch)?;
        state.info.generation = increment(state.info.generation)?;
        state.leases.clear();
        for worker in state.workers.values_mut() {
            worker.active_attempt = None;
            worker.eligible_until_unix_ms = 0;
        }
        for stored in state.jobs.values_mut() {
            for attempt in &mut stored.record.attempts {
                if attempt_active(attempt) {
                    attempt.state = AttemptState::Abandoned;
                    attempt.finished_at_unix_ms = Some(now_ms());
                    attempt.detail = Some(
                        "coordinator restarted; old authority expired; manual retry required"
                            .into(),
                    );
                    stored.record.state = JobState::Abandoned;
                }
            }
        }
        state::persist(&root, &state)?;
        Ok(Self {
            root,
            _lock: lock,
            inner: Mutex::new(Live::new(state)),
        })
    }

    pub fn info(&self) -> AuthorityInfo {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .state
            .info
            .clone()
    }

    pub fn device(&self, id: &str) -> Result<DeviceRecord> {
        valid_id(id)?;
        let inner = self.lock()?;
        inner
            .state
            .devices
            .get(id)
            .cloned()
            .ok_or_else(|| fail(ErrorCode::Unauthenticated, "device is not enrolled"))
    }

    pub fn control(&self, actor: &Actor, request: &ControlRequest) -> Result<ControlResponse> {
        self.control_inner(actor, request).map_err(storage_error)
    }

    fn control_inner(&self, actor: &Actor, request: &ControlRequest) -> Result<ControlResponse> {
        let bytes = serde_json::to_vec(request)?;
        require(
            bytes.len() <= MAX_CONTROL_BYTES,
            ErrorCode::Capacity,
            "control request exceeds 8 MiB",
        )?;
        let mut inner = self.lock()?;
        self.expire(&mut inner)?;
        authenticate(&inner.state, actor)?;
        inner
            .observations
            .retain(|_, observation| observation.expires > Instant::now());
        let request_id = control::request_id(request);
        let digest = hash(&bytes);
        if let Some(id) = request_id {
            valid_id(id)?;
            if let Some(previous) = inner.state.requests.get(&request_key(actor, id)) {
                require(
                    previous.hash == digest,
                    ErrorCode::Conflict,
                    "request ID was used with different contents",
                )?;
                let Reply::Control(response) = &previous.reply else {
                    return Err(fail(
                        ErrorCode::Conflict,
                        "request ID was used by another operation",
                    ));
                };
                self.authorize_control(&inner.state, actor, request)?;
                if matches!(
                    request,
                    ControlRequest::RenewLease { .. }
                        | ControlRequest::RenewAttempt { .. }
                        | ControlRequest::AdvertiseWorker { .. }
                ) || matches!(response.as_ref(), ControlResponse::Claim { claimed: None })
                {
                    return self.replay_observation(&inner, actor, request);
                }
                return self.replay_response(&inner, actor, response);
            }
            if let Some(previous) = inner.observations.get(&request_key(actor, id)) {
                require(
                    previous.hash == digest,
                    ErrorCode::Conflict,
                    "request ID was used with different observation contents",
                )?;
                self.authorize_control(&inner.state, actor, request)?;
                return self.replay_observation(&inner, actor, request);
            }
        }
        self.authorize_control(&inner.state, actor, request)?;
        let observation = is_observation(&inner.state, request);
        if request_id.is_some()
            && !observation
            && !matches!(request, ControlRequest::ClaimJob { .. })
        {
            require(
                inner.state.requests.len() < MAX_REQUESTS,
                ErrorCode::Capacity,
                "durable request capacity reached",
            )?;
        }
        let mut next = inner.clone();
        if request_id.is_some() && !observation {
            next.state.info.generation = increment(next.state.info.generation)?;
        }
        let response = self.dispatch(&mut next, actor, request)?;
        if let Some(id) = request_id {
            if matches!(response, ControlResponse::Claim { claimed: None }) {
                remember_observation(&mut inner, actor, id, digest);
                return Ok(response);
            }
            if observation {
                if matches!(request, ControlRequest::AdvertiseWorker { .. }) {
                    next.state.validate()?;
                    require(
                        serde_json::to_vec(&next.state)?.len() <= MAX_STATE_BYTES - 128,
                        ErrorCode::Capacity,
                        "live worker inventory would exceed bounded authority state",
                    )?;
                }
                remember_observation(&mut next, actor, id, digest);
                *inner = next;
                return Ok(response);
            }
            require(
                next.state.requests.len() < MAX_REQUESTS,
                ErrorCode::Capacity,
                "durable request capacity reached",
            )?;
            next.state.requests.insert(
                request_key(actor, id),
                RequestRecord {
                    hash: digest,
                    reply: Reply::Control(Box::new(response.clone())),
                },
            );
            self.commit(&mut inner, next)?;
        }
        Ok(response)
    }

    pub fn upload(
        &self,
        actor: &Actor,
        request: &UploadRequest,
        private_source: &Path,
    ) -> Result<PreparedUpload> {
        self.upload_inner(actor, request, private_source)
            .map_err(storage_error)
    }

    /// Admission before HTTP accepts a large body. This performs no mutation or I/O
    /// on the payload; upload repeats the same check after its immutable copy.
    pub fn check_upload(&self, actor: &Actor, request: &UploadRequest) -> Result<()> {
        let live = self.lock()?;
        self.validate_upload(&live, actor, request)
            .map_err(storage_error)
    }

    fn validate_upload(&self, live: &Live, actor: &Actor, request: &UploadRequest) -> Result<()> {
        valid_id(&request.request_id)?;
        valid_path(&request.path)?;
        valid_hash(&request.sha256)?;
        require(
            request.size <= MAX_UPLOAD_BYTES,
            ErrorCode::Capacity,
            "upload exceeds supported per-file limit",
        )?;
        authenticate(&live.state, actor)?;
        workspace(&live.state, &request.workspace_id)?;
        self.authorize_write(
            live,
            actor,
            &request.workspace_id,
            &request.path,
            request.attempt.as_ref(),
        )?;
        live_lease(
            live,
            actor,
            &request.workspace_id,
            &request.lease,
            Some(&request.path),
        )?;
        require(
            live.state
                .requests
                .contains_key(&request_key(actor, &request.request_id))
                || live.state.uploads.len() < MAX_UPLOADS
                    && live.state.requests.len() < MAX_REQUESTS,
            ErrorCode::Capacity,
            "prepared upload/request capacity reached",
        )?;
        Ok(())
    }

    fn upload_inner(
        &self,
        actor: &Actor,
        request: &UploadRequest,
        private_source: &Path,
    ) -> Result<PreparedUpload> {
        valid_id(&request.request_id)?;
        valid_path(&request.path)?;
        valid_hash(&request.sha256)?;
        require(
            request.size <= MAX_UPLOAD_BYTES,
            ErrorCode::Capacity,
            "upload exceeds supported per-file limit",
        )?;
        let digest = hash(&serde_json::to_vec(request)?);
        let workspace = {
            let mut inner = self.lock()?;
            self.expire(&mut inner)?;
            self.validate_upload(&inner, actor, request)?;
            if let Some(prior) = inner
                .state
                .requests
                .get(&request_key(actor, &request.request_id))
            {
                require(
                    prior.hash == digest,
                    ErrorCode::Conflict,
                    "request ID was used with different contents",
                )?;
                return match &prior.reply {
                    Reply::Upload(upload) => Ok(upload.as_ref().clone()),
                    _ => Err(fail(
                        ErrorCode::Conflict,
                        "request ID belongs to another operation",
                    )),
                };
            }
            live_lease(
                &inner,
                actor,
                &request.workspace_id,
                &request.lease,
                Some(&request.path),
            )?;
            require(
                inner.state.uploads.len() < MAX_UPLOADS
                    && inner.state.requests.len() < MAX_REQUESTS,
                ErrorCode::Capacity,
                "prepared upload/request capacity reached",
            )?;
            workspace(&inner.state, &request.workspace_id)?.clone()
        };
        let version = FileVersion {
            sha256: request.sha256.clone(),
            size: request.size,
            blob: format!("maxio-workspaces/{}/blobs/{}", workspace.name, new_id()),
        };
        // Payload I/O is outside the transaction; revocation and renewal stay responsive.
        vault::copy_blob(&self.root, &version, private_source)?;
        let mut inner = self.lock()?;
        self.expire(&mut inner)?;
        self.validate_upload(&inner, actor, request)?;
        if let Some(prior) = inner
            .state
            .requests
            .get(&request_key(actor, &request.request_id))
        {
            require(
                prior.hash == digest,
                ErrorCode::Conflict,
                "request ID was used with different contents",
            )?;
            return match &prior.reply {
                Reply::Upload(upload) => Ok(upload.as_ref().clone()),
                _ => Err(fail(
                    ErrorCode::Conflict,
                    "request ID belongs to another operation",
                )),
            };
        }
        require(
            inner.state.uploads.len() < MAX_UPLOADS && inner.state.requests.len() < MAX_REQUESTS,
            ErrorCode::Capacity,
            "prepared upload/request capacity reached",
        )?;
        let prepared = PreparedUpload {
            upload_id: new_id(),
            workspace_id: request.workspace_id.clone(),
            path: request.path.clone(),
            version,
            prepared_by: actor.device_id().into(),
            attempt: request.attempt.clone(),
        };
        let mut next = inner.clone();
        next.state.info.generation = increment(next.state.info.generation)?;
        next.state
            .uploads
            .insert(prepared.upload_id.clone(), prepared.clone());
        next.state.requests.insert(
            request_key(actor, &request.request_id),
            RequestRecord {
                hash: digest,
                reply: Reply::Upload(Box::new(prepared.clone())),
            },
        );
        self.commit(&mut inner, next)?;
        Ok(prepared)
    }

    pub fn read(&self, actor: &Actor, request: &FileRequest) -> Result<OpenedFile> {
        self.read_inner(actor, request).map_err(storage_error)
    }

    fn read_inner(&self, actor: &Actor, request: &FileRequest) -> Result<OpenedFile> {
        let version = {
            let mut inner = self.lock()?;
            self.expire(&mut inner)?;
            authenticate(&inner.state, actor)?;
            self.authorize_read(&inner, actor, request)?;
            let manifest = self.revision(&inner.state, &request.workspace_id, &request.revision)?;
            let version = manifest
                .files
                .get(&request.path)
                .ok_or_else(|| fail(ErrorCode::NotFound, "file is absent from exact revision"))?;
            require(
                version == &request.expected,
                ErrorCode::Conflict,
                "file version differs from requested identity",
            )?;
            version.clone()
        };
        // This is admission. A later revocation cannot recall an already admitted stream.
        let file = vault::verified_blob(&self.root, &version)?;
        Ok(OpenedFile { file, version })
    }

    fn lock(&self) -> Result<MutexGuard<'_, Live>> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| fail(ErrorCode::Unavailable, "authority state lock poisoned"))?;
        require(
            !inner.poisoned,
            ErrorCode::Unavailable,
            "authority persistence is uncertain; reopen required",
        )?;
        Ok(inner)
    }

    fn commit(&self, inner: &mut Live, next: Live) -> Result<()> {
        next.state.validate()?;
        if let Err(error) = state::persist(&self.root, &next.state) {
            // Capacity is established before any persistence I/O and leaves the
            // existing authority usable. Other failures have an uncertain outcome.
            if error
                .downcast_ref::<FabricError>()
                .is_some_and(|error| error.code == ErrorCode::Capacity)
            {
                return Err(error);
            }
            inner.poisoned = true;
            return Err(
                error.context("authority persistence uncertain; mutations stopped until reopen")
            );
        }
        *inner = next;
        Ok(())
    }

    fn expire(&self, inner: &mut Live) -> Result<()> {
        let mut next = inner.clone();
        let now = Instant::now();
        let dead: Vec<_> = next
            .state
            .leases
            .keys()
            .filter(|id| next.leases.get(*id).is_none_or(|deadline| *deadline <= now))
            .cloned()
            .collect();
        for id in &dead {
            next.state.leases.remove(id);
            next.leases.remove(id);
        }
        let mut changed = !dead.is_empty();
        let mut abandoned = Vec::new();
        for stored in next.state.jobs.values() {
            if let Some(attempt) = stored.record.attempts.last()
                && attempt_active(attempt)
                && (next
                    .attempts
                    .get(&attempt.binding.attempt_id)
                    .is_none_or(|deadline| *deadline <= now)
                    || attempt
                        .lease
                        .as_ref()
                        .is_some_and(|lease| !next.state.leases.contains_key(&lease.lease_id))
                        && !stored.record.cancel_requested)
            {
                abandoned.push(attempt.binding.clone());
            }
        }
        for binding in abandoned {
            jobs::abandon(
                &mut next,
                &binding,
                "worker heartbeat or write authority expired; manual retry required",
            );
            changed = true;
        }
        if changed {
            next.state.info.generation = increment(next.state.info.generation)?;
            self.commit(inner, next)?;
        }
        Ok(())
    }

    fn revision(
        &self,
        state: &State,
        workspace_id: &str,
        revision: &RevisionRef,
    ) -> Result<Manifest> {
        valid_id(workspace_id)?;
        valid_id(&revision.revision)?;
        valid_hash(&revision.sha256)?;
        let workspace = workspace(state, workspace_id)?;
        let entry = state
            .revisions
            .get(&revision_key(workspace_id, &revision.revision))
            .ok_or_else(|| {
                fail(
                    ErrorCode::NotFound,
                    "revision is not committed in this workspace",
                )
            })?;
        require(
            entry.reference == *revision,
            ErrorCode::Conflict,
            "revision hash does not match committed identity",
        )?;
        vault::manifest(&self.root, workspace, revision)
    }

    fn catalog(
        &self,
        state: &State,
        id: &str,
        revision: &RevisionRef,
        current: bool,
    ) -> Result<ManagedCatalog> {
        let manifest = self.revision(state, id, revision)?;
        Ok(ManagedCatalog {
            snapshot: Snapshot {
                manifest,
                manifest_sha256: revision.sha256.clone(),
                head_etag: None,
            },
            head: current.then(|| state.workspaces[id].head.clone()),
        })
    }

    fn replay_response(
        &self,
        inner: &Live,
        _actor: &Actor,
        response: &ControlResponse,
    ) -> Result<ControlResponse> {
        match response {
            ControlResponse::Lease { lease } => {
                let current = inner
                    .state
                    .leases
                    .get(&lease.token.lease_id)
                    .ok_or_else(|| {
                        fail(
                            ErrorCode::Conflict,
                            "original lease expired or was released; use a new request ID",
                        )
                    })?;
                Ok(ControlResponse::Lease {
                    lease: lease_view(inner, current),
                })
            }
            ControlResponse::Claim {
                claimed: Some(claimed),
            } => {
                let stored = inner
                    .state
                    .jobs
                    .get(&claimed.attempt.job_id)
                    .ok_or_else(|| fail(ErrorCode::NotFound, "original job is unavailable"))?;
                let attempt = stored.record.attempts.last().ok_or_else(|| {
                    fail(ErrorCode::Conflict, "original claim is no longer active")
                })?;
                require(
                    attempt.binding == claimed.attempt
                        && attempt_active(attempt)
                        && inner.attempts.contains_key(&attempt.binding.attempt_id),
                    ErrorCode::Conflict,
                    "original claim is no longer active; inspect job status",
                )?;
                Ok(ControlResponse::Claim {
                    claimed: Some(jobs::claimed(inner, stored, &claimed.attempt)?),
                })
            }
            _ => Ok(response.clone()),
        }
    }

    fn replay_observation(
        &self,
        live: &Live,
        actor: &Actor,
        request: &ControlRequest,
    ) -> Result<ControlResponse> {
        match request {
            ControlRequest::RenewLease {
                workspace_id,
                lease,
                ..
            } => {
                let current = live_lease(live, actor, workspace_id, lease, None)?;
                require(
                    has_scopes(&live.state, actor, workspace_id, &current.scopes),
                    ErrorCode::Forbidden,
                    "lease exceeds current grant",
                )?;
                Ok(ControlResponse::Lease {
                    lease: lease_view(live, current),
                })
            }
            ControlRequest::RenewAttempt { attempt, lease, .. } => {
                let stored = jobs::bound_job(&live.state, actor, attempt)?;
                let current = stored.record.attempts.last().ok_or_else(|| {
                    fail(
                        ErrorCode::Unavailable,
                        "required authority invariant is missing",
                    )
                })?;
                require(
                    current.binding == *attempt,
                    ErrorCode::Conflict,
                    "attempt superseded",
                )?;
                if stored.record.cancel_requested {
                    return Ok(ControlResponse::Heartbeat {
                        heartbeat: AttemptHeartbeat {
                            attempt: attempt.clone(),
                            state: current.state,
                            lease: None,
                            cancel_requested: true,
                        },
                    });
                }
                self.active_job(live, actor, attempt)?;
                self.authorize_submitter(&live.state, &stored.record)?;
                require(
                    current.lease.as_ref() == lease.as_ref(),
                    ErrorCode::Conflict,
                    "heartbeat lease token mismatch",
                )?;
                let renewed = lease
                    .as_ref()
                    .map(|token| {
                        live_lease(live, actor, &stored.record.workspace_id, token, None)
                            .map(|lease| lease_view(live, lease))
                    })
                    .transpose()?;
                Ok(ControlResponse::Heartbeat {
                    heartbeat: AttemptHeartbeat {
                        attempt: attempt.clone(),
                        state: current.state,
                        lease: renewed,
                        cancel_requested: false,
                    },
                })
            }
            ControlRequest::AdvertiseWorker { advertisement, .. } => {
                let current = live
                    .state
                    .workers
                    .get(&advertisement.worker_id)
                    .ok_or_else(|| {
                        fail(
                            ErrorCode::Conflict,
                            "worker advertisement no longer current",
                        )
                    })?;
                require(
                    current.advertisement.incarnation == advertisement.incarnation,
                    ErrorCode::Conflict,
                    "worker incarnation replaced; old advertisement cannot re-adopt it",
                )?;
                require(
                    live.workers
                        .get(&advertisement.worker_id)
                        .is_some_and(|deadline| *deadline > Instant::now()),
                    ErrorCode::Conflict,
                    "worker liveness expired; submit a fresh advertisement request",
                )?;
                Ok(ControlResponse::Worker {
                    worker: current.clone(),
                })
            }
            ControlRequest::ClaimJob {
                worker_id,
                incarnation,
                ..
            } => {
                require(
                    worker_id == actor.device_id()
                        && live.state.workers.get(worker_id).is_some_and(|worker| {
                            worker.advertisement.incarnation == *incarnation
                                && worker.active_attempt.is_none()
                        })
                        && live
                            .workers
                            .get(worker_id)
                            .is_some_and(|deadline| *deadline > Instant::now()),
                    ErrorCode::Conflict,
                    "empty claim observation no longer matches current worker state",
                )?;
                Ok(ControlResponse::Claim { claimed: None })
            }
            _ => Err(fail(
                ErrorCode::Conflict,
                "request ID belongs to a liveness observation",
            )),
        }
    }
}

fn is_observation(state: &State, request: &ControlRequest) -> bool {
    match request {
        ControlRequest::RenewLease { .. } | ControlRequest::RenewAttempt { .. } => true,
        ControlRequest::AdvertiseWorker { advertisement, .. } => state
            .workers
            .get(&advertisement.worker_id)
            .is_some_and(|worker| worker.advertisement.incarnation == advertisement.incarnation),
        _ => false,
    }
}

fn remember_observation(live: &mut Live, actor: &Actor, id: &str, digest: String) {
    while live.observations.len() >= MAX_OBSERVATIONS {
        if let Some(key) = live
            .observations
            .iter()
            .min_by_key(|(_, observation)| observation.expires)
            .map(|(key, _)| key.clone())
        {
            live.observations.remove(&key);
        } else {
            break;
        }
    }
    live.observations.insert(
        request_key(actor, id),
        state::Observation {
            hash: digest,
            expires: Instant::now() + Duration::from_secs(OBSERVATION_SECONDS),
        },
    );
}

fn fail(code: ErrorCode, message: impl Into<String>) -> anyhow::Error {
    FabricError {
        code,
        message: message.into(),
    }
    .into()
}
fn require(condition: bool, code: ErrorCode, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(fail(code, message))
    }
}
fn storage_error(error: anyhow::Error) -> anyhow::Error {
    if error.downcast_ref::<FabricError>().is_some() {
        error
    } else {
        fail(
            ErrorCode::Unavailable,
            format!("authority operation unavailable: {error:#}"),
        )
    }
}
fn new_id() -> String {
    Uuid::new_v4().to_string()
}
fn increment(value: u64) -> Result<u64> {
    value
        .checked_add(1)
        .ok_or_else(|| fail(ErrorCode::Capacity, "authority monotonic counter exhausted"))
}
fn now_ms() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn valid_id(value: &str) -> Result<()> {
    crate::workspace::contract::validate_id(value)
        .map_err(|_| fail(ErrorCode::Invalid, "invalid canonical UUID"))
}
fn valid_hash(value: &str) -> Result<()> {
    crate::workspace::contract::validate_hash(value)
        .map_err(|_| fail(ErrorCode::Invalid, "invalid SHA-256"))
}
fn valid_path(value: &str) -> Result<()> {
    crate::files::validate_workspace_relative(value)
        .map_err(|_| fail(ErrorCode::Invalid, "invalid portable logical path"))
}
fn valid_label(value: &str) -> Result<()> {
    require(
        !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control),
        ErrorCode::Invalid,
        "label must contain 1–128 printable bytes",
    )
}
fn valid_key(value: &str) -> Result<()> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| fail(ErrorCode::Invalid, "invalid public key encoding"))?;
    require(
        bytes.len() == 32 && STANDARD.encode(&bytes) == value,
        ErrorCode::Invalid,
        "public key must be canonical base64 Ed25519",
    )
}
fn request_key(actor: &Actor, id: &str) -> String {
    format!("{}:{id}", actor.device_id())
}
fn revision_key(workspace: &str, revision: &str) -> String {
    format!("{workspace}:{revision}")
}
fn grant_key(device: &str, workspace: &str) -> String {
    format!("{device}:{workspace}")
}
fn authenticate<'a>(state: &'a State, actor: &Actor) -> Result<&'a DeviceRecord> {
    let device = state
        .devices
        .get(actor.device_id())
        .ok_or_else(|| fail(ErrorCode::Unauthenticated, "device is not enrolled"))?;
    require(
        !device.revoked && device.key_generation == actor.key_generation(),
        ErrorCode::Unauthenticated,
        "device revoked or key generation replaced",
    )?;
    Ok(device)
}
fn owner(state: &State, actor: &Actor) -> bool {
    state.devices.get(actor.device_id()).is_some_and(|device| {
        !device.revoked
            && device.key_generation == actor.key_generation()
            && device.role == DeviceRole::Owner
    })
}
fn require_owner(state: &State, actor: &Actor) -> Result<()> {
    require(
        owner(state, actor),
        ErrorCode::Forbidden,
        "owner authorization required",
    )
}
fn workspace<'a>(state: &'a State, id: &str) -> Result<&'a WorkspaceRecord> {
    valid_id(id)?;
    state
        .workspaces
        .get(id)
        .ok_or_else(|| fail(ErrorCode::NotFound, "workspace is not registered"))
}
fn grant<'a>(state: &'a State, device: &str, workspace: &str) -> Option<&'a WorkspaceGrant> {
    state
        .grants
        .get(&grant_key(device, workspace))
        .map(|record| &record.grant)
}
fn valid_scopes(scopes: &[PathScope], empty: bool) -> Result<()> {
    require(
        (empty || !scopes.is_empty()) && scopes.len() <= MAX_SCOPES,
        ErrorCode::Invalid,
        "scope count must be within the supported bound",
    )?;
    for scope in scopes {
        match scope {
            PathScope::Workspace => {}
            PathScope::Exact { path } | PathScope::Tree { path } => valid_path(path)?,
        }
    }
    Ok(())
}
fn under(path: &str, parent: &str) -> bool {
    path == parent
        || path
            .strip_prefix(parent)
            .is_some_and(|suffix| suffix.starts_with('/'))
}
fn covers(scope: &PathScope, path: &str) -> bool {
    match scope {
        PathScope::Workspace => true,
        PathScope::Exact { path: exact } => path == exact,
        PathScope::Tree { path: tree } => under(path, tree),
    }
}
fn contains_scope(outer: &PathScope, inner: &PathScope) -> bool {
    match (outer, inner) {
        (PathScope::Workspace, _) => true,
        (_, PathScope::Workspace) => false,
        (PathScope::Exact { path: a }, PathScope::Exact { path: b }) => a == b,
        (
            PathScope::Tree { path: a },
            PathScope::Exact { path: b } | PathScope::Tree { path: b },
        ) => under(b, a),
        _ => false,
    }
}
fn overlaps(a: &PathScope, b: &PathScope) -> bool {
    contains_scope(a, b) || contains_scope(b, a)
}
fn has_path(state: &State, actor: &Actor, workspace: &str, path: &str, write: bool) -> bool {
    owner(state, actor)
        || grant(state, actor.device_id(), workspace).is_some_and(|grant| {
            (if write { &grant.write } else { &grant.read })
                .iter()
                .any(|scope| covers(scope, path))
        })
}
fn has_scopes(state: &State, actor: &Actor, workspace: &str, scopes: &[PathScope]) -> bool {
    owner(state, actor)
        || grant(state, actor.device_id(), workspace).is_some_and(|grant| {
            scopes.iter().all(|scope| {
                grant
                    .write
                    .iter()
                    .any(|allowed| contains_scope(allowed, scope))
            })
        })
}
fn can_catalog(state: &State, actor: &Actor, workspace: &str) -> bool {
    owner(state, actor)
        || grant(state, actor.device_id(), workspace).is_some_and(|grant| grant.catalog_read)
}
fn can_submit(state: &State, actor: &Actor, workspace: &str) -> bool {
    owner(state, actor)
        || grant(state, actor.device_id(), workspace).is_some_and(|grant| grant.submit_jobs)
}
fn ttl(seconds: u64) -> Result<Duration> {
    require(
        (1..=MAX_TTL_SECONDS).contains(&seconds),
        ErrorCode::Invalid,
        "lease/heartbeat TTL must be 1–300 seconds",
    )?;
    Ok(Duration::from_secs(seconds))
}
fn lease_view(live: &Live, lease: &WriteLease) -> WriteLease {
    let mut lease = lease.clone();
    lease.remaining_ms = live
        .leases
        .get(&lease.token.lease_id)
        .map(|deadline| {
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis()
                .min(u64::MAX as u128) as u64
        })
        .unwrap_or(0);
    lease
}
fn live_lease<'a>(
    live: &'a Live,
    actor: &Actor,
    workspace: &str,
    token: &LeaseToken,
    path: Option<&str>,
) -> Result<&'a WriteLease> {
    let lease = live.state.leases.get(&token.lease_id).ok_or_else(|| {
        fail(
            ErrorCode::Conflict,
            "write lease expired, released or revoked",
        )
    })?;
    require(
        lease.token == *token
            && token.epoch == live.state.info.epoch
            && lease.workspace_id == workspace
            && lease.holder == actor.device_id()
            && lease.key_generation == actor.key_generation()
            && live
                .leases
                .get(&token.lease_id)
                .is_some_and(|deadline| *deadline > Instant::now()),
        ErrorCode::Conflict,
        "write lease identity or fencing token is stale",
    )?;
    require(
        path.is_none_or(|path| lease.scopes.iter().any(|scope| covers(scope, path))),
        ErrorCode::Forbidden,
        "path lies outside write lease",
    )?;
    Ok(lease)
}
fn attempt_active(attempt: &AttemptRecord) -> bool {
    matches!(attempt.state, AttemptState::Claimed | AttemptState::Running)
        || attempt.state == AttemptState::Succeeded
            && attempt.publication.is_none()
            && attempt.lease.is_some()
}
