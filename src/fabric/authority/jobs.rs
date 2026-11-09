use super::*;
use state::{LogChunk, StoredJob};

impl Authority {
    pub(super) fn authorize_submitter(&self, state: &State, job: &JobRecord) -> Result<()> {
        let device = state
            .devices
            .get(&job.submitted_by)
            .ok_or_else(|| fail(ErrorCode::Forbidden, "job submitter no longer enrolled"))?;
        let actor = Actor::authenticated(device.device_id.clone(), device.key_generation);
        authenticate(state, &actor)
            .map_err(|_| fail(ErrorCode::Forbidden, "job submitter is revoked"))?;
        require(
            can_submit(state, &actor, &job.workspace_id)
                && has_scopes(state, &actor, &job.workspace_id, &job.output_selectors)
                && job
                    .inputs
                    .iter()
                    .all(|input| has_path(state, &actor, &job.workspace_id, &input.path, false)),
            ErrorCode::Forbidden,
            "job submitter no longer has required input/output grants",
        )
    }

    pub(super) fn active_job<'a>(
        &self,
        live: &'a Live,
        actor: &Actor,
        binding: &AttemptBinding,
    ) -> Result<&'a StoredJob> {
        let job = bound_job(&live.state, actor, binding)?;
        let current = job.record.attempts.last().ok_or_else(|| {
            fail(
                ErrorCode::Unavailable,
                "required authority invariant is missing",
            )
        })?;
        require(
            current.binding == *binding
                && attempt_active(current)
                && !job.record.cancel_requested
                && live
                    .attempts
                    .get(&binding.attempt_id)
                    .is_some_and(|deadline| *deadline > Instant::now()),
            ErrorCode::Conflict,
            "attempt is expired, cancelled or superseded",
        )?;
        current_worker(live, actor, binding)?;
        Ok(job)
    }

    pub(super) fn authorize_job_control(
        &self,
        state: &State,
        actor: &Actor,
        request: &ControlRequest,
    ) -> Result<()> {
        use ControlRequest::*;
        match request {
            AdvertiseWorker { advertisement, .. } => {
                worker_actor(state, actor, &advertisement.worker_id)
            }
            ClaimJob { worker_id, .. } => worker_actor(state, actor, worker_id),
            ListWorkers => require(
                owner(state, actor)
                    || state.devices[actor.device_id()].role == DeviceRole::Worker
                    || state.grants.values().any(|grant| {
                        grant.grant.device_id == actor.device_id() && grant.grant.submit_jobs
                    }),
                ErrorCode::Forbidden,
                "worker discovery requires owner, worker or job grant",
            ),
            SubmitJob { job } => {
                workspace(state, &job.workspace_id)?;
                require(
                    can_submit(state, actor, &job.workspace_id),
                    ErrorCode::Forbidden,
                    "job submission grant required",
                )
            }
            ExplainPlacement { job_id } | JobStatus { job_id } | ReadLog { job_id, .. } => {
                let job = &state
                    .jobs
                    .get(job_id)
                    .ok_or_else(|| fail(ErrorCode::NotFound, "job not found"))?
                    .record;
                require(
                    visible(state, actor, job),
                    ErrorCode::Forbidden,
                    "job is not visible to this device",
                )
            }
            CancelJob { job_id, .. } | RetryJob { job_id, .. } => {
                let job = &state
                    .jobs
                    .get(job_id)
                    .ok_or_else(|| fail(ErrorCode::NotFound, "job not found"))?
                    .record;
                require(
                    owner(state, actor)
                        || job.submitted_by == actor.device_id()
                            && can_submit(state, actor, &job.workspace_id),
                    ErrorCode::Forbidden,
                    "job control requires owner or current submitter grant",
                )
            }
            RenewAttempt { attempt, .. }
            | FinishAttempt { attempt, .. }
            | AppendLog { attempt, .. } => {
                bound_job(state, actor, attempt)?;
                Ok(())
            }
            ListJobs { .. } => Ok(()),
            _ => Err(fail(ErrorCode::Invalid, "unsupported control operation")),
        }
    }

    pub(super) fn dispatch_job(
        &self,
        live: &mut Live,
        actor: &Actor,
        request: &ControlRequest,
    ) -> Result<ControlResponse> {
        use ControlRequest::*;
        match request {
            AdvertiseWorker { advertisement, .. } => {
                validate_advertisement(&live.state, advertisement)?;
                if live
                    .state
                    .workers
                    .get(&advertisement.worker_id)
                    .is_none_or(|worker| {
                        worker.advertisement.incarnation != advertisement.incarnation
                    })
                {
                    let previous = live
                        .state
                        .workers
                        .get(&advertisement.worker_id)
                        .map(|worker| worker.advertisement.incarnation.clone());
                    let history = live
                        .state
                        .worker_incarnations
                        .entry(advertisement.worker_id.clone())
                        .or_default();
                    if let Some(previous) = previous {
                        history.insert(previous);
                    }
                    require(
                        !history.contains(&advertisement.incarnation),
                        ErrorCode::Conflict,
                        "worker incarnation was retired; a new process identity is required",
                    )?;
                    history.insert(advertisement.incarnation.clone());
                }
                if let Some(previous) = live.state.workers.get(&advertisement.worker_id) {
                    if previous.advertisement.incarnation != advertisement.incarnation {
                        if let Some(binding) = previous.active_attempt.clone() {
                            abandon(
                                live,
                                &binding,
                                "worker process incarnation changed; manual retry required",
                            );
                        }
                    } else if previous.active_attempt.is_some() {
                        require(
                            serde_json::to_vec(&previous.advertisement.profiles)?
                                == serde_json::to_vec(&advertisement.profiles)?,
                            ErrorCode::Conflict,
                            "cannot change configured profiles during an active attempt",
                        )?;
                    }
                }
                let active_attempt = live
                    .state
                    .workers
                    .get(&advertisement.worker_id)
                    .and_then(|worker| worker.active_attempt.clone());
                let now = now_ms();
                let worker = WorkerRecord {
                    advertisement: advertisement.clone(),
                    observed_at_unix_ms: now,
                    eligible_until_unix_ms: now.saturating_add(DEFAULT_TTL_SECONDS * 1000),
                    active_attempt,
                };
                require(
                    live.state.workers.contains_key(&advertisement.worker_id)
                        || live.state.workers.len() < MAX_WORKERS,
                    ErrorCode::Capacity,
                    "worker capacity reached",
                )?;
                live.state
                    .workers
                    .insert(advertisement.worker_id.clone(), worker.clone());
                live.workers.insert(
                    advertisement.worker_id.clone(),
                    Instant::now() + Duration::from_secs(DEFAULT_TTL_SECONDS),
                );
                Ok(ControlResponse::Worker { worker })
            }
            ListWorkers => Ok(ControlResponse::Workers {
                workers: live
                    .state
                    .workers
                    .values()
                    .map(|worker| {
                        let mut worker = worker.clone();
                        if !owner(&live.state, actor)
                            && worker.advertisement.worker_id != actor.device_id()
                        {
                            worker.advertisement.cached_files.clear();
                        }
                        if live
                            .workers
                            .get(&worker.advertisement.worker_id)
                            .is_none_or(|deadline| *deadline <= Instant::now())
                        {
                            worker.eligible_until_unix_ms = 0;
                        }
                        worker
                    })
                    .collect(),
            }),
            SubmitJob { job } => {
                require(
                    live.state.jobs.len() < MAX_JOBS,
                    ErrorCode::Capacity,
                    "job capacity reached",
                )?;
                self.validate_job(live, actor, job)?;
                let mut record = JobRecord {
                    job_id: new_id(),
                    submitted_by: actor.device_id().into(),
                    workspace_id: job.workspace_id.clone(),
                    base: job.base.clone(),
                    profile: job.profile.clone(),
                    inputs: job.inputs.clone(),
                    output_selectors: job.output_selectors.clone(),
                    resources: job.resources,
                    timeout_seconds: job.timeout_seconds,
                    required_worker: job.required_worker.clone(),
                    output_policy: job.output_policy,
                    state: JobState::Queued,
                    created_at_unix_ms: now_ms(),
                    cancel_requested: false,
                    decision: None,
                    attempts: Vec::new(),
                };
                record.decision = Some(self.placement(live, &record)?);
                live.state.jobs.insert(
                    record.job_id.clone(),
                    StoredJob {
                        record: record.clone(),
                        prompt: job.prompt.clone(),
                    },
                );
                Ok(ControlResponse::Job { job: record })
            }
            ExplainPlacement { job_id } => {
                let job = &live.state.jobs[job_id].record;
                let decision = if job.state == JobState::Queued {
                    self.placement(live, job)?
                } else {
                    job.decision.clone().unwrap_or(self.placement(live, job)?)
                };
                Ok(ControlResponse::Placement { decision })
            }
            ClaimJob {
                worker_id,
                incarnation,
                ..
            } => {
                valid_id(incarnation)?;
                let worker = live.state.workers.get(worker_id).ok_or_else(|| {
                    fail(ErrorCode::Conflict, "worker must advertise before claiming")
                })?;
                require(
                    worker.advertisement.incarnation == *incarnation
                        && live
                            .workers
                            .get(worker_id)
                            .is_some_and(|deadline| *deadline > Instant::now()),
                    ErrorCode::Conflict,
                    "worker advertisement expired or incarnation changed",
                )?;
                require(
                    worker.active_attempt.is_none(),
                    ErrorCode::Conflict,
                    "worker already owns an active attempt",
                )?;
                let mut queue: Vec<_> = live
                    .state
                    .jobs
                    .values()
                    .filter(|job| {
                        job.record.state == JobState::Queued && !job.record.cancel_requested
                    })
                    .map(|job| (job.record.created_at_unix_ms, job.record.job_id.clone()))
                    .collect();
                queue.sort();
                for (_, id) in queue {
                    let record = live.state.jobs[&id].record.clone();
                    let decision = self.placement(live, &record)?;
                    live.state
                        .jobs
                        .get_mut(&id)
                        .ok_or_else(|| {
                            fail(
                                ErrorCode::Unavailable,
                                "required authority invariant is missing",
                            )
                        })?
                        .record
                        .decision = Some(decision.clone());
                    if decision.selected_worker.as_deref() != Some(worker_id) {
                        continue;
                    }
                    require(
                        record.attempts.len() < MAX_ATTEMPTS,
                        ErrorCode::Capacity,
                        "job attempt capacity reached",
                    )?;
                    self.authorize_submitter(&live.state, &record)?;
                    let lease = if record.output_selectors.is_empty() {
                        None
                    } else {
                        Some(control::acquire(
                            live,
                            actor,
                            &record.workspace_id,
                            &record.output_selectors,
                            DEFAULT_TTL_SECONDS,
                        )?)
                    };
                    let binding = AttemptBinding {
                        job_id: id.clone(),
                        attempt_id: new_id(),
                        worker_id: worker_id.clone(),
                        worker_incarnation: incarnation.clone(),
                    };
                    let now = now_ms();
                    let attempt = AttemptRecord {
                        binding: binding.clone(),
                        state: AttemptState::Claimed,
                        lease: lease.as_ref().map(|lease| lease.token.clone()),
                        claimed_at_unix_ms: now,
                        heartbeat_at_unix_ms: now,
                        finished_at_unix_ms: None,
                        run: None,
                        prepared_outputs: Vec::new(),
                        publication: None,
                        detail: None,
                    };
                    let stored = live.state.jobs.get_mut(&id).ok_or_else(|| {
                        fail(
                            ErrorCode::Unavailable,
                            "required authority invariant is missing",
                        )
                    })?;
                    stored.record.state = JobState::Running;
                    stored.record.attempts.push(attempt);
                    live.state
                        .workers
                        .get_mut(worker_id)
                        .ok_or_else(|| {
                            fail(
                                ErrorCode::Unavailable,
                                "required authority invariant is missing",
                            )
                        })?
                        .active_attempt = Some(binding.clone());
                    live.attempts.insert(
                        binding.attempt_id.clone(),
                        Instant::now() + Duration::from_secs(DEFAULT_TTL_SECONDS),
                    );
                    return Ok(ControlResponse::Claim {
                        claimed: Some(claimed(live, &live.state.jobs[&id], &binding)?),
                    });
                }
                Ok(ControlResponse::Claim { claimed: None })
            }
            RenewAttempt {
                attempt,
                lease,
                ttl_seconds,
                ..
            } => {
                let duration = ttl(*ttl_seconds)?;
                let job = bound_job(&live.state, actor, attempt)?;
                let current = job.record.attempts.last().ok_or_else(|| {
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
                if job.record.cancel_requested {
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
                self.authorize_submitter(&live.state, &job.record)?;
                require(
                    current.lease.as_ref() == lease.as_ref(),
                    ErrorCode::Conflict,
                    "heartbeat lease token mismatch",
                )?;
                let workspace = job.record.workspace_id.clone();
                let renewed = if let Some(token) = lease {
                    live_lease(live, actor, &workspace, token, None)?;
                    Some(control::renew(live, &token.lease_id, *ttl_seconds)?)
                } else {
                    None
                };
                live.attempts
                    .insert(attempt.attempt_id.clone(), Instant::now() + duration);
                let now = now_ms();
                let current = live
                    .state
                    .jobs
                    .get_mut(&attempt.job_id)
                    .ok_or_else(|| {
                        fail(
                            ErrorCode::Unavailable,
                            "required authority invariant is missing",
                        )
                    })?
                    .record
                    .attempts
                    .last_mut()
                    .ok_or_else(|| {
                        fail(
                            ErrorCode::Unavailable,
                            "required authority invariant is missing",
                        )
                    })?;
                if current.state == AttemptState::Claimed {
                    current.state = AttemptState::Running;
                }
                current.heartbeat_at_unix_ms = now;
                let state = current.state;
                if let Some(worker) = live.state.workers.get_mut(&attempt.worker_id) {
                    worker.observed_at_unix_ms = now;
                    worker.eligible_until_unix_ms = now.saturating_add(ttl_seconds * 1000);
                }
                live.workers
                    .insert(attempt.worker_id.clone(), Instant::now() + duration);
                Ok(ControlResponse::Heartbeat {
                    heartbeat: AttemptHeartbeat {
                        attempt: attempt.clone(),
                        state,
                        lease: renewed,
                        cancel_requested: false,
                    },
                })
            }
            FinishAttempt {
                attempt,
                lease,
                run,
                upload_ids,
                ..
            } => {
                let stored = bound_job(&live.state, actor, attempt)?;
                require(
                    stored.record.attempts.last().is_some_and(|current| {
                        current.binding == *attempt
                            && matches!(
                                current.state,
                                AttemptState::Claimed | AttemptState::Running
                            )
                    }),
                    ErrorCode::Conflict,
                    "attempt already finished, expired or superseded; inspect job status",
                )?;
                current_worker(live, actor, attempt)?;
                require(
                    live.attempts
                        .get(&attempt.attempt_id)
                        .is_some_and(|deadline| *deadline > Instant::now()),
                    ErrorCode::Conflict,
                    "attempt heartbeat expired",
                )?;
                let job = stored.record.clone();
                if !job.cancel_requested {
                    self.authorize_submitter(&live.state, &job)?;
                    require(
                        job.attempts
                            .last()
                            .ok_or_else(|| {
                                fail(
                                    ErrorCode::Unavailable,
                                    "required authority invariant is missing",
                                )
                            })?
                            .lease
                            .as_ref()
                            == lease.as_ref(),
                        ErrorCode::Conflict,
                        "finish lease token mismatch",
                    )?;
                    if let Some(token) = lease {
                        live_lease(live, actor, &job.workspace_id, token, None)?;
                    }
                }
                validate_run(live, &job, attempt, run)?;
                let mut prepared = Vec::new();
                let mut seen = BTreeSet::new();
                for id in upload_ids {
                    require(
                        seen.insert(id),
                        ErrorCode::Invalid,
                        "duplicate output upload ID",
                    )?;
                    let upload =
                        live.state.uploads.get(id).ok_or_else(|| {
                            fail(ErrorCode::NotFound, "output upload not prepared")
                        })?;
                    require(
                        upload.attempt.as_ref() == Some(attempt)
                            && upload.prepared_by == actor.device_id()
                            && upload.workspace_id == job.workspace_id
                            && run.output_files.iter().any(|file| {
                                file.path == upload.path
                                    && file.sha256 == upload.version.sha256
                                    && file.size == upload.version.size
                            }),
                        ErrorCode::Forbidden,
                        "prepared output differs from actual reported attempt outputs",
                    )?;
                    prepared.push(upload.clone());
                }
                if run.status == "succeeded"
                    && job.output_policy == OutputPolicy::Publish
                    && !job.cancel_requested
                {
                    require(
                        prepared.len() == run.output_files.len(),
                        ErrorCode::Invalid,
                        "successful publish policy requires every actual allowed output prepared",
                    )?;
                }
                let terminal = if job.cancel_requested {
                    AttemptState::Cancelled
                } else {
                    run_state(&run.status)?
                };
                let pending_publication = terminal == AttemptState::Succeeded
                    && job.output_policy == OutputPolicy::Publish
                    && !prepared.is_empty();
                let record = &mut live
                    .state
                    .jobs
                    .get_mut(&attempt.job_id)
                    .ok_or_else(|| {
                        fail(
                            ErrorCode::Unavailable,
                            "required authority invariant is missing",
                        )
                    })?
                    .record;
                record.state = if pending_publication {
                    JobState::Running
                } else {
                    match terminal {
                        AttemptState::Succeeded => JobState::Succeeded,
                        AttemptState::Cancelled => JobState::Cancelled,
                        AttemptState::TimedOut => JobState::TimedOut,
                        _ => JobState::Failed,
                    }
                };
                let current = record.attempts.last_mut().ok_or_else(|| {
                    fail(
                        ErrorCode::Unavailable,
                        "required authority invariant is missing",
                    )
                })?;
                current.state = terminal;
                current.run = Some(run.clone());
                current.prepared_outputs = prepared;
                current.finished_at_unix_ms = Some(now_ms());
                if !pending_publication {
                    let token = current.lease.take();
                    if let Some(token) = token {
                        control::release(live, &token.lease_id);
                    }
                    release_worker(live, attempt);
                }
                Ok(ControlResponse::Job {
                    job: live.state.jobs[&attempt.job_id].record.clone(),
                })
            }
            CancelJob { job_id, .. } => {
                let job = &mut live
                    .state
                    .jobs
                    .get_mut(job_id)
                    .ok_or_else(|| {
                        fail(
                            ErrorCode::Unavailable,
                            "required authority invariant is missing",
                        )
                    })?
                    .record;
                let active = job
                    .attempts
                    .last()
                    .filter(|attempt| attempt_active(attempt))
                    .map(|attempt| {
                        (
                            attempt.binding.clone(),
                            attempt.state,
                            attempt.lease.clone(),
                        )
                    });
                require(
                    job.state == JobState::Queued || active.is_some() || job.cancel_requested,
                    ErrorCode::Conflict,
                    "job already terminal",
                )?;
                job.cancel_requested = true;
                job.state = if active.is_some() {
                    JobState::CancelRequested
                } else {
                    JobState::Cancelled
                };
                if let Some((binding, state, token)) = active {
                    if let Some(token) = token {
                        control::release(live, &token.lease_id);
                    }
                    if state == AttemptState::Succeeded {
                        let record = &mut live
                            .state
                            .jobs
                            .get_mut(job_id)
                            .ok_or_else(|| {
                                fail(
                                    ErrorCode::Unavailable,
                                    "required authority invariant is missing",
                                )
                            })?
                            .record;
                        record.state = JobState::Cancelled;
                        let attempt = record.attempts.last_mut().ok_or_else(|| {
                            fail(
                                ErrorCode::Unavailable,
                                "required authority invariant is missing",
                            )
                        })?;
                        attempt.state = AttemptState::Cancelled;
                        attempt.lease = None;
                        release_worker(live, &binding);
                    }
                }
                Ok(ControlResponse::Job {
                    job: live.state.jobs[job_id].record.clone(),
                })
            }
            RetryJob {
                job_id,
                expected_attempt_id,
                ..
            } => {
                let job = &live.state.jobs[job_id].record;
                require(
                    matches!(
                        job.state,
                        JobState::Failed
                            | JobState::Cancelled
                            | JobState::TimedOut
                            | JobState::Abandoned
                    ),
                    ErrorCode::Conflict,
                    "manual retry requires a terminal unsuccessful job",
                )?;
                require(
                    job.attempts.last().is_some_and(|attempt| {
                        attempt.binding.attempt_id == *expected_attempt_id
                            && !attempt_active(attempt)
                            && attempt.publication.is_none()
                    }),
                    ErrorCode::Conflict,
                    "retry base attempt differs from last terminal attempt",
                )?;
                require(
                    job.attempts.len() < MAX_ATTEMPTS,
                    ErrorCode::Capacity,
                    "job attempt capacity reached",
                )?;
                self.authorize_submitter(&live.state, job)?;
                let job = &mut live
                    .state
                    .jobs
                    .get_mut(job_id)
                    .ok_or_else(|| {
                        fail(
                            ErrorCode::Unavailable,
                            "required authority invariant is missing",
                        )
                    })?
                    .record;
                job.state = JobState::Queued;
                job.cancel_requested = false;
                let mut record = job.clone();
                record.decision = Some(self.placement(live, &record)?);
                live.state
                    .jobs
                    .get_mut(job_id)
                    .ok_or_else(|| {
                        fail(
                            ErrorCode::Unavailable,
                            "required authority invariant is missing",
                        )
                    })?
                    .record = record.clone();
                Ok(ControlResponse::Job { job: record })
            }
            JobStatus { job_id } => Ok(ControlResponse::Job {
                job: live.state.jobs[job_id].record.clone(),
            }),
            ListJobs { workspace_id } => Ok(ControlResponse::Jobs {
                jobs: live
                    .state
                    .jobs
                    .values()
                    .filter(|job| {
                        visible(&live.state, actor, &job.record)
                            && workspace_id
                                .as_ref()
                                .is_none_or(|id| *id == job.record.workspace_id)
                    })
                    .map(|job| job.record.clone())
                    .collect(),
            }),
            AppendLog {
                request_id,
                attempt,
                stream,
                offset,
                data_base64,
                truncated,
            } => {
                let stored = bound_job(&live.state, actor, attempt)?;
                require(
                    stored.record.attempts.last().is_some_and(|current| {
                        current.binding == *attempt
                            && matches!(
                                current.state,
                                AttemptState::Claimed | AttemptState::Running
                            )
                    }),
                    ErrorCode::Conflict,
                    "log append requires current running attempt",
                )?;
                current_worker(live, actor, attempt)?;
                require(
                    live.attempts
                        .get(&attempt.attempt_id)
                        .is_some_and(|deadline| *deadline > Instant::now()),
                    ErrorCode::Conflict,
                    "attempt heartbeat expired",
                )?;
                let bytes = STANDARD
                    .decode(data_base64)
                    .map_err(|_| fail(ErrorCode::Invalid, "invalid log chunk base64"))?;
                require(
                    bytes.len() <= MAX_LOG_CHUNK,
                    ErrorCode::Capacity,
                    "log chunk exceeds 64 KiB",
                )?;
                let key = log_key(&attempt.job_id, &attempt.attempt_id, *stream);
                let log = live.state.logs.entry(key).or_default();
                require(
                    log.length == *offset,
                    ErrorCode::Conflict,
                    "log append offset is not the exact next offset",
                )?;
                require(
                    log.length + bytes.len() as u64 <= MAX_LOG_BYTES && log.chunks.len() < 4096,
                    ErrorCode::Capacity,
                    "log stream exceeds bounded capacity",
                )?;
                if !bytes.is_empty() {
                    let chunk = LogChunk {
                        id: new_id(),
                        offset: *offset,
                        size: bytes.len() as u64,
                        sha256: hash(&bytes),
                    };
                    vault::write_new(
                        &log_path(
                            &self.root,
                            &attempt.job_id,
                            &attempt.attempt_id,
                            *stream,
                            &chunk.id,
                        ),
                        &bytes,
                    )?;
                    log.length += chunk.size;
                    log.chunks.push(chunk);
                }
                log.truncated |= *truncated;
                Ok(control::ack(live, request_id))
            }
            ReadLog {
                job_id,
                attempt_id,
                stream,
                offset,
                max_bytes,
            } => {
                valid_id(attempt_id)?;
                require(
                    (1..=MAX_LOG_CHUNK as u32).contains(max_bytes),
                    ErrorCode::Invalid,
                    "log page must be 1–65,536 bytes",
                )?;
                let attempt = live.state.jobs[job_id]
                    .record
                    .attempts
                    .iter()
                    .find(|attempt| attempt.binding.attempt_id == *attempt_id)
                    .ok_or_else(|| fail(ErrorCode::NotFound, "attempt not found"))?;
                let default = state::LogState::default();
                let log = live
                    .state
                    .logs
                    .get(&log_key(job_id, attempt_id, *stream))
                    .unwrap_or(&default);
                require(
                    *offset <= log.length,
                    ErrorCode::Invalid,
                    "log offset exceeds stored length",
                )?;
                let mut bytes = Vec::new();
                for chunk in &log.chunks {
                    if chunk.offset + chunk.size <= *offset {
                        continue;
                    }
                    let payload = vault::read_bounded(
                        &log_path(&self.root, job_id, attempt_id, *stream, &chunk.id),
                        MAX_LOG_CHUNK,
                    )?;
                    require(
                        payload.len() as u64 == chunk.size && hash(&payload) == chunk.sha256,
                        ErrorCode::Unavailable,
                        "retained log chunk integrity failed",
                    )?;
                    let start = offset.saturating_sub(chunk.offset) as usize;
                    let count = (payload.len() - start).min(*max_bytes as usize - bytes.len());
                    bytes.extend_from_slice(&payload[start..start + count]);
                    if bytes.len() == *max_bytes as usize {
                        break;
                    }
                }
                let next_offset = offset + bytes.len() as u64;
                Ok(ControlResponse::Log {
                    page: LogPage {
                        offset: *offset,
                        next_offset,
                        data_base64: STANDARD.encode(bytes),
                        truncated: log.truncated,
                        eof: next_offset == log.length
                            && (attempt.run.is_some() || !attempt_active(attempt)),
                    },
                })
            }
            _ => Err(fail(ErrorCode::Invalid, "unsupported job operation")),
        }
    }

    fn validate_job(&self, live: &Live, actor: &Actor, job: &JobRequest) -> Result<()> {
        require(
            workspace(&live.state, &job.workspace_id)?.head == job.base,
            ErrorCode::Conflict,
            "job output base is not current",
        )?;
        valid_profile(&job.profile)?;
        valid_scopes(&job.output_selectors, true)?;
        require(
            job.inputs.len() <= crate::workspace::contract::MAX_ENTRIES
                && (1..=86_400).contains(&job.timeout_seconds)
                && job.resources.cpu_millis > 0
                && job.resources.memory_bytes > 0,
            ErrorCode::Invalid,
            "invalid task input count, resource request or deadline",
        )?;
        require(
            job.prompt
                .as_ref()
                .is_none_or(|prompt| prompt.len() <= 1024 * 1024),
            ErrorCode::Capacity,
            "task prompt exceeds 1 MiB",
        )?;
        require(
            job.output_policy != OutputPolicy::Publish || !job.output_selectors.is_empty(),
            ErrorCode::Invalid,
            "publish policy requires explicit output selectors",
        )?;
        require(
            has_scopes(&live.state, actor, &job.workspace_id, &job.output_selectors),
            ErrorCode::Forbidden,
            "job outputs exceed current write grant",
        )?;
        if let Some(worker) = &job.required_worker {
            valid_id(worker)?;
        }
        let mut paths = BTreeSet::new();
        for input in &job.inputs {
            valid_path(&input.path)?;
            require(
                paths.insert(input.path.clone()),
                ErrorCode::Invalid,
                "duplicate task input path",
            )?;
            require(
                has_path(&live.state, actor, &job.workspace_id, &input.path, false),
                ErrorCode::Forbidden,
                "job input exceeds current read grant",
            )?;
            let revision = self.revision(&live.state, &job.workspace_id, &input.revision)?;
            require(
                revision.files.get(&input.path) == Some(&input.version),
                ErrorCode::Conflict,
                "task input is not its exact committed revision/version",
            )?;
        }
        crate::files::validate_workspace_paths(paths.iter())
            .map_err(|_| fail(ErrorCode::Invalid, "task input paths collide"))?;
        Ok(())
    }

    fn placement(&self, live: &Live, job: &JobRecord) -> Result<LocalityDecision> {
        let mut candidates = Vec::new();
        let authorization = self.authorize_submitter(&live.state, job).is_ok();
        for worker in live.state.workers.values() {
            let ad = &worker.advertisement;
            let mut reasons = Vec::new();
            if live.state.devices.get(&ad.worker_id).is_none_or(|device| {
                device.revoked || !matches!(device.role, DeviceRole::Worker | DeviceRole::Owner)
            }) {
                reasons.push("worker enrollment inactive".into());
            }
            if live
                .workers
                .get(&ad.worker_id)
                .is_none_or(|deadline| *deadline <= Instant::now())
            {
                reasons.push("worker advertisement expired".into());
            }
            if worker.active_attempt.is_some() {
                reasons.push("worker already has an active attempt".into());
            }
            if job
                .required_worker
                .as_ref()
                .is_some_and(|id| *id != ad.worker_id)
            {
                reasons.push("manual worker constraint".into());
            }
            let profile = ad
                .profiles
                .iter()
                .find(|profile| profile.name == job.profile);
            if profile.is_none() {
                reasons.push("named owner profile unavailable".into());
            }
            if !job.output_selectors.is_empty()
                && profile.is_some_and(|profile| {
                    profile.permission != crate::execution::contract::PermissionMode::WorkspaceWrite
                })
            {
                reasons.push("profile is read-only".into());
            }
            if ad.resources.cpu_millis < job.resources.cpu_millis
                || ad.resources.memory_bytes < job.resources.memory_bytes
            {
                reasons.push("insufficient advertised resources".into());
            }
            if !authorization {
                reasons.push("submitter authorization changed".into());
            }
            if live.state.leases.values().any(|lease| {
                lease.workspace_id == job.workspace_id
                    && lease.scopes.iter().any(|held| {
                        job.output_selectors
                            .iter()
                            .any(|scope| overlaps(held, scope))
                    })
            }) {
                reasons.push("output scope is leased".into());
            }
            let mut unique = BTreeSet::new();
            let mut missing = 0u64;
            for input in &job.inputs {
                if !unique.insert((input.version.sha256.clone(), input.version.size)) {
                    continue;
                }
                if !ad.cached_files.iter().any(|cached| {
                    cached.workspace_id == job.workspace_id
                        && cached.version.sha256 == input.version.sha256
                        && cached.version.size == input.version.size
                }) {
                    missing = missing.checked_add(input.version.size).ok_or_else(|| {
                        fail(ErrorCode::Capacity, "selected input byte total overflow")
                    })?;
                }
            }
            candidates.push(WorkerCandidate {
                worker_id: ad.worker_id.clone(),
                incarnation: ad.incarnation.clone(),
                eligible: reasons.is_empty(),
                missing_bytes: missing,
                reasons,
            });
        }
        let selected = candidates
            .iter()
            .filter(|candidate| candidate.eligible)
            .min_by_key(|candidate| (candidate.missing_bytes, candidate.worker_id.clone()))
            .map(|candidate| candidate.worker_id.clone());
        let reason = match &selected {
            Some(worker) => format!(
                "minimum missing selected bytes; deterministic worker-ID tie break: {worker}"
            ),
            None => "no eligible worker; task remains queued without automatic execution".into(),
        };
        Ok(LocalityDecision {
            selected_worker: selected,
            candidates,
            reason,
            decided_at_unix_ms: now_ms(),
        })
    }
}

fn valid_profile(name: &str) -> Result<()> {
    require(
        !name.is_empty()
            && name.len() <= 63
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
        ErrorCode::Invalid,
        "profile must be a short owner-configured identifier",
    )
}
fn worker_actor(state: &State, actor: &Actor, worker: &str) -> Result<()> {
    valid_id(worker)?;
    require(
        actor.device_id() == worker
            && matches!(
                state.devices[actor.device_id()].role,
                DeviceRole::Worker | DeviceRole::Owner
            ),
        ErrorCode::Forbidden,
        "only the enrolled worker may advertise or claim for itself",
    )
}
fn visible(state: &State, actor: &Actor, job: &JobRecord) -> bool {
    owner(state, actor)
        || job.submitted_by == actor.device_id()
            && (can_submit(state, actor, &job.workspace_id)
                || can_catalog(state, actor, &job.workspace_id))
        || job
            .attempts
            .iter()
            .any(|attempt| attempt.binding.worker_id == actor.device_id())
}

pub(super) fn bound_job<'a>(
    state: &'a State,
    actor: &Actor,
    binding: &AttemptBinding,
) -> Result<&'a StoredJob> {
    valid_id(&binding.job_id)?;
    valid_id(&binding.attempt_id)?;
    valid_id(&binding.worker_id)?;
    valid_id(&binding.worker_incarnation)?;
    require(
        binding.worker_id == actor.device_id(),
        ErrorCode::Forbidden,
        "attempt is assigned to another worker",
    )?;
    let job = state
        .jobs
        .get(&binding.job_id)
        .ok_or_else(|| fail(ErrorCode::NotFound, "job not found"))?;
    require(
        job.record
            .attempts
            .iter()
            .any(|attempt| attempt.binding == *binding),
        ErrorCode::Conflict,
        "attempt/incarnation does not match durable assignment",
    )?;
    Ok(job)
}

fn current_worker(live: &Live, actor: &Actor, binding: &AttemptBinding) -> Result<()> {
    worker_actor(&live.state, actor, &binding.worker_id)?;
    require(
        live.state
            .workers
            .get(&binding.worker_id)
            .is_some_and(|worker| {
                worker.advertisement.incarnation == binding.worker_incarnation
                    && worker.active_attempt.as_ref() == Some(binding)
            }),
        ErrorCode::Conflict,
        "worker incarnation or active claim replaced",
    )
}

pub(super) fn claimed(
    live: &Live,
    stored: &StoredJob,
    binding: &AttemptBinding,
) -> Result<ClaimedJob> {
    let attempt = stored
        .record
        .attempts
        .last()
        .ok_or_else(|| fail(ErrorCode::Conflict, "attempt missing"))?;
    let lease = attempt
        .lease
        .as_ref()
        .map(|token| {
            live.state
                .leases
                .get(&token.lease_id)
                .map(|lease| lease_view(live, lease))
                .ok_or_else(|| fail(ErrorCode::Conflict, "claim lease no longer active"))
        })
        .transpose()?;
    Ok(ClaimedJob {
        job: stored.record.clone(),
        attempt: binding.clone(),
        lease,
        prompt: stored.prompt.clone(),
    })
}

pub(super) fn release_worker(live: &mut Live, binding: &AttemptBinding) {
    if let Some(worker) = live.state.workers.get_mut(&binding.worker_id)
        && worker.active_attempt.as_ref() == Some(binding)
    {
        worker.active_attempt = None;
    }
    live.attempts.remove(&binding.attempt_id);
}

pub(super) fn abandon(live: &mut Live, binding: &AttemptBinding, detail: &str) {
    if let Some(job) = live.state.jobs.get_mut(&binding.job_id)
        && let Some(attempt) = job
            .record
            .attempts
            .iter_mut()
            .find(|attempt| attempt.binding == *binding)
    {
        attempt.state = AttemptState::Abandoned;
        attempt.finished_at_unix_ms = Some(now_ms());
        attempt.detail = Some(detail.into());
        let lease = attempt.lease.take();
        job.record.state = JobState::Abandoned;
        if let Some(lease) = lease {
            control::release(live, &lease.lease_id);
        }
    }
    release_worker(live, binding);
}

fn validate_advertisement(state: &State, ad: &WorkerAdvertisement) -> Result<()> {
    valid_id(&ad.incarnation)?;
    valid_label(&ad.display_name)?;
    require(
        !ad.profiles.is_empty()
            && ad.profiles.len() <= 32
            && ad.cached_files.len() <= crate::workspace::contract::MAX_ENTRIES
            && ad.resources.cpu_millis > 0
            && ad.resources.memory_bytes > 0,
        ErrorCode::Invalid,
        "invalid worker profile, cache or resource bounds",
    )?;
    let mut profiles = BTreeSet::new();
    for profile in &ad.profiles {
        valid_profile(&profile.name)?;
        require(
            profiles.insert(&profile.name),
            ErrorCode::Invalid,
            "duplicate worker profile",
        )?;
    }
    for cached in &ad.cached_files {
        vault::scoped_version(workspace(state, &cached.workspace_id)?, &cached.version)?;
    }
    Ok(())
}

fn run_state(status: &str) -> Result<AttemptState> {
    match status {
        "succeeded" => Ok(AttemptState::Succeeded),
        "failed" => Ok(AttemptState::Failed),
        "cancelled" => Ok(AttemptState::Cancelled),
        "timed_out" => Ok(AttemptState::TimedOut),
        "protocol_failed" => Ok(AttemptState::ProtocolFailed),
        _ => Err(fail(
            ErrorCode::Invalid,
            "finish requires an actual terminal execution record",
        )),
    }
}

fn validate_run(
    live: &Live,
    job: &JobRecord,
    binding: &AttemptBinding,
    run: &crate::execution::contract::RunRecord,
) -> Result<()> {
    valid_id(&run.id)?;
    run_state(&run.status)?;
    require(
        run.format == 1 && !run.published && run.finished_at.is_some(),
        ErrorCode::Invalid,
        "finish requires an unpublished terminal format-1 run",
    )?;
    let profile = live.state.workers[&binding.worker_id]
        .advertisement
        .profiles
        .iter()
        .find(|profile| profile.name == job.profile)
        .ok_or_else(|| fail(ErrorCode::Conflict, "admitted profile disappeared"))?;
    require(
        profile.adapter == run.adapter,
        ErrorCode::Invalid,
        "run adapter differs from selected owner profile",
    )?;
    let mut paths = BTreeSet::new();
    for file in &run.input_files {
        valid_path(&file.path)?;
        valid_hash(&file.sha256)?;
        require(
            paths.insert(&file.path),
            ErrorCode::Invalid,
            "duplicate run input",
        )?;
    }
    if run.status == "succeeded" {
        require(
            run.exit_code == Some(0)
                && run.input_files.len() == job.inputs.len()
                && job.inputs.iter().all(|input| {
                    run.input_files.iter().any(|file| {
                        file.path == input.path
                            && file.sha256 == input.version.sha256
                            && file.size == input.version.size
                    })
                }),
            ErrorCode::Invalid,
            "successful run input copies/exit differ from admitted identities",
        )?;
    }
    let mut outputs = BTreeSet::new();
    for file in &run.output_files {
        valid_path(&file.path)?;
        valid_hash(&file.sha256)?;
        require(
            outputs.insert(&file.path)
                && job
                    .output_selectors
                    .iter()
                    .any(|scope| covers(scope, &file.path)),
            ErrorCode::Forbidden,
            "run output lies outside explicit selectors",
        )?;
    }
    Ok(())
}

fn log_key(job: &str, attempt: &str, stream: LogStream) -> String {
    format!("{job}:{attempt}:{}", stream_name(stream))
}
fn stream_name(stream: LogStream) -> &'static str {
    match stream {
        LogStream::Stdout => "stdout",
        LogStream::Stderr => "stderr",
    }
}
fn log_path(root: &Path, job: &str, attempt: &str, stream: LogStream, chunk: &str) -> PathBuf {
    root.join("logs")
        .join(job)
        .join(attempt)
        .join(stream_name(stream))
        .join(chunk)
}
