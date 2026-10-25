use super::*;
use crate::workspace::contract::{FORMAT_VERSION, MAX_ENTRIES, manifest_hash};

pub(super) fn request_id(request: &ControlRequest) -> Option<&str> {
    use ControlRequest::*;
    match request {
        EnrollDevice { request_id, .. }
        | RotateDeviceKey { request_id, .. }
        | RevokeDevice { request_id, .. }
        | SetGrant { request_id, .. }
        | RemoveGrant { request_id, .. }
        | CreateWorkspace { request_id, .. }
        | AcquireLease { request_id, .. }
        | RenewLease { request_id, .. }
        | ReleaseLease { request_id, .. }
        | AdvertiseWorker { request_id, .. }
        | ClaimJob { request_id, .. }
        | RenewAttempt { request_id, .. }
        | FinishAttempt { request_id, .. }
        | CancelJob { request_id, .. }
        | RetryJob { request_id, .. }
        | AppendLog { request_id, .. } => Some(request_id),
        Publish { publication } => Some(&publication.context.request_id),
        Delete { context, .. } | Restore { context, .. } => Some(&context.request_id),
        SubmitJob { job } => Some(&job.request_id),
        _ => None,
    }
}

impl Authority {
    pub(super) fn authorize_control(
        &self,
        state: &State,
        actor: &Actor,
        request: &ControlRequest,
    ) -> Result<()> {
        use ControlRequest::*;
        match request {
            ListDevices
            | EnrollDevice { .. }
            | RotateDeviceKey { .. }
            | RevokeDevice { .. }
            | SetGrant { .. }
            | RemoveGrant { .. }
            | CreateWorkspace { .. } => require_owner(state, actor),
            GetDevice { device_id } => require(
                owner(state, actor) || device_id == actor.device_id(),
                ErrorCode::Forbidden,
                "device lookup requires owner or self",
            ),
            ListGrants { device_id, .. } => require(
                owner(state, actor)
                    || device_id
                        .as_deref()
                        .is_none_or(|id| id == actor.device_id()),
                ErrorCode::Forbidden,
                "cannot inspect another device's grants",
            ),
            Current { workspace_id } | Revision { workspace_id, .. } => {
                workspace(state, workspace_id)?;
                require(
                    can_catalog(state, actor, workspace_id),
                    ErrorCode::Forbidden,
                    "full catalog-read grant required",
                )
            }
            AcquireLease {
                workspace_id,
                scopes,
                ..
            } => {
                workspace(state, workspace_id)?;
                valid_scopes(scopes, false)?;
                require(
                    has_scopes(state, actor, workspace_id, scopes),
                    ErrorCode::Forbidden,
                    "requested lease exceeds current write grant",
                )
            }
            RenewLease { workspace_id, .. }
            | ReleaseLease { workspace_id, .. }
            | ListLeases { workspace_id } => {
                workspace(state, workspace_id)?;
                Ok(())
            }
            Publish { publication } => {
                self.authorize_publication(state, actor, &publication.context, &publication.changes)
            }
            Delete {
                context,
                path,
                expected,
            } => self.authorize_publication(
                state,
                actor,
                context,
                &[PublicationChange::Delete {
                    path: path.clone(),
                    expected: expected.clone(),
                }],
            ),
            Restore {
                context,
                path,
                from_revision,
                source_path,
                expected,
            } => self.authorize_publication(
                state,
                actor,
                context,
                &[PublicationChange::Restore {
                    path: path.clone(),
                    from_revision: from_revision.clone(),
                    source_path: source_path.clone(),
                    expected: expected.clone(),
                }],
            ),
            ListPrepared { workspace_id, .. } => {
                workspace(state, workspace_id)?;
                Ok(())
            }
            VerifyRetention { files, .. } => {
                require(
                    !files.is_empty() && files.len() <= 256,
                    ErrorCode::Invalid,
                    "select 1–256 exact retained files per verification",
                )?;
                for file in files {
                    valid_path(&file.path)?;
                    require(
                        self.can_retained(state, actor, file),
                        ErrorCode::Forbidden,
                        "retention verification exceeds current read authority",
                    )?;
                }
                Ok(())
            }
            Info | ListWorkspaces | PublicationStatus { .. } => Ok(()),
            _ => self.authorize_job_control(state, actor, request),
        }
    }

    fn authorize_publication(
        &self,
        state: &State,
        actor: &Actor,
        context: &PublicationContext,
        changes: &[PublicationChange],
    ) -> Result<()> {
        workspace(state, &context.workspace_id)?;
        require(
            !changes.is_empty() && changes.len() <= MAX_ENTRIES,
            ErrorCode::Invalid,
            "publication requires 1–20,000 explicit changes",
        )?;
        if let Some(attempt) = &context.attempt {
            let job = jobs::bound_job(state, actor, attempt)?;
            require(
                job.record.workspace_id == context.workspace_id
                    && job.record.output_policy == OutputPolicy::Publish,
                ErrorCode::Forbidden,
                "attempt has no publication grant",
            )?;
            self.authorize_submitter(state, &job.record)?;
            for change in changes {
                let path = change_path(change);
                valid_path(path)?;
                require(
                    job.record
                        .output_selectors
                        .iter()
                        .any(|scope| covers(scope, path)),
                    ErrorCode::Forbidden,
                    "output lies outside submitted selectors",
                )?;
            }
        } else {
            for change in changes {
                let path = change_path(change);
                valid_path(path)?;
                require(
                    has_path(state, actor, &context.workspace_id, path, true),
                    ErrorCode::Forbidden,
                    "publication exceeds current write grant",
                )?;
            }
        }
        Ok(())
    }

    pub(super) fn authorize_write(
        &self,
        live: &Live,
        actor: &Actor,
        workspace_id: &str,
        path: &str,
        attempt: Option<&AttemptBinding>,
    ) -> Result<()> {
        valid_path(path)?;
        if let Some(binding) = attempt {
            let job = self.active_job(live, actor, binding)?;
            require(
                job.record.workspace_id == workspace_id
                    && job
                        .record
                        .output_selectors
                        .iter()
                        .any(|scope| covers(scope, path)),
                ErrorCode::Forbidden,
                "write lies outside assigned job outputs",
            )?;
            self.authorize_submitter(&live.state, &job.record)
        } else {
            require(
                has_path(&live.state, actor, workspace_id, path, true),
                ErrorCode::Forbidden,
                "current path write grant required",
            )
        }
    }

    pub(super) fn authorize_read(
        &self,
        live: &Live,
        actor: &Actor,
        request: &FileRequest,
    ) -> Result<()> {
        valid_path(&request.path)?;
        if let Some(binding) = &request.attempt {
            let job = self.active_job(live, actor, binding)?;
            require(
                job.record.workspace_id == request.workspace_id
                    && job.record.inputs.iter().any(|input| {
                        input.path == request.path
                            && input.revision == request.revision
                            && input.version == request.expected
                    }),
                ErrorCode::Forbidden,
                "read is not an exact admitted job input",
            )?;
            self.authorize_submitter(&live.state, &job.record)
        } else {
            require(
                has_path(
                    &live.state,
                    actor,
                    &request.workspace_id,
                    &request.path,
                    false,
                ),
                ErrorCode::Forbidden,
                "current path read grant required",
            )
        }
    }

    fn can_retained(&self, state: &State, actor: &Actor, file: &RetainedFile) -> bool {
        if has_path(state, actor, &file.workspace_id, &file.path, false) {
            return true;
        }
        state.jobs.values().any(|stored| {
            stored.record.workspace_id == file.workspace_id
                && stored
                    .record
                    .attempts
                    .iter()
                    .any(|attempt| attempt.binding.worker_id == actor.device_id())
                && stored.record.inputs.iter().any(|input| {
                    input.path == file.path
                        && input.revision == file.revision
                        && input.version == file.version
                })
                && self.authorize_submitter(state, &stored.record).is_ok()
        })
    }

    pub(super) fn dispatch(
        &self,
        live: &mut Live,
        actor: &Actor,
        request: &ControlRequest,
    ) -> Result<ControlResponse> {
        use ControlRequest::*;
        match request {
            Info => Ok(ControlResponse::Info {
                info: live.state.info.clone(),
            }),
            ListDevices => Ok(ControlResponse::Devices {
                devices: live.state.devices.values().cloned().collect(),
            }),
            GetDevice { device_id } => Ok(ControlResponse::Device {
                device: live
                    .state
                    .devices
                    .get(device_id)
                    .cloned()
                    .ok_or_else(|| fail(ErrorCode::NotFound, "device not enrolled"))?,
            }),
            EnrollDevice {
                display_name,
                public_key,
                role,
                ..
            } => {
                valid_label(display_name)?;
                valid_key(public_key)?;
                require(
                    live.state.devices.len() < MAX_DEVICES,
                    ErrorCode::Capacity,
                    "enrollment capacity reached",
                )?;
                require(
                    !live
                        .state
                        .devices
                        .values()
                        .any(|device| device.public_key == *public_key),
                    ErrorCode::Conflict,
                    "key was already enrolled; rotate or use a new key",
                )?;
                let device = DeviceRecord {
                    device_id: new_id(),
                    display_name: display_name.clone(),
                    public_key: public_key.clone(),
                    key_generation: 1,
                    role: *role,
                    revoked: false,
                    created_at_unix_ms: now_ms(),
                    revoked_at_unix_ms: None,
                };
                live.state
                    .devices
                    .insert(device.device_id.clone(), device.clone());
                Ok(ControlResponse::Device { device })
            }
            RotateDeviceKey {
                device_id,
                expected_generation,
                public_key,
                ..
            } => {
                valid_key(public_key)?;
                require(
                    !live
                        .state
                        .devices
                        .values()
                        .any(|device| device.public_key == *public_key),
                    ErrorCode::Conflict,
                    "replacement key already used",
                )?;
                let device = live
                    .state
                    .devices
                    .get_mut(device_id)
                    .ok_or_else(|| fail(ErrorCode::NotFound, "device not enrolled"))?;
                require(
                    !device.revoked && device.key_generation == *expected_generation,
                    ErrorCode::Conflict,
                    "device revoked or generation stale",
                )?;
                device.key_generation = increment(device.key_generation)?;
                device.public_key = public_key.clone();
                let device = device.clone();
                invalidate(live, device_id, None, "device key rotated");
                Ok(ControlResponse::Device { device })
            }
            RevokeDevice {
                request_id,
                device_id,
            } => {
                let device = live
                    .state
                    .devices
                    .get(device_id)
                    .ok_or_else(|| fail(ErrorCode::NotFound, "device not enrolled"))?;
                if device.role == DeviceRole::Owner && !device.revoked {
                    require(
                        live.state.devices.values().any(|other| {
                            other.device_id != *device_id
                                && other.role == DeviceRole::Owner
                                && !other.revoked
                        }),
                        ErrorCode::Forbidden,
                        "cannot revoke the last active owner",
                    )?;
                }
                let device = live.state.devices.get_mut(device_id).ok_or_else(|| {
                    fail(
                        ErrorCode::Unavailable,
                        "required authority invariant is missing",
                    )
                })?;
                device.revoked = true;
                device.revoked_at_unix_ms = Some(now_ms());
                invalidate(live, device_id, None, "device revoked");
                Ok(ack(live, request_id))
            }
            ListGrants {
                device_id,
                workspace_id,
            } => Ok(ControlResponse::Grants {
                grants: live
                    .state
                    .grants
                    .values()
                    .filter(|record| {
                        (owner(&live.state, actor) || record.grant.device_id == actor.device_id())
                            && device_id
                                .as_ref()
                                .is_none_or(|id| *id == record.grant.device_id)
                            && workspace_id
                                .as_ref()
                                .is_none_or(|id| *id == record.grant.workspace_id)
                    })
                    .cloned()
                    .collect(),
            }),
            SetGrant { grant, .. } => {
                workspace(&live.state, &grant.workspace_id)?;
                require(
                    live.state
                        .devices
                        .get(&grant.device_id)
                        .is_some_and(|device| !device.revoked),
                    ErrorCode::NotFound,
                    "grant device missing or revoked",
                )?;
                valid_scopes(&grant.read, true)?;
                valid_scopes(&grant.write, true)?;
                let record = GrantRecord {
                    grant: grant.clone(),
                    generation: live.state.info.generation,
                };
                live.state.grants.insert(
                    grant_key(&grant.device_id, &grant.workspace_id),
                    record.clone(),
                );
                invalidate(
                    live,
                    &grant.device_id,
                    Some(&grant.workspace_id),
                    "workspace grant changed",
                );
                Ok(ControlResponse::Grant { grant: record })
            }
            RemoveGrant {
                request_id,
                device_id,
                workspace_id,
            } => {
                live.state
                    .grants
                    .remove(&grant_key(device_id, workspace_id));
                invalidate(
                    live,
                    device_id,
                    Some(workspace_id),
                    "workspace grant removed",
                );
                Ok(ack(live, request_id))
            }
            CreateWorkspace {
                name,
                import_source,
                ..
            } => {
                crate::workspace::contract::validate_name(name).map_err(|_| {
                    fail(
                        ErrorCode::Invalid,
                        "workspace name must be a portable lowercase identifier",
                    )
                })?;
                require(
                    live.state.workspaces.len() < MAX_WORKSPACES
                        && live.state.revisions.len() < MAX_REVISIONS,
                    ErrorCode::Capacity,
                    "workspace/revision capacity reached",
                )?;
                require(
                    !live
                        .state
                        .workspaces
                        .values()
                        .any(|workspace| workspace.name == *name),
                    ErrorCode::Conflict,
                    "workspace name already exists",
                )?;
                if let Some(source) = import_source {
                    validate_import(source)?;
                }
                let id = new_id();
                let manifest = Manifest {
                    format: FORMAT_VERSION,
                    workspace_id: id.clone(),
                    revision: new_id(),
                    parent: None,
                    files: BTreeMap::new(),
                };
                let reference = RevisionRef {
                    revision: manifest.revision.clone(),
                    sha256: manifest_hash(&manifest)?,
                };
                let record = WorkspaceRecord {
                    workspace_id: id.clone(),
                    name: name.clone(),
                    head: ManagedHead {
                        authority_id: live.state.info.authority_id.clone(),
                        workspace_id: id.clone(),
                        generation: live.state.info.generation,
                        revision: reference.clone(),
                    },
                    created_at_unix_ms: now_ms(),
                    import_source: import_source.clone(),
                };
                vault::write_manifest(&self.root, &record, &manifest)?;
                live.state.revisions.insert(
                    revision_key(&id, &reference.revision),
                    state::RevisionEntry {
                        reference,
                        generation: live.state.info.generation,
                    },
                );
                live.state.workspaces.insert(id, record.clone());
                Ok(ControlResponse::Workspace { workspace: record })
            }
            ListWorkspaces => Ok(ControlResponse::Workspaces {
                workspaces: live
                    .state
                    .workspaces
                    .values()
                    .filter(|workspace| can_catalog(&live.state, actor, &workspace.workspace_id))
                    .cloned()
                    .collect(),
            }),
            Current { workspace_id } => {
                let workspace = workspace(&live.state, workspace_id)?;
                Ok(ControlResponse::Catalog {
                    catalog: self.catalog(
                        &live.state,
                        workspace_id,
                        &workspace.head.revision,
                        true,
                    )?,
                })
            }
            Revision {
                workspace_id,
                revision,
            } => Ok(ControlResponse::Catalog {
                catalog: self.catalog(&live.state, workspace_id, revision, false)?,
            }),
            AcquireLease {
                workspace_id,
                scopes,
                ttl_seconds,
                ..
            } => Ok(ControlResponse::Lease {
                lease: acquire(live, actor, workspace_id, scopes, *ttl_seconds)?,
            }),
            RenewLease {
                workspace_id,
                lease,
                ttl_seconds,
                ..
            } => {
                let current = live_lease(live, actor, workspace_id, lease, None)?.clone();
                require(
                    has_scopes(&live.state, actor, workspace_id, &current.scopes),
                    ErrorCode::Forbidden,
                    "lease exceeds current grant",
                )?;
                Ok(ControlResponse::Lease {
                    lease: renew(live, &lease.lease_id, *ttl_seconds)?,
                })
            }
            ReleaseLease {
                request_id,
                workspace_id,
                lease,
            } => {
                valid_id(&lease.lease_id)?;
                if let Some(current) = live.state.leases.get(&lease.lease_id) {
                    require(
                        current.workspace_id == *workspace_id
                            && current.holder == actor.device_id()
                            && current.key_generation == actor.key_generation()
                            && current.token == *lease,
                        ErrorCode::Forbidden,
                        "cannot release another holder's lease",
                    )?;
                }
                release(live, &lease.lease_id);
                Ok(ack(live, request_id))
            }
            ListLeases { workspace_id } => Ok(ControlResponse::Leases {
                leases: live
                    .state
                    .leases
                    .values()
                    .filter(|lease| {
                        lease.workspace_id == *workspace_id
                            && (owner(&live.state, actor) || lease.holder == actor.device_id())
                    })
                    .map(|lease| lease_view(live, lease))
                    .collect(),
            }),
            Publish { publication } => self.publish(live, actor, publication),
            Delete {
                context,
                path,
                expected,
            } => self.publish(
                live,
                actor,
                &PublishRequest {
                    context: context.clone(),
                    changes: vec![PublicationChange::Delete {
                        path: path.clone(),
                        expected: expected.clone(),
                    }],
                },
            ),
            Restore {
                context,
                path,
                from_revision,
                source_path,
                expected,
            } => self.publish(
                live,
                actor,
                &PublishRequest {
                    context: context.clone(),
                    changes: vec![PublicationChange::Restore {
                        path: path.clone(),
                        from_revision: from_revision.clone(),
                        source_path: source_path.clone(),
                        expected: expected.clone(),
                    }],
                },
            ),
            PublicationStatus { request_id } => {
                valid_id(request_id)?;
                match live
                    .state
                    .requests
                    .get(&request_key(actor, request_id))
                    .map(|request| &request.reply)
                {
                    Some(Reply::Control(response)) => match response.as_ref() {
                        ControlResponse::Publication { receipt } => {
                            Ok(ControlResponse::Publication {
                                receipt: receipt.clone(),
                            })
                        }
                        _ => Err(fail(
                            ErrorCode::NotFound,
                            "request is not a committed publication",
                        )),
                    },
                    _ => Err(fail(
                        ErrorCode::NotFound,
                        "no committed publication receipt for this request",
                    )),
                }
            }
            ListPrepared {
                workspace_id,
                attempt,
            } => Ok(ControlResponse::Prepared {
                uploads: live
                    .state
                    .uploads
                    .values()
                    .filter(|upload| {
                        upload.workspace_id == *workspace_id
                            && (owner(&live.state, actor)
                                || upload.prepared_by == actor.device_id())
                            && attempt
                                .as_ref()
                                .is_none_or(|binding| upload.attempt.as_ref() == Some(binding))
                    })
                    .cloned()
                    .collect(),
            }),
            VerifyRetention { challenge, files } => {
                require(
                    (16..=256).contains(&challenge.len())
                        && challenge.bytes().all(|byte| byte.is_ascii_graphic()),
                    ErrorCode::Invalid,
                    "fresh retention challenge must be 16–256 printable ASCII bytes",
                )?;
                let mut receipts = Vec::with_capacity(files.len());
                for file in files {
                    let manifest =
                        self.revision(&live.state, &file.workspace_id, &file.revision)?;
                    require(
                        manifest.files.get(&file.path) == Some(&file.version),
                        ErrorCode::Conflict,
                        "retention request is not an exact committed file version",
                    )?;
                    vault::verified_blob(&self.root, &file.version)?;
                    receipts.push(retention_receipt(&live.state, file.clone(), &manifest)?);
                }
                let now = now_ms();
                Ok(ControlResponse::Retention {
                    verification: RetentionVerification {
                        challenge: challenge.clone(),
                        authority_id: live.state.info.authority_id.clone(),
                        vault_id: live.state.info.vault_id.clone(),
                        epoch: live.state.info.epoch,
                        verified_at_unix_ms: now,
                        valid_until_unix_ms: now.saturating_add(30_000),
                        receipts,
                    },
                })
            }
            _ => self.dispatch_job(live, actor, request),
        }
    }

    fn publish(
        &self,
        live: &mut Live,
        actor: &Actor,
        request: &PublishRequest,
    ) -> Result<ControlResponse> {
        let context = &request.context;
        self.authorize_publication(&live.state, actor, context, &request.changes)?;
        let workspace = workspace(&live.state, &context.workspace_id)?.clone();
        require(
            workspace.head == context.base,
            ErrorCode::Conflict,
            "publication base is stale; staged work retained",
        )?;
        live_lease(live, actor, &context.workspace_id, &context.lease, None)?;
        if let Some(binding) = &context.attempt {
            require(
                request
                    .changes
                    .iter()
                    .all(|change| matches!(change, PublicationChange::Put { .. })),
                ErrorCode::Forbidden,
                "job output publication permits only prepared output files; deletion/restoration needs separate explicit owner intent",
            )?;
            let job = self.active_job(live, actor, binding)?;
            let attempt = job.record.attempts.last().ok_or_else(|| {
                fail(
                    ErrorCode::Unavailable,
                    "required authority invariant is missing",
                )
            })?;
            require(
                attempt.state == AttemptState::Succeeded
                    && attempt
                        .run
                        .as_ref()
                        .is_some_and(|run| run.status == "succeeded" && !run.published)
                    && job.record.base == context.base
                    && attempt.lease.as_ref() == Some(&context.lease),
                ErrorCode::Conflict,
                "attempt must have a successful recorded finish before publication",
            )?;
        }
        require(
            live.state.revisions.len() < MAX_REVISIONS,
            ErrorCode::Capacity,
            "retained revision capacity reached",
        )?;
        let previous = self.revision(&live.state, &context.workspace_id, &context.base.revision)?;
        let mut manifest = Manifest {
            format: FORMAT_VERSION,
            workspace_id: context.workspace_id.clone(),
            revision: new_id(),
            parent: Some(context.base.revision.clone()),
            files: previous.files.clone(),
        };
        let mut paths = BTreeSet::new();
        let mut changes = Vec::new();
        for change in &request.changes {
            let path = change_path(change);
            require(
                paths.insert(path.to_owned()),
                ErrorCode::Invalid,
                "duplicate publication path",
            )?;
            self.authorize_write(
                live,
                actor,
                &context.workspace_id,
                path,
                context.attempt.as_ref(),
            )?;
            live_lease(
                live,
                actor,
                &context.workspace_id,
                &context.lease,
                Some(path),
            )?;
            let before = previous.files.get(path).cloned();
            let (after, kind) = match change {
                PublicationChange::Put {
                    upload_id,
                    expected,
                    ..
                } => {
                    require(
                        &before == expected,
                        ErrorCode::Conflict,
                        "put baseline differs from committed file",
                    )?;
                    let upload =
                        live.state.uploads.get(upload_id).ok_or_else(|| {
                            fail(ErrorCode::NotFound, "prepared upload not found")
                        })?;
                    require(
                        upload.prepared_by == actor.device_id()
                            && upload.workspace_id == context.workspace_id
                            && upload.path == path
                            && upload.attempt == context.attempt,
                        ErrorCode::Forbidden,
                        "prepared upload belongs to another actor, path or attempt",
                    )?;
                    if let Some(binding) = &context.attempt {
                        let job = &live.state.jobs[&binding.job_id].record;
                        require(
                            job.attempts
                                .last()
                                .ok_or_else(|| {
                                    fail(
                                        ErrorCode::Unavailable,
                                        "required authority invariant is missing",
                                    )
                                })?
                                .prepared_outputs
                                .iter()
                                .any(|prepared| prepared.upload_id == *upload_id),
                            ErrorCode::Forbidden,
                            "upload was not included in successful attempt finish",
                        )?;
                    }
                    vault::verified_blob(&self.root, &upload.version)?;
                    (Some(upload.version.clone()), ChangeKind::Put)
                }
                PublicationChange::Delete { expected, .. } => {
                    require(
                        before.as_ref() == Some(expected),
                        ErrorCode::Conflict,
                        "delete baseline differs from committed file",
                    )?;
                    (None, ChangeKind::Delete)
                }
                PublicationChange::Restore {
                    from_revision,
                    source_path,
                    expected,
                    ..
                } => {
                    valid_path(source_path)?;
                    require(
                        &before == expected,
                        ErrorCode::Conflict,
                        "restore target baseline differs from committed file",
                    )?;
                    require(
                        has_path(
                            &live.state,
                            actor,
                            &context.workspace_id,
                            source_path,
                            false,
                        ),
                        ErrorCode::Forbidden,
                        "restore requires read authority for the retained source",
                    )?;
                    let source =
                        self.revision(&live.state, &context.workspace_id, from_revision)?;
                    let version = source.files.get(source_path).cloned().ok_or_else(|| {
                        fail(
                            ErrorCode::NotFound,
                            "restore source absent from exact revision",
                        )
                    })?;
                    vault::verified_blob(&self.root, &version)?;
                    (Some(version), ChangeKind::Restore)
                }
            };
            if let Some(version) = &after {
                manifest.files.insert(path.into(), version.clone());
            } else {
                manifest.files.remove(path);
            }
            changes.push(ChangeReceipt {
                path: path.into(),
                previous: before,
                current: after,
                kind,
            });
        }
        let reference = vault::write_manifest(&self.root, &workspace, &manifest)?;
        // Full preparation is complete. Expiry is rechecked at final serialized admission.
        for path in &paths {
            live_lease(
                live,
                actor,
                &context.workspace_id,
                &context.lease,
                Some(path),
            )?;
        }
        let head = ManagedHead {
            authority_id: live.state.info.authority_id.clone(),
            workspace_id: context.workspace_id.clone(),
            generation: live.state.info.generation,
            revision: reference.clone(),
        };
        live.state.revisions.insert(
            revision_key(&context.workspace_id, &reference.revision),
            state::RevisionEntry {
                reference: reference.clone(),
                generation: live.state.info.generation,
            },
        );
        live.state
            .workspaces
            .get_mut(&context.workspace_id)
            .ok_or_else(|| {
                fail(
                    ErrorCode::Unavailable,
                    "required authority invariant is missing",
                )
            })?
            .head = head.clone();
        let mut retention = Vec::new();
        for change in &changes {
            if let Some(version) = &change.current {
                retention.push(retention_receipt(
                    &live.state,
                    RetainedFile {
                        workspace_id: context.workspace_id.clone(),
                        revision: reference.clone(),
                        path: change.path.clone(),
                        version: version.clone(),
                    },
                    &manifest,
                )?);
            } else if let Some(version) = &change.previous {
                retention.push(retention_receipt(
                    &live.state,
                    RetainedFile {
                        workspace_id: context.workspace_id.clone(),
                        revision: context.base.revision.clone(),
                        path: change.path.clone(),
                        version: version.clone(),
                    },
                    &previous,
                )?);
            }
        }
        let receipt = PublicationReceipt {
            publication_id: new_id(),
            request_id: context.request_id.clone(),
            authority_id: live.state.info.authority_id.clone(),
            workspace_id: context.workspace_id.clone(),
            committed_head: head,
            parent: context.base.revision.clone(),
            actor: actor.device_id().into(),
            lease: context.lease.clone(),
            attempt: context.attempt.clone(),
            changes,
            retention,
            committed_at_unix_ms: now_ms(),
        };
        if let Some(binding) = &context.attempt {
            let job = &mut live
                .state
                .jobs
                .get_mut(&binding.job_id)
                .ok_or_else(|| {
                    fail(
                        ErrorCode::Unavailable,
                        "required authority invariant is missing",
                    )
                })?
                .record;
            job.state = JobState::Succeeded;
            let attempt = job.attempts.last_mut().ok_or_else(|| {
                fail(
                    ErrorCode::Unavailable,
                    "required authority invariant is missing",
                )
            })?;
            attempt.publication = Some(receipt.clone());
            attempt.lease = None;
            release(live, &context.lease.lease_id);
            jobs::release_worker(live, binding);
        }
        Ok(ControlResponse::Publication { receipt })
    }
}

fn change_path(change: &PublicationChange) -> &str {
    match change {
        PublicationChange::Put { path, .. }
        | PublicationChange::Delete { path, .. }
        | PublicationChange::Restore { path, .. } => path,
    }
}
pub(super) fn ack(live: &Live, id: &str) -> ControlResponse {
    ControlResponse::Ack {
        request_id: id.into(),
        generation: live.state.info.generation,
    }
}
pub(super) fn release(live: &mut Live, id: &str) {
    live.state.leases.remove(id);
    live.leases.remove(id);
}

pub(super) fn acquire(
    live: &mut Live,
    actor: &Actor,
    workspace_id: &str,
    scopes: &[PathScope],
    seconds: u64,
) -> Result<WriteLease> {
    let duration = ttl(seconds)?;
    valid_scopes(scopes, false)?;
    require(
        live.state.leases.len() < MAX_LEASES,
        ErrorCode::Capacity,
        "active lease capacity reached",
    )?;
    require(
        !live.state.leases.values().any(|lease| {
            lease.workspace_id == workspace_id
                && live
                    .leases
                    .get(&lease.token.lease_id)
                    .is_some_and(|deadline| *deadline > Instant::now())
                && lease
                    .scopes
                    .iter()
                    .any(|existing| scopes.iter().any(|requested| overlaps(existing, requested)))
        }),
        ErrorCode::Conflict,
        "requested write scope overlaps an active lease",
    )?;
    live.state.fence = increment(live.state.fence)?;
    let now = now_ms();
    let lease = WriteLease {
        token: LeaseToken {
            lease_id: new_id(),
            fence: live.state.fence,
            epoch: live.state.info.epoch,
        },
        workspace_id: workspace_id.into(),
        holder: actor.device_id().into(),
        key_generation: actor.key_generation(),
        scopes: scopes.to_vec(),
        issued_at_unix_ms: now,
        expires_at_unix_ms: now.saturating_add(seconds * 1000),
        remaining_ms: seconds * 1000,
    };
    live.leases
        .insert(lease.token.lease_id.clone(), Instant::now() + duration);
    live.state
        .leases
        .insert(lease.token.lease_id.clone(), lease.clone());
    Ok(lease)
}

pub(super) fn renew(live: &mut Live, id: &str, seconds: u64) -> Result<WriteLease> {
    let duration = ttl(seconds)?;
    let lease = live
        .state
        .leases
        .get_mut(id)
        .ok_or_else(|| fail(ErrorCode::Conflict, "lease no longer active"))?;
    lease.expires_at_unix_ms = now_ms().saturating_add(seconds * 1000);
    lease.remaining_ms = seconds * 1000;
    live.leases.insert(id.into(), Instant::now() + duration);
    Ok(lease.clone())
}

fn invalidate(live: &mut Live, device: &str, workspace: Option<&str>, reason: &str) {
    let leases: Vec<_> = live
        .state
        .leases
        .values()
        .filter(|lease| {
            lease.holder == device && workspace.is_none_or(|id| id == lease.workspace_id)
        })
        .map(|lease| lease.token.lease_id.clone())
        .collect();
    for id in leases {
        release(live, &id);
    }
    let affected: Vec<_> = live
        .state
        .jobs
        .values()
        .filter(|stored| workspace.is_none_or(|id| id == stored.record.workspace_id))
        .filter_map(|stored| {
            stored
                .record
                .attempts
                .last()
                .filter(|attempt| {
                    attempt_active(attempt)
                        && (attempt.binding.worker_id == device
                            || stored.record.submitted_by == device)
                })
                .map(|attempt| attempt.binding.clone())
        })
        .collect();
    for binding in affected {
        jobs::abandon(live, &binding, reason);
    }
    if workspace.is_none() {
        if let Some(worker) = live.state.workers.get_mut(device) {
            worker.eligible_until_unix_ms = 0;
        }
        live.workers.remove(device);
    }
}

fn retention_receipt(
    state: &State,
    file: RetainedFile,
    manifest: &Manifest,
) -> Result<RetentionReceipt> {
    let entry = &state.revisions[&revision_key(&file.workspace_id, &file.revision.revision)];
    let recovery_reference = crate::workspace::contract::reference(
        &Snapshot {
            manifest: manifest.clone(),
            manifest_sha256: file.revision.sha256.clone(),
            head_etag: None,
        },
        &file.path,
    )?;
    Ok(RetentionReceipt {
        authority_id: state.info.authority_id.clone(),
        vault_id: state.info.vault_id.clone(),
        policy: RetentionPolicy::AppendOnlyNoGc,
        policy_version: state.info.retention_policy_version,
        committed_generation: entry.generation,
        file,
        recovery_reference,
    })
}

fn validate_import(source: &ImportSource) -> Result<()> {
    valid_id(&source.workspace_id)?;
    valid_id(&source.revision.revision)?;
    valid_hash(&source.revision.sha256)?;
    require(
        source.target_id.len() <= 8192,
        ErrorCode::Invalid,
        "import target identity too large",
    )?;
    let value: serde_json::Value = serde_json::from_str(&source.target_id).map_err(|_| {
        fail(
            ErrorCode::Invalid,
            "import target must be canonical credential-free JSON",
        )
    })?;
    let object = value
        .as_object()
        .ok_or_else(|| fail(ErrorCode::Invalid, "invalid import target"))?;
    require(
        object.len() == 3
            && ["endpoint", "bucket", "name"]
                .iter()
                .all(|field| object.get(*field).is_some_and(|value| value.is_string())),
        ErrorCode::Invalid,
        "import target permits endpoint, bucket and name only",
    )?;
    let endpoint = reqwest::Url::parse(object["endpoint"].as_str().ok_or_else(|| {
        fail(
            ErrorCode::Unavailable,
            "required authority invariant is missing",
        )
    })?)
    .map_err(|_| fail(ErrorCode::Invalid, "invalid import endpoint"))?;
    require(
        matches!(endpoint.scheme(), "https" | "http")
            && endpoint.username().is_empty()
            && endpoint.password().is_none()
            && endpoint.query().is_none()
            && endpoint.fragment().is_none(),
        ErrorCode::Invalid,
        "import endpoint must not contain credentials or query",
    )
}
