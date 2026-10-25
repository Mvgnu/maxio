use super::*;
use crate::execution::contract::{AdapterKind, PermissionMode, RunFile, RunRecord};
use std::io::Read;

struct Fixture {
    _directory: tempfile::TempDir,
    authority: Authority,
    owner: Actor,
    workspace: WorkspaceRecord,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let id = new_id();
        let authority = Authority::initialize(
            &directory.path().join("authority"),
            BootstrapOwner {
                device_id: id.clone(),
                display_name: "Owner".into(),
                public_key: STANDARD.encode([1u8; 32]),
            },
        )
        .unwrap();
        let owner = Actor::authenticated(id, 1);
        let workspace = match authority
            .control(
                &owner,
                &ControlRequest::CreateWorkspace {
                    request_id: new_id(),
                    name: "project".into(),
                    import_source: None,
                },
            )
            .unwrap()
        {
            ControlResponse::Workspace { workspace } => workspace,
            _ => panic!("workspace response"),
        };
        Self {
            _directory: directory,
            authority,
            owner,
            workspace,
        }
    }
    fn current(&self) -> ManagedCatalog {
        match self
            .authority
            .control(
                &self.owner,
                &ControlRequest::Current {
                    workspace_id: self.workspace.workspace_id.clone(),
                },
            )
            .unwrap()
        {
            ControlResponse::Catalog { catalog } => catalog,
            _ => panic!("catalog response"),
        }
    }
    fn lease(&self, actor: &Actor, scopes: Vec<PathScope>) -> WriteLease {
        match self
            .authority
            .control(
                actor,
                &ControlRequest::AcquireLease {
                    request_id: new_id(),
                    workspace_id: self.workspace.workspace_id.clone(),
                    scopes,
                    ttl_seconds: 60,
                },
            )
            .unwrap()
        {
            ControlResponse::Lease { lease } => lease,
            _ => panic!("lease response"),
        }
    }
    fn enroll(&self, byte: u8, role: DeviceRole) -> Actor {
        match self
            .authority
            .control(
                &self.owner,
                &ControlRequest::EnrollDevice {
                    request_id: new_id(),
                    display_name: format!("Device {byte}"),
                    public_key: STANDARD.encode([byte; 32]),
                    role,
                },
            )
            .unwrap()
        {
            ControlResponse::Device { device } => {
                Actor::authenticated(device.device_id, device.key_generation)
            }
            _ => panic!("device response"),
        }
    }
    fn upload(
        &self,
        actor: &Actor,
        lease: &WriteLease,
        path: &str,
        bytes: &[u8],
        attempt: Option<AttemptBinding>,
    ) -> PreparedUpload {
        let source = self._directory.path().join(new_id());
        std::fs::write(&source, bytes).unwrap();
        self.authority
            .upload(
                actor,
                &UploadRequest {
                    request_id: new_id(),
                    workspace_id: self.workspace.workspace_id.clone(),
                    path: path.into(),
                    sha256: hash(bytes),
                    size: bytes.len() as u64,
                    lease: lease.token.clone(),
                    attempt,
                },
                &source,
            )
            .unwrap()
    }
    fn put(
        &self,
        lease: &WriteLease,
        path: &str,
        bytes: &[u8],
    ) -> (PublishRequest, PublicationReceipt) {
        let catalog = self.current();
        let upload = self.upload(&self.owner, lease, path, bytes, None);
        let publication = PublishRequest {
            context: PublicationContext {
                request_id: new_id(),
                workspace_id: self.workspace.workspace_id.clone(),
                base: catalog.head.unwrap(),
                lease: lease.token.clone(),
                attempt: None,
            },
            changes: vec![PublicationChange::Put {
                path: path.into(),
                upload_id: upload.upload_id,
                expected: catalog.snapshot.manifest.files.get(path).cloned(),
            }],
        };
        let receipt = match self
            .authority
            .control(
                &self.owner,
                &ControlRequest::Publish {
                    publication: publication.clone(),
                },
            )
            .unwrap()
        {
            ControlResponse::Publication { receipt } => receipt,
            _ => panic!("publication response"),
        };
        (publication, receipt)
    }
    fn release(&self, actor: &Actor, lease: &WriteLease) {
        self.authority
            .control(
                actor,
                &ControlRequest::ReleaseLease {
                    request_id: new_id(),
                    workspace_id: self.workspace.workspace_id.clone(),
                    lease: lease.token.clone(),
                },
            )
            .unwrap();
    }
}

fn code<T>(result: Result<T>) -> ErrorCode {
    match result {
        Ok(_) => panic!("operation unexpectedly succeeded"),
        Err(error) => {
            error
                .downcast_ref::<FabricError>()
                .unwrap_or_else(|| panic!("untyped error: {error:#}"))
                .code
        }
    }
}

#[test]
fn publication_receipts_preserve_exact_history_and_logical_restore() {
    let f = Fixture::new();
    let lease = f.lease(&f.owner, vec![PathScope::Workspace]);
    let (first_request, first) = f.put(&lease, "src/value.txt", b"first");
    let (_, second) = f.put(&lease, "src/value.txt", b"second");
    let replay = f
        .authority
        .control(
            &f.owner,
            &ControlRequest::Publish {
                publication: first_request.clone(),
            },
        )
        .unwrap();
    match replay {
        ControlResponse::Publication { receipt } => {
            assert_eq!(receipt.committed_head, first.committed_head)
        }
        _ => panic!("receipt"),
    }
    assert_eq!(f.current().head.unwrap(), second.committed_head);
    let version = first.changes[0].current.clone().unwrap();
    let mut opened = f
        .authority
        .read(
            &f.owner,
            &FileRequest {
                workspace_id: f.workspace.workspace_id.clone(),
                revision: first.committed_head.revision.clone(),
                path: "src/value.txt".into(),
                expected: version.clone(),
                attempt: None,
            },
        )
        .unwrap();
    let mut bytes = Vec::new();
    opened.file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"first");
    let delete = PublicationContext {
        request_id: new_id(),
        workspace_id: f.workspace.workspace_id.clone(),
        base: second.committed_head,
        lease: lease.token.clone(),
        attempt: None,
    };
    f.authority
        .control(
            &f.owner,
            &ControlRequest::Delete {
                context: delete,
                path: "src/value.txt".into(),
                expected: second.changes[0].current.clone().unwrap(),
            },
        )
        .unwrap();
    assert!(f.current().snapshot.manifest.files.is_empty());
    let restore = PublicationContext {
        request_id: new_id(),
        workspace_id: f.workspace.workspace_id.clone(),
        base: f.current().head.unwrap(),
        lease: lease.token,
        attempt: None,
    };
    f.authority
        .control(
            &f.owner,
            &ControlRequest::Restore {
                context: restore,
                path: "src/value.txt".into(),
                from_revision: first.committed_head.revision.clone(),
                source_path: "src/value.txt".into(),
                expected: None,
            },
        )
        .unwrap();
    assert_eq!(
        f.current().snapshot.manifest.files["src/value.txt"],
        version
    );
    let proof = f
        .authority
        .control(
            &f.owner,
            &ControlRequest::VerifyRetention {
                challenge: new_id(),
                files: vec![RetainedFile {
                    workspace_id: f.workspace.workspace_id.clone(),
                    revision: first.committed_head.revision,
                    path: "src/value.txt".into(),
                    version,
                }],
            },
        )
        .unwrap();
    assert!(matches!(proof, ControlResponse::Retention { .. }));
    let mut changed_request = first_request;
    changed_request.changes.clear();
    assert_eq!(
        code(f.authority.control(
            &f.owner,
            &ControlRequest::Publish {
                publication: changed_request
            }
        )),
        ErrorCode::Conflict
    );
}

#[test]
fn exact_scopes_revocation_rotation_and_expired_fences_reject_staged_writes() {
    let f = Fixture::new();
    let device = f.enroll(2, DeviceRole::Device);
    let grant = WorkspaceGrant {
        device_id: device.device_id().into(),
        workspace_id: f.workspace.workspace_id.clone(),
        catalog_read: false,
        read: vec![PathScope::Tree { path: "src".into() }],
        write: vec![PathScope::Tree { path: "src".into() }],
        submit_jobs: false,
    };
    f.authority
        .control(
            &f.owner,
            &ControlRequest::SetGrant {
                request_id: new_id(),
                grant: grant.clone(),
            },
        )
        .unwrap();
    assert_eq!(
        code(f.authority.control(
            &device,
            &ControlRequest::Current {
                workspace_id: f.workspace.workspace_id.clone()
            }
        )),
        ErrorCode::Forbidden
    );
    let lease = f.lease(&device, vec![PathScope::Tree { path: "src".into() }]);
    assert_eq!(
        code(f.authority.control(
            &f.owner,
            &ControlRequest::AcquireLease {
                request_id: new_id(),
                workspace_id: f.workspace.workspace_id.clone(),
                scopes: vec![PathScope::Exact {
                    path: "src/file".into()
                }],
                ttl_seconds: 60
            }
        )),
        ErrorCode::Conflict
    );
    let wrong = UploadRequest {
        request_id: new_id(),
        workspace_id: f.workspace.workspace_id.clone(),
        path: "src-old/file".into(),
        sha256: hash(b"x"),
        size: 1,
        lease: lease.token.clone(),
        attempt: None,
    };
    assert_eq!(
        code(f.authority.check_upload(&device, &wrong)),
        ErrorCode::Forbidden
    );
    let staged = f.upload(&device, &lease, "src/file", b"x", None);
    let publication = PublishRequest {
        context: PublicationContext {
            request_id: new_id(),
            workspace_id: f.workspace.workspace_id.clone(),
            base: f.current().head.unwrap(),
            lease: lease.token.clone(),
            attempt: None,
        },
        changes: vec![PublicationChange::Put {
            path: "src/file".into(),
            upload_id: staged.upload_id,
            expected: None,
        }],
    };
    f.authority.inner.lock().unwrap().leases.insert(
        lease.token.lease_id.clone(),
        Instant::now() - Duration::from_secs(1),
    );
    assert_eq!(
        code(f.authority.control(
            &device,
            &ControlRequest::Publish {
                publication: publication.clone()
            }
        )),
        ErrorCode::Conflict
    );
    let newer = f.lease(&device, vec![PathScope::Tree { path: "src".into() }]);
    assert!(newer.token.fence > lease.token.fence);
    f.authority
        .control(
            &f.owner,
            &ControlRequest::RotateDeviceKey {
                request_id: new_id(),
                device_id: device.device_id().into(),
                expected_generation: 1,
                public_key: STANDARD.encode([3u8; 32]),
            },
        )
        .unwrap();
    assert_eq!(
        code(f.authority.control(&device, &ControlRequest::Info)),
        ErrorCode::Unauthenticated
    );
    let rotated = Actor::authenticated(device.device_id().into(), 2);
    assert_eq!(
        code(f.authority.check_upload(
            &rotated,
            &UploadRequest {
                lease: newer.token,
                path: "src/file".into(),
                ..wrong
            }
        )),
        ErrorCode::Conflict
    );
    f.authority
        .control(
            &f.owner,
            &ControlRequest::RevokeDevice {
                request_id: new_id(),
                device_id: rotated.device_id().into(),
            },
        )
        .unwrap();
    assert_eq!(
        code(f.authority.control(&rotated, &ControlRequest::Info)),
        ErrorCode::Unauthenticated
    );
    assert!(f.current().snapshot.manifest.files.is_empty());
}

#[test]
fn failed_upload_and_uncertain_state_write_preserve_prior_authority() {
    let f = Fixture::new();
    let lease = f.lease(&f.owner, vec![PathScope::Workspace]);
    let (_, receipt) = f.put(&lease, "value", b"valid");
    let source = f._directory.path().join("bad");
    std::fs::write(&source, b"wrong").unwrap();
    let request = UploadRequest {
        request_id: new_id(),
        workspace_id: f.workspace.workspace_id.clone(),
        path: "value".into(),
        sha256: hash(b"valid"),
        size: 5,
        lease: lease.token,
        attempt: None,
    };
    assert_eq!(
        code(f.authority.upload(&f.owner, &request, &source)),
        ErrorCode::Invalid
    );
    assert!(source.exists());
    assert_eq!(f.current().head.unwrap(), receipt.committed_head);
    let state = f.authority.root.join("state.json");
    let backup = f.authority.root.join("retained-state.json");
    std::fs::rename(&state, &backup).unwrap();
    std::fs::create_dir(&state).unwrap();
    assert_eq!(
        code(f.authority.control(
            &f.owner,
            &ControlRequest::EnrollDevice {
                request_id: new_id(),
                display_name: "Rejected".into(),
                public_key: STANDARD.encode([9u8; 32]),
                role: DeviceRole::Device
            }
        )),
        ErrorCode::Unavailable
    );
    assert!(backup.is_file());
    assert_eq!(
        code(f.authority.control(&f.owner, &ControlRequest::Info)),
        ErrorCode::Unavailable
    );
}

#[test]
fn restart_preserves_committed_bytes_revocation_and_fence_high_water() {
    let f = Fixture::new();
    let revoked = f.enroll(17, DeviceRole::Device);
    let lease = f.lease(&f.owner, vec![PathScope::Workspace]);
    let (_, receipt) = f.put(&lease, "retained", b"persistent contents");
    f.authority
        .control(
            &f.owner,
            &ControlRequest::RevokeDevice {
                request_id: new_id(),
                device_id: revoked.device_id().into(),
            },
        )
        .unwrap();
    let root = f.authority.root.clone();
    let before = f.authority.info();
    let Fixture {
        _directory,
        authority,
        owner,
        workspace,
    } = f;
    drop(authority);
    let reopened = Authority::open(&root).unwrap();
    assert!(reopened.info().epoch > before.epoch);
    assert!(reopened.device(revoked.device_id()).unwrap().revoked);
    assert_eq!(
        code(reopened.control(&revoked, &ControlRequest::Info)),
        ErrorCode::Unauthenticated
    );
    assert_eq!(
        code(reopened.control(
            &owner,
            &ControlRequest::RenewLease {
                request_id: new_id(),
                workspace_id: workspace.workspace_id.clone(),
                lease: lease.token.clone(),
                ttl_seconds: 60
            }
        )),
        ErrorCode::Conflict
    );
    let next = match reopened
        .control(
            &owner,
            &ControlRequest::AcquireLease {
                request_id: new_id(),
                workspace_id: workspace.workspace_id.clone(),
                scopes: vec![PathScope::Workspace],
                ttl_seconds: 60,
            },
        )
        .unwrap()
    {
        ControlResponse::Lease { lease } => lease,
        _ => panic!("lease"),
    };
    assert!(next.token.fence > lease.token.fence);
    let version = receipt.changes[0].current.clone().unwrap();
    let mut file = reopened
        .read(
            &owner,
            &FileRequest {
                workspace_id: workspace.workspace_id,
                revision: receipt.committed_head.revision,
                path: "retained".into(),
                expected: version,
                attempt: None,
            },
        )
        .unwrap();
    let mut bytes = Vec::new();
    file.file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"persistent contents");
}

fn advertise(f: &Fixture, worker: &Actor, cached: Vec<CachedContent>) -> String {
    let incarnation = new_id();
    f.authority
        .control(
            worker,
            &ControlRequest::AdvertiseWorker {
                request_id: new_id(),
                advertisement: WorkerAdvertisement {
                    worker_id: worker.device_id().into(),
                    incarnation: incarnation.clone(),
                    display_name: "Worker".into(),
                    profiles: vec![ProfileAdvertisement {
                        name: "task".into(),
                        adapter: AdapterKind::Command,
                        permission: PermissionMode::WorkspaceWrite,
                    }],
                    resources: Resources {
                        cpu_millis: 2000,
                        memory_bytes: 1024 * 1024,
                    },
                    cached_files: cached,
                },
            },
        )
        .unwrap();
    incarnation
}

fn successful_run(job: &JobRecord) -> RunRecord {
    RunRecord {
        format: 1,
        id: new_id(),
        adapter: AdapterKind::Command,
        executable: "/usr/bin/true".into(),
        executable_version: "fixture-record-only".into(),
        status: "succeeded".into(),
        workspace: PathBuf::from("/private/run"),
        stdout_log: PathBuf::from("/private/stdout"),
        stderr_log: PathBuf::from("/private/stderr"),
        input_files: job
            .inputs
            .iter()
            .map(|input| RunFile {
                path: input.path.clone(),
                sha256: input.version.sha256.clone(),
                size: input.version.size,
            })
            .collect(),
        output_files: vec![RunFile {
            path: "result.txt".into(),
            sha256: hash(b"result"),
            size: 6,
        }],
        environment_names: Vec::new(),
        started_at: "2026-10-25T00:00:00Z".into(),
        finished_at: Some("2026-10-25T00:00:01Z".into()),
        exit_code: Some(0),
        provider_session_id: None,
        detail: None,
        published: false,
    }
}

#[test]
fn locality_claim_finish_logs_and_fenced_publication_are_one_coherent_job() {
    let f = Fixture::new();
    let owner_lease = f.lease(&f.owner, vec![PathScope::Workspace]);
    let (_, seed) = f.put(
        &owner_lease,
        "dataset",
        b"large enough to distinguish locality",
    );
    f.release(&f.owner, &owner_lease);
    let input = JobInput {
        path: "dataset".into(),
        revision: seed.committed_head.revision.clone(),
        version: seed.changes[0].current.clone().unwrap(),
    };
    let cold = f.enroll(4, DeviceRole::Worker);
    let warm = f.enroll(5, DeviceRole::Worker);
    let cold_inc = advertise(&f, &cold, Vec::new());
    let warm_inc = advertise(
        &f,
        &warm,
        vec![CachedContent {
            workspace_id: f.workspace.workspace_id.clone(),
            version: input.version.clone(),
        }],
    );
    let request = JobRequest {
        request_id: new_id(),
        workspace_id: f.workspace.workspace_id.clone(),
        base: seed.committed_head.clone(),
        profile: "task".into(),
        inputs: vec![input.clone()],
        output_selectors: vec![PathScope::Exact {
            path: "result.txt".into(),
        }],
        resources: Resources {
            cpu_millis: 1000,
            memory_bytes: 1024,
        },
        timeout_seconds: 30,
        required_worker: None,
        output_policy: OutputPolicy::Publish,
        prompt: Some("private task text".into()),
    };
    let job = match f
        .authority
        .control(&f.owner, &ControlRequest::SubmitJob { job: request })
        .unwrap()
    {
        ControlResponse::Job { job } => job,
        _ => panic!("job"),
    };
    assert_eq!(
        job.decision.as_ref().unwrap().selected_worker.as_deref(),
        Some(warm.device_id())
    );
    assert!(
        !serde_json::to_string(&job)
            .unwrap()
            .contains("private task text")
    );
    assert!(matches!(
        f.authority
            .control(
                &cold,
                &ControlRequest::ClaimJob {
                    request_id: new_id(),
                    worker_id: cold.device_id().into(),
                    incarnation: cold_inc
                }
            )
            .unwrap(),
        ControlResponse::Claim { claimed: None }
    ));
    let claimed = match f
        .authority
        .control(
            &warm,
            &ControlRequest::ClaimJob {
                request_id: new_id(),
                worker_id: warm.device_id().into(),
                incarnation: warm_inc,
            },
        )
        .unwrap()
    {
        ControlResponse::Claim {
            claimed: Some(claimed),
        } => claimed,
        _ => panic!("claim"),
    };
    let binding = claimed.attempt.clone();
    let lease = claimed.lease.unwrap();
    let before_renewals = f.authority.inner.lock().unwrap().state.requests.len();
    for _ in 0..100 {
        f.authority
            .control(
                &warm,
                &ControlRequest::RenewAttempt {
                    request_id: new_id(),
                    attempt: binding.clone(),
                    lease: Some(lease.token.clone()),
                    ttl_seconds: 60,
                },
            )
            .unwrap();
    }
    assert_eq!(
        f.authority.inner.lock().unwrap().state.requests.len(),
        before_renewals
    );
    assert_eq!(
        code(f.authority.read(
            &warm,
            &FileRequest {
                workspace_id: f.workspace.workspace_id.clone(),
                revision: input.revision.clone(),
                path: input.path.clone(),
                expected: input.version.clone(),
                attempt: None
            }
        )),
        ErrorCode::Forbidden
    );
    f.authority
        .read(
            &warm,
            &FileRequest {
                workspace_id: f.workspace.workspace_id.clone(),
                revision: input.revision,
                path: input.path,
                expected: input.version,
                attempt: Some(binding.clone()),
            },
        )
        .unwrap();
    let log = ControlRequest::AppendLog {
        request_id: new_id(),
        attempt: binding.clone(),
        stream: LogStream::Stdout,
        offset: 0,
        data_base64: STANDARD.encode(b"done\n"),
        truncated: false,
    };
    f.authority.control(&warm, &log).unwrap();
    f.authority.control(&warm, &log).unwrap();
    let upload = f.upload(
        &warm,
        &lease,
        "result.txt",
        b"result",
        Some(binding.clone()),
    );
    let finish = ControlRequest::FinishAttempt {
        request_id: new_id(),
        attempt: binding.clone(),
        lease: Some(lease.token.clone()),
        run: successful_run(&job),
        upload_ids: vec![upload.upload_id.clone()],
    };
    f.authority.control(&warm, &finish).unwrap();
    f.authority.control(&warm, &finish).unwrap();
    match f
        .authority
        .control(
            &f.owner,
            &ControlRequest::JobStatus {
                job_id: job.job_id.clone(),
            },
        )
        .unwrap()
    {
        ControlResponse::Job { job } => assert_eq!(job.state, JobState::Running),
        _ => panic!("job status"),
    }
    assert!(
        f.authority.inner.lock().unwrap().state.workers[warm.device_id()]
            .active_attempt
            .is_some()
    );
    let publication = PublishRequest {
        context: PublicationContext {
            request_id: new_id(),
            workspace_id: f.workspace.workspace_id.clone(),
            base: job.base,
            lease: lease.token,
            attempt: Some(binding.clone()),
        },
        changes: vec![PublicationChange::Put {
            path: "result.txt".into(),
            upload_id: upload.upload_id,
            expected: None,
        }],
    };
    f.authority
        .control(
            &warm,
            &ControlRequest::Publish {
                publication: publication.clone(),
            },
        )
        .unwrap();
    f.authority
        .control(&warm, &ControlRequest::Publish { publication })
        .unwrap();
    let status = match f
        .authority
        .control(
            &f.owner,
            &ControlRequest::JobStatus {
                job_id: job.job_id.clone(),
            },
        )
        .unwrap()
    {
        ControlResponse::Job { job } => job,
        _ => panic!("status"),
    };
    assert!(status.attempts[0].publication.is_some());
    assert_eq!(status.state, JobState::Succeeded);
    assert!(!status.attempts[0].run.as_ref().unwrap().published);
    assert!(
        f.authority.inner.lock().unwrap().state.workers[warm.device_id()]
            .active_attempt
            .is_none()
    );
    match f
        .authority
        .control(
            &f.owner,
            &ControlRequest::ReadLog {
                job_id: job.job_id,
                attempt_id: binding.attempt_id,
                stream: LogStream::Stdout,
                offset: 0,
                max_bytes: 4096,
            },
        )
        .unwrap()
    {
        ControlResponse::Log { page } => {
            assert_eq!(STANDARD.decode(page.data_base64).unwrap(), b"done\n");
            assert!(page.eof);
        }
        _ => panic!("logs"),
    }
}

#[test]
fn cancellation_and_worker_incarnation_replacement_never_publish_old_attempts() {
    let f = Fixture::new();
    let worker = f.enroll(8, DeviceRole::Worker);
    let incarnation = advertise(&f, &worker, Vec::new());
    let job = JobRequest {
        request_id: new_id(),
        workspace_id: f.workspace.workspace_id.clone(),
        base: f.current().head.unwrap(),
        profile: "task".into(),
        inputs: Vec::new(),
        output_selectors: vec![PathScope::Exact {
            path: "result.txt".into(),
        }],
        resources: Resources {
            cpu_millis: 1,
            memory_bytes: 1,
        },
        timeout_seconds: 60,
        required_worker: Some(worker.device_id().into()),
        output_policy: OutputPolicy::Publish,
        prompt: None,
    };
    let job_id = match f
        .authority
        .control(&f.owner, &ControlRequest::SubmitJob { job })
        .unwrap()
    {
        ControlResponse::Job { job } => job.job_id,
        _ => panic!("job"),
    };
    let claim = match f
        .authority
        .control(
            &worker,
            &ControlRequest::ClaimJob {
                request_id: new_id(),
                worker_id: worker.device_id().into(),
                incarnation,
            },
        )
        .unwrap()
    {
        ControlResponse::Claim {
            claimed: Some(claim),
        } => claim,
        _ => panic!("claim"),
    };
    let prior_renewal = ControlRequest::RenewAttempt {
        request_id: new_id(),
        attempt: claim.attempt.clone(),
        lease: claim.lease.as_ref().map(|lease| lease.token.clone()),
        ttl_seconds: 60,
    };
    f.authority.control(&worker, &prior_renewal).unwrap();
    f.authority
        .control(
            &f.owner,
            &ControlRequest::CancelJob {
                request_id: new_id(),
                job_id: job_id.clone(),
            },
        )
        .unwrap();
    let heartbeat = f
        .authority
        .control(
            &worker,
            &ControlRequest::RenewAttempt {
                request_id: new_id(),
                attempt: claim.attempt.clone(),
                lease: claim.lease.as_ref().map(|lease| lease.token.clone()),
                ttl_seconds: 60,
            },
        )
        .unwrap();
    assert!(matches!(
        heartbeat,
        ControlResponse::Heartbeat {
            heartbeat: AttemptHeartbeat {
                cancel_requested: true,
                ..
            }
        }
    ));
    assert!(matches!(
        f.authority.control(&worker, &prior_renewal).unwrap(),
        ControlResponse::Heartbeat {
            heartbeat: AttemptHeartbeat {
                cancel_requested: true,
                ..
            }
        }
    ));
    advertise(&f, &worker, Vec::new());
    assert_eq!(
        code(f.authority.control(
            &worker,
            &ControlRequest::FinishAttempt {
                request_id: new_id(),
                attempt: claim.attempt.clone(),
                lease: claim.lease.map(|lease| lease.token),
                run: successful_run(&claim.job),
                upload_ids: Vec::new()
            }
        )),
        ErrorCode::Conflict
    );
    match f
        .authority
        .control(
            &f.owner,
            &ControlRequest::JobStatus {
                job_id: job_id.clone(),
            },
        )
        .unwrap()
    {
        ControlResponse::Job { job } => assert_eq!(job.state, JobState::Abandoned),
        _ => panic!("job"),
    }
    f.authority
        .control(
            &f.owner,
            &ControlRequest::RetryJob {
                request_id: new_id(),
                job_id,
                expected_attempt_id: claim.attempt.attempt_id,
            },
        )
        .unwrap();
    assert!(f.current().snapshot.manifest.files.is_empty());
}

#[test]
fn idle_worker_and_current_lease_renewal_do_not_consume_durable_receipt_capacity() {
    let f = Fixture::new();
    let worker = f.enroll(21, DeviceRole::Worker);
    let incarnation = advertise(&f, &worker, Vec::new());
    let advertisement = f.authority.inner.lock().unwrap().state.workers[worker.device_id()]
        .advertisement
        .clone();
    let lease = f.lease(&f.owner, vec![PathScope::Workspace]);
    let before_count = f.authority.inner.lock().unwrap().state.requests.len();
    let before_fence = f.authority.inner.lock().unwrap().state.fence;
    let before_file = std::fs::read(f.authority.root.join("state.json")).unwrap();
    for _ in 0..1_100 {
        f.authority
            .control(
                &worker,
                &ControlRequest::AdvertiseWorker {
                    request_id: new_id(),
                    advertisement: advertisement.clone(),
                },
            )
            .unwrap();
        assert!(matches!(
            f.authority
                .control(
                    &worker,
                    &ControlRequest::ClaimJob {
                        request_id: new_id(),
                        worker_id: worker.device_id().into(),
                        incarnation: incarnation.clone()
                    }
                )
                .unwrap(),
            ControlResponse::Claim { claimed: None }
        ));
        f.authority
            .control(
                &f.owner,
                &ControlRequest::RenewLease {
                    request_id: new_id(),
                    workspace_id: f.workspace.workspace_id.clone(),
                    lease: lease.token.clone(),
                    ttl_seconds: 60,
                },
            )
            .unwrap();
    }
    assert_eq!(
        f.authority.inner.lock().unwrap().state.requests.len(),
        before_count
    );
    assert_eq!(f.authority.inner.lock().unwrap().state.fence, before_fence);
    assert_eq!(
        std::fs::read(f.authority.root.join("state.json")).unwrap(),
        before_file
    );
    assert!(f.authority.inner.lock().unwrap().observations.len() <= MAX_OBSERVATIONS);
}

#[test]
fn retired_worker_incarnation_cannot_re_advertise_with_old_or_fresh_request_id() {
    let f = Fixture::new();
    let worker = f.enroll(22, DeviceRole::Worker);
    let incarnation = advertise(&f, &worker, Vec::new());
    let old = f.authority.inner.lock().unwrap().state.workers[worker.device_id()]
        .advertisement
        .clone();
    let request = ControlRequest::AdvertiseWorker {
        request_id: new_id(),
        advertisement: old.clone(),
    };
    f.authority.control(&worker, &request).unwrap();
    let replacement = advertise(&f, &worker, Vec::new());
    assert_ne!(replacement, incarnation);
    assert_eq!(
        code(f.authority.control(&worker, &request)),
        ErrorCode::Conflict
    );
    assert_eq!(
        code(f.authority.control(
            &worker,
            &ControlRequest::AdvertiseWorker {
                request_id: new_id(),
                advertisement: old
            }
        )),
        ErrorCode::Conflict
    );
    assert_eq!(
        f.authority.inner.lock().unwrap().state.workers[worker.device_id()]
            .advertisement
            .incarnation,
        replacement
    );
}

#[test]
fn worker_discovery_does_not_expose_another_workers_cache_inventory() {
    let f = Fixture::new();
    let lease = f.lease(&f.owner, vec![PathScope::Workspace]);
    let (_, receipt) = f.put(&lease, "private-data", b"private");
    let source = f.enroll(23, DeviceRole::Worker);
    let observer = f.enroll(24, DeviceRole::Worker);
    advertise(
        &f,
        &source,
        vec![CachedContent {
            workspace_id: f.workspace.workspace_id.clone(),
            version: receipt.changes[0].current.clone().unwrap(),
        }],
    );
    match f
        .authority
        .control(&observer, &ControlRequest::ListWorkers)
        .unwrap()
    {
        ControlResponse::Workers { workers } => assert!(
            workers
                .iter()
                .all(|worker| worker.advertisement.cached_files.is_empty())
        ),
        _ => panic!("worker list"),
    }
    for actor in [&f.owner, &source] {
        match f
            .authority
            .control(actor, &ControlRequest::ListWorkers)
            .unwrap()
        {
            ControlResponse::Workers { workers } => assert_eq!(
                workers
                    .iter()
                    .find(|worker| worker.advertisement.worker_id == source.device_id())
                    .unwrap()
                    .advertisement
                    .cached_files
                    .len(),
                1
            ),
            _ => panic!("worker list"),
        }
    }
}
