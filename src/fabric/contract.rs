//! PM-owned managed workspace, authority and worker contracts.
//! Canonical immutable catalog and execution types remain in their existing modules.
//! All UUID strings are canonical non-nil UUIDs; all logical paths use files' rules.
//! Public operations return anyhow::Error containing FabricError for a stable code.
use crate::execution::contract::{AdapterKind, PermissionMode, RunRecord};
use crate::workspace::contract::{FileVersion, RevisionRef};
pub use crate::workspace::contract::{ManagedCatalog, ManagedHead, ManagedTarget};
use serde::{Deserialize, Serialize};
use std::fs::File;

pub const FABRIC_FORMAT: u32 = 1;
pub type DeviceId = String;
pub type WorkspaceId = String;
pub type WorkerId = String;
pub type JobId = String;
pub type AttemptId = String;
pub type RequestId = String;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Unauthenticated,
    Forbidden,
    Conflict,
    NotFound,
    Invalid,
    Unavailable,
    Capacity,
}

#[derive(Clone, Debug, Serialize, Deserialize, thiserror::Error)]
#[error("{code:?}: {message}")]
#[serde(deny_unknown_fields)]
pub struct FabricError {
    pub code: ErrorCode,
    /// Safe for an operator; never contains secret values or a prompt.
    pub message: String,
}

/// Minted by the root-owned authentication layer after proof of the enrolled key.
/// Deliberately not Deserialize: an HTTP request cannot supply its own Actor.
/// Authority operations re-read enrollment, revocation and grants every time.
#[derive(Clone, Debug)]
pub struct Actor {
    device_id: DeviceId,
    key_generation: u64,
}
impl Actor {
    pub(crate) fn authenticated(device_id: DeviceId, key_generation: u64) -> Self {
        Self {
            device_id,
            key_generation,
        }
    }
    pub fn device_id(&self) -> &str {
        &self.device_id
    }
    pub fn key_generation(&self) -> u64 {
        self.key_generation
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityInfo {
    pub format: u32,
    pub authority_id: String,
    pub vault_id: String,
    /// Persistently increased before each process begins serving operations.
    pub epoch: u64,
    pub generation: u64,
    pub retention_policy_version: u32,
}

// ---- WORKSPACE CONTRACT: explicit managed mode; direct S3 format 1 unchanged. ----
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PathScope {
    Workspace,
    Exact { path: String },
    Tree { path: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedFile {
    pub workspace_id: WorkspaceId,
    pub revision: RevisionRef,
    pub path: String,
    pub version: FileVersion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionPolicy {
    AppendOnlyNoGc,
}

/// Inspectable evidence, NEVER by itself permission to delete local bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionReceipt {
    pub authority_id: String,
    pub vault_id: String,
    pub policy: RetentionPolicy,
    pub policy_version: u32,
    pub committed_generation: u64,
    pub file: RetainedFile,
    /// Stable logical reference; exact revision lookup never walks a bounded head chain.
    pub recovery_reference: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionVerification {
    /// Fresh caller challenge, echoed verbatim and checked by managed transport.
    pub challenge: String,
    pub authority_id: String,
    pub vault_id: String,
    pub epoch: u64,
    pub verified_at_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    /// Each immutable body was checked against its committed length/hash now.
    pub receipts: Vec<RetentionReceipt>,
}

/// Managed transport constructs only after authenticating the response and checking
/// target, fresh challenge, exact selection and expiry. No Deserialize or Clone.
/// Cache eviction consumes this value and revalidates its private local selection.
pub struct VerifiedRetention {
    verification: RetentionVerification,
}
impl VerifiedRetention {
    pub(crate) fn from_authenticated_response(verification: RetentionVerification) -> Self {
        Self { verification }
    }
    pub fn verification(&self) -> &RetentionVerification {
        &self.verification
    }
    pub fn into_verification(self) -> RetentionVerification {
        self.verification
    }
}

// ---- Enrollment and grants. Device keys are public; private keys never transit. ----
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceRole {
    Owner,
    Device,
    Worker,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRecord {
    pub device_id: DeviceId,
    pub display_name: String,
    /// Canonical base64 of the 32-byte Ed25519 public key.
    pub public_key: String,
    pub key_generation: u64,
    pub role: DeviceRole,
    pub revoked: bool,
    pub created_at_unix_ms: u64,
    pub revoked_at_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceGrant {
    pub device_id: DeviceId,
    pub workspace_id: WorkspaceId,
    /// Full canonical manifests expose all logical names; this is explicit.
    pub catalog_read: bool,
    pub read: Vec<PathScope>,
    pub write: Vec<PathScope>,
    pub submit_jobs: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRecord {
    pub grant: WorkspaceGrant,
    pub generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRecord {
    pub workspace_id: WorkspaceId,
    pub name: String,
    pub head: ManagedHead,
    pub created_at_unix_ms: u64,
    /// Import creates a NEW managed workspace identity; source remains unchanged.
    pub import_source: Option<ImportSource>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportSource {
    /// Existing canonical credential-free direct target identifier.
    pub target_id: String,
    pub workspace_id: WorkspaceId,
    pub revision: RevisionRef,
}

// ---- Leases and publication. All scopes use path-component overlap. ----
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseToken {
    pub lease_id: String,
    pub fence: u64,
    pub epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteLease {
    pub token: LeaseToken,
    pub workspace_id: WorkspaceId,
    pub holder: DeviceId,
    pub key_generation: u64,
    pub scopes: Vec<PathScope>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    /// Client renewal scheduling only; server uses its live monotonic deadline.
    pub remaining_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptBinding {
    pub job_id: JobId,
    pub attempt_id: AttemptId,
    pub worker_id: WorkerId,
    pub worker_incarnation: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadRequest {
    pub request_id: RequestId,
    pub workspace_id: WorkspaceId,
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub lease: LeaseToken,
    pub attempt: Option<AttemptBinding>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedUpload {
    pub upload_id: String,
    pub workspace_id: WorkspaceId,
    pub path: String,
    pub version: FileVersion,
    pub prepared_by: DeviceId,
    pub attempt: Option<AttemptBinding>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationContext {
    pub request_id: RequestId,
    pub workspace_id: WorkspaceId,
    pub base: ManagedHead,
    pub lease: LeaseToken,
    /// Exact job/attempt/worker incarnation; checked for cancellation at commit.
    pub attempt: Option<AttemptBinding>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PublicationChange {
    Put {
        path: String,
        upload_id: String,
        expected: Option<FileVersion>,
    },
    Delete {
        path: String,
        expected: FileVersion,
    },
    Restore {
        path: String,
        from_revision: RevisionRef,
        source_path: String,
        expected: Option<FileVersion>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishRequest {
    pub context: PublicationContext,
    pub changes: Vec<PublicationChange>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeReceipt {
    pub path: String,
    pub previous: Option<FileVersion>,
    pub current: Option<FileVersion>,
    /// delete is a retained logical tombstone, NEVER a physical remove call.
    pub kind: ChangeKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Put,
    Delete,
    Restore,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationReceipt {
    pub publication_id: String,
    pub request_id: RequestId,
    pub authority_id: String,
    pub workspace_id: WorkspaceId,
    /// Immutable commit result; never replaced with a later current-head token.
    pub committed_head: ManagedHead,
    pub parent: RevisionRef,
    pub actor: DeviceId,
    pub lease: LeaseToken,
    pub attempt: Option<AttemptBinding>,
    pub changes: Vec<ChangeReceipt>,
    pub retention: Vec<RetentionReceipt>,
    pub committed_at_unix_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRequest {
    pub workspace_id: WorkspaceId,
    pub revision: RevisionRef,
    pub path: String,
    pub expected: FileVersion,
    pub attempt: Option<AttemptBinding>,
}

/// Local file handle owned by the response; no vault path is serialized.
pub struct OpenedFile {
    pub file: File,
    pub version: FileVersion,
}

// ---- Worker advertisements, explainable locality, durable jobs and attempts. ----
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    pub cpu_millis: u32,
    pub memory_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileAdvertisement {
    pub name: String,
    pub adapter: AdapterKind,
    pub permission: PermissionMode,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CachedContent {
    pub workspace_id: WorkspaceId,
    pub version: FileVersion,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerAdvertisement {
    /// Must equal the authenticated enrolled Worker/Owner device ID.
    pub worker_id: WorkerId,
    /// Fresh process UUID; changing it abandons prior active claims and leases.
    pub incarnation: String,
    pub display_name: String,
    pub profiles: Vec<ProfileAdvertisement>,
    pub resources: Resources,
    /// Verified immutable cache entries only; always a locality hint, not retention.
    pub cached_files: Vec<CachedContent>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRecord {
    pub advertisement: WorkerAdvertisement,
    pub observed_at_unix_ms: u64,
    pub eligible_until_unix_ms: u64,
    pub active_attempt: Option<AttemptBinding>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobInput {
    /// Source path equals copied path in this first version.
    pub path: String,
    pub revision: RevisionRef,
    pub version: FileVersion,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputPolicy {
    #[default]
    Retain,
    Publish,
}

/// Sensitive request: intentionally no Debug. Prompt is bounded, stored privately,
/// returned only to the assigned worker, and excluded from JobRecord/public reports.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobRequest {
    pub request_id: RequestId,
    pub workspace_id: WorkspaceId,
    pub base: ManagedHead,
    /// Name resolves only through the worker owner's local profile configuration.
    pub profile: String,
    pub inputs: Vec<JobInput>,
    pub output_selectors: Vec<PathScope>,
    pub resources: Resources,
    pub timeout_seconds: u64,
    /// Hard manual placement; no silent fallback to another worker.
    pub required_worker: Option<WorkerId>,
    pub output_policy: OutputPolicy,
    pub prompt: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCandidate {
    pub worker_id: WorkerId,
    pub incarnation: String,
    pub eligible: bool,
    /// Deduplicate (workspace_id, sha256, size), matching private-cache addressing.
    pub missing_bytes: u64,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalityDecision {
    pub selected_worker: Option<WorkerId>,
    pub candidates: Vec<WorkerCandidate>,
    /// Minimum missing bytes among eligible workers, deterministic worker-ID tie break.
    pub reason: String,
    pub decided_at_unix_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    Succeeded,
    Failed,
    CancelRequested,
    Cancelled,
    TimedOut,
    Abandoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptState {
    Claimed,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
    ProtocolFailed,
    Abandoned,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptRecord {
    pub binding: AttemptBinding,
    pub state: AttemptState,
    pub lease: Option<LeaseToken>,
    pub claimed_at_unix_ms: u64,
    pub heartbeat_at_unix_ms: u64,
    pub finished_at_unix_ms: Option<u64>,
    /// Existing execution record; published MUST remain false.
    pub run: Option<RunRecord>,
    pub prepared_outputs: Vec<PreparedUpload>,
    pub publication: Option<PublicationReceipt>,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobRecord {
    pub job_id: JobId,
    pub submitted_by: DeviceId,
    pub workspace_id: WorkspaceId,
    pub base: ManagedHead,
    pub profile: String,
    pub inputs: Vec<JobInput>,
    pub output_selectors: Vec<PathScope>,
    pub resources: Resources,
    pub timeout_seconds: u64,
    pub required_worker: Option<WorkerId>,
    pub output_policy: OutputPolicy,
    pub state: JobState,
    pub created_at_unix_ms: u64,
    pub cancel_requested: bool,
    pub decision: Option<LocalityDecision>,
    pub attempts: Vec<AttemptRecord>,
}

/// Sensitive authenticated worker response: intentionally no Debug.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimedJob {
    pub job: JobRecord,
    pub attempt: AttemptBinding,
    /// None only when no output scopes exist; no publication then permitted.
    pub lease: Option<WriteLease>,
    pub prompt: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptHeartbeat {
    pub attempt: AttemptBinding,
    pub state: AttemptState,
    pub lease: Option<WriteLease>,
    pub cancel_requested: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogStream {
    Stdout,
    Stderr,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogPage {
    pub offset: u64,
    pub next_offset: u64,
    pub data_base64: String,
    pub truncated: bool,
    pub eof: bool,
}

// ---- One typed control channel. Business mutations carry durable receipts. ----
// Liveness (current lease/attempt renewals and same-incarnation advertisements)
// and empty claims are bounded observations, not permanent operation history.
// They always recheck current authority; restart expires all previous liveness.
// Limits (request bytes, scopes, devices, jobs, manifests, leases, receipt retention)
// are explicit constants in the implementation/spec; capacity never evicts authority.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlRequest {
    Info,
    ListDevices,
    GetDevice {
        device_id: DeviceId,
    },
    EnrollDevice {
        request_id: RequestId,
        display_name: String,
        public_key: String,
        role: DeviceRole,
    },
    RotateDeviceKey {
        request_id: RequestId,
        device_id: DeviceId,
        expected_generation: u64,
        public_key: String,
    },
    RevokeDevice {
        request_id: RequestId,
        device_id: DeviceId,
    },
    ListGrants {
        device_id: Option<DeviceId>,
        workspace_id: Option<WorkspaceId>,
    },
    SetGrant {
        request_id: RequestId,
        grant: WorkspaceGrant,
    },
    RemoveGrant {
        request_id: RequestId,
        device_id: DeviceId,
        workspace_id: WorkspaceId,
    },
    CreateWorkspace {
        request_id: RequestId,
        name: String,
        import_source: Option<ImportSource>,
    },
    ListWorkspaces,
    Current {
        workspace_id: WorkspaceId,
    },
    /// Resolve directly from retained committed-revision index; no 256-parent limit.
    Revision {
        workspace_id: WorkspaceId,
        revision: RevisionRef,
    },
    AcquireLease {
        request_id: RequestId,
        workspace_id: WorkspaceId,
        scopes: Vec<PathScope>,
        ttl_seconds: u64,
    },
    RenewLease {
        request_id: RequestId,
        workspace_id: WorkspaceId,
        lease: LeaseToken,
        ttl_seconds: u64,
    },
    ReleaseLease {
        request_id: RequestId,
        workspace_id: WorkspaceId,
        lease: LeaseToken,
    },
    ListLeases {
        workspace_id: WorkspaceId,
    },
    Publish {
        publication: PublishRequest,
    },
    /// Convenience variants enter exactly the same fenced publication transaction.
    Delete {
        context: PublicationContext,
        path: String,
        expected: FileVersion,
    },
    Restore {
        context: PublicationContext,
        path: String,
        from_revision: RevisionRef,
        source_path: String,
        expected: Option<FileVersion>,
    },
    PublicationStatus {
        request_id: RequestId,
    },
    ListPrepared {
        workspace_id: WorkspaceId,
        attempt: Option<AttemptBinding>,
    },
    VerifyRetention {
        challenge: String,
        files: Vec<RetainedFile>,
    },
    AdvertiseWorker {
        request_id: RequestId,
        advertisement: WorkerAdvertisement,
    },
    ListWorkers,
    SubmitJob {
        job: JobRequest,
    },
    ExplainPlacement {
        job_id: JobId,
    },
    /// Authority selects among eligible workers; one active attempt per worker.
    ClaimJob {
        request_id: RequestId,
        worker_id: WorkerId,
        incarnation: String,
    },
    RenewAttempt {
        request_id: RequestId,
        attempt: AttemptBinding,
        lease: Option<LeaseToken>,
        ttl_seconds: u64,
    },
    /// Completion preserves unpublished outputs; it is not a head mutation.
    FinishAttempt {
        request_id: RequestId,
        attempt: AttemptBinding,
        lease: Option<LeaseToken>,
        run: RunRecord,
        upload_ids: Vec<String>,
    },
    CancelJob {
        request_id: RequestId,
        job_id: JobId,
    },
    /// Only an explicit owner/submitter action; original exact task stays unchanged.
    RetryJob {
        request_id: RequestId,
        job_id: JobId,
        expected_attempt_id: AttemptId,
    },
    JobStatus {
        job_id: JobId,
    },
    ListJobs {
        workspace_id: Option<WorkspaceId>,
    },
    /// Bounded chunk, exact next offset, idempotent retry; no worker-local path access.
    AppendLog {
        request_id: RequestId,
        attempt: AttemptBinding,
        stream: LogStream,
        offset: u64,
        data_base64: String,
        truncated: bool,
    },
    ReadLog {
        job_id: JobId,
        attempt_id: AttemptId,
        stream: LogStream,
        offset: u64,
        max_bytes: u32,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
// One bounded response at a time. Keep the frozen typed RPC construction surface;
// all potentially large collections already allocate on the heap and are bounded.
#[allow(clippy::large_enum_variant)]
pub enum ControlResponse {
    Info {
        info: AuthorityInfo,
    },
    Devices {
        devices: Vec<DeviceRecord>,
    },
    Device {
        device: DeviceRecord,
    },
    Grants {
        grants: Vec<GrantRecord>,
    },
    Grant {
        grant: GrantRecord,
    },
    Workspace {
        workspace: WorkspaceRecord,
    },
    Workspaces {
        workspaces: Vec<WorkspaceRecord>,
    },
    Catalog {
        catalog: ManagedCatalog,
    },
    Lease {
        lease: WriteLease,
    },
    Leases {
        leases: Vec<WriteLease>,
    },
    Publication {
        receipt: PublicationReceipt,
    },
    Prepared {
        uploads: Vec<PreparedUpload>,
    },
    Retention {
        verification: RetentionVerification,
    },
    Worker {
        worker: WorkerRecord,
    },
    Workers {
        workers: Vec<WorkerRecord>,
    },
    Job {
        job: JobRecord,
    },
    Jobs {
        jobs: Vec<JobRecord>,
    },
    Placement {
        decision: LocalityDecision,
    },
    Claim {
        claimed: Option<ClaimedJob>,
    },
    Heartbeat {
        heartbeat: AttemptHeartbeat,
    },
    Log {
        page: LogPage,
    },
    /// Durable request receipt; cancel acknowledgment does not confirm termination.
    Ack {
        request_id: RequestId,
        generation: u64,
    },
}

// ---- Concrete Authority public API to implement in src/fabric/authority.rs. ----
/// Bootstrap is an offline, exclusive, create-new operation. Private keys absent.
#[derive(Clone, Debug)]
pub struct BootstrapOwner {
    pub device_id: DeviceId,
    pub display_name: String,
    pub public_key: String,
}

// Authority implementation exposes inherent methods: initialize(root, owner),
// open(root), info(), device(id), control(actor, request),
// upload(actor, request, private_source), and read(actor, request).
// All operations are blocking and transport dispatches them on blocking threads.
// Authority owns a lifetime fs2 lock, serialized durable mutations and no GC API.
