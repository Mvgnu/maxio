---
{
  "verification": {
    "check": "cargo check --locked --all-targets",
    "build": "cargo build --locked --bins",
    "architecture": "python3 scripts/check_architecture.py",
    "test": "cargo test --locked --lib fabric::cache:: && cargo test --locked --test fabric_worker && cargo test --locked --test fabric_cache"
  },
  "name": "worker_execution",
  "description": "Managed remote execution and guarded private immutable cache",
  "paths": {
    "owned": [
      "src/fabric/worker.rs",
      "src/fabric/worker/",
      "src/fabric/cache.rs",
      "src/fabric/cache/",
      "src/bin/maxio-worker.rs"
    ],
    "tests": [
      "tests/fabric_worker.rs",
      "tests/fabric_cache.rs"
    ],
    "exclude": []
  },
  "exports": [
    "worker::serve and local profile configuration",
    "cache::PrivateCache",
    "maxio-worker CLI",
    "retained attempts and measured cache eviction"
  ],
  "consumes": [
    "fabric::contract",
    "fabric::client::FabricClient",
    "execution::{run_verified,RunRequest,RunFile,RunRecord}",
    "files path and fsync helpers"
  ],
  "bar": {
    "reference": "Ray locality-aware task scheduling",
    "url": "https://docs.ray.io/en/latest/ray-core/scheduling/index.html#locality-aware-scheduling",
    "property": "A separately running selected worker uses its verified local dataset, executes the admitted command and publishes authorized outputs while the submitting client receives zero dataset bytes; abandoned work is retained and stale publication fails."
  },
  "artifact": "Real coordinator and two separate worker processes with a 128 MiB dataset, per-client transfer counts, cancellation, restart and private-cache reclamation."
}
---

# Managed remote execution and guarded private immutable cache

The PM ruling in `specs/00_system.md` and `fabric::contract` are authoritative.
Read `lop.md` and `gauntlet.md`. This domain cannot expand its own write gate.

## Worker entry point and profiles

`maxio-worker --config CLIENT.json --root PRIVATE_ROOT --profiles PROFILES.json`
runs one active attempt at a time. `--once` waits for one claim, completes its
attempt and exits; it does not retry the job. Polling, renewal, lease duration and
advertised CPU/memory capacity have explicit CLI controls. Resource declarations
are admission hints, not enforced OS quotas.

The client JSON is the canonical transport `ClientConfig`. The profiles file is
an array containing `name`, `adapter`, absolute `executable`, literal `args`,
`permission` and optional `environment`. Permission values are `read_only` or
`workspace_write`. Ordinary commands require the latter. Provider profiles reject
arbitrary arguments and use the existing adapters; explicit provider homes use
`CODEX_HOME` or `CLAUDE_CONFIG_DIR` in the local environment map. Profiles are never
serialized to authority or diagnostics. The runner performs its established
provider capability, authentication-selection and environment validation.

`worker::execute_prepared` is the trusted local integration helper after authority
admission and cache preparation. It checks exact job input identities through
`execution::run_verified` and polls durable cancellation without loading any PID.
The daemon polls this runner independently of log/control transfers. No provider
engine or output parser is reimplemented here.

## Private cache interface

`PrivateCache::open(root, authority_info, device_id)` binds a dedicated root to
the authority/vault/device and holds the manager lock for its lifetime. An initial
root must be empty; existing editable workspace, runtime, sync and Git roots are
refused, as are coordinator roots and descendants of protected data trees. The
fsynced `.maxio-worker` type marker is validated on every reopen; a missing or
changed marker preserves the existing root rather than adopting it as new state.
`open_offline(root)` requires the persisted binding and takes the same
lock without contacting authority. `root()` exposes the validated local root.

- `inventory(verify)` separates unverified presence from verified content and
  returns canonical `cached_files` advertisements plus detailed local state.
- `import(reference, source)` makes a verified independent private copy. It does
  not publish or mint retention authority.
- `hydrate(client, references, attempt)` streams only absent selected content;
  `(workspace_id, sha256, size)` is the shared locality/cache key.
- `copy_to(references, destination)` creates only absent selected files with
  independent inodes. Editable replacement/baselines remain a separate operation.
- `pin(references, value)`, `protect(attempt_id, references)` and `release(attempt_id)`
  persist pins and active-use guards. A pin on any provenance reference protects
  the shared content entry.
- `evict(client, references)` requires fresh opaque `VerifiedRetention`, exact
  authority/vault/version/policy binding, current clean content/inode/link identity,
  no pin/use, and a durable eviction intent. Interrupted removals reconcile without
  deleting additional files. Persistence uncertainty stops mutation until reopen.

Hydration/copy/eviction require explicit nonempty selections. Receipts report
logical bytes, allocated blocks and observed filesystem available-space delta
separately; shared-volume noise is not called proven disk reclamation. The cache
does not remove incomplete stages, attempt workspaces, logs, unpublished outputs
or editable workspace/history bytes.

These checks assume a private root owned by cooperating processes. The manager
lock and inode/hash checks do not prevent a malicious same-UID process replacing
ancestors or racing a hash/unlink operation. Tasks receive independent copies and
remain trusted native execution, not an OS filesystem sandbox.

## Attempt lifecycle and recovery

Assignments are retained under `attempts/<attempt-id>/attempt.json` before input
preparation. Source copies, one dedicated `runs` directory, output stages and
idempotent log-forwarding records remain beneath that attempt. Local records omit
prompt contents and environment values. The coordinator remains the only job
state and placement authority.

Renewal and cancellation continue while inputs, logs and outputs transfer. Loss
of authority or explicit cancellation requests the live runner's durable control
marker. A cancellation receipt does not prove termination. Preparation failure
without a real run record stops renewal and preserves work; expiry yields an
authoritative abandoned attempt eligible only for explicit manual retry.

Successful `Publish` policy stages exact allowlisted candidates, uploads immutable
bytes, reports the real terminal run, then requests the fenced head commit. The
attempt's lease remains live through that final commit. `Retain` policy, failures
and empty candidates do not publish. `RunRecord.published` stays false; only the
separate authoritative receipt identifies a published result. Lost responses
repeat the same request identity or reconcile receipts without rerunning a task.

A restart advertises a new worker incarnation, reconciles old authoritative
attempts/receipts and requests local cancellation where possible. It never signals
a persisted PID, resumes a provider session or retries execution. Old failed or
abandoned copies remain available for inspection and deliberate recovery.

## Acceptance

Use the managed B/C/D/E journey in `specs/journeys/managed_fabric.md`. Preserve
canonical workspace and execution types and standalone startup independence.
Record observed evidence in a dated review, not a progress diary in this spec.
An isolated-process demonstration must not be described as physical multi-device
validation. No claimed provider model execution follows from protocol fixtures.

## Limits

Single authority; no quorum, automatic failover, NAT discovery or hostile same-UID
execution isolation. Native commands remain owner-trusted. Vault retention means
fsynced append-only files in one private server filesystem, not redundant physical
storage. Direct-S3 editable workspaces remain non-evictable. No automatic retry or
workspace-history pruning. Capacity exhaustion rejects new work explicitly.
