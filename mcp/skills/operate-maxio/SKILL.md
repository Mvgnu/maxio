---
name: operate-maxio
description: "Operate and explain MaxIO storage, MCP management, device sync, selective workspaces and managed workers. Use for MaxIO setup, file operations, access, jobs, monitoring, recovery and troubleshooting."
---

# Operate MaxIO

## Historical source notice

This file documents the retained pre-consolidation source. Use the current
[operate-maxio skill in MCP-Host](https://github.com/Mvgnu/MCP-Host/blob/main/components/maxio/mcp/skills/operate-maxio/SKILL.md)
and its repository rules for current operation and development. The
[source cutover](../../../MIGRATION.md) preserves this snapshot; do not develop
a second implementation here. Live discovered tool schemas remain authoritative
for an existing connection.

Operate the requested workflow end to end through `maxio-management` MCP tools.
Use the authorized CLI when a feature is not wrapped by MCP. Perform routine
inspection, setup and verification yourself when tools and access permit; do not
send the operator to the console to repeat work an agent can perform.

## Choose the right product layer

| Need | Component | Read when needed |
|---|---|---|
| Understand the complete feature set and guarantees | S3, peers, sync, workspaces, execution | [Architecture and features](#architecture-and-complete-feature-map) |
| Manage objects, buckets, versions, access or jobs | The 49 concrete MCP tools | [Tool catalog](#mcp-tool-catalog) and [MCP workflows](#mcp-workflows-and-dtos) |
| Connect a client, start a service, diagnose health or recover | Private MCP settings and existing backend services | [Setup and operations](#setup-operation-and-troubleshooting) |
| Transfer large files, sync folders, publish/hydrate workspaces, run workers or local agents | Six Rust executables and ordinary S3 clients | [CLI workflows](#cli-workflows) |

The S3 server, ordinary folder sync, direct-S3 workspaces, managed authority and
workers have separate state and startup paths. Creating a bucket does not create
a managed workspace. Starting S3 does not start an authority or a worker. The MCP
adapter exposes their existing contracts; it is not a scheduler or new storage
authority. Missing configuration is an unavailable capability, not empty data.

## First contact

Discover live tool schemas; hosts may add a namespace prefix. Call `maxio_summary`
or `maxio_health` and `maxio_service_status`. If managed operations are requested,
also inspect `maxio_fabric_info`, `maxio_fabric_workspaces_list` and
`maxio_fabric_workers_list`. Reuse the connection and its private session.

Read `structuredContent.data` on success. Errors use `isError: true` and
`structuredContent.error`; invalid tool arguments can instead be protocol errors.
Managed results retain the Rust response envelope under `data.response.result`.
Inspect the tagged response and actual fields rather than treating an HTTP/MCP
response as proof the requested business action completed.

Service startup returns `state: starting`. Wait for `maxio_service_status` to report
`state: reachable` and inspect health before storage requests. A live process or
open port alone does not prove readiness. `external: true, owned: false` means the
endpoint belongs to another supervisor; this MCP session cannot stop/restart it.

## Common agent workflows

**Files:** list buckets, select the requested bucket/prefix, inspect existing data
when an overwrite matters, then write/read/list the exact object to verify the
result. MCP writes accept `encoding: utf8|base64`; reads return base64. Transfers
and console responses are capped at 1 MiB. Use an authorized S3 client for larger
objects instead of truncating or splitting one logical object into unrelated keys.

**Version recovery:** inspect versioning and `maxio_versions_list`, read the exact
selected `version_id`, then publish the intended recovered bytes as a new current
object if requested. Ordinary delete may create a marker; `maxio_version_delete`
permanently removes the selected historical version/marker. Never use permanent
version deletion as routine recovery or implicit cleanup.

**Managed work:** get the current workspace catalog/head, choose exact immutable
inputs and an advertised named worker profile, submit a job with a fresh UUID,
then inspect placement and job status. Queued is not running; successful execution
is separate from published output. Use the declared output policy and retain
unpublished work. See the MCP workflows section for canonical DTOs.

**Diagnosis:** read health/summary, then relevant metrics, membership and topology.
Use placement/rebalance tools with an explicit key; rebalance is a preview, not a
membership mutation. `maxio_observe` samples for at most 30 seconds. Persistent
alerts/reconciliation need a separately configured scheduler or running agent;
connecting MCP alone does not create one.

## Preserve authority and recoverability

- Follow the user's existing authorization. Scope changes, deletions, grants and
  lifecycle policies to the requested resources; do not invent cleanup/retention.
- Managed mutation request IDs are caller-supplied UUIDs. Retain each ID and its
  exact request. A changed request needs a new ID. On lost acknowledgment, inspect
  state/receipt before retrying; transport failure can follow a committed mutation.
- Conditional S3 writes work only for supported standalone PutObject requests.
  Unsupported conditions fail explicitly. Do not bypass a failed precondition or
  convert a rejected conditional operation into an unconditional overwrite.
- Missing peers, stale views, dirty files and revoked grants are real constraints.
  Do not replace degraded/incomplete results with invented healthy defaults.
- Editable workspaces, private immutable caches, authority vaults and S3 data dirs
  are distinct roots. Never point multiple server processes at one data dir or
  adopt a private root as an ordinary editable/synchronized folder.
- Direct-S3 editable eviction is refused. Managed cache eviction requires fresh
  exact retention proof, clean identity, no pin and no active use. One retained
  vault copy is not physical redundancy or S3 Object Lock.
- Process controls terminate only live children owned by the current session.
  Never infer kill authority from a saved PID. Explicit task retry can repeat
  external command effects; cancellation intent is not confirmed termination.
- Keep credentials, private cookies, keys and provider homes out of tool output,
  chat and Git. Presigned URLs grant bearer access. Logs/prompts may contain task
  data; redact relevant content before reporting it.

## Working on the implementation

When modifying MaxIO source, first read the checkout's `AGENTS.md`, `lop.md`,
`gauntlet.md`, `specs/00_system.md` and the relevant domain specification. Honor
its isolated worktree/write gate and regression-first workflow. Shared contract
or domain changes require the recorded PM integration specified there. Run the
domain and architecture gates and the final full gate; a scoped successful MCP
journey does not override a failing repository gate. Use a fresh critic on the
actual artifact before making a Gauntlet claim.

Report the observed result, any material limits and the remaining action. Do not
claim remote worker execution, WAN durability, persistent monitoring or a feature
merely because its command/tool name exists.

## Architecture and complete feature map

### Components and state

| Component | Responsibility | Persistent state / dependency |
|---|---|---|
| `maxio` | S3 HTTP API, console JSON API, embedded Svelte console | One owner process and data directory; Rust/Axum/Tokio |
| `maxio-sync` | Additive ordinary-folder exchange through a chosen standalone S3 endpoint | Local baseline/journal and replacement history in `.maxio-sync/` |
| `maxio-workspace` | Metadata-only discovery, immutable revisions and selected publication/hydration over S3 | Published catalog/blobs plus `.maxio-workspace/` local format 1 |
| `maxio-agent` | Independent local command/Codex/Claude execution on selected copies | Fresh retained run workspace, record, logs and cancellation marker |
| `maxio-fabric` | Single HTTPS managed authority, append-only vault, enrollment/grants, leases, publication and job decisions; also management CLI | Private Unix root, `.maxio-fabric` marker, exclusive lifetime lock, durable state and immutable vault |
| `maxio-worker` | Poll authority, advertise named profiles/cache, execute one admitted attempt at a time, retain/publish outputs | Private `.maxio-worker` root, immutable input cache and retained attempts |
| `mcp/` | Optional Bun stdio adapter for active agents | Owner-local private config; console cookie; optional session-owned service child |

The S3 process needs none of the other executables. A managed authority can run
without S3. Direct-S3 local state and managed editable state (format 2) are distinct;
there is no silent migration, head mirroring or rebinding. Git owns source history
and merges; MaxIO does not merge concurrent source edits.

### S3 and storage

| Feature | How to use | Important boundary |
|---|---|---|
| Bucket operations | List/create/head/delete/location via ordinary S3; MCP list/create/delete | Nonempty/configured buckets can refuse deletion |
| Object operations | Put/get/head/delete/copy, nested keys; MCP write/read/delete/list | Filesystem paths cannot represent every flat S3 key; reserved names/aliases are rejected |
| Listing | ListObjects V1/V2, prefixes/delimiters and continuation behavior | Distributed completeness depends on metadata strategy and responders |
| Batch delete | S3 DeleteObjects | Unsupported selectors/conditions can return 501 before mutation; do not assume every AWS variant |
| Multipart | Initiate/upload parts/list parts/list uploads/complete/abort | Use S3 SDK/CLI; no multipart MCP wrapper |
| Presigned access | S3 SigV4 URLs or MCP `maxio_object_presign` | A URL is bearer access until expiry; MCP expiry 1–604800 seconds |
| Byte ranges | S3 GetObject `Range`, HTTP206 | MCP reads complete bodies, bounded to1MiB |
| Payload integrity | CRC32, CRC32C, SHA-1, SHA-256 verification; SigV4/streaming checks | Failed validation must preserve prior visible data |
| Conditional write | Standalone PutObject `If-None-Match:*` or exact `If-Match` | Failed precondition412; distributed/copy/delete/multipart conditions unsupported |
| Versioning | Bucket enable/suspend, historical get/delete, versions and markers | Existing data is retained as the oldest null version; full AWS suspended/null parity is not promised |
| Lifecycle | Bucket expiration rules through S3, console or MCP | Enabled rules can delete data; clearing/replacing rules is a real policy change |
| Erasure coding | `--erasure-coding`, `--chunk-size`, `--parity-shards` | Chunk hashes and Reed–Solomon parity support recovery; not an at-rest format migration or cluster durability guarantee |
| HTTP integration | S3 XML errors/request IDs, CORS handling, built-in console at `/ui/` | Tested subset of AWS; no full AWS compatibility claim |

Storage uses bucket directories, object files, metadata sidecars, version history
and optional chunk/parity files; there is no required database. Rejected uploads
are staged/validated before visible replacement. Mutation serialization initially
uses a storage-wide lock. Data and JSON sidecars are not one crash-atomic
transaction; copying an actively changing directory is not a consistent snapshot.

S3 Object Lock, retention periods, legal holds and unsupported protection headers
return501. Versioning or a successful read is not proof of enforced retention.
There is no S3 IAM policy engine in this fork: additional S3/console credentials
currently share administration rights. Managed device/path grants are separate.

### Authentication and transport

- S3 requests use AWS SignatureV4 or presigned signing. Console operations use
  opaque cookie sessions; restart invalidates node-local sessions. Logout revokes
  the presented session. Login throttling uses the socket IP.
- Standalone native HTTPS uses a matching certificate/key pair. Default HTTP is
  suitable only for a trusted local/encrypted channel; default bind is0.0.0.0, so
  explicitly choose loopback for local-only operation.
- Native secure-peer mode uses mutual TLS with an exact canonical node identity
  `maxio://HOST:PORT` URI SAN and matching DNS/IP SAN, CA trust, optional fingerprint
  pin/revocation and shared-token authorization. A token alone is not encryption.
- Managed authority transport uses verified HTTPS, individual Ed25519 device keys,
  single-use challenges and revocable sessions. It rereads grants/revocation at
  admission and publication; revocation cannot recall bytes already delivered.
- MCP uses private mode0600 settings. Remote console endpoints require HTTPS;
  plaintext is accepted only for loopback. Redirects are refused. Fabric proof and
  TLS are delegated to the existing Rust client, not reimplemented in TypeScript.

### Peer S3

Explicit peers add deterministic ownership/placement, non-owner forwarding,
replica fanout, persisted retry queues, primary read-repair, rebalance planning and
background replay. Disk/headroom/storage/peer and queue readiness are observable.
Choose durability and metadata semantics deliberately:

| Setting | Meaning |
|---|---|
| `degraded-success` | May acknowledge the primary while reporting degraded replication |
| `strict-quorum` | Requires quorum acknowledgments; failure can still follow a primary side effect |
| `local-node-only` | Lists only local knowledge; not a complete cluster catalog |
| `request-time-aggregation` | Uses responder-aware fan-in; missing/inconsistent peers can fail closed |
| `consensus-index` | Uses persisted view-bound metadata; the name does not implement consensus/Raft |

Static peers are the principal documented journey. Gossip is experimental;
Raft is not implemented. No automatic failover, WAN partition durability, device
pairing or NAT traversal is established. The MCP rebalance tool is only a preview;
it does not apply membership changes. Use the actual secure-peer configuration and
control-plane contracts for an authorized cluster change.

### Folders and direct workspaces

`maxio-sync` polls a chosen standalone endpoint (default15 seconds), probes
conditional-write capability, stages downloads and preserves concurrent differing
edits in conflict siblings. It transfers whole regular files (default64MiB maximum
per file). It is additive: deleting one copy causes a surviving copy to restore it.
There is no deletion propagation, permission/symlink sync, watcher, discovery mesh,
relay, NAT traversal or automatic history pruning.

Direct workspaces publish immutable blobs/manifests and compare an opaque head
ETag. `refresh` is metadata-only; `pull` retrieves selected contents. Local hashes
and baselines protect dirty edits. Offline list/status/pin/unpin operate on local
state; pins cover already hydrated selected files, not future directory members.
A stale publication conflicts; refresh alone is not permission to overwrite dirty
files. Historical pulls preserve logical revision identity. Editable eviction is
explicitly refused because ordinary S3 readback does not enforce retention.

### Managed workspaces, caches and execution

The single managed authority serializes business mutations, durably stores an
append-only vault and authority state, and tracks individually enrolled devices,
key generations, explicit catalog/read/write/job grants, component-aware leases,
epochs/fences and idempotent receipts. Acknowledged authority bytes/state are
fsynced. Restart increases epoch, expires liveness/leases and abandons active
attempts. A stale/disconnected publisher never gains implicit authority.

Editable managed workspaces reuse the same local dirty/baseline/history logic.
Logical deletion is a retained tombstone; restore is another fenced publication.
The immutable private cache is independently disposable only with a fresh exact
retention proof and matching clean content/inode, no pin and no active use. Cache
bytes, editable bytes, attempt inputs and unpublished outputs are distinct. The
vault has no destructive GC API; one retained copy is not physical redundancy.

Workers advertise owner-selected profiles/resources and verified cached inputs.
Eligibility precedes minimizing missing selected input bytes; an explicit worker
is a hard constraint. Each worker has one active attempt, hydrates/verifies exact
inputs, copies them into a fresh task directory and runs the existing adapters.
Resources are admission hints, not OS quotas. Lease/heartbeat loss cancels where
possible and retains work. Retry is explicit and can repeat external effects.
Logs are paged; publication requires the requested output policy, current grants,
head and fence. Local success does not imply publication.

The local runner supports an ordinary command, Codex CLI and Claude Code. Provider
installation/login is external and owner-selected. `doctor` makes no model call.
Codex keeps its native sandbox; the current Claude adapter exposes file tools
without Bash/MCP. Ordinary native commands retain owner OS permissions: cwd copies
and environment filtering are not a hostile-process sandbox. Failed/cancelled
runs, outputs and logs are retained rather than automatically cleaned.

Managed mode is experimental on a private Unix filesystem with one authority.
There is no HA authority, Raft, FUSE mount, transfer resume or background GC. Fixture
provider tests are distinct from authenticated model calls and physical-device/WAN
evidence.

## MCP tool catalog

This catalog describes the implemented adapter. Rediscover tools on connection; live schemas are authoritative. All tool arguments are strict objects. Required fields are listed without `?`; optional/defaulted fields have `?`.

Success is `structuredContent.data`; text content contains the same JSON. Errors use `isError: true` and `structuredContent.error`. Managed success includes `data.response.result` (the canonical Rust ControlResponse), transfer counters, and mutation request IDs.

| Tool | Arguments | Behavior |
|---|---|---|
| `maxio_health` | None | Inspect authoritative MaxIO health |
| `maxio_metrics` | None | Inspect authoritative MaxIO metrics |
| `maxio_topology` | None | Inspect authoritative MaxIO topology |
| `maxio_membership` | None | Inspect authoritative MaxIO membership |
| `maxio_summary` | None | Inspect authoritative MaxIO summary |
| `maxio_placement` | `key`, `replicaCount?`, `chunkIndex?` | Inspect placement for a key and optional chunk |
| `maxio_rebalance` | `key`, `replicaCount?`, `chunkIndex?`, `operation`, `peer` | Preview membership-change placement; does not change membership |
| `maxio_observe` | `seconds`, `interval_seconds?` | Bounded health observations; does not install continuous monitoring |
| `maxio_buckets_list` | None | List buckets and coverage |
| `maxio_bucket_create` | `bucket` | Create a bucket |
| `maxio_bucket_delete` | `bucket` | Delete an empty bucket; backend rejects nonempty buckets |
| `maxio_objects_list` | `bucket`, `prefix?`, `delimiter?` | List objects and coverage; oversized results fail explicitly |
| `maxio_object_write` | `bucket`, `key`, `encoding`, `data`, `content_type?` | Write or overwrite up to 1 MiB inline bytes |
| `maxio_object_read` | `bucket`, `key` | Read complete object as base64, up to 1 MiB |
| `maxio_object_delete` | `bucket`, `key` | Delete object; may create a version delete marker |
| `maxio_folder_create` | `bucket`, `name` | Create logical folder marker |
| `maxio_object_presign` | `bucket`, `key`, `expires?` | Create bearer download URL for intended recipients |
| `maxio_bucket_versioning_get` | `bucket` | Inspect bucket versioning |
| `maxio_bucket_lifecycle_get` | `bucket` | Inspect bucket lifecycle |
| `maxio_bucket_versioning_set` | `bucket`, `enabled` | Enable or suspend versioning |
| `maxio_bucket_lifecycle_set` | `bucket`, `rules` | Replace lifecycle rules; enabled expiration rules may delete data |
| `maxio_versions_list` | `bucket`, `key` | List exact object versions |
| `maxio_version_read` | `bucket`, `key`, `version_id` | Read exact version as base64, up to 1 MiB |
| `maxio_version_delete` | `bucket`, `key`, `version_id` | Permanently delete exact version or marker |
| `maxio_fabric_info` | None | Inspect managed info using configured authenticated RPC |
| `maxio_fabric_devices_list` | None | Inspect managed devices list using configured authenticated RPC |
| `maxio_fabric_workspaces_list` | None | Inspect managed workspaces list using configured authenticated RPC |
| `maxio_fabric_workers_list` | None | Inspect managed workers list using configured authenticated RPC |
| `maxio_fabric_workspace_create` | `request_id`, `name` | Perform managed workspace create using configured authenticated RPC; retain request_id for identical-request recovery |
| `maxio_fabric_workspace_current` | `workspace_id` | Inspect managed workspace current using configured authenticated RPC |
| `maxio_fabric_device_enroll` | `request_id`, `display_name`, `public_key`, `role` | Perform managed device enroll using configured authenticated RPC; retain request_id for identical-request recovery |
| `maxio_fabric_device_revoke` | `request_id`, `device_id` | Perform managed device revoke using configured authenticated RPC; retain request_id for identical-request recovery |
| `maxio_fabric_device_rotate` | `request_id`, `device_id`, `expected_generation`, `public_key` | Perform managed device rotate using configured authenticated RPC; retain request_id for identical-request recovery |
| `maxio_fabric_grants_list` | `device_id?`, `workspace_id?` | Inspect managed grants list using configured authenticated RPC |
| `maxio_fabric_grant_set` | `request_id`, `grant` | Perform managed grant set using configured authenticated RPC; retain request_id for identical-request recovery |
| `maxio_fabric_grant_remove` | `request_id`, `device_id`, `workspace_id` | Perform managed grant remove using configured authenticated RPC; retain request_id for identical-request recovery |
| `maxio_fabric_leases_list` | `workspace_id` | Inspect managed leases list using configured authenticated RPC |
| `maxio_fabric_jobs_list` | `workspace_id?` | Inspect managed jobs list using configured authenticated RPC |
| `maxio_fabric_job_status` | `job_id` | Inspect managed job status using configured authenticated RPC |
| `maxio_fabric_job_explain` | `job_id` | Inspect managed job explain using configured authenticated RPC |
| `maxio_fabric_job_submit` | `job` | Perform managed job submit using configured authenticated RPC; retain request_id for identical-request recovery |
| `maxio_fabric_job_cancel` | `request_id`, `job_id` | Perform managed job cancel using configured authenticated RPC; retain request_id for identical-request recovery |
| `maxio_fabric_job_retry` | `request_id`, `job_id`, `expected_attempt_id` | Perform managed job retry using configured authenticated RPC; retain request_id for identical-request recovery |
| `maxio_fabric_job_logs` | `job_id`, `attempt_id`, `stream`, `offset?`, `max_bytes?` | Inspect managed job logs using configured authenticated RPC |
| `maxio_service_status` | None | Inspect session-owned service child; external servers never owned |
| `maxio_service_logs` | None | Tail last 16 KiB of session-owned child output; may contain application data |
| `maxio_service_start` | None | start only owner-configured child of this MCP session |
| `maxio_service_stop` | None | stop only owner-configured child of this MCP session |
| `maxio_service_restart` | None | restart only owner-configured child of this MCP session |

Tools may carry a host-specific namespace prefix. Match the discovered suffix instead of inventing a tool name. The `maxio_fabric_` tools require configured native HTTPS authority access; `maxio_service_` mutation tools require an owner-selected service command.

## MCP workflows and DTOs

### Connection and response conventions

The host launches Bun with `mcp/src/index.ts` and `MAXIO_MCP_CONFIG`. Discover the
live schemas; hosts can prefix tool names. All fields not in a schema are rejected.
Successful results are under `structuredContent.data`. Binary reads return
`{encoding:"base64",data:"...",size:N}`. Managed results contain a canonical Rust
tagged response under `data.response.result` and transfer counters alongside it.
Errors use `isError:true`, `structuredContent.error.message`, and when available
HTTP `status`, Fabric `code`, and mutation `request_id`.

Do not swallow `Forbidden`, `Conflict`, `NotFound`, `Unauthenticated`, `Capacity` or
`Unavailable`. Backend denial is not a request for a more privileged credential.
Uncertain mutation errors require state/receipt inspection before an explicit retry.

### Storage recipes

These are tool name/argument examples, not shell commands:

```json
{"name":"maxio_bucket_create","arguments":{"bucket":"project-files"}}
{"name":"maxio_object_write","arguments":{"bucket":"project-files","key":"notes/readme.txt","encoding":"utf8","data":"Project notes\n","content_type":"text/plain"}}
{"name":"maxio_objects_list","arguments":{"bucket":"project-files","prefix":"notes/","delimiter":"/"}}
{"name":"maxio_object_read","arguments":{"bucket":"project-files","key":"notes/readme.txt"}}
```

Decode base64 outside the model when possible and compare actual bytes/hashes. An
object write is an overwrite-capable operation. The console adapter does not expose
conditional PutObject; use an authorized S3 client when an atomic precondition is
required. Folder creation writes a logical folder marker, not an OS directory.

Versioning uses `maxio_bucket_versioning_set` with `{bucket,enabled:true|false}`.
`maxio_versions_list` requires both bucket and exact key. Use the returned version
identifier, including the backend's null-version representation, for exact reads
or deletes. Never guess a version from a timestamp alone. Suspend preserves history.

```json
{"name":"maxio_bucket_lifecycle_set","arguments":{"bucket":"project-files","rules":[{"id":"expire-temp","prefix":"tmp/","expirationDays":30,"enabled":true}]}}
```

This replaces the rule set and enables future deletion. Read existing rules first
and preserve rules outside the requested change. `rules:[]` clears the policy.
Configured lifecycle state can prevent empty-bucket deletion; do not silently clear
a user's policy merely to make deletion succeed.

`maxio_object_presign` takes `{bucket,key,expires}`; expiry defaults3600 seconds and
is capped604800. Deliver the returned URL only to intended recipients; it grants
bearer access. Do not invent a custom share-link service from workspace URIs.

MCP body/console limits are1MiB, with an outer encoded result bound. Oversized
listings fail rather than claim completeness. Use narrower prefixes or the normal
paginated S3 API. Large files, multipart, CopyObject, byte ranges and checksum
options use the ordinary S3 client; no wrappers for these are currently provided.

### Diagnostics and lifecycle

Use `maxio_health`/`maxio_summary` for readiness, then relevant metrics, topology,
membership and queue data. Example placement/rebalance preview:

```json
{"name":"maxio_placement","arguments":{"key":"datasets/input.bin","replicaCount":2}}
{"name":"maxio_rebalance","arguments":{"key":"datasets/input.bin","replicaCount":2,"operation":"join","peer":"127.0.0.1:9103"}}
{"name":"maxio_observe","arguments":{"seconds":15,"interval_seconds":3}}
```

`chunkIndex` is optional; rebalance operation is `join|leave`, with an endpoint-shaped
peer identity. The preview does not execute transfers or modify membership.
Observation stops within30 seconds and installs no daemon.

Service start uses only owner-local command/args/cwd. `state:starting` requires a
readiness check. Current-session children can be stopped/restarted; concurrent
transitions are serialized. Reachable external endpoints are reported as external
and protected from stop/restart. MCP disconnect stops its owned child. Log tails
are bounded; application content may still be sensitive despite credential redaction.

### Device and workspace management

Call Fabric info, workspace/device/worker lists to identify actual IDs. For a
mutation, generate a fresh non-nil UUID request ID and retain it with exact fields.
Reusing an ID with changed content is a conflict. MCP echoes mutation IDs on errors.

`maxio_fabric_workspace_create` takes `{request_id,name}`.
`maxio_fabric_workspace_current` takes `{workspace_id}` and returns the managed
catalog, exact manifest and current managed head. Do not substitute a workspace
display name where a UUID is required.

Enrollment takes `{request_id,display_name,public_key,role}`. `public_key` is base64
of the32-byte Ed25519 public key; roles are `owner|device|worker`. Generate the
private key on the target device. Enrollment sends no private key. Revocation
requires the exact device ID; rotation also requires the expected key generation.
The MCP config selects one existing device identity; it does not mint an admin
bypass identity or switch credentials through a tool argument.

A grant is:

```json
{
  "device_id":"<actual-device-uuid>",
  "workspace_id":"<actual-workspace-uuid>",
  "catalog_read":true,
  "read":[{"kind":"tree","path":"datasets"}],
  "write":[{"kind":"tree","path":"results"}],
  "submit_jobs":true
}
```

Scopes are `{kind:"workspace"}`, `{kind:"exact",path}` or `{kind:"tree",path}`.
Catalog permission reveals names in the complete manifest; it is separate from
content read/write rights. `grant_set` replaces that device/workspace grant; inspect
existing rights and preserve unrelated intent. List/remove use exact filters/IDs.

MCP wraps workspace create/current/list and lease listing. Selected publication,
hydration, restore, cache management and lease acquire/renew/release currently use
the authorized CLI, described in the CLI workflows section. They have no arbitrary-path
MCP proxy. Do not claim the49 tools wrap every CLI feature.

### Job submission and recovery

First inspect `maxio_fabric_workers_list` and the current catalog. Select a named
profile advertised by the intended worker, appropriate output scopes and exact
input versions. Fill `maxio_fabric_job_submit`'s `job` from observed values:

```json
{
  "request_id":"<fresh-request-uuid>",
  "workspace_id":"<workspace-uuid>",
  "base":{
    "authority_id":"<authority-uuid>",
    "workspace_id":"<workspace-uuid>",
    "generation":7,
    "revision":{"revision":"<observed-revision-uuid>","sha256":"<observed-manifest-sha256>"}
  },
  "profile":"summarize",
  "inputs":[{
    "path":"datasets/input.txt",
    "revision":{"revision":"<input-revision-uuid>","sha256":"<input-manifest-sha256>"},
    "version":{"sha256":"<exact-content-sha256>","size":1234,"blob":"<catalog-blob-key>"}
  }],
  "output_selectors":[{"kind":"tree","path":"results"}],
  "resources":{"cpu_millis":1000,"memory_bytes":268435456},
  "timeout_seconds":900,
  "required_worker":null,
  "output_policy":"retain",
  "prompt":"Summarize the selected input into results/summary.md."
}
```

Angle-bracket values above describe fields to populate; they are not valid IDs or
hashes. Copy actual canonical values from the catalog rather than fabricating
them. SHA-256 is64 lowercase hex characters. A non-null `required_worker` is a hard
constraint, not a preference. Task requests cannot supply executable paths,
provider homes, arbitrary flags or environment secrets.

`retain` keeps outputs without publishing. `publish` requests fenced publication
within the allowed scopes; successful execution and committed publication remain
separate records. Read status and placement explanation. No eligible worker means
queued work; creating a job does not start a worker.

Use job status/list/explain and paged logs (`job_id`, `attempt_id`,
`stream:stdout|stderr`, `offset`, `max_bytes` up to65536). Advance from the returned
next offset, decode base64 and honor eof/truncation. Cancellation requests are not
terminal success until the attempt state confirms it. Retry requires the previous
attempt ID and a fresh request ID; it creates another attempt and can repeat native
command side effects. A job may be abandoned after authority restart or lease loss.
Keep retained outputs and inspect their state before any explicit recovery action.

## CLI workflows

Use an authorized shell for features without a concrete MCP wrapper. Execute
complete workflows yourself when access exists; routine commands below are not
instructions to send the user back to a terminal. Owner-selected roots, binaries,
credentials and profiles remain explicit. Required CLI `--confirm` flags express
the already-authorized operation; they do not inherently require asking the same
permission again. Do not add them to an unrelated destructive action.

The six executable names are `maxio`, `maxio-sync`, `maxio-workspace`,
`maxio-agent`, `maxio-fabric`, `maxio-worker`. The command reference below is captured
from their actual `--help` output, including subcommands. Paths in examples are
chosen task paths, not suggestions to overwrite an existing root.

### Standalone S3 and native HTTPS

```bash
./target/debug/maxio --address 127.0.0.1 --port 9000 --data-dir /absolute/private/s3-data
```

Use `MAXIO_ACCESS_KEY`/`MAXIO_SECRET_KEY` or the documented MinIO aliases for actual
credentials. The public default pair is `minioadmin`/`minioadmin`; do not describe
that as a private deployment secret. Additional credentials have the same current
S3/console administrative rights. Select region explicitly when clients need it.
One process owns one data root. `/ui/` is optional; agents can operate without it.

Native standalone HTTPS adds `--tls-cert-path` and `--tls-key-path`. Both are
required together. Peer TLS instead uses the peer certificate/key/CA triplet;
the generic pair is not a substitute for secure peer identities. Distribute only
public certificates/CA roots to clients, not CA/server private keys.

For ordinary S3 operations, set existing AWS credential environment variables and
use an endpoint override. Example large-file and ranged/exact-version operations:

```bash
aws --endpoint-url http://127.0.0.1:9000 s3 cp /absolute/input.bin s3://project-files/input.bin
aws --endpoint-url http://127.0.0.1:9000 s3api head-object --bucket project-files --key input.bin
aws --endpoint-url http://127.0.0.1:9000 s3api get-object --bucket project-files --key input.bin --range bytes=0-1023 /absolute/output-prefix.bin
aws --endpoint-url http://127.0.0.1:9000 s3api list-object-versions --bucket project-files --prefix input.bin
```

S3 SDKs/CLI provide multipart, copy, checksums and paginated listing. Only request
the supported S3 subset; Object Lock/retention/legal-hold and unsupported mutation
conditions explicitly fail. A failed quorum write may already exist on the primary.

### Ordinary folder sync

```bash
./target/debug/maxio-sync --local /absolute/shared-folder \
  --endpoint http://127.0.0.1:9000 --bucket device-files --prefix shared --once
```

Create the target bucket beforehand. Omit `--once` for15-second polling. All polling flags are listed in the complete command reference below. Use `--ca-cert` for a private HTTPS CA; its
environment equivalent is `MAXIO_SYNC_CA_CERT`. It is rejected for HTTP.

Each client chooses an ordinary folder, never a server/private cache root. The
conditional-write probe refuses unsafe endpoints; current peer S3 conditional
writes are unsupported, so use a standalone endpoint. Simultaneous divergent edits
preserve conflict siblings. Intentional deletion requires an explicitly planned
all-copy procedure with clients stopped because the protocol is additive; do not
interpret a local remove as propagated deletion intent.

### Direct-S3 selective workspaces

Use explicit endpoint/bucket/workspace and a separate ordinary local root:

```bash
./target/debug/maxio-workspace --root /absolute/project-a --endpoint http://127.0.0.1:9000 --allow-http --bucket workspaces --workspace personal init
./target/debug/maxio-workspace --root /absolute/project-a --endpoint http://127.0.0.1:9000 --allow-http --bucket workspaces --workspace personal publish src datasets
./target/debug/maxio-workspace --root /absolute/project-b --endpoint http://127.0.0.1:9000 --allow-http --bucket workspaces --workspace personal refresh
./target/debug/maxio-workspace --root /absolute/project-b --endpoint http://127.0.0.1:9000 --allow-http --bucket workspaces --workspace personal pull src
./target/debug/maxio-workspace --root /absolute/project-b status
./target/debug/maxio-workspace --root /absolute/project-b pin src
```

`init` refuses an existing published workspace. `refresh` downloads metadata only;
`list` uses cached catalog, `status` hashes actual local files. `pull` selects files
or subtrees, and can select a historical revision. `publish` uses the observed head
and local baseline; it does not silently refresh, merge or overwrite a stale head.
Offline list/status/pin/unpin need no network credential. Direct editable `evict`
is refused; old stages/history remain recoverable. Use HTTPS/private CA for actual
cross-device traffic. Logical `maxio-workspace://` references are identities rather
than temporary HTTPS URLs or permission grants.

### Managed authority and enrollment

Use a dedicated private Unix root and a real certificate/key matching the intended
HTTPS host. Provision a leaf certificate signed by the selected CA; a CA certificate
used as the server leaf can be rejected. Exact TLS provisioning is owner-specific.

```bash
./target/debug/maxio-fabric keygen --key /absolute/private/owner.pem --public-key-out /absolute/private/owner-public.json
./target/debug/maxio-fabric init --root /absolute/private/authority --owner-key /absolute/private/owner.pem --name Owner --endpoint https://127.0.0.1:9443 --ca-cert /absolute/private/ca.crt --client-config /absolute/private/owner.json
./target/debug/maxio-fabric serve --root /absolute/private/authority --bind 127.0.0.1:9443 --tls-cert /absolute/private/server.crt --tls-key /absolute/private/server.key
./target/debug/maxio-fabric --config /absolute/private/owner.json info
```

Generate each new device's private key on that device. Owner enrollment consumes
its public-key JSON and chooses device/worker/owner role. Return client config with
endpoint, authority/vault/device IDs, target-local key path and CA root. These are
not S3 credentials. Owners issue explicit catalog, read/write path and job grants.
Revocation/rotation are real changes; they do not delete retained file history.

`maxio-fabric rpc --request` accepts a bounded regular JSON file containing the
canonical Rust `ControlRequest`. Use concrete MCP/CLI operations first. Advanced
RPC must preserve the exact DTO, request IDs, head/fence/lease and actor authority;
it is not an arbitrary remote command channel.

### Managed workspace, lease and cache operations

```bash
./target/debug/maxio-fabric --config /absolute/private/owner.json workspace create projects
./target/debug/maxio-fabric --config /absolute/private/owner.json workspace list
./target/debug/maxio-fabric --config /absolute/private/owner.json workspace inspect projects
./target/debug/maxio-fabric --config /absolute/private/owner.json workspace pull projects --root /absolute/project --path src
./target/debug/maxio-fabric --config /absolute/private/owner.json workspace publish projects --root /absolute/project --path src
./target/debug/maxio-fabric workspace status --root /absolute/project --verify
```

Without `--path`, managed pull observes metadata only. Publication uses renewable
fenced authority and exact current-head checks. Logical delete/restore are explicit
publications with retained history. Recovery replays the stored publication
operation rather than rerunning a task. Offline status/pins inspect local baselines.
`workspace references` produces exact retained version references for cache work.

Lease acquire/renew/release/list use explicit workspace and component-aware scopes;
never reuse an expired token after restart. Cache inspect/verify, hydrate/import,
pin/unpin, copy and evict use a dedicated private immutable root and exact reference
file. Supported pin behavior uses the command's own flags; no arbitrary file edits.
Evict requires fresh authenticated retention proof plus no pin/active use and clean
content/inode identity. Unexpected filesystem changes fail closed. Cache ownership
locks can exclude concurrent managers; stop the owning worker properly first.

### Local execution

```bash
./target/debug/maxio-agent doctor --adapter codex --executable /absolute/path/to/codex
./target/debug/maxio-agent run --adapter command --executable /usr/bin/python3 \
  --source /absolute/project --input src --output result.txt \
  --records /absolute/private/runs --timeout-seconds 60 \
  -- -c 'from pathlib import Path; Path("result.txt").write_text("done")'
./target/debug/maxio-agent inspect --run /absolute/private/runs/RUN_UUID
./target/debug/maxio-agent cancel --run /absolute/private/runs/ACTIVE_RUN_UUID
```

Select provider adapter, owner-installed absolute executable, explicit
`--provider-home`, prompt file, permission and deadline for Codex/Claude. Provider
adapters reject arbitrary extra flags. Secrets can be selected by environment
variable name, never argument values or source files. Provider commands need their
own existing login/installation. `doctor` checks flags/capabilities without a model
request. Commands default workspace-write; provider defaults read-only.

Run records, hashes, logs and outputs persist even on failure. `published:false`
stays separate from accepted output. Review/copy/publish requested changes through
the appropriate workspace protocol. Cancellation records intent; inspect terminal
state before asserting the process stopped. Never kill a stored PID.

### Managed workers and tasks

Owner-local profiles are a JSON array of `{name,adapter,executable,args,permission,
environment}`. Paths and credentials are chosen by the worker owner. Ordinary
command profiles use workspace-write; provider profiles cannot append arbitrary
arguments. Task requests select the profile name, not those private settings.

```bash
./target/debug/maxio-worker --config /absolute/private/worker.json --root /absolute/private/worker-cache --profiles /absolute/private/profiles.json
./target/debug/maxio-fabric --config /absolute/private/owner.json workers
./target/debug/maxio-fabric --config /absolute/private/owner.json task submit projects --profile summarize --input src --output results --prompt-file /absolute/private/task.txt
./target/debug/maxio-fabric --config /absolute/private/owner.json task status JOB_UUID
./target/debug/maxio-fabric --config /absolute/private/owner.json task explain JOB_UUID
./target/debug/maxio-fabric --config /absolute/private/owner.json task logs JOB_UUID --attempt ATTEMPT_UUID --text
```

`--publish` requests fenced result publication; otherwise outputs are retained.
`--worker` is hard placement. CPU/memory settings are admission hints. A worker
without `--once` polls continuously; `--once` waits for one completed attempt and
does not retry it. Inspect job list/status/explain, paged stdout/stderr logs, cancel
and explicit retry. Retry selects the previous attempt and can repeat side effects.
Provider fixtures, queued tasks and an empty worker list never prove actual model
execution. Logs and prompts may contain private task data.

## Setup, operation and troubleshooting

### Build and connect

Use the checkout's pinned Rust1.94.0 and Bun1.3.10 with locked dependencies. Build
the UI before Rust because the console is embedded in release executables:

```bash
cd /absolute/maxio/ui
bun install --frozen-lockfile
bun run build
cd ..
cargo build --locked --bins
cd mcp
bun install --frozen-lockfile
bun run check
```

The default server is `target/debug/maxio`; optimized builds use
`cargo build --locked --release --bins`. Standalone release needs no Bun runtime;
the separate optional MCP adapter does. Linux builds use system OpenSSL libraries.

Create an owner-owned regular JSON file, mode0600, outside source control:

```json
{
  "console":{"endpoint":"http://127.0.0.1:9000","accessKey":"YOUR_LOCAL_ACCESS_KEY","secretKey":"YOUR_LOCAL_SECRET_KEY"},
  "fabric":{"binary":"/absolute/maxio-fabric","config":"/absolute/private/owner.json"},
  "service":{"command":"/absolute/maxio","args":["--address","127.0.0.1","--port","9000","--data-dir","/absolute/private/s3-data"],"cwd":"/absolute/maxio","autoStart":false}
}
```

The console setting is required; fabric and service are optional. The service's
actual credentials must match the console config. Never package real values in
plugin manifests, skills or Git. Config/executable/cwd paths are absolute.

```bash
chmod 600 /absolute/private/maxio-mcp.json
MAXIO_MCP_CONFIG=/absolute/private/maxio-mcp.json bun /absolute/maxio/mcp/src/index.ts
```

That command speaks MCP on stdin/stdout; it is not an interactive terminal UI.
Register it with the host's stdio MCP integration. In Codex:

```bash
codex mcp add maxio-management \
  --env MAXIO_MCP_CONFIG=/absolute/private/maxio-mcp.json \
  -- /absolute/path/to/bun /absolute/maxio/mcp/src/index.ts
codex mcp get maxio-management --json
```

Registration is distinct from a live tool connection. Verify discovery and a
harmless health/Fabric-info call in the target host or a standard SDK client. A
running chat may retain its original tool inventory; never claim a newly registered
server is already usable in that chat without discovering its tools.

`autoStart:true` probes the console endpoint, attaches to an existing reachable
service, or starts its configured child. It does not start the Fabric authority
or workers. Concurrent service transitions are serialized. A child's `starting`
state is not ready; wait for reachability and health. Disconnect stops owned
children; configure a real OS supervisor separately for always-on services.

### Health and failure diagnosis

| Observation | Meaning and next action |
|---|---|
| Startup refuses config | Check absolute path, regular file, owner UID,0600 mode, valid fields and canonical endpoint; do not print secrets |
| Console401 | Session absent/revoked/restarted; observations refresh the cookie. A failed mutation is not replayed automatically; inspect state before an explicit retry |
| Console429 | Login throttle; reuse the existing connection/session and respect delay rather than creating many clients |
| Console503 / unhealthy storage | Inspect actual health checks, data-dir readability/writability, disk headroom and queues; do not call an open port healthy |
| FabricUnavailable | Missing config, unreachable authority, invalid owner setup or transport failure; distinguish from a legitimate empty catalog |
| FabricUnauthenticated / Forbidden | Check the chosen enrolled identity, current key generation/revocation and explicit grants; do not bypass authorization |
| FabricConflict | Stale head/fence/lease, changed request-ID replay or another concurrent mutation; refresh metadata and preserve edits before choosing recovery |
| FabricNotFound | The exact requested identifier does not exist for this operation; do not substitute another device/job/workspace |
| Capacity | Admission limit reached; preserve existing state and inspect resource usage; no implicit eviction of authority records |
| Object/list response exceeds limit | Narrow prefix or use the normal S3 client; a1MiB adapter limit is not an empty result |
| Serviceexternal / stop refused | Endpoint is owned by another supervisor; inspect/manage through that actual authorized supervisor |
| Jobqueued | Inspect placement explanation, worker availability, profiles, resources and grants; submitting a task does not start a worker |
| Cancelrequested / abandoned | Cancellation or liveness state is not proof a native external side effect never occurred; inspect retained work and actual attempt state |
| Listing degraded / incomplete | Check topology, membership view, metadata strategy and missing responders; avoid destructive decisions based on partial data |

Default disk headroom is256MiB; disabling its gate changes readiness policy rather
than creating free space. Replication/rebalance/membership/metadata repair queues
and workers expose their backlogs/reasons. Inspect whether a backlog is progressing
before intervening. Do not hand-edit queue or authority files to force a green state.

### Backup and recovery

For a consistent S3 backup, quiesce the owning server or use a storage snapshot
with a known consistency boundary, and retain data plus metadata/version/chunk
state together. The filesystem layout has no database, but data and sidecars are
not a complete crash-atomic transaction. Never infer a running directory copy is
a point-in-time backup. Test recovery on a separate root/port before replacing live
state. Do not start two processes over the same root.

For managed state, preserve the authority root and immutable vault together and
keep device keys/configuration backed up under the owner's security policy.
Restart changes epoch and liveness; it does not silently resume old leases/tasks.
An interrupted or uncertain publication is recovered using the retained operation
and identical request/receipt, not by rerunning a possibly effectful job. The
append-only vault is not replicated physical durability and has no automatic GC.

Do not prune `.maxio-sync`, `.maxio-workspace`, attempt directories, logs or cache
files as routine cleanup. Use their supported commands and actual eligibility
rules. Missing remote data is never permission to destroy local recoverable bytes.

### Verification and implementation map

The checkout's instructions are authoritative for development. Relevant sources:
`src/config.rs` for startup, `src/api/router.rs` for S3 routing,
`src/api/console.rs` for management endpoints, `src/fabric/contract.rs` for managed
RPCs, `src/workspace/contract.rs` for revisions/heads, `src/execution/` for adapters,
`src/bin/` for CLI contracts and `mcp/src/server.ts` for actual tool schemas.

```bash
./scripts/domain_check.sh mcp_management
python3 scripts/check_architecture.py
MAXIO_TEST_BINARY=/absolute/maxio/mcp/../target/debug/maxio bun run --cwd mcp smoke
MAXIO_TEST_FABRIC_BINARY=/absolute/maxio-fabric MAXIO_TEST_FABRIC_CONFIG=/absolute/disposable/owner.json bun mcp/scripts/smoke-fabric.ts
./scripts/domain_check.sh all
```

The Fabric smoke mutates uniquely named resources, so use a disposable authority.
The full gate includes architecture, UI, MCP, Rust checks and real-process journeys;
an early failure means later steps did not run. Report failures and scoped passes
separately. Tests do not replace the required independent running-artifact review.

## Complete CLI command reference

These are the actual command and subcommand help contracts of the six Rust executables. Global options (notably Fabric `--config`) remain available on subcommands. Explanations and complete workflows are above. `help`, `--help` and applicable `--version` are read-only discovery; they do not initialize a server or make model calls.

### maxio

```text
S3-compatible object storage server

Usage: maxio [OPTIONS]

Options:
      --port <PORT>                                                                                                  Port to listen on [env: MAXIO_PORT=] [default: 9000]
      --address <ADDRESS>                                                                                            Address to bind to [env: MAXIO_ADDRESS=] [default: 0.0.0.0]
      --internal-bind-addr <INTERNAL_BIND_ADDR>                                                                      Optional dedicated internal control-plane listener address (`host:port`). When set, `/internal/cluster/*` routes are served only on this listener [env: MAXIO_INTERNAL_BIND_ADDR=]
      --data-dir <DATA_DIR>                                                                                          Root data directory [env: MAXIO_DATA_DIR=] [default: ./data]
      --access-key <ACCESS_KEY>                                                                                      Access key (MAXIO_ACCESS_KEY, MINIO_ROOT_USER, MINIO_ACCESS_KEY) [env: MAXIO_ACCESS_KEY=] [default: minioadmin]
      --secret-key <SECRET_KEY>                                                                                      Secret key (MAXIO_SECRET_KEY, MINIO_ROOT_PASSWORD, MINIO_SECRET_KEY) [env: MAXIO_SECRET_KEY=] [default: minioadmin]
      --additional-credentials <ADDITIONAL_CREDENTIALS>                                                              Additional credentials as comma-separated access:secret pairs. Example: "user1:secret1,user2:secret2" [env: MAXIO_ADDITIONAL_CREDENTIALS=]
      --region <REGION>                                                                                              Default region (MAXIO_REGION, MINIO_REGION_NAME, MINIO_REGION) [env: MAXIO_REGION=] [default: us-east-1]
      --node-id <NODE_ID>                                                                                            Node identity; distributed mode requires this node's reachable host:port [env: MAXIO_NODE_ID=] [default: maxio-node]
      --cluster-peers <CLUSTER_PEERS>                                                                                Comma-separated cluster peer addresses (host:port) for distributed bootstrap wiring [env: MAXIO_CLUSTER_PEERS=]
      --membership-protocol <MEMBERSHIP_PROTOCOL>                                                                    Membership protocol strategy for distributed node liveness/convergence contracts [env: MAXIO_MEMBERSHIP_PROTOCOL=] [default: static-bootstrap] [possible values: static-bootstrap, gossip, raft]
      --write-durability-mode <WRITE_DURABILITY_MODE>                                                                Write durability contract for distributed primary-owner writes. - degraded-success: acknowledge primary write and expose quorum diagnostics headers. - strict-quorum: fail writes when quorum acknowledgements are not reached [env: MAXIO_WRITE_DURABILITY_MODE=] [default: degraded-success] [possible values: degraded-success, strict-quorum]
      --metadata-listing-strategy <METADATA_LISTING_STRATEGY>                                                        Distributed metadata/listing authority strategy contract [env: MAXIO_METADATA_LISTING_STRATEGY=] [default: local-node-only]
      --cluster-auth-token <CLUSTER_AUTH_TOKEN>                                                                      Shared internal auth token for trusted node-to-node forwarding/replication traffic. When unset, MaxIO keeps compatibility mode and trusts internal headers by forwarded marker [env: MAXIO_CLUSTER_AUTH_TOKEN=]
      --tls-cert-path <TLS_CERT_PATH>                                                                                Native HTTPS server certificate chain (standalone TLS; exclusive with peer TLS) [env: MAXIO_TLS_CERT_PATH=]
      --tls-key-path <TLS_KEY_PATH>                                                                                  Private key matching the native HTTPS server certificate [env: MAXIO_TLS_KEY_PATH=]
      --cluster-peer-tls-cert-path <CLUSTER_PEER_TLS_CERT_PATH>                                                      Optional mTLS certificate path for internal node-to-node transport identity [env: MAXIO_CLUSTER_PEER_TLS_CERT_PATH=]
      --cluster-peer-tls-key-path <CLUSTER_PEER_TLS_KEY_PATH>                                                        Optional mTLS private-key path for internal node-to-node transport identity [env: MAXIO_CLUSTER_PEER_TLS_KEY_PATH=]
      --cluster-peer-tls-ca-path <CLUSTER_PEER_TLS_CA_PATH>                                                          Optional mTLS trust-store/CA path for internal node-to-node transport identity [env: MAXIO_CLUSTER_PEER_TLS_CA_PATH=]
      --cluster-peer-tls-cert-sha256 <CLUSTER_PEER_TLS_CERT_SHA256>                                                  Optional SHA-256 fingerprint pin for local peer mTLS certificate identity binding. Accepts lowercase/uppercase hex with optional `sha256:` prefix and optional `:` separators [env: MAXIO_CLUSTER_PEER_TLS_CERT_SHA256=]
      --cluster-peer-tls-cert-sha256-revocations <CLUSTER_PEER_TLS_CERT_SHA256_REVOCATIONS>                          Optional comma-separated SHA-256 fingerprint revocation set for peer mTLS certificates. Accepts the same fingerprint format as `MAXIO_CLUSTER_PEER_TLS_CERT_SHA256` [env: MAXIO_CLUSTER_PEER_TLS_CERT_SHA256_REVOCATIONS=]
      --cluster-peer-transport-mode <CLUSTER_PEER_TRANSPORT_MODE>                                                    Peer transport enforcement policy for internal node-to-node requests. - compatibility: require mTLS transport only when mTLS paths are configured. - required: startup requires a shared token and a complete, valid peer TLS identity [env: MAXIO_CLUSTER_PEER_TRANSPORT_MODE=] [default: compatibility] [possible values: compatibility, required]
      --erasure-coding                                                                                               Enable erasure coding with per-chunk integrity checksums [env: MAXIO_ERASURE_CODING=]
      --chunk-size <CHUNK_SIZE>                                                                                      Chunk size in bytes for erasure coding (default 10MB) [env: MAXIO_CHUNK_SIZE=] [default: 10485760]
      --parity-shards <PARITY_SHARDS>                                                                                Number of parity shards for erasure coding (0 = no parity, requires --erasure-coding) [env: MAXIO_PARITY_SHARDS=] [default: 0]
      --min-disk-headroom-bytes <MIN_DISK_HEADROOM_BYTES>                                                            Minimum required free bytes in the data-dir filesystem for `/healthz` readiness. Set to `0` to disable disk-headroom gating [env: MAXIO_MIN_DISK_HEADROOM_BYTES=] [default: 268435456]
      --pending-replication-due-warning-threshold <PENDING_REPLICATION_DUE_WARNING_THRESHOLD>                        Optional warning threshold for due pending-replication targets reported in `/healthz`. When unset, defaults to the runtime replay batch size. Set to `0` to disable this warning class [env: MAXIO_PENDING_REPLICATION_DUE_WARNING_THRESHOLD=]
      --pending-rebalance-due-warning-threshold <PENDING_REBALANCE_DUE_WARNING_THRESHOLD>                            Optional warning threshold for due pending-rebalance transfers reported in `/healthz`. When unset, defaults to the runtime replay batch size. Set to `0` to disable this warning class [env: MAXIO_PENDING_REBALANCE_DUE_WARNING_THRESHOLD=]
      --pending-membership-propagation-due-warning-threshold <PENDING_MEMBERSHIP_PROPAGATION_DUE_WARNING_THRESHOLD>  Optional warning threshold for due pending-membership propagation operations in `/healthz`. When unset, defaults to the runtime replay batch size. Set to `0` to disable this warning class [env: MAXIO_PENDING_MEMBERSHIP_PROPAGATION_DUE_WARNING_THRESHOLD=]
      --pending-metadata-repair-due-warning-threshold <PENDING_METADATA_REPAIR_DUE_WARNING_THRESHOLD>                Optional warning threshold for due pending-metadata repair plans in `/healthz`. When unset, defaults to the runtime replay batch size. Set to `0` to disable this warning class [env: MAXIO_PENDING_METADATA_REPAIR_DUE_WARNING_THRESHOLD=]
  -h, --help                                                                                                         Print help
  -V, --version                                                                                                      Print version
```

### maxio-sync

```text
Additive folder synchronization with a directly reachable S3 peer. No cloud account, discovery service, or relay is used. The bucket must already exist. The peer must enforce conditional PUT requests. Conflicting local edits become .maxio-conflict-* siblings. Deletions are NOT propagated: surviving copies are restored. Stop all sync clients before intentionally removing a file from every copy. Local replacement history is retained under .maxio-sync/ and is never automatically pruned. Whole-file polling; no delta transfer, filesystem permissions, or symlink synchronization.

Usage: maxio-sync [OPTIONS] --local <LOCAL> --endpoint <ENDPOINT> --bucket <BUCKET> --access-key <ACCESS_KEY> --secret-key <SECRET_KEY>

Options:
      --local <LOCAL>
          

      --endpoint <ENDPOINT>
          

      --ca-cert <CA_CERT>
          PEM CA bundle to trust for this HTTPS peer instead of system roots
          
          [env: MAXIO_SYNC_CA_CERT=]

      --bucket <BUCKET>
          

      --prefix <PREFIX>
          [default: ]

      --access-key <ACCESS_KEY>
          [env: MAXIO_ACCESS_KEY]

      --secret-key <SECRET_KEY>
          [env: MAXIO_SECRET_KEY]

      --region <REGION>
          [env: MAXIO_REGION=]
          [default: us-east-1]

      --once
          Run one complete reconciliation and exit; errors return a nonzero status

      --interval-seconds <INTERVAL_SECONDS>
          [default: 15]

      --max-file-mib <MAX_FILE_MIB>
          Maximum size per file. Files are transferred whole and buffered in memory
          
          [default: 64]

  -h, --help
          Print help (see a summary with '-h')
```

### maxio-workspace

```text
Discover, pull and publish selected versioned files through S3

Usage: maxio-workspace [OPTIONS] --root <ROOT> <COMMAND>

Commands:
  init     Create a new empty published workspace. Refuses an existing one
  refresh  Fetch only current catalog metadata; never downloads file contents
  list     List the last observed catalog without contacting storage or hashing files
  status   Verify local file hashes against their baselines and the observed catalog
  pull     Hydrate exact files/directories. Dirty or conflicting local files are retained
  publish  Publish selected local edits against the last observed head. No implicit refresh
  pin      Pin currently hydrated and verified files in the observed snapshot
  unpin    Remove pins explicitly, without deleting local or published files
  evict    Currently refused: backend retention/durability enforcement is not implemented
  help     Print this message or the help of the given subcommand(s)

Options:
      --root <ROOT>            Existing ordinary working directory. Its cache state stays on this device
      --endpoint <ENDPOINT>    Explicit S3 origin, required for network commands [env: MAXIO_WORKSPACE_ENDPOINT=]
      --bucket <BUCKET>        [env: MAXIO_WORKSPACE_BUCKET=]
      --workspace <WORKSPACE>  Logical workspace name within the bucket (not a device or full folder sync) [default: projects]
      --region <REGION>        [default: us-east-1]
      --ca-cert <CA_CERT>      Trust only this PEM CA bundle, preserving hostname verification [env: MAXIO_WORKSPACE_CA_CERT=]
      --allow-http             Permit plaintext HTTP on an explicitly trusted local/encrypted network
  -h, --help                   Print help
  -V, --version                Print version
```

### maxio-workspace init

```text
Create a new empty published workspace. Refuses an existing one

Usage: maxio-workspace --root <ROOT> init [OPTIONS]

Options:
      --endpoint <ENDPOINT>    Explicit S3 origin, required for network commands [env: MAXIO_WORKSPACE_ENDPOINT=]
      --bucket <BUCKET>        [env: MAXIO_WORKSPACE_BUCKET=]
      --workspace <WORKSPACE>  Logical workspace name within the bucket (not a device or full folder sync) [default: projects]
      --region <REGION>        [default: us-east-1]
      --ca-cert <CA_CERT>      Trust only this PEM CA bundle, preserving hostname verification [env: MAXIO_WORKSPACE_CA_CERT=]
      --allow-http             Permit plaintext HTTP on an explicitly trusted local/encrypted network
  -h, --help                   Print help
```

### maxio-workspace refresh

```text
Fetch only current catalog metadata; never downloads file contents

Usage: maxio-workspace --root <ROOT> refresh [OPTIONS]

Options:
      --endpoint <ENDPOINT>    Explicit S3 origin, required for network commands [env: MAXIO_WORKSPACE_ENDPOINT=]
      --bucket <BUCKET>        [env: MAXIO_WORKSPACE_BUCKET=]
      --workspace <WORKSPACE>  Logical workspace name within the bucket (not a device or full folder sync) [default: projects]
      --region <REGION>        [default: us-east-1]
      --ca-cert <CA_CERT>      Trust only this PEM CA bundle, preserving hostname verification [env: MAXIO_WORKSPACE_CA_CERT=]
      --allow-http             Permit plaintext HTTP on an explicitly trusted local/encrypted network
  -h, --help                   Print help
```

### maxio-workspace list

```text
List the last observed catalog without contacting storage or hashing files

Usage: maxio-workspace --root <ROOT> list [OPTIONS]

Options:
      --endpoint <ENDPOINT>    Explicit S3 origin, required for network commands [env: MAXIO_WORKSPACE_ENDPOINT=]
      --bucket <BUCKET>        [env: MAXIO_WORKSPACE_BUCKET=]
      --workspace <WORKSPACE>  Logical workspace name within the bucket (not a device or full folder sync) [default: projects]
      --region <REGION>        [default: us-east-1]
      --ca-cert <CA_CERT>      Trust only this PEM CA bundle, preserving hostname verification [env: MAXIO_WORKSPACE_CA_CERT=]
      --allow-http             Permit plaintext HTTP on an explicitly trusted local/encrypted network
  -h, --help                   Print help
```

### maxio-workspace status

```text
Verify local file hashes against their baselines and the observed catalog

Usage: maxio-workspace --root <ROOT> status [OPTIONS]

Options:
      --endpoint <ENDPOINT>    Explicit S3 origin, required for network commands [env: MAXIO_WORKSPACE_ENDPOINT=]
      --bucket <BUCKET>        [env: MAXIO_WORKSPACE_BUCKET=]
      --workspace <WORKSPACE>  Logical workspace name within the bucket (not a device or full folder sync) [default: projects]
      --region <REGION>        [default: us-east-1]
      --ca-cert <CA_CERT>      Trust only this PEM CA bundle, preserving hostname verification [env: MAXIO_WORKSPACE_CA_CERT=]
      --allow-http             Permit plaintext HTTP on an explicitly trusted local/encrypted network
  -h, --help                   Print help
```

### maxio-workspace pull

```text
Hydrate exact files/directories. Dirty or conflicting local files are retained

Usage: maxio-workspace --root <ROOT> pull [OPTIONS] <PATHS>...

Arguments:
  <PATHS>...  

Options:
      --revision <REVISION>    Read this exact published historical revision; does not rewind the head
      --endpoint <ENDPOINT>    Explicit S3 origin, required for network commands [env: MAXIO_WORKSPACE_ENDPOINT=]
      --bucket <BUCKET>        [env: MAXIO_WORKSPACE_BUCKET=]
      --workspace <WORKSPACE>  Logical workspace name within the bucket (not a device or full folder sync) [default: projects]
      --region <REGION>        [default: us-east-1]
      --ca-cert <CA_CERT>      Trust only this PEM CA bundle, preserving hostname verification [env: MAXIO_WORKSPACE_CA_CERT=]
      --allow-http             Permit plaintext HTTP on an explicitly trusted local/encrypted network
  -h, --help                   Print help
```

### maxio-workspace publish

```text
Publish selected local edits against the last observed head. No implicit refresh

Usage: maxio-workspace --root <ROOT> publish [OPTIONS] <PATHS>...

Arguments:
  <PATHS>...  

Options:
      --endpoint <ENDPOINT>    Explicit S3 origin, required for network commands [env: MAXIO_WORKSPACE_ENDPOINT=]
      --bucket <BUCKET>        [env: MAXIO_WORKSPACE_BUCKET=]
      --workspace <WORKSPACE>  Logical workspace name within the bucket (not a device or full folder sync) [default: projects]
      --region <REGION>        [default: us-east-1]
      --ca-cert <CA_CERT>      Trust only this PEM CA bundle, preserving hostname verification [env: MAXIO_WORKSPACE_CA_CERT=]
      --allow-http             Permit plaintext HTTP on an explicitly trusted local/encrypted network
  -h, --help                   Print help
```

### maxio-workspace pin

```text
Pin currently hydrated and verified files in the observed snapshot

Usage: maxio-workspace --root <ROOT> pin [OPTIONS] <PATHS>...

Arguments:
  <PATHS>...  

Options:
      --endpoint <ENDPOINT>    Explicit S3 origin, required for network commands [env: MAXIO_WORKSPACE_ENDPOINT=]
      --bucket <BUCKET>        [env: MAXIO_WORKSPACE_BUCKET=]
      --workspace <WORKSPACE>  Logical workspace name within the bucket (not a device or full folder sync) [default: projects]
      --region <REGION>        [default: us-east-1]
      --ca-cert <CA_CERT>      Trust only this PEM CA bundle, preserving hostname verification [env: MAXIO_WORKSPACE_CA_CERT=]
      --allow-http             Permit plaintext HTTP on an explicitly trusted local/encrypted network
  -h, --help                   Print help
```

### maxio-workspace unpin

```text
Remove pins explicitly, without deleting local or published files

Usage: maxio-workspace --root <ROOT> unpin [OPTIONS] <PATHS>...

Arguments:
  <PATHS>...  

Options:
      --endpoint <ENDPOINT>    Explicit S3 origin, required for network commands [env: MAXIO_WORKSPACE_ENDPOINT=]
      --bucket <BUCKET>        [env: MAXIO_WORKSPACE_BUCKET=]
      --workspace <WORKSPACE>  Logical workspace name within the bucket (not a device or full folder sync) [default: projects]
      --region <REGION>        [default: us-east-1]
      --ca-cert <CA_CERT>      Trust only this PEM CA bundle, preserving hostname verification [env: MAXIO_WORKSPACE_CA_CERT=]
      --allow-http             Permit plaintext HTTP on an explicitly trusted local/encrypted network
  -h, --help                   Print help
```

### maxio-workspace evict

```text
Currently refused: backend retention/durability enforcement is not implemented

Usage: maxio-workspace --root <ROOT> evict [OPTIONS] <PATHS>...

Arguments:
  <PATHS>...  

Options:
      --endpoint <ENDPOINT>    Explicit S3 origin, required for network commands [env: MAXIO_WORKSPACE_ENDPOINT=]
      --bucket <BUCKET>        [env: MAXIO_WORKSPACE_BUCKET=]
      --workspace <WORKSPACE>  Logical workspace name within the bucket (not a device or full folder sync) [default: projects]
      --region <REGION>        [default: us-east-1]
      --ca-cert <CA_CERT>      Trust only this PEM CA bundle, preserving hostname verification [env: MAXIO_WORKSPACE_CA_CERT=]
      --allow-http             Permit plaintext HTTP on an explicitly trusted local/encrypted network
  -h, --help                   Print help
```

### maxio-agent

```text
Optional local execution with retained workspaces and records. No remote dispatch, automatic publication or source merge. Ordinary executables run with the owner's OS permissions; cwd and environment filtering are not an OS sandbox. Codex keeps its native sandbox. Claude currently exposes file tools only. Logs may contain sensitive task data.

Usage: maxio-agent <COMMAND>

Commands:
  doctor   Check executable availability and safe CLI flags, without login/model calls
  run      Execute once and keep the complete run directory regardless of outcome
  inspect  Read a retained record. Preparing/running is unconfirmed work, never implied success
  cancel   Record a cancellation request; inspect the run for its confirmed outcome
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help
          Print help (see a summary with '-h')
```

### maxio-agent doctor

```text
Check executable availability and safe CLI flags, without login/model calls

Usage: maxio-agent doctor --adapter <ADAPTER> --executable <EXECUTABLE>

Options:
      --adapter <ADAPTER>        
      --executable <EXECUTABLE>  
  -h, --help                     Print help
```

### maxio-agent run

```text
Execute once and keep the complete run directory regardless of outcome

Usage: maxio-agent run [OPTIONS] --executable <EXECUTABLE> --source <SOURCE> --records <RECORDS> [-- <ARGS>...]

Arguments:
  [ARGS]...  Literal command arguments after --. Provider adapters reject arbitrary flags

Options:
      --adapter <ADAPTER>
          [default: command]
      --executable <EXECUTABLE>
          Absolute path to an already installed owner-selected executable
      --source <SOURCE>
          
      --input <INPUTS>
          Explicit file/directory; repeat for several. No inputs means an empty workspace
      --output <OUTPUTS>
          Output candidate allowlist. Missing outputs are allowed; no files are published
      --records <RECORDS>
          Retained run directories are created here, outside the source tree
      --prompt-file <PROMPT_FILE>
          UTF-8 prompt/stdin, at most 1 MiB; its contents are not stored in the record
      --timeout-seconds <TIMEOUT_SECONDS>
          Execution deadline, excluding bounded doctor probes and input preparation [default: 900]
      --env <ENVIRONMENT>
          Copy only this named variable from this process. Values never enter records
      --provider-home <PROVIDER_HOME>
          Explicit trusted CODEX_HOME or CLAUDE_CONFIG_DIR; outside the source tree
      --permission <PERMISSION>
          read-only or workspace-write. Providers default to read-only; commands to workspace-write
  -h, --help
          Print help
```

### maxio-agent inspect

```text
Read a retained record. Preparing/running is unconfirmed work, never implied success

Usage: maxio-agent inspect --run <DIRECTORY>

Options:
      --run <DIRECTORY>  
  -h, --help             Print help
```

### maxio-agent cancel

```text
Record a cancellation request; inspect the run for its confirmed outcome

Usage: maxio-agent cancel --run <DIRECTORY>

Options:
      --run <DIRECTORY>  
  -h, --help             Print help
```

### maxio-fabric

```text
Optional managed workspaces and storage-aware jobs

Usage: maxio-fabric [OPTIONS] <COMMAND>

Commands:
  keygen     Create an individual private Ed25519 key; prints its public key only
  init       Initialize a new private authority; create the owner's client config
  serve      Run the single optional coordinator over native HTTPS
  info       
  device     
  workspace  
  cache      
  lease      
  task       
  workers    
  rpc        Advanced typed control request. Mutation request IDs must be retained for recovery
  help       Print this message or the help of the given subcommand(s)

Options:
      --config <CONFIG>  
  -h, --help             Print help
  -V, --version          Print version
```

### maxio-fabric keygen

```text
Create an individual private Ed25519 key; prints its public key only

Usage: maxio-fabric keygen [OPTIONS] --key <KEY>

Options:
      --config <CONFIG>                  
      --key <KEY>                        
      --public-key-out <PUBLIC_KEY_OUT>  
  -h, --help                             Print help
```

### maxio-fabric init

```text
Initialize a new private authority; create the owner's client config

Usage: maxio-fabric init [OPTIONS] --root <ROOT> --owner-key <OWNER_KEY> --endpoint <ENDPOINT> --client-config <CLIENT_CONFIG>

Options:
      --config <CONFIG>                
      --root <ROOT>                    
      --owner-key <OWNER_KEY>          
      --name <NAME>                    [default: Owner]
      --endpoint <ENDPOINT>            
      --ca-cert <CA_CERT>              
      --client-config <CLIENT_CONFIG>  
  -h, --help                           Print help
```

### maxio-fabric serve

```text
Run the single optional coordinator over native HTTPS

Usage: maxio-fabric serve [OPTIONS] --root <ROOT> --tls-cert <TLS_CERT> --tls-key <TLS_KEY>

Options:
      --config <CONFIG>      
      --root <ROOT>          
      --bind <BIND>          [default: 127.0.0.1:9443]
      --tls-cert <TLS_CERT>  
      --tls-key <TLS_KEY>    
  -h, --help                 Print help
```

### maxio-fabric info

```text
Usage: maxio-fabric info [OPTIONS]

Options:
      --config <CONFIG>  
  -h, --help             Print help
```

### maxio-fabric device

```text
Usage: maxio-fabric device [OPTIONS] <COMMAND>

Commands:
  list    
  enroll  
  grant   
  revoke  
  rotate  
  help    Print this message or the help of the given subcommand(s)

Options:
      --config <CONFIG>  
  -h, --help             Print help
```

### maxio-fabric device list

```text
Usage: maxio-fabric device list [OPTIONS]

Options:
      --config <CONFIG>  
  -h, --help             Print help
```

### maxio-fabric device enroll

```text
Usage: maxio-fabric device enroll [OPTIONS] --name <NAME> --public-key <PUBLIC_KEY>

Options:
      --config <CONFIG>              
      --name <NAME>                  
      --public-key <PUBLIC_KEY>      
      --role <ROLE>                  [default: device] [possible values: device, worker, owner]
      --write-config <WRITE_CONFIG>  
      --key-path <KEY_PATH>          
      --ca-cert <CA_CERT>            
  -h, --help                         Print help
```

### maxio-fabric device grant

```text
Usage: maxio-fabric device grant [OPTIONS] --device <DEVICE> --workspace <WORKSPACE>

Options:
      --config <CONFIG>        
      --device <DEVICE>        
      --workspace <WORKSPACE>  
      --catalog                
      --read <READ>            
      --write <WRITE>          
      --submit-jobs            
  -h, --help                   Print help
```

### maxio-fabric device revoke

```text
Usage: maxio-fabric device revoke [OPTIONS] --device <DEVICE>

Options:
      --config <CONFIG>  
      --device <DEVICE>  
      --confirm          
  -h, --help             Print help
```

### maxio-fabric device rotate

```text
Usage: maxio-fabric device rotate [OPTIONS] --device <DEVICE> --public-key <PUBLIC_KEY> --expected-generation <EXPECTED_GENERATION>

Options:
      --config <CONFIG>                            
      --device <DEVICE>                            
      --public-key <PUBLIC_KEY>                    
      --expected-generation <EXPECTED_GENERATION>  
      --confirm                                    
  -h, --help                                       Print help
```

### maxio-fabric workspace

```text
Usage: maxio-fabric workspace [OPTIONS] <COMMAND>

Commands:
  create               
  list                 
  inspect              Metadata-only current catalog or exact immutable revision
  pull                 Observe current metadata; selected bytes move only if --path is provided
  publish              Publish explicit local selections under renewable fenced authority
  recover-publication  Replay one retained publication request after an uncertain response; never rerun a task
  status               Inspect persisted metadata/local baseline without credentials or a connection
  pin                  
  delete               Explicit global logical deletion. Vault history and local edits remain retained
  restore              
  references           Save exact version references for offline pin/copy and explicit cache operations
  help                 Print this message or the help of the given subcommand(s)

Options:
      --config <CONFIG>  
  -h, --help             Print help
```

### maxio-fabric workspace create

```text
Usage: maxio-fabric workspace create [OPTIONS] <NAME>

Arguments:
  <NAME>  

Options:
      --config <CONFIG>  
  -h, --help             Print help
```

### maxio-fabric workspace list

```text
Usage: maxio-fabric workspace list [OPTIONS]

Options:
      --config <CONFIG>  
  -h, --help             Print help
```

### maxio-fabric workspace inspect

```text
Metadata-only current catalog or exact immutable revision

Usage: maxio-fabric workspace inspect [OPTIONS] <WORKSPACE>

Arguments:
  <WORKSPACE>  

Options:
      --config <CONFIG>      
      --revision <REVISION>  
      --sha256 <SHA256>      
  -h, --help                 Print help
```

### maxio-fabric workspace pull

```text
Observe current metadata; selected bytes move only if --path is provided

Usage: maxio-fabric workspace pull [OPTIONS] --root <ROOT> <WORKSPACE>

Arguments:
  <WORKSPACE>  

Options:
      --config <CONFIG>      
      --root <ROOT>          
      --path <PATH>          
      --revision <REVISION>  
      --sha256 <SHA256>      
  -h, --help                 Print help
```

### maxio-fabric workspace publish

```text
Publish explicit local selections under renewable fenced authority

Usage: maxio-fabric workspace publish [OPTIONS] --root <ROOT> --path <PATH> <WORKSPACE>

Arguments:
  <WORKSPACE>  

Options:
      --config <CONFIG>  
      --root <ROOT>      
      --path <PATH>      
  -h, --help             Print help
```

### maxio-fabric workspace recover-publication

```text
Replay one retained publication request after an uncertain response; never rerun a task

Usage: maxio-fabric workspace recover-publication [OPTIONS] --root <ROOT> --operation <OPERATION>

Options:
      --config <CONFIG>        
      --root <ROOT>            
      --operation <OPERATION>  
  -h, --help                   Print help
```

### maxio-fabric workspace status

```text
Inspect persisted metadata/local baseline without credentials or a connection

Usage: maxio-fabric workspace status [OPTIONS] --root <ROOT>

Options:
      --config <CONFIG>  
      --root <ROOT>      
      --verify           
  -h, --help             Print help
```

### maxio-fabric workspace pin

```text
Usage: maxio-fabric workspace pin [OPTIONS] --root <ROOT> --path <PATH>

Options:
      --config <CONFIG>  
      --root <ROOT>      
      --path <PATH>      
      --unpin            
  -h, --help             Print help
```

### maxio-fabric workspace delete

```text
Explicit global logical deletion. Vault history and local edits remain retained

Usage: maxio-fabric workspace delete [OPTIONS] --path <PATH> <WORKSPACE>

Arguments:
  <WORKSPACE>  

Options:
      --config <CONFIG>  
      --path <PATH>      
      --confirm          
  -h, --help             Print help
```

### maxio-fabric workspace restore

```text
Usage: maxio-fabric workspace restore [OPTIONS] --path <PATH> --revision <REVISION> --sha256 <SHA256> <WORKSPACE>

Arguments:
  <WORKSPACE>  

Options:
      --config <CONFIG>            
      --path <PATH>                
      --revision <REVISION>        
      --sha256 <SHA256>            
      --source-path <SOURCE_PATH>  
      --confirm                    
  -h, --help                       Print help
```

### maxio-fabric workspace references

```text
Save exact version references for offline pin/copy and explicit cache operations

Usage: maxio-fabric workspace references [OPTIONS] --path <PATH> <WORKSPACE>

Arguments:
  <WORKSPACE>  

Options:
      --config <CONFIG>  
      --path <PATH>      
      --output <OUTPUT>  
  -h, --help             Print help
```

### maxio-fabric cache

```text
Usage: maxio-fabric cache [OPTIONS] <COMMAND>

Commands:
  inspect  
  hydrate  
  import   
  pin      
  copy     
  evict    
  help     Print this message or the help of the given subcommand(s)

Options:
      --config <CONFIG>  
  -h, --help             Print help
```

### maxio-fabric cache inspect

```text
Usage: maxio-fabric cache inspect [OPTIONS] --root <ROOT>

Options:
      --config <CONFIG>  
      --root <ROOT>      
      --verify           
  -h, --help             Print help
```

### maxio-fabric cache hydrate

```text
Usage: maxio-fabric cache hydrate [OPTIONS] --root <ROOT> --references <REFERENCES>

Options:
      --config <CONFIG>          
      --root <ROOT>              
      --references <REFERENCES>  
  -h, --help                     Print help
```

### maxio-fabric cache import

```text
Usage: maxio-fabric cache import [OPTIONS] --root <ROOT> --references <REFERENCES> --source <SOURCE>

Options:
      --config <CONFIG>          
      --root <ROOT>              
      --references <REFERENCES>  
      --source <SOURCE>          
  -h, --help                     Print help
```

### maxio-fabric cache pin

```text
Usage: maxio-fabric cache pin [OPTIONS] --root <ROOT> --references <REFERENCES>

Options:
      --config <CONFIG>          
      --root <ROOT>              
      --references <REFERENCES>  
      --unpin                    
  -h, --help                     Print help
```

### maxio-fabric cache copy

```text
Usage: maxio-fabric cache copy [OPTIONS] --root <ROOT> --references <REFERENCES> --destination <DESTINATION>

Options:
      --config <CONFIG>            
      --root <ROOT>                
      --references <REFERENCES>    
      --destination <DESTINATION>  
  -h, --help                       Print help
```

### maxio-fabric cache evict

```text
Usage: maxio-fabric cache evict [OPTIONS] --root <ROOT> --references <REFERENCES>

Options:
      --config <CONFIG>          
      --root <ROOT>              
      --references <REFERENCES>  
      --confirm                  
  -h, --help                     Print help
```

### maxio-fabric lease

```text
Usage: maxio-fabric lease [OPTIONS] <COMMAND>

Commands:
  list     
  acquire  
  renew    
  release  
  help     Print this message or the help of the given subcommand(s)

Options:
      --config <CONFIG>  
  -h, --help             Print help
```

### maxio-fabric lease list

```text
Usage: maxio-fabric lease list [OPTIONS] <WORKSPACE>

Arguments:
  <WORKSPACE>  

Options:
      --config <CONFIG>  
  -h, --help             Print help
```

### maxio-fabric lease acquire

```text
Usage: maxio-fabric lease acquire [OPTIONS] --scope <SCOPE> <WORKSPACE>

Arguments:
  <WORKSPACE>  

Options:
      --config <CONFIG>  
      --scope <SCOPE>    
      --ttl <TTL>        [default: 60]
      --save <SAVE>      
  -h, --help             Print help
```

### maxio-fabric lease renew

```text
Usage: maxio-fabric lease renew [OPTIONS] --lease <LEASE> <WORKSPACE>

Arguments:
  <WORKSPACE>  

Options:
      --config <CONFIG>  
      --lease <LEASE>    
      --ttl <TTL>        [default: 60]
  -h, --help             Print help
```

### maxio-fabric lease release

```text
Usage: maxio-fabric lease release [OPTIONS] --lease <LEASE> <WORKSPACE>

Arguments:
  <WORKSPACE>  

Options:
      --config <CONFIG>  
      --lease <LEASE>    
  -h, --help             Print help
```

### maxio-fabric task

```text
Usage: maxio-fabric task [OPTIONS] <COMMAND>

Commands:
  submit   
  status   
  list     
  explain  
  cancel   
  retry    
  logs     
  help     Print this message or the help of the given subcommand(s)

Options:
      --config <CONFIG>  
  -h, --help             Print help
```

### maxio-fabric task submit

```text
Usage: maxio-fabric task submit [OPTIONS] --profile <PROFILE> <WORKSPACE>

Arguments:
  <WORKSPACE>  

Options:
      --config <CONFIG>              
      --profile <PROFILE>            
      --input <INPUT>                
      --output <OUTPUT>              
      --worker <WORKER>              
      --timeout <TIMEOUT>            [default: 3600]
      --cpu-millis <CPU_MILLIS>      [default: 1000]
      --memory-bytes <MEMORY_BYTES>  [default: 268435456]
      --prompt-file <PROMPT_FILE>    
      --publish                      
  -h, --help                         Print help
```

### maxio-fabric task status

```text
Usage: maxio-fabric task status [OPTIONS] <JOB>

Arguments:
  <JOB>  

Options:
      --config <CONFIG>  
  -h, --help             Print help
```

### maxio-fabric task list

```text
Usage: maxio-fabric task list [OPTIONS]

Options:
      --config <CONFIG>        
      --workspace <WORKSPACE>  
  -h, --help                   Print help
```

### maxio-fabric task explain

```text
Usage: maxio-fabric task explain [OPTIONS] <JOB>

Arguments:
  <JOB>  

Options:
      --config <CONFIG>  
  -h, --help             Print help
```

### maxio-fabric task cancel

```text
Usage: maxio-fabric task cancel [OPTIONS] <JOB>

Arguments:
  <JOB>  

Options:
      --config <CONFIG>  
  -h, --help             Print help
```

### maxio-fabric task retry

```text
Usage: maxio-fabric task retry [OPTIONS] --previous-attempt <PREVIOUS_ATTEMPT> <JOB>

Arguments:
  <JOB>  

Options:
      --config <CONFIG>                      
      --previous-attempt <PREVIOUS_ATTEMPT>  
  -h, --help                                 Print help
```

### maxio-fabric task logs

```text
Usage: maxio-fabric task logs [OPTIONS] --attempt <ATTEMPT> <JOB>

Arguments:
  <JOB>  

Options:
      --attempt <ATTEMPT>  
      --config <CONFIG>    
      --stderr             
      --offset <OFFSET>    [default: 0]
      --text               Print the decoded log page directly; omit for JSON pagination and transfer metadata
  -h, --help               Print help
```

### maxio-fabric workers

```text
Usage: maxio-fabric workers [OPTIONS]

Options:
      --config <CONFIG>  
  -h, --help             Print help
```

### maxio-fabric rpc

```text
Advanced typed control request. Mutation request IDs must be retained for recovery

Usage: maxio-fabric rpc [OPTIONS] --request <REQUEST>

Options:
      --config <CONFIG>    
      --request <REQUEST>  
  -h, --help               Print help
```

### maxio-worker

```text
Optional single-slot worker with a private immutable input cache and retained attempt directories. The coordinator chooses placement and authorizes publication. Profiles contain local executable paths and explicit environment values; tasks cannot select them over the wire. Native commands retain the owner's OS permissions. No automatic retry, provider login or cleanup is performed.

Usage: maxio-worker [OPTIONS] --config <CONFIG> --root <ROOT> --profiles <PROFILES>

Options:
      --config <CONFIG>
          JSON ClientConfig with HTTPS endpoint, authority/vault/device IDs and key path

      --root <ROOT>
          Dedicated private cache/attempt root, initially empty or previously bound

      --profiles <PROFILES>
          JSON array of local profiles: name, adapter, executable, args, permission, environment

      --display-name <DISPLAY_NAME>
          [default: "MaxIO worker"]

      --cpu-millis <CPU_MILLIS>
          Advertised capacity; it is an admission hint, not an OS resource quota
          
          [default: 1000]

      --memory-bytes <MEMORY_BYTES>
          [default: 1073741824]

      --poll-ms <POLL_MS>
          [default: 1000]

      --renew-ms <RENEW_MS>
          [default: 5000]

      --lease-seconds <LEASE_SECONDS>
          [default: 60]

      --once
          Keep polling until one attempt completes, then exit; never retry a job

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```
