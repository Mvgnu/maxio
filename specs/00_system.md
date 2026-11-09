---
name: system
description: PM-owned product, ownership, and shared-contract decisions for MaxIO
---

# MaxIO system contract

MaxIO stores and moves data on machines the operator chooses. Standalone storage,
optional workspaces and optional execution have independent entry points. The
simplest one must remain simple.

| Journey | User outcome | Current scope |
|---|---|---|
| [Standalone S3](journeys/standalone_s3.md) | One process, one data directory, an ordinary S3 client | Default server mode; embedded console; no cluster configuration |
| [Peer S3](journeys/peer_s3.md) | An S3 endpoint over explicitly configured storage peers | Experimental static peers, replication, forwarding and honest unavailable states |
| [Device sync](journeys/device_sync.md) | Ordinary folders exchange files through a chosen device | Optional client using a standalone peer bucket; conflict preservation; no delete propagation |
| [Selective workspace](journeys/selective_workspace.md) | Discover published files and retrieve only selected contents | Experimental immutable revisions, conditional publication, local baselines and pins; eviction refused |
| [Local agents](journeys/local_agents.md) | Run an executable on selected copies and inspect proposed results | Independent command/Codex/Claude adapters; separate publication |
| [Managed workspaces and workers](journeys/managed_fabric_usage.md) | Enroll devices, publish under leases, reclaim a private cache and execute near selected data | Experimental single HTTPS authority with append-only local vault, explicit grants and separately running workers; bounded B–E evidence belongs in the dated review |

There is no required hosted service, cloud account, telemetry endpoint, relay, or
discovery provider. A peer may be a laptop, server, or NAS under the operator's
control. The initial device-sync topology uses a selected peer as an object
endpoint; it is not an automatically paired, equal-peer mesh. A storage cluster
and synchronized directories are different consistency problems.

## Architecture that exists

One Rust crate serves S3 HTTP, a management API, and embedded Svelte assets. The
storage implementation persists files, metadata sidecars, version history and
optional erasure-coded chunks. Cluster code adds membership, placement, forwarding,
replication and metadata reconciliation. The optional `maxio-sync` client talks
through the S3 HTTP contract, not private storage paths.

The optional `maxio-workspace` client adds immutable logical revisions and selective
transfers through S3. The independent `maxio-agent` executable prepares selected
input copies and supervises a local command or coding CLI. The optional
`maxio-fabric` authority reuses canonical workspace versions for its own managed
catalog, grants and fenced publication. `maxio-worker` reuses the local execution
adapters and verified immutable cache for remote claims. None participates in S3
startup. The direct-S3 and managed modes have distinct publication authorities;
they do not silently mirror heads or migrate existing workspace state.

Keep these boundaries before considering crate extraction. Source moves must
remove a concrete responsibility tangle, not merely distribute a long file into
arbitrary numbered fragments. Unit tests may live beside their module or in a
named adjacent test module. Cross-process acceptance lives in scripts/tests.

| Domain | Spec |
|---|---|
| Runtime and process lifecycle | [runtime_platform](domains/runtime_platform.md) |
| Persistence and placement | [storage_engine](domains/storage_engine.md) |
| Peer identity and transport | [cluster_transport_security](domains/cluster_transport_security.md) |
| Listing and reconciliation | [cluster_metadata_plane](domains/cluster_metadata_plane.md) |
| Signed S3 authentication | [s3_auth_sigv4](domains/s3_auth_sigv4.md) |
| S3 HTTP behavior | [s3_api_surface](domains/s3_api_surface.md) |
| Management HTTP behavior | [console_api](domains/console_api.md) |
| Embedded console | [web_console_ui](domains/web_console_ui.md) |
| Ordinary directory synchronization | [device_sync](domains/device_sync.md) |
| Verification infrastructure | [quality_harness](domains/quality_harness.md) |
| Published workspace catalog | [workspace_catalog](domains/workspace_catalog.md) |
| Local workspace state and hydration | [workspace_cache](domains/workspace_cache.md) |
| Optional local agent execution | [agent_execution](domains/agent_execution.md) |
| Managed catalog, leases and job authority | [fabric_authority](domains/fabric_authority.md) |
| Managed device authentication, HTTPS and CLI | [fabric_transport](domains/fabric_transport.md) |
| Remote workers and private immutable cache | [worker_execution](domains/worker_execution.md) |

## Shared contracts and ownership

The checked-in Rust types are authoritative. These are existing interfaces, not
permission to create equivalent types in each domain:

- `src/storage/mod.rs`: `ObjectMeta`, `BucketMeta`, checksums, stream/result/error
  types, and `ObjectWriteCondition`.
- `src/cluster/mod.rs` and its public types: peer identity, authentication,
  forwarding envelopes and transport-attestation decisions.
- `src/metadata/mod.rs`: metadata queries, coverage, consistency, persisted state
  and reconciliation contracts.
- `src/server.rs`: `AppState` and runtime topology. Runtime owns implementation;
  changes to fields or observable wire meanings require a PM ruling.
- `src/config.rs`: CLI/environment compatibility. Runtime owns implementation;
  changed defaults or new modes are product decisions.
- S3 status/XML and console JSON are public contracts even when not in a file
  named `contract.rs`. Frontend DTOs must reflect the server, not invent defaults.

PM-owned paths are declared in `scripts/check_architecture.py`: root manifests,
lockfiles, toolchain files, CI/release/Docker configuration, entrypoint instructions,
the system and journey specs, architecture enforcement, `src/lib.rs`, and the
public module facades above. A domain's own spec is editable for accuracy, but
enlarging `paths` or weakening its bar is a PM decision. Initial governance adoption
is a PM integration across all domains, not a normal single bubble.

Permitted lower-level dependency direction is enforced for storage, metadata and
cluster modules. They do not import HTTP handler/runtime modules. Device sync
consumes HTTP and signing primitives, not storage internals. The current S3 auth
middleware depends on `AppState`; that existing adapter is not an excuse to move
runtime dependencies into signing primitives.

## Non-negotiable data behavior

1. A rejected or interrupted upload does not erase a prior valid object.
2. Conditional comparison and mutation are serialized. Unsupported conditions
   fail explicitly before mutation; they never silently become ordinary PUTs.
3. Object/version paths cannot address internal metadata or another object's files.
4. Missing peers and partial listings are unavailable/degraded states, not complete
   data. `degraded-success` and `strict-quorum` are different durability policies.
5. Sync preserves both concurrent differing contents and stages local replacements.
   The MVP never propagates deletions and never offers unsafe unconditional overwrite.
6. A single process owns a server data directory. Do not point two server processes
   at the same path. Storage locking in this milestone is in-process, not a shared
   filesystem transaction protocol.

## Security and compatibility boundaries

S3 credentials currently share administrative capabilities; its endpoint has no
IAM policy engine. The separate managed authority has explicit per-device
catalog/read/write/job grants and individual keys. Plain S3 HTTP belongs on a trusted
local/encrypted channel. Optional native HTTPS protects standalone traffic; the
secure-peer triplet provides native mutual TLS with exact node identity binding.
Shared tokens are an additional authorization factor, not transport encryption.
Certificate provisioning and revocation remain explicit operator responsibilities.

S3 support is a tested subset. Path-style requests are supported. The inherited
filesystem format cannot represent every S3 key; reserved sidecar names and path
aliases are rejected. No on-disk migration occurs in the recovery wave. Data and
sidecar replacement is not a complete crash-atomic transaction. Keep recovery and
format migration as explicit future work, not claims inferred from green tests.

## PM rulings for the recovery wave (2026-10-23)

- Preserve Rust/Bun layout; restore tracked specs and real write gates. Remove the
  append-only roadmap's authority; prior detail remains in Git history.
- Storage owns staging, validation and mutation serialization. Approve additive
  `ObjectWriteCondition::{IfAbsent, IfMatch(String)}` and
  `put_object_conditional(...) -> Result<Option<PutResult>, StorageError>`.
  `None` means a failed precondition; existing storage method signatures stay.
- S3 maps standalone PutObject conditions to that API and returns 412 on failure.
  Cluster forwarding, copy, DELETE and multipart conditions remain explicitly unsupported
  until they can preserve the same guarantee end to end.
- Device sync is an optional companion binary with a separate spec. Require a
  conditional-write capability probe and explicit target. Defer delete propagation,
  watchers, NAT traversal, pairing and full mesh synchronization.
- Peer runtime may canonicalize identities and isolate local health snapshots to
  prevent recursive peer health probes. Real two-process behavior is the criterion.
- Verify signed bytes before dispatching any mutation. Approve `tempfile` as a
  normal dependency for bounded-memory authentication staging, and real AWS chunk
  signatures in the existing client fixtures. The auth repair cycle may edit
  `tests/integration/helpers.rs` and the three streaming cases in `core_tests.rs`;
  those are explicit PM integration grants, not a permanent expansion of auth.
- Preserve pre-versioning bytes as the oldest null version. Storage, S3 marker
  handling and metadata ordering implement the same rule; no format rewrite.
- Health may run a bounded authenticated bucket fan-in and add explicit probe
  scope/status fields. It must not label TCP liveness as metadata coverage.
- Each integration test module belongs to the domain it exercises. Harness owns
  shared signing/server fixtures and the test entrypoint; shared fixture changes
  need coordination, not blanket ownership of every domain's tests.
- Stop the native inbound-peer-identity and session-revocation work for this wave
  with observed gaps in their specs. Neither receives a broader security pass.
- Remove runtime third-party font requests. Build/release belongs to this fork;
  do not publish or recommend upstream images as if they contain this work.

## PM ruling: secure peers and revocable sessions (2026-10-23)

This wave reopens the two explicit security stops above. Its acceptance artifacts
are real HTTPS processes and replay/impersonation attempts. Historical review
verdicts stay in their original record until superseded by new evidence.

### Transport contracts

- Add optional `Config::{tls_cert_path,tls_key_path}` with matching `--tls-*-path`
  flags and `MAXIO_TLS_*_PATH` variables. This pair enables ordinary native HTTPS.
  The generic pair and existing peer TLS certificate/key/CA triplet are mutually
  exclusive. The generic pair is standalone-only; configured peers require the peer
  triplet so advertised HTTPS and outbound transport cannot disagree. No TLS flags
  means the existing standalone HTTP default.
- A complete peer triplet enables native HTTPS on the public node endpoint and
  dedicated internal listener. The public listener requests optional client
  certificates so ordinary S3/console clients work; internal traffic still requires
  verified peer identity. A dedicated internal listener requires client certificates.
- Any partial family, invalid certificate/key/CA, or required peer mode without
  both a token and complete peer triplet fails before storage initialization.
- Secure certificates contain exactly one canonical `maxio://HOST:PORT` URI SAN,
  including brackets for IPv6. It must equal the canonical node ID, have an explicit
  port and contain no path, query, fragment or user information. Other URI schemes
  do not establish MaxIO identity. DNS/IP SANs, chain, validity, key correspondence
  and standard TLS signature verification remain independent requirements.
- Peer trust comes only from the configured CA bundle, plus optional fingerprint
  restrictions and revocations. Disable outbound internal redirects and proxy
  discovery. No insecure hostname/certificate switch is authorized.
- Freeze these additions in `cluster::transport_identity`: `PeerTlsConfig<'a>`
  (node ID, certificate/key/CA paths and `PeerCertificatePolicy`), private-state
  `VerifiedPeerIdentity` with `node_id()`, `peer_node_identity_uri`,
  `build_peer_tls_acceptor`, `verified_peer_identity_from_tls`, and
  `build_peer_mtls_http_client(config, expected_node_id, connect_timeout, timeout)`.
  The identity helper returns `Result<Option<VerifiedPeerIdentity>, String>`;
  missing client certificates return `None`, failed verification returns an error.
  The client verifies the expected full identity during its actual handshake.
- Runtime derives connection metadata from the completed TLS stream. Internal
  routes or protocol headers require a known nonlocal peer certificate when peer
  TLS is active. Bind forwarding's last hop and join claims to that identity before
  mutation. Shared-token and signed-request authorization remain additional checks.
  A separate TLS preflight is never authorization for a later connection.
- Runtime exports the crate-private `TlsConnection` marker, installed only for
  native TLS connections, and preserves socket `ConnectInfo` for login throttling.
  Bound concurrent handshakes and their duration; graceful shutdown must wake both
  listeners reliably. Invalid programmatic configs remain inspectable in unit
  health fixtures, but cannot start a live server.
- Approve `tokio-openssl`, direct Rustls with its existing Ring provider, and
  Reqwest's manual-root Rustls feature. Cluster code must remain independent of
  runtime configuration and HTTP handlers.
- Inbound peer extraction must also match the certificate's DNS/IP SAN to the
  host in its canonical MaxIO URI; an allowed URI does not waive that check.
  Approve direct `openssl-sys` and `foreign-types` at their already locked versions
  for a small, documented wrapper around OpenSSL's standard name-check functions,
  with subject/CN fallback disabled. Do not implement a second hostname matcher.

### Session contract

- Add `AppState::console_sessions: Arc<ConsoleSessionStore>`; console owns the
  store exported from `api::console`. Each process constructs a new empty registry.
- Use 256-bit cryptographic random opaque tokens, stored only as verifiers with
  account, credential binding, issuance and expiry. Maximum 4,096 active sessions;
  prune expired entries before issuance, then report full capacity explicitly.
- Logout revokes that session. Independent logins survive; restart invalidates all
  old cookies. Preserve existing frontend JSON fields and seven-day absolute expiry.
  Credential removal/change rejects and removes affected entries. Reject old
  deterministic cookies. Revocation governs subsequent admission, not work already
  admitted before logout.
- Login throttling uses socket IP, not caller-controlled forwarding headers.
  Native TLS always produces Secure cookies; forwarded-proto may only tighten that
  setting, never downgrade an actual TLS connection.

### Implementation bubbles and integration

Cluster owns its transport implementation and adjacent regressions. Runtime owns
listeners, startup validation, connection gates, background/control clients and
`scripts/smoke_secure_peers.py`. Console owns session/auth implementation and console
tests. The PM seeds shared fields and fixture literals before isolation and owns
API transport adapter/call-site integration in `api/object/peer_transport.rs`,
`api/object/service.rs`, `api/list.rs`, `api/bucket.rs`, and
`api/console/storage.rs`. The console builder does not edit that last file during
this wave. PM also owns journey documentation and adding secure smoke to the full
gate. These are explicit integration grants, not expanded permanent ownership.

### HTTPS for the optional sync client

The device-sync bubble may add `SyncOptions::ca_cert: Option<PathBuf>`, exposed as
`maxio-sync --ca-cert` / `MAXIO_SYNC_CA_CERT`. A supplied PEM bundle becomes the
explicit server trust roots; ordinary hostname, validity and chain checks remain
enabled. No supplied bundle retains the normal system trust configuration. Reject
the option for HTTP endpoints and reject unreadable, empty or invalid bundles before
local journal creation. Do not add an insecure verification switch. Exercise the
existing two-folder conflict/restart journey over native standalone HTTPS, including
wrong-CA rejection. Runtime may add optional TLS contexts to the shared smoke Node
and S3 helpers so the journey uses the same signing and process fixtures.

## Evidence and next decisions

Use [Gauntlet](../gauntlet.md) and dated [review records](reviews/). A successful
loopback scenario establishes its stated property only. Production durability,
power-loss behavior, internet peer security, WAN partitions and all-device UX
require additional evidence. The next wave is chosen by the largest observed gap,
not a list of previously imagined distributed features.


## PM ruling: optional workspace and execution foundation (2026-10-23)

PR #2 is merged at `7afd102bd7013b55e17f1642380ea5f3e5e5f1d6`. Its historical
review still contains an unperformed independent certificate-identity recheck.
Merge state does not change that evidence. Do not repeat the platform-blocked probe.

The product evolves as three independently usable layers: **A standalone S3**,
**B selective logical workspaces**, **C storage-aware execution**. Layer A has no
startup dependency on B/C, a cloud account, a coordinator or quorum. Existing peer
S3 and additive folder sync stay available. Git keeps source history and merges.

The first workspace wave is M1a, not the whole vision: logical discovery, immutable
revisions, selective publication/hydration, verified local state, pins and conflict
rejection, plus a local execution foundation with Codex/Claude adapters. Destructive
eviction is explicitly blocked until retention and durability authority is enforced.
No new lease, device-security, remote-scheduling or automatic-failover claims arise.

Approve these disjoint domains:

| Domain | Ownership and purpose |
|---|---|
| [workspace_catalog](domains/workspace_catalog.md) | S3 adapter, immutable catalog and CAS publication |
| [workspace_cache](domains/workspace_cache.md) | Local baselines, selective staging/hydration, pins, CLI |
| [agent_execution](domains/agent_execution.md) | Local isolated work directories, supervised commands, Codex/Claude adapters |

Freeze `workspace/contract.rs`, `execution/contract.rs` and their public facades as
PM-owned. Promote existing portable filesystem helpers into PM-owned `src/files.rs`
so sync and workspace reuse one path rule. Additional workspace rules protect its
control directories and Git internals. The PM integrates CLI/gates/docs and shared
facades; builders cannot widen their scope to implement a convenient dependency.

Approve object_store **0.12.5**, S3-only, for streaming transfers and conditional
metadata; it matches the existing Reqwest generation. Use a strict custom HTTP
connector. Approve direct libc at the already resolved major for owned Unix process
group termination. No arbitrary shell-string runner. No storage credential forwarding.

Local cancellation has a durable control-file contract: `maxio-agent cancel --run
DIR` records a request for that validated run. Only the live runner may confirm a
terminal `cancelled` state and terminate its owned process group. A request receipt
is not confirmed termination, and an abandoned record never authorizes killing a
saved PID. SIGINT/SIGTERM handling remains separately verifiable; the explicit
request path must have an actual process-level cancellation test.

The complete per-domain contracts are the specs above. Namespace references use
`maxio-workspace://<workspace-uuid>/<percent-encoded-logical-path>?revision=<uuid>`.
They identify a published logical version, not a temporary URL or access grant.
Changing physical placement must preserve workspace/revision identity. There is no
HTTPS share-link issuer or independent authorization service yet.

Publication uses fresh immutable blobs, immutable SHA-256-verified manifests, and
one opaque-ETag conditional head. CAS prevents publishing against an old head; it
is explicitly not renewable ownership or fencing against a revoked credential.
No timestamp wins a conflict. Missing/unavailable data never authorizes deletion.
S3 readback verifies bytes, not retention. Acknowledgment uncertainty preserves work.

Implement and judge [selective workspaces](journeys/selective_workspace.md) and
[local agents](journeys/local_agents.md). Full Journey B/C/D/E remain incomplete
until their named missing properties are implemented and tested. The roadmap is
`01_product_roadmap.md`; it separates implemented, verified, experimental, planned
and explicitly deferred work instead of treating green unit tests as delivery.

## PM ruling: managed workspace authority and workers (2026-10-25)

The merged PR #3 tree is the reviewed foundation, not completion of Journeys B–E.
Add an optional single coordinator and independently running workers. Standalone
`maxio`, direct-S3 `maxio-workspace` format 1, and local `maxio-agent` stay usable
without them. No automatic adoption or migration of existing S3 data occurs.

### Authority, durability and ownership

- `fabric_authority` owns a private append-only vault and one bounded, fsynced JSON
  authority snapshot under a lifetime exclusive `fs2` process lock. Canonical
  `Manifest`, `FileVersion`, `RevisionRef` and `RunRecord` are reused. Managed
  publication has its own `ManagedHead`; it never overloads an S3 ETag or mirrors
  another writable S3 head. Private immutable payloads and manifests are verified
  and fsynced before the state transaction acknowledges a publication.
- Serialize mutations. Persist a validated next state through a fresh file,
  file fsync, atomic rename and parent fsync before acknowledging. An uncertain
  persistence result stops mutations until reopen. Never reset corrupt state to
  empty. Capacity limits reject new work; they never discard authority records.
- Restart durably increases the epoch before serving, expires prior leases and
  abandons active attempts. Runtime expiry uses monotonic deadlines. Fence high
  water, acknowledged heads, receipts, enrollment and revocation survive restart.
  No disconnected partition or old incarnation can acquire implicit authority.
- The vault has no delete/GC API. Logical deletion is an explicit fenced tombstone
  retaining the previous immutable version; restore is another publication. Missing
  devices or paths are never deletion intent. Retention is one fsynced server copy,
  not physical redundancy, compliance Object Lock or an automatic failover claim.

### Device and publication contracts

- `fabric_transport` owns native verified HTTPS, individual Ed25519 device keys,
  single-use challenge proof, short-lived opaque sessions and the managed CLI.
  Reuse the existing native listener through an additive `ServerTls::standalone`;
  do not duplicate TLS handling or change existing peer identity rules. No insecure
  verification mode, ambient proxy discovery, redirects or universal device secret.
- Only an owner enrolls public keys and grants explicit catalog/read/write/job
  rights. Catalog access reveals the full canonical manifest; path read/write
  grants are separate. The authority rereads current device generation/revocation
  and grants at admission and final publication. Revocation cannot recall bytes
  already delivered or an already admitted stream. Key recovery is explicit owner
  enrollment/rotation and revocation, never a bypass secret.
- Leases cover component-aware file/tree/workspace scopes. Grant/renew/release,
  monotonic expiry, persisted fencing and current-head comparison are authoritative.
  Upload preparation does not publish. Final publication rechecks actor, grant,
  exact changed paths, current head, lease/epoch/fence and optional attempt identity
  and cancellation in one serialized state transition. Idempotent request receipts
  distinguish a lost acknowledgment from a new operation. A request ID with changed
  contents is a conflict. Reads of committed versions remain allowed during edits.

### Cache and execution contracts

- `worker_execution` owns a private immutable input cache and retained attempt
  directories. Never hard-link cache objects into editable task/user files.
  Hydration verifies exact size/hash and retains incomplete stages on failure.
  Cache eviction requires a fresh authenticated retention verification, exact
  authority/vault/version binding, matching clean inode/content, no pin or active
  use, and a durable local intent/recovery record. Report logical bytes separately
  from allocated blocks and observed filesystem-space recovery. Editable working
  copies, old staging/history, failed outputs and ambiguous attempts stay retained.
- `execution::run_verified` is an additive entry point that checks the actual
  isolated input copies against admitted `RunFile` identities before task launch.
  Existing local `run` remains compatible. The PM integrates this bridge and tests,
  the generic HTTPS constructor, managed local-workspace support and full-gate/docs
  wiring; these explicit integration grants do not enlarge builder bubbles.
- Workers advertise owner-configured named profiles and verified cache inventory.
  Wire tasks cannot select raw executables, provider homes, environment secrets or
  arbitrary command arguments. The authority filters eligibility, then minimizes
  missing selected input bytes with deterministic ties and recorded reasons. Manual
  selection is a hard constraint. A worker rechecks exact inputs before launch.
- One active attempt per worker. Heartbeat/lease loss cancels when possible and
  retains work; cancellation intent is distinct from confirmed process termination.
  Never kill a stored PID on restart. Retry is explicit and creates a new attempt;
  arbitrary external command effects are not exactly-once. Existing Codex/Claude
  adapters are reused. Provider fixtures are not authenticated model executions.
- Local run success and authoritative publication are separate receipts;
  `RunRecord.published` remains false. Publish outputs only when explicitly requested
  and within the submitted scopes; preserve outputs on conflict or failure.

The owner trusts worker-native commands. Cwd isolation, private permissions and
environment filtering are not a hostile-process sandbox. Strong separation of
coordinator keys, provider credentials and untrusted tasks requires separate OS
principals/sandboxing. No Raft, FUSE, cloud account or mandatory full replication.

`src/fabric/{mod,contract}.rs` are PM-owned. The three new domain specs establish
disjoint bubbles; builders use isolated worktrees and fresh critics. The PM owns
the B/C/D/E cross-domain acceptance in `specs/journeys/managed_fabric.md`. Do not
repeat the previously platform-blocked independent incoming-peer-certificate probe.

### Managed editable workspace adapter

The existing `workspace_cache` bubble extends `LocalWorkspace`, preserving the
direct-mode serialization and behavior. `WorkspaceReader` is a narrow hydration
transport contract in the existing workspace facade; it accepts the exact
snapshot/path. The direct S3 adapter and the managed HTTPS adapter implement it.
`LocalWorkspace::pull` becomes generic over this reader, without importing fabric.
The local manager remains the sole implementation of dirty checks, publication
staging, baseline advancement, pins and retained replaced inodes.

Freeze additive `open_managed(root, &ManagedTarget)`,
`observe_managed(&ManagedCatalog)`, `managed_head() -> Result<ManagedHead>`, and
`accept_managed_publication(&ManagedCatalog, &[Publication])`. Use explicit local
format 2 for managed state, with a separate managed head and target. Format 1 stays
readable and unchanged; it cannot be silently rebound. A managed snapshot's S3 ETag
is always absent. Offline inspection works in both modes. Remote tombstones do not
delete working bytes; publishing from an old baseline after remote deletion is a
conflict until the user makes an explicit recovery decision. Editable data is not
made eviction-eligible by this adapter. The PM owns managed CLI integration; the
workspace cache builder edits only its existing local implementation/tests/spec.

Within the transport integration, the PM owns client/server/CLI and HTTP tests;
the journey builder has the disjoint `scripts/smoke_fabric.py` write assignment.
Liveness observations and empty claims are bounded and expire after restart.
They do not consume permanent business-request capacity. New incarnations, real
claims, grants, finished executions and publications keep durable receipts. Old
retired worker incarnations cannot be revived by resending an advertisement.

Private roots are typed, including a durable `.maxio-fabric` authority marker and
`.maxio-worker` cache marker. The PM integrates cache-marker creation/validation
and regression; workspace-cache ownership rejects those roots, their descendants,
and explicitly selected nested private contents before creating editable state or
staging bytes. These guards prevent accidental adoption; they are not OS access
control against a malicious same-UID program.
