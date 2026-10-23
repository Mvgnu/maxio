---
name: system
description: PM-owned product, ownership, and shared-contract decisions for MaxIO
---

# MaxIO system contract

MaxIO stores and moves data on machines the operator chooses. Its product has
three distinct journeys. The simplest one must remain simple.

| Journey | User outcome | Current scope |
|---|---|---|
| [Standalone S3](journeys/standalone_s3.md) | One process, one data directory, an ordinary S3 client | Default server mode; embedded console; no cluster configuration |
| [Peer S3](journeys/peer_s3.md) | An S3 endpoint over explicitly configured storage peers | Experimental static peers, replication, forwarding and honest unavailable states |
| [Device sync](journeys/device_sync.md) | Ordinary folders exchange files through a chosen device | Optional client using a standalone peer bucket; conflict preservation; no delete propagation |

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

Credentials currently share administrative capabilities; there is no IAM policy
engine or per-device read/write grant system. HTTP must be confined to a trusted
local/VPN channel or terminated behind correctly configured TLS. Shared peer
tokens do not encrypt traffic. Configuring outgoing peer certificates does not
create an inbound TLS listener.

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

## Evidence and next decisions

Use [Gauntlet](../gauntlet.md) and dated [review records](reviews/). A successful
loopback scenario establishes its stated property only. Production durability,
power-loss behavior, internet peer security, WAN partitions and all-device UX
require additional evidence. The next wave is chosen by the largest observed gap,
not a list of previously imagined distributed features.
