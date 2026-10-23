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
engine or per-device read/write grant system. Plain HTTP belongs on a trusted
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
