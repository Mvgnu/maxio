# MaxIO delivery roadmap

[specs/00_system.md](specs/00_system.md) owns product invariants, contracts and domain
boundaries. Dated [Gauntlet reviews](specs/reviews/) contain actual evidence. A feature
being implemented, merged or unit-tested does not establish an independent pass.

## Product direction

**A. Standalone S3:** one process, ordinary clients, no required cloud or coordinator.
**B. Optional workspaces:** discover published files, retrieve selected versions,
manage local residency and eventually place durable copies across storage locations.
**C. Optional execution:** prepare selected inputs and run an owner-selected agent or
command; optionally use enrolled workers and execute where selected data is cached.

Git owns source history and merging. MaxIO owns published file identity, storage
placement and execution coordination. They must not become competing merge systems.

## Status language

- **Implemented:** code exists; consult verification evidence for its demonstrated scope.
- **Verified:** the stated property was actually exercised on the named artifact.
- **Experimental:** usable within stated limits, without a wider reliability claim.
- **Planned:** requirement remains open; no placeholder counts as implementation.
- **Explicitly deferred:** a conscious dependency or product decision delays it.

A row can be implemented and experimental while only a narrower property is verified.
The [foundation review](specs/reviews/2026-10-23-workspace-foundation.md) records the
direct-S3 and local-runner baseline. The [managed-fabric review](specs/reviews/2026-10-25-managed-fabric.md)
records the subsequent B–E process measurements, failure drills and independent
findings. Neither review establishes physical-device or WAN behavior.

## Reconciled baseline — M0

| Capability | State and evidence boundary |
|---|---|
| Standalone S3, embedded console, conditional standalone PUT | Implemented; recovery review and CI record ordinary operations/restart/rejected-write preservation |
| Native HTTPS, peer mTLS, revocable console sessions, private-CA sync | Implemented, merged in PR #2 at `7afd102b`; historical secure-peer review remains authoritative |
| Independent incoming certificate-identity recheck | **Unperformed:** platform-blocked after builder repair. Merge did not supply this missing review. Do not rerun the blocked experiment as part of workspace development |
| Static peer S3 | Experimental; replicated writes and outage drills do not establish consensus or automatic failover |
| Additive `maxio-sync` | Implemented, verified within bounded whole-file polling; no delete propagation or selective cache eviction |
| Filesystem data/sidecar publication | Prior bytes protected on handled errors; a complete process/power-loss-atomic storage format remains planned |
| Permissions | S3 credentials remain admin-equivalent. The optional managed authority implements individually enrolled keys and explicit catalog/read/write/job grants; these do not silently become S3 IAM policies |

## Delivery sequence

| Milestone | Current scope | State / remaining gate |
|---|---|---|
| M0 — Reconcile | Preserve recovery work; correct stale roadmap claims; define three optional layers and authoritative interfaces | Merged tree reconciled; prior functionality preserved; unsupported-retention mutation repaired and independently reviewed |
| M1a — Selective workspace foundation | Stable logical references, immutable manifests/blobs, streaming selective publish/pull, current/history discovery, CAS conflict rejection, local baseline/pin state | Implemented; independently verified within M1a on one MaxIO endpoint and isolated local roots. Experimental single-target protocol; full Journey B remains open |
| M1b — Safe storage reclamation | Fresh retention verification against one append-only authority vault; pinned/active/modified private-cache protection; durable eviction intents | Implemented and independently verified for private-cache pin/refusal/evict/refetch and post-unlink process recovery; experimental. Only private immutable cache objects are eligible. Direct-S3 editable copies, task workspaces and history remain retained. Cross-provider retention policy remains planned |
| Local execution foundation | Independent local command/Codex/Claude runner, selected input copies, logs, cancellation/deadline, retained records and proposed outputs | Implemented; scoped independent ordinary-command, protocol-fixture and retention review passed. Installed CLI capability checks verified; authenticated model execution remains unverified |
| M2 — Secure devices | Individual Ed25519 enrollment, verified HTTPS, revocation/rotation, scoped grants, worker cache locations, offline editable state, logical tombstones/restore | Implemented; independent same-host verified-HTTPS/grant/revocation/restart review passed. Experimental single authority. No auto-pairing, equal-peer mesh, background watcher, WAN or physical-device validation |
| M3 — Ownership | Renewable file/tree/workspace leases, durable epoch/fence, exact-head publication, explicit abandonment and recovery | Implemented; independent conflicting/stale-owner and crash/lost-reply review passed on named artifacts. Restart invalidates live authority before serving; no quorum or alternate partition authority is claimed |
| M4 — Move compute to data | Worker registration/resources/profiles, explained missing-input-byte selection, separately running execution, selected hydration, logs, fenced publication and retained attempts | Implemented with the existing command/Codex/Claude adapters. Managed B–E review records real 128 MiB locality execution and separate result publication; provider fixtures are not authenticated model calls. Native tasks are owner-trusted, resource declarations are not OS quotas, and successful-attempt GC remains planned |
| M5 — Resilience | Replicated coordination if justified, leader changes, partition/quorum tests, multiple providers, background cache management, progressive GUI | Explicitly deferred until the single-coordinator product justifies the operational cost |

## M1a boundaries that must not disappear from reports

- One explicitly configured S3 target per local workspace. There is no global device
  location registry or replica placement policy yet. Logical references are distinct
  from physical blob keys and are not download URLs or access grants.
- Catalog discovery is separate from hydration. A refreshed catalog does not mark
  dirty local work as published. Published versions are immutable protocol objects.
- The manifest is bounded to 20,000 files and 8 MiB. Historical lookup is bounded;
  old objects remain retained rather than silently pruned.
- Multipart transfers have bounded client buffering, with full remote integrity
  readback after publication. This costs extra traffic and is reported explicitly.
- Metadata, stages and replaced inodes persist. No automatic garbage collection,
  cache eviction, global deletion, transparent filesystem mount or transfer resume.
- Existing credentials remain trusted operator credentials. Agent subprocesses get
  neither the S3 backend configuration nor inherited storage credential variables.
  Same-user arbitrary processes are not isolated by environment scrubbing or cwd.
- Three local roots/processes are a one-host simulation. A 128 MiB test is a real
  transfer, not proof of physical-device/WAN behavior or a measured 40 GiB workload.
- Failure drills are individual exercised cases, not a claim of full Journey E.

## Managed mode boundaries

- Managed catalog, leases, jobs and retained bytes have one private authority. This
  is separate from direct-S3 publication and never silently adopts its head/state.
- Retention verification proves an exact version is retained by that append-only
  vault under its current policy. It does not establish independent disk replicas,
  provider Object Lock, power-loss durability, automatic failover or disaster recovery.
- Location scheduling uses worker-advertised, locally verified selected content.
  Eligibility and missing-byte decisions are recorded. It is not an arbitrary
  network-cost optimizer, live memory monitor or OS resource-enforcement service.
- Every task uses independent input copies. Cache eviction deliberately leaves
  original imports, editable files, task copies, failed outputs, history and logs.
  Capacity limits reject new work; no silent pruning resolves a full disk.
- Key/session revocation protects subsequent admissions and commits. It cannot
  recall bytes already delivered or stop an admitted stream instantly.
- Cancellation intent and abandonment are distinct from confirmed child death. A
  killed worker may leave a local child. Reconciliation never kills a saved PID or
  automatically reruns a command with possible external side effects.
- The managed vault currently has one filesystem backend. External S3 remains
  available through the direct-S3 workspace; managed external placement, signed
  share links, transparent mounts and multi-provider retention remain planned.

## External bars and next largest gaps

Workspace catalog/cache use Rclone's selective-copy behavior as a falsifiable bar.
Local execution uses Codex's documented noninteractive contract plus Claude's actual
CLI contract. Managed device authentication/recovery uses Syncthing, publication
ownership uses etcd's lease/transaction guarantees, and locality execution uses
Ray's data-locality behavior. A named reference never replaces running the
artifact and recording the single largest remaining gap.

The next broad product work is **safe lifecycle management of retained successful
attempts and stages**, plus a physical MacBook/Mini/VPS exercise. Preserving failed
work is mandatory; introducing cleanup requires a separate explicit recovery and
retention contract. Managed external-S3 placement and independently retained copies
follow that foundation. Raft, FUSE, Kubernetes and a new agent reasoning engine
remain explicitly deferred. The latest independent review determines the next
concrete corrective gap before expanding that roadmap.
