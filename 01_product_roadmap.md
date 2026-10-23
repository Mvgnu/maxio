# MaxIO delivery roadmap

[specs/00_system.md](specs/00_system.md) owns product invariants, contracts and domain
boundaries. Dated [Gauntlet reviews](specs/reviews/) contain actual evidence. A feature
being implemented, merged or unit-tested does not establish an independent pass.

## Product direction

**A. Standalone S3:** one process, ordinary clients, no required cloud or coordinator.
**B. Optional workspaces:** discover published files, retrieve selected versions,
manage local residency and eventually place durable copies across storage locations.
**C. Optional execution:** prepare selected inputs and run an owner-selected agent or
command; evolve toward authenticated workers and moving computation to existing data.

Git owns source history and merging. MaxIO owns published file identity, storage
placement and execution coordination. They must not become competing merge systems.

## Status language

- **Implemented:** code exists; consult verification evidence for its demonstrated scope.
- **Verified:** the stated property was actually exercised on the named artifact.
- **Experimental:** usable within stated limits, without a wider reliability claim.
- **Planned:** requirement remains open; no placeholder counts as implementation.
- **Explicitly deferred:** a conscious dependency or product decision delays it.

A row can be implemented and experimental while only a narrower property is verified.
The current wave's final verification and independent findings belong in its review.

## Reconciled baseline — M0

| Capability | State and evidence boundary |
|---|---|
| Standalone S3, embedded console, conditional standalone PUT | Implemented; recovery review and CI record ordinary operations/restart/rejected-write preservation |
| Native HTTPS, peer mTLS, revocable console sessions, private-CA sync | Implemented, merged in PR #2 at `7afd102b`; historical secure-peer review remains authoritative |
| Independent incoming certificate-identity recheck | **Unperformed:** platform-blocked after builder repair. Merge did not supply this missing review. Do not rerun the blocked experiment as part of workspace development |
| Static peer S3 | Experimental; replicated writes and outage drills do not establish consensus or automatic failover |
| Additive `maxio-sync` | Implemented, verified within bounded whole-file polling; no delete propagation or selective cache eviction |
| Filesystem data/sidecar publication | Prior bytes protected on handled errors; a complete process/power-loss-atomic storage format remains planned |
| Permissions | Existing extra S3 credentials are admin-equivalent; per-device/agent authorization is planned |

## Delivery sequence

| Milestone | Current scope | State / remaining gate |
|---|---|---|
| M0 — Reconcile | Preserve recovery work; correct stale roadmap claims; define three optional layers and authoritative interfaces | Completed read-only audit and PM contract ruling |
| M1a — Selective workspace foundation | Stable logical references, immutable manifests/blobs, streaming selective publish/pull, current/history discovery, CAS conflict rejection, local baseline/pin state | Implementation wave; experimental single-target client protocol. Actual process/critic evidence recorded separately |
| M1b — Safe storage reclamation | Backend capabilities and retention/durability policy, verified durable copies, protected active work, explicit recoverable eviction | **Planned. Eviction is refused.** Readback alone cannot authorize destruction of the last locally recoverable version |
| Local execution foundation | Independent local command/Codex/Claude runner, selected input copies, logs, cancellation/deadline, retained records and proposed outputs | Implementation wave. Real CLI capability checks and protocol fixtures do not constitute authenticated model execution |
| M2 — Secure devices | Individual enrollment, encrypted authenticated sessions, revocation, scoped grants, device-advertised locations, offline reconciliation, tombstones/recovery | Planned; existing peer TLS is not this authorization system |
| M3 — Ownership | Renewable scoped leases, coordinator authority, monotonic fencing, abandoned work recovery and stale publication rejection | Planned; manifest CAS is not a lease or a revocation fence |
| M4 — Move compute to data | Worker registration/resource discovery, explainable locality selection, isolated remote execution, hydration, fenced publication, resource/attempt records | Planned; must execute on an actual separate worker, not only rank candidates |
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

## External bars and next largest gaps

Workspace catalog/cache use Rclone's selective-copy behavior as a falsifiable bar.
Local execution uses Codex's documented noninteractive contract plus Claude's actual
CLI contract. Device reconciliation will use Syncthing; eventual locality execution
will use Ray's data-locality behavior. A named reference never replaces running the
artifact and recording the single largest remaining gap.

The next product dependency is **a durable publication/retention authority that can
safely authorize releasing local bytes**. Then device identity and publication grants,
then fenced ownership, then a real Mac Mini/VPS locality execution drill. Raft, FUSE,
Kubernetes and a new agent reasoning engine are not prerequisites for the first useful
workspace and are explicitly deferred.
