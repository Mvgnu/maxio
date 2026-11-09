---
{
  "verification": {
    "check": "cargo check --locked --all-targets",
    "build": "cargo build --locked --bins",
    "architecture": "python3 scripts/check_architecture.py",
    "test": "cargo test --locked --lib fabric::authority:: && cargo test --locked --test fabric_authority"
  },
  "name": "fabric_authority",
  "description": "Durable managed catalog, enrollment grants, leases and storage-aware job authority",
  "paths": {
    "owned": [
      "src/fabric/authority.rs",
      "src/fabric/authority/"
    ],
    "tests": [
      "tests/fabric_authority.rs"
    ],
    "exclude": []
  },
  "exports": [
    "Authority::{initialize,open,info,device,control,check_upload,upload,read}",
    "append-only retained vault",
    "idempotent fenced publication and job records"
  ],
  "consumes": [
    "fabric::contract",
    "workspace canonical immutable manifests",
    "files path and fsync helpers"
  ],
  "bar": {
    "reference": "etcd lease and transaction guarantees",
    "url": "https://etcd.io/docs/v3.6/learning/api_guarantees/",
    "property": "A committed managed publication survives coordinator restart, and an expired or replaced lease holder cannot change the authoritative head while the prior committed version remains readable."
  },
  "artifact": "Real authority process, competing independent clients, restart and lost-response publication with retained exact bytes."
}
---

# Durable managed catalog, enrollment grants, leases and storage-aware job authority

The PM ruling in `specs/00_system.md` and `fabric::contract` are authoritative.
Read `lop.md` and `gauntlet.md`. This domain cannot expand its own write gate.

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

## Authority operation limits

The authority snapshot is at most 64 MiB, control requests 8 MiB, devices 1,024,
workspaces 128, active leases 4,096, prepared uploads 20,000, durable request
receipts 20,000, retained revisions 40,000, workers 128, and jobs 256 with at most
32 explicit attempts each. These are admission limits, not pruning policies.
Scope lists contain at most 256 entries. Individual uploads use the existing
83,886,080,000-byte workspace limit. Logs retain at most 4 MiB per stream through
chunks of at most 64 KiB. Task prompts are bounded to 1 MiB and appear only in
private authority state and the assigned worker's authenticated claim.

Lease and heartbeat requests accept 1–300 seconds; initial job claims and worker
advertisements last 60 seconds. Retention verification lasts 30 seconds and hashes
the exact retained bytes for 1–256 explicit references per request. A caller supplies
a fresh challenge; serialized evidence
alone never authorizes cache eviction. `check_upload` is the PM-approved admission
check before accepting a large request body; `upload` repeats it after payload I/O.

Successful `FinishAttempt` under explicit Publish policy retains its current lease
and worker slot when prepared outputs exist. The subsequent fenced `Publish`
records a distinct receipt and releases that slot/lease. Other terminal finishes
release them immediately. Cancellation remains a request until the worker confirms
a terminal result or the authority records abandonment; no saved PID is signaled.
The job remains Running while its successful local attempt awaits required
publication, then becomes Succeeded only when the publication receipt commits.
Output selectors are allowlists. When no outputs match the allowlist, a successful
run completes without publication.

## Bounded liveness observations

An empty claim does not mutate durable job state. Same-incarnation advertisements
and valid current lease/attempt renewals update live observations without appending
permanent business receipts or fsyncing a snapshot. Their replay observations keep
only request hashes for at most 1,024 requests and five minutes; every replay still
checks current identity, incarnation, lease and cancellation state. Evicting an
observation never revives an expired lease or grants an old attempt authority.

First advertisements, incarnation changes, actual claims, finished attempts and
catalog/grant/job mutations remain durable and idempotent. Retired incarnations
are retained and cannot re-adopt themselves with either an old or fresh request
ID. Fence high-water remains durable. Restart expires all live observations and
leases regardless of their last renewal. Business transactions may incidentally
persist diagnostic heartbeat times; those times never establish post-restart life.
Worker discovery exposes full cache inventories only to an owner or that worker
itself; other authorized observers can inspect capabilities and placement decisions
without learning unrelated workspace content identities.
