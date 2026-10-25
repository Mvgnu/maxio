# Managed workspace and storage-aware execution: Journeys B–E

This is the acceptance contract for the optional managed mode. Implemented and
independently observed results belong in the dated review and roadmap. The direct
S3 workspace is a separate, still supported mode. Until observed, each property
below remains open.

## B — Selective three-device workspace

Use three separately enrolled keys and separate local roots representing MacBook,
Mac Mini and VPS. State explicitly when these are processes on one host. Publish
small source files and a real non-sparse dataset of at least 128 MiB. All granted
devices discover metadata with zero dataset payload. Hydrate one selected directory
and prove unrelated bytes did not transfer. Publish selected edits, refresh other
devices, and preserve/reject concurrent edits explicitly. Restart/disconnect and
inspect retained local work and authoritative exact versions. Pin a hydrated
private cache entry, observe eviction refusal, unpin and reclaim measurable space
only with fresh verified retained-vault evidence. Refetch and compare SHA-256.
Logical deletion is explicit; a missing directory never propagates a delete.

External property: Rclone selective copy transfers selected data only; Syncthing
conflict/version recovery does not silently discard divergent work. Use their
official documentation as the comparison contract, not an unrun benchmark claim.

## C — Concurrent ownership

Two independently authenticated processes request overlapping write leases. Only
one succeeds. The last committed version stays readable. Prepare a change, kill
its holder or let its lease expire, grant new authority and reject the old publish.
Also restart the coordinator and reject pre-restart leases after epoch change.
Confirm retained bytes and a monotonically newer fence, not just error messages.

External property: etcd's lease/transaction model rejects work lacking current
authority; linearizable publication is claimed only within this one authority.

## D — Move compute to data

Run an actual coordinator and two separate worker processes. Only the Mini worker
has the dataset cached. The Book submits a task requiring the exact dataset and
source versions. Verify the recorded eligible candidates and missing-byte totals,
actual Mini process execution, deterministic correct output and a separate durable
publication receipt. Book receives zero dataset bytes; Mini does not redownload
the resident dataset. Inspect logs, retained run/input/output identities and safe
cache cleanup. Exercise both Codex and Claude adapter paths with labelled protocol
fixtures; authenticated model calls need separate evidence.

External property: Ray locality-aware scheduling favors the eligible worker with
the required large input already local. No claim of a complete Ray replacement.

## E — Failure recovery

Interrupt upload/download, cache eviction, lease renewal, running worker and
coordinator. Exercise conflicting publication, cancellation, worker disappearance,
and lost publication/finish acknowledgments. Record concrete bytes/status/receipts.
Uncommitted/ambiguous work remains recoverable. Old leases/incarnations cannot
publish. Reconciliation never reruns a command or kills a saved PID automatically.
Any unsupported failure case is rejected or kept open with its actual limitation.

## Guard and review

Journey A (ordinary S3 create/upload/download/restart) must still pass without any
managed configuration. Run declared domain and architecture/full gates, then give
the running binaries and this contract to fresh read-only critics. One largest
gap per round; builders do not award passes. Finish with a fresh documented
onboarding attempt. Never convert an unobserved property to verified by inference.
