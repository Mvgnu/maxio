# Managed workspaces, ownership and storage-aware execution

Date: 2026-10-25. This wave continues the merged recovery/foundation work. It
delivers optional managed software and actual process journeys, with the scope
and evidence below. Standalone S3 remains a separate executable and startup path.

## Reconciled baseline and product decisions

Main was `53e50fe0a4ddaea44a1acc9af7cca27430165a28`, the user's merge of PR #3.
Its tree `911b8296b57d3c617d9cf0f61dfc26961850b83d` exactly matched the previous
reviewed head `37e55e8de1d63d2f33a5b98d5d051bada44d639c`. Existing immutable S3
workspace revisions, local baseline/pin/history logic and command/Codex/Claude
execution adapters were reused, not replaced. There is no data-format migration.

The prerequisite S3 audit found unsupported Object Lock/retention requests could
fall through to ordinary object operations. The router now rejects these queries
and headers before mutation. This matters independently of managed mode: a request
to retain an object must not overwrite it with retention XML. MaxIO still does not
implement S3 Object Lock. Readback from an arbitrary S3 backend is insufficient
authority to destroy the last locally recoverable copy.

Managed mode therefore has one explicitly separate publication authority and an
append-only private filesystem vault. Its acknowledged immutable payloads and
authority snapshot are fsynced; the vault has no destructive/GC API. It supplies
fresh, exact-version retention verification for a separate immutable cache. This
is one retained server-filesystem copy, not physical redundancy or a claim about
external provider retention. Direct-S3 editable workspace eviction stays refused.

## What was implemented

Three new Lop domains have disjoint builders, frozen shared DTOs, commands and
external bars. Existing Rust/Bun layout and one crate were preserved.

| Domain | Concrete capability and boundary |
|---|---|
| `fabric_authority` | Durable managed catalog, append-only versions, enrollment/grants/revocation/rotation, component-aware renewable leases, epoch/fencing, prepared uploads versus committed heads, tombstones/restore, job/attempt records and locality decisions |
| `fabric_transport` | Native verified HTTPS, individual Ed25519 challenge proof, single-use challenges and revocable sessions, streaming checked transfers, typed control API and `maxio-fabric` CLI |
| `worker_execution` | Separately running `maxio-worker`, owner-selected profiles, verified private immutable cache, selected hydration, independent execution copies, logs/cancellation, fenced result publication and retained failed/abandoned work |
| Existing `workspace_cache` | Explicit managed format 2 using the same baselines, dirty checks, pins, staging and history as direct format 1; no silent rebinding or parallel implementation |
| Existing `agent_execution` | Additive `run_verified` checks admitted input identities before launching the existing command/Codex/Claude adapters |
| Existing S3/harness | Unsupported-retention rejection, standalone regression coverage, 16-domain architecture enforcement, managed process journey in the complete gate |

Standalone `maxio` does not import or initialize workspace/fabric execution.
Architecture checks enforce the lower-layer boundary. Managed profiles and provider
credentials are configured locally by the worker owner. Submitted jobs select a
named profile, exact inputs, authorized output scopes and resources; they do not
select arbitrary executables, provider homes or storage credentials.

Private roots are marked and not adopted as editable workspaces. Cached inputs,
task copies, published versions, dirty edits, pins, active use and retention proof
remain distinct states. Successful local execution is distinct from a publication
receipt. Publish-policy jobs with prepared outputs remain Running until that commit.

One important integration correction bounded idle claims, advertisements and
renewals instead of appending permanent request receipts on every heartbeat.
The regression observes 3,300 liveness operations without changing durable state
bytes or receipt count. New incarnations and real business mutations remain durable;
retired incarnations cannot return under a fresh request ID.

## Artifact attribution

Independent authority/cache and the first onboarding/worker rounds use frozen
local source `22c1d523e25a390650dff1b8ddec41c1c277e3e9`:

- `maxio-fabric`: `1d6d171f43a5388a94e3534ef53c1a2086bb8ab6129ce7ed5cc13122890db00b`
- `maxio-worker`: `5c172e129d435a2cfdbf535f803535ce59fc7d2c207c6bb6d651a8b869a09a19`

The follow-up frozen source is `8f120ac548a2b78a6b37d95f43299814affe204a`, with
`maxio-fabric` SHA-256
`d9bda8729905ce69885ad0f3bf44662f6b98d0f009ef350a5129da5262bbee28`.
Runtime changes since the first artifact are two equivalent Result-return lint
cleanups and the additive CLI log-display option. Full artifact inventories are
preserved in [artifact-reviewed.json](evidence/2026-10-25/artifact-reviewed.json)
and [artifact-log-followup.json](evidence/2026-10-25/artifact-log-followup.json).
These are local build-source identities; GitHub publication records the final tree
and its own commit identity. Do not silently attribute a critic to another binary.

Platform: Linux x86_64, Rust 1.94.0, Bun 1.3.10, debug binaries. All device/worker
claims below are **separate processes, keys and roots on one host**. No physical
MacBook/Mini/VPS, WAN/NAT, 40 GiB workload, HA or quorum result is claimed.

## Journey A — ordinary S3 remains independent

The ordinary AWS CLI **1.46.2**, Python 3.12.14 and botocore 1.43.62 created a
bucket, uploaded 1,048,601 binary bytes, listed/read them, restarted standalone
MaxIO, and read exactly the same bytes again. There was no managed configuration,
peer setup, cloud service or orchestrator. SHA-256:
`3d97005f7c64e5a37c5c231ddd08ca229c259ff550e1ff50064982192477b690`.
The [AWS CLI result](evidence/2026-10-25/ordinary_s3_aws.json) and
[reproducible driver](evidence/2026-10-25/ordinary_s3_aws.py) are checked in.

A separate S3 critic made **4,337 signed requests**, including **186 unsupported
retention/Object Lock/legal-hold variants**. All 186 returned 501, preserving actual
file inventories, hashes, ETags, versions, bucket configuration and multipart parts.
Ordinary uploads, reads, versioning and multipart completion survived two restarts.
This is a bounded preservation pass, not retention-feature support. See the
[independent S3 review](evidence/2026-10-25/s3-retention-review.md) and
[observations](evidence/2026-10-25/s3-retention-checks.json).

## Journeys B and D — selection and actual computation near data

The checked-in process journey ran a real **134,217,728-byte non-sparse dataset**,
with SHA-256 `8b8303d23b3ef412c9aa4bae37d6e2f10e0213fda56a4c954806d49a327d6bbc`.
Both Mini and VPS were available and eligible. The Book submitted an actual Python
hash task; only the Mini initially had the verified dataset in its private cache.

| Measurement | Observed value |
|---|---:|
| Mini missing selected input bytes | 611 |
| VPS missing selected input bytes | 134,218,339 |
| Selected worker | Mini |
| Mini input hydration for the task | 611 bytes of Python source |
| Mini dataset redownload during execution | 0 bytes |
| Book dataset download over the entire journey | 0 bytes |
| VPS dataset download over the entire journey | 0 bytes |
| Cache logical and allocated bytes unlinked | 134,217,728 |
| Observed filesystem available-space increase | 134,000,640 |
| Deliberate later dataset refetch | 134,217,728 bytes, original hash |

Per-identity HTTPS observers measured application payload independently of CLI
counters. This excludes TLS/framing overhead; it is not a network-egress benchmark.
The actual command produced the correct hash/size on the Mini under a child PID,
and a separate durable receipt published the result. Inputs and outputs retain their
exact identities. Cache, task, original and editable copies have independent inodes.
Successful cache eviction does not delete those other retained copies.

All authorized devices discovered metadata without fetching dataset contents.
Selected directory pulls left unrelated paths absent. Selected publications were
discoverable elsewhere. Dirty/conflicting edits were explicitly rejected and
preserved, including after restart; missing local directories did not trigger
global deletion. Logical delete/restore retained exact historical versions.

The independent cache critic used another 128 MiB dataset and its own driver.
Book and VPS each pulled exactly **110 bytes** of selected documentation; the Book
received no other file payload throughout that review. The critic verified dirty
edits, late writes to a replaced inode retained in history, pin state after deletion,
exact restore, missing-vault/offline/tamper eviction refusals, 128 MiB unlink/refetch,
and a retained **2 MiB** partial download. Its observed free-space delta was
106,213,376 bytes; shared-volume noise is kept separate from exact allocation removed.
See [cache review](evidence/2026-10-25/cache-review.md) and
[31 checks](evidence/2026-10-25/cache-checks.json).

The [builder measurements](evidence/2026-10-25/builder-metrics.json) and
[15-scenario record](evidence/2026-10-25/builder-journeys.json) preserve complete
attribution. They are explicitly builder evidence, not an independent verdict.

A separate execution critic repeated the flagship with its own 128 MiB dataset,
profiles and HTTPS observers. Mini and VPS were eligible at **741** versus
**134,218,469** missing bytes. The actual Python child reported its parent as the
launched Mini worker. The correct **98-byte** result was separately published and
read by Book; across **2,121 observed requests**, Book's only file read was that
result. Mini downloaded only the 741-byte source before execution. Cancellation,
old-incarnation publication rejection, explicit retry after worker loss, cache
pin/evict/refetch and both labelled provider fixtures also passed. An additional
measurement audit recomputed 82 retained-file hashes/lengths without mismatch.
See [independent execution review](evidence/2026-10-25/execution-review.md),
[actual placement](evidence/2026-10-25/execution-placement.json) and
[execution summary](evidence/2026-10-25/execution-summary.json).

## Journey C — real competing and stale owners

Two authenticated client processes requested overlapping leases: exactly one won,
and the last committed version stayed readable. Expiry advanced the process-drill
fence from 9 to 10. Coordinator restart advanced epoch 2 to 3 and fence 11 to 12;
old publication authority was rejected. Actual worker jobs also contended for a
scope. Killing one worker caused abandonment, let the waiting worker run, and allowed
an explicit retry with exactly two attempts. Old/superseded renewals and publication
were rejected while the original work remained inspectable.

The independent authority critic separately exercised already-authenticated requests
paused before admission, then removed grants/revoked devices. Reads and commits were
denied without changing the head. It crashed the authority twice, recovered the
same receipt after a deliberately lost successful response, rejected changed-content
request-ID replay, and read three exact versions after the last restart. Post-shutdown
inspection confirmed the actual manifests, payload hashes and durable receipts.
See [authority review](evidence/2026-10-25/authority-review.md),
[48 checks](evidence/2026-10-25/authority-checks.json) and
[durable audit](evidence/2026-10-25/authority-durable-audit.json).

## Journey E — concrete failures, not universal fault tolerance

| Failure actually injected | Observed outcome |
|---|---|
| Upload/download cut after 65,536 payload bytes | Failed operation preserved prior/partial bytes; deliberate recovery succeeded |
| Missing/offline fresh retention verification or pinned object | Eviction refused and cache bytes preserved |
| Eviction process killed while proof response withheld | No unlink occurred; exact cache remained recoverable |
| Successful finish/publication replies suppressed | Same operation receipts reconciled, without rerunning the command |
| Cancellation of a real command | Terminal cancellation recorded; unpublished work retained |
| Failed attempt renewal | Execution stopped when supervision observed loss; no publication; work retained |
| Head changes after output preparation | Fenced publication conflicted; job ended abandoned, output retained |
| Worker SIGKILL and reincarnation | Old work abandoned/recoverable; stale authority rejected; explicit retry created a new attempt |
| Coordinator SIGKILL during execution | Epoch advanced 3 to 4, old attempt fenced, work retained, no automatic retry |
| Revoked device | Subsequent authenticated access rejected |

In a separate follow-up on `8f120ac`, the cache critic captured **two real process
interruptions after unlink began**. Each had a persisted pending intent, the old
256-entry index, one actually absent object and 255 survivors. SIGSTOP was observed
before SIGKILL. Offline reopen reconciled to 255 entries and cleared the intent;
a second reopen deleted nothing. The authoritative catalog was unchanged. Exactly
one 4,096-byte refetch restored the original hash and all 256 verified entries.
The separate report and precise Linux reproduction are retained with this review.
See [post-unlink review](evidence/2026-10-25/eviction-interruption-review.md),
[28 checks](evidence/2026-10-25/eviction-interruption-checks.json) and the
[independent driver](evidence/2026-10-25/interrupted_eviction.py).

This does not establish power-loss ordering, filesystem/storage-full behavior,
physical disk loss, replicated durability, arbitrary partitions or exhaustive
interleavings. A killed worker can leave its native child alive; abandonment and
fencing do not claim that the child died. Reconciliation never kills a saved PID
or automatically retries external side effects.

## Gauntlet loop and onboarding

Each critic received the goal, public contracts, external bar and frozen executables,
without builder report/history. Authority used the specified Syncthing enrollment
and etcd lease/transaction properties; cache used Rclone selection and Syncthing
recoverable-conflict properties; worker placement used Ray's locality property.
The references are official documentation comparisons, not competitor benchmarks.

| Fresh review | Verdict and exact scope |
|---|---|
| Standalone S3 retention guard | Pass: 186 explicit refusals preserved bytes and ordinary operations; earlier isolated S3 artifact |
| Managed authority / HTTPS | Pass: 48 observed checks for individual authority, grants/revocation, fencing, crash and lost-reply recovery on `22c1d52` |
| Managed editable workspace / cache | Pass: 31 observed checks for selection, recoverable conflicts/deletion and guarded reclamation/refetch on `22c1d52` |
| Managed worker execution | Pass: actual locality execution, publication and bounded lifecycle recovery, including labelled provider fixtures, on `22c1d52` |
| Post-unlink cache interruption | Pass: two real Linux stop/kill/reopen/refetch cycles and 28 checks on `8f120ac` |
| Fresh documented onboarding | Round-one gap: base64-only logs. Follow-up pass on `8f120ac`: readable retained pages, JSON compatibility, offsets and stderr |

Fresh documented onboarding completed setup, enrollment, selected transfer, two
workers, real publication and pin/evict/refetch. It found one actual gap: reading
logs required undocumented base64 decoding. The builder reproduced that missing
CLI option, added `task logs --text`, retained default JSON/pagination, and added
tests for exact output bytes and unchanged JSON. A fresh-artifact follow-up observed
the original readable line, two actual stdout pages (65,536 + 4,466 bytes), separate
stderr, offsets and EOF. The original gap remains in
[round one](evidence/2026-10-25/onboarding-round1.md); it is not rewritten as a pass.
The [follow-up review](evidence/2026-10-25/onboarding-round2.md) and
[exact comparisons](evidence/2026-10-25/onboarding-round2.json) record its closure.

The runner normalizes invalid UTF-8 child log output before retention, as independently
observed in the follow-up. `--text` preserves retained log bytes. Logs are not a
lossless archive of arbitrary binary stdout; publish binary results as files.

## Verification and reproduction

The complete local integration gate passed: **1,627 Rust tests**, no ignored tests,
**45 console tests**, **9 architecture tests**, all **16 domain specs**, formatting,
all-target check, both strict Clippy variants, all binaries and **eight process
journeys**. Its managed journey observed all 15 named cases. After the log-display
correction, **two additional CLI regressions**, binary build and both strict Clippy
variants passed. GitHub's final-head check is separate evidence, linked from the PR.

```bash
cd ui
bun install --frozen-lockfile
bun run build
cd ..
cargo build --locked --bins
./scripts/domain_check.sh all
```

The measured managed drill can also be run alone with a new evidence directory:

```bash
python3 scripts/smoke_fabric.py \
  --fabric-binary target/debug/maxio-fabric \
  --worker-binary target/debug/maxio-worker \
  --size-mib 128 --evidence /tmp/maxio-managed-review-new
```

Follow [managed setup and recovery](../journeys/managed_fabric_usage.md) for the
actual daily-use commands, device enrollment and worker/Codex/Claude profiles.
Authenticated provider model execution was **not run**. Both existing adapter paths
were exercised with clearly labelled local protocol fixtures; these are distinct
from live provider authentication/capability evidence in earlier reviews.

Earlier development runs in the shared synchronized workspace stopped on an inode
changing during verification and an unindexed object appearing after eviction.
Those observations were retained, not suppressed or weakened. The same binaries
passed a controlled `/tmp` cache comparison, and final builder/critic runs used
private `/tmp` runtime roots with evidence copied only after shutdown. The precise
cause of the earlier workspace anomalies remains unproven. Private authority/cache
roots require one cooperating manager and must not be independently synchronized.

## Still open and next product work

- Physical MacBook/Mini/VPS, WAN and larger-workload validation.
- Actual authenticated Codex CLI/Claude Code model calls on workers.
- Safe reclamation of retained successful attempt copies, incomplete stages and
  history. Current cache eviction deliberately preserves these; no general GC.
- Managed external-S3 placement, independent retained copies, backend capability
  policies, signed external sharing links and continuous folder synchronization.
- OS isolation/resource enforcement for untrusted native tasks; current workers
  are owner-trusted and resource declarations are admission hints.
- Power loss, storage-full/fsync errors, host/disk loss and replicated coordination.
  Raft, automatic failover, FUSE and Kubernetes remain explicitly deferred.

The next broad product gap is bounded lifecycle/space management for retained task
copies, followed by physical-device deployment. The present milestone demonstrates
selection, authority and actual computation near data while preserving failed work;
it does not silently convert every long-term requirement into a completed feature.
