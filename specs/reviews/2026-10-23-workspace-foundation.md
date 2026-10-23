# Workspace and local execution foundation — 2026-10-23

This record separates implementation, integration gates and independent judgments.
The accepted scope is **M1a selective workspaces plus a local execution foundation**.
Full Journeys B, C, D and E remain open. In particular, eviction refusal is not disk
reclamation, manifest CAS is not a lease, and a local process is not a remote worker.

## Reconciled starting point and ownership

The wave starts from merged PR #2, main commit
`7afd102bd7013b55e17f1642380ea5f3e5e5f1d6`. Its prior independent incoming-certificate
recheck remains unperformed after platform enforcement blocked it. This wave did
not repeat that experiment or infer a security pass from merge status.

The PM froze workspace/execution contracts and assigned three disjoint worktrees:

| Domain | Builder ownership | Independent critic |
|---|---|---|
| `workspace_catalog` | S3 adapter, immutable manifests/blobs, conditional head, remote integrity | Fresh `critic_workspace_catalog` |
| `workspace_cache` | Local baselines, staging/history, pins, offline state | Fresh `critic_workspace_onboarding`, after README-only onboarding |
| `agent_execution` | Supervised local executable, provider adapters, records, cancellation | Fresh `critic_agent_execution` |

The PM integrated the CLI, shared filesystem helpers, architectural gates, journey
scripts and documentation. A required integration Clippy repair only collapsed
equivalent conditional branches in catalog acknowledgment reconciliation. No
functional catalog contract changed in that repair.

Final integration also corrected the release archive and container recipes to
include all four executables. The container still starts only `maxio` by default;
provider CLIs remain owner-provisioned. The recipes and executable lists were
inspected, but no container image or tagged release was built or published in this
wave. README now reports the actual thirteen domains.

All critics received goals, references, specs, instructions and frozen binaries,
without builder histories or reports. Critics made no implementation edits. Their
temporary scripts/data are independent experiments, not changes to the product.

## Artifact identity and environment

The first workspace artifact was built at local integration commit
`7ff4916a881e2ddf64766047e48c052f25563dda`:

| Binary | SHA-256 |
|---|---|
| `maxio` | `1ba27db3eaf55cbff6f68893a964241e7e71b80a4a4c5957eac825041f98e6e6` |
| `maxio-workspace` | `0fdf740b0fdc81f0ba2fae7906fc51cf09c130872246742f9f9fa32f6406236b` |

The first integrated execution artifact was built at local commit
`b309dcdd44427f5d46443b31beec38def8e9e113`; its `maxio-agent` SHA-256 was
`9b17bff52af1317a83ad96fc69911e7ff6155a72926c4cf63a6ef8d56ca38c90`.

Platform: Linux x86_64, kernel `6.18.55`, glibc `2.39`; Rust `1.94.0`, Bun `1.3.10`.
Ordinary client: AWS CLI `1.46.2`, Botocore `1.43.62`, Python `3.12.14`.
"Mac Mini", "MacBook" and "VPS" are separate directories/processes on this one
host. No physical-device, WAN, external-provider or 40 GiB benchmark is claimed.

The ordinary sandbox disallowed loopback listening/access. Normal execution
escalation approved disposable local servers and clients. No rejected approval was
bypassed. Installed provider tools were inspected through version/help only; no
real credentials were inspected and no authentication or model request occurred.

## References and compared properties

- [Rclone copy](https://rclone.org/commands/rclone_copy/): explicit selections leave
  unrelated payloads untransferred and destination-only data intact. MaxIO's domain
  contract adds exact immutable history and competing-publisher preservation.
- [Garage quick start](https://garagehq.deuxfleurs.fr/documentation/quick-start/)
  and [S3 PutObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html):
  ordinary standalone startup/client use and the exercised restart property.
- [Codex noninteractive mode](https://developers.openai.com/codex/non-interactive-mode),
  [Claude CLI](https://code.claude.com/docs/en/cli-reference) and
  [Claude headless execution](https://code.claude.com/docs/en/headless): explicit
  inputs, literal process invocation, valid completion and retained failed work.

Critics read these official references. They did not execute Rclone or Garage, and
did not claim feature parity with either. Provider protocol fixtures were explicitly
labelled synthetic; they are not authenticated Codex/Claude runs.

## Standalone and fresh onboarding — pass, scoped

The fresh operator first read only README and the standalone/selective-workspace
journeys. The supplied binary replaced the README's built-binary path. Startup
needed only credentials, address, port and a fresh data directory; it reported zero
peers. Ordinary AWS CLI created a bucket and uploaded/listed/downloaded a nested
object. After stopping/restarting the server with the same data directory, its
**1,048,607 bytes** retained SHA-256
`e836455f17a618dd870def427d649ad535e8c15cb63600c84fd7b155736f0cc6`.
An ordinary AWS download after the workspace review and another restart matched too.

The documented two-root workspace quick start also succeeded: initialize, selected
publication, metadata refresh, source-only pull, credential-free list/status/pin,
one-file edit/publication and retrieval on the original root. The Book dataset
directory stayed absent. **Zero undocumented product or configuration edits** were
required. Build-tool installation and the unchanged console UI were not judged by
this onboarding review.

Representative ordinary-client commands, after the README credential setup:

```bash
maxio --address 127.0.0.1 --port 19240 --data-dir ./standalone-data
aws --endpoint-url http://127.0.0.1:19240 s3 mb s3://files
aws --endpoint-url http://127.0.0.1:19240 s3 cp ./example.txt s3://files/nested/example.txt
aws --endpoint-url http://127.0.0.1:19240 s3 cp s3://files/nested/example.txt ./before.bin
# Stop and restart that exact server with the same data directory.
aws --endpoint-url http://127.0.0.1:19240 s3 cp s3://files/nested/example.txt ./after.bin
```

## Workspace catalog — pass, scoped

The critic used independent real-process harnesses and a request-counting/fault
proxy. Its **134,217,728-byte** dataset was actually uploaded in sixteen 8 MiB parts,
read back and later hydrated. Initial selected payload total was **134,217,778
bytes** in each direction; publication verification accounts for the download.

| Exercise | Observed evidence |
|---|---|
| Empty Book/VPS discovery | Each fetched 1,210 metadata bytes, no blob GETs and zero payload; neither acquired a dataset |
| Selected source/config pull | Exactly 50 payload bytes; no dataset/unrelated directory |
| One-file edit publication | 30 bytes uploaded and verified; dataset not retransferred |
| Exact old revision | Original 22-byte file before and after server restart; observed current revision stayed separate and status was `stale` |
| True concurrent head update | Proxy held both final PUTs behind a two-party barrier, then released them: one HTTP 200, one HTTP 412 |
| Losing writer | Both live and separate publication-stage edits retained; refresh did not bless the stale baseline; independent reader retrieved winner and preceding revision |
| Corrupt body | Same-length corruption rejected by hash; no working file installed; stage retained |
| Interrupted multipart upload | 17 MiB live/staged input preserved; head unchanged; both attempted 8 MiB parts counted; abort issued |
| Truncated/resume-interrupted download | 32,768 received bytes retained in an uninstalled stage for a 65,537-byte file; clean retry matched |
| Lost successful head response | Unique revision reconciled to the actual committed publication |
| Lost response after another writer advanced head | Explicit known-published-but-advanced error; no newer head token attached to the older manifest; both publications recoverable |
| Lost response and denied reconciliation | Explicit unresolved outcome; stage/local bytes retained; no false local baseline/catalog entry; independent retry recovered committed 51 bytes |

**Largest in-scope gap: none observed.** The decisive evidence was two real writers
at the conditional publication point, one winner, preserved loser work, and exact
old/new bytes retrievable independently. This does not establish generic distributed
consistency or backend retention.

## Workspace cache — pass, scoped

A separate critic built its own three-root counting/fault harness after completing
fresh onboarding. Its dataset had **134,217,728 logical and allocated bytes**.
The six-file fixture included source, config, dataset, unrelated archive and a
`src-old` prefix neighbor.

| Operation | Payload uploaded | Payload downloaded | Independent observation |
|---|---:|---:|---|
| Publish all six explicit files | 135,414,366 | 135,414,366 | Full verification; originals retained |
| Book refresh | 0 | 0 | Six entries, 1,634 metadata bytes, no blob requests |
| VPS refresh | 0 | 0 | Same catalog, no local contents |
| Book pull `src` | 0 | 4,147 | Exactly two source files; no dataset/archive/config/`src-old` |
| VPS pull `datasets` | 0 | 134,217,728 | Exact dataset hash |
| Book publish one source | 58 | 58 | Only selected edit and its verification |

Historical pull kept the current observed catalog separate from the old working
baseline; editing the old copy and refreshing still refused publication. A real
concurrent publication produced one head 412 and preserved the loser's complete
working/staged edit. Dirty pulls made no payload request. A destination created
while a download was gated was preserved, with the new stage retained separately.

Missing and corrupted blobs preserved preceding local bytes. Interrupting a 128 MiB
download left a **3,145,728-byte** incomplete stage and no hydrated file. Interrupted
publication retained its **2,818,048-byte** input and complete stage without moving
the head. An open-descriptor write after clean replacement remained recoverable in
the old history inode while the new working file stayed correct.

Offline fresh processes, with credentials removed, completed list/status/pin/unpin
without proxy requests. An unavailable refresh preserved catalog, baselines and
bytes. Restart retained pins, winning catalog C, losing baseline B and every working
hash. Eviction explicitly refused and changed no bytes.

**Largest in-scope gap: none observed.** The full Journey B gap remains enforced
durability/retention and safe eviction, followed by device authorization and offline
reconciliation. It has not been converted into a pass by this smaller judgment.

### Transfer accounting

CLI counters are application-level payload/metadata accounting, excluding HTTP
framing and SDK retries. Upload counts include bytes handed to the SDK on failed
attempts. Downloads include verification and failed partial bodies. The independent
proxies observed retries separately: a 2,818,048-byte attempted upload produced
8,454,144 bytes across three HTTP attempts. Multipart control XML is not file payload.

Both independent workspace harnesses initially needed fixture-only corrections
(resumed downloads must also be interrupted; multipart XML must be classified
separately). Original logs were preserved. Neither correction changed the product
or its state, and neither preliminary assertion is recorded as a product failure.

## Agent execution — round 1 gap

The independent critic inspected 24 real run records. The README Python example,
selected fresh copies, literal argv, scrubbed disposable storage variables, failed
exit retention, malformed/missing protocol outcomes, permission denial, timeout and
explicit cancellation all behaved as contracted. Recorded output hashes matched
the retained files; every run had `published: false`. A SIGTERM-ignoring descendant
stopped after timeout and explicit cancellation, with edits/logs retained.

The **single largest gap** was a sticky success flag. A Codex fixture emitted:

```json
{"type":"thread.started","thread_id":"independent-fixture-thread"}
{"type":"turn.started"}
{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}
{"type":"turn.started"}
```

It then exited zero. MaxIO incorrectly recorded `succeeded` despite the unfinished
last turn. A Claude fixture reproduced the defect with successful `result`, then
new `assistant` content, then EOF without another result. This gap went back to the
execution builder for failing regressions and a repair. Round 1 is not a pass.

Native auth-free doctor checks accepted Codex CLI **0.164.0** and Claude Code
**2.1.309**, explicitly reporting authentication/model execution unverified. Public
doctor uses a minimal PATH; the tested Codex installation needed its native binary
because its npm wrapper's Node runtime was outside that PATH. `run --env PATH` is an
explicit owner choice, not automatic environment inheritance.

## Agent execution — round 2 gap

The corrected artifact at local commit
`c39571b4e8dd3178def0634bc732b7961b00abb2` had `maxio-agent` SHA-256
`fae5cf988688fcaea19bcdcea889e1fbd3daa5eb11ff576d9d3e1f18a8a8e6fa`.
The critic independently reran the original unfinished-follow-up executables. Both
now recorded `protocol_failed`, even with child exit zero, while completed multiple
turns still succeeded. Errors, denials, malformed events and unsuccessful exits
continued to override earlier success. All 34 inspected round-2 records retained
their logs and work, matched recorded output hashes, and had `published: false`.

The **single largest remaining gap** was the converse: a successful Claude result
followed only by `system/session_state_changed` with `state: "idle"` became a false
protocol failure. The otherwise identical stream without that notification succeeded.
Anthropic's published
[`@anthropic-ai/claude-agent-sdk` 0.3.301 declarations](https://app.unpkg.com/@anthropic-ai/claude-agent-sdk@0.3.301/files/sdk.d.ts)
define result as turn completion, allow informational system messages afterward,
and describe idle as following the held result. The critic inspected that primary
contract and retained both paired streams. The gap returned to the builder; round
2 is not a pass. Informational events must preserve an existing completion without
creating one or concealing genuinely unfinished work.

## Execution correction reviewed in round 3

The same primary SDK contract states that positive `queued_turn_count` announces
pending user work. During integration review the PM identified this adjacent case;
the builder reproduced positive and malformed counts as failing regressions before
correcting them. A later successful result with no queued work is required; absent
counts remain compatible with older producers. Informational idle messages cannot
complete an otherwise unfinished run.

The corrected builder commit is `3d92bca3e2b72b7f94bd848c217cf5498977acf4`, integrated
locally as `3283c8b`. The frozen execution binary has SHA-256
`b425b91589bf237c5a7788ad681ca1ebe30f5c7778649bf4f91ce7fddb572259`.
The PM independently verified that its execution subtree, CLI, shared file helpers,
Cargo manifests/lockfile, execution tests and process script exactly match the
integrated source. The execution subtree Git object is
`839fff48aa803cce4dbb7192bcf9de8868e56f15`.

Builder verification passed 9 execution unit tests, 17 integration tests, locked
all-target check, both Clippy gates, formatting, architecture/scope and binary build.
The maintained process journey exercised actual ordinary execution, timeout,
explicit cancellation and 17 labeled provider protocol cases. This is builder
verification; the separate critic's judgments are recorded in this document.

## Agent execution — round 3 gap

The independent critic verified the frozen hash above, replayed the exact old
fixtures and inspected 48 retained execution records. Idle tails now succeeded;
unfinished follow-up work and queued results remained incomplete. A later unqueued
result completed the run, including several queued sends coalesced into one turn.
Malformed queue counts, explicit failures and unsuccessful process exits stayed
failures. Every recorded output matched retained bytes and all original sources
were unchanged.

The **single largest gap** was another documented reporting event: a complete
Claude result with zero queued turns followed by `system/informational`, `level:
"info"`, and a string `content` still became `protocol_failed` with child exit zero.
The SDK declares this a non-error banner. The otherwise identical completed-result
and idle controls succeeded. The critic retained the exact stream, invocation,
record and hashes; round 3 is not a pass. The reporting-event classification was
returned to the builder for a coherent review of the declared metadata and heartbeat
events, preserving the unfinished-work checks.

## Execution correction submitted to round 4

Builder commit `7b358b57b89a12db32fee9700eed5f0f188e4454`, integrated locally as
`a0f3f6a783ef36f181d8863e81e393c403fa2d1c`, classifies the supported reporting
events without creating completion or clearing queued/unfinished work. The frozen
`maxio-agent` SHA-256 is
`d9733b47f59876348a4a4aae784ff8476994b0107c0e9d7fb4d55ceac5de9625`.
The PM checked the binary hash and exact integrated identities of the execution
subtree (`b187570ca62fea9268cd129ccc59f5bff84d15ea`), CLI, shared filesystem helpers,
Cargo manifests/lockfile, execution tests, script and domain spec.

The builder first reproduced the informational-tail regression on the preceding
parser. The corrected source passed 11 execution unit tests, 18 integration tests,
formatting, locked all-target check, both Clippy gates, architecture/domain scope,
Python compilation and binary build. The maintained CLI journey passed actual
ordinary execution, timeout, explicit cancellation and 22 labelled protocol cases.
Seven exact earlier critic fixtures were also replayed. These are builder gates;
the independent judgment is separate.

The domain spec records two deliberate policies: unknown trailing messages require
another terminal result, despite the SDK's generic ignore-unknown advice; explicit
auth/hook/persistence/plugin failures remain whole-run failures under MaxIO policy.
Supported reporting preserves completion only. An informational controlled stop is
not automatically an error, and separate task outcomes do not redefine main-turn
completion. This is a bounded supported protocol, not a future-CLI compatibility
claim.

## Agent execution — round 4 pass, scoped

The independent critic checked the final artifact hash and inspected **66 new
records**: 48 exact retained protocol replays, 16 independent reporting/activity
combinations and two real ordinary Python tasks. Observed outcomes were 23
`succeeded`, 34 `protocol_failed` and 9 `failed`, all matching the contracted cases.

The original Codex/Claude unfinished-follow-up streams still failed. The previously
rejected idle and informational tails now succeeded after a completed unqueued
result. Banners, idle and heartbeat events could neither create completion nor
clear queued work. Controlled-stop banners preserved completed unqueued turns;
explicit provider/hook failures and malformed queue counts remained failures.
Unknown trailing events followed the documented conservative policy.

The README ordinary Python example succeeded with no documentation repairs; only
the frozen binary path was substituted. A real exit-7 Python task retained its
edits. Across all 66 records, the critic verified exact stdout/stderr bytes, retained
copied-input edits and proposed outputs, recorded output sizes/hashes, unchanged
original input hashes, distinct source/copy inodes, selected-only initial fixture
workspaces and `published: false`. Four representative `inspect` calls agreed with
disk records without changing them.

**Largest in-scope gap: none observed.** The pass is argued from the repaired exact
counterexamples, paired completion/activity cases, real ordinary execution and
independent retained-byte audit. It covers this final-turn/retention contract, not
authenticated model execution, provider sandbox enforcement or remote workers.
Round 4 did not repeat earlier independent timeout, cancellation, environment,
literal-argument or native-doctor exercises; those remain attached to their stated
artifacts. The final builder process journey separately re-exercised timeout and
explicit cancellation on the new binary.
Evidence was preserved under `critic-agent-execution-r4-20261023/`, including
`retention-and-hashes.json`; earlier rounds were not overwritten.

## Fresh combined workflow — pass, scoped

A separate fresh critic used only README and the journey instructions, the frozen
integrated binaries, and disposable roots. No undocumented product/configuration
edits were needed. Ordinary AWS client round-trips worked before and after the
workspace/agent handoff under the same server configuration; it reported zero peers.

The two receiver roots fetched **1,269 metadata bytes each and zero payload**.
The worker pulled exactly **236 source bytes**, leaving dataset files absent. An
actual Python task consumed two selected copies, generated a **53-byte result**,
and retained its logs and matching hashes. Source files stayed unchanged, storage
credential variables were absent, and the run reported `published: false`.
The remote head did not change during execution or inspection.

Only after explicitly copying the reviewed result into the workspace and publishing
that selected file did the head advance: **53 bytes uploaded and 53 read back**.
The second receiver retrieved those same 53 bytes, SHA-256
`1cc554558f7bddd93085bbf4f590979d3281bab94021a3461d16803d079ab633`.
Its unrelated dataset remained absent. This establishes a useful manual handoff
from discovery through local execution to reviewed publication; it does not prove
remote dispatch or provider model execution.

The independent fixture also contained an unexplained **113,770,496-byte temporary
file before MaxIO started**, alongside its intended 128 MiB dataset. The critic
preserved that evidence and included the file in the initial explicit directory
publication. Actual initial payload was **247,988,460 bytes each way**, not 128 MiB.
Timestamps establish that the extra file preceded the product run; no product defect
or origin is inferred. Neither dataset entry was transferred to the other roots.

**Largest in-scope gap: none observed.** The critic argued the pass from zero
unrelated transfer, retained local execution, unchanged source/head until an explicit
publication, exact final bytes, and ordinary S3 operation throughout. The independent
onboarding review above supplies the separate restart evidence.

## Verification and final disposition

The first published implementation commit is
[`3709c8ec08846c0a5dd1f4aaf13485d729528c4f`](https://github.com/Mvgnu/maxio/commit/3709c8ec08846c0a5dd1f4aaf13485d729528c4f),
tree `38a972a6405f0661b8c9d2a2441ddb5da987daaa`, matching local integration
commit `4ed6dc99d16fa82e96e9bbff29f9d0e599c31bfe`. It precedes the later
execution protocol corrections and their independent judgments. All changes
are reviewable in [draft PR #3](https://github.com/Mvgnu/maxio/pull/3).

| Integration gate | Observed result on that integration tree |
|---|---|
| Architecture | 13 domain specs, ownership/dependency checks and 9 architecture tests passed |
| Console | Type check, 45 tests and production build passed |
| Rust static checks | `cargo fmt --check`, locked all-target check and all-target Clippy with warnings denied passed |
| Production lint | Library/binaries passed the explicit no-unwrap/expect/panic gate |
| Full Rust suite | 1,565 passed, zero failures or ignored tests |
| Binaries and shell | All four binaries built; shell syntax checks passed |
| Maintained real-process journeys | Standalone, static peer S3, existing secure-peer smoke, sync over HTTP, sync over TLS, selective workspace and local agents passed |

The local full-gate attempts first stopped at catalog Clippy findings. Equivalent
conditional branches and redundant test clones were corrected; the remaining gates
then completed successfully. The table records the completed commands across that
repair cycle, not one uninterrupted invocation. The existing secure-peer smoke is
an integration regression; it does not replace the independently blocked historical
certificate-identity recheck. Final execution correction verification and its
independent verdict are recorded separately in the execution sections. Hosted
complete integration gates are visible in the PR's Checks tab and must be read at
their actual commit.

[Hosted CI run 71](https://github.com/Mvgnu/maxio/actions/runs/39966909911) passed
one uninterrupted `./scripts/domain_check.sh all` invocation on published commit
`3709c8ec08846c0a5dd1f4aaf13485d729528c4f`. This is independent runner evidence for
the integration gate, not a substitute for the product critics or a pass for later
source changes.

### Milestone disposition

| Scope | Disposition |
|---|---|
| Journey A, ordinary standalone S3 | Independent client/restart and onboarding pass; existing server stays independently usable |
| M1a selected workspace publication/hydration | Catalog and cache critics pass the bounded single-target protocol; actual bytes and failures are recorded above |
| Local execution foundation | Final-turn/retention critic passes; actual ordinary commands, labelled provider fixtures and installed CLI capability checks are distinct evidence |
| Combined documented workflow | Fresh discovery → selected local execution → explicit reviewed publication pass, with no undocumented edits |
| Full Journey B | Open: retention-authorized eviction, device grants/location registry and full offline/deletion reconciliation remain missing |
| Journeys C and D | Open: no renewable leases/fencing, remote dispatch or actual locality-selected worker execution |
| Full Journey E | Open: only the named transfer, publication, process and restart failures were exercised |

The final source and complete integration result are reviewable through PR #3's
commits and Checks. The hosted run named above is pinned to its earlier source;
it must not be silently attributed to the later execution corrections.

## Reproduction and limits

Build using README's pinned Rust/Bun/locked-dependency commands. The maintained
real-process entry points are:

```bash
python3 scripts/smoke_standalone.py --binary ./target/debug/maxio
python3 scripts/smoke_workspace.py --binary ./target/debug/maxio \
  --workspace-binary ./target/debug/maxio-workspace --keep-data
python3 scripts/smoke_agents.py --binary ./target/debug/maxio-agent \
  --artifacts /new/absolute/agent-evidence-directory
./scripts/domain_check.sh all
```

The independent session evidence used `critic-workspace-catalog/{probe,race_probe}.py`,
`critic-workspace-20261023/{onboarding,cache_review}.py`, and
`critic-agent-execution-20261023/` under the task scratch directory. Their reports
preserve exact argv/results, JSON streams, actual proxy bodies, hashes and local
state snapshots. These temporary paths are not installation requirements; the
commands above and scenario descriptions are the repository's replay instructions.

No safe destructive eviction, tombstones, global location registry, device grants,
renewable leases, stale-worker fencing, remote dispatch, locality scheduler, automatic
failover, resource quotas/usage reporting, provider session resume or automatic output
publication is delivered by this slice. Claude exposes file tools only; its full
sandboxed build/test loop remains open. Arbitrary owner-selected commands are trusted
local execution; cwd and an environment allowlist are not an OS boundary. A process
escaping its group, a killed runner, hostile path-ancestor replacement and power loss
require separate containment/recovery work. Signal-based cancellation is implemented
but was not established on this host; the explicit request command was exercised.

The next largest product dependency is a publication/retention authority that can
safely authorize releasing local bytes, then scoped device identity and fencing,
then an actual separately running worker chosen for data locality. Raft and FUSE
remain optional later decisions.
