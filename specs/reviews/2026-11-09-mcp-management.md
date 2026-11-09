# Optional MCP management and agent manual

Date: 2026-11-09. Platform: macOS arm64, Rust1.94.0, Bun1.3.10.
Base: own fork `fd109b2`. Runtime artifact: `ea78050`; expanded smoke/manual baseline:
`9769b04`. Later edits concern documentation and this acceptance record.

## Delivered surface

The optional `mcp/` Bun package exposes49 concrete stdio tools through the standard
MCP SDK. It consumes authenticated console HTTP and existing native-HTTPS
`maxio-fabric rpc`, leaving Rust storage, authentication, transport and data formats
unchanged. Owner configuration selects endpoints, credentials, executables and
paths; tool arguments cannot replace them. Managed mutations preserve caller
request IDs and canonical errors. Service supervision is current-session child-only.
Observation is bounded and is not a standing monitoring/reconciliation service.

The single `mcp/skills/operate-maxio/SKILL.md` contains architecture/features,
all49 MCP tools, complete agent workflows, setup/diagnosis/recovery and63 actual
CLI help pages across the six Rust executables. The user explicitly requested all
guidance in one file. There are no separate skill reference files. The same skill
is installed in the owner's local Codex skills directory.

## Paths and integration

- New domain specification and recorded PM ruling in `specs/00_system.md`.
- `mcp/` implementation, frozen package/lockfile, tests, actual SDK process smokes,
  optional portable plugin wiring and single-file operating skill.
- `scripts/check_architecture.py`: new domain/source ownership and generated-path
  exclusions; plugin metadata/skill remain PM-owned.
- `scripts/run_checks.py`: locked MCP checks/build and actual SDK storage journey
  in the full integration gate. Existing Rust gates remain intact.
- Root README entrypoints and this dated review. No `src/` or Cargo changes.

Builder used an isolated worktree from PM foundation `ecbc6fc`. Domain scope was
checked against that exact base on `codex/mcp-management-builder`; PM packaging and
integration changes were checked with the whole-repository architecture gate.

## Verification actually run

| Command / observation | Result |
|---|---|
| `./scripts/domain_check.sh mcp_management` in builder worktree | Passed check,12 tests, bundle and architecture |
| `python3 scripts/check_architecture.py --domain mcp_management --base ecbc6fc --head codex/mcp-management-builder` | Passed complete builder scope |
| `python3 scripts/check_architecture.py` and architecture negative-case unittest discovery | Passed17 domains and9 harness tests |
| `cd mcp && bun run check && bun test` | Passed12 tests,50 assertions |
| `MAXIO_TEST_BINARY=... bun run --cwd mcp smoke` | Real SDK discovery, bucket/create/list, UTF8 bytes, persisted restart/cookie refresh, placement/rebalance, lifecycle/presign, exact versions/delete, error and cleanup passed |
| `MAXIO_TEST_FABRIC_BINARY=... MAXIO_TEST_FABRIC_CONFIG=... bun mcp/scripts/smoke-fabric.ts` | Real native HTTPS info/list/create/current, enrollment/grant/revoke and missing-job error passed |
| Actual local private configuration via SDK stdio |49 tools; healthy S3 on loopback9000, native HTTPS authority info on loopback9443, existing server accurately external/owned:false |
| `codex mcp add ...` and `codex mcp get maxio-management --json` | Registered enabled global stdio connection using absolute Bun/entrypoint and private config-file path; no secrets in registration |
| Skill quick validation and internal-anchor / CLI-help comparison | Passed; all63 help pages match actual binaries |
| `./scripts/domain_check.sh all` on integration tree | Failed at inherited Rust library tests:964 passed,22 failed; later full-gate journeys did not run |

Before the final full-gate failure, architecture tests, UI check/45 tests/build,
MCP check/12 tests/bundle, Cargo formatting, all-target check, Clippy warnings gate
and panic/unwrap/expect lint gates passed. Full-gate logs remain in the ignored
integration `target/mcp-full-gate*.log`. The same22 Rust library failures were
observed on the unmodified fork before the MCP change: six native TLS connection
cases and16 managed private-root/ancestor cases on macOS. This feature does not
repair those inherited domains and does not claim a full repository pass.

## Independent Gauntlet and operator judgment

The initial fresh critic used frozen runtime `df66f19` with standard SDK clients
and disposable actual services. It found a real ownership race: concurrent starts
spawned several children, discarded the live child's handle and left an orphan.
It also found unusable placement/rebalance schemas and opaque Fabric errors.

Builder fixed the race through serialized lifecycle transitions, corrected query
schemas and preserved structured canonical errors. Regression-first tests cover
concurrent starts, reachable external protection, private cookies, redirects,
bounded responses, mutation non-retry and safe Fabric failure categories.

The critic independently retested frozen `ea78050`: six concurrent starts kept one
owned process; explicit stop and disconnect terminated it, a second session could
not stop the first, valid placement/rebalance inputs worked, and missing-job,
permission-denial and outage errors remained distinguishable. Real storage/version
and HTTPS workspace/grant/queued-job controls passed. Verdict: scoped pass.

A separate fresh operator used `9769b04`, README-only setup and an independent SDK
client, without source repairs or builder reports. It observed49 strict schemas,
real UTF8/binary storage roundtrips/restart, native HTTPS catalog/job operations,
changed-request-ID and stale-head rejection, explicit absent-fabric errors and no
configured credentials in captured results. Eight simultaneous starts left one
child; stop/disconnect left zero; external stop/restart was refused. It also
rejected endpoint/command/path injection. Verdict: scoped pass. Startup remains
asynchronous: observe reachable state before storage operations.

The fresh operator separately reviewed the final single-file skill: all63 CLI
pages matched the executables, all five internal routing links resolved and the
MCP/CLI coverage and authority/retention/ownership distinctions matched inspected
contracts and observed behavior. Verdict: scoped documentation pass.

Raw disposable review scripts/results are in private scratch directories
`/tmp/maxio-mcp-critic-evidence/` and `/tmp/maxio-mcp-operator-9769b04/`. They are not
packaged with credentials. Source-controlled SDK smoke scripts reproduce the
core journeys. No public-internet/WAN or remote-provider execution claim follows.

## Remaining limits and PM stop

The adapter does not wrap every CLI feature: large/multipart/copy/range transfers,
editable publication/hydration/restore, cache operations, lease mutations and
backend service provisioning use the authorized existing CLI. The manual explains
those paths. No arbitrary HTTP, shell or local-file proxy is exposed.

Actual worker execution/log retrieval/retry, exhaustive tool/fuzz/leakage coverage,
WAN durability and background unattended operation were not independently certified
in this wave. MCP observation is on-demand; the currently running S3 and authority
are externally managed processes, not silently adopted session children. Global
Codex registration does not prove that an already-running chat refreshed its tool
inventory; discovery was independently verified with the standard SDK.

PM stops this wave at the requested local management surface and comprehensive
single-file skill. Keep the inherited22 macOS Rust failures visible and unchanged;
repairing transport/filesystem baselines is separate domain work. This is a scoped
MCP/operating-documentation pass, not production or whole-product certification.
