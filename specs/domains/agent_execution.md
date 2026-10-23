---
{
  "name": "agent_execution",
  "description": "Vendor-neutral supervised local command and agent execution",
  "paths": {
    "owned": [
      "src/execution/runner.rs",
      "src/execution/runner/",
      "src/bin/maxio-agent.rs"
    ],
    "tests": [
      "tests/execution_runner.rs",
      "scripts/smoke_agents.py"
    ],
    "exclude": []
  },
  "exports": [
    "execution::run",
    "execution::doctor",
    "execution::runner::request_cancel",
    "maxio-agent CLI",
    "recoverable run records and proposed outputs"
  ],
  "consumes": [
    "execution::contract",
    "files portable filesystem checks",
    "owner-selected executable and provider authentication"
  ],
  "verification": {
    "check": "cargo check --locked --all-targets",
    "test": "cargo test --locked --lib execution:: && cargo test --locked --test execution_runner",
    "build": "cargo build --locked --bins",
    "architecture": "python3 scripts/check_architecture.py"
  },
  "bar": {
    "reference": "Codex non-interactive execution contract",
    "url": "https://developers.openai.com/codex/non-interactive-mode",
    "property": "A task runs in a fresh directory containing only selected inputs; a completed process and valid provider terminal event are required for success, while cancellation or failure preserves logs and unpublished edits."
  },
  "artifact": "Real ordinary executable plus separately identified Codex/Claude protocol fixtures; installed CLI help checks; live authenticated providers require their own explicit evidence."
}
---

# Vendor-neutral supervised local command and agent execution

## Required behavior

Use the PM-owned `RunRequest`, `RunRecord`, `DoctorReport` and seeded function
signatures. No dependency on S3 server startup, storage credentials or workspace
backend implementation. This wave is a trusted local runner, not remote scheduling.

- Create an exclusive new run directory under explicit records root; copy only
  selected safe regular input files to a fresh workspace. Hash inputs. Never hard-link
  writable inputs to the source. Exclude control directories and symlinks. Record
  output candidates only under the explicit output allowlist, with hashes/size.
- Launch absolute owner-selected executable with literal argv, cwd and stdin.
  No generated shell command. Clear the inherited environment, use a documented
  small baseline and only explicit provider variables/credential directory references.
  Deny storage credentials (MAXIO_*, AWS_*, storage tokens). Never serialize secret
  values or prompts. An environment allowlist is not an OS isolation boundary.
- Provider homes/authentication are explicit; do not copy auth into task inputs.
  Reject arbitrary inherited provider overrides. Command adapter is trusted user
  execution; do not claim arbitrary native code is filesystem-confined by cwd.
- Codex uses `exec --json`, stdin prompt, approval policy never, and selected
  read-only/workspace-write sandbox. Keep native safeguards, no bypass flags.
  Require successful exit plus `turn.completed`; preserve errors/unknown raw events.
- Claude uses print/stream-json/verbose with version/capability-gated restricted,
  dontAsk and no permission prompts. No ambient hooks/MCP from unreviewed projects.
  Default file-tool profile; do not silently enable unsandboxed Bash. Never make
  bare mode mandatory: it excludes subscription authentication. Require successful
  terminal result and exit, report permission denials/protocol errors.
- Success belongs to the final active turn. A later turn start, assistant/user
  message, tool activity or partial stream requires another successful terminal
  result. Unknown trailing events also require a subsequent terminal result.
  Claude's reporting-only rate-limit events, tool/post-turn summaries, idle status
  and turn-duration reports with no pending background work preserve completion;
  none can create completion. Explicit errors, permission denials and unsuccessful
  process exits take precedence even if a later turn reports success. See the
  [Codex JSONL event contract](https://developers.openai.com/codex/non-interactive-mode)
  and [Claude stream lifecycle](https://code.claude.com/docs/en/headless#stream-responses).
- `doctor` checks real executable version/help and refuses unavailable required
  safety flags. No authentication, model calls or automatic installation in doctor.
  Actual provider protocol adapters and fixture evidence are distinct from a real
  authenticated model run. Older unsupported CLIs fail visibly, not less safely.
- Persist preparing/running/terminal state, input/output hashes, version, status,
  logs, actual exit, session ID and timings. Stream bounded logs to disk. Enforce
  deadlines and cancellation; terminate the owned Unix process group and descendants.
  Retain workspaces/logs for success and failure. No automatic retries or cleanup.
- A stale running record after runner death is inspectable abandoned work, not a
  completed task; no PID-only recovery kill. No resume/latest-session shortcut in
  this first slice. Publication is always separate and `published` is always false.

## Limits and next decisions

No worker registration, enrollment, remote dispatch, locality scheduling, leases,
OS-level all-process credential isolation, provider session resumption or automatic
output publication in this wave. Unix process supervision first; unsupported platforms
must fail clearly. CPU/memory resource limits and usage measurement remain planned.

Full Claude command execution will need a tested fail-closed sandbox profile; do not
suggest permission bypass to work around a missing sandbox. Local owner authentication
is supported as an explicit credential-directory choice, not token distribution.

## CLI contract

Build with `cargo build --locked --bin maxio-agent`. A concrete ordinary command:

```sh
maxio-agent run --adapter command --executable /usr/bin/python3 \
  --source /absolute/project --input src/task.py --input data/selected.csv \
  --output results --records /absolute/maxio-runs --timeout-seconds 300 \
  -- src/task.py
```

Repeat `--input` and `--output` for exact files or directory trees. No input means
an empty workspace; an output selector is an allowlist, so missing outputs do not
by themselves fail the task. Symlinks, special files, nonportable names, Git
internals, MaxIO control directories and provider/credential control directories
are refused. Choose a narrower selector when a selected tree contains one.
Inputs are copied, never hard-linked. Output inspection never copies bytes back
to the source. The source and records roots must be separate.

The JSON response and `<records>/<run-id>/record.json` contain status, source-copy
hashes, output candidate hashes, executable identity, environment **names**, times,
logs and provider session identity where available. Ordinary executable identity
is its SHA-256 rather than running an arbitrary `--version` command. There is no
saved prompt, environment value, replay command or automatic publication.

`maxio-agent inspect --run /absolute/maxio-runs/<run-id>` reads a record without
mutating it. A record left in preparing/running after interruption is unconfirmed
work; it does not prove liveness or completion. Workspaces, private home/temp
directories and logs remain after every outcome. No automatic pruning is offered.

The default environment is `PATH=/usr/local/bin:/usr/bin:/bin`, private per-run
`HOME` and `TMPDIR`, `LANG=C.UTF-8`, `TERM=dumb` and `NO_COLOR=1`. `--env NAME`
selects a caller variable explicitly; `--env PATH` can select an owner's runtime
toolchain. Storage credentials/configuration, loader injection and home/temp
overrides are rejected. Provider adapters additionally accept only their named
authentication variables and explicit provider home. No ambient provider override
or arbitrary provider argument is accepted.

Logs are bounded to 4 MiB per stream and lines to 1 MiB; truncation is recorded.
Configured credential values are redacted when directly echoed. Logs and outputs
can still contain sensitive task data or encoded secrets and are not safe-to-share
by default. A timeout governs execution after preflight and input preparation.
The runner installs SIGINT/SIGTERM handlers that request owned-process-group
termination and retain work; this signal path requires platform verification.
Descendants that deliberately escape that group require an OS-level worker
boundary. A runner killed without cleanup can leave active processes and an
unconfirmed record; recovery never kills a process using an old saved PID.

`maxio-agent cancel --run /absolute/maxio-runs/<run-id>` records an explicit local
cancellation request. The live runner polls its own private directory and performs
the same owned-process-group termination. The command returns a **request receipt**,
not confirmed cancellation; inspect the terminal run record. A request written for
an abandoned run remains pending and never signals a PID recovered from metadata.
This control also works where an OS signal cannot be delivered to the runner's
async signal driver. Signal delivery needs separate platform verification; the
portable smoke journey verifies this explicit command instead.

### Codex and Claude Code

```sh
maxio-agent doctor --adapter codex --executable /absolute/native/codex
maxio-agent doctor --adapter claude --executable /absolute/native/claude
maxio-agent run --adapter codex --executable /absolute/native/codex \
  --source /absolute/project --input src --input AGENTS.md --output src \
  --records /absolute/maxio-runs --prompt-file /absolute/task.txt \
  --provider-home /absolute/trusted-codex-home --permission workspace-write
```

For Claude, choose `--adapter claude`, its executable and its trusted configuration
directory. Providers default to read-only; ordinary commands default to trusted
workspace-write execution and reject a requested read-only guarantee. Codex uses
an explicitly selected native sandbox. Fresh input copies exclude `.git`, so its
documented `--skip-git-repo-check` applies only to this prepared directory. Claude
requires version 2.1.259 or later and all advertised safety flags; it exposes only
Read/Glob/Grep, plus Edit/Write when workspace-write is selected. Bash and MCP tools
are unavailable in this profile. It does not promise a full coding/test loop.

Doctor runs only bounded version/help probes with a temporary home and minimal
PATH. Prefer a native binary if an npm wrapper needs a runtime outside that PATH.
`run --env PATH` also uses that explicit runtime path for capability preflight.
Provider homes remain outside input trees. `--env CODEX_API_KEY` or
`--env ANTHROPIC_API_KEY` selects already provisioned API authentication instead;
Claude also accepts an explicitly provisioned `CLAUDE_CODE_OAUTH_TOKEN`. No login,
credential distribution, installation, bare-mode requirement or permission bypass
is performed. Successful doctor output is not authenticated model execution.

Run `python3 scripts/smoke_agents.py --binary /absolute/maxio-agent` for the real
ordinary-command journey and explicitly labelled provider protocol fixtures. Add
`--artifacts /new/absolute/directory` to retain its disposable evidence. A fresh
critic must review this running artifact separately.

## Verification and independent review

Carry concrete regression tests for literal argv, selected inputs, no inherited
storage credentials, failed exit, missing/malformed terminal records, bounded logs,
wrong output paths, timeout/cancellation and retained edits. Run a real ordinary
command and inspect its outputs. Label fixtures plainly; never report them as real
Codex or Claude model execution. Fresh critic receives executable and instructions,
not the builder's reasoning. Follow `specs/journeys/local_agents.md`.
