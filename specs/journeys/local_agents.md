# Local command, Codex and Claude adapters: execution foundation

The artifact is `maxio-agent`, with a fresh run directory, selected input files,
logs, durable run record and proposed outputs. It is an optional local runner.

## Acceptance property

Against [Codex non-interactive execution](https://developers.openai.com/codex/non-interactive-mode):
a real task runs using explicit inputs and literal argv, records completion only
after a successful process and terminal protocol event, and preserves work after
failure or cancellation. Claude's own [CLI contract](https://code.claude.com/docs/en/cli-reference)
and [headless behavior](https://code.claude.com/docs/en/headless) govern its adapter.

## Required exercise

- Run a real ordinary command that consumes one selected input, writes an allowed
  output, and logs progress. Confirm the original input and unrelated files stay intact.
- Observe child environment without printing secrets: inherited storage variables
  must be absent. Arguments containing shell metacharacters must remain literal.
- Run a failing command after it writes an output. Inspect retained edit, stderr,
  exit code and failed record. Timeout a descendant process group. For cancellation,
  use `maxio-agent cancel --run DIR`, distinguish its request receipt from the
  runner's terminal `cancelled` state, and inspect retained edits and stopped
  descendants. An abandoned record never authorizes signaling a saved PID. Verify
  SIGINT/SIGTERM separately before claiming signal-based cancellation. No automatic
  publication or cleanup is allowed.
- Exercise provider success, failure, permission denial and malformed/incomplete
  terminal event streams with clearly named fixture executables. These are adapter
  contract tests, not authenticated model execution.
- If real supported CLIs are installed, `doctor` reads their actual version/help.
  It must not authenticate, run a model, install tools or relax permission policy.
- Only claim real Codex/Claude execution after an installed authenticated provider
  has actually completed the requested edit and validation under the declared policy.
  If credentials are absent, record that scope as unverified.

## Trust boundary and future work

Only trusted owner-selected executables are in scope. Native provider safeguards
are preserved, but cwd and environment scrubbing do not isolate arbitrary code from
same-user files. Do not pass storage master keys to a child. Provider credential
profiles are explicitly selected and never copied into task inputs or artifacts.

No remote worker, locality scheduling, lease authority, job retry, OS resource quota,
provider resume, automatic source merge or automatic artifact publication is delivered
by this slice. Git still handles source history and merging. The flagship move-compute-
to-data journey needs actual separate worker execution in a later milestone.
