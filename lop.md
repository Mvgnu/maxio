---
description: Domain-scoped Rust and Svelte development with explicit write boundaries
---

# Lop: scoped development

Lop asks whether a domain implements its specification. [Gauntlet](gauntlet.md)
asks whether the result meets an external standard. Use both.

MaxIO is a Rust crate and a Bun/Svelte console. Do not impose a pnpm workspace or
split crates merely to imitate the originating workflow. A domain is a coherent
responsibility with one spec in `specs/domains/<name>.md`. Product journeys in
`specs/journeys/` cut across these responsibilities; they are PM-owned acceptance
contracts, not a second set of writable bubbles.

## Write gate

Each domain spec declares `paths.owned`, `paths.tests`, `exports`, `consumes`,
`verification`, and an external `bar.reference` plus `bar.property`. Frontmatter
uses JSON, a YAML subset, so the gate can parse it without another dependency.
Patterns are repository-relative; a trailing `/` owns the subtree. `paths.exclude`
and PM-owned paths override a broad grant. A builder may edit its own domain spec
to correct its interface or commands, but cannot enlarge its own write permissions.

Allowed: its owned paths, its test paths, and its own spec. Read-only: everything
else. The PM owns `specs/00_system.md`, journey specs, root manifests/lockfiles,
toolchain and release configuration, CI, agent instructions, architecture gates,
and the shared contract facades listed in the system contract. Build artifacts and
data directories are never source changes. Existing lower-level types are the
contract; never create parallel copies to evade a dependency or ownership problem.

## Cycle

1. Read the system contract, domain spec, consumed interfaces, and external bar.
2. Branch into an isolated worktree from the PM's named integration commit.
3. Reproduce the defect or define the acceptance scenario. Change only your bubble.
4. Run the declared commands. Run the architecture gate. At integration, the PM
   runs the full suite once, rather than hundreds of duplicated test invocations.
5. Gate the complete branch diff, including deletions and renames:
   `python3 scripts/check_architecture.py --domain DOMAIN --base BASE_SHA`.
   The PM can inspect a finished branch using `--head BRANCH`.
6. If a shared contract is wrong, stop that part, report it plainly, and ask the PM
   for a ruling. The PM changes the contract and assigns the follow-up bubble.
7. Update public-surface descriptions and report four things: changed paths;
   commands actually run and outcomes; disagreements; what remains broken.
8. Give the artifact to a fresh Gauntlet critic. The builder does not award a pass.

Run targeted regressions during the cycle, the domain gates before handoff, and
the full gate after integration. Do not rerun the full suite after every keystroke.

## Scope changes

A cross-domain change starts in `specs/00_system.md`, with an explicit PM ruling.
Split implementation by disjoint paths, integrate in dependency order, and check
the resulting journey. Domain owners may not expand `paths` or rewrite architecture
tests to make their own violation pass. The gate compares the scope to the base
spec when it exists; initial adoption requires the PM to establish that baseline.

## Anti-patterns

| Pattern | Required correction |
|---|---|
| Missing or ignored specs | Track them and fail the architecture gate |
| Hundreds of claims without a runnable example | Write a small process-level journey |
| Making standalone users configure a cluster | Keep standalone defaults independent |
| Calling replication "folder sync" | Specify files, baselines, conflicts, and deletion behavior |
| Duplicating transport or storage types | Import the canonical type; request a contract amendment |
| Silently ignoring a precondition | Honor it atomically or reject the operation |
| Adding a framework to organize a tiny operation | Prefer an existing responsibility and a small module |
| A critic judging the builder's report | Give the critic the real artifact and the bar |
