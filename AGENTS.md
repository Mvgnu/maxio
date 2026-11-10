# MaxIO source ownership and agent routing

Current implementation, specs and contributions belong in the
[MCP-Host monorepo](https://github.com/Mvgnu/MCP-Host). Read
[MIGRATION.md](MIGRATION.md), then that checkout's root `AGENTS.md`,
`specs/00_product.md`, `specs/02_monorepo.md`, workflow rules and relevant
component/crate spec before making current product changes.

This repository retains the historical MaxIO source imported at
`4acb17fb10f177a4e1e071247da376dcbe960fc7`. Do not develop a parallel runtime,
coordinator, storage implementation or provider adapter here. Do not restore
automatic CI or a release publisher here as a shortcut for current development.
The Host consolidation must land before this companion cutover is merged.

This source-ownership ruling takes precedence over the historical development
instructions, specs, skill text and roadmap retained below and elsewhere in
this repository. An explicitly requested historical reproduction uses the
retained rules against its named revision and reports that limited scope.

## Historical development rules

Read [the system contract](specs/00_system.md), [Lop](lop.md), and
[Gauntlet](gauntlet.md) before changing code. Read your domain's spec in
`specs/domains/`; a missing spec is a PM task, not permission to invent a boundary.

- Keep the default `maxio` server a simple standalone S3 service.
- Peer S3 and device sync are separate product journeys with separate guarantees.
- Use Rust and **Bun**, the checked-in toolchain versions, and locked dependencies.
- Work in an isolated branch/worktree. Stay inside the spec's write gate.
- Shared contract changes and cross-domain work require a recorded PM ruling.
- Preserve data and source compatibility deliberately; do not silently migrate storage.
- Write a regression that fails for a concrete defect before fixing it.
- Run the domain gates, architecture gate, and final full gate at integration.
- A passing test is not a Gauntlet pass. A fresh critic must inspect the actual
  running binary, served console, or synchronization result against its stated bar.
- Report paths changed, commands/results, disagreements, and remaining defects.
  Never claim an unrun check or an unobserved product capability.

Product spelling is **MaxIO**. Lowercase `maxio` is appropriate for paths,
commands, identifiers, and URLs. Do not append progress diaries to specifications.
