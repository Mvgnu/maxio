# Working on MaxIO

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
