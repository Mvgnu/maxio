# MaxIO source cutover to MCP-Host

## Merge order

1. Merge the [MCP-Host consolidation](https://github.com/Mvgnu/MCP-Host/tree/refactor/agent-infra-monorepo)
   after its required review and verification.
2. Merge this companion MaxIO source cutover.

The companion must not land first: its current-source links target the resulting
MCP-Host `main` branch. Preparing or merging these repository changes does not
deploy services, migrate data, replace identities or authenticate providers.

## One canonical source repository

Current development, issues, pull requests, operating documentation and release
configuration belong in [Mvgnu/MCP-Host](https://github.com/Mvgnu/MCP-Host).
The imported source is MaxIO commit
`4acb17fb10f177a4e1e071247da376dcbe960fc7`.
The Host monorepo records the original blobs and modes in
[`specs/imports/maxio.json`](https://github.com/Mvgnu/MCP-Host/blob/main/specs/imports/maxio.json).

| Responsibility | Canonical location |
|---|---|
| S3, peer storage, sync, workspaces, immutable data, private cache and publication authority | [`components/maxio/`](https://github.com/Mvgnu/MCP-Host/tree/main/components/maxio) |
| MaxIO data-management MCP adapter and agent skill | [`components/maxio/mcp/`](https://github.com/Mvgnu/MCP-Host/tree/main/components/maxio/mcp) |
| Commands/provider adapters, local execution and retained run records | [`crates/agent-execution/`](https://github.com/Mvgnu/MCP-Host/tree/main/crates/agent-execution) |
| Managed worker execution and retained-attempt reconciliation | [`crates/worker/`](https://github.com/Mvgnu/MCP-Host/tree/main/crates/worker) |
| Shared portable file/path/hash/fsync primitives | [`crates/portable-files/`](https://github.com/Mvgnu/MCP-Host/tree/main/crates/portable-files) |
| Machine/service management, deployments and infrastructure observations | [`apps/`](https://github.com/Mvgnu/MCP-Host/tree/main/apps) and [`packages/`](https://github.com/Mvgnu/MCP-Host/tree/main/packages) |
| Cross-domain ownership and migration decisions | [`specs/02_monorepo.md`](https://github.com/Mvgnu/MCP-Host/blob/main/specs/02_monorepo.md) |

Read the monorepo's root instructions and the applicable domain spec before
changing code. Its scoped write gates and fresh-artifact Gauntlet govern current
work. This repository's earlier rules and product claims are historical context,
not a competing set of current ownership instructions.

## What remains here

This repository retains its Git history, Rust/Bun implementation, tests, specs,
historical review records, LICENSE and NOTICE. No runtime source or storage
format is deleted or changed by this companion. The README's original build and
operation instructions are labelled historical so the imported revision remains
inspectable and reproducible.

Automatic push/PR CI is disabled here. The remaining workflow requires an
explicit manual dispatch and verifies historical source with read-only repository
permissions. The release workflow is removed so this repository does not remain
a second automatic or manual image/release publisher. Its former configuration
remains recoverable in Git history. Existing tags and published artifacts are not
deleted or presented as current monorepo builds.

This change does not alter GitHub repository archive settings or install an
automatic synchronization bot. Future changes belong in the canonical repository;
keeping two independently developed copies is outside the cutover contract.

Repository visibility also stays unchanged: MCP-Host is currently private, while
this MaxIO repository is public. Access to current monorepo development therefore
requires a Host grant; the current-source links are not public source mirrors.
The public historical snapshot and existing releases remain available here.
Future public standalone S3 source/releases need an explicit export/distribution
decision in the canonical repository. Private CI artifacts are not a public
release channel, and this cutover does not publish the private control plane.

## Executable and source compatibility

Standalone `maxio` continues to run without a Host control plane, managed
authority or worker. Rust and Bun remain the data/execution component toolchains;
Node/pnpm remain the infrastructure control-plane toolchains.

The monorepo supplies `mcp-host-agent` and `mcp-host-worker`; the existing
`maxio-agent` and `maxio-worker` names are compatibility entrypoints to those
same execution implementations. The worker library import moves from
`maxio::fabric::worker` to `mcp_host_worker`; this is an explicit source API
change, not a wire or retained-state format migration.

The existing managed authority remains the sole canonical job/lease/publication
transaction during extraction. A later orchestration/data-authority split
requires its own versioned protocol and cutover. Moving source into one repository
does not create a second coordinator.

## Existing installations

Running services, private settings, MCP registrations, provider installations and
user data are not changed by this repository cutover. Follow the canonical
operating instructions for any separately authorized binary replacement.

Preserve complete persistent roots, credentials, device identities and unpublished
work. Keep a worker's absolute root/mount path stable because it is part of the
retained binding. Do not run initialization to compensate for a missing mount,
generate replacement keys during an update, prune retained attempts or translate
an interrupted action into an automatic retry.

An MCP registration that points into this old checkout is not automatically
redirected. Update its executable/source paths deliberately to a verified
monorepo build and discover the live tool schemas. Existing private configuration
and grants retain their intended authority; a source move is not a credential
exchange or permission change.

Image/configuration rollback does not rewind data, workspace heads, leases or
external execution effects. Authority restart and worker reconciliation retain
their existing explicit semantics. Runtime acceptance evidence belongs to the
exact built artifact being deployed, not to this source notice.
