---
{
  "name": "workspace_cache",
  "description": "Selective hydration and recoverable local workspace state",
  "paths": {
    "owned": [
      "src/workspace/local.rs",
      "src/workspace/local/",
      "src/bin/maxio-workspace.rs"
    ],
    "tests": [
      "tests/workspace_client.rs",
      "scripts/smoke_workspace.py"
    ],
    "exclude": []
  },
  "exports": [
    "workspace::LocalWorkspace (including credential-free open_offline)",
    "explicit managed format-2 binding, catalog observation and publication acceptance",
    "maxio-workspace CLI",
    "persisted catalog and per-file working baseline"
  ],
  "consumes": [
    "workspace::contract",
    "workspace::WorkspaceReader for exact-snapshot hydration",
    "workspace::WorkspaceRemote",
    "files portable filesystem checks"
  ],
  "verification": {
    "check": "cargo check --locked --all-targets",
    "test": "cargo test --locked --lib workspace::local:: && cargo test --locked --test workspace_client",
    "build": "cargo build --locked --bins",
    "architecture": "python3 scripts/check_architecture.py"
  },
  "bar": {
    "reference": "Rclone selective copy",
    "url": "https://rclone.org/commands/rclone_copy/",
    "property": "Three isolated client roots can discover the same dataset, hydrate only an explicit directory and publish selected edits, with zero unrelated payload transfer and no overwrite of a dirty local copy."
  },
  "artifact": "Built maxio-workspace CLI against a real S3 process; three local device roots, a 128 MiB dataset, byte reports, conflict and restart recovery."
}
---

# Selective hydration and recoverable local workspace state

## Required behavior

The PM-owned types and seeded method signatures are the cross-domain contract.
`LocalWorkspace::open(root,target_id)` locks one trusted local root and binds its
`.maxio-workspace` state to one canonical storage target. The root already exists.
Reject symlinks, unsafe/ambiguous paths, runtime data directories and target switches.
Reuse `files` helpers; never invent another path normalization rule.
Admission and local file selection reject any requested path inside a root marked
by `.maxio-runtime`, `.maxio-fabric` or `.maxio-worker`. Marker entries, including
dangling symlinks, are checked before creating workspace control state, publication
stages or hydration destinations. Authority vaults and worker caches remain private;
an explicit nested-file selector cannot bypass their root marker. Independent
source projects and ordinary nested source directories retain their existing
behavior. An existing workspace placed inside a newly marked private tree is
refused without modifying its saved state or files.

`open_managed(root, &ManagedTarget)` explicitly creates managed local format 2.
It persists the canonical HTTPS origin, authority, vault and workspace binding,
and a separate `ManagedHead`; its canonical `Snapshot` always has no S3 ETag.
Direct format-1 state keeps its original serialized shape and behavior. Neither
mode can adopt the other's root, even if a caller supplies a matching target string.
Offline inspection takes the same operation lock and supports either initialized
format without credentials or network access. Invalid or inconsistent saved state
is rejected and preserved rather than migrated, reset or rebound.

- Persist an observed published snapshot separately from each working file's baseline
  and pin state. Atomic fsynced state replacement; bound parsed state. Reload after
  process restart. A refresh updates discovery, never falsely advances a dirty
  working copy to a newly observed remote version.
- `snapshot()` returns the cached observed snapshot or a clear initialization error.
  `observe()` checks stable workspace identity and validates imported metadata before
  replacing that snapshot. Metadata-only `describe(false)` must not hash/read all
  cached file contents; report present_unverified. `describe(true)` checks actual
  local bytes and reports absent/clean/stale/dirty without pretending presence is trust.
  Stale means bytes still match their hydrated baseline but the observed catalog
  references a different immutable version. Refresh never advances that baseline.
  `open_offline(root)` reloads an initialized binding/catalog without credentials
  or network access and takes the same operation lock as online commands.
- `observe_managed(&ManagedCatalog)` validates canonical manifest content, the
  bound authority/workspace, an exact head-to-manifest match and a positive current
  generation. It rejects historical catalogs, S3 ETags, generation rollback and
  conflicting identities at an already observed generation. `managed_head()`
  returns only that separately persisted publication base. Discovery changes
  never advance a working baseline or remove local bytes.
- `prepare_publish(selectors)` selects exact files/directories (or explicit `.`),
  rejects missing selectors and reserved control paths, stages/fsyncs selected regular
  files with bounded memory and records SHA-256/size. No unrelated directory upload.
  For existing remote paths require a matching working baseline; an untracked local
  file must never overwrite an existing published path. Compare selected baselines
  with the current observed snapshot. Preserve staged edits on any failure.
- `accept_publication(snapshot,files)` updates the catalog and the published baselines,
  not an assertion that live local bytes stayed unchanged during transfer. Do not
  remove unpublished data. A failed metadata save leaves recoverable staging.
- `accept_managed_publication(&ManagedCatalog,files)` applies the same staged-byte,
  selected-path and parent-revision checks, atomically persisting its managed head,
  observed snapshot and selected baselines. A matching retry is accepted. A failed
  save preserves the old in-memory head/baselines, live edits and publication stages.
  Direct catalog/publication entry points cannot be used on managed roots.
- `pull(reader,snapshot,selectors)` is generic over the frozen `WorkspaceReader`
  contract. It calls `download_at` with the exact requested snapshot and path, and
  verifies the reader's target binding before transferring any payload. It hydrates
  only selected files through verified
  staging. If the target differs from its baseline or is an untracked conflicting
  file, reject and leave it untouched. Preserve the old inode before a clean
  replacement so a late open-descriptor write remains recoverable. Never replace
  a concurrently arriving file. Missing remote content is unavailable, not deletion.
- `pin(selectors,true)` pins successfully hydrated exact files in this snapshot,
  not future directory members; require verified matching bytes first. Unpin is
  explicit. Catalog/status/pin state remain inspectable offline.
- Historical pull is explicit; it must not turn the historical snapshot into a
  publication base or silently change the currently observed catalog. Working
  baselines retain the actual hydrated version, so a stale edit still conflicts.
- Managed remote deletion is logical absence, never a local filesystem deletion.
  A retained baseline absent from the observed catalog remains visible in managed
  status with its historical logical reference, byte identity and pin. Verified
  bytes matching that baseline are stale; later edits are dirty. Its old baseline
  cannot authorize republishing a deleted path. Unpinning that retained path works
  offline; pinning a current version still requires verified current bytes. An
  explicit authority restore of the exact original immutable `FileVersion` is a
  recovery decision: after observing it, ordinary matching-baseline publication may
  proceed. The local cache does not create a second persistent tombstone authority.
- The CLI prints machine-readable JSON with revisions, paths and transfer counters.
  Failures exit nonzero. Endpoint credentials are environment-only (no secrets in
  config or logs); `--allow-http` is an explicit trusted-network development option.

## Limits / PM stop

This domain implements discovery, selective transfer, immutable revision baselines,
conflict rejection, pins and inspectable editable state. Managed authorization,
logical delete/restore commands and transport belong to their separate authority
and CLI domains. This adapter adds no destructive eviction, background sync or
resumable transfers. Editable working copies and their retained staging/history
never become eviction eligible because a managed catalog was observed. The existing
`evict` refusal and its retention/durability explanation leave bytes intact. This
adapter alone does not establish complete Journey B or disk reclamation.

Filesystem protection assumes an operator-owned root with no hostile concurrent
ancestor replacement. A local lock coordinates MaxIO processes, not arbitrary editors.
The catalog and working baselines are bounded; whole-directory atomic snapshots
are not promised.
State is limited to 32 MiB. Publication stages and replaced inodes remain under
`.maxio-workspace/staging/` and `history/` with path/version recovery receipts;
this wave does not automatically prune them. Failed state writes preserve those
bytes and can leave an installed file reported dirty until manually reconciled.

## PM integration grant

The PM implements the direct and managed CLIs and cross-domain process drills,
updates shared filesystem/helpers/contracts and full-gate registration. The cache
builder owns local implementation and regressions only. The managed adapter uses
workspace contracts without importing fabric. No other domain's source is writable
from this bubble.

## Review

Follow `specs/journeys/selective_workspace.md`, including dirty-file refusal,
restart/offline preservation and actual byte observations. A green unit suite is not
an independent pass; full safe eviction remains a recorded open requirement.
