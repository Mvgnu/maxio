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
    "maxio-workspace CLI",
    "persisted catalog and per-file working baseline"
  ],
  "consumes": [
    "workspace::contract",
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
- `prepare_publish(selectors)` selects exact files/directories (or explicit `.`),
  rejects missing selectors and reserved control paths, stages/fsyncs selected regular
  files with bounded memory and records SHA-256/size. No unrelated directory upload.
  For existing remote paths require a matching working baseline; an untracked local
  file must never overwrite an existing published path. Compare selected baselines
  with the current observed snapshot. Preserve staged edits on any failure.
- `accept_publication(snapshot,files)` updates the catalog and the published baselines,
  not an assertion that live local bytes stayed unchanged during transfer. Do not
  remove unpublished data. A failed metadata save leaves recoverable staging.
- `pull(remote,snapshot,selectors)` hydrates only selected files through verified
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
- The CLI prints machine-readable JSON with revisions, paths and transfer counters.
  Failures exit nonzero. Endpoint credentials are environment-only (no secrets in
  config or logs); `--allow-http` is an explicit trusted-network development option.

## Limits / PM stop

M1 is split deliberately. This first slice implements discovery, selective transfer,
immutable revisions, conflict rejection, pins and inspectable cache state. It does
not yet implement destructive eviction, tombstones, background sync, resumable
transfers or secure device enrollment. `evict` must refuse with a precise unsupported
retention/durability message and leave bytes intact. Do not claim the complete
three-device Journey B or disk-reclamation requirement has passed.

Filesystem protection assumes an operator-owned root with no hostile concurrent
ancestor replacement. A local lock coordinates MaxIO processes, not arbitrary editors.
The catalog and working baselines are bounded; whole-directory atomic snapshots
are not promised.
State is limited to 32 MiB. Publication stages and replaced inodes remain under
`.maxio-workspace/staging/` and `history/` with path/version recovery receipts;
this wave does not automatically prune them. Failed state writes preserve those
bytes and can leave an installed file reported dirty until manually reconciled.

## PM integration grant

The PM implements the CLI and cross-domain process drill, updates shared filesystem
helpers and full-gate registration. The cache builder owns local implementation and
regressions only. No other domain's source is writable from this bubble.

## Review

Follow `specs/journeys/selective_workspace.md`, including dirty-file refusal,
restart/offline preservation and actual byte observations. A green unit suite is not
an independent pass; full safe eviction remains a recorded open requirement.
