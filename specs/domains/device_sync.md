---
{
  "name": "device_sync",
  "description": "Synchronize ordinary files with an explicitly selected peer without mandatory cloud services",
  "paths": {
    "owned": [
      "src/sync/",
      "src/bin/maxio-sync.rs"
    ],
    "tests": [
      "tests/device_sync.rs",
      "scripts/smoke_device_sync.py"
    ],
    "exclude": []
  },
  "exports": [
    "maxio-sync CLI",
    "sync configuration",
    "persistent baseline and reconciliation outcomes"
  ],
  "consumes": [
    "S3 SigV4 HTTP",
    "standalone conditional PutObject",
    "standard filesystem"
  ],
  "verification": {
    "check": "cargo check --locked --all-targets",
    "test": "cargo test --locked --lib sync:: && cargo test --locked --test device_sync",
    "build": "cargo build --locked --bins",
    "architecture": "python3 scripts/check_architecture.py"
  },
  "bar": {
    "reference": "Syncthing synchronization and conflict preservation",
    "url": "https://docs.syncthing.net/users/syncing.html",
    "property": "Interrupted transfers and concurrent differing edits preserve both versions; a restart can resume a direct sync without a cloud coordinator."
  },
  "artifact": "Run two ordinary folders against an explicitly selected local peer, change each side, create a conflict, stop/restart peer and sync processes."
}
---

# Synchronize ordinary files with an explicitly selected peer without mandatory cloud services

## Required behavior

- Separate optional executable; maxio server startup remains unchanged.
- Persist the baseline scoped to local root, endpoint, bucket and prefix; never reuse another target journal.
- Require verified conditional-write behavior before user writes; fail closed if the endpoint ignores conditions.
- Complete and validate listings before reconciliation; reject unsafe keys, symlinks and ambiguous file paths.
- Stage downloads, preserve conflict copies, and compare content digests; wall-clock time is not an authority.
- No deletion propagation in this milestone: a missing copy is restored from the surviving one.

## Known limits / next decision

- An existing peer bucket is required. There is no automatic pairing, discovery, NAT traversal, relay, mesh membership or background OS service.
- This is polling of regular files, not a database replication protocol or full Syncthing replacement.
- Permissions, symlinks, filesystem metadata, atomic directory snapshots and deletions are outside this initial contract.

## Review

Use [Gauntlet](../../gauntlet.md). The dated record in `specs/reviews/` is
the evidence; this specification alone is not a pass. Report the single largest
remaining gap against the property above.
