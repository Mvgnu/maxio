---
{
  "verification": {
    "check": "cargo check --locked --all-targets",
    "build": "cargo build --locked --bins",
    "architecture": "python3 scripts/check_architecture.py",
    "test": "cargo test --locked --test fabric_transport"
  },
  "name": "fabric_transport",
  "description": "Individual device authentication and verified HTTPS managed workspace CLI",
  "paths": {
    "owned": [
      "src/fabric/client.rs",
      "src/fabric/transport.rs",
      "src/fabric/transport/",
      "src/bin/maxio-fabric.rs"
    ],
    "tests": [
      "tests/fabric_transport.rs",
      "scripts/smoke_fabric.py"
    ],
    "exclude": []
  },
  "exports": [
    "FabricClient authenticated streaming transfer",
    "maxio-fabric CLI",
    "individual Ed25519 key proof and revocable sessions"
  ],
  "consumes": [
    "fabric::contract",
    "fabric::authority::Authority",
    "server::{ServerTls,serve_listener}",
    "workspace::LocalWorkspace",
    "fabric::cache and worker inspection"
  ],
  "bar": {
    "reference": "Syncthing device authentication",
    "url": "https://docs.syncthing.net/users/security.html",
    "property": "A newly generated device key has no workspace authority until explicitly enrolled and granted; revocation rejects subsequent reads and commits over verified encrypted connections without sharing storage credentials."
  },
  "artifact": "Three distinct key/root client environments, running native HTTPS authority, targeted transfers and live revocation."
}
---

# Individual device authentication and verified HTTPS managed workspace CLI

The PM ruling in `specs/00_system.md` and `fabric::contract` are authoritative.
Read `lop.md` and `gauntlet.md`. This domain cannot expand its own write gate.

## Acceptance

The managed CLI keeps JSON output by default. `task logs --text` prints the exact
decoded retained log page without an external decoding step. `--offset` selects
the next byte page and `--stderr` selects that stream; JSON retains pagination and
transfer metadata. The wire `LogPage` remains base64 and unchanged.

Use the managed B/C/D/E journey in `specs/journeys/managed_fabric.md`. Preserve
canonical workspace and execution types and standalone startup independence.
Record observed evidence in a dated review, not a progress diary in this spec.
An isolated-process demonstration must not be described as physical multi-device
validation. No claimed provider model execution follows from protocol fixtures.

## Limits

Single authority; no quorum, automatic failover, NAT discovery or hostile same-UID
execution isolation. Native commands remain owner-trusted. Vault retention means
fsynced append-only files in one private server filesystem, not redundant physical
storage. Direct-S3 editable workspaces remain non-evictable. No automatic retry or
workspace-history pruning. Capacity exhaustion rejects new work explicitly.
