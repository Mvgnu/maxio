---
{
  "name": "runtime_platform",
  "description": "Start, stop, configure, and observe standalone and peer processes",
  "paths": {
    "owned": [
      "src/main.rs",
      "src/config.rs",
      "src/server.rs",
      "src/server/",
      "src/membership.rs",
      "src/embedded.rs"
    ],
    "tests": [
      "tests/peer_config.rs",
      "scripts/smoke_peer_s3.py",
      "tests/integration/runtime_tests.rs",
      "scripts/smoke_secure_peers.py"
    ],
    "exclude": []
  },
  "exports": [
    "Config",
    "AppState",
    "RuntimeTopologySnapshot",
    "build_public_router",
    "build_internal_router",
    "ServerTls",
    "serve_listener",
    "membership engine status",
    "native HTTPS listeners",
    "TLS-derived connection metadata"
  ],
  "consumes": [
    "storage_engine.FilesystemStorage",
    "cluster_transport_security peer identities",
    "cluster_metadata_plane coverage",
    "s3_api_surface routes",
    "console_api routes"
  ],
  "verification": {
    "check": "cargo check --locked --all-targets",
    "test": "cargo test --locked --lib server:: && cargo test --locked --lib config:: && cargo test --locked --lib membership:: && cargo test --locked --test peer_config && cargo test --locked --test integration runtime_tests::",
    "build": "cargo build --locked --bins",
    "architecture": "python3 scripts/check_architecture.py"
  },
  "bar": {
    "reference": "Garage quick start",
    "url": "https://garagehq.deuxfleurs.fr/documentation/quick-start/",
    "property": "A new operator starts one S3 process without cluster settings, or two explicitly configured peers, and can tell whether data operations are ready."
  },
  "artifact": "Run the binary, /healthz, scripts/smoke_peer_s3.py and scripts/smoke_secure_peers.py against disposable data; restart processes."
}
---

# Start, stop, configure, and observe standalone and peer processes

## Required behavior

- No peers means standalone; optional peer configuration must not complicate that path.
- Canonical host:port peer identities must be shared by membership, placement and authentication.
- Reject invalid peer endpoints before they can become routing targets; keep readiness diagnostics truthful.
- Bind internal routes only on the selected listener; report storage and peer readiness independently.
- Retry queues persist failures across restart; metrics describe actual acknowledgements and backlog.
- Cluster health probes authenticated bucket enumeration with a two-second bound.
  Its scope/status distinguish observed bucket readiness from coverage of a future
  object listing. The local probe never contacts another peer.

## Known limits / next decision

- Native HTTPS is optional. Peer TLS secures both the public node endpoint and
  any dedicated internal listener; ordinary S3/console clients need no peer certificate
  on the public listener. The internal listener requires a peer certificate.
- Invalid TLS pairs, partial peer triplets, conflicting TLS families, or required
  peer mode without a shared token fail before storage initialization or workers.
- Connection identity is derived from the verified TLS stream. Internal requests
  require an allowed nonlocal certificate identity bound to their sender claims.
- Runtime owns bounded handshakes, request metadata, safe shutdown, and target-aware
  clients for all background and control-plane traffic.
- Generic HTTPS is for standalone storage. Cluster peers require the peer TLS
  triplet so public node endpoints and outbound peer URLs use the same transport.
- A separate internal listener isolates control routes and requires peer TLS
  certificates when peer TLS is enabled. There is no separate peer control-address
  map: automated membership propagation still targets public node IDs. Use the
  combined listener for automatic peer control traffic; startup warns otherwise.
- Gossip is experimental probe-driven discovery. Raft is an unimplemented mode, never consensus.
- Existing public AppState/Config fields remain shared contracts; changes need a PM ruling.

## Review

Use [Gauntlet](../../gauntlet.md). The dated record in `specs/reviews/` is
the evidence; this specification alone is not a pass. Report the single largest
remaining gap against the property above.
