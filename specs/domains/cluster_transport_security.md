---
{
  "name": "cluster_transport_security",
  "description": "Bind authenticated requests to the configured peer identity",
  "paths": {
    "owned": [
      "src/cluster/"
    ],
    "tests": [],
    "exclude": [
      "src/cluster/mod.rs"
    ]
  },
  "exports": [
    "PeerAuthenticator",
    "canonical_peer_identity",
    "forwarding envelopes",
    "transport identity and attestation",
    "join authorization"
  ],
  "consumes": [
    "HTTP headers",
    "OpenSSL certificate APIs"
  ],
  "verification": {
    "check": "cargo check --locked --all-targets",
    "test": "cargo test --locked --lib cluster::",
    "build": "cargo build --locked --bins",
    "architecture": "python3 scripts/check_architecture.py"
  },
  "bar": {
    "reference": "TLS 1.3 peer authentication",
    "url": "https://www.rfc-editor.org/rfc/rfc8446",
    "property": "An untrusted peer cannot become a trusted internal sender by copying forwarding headers or claiming another node identity."
  },
  "artifact": "Run live internal-header rejection and certificate identity tests; inspect actual listeners, not merely configuration names."
}
---

# Bind authenticated requests to the configured peer identity

## Required behavior

- A shared token is authentication, not transport encryption or per-device authorization.
- Normalize identities once; forwarding-hop and allowlist checks use the same canonical identity.
- Reject forged, replayed, mismatched, or unbound internal operations with observable reasons.
- Never describe outbound TLS verification as an inbound TLS server.

## Known limits / next decision

- Compatibility mode is not a safe internet deployment.
- Inbound TLS termination and certificate lifecycle are deployment requirements, not delivered device pairing.
- **Gauntlet gap, PM stop for this wave:** a holder of the shared cluster token can
  claim another configured peer. The native HTTP listener does not prove possession
  of that peer's private key. Required transport mode fails closed in the tested
  configuration; it does not supply inbound TLS. This domain has no quality pass
  against its identity bar. Keep the experimental peer journey on an operator-
  controlled encrypted channel pending an inbound identity design.

## Review

Use [Gauntlet](../../gauntlet.md). The dated record in `specs/reviews/` is
the evidence; this specification alone is not a pass. Report the single largest
remaining gap against the property above.
