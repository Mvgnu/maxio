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
    "join authorization",
    "PeerTlsConfig",
    "VerifiedPeerIdentity",
    "peer_node_identity_uri",
    "build_peer_tls_acceptor",
    "verified_peer_identity_from_tls",
    "build_peer_mtls_http_client"
  ],
  "consumes": [
    "HTTP headers",
    "OpenSSL certificate APIs",
    "Rustls WebPkiServerVerifier and Reqwest TLS configuration"
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

## Secure transport contract

The secure-peers ruling in `specs/00_system.md` is authoritative. Native peer TLS
must prove the exact canonical host:port identity on the connection carrying the
request. The MaxIO URI SAN binds a certificate to a node; normal DNS/IP SAN and
chain verification remain required. A separate preflight cannot authorize traffic.

`VerifiedPeerIdentity` has private state and is minted only from a completed,
verified TLS connection. Outbound clients verify the expected full node identity
inside the actual handshake, with normal signature verification, configured CA
roots, revocation checks, no redirects and no environmental proxies.

Incoming certificates must independently bind the URI host to a normal DNS/IP
SAN before an identity is minted or HTTP is dispatched. OpenSSL performs DNS
matching with common-name fallback disabled, and matches IPv4/IPv6 hosts against
IP SAN bytes. A trusted URI alone, a mismatched host SAN, or a matching common
name without the required host SAN cannot authenticate a peer.

`PeerTlsConfig` is independent of runtime configuration. Its constructors validate
the local key pair, validity, full node URI, DNS/IP SAN and certificate chain for
both server and client use. The CA path accepts a certificate bundle. A local leaf
fingerprint pin is optional; configured leaf revocations apply to local and remote
identities. Key and policy changes take effect when the relevant transport is rebuilt.

The public acceptor verifies supplied client certificates while permitting ordinary
HTTPS clients without one. Runtime must require `VerifiedPeerIdentity` for internal
operations and bind it to membership and claimed sender. The node-bound readiness
probe uses the same URI parser, but readiness diagnostics and legacy attestation
functions never authorize an HTTP request on another connection.

## Known limits / next decision

- Compatibility mode is not a safe internet deployment.
- Certificate issuance, distribution, renewal and revocation are operator tasks;
  automatic device pairing and NAT traversal are outside this milestone.
- Independent acceptance of the repaired incoming DNS/IP SAN boundary remains
  blocked by the platform security gate. The required join/mutation recheck and
  PM stop are recorded in the [secure-peers review](../reviews/2026-10-23-secure-peers.md).
  Passing automated handshake tests does not close that artifact review.

## Review

Use [Gauntlet](../../gauntlet.md). Review actual connections and bytes. A passing
certificate parser test is not a peer-identity quality verdict.
