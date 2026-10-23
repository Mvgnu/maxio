---
{
  "name": "console_api",
  "description": "Provide authenticated JSON management and downloads",
  "paths": {
    "owned": [
      "src/api/console.rs",
      "src/api/console/"
    ],
    "tests": [
      "tests/integration/console_tests.rs"
    ],
    "exclude": []
  },
  "exports": [
    "session/auth JSON",
    "bucket/object/version/lifecycle JSON",
    "system diagnostics DTOs",
    "ConsoleSessionStore"
  ],
  "consumes": [
    "runtime_platform.AppState and trusted TlsConnection metadata",
    "storage_engine",
    "cluster_metadata_plane",
    "s3_api_surface shared services"
  ],
  "verification": {
    "check": "cargo check --locked --all-targets",
    "test": "cargo test --locked --lib api::console:: && cargo test --locked --test integration console_tests::",
    "build": "cargo build --locked --bins",
    "architecture": "python3 scripts/check_architecture.py"
  },
  "bar": {
    "reference": "OWASP Session Management Cheat Sheet",
    "url": "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
    "property": "After logout, replaying a copied cookie cannot read or mutate protected management data; independent active sessions remain usable."
  },
  "artifact": "Live cookie login, bucket creation, upload/download, logout, unauthorized controls and typed error responses."
}
---

# Provide authenticated JSON management and downloads

## Required behavior

- Authenticate management routes and keep cookie sessions distinct from S3 credentials on the wire.
- Maintain typed JSON DTOs; do not turn missing data into invented healthy defaults.
- Delegate storage safety and consistency to the shared lower layer.
- Keep failures actionable and response contracts stable for the Svelte client.

## Known limits / next decision

- Credentials currently have equal management rights; authorization policy is not provided.
- Sessions are node-local, in-memory and limited to 4,096 active entries. Restart
  invalidates every previous cookie. The seven-day absolute expiry remains.
- Logout removes only the presented active session. Concurrent logins have distinct
  opaque random tokens; legacy stateless cookies are rejected. No raw bearer token
  is retained in the registry. Credential changes invalidate affected sessions.
- Full capacity fails explicitly after pruning expired entries; it does not evict
  another active operator. Already-admitted requests may finish after logout.
- Session tokens contain 32 random bytes encoded as 64 lowercase hex characters.
  Only SHA-256 verifiers and credential bindings are retained. Missing, malformed,
  duplicate, expired and revoked cookies receive the same unauthenticated response.
  A full registry returns HTTP 503 with an actionable JSON error.
- Login throttling uses the actual socket IP. Forwarded headers cannot create a
  new rate-limit bucket. At most 4,096 IP buckets are retained for the five-minute
  window; capacity denies new IPs without evicting existing limits. A reverse proxy's
  clients share its socket IP and login allowance. TLS connection metadata makes
  native HTTPS cookies Secure; forwarded protocol can only add that restriction.
- Copied-cookie revocation meets the selected live-session property in the
  [secure-peers review](../reviews/2026-10-23-secure-peers.md). That scoped verdict
  does not claim distributed sessions, in-flight revocation or a complete security audit.

## Review

Use [Gauntlet](../../gauntlet.md). The dated record in `specs/reviews/` is
the evidence; this specification alone is not a pass. Report the single largest
remaining gap against the property above.
