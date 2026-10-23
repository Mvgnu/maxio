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
    "system diagnostics DTOs"
  ],
  "consumes": [
    "runtime_platform.AppState",
    "storage_engine",
    "cluster_metadata_plane",
    "s3_api_surface shared services"
  ],
  "verification": {
    "check": "cargo check --locked --all-targets",
    "test": "cargo test --locked --test integration console_tests::",
    "build": "cargo build --locked --bins",
    "architecture": "python3 scripts/check_architecture.py"
  },
  "bar": {
    "reference": "MinIO Console object management",
    "url": "https://github.com/minio/console",
    "property": "An authenticated operator can upload and retrieve identical bytes; unauthenticated callers cannot perform that task."
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
- Logout clears the browser cookie but does not revoke a copied stateless session.
  The critic reproduced replay until expiry (seven days) or credential change.
  PM stops session revocation work in this wave; treat the cookie as a bearer
  credential. Server-side revocation is an explicit next decision.

## Review

Use [Gauntlet](../../gauntlet.md). The dated record in `specs/reviews/` is
the evidence; this specification alone is not a pass. Report the single largest
remaining gap against the property above.
