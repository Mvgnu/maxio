---
{
  "name": "s3_auth_sigv4",
  "description": "Authenticate normal S3 clients and reject forged requests",
  "paths": {
    "owned": [
      "src/auth/"
    ],
    "tests": [
      "tests/auth_payload.rs",
      "tests/integration/auth_tests.rs"
    ],
    "exclude": []
  },
  "exports": [
    "SigV4 verification",
    "auth middleware",
    "presign verification"
  ],
  "consumes": [
    "runtime_platform.AppState",
    "cluster_transport_security internal header boundary"
  ],
  "verification": {
    "check": "cargo check --locked --all-targets",
    "test": "cargo test --locked --lib auth:: && cargo test --locked --test integration auth_tests:: && cargo test --locked --test auth_payload",
    "build": "cargo build --locked --bins",
    "architecture": "python3 scripts/check_architecture.py"
  },
  "bar": {
    "reference": "AWS Signature Version 4",
    "url": "https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html",
    "property": "An ordinary SigV4 client can authenticate while invalid credentials, changed signed bytes and invalid internal trust fail."
  },
  "artifact": "Use a real signed HTTP client against the binary, include a wrong-secret control and presigned expiry tests."
}
---

# Authenticate normal S3 clients and reject forged requests

## Required behavior

- Use the existing canonical request implementation; no endpoint-specific signing variants.
- Additional credentials are identities with equal current capabilities, not an IAM policy engine.
- Internal forwarding trust does not bypass public credential validation accidentally.
- Verify hexadecimal payload digests before any handler can mutate data. Verify
  every signature in the supported AWS chunk chain, including its terminal chunk.
- Authentication stages at most 64 KiB in memory, then uses a private temporary
  file. Downstream handlers still buffer whole uploads; this is not a server-wide
  streaming-memory guarantee.

## Known limits / next decision

- Multi-user authorization/IAM policies are not implemented.
- Accepted UNSIGNED-PAYLOAD behavior is deliberate; it is not an end-to-end content checksum.
- Streaming trailer variants and SigV4a are unsupported and must fail explicitly.

## Review

Use [Gauntlet](../../gauntlet.md). The dated record in `specs/reviews/` is
the evidence; this specification alone is not a pass. Report the single largest
remaining gap against the property above.
