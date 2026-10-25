---
{
  "name": "s3_api_surface",
  "description": "Expose honest S3 semantics over HTTP",
  "paths": {
    "owned": [
      "src/api/bucket.rs",
      "src/api/bucket/",
      "src/api/object.rs",
      "src/api/object/",
      "src/api/list.rs",
      "src/api/list/",
      "src/api/multipart.rs",
      "src/api/multipart/",
      "src/api/router.rs",
      "src/error.rs",
      "src/xml/",
      "src/api/conditions.rs"
    ],
    "tests": [
      "tests/s3_contract.rs",
      "tests/integration/core_tests.rs",
      "tests/integration/checksum_tests.rs"
    ],
    "exclude": []
  },
  "exports": [
    "S3 HTTP routes",
    "S3Error XML",
    "bucket/object/multipart/list responses"
  ],
  "consumes": [
    "runtime_platform.AppState",
    "storage_engine",
    "s3_auth_sigv4",
    "cluster_metadata_plane",
    "cluster_transport_security"
  ],
  "verification": {
    "check": "cargo check --locked --all-targets",
    "test": "cargo test --locked --lib api:: && cargo test --locked --lib error:: && cargo test --locked --test integration core_tests:: && cargo test --locked --test s3_contract",
    "build": "cargo build --locked --bins",
    "architecture": "python3 scripts/check_architecture.py"
  },
  "bar": {
    "reference": "Amazon S3 PutObject and conditional writes",
    "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html",
    "property": "A standard HTTP client receives correctly framed responses and an atomic failed precondition instead of a silent lost update."
  },
  "artifact": "Signed live PUT/GET/list/restart requests, competing conditional writes and body-framing checks."
}
---

# Expose honest S3 semantics over HTTP

## Required behavior

- Response Content-Length describes the response body, never the stored object for an empty PUT response.
- Standalone PutObject honors If-None-Match:* and exact If-Match; failed conditions return 412.
- Reject unsupported conditional mutation families and distributed conditional writes explicitly; never ignore them.
- Reject unsupported `retention`, `legal-hold` and `object-lock` subresources and
  `x-amz-object-lock-*`, `x-amz-bucket-object-lock-enabled` and
  `x-amz-bypass-governance-retention` headers with S3 `NotImplemented` (501) at the
  authenticated S3 router before operation dispatch. Mixed multipart, copy, batch
  delete, version-specific delete or bucket-configuration requests must not mutate
  objects, versions, uploads or buckets. Read requests must not return ordinary
  object/listing data as if it were retention metadata.
- Map storage errors to canonical S3 XML and preserve the request ID.
- Keep S3 handlers and console handlers on the same storage contracts.
- Count each rolled-up common prefix as one result before applying the listing
  limit. Resume after the entire prefix, including across peer listings.
- Internal requests whose method or bytes change must have corresponding
  authentication/checksum headers; copying the caller's digest is not valid.

## Known limits / next decision

- Conditional writes are initially limited to standalone PutObject; distributed,
  CopyObject, DELETE and multipart conditions are rejected with 501. Batch
  version-specific and conditional selectors are also rejected before deletion.
- Full AWS API compatibility is not claimed; see the README capability limits.
- MaxIO does not implement S3 Object Lock, retention periods or legal holds.
  Bucket versioning and a successful object read do not establish retention.

## Review

Use [Gauntlet](../../gauntlet.md). The dated record in `specs/reviews/` is
the evidence; this specification alone is not a pass. Report the single largest
remaining gap against the property above.
