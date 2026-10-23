---
{
  "name": "storage_engine",
  "description": "Persist complete objects and versions without corrupting earlier data",
  "paths": {
    "owned": [
      "src/storage/"
    ],
    "tests": [
      "tests/storage_safety.rs",
      "tests/integration/erasure_tests.rs",
      "tests/integration/parity_tests.rs"
    ],
    "exclude": [
      "src/storage/mod.rs"
    ]
  },
  "exports": [
    "FilesystemStorage",
    "ObjectMeta",
    "BucketMeta",
    "ObjectWriteCondition",
    "PutResult",
    "StorageError",
    "PlacementViewState"
  ],
  "consumes": [
    "Shared storage DTOs in src/storage/mod.rs"
  ],
  "verification": {
    "check": "cargo check --locked --all-targets",
    "test": "cargo test --locked --lib storage:: && cargo test --locked --test storage_safety",
    "build": "cargo build --locked --bins",
    "architecture": "python3 scripts/check_architecture.py"
  },
  "bar": {
    "reference": "Amazon S3 PutObject integrity contract",
    "url": "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html",
    "property": "A rejected or interrupted overwrite preserves the previously readable bytes and metadata; conditional writes cannot both win on one baseline."
  },
  "artifact": "Exercise filesystem storage through real S3 requests and inspect bytes after checksum failure and restart, for flat and erasure-coded objects."
}
---

# Persist complete objects and versions without corrupting earlier data

## Required behavior

- Validate object keys, upload/version identifiers and internal namespace boundaries before constructing paths.
- Stage and verify data before replacing a visible object. Publish a successful write only with complete bytes.
- Serialize current-object mutation and conditional comparison through one storage lock.
- Checksums are enforced in both flat and erasure-coded paths. Version targeting never escapes its key.
- Keep the current on-disk format; no silent migration or deleting unknown data.
- Enabling versioning preserves existing bytes as the null version before a later
  overwrite or delete marker. Null sorts older than generated version IDs.

## Known limits / next decision

- The path-based layout cannot represent every S3 flat-namespace key (a and a/b together). Reserved sidecar names and ambiguous path aliases are rejected.
- Data plus JSON sidecars are not a crash-atomic transaction; power-loss atomicity requires a format migration.
- The initial mutation lock is storage-wide; uploads trade throughput for correct conditional writes.
- Full suspended/null-version replacement parity remains outside this milestone.

## Review

Use [Gauntlet](../../gauntlet.md). The dated record in `specs/reviews/` is
the evidence; this specification alone is not a pass. Report the single largest
remaining gap against the property above.
