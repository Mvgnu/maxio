---
{
  "name": "workspace_catalog",
  "description": "Versioned selective workspace publication through explicit S3 storage",
  "paths": {
    "owned": [
      "src/workspace/remote.rs",
      "src/workspace/remote/"
    ],
    "tests": [
      "tests/workspace_remote.rs"
    ],
    "exclude": []
  },
  "exports": [
    "workspace::WorkspaceRemote",
    "immutable manifest and file versions",
    "transfer counters"
  ],
  "consumes": [
    "workspace::contract",
    "files portable path checks",
    "object_store S3 HTTP"
  ],
  "verification": {
    "check": "cargo check --locked --all-targets",
    "test": "cargo test --locked --lib workspace::remote:: && cargo test --locked --test workspace_remote",
    "build": "cargo build --locked --bins",
    "architecture": "python3 scripts/check_architecture.py"
  },
  "bar": {
    "reference": "Rclone copy and integrity checking",
    "url": "https://rclone.org/commands/rclone_copy/",
    "property": "An operator can publish selected files and read an exact historical revision; a competing stale publication fails while both local edits and the winning published bytes remain recoverable."
  },
  "artifact": "Real MaxIO S3 process with streaming multipart transfers, competing clients, restart, metadata-only discovery, and deliberately interrupted operations."
}
---

# Versioned selective workspace publication through explicit S3 storage

## Required behavior

The PM-owned Rust contract is `src/workspace/contract.rs`; public method signatures
are seeded in `src/workspace/remote.rs`. Preserve them or request a PM ruling.

- Use `object_store = 0.12.5` with explicit endpoint, bucket, credentials and region.
  No environment/IAM discovery, redirect, proxy or TLS-validation bypass. HTTP
  requires `allow_http`; a private CA replaces system trust. Keep secrets out of
  Debug, serialization, operation records and subprocess environments.
- `target_id()` is a canonical endpoint/bucket/name binding without credentials.
  Workspace names use a short portable ASCII identifier. Store protocol objects
  under `maxio-workspaces/<name>/`; callers never supply arbitrary backend keys.
- Format 1 has a stable workspace UUID, immutable uniquely named blob objects,
  immutable manifest revisions and a small CAS-updated head. Every revision has
  a fresh UUID and a SHA-256 manifest identity. Keep parent references. Never
  overwrite a blob/manifest key or delete published history in this milestone.
- Blob keys use a fresh UUID, not a shared digest key: generic multipart completion
  has no create-only condition. A file version records SHA-256 and length separately.
- Before user publication, probe create-only, stale/matching update and one-winner
  concurrent CAS behavior on disposable keys. Failed/unsupported conditions fail
  closed; never retry unconditionally. No claim of distributed atomicity follows
  from a probe. Initial supported coordinator target is ordinary standalone S3.
- A complete validated head/manifest is the publication authority. Validate format,
  UUIDs, hashes, blob scope, path collisions, at most 20,000 files and 8 MiB metadata.
  Directory discovery fetches metadata only. Never infer deletion from listing,
  absence, outage or a missing local path. No global delete operation exists yet.
- `initialize` creates an empty workspace once and refuses an existing head.
  `latest` returns a current publication base; `revision` follows validated history
  from the current head to an exact revision and returns no writable head token.
  Traversal is limited to 256 revisions and 64 MiB of cumulative manifest metadata.
  Older history is retained; resolution beyond either limit is explicitly refused.
- `publish(base, files)` uploads only staged explicit files, reads completed blobs
  back to verify size/SHA-256, writes a new immutable manifest, then CASes the head.
  Reject missing/stale base token. Reconcile a lost head acknowledgment by unique
  revision identity when possible; otherwise report unknown outcome and retain work.
  Never falsely mark local work committed. CAS is not a lease or revocation fence.
  If the attempted revision is committed but a later writer has advanced the head,
  report that known outcome and require refresh/recovery before recording local
  publication. Do not attach a newer head token to the attempted older manifest.
- `download` streams to a new staging file, checks exact published size/SHA-256 and
  fsyncs before success. Reject overlong/truncated/corrupt bodies. No whole-file Vec.
  Multipart upload uses 8 MiB parts with explicit bounded backpressure (two in flight).
  Abort recoverable failed uploads; crashed multipart operations/orphans are retained
  for operator recovery, never swept automatically.
  The current per-file upload limit is 10,000 parts (83,886,080,000 bytes).
  Failed downloads also drain and fsync pending writes; a partial stage stays marked
  unverified and is never substituted for an existing working file.
- Counters report actual application bytes read/written, separately for metadata,
  publication payload and verification/download payload. They exclude HTTP framing
  and SDK retries; do not describe them as wire-level billing measurements.
  Upload counters count bytes handed to the SDK, including attempted parts that may
  fail; download counters count received bytes, including failed partial transfers.
  A separate transport observer is needed to measure HTTP retries or billable traffic.

## Limits and the next decision

This is a client-side protocol for trusted operators. Existing S3 credentials are
admin-equivalent. It does not enforce device grants, leases, fencing, retention,
provider-native Object Lock, replica placement, failover or automatic deletion.
A verified remote read is present recoverability, not proof of crash-safe durability.
Safe cache eviction stays unavailable until a retention/durability contract is enforced.

External providers are adapter-compatible candidates until tested. Verify against a
real endpoint before naming AWS/R2/B2 operation as demonstrated.

## Review

Run an independent critic on the built CLI and real S3 process, following
`specs/journeys/selective_workspace.md`. Record one largest gap and actual evidence.
