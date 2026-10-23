---
{
  "name": "cluster_metadata_plane",
  "description": "List and reconcile cluster metadata without claiming partial data is complete",
  "paths": {
    "owned": [
      "src/metadata/"
    ],
    "tests": [],
    "exclude": [
      "src/metadata/mod.rs"
    ]
  },
  "exports": [
    "MetadataIndex",
    "MetadataQuery",
    "ClusterMetadataCoverage",
    "PersistedMetadataState",
    "reconciliation plans and queues"
  ],
  "consumes": [
    "Canonical metadata state and typed topology snapshots"
  ],
  "verification": {
    "check": "cargo check --locked --all-targets",
    "test": "cargo test --locked --lib metadata::",
    "build": "cargo build --locked --bins",
    "architecture": "python3 scripts/check_architecture.py"
  },
  "bar": {
    "reference": "Amazon S3 ListObjectsV2",
    "url": "https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html",
    "property": "A complete listing contains all acknowledged keys across pages; unavailable peer coverage is exposed instead of silently returning an incomplete success."
  },
  "artifact": "Run signed list requests through both real peers, paginate, stop a peer, and inspect coverage/unavailable responses."
}
---

# List and reconcile cluster metadata without claiming partial data is complete

## Required behavior

- Do not maintain parallel key/version types in API handlers.
- Bind continuation state to a defined membership/snapshot view; reject invalid or stale tokens.
- Validate responder identities and completeness before claiming authoritative coverage.
- Persist reconciliation retries and classify terminal errors without hiding them.

## Known limits / next decision

- PM stops broader consensus reconciliation work in this wave. The persisted
  consensus projection does not automatically acquire lazily retained null
  versions; inherited merging also prefers a live current record over a delete
  marker before comparing ranks. These are unresolved authority/projection gaps.
  The admitted peer journey uses request-time aggregation and explicit quorum.

- consensus-index is a persisted metadata projection, not a Raft consensus implementation.
- Cluster-wide snapshot isolation and WAN partition convergence remain unproven.

## Review

Use [Gauntlet](../../gauntlet.md). The dated record in `specs/reviews/` is
the evidence; this specification alone is not a pass. Report the single largest
remaining gap against the property above.
