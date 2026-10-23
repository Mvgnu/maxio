# MaxIO delivery priorities

The authoritative product and ownership contract is
[specs/00_system.md](specs/00_system.md). The previous append-only implementation
diary remains in Git history at `c9ffef2`; it is not a current capability claim.

## Current recovery wave

1. Keep standalone S3 easy to start and make rejected writes preserve data.
2. Demonstrate two actual peers, complete listings, honest outage behavior and
   persisted replicas after restart.
3. Deliver an optional direct folder-sync client with conflict preservation and
   explicit scope, using safe conditional writes.
4. Track domain specs, enforce write boundaries, and judge real artifacts with
   fresh critics against named external properties.

## Next decisions, in data-safety order

| Gap | Decision / evidence required |
|---|---|
| Filesystem key collisions and crash atomicity | A versioned storage-layout migration, recovery protocol and power-loss tests |
| Peer deployment security | Inbound TLS/pairing or a supported encrypted tunnel recipe with identity tests |
| Distributed conditional writes | Same-owner serialization and replicated preconditions through every forwarding path |
| Folder deletion/rename behavior | Tombstones, per-device acknowledgements, offline conflict rules and recovery UX |
| Large folder efficiency | Bounded-memory streaming, incremental scan/index, resumption and resource measurements |
| Multi-user access | Real permission model before describing extra credentials as isolated users |
| Cluster consensus and WAN operation | Explicit consistency model, adversarial partitions/restarts and repair evidence |
| Console usability | Largest gap from an independent mobile/desktop task review |

Do not attach percentages to these rows. Record completed evidence in a dated
Gauntlet review, update the applicable contract, and remove obsolete claims.
