---
name: device_sync
description: Direct additive folder synchronization through a chosen peer device
---

# Device files without a mandatory cloud service

## Goal and bar

Reference: [Syncthing synchronization](https://docs.syncthing.net/users/syncing.html).
Property: differing concurrent edits and interrupted transfers preserve both sets
of bytes, and a restart resumes direct synchronization from a durable baseline.
This compares conflict safety, not Syncthing's complete feature set.

## Topology

One device runs standalone `maxio` with a bucket. Each participating device runs
`maxio-sync` against that explicit endpoint and its own ordinary directory. The
object endpoint may be one of the participating devices. No hosted service,
account, relay, discovery provider or intermediary cloud is required. The selected
peer must be reachable while transferring. This initial topology is not a mesh.

Do not use the MaxIO server's data directory as a sync directory. Do not point the
client at a distributed endpoint yet; that mode rejects conditional writes.

## Run

Build both binaries using the README. Start a standalone server and create a
bucket with `mc mb maxio/device-files` or the console. On each device:

```bash
export MAXIO_ACCESS_KEY=local-admin
export MAXIO_SECRET_KEY='the-secret-of-your-chosen-peer'
./target/debug/maxio-sync --local ./shared-files \
  --endpoint http://127.0.0.1:9000 --bucket device-files --prefix shared --once
```

Replace loopback with the chosen device's private/VPN address or a verified HTTPS
endpoint. Omit `--once` to poll; default interval is 15 seconds. Ctrl+C stops the
client. There is no OS service installation or automatic peer discovery.

## Reconciliation contract

| Observed state | Action |
|---|---|
| New file on one side | Create the absent copy conditionally |
| Only local content changed since baseline | Conditional upload against the observed remote ETag |
| Only remote content changed | Stage download, retain old local content, atomically replace |
| Both changed to different contents | Preserve a `.maxio-conflict-<digest>` sibling, converge main to remote |
| First contact has differing files | Preserve both as a conflict, never guess by timestamp |
| A copy is absent | Restore it from the surviving side; deletions do not propagate |
| Peer unavailable, incomplete listing, failed precondition | Stop the attempt without treating missing data as deletion; retry safely |
| Endpoint ignores conditional writes | Refuse user-file uploads after a disposable capability probe |

The local `.maxio-sync/` directory contains a target-scoped journal, process lock,
staging and retained replacement history. It is not uploaded. Credentials are not
stored there. History is not pruned automatically. A root is owned by one running
sync process; unsafe paths, symlinks and case/file-directory aliases are rejected.

## Acceptance

```bash
python3 scripts/smoke_device_sync.py --binary ./target/debug/maxio \
  --sync-binary ./target/debug/maxio-sync
```

A critic must inspect actual folders after initial transfer, updates, restart,
simultaneous differing edits, an offline peer and recovery. Both conflict contents
must remain accessible. Also test an endpoint that ignores conditions; no user file
may be uploaded to it. `cargo test --test device_sync` supplies focused regressions,
but the executable drill establishes CLI wiring.

## Deliberate limits

No delete propagation: stop clients and remove all copies to intentionally delete.
No automatic pairing, NAT traversal, watcher, block/delta transfer, filesystem
permission/metadata sync, or arbitrary application/database-state replication.
Regular files are transferred whole, with a configurable `--max-file-mib` bound
(64 MiB by default). An initial failure on a reserved server key is explicit; the
client does not silently skip incompatible filenames. Local roots are trusted:
hostile concurrent filesystem namespace replacement is outside this boundary.
