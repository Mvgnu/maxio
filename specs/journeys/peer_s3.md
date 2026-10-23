---
name: peer_s3
description: Two explicitly configured devices expose replicated S3 objects
---

# Peer S3

## Goal and bar

Reference: [Garage cluster deployment](https://garagehq.deuxfleurs.fr/documentation/cookbook/real-world/).
Property: documented settings produce usable peers; acknowledged replicas can be
read independently after restart, and lost quorum does not look like complete success.

This is experimental replicated S3 across configured peers. It is not a discovery,
pairing, NAT traversal or ordinary-directory synchronization product.

## Reproducible local drill

```bash
python3 scripts/smoke_peer_s3.py --binary ./target/debug/maxio
```

The script owns temporary directories and two loopback processes, uses random
temporary credentials/token, sends real signed S3 requests and prints the observed
result. `--keep-data` retains its data and logs for an independent critic.

## Manual two-peer configuration

Use the same credentials, cluster token and cluster ID in both terminals:

```bash
export MAXIO_ACCESS_KEY=peer-admin
export MAXIO_SECRET_KEY='replace-with-a-long-shared-secret'
export MAXIO_CLUSTER_AUTH_TOKEN='replace-with-another-long-shared-secret'
export MAXIO_CLUSTER_ID=local-pair
```

First terminal:

```bash
./target/debug/maxio --address 127.0.0.1 --port 9101 \
  --node-id 127.0.0.1:9101 --cluster-peers 127.0.0.1:9102 \
  --data-dir ./peer-a --metadata-listing-strategy request-time-aggregation \
  --write-durability-mode strict-quorum
```

Second terminal:

```bash
./target/debug/maxio --address 127.0.0.1 --port 9102 \
  --node-id 127.0.0.1:9102 --cluster-peers 127.0.0.1:9101 \
  --data-dir ./peer-b --metadata-listing-strategy request-time-aggregation \
  --write-durability-mode strict-quorum
```

An ordinary S3 client uses either `http://127.0.0.1:9101` or `:9102`. On separate
devices replace addresses with mutually reachable private/VPN addresses and bind
the selected interface. Each node ID is its reachable endpoint, not a display name.
Do not expose these plain HTTP listeners to the public internet.

## Acceptance

- Both health requests return promptly; peer observation cannot recursively call
  another cluster-wide health check. `scope=local` makes only a local observation.
- Both endpoints list and read identical bytes, exercising both placement owners.
- Successful strict-quorum writes expose both replica acknowledgements.
- Stop one peer: complete listing and quorum writes return an explicit unavailable
  result. An unavailable write may already have reached the primary; failure is
  not a promise that no side effect happened.
- Restart the peer: listing recovers. Stop both, boot each stored copy independently
  and read every acknowledged object. This proves replication rather than forwarding.
- Invalid/forged peer identities fail; equivalent valid DNS/IPv6 forms normalize.

## Limits and migration

The drill proves a static two-node loopback configuration. It does not prove WAN
partition recovery or availability during a two-node outage. Default peer settings
remain `local-node-only` listing and `degraded-success` writes unless explicitly
changed; use the settings above for this journey.

Native inbound TLS is absent. Outbound certificate flags alone cannot secure a
MaxIO-to-MaxIO connection. A properly configured TLS terminator or encrypted private
transport and an identity deployment review are separate requirements.

Canonicalizing legacy mixed-case/IPv6 node identifiers changes placement fingerprints.
Plan a coordinated migration/rebalance for an existing noncanonical cluster. Do
not perform an unexamined rolling upgrade. Raft remains unimplemented; the persisted
`consensus-index` mode does not create consensus. Distributed conditional writes
remain unsupported; the initial folder-sync client uses a standalone peer endpoint.
