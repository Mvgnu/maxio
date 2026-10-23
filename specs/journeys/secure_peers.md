---
name: secure_peers
description: Native HTTPS and certificate-bound identity for two explicitly configured peers
---

# Secure peer connections

## Goal and bar

Reference: [TLS 1.3 peer authentication](https://www.rfc-editor.org/rfc/rfc8446).
Property: possession of the shared token and another node's name is insufficient
to act as that node. The connection carrying an internal operation must prove
possession of the key for its exact certificate identity, and the receiver must
bind that identity to the operation. Ordinary S3 clients can still use the public
HTTPS endpoint with server verification and S3 credentials.

This extends the [peer S3](peer_s3.md) journey. It does not add automatic pairing,
certificate issuance, NAT traversal, consensus or distributed conditional writes.

## Reproducible drill

```bash
python3 scripts/smoke_secure_peers.py --binary ./target/debug/maxio
```

The drill creates disposable credentials, a local CA, distinct certificates and
real HTTPS processes. Use `--keep-data` to retain its evidence. Its loopback scope
does not establish WAN availability or a complete internet deployment review.

## A local two-node certificate recipe

Run this once in a new directory with OpenSSL available. The example uses two
ports on one host so a host-only identity check would be insufficient. On separate
devices replace each URI's address and its IP/DNS SAN with the actual reachable
endpoint. For IPv6, use `URI:maxio://[::1]:9101` and `IP:::1`.

```bash
umask 077
mkdir tls
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 365 \
  -keyout tls/ca.key -out tls/ca.crt -subj '/CN=MaxIO private CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'

for item in a:9101 b:9102; do
  name=${item%:*}
  port=${item#*:}
  openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -keyout "tls/$name.key" -out "tls/$name.csr" -subj "/CN=MaxIO $name"
  cat > "tls/$name.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=IP:127.0.0.1,URI:maxio://127.0.0.1:$port
EOF
  openssl x509 -req -in "tls/$name.csr" -CA tls/ca.crt -CAkey tls/ca.key \
    -CAcreateserial -out "tls/$name.crt" -days 30 -sha256 -extfile "tls/$name.ext"
done
```

The CA key signs identities; keep it off the running peers. Each peer receives
only its own private key and certificate chain, plus the CA certificate. A leaf
certificate needs exactly one canonical MaxIO URI SAN including its port, and
normal DNS/IP SANs for hostname verification. Reusing one leaf across nodes defeats
per-node key separation. Local fingerprint pins are optional additional restrictions.

## Start the peers

In both terminals set the same operator credentials, peer token and cluster ID:

```bash
export MAXIO_ACCESS_KEY=peer-admin
export MAXIO_SECRET_KEY='replace-with-a-long-shared-secret'
export MAXIO_CLUSTER_AUTH_TOKEN='replace-with-another-long-shared-secret'
export MAXIO_CLUSTER_ID=secure-pair
```

First terminal:

```bash
./target/debug/maxio --address 127.0.0.1 --port 9101 \
  --node-id 127.0.0.1:9101 --cluster-peers 127.0.0.1:9102 \
  --data-dir ./secure-a --metadata-listing-strategy request-time-aggregation \
  --write-durability-mode strict-quorum --cluster-peer-transport-mode required \
  --cluster-peer-tls-cert-path ./tls/a.crt \
  --cluster-peer-tls-key-path ./tls/a.key --cluster-peer-tls-ca-path ./tls/ca.crt
```

Second terminal:

```bash
./target/debug/maxio --address 127.0.0.1 --port 9102 \
  --node-id 127.0.0.1:9102 --cluster-peers 127.0.0.1:9101 \
  --data-dir ./secure-b --metadata-listing-strategy request-time-aggregation \
  --write-durability-mode strict-quorum --cluster-peer-transport-mode required \
  --cluster-peer-tls-cert-path ./tls/b.crt \
  --cluster-peer-tls-key-path ./tls/b.key --cluster-peer-tls-ca-path ./tls/ca.crt
```

Both public node endpoints now speak HTTPS. The listener requests optional client
certificates; ordinary S3 clients and the console do not need one. Internal routes
and forwarding headers require a verified, allowed, nonlocal certificate identity,
plus existing token and request authorization. The sender's last forwarding hop
and join claims must match its actual connection identity.

Use this combined listener for the documented cluster workflow. A separate
`--internal-bind-addr` isolates control routes and requires a client certificate,
but configured node IDs still identify public endpoints. There is no separate
per-peer control-endpoint map for automatic membership propagation.

## Use an ordinary S3 client

```bash
curl --cacert ./tls/ca.crt 'https://127.0.0.1:9101/healthz?scope=local'
export AWS_CA_BUNDLE="$PWD/tls/ca.crt"
export AWS_ACCESS_KEY_ID="$MAXIO_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$MAXIO_SECRET_KEY"
export AWS_DEFAULT_REGION=us-east-1
aws --endpoint-url https://127.0.0.1:9101 s3 mb s3://files
aws --endpoint-url https://127.0.0.1:9101 s3 cp ./example.txt s3://files/example.txt
aws --endpoint-url https://127.0.0.1:9102 s3 cp s3://files/example.txt ./received.txt
```

For the console, trust the private CA in the browser's trust store before opening
`https://127.0.0.1:9101/ui/`. A certificate warning is a configuration failure to
resolve, not a normal onboarding step. Native HTTPS session cookies are Secure.

## Certificate rotation and revocation

Issue a replacement with the same exact node URI, correct DNS/IP SANs and both
client/server authentication usages. Replace the files and restart the node;
certificate configuration is loaded for connections at startup and client creation,
not a coordinated online rotation service.

To deny a compromised leaf, calculate its SHA-256 fingerprint with
`openssl x509 -in tls/a.crt -noout -fingerprint -sha256`. Configure its hex value
in `MAXIO_CLUSTER_PEER_TLS_CERT_SHA256_REVOCATIONS` on every remaining node and
restart them. Comma-separated values revoke multiple leaves. This is a local
operator-managed denylist, not distributed CRL/OCSP or automatic key recovery.
Do not distribute the CA signing key to compensate for an unavailable peer.

## Acceptance

- Both peers complete ordinary signed S3 operations over verified HTTPS. A strict
  write has the expected acknowledgements and remains readable after restart.
- A caller with the correct shared token but no client certificate cannot perform
  internal operations. A client certificate from another CA also fails.
- A certificate for a different port on the same host cannot claim the target
  node or another sender. A valid configured peer cannot claim a different last hop.
- Revoked leaves, malformed/multiple MaxIO URI identities, hostname mismatches and
  expired certificates fail before the request gains trusted internal privileges.
- The outbound identity check applies to the connection carrying the payload;
  changing the server identity between connections cannot exploit a preflight gap.
- Internal traffic follows no redirect and consults no environment proxy. Ordinary
  HTTP bytes cannot be sent successfully to the native TLS listener.
- Invalid or partial TLS startup configuration fails before creating storage state.
  Slow handshakes are bounded, and both listeners terminate on shutdown.

## Limits

Shared S3 credentials still have equal administrative privileges. This milestone
does not provide per-device bucket grants. Two-node quorum cannot remain available
with one node down. Certificate-bound transport does not change the experimental
membership or storage crash-consistency guarantees. Review records must separate
the identity verdict from those independent durability and authorization limits.
