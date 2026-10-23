---
name: standalone_s3
description: One straightforward S3 server with persistent bytes and an offline console
---

# One S3 server

## Goal and bar

Reference: [Garage quick start](https://garagehq.deuxfleurs.fr/documentation/quick-start/).
Property: after building, an operator can start one process with a data directory
and credentials, then use an ordinary S3 client without choosing cluster settings.
For data behavior, compare [S3 PutObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html):
rejected writes preserve the previous object and acknowledged bytes survive restart.

## Run

Build with the README commands. In one terminal:

```bash
export MAXIO_ACCESS_KEY=local-admin
export MAXIO_SECRET_KEY='replace-with-a-long-local-secret'
./target/debug/maxio --address 127.0.0.1 --data-dir ./data --port 9000
```

Then use `mc` or AWS CLI as shown in the README, or run the isolated acceptance
drill (which creates its own process and temporary data):

```bash
python3 scripts/smoke_standalone.py --binary ./target/debug/maxio
```

The console is `http://127.0.0.1:9000/ui/`. No external fonts or runtime CDN assets
are needed. Defaults remain a server, not a setup wizard for distributed storage.

## Acceptance

1. Start without peers; health identifies standalone mode.
2. Create a bucket, upload nested-key bytes, list and download identical bytes.
3. A wrong-secret client is denied. An unauthenticated management request is denied.
4. Reject a checksum-invalid overwrite without changing prior bytes or ETag.
5. An `If-None-Match:*` overwrite returns 412; two writes with the same If-Match
   baseline cannot both succeed.
6. Stop and restart with the same data directory; the object is still readable.
7. A fresh UI critic performs create/upload/download at 390x844 and 1440x900 and
   verifies no third-party requests. Script success alone does not satisfy this step.

## Honest limits

One process per data directory. Path-style S3 subset; reserved internal filenames
and ambiguous paths are rejected. Data/metadata replacement is not a full power-loss
transaction. IAM policies, virtual-hosted buckets and full AWS feature parity are
not promised. The recovery review must state any remaining gap rather than turning
the acceptance list into an unearned pass.
