<div align="center">

# MaxIO

S3-compatible object storage server — single-binary replacement for MinIO.

Rust · Axum · Svelte 5 · Tailwind CSS v4 · shadcn-svelte

</div>

## About the Project

> **Warning:** MaxIO is under active development. Do not use it in production yet.

MaxIO is a lightweight, single-binary S3-compatible object storage server written in Rust. No JVM, no database, no runtime dependencies — just one binary and a data directory. Buckets are directories, objects are files. Back up by copying the data dir.

## Features

- **Single Binary** — Frontend assets are compiled into the binary via `rust-embed`. Nothing extra to deploy
- **Pure Filesystem Storage** — No database. Buckets are directories, objects are files, metadata in `.meta.json` sidecars
- **AWS Signature V4** — Compatible with `mc`, AWS CLI, and any S3 SDK
- **Multi-Credential Auth** — Supports primary plus additional `access:secret` credential pairs for S3 and console login
- **Web Console** — Built-in UI at `/ui/` for browsing, uploading, and managing objects
- **S3 API Coverage** — ListBuckets, CreateBucket, HeadBucket, DeleteBucket, GetBucketLocation, ListObjectsV1/V2, PutObject, GetObject, HeadObject, DeleteObject, DeleteObjects (batch), CopyObject, Multipart Upload, Bucket Versioning APIs, Bucket Lifecycle APIs
- **Range Requests** — HTTP 206 Partial Content support via `Range` header on GetObject
- **Versioning** — Object version creation, list/get/delete by `versionId`, marker-aware `?versions` pagination, suspend-with-history-preservation semantics
- **Lifecycle Rules** — Bucket lifecycle rule set/get/delete plus background lifecycle sweep execution
- **Distributed Routing Foundation** — Placement-aware forwarding for non-owner reads/writes, replica fanout for primary writes (`PUT`/`CopyObject`/multipart complete/`DELETE`), quorum diagnostics headers, placement epoch/view wiring
- **Read-Repair Foundation** — Primary-owner `GET`/`HEAD` read-repair (current-version and `versionId`-targeted) with trusted replica probes and replica repair fanout
- **Runtime Observability** — Prometheus metrics at `/metrics` and probe-backed health/readiness status at `/healthz`
- **Checksum Verification** — CRC32, CRC32C, SHA-1, and SHA-256 checksums on upload with automatic validation and persistent storage
- **Erasure Coding** — Optional chunked storage with per-chunk SHA-256 integrity verification and Reed-Solomon parity for automatic recovery from corrupted or missing data

## Installation

### Build from Source

```bash
# Build frontend (required — assets are embedded into the binary)
cd ui && bun run build && cd ..

# Build binary
cargo build --release

# Run
./target/release/maxio --data-dir ./data --port 9000
```

### Docker

```bash
docker run -d \
  -p 9000:9000 \
  -v $(pwd)/data:/data \
  ghcr.io/coollabsio/maxio
```

Or from Docker Hub:

```bash
docker run -d \
  -p 9000:9000 \
  -v $(pwd)/data:/data \
  coollabsio/maxio
```

Configure with environment variables:

```bash
docker run -d \
  -p 9000:9000 \
  -v $(pwd)/data:/data \
  -e MAXIO_ACCESS_KEY=myadmin \
  -e MAXIO_SECRET_KEY=mysecret \
  ghcr.io/coollabsio/maxio
```

Docker Compose:

```yaml
services:
  maxio:
    image: ghcr.io/coollabsio/maxio
    ports:
      - "9000:9000"
    volumes:
      - maxio-data:/data
    environment:
      - MAXIO_ACCESS_KEY=minioadmin
      - MAXIO_SECRET_KEY=minioadmin
```

```bash
docker compose up -d
```

Open `http://localhost:9000/ui/` in your browser. Default credentials: `minioadmin` / `minioadmin`

## Configuration

| Variable | CLI Flag | Default | Description |
|---|---|---|---|
| `MAXIO_PORT` | `--port` | `9000` | Listen port |
| `MAXIO_ADDRESS` | `--address` | `0.0.0.0` | Bind address |
| `MAXIO_DATA_DIR` | `--data-dir` | `./data` | Storage directory |
| `MAXIO_ACCESS_KEY` | `--access-key` | `minioadmin` | Access key (aliases: `MINIO_ROOT_USER`, `MINIO_ACCESS_KEY`) |
| `MAXIO_SECRET_KEY` | `--secret-key` | `minioadmin` | Secret key (aliases: `MINIO_ROOT_PASSWORD`, `MINIO_SECRET_KEY`) |
| `MAXIO_ADDITIONAL_CREDENTIALS` | `--additional-credentials` | _empty_ | Comma-separated `access:secret` pairs for additional S3/console users |
| `MAXIO_REGION` | `--region` | `us-east-1` | S3 region (aliases: `MINIO_REGION_NAME`, `MINIO_REGION`) |
| `MAXIO_NODE_ID` | `--node-id` | `HOSTNAME` or `maxio-node` | Stable node identifier for distributed-mode bootstrap wiring |
| `MAXIO_CLUSTER_PEERS` | `--cluster-peers` | _empty_ | Comma-separated `host:port` peer list for distributed bootstrap wiring |
| `MAXIO_MEMBERSHIP_PROTOCOL` | `--membership-protocol` | `static-bootstrap` | Membership protocol mode (`static-bootstrap`, `gossip`, `raft`; gossip/raft are currently config placeholders) |
| `MAXIO_ERASURE_CODING` | `--erasure-coding` | `false` | Enable erasure coding with per-chunk integrity checksums |
| `MAXIO_CHUNK_SIZE` | `--chunk-size` | `10485760` (10MB) | Chunk size in bytes for erasure coding |
| `MAXIO_PARITY_SHARDS` | `--parity-shards` | `0` | Number of parity shards per object (requires `--erasure-coding`, 0 = no parity) |
| `MAXIO_MIN_DISK_HEADROOM_BYTES` | `--min-disk-headroom-bytes` | `268435456` (256MB) | Minimum required free bytes for `/healthz` readiness (`0` disables this gate) |

## Usage

### MinIO Client (mc)

```bash
mc alias set maxio http://localhost:9000 minioadmin minioadmin

mc mb maxio/my-bucket
mc cp file.txt maxio/my-bucket/file.txt
mc ls maxio/my-bucket/
mc cat maxio/my-bucket/file.txt
mc rm maxio/my-bucket/file.txt
mc rb maxio/my-bucket
```

### AWS CLI

```bash
export AWS_ACCESS_KEY_ID=minioadmin
export AWS_SECRET_ACCESS_KEY=minioadmin

aws --endpoint-url http://localhost:9000 s3 mb s3://my-bucket
aws --endpoint-url http://localhost:9000 s3 cp file.txt s3://my-bucket/file.txt
aws --endpoint-url http://localhost:9000 s3 ls s3://my-bucket/
aws --endpoint-url http://localhost:9000 s3 rm s3://my-bucket/file.txt
aws --endpoint-url http://localhost:9000 s3 rb s3://my-bucket
```

## Roadmap

- Done: multipart upload, presigned URLs, CopyObject, CORS, range headers, lifecycle rules, metrics baseline, erasure coding
- Done: versioning foundation (version lifecycle APIs/flows, versions pagination, version-aware range reads)
- In progress: distributed mode foundations (placement/epoch state, non-owner forwarding, primary replica fanout + quorum diagnostics, primary read-repair for current-version and `versionId`-targeted GET/HEAD)
- In progress: replication hardening, read-repair expansion, rebalance executor, dynamic membership engines (gossip/raft), multi-user policy/authorization layers

## Contributing

See [CLAUDE.md](CLAUDE.md) for the full development workflow, architecture details, and testing instructions.

### Domain Verification

Run domain-scoped checks with:

```bash
./scripts/domain_check.sh <domain>
```

Note: `quality_harness` also enforces `cargo clippy --all-targets -- -D warnings`.

Example:

```bash
./scripts/domain_check.sh s3_auth_sigv4
./scripts/domain_check.sh web_console_ui
./scripts/domain_check.sh quality_harness
```

Run all domain checks:

```bash
./scripts/domain_check.sh all
```

## Maintainer

| [<img src="https://github.com/Mvgnu.png" width="120" /><br />Magnus Ohle](https://github.com/Mvgnu) |
|---|

## License

[Apache-2.0](LICENSE)

See [NOTICE](NOTICE) for fork attribution and modification notice.
