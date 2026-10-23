# MaxIO

**S3 storage, selective workspaces and optional local agent execution on your own infrastructure.**

MaxIO is a Rust S3 server with an embedded Svelte console. Start with one process
and a data directory. Add explicit storage peers or the optional folder-sync
client when you need them. The optional workspace and agent tools are separate
executables; none is required to start the S3 server.

| I want… | Start here | Status |
|---|---|---|
| One straightforward S3 service | [Standalone](#one-s3-server) | Default mode; ordinary S3 clients and built-in console |
| S3 data on multiple devices | [Peer S3](specs/journeys/peer_s3.md) | Experimental static peers; tested replication and honest outage behavior |
| My folders on my devices, without a cloud intermediary | [Device sync](#direct-device-folder-sync) | Additive sync through a chosen peer; preserves conflicts; no deletion propagation |
| See files without copying everything | [Selective workspace](#selective-workspace) | Experimental versioned catalog and selected transfers; no eviction yet |
| Run a command, Codex or Claude on selected files | [Local agents](#local-agents) | Optional supervised local runner; remote locality scheduling remains planned |

This is an actively developed fork. Its supported behavior and limits are recorded
in [the system contract](specs/00_system.md), with independent evidence in
[dated reviews](specs/reviews/). It does not claim full AWS compatibility or
production-grade distributed durability.

## Build

Use Rust **1.94.0**, Bun **1.3.10**, and Python 3 for verification. On Debian/Ubuntu,
install `build-essential`, `pkg-config`, `libssl-dev` and `openssl`. Rustup reads the pinned
`rust-toolchain.toml`. The Linux executables use the system OpenSSL libraries.

```bash
cd ui
bun install --frozen-lockfile
bun run build
cd ..
cargo build --locked --bins
```

This creates `target/debug/maxio`, `maxio-sync`, `maxio-workspace` and `maxio-agent`. For optimized,
self-contained console assets, use `cargo build --locked --release --bins` and the
executables under `target/release/`. Release executables embed the console; no Node
or Bun runtime is needed. Debug builds read `ui/dist/` from the checkout.

## One S3 server

```bash
export MAXIO_ACCESS_KEY=local-admin
export MAXIO_SECRET_KEY='replace-with-a-long-local-secret'
./target/debug/maxio --address 127.0.0.1 --data-dir ./data --port 9000
```

Open [the console](http://127.0.0.1:9000/ui/) and sign in with those credentials.
The console uses local assets and system fonts. No cluster settings are required.
For other devices, bind the chosen private interface and use native HTTPS as shown
below, or an operator-controlled encrypted channel.

### Optional native HTTPS

Provide a PEM certificate chain and matching private key for the address your
clients use. No peer configuration is required:

```bash
./target/debug/maxio --address 127.0.0.1 --data-dir ./data --port 9000 \
  --tls-cert-path ./tls/server.crt --tls-key-path ./tls/server.key
```

Use `https://` endpoints. With a private CA, set `AWS_CA_BUNDLE` for AWS CLI and
trust that CA in your browser for the console. A partial or invalid certificate/key
pair fails startup. The ordinary no-flags standalone command still uses HTTP.

### With MinIO Client

```bash
mc alias set maxio http://127.0.0.1:9000 "$MAXIO_ACCESS_KEY" "$MAXIO_SECRET_KEY"
mc mb maxio/files
mc cp ./example.txt maxio/files/example.txt
mc cat maxio/files/example.txt
```

### With AWS CLI

```bash
export AWS_ACCESS_KEY_ID="$MAXIO_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$MAXIO_SECRET_KEY"
export AWS_DEFAULT_REGION=us-east-1
aws --endpoint-url http://127.0.0.1:9000 s3 mb s3://files
aws --endpoint-url http://127.0.0.1:9000 s3 cp ./example.txt s3://files/example.txt
aws --endpoint-url http://127.0.0.1:9000 s3 ls s3://files/
```

S3 credentials default to `minioadmin` / `minioadmin` when omitted. The default
address is `0.0.0.0`; the example explicitly chooses loopback. Additional
credentials currently have the same administrative capabilities, not separate IAM
permissions. One server process must own each data directory.

## Direct device folder sync

Run standalone MaxIO on one chosen device, create a bucket such as `device-files`,
and run the optional client on each device with its own ordinary folder:

```bash
./target/debug/maxio-sync --local ./shared-files \
  --endpoint http://127.0.0.1:9000 --bucket device-files --prefix shared --once
```

The client reads `MAXIO_ACCESS_KEY` and `MAXIO_SECRET_KEY`. Replace loopback with the
chosen device's reachable private/VPN address or verified HTTPS endpoint. Omit
`--once` to poll every 15 seconds; Ctrl+C stops it. There is no hosted account,
mandatory discovery service, relay or cloud storage between the devices.

For a native HTTPS server signed by your private CA:

```bash
./target/debug/maxio-sync --local ./shared-files \
  --endpoint https://your-device.lan:9000 --ca-cert ./tls/ca.crt \
  --bucket device-files --prefix shared --once
```

`MAXIO_SYNC_CA_CERT` is the environment equivalent. The supplied PEM bundle becomes
the explicit trust roots for that client; hostname and certificate checks stay on.
Without it, the client uses normal system roots. The option is rejected for HTTP.

A persistent local baseline detects which side changed. Downloads are staged;
concurrent differing edits preserve a `.maxio-conflict-<digest>` sibling. The client
first verifies that the endpoint actually honors conditional writes and refuses
unsafe endpoints. The current distributed server mode does not support those
conditions, so this client uses a **standalone peer bucket**.

This first version is **additive**: removing one copy restores it from the surviving
side. To intentionally delete a file, stop the clients and remove all copies. It
transfers regular files whole, with a configurable `--max-file-mib` limit of 64 MiB
by default. Replacement history and the journal stay in local `.maxio-sync/` and
are not automatically pruned. Do not select a server data directory as a sync folder.

There is no automatic device pairing, NAT traversal, mesh discovery, filesystem
watcher, deletion propagation or permission/symlink synchronization in this version.
See the [complete device-sync contract](specs/journeys/device_sync.md).

## Selective workspace

Use this when a project should be discoverable everywhere while file contents are
present only where requested. It is a separate, experimental client protocol over
ordinary S3. It does not change server startup or the additive `maxio-sync` behavior.

Start the standalone server above, create a bucket named `workspaces` using AWS CLI
or `mc`, and keep `MAXIO_ACCESS_KEY` / `MAXIO_SECRET_KEY` set for that target. Do not
point a workspace at the server's data directory. A local example:

```bash
mkdir -p demo-mini/src demo-mini/datasets demo-book
printf 'initial project note\n' > demo-mini/src/note.txt
printf 'a dataset only the Mini initially needs\n' > demo-mini/datasets/example.txt

ws() {
  ./target/debug/maxio-workspace \
    --endpoint http://127.0.0.1:9000 --allow-http \
    --bucket workspaces --workspace personal "$@"
}

ws --root ./demo-mini init
ws --root ./demo-mini publish src datasets
ws --root ./demo-book refresh             # metadata only, no dataset contents
ws --root ./demo-book pull src            # datasets/ remains absent
./target/debug/maxio-workspace --root ./demo-book list
./target/debug/maxio-workspace --root ./demo-book status
./target/debug/maxio-workspace --root ./demo-book pin src

printf 'edited on the MacBook\n' > demo-book/src/note.txt
ws --root ./demo-book publish src/note.txt
ws --root ./demo-mini pull src/note.txt
```

Every response is JSON with the observed revision and transfer counters. `list`
uses the cached catalog; `refresh` fetches current metadata. `status` verifies local
hashes. `list`, `status`, `pin` and `unpin` work offline without storage credentials.
A pin covers the currently hydrated selected files, not future directory members.

Use HTTPS for cross-device traffic. `--ca-cert /path/to/ca.pem` selects only those
roots while retaining normal hostname validation; `--allow-http` is explicit for a
trusted local or encrypted network. Set `MAXIO_SESSION_TOKEN` when an explicitly
configured S3 credential needs a session token. There is no implicit host IAM lookup.
External S3 providers use this same adapter, but provider interoperability must be
verified per endpoint; this wave's process evidence uses MaxIO.

### Versions, conflicts and local recovery

Published references look like:

```text
maxio-workspace://<workspace-uuid>/src/note.txt?revision=<revision-uuid>
```

These are logical identities, not HTTPS download links or permission grants. To
hydrate an earlier committed version, use `pull src/note.txt --revision <uuid>`.
The observed current catalog stays current; status reports an unchanged older copy
as `stale`. Pull the current version again before publishing against it.

`publish` uses the last observed head and each selected file's working baseline.
Another publication can make that head stale; the command then fails without losing
local edits. `refresh` alone cannot turn conflicting edits into a valid overwrite.
Inspect/reconcile the preserved changes and pull a clean current version before
publishing again. MaxIO does not merge source code; use Git branches/worktrees for
concurrent coding and Git to resolve source history.

Local state, staged publication copies, receipts and replaced-file history live under
`.maxio-workspace`. Failed or interrupted transfers remain recoverable there. The
root must be operator-owned; these checks are not protection against a hostile
process replacing directory ancestors while an operation runs. No global delete
operation exists, and unavailability is never treated as deletion evidence.

**Eviction is deliberately unavailable in this slice.** A matching remote read proves
current recoverability, not enforced retention or crash-safe durability. `evict`
returns an error and leaves local files intact. History/stages are not automatically
pruned. This is M1a, with safe disk reclamation still open in
[the roadmap](01_product_roadmap.md). It is not yet the complete distributed fabric.

Reproduce the real selective-transfer and failure journey:

```bash
python3 scripts/smoke_workspace.py \
  --binary ./target/debug/maxio \
  --workspace-binary ./target/debug/maxio-workspace --keep-data
```

It uses three isolated local roots, an actual 128 MiB dataset, byte-counting transport,
conditional publication races, truncated downloads, failed uploads, a lost publication
response and server restart. It is a one-host test, not a physical three-device/WAN
claim. Client counters separate payload and metadata bytes and exclude HTTP framing
and SDK retries; the fixture additionally counts bytes forwarded through its proxy.

## Local agents

`maxio-agent` is an independent local runner for an owner-selected executable,
Codex CLI or Claude Code. It prepares a fresh run workspace from explicit inputs,
records input/output hashes, streams logs, enforces a deadline and retains failed or
cancelled work. It never automatically publishes outputs or deletes a run directory.

### Run an ordinary command

This example reads only the selected `src` directory in a fresh working copy. Use
the absolute path of your Python executable if it is installed elsewhere:

```bash
mkdir -p agent-example/src
printf 'a selected input\n' > agent-example/src/note.txt

./target/debug/maxio-agent run \
  --adapter command --executable /usr/bin/python3 \
  --source ./agent-example --input src --output result.txt \
  --records ./agent-runs --timeout-seconds 60 \
  -- -c 'from pathlib import Path; Path("result.txt").write_text(Path("src/note.txt").read_text().upper())'
```

The JSON result names the run UUID, retained workspace and log paths, input/output
hashes, status and exit code. `output_files` are candidates for review; `published`
stays false. Review the result, then explicitly copy accepted outputs into a tracked
workspace and publish selected files with `maxio-workspace`. The source tree is not
changed automatically. Records must be outside the source tree.

```bash
./target/debug/maxio-agent inspect --run ./agent-runs/<run-uuid>
./target/debug/maxio-agent cancel --run ./agent-runs/<active-run-uuid>
```

`cancel` confirms that a cancellation request was recorded. Inspect the run again
for the live runner's terminal `cancelled` state; a request is not proof that an
abandoned worker has stopped. Failed, cancelled and timed-out runs keep their edits
and logs. Nothing kills a process based on a saved PID.

### Codex CLI and Claude Code

Install and authenticate the CLI you choose using its own instructions. MaxIO does
not install a provider, perform login or make a model request during `doctor`. Use
an absolute executable path and an explicitly chosen owner-managed credential
directory outside the source tree:

```bash
./target/debug/maxio-agent doctor --adapter codex --executable /absolute/path/to/codex
./target/debug/maxio-agent doctor --adapter claude --executable /absolute/path/to/claude

printf 'Read src/note.txt and write a concise summary to result.md.\n' > task.txt

./target/debug/maxio-agent run \
  --adapter codex --executable /absolute/path/to/codex \
  --provider-home /absolute/path/to/owner-managed-codex-home \
  --source ./agent-example --input src --output result.md \
  --records ./codex-runs --prompt-file ./task.txt \
  --permission workspace-write --timeout-seconds 900

./target/debug/maxio-agent run \
  --adapter claude --executable /absolute/path/to/claude \
  --provider-home /absolute/path/to/owner-managed-claude-config \
  --source ./agent-example --input src --output result.md \
  --records ./claude-runs --prompt-file ./task.txt \
  --permission workspace-write --timeout-seconds 900
```

`--provider-home` selects `CODEX_HOME` or `CLAUDE_CONFIG_DIR`; MaxIO references that
directory rather than copying credentials into task inputs. Instead, API users can
select an already-set credential with `--env CODEX_API_KEY` or
`--env ANTHROPIC_API_KEY`. Do not put secret values in arguments. Provider adapters
reject arbitrary extra flags and inherited provider overrides.

Providers default to `read-only`; the examples explicitly permit workspace edits.
Codex keeps its native sandbox and unattended approval policy. Claude requires
restricted-mode and unattended-permission capabilities (at least version 2.1.259)
and currently exposes **file read/edit tools only, without Bash or MCP**. A full
sandboxed Claude command-execution profile remains open.

The baseline child environment supplies `/usr/local/bin:/usr/bin:/bin`. If an npm
wrapper needs Node elsewhere, select the native provider executable or explicitly
pass `--env PATH` to `run` for that trusted runtime path. `doctor` uses the baseline
path; it does not inherit your shell's runtime configuration. Provider capability
checks use real `--version` / `--help` output. Provider protocol fixtures are not
evidence of an authenticated model run.

See [the local-agent journey](specs/journeys/local_agents.md) and
`maxio-agent run --help` for the full invocation contract. A successful child process
is separate from validated output and storage publication. Logs can contain task
content; keep the retained records private.

This foundation does not yet register remote workers, schedule by dataset locality,
issue leases or fence stale publishers. Ordinary commands are trusted-user execution;
a working directory and cleared environment are not an OS sandbox. Agent credentials
are explicitly selected, storage credentials are excluded, and vendor safety controls
are preserved. Git remains responsible for source merges. Full remote execution is
an upcoming independent milestone, not a flag hidden in the S3 startup command.

## Peer S3

The [two-peer recipe](specs/journeys/peer_s3.md) gives exact commands for explicit
endpoint-shaped node IDs, shared credentials/token, authoritative request-time
listing and strict write quorum. A client can address either configured node.

The acceptance drill starts two real processes, exercises both placement owners,
checks two replica acknowledgements, stops/restarts a peer and reads each stored
copy independently:

```bash
python3 scripts/smoke_peer_s3.py --binary ./target/debug/maxio
```

The default peer settings remain `local-node-only` metadata and `degraded-success`
writes. Use the explicit recipe when testing cluster-wide visibility/durability.
Two-node strict quorum does not promise availability when one node is offline.

For native HTTPS with peer authentication, follow the [secure-peer recipe](specs/journeys/secure_peers.md).
Each peer has its own certificate and key, a shared CA trust bundle, and an exact
`maxio://host:port` certificate identity. Internal operations bind sender claims to
the actual TLS connection; copying the shared token is insufficient to impersonate
another certificate identity. Public HTTPS still accepts ordinary S3 clients.

```bash
python3 scripts/smoke_secure_peers.py --binary ./target/debug/maxio
```

The plain HTTP compatibility recipe remains for loopback/private encrypted
channels. Existing clusters using noncanonical mixed-case/IPv6 identities need a
planned migration because canonicalization changes placement IDs. Certificate
issuance and rotation remain explicit operator responsibilities.

## Configuration

Each executable's `--help` is its complete flag reference: `maxio`, `maxio-sync`,
`maxio-workspace`, and `maxio-agent`.

| Setting | Environment | Default / meaning |
|---|---|---|
| Address / port | `MAXIO_ADDRESS`, `MAXIO_PORT` | `0.0.0.0`, `9000` |
| Data directory | `MAXIO_DATA_DIR` | `./data` |
| Credentials | `MAXIO_ACCESS_KEY`, `MAXIO_SECRET_KEY` | `minioadmin`, `minioadmin`; MinIO aliases supported |
| Region | `MAXIO_REGION` | `us-east-1`; MinIO aliases supported |
| Extra credentials | `MAXIO_ADDITIONAL_CREDENTIALS` | Comma-separated `access:secret` pairs, equal current rights |
| Node / peers | `MAXIO_NODE_ID`, `MAXIO_CLUSTER_PEERS` | Explicit reachable `host:port` IDs for peers |
| Peer token | `MAXIO_CLUSTER_AUTH_TOKEN` | Configure explicitly for peer use |
| Metadata strategy | `MAXIO_METADATA_LISTING_STRATEGY` | `local-node-only`; peer recipe uses `request-time-aggregation` |
| Write durability | `MAXIO_WRITE_DURABILITY_MODE` | `degraded-success`; peer recipe uses `strict-quorum` |
| Membership | `MAXIO_MEMBERSHIP_PROTOCOL` | `static-bootstrap`; gossip is experimental, Raft unimplemented |
| Erasure coding | `MAXIO_ERASURE_CODING`, `MAXIO_CHUNK_SIZE`, `MAXIO_PARITY_SHARDS` | Off; 10 MiB chunks; zero parity by default |
| Standalone HTTPS | `MAXIO_TLS_CERT_PATH`, `MAXIO_TLS_KEY_PATH` | Optional PEM chain/key pair; mutually exclusive with peer TLS |
| Sync private CA | `MAXIO_SYNC_CA_CERT` | Optional explicit trust bundle for an HTTPS sync endpoint |
| Secure peers | `MAXIO_CLUSTER_PEER_TLS_CERT_PATH`, `MAXIO_CLUSTER_PEER_TLS_KEY_PATH`, `MAXIO_CLUSTER_PEER_TLS_CA_PATH` | Complete identity/trust triplet enables native peer HTTPS |
| Peer transport policy | `MAXIO_CLUSTER_PEER_TRANSPORT_MODE` | `compatibility`; secure recipe uses `required` and a shared token |
| Internal listener | `MAXIO_INTERNAL_BIND_ADDR` | Optional separate control listener; TLS follows public configuration |

`/healthz` returns diagnostic JSON and `/metrics` Prometheus metrics.
`/healthz?scope=local` is a nonrecursive local observation used between peers; it
does not assert cluster readiness. Aggregate readiness uses a bounded authenticated
bucket-listing probe and labels its scope; individual object requests still report
their own coverage. Read readiness fields, not just HTTP status.

## Supported S3 surface and limits

Bucket create/head/list/delete/location, ListObjects v1/v2, object
put/get/head/delete/copy, batch delete, multipart upload, presigned URLs, range
reads, checksums, versioning and lifecycle foundations are implemented. Standalone
PutObject supports `If-None-Match: *` and an exact quoted `If-Match` ETag; failures
return 412. Conditional DELETE, CopyObject, multipart and distributed writes are
rejected with 501; conditional or version-specific batch deletion is also rejected.
Ordinary signed payloads and AWS chunk-signature chains are verified before
mutation. Streaming trailer variants and SigV4a remain unsupported.

The storage format is still path-based with JSON sidecars. It rejects internal
names (`.bucket.json`, `.uploads`, `.versions`, `.meta.json`/`.ec` suffixes and other
reserved segments) and ambiguous paths. It cannot represent all S3 flat-namespace
keys, such as both `a` and `a/b` as ordinary objects. Failed writes preserve existing
data, but payload and sidecar publication is not a full power-loss transaction.
Concurrent reads do not provide a guaranteed snapshot during replacement. Mutations
currently serialize per storage instance. Enabling versioning preserves existing
bytes as the null version; suspended-versioning semantics are not full AWS parity.

Console logout revokes the current session, including a copied cookie. Independent
logins remain active. Sessions are node-local and expire after seven days; server
restart invalidates them all. Upgrading from the former stateless cookies requires
a new login. At 4,096 active sessions, new login fails until a session expires or
is revoked. Native HTTPS cookies are Secure; login throttling uses the socket IP.
Operators behind one reverse proxy therefore share that proxy IP's login limit.

Back up the **whole** data directory while the server is stopped or through a
consistent filesystem snapshot, preserving sidecars, versions and runtime state.
Copying only object payload files is not a complete backup.

## Docker from this checkout

```bash
docker build -t maxio-local .
docker run --rm -p 127.0.0.1:9000:9000 -v maxio-data:/data \
  -e MAXIO_ACCESS_KEY -e MAXIO_SECRET_KEY maxio-local
```

The Docker image and release archives include `maxio`, `maxio-sync`,
`maxio-workspace` and `maxio-agent`. The container includes required native TLS
libraries and starts only the standalone `maxio` server by default. Select an
optional command with `--entrypoint`; agent provider CLIs and their runtimes are
separately provisioned by the owner.
The release workflow targets this fork's `ghcr.io/<owner>/<repo>` namespace.
No upstream container image is presented as containing this fork's changes.

## Development and verification

Read [AGENTS.md](AGENTS.md), [Lop](lop.md), [Gauntlet](gauntlet.md) and the
[domain map](specs/00_system.md). Thirteen tracked specs define write ownership,
interfaces, verification commands and external quality bars.

```bash
./scripts/domain_check.sh list
./scripts/domain_check.sh storage_engine
./scripts/domain_check.sh all
```

The full gate runs formatting, strict Clippy, the Rust suite once, frontend checks,
architecture/ownership checks, the three real-process journeys, and the secure-peer
transport drill. Python 3, OpenSSL and loopback networking are required. The existing `tests/mc_test.sh` and
`tests/aws_cli_test.sh` provide optional extra client compatibility drills.

For a domain branch, gate the complete diff against the PM-approved base:

```bash
python3 scripts/check_architecture.py --domain storage_engine --base BASE_SHA
```

A domain cannot widen its own scope or lower its bar. A green test command is not
an independent Gauntlet verdict. Review records state what was actually observed,
what remains a gap, and any explicit decision to stop.

## License and attribution

[Apache-2.0](LICENSE). See [NOTICE](NOTICE) for upstream attribution and modification
notice. Maintained by [Magnus Ohle](https://github.com/Mvgnu).
