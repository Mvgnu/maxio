# Managed workspace: setup, daily use and recovery

This guide is for the optional `maxio-fabric` coordinator and `maxio-worker`.
Ordinary S3 uses the separate [standalone instructions](standalone_s3.md) and needs
none of this configuration. Build the six binaries as described in the README.
The managed authority and cache currently require a private Unix filesystem.

The commands below deliberately use disposable, separate environments on **one
host**. They establish a useful local setup, not physical three-device/WAN proof.
On real devices, generate each key on that device, send only its public-key JSON
to the owner, and put the returned client configuration and trusted CA there.
Use a certificate valid for the actual reachable server address. No private device
key or provider credential belongs in a workspace catalog.

## 1. Start a private HTTPS authority

Run from the repository root. These variables are just local shell conveniences:

```bash
export MAXIO_FABRIC_BIN="$(pwd)/target/debug/maxio-fabric"
export MAXIO_WORKER_BIN="$(pwd)/target/debug/maxio-worker"
export MAXIO_DEMO_ROOT="$(mktemp -d)"
umask 077
mkdir "$MAXIO_DEMO_ROOT/tls"
```

For the disposable loopback example, create a CA and a separate server leaf. A CA
certificate used as a server leaf is correctly rejected by the client.

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=MaxIO demo CA' -addext 'basicConstraints=critical,CA:TRUE' \
  -keyout "$MAXIO_DEMO_ROOT/tls/ca.key" -out "$MAXIO_DEMO_ROOT/tls/ca.crt"
openssl req -new -newkey rsa:2048 -nodes -subj '/CN=localhost' \
  -keyout "$MAXIO_DEMO_ROOT/tls/server.key" -out "$MAXIO_DEMO_ROOT/tls/server.csr"
cat > "$MAXIO_DEMO_ROOT/tls/server.ext" <<'CERT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
CERT
openssl x509 -req -in "$MAXIO_DEMO_ROOT/tls/server.csr" \
  -CA "$MAXIO_DEMO_ROOT/tls/ca.crt" -CAkey "$MAXIO_DEMO_ROOT/tls/ca.key" \
  -CAcreateserial -days 1 -extfile "$MAXIO_DEMO_ROOT/tls/server.ext" \
  -out "$MAXIO_DEMO_ROOT/tls/server.crt"

"$MAXIO_FABRIC_BIN" keygen --key "$MAXIO_DEMO_ROOT/book.pem" \
  --public-key-out "$MAXIO_DEMO_ROOT/book-public.json"
"$MAXIO_FABRIC_BIN" init --root "$MAXIO_DEMO_ROOT/authority" \
  --owner-key "$MAXIO_DEMO_ROOT/book.pem" --name MacBook \
  --endpoint https://127.0.0.1:9443 --ca-cert "$MAXIO_DEMO_ROOT/tls/ca.crt" \
  --client-config "$MAXIO_DEMO_ROOT/book.json"
"$MAXIO_FABRIC_BIN" serve --root "$MAXIO_DEMO_ROOT/authority" \
  --bind 127.0.0.1:9443 --tls-cert "$MAXIO_DEMO_ROOT/tls/server.crt" \
  --tls-key "$MAXIO_DEMO_ROOT/tls/server.key"
```

Keep `serve` running in its terminal, or start that last command in the background
for this disposable test. Use the same environment variables in the next terminal.
The authority root is exclusive and append-only. Never point another authority,
S3 server, editable workspace or worker cache at it. Keep the CA private key off
workers in a real deployment; workers need the CA certificate only.
Keep private authority/cache roots outside directories managed by another file
synchronizer. Unexpected inode or index changes intentionally stop mutation and
preserve bytes; MaxIO does not silently adopt those changes as verified cache state.

For the remaining commands this helper selects the owner's client configuration:

```bash
book() { "$MAXIO_FABRIC_BIN" --config "$MAXIO_DEMO_ROOT/book.json" "$@"; }
book info
book workspace create projects
```

Online commands print JSON containing `result` and `transfers`. Payload counters
count application bytes supplied to/read from HTTP, excluding framing; they are
not a provider durability acknowledgment. The process journey independently counts
payload at its HTTPS observation proxies.

## 2. Enroll the Mini and VPS

```bash
for device in mini vps; do
  "$MAXIO_FABRIC_BIN" keygen --key "$MAXIO_DEMO_ROOT/$device.pem" \
    --public-key-out "$MAXIO_DEMO_ROOT/$device-public.json"
  book device enroll --name "$device" --role worker \
    --public-key "$MAXIO_DEMO_ROOT/$device-public.json" \
    --write-config "$MAXIO_DEMO_ROOT/$device.json" \
    --key-path "$MAXIO_DEMO_ROOT/$device.pem"
done
```

Enrollment establishes device identity, not workspace access. Read each returned
`device_id`, or get it from its client configuration. Grant access explicitly:

```bash
export MAXIO_MINI_ID="$(python3 -c 'import json,os; print(json.load(open(os.environ["MAXIO_DEMO_ROOT"]+"/mini.json"))["device_id"])')"
export MAXIO_VPS_ID="$(python3 -c 'import json,os; print(json.load(open(os.environ["MAXIO_DEMO_ROOT"]+"/vps.json"))["device_id"])')"
book device grant --device "$MAXIO_MINI_ID" --workspace projects --catalog \
  --read . --write docs/ --write src/ --write data/ --write results/
book device grant --device "$MAXIO_VPS_ID" --workspace projects --catalog \
  --read . --write results/
mini() { "$MAXIO_FABRIC_BIN" --config "$MAXIO_DEMO_ROOT/mini.json" "$@"; }
```

A trailing `/` denotes a tree scope; an ordinary path denotes an exact file; `.`
is the whole workspace. Full catalog visibility is a separate `--catalog` grant.
A job submitter additionally needs `--submit-jobs`, read rights for its exact inputs
and write rights for its output scopes. The owner already has full authority.

`device revoke --device UUID --confirm` prevents subsequent admission and commits.
It cannot recall bytes already delivered, offline copies or a stream already
admitted. Key rotation takes a new public-key JSON and the expected generation;
keep the new private key on its device, update that device's configuration, and
verify access. Sessions are short-lived and restart invalidates all old sessions.
No shared enrollment password substitutes for proof of an enrolled private key.

## 3. Discover, pull and publish selected files

```bash
mkdir "$MAXIO_DEMO_ROOT/mini-work" "$MAXIO_DEMO_ROOT/book-work"
mini workspace pull projects --root "$MAXIO_DEMO_ROOT/mini-work"
mkdir -p "$MAXIO_DEMO_ROOT/mini-work/docs" "$MAXIO_DEMO_ROOT/mini-work/data" \
  "$MAXIO_DEMO_ROOT/mini-work/src"
printf 'A selected project note.\n' > "$MAXIO_DEMO_ROOT/mini-work/docs/note.md"
python3 -c 'import os,pathlib; pathlib.Path(os.environ["MAXIO_DEMO_ROOT"]+"/mini-work/data/example.bin").write_bytes(bytes(range(256))*4096)'
cat > "$MAXIO_DEMO_ROOT/mini-work/src/hash.py" <<'PY'
from pathlib import Path
import hashlib, json
path = Path('data/example.bin')
hash = hashlib.sha256()
size = 0
with path.open('rb') as source:
    for chunk in iter(lambda: source.read(1024 * 1024), b''):
        hash.update(chunk)
        size += len(chunk)
Path('results').mkdir(exist_ok=True)
Path('results/hash.json').write_text(json.dumps({'sha256': hash.hexdigest(), 'size': size}))
print('Hashed', size, 'bytes on the selected worker')
PY
mini workspace publish projects --root "$MAXIO_DEMO_ROOT/mini-work" \
  --path docs/ --path src/ --path data/

book workspace pull projects --root "$MAXIO_DEMO_ROOT/book-work"
book workspace pull projects --root "$MAXIO_DEMO_ROOT/book-work" --path docs/
"$MAXIO_FABRIC_BIN" workspace status --root "$MAXIO_DEMO_ROOT/book-work" --verify
"$MAXIO_FABRIC_BIN" workspace pin --root "$MAXIO_DEMO_ROOT/book-work" --path docs/
```

The first Book pull updates metadata only. The second retrieves `docs/`; `data/`
and `src/` remain absent. Status and pin/unpin are available offline. A pin covers
currently hydrated exact versions, not future files added to a directory.

Edit selected files, then use `workspace publish ... --path docs/`. Publication
stages immutable copies, renews its lease during transfer, checks the original
baselines, and commits against the exact managed head. Another writer or a changed
baseline produces an explicit conflict; your local edit and stage stay retained.
Refreshing metadata cannot turn conflicting edits into a safe overwrite.

`workspace delete projects --path docs/note.md --confirm` is an explicit global
logical deletion. The vault retains its previous version; local working files
remain untouched and visible as stale/dirty retained baselines. Restore with
`workspace restore ... --revision UUID --sha256 HASH --path docs/note.md --confirm`.
The exact revision hash appears in catalog/head output. A historical pull uses the
same `--revision` and `--sha256` pair and does not become a publication base.

## 4. Keep the dataset on the Mini and run the task there

Save exact references, then import the Mini's existing dataset into its private
immutable cache. This is a local verified copy, not a network dataset transfer:

```bash
book workspace references projects --path data/example.bin \
  --output "$MAXIO_DEMO_ROOT/dataset-references.json"
mini cache import --root "$MAXIO_DEMO_ROOT/mini-worker" \
  --references "$MAXIO_DEMO_ROOT/dataset-references.json" \
  --source "$MAXIO_DEMO_ROOT/mini-work/data/example.bin"
cat > "$MAXIO_DEMO_ROOT/profiles.json" <<'JSON'
[
  {"name":"hash","adapter":"command","executable":"/usr/bin/python3",
   "args":["src/hash.py"],"permission":"workspace_write","environment":{}}
]
JSON
"$MAXIO_WORKER_BIN" --config "$MAXIO_DEMO_ROOT/mini.json" \
  --root "$MAXIO_DEMO_ROOT/mini-worker" --profiles "$MAXIO_DEMO_ROOT/profiles.json"
```

Start the VPS worker in another terminal with its `vps.json` and a separate
`vps-worker` root, using the same profile. Use the absolute Python path installed
on each machine. Then submit from the Book:

```bash
book workers
book task submit projects --profile hash --input src/hash.py \
  --input data/example.bin --output results/hash.json --publish
book task status JOB_UUID
book task explain JOB_UUID
book task logs JOB_UUID --attempt ATTEMPT_UUID --text
book workspace pull projects --root "$MAXIO_DEMO_ROOT/book-work" --path results/
```

The candidate decision names eligible workers and missing selected bytes. With
both workers compatible and available, the Mini's verified dataset reduces its
transfer cost. Its attempt retains the selected input identities, local run,
logs, output candidates and publication receipt. The Book does not receive the
dataset. `--worker DEVICE_UUID` imposes a manual worker constraint; it does not
silently fall back to a different worker.

`task logs --text` prints the decoded log page directly, preserving its exact bytes.
Omit `--text` for JSON with `data_base64`, `next_offset`, `eof` and transfer counts.
Each page is at most 64 KiB; use `--offset NEXT_OFFSET` for later pages and
`--stderr` to inspect the separate error stream. This reads retained output, not a
continuous live-follow subscription.
Native child output is normalized to UTF-8 before retained logging. Publish binary
results as files; logs are not a lossless archive of arbitrary binary stdout.

`--output` is an allowlist of proposed output paths, not a promise that a command
will produce each path. Without `--publish`, successful results remain in the
worker attempt for inspection. `RunRecord.published` always remains false; the
separate `PublicationReceipt` is the authoritative published result. A required
publication conflict leaves the successful local output recoverable.

### Codex CLI and Claude Code profiles

Use the same worker boundary with installed, owner-authenticated CLIs:

```json
[
  {
    "name": "codex",
    "adapter": "codex",
    "executable": "/absolute/path/to/codex",
    "args": [],
    "permission": "workspace_write",
    "environment": {"CODEX_HOME": "/absolute/worker-private/codex-home"}
  },
  {
    "name": "claude",
    "adapter": "claude",
    "executable": "/absolute/path/to/claude",
    "args": [],
    "permission": "workspace_write",
    "environment": {"CLAUDE_CONFIG_DIR": "/absolute/worker-private/claude-config"}
  }
]
```

Provider profiles cannot append arbitrary CLI flags. The existing runner applies
its tested safe adapter flags and checks capability before execution. Claude's
current adapter exposes file tools only. Add `--prompt-file /local/task.txt` at
submission; prompt contents are sent privately to the assigned worker and are not
public job-status fields. Prompts and logs may contain task data. A command/model
can echo input in its own output; do not treat logging as a secret filter.

Credentials, provider homes, executable paths and environment values are selected
locally by the worker owner. The submitted job cannot choose them. MaxIO performs
no provider login and supplies no general storage credentials to the child.
Environment filtering/cwd copies are not an OS sandbox; use appropriate OS users
or external isolation for untrusted native commands. A protocol-fixture pass is
not evidence of an authenticated provider model call.

## 5. Pin, evict and refetch the private cache

Stop the idle Mini worker first: its lifetime cache lock intentionally excludes a
second manager. Offline inspection and pins need no authority connection:

```bash
"$MAXIO_FABRIC_BIN" cache inspect --root "$MAXIO_DEMO_ROOT/mini-worker" --verify
"$MAXIO_FABRIC_BIN" cache pin --root "$MAXIO_DEMO_ROOT/mini-worker" \
  --references "$MAXIO_DEMO_ROOT/dataset-references.json"
mini cache evict --root "$MAXIO_DEMO_ROOT/mini-worker" \
  --references "$MAXIO_DEMO_ROOT/dataset-references.json" --confirm
```

That eviction must fail while pinned. Unpin and retry:

```bash
"$MAXIO_FABRIC_BIN" cache pin --root "$MAXIO_DEMO_ROOT/mini-worker" \
  --references "$MAXIO_DEMO_ROOT/dataset-references.json" --unpin
mini cache evict --root "$MAXIO_DEMO_ROOT/mini-worker" \
  --references "$MAXIO_DEMO_ROOT/dataset-references.json" --confirm
mini cache hydrate --root "$MAXIO_DEMO_ROOT/mini-worker" \
  --references "$MAXIO_DEMO_ROOT/dataset-references.json"
```

Eviction checks fresh verified retention of the exact immutable version in the
append-only vault. Offline/unverifiable retention, pins, active attempts, changed
contents or inode/link mismatches preserve local bytes. Its JSON separates logical
bytes removed, allocated blocks unlinked and observed filesystem free-space delta.
Other processes can affect that last observation; the isolated journey records it.
Each eviction verifies at most 256 explicit references. Split larger selections
into bounded batches; a capacity rejection preserves the selected local bytes.

Only `cache/objects` is eligible. Original files imported from the Mini, editable
working copies, retained task input copies, incomplete stages, logs, outputs and
history are not deleted by cache eviction. This first version has no general GC;
large active tasks still need room for independent writable copies.

## 6. Recover failures deliberately

- **Uncertain publication response:** the CLI prints and retains a publication
  request under `.maxio-workspace/managed-operations/`. Run
  `workspace recover-publication --root ROOT --operation REQUEST.json` with the
  same client configuration. An already committed request returns its durable
  receipt; the same ID with altered contents is rejected. If it never committed
  and its lease expired, inspect retained edits and publish under new authority.
- **Failed/cancelled task:** inspect `task status` and `task logs`. Its local
  `WORKER_ROOT/attempts/ATTEMPT_UUID/` retains `attempt.json`, selected source,
  `runs/RUN_UUID/record.json`, logs, edited workspace and staged outputs. Use
  `maxio-agent inspect --run .../runs/RUN_UUID` for the canonical local record.
- **Cancellation:** `task cancel JOB_UUID` records intent. Wait for an actual
  terminal record. A disconnected worker may continue locally until supervision
  notices; expiry/fencing blocks stale publication. A killed worker can leave an
  unconfirmed child. Restart reconciliation does not kill a stored PID.
- **Worker loss:** restart with the same private root and device configuration.
  A fresh incarnation reconciles existing attempts and retains unconfirmed work.
  `task retry JOB_UUID --previous-attempt ATTEMPT_UUID` is explicit and creates a
  new attempt. Commands with external side effects are not exactly-once.
- **Coordinator loss:** restart `serve` on the same authority root. Its persisted
  epoch advances before accepting work, old leases/claims expire, and active jobs
  become abandoned for inspection/manual retry. Committed versions and receipts
  remain readable. There is no leader failover or alternate partition authority.
- **Partial transfer/eviction:** incomplete stages and eviction intents remain
  inspectable. Reopen reconciles what actually exists; it never repeats an
  ambiguous unlink against a replacement inode or treats missing data as a delete.

The vault has no destructive API and retains one server-filesystem copy. That is
not protection against host/disk loss, external administrator deletion, power-loss
behavior not covered by the tests, or an incorrectly backed-up authority/vault.
No signed external share-link service, provider replication policy, continuous
filesystem watcher or FUSE mount is implemented in managed mode.

For the reproducible measured process exercise, use `scripts/smoke_fabric.py`
with `--fabric-binary`, `--worker-binary` and an explicit `--evidence` directory.
Its report states which failure cases were actually exercised. The dated review
contains independent Gauntlet judgments; a successful script alone is not that
judgment.
