# Independent managed onboarding review

## Verdict

**One actual onboarding gap: readable task-log inspection is incomplete as documented.** The remaining observed steps receive a bounded pass for this local command-worker journey. Starting from the README, the managed usage guide, the linked standalone guide, and executable help, I completed device enrollment, explicit grants, publication, metadata-only discovery, selected pulls, two-worker placement, the documented Python hash job, result publication, and the cache pin/refusal/unpin/evict/refetch sequence. No undocumented product or configuration edit was needed to make those operations succeed.

The largest observed operability gap is **human-readable task logs**. The documented `task logs JOB --attempt ATTEMPT` command returns JSON containing only base64 log bytes. Its help has no text/raw/decoded option, and the guide supplies no decoding command. I could inspect the actual stdout only after adding a small external base64-decoding step. That extra operation is recorded as a gap, not counted as success of the documented log-inspection step. It did not prevent submission, execution, publication, or recovery of the result, but it prevents an unqualified documented-only onboarding pass.

This is a review of the documented onboarding experience, not a full functional, security, failure-recovery, durability, provider, or WAN acceptance verdict.

## Scope and isolation

- Review date: 2026-10-25. The successful hash run started at 17:29:32 UTC.
- Frozen artifact source: `22c1d523e25a390650dff1b8ddec41c1c277e3e9`.
- Binaries: `/workspace/scratch/05c136f30bb4/fabric-integration-22c1d52/`. All six executable SHA-256 values matched `artifact.json`; see `observed-20261025T1729/binary-verification.json`.
- Documents read: `README.md`, `specs/journeys/managed_fabric_usage.md`, and its linked `standalone_s3.md`. Relevant top-level and task-command help were also inspected. I did not read implementation, smoke scripts, tests, or earlier review reports.
- No Cargo invocation, product edits, model calls, provider credentials, outside credentials, or external network service was used.
- Successful managed runtime: `/tmp/maxio-managed-onboarding.GfQSIf`, with authority endpoint `https://127.0.0.1:41593`. Device workspaces, worker roots, TLS material, and runtime records were all under that directory.
- Separate standalone startup and an initial harness timing attempt used `/tmp/maxio-managed-onboarding.oEjuiY`.
- The guide's private CA and separate SAN-bearing server leaf were used. Client configurations were generated with `--ca-cert`; no TLS bypass was used. Managed authentication was individual device-key authentication over verified server TLS.
- Normal environment substitutions were the supplied prebuilt binary paths, available loopback ports, and the installed absolute Python path. The profile used `/opt/codex/runtimes/codex-primary-runtime/dependencies/python/bin/python3`; the run record resolved it to `python3.12`.
- Every server and worker was stopped and waited for before the completed evidence was copied here. `managed/stopped-processes.json` records that the three main managed PIDs no longer existed. The task had already reached a terminal state before stopping the idle Mini worker.

## Commands followed and observed behavior

The full expanded command trace is in `observed-20261025T1729/managed/transcript.txt`. The setup used the guide's `book()` and `mini()` helpers, with the documented generated client configurations.

| Stage | Documented commands followed | Observed result and evidence |
|---|---|---|
| Independent standalone start | `maxio --address 127.0.0.1 --data-dir ... --port ...`, with the README's S3 credential environment variables | `/healthz` returned `ok: true`, `mode: standalone`, and `clusterPeerCount: 0`. The process required no managed authority, device key, worker profile, or workspace configuration. See `preliminary-startup/standalone-health.json` and `standalone-help.txt`. |
| Verified HTTPS authority | Guide's three OpenSSL certificate commands; `keygen`; `init --owner-key ... --endpoint https://127.0.0.1:41593 --ca-cert ... --client-config ...`; `serve --bind ... --tls-cert ... --tls-key ...`; `book info` | The generated client authenticated successfully and returned the authority/vault identity. See `managed/authority-init.json`, `managed/info.json`, and the command trace. |
| Enrollment and explicit access | `book workspace create projects`; key generation and `device enroll --role worker` for Mini and VPS; the guide's `device grant --catalog --read . --write ...` commands | Both workers received separate device IDs and grants. Mini had the documented source/data/docs/results write scopes; VPS had results write access. See enrollment/grant JSON files. |
| Publish the Mini's files | Metadata pull into `mini-work`; create the exact guide note, 1 MiB dataset, and `src/hash.py`; `mini workspace publish projects --root ... --path docs/ --path src/ --path data/` | Publication committed all three paths with a durable receipt. Application payload upload was 1,049,044 bytes: 1,048,576 dataset bytes, 443 source bytes, and a 25-byte note. See `managed/mini-publish.json`. |
| Discover and selectively pull from Book | `book workspace pull projects --root ...`; repeat with `--path docs/`; offline `workspace status --verify` and `workspace pin --path docs/` | Metadata-only pull hydrated nothing and reported zero payload bytes. The selected pull downloaded only the 25-byte note. Source and dataset stayed absent; verified status called the note clean. See `book-metadata-pull.json`, `book-docs-pull.json`, `book-status.json`, and `selected-presence-before-workers.json`. |
| Seed Mini locality and start two workers | `book workspace references ... --path data/example.bin --output ...`; `mini cache import ... --source ...`; start `maxio-worker` for Mini and VPS with distinct roots and the documented hash profile | Import reported zero uploaded/downloaded payload. Both workers advertised the hash profile and compatible resources; only Mini advertised the dataset. See `mini-cache-import.json` and `workers-before-submit.json`. |
| Submit and inspect placement | `book task submit projects --profile hash --input src/hash.py --input data/example.bin --output results/hash.json --publish`; `task status`; `task explain` | Both workers were eligible. Mini cost was 443 missing bytes; VPS cost was 1,049,019 missing bytes. Mini was selected. See `task-submit.json`, `task-explain.json`, and `task-status.json`. |
| Inspect actual run, logs, and published result | `book task logs JOB --attempt ATTEMPT`; `book workspace pull projects --root ... --path results/` | The run and job succeeded with exit code 0. The separate publication receipt committed `results/hash.json`. Book pulled 95 payload bytes. After decoding the returned log page, stdout read `Hashed 1048576 bytes on the selected worker`. See `task-logs.json`, `task-stdout-decoded.txt`, `book-result-pull.json`, and `hash-result-verification.json`. |
| Stop idle worker and pin cache | Confirm `active_attempt: null`; stop and wait for Mini; `cache inspect --verify`; `cache pin --references ...`; `mini cache evict ... --confirm` | Both selected inputs verified. Pinned eviction exited 1 with `selected cache content is pinned`; inspection still showed the dataset verified and pinned. See `workers-after-task.json`, `cache-before-pin.json`, `cache-pinned-refusal.txt`, `cache-pinned-exit-code.txt`, and `cache-after-refusal.json`. |
| Unpin, evict, and refetch | `cache pin ... --unpin`; `mini cache evict ... --confirm`; `mini cache hydrate ...`; `cache inspect --verify` | Eviction removed 1,048,576 logical cache bytes and reported the same allocated bytes unlinked. Only the 443-byte source entry remained. Refetch downloaded exactly 1,048,576 payload bytes and restored a verified dataset entry. See `cache-unpin.json`, `cache-evict.json`, `cache-after-evict.json`, `cache-refetch.json`, and `cache-after-refetch.json`. |

The job ID was `f461619e-fddb-497d-8541-ba56cc515d9f`; its attempt ID was `7da952cb-2031-41b6-8036-10c0b0039f64`. Mini's device ID was `cfa39a0b-caee-4dfa-92cd-9b4829bafaa9`; VPS's was `e5bbd3e9-4091-4e3d-b39f-19051720de53`.

The published result was independently compared with the original dataset:

```json
{
  "sha256": "fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83",
  "size": 1048576
}
```

Book still had neither `data/example.bin` nor `src/hash.py` after obtaining the result. VPS's final verified cache was empty. The Mini's original dataset and retained run input still existed with the same hash after eviction/refetch. The worker's native `RunRecord.published` remained false while its separate publication receipt and worker completion event showed successful publication, matching the guide's distinction.

## Largest operability gap: reading task logs

`task logs` returned this structure, with the actual content encoded:

```json
{
  "page": {
    "data_base64": "SGFzaGVkIDEwNDg1NzYgYnl0ZXMgb24gdGhlIHNlbGVjdGVkIHdvcmtlcgo=",
    "eof": true,
    "next_offset": 44,
    "offset": 0,
    "truncated": false
  }
}
```

The extra inspection operation was equivalent to:

```python
page = json.load(open('task-logs.json'))['result']['page']
print(base64.b64decode(page['data_base64']).decode(), end='')
```

The guide establishes JSON output, so structured logs are not surprising. The practical gap is that its advertised log-inspection command does not produce readable log text and no documented next step or CLI flag completes that inspection. An operator investigating a failed remote job would have to infer the encoding and decode/page the response. This is the one improvement I would prioritize from the observed journey. No fix was made during this review.

## Harness timing issue, explicitly retained

The first attempt backgrounded `serve` and immediately invoked `book info` within the same automated command block. It received connection refused before the listener was ready. Strict harness error handling stopped and waited for its processes. That attempt's transcript is retained under `preliminary-startup/`.

I restarted the managed sequence in a new disposable root and allowed the background server to start before issuing the next-terminal client commands. No certificate, server, client, or profile setting was changed to address this timing issue. The full successful managed sequence then remained within one uninterrupted escalated shell subprocess. I treat the initial event as a harness readiness race, not evidence of a broken documented manual setup or a peer-certificate failure.

## Practical limits of this pass

- This used separate roots and real processes on one host with a 1 MiB dataset. It proves neither physical device operation nor WAN reachability, NAT traversal, throughput, large-file behavior, or redundant storage durability.
- Reported transfer figures are the CLI's application-byte counters. I did not insert a proxy or independently measure network packets, framing, or retry traffic. The scheduler's 443-byte and 1,049,019-byte figures are its stated placement costs, not an independent worker-network measurement.
- The eviction's observed filesystem free-space delta was **−4,096 bytes**, despite 1,048,576 logical bytes removed and allocated bytes reported unlinked. This shared filesystem observation does not demonstrate a 1 MiB physical free-space increase. The guide appropriately separates those measurements; this review preserves that distinction.
- Editable originals and retained attempt copies remained. Cache eviction is not whole-project disk cleanup, and this review makes no general garbage-collection claim.
- The command profile was the only executed adapter. The README and guide specify separately installed, owner-authenticated Codex/Claude CLIs, absolute executable paths, worker-private credential/configuration directories, and current Claude file-tool limitations. Those instructions were assessed as prerequisites only. No provider was installed, authenticated, or asked to execute a model task.
- The review did not exercise explicit worker constraints, revocation, key rotation, unauthorized access, cancellation, retry, publication conflicts, restart reconciliation, historical restore, or the guide's failure-recovery cases. Their documentation is not execution evidence here.
- Standalone separation was verified through executable help and actual independent startup/health. No claim is made here about the standalone console, S3 CRUD, restart durability, build/release packaging, or container contents.

## Evidence location

All completed evidence is under `observed-20261025T1729/`. It includes raw JSON responses, command traces, process logs, the exact hash source and profile, reviewed-document hashes, executable help, binary hash verification, and post-stop observations. Private keys, client configurations, and provider credentials are not included in the saved evidence.
