# Independent managed authority and HTTPS critic

## Judgment

**Bounded pass for the assigned enrollment/grant/revocation and fenced publication/restart properties. No violating gap was observed in this round.** This judgment concerns the exact executable below, a single native authority, separate client processes and fresh device keys on one host. It is not a judgment about the whole product or other binaries.

## Exact artifact and independence

- Executable: `/workspace/scratch/05c136f30bb4/fabric-integration-22c1d52/maxio-fabric`
- Source attribution supplied with that frozen artifact: `22c1d523e25a390650dff1b8ddec41c1c277e3e9`
- SHA-256 independently computed at execution: `1d6d171f43a5388a94e3534ef53c1a2086bb8ab6129ce7ed5cc13122890db00b`
- Date: 2026-10-25 UTC.
- Definitive completed run: `full-2/`, containing 48 recorded checks, all passed. These include orchestration checks as well as the substantive properties below.

I read the four assigned managed specs, the public `src/fabric/contract.rs`, CLI help, and the official comparison documents. I did not read implementation source, builder reports, review history, or builder test evidence; did not invoke Cargo; and made no provider/model calls. I wrote only my independent harness and evidence in the assigned critic folder. Live authority data and processes stayed together in `/tmp/maxio-independent-managed-critic-8hcvaayz`; evidence was copied after shutdown.

The harness generated five fresh Ed25519 keys: one bootstrap owner, three separately enrolled devices, and an unenrolled stranger. It used a fresh private CA and a separate localhost leaf certificate. All application requests used verified server HTTPS. A narrow observation proxy, with the same verified CA on both connections, paused or suppressed selected requests/responses. Device identity remained the managed application-key protocol throughout.

## Security observations

The comparison property is invitation-based device authority and encrypted, authenticated transport, drawn from [Syncthing Security Principles](https://docs.syncthing.net/users/security.html). This is a property comparison, not a claim of implementing Syncthing's certificate-based identity mechanism or its complete security model.

| Scenario | Actual observation |
|---|---|
| Fresh, unenrolled key | A typed catalog request failed with `Unauthenticated`. |
| Unrelated private key claiming the owner's enrolled ID | The proof failed with `Unauthenticated`; copying the ID/config did not confer authority. |
| Reachable native server with an unrelated trust root | The client rejected `invalid peer certificate: UnknownIssuer`. |
| Enrolled Alice before any workspace grant | Catalog and lease requests failed with `Forbidden`; an exact file read returned HTTP 403. |
| Catalog-only grant | The manifest became inspectable, but the exact payload read still returned HTTP 403. |
| Explicit `docs/` read/write grant | `docs/a.txt` returned its exact 7,948 bytes. Both `private/secret.txt` and `docs-sibling/not-allowed.txt` were denied for reads and write leases, confirming path-component scope behavior. |
| Grant removal after successful preparation | Carol authenticated, acquired a lease, uploaded actual replacement bytes, and reached a publication gate. The owner removed Carol's grant before the native authority admitted publication. The existing-session commit returned HTTP 403, `publication exceeds current write grant`. The committed head and Carol's local edited bytes remained unchanged. |
| Device revocation with two existing sessions | Alice's actual upload was prepared and its publication paused. A second Alice process authenticated, obtained metadata, and paused immediately before its file-read request reached the authority. After owner revocation, publication and file read both returned HTTP 401. No target file was installed. A new authentication attempt also failed. The head and Alice's local unpublished edit remained intact. |

The decisive proxy records are `full-2/proxy/requests.json` entries 114 (grant removal), 129 (revoked publication), and 135 (revoked read). The raw HTTP responses, request hashes, selected request bodies, byte counts and timestamps are retained. Session bearer values are redacted in the saved proxy evidence.

## Ownership, publication and restart observations

The comparison property is durable atomic publication with current ownership, using the durability, strict-serializability and lease discussion in [etcd API guarantees](https://etcd.io/docs/v3.6/learning/api_guarantees/). No etcd/Raft implementation or distributed consensus claim follows from this review.

1. **Overlapping ownership:** Two independent CLI processes authenticated as Alice and Bob and requested `docs/` leases concurrently. Bob received a lease; Alice received `Conflict: requested write scope overlaps an active lease`. The previous committed file remained readable while the lease was held.

2. **Expired prepared writer:** Alice obtained a two-second lease at epoch 2, fence 3, and successfully uploaded 800 actual replacement bytes. After expiry, Bob received fence 4. Alice's saved publication and renewal were rejected with `Conflict: write lease expired, released or revoked`; the entire head was unchanged. Bob then uploaded and committed 9,507 different bytes under the new lease. Both the new and previous exact versions remained readable.

3. **Real crash with prepared work:** Bob acquired a 120-second lease at epoch 2, fence 5, and uploaded actual replacement bytes for `docs/b.txt`. The native authority process was killed with SIGKILL (exit `-9`) and restarted on the same private root. The epoch advanced from 2 to 3. An old session returned HTTP 401; a fresh Bob session presenting the old publication/lease received a conflict. The head remained unchanged. A newly acquired lease carried epoch 3, fence 6.

4. **Lost successful response and another crash:** The proxy forwarded an owner publication to the native authority, captured its HTTP 200 receipt, and deliberately closed the client connection without returning the response. The CLI exited unsuccessfully and retained the publication request. The authority was then killed with SIGKILL and restarted again. `workspace recover-publication` returned an identical receipt for request `2477768e-ec0e-4874-8634-a179da488d30`, publication `b9f2ff8b-3b44-47f1-8164-f13c21c65ed0`. Recovery did not advance the head. Replaying the same request ID with an altered path was rejected with `Conflict: request ID was used with different contents`.

5. **Exact history after restart:** All three committed `docs/a.txt` versions returned exact bytes after the second restart. The first two versions survived both crashes; the third survived the crash immediately following its lost acknowledgment.

| Committed version | Bytes | SHA-256 |
|---|---:|---|
| Original | 7,948 | `4e6fee374d77a2b3c83509b783501f8dd66129fef6580b3eb35d9f884dacea70` |
| New fence | 9,507 | `852ebbb289ed928c1cb79cb833e8d69bdea5f0280aa84b6386e0312a768deef6` |
| Lost acknowledgment | 9,234 | `0bd827622c3c51bf265a087b4b022584581fd3768a193d0bbf39755ef77c8b0b` |

## Independent durable-record inspection

After shutdown I inspected the copied authority snapshot, revision manifests and actual vault bodies, in addition to the network and CLI observations. `full-2/durable-record-audit.json` records the results:

- Final authority epoch 4; fence high-water 9; no active leases.
- Exactly three durable publication receipts, plus the initial empty revision in the retained revision index.
- Exactly one stored receipt for the lost-response request; its committed head is generation 34, revision `ec06617a-5a64-434a-b8bf-71f9223f4c5d`.
- Manifest and actual body hashes match all three exact versions above.
- Failed expired, pre-restart, grant-removed and revoked edits did not appear in any committed manifest. Their uploaded/staged bytes remain retained separately.
- Final committed head matches the lost-response publication despite subsequent rejected writes and authorization changes.

## Reproduce and evidence

From an environment allowing loopback sockets:

```bash
python3 /workspace/scratch/05c136f30bb4/critic-managed-authority/run_critic.py \
  --binary /workspace/scratch/05c136f30bb4/fabric-integration-22c1d52/maxio-fabric \
  --phase full \
  --evidence /workspace/scratch/05c136f30bb4/critic-managed-authority/new-run
```

The command generates new device keys and a fresh authority root. Its `tls/` fixture is the critic's disposable CA/server leaf, generated independently for this review and valid for two days. Regenerate that fixture with the documented separate-CA/leaf procedure when expired. Choose a new evidence directory for each run. No existing repository data or authority is used.

Primary evidence: `full-2/events.json`, `full-2/checks.json`, `full-2/proxy/requests.json`, `full-2/durable-record-audit.json`, `full-2/authority-file-inventory.json`, copied native logs, retained operation requests/receipts, copied local edits, and the copied vault. The earlier `full-1` stopped because my harness incorrectly expected a nested lease field in a high-level CLI response; that was a harness parser error, corrected before the definitive run. `explore-1` established observed wire formats and baseline behavior.

## Genuine limits of this pass

This establishes the specified authority/security properties for these concrete process-level scenarios. It does not establish physical multi-device or WAN behavior, quorum/HA/failover, resistance to host or disk loss, arbitrary power-loss ordering, hostile same-UID isolation, scalability limits, or exhaustive linearizability under arbitrary schedules. The data here were small deterministic non-sparse payloads, not the separate 128-MiB selective-transfer journey. Worker execution, provider model execution, cache eviction and standalone S3 were outside this critic's assignment.

Revocation was tested at new operation admission using already-created sessions; it cannot recall offline copies or bytes already delivered, and this report makes no claim to interrupt an already admitted file stream. The exact binary hash above is the review boundary; later binaries need their own attribution and applicable verification.
