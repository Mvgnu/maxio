# Independent worker-execution Gauntlet assessment

**Verdict: bounded pass for the exercised worker-execution contract on frozen commit 22c1d523e25a390650dff1b8ddec41c1c277e3e9. No blocking product gap was found in these observations.**

The eligible worker with the resident 128 MiB dataset executed a real command, produced the independently verified result, and obtained a separate publication receipt. The submitting client received zero dataset payload. Cancellation, worker replacement during publication, and abrupt loss during execution preserved recoverable work. Explicit retries succeeded. Both provider adapters subsequently passed through explicitly labelled local protocol fixtures.

This is a one-host, separate-process result with one authority. It does not establish physical multi-device behavior, WAN performance, an OS sandbox, enforced resource quotas, authenticated provider model execution, or every failure case in Journey E.

## Artifact and independence

The tested binaries came only from /workspace/scratch/05c136f30bb4/fabric-integration-22c1d52. Their measured SHA-256 values matched the frozen artifact manifest:

| Binary | SHA-256 |
|---|---|
| maxio-fabric | 1d6d171f43a5388a94e3534ef53c1a2086bb8ab6129ce7ed5cc13122890db00b |
| maxio-worker | 5c172e129d435a2cfdbf535f803535ce59fc7d2c207c6bb6d651a8b869a09a19 |
| maxio-agent | 347be02599e83d170d38c9f9197f40dc7c5005d9200272042badff49915675c9 |

The review used the three permitted managed journey/domain documents, public CLI help, and src/fabric/contract.rs. No implementation, builder report, smoke script, historical review, Cargo command, or product change was used to construct or judge this exercise. A separate measurement reviewer checked the newly produced harness and stopped evidence; it did not inspect implementation or sibling work.

The external comparison is the specific [Ray locality-aware scheduling property](https://docs.ray.io/en/latest/ray-core/scheduling/index.html#locality-aware-scheduling), retrieved on 2026-10-25: favor an available eligible node with large inputs already local. Recoverable failed work is an additional acceptance requirement from the MaxIO contract. This is not a benchmark or a claim of Ray feature equivalence.

## Main execution and placement

The main successful runtime was /tmp/critic-managed-execution-dri_4pg7. Book, Mini, and VPS had separately enrolled keys/configurations. The authority, both workers, and the HTTPS observation proxies were separate processes or server instances. Each client used its own proxy endpoint, allowing file selections and decrypted HTTP request/response body lengths and hashes to be counted independently of the CLI counters.

The dataset was written normally, flushed, and measured at **134,217,728 logical bytes and 134,217,728 allocated bytes**. Its SHA-256 was:

~~~text
30c9df269d1bc8900ad2249ecbc03dc6adc8c9019e5101092f82e09baa008611
~~~

Mini published the dataset and source, then imported the dataset into its private cache as a verified independent copy. VPS began with no cached input. Book performed metadata discovery without hydrating the dataset.

The baseline job had no required-worker constraint. Its recorded decision was:

| Candidate | Eligible | Missing selected bytes | Decision |
|---|---:|---:|---|
| Mini: 9a2b78d2-b428-4fe0-bfd7-2878b4d45feb | Yes | 741 | Selected |
| VPS: 9603d12a-de4c-4c77-9dec-a19bf7396a30 | Yes | 134,218,469 | Not selected |

The 741-byte difference is the exact hash source file. The Mini hydration receipt says it reused the dataset and fetched only that source. The Python command observed its own PID 59898 and parent PID 59098; 59098 was the actual Mini worker launched by the harness. Its cwd was inside the selected attempt’s retained run workspace.

The deterministic result was exactly:

~~~json
{"sha256": "30c9df269d1bc8900ad2249ecbc03dc6adc8c9019e5101092f82e09baa008611", "size": 134217728}
~~~

The file contained a final newline, measured **98 bytes**, and had SHA-256 **27a3ddc83f63c3db1a9ff08dafb43fb63c8db33e4f9c61617040106600c28bcc**.

The canonical run succeeded with exit code 0 and retained both exact input identities and its output identity. RunRecord.published remained false, as documented. Publication was independently established by receipt **6fa4a8ee-8d5c-4006-9b51-a1985ee6c06b**, request **249d4731-5474-4500-b32d-1d82189fb3a6**, committed generation **21**, fence **2**. The baseline job was **62047d45-be32-48f6-a3d5-494490c37fe6**, attempt **c3eebf1b-3266-40f3-a425-0d56116b0336**, run **b4b1d800-9ae9-417c-98a9-2eaae0e0b410**.

Evidence: [baseline status and publication](sandbox:/workspace/scratch/05c136f30bb4/critic-managed-execution/main/baseline-status.json), [placement explanation](sandbox:/workspace/scratch/05c136f30bb4/critic-managed-execution/main/baseline-explain.json), [retained file inventory](sandbox:/workspace/scratch/05c136f30bb4/critic-managed-execution/main/mini-worker-inventory.json).

## Independently observed file payload

Whole-dataset body-hash counters were cross-checked against every /v1/file/read selection. This avoids treating a zero whole-body hash match as proof that no partial dataset transfer occurred.

| Client | All file reads during the main run |
|---|---|
| Book | results/hash.json: **98 bytes** |
| Mini | src/hash.py: **741 bytes**; src/sleeper.py: **589 bytes**; data/example.bin: **134,217,728 bytes**, only during the later explicit refetch after cache eviction |
| VPS | None |

Thus Book received **zero dataset payload throughout the main run**, and Mini did **not** download the dataset during baseline execution. Mini’s later 128 MiB download was the deliberately requested cache refetch and is not hidden in the locality claim.

There were 2,121 recorded main-run requests. Control/authentication traffic is separate from file payload; Book’s total response-body traffic, including that metadata, was 726,202 bytes. These are decrypted HTTP body measurements, not TLS wire-byte counts or proof that a remote disk physically persisted data.

Evidence: [raw HTTPS observations](sandbox:/workspace/scratch/05c136f30bb4/critic-managed-execution/main/network.jsonl), [main summary](sandbox:/workspace/scratch/05c136f30bb4/critic-managed-execution/main/summary.json), [baseline network snapshot](sandbox:/workspace/scratch/05c136f30bb4/critic-managed-execution/main/baseline-network.json).

## Failure and recovery observations

### Cancellation

Job **34e0ab2d-58e6-4c80-b203-67820479cc5d** wrote a concrete 55-byte local result and then slept. The cancel response initially reported cancel_requested. The critic waited for the actual terminal cancelled state. The canonical run recorded signal 15, the observed child was no longer alive, and publication remained null.

The pre-cancellation local output survived, with SHA-256 **8d58d4b045c911f59dcfe5f959b2d49b96c35fb28860a688e030ad0b46072522**. No upload or publication of that result appeared in the network log. This tests live cancellation and retained output, not merely acceptance of cancel intent.

### Old publication after worker replacement

The proxy held the real publication request for completed job **d9680a2d-4f2e-4153-886b-62ecf05cb150**, original attempt **4fb40c6f-fdca-4e78-89b1-8b14984377c6**, before forwarding it to the authority. Its output had already been prepared and its real run had succeeded; its publication was still null.

The critic killed worker PID 59098, restarted the same private root as PID 60152, and waited for the new incarnation to be accepted before releasing the held request.

- Old incarnation: **52d54661-aa88-4711-8995-541960f9c882**
- Replacement incarnation: **b3f085f6-f038-4241-b61c-eb1f68f8d8ba**
- New incarnation accepted at Unix time **1792949889.097**
- Held request completed at **1792949889.470738**
- Authority result: **HTTP 409**, conflict, **write lease expired, released or revoked**

The gate did not time out. No additional publication from that original attempt bypassed it. This establishes authority-side rejection; the killed worker did not receive the response.

The old attempt became abandoned with an explicit incarnation-change explanation. Its correct 98-byte output, successful local run, selected sources, and prepared-output identity survived. Explicit retry created attempt **86e3385a-7f98-45f6-92af-51e4138b2363**, moved the fence from **4 to 5**, and succeeded with publication **de5107d9-4b50-47bc-9811-6213e27a929b**. The same exact result bytes were published.

Evidence: [original publication request](sandbox:/workspace/scratch/05c136f30bb4/critic-managed-execution/main/stale-original-publication-request.json), [before-kill status](sandbox:/workspace/scratch/05c136f30bb4/critic-managed-execution/main/stale-before-worker-kill.json), [after-restart status](sandbox:/workspace/scratch/05c136f30bb4/critic-managed-execution/main/stale-after-restart-status.json), [explicit retry result](sandbox:/workspace/scratch/05c136f30bb4/critic-managed-execution/main/stale-explicit-retry-status.json).

### Abrupt loss while a command was running

For job **7d6d009c-acb6-4bff-a68c-7363009287ec**, the critic killed only the running worker daemon. Its already observed child PID **60816** remained alive after the replacement worker started. The authority marked the old attempt abandoned. Exactly one command start was observed before the explicit retry.

The original 53-byte result survived, SHA-256 **15a3eeabc4504324da48c3172aa270d2fc80dd4573a9b50788332d265324ecb9**. Explicit retry produced attempt states **[abandoned, succeeded]**, a distinct new attempt/run, and publication **ca015a17-8d22-42c8-aae9-2205fc0d311d**.

The important limitation is directly observed: the original local run record remains running/unconfirmed, with no finished_at and no enumerated output candidates, while the authority attempt is abandoned. The actual output file remains inspectable. This validates authority reconciliation and deliberate recovery; it does not establish automatic orphan termination, exactly-once external effects, or complete repair of every local run record.

Evidence: [running status before kill](sandbox:/workspace/scratch/05c136f30bb4/critic-managed-execution/main/loss-running-before-kill.json), [recovered job with both attempts](sandbox:/workspace/scratch/05c136f30bb4/critic-managed-execution/main/loss-recovered-status.json).

## Private cache reclamation

After stopping the worker managers, pinning the exact dataset reference caused eviction to fail with exit code 1 and the specific message “selected cache content is pinned.” After unpinning, eviction succeeded with fresh retained-vault verification.

| Measurement | Bytes |
|---|---:|
| Logical cache bytes removed | 134,217,728 |
| Allocated blocks unlinked | 134,217,728 |
| Observed filesystem available-space increase | 134,209,536 |
| Explicit refetch payload | 134,217,728 |

The fresh verification challenge/response and eviction receipt agree. Final cache inspection reports the dataset verified. Its new cache inode differs from the evicted inode. The original data and all retained attempt source/run copies still exist with the exact dataset hash and separate inodes.

The free-space figure is the observed value, 8,192 bytes below 128 MiB; it is not rounded into a stronger physical-reclamation claim. This exercise does not cover every concurrent eviction or unavailable-vault case.

Evidence: [cache before eviction](sandbox:/workspace/scratch/05c136f30bb4/critic-managed-execution/main/cache-before-eviction.json), [cache after verified refetch](sandbox:/workspace/scratch/05c136f30bb4/critic-managed-execution/main/cache-after-refetch.json), [main summary and eviction result](sandbox:/workspace/scratch/05c136f30bb4/critic-managed-execution/main/summary.json).

## Codex and Claude paths: local protocol fixtures only

Both adapters eventually completed real managed-worker attempts through local executables clearly named and labelled LOCAL PROTOCOL FIXTURE. No installed provider executable, provider credential, provider login, paid call, or authenticated model execution was used.

The initial fixture help omitted required capabilities. Public doctor responses were used to correct the fixture help; Claude’s fake advertised version was also raised to the artifact’s stated minimum, 2.1.259. These are corrections to critic-owned fakes, not product fixes or evidence of real CLI compatibility.

| Adapter | Final job | Result |
|---|---|---|
| Codex | d70fa83b-1639-4087-9d2f-6c61f1e47630 | succeeded; 78-byte labelled output; separate publication receipt |
| Claude | d8051baa-6af4-4de5-9dd3-12f297b19863 | succeeded; 79-byte labelled output; separate publication receipt; Book downloaded and verified it |

Actual non-probe invocation arguments were retained. Codex used approval never, exec, workspace-write sandbox, JSON, an explicit run cwd, skip-git-repo-check, and stdin. Claude used restricted, print, stream-json, permission mode dontAsk, permission prompts none, disallowed MCP tools, and only the advertised file tools. The fixtures returned labelled session IDs and deterministic protocol output; these prove the exercised adapter/runner/publication paths only.

The first Codex result pull reused an editable Book root after changing its observation-proxy endpoint and was refused by the target-binding check. Codex publication itself is established by the authoritative receipt and retained output. The subsequent Claude pull used a fresh root and downloaded the 79-byte result. No claim of a successful Codex result download is made.

Evidence: [Codex final status and receipt](sandbox:/workspace/scratch/05c136f30bb4/critic-managed-execution/provider-codex/codex-fixture-final-status.json), [Claude final status and receipt](sandbox:/workspace/scratch/05c136f30bb4/critic-managed-execution/provider-claude/claude-fixture-final-status.json), [actual fixture invocations](sandbox:/workspace/scratch/05c136f30bb4/critic-managed-execution/provider-claude/fixture-invocations.jsonl).

## Exact entry points and reproducibility

The argv arrays, exit codes, stdout, stderr, and durations for short-lived CLI commands are in each evidence directory’s commands.jsonl. Daemon launch arguments and the complete independently written orchestration are retained in the harnesses.

Main successful entry point:

~~~bash
python3 -u /tmp/critic_managed_execution.py
~~~

Its worker/task commands used these variable substitutions; task argv is in the transcript and worker launch argv is in the retained harness:

~~~bash
R=/tmp/critic-managed-execution-dri_4pg7
B=/workspace/scratch/05c136f30bb4/fabric-integration-22c1d52
"$B/maxio-worker" --config "$R/mini.json" --root "$R/mini-worker" --profiles "$R/mini-profiles.json" --display-name "Independent critic mini" --poll-ms 100 --renew-ms 300 --lease-seconds 30
"$B/maxio-worker" --config "$R/vps.json" --root "$R/vps-worker" --profiles "$R/vps-profiles.json" --display-name "Independent critic vps" --poll-ms 100 --renew-ms 300 --lease-seconds 30
"$B/maxio-fabric" --config "$R/book.json" task submit projects --profile hash --input src/hash.py --input data/example.bin --output results/hash.json --publish
"$B/maxio-fabric" --config "$R/book.json" task status 62047d45-be32-48f6-a3d5-494490c37fe6
"$B/maxio-fabric" --config "$R/book.json" task explain 62047d45-be32-48f6-a3d5-494490c37fe6
"$B/maxio-fabric" --config "$R/book.json" workspace pull projects --root "$R/book-work" --path results/hash.json
"$B/maxio-fabric" --config "$R/book.json" task cancel 34e0ab2d-58e6-4c80-b203-67820479cc5d
"$B/maxio-fabric" --config "$R/book.json" task retry d9680a2d-4f2e-4153-886b-62ecf05cb150 --previous-attempt 4fb40c6f-fdca-4e78-89b1-8b14984377c6
"$B/maxio-fabric" --config "$R/book.json" task retry 7d6d009c-acb6-4bff-a68c-7363009287ec --previous-attempt 963102be-8856-42bb-acf8-015e83ae3872
~~~

The provider supplements were invoked as python3 -u /tmp/critic_provider_supplement.py and python3 -u /tmp/critic_claude_supplement.py. Every service lifetime stayed within its uninterrupted escalated loop; all state remained under /tmp. No listeners or workers were carried across sandbox execution boundaries.

Two earlier setup attempts are retained honestly. The first harness had a short 25-second observation window; the second exposed its reserved MAXIO_TEST_* environment names, which the runner correctly refused as storage/configuration variables. The successful harness uses ordinary CRITIC_* observation names. Those setup errors and the initial incomplete provider fixtures are not product defects.

## Evidence hygiene and limits

All services were stopped before copying evidence. A final independent /proc scan across every runtime root and tracked process group found **zero live runtime processes and zero zombie entries**. Every main-run network row has a completion timestamp; no proxy error or gate timeout was recorded. Expected keepalive EOFs occurred when workers were deliberately killed.

A separate measurement review recomputed hashes and lengths for 82 copied retained files and found no mismatch. Large dataset copies were hashed and inventoried rather than duplicated into the evidence package; the deterministic generation code and the original retained /tmp runtime remain available in this session.

The pass is deliberately bounded to the observed cases. Active coordinator-loss fencing, interrupted uploads/downloads, ambiguous finish/publication acknowledgments, hostile same-UID races, physical host/disk loss, real-provider authentication, and WAN/device behavior were not established by this critic. Resource declarations remain admission hints, native commands remain owner-trusted, and the vault remains a single server-filesystem copy.

Evidence index: [main harness](sandbox:/workspace/scratch/05c136f30bb4/critic-managed-execution/main/independent-harness.py), [main command transcript](sandbox:/workspace/scratch/05c136f30bb4/critic-managed-execution/main/commands.jsonl), [cleanup verification](sandbox:/workspace/scratch/05c136f30bb4/critic-managed-execution/cleanup-verification.json), [artifact manifest](sandbox:/workspace/scratch/05c136f30bb4/critic-managed-execution/artifact.json).
