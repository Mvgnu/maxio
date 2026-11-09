# Managed onboarding follow-up: readable task logs

## Verdict

**The first-round human-readable log gap is closed by the documented `--text` command on artifact `8f120ac548a2b78a6b37d95f43299814affe204a`.** I executed the updated guide's command against the original retained hash job and received its readable stdout directly. No external decoder, product change, or undocumented configuration workaround was required for that operation.

Default JSON output remained usable, including transfer metadata, `data_base64`, byte offsets, `next_offset`, and `eof`. A separate actual command job exercised two stdout pages, nonempty stderr, offsets, and exact byte preservation at the retained-page boundary.

The first-round assessment and its evidence remain unchanged. That version had an actual documentation/CLI gap; this follow-up records closure on the new artifact rather than retroactively changing the first-round result. This is a narrow log follow-up, not a rerun of the full managed journey on the new build.

## Artifact and review boundary

| Item | Exact observation |
|---|---|
| Source commit | `8f120ac548a2b78a6b37d95f43299814affe204a` |
| Artifact directory | `/workspace/scratch/05c136f30bb4/fabric-integration-8f120ac/` |
| `maxio-fabric` SHA-256 | `d9bda8729905ce69885ad0f3bf44662f6b98d0f009ef350a5129da5262bbee28` |
| `maxio-worker` SHA-256 | `8108d2d6ec9e7074d63e688a7eab41af0c6daf08e9aac128df49403d931fe6fc` |
| Hash verification | Both executed binaries matched the supplied `artifact.json`. |
| Sources read | Updated `managed_fabric_usage.md`, `task logs --help`, and the artifact manifest; runtime outputs and this review's own retained evidence. |
| Excluded | Builder implementation, builder tests/reports, Cargo, model calls, external services, and provider credentials. |

The updated guide now uses `book task logs JOB_UUID --attempt ATTEMPT_UUID --text` and explicitly explains default JSON, the 64 KiB page limit, subsequent `--offset` requests, `--stderr`, and retained-output rather than live-follow behavior. Help advertises `--text` and the default JSON/pagination distinction.

I safely reopened the stopped disposable authority at `/tmp/maxio-managed-onboarding.GfQSIf/authority` using the new fabric binary, its existing private-CA configuration, and `https://127.0.0.1:41593`. Certificate verification stayed enabled. The diagnostic worker and all new runtime data used fresh `/tmp` directories. Every process was stopped and waited for before completed evidence was copied to this review directory.

## Original documented job: readable output now works

Original job: `f461619e-fddb-497d-8541-ba56cc515d9f`.

Original attempt: `7da952cb-2031-41b6-8036-10c0b0039f64`.

With `MAXIO_FABRIC_BIN` pointing to the new artifact and the existing documented `book()` helper:

```bash
book task logs f461619e-fddb-497d-8541-ba56cc515d9f \
  --attempt 7da952cb-2031-41b6-8036-10c0b0039f64 --text
```

The command returned exactly 44 stdout bytes, including the final newline:

```text
Hashed 1048576 bytes on the selected worker
```

Its exit code was zero. The retained job still reported `succeeded`. Omitting `--text` returned the ordinary JSON envelope, and decoding its `data_base64` for reviewer comparison produced the same 44 bytes. The human-readable inspection itself required no decoding step.

| Request | Returned bytes | `next_offset` | `eof` | Observation |
|---|---:|---:|---|---|
| Original stdout, offset 0 | 44 | 44 | true | Direct readable text matches the original log and default JSON. |
| Original stdout, `--offset 7` | 37 | 44 | true | Exact suffix starting with `1048576`; both output modes agree. |
| Original stdout, `--offset 44` | 0 | 44 | true | Clean end-of-file behavior, without an added newline or envelope in text mode. |
| Original `--stderr` | 0 | 0 | true | The separate empty error stream remains empty in both modes. |

Raw evidence is in `observed-8f120ac-logs/retained-log-and-real-job/`, particularly the `original-stdout`, `original-offset-7`, `original-at-eof`, and `original-stderr` response pairs and comparison JSON files.

## Actual two-page output and separate stderr

To verify pagination with real retained output, I used the documented owner-configured command-profile fields to start one fresh Mini worker root with a `log-probe` profile. Its installed absolute Python executable emitted a controlled large stdout stream and a distinct stderr stream, then created `results/log-probe.txt`. The exact profile is saved with the evidence.

The actual submission was:

```bash
book task submit projects --profile log-probe \
  --input src/hash.py --output results/log-probe.txt
```

This diagnostic task omitted `--publish`; it succeeded and retained its output locally, with no publication receipt. Job ID: `82f31fbe-bf06-405c-8973-4fe0a660da95`; attempt ID: `11a64bf5-6a6e-43f1-b1bd-7a19ac397778`.

For every following request, I executed both ordinary JSON and `--text`, compared their bytes, and compared the reconstructed data with the saved local run log:

| Stream/request | Returned bytes | `next_offset` | `eof` | Result |
|---|---:|---:|---|---|
| stdout, offset 0 | 65,536 | 65,536 | false | First page matches byte-for-byte. |
| stdout, offset 65,536 | 4,466 | 70,002 | true | Second page matches; concatenation exactly reproduces the retained stdout log. |
| stdout, offset 70,002 | 0 | 70,002 | true | Correct EOF response. |
| stderr, offset 0 | 22 | 22 | true | Correct separate error stream, including its embedded NUL. |
| stderr, offset 4 | 18 | 22 | true | Correct byte suffix from the error stream. |
| stdout, offset 69,995 | 7 | 70,002 | true | Offset begins inside a UTF-8 sequence; text output still preserves the retained bytes exactly, beginning `bf bd 54 41 49 4c`. |

The JSON responses preserved their transfer metadata. The text commands added no JSON envelope or extra stdout bytes and emitted no CLI stderr. Full reconstructed stdout was 70,002 retained bytes, with SHA-256 `6816551fd9dba9ccfb7ebc6cfe1db2858bce59ac05d638662205e9937ca696b5`. The retained stderr SHA-256 was `c9f9e6f265a88470a8a9f23700675acfcd93b1014848a4d05db8997e5534ffff`.

Detailed responses and hashes are in `observed-8f120ac-logs/pagination/`; its `summary.json` records the complete successful comparison.

## Separate genuine limitation: native invalid UTF-8 is normalized in saved logs

The diagnostic program deliberately emitted one invalid byte (`ff`) in each native stream. Before I compared CLI log output, the local retained stdout and stderr files already contained the UTF-8 replacement-character bytes `ef bf bd` at those positions. The native stdout was designed to be 70,000 bytes and the stored stdout was 70,002; native stderr was 20 bytes and stored stderr was 22. Embedded NUL bytes survived.

My first probe harness asserted that emitted native bytes and saved logs were identical and therefore stopped after the successful job. Its cleanup stopped both processes. That assertion and the observed mismatch are preserved in the evidence. I then reopened only the authority and completed the appropriate documented comparison: `--text` versus the exact retained log-page bytes. Every such comparison passed, including an offset inside the replacement character.

This is a separate limitation of the saved log representation, not a failure of `--text` to preserve its returned page. The follow-up does not claim lossless capture of arbitrary binary child streams. Binary artifacts should be treated as output files rather than assumed to survive through logs unchanged. No upstream runner change was made or investigated during this review.

## Evidence and conclusion

- `assessment.md` and `observed-20261025T1729/` preserve the first-round gap.
- `observed-8f120ac-logs/combined-summary.json` records this follow-up's final verdict and both observation sets.
- `observed-8f120ac-logs/retained-log-and-real-job/` contains artifact verification, updated help/guide evidence, the readable original job, the actual diagnostic job, and the initial native-byte comparison.
- `observed-8f120ac-logs/pagination/` contains the completed page/offset/stderr comparisons and final process-stop record.

The original onboarding requirement is now satisfied by the documented command. Default JSON remains useful for automation and pagination; `--text` provides direct inspection of the same retained bytes. The scope remains a local, verified-TLS, retained-output follow-up, with the native invalid-UTF-8 limitation explicitly preserved.
