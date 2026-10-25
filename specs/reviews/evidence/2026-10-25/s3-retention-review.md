# Independent standalone S3 retention rejection review

## Verdict: bounded pass

No meaningful gap was reproduced for the requested property. The frozen MaxIO executable explicitly rejected all **186 signed unsupported Object Lock, retention, and legal-hold request variants**. Every rejection preserved the observed object bytes and ETags, existing versions and version listing, bucket set and versioning configuration, and active multipart upload and part state. The data directory's file inventory, file sizes, and SHA-256 digests were unchanged across each rejection.

This is a pass for explicit rejection with preservation in ordinary standalone S3. It is not a claim that MaxIO implements retention enforcement or full S3 compatibility.

## Artifact and environment

- Tested executable: `/workspace/scratch/05c136f30bb4/s3-retention-f70e5f8/maxio`
- SHA-256: `df9106d087399ceb19f8d2415ee3378e7d215783263f321a0e4eb7613663f982`
- Test date: 2026-10-25 UTC
- Independent test directory: `/workspace/scratch/05c136f30bb4/critic-s3-retention`
- Actual run directory: `run-20261025T163740Z`
- Mode: one process, standalone, HTTP on a disposable `127.0.0.1` port; fresh isolated data directory and fresh test credentials.
- The HTTP health response identified standalone mode.
- Test process was stopped after completion.

The assessment used the executable's actual HTTP responses and persisted files. It did not rely on source changes or a builder's report. No Cargo invocation, implementation modification, provider/model call, peer cluster, or peer-certificate experiment was performed.

## Reference bar

The AWS [Object Lock guide](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html) describes retention and legal holds as protections on object versions. The [PutObjectRetention API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectRetention.html) uses a `PUT` request with the `retention` subresource and optional `versionId`, carrying retention configuration XML. Those references were opened during the review. For this unsupported feature, the required property is that such an operation fails explicitly and does not turn its XML into an ordinary object write or otherwise mutate storage.

## Actual evidence

An ordinary initial `PUT /critic-plain/item` stored `b'original ordinary object\x00\xff\n'` with HTTP 200 and ETag `"88910ffc34fe4517cc368970fc72508d"`. A normal GET returned the identical bytes.

A correctly signed request with the standard retention XML and its valid Content-MD5:

```http
PUT /critic-plain/item?retention=
Content-MD5: k0zZIcptDoSdLFuFvnGuNQ==

<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Mode>COMPLIANCE</Mode><RetainUntilDate>2035-01-01T00:00:00Z</RetainUntilDate></Retention>
```

returned HTTP **501** with XML error code **NotImplemented** and the message:

> S3 Object Lock, retention periods and legal holds are not supported

The request left the original bytes and ETag unchanged, created no extra object or version, and changed no data-file content or size.

The same request directed to an existing version, `PUT /critic-versioned/item?retention=&versionId=1792946261067716-0d6dc643`, also returned 501. Both stored versions remained accessible with their original bodies, IDs, and ETags:

| Version | Body | ETag |
|---|---|---|
| `1792946261067716-0d6dc643` | `version one\n` | `"dd8f100298ff923592ab35dc15788abc"` |
| `1792946261071393-e2e5108e` | `version two\n` | `"223deef93d3131e3705ab44c2cd042f9"` |

An active multipart upload, ID `55aa5047-7fc8-4780-a78d-49a38a039837`, had one original part with ETag `"1c4e7263fd2d9561ef652a0c3b2dbd46"`. Unsupported operations aimed at initiation, replacement of that part, completion, and abortion all returned 501 and preserved its state. After the entire rejection matrix and another process restart, the ordinary completion request succeeded with HTTP 200. The completed object downloaded as the original `b'original multipart part\n'` and had multipart ETag `"a90576b97b217357d2cce85fae66e6b0-1"`.

## Coverage

**66 query cases** exercised each of `retention`, `legal-hold`, and `object-lock`:

- GET, HEAD, PUT, POST, and DELETE against an existing ordinary object.
- PUT against a specific existing version and a previously absent object.
- Bucket configuration PUT, attempted new-bucket creation, and DELETE of an existing empty bucket.
- Bare subresource, empty value, nonempty value, percent-encoded query-key character, a preceding unrelated query, and repeated subresource parameters.
- Combination with multipart initiation, upload-part replacement, completion, and abortion.
- Combination with multi-object deletion, object copy, and a versioning-configuration change.

**120 header cases** exercised ten header/value combinations over twelve mutation targets each:

- `x-amz-bucket-object-lock-enabled`: `true`, `false`.
- `x-amz-object-lock-mode`: `COMPLIANCE`, `GOVERNANCE`, and an empty value.
- `x-amz-object-lock-retain-until-date`: a future date.
- `x-amz-object-lock-legal-hold`: `ON`, `OFF`.
- `x-amz-bypass-governance-retention`: `true`, `false`.

The twelve targets were ordinary object PUT, versioned object PUT, ordinary object DELETE, specific-version DELETE, new-bucket creation, empty-bucket DELETE, object copy, multipart initiation, upload-part replacement, completion, abortion, and multi-object deletion. The HTTP client normalizes header capitalization, so this review does not claim a separate arbitrary-wire-casing test.

All 186 cases returned 501. Every response that can contain a body carried the `NotImplemented` error code; HEAD responses correctly contained no body.

## Preservation and ordinary-operation controls

Before and after each rejected request, the test collected eleven signed API observations: bucket listing, ordinary object listing, original object and copy destination, version listing, current and both explicit versions, versioning configuration, multipart upload listing, and multipart part listing. The status, ETag when supplied, and SHA-256 of each response body stayed identical. It also compared every data-file path, byte length, and SHA-256 digest.

Ordinary controls succeeded before the unsupported-request matrix: bucket creation, binary object upload/download, versioning enablement, two versioned writes, multipart initiation and part upload, and restart with the same data directory. After the matrix, a second restart preserved the baseline, ordinary completion of the original multipart upload succeeded, and an ordinary object overwrite/download succeeded. These controls show that explicit unsupported-operation failures were not the consequence of a broken server or unusable S3 fixture.

There were **4,337 signed requests** in the complete trace, including preservation reads and ordinary-operation controls. The process exited successfully; the summary reports 186 checks and zero failures.

## Reproduction and files

From an environment that permits loopback listeners:

```bash
python3 /workspace/scratch/05c136f30bb4/critic-s3-retention/probe.py
```

The script uses only the Python standard library, starts the exact frozen executable, creates a new timestamped run directory, records results, and stops its process in a `finally` block.

- `probe.py`: independent SigV4 fixture and complete runnable matrix.
- `run-20261025T163740Z/summary.json`: all 186 outcomes, explicit-rejection results, preservation results, and any data-file differences (none).
- `run-20261025T163740Z/requests.jsonl`: complete request labels, methods, paths, queries, application headers and payloads, HTTP status, response headers, and response payloads. Credentials and Authorization signatures are not recorded. Binary bodies in the human-readable trace use UTF-8 replacement; the running checks compared the original bytes and SHA-256 digests.
- `run-20261025T163740Z/server.log`: process output from all three starts.
- `run-20261025T163740Z/data/`: retained disposable test storage.

The finite matrix covers the specified ordinary standalone S3 request surface. It does not establish atomicity under power loss, concurrent external writers, or behavior of another build. No broader defect is asserted without reproduced evidence.
