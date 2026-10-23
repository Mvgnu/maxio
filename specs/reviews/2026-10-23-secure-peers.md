# Secure peers and revocable sessions — Gauntlet, 2026-10-23

This wave reopens the native peer identity and copied-session stops from the
[recovery review](2026-10-23.md). Its first independent round found an incoming
certificate-name defect despite passing local and hosted gates. That round is
recorded below. The defect has a scoped implementation repair and live TLS
regressions, but the platform blocked the independent second-round certificate
probe before execution. **Transport review remains blocked; the PR stays draft.**
The repaired release passed independent console, runtime and HTTPS sync rechecks.

## Artifacts and independence

| Field | First reviewed artifact |
|---|---|
| Published code commit | `007ff86cee11600ecbadfc4b404a4617d7c47a5f` |
| Source tree | `c6d3e7c2319dfaec609f276274f78e52239cb240` |
| Local integration commit with that tree | `afe280cc53974cc9f2d3c0d99fe55fc638d8c6c9` |
| Platform | Linux 6.18.55 x86_64, glibc 2.39, OpenSSL 3.0.13 |
| Build | Rust 1.94.0, Bun 1.3.10, locked dependencies, optimized release |
| `maxio` SHA-256 | `359082f994c5bdbcda1e6a2b4c7fa2d507cef1e7588806a5f25ee49f0a1f9e1c` |
| `maxio-sync` SHA-256 | `05ce4de8ff043f22f27e30aeee88c936a1d115a233fb2c69600be21a363be239` |

The release build started at local commit `1082d49982e92c8d6f6653febca0c4facf4dab18`.
The sole intervening change corrected the secure process drill's health-response
selection; Rust, manifests and UI inputs were identical to the published tree.
Frozen copies were hashed before review and retained separately from build caches.

| Field | Repaired release artifact (v2) |
|---|---|
| Local build source commit | `90af486cee0f268964db8b83dfef495a837657da` |
| Build source tree | `87ac0f035d8cee4d5f9d3319e973031de8f616b2` |
| Platform/toolchain | Same as v1 above |
| `maxio` SHA-256 | `137e3947cf855eee64701209bbcdd5a7203a48f90ebc0501ba6292868db390ea` |
| `maxio-sync` SHA-256 | `719c751d8cd6bda21c5d0b8f45d722c49ff4e8e53c93f09fc731bfbcde1ca76c` |

After freezing v2, the only Rust change rewrote a test assertion to satisfy
Clippy; production inputs stayed identical. Subsequent specification/review
updates also do not change binary inputs. Console and operator critics checked
both the supplied hashes and the hashes after their live runs.

Three fresh critics received the specs, external bars, binaries and disposable
setup instructions, with no builder reports or historical review context. They
ran native processes and inspected responses, TLS connections, file bytes and
journals. They did not fix implementation. Reference documentation was consulted;
Garage, Syncthing, AWS S3 and pytest were not executed as competing products.
The console and operator critics then rechecked v2 without builder reports.

## First-round verdicts

| Domain or journey | Verdict | Exact scope |
|---|---|---|
| `cluster_transport_security` | **gap** | Incoming DNS/IP SAN did not have to match the host in an otherwise valid MaxIO URI. |
| `runtime_platform` | **pass**, operator scope | Documented standalone/HTTPS/peer startup, readiness, failure and restart. Does not override the transport gap. |
| `console_api` | **pass**, session scope | Logout rejects copied cookies, independent sessions survive, restart invalidates old sessions; native Secure cookies and socket-IP throttling. |
| `s3_api_surface` | **pass**, exercised contract | HTTPS forwarding/framing, standalone failed preconditions and races, explicit rejection of distributed conditions. |
| `device_sync` | **pass**, HTTPS scope | Conflict preservation, interrupted transfer safety, trust failures and recovery through the selected standalone peer. |
| `quality_harness` | **pass**, negative contracts | Invalid domain, missing/invalid spec, ownership expansion/violation and empty test selection fail visibly. |
| Onboarding and smoothing | **pass**, operator scope | Three distinct documented modes, no undocumented source/configuration repair. |

Storage internals, metadata internals, signing internals and rendered console UI
were not independently re-graded as whole domains in this wave. Their prior
records and limits remain; a changed transport adapter is not a new blanket pass.

## Transport: the gap and the connection evidence

Reference: [RFC 8446, certificate authentication](https://www.rfc-editor.org/rfc/rfc8446#section-4.4.3).
Property: an untrusted sender cannot gain internal authority by copying headers
or claiming another node. The connection carrying the operation must prove the
expected identity, with the independent DNS/IP SAN requirements in the system
contract.

### Largest gap, reproduced twice

A trusted-CA client leaf had the allowed URI `maxio://127.0.0.1:<peer-port>` but
only IP SAN `127.0.0.2`. It possessed the corresponding private key. The receiving
node accepted its join with HTTP 200 and `authorized:true`, then accepted a signed
internal replication PUT with HTTP 200. A subsequent ordinary read contained the
attempted replacement bytes rather than the prior object. A second disposable
run with fresh ports reproduced both results.

Controls mattered: the correct peer certificate succeeded, no certificate returned
403, and a same-host certificate for another port returned 403. The mismatched leaf
also failed local MaxIO startup with an IP-address-mismatch error before creating
storage. Thus the defect was specifically incoming SAN validation, not token-only
authentication or acceptance of an incorrect URI. This is why the first transport
round is a gap even though its other connection tests passed.

### Repair and blocked second-round judgment

The builder added a regression using real TLS connections. Before the repair,
all six missing/mismatched host-SAN cases were admitted: DNS, IPv4 and IPv6, each
with the correct MaxIO URI. The original failing run is retained in the tool
transcript; no standalone failing-run log exists. The missing DNS SAN fixture
has a matching common name, so it also detects accidental common-name fallback.

The repair requires OpenSSL's standard DNS/IP name check before constructing an
incoming `VerifiedPeerIdentity`. DNS checks disable subject/common-name fallback;
IP checks use parsed network-order address bytes. This adds no parallel hostname
matcher. The fixed live TLS regression rejects all six cases before reading an
HTTP request, while valid DNS, IPv4, IPv6, case-insensitive DNS and wildcard DNS
controls succeed. The scoped cluster suite passed 166 tests. These are builder
and integration checks, not a substitute for independent artifact judgment.

The independent critic prepared its original join/replication probe for v2, with
the new binary path/hash, rejected-connection handling, valid-peer controls and
reads through both peers to verify preserved bytes. When the PM authorized the
run, the platform rejected the critic's turn for possible cybersecurity risk and
required additional account security setup. No v2 identity-test output or process
evidence was produced. The probe and supplied secure-peer drill were not rerun by
that critic, nor reassigned to bypass the block.

**PM stop:** retain `blocked` for the repaired transport artifact and keep the PR
draft. The remaining acceptance is an independent observation that the previously
accepted inconsistent-SAN certificate cannot authorize a join or mutate an object,
with original bytes still readable through both peers. Ordinary valid-peer
operation passed the separate v2 operator review, but cannot answer this question.
No inference of a Gauntlet pass is made from the code change or automated gates.

### Completed outgoing observations

The critic replaced only its disposable peer endpoint with a controlled TLS test
server and observed application requests on that endpoint:

| Offered server identity | Client result | Observed HTTP at the test endpoint |
|---|---|---|
| Correct CA, IP SAN and full node URI | 200 | One request carrying the expected 12,852 bytes. |
| Same host, different port in URI | 503 on two attempts | Zero HTTP requests; TLS failed. |
| Correct identity, then wrong URI on the next connection | 200, then 503 | The first 18,249-byte request reached only the correct-identity connection. |
| Foreign CA, exact URI | 503 | Zero HTTP requests; TLS failed. |
| Correct CA/URI, wrong IP SAN | 503 | Zero HTTP requests; TLS failed. |

The real peer was then restored and its original bytes checked. A test server's
200 response establishes connection/payload behavior, not storage durability.
These observations show that outgoing checks were attached to the connection
carrying the request, rather than a separate preflight.

The platform security gate interrupted the critic's turn after this original
experiment had written a complete log, final result and cleanup marker. A later
read-only inspection recovered that completed evidence. No blocked experiment was
retried. Further outgoing experiments are not claimed.

The critic also ran the checked-in secure-peer drill against the frozen binary:
two owners and two acknowledgements, ordinary clients without peer certificates,
token/SigV4/claim/CA controls, revocation, outage/restart, isolated persisted copies,
dedicated-route isolation, handshake expiry and shutdown.

## Console sessions

Reference: [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).
Property: a copied cookie loses protected access after logout while independent
sessions remain usable. The critic made 69 requests over verified native TLS 1.3.

Four same-account logins produced distinct cookies. After logging out session A,
all twelve copied-cookie replays returned 401 with the same unauthenticated JSON.
They covered identity, listings, download, diagnostics, bucket creation/deletion,
object creation/replacement/deletion and logout. Independent B, C and D remained
usable. Reads confirmed rejected mutations had not changed stored bytes or bucket
membership; an attempted new object remained absent.

A real process restart used the same data directory. All four old cookies failed,
including the three active immediately before restart. A fresh login recovered
the exact 65,814-byte and 4,864-byte objects.

Login cookies retained `HttpOnly; SameSite=Strict; Secure` under missing, forged
`http`, mixed and empty forwarded-proto values. Logout retained `Secure` and set
`Max-Age=0`. After ten attempts from one socket IP, changing `X-Forwarded-For`,
`X-Real-IP` and `Forwarded` did not evade 429. A genuinely different loopback source
IP could log in even while claiming the blocked address. Existing authenticated
access remained usable while new logins were throttled.

No browser/UI, seven-day elapsed expiry, session-capacity, live credential-change,
in-flight logout-race, internal token-storage or full OWASP-compliance verdict is
claimed. This pass is based on subsequent admission through the tested routes.

The console critic repeated the same independent 69-request drill against frozen
v2: 27 responses were 200, 38 were 401, one was 404 and three were 429, all matching
their expected cases. Copied-cookie and restart rejection, unaffected independent
sessions, exact bytes, Secure attributes and socket-IP throttling all passed. The
binary hash was unchanged afterward. The **console session verdict is pass on v2**;
the exclusions above still apply.

## Runtime, S3 and onboarding

Runtime reference: [Garage quick start](https://garagehq.deuxfleurs.fr/documentation/quick-start/).
S3 reference: [AWS conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html).

A fresh operator started standalone storage with only credentials, address, port
and data directory. Installed curl SigV4 support created a bucket, transferred
binary bytes and recovered them after restart. Generic native HTTPS required only
its certificate/key pair. AWS CLI and MinIO Client were unavailable, so their exact
README commands were not exercised.

The operator extracted and executed the unchanged OpenSSL certificate-generation
block in the secure-peer journey and ran the two documented node commands on free
ports 9101 and 9102. Both public HTTPS endpoints worked without client certificates;
a write reported two acknowledgements. No undocumented configuration/source edit
was required.

With one peer stopped, aggregate health remained HTTP 200 but reported `ok:false`,
`status:degraded`, `metadataListReady:false`, `peerConnectivityReady:false` and a
missing node. It returned in approximately 0.011 seconds. Complete listing and
strict-quorum PUT returned 503. Restart restored readiness and access. This matches
the README instruction to inspect readiness fields rather than HTTP status alone.
Invalid/partial TLS, a mismatched key, required mode without a token and generic TLS
combined with peers exited 1 before storage creation. Normal shutdowns exited 0.

Separately, signed PUT/HEAD/GET through both owners reused HTTP/1.1 connections
with correct response framing: empty PUT responses advertised zero body bytes,
HEAD advertised object length without a body, and GET returned exact bytes.
Distributed conditional attempts returned 501 and preserved both copies, including
an absent object remaining absent. Standalone failed conditions returned 412 and
preserved bytes. Four-client create and update races each had one 200 and three
412 responses; winner bytes survived restart.

The independent operator repeated standalone HTTP/HTTPS and the unchanged secure
peer certificate/start commands against v2. Two acknowledgements, exact reads,
degraded peer-down health, 503 listing/strict writes, recovery and all four invalid
startup cases passed. The peer-down health response took approximately 0.0115
seconds. No undocumented repair was needed. **Runtime and onboarding pass on v2**
within these cases; this does not judge the inconsistent-SAN scenario. The detailed
S3 framing/condition races above remain v1 evidence, not a claimed v2 rerun.

## HTTPS device synchronization

Reference: [Syncthing synchronization and conflicts](https://docs.syncthing.net/users/syncing.html).
Property: differing edits and interrupted transfers preserve both contents, and
fresh processes can retry safely without a cloud coordinator.

The documented HTTPS drill passed thirteen fresh client invocations, including
nested/Unicode files, wrong-CA rejection, conflicts, peer/client restart, offline
journal invariance, recovery and additive restoration.

An independent two-client race changed both folders from the same baseline to
different 1,966,080-byte contents. Initial exits were 1 and 0: the losing client
reported a 412 and instructed retry. Subsequent runs preserved both content
digests as main file and conflict sibling and converged both folders.

For interruption, a transparent tunnel forwarded opaque TLS bytes to the actual
native server and cut a 14,000,000-byte object's download after 1,059,494 encrypted
bytes. The client exited 1 with premature EOF. Every local file and state-file
digest, including the journal, remained identical. After peer restart and a fresh
client invocation, the complete expected replacement arrived and prior bytes
remained in history. The final audit matched journal digests to actual files.

Wrong CA on an existing baseline, missing trust and hostname mismatch failed safely.
Empty/invalid/unreadable bundles and HTTP plus `--ca-cert` failed before state
creation. This establishes safe retry, not partial block-level download resumption.
A fake endpoint ignoring conditions was not independently exercised in this round.

For v2, the operator reran the checked-in HTTPS sync drill with the new binary pair
and inspected its retained folders and journals. All thirteen fresh client runs
passed. Both folders held the A edit as the main file and the B edit as the same
conflict sibling; all four file hashes matched between folders, and every journal
hash matched its local file. **HTTPS sync passes this v2 recheck.** The separate
large-transfer interruption and simultaneous-client race above were performed on
v1 and were not repeated on v2.

## Harness judgment

Reference: [pytest exit-code contract](https://docs.pytest.org/en/stable/reference/exit-codes.html).
Property: missing or invalid work must fail visibly rather than return a green
no-op. All adversarial mutations were confined to a disposable repository copy.

| Negative case | Observed result |
|---|---|
| Misspelled domain | Exit 2, unknown domain. |
| Missing spec | Exit 1, inventory mismatch. |
| Missing external-bar property | Exit 1, missing `bar.property`. |
| Device-sync edit to runtime | Exit 1, outside write gate. |
| Unowned Rust source | Exit 1, exactly one owner required. |
| Domain expands its own scope | Exit 1, PM review required. |
| Empty test selection | Exit 1, no tests selected. |

The empty-selection case used a controlled Cargo stand-in returning
`0 tests, 0 benchmarks` to the real runner. It did not compile/enumerate a real Rust
inventory. The clean architecture gate passed before and after these cases, and
all seven enforcement regressions passed. Actual positive Rust enumeration belongs
to the PM integration gate below.

## End-of-wave review disposition

| Scope | Current verdict | Evidence boundary |
|---|---|---|
| Native peer identity | **blocked** after repair | V1 exposed the incoming SAN gap. Builder regressions pass, but the independent v2 join/mutation recheck was blocked before execution. |
| Runtime/operator | **pass**, v2 | Simple HTTP/HTTPS, documented peers, two acknowledgements, readiness, outage/restart and invalid startup. |
| Console sessions | **pass**, v2 | The repeated 69-request independent native HTTPS drill met the copied-cookie and related session property. |
| HTTPS device sync | **pass**, v2 recheck | Thirteen fresh clients plus actual file/journal inspection; larger interruption/race evidence remains v1. |
| S3 framing/conditional boundary | **pass**, v1 scope retained | Both forwarding owners, keep-alive framing, explicit unsupported conditions and standalone races; no claimed detailed v2 rerun. |
| Quality harness | **pass**, v1 scope retained | Negative enforcement scenarios and clean baseline; no harness implementation changed in the SAN repair. |
| Onboarding/smoothing | **pass**, v2 operator paths | No undocumented configuration/source repair; this does not waive the blocked identity review. |

The PM stops further identity probing under the platform restriction. This is a
recorded review stop, not acceptance of the remaining uncertainty. The draft PR
contains the repair and the successful independent scopes; native peer identity
must not be advertised as independently cleared on v2. The original recovery
review remains historical evidence, including the console gap now superseded by
the observed live-session passes here.

## Integration evidence and scope boundaries

To reproduce the full gate and then run the checked-in process drills against a
release build (after installing the README prerequisites):

```bash
python3 scripts/run_checks.py all
cargo build --release --locked --bins
python3 scripts/smoke_standalone.py --binary target/release/maxio
python3 scripts/smoke_peer_s3.py --binary target/release/maxio
python3 scripts/smoke_secure_peers.py --binary target/release/maxio
python3 scripts/smoke_device_sync.py --binary target/release/maxio \
  --sync-binary target/release/maxio-sync
python3 scripts/smoke_device_sync.py --binary target/release/maxio \
  --sync-binary target/release/maxio-sync --tls
```

The PM full gate builds the UI before both binaries and runs the process drills
against its selected Cargo target directory. Critics used explicit absolute paths
to separately frozen release binaries. Their additional experiments used independent
clients; the scenarios and observed bytes/statuses above define those comparisons.
These are local disposable-process exercises, not production traffic.

The first code tree passed `python3 scripts/run_checks.py all`: 1,513 Rust tests,
45 Bun tests with 269 expectations, seven architecture tests, formatting, checks,
both Clippy gates, UI/binary builds and all five process drills. Its clean-checkout
[hosted CI run](https://github.com/Mvgnu/maxio/actions/runs/39940258933) also passed.
The independent incoming-SAN gap remained a gap despite those gates.

After the repair and the test-only lint correction, the full integration gate
passed again: **1,515 Rust tests, 45 Bun tests with 269 expectations, seven
architecture regressions, both Clippy gates, formatting/checks, UI and binary
builds, and all five real process drills**. No test was skipped. The first repaired
gate attempt caught a conditional unwrap in the new test; it was rewritten as a
match, without suppressing a lint or changing production behavior.

Local test compilation used one build job, one test codegen unit, disabled debug
symbols and disabled incremental compilation after local compiler/linker failures,
including a zero-byte object file. Hosted CI used the checked-in workflow normally.
The independent blocked review remains blocked despite the repaired gate passing.

The three operator modes remained distinct: one standalone S3 process; explicit
secure storage peers; optional folder sync through a selected standalone bucket.
None required a cloud service. The review does not establish WAN reachability,
automatic pairing, NAT traversal, IAM grants, consensus, complete AWS compatibility
or power-loss durability. Data/sidecar replacement is not a complete crash-atomic
transaction. Sessions are node-local; separate internal listener addresses lack a
per-peer control-endpoint map. Sync remains additive and transfers regular files
whole. These boundaries remain in the authoritative specs.
