---
description: Build, independently judge the running product against an external bar, repeat
---

# Gauntlet: the quality loop

Green compilation and tests are admission to judgment. They do not show that an
operator can run one S3 server, use two peers, or synchronize a folder safely.
[Lop](lop.md) keeps builders isolated. Gauntlet checks the result.

## The bar and the artifact

Every domain spec names an external reference and one concrete compared property.
Product journey specs define the user-visible cross-domain bar. Compare the exact
property, not every feature of the reference and not a vague overall impression.

MaxIO's artifact is the built binary operating on disposable real data, plus its
embedded console and the optional `maxio-sync`, `maxio-workspace` and `maxio-agent`
executables. A static export cannot prove server persistence, authorization,
replication, or synchronization. Do not
copy a web-only review recipe into this repository.

| Surface | What the critic must inspect |
|---|---|
| Standalone S3 | Real signed client requests, data after restart, failed writes, response framing |
| Storage | Actual bytes and metadata after interrupted/rejected writes, version/path boundaries |
| Peer S3 | Two real processes, visibility through either peer, peer outage/restart, durability diagnostics |
| Transport | Live accepted/rejected requests and documented TLS boundary, not certificate flag names |
| Metadata | Complete/missing peer responses, listing continuity and honest unavailable states |
| Console API | Live login/session and bucket/object operations with unauthorized controls |
| Console UI | Served embedded page at mobile and desktop sizes, actual bucket/file task, network requests |
| Device sync | Two ordinary folders, changed bytes, simultaneous edits, stopped peer/restart, conflict copies |
| Workspace catalog | Metadata-only discovery, measured selected transfers, exact revisions, competing publications, interrupted transfers |
| Workspace cache | Actual baselines and retained bytes, dirty/stale state, offline pins, failed replacement, explicit eviction outcome |
| Local execution | Actual child process, selected input copies, terminal records, logs, cancellation and retained unpublished outputs; fixtures distinguished from authenticated providers |
| Harness | Deliberately invalid ownership/spec/test selection must fail, clean checkout must run |

## Review loop

1. PM states a small goal and bar. Builder implements within its Lop bubble.
2. Spawn a **fresh critic with no builder history**. Supply the goal, spec, bar,
   artifact location, start command, and disposable test data. Do not supply the
   builder's report, rationale, or prior claimed test results.
3. Critic inspects the actual artifact. If it cannot start/reach it, the round is
   **blocked**, with the command and failure recorded; it cannot pass on a diff.
4. Critic reports the single largest gap for that domain/journey, with observed
   behavior and a repeatable scenario. The critic never edits implementation.
5. Builder addresses that gap. Repeat without a fixed round count. Stop on an
   argued pass, diminishing useful improvement, or an explicit PM stop decision.
6. A fresh smoothing review combines the affected user journeys, including the
   ordinary standalone server, and checks terminology, commands, defaults, failures
   and the handoffs between them. A local workspace/agent handoff does not establish
   remote worker dispatch or data-locality scheduling.
7. At a milestone, a fresh operator follows only the README and journey specs in
   disposable directories. Every undocumented code/configuration edit needed is
   an onboarding failure. They must not repair the product while reviewing it.

Blind comparisons are useful for console usability when possible. Protocol and
data-loss properties need adversarial experiments against the published reference
contract. Do not claim a competitor was executed if only its documentation was read.

## Review record

Write `specs/reviews/<date>[-<wave>].md` with artifact commit, platform, commands, reference
URL/property, observed evidence, single largest gap, and verdict for each reviewed
domain. Verdicts: `pass`, `gap`, `blocked`, or `not-reviewed`. A pass must explain
why the observed behavior meets the stated property. A PM stop records the remaining
gap and its consequence in the relevant spec. No invented percentages of completion.

Review evidence belongs in the dated record; specifications state current contracts.
Do not append a changelog to the product spec. Never mark unobserved domains passed.

## Known boundaries to test before reporting

Native HTTPS and peer TLS must be judged on live connections: a correct shared
token without a client certificate must fail internal authorization, and a
same-host certificate for another port must not satisfy identity checks. Preserve
ordinary S3/console access to the public HTTPS listener. A two-process loopback
exercise does not prove internet reachability, NAT traversal or WAN partition
recovery. Record encryption only after exercising actual verified TLS connections.
The sync MVP has explicit peers and no deletion propagation. It is not a full
Syncthing replacement. Verify current capabilities rather than repeating this list
after implementation changes.

## Done

Domain checks, full checks, architecture checks, built artifacts, satisfied spec,
and an independent argued pass on the requested scope; or a PM stop with the exact
remaining gap recorded. "Tests passed" alone is never a product verdict.
