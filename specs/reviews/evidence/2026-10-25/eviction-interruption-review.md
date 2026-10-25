# Independent E review: process death after cache unlink starts

## Verdict

**PASS for this precise process boundary on frozen artifact `8f120ac`.** Two complete captures observed an actual cache-object deletion before the final index commit. Each capture established a saved pending eviction intent, both missing and surviving objects, confirmed process termination, safe offline reconciliation, unchanged authoritative files, and exact selective refetch.

This review is separate from the earlier selective workspace/private-cache pass in `review.md`. It closes the previously unobserved mid-unlink process boundary only; it does not claim all Journey E failures were exercised.

## Artifact and command

- Source commit: `8f120ac548a2b78a6b37d95f43299814affe204a`.
- Binary: `/workspace/scratch/05c136f30bb4/fabric-integration-8f120ac/maxio-fabric`.
- Independently calculated binary SHA-256: `d9bda8729905ce69885ad0f3bf44662f6b98d0f009ef350a5129da5262bbee28`.
- Platform: Linux 6.18.55 x86_64, glibc 2.39, Python 3.12.14.
- Completed command:

```bash
python3 /workspace/scratch/05c136f30bb4/critic-managed-cache/interrupted_eviction.py \
  --fabric-binary /workspace/scratch/05c136f30bb4/fabric-integration-8f120ac/maxio-fabric \
  --evidence /tmp/maxio-critic-eviction-8f120ac
```

The command exited zero with **28 checks passed**, **28 CLI commands**, and **596 independently observed HTTPS requests**. Reproduction requires a new empty evidence path. Socket access and signalling the test's own child ran within one narrowly scoped escalated test process. All runtime data remained under `/tmp`; completed evidence was copied into the workspace only after authority and observation servers stopped.

### Source dependencies for a checkout rerun

Keep `interrupted_eviction.py` and its critic-owned helper `critic.py` together in the same directory: the driver imports `Journey`, `digest` and `find_dict` from that helper. Exact completed-run copies are preserved in `eviction-interruption/`. These two files are the complete test source; there is no dependency on the repository's smoke scripts, internal implementation modules or builder harnesses.

The experiment requires Python 3 (tested with 3.12.14), the OpenSSL command-line executable on `PATH`, an already built `maxio-fabric`, and Linux libc exposing `inotify_init1`/`inotify_add_watch`. It uses Python standard-library modules only. The account must be able to bind local TCP sockets, signal its own child processes, and create private files under the chosen temporary directory. SIGSTOP/SIGKILL, `waitpid` stopped-child reporting, inotify and Unix inode/allocation attributes make this a **Linux-specific experiment**.

From a checkout, point `--fabric-binary` at that checkout's built binary and run the preserved driver from wherever the two source files were saved together. The driver creates its own CA, server leaf, keys, authority, workspaces and cache. It does not require existing accounts, credentials, data, environment configuration or any product-code modification.

## Method

The critic created and published 256 individually distinct 4,096-byte files, then hydrated those exact references into a private cache. This is 1 MiB of payload, and each eviction selection respects the documented 256-reference retention-verification limit. Verified inventory and independent SHA-256 checks established all 256 initial objects.

Before starting an ordinary public-CLI `cache evict --confirm` child, the driver installed a Linux inotify watch for `IN_DELETE` on that cache's object directory. On observing a deletion of a known cached object, it immediately sent **SIGSTOP to that exact child PID** and used `waitpid(..., WUNTRACED)` to confirm the child was stopped. While the child was stopped, the driver read the real saved cache state and enumerated and hashed the real object files. It then sent SIGKILL and waited for the child's `-9` termination result.

There were no product hooks, implementation edits, implementation reads, Cargo invocations, or synthetic intent/state injection. The observer inspected only its own runtime files. The cache state was never edited by the driver.

## Captured boundaries

| Evidence | Cycle 1 | Cycle 2 |
|---|---:|---:|
| Eviction child PID | 62557 | 62719 |
| Confirmed stopped by `waitpid` | Yes; status 4991 | Yes; status 4991 |
| Actual `IN_DELETE` events before stop | 1 | 1 |
| Actual absent cache objects | 1 | 1 |
| Actual surviving cache objects | 255 | 255 |
| Entries still in saved index at stop | 256 | 256 |
| Entries in saved pending intent | 256 | 256 |
| Child termination result | `-9` / SIGKILL | `-9` / SIGKILL |
| Index entries after first offline reopen | 255 | 255 |
| Pending intent after first offline reopen | `null` | `null` |
| Additional survivors removed by either reopen | 0 | 0 |
| Exact refetch response count | 1 | 1 |
| Exact refetch payload bytes | 4,096 | 4,096 |
| Verified entries after refetch | 256 | 256 |

The captured pending operation IDs were:

- Cycle 1: `74b10ed8-2dfe-4059-82d0-9608988f4e7f`.
- Cycle 2: `04d83662-ad42-4e68-82be-8c93cf7c548c`.

The saved full index plus a real missing object and a non-null full pending intent establishes the requested boundary: unlink had occurred, and the final index commit had not occurred. This was captured twice without relaxing that assertion.

## Recovery observations

For each cycle, two separate **offline** `cache inspect --verify` processes reopened the cache. Neither made an HTTP request. Both retained exactly the same 255 surviving object names, SHA-256 values, sizes, inodes, link counts and allocated-byte counts observed while the eviction child was stopped. Inventory advertised exactly those present verified objects. The first reopen reconciled the saved index to 255 entries and cleared the pending intent; the second made no further deletion.

The authoritative catalog, including its exact head and manifest, was identical as parsed JSON to the pre-eviction catalog and still contained all 256 logical files. Original workspace source files retained their hashes. A distinct unpublished sentinel outside `cache/objects` retained its bytes through both process deaths, reopens and refetches.

Each subsequent `cache hydrate` read exactly **one 4,096-byte file body** from the authority, independently counted at the HTTPS observation proxy. Its body SHA-256 was:

`0037707b0817c09286785ad07ec2fcc55b2266aa59f2bdb887ef47853c3c1b9c`

That was the exact missing object's original SHA-256. The resulting cache again contained all 256 exact objects, with all 255 surviving inodes and hashes unchanged. Final verified inventory advertised all 256 files. The second interruption began from that fully recovered cache and reproduced the same safe behavior.

## Evidence locations

All paths are under `/workspace/scratch/05c136f30bb4/critic-managed-cache/eviction-interruption/`:

- `interrupted_eviction.py` and `critic.py`: exact driver and critic-owned HTTPS/setup helper used for the completed run.
- `cycle-1-interruption.json` and `cycle-2-interruption.json`: watcher events, signal/wait evidence, actual absent/survivor identities, and complete before/stopped object measurements.
- `cycle-1-state-stopped.json` and `cycle-2-state-stopped.json`: saved pending intents and full uncommitted indexes captured while each child was stopped.
- `cycle-*-state-before.json` and `cycle-*-state-reopened-*.json`: state before eviction and after each offline recovery.
- `commands.json`, `checks.json`, `http-events.json`: command outcomes, all assertions, and independent HTTP byte/hash observations.
- `filesystem-evidence.json` and `preserved/`: completed runtime file measurements and copies, excluding private key files.
- `artifact.json` and `run-metadata.json`: provenance, independent binary hash and completed run totals.

## Limits

This is a process-death and reopen test on one host. It does not establish power-loss/fsync behavior, disk failure protection, remote physical redundancy, hostile concurrent replacement, every possible instruction-level interruption point, or other untested Journey E cases. No eviction receipt was fabricated from the killed commands; their stdout was empty and their actual exit status was SIGKILL.

For the observed boundary, recovery reconciled only the deletion already performed. It preserved every survivor, kept global logical files intact and refetched exactly the missing immutable bytes. No gap was observed within this precise property.
