# Independent managed selective workspace and private cache review

## Verdict

**PASS, bounded to the requested managed Journey B workspace/cache subset on the frozen artifact below.** I found no product gap in the exercised selection, dirty-baseline preservation, explicit delete/restore, guarded cache reclamation, and interrupted-refetch recovery behavior. This is an independently observed process verdict, not an inference from unit tests or builder reports.

The completed run passed **31 checks**, executed **65 CLI commands**, and recorded **246 HTTPS requests**. Ten commands intentionally returned failure for a conflicting or unsafe action. The runner exited zero. The authority and all observation proxy processes shut down before evidence was copied from `/tmp`.

## Artifact and environment

- Source commit: `22c1d523e25a390650dff1b8ddec41c1c277e3e9`.
- Binary: `/workspace/scratch/05c136f30bb4/fabric-integration-22c1d52/maxio-fabric`.
- Independently calculated binary SHA-256: `1d6d171f43a5388a94e3534ef53c1a2086bb8ab6129ce7ed5cc13122890db00b`.
- Platform: Linux 6.18.55 x86_64, glibc 2.39; Python 3.12.14 test driver. Artifact metadata labels the binary a debug build with Rust 1.94.0.
- Three separately generated Ed25519 device keys, separate enrolled identities, separate editable roots, and a separate private cache root on **one host**. These are local processes representing Book, Mini and VPS, not three physical machines.
- One authority with verified ordinary HTTPS, a disposable CA and separate server leaf certificate. Each client uses its own TLS observation proxy; each proxy verifies the upstream authority TLS certificate. The managed device key is independent of the transport certificate.
- Runtime data stayed under `/tmp/maxio-critic-managed-cache-22c1d52-round2` throughout one uninterrupted escalated test process. No live runtime files were read by a second tool sandbox.
- No Cargo, repository edits, provider calls, provider credentials, worker command execution, or historical blocked incoming-PEER certificate experiment.

The authority vault retains one copy on its local server filesystem. This review does not establish remote physical redundancy or survival of loss of that host or disk.

## External comparison property

The official [rclone copy documentation](https://rclone.org/commands/rclone_copy/) describes copying selected source content without deleting destination-only files. The comparison here is explicit selection and absence of unrelated transfer or implicit deletion, not a performance benchmark.

The official [Syncthing versioning documentation](https://docs.syncthing.net/users/versioning.html) describes archiving old remotely changed versions when versioning is configured; it is off by default. Its [synchronization documentation](https://docs.syncthing.net/users/syncing.html) describes preserving divergent changes as conflict copies and retaining temporary files after interrupted synchronization. The comparison here is recoverable divergent/versioned bytes, not identical conflict policy or full feature parity. Neither competitor was executed.

## Reproduction

The completed command was:

```bash
python3 /workspace/scratch/05c136f30bb4/critic-managed-cache/critic.py \
  --fabric-binary /workspace/scratch/05c136f30bb4/fabric-integration-22c1d52/maxio-fabric \
  --evidence /tmp/maxio-critic-managed-cache-22c1d52-round2
```

Use a new empty evidence path to repeat it; the driver deliberately refuses to reuse an existing test root. Socket creation is denied by the ordinary tool sandbox, so the actual run used the loopback-only escalated execution capability.

The driver generates its own TLS materials, keys and deterministic non-sparse dataset; it imports no builder harness. It starts a real authority and three separate HTTPS observation endpoints. It records decoded HTTP body lengths and SHA-256 values independently of the CLI transfer counters. Request bodies, sessions and private keys are not copied into the report.

## Observed evidence

| Property | Actual observation |
|---|---|
| Real dataset | 134,217,728-byte file; 134,217,728 allocated bytes in the completed run. SHA-256 `31e3c26fd85e14c0282fb6a573d2e4267a93392a54a0e2224738dfb0aef7c421`. |
| Selected publication | Initial upload carried exactly four selected file bodies: 134,217,728, 60, 50 and 32 bytes. The unselected private local file was absent from the authoritative catalog. |
| Metadata discovery on all three devices | Each refresh reported zero payload and observed only authentication/control HTTP endpoints. Each response total was 2,590 metadata bytes; no `/v1/file/read` request occurred. Book and VPS still had no `docs`, `src` or `data` directory. |
| Select one directory | Book and VPS each received exactly two payload bodies, 60 and 50 bytes, matching the selected `docs/` files. CLI totals and independently counted HTTP bodies both equaled 110 bytes. `src/` and `data/` remained absent. |
| Entire Book journey | Book's only file reads throughout all publication conflicts, refreshes, delete and restore operations remained those original 60- and 50-byte bodies. Its dataset remained absent. |
| Divergent work | Book made a unique unpublished edit; Mini published a different version. Metadata refresh kept Book dirty. Selected pull refused replacement, and selected publish refused the mismatching baseline. The exact Book bytes survived each refusal. |
| Restart recovery | With authority stopped, offline `workspace status --verify` still reported the Book file dirty. After restarting the same authority, refresh did not change the file and publication remained explicitly rejected. |
| Clean stale replacement | VPS's original clean baseline became `stale` after observing Mini's new version. A selected pull installed the new exact version. An already open descriptor could still write the prior inode, and the new late bytes were found under `.maxio-workspace/history/`. |
| Explicit logical deletion | An explicit `workspace delete ... --confirm` removed the authoritative path. Book's dirty bytes and VPS's clean historical bytes remained on disk. Status retained the historical reference and showed dirty/stale respectively; VPS's pin remained visible. Republishing the removed baseline was refused. |
| Exact restore | Explicit restore with the pre-deletion revision UUID and manifest hash reintroduced the exact prior file version. VPS's matching baseline became clean; a deliberate new edit then published successfully. Offline unpin of the deleted retained path also succeeded. |
| Missing directory is not deletion | Mini removed its local `src/` directory and published only an edited guide. The authoritative `src/main.py` and dataset remained present. |
| Private cache import | Import made a separate verified inode: source inode 526828, cache inode 538943. It downloaded no file body. Offline verified inventory advertised the exact dataset. |
| Pin protection | Pinned eviction returned `selected cache content is pinned`; the complete dataset hash remained unchanged. |
| Offline retention | With authority stopped, eviction failed, and offline cache reopen still preserved the complete dataset. |
| Fresh exact vault verification | With the exact authority vault body temporarily renamed out of its logical location, eviction returned `fresh retained-vault verification unavailable; local cache preserved`. The local cache and the temporarily displaced authority bytes both retained the original hash. The test then restored the authority file to its original location. |
| Successful reclamation | Unpinned verified eviction removed the selected cache object. Receipt: 134,217,728 logical bytes removed, 134,217,728 allocated bytes unlinked. The object was physically absent after the command. |
| Unrelated bytes survive reclamation | The source dataset, Book's dirty edit and a 74-byte unpublished sentinel under `attempts/<uuid>/` retained their exact bytes/hashes. The sentinel is a test file, not a claimed real worker output. |
| Interrupted refetch | Proxy deliberately cut the dataset response after 2,097,152 bytes. The command failed and named a retained private partial stage. Offline reopen succeeded. That 2 MiB file remained after the successful later refetch, with the same SHA-256 as the observed partial HTTP body. |
| Exact refetch | The next hydrate received exactly 134,217,728 bytes, and the HTTP body hash and resulting cache file hash both matched the original dataset SHA-256. Verified inventory advertised the recovered exact content. |
| Hardlink protection | After successful refetch, a deliberately created hardlink caused eviction to fail with `cache object has a hardlink alias; preserve it`; both links retained the exact bytes. |
| Changed-content protection | In a separate small cache root, a same-file local edit caused eviction to fail with `cache content changed; preserve it`. Reopen reported `modified`, advertised no cached content, and preserved the edited SHA-256. |

### Reclamation measurement

The independently measured cache object's allocation before eviction was 134,217,728 bytes. The receipt reported the same allocation unlinked and the object was absent afterward. The observed filesystem available-space increase was **106,213,376 bytes**, from 21,542,977,536 to 21,649,190,912. Other work shared this filesystem; I therefore do not attribute the exact free-space delta solely to this eviction. Logical removal, object allocation removal and observed free space are separate measurements.

### Concrete retained bytes

- Book dirty edit SHA-256: `5a9d6a7530b8a0670933003194680a923e2ccb9eaf2f511f8cf0cb2d0656826b`.
- Late-descriptor history file: `data/vps-work/.maxio-workspace/history/a9237b77-e939-4624-8619-521f27870112.data`; 68 bytes; SHA-256 `6684ffa775a7e58ff6fe73c102c15d360231135a67bc470985472fd4e45b8f60`.
- Unpublished sentinel: `data/mini-private-cache/attempts/a61382d6-5036-44f9-a1ae-0c720816c597/unpublished-output.bin`; 74 bytes; SHA-256 `0ee7b4f72ceac4fa93558d341260620ffd100ffb48ccde7b0067cf2f256b418f`.
- Retained partial stage: `data/mini-private-cache/cache/staging/990f7665-125a-4e23-b8c7-7c4276b7bbe3/payload`; 2,097,152 bytes; SHA-256 `88b32a40b822da24d2aa1c93b8dc81657328c116ddabadbcd74ebcdfd1d79a21`.
- Deliberately modified small cache object SHA-256: `2b6419d2ea690793f5089191af7af9b25f445970a95cc18471b35c77dbdcd8ec`.

## Evidence files

All paths below are under `/workspace/scratch/05c136f30bb4/critic-managed-cache/`:

- `critic.py`: reproducible independent test driver.
- `round2/critic.py`: exact driver snapshot used by the completed run.
- `round2/commands.json`: each CLI invocation, exit status, stdout, stderr and elapsed time.
- `round2/http-events.json`: independent HTTP request/response byte observations and response hashes.
- `round2/checks.json`: all 31 assertions and concrete supporting values.
- `round2/filesystem-evidence.json`: post-shutdown file sizes, allocations, link counts, inodes and SHA-256 values.
- `round2/preserved/`: small state, receipts, editable/history bytes and the unpublished sentinel, copied after shutdown. Large data files are represented by their measured identities and reproducible generation in the driver; private key files are omitted.
- `round2/artifact.json` and `round2/run-metadata.json`: artifact provenance and independent binary hash.
- `round2/authority.log`: process log.

`round1/` retains the initial driver attempt for transparency. That attempt deliberately added and removed a hardlink before the ordinary eviction check, invalidating the saved inode fingerprint. The product correctly refused subsequent eviction. The driver had incorrectly expected the fingerprint to revert after alias removal. The completed run moved that destructive probe after the normal eviction/refetch sequence and used fresh roots with the **same binary**. No product fix or implementation change occurred between these attempts.

## Boundaries of this pass

This review exercises the requested selective workspace/private cache portion of Journey B, plus the concrete disconnect/restart and partial-refetch recovery above. It does not certify all of Journeys C, D or E.

I did not execute a worker or provider profile, claim an active attempt guard, kill a process during the cache unlink/intent commit itself, inject storage-full/fsync failure, test lost publication acknowledgments, or test physical-machine/WAN behavior. No claim is made about automatic eviction recovery after an interrupted unlink, power-loss durability, host/disk redundancy, hostile same-UID writers, full Syncthing functionality or rclone performance.

The observed refusal paths retain bytes, and the successful reclaim/refetch path recovers the exact immutable dataset while the Book never receives it. Those observations satisfy the bounded selection and preservation property assigned to this critic.
