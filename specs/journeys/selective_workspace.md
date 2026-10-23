# Selective workspace: M1a acceptance

The artifact is the built `maxio-workspace` CLI against a real standalone MaxIO
process. Three separate local roots represent MacBook, Mac Mini and VPS on one host;
this is a process simulation, not a test on physical devices or a WAN.

## Acceptance property

Against [Rclone copy](https://rclone.org/commands/rclone_copy/): discover all published
files without fetching payloads, pull one directory, and publish selected edits while
unrelated payload bytes remain untransferred and stale/dirty writes are rejected.

## Required exercise

1. Start ordinary standalone S3 with an explicit temporary data directory. Create
   a bucket using an ordinary signed S3 client. No peers or execution configuration.
2. Create source/config files plus an actual 128 MiB dataset under Mac Mini root.
3. Initialize a workspace and publish explicit paths. Capture JSON revision and
   transfer counters, including verification traffic. Retain all source bytes.
4. From empty MacBook and VPS roots, refresh and list. Both discover the dataset
   with zero payload downloads and no local dataset file.
5. Pull only source/config from MacBook. Verify exact files and no dataset/unrelated
   directory. Pull a dataset only from the explicitly selected root.
6. Edit one source file; publish only that file. Refresh/pull on another client.
   Read the previous revision explicitly and verify its old bytes remain available.
7. Compete from a stale base: exactly one manifest update wins. Verify the loser
   keeps working and staged bytes. Refresh does not erase its baseline conflict.
8. Dirty a destination then request pull: refuse overwrite and preserve dirty bytes.
9. Stop/restart the server and CLI. Observe metadata/pins/local baselines persist.
   A disconnected operation fails without deleting local or global data.
10. Exercise interruption during download/publication and an absent/corrupt blob.
    Prior content or staged work remains; incomplete bytes never become hydrated.
11. Request eviction: refuse explicitly because retention/durability is not enforced.
    Confirm every byte remains. This is a safety refusal, **not disk reclamation**.
12. Run standalone Journey A after the wave. No workspace or agent configuration
    may be required by the server.

## Honest boundaries

Report payload application bytes and metadata bytes separately; exclude HTTP/TLS
framing and SDK retries from these counters. The fixed test size is a real transfer,
not a claim that 40 GiB or physical three-machine operation has been measured.

Full Journey B remains open at durable eviction, device authentication, offline
reconciliation/deletion and recovery. CAS is not a write lease: Journey C is still
planned. No scheduler/remote worker is demonstrated here: Journey D is still planned.

The fresh critic runs the artifact and reports one largest gap against the property.
A separate onboarding critic uses README and these instructions alone. Record actual
commands, sizes, platform, commit and unresolved failures in `specs/reviews/`.
