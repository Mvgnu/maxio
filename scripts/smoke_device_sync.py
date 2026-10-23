#!/usr/bin/env python3
"""Exercise the built MaxIO server and maxio-sync companion as real processes.

Two ordinary folders synchronize through an explicitly chosen loopback S3 peer.
This drill covers restart, conflicting edits, offline failure and recovery. It
does not establish WAN transport security, NAT traversal, deletion propagation,
or Syncthing feature parity. Only Python's standard library is required.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import uuid

from smoke_peer_s3 import Node, S3, expect, list_keys


def snapshot(folder, include_state=False):
    """Compare actual file bytes, optionally including the durable journal."""
    return {
        path.relative_to(folder).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in folder.rglob("*")
        if path.is_file()
        and (include_state or path.relative_to(folder).parts[0] != ".maxio-sync")
    }


class SyncProcess:
    def __init__(self, binary, endpoint, bucket, env, root):
        self.binary = binary
        self.endpoint = endpoint
        self.bucket = bucket
        self.env = env
        self.root = root
        self.invocations = 0

    def once(self, folder, should_succeed=True):
        # Each call starts a fresh process, so successful later calls must load
        # their baseline from disk instead of relying on process memory.
        self.invocations += 1
        command = [
            str(self.binary),
            "--local", str(folder),
            "--endpoint", self.endpoint,
            "--bucket", self.bucket,
            "--prefix", "shared",
            "--once",
        ]
        result = subprocess.run(
            command, env=self.env, capture_output=True, text=True, timeout=45,
        )
        log = self.root / f"sync-{self.invocations:02d}-{folder.name}.log"
        log.write_text(
            f"exit={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}",
            encoding="utf-8",
        )
        if should_succeed:
            if result.returncode != 0:
                raise AssertionError(
                    f"sync {folder.name} failed (see {log}): {result.stderr[-2000:]}"
                )
            try:
                report = json.loads(result.stdout)
            except json.JSONDecodeError as error:
                raise AssertionError(f"sync did not emit one JSON report: {log}") from error
            for field in ("uploaded", "downloaded", "unchanged", "conflicts"):
                if not isinstance(report.get(field), int) or report[field] < 0:
                    raise AssertionError(f"invalid sync report field {field}: {report}")
            return report
        if result.returncode == 0:
            raise AssertionError("offline peer incorrectly produced a successful sync")
        return None


def run(binary, sync_binary, keep_data):
    root = Path(tempfile.mkdtemp(prefix="maxio-device-sync-smoke-"))
    reservation = socket.socket()
    reservation.bind(("127.0.0.1", 0))
    port = reservation.getsockname()[1]
    env = {
        key: value for key, value in os.environ.items()
        if not key.startswith(("MAXIO_", "MINIO_"))
        and key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}
    }
    env.update({
        "MAXIO_ACCESS_KEY": "device-smoke-access",
        "MAXIO_SECRET_KEY": uuid.uuid4().hex,
        "MAXIO_MIN_DISK_HEADROOM_BYTES": "0",
        "RUST_LOG": "warn",
        "NO_PROXY": "127.0.0.1,localhost",
    })
    node = Node(binary, root, "peer", port, 0, env)
    client = S3(port, env["MAXIO_ACCESS_KEY"], env["MAXIO_SECRET_KEY"])
    bucket = "device-sync-smoke"
    runner = SyncProcess(sync_binary, client.endpoint, bucket, env, root)
    folders = [root / "device-a", root / "device-b"]
    for folder in folders:
        folder.mkdir()
    a, b = folders
    success = False
    try:
        reservation.close()
        node.start(clustered=False)
        expect(client.request("PUT", f"/{bucket}"), 200, "create sync bucket")

        (a / "work").mkdir()
        unicode_key = "work/café + #%.txt"
        (a / unicode_key).write_bytes(b"initial device A bytes\n")
        (a / "notes.txt").write_bytes(b"shared original\n")
        if runner.once(a)["uploaded"] != 2:
            raise AssertionError("first device did not upload both local files")
        if runner.once(b)["downloaded"] != 2 or snapshot(a) != snapshot(b):
            raise AssertionError("second device did not receive identical ordinary files")
        expected_keys = {f"shared/{key}" for key in snapshot(a)}
        if list_keys(client, bucket) != expected_keys:
            raise AssertionError("peer keys differ or a capability probe was left behind")
        print("PASS: two ordinary folders exchange identical nested and Unicode files")

        node.stop()
        node.start(clustered=False)
        (a / unicode_key).write_bytes(b"updated after peer and client restart\n")
        if runner.once(a)["uploaded"] != 1 or runner.once(b)["downloaded"] != 1:
            raise AssertionError("persisted baseline did not distinguish a one-sided update")
        if (b / unicode_key).read_bytes() != (a / unicode_key).read_bytes():
            raise AssertionError("updated file differs after restart")
        if runner.once(b)["unchanged"] != 2:
            raise AssertionError("an unchanged restarted client did not retain its baseline")
        print("PASS: real peer/client restarts retain bytes and baseline; one-sided edits propagate")

        (a / "notes.txt").write_bytes(b"device A independent edit\n")
        (b / "notes.txt").write_bytes(b"device B independent edit\n")
        runner.once(a)
        if runner.once(b)["conflicts"] != 1:
            raise AssertionError("independent edits were not reported as one conflict")
        conflicts = list(b.glob("notes.txt.maxio-conflict-*"))
        if len(conflicts) != 1 or conflicts[0].read_bytes() != b"device B independent edit\n":
            raise AssertionError("the local side of the conflict was not preserved visibly")
        if (b / "notes.txt").read_bytes() != b"device A independent edit\n":
            raise AssertionError("the peer's main file was overwritten during conflict resolution")
        runner.once(a)
        if snapshot(a) != snapshot(b):
            raise AssertionError("conflict sibling did not reach both devices")
        print("PASS: concurrent edits survive as main file plus a shared conflict sibling")

        node.stop()
        (a / "offline").mkdir()
        (a / "offline" / "new.txt").write_bytes(b"created with peer offline\n")
        before = snapshot(a, include_state=True)
        runner.once(a, should_succeed=False)
        if snapshot(a, include_state=True) != before:
            raise AssertionError("offline sync changed local bytes or advanced the journal")
        print("PASS: an unavailable peer returns failure without changing local files or journal")

        node.start(clustered=False)
        if runner.once(a)["uploaded"] != 1 or runner.once(b)["downloaded"] != 1:
            raise AssertionError("offline edit did not transfer after peer recovery")
        if snapshot(a) != snapshot(b):
            raise AssertionError("devices disagree after recovery")

        # Lock the intentionally additive deletion policy: one removed copy is
        # restored; removal is never silently propagated to the other device.
        (b / "offline" / "new.txt").unlink()
        if runner.once(b)["downloaded"] != 1 or snapshot(a) != snapshot(b):
            raise AssertionError("a missing copy was not restored under additive sync")
        print("PASS: recovery transfers offline changes; missing copies are restored without deletion propagation")
        print(json.dumps({
            "result": "pass", "devices": 2, "peer_servers": 1,
            "files": len(snapshot(a)), "fresh_client_processes": runner.invocations,
            "cloud_services": 0,
        }))
        success = True
    finally:
        reservation.close()
        node.stop()
        if success and not keep_data:
            shutil.rmtree(root)
        else:
            print(f"Smoke data, sync journals and process logs: {root}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/debug/maxio"))
    parser.add_argument("--sync-binary", type=Path, default=Path("target/debug/maxio-sync"))
    parser.add_argument("--keep-data", action="store_true")
    args = parser.parse_args()
    binary, sync_binary = args.binary.resolve(), args.sync_binary.resolve()
    for executable in (binary, sync_binary):
        if not executable.is_file():
            parser.error(f"build both binaries first; executable not found: {executable}")
    run(binary, sync_binary, args.keep_data)


if __name__ == "__main__":
    main()
