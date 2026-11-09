#!/usr/bin/env python3
"""Observe a real mid-eviction process death, with no product hooks.

Uses the critic-owned ordinary HTTPS setup and public CLI from critic.py. Runtime
state inspection is confined to disposable roots, in the one owning test process.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import struct
import subprocess
import time
import traceback
import uuid

from critic import Journey, digest, find_dict


IN_DELETE = 0x00000200
IN_Q_OVERFLOW = 0x00004000


class EvictionJourney(Journey):
    def check(self, name, condition, **evidence):
        self.checks.append({"name": name, "pass": bool(condition), "evidence": evidence})
        self.save()
        print(json.dumps({"check": name, "pass": bool(condition)}), flush=True)
        if not condition:
            raise AssertionError(name)

    def objects(self, cache):
        result = {}
        for path in sorted((cache / "cache/objects").iterdir()):
            if path.is_file():
                st = path.stat()
                result[path.name] = {"size": st.st_size, "sha256": digest(path),
                                     "inode": st.st_ino, "links": st.st_nlink,
                                     "allocated": st.st_blocks * 512}
        return result

    def read_state(self, cache):
        return json.loads((cache / "cache/state.json").read_text())

    def inotify(self, cache):
        libc = ctypes.CDLL(None, use_errno=True)
        libc.inotify_init1.argtypes = [ctypes.c_int]
        libc.inotify_init1.restype = ctypes.c_int
        libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        libc.inotify_add_watch.restype = ctypes.c_int
        fd = libc.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
        if fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1")
        watch = libc.inotify_add_watch(fd, os.fsencode(cache / "cache/objects"), IN_DELETE)
        if watch < 0:
            os.close(fd)
            raise OSError(ctypes.get_errno(), "inotify_add_watch")
        return fd

    @staticmethod
    def drain_events(fd):
        events = []
        while True:
            try:
                data = os.read(fd, 65536)
            except BlockingIOError:
                break
            offset = 0
            while offset < len(data):
                watch, mask, cookie, length = struct.unpack_from("iIII", data, offset)
                offset += 16
                name = data[offset:offset + length].split(b"\0", 1)[0].decode()
                offset += length
                events.append({"watch": watch, "mask": mask, "cookie": cookie, "name": name})
        return events

    def interrupt_one(self, cache, refs, cycle):
        label = f"cycle-{cycle}-evict-interrupted"
        before = self.objects(cache)
        state_before = self.read_state(cache)
        (self.out / f"cycle-{cycle}-state-before.json").write_text(json.dumps(state_before, indent=2))
        self.check(f"cycle-{cycle}-starts-with-complete-clean-index", len(before) == 256
                   and len(state_before["entries"]) == 256 and state_before["pending"] is None)
        fd = self.inotify(cache)
        args = [self.binary, "--config", str(self.root / "mini.json"), "cache", "evict",
                "--root", str(cache), "--references", str(refs), "--confirm"]
        stdout_path = self.out / f"cycle-{cycle}-evict.stdout"
        stderr_path = self.out / f"cycle-{cycle}-evict.stderr"
        self.label = label
        http_start = len(self.events)
        launched_ns = time.monotonic_ns()
        stdout_file = stdout_path.open("w")
        stderr_file = stderr_path.open("w")
        process = subprocess.Popen(args, stdout=stdout_file, stderr=stderr_file)
        observation = {"cycle": cycle, "eviction_pid": process.pid,
                       "launched_monotonic_ns": launched_ns, "initial_object_count": len(before),
                       "inotify_events": []}
        try:
            deadline = time.monotonic() + 120
            captured = False
            while time.monotonic() < deadline:
                ready, _, _ = select.select([fd], [], [], 0.25)
                if ready:
                    events = self.drain_events(fd)
                    observation["inotify_events"].extend(events)
                    if any(e["mask"] & IN_Q_OVERFLOW for e in events):
                        raise AssertionError("inotify queue overflow: cannot prove the event boundary")
                    if any(e["mask"] & IN_DELETE and e["name"] in before for e in events):
                        observation["first_delete_observed_monotonic_ns"] = time.monotonic_ns()
                        os.kill(process.pid, signal.SIGSTOP)
                        observation["sigstop_sent_monotonic_ns"] = time.monotonic_ns()
                        waited_pid, status = os.waitpid(process.pid, os.WUNTRACED)
                        observation["waitpid"] = waited_pid
                        observation["wait_status"] = status
                        observation["confirmed_stopped"] = os.WIFSTOPPED(status)
                        if not os.WIFSTOPPED(status):
                            raise AssertionError("eviction completed before SIGSTOP; boundary unobserved")
                        observation["inotify_events"].extend(self.drain_events(fd))
                        captured = True
                        break
                if process.poll() is not None:
                    break
            if not captured:
                raise AssertionError("no reproducible mid-eviction stop was captured; boundary unobserved")

            stopped_state = self.read_state(cache)
            stopped_objects = self.objects(cache)
            absent = sorted(set(before) - set(stopped_objects))
            survivors = sorted(set(stopped_objects))
            pending = stopped_state.get("pending")
            observation.update({"pending_operation_id": pending.get("operation_id") if pending else None,
                                "pending_entry_count": len(pending.get("entries", {})) if pending else 0,
                                "saved_index_count_at_stop": len(stopped_state.get("entries", {})),
                                "absent_count_at_stop": len(absent), "survivor_count_at_stop": len(survivors),
                                "absent_keys": absent, "survivor_keys": survivors,
                                "objects_before": before, "objects_stopped": stopped_objects})
            (self.out / f"cycle-{cycle}-state-stopped.json").write_text(json.dumps(stopped_state, indent=2))
            (self.out / f"cycle-{cycle}-interruption.json").write_text(json.dumps(observation, indent=2))
            self.check(f"cycle-{cycle}-actual-unlink-before-index-commit", pending is not None
                       and len(pending["entries"]) == 256 and len(stopped_state["entries"]) == 256
                       and 0 < len(absent) < 256 and len(survivors) + len(absent) == 256,
                       operation_id=observation["pending_operation_id"], absent_count=len(absent),
                       survivor_count=len(survivors), saved_index_count=len(stopped_state["entries"]))
            self.check(f"cycle-{cycle}-stopped-survivors-retain-original-bytes",
                       all(stopped_objects[key] == before[key] for key in survivors))
            os.kill(process.pid, signal.SIGKILL)
            returncode = process.wait(timeout=10)
            observation["terminated_returncode"] = returncode
            self.check(f"cycle-{cycle}-evict-child-killed-while-stopped", returncode == -signal.SIGKILL)
            (self.out / f"cycle-{cycle}-interruption.json").write_text(json.dumps(observation, indent=2))
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            stdout_file.close()
            stderr_file.close()
            os.close(fd)
            self.commands.append({"label": label, "command": args, "returncode": process.returncode,
                                  "stdout": stdout_path.read_text(), "stderr": stderr_path.read_text(),
                                  "elapsed_s": (time.monotonic_ns() - launched_ns) / 1e9,
                                  "http_event_start": http_start, "http_event_end": len(self.events)})
            self.save()

        print(json.dumps({"cycle": cycle, "actual_absent": len(absent), "actual_survivors": len(survivors),
                          "pending_operation_id": observation["pending_operation_id"]}), flush=True)
        return before, stopped_objects, absent, observation

    def exercise(self):
        mini = self.work("mini")
        self.run("mini-empty-metadata", ["workspace", "pull", "selection", "--root", mini], actor="mini")
        folder = mini / "batch"
        folder.mkdir()
        expected_hashes = {}
        for number in range(256):
            block = hashlib.sha256(f"independent eviction critic content {number:04d}".encode()).digest()
            content = block * 128
            path = folder / f"file-{number:04d}.bin"
            path.write_bytes(content)
            expected_hashes[f"batch/{path.name}"] = hashlib.sha256(content).hexdigest()
        self.check("256-individually-distinct-4096-byte-files", len(set(expected_hashes.values())) == 256
                   and all(p.stat().st_size == 4096 for p in folder.iterdir()))
        self.run("publish-distinct-batch", ["workspace", "publish", "selection", "--root", mini,
                 "--path", "batch/"], actor="mini", timeout=240)
        refs = self.root / "batch-references.json"
        self.run("save-exact-batch-references", ["workspace", "references", "selection", "--path", "batch/", "--output", refs], actor="mini")
        references = json.loads(refs.read_text())
        self.check("exact-references-cover-entire-distinct-batch", len(references) == 256
                   and all(r["version"]["sha256"] == expected_hashes[r["path"]] for r in references))
        baseline = self.run("authoritative-catalog-before-eviction", ["workspace", "inspect", "selection"], actor="book")
        baseline = find_dict(baseline, lambda d: "snapshot" in d and "head" in d)
        assert baseline is not None
        cache = self.root / "eviction-cache"
        self.run("hydrate-entire-private-batch", ["cache", "hydrate", "--root", cache, "--references", refs], actor="mini", timeout=240)
        inventory = self.run("verify-private-batch", ["cache", "inspect", "--root", cache, "--verify"], timeout=120)
        self.check("initial-batch-is-verified", len(inventory["entries"]) == 256
                   and all(row["state"] == "verified" for row in inventory["entries"]))
        retained = cache / "attempts" / str(uuid.uuid4()) / "unpublished.txt"
        retained.parent.mkdir(parents=True)
        retained.write_bytes(b"Independent unpublished bytes outside cache/objects survive recovery.\n")
        retained_hash = digest(retained)
        (self.out / "expected-hashes.json").write_text(json.dumps(expected_hashes, indent=2))

        for cycle in (1, 2):
            before, stopped_objects, absent, observation = self.interrupt_one(cache, refs, cycle)
            absent_set = set(absent)
            expected_missing_hashes = {before[key]["sha256"] for key in absent}
            for reopen in (1, 2):
                inventory = self.run(f"cycle-{cycle}-offline-reopen-{reopen}", ["cache", "inspect", "--root", cache, "--verify"], timeout=120)
                reopened_objects = self.objects(cache)
                state = self.read_state(cache)
                (self.out / f"cycle-{cycle}-state-reopened-{reopen}.json").write_text(json.dumps(state, indent=2))
                self.check(f"cycle-{cycle}-reopen-{reopen}-never-unlinks-survivors",
                           reopened_objects == stopped_objects and digest(retained) == retained_hash,
                           object_count_before_reopen=len(stopped_objects), object_count_after_reopen=len(reopened_objects),
                           pending_after_reopen=state.get("pending"))
                actual_cached_hashes = {row["version"]["sha256"] for row in inventory["cached_files"]}
                self.check(f"cycle-{cycle}-reopen-{reopen}-advertises-only-present-verified-content",
                           actual_cached_hashes == {row["sha256"] for row in stopped_objects.values()})

            current = self.run(f"cycle-{cycle}-authoritative-catalog-after-recovery", ["workspace", "inspect", "selection"], actor="book")
            current = find_dict(current, lambda d: "snapshot" in d and "head" in d)
            self.check(f"cycle-{cycle}-missing-private-copies-do-not-delete-global-files", current == baseline
                       and all(digest(mini / name) == h for name, h in expected_hashes.items()),
                       catalog_revision=current["head"]["revision"], file_count=len(current["snapshot"]["manifest"]["files"]))
            label = f"cycle-{cycle}-exact-refetch"
            output = self.run(label, ["cache", "hydrate", "--root", cache, "--references", refs], actor="mini", timeout=240)
            payload_events = [e for e in self.network(label) if e["path"] == "/v1/file/read"]
            after = self.objects(cache)
            self.check(f"cycle-{cycle}-refetch-downloads-exactly-missing-content",
                       len(payload_events) == len(absent) and sum(e["response_bytes"] for e in payload_events) == 4096 * len(absent)
                       and {e["response_sha256"] for e in payload_events} == expected_missing_hashes
                       and output["transfers"]["payload_downloaded"] == 4096 * len(absent),
                       missing_count=len(absent), actual_download_count=len(payload_events),
                       actual_download_bytes=sum(e["response_bytes"] for e in payload_events))
            self.check(f"cycle-{cycle}-refetch-restores-all-exact-bytes-without-changing-survivors",
                       set(after) == set(before)
                       and all(after[key]["sha256"] == before[key]["sha256"] and after[key]["size"] == before[key]["size"] for key in before)
                       and all(after[key] == stopped_objects[key] for key in stopped_objects)
                       and digest(retained) == retained_hash)
            final = self.run(f"cycle-{cycle}-final-verified-inventory", ["cache", "inspect", "--root", cache, "--verify"], timeout=120)
            self.check(f"cycle-{cycle}-fully-verified-after-recovery", len(final["entries"]) == 256
                       and len(final["cached_files"]) == 256 and all(row["state"] == "verified" for row in final["entries"]))
        self.check("two-observed-mid-unlink-recovery-cycles-complete", True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fabric-binary", required=True)
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()
    journey = EvictionJourney(args.fabric_binary, args.evidence)
    try:
        journey.setup()
        journey.exercise()
    except BaseException:
        (journey.out / "failure.txt").write_text(traceback.format_exc())
        print(traceback.format_exc(), flush=True)
        raise
    finally:
        journey.close()


if __name__ == "__main__":
    main()
