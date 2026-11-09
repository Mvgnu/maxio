#!/usr/bin/env python3
"""Independent managed workspace/cache critic; disposable real HTTPS processes.

No builder harness imports. The only executable under test is the frozen binary.
"""
import argparse
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import random
import shutil
import socket
import ssl
import subprocess
import threading
import time
import traceback
import uuid


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def find_dict(value, predicate):
    if isinstance(value, dict):
        if predicate(value):
            return value
        for child in value.values():
            found = find_dict(child, predicate)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = find_dict(child, predicate)
            if found is not None:
                return found
    return None


class Journey:
    def __init__(self, binary, out):
        self.binary = str(Path(binary).resolve())
        self.out = Path(out).resolve()
        self.out.mkdir(parents=True, exist_ok=False)
        self.root = self.out / "data"
        self.root.mkdir(mode=0o700)
        self.events = []
        self.checks = []
        self.commands = []
        self.label = "setup"
        self.lock = threading.Lock()
        self.proxies = []
        self.authority = None
        self.stop_download = {}
        self.server_port = self.free_port()
        self.proxy_ports = {n: self.free_port() for n in ("book", "mini", "vps")}

    def free_port(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def save(self):
        for name, value in (("commands", self.commands), ("http-events", self.events), ("checks", self.checks)):
            (self.out / (name + ".json")).write_text(json.dumps(value, indent=2))

    def check(self, name, condition, **evidence):
        row = {"name": name, "pass": bool(condition), "evidence": evidence}
        self.checks.append(row)
        self.save()
        print(json.dumps(row), flush=True)
        if not condition:
            raise AssertionError(name)

    def run(self, label, args, actor=None, expected=0, timeout=90):
        self.label = label
        cmd = [self.binary]
        if actor:
            cmd += ["--config", str(self.root / (actor + ".json"))]
        cmd += [str(x) for x in args]
        before = len(self.events)
        start = time.time()
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
        row = {"label": label, "command": cmd, "returncode": p.returncode,
               "stdout": p.stdout, "stderr": p.stderr, "elapsed_s": time.time() - start,
               "http_event_start": before, "http_event_end": len(self.events)}
        self.commands.append(row)
        self.save()
        print(json.dumps({"command": label, "returncode": p.returncode,
                          "elapsed_s": round(row["elapsed_s"], 3),
                          "http_events": len(self.events) - before}), flush=True)
        if expected == "fail":
            if p.returncode == 0:
                raise AssertionError(f"{label}: expected refusal but command succeeded")
        elif p.returncode != expected:
            raise AssertionError(f"{label}: rc {p.returncode}: {p.stderr}")
        try:
            return json.loads(p.stdout)
        except json.JSONDecodeError:
            return {"stdout": p.stdout, "stderr": p.stderr, "returncode": p.returncode}

    def external(self, args):
        subprocess.run([str(x) for x in args], check=True, capture_output=True, text=True)

    def make_tls(self):
        t = self.root / "tls"
        t.mkdir()
        self.external(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                       "-subj", "/CN=Independent managed cache critic CA",
                       "-addext", "basicConstraints=critical,CA:TRUE",
                       "-keyout", t / "ca.key", "-out", t / "ca.crt"])
        self.external(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
                       "-keyout", t / "server.key", "-out", t / "server.csr"])
        (t / "server.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n")
        self.external(["openssl", "x509", "-req", "-in", t / "server.csr", "-CA", t / "ca.crt",
                       "-CAkey", t / "ca.key", "-CAcreateserial", "-days", "1",
                       "-extfile", t / "server.ext", "-out", t / "server.crt"])

    def start_proxy(self, actor):
        journey = self
        context = ssl.create_default_context(cafile=str(self.root / "tls/ca.crt"))

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def forward(self):
                label = journey.label
                event = {"actor": actor, "label": label, "method": self.command, "path": self.path,
                         "request_bytes": 0, "response_bytes": 0, "time": time.time()}
                conn = http.client.HTTPSConnection("127.0.0.1", journey.server_port,
                                                   context=context, timeout=120)
                response_hash = hashlib.sha256()
                try:
                    conn.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
                    ignored = {"connection", "proxy-connection", "host", "expect"}
                    for key, value in self.headers.items():
                        if key.lower() not in ignored:
                            conn.putheader(key, value)
                    conn.putheader("Host", "127.0.0.1:" + str(journey.server_port))
                    conn.putheader("Connection", "close")
                    conn.endheaders()
                    if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                        while True:
                            line = self.rfile.readline()
                            size = int(line.strip().split(b";", 1)[0], 16)
                            conn.send(line)
                            if size == 0:
                                while True:
                                    trail = self.rfile.readline()
                                    conn.send(trail)
                                    if trail == b"\r\n":
                                        break
                                break
                            body = self.rfile.read(size)
                            event["request_bytes"] += len(body)
                            conn.send(body)
                            conn.send(self.rfile.read(2))
                    else:
                        remaining = int(self.headers.get("Content-Length", "0"))
                        while remaining:
                            chunk = self.rfile.read(min(64 * 1024, remaining))
                            if not chunk:
                                raise RuntimeError("client request truncated")
                            event["request_bytes"] += len(chunk)
                            conn.send(chunk)
                            remaining -= len(chunk)
                    response = conn.getresponse()
                    event["status"] = response.status
                    event["content_type"] = response.getheader("Content-Type")
                    event["declared_response_bytes"] = response.getheader("Content-Length")
                    self.send_response(response.status)
                    for key, value in response.getheaders():
                        if key.lower() not in {"connection", "transfer-encoding", "server", "date"}:
                            self.send_header(key, value)
                    self.send_header("Connection", "close")
                    self.end_headers()
                    cut = journey.stop_download.get(label)
                    large = int(response.getheader("Content-Length", "0")) >= 128 * 1024 * 1024
                    while True:
                        chunk = response.read(64 * 1024)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        self.wfile.flush()
                        event["response_bytes"] += len(chunk)
                        response_hash.update(chunk)
                        if cut is not None and large and event["response_bytes"] >= cut:
                            event["injected_disconnect"] = True
                            journey.stop_download.pop(label, None)
                            break
                    event["response_sha256"] = response_hash.hexdigest()
                except Exception as error:
                    event["error"] = repr(error)
                    if "status" not in event:
                        try:
                            self.send_error(502, "critic observation proxy: authority unavailable")
                        except Exception:
                            pass
                finally:
                    self.close_connection = True
                    conn.close()
                    with journey.lock:
                        journey.events.append(event)

            do_GET = forward
            do_POST = forward
            do_PUT = forward
            do_DELETE = forward

        server = http.server.ThreadingHTTPServer(("127.0.0.1", self.proxy_ports[actor]), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(self.root / "tls/server.crt"), str(self.root / "tls/server.key"))
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.proxies.append(server)

    def start_authority(self):
        log = (self.out / "authority.log").open("ab")
        args = [self.binary, "serve", "--root", str(self.root / "authority"),
                "--bind", f"127.0.0.1:{self.server_port}", "--tls-cert", str(self.root / "tls/server.crt"),
                "--tls-key", str(self.root / "tls/server.key")]
        self.authority = subprocess.Popen(args, stdout=log, stderr=log)
        log.close()
        for _ in range(100):
            if self.authority.poll() is not None:
                raise AssertionError("authority exited during startup")
            try:
                with socket.create_connection(("127.0.0.1", self.server_port), timeout=.1):
                    return
            except OSError:
                time.sleep(.05)
        raise AssertionError("authority did not start")

    def stop_authority(self):
        if self.authority is not None:
            self.authority.terminate()
            try:
                self.authority.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.authority.kill()
                self.authority.wait(timeout=10)
            self.authority = None

    def close(self):
        self.stop_authority()
        for server in self.proxies:
            server.shutdown()
            server.server_close()
        self.save()

    def network(self, label):
        return [e for e in self.events if e["label"] == label]

    def work(self, actor):
        return self.root / (actor + "-work")

    def setup(self):
        os.umask(0o077)
        self.make_tls()
        for actor in ("book", "mini", "vps"):
            self.run("keygen-" + actor, ["keygen", "--key", self.root / (actor + ".pem"),
                                       "--public-key-out", self.root / (actor + "-public.json")])
            self.work(actor).mkdir()
        self.run("init", ["init", "--root", self.root / "authority", "--owner-key", self.root / "book.pem",
                          "--name", "critic-book", "--endpoint", f"https://127.0.0.1:{self.proxy_ports['book']}",
                          "--ca-cert", self.root / "tls/ca.crt", "--client-config", self.root / "book.json"])
        self.start_authority()
        for actor in ("book", "mini", "vps"):
            self.start_proxy(actor)
        self.run("authority-info", ["info"], actor="book")
        self.run("workspace-create", ["workspace", "create", "selection"], actor="book")
        for actor in ("mini", "vps"):
            self.run("enroll-" + actor, ["device", "enroll", "--name", "critic-" + actor, "--role", "worker",
                      "--public-key", self.root / (actor + "-public.json"), "--write-config", self.root / (actor + ".json"),
                      "--key-path", self.root / (actor + ".pem")], actor="book")
            cfgpath = self.root / (actor + ".json")
            cfg = json.loads(cfgpath.read_text())
            endpoint_key = "endpoint" if "endpoint" in cfg else "origin"
            cfg[endpoint_key] = f"https://127.0.0.1:{self.proxy_ports[actor]}"
            cfgpath.write_text(json.dumps(cfg, indent=2))
            self.run("grant-" + actor, ["device", "grant", "--device", cfg["device_id"], "--workspace", "selection",
                     "--catalog", "--read", ".", "--write", "."], actor="book")

    def exercise(self):
        self.run("mini-initial-metadata", ["workspace", "pull", "selection", "--root", self.work("mini")], actor="mini")
        mini = self.work("mini")
        for folder in ("docs", "src", "data"):
            (mini / folder).mkdir()
        original_note = b"Independent critic note, first committed version.\n"
        guide = b"Only this selected docs directory should cross to the Book.\n"
        source = b"print('source remains on Mini')\n"
        (mini / "docs/note.md").write_bytes(original_note)
        (mini / "docs/guide.md").write_bytes(guide)
        (mini / "src/main.py").write_bytes(source)
        data = mini / "data/dataset.bin"
        rng = random.Random(701395426)
        with data.open("wb") as target:
            for _ in range(128):
                target.write(rng.randbytes(1024 * 1024))
            target.flush()
            os.fsync(target.fileno())
        data_hash = digest(data)
        data_size = data.stat().st_size
        self.check("real-nonsparse-128MiB-dataset", data_size == 128 * 1024 * 1024 and data.stat().st_blocks * 512 >= data_size,
                   size=data_size, allocated=data.stat().st_blocks * 512, sha256=data_hash)
        (mini / "unselected-private.txt").write_text("Never publish this unrelated local file.\n")
        publication = self.run("initial-selected-publish", ["workspace", "publish", "selection", "--root", mini,
                              "--path", "docs/", "--path", "src/", "--path", "data/"], actor="mini", timeout=180)
        original_catalog = self.run("initial-catalog", ["workspace", "inspect", "selection"], actor="book")
        catalog = find_dict(original_catalog, lambda d: "snapshot" in d and "head" in d)
        assert catalog, "catalog JSON missing canonical snapshot/head envelope"
        self.initial_revision = catalog["head"]["revision"]
        self.check("selected-publication-excludes-unselected-file", set(catalog["snapshot"]["manifest"]["files"]) ==
                   {"docs/note.md", "docs/guide.md", "src/main.py", "data/dataset.bin"}, catalog=catalog)
        for actor in ("book", "mini", "vps"):
            label = actor + "-metadata-only"
            output = self.run(label, ["workspace", "pull", "selection", "--root", self.work(actor)], actor=actor)
            events = self.network(label)
            transfers = output.get("transfers", {})
            self.check(label + "-no-payload", transfers.get("payload_downloaded") == 0 and
                       not any(e["path"] == "/v1/file/read" for e in events) and
                       sum(e["response_bytes"] for e in events) < 64 * 1024,
                       cli_transfers=transfers, observed_responses=events)
            if actor != "mini":
                self.check(actor + "-discovery-leaves-files-absent", not (self.work(actor) / "data").exists()
                           and not (self.work(actor) / "docs").exists() and not (self.work(actor) / "src").exists())
        for actor in ("book", "vps"):
            output = self.run(actor + "-selected-docs", ["workspace", "pull", "selection", "--root", self.work(actor),
                              "--path", "docs/"], actor=actor)
            events = self.network(actor + "-selected-docs")
            payload_events = [e for e in events if e.get("content_type", "").startswith("application/octet-stream")]
            self.check(actor + "-selected-docs-exact-bytes", (self.work(actor) / "docs/note.md").read_bytes() == original_note
                       and (self.work(actor) / "docs/guide.md").read_bytes() == guide
                       and not (self.work(actor) / "data").exists() and not (self.work(actor) / "src").exists()
                       and output["transfers"]["payload_downloaded"] == len(original_note) + len(guide)
                       and sum(e["response_bytes"] for e in payload_events) == len(original_note) + len(guide),
                       cli_transfers=output["transfers"], observed_payload_events=payload_events)
        book_note = self.work("book") / "docs/note.md"
        dirty_note = b"Book has a unique unpublished conflicting edit: 3fb72d65.\n"
        book_note.write_bytes(dirty_note)
        remote_note = b"Mini has independently published the second note version.\n"
        (mini / "docs/note.md").write_bytes(remote_note)
        self.run("mini-publish-second-version", ["workspace", "publish", "selection", "--root", mini,
                 "--path", "docs/note.md"], actor="mini")
        self.run("book-refresh-with-dirty-file", ["workspace", "pull", "selection", "--root", self.work("book")], actor="book")
        status = self.run("book-status-dirty", ["workspace", "status", "--root", self.work("book"), "--verify"])
        row = find_dict(status, lambda d: d.get("path") == "docs/note.md" and "local_state" in d)
        self.check("dirty-baseline-is-not-advanced-by-refresh", row is not None and row["local_state"] == "dirty"
                   and book_note.read_bytes() == dirty_note, status_row=row)
        self.run("book-dirty-pull-refused", ["workspace", "pull", "selection", "--root", self.work("book"),
                 "--path", "docs/note.md"], actor="book", expected="fail")
        self.run("book-conflicting-publish-refused", ["workspace", "publish", "selection", "--root", self.work("book"),
                 "--path", "docs/note.md"], actor="book", expected="fail")
        self.check("conflicting-commands-preserve-dirty-bytes", book_note.read_bytes() == dirty_note,
                   sha256=digest(book_note))
        self.stop_authority()
        offline = self.run("book-offline-status-after-disconnect", ["workspace", "status", "--root", self.work("book"), "--verify"])
        row = find_dict(offline, lambda d: d.get("path") == "docs/note.md" and "local_state" in d)
        self.check("offline-reopen-preserves-dirty-bytes", row is not None and row["local_state"] == "dirty"
                   and book_note.read_bytes() == dirty_note, status_row=row)
        self.start_authority()
        self.run("book-refresh-after-authority-restart", ["workspace", "pull", "selection", "--root", self.work("book")], actor="book")
        self.run("book-publish-after-restart-refused", ["workspace", "publish", "selection", "--root", self.work("book"),
                 "--path", "docs/note.md"], actor="book", expected="fail")
        self.check("authority-restart-preserves-dirty-edit", book_note.read_bytes() == dirty_note)

        vps_note = self.work("vps") / "docs/note.md"
        old_fd = os.open(vps_note, os.O_RDWR)
        try:
            self.run("vps-refresh-clean-baseline", ["workspace", "pull", "selection", "--root", self.work("vps")], actor="vps")
            status = self.run("vps-status-stale", ["workspace", "status", "--root", self.work("vps"), "--verify"])
            row = find_dict(status, lambda d: d.get("path") == "docs/note.md" and "local_state" in d)
            self.check("old-clean-baseline-is-stale", row is not None and row["local_state"] == "stale", status_row=row)
            self.run("vps-selected-new-version", ["workspace", "pull", "selection", "--root", self.work("vps"), "--path", "docs/note.md"], actor="vps")
            late_bytes = b"Late editor write to the old replaced inode; keep this recoverable.\n"
            os.lseek(old_fd, 0, os.SEEK_SET)
            os.write(old_fd, late_bytes)
            os.ftruncate(old_fd, len(late_bytes))
            os.fsync(old_fd)
            history = self.work("vps") / ".maxio-workspace/history"
            matches = [str(p) for p in history.rglob("*") if p.is_file() and p.stat().st_size == len(late_bytes) and p.read_bytes() == late_bytes]
            self.check("clean-replacement-retains-late-open-descriptor-edit", vps_note.read_bytes() == remote_note and bool(matches),
                       recovery_paths=matches, new_sha256=digest(vps_note))
        finally:
            os.close(old_fd)

        self.run("vps-pin-current-note", ["workspace", "pin", "--root", self.work("vps"), "--path", "docs/note.md"])
        before_delete = self.run("catalog-before-delete", ["workspace", "inspect", "selection"], actor="book")
        before_delete = find_dict(before_delete, lambda d: "snapshot" in d and "head" in d)
        revision_before_delete = before_delete["head"]["revision"]
        self.run("explicit-logical-delete", ["workspace", "delete", "selection", "--path", "docs/note.md", "--confirm"], actor="book")
        for actor in ("book", "vps"):
            self.run(actor + "-observe-deletion", ["workspace", "pull", "selection", "--root", self.work(actor)], actor=actor)
            status = self.run(actor + "-deleted-path-status", ["workspace", "status", "--root", self.work(actor), "--verify"])
            row = find_dict(status, lambda d: d.get("path") == "docs/note.md" and "local_state" in d)
            expected_bytes = dirty_note if actor == "book" else remote_note
            expected_state = "dirty" if actor == "book" else "stale"
            self.check(actor + "-logical-delete-retains-local-version", row is not None and row["local_state"] == expected_state
                       and (self.work(actor) / "docs/note.md").read_bytes() == expected_bytes,
                       status_row=row)
        self.run("stale-deleted-path-publish-refused", ["workspace", "publish", "selection", "--root", self.work("vps"),
                 "--path", "docs/note.md"], actor="vps", expected="fail")
        self.run("vps-unpin-deleted-path-offline", ["workspace", "pin", "--root", self.work("vps"), "--path", "docs/note.md", "--unpin"])
        self.run("explicit-exact-version-restore", ["workspace", "restore", "selection", "--path", "docs/note.md",
                 "--revision", revision_before_delete["revision"], "--sha256", revision_before_delete["sha256"], "--confirm"], actor="book")
        self.run("vps-observe-restored-version", ["workspace", "pull", "selection", "--root", self.work("vps")], actor="vps")
        status = self.run("vps-restored-status", ["workspace", "status", "--root", self.work("vps"), "--verify"])
        row = find_dict(status, lambda d: d.get("path") == "docs/note.md" and "local_state" in d)
        self.check("explicit-restore-recovers-matching-baseline", row is not None and row["local_state"] == "clean"
                   and vps_note.read_bytes() == remote_note, status_row=row)
        vps_note.write_bytes(b"Explicitly restored baseline permits this deliberate next edit.\n")
        self.run("publish-after-explicit-restore", ["workspace", "publish", "selection", "--root", self.work("vps"),
                 "--path", "docs/note.md"], actor="vps")
        shutil.rmtree(mini / "src")
        (mini / "docs/guide.md").write_bytes(guide + b"Selected followup edit.\n")
        self.run("mini-refresh-for-selected-guide", ["workspace", "pull", "selection", "--root", mini], actor="mini")
        self.run("publish-with-unrelated-directory-absent", ["workspace", "publish", "selection", "--root", mini,
                 "--path", "docs/guide.md"], actor="mini")
        after = self.run("catalog-after-missing-directory", ["workspace", "inspect", "selection"], actor="book")
        after = find_dict(after, lambda d: "snapshot" in d and "head" in d)
        self.check("missing-local-directory-does-not-delete-remote", "src/main.py" in after["snapshot"]["manifest"]["files"]
                   and "data/dataset.bin" in after["snapshot"]["manifest"]["files"])

        self.exercise_cache(data, data_hash, data_size, dirty_note)
        self.check("final-unrelated-book-dataset-still-absent", not (self.work("book") / "data").exists()
                   and not (self.work("book") / "src").exists() and book_note.read_bytes() == dirty_note)

    def exercise_cache(self, data, data_hash, data_size, dirty_note):
        refs = self.root / "data-references.json"
        self.run("exact-dataset-references", ["workspace", "references", "selection", "--path", "data/dataset.bin", "--output", refs], actor="mini")
        cache = self.root / "mini-private-cache"
        self.run("local-cache-import", ["cache", "import", "--root", cache, "--references", refs, "--source", data], actor="mini", timeout=180)
        objects = [p for p in (cache / "cache/objects").rglob("*") if p.is_file() and p.stat().st_size == data_size]
        assert len(objects) == 1, f"expected one cache object, got {objects}"
        cached = objects[0]
        inventory = self.run("imported-cache-inspect-verified", ["cache", "inspect", "--root", cache, "--verify"], timeout=180)
        self.check("cache-import-independent-verified-copy", digest(cached) == data_hash and cached.stat().st_ino != data.stat().st_ino,
                   source_inode=data.stat().st_ino, cache_inode=cached.stat().st_ino, cache_path=str(cached), inventory=inventory)
        self.run("offline-cache-pin", ["cache", "pin", "--root", cache, "--references", refs])
        self.run("pinned-cache-eviction-refused", ["cache", "evict", "--root", cache, "--references", refs, "--confirm"], actor="mini", expected="fail", timeout=180)
        self.check("pinned-refusal-preserves-exact-bytes", cached.exists() and digest(cached) == data_hash)
        self.run("offline-cache-unpin", ["cache", "pin", "--root", cache, "--references", refs, "--unpin"])

        self.stop_authority()
        self.run("offline-retention-eviction-refused", ["cache", "evict", "--root", cache, "--references", refs, "--confirm"], actor="mini", expected="fail", timeout=45)
        self.run("offline-cache-reopen", ["cache", "inspect", "--root", cache, "--verify"], timeout=180)
        self.check("unverifiable-retention-preserves-cache", cached.exists() and digest(cached) == data_hash)
        self.start_authority()

        reference = json.loads(refs.read_text())[0]
        vault_body = self.root / "authority/vault" / reference["version"]["blob"]
        hidden_body = vault_body.with_name(vault_body.name + ".critic-temporarily-unavailable")
        assert digest(vault_body) == data_hash
        vault_body.rename(hidden_body)
        try:
            self.run("missing-vault-version-eviction-refused", ["cache", "evict", "--root", cache, "--references", refs, "--confirm"], actor="mini", expected="fail", timeout=180)
            self.check("fresh-retention-check-rejects-unavailable-exact-vault-body", cached.exists() and digest(cached) == data_hash
                       and hidden_body.exists() and digest(hidden_body) == data_hash)
        finally:
            hidden_body.rename(vault_body)

        retained = cache / "attempts" / str(uuid.uuid4()) / "unpublished-output.bin"
        retained.parent.mkdir(parents=True)
        retained.write_bytes(b"Unique unpublished attempt bytes must never be cache eviction candidates.\n")
        retained_hash = digest(retained)
        before_allocated = cached.stat().st_blocks * 512
        output = self.run("verified-exact-cache-eviction", ["cache", "evict", "--root", cache, "--references", refs, "--confirm"], actor="mini", timeout=180)
        receipt = find_dict(output, lambda d: "logical_bytes_removed" in d and "allocated_bytes_unlinked" in d)
        self.check("fresh-verified-eviction-reclaims-only-cache-object", not cached.exists() and receipt is not None
                   and receipt["logical_bytes_removed"] == data_size and receipt["allocated_bytes_unlinked"] == before_allocated
                   and digest(data) == data_hash and digest(retained) == retained_hash
                   and (self.work("book") / "docs/note.md").read_bytes() == dirty_note,
                   receipt=receipt, measured_allocated_before=before_allocated, retained_output=str(retained))
        self.run("cache-reopen-after-eviction", ["cache", "inspect", "--root", cache, "--verify"])
        self.stop_download["interrupted-cache-refetch"] = 2 * 1024 * 1024
        self.run("interrupted-cache-refetch", ["cache", "hydrate", "--root", cache, "--references", refs], actor="mini", expected="fail", timeout=180)
        partial_events = [e for e in self.network("interrupted-cache-refetch") if e.get("injected_disconnect")]
        self.check("refetch-interruption-really-delivered-partial-body", len(partial_events) == 1
                   and partial_events[0]["response_bytes"] == 2 * 1024 * 1024,
                   partial_events=partial_events)
        files_after_failure = [{"path": str(p), "bytes": p.stat().st_size} for p in cache.rglob("*") if p.is_file()]
        self.run("cache-offline-reopen-after-partial-refetch", ["cache", "inspect", "--root", cache, "--verify"], timeout=180)
        self.check("failed-refetch-preserves-unpublished-and-original-bytes", digest(data) == data_hash and digest(retained) == retained_hash,
                   private_files_after_failure=files_after_failure)
        output = self.run("exact-cache-refetch-after-failure", ["cache", "hydrate", "--root", cache, "--references", refs], actor="mini", timeout=180)
        events = [e for e in self.network("exact-cache-refetch-after-failure") if e.get("content_type", "").startswith("application/octet-stream")]
        objects = [p for p in (cache / "cache/objects").rglob("*") if p.is_file() and p.stat().st_size == data_size]
        self.check("exact-cache-refetch-verifies-full-original-dataset", len(objects) == 1 and digest(objects[0]) == data_hash
                   and sum(e["response_bytes"] for e in events) == data_size and digest(retained) == retained_hash,
                   observed_payload_events=events, output=output, sha256=digest(objects[0]) if objects else None)
        final = self.run("final-cache-inventory-verified", ["cache", "inspect", "--root", cache, "--verify"], timeout=180)
        self.check("recovered-cache-has-verified-advertisement", find_dict(final, lambda d: d.get("state") == "verified") is not None,
                   inventory=final)

        cached = objects[0]
        link = self.root / "cache-alias-hardlink"
        os.link(cached, link)
        self.run("hardlink-cache-eviction-refused", ["cache", "evict", "--root", cache, "--references", refs, "--confirm"], actor="mini", expected="fail", timeout=180)
        self.check("hardlink-refusal-preserves-both-links", cached.exists() and link.exists() and digest(cached) == data_hash,
                   link_count=cached.stat().st_nlink)

        small_refs = self.root / "guide-references.json"
        self.run("small-exact-references", ["workspace", "references", "selection", "--path", "docs/guide.md", "--output", small_refs], actor="mini")
        modified_cache = self.root / "modified-private-cache"
        self.run("small-independent-cache-import", ["cache", "import", "--root", modified_cache, "--references", small_refs,
                 "--source", self.work("mini") / "docs/guide.md"], actor="mini")
        small_objects = [p for p in (modified_cache / "cache/objects").rglob("*") if p.is_file()]
        assert len(small_objects) == 1
        modified = small_objects[0]
        with modified.open("r+b") as edit:
            edit.write(b"UNPUBLISHED LOCAL CACHE EDIT")
            edit.flush()
            os.fsync(edit.fileno())
        modified_hash = digest(modified)
        self.run("modified-cache-eviction-refused", ["cache", "evict", "--root", modified_cache,
                 "--references", small_refs, "--confirm"], actor="mini", expected="fail")
        changed = self.run("modified-cache-reopen-inspection", ["cache", "inspect", "--root", modified_cache, "--verify"])
        self.check("modified-cache-bytes-retained-and-not-advertised", modified.exists() and digest(modified) == modified_hash
                   and find_dict(changed, lambda d: d.get("state") == "modified") is not None
                   and changed.get("cached_files") == [], inventory=changed, sha256=modified_hash)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--fabric-binary", required=True)
    p.add_argument("--evidence", required=True)
    args = p.parse_args()
    journey = Journey(args.fabric_binary, args.evidence)
    try:
        journey.setup()
        journey.exercise()
    except BaseException as error:
        (journey.out / "failure.txt").write_text(traceback.format_exc())
        print(traceback.format_exc(), flush=True)
        raise
    finally:
        journey.close()


if __name__ == "__main__":
    main()
