#!/usr/bin/env python3
"""Real-process selective workspace journey; three local roots, never three physical devices.

The loopback proxy counts actual payload body bytes and injects controlled transfer
failures. It is an acceptance fixture, not a production proxy or security boundary.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import uuid

from smoke_peer_s3 import Node, S3, expect


class TransferProxy(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, upstream_port):
        super().__init__(("127.0.0.1", 0), ProxyRequest)
        self.upstream_port = upstream_port
        self.lock = threading.Lock()
        self.uploaded = 0
        self.downloaded = 0
        self.truncate_blobs = False
        self.reject_uploads = False
        self.drop_head_response = False
        self.dropped_head_responses = 0

    def counts(self):
        with self.lock:
            return {"payload_uploaded": self.uploaded, "payload_downloaded": self.downloaded}


class ProxyRequest(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.forward()

    do_HEAD = do_PUT = do_POST = do_DELETE = do_GET

    def forward(self):
        upstream = None
        try:
            is_blob = "/blobs/" in self.path
            length = int(self.headers.get("Content-Length", "0"))
            if length > 16 * 1024 * 1024 or self.headers.get("Transfer-Encoding"):
                self.send_error(400, "fixture only accepts bounded content-length requests")
                return
            body = self.rfile.read(length) if length else None
            if is_blob and self.server.reject_uploads and self.command in {"PUT", "POST"}:
                error = b"<Error><Code>ServiceUnavailable</Code><Message>injected transfer failure</Message></Error>"
                self.send_response(503)
                self.send_header("Content-Type", "application/xml")
                self.send_header("Content-Length", str(len(error)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(error)
                self.close_connection = True
                return
            headers = {key: value for key, value in self.headers.items()
                       if key.lower() not in {"connection", "proxy-connection"}}
            upstream = http.client.HTTPConnection("127.0.0.1", self.server.upstream_port, timeout=60)
            upstream.request(self.command, self.path, body=body, headers=headers)
            if is_blob and body:
                with self.server.lock:
                    self.server.uploaded += len(body)
            response = upstream.getresponse()
            if self.command == "PUT" and self.path.split("?")[0].endswith("/head.json") and 200 <= response.status < 300:
                with self.server.lock:
                    drop = self.server.drop_head_response
                    if drop:
                        self.server.drop_head_response = False
                        self.server.dropped_head_responses += 1
                if drop:
                    response.read()
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in {"connection", "transfer-encoding", "server", "date"}:
                    self.send_header(key, value)
            self.send_header("Connection", "close")
            self.end_headers()
            sent = 0
            if self.command != "HEAD":
                while chunk := response.read(65536):
                    self.wfile.write(chunk)
                    self.wfile.flush()
                    sent += len(chunk)
                    if is_blob:
                        with self.server.lock:
                            self.server.downloaded += len(chunk)
                    if is_blob and self.server.truncate_blobs and self.command == "GET" and sent >= 262144:
                        self.close_connection = True
                        self.connection.shutdown(socket.SHUT_RDWR)
                        break
            self.close_connection = True
        except (BrokenPipeError, ConnectionResetError, OSError, http.client.HTTPException):
            self.close_connection = True
        finally:
            if upstream:
                upstream.close()


def hash_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


class WorkspaceCLI:
    def __init__(self, binary, endpoint, env, evidence):
        self.binary, self.endpoint, self.env, self.evidence = binary, endpoint, env, evidence
        self.lock = threading.Lock()
        self.calls = 0

    def call(self, folder, *args, success=True, offline=False):
        with self.lock:
            self.calls += 1
            call_id = self.calls
        command = [str(self.binary), "--root", str(folder)]
        if not offline:
            command += ["--endpoint", self.endpoint, "--bucket", "workspace-smoke", "--workspace", "projects", "--allow-http"]
        command += list(args)
        env = self.env if not offline else {key: value for key, value in self.env.items() if not key.startswith("MAXIO_")}
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=180)
        (self.evidence / f"{call_id:02d}-{folder.name}-{args[0]}.json").write_text(json.dumps({
            "command": command, "exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
        }, indent=2))
        if (result.returncode == 0) != success:
            raise AssertionError(f"unexpected {args[0]} exit={result.returncode}: {result.stderr[-3000:]}")
        report = json.loads(result.stdout if success else result.stderr.strip().splitlines()[-1])
        assert report["ok"] == success, report
        return report


def run(binary, workspace_binary, keep_data, dataset_mib):
    root = Path(tempfile.mkdtemp(prefix="maxio-workspace-smoke-"))
    evidence = root / "evidence"
    evidence.mkdir()
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("MAXIO_", "MINIO_", "AWS_"))
           and key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}}
    env.update(MAXIO_ACCESS_KEY="workspace-smoke-access", MAXIO_SECRET_KEY=uuid.uuid4().hex,
               MAXIO_MIN_DISK_HEADROOM_BYTES="0", RUST_LOG="warn")
    node = Node(binary, root, "server", port, 0, env)
    client = S3(port, env["MAXIO_ACCESS_KEY"], env["MAXIO_SECRET_KEY"])
    proxy = TransferProxy(port)
    thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    thread.start()
    cli = WorkspaceCLI(workspace_binary, f"http://127.0.0.1:{proxy.server_port}", env, evidence)
    mini, book, vps = [root / name for name in ("mac-mini", "macbook", "vps")]
    for folder in (mini, book, vps):
        folder.mkdir()
    for folder in ("src", "docs", "datasets", "unrelated"):
        (mini / folder).mkdir()
    source = b"export const ranking = 'initial';\n"
    (mini / "src/ranking.ts").write_bytes(source)
    (mini / "docs/guide.md").write_bytes(b"selected project documentation\n")
    (mini / "unrelated/private.txt").write_bytes(b"must not be published\n")
    dataset = mini / "datasets/offers.bin"
    block = bytes(range(256)) * 4096
    with dataset.open("wb") as file:
        for _ in range(dataset_mib):
            file.write(block)
    dataset_hash = hash_file(dataset)
    observations = {"environment": "three isolated roots/processes on one Linux host", "dataset_bytes": dataset.stat().st_size}
    succeeded = False
    try:
        node.start(clustered=False)
        expect(client.request("PUT", "/workspace-smoke"), 200, "create workspace bucket")
        cli.call(mini, "init")
        first = cli.call(mini, "publish", "src", "docs", "datasets")
        initial_revision = first["revision"]
        assert first["transfer"]["payload_uploaded"] >= dataset.stat().st_size
        observations["initial_publication"] = first["transfer"]
        before = proxy.counts()
        for folder in (book, vps):
            listing = cli.call(folder, "refresh")
            assert {row["path"] for row in listing["files"]} == {"src/ranking.ts", "docs/guide.md", "datasets/offers.bin"}
            assert listing["transfer"]["payload_downloaded"] == 0
            assert not (folder / "datasets").exists()
            assert not (folder / "unrelated").exists()
        assert proxy.counts() == before, "discovery transferred blob payload bytes"
        observations["two_device_discovery_payload_bytes"] = 0
        pull = cli.call(book, "pull", "src")
        assert (book / "src/ranking.ts").read_bytes() == source
        assert not (book / "datasets").exists() and not (book / "docs").exists()
        assert pull["transfer"]["payload_downloaded"] == len(source), pull
        observations["selected_source_pull"] = pull["transfer"]
        cli.call(vps, "pull", "docs")
        cli.call(vps, "pin", "docs", offline=True)
        updated = b"export const ranking = 'published from macbook';\n"
        (book / "src/ranking.ts").write_bytes(updated)
        second = cli.call(book, "publish", "src/ranking.ts")
        assert second["transfer"]["payload_uploaded"] == len(updated)
        (mini / "src/ranking.ts").write_bytes(b"unpublished mini edit\n")
        cli.call(mini, "publish", "src/ranking.ts", success=False)
        cli.call(mini, "refresh")
        cli.call(mini, "publish", "src/ranking.ts", success=False)
        cli.call(mini, "pull", "src", success=False)
        assert (mini / "src/ranking.ts").read_bytes() == b"unpublished mini edit\n"
        cli.call(vps, "pull", "src")
        assert (vps / "src/ranking.ts").read_bytes() == updated
        old = cli.call(book, "pull", "src", "--revision", initial_revision)
        assert old["revision"] == second["revision"], "historical pull rewound the observed head"
        assert (book / "src/ranking.ts").read_bytes() == source
        status = cli.call(book, "status", offline=True)
        assert next(row for row in status["files"] if row["path"] == "src/ranking.ts")["local_state"] == "stale"
        cli.call(book, "pull", "src")
        for folder in (book, vps):
            cli.call(folder, "refresh")
            (folder / "src/ranking.ts").write_text(f"concurrent edit from {folder.name}\n")

        def compete(folder):
            # Both commands must use the exact same observed base. Do not refresh here.
            command = [str(workspace_binary), "--root", str(folder), "--endpoint", cli.endpoint,
                       "--bucket", "workspace-smoke", "--workspace", "projects", "--allow-http", "publish", "src"]
            result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=180)
            (evidence / f"race-{folder.name}.json").write_text(json.dumps({"exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr}, indent=2))
            return result.returncode, folder

        with ThreadPoolExecutor(max_workers=2) as pool:
            race = list(pool.map(compete, (book, vps)))
        assert sum(code == 0 for code, _ in race) == 1, race
        winner = next(folder for code, folder in race if code == 0)
        loser = next(folder for code, folder in race if code != 0)
        assert (loser / "src/ranking.ts").read_text() == f"concurrent edit from {loser.name}\n"
        observations["simultaneous_publish"] = {"winner": winner.name, "loser_preserved": loser.name}
        node.stop()
        saved = cli.call(vps, "list", offline=True)
        assert next(row for row in saved["files"] if row["path"] == "docs/guide.md")["pinned"]
        cli.call(vps, "refresh", success=False)
        assert (loser / "src/ranking.ts").exists()
        node.start(clustered=False)
        cli.call(vps, "refresh")
        # Truncate a real 128 MiB object response: no partial final file may appear.
        proxy.truncate_blobs = True
        failed = cli.call(vps, "pull", "datasets", success=False)
        proxy.truncate_blobs = False
        assert not (vps / "datasets/offers.bin").exists()
        assert (vps / "docs/guide.md").read_bytes() == b"selected project documentation\n"
        observations["interrupted_download"] = failed["transfer"]
        hydrated = cli.call(vps, "pull", "datasets")
        assert hash_file(vps / "datasets/offers.bin") == dataset_hash
        assert hydrated["transfer"]["payload_downloaded"] == dataset.stat().st_size
        assert not (book / "datasets").exists(), "unselected MacBook received the dataset"
        observations["explicit_dataset_pull"] = hydrated["transfer"]
        # A refused eviction is a retained-copy safety result, not a feature pass.
        cli.call(vps, "evict", "datasets", success=False, offline=True)
        assert hash_file(vps / "datasets/offers.bin") == dataset_hash
        observations["eviction"] = "refused; enforced retention/durability not implemented; bytes retained"
        (vps / "docs/failed.txt").write_bytes(b"retain this failed upload\n")
        before_head = cli.call(vps, "refresh")["revision"]
        proxy.reject_uploads = True
        cli.call(vps, "publish", "docs/failed.txt", success=False)
        proxy.reject_uploads = False
        assert (vps / "docs/failed.txt").read_bytes() == b"retain this failed upload\n"
        assert cli.call(vps, "refresh")["revision"] == before_head
        # Commit the head but lose its HTTP response. Publication must reconcile its ID.
        proxy.drop_head_response = True
        recovered = cli.call(vps, "publish", "docs/failed.txt")
        assert proxy.dropped_head_responses == 1, "lost acknowledgment injection did not reach the head"
        assert recovered["revision"] != before_head
        assert cli.call(book, "refresh")["revision"] == recovered["revision"]
        cli.call(book, "pull", "docs/failed.txt")
        assert (book / "docs/failed.txt").read_bytes() == b"retain this failed upload\n"
        observations["lost_head_acknowledgment"] = "publication identity reconciled"
        observations["actual_proxy_blob_body_bytes"] = proxy.counts()
        observations["result"] = "pass: M1a scoped journey; full B/C/D/E remain open"
        (evidence / "report.json").write_text(json.dumps(observations, indent=2))
        print(json.dumps(observations, indent=2))
        succeeded = True
    finally:
        node.stop()
        proxy.shutdown()
        proxy.server_close()
        if succeeded and not keep_data:
            shutil.rmtree(root)
        else:
            print(f"Workspace evidence retained: {root}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/debug/maxio"))
    parser.add_argument("--workspace-binary", type=Path, default=Path("target/debug/maxio-workspace"))
    parser.add_argument("--dataset-mib", type=int, default=128)
    parser.add_argument("--keep-data", action="store_true")
    args = parser.parse_args()
    if args.dataset_mib < 8:
        parser.error("use at least 8 MiB to exercise real multipart transfer")
    for binary in (args.binary, args.workspace_binary):
        if not binary.is_file():
            parser.error(f"build the executable first: {binary}")
    run(args.binary.resolve(), args.workspace_binary.resolve(), args.keep_data, args.dataset_mib)


if __name__ == "__main__":
    main()
