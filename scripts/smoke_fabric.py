#!/usr/bin/env python3
"""Process evidence for managed MaxIO journeys B/C/D/E (one host, no models).

Run against already-built binaries; this script never builds or changes MaxIO.
Every run creates a new, retained evidence directory. Book, Mini and VPS are
separately enrolled identities with separate working/cache roots, represented by
processes on ONE host. They are not physical machines or a WAN test.

Four small HTTPS forwarding observers use a fixture CA and a correctly signed
server leaf. Both TLS hops verify that CA. Observers count actual application
payload bytes and inject named faults; they never persist session tokens or
private keys in request logs. They are test instrumentation, not product proxies.

No provider is contacted. The Codex/Claude executables below are explicitly
labelled protocol fixtures exercised through the existing execution adapters.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable


MIB = 1024 * 1024
DATASET = "data/dataset.bin"
TERMINAL = {"succeeded", "failed", "cancelled", "timed_out", "abandoned"}


class JourneyFailure(RuntimeError):
    pass


class Blocked(RuntimeError):
    pass


def require(condition: Any, message: str) -> None:
    if not condition:
        raise JourneyFailure(message)


def dump(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def identity(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(MIB):
            digest.update(block)
    stat = path.stat()
    return {
        "path": str(path), "sha256": digest.hexdigest(), "size": stat.st_size,
        "allocated_bytes": getattr(stat, "st_blocks", 0) * 512,
        "device": stat.st_dev, "inode": stat.st_ino, "links": stat.st_nlink,
    }


def text_file(path: Path, content: str, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if executable:
        path.chmod(0o700)


def unique_id() -> str:
    return str(uuid.uuid4())


def available_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@dataclass
class Fault:
    name: str
    route: str
    action: str
    operation: str | None = None
    file_path: str | None = None
    remaining: int = 1
    cut_bytes: int = 64 * 1024
    matched: int = 0
    ready: threading.Event = field(default_factory=threading.Event)
    release: threading.Event = field(default_factory=threading.Event)

    def matches(self, event: dict[str, Any]) -> bool:
        return (
            self.remaining > 0 and event["route"] == self.route
            and (self.operation is None or event.get("operation") == self.operation)
            and (self.file_path is None or event.get("file_path") == self.file_path)
        )


class Observer:
    """Bounded-memory HTTPS forwarder; each actor has a distinct listening port."""

    def __init__(self, label: str, evidence: Path, upstream: int, cert: Path,
                 key: Path, ca: Path):
        self.label = label
        self.evidence = evidence
        self.upstream = upstream
        self.context = ssl.create_default_context(cafile=str(ca))
        self.lock = threading.Lock()
        self.events: list[dict[str, Any]] = []
        self.faults: list[Fault] = []
        observer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, _format: str, *_args: Any) -> None:
                pass

            def do_POST(self) -> None:
                observer.forward(self)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(str(cert), str(key))
        self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def endpoint(self) -> str:
        return f"https://127.0.0.1:{self.port}"

    def arm(self, fault: Fault) -> Fault:
        with self.lock:
            self.faults.append(fault)
        return fault

    def choose_fault(self, event: dict[str, Any]) -> Fault | None:
        with self.lock:
            for fault in self.faults:
                if fault.matches(event):
                    fault.remaining -= 1
                    fault.matched += 1
                    return fault
        return None

    def snapshot(self) -> list[dict[str, Any]]:
        with self.lock:
            return [dict(event) for event in self.events]

    def payload(self, file_path: str | None = None, direction: str = "download") -> int:
        key = f"payload_{direction}_bytes"
        return sum(event.get(key, 0) for event in self.snapshot()
                   if file_path is None or event.get("file_path") == file_path)

    @staticmethod
    def close_socket(handler: http.server.BaseHTTPRequestHandler) -> None:
        handler.close_connection = True
        with contextlib.suppress(OSError):
            handler.connection.shutdown(socket.SHUT_RDWR)

    @staticmethod
    def error(handler: http.server.BaseHTTPRequestHandler, message: str) -> None:
        body = json.dumps({"error": {"code": "unavailable", "message": message}}).encode()
        handler.send_response(503)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.wfile.write(body)
        handler.close_connection = True

    def forward(self, handler: http.server.BaseHTTPRequestHandler) -> None:
        event: dict[str, Any] = {
            "actor": self.label, "route": handler.path, "started_unix": time.time(),
            "payload_upload_bytes": 0, "payload_download_bytes": 0,
        }
        connection: http.client.HTTPSConnection | None = None
        sent_headers = False
        try:
            handler.connection.settimeout(45)
            length = int(handler.headers.get("content-length", "0"))
            require(0 <= length <= 1024 * 1024 * MIB, "invalid observer request length")
            upload = handler.path == "/v1/file/upload"
            body = b""
            request: dict[str, Any] = {}
            if upload:
                request = json.loads(base64.b64decode(handler.headers["x-maxio-upload"]))
            else:
                require(length <= 16 * MIB, "metadata request exceeds observer bound")
                body = handler.rfile.read(length)
                require(len(body) == length, "short metadata request")
                if body:
                    request = json.loads(body)
            event["metadata_request_bytes"] = len(body)
            if handler.path == "/v1/control":
                event["operation"] = request.get("op")
                event["request_id"] = request.get("request_id")
                if request.get("op") == "publish":
                    event["request_id"] = request["publication"]["context"]["request_id"]
            if upload or handler.path == "/v1/file/read":
                event["file_path"] = request.get("path")
                version = request if upload else request.get("expected", {})
                event["sha256"] = version.get("sha256")
                event["declared_size"] = version.get("size")
                event["attempt"] = request.get("attempt")
            fault = self.choose_fault(event)
            if fault:
                event["fault"] = fault.name
                event["fault_action"] = fault.action
            if fault and fault.action == "reject":
                fault.ready.set()
                self.error(handler, f"journey injected interruption: {fault.name}")
                event["status"] = 503
                return
            if fault and fault.action == "pause_before":
                fault.ready.set()
                require(fault.release.wait(25), "fault gate was not released")
            connection = http.client.HTTPSConnection(
                "127.0.0.1", self.upstream, context=self.context, timeout=45)
            connection.putrequest("POST", handler.path, skip_accept_encoding=True)
            for name, value in handler.headers.items():
                if name.lower() not in {"host", "connection", "transfer-encoding"}:
                    connection.putheader(name, value)
            connection.putheader("Connection", "close")
            connection.endheaders()
            if upload:
                remaining = length
                while remaining:
                    limit = min(256 * 1024, remaining)
                    if fault and fault.action == "cut_upload":
                        limit = min(limit, fault.cut_bytes - event["payload_upload_bytes"])
                        if limit <= 0:
                            break
                    block = handler.rfile.read(limit)
                    require(block, "upload client closed before declared length")
                    connection.send(block)
                    event["payload_upload_bytes"] += len(block)
                    remaining -= len(block)
                if fault and fault.action == "cut_upload":
                    fault.ready.set()
                    connection.close()
                    self.close_socket(handler)
                    return
            elif body:
                connection.send(body)
            response = connection.getresponse()
            event["status"] = response.status
            file_response = handler.path == "/v1/file/read" and response.status == 200
            if file_response:
                response_body = None
                response_length = int(response.getheader("content-length", "-1"))
                require(response_length >= 0, "file response lacks content length")
            else:
                response_body = response.read(16 * MIB + 1)
                require(len(response_body) <= 16 * MIB, "metadata response exceeds bound")
                response_length = len(response_body)
                event["metadata_response_bytes"] = response_length
            if fault and fault.action == "drop_response":
                fault.ready.set()
                event["upstream_acknowledged"] = 200 <= response.status < 300
                self.close_socket(handler)
                return
            if fault and fault.action == "pause_response":
                fault.ready.set()
                require(fault.release.wait(25), "response gate was not released")
            handler.send_response(response.status)
            for name, value in response.getheaders():
                if name.lower() not in {"connection", "transfer-encoding", "content-length"}:
                    handler.send_header(name, value)
            handler.send_header("Content-Length", str(response_length))
            handler.send_header("Connection", "close")
            handler.end_headers()
            sent_headers = True
            if response_body is not None:
                handler.wfile.write(response_body)
            else:
                while block := response.read(min(256 * 1024, response_length or 1)):
                    if fault and fault.action == "cut_download":
                        left = fault.cut_bytes - event["payload_download_bytes"]
                        block = block[:left]
                    handler.wfile.write(block)
                    event["payload_download_bytes"] += len(block)
                    if fault and fault.action == "cut_download":
                        if event["payload_download_bytes"] >= fault.cut_bytes:
                            fault.ready.set()
                            self.close_socket(handler)
                            return
            handler.close_connection = True
        except (OSError, ValueError, KeyError, http.client.HTTPException,
                JourneyFailure) as error:
            event["observer_error"] = f"{type(error).__name__}: {error}"
            if not sent_headers:
                with contextlib.suppress(OSError):
                    self.error(handler, "journey upstream unavailable")
            self.close_socket(handler)
        finally:
            if connection:
                connection.close()
            event["finished_unix"] = time.time()
            with self.lock:
                self.events.append(event)
                with (self.evidence / f"network-{self.label}.jsonl").open("a") as stream:
                    stream.write(json.dumps(event, sort_keys=True) + "\n")

    def close(self) -> None:
        for fault in self.faults:
            fault.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


@dataclass
class CommandResult:
    returncode: int
    data: Any
    stdout: Path
    stderr: Path
    command_file: Path

    @property
    def value(self) -> Any:
        if isinstance(self.data, dict) and "transfers" in self.data:
            return self.data["result"]
        return self.data

    def error_text(self) -> str:
        return self.stderr.read_text(encoding="utf-8", errors="replace")


@dataclass
class Process:
    label: str
    process: subprocess.Popen[bytes]
    stdout: Path
    stderr: Path
    command_file: Path

    def stop(self, abrupt: bool = False) -> None:
        if self.process.poll() is not None:
            return
        if abrupt:
            self.process.kill()
        else:
            self.process.terminate()
        try:
            self.process.wait(timeout=12)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)


class Journey:
    def __init__(self, args: argparse.Namespace):
        self.fabric = Path(args.fabric_binary).resolve(strict=True)
        self.worker = Path(args.worker_binary).resolve(strict=True)
        require(os.access(self.fabric, os.X_OK), "fabric binary is not executable")
        require(os.access(self.worker, os.X_OK), "worker binary is not executable")
        require(args.size_mib >= 128, "Journey B/D requires at least 128 MiB")
        self.size = args.size_mib * MIB
        if args.evidence:
            self.root = Path(args.evidence).absolute()
            self.root.mkdir(parents=True, exist_ok=False)
        else:
            self.root = Path(tempfile.mkdtemp(prefix="maxio-fabric-journey-"))
        self.root.chmod(0o700)
        self.commands = self.root / "commands"
        self.commands.mkdir()
        self.counter = 0
        self.cases: list[dict[str, Any]] = []
        self.processes: list[Process] = []
        self.observers: dict[str, Observer] = {}
        self.devices: dict[str, dict[str, Any]] = {}
        self.workers: dict[str, Process] = {}
        self.authority: Process | None = None
        self.workspace: str | None = None
        self.dataset: dict[str, Any] | None = None
        self.env = {
            "PATH": os.defpath + ":/usr/local/bin", "LANG": "C.UTF-8",
            "HOME": str(self.root / "harness-home"), "RUST_BACKTRACE": "1",
        }
        Path(self.env["HOME"]).mkdir()
        self.summary: dict[str, Any] = {
            "format": 1, "started_unix": time.time(),
            "topology": "Book, Mini, VPS and coordinator are separate processes/roots on ONE host",
            "provider_execution": "Codex and Claude protocol fixtures only; no model calls or authentication",
            "tls": "fixture CA signs CA:false localhost/127.0.0.1 leaf; both observer hops verify CA",
            "payload_measurement": "actual application bytes forwarded by per-actor HTTPS observers; not TLS framing bytes",
            "ownership": "owner-trusted native processes; no hostile same-UID isolation claim",
            "evidence": str(self.root),
            "runtime_filesystem": {
                "path": str(self.root), "device": self.root.stat().st_dev,
                "block_size": os.statvfs(self.root).f_frsize,
                "filesystem_id": getattr(os.statvfs(self.root), "f_fsid", None),
            },
            "binaries": {"fabric": identity(self.fabric), "worker": identity(self.worker)},
            "script": identity(Path(__file__).resolve()),
            "cases": self.cases,
        }
        artifact = self.fabric.parent / "artifact.json"
        if artifact.is_file():
            self.summary["artifact_manifest"] = load(artifact)
        self.save_summary()

    def save_summary(self) -> None:
        dump(self.root / "summary.json", self.summary)

    def command_paths(self, label: str) -> tuple[Path, Path, Path]:
        self.counter += 1
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in label)[:80]
        stem = self.commands / f"{self.counter:04d}-{safe}"
        return stem.with_suffix(".stdout"), stem.with_suffix(".stderr"), stem.with_suffix(".json")

    def run(self, argv: list[Any], label: str, ok: bool = True,
            timeout: float = 100) -> CommandResult:
        command = [str(arg) for arg in argv]
        stdout, stderr, record = self.command_paths(label)
        started = time.time()
        with stdout.open("wb") as out, stderr.open("wb") as err:
            try:
                completed = subprocess.run(command, stdout=out, stderr=err, env=self.env,
                                           timeout=timeout, check=False, start_new_session=True)
            except subprocess.TimeoutExpired as error:
                dump(record, {"argv": command, "started_unix": started,
                              "timed_out": True, "timeout_seconds": timeout})
                raise JourneyFailure(f"{label} timed out; see {record}") from error
        dump(record, {"argv": command, "started_unix": started,
                      "finished_unix": time.time(), "returncode": completed.returncode})
        try:
            data = json.loads(stdout.read_text())
        except (ValueError, UnicodeError):
            data = None
        result = CommandResult(completed.returncode, data, stdout, stderr, record)
        if ok and result.returncode != 0:
            raise JourneyFailure(f"{label} failed ({result.returncode}): {result.error_text()[-4000:]}; {record}")
        if not ok and result.returncode == 0:
            raise JourneyFailure(f"{label} unexpectedly succeeded; {record}")
        return result

    def cli(self, actor: str | None, *args: Any, ok: bool = True,
            label: str | None = None, timeout: float = 100) -> CommandResult:
        argv: list[Any] = [self.fabric]
        if actor:
            argv += ["--config", self.devices[actor]["config"]]
        argv += list(args)
        return self.run(argv, label or f"{actor or 'offline'}-{'-'.join(map(str, args[:2]))}",
                        ok=ok, timeout=timeout)

    def rpc(self, actor: str, request: dict[str, Any], *, ok: bool = True,
            label: str = "rpc") -> CommandResult:
        path = self.root / "requests" / f"{unique_id()}.json"
        dump(path, request)
        return self.cli(actor, "rpc", "--request", path, ok=ok, label=f"{actor}-{label}")

    def spawn(self, argv: list[Any], label: str) -> Process:
        stdout, stderr, record = self.command_paths(label)
        command = [str(arg) for arg in argv]
        with stdout.open("wb") as out, stderr.open("wb") as err:
            process = subprocess.Popen(command, stdout=out, stderr=err,
                                       env=self.env, start_new_session=True)
        dump(record, {"argv": command, "started_unix": time.time(), "pid": process.pid})
        handle = Process(label, process, stdout, stderr, record)
        self.processes.append(handle)
        return handle

    def case(self, name: str, action: Callable[[], Any]) -> bool:
        print(f"[RUN] {name}", flush=True)
        case: dict[str, Any] = {"name": name, "started_unix": time.time()}
        self.cases.append(case)
        try:
            case["evidence"] = action()
            case["status"] = "observed"
        except Blocked as error:
            case.update(status="blocked", error=str(error))
        except Exception as error:
            case.update(status="failed", error=f"{type(error).__name__}: {error}")
            trace = self.root / f"failure-{len(self.cases):02d}.txt"
            trace.write_text(traceback.format_exc())
            case["trace"] = str(trace)
        case["finished_unix"] = time.time()
        self.save_summary()
        print(f"[{case['status'].upper()}] {name}" +
              (f": {case['error']}" if "error" in case else ""), flush=True)
        return case["status"] == "observed"

    def current(self, actor: str = "Book") -> dict[str, Any]:
        require(self.workspace, "workspace not initialized")
        return self.cli(actor, "workspace", "inspect", self.workspace).value

    def pull(self, actor: str, paths: list[str], root: Path | None = None,
             *, ok: bool = True, **kwargs: Any) -> CommandResult:
        destination = root or self.devices[actor]["working"]
        destination.mkdir(parents=True, exist_ok=True)
        argv: list[Any] = ["workspace", "pull", self.workspace, "--root",
                           destination]
        for path in paths:
            argv += ["--path", path]
        return self.cli(actor, *argv, ok=ok, **kwargs)

    def publish(self, actor: str, paths: list[str], *, ok: bool = True,
                root: Path | None = None) -> CommandResult:
        argv: list[Any] = ["workspace", "publish", self.workspace, "--root",
                           root or self.devices[actor]["working"]]
        for path in paths:
            argv += ["--path", path]
        return self.cli(actor, *argv, ok=ok, timeout=180)

    def wait(self, predicate: Callable[[], Any], description: str,
             timeout: float = 60, interval: float = .25) -> Any:
        deadline = time.monotonic() + timeout
        last: Any = None
        while time.monotonic() < deadline:
            last = predicate()
            if last:
                return last
            time.sleep(interval)
        raise JourneyFailure(f"timed out waiting for {description}; last={last!r}")

    def start_authority(self) -> None:
        self.authority = self.spawn([
            self.fabric, "serve", "--root", self.root / "authority", "--bind",
            f"127.0.0.1:{self.upstream_port}", "--tls-cert", self.cert,
            "--tls-key", self.key,
        ], "coordinator")

        def available() -> bool:
            require(self.authority is not None and self.authority.process.poll() is None,
                    "coordinator exited during startup")
            try:
                context = ssl.create_default_context(cafile=str(self.ca))
                with socket.create_connection(("127.0.0.1", self.upstream_port), timeout=.5) as sock:
                    with context.wrap_socket(sock, server_hostname="127.0.0.1"):
                        return True
            except (OSError, ssl.SSLError):
                return False
        self.wait(available, "verified coordinator HTTPS", timeout=15)

    def setup(self) -> dict[str, Any]:
        openssl = shutil.which("openssl")
        require(openssl, "openssl is required to create local CA and signed leaf fixtures")
        tls = self.root / "tls"
        tls.mkdir()
        self.ca, self.cert, self.key = tls / "ca.pem", tls / "server.pem", tls / "server.key"
        self.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                  "-keyout", tls / "ca.key", "-out", self.ca, "-subj", "/CN=MaxIO journey fixture CA",
                  "-addext", "basicConstraints=critical,CA:TRUE",
                  "-addext", "keyUsage=critical,keyCertSign,cRLSign"], "fixture-ca")
        self.run([openssl, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", self.key,
                  "-out", tls / "server.csr", "-subj", "/CN=localhost"], "fixture-leaf-csr")
        extensions = tls / "leaf.ext"
        text_file(extensions, "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n")
        self.run([openssl, "x509", "-req", "-in", tls / "server.csr", "-CA", self.ca,
                  "-CAkey", tls / "ca.key", "-CAcreateserial", "-out", self.cert,
                  "-days", "2", "-extfile", extensions], "fixture-signed-leaf")
        self.run([openssl, "verify", "-CAfile", self.ca, self.cert], "fixture-verify-chain")
        self.upstream_port = available_port()
        for name in ("Owner", "Book", "Mini", "VPS"):
            home = self.root / "devices" / name
            for directory in ("keys", "client", "working"):
                (home / directory).mkdir(parents=True)
            self.devices[name] = {
                "root": home, "key": home / "keys/device.key",
                "public": home / "keys/public.json", "config": home / "client/config.json",
                "working": home / "working", "cache": home / "cache",
            }
            self.cli(None, "keygen", "--key", self.devices[name]["key"],
                     "--public-key-out", self.devices[name]["public"], label=f"{name}-keygen")
            self.observers[name] = Observer(name, self.root, self.upstream_port,
                                            self.cert, self.key, self.ca)
        owner = self.devices["Owner"]
        initialized = self.cli(None, "init", "--root", self.root / "authority", "--owner-key",
                               owner["key"], "--name", "Journey owner", "--endpoint",
                               self.observers["Owner"].endpoint, "--ca-cert", self.ca,
                               "--client-config", owner["config"]).value
        owner["id"] = initialized["owner_device_id"]
        self.start_authority()
        self.cli("Owner", "info")
        for name in ("Book", "Mini", "VPS"):
            device = self.devices[name]
            enrolled = self.cli("Owner", "device", "enroll", "--name", name, "--public-key",
                                device["public"], "--role", "device" if name == "Book" else "worker",
                                "--write-config", device["config"], "--key-path", device["key"]).value
            device["id"] = enrolled["device"]["device_id"]
            config = load(device["config"])
            config["endpoint"] = self.observers[name].endpoint
            dump(device["config"], config)
        created = self.cli("Owner", "workspace", "create", "managed-journey").value
        self.workspace = created["workspace"]["workspace_id"]
        denied = self.cli("Book", "workspace", "inspect", self.workspace, ok=False,
                          label="Book-no-grant-rejected")
        require("forbidden" in denied.error_text().lower() or "grant" in denied.error_text().lower(),
                "unenrolled workspace authority failure was not a grant rejection")
        for name in ("Book", "Mini", "VPS"):
            self.cli("Owner", "device", "grant", "--device", self.devices[name]["id"],
                     "--workspace", self.workspace, "--catalog", "--read", ".", "--write", ".",
                     "--submit-jobs")
        ids = {name: device["id"] for name, device in self.devices.items()}
        require(len(set(ids.values())) == 4, "identities must be distinct")
        self.summary["device_ids"] = ids
        self.summary["workspace_id"] = self.workspace
        self.write_profiles()
        return {"identities": ids, "workspace_id": self.workspace,
                "Book_without_grant": str(denied.command_file), "coordinator_pid": self.authority.process.pid}

    def write_profiles(self) -> None:
        fixture = self.root / "fixtures/provider-protocol-fixture"
        text_file(fixture, f"#!{Path(sys.executable).resolve()}\n" + PROVIDER_FIXTURE, executable=True)
        for name in ("Mini", "VPS"):
            environment = {"DEVICE_LABEL": name}
            profiles = [
                {"name": label, "adapter": "command", "executable": str(Path(sys.executable).resolve()),
                 "args": [script], "permission": "workspace_write", "environment": environment}
                for label, script in (("python-hash", "src/hash_dataset.py"),
                                      ("slow-output", "src/slow_task.py"),
                                      ("long-output", "src/long_task.py"),
                                      ("quick-output", "src/quick_task.py"))
            ]
            for adapter in ("codex", "claude"):
                profiles.append({
                    "name": f"{adapter}-protocol-fixture", "adapter": adapter,
                    "executable": str(fixture), "args": [], "permission": "workspace_write",
                    "environment": {"CODEX_API_KEY" if adapter == "codex" else "ANTHROPIC_API_KEY":
                                    "fixture-only-not-a-provider-credential"},
                })
            self.devices[name]["profiles"] = self.devices[name]["root"] / "profiles.json"
            dump(self.devices[name]["profiles"], profiles)

    def seed(self) -> dict[str, Any]:
        mini = self.devices["Mini"]["working"]
        data = mini / DATASET
        data.parent.mkdir()
        digest = hashlib.sha256()
        block = hashlib.shake_256(b"MaxIO managed journey actual dataset v1").digest(MIB)
        with data.open("wb") as stream:
            for index in range(self.size // MIB):
                chunk = index.to_bytes(8, "big") + block[8:]
                stream.write(chunk)
                digest.update(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        self.dataset = identity(data)
        require(self.dataset["size"] == self.size and self.dataset["sha256"] == digest.hexdigest(),
                "dataset generation identity mismatch")
        require(self.dataset["allocated_bytes"] >= self.size,
                "dataset is sparse or physical allocation cannot be established on this filesystem")
        self.summary["dataset"] = self.dataset
        text_file(mini / "docs/readme.md", "Managed journey notes, revision one.\n")
        text_file(mini / "docs/guide.txt", "Only selected files should be hydrated.\n")
        text_file(mini / "control/lease-target.txt", "Last committed text remains readable under a lease.\n")
        text_file(mini / "src/hash_dataset.py", HASH_TASK)
        text_file(mini / "src/slow_task.py", output_task("results/conflict.txt", 8))
        text_file(mini / "src/long_task.py", output_task("results/long.txt", 20))
        text_file(mini / "src/quick_task.py", output_task("results/quick.txt", 0))
        text_file(mini / "src/provider-context.txt", "This is an explicit protocol fixture, with no model calls.\n")
        text_file(mini / "assets/failure.bin", "transfer-failure-fixture\n" * (4 * MIB // 25))
        seed = self.publish("Mini", ["docs", "control", "src", "assets", DATASET])
        self.seed_catalog = self.current()
        references = self.cli("Mini", "workspace", "references", self.workspace,
                              "--path", DATASET).value
        self.dataset_refs = self.root / "references/dataset.json"
        dump(self.dataset_refs, references)
        before = self.observers["Mini"].payload(DATASET)
        imported = self.cli("Mini", "cache", "import", "--root", self.devices["Mini"]["cache"],
                            "--references", self.dataset_refs, "--source", data)
        require(self.observers["Mini"].payload(DATASET) == before == 0,
                "local cache import downloaded the dataset")
        return {"dataset": self.dataset, "seed": str(seed.command_file),
                "Mini_cache_import": str(imported.command_file), "references": str(self.dataset_refs)}

    def selective_workspace(self) -> dict[str, Any]:
        require(self.dataset, "dataset was not seeded")
        transfer_evidence = {}
        for name in ("Book", "Mini", "VPS"):
            before = self.observers[name].payload()
            result = self.pull(name, [])
            require(self.observers[name].payload() == before, "metadata-only pull transferred a file")
            require(result.data["transfers"]["payload_downloaded"] == 0,
                    "metadata-only CLI counter reports a payload")
            transfer_evidence[name] = str(result.command_file)
        for name in ("Book", "VPS"):
            result = self.pull(name, ["docs"])
            expected = sum(version["size"] for path, version in self.seed_catalog["snapshot"]["manifest"]["files"].items()
                           if path.startswith("docs/"))
            require(result.data["transfers"]["payload_downloaded"] == expected,
                    "selected docs transfer did not equal selected file lengths")
            require(not (self.devices[name]["working"] / DATASET).exists(),
                    f"{name} unexpectedly has the dataset")
        require(all(observer.payload(DATASET) == 0 for observer in self.observers.values()),
                "metadata/docs selection downloaded dataset bytes")
        book = self.devices["Book"]["working"]
        vps = self.devices["VPS"]["working"]
        text_file(book / "docs/readme.md", "Book selected edit, revision two.\n")
        text_file(book / "notes/unpublished.txt", "Book unpublished note must remain local.\n")
        # Removing an owned disposable local file is not a global delete request.
        (book / "docs/guide.txt").unlink()
        selected = self.publish("Book", ["docs/readme.md"])
        published = self.current()
        files = published["snapshot"]["manifest"]["files"]
        require("notes/unpublished.txt" not in files and "docs/guide.txt" in files,
                "selected publication uploaded unrelated bytes or propagated local absence")
        require(files["docs/readme.md"]["sha256"] == identity(book / "docs/readme.md")["sha256"],
                "selected publication has wrong content")
        text_file(vps / "docs/readme.md", "VPS divergent unpublished edit must survive.\n")
        divergent = identity(vps / "docs/readme.md")
        rejected = self.publish("VPS", ["docs/readme.md"], ok=False)
        require("conflict" in rejected.error_text().lower(), "stale publication did not report conflict")
        self.pull("VPS", ["docs/readme.md"], ok=False, label="VPS-dirty-pull-rejected")
        require(identity(vps / "docs/readme.md")["sha256"] == divergent["sha256"],
                "conflict handling changed the unpublished edit")
        self.pull("Mini", ["docs"])
        require((self.devices["Mini"]["working"] / "docs/readme.md").read_bytes() ==
                (book / "docs/readme.md").read_bytes(), "clean device did not refresh selected edit")
        old = self.current()
        revision = old["head"]["revision"]
        deleted = self.cli("Book", "workspace", "delete", self.workspace,
                           "--path", "docs/guide.txt", "--confirm")
        require("docs/guide.txt" not in self.current()["snapshot"]["manifest"]["files"],
                "explicit logical deletion did not remove catalog path")
        historical = self.cli("Book", "workspace", "inspect", self.workspace,
                              "--revision", revision["revision"], "--sha256", revision["sha256"])
        require("docs/guide.txt" in historical.value["snapshot"]["manifest"]["files"],
                "logical deletion lost the retained historical reference")
        restored = self.cli("Book", "workspace", "restore", self.workspace, "--path", "docs/guide.txt",
                            "--revision", revision["revision"], "--sha256", revision["sha256"], "--confirm")
        self.pull("Book", ["docs/guide.txt"])
        require(identity(book / "docs/guide.txt")["sha256"] ==
                old["snapshot"]["manifest"]["files"]["docs/guide.txt"]["sha256"],
                "restored bytes differ from the retained exact version")
        self.divergent = divergent
        return {"metadata_only": transfer_evidence, "selected_publication": str(selected.command_file),
                "conflict_rejection": str(rejected.command_file), "preserved_VPS_edit": divergent,
                "logical_delete": str(deleted.command_file), "restore": str(restored.command_file),
                "Book_dataset_download_bytes": self.observers["Book"].payload(DATASET)}

    def start_worker(self, name: str) -> Process:
        previous = self.workers.get(name)
        if previous and previous.process.poll() is None:
            return previous
        device = self.devices[name]
        worker = self.spawn([
            self.worker, "--config", device["config"], "--root", device["cache"],
            "--profiles", device["profiles"], "--display-name", f"{name} on one-host journey",
            "--poll-ms", "250", "--renew-ms", "500", "--lease-seconds", "4",
        ], f"{name}-worker")
        self.workers[name] = worker

        def advertised() -> Any:
            require(worker.process.poll() is None,
                    f"{name} worker exited: {worker.stderr.read_text(errors='replace')[-3000:]}")
            rows = self.cli("Book", "workers").value["workers"]
            return next((row for row in rows if row["advertisement"]["worker_id"] == device["id"]
                         and row["eligible_until_unix_ms"] > time.time() * 1000), None)
        self.wait(advertised, f"{name} live worker advertisement", timeout=20)
        return worker

    def submit(self, profile: str, inputs: list[str], output: str, *, worker: str | None = None,
               publish: bool = True, prompt: Path | None = None) -> dict[str, Any]:
        argv: list[Any] = ["task", "submit", self.workspace, "--profile", profile,
                           "--output", output, "--timeout", "60"]
        for path in inputs:
            argv += ["--input", path]
        if worker:
            argv += ["--worker", self.devices[worker]["id"]]
        if publish:
            argv += ["--publish"]
        if prompt:
            argv += ["--prompt-file", prompt]
        return self.cli("Book", *argv).value["job"]

    def job(self, job_id: str) -> dict[str, Any]:
        return self.cli("Book", "task", "status", job_id).value["job"]

    def completed(self, job_id: str, *, publication: bool = False,
                  timeout: float = 70) -> dict[str, Any]:
        def done() -> Any:
            job = self.job(job_id)
            if publication:
                if job["attempts"] and job["attempts"][-1].get("publication"):
                    return job
                require(job["state"] not in TERMINAL - {"succeeded"},
                        f"job terminated without publication: {json.dumps(job)}")
            elif job["state"] in TERMINAL:
                return job
            return None
        return self.wait(done, f"job {job_id} {'durable publication' if publication else 'terminal state'}",
                         timeout=timeout, interval=.4)

    def attempt_root(self, name: str, attempt: dict[str, Any]) -> Path:
        return self.devices[name]["cache"] / "attempts" / attempt["binding"]["attempt_id"]

    def run_record(self, attempt_root: Path) -> dict[str, Any] | None:
        records = list((attempt_root / "runs").glob("*/record.json"))
        require(len(records) <= 1, "one attempt unexpectedly created multiple local runs")
        return load(records[0]) if records else None

    def running_output(self, job_id: str, name: str, output: str) -> tuple[dict[str, Any], dict[str, Any]]:
        def started() -> Any:
            job = self.job(job_id)
            if job["state"] != "running" or not job["attempts"]:
                return None
            attempt = job["attempts"][-1]
            # A killed worker may leave its local RunRecord saying "running".
            # Only fresh authority state establishes that a retry actually began.
            if attempt["state"] != "running":
                return None
            run = self.run_record(self.attempt_root(name, attempt))
            if run and run["status"] == "running" and (Path(run["workspace"]) / output).is_file():
                if attempt["heartbeat_at_unix_ms"] >= attempt["claimed_at_unix_ms"]:
                    return job, run
            return None
        return self.wait(started, f"real {name} command and retained output", timeout=30)

    def data_local_execution(self) -> dict[str, Any]:
        require(self.dataset, "dataset not initialized")
        self.start_worker("Mini")
        self.start_worker("VPS")
        before = {name: observer.payload(DATASET) for name, observer in self.observers.items()}
        submitted = self.submit("python-hash", [DATASET, "src/hash_dataset.py"], "results/hash.json")
        decision = submitted["decision"]
        candidates = {row["worker_id"]: row for row in decision["candidates"]}
        mini, vps = self.devices["Mini"]["id"], self.devices["VPS"]["id"]
        require(candidates[mini]["eligible"] and candidates[vps]["eligible"],
                "both actual workers must be eligible for locality comparison")
        script_size = self.seed_catalog["snapshot"]["manifest"]["files"]["src/hash_dataset.py"]["size"]
        require(candidates[mini]["missing_bytes"] == script_size,
                "Mini missing-byte count does not equal only the tiny source")
        require(candidates[vps]["missing_bytes"] == self.size + script_size,
                "VPS missing-byte count does not include the resident-Mini dataset")
        require(decision["selected_worker"] == mini, "authority did not select the data-local Mini")
        job = self.completed(submitted["job_id"], publication=True)
        attempt = job["attempts"][-1]
        require(attempt["binding"]["worker_id"] == mini, "wrong worker executed the selected job")
        self.pull("Book", ["results/hash.json"])
        result_path = self.devices["Book"]["working"] / "results/hash.json"
        result = load(result_path)
        require(result["sha256"] == self.dataset["sha256"] and result["size"] == self.size,
                "actual Python result does not match the seeded dataset")
        require(result["device_label"] == "Mini" and result["pid"] != self.workers["Mini"].process.pid,
                "result does not identify a real separate Mini command")
        root = self.attempt_root("Mini", attempt)
        hydration = load(root / "hydration.json")
        require(hydration["transfer"]["payload_downloaded"] == script_size,
                "Mini hydrated more than the selected tiny source")
        require(any(item["path"] == DATASET for item in hydration["reused"]),
                "worker did not reuse the imported immutable dataset")
        run = attempt["run"]
        require(run["adapter"] == "command" and run["status"] == "succeeded" and not run["published"],
                "execution record does not distinguish execution from publication")
        expected = {item["path"]: (item["version"]["sha256"], item["version"]["size"])
                    for item in job["inputs"]}
        require({item["path"]: (item["sha256"], item["size"]) for item in run["input_files"]} == expected,
                "run inputs are not the admitted exact identities")
        require(attempt["publication"]["attempt"] == attempt["binding"],
                "publication receipt does not bind this exact attempt")
        log = self.cli("Book", "task", "logs", job["job_id"], "--attempt",
                       attempt["binding"]["attempt_id"]).value["page"]
        log_bytes = base64.b64decode(log["data_base64"])
        # The runner deliberately redacts explicit environment values from logs.
        # Device identity is checked in the published result and attempt binding.
        require(self.dataset["sha256"].encode() in log_bytes and b"hash_result" in log_bytes,
                "actual hash command logs are unavailable")
        (self.root / "hash-job-remote-stdout.log").write_bytes(log_bytes)
        require(self.observers["Book"].payload(DATASET) == before["Book"] == 0,
                "submitting Book received dataset payload")
        require(self.observers["Mini"].payload(DATASET) == before["Mini"] == 0,
                "Mini redownloaded its imported dataset during the job")
        require(self.observers["VPS"].payload(DATASET) == before["VPS"] == 0,
                "unselected VPS downloaded the dataset")
        objects = list((self.devices["Mini"]["cache"] / "cache/objects").glob(f"*-{self.dataset['sha256']}-{self.size}"))
        require(len(objects) == 1, "expected one private immutable dataset cache entry")
        copies = [identity(path) for path in (objects[0], root / "source" / DATASET,
                                              Path(run["workspace"]) / DATASET,
                                              self.devices["Mini"]["working"] / DATASET)]
        require(len({(item["device"], item["inode"]) for item in copies}) == 4 and
                all(item["links"] == 1 for item in copies),
                "mutable task/working data aliases the private cache inode")
        self.hash_job = job
        return {"job": job, "placement": decision, "result": result, "hydration": hydration,
                "independent_input_copies": copies, "Book_dataset_bytes": 0,
                "Mini_dataset_redownload_bytes": 0, "VPS_dataset_bytes": 0,
                "actual_worker_pids": {name: handle.process.pid for name, handle in self.workers.items()}}

    def provider_fixtures(self) -> dict[str, Any]:
        self.start_worker("Mini")
        prompt = self.root / "fixtures/prompt.txt"
        text_file(prompt, "worker protocol fixture prompt")
        evidence = {}
        for adapter in ("codex", "claude"):
            output = f"results/{adapter}-fixture.json"
            submitted = self.submit(f"{adapter}-protocol-fixture", ["src/provider-context.txt"],
                                    output, worker="Mini", prompt=prompt)
            job = self.completed(submitted["job_id"], publication=True)
            attempt = job["attempts"][-1]
            require(attempt["run"]["adapter"] == adapter and
                    attempt["run"]["provider_session_id"] == "journey-protocol-fixture",
                    f"{adapter} existing adapter protocol path was not exercised")
            self.pull("Book", [output])
            result = load(self.devices["Book"]["working"] / output)
            require(result == {"adapter": adapter, "fixture_only": True},
                    "provider fixture result is wrong or incorrectly labelled")
            evidence[adapter] = {"job": job, "result": result}
        return evidence

    def lost_acknowledgments(self) -> dict[str, Any]:
        self.start_worker("Mini")
        observer = self.observers["Mini"]
        finish = observer.arm(Fault("lost-finish-ack", "/v1/control", "drop_response",
                                    operation="finish_attempt", remaining=2))
        publish = observer.arm(Fault("lost-publication-ack", "/v1/control", "drop_response",
                                     operation="publish", remaining=2))
        submitted = self.submit("quick-output", ["src/quick_task.py"], "results/quick.txt", worker="Mini")
        job = self.completed(submitted["job_id"], publication=True)
        require(finish.matched == 2 and publish.matched == 2,
                "both attempts at each acknowledgment were not actually lost")
        events = [event for event in observer.snapshot() if event.get("fault") in
                  {finish.name, publish.name}]
        require(all(event.get("upstream_acknowledged") for event in events),
                "faults did not occur after durable upstream acknowledgments")
        for fault in (finish, publish):
            require(len({event["request_id"] for event in events if event.get("fault") == fault.name}) == 1,
                    "ambiguous retry changed its durable request identity")
        require(len(job["attempts"]) == 1, "lost acknowledgments reran the task")
        attempt = job["attempts"][0]
        receipt = attempt["publication"]
        # Mutation idempotency receipts are scoped to the publishing actor. The
        # submitting Book sees the same receipt through its authorized job view.
        lookup = self.rpc("Mini", {"op": "publication_status", "request_id": receipt["request_id"]}).value
        require(lookup["receipt"] == receipt, "receipt lookup disagrees with committed job publication")
        records = list((self.attempt_root("Mini", attempt) / "runs").glob("*/record.json"))
        require(len(records) == 1, "ack recovery created another local command run")
        return {"job": job, "injected_ack_losses": events, "run_record": str(records[0])}

    def stop_workers(self) -> None:
        for worker in self.workers.values():
            worker.stop()

    def cache_recovery(self) -> dict[str, Any]:
        self.stop_workers()
        cache = self.devices["Mini"]["cache"]
        inventory = self.cli(None, "cache", "inspect", "--root", cache, "--verify").value
        row = next(row for row in inventory["entries"]
                   if any(ref["path"] == DATASET for ref in row["references"]))
        object_path = cache / "cache/objects" / row["key"]
        original = identity(object_path)
        self.cli(None, "cache", "pin", "--root", cache, "--references", self.dataset_refs)
        pinned = self.cli("Mini", "cache", "evict", "--root", cache, "--references",
                          self.dataset_refs, "--confirm", ok=False, label="pinned-eviction-refused")
        require("pin" in pinned.error_text().lower(), "pinned eviction failed for an unrelated reason")
        require(identity(object_path)["sha256"] == original["sha256"], "pin refusal removed content")
        self.cli(None, "cache", "pin", "--root", cache, "--references", self.dataset_refs, "--unpin")
        proof_failure = self.observers["Mini"].arm(Fault(
            "eviction-retention-unavailable", "/v1/control", "reject", operation="verify_retention"))
        no_proof = self.cli("Mini", "cache", "evict", "--root", cache, "--references",
                            self.dataset_refs, "--confirm", ok=False, label="eviction-no-fresh-proof")
        require(proof_failure.matched == 1 and object_path.exists(),
                "eviction without fresh proof was not refused before deletion")
        gate = self.observers["Mini"].arm(Fault(
            "interrupt-eviction-before-proof-delivery", "/v1/control", "pause_response",
            operation="verify_retention"))
        eviction = self.spawn([self.fabric, "--config", self.devices["Mini"]["config"],
                               "cache", "evict", "--root", cache, "--references",
                               self.dataset_refs, "--confirm"], "interrupted-cache-eviction")
        try:
            require(gate.ready.wait(15), "eviction did not reach fresh-retention response gate")
            eviction.stop(abrupt=True)
        finally:
            gate.release.set()
        after_interrupt = self.cli(None, "cache", "inspect", "--root", cache, "--verify").value
        require(identity(object_path)["sha256"] == original["sha256"],
                "interrupted pre-unlink eviction lost its input")
        evicted = self.cli("Mini", "cache", "evict", "--root", cache,
                           "--references", self.dataset_refs, "--confirm").value
        require(not object_path.exists() and evicted["logical_bytes_removed"] == self.size and
                evicted["allocated_bytes_unlinked"] > 0,
                "safe eviction did not unlink the selected private allocated bytes")
        require(evicted["observed_available_delta"] > 0,
                f"space reclamation was not measurable; shared filesystem noise: {evicted}")
        working = identity(self.devices["Mini"]["working"] / DATASET)
        require(working["sha256"] == original["sha256"], "eviction removed the editable source")
        before = self.observers["Mini"].payload(DATASET)
        hydration = self.cli("Mini", "cache", "hydrate", "--root", cache,
                             "--references", self.dataset_refs).value
        require(self.observers["Mini"].payload(DATASET) - before == self.size,
                "refetch did not transfer the selected dataset exactly once")
        copied = self.devices["Mini"]["root"] / "refetched"
        copied.mkdir()
        self.cli(None, "cache", "copy", "--root", cache, "--references", self.dataset_refs,
                 "--destination", copied)
        recovered = identity(copied / DATASET)
        require(recovered["sha256"] == original["sha256"], "refetched content hash differs")
        return {"pinned_refusal": str(pinned.command_file), "proof_refusal": str(no_proof.command_file),
                "interruption": "SIGKILL while verified proof response was withheld, before unlink",
                "after_interruption": after_interrupt, "eviction": evicted,
                "retained_editable_original": working, "refetch": hydration, "recovered": recovered}

    def lease(self, actor: str, path: str, ttl: int) -> dict[str, Any]:
        return self.cli(actor, "lease", "acquire", self.workspace,
                        "--scope", path, "--ttl", ttl).value

    def release_lease(self, actor: str, lease: dict[str, Any]) -> None:
        self.rpc(actor, {"op": "release_lease", "request_id": unique_id(),
                         "workspace_id": self.workspace, "lease": lease["token"]})

    def rejected_delete(self, actor: str, lease: dict[str, Any], catalog: dict[str, Any]) -> CommandResult:
        path = "control/lease-target.txt"
        result = self.rpc(actor, {"op": "delete", "context": {
            "request_id": unique_id(), "workspace_id": self.workspace, "base": catalog["head"],
            "lease": lease["token"], "attempt": None,
        }, "path": path, "expected": catalog["snapshot"]["manifest"]["files"][path]},
                          ok=False, label="stale-publication-rejected")
        require(any(term in result.error_text().lower() for term in ("lease", "fence", "epoch", "expired")),
                "stale publication was rejected for an unrelated invalid request")
        require(self.current()["head"] == catalog["head"], "stale publication changed the head")
        return result

    def leases_and_restart(self) -> dict[str, Any]:
        self.stop_workers()
        catalog = self.current()
        first = self.lease("Book", "control/lease-target.txt", 2)
        overlap = self.cli("VPS", "lease", "acquire", self.workspace,
                           "--scope", "control/lease-target.txt", "--ttl", 10, ok=False)
        require("conflict" in overlap.error_text().lower() or "overlap" in overlap.error_text().lower(),
                "overlapping independently authenticated lease was not denied")
        committed = self.devices["VPS"]["root"] / "committed-while-leased"
        self.pull("VPS", ["control/lease-target.txt"], committed)
        require(identity(committed / "control/lease-target.txt")["sha256"] ==
                catalog["snapshot"]["manifest"]["files"]["control/lease-target.txt"]["sha256"],
                "read under another actor's lease did not return last committed bytes")
        time.sleep(2.2)
        second = self.lease("VPS", "control/lease-target.txt", 20)
        require(second["token"]["fence"] > first["token"]["fence"], "lease fence did not increase")
        stale = self.rejected_delete("Book", first, catalog)
        self.release_lease("VPS", second)
        pre_restart = self.lease("Book", "control/lease-target.txt", 30)
        old_info = self.cli("Book", "info").value["info"]
        require(self.authority is not None, "no coordinator process")
        self.authority.stop(abrupt=True)
        offline = self.cli(None, "workspace", "status", "--root", self.devices["Book"]["working"], "--verify")
        self.start_authority()
        new_info = self.cli("Book", "info").value["info"]
        require(new_info["epoch"] > old_info["epoch"], "restart did not advance coordinator epoch")
        require(self.current()["head"] == catalog["head"], "restart lost exact committed head")
        replacement = self.lease("VPS", "control/lease-target.txt", 20)
        require(replacement["token"]["fence"] > pre_restart["token"]["fence"],
                "restart reused an earlier fence")
        stale_restart = self.rejected_delete("Book", pre_restart, catalog)
        self.release_lease("VPS", replacement)
        if hasattr(self, "divergent"):
            require(identity(self.devices["VPS"]["working"] / "docs/readme.md")["sha256"] ==
                    self.divergent["sha256"], "restart changed divergent unpublished work")
        require("docs/guide.txt" in self.current()["snapshot"]["manifest"]["files"],
                "logical restore was not durable across restart")
        return {"first_lease": first, "replacement_after_expiry": second,
                "stale_delete": str(stale.command_file), "pre_restart": pre_restart,
                "replacement_after_restart": replacement, "old_epoch": old_info["epoch"],
                "new_epoch": new_info["epoch"], "stale_epoch_delete": str(stale_restart.command_file),
                "offline_inspection": str(offline.command_file), "durable_head": catalog["head"]}

    def stale_attempt(self, name: str, job: dict[str, Any], attempt: dict[str, Any]) -> dict[str, Any]:
        renew = self.rpc(name, {"op": "renew_attempt", "request_id": unique_id(),
                               "attempt": attempt["binding"], "lease": attempt["lease"],
                               "ttl_seconds": 4}, ok=False, label="stale-attempt-renewal")
        output = job["output_selectors"][0]["path"]
        current = self.current()
        publication = {"context": {
            "request_id": unique_id(), "workspace_id": self.workspace, "base": job["base"],
            "lease": attempt["lease"], "attempt": attempt["binding"],
        }, "changes": [{"kind": "restore", "path": output,
                        "from_revision": job["base"]["revision"],
                        "source_path": "control/lease-target.txt",
                        "expected": current["snapshot"]["manifest"]["files"].get(output)}]}
        rejected = self.rpc(name, {"op": "publish", "publication": publication},
                            ok=False, label="stale-attempt-publication")
        require(any(word in rejected.error_text().lower() for word in
                    ("attempt", "lease", "incarnation", "fence", "epoch")),
                "stale attempt publication was rejected for an unrelated malformed request")
        require(self.current()["head"] == current["head"], "stale attempt changed the head")
        return {"renewal": str(renew.command_file), "publication": str(rejected.command_file)}

    def conflicting_workers(self) -> dict[str, Any]:
        self.start_worker("Mini")
        self.start_worker("VPS")
        first = self.submit("slow-output", ["src/slow_task.py"], "results/conflict.txt",
                            worker="Mini", publish=False)
        running, run = self.running_output(first["job_id"], "Mini", "results/conflict.txt")
        old = running["attempts"][-1]
        second = self.submit("slow-output", ["src/slow_task.py"], "results/conflict.txt",
                             worker="VPS", publish=False)
        placement = self.cli("Book", "task", "explain", second["job_id"]).value["decision"]
        require(placement["selected_worker"] is None and
                any("lease" in reason.lower() or "overlap" in reason.lower()
                    for row in placement["candidates"] for reason in row["reasons"]),
                "second real worker job was not queued behind the overlapping scope")
        require(not self.job(second["job_id"])["attempts"], "overlapping jobs ran simultaneously")
        dirty = Path(run["workspace"]) / "results/conflict.txt"
        require(dirty.is_file(), "first worker had no retained unpublished bytes before kill")
        self.workers["Mini"].stop(abrupt=True)
        abandoned = self.completed(first["job_id"], timeout=20)
        require(abandoned["state"] == "abandoned", "disappeared worker was not marked abandoned")
        finished_second = self.completed(second["job_id"], timeout=25)
        require(finished_second["state"] == "succeeded" and
                finished_second["attempts"][-1]["binding"]["worker_id"] == self.devices["VPS"]["id"],
                "the waiting VPS job did not run after old authority expired")
        require(finished_second["attempts"][-1]["publication"] is None,
                "retain-only output was unexpectedly published")
        rejected = self.stale_attempt("Mini", first, old)
        preserved = identity(dirty)
        self.start_worker("Mini")
        after_restart = self.job(first["job_id"])
        require(after_restart["state"] == "abandoned" and len(after_restart["attempts"]) == 1,
                "worker reconciliation automatically retried abandoned work")
        self.cli("Book", "task", "retry", first["job_id"], "--previous-attempt", old["binding"]["attempt_id"])
        retry_running, _ = self.running_output(first["job_id"], "Mini", "results/conflict.txt")
        retry_authority = retry_running["attempts"][-1]
        rejected_after_reassignment = self.stale_attempt("Mini", first, old)
        recovered = self.completed(first["job_id"], timeout=25)
        require(recovered["state"] == "succeeded" and len(recovered["attempts"]) == 2,
                "explicit manual retry did not create exactly one fresh successful attempt")
        latest = recovered["attempts"][-1]
        require(latest["binding"]["attempt_id"] != old["binding"]["attempt_id"] and
                retry_authority["lease"]["fence"] > old["lease"]["fence"],
                "manual recovery reused old attempt authority")
        require(identity(dirty)["sha256"] == preserved["sha256"],
                "manual recovery modified the abandoned attempt's bytes")
        return {"queued_conflicting_job": second, "placement": placement,
                "abandoned": abandoned, "waiting_job_completed": finished_second,
                "stale_authority_rejections": rejected, "retained_old_work": preserved,
                "superseded_attempt_rejections": rejected_after_reassignment,
                "manual_recovery": recovered}

    def cancellation(self) -> dict[str, Any]:
        self.start_worker("Mini")
        submitted = self.submit("long-output", ["src/long_task.py"], "results/long.txt", worker="Mini")
        running, run = self.running_output(submitted["job_id"], "Mini", "results/long.txt")
        self.cli("Book", "task", "cancel", submitted["job_id"])
        job = self.completed(submitted["job_id"], timeout=20)
        require(job["state"] == "cancelled", "explicit running cancellation did not become cancelled")
        root = self.attempt_root("Mini", running["attempts"][-1])
        local_run = self.wait(lambda: (record if (record := self.run_record(root)) and
                                      record["status"] == "cancelled" else None),
                              "cancelled local runner record", timeout=15)
        retained = identity(Path(run["workspace"]) / "results/long.txt")
        require(job["attempts"][-1]["publication"] is None,
                "cancelled attempt published a candidate")
        return {"job": job, "local_run": local_run, "retained_unpublished_output": retained}

    def transfer_interruptions(self) -> dict[str, Any]:
        observer = self.observers["Book"]
        path = "assets/failure.bin"
        version = self.current()["snapshot"]["manifest"]["files"][path]
        target = self.devices["Book"]["root"] / "interrupted-download"
        fault = observer.arm(Fault("interrupted-selected-download", "/v1/file/read", "cut_download",
                                   file_path=path))
        failed_pull = self.pull("Book", [path], target, ok=False, label="interrupted-selected-download")
        require(fault.matched == 1,
                "download fault did not run; inspect the CLI failure before claiming transfer behavior")
        require(not (target / path).exists(),
                "partial download was installed as a complete editable file")
        partials = [{"path": str(item), "size": item.stat().st_size} for item in target.rglob("*")
                    if item.is_file() and 0 < item.stat().st_size < version["size"]
                    and item.name not in {"state.json", "lock"}]
        require(any(item["size"] == fault.cut_bytes for item in partials),
                "interrupted download did not retain the observed partial payload")
        self.pull("Book", [path], target)
        recovered = identity(target / path)
        require(recovered["sha256"] == version["sha256"], "download recovery has wrong bytes")
        upload_path = "assets/upload-interrupted.bin"
        source = self.devices["Book"]["working"] / upload_path
        source.parent.mkdir(exist_ok=True)
        source.write_bytes(hashlib.shake_256(b"upload interruption fixture").digest(4 * MIB))
        original = identity(source)
        before = self.current()
        spools = set((self.root / "authority/transport-spool").glob("*"))
        fault_upload = observer.arm(Fault("interrupted-selected-upload", "/v1/file/upload", "cut_upload",
                                          file_path=upload_path))
        failed_publish = self.publish("Book", [upload_path], ok=False)
        require(fault_upload.matched == 1 and self.current()["head"] == before["head"],
                "interrupted upload changed the committed head")
        require(identity(source)["sha256"] == original["sha256"], "interrupted upload changed local edits")
        def partial_uploads() -> Any:
            rows = [{"path": str(item / "body"), "size": (item / "body").stat().st_size}
                    for item in set((self.root / "authority/transport-spool").glob("*")) - spools
                    if (item / "body").is_file() and 0 < (item / "body").stat().st_size < original["size"]]
            return rows or None
        retained_uploads = self.wait(partial_uploads, "server-retained interrupted upload", timeout=8)
        self.publish("Book", [upload_path])
        require(self.current()["snapshot"]["manifest"]["files"][upload_path]["sha256"] == original["sha256"],
                "manual upload recovery did not publish the original edit")
        return {"download_failure": str(failed_pull.command_file), "retained_download_partials": partials,
                "recovered_download": recovered, "upload_failure": str(failed_publish.command_file),
                "retained_upload_partials": retained_uploads, "preserved_local_upload": original}

    def renewal_failure(self) -> dict[str, Any]:
        self.start_worker("Mini")
        submitted = self.submit("long-output", ["src/long_task.py"], "results/long.txt", worker="Mini")
        running, run = self.running_output(submitted["job_id"], "Mini", "results/long.txt")
        fault = self.observers["Mini"].arm(Fault("running-attempt-renewal-unavailable", "/v1/control",
                                               "reject", operation="renew_attempt", remaining=2))
        root = self.attempt_root("Mini", running["attempts"][-1])
        local = self.wait(lambda: (record if (record := self.run_record(root)) and
                                  record["status"] in TERMINAL else None),
                          "local cancellation after failed authority renewal", timeout=20)
        require(fault.matched == 2 and local["status"] == "cancelled",
                "failed renewals did not stop the actual running command")
        job = self.completed(submitted["job_id"], timeout=15)
        require(job["attempts"][-1]["publication"] is None, "renewal failure still published output")
        retained = identity(Path(run["workspace"]) / "results/long.txt")
        return {"job": job, "local_run": local, "retained_unpublished_output": retained,
                "injected_renewal_rejections": fault.matched}

    def prepared_publication_conflict(self) -> dict[str, Any]:
        if self.workers.get("Mini"):
            self.workers["Mini"].stop()
        self.start_worker("Mini")
        gate = self.observers["Mini"].arm(Fault("prepared-output-head-conflict", "/v1/control",
                                              "pause_before", operation="publish"))
        submitted = self.submit("quick-output", ["src/quick_task.py"], "results/quick.txt", worker="Mini")
        try:
            require(gate.ready.wait(20), "worker never reached prepared final publication")
            base = submitted["base"]["revision"]
            moved = self.cli("Owner", "workspace", "restore", self.workspace,
                             "--path", "control/conflict-head.txt", "--revision", base["revision"],
                             "--sha256", base["sha256"], "--source-path", "control/lease-target.txt", "--confirm")
            current = self.current()
        finally:
            gate.release.set()
        job = self.wait(lambda: (job if (job := self.job(submitted["job_id"]))["attempts"] else None),
                        "conflicting attempt record", timeout=10)
        attempt = job["attempts"][-1]
        root = self.attempt_root("Mini", attempt)
        local = self.wait(lambda: (record if (record := load(root / "attempt.json"))["phase"] == "retained" else None),
                          "retained prepared output after head conflict", timeout=20)
        require(local["outputs"] and all(item["prepared"] for item in local["outputs"]),
                "conflict happened before actual output upload/preparation")
        require(local["publication"] is None and self.current()["head"] == current["head"],
                "conflicting publication unexpectedly committed")
        retained = [identity(root / "outputs" / item["stage_name"]) for item in local["outputs"]]
        job = self.completed(submitted["job_id"], timeout=12)
        require(job["state"] != "succeeded" and job["attempts"][-1]["publication"] is None,
                "authority reported success or attached a receipt to the conflicting output")
        return {"job": job, "local_attempt": local, "retained_candidates": retained,
                "concurrent_head_change": str(moved.command_file), "winning_head": current["head"]}

    def coordinator_interruption(self) -> dict[str, Any]:
        self.stop_workers()
        self.start_worker("Mini")
        submitted = self.submit("long-output", ["src/long_task.py"], "results/long.txt", worker="Mini")
        running, run = self.running_output(submitted["job_id"], "Mini", "results/long.txt")
        old = running["attempts"][-1]
        before = self.cli("Book", "info").value["info"]
        require(self.authority is not None, "no coordinator to interrupt")
        self.authority.stop(abrupt=True)
        root = self.attempt_root("Mini", old)
        local = self.wait(lambda: (record if (record := self.run_record(root)) and
                                  record["status"] == "cancelled" else None),
                          "running command cancellation during coordinator outage", timeout=25)
        self.workers["Mini"].stop()
        offline = self.cli(None, "workspace", "status", "--root", self.devices["Book"]["working"], "--verify")
        self.start_authority()
        after = self.cli("Book", "info").value["info"]
        require(after["epoch"] > before["epoch"], "coordinator outage did not fence old authority")
        job = self.job(submitted["job_id"])
        require(job["state"] == "abandoned" and len(job["attempts"]) == 1,
                "coordinator restart did not retain one abandoned attempt")
        rejection = self.stale_attempt("Mini", submitted, old)
        retained = identity(Path(run["workspace"]) / "results/long.txt")
        self.start_worker("Mini")
        reconciled = self.job(submitted["job_id"])
        require(len(reconciled["attempts"]) == 1 and reconciled["state"] == "abandoned",
                "restart reconciliation reran an unapproved abandoned command")
        return {"old_epoch": before["epoch"], "new_epoch": after["epoch"], "job": job,
                "local_run": local, "retained_unpublished_output": retained,
                "stale_attempt_rejection": rejection, "offline_status": str(offline.command_file)}

    def final_checks(self) -> dict[str, Any]:
        self.stop_workers()
        require(self.observers["Book"].payload(DATASET) == 0,
                "Book received dataset bytes in some later scenario")
        files = [item for item in self.devices["Book"]["root"].rglob("*") if item.is_file()]
        require(not any(item.name == "dataset.bin" or item.stat().st_size >= self.size for item in files),
                "Book contains an unexpected dataset-sized local artifact")
        self.cli("Owner", "device", "revoke", "--device", self.devices["VPS"]["id"], "--confirm")
        revoked = self.cli("VPS", "workspace", "inspect", self.workspace, ok=False,
                           label="revoked-VPS-read-rejected")
        return {"Book_dataset_download_bytes_across_entire_run": 0,
                "Book_local_files_checked": len(files), "revoked_VPS_rejection": str(revoked.command_file)}

    def finish(self) -> int:
        for process in reversed(self.processes):
            process.stop()
        for observer in self.observers.values():
            observer.close()
        self.summary["finished_unix"] = time.time()
        self.summary["processes"] = [{"label": process.label, "pid": process.process.pid,
                                       "returncode": process.process.poll(), "stdout": str(process.stdout),
                                       "stderr": str(process.stderr), "command": str(process.command_file)}
                                      for process in self.processes]
        self.summary["not_exercised"] = [
            "Physical MacBook/Mini/VPS devices, WAN/NAT traversal, network partitions between machines.",
            "Authenticated Codex/Claude model calls (only labelled protocol fixtures were run).",
            "Host power loss or interruption after cache unlink but before final state persistence.",
            "Malicious same-UID tampering, hardware/media failure, redundant vault durability.",
            "Independent Gauntlet critique and standalone S3 Journey A; this builder does not award a pass.",
        ]
        self.summary["outcome"] = "observations_complete" if all(
            case["status"] == "observed" for case in self.cases) else "gaps_observed"
        self.save_summary()
        lines = ["# Managed MaxIO process journey evidence", "", self.summary["topology"] + ".", "",
                 self.summary["provider_execution"] + ".", "",
                 "All roots, private fixture keys, exact command outputs and process logs are retained here.",
                 "The JSON summary is the detailed machine-readable record. This is builder evidence, not a Gauntlet verdict.",
                 "", "| Scenario | Observed outcome |", "|---|---|"]
        for case in self.cases:
            lines.append(f"| {case['name']} | {case['status']} |")
        lines += ["", "## Not exercised", ""]
        lines += [f"- {item}" for item in self.summary["not_exercised"]]
        text_file(self.root / "README.md", "\n".join(lines) + "\n")
        print(json.dumps({"evidence": str(self.root), "outcome": self.summary["outcome"],
                          "cases": [{"name": case["name"], "status": case["status"]} for case in self.cases]},
                         indent=2), flush=True)
        return 0 if self.summary["outcome"] == "observations_complete" else 1


HASH_TASK = '''import hashlib, json, os, pathlib
source = pathlib.Path("data/dataset.bin")
digest = hashlib.sha256()
size = 0
with source.open("rb") as stream:
    while block := stream.read(1024 * 1024):
        digest.update(block)
        size += len(block)
result = {"sha256": digest.hexdigest(), "size": size,
          "device_label": os.environ["DEVICE_LABEL"], "pid": os.getpid()}
pathlib.Path("results").mkdir(exist_ok=True)
pathlib.Path("results/hash.json").write_text(json.dumps(result, sort_keys=True) + "\\n")
print(f"hash_result sha256={result['sha256']} size={size} device={result['device_label']}", flush=True)
'''


def output_task(output: str, seconds: int) -> str:
    return f'''import json, os, pathlib, time
path = pathlib.Path({output!r})
path.parent.mkdir(parents=True, exist_ok=True)
record = {{"device_label": os.environ["DEVICE_LABEL"], "pid": os.getpid(), "phase": "dirty"}}
path.write_text(json.dumps(record, sort_keys=True) + "\\n")
print("started real finite command on " + record["device_label"], flush=True)
time.sleep({seconds})
record["phase"] = "complete"
path.write_text(json.dumps(record, sort_keys=True) + "\\n")
print("completed real finite command", flush=True)
'''


PROVIDER_FIXTURE = '''# Protocol fixture only: no provider authentication, network access or model calls.
import json, os, pathlib, sys
if "--version" in sys.argv:
    print("2.1.309 journey-protocol-fixture")
    sys.exit(0)
if "--help" in sys.argv:
    print("--ask-for-approval never --sandbox read-only workspace-write --json --cd --color --skip-git-repo-check --restricted --print --output-format stream-json --verbose --permission-mode dontAsk --permission-prompts --tools --allowedTools --disallowedTools")
    sys.exit(0)
assert sys.stdin.read() == "worker protocol fixture prompt"
assert pathlib.Path("src/provider-context.txt").is_file()
assert not any(arg in sys.argv for arg in ("--yolo", "--dangerously-skip-permissions"))
adapter = "claude" if "--restricted" in sys.argv else "codex"
pathlib.Path("results").mkdir(exist_ok=True)
pathlib.Path(f"results/{adapter}-fixture.json").write_text(json.dumps(
    {"adapter": adapter, "fixture_only": True}) + "\\n")
if adapter == "claude":
    assert "Bash" not in ",".join(sys.argv)
    print(json.dumps({"type": "result", "subtype": "success", "is_error": False,
                      "session_id": "journey-protocol-fixture", "permission_denials": []}))
else:
    assert sys.argv[1:4] == ["--ask-for-approval", "never", "exec"]
    print(json.dumps({"type": "thread.started", "thread_id": "journey-protocol-fixture"}))
    print(json.dumps({"type": "turn.completed"}))
'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--fabric-binary", required=True)
    parser.add_argument("--worker-binary", required=True)
    parser.add_argument("--size-mib", type=int, default=128)
    parser.add_argument("--evidence", help="new directory; retained, never overwritten or deleted")
    args = parser.parse_args()
    os.umask(0o077)
    journey = Journey(args)
    try:
        if not journey.case("Setup: proper TLS, independent enrolled identities and explicit grants", journey.setup):
            return journey.finish()
        if not journey.case("B/D: Mini seeds a real non-sparse dataset and imports private cache", journey.seed):
            return journey.finish()
        journey.case("B: metadata/docs selection, selected publication, conflicts, delete/restore", journey.selective_workspace)
        journey.case("D: two real workers, exact locality, actual Python hash and published result", journey.data_local_execution)
        journey.case("D: Codex and Claude existing adapters with labelled protocol fixtures", journey.provider_fixtures)
        journey.case("E: lost finish/publication acknowledgments reconcile without rerunning", journey.lost_acknowledgments)
        journey.case("B/E: pins, failed/interrupted proof, measured private eviction and exact refetch", journey.cache_recovery)
        journey.case("C/B: overlapping leases, committed read, expiry/new fence, durable restart", journey.leases_and_restart)
        journey.case("C/E: overlapping worker jobs, unexpected kill, abandonment and manual retry", journey.conflicting_workers)
        journey.case("E: cancel a real running command and retain unpublished work", journey.cancellation)
        journey.case("E: interrupted selected upload/download preserve bytes and recover", journey.transfer_interruptions)
        journey.case("E: running command stops after real renewal failure", journey.renewal_failure)
        journey.case("E: prepared worker output conflicts with a concurrent head publication", journey.prepared_publication_conflict)
        journey.case("E: coordinator dies during execution; restart fences and retains work", journey.coordinator_interruption)
        journey.case("Final: Book zero dataset throughout; revoked identity rejected", journey.final_checks)
    except BaseException:
        journey.summary["harness_interruption"] = traceback.format_exc()
        journey.save_summary()
        journey.finish()
        raise
    return journey.finish()


if __name__ == "__main__":
    raise SystemExit(main())
