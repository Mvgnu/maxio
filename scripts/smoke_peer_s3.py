#!/usr/bin/env python3
"""Exercise two real MaxIO processes through signed S3 requests, using only stdlib.

This is a loopback acceptance drill, not proof of Internet-safe transport, device
folder sync, or failover availability. It requires a built binary; it does not
build, install, download, or contact any cloud service.
"""

import argparse
import datetime as dt
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET


class S3:
    def __init__(self, port, access, secret, tls_context=None):
        self.endpoint = f"{'https' if tls_context else 'http'}://127.0.0.1:{port}"
        self.access = access
        self.secret = secret
        handlers = [urllib.request.ProxyHandler({})]
        if tls_context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=tls_context))
        self.opener = urllib.request.build_opener(*handlers)

    def request(self, method, path="/", body=b"", query=None, extra_headers=None):
        path = urllib.parse.quote(path, safe="/~")
        query_string = "&".join(
            f"{urllib.parse.quote(k, safe='~')}={urllib.parse.quote(v, safe='~')}"
            for k, v in sorted((query or {}).items())
        )
        timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        date = timestamp[:8]
        host = urllib.parse.urlsplit(self.endpoint).netloc
        payload_hash = hashlib.sha256(body).hexdigest()
        headers = {
            "host": host,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": timestamp,
        }
        headers.update({key.lower(): value for key, value in (extra_headers or {}).items()})
        signed_headers = ";".join(sorted(headers))
        canonical_headers = "".join(f"{k}:{v}\n" for k, v in sorted(headers.items()))
        canonical = "\n".join(
            [method, path, query_string, canonical_headers, signed_headers, payload_hash]
        )
        scope = f"{date}/us-east-1/s3/aws4_request"
        string_to_sign = "\n".join(
            ["AWS4-HMAC-SHA256", timestamp, scope, hashlib.sha256(canonical.encode()).hexdigest()]
        )
        key = ("AWS4" + self.secret).encode()
        for value in [date, "us-east-1", "s3", "aws4_request"]:
            key = hmac.new(key, value.encode(), hashlib.sha256).digest()
        signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
        headers["authorization"] = (
            f"AWS4-HMAC-SHA256 Credential={self.access}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        url = self.endpoint + path + ("?" + query_string if query_string else "")
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, dict(response.headers.items()), response.read()


def expect(response, status, context):
    actual, headers, body = response
    if actual != status:
        raise AssertionError(f"{context}: expected {status}, got {actual}: {body[:500]!r}")
    return {key.lower(): value for key, value in headers.items()}, body


def list_keys(client, bucket):
    _, body = expect(
        client.request("GET", f"/{bucket}", query={"list-type": "2"}),
        200,
        "list objects",
    )
    root = ET.fromstring(body)
    return {element.text for element in root.findall("{*}Contents/{*}Key")}


class Node:
    def __init__(self, binary, root, name, port, peer_port, env, tls_context=None):
        self.binary = str(binary)
        self.root = root / name
        self.root.mkdir()
        self.port = port
        self.peer_port = peer_port
        self.env = env
        self.tls_context = tls_context
        self.process = None
        self.log = None

    def start(self, clustered=True):
        args = [
            self.binary,
            "--address", "127.0.0.1",
            "--port", str(self.port),
            "--node-id", f"127.0.0.1:{self.port}",
            "--data-dir", str(self.root / "data"),
        ]
        if clustered:
            args += [
                "--cluster-peers", f"127.0.0.1:{self.peer_port}",
                "--metadata-listing-strategy", "request-time-aggregation",
                "--write-durability-mode", "strict-quorum",
            ]
        self.log = (self.root / "server.log").open("ab")
        self.process = subprocess.Popen(args, env=self.env, stdout=self.log, stderr=self.log)
        handlers = [urllib.request.ProxyHandler({})]
        if self.tls_context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=self.tls_context))
        opener = urllib.request.build_opener(*handlers)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"server exited with {self.process.returncode}: {self.root / 'server.log'}")
            try:
                scheme = 'https' if self.tls_context is not None else 'http'
                with opener.open(f"{scheme}://127.0.0.1:{self.port}/healthz", timeout=1):
                    return
            except urllib.error.HTTPError as error:
                # A degraded cluster is still serving; exercise S3 separately.
                if error.code == 503:
                    error.close()
                    return
                raise
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        raise RuntimeError(f"server did not listen: {self.root / 'server.log'}")

    def stop(self):
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
            self.process = None
        if self.log is not None:
            self.log.close()
            self.log = None


def run(binary, keep_data):
    root = Path(tempfile.mkdtemp(prefix="maxio-peer-smoke-"))
    # Reserve both ports together so they cannot accidentally be equal.
    reservations = [socket.socket(), socket.socket()]
    for reservation in reservations:
        reservation.bind(("127.0.0.1", 0))
    ports = [reservation.getsockname()[1] for reservation in reservations]
    env = {
        key: value for key, value in os.environ.items()
        if not key.startswith(("MAXIO_", "MINIO_"))
        and key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}
    }
    env.update({
        "MAXIO_ACCESS_KEY": "smoke-access",
        "MAXIO_SECRET_KEY": uuid.uuid4().hex,
        "MAXIO_CLUSTER_AUTH_TOKEN": uuid.uuid4().hex,
        "MAXIO_CLUSTER_ID": "smoke-" + uuid.uuid4().hex,
        "RUST_LOG": "warn",
        "NO_PROXY": "127.0.0.1,localhost",
    })
    nodes = [
        Node(binary, root, "a", ports[0], ports[1], env),
        Node(binary, root, "b", ports[1], ports[0], env),
    ]
    clients = [S3(port, env["MAXIO_ACCESS_KEY"], env["MAXIO_SECRET_KEY"]) for port in ports]
    success = False
    try:
        for reservation, node in zip(reservations, nodes):
            reservation.close()
            node.start()
        bucket = "peer-smoke"
        expect(clients[0].request("PUT", f"/{bucket}"), 200, "create shared bucket")
        expect(clients[1].request("HEAD", f"/{bucket}"), 200, "peer sees bucket")
        objects = {}
        primary_keys = {}
        # Discover both placement owners from the API, without importing server logic.
        for index in range(64):
            key = f"folder/device-file-{index}.txt"
            payload = f"direct peer payload {index}\n".encode()
            headers, _ = expect(
                clients[index % 2].request("PUT", f"/{bucket}/{key}", payload),
                200,
                f"write {key}",
            )
            if headers.get("x-maxio-write-quorum-reached") != "true":
                raise AssertionError(f"write lacked quorum acknowledgement: {headers}")
            if headers.get("x-maxio-write-ack-count") != "2":
                raise AssertionError(f"write did not acknowledge both replicas: {headers}")
            primary_keys[headers.get("x-maxio-primary-owner")] = key
            objects[key] = payload
            if len(primary_keys) == 2:
                break
        if set(primary_keys) != {f"127.0.0.1:{port}" for port in ports}:
            raise AssertionError("could not exercise both placement owners")
        for group in range(5):
            for item in range(3):
                key = f"group-{group}/item-{item}.txt"
                payload = f"grouped object {group}/{item}".encode()
                expect(clients[item % 2].request("PUT", f"/{bucket}/{key}", payload), 200, key)
                objects[key] = payload
        for client in clients:
            if list_keys(client, bucket) != set(objects):
                raise AssertionError("both nodes must list the same keys")
            for key, payload in objects.items():
                _, downloaded = expect(client.request("GET", f"/{bucket}/{key}"), 200, key)
                if downloaded != payload:
                    raise AssertionError(f"download differs: {key}")
            prefixes = []
            continuation = None
            for _ in range(4):
                query = {"list-type": "2", "delimiter": "/", "max-keys": "2"}
                if continuation is not None:
                    query["continuation-token"] = continuation
                _, body = expect(client.request("GET", f"/{bucket}", query=query), 200, "grouped listing")
                page = ET.fromstring(body)
                prefixes.extend(element.text for element in page.findall("{*}CommonPrefixes/{*}Prefix"))
                if page.findtext("{*}IsTruncated") != "true":
                    break
                continuation = page.findtext("{*}NextContinuationToken")
                assert continuation, "truncated page must have a continuation token"
            assert prefixes == ["folder/"] + [f"group-{group}/" for group in range(5)], prefixes
        print("PASS: both endpoints list/read identical bytes; both owners acknowledge two replicas")
        print("PASS: delimiter pagination counts each common prefix once through either endpoint")

        nodes[1].stop()
        expect(
            clients[0].request("GET", f"/{bucket}", query={"list-type": "2"}),
            503,
            "unavailable peer must not produce a partial successful listing",
        )
        local_key = primary_keys[f"127.0.0.1:{ports[0]}"]
        expect(
            clients[0].request("PUT", f"/{bucket}/{local_key}", objects[local_key]),
            503,
            "strict quorum must reject a write with the other replica offline",
        )
        print("PASS: missing peer gives explicit 503 for complete listings and strict-quorum writes")
        nodes[1].start()
        for client in clients:
            if list_keys(client, bucket) != set(objects):
                raise AssertionError("peer restart lost listing contents")
        print("PASS: peer restart restores shared listing")

        for node in nodes:
            node.stop()
        # Opening each persisted data directory alone proves that reads were not
        # merely forwarded to a single surviving copy during the earlier checks.
        for node, client in zip(nodes, clients):
            node.start(clustered=False)
            for key, payload in objects.items():
                _, downloaded = expect(client.request("GET", f"/{bucket}/{key}"), 200, key)
                if downloaded != payload:
                    raise AssertionError(f"persisted replica differs at {node.root}: {key}")
            node.stop()
        print("PASS: each independent restarted data directory contains every acknowledged object")
        print(json.dumps({"result": "pass", "nodes": 2, "objects": len(objects), "cloud_services": 0}))
        success = True
    finally:
        for reservation in reservations:
            reservation.close()
        for node in nodes:
            node.stop()
        if success and not keep_data:
            shutil.rmtree(root)
        else:
            print(f"Smoke data and process logs: {root}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/debug/maxio"))
    parser.add_argument("--keep-data", action="store_true")
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"build MaxIO first; binary not found: {binary}")
    run(binary, args.keep_data)


if __name__ == "__main__":
    main()
