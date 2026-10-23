#!/usr/bin/env python3
"""Real standalone binary acceptance: signed S3, conditional safety, console, restart."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import http.cookiejar
import json
import os
from pathlib import Path
import shutil
import socket
import tempfile
import urllib.error
import urllib.request
import uuid

from smoke_peer_s3 import Node, S3, expect, list_keys


def run(binary, keep_data):
    root = Path(tempfile.mkdtemp(prefix="maxio-standalone-smoke-"))
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("MAXIO_", "MINIO_"))
           and key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}}
    env.update(MAXIO_ACCESS_KEY="smoke-admin", MAXIO_SECRET_KEY=uuid.uuid4().hex, RUST_LOG="warn")
    node = Node(binary, root, "server", port, 0, env)
    client = S3(port, env["MAXIO_ACCESS_KEY"], env["MAXIO_SECRET_KEY"])
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    success = False
    try:
        node.start(clustered=False)
        with opener.open(client.endpoint + "/healthz", timeout=5) as response:
            assert json.load(response)["mode"] == "standalone"
        expect(S3(port, env["MAXIO_ACCESS_KEY"], "wrong-secret").request("GET"), 403, "wrong-secret control")
        expect(client.request("PUT", "/standalone-smoke"), 200, "create bucket")
        payload = b"previous valid bytes\x00\xff\n"
        headers, body = expect(client.request("PUT", "/standalone-smoke/folder/object.bin", payload), 200, "initial PUT")
        assert body == b"", "PUT response must be empty"
        assert headers.get("content-length") == "0", "PUT response length must describe its body"
        etag = headers["etag"]
        expect(client.request("PUT", "/standalone-smoke/folder/object.bin", b"rejected", extra_headers={
            "x-amz-checksum-sha256": base64.b64encode(bytes(32)).decode()
        }), 400, "bad checksum")
        preserved, body = expect(client.request("GET", "/standalone-smoke/folder/object.bin"), 200, "read after rejection")
        assert body == payload and preserved["etag"] == etag, "rejected write changed valid data"
        expect(client.request("PUT", "/standalone-smoke/folder/object.bin", b"rejected", extra_headers={"if-none-match": "*"}), 412, "conditional create")
        def writer(value):
            response = client.request("PUT", "/standalone-smoke/folder/object.bin", value, extra_headers={"if-match": etag})
            return response[0], value
        with ThreadPoolExecutor(max_workers=2) as pool:
            writes = list(pool.map(writer, [b"writer-one", b"writer-two"]))
        assert sorted(code for code, _ in writes) == [200, 412], writes
        winner = next(value for code, value in writes if code == 200)
        expect(client.request("DELETE", "/standalone-smoke/folder/object.bin", extra_headers={
            "if-match": "\"never-this-etag\""
        }), 501, "unsupported conditional delete must not remove data")
        _, preserved = expect(client.request("GET", "/standalone-smoke/folder/object.bin"), 200, "read after rejected delete")
        assert preserved == winner
        assert list_keys(client, "standalone-smoke") == {"folder/object.bin"}
        print("PASS: signed S3, complete response framing, failed-overwrite preservation and one conditional winner")

        try:
            opener.open(client.endpoint + "/api/buckets", timeout=5)
            raise AssertionError("unauthenticated console request was accepted")
        except urllib.error.HTTPError as error:
            assert error.code == 401, error.code
            error.close()
        login = urllib.request.Request(client.endpoint + "/api/auth/login", method="POST",
            data=json.dumps({"accessKey": env["MAXIO_ACCESS_KEY"], "secretKey": env["MAXIO_SECRET_KEY"]}).encode(),
            headers={"Content-Type": "application/json"})
        with opener.open(login, timeout=5) as response:
            assert response.status == 200
        upload = urllib.request.Request(client.endpoint + "/api/buckets/standalone-smoke/upload/from-console.txt",
                                        data=b"console bytes", method="PUT")
        with opener.open(upload, timeout=5) as response:
            assert response.status == 200
        with opener.open(client.endpoint + "/api/buckets/standalone-smoke/download/from-console.txt", timeout=5) as response:
            assert response.read() == b"console bytes"
        with opener.open(client.endpoint + "/ui/", timeout=5) as response:
            html = response.read().decode()
            assert "fonts.googleapis.com" not in html and "fonts.gstatic.com" not in html
        print("PASS: authenticated console upload/download and local embedded assets; unauthenticated access denied")
        node.stop()
        node.start(clustered=False)
        _, body = expect(client.request("GET", "/standalone-smoke/folder/object.bin"), 200, "restart read")
        assert body == winner
        _, body = expect(client.request("GET", "/standalone-smoke/from-console.txt"), 200, "restart console upload")
        assert body == b"console bytes"
        print("PASS: acknowledged bytes survive a complete process restart")
        print(json.dumps({"result": "pass", "servers": 1, "cloud_services": 0}))
        success = True
    finally:
        node.stop()
        if success and not keep_data:
            shutil.rmtree(root)
        else:
            print(f"Smoke data and logs: {root}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/debug/maxio"))
    parser.add_argument("--keep-data", action="store_true")
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"build MaxIO first: {binary}")
    run(binary, args.keep_data)


if __name__ == "__main__":
    main()
