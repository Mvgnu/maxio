#!/usr/bin/env python3
"""Journey A using an installed ordinary AWS CLI and disposable standalone MaxIO."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.request
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--aws", required=True, help="installed AWS CLI executable")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("AWS_", "MAXIO_", "MINIO_"))
           and k.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}}
    env.update(MAXIO_ACCESS_KEY="journey-a", MAXIO_SECRET_KEY=uuid.uuid4().hex,
               AWS_DEFAULT_REGION="us-east-1", AWS_EC2_METADATA_DISABLED="true")
    env.update(AWS_ACCESS_KEY_ID=env["MAXIO_ACCESS_KEY"],
               AWS_SECRET_ACCESS_KEY=env["MAXIO_SECRET_KEY"])
    report = {"client": subprocess.check_output([args.aws, "--version"], env=env,
                                                text=True).strip(),
              "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
              "operations": []}
    with tempfile.TemporaryDirectory(prefix="maxio-ordinary-aws-") as directory:
        root = Path(directory)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        endpoint = f"http://127.0.0.1:{port}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        process = None
        log = (root / "server.log").open("wb")

        def stop():
            nonlocal process
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
                process = None

        def start():
            nonlocal process
            process = subprocess.Popen([str(args.binary.resolve()), "--address", "127.0.0.1",
                                        "--port", str(port), "--data-dir", str(root / "data")],
                                       env=env, stdout=log, stderr=log)
            for _ in range(100):
                if process.poll() is not None:
                    raise AssertionError("standalone process exited during startup")
                try:
                    with opener.open(endpoint + "/healthz", timeout=1) as response:
                        assert json.load(response)["mode"] == "standalone"
                        return
                except (OSError, ValueError):
                    time.sleep(0.05)
            raise AssertionError("standalone readiness deadline exceeded")

        def aws(label, *command):
            result = subprocess.run([args.aws, "--endpoint-url", endpoint, "s3api", *command],
                                    env=env, text=True, capture_output=True, timeout=30)
            assert result.returncode == 0, (label, result.stderr)
            report["operations"].append({"operation": label, "exit_code": result.returncode,
                                         "response": json.loads(result.stdout or "{}")})

        try:
            payload = bytes(range(256)) * 4096 + b"MaxIO ordinary AWS CLI\x00\xff\n"
            source = root / "source.bin"
            source.write_bytes(payload)
            start()
            aws("create bucket", "create-bucket", "--bucket", "ordinary-journey")
            aws("upload", "put-object", "--bucket", "ordinary-journey", "--key", "docs/input.bin",
                "--body", str(source))
            aws("head", "head-object", "--bucket", "ordinary-journey", "--key", "docs/input.bin")
            aws("list", "list-objects-v2", "--bucket", "ordinary-journey", "--prefix", "docs/")
            aws("download", "get-object", "--bucket", "ordinary-journey", "--key", "docs/input.bin",
                str(root / "before.bin"))
            assert (root / "before.bin").read_bytes() == payload
            stop()
            start()
            aws("download after restart", "get-object", "--bucket", "ordinary-journey",
                "--key", "docs/input.bin", str(root / "after.bin"))
            assert (root / "after.bin").read_bytes() == payload
            report.update(result="pass", bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest(),
                          standalone_process_starts=2, managed_configuration=False,
                          physical_machines=1, external_services=0)
        finally:
            stop()
            log.close()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
