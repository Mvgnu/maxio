#!/usr/bin/env python3
"""Real HTTPS/mTLS acceptance: two peers, adversarial identities and restart.

Uses Python's standard library and the local openssl executable. Generates a
disposable private CA and never disables certificate/hostname verification.
It does not build, download, install or contact a cloud service.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

from smoke_peer_s3 import Node, S3, expect, list_keys


def openssl(*arguments):
    result = subprocess.run(["openssl", *map(str, arguments)], capture_output=True, timeout=20)
    if result.returncode:
        raise RuntimeError(f"openssl failed: {result.stderr.decode(errors='replace')}")
    return result.stdout


def make_ca(root, name):
    certificate, key = root / f"{name}.crt", root / f"{name}.key"
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-keyout", key, "-out", certificate, "-days", "2", "-sha256",
            "-subj", f"/CN={name}", "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    return certificate, key


def make_identity(root, name, port, ca):
    certificate, key = root / f"{name}.crt", root / f"{name}.key"
    request, extensions = root / f"{name}.csr", root / f"{name}.ext"
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth,clientAuth\n"
        f"subjectAltName=IP:127.0.0.1,URI:maxio://127.0.0.1:{port}\n"
    )
    openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-keyout", key, "-out", request, "-subj", f"/CN={name}")
    openssl("x509", "-req", "-in", request, "-CA", ca[0], "-CAkey", ca[1],
            "-set_serial", str(uuid.uuid4().int), "-out", certificate,
            "-days", "2", "-sha256", "-extfile", extensions)
    return certificate, key


def tls_context(ca, identity=None):
    context = ssl.create_default_context(cafile=str(ca))
    if identity:
        context.load_cert_chain(str(identity[0]), str(identity[1]))
    return context


def request(port, path, context, method="GET", headers=None, body=None):
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    req = urllib.request.Request(f"https://127.0.0.1:{port}{path}", data=body,
                                 headers=headers or {}, method=method)
    try:
        response = opener.open(req, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, dict(response.headers.items()), response.read()


def expect_transport_rejected(action, label):
    try:
        response = action()
    except urllib.error.HTTPError as error:
        error.close()
        raise AssertionError(f"{label}: received an HTTP response instead of TLS rejection") from error
    except (OSError, urllib.error.URLError):
        return
    raise AssertionError(f"{label}: expected TLS rejection, received HTTP {response}")


def join_headers(node_id, env):
    return {
        "x-maxio-forwarded-by": node_id,
        "x-maxio-internal-auth-token": env["MAXIO_CLUSTER_AUTH_TOKEN"],
        "x-maxio-join-cluster-id": env["MAXIO_CLUSTER_ID"],
        "x-maxio-join-node-id": node_id,
        "x-maxio-join-unix-ms": str(int(time.time() * 1000)),
        "x-maxio-join-nonce": uuid.uuid4().hex,
    }


def stop_cleanly(node, timeout=8):
    process = node.process
    if process is None:
        return
    process.terminate()
    code = process.wait(timeout=timeout)
    assert code == 0, f"server did not drain cleanly: exit {code}, {node.root / 'server.log'}"
    node.process = None
    node.log.close()
    node.log = None


def startup_rejections(binary, root, env, identity, ca, peer_port):
    bad = root / "invalid.pem"
    bad.write_text("this is not a certificate or private key\n")
    encrypted_key = root / "encrypted.key"
    openssl("pkcs8", "-topk8", "-in", identity[1], "-out", encrypted_key,
            "-passout", "pass:disposable-smoke-password")
    peer_flags = ["--cluster-peer-tls-cert-path", str(identity[0]),
                  "--cluster-peer-tls-key-path", str(identity[1]),
                  "--cluster-peer-tls-ca-path", str(ca)]
    cases = [
        (["--tls-cert-path", str(identity[0])], "both --tls-cert-path"),
        (["--tls-cert-path", str(bad), "--tls-key-path", str(bad)], "invalid native HTTPS"),
        (["--tls-cert-path", str(identity[0]), "--tls-key-path", str(encrypted_key)], "encrypted native HTTPS private keys"),
        (["--cluster-peer-tls-cert-path", str(identity[0])], "all three"),
        (["--cluster-peer-transport-mode", "required"], "not_configured"),
        (peer_flags + ["--tls-cert-path", str(identity[0]), "--tls-key-path", str(identity[1])], "mutually exclusive"),
        (["--tls-cert-path", str(identity[0]), "--tls-key-path", str(identity[1]),
          "--cluster-peers", f"127.0.0.1:{peer_port}"], "use the cluster peer TLS"),
        (peer_flags + ["--node-id", f"127.0.0.1:{peer_port}"], "URI does not match"),
    ]
    for index, (flags, message) in enumerate(cases):
        data = root / f"rejected-startup-{index}"
        result = subprocess.run([str(binary), "--data-dir", str(data), *flags],
                                env=env, capture_output=True, timeout=10)
        output = (result.stdout + result.stderr).decode(errors="replace")
        assert result.returncode != 0 and message in output, (flags, output)
        assert not data.exists(), f"rejected configuration initialized storage: {data}"
    no_token = {key: value for key, value in env.items() if key != "MAXIO_CLUSTER_AUTH_TOKEN"}
    data = root / "rejected-without-token"
    result = subprocess.run([str(binary), "--data-dir", str(data),
                             "--cluster-peer-transport-mode", "required"],
                            env=no_token, capture_output=True, timeout=10)
    assert result.returncode != 0 and b"--cluster-auth-token" in result.stderr
    assert not data.exists()
    print("PASS: partial, invalid, conflicting and required-without-identity/token configurations fail before storage")


def run(binary, keep_data):
    root = Path(tempfile.mkdtemp(prefix="maxio-secure-peers-"))
    reservations = [socket.socket() for _ in range(5)]
    for reservation in reservations:
        reservation.bind(("127.0.0.1", 0))
    ports = [reservation.getsockname()[1] for reservation in reservations]
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("MAXIO_", "MINIO_"))
           and key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}}
    env.update(MAXIO_ACCESS_KEY="secure-smoke", MAXIO_SECRET_KEY=uuid.uuid4().hex,
               MAXIO_CLUSTER_AUTH_TOKEN=uuid.uuid4().hex,
               MAXIO_CLUSTER_ID="secure-smoke-" + uuid.uuid4().hex, RUST_LOG="warn")
    nodes, slow_connections = [], []
    success = False
    try:
        ca, foreign_ca = make_ca(root, "cluster-ca"), make_ca(root, "foreign-ca")
        identities = [make_identity(root, f"peer-{index}", port, ca)
                      for index, port in enumerate(ports[:2])]
        unknown_identity = make_identity(root, "same-host-other-port", ports[4], ca)
        foreign_identity = make_identity(root, "foreign-same-node", ports[1], foreign_ca)
        context = tls_context(ca[0])
        peer_context = tls_context(ca[0], identities[1])
        startup_rejections(binary, root, env, identities[0], ca[0], ports[1])

        for index in range(2):
            node_env = dict(env, MAXIO_CLUSTER_PEER_TRANSPORT_MODE="required",
                            MAXIO_CLUSTER_PEER_TLS_CERT_PATH=str(identities[index][0]),
                            MAXIO_CLUSTER_PEER_TLS_KEY_PATH=str(identities[index][1]),
                            MAXIO_CLUSTER_PEER_TLS_CA_PATH=str(ca[0]))
            nodes.append(Node(binary, root, f"node-{index}", ports[index], ports[1-index],
                              node_env, tls_context=context))
            reservations[index].close()
            nodes[index].start()
        clients = [S3(port, env["MAXIO_ACCESS_KEY"], env["MAXIO_SECRET_KEY"], tls_context=context)
                   for port in ports[:2]]
        for port in ports[:2]:
            # The local scope reports liveness/topology only. Full health owns
            # the readiness checks for cryptographic peer identity.
            _, body = expect(request(port, "/healthz", context), 200, "native HTTPS identity readiness")
            health = json.loads(body)
            for check in ("clusterPeerAuthIdentityBound", "clusterPeerAuthTransportReady",
                          "clusterPeerAuthTransportRequired"):
                assert health["checks"][check] is True, (check, health)
        expect(request(ports[0], "/internal/cluster/join/authorize", peer_context,
                       "POST", join_headers(f"127.0.0.1:{ports[1]}", env)), 200,
               "known certificate-bound peer join authorization")

        bucket, objects, primary_keys = "secure-peers", {}, {}
        expect(clients[0].request("PUT", f"/{bucket}"), 200, "HTTPS bucket creation")
        for index in range(64):
            key, payload = f"folder/file-{index}.bin", b"encrypted direct peer bytes\x00\xff" + bytes([index])
            headers, _ = expect(clients[index % 2].request("PUT", f"/{bucket}/{key}", payload), 200, key)
            assert headers.get("x-maxio-write-quorum-reached") == "true", headers
            assert headers.get("x-maxio-write-ack-count") == "2", headers
            objects[key] = payload
            primary_keys[headers.get("x-maxio-primary-owner")] = key
            if len(primary_keys) == 2:
                break
        assert set(primary_keys) == {f"127.0.0.1:{port}" for port in ports[:2]}, primary_keys
        for client in clients:
            assert list_keys(client, bucket) == set(objects)
            for key, payload in objects.items():
                _, body = expect(client.request("GET", f"/{bucket}/{key}"), 200, "cross-peer HTTPS read")
                assert body == payload
        print("PASS: ordinary S3 clients need no peer certificate; both owners acknowledge two HTTPS replicas and list/read identical bytes")

        claimed_peer = f"127.0.0.1:{ports[1]}"
        forged = {"x-maxio-forwarded-by": claimed_peer,
                  "x-maxio-internal-auth-token": env["MAXIO_CLUSTER_AUTH_TOKEN"],
                  "x-forwarded-proto": "https"}
        expect(clients[0].request("PUT", f"/{bucket}/forged-no-cert", b"must not exist",
                                  extra_headers=forged), 403, "correct token without client certificate")
        expect(request(ports[0], "/internal/cluster/join/authorize", context, "POST",
                       join_headers(claimed_peer, env)), 403, "internal control without client certificate")
        expect(request(ports[0], "/internal/cluster/join/authorize",
                       tls_context(ca[0], unknown_identity), "POST", join_headers(claimed_peer, env)),
               403, "same-host certificate for an unconfigured port")
        expect(request(ports[0], "/internal/cluster/join/authorize",
                       tls_context(ca[0], identities[0]), "POST", join_headers(claimed_peer, env)),
               403, "self certificate cannot impersonate remote peer")
        bad_claim = join_headers(claimed_peer, env)
        bad_claim["x-maxio-join-node-id"] = f"127.0.0.1:{ports[4]}"
        expect(request(ports[0], "/internal/cluster/join/authorize", peer_context,
                       "POST", bad_claim), 403, "join claim differs from certificate")
        bad_hop = join_headers(claimed_peer, env)
        bad_hop["x-maxio-forwarded-by"] = f"127.0.0.1:{ports[4]}"
        expect(request(ports[0], "/internal/cluster/join/authorize", peer_context,
                       "POST", bad_hop), 403, "last forwarding hop differs from certificate")
        peer_client = S3(ports[0], env["MAXIO_ACCESS_KEY"], env["MAXIO_SECRET_KEY"], tls_context=peer_context)
        expect(peer_client.request("PUT", f"/{bucket}/forged-bad-token", b"must not exist",
                                   extra_headers=dict(forged, **{"x-maxio-internal-auth-token": "wrong"})),
               403, "valid peer certificate does not replace shared-token authorization")
        expect(S3(ports[0], env["MAXIO_ACCESS_KEY"], "wrong-secret", tls_context=peer_context)
               .request("GET", f"/{bucket}", extra_headers=forged), 403,
               "valid peer certificate does not replace SigV4")
        assert list_keys(clients[0], bucket) == set(objects), "rejected requests mutated storage"
        expect_transport_rejected(lambda: request(ports[0], "/healthz", tls_context(ca[0], foreign_identity)),
                                  "foreign CA certificate claiming the exact allowed peer")
        expect_transport_rejected(lambda: request(ports[0], "/healthz", tls_context(foreign_ca[0])),
                                  "client does not trust the server CA")
        plaintext = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        expect_transport_rejected(lambda: plaintext.open(f"http://127.0.0.1:{ports[0]}/healthz", timeout=3),
                                  "plaintext HTTP on the HTTPS listener")
        expect(request(ports[0], "/healthz?scope=local", context), 200, "listener still serves after rejected connections")
        print("PASS: forged headers, wrong port/self/join/hop identities, wrong token, wrong SigV4, wrong CA and plaintext are rejected without mutation")

        stop_cleanly(nodes[1])
        expect(clients[0].request("GET", f"/{bucket}", query={"list-type": "2"}), 503, "offline peer listing")
        local_key = primary_keys[f"127.0.0.1:{ports[0]}"]
        expect(clients[0].request("PUT", f"/{bucket}/{local_key}", objects[local_key]), 503, "offline peer strict quorum")
        nodes[1].start()
        assert list_keys(clients[0], bucket) == set(objects)
        for node in nodes:
            stop_cleanly(node)
        for node, client in zip(nodes, clients):
            node.start(clustered=False)
            for key, payload in objects.items():
                _, body = expect(client.request("GET", f"/{bucket}/{key}"), 200, "independent persisted HTTPS replica")
                assert body == payload
            stop_cleanly(node)
        print("PASS: peer loss fails complete listings and strict quorum explicitly; restart recovers; each isolated persisted replica contains acknowledged bytes")

        # Revoke only the remote certificate, leaving the server's own identity
        # valid. Test a new actual connection, not a cached preflight result.
        fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(identities[1][0].read_text())).hexdigest()
        nodes[0].env["MAXIO_CLUSTER_PEER_TLS_CERT_SHA256_REVOCATIONS"] = fingerprint
        nodes[0].start()
        expect_transport_rejected(lambda: request(ports[0], "/healthz", peer_context), "revoked peer certificate")
        expect(request(ports[0], "/healthz?scope=local", context), 200, "ordinary HTTPS client during peer revocation")
        stop_cleanly(nodes[0])
        del nodes[0].env["MAXIO_CLUSTER_PEER_TLS_CERT_SHA256_REVOCATIONS"]

        # A dedicated control listener must not expose S3/UI, and a public
        # listener must not expose the relocated control endpoint.
        internal_port = ports[3]
        reservations[3].close()
        nodes[0].env["MAXIO_INTERNAL_BIND_ADDR"] = f"127.0.0.1:{internal_port}"
        nodes[0].start()
        expect_transport_rejected(lambda: request(internal_port, "/internal/cluster/join/authorize",
                                                  context, "POST", join_headers(claimed_peer, env)),
                                  "dedicated internal listener requires certificate at handshake")
        expect(request(internal_port, "/internal/cluster/join/authorize", peer_context,
                       "POST", join_headers(claimed_peer, env)), 200, "dedicated control route")
        public_response = request(ports[0], "/internal/cluster/join/authorize", peer_context,
                                  "POST", join_headers(claimed_peer, env))
        assert public_response[0] != 200 and b'"authorized":true' not in public_response[2], public_response
        expect(request(internal_port, "/ui/", peer_context), 404, "internal listener isolates public UI")
        # Hold several TLS handshakes open. One slow socket must not serialize
        # acceptance of healthy clients, and SIGTERM must cancel pending work.
        slow_connections = [socket.create_connection(("127.0.0.1", ports[0]), timeout=2) for _ in range(8)]
        started = time.monotonic()
        expect(request(ports[0], "/healthz?scope=local", context), 200, "concurrent handshake acceptance")
        assert time.monotonic() - started < 4, "healthy request waited for slow TLS handshakes"
        slow_connections[0].settimeout(7)
        assert slow_connections[0].recv(1) == b"", "unfinished TLS handshake did not expire"
        for connection in slow_connections:
            connection.close()
        slow_connections = [socket.create_connection(("127.0.0.1", ports[0]), timeout=2) for _ in range(8)]
        stop_cleanly(nodes[0])
        for connection in slow_connections:
            connection.close()
        slow_connections.clear()
        print("PASS: revocation is checked on new TLS connections; listener isolation, concurrent handshakes and two-listener SIGTERM drain work")

        standalone_env = dict(env, MAXIO_TLS_CERT_PATH=str(identities[0][0]),
                              MAXIO_TLS_KEY_PATH=str(identities[0][1]))
        standalone = Node(binary, root, "standalone", ports[2], 0, standalone_env, tls_context=context)
        nodes.append(standalone)
        reservations[2].close()
        standalone.start(clustered=False)
        client = S3(ports[2], env["MAXIO_ACCESS_KEY"], env["MAXIO_SECRET_KEY"], tls_context=context)
        expect(client.request("PUT", "/single-https"), 200, "standalone HTTPS bucket")
        expect(client.request("PUT", "/single-https/file", b"one S3 endpoint"), 200, "standalone HTTPS write")
        _, body = expect(client.request("GET", "/single-https/file"), 200, "standalone HTTPS read")
        assert body == b"one S3 endpoint"
        expect(request(ports[2], "/ui/", context), 200, "standalone embedded UI over HTTPS")
        stop_cleanly(standalone)
        print("PASS: standalone HTTPS works with only a certificate/key pair and no cluster setup")
        print(json.dumps({"result": "pass", "peer_nodes": 2, "native_https": True,
                          "certificate_node_identity": True, "cloud_services": 0}))
        success = True
    finally:
        for connection in slow_connections:
            connection.close()
        for reservation in reservations:
            reservation.close()
        for node in nodes:
            node.stop()
        if success and not keep_data:
            shutil.rmtree(root)
        else:
            print(f"Smoke data, certificates and process logs: {root}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/debug/maxio"))
    parser.add_argument("--keep-data", action="store_true")
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error(f"build MaxIO first: {binary}")
    if shutil.which("openssl") is None:
        parser.error("the local openssl executable is required for disposable test certificates")
    run(binary, args.keep_data)


if __name__ == "__main__":
    main()
