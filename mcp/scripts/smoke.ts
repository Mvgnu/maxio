import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, isAbsolute } from "node:path";
import { connect } from "./client";
import assert from "node:assert/strict";
const binary = process.env.MAXIO_TEST_BINARY;
if (!binary || !isAbsolute(binary))
  throw new Error(
    "MAXIO_TEST_BINARY must be an absolute real MaxIO executable",
  );
const probe = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  fetch: () => new Response(""),
});
const port = probe.port!;
probe.stop(true);
const dir = await mkdtemp(join(tmpdir(), "maxio-mcp-smoke-")),
  endpoint = `http://127.0.0.1:${port}`;
const spawnServer = () =>
  Bun.spawn(
    [
      binary,
      "--address",
      "127.0.0.1",
      "--port",
      String(port),
      "--data-dir",
      join(dir, "data"),
      "--access-key",
      "smoke-owner",
      "--secret-key",
      "smoke-secret",
    ],
    { stdin: "ignore", stdout: "ignore", stderr: "ignore" },
  );
let child = spawnServer();
async function readyServer() {
  for (let i = 0; i < 100; i++) {
    try {
      await fetch(endpoint + "/api/auth/check");
      return;
    } catch {
      await Bun.sleep(100);
    }
  }
  throw new Error("MaxIO failed to become ready");
}
let session: Awaited<ReturnType<typeof connect>> | undefined;
try {
  let ready = false;
  for (let i = 0; i < 100; i++) {
    try {
      await fetch(endpoint + "/api/auth/check");
      ready = true;
      break;
    } catch {
      await Bun.sleep(100);
    }
  }
  assert(ready, "MaxIO failed to start");
  const path = join(dir, "config.json");
  await writeFile(
    path,
    JSON.stringify({
      console: {
        endpoint,
        accessKey: "smoke-owner",
        secretKey: "smoke-secret",
      },
    }),
    { mode: 0o600 },
  );
  session = await connect(path);
  const { call, client } = session;
  const tools = await client.listTools();
  assert(
    tools.tools.some(
      (t) => t.name === "maxio_object_write" && t.annotations?.destructiveHint,
    ),
  );
  const bucket = "mcp-smoke";
  await call("maxio_bucket_create", { bucket });
  assert(JSON.stringify(await call("maxio_buckets_list")).includes(bucket));
  await call("maxio_object_write", {
    bucket,
    key: "hello.txt",
    encoding: "utf8",
    data: "first",
  });
  assert.equal(
    Buffer.from(
      (await call("maxio_object_read", { bucket, key: "hello.txt" })).data,
      "base64",
    ).toString(),
    "first",
  );
  child.kill();
  await child.exited;
  child = spawnServer();
  await readyServer();
  assert.equal(
    Buffer.from(
      (await call("maxio_object_read", { bucket, key: "hello.txt" })).data,
      "base64",
    ).toString(),
    "first",
    "MCP refreshes the restart-invalidated cookie without losing object bytes",
  );
  await call("maxio_placement", { key: "hello.txt" });
  await call("maxio_rebalance", {
    key: "hello.txt",
    operation: "join",
    peer: "127.0.0.1:19999",
  });
  await call("maxio_bucket_lifecycle_set", {
    bucket,
    rules: [{ id: "disabled", prefix: "", expirationDays: 30, enabled: false }],
  });
  await call("maxio_bucket_lifecycle_get", { bucket });
  await call("maxio_object_presign", { bucket, key: "hello.txt", expires: 60 });
  await call("maxio_bucket_versioning_set", { bucket, enabled: true });
  await call("maxio_object_write", {
    bucket,
    key: "hello.txt",
    encoding: "utf8",
    data: "second",
  });
  assert(
    JSON.stringify(await call("maxio_objects_list", { bucket })).includes(
      "hello.txt",
    ),
  );
  const versions = (
    await call("maxio_versions_list", { bucket, key: "hello.txt" })
  ).versions;
  assert(versions.length >= 2);
  for (const v of versions) {
    const version_id = v.versionId ?? "null";
    await call("maxio_version_read", { bucket, key: "hello.txt", version_id });
    await call("maxio_version_delete", {
      bucket,
      key: "hello.txt",
      version_id,
    });
  }
  const error = await client.callTool({
    name: "maxio_object_read",
    arguments: { bucket, key: "missing" },
  });
  assert.equal(error.isError, true);
  await call("maxio_bucket_lifecycle_set", { bucket, rules: [] });
  await call("maxio_bucket_delete", { bucket });
  console.log(
    "PASS: SDK stdio discovery, bucket/create/list, inline upload/read, restart/session refresh, placement/rebalance/lifecycle/presign, versioning/list/download/delete, backend error, bucket cleanup",
  );
} finally {
  await session?.client.close();
  child.kill();
  await child.exited;
  await rm(dir, { recursive: true, force: true });
}
