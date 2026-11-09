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
const child = Bun.spawn(
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
  await call("maxio_bucket_delete", { bucket });
  console.log(
    "PASS: SDK stdio discovery, bucket/create/list, inline upload/read, versioning/list/download/delete, backend error, bucket cleanup",
  );
} finally {
  await session?.client.close();
  child.kill();
  await child.exited;
  await rm(dir, { recursive: true, force: true });
}
