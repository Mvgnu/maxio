import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect } from "./client";
import assert from "node:assert/strict";
const binary = process.env.MAXIO_TEST_FABRIC_BINARY,
  config = process.env.MAXIO_TEST_FABRIC_CONFIG;
if (!binary || !config)
  throw new Error(
    "Set MAXIO_TEST_FABRIC_BINARY and MAXIO_TEST_FABRIC_CONFIG for a disposable verified HTTPS authority",
  );
const dir = await mkdtemp(join(tmpdir(), "maxio-mcp-fabric-"));
let session: Awaited<ReturnType<typeof connect>> | undefined;
try {
  const path = join(dir, "config.json");
  await writeFile(
    path,
    JSON.stringify({
      console: {
        endpoint: "http://127.0.0.1:1",
        accessKey: "unused",
        secretKey: "unused",
      },
      fabric: { binary, config },
    }),
    { mode: 0o600 },
  );
  session = await connect(path);
  const { call, client } = session;
  assert.equal(
    (await call("maxio_fabric_info")).response.result.result,
    "info",
  );
  const request_id = crypto.randomUUID(),
    created = await call("maxio_fabric_workspace_create", {
      request_id,
      name: "mcp-" + request_id,
    });
  assert.equal(created.request_id, request_id);
  const workspace_id = created.response.result.workspace.workspace_id;
  assert.equal(
    (await call("maxio_fabric_workspace_current", { workspace_id })).response
      .result.result,
    "catalog",
  );
  assert(
    JSON.stringify(await call("maxio_fabric_workspaces_list")).includes(
      workspace_id,
    ),
  );
  const key = await crypto.subtle.generateKey("Ed25519", true, [
    "sign",
    "verify",
  ]);
  const public_key = Buffer.from(
    await crypto.subtle.exportKey("raw", key.publicKey),
  ).toString("base64");
  const device = (
    await call("maxio_fabric_device_enroll", {
      request_id: crypto.randomUUID(),
      display_name: "MCP disposable",
      public_key,
      role: "device",
    })
  ).response.result.device;
  const device_id = device.device_id;
  await call("maxio_fabric_grant_set", {
    request_id: crypto.randomUUID(),
    grant: {
      device_id,
      workspace_id,
      catalog_read: true,
      read: [],
      write: [],
      submit_jobs: false,
    },
  });
  assert(
    JSON.stringify(
      await call("maxio_fabric_grants_list", { device_id, workspace_id }),
    ).includes(device_id),
  );
  await call("maxio_fabric_device_revoke", {
    request_id: crypto.randomUUID(),
    device_id,
  });
  assert(
    JSON.stringify(await call("maxio_fabric_devices_list")).includes(
      '"revoked":true',
    ),
  );
  const error = await client.callTool({
    name: "maxio_fabric_job_status",
    arguments: { job_id: crypto.randomUUID() },
  });
  assert.equal(error.isError, true);
  console.log(
    "PASS: real HTTPS Fabric via SDK stdio info/list/create/current, enroll/grant/revoke, missing job error",
  );
} finally {
  await session?.client.close();
  await rm(dir, { recursive: true, force: true });
}
