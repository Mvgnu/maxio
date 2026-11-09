import { test, expect } from "bun:test";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { connect } from "../scripts/client";
import { Service } from "../src/service";
import { boundedBody, ConsoleClient } from "../src/console";

test("SDK discovery, strict schemas, unavailable fabric and backend errors", async () => {
  const backend = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch: (r) =>
      new URL(r.url).pathname === "/api/auth/login"
        ? Response.json(
            {},
            { headers: { "set-cookie": "maxio_session=private" } },
          )
        : Response.json({ error: "unavailable" }, { status: 503 }),
  });
  const dir = await mkdtemp(join(tmpdir(), "mcp-protocol-"));
  let session: Awaited<ReturnType<typeof connect>> | undefined;
  try {
    const path = join(dir, "config");
    await writeFile(
      path,
      JSON.stringify({
        console: {
          endpoint: backend.url.origin,
          accessKey: "owner",
          secretKey: "secret",
        },
      }),
      { mode: 0o600 },
    );
    session = await connect(path);
    const { client } = session;
    const tools = (await client.listTools()).tools;
    expect(tools.length).toBeGreaterThan(40);
    expect(
      tools.find((t) => t.name === "maxio_object_delete")?.annotations
        ?.destructiveHint,
    ).toBe(true);
    expect(
      tools.find((t) => t.name === "maxio_health")?.annotations?.readOnlyHint,
    ).toBe(true);
    expect(
      tools.find((t) => t.name === "maxio_placement")?.inputSchema.required,
    ).toContain("key");
    for (const [name, args] of [
      [
        "maxio_bucket_create",
        { bucket: "test", endpoint: "https://evil.example" },
      ],
      ["maxio_fabric_info", {}],
      ["maxio_health", {}],
    ] as const) {
      const result = await client.callTool({ name, arguments: args });
      expect(result.isError).toBe(true);
      expect(JSON.stringify(result)).not.toContain("private");
    }
  } finally {
    await session?.client.close();
    backend.stop(true);
    await rm(dir, { recursive: true, force: true });
  }
});

test("bounded bodies reject excess and mutation 401 never replays", async () => {
  await expect(boundedBody(new Response("oversized"), 2)).rejects.toThrow(
    "limit",
  );
  let writes = 0;
  const backend = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch: (r) =>
      new URL(r.url).pathname === "/api/auth/login"
        ? Response.json(
            {},
            { headers: { "set-cookie": "maxio_session=private" } },
          )
        : (writes++, new Response("", { status: 401 })),
  });
  try {
    await expect(
      new ConsoleClient({
        endpoint: backend.url.origin,
        accessKey: "a",
        secretKey: "s",
      }).json("POST", "/api/buckets", { name: "test" }),
    ).rejects.toThrow("not retried");
    expect(writes).toBe(1);
  } finally {
    backend.stop(true);
  }
});

test("external reachable server with denied auth cannot be spawned, stopped or restarted", async () => {
  const backend = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch: () => new Response("", { status: 403 }),
  });
  try {
    const service = new Service(
      {
        command: process.execPath,
        args: ["-e", 'throw new Error("must not run")'],
        cwd: process.cwd(),
      },
      { endpoint: backend.url.origin, accessKey: "a", secretKey: "s" },
    );
    expect((await service.start()).owned).toBe(false);
    expect((await service.observedStatus()).running).toBe(true);
    await expect(service.stop()).rejects.toThrow("not owned");
    await expect(service.restart()).rejects.toThrow("not owned");
  } finally {
    backend.stop(true);
  }
});

test("only a live session child is terminated and credentials are redacted in bounded logs", async () => {
  const service = new Service(
    {
      command: process.execPath,
      args: ["-e", 'console.error("private-secret");setInterval(()=>{},1000)'],
      cwd: process.cwd(),
    },
    {
      endpoint: "http://127.0.0.1:1",
      accessKey: "owner",
      secretKey: "private-secret",
    },
  );
  try {
    await service.start();
    expect(service.status().owned).toBe(true);
    await Bun.sleep(100);
    expect(service.tail().logs).not.toContain("private-secret");
    await service.stop();
    expect(service.status().owned).toBe(false);
  } finally {
    await service.stop();
  }
});

test("fabric preserves canonical safe failure codes without raw stderr/config leakage", async () => {
  const { FabricClient } = await import("../src/fabric");
  const dir = await mkdtemp(join(tmpdir(), "mcp-failure-"));
  try {
    const binary = join(dir, "rpc-fixture"),
      config = join(dir, "private-config");
    await writeFile(
      binary,
      "#!/bin/sh\nprintf '%s\\n' '{\"error\":\"Forbidden: device has no grant\"}' >&2\nexit 1\n",
      { mode: 0o700 },
    );
    await expect(
      new FabricClient({ binary, config }).control({ op: "info" }),
    ).rejects.toThrow("Forbidden: device has no grant");
    await writeFile(
      binary,
      "#!/bin/sh\nprintf '%s\\n' '{\"error\":\"connection refused /private/owner.json secret-value\"}' >&2\nexit 1\n",
      { mode: 0o700 },
    );
    try {
      await new FabricClient({ binary, config }).control({ op: "info" });
      throw new Error("must fail");
    } catch (e) {
      expect(String(e)).toContain("unavailable");
      expect(String(e)).not.toContain("secret-value");
      expect(String(e)).not.toContain("/private/owner.json");
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("six concurrent starts retain exactly one owned child, and stop closes its listener", async () => {
  const probe = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch: () => new Response(""),
  });
  const port = probe.port!;
  probe.stop(true);
  const endpoint = `http://127.0.0.1:${port}`;
  const service = new Service(
    {
      command: process.execPath,
      args: [
        "-e",
        `console.log('started-once');Bun.serve({hostname:'127.0.0.1',port:${port},fetch:()=>new Response('ok')})`,
      ],
      cwd: process.cwd(),
    },
    { endpoint, accessKey: "owner", secretKey: "secret" },
  );
  try {
    const results = await Promise.all(
      Array.from({ length: 6 }, () => service.start()),
    );
    expect(results.every((r) => r.owned)).toBe(true);
    let ready = false;
    for (let i = 0; i < 100; i++) {
      try {
        await fetch(endpoint);
        ready = true;
        break;
      } catch {
        await Bun.sleep(10);
      }
    }
    expect(ready).toBe(true);
    expect(service.tail().logs.match(/started-once/g)?.length).toBe(1);
    expect(service.status().owned).toBe(true);
    await service.stop();
    expect(service.status().owned).toBe(false);
    await expect(fetch(endpoint)).rejects.toThrow();
  } finally {
    await service.stop();
  }
});
