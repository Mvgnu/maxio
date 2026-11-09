import { afterEach, describe, expect, test } from "bun:test";
import { ConsoleClient, objectPath } from "../src/console";

const servers: ReturnType<typeof Bun.serve>[] = [];
afterEach(() => {
  for (const server of servers.splice(0)) server.stop(true);
});
function endpoint(handler: (request: Request) => Response | Promise<Response>) {
  const server = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: handler });
  servers.push(server);
  return server.url.origin;
}
function client(url: string) {
  return new ConsoleClient({
    endpoint: url,
    accessKey: "owner",
    secretKey: "never-echo-this",
  });
}

describe("authenticated console bridge", () => {
  test("one login is shared by concurrent requests and cookies never enter results", async () => {
    let logins = 0;
    const url = endpoint(async (request) => {
      if (new URL(request.url).pathname === "/api/auth/login") {
        logins++;
        expect(await request.json()).toEqual({
          accessKey: "owner",
          secretKey: "never-echo-this",
        });
        return Response.json(
          { ok: true },
          {
            headers: { "set-cookie": "maxio_session=opaque; Path=/; HttpOnly" },
          },
        );
      }
      expect(request.headers.get("cookie")).toBe("maxio_session=opaque");
      return Response.json({ ok: true });
    });
    const api = client(url);
    expect(
      await Promise.all([
        api.json("GET", "/api/system/health"),
        api.json("GET", "/api/buckets"),
      ]),
    ).toEqual([{ ok: true }, { ok: true }]);
    expect(logins).toBe(1);
  });

  test("restart-invalidated sessions are refreshed once", async () => {
    let logins = 0;
    let attempts = 0;
    const api = client(
      endpoint((request) => {
        if (new URL(request.url).pathname === "/api/auth/login") {
          logins++;
          return Response.json(
            { ok: true },
            {
              headers: {
                "set-cookie": `maxio_session=session${logins}; HttpOnly`,
              },
            },
          );
        }
        attempts++;
        return attempts === 1
          ? Response.json({ error: "Not authenticated" }, { status: 401 })
          : Response.json({ ok: true });
      }),
    );
    expect(await api.json("GET", "/api/buckets")).toEqual({ ok: true });
    expect(logins).toBe(2);
    expect(attempts).toBe(2);
  });

  test("a failed mutation is reported without automatic retries or secret disclosure", async () => {
    let writes = 0;
    const api = client(
      endpoint((request) => {
        if (new URL(request.url).pathname === "/api/auth/login")
          return Response.json(
            {},
            { headers: { "set-cookie": "maxio_session=opaque" } },
          );
        writes++;
        return Response.json({ error: "storage unavailable" }, { status: 503 });
      }),
    );
    await expect(
      api.json("POST", "/api/buckets", { name: "test" }),
    ).rejects.toThrow("503");
    expect(writes).toBe(1);
  });

  test("redirects are refused so credentials cannot be forwarded", async () => {
    let leaked = false;
    const other = endpoint(() => {
      leaked = true;
      return Response.json({});
    });
    const api = client(endpoint(() => Response.redirect(other, 307)));
    await expect(api.json("GET", "/api/buckets")).rejects.toThrow("307");
    expect(leaked).toBe(false);
  });

  test("remote plaintext endpoints and path-bearing origins are refused", () => {
    expect(() => client("http://example.com")).toThrow();
    expect(() => client("http://127.0.0.1:9000/api")).toThrow();
  });

  test("object names preserve delimiters and cannot escape into another API route", () => {
    expect(objectPath("my-bucket", "objects", "notes/a?#%.txt")).toBe(
      "/api/buckets/my-bucket/objects/notes/a%3F%23%25.txt",
    );
    for (const key of ["../system/health", "a/../b", "./x", "/x", "a//b"])
      expect(() => objectPath("my-bucket", "objects", key)).toThrow();
  });
});
