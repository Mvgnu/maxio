import { mkdtemp, writeFile, rm, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Config } from "./config";
import { boundedBody, MAX_BYTES } from "./console";
// Only concrete registered tool builders call this adapter, never arbitrary RPC input.
export class FabricClient {
  constructor(private config: Config["fabric"]) {}
  async control(request: Record<string, unknown>): Promise<unknown> {
    if (!this.config)
      throw new Error(
        "Managed fabric unavailable: owner has not configured fabric",
      );
    const dir = await mkdtemp(join(tmpdir(), "maxio-mcp-"));
    await chmod(dir, 0o700);
    let child: Bun.Subprocess<"ignore", "pipe", "pipe"> | undefined;
    try {
      const path = join(dir, "request.json");
      await writeFile(path, JSON.stringify(request), {
        mode: 0o600,
        flag: "wx",
      });
      child = Bun.spawn(
        [
          this.config.binary,
          "--config",
          this.config.config,
          "rpc",
          "--request",
          path,
        ],
        { stdin: "ignore", stdout: "pipe", stderr: "pipe" },
      );
      const timer = setTimeout(() => child?.kill(), 20000);
      try {
        const [stdout, stderr, code] = await Promise.all([
          boundedBody(new Response(child.stdout), MAX_BYTES),
          boundedBody(new Response(child.stderr), 65536),
          child.exited,
        ]);
        if (code !== 0) {
          const decoded = new TextDecoder().decode(stderr);
          let reason = "Fabric unavailable or invalid owner configuration";
          for (const line of decoded.split("\n")) {
            try {
              const parsed = JSON.parse(line);
              if (typeof parsed.error === "string") {
                const match = parsed.error.match(
                  /\b(Unauthenticated|Forbidden|Conflict|NotFound|Invalid|Unavailable|Capacity): ([^\r\n]{1,512})/,
                );
                if (match) reason = `Fabric ${match[1]}: ${match[2]}`;
              }
            } catch {}
          }
          reason = reason
            .split(this.config.config)
            .join("[owner config]")
            .split(this.config.binary)
            .join("[owner executable]");
          throw new Error(
            reason +
              "; inspect authority state before replaying the same request ID",
          );
        }
        return JSON.parse(new TextDecoder().decode(stdout));
      } finally {
        clearTimeout(timer);
      }
    } catch (error) {
      child?.kill();
      throw error;
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
}
