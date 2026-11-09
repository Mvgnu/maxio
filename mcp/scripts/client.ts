import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { resolve } from "node:path";
export async function connect(config: string) {
  const client = new Client({ name: "maxio-smoke", version: "1.0.0" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [resolve(import.meta.dir, "../src/index.ts")],
    env: {
      ...Object.fromEntries(
        Object.entries(process.env).filter(
          (e): e is [string, string] => e[1] !== undefined,
        ),
      ),
      MAXIO_MCP_CONFIG: config,
    },
    stderr: "pipe",
  });
  await client.connect(transport);
  return {
    client,
    transport,
    call: async (name: string, args: Record<string, unknown> = {}) => {
      const result = await client.callTool({ name, arguments: args });
      if (result.isError) throw new Error(JSON.stringify(result.content));
      return (result.structuredContent as { data: any }).data;
    },
  };
}
