import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { readConfig } from "./config";
import { createServer } from "./server";
try {
  const config = await readConfig(),
    { server, service } = createServer(config);
  if (config.service?.autoStart) await service.start();
  let closing = false;
  async function close() {
    if (closing) return;
    closing = true;
    await service.dispose();
    await server.close();
    process.exit(0);
  }
  process.on("SIGTERM", () => void close());
  process.on("SIGINT", () => void close());
  process.stdin.on("end", () => void close());
  await server.connect(new StdioServerTransport());
} catch (error) {
  const message = error instanceof Error ? error.message : "";
  console.error(
    "MaxIO MCP startup failed: " +
      (message.startsWith("MCP config") ||
      message.startsWith("MAXIO_MCP_CONFIG") ||
      message.startsWith("Console endpoint") ||
      message.startsWith("Remote console")
        ? message
        : "verify owner-selected executable and service settings"),
  );
  process.exit(1);
}
