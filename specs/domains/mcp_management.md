---
{
  "name": "mcp_management",
  "description": "Operate existing MaxIO management contracts through an optional local MCP adapter",
  "paths": {
    "owned": ["mcp/src/", "mcp/scripts/", "mcp/README.md"],
    "tests": ["mcp/tests/"],
    "exclude": []
  },
  "exports": ["stdio MCP tools and structured results", "owner-local MCP client configuration"],
  "consumes": ["console_api authenticated HTTP contracts", "fabric_transport maxio-fabric rpc", "fabric_authority ControlRequest"],
  "verification": {
    "check": "cd mcp && bun run check",
    "test": "cd mcp && bun run test",
    "build": "cd mcp && bun build src/index.ts --target=bun --outdir=dist",
    "architecture": "python3 scripts/check_architecture.py"
  },
  "bar": {
    "reference": "Model Context Protocol tools specification",
    "url": "https://modelcontextprotocol.io/specification/2025-11-25/server/tools",
    "property": "A standard MCP client discovers usable schemas, performs authenticated storage operations, receives structured operational errors and accurate destructive/read-only annotations without exposing credentials or bypassing backend authority."
  },
  "artifact": "Bun stdio process connected to real disposable MaxIO storage and optional HTTPS authority; inspected with an independent MCP SDK client."
}
---

# Agent-operated management

The adapter exposes existing product operations. It must not weaken authentication,
lease/fencing, retention or data-path boundaries. Runtime/service configuration is
owner-selected and private. Tool arguments cannot replace commands or endpoints.
The default S3 executable has no dependency on this package.

Report unavailable components and failed observations explicitly. Polling a health
endpoint is not continuous monitoring. Native process control applies only to
children owned by this MCP session. Standing reconciliation is a separate product
decision. See the PM ruling in the system contract for the acceptance scope.
