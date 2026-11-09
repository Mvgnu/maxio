# MaxIO MCP

Optional Bun stdio adapter for an existing MaxIO console and managed authority.
The ordinary S3 server does not depend on this package. Requires Bun 1.3.10.

```sh
cd mcp
bun install --frozen-lockfile
chmod 600 /absolute/private/maxio-mcp.json
MAXIO_MCP_CONFIG=/absolute/private/maxio-mcp.json bun src/index.ts
```

Owner-local configuration (absolute executable/config/cwd paths):

```json
{
  "console": {"endpoint":"http://127.0.0.1:9000", "accessKey":"owner", "secretKey":"replace-me"},
  "fabric": {"binary":"/absolute/maxio-fabric", "config":"/absolute/private/owner.json"},
  "service": {"command":"/absolute/maxio", "args":["--data-dir","/absolute/private/data"], "cwd":"/absolute/project", "autoStart":false}
}
```

`fabric` and `service` are optional. Missing fabric returns an explicit MCP tool
error. Remote consoles require verified HTTPS; HTTP is loopback-only. No redirects
are followed. Configuration must be an owner-owned regular file with mode 0600.
Do not put credentials in a plugin manifest or source control.

Register your MCP client with the absolute Bun executable, absolute `src/index.ts`
argument and `MAXIO_MCP_CONFIG` environment variable. Stdout is exclusively MCP.

Tools discover health, metrics, topology, membership, placement and rebalance;
manage buckets, objects, logical folders, bearer presigned links, bucket
versioning/lifecycle and exact versions. Read results preserve backend JSON and
coverage; binary bodies use base64. Writes accept UTF-8 or base64 inline data.
Uploads/downloads and console responses are limited to 1 MiB; oversized listings
fail explicitly, with no false claim of completeness. No arbitrary file access,
HTTP proxy, command execution or endpoint argument is exposed.

Managed tools use the existing `maxio-fabric --config ... rpc --request ...`
contract for info, workspaces/current catalog, enrollment/revocation/key rotation,
grants, leases, workers and jobs (submit/status/list/cancel/retry/logs/explain).
Job submission takes the canonical typed job DTO, including current managed head
and exact immutable inputs. Names in job profiles resolve through worker owner
configuration. All mutation request IDs are caller-supplied UUIDs and echoed even
on failure: retain the ID and original contents to recover an uncertain outcome.
The adapter never retries a mutation. Fabric uses native verified HTTPS and device
proof from its owner config; it does not duplicate authentication or signing.

Service tools only supervise children started by the current MCP process. Startup
probes the configured console origin and attaches without spawning when it is
already reachable. Stop/restart refuses an external server. There is no saved PID
recovery. Shutdown stops the owned child. Logs retain the last 16 KiB; console
credentials are redacted, but other application data can appear. Commands belong
to the trusted owner; this is not a hostile-process sandbox.

`maxio_observe` samples health for at most 30 seconds. It installs no standing
monitor, daemon, alert or reconciliation job. Backend authorization and storage
safety remain authoritative. Presigned URLs are bearer credentials; share carefully.

```sh
bun run check
bun test
MAXIO_TEST_BINARY=/absolute/maxio bun run smoke
# Optional disposable HTTPS authority, already provisioned by its owner:
MAXIO_TEST_FABRIC_BINARY=/absolute/maxio-fabric MAXIO_TEST_FABRIC_CONFIG=/absolute/owner.json bun scripts/smoke-fabric.ts
```
