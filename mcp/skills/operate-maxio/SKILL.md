---
name: operate-maxio
description: "Use MaxIO MCP tools to inspect, administer and diagnose the user's configured MaxIO storage, workspaces, devices and jobs."
---

# Operate MaxIO

Use the installed `maxio-management` MCP tools for the user's requested operation.
Discover the current tool schemas and start with status/health to identify the
configured capabilities. Use concrete operations and structured results; the
operator should not need to repeat them in a browser or paste CLI output.

Keep standalone S3, managed workspaces and worker execution distinct. An absent
authority or worker is an unavailable component, not an empty healthy cluster.
Read topology, health and metrics when diagnosing unavailable reads or writes.
Do not label a TCP listener, an accepted job or an attempted restart as success;
inspect the resulting health, job state or authoritative receipt.

Use explicit paths and preserve immutable versions, leases and request IDs.
Reuse a mutation's request ID only for the identical intended request. On a lost
acknowledgment, inspect the backend state/receipt before retrying. A successful
local command is separate from publication. Job retries create a new attempt and
can repeat external effects.

Follow the user's existing authorization. Scope deletions, revocations and
lifecycle rules to the requested resources. Do not remove other data as cleanup
or invent a retention policy. Never expose private cookies, credentials, device
keys, command configuration or provider secrets in tool results or chat.

Service controls apply only to live child processes owned by that MCP session.
An external service must be managed by its actual supervisor. Report that boundary
and the observed failure clearly; do not kill saved PIDs or unrelated listeners.

Use bounded monitoring tools during active work. Persistent alerts or unattended
reconciliation need a separately configured scheduler; the MCP connection alone
does not establish either. Report concrete changes or required user action.
