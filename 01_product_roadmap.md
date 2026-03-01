---
name: product_roadmap
description: "Roadmap-to-domain mapping for MaxIO delivery planning and execution"
---

# Product Roadmap Spec

## Source Snapshot

Roadmap sources reviewed on March 1, 2026:

- `README.md` -> `## Roadmap`
- `CLAUDE.md` -> phased roadmap section

## Roadmap Items (Reflected)

From README:

- Multipart upload, presigned URLs, CopyObject: completed
- CORS: completed
- Range headers: completed
- Versioning: pending (implementation exists, requires production-hardening cycle)
- Lifecycle rules: completed (baseline storage + S3/API/UI flows delivered; hardening/compat expansion pending)
- Metrics: completed (baseline runtime + UI visibility delivered; deeper operational metrics pending)
- Multi-user support: pending (credential-foundation delivered; identity/authorization layers pending)
- Distributed mode: pending
- Erasure coding: completed (requires continued hardening)
- Replication: pending

From CLAUDE phased roadmap (additional context):

- DeleteObjects batch: completed
- Web console SPA: completed
- Metrics: baseline completed, expansion pending

## Domain Ownership Mapping

- `runtime_platform`
  - Metrics plumbing and service-level runtime wiring
  - Distributed runtime topology/bootstrap hooks
- `storage_engine`
  - Lifecycle rule execution and retention behavior
  - Replication and distributed storage primitives
  - Erasure-coding correctness/performance hardening
- `s3_auth_sigv4`
  - Multi-user auth model foundation for request signing/verification
- `s3_api_surface`
  - CORS behavior and S3-facing lifecycle APIs
  - Distributed/replication-aware API behavior
- `console_api`
  - Multi-user session/auth flows
  - JSON endpoints for lifecycle/metrics/admin workflows
- `web_console_ui`
  - Multi-user and policy-oriented UX
  - Lifecycle/metrics UI workflows
- `quality_harness`
  - End-to-end regression and compatibility tests for each roadmap item

## Delivery Order (Roadmap-Aware)

1. CORS (low-risk, high-utility compatibility gap)
2. Versioning hardening completion and test expansion
3. Lifecycle rules (storage + API + console/UI)
4. Multi-user support (auth + console + UI + config)
5. Metrics (runtime + API exposure + UI)
6. Replication and distributed mode (largest cross-domain scope)

## Progress Notes (March 1, 2026)

- CORS delivered:
  - Global CORS middleware is active for API/S3 flows.
  - Preflight and error-path CORS behavior has integration coverage.
  - Runtime regression coverage now asserts preflight `Vary: Origin` and request-id propagation semantics.
  - CORS middleware now merges (instead of overwriting) existing `Vary` values and includes preflight cache-key fields (`Access-Control-Request-Method`, `Access-Control-Request-Headers`) when present.
  - Runtime metrics/health and CORS preflight response construction now avoid panic-prone response builders (`unwrap`) and use deterministic header/status assignment.
- Versioning hardening advanced:
  - Explicit `PUT ?versioning` XML status validation now enforced.
  - Versioning/bucket protocol validation was split into an isolated `bucket/validation` module with unit coverage.
  - Object protocol parsing (range, copy-source, HTTP-date formatting, DeleteObjects key extraction) was split into `object/parsing` with unit coverage.
  - Multipart complete XML parsing and part-number validation were split into `multipart/parsing` with unit and integration coverage for malformed, out-of-range, and non-ascending inputs.
  - Added end-to-end S3 object-version lifecycle coverage (`PUT` version IDs, `GET ?versions`, `GET ?versionId`, `DELETE ?versionId`, missing-version errors).
  - Versioning suspend transition now preserves historical versions (no destructive cleanup on suspend).
  - Added regression coverage for preserved version history after suspend.
  - Fixed delete-marker/current-version reconciliation: deleting older versions no longer resurrects tombstoned objects.
  - Added erasure-coded versioning regression coverage for delete-marker semantics on chunked objects.
  - S3 delete endpoints now return explicit `NoSuchBucket` for missing-bucket paths across:
    - `DELETE /{bucket}/{key}`
    - `DELETE /{bucket}/{key}?versionId=...`
    - `POST /{bucket}?delete`
  - Integration coverage now locks missing-bucket delete semantics for all three paths above.
  - `GET ?versions` now supports marker-based pagination semantics (`max-keys`, `key-marker`, `version-id-marker`).
  - Version-list XML responses now emit `NextKeyMarker` and `NextVersionIdMarker` when truncated.
  - Console API now has regression coverage ensuring object version history remains listable after bucket versioning is suspended.
  - Web console versioning UX now reflects non-destructive suspend semantics and keeps version-history access reachable while suspended.
  - DeleteObjects request parsing now supports `<Quiet>true</Quiet>` and routes through a dedicated typed parser (`object/parsing`).
  - DeleteObjects response XML shaping is now centralized in `object/service` for deterministic request-order output and clearer handler boundaries.
  - Integration tests cover enable/suspend and invalid-status rejection.
- Verification platform advanced:
  - Integration tests are now split into domain modules.
  - Runtime/auth/console capability tests are now isolated into dedicated integration modules for domain-local verification.
  - Shared integration helpers are now isolated in `tests/integration/helpers.rs`.
  - CORS origin-reflection behavior on successful authenticated S3 responses now has regression coverage.
  - Domain runtime verification now explicitly executes the successful-response CORS origin-reflection regression.
  - Storage key/upload-id validation rules now have explicit unit-test coverage.
  - Erasure/degraded-read chunk verification now runs through async shard reads in `VerifiedChunkReader` (no synchronous shard reads in stream path).
  - Extracted bucket/object/auth parser/validation helpers now have direct unit-test coverage.
  - S3 error code/status mapping and XML error response contract behavior now have focused unit-test coverage (`error::tests`).
  - S3 listing pagination/token/delimiter/version shaping helpers are now covered by focused list-service unit tests (`api::list::service::tests`).
  - S3 object checksum extraction/response-header mapping and streaming-body decoding helpers are now covered by focused object-service unit tests (`api::object::service::tests`).
  - Integration coverage now includes DeleteObjects quiet-mode response semantics.
  - Integration coverage now includes versions-list marker pagination roundtrip semantics.
  - Integration checksum regression now asserts failed checksum uploads do not leave retrievable object remnants.
  - Web console API-client regressions now run through automated UI tests (`ui/src/lib/api.test.ts`) in domain verification.
  - Frontend verification (`bun run check`, `bun run build`) remains green after backend refactors.
  - CI includes non-release backend/frontend verification.
  - AWS CLI and mc compatibility scripts now include lifecycle regression flows.
- Metrics groundwork advanced:
  - Runtime Prometheus-style `/metrics` endpoint is now available with request count, uptime, and build info gauges/counters.
  - Runtime health endpoint `/healthz` is now available for lightweight liveness/readiness checks.
  - Integration coverage includes `/metrics` endpoint behavior.
  - Integration coverage now asserts distributed metrics gauge values when cluster peers are configured.
  - Console API now exposes authenticated JSON metrics endpoint (`/api/system/metrics`) including runtime topology context.
  - Console API now also exposes authenticated health endpoint (`/api/system/health`) to mirror runtime health/topology context for admin workflows.
  - Console API now also exposes authenticated topology endpoint (`/api/system/topology`) for distributed admin workflows.
  - Web console now includes a metrics view wired to runtime metrics output and topology context (mode/node/peer count).
  - Web console typed API client now supports `/api/system/health`, with shared topology normalization reused across metrics/topology/health flows.
  - Web console metrics panel now surfaces explicit health status from `/api/system/health` alongside runtime counters.
- Lifecycle delivery advanced:
  - Storage lifecycle rules are persisted and executable, with periodic runtime sweeps.
  - Storage lifecycle regressions now assert disabled rules do not delete matching objects.
  - Storage validation and path-layout responsibilities are now isolated into dedicated modules (`storage/validation`, `storage/layout`) to support further `filesystem.rs` decomposition.
  - S3 lifecycle APIs are available (`PUT/GET/DELETE ?lifecycle`) with explicit lifecycle XML contracts.
  - Console lifecycle admin JSON endpoints are available and test-backed.
  - Web console bucket settings now expose lifecycle rule management UX.
  - Storage checksum-write finalization now uses typed error paths (no panic-on-invariant `unwrap` in write flows), with cleanup of staged files on checksum mismatch.
  - Flat-object writes now clean up staged data files when metadata persistence fails, with storage-unit regression coverage for no-orphan behavior.
  - Chunked and multipart-complete write flows now also clean up staged object artifacts when metadata persistence fails, with dedicated storage-unit regressions.
- Console readiness advanced:
  - Session/login/logout/rate-limit behavior now has dedicated integration coverage.
  - Console API handlers are split by concern (auth/buckets/objects/presign/versions) with `console.rs` as router entrypoint.
  - Console JSON success/error response shaping is centralized via shared response helpers.
  - Console versioning/version-history endpoints now return explicit `404` for missing buckets and missing versions (instead of generic `500`), with dedicated regression coverage.
  - Console object-management endpoints now return `404` for missing buckets on folder creation and object deletion paths (instead of implicit success/`500` drift), with dedicated regression coverage.
  - Console object/version download handlers now use panic-free response construction for streamed responses, with safe fallback headers for malformed metadata values.
  - Integration coverage now asserts console object and version download header/body contracts.
  - Integration coverage now locks console JSON contract shapes for bucket/object success payloads and auth/protected-route error payloads.
  - Integration coverage now includes tampered-session-cookie rejection for protected console routes.
  - Integration coverage now includes session-boundary rejection for expired and future-dated console cookies.
- Multi-user foundation advanced:
  - Runtime config now supports additional credential pairs (`MAXIO_ADDITIONAL_CREDENTIALS`).
  - SigV4 and console auth now validate against the shared credential map.
  - Integration credential-matrix coverage now validates primary/secondary acceptance and unknown-key rejection for S3 SigV4 requests.
  - Presigned S3 GET flows now include regression coverage for secondary-credential signing/verification.
  - SigV4 now enforces strict credential-scope semantics (`.../s3/aws4_request`) for both header-auth and presigned requests.
  - Console exposes authenticated identity context via `/api/auth/check` and `/api/auth/me` (access key + session issued/expiry metadata).
  - Console presign endpoint now signs URLs with the authenticated session identity (instead of fixed primary credentials).
  - Login response now includes session identity metadata for client-side state alignment.
  - Web console now hydrates auth identity from `/api/auth/check` and surfaces session expiry context in the shell UI.
  - Integration coverage includes secondary-credential S3 signing and console login flows.
  - Console login now also has explicit primary/secondary/unknown credential-matrix regression coverage.
  - Presigned S3 auth now rejects excessive future `X-Amz-Date` skew (`RequestTimeTooSkewed`) with dedicated integration coverage.
  - Presigned S3 auth now has explicit unknown-access-key regression coverage (`InvalidAccessKeyId`) in the credential matrix.
- Distributed bootstrap groundwork advanced:
  - Runtime config now supports `MAXIO_NODE_ID` and `MAXIO_CLUSTER_PEERS` for topology bootstrap wiring.
  - `/healthz` and `/metrics` now expose standalone/distributed runtime topology context.
  - Integration coverage includes distributed-mode health reporting when peers are configured.

## Governance

- Any roadmap item touching more than one domain must be split into sequential domain cycles.
- Each cycle must update both the relevant domain spec and this roadmap spec status.
- Roadmap status in docs should be updated once cycle verification passes.
