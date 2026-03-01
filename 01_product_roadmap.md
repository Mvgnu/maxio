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
  - Console-route preflights (`OPTIONS /api/...`) are now explicitly covered to ensure global middleware behavior is consistent outside S3 paths.
  - Runtime regression coverage now asserts preflight `Vary: Origin` and request-id propagation semantics.
  - CORS middleware now merges (instead of overwriting) existing `Vary` values and includes preflight cache-key fields (`Access-Control-Request-Method`, `Access-Control-Request-Headers`) when present.
  - CORS preflight responses now merge valid requested header names into `Access-Control-Allow-Headers` for custom metadata/tracing headers (while retaining the baseline S3/console allowlist).
  - CORS responses with reflected request origins now explicitly include `Access-Control-Allow-Credentials: true`; origin-less preflights keep wildcard origin semantics without credential headers.
  - Runtime metrics/health and CORS preflight response construction now avoid panic-prone response builders (`unwrap`) and use deterministic header/status assignment.
- Versioning hardening advanced:
  - Explicit `PUT ?versioning` XML status validation now enforced.
  - Versioning/bucket protocol validation was split into an isolated `bucket/validation` module with unit coverage.
  - Object protocol parsing (range, copy-source, HTTP-date formatting, DeleteObjects key extraction) was split into `object/parsing` with unit coverage.
  - Multipart complete XML parsing and part-number validation were split into `multipart/parsing` with unit and integration coverage for malformed, out-of-range, and non-ascending inputs.
  - Added end-to-end S3 object-version lifecycle coverage (`PUT` version IDs, `GET ?versions`, `GET ?versionId`, `DELETE ?versionId`, missing-version errors).
  - Version-aware object reads now apply HTTP range requests against the selected `versionId` payload (instead of implicitly ranging the current version).
  - `GET` range responses now also propagate `x-amz-version-id` and checksum headers consistently for both explicit `versionId` reads and current-version range reads.
  - Storage versioned read paths now share a single internal reader helper for full-object and range reads, reducing duplicated logic in version I/O flows.
  - Versioning suspend transition now preserves historical versions (no destructive cleanup on suspend).
  - Added regression coverage for preserved version history after suspend.
  - Fixed delete-marker/current-version reconciliation: deleting older versions no longer resurrects tombstoned objects.
  - Added erasure-coded versioning regression coverage for delete-marker semantics on chunked objects.
  - Storage versioning snapshot/restore paths now avoid panic-prone `version_id` unwraps and return typed invalid-data errors on corrupt metadata.
  - Added storage regression coverage for corrupted version metadata (missing `version_id`) to lock clean failure behavior.
  - S3 delete endpoints now return explicit `NoSuchBucket` for missing-bucket paths across:
    - `DELETE /{bucket}/{key}`
    - `DELETE /{bucket}/{key}?versionId=...`
    - `POST /{bucket}?delete`
  - Integration coverage now locks missing-bucket delete semantics for all three paths above.
  - S3 delete endpoints now map invalid-key paths to explicit `InvalidArgument` (instead of generic internal errors) across:
    - `DELETE /{bucket}/{key}`
    - `DELETE /{bucket}/{key}?versionId=...`
    - `POST /{bucket}?delete` per-key error entries
  - Integration coverage now locks invalid-key delete semantics for both single-delete and DeleteObjects batch flows.
  - S3 object read endpoints now return explicit `NoSuchBucket` for missing-bucket paths across:
    - `GET /{bucket}/{key}`
    - `HEAD /{bucket}/{key}`
  - Integration coverage now locks missing-bucket read semantics for both object paths above.
  - S3 list and versions-list endpoints now map invalid `prefix` query values to explicit `InvalidArgument` (instead of generic internal errors).
  - S3 list and versions-list now enforce prefix validation at query/service boundary (`validate_prefix`) before storage traversal.
  - Integration coverage now locks invalid-prefix list semantics for both `GET ?list-type=2` and `GET ?versions` paths.
  - CopyObject now returns explicit `NoSuchBucket` when either source or destination bucket is missing.
  - Integration coverage now locks missing-bucket CopyObject semantics for both source and destination bucket paths.
  - CopyObject now accepts case-insensitive `x-amz-metadata-directive` values (`copy`/`replace`) for metadata-behavior compatibility across client variations.
  - Integration coverage now locks case-insensitive metadata-directive CopyObject semantics.
  - Multipart endpoints now return explicit `NoSuchBucket` for missing-bucket paths across:
    - `POST /{bucket}/{key}?uploads=`
    - `PUT /{bucket}/{key}?partNumber=...&uploadId=...`
    - `POST /{bucket}/{key}?uploadId=...`
    - `GET /{bucket}/{key}?uploadId=...`
    - `GET /{bucket}?uploads=`
  - Integration coverage now locks missing-bucket multipart semantics for all five multipart paths above.
  - `GET ?versions` now supports marker-based pagination semantics (`max-keys`, `key-marker`, `version-id-marker`).
  - Version-list XML responses now emit `NextKeyMarker` and `NextVersionIdMarker` when truncated.
  - Console API now has regression coverage ensuring object version history remains listable after bucket versioning is suspended.
  - Web console versioning UX now reflects non-destructive suspend semantics and keeps version-history access reachable while suspended.
  - DeleteObjects request parsing now supports `<Quiet>true</Quiet>` and routes through a dedicated typed parser (`object/parsing`).
  - DeleteObjects response XML shaping is now centralized in `object/service` for deterministic request-order output and clearer handler boundaries.
  - AWS chunked upload decode now enforces strict framing semantics and rejects malformed/truncated chunked payloads with explicit `InvalidArgument` responses.
  - Integration tests cover enable/suspend and invalid-status rejection.
- Verification platform advanced:
  - Integration tests are now split into domain modules.
  - Runtime/auth/console capability tests are now isolated into dedicated integration modules for domain-local verification.
  - Shared integration helpers are now isolated in `tests/integration/helpers.rs`.
  - CORS origin-reflection behavior on successful authenticated S3 responses now has regression coverage.
  - Domain runtime verification now explicitly executes the successful-response CORS origin-reflection regression.
  - Domain runtime verification now also executes origin-less preflight regression coverage for wildcard/no-credentials CORS behavior.
  - Domain runtime verification now also executes console-route preflight regression coverage to lock shared CORS/request-id behavior across API and S3 routing paths.
  - Domain runtime verification now also executes requested-header reflection regression coverage for CORS preflight `Access-Control-Allow-Headers` shaping.
  - Storage key/upload-id validation rules now have explicit unit-test coverage.
  - Erasure/degraded-read chunk verification now runs through async shard reads in `VerifiedChunkReader` (no synchronous shard reads in stream path).
  - Extracted bucket/object/auth parser/validation helpers now have direct unit-test coverage.
  - S3 error code/status mapping and XML error response contract behavior now have focused unit-test coverage (`error::tests`).
  - S3 listing pagination/token/delimiter/version shaping helpers are now covered by focused list-service unit tests (`api::list::service::tests`).
  - S3 list-service unit coverage now also includes dedicated prefix-validation behavior (`validate_prefix`) for deterministic query-boundary rejection semantics.
  - S3 list XML transport response construction is now centralized in a dedicated helper module (`api::list::response`) with focused unit coverage (content-type/status + bucket-location XML escaping).
  - S3 object checksum extraction/response-header mapping and streaming-body decoding helpers are now covered by focused object-service unit tests (`api::object::service::tests`).
  - S3 object-service unit coverage now also includes delete-path error-mapping helpers (`map_delete_storage_err`, `map_delete_objects_err`) for invalid-key and missing-bucket edge handling.
  - S3 object-service unit coverage now also includes malformed/truncated AWS chunked-framing regressions for strict decode-path validation.
  - S3 multipart transport response helpers are now covered by focused unit tests (`api::multipart::tests`) and use panic-free response construction.
  - S3 bucket/list/object transport handlers now also use fallible panic-free response construction (`map_err`) instead of `Response::builder(...).unwrap()`.
  - S3 object/multipart mutation error mapping now preserves explicit `NoSuchBucket` semantics for storage-layer missing-bucket paths (instead of collapsing to generic internal errors).
  - S3 list/versioning read paths now also preserve explicit `NoSuchBucket` semantics when storage returns missing-bucket errors in race/edge conditions.
  - S3 bucket handlers now delegate bucket-existence checks, storage-error mapping, and XML/empty response construction to a dedicated `bucket/service` helper module.
  - Integration coverage now includes DeleteObjects quiet-mode response semantics.
  - Integration coverage now includes versions-list marker pagination roundtrip semantics.
  - Integration coverage now includes `GET ?versionId=...` + `Range` regression semantics for version-specific partial reads.
  - Integration coverage now also locks checksum-header propagation on `GET` range responses for checksum-validated objects.
  - Domain check runner now executes runtime and console response-helper unit suites in domain-local cycles (`server::tests`, `api::console::response::tests`) instead of only catching them in full-suite runs.
  - Domain check runner now also executes console auth-helper unit suites (`api::console::auth::tests`) in console domain-local cycles.
  - Domain check runner now also executes console storage-helper unit suites (`api::console::storage::tests`) in console domain-local cycles.
  - Domain check runner now also executes console list-input validation regressions (`console_tests::test_console_list_objects_returns_bad_request_for_invalid_prefix`, `console_tests::test_console_list_objects_returns_bad_request_for_empty_delimiter`, `console_tests::test_console_list_versions_returns_bad_request_for_invalid_key`) in console domain-local cycles.
  - Domain check runner now also executes console presign missing-bucket/missing-object regressions (`console_tests::test_console_presign_returns_not_found_for_missing_bucket`, `console_tests::test_console_presign_returns_not_found_for_missing_object`) in console domain-local cycles.
  - Domain check runner now also executes console presign key-encoding regression (`console_tests::test_console_presign_encodes_object_keys_with_spaces_and_utf8`) in console domain-local cycles.
  - Domain check runner now also executes console encoded-key route regressions for object delete/download and version download paths (`console_tests::test_console_object_routes_support_percent_encoded_key_path`, `console_tests::test_console_download_version_supports_percent_encoded_key_path`) in console domain-local cycles.
  - Domain check runner now also executes S3 bucket validation/service helper unit suites (`api::bucket::validation::tests`, `api::bucket::service::tests`) in S3 domain-local cycles.
  - Domain check runner now also executes S3 list-handler unit suites (`api::list::tests`) in S3 domain-local cycles.
  - Domain check runner now also executes S3 list-response helper unit suites (`api::list::response::tests`) in S3 domain-local cycles.
  - Domain check runner now also executes missing-bucket object-read regressions (`core_tests::test_get_object_missing_bucket_returns_no_such_bucket`, `core_tests::test_head_object_missing_bucket_returns_no_such_bucket`) in S3 domain-local cycles.
  - Domain check runner now also executes invalid-prefix list regressions (`core_tests::test_list_objects_invalid_prefix_returns_invalid_argument`, `core_tests::test_list_object_versions_invalid_prefix_returns_invalid_argument`) in S3 domain-local cycles.
  - Domain check runner now also executes missing-bucket CopyObject regressions (`core_tests::test_copy_object_missing_source_bucket_returns_no_such_bucket`, `core_tests::test_copy_object_missing_destination_bucket_returns_no_such_bucket`) in S3 domain-local cycles.
  - Domain check runner now also executes missing-bucket multipart regressions (`core_tests::test_multipart_create_upload_missing_bucket_returns_no_such_bucket`, `core_tests::test_multipart_upload_part_missing_bucket_returns_no_such_bucket`, `core_tests::test_multipart_complete_missing_bucket_returns_no_such_bucket`, `core_tests::test_multipart_list_parts_missing_bucket_returns_no_such_bucket`, `core_tests::test_multipart_list_uploads_missing_bucket_returns_no_such_bucket`) in S3 domain-local cycles.
  - Domain check runner now also executes invalid-key delete regressions (`core_tests::test_delete_object_invalid_key_returns_invalid_argument`, `core_tests::test_delete_objects_batch_invalid_key_returns_invalid_argument_entry`) in S3 domain-local cycles.
  - Domain check runner now also executes version-aware range regression coverage (`core_tests::test_get_object_range_with_version_id_reads_specific_version`, `core_tests::test_get_object_range_without_version_id_returns_current_version_header`) in S3 domain-local cycles.
  - Domain check runner now also executes S3 range-checksum-header regression coverage (`core_tests::test_get_object_range_preserves_checksum_header`) in S3 domain-local cycles.
  - Integration checksum regression now asserts failed checksum uploads do not leave retrievable object remnants.
  - Storage unit coverage now also locks multipart part-upload checksum-mismatch cleanup semantics (no orphaned part data/metadata files).
  - Web console API-client regressions now run through automated UI tests (`ui/src/lib/api.test.ts`) in domain verification.
  - Web console object-key path handling is now centralized and segment-encoded in the shared API client for upload/delete/presign/download/version-download routes, with dedicated UI API-client regression coverage for encoded path semantics.
  - Web console hash-route parsing/building is now centralized in a shared helper module (`ui/src/lib/navigation.ts`) with focused unit coverage (`ui/src/lib/navigation.test.ts`).
  - Web console hash-route bucket decoding now tolerates malformed percent-encoding without runtime crashes, with dedicated navigation-helper regression coverage.
  - Web console settings-route hash generation now also flows through shared navigation helpers (`buildHashRoute`) instead of ad-hoc `App.svelte` hash string assembly, with explicit route-builder regression coverage.
  - Web console object-browser path/breadcrumb/display-size helpers are now centralized in a shared helper module (`ui/src/lib/object-browser.ts`) with focused unit coverage (`ui/src/lib/object-browser.test.ts`).
  - Frontend verification (`bun run check`, `bun run build`) remains green after backend refactors.
  - Repository-wide strict lint verification now passes with `cargo clippy --all-targets -- -D warnings` (including integration test targets).
  - Integration helper/test harness signing and parity fixtures were lint-hardened (array-based sortable header sets, iterator/repeat helpers) with no behavior drift.
  - Domain check runner now enforces strict lint verification inside the `quality_harness` domain (`cargo clippy --all-targets -- -D warnings`).
  - Domain check runner `quality_harness` suite now also executes UI unit tests (`ui: bun run test`) to keep frontend regression coverage in the top-level harness cycle.
  - CI backend checks now include explicit `cargo clippy --all-targets -- -D warnings` gating before test execution.
  - CI includes non-release backend/frontend verification.
  - CI frontend checks now also execute automated UI unit tests (`bun run test`) in addition to typecheck/build.
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
  - Multipart part-upload checksum mismatches now also explicitly clean up staged part artifacts, with dedicated storage-unit regression coverage.
  - Flat-object writes now clean up staged data files when metadata persistence fails, with storage-unit regression coverage for no-orphan behavior.
  - Chunked and multipart-complete write flows now also clean up staged object artifacts when metadata persistence fails, with dedicated storage-unit regressions.
  - Storage object write/delete/multipart-init paths now enforce explicit bucket existence and reject missing-bucket mutations without implicitly creating bucket directory trees.
  - Storage listing paths (`list_objects`, `list_object_versions`, `list_multipart_uploads`) now also enforce explicit missing-bucket `NotFound` semantics instead of implicit empty/IO-derived behavior.
  - Storage version-restore/version-read and recursive folder-marker traversal paths now propagate filesystem probe errors instead of silently coercing failed probes to "not found".
  - Storage bucket metadata and version metadata/path handling are now centralized through shared internal helpers in `filesystem.rs`, reducing duplicated bucket/versioning logic while preserving behavior.
- Console readiness advanced:
  - Session/login/logout/rate-limit behavior now has dedicated integration coverage.
  - Console API handlers are split by concern (auth/buckets/objects/presign/versions) with `console.rs` as router entrypoint.
  - Console JSON success/error response shaping is centralized via shared response helpers.
  - Console versioning/version-history endpoints now return explicit `404` for missing buckets and missing versions (instead of generic `500`), with dedicated regression coverage.
  - Console object-management endpoints now return `404` for missing buckets on folder creation and object deletion paths (instead of implicit success/`500` drift), with dedicated regression coverage.
  - Console object/version download endpoints now also return explicit `404` for missing buckets, with dedicated regression coverage.
  - Console presign endpoint now also returns explicit `404` semantics for missing buckets (`Bucket not found`) and missing objects (`Object not found`), with dedicated regression coverage.
  - Console presign endpoint now has dedicated regression coverage for percent-encoded object-key signing/URL generation (spaces + UTF-8 segments).
  - Console object/version/lifecycle handlers now share a centralized storage-error helper module for consistent bucket/version `404` semantics and internal error shaping.
  - Console object/version list paths now map invalid key/prefix inputs to explicit `400` responses (instead of generic `500`/silent empty responses), with dedicated regression coverage.
  - Console object-listing now also rejects empty `delimiter` query values with explicit `400` responses to avoid ambiguous folder-grouping behavior.
  - Console object/version download handlers now use panic-free response construction for streamed responses, with safe fallback headers for malformed metadata values.
  - Integration coverage now asserts console object and version download header/body contracts.
  - Integration coverage now also asserts console object delete/download and version-download behavior for percent-encoded key paths (spaces/`+`/`#`), aligning console route handling with UI key-path encoding.
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
  - Console auth/session internals now avoid panic-prone lock/HMAC/cookie parsing paths and return explicit error responses on internal token/cookie failures.
  - Console session cookie `Secure`-flag detection now robustly handles forwarded-proto header variants (case-insensitive and comma-separated proxy values) with dedicated auth-unit coverage.
  - Presigned S3 auth now rejects excessive future `X-Amz-Date` skew (`RequestTimeTooSkewed`) with dedicated integration coverage.
  - Presigned S3 auth now has explicit unknown-access-key regression coverage (`InvalidAccessKeyId`) in the credential matrix.
  - SigV4 verify/presign signing flow now avoids panic-prone HMAC `unwrap` paths and uses explicit fallible helper handling.
  - SigV4 presigned-query parsing now decodes `X-Amz-*` query components consistently (including encoded `X-Amz-SignedHeaders`) and rejects invalid UTF-8 encoded query-component bytes.
  - SigV4 presigned request detection/verification now also handles percent-encoded `X-Amz-Signature` query keys consistently (middleware detection + canonical signature-filter path).
  - SigV4 header-auth and presigned-query parsers now reject duplicated auth components (`Credential`/`SignedHeaders`/`Signature`, duplicated `X-Amz-*`) to avoid ambiguous signature inputs.
  - SigV4 header-auth parsing now rejects unrecognized `Authorization` components to avoid silent acceptance of malformed/ambiguous auth headers.
  - Integration coverage now includes duplicate-component rejection regressions for both `Authorization` header inputs and presigned `X-Amz-*` query inputs.
  - SigV4 canonical URI normalization now decodes and re-encodes path segments to avoid double-encoding already-encoded request paths in presigned verification flows.
  - Shared SigV4 presign generation now uses a typed `PresignRequest` contract instead of positional multi-argument call sites.
  - Auth domain verification now explicitly includes `auth::signature_v4::tests` in domain-local checks.
  - Auth domain verification now also executes duplicate SigV4 component rejection integration regressions in domain-local cycles.
- Distributed bootstrap groundwork advanced:
  - Runtime config now supports `MAXIO_NODE_ID` and `MAXIO_CLUSTER_PEERS` for topology bootstrap wiring.
  - `/healthz` and `/metrics` now expose standalone/distributed runtime topology context.
  - Integration coverage includes distributed-mode health reporting when peers are configured.
  - Runtime process shutdown now handles SIGINT and SIGTERM (Unix) via graceful-drain signal handling without panic-prone `expect` paths.

## Governance

- Any roadmap item touching more than one domain must be split into sequential domain cycles.
- Each cycle must update both the relevant domain spec and this roadmap spec status.
- Roadmap status in docs should be updated once cycle verification passes.
