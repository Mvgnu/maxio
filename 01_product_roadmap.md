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

## Explicit Near-Term Gaps (March 2, 2026)

- Storage decomposition (`storage_engine`):
  - `src/storage/filesystem.rs` staged split Stages 1-4 are complete and currently sufficient; Stage 5 facade-thinning is deferred unless measurable coupling/regression pressure appears.
- Console contract typing (`console_api`):
  - Console handler responses are now migrated to typed DTO contracts across system, buckets, versions, objects, lifecycle, presign, and auth/session paths; keep new endpoint work on typed DTOs and contract tests to prevent regression into ad-hoc payload maps.
- Membership protocol semantics (`runtime_platform`):
  - `gossip`/`raft` config values exist as typed options but do not yet activate corresponding protocol engines; runtime behavior and operator messaging should make this explicit until engines land.
- Placement state model (`storage_engine` + `s3_api_surface` + `runtime_platform`) [active]:
  - promote stateless placement helpers to an epoch-backed placement state model (`placementViewId` + persisted epoch semantics). (foundation now landed in storage with typed placement state helpers)
  - define handoff coordination state and transfer lifecycle between previous and next owner sets. (deterministic handoff plan/role model now landed in storage)
  - implement the forwarded-write wire protocol (request/ack/failure contract) so any-node writes route to the correct owner/quorum path. (typed forwarding envelope + S3 header wiring + persisted runtime epoch integration now landed; distributed `PUT` + `CopyObject` + multipart-complete + single-object `DELETE` including version-specific delete replica fanout + quorum observation are active, multipart operation-family forwarding is active across create/upload/list/abort/complete, and mixed-owner `DeleteObjects` multi-target forwarding/quorum aggregation is now active)
  - read-repair runtime wiring is active for primary-owner current-version `GET`/`HEAD` paths (trusted replica-head probes + replica upsert/delete repairs), with explicit execution-policy modeling to avoid implicit quorum-bypass behavior.
  - add split-brain safeguards for conflicting membership views and stale forwarding epochs.
- Health readiness accuracy (`runtime_platform` + `quality_harness`):
  - `/healthz` now includes probe-backed degraded readiness for data-dir access/writeability, storage data-path readability, configurable disk headroom thresholds, membership-protocol readiness, and static-bootstrap peer-connectivity probing; extend with deeper dependency probes (membership convergence/split-brain health) and keep regression coverage current as readiness contracts evolve.

## Distributed Foundation Scorecard (March 2, 2026)

| Layer | Difficulty | Status | Evidence |
|---|---|---|---|
| Consistent hashing / placement | Medium | Done | `storage::placement` rendezvous ownership, write plans/quorum evaluation, read-repair planning, rebalance planning, typed placement view/epoch contracts |
| Write forwarding / quorum | Hard | In progress (~97%) | Non-owner `PUT`/`CopyObject`/`DELETE` and `DeleteObjects` (single-target + mixed-owner multi-target) forwarding are active with loop/epoch/view guards and spoofed-header hardening; non-owner `GET`/`HEAD` forwarding is active; multipart operation-family non-owner forwarding (`create/upload/list/abort/complete`) is active; distributed primary-owner `PUT`, `CopyObject`, multipart-complete, and single-object `DELETE` (including version-specific delete) perform replica fanout with quorum ack diagnostics (`x-maxio-write-ack-count`, `x-maxio-write-quorum-size`, `x-maxio-write-quorum-reached`); mixed-owner `DeleteObjects` now aggregates available quorum diagnostics at batch level, with remaining gap on per-entry quorum diagnostics surfacing |
| Placement state / epochs | Medium | Done | `PlacementViewState` epoch/view state wired to runtime persistence (`placement-state.json`) and surfaced in `/healthz`, `/metrics`, console system APIs |
| Read repair | Medium | In progress (~70%) | Typed read-repair planning/execution is implemented; primary-owner current-version `GET`/`HEAD` read paths now execute runtime read-repair with trusted replica probes and repair fanout; remaining scope is broader read-family wiring and hardening |
| Rebalancing on topology change | Very hard | Planning done | Typed `ObjectRebalancePlan`/`RebalanceTransfer` plus console preview endpoint exist; runtime transfer executor is not yet implemented |
| Gossip / Raft membership | Hard | Config only | `MembershipProtocol` enum/config exists, `/healthz` + startup warnings mark unimplemented protocols as degraded, no live membership engine yet |

## Progress Notes (March 1, 2026)

- CORS delivered:
  - Global CORS middleware is active for API/S3 flows.
  - Preflight and error-path CORS behavior has integration coverage.
  - Console-route preflights (`OPTIONS /api/...`) are now explicitly covered to ensure global middleware behavior is consistent outside S3 paths.
  - Runtime regression coverage now asserts preflight `Vary: Origin` and request-id propagation semantics.
  - CORS middleware now merges (instead of overwriting) existing `Vary` values and includes preflight cache-key fields (`Access-Control-Request-Method`, `Access-Control-Request-Headers`) when present.
  - CORS preflight responses now merge valid requested header names into `Access-Control-Allow-Headers` for custom metadata/tracing headers (while retaining the baseline S3/console allowlist).
  - CORS middleware now captures request headers from the inbound request before `next.run()` (including non-preflight flows), removing brittle response-extension ordering assumptions with request-id middleware layering.
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
  - Added erasure-coded version-aware range regression coverage for `GET ?versionId=...` + `Range` semantics on chunked object paths.
  - Added erasure-coded version-recovery regression coverage for restoring previous current versions after deleting the latest chunked object version.
  - Storage versioning snapshot/restore paths now avoid panic-prone `version_id` unwraps and return typed invalid-data errors on corrupt metadata.
  - Added storage regression coverage for corrupted version metadata (missing `version_id`) to lock clean failure behavior.
  - Storage version snapshot writers now clean partial `.versions` artifacts on snapshot-metadata write failures (flat and chunked paths), avoiding orphaned version data during partial-write failures.
  - Added storage unit regressions for version snapshot partial-write cleanup on metadata persistence failures.
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
  - S3 list query dispatch now rejects unsupported `list-type` values (for example `list-type=1`) with explicit `InvalidArgument` instead of silently falling back to v1 behavior.
  - S3 versions-list query parsing now rejects orphaned `version-id-marker` values unless `key-marker` is also present (`InvalidArgument`).
  - S3 list query parsing now rejects empty `delimiter` values for both v1 and v2 list routes with explicit `InvalidArgument`.
  - Integration coverage now locks invalid-prefix list semantics for both `GET ?list-type=2` and `GET ?versions` paths.
  - Integration coverage now also locks invalid list query-combination semantics for `GET ?list-type=1` and `GET ?versions&version-id-marker=...`.
  - Integration coverage now also locks empty-delimiter list query semantics for both `GET ?delimiter=` and `GET ?list-type=2&delimiter=`.
  - CopyObject now returns explicit `NoSuchBucket` when either source or destination bucket is missing.
  - Integration coverage now locks missing-bucket CopyObject semantics for both source and destination bucket paths.
  - CopyObject now accepts case-insensitive `x-amz-metadata-directive` values (`copy`/`replace`) for metadata-behavior compatibility across client variations.
  - Integration coverage now locks case-insensitive metadata-directive CopyObject semantics.
  - CopyObject now supports `x-amz-copy-source` `versionId` query semantics for version-targeted source copies.
  - Integration coverage now locks version-targeted CopyObject behavior and `x-amz-copy-source-version-id` response propagation.
  - CopyObject source parsing now rejects empty source bucket/key values in decoded `x-amz-copy-source` paths.
  - Integration coverage now locks invalid `x-amz-copy-source` empty-bucket/empty-key semantics.
  - CopyObject source parsing now rejects double-leading-slash `x-amz-copy-source` inputs instead of collapsing them into valid bucket/key paths.
  - Integration coverage now locks double-leading-slash `x-amz-copy-source` rejection semantics.
  - Multipart endpoints now return explicit `NoSuchBucket` for missing-bucket paths across:
    - `POST /{bucket}/{key}?uploads=`
    - `PUT /{bucket}/{key}?partNumber=...&uploadId=...`
    - `POST /{bucket}/{key}?uploadId=...`
    - `GET /{bucket}/{key}?uploadId=...`
    - `GET /{bucket}?uploads=`
  - Integration coverage now locks missing-bucket multipart semantics for all five multipart paths above.
  - `GET /{bucket}/{key}?uploadId=...` now supports marker-based pagination semantics for multipart parts (`part-number-marker`, `max-parts` capped to `1000`) and emits `PartNumberMarker`/`NextPartNumberMarker`/`MaxParts` response fields.
  - Integration coverage now locks multipart list-parts pagination and invalid query semantics (`max-parts`, `part-number-marker`).
  - `GET ?versions` now supports marker-based pagination semantics (`max-keys`, `key-marker`, `version-id-marker`).
  - Version-list XML responses now emit `NextKeyMarker` and `NextVersionIdMarker` when truncated.
  - Console API now has regression coverage ensuring object version history remains listable after bucket versioning is suspended.
  - Web console versioning UX now reflects non-destructive suspend semantics and keeps version-history access reachable while suspended.
  - DeleteObjects request parsing now supports `<Quiet>true</Quiet>` and routes through a dedicated typed parser (`object/parsing`).
  - DeleteObjects request parsing now enforces strict XML text unescape handling (invalid escaped content is rejected as malformed XML).
  - DeleteObjects request parsing now enforces S3 batch cardinality limits (more than 1000 keys rejected as malformed XML before mutation).
  - DeleteObjects request parsing now enforces `Delete/Object/Key` XML structure (for example `<Key>` outside `<Object>` is rejected as malformed XML).
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
  - S3 list bucket-existence guarding and storage-error mapping are now centralized in list-service helpers (`ensure_bucket_exists`, `map_bucket_storage_err`) with focused unit coverage.
  - S3 bucket-level `GET` query dispatch precedence is now centralized in a list-service resolver (`resolve_bucket_get_operation`) with focused unit coverage for stable operation selection semantics.
  - S3 list XML transport response construction is now centralized in a dedicated helper module (`api::list::response`) with focused unit coverage (content-type/status + bucket-location XML escaping).
  - S3 object checksum extraction/response-header mapping and streaming-body decoding helpers are now covered by focused object-service unit tests (`api::object::service::tests`).
  - S3 object-service unit coverage now also includes shared object read/write storage-error mapping helpers (`map_object_get_err`, `map_object_version_get_err`, `map_object_put_err`) for consistent `NoSuchKey`/`NoSuchVersion`/`NoSuchBucket` contract shaping across handlers.
  - S3 object-service unit coverage now also includes delete-path error-mapping helpers (`map_delete_storage_err`, `map_delete_objects_err`) for invalid-key and missing-bucket edge handling.
  - S3 object-service unit coverage now also includes malformed/truncated AWS chunked-framing regressions for strict decode-path validation.
  - S3 object GET/HEAD/range response construction is now centralized via shared object-service helper (`object_response`) with focused unit coverage for deterministic `Content-Length`/`Content-Range` and version/checksum header shaping.
  - S3 multipart transport response helpers are now covered by focused unit tests (`api::multipart::tests`) and use panic-free response construction.
  - S3 multipart transport guard/error/response helpers are now centralized in a dedicated service submodule (`api::multipart::service`) to keep handlers transport-focused and reduce inline duplication.
  - S3 bucket/list/object transport handlers now also use fallible panic-free response construction (`map_err`) instead of `Response::builder(...).unwrap()`.
  - S3 object/multipart mutation error mapping now preserves explicit `NoSuchBucket` semantics for storage-layer missing-bucket paths (instead of collapsing to generic internal errors).
  - S3 list/versioning read paths now also preserve explicit `NoSuchBucket` semantics when storage returns missing-bucket errors in race/edge conditions.
  - S3 bucket handlers now delegate bucket-existence checks, storage-error mapping, and XML/empty response construction to a dedicated `bucket/service` helper module.
  - Integration coverage now includes DeleteObjects quiet-mode response semantics.
  - Integration coverage now also includes strict DeleteObjects XML regressions for invalid escaped key text, invalid XML structure, and >1000 key request limits.
  - Integration coverage now includes versions-list marker pagination roundtrip semantics.
  - Integration coverage now includes `GET ?versionId=...` + `Range` regression semantics for version-specific partial reads.
  - Integration coverage now also locks checksum-header propagation on `GET` range responses for checksum-validated objects.
  - Domain check runner now executes runtime and console response-helper unit suites in domain-local cycles (`server::tests`, `api::console::response::tests`) instead of only catching them in full-suite runs.
  - Domain check runner now also executes console auth-helper unit suites (`api::console::auth::tests`) in console domain-local cycles.
  - Domain check runner now also executes console storage-helper unit suites (`api::console::storage::tests`) in console domain-local cycles.
  - Domain check runner now also executes console list-input validation regressions (`console_tests::test_console_list_objects_returns_bad_request_for_invalid_prefix`, `console_tests::test_console_list_objects_returns_bad_request_for_empty_delimiter`, `console_tests::test_console_list_versions_returns_bad_request_for_invalid_key`) in console domain-local cycles.
  - Domain check runner now also executes console system-summary regressions (`console_tests::test_console_summary_endpoint_requires_auth_and_returns_json`, `console_tests::test_console_summary_endpoint_reports_distributed_mode_when_configured`) in console domain-local cycles.
  - Domain check runner now also executes console degraded-readiness system regressions (`console_tests::test_console_health_endpoint_reports_degraded_when_storage_data_path_probe_fails`, `console_tests::test_console_summary_endpoint_reports_degraded_health_when_storage_data_path_probe_fails`) in console domain-local cycles.
  - Domain check runner now also executes console system-contract shape regressions (`console_tests::test_console_health_endpoint_contract_shape_is_stable`, `console_tests::test_console_summary_endpoint_contract_shape_is_stable`) in console domain-local cycles.
  - Domain check runner now also executes console membership regressions (`console_tests::test_console_membership_endpoint_requires_auth_and_returns_json`, `console_tests::test_console_membership_endpoint_reports_distributed_mode_when_configured`) in console domain-local cycles.
  - Domain check runner now also executes console placement regressions (`console_tests::test_console_placement_endpoint_requires_auth_and_returns_json`, `console_tests::test_console_placement_endpoint_reports_distributed_chunk_owners`, `console_tests::test_console_placement_endpoint_contract_shape_is_stable`, `console_tests::test_console_placement_endpoint_rejects_invalid_query`) in console domain-local cycles.
  - Domain check runner now also executes console rebalance regressions (`console_tests::test_console_rebalance_endpoint_requires_auth_and_reports_join_preview`, `console_tests::test_console_rebalance_endpoint_reports_distributed_leave_preview`, `console_tests::test_console_rebalance_endpoint_rejects_invalid_query`) in console domain-local cycles.
  - Console placement invalid-query regressions now also lock invalid-key and invalid-chunk-index semantics in `/api/system/placement` request validation.
  - Domain check runner now also executes console presign missing-bucket/missing-object regressions (`console_tests::test_console_presign_returns_not_found_for_missing_bucket`, `console_tests::test_console_presign_returns_not_found_for_missing_object`) in console domain-local cycles.
  - Domain check runner now also executes console presign key-encoding regression (`console_tests::test_console_presign_encodes_object_keys_with_spaces_and_utf8`) in console domain-local cycles.
  - Domain check runner now also executes console encoded-key route regressions for object delete/download and version download paths (`console_tests::test_console_object_routes_support_percent_encoded_key_path`, `console_tests::test_console_download_version_supports_percent_encoded_key_path`) in console domain-local cycles.
  - Domain check runner now also executes S3 bucket validation/service helper unit suites (`api::bucket::validation::tests`, `api::bucket::service::tests`) in S3 domain-local cycles.
  - Domain check runner now also executes S3 list-handler unit suites (`api::list::tests`) in S3 domain-local cycles.
  - Domain check runner now also executes S3 list-response helper unit suites (`api::list::response::tests`) in S3 domain-local cycles.
  - Domain check runner now also executes S3 object parser unit suites (`api::object::parsing::tests`) in S3 domain-local cycles.
  - Domain check runner now also executes missing-bucket object-read regressions (`core_tests::test_get_object_missing_bucket_returns_no_such_bucket`, `core_tests::test_head_object_missing_bucket_returns_no_such_bucket`) in S3 domain-local cycles.
  - Domain check runner now also executes invalid-prefix list regressions (`core_tests::test_list_objects_invalid_prefix_returns_invalid_argument`, `core_tests::test_list_object_versions_invalid_prefix_returns_invalid_argument`) in S3 domain-local cycles.
  - Domain check runner now also executes invalid list query-combination regressions (`core_tests::test_list_objects_invalid_list_type_returns_invalid_argument`, `core_tests::test_list_object_versions_orphaned_version_id_marker_returns_invalid_argument`) in S3 domain-local cycles.
  - Domain check runner now also executes empty-delimiter list regressions (`core_tests::test_list_objects_v2_empty_delimiter_returns_invalid_argument`, `core_tests::test_list_objects_v1_empty_delimiter_returns_invalid_argument`) in S3 domain-local cycles.
  - Domain check runner now also executes missing-bucket CopyObject regressions (`core_tests::test_copy_object_missing_source_bucket_returns_no_such_bucket`, `core_tests::test_copy_object_missing_destination_bucket_returns_no_such_bucket`) in S3 domain-local cycles.
  - Domain check runner now also executes CopyObject metadata-directive compatibility regression (`core_tests::test_copy_object_metadata_directive_is_case_insensitive`) in S3 domain-local cycles.
  - Domain check runner now also executes CopyObject source-version compatibility regression (`core_tests::test_copy_object_can_target_specific_source_version`) in S3 domain-local cycles.
  - Domain check runner now also executes CopyObject invalid-source-shape regressions (`core_tests::test_copy_object_rejects_empty_source_key`, `core_tests::test_copy_object_rejects_empty_source_bucket`) in S3 domain-local cycles.
  - Domain check runner now also executes CopyObject double-leading-slash-source regression (`core_tests::test_copy_object_rejects_double_leading_slash_source`) in S3 domain-local cycles.
  - S3 object-service now exposes typed write-routing diagnostics (`ObjectWriteRoutingHint`, `object_write_routing_hint`) for deterministic primary-owner and forward-target hint shaping from runtime membership snapshots.
  - S3 mutation responses (`PUT`, `CopyObject`, `DELETE`) now include distributed-only routing hints (`x-maxio-primary-owner`, `x-maxio-forward-target`, `x-maxio-routing-local-primary-owner`) while preserving standalone response contracts.
  - Integration regressions now lock routing-hint header behavior for standalone omission and distributed inclusion (`core_tests::test_put_object_standalone_omits_routing_headers`, `core_tests::test_put_object_distributed_sets_routing_headers`).
  - Integration regressions now also lock distributed routing-hint header behavior for `CopyObject` and single-object `DELETE` mutation responses (`core_tests::test_copy_object_distributed_sets_routing_headers`, `core_tests::test_delete_object_distributed_sets_routing_headers`).
  - Integration regressions now also lock distributed routing-hint header behavior for versioned single-object `DELETE ?versionId=...` responses (`core_tests::test_delete_object_version_distributed_sets_routing_headers`).
  - Distributed S3 mutation paths now enforce an explicit non-owner safety policy by actively forwarding single-key writes to computed primary owners (with loop-guarding), instead of executing local out-of-placement writes.
  - Storage placement now also exposes typed placement state and forwarding contracts (`PlacementViewState`, epoch comparison, handoff planning, forwarded-write envelope/decision model) for distributed coordinator evolution.
  - S3 forwarding paths now consume typed placement forwarding resolution and propagate explicit forwarding-wire headers (epoch/view/hop/idempotency) while preserving signed client headers end-to-end.
  - Runtime now persists placement epoch state at `${data_dir}/.maxio-runtime/placement-state.json` and increments epoch when membership view changes across restarts.
  - Runtime placement-state persistence now uses atomic temp-file replacement (`placement-state.json.tmp-*` + rename) to avoid partial placement-state JSON writes on interruption and cleans temporary artifacts after successful writes.
  - S3 forwarding target resolution now consumes runtime-provided `PlacementViewState` (including persisted epoch) instead of static epoch `0` wiring.
  - Runtime `/healthz` now exposes `placementEpoch`, runtime `/metrics` now emits `maxio_placement_epoch`, and startup logs now print placement epoch for operator diagnostics.
  - Console system health/topology/summary contracts now surface `placementEpoch` for admin parity with runtime placement-state observability.
  - Runtime regression coverage now locks persisted/incremented placement epoch behavior across membership-view changes (`runtime_tests::test_placement_epoch_persists_and_increments_when_membership_view_changes`).
  - S3 forwarding now treats forwarding-wire protocol headers as trusted only on internally-forwarded requests (`x-maxio-forwarded-by` present), preventing direct client header spoofing from perturbing local forwarding decisions.
  - S3 forwarding now also emits and prefers a dedicated trusted internal forwarding-header channel (`x-maxio-internal-forwarded-write-*`) so coordinator-controlled placement envelope fields remain authoritative without mutating client-signed legacy forwarding headers.
  - S3 forwarded-response relays now strip internal forwarding wire-protocol headers (legacy + trusted channels) before returning proxied owner responses to external clients.
  - Integration regressions now lock distributed non-owner forwarding semantics for `PUT`, `CopyObject`, and single-object `DELETE` mutation paths.
  - Integration regressions now also lock spoofed-forwarding-header safety (`core_tests::test_put_object_distributed_non_owner_write_ignores_untrusted_forward_protocol_headers`) for distributed non-owner `PUT` flows.
  - Integration regressions now also lock explicit `AccessDenied` fallback behavior when primary-owner forwarding targets are unreachable.
  - Distributed S3 read paths now also enforce non-owner forwarding policy by proxying `GET`/`HEAD` object requests to computed primary owners instead of serving local-only read misses on non-owner nodes.
  - Integration regressions now also lock distributed non-owner read forwarding and unreachable-target fallback behavior (`core_tests::test_get_object_distributed_forwards_non_owner_read_to_primary_owner`, `core_tests::test_head_object_distributed_forwards_non_owner_read_to_primary_owner`, `core_tests::test_get_object_distributed_non_owner_read_returns_access_denied_when_forward_target_unreachable`).
  - Distributed primary-owner `CopyObject` writes now also execute replica fanout with quorum diagnostics (`x-maxio-write-ack-count`, `x-maxio-write-quorum-size`, `x-maxio-write-quorum-reached`) aligned with primary `PUT`/`DELETE` contracts.
  - Integration regressions now lock distributed primary-copy quorum behavior for replica-ack and replica-unreachable paths (`core_tests::test_copy_object_distributed_primary_write_reports_quorum_headers_when_replica_acks`, `core_tests::test_copy_object_distributed_primary_write_reports_degraded_quorum_when_replica_unreachable`).
  - DeleteObjects batch flow now forwards full signed requests when all keys resolve to the same non-local owner target, and mixed-owner batches now orchestrate per-key non-owner forwarding to computed primary owners while continuing eligible local-owner entries.
  - DeleteObjects mixed-owner distributed responses now aggregate available write-quorum diagnostics at batch level (`x-maxio-write-ack-count`, `x-maxio-write-quorum-size`, `x-maxio-write-quorum-reached`).
  - Domain check runner now also executes S3 write-routing hint regressions (`core_tests::test_put_object_standalone_omits_routing_headers`, `core_tests::test_put_object_distributed_sets_routing_headers`) in S3 domain-local cycles.
  - Domain check runner now also executes S3 CopyObject/DeleteObject distributed routing-hint regressions (`core_tests::test_copy_object_distributed_sets_routing_headers`, `core_tests::test_delete_object_distributed_sets_routing_headers`) in S3 domain-local cycles.
  - Domain check runner now also executes S3 versioned delete distributed routing-hint regression (`core_tests::test_delete_object_version_distributed_sets_routing_headers`) in S3 domain-local cycles.
  - Domain check runner now also executes distributed non-owner mutation forwarding/failure regressions (`core_tests::test_put_object_distributed_forwards_non_owner_write_to_primary_owner`, `core_tests::test_copy_object_distributed_forwards_non_owner_destination_write_to_primary_owner`, `core_tests::test_delete_object_distributed_forwards_non_owner_write_to_primary_owner`, `core_tests::test_put_object_distributed_non_owner_write_returns_access_denied_when_forward_target_unreachable`, `core_tests::test_delete_objects_batch_distributed_reports_access_denied_when_forward_target_unreachable`, `core_tests::test_delete_objects_batch_distributed_forwards_non_owner_batch_to_primary_owner`, `core_tests::test_delete_objects_batch_distributed_forwards_mixed_owner_entries`) in S3 domain-local cycles.
  - Domain check runner now also executes distributed non-owner read forwarding/failure regressions (`core_tests::test_get_object_distributed_forwards_non_owner_read_to_primary_owner`, `core_tests::test_head_object_distributed_forwards_non_owner_read_to_primary_owner`, `core_tests::test_get_object_distributed_non_owner_read_returns_access_denied_when_forward_target_unreachable`) in S3 domain-local cycles.
  - Domain check runner now also executes distributed primary-copy quorum diagnostics regressions (`core_tests::test_copy_object_distributed_primary_write_reports_quorum_headers_when_replica_acks`, `core_tests::test_copy_object_distributed_primary_write_reports_degraded_quorum_when_replica_unreachable`) in S3 domain-local cycles.
  - Domain check runner now also executes spoofed-forwarding-header regression coverage (`core_tests::test_put_object_distributed_non_owner_write_ignores_untrusted_forward_protocol_headers`) in S3 domain-local cycles.
  - Domain check runner now also executes missing-bucket multipart regressions (`core_tests::test_multipart_create_upload_missing_bucket_returns_no_such_bucket`, `core_tests::test_multipart_upload_part_missing_bucket_returns_no_such_bucket`, `core_tests::test_multipart_complete_missing_bucket_returns_no_such_bucket`, `core_tests::test_multipart_list_parts_missing_bucket_returns_no_such_bucket`, `core_tests::test_multipart_list_uploads_missing_bucket_returns_no_such_bucket`) in S3 domain-local cycles.
  - Domain check runner now also executes multipart list-parts pagination/query-validation regressions (`core_tests::test_multipart_list_parts`, `core_tests::test_multipart_list_parts_supports_max_parts_and_marker`, `core_tests::test_multipart_list_parts_invalid_max_parts_returns_invalid_argument`, `core_tests::test_multipart_list_parts_invalid_part_number_marker_returns_invalid_argument`) in S3 domain-local cycles.
  - Domain check runner now also executes invalid-key delete regressions (`core_tests::test_delete_object_invalid_key_returns_invalid_argument`, `core_tests::test_delete_objects_batch_invalid_key_returns_invalid_argument_entry`) in S3 domain-local cycles.
  - Domain check runner now also executes strict DeleteObjects XML regressions (`core_tests::test_delete_objects_batch_rejects_invalid_escaped_xml_content`, `core_tests::test_delete_objects_batch_rejects_more_than_1000_keys`, `core_tests::test_delete_objects_batch_rejects_invalid_xml_structure`) in S3 domain-local cycles.
  - Domain check runner now also executes version-aware range regression coverage (`core_tests::test_get_object_range_with_version_id_reads_specific_version`, `core_tests::test_get_object_range_without_version_id_returns_current_version_header`) in S3 domain-local cycles.
  - Domain check runner now also executes erasure-coded version-aware range regression coverage (`erasure_tests::test_ec_get_object_range_with_version_id_reads_selected_version`) in storage domain-local cycles.
  - Domain check runner now also executes erasure-coded latest-version delete recovery regression coverage (`erasure_tests::test_ec_deleting_latest_version_restores_previous_current_version`) in storage domain-local cycles.
  - Domain check runner now also executes S3 range-checksum-header regression coverage (`core_tests::test_get_object_range_preserves_checksum_header`) in S3 domain-local cycles.
  - Integration checksum regression now asserts failed checksum uploads do not leave retrievable object remnants.
  - Storage unit coverage now also locks multipart part-upload checksum-mismatch cleanup semantics (no orphaned part data/metadata files).
  - Web console API-client regressions now run through automated UI tests (`ui/src/lib/api.test.ts`) in domain verification.
  - Web console placement-input helper regressions now run through automated UI tests (`ui/src/lib/system-placement.test.ts`) in domain verification.
  - Web console object-key path handling is now centralized and segment-encoded in the shared API client for upload/delete/presign/download/version-download routes, with dedicated UI API-client regression coverage for encoded path semantics.
  - Web console hash-route parsing/building is now centralized in a shared helper module (`ui/src/lib/navigation.ts`) with focused unit coverage (`ui/src/lib/navigation.test.ts`).
  - Web console hash-route bucket decoding now tolerates malformed percent-encoding without runtime crashes, with dedicated navigation-helper regression coverage.
  - Web console settings-route hash generation now also flows through shared navigation helpers (`buildHashRoute`) instead of ad-hoc `App.svelte` hash string assembly, with explicit route-builder regression coverage.
  - Web console object-browser path/breadcrumb/display-size helpers are now centralized in a shared helper module (`ui/src/lib/object-browser.ts`) with focused unit coverage (`ui/src/lib/object-browser.test.ts`).
  - Web console API failure-message normalization is now centralized in `ui/src/lib/error-message.ts`, with helper-level regression coverage (`ui/src/lib/error-message.test.ts`) and shared consumption across login/bucket/object/settings/version/metrics flows.
  - Frontend verification (`bun run check`, `bun run build`) remains green after backend refactors.
  - Repository-wide strict lint verification now passes with `cargo clippy --all-targets -- -D warnings` (including integration test targets).
  - Quality harness lint verification now also enforces no `unwrap`/`expect` in production library code (`cargo clippy --lib -- -D clippy::unwrap_used -D clippy::expect_used`).
  - Integration helper/test harness signing and parity fixtures were lint-hardened (array-based sortable header sets, iterator/repeat helpers) with no behavior drift.
  - Domain check runner `s3_auth_sigv4` suite now also executes zero-expiry presigned URL rejection regression coverage (`auth_tests::test_presigned_rejects_zero_expires`).
  - SigV4 auth middleware now rejects duplicate `Authorization` header inputs up-front to avoid ambiguous credential interpretation in header-auth and presigned paths.
  - Domain check runner `s3_auth_sigv4` suite now also executes duplicate-`Authorization` rejection regressions (`auth_tests::test_auth_rejects_multiple_authorization_headers`, `auth_tests::test_presigned_rejects_multiple_authorization_headers`).
  - Domain check runner now enforces strict lint verification inside the `quality_harness` domain (`cargo clippy --all-targets -- -D warnings`).
  - Domain check runner `quality_harness` suite now also executes UI unit tests (`ui: bun run test`) to keep frontend regression coverage in the top-level harness cycle.
  - Domain check runner `storage_engine` suite now also executes placement-determinism unit coverage (`storage::placement::tests`) for distributed-foundation regression gating.
  - Storage placement-determinism coverage now also includes typed read-repair planning invariants (majority selection, tie-break determinism, and stale/missing replica targeting).
  - Storage placement layer now also exposes typed write-ack quorum evaluation primitives (`WriteAckObservation`, `ObjectWriteQuorumOutcome`, `object_write_quorum_outcome`) for deterministic ack/reject/pending accounting against owner/quorum plans.
  - Storage placement coverage now also includes write-quorum outcome regressions for majority detection, duplicate-observation collapse semantics, unknown-node ignore behavior, and zero-quorum safety.
  - CI backend checks now include explicit `cargo clippy --all-targets -- -D warnings` gating before test execution.
  - CI includes non-release backend/frontend verification.
  - CI frontend checks now also execute automated UI unit tests (`bun run test`) in addition to typecheck/build.
  - AWS CLI and mc compatibility scripts now include lifecycle regression flows.
- Metrics groundwork advanced:
  - Runtime Prometheus-style `/metrics` endpoint is now available with request count, uptime, and build info gauges/counters.
  - Runtime health endpoint `/healthz` is now available for lightweight liveness/readiness checks.
  - Runtime topology shaping is now centralized behind a typed helper surface (`RuntimeMode`, `RuntimeTopologySnapshot`, `runtime_topology_snapshot`) to keep mode/node/peer/view semantics single-sourced.
  - Integration coverage includes `/metrics` endpoint behavior.
  - Integration coverage now asserts distributed metrics gauge values when cluster peers are configured.
  - Console API now exposes authenticated JSON metrics endpoint (`/api/system/metrics`) including runtime topology context.
  - Console API now also exposes authenticated health endpoint (`/api/system/health`) to mirror runtime health/topology context for admin workflows.
  - Console API now also exposes authenticated topology endpoint (`/api/system/topology`) for distributed admin workflows.
  - Console API now also exposes authenticated system-summary endpoint (`/api/system/summary`) for consolidated distributed admin workflows.
  - Console API now also exposes authenticated placement-owner preview endpoint (`/api/system/placement`) for object/chunk ownership diagnostics (`key`, optional `replicaCount`, optional `chunkIndex`).
  - Console placement payload now also exposes write-consistency diagnostics (`writeQuorumSize`, `writeAckPolicy`, `nonOwnerMutationPolicy`, `nonOwnerBatchMutationPolicy`, `mixedOwnerBatchMutationPolicy`), and now reports `forward-single-write` as the active non-owner single-key mutation policy.
  - Console API now also exposes authenticated rebalance-preview endpoint (`/api/system/rebalance`) for join/leave owner-transition diagnostics (`key`, optional `replicaCount`, optional `chunkIndex`, `addPeer` xor `removePeer`).
  - Web console placement preview now also surfaces write-consistency diagnostics (quorum size, ack policy, non-owner mutation policy) alongside owner/forward-target hints.
  - Console placement payload now also exposes coordinator-routing diagnostics (`primaryOwner`, `forwardTarget`, `isLocalPrimaryOwner`, `isLocalReplicaOwner`) to prepare write-forwarding observability.
  - Console rebalance payload now also exposes source/target membership snapshots plus deterministic owner-transition transfer plans (`previousOwners`, `nextOwners`, `addedOwners`, `removedOwners`, `transfers`) for operator migration previews.
  - Console system endpoints now consume shared runtime topology snapshots for health/metrics/topology/membership/summary shaping, eliminating duplicated runtime topology/view composition logic in console handlers.
  - Console system health and summary handlers now consume shared runtime probe-backed health payload shaping (`runtime_health_payload`) instead of endpoint-local `ok` construction.
  - Console membership payload shaping now also consumes runtime-snapshot `membershipViewId` directly (no endpoint-local recomputation), keeping health/membership/summary diagnostics strictly aligned.
  - Console system-health payload now also includes deterministic `membershipViewId` for membership-view diagnostics in admin tooling.
  - Console system-summary payload now also embeds membership snapshot data (`membership`) so topology + membership context can be hydrated in one authenticated call.
  - Web console now includes a metrics view wired to runtime metrics output and topology context (mode/node/peer count).
  - Web console metrics loading now prefers `/api/system/summary` and uses deterministic fallback to `/api/system/metrics` + `/api/system/health` via a shared snapshot loader (`ui/src/lib/system-metrics.ts`).
  - Web console typed API client now supports `/api/system/health`, with shared topology normalization reused across metrics/topology/health flows.
  - Web console typed API client now also supports `/api/system/membership` with normalized membership-node role/status shaping for distributed admin views.
  - Web console typed API client now also supports `/api/system/placement` for object/chunk owner preview payloads.
  - Web console typed API client now also supports `/api/system/rebalance` for join/leave owner-transition preview payloads.
  - Web console summary client now parses optional embedded membership payloads from `/api/system/summary`.
  - Web console snapshot loader now prefers summary-embedded membership and only calls `/api/system/membership` when summary omits membership, reducing redundant admin API fetches.
  - Web console summary and snapshot-fallback behavior now has dedicated UI unit coverage (`ui/src/lib/api.test.ts`, `ui/src/lib/system-metrics.test.ts`).
  - Web console API and snapshot-loader unit coverage now also locks membership contract behavior (`/api/system/membership`) for success and failure paths.
  - Web console metrics panel now surfaces explicit health status from `/api/system/health` alongside runtime counters.
  - Web console typed health contracts now parse readiness diagnostics (`status`, `checks`, `warnings`) and surface them in metrics snapshot/card state when provided.
  - Web console metrics panel now also surfaces membership identity context (`viewId`, protocol, coordinator/leader, member count) to improve distributed-state observability.
  - Web console metrics panel now also provides interactive placement-owner lookup (object key + replica count + optional chunk index) for distributed diagnostics.
  - Web console placement preview now also surfaces primary-owner and forward-target hints with local owner-role flags for operator-facing routing diagnostics.
  - Web console placement preview input parsing is now centralized in a dedicated helper with strict integer parsing/range guards (rejecting parse-prefix numeric garbage like `3abc` before API requests).
  - Web console metrics panel now also provides interactive rebalance lookup (object key + replica count + optional chunk index + join/leave peer operation) for topology-change diagnostics.
  - Web console rebalance preview now also surfaces source/target peer sets plus owner-transition summaries (previous/next/added/removed owners and transfer count).
  - Web console rebalance preview input parsing is now centralized in a dedicated helper with strict operation/peer-endpoint/numeric validation.
  - Web console typed runtime clients now parse `membershipProtocol` consistently across health/metrics/topology/placement payloads, and `/metrics` text fallback now preserves protocol context via `maxio_membership_protocol_info{protocol=\"...\"}` parsing.
  - Web console typed runtime clients now parse `placementEpoch` across health/metrics/topology payloads, including `/metrics` text fallback via `maxio_placement_epoch`.
  - Web console typed health contracts now parse storage-path readiness checks (`checks.storageDataPathReadable`) for operator-facing degraded-readiness context.
  - Web console metrics snapshot loader now threads `placementEpoch` through summary-first and fallback load paths.
  - Web console metrics UI now renders placement epoch plus expanded health-readiness indicators (data-dir writable, storage path readable, membership protocol readiness).
  - Web console system snapshot loader now falls back to summary/health/metrics `membershipProtocol` when membership payloads are unavailable, with dedicated UI regression coverage.
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
  - Storage bucket/lifecycle orchestration is now extracted to `src/storage/filesystem/bucket.rs` as the first staged split of oversized `filesystem.rs`.
  - Storage version snapshot/restore/list/delete and version read/get/head flows are now extracted to `src/storage/filesystem/versioning.rs` as the next staged split of oversized `filesystem.rs`.
  - Storage multipart upload init/part/complete/abort/list flows plus multipart path/meta helpers are now extracted to `src/storage/filesystem/multipart.rs` as the next staged split of oversized `filesystem.rs`.
  - Storage object/erasure put/get/head/delete/list flows plus chunk/parity write helpers are now extracted to `src/storage/filesystem/object.rs` as the next staged split of oversized `filesystem.rs`.
- Console readiness advanced:
  - Session/login/logout/rate-limit behavior now has dedicated integration coverage.
  - Console API handlers are split by concern (auth/buckets/objects/presign/versions) with `console.rs` as router entrypoint.
  - Console JSON success/error response shaping is centralized via shared response helpers.
  - Console handlers now use typed DTO response contracts across auth, buckets, objects, lifecycle, presign, versions, and system/admin paths (no inline handler `json!` payload assembly in `src/api/console/`).
  - Console versioning/version-history endpoints now return explicit `404` for missing buckets and missing versions (instead of generic `500`), with dedicated regression coverage.
  - Console object-management endpoints now return `404` for missing buckets on folder creation and object deletion paths (instead of implicit success/`500` drift), with dedicated regression coverage.
  - Console object/version download endpoints now also return explicit `404` for missing buckets, with dedicated regression coverage.
  - Console presign endpoint now also returns explicit `404` semantics for missing buckets (`Bucket not found`) and missing objects (`Object not found`), with dedicated regression coverage.
  - Console presign endpoint now has dedicated regression coverage for percent-encoded object-key signing/URL generation (spaces + UTF-8 segments).
  - Console object/version/lifecycle handlers now share a centralized storage-error helper module for consistent bucket/version `404` semantics and internal error shaping.
  - Console object/version list paths now map invalid key/prefix inputs to explicit `400` responses (instead of generic `500`/silent empty responses), with dedicated regression coverage.
  - Console object-listing now also rejects empty `delimiter` query values with explicit `400` responses to avoid ambiguous folder-grouping behavior.
  - Console object/version download handlers now use panic-free response construction for streamed responses, with safe fallback headers for malformed metadata values.
  - Console API now also exposes authenticated membership endpoint (`/api/system/membership`) with deterministic view fingerprints and leader/coordinator state placeholders for distributed admin workflows.
  - Console API now also exposes authenticated placement-owner preview endpoint (`/api/system/placement`) with strict query validation for `key`, `replicaCount`, and optional `chunkIndex`.
  - Console API now also exposes authenticated rebalance-preview endpoint (`/api/system/rebalance`) with strict query validation for key/replica/chunk plus mutually-exclusive join/leave peer operations.
  - Console placement query parsing now validates `key` via shared storage key constraints while accepting trimmed numeric query input for `replicaCount`/`chunkIndex`.
  - Console rebalance query parsing now validates peer endpoint shape (`host:port`) and membership constraints (join requires new peer, leave requires existing non-local peer).
  - Console health and summary contracts now consistently expose membership-view identity (`membershipViewId`) for distributed diagnostics parity.
  - Console summary contract now also embeds the membership payload to make consolidated admin snapshots actually self-contained.
  - Integration coverage now asserts console object and version download header/body contracts.
  - Integration coverage now also asserts console object delete/download and version-download behavior for percent-encoded key paths (spaces/`+`/`#`), aligning console route handling with UI key-path encoding.
  - Integration coverage now locks console JSON contract shapes for bucket/object success payloads and auth/protected-route error payloads.
  - Integration coverage now includes tampered-session-cookie rejection for protected console routes.
  - Integration coverage now includes session-boundary rejection for expired and future-dated console cookies.
  - Integration coverage now also locks tampered/session-boundary rejection on identity endpoints (`/api/auth/check`, `/api/auth/me`) including unknown-access-key cookie rejection.
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
  - SigV4 `SignedHeaders` parsing is now strict across header-auth and presigned query paths:
    - requires `host`
    - rejects duplicate signed-header entries
    - rejects invalid header-token syntax
  - SigV4 verification now also requires every header listed in `SignedHeaders` to be present in the incoming request (missing signed headers are rejected instead of being canonicalized as empty values).
  - Integration coverage now includes missing-host `SignedHeaders` rejection regressions for both header-auth and presigned query requests.
  - Integration coverage now also includes duplicate-entry and invalid-token `SignedHeaders` rejection regressions for both header-auth and presigned query requests.
  - Integration coverage now also includes missing-signed-header-value rejection regressions for both header-auth and presigned query requests.
  - Integration coverage now includes duplicate-component rejection regressions for both `Authorization` header inputs and presigned `X-Amz-*` query inputs.
  - SigV4 canonical URI normalization now decodes and re-encodes path segments to avoid double-encoding already-encoded request paths in presigned verification flows.
  - Shared SigV4 presign generation now uses a typed `PresignRequest` contract instead of positional multi-argument call sites.
  - SigV4 presigned-query parsing and presigned URL generation now enforce strict lower-bound expiry semantics (`X-Amz-Expires > 0`) in addition to max-expiry checks.
  - Auth domain verification now explicitly includes `auth::signature_v4::tests` in domain-local checks.
  - Auth domain verification now also executes duplicate SigV4 component rejection integration regressions in domain-local cycles.
  - Auth domain verification now also executes strict `SignedHeaders` regressions for missing-host, duplicate-entry, and invalid-token rejection in header-auth and presigned flows.
  - Auth domain verification now also executes zero-expiry presigned URL regression coverage in domain-local cycles.
  - Integration signing helpers now normalize header names to lowercase before canonical signing to keep harness-generated SigV4 requests compatible with strict header canonicalization.
- Distributed bootstrap groundwork advanced:
  - Runtime config now supports `MAXIO_NODE_ID` and `MAXIO_CLUSTER_PEERS` for topology bootstrap wiring.
  - Runtime config now also supports typed membership-protocol selection via `MAXIO_MEMBERSHIP_PROTOCOL` (`static-bootstrap`, `gossip`, `raft`).
  - `/healthz` and `/metrics` now expose standalone/distributed runtime topology context.
  - `/healthz` now also exposes runtime-selected membership protocol identity (`membershipProtocol`).
  - `/healthz` now also exposes normalized membership-node diagnostics (`membershipNodeCount`, `membershipNodes`) for self+peer view visibility.
  - `/metrics` now also exposes membership protocol info gauge (`maxio_membership_protocol_info{protocol=\"...\"}`).
  - `/metrics` now also exposes normalized membership-view cardinality gauge (`maxio_membership_nodes_total`).
  - `/healthz` now also exposes deterministic bootstrap membership view identity (`membershipViewId`) derived from node+peer membership inputs.
  - `/healthz` now also exposes probe-backed readiness diagnostics (`status`, `checks`, `warnings`) instead of unconditional `ok: true` behavior.
  - `/healthz` readiness checks now also include storage metadata traversal viability (`checks.storageDataPathReadable`) and degrade when storage data-path probing fails.
  - `/healthz` readiness checks now also include configurable disk-headroom threshold gating (`checks.diskHeadroomSufficient`) from `MAXIO_MIN_DISK_HEADROOM_BYTES` / `--min-disk-headroom-bytes`.
  - `/healthz` now marks unimplemented membership-protocol selections (`gossip`, `raft`) as degraded readiness with explicit operator-facing warnings.
  - Startup logs now also emit explicit warnings when unimplemented membership-protocol selections (`gossip`, `raft`) are configured, mirroring `/healthz` readiness warning semantics.
  - Integration coverage includes distributed-mode health reporting when peers are configured.
  - Runtime process shutdown now handles SIGINT and SIGTERM (Unix) via graceful-drain signal handling without panic-prone `expect` paths.
  - Build metadata wiring (`build.rs`) now avoids panic-prone `expect` on `VERSION` reads and falls back to package-version defaults.
  - Storage now includes deterministic rendezvous-based placement primitives (`storage::placement`) for object/chunk owner selection and stable membership fingerprinting.
  - Storage placement now also exposes shared local+peer membership view helpers (`membership_with_self`, `membership_view_id_with_self`) used by runtime and console contracts to avoid duplicated membership-fingerprint logic.
  - Storage placement now also exposes local-membership owner-selection and ownership predicates (`select_*_owners_with_self`, `is_local_*_owner`) to support deterministic write-forwarding/quorum coordinator decisions.
  - Storage placement now also exposes deterministic primary-owner and forward-target helpers (`primary_*_owner[_with_self]`, `*_forward_target_with_self`) to prepare non-owner write forwarding without duplicating coordinator selection logic.
  - Storage placement now also exposes quorum/write-plan helpers (`quorum_size`, `ObjectWritePlan`, `object_write_plan_with_self`) to centralize owner order, forwarding target, and majority-ack planning semantics.
  - Storage placement now also exposes typed read-repair planning helpers (`ReplicaObservation`, `ObjectReadRepairPlan`, `object_read_repair_plan`) for deterministic version-majority/quorum diagnostics and stale/missing replica targeting.
  - Storage placement now also exposes typed read-repair execution helpers (`ReadRepairAction`, `ObjectReadRepairExecutionPlan`, `object_read_repair_execution_plan`) for quorum-gated stale/missing replica action planning.
  - Storage placement read-repair execution now also exposes explicit policy controls (`ReadRepairExecutionPolicy`, `object_read_repair_execution_plan_with_policy`) so runtime/API layers can opt into primary-authoritative repair semantics without implicit quorum-size overrides.
  - S3 primary-owner current-version read paths now execute runtime read-repair:
    - trusted internal replica-head probes (`replicate-head-object`) collect replica-version observations.
    - stale/missing replicas are repaired via internal replica put/delete fanout actions.
    - integration regressions now lock `GET` and `HEAD` missing-replica repair behavior.
  - Storage placement now also exposes typed rebalance planning helpers (`ObjectRebalancePlan`, `RebalanceTransfer`, `object_rebalance_plan`, `chunk_rebalance_plan`) for deterministic owner-transition and transfer-source planning across join/leave/bootstrap membership changes.
  - Placement foundation now has focused unit coverage for deterministic ownership, replica clamping, and order-insensitive membership fingerprints.
  - Placement foundation coverage now also locks rendezvous monotonicity invariants on topology change (node join and non-owner removal) for safer rebalancing and forwarding evolution.
  - Placement foundation coverage now also locks read-repair execution invariants (quorum-gated action emission, stale/missing upsert behavior, and majority-missing delete behavior).
  - Placement foundation coverage now also locks rebalance-plan invariants (equivalent-view stability, join/leave transitions, bootstrap source semantics, and chunk-plan parity).
  - Console API membership contract now surfaces runtime-selected membership protocol snapshots (`protocol`, `viewId`, node set, leader/coordinator placeholders) and system contracts expose `membershipProtocol` across health/metrics/topology/placement/summary payloads.
  - Runtime binary entrypoint now uses shared library modules directly (`maxio::{config,server,storage}`), removing duplicate bin/lib module graphs and reducing drift/noise in strict verification.

## Governance

- Any roadmap item touching more than one domain must be split into sequential domain cycles.
- Each cycle must update both the relevant domain spec and this roadmap spec status.
- Roadmap status in docs should be updated once cycle verification passes.
