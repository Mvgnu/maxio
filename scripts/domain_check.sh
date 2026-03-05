#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/domain_check.sh <domain|all>

Domains:
  runtime_platform
  storage_engine
  cluster_transport_security
  cluster_metadata_plane
  s3_auth_sigv4
  s3_api_surface
  console_api
  web_console_ui
  quality_harness
EOF
}

run_domain() {
  local domain="$1"
  echo "==> Running checks for domain: $domain"

  case "$domain" in
    runtime_platform)
      cargo check
      cargo clippy --lib --bins -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
      cargo test server::tests
      cargo test config::tests::parse_cluster_id_accepts_valid_values -- --exact
      cargo test config::tests::parse_cluster_id_rejects_invalid_values -- --exact
      for t in \
        runtime_tests::test_request_id_header_present_on_s3_auth_failure \
        runtime_tests::test_metrics_endpoint_exposes_runtime_counters \
        runtime_tests::test_metrics_peer_auth_reject_reason_counter_increments_when_forwarded_headers_rejected \
        runtime_tests::test_metrics_peer_auth_reject_reason_counter_increments_for_runtime_endpoint_headers \
        runtime_tests::test_metrics_runtime_internal_header_reject_dimensions_track_api_unknown_sender \
        runtime_tests::test_metrics_runtime_internal_header_reject_dimensions_track_api_known_sender_token_mismatch \
        runtime_tests::test_metrics_endpoint_reports_distributed_gauges_when_cluster_peers_configured \
        runtime_tests::test_metrics_pending_replication_replay_counters_increment_in_distributed_mode \
        runtime_tests::test_metrics_pending_membership_propagation_replay_counters_increment_in_distributed_mode \
        runtime_tests::test_metrics_pending_rebalance_replay_counters_increment_in_distributed_mode \
        runtime_tests::test_pending_rebalance_replay_worker_forwards_due_send_transfer_and_drains_queue \
        runtime_tests::test_metrics_membership_converged_reflects_peer_probe_for_static_bootstrap \
        runtime_tests::test_healthz_endpoint_reports_runtime_status \
        runtime_tests::test_healthz_reports_distributed_mode_when_cluster_peers_configured \
        runtime_tests::test_healthz_reports_degraded_when_distributed_peer_auth_sender_allowlist_not_bound \
        runtime_tests::test_healthz_and_metrics_report_shared_token_cluster_auth_mode_when_configured \
        runtime_tests::test_healthz_and_metrics_require_certificate_pin_for_mtls_node_id_binding \
        runtime_tests::test_healthz_and_metrics_report_mtls_transport_ready_when_pin_matches \
        runtime_tests::test_healthz_and_metrics_report_mtls_transport_unready_when_node_identity_mismatches_certificate \
        runtime_tests::test_healthz_and_metrics_report_mtls_transport_pin_mismatch_as_unready \
        runtime_tests::test_healthz_and_metrics_report_strict_quorum_write_durability_mode_when_configured \
        runtime_tests::test_healthz_and_metrics_report_consensus_index_metadata_listing_strategy_when_configured \
        runtime_tests::test_healthz_and_metrics_report_consensus_index_metadata_listing_strategy_as_unready_when_shared_token_missing \
        runtime_tests::test_healthz_reports_degraded_when_consensus_metadata_state_is_not_queryable \
        runtime_tests::test_healthz_and_metrics_report_request_time_aggregation_metadata_listing_strategy_as_unready_when_distributed \
        runtime_tests::test_cluster_join_authorize_endpoint_accepts_and_rejects_nonce_replay \
        runtime_tests::test_cluster_join_authorize_endpoint_persists_nonce_replay_guard_across_restart \
        runtime_tests::test_cluster_join_authorize_endpoint_rejects_missing_auth_token_in_shared_mode \
        runtime_tests::test_cluster_join_authorize_endpoint_rejects_invalid_peer_node_identity \
        runtime_tests::test_cluster_join_authorize_endpoint_returns_service_unavailable_for_invalid_local_node_identity_configuration \
        runtime_tests::test_cluster_join_authorize_endpoint_returns_service_unavailable_when_not_distributed \
        runtime_tests::test_cluster_join_authorize_endpoint_returns_service_unavailable_when_membership_engine_not_ready \
        runtime_tests::test_cluster_join_authorize_endpoint_returns_service_unavailable_when_cluster_auth_token_not_configured_in_distributed_mode \
        runtime_tests::test_cluster_join_endpoint_applies_membership_for_authorized_peer \
        runtime_tests::test_cluster_join_endpoint_is_idempotent_for_existing_peer \
        runtime_tests::test_cluster_join_endpoint_rejects_stale_precondition \
        runtime_tests::test_cluster_join_endpoint_rejects_forwarded_sender_not_in_allowlist \
        runtime_tests::test_cluster_join_endpoint_rejects_forwarded_sender_node_id_mismatch \
        runtime_tests::test_cluster_join_endpoint_rejects_known_sender_with_token_mismatch \
        runtime_tests::test_cluster_join_endpoint_metrics_track_status_and_reason_labels \
        runtime_tests::test_split_internal_listener_isolates_control_plane_routes \
        runtime_tests::test_cluster_membership_update_endpoint_applies_live_view_and_epoch \
        runtime_tests::test_cluster_membership_update_endpoint_propagates_updates_to_peer_control_plane \
        runtime_tests::test_cluster_membership_update_endpoint_propagates_updates_to_removed_peers \
        runtime_tests::test_cluster_membership_update_endpoint_retries_propagation_on_transient_peer_failure \
        runtime_tests::test_cluster_membership_update_endpoint_replays_failed_propagation_from_persisted_queue \
        runtime_tests::test_cluster_membership_update_endpoint_queues_rebalance_operations_for_local_objects \
        runtime_tests::test_cluster_membership_update_endpoint_skips_fanout_for_propagated_requests \
        runtime_tests::test_cluster_membership_update_endpoint_allows_transition_to_standalone \
        runtime_tests::test_cluster_membership_update_endpoint_rejects_unauthorized_requests \
        runtime_tests::test_cluster_membership_update_endpoint_rejects_invalid_payload \
        runtime_tests::test_cluster_membership_update_endpoint_rejects_whitespace_only_peer_payload \
        runtime_tests::test_cluster_membership_update_endpoint_rejects_stale_membership_precondition \
        runtime_tests::test_cluster_membership_update_endpoint_rejects_stale_epoch_precondition \
        runtime_tests::test_cluster_membership_update_endpoint_metrics_track_status_and_reason_labels \
        runtime_tests::test_cluster_membership_update_endpoint_returns_service_unavailable_when_membership_engine_not_ready \
        runtime_tests::test_cluster_membership_update_endpoint_returns_service_unavailable_when_cluster_auth_token_not_configured_in_distributed_mode \
        runtime_tests::test_cluster_membership_update_endpoint_rejects_forwarded_sender_not_in_allowlist \
        runtime_tests::test_cluster_membership_update_endpoint_rejects_forwarded_sender_node_id_mismatch \
        runtime_tests::test_cluster_membership_update_endpoint_rejects_known_sender_with_token_mismatch \
        runtime_tests::test_healthz_reports_warning_for_invalid_local_node_id_in_shared_token_binding \
        runtime_tests::test_healthz_reports_degraded_when_storage_data_path_probe_fails \
        runtime_tests::test_healthz_reports_degraded_when_pending_replication_queue_probe_fails_in_distributed_degraded_mode \
        runtime_tests::test_healthz_warns_when_pending_membership_propagation_due_backlog_exceeds_replay_batch_size \
        runtime_tests::test_healthz_reports_degraded_when_disk_headroom_threshold_not_met \
        runtime_tests::test_healthz_reports_degraded_when_static_peer_connectivity_probe_fails \
        runtime_tests::test_healthz_reports_degraded_when_cluster_peers_include_local_node_id \
        runtime_tests::test_healthz_reports_degraded_when_static_peer_membership_view_mismatches \
        runtime_tests::test_static_bootstrap_convergence_worker_applies_discovered_peers_from_peer_healthz \
        runtime_tests::test_static_bootstrap_convergence_worker_propagates_discovered_peers_to_control_plane \
        runtime_tests::test_gossip_convergence_worker_persists_retryable_stale_peer_reconciliation_failure \
        runtime_tests::test_static_bootstrap_convergence_worker_rejects_discovered_peers_on_cluster_id_mismatch \
        runtime_tests::test_static_bootstrap_convergence_worker_rejects_discovered_peers_when_cluster_id_missing \
        runtime_tests::test_static_bootstrap_convergence_worker_rejects_discovered_peers_when_membership_view_id_missing \
        runtime_tests::test_placement_epoch_persists_and_increments_when_membership_view_changes \
        runtime_tests::test_cluster_id_persists_when_membership_view_changes \
        runtime_tests::test_cors_preflight_s3_without_auth \
        runtime_tests::test_cors_preflight_without_origin_uses_wildcard_without_credentials \
        runtime_tests::test_cors_preflight_console_route_without_auth \
        runtime_tests::test_cors_preflight_includes_vary_origin_and_request_id \
        runtime_tests::test_cors_preflight_reflects_requested_allow_headers \
        runtime_tests::test_cors_headers_present_on_s3_error_response \
        runtime_tests::test_cors_origin_reflection_on_successful_s3_response
      do
        cargo test --test integration "$t" -- --exact
      done
      ;;
    storage_engine)
      cargo check
      cargo clippy --lib -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
      cargo test storage::placement::tests
      cargo test storage::validation::tests
      cargo test storage::layout::tests
      cargo test lifecycle_tests
      cargo test versioning_tests
      cargo test lifecycle::tests
      for t in \
        core_tests::test_put_and_get_object \
        core_tests::test_multipart_complete \
        core_tests::test_delete_marker_stays_current_after_deleting_older_version \
        erasure_tests::test_ec_put_and_get_object \
        erasure_tests::test_ec_get_object_range_with_version_id_reads_selected_version \
        erasure_tests::test_ec_deleting_latest_version_restores_previous_current_version \
        erasure_tests::test_ec_delete_marker_stays_current_after_deleting_older_version \
        parity_tests::test_parity_read_healthy \
        checksum_tests::test_put_object_with_wrong_checksum
      do
        cargo test --test integration "$t" -- --exact
      done
      ;;
    cluster_transport_security)
      cargo check
      cargo clippy --lib --bins -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
      cargo test cluster::security::tests
      cargo test cluster::authenticator::tests
      cargo test cluster::join_authorization::tests
      cargo test cluster::wire_auth::tests
      cargo test cluster::internal_transport::tests
      cargo test cluster::peer_identity::tests
      cargo test cluster::transport_identity::tests
      cargo test api::object::service::tests::forwarded_write_envelope_ignores_forwarded_metadata_when_auth_token_is_missing
      cargo test api::object::service::tests::forwarded_write_envelope_uses_forwarded_metadata_when_auth_token_matches
      cargo test --test integration core_tests::test_put_object_distributed_non_owner_write_ignores_untrusted_forward_protocol_headers_when_cluster_auth_token_configured -- --exact
      cargo test --test integration core_tests::test_put_object_distributed_non_owner_write_accepts_authenticated_internal_auth_headers_from_known_sender -- --exact
      cargo test --test integration core_tests::test_put_object_distributed_non_owner_write_rejects_spoofed_internal_auth_headers_with_invalid_sender_identity -- --exact
      cargo test --test integration core_tests::test_put_object_distributed_non_owner_write_rejects_spoofed_internal_auth_headers_with_token_mismatch_from_known_sender -- --exact
      cargo test --test integration core_tests::test_delete_object_distributed_non_owner_write_rejects_spoofed_internal_auth_headers_with_invalid_sender_identity -- --exact
      cargo test --test integration core_tests::test_delete_object_distributed_non_owner_write_rejects_spoofed_internal_auth_headers_with_token_mismatch_from_known_sender -- --exact
      cargo test --test integration core_tests::test_get_object_distributed_non_owner_read_rejects_spoofed_internal_auth_headers_with_invalid_sender_identity -- --exact
      cargo test --test integration core_tests::test_get_object_distributed_non_owner_read_rejects_spoofed_internal_auth_headers_with_token_mismatch_from_known_sender -- --exact
      cargo test --test integration core_tests::test_head_object_distributed_non_owner_read_rejects_spoofed_internal_auth_headers_with_invalid_sender_identity -- --exact
      cargo test --test integration core_tests::test_head_object_distributed_non_owner_read_rejects_spoofed_internal_auth_headers_with_token_mismatch_from_known_sender -- --exact
      cargo test --test integration core_tests::test_copy_object_distributed_non_owner_write_rejects_spoofed_internal_auth_headers_with_invalid_sender_identity -- --exact
      cargo test --test integration core_tests::test_create_multipart_distributed_non_owner_write_rejects_spoofed_internal_auth_headers_with_invalid_sender_identity -- --exact
      cargo test --test integration core_tests::test_multipart_upload_part_distributed_non_owner_write_rejects_spoofed_internal_auth_headers_with_invalid_sender_identity -- --exact
      cargo test --test integration core_tests::test_multipart_upload_part_distributed_non_owner_write_rejects_spoofed_internal_auth_headers_with_token_mismatch_from_known_sender -- --exact
      cargo test --test integration core_tests::test_multipart_list_parts_distributed_non_owner_read_rejects_spoofed_internal_auth_headers_with_invalid_sender_identity -- --exact
      cargo test --test integration core_tests::test_multipart_list_parts_distributed_non_owner_read_rejects_spoofed_internal_auth_headers_with_token_mismatch_from_known_sender -- --exact
      cargo test --test integration core_tests::test_multipart_abort_distributed_non_owner_write_rejects_spoofed_internal_auth_headers_with_invalid_sender_identity -- --exact
      cargo test --test integration core_tests::test_multipart_abort_distributed_non_owner_write_rejects_spoofed_internal_auth_headers_with_token_mismatch_from_known_sender -- --exact
      cargo test --test integration core_tests::test_multipart_complete_distributed_non_owner_write_rejects_spoofed_internal_auth_headers_with_invalid_sender_identity -- --exact
      cargo test --test integration core_tests::test_multipart_complete_distributed_non_owner_write_rejects_spoofed_internal_auth_headers_with_token_mismatch_from_known_sender -- --exact
      cargo test --test integration core_tests::test_delete_objects_batch_distributed_non_owner_write_rejects_spoofed_internal_auth_headers_with_invalid_sender_identity -- --exact
      cargo test --test integration core_tests::test_delete_objects_batch_distributed_non_owner_write_rejects_spoofed_internal_auth_headers_with_token_mismatch_from_known_sender -- --exact
      cargo test --test integration runtime_tests::test_cluster_join_authorize_endpoint_rejects_invalid_peer_node_identity -- --exact
      cargo test --test integration runtime_tests::test_cluster_join_authorize_endpoint_returns_service_unavailable_for_invalid_local_node_identity_configuration -- --exact
      cargo test --test integration runtime_tests::test_healthz_and_metrics_report_mtls_transport_unready_when_node_identity_mismatches_certificate -- --exact
      cargo test --test integration runtime_tests::test_cluster_join_authorize_endpoint_returns_service_unavailable_when_cluster_auth_token_not_configured_in_distributed_mode -- --exact
      cargo test --test integration runtime_tests::test_cluster_join_endpoint_rejects_forwarded_sender_not_in_allowlist -- --exact
      cargo test --test integration runtime_tests::test_cluster_join_endpoint_rejects_forwarded_sender_node_id_mismatch -- --exact
      cargo test --test integration runtime_tests::test_cluster_join_endpoint_rejects_known_sender_with_token_mismatch -- --exact
      cargo test --test integration runtime_tests::test_cluster_membership_update_endpoint_returns_service_unavailable_when_cluster_auth_token_not_configured_in_distributed_mode -- --exact
      cargo test --test integration runtime_tests::test_cluster_membership_update_endpoint_rejects_forwarded_sender_not_in_allowlist -- --exact
      cargo test --test integration runtime_tests::test_cluster_membership_update_endpoint_rejects_forwarded_sender_node_id_mismatch -- --exact
      cargo test --test integration runtime_tests::test_cluster_membership_update_endpoint_rejects_known_sender_with_token_mismatch -- --exact
      ;;
    cluster_metadata_plane)
      cargo check
      cargo clippy --lib -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
      cargo test metadata::
      ;;
    s3_auth_sigv4)
      cargo check
      cargo clippy --lib -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
      cargo test auth::signature_v4::tests
      for t in \
        auth_tests::test_auth_rejects_bad_key \
        auth_tests::test_auth_accepts_valid_signature \
        auth_tests::test_auth_accepts_signed_requests_with_custom_forwarding_like_headers \
        auth_tests::test_auth_rejects_internal_operation_headers_without_forwarded_by_marker \
        auth_tests::test_auth_internal_header_trust_uses_live_runtime_membership_peers \
        auth_tests::test_auth_rejects_multiple_authorization_headers \
        auth_tests::test_auth_rejects_invalid_credential_scope_service \
        auth_tests::test_auth_accepts_secondary_configured_credentials \
        auth_tests::test_auth_credential_matrix_primary_secondary_and_unknown \
        auth_tests::test_auth_compact_header_no_spaces \
        auth_tests::test_auth_rejects_duplicate_authorization_components \
        auth_tests::test_auth_rejects_unknown_authorization_component \
        auth_tests::test_auth_rejects_signed_headers_without_host \
        auth_tests::test_auth_rejects_duplicate_signed_headers_entries \
        auth_tests::test_auth_rejects_signed_headers_with_invalid_token \
        auth_tests::test_auth_rejects_missing_signed_header_value \
        auth_tests::test_presigned_rejects_invalid_credential_scope_service \
        auth_tests::test_presigned_rejects_multiple_authorization_headers \
        auth_tests::test_presigned_rejects_future_timestamp_skew \
        auth_tests::test_presigned_rejects_unknown_access_key \
        auth_tests::test_presigned_rejects_zero_expires \
        auth_tests::test_presigned_get_object_with_secondary_credentials \
        auth_tests::test_presigned_accepts_percent_encoded_signature_query_key \
        auth_tests::test_presigned_bad_signature \
        auth_tests::test_presigned_expired_url \
        auth_tests::test_presigned_rejects_duplicate_auth_query_components \
        auth_tests::test_presigned_rejects_signed_headers_without_host \
        auth_tests::test_presigned_rejects_duplicate_signed_headers_entries \
        auth_tests::test_presigned_rejects_signed_headers_with_invalid_token \
        auth_tests::test_presigned_rejects_missing_signed_header_value
      do
        cargo test --test integration "$t" -- --exact
      done
      ;;
    s3_api_surface)
      cargo check
      cargo clippy --lib -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
      cargo test error::tests
      cargo test api::bucket::validation::tests
      cargo test api::bucket::service::tests
      cargo test api::list::tests
      cargo test api::list::response::tests
      cargo test api::list::service::tests
      cargo test api::object::parsing::tests
      cargo test api::object::service::tests
      cargo test api::object::tests
      cargo test api::multipart::tests
      cargo test api::multipart::service::tests
      for t in \
        core_tests::test_create_bucket \
        core_tests::test_head_bucket_not_found \
        core_tests::test_head_bucket_distributed_request_aggregation_returns_service_unavailable_when_unready \
        core_tests::test_head_bucket_distributed_request_aggregation_rejects_inconsistent_peer_state \
        core_tests::test_head_bucket_consensus_index_uses_persisted_metadata_state \
        core_tests::test_head_bucket_consensus_index_persists_local_create_into_consensus_state \
        core_tests::test_create_bucket_consensus_index_rejects_active_tombstone_without_local_side_effect \
        core_tests::test_create_bucket_consensus_index_rejects_existing_persisted_bucket_without_local_side_effect \
        core_tests::test_delete_bucket_consensus_index_rejects_missing_persisted_bucket_without_local_side_effect \
        core_tests::test_delete_bucket_consensus_index_rejects_tombstoned_persisted_bucket_without_local_side_effect \
        core_tests::test_list_buckets_distributed_request_aggregation_returns_service_unavailable_when_unready \
        core_tests::test_list_buckets_consensus_index_uses_persisted_metadata_state \
        core_tests::test_list_buckets_consensus_index_persists_local_create_into_consensus_state \
        core_tests::test_create_bucket_distributed_request_aggregation_returns_service_unavailable_when_unready \
        core_tests::test_delete_bucket_distributed_request_aggregation_returns_service_unavailable_when_unready \
        core_tests::test_list_buckets_distributed_request_aggregation_merges_peer_bucket_state_when_ready \
        core_tests::test_create_bucket_distributed_request_aggregation_converges_peer_state_when_ready \
        core_tests::test_create_bucket_distributed_request_aggregation_succeeds_when_peer_already_has_bucket \
        core_tests::test_delete_bucket_distributed_request_aggregation_converges_peer_state_when_ready \
        core_tests::test_bucket_versioning_distributed_request_aggregation_returns_service_unavailable_when_unready \
        core_tests::test_get_bucket_versioning_consensus_index_uses_persisted_metadata_state \
        core_tests::test_get_bucket_lifecycle_consensus_index_uses_persisted_metadata_state_for_disabled_state \
        core_tests::test_get_bucket_lifecycle_consensus_index_uses_persisted_lifecycle_configuration_payload \
        core_tests::test_get_bucket_lifecycle_consensus_index_persists_local_mutation_state \
        core_tests::test_get_bucket_lifecycle_consensus_index_returns_service_unavailable_when_token_missing_for_enabled_rules \
        core_tests::test_get_bucket_lifecycle_consensus_index_merges_peer_state_when_token_configured \
        core_tests::test_bucket_versioning_distributed_request_aggregation_merges_peer_state_when_ready \
        core_tests::test_bucket_versioning_distributed_request_aggregation_rejects_inconsistent_peer_state \
        core_tests::test_bucket_versioning_distributed_request_aggregation_put_converges_peer_state_when_ready \
        core_tests::test_bucket_versioning_distributed_request_aggregation_put_returns_service_unavailable_when_peer_missing_bucket \
        core_tests::test_bucket_lifecycle_distributed_request_aggregation_returns_service_unavailable_when_unready \
        core_tests::test_bucket_lifecycle_distributed_request_aggregation_merges_peer_state_when_ready \
        core_tests::test_bucket_lifecycle_distributed_request_aggregation_rejects_inconsistent_peer_state \
        core_tests::test_bucket_lifecycle_distributed_request_aggregation_put_converges_peer_state_when_ready \
        core_tests::test_bucket_lifecycle_distributed_request_aggregation_delete_converges_peer_state_when_ready \
        core_tests::test_list_objects \
        core_tests::test_list_objects_distributed_request_aggregation_merges_peer_object_state_when_ready \
        core_tests::test_list_objects_distributed_consensus_index_merges_peer_object_state_when_token_configured \
        core_tests::test_list_objects_distributed_consensus_index_does_not_fallback_to_local_object_listing \
        core_tests::test_list_objects_distributed_request_aggregation_rejects_inconsistent_bucket_presence \
        core_tests::test_list_objects_distributed_reports_metadata_coverage_headers \
        core_tests::test_list_objects_distributed_consensus_index_returns_service_unavailable_when_token_missing \
        core_tests::test_list_objects_distributed_consensus_index_returns_service_unavailable_when_peer_fan_in_incomplete \
        core_tests::test_list_objects_distributed_request_aggregation_returns_service_unavailable_when_unready \
        core_tests::test_list_object_versions_distributed_reports_metadata_coverage_headers \
        core_tests::test_list_object_versions_distributed_consensus_index_returns_service_unavailable_when_token_missing \
        core_tests::test_list_object_versions_distributed_consensus_index_returns_service_unavailable_when_peer_fan_in_incomplete \
        core_tests::test_list_object_versions_distributed_request_aggregation_merges_peer_state_when_ready \
        core_tests::test_list_object_versions_distributed_consensus_index_merges_peer_state_when_token_configured \
        core_tests::test_list_object_versions_distributed_consensus_index_does_not_fallback_to_local_listing \
        core_tests::test_list_object_versions_distributed_request_aggregation_rejects_inconsistent_bucket_presence \
        core_tests::test_list_objects_invalid_prefix_returns_invalid_argument \
        core_tests::test_list_objects_invalid_max_keys_returns_invalid_argument \
        core_tests::test_list_objects_invalid_continuation_token_returns_invalid_argument \
        core_tests::test_list_objects_v2_empty_delimiter_returns_invalid_argument \
        core_tests::test_list_objects_v1_empty_delimiter_returns_invalid_argument \
        core_tests::test_list_objects_invalid_list_type_returns_invalid_argument \
        core_tests::test_list_object_versions_invalid_prefix_returns_invalid_argument \
        core_tests::test_list_object_versions_invalid_max_keys_returns_invalid_argument \
        core_tests::test_list_object_versions_orphaned_version_id_marker_returns_invalid_argument \
        core_tests::test_put_and_get_object \
        core_tests::test_put_object_standalone_omits_routing_headers \
        core_tests::test_put_object_distributed_sets_routing_headers \
        core_tests::test_put_object_distributed_non_owner_write_returns_service_unavailable_when_forward_target_unreachable \
        core_tests::test_put_object_distributed_forwards_non_owner_write_to_primary_owner \
        core_tests::test_put_object_distributed_primary_write_reports_quorum_headers_when_replica_acks \
        core_tests::test_put_object_distributed_primary_write_reports_degraded_quorum_when_replica_unreachable \
        core_tests::test_put_object_distributed_primary_write_strict_quorum_returns_service_unavailable_when_replica_unreachable \
        core_tests::test_put_object_distributed_non_owner_write_ignores_untrusted_forward_protocol_headers \
        core_tests::test_put_object_distributed_non_owner_write_ignores_untrusted_forward_protocol_headers_when_cluster_auth_token_configured \
        core_tests::test_put_object_distributed_non_owner_write_rejects_spoofed_internal_auth_headers_from_unknown_sender \
        core_tests::test_put_object_distributed_non_owner_write_rejects_spoofed_internal_auth_headers_with_token_mismatch_from_known_sender \
        core_tests::test_create_multipart_distributed_non_owner_write_rejects_spoofed_internal_auth_headers_with_invalid_sender_identity \
        core_tests::test_delete_objects_batch_distributed_non_owner_write_rejects_spoofed_internal_auth_headers_with_invalid_sender_identity \
        core_tests::test_get_object_distributed_forwards_non_owner_read_to_primary_owner \
        core_tests::test_head_object_distributed_forwards_non_owner_read_to_primary_owner \
        core_tests::test_get_object_version_distributed_forwards_non_owner_read_to_primary_owner \
        core_tests::test_head_object_version_distributed_forwards_non_owner_read_to_primary_owner \
        core_tests::test_get_object_distributed_primary_read_repairs_missing_replica \
        core_tests::test_get_object_range_distributed_primary_read_repairs_missing_replica \
        core_tests::test_head_object_distributed_primary_read_repairs_missing_replica \
        core_tests::test_get_object_version_distributed_primary_read_repairs_missing_replica \
        core_tests::test_get_object_version_range_distributed_primary_read_repairs_missing_replica \
        core_tests::test_head_object_version_distributed_primary_read_repairs_missing_replica \
        core_tests::test_get_object_distributed_non_owner_read_returns_service_unavailable_when_forward_target_unreachable \
        core_tests::test_copy_object_distributed_sets_routing_headers \
        core_tests::test_copy_object_distributed_forwards_non_owner_destination_write_to_primary_owner \
        core_tests::test_copy_object_distributed_primary_write_reports_quorum_headers_when_replica_acks \
        core_tests::test_copy_object_distributed_primary_write_reports_degraded_quorum_when_replica_unreachable \
        core_tests::test_copy_object_distributed_primary_write_strict_quorum_returns_service_unavailable_when_replica_unreachable \
        core_tests::test_delete_object_distributed_sets_routing_headers \
        core_tests::test_delete_object_distributed_forwards_non_owner_write_to_primary_owner \
        core_tests::test_delete_object_distributed_primary_write_reports_quorum_headers_when_replica_acks \
        core_tests::test_delete_object_distributed_primary_write_reports_degraded_quorum_when_replica_unreachable \
        core_tests::test_delete_object_distributed_primary_write_strict_quorum_returns_service_unavailable_when_replica_unreachable \
        core_tests::test_get_object_missing_bucket_returns_no_such_bucket \
        core_tests::test_head_object_missing_bucket_returns_no_such_bucket \
        core_tests::test_delete_object_missing_bucket_returns_no_such_bucket \
        core_tests::test_delete_object_version_missing_bucket_returns_no_such_bucket \
        core_tests::test_delete_object_version_distributed_sets_routing_headers \
        core_tests::test_delete_object_version_distributed_primary_write_reports_quorum_headers_when_replica_acks \
        core_tests::test_delete_object_version_distributed_primary_write_reports_degraded_quorum_when_replica_unreachable \
        core_tests::test_delete_object_version_distributed_primary_write_strict_quorum_returns_service_unavailable_when_replica_unreachable \
        core_tests::test_delete_objects_batch \
        core_tests::test_delete_objects_batch_distributed_reports_service_unavailable_when_forward_target_unreachable \
        core_tests::test_delete_objects_batch_distributed_forwards_non_owner_batch_to_primary_owner \
        core_tests::test_delete_objects_batch_distributed_forwards_mixed_owner_entries \
        core_tests::test_delete_objects_batch_distributed_primary_write_surfaces_per_entry_quorum_error \
        core_tests::test_delete_objects_batch_distributed_primary_write_strict_quorum_returns_service_unavailable_when_replica_unreachable \
        core_tests::test_delete_objects_batch_missing_bucket_returns_no_such_bucket \
        core_tests::test_delete_objects_batch_quiet_mode_suppresses_deleted_entries \
        core_tests::test_delete_objects_batch_rejects_invalid_escaped_xml_content \
        core_tests::test_delete_objects_batch_rejects_more_than_1000_keys \
        core_tests::test_delete_objects_batch_rejects_invalid_xml_structure \
        core_tests::test_delete_object_invalid_key_returns_invalid_argument \
        core_tests::test_delete_objects_batch_invalid_key_returns_invalid_argument_entry \
        core_tests::test_copy_object_basic \
        core_tests::test_copy_object_metadata_directive_is_case_insensitive \
        core_tests::test_copy_object_can_target_specific_source_version \
        core_tests::test_copy_object_missing_source_bucket_returns_no_such_bucket \
        core_tests::test_copy_object_missing_destination_bucket_returns_no_such_bucket \
        core_tests::test_multipart_create_upload_missing_bucket_returns_no_such_bucket \
        core_tests::test_create_multipart_distributed_non_owner_write_rejects_spoofed_internal_auth_headers_with_invalid_sender_identity \
        core_tests::test_copy_object_rejects_empty_source_key \
        core_tests::test_copy_object_rejects_empty_source_bucket \
        core_tests::test_copy_object_rejects_double_leading_slash_source \
        core_tests::test_multipart_upload_part_missing_bucket_returns_no_such_bucket \
        core_tests::test_multipart_complete_missing_bucket_returns_no_such_bucket \
        core_tests::test_multipart_list_parts_missing_bucket_returns_no_such_bucket \
        core_tests::test_multipart_list_parts \
        core_tests::test_multipart_list_parts_supports_max_parts_and_marker \
        core_tests::test_multipart_list_parts_invalid_max_parts_returns_invalid_argument \
        core_tests::test_multipart_list_parts_invalid_part_number_marker_returns_invalid_argument \
        core_tests::test_multipart_list_uploads_missing_bucket_returns_no_such_bucket \
        core_tests::test_multipart_complete \
        core_tests::test_multipart_complete_distributed_non_owner_write_forwards_to_primary_owner \
        core_tests::test_multipart_complete_distributed_primary_write_reports_quorum_headers_when_replica_acks \
        core_tests::test_multipart_complete_distributed_primary_write_reports_degraded_quorum_when_replica_unreachable \
        core_tests::test_multipart_complete_distributed_primary_write_strict_quorum_returns_service_unavailable_when_replica_unreachable \
        core_tests::test_multipart_upload_part_rejects_out_of_range_part_number \
        core_tests::test_multipart_complete_rejects_non_ascending_part_order \
        core_tests::test_multipart_complete_rejects_malformed_xml \
        core_tests::test_get_object_range_first_bytes \
        core_tests::test_get_object_range_preserves_checksum_header \
        core_tests::test_bucket_versioning_enable_and_suspend \
        core_tests::test_bucket_versioning_invalid_status_rejected \
        core_tests::test_bucket_versioning_suspend_preserves_existing_versions \
        core_tests::test_object_version_roundtrip_and_specific_version_delete \
        core_tests::test_get_object_range_with_version_id_reads_specific_version \
        core_tests::test_get_object_range_without_version_id_returns_current_version_header \
        core_tests::test_list_object_versions_supports_max_keys_and_markers \
        core_tests::test_delete_marker_stays_current_after_deleting_older_version \
        core_tests::test_bucket_lifecycle_put_and_get \
        core_tests::test_bucket_lifecycle_get_missing_returns_not_found_code \
        core_tests::test_bucket_lifecycle_invalid_status_rejected \
        core_tests::test_bucket_lifecycle_delete_configuration
      do
        cargo test --test integration "$t" -- --exact
      done
      ;;
    console_api)
      cargo check
      cargo clippy --lib --bins -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
      cargo test api::console::auth::tests
      cargo test api::console::system::tests
      cargo test api::console::storage::tests
      cargo test api::console::response::tests
      for t in \
        console_tests::test_console_auth_login_check_logout_flow \
        console_tests::test_console_auth_secondary_credentials_login_flow \
        console_tests::test_console_auth_credential_matrix_primary_secondary_and_unknown \
        console_tests::test_console_auth_me_returns_authenticated_access_key \
        console_tests::test_console_auth_me_supports_secondary_credentials \
        console_tests::test_console_auth_check_rejects_tampered_cookie \
        console_tests::test_console_auth_me_rejects_expired_cookie \
        console_tests::test_console_auth_me_rejects_future_dated_cookie \
        console_tests::test_console_auth_me_rejects_unknown_access_key_cookie \
        console_tests::test_console_auth_invalid_credentials \
        console_tests::test_console_protected_route_requires_cookie \
        console_tests::test_console_protected_route_rejects_tampered_cookie \
        console_tests::test_console_protected_route_rejects_expired_cookie \
        console_tests::test_console_protected_route_rejects_future_dated_cookie \
        console_tests::test_console_login_rate_limit_enforced \
        console_tests::test_console_presign_uses_authenticated_session_identity \
        console_tests::test_console_presign_encodes_object_keys_with_spaces_and_utf8 \
        console_tests::test_console_presign_returns_not_found_for_missing_bucket \
        console_tests::test_console_presign_returns_not_found_for_missing_object \
        console_tests::test_console_lifecycle_roundtrip \
        console_tests::test_console_lifecycle_rejects_invalid_rules \
        console_tests::test_console_versioning_endpoints_return_not_found_for_missing_bucket \
        console_tests::test_console_list_versions_returns_not_found_for_missing_bucket \
        console_tests::test_console_get_bucket_versioning_request_time_aggregation_merges_peer_state_when_ready \
        console_tests::test_console_get_bucket_versioning_request_time_aggregation_rejects_inconsistent_peer_state \
        console_tests::test_console_get_bucket_versioning_consensus_index_uses_persisted_metadata_state \
        console_tests::test_console_get_bucket_versioning_consensus_index_rejects_persisted_view_mismatch \
        console_tests::test_console_get_bucket_versioning_consensus_index_persists_local_mutation_state \
        console_tests::test_console_get_bucket_lifecycle_consensus_index_returns_empty_rules_when_disabled \
        console_tests::test_console_get_bucket_lifecycle_consensus_index_uses_persisted_lifecycle_configuration_payload \
        console_tests::test_console_get_bucket_lifecycle_consensus_index_persists_local_mutation_state \
        console_tests::test_console_get_bucket_lifecycle_consensus_index_returns_service_unavailable_when_token_missing_for_enabled_rules \
        console_tests::test_console_get_bucket_lifecycle_consensus_index_merges_peer_state_when_token_configured \
        console_tests::test_console_get_bucket_lifecycle_request_time_aggregation_merges_peer_state_when_ready \
        console_tests::test_console_get_bucket_lifecycle_request_time_aggregation_rejects_inconsistent_peer_state \
        console_tests::test_console_set_bucket_versioning_request_time_aggregation_converges_peer_state_when_ready \
        console_tests::test_console_set_bucket_versioning_request_time_aggregation_returns_service_unavailable_when_peer_missing_bucket \
        console_tests::test_console_set_bucket_lifecycle_request_time_aggregation_converges_peer_state_when_ready \
        console_tests::test_console_set_bucket_lifecycle_request_time_aggregation_delete_converges_peer_state_when_ready \
        console_tests::test_console_get_bucket_versioning_rejects_unready_authoritative_metadata_strategy \
        console_tests::test_console_get_bucket_lifecycle_rejects_unready_authoritative_metadata_strategy \
        console_tests::test_console_list_objects_reports_distributed_metadata_coverage \
        console_tests::test_console_list_objects_reports_metadata_strategy_for_consensus_index \
        console_tests::test_console_list_objects_consensus_index_returns_service_unavailable_when_token_missing \
        console_tests::test_console_list_objects_consensus_index_returns_service_unavailable_when_peer_fan_in_incomplete \
        console_tests::test_console_list_buckets_request_time_aggregation_merges_peer_bucket_state_when_ready \
        console_tests::test_console_list_buckets_request_time_aggregation_rejects_inconsistent_peer_versioning_state \
        console_tests::test_console_list_buckets_consensus_index_uses_persisted_metadata_state \
        console_tests::test_console_list_buckets_consensus_index_rejects_persisted_view_mismatch \
        console_tests::test_console_list_buckets_consensus_index_persists_local_create_into_consensus_state \
        console_tests::test_console_create_bucket_consensus_index_rejects_existing_persisted_bucket_without_local_side_effect \
        console_tests::test_console_create_bucket_consensus_index_rejects_active_tombstone_without_local_side_effect \
        console_tests::test_console_delete_bucket_consensus_index_rejects_missing_persisted_bucket_without_local_side_effect \
        console_tests::test_console_delete_bucket_consensus_index_rejects_tombstoned_persisted_bucket_without_local_side_effect \
        console_tests::test_console_list_objects_request_time_aggregation_merges_peer_object_state_when_ready \
        console_tests::test_console_list_versions_consensus_index_merges_peer_state_when_ready \
        console_tests::test_console_list_versions_consensus_index_does_not_fallback_to_local_storage \
        console_tests::test_console_list_versions_consensus_index_returns_service_unavailable_when_token_missing \
        console_tests::test_console_list_versions_consensus_index_returns_service_unavailable_when_peer_fan_in_incomplete \
        console_tests::test_console_list_versions_request_time_aggregation_merges_peer_state_when_ready \
        console_tests::test_console_create_bucket_request_time_aggregation_converges_peer_state_when_ready \
        console_tests::test_console_create_bucket_request_time_aggregation_succeeds_when_peer_already_has_bucket \
        console_tests::test_console_delete_bucket_request_time_aggregation_converges_peer_state_when_ready \
        console_tests::test_console_create_bucket_rejects_unready_authoritative_metadata_strategy \
        console_tests::test_console_delete_bucket_rejects_unready_authoritative_metadata_strategy \
        console_tests::test_console_list_buckets_rejects_unready_authoritative_metadata_strategy \
        console_tests::test_console_list_objects_rejects_unready_authoritative_metadata_strategy \
        console_tests::test_console_list_versions_reports_distributed_metadata_coverage \
        console_tests::test_console_list_versions_rejects_unready_authoritative_metadata_strategy \
        console_tests::test_console_list_objects_returns_bad_request_for_invalid_prefix \
        console_tests::test_console_list_objects_returns_bad_request_for_empty_delimiter \
        console_tests::test_console_list_versions_returns_bad_request_for_invalid_key \
        console_tests::test_console_delete_version_returns_not_found_for_missing_version \
        console_tests::test_console_create_folder_returns_not_found_for_missing_bucket \
        console_tests::test_console_delete_object_returns_not_found_for_missing_bucket \
        console_tests::test_console_download_object_returns_not_found_for_missing_bucket \
        console_tests::test_console_download_version_returns_not_found_for_missing_bucket \
        console_tests::test_console_health_endpoint_requires_auth_and_returns_json \
        console_tests::test_console_health_endpoint_reports_distributed_mode_when_configured \
        console_tests::test_console_health_endpoint_reports_degraded_when_storage_data_path_probe_fails \
        console_tests::test_console_health_endpoint_reports_degraded_when_disk_headroom_threshold_not_met \
        console_tests::test_console_health_endpoint_reports_degraded_when_cluster_peers_include_local_node_id \
        console_tests::test_console_health_endpoint_contract_shape_is_stable \
        console_tests::test_console_metrics_endpoint_requires_auth_and_returns_json \
        console_tests::test_console_metrics_endpoint_reports_distributed_mode_when_configured \
        console_tests::test_console_topology_endpoint_requires_auth_and_returns_json \
        console_tests::test_console_topology_endpoint_reports_distributed_mode_when_configured \
        console_tests::test_console_membership_endpoint_requires_auth_and_returns_json \
        console_tests::test_console_membership_endpoint_reports_distributed_mode_when_configured \
        console_tests::test_console_placement_endpoint_requires_auth_and_returns_json \
        console_tests::test_console_placement_endpoint_reports_distributed_chunk_owners \
        console_tests::test_console_placement_endpoint_contract_shape_is_stable \
        console_tests::test_console_placement_endpoint_rejects_invalid_query \
        console_tests::test_console_rebalance_endpoint_requires_auth_and_reports_join_preview \
        console_tests::test_console_rebalance_endpoint_reports_distributed_leave_preview \
        console_tests::test_console_rebalance_endpoint_contract_shape_is_stable \
        console_tests::test_console_rebalance_endpoint_rejects_invalid_query \
        console_tests::test_console_summary_endpoint_requires_auth_and_returns_json \
        console_tests::test_console_summary_endpoint_reports_distributed_mode_when_configured \
        console_tests::test_console_summary_endpoint_reports_degraded_health_when_storage_data_path_probe_fails \
        console_tests::test_console_summary_endpoint_reports_degraded_health_when_cluster_peers_include_local_node_id \
        console_tests::test_console_summary_endpoint_contract_shape_is_stable \
        console_tests::test_console_buckets_and_objects_json_contract_shapes \
        console_tests::test_console_download_object_returns_expected_headers_and_body \
        console_tests::test_console_object_routes_support_percent_encoded_key_path \
        console_tests::test_console_download_version_returns_expected_headers_and_body \
        console_tests::test_console_download_version_supports_percent_encoded_key_path \
        console_tests::test_console_versions_list_remains_available_after_versioning_suspend \
        console_tests::test_console_error_contract_shape_for_auth_failures
      do
        cargo test --test integration "$t" -- --exact
      done
      ;;
    web_console_ui)
      (
        cd ui
        bun run test
        bun run check
        bun run build
      )
      ;;
    quality_harness)
      cargo clippy --all-targets -- -D warnings
      cargo clippy --lib -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
      cargo clippy --bins -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
      cargo test -- --test-threads=1
      (
        cd ui
        bun run test
      )
      bash -n tests/mc_test.sh
      bash -n tests/aws_cli_test.sh
      ;;
    *)
      echo "Unknown domain: $domain" >&2
      usage
      return 1
      ;;
  esac
}

main() {
  if [[ "${1:-}" == "" ]]; then
    usage
    exit 1
  fi

  if [[ "$1" == "all" ]]; then
    for domain in \
      runtime_platform \
      storage_engine \
      cluster_transport_security \
      cluster_metadata_plane \
      s3_auth_sigv4 \
      s3_api_surface \
      console_api \
      web_console_ui \
      quality_harness
    do
      run_domain "$domain"
    done
    exit 0
  fi

  run_domain "$1"
}

main "$@"
