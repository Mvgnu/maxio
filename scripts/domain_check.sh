#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/domain_check.sh <domain|all>

Domains:
  runtime_platform
  storage_engine
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
      cargo clippy --lib --bins -- -D clippy::unwrap_used -D clippy::expect_used
      cargo test server::tests
      for t in \
        runtime_tests::test_request_id_header_present_on_s3_auth_failure \
        runtime_tests::test_metrics_endpoint_exposes_runtime_counters \
        runtime_tests::test_metrics_endpoint_reports_distributed_gauges_when_cluster_peers_configured \
        runtime_tests::test_healthz_endpoint_reports_runtime_status \
        runtime_tests::test_healthz_reports_distributed_mode_when_cluster_peers_configured \
        runtime_tests::test_healthz_reports_degraded_when_storage_data_path_probe_fails \
        runtime_tests::test_healthz_reports_degraded_when_disk_headroom_threshold_not_met \
        runtime_tests::test_healthz_reports_degraded_when_static_peer_connectivity_probe_fails \
        runtime_tests::test_healthz_reports_degraded_when_cluster_peers_include_local_node_id \
        runtime_tests::test_placement_epoch_persists_and_increments_when_membership_view_changes \
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
      cargo clippy --lib -- -D clippy::unwrap_used -D clippy::expect_used
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
    s3_auth_sigv4)
      cargo check
      cargo test auth::signature_v4::tests
      for t in \
        auth_tests::test_auth_rejects_bad_key \
        auth_tests::test_auth_accepts_valid_signature \
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
      cargo clippy --lib -- -D clippy::unwrap_used -D clippy::expect_used
      cargo test error::tests
      cargo test api::bucket::validation::tests
      cargo test api::bucket::service::tests
      cargo test api::list::tests
      cargo test api::list::response::tests
      cargo test api::list::service::tests
      cargo test api::object::parsing::tests
      cargo test api::object::service::tests
      cargo test api::multipart::tests
      cargo test api::multipart::service::tests
      for t in \
        core_tests::test_create_bucket \
        core_tests::test_list_objects \
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
        core_tests::test_put_object_distributed_non_owner_write_returns_access_denied_when_forward_target_unreachable \
        core_tests::test_put_object_distributed_forwards_non_owner_write_to_primary_owner \
        core_tests::test_put_object_distributed_primary_write_reports_quorum_headers_when_replica_acks \
        core_tests::test_put_object_distributed_primary_write_reports_degraded_quorum_when_replica_unreachable \
        core_tests::test_put_object_distributed_non_owner_write_ignores_untrusted_forward_protocol_headers \
        core_tests::test_get_object_distributed_forwards_non_owner_read_to_primary_owner \
        core_tests::test_head_object_distributed_forwards_non_owner_read_to_primary_owner \
        core_tests::test_get_object_distributed_primary_read_repairs_missing_replica \
        core_tests::test_head_object_distributed_primary_read_repairs_missing_replica \
        core_tests::test_get_object_version_distributed_primary_read_repairs_missing_replica \
        core_tests::test_head_object_version_distributed_primary_read_repairs_missing_replica \
        core_tests::test_get_object_distributed_non_owner_read_returns_access_denied_when_forward_target_unreachable \
        core_tests::test_copy_object_distributed_sets_routing_headers \
        core_tests::test_copy_object_distributed_forwards_non_owner_destination_write_to_primary_owner \
        core_tests::test_copy_object_distributed_primary_write_reports_quorum_headers_when_replica_acks \
        core_tests::test_copy_object_distributed_primary_write_reports_degraded_quorum_when_replica_unreachable \
        core_tests::test_delete_object_distributed_sets_routing_headers \
        core_tests::test_delete_object_distributed_forwards_non_owner_write_to_primary_owner \
        core_tests::test_delete_object_distributed_primary_write_reports_quorum_headers_when_replica_acks \
        core_tests::test_delete_object_distributed_primary_write_reports_degraded_quorum_when_replica_unreachable \
        core_tests::test_get_object_missing_bucket_returns_no_such_bucket \
        core_tests::test_head_object_missing_bucket_returns_no_such_bucket \
        core_tests::test_delete_object_missing_bucket_returns_no_such_bucket \
        core_tests::test_delete_object_version_missing_bucket_returns_no_such_bucket \
        core_tests::test_delete_object_version_distributed_sets_routing_headers \
        core_tests::test_delete_object_version_distributed_primary_write_reports_quorum_headers_when_replica_acks \
        core_tests::test_delete_object_version_distributed_primary_write_reports_degraded_quorum_when_replica_unreachable \
        core_tests::test_delete_objects_batch \
        core_tests::test_delete_objects_batch_distributed_reports_access_denied_when_forward_target_unreachable \
        core_tests::test_delete_objects_batch_distributed_forwards_non_owner_batch_to_primary_owner \
        core_tests::test_delete_objects_batch_distributed_forwards_mixed_owner_entries \
        core_tests::test_delete_objects_batch_distributed_primary_write_surfaces_per_entry_quorum_error \
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
      cargo clippy --lib --bins -- -D clippy::unwrap_used -D clippy::expect_used
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
      cargo clippy --lib -- -D clippy::unwrap_used -D clippy::expect_used
      cargo clippy --bins -- -D clippy::unwrap_used -D clippy::expect_used
      cargo test
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
