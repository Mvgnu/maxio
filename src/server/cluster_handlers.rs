use super::*;

fn cluster_peer_transport_not_ready(state: &AppState, topology: &RuntimeTopologySnapshot) -> bool {
    let auth_status = probe_cluster_peer_auth_status(state.config.as_ref(), topology);
    let transport_policy = cluster_peer_auth_transport_policy_assessment(
        state.config.as_ref(),
        topology,
        &auth_status,
    );
    !transport_policy.is_ready()
}

fn membership_update_preconditions_missing(
    expected_membership_view_id: Option<&str>,
    expected_placement_epoch: Option<u64>,
) -> bool {
    expected_membership_view_id.is_none() || expected_placement_epoch.is_none()
}

pub(super) async fn cluster_join_authorize_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let topology = runtime_topology_snapshot(&state);
    let default_mode = if state.config.cluster_auth_token().is_some() {
        "shared_token"
    } else {
        "compatibility_no_token"
    };
    let (status, status_label, mode, reason, peer_node_id, authorized) =
        if !topology.is_distributed() {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "misconfigured",
                default_mode.to_string(),
                JOIN_AUTHORIZE_REASON_DISTRIBUTED_MODE_DISABLED.to_string(),
                None,
                false,
            )
        } else if !topology.membership_status.ready {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "misconfigured",
                default_mode.to_string(),
                JOIN_AUTHORIZE_REASON_MEMBERSHIP_ENGINE_NOT_READY.to_string(),
                None,
                false,
            )
        } else if state.config.cluster_auth_token().is_none() {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "misconfigured",
                default_mode.to_string(),
                JOIN_AUTHORIZE_REASON_CLUSTER_AUTH_TOKEN_NOT_CONFIGURED.to_string(),
                None,
                false,
            )
        } else if cluster_peer_transport_not_ready(&state, &topology) {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "misconfigured",
                default_mode.to_string(),
                JOIN_AUTHORIZE_REASON_CLUSTER_PEER_TRANSPORT_NOT_READY.to_string(),
                None,
                false,
            )
        } else {
            let result = authorize_join_request(
                &headers,
                topology.cluster_id.as_str(),
                state.config.cluster_auth_token(),
                topology.node_id.as_str(),
                unix_ms_now(),
                DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
                Some(state.join_nonce_replay_guard.as_ref()),
            );

            let status = if result.authorized {
                StatusCode::OK
            } else if matches!(
                result.error,
                Some(JoinAuthorizationError::InvalidConfiguration)
            ) {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::FORBIDDEN
            };
            let status_label = if result.authorized {
                "authorized"
            } else if status == StatusCode::SERVICE_UNAVAILABLE {
                "misconfigured"
            } else {
                "rejected"
            };
            (
                status,
                status_label,
                result.mode.as_str().to_string(),
                result.reject_reason().to_string(),
                result.peer_node_id,
                result.authorized,
            )
        };
    state
        .cluster_join_authorize_counters
        .record(status_label, reason.as_str());
    let payload = ClusterJoinAuthorizePayload {
        authorized,
        status: status_label.to_string(),
        mode,
        reason,
        peer_node_id,
        cluster_id: topology.cluster_id.clone(),
        membership_view_id: topology.membership_view_id,
        local_node_id: topology.node_id,
        placement_epoch: topology.placement_epoch,
    };

    response_with_content_type(
        status,
        HeaderValue::from_static("application/json"),
        json_body_or_fallback(
            &payload,
            b"{\"authorized\":false,\"status\":\"degraded\"}",
            "cluster_join_authorize_handler",
        ),
    )
}

pub(super) async fn cluster_join_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ClusterJoinRequest>,
) -> Response {
    let topology = runtime_topology_snapshot(&state);
    let is_propagation_request = is_membership_update_propagation_request(&headers);
    let default_mode = if state.config.cluster_auth_token().is_some() {
        "shared_token"
    } else {
        "compatibility_no_token"
    };
    if !topology.is_distributed() {
        let payload = ClusterMembershipUpdatePayload {
            status: "misconfigured".to_string(),
            reason: JOIN_AUTHORIZE_REASON_DISTRIBUTED_MODE_DISABLED.to_string(),
            auth_reason: None,
            mode: default_mode.to_string(),
            updated: false,
            cluster_id: topology.cluster_id,
            local_node_id: topology.node_id,
            cluster_peers: topology.cluster_peers,
            membership_view_id: topology.membership_view_id,
            placement_epoch: topology.placement_epoch,
            membership_last_update_unix_ms: topology.membership_status.last_update_unix_ms,
        };
        return cluster_join_response(&state, StatusCode::SERVICE_UNAVAILABLE, payload);
    }
    if !topology.membership_status.ready {
        let payload = ClusterMembershipUpdatePayload {
            status: "misconfigured".to_string(),
            reason: JOIN_AUTHORIZE_REASON_MEMBERSHIP_ENGINE_NOT_READY.to_string(),
            auth_reason: None,
            mode: default_mode.to_string(),
            updated: false,
            cluster_id: topology.cluster_id,
            local_node_id: topology.node_id,
            cluster_peers: topology.cluster_peers,
            membership_view_id: topology.membership_view_id,
            placement_epoch: topology.placement_epoch,
            membership_last_update_unix_ms: topology.membership_status.last_update_unix_ms,
        };
        return cluster_join_response(&state, StatusCode::SERVICE_UNAVAILABLE, payload);
    }
    if state.config.cluster_auth_token().is_none() {
        let payload = ClusterMembershipUpdatePayload {
            status: "misconfigured".to_string(),
            reason: JOIN_AUTHORIZE_REASON_CLUSTER_AUTH_TOKEN_NOT_CONFIGURED.to_string(),
            auth_reason: None,
            mode: default_mode.to_string(),
            updated: false,
            cluster_id: topology.cluster_id,
            local_node_id: topology.node_id,
            cluster_peers: topology.cluster_peers,
            membership_view_id: topology.membership_view_id,
            placement_epoch: topology.placement_epoch,
            membership_last_update_unix_ms: topology.membership_status.last_update_unix_ms,
        };
        return cluster_join_response(&state, StatusCode::SERVICE_UNAVAILABLE, payload);
    }
    if cluster_peer_transport_not_ready(&state, &topology) {
        let payload = ClusterMembershipUpdatePayload {
            status: "misconfigured".to_string(),
            reason: JOIN_AUTHORIZE_REASON_CLUSTER_PEER_TRANSPORT_NOT_READY.to_string(),
            auth_reason: None,
            mode: default_mode.to_string(),
            updated: false,
            cluster_id: topology.cluster_id,
            local_node_id: topology.node_id,
            cluster_peers: topology.cluster_peers,
            membership_view_id: topology.membership_view_id,
            placement_epoch: topology.placement_epoch,
            membership_last_update_unix_ms: topology.membership_status.last_update_unix_ms,
        };
        return cluster_join_response(&state, StatusCode::SERVICE_UNAVAILABLE, payload);
    }

    let join_precondition_present =
        request.expected_membership_view_id.is_some() || request.expected_placement_epoch.is_some();
    let mut auth = authorize_join_request(
        &headers,
        topology.cluster_id.as_str(),
        state.config.cluster_auth_token(),
        topology.node_id.as_str(),
        unix_ms_now(),
        DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
        Some(state.join_nonce_replay_guard.as_ref()),
    );
    if !auth.authorized
        && join_precondition_present
        && matches!(
            auth.error,
            Some(JoinAuthorizationError::ForwardedByNodeIdMismatch)
        )
    {
        let mut headers_without_forwarded_sender_binding = headers.clone();
        headers_without_forwarded_sender_binding.remove(FORWARDED_BY_HEADER);
        auth = authorize_join_request(
            &headers_without_forwarded_sender_binding,
            topology.cluster_id.as_str(),
            state.config.cluster_auth_token(),
            topology.node_id.as_str(),
            unix_ms_now(),
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            Some(state.join_nonce_replay_guard.as_ref()),
        );
    }

    if !auth.authorized {
        let status = if matches!(
            auth.error,
            Some(JoinAuthorizationError::InvalidConfiguration)
        ) {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::FORBIDDEN
        };
        let status_label = if status == StatusCode::SERVICE_UNAVAILABLE {
            "misconfigured"
        } else {
            "rejected"
        };
        let payload = ClusterMembershipUpdatePayload {
            status: status_label.to_string(),
            reason: MEMBERSHIP_UPDATE_REASON_UNAUTHORIZED.to_string(),
            auth_reason: Some(auth.reject_reason().to_string()),
            mode: auth.mode.as_str().to_string(),
            updated: false,
            cluster_id: topology.cluster_id,
            local_node_id: topology.node_id,
            cluster_peers: topology.cluster_peers,
            membership_view_id: topology.membership_view_id,
            placement_epoch: topology.placement_epoch,
            membership_last_update_unix_ms: topology.membership_status.last_update_unix_ms,
        };
        return cluster_join_response(&state, status, payload);
    }

    let forwarded_auth = authenticate_forwarded_request(
        &headers,
        FORWARDED_BY_HEADER,
        state.config.cluster_auth_token(),
        topology.node_id.as_str(),
        topology.cluster_peers.as_slice(),
    );
    if !forwarded_auth.trusted {
        record_peer_auth_rejection(&forwarded_auth);
        let status = if matches!(
            forwarded_auth.error,
            Some(PeerAuthenticationError::InvalidAuthenticatorConfiguration)
        ) {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::FORBIDDEN
        };
        let status_label = if status == StatusCode::SERVICE_UNAVAILABLE {
            "misconfigured"
        } else {
            "rejected"
        };
        let payload = ClusterMembershipUpdatePayload {
            status: status_label.to_string(),
            reason: MEMBERSHIP_UPDATE_REASON_UNAUTHORIZED.to_string(),
            auth_reason: Some(forwarded_auth.reject_reason().to_string()),
            mode: forwarded_auth.mode.as_str().to_string(),
            updated: false,
            cluster_id: topology.cluster_id,
            local_node_id: topology.node_id,
            cluster_peers: topology.cluster_peers,
            membership_view_id: topology.membership_view_id,
            placement_epoch: topology.placement_epoch,
            membership_last_update_unix_ms: topology.membership_status.last_update_unix_ms,
        };
        return cluster_join_response(&state, status, payload);
    }

    let expected_membership_view_id = match request.expected_membership_view_id.as_deref() {
        Some(raw) if raw.trim().is_empty() => {
            let payload = ClusterMembershipUpdatePayload {
                status: "rejected".to_string(),
                reason: MEMBERSHIP_UPDATE_REASON_INVALID_PAYLOAD.to_string(),
                auth_reason: None,
                mode: forwarded_auth.mode.as_str().to_string(),
                updated: false,
                cluster_id: topology.cluster_id,
                local_node_id: topology.node_id,
                cluster_peers: topology.cluster_peers,
                membership_view_id: topology.membership_view_id,
                placement_epoch: topology.placement_epoch,
                membership_last_update_unix_ms: topology.membership_status.last_update_unix_ms,
            };
            return cluster_join_response(&state, StatusCode::BAD_REQUEST, payload);
        }
        Some(raw) => Some(raw.trim().to_string()),
        None => None,
    };
    if membership_update_precondition_failed(
        &topology,
        expected_membership_view_id.as_deref(),
        request.expected_placement_epoch,
    ) {
        let payload = ClusterMembershipUpdatePayload {
            status: "rejected".to_string(),
            reason: MEMBERSHIP_UPDATE_REASON_PRECONDITION_FAILED.to_string(),
            auth_reason: None,
            mode: forwarded_auth.mode.as_str().to_string(),
            updated: false,
            cluster_id: topology.cluster_id,
            local_node_id: topology.node_id,
            cluster_peers: topology.cluster_peers,
            membership_view_id: topology.membership_view_id,
            placement_epoch: topology.placement_epoch,
            membership_last_update_unix_ms: topology.membership_status.last_update_unix_ms,
        };
        return cluster_join_response(&state, StatusCode::CONFLICT, payload);
    }

    let join_peer_node_id = match auth.peer_node_id.as_deref() {
        Some(peer_node_id) => peer_node_id.to_string(),
        None => {
            let payload = ClusterMembershipUpdatePayload {
                status: "rejected".to_string(),
                reason: MEMBERSHIP_UPDATE_REASON_INVALID_PAYLOAD.to_string(),
                auth_reason: None,
                mode: forwarded_auth.mode.as_str().to_string(),
                updated: false,
                cluster_id: topology.cluster_id,
                local_node_id: topology.node_id,
                cluster_peers: topology.cluster_peers,
                membership_view_id: topology.membership_view_id,
                placement_epoch: topology.placement_epoch,
                membership_last_update_unix_ms: topology.membership_status.last_update_unix_ms,
            };
            return cluster_join_response(&state, StatusCode::BAD_REQUEST, payload);
        }
    };

    let mut next_cluster_peers = topology.cluster_peers.clone();
    next_cluster_peers.push(join_peer_node_id);
    let normalized_cluster_peers = match normalize_cluster_peers_for_membership_update(
        topology.node_id.as_str(),
        next_cluster_peers.as_slice(),
    ) {
        Ok(peers) => peers,
        Err(_) => {
            let payload = ClusterMembershipUpdatePayload {
                status: "rejected".to_string(),
                reason: MEMBERSHIP_UPDATE_REASON_INVALID_PAYLOAD.to_string(),
                auth_reason: None,
                mode: forwarded_auth.mode.as_str().to_string(),
                updated: false,
                cluster_id: topology.cluster_id,
                local_node_id: topology.node_id,
                cluster_peers: topology.cluster_peers,
                membership_view_id: topology.membership_view_id,
                placement_epoch: topology.placement_epoch,
                membership_last_update_unix_ms: topology.membership_status.last_update_unix_ms,
            };
            return cluster_join_response(&state, StatusCode::BAD_REQUEST, payload);
        }
    };

    match state.apply_membership_peers(normalized_cluster_peers).await {
        Ok(outcome) => {
            let updated_topology = runtime_topology_snapshot(&state);
            if outcome.changed {
                spawn_rebalance_queue_population(&state, &topology, &updated_topology);
                if !is_propagation_request {
                    spawn_membership_update_propagation(
                        state.config.clone(),
                        &topology,
                        &updated_topology,
                        state.config.cluster_auth_token(),
                    );
                }
            }
            let payload = ClusterMembershipUpdatePayload {
                status: "applied".to_string(),
                reason: MEMBERSHIP_UPDATE_REASON_APPLIED.to_string(),
                auth_reason: None,
                mode: forwarded_auth.mode.as_str().to_string(),
                updated: outcome.changed,
                cluster_id: updated_topology.cluster_id,
                local_node_id: updated_topology.node_id,
                cluster_peers: updated_topology.cluster_peers,
                membership_view_id: outcome.membership_view_id,
                placement_epoch: outcome.placement_epoch,
                membership_last_update_unix_ms: outcome.membership_last_update_unix_ms,
            };
            cluster_join_response(&state, StatusCode::OK, payload)
        }
        Err(_) => {
            let payload = ClusterMembershipUpdatePayload {
                status: "misconfigured".to_string(),
                reason: MEMBERSHIP_UPDATE_REASON_STATE_PERSIST_FAILED.to_string(),
                auth_reason: None,
                mode: forwarded_auth.mode.as_str().to_string(),
                updated: false,
                cluster_id: topology.cluster_id,
                local_node_id: topology.node_id,
                cluster_peers: topology.cluster_peers,
                membership_view_id: topology.membership_view_id,
                placement_epoch: topology.placement_epoch,
                membership_last_update_unix_ms: topology.membership_status.last_update_unix_ms,
            };
            cluster_join_response(&state, StatusCode::SERVICE_UNAVAILABLE, payload)
        }
    }
}

pub(super) async fn cluster_membership_update_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ClusterMembershipUpdateRequest>,
) -> Response {
    let topology = runtime_topology_snapshot(&state);
    let is_propagation_request = is_membership_update_propagation_request(&headers);
    let default_mode = if state.config.cluster_auth_token().is_some() {
        "shared_token"
    } else {
        "compatibility_no_token"
    };
    if !topology.is_distributed() {
        let payload = ClusterMembershipUpdatePayload {
            status: "misconfigured".to_string(),
            reason: JOIN_AUTHORIZE_REASON_DISTRIBUTED_MODE_DISABLED.to_string(),
            auth_reason: None,
            mode: default_mode.to_string(),
            updated: false,
            cluster_id: topology.cluster_id,
            local_node_id: topology.node_id,
            cluster_peers: topology.cluster_peers,
            membership_view_id: topology.membership_view_id,
            placement_epoch: topology.placement_epoch,
            membership_last_update_unix_ms: topology.membership_status.last_update_unix_ms,
        };
        return membership_update_response(&state, StatusCode::SERVICE_UNAVAILABLE, payload);
    }
    if !topology.membership_status.ready {
        let payload = ClusterMembershipUpdatePayload {
            status: "misconfigured".to_string(),
            reason: JOIN_AUTHORIZE_REASON_MEMBERSHIP_ENGINE_NOT_READY.to_string(),
            auth_reason: None,
            mode: default_mode.to_string(),
            updated: false,
            cluster_id: topology.cluster_id,
            local_node_id: topology.node_id,
            cluster_peers: topology.cluster_peers,
            membership_view_id: topology.membership_view_id,
            placement_epoch: topology.placement_epoch,
            membership_last_update_unix_ms: topology.membership_status.last_update_unix_ms,
        };
        return membership_update_response(&state, StatusCode::SERVICE_UNAVAILABLE, payload);
    }
    if state.config.cluster_auth_token().is_none() {
        let payload = ClusterMembershipUpdatePayload {
            status: "misconfigured".to_string(),
            reason: JOIN_AUTHORIZE_REASON_CLUSTER_AUTH_TOKEN_NOT_CONFIGURED.to_string(),
            auth_reason: None,
            mode: default_mode.to_string(),
            updated: false,
            cluster_id: topology.cluster_id,
            local_node_id: topology.node_id,
            cluster_peers: topology.cluster_peers,
            membership_view_id: topology.membership_view_id,
            placement_epoch: topology.placement_epoch,
            membership_last_update_unix_ms: topology.membership_status.last_update_unix_ms,
        };
        return membership_update_response(&state, StatusCode::SERVICE_UNAVAILABLE, payload);
    }
    if cluster_peer_transport_not_ready(&state, &topology) {
        let payload = ClusterMembershipUpdatePayload {
            status: "misconfigured".to_string(),
            reason: JOIN_AUTHORIZE_REASON_CLUSTER_PEER_TRANSPORT_NOT_READY.to_string(),
            auth_reason: None,
            mode: default_mode.to_string(),
            updated: false,
            cluster_id: topology.cluster_id,
            local_node_id: topology.node_id,
            cluster_peers: topology.cluster_peers,
            membership_view_id: topology.membership_view_id,
            placement_epoch: topology.placement_epoch,
            membership_last_update_unix_ms: topology.membership_status.last_update_unix_ms,
        };
        return membership_update_response(&state, StatusCode::SERVICE_UNAVAILABLE, payload);
    }

    let join_node_id_from_header = headers
        .get(JOIN_NODE_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let payload_targets_single_join_node =
        join_node_id_from_header
            .as_deref()
            .is_some_and(|join_node_id| {
                request.cluster_peers.len() == 1
                    && peer_identity_eq(request.cluster_peers[0].as_str(), join_node_id)
            });
    let mut auth = authorize_join_request(
        &headers,
        topology.cluster_id.as_str(),
        state.config.cluster_auth_token(),
        topology.node_id.as_str(),
        unix_ms_now(),
        DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
        Some(state.join_nonce_replay_guard.as_ref()),
    );
    if !auth.authorized
        && !payload_targets_single_join_node
        && matches!(
            auth.error,
            Some(JoinAuthorizationError::ForwardedByNodeIdMismatch)
        )
    {
        let mut headers_without_forwarded_sender_binding = headers.clone();
        headers_without_forwarded_sender_binding.remove(FORWARDED_BY_HEADER);
        auth = authorize_join_request(
            &headers_without_forwarded_sender_binding,
            topology.cluster_id.as_str(),
            state.config.cluster_auth_token(),
            topology.node_id.as_str(),
            unix_ms_now(),
            DEFAULT_JOIN_MAX_CLOCK_SKEW_MS,
            Some(state.join_nonce_replay_guard.as_ref()),
        );
    }

    if !auth.authorized {
        let status = if matches!(
            auth.error,
            Some(JoinAuthorizationError::InvalidConfiguration)
        ) {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::FORBIDDEN
        };
        let status_label = if status == StatusCode::SERVICE_UNAVAILABLE {
            "misconfigured"
        } else {
            "rejected"
        };
        let payload = ClusterMembershipUpdatePayload {
            status: status_label.to_string(),
            reason: MEMBERSHIP_UPDATE_REASON_UNAUTHORIZED.to_string(),
            auth_reason: Some(auth.reject_reason().to_string()),
            mode: auth.mode.as_str().to_string(),
            updated: false,
            cluster_id: topology.cluster_id,
            local_node_id: topology.node_id,
            cluster_peers: topology.cluster_peers,
            membership_view_id: topology.membership_view_id,
            placement_epoch: topology.placement_epoch,
            membership_last_update_unix_ms: topology.membership_status.last_update_unix_ms,
        };
        return membership_update_response(&state, status, payload);
    }

    let forwarded_auth = authenticate_forwarded_request(
        &headers,
        FORWARDED_BY_HEADER,
        state.config.cluster_auth_token(),
        topology.node_id.as_str(),
        topology.cluster_peers.as_slice(),
    );
    if !forwarded_auth.trusted {
        record_peer_auth_rejection(&forwarded_auth);
        let status = if matches!(
            forwarded_auth.error,
            Some(PeerAuthenticationError::InvalidAuthenticatorConfiguration)
        ) {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::FORBIDDEN
        };
        let status_label = if status == StatusCode::SERVICE_UNAVAILABLE {
            "misconfigured"
        } else {
            "rejected"
        };
        let payload = ClusterMembershipUpdatePayload {
            status: status_label.to_string(),
            reason: MEMBERSHIP_UPDATE_REASON_UNAUTHORIZED.to_string(),
            auth_reason: Some(forwarded_auth.reject_reason().to_string()),
            mode: forwarded_auth.mode.as_str().to_string(),
            updated: false,
            cluster_id: topology.cluster_id,
            local_node_id: topology.node_id,
            cluster_peers: topology.cluster_peers,
            membership_view_id: topology.membership_view_id,
            placement_epoch: topology.placement_epoch,
            membership_last_update_unix_ms: topology.membership_status.last_update_unix_ms,
        };
        return membership_update_response(&state, status, payload);
    }

    if request.cluster_id.trim() != topology.cluster_id {
        let payload = ClusterMembershipUpdatePayload {
            status: "rejected".to_string(),
            reason: MEMBERSHIP_UPDATE_REASON_CLUSTER_ID_MISMATCH.to_string(),
            auth_reason: None,
            mode: auth.mode.as_str().to_string(),
            updated: false,
            cluster_id: topology.cluster_id,
            local_node_id: topology.node_id,
            cluster_peers: topology.cluster_peers,
            membership_view_id: topology.membership_view_id,
            placement_epoch: topology.placement_epoch,
            membership_last_update_unix_ms: topology.membership_status.last_update_unix_ms,
        };
        return membership_update_response(&state, StatusCode::FORBIDDEN, payload);
    }
    let expected_membership_view_id = match request.expected_membership_view_id.as_deref() {
        Some(raw) if raw.trim().is_empty() => {
            let payload = ClusterMembershipUpdatePayload {
                status: "rejected".to_string(),
                reason: MEMBERSHIP_UPDATE_REASON_INVALID_PAYLOAD.to_string(),
                auth_reason: None,
                mode: auth.mode.as_str().to_string(),
                updated: false,
                cluster_id: topology.cluster_id,
                local_node_id: topology.node_id,
                cluster_peers: topology.cluster_peers,
                membership_view_id: topology.membership_view_id,
                placement_epoch: topology.placement_epoch,
                membership_last_update_unix_ms: topology.membership_status.last_update_unix_ms,
            };
            return membership_update_response(&state, StatusCode::BAD_REQUEST, payload);
        }
        Some(raw) => Some(raw.trim().to_string()),
        None => None,
    };
    if is_propagation_request
        && membership_update_preconditions_missing(
            expected_membership_view_id.as_deref(),
            request.expected_placement_epoch,
        )
    {
        let payload = ClusterMembershipUpdatePayload {
            status: "rejected".to_string(),
            reason: MEMBERSHIP_UPDATE_REASON_PRECONDITION_FAILED.to_string(),
            auth_reason: None,
            mode: auth.mode.as_str().to_string(),
            updated: false,
            cluster_id: topology.cluster_id,
            local_node_id: topology.node_id,
            cluster_peers: topology.cluster_peers,
            membership_view_id: topology.membership_view_id,
            placement_epoch: topology.placement_epoch,
            membership_last_update_unix_ms: topology.membership_status.last_update_unix_ms,
        };
        return membership_update_response(&state, StatusCode::CONFLICT, payload);
    }
    if membership_update_precondition_failed(
        &topology,
        expected_membership_view_id.as_deref(),
        request.expected_placement_epoch,
    ) {
        let payload = ClusterMembershipUpdatePayload {
            status: "rejected".to_string(),
            reason: MEMBERSHIP_UPDATE_REASON_PRECONDITION_FAILED.to_string(),
            auth_reason: None,
            mode: auth.mode.as_str().to_string(),
            updated: false,
            cluster_id: topology.cluster_id,
            local_node_id: topology.node_id,
            cluster_peers: topology.cluster_peers,
            membership_view_id: topology.membership_view_id,
            placement_epoch: topology.placement_epoch,
            membership_last_update_unix_ms: topology.membership_status.last_update_unix_ms,
        };
        return membership_update_response(&state, StatusCode::CONFLICT, payload);
    }

    let normalized_cluster_peers = match normalize_cluster_peers_for_membership_update(
        topology.node_id.as_str(),
        request.cluster_peers.as_slice(),
    ) {
        Ok(peers) => peers,
        Err(_) => {
            let payload = ClusterMembershipUpdatePayload {
                status: "rejected".to_string(),
                reason: MEMBERSHIP_UPDATE_REASON_INVALID_PAYLOAD.to_string(),
                auth_reason: None,
                mode: auth.mode.as_str().to_string(),
                updated: false,
                cluster_id: topology.cluster_id,
                local_node_id: topology.node_id,
                cluster_peers: topology.cluster_peers,
                membership_view_id: topology.membership_view_id,
                placement_epoch: topology.placement_epoch,
                membership_last_update_unix_ms: topology.membership_status.last_update_unix_ms,
            };
            return membership_update_response(&state, StatusCode::BAD_REQUEST, payload);
        }
    };
    if !request.cluster_peers.is_empty() && normalized_cluster_peers.is_empty() {
        let payload = ClusterMembershipUpdatePayload {
            status: "rejected".to_string(),
            reason: MEMBERSHIP_UPDATE_REASON_INVALID_PAYLOAD.to_string(),
            auth_reason: None,
            mode: auth.mode.as_str().to_string(),
            updated: false,
            cluster_id: topology.cluster_id,
            local_node_id: topology.node_id,
            cluster_peers: topology.cluster_peers,
            membership_view_id: topology.membership_view_id,
            placement_epoch: topology.placement_epoch,
            membership_last_update_unix_ms: topology.membership_status.last_update_unix_ms,
        };
        return membership_update_response(&state, StatusCode::BAD_REQUEST, payload);
    }

    match state.apply_membership_peers(normalized_cluster_peers).await {
        Ok(outcome) => {
            let updated_topology = runtime_topology_snapshot(&state);
            if outcome.changed {
                spawn_rebalance_queue_population(&state, &topology, &updated_topology);
                if !is_propagation_request {
                    spawn_membership_update_propagation(
                        state.config.clone(),
                        &topology,
                        &updated_topology,
                        state.config.cluster_auth_token(),
                    );
                }
            }
            let payload = ClusterMembershipUpdatePayload {
                status: "applied".to_string(),
                reason: MEMBERSHIP_UPDATE_REASON_APPLIED.to_string(),
                auth_reason: None,
                mode: auth.mode.as_str().to_string(),
                updated: outcome.changed,
                cluster_id: updated_topology.cluster_id,
                local_node_id: updated_topology.node_id,
                cluster_peers: updated_topology.cluster_peers,
                membership_view_id: outcome.membership_view_id,
                placement_epoch: outcome.placement_epoch,
                membership_last_update_unix_ms: outcome.membership_last_update_unix_ms,
            };
            membership_update_response(&state, StatusCode::OK, payload)
        }
        Err(_) => {
            let payload = ClusterMembershipUpdatePayload {
                status: "misconfigured".to_string(),
                reason: MEMBERSHIP_UPDATE_REASON_STATE_PERSIST_FAILED.to_string(),
                auth_reason: None,
                mode: auth.mode.as_str().to_string(),
                updated: false,
                cluster_id: topology.cluster_id,
                local_node_id: topology.node_id,
                cluster_peers: topology.cluster_peers,
                membership_view_id: topology.membership_view_id,
                placement_epoch: topology.placement_epoch,
                membership_last_update_unix_ms: topology.membership_status.last_update_unix_ms,
            };
            membership_update_response(&state, StatusCode::SERVICE_UNAVAILABLE, payload)
        }
    }
}
