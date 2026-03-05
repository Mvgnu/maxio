use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, Method, StatusCode},
    response::IntoResponse,
};
use chrono::Utc;
use quick_xml::de::from_str;
use quick_xml::se::to_string as to_xml_string;
use std::collections::HashMap;

use crate::api::console::{response, storage};
use crate::metadata::{
    BucketLifecycleConfigurationOperation, BucketMetadataOperation,
    ClusterBucketMetadataMutationPreconditionFailureDisposition,
    ClusterBucketMetadataMutationPreconditionGap, ClusterBucketMetadataResponderState,
    cluster_bucket_metadata_mutation_precondition_failure_disposition,
    cluster_bucket_metadata_mutation_precondition_gap_is_no_responder_values,
    cluster_bucket_metadata_mutation_precondition_gap_is_strategy_unready,
};
use crate::server::{AppState, runtime_topology_snapshot};
use crate::storage::{StorageError, lifecycle::LifecycleRule};
use crate::xml::types::{LifecycleConfiguration, LifecycleExpiration, LifecycleFilter};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct LifecycleRuleDto {
    id: String,
    prefix: String,
    expiration_days: u32,
    enabled: bool,
}

impl From<LifecycleRule> for LifecycleRuleDto {
    fn from(rule: LifecycleRule) -> Self {
        Self {
            id: rule.id,
            prefix: rule.prefix,
            expiration_days: rule.expiration_days,
            enabled: rule.enabled,
        }
    }
}

impl From<LifecycleRuleDto> for LifecycleRule {
    fn from(rule: LifecycleRuleDto) -> Self {
        Self {
            id: rule.id,
            prefix: rule.prefix,
            expiration_days: rule.expiration_days,
            enabled: rule.enabled,
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SetLifecycleRequest {
    rules: Vec<LifecycleRuleDto>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct GetLifecycleResponse {
    rules: Vec<LifecycleRuleDto>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename = "Error")]
struct PeerErrorResponse {
    #[serde(rename = "Code")]
    code: Option<String>,
}

struct ClusterBucketLifecycleFanIn {
    responded_nodes: Vec<String>,
    lifecycle_states: Vec<ClusterBucketMetadataResponderState<BucketLifecycleResponderValue>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BucketLifecycleResponderValue {
    NoLifecycleConfiguration,
    Rules(Vec<LifecycleRule>),
}

pub(super) async fn get_lifecycle(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let topology = runtime_topology_snapshot(&state);
    let internal_local_only =
        storage::is_trusted_internal_local_metadata_scope_request(&state, &headers, &params);
    let use_consensus_bucket_metadata = storage::should_use_consensus_index_bucket_metadata_state(
        &state,
        &topology,
        internal_local_only,
    );

    let rules = if storage::should_attempt_cluster_bucket_metadata_fan_in(
        &state,
        &topology,
        internal_local_only,
    ) {
        let fan_in = match fetch_cluster_bucket_lifecycle_fan_in(&state, &topology, &bucket).await {
            Ok(fan_in) => fan_in,
            Err(err) => return storage::map_bucket_storage_err(err),
        };
        if let Some(err) = storage::reject_unready_bucket_metadata_operation_for_responders(
            &state,
            "GetBucketLifecycle",
            fan_in.responded_nodes.as_slice(),
        ) {
            return err;
        }
        match resolve_cluster_bucket_lifecycle_state(
            &state,
            &topology,
            "GetBucketLifecycle",
            &bucket,
            fan_in.responded_nodes.as_slice(),
            fan_in.lifecycle_states.as_slice(),
        ) {
            Ok(rules) => rules,
            Err(err) => return response::error(StatusCode::SERVICE_UNAVAILABLE, err),
        }
    } else {
        if !internal_local_only && !use_consensus_bucket_metadata {
            if let Some(err) =
                storage::reject_unready_bucket_metadata_operation(&state, "GetBucketLifecycle")
            {
                return err;
            }
        }
        if use_consensus_bucket_metadata {
            let bucket_state = match storage::consensus_bucket_metadata_state_for_bucket(
                &state,
                &topology,
                &bucket,
                "GetBucketLifecycle",
            ) {
                Ok(row) => row,
                Err(err) => return *err,
            };
            if !bucket_state.lifecycle_enabled {
                Vec::new()
            } else {
                let persisted_xml =
                    match storage::consensus_bucket_lifecycle_configuration_xml_for_bucket(
                        &state,
                        &topology,
                        &bucket,
                        "GetBucketLifecycle",
                    ) {
                        Ok(Some(xml)) => xml,
                        Ok(None) => {
                            return response::error(
                                StatusCode::SERVICE_UNAVAILABLE,
                                format!(
                                    "Distributed bucket metadata operation 'GetBucketLifecycle' cannot query consensus metadata state: missing persisted lifecycle configuration for '{}'",
                                    bucket
                                ),
                            );
                        }
                        Err(err) => return *err,
                    };
                match parse_lifecycle_rules_from_xml(persisted_xml.as_str()) {
                    Ok(rules) => canonicalize_lifecycle_rules(rules),
                    Err(err) => {
                        return response::error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            format!(
                                "Distributed bucket metadata operation 'GetBucketLifecycle' cannot decode persisted lifecycle state for '{}': {}",
                                bucket, err
                            ),
                        );
                    }
                }
            }
        } else {
            match state.storage.get_lifecycle_rules(&bucket).await {
                Ok(rules) => rules,
                Err(err) => return storage::map_bucket_storage_err(err),
            }
        }
    };

    response::json(
        StatusCode::OK,
        GetLifecycleResponse {
            rules: rules.into_iter().map(LifecycleRuleDto::from).collect(),
        },
    )
}

pub(super) async fn set_lifecycle(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    Json(body): Json<SetLifecycleRequest>,
) -> impl IntoResponse {
    let rules: Vec<LifecycleRule> = body.rules.into_iter().map(LifecycleRule::from).collect();
    let topology = runtime_topology_snapshot(&state);
    let internal_local_only =
        storage::is_trusted_internal_local_metadata_scope_request(&state, &headers, &params);
    let should_fan_in = storage::should_attempt_cluster_bucket_metadata_fan_in(
        &state,
        &topology,
        internal_local_only,
    );
    let use_consensus_bucket_metadata = storage::should_use_consensus_index_bucket_metadata_state(
        &state,
        &topology,
        internal_local_only,
    );
    if !internal_local_only && !should_fan_in && !use_consensus_bucket_metadata {
        if let Some(err) =
            storage::reject_unready_bucket_metadata_operation(&state, "SetBucketLifecycle")
        {
            return err;
        }
    }
    if let Err(resp) = storage::ensure_bucket_exists(&state, &bucket).await {
        return resp;
    }

    if let Err(err) = state.storage.set_lifecycle_rules(&bucket, &rules).await {
        return match err {
            StorageError::NotFound(_) => storage::bucket_not_found(),
            StorageError::InvalidKey(msg) => response::error(StatusCode::BAD_REQUEST, msg),
            other => storage::internal_err(other),
        };
    }

    if let Err(err) = storage::persist_bucket_metadata_operation(
        &state,
        &topology,
        "SetBucketLifecycle",
        &BucketMetadataOperation::SetLifecycle {
            bucket: bucket.clone(),
            enabled: !rules.is_empty(),
        },
    ) {
        return *err;
    }
    let lifecycle_persist_operation = if rules.is_empty() {
        BucketLifecycleConfigurationOperation::DeleteConfiguration {
            bucket: bucket.clone(),
        }
    } else {
        let lifecycle_xml = match lifecycle_rules_to_xml(rules.as_slice()) {
            Ok(xml) => xml,
            Err(err) => return response::error(StatusCode::BAD_REQUEST, err),
        };
        BucketLifecycleConfigurationOperation::UpsertConfiguration {
            bucket: bucket.clone(),
            configuration_xml: lifecycle_xml,
            updated_at_unix_ms: u64::try_from(Utc::now().timestamp_millis()).map_or(0, |v| v),
        }
    };
    if let Err(err) = storage::persist_bucket_lifecycle_configuration_operation(
        &state,
        &topology,
        "SetBucketLifecycle",
        &lifecycle_persist_operation,
    ) {
        return *err;
    }

    if should_fan_in {
        let responder_nodes =
            match fan_out_bucket_lifecycle_mutation_to_peers(&state, &topology, &bucket, &rules)
                .await
            {
                Ok(nodes) => nodes,
                Err(err) => return response::error(StatusCode::SERVICE_UNAVAILABLE, err),
            };
        if let Some(err) = storage::reject_unready_bucket_metadata_operation_for_responders(
            &state,
            "SetBucketLifecycle",
            responder_nodes.as_slice(),
        ) {
            return err;
        }
        let fan_in = match fetch_cluster_bucket_lifecycle_fan_in(&state, &topology, &bucket).await {
            Ok(fan_in) => fan_in,
            Err(err) => return storage::map_bucket_storage_err(err),
        };
        if let Some(err) = storage::reject_unready_bucket_metadata_operation_for_responders(
            &state,
            "SetBucketLifecycle",
            fan_in.responded_nodes.as_slice(),
        ) {
            return err;
        }
        let converged = match resolve_cluster_bucket_lifecycle_state(
            &state,
            &topology,
            "SetBucketLifecycle",
            &bucket,
            fan_in.responded_nodes.as_slice(),
            fan_in.lifecycle_states.as_slice(),
        ) {
            Ok(rules) => rules,
            Err(err) => return response::error(StatusCode::SERVICE_UNAVAILABLE, err),
        };
        let expected = canonicalize_lifecycle_rules(rules);
        if canonicalize_lifecycle_rules(converged) != expected {
            return response::error(
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "Distributed bucket lifecycle mutation did not converge for '{}'",
                    bucket
                ),
            );
        }
    }

    response::ok()
}

fn lifecycle_rules_to_xml(rules: &[LifecycleRule]) -> Result<String, String> {
    let rules = rules
        .iter()
        .map(|rule| crate::xml::types::LifecycleRule {
            id: Some(rule.id.clone()),
            status: if rule.enabled {
                "Enabled".to_string()
            } else {
                "Disabled".to_string()
            },
            filter: Some(LifecycleFilter {
                prefix: Some(rule.prefix.clone()),
            }),
            prefix: None,
            expiration: LifecycleExpiration {
                days: rule.expiration_days,
            },
        })
        .collect::<Vec<_>>();
    to_xml_string(&LifecycleConfiguration { rules }).map_err(|err| err.to_string())
}

async fn fan_out_bucket_lifecycle_mutation_to_peers(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    bucket: &str,
    rules: &[LifecycleRule],
) -> Result<Vec<String>, String> {
    let path = format!("/{}", bucket);
    let query = [
        ("lifecycle", ""),
        (
            storage::INTERNAL_METADATA_SCOPE_QUERY_PARAM,
            storage::INTERNAL_METADATA_SCOPE_LOCAL_ONLY,
        ),
    ];
    let is_delete = rules.is_empty();
    let method = if is_delete {
        Method::DELETE
    } else {
        Method::PUT
    };
    let body = if is_delete {
        None
    } else {
        Some(lifecycle_rules_to_xml(rules)?.into_bytes())
    };
    let mut responded_nodes = vec![topology.node_id.clone()];

    for peer in &topology.cluster_peers {
        let response = storage::send_internal_peer_request(
            state,
            peer,
            method.clone(),
            path.as_str(),
            &query,
            body.clone(),
        )
        .await
        .map_err(|err| {
            format!(
                "Distributed bucket metadata mutation 'SetBucketLifecycle' failed while contacting responder node '{}': {}",
                peer, err
            )
        })?;
        let status = response.status();
        if status.is_success() {
            responded_nodes.push(peer.clone());
            continue;
        }
        let body = response.text().await.map_err(|err| {
            format!(
                "Distributed bucket metadata mutation 'SetBucketLifecycle' failed while reading responder error payload from node '{}': {}",
                peer, err
            )
        })?;
        if status == StatusCode::NOT_FOUND
            && parse_peer_error_code(body.as_str()).as_deref() == Some("NoSuchBucket")
        {
            return Err(format!(
                "Distributed bucket metadata mutation 'SetBucketLifecycle' failed because bucket '{}' is missing on responder node '{}'",
                bucket, peer
            ));
        }
        return Err(format!(
            "Distributed bucket metadata mutation 'SetBucketLifecycle' failed on responder node '{}' with status {}",
            peer,
            status.as_u16()
        ));
    }

    Ok(responded_nodes)
}

async fn fetch_cluster_bucket_lifecycle_fan_in(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    bucket: &str,
) -> Result<ClusterBucketLifecycleFanIn, StorageError> {
    let local_rules = state.storage.get_lifecycle_rules(bucket).await?;
    let local_state = if local_rules.is_empty() {
        ClusterBucketMetadataResponderState::Present(
            BucketLifecycleResponderValue::NoLifecycleConfiguration,
        )
    } else {
        ClusterBucketMetadataResponderState::Present(BucketLifecycleResponderValue::Rules(
            canonicalize_lifecycle_rules(local_rules),
        ))
    };

    let mut responded_nodes = vec![topology.node_id.clone()];
    let mut lifecycle_states = vec![local_state];
    for peer in &topology.cluster_peers {
        match fetch_peer_bucket_lifecycle_state(state, peer, bucket).await {
            Ok(peer_state) => {
                responded_nodes.push(peer.clone());
                lifecycle_states.push(peer_state);
            }
            Err(err) => {
                tracing::warn!(
                    peer = %peer,
                    bucket,
                    error = %err,
                    "Console bucket lifecycle fan-in peer request failed"
                );
            }
        }
    }

    Ok(ClusterBucketLifecycleFanIn {
        responded_nodes,
        lifecycle_states,
    })
}

async fn fetch_peer_bucket_lifecycle_state(
    state: &AppState,
    peer: &str,
    bucket: &str,
) -> Result<ClusterBucketMetadataResponderState<BucketLifecycleResponderValue>, String> {
    let path = format!("/{}", bucket);
    let response = storage::send_internal_peer_get(
        state,
        peer,
        path.as_str(),
        &[
            ("lifecycle", ""),
            (
                storage::INTERNAL_METADATA_SCOPE_QUERY_PARAM,
                storage::INTERNAL_METADATA_SCOPE_LOCAL_ONLY,
            ),
        ],
    )
    .await?;
    let status = response.status();
    let body = response.text().await.map_err(|err| err.to_string())?;

    if status.is_success() {
        let rules = parse_lifecycle_rules_from_xml(body.as_str())?;
        if rules.is_empty() {
            return Ok(ClusterBucketMetadataResponderState::Present(
                BucketLifecycleResponderValue::NoLifecycleConfiguration,
            ));
        }
        return Ok(ClusterBucketMetadataResponderState::Present(
            BucketLifecycleResponderValue::Rules(canonicalize_lifecycle_rules(rules)),
        ));
    }
    if status == StatusCode::NOT_FOUND {
        let code = parse_peer_error_code(body.as_str());
        return match code.as_deref() {
            Some("NoSuchLifecycleConfiguration") => {
                Ok(ClusterBucketMetadataResponderState::Present(
                    BucketLifecycleResponderValue::NoLifecycleConfiguration,
                ))
            }
            Some("NoSuchBucket") => Ok(ClusterBucketMetadataResponderState::MissingBucket),
            _ => Err(format!("peer bucket lifecycle status {}", status.as_u16())),
        };
    }

    Err(format!("peer bucket lifecycle status {}", status.as_u16()))
}

fn resolve_cluster_bucket_lifecycle_state(
    state: &AppState,
    topology: &crate::server::RuntimeTopologySnapshot,
    operation: &str,
    bucket: &str,
    responded_nodes: &[String],
    states: &[ClusterBucketMetadataResponderState<BucketLifecycleResponderValue>],
) -> Result<Vec<LifecycleRule>, String> {
    let assessment = storage::assess_bucket_metadata_operation_preconditions(
        state,
        topology,
        operation,
        responded_nodes,
        states,
    )?;
    ensure_cluster_bucket_metadata_operation_ready(operation, assessment.gap)?;
    if assessment
        .gap
        .is_some_and(cluster_bucket_metadata_mutation_precondition_gap_is_no_responder_values)
    {
        return Err(
            "Distributed bucket metadata fan-in did not include any lifecycle responders"
                .to_string(),
        );
    }

    match cluster_bucket_metadata_mutation_precondition_failure_disposition(assessment.gap) {
        Some(ClusterBucketMetadataMutationPreconditionFailureDisposition::NoSuchBucket) => Err(
            format!(
                "Distributed bucket metadata is inconsistent for '{}' (bucket missing on one or more responder nodes)",
                bucket
            ),
        ),
        Some(ClusterBucketMetadataMutationPreconditionFailureDisposition::ServiceUnavailable) => {
            if assessment.gap
                == Some(ClusterBucketMetadataMutationPreconditionGap::InconsistentResponderValues)
            {
                Err(format!(
                    "Distributed bucket lifecycle state is inconsistent across responder nodes for '{}'",
                    bucket
                ))
            } else {
                let gap_reason = assessment.gap.map(|gap| gap.as_str()).unwrap_or("unknown-gap");
                Err(format!(
                    "Distributed bucket metadata fan-in for '{}' is not ready ({})",
                    operation, gap_reason
                ))
            }
        }
        None => match assessment.current_value {
            Some(BucketLifecycleResponderValue::NoLifecycleConfiguration) => Ok(Vec::new()),
            Some(BucketLifecycleResponderValue::Rules(rules)) => Ok(rules),
            None => Err(
                "Distributed bucket metadata fan-in did not include any lifecycle responders"
                    .to_string(),
            ),
        },
    }
}

fn ensure_cluster_bucket_metadata_operation_ready(
    operation: &str,
    gap: Option<ClusterBucketMetadataMutationPreconditionGap>,
) -> Result<(), String> {
    match gap
        .filter(|gap| cluster_bucket_metadata_mutation_precondition_gap_is_strategy_unready(*gap))
    {
        Some(gap) => Err(format!(
            "Distributed metadata strategy is not ready for bucket metadata operation '{}' ({})",
            operation,
            gap.as_str()
        )),
        None => Ok(()),
    }
}

fn parse_lifecycle_rules_from_xml(xml: &str) -> Result<Vec<LifecycleRule>, String> {
    let parsed = from_str::<LifecycleConfiguration>(xml).map_err(|err| err.to_string())?;
    parsed
        .rules
        .into_iter()
        .enumerate()
        .map(|(idx, rule)| {
            let enabled = match rule.status.as_str() {
                "Enabled" => true,
                "Disabled" => false,
                _ => {
                    return Err(format!(
                        "peer lifecycle rule {} has invalid status '{}'",
                        idx, rule.status
                    ));
                }
            };
            let id = match rule.id {
                Some(id) if !id.trim().is_empty() => id,
                Some(_) => {
                    return Err(format!("peer lifecycle rule {} has empty id", idx));
                }
                None => format!("rule-{}", idx + 1),
            };
            let prefix = rule
                .filter
                .and_then(|filter| filter.prefix)
                .or(rule.prefix)
                .unwrap_or_default();

            Ok(LifecycleRule {
                id,
                prefix,
                expiration_days: rule.expiration.days,
                enabled,
            })
        })
        .collect()
}

fn canonicalize_lifecycle_rules(mut rules: Vec<LifecycleRule>) -> Vec<LifecycleRule> {
    rules.sort_by(|a, b| {
        (
            a.id.as_str(),
            a.prefix.as_str(),
            a.expiration_days,
            a.enabled,
        )
            .cmp(&(
                b.id.as_str(),
                b.prefix.as_str(),
                b.expiration_days,
                b.enabled,
            ))
    });
    rules
}

fn parse_peer_error_code(xml: &str) -> Option<String> {
    from_str::<PeerErrorResponse>(xml).ok()?.code
}
