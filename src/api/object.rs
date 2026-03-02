mod parsing;
mod service;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::Response,
};
use std::collections::HashMap;
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;

use crate::auth::signature_v4::{PresignRequest, generate_presigned_url};
use crate::error::S3Error;
use crate::server::AppState;
use crate::storage::placement::{
    ForwardedWriteEnvelope, ForwardedWriteOperation, ObjectWriteQuorumOutcome, PlacementViewState,
    ReadRepairAction, ReadRepairExecutionPolicy, ReplicaObservation, WriteAckObservation,
    object_read_repair_execution_plan_with_policy, object_write_plan_with_self,
    object_write_quorum_outcome,
};
use crate::storage::{ChecksumAlgorithm, ObjectMeta};
use crate::xml::{response::to_xml, types::CopyObjectResult};
use parsing::{
    MetadataDirective, parse_copy_source, parse_delete_objects_request, parse_metadata_directive,
    parse_range,
};
use service::{
    DeleteObjectsOutcome, bucket_path_and_query, build_delete_objects_response_xml,
    copy_object_response, delete_objects_xml_response, forward_replica_delete_to_target,
    forward_replica_head_to_target, internal_replica_version_id,
    is_internal_replica_delete_request, is_internal_replica_put_request, map_delete_objects_err,
    map_delete_storage_err, map_object_get_err, map_object_put_err, map_object_version_delete_err,
    map_object_version_get_err, no_content_delete_response, object_response, put_object_response,
};

use super::multipart;
use service::ensure_bucket_exists;
pub(crate) use service::{body_to_reader, extract_checksum};
pub(crate) use service::{
    ensure_local_write_owner, forward_replica_put_to_target, forward_write_to_target,
    object_path_and_query, object_write_routing_hint, write_forward_target,
    write_replica_count_for_membership_count,
};

pub async fn put_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    let internal_replica_put = is_internal_replica_put_request(&headers);

    if !internal_replica_put && headers.contains_key("x-amz-copy-source") {
        return copy_object(State(state), Path((bucket, key)), Query(params), headers).await;
    }

    if params.contains_key("uploadId") {
        return multipart::upload_part(
            State(state),
            Path((bucket, key)),
            Query(params),
            headers,
            body,
        )
        .await;
    }

    let routing_hint =
        object_write_routing_hint(&key, state.node_id.as_ref(), state.cluster_peers.as_slice());
    let placement = PlacementViewState::from_membership(
        state.placement_epoch(),
        state.node_id.as_ref(),
        state.cluster_peers.as_slice(),
    );
    if let Some(forward) = write_forward_target(
        &bucket,
        &key,
        ForwardedWriteOperation::PutObject,
        &routing_hint,
        &headers,
        state.node_id.as_ref(),
        &placement,
    )? {
        let path_and_query = object_path_and_query(&bucket, &key, &params);
        let body_bytes = axum::body::to_bytes(body, usize::MAX)
            .await
            .map_err(S3Error::internal)?
            .to_vec();
        return forward_write_to_target(
            Method::PUT,
            &forward.target,
            &path_and_query,
            &headers,
            body_bytes,
            &forward.envelope,
        )
        .await;
    }
    if !internal_replica_put {
        ensure_local_write_owner(&routing_hint)?;
    }

    ensure_bucket_exists(&state, &bucket).await?;

    let raw_body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(S3Error::internal)?
        .to_vec();

    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");

    let mut reader = body_to_reader(&headers, Body::from(raw_body_bytes.clone())).await?;

    // If Content-MD5 is provided, buffer the body and verify before writing
    let content_md5 = headers
        .get("content-md5")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    if let Some(ref expected_md5) = content_md5 {
        use md5::Digest;
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .await
            .map_err(S3Error::internal)?;
        let computed_hash = md5::Md5::digest(&buf);
        use base64::Engine;
        let computed_md5 = base64::engine::general_purpose::STANDARD.encode(computed_hash);
        if computed_md5 != *expected_md5 {
            return Err(S3Error::bad_digest());
        }
        reader = Box::pin(std::io::Cursor::new(buf));
    }

    let checksum = extract_checksum(&headers);
    let replica_version_id = internal_replica_version_id(&headers);
    let result = state
        .storage
        .put_object_with_version_id(
            &bucket,
            &key,
            content_type,
            reader,
            checksum,
            replica_version_id.as_deref(),
        )
        .await
        .map_err(|e| map_object_put_err(&bucket, e))?;

    let quorum_outcome =
        if routing_hint.distributed && routing_hint.is_local_primary_owner && !internal_replica_put
        {
            Some(
                replicate_put_to_replica_owners(ReplicaPutRequest {
                    state: &state,
                    bucket: &bucket,
                    key: &key,
                    params: &params,
                    headers: &headers,
                    raw_body_bytes: &raw_body_bytes,
                    version_id: result.version_id.as_deref(),
                    placement: &placement,
                })
                .await,
            )
        } else {
            None
        };

    let mut response = put_object_response(&result, &routing_hint)?;
    if let Some(outcome) = quorum_outcome {
        add_write_quorum_headers(response.headers_mut(), &outcome);
    }
    Ok(response)
}

const WRITE_ACK_COUNT_HEADER: &str = "x-maxio-write-ack-count";
const WRITE_QUORUM_SIZE_HEADER: &str = "x-maxio-write-quorum-size";
const WRITE_QUORUM_REACHED_HEADER: &str = "x-maxio-write-quorum-reached";

struct ReplicaPutRequest<'a> {
    state: &'a AppState,
    bucket: &'a str,
    key: &'a str,
    params: &'a HashMap<String, String>,
    headers: &'a HeaderMap,
    raw_body_bytes: &'a [u8],
    version_id: Option<&'a str>,
    placement: &'a PlacementViewState,
}

async fn replicate_put_to_replica_owners(
    request: ReplicaPutRequest<'_>,
) -> ObjectWriteQuorumOutcome {
    let replica_count = write_replica_count_for_membership_count(request.placement.members.len());
    let write_plan = object_write_plan_with_self(
        request.key,
        request.state.node_id.as_ref(),
        request.state.cluster_peers.as_slice(),
        replica_count,
    );
    let mut observations = vec![WriteAckObservation {
        node: request.state.node_id.to_string(),
        acked: true,
    }];
    let path_and_query = object_path_and_query(request.bucket, request.key, request.params);
    let mut envelope = ForwardedWriteEnvelope::new(
        ForwardedWriteOperation::ReplicatePutObject,
        request.bucket,
        request.key,
        request.state.node_id.as_ref(),
        request.state.node_id.as_ref(),
        &uuid::Uuid::new_v4().to_string(),
        request.placement,
    );
    envelope.visited_nodes = vec![request.state.node_id.to_string()];
    envelope.hop_count = 1;

    for target in write_plan
        .owners
        .iter()
        .filter(|owner| owner.as_str() != request.state.node_id.as_ref())
    {
        let acked = match forward_replica_put_to_target(
            target,
            &path_and_query,
            request.headers,
            request.raw_body_bytes.to_vec(),
            request.version_id,
            &envelope,
        )
        .await
        {
            Ok(response) => {
                let success = response.status().is_success();
                if !success {
                    tracing::warn!(
                        operation = "replicate-put-object",
                        target_node = %target,
                        bucket = %request.bucket,
                        key = %request.key,
                        status = %response.status(),
                        "Replica fanout response was not successful"
                    );
                }
                success
            }
            Err(err) => {
                tracing::warn!(
                    operation = "replicate-put-object",
                    target_node = %target,
                    bucket = %request.bucket,
                    key = %request.key,
                    error = ?err,
                    "Replica fanout request failed"
                );
                false
            }
        };
        observations.push(WriteAckObservation {
            node: target.clone(),
            acked,
        });
    }

    object_write_quorum_outcome(&write_plan, &observations)
}

pub(crate) fn add_write_quorum_headers(
    headers: &mut HeaderMap,
    outcome: &ObjectWriteQuorumOutcome,
) {
    add_write_quorum_header_values(
        headers,
        outcome.ack_count,
        outcome.quorum_size,
        outcome.quorum_reached,
    );
}

fn add_write_quorum_header_values(
    headers: &mut HeaderMap,
    ack_count: usize,
    quorum_size: usize,
    quorum_reached: bool,
) {
    if let Ok(value) = HeaderValue::from_str(&ack_count.to_string()) {
        headers.insert(
            header::HeaderName::from_static(WRITE_ACK_COUNT_HEADER),
            value,
        );
    }
    if let Ok(value) = HeaderValue::from_str(&quorum_size.to_string()) {
        headers.insert(
            header::HeaderName::from_static(WRITE_QUORUM_SIZE_HEADER),
            value,
        );
    }
    headers.insert(
        header::HeaderName::from_static(WRITE_QUORUM_REACHED_HEADER),
        if quorum_reached {
            HeaderValue::from_static("true")
        } else {
            HeaderValue::from_static("false")
        },
    );
}

#[derive(Debug, Clone)]
struct BatchWriteQuorumAggregate {
    observed: bool,
    ack_count: usize,
    quorum_size: usize,
    quorum_reached: bool,
}

impl BatchWriteQuorumAggregate {
    fn new() -> Self {
        Self {
            observed: false,
            ack_count: 0,
            quorum_size: 0,
            quorum_reached: true,
        }
    }

    fn record(&mut self, ack_count: usize, quorum_size: usize, quorum_reached: bool) {
        self.observed = true;
        self.ack_count += ack_count;
        self.quorum_size += quorum_size;
        self.quorum_reached &= quorum_reached;
    }

    fn record_outcome(&mut self, outcome: &ObjectWriteQuorumOutcome) {
        self.record(
            outcome.ack_count,
            outcome.quorum_size,
            outcome.quorum_reached,
        );
    }

    fn record_headers(&mut self, headers: &HeaderMap) {
        if let Some((ack_count, quorum_size, quorum_reached)) = parse_write_quorum_headers(headers)
        {
            self.record(ack_count, quorum_size, quorum_reached);
        }
    }
}

fn parse_write_quorum_headers(headers: &HeaderMap) -> Option<(usize, usize, bool)> {
    let ack_count = parse_header_usize(headers, WRITE_ACK_COUNT_HEADER)?;
    let quorum_size = parse_header_usize(headers, WRITE_QUORUM_SIZE_HEADER)?;
    let quorum_reached = parse_header_bool(headers, WRITE_QUORUM_REACHED_HEADER)?;
    Some((ack_count, quorum_size, quorum_reached))
}

fn parse_header_usize(headers: &HeaderMap, name: &str) -> Option<usize> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<usize>().ok())
}

fn parse_header_bool(headers: &HeaderMap, name: &str) -> Option<bool> {
    let value = headers.get(name)?.to_str().ok()?.trim();
    if value.eq_ignore_ascii_case("true") {
        Some(true)
    } else if value.eq_ignore_ascii_case("false") {
        Some(false)
    } else {
        None
    }
}

fn parse_header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn checksum_algorithm_header_value(algorithm: ChecksumAlgorithm) -> &'static str {
    match algorithm {
        ChecksumAlgorithm::CRC32 => "CRC32",
        ChecksumAlgorithm::CRC32C => "CRC32C",
        ChecksumAlgorithm::SHA1 => "SHA1",
        ChecksumAlgorithm::SHA256 => "SHA256",
    }
}

fn replica_delete_headers(request_headers: &HeaderMap) -> HeaderMap {
    let mut headers = request_headers.clone();
    headers.remove(header::AUTHORIZATION);
    headers
}

fn presigned_replica_path_and_query(
    state: &AppState,
    method: &'static str,
    signed_host: &str,
    bucket: &str,
    key: &str,
) -> Option<String> {
    let url = generate_presigned_url(PresignRequest {
        method,
        scheme: "http",
        host: signed_host,
        path: &format!("/{bucket}/{key}"),
        access_key: state.config.access_key.as_str(),
        secret_key: state.config.secret_key.as_str(),
        region: state.config.region.as_str(),
        now: chrono::Utc::now(),
        expires_secs: 60,
    })
    .ok()?;
    let parsed = reqwest::Url::parse(&url).ok()?;
    let mut path = parsed.path().to_string();
    if let Some(query) = parsed.query() {
        path.push('?');
        path.push_str(query);
    }
    Some(path)
}

fn presigned_replica_delete_path_and_query(
    state: &AppState,
    signed_host: &str,
    bucket: &str,
    key: &str,
) -> Option<String> {
    presigned_replica_path_and_query(state, "DELETE", signed_host, bucket, key)
}

fn presigned_replica_put_path_and_query(
    state: &AppState,
    signed_host: &str,
    bucket: &str,
    key: &str,
) -> Option<String> {
    presigned_replica_path_and_query(state, "PUT", signed_host, bucket, key)
}

fn presigned_replica_head_path_and_query(
    state: &AppState,
    signed_host: &str,
    bucket: &str,
    key: &str,
) -> Option<String> {
    presigned_replica_path_and_query(state, "HEAD", signed_host, bucket, key)
}

fn replica_put_headers_for_copy(
    request_headers: &HeaderMap,
    content_type: &str,
    checksum_algorithm: Option<ChecksumAlgorithm>,
) -> HeaderMap {
    let mut headers = request_headers.clone();
    let content_type = HeaderValue::from_str(content_type)
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
    headers.insert(header::CONTENT_TYPE, content_type);
    if let Some(algorithm) = checksum_algorithm {
        headers.insert(
            header::HeaderName::from_static("x-amz-checksum-algorithm"),
            HeaderValue::from_static(checksum_algorithm_header_value(algorithm)),
        );
    }
    headers
}

fn replica_put_headers_for_read_repair(
    request_headers: &HeaderMap,
    meta: &ObjectMeta,
) -> HeaderMap {
    let mut headers =
        replica_put_headers_for_copy(request_headers, &meta.content_type, meta.checksum_algorithm);
    headers.remove(header::AUTHORIZATION);
    if let (Some(algorithm), Some(value)) = (meta.checksum_algorithm, meta.checksum_value.as_ref())
    {
        if let Ok(header_value) = HeaderValue::from_str(value) {
            headers.insert(
                header::HeaderName::from_static(algorithm.header_name()),
                header_value,
            );
        }
    }
    headers
}

async fn replicate_delete_to_replica_owners(
    state: &AppState,
    bucket: &str,
    key: &str,
    params: &HashMap<String, String>,
    headers: &HeaderMap,
    placement: &PlacementViewState,
) -> ObjectWriteQuorumOutcome {
    let replica_count = write_replica_count_for_membership_count(placement.members.len());
    let write_plan = object_write_plan_with_self(
        key,
        state.node_id.as_ref(),
        state.cluster_peers.as_slice(),
        replica_count,
    );
    let mut observations = vec![WriteAckObservation {
        node: state.node_id.to_string(),
        acked: true,
    }];
    let replica_headers = replica_delete_headers(headers);
    let mut envelope = ForwardedWriteEnvelope::new(
        ForwardedWriteOperation::ReplicateDeleteObject,
        bucket,
        key,
        state.node_id.as_ref(),
        state.node_id.as_ref(),
        &uuid::Uuid::new_v4().to_string(),
        placement,
    );
    envelope.visited_nodes = vec![state.node_id.to_string()];
    envelope.hop_count = 1;

    for target in write_plan
        .owners
        .iter()
        .filter(|owner| owner.as_str() != state.node_id.as_ref())
    {
        let path_and_query = if params.is_empty() {
            let signed_host = replica_headers
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .filter(|value| !value.trim().is_empty())
                .unwrap_or(target.as_str());
            let Some(path_and_query) =
                presigned_replica_delete_path_and_query(state, signed_host, bucket, key)
            else {
                observations.push(WriteAckObservation {
                    node: target.clone(),
                    acked: false,
                });
                continue;
            };
            path_and_query
        } else {
            object_path_and_query(bucket, key, params)
        };
        let request_headers = if params.is_empty() {
            &replica_headers
        } else {
            headers
        };
        let acked = match forward_replica_delete_to_target(
            target,
            &path_and_query,
            request_headers,
            &envelope,
        )
        .await
        {
            Ok(response) => {
                let success = response.status().is_success();
                if !success {
                    tracing::warn!(
                        operation = "replicate-delete-object",
                        target_node = %target,
                        bucket = %bucket,
                        key = %key,
                        status = %response.status(),
                        "Replica fanout response was not successful"
                    );
                }
                success
            }
            Err(err) => {
                tracing::warn!(
                    operation = "replicate-delete-object",
                    target_node = %target,
                    bucket = %bucket,
                    key = %key,
                    error = ?err,
                    "Replica fanout request failed"
                );
                false
            }
        };
        observations.push(WriteAckObservation {
            node: target.clone(),
            acked,
        });
    }

    object_write_quorum_outcome(&write_plan, &observations)
}

async fn execute_primary_read_repair(
    state: &AppState,
    bucket: &str,
    key: &str,
    headers: &HeaderMap,
    placement: &PlacementViewState,
    local_meta: &ObjectMeta,
) {
    let replica_count = write_replica_count_for_membership_count(placement.members.len());
    let write_plan = object_write_plan_with_self(
        key,
        state.node_id.as_ref(),
        state.cluster_peers.as_slice(),
        replica_count,
    );
    if !write_plan.is_local_primary_owner || write_plan.owners.len() <= 1 {
        return;
    }

    let mut observations = vec![ReplicaObservation {
        node: state.node_id.to_string(),
        version: local_meta.version_id.clone(),
    }];

    let probe_headers = replica_delete_headers(headers);
    let mut probe_envelope = ForwardedWriteEnvelope::new(
        ForwardedWriteOperation::ReplicateHeadObject,
        bucket,
        key,
        state.node_id.as_ref(),
        state.node_id.as_ref(),
        &uuid::Uuid::new_v4().to_string(),
        placement,
    );
    probe_envelope.visited_nodes = vec![state.node_id.to_string()];
    probe_envelope.hop_count = 1;

    for target in write_plan
        .owners
        .iter()
        .filter(|owner| owner.as_str() != state.node_id.as_ref())
    {
        let signed_host = probe_headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(target.as_str());
        let Some(path_and_query) =
            presigned_replica_head_path_and_query(state, signed_host, bucket, key)
        else {
            observations.push(ReplicaObservation {
                node: target.clone(),
                version: None,
            });
            continue;
        };

        match forward_replica_head_to_target(
            target,
            &path_and_query,
            &probe_headers,
            &probe_envelope,
        )
        .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    observations.push(ReplicaObservation {
                        node: target.clone(),
                        version: parse_header_string(response.headers(), "x-amz-version-id"),
                    });
                } else {
                    if response.status() != StatusCode::NOT_FOUND {
                        tracing::warn!(
                            operation = "read-repair-probe-head",
                            target_node = %target,
                            bucket = %bucket,
                            key = %key,
                            status = %response.status(),
                            "Read-repair probe response was not successful"
                        );
                    }
                    observations.push(ReplicaObservation {
                        node: target.clone(),
                        version: None,
                    });
                }
            }
            Err(err) => {
                tracing::warn!(
                    operation = "read-repair-probe-head",
                    target_node = %target,
                    bucket = %bucket,
                    key = %key,
                    error = ?err,
                    "Read-repair probe request failed"
                );
                observations.push(ReplicaObservation {
                    node: target.clone(),
                    version: None,
                });
            }
        }
    }

    let execution = object_read_repair_execution_plan_with_policy(
        &observations,
        write_plan.owners.len(),
        ReadRepairExecutionPolicy::PrimaryAuthoritative,
    );
    if execution.actions.is_empty() {
        return;
    }
    let local_version = local_meta.version_id.clone();
    if execution.plan.chosen_version != local_version {
        tracing::warn!(
            operation = "read-repair-execute",
            bucket = %bucket,
            key = %key,
            local_version = ?local_version,
            chosen_version = ?execution.plan.chosen_version,
            "Skipping read-repair execution because chosen version is not locally available"
        );
        return;
    }

    let put_headers = replica_put_headers_for_read_repair(headers, local_meta);
    let delete_headers = replica_delete_headers(headers);
    let mut put_envelope = ForwardedWriteEnvelope::new(
        ForwardedWriteOperation::ReplicatePutObject,
        bucket,
        key,
        state.node_id.as_ref(),
        state.node_id.as_ref(),
        &uuid::Uuid::new_v4().to_string(),
        placement,
    );
    put_envelope.visited_nodes = vec![state.node_id.to_string()];
    put_envelope.hop_count = 1;
    let mut delete_envelope = ForwardedWriteEnvelope::new(
        ForwardedWriteOperation::ReplicateDeleteObject,
        bucket,
        key,
        state.node_id.as_ref(),
        state.node_id.as_ref(),
        &uuid::Uuid::new_v4().to_string(),
        placement,
    );
    delete_envelope.visited_nodes = vec![state.node_id.to_string()];
    delete_envelope.hop_count = 1;

    let mut repair_payload = None::<Vec<u8>>;
    for action in execution.actions {
        match action {
            ReadRepairAction::UpsertVersion { node, .. } => {
                if repair_payload.is_none() {
                    let Ok((mut reader, _)) = state.storage.get_object(bucket, key).await else {
                        tracing::warn!(
                            operation = "read-repair-upsert",
                            target_node = %node,
                            bucket = %bucket,
                            key = %key,
                            "Skipping read-repair upsert because local object could not be reloaded"
                        );
                        continue;
                    };
                    let mut body = Vec::new();
                    if reader.read_to_end(&mut body).await.is_err() {
                        tracing::warn!(
                            operation = "read-repair-upsert",
                            target_node = %node,
                            bucket = %bucket,
                            key = %key,
                            "Skipping read-repair upsert because local object payload could not be read"
                        );
                        continue;
                    }
                    repair_payload = Some(body);
                }

                let signed_host = put_headers
                    .get(header::HOST)
                    .and_then(|value| value.to_str().ok())
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or(node.as_str());
                let Some(path_and_query) =
                    presigned_replica_put_path_and_query(state, signed_host, bucket, key)
                else {
                    tracing::warn!(
                        operation = "read-repair-upsert",
                        target_node = %node,
                        bucket = %bucket,
                        key = %key,
                        "Skipping read-repair upsert because internal presign failed"
                    );
                    continue;
                };
                let payload = repair_payload.clone().unwrap_or_default();
                match forward_replica_put_to_target(
                    &node,
                    &path_and_query,
                    &put_headers,
                    payload,
                    local_meta.version_id.as_deref(),
                    &put_envelope,
                )
                .await
                {
                    Ok(response) => {
                        if !response.status().is_success() {
                            tracing::warn!(
                                operation = "read-repair-upsert",
                                target_node = %node,
                                bucket = %bucket,
                                key = %key,
                                status = %response.status(),
                                "Read-repair upsert response was not successful"
                            );
                        }
                    }
                    Err(err) => tracing::warn!(
                        operation = "read-repair-upsert",
                        target_node = %node,
                        bucket = %bucket,
                        key = %key,
                        error = ?err,
                        "Read-repair upsert request failed"
                    ),
                }
            }
            ReadRepairAction::DeleteReplica { node } => {
                let signed_host = delete_headers
                    .get(header::HOST)
                    .and_then(|value| value.to_str().ok())
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or(node.as_str());
                let Some(path_and_query) =
                    presigned_replica_delete_path_and_query(state, signed_host, bucket, key)
                else {
                    tracing::warn!(
                        operation = "read-repair-delete",
                        target_node = %node,
                        bucket = %bucket,
                        key = %key,
                        "Skipping read-repair delete because internal presign failed"
                    );
                    continue;
                };
                match forward_replica_delete_to_target(
                    &node,
                    &path_and_query,
                    &delete_headers,
                    &delete_envelope,
                )
                .await
                {
                    Ok(response) => {
                        if !response.status().is_success()
                            && response.status() != StatusCode::NOT_FOUND
                        {
                            tracing::warn!(
                                operation = "read-repair-delete",
                                target_node = %node,
                                bucket = %bucket,
                                key = %key,
                                status = %response.status(),
                                "Read-repair delete response was not successful"
                            );
                        }
                    }
                    Err(err) => tracing::warn!(
                        operation = "read-repair-delete",
                        target_node = %node,
                        bucket = %bucket,
                        key = %key,
                        error = ?err,
                        "Read-repair delete request failed"
                    ),
                }
            }
        }
    }
}

async fn copy_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response<Body>, S3Error> {
    let routing_hint =
        object_write_routing_hint(&key, state.node_id.as_ref(), state.cluster_peers.as_slice());
    let placement = PlacementViewState::from_membership(
        state.placement_epoch(),
        state.node_id.as_ref(),
        state.cluster_peers.as_slice(),
    );
    if let Some(forward) = write_forward_target(
        &bucket,
        &key,
        ForwardedWriteOperation::CopyObject,
        &routing_hint,
        &headers,
        state.node_id.as_ref(),
        &placement,
    )? {
        let path_and_query = object_path_and_query(&bucket, &key, &params);
        return forward_write_to_target(
            Method::PUT,
            &forward.target,
            &path_and_query,
            &headers,
            Vec::new(),
            &forward.envelope,
        )
        .await;
    }
    let internal_replica_put = is_internal_replica_put_request(&headers);
    ensure_local_write_owner(&routing_hint)?;

    let copy_source = headers
        .get("x-amz-copy-source")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| S3Error::invalid_argument("missing x-amz-copy-source header"))?;

    let copy_source = parse_copy_source(copy_source)?;

    // Validate source and destination bucket existence.
    ensure_bucket_exists(&state, &copy_source.bucket).await?;
    ensure_bucket_exists(&state, &bucket).await?;

    // Get source object
    let (mut reader, src_meta) = if let Some(source_version_id) = copy_source.version_id.as_deref()
    {
        state
            .storage
            .get_object_version(&copy_source.bucket, &copy_source.key, source_version_id)
            .await
            .map_err(|e| map_object_version_get_err(&copy_source.key, source_version_id, e))?
    } else {
        state
            .storage
            .get_object(&copy_source.bucket, &copy_source.key)
            .await
            .map_err(|e| map_object_get_err(&copy_source.key, e))?
    };

    // Determine content-type based on metadata directive.
    let directive = parse_metadata_directive(
        headers
            .get("x-amz-metadata-directive")
            .and_then(|v| v.to_str().ok()),
    )?;

    let content_type = match directive {
        MetadataDirective::Copy => src_meta.content_type.clone(),
        MetadataDirective::Replace => headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string(),
    };

    // Propagate source checksum algorithm so it's recomputed during copy
    let checksum = src_meta.checksum_algorithm.map(|algo| (algo, None));
    let mut source_body = Vec::new();
    reader
        .read_to_end(&mut source_body)
        .await
        .map_err(S3Error::internal)?;
    // Write destination
    let result = state
        .storage
        .put_object(
            &bucket,
            &key,
            &content_type,
            Box::pin(std::io::Cursor::new(source_body.clone())),
            checksum,
        )
        .await
        .map_err(|e| map_object_put_err(&bucket, e))?;

    let quorum_outcome =
        if routing_hint.distributed && routing_hint.is_local_primary_owner && !internal_replica_put
        {
            let replica_headers =
                replica_put_headers_for_copy(&headers, &content_type, result.checksum_algorithm);
            Some(
                replicate_put_to_replica_owners(ReplicaPutRequest {
                    state: &state,
                    bucket: &bucket,
                    key: &key,
                    params: &params,
                    headers: &replica_headers,
                    raw_body_bytes: &source_body,
                    version_id: result.version_id.as_deref(),
                    placement: &placement,
                })
                .await,
            )
        } else {
            None
        };

    // Get destination metadata for LastModified
    let dst_meta = state
        .storage
        .head_object(&bucket, &key)
        .await
        .map_err(S3Error::internal)?;

    let xml = to_xml(&CopyObjectResult {
        etag: result.etag,
        last_modified: dst_meta.last_modified,
    })
    .map_err(S3Error::internal)?;

    let mut response = copy_object_response(
        xml,
        src_meta.version_id.as_deref(),
        result.version_id.as_deref(),
        &routing_hint,
    )?;
    if let Some(outcome) = quorum_outcome {
        add_write_quorum_headers(response.headers_mut(), &outcome);
    }
    Ok(response)
}

pub async fn get_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response<Body>, S3Error> {
    if params.contains_key("uploadId") {
        return multipart::list_parts(State(state), Path((bucket, key)), Query(params), headers)
            .await;
    }

    let routing_hint =
        object_write_routing_hint(&key, state.node_id.as_ref(), state.cluster_peers.as_slice());
    let placement = PlacementViewState::from_membership(
        state.placement_epoch(),
        state.node_id.as_ref(),
        state.cluster_peers.as_slice(),
    );
    if let Some(forward) = write_forward_target(
        &bucket,
        &key,
        ForwardedWriteOperation::PutObject,
        &routing_hint,
        &headers,
        state.node_id.as_ref(),
        &placement,
    )? {
        let path_and_query = object_path_and_query(&bucket, &key, &params);
        return forward_write_to_target(
            Method::GET,
            &forward.target,
            &path_and_query,
            &headers,
            Vec::new(),
            &forward.envelope,
        )
        .await;
    }

    ensure_bucket_exists(&state, &bucket).await?;

    let range_header = headers.get("range").and_then(|v| v.to_str().ok());
    let requested_version_id = params.get("versionId").map(String::as_str);

    if let Some(range_str) = range_header {
        let meta = if let Some(version_id) = requested_version_id {
            state
                .storage
                .head_object_version(&bucket, &key, version_id)
                .await
                .map_err(|e| map_object_version_get_err(&key, version_id, e))?
        } else {
            state
                .storage
                .head_object(&bucket, &key)
                .await
                .map_err(|e| map_object_get_err(&key, e))?
        };

        match parse_range(range_str, meta.size) {
            Ok(Some((start, end))) => {
                let length = end - start + 1;
                let (reader, _) = if let Some(version_id) = requested_version_id {
                    state
                        .storage
                        .get_object_version_range(&bucket, &key, version_id, start, length)
                        .await
                        .map_err(|e| map_object_version_get_err(&key, version_id, e))?
                } else {
                    state
                        .storage
                        .get_object_range(&bucket, &key, start, length)
                        .await
                        .map_err(|e| map_object_get_err(&key, e))?
                };

                let stream = ReaderStream::new(reader);
                let body = Body::from_stream(stream);

                if requested_version_id.is_none()
                    && routing_hint.distributed
                    && routing_hint.is_local_primary_owner
                {
                    execute_primary_read_repair(&state, &bucket, &key, &headers, &placement, &meta)
                        .await;
                }

                return object_response(
                    &meta,
                    StatusCode::PARTIAL_CONTENT,
                    body,
                    length,
                    Some((start, end, meta.size)),
                );
            }
            Ok(None) => {
                // Unparseable or multi-range — fall through to full 200
            }
            Err(()) => {
                return Err(S3Error::invalid_range());
            }
        }
    }

    let (reader, meta) = if let Some(version_id) = params.get("versionId") {
        state
            .storage
            .get_object_version(&bucket, &key, version_id)
            .await
            .map_err(|e| map_object_version_get_err(&key, version_id, e))?
    } else {
        state
            .storage
            .get_object(&bucket, &key)
            .await
            .map_err(|e| map_object_get_err(&key, e))?
    };

    if !params.contains_key("versionId")
        && routing_hint.distributed
        && routing_hint.is_local_primary_owner
    {
        execute_primary_read_repair(&state, &bucket, &key, &headers, &placement, &meta).await;
    }

    let stream = ReaderStream::new(reader);
    let body = Body::from_stream(stream);

    object_response(&meta, StatusCode::OK, body, meta.size, None)
}

pub async fn head_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response<Body>, S3Error> {
    let routing_hint =
        object_write_routing_hint(&key, state.node_id.as_ref(), state.cluster_peers.as_slice());
    let placement = PlacementViewState::from_membership(
        state.placement_epoch(),
        state.node_id.as_ref(),
        state.cluster_peers.as_slice(),
    );
    if let Some(forward) = write_forward_target(
        &bucket,
        &key,
        ForwardedWriteOperation::PutObject,
        &routing_hint,
        &headers,
        state.node_id.as_ref(),
        &placement,
    )? {
        let path_and_query = object_path_and_query(&bucket, &key, &params);
        return forward_write_to_target(
            Method::HEAD,
            &forward.target,
            &path_and_query,
            &headers,
            Vec::new(),
            &forward.envelope,
        )
        .await;
    }

    ensure_bucket_exists(&state, &bucket).await?;

    let meta = if let Some(version_id) = params.get("versionId") {
        state
            .storage
            .head_object_version(&bucket, &key, version_id)
            .await
            .map_err(|e| map_object_version_get_err(&key, version_id, e))?
    } else {
        state
            .storage
            .head_object(&bucket, &key)
            .await
            .map_err(|e| map_object_get_err(&key, e))?
    };

    if !params.contains_key("versionId")
        && routing_hint.distributed
        && routing_hint.is_local_primary_owner
    {
        execute_primary_read_repair(&state, &bucket, &key, &headers, &placement, &meta).await;
    }

    object_response(&meta, StatusCode::OK, Body::empty(), meta.size, None)
}

pub async fn delete_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response<Body>, S3Error> {
    if params.contains_key("uploadId") {
        return multipart::abort_multipart_upload(
            State(state),
            Path((bucket, key)),
            Query(params),
            headers,
        )
        .await;
    }

    // Permanent version deletion
    let routing_hint =
        object_write_routing_hint(&key, state.node_id.as_ref(), state.cluster_peers.as_slice());
    let placement = PlacementViewState::from_membership(
        state.placement_epoch(),
        state.node_id.as_ref(),
        state.cluster_peers.as_slice(),
    );
    if let Some(forward) = write_forward_target(
        &bucket,
        &key,
        ForwardedWriteOperation::DeleteObject,
        &routing_hint,
        &headers,
        state.node_id.as_ref(),
        &placement,
    )? {
        let path_and_query = object_path_and_query(&bucket, &key, &params);
        return forward_write_to_target(
            Method::DELETE,
            &forward.target,
            &path_and_query,
            &headers,
            Vec::new(),
            &forward.envelope,
        )
        .await;
    }
    let internal_replica_delete = is_internal_replica_delete_request(&headers);
    if !internal_replica_delete {
        ensure_local_write_owner(&routing_hint)?;
    }

    if let Some(version_id) = params.get("versionId") {
        ensure_bucket_exists(&state, &bucket).await?;

        let deleted_meta = state
            .storage
            .delete_object_version(&bucket, &key, version_id)
            .await
            .map_err(|e| map_object_version_delete_err(&bucket, version_id, e))?;

        let mut response = no_content_delete_response(
            Some(version_id),
            deleted_meta.is_delete_marker,
            &routing_hint,
        )?;
        if routing_hint.distributed
            && routing_hint.is_local_primary_owner
            && !internal_replica_delete
        {
            let outcome = replicate_delete_to_replica_owners(
                &state, &bucket, &key, &params, &headers, &placement,
            )
            .await;
            add_write_quorum_headers(response.headers_mut(), &outcome);
        }
        return Ok(response);
    }

    ensure_bucket_exists(&state, &bucket).await?;

    let result = state
        .storage
        .delete_object(&bucket, &key)
        .await
        .map_err(|e| map_delete_storage_err(&bucket, e))?;

    let mut response = no_content_delete_response(
        result.version_id.as_deref(),
        result.is_delete_marker,
        &routing_hint,
    )?;
    if routing_hint.distributed && routing_hint.is_local_primary_owner && !internal_replica_delete {
        let outcome = replicate_delete_to_replica_owners(
            &state, &bucket, &key, &params, &headers, &placement,
        )
        .await;
        add_write_quorum_headers(response.headers_mut(), &outcome);
    }
    Ok(response)
}

pub async fn post_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    if params.contains_key("uploads") {
        return multipart::create_multipart_upload(State(state), Path((bucket, key)), headers)
            .await;
    }
    if params.contains_key("uploadId") {
        return multipart::complete_multipart_upload(
            State(state),
            Path((bucket, key)),
            Query(params),
            headers,
            body,
        )
        .await;
    }
    Err(S3Error::not_implemented(
        "Unsupported POST object operation",
    ))
}

const DELETE_BODY_MAX: usize = 1024 * 1024;

#[derive(Debug, Clone)]
struct PlannedDeleteObjectEntry {
    key: String,
    routing_hint: service::ObjectWriteRoutingHint,
    forward_target: Option<service::ForwardWriteTarget>,
}

fn forwarded_delete_objects_outcome(
    key: String,
    response: &Response<Body>,
) -> DeleteObjectsOutcome {
    if response.status().is_success() {
        let version_id = parse_header_string(response.headers(), "x-amz-version-id");
        let is_delete_marker =
            parse_header_bool(response.headers(), "x-amz-delete-marker").unwrap_or(false);
        DeleteObjectsOutcome::Deleted {
            key,
            version_id,
            is_delete_marker,
        }
    } else {
        let code = match response.status() {
            StatusCode::BAD_REQUEST => "InvalidArgument",
            StatusCode::NOT_FOUND => "NoSuchBucket",
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => "AccessDenied",
            _ => "InternalError",
        };
        let message = response
            .status()
            .canonical_reason()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| {
                format!(
                    "Forwarded delete request failed with status {}",
                    response.status().as_u16()
                )
            });
        DeleteObjectsOutcome::Error { key, code, message }
    }
}

/// Handle POST /{bucket}?delete — multi-object delete (DeleteObjects API).
pub async fn delete_objects(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    let bytes = axum::body::to_bytes(body, DELETE_BODY_MAX)
        .await
        .map_err(S3Error::internal)?;
    let body_str = std::str::from_utf8(&bytes).map_err(|_| S3Error::malformed_xml())?;
    let request = parse_delete_objects_request(body_str)?;
    let body_bytes = bytes.to_vec();

    let placement = PlacementViewState::from_membership(
        state.placement_epoch(),
        state.node_id.as_ref(),
        state.cluster_peers.as_slice(),
    );
    let mut planned_entries = Vec::with_capacity(request.keys.len());
    let mut batch_forward_target: Option<service::ForwardWriteTarget> = None;
    let mut can_forward_batch = !request.keys.is_empty();
    for key in &request.keys {
        let routing_hint =
            object_write_routing_hint(key, state.node_id.as_ref(), state.cluster_peers.as_slice());
        let forward_target = write_forward_target(
            &bucket,
            key,
            ForwardedWriteOperation::DeleteObject,
            &routing_hint,
            &headers,
            state.node_id.as_ref(),
            &placement,
        )?;
        if let Some(forward) = &forward_target {
            if let Some(existing_target) = batch_forward_target.as_ref().map(|v| &v.target) {
                if existing_target != &forward.target {
                    can_forward_batch = false;
                }
            } else {
                batch_forward_target = Some(forward.clone());
            }
        } else {
            can_forward_batch = false;
        }
        planned_entries.push(PlannedDeleteObjectEntry {
            key: key.clone(),
            routing_hint,
            forward_target,
        });
    }

    if can_forward_batch {
        if let Some(forward) = batch_forward_target {
            let path_and_query = bucket_path_and_query(&bucket, &params);
            return forward_write_to_target(
                Method::POST,
                &forward.target,
                &path_and_query,
                &headers,
                body_bytes,
                &forward.envelope,
            )
            .await;
        }
    }

    let has_local_entries = planned_entries
        .iter()
        .any(|entry| entry.forward_target.is_none());
    if has_local_entries {
        ensure_bucket_exists(&state, &bucket).await?;
    }

    let mut outcomes = Vec::with_capacity(planned_entries.len());
    let mut quorum_aggregate = BatchWriteQuorumAggregate::new();
    let empty_params = HashMap::new();
    let forwarded_delete_headers = replica_delete_headers(&headers);
    for entry in planned_entries {
        if let Some(forward) = entry.forward_target {
            let signed_host = forwarded_delete_headers
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .filter(|value| !value.trim().is_empty())
                .unwrap_or(forward.target.as_str());
            let Some(path_and_query) =
                presigned_replica_delete_path_and_query(&state, signed_host, &bucket, &entry.key)
            else {
                outcomes.push(DeleteObjectsOutcome::Error {
                    key: entry.key,
                    code: "AccessDenied",
                    message: "Write forwarding to primary owner failed: unable to presign internal delete request".to_string(),
                });
                continue;
            };
            match forward_write_to_target(
                Method::DELETE,
                &forward.target,
                path_and_query.as_str(),
                &forwarded_delete_headers,
                Vec::new(),
                &forward.envelope,
            )
            .await
            {
                Ok(response) => {
                    quorum_aggregate.record_headers(response.headers());
                    outcomes.push(forwarded_delete_objects_outcome(entry.key, &response));
                }
                Err(err) => outcomes.push(DeleteObjectsOutcome::Error {
                    key: entry.key,
                    code: "AccessDenied",
                    message: err.message,
                }),
            }
            continue;
        }

        if let Err(err) = ensure_local_write_owner(&entry.routing_hint) {
            outcomes.push(DeleteObjectsOutcome::Error {
                key: entry.key,
                code: "AccessDenied",
                message: err.message,
            });
            continue;
        }

        let delete_result = state.storage.delete_object(&bucket, &entry.key).await;
        match delete_result {
            Ok(dr) => {
                if entry.routing_hint.distributed && entry.routing_hint.is_local_primary_owner {
                    let outcome = replicate_delete_to_replica_owners(
                        &state,
                        &bucket,
                        &entry.key,
                        &empty_params,
                        &headers,
                        &placement,
                    )
                    .await;
                    quorum_aggregate.record_outcome(&outcome);
                }
                outcomes.push(DeleteObjectsOutcome::Deleted {
                    key: entry.key,
                    version_id: dr.version_id,
                    is_delete_marker: dr.is_delete_marker,
                });
            }
            Err(e) => outcomes.push(map_delete_objects_err(&bucket, entry.key, e)),
        }
    }

    let response_xml = build_delete_objects_response_xml(&outcomes, request.quiet);
    let mut response = delete_objects_xml_response(response_xml)?;
    if quorum_aggregate.observed {
        add_write_quorum_header_values(
            response.headers_mut(),
            quorum_aggregate.ack_count,
            quorum_aggregate.quorum_size,
            quorum_aggregate.quorum_reached,
        );
    }
    Ok(response)
}
