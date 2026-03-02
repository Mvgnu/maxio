use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::Response,
};
use futures::TryStreamExt;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncReadExt};

use super::parsing::to_http_date;
use crate::error::S3Error;
use crate::server::AppState;
use crate::storage::placement::{
    ForwardedWriteEnvelope, ForwardedWriteOperation, ForwardedWriteRejectReason,
    ForwardedWriteResolution, PlacementViewState, object_forward_target_with_self,
    primary_object_owner_with_self, resolve_forwarded_write_envelope,
};
use crate::storage::{ChecksumAlgorithm, ObjectMeta, PutResult, StorageError};

const INTERNAL_FORWARDED_BY_HEADER: &str = "x-maxio-forwarded-by";
const INTERNAL_FORWARD_EPOCH_HEADER: &str = "x-maxio-forwarded-write-epoch";
const INTERNAL_FORWARD_VIEW_ID_HEADER: &str = "x-maxio-forwarded-write-view-id";
const INTERNAL_FORWARD_HOP_COUNT_HEADER: &str = "x-maxio-forwarded-write-hop-count";
const INTERNAL_FORWARD_MAX_HOPS_HEADER: &str = "x-maxio-forwarded-write-max-hops";
const INTERNAL_FORWARD_IDEMPOTENCY_KEY_HEADER: &str = "x-maxio-forwarded-write-idempotency-key";
const INTERNAL_TRUSTED_FORWARD_EPOCH_HEADER: &str = "x-maxio-internal-forwarded-write-epoch";
const INTERNAL_TRUSTED_FORWARD_VIEW_ID_HEADER: &str = "x-maxio-internal-forwarded-write-view-id";
const INTERNAL_TRUSTED_FORWARD_HOP_COUNT_HEADER: &str =
    "x-maxio-internal-forwarded-write-hop-count";
const INTERNAL_TRUSTED_FORWARD_MAX_HOPS_HEADER: &str = "x-maxio-internal-forwarded-write-max-hops";
const INTERNAL_TRUSTED_FORWARD_IDEMPOTENCY_KEY_HEADER: &str =
    "x-maxio-internal-forwarded-write-idempotency-key";
const INTERNAL_TRUSTED_FORWARD_OPERATION_HEADER: &str =
    "x-maxio-internal-forwarded-write-operation";
const INTERNAL_TRUSTED_FORWARD_VERSION_ID_HEADER: &str =
    "x-maxio-internal-forwarded-write-version-id";
const INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_PUT: &str = "replicate-put-object";
const INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_DELETE: &str = "replicate-delete-object";
const INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_HEAD: &str = "replicate-head-object";
const FORWARD_MAX_HOPS_DEFAULT: u8 = 8;
const DISTRIBUTED_WRITE_REPLICA_TARGET: usize = 2;
const S3_PATH_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b'/');
const S3_QUERY_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

pub(crate) async fn ensure_bucket_exists(state: &AppState, bucket: &str) -> Result<(), S3Error> {
    match state.storage.head_bucket(bucket).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(S3Error::no_such_bucket(bucket)),
        Err(err) => Err(S3Error::internal(err)),
    }
}

/// Extract checksum algorithm and optional expected value from request headers.
pub(crate) fn extract_checksum(headers: &HeaderMap) -> Option<(ChecksumAlgorithm, Option<String>)> {
    let pairs = [
        ("x-amz-checksum-crc32", ChecksumAlgorithm::CRC32),
        ("x-amz-checksum-crc32c", ChecksumAlgorithm::CRC32C),
        ("x-amz-checksum-sha1", ChecksumAlgorithm::SHA1),
        ("x-amz-checksum-sha256", ChecksumAlgorithm::SHA256),
    ];

    // Check for a value header first (implies the algorithm).
    for (header, algo) in &pairs {
        if let Some(val) = headers.get(*header).and_then(|v| v.to_str().ok()) {
            return Some((*algo, Some(val.to_string())));
        }
    }

    // Fall back to algorithm-only header (compute but don't validate).
    headers
        .get("x-amz-checksum-algorithm")
        .and_then(|v| v.to_str().ok())
        .and_then(ChecksumAlgorithm::from_header_str)
        .map(|algo| (algo, None))
}

pub(crate) fn add_checksum_header(
    builder: http::response::Builder,
    meta: &ObjectMeta,
) -> http::response::Builder {
    if let (Some(algo), Some(val)) = (&meta.checksum_algorithm, &meta.checksum_value) {
        builder.header(algo.header_name(), val.as_str())
    } else {
        builder
    }
}

pub(crate) fn object_response(
    meta: &ObjectMeta,
    status: StatusCode,
    body: Body,
    content_length: u64,
    content_range: Option<(u64, u64, u64)>,
) -> Result<Response<Body>, S3Error> {
    let mut builder = Response::builder()
        .status(status)
        .header("Content-Type", &meta.content_type)
        .header("Content-Length", content_length.to_string())
        .header("Accept-Ranges", "bytes")
        .header("ETag", &meta.etag)
        .header("Last-Modified", to_http_date(&meta.last_modified));

    if let Some((start, end, total)) = content_range {
        builder = builder.header(
            "Content-Range",
            format!("bytes {}-{}/{}", start, end, total),
        );
    }

    if let Some(vid) = &meta.version_id {
        builder = builder.header("x-amz-version-id", vid.as_str());
    }

    builder = add_checksum_header(builder, meta);
    builder.body(body).map_err(S3Error::internal)
}

pub(crate) enum DeleteObjectsOutcome {
    Deleted {
        key: String,
        version_id: Option<String>,
        is_delete_marker: bool,
    },
    Error {
        key: String,
        code: &'static str,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ObjectWriteRoutingHint {
    pub distributed: bool,
    pub primary_owner: Option<String>,
    pub forward_target: Option<String>,
    pub is_local_primary_owner: bool,
}

pub(crate) fn object_write_routing_hint(
    key: &str,
    node_id: &str,
    peers: &[String],
) -> ObjectWriteRoutingHint {
    let local_node = node_id.trim();
    let primary_owner = primary_object_owner_with_self(key, local_node, peers);
    let forward_target = object_forward_target_with_self(key, local_node, peers);

    ObjectWriteRoutingHint {
        distributed: !peers.is_empty(),
        primary_owner: primary_owner.clone(),
        forward_target,
        is_local_primary_owner: primary_owner.as_deref() == Some(local_node),
    }
}

fn non_owner_write_message(routing_hint: &ObjectWriteRoutingHint) -> String {
    let primary = routing_hint
        .primary_owner
        .as_deref()
        .unwrap_or("unknown-primary-owner");
    let target = routing_hint.forward_target.as_deref().unwrap_or(primary);
    format!("Write request reached non-owner node. Retry against primary owner: {target}")
}

pub(crate) fn ensure_local_write_owner(
    routing_hint: &ObjectWriteRoutingHint,
) -> Result<(), S3Error> {
    if !routing_hint.distributed || routing_hint.is_local_primary_owner {
        return Ok(());
    }
    Err(S3Error::access_denied(&non_owner_write_message(
        routing_hint,
    )))
}

pub(crate) fn write_forward_target(
    bucket: &str,
    key: &str,
    operation: ForwardedWriteOperation,
    routing_hint: &ObjectWriteRoutingHint,
    headers: &HeaderMap,
    node_id: &str,
    placement: &PlacementViewState,
) -> Result<Option<ForwardWriteTarget>, S3Error> {
    if !routing_hint.distributed {
        return Ok(None);
    }

    let envelope =
        forwarded_write_envelope_from_headers(headers, operation, bucket, key, node_id, placement);
    let replica_count = write_replica_count_for_membership_count(placement.members.len());
    match resolve_forwarded_write_envelope(&envelope, node_id, placement, replica_count) {
        ForwardedWriteResolution::ExecuteLocal { .. } => Ok(None),
        ForwardedWriteResolution::ForwardToPrimary { target, envelope } => {
            Ok(Some(ForwardWriteTarget { target, envelope }))
        }
        ForwardedWriteResolution::Reject { reason } => match reason {
            ForwardedWriteRejectReason::MissingPrimaryOwner
            | ForwardedWriteRejectReason::MissingForwardTarget => Err(S3Error::access_denied(
                &non_owner_write_message(routing_hint),
            )),
            ForwardedWriteRejectReason::StaleEpoch {
                local_epoch,
                request_epoch,
            } => Err(S3Error::access_denied(&format!(
                "Write forwarding rejected due to stale placement epoch (local={local_epoch}, request={request_epoch})"
            ))),
            ForwardedWriteRejectReason::FutureEpoch {
                local_epoch,
                request_epoch,
            } => Err(S3Error::access_denied(&format!(
                "Write forwarding rejected due to future placement epoch (local={local_epoch}, request={request_epoch})"
            ))),
            ForwardedWriteRejectReason::ViewIdMismatch {
                local_view_id,
                request_view_id,
            } => Err(S3Error::access_denied(&format!(
                "Write forwarding rejected due to placement view mismatch (local={local_view_id}, request={request_view_id})"
            ))),
            ForwardedWriteRejectReason::ForwardLoop { node } => Err(S3Error::access_denied(
                &format!("Write forwarding loop detected while routing request (node={node})"),
            )),
            ForwardedWriteRejectReason::HopLimitExceeded {
                hop_count,
                max_hops,
            } => Err(S3Error::access_denied(&format!(
                "Write forwarding hop limit exceeded ({hop_count}/{max_hops})"
            ))),
        },
    }
}

pub(crate) fn write_replica_count_for_membership_count(membership_count: usize) -> usize {
    if membership_count <= 1 {
        1
    } else {
        membership_count.min(DISTRIBUTED_WRITE_REPLICA_TARGET)
    }
}

pub(crate) fn object_path_and_query(
    bucket: &str,
    key: &str,
    params: &HashMap<String, String>,
) -> String {
    let bucket = utf8_percent_encode(bucket, S3_PATH_ENCODE_SET);
    let key = utf8_percent_encode(key, S3_PATH_ENCODE_SET);
    let mut path = format!("/{bucket}/{key}");
    let query = canonical_query_string(params);
    if !query.is_empty() {
        path.push('?');
        path.push_str(&query);
    }
    path
}

pub(crate) fn bucket_path_and_query(bucket: &str, params: &HashMap<String, String>) -> String {
    let bucket = utf8_percent_encode(bucket, S3_PATH_ENCODE_SET);
    let mut path = format!("/{bucket}");
    let query = canonical_query_string(params);
    if !query.is_empty() {
        path.push('?');
        path.push_str(&query);
    }
    path
}

fn canonical_query_string(params: &HashMap<String, String>) -> String {
    if params.is_empty() {
        return String::new();
    }

    let mut pairs: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| {
            (
                utf8_percent_encode(k, S3_QUERY_ENCODE_SET).to_string(),
                utf8_percent_encode(v, S3_QUERY_ENCODE_SET).to_string(),
            )
        })
        .collect();
    pairs.sort();

    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

pub(crate) async fn forward_write_to_target(
    method: Method,
    target: &str,
    path_and_query: &str,
    headers: &HeaderMap,
    body: Vec<u8>,
    envelope: &ForwardedWriteEnvelope,
) -> Result<Response<Body>, S3Error> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(S3Error::internal)?;
    let url = format!("http://{target}{path_and_query}");
    let mut request_builder = client.request(method, &url);

    for (name, value) in headers {
        if should_skip_forwarded_request_header(name) {
            continue;
        }
        request_builder = request_builder.header(name, value);
    }
    request_builder = request_builder.header(
        INTERNAL_FORWARDED_BY_HEADER,
        envelope.visited_nodes.join(","),
    );
    if !headers.contains_key(INTERNAL_FORWARD_EPOCH_HEADER) {
        request_builder = request_builder.header(
            INTERNAL_FORWARD_EPOCH_HEADER,
            envelope.placement_epoch.to_string(),
        );
    }
    if !headers.contains_key(INTERNAL_FORWARD_VIEW_ID_HEADER) {
        request_builder =
            request_builder.header(INTERNAL_FORWARD_VIEW_ID_HEADER, &envelope.placement_view_id);
    }
    if !headers.contains_key(INTERNAL_FORWARD_HOP_COUNT_HEADER) {
        request_builder = request_builder.header(
            INTERNAL_FORWARD_HOP_COUNT_HEADER,
            envelope.hop_count.to_string(),
        );
    }
    if !headers.contains_key(INTERNAL_FORWARD_MAX_HOPS_HEADER) {
        request_builder = request_builder.header(
            INTERNAL_FORWARD_MAX_HOPS_HEADER,
            envelope.max_hops.to_string(),
        );
    }
    if !headers.contains_key(INTERNAL_FORWARD_IDEMPOTENCY_KEY_HEADER) {
        request_builder = request_builder.header(
            INTERNAL_FORWARD_IDEMPOTENCY_KEY_HEADER,
            &envelope.idempotency_key,
        );
    }
    request_builder = request_builder.header(
        INTERNAL_TRUSTED_FORWARD_EPOCH_HEADER,
        envelope.placement_epoch.to_string(),
    );
    request_builder = request_builder.header(
        INTERNAL_TRUSTED_FORWARD_VIEW_ID_HEADER,
        &envelope.placement_view_id,
    );
    request_builder = request_builder.header(
        INTERNAL_TRUSTED_FORWARD_HOP_COUNT_HEADER,
        envelope.hop_count.to_string(),
    );
    request_builder = request_builder.header(
        INTERNAL_TRUSTED_FORWARD_MAX_HOPS_HEADER,
        envelope.max_hops.to_string(),
    );
    request_builder = request_builder.header(
        INTERNAL_TRUSTED_FORWARD_IDEMPOTENCY_KEY_HEADER,
        &envelope.idempotency_key,
    );

    if !body.is_empty() {
        request_builder = request_builder.body(body);
    }

    let forwarded = request_builder.send().await.map_err(|err| {
        S3Error::access_denied(&format!(
            "Write forwarding to primary owner failed ({target}): {err}"
        ))
    })?;
    let status = forwarded.status();
    let forwarded_headers = forwarded.headers().clone();
    let forwarded_body = forwarded.bytes().await.map_err(S3Error::internal)?;

    let mut response = Response::new(Body::from(forwarded_body.to_vec()));
    *response.status_mut() = status;
    for (name, value) in &forwarded_headers {
        if should_skip_forwarded_response_header(name) {
            continue;
        }
        response.headers_mut().append(name.clone(), value.clone());
    }
    Ok(response)
}

pub(crate) async fn forward_replica_put_to_target(
    target: &str,
    path_and_query: &str,
    headers: &HeaderMap,
    body: Vec<u8>,
    replica_version_id: Option<&str>,
    envelope: &ForwardedWriteEnvelope,
) -> Result<Response<Body>, S3Error> {
    let mut replica_headers = headers.clone();
    replica_headers.insert(
        header::HeaderName::from_static(INTERNAL_TRUSTED_FORWARD_OPERATION_HEADER),
        HeaderValue::from_static(INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_PUT),
    );
    if let Some(version_id) = replica_version_id {
        if let Ok(value) = HeaderValue::from_str(version_id) {
            replica_headers.insert(
                header::HeaderName::from_static(INTERNAL_TRUSTED_FORWARD_VERSION_ID_HEADER),
                value,
            );
        }
    }
    forward_write_to_target(
        Method::PUT,
        target,
        path_and_query,
        &replica_headers,
        body,
        envelope,
    )
    .await
}

pub(crate) async fn forward_replica_delete_to_target(
    target: &str,
    path_and_query: &str,
    headers: &HeaderMap,
    envelope: &ForwardedWriteEnvelope,
) -> Result<Response<Body>, S3Error> {
    let mut replica_headers = headers.clone();
    replica_headers.insert(
        header::HeaderName::from_static(INTERNAL_TRUSTED_FORWARD_OPERATION_HEADER),
        HeaderValue::from_static(INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_DELETE),
    );
    forward_write_to_target(
        Method::DELETE,
        target,
        path_and_query,
        &replica_headers,
        Vec::new(),
        envelope,
    )
    .await
}

pub(crate) async fn forward_replica_head_to_target(
    target: &str,
    path_and_query: &str,
    headers: &HeaderMap,
    envelope: &ForwardedWriteEnvelope,
) -> Result<Response<Body>, S3Error> {
    let mut replica_headers = headers.clone();
    replica_headers.insert(
        header::HeaderName::from_static(INTERNAL_TRUSTED_FORWARD_OPERATION_HEADER),
        HeaderValue::from_static(INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_HEAD),
    );
    forward_write_to_target(
        Method::HEAD,
        target,
        path_and_query,
        &replica_headers,
        Vec::new(),
        envelope,
    )
    .await
}

pub(crate) fn is_internal_replica_put_request(headers: &HeaderMap) -> bool {
    is_internal_replica_operation_request(headers, INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_PUT)
}

pub(crate) fn is_internal_replica_delete_request(headers: &HeaderMap) -> bool {
    is_internal_replica_operation_request(
        headers,
        INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_DELETE,
    )
}

pub(crate) fn internal_replica_version_id(headers: &HeaderMap) -> Option<String> {
    if !is_internal_replica_put_request(headers) {
        return None;
    }
    parse_last_header_string(headers, INTERNAL_TRUSTED_FORWARD_VERSION_ID_HEADER)
}

fn is_internal_replica_operation_request(headers: &HeaderMap, operation: &str) -> bool {
    if !headers.contains_key(INTERNAL_FORWARDED_BY_HEADER) {
        return false;
    }
    parse_last_header_string(headers, INTERNAL_TRUSTED_FORWARD_OPERATION_HEADER)
        .map(|value| value.eq_ignore_ascii_case(operation))
        .unwrap_or(false)
}

fn should_skip_forwarded_request_header(name: &header::HeaderName) -> bool {
    name == header::CONNECTION
        || name == header::TRANSFER_ENCODING
        || name == header::CONTENT_LENGTH
        || name
            .as_str()
            .eq_ignore_ascii_case(INTERNAL_FORWARDED_BY_HEADER)
}

fn should_skip_forwarded_response_header(name: &header::HeaderName) -> bool {
    name == header::TRANSFER_ENCODING
        || name == header::CONNECTION
        || name
            .as_str()
            .eq_ignore_ascii_case(INTERNAL_FORWARDED_BY_HEADER)
        || name
            .as_str()
            .eq_ignore_ascii_case(INTERNAL_FORWARD_EPOCH_HEADER)
        || name
            .as_str()
            .eq_ignore_ascii_case(INTERNAL_FORWARD_VIEW_ID_HEADER)
        || name
            .as_str()
            .eq_ignore_ascii_case(INTERNAL_FORWARD_HOP_COUNT_HEADER)
        || name
            .as_str()
            .eq_ignore_ascii_case(INTERNAL_FORWARD_MAX_HOPS_HEADER)
        || name
            .as_str()
            .eq_ignore_ascii_case(INTERNAL_FORWARD_IDEMPOTENCY_KEY_HEADER)
        || name
            .as_str()
            .eq_ignore_ascii_case(INTERNAL_TRUSTED_FORWARD_EPOCH_HEADER)
        || name
            .as_str()
            .eq_ignore_ascii_case(INTERNAL_TRUSTED_FORWARD_VIEW_ID_HEADER)
        || name
            .as_str()
            .eq_ignore_ascii_case(INTERNAL_TRUSTED_FORWARD_HOP_COUNT_HEADER)
        || name
            .as_str()
            .eq_ignore_ascii_case(INTERNAL_TRUSTED_FORWARD_MAX_HOPS_HEADER)
        || name
            .as_str()
            .eq_ignore_ascii_case(INTERNAL_TRUSTED_FORWARD_IDEMPOTENCY_KEY_HEADER)
        || name
            .as_str()
            .eq_ignore_ascii_case(INTERNAL_TRUSTED_FORWARD_OPERATION_HEADER)
        || name
            .as_str()
            .eq_ignore_ascii_case(INTERNAL_TRUSTED_FORWARD_VERSION_ID_HEADER)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ForwardWriteTarget {
    pub target: String,
    pub envelope: ForwardedWriteEnvelope,
}

fn forwarded_write_envelope_from_headers(
    headers: &HeaderMap,
    operation: ForwardedWriteOperation,
    bucket: &str,
    key: &str,
    node_id: &str,
    placement: &PlacementViewState,
) -> ForwardedWriteEnvelope {
    let is_forwarded_request = headers.contains_key(INTERNAL_FORWARDED_BY_HEADER);
    let mut envelope = ForwardedWriteEnvelope::new(
        operation,
        bucket,
        key,
        node_id,
        node_id,
        &forward_idempotency_key(headers, is_forwarded_request),
        placement,
    );
    if let Some(operation) = parse_internal_forwarded_operation(headers, is_forwarded_request) {
        envelope.operation = operation;
    }
    if is_forwarded_request {
        envelope.visited_nodes = header_forwarded_by_nodes(headers);
        if let Some(value) = parse_last_header_u64(headers, INTERNAL_TRUSTED_FORWARD_EPOCH_HEADER)
            .or_else(|| parse_header_u64(headers, INTERNAL_FORWARD_EPOCH_HEADER))
        {
            envelope.placement_epoch = value;
        }
        if let Some(value) =
            parse_last_header_string(headers, INTERNAL_TRUSTED_FORWARD_VIEW_ID_HEADER)
                .or_else(|| parse_header_string(headers, INTERNAL_FORWARD_VIEW_ID_HEADER))
        {
            envelope.placement_view_id = value;
        }
        if let Some(value) =
            parse_last_header_u8(headers, INTERNAL_TRUSTED_FORWARD_HOP_COUNT_HEADER)
                .or_else(|| parse_header_u8(headers, INTERNAL_FORWARD_HOP_COUNT_HEADER))
        {
            envelope.hop_count = value;
        }
        if let Some(value) = parse_last_header_u8(headers, INTERNAL_TRUSTED_FORWARD_MAX_HOPS_HEADER)
            .or_else(|| parse_header_u8(headers, INTERNAL_FORWARD_MAX_HOPS_HEADER))
        {
            envelope.max_hops = value.max(1);
        } else {
            envelope.max_hops = FORWARD_MAX_HOPS_DEFAULT;
        }
    }
    envelope
}

fn parse_internal_forwarded_operation(
    headers: &HeaderMap,
    is_forwarded_request: bool,
) -> Option<ForwardedWriteOperation> {
    if !is_forwarded_request {
        return None;
    }
    let value = parse_last_header_string(headers, INTERNAL_TRUSTED_FORWARD_OPERATION_HEADER)?;
    if value.eq_ignore_ascii_case(INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_PUT) {
        Some(ForwardedWriteOperation::ReplicatePutObject)
    } else if value.eq_ignore_ascii_case(INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_DELETE) {
        Some(ForwardedWriteOperation::ReplicateDeleteObject)
    } else if value.eq_ignore_ascii_case(INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_HEAD) {
        Some(ForwardedWriteOperation::ReplicateHeadObject)
    } else {
        None
    }
}

fn forward_idempotency_key(headers: &HeaderMap, is_forwarded_request: bool) -> String {
    let payload_hash = parse_header_string(headers, "x-amz-content-sha256");
    if is_forwarded_request {
        parse_last_header_string(headers, INTERNAL_TRUSTED_FORWARD_IDEMPOTENCY_KEY_HEADER)
            .or_else(|| parse_header_string(headers, INTERNAL_FORWARD_IDEMPOTENCY_KEY_HEADER))
            .or(payload_hash)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
    } else {
        payload_hash.unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
    }
}

fn header_forwarded_by_nodes(headers: &HeaderMap) -> Vec<String> {
    headers
        .get(INTERNAL_FORWARDED_BY_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|node| !node.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn parse_header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn parse_last_header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .next_back()
}

fn parse_header_u64(headers: &HeaderMap, name: &str) -> Option<u64> {
    parse_header_string(headers, name).and_then(|value| value.parse::<u64>().ok())
}

fn parse_header_u8(headers: &HeaderMap, name: &str) -> Option<u8> {
    parse_header_string(headers, name).and_then(|value| value.parse::<u8>().ok())
}

fn parse_last_header_u64(headers: &HeaderMap, name: &str) -> Option<u64> {
    parse_last_header_string(headers, name).and_then(|value| value.parse::<u64>().ok())
}

fn parse_last_header_u8(headers: &HeaderMap, name: &str) -> Option<u8> {
    parse_last_header_string(headers, name).and_then(|value| value.parse::<u8>().ok())
}

fn add_write_routing_headers(
    mut builder: http::response::Builder,
    routing_hint: &ObjectWriteRoutingHint,
) -> http::response::Builder {
    if !routing_hint.distributed {
        return builder;
    }

    if let Some(primary_owner) = &routing_hint.primary_owner {
        builder = builder.header("x-maxio-primary-owner", primary_owner);
    }
    if let Some(forward_target) = &routing_hint.forward_target {
        builder = builder.header("x-maxio-forward-target", forward_target);
    }
    builder.header(
        "x-maxio-routing-local-primary-owner",
        if routing_hint.is_local_primary_owner {
            "true"
        } else {
            "false"
        },
    )
}

pub(super) fn map_delete_storage_err(bucket: &str, err: StorageError) -> S3Error {
    match err {
        StorageError::NotFound(_) => S3Error::no_such_bucket(bucket),
        StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
        _ => S3Error::internal(err),
    }
}

pub(super) fn map_object_get_err(key: &str, err: StorageError) -> S3Error {
    match err {
        StorageError::NotFound(_) => S3Error::no_such_key(key),
        StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
        _ => S3Error::internal(err),
    }
}

pub(super) fn map_object_version_get_err(
    key: &str,
    version_id: &str,
    err: StorageError,
) -> S3Error {
    match err {
        StorageError::VersionNotFound(_) => S3Error::no_such_version(version_id),
        StorageError::NotFound(_) => S3Error::no_such_key(key),
        StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
        _ => S3Error::internal(err),
    }
}

pub(super) fn map_object_put_err(bucket: &str, err: StorageError) -> S3Error {
    match err {
        StorageError::NotFound(_) => S3Error::no_such_bucket(bucket),
        StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
        StorageError::ChecksumMismatch(_) => S3Error::bad_checksum("x-amz-checksum"),
        _ => S3Error::internal(err),
    }
}

pub(super) fn map_object_version_delete_err(
    bucket: &str,
    version_id: &str,
    err: StorageError,
) -> S3Error {
    match err {
        StorageError::VersionNotFound(_) => S3Error::no_such_version(version_id),
        _ => map_delete_storage_err(bucket, err),
    }
}

pub(super) fn map_delete_objects_err(
    bucket: &str,
    key: String,
    err: StorageError,
) -> DeleteObjectsOutcome {
    match err {
        StorageError::InvalidKey(msg) => DeleteObjectsOutcome::Error {
            key,
            code: "InvalidArgument",
            message: msg,
        },
        StorageError::NotFound(_) => DeleteObjectsOutcome::Error {
            key,
            code: "NoSuchBucket",
            message: format!("The specified bucket does not exist: {bucket}"),
        },
        _ => DeleteObjectsOutcome::Error {
            key,
            code: "InternalError",
            message: err.to_string(),
        },
    }
}

pub(super) fn build_delete_objects_response_xml(
    outcomes: &[DeleteObjectsOutcome],
    quiet: bool,
) -> String {
    let mut deleted_xml = String::new();
    let mut error_xml = String::new();

    for outcome in outcomes {
        match outcome {
            DeleteObjectsOutcome::Deleted {
                key,
                version_id,
                is_delete_marker,
            } => {
                if quiet {
                    continue;
                }
                let mut entry = format!("<Deleted><Key>{}</Key>", quick_xml::escape::escape(key));
                if let Some(vid) = version_id {
                    entry.push_str(&format!(
                        "<VersionId>{}</VersionId>",
                        quick_xml::escape::escape(vid)
                    ));
                }
                if *is_delete_marker {
                    entry.push_str("<DeleteMarker>true</DeleteMarker>");
                }
                entry.push_str("</Deleted>");
                deleted_xml.push_str(&entry);
            }
            DeleteObjectsOutcome::Error { key, code, message } => {
                error_xml.push_str(&format!(
                    "<Error><Key>{}</Key><Code>{}</Code><Message>{}</Message></Error>",
                    quick_xml::escape::escape(key),
                    code,
                    quick_xml::escape::escape(message)
                ));
            }
        }
    }

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{}{}</DeleteResult>",
        deleted_xml, error_xml
    )
}

pub(super) fn put_object_response(
    result: &PutResult,
    routing_hint: &ObjectWriteRoutingHint,
) -> Result<Response<Body>, S3Error> {
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("ETag", &result.etag)
        .header("Content-Length", result.size.to_string());
    if let Some(vid) = &result.version_id {
        builder = builder.header("x-amz-version-id", vid.as_str());
    }
    if let (Some(algo), Some(val)) = (&result.checksum_algorithm, &result.checksum_value) {
        builder = builder.header(algo.header_name(), val.as_str());
    }
    builder = add_write_routing_headers(builder, routing_hint);
    builder.body(Body::empty()).map_err(S3Error::internal)
}

pub(super) fn no_content_delete_response(
    version_id: Option<&str>,
    is_delete_marker: bool,
    routing_hint: &ObjectWriteRoutingHint,
) -> Result<Response<Body>, S3Error> {
    let mut builder = Response::builder().status(StatusCode::NO_CONTENT);
    if let Some(version_id) = version_id {
        builder = builder.header("x-amz-version-id", version_id);
    }
    if is_delete_marker {
        builder = builder.header("x-amz-delete-marker", "true");
    }
    builder = add_write_routing_headers(builder, routing_hint);
    builder.body(Body::empty()).map_err(S3Error::internal)
}

pub(super) fn copy_object_response(
    xml: String,
    source_version_id: Option<&str>,
    version_id: Option<&str>,
    routing_hint: &ObjectWriteRoutingHint,
) -> Result<Response<Body>, S3Error> {
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml");
    if let Some(source_version_id) = source_version_id {
        builder = builder.header("x-amz-copy-source-version-id", source_version_id);
    }
    if let Some(version_id) = version_id {
        builder = builder.header("x-amz-version-id", version_id);
    }
    builder = add_write_routing_headers(builder, routing_hint);
    builder.body(Body::from(xml)).map_err(S3Error::internal)
}

pub(super) fn delete_objects_xml_response(xml: String) -> Result<Response<Body>, S3Error> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/xml")
        .body(Body::from(xml))
        .map_err(S3Error::internal)
}

pub(crate) async fn body_to_reader(
    headers: &HeaderMap,
    body: Body,
) -> Result<std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>, S3Error> {
    let is_aws_chunked = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        == Some("STREAMING-AWS4-HMAC-SHA256-PAYLOAD");

    let stream = body.into_data_stream();
    let raw_reader = tokio_util::io::StreamReader::new(stream.map_err(std::io::Error::other));

    if is_aws_chunked {
        let framing_err = || S3Error::invalid_argument("invalid aws-chunked payload framing");
        let mut buf_reader = tokio::io::BufReader::new(raw_reader);
        let mut decoded = Vec::new();
        let mut saw_final_chunk = false;
        loop {
            let mut line = String::new();
            let n = buf_reader
                .read_line(&mut line)
                .await
                .map_err(S3Error::internal)?;
            if n == 0 {
                break;
            }
            let line = line.trim_end_matches(['\r', '\n']);
            let size_str = line.split(';').next().unwrap_or("0");
            let chunk_size =
                usize::from_str_radix(size_str.trim(), 16).map_err(|_| framing_err())?;
            if chunk_size == 0 {
                saw_final_chunk = true;
                break;
            }
            let mut chunk = vec![0u8; chunk_size];
            buf_reader
                .read_exact(&mut chunk)
                .await
                .map_err(|_| framing_err())?;
            decoded.extend_from_slice(&chunk);
            let mut crlf = [0u8; 2];
            buf_reader
                .read_exact(&mut crlf)
                .await
                .map_err(|_| framing_err())?;
            if crlf != *b"\r\n" {
                return Err(framing_err());
            }
        }
        if !saw_final_chunk {
            return Err(framing_err());
        }
        Ok(Box::pin(std::io::Cursor::new(decoded)))
    } else {
        Ok(Box::pin(raw_reader))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use tokio::io::AsyncReadExt;

    const TEST_PLACEMENT_EPOCH: u64 = 42;

    fn standalone_routing_hint() -> ObjectWriteRoutingHint {
        ObjectWriteRoutingHint {
            distributed: false,
            primary_owner: None,
            forward_target: None,
            is_local_primary_owner: true,
        }
    }

    fn distributed_forwarding_hint() -> ObjectWriteRoutingHint {
        ObjectWriteRoutingHint {
            distributed: true,
            primary_owner: Some("node-b:9000".to_string()),
            forward_target: Some("node-b:9000".to_string()),
            is_local_primary_owner: false,
        }
    }

    #[test]
    fn extract_checksum_prefers_explicit_value_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-checksum-algorithm", "SHA1".parse().unwrap());
        headers.insert("x-amz-checksum-sha256", "abc123=".parse().unwrap());

        let checksum = extract_checksum(&headers).expect("checksum should be extracted");
        assert_eq!(checksum.0, ChecksumAlgorithm::SHA256);
        assert_eq!(checksum.1.as_deref(), Some("abc123="));
    }

    #[test]
    fn extract_checksum_supports_algorithm_only_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-checksum-algorithm", "CRC32C".parse().unwrap());

        let checksum = extract_checksum(&headers).expect("checksum should be extracted");
        assert_eq!(checksum.0, ChecksumAlgorithm::CRC32C);
        assert_eq!(checksum.1, None);
    }

    #[test]
    fn add_checksum_header_adds_header_for_known_checksum() {
        let meta = ObjectMeta {
            key: "a.txt".to_string(),
            size: 1,
            etag: "\"etag\"".to_string(),
            content_type: "text/plain".to_string(),
            last_modified: "2026-03-01T00:00:00Z".to_string(),
            version_id: None,
            is_delete_marker: false,
            storage_format: None,
            checksum_algorithm: Some(ChecksumAlgorithm::SHA256),
            checksum_value: Some("value==".to_string()),
        };

        let response = add_checksum_header(http::Response::builder(), &meta)
            .status(200)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            response
                .headers()
                .get("x-amz-checksum-sha256")
                .and_then(|v| v.to_str().ok()),
            Some("value==")
        );
    }

    #[tokio::test]
    async fn body_to_reader_decodes_streaming_chunked_payload() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".parse().unwrap(),
        );
        let encoded =
            b"5;chunk-signature=a\r\nhello\r\n6;chunk-signature=b\r\n world\r\n0;chunk-signature=c\r\n\r\n";
        let mut reader = body_to_reader(&headers, Body::from(encoded.as_slice()))
            .await
            .expect("chunked payload should decode");
        let mut decoded = Vec::new();
        reader.read_to_end(&mut decoded).await.unwrap();
        assert_eq!(decoded, b"hello world");
    }

    #[tokio::test]
    async fn body_to_reader_keeps_regular_payload_unchanged() {
        let headers = HeaderMap::new();
        let expected = b"plain payload bytes";
        let mut reader = body_to_reader(&headers, Body::from(expected.as_slice()))
            .await
            .expect("plain payload should be readable");
        let mut actual = Vec::new();
        reader.read_to_end(&mut actual).await.unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn body_to_reader_rejects_chunked_payload_without_final_chunk() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".parse().unwrap(),
        );
        let encoded = b"5;chunk-signature=a\r\nhello\r\n";
        let err = match body_to_reader(&headers, Body::from(encoded.as_slice())).await {
            Ok(_) => panic!("payload without final chunk should fail"),
            Err(err) => err,
        };
        assert_eq!(err.code.as_str(), "InvalidArgument");
    }

    #[tokio::test]
    async fn body_to_reader_rejects_chunked_payload_with_invalid_size() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".parse().unwrap(),
        );
        let encoded = b"zz;chunk-signature=a\r\nhello\r\n0;chunk-signature=b\r\n\r\n";
        let err = match body_to_reader(&headers, Body::from(encoded.as_slice())).await {
            Ok(_) => panic!("payload with invalid chunk size should fail"),
            Err(err) => err,
        };
        assert_eq!(err.code.as_str(), "InvalidArgument");
    }

    #[test]
    fn build_delete_objects_response_xml_includes_deleted_and_error_entries() {
        let xml = build_delete_objects_response_xml(
            &[
                DeleteObjectsOutcome::Deleted {
                    key: "a&b.txt".to_string(),
                    version_id: Some("v1".to_string()),
                    is_delete_marker: true,
                },
                DeleteObjectsOutcome::Error {
                    key: "bad<key>.txt".to_string(),
                    code: "InternalError",
                    message: "failed > reason".to_string(),
                },
            ],
            false,
        );

        assert!(xml.contains("<Deleted><Key>a&amp;b.txt</Key>"));
        assert!(xml.contains("<VersionId>v1</VersionId>"));
        assert!(xml.contains("<DeleteMarker>true</DeleteMarker>"));
        assert!(xml.contains("<Error><Key>bad&lt;key&gt;.txt</Key>"));
        assert!(xml.contains("<Code>InternalError</Code>"));
        assert!(xml.contains("<Message>failed &gt; reason</Message>"));
    }

    #[test]
    fn build_delete_objects_response_xml_honors_quiet_mode() {
        let xml = build_delete_objects_response_xml(
            &[DeleteObjectsOutcome::Deleted {
                key: "a.txt".to_string(),
                version_id: None,
                is_delete_marker: false,
            }],
            true,
        );

        assert!(!xml.contains("<Deleted>"));
        assert!(xml.contains("<DeleteResult"));
    }

    #[test]
    fn map_delete_storage_err_maps_invalid_key_to_invalid_argument() {
        let err = map_delete_storage_err("bucket", StorageError::InvalidKey("bad key".into()));
        assert_eq!(err.code.as_str(), "InvalidArgument");
        assert_eq!(err.message, "bad key");
    }

    #[test]
    fn map_delete_objects_err_maps_invalid_key_to_invalid_argument_entry() {
        let outcome = map_delete_objects_err(
            "bucket",
            "../oops.txt".to_string(),
            StorageError::InvalidKey("bad key".into()),
        );
        match outcome {
            DeleteObjectsOutcome::Error { code, message, .. } => {
                assert_eq!(code, "InvalidArgument");
                assert_eq!(message, "bad key");
            }
            _ => panic!("expected error outcome"),
        }
    }

    #[test]
    fn map_object_get_err_maps_not_found_and_invalid_key() {
        let key_err = map_object_get_err("docs/a.txt", StorageError::NotFound("x".into()));
        assert_eq!(key_err.code.as_str(), "NoSuchKey");

        let invalid_err =
            map_object_get_err("docs/a.txt", StorageError::InvalidKey("bad key".into()));
        assert_eq!(invalid_err.code.as_str(), "InvalidArgument");
        assert_eq!(invalid_err.message, "bad key");
    }

    #[test]
    fn map_object_version_get_err_maps_missing_version_and_key() {
        let version_err = map_object_version_get_err(
            "docs/a.txt",
            "v123",
            StorageError::VersionNotFound("v123".into()),
        );
        assert_eq!(version_err.code.as_str(), "NoSuchVersion");

        let key_err =
            map_object_version_get_err("docs/a.txt", "v123", StorageError::NotFound("x".into()));
        assert_eq!(key_err.code.as_str(), "NoSuchKey");
    }

    #[test]
    fn map_object_put_err_maps_bucket_invalid_and_checksum_errors() {
        let bucket_err = map_object_put_err("bucket", StorageError::NotFound("x".into()));
        assert_eq!(bucket_err.code.as_str(), "NoSuchBucket");

        let invalid_err = map_object_put_err("bucket", StorageError::InvalidKey("bad key".into()));
        assert_eq!(invalid_err.code.as_str(), "InvalidArgument");

        let checksum_err = map_object_put_err(
            "bucket",
            StorageError::ChecksumMismatch("digest mismatch".into()),
        );
        assert_eq!(checksum_err.code.as_str(), "BadDigest");
    }

    #[test]
    fn map_object_version_delete_err_maps_missing_version() {
        let err = map_object_version_delete_err(
            "bucket",
            "v-1",
            StorageError::VersionNotFound("v-1".into()),
        );
        assert_eq!(err.code.as_str(), "NoSuchVersion");
    }

    #[test]
    fn put_object_response_sets_headers() {
        let result = PutResult {
            size: 12,
            etag: "\"etag\"".to_string(),
            version_id: Some("v2".to_string()),
            checksum_algorithm: Some(ChecksumAlgorithm::SHA256),
            checksum_value: Some("checksum==".to_string()),
        };
        let response = put_object_response(&result, &standalone_routing_hint())
            .expect("response should build");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok()),
            Some("12")
        );
        assert_eq!(
            response.headers().get("etag").and_then(|v| v.to_str().ok()),
            Some("\"etag\"")
        );
        assert_eq!(
            response
                .headers()
                .get("x-amz-version-id")
                .and_then(|v| v.to_str().ok()),
            Some("v2")
        );
        assert_eq!(
            response
                .headers()
                .get("x-amz-checksum-sha256")
                .and_then(|v| v.to_str().ok()),
            Some("checksum==")
        );
        assert!(response.headers().get("x-maxio-primary-owner").is_none());
    }

    #[test]
    fn put_object_response_sets_distributed_routing_headers() {
        let result = PutResult {
            size: 12,
            etag: "\"etag\"".to_string(),
            version_id: None,
            checksum_algorithm: None,
            checksum_value: None,
        };
        let response = put_object_response(&result, &distributed_forwarding_hint())
            .expect("response should build");
        assert_eq!(
            response
                .headers()
                .get("x-maxio-primary-owner")
                .and_then(|v| v.to_str().ok()),
            Some("node-b:9000")
        );
        assert_eq!(
            response
                .headers()
                .get("x-maxio-forward-target")
                .and_then(|v| v.to_str().ok()),
            Some("node-b:9000")
        );
        assert_eq!(
            response
                .headers()
                .get("x-maxio-routing-local-primary-owner")
                .and_then(|v| v.to_str().ok()),
            Some("false")
        );
    }

    #[test]
    fn no_content_delete_response_sets_optional_headers() {
        let response = no_content_delete_response(Some("v1"), true, &distributed_forwarding_hint())
            .expect("response should build");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            response
                .headers()
                .get("x-amz-version-id")
                .and_then(|v| v.to_str().ok()),
            Some("v1")
        );
        assert_eq!(
            response
                .headers()
                .get("x-amz-delete-marker")
                .and_then(|v| v.to_str().ok()),
            Some("true")
        );
        assert_eq!(
            response
                .headers()
                .get("x-maxio-primary-owner")
                .and_then(|v| v.to_str().ok()),
            Some("node-b:9000")
        );
    }

    #[tokio::test]
    async fn copy_object_response_sets_headers_and_body() {
        let response = copy_object_response(
            "<CopyObjectResult />".to_string(),
            Some("src-v1"),
            Some("dst-v2"),
            &distributed_forwarding_hint(),
        )
        .expect("response should build");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/xml")
        );
        assert_eq!(
            response
                .headers()
                .get("x-amz-copy-source-version-id")
                .and_then(|v| v.to_str().ok()),
            Some("src-v1")
        );
        assert_eq!(
            response
                .headers()
                .get("x-amz-version-id")
                .and_then(|v| v.to_str().ok()),
            Some("dst-v2")
        );
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        assert_eq!(body.as_ref(), b"<CopyObjectResult />");
    }

    #[test]
    fn object_write_routing_hint_shapes_distributed_forwarding_state() {
        let peers = vec!["node-b:9000".to_string()];
        let hint = object_write_routing_hint("docs/object.txt", "node-a:9000", &peers);
        assert!(hint.distributed);
        assert!(hint.primary_owner.is_some());
        assert_eq!(
            hint.forward_target,
            if hint.is_local_primary_owner {
                None
            } else {
                hint.primary_owner.clone()
            }
        );
    }

    #[test]
    fn object_write_routing_hint_is_local_primary_for_standalone() {
        let hint = object_write_routing_hint("docs/object.txt", "node-a:9000", &[]);
        assert!(!hint.distributed);
        assert_eq!(hint.primary_owner.as_deref(), Some("node-a:9000"));
        assert_eq!(hint.forward_target, None);
        assert!(hint.is_local_primary_owner);
    }

    #[test]
    fn ensure_local_write_owner_accepts_local_primary_writes() {
        let hint = ObjectWriteRoutingHint {
            distributed: true,
            primary_owner: Some("node-a:9000".to_string()),
            forward_target: None,
            is_local_primary_owner: true,
        };
        assert!(ensure_local_write_owner(&hint).is_ok());
    }

    #[test]
    fn ensure_local_write_owner_rejects_non_owner_writes_with_forward_target() {
        let err = ensure_local_write_owner(&distributed_forwarding_hint())
            .expect_err("non-owner writes should be rejected");
        assert_eq!(err.code.as_str(), "AccessDenied");
        assert!(err.message.contains("non-owner node"));
        assert!(err.message.contains("node-b:9000"));
    }

    #[test]
    fn should_skip_forwarded_request_header_skips_only_transport_and_loop_headers() {
        assert!(should_skip_forwarded_request_header(&header::CONNECTION));
        assert!(should_skip_forwarded_request_header(
            &header::TRANSFER_ENCODING
        ));
        assert!(should_skip_forwarded_request_header(
            &header::CONTENT_LENGTH
        ));
        assert!(should_skip_forwarded_request_header(
            &header::HeaderName::from_static(INTERNAL_FORWARDED_BY_HEADER)
        ));
        assert!(!should_skip_forwarded_request_header(
            &header::HeaderName::from_static(INTERNAL_FORWARD_EPOCH_HEADER)
        ));
        assert!(!should_skip_forwarded_request_header(
            &header::HeaderName::from_static(INTERNAL_FORWARD_VIEW_ID_HEADER)
        ));
        assert!(!should_skip_forwarded_request_header(
            &header::HeaderName::from_static(INTERNAL_FORWARD_HOP_COUNT_HEADER)
        ));
        assert!(!should_skip_forwarded_request_header(
            &header::HeaderName::from_static(INTERNAL_FORWARD_MAX_HOPS_HEADER)
        ));
        assert!(!should_skip_forwarded_request_header(
            &header::HeaderName::from_static(INTERNAL_FORWARD_IDEMPOTENCY_KEY_HEADER)
        ));
        assert!(!should_skip_forwarded_request_header(
            &header::HeaderName::from_static("x-amz-date")
        ));
    }

    #[test]
    fn should_skip_forwarded_response_header_hides_internal_forwarding_protocol_headers() {
        assert!(should_skip_forwarded_response_header(&header::CONNECTION));
        assert!(should_skip_forwarded_response_header(
            &header::TRANSFER_ENCODING
        ));
        assert!(should_skip_forwarded_response_header(
            &header::HeaderName::from_static(INTERNAL_FORWARDED_BY_HEADER)
        ));
        assert!(should_skip_forwarded_response_header(
            &header::HeaderName::from_static(INTERNAL_FORWARD_EPOCH_HEADER)
        ));
        assert!(should_skip_forwarded_response_header(
            &header::HeaderName::from_static(INTERNAL_FORWARD_VIEW_ID_HEADER)
        ));
        assert!(should_skip_forwarded_response_header(
            &header::HeaderName::from_static(INTERNAL_FORWARD_HOP_COUNT_HEADER)
        ));
        assert!(should_skip_forwarded_response_header(
            &header::HeaderName::from_static(INTERNAL_FORWARD_MAX_HOPS_HEADER)
        ));
        assert!(should_skip_forwarded_response_header(
            &header::HeaderName::from_static(INTERNAL_FORWARD_IDEMPOTENCY_KEY_HEADER)
        ));
        assert!(should_skip_forwarded_response_header(
            &header::HeaderName::from_static(INTERNAL_TRUSTED_FORWARD_EPOCH_HEADER)
        ));
        assert!(should_skip_forwarded_response_header(
            &header::HeaderName::from_static(INTERNAL_TRUSTED_FORWARD_VIEW_ID_HEADER)
        ));
        assert!(should_skip_forwarded_response_header(
            &header::HeaderName::from_static(INTERNAL_TRUSTED_FORWARD_HOP_COUNT_HEADER)
        ));
        assert!(should_skip_forwarded_response_header(
            &header::HeaderName::from_static(INTERNAL_TRUSTED_FORWARD_MAX_HOPS_HEADER)
        ));
        assert!(should_skip_forwarded_response_header(
            &header::HeaderName::from_static(INTERNAL_TRUSTED_FORWARD_IDEMPOTENCY_KEY_HEADER)
        ));
        assert!(should_skip_forwarded_response_header(
            &header::HeaderName::from_static(INTERNAL_TRUSTED_FORWARD_OPERATION_HEADER)
        ));
        assert!(!should_skip_forwarded_response_header(
            &header::HeaderName::from_static("etag")
        ));
    }

    #[test]
    fn forwarded_write_envelope_ignores_untrusted_protocol_headers_without_internal_forward_marker()
    {
        let mut headers = HeaderMap::new();
        headers.insert(
            INTERNAL_FORWARD_EPOCH_HEADER,
            "999".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_FORWARD_VIEW_ID_HEADER,
            "tampered-view".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_FORWARD_HOP_COUNT_HEADER,
            "7".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_FORWARD_MAX_HOPS_HEADER,
            "9".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_FORWARD_IDEMPOTENCY_KEY_HEADER,
            "tampered-idempotency".parse().expect("header"),
        );

        let peers = vec!["node-b:9000".to_string()];
        let placement =
            PlacementViewState::from_membership(TEST_PLACEMENT_EPOCH, "node-a:9000", &peers);
        let envelope = forwarded_write_envelope_from_headers(
            &headers,
            ForwardedWriteOperation::PutObject,
            "bucket",
            "docs/object.txt",
            "node-a:9000",
            &placement,
        );

        assert_eq!(envelope.placement_epoch, TEST_PLACEMENT_EPOCH);
        assert_eq!(envelope.placement_view_id, placement.view_id);
        assert_eq!(envelope.hop_count, 0);
        assert_eq!(envelope.max_hops, FORWARD_MAX_HOPS_DEFAULT);
        assert_ne!(envelope.idempotency_key, "tampered-idempotency");
    }

    #[test]
    fn write_forward_target_rejects_looped_non_owner_request() {
        let mut headers = HeaderMap::new();
        headers.insert(INTERNAL_FORWARDED_BY_HEADER, "node-a:9000".parse().unwrap());
        let peers = vec!["node-b:9000".to_string()];
        let placement =
            PlacementViewState::from_membership(TEST_PLACEMENT_EPOCH, "node-a:9000", &peers);

        let err = write_forward_target(
            "bucket",
            "docs/object.txt",
            ForwardedWriteOperation::PutObject,
            &distributed_forwarding_hint(),
            &headers,
            "node-a:9000",
            &placement,
        )
        .expect_err("forward loop should be rejected");
        assert_eq!(err.code.as_str(), "AccessDenied");
        assert!(err.message.contains("loop"));
    }

    #[test]
    fn write_forward_target_returns_envelope_for_non_primary_owner() {
        let headers = HeaderMap::new();
        let peers = vec!["node-b:9000".to_string(), "node-c:9000".to_string()];
        let local_node = "node-a:9000";

        let (key, hint) = (0..4096)
            .find_map(|idx| {
                let key = format!("forward/hint-{idx}.txt");
                let hint = object_write_routing_hint(&key, local_node, &peers);
                if hint.distributed && !hint.is_local_primary_owner {
                    Some((key, hint))
                } else {
                    None
                }
            })
            .expect("expected at least one non-primary key");
        let placement =
            PlacementViewState::from_membership(TEST_PLACEMENT_EPOCH, local_node, &peers);

        let target = write_forward_target(
            "bucket-a",
            &key,
            ForwardedWriteOperation::PutObject,
            &hint,
            &headers,
            local_node,
            &placement,
        )
        .expect("forward target resolution should succeed")
        .expect("non-primary key should return forward target");

        assert_eq!(
            target.target,
            hint.primary_owner.expect("primary should exist")
        );
        assert_eq!(
            target.envelope.operation,
            ForwardedWriteOperation::PutObject
        );
        assert_eq!(target.envelope.bucket, "bucket-a");
        assert_eq!(target.envelope.key, key);
        assert_eq!(target.envelope.hop_count, 1);
        assert_eq!(target.envelope.max_hops, FORWARD_MAX_HOPS_DEFAULT);
        assert_eq!(target.envelope.visited_nodes, vec![local_node.to_string()]);
        assert_eq!(target.envelope.placement_epoch, TEST_PLACEMENT_EPOCH);
        assert!(!target.envelope.placement_view_id.is_empty());
        assert!(!target.envelope.idempotency_key.is_empty());
    }

    #[test]
    fn write_forward_target_rejects_view_mismatch() {
        let peers = vec!["node-b:9000".to_string(), "node-c:9000".to_string()];
        let local_node = "node-a:9000";
        let (key, hint) = (0..4096)
            .find_map(|idx| {
                let key = format!("forward/mismatch-{idx}.txt");
                let hint = object_write_routing_hint(&key, local_node, &peers);
                if hint.distributed && !hint.is_local_primary_owner {
                    Some((key, hint))
                } else {
                    None
                }
            })
            .expect("expected at least one non-primary key");

        let mut headers = HeaderMap::new();
        headers.insert(INTERNAL_FORWARDED_BY_HEADER, "node-x:9000".parse().unwrap());
        headers.insert(
            INTERNAL_FORWARD_VIEW_ID_HEADER,
            "wrong-view".parse().unwrap(),
        );
        let placement =
            PlacementViewState::from_membership(TEST_PLACEMENT_EPOCH, local_node, &peers);
        let err = write_forward_target(
            "bucket-a",
            &key,
            ForwardedWriteOperation::DeleteObject,
            &hint,
            &headers,
            local_node,
            &placement,
        )
        .expect_err("view mismatch should be rejected");
        assert_eq!(err.code.as_str(), "AccessDenied");
        assert!(err.message.contains("view mismatch"));
    }

    #[test]
    fn forwarded_write_envelope_prefers_trusted_internal_headers_for_forwarded_requests() {
        let mut headers = HeaderMap::new();
        headers.insert(
            INTERNAL_FORWARDED_BY_HEADER,
            "node-a:9000".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_FORWARD_EPOCH_HEADER,
            "999".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_FORWARD_VIEW_ID_HEADER,
            "legacy-tampered-view".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_FORWARD_HOP_COUNT_HEADER,
            "7".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_FORWARD_MAX_HOPS_HEADER,
            "9".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_FORWARD_IDEMPOTENCY_KEY_HEADER,
            "legacy-idempotency".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_EPOCH_HEADER,
            "42".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_VIEW_ID_HEADER,
            "trusted-view".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_HOP_COUNT_HEADER,
            "2".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_MAX_HOPS_HEADER,
            "6".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_IDEMPOTENCY_KEY_HEADER,
            "trusted-idempotency".parse().expect("header"),
        );

        let placement = PlacementViewState::from_membership(
            TEST_PLACEMENT_EPOCH,
            "node-a:9000",
            &["node-b:9000".to_string()],
        );
        let envelope = forwarded_write_envelope_from_headers(
            &headers,
            ForwardedWriteOperation::PutObject,
            "bucket",
            "docs/object.txt",
            "node-a:9000",
            &placement,
        );

        assert_eq!(envelope.placement_epoch, 42);
        assert_eq!(envelope.placement_view_id, "trusted-view");
        assert_eq!(envelope.hop_count, 2);
        assert_eq!(envelope.max_hops, 6);
        assert_eq!(envelope.idempotency_key, "trusted-idempotency");
    }

    #[test]
    fn forwarded_write_envelope_uses_trusted_internal_operation_for_replica_writes() {
        let mut headers = HeaderMap::new();
        headers.insert(
            INTERNAL_FORWARDED_BY_HEADER,
            "node-a:9000".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_OPERATION_HEADER,
            INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_PUT
                .parse()
                .expect("header"),
        );

        let placement = PlacementViewState::from_membership(
            TEST_PLACEMENT_EPOCH,
            "node-a:9000",
            &["node-b:9000".to_string()],
        );
        let envelope = forwarded_write_envelope_from_headers(
            &headers,
            ForwardedWriteOperation::PutObject,
            "bucket",
            "docs/object.txt",
            "node-a:9000",
            &placement,
        );

        assert_eq!(
            envelope.operation,
            ForwardedWriteOperation::ReplicatePutObject
        );
    }

    #[test]
    fn forwarded_write_envelope_uses_trusted_internal_operation_for_replica_heads() {
        let mut headers = HeaderMap::new();
        headers.insert(
            INTERNAL_FORWARDED_BY_HEADER,
            "node-a:9000".parse().expect("header"),
        );
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_OPERATION_HEADER,
            INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_HEAD
                .parse()
                .expect("header"),
        );

        let placement = PlacementViewState::from_membership(
            TEST_PLACEMENT_EPOCH,
            "node-a:9000",
            &["node-b:9000".to_string()],
        );
        let envelope = forwarded_write_envelope_from_headers(
            &headers,
            ForwardedWriteOperation::PutObject,
            "bucket",
            "docs/object.txt",
            "node-a:9000",
            &placement,
        );

        assert_eq!(
            envelope.operation,
            ForwardedWriteOperation::ReplicateHeadObject
        );
    }

    #[test]
    fn is_internal_replica_put_request_requires_forwarded_marker_and_trusted_operation() {
        let mut headers = HeaderMap::new();
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_OPERATION_HEADER,
            INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_PUT
                .parse()
                .expect("header"),
        );
        assert!(!is_internal_replica_put_request(&headers));

        headers.insert(
            INTERNAL_FORWARDED_BY_HEADER,
            "node-a:9000".parse().expect("header"),
        );
        assert!(is_internal_replica_put_request(&headers));
        assert!(!is_internal_replica_delete_request(&headers));
    }

    #[test]
    fn is_internal_replica_delete_request_requires_forwarded_marker_and_trusted_operation() {
        let mut headers = HeaderMap::new();
        headers.insert(
            INTERNAL_TRUSTED_FORWARD_OPERATION_HEADER,
            INTERNAL_TRUSTED_FORWARD_OPERATION_REPLICATE_DELETE
                .parse()
                .expect("header"),
        );
        assert!(!is_internal_replica_delete_request(&headers));

        headers.insert(
            INTERNAL_FORWARDED_BY_HEADER,
            "node-a:9000".parse().expect("header"),
        );
        assert!(is_internal_replica_delete_request(&headers));
        assert!(!is_internal_replica_put_request(&headers));
    }

    #[test]
    fn write_replica_count_for_membership_count_caps_to_two_nodes() {
        assert_eq!(write_replica_count_for_membership_count(0), 1);
        assert_eq!(write_replica_count_for_membership_count(1), 1);
        assert_eq!(write_replica_count_for_membership_count(2), 2);
        assert_eq!(write_replica_count_for_membership_count(3), 2);
    }

    #[test]
    fn object_path_and_query_encodes_path_and_sorts_query_keys() {
        let mut params = HashMap::new();
        params.insert("X-Amz-Date".to_string(), "20260302T101010Z".to_string());
        params.insert("versionId".to_string(), "v1 / part".to_string());

        let path = object_path_and_query("bucket", "docs/Jan 2026/cafe+notes.txt", &params);
        assert!(path.starts_with("/bucket/docs/Jan%202026/cafe%2Bnotes.txt?"));
        assert!(path.contains("X-Amz-Date=20260302T101010Z"));
        assert!(path.contains("versionId=v1%20%2F%20part"));
        assert!(
            path.find("X-Amz-Date").expect("query should contain date")
                < path
                    .find("versionId")
                    .expect("query should contain version"),
            "query parameters should be sorted"
        );
    }

    #[test]
    fn bucket_path_and_query_encodes_path_and_sorts_query_keys() {
        let mut params = HashMap::new();
        params.insert("delete".to_string(), String::new());
        params.insert("X-Amz-Date".to_string(), "20260302T101010Z".to_string());

        let path = bucket_path_and_query("my bucket", &params);
        assert!(path.starts_with("/my%20bucket?"));
        assert!(path.contains("X-Amz-Date=20260302T101010Z"));
        assert!(path.contains("delete="));
        assert!(
            path.find("X-Amz-Date").expect("query should contain date")
                < path.find("delete").expect("query should contain delete"),
            "query parameters should be sorted"
        );
    }

    #[tokio::test]
    async fn delete_objects_xml_response_sets_status_and_content_type() {
        let response = delete_objects_xml_response("<DeleteResult />".to_string())
            .expect("response should build");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/xml")
        );
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        assert_eq!(body.as_ref(), b"<DeleteResult />");
    }

    #[test]
    fn object_response_sets_common_headers_for_ok_response() {
        let meta = ObjectMeta {
            key: "docs/readme.txt".to_string(),
            size: 42,
            etag: "\"etag\"".to_string(),
            content_type: "text/plain".to_string(),
            last_modified: "2026-03-01T00:00:00Z".to_string(),
            version_id: Some("v1".to_string()),
            is_delete_marker: false,
            storage_format: None,
            checksum_algorithm: Some(ChecksumAlgorithm::SHA256),
            checksum_value: Some("checksum==".to_string()),
        };

        let response = object_response(&meta, StatusCode::OK, Body::empty(), meta.size, None)
            .expect("response should build");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok()),
            Some("42")
        );
        assert_eq!(
            response
                .headers()
                .get("x-amz-version-id")
                .and_then(|v| v.to_str().ok()),
            Some("v1")
        );
        assert_eq!(
            response
                .headers()
                .get("x-amz-checksum-sha256")
                .and_then(|v| v.to_str().ok()),
            Some("checksum==")
        );
        assert_eq!(
            response
                .headers()
                .get("accept-ranges")
                .and_then(|v| v.to_str().ok()),
            Some("bytes")
        );
    }

    #[test]
    fn object_response_sets_content_range_for_partial_response() {
        let meta = ObjectMeta {
            key: "docs/readme.txt".to_string(),
            size: 42,
            etag: "\"etag\"".to_string(),
            content_type: "text/plain".to_string(),
            last_modified: "2026-03-01T00:00:00Z".to_string(),
            version_id: None,
            is_delete_marker: false,
            storage_format: None,
            checksum_algorithm: None,
            checksum_value: None,
        };

        let response = object_response(
            &meta,
            StatusCode::PARTIAL_CONTENT,
            Body::empty(),
            10,
            Some((5, 14, 42)),
        )
        .expect("response should build");

        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            response
                .headers()
                .get("content-range")
                .and_then(|v| v.to_str().ok()),
            Some("bytes 5-14/42")
        );
        assert_eq!(
            response
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok()),
            Some("10")
        );
    }
}
