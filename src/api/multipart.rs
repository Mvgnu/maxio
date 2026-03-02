use std::collections::HashMap;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::Response,
};
use tokio::io::AsyncReadExt;

use crate::auth::signature_v4::{PresignRequest, generate_presigned_url};
use crate::error::S3Error;
use crate::server::AppState;
use crate::storage::ChecksumAlgorithm;
use crate::storage::placement::{
    ForwardedWriteEnvelope, ForwardedWriteOperation, ObjectWriteQuorumOutcome, PlacementViewState,
    WriteAckObservation, object_write_plan_with_self, object_write_quorum_outcome,
};
use crate::xml::{response::to_xml, types::*};

use super::object::{
    add_write_quorum_headers, body_to_reader, ensure_local_write_owner, extract_checksum,
    forward_replica_put_to_target, forward_write_to_target, object_path_and_query,
    object_write_routing_hint, write_forward_target, write_replica_count_for_membership_count,
};
use parsing::{parse_complete_parts, parse_part_number};
use service::{empty_response, ensure_bucket_exists, map_storage_err, set_header, xml_response};

mod parsing;
mod service;

const COMPLETE_BODY_MAX: usize = 1024 * 1024;

pub async fn create_multipart_upload(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
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
        ForwardedWriteOperation::CreateMultipartUpload,
        &routing_hint,
        &headers,
        state.node_id.as_ref(),
        &placement,
    )? {
        let mut params = HashMap::new();
        params.insert("uploads".to_string(), String::new());
        let path_and_query = object_path_and_query(&bucket, &key, &params);
        return forward_write_to_target(
            Method::POST,
            &forward.target,
            &path_and_query,
            &headers,
            Vec::new(),
            &forward.envelope,
        )
        .await;
    }
    ensure_local_write_owner(&routing_hint)?;

    ensure_bucket_exists(&state, &bucket).await?;

    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");
    let checksum_algorithm = headers
        .get("x-amz-checksum-algorithm")
        .and_then(|v| v.to_str().ok())
        .and_then(ChecksumAlgorithm::from_header_str);
    let upload = state
        .storage
        .create_multipart_upload(&bucket, &key, content_type, checksum_algorithm)
        .await
        .map_err(map_storage_err)?;

    let xml = to_xml(&InitiateMultipartUploadResult {
        bucket,
        key,
        upload_id: upload.upload_id,
    })
    .map_err(S3Error::internal)?;

    Ok(xml_response(StatusCode::OK, xml))
}

pub async fn upload_part(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
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
        ForwardedWriteOperation::UploadMultipartPart,
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
    ensure_local_write_owner(&routing_hint)?;

    ensure_bucket_exists(&state, &bucket).await?;

    let upload_id = params
        .get("uploadId")
        .ok_or_else(|| S3Error::invalid_argument("missing uploadId"))?;
    let part_number = params
        .get("partNumber")
        .ok_or_else(|| S3Error::invalid_argument("missing partNumber"))?
        .as_str();
    let part_number = parse_part_number(part_number)?;

    let checksum = extract_checksum(&headers);
    let reader = body_to_reader(&headers, body).await?;
    let part = state
        .storage
        .upload_part(&bucket, upload_id, part_number, reader, checksum)
        .await
        .map_err(map_storage_err)?;

    let mut response = empty_response(StatusCode::OK);
    set_header(&mut response, "ETag", &part.etag);
    if let (Some(algo), Some(val)) = (&part.checksum_algorithm, &part.checksum_value) {
        set_header(&mut response, algo.header_name(), val);
    }
    Ok(response)
}

pub async fn complete_multipart_upload(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    let routing_hint =
        object_write_routing_hint(&key, state.node_id.as_ref(), state.cluster_peers.as_slice());
    let placement = PlacementViewState::from_membership(
        state.placement_epoch(),
        state.node_id.as_ref(),
        state.cluster_peers.as_slice(),
    );
    let body_bytes = axum::body::to_bytes(body, COMPLETE_BODY_MAX)
        .await
        .map_err(S3Error::internal)?
        .to_vec();
    if let Some(forward) = write_forward_target(
        &bucket,
        &key,
        ForwardedWriteOperation::CompleteMultipartUpload,
        &routing_hint,
        &headers,
        state.node_id.as_ref(),
        &placement,
    )? {
        let path_and_query = object_path_and_query(&bucket, &key, &params);
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
    ensure_local_write_owner(&routing_hint)?;

    ensure_bucket_exists(&state, &bucket).await?;
    let upload_id = params
        .get("uploadId")
        .ok_or_else(|| S3Error::invalid_argument("missing uploadId"))?;

    let body_str = String::from_utf8_lossy(&body_bytes);
    let parts = parse_complete_parts(&body_str)?;

    let result = state
        .storage
        .complete_multipart_upload(&bucket, upload_id, &parts)
        .await
        .map_err(map_storage_err)?;
    let checksum_algorithm = result.checksum_algorithm;
    let checksum_value = result.checksum_value.clone();
    let version_id = result.version_id.clone();
    let quorum_outcome = if routing_hint.distributed && routing_hint.is_local_primary_owner {
        Some(
            replicate_completed_object_to_replica_owners(ReplicaCompleteRequest {
                state: &state,
                bucket: &bucket,
                key: &key,
                headers: &headers,
                placement: &placement,
                version_id: version_id.as_deref(),
                checksum_algorithm,
                checksum_value: checksum_value.as_deref(),
            })
            .await,
        )
    } else {
        None
    };

    let xml = to_xml(&CompleteMultipartUploadResult {
        location: format!("/{}/{}", bucket, key),
        bucket,
        key,
        etag: result.etag,
    })
    .map_err(S3Error::internal)?;

    let mut response = xml_response(StatusCode::OK, xml);
    if let (Some(algo), Some(val)) = (checksum_algorithm, checksum_value.as_deref()) {
        set_header(&mut response, algo.header_name(), val);
    }
    if let Some(outcome) = quorum_outcome {
        add_write_quorum_headers(response.headers_mut(), &outcome);
    }
    Ok(response)
}

fn checksum_algorithm_header_value(algorithm: ChecksumAlgorithm) -> &'static str {
    match algorithm {
        ChecksumAlgorithm::CRC32 => "CRC32",
        ChecksumAlgorithm::CRC32C => "CRC32C",
        ChecksumAlgorithm::SHA1 => "SHA1",
        ChecksumAlgorithm::SHA256 => "SHA256",
    }
}

fn replica_put_headers_for_complete(
    request_headers: &HeaderMap,
    content_type: &str,
    checksum_algorithm: Option<ChecksumAlgorithm>,
    checksum_value: Option<&str>,
) -> HeaderMap {
    let mut headers = request_headers.clone();
    headers.remove(header::AUTHORIZATION);
    let content_type = HeaderValue::from_str(content_type)
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
    headers.insert(header::CONTENT_TYPE, content_type);

    if let Some(algorithm) = checksum_algorithm {
        headers.insert(
            header::HeaderName::from_static("x-amz-checksum-algorithm"),
            HeaderValue::from_static(checksum_algorithm_header_value(algorithm)),
        );
        if let Some(value) = checksum_value.and_then(|raw| HeaderValue::from_str(raw).ok()) {
            headers.insert(
                header::HeaderName::from_static(algorithm.header_name()),
                value,
            );
        }
    }

    headers
}

fn presigned_replica_put_path_and_query(
    state: &AppState,
    signed_host: &str,
    bucket: &str,
    key: &str,
) -> Option<String> {
    let url = generate_presigned_url(PresignRequest {
        method: "PUT",
        scheme: "http",
        host: signed_host,
        path: &format!("/{bucket}/{key}"),
        extra_query_params: &[],
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

async fn replicate_completed_object_to_replica_owners(
    request: ReplicaCompleteRequest<'_>,
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
    let (mut object_reader, object_meta) = match request
        .state
        .storage
        .get_object(request.bucket, request.key)
        .await
    {
        Ok(value) => value,
        Err(_) => return object_write_quorum_outcome(&write_plan, &observations),
    };
    let mut object_bytes = Vec::new();
    if object_reader.read_to_end(&mut object_bytes).await.is_err() {
        return object_write_quorum_outcome(&write_plan, &observations);
    }
    let replica_headers = replica_put_headers_for_complete(
        request.headers,
        &object_meta.content_type,
        request.checksum_algorithm,
        request.checksum_value,
    );

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
        let signed_host = replica_headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(target.as_str());
        let Some(path_and_query) = presigned_replica_put_path_and_query(
            request.state,
            signed_host,
            request.bucket,
            request.key,
        ) else {
            observations.push(WriteAckObservation {
                node: target.clone(),
                acked: false,
            });
            continue;
        };
        let acked = match forward_replica_put_to_target(
            target,
            path_and_query.as_str(),
            &replica_headers,
            object_bytes.clone(),
            request.version_id,
            &envelope,
        )
        .await
        {
            Ok(response) => {
                let success = response.status().is_success();
                if !success {
                    tracing::warn!(
                        operation = "replicate-complete-multipart-upload",
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
                    operation = "replicate-complete-multipart-upload",
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

struct ReplicaCompleteRequest<'a> {
    state: &'a AppState,
    bucket: &'a str,
    key: &'a str,
    headers: &'a HeaderMap,
    placement: &'a PlacementViewState,
    version_id: Option<&'a str>,
    checksum_algorithm: Option<ChecksumAlgorithm>,
    checksum_value: Option<&'a str>,
}

pub async fn abort_multipart_upload(
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
        ForwardedWriteOperation::AbortMultipartUpload,
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
    ensure_local_write_owner(&routing_hint)?;

    ensure_bucket_exists(&state, &bucket).await?;
    let upload_id = params
        .get("uploadId")
        .ok_or_else(|| S3Error::invalid_argument("missing uploadId"))?;

    state
        .storage
        .abort_multipart_upload(&bucket, upload_id)
        .await
        .map_err(map_storage_err)?;

    Ok(empty_response(StatusCode::NO_CONTENT))
}

pub async fn list_parts(
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
        ForwardedWriteOperation::UploadMultipartPart,
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
    let query = service::ListPartsQuery::from_params(&params)?;

    let (upload, parts) = state
        .storage
        .list_parts(&bucket, &query.upload_id)
        .await
        .map_err(map_storage_err)?;
    let (page, is_truncated, next_part_number_marker) =
        service::paginate_parts(parts, query.part_number_marker, query.max_parts);

    let xml = to_xml(&ListPartsResult {
        bucket,
        key: upload.key,
        upload_id: query.upload_id,
        part_number_marker: query.part_number_marker,
        next_part_number_marker,
        max_parts: query.max_parts as u32,
        is_truncated,
        parts: page
            .into_iter()
            .map(|p| PartEntry {
                part_number: p.part_number,
                last_modified: p.last_modified,
                etag: p.etag,
                size: p.size,
            })
            .collect(),
    })
    .map_err(S3Error::internal)?;

    Ok(xml_response(StatusCode::OK, xml))
}

pub async fn list_multipart_uploads(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> Result<Response<Body>, S3Error> {
    ensure_bucket_exists(&state, &bucket).await?;

    let uploads = state
        .storage
        .list_multipart_uploads(&bucket)
        .await
        .map_err(map_storage_err)?;

    let xml = to_xml(&ListMultipartUploadsResult {
        bucket,
        is_truncated: false,
        uploads: uploads
            .into_iter()
            .map(|u| MultipartUploadEntry {
                key: u.key,
                upload_id: u.upload_id,
                initiated: u.initiated,
            })
            .collect(),
    })
    .map_err(S3Error::internal)?;

    Ok(xml_response(StatusCode::OK, xml))
}

#[cfg(test)]
mod tests {
    use super::service::{empty_response, map_storage_err, set_header, xml_response};
    use crate::error::S3ErrorCode;
    use crate::storage::StorageError;
    use axum::http::{StatusCode, header};

    #[test]
    fn xml_response_sets_status_and_content_type() {
        let response = xml_response(StatusCode::CREATED, "<ok/>".to_string());
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/xml")
        );
    }

    #[test]
    fn set_header_ignores_invalid_header_value() {
        let mut response = empty_response(StatusCode::OK);
        set_header(&mut response, "x-test", "valid");
        set_header(&mut response, "x-test", "bad\r\nvalue");

        assert_eq!(
            response
                .headers()
                .get("x-test")
                .and_then(|v| v.to_str().ok()),
            Some("valid")
        );
    }

    #[test]
    fn map_storage_err_missing_bucket_maps_to_no_such_bucket() {
        let err = map_storage_err(StorageError::NotFound("missing".to_string()));
        assert!(matches!(err.code, S3ErrorCode::NoSuchBucket));
        assert_eq!(err.code.status_code(), StatusCode::NOT_FOUND);
    }
}
