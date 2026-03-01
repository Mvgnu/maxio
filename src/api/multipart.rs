use std::collections::HashMap;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::Response,
};

use crate::error::S3Error;
use crate::server::AppState;
use crate::storage::{ChecksumAlgorithm, StorageError};
use crate::xml::{response::to_xml, types::*};

use super::object::{body_to_reader, extract_checksum};
use parsing::{parse_complete_parts, parse_part_number};

mod parsing;

const COMPLETE_BODY_MAX: usize = 1024 * 1024;

pub async fn create_multipart_upload(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response<Body>, S3Error> {
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
    Path((bucket, _key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response<Body>, S3Error> {
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
    body: Body,
) -> Result<Response<Body>, S3Error> {
    ensure_bucket_exists(&state, &bucket).await?;
    let upload_id = params
        .get("uploadId")
        .ok_or_else(|| S3Error::invalid_argument("missing uploadId"))?;

    let bytes = axum::body::to_bytes(body, COMPLETE_BODY_MAX)
        .await
        .map_err(S3Error::internal)?;
    let body_str = String::from_utf8_lossy(&bytes);
    let parts = parse_complete_parts(&body_str)?;

    let result = state
        .storage
        .complete_multipart_upload(&bucket, upload_id, &parts)
        .await
        .map_err(map_storage_err)?;

    let xml = to_xml(&CompleteMultipartUploadResult {
        location: format!("/{}/{}", bucket, key),
        bucket,
        key,
        etag: result.etag,
    })
    .map_err(S3Error::internal)?;

    let mut response = xml_response(StatusCode::OK, xml);
    if let (Some(algo), Some(val)) = (&result.checksum_algorithm, &result.checksum_value) {
        set_header(&mut response, algo.header_name(), val);
    }
    Ok(response)
}

pub async fn abort_multipart_upload(
    State(state): State<AppState>,
    Path((bucket, _key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response<Body>, S3Error> {
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
    Path((bucket, _key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response<Body>, S3Error> {
    ensure_bucket_exists(&state, &bucket).await?;
    let upload_id = params
        .get("uploadId")
        .ok_or_else(|| S3Error::invalid_argument("missing uploadId"))?;

    let (upload, parts) = state
        .storage
        .list_parts(&bucket, upload_id)
        .await
        .map_err(map_storage_err)?;

    let xml = to_xml(&ListPartsResult {
        bucket,
        key: upload.key,
        upload_id: upload_id.clone(),
        is_truncated: false,
        parts: parts
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

fn empty_response(status: StatusCode) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}

fn xml_response(status: StatusCode, xml: String) -> Response<Body> {
    let mut response = Response::new(Body::from(xml));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml"),
    );
    response
}

fn set_header(response: &mut Response<Body>, name: &str, value: &str) {
    if let (Ok(header_name), Ok(header_value)) = (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) {
        response.headers_mut().insert(header_name, header_value);
    }
}

async fn ensure_bucket_exists(state: &AppState, bucket: &str) -> Result<(), S3Error> {
    match state.storage.head_bucket(bucket).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(S3Error::no_such_bucket(bucket)),
        Err(e) => Err(S3Error::internal(e)),
    }
}

fn map_storage_err(err: StorageError) -> S3Error {
    match err {
        StorageError::NotFound(bucket) => S3Error::no_such_bucket(&bucket),
        StorageError::ChecksumMismatch(_) => S3Error::bad_checksum("x-amz-checksum"),
        StorageError::UploadNotFound(upload_id) => S3Error::no_such_upload(&upload_id),
        StorageError::InvalidKey(msg) if msg.contains("part too small") => {
            S3Error::entity_too_small()
        }
        StorageError::InvalidKey(msg)
            if msg.contains("part")
                || msg.contains("etag")
                || msg.contains("upload")
                || msg.contains("at least one") =>
        {
            S3Error::invalid_part(&msg)
        }
        StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
        _ => S3Error::internal(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::S3ErrorCode;

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
