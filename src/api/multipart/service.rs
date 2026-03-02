use axum::{
    body::Body,
    http::{HeaderName, HeaderValue, StatusCode, header},
    response::Response,
};
use std::collections::HashMap;

use crate::error::S3Error;
use crate::server::AppState;
use crate::storage::{PartMeta, StorageError};

const MAX_PARTS_CAP: usize = 1000;

#[derive(Debug)]
pub(super) struct ListPartsQuery {
    pub(super) upload_id: String,
    pub(super) part_number_marker: u32,
    pub(super) max_parts: usize,
}

impl ListPartsQuery {
    pub(super) fn from_params(params: &HashMap<String, String>) -> Result<Self, S3Error> {
        let upload_id = params
            .get("uploadId")
            .cloned()
            .ok_or_else(|| S3Error::invalid_argument("missing uploadId"))?;
        let part_number_marker = parse_part_number_marker(params)?;
        let max_parts = parse_max_parts(params)?;

        Ok(Self {
            upload_id,
            part_number_marker,
            max_parts,
        })
    }
}

pub(super) fn paginate_parts(
    all_parts: Vec<PartMeta>,
    part_number_marker: u32,
    max_parts: usize,
) -> (Vec<PartMeta>, bool, Option<u32>) {
    let filtered: Vec<PartMeta> = all_parts
        .into_iter()
        .filter(|part| part.part_number > part_number_marker)
        .collect();
    let is_truncated = filtered.len() > max_parts;
    let page: Vec<PartMeta> = filtered.into_iter().take(max_parts).collect();
    let next_part_number_marker = if is_truncated {
        page.last().map(|part| part.part_number)
    } else {
        None
    };
    (page, is_truncated, next_part_number_marker)
}

fn parse_part_number_marker(params: &HashMap<String, String>) -> Result<u32, S3Error> {
    let Some(raw_marker) = params.get("part-number-marker").map(String::as_str) else {
        return Ok(0);
    };

    raw_marker
        .parse::<u32>()
        .map_err(|_| S3Error::invalid_argument("Invalid part-number-marker value"))
}

fn parse_max_parts(params: &HashMap<String, String>) -> Result<usize, S3Error> {
    let Some(raw_max_parts) = params.get("max-parts").map(String::as_str) else {
        return Ok(MAX_PARTS_CAP);
    };

    let max_parts = raw_max_parts
        .parse::<usize>()
        .map_err(|_| S3Error::invalid_argument("Invalid max-parts value"))?;
    Ok(max_parts.min(MAX_PARTS_CAP))
}

pub(super) fn empty_response(status: StatusCode) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}

pub(super) fn xml_response(status: StatusCode, xml: String) -> Response<Body> {
    let mut response = Response::new(Body::from(xml));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml"),
    );
    response
}

pub(super) fn set_header(response: &mut Response<Body>, name: &str, value: &str) {
    if let (Ok(header_name), Ok(header_value)) = (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) {
        response.headers_mut().insert(header_name, header_value);
    }
}

pub(super) async fn ensure_bucket_exists(state: &AppState, bucket: &str) -> Result<(), S3Error> {
    match state.storage.head_bucket(bucket).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(S3Error::no_such_bucket(bucket)),
        Err(e) => Err(S3Error::internal(e)),
    }
}

pub(super) fn map_storage_err(err: StorageError) -> S3Error {
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
    use crate::storage::PartMeta;

    fn part_meta(part_number: u32) -> PartMeta {
        PartMeta {
            part_number,
            etag: format!("\"etag-{}\"", part_number),
            size: 10,
            last_modified: "2026-03-02T00:00:00Z".to_string(),
            checksum_algorithm: None,
            checksum_value: None,
        }
    }

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

    #[test]
    fn list_parts_query_defaults_marker_and_max_parts() {
        let mut params = HashMap::<String, String>::new();
        params.insert("uploadId".to_string(), "upload-1".to_string());

        let query = ListPartsQuery::from_params(&params).expect("query should parse");
        assert_eq!(query.upload_id, "upload-1");
        assert_eq!(query.part_number_marker, 0);
        assert_eq!(query.max_parts, MAX_PARTS_CAP);
    }

    #[test]
    fn list_parts_query_rejects_invalid_max_parts() {
        let mut params = HashMap::<String, String>::new();
        params.insert("uploadId".to_string(), "upload-1".to_string());
        params.insert("max-parts".to_string(), "abc".to_string());

        let err = ListPartsQuery::from_params(&params).expect_err("invalid max-parts should fail");
        assert!(matches!(err.code, S3ErrorCode::InvalidArgument));
    }

    #[test]
    fn list_parts_query_rejects_invalid_marker() {
        let mut params = HashMap::<String, String>::new();
        params.insert("uploadId".to_string(), "upload-1".to_string());
        params.insert("part-number-marker".to_string(), "abc".to_string());

        let err = ListPartsQuery::from_params(&params)
            .expect_err("invalid part-number-marker should fail");
        assert!(matches!(err.code, S3ErrorCode::InvalidArgument));
    }

    #[test]
    fn paginate_parts_respects_marker_and_max_parts() {
        let parts = vec![part_meta(1), part_meta(2), part_meta(3)];
        let (page, is_truncated, next_marker) = paginate_parts(parts, 1, 1);
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].part_number, 2);
        assert!(is_truncated);
        assert_eq!(next_marker, Some(2));
    }

    #[test]
    fn paginate_parts_handles_non_truncated_page() {
        let parts = vec![part_meta(1), part_meta(2), part_meta(3)];
        let (page, is_truncated, next_marker) = paginate_parts(parts, 2, 10);
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].part_number, 3);
        assert!(!is_truncated);
        assert_eq!(next_marker, None);
    }
}
