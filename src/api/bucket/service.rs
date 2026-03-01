use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use serde::Serialize;

use crate::error::S3Error;
use crate::storage::StorageError;
use crate::storage::filesystem::FilesystemStorage;
use crate::xml::response::to_xml;

pub(super) async fn ensure_bucket_exists(
    storage: &FilesystemStorage,
    bucket: &str,
) -> Result<(), S3Error> {
    match storage.head_bucket(bucket).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(S3Error::no_such_bucket(bucket)),
        Err(err) => Err(S3Error::internal(err)),
    }
}

pub(super) fn map_bucket_storage_err(bucket: &str, err: StorageError) -> S3Error {
    match err {
        StorageError::NotFound(_) => S3Error::no_such_bucket(bucket),
        other => S3Error::internal(other),
    }
}

pub(super) fn map_lifecycle_storage_err(bucket: &str, err: StorageError) -> S3Error {
    match err {
        StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
        other => map_bucket_storage_err(bucket, other),
    }
}

pub(super) fn xml_response<T: Serialize>(
    status: StatusCode,
    payload: &T,
) -> Result<Response<Body>, S3Error> {
    let xml = to_xml(payload).map_err(S3Error::internal)?;
    Response::builder()
        .status(status)
        .header("content-type", "application/xml")
        .body(Body::from(xml))
        .map_err(S3Error::internal)
}

pub(super) fn empty_response(status: StatusCode) -> Result<Response<Body>, S3Error> {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .map_err(S3Error::internal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::S3ErrorCode;
    use crate::xml::types::VersioningConfiguration;
    use http::header;

    #[test]
    fn map_bucket_storage_err_maps_not_found_to_no_such_bucket() {
        let err = map_bucket_storage_err("missing", StorageError::NotFound("missing".to_string()));
        assert!(matches!(err.code, S3ErrorCode::NoSuchBucket));
    }

    #[test]
    fn map_lifecycle_storage_err_maps_invalid_key_to_invalid_argument() {
        let err = map_lifecycle_storage_err(
            "bucket",
            StorageError::InvalidKey("invalid lifecycle rule".to_string()),
        );
        assert!(matches!(err.code, S3ErrorCode::InvalidArgument));
    }

    #[test]
    fn xml_response_sets_content_type_and_status() {
        let payload = VersioningConfiguration {
            status: Some("Enabled".to_string()),
        };
        let response = xml_response(StatusCode::OK, &payload).expect("xml response should build");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&"application/xml".parse().expect("valid content-type"))
        );
    }

    #[test]
    fn empty_response_uses_requested_status() {
        let response = empty_response(StatusCode::NO_CONTENT).expect("empty response should build");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
}
