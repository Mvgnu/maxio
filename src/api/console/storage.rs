use axum::http::StatusCode;
use axum::response::Response;

use super::response;
use crate::server::AppState;
use crate::storage::StorageError;

pub(super) async fn ensure_bucket_exists(state: &AppState, bucket: &str) -> Result<(), Response> {
    match state.storage.head_bucket(bucket).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(bucket_not_found()),
        Err(err) => Err(internal_err(err)),
    }
}

pub(super) fn bucket_not_found() -> Response {
    response::error(StatusCode::NOT_FOUND, "Bucket not found")
}

pub(super) fn version_not_found() -> Response {
    response::error(StatusCode::NOT_FOUND, "Version not found")
}

pub(super) fn internal_err(err: impl std::fmt::Display) -> Response {
    response::error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

pub(super) fn map_bucket_storage_err(err: StorageError) -> Response {
    match err {
        StorageError::NotFound(_) => bucket_not_found(),
        other => internal_err(other),
    }
}

pub(super) fn map_version_delete_err(err: StorageError) -> Response {
    match err {
        StorageError::VersionNotFound(_) | StorageError::NotFound(_) => version_not_found(),
        other => internal_err(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response_status(response: Response) -> StatusCode {
        response.status()
    }

    #[test]
    fn map_bucket_storage_err_maps_not_found_to_404() {
        let status = response_status(map_bucket_storage_err(StorageError::NotFound(
            "bucket".to_string(),
        )));
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn map_bucket_storage_err_maps_other_errors_to_500() {
        let status = response_status(map_bucket_storage_err(StorageError::InvalidKey(
            "bad".to_string(),
        )));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn map_version_delete_err_maps_not_found_to_404() {
        let status = response_status(map_version_delete_err(StorageError::VersionNotFound(
            "missing".to_string(),
        )));
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn map_version_delete_err_maps_other_errors_to_500() {
        let status = response_status(map_version_delete_err(StorageError::InvalidKey(
            "bad".to_string(),
        )));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }
}
