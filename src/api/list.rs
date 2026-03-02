mod response;
mod service;

use std::collections::HashMap;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    response::Response,
};
use http::StatusCode;

use super::multipart;
use crate::error::S3Error;
use crate::server::AppState;
use crate::xml::types::*;
use response::{bucket_location_response, xml_response};

pub async fn handle_bucket_get(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response<Body>, S3Error> {
    tracing::debug!("GET /{} params={:?}", bucket, params);

    service::ensure_bucket_exists(&state, &bucket).await?;

    match service::resolve_bucket_get_operation(&params)? {
        service::BucketGetOperation::ListUploads => {
            multipart::list_multipart_uploads(State(state), Path(bucket)).await
        }
        service::BucketGetOperation::GetVersioning => {
            super::bucket::get_bucket_versioning(state, bucket).await
        }
        service::BucketGetOperation::GetLifecycle => {
            super::bucket::get_bucket_lifecycle(state, bucket).await
        }
        service::BucketGetOperation::ListVersions => {
            list_object_versions(state, bucket, params).await
        }
        service::BucketGetOperation::GetLocation => {
            tracing::debug!("GetBucketLocation for {}", bucket);
            bucket_location_response(&state.config.region)
        }
        service::BucketGetOperation::ListV2 => list_objects_v2(state, bucket, params).await,
        service::BucketGetOperation::ListV1 => list_objects_v1(state, bucket, params).await,
    }
}

async fn list_objects_v2(
    state: AppState,
    bucket: String,
    params: HashMap<String, String>,
) -> Result<Response<Body>, S3Error> {
    let query = service::ListV2Query::from_params(&params)?;
    service::validate_prefix(&query.prefix)?;

    let all_objects = state
        .storage
        .list_objects(&bucket, &query.prefix)
        .await
        .map_err(|e| service::map_bucket_storage_err(&bucket, e))?;

    let filtered = service::filter_objects_after(&all_objects, query.effective_start.as_deref());
    let (page, is_truncated) = service::paginate_objects(filtered, query.max_keys);
    let (contents, common_prefixes) =
        service::split_by_delimiter(&page, &query.prefix, query.delimiter.as_deref());

    let next_token = if is_truncated {
        page.last()
            .map(|meta| service::encode_continuation_token(&meta.key))
    } else {
        None
    };

    let result = ListBucketResult {
        name: bucket,
        prefix: query.prefix,
        key_count: contents.len() as i32 + common_prefixes.len() as i32,
        max_keys: query.max_keys as i32,
        is_truncated,
        contents,
        common_prefixes,
        continuation_token: query.continuation_token,
        next_continuation_token: next_token,
        delimiter: query.delimiter,
        start_after: query.start_after,
    };

    xml_response(StatusCode::OK, &result)
}

async fn list_objects_v1(
    state: AppState,
    bucket: String,
    params: HashMap<String, String>,
) -> Result<Response<Body>, S3Error> {
    let query = service::ListV1Query::from_params(&params)?;
    service::validate_prefix(&query.prefix)?;

    let all_objects = state
        .storage
        .list_objects(&bucket, &query.prefix)
        .await
        .map_err(|e| service::map_bucket_storage_err(&bucket, e))?;

    let filtered = service::filter_objects_after(&all_objects, query.marker.as_deref());
    let (page, is_truncated) = service::paginate_objects(filtered, query.max_keys);
    let (contents, common_prefixes) =
        service::split_by_delimiter(&page, &query.prefix, query.delimiter.as_deref());

    let next_marker = if is_truncated {
        page.last().map(|meta| meta.key.clone())
    } else {
        None
    };

    let result = ListBucketResultV1 {
        name: bucket,
        prefix: query.prefix,
        marker: query.marker.unwrap_or_default(),
        next_marker,
        max_keys: query.max_keys as i32,
        is_truncated,
        contents,
        common_prefixes,
        delimiter: query.delimiter,
    };

    xml_response(StatusCode::OK, &result)
}

async fn list_object_versions(
    state: AppState,
    bucket: String,
    params: HashMap<String, String>,
) -> Result<Response<Body>, S3Error> {
    let query = service::ListVersionsQuery::from_params(&params)?;
    service::validate_prefix(&query.prefix)?;

    let all_versions = state
        .storage
        .list_object_versions(&bucket, &query.prefix)
        .await
        .map_err(|e| service::map_bucket_storage_err(&bucket, e))?;

    let latest_per_key = service::latest_version_per_key(&all_versions);
    let filtered = service::filter_versions_after(
        &all_versions,
        query.key_marker.as_deref(),
        query.version_id_marker.as_deref(),
    );
    let (page, is_truncated, next_markers) = service::paginate_versions(filtered, query.max_keys);
    let page_owned: Vec<_> = page.into_iter().cloned().collect();
    let (versions, delete_markers) = service::split_version_entries(&page_owned, &latest_per_key);

    let result = ListVersionsResult {
        name: bucket,
        prefix: query.prefix,
        key_marker: query.key_marker.unwrap_or_default(),
        version_id_marker: query.version_id_marker.unwrap_or_default(),
        next_key_marker: next_markers.as_ref().map(|(key, _)| key.clone()),
        next_version_id_marker: next_markers.map(|(_, version_id)| version_id),
        max_keys: query.max_keys as i32,
        is_truncated,
        versions,
        delete_markers,
    };

    xml_response(StatusCode::OK, &result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::S3ErrorCode;
    use crate::storage::StorageError;

    #[test]
    fn map_bucket_storage_err_maps_not_found_to_no_such_bucket() {
        let err = service::map_bucket_storage_err(
            "missing",
            StorageError::NotFound("missing".to_string()),
        );
        assert!(matches!(err.code, S3ErrorCode::NoSuchBucket));
    }

    #[test]
    fn map_bucket_storage_err_maps_invalid_key_to_invalid_argument() {
        let err = service::map_bucket_storage_err(
            "bucket",
            StorageError::InvalidKey("invalid prefix".to_string()),
        );
        assert!(matches!(err.code, S3ErrorCode::InvalidArgument));
    }
}
