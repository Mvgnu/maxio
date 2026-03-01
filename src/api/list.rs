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
use crate::xml::{response::to_xml, types::*};

pub async fn handle_bucket_get(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response<Body>, S3Error> {
    tracing::debug!("GET /{} params={:?}", bucket, params);

    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return Err(S3Error::no_such_bucket(&bucket)),
        Err(e) => return Err(S3Error::internal(e)),
    }

    if params.contains_key("uploads") {
        return multipart::list_multipart_uploads(State(state), Path(bucket)).await;
    }

    if params.contains_key("versioning") {
        return super::bucket::get_bucket_versioning(state, bucket).await;
    }

    if params.contains_key("lifecycle") {
        return super::bucket::get_bucket_lifecycle(state, bucket).await;
    }

    if params.contains_key("versions") {
        return list_object_versions(state, bucket, params).await;
    }

    // Handle ?location query (GetBucketLocation)
    if params.contains_key("location") {
        tracing::debug!("GetBucketLocation for {}", bucket);
        let xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <LocationConstraint>{}</LocationConstraint>",
            state.config.region
        );
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/xml")
            .body(Body::from(xml))
            .unwrap());
    }

    if params.get("list-type").map(|v| v.as_str()) == Some("2") {
        list_objects_v2(state, bucket, params).await
    } else {
        list_objects_v1(state, bucket, params).await
    }
}

async fn list_objects_v2(
    state: AppState,
    bucket: String,
    params: HashMap<String, String>,
) -> Result<Response<Body>, S3Error> {
    let query = service::ListV2Query::from_params(&params);

    let all_objects = state
        .storage
        .list_objects(&bucket, &query.prefix)
        .await
        .map_err(|e| S3Error::internal(e))?;

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

    let xml = to_xml(&result).map_err(|e| S3Error::internal(e))?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .body(Body::from(xml))
        .unwrap())
}

async fn list_objects_v1(
    state: AppState,
    bucket: String,
    params: HashMap<String, String>,
) -> Result<Response<Body>, S3Error> {
    let query = service::ListV1Query::from_params(&params);

    let all_objects = state
        .storage
        .list_objects(&bucket, &query.prefix)
        .await
        .map_err(|e| S3Error::internal(e))?;

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

    let xml = to_xml(&result).map_err(|e| S3Error::internal(e))?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .body(Body::from(xml))
        .unwrap())
}

async fn list_object_versions(
    state: AppState,
    bucket: String,
    params: HashMap<String, String>,
) -> Result<Response<Body>, S3Error> {
    let prefix = params.get("prefix").cloned().unwrap_or_default();

    let all_versions = state
        .storage
        .list_object_versions(&bucket, &prefix)
        .await
        .map_err(|e| S3Error::internal(e))?;

    let latest_per_key = service::latest_version_per_key(&all_versions);
    let (versions, delete_markers) = service::split_version_entries(&all_versions, &latest_per_key);

    let result = ListVersionsResult {
        name: bucket,
        prefix,
        key_marker: String::new(),
        version_id_marker: String::new(),
        max_keys: 1000,
        is_truncated: false,
        versions,
        delete_markers,
    };

    let xml = to_xml(&result).map_err(|e| S3Error::internal(e))?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .body(Body::from(xml))
        .unwrap())
}
