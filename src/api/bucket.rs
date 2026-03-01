mod validation;

use std::collections::HashMap;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::StatusCode,
    response::Response,
};

use crate::error::S3Error;
use crate::server::AppState;
use crate::storage::{BucketMeta, StorageError};
use crate::xml::{response::to_xml, types::*};
use validation::{
    parse_lifecycle_rules, parse_versioning_status, serialize_lifecycle_rules, validate_bucket_name,
};

pub async fn list_buckets(State(state): State<AppState>) -> Result<Response<Body>, S3Error> {
    let buckets = state
        .storage
        .list_buckets()
        .await
        .map_err(|e| S3Error::internal(e))?;

    let result = ListAllMyBucketsResult {
        owner: Owner {
            id: "maxio".to_string(),
            display_name: "maxio".to_string(),
        },
        buckets: Buckets {
            bucket: buckets
                .into_iter()
                .map(|b| BucketEntry {
                    name: b.name,
                    creation_date: b.created_at,
                })
                .collect(),
        },
    };

    let xml = to_xml(&result).map_err(|e| S3Error::internal(e))?;

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .body(Body::from(xml))
        .map_err(S3Error::internal)
}

pub async fn create_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> Result<Response<Body>, S3Error> {
    validate_bucket_name(&bucket)?;

    let now = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();

    let meta = BucketMeta {
        name: bucket.clone(),
        created_at: now,
        region: state.config.region.clone(),
        versioning: false,
    };

    let created = state
        .storage
        .create_bucket(&meta)
        .await
        .map_err(|e| S3Error::internal(e))?;

    if !created {
        return Err(S3Error::bucket_already_owned(&bucket));
    }

    Response::builder()
        .status(StatusCode::OK)
        .header("Location", format!("/{}", bucket))
        .body(Body::empty())
        .map_err(S3Error::internal)
}

pub async fn head_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> Result<Response<Body>, S3Error> {
    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return Err(S3Error::no_such_bucket(&bucket)),
        Err(e) => return Err(S3Error::internal(e)),
    }

    Response::builder()
        .status(StatusCode::OK)
        .header("x-amz-bucket-region", &*state.config.region)
        .body(Body::empty())
        .map_err(S3Error::internal)
}

pub async fn delete_bucket(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> Result<Response<Body>, S3Error> {
    match state.storage.delete_bucket(&bucket).await {
        Ok(true) => Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())
            .map_err(S3Error::internal),
        Ok(false) => Err(S3Error::no_such_bucket(&bucket)),
        Err(StorageError::BucketNotEmpty) => Err(S3Error::bucket_not_empty(&bucket)),
        Err(e) => Err(S3Error::internal(e)),
    }
}

pub async fn handle_bucket_delete(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response<Body>, S3Error> {
    if params.contains_key("lifecycle") {
        return delete_bucket_lifecycle(State(state), Path(bucket)).await;
    }
    delete_bucket(State(state), Path(bucket)).await
}

pub async fn handle_bucket_put(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    if params.contains_key("versioning") {
        return put_bucket_versioning(State(state), Path(bucket), body).await;
    }
    if params.contains_key("lifecycle") {
        return put_bucket_lifecycle(State(state), Path(bucket), body).await;
    }
    create_bucket(State(state), Path(bucket)).await
}

async fn put_bucket_versioning(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return Err(S3Error::no_such_bucket(&bucket)),
        Err(e) => return Err(S3Error::internal(e)),
    }

    let body_bytes = axum::body::to_bytes(body, 1024 * 64)
        .await
        .map_err(|e| S3Error::internal(e))?;
    let body_str = String::from_utf8_lossy(&body_bytes);
    let enabled = parse_versioning_status(&body_str)?;

    state
        .storage
        .set_versioning(&bucket, enabled)
        .await
        .map_err(|e| S3Error::internal(e))?;

    Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .map_err(S3Error::internal)
}

async fn put_bucket_lifecycle(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return Err(S3Error::no_such_bucket(&bucket)),
        Err(e) => return Err(S3Error::internal(e)),
    }

    let body_bytes = axum::body::to_bytes(body, 1024 * 256)
        .await
        .map_err(S3Error::internal)?;
    let body_str = String::from_utf8_lossy(&body_bytes);
    let rules = parse_lifecycle_rules(&body_str)?;

    state
        .storage
        .set_lifecycle_rules(&bucket, &rules)
        .await
        .map_err(|e| match e {
            StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
            StorageError::NotFound(_) => S3Error::no_such_bucket(&bucket),
            other => S3Error::internal(other),
        })?;

    Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .map_err(S3Error::internal)
}

async fn delete_bucket_lifecycle(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
) -> Result<Response<Body>, S3Error> {
    match state.storage.head_bucket(&bucket).await {
        Ok(true) => {}
        Ok(false) => return Err(S3Error::no_such_bucket(&bucket)),
        Err(e) => return Err(S3Error::internal(e)),
    }

    state
        .storage
        .set_lifecycle_rules(&bucket, &[])
        .await
        .map_err(|e| match e {
            StorageError::NotFound(_) => S3Error::no_such_bucket(&bucket),
            StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
            other => S3Error::internal(other),
        })?;

    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .map_err(S3Error::internal)
}

pub async fn get_bucket_versioning(
    state: AppState,
    bucket: String,
) -> Result<Response<Body>, S3Error> {
    let versioned = state
        .storage
        .is_versioned(&bucket)
        .await
        .map_err(|e| S3Error::internal(e))?;

    let result = VersioningConfiguration {
        status: if versioned {
            Some("Enabled".to_string())
        } else {
            None
        },
    };

    let xml = to_xml(&result).map_err(|e| S3Error::internal(e))?;
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .body(Body::from(xml))
        .map_err(S3Error::internal)
}

pub async fn get_bucket_lifecycle(
    state: AppState,
    bucket: String,
) -> Result<Response<Body>, S3Error> {
    let rules = state
        .storage
        .get_lifecycle_rules(&bucket)
        .await
        .map_err(|e| match e {
            StorageError::NotFound(_) => S3Error::no_such_bucket(&bucket),
            other => S3Error::internal(other),
        })?;

    if rules.is_empty() {
        return Err(S3Error::no_such_lifecycle_configuration(&bucket));
    }

    let result = serialize_lifecycle_rules(rules);
    let xml = to_xml(&result).map_err(S3Error::internal)?;
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml")
        .body(Body::from(xml))
        .map_err(S3Error::internal)
}
