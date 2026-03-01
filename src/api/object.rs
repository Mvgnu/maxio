mod parsing;
mod service;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use std::collections::HashMap;
use tokio_util::io::ReaderStream;

use crate::error::S3Error;
use crate::server::AppState;
use crate::storage::StorageError;
use crate::xml::{response::to_xml, types::CopyObjectResult};
use parsing::{parse_copy_source, parse_delete_objects_request, parse_range, to_http_date};
use service::{
    DeleteObjectsOutcome, add_checksum_header, build_delete_objects_response_xml,
    map_delete_objects_err, map_delete_storage_err,
};

use super::multipart;
use service::ensure_bucket_exists;
pub(crate) use service::{body_to_reader, extract_checksum};

pub async fn put_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    if headers.contains_key("x-amz-copy-source") {
        return copy_object(State(state), Path((bucket, key)), headers).await;
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

    ensure_bucket_exists(&state, &bucket).await?;

    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");

    let mut reader = body_to_reader(&headers, body).await?;

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

    let result = state
        .storage
        .put_object(&bucket, &key, content_type, reader, checksum)
        .await
        .map_err(|e| match e {
            StorageError::NotFound(_) => S3Error::no_such_bucket(&bucket),
            StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
            StorageError::ChecksumMismatch(_) => S3Error::bad_checksum("x-amz-checksum"),
            _ => S3Error::internal(e),
        })?;

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
    builder.body(Body::empty()).map_err(S3Error::internal)
}

async fn copy_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response<Body>, S3Error> {
    let copy_source = headers
        .get("x-amz-copy-source")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| S3Error::invalid_argument("missing x-amz-copy-source header"))?;

    let (src_bucket, src_key) = parse_copy_source(copy_source)?;

    // Validate source and destination bucket existence.
    ensure_bucket_exists(&state, &src_bucket).await?;
    ensure_bucket_exists(&state, &bucket).await?;

    // Get source object
    let (reader, src_meta) = state
        .storage
        .get_object(&src_bucket, &src_key)
        .await
        .map_err(|e| match e {
            StorageError::NotFound(_) => S3Error::no_such_key(&src_key),
            StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
            _ => S3Error::internal(e),
        })?;

    // Determine content-type based on metadata directive
    let directive = headers
        .get("x-amz-metadata-directive")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("COPY");

    let content_type = match directive {
        "COPY" => src_meta.content_type.clone(),
        "REPLACE" => headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string(),
        _ => {
            return Err(S3Error::invalid_argument(
                "invalid x-amz-metadata-directive",
            ));
        }
    };

    // Propagate source checksum algorithm so it's recomputed during copy
    let checksum = src_meta.checksum_algorithm.map(|algo| (algo, None));

    // Write destination
    let result = state
        .storage
        .put_object(&bucket, &key, &content_type, reader, checksum)
        .await
        .map_err(|e| match e {
            StorageError::NotFound(_) => S3Error::no_such_bucket(&bucket),
            StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
            _ => S3Error::internal(e),
        })?;

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

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/xml");
    if let Some(vid) = &result.version_id {
        builder = builder.header("x-amz-version-id", vid.as_str());
    }
    builder.body(Body::from(xml)).map_err(S3Error::internal)
}

pub async fn get_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response<Body>, S3Error> {
    if params.contains_key("uploadId") {
        return multipart::list_parts(State(state), Path((bucket, key)), Query(params)).await;
    }

    ensure_bucket_exists(&state, &bucket).await?;

    let range_header = headers.get("range").and_then(|v| v.to_str().ok());

    if let Some(range_str) = range_header {
        let meta = state
            .storage
            .head_object(&bucket, &key)
            .await
            .map_err(|e| match e {
                StorageError::NotFound(_) => S3Error::no_such_key(&key),
                StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
                _ => S3Error::internal(e),
            })?;

        match parse_range(range_str, meta.size) {
            Ok(Some((start, end))) => {
                let length = end - start + 1;
                let (reader, _) = state
                    .storage
                    .get_object_range(&bucket, &key, start, length)
                    .await
                    .map_err(|e| match e {
                        StorageError::NotFound(_) => S3Error::no_such_key(&key),
                        _ => S3Error::internal(e),
                    })?;

                let stream = ReaderStream::new(reader);
                let body = Body::from_stream(stream);

                return Response::builder()
                    .status(StatusCode::PARTIAL_CONTENT)
                    .header("Content-Type", &meta.content_type)
                    .header("Content-Length", length.to_string())
                    .header(
                        "Content-Range",
                        format!("bytes {}-{}/{}", start, end, meta.size),
                    )
                    .header("Accept-Ranges", "bytes")
                    .header("ETag", &meta.etag)
                    .header("Last-Modified", to_http_date(&meta.last_modified))
                    .body(body)
                    .map_err(S3Error::internal);
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
            .map_err(|e| match e {
                StorageError::VersionNotFound(_) => S3Error::no_such_version(version_id),
                StorageError::NotFound(_) => S3Error::no_such_key(&key),
                StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
                _ => S3Error::internal(e),
            })?
    } else {
        state
            .storage
            .get_object(&bucket, &key)
            .await
            .map_err(|e| match e {
                StorageError::NotFound(_) => S3Error::no_such_key(&key),
                StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
                _ => S3Error::internal(e),
            })?
    };

    let stream = ReaderStream::new(reader);
    let body = Body::from_stream(stream);

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", &meta.content_type)
        .header("Content-Length", meta.size.to_string())
        .header("Accept-Ranges", "bytes")
        .header("ETag", &meta.etag)
        .header("Last-Modified", to_http_date(&meta.last_modified));
    if let Some(vid) = &meta.version_id {
        builder = builder.header("x-amz-version-id", vid.as_str());
    }
    builder = add_checksum_header(builder, &meta);
    builder.body(body).map_err(S3Error::internal)
}

pub async fn head_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response<Body>, S3Error> {
    ensure_bucket_exists(&state, &bucket).await?;

    let meta = if let Some(version_id) = params.get("versionId") {
        state
            .storage
            .head_object_version(&bucket, &key, version_id)
            .await
            .map_err(|e| match e {
                StorageError::VersionNotFound(_) => S3Error::no_such_version(version_id),
                StorageError::NotFound(_) => S3Error::no_such_key(&key),
                StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
                _ => S3Error::internal(e),
            })?
    } else {
        state
            .storage
            .head_object(&bucket, &key)
            .await
            .map_err(|e| match e {
                StorageError::NotFound(_) => S3Error::no_such_key(&key),
                StorageError::InvalidKey(msg) => S3Error::invalid_argument(&msg),
                _ => S3Error::internal(e),
            })?
    };

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", &meta.content_type)
        .header("Content-Length", meta.size.to_string())
        .header("ETag", &meta.etag)
        .header("Last-Modified", to_http_date(&meta.last_modified))
        .header("Accept-Ranges", "bytes");
    if let Some(vid) = &meta.version_id {
        builder = builder.header("x-amz-version-id", vid.as_str());
    }
    builder = add_checksum_header(builder, &meta);
    builder.body(Body::empty()).map_err(S3Error::internal)
}

pub async fn delete_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response<Body>, S3Error> {
    if params.contains_key("uploadId") {
        return multipart::abort_multipart_upload(State(state), Path((bucket, key)), Query(params))
            .await;
    }

    // Permanent version deletion
    if let Some(version_id) = params.get("versionId") {
        ensure_bucket_exists(&state, &bucket).await?;

        let deleted_meta = state
            .storage
            .delete_object_version(&bucket, &key, version_id)
            .await
            .map_err(|e| match e {
                StorageError::VersionNotFound(_) => S3Error::no_such_version(version_id),
                _ => map_delete_storage_err(&bucket, e),
            })?;

        let mut builder = Response::builder().status(StatusCode::NO_CONTENT);
        builder = builder.header("x-amz-version-id", version_id.as_str());
        if deleted_meta.is_delete_marker {
            builder = builder.header("x-amz-delete-marker", "true");
        }
        return builder.body(Body::empty()).map_err(S3Error::internal);
    }

    ensure_bucket_exists(&state, &bucket).await?;

    let result = state
        .storage
        .delete_object(&bucket, &key)
        .await
        .map_err(|e| map_delete_storage_err(&bucket, e))?;

    let mut builder = Response::builder().status(StatusCode::NO_CONTENT);
    if let Some(vid) = &result.version_id {
        builder = builder.header("x-amz-version-id", vid.as_str());
    }
    if result.is_delete_marker {
        builder = builder.header("x-amz-delete-marker", "true");
    }
    builder.body(Body::empty()).map_err(S3Error::internal)
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
            body,
        )
        .await;
    }
    Err(S3Error::not_implemented(
        "Unsupported POST object operation",
    ))
}

const DELETE_BODY_MAX: usize = 1024 * 1024;

/// Handle POST /{bucket}?delete — multi-object delete (DeleteObjects API).
pub async fn delete_objects(
    State(state): State<AppState>,
    Path(bucket): Path<String>,
    body: Body,
) -> Result<Response<Body>, S3Error> {
    ensure_bucket_exists(&state, &bucket).await?;

    let bytes = axum::body::to_bytes(body, DELETE_BODY_MAX)
        .await
        .map_err(|e| S3Error::internal(e))?;
    let body_str = std::str::from_utf8(&bytes).map_err(|_| S3Error::malformed_xml())?;
    let request = parse_delete_objects_request(body_str)?;

    let mut outcomes = Vec::with_capacity(request.keys.len());
    for key in request.keys {
        let delete_result = state.storage.delete_object(&bucket, &key).await;
        match delete_result {
            Ok(dr) => outcomes.push(DeleteObjectsOutcome::Deleted {
                key,
                version_id: dr.version_id,
                is_delete_marker: dr.is_delete_marker,
            }),
            Err(e) => outcomes.push(map_delete_objects_err(&bucket, key, e)),
        }
    }

    let response_xml = build_delete_objects_response_xml(&outcomes, request.quiet);

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/xml")
        .body(Body::from(response_xml))
        .map_err(S3Error::internal)
}
