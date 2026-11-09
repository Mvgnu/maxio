use axum::{
    Router,
    extract::{Query, Request},
    middleware::{self, Next},
    response::Response,
    routing::{delete, get, head, post, put},
};
use std::collections::HashMap;

use crate::{error::S3Error, server::AppState};

use super::{bucket, list, object};

pub fn s3_router() -> Router<AppState> {
    Router::new()
        .route("/", get(bucket::list_buckets))
        // Bucket routes — with and without trailing slash
        .route("/{bucket}", put(bucket::handle_bucket_put))
        .route("/{bucket}/", put(bucket::handle_bucket_put))
        .route("/{bucket}", head(bucket::head_bucket))
        .route("/{bucket}/", head(bucket::head_bucket))
        .route("/{bucket}", delete(bucket::handle_bucket_delete))
        .route("/{bucket}/", delete(bucket::handle_bucket_delete))
        .route("/{bucket}", get(list::handle_bucket_get))
        .route("/{bucket}/", get(list::handle_bucket_get))
        // POST for DeleteObjects (multi-object delete)
        .route("/{bucket}", post(object::delete_objects))
        .route("/{bucket}/", post(object::delete_objects))
        // Object routes
        .route("/{bucket}/{*key}", post(object::post_object))
        .route("/{bucket}/{*key}", put(object::put_object))
        .route("/{bucket}/{*key}", get(object::get_object))
        .route("/{bucket}/{*key}", head(object::head_object))
        .route("/{bucket}/{*key}", delete(object::delete_object))
        .route_layer(middleware::from_fn(reject_unsupported_retention))
}

/// A protection request must never fall through to an ordinary object operation.
/// Keep this on the S3 router so multipart, copy and batch dispatch cannot bypass
/// it. The runtime applies signed-request authentication outside this layer.
async fn reject_unsupported_retention(
    Query(params): Query<HashMap<String, String>>,
    request: Request,
    next: Next,
) -> Result<Response, S3Error> {
    let subresource = ["retention", "legal-hold", "object-lock"]
        .iter()
        .any(|name| params.contains_key(*name));
    let header = request.headers().keys().any(|name| {
        name.as_str().starts_with("x-amz-object-lock-")
            || matches!(
                name.as_str(),
                "x-amz-bucket-object-lock-enabled" | "x-amz-bypass-governance-retention"
            )
    });
    if subresource || header {
        return Err(S3Error::not_implemented(
            "S3 Object Lock, retention periods and legal holds are not supported",
        ));
    }
    Ok(next.run(request).await)
}
