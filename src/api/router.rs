use axum::{
    Router,
    routing::{delete, get, head, post, put},
};

use crate::server::AppState;

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
}
