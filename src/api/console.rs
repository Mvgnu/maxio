mod auth;
mod buckets;
mod lifecycle;
mod objects;
mod presign;
mod response;
mod system;
mod versions;

use axum::{
    Router,
    routing::{delete, get, post, put},
};

use crate::server::AppState;

pub use auth::LoginRateLimiter;

pub fn console_router(state: AppState) -> Router<AppState> {
    let public = Router::new()
        .route("/auth/login", post(auth::login))
        .route("/auth/check", get(auth::check));

    let protected = Router::new()
        .route("/auth/logout", post(auth::logout))
        .route("/auth/me", get(auth::me))
        .route("/buckets", get(buckets::list_buckets))
        .route("/buckets", post(buckets::create_bucket))
        .route("/buckets/{bucket}", delete(buckets::delete_bucket_api))
        .route("/buckets/{bucket}/folders", post(objects::create_folder))
        .route("/buckets/{bucket}/objects", get(objects::list_objects))
        .route(
            "/buckets/{bucket}/objects/{*key}",
            delete(objects::delete_object_api),
        )
        .route(
            "/buckets/{bucket}/upload/{*key}",
            put(objects::upload_object),
        )
        .route(
            "/buckets/{bucket}/download/{*key}",
            get(objects::download_object),
        )
        .route(
            "/buckets/{bucket}/presign/{*key}",
            get(presign::presign_object),
        )
        .route(
            "/buckets/{bucket}/versioning",
            get(versions::get_versioning),
        )
        .route(
            "/buckets/{bucket}/versioning",
            put(versions::set_versioning),
        )
        .route("/buckets/{bucket}/lifecycle", get(lifecycle::get_lifecycle))
        .route("/buckets/{bucket}/lifecycle", put(lifecycle::set_lifecycle))
        .route("/system/health", get(system::get_health))
        .route("/system/metrics", get(system::get_metrics))
        .route("/system/topology", get(system::get_topology))
        .route("/buckets/{bucket}/versions", get(versions::list_versions))
        .route(
            "/buckets/{bucket}/versions/{version_id}/objects/{*key}",
            delete(versions::delete_version),
        )
        .route(
            "/buckets/{bucket}/versions/{version_id}/download/{*key}",
            get(versions::download_version),
        )
        .layer(axum::middleware::from_fn_with_state(
            state,
            auth::console_auth_middleware,
        ));

    public.merge(protected)
}
