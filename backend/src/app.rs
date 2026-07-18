use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderName, StatusCode};
use std::time::Duration;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::{errors::ApiError, routes};

async fn not_found() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        "not_found",
        "The requested route does not exist",
    )
}

fn read_env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn read_env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn cors_layer() -> CorsLayer {
    let origins = std::env::var("SIKRYPT_CORS_ORIGINS").unwrap_or_else(|_| {
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:8080,http://127.0.0.1:8080"
            .to_string()
    });

    if origins.trim() == "*" {
        CorsLayer::new()
            .allow_methods(Any)
            .allow_headers(Any)
            .allow_origin(Any)
    } else {
        let allow_list: Vec<_> = origins
            .split(',')
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .filter_map(|value| value.parse().ok())
            .collect();

        CorsLayer::new()
            .allow_methods(Any)
            .allow_headers(Any)
            .allow_origin(allow_list)
    }
}

fn require_api_key_configuration() -> String {
    let key = std::env::var("SIKRYPT_API_KEY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    if let Some(key) = key {
        return key;
    }

    if cfg!(debug_assertions) {
        tracing::warn!(
            "SIKRYPT_API_KEY is not set; using a development fallback key. Set SIKRYPT_API_KEY for production."
        );
        return "dev-sikrypt-api-key".to_string();
    }

    panic!("SIKRYPT_API_KEY must be configured before starting Sikrypt");
}

pub fn create_app() -> Router {
    let api_key = require_api_key_configuration();

    let request_id_header = HeaderName::from_static("x-request-id");
    let timeout_ms = read_env_u64("SIKRYPT_REQUEST_TIMEOUT_MS", 15000);
    let concurrency_limit = read_env_usize("SIKRYPT_CONCURRENCY_LIMIT", 128);

    Router::new()
        .merge(routes::asymmetric::router())
        .merge(routes::classic::router())
        .merge(routes::comms::router())
        .merge(routes::crypto::router(api_key))
        .merge(routes::health::router())
        .merge(routes::hash::router())
        .merge(routes::openapi::router())
        .merge(routes::signature::router())
        .merge(routes::symmetric::router())
        .merge(routes::ws::router())
        .layer(TraceLayer::new_for_http())
        .layer(cors_layer())
        .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid))
        .layer(TimeoutLayer::new(Duration::from_millis(timeout_ms)))
        .layer(ConcurrencyLimitLayer::new(concurrency_limit))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .fallback(not_found)
}
