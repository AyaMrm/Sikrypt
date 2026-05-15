use axum::{routing::get, Json, Router};

use crate::{errors::ApiError, models::common::HealthResponse};

async fn health() -> Result<Json<HealthResponse>, ApiError> {
    Ok(Json(HealthResponse {
        status: "ok",
        service: "sikrypt-backend",
    }))
}

pub fn router() -> Router {
    Router::new().route("/health", get(health))
}
