use axum::{Router, extract::Json, http::StatusCode, routing::post};

use crate::{
    algorithms::hash::{hmac_impl, md5, sha},
    errors::ApiError,
    models::hash::{DigestResponse, HashTextRequest, HmacRequest},
};

fn map_hmac_error(error: hmac_impl::HmacError) -> ApiError {
    match error {
        hmac_impl::HmacError::InvalidKeyLength => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_key_length",
            "The HMAC key is invalid",
        ),
    }
}

async fn md5_hash(Json(payload): Json<HashTextRequest>) -> Result<Json<DigestResponse>, ApiError> {
    Ok(Json(DigestResponse {
        digest: md5::md5(&payload.text),
    }))
}

async fn sha256_hash(
    Json(payload): Json<HashTextRequest>,
) -> Result<Json<DigestResponse>, ApiError> {
    Ok(Json(DigestResponse {
        digest: sha::sha256(&payload.text),
    }))
}

async fn sha512_hash(
    Json(payload): Json<HashTextRequest>,
) -> Result<Json<DigestResponse>, ApiError> {
    Ok(Json(DigestResponse {
        digest: sha::sha512(&payload.text),
    }))
}

async fn hmac_sha256_hash(
    Json(payload): Json<HmacRequest>,
) -> Result<Json<DigestResponse>, ApiError> {
    let digest =
        hmac_impl::hmac_sha256(payload.key.as_bytes(), &payload.text).map_err(map_hmac_error)?;

    Ok(Json(DigestResponse { digest }))
}

pub fn router() -> Router {
    Router::new()
        .route("/hash/md5", post(md5_hash))
        .route("/hash/sha256", post(sha256_hash))
        .route("/hash/sha512", post(sha512_hash))
        .route("/hash/hmac", post(hmac_sha256_hash))
}
