use axum::{extract::Json, http::StatusCode, routing::post, Router};

use crate::{
    algorithms::symmetric::{
        aes::{self, AesError, AesKeySize},
        des::{self, DesError},
        rc4::{self, Rc4Error},
    },
    errors::ApiError,
    models::symmetric::{
        AesEncryptResponse, BlockCipherDecryptRequest, BlockCipherEncryptRequest, DesEncryptResponse,
        PlaintextResponse, Rc4DecryptRequest, Rc4EncryptRequest, Rc4EncryptResponse,
    },
};

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn from_hex(value: &str) -> Result<Vec<u8>, ApiError> {
    if !value.len().is_multiple_of(2) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_hex",
            "Hex input must contain an even number of characters",
        ));
    }

    let mut bytes = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks_exact(2) {
        let pair = std::str::from_utf8(chunk).map_err(|_| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_hex",
                "Hex input contains invalid UTF-8 data",
            )
        })?;

        let byte = u8::from_str_radix(pair, 16).map_err(|_| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_hex",
                "Hex input contains non-hexadecimal characters",
            )
        })?;

        bytes.push(byte);
    }

    Ok(bytes)
}

fn map_rc4_error(error: Rc4Error) -> ApiError {
    match error {
        Rc4Error::EmptyKey => ApiError::new(
            StatusCode::BAD_REQUEST,
            "empty_key",
            "The RC4 key cannot be empty",
        ),
    }
}

fn map_des_error(error: DesError) -> ApiError {
    match error {
        DesError::InvalidKeyLength => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_key_length",
            "DES requires an 8-byte key",
        ),
        DesError::InvalidIvLength => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_iv_length",
            "DES-CBC requires an 8-byte IV",
        ),
        DesError::DecryptionFailed => ApiError::new(
            StatusCode::BAD_REQUEST,
            "decryption_failed",
            "DES decryption failed",
        ),
    }
}

fn map_aes_error(error: AesError) -> ApiError {
    match error {
        AesError::InvalidKeyLength => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_key_length",
            "AES requires a 16, 24, or 32-byte key",
        ),
        AesError::InvalidIvLength => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_iv_length",
            "AES-CBC requires a 16-byte IV",
        ),
        AesError::DecryptionFailed => ApiError::new(
            StatusCode::BAD_REQUEST,
            "decryption_failed",
            "AES decryption failed",
        ),
    }
}

fn key_size_label(key_size: AesKeySize) -> String {
    match key_size {
        AesKeySize::Bits128 => "AES-128".to_string(),
        AesKeySize::Bits192 => "AES-192".to_string(),
        AesKeySize::Bits256 => "AES-256".to_string(),
    }
}

async fn rc4_encrypt(
    Json(payload): Json<Rc4EncryptRequest>,
) -> Result<Json<Rc4EncryptResponse>, ApiError> {
    let output =
        rc4::encrypt(payload.key.as_bytes(), payload.plaintext.as_bytes()).map_err(map_rc4_error)?;

    Ok(Json(Rc4EncryptResponse {
        ciphertext_hex: to_hex(&output.ciphertext),
        keystream_hex: to_hex(&output.keystream),
    }))
}

async fn rc4_decrypt(
    Json(payload): Json<Rc4DecryptRequest>,
) -> Result<Json<PlaintextResponse>, ApiError> {
    let ciphertext = from_hex(&payload.ciphertext_hex)?;
    let output = rc4::decrypt(payload.key.as_bytes(), &ciphertext).map_err(map_rc4_error)?;
    let result = String::from_utf8(output.ciphertext).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_plaintext",
            "The decrypted RC4 output is not valid UTF-8 text",
        )
    })?;

    Ok(Json(PlaintextResponse { result }))
}

async fn des_encrypt(
    Json(payload): Json<BlockCipherEncryptRequest>,
) -> Result<Json<DesEncryptResponse>, ApiError> {
    let output = des::encrypt_cbc(
        payload.key.as_bytes(),
        payload.iv.as_bytes(),
        payload.plaintext.as_bytes(),
    )
    .map_err(map_des_error)?;

    Ok(Json(DesEncryptResponse {
        ciphertext_hex: to_hex(&output.ciphertext),
        iv_hex: to_hex(&output.iv),
    }))
}

async fn des_decrypt(
    Json(payload): Json<BlockCipherDecryptRequest>,
) -> Result<Json<PlaintextResponse>, ApiError> {
    let ciphertext = from_hex(&payload.ciphertext_hex)?;
    let plaintext = des::decrypt_cbc(
        payload.key.as_bytes(),
        payload.iv.as_bytes(),
        &ciphertext,
    )
    .map_err(map_des_error)?;
    let result = String::from_utf8(plaintext).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_plaintext",
            "The decrypted DES output is not valid UTF-8 text",
        )
    })?;

    Ok(Json(PlaintextResponse { result }))
}

async fn aes_encrypt(
    Json(payload): Json<BlockCipherEncryptRequest>,
) -> Result<Json<AesEncryptResponse>, ApiError> {
    let output = aes::encrypt_cbc(
        payload.key.as_bytes(),
        payload.iv.as_bytes(),
        payload.plaintext.as_bytes(),
    )
    .map_err(map_aes_error)?;

    Ok(Json(AesEncryptResponse {
        ciphertext_hex: to_hex(&output.ciphertext),
        iv_hex: to_hex(&output.iv),
        key_size: key_size_label(output.key_size),
    }))
}

async fn aes_decrypt(
    Json(payload): Json<BlockCipherDecryptRequest>,
) -> Result<Json<PlaintextResponse>, ApiError> {
    let ciphertext = from_hex(&payload.ciphertext_hex)?;
    let plaintext = aes::decrypt_cbc(
        payload.key.as_bytes(),
        payload.iv.as_bytes(),
        &ciphertext,
    )
    .map_err(map_aes_error)?;
    let result = String::from_utf8(plaintext).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_plaintext",
            "The decrypted AES output is not valid UTF-8 text",
        )
    })?;

    Ok(Json(PlaintextResponse { result }))
}

pub fn router() -> Router {
    Router::new()
        .route("/symmetric/rc4/encrypt", post(rc4_encrypt))
        .route("/symmetric/rc4/decrypt", post(rc4_decrypt))
        .route("/symmetric/des/encrypt", post(des_encrypt))
        .route("/symmetric/des/decrypt", post(des_decrypt))
        .route("/symmetric/aes/encrypt", post(aes_encrypt))
        .route("/symmetric/aes/decrypt", post(aes_decrypt))
}
