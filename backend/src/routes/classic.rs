use axum::{extract::Json, http::StatusCode, routing::post, Router};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::{
    algorithms::classic::{
        affine::{self, AffineError},
        analysis,
        caesar,
        hill::{self, HillError, Matrix2x2},
        otp::{self, OtpError},
        playfair::{self, PlayfairError},
        vigenere::{self, VigenereError},
    },
    errors::ApiError,
    models::classic::{
        AffineRequest, CaesarBruteforceCandidateResponse, CaesarBruteforceRequest,
        CaesarBruteforceResponse, CaesarRequest, FrequencyAnalysisRequest, FrequencyAnalysisResponse,
        HillEncryptRequest, IndexCoincidenceRequest, IndexCoincidenceResponse, KasiskiCandidateResponse,
        KasiskiRequest, KasiskiResponse, LetterFrequencyResponse, OtpDecryptRequest, OtpEncryptRequest,
        OtpResponse, PlayfairRequest, TextResultResponse, VigenereEncryptRequest,
        VigenereEstimateKeyRequest, VigenereEstimateKeyResponse, VigenereKeyLengthListResponse,
        VigenereKeyLengthRequest, VigenereKeyLengthResponse,
    },
};

fn map_vigenere_error(error: VigenereError) -> ApiError {
    match error {
        VigenereError::EmptyKey => ApiError::new(
            StatusCode::BAD_REQUEST,
            "empty_key",
            "The Vigenere key cannot be empty",
        ),
        VigenereError::InvalidKey => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_key",
            "The Vigenere key must contain at least one alphabetic character",
        ),
    }
}

fn map_hill_error(error: HillError) -> ApiError {
    match error {
        HillError::InvalidMatrix => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_matrix",
            "The Hill ciphertext must contain an even number of alphabetic characters",
        ),
        HillError::NonInvertibleMatrix => ApiError::new(
            StatusCode::BAD_REQUEST,
            "non_invertible_matrix",
            "The Hill key matrix must be invertible modulo 26",
        ),
    }
}

fn map_affine_error(error: AffineError) -> ApiError {
    match error {
        AffineError::InvalidMultiplier => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_multiplier",
            "Affine cipher requires a multiplier coprime with 26",
        ),
    }
}

fn map_playfair_error(error: PlayfairError) -> ApiError {
    match error {
        PlayfairError::EmptyKey => ApiError::new(
            StatusCode::BAD_REQUEST,
            "empty_key",
            "Playfair key cannot be empty",
        ),
    }
}

fn map_otp_error(error: OtpError) -> ApiError {
    match error {
        OtpError::KeyLengthMismatch => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_key_length",
            "OTP key length must match the message length",
        ),
    }
}

fn matrix_from_request(key: [[i32; 2]; 2]) -> Matrix2x2 {
    Matrix2x2 {
        a11: key[0][0],
        a12: key[0][1],
        a21: key[1][0],
        a22: key[1][1],
    }
}

async fn caesar_encrypt(
    Json(payload): Json<CaesarRequest>,
) -> Result<Json<TextResultResponse>, ApiError> {
    Ok(Json(TextResultResponse {
        result: caesar::encrypt(&payload.text, payload.shift),
    }))
}

async fn caesar_decrypt(
    Json(payload): Json<CaesarRequest>,
) -> Result<Json<TextResultResponse>, ApiError> {
    Ok(Json(TextResultResponse {
        result: caesar::decrypt(&payload.text, payload.shift),
    }))
}

async fn caesar_bruteforce(
    Json(payload): Json<CaesarBruteforceRequest>,
) -> Result<Json<CaesarBruteforceResponse>, ApiError> {
    let candidates = caesar::brute_force_scored(&payload.text);
    let best = candidates.first();
    let response_candidates = candidates
        .iter()
        .map(|candidate| CaesarBruteforceCandidateResponse {
            shift: candidate.shift,
            plaintext: candidate.plaintext.clone(),
            score: candidate.score,
        })
        .collect();

    Ok(Json(CaesarBruteforceResponse {
        best_shift: best.map(|candidate| candidate.shift),
        best_plaintext: best.map(|candidate| candidate.plaintext.clone()),
        candidates: response_candidates,
    }))
}

async fn vigenere_encrypt(
    Json(payload): Json<VigenereEncryptRequest>,
) -> Result<Json<TextResultResponse>, ApiError> {
    let result = vigenere::encrypt(&payload.text, &payload.key).map_err(map_vigenere_error)?;

    Ok(Json(TextResultResponse { result }))
}

async fn vigenere_decrypt(
    Json(payload): Json<VigenereEncryptRequest>,
) -> Result<Json<TextResultResponse>, ApiError> {
    let result = vigenere::decrypt(&payload.text, &payload.key).map_err(map_vigenere_error)?;

    Ok(Json(TextResultResponse { result }))
}

async fn hill_encrypt(
    Json(payload): Json<HillEncryptRequest>,
) -> Result<Json<TextResultResponse>, ApiError> {
    let key = matrix_from_request(payload.key);
    let result = hill::encrypt(&payload.text, key).map_err(map_hill_error)?;

    Ok(Json(TextResultResponse { result }))
}

async fn hill_decrypt(
    Json(payload): Json<HillEncryptRequest>,
) -> Result<Json<TextResultResponse>, ApiError> {
    let key = matrix_from_request(payload.key);
    let result = hill::decrypt(&payload.text, key).map_err(map_hill_error)?;

    Ok(Json(TextResultResponse { result }))
}

async fn affine_encrypt(
    Json(payload): Json<AffineRequest>,
) -> Result<Json<TextResultResponse>, ApiError> {
    let result = affine::encrypt(&payload.text, payload.a, payload.b).map_err(map_affine_error)?;

    Ok(Json(TextResultResponse { result }))
}

async fn affine_decrypt(
    Json(payload): Json<AffineRequest>,
) -> Result<Json<TextResultResponse>, ApiError> {
    let result = affine::decrypt(&payload.text, payload.a, payload.b).map_err(map_affine_error)?;

    Ok(Json(TextResultResponse { result }))
}

async fn playfair_encrypt(
    Json(payload): Json<PlayfairRequest>,
) -> Result<Json<TextResultResponse>, ApiError> {
    let result = playfair::encrypt(&payload.text, &payload.key).map_err(map_playfair_error)?;

    Ok(Json(TextResultResponse { result }))
}

async fn playfair_decrypt(
    Json(payload): Json<PlayfairRequest>,
) -> Result<Json<TextResultResponse>, ApiError> {
    let result = playfair::decrypt(&payload.text, &payload.key).map_err(map_playfair_error)?;

    Ok(Json(TextResultResponse { result }))
}

async fn otp_encrypt(
    Json(payload): Json<OtpEncryptRequest>,
) -> Result<Json<OtpResponse>, ApiError> {
    let plaintext = STANDARD
        .decode(payload.plaintext_base64)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid_base64", "Invalid plaintext base64"))?;
    let key = STANDARD
        .decode(payload.key_base64)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid_base64", "Invalid key base64"))?;
    let output = otp::apply(&key, &plaintext).map_err(map_otp_error)?;

    Ok(Json(OtpResponse {
        result_base64: STANDARD.encode(output),
    }))
}

async fn otp_decrypt(
    Json(payload): Json<OtpDecryptRequest>,
) -> Result<Json<OtpResponse>, ApiError> {
    let ciphertext = STANDARD
        .decode(payload.ciphertext_base64)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid_base64", "Invalid ciphertext base64"))?;
    let key = STANDARD
        .decode(payload.key_base64)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid_base64", "Invalid key base64"))?;
    let output = otp::apply(&key, &ciphertext).map_err(map_otp_error)?;

    Ok(Json(OtpResponse {
        result_base64: STANDARD.encode(output),
    }))
}

async fn frequency_analysis(
    Json(payload): Json<FrequencyAnalysisRequest>,
) -> Result<Json<FrequencyAnalysisResponse>, ApiError> {
    let (total, frequencies) = analysis::frequency_analysis(&payload.text);
    let frequencies = frequencies
        .into_iter()
        .map(|entry| LetterFrequencyResponse {
            letter: entry.letter.to_string(),
            count: entry.count,
            frequency: entry.frequency,
        })
        .collect();

    Ok(Json(FrequencyAnalysisResponse {
        total_letters: total,
        frequencies,
    }))
}

async fn index_of_coincidence(
    Json(payload): Json<IndexCoincidenceRequest>,
) -> Result<Json<IndexCoincidenceResponse>, ApiError> {
    let (total, index) = analysis::index_of_coincidence(&payload.text);

    Ok(Json(IndexCoincidenceResponse {
        total_letters: total,
        index,
    }))
}

async fn kasiski_test(
    Json(payload): Json<KasiskiRequest>,
) -> Result<Json<KasiskiResponse>, ApiError> {
    let sequence_len = payload.sequence_len.unwrap_or(3).max(2);
    let max_key_len = payload.max_key_len.unwrap_or(20).max(2);
    let distances = analysis::kasiski_distances(&payload.text, sequence_len);
    let (gcd, candidates) = analysis::kasiski_candidates(&distances, max_key_len);

    Ok(Json(KasiskiResponse {
        distances: distances.iter().map(|value| *value as u32).collect(),
        gcd: gcd.map(|value| value as u32),
        candidates: candidates
            .into_iter()
            .map(|(key_length, score)| KasiskiCandidateResponse { key_length, score })
            .collect(),
    }))
}

async fn vigenere_key_length_ic(
    Json(payload): Json<VigenereKeyLengthRequest>,
) -> Result<Json<VigenereKeyLengthListResponse>, ApiError> {
    let candidates = analysis::ic_by_key_length(&payload.text, payload.max_length);
    let response = candidates
        .into_iter()
        .map(|(length, average_ic)| VigenereKeyLengthResponse { length, average_ic })
        .collect();

    Ok(Json(VigenereKeyLengthListResponse { candidates: response }))
}

async fn vigenere_estimate_key(
    Json(payload): Json<VigenereEstimateKeyRequest>,
) -> Result<Json<VigenereEstimateKeyResponse>, ApiError> {
    let key = analysis::estimate_vigenere_key(&payload.text, payload.key_length);

    Ok(Json(VigenereEstimateKeyResponse { key }))
}

pub fn router() -> Router {
    Router::new()
        .route("/classic/caesar/encrypt", post(caesar_encrypt))
        .route("/classic/caesar/decrypt", post(caesar_decrypt))
        .route("/classic/caesar/bruteforce", post(caesar_bruteforce))
        .route("/classic/vigenere/encrypt", post(vigenere_encrypt))
        .route("/classic/vigenere/decrypt", post(vigenere_decrypt))
        .route("/classic/hill/encrypt", post(hill_encrypt))
        .route("/classic/hill/decrypt", post(hill_decrypt))
        .route("/classic/affine/encrypt", post(affine_encrypt))
        .route("/classic/affine/decrypt", post(affine_decrypt))
        .route("/classic/playfair/encrypt", post(playfair_encrypt))
        .route("/classic/playfair/decrypt", post(playfair_decrypt))
        .route("/classic/otp/encrypt", post(otp_encrypt))
        .route("/classic/otp/decrypt", post(otp_decrypt))
        .route("/classic/analysis/frequency", post(frequency_analysis))
        .route("/classic/analysis/index-coincidence", post(index_of_coincidence))
        .route("/classic/analysis/kasiski", post(kasiski_test))
        .route("/classic/analysis/vigenere/key-length", post(vigenere_key_length_ic))
        .route("/classic/analysis/vigenere/estimate-key", post(vigenere_estimate_key))
}
