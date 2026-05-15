use axum::{extract::Json, http::StatusCode, routing::post, Router};

use crate::{
    algorithms::{
        asymmetric::rsa,
        signature::{
            dsa::{self, DsaError, DsaParameters, DsaSignature},
            ecdsa::{self, CurvePoint, EcdsaError, EcdsaSignature},
            elgamal::{self, ElGamalSignature, ElGamalSignatureError},
            rsa_pkcs1v15::{self, RsaPkcs1v15Error, RsaPkcs1v15Signature},
            rsa_pss::{self, RsaPssError, RsaPssSignature},
        },
    },
    errors::ApiError,
    models::signature::{
        DsaSignRequest, DsaVerifyRequest, EcdsaSignRequest, EcdsaVerifyRequest, ElGamalSignRequest,
        ElGamalVerifyRequest, PairSignatureResponse, RsaSignatureRequest, RsaSignatureResponse,
        RsaVerifyRequest, VerifyResponse,
    },
};

fn map_rsa_error(error: rsa::RsaError) -> ApiError {
    match error {
        rsa::RsaError::InvalidPrimeParameters => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_prime_parameters",
            "RSA requires distinct prime values for p and q",
        ),
        rsa::RsaError::InvalidPublicExponent => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_public_exponent",
            "RSA requires a valid public exponent e such that gcd(e, phi) = 1",
        ),
        rsa::RsaError::MessageTooLarge => ApiError::new(
            StatusCode::BAD_REQUEST,
            "message_too_large",
            "RSA message must be strictly smaller than n",
        ),
        rsa::RsaError::ModularInverseDoesNotExist => ApiError::new(
            StatusCode::BAD_REQUEST,
            "modular_inverse_error",
            "RSA could not compute the modular inverse for the chosen parameters",
        ),
    }
}

fn map_rsa_pss_error(error: RsaPssError) -> ApiError {
    match error {
        RsaPssError::InvalidModulus => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_modulus",
            "RSA signature requires a modulus greater than 1",
        ),
    }
}

fn map_dsa_error(error: DsaError) -> ApiError {
    match error {
        DsaError::InvalidParameters => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_parameters",
            "DSA parameters p, q, and g are invalid",
        ),
        DsaError::InvalidPrivateKey => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_private_key",
            "DSA private key must be in the range [1, q-1]",
        ),
        DsaError::InvalidEphemeralKey => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_ephemeral_key",
            "DSA ephemeral key must be in the range [1, q-1]",
        ),
        DsaError::ModularInverseDoesNotExist => ApiError::new(
            StatusCode::BAD_REQUEST,
            "modular_inverse_error",
            "DSA could not compute the modular inverse for the chosen parameters",
        ),
    }
}

fn map_rsa_pkcs1v15_error(error: RsaPkcs1v15Error) -> ApiError {
    match error {
        RsaPkcs1v15Error::InvalidModulus => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_modulus",
            "RSA signature requires a modulus greater than 1",
        ),
    }
}

fn map_elgamal_error(error: ElGamalSignatureError) -> ApiError {
    match error {
        ElGamalSignatureError::InvalidParameters => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_parameters",
            "ElGamal parameters p and g are invalid",
        ),
        ElGamalSignatureError::InvalidPrivateKey => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_private_key",
            "ElGamal private key must be in the range [1, p-2]",
        ),
        ElGamalSignatureError::InvalidEphemeralKey => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_ephemeral_key",
            "ElGamal ephemeral key must be coprime with p-1",
        ),
        ElGamalSignatureError::ModularInverseDoesNotExist => ApiError::new(
            StatusCode::BAD_REQUEST,
            "modular_inverse_error",
            "ElGamal could not compute the modular inverse for the chosen parameters",
        ),
    }
}

fn map_ecdsa_error(error: EcdsaError) -> ApiError {
    match error {
        EcdsaError::InvalidCurve => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_curve",
            "The demo ECDSA curve parameters are invalid",
        ),
        EcdsaError::InvalidPrivateKey => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_private_key",
            "ECDSA private key must be in the range [1, n-1]",
        ),
        EcdsaError::InvalidEphemeralKey => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_ephemeral_key",
            "ECDSA ephemeral key must be in the range [1, n-1]",
        ),
        EcdsaError::PointAtInfinity => ApiError::new(
            StatusCode::BAD_REQUEST,
            "point_at_infinity",
            "ECDSA produced the point at infinity with the chosen parameters",
        ),
        EcdsaError::ModularInverseDoesNotExist => ApiError::new(
            StatusCode::BAD_REQUEST,
            "modular_inverse_error",
            "ECDSA could not compute the modular inverse for the chosen parameters",
        ),
    }
}

async fn rsa_sign(
    Json(payload): Json<RsaSignatureRequest>,
) -> Result<Json<RsaSignatureResponse>, ApiError> {
    let key_pair = rsa::generate_key_pair(payload.p, payload.q, payload.e).map_err(map_rsa_error)?;
    let signature = rsa_pss::sign(&payload.message, &key_pair).map_err(map_rsa_pss_error)?;

    Ok(Json(RsaSignatureResponse {
        signature: signature.signature,
    }))
}

async fn rsa_verify(
    Json(payload): Json<RsaVerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let key_pair = rsa::generate_key_pair(payload.p, payload.q, payload.e).map_err(map_rsa_error)?;
    let signature = RsaPssSignature {
        signature: payload.signature,
    };
    let valid = rsa_pss::verify(&payload.message, &signature, &key_pair).map_err(map_rsa_pss_error)?;

    Ok(Json(VerifyResponse { valid }))
}

async fn rsa_pkcs1v15_sign(
    Json(payload): Json<RsaSignatureRequest>,
) -> Result<Json<RsaSignatureResponse>, ApiError> {
    let key_pair = rsa::generate_key_pair(payload.p, payload.q, payload.e).map_err(map_rsa_error)?;
    let signature =
        rsa_pkcs1v15::sign(&payload.message, &key_pair).map_err(map_rsa_pkcs1v15_error)?;

    Ok(Json(RsaSignatureResponse {
        signature: signature.signature,
    }))
}

async fn rsa_pkcs1v15_verify(
    Json(payload): Json<RsaVerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let key_pair = rsa::generate_key_pair(payload.p, payload.q, payload.e).map_err(map_rsa_error)?;
    let signature = RsaPkcs1v15Signature {
        signature: payload.signature,
    };
    let valid =
        rsa_pkcs1v15::verify(&payload.message, &signature, &key_pair).map_err(map_rsa_pkcs1v15_error)?;

    Ok(Json(VerifyResponse { valid }))
}

async fn dsa_sign(
    Json(payload): Json<DsaSignRequest>,
) -> Result<Json<PairSignatureResponse>, ApiError> {
    let parameters = DsaParameters {
        p: payload.p,
        q: payload.q,
        g: payload.g,
    };
    let signature = dsa::sign(
        &parameters,
        payload.private_key,
        &payload.message,
        payload.ephemeral_key,
    )
    .map_err(map_dsa_error)?;

    Ok(Json(PairSignatureResponse {
        r: signature.r,
        s: signature.s,
    }))
}

async fn dsa_verify(
    Json(payload): Json<DsaVerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let parameters = DsaParameters {
        p: payload.p,
        q: payload.q,
        g: payload.g,
    };
    let signature = DsaSignature {
        r: payload.r,
        s: payload.s,
    };
    let valid = dsa::verify(&parameters, payload.public_key, &payload.message, &signature)
        .map_err(map_dsa_error)?;

    Ok(Json(VerifyResponse { valid }))
}

async fn ecdsa_sign(
    Json(payload): Json<EcdsaSignRequest>,
) -> Result<Json<PairSignatureResponse>, ApiError> {
    let curve = ecdsa::demo_curve();
    let signature = ecdsa::sign(
        &curve,
        payload.private_key,
        &payload.message,
        payload.ephemeral_key,
    )
    .map_err(map_ecdsa_error)?;

    Ok(Json(PairSignatureResponse {
        r: signature.r,
        s: signature.s,
    }))
}

async fn ecdsa_verify(
    Json(payload): Json<EcdsaVerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let curve = ecdsa::demo_curve();
    let public_key = CurvePoint {
        x: payload.public_key_x,
        y: payload.public_key_y,
    };
    let signature = EcdsaSignature {
        r: payload.r,
        s: payload.s,
    };
    let valid = ecdsa::verify(&curve, public_key, &payload.message, &signature)
        .map_err(map_ecdsa_error)?;

    Ok(Json(VerifyResponse { valid }))
}

async fn elgamal_sign(
    Json(payload): Json<ElGamalSignRequest>,
) -> Result<Json<PairSignatureResponse>, ApiError> {
    let signature = elgamal::sign(
        payload.p,
        payload.g,
        payload.private_key,
        &payload.message,
        payload.ephemeral_key,
    )
    .map_err(map_elgamal_error)?;

    Ok(Json(PairSignatureResponse {
        r: signature.r,
        s: signature.s,
    }))
}

async fn elgamal_verify(
    Json(payload): Json<ElGamalVerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let signature = ElGamalSignature {
        r: payload.r,
        s: payload.s,
    };
    let valid = elgamal::verify(
        payload.p,
        payload.g,
        payload.public_key,
        &payload.message,
        &signature,
    )
    .map_err(map_elgamal_error)?;

    Ok(Json(VerifyResponse { valid }))
}

pub fn router() -> Router {
    Router::new()
        .route("/signature/rsa/sign", post(rsa_sign))
        .route("/signature/rsa/verify", post(rsa_verify))
    .route("/signature/rsa/pkcs1v15/sign", post(rsa_pkcs1v15_sign))
    .route("/signature/rsa/pkcs1v15/verify", post(rsa_pkcs1v15_verify))
        .route("/signature/dsa/sign", post(dsa_sign))
        .route("/signature/dsa/verify", post(dsa_verify))
        .route("/signature/ecdsa/sign", post(ecdsa_sign))
        .route("/signature/ecdsa/verify", post(ecdsa_verify))
    .route("/signature/elgamal/sign", post(elgamal_sign))
    .route("/signature/elgamal/verify", post(elgamal_verify))
}
