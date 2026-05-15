use axum::{extract::Json, http::StatusCode, routing::post, Router};

use crate::{
    algorithms::asymmetric::{
        diffie_hellman::{self, DiffieHellmanError, DiffieHellmanSetup},
        elgamal::{self, ElGamalError, ElGamalParameters},
        rsa::{self, RsaError},
    },
    errors::ApiError,
    models::asymmetric::{
        DiffieHellmanExchangeRequest, DiffieHellmanExchangeResponse, ElGamalEncryptRequest,
        ElGamalEncryptResponse, ElGamalDecryptRequest, ElGamalDecryptResponse, RsaDecryptRequest,
        RsaDecryptResponse, RsaEncryptRequest, RsaEncryptResponse,
    },
};

fn map_diffie_hellman_error(error: DiffieHellmanError) -> ApiError {
    match error {
        DiffieHellmanError::InvalidModulus => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_modulus",
            "Diffie-Hellman requires a modulus p greater than or equal to 3",
        ),
        DiffieHellmanError::InvalidGenerator => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_generator",
            "Diffie-Hellman requires a generator g in the range [2, p-1]",
        ),
        DiffieHellmanError::InvalidPrivateKey => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_private_key",
            "Diffie-Hellman private keys must be in the range [1, p-1]",
        ),
    }
}

fn map_rsa_error(error: RsaError) -> ApiError {
    match error {
        RsaError::InvalidPrimeParameters => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_prime_parameters",
            "RSA requires distinct prime values for p and q",
        ),
        RsaError::InvalidPublicExponent => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_public_exponent",
            "RSA requires a valid public exponent e such that gcd(e, phi) = 1",
        ),
        RsaError::MessageTooLarge => ApiError::new(
            StatusCode::BAD_REQUEST,
            "message_too_large",
            "RSA message or ciphertext must be strictly smaller than n",
        ),
        RsaError::ModularInverseDoesNotExist => ApiError::new(
            StatusCode::BAD_REQUEST,
            "modular_inverse_error",
            "RSA could not compute the modular inverse for the chosen parameters",
        ),
    }
}

fn map_elgamal_error(error: ElGamalError) -> ApiError {
    match error {
        ElGamalError::InvalidModulus => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_modulus",
            "ElGamal requires a modulus p greater than or equal to 3",
        ),
        ElGamalError::InvalidGenerator => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_generator",
            "ElGamal requires a generator g in the range [2, p-1]",
        ),
        ElGamalError::InvalidPrivateKey => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_private_key",
            "ElGamal private keys must be in the range [1, p-2]",
        ),
        ElGamalError::InvalidEphemeralKey => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_ephemeral_key",
            "ElGamal ephemeral keys must be in the range [1, p-2]",
        ),
        ElGamalError::MessageTooLarge => ApiError::new(
            StatusCode::BAD_REQUEST,
            "message_too_large",
            "ElGamal messages must be strictly smaller than p",
        ),
        ElGamalError::SharedSecretNotInvertible => ApiError::new(
            StatusCode::BAD_REQUEST,
            "shared_secret_not_invertible",
            "ElGamal could not invert the shared secret modulo p",
        ),
    }
}

async fn diffie_hellman_exchange(
    Json(payload): Json<DiffieHellmanExchangeRequest>,
) -> Result<Json<DiffieHellmanExchangeResponse>, ApiError> {
    let setup = DiffieHellmanSetup {
        p: payload.p,
        g: payload.g,
    };
    let exchange = diffie_hellman::perform_key_exchange(
        &setup,
        payload.alice_private,
        payload.bob_private,
    )
    .map_err(map_diffie_hellman_error)?;

    Ok(Json(DiffieHellmanExchangeResponse {
        alice_public: exchange.alice_public,
        bob_public: exchange.bob_public,
        shared_secret: exchange.shared_secret,
    }))
}

async fn rsa_encrypt(
    Json(payload): Json<RsaEncryptRequest>,
) -> Result<Json<RsaEncryptResponse>, ApiError> {
    let key_pair = rsa::generate_key_pair(payload.p, payload.q, payload.e).map_err(map_rsa_error)?;
    let ciphertext = rsa::encrypt(payload.message, &key_pair).map_err(map_rsa_error)?;

    Ok(Json(RsaEncryptResponse {
        ciphertext,
        n: key_pair.n,
        e: key_pair.e,
        d: key_pair.d,
    }))
}

async fn rsa_decrypt(
    Json(payload): Json<RsaDecryptRequest>,
) -> Result<Json<RsaDecryptResponse>, ApiError> {
    let key_pair = rsa::generate_key_pair(payload.p, payload.q, payload.e).map_err(map_rsa_error)?;
    if payload.ciphertext >= key_pair.n {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "ciphertext_too_large",
            "RSA ciphertext must be strictly smaller than n",
        ));
    }

    let message = rsa::decrypt(payload.ciphertext, &key_pair);
    Ok(Json(RsaDecryptResponse { message }))
}

async fn elgamal_encrypt(
    Json(payload): Json<ElGamalEncryptRequest>,
) -> Result<Json<ElGamalEncryptResponse>, ApiError> {
    let parameters = ElGamalParameters {
        p: payload.p,
        g: payload.g,
    };
    let key_pair =
        elgamal::generate_key_pair(&parameters, payload.private_key).map_err(map_elgamal_error)?;
    let ciphertext = elgamal::encrypt(
        &parameters,
        key_pair.public_key,
        payload.message,
        payload.ephemeral_key,
    )
    .map_err(map_elgamal_error)?;

    Ok(Json(ElGamalEncryptResponse {
        public_key: key_pair.public_key,
        c1: ciphertext.c1,
        c2: ciphertext.c2,
    }))
}

async fn elgamal_decrypt(
    Json(payload): Json<ElGamalDecryptRequest>,
) -> Result<Json<ElGamalDecryptResponse>, ApiError> {
    let parameters = ElGamalParameters {
        p: payload.p,
        g: payload.g,
    };
    let ciphertext = elgamal::ElGamalCiphertext {
        c1: payload.c1,
        c2: payload.c2,
    };
    let message = elgamal::decrypt(&parameters, payload.private_key, &ciphertext)
        .map_err(map_elgamal_error)?;

    Ok(Json(ElGamalDecryptResponse { message }))
}

pub fn router() -> Router {
    Router::new()
        .route("/asymmetric/dh/exchange", post(diffie_hellman_exchange))
        .route("/asymmetric/rsa/encrypt", post(rsa_encrypt))
        .route("/asymmetric/rsa/decrypt", post(rsa_decrypt))
        .route("/asymmetric/elgamal/encrypt", post(elgamal_encrypt))
        .route("/asymmetric/elgamal/decrypt", post(elgamal_decrypt))
}
