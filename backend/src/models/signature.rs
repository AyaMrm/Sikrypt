use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct RsaSignatureRequest {
    pub p: u128,
    pub q: u128,
    pub e: u128,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct RsaVerifyRequest {
    pub p: u128,
    pub q: u128,
    pub e: u128,
    pub message: String,
    pub signature: u128,
}

#[derive(Debug, Serialize)]
pub struct RsaSignatureResponse {
    pub signature: u128,
}

#[derive(Debug, Deserialize)]
pub struct DsaSignRequest {
    pub p: u128,
    pub q: u128,
    pub g: u128,
    pub private_key: u128,
    pub message: String,
    pub ephemeral_key: u128,
}

#[derive(Debug, Deserialize)]
pub struct DsaVerifyRequest {
    pub p: u128,
    pub q: u128,
    pub g: u128,
    pub public_key: u128,
    pub message: String,
    pub r: u128,
    pub s: u128,
}

#[derive(Debug, Serialize)]
pub struct PairSignatureResponse {
    pub r: u128,
    pub s: u128,
}

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
}

#[derive(Debug, Deserialize)]
pub struct EcdsaSignRequest {
    pub private_key: u128,
    pub message: String,
    pub ephemeral_key: u128,
}

#[derive(Debug, Deserialize)]
pub struct EcdsaVerifyRequest {
    pub public_key_x: u128,
    pub public_key_y: u128,
    pub message: String,
    pub r: u128,
    pub s: u128,
}

#[derive(Debug, Deserialize)]
pub struct ElGamalSignRequest {
    pub p: u128,
    pub g: u128,
    pub private_key: u128,
    pub message: String,
    pub ephemeral_key: u128,
}

#[derive(Debug, Deserialize)]
pub struct ElGamalVerifyRequest {
    pub p: u128,
    pub g: u128,
    pub public_key: u128,
    pub message: String,
    pub r: u128,
    pub s: u128,
}
