use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct DiffieHellmanExchangeRequest {
    pub p: u128,
    pub g: u128,
    pub alice_private: u128,
    pub bob_private: u128,
}

#[derive(Debug, Serialize)]
pub struct DiffieHellmanExchangeResponse {
    pub alice_public: u128,
    pub bob_public: u128,
    pub shared_secret: u128,
}

#[derive(Debug, Deserialize)]
pub struct RsaEncryptRequest {
    pub p: u128,
    pub q: u128,
    pub e: u128,
    pub message: u128,
}

#[derive(Debug, Serialize)]
pub struct RsaEncryptResponse {
    pub ciphertext: u128,
    pub n: u128,
    pub e: u128,
    pub d: u128,
}

#[derive(Debug, Deserialize)]
pub struct RsaDecryptRequest {
    pub p: u128,
    pub q: u128,
    pub e: u128,
    pub ciphertext: u128,
}

#[derive(Debug, Serialize)]
pub struct RsaDecryptResponse {
    pub message: u128,
}

#[derive(Debug, Deserialize)]
pub struct ElGamalEncryptRequest {
    pub p: u128,
    pub g: u128,
    pub private_key: u128,
    pub message: u128,
    pub ephemeral_key: u128,
}

#[derive(Debug, Serialize)]
pub struct ElGamalEncryptResponse {
    pub public_key: u128,
    pub c1: u128,
    pub c2: u128,
}

#[derive(Debug, Deserialize)]
pub struct ElGamalDecryptRequest {
    pub p: u128,
    pub g: u128,
    pub private_key: u128,
    pub c1: u128,
    pub c2: u128,
}

#[derive(Debug, Serialize)]
pub struct ElGamalDecryptResponse {
    pub message: u128,
}

#[derive(Debug, Serialize)]
pub struct EccKeyGenResponse {
    pub public_key_base64: String,
    pub private_key_base64: String,
}

#[derive(Debug, Deserialize)]
pub struct EccDeriveRequest {
    pub private_key_base64: String,
    pub peer_public_key_base64: String,
}

#[derive(Debug, Serialize)]
pub struct EccDeriveResponse {
    pub shared_secret_base64: String,
}
