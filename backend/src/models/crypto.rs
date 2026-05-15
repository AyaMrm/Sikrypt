use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct RsaKeyGenRequest {
    pub bits: u32,
}

#[derive(Debug, Serialize)]
pub struct RsaKeyPairResponse {
    pub public_key_pem: String,
    pub private_key_pem: String,
}

#[derive(Debug, Serialize)]
pub struct X25519KeyPairResponse {
    pub public_key_base64: String,
    pub private_key_base64: String,
}

#[derive(Debug, Serialize)]
pub struct Ed25519KeyPairResponse {
    pub public_key_base64: String,
    pub private_key_base64: String,
}

#[derive(Debug, Deserialize)]
pub struct SecureChannelEncryptRequest {
    pub sender_private_key_base64: String,
    pub receiver_public_key_base64: String,
    pub plaintext_base64: String,
    pub aad_base64: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SecureChannelEncryptResponse {
    pub sender_public_key_base64: String,
    pub salt_base64: String,
    pub nonce_base64: String,
    pub ciphertext_base64: String,
}

#[derive(Debug, Deserialize)]
pub struct SecureChannelDecryptRequest {
    pub receiver_private_key_base64: String,
    pub sender_public_key_base64: String,
    pub salt_base64: String,
    pub nonce_base64: String,
    pub ciphertext_base64: String,
    pub aad_base64: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SecureChannelDecryptResponse {
    pub plaintext_base64: String,
}

#[derive(Debug, Deserialize)]
pub struct RsaOaepEncryptRequest {
    pub public_key_pem: String,
    pub plaintext_base64: String,
    pub label_base64: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RsaOaepEncryptResponse {
    pub ciphertext_base64: String,
}

#[derive(Debug, Deserialize)]
pub struct RsaOaepDecryptRequest {
    pub private_key_pem: String,
    pub ciphertext_base64: String,
    pub label_base64: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RsaOaepDecryptResponse {
    pub plaintext_base64: String,
}

#[derive(Debug, Deserialize)]
pub struct Ed25519SignRequest {
    pub private_key_base64: String,
    pub message_base64: String,
}

#[derive(Debug, Serialize)]
pub struct Ed25519SignResponse {
    pub signature_base64: String,
}

#[derive(Debug, Deserialize)]
pub struct Ed25519VerifyRequest {
    pub public_key_base64: String,
    pub message_base64: String,
    pub signature_base64: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
}

#[derive(Debug, Deserialize)]
pub struct RsaPssSignRequest {
    pub private_key_pem: String,
    pub message_base64: String,
}

#[derive(Debug, Serialize)]
pub struct RsaPssSignResponse {
    pub signature_base64: String,
}

#[derive(Debug, Deserialize)]
pub struct RsaPssVerifyRequest {
    pub public_key_pem: String,
    pub message_base64: String,
    pub signature_base64: String,
}

#[derive(Debug, Deserialize)]
pub struct PaillierKeyGenRequest {
    pub bits: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaillierPublicKeyResponse {
    pub n_base64: String,
    pub g_base64: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaillierPrivateKeyResponse {
    pub lambda_base64: String,
    pub mu_base64: String,
}

#[derive(Debug, Serialize)]
pub struct PaillierKeyPairResponse {
    pub public_key: PaillierPublicKeyResponse,
    pub private_key: PaillierPrivateKeyResponse,
}

#[derive(Debug, Deserialize)]
pub struct PaillierEncryptRequest {
    pub public_key: PaillierPublicKeyResponse,
    pub plaintext_base64: String,
}

#[derive(Debug, Serialize)]
pub struct PaillierEncryptResponse {
    pub ciphertext_base64: String,
}

#[derive(Debug, Deserialize)]
pub struct PaillierDecryptRequest {
    pub public_key: PaillierPublicKeyResponse,
    pub private_key: PaillierPrivateKeyResponse,
    pub ciphertext_base64: String,
}

#[derive(Debug, Serialize)]
pub struct PaillierDecryptResponse {
    pub plaintext_base64: String,
}

#[derive(Debug, Deserialize)]
pub struct PaillierAddRequest {
    pub public_key: PaillierPublicKeyResponse,
    pub ciphertext_left_base64: String,
    pub ciphertext_right_base64: String,
}

#[derive(Debug, Serialize)]
pub struct PaillierAddResponse {
    pub ciphertext_base64: String,
}

#[derive(Debug, Deserialize)]
pub struct ShamirSplitRequest {
    pub secret_base64: String,
    pub threshold: u8,
    pub shares: u8,
}

#[derive(Debug, Deserialize)]
pub struct ShamirShareInput {
    pub id: u8,
    pub share_base64: String,
}

#[derive(Debug, Serialize)]
pub struct ShamirShareResponse {
    pub id: u8,
    pub share_base64: String,
}

#[derive(Debug, Serialize)]
pub struct ShamirSplitResponse {
    pub shares: Vec<ShamirShareResponse>,
}

#[derive(Debug, Deserialize)]
pub struct ShamirCombineRequest {
    pub threshold: u8,
    pub shares: Vec<ShamirShareInput>,
}

#[derive(Debug, Serialize)]
pub struct ShamirCombineResponse {
    pub secret_base64: String,
}
