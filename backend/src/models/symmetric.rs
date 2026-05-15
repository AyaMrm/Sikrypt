use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct Rc4EncryptRequest {
    pub plaintext: String,
    pub key: String,
}

#[derive(Debug, Deserialize)]
pub struct BlockCipherEncryptRequest {
    pub plaintext: String,
    pub key: String,
    pub iv: String,
}

#[derive(Debug, Deserialize)]
pub struct Rc4DecryptRequest {
    pub ciphertext_hex: String,
    pub key: String,
}

#[derive(Debug, Deserialize)]
pub struct BlockCipherDecryptRequest {
    pub ciphertext_hex: String,
    pub key: String,
    pub iv: String,
}

#[derive(Debug, Serialize)]
pub struct Rc4EncryptResponse {
    pub ciphertext_hex: String,
    pub keystream_hex: String,
}

#[derive(Debug, Serialize)]
pub struct DesEncryptResponse {
    pub ciphertext_hex: String,
    pub iv_hex: String,
}

#[derive(Debug, Serialize)]
pub struct AesEncryptResponse {
    pub ciphertext_hex: String,
    pub iv_hex: String,
    pub key_size: String,
}

#[derive(Debug, Serialize)]
pub struct PlaintextResponse {
    pub result: String,
}
