use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct HashTextRequest {
    pub text: String,
}

#[derive(Debug, Deserialize)]
pub struct HmacRequest {
    pub text: String,
    pub key: String,
}

#[derive(Debug, Serialize)]
pub struct DigestResponse {
    pub digest: String,
}
