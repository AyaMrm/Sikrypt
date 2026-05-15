use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CaesarRequest {
    pub text: String,
    pub shift: i32,
}

#[derive(Debug, Deserialize)]
pub struct VigenereEncryptRequest {
    pub text: String,
    pub key: String,
}

#[derive(Debug, Deserialize)]
pub struct AffineRequest {
    pub text: String,
    pub a: i32,
    pub b: i32,
}

#[derive(Debug, Deserialize)]
pub struct PlayfairRequest {
    pub text: String,
    pub key: String,
}

#[derive(Debug, Deserialize)]
pub struct OtpEncryptRequest {
    pub plaintext_base64: String,
    pub key_base64: String,
}

#[derive(Debug, Deserialize)]
pub struct OtpDecryptRequest {
    pub ciphertext_base64: String,
    pub key_base64: String,
}

#[derive(Debug, Serialize)]
pub struct OtpResponse {
    pub result_base64: String,
}

#[derive(Debug, Deserialize)]
pub struct HillEncryptRequest {
    pub text: String,
    pub key: [[i32; 2]; 2],
}

#[derive(Debug, Deserialize)]
pub struct FrequencyAnalysisRequest {
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct LetterFrequencyResponse {
    pub letter: String,
    pub count: u32,
    pub frequency: f64,
}

#[derive(Debug, Serialize)]
pub struct FrequencyAnalysisResponse {
    pub total_letters: u32,
    pub frequencies: Vec<LetterFrequencyResponse>,
}

#[derive(Debug, Deserialize)]
pub struct IndexCoincidenceRequest {
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct IndexCoincidenceResponse {
    pub total_letters: u32,
    pub index: f64,
}

#[derive(Debug, Serialize)]
pub struct TextResultResponse {
    pub result: String,
}

#[derive(Debug, Deserialize)]
pub struct CaesarBruteforceRequest {
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct CaesarBruteforceCandidateResponse {
    pub shift: i32,
    pub plaintext: String,
    pub score: u32,
}

#[derive(Debug, Serialize)]
pub struct CaesarBruteforceResponse {
    pub best_shift: Option<i32>,
    pub best_plaintext: Option<String>,
    pub candidates: Vec<CaesarBruteforceCandidateResponse>,
}

#[derive(Debug, Deserialize)]
pub struct KasiskiRequest {
    pub text: String,
    pub sequence_len: Option<usize>,
    pub max_key_len: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct KasiskiCandidateResponse {
    pub key_length: usize,
    pub score: u32,
}

#[derive(Debug, Serialize)]
pub struct KasiskiResponse {
    pub distances: Vec<u32>,
    pub gcd: Option<u32>,
    pub candidates: Vec<KasiskiCandidateResponse>,
}

#[derive(Debug, Deserialize)]
pub struct VigenereKeyLengthRequest {
    pub text: String,
    pub max_length: usize,
}

#[derive(Debug, Serialize)]
pub struct VigenereKeyLengthResponse {
    pub length: usize,
    pub average_ic: f64,
}

#[derive(Debug, Serialize)]
pub struct VigenereKeyLengthListResponse {
    pub candidates: Vec<VigenereKeyLengthResponse>,
}

#[derive(Debug, Deserialize)]
pub struct VigenereEstimateKeyRequest {
    pub text: String,
    pub key_length: usize,
}

#[derive(Debug, Serialize)]
pub struct VigenereEstimateKeyResponse {
    pub key: String,
}
