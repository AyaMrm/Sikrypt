use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct SecureChannelSendRequest {
    pub p: u128,
    pub g: u128,
    pub sender_private: u128,
    pub receiver_public: u128,
    pub sender_public: u128,
    pub iv: String,
    pub plaintext: String,
}

#[derive(Debug, Serialize)]
pub struct SecureChannelSendResponse {
    pub sender_public_key: u128,
    pub iv_hex: String,
    pub ciphertext_hex: String,
    pub mac_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct SecureChannelOpenRequest {
    pub p: u128,
    pub g: u128,
    pub receiver_private: u128,
    pub sender_public: u128,
    pub iv_hex: String,
    pub ciphertext_hex: String,
    pub mac_hex: String,
}

#[derive(Debug, Serialize)]
pub struct SecureChannelOpenResponse {
    pub plaintext: String,
}

#[derive(Debug, Deserialize)]
pub struct SignBallotRequest {
    pub voter_id: String,
    pub candidate: String,
}

#[derive(Debug, Serialize)]
pub struct SignBallotResponse {
    pub voter_id: String,
    pub candidate: String,
    pub signature: u128,
}

#[derive(Debug, Deserialize)]
pub struct SignedBallotInput {
    pub voter_id: String,
    pub candidate: String,
    pub signature: u128,
}

#[derive(Debug, Deserialize)]
pub struct TallyVotesRequest {
    pub ballots: Vec<SignedBallotInput>,
}

#[derive(Debug, Serialize)]
pub struct CandidateTally {
    pub candidate: String,
    pub votes: u32,
}

#[derive(Debug, Serialize)]
pub struct TallyVotesResponse {
    pub results: Vec<CandidateTally>,
}
