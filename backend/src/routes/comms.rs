use axum::{Router, extract::Json, http::StatusCode, routing::post};

use crate::{
    algorithms::{
        asymmetric::diffie_hellman::DiffieHellmanSetup,
        comms::{
            secure_channel::{self, SecureChannelError, SecurePacket},
            voting::{self, Ballot, SignedBallot, VotingError},
        },
        signature::rsa_pss::RsaPssSignature,
    },
    errors::ApiError,
    models::comms::{
        CandidateTally, SecureChannelOpenRequest, SecureChannelOpenResponse,
        SecureChannelSendRequest, SecureChannelSendResponse, SignBallotRequest, SignBallotResponse,
        SignedBallotInput, TallyVotesRequest, TallyVotesResponse,
    },
};

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn from_hex(value: &str) -> Result<Vec<u8>, ApiError> {
    if !value.len().is_multiple_of(2) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_hex",
            "Hex input must contain an even number of characters",
        ));
    }

    let mut bytes = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks_exact(2) {
        let pair = std::str::from_utf8(chunk).map_err(|_| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_hex",
                "Hex input contains invalid UTF-8 data",
            )
        })?;

        let byte = u8::from_str_radix(pair, 16).map_err(|_| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_hex",
                "Hex input contains non-hexadecimal characters",
            )
        })?;

        bytes.push(byte);
    }

    Ok(bytes)
}

fn map_secure_channel_error(error: SecureChannelError) -> ApiError {
    match error {
        SecureChannelError::KeyExchangeFailed => ApiError::new(
            StatusCode::BAD_REQUEST,
            "key_exchange_failed",
            "The secure channel key exchange parameters are invalid",
        ),
        SecureChannelError::EncryptionFailed => ApiError::new(
            StatusCode::BAD_REQUEST,
            "encryption_failed",
            "The secure channel encryption step failed",
        ),
        SecureChannelError::DecryptionFailed => ApiError::new(
            StatusCode::BAD_REQUEST,
            "decryption_failed",
            "The secure channel decryption step failed",
        ),
        SecureChannelError::IntegrityCheckFailed => ApiError::new(
            StatusCode::BAD_REQUEST,
            "integrity_check_failed",
            "The secure channel integrity check failed",
        ),
        SecureChannelError::InvalidIvLength => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_iv_length",
            "The secure channel requires a 16-byte IV",
        ),
    }
}

fn map_voting_error(error: VotingError) -> ApiError {
    match error {
        VotingError::InvalidSignature => ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_signature",
            "At least one ballot signature is invalid",
        ),
        VotingError::DuplicateVote => ApiError::new(
            StatusCode::BAD_REQUEST,
            "duplicate_vote",
            "A voter attempted to submit more than one ballot",
        ),
    }
}

async fn secure_channel_send(
    Json(payload): Json<SecureChannelSendRequest>,
) -> Result<Json<SecureChannelSendResponse>, ApiError> {
    let setup = DiffieHellmanSetup {
        p: payload.p,
        g: payload.g,
    };
    let session_keys = secure_channel::derive_session_keys(
        &setup,
        payload.sender_private,
        payload.receiver_public,
    )
    .map_err(map_secure_channel_error)?;
    let packet = secure_channel::protect_message(
        &session_keys,
        payload.sender_public,
        payload.iv.as_bytes(),
        &payload.plaintext,
    )
    .map_err(map_secure_channel_error)?;

    Ok(Json(SecureChannelSendResponse {
        sender_public_key: packet.sender_public_key,
        iv_hex: to_hex(&packet.iv),
        ciphertext_hex: to_hex(&packet.ciphertext),
        mac_hex: packet.mac_hex,
    }))
}

async fn secure_channel_open(
    Json(payload): Json<SecureChannelOpenRequest>,
) -> Result<Json<SecureChannelOpenResponse>, ApiError> {
    let setup = DiffieHellmanSetup {
        p: payload.p,
        g: payload.g,
    };
    let session_keys = secure_channel::derive_session_keys(
        &setup,
        payload.receiver_private,
        payload.sender_public,
    )
    .map_err(map_secure_channel_error)?;
    let packet = SecurePacket {
        sender_public_key: payload.sender_public,
        iv: from_hex(&payload.iv_hex)?,
        ciphertext: from_hex(&payload.ciphertext_hex)?,
        mac_hex: payload.mac_hex,
    };
    let plaintext =
        secure_channel::open_message(&session_keys, &packet).map_err(map_secure_channel_error)?;

    Ok(Json(SecureChannelOpenResponse { plaintext }))
}

async fn sign_ballot(
    Json(payload): Json<SignBallotRequest>,
) -> Result<Json<SignBallotResponse>, ApiError> {
    let key_pair = voting::demo_voter_key_pair().map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "key_generation_failed",
            "The demo voting key pair could not be generated",
        )
    })?;
    let signed = voting::sign_ballot(
        Ballot {
            voter_id: payload.voter_id,
            candidate: payload.candidate,
        },
        &key_pair,
    );

    Ok(Json(SignBallotResponse {
        voter_id: signed.ballot.voter_id,
        candidate: signed.ballot.candidate,
        signature: signed.signature.signature,
    }))
}

fn map_signed_ballot(input: SignedBallotInput) -> SignedBallot {
    SignedBallot {
        ballot: Ballot {
            voter_id: input.voter_id,
            candidate: input.candidate,
        },
        signature: RsaPssSignature {
            signature: input.signature,
        },
    }
}

async fn tally_votes(
    Json(payload): Json<TallyVotesRequest>,
) -> Result<Json<TallyVotesResponse>, ApiError> {
    let key_pair = voting::demo_voter_key_pair().map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "key_generation_failed",
            "The demo voting key pair could not be generated",
        )
    })?;
    let signed_ballots: Vec<SignedBallot> =
        payload.ballots.into_iter().map(map_signed_ballot).collect();
    let tally = voting::tally_votes(&signed_ballots, &key_pair).map_err(map_voting_error)?;

    let mut results: Vec<CandidateTally> = tally
        .into_iter()
        .map(|(candidate, votes)| CandidateTally { candidate, votes })
        .collect();
    results.sort_by(|left, right| left.candidate.cmp(&right.candidate));

    Ok(Json(TallyVotesResponse { results }))
}

pub fn router() -> Router {
    Router::new()
        .route("/comms/secure-channel/send", post(secure_channel_send))
        .route("/comms/secure-channel/open", post(secure_channel_open))
        .route("/comms/voting/sign-ballot", post(sign_ballot))
        .route("/comms/voting/tally", post(tally_votes))
}
