use aes_gcm::{aead::Aead, aead::Payload, Aes256Gcm, KeyInit};
use axum::{
    extract::{ConnectInfo, Json},
    http::{Request, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use axum::middleware::Next;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hkdf::Hkdf;
use rsa::rand_core::{OsRng, RngCore};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::pss::{Signature as RsaPssSignature, SigningKey, VerifyingKey};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use signature::{RandomizedSigner, SignatureEncoding, Signer, Verifier};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

use ed25519_dalek::{Signature as Ed25519Signature, SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};

use crate::errors::ApiError;
use crate::models::crypto::{
    Ed25519KeyPairResponse, Ed25519SignRequest, Ed25519SignResponse, Ed25519VerifyRequest,
    RsaKeyGenRequest, RsaKeyPairResponse, RsaOaepDecryptRequest, RsaOaepDecryptResponse,
    RsaOaepEncryptRequest, RsaOaepEncryptResponse, RsaPssSignRequest, RsaPssSignResponse,
    RsaPssVerifyRequest, SecureChannelDecryptRequest, SecureChannelDecryptResponse,
    SecureChannelEncryptRequest, SecureChannelEncryptResponse, VerifyResponse, X25519KeyPairResponse,
};

const X25519_KEY_LEN: usize = 32;
const ED25519_KEY_LEN: usize = 32;
const ED25519_SIG_LEN: usize = 64;
const HKDF_INFO: &[u8] = b"sikrypt-secure-channel-v1";
const MAX_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_AAD_BYTES: usize = 8 * 1024;
const MAX_RSA_LABEL_BYTES: usize = 1024;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const RATE_LIMIT_PER_KEY: u32 = 60;
const RATE_LIMIT_PER_IP: u32 = 120;

static RATE_LIMIT_STATE: once_cell::sync::Lazy<Mutex<HashMap<String, (Instant, u32)>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(HashMap::new()));

fn expected_api_key() -> Option<String> {
    std::env::var("SIKRYPT_API_KEY")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

async fn require_api_key(req: Request<axum::body::Body>, next: Next) -> Response {
    if let Some(expected) = expected_api_key() {
        let provided = req
            .headers()
            .get("x-api-key")
            .and_then(|value| value.to_str().ok());

        if provided != Some(expected.as_str()) {
            return ApiError::new(
                StatusCode::UNAUTHORIZED,
                "invalid_api_key",
                "Missing or invalid API key",
            )
            .into_response();
        }
    }

    next.run(req).await
}

fn rate_limit_key(req: &Request<axum::body::Body>) -> String {
    req.headers()
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .map(|value| format!("key:{value}"))
        .unwrap_or_else(|| "key:anonymous".to_string())
}

fn rate_limit_ip(req: &Request<axum::body::Body>) -> Option<String> {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| format!("ip:{}", info.0.ip()))
}

fn check_rate_limit(key: &str, limit: u32) -> bool {
    let now = Instant::now();
    let mut state = RATE_LIMIT_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let entry = state.entry(key.to_string()).or_insert((now, 0));

    if now.duration_since(entry.0) >= RATE_LIMIT_WINDOW {
        *entry = (now, 1);
        return true;
    }

    if entry.1 >= limit {
        return false;
    }

    entry.1 += 1;
    true
}

async fn rate_limit(req: Request<axum::body::Body>, next: Next) -> Response {
    let key_bucket = rate_limit_key(&req);
    if !check_rate_limit(&key_bucket, RATE_LIMIT_PER_KEY) {
        return ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "Too many requests for this API key",
        )
        .into_response();
    }

    if let Some(ip_bucket) = rate_limit_ip(&req) {
        if !check_rate_limit(&ip_bucket, RATE_LIMIT_PER_IP) {
            return ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "Too many requests for this IP",
            )
            .into_response();
        }
    }

    next.run(req).await
}

fn decode_base64(value: &str, field: &str) -> Result<Vec<u8>, ApiError> {
    STANDARD.decode(value).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_base64",
            format!("Invalid base64 for {field}"),
        )
    })
}

fn decode_base64_limited(value: &str, field: &str, max_bytes: usize) -> Result<Vec<u8>, ApiError> {
    let decoded = decode_base64(value, field)?;
    if decoded.len() > max_bytes {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            format!("{field} exceeds {max_bytes} bytes"),
        ));
    }

    Ok(decoded)
}

fn decode_label_string(value: &str, field: &str, max_bytes: usize) -> Result<String, ApiError> {
    let bytes = decode_base64_limited(value, field, max_bytes)?;
    String::from_utf8(bytes).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_label",
            "Label must be valid UTF-8",
        )
    })
}

fn encode_base64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn parse_x25519_private_key(value: &str, field: &str) -> Result<X25519Secret, ApiError> {
    let bytes = decode_base64(value, field)?;
    if bytes.len() != X25519_KEY_LEN {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_key_length",
            "X25519 private key must be 32 bytes",
        ));
    }

    let mut key = [0u8; X25519_KEY_LEN];
    key.copy_from_slice(&bytes);
    Ok(X25519Secret::from(key))
}

fn parse_x25519_public_key(value: &str, field: &str) -> Result<X25519PublicKey, ApiError> {
    let bytes = decode_base64(value, field)?;
    if bytes.len() != X25519_KEY_LEN {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_key_length",
            "X25519 public key must be 32 bytes",
        ));
    }

    let mut key = [0u8; X25519_KEY_LEN];
    key.copy_from_slice(&bytes);
    Ok(X25519PublicKey::from(key))
}

fn derive_aead_key(shared_secret: &[u8], salt: &[u8]) -> Result<[u8; 32], ApiError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "hkdf_failed",
            "Failed to derive session key",
        )
    })?;

    Ok(okm)
}

async fn x25519_keygen() -> Result<Json<X25519KeyPairResponse>, ApiError> {
    let mut secret_bytes = [0u8; X25519_KEY_LEN];
    let mut rng = OsRng;
    rng.fill_bytes(&mut secret_bytes);
    let secret = X25519Secret::from(secret_bytes);
    let public = X25519PublicKey::from(&secret);

    Ok(Json(X25519KeyPairResponse {
        public_key_base64: encode_base64(public.as_bytes()),
        private_key_base64: encode_base64(&secret_bytes),
    }))
}

async fn ed25519_keygen() -> Result<Json<Ed25519KeyPairResponse>, ApiError> {
    let mut rng = OsRng;
    let mut secret_bytes = [0u8; ED25519_KEY_LEN];
    rng.fill_bytes(&mut secret_bytes);
    let signing_key = Ed25519SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();

    Ok(Json(Ed25519KeyPairResponse {
        public_key_base64: encode_base64(verifying_key.as_bytes()),
        private_key_base64: encode_base64(&secret_bytes),
    }))
}

async fn rsa_keygen(
    Json(payload): Json<RsaKeyGenRequest>,
) -> Result<Json<RsaKeyPairResponse>, ApiError> {
    if payload.bits < 2048 || payload.bits > 4096 || payload.bits % 256 != 0 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_key_size",
            "RSA key size must be 2048..=4096 and a multiple of 256",
        ));
    }

    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, payload.bits as usize).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "key_generation_failed",
            "RSA key generation failed",
        )
    })?;
    let public_key = RsaPublicKey::from(&private_key);

    let private_key_pem = private_key
        .to_pkcs8_pem(Default::default())
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "key_encoding_failed",
                "Failed to encode RSA private key",
            )
        })?
        .to_string();
    let public_key_pem = public_key
        .to_public_key_pem(Default::default())
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "key_encoding_failed",
                "Failed to encode RSA public key",
            )
        })?;

    Ok(Json(RsaKeyPairResponse {
        public_key_pem,
        private_key_pem,
    }))
}

async fn secure_channel_encrypt(
    Json(payload): Json<SecureChannelEncryptRequest>,
) -> Result<Json<SecureChannelEncryptResponse>, ApiError> {
    let sender_secret = parse_x25519_private_key(&payload.sender_private_key_base64, "sender_private_key_base64")?;
    let receiver_public = parse_x25519_public_key(&payload.receiver_public_key_base64, "receiver_public_key_base64")?;
    let plaintext = decode_base64_limited(&payload.plaintext_base64, "plaintext_base64", MAX_MESSAGE_BYTES)?;
    let aad = match &payload.aad_base64 {
        Some(value) => decode_base64_limited(value, "aad_base64", MAX_AAD_BYTES)?,
        None => Vec::new(),
    };

    let shared_secret = sender_secret.diffie_hellman(&receiver_public);
    let mut salt = [0u8; 16];
    let mut rng = OsRng;
    rng.fill_bytes(&mut salt);
    let key = derive_aead_key(shared_secret.as_bytes(), &salt)?;

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cipher_init_failed",
            "Failed to initialize AEAD",
        )
    })?;

    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(
            &nonce.into(),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "encryption_failed",
                "AEAD encryption failed",
            )
        })?;

    let sender_public = X25519PublicKey::from(&sender_secret);

    Ok(Json(SecureChannelEncryptResponse {
        sender_public_key_base64: encode_base64(sender_public.as_bytes()),
        salt_base64: encode_base64(&salt),
        nonce_base64: encode_base64(&nonce),
        ciphertext_base64: encode_base64(&ciphertext),
    }))
}

async fn secure_channel_decrypt(
    Json(payload): Json<SecureChannelDecryptRequest>,
) -> Result<Json<SecureChannelDecryptResponse>, ApiError> {
    let receiver_secret = parse_x25519_private_key(&payload.receiver_private_key_base64, "receiver_private_key_base64")?;
    let sender_public = parse_x25519_public_key(&payload.sender_public_key_base64, "sender_public_key_base64")?;
    let salt = decode_base64(&payload.salt_base64, "salt_base64")?;
    let nonce = decode_base64(&payload.nonce_base64, "nonce_base64")?;
    let ciphertext = decode_base64_limited(
        &payload.ciphertext_base64,
        "ciphertext_base64",
        MAX_MESSAGE_BYTES + 64,
    )?;
    let aad = match &payload.aad_base64 {
        Some(value) => decode_base64_limited(value, "aad_base64", MAX_AAD_BYTES)?,
        None => Vec::new(),
    };

    if nonce.len() != 12 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_nonce_length",
            "Nonce must be 12 bytes",
        ));
    }

    let shared_secret = receiver_secret.diffie_hellman(&sender_public);
    let key = derive_aead_key(shared_secret.as_bytes(), &salt)?;

    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cipher_init_failed",
            "Failed to initialize AEAD",
        )
    })?;

    let plaintext = cipher
        .decrypt(
            nonce.as_slice().into(),
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "decryption_failed",
                "AEAD decryption failed",
            )
        })?;

    Ok(Json(SecureChannelDecryptResponse {
        plaintext_base64: encode_base64(&plaintext),
    }))
}

async fn rsa_oaep_encrypt(
    Json(payload): Json<RsaOaepEncryptRequest>,
) -> Result<Json<RsaOaepEncryptResponse>, ApiError> {
    let public_key = RsaPublicKey::from_public_key_pem(&payload.public_key_pem).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_public_key",
            "Failed to parse RSA public key PEM",
        )
    })?;
    let plaintext = decode_base64_limited(&payload.plaintext_base64, "plaintext_base64", MAX_MESSAGE_BYTES)?;
    let oaep = match &payload.label_base64 {
        Some(label) => Oaep::new_with_label::<Sha256, _>(
            decode_label_string(label, "label_base64", MAX_RSA_LABEL_BYTES)?,
        ),
        None => Oaep::new::<Sha256>(),
    };

    let mut rng = OsRng;
    let ciphertext = public_key
        .encrypt(&mut rng, oaep, &plaintext)
        .map_err(|_| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "encryption_failed",
                "RSA-OAEP encryption failed",
            )
        })?;

    Ok(Json(RsaOaepEncryptResponse {
        ciphertext_base64: encode_base64(&ciphertext),
    }))
}

async fn rsa_oaep_decrypt(
    Json(payload): Json<RsaOaepDecryptRequest>,
) -> Result<Json<RsaOaepDecryptResponse>, ApiError> {
    let private_key = RsaPrivateKey::from_pkcs8_pem(&payload.private_key_pem).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_private_key",
            "Failed to parse RSA private key PEM",
        )
    })?;
    let ciphertext = decode_base64_limited(
        &payload.ciphertext_base64,
        "ciphertext_base64",
        MAX_MESSAGE_BYTES + 512,
    )?;
    let oaep = match &payload.label_base64 {
        Some(label) => Oaep::new_with_label::<Sha256, _>(
            decode_label_string(label, "label_base64", MAX_RSA_LABEL_BYTES)?,
        ),
        None => Oaep::new::<Sha256>(),
    };

    let plaintext = private_key.decrypt(oaep, &ciphertext).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "decryption_failed",
            "RSA-OAEP decryption failed",
        )
    })?;

    Ok(Json(RsaOaepDecryptResponse {
        plaintext_base64: encode_base64(&plaintext),
    }))
}

async fn ed25519_sign(
    Json(payload): Json<Ed25519SignRequest>,
) -> Result<Json<Ed25519SignResponse>, ApiError> {
    let key_bytes = decode_base64(&payload.private_key_base64, "private_key_base64")?;
    if key_bytes.len() != ED25519_KEY_LEN {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_key_length",
            "Ed25519 private key must be 32 bytes",
        ));
    }
    let message = decode_base64_limited(&payload.message_base64, "message_base64", MAX_MESSAGE_BYTES)?;

    let mut key = [0u8; ED25519_KEY_LEN];
    key.copy_from_slice(&key_bytes);
    let signing_key = Ed25519SigningKey::from_bytes(&key);
    let signature = signing_key.sign(&message);

    Ok(Json(Ed25519SignResponse {
        signature_base64: encode_base64(&signature.to_bytes()),
    }))
}

async fn ed25519_verify(
    Json(payload): Json<Ed25519VerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let key_bytes = decode_base64(&payload.public_key_base64, "public_key_base64")?;
    if key_bytes.len() != ED25519_KEY_LEN {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_key_length",
            "Ed25519 public key must be 32 bytes",
        ));
    }
    let signature_bytes = decode_base64_limited(
        &payload.signature_base64,
        "signature_base64",
        ED25519_SIG_LEN,
    )?;
    if signature_bytes.len() != ED25519_SIG_LEN {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_signature_length",
            "Ed25519 signature must be 64 bytes",
        ));
    }
    let message = decode_base64_limited(&payload.message_base64, "message_base64", MAX_MESSAGE_BYTES)?;

    let mut key = [0u8; ED25519_KEY_LEN];
    key.copy_from_slice(&key_bytes);
    let verifying_key = Ed25519VerifyingKey::from_bytes(&key).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_public_key",
            "Failed to parse Ed25519 public key",
        )
    })?;

    let mut sig = [0u8; ED25519_SIG_LEN];
    sig.copy_from_slice(&signature_bytes);
    let signature = Ed25519Signature::from_bytes(&sig);

    let valid = verifying_key.verify(&message, &signature).is_ok();

    Ok(Json(VerifyResponse { valid }))
}

async fn rsa_pss_sign(
    Json(payload): Json<RsaPssSignRequest>,
) -> Result<Json<RsaPssSignResponse>, ApiError> {
    let private_key = RsaPrivateKey::from_pkcs8_pem(&payload.private_key_pem).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_private_key",
            "Failed to parse RSA private key PEM",
        )
    })?;
    let message = decode_base64_limited(&payload.message_base64, "message_base64", MAX_MESSAGE_BYTES)?;

    let signing_key = SigningKey::<Sha256>::new(private_key);
    let mut rng = OsRng;
    let signature = signing_key.sign_with_rng(&mut rng, &message);

    Ok(Json(RsaPssSignResponse {
        signature_base64: encode_base64(&signature.to_bytes()),
    }))
}

async fn rsa_pss_verify(
    Json(payload): Json<RsaPssVerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let public_key = RsaPublicKey::from_public_key_pem(&payload.public_key_pem).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_public_key",
            "Failed to parse RSA public key PEM",
        )
    })?;
    let message = decode_base64_limited(&payload.message_base64, "message_base64", MAX_MESSAGE_BYTES)?;
    let signature_bytes = decode_base64_limited(
        &payload.signature_base64,
        "signature_base64",
        MAX_MESSAGE_BYTES,
    )?;

    let signature = RsaPssSignature::try_from(signature_bytes.as_slice()).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid_signature",
            "Invalid RSA-PSS signature bytes",
        )
    })?;

    let verifying_key = VerifyingKey::<Sha256>::new(public_key);
    let valid = verifying_key.verify(&message, &signature).is_ok();

    Ok(Json(VerifyResponse { valid }))
}

pub fn router() -> Router {
    Router::new()
        .route("/crypto/keys/x25519", post(x25519_keygen))
        .route("/crypto/keys/ed25519", post(ed25519_keygen))
        .route("/crypto/keys/rsa", post(rsa_keygen))
        .route("/crypto/secure-channel/encrypt", post(secure_channel_encrypt))
        .route("/crypto/secure-channel/decrypt", post(secure_channel_decrypt))
        .route("/crypto/rsa/oaep/encrypt", post(rsa_oaep_encrypt))
        .route("/crypto/rsa/oaep/decrypt", post(rsa_oaep_decrypt))
        .route("/crypto/ed25519/sign", post(ed25519_sign))
        .route("/crypto/ed25519/verify", post(ed25519_verify))
        .route("/crypto/rsa/pss/sign", post(rsa_pss_sign))
        .route("/crypto/rsa/pss/verify", post(rsa_pss_verify))
        .layer(middleware::from_fn(rate_limit))
        .layer(middleware::from_fn(require_api_key))
}
