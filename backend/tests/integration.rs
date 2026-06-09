use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use backend::algorithms::asymmetric::diffie_hellman::{DiffieHellmanSetup, compute_public_key};
use backend::algorithms::asymmetric::elgamal::{self, ElGamalParameters};
use backend::algorithms::hash::hmac_impl;
use backend::algorithms::signature::{dsa, ecdsa};
use backend::app::create_app;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Mutex, MutexGuard, OnceLock};
use tower::ServiceExt;

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
const DEFAULT_TEST_API_KEY: &str = "test-api-key";

fn env_lock() -> MutexGuard<'static, ()> {
    ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn ensure_api_key_disabled() -> MutexGuard<'static, ()> {
    let guard = env_lock();
    // The app now requires a configured API key, so tests install a stable one.
    unsafe {
        std::env::set_var("SIKRYPT_API_KEY", DEFAULT_TEST_API_KEY);
    }
    guard
}

fn to_json_request(path: &str, payload: Value) -> Request<Body> {
    let mut request = Request::post(path)
        .header("content-type", "application/json")
        .body(Body::from(payload.to_string()))
        .unwrap();

    if path.starts_with("/crypto/") {
        let api_key = std::env::var("SIKRYPT_API_KEY").unwrap_or_default();
        request
            .headers_mut()
            .insert("x-api-key", api_key.parse().unwrap());
    }

    request
}

fn crypto_empty_request(path: &str) -> Request<Body> {
    let mut request = Request::post(path).body(Body::empty()).unwrap();
    let api_key = std::env::var("SIKRYPT_API_KEY").unwrap_or_default();
    request
        .headers_mut()
        .insert("x-api-key", api_key.parse().unwrap());
    request
}

fn to_json_request_with_key(path: &str, payload: Value, api_key: &str) -> Request<Body> {
    Request::post(path)
        .header("content-type", "application/json")
        .header("x-api-key", api_key)
        .body(Body::from(payload.to_string()))
        .unwrap()
}

fn set_api_key(value: &str) -> MutexGuard<'static, ()> {
    let guard = env_lock();
    unsafe {
        std::env::set_var("SIKRYPT_API_KEY", value);
    }
    guard
}

fn clear_api_key(_guard: &MutexGuard<'static, ()>) {
    unsafe {
        std::env::remove_var("SIKRYPT_API_KEY");
    }
}

#[tokio::test]
async fn create_app_requires_api_key_configuration() {
    let _guard = env_lock();
    unsafe {
        std::env::remove_var("SIKRYPT_API_KEY");
    }

    let result = catch_unwind(AssertUnwindSafe(create_app));
    assert!(result.is_err());
}

#[tokio::test]
async fn health_endpoint_works() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();
    let response = app
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn openapi_is_served() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();
    let response = app
        .oneshot(Request::get("/openapi.json").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 200);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("\"openapi\""));
}

#[tokio::test]
async fn swagger_ui_is_served() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();
    let response = app
        .oneshot(Request::get("/docs").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 200);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("swagger-ui"));
}

#[tokio::test]
async fn x25519_keygen_returns_base64_keys() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();
    let response = app
        .oneshot(crypto_empty_request("/crypto/keys/x25519"))
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 200);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    let public_key = value
        .get("public_key_base64")
        .and_then(|val| val.as_str())
        .unwrap();
    let private_key = value
        .get("private_key_base64")
        .and_then(|val| val.as_str())
        .unwrap();

    assert!(!public_key.is_empty());
    assert!(!private_key.is_empty());
}

#[tokio::test]
async fn ecc_p256_keygen_and_derive() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let alice_response = app
        .clone()
        .oneshot(
            Request::post("/asymmetric/ecc/p256/keygen")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(alice_response.status().as_u16(), 200);
    let alice_body = to_bytes(alice_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let alice_json: Value = serde_json::from_slice(&alice_body).unwrap();

    let bob_response = app
        .clone()
        .oneshot(
            Request::post("/asymmetric/ecc/p256/keygen")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bob_response.status().as_u16(), 200);
    let bob_body = to_bytes(bob_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let bob_json: Value = serde_json::from_slice(&bob_body).unwrap();

    let alice_private = alice_json
        .get("private_key_base64")
        .and_then(|val| val.as_str())
        .unwrap();
    let alice_public = alice_json
        .get("public_key_base64")
        .and_then(|val| val.as_str())
        .unwrap();
    let bob_private = bob_json
        .get("private_key_base64")
        .and_then(|val| val.as_str())
        .unwrap();
    let bob_public = bob_json
        .get("public_key_base64")
        .and_then(|val| val.as_str())
        .unwrap();

    let alice_derive = json!({
        "private_key_base64": alice_private,
        "peer_public_key_base64": bob_public
    });
    let alice_response = app
        .clone()
        .oneshot(to_json_request("/asymmetric/ecc/p256/derive", alice_derive))
        .await
        .unwrap();
    assert_eq!(alice_response.status().as_u16(), 200);
    let alice_body = to_bytes(alice_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let alice_json: Value = serde_json::from_slice(&alice_body).unwrap();

    let bob_derive = json!({
        "private_key_base64": bob_private,
        "peer_public_key_base64": alice_public
    });
    let bob_response = app
        .oneshot(to_json_request("/asymmetric/ecc/p256/derive", bob_derive))
        .await
        .unwrap();
    assert_eq!(bob_response.status().as_u16(), 200);
    let bob_body = to_bytes(bob_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let bob_json: Value = serde_json::from_slice(&bob_body).unwrap();

    let alice_secret = alice_json
        .get("shared_secret_base64")
        .and_then(|val| val.as_str())
        .unwrap();
    let bob_secret = bob_json
        .get("shared_secret_base64")
        .and_then(|val| val.as_str())
        .unwrap();

    assert!(!alice_secret.is_empty());
    assert_eq!(alice_secret, bob_secret);
}

#[tokio::test]
async fn crypto_endpoints_require_api_key_when_enabled() {
    let api_key = "test-api-key";
    let env_guard = set_api_key(api_key);
    let app = create_app();

    let missing_key_response = app
        .clone()
        .oneshot(
            Request::post("/crypto/keys/x25519")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_key_response.status(), StatusCode::UNAUTHORIZED);

    let with_key_response = app
        .oneshot(to_json_request_with_key(
            "/crypto/keys/x25519",
            json!({}),
            api_key,
        ))
        .await
        .unwrap();
    assert_eq!(with_key_response.status(), StatusCode::OK);

    clear_api_key(&env_guard);
}

#[tokio::test]
async fn crypto_rate_limit_triggers_for_api_key() {
    let api_key = "rate-limit-key";
    let env_guard = set_api_key(api_key);
    let app = create_app();

    let mut last_status = StatusCode::OK;
    for _ in 0..61 {
        let response = app
            .clone()
            .oneshot(to_json_request_with_key(
                "/crypto/keys/x25519",
                json!({}),
                api_key,
            ))
            .await
            .unwrap();
        last_status = response.status();
    }

    assert_eq!(last_status, StatusCode::TOO_MANY_REQUESTS);
    clear_api_key(&env_guard);
}

#[tokio::test]
async fn secure_channel_roundtrip() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let sender_keys = app
        .clone()
        .oneshot(crypto_empty_request("/crypto/keys/x25519"))
        .await
        .unwrap();
    assert_eq!(sender_keys.status(), StatusCode::OK);
    let sender_body = to_bytes(sender_keys.into_body(), usize::MAX).await.unwrap();
    let sender_json: Value = serde_json::from_slice(&sender_body).unwrap();

    let receiver_keys = app
        .clone()
        .oneshot(crypto_empty_request("/crypto/keys/x25519"))
        .await
        .unwrap();
    assert_eq!(receiver_keys.status(), StatusCode::OK);
    let receiver_body = to_bytes(receiver_keys.into_body(), usize::MAX)
        .await
        .unwrap();
    let receiver_json: Value = serde_json::from_slice(&receiver_body).unwrap();

    let plaintext = b"hello secure channel";
    let encrypt_payload = json!({
        "sender_private_key_base64": sender_json["private_key_base64"],
        "receiver_public_key_base64": receiver_json["public_key_base64"],
        "plaintext_base64": STANDARD.encode(plaintext)
    });

    let encrypt_response = app
        .clone()
        .oneshot(to_json_request(
            "/crypto/secure-channel/encrypt",
            encrypt_payload,
        ))
        .await
        .unwrap();
    assert_eq!(encrypt_response.status(), StatusCode::OK);
    let encrypt_body = to_bytes(encrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let encrypt_json: Value = serde_json::from_slice(&encrypt_body).unwrap();

    let decrypt_payload = json!({
        "receiver_private_key_base64": receiver_json["private_key_base64"],
        "sender_public_key_base64": encrypt_json["sender_public_key_base64"],
        "salt_base64": encrypt_json["salt_base64"],
        "nonce_base64": encrypt_json["nonce_base64"],
        "ciphertext_base64": encrypt_json["ciphertext_base64"]
    });

    let decrypt_response = app
        .oneshot(to_json_request(
            "/crypto/secure-channel/decrypt",
            decrypt_payload,
        ))
        .await
        .unwrap();
    assert_eq!(decrypt_response.status(), StatusCode::OK);
    let decrypt_body = to_bytes(decrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let decrypt_json: Value = serde_json::from_slice(&decrypt_body).unwrap();

    let plaintext_out = STANDARD
        .decode(
            decrypt_json
                .get("plaintext_base64")
                .and_then(|value| value.as_str())
                .unwrap(),
        )
        .unwrap();
    assert_eq!(plaintext_out, plaintext);
}

#[tokio::test]
async fn rsa_oaep_roundtrip() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let keygen_payload = json!({ "bits": 2048 });
    let keygen_response = app
        .clone()
        .oneshot(to_json_request("/crypto/keys/rsa", keygen_payload))
        .await
        .unwrap();
    assert_eq!(keygen_response.status(), StatusCode::OK);
    let keygen_body = to_bytes(keygen_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let keygen_json: Value = serde_json::from_slice(&keygen_body).unwrap();

    let plaintext = b"hello rsa oaep";
    let encrypt_payload = json!({
        "public_key_pem": keygen_json["public_key_pem"],
        "plaintext_base64": STANDARD.encode(plaintext)
    });
    let encrypt_response = app
        .clone()
        .oneshot(to_json_request("/crypto/rsa/oaep/encrypt", encrypt_payload))
        .await
        .unwrap();
    assert_eq!(encrypt_response.status(), StatusCode::OK);
    let encrypt_body = to_bytes(encrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let encrypt_json: Value = serde_json::from_slice(&encrypt_body).unwrap();

    let decrypt_payload = json!({
        "private_key_pem": keygen_json["private_key_pem"],
        "ciphertext_base64": encrypt_json["ciphertext_base64"]
    });
    let decrypt_response = app
        .oneshot(to_json_request("/crypto/rsa/oaep/decrypt", decrypt_payload))
        .await
        .unwrap();
    assert_eq!(decrypt_response.status(), StatusCode::OK);
    let decrypt_body = to_bytes(decrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let decrypt_json: Value = serde_json::from_slice(&decrypt_body).unwrap();

    let plaintext_out = STANDARD
        .decode(
            decrypt_json
                .get("plaintext_base64")
                .and_then(|value| value.as_str())
                .unwrap(),
        )
        .unwrap();
    assert_eq!(plaintext_out, plaintext);
}

#[tokio::test]
async fn ed25519_sign_and_verify() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let keygen_response = app
        .clone()
        .oneshot(crypto_empty_request("/crypto/keys/ed25519"))
        .await
        .unwrap();
    assert_eq!(keygen_response.status(), StatusCode::OK);
    let keygen_body = to_bytes(keygen_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let keygen_json: Value = serde_json::from_slice(&keygen_body).unwrap();

    let message = b"hello ed25519";
    let private_key = keygen_json
        .get("private_key_base64")
        .and_then(|value| value.as_str())
        .unwrap();
    let public_key = keygen_json
        .get("public_key_base64")
        .and_then(|value| value.as_str())
        .unwrap();
    let sign_payload = json!({
        "private_key_base64": private_key,
        "message_base64": STANDARD.encode(message)
    });
    let sign_response = app
        .clone()
        .oneshot(to_json_request("/crypto/ed25519/sign", sign_payload))
        .await
        .unwrap();
    let sign_status = sign_response.status();
    let sign_body = to_bytes(sign_response.into_body(), usize::MAX)
        .await
        .unwrap();
    if sign_status != StatusCode::OK {
        let sign_text = String::from_utf8_lossy(&sign_body);
        panic!(
            "ed25519 sign failed: status={} body={}",
            sign_status, sign_text
        );
    }
    let sign_json: Value = serde_json::from_slice(&sign_body).unwrap();

    let verify_payload = json!({
        "public_key_base64": public_key,
        "message_base64": STANDARD.encode(message),
        "signature_base64": sign_json["signature_base64"]
    });
    let verify_response = app
        .oneshot(to_json_request("/crypto/ed25519/verify", verify_payload))
        .await
        .unwrap();
    assert_eq!(verify_response.status(), StatusCode::OK);
    let verify_body = to_bytes(verify_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let verify_json: Value = serde_json::from_slice(&verify_body).unwrap();

    assert_eq!(
        verify_json.get("valid").and_then(|v| v.as_bool()),
        Some(true)
    );
}

#[tokio::test]
async fn rsa_pss_sign_and_verify() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let keygen_payload = json!({ "bits": 2048 });
    let keygen_response = app
        .clone()
        .oneshot(to_json_request("/crypto/keys/rsa", keygen_payload))
        .await
        .unwrap();
    assert_eq!(keygen_response.status(), StatusCode::OK);
    let keygen_body = to_bytes(keygen_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let keygen_json: Value = serde_json::from_slice(&keygen_body).unwrap();

    let message = b"hello rsa pss";
    let sign_payload = json!({
        "private_key_pem": keygen_json["private_key_pem"],
        "message_base64": STANDARD.encode(message)
    });
    let sign_response = app
        .clone()
        .oneshot(to_json_request("/crypto/rsa/pss/sign", sign_payload))
        .await
        .unwrap();
    assert_eq!(sign_response.status(), StatusCode::OK);
    let sign_body = to_bytes(sign_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let sign_json: Value = serde_json::from_slice(&sign_body).unwrap();

    let verify_payload = json!({
        "public_key_pem": keygen_json["public_key_pem"],
        "message_base64": STANDARD.encode(message),
        "signature_base64": sign_json["signature_base64"]
    });
    let verify_response = app
        .oneshot(to_json_request("/crypto/rsa/pss/verify", verify_payload))
        .await
        .unwrap();
    assert_eq!(verify_response.status(), StatusCode::OK);
    let verify_body = to_bytes(verify_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let verify_json: Value = serde_json::from_slice(&verify_body).unwrap();

    assert_eq!(
        verify_json.get("valid").and_then(|v| v.as_bool()),
        Some(true)
    );
}

#[tokio::test]
async fn caesar_encrypt_endpoint_works() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let payload = json!({
        "text": "Abc-xyz!",
        "shift": 2
    });
    let response = app
        .oneshot(to_json_request("/classic/caesar/encrypt", payload))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        value.get("result").and_then(|v| v.as_str()),
        Some("Cde-zab!")
    );
}

#[tokio::test]
async fn caesar_bruteforce_endpoint_works() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let payload = json!({
        "text": "erqmrxu"
    });
    let response = app
        .oneshot(to_json_request("/classic/caesar/bruteforce", payload))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(value.get("best_shift").and_then(|v| v.as_i64()), Some(3));
    assert_eq!(
        value.get("best_plaintext").and_then(|v| v.as_str()),
        Some("bonjour")
    );
}

#[tokio::test]
async fn caesar_decrypt_endpoint_works() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let payload = json!({
        "text": "Cde-zab!",
        "shift": 2
    });
    let response = app
        .oneshot(to_json_request("/classic/caesar/decrypt", payload))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        value.get("result").and_then(|v| v.as_str()),
        Some("Abc-xyz!")
    );
}

#[tokio::test]
async fn vigenere_encrypt_and_decrypt_endpoints_work() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let encrypt_payload = json!({
        "text": "ATTACKATDAWN",
        "key": "LEMON"
    });
    let encrypt_response = app
        .clone()
        .oneshot(to_json_request(
            "/classic/vigenere/encrypt",
            encrypt_payload,
        ))
        .await
        .unwrap();
    assert_eq!(encrypt_response.status(), StatusCode::OK);
    let encrypt_body = to_bytes(encrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let encrypt_json: Value = serde_json::from_slice(&encrypt_body).unwrap();

    assert_eq!(
        encrypt_json.get("result").and_then(|v| v.as_str()),
        Some("LXFOPVEFRNHR")
    );

    let decrypt_payload = json!({
        "text": "LXFOPVEFRNHR",
        "key": "LEMON"
    });
    let decrypt_response = app
        .oneshot(to_json_request(
            "/classic/vigenere/decrypt",
            decrypt_payload,
        ))
        .await
        .unwrap();
    assert_eq!(decrypt_response.status(), StatusCode::OK);
    let decrypt_body = to_bytes(decrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let decrypt_json: Value = serde_json::from_slice(&decrypt_body).unwrap();

    assert_eq!(
        decrypt_json.get("result").and_then(|v| v.as_str()),
        Some("ATTACKATDAWN")
    );
}

#[tokio::test]
async fn affine_encrypt_and_decrypt_endpoints_work() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let encrypt_payload = json!({
        "text": "AFFINE CIPHER",
        "a": 5,
        "b": 8
    });
    let encrypt_response = app
        .clone()
        .oneshot(to_json_request("/classic/affine/encrypt", encrypt_payload))
        .await
        .unwrap();
    assert_eq!(encrypt_response.status(), StatusCode::OK);
    let encrypt_body = to_bytes(encrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let encrypt_json: Value = serde_json::from_slice(&encrypt_body).unwrap();

    assert_eq!(
        encrypt_json.get("result").and_then(|v| v.as_str()),
        Some("IHHWVC SWFRCP")
    );

    let decrypt_payload = json!({
        "text": "IHHWVC SWFRCP",
        "a": 5,
        "b": 8
    });
    let decrypt_response = app
        .oneshot(to_json_request("/classic/affine/decrypt", decrypt_payload))
        .await
        .unwrap();
    assert_eq!(decrypt_response.status(), StatusCode::OK);
    let decrypt_body = to_bytes(decrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let decrypt_json: Value = serde_json::from_slice(&decrypt_body).unwrap();

    assert_eq!(
        decrypt_json.get("result").and_then(|v| v.as_str()),
        Some("AFFINE CIPHER")
    );
}

#[tokio::test]
async fn playfair_encrypt_and_decrypt_endpoints_work() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let encrypt_payload = json!({
        "text": "HIDE THE GOLD",
        "key": "PLAYFAIR EXAMPLE"
    });
    let encrypt_response = app
        .clone()
        .oneshot(to_json_request(
            "/classic/playfair/encrypt",
            encrypt_payload,
        ))
        .await
        .unwrap();
    assert_eq!(encrypt_response.status(), StatusCode::OK);
    let encrypt_body = to_bytes(encrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let encrypt_json: Value = serde_json::from_slice(&encrypt_body).unwrap();
    let ciphertext = encrypt_json.get("result").and_then(|v| v.as_str()).unwrap();

    assert_eq!(ciphertext, "BMODZBXDNAGE");

    let decrypt_payload = json!({
        "text": ciphertext,
        "key": "PLAYFAIR EXAMPLE"
    });
    let decrypt_response = app
        .oneshot(to_json_request(
            "/classic/playfair/decrypt",
            decrypt_payload,
        ))
        .await
        .unwrap();
    assert_eq!(decrypt_response.status(), StatusCode::OK);
    let decrypt_body = to_bytes(decrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let decrypt_json: Value = serde_json::from_slice(&decrypt_body).unwrap();
    let plaintext = decrypt_json.get("result").and_then(|v| v.as_str()).unwrap();

    assert!(plaintext.starts_with("HIDETHEGOLD"));
}

#[tokio::test]
async fn hill_encrypt_and_decrypt_endpoints_work() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let encrypt_payload = json!({
        "text": "HELP",
        "key": [[3, 3], [2, 5]]
    });
    let encrypt_response = app
        .clone()
        .oneshot(to_json_request("/classic/hill/encrypt", encrypt_payload))
        .await
        .unwrap();
    assert_eq!(encrypt_response.status(), StatusCode::OK);
    let encrypt_body = to_bytes(encrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let encrypt_json: Value = serde_json::from_slice(&encrypt_body).unwrap();
    let ciphertext = encrypt_json.get("result").and_then(|v| v.as_str()).unwrap();

    assert_eq!(ciphertext, "HIAT");

    let decrypt_payload = json!({
        "text": ciphertext,
        "key": [[3, 3], [2, 5]]
    });
    let decrypt_response = app
        .oneshot(to_json_request("/classic/hill/decrypt", decrypt_payload))
        .await
        .unwrap();
    assert_eq!(decrypt_response.status(), StatusCode::OK);
    let decrypt_body = to_bytes(decrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let decrypt_json: Value = serde_json::from_slice(&decrypt_body).unwrap();

    assert_eq!(
        decrypt_json.get("result").and_then(|v| v.as_str()),
        Some("HELP")
    );
}

#[tokio::test]
async fn otp_encrypt_and_decrypt_endpoints_work() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let plaintext = b"hello";
    let key = [1u8, 2, 3, 4, 5];

    let encrypt_payload = json!({
        "plaintext_base64": STANDARD.encode(plaintext),
        "key_base64": STANDARD.encode(key)
    });
    let encrypt_response = app
        .clone()
        .oneshot(to_json_request("/classic/otp/encrypt", encrypt_payload))
        .await
        .unwrap();
    assert_eq!(encrypt_response.status(), StatusCode::OK);
    let encrypt_body = to_bytes(encrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let encrypt_json: Value = serde_json::from_slice(&encrypt_body).unwrap();

    let decrypt_payload = json!({
        "ciphertext_base64": encrypt_json["result_base64"],
        "key_base64": STANDARD.encode(key)
    });
    let decrypt_response = app
        .oneshot(to_json_request("/classic/otp/decrypt", decrypt_payload))
        .await
        .unwrap();
    assert_eq!(decrypt_response.status(), StatusCode::OK);
    let decrypt_body = to_bytes(decrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let decrypt_json: Value = serde_json::from_slice(&decrypt_body).unwrap();

    let decrypted = STANDARD
        .decode(
            decrypt_json
                .get("result_base64")
                .and_then(|v| v.as_str())
                .unwrap(),
        )
        .unwrap();

    assert_eq!(decrypted, plaintext);
}

#[tokio::test]
async fn frequency_and_index_endpoints_work() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let freq_payload = json!({ "text": "ABBA" });
    let freq_response = app
        .clone()
        .oneshot(to_json_request("/classic/analysis/frequency", freq_payload))
        .await
        .unwrap();
    assert_eq!(freq_response.status(), StatusCode::OK);
    let freq_body = to_bytes(freq_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let freq_json: Value = serde_json::from_slice(&freq_body).unwrap();

    assert_eq!(
        freq_json.get("total_letters").and_then(|v| v.as_i64()),
        Some(4)
    );

    let ic_payload = json!({ "text": "ABBA" });
    let ic_response = app
        .oneshot(to_json_request(
            "/classic/analysis/index-coincidence",
            ic_payload,
        ))
        .await
        .unwrap();
    assert_eq!(ic_response.status(), StatusCode::OK);
    let ic_body = to_bytes(ic_response.into_body(), usize::MAX).await.unwrap();
    let ic_json: Value = serde_json::from_slice(&ic_body).unwrap();

    let index = ic_json.get("index").and_then(|v| v.as_f64()).unwrap();
    assert!(index > 0.0);
}

#[tokio::test]
async fn sha256_hash_endpoint_works() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let payload = json!({
        "text": "abc"
    });
    let response = app
        .oneshot(to_json_request("/hash/sha256", payload))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        value.get("digest").and_then(|v| v.as_str()),
        Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

#[tokio::test]
async fn kasiski_endpoint_works() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let payload = json!({
        "text": "ABCXYZABCXYZ",
        "sequence_len": 3,
        "max_key_len": 12
    });
    let response = app
        .oneshot(to_json_request("/classic/analysis/kasiski", payload))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();

    let distances = value.get("distances").and_then(|v| v.as_array()).unwrap();
    assert!(distances.iter().any(|v| v.as_i64() == Some(6)));
}

#[tokio::test]
async fn vigenere_key_length_endpoint_works() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let payload = json!({
        "text": "QPWKALQPWKALQPWKAL",
        "max_length": 6
    });
    let response = app
        .oneshot(to_json_request(
            "/classic/analysis/vigenere/key-length",
            payload,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    let candidates = value.get("candidates").and_then(|v| v.as_array()).unwrap();

    assert_eq!(candidates.len(), 6);
}

#[tokio::test]
async fn vigenere_estimate_key_endpoint_works() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let payload = json!({
        "text": "QPWKALQPWKALQPWKAL",
        "key_length": 3
    });
    let response = app
        .oneshot(to_json_request(
            "/classic/analysis/vigenere/estimate-key",
            payload,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    let key = value.get("key").and_then(|v| v.as_str()).unwrap();

    assert_eq!(key.len(), 3);
}

#[tokio::test]
async fn rc4_roundtrip_endpoint_works() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let encrypt_payload = json!({
        "plaintext": "Hello RC4",
        "key": "secret"
    });
    let encrypt_response = app
        .clone()
        .oneshot(to_json_request("/symmetric/rc4/encrypt", encrypt_payload))
        .await
        .unwrap();
    assert_eq!(encrypt_response.status(), StatusCode::OK);
    let encrypt_body = to_bytes(encrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let encrypt_json: Value = serde_json::from_slice(&encrypt_body).unwrap();

    let decrypt_payload = json!({
        "ciphertext_hex": encrypt_json["ciphertext_hex"],
        "key": "secret"
    });
    let decrypt_response = app
        .oneshot(to_json_request("/symmetric/rc4/decrypt", decrypt_payload))
        .await
        .unwrap();
    assert_eq!(decrypt_response.status(), StatusCode::OK);
    let decrypt_body = to_bytes(decrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let decrypt_json: Value = serde_json::from_slice(&decrypt_body).unwrap();

    assert_eq!(
        decrypt_json.get("result").and_then(|v| v.as_str()),
        Some("Hello RC4")
    );
}

#[tokio::test]
async fn des_roundtrip_endpoint_works() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let encrypt_payload = json!({
        "plaintext": "hello des",
        "key": "12345678",
        "iv": "87654321"
    });
    let encrypt_response = app
        .clone()
        .oneshot(to_json_request("/symmetric/des/encrypt", encrypt_payload))
        .await
        .unwrap();
    assert_eq!(encrypt_response.status(), StatusCode::OK);
    let encrypt_body = to_bytes(encrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let encrypt_json: Value = serde_json::from_slice(&encrypt_body).unwrap();

    let decrypt_payload = json!({
        "ciphertext_hex": encrypt_json["ciphertext_hex"],
        "key": "12345678",
        "iv": "87654321"
    });
    let decrypt_response = app
        .oneshot(to_json_request("/symmetric/des/decrypt", decrypt_payload))
        .await
        .unwrap();
    assert_eq!(decrypt_response.status(), StatusCode::OK);
    let decrypt_body = to_bytes(decrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let decrypt_json: Value = serde_json::from_slice(&decrypt_body).unwrap();

    assert_eq!(
        decrypt_json.get("result").and_then(|v| v.as_str()),
        Some("hello des")
    );
}

#[tokio::test]
async fn aes_roundtrip_endpoint_works() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let encrypt_payload = json!({
        "plaintext": "hello aes",
        "key": "0123456789abcdef",
        "iv": "abcdef9876543210"
    });
    let encrypt_response = app
        .clone()
        .oneshot(to_json_request("/symmetric/aes/encrypt", encrypt_payload))
        .await
        .unwrap();
    assert_eq!(encrypt_response.status(), StatusCode::OK);
    let encrypt_body = to_bytes(encrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let encrypt_json: Value = serde_json::from_slice(&encrypt_body).unwrap();

    assert_eq!(
        encrypt_json.get("key_size").and_then(|v| v.as_str()),
        Some("AES-128")
    );

    let decrypt_payload = json!({
        "ciphertext_hex": encrypt_json["ciphertext_hex"],
        "key": "0123456789abcdef",
        "iv": "abcdef9876543210"
    });
    let decrypt_response = app
        .oneshot(to_json_request("/symmetric/aes/decrypt", decrypt_payload))
        .await
        .unwrap();
    assert_eq!(decrypt_response.status(), StatusCode::OK);
    let decrypt_body = to_bytes(decrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let decrypt_json: Value = serde_json::from_slice(&decrypt_body).unwrap();

    assert_eq!(
        decrypt_json.get("result").and_then(|v| v.as_str()),
        Some("hello aes")
    );
}

#[tokio::test]
async fn twofish_roundtrip_endpoint_works() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let encrypt_payload = json!({
        "plaintext": "Twofish test message",
        "key": "0123456789ABCDEF",
        "iv": "FEDCBA9876543210"
    });
    let encrypt_response = app
        .clone()
        .oneshot(to_json_request(
            "/symmetric/twofish/encrypt",
            encrypt_payload,
        ))
        .await
        .unwrap();
    assert_eq!(encrypt_response.status(), StatusCode::OK);
    let encrypt_body = to_bytes(encrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let encrypt_json: Value = serde_json::from_slice(&encrypt_body).unwrap();

    let decrypt_payload = json!({
        "ciphertext_hex": encrypt_json["ciphertext_hex"],
        "key": "0123456789ABCDEF",
        "iv": "FEDCBA9876543210"
    });
    let decrypt_response = app
        .oneshot(to_json_request(
            "/symmetric/twofish/decrypt",
            decrypt_payload,
        ))
        .await
        .unwrap();
    assert_eq!(decrypt_response.status(), StatusCode::OK);
    let decrypt_body = to_bytes(decrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let decrypt_json: Value = serde_json::from_slice(&decrypt_body).unwrap();

    assert_eq!(
        decrypt_json.get("result").and_then(|v| v.as_str()),
        Some("Twofish test message")
    );
}

#[tokio::test]
async fn serpent_roundtrip_endpoint_works() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let encrypt_payload = json!({
        "plaintext": "Serpent test message",
        "key": "0123456789ABCDEF",
        "iv": "FEDCBA9876543210"
    });
    let encrypt_response = app
        .clone()
        .oneshot(to_json_request(
            "/symmetric/serpent/encrypt",
            encrypt_payload,
        ))
        .await
        .unwrap();
    assert_eq!(encrypt_response.status(), StatusCode::OK);
    let encrypt_body = to_bytes(encrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let encrypt_json: Value = serde_json::from_slice(&encrypt_body).unwrap();

    let decrypt_payload = json!({
        "ciphertext_hex": encrypt_json["ciphertext_hex"],
        "key": "0123456789ABCDEF",
        "iv": "FEDCBA9876543210"
    });
    let decrypt_response = app
        .oneshot(to_json_request(
            "/symmetric/serpent/decrypt",
            decrypt_payload,
        ))
        .await
        .unwrap();
    assert_eq!(decrypt_response.status(), StatusCode::OK);
    let decrypt_body = to_bytes(decrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let decrypt_json: Value = serde_json::from_slice(&decrypt_body).unwrap();

    assert_eq!(
        decrypt_json.get("result").and_then(|v| v.as_str()),
        Some("Serpent test message")
    );
}

#[tokio::test]
async fn rc6_roundtrip_endpoint_works() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let encrypt_payload = json!({
        "plaintext": "RC6 test message",
        "key": "0123456789ABCDEF",
        "iv": "FEDCBA9876543210"
    });
    let encrypt_response = app
        .clone()
        .oneshot(to_json_request("/symmetric/rc6/encrypt", encrypt_payload))
        .await
        .unwrap();
    assert_eq!(encrypt_response.status(), StatusCode::OK);
    let encrypt_body = to_bytes(encrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let encrypt_json: Value = serde_json::from_slice(&encrypt_body).unwrap();

    let decrypt_payload = json!({
        "ciphertext_hex": encrypt_json["ciphertext_hex"],
        "key": "0123456789ABCDEF",
        "iv": "FEDCBA9876543210"
    });
    let decrypt_response = app
        .oneshot(to_json_request("/symmetric/rc6/decrypt", decrypt_payload))
        .await
        .unwrap();
    assert_eq!(decrypt_response.status(), StatusCode::OK);
    let decrypt_body = to_bytes(decrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let decrypt_json: Value = serde_json::from_slice(&decrypt_body).unwrap();

    assert_eq!(
        decrypt_json.get("result").and_then(|v| v.as_str()),
        Some("RC6 test message")
    );
}

#[tokio::test]
async fn rijndael_roundtrip_endpoint_works() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let encrypt_payload = json!({
        "plaintext": "Rijndael test message",
        "key": "0123456789ABCDEF",
        "iv": "FEDCBA9876543210"
    });
    let encrypt_response = app
        .clone()
        .oneshot(to_json_request(
            "/symmetric/rijndael/encrypt",
            encrypt_payload,
        ))
        .await
        .unwrap();
    assert_eq!(encrypt_response.status(), StatusCode::OK);
    let encrypt_body = to_bytes(encrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let encrypt_json: Value = serde_json::from_slice(&encrypt_body).unwrap();

    let decrypt_payload = json!({
        "ciphertext_hex": encrypt_json["ciphertext_hex"],
        "key": "0123456789ABCDEF",
        "iv": "FEDCBA9876543210"
    });
    let decrypt_response = app
        .oneshot(to_json_request(
            "/symmetric/rijndael/decrypt",
            decrypt_payload,
        ))
        .await
        .unwrap();
    assert_eq!(decrypt_response.status(), StatusCode::OK);
    let decrypt_body = to_bytes(decrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let decrypt_json: Value = serde_json::from_slice(&decrypt_body).unwrap();

    assert_eq!(
        decrypt_json.get("result").and_then(|v| v.as_str()),
        Some("Rijndael test message")
    );
}

#[tokio::test]
async fn rsa_signature_roundtrip_endpoint_works() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let sign_payload = json!({
        "p": 61,
        "q": 53,
        "e": 17,
        "message": "hello"
    });
    let sign_response = app
        .clone()
        .oneshot(to_json_request("/signature/rsa/sign", sign_payload))
        .await
        .unwrap();
    assert_eq!(sign_response.status(), StatusCode::OK);
    let sign_body = to_bytes(sign_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let sign_json: Value = serde_json::from_slice(&sign_body).unwrap();

    let verify_payload = json!({
        "p": 61,
        "q": 53,
        "e": 17,
        "message": "hello",
        "signature": sign_json["signature"]
    });
    let verify_response = app
        .oneshot(to_json_request("/signature/rsa/verify", verify_payload))
        .await
        .unwrap();
    assert_eq!(verify_response.status(), StatusCode::OK);
    let verify_body = to_bytes(verify_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let verify_json: Value = serde_json::from_slice(&verify_body).unwrap();

    assert_eq!(
        verify_json.get("valid").and_then(|v| v.as_bool()),
        Some(true)
    );
}

#[tokio::test]
async fn comms_secure_channel_roundtrip_works() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let setup = DiffieHellmanSetup { p: 23, g: 5 };
    let sender_private = 6;
    let receiver_private = 15;
    let sender_public = compute_public_key(&setup, sender_private).unwrap();
    let receiver_public = compute_public_key(&setup, receiver_private).unwrap();

    let send_payload = json!({
        "p": setup.p,
        "g": setup.g,
        "sender_private": sender_private,
        "receiver_public": receiver_public,
        "sender_public": sender_public,
        "iv": "INITVECTOR123456",
        "plaintext": "bonjour"
    });
    let send_response = app
        .clone()
        .oneshot(to_json_request("/comms/secure-channel/send", send_payload))
        .await
        .unwrap();
    assert_eq!(send_response.status(), StatusCode::OK);
    let send_body = to_bytes(send_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let send_json: Value = serde_json::from_slice(&send_body).unwrap();

    let open_payload = json!({
        "p": setup.p,
        "g": setup.g,
        "receiver_private": receiver_private,
        "sender_public": sender_public,
        "iv_hex": send_json["iv_hex"],
        "ciphertext_hex": send_json["ciphertext_hex"],
        "mac_hex": send_json["mac_hex"]
    });
    let open_response = app
        .oneshot(to_json_request("/comms/secure-channel/open", open_payload))
        .await
        .unwrap();
    assert_eq!(open_response.status(), StatusCode::OK);
    let open_body = to_bytes(open_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let open_json: Value = serde_json::from_slice(&open_body).unwrap();

    assert_eq!(
        open_json.get("plaintext").and_then(|v| v.as_str()),
        Some("bonjour")
    );
}

#[tokio::test]
async fn voting_sign_and_tally_works() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let sign_alice = app
        .clone()
        .oneshot(to_json_request(
            "/comms/voting/sign-ballot",
            json!({"voter_id": "alice", "candidate": "A"}),
        ))
        .await
        .unwrap();
    assert_eq!(sign_alice.status(), StatusCode::OK);
    let alice_body = to_bytes(sign_alice.into_body(), usize::MAX).await.unwrap();
    let alice_json: Value = serde_json::from_slice(&alice_body).unwrap();

    let sign_bob = app
        .clone()
        .oneshot(to_json_request(
            "/comms/voting/sign-ballot",
            json!({"voter_id": "bob", "candidate": "B"}),
        ))
        .await
        .unwrap();
    assert_eq!(sign_bob.status(), StatusCode::OK);
    let bob_body = to_bytes(sign_bob.into_body(), usize::MAX).await.unwrap();
    let bob_json: Value = serde_json::from_slice(&bob_body).unwrap();

    let tally_payload = json!({
        "ballots": [
            {
                "voter_id": alice_json["voter_id"],
                "candidate": alice_json["candidate"],
                "signature": alice_json["signature"]
            },
            {
                "voter_id": bob_json["voter_id"],
                "candidate": bob_json["candidate"],
                "signature": bob_json["signature"]
            }
        ]
    });

    let tally_response = app
        .oneshot(to_json_request("/comms/voting/tally", tally_payload))
        .await
        .unwrap();
    assert_eq!(tally_response.status(), StatusCode::OK);
    let tally_body = to_bytes(tally_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let tally_json: Value = serde_json::from_slice(&tally_body).unwrap();

    let results = tally_json
        .get("results")
        .and_then(|value| value.as_array())
        .unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0]["candidate"], "A");
    assert_eq!(results[0]["votes"], 1);
    assert_eq!(results[1]["candidate"], "B");
    assert_eq!(results[1]["votes"], 1);
}

#[tokio::test]
async fn dsa_sign_and_verify_endpoint_works() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let parameters = dsa::DsaParameters { p: 23, q: 11, g: 4 };
    let key_pair = dsa::generate_key_pair(&parameters, 3).unwrap();

    let sign_payload = json!({
        "p": parameters.p,
        "q": parameters.q,
        "g": parameters.g,
        "private_key": key_pair.private_key,
        "message": "hello",
        "ephemeral_key": 7
    });
    let sign_response = app
        .clone()
        .oneshot(to_json_request("/signature/dsa/sign", sign_payload))
        .await
        .unwrap();
    assert_eq!(sign_response.status(), StatusCode::OK);
    let sign_body = to_bytes(sign_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let sign_json: Value = serde_json::from_slice(&sign_body).unwrap();

    let verify_payload = json!({
        "p": parameters.p,
        "q": parameters.q,
        "g": parameters.g,
        "public_key": key_pair.public_key,
        "message": "hello",
        "r": sign_json["r"],
        "s": sign_json["s"]
    });
    let verify_response = app
        .oneshot(to_json_request("/signature/dsa/verify", verify_payload))
        .await
        .unwrap();
    assert_eq!(verify_response.status(), StatusCode::OK);
    let verify_body = to_bytes(verify_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let verify_json: Value = serde_json::from_slice(&verify_body).unwrap();

    assert_eq!(
        verify_json.get("valid").and_then(|v| v.as_bool()),
        Some(true)
    );
}

#[tokio::test]
async fn ecdsa_sign_and_verify_endpoint_works() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let curve = ecdsa::demo_curve();
    let key_pair = ecdsa::generate_key_pair(&curve, 7).unwrap();

    let sign_payload = json!({
        "private_key": key_pair.private_key,
        "message": "hello",
        "ephemeral_key": 3
    });
    let sign_response = app
        .clone()
        .oneshot(to_json_request("/signature/ecdsa/sign", sign_payload))
        .await
        .unwrap();
    assert_eq!(sign_response.status(), StatusCode::OK);
    let sign_body = to_bytes(sign_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let sign_json: Value = serde_json::from_slice(&sign_body).unwrap();

    let verify_payload = json!({
        "public_key_x": key_pair.public_key.x,
        "public_key_y": key_pair.public_key.y,
        "message": "hello",
        "r": sign_json["r"],
        "s": sign_json["s"]
    });
    let verify_response = app
        .oneshot(to_json_request("/signature/ecdsa/verify", verify_payload))
        .await
        .unwrap();
    assert_eq!(verify_response.status(), StatusCode::OK);
    let verify_body = to_bytes(verify_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let verify_json: Value = serde_json::from_slice(&verify_body).unwrap();

    assert_eq!(
        verify_json.get("valid").and_then(|v| v.as_bool()),
        Some(true)
    );
}

#[tokio::test]
async fn rsa_pkcs1v15_sign_and_verify_endpoint_works() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let sign_payload = json!({
        "p": 61,
        "q": 53,
        "e": 17,
        "message": "hello"
    });
    let sign_response = app
        .clone()
        .oneshot(to_json_request(
            "/signature/rsa/pkcs1v15/sign",
            sign_payload,
        ))
        .await
        .unwrap();
    assert_eq!(sign_response.status(), StatusCode::OK);
    let sign_body = to_bytes(sign_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let sign_json: Value = serde_json::from_slice(&sign_body).unwrap();

    let verify_payload = json!({
        "p": 61,
        "q": 53,
        "e": 17,
        "message": "hello",
        "signature": sign_json["signature"]
    });
    let verify_response = app
        .oneshot(to_json_request(
            "/signature/rsa/pkcs1v15/verify",
            verify_payload,
        ))
        .await
        .unwrap();
    assert_eq!(verify_response.status(), StatusCode::OK);
    let verify_body = to_bytes(verify_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let verify_json: Value = serde_json::from_slice(&verify_body).unwrap();

    assert_eq!(
        verify_json.get("valid").and_then(|v| v.as_bool()),
        Some(true)
    );
}

#[tokio::test]
async fn elgamal_signature_sign_and_verify_endpoint_works() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let parameters = ElGamalParameters { p: 23, g: 5 };
    let key_pair = elgamal::generate_key_pair(&parameters, 6).unwrap();

    let sign_payload = json!({
        "p": parameters.p,
        "g": parameters.g,
        "private_key": key_pair.private_key,
        "message": "hello",
        "ephemeral_key": 7
    });
    let sign_response = app
        .clone()
        .oneshot(to_json_request("/signature/elgamal/sign", sign_payload))
        .await
        .unwrap();
    assert_eq!(sign_response.status(), StatusCode::OK);
    let sign_body = to_bytes(sign_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let sign_json: Value = serde_json::from_slice(&sign_body).unwrap();

    let verify_payload = json!({
        "p": parameters.p,
        "g": parameters.g,
        "public_key": key_pair.public_key,
        "message": "hello",
        "r": sign_json["r"],
        "s": sign_json["s"]
    });
    let verify_response = app
        .oneshot(to_json_request("/signature/elgamal/verify", verify_payload))
        .await
        .unwrap();
    assert_eq!(verify_response.status(), StatusCode::OK);
    let verify_body = to_bytes(verify_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let verify_json: Value = serde_json::from_slice(&verify_body).unwrap();

    assert_eq!(
        verify_json.get("valid").and_then(|v| v.as_bool()),
        Some(true)
    );
}

#[tokio::test]
async fn rsa_keygen_rejects_small_key_size() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let payload = json!({ "bits": 1024 });
    let response = app
        .oneshot(to_json_request("/crypto/keys/rsa", payload))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn otp_encrypt_rejects_invalid_base64() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let payload = json!({
        "plaintext_base64": "not-base64",
        "key_base64": "AQIDBAU="
    });
    let response = app
        .oneshot(to_json_request("/classic/otp/encrypt", payload))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn aes_encrypt_rejects_invalid_key_length() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let payload = json!({
        "plaintext": "hello",
        "key": "short",
        "iv": "abcdef9876543210"
    });
    let response = app
        .oneshot(to_json_request("/symmetric/aes/encrypt", payload))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn secure_channel_decrypt_rejects_invalid_nonce_length() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let payload = json!({
        "receiver_private_key_base64": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
        "sender_public_key_base64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "salt_base64": "c2FsdA==",
        "nonce_base64": "bm9uY2U=",
        "ciphertext_base64": "Q0lQSEVSVEVYVA=="
    });
    let response = app
        .oneshot(to_json_request("/crypto/secure-channel/decrypt", payload))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn md5_sha512_and_hmac_endpoints_work() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let md5_payload = json!({ "text": "abc" });
    let md5_response = app
        .clone()
        .oneshot(to_json_request("/hash/md5", md5_payload))
        .await
        .unwrap();
    assert_eq!(md5_response.status(), StatusCode::OK);
    let md5_body = to_bytes(md5_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let md5_json: Value = serde_json::from_slice(&md5_body).unwrap();

    assert_eq!(
        md5_json.get("digest").and_then(|v| v.as_str()),
        Some("900150983cd24fb0d6963f7d28e17f72")
    );

    let sha_payload = json!({ "text": "abc" });
    let sha_response = app
        .clone()
        .oneshot(to_json_request("/hash/sha512", sha_payload))
        .await
        .unwrap();
    assert_eq!(sha_response.status(), StatusCode::OK);
    let sha_body = to_bytes(sha_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let sha_json: Value = serde_json::from_slice(&sha_body).unwrap();

    assert_eq!(
        sha_json.get("digest").and_then(|v| v.as_str()),
        Some(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )
    );

    let hmac_payload = json!({ "text": "message", "key": "secret" });
    let hmac_response = app
        .oneshot(to_json_request("/hash/hmac", hmac_payload))
        .await
        .unwrap();
    assert_eq!(hmac_response.status(), StatusCode::OK);
    let hmac_body = to_bytes(hmac_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let hmac_json: Value = serde_json::from_slice(&hmac_body).unwrap();
    let expected = hmac_impl::hmac_sha256(b"secret", "message").unwrap();

    assert_eq!(
        hmac_json.get("digest").and_then(|v| v.as_str()),
        Some(expected.as_str())
    );
}

#[tokio::test]
async fn diffie_hellman_exchange_endpoint_works() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let payload = json!({
        "p": 23,
        "g": 5,
        "alice_private": 6,
        "bob_private": 15
    });
    let response = app
        .oneshot(to_json_request("/asymmetric/dh/exchange", payload))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(value.get("alice_public").and_then(|v| v.as_i64()), Some(8));
    assert_eq!(value.get("bob_public").and_then(|v| v.as_i64()), Some(19));
    assert_eq!(value.get("shared_secret").and_then(|v| v.as_i64()), Some(2));
}

#[tokio::test]
async fn rsa_encrypt_and_decrypt_endpoints_work() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let encrypt_payload = json!({
        "p": 61,
        "q": 53,
        "e": 17,
        "message": 65
    });
    let encrypt_response = app
        .clone()
        .oneshot(to_json_request("/asymmetric/rsa/encrypt", encrypt_payload))
        .await
        .unwrap();
    assert_eq!(encrypt_response.status(), StatusCode::OK);
    let encrypt_body = to_bytes(encrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let encrypt_json: Value = serde_json::from_slice(&encrypt_body).unwrap();

    let decrypt_payload = json!({
        "p": 61,
        "q": 53,
        "e": 17,
        "ciphertext": encrypt_json["ciphertext"]
    });
    let decrypt_response = app
        .oneshot(to_json_request("/asymmetric/rsa/decrypt", decrypt_payload))
        .await
        .unwrap();
    assert_eq!(decrypt_response.status(), StatusCode::OK);
    let decrypt_body = to_bytes(decrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let decrypt_json: Value = serde_json::from_slice(&decrypt_body).unwrap();

    assert_eq!(
        decrypt_json.get("message").and_then(|v| v.as_i64()),
        Some(65)
    );
}

#[tokio::test]
async fn elgamal_encrypt_and_decrypt_endpoints_work() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let encrypt_payload = json!({
        "p": 23,
        "g": 5,
        "private_key": 6,
        "message": 10,
        "ephemeral_key": 7
    });
    let encrypt_response = app
        .clone()
        .oneshot(to_json_request(
            "/asymmetric/elgamal/encrypt",
            encrypt_payload,
        ))
        .await
        .unwrap();
    assert_eq!(encrypt_response.status(), StatusCode::OK);
    let encrypt_body = to_bytes(encrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let encrypt_json: Value = serde_json::from_slice(&encrypt_body).unwrap();

    let decrypt_payload = json!({
        "p": 23,
        "g": 5,
        "private_key": 6,
        "c1": encrypt_json["c1"],
        "c2": encrypt_json["c2"]
    });
    let decrypt_response = app
        .oneshot(to_json_request(
            "/asymmetric/elgamal/decrypt",
            decrypt_payload,
        ))
        .await
        .unwrap();
    assert_eq!(decrypt_response.status(), StatusCode::OK);
    let decrypt_body = to_bytes(decrypt_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let decrypt_json: Value = serde_json::from_slice(&decrypt_body).unwrap();

    assert_eq!(
        decrypt_json.get("message").and_then(|v| v.as_i64()),
        Some(10)
    );
}

#[tokio::test]
async fn websocket_route_requires_upgrade() {
    let _env_guard = ensure_api_key_disabled();
    let app = create_app();

    let response = app
        .oneshot(Request::get("/ws/secure").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
