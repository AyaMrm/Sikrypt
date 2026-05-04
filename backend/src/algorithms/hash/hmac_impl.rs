use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HmacError {
    InvalidKeyLength,
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn hmac_sha256(key: &[u8], message: &str) -> Result<String, HmacError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| HmacError::InvalidKeyLength)?;
    mac.update(message.as_bytes());

    let tag = mac.finalize().into_bytes();
    Ok(to_hex(&tag))
}

pub fn verify_hmac_sha256(key: &[u8], message: &str, expected_hex: &str) -> Result<bool, HmacError> {
    Ok(hmac_sha256(key, message)? == expected_hex.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::{hmac_sha256, verify_hmac_sha256};

    #[test]
    fn computes_hmac_sha256_known_vector() {
        let digest = hmac_sha256(b"key", "The quick brown fox jumps over the lazy dog").unwrap();
        assert_eq!(
            digest,
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn verifies_valid_hmac() {
        let valid = verify_hmac_sha256(
            b"key",
            "The quick brown fox jumps over the lazy dog",
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
        )
        .unwrap();

        assert!(valid);
    }

    #[test]
    fn rejects_invalid_hmac() {
        let valid = verify_hmac_sha256(b"key", "hello", "deadbeef").unwrap();
        assert!(!valid);
    }
}
