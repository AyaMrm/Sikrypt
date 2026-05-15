use crate::algorithms::asymmetric::rsa::RsaKeyPair;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RsaPssError {
    InvalidModulus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPssSignature {
    pub signature: u128,
}

fn mod_pow(mut base: u128, mut exponent: u128, modulus: u128) -> u128 {
    let mut result = 1u128;
    base %= modulus;

    while exponent > 0 {
        if exponent & 1 == 1 {
            result = result.saturating_mul(base) % modulus;
        }
        exponent >>= 1;
        base = base.saturating_mul(base) % modulus;
    }

    result
}

fn hash_message_to_modulus(message: &str, modulus: u128) -> Result<u128, RsaPssError> {
    if modulus <= 1 {
        return Err(RsaPssError::InvalidModulus);
    }

    let digest = Sha256::digest(message.as_bytes());
    let mut reduced = 0u128;

    for &byte in digest.iter().take(16) {
        reduced = (reduced << 8) | byte as u128;
    }

    Ok(reduced % modulus)
}

pub fn sign(message: &str, key_pair: &RsaKeyPair) -> Result<RsaPssSignature, RsaPssError> {
    let hashed = hash_message_to_modulus(message, key_pair.n)?;
    Ok(RsaPssSignature {
        signature: mod_pow(hashed, key_pair.d, key_pair.n),
    })
}

pub fn verify(
    message: &str,
    signature: &RsaPssSignature,
    key_pair: &RsaKeyPair,
) -> Result<bool, RsaPssError> {
    let expected = hash_message_to_modulus(message, key_pair.n)?;
    let recovered = mod_pow(signature.signature, key_pair.e, key_pair.n);
    Ok(expected == recovered)
}

#[cfg(test)]
mod tests {
    use super::{sign, verify};
    use crate::algorithms::asymmetric::rsa;

    #[test]
    fn signs_and_verifies_message() {
        let key_pair = rsa::generate_key_pair(61, 53, 17).unwrap();
        let signature = sign("hello", &key_pair).unwrap();

        assert!(verify("hello", &signature, &key_pair).unwrap());
    }

    #[test]
    fn rejects_modified_message() {
        let key_pair = rsa::generate_key_pair(61, 53, 17).unwrap();
        let signature = sign("hello", &key_pair).unwrap();

        assert!(!verify("HELLO", &signature, &key_pair).unwrap());
    }
}
