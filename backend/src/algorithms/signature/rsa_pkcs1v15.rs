use crate::algorithms::asymmetric::rsa::RsaKeyPair;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RsaPkcs1v15Error {
    InvalidModulus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPkcs1v15Signature {
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

fn hash_message_to_modulus(message: &str, modulus: u128) -> Result<u128, RsaPkcs1v15Error> {
    if modulus <= 1 {
        return Err(RsaPkcs1v15Error::InvalidModulus);
    }

    // Educational placeholder for PKCS#1 v1.5: hash with domain separation and reduce.
    let mut hasher = Sha256::new();
    hasher.update(b"pkcs1v15");
    hasher.update(message.as_bytes());
    let digest = hasher.finalize();
    let mut reduced = 0u128;

    for &byte in digest.iter().take(16) {
        reduced = (reduced << 8) | byte as u128;
    }

    Ok(reduced % modulus)
}

pub fn sign(
    message: &str,
    key_pair: &RsaKeyPair,
) -> Result<RsaPkcs1v15Signature, RsaPkcs1v15Error> {
    let hashed = hash_message_to_modulus(message, key_pair.n)?;
    Ok(RsaPkcs1v15Signature {
        signature: mod_pow(hashed, key_pair.d, key_pair.n),
    })
}

pub fn verify(
    message: &str,
    signature: &RsaPkcs1v15Signature,
    key_pair: &RsaKeyPair,
) -> Result<bool, RsaPkcs1v15Error> {
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
