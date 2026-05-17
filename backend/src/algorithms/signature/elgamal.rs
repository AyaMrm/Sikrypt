use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElGamalSignatureError {
    InvalidParameters,
    InvalidPrivateKey,
    InvalidEphemeralKey,
    ModularInverseDoesNotExist,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElGamalSignature {
    pub r: u128,
    pub s: u128,
}

fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let tmp = a % b;
        a = b;
        b = tmp;
    }
    a
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

fn extended_gcd(a: i128, b: i128) -> (i128, i128, i128) {
    if b == 0 {
        (a, 1, 0)
    } else {
        let (gcd, x1, y1) = extended_gcd(b, a % b);
        (gcd, y1, x1 - (a / b) * y1)
    }
}

fn mod_inverse(value: u128, modulus: u128) -> Option<u128> {
    let (gcd, x, _) = extended_gcd(value as i128, modulus as i128);
    if gcd != 1 {
        None
    } else {
        Some(x.rem_euclid(modulus as i128) as u128)
    }
}

fn hash_to_modulus(message: &str, modulus: u128) -> u128 {
    let digest = Sha256::digest(message.as_bytes());
    let mut reduced = 0u128;

    for &byte in digest.iter().take(16) {
        reduced = (reduced << 8) | byte as u128;
    }

    reduced % modulus
}

fn validate_parameters(p: u128, g: u128) -> Result<(), ElGamalSignatureError> {
    if p <= 3 {
        return Err(ElGamalSignatureError::InvalidParameters);
    }

    if g < 2 || g >= p {
        return Err(ElGamalSignatureError::InvalidParameters);
    }

    Ok(())
}

fn validate_private_key(p: u128, g: u128, private_key: u128) -> Result<(), ElGamalSignatureError> {
    validate_parameters(p, g)?;

    if private_key == 0 || private_key >= p - 1 {
        return Err(ElGamalSignatureError::InvalidPrivateKey);
    }

    Ok(())
}

pub fn sign(
    p: u128,
    g: u128,
    private_key: u128,
    message: &str,
    ephemeral_key: u128,
) -> Result<ElGamalSignature, ElGamalSignatureError> {
    validate_private_key(p, g, private_key)?;

    if ephemeral_key == 0 || ephemeral_key >= p - 1 {
        return Err(ElGamalSignatureError::InvalidEphemeralKey);
    }

    let modulus = p - 1;
    if gcd(ephemeral_key, modulus) != 1 {
        return Err(ElGamalSignatureError::InvalidEphemeralKey);
    }

    let r = mod_pow(g, ephemeral_key, p);
    if r == 0 {
        return Err(ElGamalSignatureError::InvalidEphemeralKey);
    }

    let k_inv = mod_inverse(ephemeral_key, modulus)
        .ok_or(ElGamalSignatureError::ModularInverseDoesNotExist)?;
    let hash = hash_to_modulus(message, modulus);

    let xr = (private_key.saturating_mul(r)) % modulus;
    let s = ((hash + modulus).saturating_sub(xr) % modulus).saturating_mul(k_inv) % modulus;

    if s == 0 {
        return Err(ElGamalSignatureError::InvalidEphemeralKey);
    }

    Ok(ElGamalSignature { r, s })
}

pub fn verify(
    p: u128,
    g: u128,
    public_key: u128,
    message: &str,
    signature: &ElGamalSignature,
) -> Result<bool, ElGamalSignatureError> {
    validate_parameters(p, g)?;

    if signature.r == 0 || signature.r >= p {
        return Ok(false);
    }

    let modulus = p - 1;
    if signature.s == 0 || signature.s >= modulus {
        return Ok(false);
    }

    let hash = hash_to_modulus(message, modulus);
    let left = mod_pow(g, hash, p);
    let right = (mod_pow(public_key, signature.r, p) * mod_pow(signature.r, signature.s, p)) % p;

    Ok(left == right)
}

#[cfg(test)]
mod tests {
    use super::{ElGamalSignatureError, sign, verify};

    #[test]
    fn signs_and_verifies_message() {
        let p = 23;
        let g = 5;
        let private_key = 6;
        let public_key = 8;
        let signature = sign(p, g, private_key, "hello", 7).unwrap();

        assert!(verify(p, g, public_key, "hello", &signature).unwrap());
    }

    #[test]
    fn rejects_modified_message() {
        let p = 23;
        let g = 5;
        let private_key = 6;
        let public_key = 8;
        let signature = sign(p, g, private_key, "hello", 7).unwrap();

        assert!(!verify(p, g, public_key, "HELLO", &signature).unwrap());
    }

    #[test]
    fn rejects_bad_ephemeral_key() {
        let result = sign(23, 5, 6, "hello", 11);
        assert_eq!(result, Err(ElGamalSignatureError::InvalidEphemeralKey));
    }
}
