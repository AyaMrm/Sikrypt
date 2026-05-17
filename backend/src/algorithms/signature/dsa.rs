use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DsaError {
    InvalidParameters,
    InvalidPrivateKey,
    InvalidEphemeralKey,
    ModularInverseDoesNotExist,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsaParameters {
    pub p: u128,
    pub q: u128,
    pub g: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsaKeyPair {
    pub private_key: u128,
    pub public_key: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsaSignature {
    pub r: u128,
    pub s: u128,
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

fn hash_to_field(message: &str, modulus: u128) -> u128 {
    let digest = Sha256::digest(message.as_bytes());
    let mut reduced = 0u128;

    for &byte in digest.iter().take(16) {
        reduced = (reduced << 8) | byte as u128;
    }

    reduced % modulus
}

fn validate_parameters(parameters: &DsaParameters) -> Result<(), DsaError> {
    if parameters.p <= 2 || parameters.q <= 1 || parameters.g <= 1 || parameters.g >= parameters.p {
        return Err(DsaError::InvalidParameters);
    }

    Ok(())
}

pub fn generate_key_pair(
    parameters: &DsaParameters,
    private_key: u128,
) -> Result<DsaKeyPair, DsaError> {
    validate_parameters(parameters)?;

    if private_key == 0 || private_key >= parameters.q {
        return Err(DsaError::InvalidPrivateKey);
    }

    Ok(DsaKeyPair {
        private_key,
        public_key: mod_pow(parameters.g, private_key, parameters.p),
    })
}

pub fn sign(
    parameters: &DsaParameters,
    private_key: u128,
    message: &str,
    ephemeral_key: u128,
) -> Result<DsaSignature, DsaError> {
    validate_parameters(parameters)?;

    if private_key == 0 || private_key >= parameters.q {
        return Err(DsaError::InvalidPrivateKey);
    }

    if ephemeral_key == 0 || ephemeral_key >= parameters.q {
        return Err(DsaError::InvalidEphemeralKey);
    }

    let r = mod_pow(parameters.g, ephemeral_key, parameters.p) % parameters.q;
    let k_inv =
        mod_inverse(ephemeral_key, parameters.q).ok_or(DsaError::ModularInverseDoesNotExist)?;
    let z = hash_to_field(message, parameters.q);
    let s = (k_inv.saturating_mul(z + private_key.saturating_mul(r))) % parameters.q;

    if r == 0 || s == 0 {
        return Err(DsaError::InvalidEphemeralKey);
    }

    Ok(DsaSignature { r, s })
}

pub fn verify(
    parameters: &DsaParameters,
    public_key: u128,
    message: &str,
    signature: &DsaSignature,
) -> Result<bool, DsaError> {
    validate_parameters(parameters)?;

    if signature.r == 0
        || signature.r >= parameters.q
        || signature.s == 0
        || signature.s >= parameters.q
    {
        return Ok(false);
    }

    let w = mod_inverse(signature.s, parameters.q).ok_or(DsaError::ModularInverseDoesNotExist)?;
    let z = hash_to_field(message, parameters.q);
    let u1 = (z * w) % parameters.q;
    let u2 = (signature.r * w) % parameters.q;
    let v = (mod_pow(parameters.g, u1, parameters.p) * mod_pow(public_key, u2, parameters.p)
        % parameters.p)
        % parameters.q;

    Ok(v == signature.r)
}

#[cfg(test)]
mod tests {
    use super::{DsaParameters, generate_key_pair, sign, verify};

    #[test]
    fn signs_and_verifies_message() {
        let parameters = DsaParameters { p: 23, q: 11, g: 4 };
        let key_pair = generate_key_pair(&parameters, 3).unwrap();
        let signature = sign(&parameters, key_pair.private_key, "hello", 7).unwrap();

        assert!(verify(&parameters, key_pair.public_key, "hello", &signature).unwrap());
    }

    #[test]
    fn rejects_modified_message() {
        let parameters = DsaParameters { p: 23, q: 11, g: 4 };
        let key_pair = generate_key_pair(&parameters, 3).unwrap();
        let signature = sign(&parameters, key_pair.private_key, "hello", 7).unwrap();

        assert!(!verify(&parameters, key_pair.public_key, "HELLO", &signature).unwrap());
    }
}
