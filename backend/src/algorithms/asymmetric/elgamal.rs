#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElGamalError {
    InvalidModulus,
    InvalidGenerator,
    InvalidPrivateKey,
    InvalidEphemeralKey,
    MessageTooLarge,
    SharedSecretNotInvertible,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElGamalParameters {
    pub p: u128,
    pub g: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElGamalKeyPair {
    pub private_key: u128,
    pub public_key: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElGamalCiphertext {
    pub c1: u128,
    pub c2: u128,
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

fn validate_parameters(parameters: &ElGamalParameters) -> Result<(), ElGamalError> {
    if parameters.p < 3 {
        return Err(ElGamalError::InvalidModulus);
    }

    if parameters.g < 2 || parameters.g >= parameters.p {
        return Err(ElGamalError::InvalidGenerator);
    }

    Ok(())
}

fn validate_private_key(parameters: &ElGamalParameters, private_key: u128) -> Result<(), ElGamalError> {
    validate_parameters(parameters)?;

    if private_key == 0 || private_key >= parameters.p - 1 {
        return Err(ElGamalError::InvalidPrivateKey);
    }

    Ok(())
}

pub fn generate_key_pair(
    parameters: &ElGamalParameters,
    private_key: u128,
) -> Result<ElGamalKeyPair, ElGamalError> {
    validate_private_key(parameters, private_key)?;

    Ok(ElGamalKeyPair {
        private_key,
        public_key: mod_pow(parameters.g, private_key, parameters.p),
    })
}

pub fn encrypt(
    parameters: &ElGamalParameters,
    recipient_public_key: u128,
    message: u128,
    ephemeral_key: u128,
) -> Result<ElGamalCiphertext, ElGamalError> {
    validate_parameters(parameters)?;

    if message >= parameters.p {
        return Err(ElGamalError::MessageTooLarge);
    }

    if ephemeral_key == 0 || ephemeral_key >= parameters.p - 1 {
        return Err(ElGamalError::InvalidEphemeralKey);
    }

    let c1 = mod_pow(parameters.g, ephemeral_key, parameters.p);
    let shared_secret = mod_pow(recipient_public_key, ephemeral_key, parameters.p);
    let c2 = message.saturating_mul(shared_secret) % parameters.p;

    Ok(ElGamalCiphertext { c1, c2 })
}

pub fn decrypt(
    parameters: &ElGamalParameters,
    private_key: u128,
    ciphertext: &ElGamalCiphertext,
) -> Result<u128, ElGamalError> {
    validate_private_key(parameters, private_key)?;

    let shared_secret = mod_pow(ciphertext.c1, private_key, parameters.p);
    let inverse = mod_inverse(shared_secret, parameters.p)
        .ok_or(ElGamalError::SharedSecretNotInvertible)?;

    Ok(ciphertext.c2.saturating_mul(inverse) % parameters.p)
}

#[cfg(test)]
mod tests {
    use super::{decrypt, encrypt, generate_key_pair, ElGamalError, ElGamalParameters};

    #[test]
    fn encrypts_and_decrypts_message() {
        let parameters = ElGamalParameters { p: 23, g: 5 };
        let key_pair = generate_key_pair(&parameters, 6).unwrap();
        let ciphertext = encrypt(&parameters, key_pair.public_key, 10, 7).unwrap();

        assert_eq!(decrypt(&parameters, key_pair.private_key, &ciphertext).unwrap(), 10);
    }

    #[test]
    fn same_message_with_different_ephemeral_keys_changes_ciphertext() {
        let parameters = ElGamalParameters { p: 23, g: 5 };
        let key_pair = generate_key_pair(&parameters, 6).unwrap();

        let first = encrypt(&parameters, key_pair.public_key, 10, 7).unwrap();
        let second = encrypt(&parameters, key_pair.public_key, 10, 11).unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn rejects_message_too_large() {
        let parameters = ElGamalParameters { p: 23, g: 5 };
        let result = encrypt(&parameters, 8, 23, 7);

        assert_eq!(result, Err(ElGamalError::MessageTooLarge));
    }
}
