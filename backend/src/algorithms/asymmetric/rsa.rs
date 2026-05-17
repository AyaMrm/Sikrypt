#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RsaError {
    InvalidPrimeParameters,
    InvalidPublicExponent,
    MessageTooLarge,
    ModularInverseDoesNotExist,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaKeyPair {
    pub p: u128,
    pub q: u128,
    pub n: u128,
    pub phi: u128,
    pub e: u128,
    pub d: u128,
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

fn is_prime(n: u128) -> bool {
    if n < 2 {
        return false;
    }
    if n == 2 {
        return true;
    }
    if n.is_multiple_of(2) {
        return false;
    }

    let mut divisor = 3u128;
    while divisor * divisor <= n {
        if n.is_multiple_of(divisor) {
            return false;
        }
        divisor += 2;
    }

    true
}

pub fn generate_key_pair(p: u128, q: u128, e: u128) -> Result<RsaKeyPair, RsaError> {
    if !is_prime(p) || !is_prime(q) || p == q {
        return Err(RsaError::InvalidPrimeParameters);
    }

    let n = p.saturating_mul(q);
    let phi = (p - 1).saturating_mul(q - 1);

    if e <= 1 || e >= phi || gcd(e, phi) != 1 {
        return Err(RsaError::InvalidPublicExponent);
    }

    let d = mod_inverse(e, phi).ok_or(RsaError::ModularInverseDoesNotExist)?;

    Ok(RsaKeyPair { p, q, n, phi, e, d })
}

pub fn encrypt(message: u128, key_pair: &RsaKeyPair) -> Result<u128, RsaError> {
    if message >= key_pair.n {
        return Err(RsaError::MessageTooLarge);
    }

    Ok(mod_pow(message, key_pair.e, key_pair.n))
}

pub fn decrypt(ciphertext: u128, key_pair: &RsaKeyPair) -> u128 {
    mod_pow(ciphertext, key_pair.d, key_pair.n)
}

#[cfg(test)]
mod tests {
    use super::{RsaError, decrypt, encrypt, generate_key_pair};

    #[test]
    fn encrypts_and_decrypts_known_example() {
        let key_pair = generate_key_pair(61, 53, 17).unwrap();
        let ciphertext = encrypt(65, &key_pair).unwrap();

        assert_eq!(ciphertext, 2790);
        assert_eq!(decrypt(ciphertext, &key_pair), 65);
    }

    #[test]
    fn rejects_non_prime_parameters() {
        let result = generate_key_pair(4, 53, 17);
        assert_eq!(result, Err(RsaError::InvalidPrimeParameters));
    }

    #[test]
    fn rejects_message_outside_modulus() {
        let key_pair = generate_key_pair(61, 53, 17).unwrap();
        let result = encrypt(key_pair.n, &key_pair);

        assert_eq!(result, Err(RsaError::MessageTooLarge));
    }
}
