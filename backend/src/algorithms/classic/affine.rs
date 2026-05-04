#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AffineError {
    InvalidMultiplier,
}

fn gcd(mut a: i32, mut b: i32) -> i32 {
    while b != 0 {
        let temp = a % b;
        a = b;
        b = temp;
    }

    a.abs()
}

fn mod_inverse(value: i32, modulus: i32) -> Option<i32> {
    let mut t = 0;
    let mut new_t = 1;
    let mut r = modulus;
    let mut new_r = value.rem_euclid(modulus);

    while new_r != 0 {
        let quotient = r / new_r;

        let temp_t = t - quotient * new_t;
        t = new_t;
        new_t = temp_t;

        let temp_r = r - quotient * new_r;
        r = new_r;
        new_r = temp_r;
    }

    if r > 1 {
        return None;
    }

    Some(t.rem_euclid(modulus))
}

fn transform_char(ch: char, a: i32, b: i32, decrypt: bool) -> Result<char, AffineError> {
    if !ch.is_ascii_alphabetic() {
        return Ok(ch);
    }

    if gcd(a, 26) != 1 {
        return Err(AffineError::InvalidMultiplier);
    }

    let base = if ch.is_ascii_uppercase() { b'A' } else { b'a' };
    let normalized = (ch as u8 - base) as i32;

    let transformed = if decrypt {
        let inv = mod_inverse(a, 26).ok_or(AffineError::InvalidMultiplier)?;
        (inv * (normalized - b)).rem_euclid(26)
    } else {
        (a * normalized + b).rem_euclid(26)
    } as u8;

    Ok((base + transformed) as char)
}

pub fn encrypt(plaintext: &str, a: i32, b: i32) -> Result<String, AffineError> {
    plaintext
        .chars()
        .map(|ch| transform_char(ch, a, b, false))
        .collect()
}

pub fn decrypt(ciphertext: &str, a: i32, b: i32) -> Result<String, AffineError> {
    ciphertext
        .chars()
        .map(|ch| transform_char(ch, a, b, true))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{decrypt, encrypt, AffineError};

    #[test]
    fn encrypts_and_decrypts() {
        let encrypted = encrypt("AFFINE CIPHER", 5, 8).unwrap();
        assert_eq!(encrypted, "IHHWVC SWFRCP");
        assert_eq!(decrypt(&encrypted, 5, 8).unwrap(), "AFFINE CIPHER");
    }

    #[test]
    fn rejects_invalid_multiplier() {
        let result = encrypt("HELLO", 13, 2);
        assert_eq!(result, Err(AffineError::InvalidMultiplier));
    }
}
