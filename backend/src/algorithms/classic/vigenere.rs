#[derive(Debug, Clone, PartialEq, Eq)]

pub enum VigenereError {
    EmptyKey,
    InvalidKey,
}

fn normalize_key(key: &str) -> Result<Vec<u8>, VigenereError> {
    if key.is_empty() {
        return Err(VigenereError::EmptyKey);
    }

    let shifts: Vec<u8> = key
        .chars()
        .filter(|ch| ch.is_ascii_alphabetic())
        .map(|ch| ch.to_ascii_uppercase() as u8 - b'A')
        .collect();

    if shifts.is_empty() {
        return Err(VigenereError::InvalidKey);
    }

    Ok(shifts)
}

fn transform(text: &str, key: &str, decrypt: bool) -> Result<String, VigenereError> {
    let shifts = normalize_key(key)?;
    let mut key_index = 0usize;
    let mut output = String::with_capacity(text.len());

    for ch in text.chars() {
        if ch.is_ascii_alphabetic() {
            let shift = shifts[key_index % shifts.len()] as i32;
            let effective_shift = if decrypt { -shift } else { shift };
            let base = if ch.is_ascii_uppercase() { b'A' } else { b'a' };
            let normalized = ch as u8 - base;
            let transformed = (normalized as i32 + effective_shift).rem_euclid(26) as u8;

            output.push((base + transformed) as char);
            key_index += 1;
        } else {
            output.push(ch);
        }
    }

    Ok(output)
}

pub fn encrypt(plaintext: &str, key: &str) -> Result<String, VigenereError> {
    transform(plaintext, key, false)
}

pub fn decrypt(ciphertext: &str, key: &str) -> Result<String, VigenereError> {
    transform(ciphertext, key, true)
}

#[cfg(test)]
mod tests {
    use super::{VigenereError, decrypt, encrypt};

    #[test]
    fn encrypts_and_decrypts_known_example() {
        let encrypted = encrypt("ATTACKATDAWN", "LEMON").unwrap();
        assert_eq!(encrypted, "LXFOPVEFRNHR");
        assert_eq!(decrypt(&encrypted, "LEMON").unwrap(), "ATTACKATDAWN");
    }

    #[test]
    fn preserves_non_alphabetic_characters() {
        let encrypted = encrypt("Attack at dawn!", "LEMON").unwrap();
        assert_eq!(encrypted, "Lxfopv ef rnhr!");
    }

    #[test]
    fn rejects_empty_key() {
        assert_eq!(encrypt("HELLO", ""), Err(VigenereError::EmptyKey));
    }
}
