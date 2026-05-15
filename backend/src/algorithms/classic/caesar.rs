#[derive(Debug, Clone, PartialEq, Eq)]

pub struct CaesarCandidate {
    pub shift: i32,
    pub plaintext: String,
}

fn shift_char(ch: char, shift: i32) -> char {
    if !ch.is_ascii_alphabetic() {
        return ch;
    }

    let base = if ch.is_ascii_uppercase() { b'A' } else { b'a' };
    let normalized = ch as u8 - base;
    let shifted = (normalized as i32 + shift).rem_euclid(26) as u8;

    (base + shifted) as char
}

pub fn encrypt(plaintext: &str, shift: i32) -> String {
    plaintext.chars().map(|ch| shift_char(ch, shift)).collect()
}

pub fn decrypt(ciphertext: &str, shift: i32) -> String {
    encrypt(ciphertext, -shift)
}

pub fn brute_force(ciphertext: &str) -> Vec<CaesarCandidate> {
    (0..26)
        .map(|shift| CaesarCandidate {
            shift,
            plaintext: decrypt(ciphertext, shift),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{brute_force, decrypt, encrypt};

    #[test]
    fn encrypts_and_decrypts_basic_text() {
        let encrypted = encrypt("HELLO WORLD", 3);
        assert_eq!(encrypted, "KHOOR ZRUOG");
        assert_eq!(decrypt(&encrypted, 3), "HELLO WORLD");
    }

    #[test]
    fn preserves_case_and_symbols() {
        let encrypted = encrypt("Abc-xyz!", 2);
        assert_eq!(encrypted, "Cde-zab!");
    }

    #[test]
    fn brute_force_returns_all_candidates() {
        let candidates = brute_force("KHOOR");
        assert_eq!(candidates.len(), 26);
        assert!(candidates.iter().any(|candidate| candidate.plaintext == "HELLO"));
    }
}
