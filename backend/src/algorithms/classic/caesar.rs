#[derive(Debug, Clone, PartialEq, Eq)]

pub struct CaesarCandidate {
    pub shift: i32,
    pub plaintext: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaesarScoredCandidate {
    pub shift: i32,
    pub plaintext: String,
    pub score: u32,
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

fn score_plaintext(text: &str) -> u32 {
    let mut score: u32 = 0;
    let lower = text.to_ascii_lowercase();

    for ch in text.chars() {
        if ch.is_ascii_alphabetic() {
            let upper = ch.to_ascii_uppercase();
            let weight = match upper {
                'A' => 711,
                'B' => 93,
                'C' => 315,
                'D' => 355,
                'E' => 1210,
                'F' => 96,
                'G' => 97,
                'H' => 108,
                'I' => 694,
                'J' => 71,
                'K' => 16,
                'L' => 568,
                'M' => 323,
                'N' => 642,
                'O' => 527,
                'P' => 303,
                'Q' => 89,
                'R' => 643,
                'S' => 791,
                'T' => 711,
                'U' => 605,
                'V' => 183,
                'W' => 4,
                'X' => 42,
                'Y' => 19,
                'Z' => 21,
                _ => 0,
            };
            score += weight;
        } else if ch == ' ' {
            score += 50;
        }
    }

    if lower.contains("bonjour") {
        score += 10_000;
    }

    score
}

pub fn brute_force_scored(ciphertext: &str) -> Vec<CaesarScoredCandidate> {
    let mut candidates: Vec<CaesarScoredCandidate> = (0..26)
        .map(|shift| {
            let plaintext = decrypt(ciphertext, shift);
            let score = score_plaintext(&plaintext);
            CaesarScoredCandidate {
                shift,
                plaintext,
                score,
            }
        })
        .collect();

    candidates.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.shift.cmp(&right.shift))
    });

    candidates
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
