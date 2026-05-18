#[derive(Debug, Clone, PartialEq, Eq)]

pub enum HillError {
    InvalidMatrix,
    NonInvertibleMatrix,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Matrix2x2 {
    pub a11: i32,
    pub a12: i32,
    pub a21: i32,
    pub a22: i32,
}

impl Matrix2x2 {
    pub fn determinant(self) -> i32 {
        self.a11 * self.a22 - self.a12 * self.a21
    }

    pub fn inverse_mod_26(self) -> Result<Self, HillError> {
        let det = self.determinant().rem_euclid(26);
        let det_inv = mod_inverse(det, 26).ok_or(HillError::NonInvertibleMatrix)?;

        Ok(Self {
            a11: (self.a22 * det_inv).rem_euclid(26),
            a12: (-self.a12 * det_inv).rem_euclid(26),
            a21: (-self.a21 * det_inv).rem_euclid(26),
            a22: (self.a11 * det_inv).rem_euclid(26),
        })
    }
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

fn text_to_numbers(text: &str) -> Vec<i32> {
    text.chars()
        .filter(|ch| ch.is_ascii_alphabetic())
        .map(|ch| (ch.to_ascii_uppercase() as u8 - b'A') as i32)
        .collect()
}

fn numbers_to_text(values: &[i32]) -> String {
    values
        .iter()
        .map(|value| (b'A' + value.rem_euclid(26) as u8) as char)
        .collect()
}

fn apply_matrix_pair(matrix: Matrix2x2, x: i32, y: i32) -> (i32, i32) {
    let first = (matrix.a11 * x + matrix.a12 * y).rem_euclid(26);
    let second = (matrix.a21 * x + matrix.a22 * y).rem_euclid(26);
    (first, second)
}

pub fn encrypt(plaintext: &str, key: Matrix2x2) -> Result<String, HillError> {
    key.inverse_mod_26()?;

    let mut values = text_to_numbers(plaintext);
    if values.is_empty() {
        return Ok(String::new());
    }

    if !values.len().is_multiple_of(2) {
        values.push(23);
    }

    let mut output = Vec::with_capacity(values.len());
    for pair in values.chunks_exact(2) {
        let (first, second) = apply_matrix_pair(key, pair[0], pair[1]);
        output.push(first);
        output.push(second);
    }

    Ok(numbers_to_text(&output))
}

pub fn decrypt(ciphertext: &str, key: Matrix2x2) -> Result<String, HillError> {
    let inverse = key.inverse_mod_26()?;
    let values = text_to_numbers(ciphertext);

    if !values.len().is_multiple_of(2) {
        return Err(HillError::InvalidMatrix);
    }

    let mut output = Vec::with_capacity(values.len());
    for pair in values.chunks_exact(2) {
        let (first, second) = apply_matrix_pair(inverse, pair[0], pair[1]);
        output.push(first);
        output.push(second);
    }

    Ok(numbers_to_text(&output))
}

#[cfg(test)]
mod tests {
    use super::{HillError, Matrix2x2, decrypt, encrypt};

    #[test]
    fn encrypts_known_example() {
        let key = Matrix2x2 {
            a11: 3,
            a12: 3,
            a21: 2,
            a22: 5,
        };

        let encrypted = encrypt("HELP", key).unwrap();
        assert_eq!(encrypted, "HIAT");
        assert_eq!(decrypt(&encrypted, key).unwrap(), "HELP");
    }

    #[test]
    fn pads_odd_length_messages_with_x() {
        let key = Matrix2x2 {
            a11: 3,
            a12: 3,
            a21: 2,
            a22: 5,
        };

        let encrypted = encrypt("CAT", key).unwrap();
        assert_eq!(decrypt(&encrypted, key).unwrap(), "CATX");
    }

    #[test]
    fn rejects_non_invertible_matrix() {
        let key = Matrix2x2 {
            a11: 2,
            a12: 4,
            a21: 2,
            a22: 4,
        };

        assert_eq!(encrypt("TEST", key), Err(HillError::NonInvertibleMatrix));
    }
}
