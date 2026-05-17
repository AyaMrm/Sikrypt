use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlayfairError {
    EmptyKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Position {
    row: usize,
    col: usize,
}

fn normalize_key(key: &str) -> Result<Vec<char>, PlayfairError> {
    let mut seen = HashMap::new();
    let mut chars = Vec::new();

    for ch in key.chars() {
        if !ch.is_ascii_alphabetic() {
            continue;
        }

        let mut upper = ch.to_ascii_uppercase();
        if upper == 'J' {
            upper = 'I';
        }

        if seen.insert(upper, true).is_none() {
            chars.push(upper);
        }
    }

    if chars.is_empty() {
        return Err(PlayfairError::EmptyKey);
    }

    for ch in 'A'..='Z' {
        if ch == 'J' {
            continue;
        }
        if seen.insert(ch, true).is_none() {
            chars.push(ch);
        }
    }

    Ok(chars)
}

fn build_square(key: &str) -> Result<([char; 25], HashMap<char, Position>), PlayfairError> {
    let chars = normalize_key(key)?;
    let mut square = ['A'; 25];
    let mut positions = HashMap::new();

    for (index, ch) in chars.into_iter().enumerate() {
        square[index] = ch;
        positions.insert(
            ch,
            Position {
                row: index / 5,
                col: index % 5,
            },
        );
    }

    Ok((square, positions))
}

fn sanitize_text(text: &str) -> Vec<char> {
    text.chars()
        .filter(|ch| ch.is_ascii_alphabetic())
        .map(|ch| {
            let mut upper = ch.to_ascii_uppercase();
            if upper == 'J' {
                upper = 'I';
            }
            upper
        })
        .collect()
}

fn digraphs_for_encrypt(text: &str) -> Vec<(char, char)> {
    let chars = sanitize_text(text);
    let mut pairs = Vec::new();

    let mut index = 0;
    while index < chars.len() {
        let first = chars[index];
        let second = if index + 1 < chars.len() { chars[index + 1] } else { 'X' };

        if first == second {
            pairs.push((first, 'X'));
            index += 1;
        } else {
            pairs.push((first, second));
            index += 2;
        }
    }

    if let Some(last) = pairs.last_mut() {
        if last.1 == 0 as char {
            last.1 = 'X';
        }
    }

    pairs
}

fn digraphs_for_decrypt(text: &str) -> Vec<(char, char)> {
    let chars = sanitize_text(text);
    let mut pairs = Vec::new();

    for chunk in chars.chunks(2) {
        let first = chunk[0];
        let second = *chunk.get(1).unwrap_or(&'X');
        pairs.push((first, second));
    }

    pairs
}

fn position_of(positions: &HashMap<char, Position>, ch: char) -> Position {
    positions.get(&ch).copied().unwrap_or(Position { row: 0, col: 0 })
}

fn char_at(square: &[char; 25], row: usize, col: usize) -> char {
    square[row * 5 + col]
}

fn transform_pair(
    square: &[char; 25],
    positions: &HashMap<char, Position>,
    a: char,
    b: char,
    decrypt: bool,
) -> (char, char) {
    let pos_a = position_of(positions, a);
    let pos_b = position_of(positions, b);

    if pos_a.row == pos_b.row {
        let shift = if decrypt { 4 } else { 1 };
        let col_a = (pos_a.col + shift) % 5;
        let col_b = (pos_b.col + shift) % 5;
        return (char_at(square, pos_a.row, col_a), char_at(square, pos_b.row, col_b));
    }

    if pos_a.col == pos_b.col {
        let shift = if decrypt { 4 } else { 1 };
        let row_a = (pos_a.row + shift) % 5;
        let row_b = (pos_b.row + shift) % 5;
        return (char_at(square, row_a, pos_a.col), char_at(square, row_b, pos_b.col));
    }

    (
        char_at(square, pos_a.row, pos_b.col),
        char_at(square, pos_b.row, pos_a.col),
    )
}

pub fn encrypt(plaintext: &str, key: &str) -> Result<String, PlayfairError> {
    let (square, positions) = build_square(key)?;
    let pairs = digraphs_for_encrypt(plaintext);

    let mut output = String::with_capacity(pairs.len() * 2);
    for (a, b) in pairs {
        let (c1, c2) = transform_pair(&square, &positions, a, b, false);
        output.push(c1);
        output.push(c2);
    }

    Ok(output)
}

pub fn decrypt(ciphertext: &str, key: &str) -> Result<String, PlayfairError> {
    let (square, positions) = build_square(key)?;
    let pairs = digraphs_for_decrypt(ciphertext);

    let mut output = String::with_capacity(pairs.len() * 2);
    for (a, b) in pairs {
        let (c1, c2) = transform_pair(&square, &positions, a, b, true);
        output.push(c1);
        output.push(c2);
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{decrypt, encrypt};

    #[test]
    fn encrypts_and_decrypts() {
        let encrypted = encrypt("HIDE THE GOLD", "PLAYFAIR EXAMPLE").unwrap();
        assert_eq!(encrypted, "BMODZBXDNAGE");
        let decrypted = decrypt(&encrypted, "PLAYFAIR EXAMPLE").unwrap();
        assert!(decrypted.starts_with("HIDETHEGOLD"));
    }
}
