#[derive(Debug, Clone, PartialEq)]
pub struct LetterFrequency {
    pub letter: char,
    pub count: u32,
    pub frequency: f64,
}

use std::collections::HashMap;

fn normalize(text: &str) -> Vec<char> {
    text.chars()
        .filter(|ch| ch.is_ascii_alphabetic())
        .map(|ch| ch.to_ascii_uppercase())
        .collect()
}

pub fn frequency_analysis(text: &str) -> (u32, Vec<LetterFrequency>) {
    let letters = normalize(text);
    let total = letters.len() as u32;

    let mut counts = [0u32; 26];
    for ch in letters {
        let idx = (ch as u8 - b'A') as usize;
        counts[idx] += 1;
    }

    let frequencies = counts
        .iter()
        .enumerate()
        .map(|(idx, &count)| {
            let frequency = if total == 0 {
                0.0
            } else {
                count as f64 / total as f64
            };
            LetterFrequency {
                letter: (b'A' + idx as u8) as char,
                count,
                frequency,
            }
        })
        .collect();

    (total, frequencies)
}

pub fn index_of_coincidence(text: &str) -> (u32, f64) {
    let letters = normalize(text);
    let total = letters.len() as u32;

    if total <= 1 {
        return (total, 0.0);
    }

    let mut counts = [0u32; 26];
    for ch in letters {
        let idx = (ch as u8 - b'A') as usize;
        counts[idx] += 1;
    }

    let numerator: u32 = counts
        .iter()
        .map(|count| count * count.saturating_sub(1))
        .sum();
    let denominator = total * (total - 1);

    (total, numerator as f64 / denominator as f64)
}

fn index_of_coincidence_letters(letters: &[char]) -> f64 {
    let total = letters.len() as u32;
    if total <= 1 {
        return 0.0;
    }

    let mut counts = [0u32; 26];
    for ch in letters {
        let idx = (*ch as u8 - b'A') as usize;
        counts[idx] += 1;
    }

    let numerator: u32 = counts
        .iter()
        .map(|count| count * count.saturating_sub(1))
        .sum();
    let denominator = total * (total - 1);

    numerator as f64 / denominator as f64
}

fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let remainder = a % b;
        a = b;
        b = remainder;
    }
    a
}

pub fn kasiski_distances(text: &str, sequence_len: usize) -> Vec<usize> {
    if sequence_len < 2 {
        return Vec::new();
    }

    let letters = normalize(text);
    if letters.len() < sequence_len {
        return Vec::new();
    }

    let mut occurrences: HashMap<String, Vec<usize>> = HashMap::new();

    for idx in 0..=letters.len() - sequence_len {
        let slice: String = letters[idx..idx + sequence_len].iter().collect();
        occurrences.entry(slice).or_default().push(idx);
    }

    let mut distances = Vec::new();
    for positions in occurrences.values() {
        if positions.len() < 2 {
            continue;
        }

        for window in positions.windows(2) {
            if let [first, second] = window {
                distances.push(second - first);
            }
        }
    }

    distances.sort_unstable();
    distances
}

pub fn kasiski_candidates(
    distances: &[usize],
    max_key_len: usize,
) -> (Option<usize>, Vec<(usize, u32)>) {
    if distances.is_empty() {
        return (None, Vec::new());
    }

    let mut iter = distances.iter();
    let mut current_gcd = *iter.next().unwrap();
    for value in iter {
        current_gcd = gcd(current_gcd, *value);
    }

    let mut candidates: Vec<(usize, u32)> = Vec::new();
    for key_len in 2..=max_key_len {
        let score = distances
            .iter()
            .filter(|distance| *distance % key_len == 0)
            .count() as u32;

        if score > 0 {
            candidates.push((key_len, score));
        }
    }

    candidates.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));

    (Some(current_gcd), candidates)
}

pub fn ic_by_key_length(text: &str, max_length: usize) -> Vec<(usize, f64)> {
    if max_length == 0 {
        return Vec::new();
    }

    let letters = normalize(text);
    let mut results = Vec::new();

    for key_len in 1..=max_length {
        let mut buckets: Vec<Vec<char>> = vec![Vec::new(); key_len];
        for (idx, ch) in letters.iter().enumerate() {
            buckets[idx % key_len].push(*ch);
        }

        let mut sum_ic = 0.0;
        let mut groups = 0u32;
        for bucket in buckets {
            if bucket.len() >= 2 {
                sum_ic += index_of_coincidence_letters(&bucket);
                groups += 1;
            }
        }

        let average = if groups == 0 {
            0.0
        } else {
            sum_ic / groups as f64
        };

        results.push((key_len, average));
    }

    results
}

pub fn estimate_vigenere_key(text: &str, key_length: usize) -> String {
    if key_length == 0 {
        return String::new();
    }

    let letters = normalize(text);
    let mut buckets: Vec<Vec<char>> = vec![Vec::new(); key_length];
    for (idx, ch) in letters.iter().enumerate() {
        buckets[idx % key_length].push(*ch);
    }

    let mut key = String::with_capacity(key_length);
    for bucket in buckets {
        if bucket.is_empty() {
            key.push('A');
            continue;
        }

        let mut counts = [0u32; 26];
        for ch in bucket {
            let idx = (ch as u8 - b'A') as usize;
            counts[idx] += 1;
        }

        let mut best_idx = 0usize;
        let mut best_count = 0u32;
        for (idx, &count) in counts.iter().enumerate() {
            if count > best_count {
                best_idx = idx;
                best_count = count;
            }
        }

        let shift = (best_idx + 26 - (b'E' - b'A') as usize) % 26;
        key.push((b'A' + shift as u8) as char);
    }

    key
}

#[cfg(test)]
mod tests {
    use super::{frequency_analysis, index_of_coincidence};

    #[test]
    fn computes_frequency() {
        let (total, freq) = frequency_analysis("ABBA");
        assert_eq!(total, 4);
        assert_eq!(freq[0].count, 2);
        assert_eq!(freq[1].count, 2);
    }

    #[test]
    fn computes_ic() {
        let (total, ic) = index_of_coincidence("ABBA");
        assert_eq!(total, 4);
        assert!(ic > 0.2);
    }
}
