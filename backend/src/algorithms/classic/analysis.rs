#[derive(Debug, Clone, PartialEq)]
pub struct LetterFrequency {
    pub letter: char,
    pub count: u32,
    pub frequency: f64,
}

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

    let numerator: u32 = counts.iter().map(|count| count * (count - 1)).sum();
    let denominator = total * (total - 1);

    (total, numerator as f64 / denominator as f64)
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
