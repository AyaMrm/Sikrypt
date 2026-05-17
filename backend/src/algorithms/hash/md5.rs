use once_cell::sync::Lazy;

static K: Lazy<[u32; 64]> = Lazy::new(|| {
    let mut constants = [0u32; 64];

    for (index, value) in constants.iter_mut().enumerate() {
        let sin_value = (index as f64 + 1.0).sin().abs();
        *value = (sin_value * (2u64.pow(32) as f64)) as u32;
    }

    constants
});

static S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

fn round_function(x: u32, y: u32, z: u32, round: usize) -> u32 {
    match round {
        0..=15 => (x & y) | ((!x) & z),
        16..=31 => (x & z) | (y & (!z)),
        32..=47 => x ^ y ^ z,
        _ => y ^ (x | (!z)),
    }
}

fn word_index(round: usize) -> usize {
    match round {
        0..=15 => round,
        16..=31 => (5 * round + 1) % 16,
        32..=47 => (3 * round + 5) % 16,
        _ => (7 * round) % 16,
    }
}

pub fn md5(message: &str) -> String {
    let bit_length = (message.len() as u64) * 8;
    let mut padded_message: Vec<u8> = message.bytes().collect();

    // MD5 adds a single 1 bit, represented by 0x80 in little-endian byte order.
    padded_message.push(0x80);

    while padded_message.len() % 64 != 56 {
        padded_message.push(0x00);
    }

    padded_message.extend_from_slice(&bit_length.to_le_bytes());

    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xEFCD_AB89;
    let mut c0: u32 = 0x98BA_DCFE;
    let mut d0: u32 = 0x1032_5476;

    let mut words = [0u32; 16];

    for chunk in padded_message.chunks(64) {
        let mut a = a0;
        let mut b = b0;
        let mut c = c0;
        let mut d = d0;

        for (word_index, word) in words.iter_mut().enumerate() {
            let offset = word_index * 4;
            *word = u32::from_le_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
        }

        for round in 0..64 {
            let temp = b;
            let sum = a
                .wrapping_add(round_function(b, c, d, round))
                .wrapping_add(words[word_index(round)])
                .wrapping_add(K[round]);

            b = b.wrapping_add(sum.rotate_left(S[round]));
            a = d;
            d = c;
            c = temp;
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut digest = Vec::with_capacity(16);
    digest.extend_from_slice(&a0.to_le_bytes());
    digest.extend_from_slice(&b0.to_le_bytes());
    digest.extend_from_slice(&c0.to_le_bytes());
    digest.extend_from_slice(&d0.to_le_bytes());

    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::md5;

    #[test]
    fn hashes_empty_string() {
        assert_eq!(md5(""), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn hashes_known_message() {
        assert_eq!(md5("abc"), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn hashes_longer_sentence() {
        assert_eq!(md5("message digest"), "f96b697d7cb7938d525a2f31aaf161d0");
    }
}
