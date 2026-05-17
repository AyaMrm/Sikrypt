#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rc4Error {
    EmptyKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rc4Output {
    pub ciphertext: Vec<u8>,
    pub keystream: Vec<u8>,
}

fn ksa(key: &[u8]) -> [u8; 256] {
    let mut s = [0u8; 256];
    for (i, value) in s.iter_mut().enumerate() {
        *value = i as u8;
    }

    let mut j = 0usize;
    for i in 0..256usize {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }

    s
}

fn prga(s: &mut [u8; 256], len: usize) -> Vec<u8> {
    let mut i = 0usize;
    let mut j = 0usize;
    let mut stream = Vec::with_capacity(len);

    for _ in 0..len {
        i = (i + 1) % 256;
        j = (j + s[i] as usize) % 256;
        s.swap(i, j);

        let idx = (s[i] as usize + s[j] as usize) % 256;
        stream.push(s[idx]);
    }

    stream
}

pub fn apply(key: &[u8], input: &[u8]) -> Result<Rc4Output, Rc4Error> {
    if key.is_empty() {
        return Err(Rc4Error::EmptyKey);
    }

    let mut state = ksa(key);
    let keystream = prga(&mut state, input.len());
    let ciphertext = input
        .iter()
        .zip(keystream.iter())
        .map(|(byte, stream_byte)| byte ^ stream_byte)
        .collect();

    Ok(Rc4Output {
        ciphertext,
        keystream,
    })
}

pub fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<Rc4Output, Rc4Error> {
    apply(key, plaintext)
}

pub fn decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Rc4Output, Rc4Error> {
    apply(key, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::{Rc4Error, decrypt, encrypt};

    #[test]
    fn encrypts_and_decrypts_roundtrip() {
        let key = b"Key";
        let plaintext = b"Plaintext";

        let encrypted = encrypt(key, plaintext).unwrap();
        let decrypted = decrypt(key, &encrypted.ciphertext).unwrap();

        assert_eq!(decrypted.ciphertext, plaintext);
    }

    #[test]
    fn matches_known_test_vector() {
        let encrypted = encrypt(b"Key", b"Plaintext").unwrap();
        let expected = vec![0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3];
        assert_eq!(encrypted.ciphertext, expected);
    }

    #[test]
    fn rejects_empty_key() {
        let result = encrypt(b"", b"hello");
        assert_eq!(result, Err(Rc4Error::EmptyKey));
    }
}
