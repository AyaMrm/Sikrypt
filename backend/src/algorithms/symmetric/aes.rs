use aes::{Aes128, Aes192, Aes256};
use cbc::{Decryptor, Encryptor};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AesError {
    InvalidKeyLength,
    InvalidIvLength,
    DecryptionFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesKeySize {
    Bits128,
    Bits192,
    Bits256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AesCbcOutput {
    pub ciphertext: Vec<u8>,
    pub iv: Vec<u8>,
    pub key_size: AesKeySize,
}

fn detect_key_size(key: &[u8]) -> Result<AesKeySize, AesError> {
    match key.len() {
        16 => Ok(AesKeySize::Bits128),
        24 => Ok(AesKeySize::Bits192),
        32 => Ok(AesKeySize::Bits256),
        _ => Err(AesError::InvalidKeyLength),
    }
}

fn validate_iv(iv: &[u8]) -> Result<(), AesError> {
    if iv.len() == 16 {
        Ok(())
    } else {
        Err(AesError::InvalidIvLength)
    }
}

pub fn encrypt_cbc(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<AesCbcOutput, AesError> {
    let key_size = detect_key_size(key)?;
    validate_iv(iv)?;

    let ciphertext = match key_size {
        AesKeySize::Bits128 => Encryptor::<Aes128>::new_from_slices(key, iv)
            .map_err(|_| AesError::InvalidIvLength)?
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext),
        AesKeySize::Bits192 => Encryptor::<Aes192>::new_from_slices(key, iv)
            .map_err(|_| AesError::InvalidIvLength)?
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext),
        AesKeySize::Bits256 => Encryptor::<Aes256>::new_from_slices(key, iv)
            .map_err(|_| AesError::InvalidIvLength)?
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext),
    };

    Ok(AesCbcOutput {
        ciphertext,
        iv: iv.to_vec(),
        key_size,
    })
}

pub fn decrypt_cbc(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, AesError> {
    let key_size = detect_key_size(key)?;
    validate_iv(iv)?;

    match key_size {
        AesKeySize::Bits128 => Decryptor::<Aes128>::new_from_slices(key, iv)
            .map_err(|_| AesError::InvalidIvLength)?
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            .map_err(|_| AesError::DecryptionFailed),
        AesKeySize::Bits192 => Decryptor::<Aes192>::new_from_slices(key, iv)
            .map_err(|_| AesError::InvalidIvLength)?
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            .map_err(|_| AesError::DecryptionFailed),
        AesKeySize::Bits256 => Decryptor::<Aes256>::new_from_slices(key, iv)
            .map_err(|_| AesError::InvalidIvLength)?
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            .map_err(|_| AesError::DecryptionFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::{AesError, AesKeySize, decrypt_cbc, encrypt_cbc};

    #[test]
    fn encrypts_and_decrypts_aes_128_cbc() {
        let key = *b"0123456789ABCDEF";
        let iv = *b"FEDCBA9876543210";
        let plaintext = b"Confidential AES message";

        let encrypted = encrypt_cbc(&key, &iv, plaintext).unwrap();
        let decrypted = decrypt_cbc(&key, &iv, &encrypted.ciphertext).unwrap();

        assert_eq!(encrypted.key_size, AesKeySize::Bits128);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn rejects_invalid_key_length() {
        let result = encrypt_cbc(b"short-key", b"FEDCBA9876543210", b"hello");
        assert_eq!(result, Err(AesError::InvalidKeyLength));
    }

    #[test]
    fn rejects_invalid_iv_length() {
        let result = encrypt_cbc(b"0123456789ABCDEF", b"tiny-iv", b"hello");
        assert_eq!(result, Err(AesError::InvalidIvLength));
    }

    #[test]
    fn rejects_invalid_padding_on_decryption() {
        let result = decrypt_cbc(
            b"0123456789ABCDEF",
            b"FEDCBA9876543210",
            b"not-valid-ciphertext",
        );
        assert_eq!(result, Err(AesError::DecryptionFailed));
    }
}
