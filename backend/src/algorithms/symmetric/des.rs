use cbc::{Decryptor, Encryptor};
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use des::Des;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesError {
    InvalidKeyLength,
    InvalidIvLength,
    DecryptionFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesCbcOutput {
    pub ciphertext: Vec<u8>,
    pub iv: Vec<u8>,
}

fn validate_key(key: &[u8]) -> Result<(), DesError> {
    if key.len() == 8 {
        Ok(())
    } else {
        Err(DesError::InvalidKeyLength)
    }
}

fn validate_iv(iv: &[u8]) -> Result<(), DesError> {
    if iv.len() == 8 {
        Ok(())
    } else {
        Err(DesError::InvalidIvLength)
    }
}

pub fn encrypt_cbc(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<DesCbcOutput, DesError> {
    validate_key(key)?;
    validate_iv(iv)?;

    let ciphertext = Encryptor::<Des>::new_from_slices(key, iv)
        .map_err(|_| DesError::InvalidIvLength)?
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    Ok(DesCbcOutput {
        ciphertext,
        iv: iv.to_vec(),
    })
}

pub fn decrypt_cbc(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, DesError> {
    validate_key(key)?;
    validate_iv(iv)?;

    Decryptor::<Des>::new_from_slices(key, iv)
        .map_err(|_| DesError::InvalidIvLength)?
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| DesError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::{decrypt_cbc, encrypt_cbc, DesError};

    #[test]
    fn encrypts_and_decrypts_des_cbc() {
        let key = *b"DESKEY01";
        let iv = *b"INITVEC8";
        let plaintext = b"Short DES message";

        let encrypted = encrypt_cbc(&key, &iv, plaintext).unwrap();
        let decrypted = decrypt_cbc(&key, &iv, &encrypted.ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn rejects_invalid_key_length() {
        let result = encrypt_cbc(b"tiny", b"INITVEC8", b"hello");
        assert_eq!(result, Err(DesError::InvalidKeyLength));
    }

    #[test]
    fn rejects_invalid_iv_length() {
        let result = encrypt_cbc(b"DESKEY01", b"small", b"hello");
        assert_eq!(result, Err(DesError::InvalidIvLength));
    }

    #[test]
    fn rejects_invalid_padding_on_decryption() {
        let result = decrypt_cbc(b"DESKEY01", b"INITVEC8", b"invalid");
        assert_eq!(result, Err(DesError::DecryptionFailed));
    }
}
