use aes::{Aes128, Aes192, Aes256};
use cbc::{Decryptor, Encryptor};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use cipher05::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use rc6::RC6_32_20_16;
use serpent::Serpent;
use twofish::Twofish;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalistError {
    InvalidKeyLength,
    InvalidIvLength,
    DecryptionFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalistKeySize {
    Bits128,
    Bits192,
    Bits256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalistCbcOutput {
    pub ciphertext: Vec<u8>,
    pub iv: Vec<u8>,
    pub key_size: FinalistKeySize,
}

fn validate_iv_16(iv: &[u8]) -> Result<(), FinalistError> {
    if iv.len() == 16 {
        Ok(())
    } else {
        Err(FinalistError::InvalidIvLength)
    }
}

fn key_size_from_len(len: usize) -> Result<FinalistKeySize, FinalistError> {
    match len {
        16 => Ok(FinalistKeySize::Bits128),
        24 => Ok(FinalistKeySize::Bits192),
        32 => Ok(FinalistKeySize::Bits256),
        _ => Err(FinalistError::InvalidKeyLength),
    }
}

pub fn twofish_encrypt_cbc(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<FinalistCbcOutput, FinalistError> {
    let key_size = key_size_from_len(key.len())?;
    validate_iv_16(iv)?;

    let ciphertext = Encryptor::<Twofish>::new_from_slices(key, iv)
        .map_err(|_| FinalistError::InvalidIvLength)?
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    Ok(FinalistCbcOutput {
        ciphertext,
        iv: iv.to_vec(),
        key_size,
    })
}

pub fn twofish_decrypt_cbc(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, FinalistError> {
    key_size_from_len(key.len())?;
    validate_iv_16(iv)?;

    Decryptor::<Twofish>::new_from_slices(key, iv)
        .map_err(|_| FinalistError::InvalidIvLength)?
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| FinalistError::DecryptionFailed)
}

pub fn serpent_encrypt_cbc(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<FinalistCbcOutput, FinalistError> {
    let key_size = key_size_from_len(key.len())?;
    validate_iv_16(iv)?;

    let ciphertext = Encryptor::<Serpent>::new_from_slices(key, iv)
        .map_err(|_| FinalistError::InvalidIvLength)?
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    Ok(FinalistCbcOutput {
        ciphertext,
        iv: iv.to_vec(),
        key_size,
    })
}

pub fn serpent_decrypt_cbc(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, FinalistError> {
    key_size_from_len(key.len())?;
    validate_iv_16(iv)?;

    Decryptor::<Serpent>::new_from_slices(key, iv)
        .map_err(|_| FinalistError::InvalidIvLength)?
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| FinalistError::DecryptionFailed)
}

fn pkcs7_pad_block16(data: &[u8]) -> Vec<u8> {
    let pad_len = 16 - (data.len() % 16);
    let pad_len = if pad_len == 0 { 16 } else { pad_len };
    let mut out = data.to_vec();
    out.extend(std::iter::repeat_n(pad_len as u8, pad_len));
    out
}

fn pkcs7_unpad_block16(data: &[u8]) -> Result<Vec<u8>, FinalistError> {
    if data.is_empty() || data.len() % 16 != 0 {
        return Err(FinalistError::DecryptionFailed);
    }

    let pad_len = *data.last().unwrap() as usize;
    if pad_len == 0 || pad_len > 16 {
        return Err(FinalistError::DecryptionFailed);
    }

    if data[data.len() - pad_len..]
        .iter()
        .any(|&b| b as usize != pad_len)
    {
        return Err(FinalistError::DecryptionFailed);
    }

    Ok(data[..data.len() - pad_len].to_vec())
}

pub fn rc6_encrypt_cbc(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<FinalistCbcOutput, FinalistError> {
    if key.len() != 16 {
        return Err(FinalistError::InvalidKeyLength);
    }
    validate_iv_16(iv)?;

    let cipher = RC6_32_20_16::new_from_slice(key).map_err(|_| FinalistError::InvalidKeyLength)?;

    let padded = pkcs7_pad_block16(plaintext);
    let mut prev = [0u8; 16];
    prev.copy_from_slice(iv);

    let mut ciphertext = Vec::with_capacity(padded.len());

    for chunk in padded.chunks(16) {
        let mut xored = [0u8; 16];
        for i in 0..16 {
            xored[i] = chunk[i] ^ prev[i];
        }

        let mut block = Block::<RC6_32_20_16>::default();
        block.copy_from_slice(&xored);
        cipher.encrypt_block(&mut block);

        ciphertext.extend_from_slice(&block);
        prev.copy_from_slice(&block);
    }

    Ok(FinalistCbcOutput {
        ciphertext,
        iv: iv.to_vec(),
        key_size: FinalistKeySize::Bits128,
    })
}

pub fn rc6_decrypt_cbc(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, FinalistError> {
    if key.len() != 16 {
        return Err(FinalistError::InvalidKeyLength);
    }
    validate_iv_16(iv)?;

    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err(FinalistError::DecryptionFailed);
    }

    let cipher = RC6_32_20_16::new_from_slice(key).map_err(|_| FinalistError::InvalidKeyLength)?;

    let mut prev = [0u8; 16];
    prev.copy_from_slice(iv);

    let mut plaintext = Vec::with_capacity(ciphertext.len());

    for chunk in ciphertext.chunks(16) {
        let mut block = Block::<RC6_32_20_16>::default();
        block.copy_from_slice(chunk);

        let current_ct = block.clone();
        cipher.decrypt_block(&mut block);

        for i in 0..16 {
            block[i] ^= prev[i];
        }

        plaintext.extend_from_slice(&block);
        prev.copy_from_slice(&current_ct);
    }

    pkcs7_unpad_block16(&plaintext)
}

pub fn rijndael_encrypt_cbc(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<FinalistCbcOutput, FinalistError> {
    let key_size = key_size_from_len(key.len())?;
    validate_iv_16(iv)?;

    let ciphertext = match key_size {
        FinalistKeySize::Bits128 => Encryptor::<Aes128>::new_from_slices(key, iv)
            .map_err(|_| FinalistError::InvalidIvLength)?
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext),
        FinalistKeySize::Bits192 => Encryptor::<Aes192>::new_from_slices(key, iv)
            .map_err(|_| FinalistError::InvalidIvLength)?
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext),
        FinalistKeySize::Bits256 => Encryptor::<Aes256>::new_from_slices(key, iv)
            .map_err(|_| FinalistError::InvalidIvLength)?
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext),
    };

    Ok(FinalistCbcOutput {
        ciphertext,
        iv: iv.to_vec(),
        key_size,
    })
}

pub fn rijndael_decrypt_cbc(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, FinalistError> {
    let key_size = key_size_from_len(key.len())?;
    validate_iv_16(iv)?;

    let decrypted = match key_size {
        FinalistKeySize::Bits128 => Decryptor::<Aes128>::new_from_slices(key, iv)
            .map_err(|_| FinalistError::InvalidIvLength)?
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext),
        FinalistKeySize::Bits192 => Decryptor::<Aes192>::new_from_slices(key, iv)
            .map_err(|_| FinalistError::InvalidIvLength)?
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext),
        FinalistKeySize::Bits256 => Decryptor::<Aes256>::new_from_slices(key, iv)
            .map_err(|_| FinalistError::InvalidIvLength)?
            .decrypt_padded_vec_mut::<Pkcs7>(ciphertext),
    };

    decrypted.map_err(|_| FinalistError::DecryptionFailed)
}
