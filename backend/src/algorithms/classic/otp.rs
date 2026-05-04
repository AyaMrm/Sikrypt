#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OtpError {
    KeyLengthMismatch,
}

pub fn apply(key: &[u8], input: &[u8]) -> Result<Vec<u8>, OtpError> {
    if key.len() != input.len() {
        return Err(OtpError::KeyLengthMismatch);
    }

    Ok(input
        .iter()
        .zip(key.iter())
        .map(|(byte, mask)| byte ^ mask)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::apply;

    #[test]
    fn encrypts_and_decrypts() {
        let key = b"secretkey";
        let plaintext = b"plaintext";
        let encrypted = apply(key, plaintext).unwrap();
        let decrypted = apply(key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
