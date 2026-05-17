use crate::algorithms::{
    asymmetric::diffie_hellman::{self, DiffieHellmanSetup},
    hash::hmac_impl,
    symmetric::aes,
};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecureChannelError {
    KeyExchangeFailed,
    EncryptionFailed,
    DecryptionFailed,
    IntegrityCheckFailed,
    InvalidIvLength,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeys {
    pub aes_key: Vec<u8>,
    pub hmac_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurePacket {
    pub sender_public_key: u128,
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub mac_hex: String,
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn derive_material(shared_secret: u128) -> [u8; 32] {
    let digest = Sha256::digest(shared_secret.to_be_bytes());
    digest.into()
}

pub fn derive_session_keys(
    setup: &DiffieHellmanSetup,
    private_key: u128,
    peer_public_key: u128,
) -> Result<SessionKeys, SecureChannelError> {
    let shared_secret = diffie_hellman::compute_shared_secret(setup, private_key, peer_public_key)
        .map_err(|_| SecureChannelError::KeyExchangeFailed)?;
    let material = derive_material(shared_secret);

    Ok(SessionKeys {
        aes_key: material[..16].to_vec(),
        hmac_key: material[16..].to_vec(),
    })
}

pub fn protect_message(
    session_keys: &SessionKeys,
    sender_public_key: u128,
    iv: &[u8],
    plaintext: &str,
) -> Result<SecurePacket, SecureChannelError> {
    if iv.len() != 16 {
        return Err(SecureChannelError::InvalidIvLength);
    }

    let encrypted = aes::encrypt_cbc(&session_keys.aes_key, iv, plaintext.as_bytes())
        .map_err(|_| SecureChannelError::EncryptionFailed)?;
    let mac_input = format!(
        "{}:{}:{}",
        sender_public_key,
        to_hex(iv),
        to_hex(&encrypted.ciphertext)
    );
    let mac_hex = hmac_impl::hmac_sha256(&session_keys.hmac_key, &mac_input)
        .map_err(|_| SecureChannelError::IntegrityCheckFailed)?;

    Ok(SecurePacket {
        sender_public_key,
        iv: iv.to_vec(),
        ciphertext: encrypted.ciphertext,
        mac_hex,
    })
}

pub fn open_message(
    session_keys: &SessionKeys,
    packet: &SecurePacket,
) -> Result<String, SecureChannelError> {
    let mac_input = format!(
        "{}:{}:{}",
        packet.sender_public_key,
        to_hex(&packet.iv),
        to_hex(&packet.ciphertext)
    );
    let mac_valid =
        hmac_impl::verify_hmac_sha256(&session_keys.hmac_key, &mac_input, &packet.mac_hex)
            .map_err(|_| SecureChannelError::IntegrityCheckFailed)?;

    if !mac_valid {
        return Err(SecureChannelError::IntegrityCheckFailed);
    }

    let plaintext = aes::decrypt_cbc(&session_keys.aes_key, &packet.iv, &packet.ciphertext)
        .map_err(|_| SecureChannelError::DecryptionFailed)?;

    String::from_utf8(plaintext).map_err(|_| SecureChannelError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::{SecureChannelError, derive_session_keys, open_message, protect_message};
    use crate::algorithms::asymmetric::diffie_hellman::{DiffieHellmanSetup, compute_public_key};

    #[test]
    fn encrypts_and_opens_secure_packet() {
        let setup = DiffieHellmanSetup { p: 23, g: 5 };
        let alice_public = compute_public_key(&setup, 6).unwrap();
        let bob_public = compute_public_key(&setup, 15).unwrap();

        let alice_keys = derive_session_keys(&setup, 6, bob_public).unwrap();
        let bob_keys = derive_session_keys(&setup, 15, alice_public).unwrap();

        let packet =
            protect_message(&alice_keys, alice_public, b"INITVECTOR123456", "bonjour").unwrap();
        let message = open_message(&bob_keys, &packet).unwrap();

        assert_eq!(message, "bonjour");
    }

    #[test]
    fn rejects_tampered_packet() {
        let setup = DiffieHellmanSetup { p: 23, g: 5 };
        let alice_public = compute_public_key(&setup, 6).unwrap();
        let bob_public = compute_public_key(&setup, 15).unwrap();

        let alice_keys = derive_session_keys(&setup, 6, bob_public).unwrap();
        let bob_keys = derive_session_keys(&setup, 15, alice_public).unwrap();

        let mut packet =
            protect_message(&alice_keys, alice_public, b"INITVECTOR123456", "bonjour").unwrap();
        packet.ciphertext[0] ^= 0x01;

        let result = open_message(&bob_keys, &packet);
        assert_eq!(result, Err(SecureChannelError::IntegrityCheckFailed));
    }
}
