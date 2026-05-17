use p256::{ecdh::diffie_hellman, EncodedPoint, PublicKey, SecretKey};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use rand_core::OsRng;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EccError {
	InvalidPrivateKey,
	InvalidPublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EccKeyPair {
	pub private_key: Vec<u8>,
	pub public_key: Vec<u8>,
}

pub fn generate_key_pair() -> EccKeyPair {
	let secret = SecretKey::random(&mut OsRng);
	let public = PublicKey::from_secret_scalar(&secret.to_nonzero_scalar());

	let private_key = secret.to_bytes().to_vec();
	let public_key = public.to_encoded_point(false).as_bytes().to_vec();

	EccKeyPair {
		private_key,
		public_key,
	}
}

pub fn derive_shared_secret(
	private_key: &[u8],
	peer_public_key: &[u8],
) -> Result<Vec<u8>, EccError> {
	let secret = SecretKey::from_slice(private_key).map_err(|_| EccError::InvalidPrivateKey)?;
	let encoded = EncodedPoint::from_bytes(peer_public_key)
		.map_err(|_| EccError::InvalidPublicKey)?;
	let public = PublicKey::from_sec1_bytes(encoded.as_bytes())
		.map_err(|_| EccError::InvalidPublicKey)?;

	let shared = diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
	Ok(shared.raw_secret_bytes().to_vec())
}
