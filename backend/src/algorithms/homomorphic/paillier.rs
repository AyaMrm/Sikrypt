use num_bigint_dig::{BigInt, BigUint, RandBigInt, RandPrime, ToBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::rngs::OsRng;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaillierPublicKey {
    pub n: BigUint,
    pub g: BigUint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaillierPrivateKey {
    pub lambda: BigUint,
    pub mu: BigUint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaillierKeyPair {
    pub public: PaillierPublicKey,
    pub private: PaillierPrivateKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaillierError {
    InvalidKeySize,
    MessageTooLarge,
    InvalidCiphertext,
    KeyGenerationFailed,
}

fn l_function(value: &BigUint, n: &BigUint) -> BigUint {
    (value - BigUint::one()) / n
}

fn mod_inverse(value: &BigUint, modulus: &BigUint) -> Option<BigUint> {
    let value_int = value.to_bigint()?;
    let modulus_int = modulus.to_bigint()?;

    let mut t = BigInt::zero();
    let mut new_t = BigInt::one();
    let mut r = modulus_int.clone();
    let mut new_r = value_int.mod_floor(&modulus_int);

    while !new_r.is_zero() {
        let quotient = &r / &new_r;
        let temp_t = &t - &quotient * &new_t;
        t = new_t;
        new_t = temp_t;

        let temp_r = &r - &quotient * &new_r;
        r = new_r;
        new_r = temp_r;
    }

    if r != BigInt::one() {
        return None;
    }

    let result = t.mod_floor(&modulus_int);
    result.to_biguint()
}

fn random_prime(bits: usize) -> BigUint {
    let mut rng = OsRng;
    rng.gen_prime(bits)
}

pub fn keygen(bits: usize) -> Result<PaillierKeyPair, PaillierError> {
    if !(2048..=4096).contains(&bits) || !bits.is_multiple_of(256) {
        return Err(PaillierError::InvalidKeySize);
    }

    let half = bits / 2;
    let p = random_prime(half);
    let mut q = random_prime(half);
    while q == p {
        q = random_prime(half);
    }

    let n = &p * &q;
    let g = &n + BigUint::one();
    let n_square = &n * &n;

    let p_minus = &p - BigUint::one();
    let q_minus = &q - BigUint::one();
    let lambda = p_minus.lcm(&q_minus);

    let g_lambda = g.modpow(&lambda, &n_square);
    let l_value = l_function(&g_lambda, &n);
    let mu = mod_inverse(&l_value, &n).ok_or(PaillierError::KeyGenerationFailed)?;

    Ok(PaillierKeyPair {
        public: PaillierPublicKey { n: n.clone(), g },
        private: PaillierPrivateKey { lambda, mu },
    })
}

pub fn encrypt(
    public_key: &PaillierPublicKey,
    message: &BigUint,
) -> Result<BigUint, PaillierError> {
    if message >= &public_key.n {
        return Err(PaillierError::MessageTooLarge);
    }

    let n_square = &public_key.n * &public_key.n;
    let mut rng = OsRng;

    let mut r = rng.gen_biguint_below(&public_key.n);
    while r.is_zero() || r.gcd(&public_key.n) != BigUint::one() {
        r = rng.gen_biguint_below(&public_key.n);
    }

    let gm = public_key.g.modpow(message, &n_square);
    let rn = r.modpow(&public_key.n, &n_square);

    Ok((gm * rn) % n_square)
}

pub fn decrypt(
    public_key: &PaillierPublicKey,
    private_key: &PaillierPrivateKey,
    ciphertext: &BigUint,
) -> Result<BigUint, PaillierError> {
    let n_square = &public_key.n * &public_key.n;
    if ciphertext >= &n_square {
        return Err(PaillierError::InvalidCiphertext);
    }

    let u = ciphertext.modpow(&private_key.lambda, &n_square);
    let l_value = l_function(&u, &public_key.n);

    Ok((l_value * &private_key.mu) % &public_key.n)
}

pub fn add(
    public_key: &PaillierPublicKey,
    c1: &BigUint,
    c2: &BigUint,
) -> Result<BigUint, PaillierError> {
    let n_square = &public_key.n * &public_key.n;
    if c1 >= &n_square || c2 >= &n_square {
        return Err(PaillierError::InvalidCiphertext);
    }

    Ok((c1 * c2) % n_square)
}

#[cfg(test)]
mod tests {
    use super::{add, decrypt, encrypt, keygen};
    use num_bigint_dig::BigUint;

    #[test]
    fn encrypts_decrypts_and_adds() {
        let keypair = keygen(2048).unwrap();
        let m1 = BigUint::from(42u32);
        let m2 = BigUint::from(13u32);

        let c1 = encrypt(&keypair.public, &m1).unwrap();
        let c2 = encrypt(&keypair.public, &m2).unwrap();
        let c_sum = add(&keypair.public, &c1, &c2).unwrap();

        let m_sum = decrypt(&keypair.public, &keypair.private, &c_sum).unwrap();
        assert_eq!(m_sum, BigUint::from(55u32));
    }
}
