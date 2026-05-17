#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffieHellmanError {
    InvalidModulus,
    InvalidGenerator,
    InvalidPrivateKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffieHellmanSetup {
    pub p: u128,
    pub g: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffieHellmanExchange {
    pub alice_public: u128,
    pub bob_public: u128,
    pub shared_secret: u128,
}

fn mod_pow(mut base: u128, mut exponent: u128, modulus: u128) -> u128 {
    let mut result = 1u128;
    base %= modulus;

    while exponent > 0 {
        if exponent & 1 == 1 {
            result = result.saturating_mul(base) % modulus;
        }
        exponent >>= 1;
        base = base.saturating_mul(base) % modulus;
    }

    result
}

fn validate_setup(setup: &DiffieHellmanSetup) -> Result<(), DiffieHellmanError> {
    if setup.p < 3 {
        return Err(DiffieHellmanError::InvalidModulus);
    }

    if setup.g < 2 || setup.g >= setup.p {
        return Err(DiffieHellmanError::InvalidGenerator);
    }

    Ok(())
}

fn validate_private_key(
    setup: &DiffieHellmanSetup,
    private_key: u128,
) -> Result<(), DiffieHellmanError> {
    validate_setup(setup)?;

    if private_key == 0 || private_key >= setup.p {
        return Err(DiffieHellmanError::InvalidPrivateKey);
    }

    Ok(())
}

pub fn compute_public_key(
    setup: &DiffieHellmanSetup,
    private_key: u128,
) -> Result<u128, DiffieHellmanError> {
    validate_private_key(setup, private_key)?;
    Ok(mod_pow(setup.g, private_key, setup.p))
}

pub fn compute_shared_secret(
    setup: &DiffieHellmanSetup,
    private_key: u128,
    peer_public_key: u128,
) -> Result<u128, DiffieHellmanError> {
    validate_private_key(setup, private_key)?;
    Ok(mod_pow(peer_public_key, private_key, setup.p))
}

pub fn perform_key_exchange(
    setup: &DiffieHellmanSetup,
    alice_private: u128,
    bob_private: u128,
) -> Result<DiffieHellmanExchange, DiffieHellmanError> {
    let alice_public = compute_public_key(setup, alice_private)?;
    let bob_public = compute_public_key(setup, bob_private)?;
    let alice_shared = compute_shared_secret(setup, alice_private, bob_public)?;
    let bob_shared = compute_shared_secret(setup, bob_private, alice_public)?;

    debug_assert_eq!(alice_shared, bob_shared);

    Ok(DiffieHellmanExchange {
        alice_public,
        bob_public,
        shared_secret: alice_shared,
    })
}

#[cfg(test)]
mod tests {
    use super::{DiffieHellmanError, DiffieHellmanSetup, compute_public_key, perform_key_exchange};

    #[test]
    fn computes_matching_shared_secret() {
        let setup = DiffieHellmanSetup { p: 23, g: 5 };
        let exchange = perform_key_exchange(&setup, 6, 15).unwrap();

        assert_eq!(exchange.alice_public, 8);
        assert_eq!(exchange.bob_public, 19);
        assert_eq!(exchange.shared_secret, 2);
    }

    #[test]
    fn rejects_invalid_generator() {
        let setup = DiffieHellmanSetup { p: 23, g: 23 };
        let result = compute_public_key(&setup, 6);

        assert_eq!(result, Err(DiffieHellmanError::InvalidGenerator));
    }

    #[test]
    fn rejects_zero_private_key() {
        let setup = DiffieHellmanSetup { p: 23, g: 5 };
        let result = compute_public_key(&setup, 0);

        assert_eq!(result, Err(DiffieHellmanError::InvalidPrivateKey));
    }
}
