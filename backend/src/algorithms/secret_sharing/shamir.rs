use rand::RngCore;
use rand::rngs::OsRng;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShamirShare {
    pub id: u8,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShamirError {
    InvalidThreshold,
    InvalidShare,
}

fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    for _ in 0..8 {
        if b & 1 == 1 {
            result ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    result
}

fn gf256_pow(mut base: u8, mut exp: u8) -> u8 {
    let mut result = 1u8;
    while exp > 0 {
        if exp & 1 == 1 {
            result = gf256_mul(result, base);
        }
        base = gf256_mul(base, base);
        exp >>= 1;
    }
    result
}

fn gf256_inv(value: u8) -> Option<u8> {
    if value == 0 {
        return None;
    }

    Some(gf256_pow(value, 254))
}

fn eval_polynomial(x: u8, coeffs: &[u8], constant: u8) -> u8 {
    let mut result = constant;
    let mut power = x;

    for &coeff in coeffs {
        result = gf256_add(result, gf256_mul(coeff, power));
        power = gf256_mul(power, x);
    }

    result
}

pub fn split(
    secret: &[u8],
    threshold: u8,
    share_count: u8,
) -> Result<Vec<ShamirShare>, ShamirError> {
    if threshold < 2 || share_count < threshold || share_count == 0 {
        return Err(ShamirError::InvalidThreshold);
    }

    let mut rng = OsRng;
    let mut shares: Vec<ShamirShare> = (1..=share_count)
        .map(|id| ShamirShare {
            id,
            value: vec![0u8; secret.len()],
        })
        .collect();

    for (index, &byte) in secret.iter().enumerate() {
        let mut coeffs = vec![0u8; (threshold - 1) as usize];
        rng.fill_bytes(&mut coeffs);

        for share in &mut shares {
            let x = share.id;
            share.value[index] = eval_polynomial(x, &coeffs, byte);
        }
    }

    Ok(shares)
}

pub fn combine(shares: &[ShamirShare], threshold: u8) -> Result<Vec<u8>, ShamirError> {
    if threshold < 2 || shares.len() < threshold as usize {
        return Err(ShamirError::InvalidThreshold);
    }

    let share_len = shares[0].value.len();
    if shares.iter().any(|share| share.value.len() != share_len) {
        return Err(ShamirError::InvalidShare);
    }

    let subset = &shares[..threshold as usize];
    let mut secret = vec![0u8; share_len];

    for (byte_index, secret_byte) in secret.iter_mut().enumerate().take(share_len) {
        let mut value = 0u8;

        for (i, share_i) in subset.iter().enumerate() {
            let xi = share_i.id;
            let yi = share_i.value[byte_index];

            let mut numerator = 1u8;
            let mut denominator = 1u8;

            for (j, share_j) in subset.iter().enumerate() {
                if i == j {
                    continue;
                }
                let xj = share_j.id;
                numerator = gf256_mul(numerator, xj);
                denominator = gf256_mul(denominator, gf256_add(xj, xi));
            }

            let inv = gf256_inv(denominator).ok_or(ShamirError::InvalidShare)?;
            let lagrange = gf256_mul(numerator, inv);
            value = gf256_add(value, gf256_mul(yi, lagrange));
        }

        *secret_byte = value;
    }

    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::{combine, split};

    #[test]
    fn splits_and_combines() {
        let secret = b"secret";
        let shares = split(secret, 3, 5).unwrap();
        let recovered = combine(&shares[..3], 3).unwrap();

        assert_eq!(recovered, secret);
    }
}
