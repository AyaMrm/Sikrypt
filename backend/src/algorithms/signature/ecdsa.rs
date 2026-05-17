use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcdsaError {
    InvalidCurve,
    InvalidPrivateKey,
    InvalidEphemeralKey,
    PointAtInfinity,
    ModularInverseDoesNotExist,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurvePoint {
    pub x: u128,
    pub y: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToyCurve {
    pub p: u128,
    pub a: i128,
    pub b: i128,
    pub generator: CurvePoint,
    pub n: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaKeyPair {
    pub private_key: u128,
    pub public_key: CurvePoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaSignature {
    pub r: u128,
    pub s: u128,
}

fn mod_reduce(value: i128, modulus: u128) -> u128 {
    value.rem_euclid(modulus as i128) as u128
}

fn extended_gcd(a: i128, b: i128) -> (i128, i128, i128) {
    if b == 0 {
        (a, 1, 0)
    } else {
        let (gcd, x1, y1) = extended_gcd(b, a % b);
        (gcd, y1, x1 - (a / b) * y1)
    }
}

fn mod_inverse(value: u128, modulus: u128) -> Option<u128> {
    let (gcd, x, _) = extended_gcd(value as i128, modulus as i128);
    if gcd != 1 {
        None
    } else {
        Some(x.rem_euclid(modulus as i128) as u128)
    }
}

fn hash_to_field(message: &str, modulus: u128) -> u128 {
    let digest = Sha256::digest(message.as_bytes());
    let mut reduced = 0u128;

    for &byte in digest.iter().take(16) {
        reduced = (reduced << 8) | byte as u128;
    }

    reduced % modulus
}

type MaybePoint = Option<CurvePoint>;

fn is_on_curve(curve: &ToyCurve, point: CurvePoint) -> bool {
    let left = mod_reduce((point.y * point.y) as i128, curve.p);
    let right = mod_reduce(
        (point.x.pow(3) as i128) + curve.a * point.x as i128 + curve.b,
        curve.p,
    );
    left == right
}

fn point_add(curve: &ToyCurve, p1: MaybePoint, p2: MaybePoint) -> Result<MaybePoint, EcdsaError> {
    match (p1, p2) {
        (None, point) | (point, None) => Ok(point),
        (Some(a), Some(b)) => {
            if a.x == b.x && (a.y + b.y).is_multiple_of(curve.p) {
                return Ok(None);
            }

            let slope = if a == b {
                let numerator = mod_reduce(3 * (a.x * a.x) as i128 + curve.a, curve.p);
                let denominator = mod_inverse((2 * a.y) % curve.p, curve.p)
                    .ok_or(EcdsaError::ModularInverseDoesNotExist)?;
                (numerator * denominator) % curve.p
            } else {
                let numerator = mod_reduce(b.y as i128 - a.y as i128, curve.p);
                let denominator =
                    mod_inverse(mod_reduce(b.x as i128 - a.x as i128, curve.p), curve.p)
                        .ok_or(EcdsaError::ModularInverseDoesNotExist)?;
                (numerator * denominator) % curve.p
            };

            let x3 = mod_reduce((slope * slope) as i128 - a.x as i128 - b.x as i128, curve.p);
            let y3 = mod_reduce(
                slope as i128 * (a.x as i128 - x3 as i128) - a.y as i128,
                curve.p,
            );

            Ok(Some(CurvePoint { x: x3, y: y3 }))
        }
    }
}

fn scalar_mul(curve: &ToyCurve, scalar: u128, point: CurvePoint) -> Result<MaybePoint, EcdsaError> {
    let mut result: MaybePoint = None;
    let mut addend = Some(point);
    let mut k = scalar;

    while k > 0 {
        if k & 1 == 1 {
            result = point_add(curve, result, addend)?;
        }
        addend = point_add(curve, addend, addend)?;
        k >>= 1;
    }

    Ok(result)
}

pub fn demo_curve() -> ToyCurve {
    ToyCurve {
        p: 17,
        a: 2,
        b: 2,
        generator: CurvePoint { x: 5, y: 1 },
        n: 19,
    }
}

pub fn generate_key_pair(curve: &ToyCurve, private_key: u128) -> Result<EcdsaKeyPair, EcdsaError> {
    if !is_on_curve(curve, curve.generator) || curve.n <= 1 {
        return Err(EcdsaError::InvalidCurve);
    }

    if private_key == 0 || private_key >= curve.n {
        return Err(EcdsaError::InvalidPrivateKey);
    }

    let public_key =
        scalar_mul(curve, private_key, curve.generator)?.ok_or(EcdsaError::PointAtInfinity)?;

    Ok(EcdsaKeyPair {
        private_key,
        public_key,
    })
}

pub fn sign(
    curve: &ToyCurve,
    private_key: u128,
    message: &str,
    ephemeral_key: u128,
) -> Result<EcdsaSignature, EcdsaError> {
    if private_key == 0 || private_key >= curve.n {
        return Err(EcdsaError::InvalidPrivateKey);
    }

    if ephemeral_key == 0 || ephemeral_key >= curve.n {
        return Err(EcdsaError::InvalidEphemeralKey);
    }

    let point =
        scalar_mul(curve, ephemeral_key, curve.generator)?.ok_or(EcdsaError::PointAtInfinity)?;
    let r = point.x % curve.n;
    if r == 0 {
        return Err(EcdsaError::InvalidEphemeralKey);
    }

    let k_inv =
        mod_inverse(ephemeral_key, curve.n).ok_or(EcdsaError::ModularInverseDoesNotExist)?;
    let z = hash_to_field(message, curve.n);
    let s = (k_inv * (z + (r * private_key) % curve.n)) % curve.n;

    if s == 0 {
        return Err(EcdsaError::InvalidEphemeralKey);
    }

    Ok(EcdsaSignature { r, s })
}

pub fn verify(
    curve: &ToyCurve,
    public_key: CurvePoint,
    message: &str,
    signature: &EcdsaSignature,
) -> Result<bool, EcdsaError> {
    if signature.r == 0 || signature.r >= curve.n || signature.s == 0 || signature.s >= curve.n {
        return Ok(false);
    }

    let w = mod_inverse(signature.s, curve.n).ok_or(EcdsaError::ModularInverseDoesNotExist)?;
    let z = hash_to_field(message, curve.n);
    let u1 = (z * w) % curve.n;
    let u2 = (signature.r * w) % curve.n;

    let p1 = scalar_mul(curve, u1, curve.generator)?;
    let p2 = scalar_mul(curve, u2, public_key)?;
    let Some(point) = point_add(curve, p1, p2)? else {
        return Ok(false);
    };

    Ok(point.x % curve.n == signature.r)
}

#[cfg(test)]
mod tests {
    use super::{demo_curve, generate_key_pair, sign, verify};

    #[test]
    fn signs_and_verifies_message() {
        let curve = demo_curve();
        let key_pair = generate_key_pair(&curve, 7).unwrap();
        let signature = sign(&curve, key_pair.private_key, "hello", 3).unwrap();

        assert!(verify(&curve, key_pair.public_key, "hello", &signature).unwrap());
    }

    #[test]
    fn rejects_modified_message() {
        let curve = demo_curve();
        let key_pair = generate_key_pair(&curve, 7).unwrap();
        let signature = sign(&curve, key_pair.private_key, "hello", 3).unwrap();

        assert!(!verify(&curve, key_pair.public_key, "HELLO", &signature).unwrap());
    }
}
