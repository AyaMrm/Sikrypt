use sha2::{Digest, Sha256, Sha512};
use std::time::{Duration, Instant};

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShaVariant {
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashBenchmarkResult {
    pub variant: ShaVariant,
    pub input_len: usize,
    pub iterations: u32,
    pub total_nanos: u128,
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn sha256(message: &str) -> String {
    let digest = Sha256::digest(message.as_bytes());
    to_hex(&digest)
}

pub fn sha512(message: &str) -> String {
    let digest = Sha512::digest(message.as_bytes());
    to_hex(&digest)
}

pub fn benchmark_hash(variant: ShaVariant, message: &str, iterations: u32) -> HashBenchmarkResult {
    let iterations = iterations.max(1);
    let started_at = Instant::now();

    for _ in 0..iterations {
        match variant {
            ShaVariant::Sha256 => {
                let _ = Sha256::digest(message.as_bytes());
            }
            ShaVariant::Sha512 => {
                let _ = Sha512::digest(message.as_bytes());
            }
        }
    }

    let elapsed = started_at.elapsed();

    HashBenchmarkResult {
        variant,
        input_len: message.len(),
        iterations,
        total_nanos: duration_to_nanos(elapsed),
    }
}

fn duration_to_nanos(duration: Duration) -> u128 {
    duration.as_nanos()
}

#[cfg(test)]
mod tests {
    use super::{benchmark_hash, sha256, sha512, ShaVariant};

    #[test]
    fn hashes_sha256_known_vector() {
        assert_eq!(
            sha256("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hashes_sha512_known_vector() {
        assert_eq!(
            sha512("abc"),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn benchmark_reports_iterations() {
        let result = benchmark_hash(ShaVariant::Sha256, "benchmark", 25);

        assert_eq!(result.variant, ShaVariant::Sha256);
        assert_eq!(result.input_len, 9);
        assert_eq!(result.iterations, 25);
        assert!(result.total_nanos > 0);
    }
}
