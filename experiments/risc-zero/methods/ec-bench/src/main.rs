#![no_main]

use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

/// Benchmark type to run
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BenchType {
    P256 = 0,
    P384 = 1,
}

fn main() {
    // Read which benchmark to run
    let bench_type: u8 = env::read();

    // Read the test data
    let pubkey_bytes: Vec<u8> = env::read();
    let message_hash: [u8; 32] = env::read();
    let signature_bytes: Vec<u8> = env::read();

    let result = match bench_type {
        0 => verify_p256(&pubkey_bytes, &message_hash, &signature_bytes),
        1 => verify_p384(&pubkey_bytes, &message_hash, &signature_bytes),
        _ => panic!("Unknown benchmark type"),
    };

    // Commit the result
    env::commit(&result);
}

fn verify_p256(pubkey_bytes: &[u8], message_hash: &[u8; 32], signature_bytes: &[u8]) -> bool {
    use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};

    let verifying_key = VerifyingKey::from_sec1_bytes(pubkey_bytes)
        .expect("Invalid P-256 public key");

    let signature = Signature::from_slice(signature_bytes)
        .expect("Invalid P-256 signature");

    verifying_key.verify_prehash(message_hash, &signature).is_ok()
}

fn verify_p384(pubkey_bytes: &[u8], message_hash: &[u8; 32], signature_bytes: &[u8]) -> bool {
    use p384::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};

    let verifying_key = VerifyingKey::from_sec1_bytes(pubkey_bytes)
        .expect("Invalid P-384 public key");

    let signature = Signature::from_slice(signature_bytes)
        .expect("Invalid P-384 signature");

    verifying_key.verify_prehash(message_hash, &signature).is_ok()
}
