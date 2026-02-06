#![no_main]

use pki_types::UnixTime;
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::time::Duration;
use vaportpm_verify::{flat, verify_decoded_attestation_output, CloudProvider, P256PublicKey, PcrBank};

risc0_zkvm::guest::entry!(main);

/// Public inputs committed by the ZK circuit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkPublicInputs {
    pub pcr_hash: [u8; 32],
    pub ak_pubkey: P256PublicKey,
    pub nonce: [u8; 32],
    pub provider: u8,
    pub verified_at: u64,
}

fn main() {
    // Read raw bytes - no serde deserialization!
    let mut input_bytes = Vec::<u8>::new();
    env::stdin().read_to_end(&mut input_bytes).unwrap();

    // Last 8 bytes are the verification timestamp
    if input_bytes.len() < 8 {
        panic!("Input too short - missing timestamp");
    }
    let time_bytes: [u8; 8] = input_bytes[input_bytes.len() - 8..].try_into().unwrap();
    let time_secs = u64::from_le_bytes(time_bytes);
    let time = UnixTime::since_unix_epoch(Duration::from_secs(time_secs));

    // Parse flat binary format (everything except the trailing timestamp)
    let flat_data = &input_bytes[..input_bytes.len() - 8];
    let decoded = flat::from_bytes(flat_data).expect("Failed to parse flat input");

    // Verify using decoded path (no hex::decode, no PEM parsing)
    let result =
        verify_decoded_attestation_output(&decoded, time).expect("Attestation verification failed");

    // Compute canonical PCR hash from pre-decoded binary data
    let pcr_hash = compute_pcr_hash(&decoded.pcrs);

    // Map provider to u8 (root hash already verified against known roots)
    let provider = match result.provider {
        CloudProvider::Aws => 0u8,
        CloudProvider::Gcp => 1u8,
    };

    // Build and commit public inputs
    let public_inputs = ZkPublicInputs {
        pcr_hash,
        ak_pubkey: decoded.ak_pubkey,
        nonce: decoded.nonce,
        provider,
        verified_at: result.verified_at,
    };

    env::commit(&public_inputs);
}

/// Compute canonical PCR hash from a validated PcrBank
///
/// Canonicalization: [alg_u16 LE, count] then each [idx, value...] in index order
fn compute_pcr_hash(pcrs: &PcrBank) -> [u8; 32] {
    let mut hasher = Sha256::new();

    let alg_u16 = pcrs.algorithm() as u16;
    hasher.update(alg_u16.to_le_bytes());
    hasher.update([24u8]);

    for (idx, value) in pcrs.values().enumerate() {
        hasher.update([idx as u8]);
        hasher.update(value);
    }

    hasher.finalize().into()
}
