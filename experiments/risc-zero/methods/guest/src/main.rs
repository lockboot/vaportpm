#![no_main]

use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use vaportpm_attest::a9n::AttestationOutput;
use vaportpm_verify::{verify_attestation_output, CloudProvider};

risc0_zkvm::guest::entry!(main);

/// Public inputs committed by the ZK circuit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkPublicInputs {
    pub pcr_hash: [u8; 32],
    #[serde(with = "BigArray")]
    pub ak_pubkey: [u8; 65],
    pub nonce: [u8; 32],
    pub provider: u8,
    pub root_pubkey_hash: [u8; 32],
}

fn main() {
    // Read inputs from host
    let attestation_json: String = env::read();
    let time_secs: u64 = env::read();

    // Parse attestation
    let output: AttestationOutput =
        serde_json::from_str(&attestation_json).expect("Failed to parse attestation JSON");

    // Run EXACT SAME verification as native
    let time = pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(time_secs));
    let result =
        verify_attestation_output(&output, time).expect("Attestation verification failed");

    // Compute canonical PCR hash
    let pcr_hash = compute_pcr_hash(&output.pcrs);

    // Extract AK public key
    let ak_pk = output.ak_pubkeys.get("ecc_p256").expect("Missing AK");
    let mut ak_pubkey = [0u8; 65];
    ak_pubkey[0] = 0x04;
    let x_bytes = hex::decode(&ak_pk.x).expect("Invalid AK x coordinate");
    let y_bytes = hex::decode(&ak_pk.y).expect("Invalid AK y coordinate");
    ak_pubkey[1..33].copy_from_slice(&x_bytes);
    ak_pubkey[33..65].copy_from_slice(&y_bytes);

    // Parse nonce
    let nonce_bytes = hex::decode(&output.nonce).expect("Invalid nonce");
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&nonce_bytes);

    // Parse root pubkey hash
    let root_hash_bytes = hex::decode(&result.root_pubkey_hash).expect("Invalid root hash");
    let mut root_pubkey_hash = [0u8; 32];
    root_pubkey_hash.copy_from_slice(&root_hash_bytes);

    // Map provider to u8
    let provider = match result.provider {
        CloudProvider::Aws => 0u8,
        CloudProvider::Gcp => 1u8,
    };

    // Build and commit public inputs
    let public_inputs = ZkPublicInputs {
        pcr_hash,
        ak_pubkey,
        nonce,
        provider,
        root_pubkey_hash,
    };

    env::commit(&public_inputs);
}

/// Compute canonical PCR hash
///
/// Canonicalization: sort by algorithm name, then by PCR index
fn compute_pcr_hash(
    pcrs: &std::collections::HashMap<String, BTreeMap<u8, String>>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Sort algorithm names
    let mut alg_names: Vec<_> = pcrs.keys().collect();
    alg_names.sort();

    for alg_name in alg_names {
        let pcr_map = &pcrs[alg_name];

        // Add algorithm name (length-prefixed)
        hasher.update(&[alg_name.len() as u8]);
        hasher.update(alg_name.as_bytes());

        // Add PCR count
        hasher.update(&[pcr_map.len() as u8]);

        // BTreeMap is already sorted by key
        for (idx, value_hex) in pcr_map {
            let value_bytes = hex::decode(value_hex).expect("valid hex");
            hasher.update(&[*idx]);
            hasher.update(&[value_bytes.len() as u8]);
            hasher.update(&value_bytes);
        }
    }

    hasher.finalize().into()
}
