use risc0_zkvm::{default_executor, ExecutorEnv};
use std::fs;
use vaportpm_attest::a9n::AttestationOutput;
use vaportpm_verify::{flat, DecodedAttestationOutput};
use vaportpm_zk_methods::VAPORTPM_ZK_GUEST_ELF;

/// Timestamp for GCP test fixture (Feb 2, 2026 when certificates are valid)
const GCP_FIXTURE_TIMESTAMP_SECS: u64 = 1770019200;

/// Timestamp for Nitro test fixture (Feb 3, 2026 within cert validity window)
const NITRO_FIXTURE_TIMESTAMP_SECS: u64 = 1770116400;

#[test]
fn test_gcp_attestation_cycle_count() {
    // Load test fixture
    let attestation_json =
        fs::read_to_string("../../crates/vaportpm-verify/test-gcp-amd-fixture.json")
            .expect("Failed to load GCP fixture");

    // Parse JSON on host
    let output: AttestationOutput =
        serde_json::from_str(&attestation_json).expect("Failed to parse attestation JSON");

    // Decode to binary format on host
    let decoded =
        DecodedAttestationOutput::decode(&output).expect("Failed to decode attestation");

    // Convert to flat binary format with timestamp appended
    let mut flat_bytes = flat::to_bytes(&decoded);
    flat_bytes.extend_from_slice(&GCP_FIXTURE_TIMESTAMP_SECS.to_le_bytes());

    let env = ExecutorEnv::builder()
        .write_slice(&flat_bytes) // write_slice instead of write!
        .build()
        .unwrap();

    let executor = default_executor();
    let session = executor.execute(env, VAPORTPM_ZK_GUEST_ELF).unwrap();

    println!();
    println!("=== GCP Attestation Verification (Optimized + zerocopy) ===");
    println!("Flat input size: {} bytes", flat_bytes.len());
    println!("Total cycles: {}", session.cycles());
    println!("Segments: {}", session.segments.len());
    println!();
}

#[test]
fn test_nitro_attestation_cycle_count() {
    // Load test fixture
    let attestation_json =
        fs::read_to_string("../../crates/vaportpm-verify/test-nitro-fixture.json")
            .expect("Failed to load Nitro fixture");

    // Parse JSON on host
    let output: AttestationOutput =
        serde_json::from_str(&attestation_json).expect("Failed to parse attestation JSON");

    // Decode to binary format on host
    let decoded =
        DecodedAttestationOutput::decode(&output).expect("Failed to decode attestation");

    // Convert to flat binary format with timestamp appended
    let mut flat_bytes = flat::to_bytes(&decoded);
    flat_bytes.extend_from_slice(&NITRO_FIXTURE_TIMESTAMP_SECS.to_le_bytes());

    let env = ExecutorEnv::builder()
        .write_slice(&flat_bytes)
        .build()
        .unwrap();

    let executor = default_executor();
    let session = executor.execute(env, VAPORTPM_ZK_GUEST_ELF).unwrap();

    println!();
    println!("=== Nitro Attestation Verification (Optimized + zerocopy) ===");
    println!("Flat input size: {} bytes", flat_bytes.len());
    println!("Total cycles: {}", session.cycles());
    println!("Segments: {}", session.segments.len());
    println!();
}

#[test]
fn test_data_size_comparison() {
    // Load test fixture
    let attestation_json =
        fs::read_to_string("../../crates/vaportpm-verify/test-gcp-amd-fixture.json")
            .expect("Failed to load GCP fixture");

    println!("\n=== Original JSON approach ===");
    println!("JSON string length: {} bytes", attestation_json.len());

    // Parse JSON on host
    let output: AttestationOutput =
        serde_json::from_str(&attestation_json).expect("Failed to parse attestation JSON");

    // Decode to binary format
    let decoded =
        DecodedAttestationOutput::decode(&output).expect("Failed to decode attestation");

    // Flat binary format (what we now use) + timestamp
    let flat_bytes = flat::to_bytes(&decoded);
    println!("\n=== Flat binary approach (zerocopy) ===");
    println!("Flat binary size: {} bytes (+ 8 bytes timestamp)", flat_bytes.len());

    println!("\nComponent sizes:");
    println!("  header: {} bytes (zerocopy, zero-copy parse)", flat::HEADER_SIZE);
    println!("  quote_attest: {} bytes", decoded.quote_attest.len());
    println!("  quote_signature: {} bytes", decoded.quote_signature.len());

    match &decoded.platform {
        vaportpm_verify::DecodedPlatformAttestation::Gcp { cert_chain_der } => {
            let total_cert_bytes: usize = cert_chain_der.iter().map(|c| c.len()).sum();
            println!(
                "  cert_chain_der: {} certs, {} total bytes",
                cert_chain_der.len(),
                total_cert_bytes
            );
        }
        _ => {}
    }

    let pcr_bytes: usize = decoded.pcrs.values().map(|v| v.len()).sum();
    println!("  pcrs: {} entries, {} total bytes", decoded.pcrs.len(), pcr_bytes);
    println!();
}
