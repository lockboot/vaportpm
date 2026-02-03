use risc0_zkvm::{default_executor, ExecutorEnv};
use std::fs;
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

    let time_secs: u64 = GCP_FIXTURE_TIMESTAMP_SECS;

    let env = ExecutorEnv::builder()
        .write(&attestation_json)
        .unwrap()
        .write(&time_secs)
        .unwrap()
        .build()
        .unwrap();

    let executor = default_executor();
    let session = executor.execute(env, VAPORTPM_ZK_GUEST_ELF).unwrap();

    println!();
    println!("=== GCP Attestation Verification ===");
    println!("Total cycles: {}", session.cycles());
    println!("Segments: {}", session.segments.len());

    /*
    for (i, segment) in session.segments.iter().enumerate() {
        println!("  Segment {}: {} cycles", i, segment.cycles);
    }
    */
    println!();
}

#[test]
fn test_nitro_attestation_cycle_count() {
    // Load test fixture
    let attestation_json =
        fs::read_to_string("../../crates/vaportpm-verify/test-nitro-fixture.json")
            .expect("Failed to load Nitro fixture");

    let time_secs: u64 = NITRO_FIXTURE_TIMESTAMP_SECS;

    let env = ExecutorEnv::builder()
        .write(&attestation_json)
        .unwrap()
        .write(&time_secs)
        .unwrap()
        .build()
        .unwrap();

    let executor = default_executor();
    let session = executor.execute(env, VAPORTPM_ZK_GUEST_ELF).unwrap();

    println!();
    println!("=== Nitro Attestation Verification ===");
    println!("Total cycles: {}", session.cycles());
    println!("Segments: {}", session.segments.len());

    /*
    for (i, segment) in session.segments.iter().enumerate() {
        println!("  Segment {}: {} cycles", i, segment.cycles);
    }
    */
    println!();
}
