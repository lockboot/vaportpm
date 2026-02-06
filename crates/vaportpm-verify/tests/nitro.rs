// SPDX-License-Identifier: MIT OR Apache-2.0

//! AWS Nitro attestation verification — happy path and tampering tests
//!
//! These tests verify that the Nitro verification path correctly accepts
//! valid attestations and rejects any where a component has been tampered with.

use std::collections::BTreeMap;
use std::time::Duration;

use vaportpm_verify::{
    verify_attestation_output, verify_decoded_attestation_output, ChainValidationReason,
    CloudProvider, DecodedAttestationOutput, DecodedPlatformAttestation, EccPublicKeyCoords,
    InvalidAttestReason, UnixTime, VerifyError,
};

use vaportpm_verify::AttestationOutput;

/// Timestamp when Nitro fixture certificates are valid (Feb 3, 2026 11:00:00 UTC)
const NITRO_FIXTURE_TIMESTAMP_SECS: u64 = 1770116400;

fn nitro_fixture_time() -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(NITRO_FIXTURE_TIMESTAMP_SECS))
}

fn load_nitro_fixture() -> AttestationOutput {
    let fixture = include_str!("../test-nitro-fixture.json");
    serde_json::from_str(fixture).expect("Failed to parse Nitro fixture")
}

fn decode_nitro_fixture() -> DecodedAttestationOutput {
    let output = load_nitro_fixture();
    DecodedAttestationOutput::decode(&output).expect("Failed to decode Nitro fixture")
}

// =============================================================================
// Sanity: unmodified fixture
// =============================================================================

#[test]
fn test_nitro_fixture_verifies() {
    let output = load_nitro_fixture();
    let result = verify_attestation_output(&output, nitro_fixture_time())
        .expect("Verification should succeed");

    assert_eq!(result.provider, CloudProvider::Aws);

    let expected_nonce =
        hex::decode("230af3f7c0ec43ccf99a4cab47ac61469a36ea74b1e79740fdf8ccfc8f56161a").unwrap();
    assert_eq!(result.nonce.as_slice(), expected_nonce.as_slice());

    assert!(!result.pcrs.is_empty());

    // Verify SHA-384 PCRs are present
    let has_sha384 = result.pcrs.keys().any(|(alg_id, _)| *alg_id == 1);
    assert!(has_sha384, "Should have SHA-384 PCRs");
}

// =============================================================================
// Tampering: AK public key
// =============================================================================

/// Attacker substitutes their own AK public key coordinates.
///
/// Detected at: nitro.rs — the AK pubkey won't match the signed
/// `public_key` binding in the Nitro NSM document.
#[test]
fn test_nitro_reject_tampered_ak_public_key() {
    let mut output = load_nitro_fixture();

    output.ak_pubkeys.insert(
        "ecc_p256".to_string(),
        EccPublicKeyCoords {
            x: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            y: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        },
    );

    let result = verify_attestation_output(&output, nitro_fixture_time());
    assert!(
        matches!(result, Err(VerifyError::SignatureInvalid(_))),
        "Should reject tampered AK public key, got: {:?}",
        result
    );
}

// =============================================================================
// Tampering: nonce
// =============================================================================

/// Attacker replaces the nonce with a short value (wrong length).
///
/// Detected at: DecodedAttestationOutput::decode() — "nonce must be 32 bytes"
#[test]
fn test_nitro_reject_tampered_nonce_wrong_length() {
    let mut output = load_nitro_fixture();

    output.nonce = "deadbeef".to_string();

    let result = verify_attestation_output(&output, nitro_fixture_time());
    assert!(
        matches!(
            result,
            Err(VerifyError::InvalidAttest(
                InvalidAttestReason::NonceLengthInvalid
            ))
        ),
        "Should reject wrong-length nonce, got: {:?}",
        result
    );
}

/// Attacker replaces the nonce with a different 32-byte value.
///
/// This exercises the actual nonce comparison in verify_nitro_decoded,
/// not the decode-time length check.
///
/// Detected at: nitro.rs — "Nonce does not match Quote"
#[test]
fn test_nitro_reject_tampered_nonce_correct_length() {
    let mut output = load_nitro_fixture();

    // Different 32-byte nonce (64 hex chars)
    output.nonce = "0000000000000000000000000000000000000000000000000000000000000001".to_string();

    let result = verify_attestation_output(&output, nitro_fixture_time());
    assert!(
        matches!(
            result,
            Err(VerifyError::InvalidAttest(
                InvalidAttestReason::NonceMismatch
            ))
        ),
        "Should reject nonce that doesn't match Quote extraData, got: {:?}",
        result
    );
}

// =============================================================================
// Tampering: PCR values
// =============================================================================

/// Attacker modifies a SHA-384 PCR value.
///
/// Detected at: nitro.rs — claimed PCR values don't match the signed
/// values in the Nitro NSM document.
#[test]
fn test_nitro_reject_tampered_pcr_values() {
    let mut output = load_nitro_fixture();

    if let Some(sha384_pcrs) = output.pcrs.get_mut("sha384") {
        sha384_pcrs.insert(
            0,
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string()
        );
    }

    let result = verify_attestation_output(&output, nitro_fixture_time());
    assert!(
        matches!(result, Err(VerifyError::SignatureInvalid(_))),
        "Should reject tampered PCR values, got: {:?}",
        result
    );
}

// =============================================================================
// Critical: Tampered quote signature
// =============================================================================

/// Attacker corrupts the ECDSA signature over the TPM quote.
///
/// Detected at: nitro.rs `verify_ecdsa_p256` — the corrupted DER signature
/// won't verify against the AK public key.
#[test]
fn test_nitro_reject_tampered_quote_signature() {
    let mut output = load_nitro_fixture();

    if let Some(tpm) = output.attestation.tpm.get_mut("ecc_p256") {
        let mut sig_bytes = hex::decode(&tpm.signature).unwrap();
        // Flip a byte in the middle of the DER-encoded signature
        sig_bytes[10] ^= 0xff;
        tpm.signature = hex::encode(sig_bytes);
    }

    let result = verify_attestation_output(&output, nitro_fixture_time());
    assert!(
        matches!(result, Err(VerifyError::SignatureInvalid(_))),
        "Should reject tampered quote signature, got: {:?}",
        result
    );
}

// =============================================================================
// Critical: Tampered quote attest_data
// =============================================================================

/// Attacker corrupts the TPM quote attest_data body.
///
/// With the verification order fix, the ECDSA signature is verified first,
/// so corrupting attest_data should produce SignatureInvalid (not a PCR
/// digest mismatch or nonce error).
///
/// Detected at: nitro.rs `verify_ecdsa_p256` — SHA-256(modified attest_data)
/// won't match the existing signature.
#[test]
fn test_nitro_reject_tampered_quote_attest_data() {
    let mut output = load_nitro_fixture();

    if let Some(tpm) = output.attestation.tpm.get_mut("ecc_p256") {
        let mut attest_bytes = hex::decode(&tpm.attest_data).unwrap();
        // Flip the last byte (in the PCR digest area, not the nonce)
        let last = attest_bytes.len() - 1;
        attest_bytes[last] ^= 0xff;
        tpm.attest_data = hex::encode(attest_bytes);
    }

    let result = verify_attestation_output(&output, nitro_fixture_time());
    assert!(
        matches!(result, Err(VerifyError::SignatureInvalid(_))),
        "Should reject tampered attest_data with SignatureInvalid (not PCR mismatch), got: {:?}",
        result
    );
}

// =============================================================================
// Medium: Certificate time validity
// =============================================================================

/// Verification at a time before the leaf certificate's notBefore.
///
/// Detected at: x509.rs `validate_tpm_cert_chain` — "not yet valid"
#[test]
fn test_nitro_reject_cert_not_yet_valid() {
    let output = load_nitro_fixture();

    // Use a timestamp far in the past (year 2020)
    let past_time = UnixTime::since_unix_epoch(Duration::from_secs(1577836800));

    let result = verify_attestation_output(&output, past_time);
    assert!(
        matches!(
            result,
            Err(VerifyError::ChainValidation(
                ChainValidationReason::CertNotYetValid { .. }
            ))
        ),
        "Should reject cert not yet valid, got: {:?}",
        result
    );
}

/// Verification at a time after the leaf certificate's notAfter.
///
/// Detected at: x509.rs `validate_tpm_cert_chain` — "has expired"
#[test]
fn test_nitro_reject_cert_expired() {
    let output = load_nitro_fixture();

    // Use a timestamp far in the future (year 2100)
    let future_time = UnixTime::since_unix_epoch(Duration::from_secs(4102444800));

    let result = verify_attestation_output(&output, future_time);
    assert!(
        matches!(
            result,
            Err(VerifyError::ChainValidation(
                ChainValidationReason::CertExpired { .. }
            ))
        ),
        "Should reject expired cert, got: {:?}",
        result
    );
}

// =============================================================================
// High: Missing SHA-384 PCRs
// =============================================================================

/// Attestation has PCR values but none for SHA-384 (only SHA-256).
/// Nitro verification explicitly requires SHA-384 PCRs and rejects
/// any non-SHA-384 bank.
///
/// Detected at: nitro.rs — non-SHA-384 PCR rejection
#[test]
fn test_nitro_reject_non_sha384_pcrs() {
    let mut output = load_nitro_fixture();

    // Remove the SHA-384 bank entirely, substitute a SHA-256 entry
    // so that decode() doesn't fail on empty PCRs
    output.pcrs.remove("sha384");
    let mut sha256_pcrs = BTreeMap::new();
    sha256_pcrs.insert(
        0u8,
        "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
    );
    output.pcrs.insert("sha256".to_string(), sha256_pcrs);

    let result = verify_attestation_output(&output, nitro_fixture_time());
    assert!(
        matches!(
            result,
            Err(VerifyError::InvalidAttest(
                InvalidAttestReason::UnexpectedPcrAlgorithmNitro { .. }
            ))
        ),
        "Should reject attestation with non-SHA-384 PCRs, got: {:?}",
        result
    );
}

/// Attestation has SHA-384 PCRs but also includes SHA-256 PCRs.
/// The Nitro path must reject extra unverified PCR banks — they would
/// pass through to the output as unverified data.
///
/// Detected at: nitro.rs — non-SHA-384 PCR rejection
#[test]
fn test_nitro_reject_extra_sha256_pcrs() {
    let mut output = load_nitro_fixture();

    // Add a SHA-256 bank alongside the existing SHA-384 bank
    let mut sha256_pcrs = BTreeMap::new();
    sha256_pcrs.insert(
        0u8,
        "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
    );
    output.pcrs.insert("sha256".to_string(), sha256_pcrs);

    let result = verify_attestation_output(&output, nitro_fixture_time());
    assert!(
        matches!(
            result,
            Err(VerifyError::InvalidAttest(
                InvalidAttestReason::UnexpectedPcrAlgorithmNitro { .. }
            ))
        ),
        "Should reject attestation with extra SHA-256 PCRs alongside SHA-384, got: {:?}",
        result
    );
}

// =============================================================================
// Coverage: decoded-level edge cases (via verify_decoded_attestation_output)
//
// These tests bypass the JSON→decode path to inject data that can't occur
// through normal deserialization but could arrive via the flat binary format
// or a buggy/malicious caller.
// =============================================================================

/// Empty COSE document bytes.
///
/// Covers: nitro.rs — CoseSign1::from_slice error path
#[test]
fn test_nitro_decoded_reject_empty_cose_document() {
    let mut decoded = decode_nitro_fixture();
    decoded.platform = DecodedPlatformAttestation::Nitro { document: vec![] };

    let result = verify_decoded_attestation_output(&decoded, nitro_fixture_time());
    assert!(
        matches!(result, Err(VerifyError::CoseVerify(_))),
        "Should reject empty COSE document, got: {:?}",
        result
    );
}

/// Corrupted COSE document bytes.
///
/// Covers: nitro.rs — CoseSign1::from_slice error path
#[test]
fn test_nitro_decoded_reject_corrupted_cose_document() {
    let mut decoded = decode_nitro_fixture();
    decoded.platform = DecodedPlatformAttestation::Nitro {
        document: vec![0xFF, 0xFF, 0xFF, 0xFF],
    };

    let result = verify_decoded_attestation_output(&decoded, nitro_fixture_time());
    assert!(
        matches!(result, Err(VerifyError::CoseVerify(_))),
        "Should reject corrupted COSE document, got: {:?}",
        result
    );
}

/// Empty PCR map at the decoded level.
///
/// The COSE and ECDSA signatures still pass (unmodified), but Phase 3
/// rejects the empty PCRs before cross-verification.
///
/// Covers: nitro.rs — "Missing SHA-384 PCRs - required for Nitro attestation"
#[test]
fn test_nitro_decoded_reject_empty_pcrs() {
    let mut decoded = decode_nitro_fixture();
    decoded.pcrs.clear();

    let result = verify_decoded_attestation_output(&decoded, nitro_fixture_time());
    assert!(
        matches!(
            result,
            Err(VerifyError::InvalidAttest(
                InvalidAttestReason::MissingSha384Pcrs
            ))
        ),
        "Should reject empty PCRs, got: {:?}",
        result
    );
}

/// Decoded PCRs contain a non-SHA-384 entry (alg_id=0 is SHA-256).
///
/// Covers: nitro.rs — "non-SHA-384 PCR" rejection at decoded level
#[test]
fn test_nitro_decoded_reject_non_sha384_pcr() {
    let mut decoded = decode_nitro_fixture();

    // Replace all PCRs with SHA-256 (alg_id=0) entries
    let sha384_values: Vec<(u8, Vec<u8>)> = decoded
        .pcrs
        .iter()
        .filter(|((alg, _), _)| *alg == 1)
        .map(|((_alg, idx), val)| (*idx, val.clone()))
        .collect();

    decoded.pcrs.clear();
    for (idx, val) in sha384_values {
        // Insert as SHA-256 (alg_id=0) instead of SHA-384 (alg_id=1)
        decoded.pcrs.insert((0, idx), val);
    }

    let result = verify_decoded_attestation_output(&decoded, nitro_fixture_time());
    assert!(
        matches!(
            result,
            Err(VerifyError::InvalidAttest(
                InvalidAttestReason::UnexpectedPcrAlgorithmNitro { .. }
            ))
        ),
        "Should reject non-SHA-384 PCRs at decoded level, got: {:?}",
        result
    );
}

/// Decoded PCRs contain an index above 23.
///
/// Covers: nitro.rs — "PCR index {} out of range; only PCRs 0-23 are valid"
#[test]
fn test_nitro_decoded_reject_pcr_index_out_of_range() {
    let mut decoded = decode_nitro_fixture();

    // Add a PCR with index 24 (out of range)
    decoded.pcrs.insert((1, 24), vec![0x00; 48]);

    let result = verify_decoded_attestation_output(&decoded, nitro_fixture_time());
    assert!(
        matches!(
            result,
            Err(VerifyError::InvalidAttest(
                InvalidAttestReason::PcrIndexOutOfRange { .. }
            ))
        ),
        "Should reject PCR index > 23, got: {:?}",
        result
    );
}

/// Decoded PCRs are missing one of the 24 required SHA-384 entries.
///
/// Covers: nitro.rs — "Missing SHA-384 PCR {} - all 24 PCRs (0-23) are required"
#[test]
fn test_nitro_decoded_reject_missing_pcr() {
    let mut decoded = decode_nitro_fixture();

    // Remove PCR 5 (arbitrary choice)
    decoded.pcrs.remove(&(1, 5));

    let result = verify_decoded_attestation_output(&decoded, nitro_fixture_time());
    assert!(
        matches!(
            result,
            Err(VerifyError::InvalidAttest(
                InvalidAttestReason::MissingPcr { .. }
            ))
        ),
        "Should reject missing SHA-384 PCR, got: {:?}",
        result
    );
}
