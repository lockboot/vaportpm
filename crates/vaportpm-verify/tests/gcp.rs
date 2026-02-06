// SPDX-License-Identifier: MIT OR Apache-2.0

//! GCP Shielded VM attestation verification — tampering and edge case tests
//!
//! These tests verify that the GCP verification path correctly rejects
//! attestations where any component has been tampered with. Each test
//! modifies exactly one field in a known-good fixture and asserts the
//! expected error.

use std::collections::BTreeMap;
use std::time::Duration;

use vaportpm_verify::{
    verify_attestation_output, verify_decoded_attestation_output, CertificateParseReason,
    ChainValidationReason, CloudProvider, DecodedAttestationOutput, DecodedPlatformAttestation,
    EccPublicKeyCoords, InvalidAttestReason, P256PublicKey, PcrAlgorithm, SignatureInvalidReason,
    UnixTime, VerifyError,
};

use vaportpm_verify::AttestationOutput;

/// Timestamp when GCP AMD fixture certificates are valid (Feb 2, 2026 08:00:00 UTC)
const GCP_AMD_FIXTURE_TIMESTAMP_SECS: u64 = 1770019200;

/// Timestamp when GCP TDX fixture certificates are valid (Feb 3, 2026 08:00:00 UTC)
const GCP_TDX_FIXTURE_TIMESTAMP_SECS: u64 = 1770091200;

fn gcp_amd_fixture_time() -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(GCP_AMD_FIXTURE_TIMESTAMP_SECS))
}

fn gcp_tdx_fixture_time() -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(GCP_TDX_FIXTURE_TIMESTAMP_SECS))
}

fn load_gcp_amd_fixture() -> AttestationOutput {
    let fixture = include_str!("../test-gcp-amd-fixture.json");
    serde_json::from_str(fixture).expect("Failed to parse GCP AMD fixture")
}

fn load_gcp_tdx_fixture() -> AttestationOutput {
    let fixture = include_str!("../test-gcp-tdx-fixture.json");
    serde_json::from_str(fixture).expect("Failed to parse GCP TDX fixture")
}

fn decode_gcp_amd_fixture() -> DecodedAttestationOutput {
    let output = load_gcp_amd_fixture();
    DecodedAttestationOutput::decode(&output).expect("Failed to decode GCP AMD fixture")
}

// =============================================================================
// Sanity: unmodified fixtures
// =============================================================================

#[test]
fn test_gcp_amd_fixture_verifies() {
    let output = load_gcp_amd_fixture();
    let result = verify_attestation_output(&output, gcp_amd_fixture_time())
        .expect("Verification should succeed");

    assert_eq!(result.provider, CloudProvider::Gcp);

    let expected_nonce =
        hex::decode("8a543108a653b4a1162232744cc9b945017a449dea4fbb0ca62f42d3ef145562").unwrap();
    assert_eq!(result.nonce.as_slice(), expected_nonce.as_slice());

    assert_eq!(result.pcrs.algorithm(), PcrAlgorithm::Sha256);
}

#[test]
fn test_gcp_tdx_fixture_verifies() {
    let output = load_gcp_tdx_fixture();
    let result = verify_attestation_output(&output, gcp_tdx_fixture_time())
        .expect("Verification should succeed");

    assert_eq!(result.provider, CloudProvider::Gcp);

    let expected_nonce =
        hex::decode("6424632e79ec068f2189adf46d121b9a10f758c45a18c52f630da14600d4317b").unwrap();
    assert_eq!(result.nonce.as_slice(), expected_nonce.as_slice());

    assert_eq!(result.pcrs.algorithm(), PcrAlgorithm::Sha256);
}

// =============================================================================
// Critical: AK public key tampering
// =============================================================================

/// Attacker substitutes their own ECC P-256 public key coordinates.
///
/// Detected at: gcp.rs — AK pubkey from leaf certificate won't match
/// the tampered `decoded.ak_pubkey`.
#[test]
fn test_gcp_reject_tampered_ak_public_key() {
    let mut output = load_gcp_amd_fixture();

    output.ak_pubkeys.insert(
        "ecc_p256".to_string(),
        EccPublicKeyCoords {
            x: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            y: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        },
    );

    let result = verify_attestation_output(&output, gcp_amd_fixture_time());
    assert!(
        matches!(
            result,
            Err(VerifyError::SignatureInvalid(
                SignatureInvalidReason::AkPublicKeyMismatch
            ))
        ),
        "Should reject tampered AK public key, got: {:?}",
        result
    );
}

// =============================================================================
// Critical: PCR value tampering
// =============================================================================

/// Attacker modifies a single SHA-256 PCR value.
///
/// Detected at: gcp.rs `verify_pcr_digest_matches` — the recomputed SHA-256
/// digest of concatenated PCR values won't match the signed digest in the
/// TPM quote.
#[test]
fn test_gcp_reject_tampered_pcr_value() {
    let mut output = load_gcp_amd_fixture();

    if let Some(sha256_pcrs) = output.pcrs.get_mut("sha256") {
        sha256_pcrs.insert(
            0,
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        );
    }

    let result = verify_attestation_output(&output, gcp_amd_fixture_time());
    assert!(
        matches!(
            result,
            Err(VerifyError::InvalidAttest(
                InvalidAttestReason::PcrDigestMismatch
            ))
        ),
        "Should reject tampered PCR value, got: {:?}",
        result
    );
}

// =============================================================================
// Critical: TPM quote signature tampering
// =============================================================================

/// Attacker corrupts the ECDSA signature over the TPM quote.
///
/// Detected at: gcp.rs `verify_ecdsa_p256` — the corrupted DER signature
/// won't verify against the AK public key.
#[test]
fn test_gcp_reject_tampered_quote_signature() {
    let mut output = load_gcp_amd_fixture();

    if let Some(tpm) = output.attestation.tpm.get_mut("ecc_p256") {
        let mut sig_bytes = hex::decode(&tpm.signature).unwrap();
        // Flip a byte in the middle of the DER-encoded signature
        sig_bytes[10] ^= 0xff;
        tpm.signature = hex::encode(sig_bytes);
    }

    let result = verify_attestation_output(&output, gcp_amd_fixture_time());
    assert!(
        matches!(result, Err(VerifyError::SignatureInvalid(_))),
        "Should reject tampered quote signature, got: {:?}",
        result
    );
}

// =============================================================================
// Critical: TPM quote attest_data tampering
// =============================================================================

/// Attacker corrupts the TPM quote attest_data body (outside the nonce region).
///
/// Detected at: gcp.rs `verify_ecdsa_p256` — SHA-256(modified attest_data)
/// won't match the existing signature.
#[test]
fn test_gcp_reject_tampered_quote_attest_data() {
    let mut output = load_gcp_amd_fixture();

    if let Some(tpm) = output.attestation.tpm.get_mut("ecc_p256") {
        let mut attest_bytes = hex::decode(&tpm.attest_data).unwrap();
        // Flip the last byte (in the PCR digest area, not the nonce)
        let last = attest_bytes.len() - 1;
        attest_bytes[last] ^= 0xff;
        tpm.attest_data = hex::encode(attest_bytes);
    }

    let result = verify_attestation_output(&output, gcp_amd_fixture_time());
    assert!(
        matches!(result, Err(VerifyError::SignatureInvalid(_))),
        "Should reject tampered attest_data, got: {:?}",
        result
    );
}

// =============================================================================
// Critical: Nonce tampering (correct length)
// =============================================================================

/// Attacker replaces the nonce with a different 32-byte value.
///
/// This test uses a valid-length nonce (64 hex chars = 32 bytes) to exercise
/// the actual nonce comparison logic in verify_gcp_decoded, unlike the
/// existing test in lib.rs which uses a 4-byte nonce that fails at decode
/// time before reaching the comparison.
///
/// Detected at: gcp.rs — `decoded.nonce != quote_info.nonce`
#[test]
fn test_gcp_reject_tampered_nonce_correct_length() {
    let mut output = load_gcp_amd_fixture();

    // Different 32-byte nonce (64 hex chars)
    output.nonce = "0000000000000000000000000000000000000000000000000000000000000001".to_string();

    let result = verify_attestation_output(&output, gcp_amd_fixture_time());
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
// High: Missing SHA-256 PCRs
// =============================================================================

/// Attestation has PCR values but none for SHA-256 (only SHA-384).
/// GCP verification explicitly requires SHA-256 PCRs and rejects
/// any non-SHA-256 bank.
///
/// Detected at: gcp.rs — WrongPcrBankAlgorithm check
#[test]
fn test_gcp_reject_non_sha256_pcrs() {
    let mut output = load_gcp_amd_fixture();

    // Remove the SHA-256 bank entirely, substitute 24 SHA-384 entries
    // so that PcrBank::from_values succeeds. GCP then rejects it
    // with WrongPcrBankAlgorithm.
    output.pcrs.remove("sha256");
    let mut sha384_pcrs = BTreeMap::new();
    let sha384_zero = "0".repeat(96); // 48 bytes = 96 hex chars
    for idx in 0u8..24 {
        sha384_pcrs.insert(idx, sha384_zero.clone());
    }
    output.pcrs.insert("sha384".to_string(), sha384_pcrs);

    let result = verify_attestation_output(&output, gcp_amd_fixture_time());
    assert!(
        matches!(
            result,
            Err(VerifyError::InvalidAttest(
                InvalidAttestReason::WrongPcrBankAlgorithm {
                    expected: PcrAlgorithm::Sha256,
                    got: PcrAlgorithm::Sha384,
                }
            ))
        ),
        "Should reject attestation with non-SHA-256 PCRs, got: {:?}",
        result
    );
}

// =============================================================================
// High: PCR selected in quote but missing from attestation
// =============================================================================

/// Removing a PCR from the attestation when all 24 are required.
///
/// Detected at: PcrBank::from_values — rejects incomplete PCR sets
#[test]
fn test_gcp_reject_missing_pcr() {
    let mut output = load_gcp_amd_fixture();

    // Remove PCR 0 — hits MissingPcr at decode time
    if let Some(sha256_pcrs) = output.pcrs.get_mut("sha256") {
        sha256_pcrs.remove(&0u8);
    }

    let result = verify_attestation_output(&output, gcp_amd_fixture_time());
    assert!(
        matches!(
            result,
            Err(VerifyError::InvalidAttest(
                InvalidAttestReason::MissingPcr { index: 0 }
            ))
        ),
        "Should reject when a PCR is missing, got: {:?}",
        result
    );
}

// =============================================================================
// High: Certificate chain tampering
// =============================================================================

/// Attacker provides an empty certificate chain.
///
/// Detected at: gcp.rs — "Empty certificate chain" check on parsed DER certs
#[test]
fn test_gcp_reject_empty_cert_chain() {
    let mut output = load_gcp_amd_fixture();

    if let Some(ref mut gcp) = output.attestation.gcp {
        gcp.ak_cert_chain = String::new();
    }

    let result = verify_attestation_output(&output, gcp_amd_fixture_time());
    assert!(
        result.is_err(),
        "Should reject empty certificate chain, got: {:?}",
        result
    );
}

/// Attacker provides a cert chain with corrupted PEM content.
///
/// Detected at: x509.rs PEM parser or DER decoder
#[test]
fn test_gcp_reject_corrupted_cert_chain() {
    let mut output = load_gcp_amd_fixture();

    if let Some(ref mut gcp) = output.attestation.gcp {
        gcp.ak_cert_chain =
            "-----BEGIN CERTIFICATE-----\nTm90QVJlYWxDZXJ0\n-----END CERTIFICATE-----\n"
                .to_string();
    }

    let result = verify_attestation_output(&output, gcp_amd_fixture_time());
    assert!(
        matches!(result, Err(VerifyError::CertificateParse(_))),
        "Should reject corrupted cert chain, got: {:?}",
        result
    );
}

// =============================================================================
// Medium: Time validity
// =============================================================================

/// Verification at a time before the leaf certificate's notBefore.
///
/// Detected at: x509.rs `validate_tpm_cert_chain` — "not yet valid"
#[test]
fn test_gcp_reject_cert_not_yet_valid() {
    let output = load_gcp_amd_fixture();

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
fn test_gcp_reject_cert_expired() {
    let output = load_gcp_amd_fixture();

    // Use a timestamp far in the future (year 2100).
    // The GCP leaf cert expires 2056-01-26, root expires 2122-07-08.
    // The intermediate also expires 2122-07-08. So 2060 should trigger
    // leaf expiry.
    let future_time = UnixTime::since_unix_epoch(Duration::from_secs(2840140800));

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
// Coverage: decoded-level edge cases (via verify_decoded_attestation_output)
//
// These tests bypass the JSON→decode path to inject data that can't occur
// through normal deserialization but could arrive via the flat binary format
// or a buggy caller.
//
// These are crucial for testing the ZK verification path which takes data directly
// from the ZK host program, where essentially the host coul be malicious or adversarial
// =============================================================================

/// Empty cert_chain_der — no certificates at all.
///
/// Covers: gcp.rs:40-44 (certs.is_empty() branch)
#[test]
fn test_gcp_decoded_reject_empty_cert_chain() {
    let mut decoded = decode_gcp_amd_fixture();
    decoded.platform = DecodedPlatformAttestation::Gcp {
        cert_chain_der: vec![],
    };

    let result = verify_decoded_attestation_output(&decoded, gcp_amd_fixture_time());
    assert!(
        matches!(
            result,
            Err(VerifyError::ChainValidation(
                ChainValidationReason::EmptyChain
            ))
        ),
        "Should reject empty cert chain in decoded path, got: {:?}",
        result
    );
}

/// Invalid DER bytes in cert_chain_der.
///
/// Covers: gcp.rs:35-37 (Certificate::from_der error path)
#[test]
fn test_gcp_decoded_reject_invalid_der_cert() {
    let mut decoded = decode_gcp_amd_fixture();
    decoded.platform = DecodedPlatformAttestation::Gcp {
        cert_chain_der: vec![vec![0x30, 0x00, 0xFF, 0xFF]],
    };

    let result = verify_decoded_attestation_output(&decoded, gcp_amd_fixture_time());
    assert!(
        matches!(
            result,
            Err(VerifyError::CertificateParse(
                CertificateParseReason::InvalidDer(_)
            ))
        ),
        "Should reject invalid DER cert, got: {:?}",
        result
    );
}

/// Certificate chain that is structurally valid but not rooted at a known
/// cloud provider CA. The chain validation passes but provider lookup fails.
///
/// Covers: gcp.rs — provider_from_hash returns None → "Unknown root CA"
#[test]
fn test_gcp_decoded_reject_unknown_root_ca() {
    use ecdsa::signature::hazmat::PrehashSigner;
    use p256::pkcs8::DecodePrivateKey;
    use sha2::Digest;

    // Generate a self-signed CA
    let mut ca_params = rcgen::CertificateParams::new(vec!["Fake Root CA".to_string()]).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Fake Root CA");
    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    // Generate a leaf cert signed by our fake CA
    let mut leaf_params = rcgen::CertificateParams::new(vec!["Fake Leaf".to_string()]).unwrap();
    leaf_params.is_ca = rcgen::IsCa::NoCa;
    leaf_params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Fake Leaf");
    let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

    // Start from the real fixture (has valid quote_attest, nonce, PCRs)
    let mut decoded = decode_gcp_amd_fixture();

    // Extract AK public key from the leaf signing key
    let leaf_signing_key_for_pk =
        p256::ecdsa::SigningKey::from_pkcs8_der(&leaf_key.serialize_der()).unwrap();
    let ak_point = leaf_signing_key_for_pk
        .verifying_key()
        .to_encoded_point(false);
    decoded.ak_pubkey = P256PublicKey::from_sec1_uncompressed(ak_point.as_bytes()).unwrap();

    // Re-sign the quote_attest with the fake leaf's private key so the
    // signature verification passes. verify_ecdsa_p256 does
    // verify_prehash(SHA-256(message)), so we sign_prehash the same digest.
    let leaf_signing_key =
        p256::ecdsa::SigningKey::from_pkcs8_der(&leaf_key.serialize_der()).unwrap();
    let digest = sha2::Sha256::digest(&decoded.quote_attest);
    let signature: p256::ecdsa::Signature = leaf_signing_key.sign_prehash(&digest).unwrap();
    decoded.quote_signature = signature.to_der().as_bytes().to_vec();

    // Swap in our fake cert chain
    decoded.platform = DecodedPlatformAttestation::Gcp {
        cert_chain_der: vec![leaf_cert.der().to_vec(), ca_cert.der().to_vec()],
    };

    let result = verify_decoded_attestation_output(&decoded, gcp_amd_fixture_time());
    assert!(
        matches!(
            result,
            Err(VerifyError::ChainValidation(
                ChainValidationReason::UnknownRootCa { .. }
            ))
        ),
        "Should reject unknown root CA, got: {:?}",
        result
    );
}
