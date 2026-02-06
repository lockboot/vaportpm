// SPDX-License-Identifier: MIT OR Apache-2.0

//! Ephemeral key tests for the Nitro verification path.
//!
//! These tests build complete, cryptographically valid attestations from scratch
//! using ephemeral keys, then introduce specific inconsistencies to test error
//! paths through the public API (`verify_decoded_attestation_output`).

use std::collections::BTreeMap;

use p256::pkcs8::DecodePrivateKey as _;

use crate::error::{
    CborParseReason, ChainValidationReason, CoseVerifyReason, InvalidAttestReason,
    SignatureInvalidReason, VerifyError,
};
use crate::pcr::{P256PublicKey, PcrAlgorithm, PcrBank};
use crate::roots::register_test_root;
use crate::test_support;
use crate::{
    verify_decoded_attestation_output, CloudProvider, DecodedAttestationOutput,
    DecodedPlatformAttestation,
};

/// Helper: generate an ephemeral P-256 AK key pair, returning (P256PublicKey, pkcs8_der).
fn ephemeral_ak() -> (P256PublicKey, Vec<u8>) {
    let ak_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let ak_pkcs8 = ak_key.serialize_der();
    let ak_sk = p256::ecdsa::SigningKey::from_pkcs8_der(&ak_pkcs8).unwrap();
    let ak_point = ak_sk.verifying_key().to_encoded_point(false);
    let ak_pubkey = P256PublicKey::from_sec1_uncompressed(ak_point.as_bytes()).unwrap();
    (ak_pubkey, ak_pkcs8)
}

/// Helper: convert PcrBank → idx-only map for COSE document.
fn to_nitro_pcr_map(pcrs: &PcrBank) -> BTreeMap<u8, Vec<u8>> {
    pcrs.values()
        .enumerate()
        .map(|(idx, val)| (idx as u8, val.to_vec()))
        .collect()
}

// =========================================================================

#[test]
fn test_ephemeral_nitro_happy_path() {
    let nonce = [0xAA; 32];
    let pcrs = test_support::make_nitro_pcrs();
    let (decoded, time, _guard) = test_support::build_valid_nitro(&nonce, &pcrs);

    let result = verify_decoded_attestation_output(&decoded, time);
    assert!(result.is_ok(), "Happy path should succeed: {:?}", result);

    let vr = result.unwrap();
    assert_eq!(vr.provider, CloudProvider::Aws);
    assert_eq!(vr.nonce, nonce);
}

#[test]
fn test_ephemeral_nitro_reject_multiple_pcr_banks() {
    let nonce = [0xAA; 32];
    let pcrs = test_support::make_nitro_pcrs();
    let nitro_pcrs = to_nitro_pcr_map(&pcrs);

    let pcr_select = vec![
        (PcrAlgorithm::Sha384 as u16, vec![0xFF, 0xFF, 0xFF]),
        (PcrAlgorithm::Sha256 as u16, vec![0xFF, 0xFF, 0xFF]),
    ];
    // Build with two PCR banks in the Quote:
    let chain = test_support::generate_nitro_chain();
    let guard = register_test_root(chain.root_pubkey_hash, CloudProvider::Aws);
    let (ak_pubkey, ak_pkcs8) = ephemeral_ak();
    let ak_sec1 = ak_pubkey.to_sec1_uncompressed();
    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &ak_pkcs8);
    let cose_doc = test_support::build_nitro_cose_doc(
        &chain.leaf_der,
        std::slice::from_ref(&chain.root_der),
        &nitro_pcrs,
        Some(&ak_sec1),
        Some(&nonce),
        &chain.cose_signing_key,
    );
    let decoded = DecodedAttestationOutput {
        nonce,
        pcrs,
        ak_pubkey,
        quote_attest,
        quote_signature: quote_sig,
        platform: DecodedPlatformAttestation::Nitro { document: cose_doc },
    };

    let result = verify_decoded_attestation_output(&decoded, test_support::ephemeral_time());
    drop(guard);
    assert!(
        matches!(
            result,
            Err(VerifyError::InvalidAttest(
                InvalidAttestReason::MultiplePcrBanks { .. }
            ))
        ),
        "Expected multiple PCR bank error, got: {:?}",
        result
    );
}

#[test]
fn test_ephemeral_nitro_reject_wrong_pcr_algorithm() {
    let nonce = [0xAA; 32];
    let pcrs = test_support::make_nitro_pcrs();
    let nitro_pcrs = to_nitro_pcr_map(&pcrs);

    let chain = test_support::generate_nitro_chain();
    let guard = register_test_root(chain.root_pubkey_hash, CloudProvider::Aws);
    let (ak_pubkey, ak_pkcs8) = ephemeral_ak();
    let ak_sec1 = ak_pubkey.to_sec1_uncompressed();
    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    // SHA-256 instead of SHA-384
    let pcr_select = vec![(PcrAlgorithm::Sha256 as u16, vec![0xFF, 0xFF, 0xFF])];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &ak_pkcs8);
    let cose_doc = test_support::build_nitro_cose_doc(
        &chain.leaf_der,
        std::slice::from_ref(&chain.root_der),
        &nitro_pcrs,
        Some(&ak_sec1),
        Some(&nonce),
        &chain.cose_signing_key,
    );
    let decoded = DecodedAttestationOutput {
        nonce,
        pcrs,
        ak_pubkey,
        quote_attest,
        quote_signature: quote_sig,
        platform: DecodedPlatformAttestation::Nitro { document: cose_doc },
    };

    let result = verify_decoded_attestation_output(&decoded, test_support::ephemeral_time());
    drop(guard);
    assert!(
        matches!(
            result,
            Err(VerifyError::InvalidAttest(
                InvalidAttestReason::WrongPcrAlgorithm {
                    expected: PcrAlgorithm::Sha384,
                    got: 0x000B,
                }
            ))
        ),
        "Expected wrong algorithm error, got: {:?}",
        result
    );
}

#[test]
fn test_ephemeral_nitro_reject_partial_pcr_bitmap() {
    let nonce = [0xAA; 32];
    let pcrs = test_support::make_nitro_pcrs();
    let nitro_pcrs = to_nitro_pcr_map(&pcrs);

    let chain = test_support::generate_nitro_chain();
    let guard = register_test_root(chain.root_pubkey_hash, CloudProvider::Aws);
    let (ak_pubkey, ak_pkcs8) = ephemeral_ak();
    let ak_sec1 = ak_pubkey.to_sec1_uncompressed();
    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    // PCR 23 deselected
    let pcr_select = vec![(PcrAlgorithm::Sha384 as u16, vec![0xFF, 0xFF, 0xFE])];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &ak_pkcs8);
    let cose_doc = test_support::build_nitro_cose_doc(
        &chain.leaf_der,
        std::slice::from_ref(&chain.root_der),
        &nitro_pcrs,
        Some(&ak_sec1),
        Some(&nonce),
        &chain.cose_signing_key,
    );
    let decoded = DecodedAttestationOutput {
        nonce,
        pcrs,
        ak_pubkey,
        quote_attest,
        quote_signature: quote_sig,
        platform: DecodedPlatformAttestation::Nitro { document: cose_doc },
    };

    let result = verify_decoded_attestation_output(&decoded, test_support::ephemeral_time());
    drop(guard);
    assert!(
        matches!(
            result,
            Err(VerifyError::InvalidAttest(
                InvalidAttestReason::PartialPcrBitmap
            ))
        ),
        "Expected partial bitmap error, got: {:?}",
        result
    );
}

#[test]
fn test_ephemeral_nitro_reject_nonce_mismatch() {
    let nonce = [0xAA; 32];
    let pcrs = test_support::make_nitro_pcrs();
    let (mut decoded, time, _guard) = test_support::build_valid_nitro(&nonce, &pcrs);

    decoded.nonce = [0xBB; 32];

    let result = verify_decoded_attestation_output(&decoded, time);
    assert!(
        matches!(
            result,
            Err(VerifyError::InvalidAttest(
                InvalidAttestReason::NonceMismatch
            ))
        ),
        "Expected nonce mismatch error, got: {:?}",
        result
    );
}

#[test]
fn test_ephemeral_nitro_reject_missing_nitro_nonce() {
    let nonce = [0xAA; 32];
    let pcrs = test_support::make_nitro_pcrs();
    let nitro_pcrs = to_nitro_pcr_map(&pcrs);

    let chain = test_support::generate_nitro_chain();
    let guard = register_test_root(chain.root_pubkey_hash, CloudProvider::Aws);
    let (ak_pubkey, ak_pkcs8) = ephemeral_ak();
    let ak_sec1 = ak_pubkey.to_sec1_uncompressed();
    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    let pcr_select = vec![(PcrAlgorithm::Sha384 as u16, vec![0xFF, 0xFF, 0xFF])];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &ak_pkcs8);
    let cose_doc = test_support::build_nitro_cose_doc(
        &chain.leaf_der,
        std::slice::from_ref(&chain.root_der),
        &nitro_pcrs,
        Some(&ak_sec1),
        None, // no nonce
        &chain.cose_signing_key,
    );
    let decoded = DecodedAttestationOutput {
        nonce,
        pcrs,
        ak_pubkey,
        quote_attest,
        quote_signature: quote_sig,
        platform: DecodedPlatformAttestation::Nitro { document: cose_doc },
    };

    let result = verify_decoded_attestation_output(&decoded, test_support::ephemeral_time());
    drop(guard);
    assert!(
        matches!(
            result,
            Err(VerifyError::CborParse(CborParseReason::MissingField {
                field: "nonce"
            }))
        ),
        "Expected missing nonce error, got: {:?}",
        result
    );
}

#[test]
fn test_ephemeral_nitro_reject_nitro_nonce_mismatch() {
    let nonce = [0xAA; 32];
    let wrong_nonce = [0xCC; 32];
    let pcrs = test_support::make_nitro_pcrs();
    let nitro_pcrs = to_nitro_pcr_map(&pcrs);

    let chain = test_support::generate_nitro_chain();
    let guard = register_test_root(chain.root_pubkey_hash, CloudProvider::Aws);
    let (ak_pubkey, ak_pkcs8) = ephemeral_ak();
    let ak_sec1 = ak_pubkey.to_sec1_uncompressed();
    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    let pcr_select = vec![(PcrAlgorithm::Sha384 as u16, vec![0xFF, 0xFF, 0xFF])];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &ak_pkcs8);
    let cose_doc = test_support::build_nitro_cose_doc(
        &chain.leaf_der,
        std::slice::from_ref(&chain.root_der),
        &nitro_pcrs,
        Some(&ak_sec1),
        Some(&wrong_nonce), // different nonce
        &chain.cose_signing_key,
    );
    let decoded = DecodedAttestationOutput {
        nonce,
        pcrs,
        ak_pubkey,
        quote_attest,
        quote_signature: quote_sig,
        platform: DecodedPlatformAttestation::Nitro { document: cose_doc },
    };

    let result = verify_decoded_attestation_output(&decoded, test_support::ephemeral_time());
    drop(guard);
    assert!(
        matches!(
            result,
            Err(VerifyError::SignatureInvalid(
                SignatureInvalidReason::NitroNonceMismatch
            ))
        ),
        "Expected Nitro nonce mismatch error, got: {:?}",
        result
    );
}

#[test]
fn test_ephemeral_nitro_reject_empty_signed_pcrs() {
    let nonce = [0xAA; 32];
    let pcrs = test_support::make_nitro_pcrs();

    let chain = test_support::generate_nitro_chain();
    let guard = register_test_root(chain.root_pubkey_hash, CloudProvider::Aws);
    let (ak_pubkey, ak_pkcs8) = ephemeral_ak();
    let ak_sec1 = ak_pubkey.to_sec1_uncompressed();
    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    let pcr_select = vec![(PcrAlgorithm::Sha384 as u16, vec![0xFF, 0xFF, 0xFF])];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &ak_pkcs8);
    let cose_doc = test_support::build_nitro_cose_doc(
        &chain.leaf_der,
        std::slice::from_ref(&chain.root_der),
        &BTreeMap::new(), // empty PCRs in COSE document
        Some(&ak_sec1),
        Some(&nonce),
        &chain.cose_signing_key,
    );
    let decoded = DecodedAttestationOutput {
        nonce,
        pcrs,
        ak_pubkey,
        quote_attest,
        quote_signature: quote_sig,
        platform: DecodedPlatformAttestation::Nitro { document: cose_doc },
    };

    let result = verify_decoded_attestation_output(&decoded, test_support::ephemeral_time());
    drop(guard);
    assert!(
        matches!(
            result,
            Err(VerifyError::InvalidAttest(
                InvalidAttestReason::EmptySignedPcrs
            ))
        ),
        "Expected empty signed PCRs error, got: {:?}",
        result
    );
}

// Note: test_ephemeral_nitro_reject_pcr_missing_from_attestation was removed
// because PcrBank guarantees all 24 PCRs are present by construction. The
// missing-PCR invariant is tested in pcr.rs unit tests
// (test_reject_wrong_count, test_reject_index_out_of_range).

#[test]
fn test_ephemeral_nitro_reject_pcr_not_signed() {
    let nonce = [0xAA; 32];
    let pcrs = test_support::make_nitro_pcrs();

    // COSE has only 23 PCRs (missing PCR 0) — tests that the COSE document
    // must contain all 24 PCR values that match the decoded PcrBank.
    let mut nitro_pcrs = to_nitro_pcr_map(&pcrs);
    nitro_pcrs.remove(&0);

    let chain = test_support::generate_nitro_chain();
    let guard = register_test_root(chain.root_pubkey_hash, CloudProvider::Aws);
    let (ak_pubkey, ak_pkcs8) = ephemeral_ak();
    let ak_sec1 = ak_pubkey.to_sec1_uncompressed();
    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    let pcr_select = vec![(PcrAlgorithm::Sha384 as u16, vec![0xFF, 0xFF, 0xFF])];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &ak_pkcs8);
    let cose_doc = test_support::build_nitro_cose_doc(
        &chain.leaf_der,
        std::slice::from_ref(&chain.root_der),
        &nitro_pcrs,
        Some(&ak_sec1),
        Some(&nonce),
        &chain.cose_signing_key,
    );
    let decoded = DecodedAttestationOutput {
        nonce,
        pcrs,
        ak_pubkey,
        quote_attest,
        quote_signature: quote_sig,
        platform: DecodedPlatformAttestation::Nitro { document: cose_doc },
    };

    let result = verify_decoded_attestation_output(&decoded, test_support::ephemeral_time());
    drop(guard);
    assert!(
        matches!(
            result,
            Err(VerifyError::InvalidAttest(
                InvalidAttestReason::PcrNotSigned { .. }
            ))
        ),
        "Expected unsigned PCR error, got: {:?}",
        result
    );
}

#[test]
fn test_ephemeral_nitro_reject_pcr_value_mismatch() {
    let nonce = [0xAA; 32];
    let pcrs = test_support::make_nitro_pcrs();

    // COSE has different value for PCR 0 — tests that the COSE document's
    // signed PCR values must match the decoded PcrBank values exactly.
    let mut nitro_pcrs = to_nitro_pcr_map(&pcrs);
    nitro_pcrs.insert(0, vec![0xFF; 48]);

    let chain = test_support::generate_nitro_chain();
    let guard = register_test_root(chain.root_pubkey_hash, CloudProvider::Aws);
    let (ak_pubkey, ak_pkcs8) = ephemeral_ak();
    let ak_sec1 = ak_pubkey.to_sec1_uncompressed();
    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    let pcr_select = vec![(PcrAlgorithm::Sha384 as u16, vec![0xFF, 0xFF, 0xFF])];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &ak_pkcs8);
    let cose_doc = test_support::build_nitro_cose_doc(
        &chain.leaf_der,
        std::slice::from_ref(&chain.root_der),
        &nitro_pcrs,
        Some(&ak_sec1),
        Some(&nonce),
        &chain.cose_signing_key,
    );
    let decoded = DecodedAttestationOutput {
        nonce,
        pcrs,
        ak_pubkey,
        quote_attest,
        quote_signature: quote_sig,
        platform: DecodedPlatformAttestation::Nitro { document: cose_doc },
    };

    let result = verify_decoded_attestation_output(&decoded, test_support::ephemeral_time());
    drop(guard);
    assert!(
        matches!(
            result,
            Err(VerifyError::SignatureInvalid(
                SignatureInvalidReason::PcrValueMismatch { index: 0 }
            ))
        ),
        "Expected PCR value mismatch error, got: {:?}",
        result
    );
}

#[test]
fn test_ephemeral_nitro_reject_missing_public_key() {
    let nonce = [0xAA; 32];
    let pcrs = test_support::make_nitro_pcrs();
    let nitro_pcrs = to_nitro_pcr_map(&pcrs);

    let chain = test_support::generate_nitro_chain();
    let guard = register_test_root(chain.root_pubkey_hash, CloudProvider::Aws);
    let (ak_pubkey, ak_pkcs8) = ephemeral_ak();
    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    let pcr_select = vec![(PcrAlgorithm::Sha384 as u16, vec![0xFF, 0xFF, 0xFF])];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &ak_pkcs8);
    let cose_doc = test_support::build_nitro_cose_doc(
        &chain.leaf_der,
        std::slice::from_ref(&chain.root_der),
        &nitro_pcrs,
        None, // no public_key
        Some(&nonce),
        &chain.cose_signing_key,
    );
    let decoded = DecodedAttestationOutput {
        nonce,
        pcrs,
        ak_pubkey,
        quote_attest,
        quote_signature: quote_sig,
        platform: DecodedPlatformAttestation::Nitro { document: cose_doc },
    };

    let result = verify_decoded_attestation_output(&decoded, test_support::ephemeral_time());
    drop(guard);
    assert!(
        matches!(
            result,
            Err(VerifyError::CborParse(CborParseReason::MissingField {
                field: "public_key"
            }))
        ),
        "Expected missing public_key error, got: {:?}",
        result
    );
}

#[test]
fn test_ephemeral_nitro_reject_ak_mismatch() {
    let nonce = [0xAA; 32];
    let pcrs = test_support::make_nitro_pcrs();
    let nitro_pcrs = to_nitro_pcr_map(&pcrs);

    let chain = test_support::generate_nitro_chain();
    let guard = register_test_root(chain.root_pubkey_hash, CloudProvider::Aws);
    let (ak_pubkey, ak_pkcs8) = ephemeral_ak();
    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    let pcr_select = vec![(PcrAlgorithm::Sha384 as u16, vec![0xFF, 0xFF, 0xFF])];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &ak_pkcs8);
    // Different public_key in COSE
    let wrong_pubkey = [0x05; 65];
    let cose_doc = test_support::build_nitro_cose_doc(
        &chain.leaf_der,
        std::slice::from_ref(&chain.root_der),
        &nitro_pcrs,
        Some(&wrong_pubkey),
        Some(&nonce),
        &chain.cose_signing_key,
    );
    let decoded = DecodedAttestationOutput {
        nonce,
        pcrs,
        ak_pubkey,
        quote_attest,
        quote_signature: quote_sig,
        platform: DecodedPlatformAttestation::Nitro { document: cose_doc },
    };

    let result = verify_decoded_attestation_output(&decoded, test_support::ephemeral_time());
    drop(guard);
    assert!(
        matches!(
            result,
            Err(VerifyError::SignatureInvalid(
                SignatureInvalidReason::AkPublicKeyMismatch
            ))
        ),
        "Expected AK mismatch error, got: {:?}",
        result
    );
}

#[test]
fn test_ephemeral_nitro_reject_wrong_provider_root() {
    let nonce = [0xAA; 32];
    let pcrs = test_support::make_nitro_pcrs();
    let nitro_pcrs = to_nitro_pcr_map(&pcrs);

    let chain = test_support::generate_nitro_chain();
    // Register as GCP instead of AWS
    let guard = register_test_root(chain.root_pubkey_hash, CloudProvider::Gcp);
    let (ak_pubkey, ak_pkcs8) = ephemeral_ak();
    let ak_sec1 = ak_pubkey.to_sec1_uncompressed();
    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    let pcr_select = vec![(PcrAlgorithm::Sha384 as u16, vec![0xFF, 0xFF, 0xFF])];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &ak_pkcs8);
    let cose_doc = test_support::build_nitro_cose_doc(
        &chain.leaf_der,
        std::slice::from_ref(&chain.root_der),
        &nitro_pcrs,
        Some(&ak_sec1),
        Some(&nonce),
        &chain.cose_signing_key,
    );
    let decoded = DecodedAttestationOutput {
        nonce,
        pcrs,
        ak_pubkey,
        quote_attest,
        quote_signature: quote_sig,
        platform: DecodedPlatformAttestation::Nitro { document: cose_doc },
    };

    let result = verify_decoded_attestation_output(&decoded, test_support::ephemeral_time());
    drop(guard);
    assert!(
        matches!(
            result,
            Err(VerifyError::ChainValidation(
                ChainValidationReason::WrongProvider {
                    expected: CloudProvider::Aws,
                    got: CloudProvider::Gcp,
                }
            ))
        ),
        "Expected wrong provider error, got: {:?}",
        result
    );
}

#[test]
fn test_ephemeral_nitro_reject_unknown_root_ca() {
    let nonce = [0xAA; 32];
    let pcrs = test_support::make_nitro_pcrs();
    let nitro_pcrs = to_nitro_pcr_map(&pcrs);

    let chain = test_support::generate_nitro_chain();
    // Deliberately NOT registering the root
    let (ak_pubkey, ak_pkcs8) = ephemeral_ak();
    let ak_sec1 = ak_pubkey.to_sec1_uncompressed();
    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    let pcr_select = vec![(PcrAlgorithm::Sha384 as u16, vec![0xFF, 0xFF, 0xFF])];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &ak_pkcs8);
    let cose_doc = test_support::build_nitro_cose_doc(
        &chain.leaf_der,
        std::slice::from_ref(&chain.root_der),
        &nitro_pcrs,
        Some(&ak_sec1),
        Some(&nonce),
        &chain.cose_signing_key,
    );
    let decoded = DecodedAttestationOutput {
        nonce,
        pcrs,
        ak_pubkey,
        quote_attest,
        quote_signature: quote_sig,
        platform: DecodedPlatformAttestation::Nitro { document: cose_doc },
    };

    let result = verify_decoded_attestation_output(&decoded, test_support::ephemeral_time());
    assert!(
        matches!(
            result,
            Err(VerifyError::ChainValidation(
                ChainValidationReason::UnknownRootCa { .. }
            ))
        ),
        "Expected unknown root CA error, got: {:?}",
        result
    );
}

#[test]
fn test_ephemeral_nitro_reject_payload_not_map() {
    use coset::{iana, CborSerializable, CoseSign1, HeaderBuilder};

    let payload_array = ciborium::Value::Array(vec![ciborium::Value::Integer(42.into())]);
    let mut payload_bytes = Vec::new();
    ciborium::into_writer(&payload_array, &mut payload_bytes).unwrap();

    let cose = CoseSign1 {
        protected: coset::ProtectedHeader {
            original_data: None,
            header: HeaderBuilder::new()
                .algorithm(iana::Algorithm::ES384)
                .build(),
        },
        unprotected: Default::default(),
        payload: Some(payload_bytes),
        signature: vec![0u8; 96],
    };
    let document = cose.to_vec().unwrap();

    let nonce = [0xAA; 32];
    let decoded = DecodedAttestationOutput {
        nonce,
        pcrs: test_support::make_nitro_pcrs(),
        ak_pubkey: P256PublicKey {
            x: [0x04; 32],
            y: [0x04; 32],
        },
        quote_attest: vec![],
        quote_signature: vec![],
        platform: DecodedPlatformAttestation::Nitro { document },
    };

    let result = verify_decoded_attestation_output(&decoded, test_support::ephemeral_time());
    assert!(
        matches!(
            result,
            Err(VerifyError::CborParse(CborParseReason::PayloadNotMap))
        ),
        "Expected PayloadNotMap error, got: {:?}",
        result
    );
}

#[test]
fn test_ephemeral_nitro_reject_invalid_signature_length() {
    use coset::{CborSerializable, CoseSign1};

    let nonce = [0xAA; 32];
    let pcrs = test_support::make_nitro_pcrs();
    let nitro_pcrs = to_nitro_pcr_map(&pcrs);

    let chain = test_support::generate_nitro_chain();
    let guard = register_test_root(chain.root_pubkey_hash, CloudProvider::Aws);
    let (ak_pubkey, ak_pkcs8) = ephemeral_ak();
    let ak_sec1 = ak_pubkey.to_sec1_uncompressed();

    // Build a valid COSE doc first
    let valid_doc = test_support::build_nitro_cose_doc(
        &chain.leaf_der,
        std::slice::from_ref(&chain.root_der),
        &nitro_pcrs,
        Some(&ak_sec1),
        Some(&nonce),
        &chain.cose_signing_key,
    );

    // Re-encode with a 64-byte signature instead of 96
    let mut cose = CoseSign1::from_slice(&valid_doc).unwrap();
    cose.signature = vec![0u8; 64];
    let bad_doc = cose.to_vec().unwrap();

    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    let pcr_select = vec![(PcrAlgorithm::Sha384 as u16, vec![0xFF, 0xFF, 0xFF])];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &ak_pkcs8);

    let decoded = DecodedAttestationOutput {
        nonce,
        pcrs,
        ak_pubkey,
        quote_attest,
        quote_signature: quote_sig,
        platform: DecodedPlatformAttestation::Nitro { document: bad_doc },
    };

    let result = verify_decoded_attestation_output(&decoded, test_support::ephemeral_time());
    drop(guard);
    assert!(
        matches!(
            result,
            Err(VerifyError::CoseVerify(
                CoseVerifyReason::InvalidSignatureLength {
                    expected: 96,
                    got: 64,
                }
            ))
        ),
        "Expected InvalidSignatureLength error, got: {:?}",
        result
    );
}

#[test]
fn test_ephemeral_nitro_reject_wrong_pcr_bank_algorithm() {
    // Construct a valid GCP (SHA-256) PcrBank and pass it to Nitro verification.
    // This should be rejected by the algorithm check in verify_nitro_bindings.
    let nonce = [0xAA; 32];
    let wrong_pcrs = test_support::make_gcp_pcrs(); // SHA-256
    let nitro_pcrs = test_support::make_nitro_pcrs(); // SHA-384

    let (mut decoded, time, _guard) = test_support::build_valid_nitro(&nonce, &nitro_pcrs);
    decoded.pcrs = wrong_pcrs;

    let result = verify_decoded_attestation_output(&decoded, time);
    assert!(
        matches!(
            result,
            Err(VerifyError::InvalidAttest(
                InvalidAttestReason::WrongPcrBankAlgorithm {
                    expected: PcrAlgorithm::Sha384,
                    got: PcrAlgorithm::Sha256,
                }
            ))
        ),
        "Expected WrongPcrBankAlgorithm error, got: {:?}",
        result
    );
}
