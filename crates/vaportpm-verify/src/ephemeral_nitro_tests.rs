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
    NoValidAttestationReason, SignatureInvalidReason, VerifyError,
};
use crate::roots::register_test_root;
use crate::test_support;
use crate::{
    verify_decoded_attestation_output, CloudProvider, DecodedAttestationOutput,
    DecodedPlatformAttestation,
};

/// Helper: generate an ephemeral P-256 AK key pair, returning (pubkey_65bytes, pkcs8_der).
fn ephemeral_ak() -> ([u8; 65], Vec<u8>) {
    let ak_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let ak_pkcs8 = ak_key.serialize_der();
    let ak_sk = p256::ecdsa::SigningKey::from_pkcs8_der(&ak_pkcs8).unwrap();
    let ak_point = ak_sk.verifying_key().to_encoded_point(false);
    let mut ak_pubkey = [0u8; 65];
    ak_pubkey.copy_from_slice(ak_point.as_bytes());
    (ak_pubkey, ak_pkcs8)
}

/// Helper: convert decoded PCRs (alg_id, idx) → idx-only map for COSE.
fn to_nitro_pcr_map(pcrs: &BTreeMap<(u8, u8), Vec<u8>>) -> BTreeMap<u8, Vec<u8>> {
    pcrs.iter()
        .map(|((_alg, idx), val)| (*idx, val.clone()))
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
        (0x000Cu16, vec![0xFF, 0xFF, 0xFF]),
        (0x000Bu16, vec![0xFF, 0xFF, 0xFF]),
    ];
    // Build with two PCR banks in the Quote:
    let chain = test_support::generate_nitro_chain();
    let guard = register_test_root(chain.root_pubkey_hash, CloudProvider::Aws);
    let (ak_pubkey, ak_pkcs8) = ephemeral_ak();
    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &ak_pkcs8);
    let cose_doc = test_support::build_nitro_cose_doc(
        &chain.leaf_der,
        std::slice::from_ref(&chain.root_der),
        &nitro_pcrs,
        Some(&ak_pubkey),
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
    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    // SHA-256 (0x000B) instead of SHA-384 (0x000C)
    let pcr_select = vec![(0x000Bu16, vec![0xFF, 0xFF, 0xFF])];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &ak_pkcs8);
    let cose_doc = test_support::build_nitro_cose_doc(
        &chain.leaf_der,
        std::slice::from_ref(&chain.root_der),
        &nitro_pcrs,
        Some(&ak_pubkey),
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
                    expected: 0x000C,
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
    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    // PCR 23 deselected
    let pcr_select = vec![(0x000Cu16, vec![0xFF, 0xFF, 0xFE])];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &ak_pkcs8);
    let cose_doc = test_support::build_nitro_cose_doc(
        &chain.leaf_der,
        std::slice::from_ref(&chain.root_der),
        &nitro_pcrs,
        Some(&ak_pubkey),
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
    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    let pcr_select = vec![(0x000Cu16, vec![0xFF, 0xFF, 0xFF])];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &ak_pkcs8);
    let cose_doc = test_support::build_nitro_cose_doc(
        &chain.leaf_der,
        std::slice::from_ref(&chain.root_der),
        &nitro_pcrs,
        Some(&ak_pubkey),
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
            Err(VerifyError::NoValidAttestation(
                NoValidAttestationReason::MissingNonce
            ))
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
    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    let pcr_select = vec![(0x000Cu16, vec![0xFF, 0xFF, 0xFF])];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &ak_pkcs8);
    let cose_doc = test_support::build_nitro_cose_doc(
        &chain.leaf_der,
        std::slice::from_ref(&chain.root_der),
        &nitro_pcrs,
        Some(&ak_pubkey),
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
    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    let pcr_select = vec![(0x000Cu16, vec![0xFF, 0xFF, 0xFF])];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &ak_pkcs8);
    let cose_doc = test_support::build_nitro_cose_doc(
        &chain.leaf_der,
        std::slice::from_ref(&chain.root_der),
        &BTreeMap::new(), // empty PCRs
        Some(&ak_pubkey),
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

#[test]
fn test_ephemeral_nitro_reject_pcr_missing_from_attestation() {
    let nonce = [0xAA; 32];
    let pcrs = test_support::make_nitro_pcrs();
    let nitro_pcrs = to_nitro_pcr_map(&pcrs);

    let chain = test_support::generate_nitro_chain();
    let guard = register_test_root(chain.root_pubkey_hash, CloudProvider::Aws);
    let (ak_pubkey, ak_pkcs8) = ephemeral_ak();
    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    let pcr_select = vec![(0x000Cu16, vec![0xFF, 0xFF, 0xFF])];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &ak_pkcs8);
    let cose_doc = test_support::build_nitro_cose_doc(
        &chain.leaf_der,
        std::slice::from_ref(&chain.root_der),
        &nitro_pcrs,
        Some(&ak_pubkey),
        Some(&nonce),
        &chain.cose_signing_key,
    );

    // decoded is missing PCR 5 → hits "all 24 PCRs" check
    let mut decoded_pcrs = pcrs.clone();
    decoded_pcrs.remove(&(1, 5));
    let decoded = DecodedAttestationOutput {
        nonce,
        pcrs: decoded_pcrs,
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
                InvalidAttestReason::MissingPcr { .. }
            ))
        ),
        "Expected missing PCR error, got: {:?}",
        result
    );
}

#[test]
fn test_ephemeral_nitro_reject_pcr_not_signed() {
    let nonce = [0xAA; 32];
    let pcrs = test_support::make_nitro_pcrs();

    // COSE has only 23 PCRs (missing PCR 0)
    let mut nitro_pcrs = to_nitro_pcr_map(&pcrs);
    nitro_pcrs.remove(&0);

    let chain = test_support::generate_nitro_chain();
    let guard = register_test_root(chain.root_pubkey_hash, CloudProvider::Aws);
    let (ak_pubkey, ak_pkcs8) = ephemeral_ak();
    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    let pcr_select = vec![(0x000Cu16, vec![0xFF, 0xFF, 0xFF])];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &ak_pkcs8);
    let cose_doc = test_support::build_nitro_cose_doc(
        &chain.leaf_der,
        std::slice::from_ref(&chain.root_der),
        &nitro_pcrs,
        Some(&ak_pubkey),
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

    // COSE has different value for PCR 0
    let mut nitro_pcrs = to_nitro_pcr_map(&pcrs);
    nitro_pcrs.insert(0, vec![0xFF; 48]);

    let chain = test_support::generate_nitro_chain();
    let guard = register_test_root(chain.root_pubkey_hash, CloudProvider::Aws);
    let (ak_pubkey, ak_pkcs8) = ephemeral_ak();
    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    let pcr_select = vec![(0x000Cu16, vec![0xFF, 0xFF, 0xFF])];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &ak_pkcs8);
    let cose_doc = test_support::build_nitro_cose_doc(
        &chain.leaf_der,
        std::slice::from_ref(&chain.root_der),
        &nitro_pcrs,
        Some(&ak_pubkey),
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
    let pcr_select = vec![(0x000Cu16, vec![0xFF, 0xFF, 0xFF])];
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
            Err(VerifyError::NoValidAttestation(
                NoValidAttestationReason::MissingPublicKey
            ))
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
    let pcr_select = vec![(0x000Cu16, vec![0xFF, 0xFF, 0xFF])];
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
                SignatureInvalidReason::AkNitroBindingMismatch
            ))
        ),
        "Expected AK mismatch error, got: {:?}",
        result
    );
}

#[test]
fn test_ephemeral_nitro_reject_wrong_provider_root() {
    // Build a valid Nitro attestation but register the root as GCP.
    // The COSE signature and cert chain will validate, but the provider
    // check should reject it: "requires AWS root CA, got Gcp".
    let nonce = [0xAA; 32];
    let pcrs = test_support::make_nitro_pcrs();
    let nitro_pcrs = to_nitro_pcr_map(&pcrs);

    let chain = test_support::generate_nitro_chain();
    // Register as GCP instead of AWS
    let guard = register_test_root(chain.root_pubkey_hash, CloudProvider::Gcp);
    let (ak_pubkey, ak_pkcs8) = ephemeral_ak();
    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    let pcr_select = vec![(0x000Cu16, vec![0xFF, 0xFF, 0xFF])];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &ak_pkcs8);
    let cose_doc = test_support::build_nitro_cose_doc(
        &chain.leaf_der,
        std::slice::from_ref(&chain.root_der),
        &nitro_pcrs,
        Some(&ak_pubkey),
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
    // Build a valid Nitro attestation but don't register the root at all.
    // The COSE signature and cert chain validate, but provider_from_hash
    // returns None → "Unknown root CA".
    let nonce = [0xAA; 32];
    let pcrs = test_support::make_nitro_pcrs();
    let nitro_pcrs = to_nitro_pcr_map(&pcrs);

    let chain = test_support::generate_nitro_chain();
    // Deliberately NOT registering the root
    let (ak_pubkey, ak_pkcs8) = ephemeral_ak();
    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    let pcr_select = vec![(0x000Cu16, vec![0xFF, 0xFF, 0xFF])];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &ak_pkcs8);
    let cose_doc = test_support::build_nitro_cose_doc(
        &chain.leaf_der,
        std::slice::from_ref(&chain.root_der),
        &nitro_pcrs,
        Some(&ak_pubkey),
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
    // Build a COSE Sign1 whose payload is a CBOR array, not a map.
    // PayloadNotMap fires before signature verification, so the signature
    // and other fields don't need to be valid.
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
        ak_pubkey: [0x04; 65],
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
    // Build a valid COSE doc then re-encode it with a truncated signature.
    // The flow: parse COSE → extract payload map → extract cert/cabundle →
    // parse certs → verify_cose_signature → check sig length → error.
    use coset::{CborSerializable, CoseSign1};

    let nonce = [0xAA; 32];
    let pcrs = test_support::make_nitro_pcrs();
    let nitro_pcrs = to_nitro_pcr_map(&pcrs);

    let chain = test_support::generate_nitro_chain();
    let guard = register_test_root(chain.root_pubkey_hash, CloudProvider::Aws);
    let (ak_pubkey, ak_pkcs8) = ephemeral_ak();

    // Build a valid COSE doc first
    let valid_doc = test_support::build_nitro_cose_doc(
        &chain.leaf_der,
        std::slice::from_ref(&chain.root_der),
        &nitro_pcrs,
        Some(&ak_pubkey),
        Some(&nonce),
        &chain.cose_signing_key,
    );

    // Re-encode with a 64-byte signature instead of 96
    let mut cose = CoseSign1::from_slice(&valid_doc).unwrap();
    cose.signature = vec![0u8; 64];
    let bad_doc = cose.to_vec().unwrap();

    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    let pcr_select = vec![(0x000Cu16, vec![0xFF, 0xFF, 0xFF])];
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
