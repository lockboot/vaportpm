// SPDX-License-Identifier: MIT OR Apache-2.0

//! Ephemeral key tests for the GCP verification path.
//!
//! These tests build complete, cryptographically valid attestations from scratch
//! using ephemeral keys, then introduce specific inconsistencies to test error
//! paths through the public API (`verify_decoded_attestation_output`).

use crate::error::{
    ChainValidationReason, InvalidAttestReason, SignatureInvalidReason, VerifyError,
};
use crate::pcr::{P256PublicKey, PcrAlgorithm};
use crate::roots::register_test_root;
use crate::test_support;
use crate::{
    verify_decoded_attestation_output, CloudProvider, DecodedAttestationOutput,
    DecodedPlatformAttestation,
};

#[test]
fn test_ephemeral_gcp_happy_path() {
    let nonce = [0xBB; 32];
    let pcrs = test_support::make_gcp_pcrs();
    let (decoded, time, _guard) = test_support::build_valid_gcp(&nonce, &pcrs);

    let result = verify_decoded_attestation_output(&decoded, time);
    assert!(result.is_ok(), "Happy path should succeed: {:?}", result);

    let vr = result.unwrap();
    assert_eq!(vr.provider, CloudProvider::Gcp);
    assert_eq!(vr.nonce, nonce);
}

#[test]
fn test_ephemeral_gcp_reject_multiple_pcr_banks() {
    let nonce = [0xBB; 32];
    let pcrs = test_support::make_gcp_pcrs();

    let chain = test_support::generate_gcp_chain();
    let guard = register_test_root(chain.root_pubkey_hash, CloudProvider::Gcp);

    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    // TWO banks in pcr_select
    let pcr_select = vec![
        (PcrAlgorithm::Sha256 as u16, vec![0xFF, 0xFF, 0xFF]),
        (PcrAlgorithm::Sha384 as u16, vec![0xFF, 0xFF, 0xFF]),
    ];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &chain.ak_signing_key);

    let decoded = DecodedAttestationOutput {
        nonce,
        pcrs,
        ak_pubkey: chain.ak_pubkey,
        quote_attest,
        quote_signature: quote_sig,
        platform: DecodedPlatformAttestation::Gcp {
            cert_chain_der: vec![chain.leaf_der, chain.root_der],
        },
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
fn test_ephemeral_gcp_reject_wrong_pcr_algorithm() {
    let nonce = [0xBB; 32];
    let pcrs = test_support::make_gcp_pcrs();

    let chain = test_support::generate_gcp_chain();
    let guard = register_test_root(chain.root_pubkey_hash, CloudProvider::Gcp);

    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    // SHA-384 instead of SHA-256
    let pcr_select = vec![(PcrAlgorithm::Sha384 as u16, vec![0xFF, 0xFF, 0xFF])];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &chain.ak_signing_key);

    let decoded = DecodedAttestationOutput {
        nonce,
        pcrs,
        ak_pubkey: chain.ak_pubkey,
        quote_attest,
        quote_signature: quote_sig,
        platform: DecodedPlatformAttestation::Gcp {
            cert_chain_der: vec![chain.leaf_der, chain.root_der],
        },
    };

    let result = verify_decoded_attestation_output(&decoded, test_support::ephemeral_time());
    drop(guard);
    assert!(
        matches!(
            result,
            Err(VerifyError::InvalidAttest(
                InvalidAttestReason::WrongPcrAlgorithm {
                    expected: PcrAlgorithm::Sha256,
                    got: 0x000C,
                }
            ))
        ),
        "Expected wrong algorithm error, got: {:?}",
        result
    );
}

#[test]
fn test_ephemeral_gcp_reject_nonce_mismatch() {
    let nonce = [0xBB; 32];
    let pcrs = test_support::make_gcp_pcrs();
    let (mut decoded, time, _guard) = test_support::build_valid_gcp(&nonce, &pcrs);

    // Change the decoded nonce
    decoded.nonce = [0xCC; 32];

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
fn test_ephemeral_gcp_reject_ak_pubkey_mismatch() {
    let nonce = [0xBB; 32];
    let pcrs = test_support::make_gcp_pcrs();
    let (mut decoded, time, _guard) = test_support::build_valid_gcp(&nonce, &pcrs);

    // Change the AK pubkey — doesn't match the leaf cert
    decoded.ak_pubkey = P256PublicKey {
        x: [0x04; 32],
        y: [0x04; 32],
    };

    let result = verify_decoded_attestation_output(&decoded, time);
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
fn test_ephemeral_gcp_reject_wrong_pcr_bank_algorithm() {
    // Construct a valid Nitro (SHA-384) PcrBank and pass it to GCP verification
    // This should be rejected by the algorithm check.
    let nonce = [0xBB; 32];
    let wrong_pcrs = test_support::make_nitro_pcrs(); // SHA-384
    let gcp_pcrs = test_support::make_gcp_pcrs(); // SHA-256

    let (mut decoded, time, _guard) = test_support::build_valid_gcp(&nonce, &gcp_pcrs);
    decoded.pcrs = wrong_pcrs;

    let result = verify_decoded_attestation_output(&decoded, time);
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
        "Expected WrongPcrBankAlgorithm error, got: {:?}",
        result
    );
}

#[test]
fn test_ephemeral_gcp_reject_partial_pcr_bitmap() {
    let nonce = [0xBB; 32];
    let pcrs = test_support::make_gcp_pcrs();

    let chain = test_support::generate_gcp_chain();
    let guard = register_test_root(chain.root_pubkey_hash, CloudProvider::Gcp);

    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    // Correct algorithm but partial bitmap — only first 16 PCRs selected
    let pcr_select = vec![(PcrAlgorithm::Sha256 as u16, vec![0xFF, 0xFF, 0x00])];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &chain.ak_signing_key);

    let decoded = DecodedAttestationOutput {
        nonce,
        pcrs,
        ak_pubkey: chain.ak_pubkey,
        quote_attest,
        quote_signature: quote_sig,
        platform: DecodedPlatformAttestation::Gcp {
            cert_chain_der: vec![chain.leaf_der, chain.root_der],
        },
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
        "Expected PartialPcrBitmap error, got: {:?}",
        result
    );
}

#[test]
fn test_ephemeral_gcp_reject_wrong_provider_root() {
    // Build a valid GCP attestation but register the root as AWS.
    // The cert chain will validate, but the provider check should
    // reject it: "requires GCP root CA, got Aws".
    let nonce = [0xBB; 32];
    let pcrs = test_support::make_gcp_pcrs();

    let chain = test_support::generate_gcp_chain();
    // Register as AWS instead of GCP
    let guard = register_test_root(chain.root_pubkey_hash, CloudProvider::Aws);

    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    let pcr_select = vec![(PcrAlgorithm::Sha256 as u16, vec![0xFF, 0xFF, 0xFF])];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_sig = test_support::sign_tpm_quote(&quote_attest, &chain.ak_signing_key);

    let decoded = DecodedAttestationOutput {
        nonce,
        pcrs,
        ak_pubkey: chain.ak_pubkey,
        quote_attest,
        quote_signature: quote_sig,
        platform: DecodedPlatformAttestation::Gcp {
            cert_chain_der: vec![chain.leaf_der, chain.root_der],
        },
    };

    let result = verify_decoded_attestation_output(&decoded, test_support::ephemeral_time());
    drop(guard);
    assert!(
        matches!(
            result,
            Err(VerifyError::ChainValidation(
                ChainValidationReason::WrongProvider {
                    expected: CloudProvider::Gcp,
                    got: CloudProvider::Aws,
                }
            ))
        ),
        "Expected wrong provider error, got: {:?}",
        result
    );
}
