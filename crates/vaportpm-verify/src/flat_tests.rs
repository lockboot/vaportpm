// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for `flat.rs` — the flat binary serialization format used for zkVM input.
//!
//! Strategy: build valid `DecodedAttestationOutput` via `test_support`, serialize
//! with `flat::to_bytes()`, then either verify roundtrip or mutate bytes to trigger
//! specific `from_bytes` error paths.

use crate::error::InvalidAttestReason;
use crate::flat::{self, FlatHeader, HEADER_SIZE};
use crate::pcr::{PcrAlgorithm, PCR_COUNT};
use crate::test_support;
use crate::{DecodedPlatformAttestation, VerifyError};

// ============================================================================
// Field offsets in the repr(C, packed) FlatHeader
// ============================================================================

/// ak_pubkey: [u8; 65] at offset 32
const OFF_AK_PUBKEY: usize = 32;
/// platform_type: u8 at offset 97
const OFF_PLATFORM_TYPE: usize = 97;
/// quote_attest_len: u16 at offset 98
const OFF_QUOTE_ATTEST_LEN: usize = 98;
/// quote_signature_len: u16 at offset 100
const OFF_QUOTE_SIGNATURE_LEN: usize = 100;
/// pcr_algorithm: u16 at offset 102
const OFF_PCR_ALGORITHM: usize = 102;
/// platform_data_len: u16 at offset 104
const OFF_PLATFORM_DATA_LEN: usize = 104;

// ============================================================================
// Helpers
// ============================================================================

fn valid_gcp_bytes() -> Vec<u8> {
    let nonce = [0xAA; 32];
    let pcrs = test_support::make_gcp_pcrs();
    let (decoded, _, _guard) = test_support::build_valid_gcp(&nonce, &pcrs);
    flat::to_bytes(&decoded)
}

/// Patch a little-endian u16 at the given offset in `data`.
fn patch_u16_le(data: &mut [u8], offset: usize, value: u16) {
    data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

// ============================================================================
// Roundtrip tests (2)
// ============================================================================

#[test]
fn test_roundtrip_gcp() {
    let nonce = [0xAA; 32];
    let pcrs = test_support::make_gcp_pcrs();
    let (original, _, _guard) = test_support::build_valid_gcp(&nonce, &pcrs);

    let bytes = flat::to_bytes(&original);
    let restored = flat::from_bytes(&bytes).expect("roundtrip should succeed");

    // Nonce
    assert_eq!(restored.nonce, original.nonce);

    // AK pubkey
    assert_eq!(
        restored.ak_pubkey.to_sec1_uncompressed(),
        original.ak_pubkey.to_sec1_uncompressed()
    );

    // PCRs — algorithm and all 24 values
    assert_eq!(restored.pcrs.algorithm(), PcrAlgorithm::Sha256);
    for i in 0..PCR_COUNT {
        assert_eq!(
            restored.pcrs.get(i),
            original.pcrs.get(i),
            "PCR {i} mismatch"
        );
    }

    // Quote attest & signature
    assert_eq!(restored.quote_attest, original.quote_attest);
    assert_eq!(restored.quote_signature, original.quote_signature);

    // Platform — GCP cert chain
    match (&restored.platform, &original.platform) {
        (
            DecodedPlatformAttestation::Gcp {
                cert_chain_der: restored_certs,
            },
            DecodedPlatformAttestation::Gcp {
                cert_chain_der: original_certs,
            },
        ) => {
            assert_eq!(restored_certs.len(), original_certs.len());
            for (i, (r, o)) in restored_certs.iter().zip(original_certs.iter()).enumerate() {
                assert_eq!(r, o, "cert {i} mismatch");
            }
        }
        _ => panic!("expected GCP platform"),
    }
}

#[test]
fn test_roundtrip_nitro() {
    let nonce = [0xBB; 32];
    let pcrs = test_support::make_nitro_pcrs();
    let (original, _, _guard) = test_support::build_valid_nitro(&nonce, &pcrs);

    let bytes = flat::to_bytes(&original);
    let restored = flat::from_bytes(&bytes).expect("roundtrip should succeed");

    // Nonce
    assert_eq!(restored.nonce, original.nonce);

    // AK pubkey
    assert_eq!(
        restored.ak_pubkey.to_sec1_uncompressed(),
        original.ak_pubkey.to_sec1_uncompressed()
    );

    // PCRs — algorithm and all 24 values
    assert_eq!(restored.pcrs.algorithm(), PcrAlgorithm::Sha384);
    for i in 0..PCR_COUNT {
        assert_eq!(
            restored.pcrs.get(i),
            original.pcrs.get(i),
            "PCR {i} mismatch"
        );
    }

    // Quote attest & signature
    assert_eq!(restored.quote_attest, original.quote_attest);
    assert_eq!(restored.quote_signature, original.quote_signature);

    // Platform — Nitro COSE document
    match (&restored.platform, &original.platform) {
        (
            DecodedPlatformAttestation::Nitro {
                document: restored_doc,
            },
            DecodedPlatformAttestation::Nitro {
                document: original_doc,
            },
        ) => {
            assert_eq!(restored_doc, original_doc);
        }
        _ => panic!("expected Nitro platform"),
    }
}

// ============================================================================
// Header size (1)
// ============================================================================

#[test]
fn test_header_size() {
    assert_eq!(
        HEADER_SIZE, 106,
        "FlatHeader size changed — update flat format and tests"
    );
    assert_eq!(HEADER_SIZE, std::mem::size_of::<FlatHeader>());
}

// ============================================================================
// Input too short (2)
// ============================================================================

#[test]
fn test_reject_empty_input() {
    let err = flat::from_bytes(&[]).unwrap_err();
    assert!(
        matches!(
            err,
            VerifyError::InvalidAttest(InvalidAttestReason::InputTooShort {
                actual: 0,
                minimum: 106,
            })
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_reject_truncated_header() {
    let err = flat::from_bytes(&[0u8; 105]).unwrap_err();
    assert!(
        matches!(
            err,
            VerifyError::InvalidAttest(InvalidAttestReason::InputTooShort {
                actual: 105,
                minimum: 106,
            })
        ),
        "unexpected error: {err:?}"
    );
}

// ============================================================================
// Invalid header fields (2)
// ============================================================================

#[test]
fn test_reject_unknown_pcr_algorithm() {
    let mut data = valid_gcp_bytes();
    patch_u16_le(&mut data, OFF_PCR_ALGORITHM, 0x9999);
    let err = flat::from_bytes(&data).unwrap_err();
    assert!(
        matches!(
            err,
            VerifyError::InvalidAttest(InvalidAttestReason::UnknownPcrAlgorithm { alg_id: 0x9999 })
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_reject_unknown_platform_type() {
    let mut data = valid_gcp_bytes();
    data[OFF_PLATFORM_TYPE] = 0xFF;
    let err = flat::from_bytes(&data).unwrap_err();
    assert!(
        matches!(
            err,
            VerifyError::InvalidAttest(InvalidAttestReason::UnknownPlatformType {
                platform_type: 0xFF
            })
        ),
        "unexpected error: {err:?}"
    );
}

// ============================================================================
// Truncation at each field boundary (4)
// ============================================================================

#[test]
fn test_reject_truncated_pcr_data() {
    let data = valid_gcp_bytes();
    // Truncate 1 byte into the PCR region
    let truncated = &data[..HEADER_SIZE + 1];
    let err = flat::from_bytes(truncated).unwrap_err();
    assert!(
        matches!(
            err,
            VerifyError::InvalidAttest(InvalidAttestReason::FlatTruncated { field: "PCR data" })
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_reject_truncated_quote_attest() {
    let data = valid_gcp_bytes();
    // PCR data for SHA-256: 24 * 32 = 768 bytes. Truncate 1 byte into quote_attest.
    let pcr_end = HEADER_SIZE + PCR_COUNT * PcrAlgorithm::Sha256.digest_len();
    let truncated = &data[..pcr_end + 1];
    let err = flat::from_bytes(truncated).unwrap_err();
    assert!(
        matches!(
            err,
            VerifyError::InvalidAttest(InvalidAttestReason::FlatTruncated {
                field: "quote_attest"
            })
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_reject_truncated_quote_signature() {
    let data = valid_gcp_bytes();
    // Read quote_attest_len from the header to find where quote_signature starts
    let quote_attest_len = u16::from_le_bytes(
        data[OFF_QUOTE_ATTEST_LEN..OFF_QUOTE_ATTEST_LEN + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    let pcr_end = HEADER_SIZE + PCR_COUNT * PcrAlgorithm::Sha256.digest_len();
    let sig_start = pcr_end + quote_attest_len;
    // Truncate 1 byte into quote_signature
    let truncated = &data[..sig_start + 1];
    let err = flat::from_bytes(truncated).unwrap_err();
    assert!(
        matches!(
            err,
            VerifyError::InvalidAttest(InvalidAttestReason::FlatTruncated {
                field: "quote_signature"
            })
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_reject_truncated_platform_data() {
    let data = valid_gcp_bytes();
    let quote_attest_len = u16::from_le_bytes(
        data[OFF_QUOTE_ATTEST_LEN..OFF_QUOTE_ATTEST_LEN + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    let quote_sig_len = u16::from_le_bytes(
        data[OFF_QUOTE_SIGNATURE_LEN..OFF_QUOTE_SIGNATURE_LEN + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    let pcr_end = HEADER_SIZE + PCR_COUNT * PcrAlgorithm::Sha256.digest_len();
    let platform_start = pcr_end + quote_attest_len + quote_sig_len;
    // Truncate 1 byte into platform data
    let truncated = &data[..platform_start + 1];
    let err = flat::from_bytes(truncated).unwrap_err();
    assert!(
        matches!(
            err,
            VerifyError::InvalidAttest(InvalidAttestReason::FlatTruncated {
                field: "platform data"
            })
        ),
        "unexpected error: {err:?}"
    );
}

// ============================================================================
// GCP platform data parsing (3)
// ============================================================================

#[test]
fn test_reject_gcp_empty_platform_data() {
    let mut data = valid_gcp_bytes();
    // Find where platform data starts and set its length to 0
    let quote_attest_len = u16::from_le_bytes(
        data[OFF_QUOTE_ATTEST_LEN..OFF_QUOTE_ATTEST_LEN + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    let quote_sig_len = u16::from_le_bytes(
        data[OFF_QUOTE_SIGNATURE_LEN..OFF_QUOTE_SIGNATURE_LEN + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    let pcr_end = HEADER_SIZE + PCR_COUNT * PcrAlgorithm::Sha256.digest_len();
    let platform_start = pcr_end + quote_attest_len + quote_sig_len;

    // Set platform_data_len = 0 and truncate
    patch_u16_le(&mut data, OFF_PLATFORM_DATA_LEN, 0);
    data.truncate(platform_start);

    let err = flat::from_bytes(&data).unwrap_err();
    assert!(
        matches!(
            err,
            VerifyError::InvalidAttest(InvalidAttestReason::FlatTruncated {
                field: "GCP platform data"
            })
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_reject_gcp_truncated_cert_lengths() {
    let mut data = valid_gcp_bytes();
    let quote_attest_len = u16::from_le_bytes(
        data[OFF_QUOTE_ATTEST_LEN..OFF_QUOTE_ATTEST_LEN + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    let quote_sig_len = u16::from_le_bytes(
        data[OFF_QUOTE_SIGNATURE_LEN..OFF_QUOTE_SIGNATURE_LEN + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    let pcr_end = HEADER_SIZE + PCR_COUNT * PcrAlgorithm::Sha256.digest_len();
    let platform_start = pcr_end + quote_attest_len + quote_sig_len;

    // Build minimal platform data: cert_count=2 but only 2 bytes (space for 1 length)
    // Format: [cert_count: u8, len0: u16_le] — missing len1
    let platform_data = vec![
        2u8, // cert_count = 2
        0x10, 0x00, // len[0] = 16
              // len[1] is missing
    ];
    let platform_len = platform_data.len() as u16;
    patch_u16_le(&mut data, OFF_PLATFORM_DATA_LEN, platform_len);
    data.truncate(platform_start);
    data.extend_from_slice(&platform_data);

    let err = flat::from_bytes(&data).unwrap_err();
    assert!(
        matches!(
            err,
            VerifyError::InvalidAttest(InvalidAttestReason::FlatTruncated {
                field: "cert length"
            })
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_reject_gcp_truncated_cert_data() {
    let mut data = valid_gcp_bytes();
    let quote_attest_len = u16::from_le_bytes(
        data[OFF_QUOTE_ATTEST_LEN..OFF_QUOTE_ATTEST_LEN + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    let quote_sig_len = u16::from_le_bytes(
        data[OFF_QUOTE_SIGNATURE_LEN..OFF_QUOTE_SIGNATURE_LEN + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    let pcr_end = HEADER_SIZE + PCR_COUNT * PcrAlgorithm::Sha256.digest_len();
    let platform_start = pcr_end + quote_attest_len + quote_sig_len;

    // Build platform data: 1 cert with claimed length 100, but only 10 bytes of data
    let mut platform_data = Vec::new();
    platform_data.push(1u8); // cert_count = 1
    platform_data.extend_from_slice(&100u16.to_le_bytes()); // cert len = 100
    platform_data.extend_from_slice(&[0xDE; 10]); // only 10 bytes of cert data

    let platform_len = platform_data.len() as u16;
    patch_u16_le(&mut data, OFF_PLATFORM_DATA_LEN, platform_len);
    data.truncate(platform_start);
    data.extend_from_slice(&platform_data);

    let err = flat::from_bytes(&data).unwrap_err();
    assert!(
        matches!(
            err,
            VerifyError::InvalidAttest(InvalidAttestReason::FlatTruncated { field: "cert data" })
        ),
        "unexpected error: {err:?}"
    );
}

// ============================================================================
// AK pubkey validation (1)
// ============================================================================

#[test]
fn test_reject_invalid_ak_pubkey() {
    let mut data = valid_gcp_bytes();
    // Patch first byte of ak_pubkey from 0x04 (uncompressed) to 0x02 (compressed)
    data[OFF_AK_PUBKEY] = 0x02;
    let err = flat::from_bytes(&data).unwrap_err();
    assert!(
        matches!(
            err,
            VerifyError::InvalidAttest(InvalidAttestReason::InvalidAkPubkeyFormat)
        ),
        "unexpected error: {err:?}"
    );
}

// ============================================================================
// Multi-cert roundtrip (1)
// ============================================================================

#[test]
fn test_roundtrip_gcp_multiple_certs() {
    let nonce = [0xCC; 32];
    let pcrs = test_support::make_gcp_pcrs();
    let chain = test_support::generate_gcp_chain();

    // Build a DecodedAttestationOutput with 3 certs (leaf + 2 fake intermediates)
    let pcr_digest = test_support::compute_pcr_digest(&pcrs);
    let pcr_select = vec![(PcrAlgorithm::Sha256 as u16, vec![0xFF, 0xFF, 0xFF])];
    let quote_attest = test_support::build_tpm_quote_attest(&nonce, &pcr_select, &pcr_digest);
    let quote_signature = test_support::sign_tpm_quote(&quote_attest, &chain.ak_signing_key);

    let fake_intermediate_1: Vec<u8> = [0x30, 0x82, 0x01, 0x00]
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0xAA, 256))
        .collect();
    let fake_intermediate_2: Vec<u8> = [0x30, 0x82, 0x02, 0x00]
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0xBB, 512))
        .collect();

    let original = crate::DecodedAttestationOutput {
        nonce,
        pcrs: pcrs.clone(),
        ak_pubkey: chain.ak_pubkey,
        quote_attest,
        quote_signature,
        platform: DecodedPlatformAttestation::Gcp {
            cert_chain_der: vec![
                chain.leaf_der.clone(),
                fake_intermediate_1.clone(),
                fake_intermediate_2.clone(),
            ],
        },
    };

    let bytes = flat::to_bytes(&original);
    let restored = flat::from_bytes(&bytes).expect("multi-cert roundtrip should succeed");

    match &restored.platform {
        DecodedPlatformAttestation::Gcp { cert_chain_der } => {
            assert_eq!(cert_chain_der.len(), 3, "expected 3 certs");
            assert_eq!(cert_chain_der[0], chain.leaf_der);
            assert_eq!(cert_chain_der[1], fake_intermediate_1);
            assert_eq!(cert_chain_der[2], fake_intermediate_2);
        }
        _ => panic!("expected GCP platform"),
    }
}
