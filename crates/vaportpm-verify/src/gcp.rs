// SPDX-License-Identifier: MIT OR Apache-2.0

//! GCP Shielded VM attestation verification

use std::collections::BTreeMap;

use der::Decode;
use pki_types::UnixTime;
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

use crate::error::VerifyError;
use crate::tpm::{parse_quote_attest, verify_ecdsa_p256, TpmQuoteInfo};
use crate::x509::{extract_public_key, validate_tpm_cert_chain};
use crate::{roots, DecodedAttestationOutput, VerificationResult};

/// Verify GCP Shielded VM attestation
///
/// This verification path:
/// 1. Parses TPM2_Quote attestation to extract PCR digest and nonce
/// 2. Validates AK certificate chain to Google's root CA
/// 3. Verifies Quote signature with AK public key from certificate
/// 4. Verifies PCR digest matches claimed PCR values
///
/// All inputs should be pre-decoded binary data (DER certs, raw bytes).
pub fn verify_gcp_decoded(
    decoded: &DecodedAttestationOutput,
    cert_chain_der: &[Vec<u8>],
    time: UnixTime,
) -> Result<VerificationResult, VerifyError> {
    // Parse DER → Certificate (still needed for chain validation)
    let certs: Vec<Certificate> = cert_chain_der
        .iter()
        .map(|der| {
            Certificate::from_der(der)
                .map_err(|e| VerifyError::CertificateParse(format!("Invalid DER cert: {}", e)))
        })
        .collect::<Result<_, _>>()?;

    if certs.is_empty() {
        return Err(VerifyError::ChainValidation(
            "Empty certificate chain".into(),
        ));
    }

    // Parse TPM2_Quote attestation
    let quote_info = parse_quote_attest(&decoded.quote_attest)?;

    // Verify nonce matches Quote
    if decoded.nonce != quote_info.nonce.as_slice() {
        return Err(VerifyError::InvalidAttest(format!(
            "Nonce does not match Quote. Expected: {}, Quote: {}",
            hex::encode(decoded.nonce),
            hex::encode(&quote_info.nonce)
        )));
    }

    // Validate AK certificate chain to GCP root
    let chain_result = validate_tpm_cert_chain(&certs, time)?;

    // Extract AK public key from leaf certificate for comparison
    let ak_pubkey_from_cert = extract_public_key(&certs[0])?;

    // Verify the AK public key matches the one in the decoded input
    if ak_pubkey_from_cert != decoded.ak_pubkey {
        return Err(VerifyError::SignatureInvalid(format!(
            "AK public key mismatch: cert has {}, decoded has {}",
            hex::encode(&ak_pubkey_from_cert),
            hex::encode(decoded.ak_pubkey)
        )));
    }

    // Verify Quote signature with AK public key
    verify_ecdsa_p256(
        &decoded.quote_attest,
        &decoded.quote_signature,
        &decoded.ak_pubkey,
    )?;

    // Verify we have SHA-256 PCRs (algorithm ID 0)
    let has_sha256_pcrs = decoded.pcrs.keys().any(|(alg_id, _)| *alg_id == 0);
    if !has_sha256_pcrs {
        return Err(VerifyError::InvalidAttest(
            "Missing SHA-256 PCRs - required for GCP attestation".into(),
        ));
    }

    // Verify PCR digest matches claimed PCR values
    verify_pcr_digest_matches(&quote_info, &decoded.pcrs)?;

    // Verify root is a known GCP root
    let provider = roots::provider_from_hash(&chain_result.root_pubkey_hash).ok_or_else(|| {
        VerifyError::ChainValidation(format!(
            "Unknown root CA: {}. Only known cloud provider roots are trusted.",
            hex::encode(chain_result.root_pubkey_hash)
        ))
    })?;

    // Convert nonce to fixed-size array
    let nonce: [u8; 32] = quote_info
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| VerifyError::InvalidAttest("nonce is not 32 bytes".into()))?;

    Ok(VerificationResult {
        nonce,
        provider,
        pcrs: decoded.pcrs.clone(),
        verified_at: time.as_secs(),
    })
}

/// Verify that the PCR digest in a Quote matches the claimed PCR values
fn verify_pcr_digest_matches(
    quote_info: &TpmQuoteInfo,
    pcrs: &BTreeMap<(u8, u8), Vec<u8>>,
) -> Result<(), VerifyError> {
    // The PCR digest is SHA-256(concatenation of selected PCR values in order)
    // The selection order is determined by the pcr_select field

    // Build the expected digest by concatenating PCR values in selection order
    let mut hasher = Sha256::new();

    for (alg, bitmap) in &quote_info.pcr_select {
        // Only handle SHA-256 PCRs for now
        if *alg != 0x000B {
            // TPM_ALG_SHA256
            continue;
        }

        // Iterate through bitmap to find selected PCRs
        for (byte_idx, byte_val) in bitmap.iter().enumerate() {
            for bit_idx in 0..8 {
                if byte_val & (1 << bit_idx) != 0 {
                    let pcr_idx = (byte_idx * 8 + bit_idx) as u8;
                    // Look up by (algorithm_id=0 for SHA-256, pcr_index)
                    if let Some(pcr_value) = pcrs.get(&(0, pcr_idx)) {
                        hasher.update(pcr_value);
                    } else {
                        return Err(VerifyError::InvalidAttest(format!(
                            "PCR {} selected in Quote but not present in attestation",
                            pcr_idx
                        )));
                    }
                }
            }
        }
    }

    let computed_digest = hasher.finalize();
    if computed_digest.as_ref() != quote_info.pcr_digest {
        return Err(VerifyError::InvalidAttest(format!(
            "PCR digest mismatch. Quote digest: {}, Computed from PCRs: {}",
            hex::encode(&quote_info.pcr_digest),
            hex::encode(computed_digest)
        )));
    }

    Ok(())
}
