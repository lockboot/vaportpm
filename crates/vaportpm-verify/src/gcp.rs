// SPDX-License-Identifier: MIT OR Apache-2.0

//! GCP Shielded VM attestation verification

use std::collections::BTreeMap;

use pki_types::UnixTime;
use sha2::{Digest, Sha256};

use crate::error::VerifyError;
use crate::tpm::{parse_quote_attest, verify_ecdsa_p256, TpmQuoteInfo};
use crate::x509::{extract_public_key, parse_cert_chain_pem, validate_tpm_cert_chain};
use crate::{roots, VerificationResult};

use vaportpm_attest::a9n::{AttestationOutput, GcpAttestationData};

/// Verify GCP Shielded VM attestation
///
/// This verification path:
/// 1. Parses TPM2_Quote attestation to extract PCR digest and nonce
/// 2. Validates AK certificate chain to Google's root CA
/// 3. Verifies Quote signature with AK public key from certificate
/// 4. Verifies PCR digest matches claimed PCR values
pub fn verify_gcp_attestation(
    output: &AttestationOutput,
    gcp: &GcpAttestationData,
    time: UnixTime,
) -> Result<VerificationResult, VerifyError> {
    // Get TPM attestation (contains Quote data and signature)
    let (_, tpm_attestation) = output
        .attestation
        .tpm
        .iter()
        .next()
        .ok_or_else(|| VerifyError::NoValidAttestation("Missing TPM attestation".into()))?;

    // Parse TPM2_Quote attestation (type = QUOTE, not CERTIFY)
    let quote_data = hex::decode(&tpm_attestation.attest_data)?;
    let quote_info = parse_quote_attest(&quote_data)?;

    // Verify top-level nonce matches nonce in Quote (prevents tampering)
    let nonce_from_field = hex::decode(&output.nonce)?;
    if nonce_from_field != quote_info.nonce {
        return Err(VerifyError::InvalidAttest(format!(
            "Nonce field does not match nonce in Quote. \
             Field: {}, Quote: {}",
            output.nonce,
            hex::encode(&quote_info.nonce)
        )));
    }

    // Validate AK certificate chain to GCP root
    let chain_result = validate_tpm_cert_chain(&parse_cert_chain_pem(&gcp.ak_cert_chain)?, time)?;

    // Extract AK public key from leaf certificate
    let certs = parse_cert_chain_pem(&gcp.ak_cert_chain)?;
    let ak_pubkey = extract_public_key(&certs[0])?;

    // Verify Quote signature with AK public key from certificate
    let signature = hex::decode(&tpm_attestation.signature)?;
    verify_ecdsa_p256(&quote_data, &signature, &ak_pubkey)?;

    // Verify PCR digest matches claimed PCR values
    // The Quote contains a digest of the selected PCRs - this MUST be verified
    let pcrs = output.pcrs.get("sha256").ok_or_else(|| {
        VerifyError::InvalidAttest("Missing SHA-256 PCRs - required for GCP attestation".into())
    })?;
    if pcrs.is_empty() {
        return Err(VerifyError::InvalidAttest(
            "SHA-256 PCRs map is empty - at least one PCR required".into(),
        ));
    }
    verify_pcr_digest_matches(&quote_info, pcrs)?;

    // Verify root is a known GCP root - fail if not recognized
    let provider = roots::provider_from_hash(&chain_result.root_pubkey_hash).ok_or_else(|| {
        VerifyError::ChainValidation(format!(
            "Unknown root CA: {}. Only known cloud provider roots are trusted.",
            chain_result.root_pubkey_hash
        ))
    })?;

    Ok(VerificationResult {
        nonce: hex::encode(&quote_info.nonce),
        provider,
        pcrs: pcrs.clone(),
        root_pubkey_hash: chain_result.root_pubkey_hash,
    })
}

/// Verify that the PCR digest in a Quote matches the claimed PCR values
fn verify_pcr_digest_matches(
    quote_info: &TpmQuoteInfo,
    pcrs: &BTreeMap<u8, String>,
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
                    if let Some(pcr_value_hex) = pcrs.get(&pcr_idx) {
                        let pcr_value = hex::decode(pcr_value_hex).map_err(|e| {
                            VerifyError::InvalidAttest(format!(
                                "Invalid PCR {} hex value: {}",
                                pcr_idx, e
                            ))
                        })?;
                        hasher.update(&pcr_value);
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
