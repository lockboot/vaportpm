// SPDX-License-Identifier: MIT OR Apache-2.0

//! GCP Shielded VM attestation verification

use der::Decode;
use pki_types::UnixTime;
use x509_cert::Certificate;

use crate::error::VerifyError;
use crate::tpm::{parse_quote_attest, verify_ecdsa_p256, verify_pcr_digest_matches};
use crate::x509::{extract_public_key, validate_tpm_cert_chain};
use crate::CloudProvider;
use crate::{roots, DecodedAttestationOutput, VerificationResult};

fn verify_gcp_certs(
    cert_chain_der: &[Vec<u8>],
    time: UnixTime,
) -> Result<(Vec<Certificate>, CloudProvider), VerifyError> {
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

    // Validate AK certificate chain to GCP root
    let chain_result = validate_tpm_cert_chain(&certs, time)?;

    // Verify root is a known GCP root
    let provider = roots::provider_from_hash(&chain_result.root_pubkey_hash).ok_or_else(|| {
        VerifyError::ChainValidation(format!(
            "Unknown root CA: {}. Only known cloud provider roots are trusted.",
            hex::encode(chain_result.root_pubkey_hash)
        ))
    })?;

    // Defence in depth: ensure the GCP verification path only accepts GCP roots
    if provider != CloudProvider::Gcp {
        return Err(VerifyError::ChainValidation(format!(
            "GCP verification path requires GCP root CA, got {:?}",
            provider
        )));
    }

    Ok((certs, provider))
}

/// Verify GCP Shielded VM attestation
///
/// This verification path:
/// 1. Validates AK certificate chain to Google's root CA
/// 2. Verifies Quote ECDSA signature with AK public key (authenticates quote)
/// 3. Verifies nonce matches the authenticated Quote extraData
/// 4. Verifies PCR digest matches claimed PCR values
///
/// The signature is verified before trusting any data parsed from the quote.
/// All inputs should be pre-decoded binary data (DER certs, raw bytes).
pub fn verify_gcp_decoded(
    decoded: &DecodedAttestationOutput,
    cert_chain_der: &[Vec<u8>],
    time: UnixTime,
) -> Result<VerificationResult, VerifyError> {
    // Enforce that only SHA-256 PCRs (algorithm ID 0) are present.
    // The GCP path only verifies SHA-256 PCRs (covered by the TPM Quote's
    // PCR digest and the AK certificate chain). Any other bank would be
    // unverified data passed through to the output.
    if decoded.pcrs.is_empty() {
        return Err(VerifyError::InvalidAttest(
            "Missing SHA-256 PCRs - required for GCP attestation".into(),
        ));
    }
    for (alg_id, pcr_idx) in decoded.pcrs.keys() {
        if *alg_id != 0 {
            return Err(VerifyError::InvalidAttest(format!(
                "GCP attestation contains non-SHA-256 PCR (alg_id={}, pcr={}); \
                 only SHA-256 PCRs are verified in the GCP path",
                alg_id, pcr_idx
            )));
        }
    }

    // Enforce all 24 SHA-256 PCRs are present.
    // Complete, unambiguous PCR state — no selective omission.
    for pcr_idx in 0..24u8 {
        if !decoded.pcrs.contains_key(&(0, pcr_idx)) {
            return Err(VerifyError::InvalidAttest(format!(
                "Missing SHA-256 PCR {} - all 24 PCRs (0-23) are required for GCP attestation",
                pcr_idx
            )));
        }
    }

    // Reject any PCR indices outside 0-23
    for (_alg_id, pcr_idx) in decoded.pcrs.keys() {
        if *pcr_idx > 23 {
            return Err(VerifyError::InvalidAttest(format!(
                "PCR index {} out of range; only PCRs 0-23 are valid",
                pcr_idx
            )));
        }
    }

    // Parse TPM2_Quote attestation (structure only — not yet authenticated)
    let quote_info = parse_quote_attest(&decoded.quote_attest)?;

    let (certs, provider) = verify_gcp_certs(cert_chain_der, time)?;

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

    // Verify Quote signature with AK public key — this authenticates
    // the quote data. All checks below trust the parsed quote_info
    // because the signature covers the entire attest structure.
    verify_ecdsa_p256(
        &decoded.quote_attest,
        &decoded.quote_signature,
        &decoded.ak_pubkey,
    )?;

    // --- Quote is now authenticated; safe to trust its contents ---

    // Enforce that the TPM Quote selects exactly one PCR bank: SHA-256 (0x000B),
    // and that it selects all 24 PCRs (bitmap 0xFF 0xFF 0xFF).
    if quote_info.pcr_select.len() != 1 {
        return Err(VerifyError::InvalidAttest(format!(
            "GCP path requires exactly one PCR bank selection, got {}",
            quote_info.pcr_select.len()
        )));
    }
    let (quote_alg, quote_bitmap) = &quote_info.pcr_select[0];
    if *quote_alg != 0x000B {
        return Err(VerifyError::InvalidAttest(format!(
            "GCP path requires TPM Quote to select SHA-256 PCRs (0x000B), got 0x{:04X}",
            quote_alg
        )));
    }
    if quote_bitmap.len() < 3
        || quote_bitmap[0] != 0xFF
        || quote_bitmap[1] != 0xFF
        || quote_bitmap[2] != 0xFF
    {
        return Err(VerifyError::InvalidAttest(format!(
            "GCP path requires all 24 PCRs selected in Quote bitmap, got {:?}",
            quote_bitmap
        )));
    }

    // Verify nonce matches Quote
    if decoded.nonce != quote_info.nonce.as_slice() {
        return Err(VerifyError::InvalidAttest(format!(
            "Nonce does not match Quote. Expected: {}, Quote: {}",
            hex::encode(decoded.nonce),
            hex::encode(&quote_info.nonce)
        )));
    }

    // Verify PCR digest matches claimed PCR values
    verify_pcr_digest_matches(&quote_info, &decoded.pcrs)?;

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
