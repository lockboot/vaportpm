// SPDX-License-Identifier: MIT OR Apache-2.0

//! GCP Shielded VM attestation verification

use der::Decode;
use pki_types::UnixTime;
use x509_cert::Certificate;

use crate::error::{
    CertificateParseReason, ChainValidationReason, InvalidAttestReason, SignatureInvalidReason,
    VerifyError,
};
use crate::pcr::PcrAlgorithm;
use crate::tpm::verify_quote;
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
                .map_err(|e| CertificateParseReason::InvalidDer(e.to_string()))
        })
        .collect::<Result<_, _>>()?;

    if certs.is_empty() {
        return Err(ChainValidationReason::EmptyChain.into());
    }

    // Validate AK certificate chain to GCP root
    let chain_result = validate_tpm_cert_chain(&certs, time)?;

    // Verify root is a known GCP root
    let provider = roots::provider_from_hash(&chain_result.root_pubkey_hash).ok_or_else(|| {
        VerifyError::ChainValidation(ChainValidationReason::UnknownRootCa {
            hash: hex::encode(chain_result.root_pubkey_hash),
        })
    })?;

    // Defence in depth: ensure the GCP verification path only accepts GCP roots
    if provider != CloudProvider::Gcp {
        return Err(ChainValidationReason::WrongProvider {
            expected: CloudProvider::Gcp,
            got: provider,
        }
        .into());
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
    let (certs, provider) = verify_gcp_certs(cert_chain_der, time)?;

    // Verify AK public key from cert chain matches the decoded input
    let ak_pubkey_from_cert = extract_public_key(&certs[0])?;
    let ak_sec1 = decoded.ak_pubkey.to_sec1_uncompressed();
    if ak_pubkey_from_cert != ak_sec1 {
        return Err(SignatureInvalidReason::AkPublicKeyMismatch.into());
    }

    // Verify TPM Quote: signature, PCR bank (SHA-256), nonce, PCR digest
    let quote_info = verify_quote(decoded, PcrAlgorithm::Sha256)?;

    let nonce: [u8; 32] = quote_info
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| InvalidAttestReason::NonceLengthInvalid)?;

    Ok(VerificationResult {
        nonce,
        provider,
        pcrs: decoded.pcrs.clone(),
        verified_at: time.as_secs(),
    })
}
