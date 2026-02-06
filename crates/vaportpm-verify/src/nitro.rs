// SPDX-License-Identifier: MIT OR Apache-2.0

//! AWS Nitro Enclave attestation verification

use std::collections::BTreeMap;

use ciborium::Value as CborValue;
use coset::{CborSerializable, CoseSign1};
use der::Decode;
use ecdsa::signature::hazmat::PrehashVerifier;
use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
use sha2::{Digest, Sha384};
use x509_cert::Certificate;

use pki_types::UnixTime;

use crate::error::VerifyError;
use crate::tpm::{parse_quote_attest, verify_ecdsa_p256, verify_pcr_digest_matches, TpmQuoteInfo};
use crate::x509::{extract_public_key, validate_tpm_cert_chain};
use crate::CloudProvider;
use crate::{roots, DecodedAttestationOutput, VerificationResult};

/// Parsed Nitro attestation document (internal)
#[derive(Debug, Clone)]
struct NitroDocument {
    /// TPM PCR values from Nitro document's `nitrotpm_pcrs` field (index -> SHA-384 digest)
    /// These are the PCR values signed by AWS hardware.
    pub pcrs: BTreeMap<u8, Vec<u8>>,
    /// Public key (raw bytes, if provided)
    pub public_key: Option<Vec<u8>>,
    /// Nonce (raw bytes, if provided)
    pub nonce: Option<Vec<u8>>,
}

/// Verify Nitro TPM attestation with pre-decoded data
///
/// Verification order (trust chain first, then cross-verify):
///
/// 1. **COSE trust chain**: verify COSE signature → cert chain → AWS root
///    Establishes that the Nitro document came from AWS hardware before
///    we parse any of its semantic content.
///
/// 2. **Parse authenticated Nitro document**: extract PCRs, public_key, nonce
///    from the now-authenticated COSE payload.
///
/// 3. **TPM Quote signature**: verify ECDSA signature over Quote with the AK
///    that the Nitro document binds.
///
/// 4. **Cross-verification**: nonce, AK binding, PCR values, PCR digest.
///
/// All inputs should be pre-decoded binary data (raw COSE document bytes).
pub fn verify_nitro_decoded(
    decoded: &DecodedAttestationOutput,
    document_bytes: &[u8],
    time: UnixTime,
) -> Result<VerificationResult, VerifyError> {
    // === Phase 1: Verify COSE trust chain ===
    // Establish that this document came from AWS before parsing its contents.
    let (nitro_doc, provider) = verify_nitro_cose_chain(document_bytes, time)?;

    // === Phase 2: Verify TPM Quote authenticity ===
    // The Nitro document binds the AK public key — verify the Quote was
    // signed by that key.
    let quote_info = verify_tpm_quote_signature(decoded, &nitro_doc)?;

    // === Phase 3: Cross-verify all authenticated data ===
    verify_nitro_bindings(decoded, &quote_info, &nitro_doc)?;

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

/// Phase 1: Verify COSE signature, certificate chain, and AWS root.
///
/// Returns the authenticated Nitro document and cloud provider.
/// No semantic content from the document is trusted before this passes.
fn verify_nitro_cose_chain(
    document_bytes: &[u8],
    time: UnixTime,
) -> Result<(NitroDocument, CloudProvider), VerifyError> {
    // Parse COSE Sign1 envelope
    let cose_sign1 = CoseSign1::from_slice(document_bytes)
        .map_err(|e| VerifyError::CoseVerify(format!("Failed to parse COSE Sign1: {}", e)))?;

    let payload = cose_sign1
        .payload
        .as_ref()
        .ok_or_else(|| VerifyError::CoseVerify("Missing payload".into()))?;

    // Minimal parse: extract only the certificate and CA bundle needed
    // to verify the COSE signature. We don't touch semantic fields yet.
    let payload_cbor: CborValue = ciborium::from_reader(payload.as_slice())
        .map_err(|e| VerifyError::CborParse(format!("Failed to parse payload: {}", e)))?;

    let payload_map = match &payload_cbor {
        CborValue::Map(m) => m,
        _ => return Err(VerifyError::CborParse("Payload is not a map".into())),
    };

    let cert_der = extract_cbor_bytes(payload_map, "certificate")?;
    let cabundle = extract_cbor_byte_array(payload_map, "cabundle")?;

    // Build certificate chain (leaf first)
    let leaf_cert = Certificate::from_der(&cert_der)
        .map_err(|e| VerifyError::CertificateParse(format!("Invalid leaf cert: {}", e)))?;

    let mut chain = vec![leaf_cert];
    for ca_der in cabundle.into_iter().rev() {
        let ca_cert = Certificate::from_der(&ca_der)
            .map_err(|e| VerifyError::CertificateParse(format!("Invalid CA cert: {}", e)))?;
        chain.push(ca_cert);
    }

    // Verify COSE signature
    let leaf_pubkey = extract_public_key(&chain[0])?;
    verify_cose_signature(&cose_sign1, &leaf_pubkey, payload)?;

    // Validate certificate chain and time validity
    let chain_result = validate_tpm_cert_chain(&chain, time)?;

    // Verify root is a known AWS root
    let provider = roots::provider_from_hash(&chain_result.root_pubkey_hash).ok_or_else(|| {
        VerifyError::ChainValidation(format!(
            "Unknown root CA: {}. Only known cloud provider roots are trusted.",
            hex::encode(chain_result.root_pubkey_hash)
        ))
    })?;

    if provider != CloudProvider::Aws {
        return Err(VerifyError::ChainValidation(format!(
            "Nitro verification path requires AWS root CA, got {:?}",
            provider
        )));
    }

    // --- COSE document is now authenticated; safe to parse its contents ---
    let nitro_doc = parse_nitro_document(payload_map)?;

    Ok((nitro_doc, provider))
}

/// Phase 2: Verify the TPM Quote was signed by the AK that the Nitro document binds.
///
/// Returns the authenticated TpmQuoteInfo.
fn verify_tpm_quote_signature(
    decoded: &DecodedAttestationOutput,
    nitro_doc: &NitroDocument,
) -> Result<TpmQuoteInfo, VerifyError> {
    // The Nitro document's public_key field tells us which AK to trust.
    // Verify the claimed AK matches before we use it for signature verification.
    let signed_pubkey = nitro_doc.public_key.as_ref().ok_or_else(|| {
        VerifyError::NoValidAttestation(
            "Nitro document missing public_key field - cannot bind TPM signing key".into(),
        )
    })?;

    if decoded.ak_pubkey.as_slice() != signed_pubkey.as_slice() {
        return Err(VerifyError::SignatureInvalid(format!(
            "TPM signing key does not match Nitro public_key binding: {} != {}",
            hex::encode(decoded.ak_pubkey),
            hex::encode(signed_pubkey)
        )));
    }

    // Parse and verify TPM2_Quote
    let quote_info = parse_quote_attest(&decoded.quote_attest)?;

    verify_ecdsa_p256(
        &decoded.quote_attest,
        &decoded.quote_signature,
        &decoded.ak_pubkey,
    )?;

    // --- Quote is now authenticated; safe to trust its contents ---

    Ok(quote_info)
}

/// Phase 3: Cross-verify all authenticated data from the Nitro document and TPM Quote.
///
/// At this point both the Nitro document (COSE) and TPM Quote (ECDSA) are
/// authenticated. This function verifies they agree on nonce, PCR values,
/// and PCR digest.
fn verify_nitro_bindings(
    decoded: &DecodedAttestationOutput,
    quote_info: &TpmQuoteInfo,
    nitro_doc: &NitroDocument,
) -> Result<(), VerifyError> {
    // --- Quote structure enforcement ---

    // Exactly one PCR bank: SHA-384 (0x000C), all 24 PCRs selected.
    if quote_info.pcr_select.len() != 1 {
        return Err(VerifyError::InvalidAttest(format!(
            "Nitro path requires exactly one PCR bank selection, got {}",
            quote_info.pcr_select.len()
        )));
    }
    let (quote_alg, quote_bitmap) = &quote_info.pcr_select[0];
    if *quote_alg != 0x000C {
        return Err(VerifyError::InvalidAttest(format!(
            "Nitro path requires TPM Quote to select SHA-384 PCRs (0x000C), got 0x{:04X}",
            quote_alg
        )));
    }
    if quote_bitmap.len() < 3
        || quote_bitmap[0] != 0xFF
        || quote_bitmap[1] != 0xFF
        || quote_bitmap[2] != 0xFF
    {
        return Err(VerifyError::InvalidAttest(format!(
            "Nitro path requires all 24 PCRs selected in Quote bitmap, got {:?}",
            quote_bitmap
        )));
    }

    // --- Nonce verification ---

    if decoded.nonce != quote_info.nonce.as_slice() {
        return Err(VerifyError::InvalidAttest(format!(
            "Nonce does not match Quote. Expected: {}, Quote: {}",
            hex::encode(decoded.nonce),
            hex::encode(&quote_info.nonce)
        )));
    }

    let signed_nonce = nitro_doc.nonce.as_ref().ok_or_else(|| {
        VerifyError::NoValidAttestation(
            "Nitro document missing nonce field - cannot verify freshness".into(),
        )
    })?;

    if quote_info.nonce.as_slice() != signed_nonce.as_slice() {
        return Err(VerifyError::SignatureInvalid(format!(
            "TPM nonce does not match Nitro nonce: {} != {}",
            hex::encode(&quote_info.nonce),
            hex::encode(signed_nonce)
        )));
    }

    // --- PCR enforcement ---

    // Only SHA-384 PCRs allowed (algorithm ID 1). Any other bank would be
    // unverified data passed through to the output.
    if decoded.pcrs.is_empty() {
        return Err(VerifyError::InvalidAttest(
            "Missing SHA-384 PCRs - required for Nitro attestation".into(),
        ));
    }

    for (alg_id, pcr_idx) in decoded.pcrs.keys() {
        if *alg_id != 1 {
            return Err(VerifyError::InvalidAttest(format!(
                "Nitro attestation contains non-SHA-384 PCR (alg_id={}, pcr={}); \
                 only SHA-384 PCRs are verified in the Nitro path",
                alg_id, pcr_idx
            )));
        }
        if *pcr_idx > 23 {
            return Err(VerifyError::InvalidAttest(format!(
                "PCR index {} out of range; only PCRs 0-23 are valid",
                pcr_idx
            )));
        }
    }

    // All 24 PCRs must be present — complete, unambiguous state.
    for pcr_idx in 0..24u8 {
        if !decoded.pcrs.contains_key(&(1, pcr_idx)) {
            return Err(VerifyError::InvalidAttest(format!(
                "Missing SHA-384 PCR {} - all 24 PCRs (0-23) are required for Nitro attestation",
                pcr_idx
            )));
        }
    }

    // --- Bidirectional PCR match against Nitro-signed values ---

    let signed_pcrs = &nitro_doc.pcrs;
    if signed_pcrs.is_empty() {
        return Err(VerifyError::InvalidAttest(
            "Nitro document contains no signed PCRs".into(),
        ));
    }

    for (idx, signed_value) in signed_pcrs.iter() {
        match decoded.pcrs.get(&(1, *idx)) {
            Some(claimed_value) if claimed_value == signed_value => {}
            Some(claimed_value) => {
                return Err(VerifyError::SignatureInvalid(format!(
                    "PCR {} SHA-384 mismatch: claimed {} != signed {}",
                    idx,
                    hex::encode(claimed_value),
                    hex::encode(signed_value)
                )));
            }
            None => {
                return Err(VerifyError::SignatureInvalid(format!(
                    "PCR {} in signed Nitro document but missing from attestation",
                    idx
                )));
            }
        }
    }

    for (_alg_id, pcr_idx) in decoded.pcrs.keys() {
        if !signed_pcrs.contains_key(pcr_idx) {
            return Err(VerifyError::InvalidAttest(format!(
                "PCR {} in attestation but not signed by Nitro document",
                pcr_idx
            )));
        }
    }

    // --- PCR digest: cryptographic binding ---
    // COSE signature authenticates the Nitro document (including PCR values).
    // ECDSA signature authenticates the TPM Quote (including PCR digest).
    // This check proves the PCR digest covers the same values.
    verify_pcr_digest_matches(quote_info, &decoded.pcrs)?;

    Ok(())
}

/// Parse Nitro document fields from CBOR map
fn parse_nitro_document(map: &[(CborValue, CborValue)]) -> Result<NitroDocument, VerifyError> {
    // Verify digest algorithm is SHA384 as expected
    let digest = extract_cbor_text(map, "digest")?;
    if digest != "SHA384" {
        return Err(VerifyError::InvalidAttest(format!(
            "Unexpected Nitro digest algorithm: expected SHA384, got {}",
            digest
        )));
    }

    // Parse PCRs (binary)
    let pcrs = extract_cbor_pcrs(map)?;

    // Optional fields (binary)
    let public_key = extract_cbor_bytes_optional(map, "public_key");
    let nonce = extract_cbor_bytes_optional(map, "nonce");

    Ok(NitroDocument {
        pcrs,
        public_key,
        nonce,
    })
}

/// Extract text field from CBOR map
fn extract_cbor_text(map: &[(CborValue, CborValue)], key: &str) -> Result<String, VerifyError> {
    for (k, v) in map {
        if let CborValue::Text(k_text) = k {
            if k_text == key {
                if let CborValue::Text(val) = v {
                    return Ok(val.clone());
                }
            }
        }
    }
    Err(VerifyError::CborParse(format!("Missing field: {}", key)))
}

/// Extract bytes field from CBOR map
fn extract_cbor_bytes(map: &[(CborValue, CborValue)], key: &str) -> Result<Vec<u8>, VerifyError> {
    for (k, v) in map {
        if let CborValue::Text(k_text) = k {
            if k_text == key {
                if let CborValue::Bytes(val) = v {
                    return Ok(val.clone());
                }
            }
        }
    }
    Err(VerifyError::CborParse(format!("Missing field: {}", key)))
}

/// Extract optional bytes field from CBOR map
fn extract_cbor_bytes_optional(map: &[(CborValue, CborValue)], key: &str) -> Option<Vec<u8>> {
    for (k, v) in map {
        if let CborValue::Text(k_text) = k {
            if k_text == key {
                if let CborValue::Bytes(val) = v {
                    return Some(val.clone());
                }
                if let CborValue::Null = v {
                    return None;
                }
            }
        }
    }
    None
}

/// Extract byte array field from CBOR map
fn extract_cbor_byte_array(
    map: &[(CborValue, CborValue)],
    key: &str,
) -> Result<Vec<Vec<u8>>, VerifyError> {
    for (k, v) in map {
        if let CborValue::Text(k_text) = k {
            if k_text == key {
                if let CborValue::Array(arr) = v {
                    let mut result = Vec::new();
                    for item in arr {
                        if let CborValue::Bytes(b) = item {
                            result.push(b.clone());
                        }
                    }
                    return Ok(result);
                }
            }
        }
    }
    Err(VerifyError::CborParse(format!("Missing field: {}", key)))
}

/// Maximum valid PCR index for AWS Nitro Enclaves (0-15)
const MAX_NITRO_ENCLAVE_PCR_INDEX: u8 = 15;

/// Maximum valid PCR index for TPMs (0-23)
const MAX_TPM_PCR_INDEX: u8 = 23;

/// Extract PCRs from CBOR map
/// Handles both "pcrs" (Nitro Enclave) and "nitrotpm_pcrs" (Nitro TPM) field names
fn extract_cbor_pcrs(map: &[(CborValue, CborValue)]) -> Result<BTreeMap<u8, Vec<u8>>, VerifyError> {
    for (k, v) in map {
        if let CborValue::Text(k_text) = k {
            // Check for both field names: "pcrs" (enclave) and "nitrotpm_pcrs" (TPM)
            let (is_pcrs, max_index) = if k_text == "pcrs" {
                (true, MAX_NITRO_ENCLAVE_PCR_INDEX)
            } else if k_text == "nitrotpm_pcrs" {
                (true, MAX_TPM_PCR_INDEX)
            } else {
                (false, 0)
            };

            if is_pcrs {
                if let CborValue::Map(pcr_map) = v {
                    let mut pcrs = BTreeMap::new();
                    for (pk, pv) in pcr_map {
                        if let CborValue::Integer(idx) = pk {
                            if let CborValue::Bytes(val) = pv {
                                let idx_i128: i128 = (*idx).into();

                                // Validate PCR index bounds
                                if idx_i128 < 0 {
                                    return Err(VerifyError::PcrIndexOutOfBounds(format!(
                                        "Negative PCR index: {}",
                                        idx_i128
                                    )));
                                }
                                if idx_i128 > max_index as i128 {
                                    return Err(VerifyError::PcrIndexOutOfBounds(format!(
                                        "PCR index {} exceeds maximum {}",
                                        idx_i128, max_index
                                    )));
                                }

                                pcrs.insert(idx_i128 as u8, val.clone());
                            }
                        }
                    }
                    return Ok(pcrs);
                }
            }
        }
    }
    Err(VerifyError::CborParse(
        "Missing pcrs or nitrotpm_pcrs field".into(),
    ))
}

/// Verify COSE Sign1 signature
fn verify_cose_signature(
    cose: &CoseSign1,
    public_key: &[u8],
    payload: &[u8],
) -> Result<(), VerifyError> {
    // Nitro uses ES384 (ECDSA with P-384 and SHA-384)
    // Build the Sig_structure for COSE_Sign1:
    // Sig_structure = [
    //   context : "Signature1",
    //   body_protected : protected,
    //   external_aad : bstr,
    //   payload : bstr
    // ]

    // Get the protected header bytes using coset's serialization
    let protected = cose.protected.clone().to_vec().map_err(|e| {
        VerifyError::CoseVerify(format!("Failed to serialize protected header: {}", e))
    })?;

    let sig_structure = CborValue::Array(vec![
        CborValue::Text("Signature1".to_string()),
        CborValue::Bytes(protected),
        CborValue::Bytes(vec![]), // external_aad
        CborValue::Bytes(payload.to_vec()),
    ]);

    let mut sig_structure_bytes = Vec::new();
    ciborium::into_writer(&sig_structure, &mut sig_structure_bytes)
        .map_err(|e| VerifyError::CoseVerify(format!("Failed to encode Sig_structure: {}", e)))?;

    // Hash the Sig_structure
    let digest = Sha384::digest(&sig_structure_bytes);

    // Parse the public key
    let verifying_key = P384VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| VerifyError::CoseVerify(format!("Invalid P-384 key: {}", e)))?;

    // Parse the signature (raw r||s format for COSE, not DER)
    let sig_bytes = &cose.signature;
    if sig_bytes.len() != 96 {
        return Err(VerifyError::CoseVerify(format!(
            "Invalid ES384 signature length: expected 96, got {}",
            sig_bytes.len()
        )));
    }

    // Convert raw r||s to DER format for the ecdsa crate
    let signature = P384Signature::from_slice(sig_bytes)
        .map_err(|e| VerifyError::CoseVerify(format!("Invalid signature: {}", e)))?;

    verifying_key
        .verify_prehash(&digest, &signature)
        .map_err(|e| VerifyError::CoseVerify(format!("Signature verification failed: {}", e)))
}

#[cfg(test)]
#[allow(clippy::useless_vec)]
mod tests {
    use super::*;
    use sha2::Sha256;

    // === CBOR Field Extraction Tests ===

    fn make_test_map() -> Vec<(CborValue, CborValue)> {
        vec![
            (
                CborValue::Text("module_id".to_string()),
                CborValue::Text("test-module".to_string()),
            ),
            (
                CborValue::Text("timestamp".to_string()),
                CborValue::Integer(1234567890.into()),
            ),
            (
                CborValue::Text("digest".to_string()),
                CborValue::Text("SHA384".to_string()),
            ),
            (
                CborValue::Text("pcrs".to_string()),
                CborValue::Map(vec![
                    (
                        CborValue::Integer(0.into()),
                        CborValue::Bytes(vec![0x00; 48]),
                    ),
                    (
                        CborValue::Integer(1.into()),
                        CborValue::Bytes(vec![0x01; 48]),
                    ),
                ]),
            ),
            (
                CborValue::Text("certificate".to_string()),
                CborValue::Bytes(vec![0x30, 0x00]),
            ),
            (
                CborValue::Text("cabundle".to_string()),
                CborValue::Array(vec![]),
            ),
        ]
    }

    #[test]
    fn test_extract_cbor_text_valid() {
        let map = make_test_map();
        let result = extract_cbor_text(&map, "module_id");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test-module");
    }

    #[test]
    fn test_extract_cbor_text_missing() {
        let map = make_test_map();
        let result = extract_cbor_text(&map, "nonexistent");
        assert!(matches!(result, Err(VerifyError::CborParse(_))));
    }

    #[test]
    fn test_extract_cbor_text_wrong_type() {
        let map = vec![(
            CborValue::Text("wrong".to_string()),
            CborValue::Integer(123.into()),
        )];
        let result = extract_cbor_text(&map, "wrong");
        assert!(matches!(result, Err(VerifyError::CborParse(_))));
    }

    #[test]
    fn test_extract_cbor_bytes_valid() {
        let map = make_test_map();
        let result = extract_cbor_bytes(&map, "certificate");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0x30, 0x00]);
    }

    #[test]
    fn test_extract_cbor_bytes_missing() {
        let map = make_test_map();
        let result = extract_cbor_bytes(&map, "nonexistent");
        assert!(matches!(result, Err(VerifyError::CborParse(_))));
    }

    #[test]
    fn test_extract_cbor_bytes_optional_present() {
        let map = vec![(
            CborValue::Text("data".to_string()),
            CborValue::Bytes(vec![1, 2, 3]),
        )];
        let result = extract_cbor_bytes_optional(&map, "data");
        assert_eq!(result, Some(vec![1, 2, 3]));
    }

    #[test]
    fn test_extract_cbor_bytes_optional_null() {
        let map = vec![(CborValue::Text("data".to_string()), CborValue::Null)];
        let result = extract_cbor_bytes_optional(&map, "data");
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_cbor_bytes_optional_missing() {
        let map: Vec<(CborValue, CborValue)> = vec![];
        let result = extract_cbor_bytes_optional(&map, "data");
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_cbor_pcrs_valid() {
        let map = make_test_map();
        let result = extract_cbor_pcrs(&map);
        assert!(result.is_ok());
        let pcrs = result.unwrap();
        assert_eq!(pcrs.len(), 2);
        assert!(pcrs.contains_key(&0));
        assert!(pcrs.contains_key(&1));
    }

    #[test]
    fn test_extract_cbor_pcrs_missing() {
        let map: Vec<(CborValue, CborValue)> = vec![];
        let result = extract_cbor_pcrs(&map);
        assert!(matches!(result, Err(VerifyError::CborParse(_))));
    }

    // === PCR Index Bounds Tests ===

    #[test]
    fn test_pcr_index_valid_range() {
        // Valid PCR indices: 0-15
        let map = vec![(
            CborValue::Text("pcrs".to_string()),
            CborValue::Map(vec![
                (
                    CborValue::Integer(0.into()),
                    CborValue::Bytes(vec![0x00; 48]),
                ),
                (
                    CborValue::Integer(15.into()),
                    CborValue::Bytes(vec![0x0f; 48]),
                ),
            ]),
        )];
        let result = extract_cbor_pcrs(&map);
        assert!(result.is_ok());
        let pcrs = result.unwrap();
        assert!(pcrs.contains_key(&0));
        assert!(pcrs.contains_key(&15));
    }

    #[test]
    fn test_pcr_index_too_large() {
        // PCR index 16 should be rejected
        let map = vec![(
            CborValue::Text("pcrs".to_string()),
            CborValue::Map(vec![(
                CborValue::Integer(16.into()),
                CborValue::Bytes(vec![0x00; 48]),
            )]),
        )];
        let result = extract_cbor_pcrs(&map);
        assert!(matches!(result, Err(VerifyError::PcrIndexOutOfBounds(_))));
    }

    #[test]
    fn test_pcr_index_very_large() {
        // Very large PCR index should be rejected
        let map = vec![(
            CborValue::Text("pcrs".to_string()),
            CborValue::Map(vec![(
                CborValue::Integer(255.into()),
                CborValue::Bytes(vec![0x00; 48]),
            )]),
        )];
        let result = extract_cbor_pcrs(&map);
        assert!(matches!(result, Err(VerifyError::PcrIndexOutOfBounds(_))));
    }

    #[test]
    fn test_pcr_index_negative() {
        // Negative PCR index should be rejected
        let map = vec![(
            CborValue::Text("pcrs".to_string()),
            CborValue::Map(vec![(
                CborValue::Integer((-1).into()),
                CborValue::Bytes(vec![0x00; 48]),
            )]),
        )];
        let result = extract_cbor_pcrs(&map);
        assert!(matches!(result, Err(VerifyError::PcrIndexOutOfBounds(_))));
    }

    // === parse_nitro_document Tests ===

    #[test]
    fn test_parse_nitro_document_wrong_digest_algorithm() {
        let map = vec![
            (
                CborValue::Text("digest".to_string()),
                CborValue::Text("SHA256".to_string()),
            ),
            (
                CborValue::Text("pcrs".to_string()),
                CborValue::Map(vec![(
                    CborValue::Integer(0.into()),
                    CborValue::Bytes(vec![0x00; 48]),
                )]),
            ),
        ];
        let result = parse_nitro_document(&map);
        assert!(
            matches!(result, Err(VerifyError::InvalidAttest(ref msg)) if msg.contains("Unexpected Nitro digest algorithm")),
            "Should reject SHA256 digest, got: {:?}",
            result
        );
    }

    #[test]
    fn test_parse_nitro_document_public_key_absent() {
        let map = vec![
            (
                CborValue::Text("digest".to_string()),
                CborValue::Text("SHA384".to_string()),
            ),
            (
                CborValue::Text("pcrs".to_string()),
                CborValue::Map(vec![(
                    CborValue::Integer(0.into()),
                    CborValue::Bytes(vec![0x00; 48]),
                )]),
            ),
            // public_key field is absent
        ];
        let result = parse_nitro_document(&map).unwrap();
        assert_eq!(result.public_key, None);
    }

    #[test]
    fn test_parse_nitro_document_public_key_null() {
        let map = vec![
            (
                CborValue::Text("digest".to_string()),
                CborValue::Text("SHA384".to_string()),
            ),
            (
                CborValue::Text("pcrs".to_string()),
                CborValue::Map(vec![(
                    CborValue::Integer(0.into()),
                    CborValue::Bytes(vec![0x00; 48]),
                )]),
            ),
            (CborValue::Text("public_key".to_string()), CborValue::Null),
        ];
        let result = parse_nitro_document(&map).unwrap();
        assert_eq!(result.public_key, None);
    }

    #[test]
    fn test_parse_nitro_document_public_key_present() {
        let pk = vec![0x04; 65];
        let map = vec![
            (
                CborValue::Text("digest".to_string()),
                CborValue::Text("SHA384".to_string()),
            ),
            (
                CborValue::Text("pcrs".to_string()),
                CborValue::Map(vec![(
                    CborValue::Integer(0.into()),
                    CborValue::Bytes(vec![0x00; 48]),
                )]),
            ),
            (
                CborValue::Text("public_key".to_string()),
                CborValue::Bytes(pk.clone()),
            ),
        ];
        let result = parse_nitro_document(&map).unwrap();
        assert_eq!(result.public_key, Some(pk));
    }

    #[test]
    fn test_parse_nitro_document_nonce_absent() {
        let map = vec![
            (
                CborValue::Text("digest".to_string()),
                CborValue::Text("SHA384".to_string()),
            ),
            (
                CborValue::Text("pcrs".to_string()),
                CborValue::Map(vec![(
                    CborValue::Integer(0.into()),
                    CborValue::Bytes(vec![0x00; 48]),
                )]),
            ),
            // nonce field is absent
        ];
        let result = parse_nitro_document(&map).unwrap();
        assert_eq!(result.nonce, None);
    }

    #[test]
    fn test_parse_nitro_document_nonce_null() {
        let map = vec![
            (
                CborValue::Text("digest".to_string()),
                CborValue::Text("SHA384".to_string()),
            ),
            (
                CborValue::Text("pcrs".to_string()),
                CborValue::Map(vec![(
                    CborValue::Integer(0.into()),
                    CborValue::Bytes(vec![0x00; 48]),
                )]),
            ),
            (CborValue::Text("nonce".to_string()), CborValue::Null),
        ];
        let result = parse_nitro_document(&map).unwrap();
        assert_eq!(result.nonce, None);
    }

    #[test]
    fn test_parse_nitro_document_nonce_present() {
        let nonce = vec![0xAB; 32];
        let map = vec![
            (
                CborValue::Text("digest".to_string()),
                CborValue::Text("SHA384".to_string()),
            ),
            (
                CborValue::Text("pcrs".to_string()),
                CborValue::Map(vec![(
                    CborValue::Integer(0.into()),
                    CborValue::Bytes(vec![0x00; 48]),
                )]),
            ),
            (
                CborValue::Text("nonce".to_string()),
                CborValue::Bytes(nonce.clone()),
            ),
        ];
        let result = parse_nitro_document(&map).unwrap();
        assert_eq!(result.nonce, Some(nonce));
    }

    // === extract_cbor_byte_array edge cases ===

    #[test]
    fn test_extract_cbor_byte_array_mixed_items_skips_non_bytes() {
        // Mixed array with bytes and non-bytes items — only bytes should be returned
        let map = vec![(
            CborValue::Text("mixed".to_string()),
            CborValue::Array(vec![
                CborValue::Bytes(vec![1, 2, 3]),
                CborValue::Integer(42.into()),
                CborValue::Bytes(vec![4, 5, 6]),
                CborValue::Text("not bytes".to_string()),
                CborValue::Bytes(vec![7, 8, 9]),
            ]),
        )];
        let result = extract_cbor_byte_array(&map, "mixed").unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], vec![1, 2, 3]);
        assert_eq!(result[1], vec![4, 5, 6]);
        assert_eq!(result[2], vec![7, 8, 9]);
    }

    // === verify_nitro_bindings Tests ===

    /// Build a consistent (DecodedAttestationOutput, TpmQuoteInfo, NitroDocument) triple
    /// where `verify_nitro_bindings` succeeds. Tests tweak individual fields to trigger errors.
    fn make_valid_bindings_inputs() -> (DecodedAttestationOutput, TpmQuoteInfo, NitroDocument) {
        let nonce = [0xAA; 32];

        // 24 SHA-384 PCRs: value = vec![idx; 48]
        let mut decoded_pcrs = BTreeMap::new();
        let mut nitro_pcrs = BTreeMap::new();
        for idx in 0u8..24 {
            let value = vec![idx; 48];
            decoded_pcrs.insert((1, idx), value.clone()); // alg_id 1 = SHA-384
            nitro_pcrs.insert(idx, value);
        }

        // Compute the PCR digest: SHA-256 of concatenated PCR values in order (0..23)
        let mut hasher = Sha256::new();
        for idx in 0u8..24 {
            hasher.update(vec![idx; 48]);
        }
        let pcr_digest = hasher.finalize().to_vec();

        let decoded = DecodedAttestationOutput {
            nonce,
            pcrs: decoded_pcrs,
            ak_pubkey: [0x04; 65],
            quote_attest: vec![],
            quote_signature: vec![],
            platform: crate::DecodedPlatformAttestation::Nitro { document: vec![] },
        };

        let quote_info = TpmQuoteInfo {
            nonce: nonce.to_vec(),
            signer_name: vec![0x00; 34],
            pcr_select: vec![(0x000C, vec![0xFF, 0xFF, 0xFF])], // SHA-384, all 24 selected
            pcr_digest,
        };

        let nitro_doc = NitroDocument {
            pcrs: nitro_pcrs,
            public_key: Some(vec![0x04; 65]),
            nonce: Some(nonce.to_vec()),
        };

        (decoded, quote_info, nitro_doc)
    }

    #[test]
    fn test_bindings_happy_path() {
        let (decoded, quote_info, nitro_doc) = make_valid_bindings_inputs();
        let result = verify_nitro_bindings(&decoded, &quote_info, &nitro_doc);
        assert!(result.is_ok(), "Happy path should succeed: {:?}", result);
    }

    #[test]
    fn test_bindings_reject_multiple_pcr_banks() {
        let (decoded, mut quote_info, nitro_doc) = make_valid_bindings_inputs();
        quote_info.pcr_select.push((0x000B, vec![0xFF, 0xFF, 0xFF]));
        let result = verify_nitro_bindings(&decoded, &quote_info, &nitro_doc);
        assert!(
            matches!(result, Err(VerifyError::InvalidAttest(ref msg)) if msg.contains("exactly one PCR bank selection, got 2")),
            "Expected multiple PCR bank error, got: {:?}",
            result
        );
    }

    #[test]
    fn test_bindings_reject_wrong_pcr_algorithm() {
        let (decoded, mut quote_info, nitro_doc) = make_valid_bindings_inputs();
        quote_info.pcr_select[0].0 = 0x000B; // SHA-256 instead of SHA-384
        let result = verify_nitro_bindings(&decoded, &quote_info, &nitro_doc);
        assert!(
            matches!(result, Err(VerifyError::InvalidAttest(ref msg)) if msg.contains("SHA-384 PCRs (0x000C), got 0x000B")),
            "Expected wrong algorithm error, got: {:?}",
            result
        );
    }

    #[test]
    fn test_bindings_reject_partial_pcr_bitmap() {
        let (decoded, mut quote_info, nitro_doc) = make_valid_bindings_inputs();
        quote_info.pcr_select[0].1 = vec![0xFF, 0xFF, 0xFE]; // PCR 23 not selected
        let result = verify_nitro_bindings(&decoded, &quote_info, &nitro_doc);
        assert!(
            matches!(result, Err(VerifyError::InvalidAttest(ref msg)) if msg.contains("all 24 PCRs selected in Quote bitmap")),
            "Expected partial bitmap error, got: {:?}",
            result
        );
    }

    #[test]
    fn test_bindings_reject_nonce_mismatch_decoded_vs_quote() {
        let (mut decoded, quote_info, nitro_doc) = make_valid_bindings_inputs();
        decoded.nonce = [0xBB; 32]; // Different from quote_info.nonce
        let result = verify_nitro_bindings(&decoded, &quote_info, &nitro_doc);
        assert!(
            matches!(result, Err(VerifyError::InvalidAttest(ref msg)) if msg.contains("Nonce does not match Quote")),
            "Expected nonce mismatch error, got: {:?}",
            result
        );
    }

    #[test]
    fn test_bindings_reject_missing_nitro_nonce() {
        let (decoded, quote_info, mut nitro_doc) = make_valid_bindings_inputs();
        nitro_doc.nonce = None;
        let result = verify_nitro_bindings(&decoded, &quote_info, &nitro_doc);
        assert!(
            matches!(result, Err(VerifyError::NoValidAttestation(ref msg)) if msg.contains("missing nonce field")),
            "Expected missing nonce error, got: {:?}",
            result
        );
    }

    #[test]
    fn test_bindings_reject_nitro_nonce_mismatch() {
        let (decoded, quote_info, mut nitro_doc) = make_valid_bindings_inputs();
        nitro_doc.nonce = Some(vec![0xCC; 32]); // Different from quote nonce
        let result = verify_nitro_bindings(&decoded, &quote_info, &nitro_doc);
        assert!(
            matches!(result, Err(VerifyError::SignatureInvalid(ref msg)) if msg.contains("TPM nonce does not match Nitro nonce")),
            "Expected Nitro nonce mismatch error, got: {:?}",
            result
        );
    }

    #[test]
    fn test_bindings_reject_empty_signed_pcrs() {
        let (decoded, quote_info, mut nitro_doc) = make_valid_bindings_inputs();
        nitro_doc.pcrs = BTreeMap::new();
        let result = verify_nitro_bindings(&decoded, &quote_info, &nitro_doc);
        assert!(
            matches!(result, Err(VerifyError::InvalidAttest(ref msg)) if msg.contains("no signed PCRs")),
            "Expected empty signed PCRs error, got: {:?}",
            result
        );
    }

    #[test]
    fn test_bindings_reject_signed_pcr_missing_from_attestation() {
        let (decoded, quote_info, mut nitro_doc) = make_valid_bindings_inputs();
        // Add PCR 24 to nitro_doc but it doesn't exist in decoded.pcrs
        nitro_doc.pcrs.insert(24, vec![0xFF; 48]);
        let result = verify_nitro_bindings(&decoded, &quote_info, &nitro_doc);
        assert!(
            matches!(result, Err(VerifyError::SignatureInvalid(ref msg)) if msg.contains("in signed Nitro document but missing")),
            "Expected signed PCR missing error, got: {:?}",
            result
        );
    }

    #[test]
    fn test_bindings_reject_attestation_pcr_not_signed() {
        let (decoded, quote_info, mut nitro_doc) = make_valid_bindings_inputs();
        nitro_doc.pcrs.remove(&0); // Remove PCR 0 from signed set
        let result = verify_nitro_bindings(&decoded, &quote_info, &nitro_doc);
        assert!(
            matches!(result, Err(VerifyError::InvalidAttest(ref msg)) if msg.contains("in attestation but not signed")),
            "Expected unsigned PCR error, got: {:?}",
            result
        );
    }

    #[test]
    fn test_bindings_reject_pcr_value_mismatch() {
        let (decoded, quote_info, mut nitro_doc) = make_valid_bindings_inputs();
        nitro_doc.pcrs.insert(0, vec![0xFF; 48]); // Different value for PCR 0
        let result = verify_nitro_bindings(&decoded, &quote_info, &nitro_doc);
        assert!(
            matches!(result, Err(VerifyError::SignatureInvalid(ref msg)) if msg.contains("PCR 0 SHA-384 mismatch")),
            "Expected PCR value mismatch error, got: {:?}",
            result
        );
    }

    // === verify_tpm_quote_signature Tests ===

    /// Build a (DecodedAttestationOutput, NitroDocument) pair with matching AK pubkey / public_key.
    /// The quote_attest and quote_signature are dummy since we only test pre-crypto error paths.
    fn make_valid_quote_sig_inputs() -> (DecodedAttestationOutput, NitroDocument) {
        let ak_pubkey = [0x04; 65];

        let decoded = DecodedAttestationOutput {
            nonce: [0xAA; 32],
            pcrs: BTreeMap::new(),
            ak_pubkey,
            quote_attest: vec![],
            quote_signature: vec![],
            platform: crate::DecodedPlatformAttestation::Nitro { document: vec![] },
        };

        let nitro_doc = NitroDocument {
            pcrs: BTreeMap::new(),
            public_key: Some(ak_pubkey.to_vec()),
            nonce: Some(vec![0xAA; 32]),
        };

        (decoded, nitro_doc)
    }

    #[test]
    fn test_quote_sig_reject_missing_public_key() {
        let (decoded, mut nitro_doc) = make_valid_quote_sig_inputs();
        nitro_doc.public_key = None;
        let result = verify_tpm_quote_signature(&decoded, &nitro_doc);
        assert!(
            matches!(result, Err(VerifyError::NoValidAttestation(ref msg)) if msg.contains("missing public_key field")),
            "Expected missing public_key error, got: {:?}",
            result
        );
    }

    #[test]
    fn test_quote_sig_reject_ak_mismatch() {
        let (decoded, mut nitro_doc) = make_valid_quote_sig_inputs();
        nitro_doc.public_key = Some(vec![0x05; 65]); // Different key
        let result = verify_tpm_quote_signature(&decoded, &nitro_doc);
        assert!(
            matches!(result, Err(VerifyError::SignatureInvalid(ref msg)) if msg.contains("does not match Nitro public_key binding")),
            "Expected AK mismatch error, got: {:?}",
            result
        );
    }
}
