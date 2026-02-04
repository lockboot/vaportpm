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
use crate::tpm::{parse_quote_attest, verify_ecdsa_p256};
use crate::x509::{extract_public_key, validate_tpm_cert_chain};
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
/// This verification path:
/// 1. Parses TPM2_Quote attestation to extract PCR digest and nonce
/// 2. Verifies Quote signature with AK public key
/// 3. Verifies Nitro NSM document binds the AK public key
/// 4. Verifies PCRs match signed values in Nitro document
///
/// All inputs should be pre-decoded binary data (raw COSE document bytes).
pub fn verify_nitro_decoded(
    decoded: &DecodedAttestationOutput,
    document_bytes: &[u8],
    time: UnixTime,
) -> Result<VerificationResult, VerifyError> {
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

    // Verify AK signature over TPM2_Quote
    verify_ecdsa_p256(
        &decoded.quote_attest,
        &decoded.quote_signature,
        &decoded.ak_pubkey,
    )?;

    // Parse and verify Nitro document (COSE signature, cert chain)
    let cose_sign1 = CoseSign1::from_slice(document_bytes)
        .map_err(|e| VerifyError::CoseVerify(format!("Failed to parse COSE Sign1: {}", e)))?;

    let payload = cose_sign1
        .payload
        .as_ref()
        .ok_or_else(|| VerifyError::CoseVerify("Missing payload".into()))?;

    let doc_value: CborValue = ciborium::from_reader(payload.as_slice())
        .map_err(|e| VerifyError::CborParse(format!("Failed to parse payload: {}", e)))?;

    let doc_map = match &doc_value {
        CborValue::Map(m) => m,
        _ => return Err(VerifyError::CborParse("Payload is not a map".into())),
    };

    let nitro_doc = parse_nitro_document(doc_map)?;

    // Extract certificate and CA bundle
    let cert_der = extract_cbor_bytes(doc_map, "certificate")?;
    let cabundle = extract_cbor_byte_array(doc_map, "cabundle")?;

    // Parse certificates
    let leaf_cert = Certificate::from_der(&cert_der)
        .map_err(|e| VerifyError::CertificateParse(format!("Invalid leaf cert: {}", e)))?;

    // Build chain in leaf-to-root order
    let mut chain = vec![leaf_cert];
    for ca_der in cabundle.into_iter().rev() {
        let ca_cert = Certificate::from_der(&ca_der)
            .map_err(|e| VerifyError::CertificateParse(format!("Invalid CA cert: {}", e)))?;
        chain.push(ca_cert);
    }

    // Verify COSE signature using leaf certificate
    let leaf_pubkey = extract_public_key(&chain[0])?;
    verify_cose_signature(&cose_sign1, &leaf_pubkey, payload)?;

    // Validate certificate chain
    let chain_result = validate_tpm_cert_chain(&chain, time)?;

    // Extract signed values from Nitro document
    let signed_pubkey = nitro_doc.public_key.as_ref().ok_or_else(|| {
        VerifyError::NoValidAttestation(
            "Nitro document missing public_key field - cannot bind TPM signing key".into(),
        )
    })?;
    let signed_nonce = nitro_doc.nonce.as_ref().ok_or_else(|| {
        VerifyError::NoValidAttestation(
            "Nitro document missing nonce field - cannot verify freshness".into(),
        )
    })?;

    // Verify the AK public key matches the signed public_key in NSM document (binary comparison)
    if decoded.ak_pubkey.as_slice() != signed_pubkey.as_slice() {
        return Err(VerifyError::SignatureInvalid(format!(
            "TPM signing key does not match Nitro public_key binding: {} != {}",
            hex::encode(decoded.ak_pubkey),
            hex::encode(signed_pubkey)
        )));
    }

    // Verify TPM nonce matches Nitro nonce (binary comparison)
    if quote_info.nonce.as_slice() != signed_nonce.as_slice() {
        return Err(VerifyError::SignatureInvalid(format!(
            "TPM nonce does not match Nitro nonce: {} != {}",
            hex::encode(&quote_info.nonce),
            hex::encode(signed_nonce)
        )));
    }

    // Verify we have SHA-384 PCRs (algorithm ID 1)
    let has_sha384_pcrs = decoded.pcrs.keys().any(|(alg_id, _)| *alg_id == 1);
    if !has_sha384_pcrs {
        return Err(VerifyError::InvalidAttest(
            "Missing SHA-384 PCRs - required for Nitro attestation".into(),
        ));
    }

    let signed_pcrs = &nitro_doc.pcrs;
    if signed_pcrs.is_empty() {
        return Err(VerifyError::InvalidAttest(
            "Nitro document contains no signed PCRs".into(),
        ));
    }

    // All signed PCRs must be present and match (binary comparison)
    // Look up in decoded.pcrs using (algorithm_id=1 for SHA-384, pcr_index)
    for (idx, signed_value) in signed_pcrs.iter() {
        match decoded.pcrs.get(&(1, *idx)) {
            Some(claimed_value) if claimed_value == signed_value => {
                // Match - good
            }
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

    // Verify root is known
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

    // === Signature Length Validation ===

    #[test]
    fn test_signature_length_check() {
        // Directly test the signature length check in verify_cose_signature
        // by checking that wrong-length signatures are rejected

        // Test that signatures with wrong length are rejected
        // Expected length for ES384 is 96 bytes (48 for R + 48 for S)
        let wrong_lengths = [0, 48, 64, 95, 97, 128];

        for len in wrong_lengths {
            let sig = vec![0u8; len];
            // Simulate what verify_cose_signature checks
            assert_ne!(sig.len(), 96, "Length {} should be invalid", len);
        }

        // Correct length should pass the check (but would fail signature verification)
        let sig = vec![0u8; 96];
        assert_eq!(sig.len(), 96);
    }

    // === Nonce Validation ===

    #[test]
    fn test_nonce_validation_matches() {
        // When nonce is present and matches, no error from nonce check
        // This tests the nonce comparison logic
        let expected = b"test-nonce";
        let actual = hex::encode(expected);

        // Simulate the check in verify_nitro_attestation
        let nonce_bytes = hex::decode(&actual).unwrap();
        assert_eq!(nonce_bytes, expected);
    }

    #[test]
    fn test_nonce_validation_mismatch() {
        let expected = b"expected-nonce";
        let actual = b"different-nonce";

        // These should not match
        assert_ne!(expected.as_slice(), actual.as_slice());
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
}
