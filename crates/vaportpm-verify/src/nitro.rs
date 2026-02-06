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

use crate::error::{
    CborParseReason, CertificateParseReason, ChainValidationReason, CoseVerifyReason,
    InvalidAttestReason, PcrIndexOutOfBoundsReason, SignatureInvalidReason, VerifyError,
};
use crate::pcr::PcrAlgorithm;
use crate::tpm::{verify_quote, TpmQuoteInfo};
use crate::x509::{extract_public_key, validate_tpm_cert_chain};
use crate::CloudProvider;
use crate::{roots, DecodedAttestationOutput, VerificationResult};

/// Parsed Nitro attestation document (internal)
#[derive(Debug, Clone)]
struct NitroDocument {
    /// TPM PCR values from Nitro document's `nitrotpm_pcrs` field (index -> SHA-384 digest)
    /// These are the PCR values signed by AWS hardware.
    pub pcrs: BTreeMap<u8, Vec<u8>>,
    /// AK public key bound by the Nitro document (raw SEC1 bytes)
    pub public_key: Vec<u8>,
    /// Nonce signed by the Nitro document (raw bytes)
    pub nonce: Vec<u8>,
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

    // === Phase 2: AK binding — Nitro document must agree on which key signed the Quote ===
    let ak_sec1 = decoded.ak_pubkey.to_sec1_uncompressed();
    if ak_sec1.as_slice() != nitro_doc.public_key.as_slice() {
        return Err(SignatureInvalidReason::AkPublicKeyMismatch.into());
    }

    // === Phase 3: Verify TPM Quote (signature, PCR bank, nonce, PCR digest) ===
    let quote_info = verify_quote(decoded, PcrAlgorithm::Sha384)?;

    // === Phase 4: Cross-verify Nitro-specific bindings ===
    verify_nitro_bindings(decoded, &quote_info, &nitro_doc)?;

    // Convert nonce to fixed-size array
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
        .map_err(|e| CoseVerifyReason::CoseSign1ParseFailed(e.to_string()))?;

    let payload = cose_sign1
        .payload
        .as_ref()
        .ok_or(CoseVerifyReason::MissingPayload)?;

    // Minimal parse: extract only the certificate and CA bundle needed
    // to verify the COSE signature. We don't touch semantic fields yet.
    let payload_cbor: CborValue = ciborium::from_reader(payload.as_slice())
        .map_err(|e| CborParseReason::DeserializeFailed(e.to_string()))?;

    let payload_map = match &payload_cbor {
        CborValue::Map(m) => m,
        _ => return Err(CborParseReason::PayloadNotMap.into()),
    };

    let cert_der = extract_cbor_bytes(payload_map, "certificate")?;
    let cabundle = extract_cbor_byte_array(payload_map, "cabundle")?;

    // Build certificate chain (leaf first)
    let leaf_cert = Certificate::from_der(&cert_der)
        .map_err(|e| CertificateParseReason::InvalidDer(e.to_string()))?;

    let mut chain = vec![leaf_cert];
    for ca_der in cabundle.into_iter().rev() {
        let ca_cert = Certificate::from_der(&ca_der)
            .map_err(|e| CertificateParseReason::InvalidDer(e.to_string()))?;
        chain.push(ca_cert);
    }

    // Verify COSE signature
    let leaf_pubkey = extract_public_key(&chain[0])?;
    verify_cose_signature(&cose_sign1, &leaf_pubkey, payload)?;

    // Validate certificate chain and time validity
    let chain_result = validate_tpm_cert_chain(&chain, time)?;

    // Verify root is a known AWS root
    let provider = roots::provider_from_hash(&chain_result.root_pubkey_hash).ok_or_else(|| {
        VerifyError::ChainValidation(ChainValidationReason::UnknownRootCa {
            hash: hex::encode(chain_result.root_pubkey_hash),
        })
    })?;

    if provider != CloudProvider::Aws {
        return Err(ChainValidationReason::WrongProvider {
            expected: CloudProvider::Aws,
            got: provider,
        }
        .into());
    }

    // --- COSE document is now authenticated; safe to parse its contents ---
    let nitro_doc = parse_nitro_document(payload_map)?;

    Ok((nitro_doc, provider))
}

/// Cross-verify Nitro-specific bindings after the TPM Quote has been authenticated.
///
/// At this point the COSE document (AWS-signed) and TPM Quote (AK-signed) are
/// both authenticated. This verifies Nitro-specific consistency:
/// - COSE nonce matches Quote nonce
/// - PCR bank is SHA-384 (Nitro requirement)
/// - COSE-signed PCR values match decoded PCR values (bidirectional)
fn verify_nitro_bindings(
    decoded: &DecodedAttestationOutput,
    quote_info: &TpmQuoteInfo,
    nitro_doc: &NitroDocument,
) -> Result<(), VerifyError> {
    // --- Nonce: COSE document must agree with authenticated Quote ---
    if quote_info.nonce.as_slice() != nitro_doc.nonce.as_slice() {
        return Err(SignatureInvalidReason::NitroNonceMismatch.into());
    }

    // --- Bidirectional PCR match against COSE-signed values ---
    let signed_pcrs = &nitro_doc.pcrs;
    if signed_pcrs.is_empty() {
        return Err(InvalidAttestReason::EmptySignedPcrs.into());
    }

    // Forward: every COSE-signed PCR must match the decoded value
    for (idx, signed_value) in signed_pcrs.iter() {
        let claimed_value = decoded.pcrs.get(*idx as usize);
        if claimed_value != signed_value.as_slice() {
            return Err(SignatureInvalidReason::PcrValueMismatch { index: *idx }.into());
        }
    }

    // Reverse: every decoded PCR index must be present in COSE-signed PCRs
    for pcr_idx in 0..24u8 {
        if !signed_pcrs.contains_key(&pcr_idx) {
            return Err(InvalidAttestReason::PcrNotSigned { pcr_index: pcr_idx }.into());
        }
    }

    Ok(())
}

/// Parse Nitro document fields from CBOR map
fn parse_nitro_document(map: &[(CborValue, CborValue)]) -> Result<NitroDocument, VerifyError> {
    // Verify digest algorithm is SHA384 as expected
    let digest = extract_cbor_text(map, "digest")?;
    if digest != "SHA384" {
        return Err(InvalidAttestReason::WrongDigestAlgorithm { got: digest }.into());
    }

    // Parse PCRs (binary)
    let pcrs = extract_cbor_pcrs(map)?;

    // Required fields (binary)
    let public_key = extract_cbor_bytes(map, "public_key")?;
    let nonce = extract_cbor_bytes(map, "nonce")?;

    Ok(NitroDocument {
        pcrs,
        public_key,
        nonce,
    })
}

/// Extract text field from CBOR map
fn extract_cbor_text(
    map: &[(CborValue, CborValue)],
    key: &'static str,
) -> Result<String, VerifyError> {
    for (k, v) in map {
        if let CborValue::Text(k_text) = k {
            if k_text == key {
                if let CborValue::Text(val) = v {
                    return Ok(val.clone());
                }
            }
        }
    }
    Err(CborParseReason::MissingField { field: key }.into())
}

/// Extract bytes field from CBOR map
fn extract_cbor_bytes(
    map: &[(CborValue, CborValue)],
    key: &'static str,
) -> Result<Vec<u8>, VerifyError> {
    for (k, v) in map {
        if let CborValue::Text(k_text) = k {
            if k_text == key {
                if let CborValue::Bytes(val) = v {
                    return Ok(val.clone());
                }
            }
        }
    }
    Err(CborParseReason::MissingField { field: key }.into())
}

/// Extract byte array field from CBOR map
fn extract_cbor_byte_array(
    map: &[(CborValue, CborValue)],
    key: &'static str,
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
    Err(CborParseReason::MissingField { field: key }.into())
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
                                    return Err(PcrIndexOutOfBoundsReason::Negative {
                                        index: idx_i128,
                                    }
                                    .into());
                                }
                                if idx_i128 > max_index as i128 {
                                    return Err(PcrIndexOutOfBoundsReason::ExceedsMaximum {
                                        index: idx_i128,
                                        maximum: max_index,
                                    }
                                    .into());
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
    Err(CborParseReason::MissingPcrs.into())
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
    let protected = cose
        .protected
        .clone()
        .to_vec()
        .map_err(|e| CoseVerifyReason::ProtectedHeaderSerializeFailed(e.to_string()))?;

    let sig_structure = CborValue::Array(vec![
        CborValue::Text("Signature1".to_string()),
        CborValue::Bytes(protected),
        CborValue::Bytes(vec![]), // external_aad
        CborValue::Bytes(payload.to_vec()),
    ]);

    let mut sig_structure_bytes = Vec::new();
    ciborium::into_writer(&sig_structure, &mut sig_structure_bytes)
        .map_err(|e| CoseVerifyReason::SigStructureEncodeFailed(e.to_string()))?;

    // Hash the Sig_structure
    let digest = Sha384::digest(&sig_structure_bytes);

    // Parse the public key
    let verifying_key = P384VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| CoseVerifyReason::InvalidP384Key(e.to_string()))?;

    // Parse the signature (raw r||s format for COSE, not DER)
    let sig_bytes = &cose.signature;
    if sig_bytes.len() != 96 {
        return Err(CoseVerifyReason::InvalidSignatureLength {
            expected: 96,
            got: sig_bytes.len(),
        }
        .into());
    }

    // Convert raw r||s to DER format for the ecdsa crate
    let signature = P384Signature::from_slice(sig_bytes)
        .map_err(|e| CoseVerifyReason::InvalidSignature(e.to_string()))?;

    verifying_key
        .verify_prehash(&digest, &signature)
        .map_err(|e| CoseVerifyReason::SignatureVerificationFailed(e.to_string()))?;

    Ok(())
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
        assert!(matches!(
            result,
            Err(VerifyError::CborParse(CborParseReason::MissingField { .. }))
        ));
    }

    #[test]
    fn test_extract_cbor_text_wrong_type() {
        let map = vec![(
            CborValue::Text("wrong".to_string()),
            CborValue::Integer(123.into()),
        )];
        let result = extract_cbor_text(&map, "wrong");
        assert!(matches!(
            result,
            Err(VerifyError::CborParse(CborParseReason::MissingField { .. }))
        ));
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
        assert!(matches!(
            result,
            Err(VerifyError::CborParse(CborParseReason::MissingField { .. }))
        ));
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
        assert!(matches!(
            result,
            Err(VerifyError::CborParse(CborParseReason::MissingPcrs))
        ));
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
        assert!(matches!(
            result,
            Err(VerifyError::PcrIndexOutOfBounds(
                PcrIndexOutOfBoundsReason::ExceedsMaximum { .. }
            ))
        ));
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
        assert!(matches!(
            result,
            Err(VerifyError::PcrIndexOutOfBounds(
                PcrIndexOutOfBoundsReason::ExceedsMaximum { .. }
            ))
        ));
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
        assert!(matches!(
            result,
            Err(VerifyError::PcrIndexOutOfBounds(
                PcrIndexOutOfBoundsReason::Negative { .. }
            ))
        ));
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
            matches!(
                result,
                Err(VerifyError::InvalidAttest(
                    InvalidAttestReason::WrongDigestAlgorithm { .. }
                ))
            ),
            "Should reject SHA256 digest, got: {:?}",
            result
        );
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

    // verify_nitro_bindings and verify_tpm_quote_signature error paths are
    // tested through the public API in ephemeral_nitro_tests.rs.
}
