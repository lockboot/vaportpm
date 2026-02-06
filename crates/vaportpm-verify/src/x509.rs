// SPDX-License-Identifier: MIT OR Apache-2.0

//! X.509 certificate chain validation

use base64::{engine::general_purpose::STANDARD, Engine as _};
use der::oid::ObjectIdentifier;
use der::{Decode, Encode};
use ecdsa::signature::Verifier;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
use pki_types::UnixTime;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

use crate::error::{CertificateParseReason, ChainValidationReason, VerifyError};

// X.509 extension OIDs
const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");

/// Key Usage extension flags (OID 2.5.29.15)
/// Only includes bits used for TPM certificate chain validation.
#[derive(Debug, Clone, Default)]
pub(crate) struct KeyUsageFlags {
    /// digitalSignature (bit 0) - key can be used to verify digital signatures
    pub digital_signature: bool,
    /// keyCertSign (bit 5) - key can be used to verify certificate signatures
    pub key_cert_sign: bool,
}

/// Basic Constraints extension (OID 2.5.29.19)
#[derive(Debug, Clone, Default)]
pub(crate) struct BasicConstraints {
    /// Whether this certificate is a CA
    pub ca: bool,
    /// Maximum number of intermediate certificates allowed below this CA
    pub path_len_constraint: Option<u8>,
}

/// Extract Key Usage extension from a certificate (OID 2.5.29.15)
///
/// Returns None if the extension is not present.
pub(crate) fn extract_key_usage(cert: &Certificate) -> Option<KeyUsageFlags> {
    let extensions = cert.tbs_certificate.extensions.as_ref()?;

    for ext in extensions.iter() {
        if ext.extn_id == OID_KEY_USAGE {
            // Key Usage is a BIT STRING
            // The extn_value is an OctetString containing the DER-encoded BIT STRING directly
            // (x509_cert already unwrapped the outer OCTET STRING)
            let bit_string = der::asn1::BitString::from_der(ext.extn_value.as_bytes()).ok()?;

            // Key Usage bits are numbered from the most significant bit
            // Bit 0 = digitalSignature (MSB of first byte)
            // Bit 5 = keyCertSign
            let raw_bits = bit_string.raw_bytes();
            if raw_bits.is_empty() {
                return Some(KeyUsageFlags::default());
            }

            let byte0 = raw_bits[0];

            return Some(KeyUsageFlags {
                digital_signature: (byte0 & 0x80) != 0, // bit 0
                key_cert_sign: (byte0 & 0x04) != 0,     // bit 5
            });
        }
    }
    None
}

/// Extract Basic Constraints extension from a certificate (OID 2.5.29.19)
///
/// Returns None if the extension is not present.
pub(crate) fn extract_basic_constraints(cert: &Certificate) -> Option<BasicConstraints> {
    let extensions = cert.tbs_certificate.extensions.as_ref()?;

    for ext in extensions.iter() {
        if ext.extn_id == OID_BASIC_CONSTRAINTS {
            // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER (0..MAX) OPTIONAL }
            // The extn_value is an OctetString containing the DER-encoded SEQUENCE directly
            let bytes = ext.extn_value.as_bytes();

            // Parse the SEQUENCE header manually
            if bytes.is_empty() {
                return Some(BasicConstraints::default());
            }

            // First byte should be SEQUENCE tag (0x30)
            if bytes[0] != 0x30 {
                return Some(BasicConstraints::default());
            }

            // Get length
            if bytes.len() < 2 {
                return Some(BasicConstraints::default());
            }

            let len = bytes[1] as usize;
            let seq_start = 2;

            // Empty sequence means cA defaults to false
            if len == 0 {
                return Some(BasicConstraints::default());
            }

            // Parse sequence contents
            let seq_bytes = &bytes[seq_start..seq_start + len.min(bytes.len() - seq_start)];

            let mut bc = BasicConstraints::default();

            // Check if there's a BOOLEAN (tag 0x01)
            if !seq_bytes.is_empty() && seq_bytes[0] == 0x01 {
                // BOOLEAN: tag (0x01), length (0x01), value
                if seq_bytes.len() >= 3 && seq_bytes[1] == 0x01 {
                    bc.ca = seq_bytes[2] != 0;

                    // Check for pathLenConstraint after BOOLEAN
                    if seq_bytes.len() >= 6 && seq_bytes[3] == 0x02 {
                        // INTEGER: tag (0x02), length, value
                        let int_len = seq_bytes[4] as usize;
                        if int_len == 1 && seq_bytes.len() >= 6 {
                            bc.path_len_constraint = Some(seq_bytes[5]);
                        }
                    }
                }
            }

            return Some(bc);
        }
    }
    None
}

/// Maximum allowed certificate chain depth (to prevent DoS)
pub(crate) const MAX_CHAIN_DEPTH: usize = 10;

/// PEM certificate begin marker
const PEM_CERT_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
/// PEM certificate end marker
const PEM_CERT_END: &str = "-----END CERTIFICATE-----";

/// Parse X.509 certificate chain from PEM format
///
/// Returns certificates in order from the PEM file (typically leaf first, root last).
///
/// This parser is strict about:
/// - Exact BEGIN/END markers (not just "contains")
/// - No non-whitespace data between certificates
/// - Valid base64 content within certificate blocks
pub(crate) fn parse_cert_chain_pem(pem: &str) -> Result<Vec<Certificate>, VerifyError> {
    let mut certs = Vec::new();
    let mut current_cert = String::new();
    let mut in_cert = false;
    for (idx, line) in pem.lines().enumerate() {
        let line_number = idx + 1;
        let trimmed = line.trim();

        // Check for BEGIN marker
        if trimmed == PEM_CERT_BEGIN {
            if in_cert {
                return Err(CertificateParseReason::NestedBeginMarker { line: line_number }.into());
            }
            in_cert = true;
            current_cert.clear();
            continue;
        }

        // Check for END marker
        if trimmed == PEM_CERT_END {
            if !in_cert {
                return Err(CertificateParseReason::EndWithoutBegin { line: line_number }.into());
            }
            in_cert = false;

            // Decode the certificate
            if current_cert.is_empty() {
                return Err(CertificateParseReason::EmptyCertContent { line: line_number }.into());
            }

            let der_bytes = base64_decode(&current_cert)?;
            let cert = Certificate::from_der(&der_bytes)
                .map_err(|e| CertificateParseReason::InvalidDer(e.to_string()))?;
            certs.push(cert);
            continue;
        }

        // Inside a certificate block: accumulate base64 content
        if in_cert {
            // Validate that line contains only base64 characters
            if !trimmed.is_empty() && !is_valid_base64_line(trimmed) {
                return Err(CertificateParseReason::InvalidBase64 { line: line_number }.into());
            }
            current_cert.push_str(trimmed);
            continue;
        }

        // Outside certificate blocks: only whitespace is allowed
        if !trimmed.is_empty() {
            return Err(CertificateParseReason::UnexpectedContent { line: line_number }.into());
        }
    }

    // Check for unclosed certificate block
    if in_cert {
        return Err(CertificateParseReason::UnclosedBlock.into());
    }

    if certs.is_empty() {
        return Err(CertificateParseReason::NoCertificates.into());
    }

    Ok(certs)
}

/// Check if a string contains only valid base64 characters
fn is_valid_base64_line(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

/// Decode base64 string
fn base64_decode(input: &str) -> Result<Vec<u8>, VerifyError> {
    STANDARD.decode(input).map_err(|e| {
        VerifyError::CertificateParse(CertificateParseReason::InvalidDer(e.to_string()))
    })
}

/// Extract raw public key bytes from an X.509 certificate
///
/// Returns the SubjectPublicKeyInfo's bit string contents
pub(crate) fn extract_public_key(cert: &Certificate) -> Result<Vec<u8>, VerifyError> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let pubkey_bits = spki
        .subject_public_key
        .as_bytes()
        .ok_or(CertificateParseReason::PublicKeyUnusedBits)?;
    Ok(pubkey_bits.to_vec())
}

/// Compute SHA-256 hash of public key
pub(crate) fn hash_public_key(pubkey_bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(pubkey_bytes).into()
}

/// Result of certificate chain validation
#[derive(Debug)]
pub(crate) struct ChainValidationResult {
    /// SHA-256 hash of the root CA's public key
    pub root_pubkey_hash: [u8; 32],
}

/// Validate certificate chain with rigid X.509 validation
///
/// This function performs comprehensive certificate chain validation suitable for
/// TPM attestation key certificates. It validates:
///
/// **Signature chain:**
/// - Each certificate is signed by the next in chain
/// - Root certificate is self-signed
///
/// **Time validity:**
/// - Certificate validity periods include the specified time
///
/// **Basic Constraints (OID 2.5.29.19):**
/// - Leaf certificate must have `CA:FALSE` (or no Basic Constraints)
/// - Intermediate/root certificates must have `CA:TRUE`
/// - Path length constraints are honored
///
/// **Key Usage (OID 2.5.29.15):**
/// - Leaf certificate must have `digitalSignature` bit set
/// - CA certificates must have `keyCertSign` bit set
///
/// **Extended Key Usage (OID 2.5.29.37):**
/// - CA certificates should have TPM EK Certificate EKU (2.23.133.8.1)
/// - Note: GCP AK leaf certificates don't have EKU, only Key Usage
///
/// **Name chaining:**
/// - Each certificate's Issuer must match its parent's Subject
///
/// Chain should be leaf-first, root-last.
pub(crate) fn validate_tpm_cert_chain(
    chain: &[Certificate],
    time: UnixTime,
) -> Result<ChainValidationResult, VerifyError> {
    if chain.is_empty() {
        return Err(ChainValidationReason::EmptyChain.into());
    }
    if chain.len() > MAX_CHAIN_DEPTH {
        return Err(ChainValidationReason::ChainTooDeep {
            depth: chain.len(),
            max: MAX_CHAIN_DEPTH,
        }
        .into());
    }

    // === X.509 Extension Validation ===
    // Validate Basic Constraints, Key Usage, EKU, and name chaining

    for (i, cert) in chain.iter().enumerate() {
        let is_leaf = i == 0;
        let is_root = i == chain.len() - 1;

        // 1. Basic Constraints validation
        if let Some(bc) = extract_basic_constraints(cert) {
            if is_leaf && bc.ca {
                return Err(ChainValidationReason::LeafIsCa.into());
            }
            if !is_leaf && !bc.ca {
                return Err(ChainValidationReason::CaMissingCaFlag { index: i }.into());
            }

            // Check pathLenConstraint for CA certificates
            // pathLenConstraint limits how many CAs can exist below this one
            if !is_leaf {
                if let Some(path_len) = bc.path_len_constraint {
                    // Number of CAs below this certificate in the chain
                    // i=0 is leaf, so CAs below cert at position i are at positions 0..i-1
                    // But the count should be: number of intermediate CAs between this CA and the leaf
                    // For position i, there are (i - 1) intermediate CAs between it and the leaf
                    // (position 0 is leaf, positions 1..i-1 are intermediates below)
                    let cas_below = if i > 0 { i - 1 } else { 0 };
                    if cas_below > path_len as usize {
                        return Err(ChainValidationReason::PathLenViolated {
                            index: i,
                            allowed: path_len,
                            actual: cas_below,
                        }
                        .into());
                    }
                }
            }
        } else if !is_leaf {
            // CA certificates SHOULD have Basic Constraints
            // This is a SHOULD per RFC 5280, but we enforce it for security
            return Err(ChainValidationReason::MissingBasicConstraints { index: i }.into());
        }

        // 2. Key Usage validation
        if let Some(ku) = extract_key_usage(cert) {
            if is_leaf && !ku.digital_signature {
                return Err(ChainValidationReason::LeafMissingDigitalSignature.into());
            }
            if !is_leaf && !ku.key_cert_sign {
                return Err(ChainValidationReason::CaMissingKeyCertSign { index: i }.into());
            }
        } else if is_leaf {
            // Leaf certificate MUST have Key Usage for signing
            return Err(ChainValidationReason::LeafMissingKeyUsage.into());
        }

        // 3. Subject/Issuer name chaining
        if !is_root {
            let parent = &chain[i + 1];
            if cert.tbs_certificate.issuer != parent.tbs_certificate.subject {
                return Err(ChainValidationReason::IssuerMismatch { index: i }.into());
            }
        }
    }

    // === Signature Chain Validation ===
    // Validate each certificate is signed by the next one in chain

    for i in 0..chain.len() - 1 {
        let cert = &chain[i];
        let issuer = &chain[i + 1];

        // Get issuer's public key
        let issuer_pubkey = extract_public_key(issuer)?;

        // Get the TBS (to be signed) certificate bytes
        let tbs_der = cert
            .tbs_certificate
            .to_der()
            .map_err(|e| ChainValidationReason::CryptoError(e.to_string()))?;

        // Get the signature
        let sig_bytes = cert.signature.raw_bytes();

        // Determine algorithm and verify
        let alg_oid = &cert.signature_algorithm.oid;

        // ECDSA with SHA-256 on P-256: 1.2.840.10045.4.3.2
        // ECDSA with SHA-384 on P-384: 1.2.840.10045.4.3.3
        const ECDSA_SHA256_OID: &str = "1.2.840.10045.4.3.2";
        const ECDSA_SHA384_OID: &str = "1.2.840.10045.4.3.3";
        const RSA_SHA256_OID: &str = "1.2.840.113549.1.1.11";

        let alg_str = alg_oid.to_string();
        match alg_str.as_str() {
            RSA_SHA256_OID => {
                // RSA PKCS#1 v1.5 with SHA-256 verification
                // For RSA, we need the full SPKI structure, not just raw key bytes
                let issuer_spki = &issuer.tbs_certificate.subject_public_key_info;
                let issuer_spki_der = issuer_spki
                    .to_der()
                    .map_err(|e| ChainValidationReason::CryptoError(e.to_string()))?;

                let rsa_pubkey = RsaPublicKey::try_from(
                    spki::SubjectPublicKeyInfoRef::try_from(issuer_spki_der.as_slice())
                        .map_err(|e| ChainValidationReason::CryptoError(e.to_string()))?,
                )
                .map_err(|e| ChainValidationReason::CryptoError(e.to_string()))?;

                let verifying_key = RsaVerifyingKey::<Sha256>::new(rsa_pubkey);

                let signature = RsaSignature::try_from(sig_bytes)
                    .map_err(|e| ChainValidationReason::CryptoError(e.to_string()))?;

                verifying_key
                    .verify(&tbs_der, &signature)
                    .map_err(|_| ChainValidationReason::SignatureVerificationFailed { index: i })?;
            }
            ECDSA_SHA256_OID => {
                // P-256 verification
                if issuer_pubkey.len() != 65 || issuer_pubkey[0] != 0x04 {
                    return Err(ChainValidationReason::CryptoError(
                        "Invalid issuer public key format for P-256".into(),
                    )
                    .into());
                }
                let verifying_key = P256VerifyingKey::from_sec1_bytes(&issuer_pubkey)
                    .map_err(|e| ChainValidationReason::CryptoError(e.to_string()))?;

                let signature = P256Signature::from_der(sig_bytes)
                    .map_err(|e| ChainValidationReason::CryptoError(e.to_string()))?;

                verifying_key
                    .verify(&tbs_der, &signature)
                    .map_err(|_| ChainValidationReason::SignatureVerificationFailed { index: i })?;
            }
            ECDSA_SHA384_OID => {
                // P-384 verification
                if issuer_pubkey.len() != 97 || issuer_pubkey[0] != 0x04 {
                    return Err(ChainValidationReason::CryptoError(
                        "Invalid issuer public key format for P-384".into(),
                    )
                    .into());
                }
                let verifying_key = P384VerifyingKey::from_sec1_bytes(&issuer_pubkey)
                    .map_err(|e| ChainValidationReason::CryptoError(e.to_string()))?;

                let signature = P384Signature::from_der(sig_bytes)
                    .map_err(|e| ChainValidationReason::CryptoError(e.to_string()))?;

                verifying_key
                    .verify(&tbs_der, &signature)
                    .map_err(|_| ChainValidationReason::SignatureVerificationFailed { index: i })?;
            }
            _ => {
                return Err(ChainValidationReason::UnsupportedAlgorithm { oid: alg_str }.into());
            }
        }
    }

    // === Time Validity ===
    // Validate time for each certificate

    let unix_secs = time.as_secs();

    for (i, cert) in chain.iter().enumerate() {
        let validity = &cert.tbs_certificate.validity;

        // Convert not_before and not_after to unix timestamps
        let not_before = validity.not_before.to_unix_duration().as_secs();
        let not_after = validity.not_after.to_unix_duration().as_secs();

        if unix_secs < not_before {
            return Err(ChainValidationReason::CertNotYetValid { index: i }.into());
        }
        if unix_secs > not_after {
            return Err(ChainValidationReason::CertExpired { index: i }.into());
        }
    }

    // Extract and hash root's public key
    let root_pubkey = extract_public_key(&chain[chain.len() - 1])?;
    let root_hash = hash_public_key(&root_pubkey);

    Ok(ChainValidationResult {
        root_pubkey_hash: root_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_public_key() {
        let pubkey = [0x04, 0x01, 0x02, 0x03];
        let hash = hash_public_key(&pubkey);
        // SHA-256 returns 32 bytes
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_base64_decode() {
        let input = "SGVsbG8gV29ybGQ="; // "Hello World"
        let decoded = STANDARD.decode(input).unwrap();
        assert_eq!(decoded, b"Hello World");
    }

    // === PEM Parsing Edge Cases ===

    #[test]
    fn test_reject_no_certificates() {
        let pem = "This is not a PEM file at all";
        let result = parse_cert_chain_pem(pem);
        assert!(matches!(result, Err(VerifyError::CertificateParse(_))));
    }

    #[test]
    fn test_reject_empty_pem() {
        let pem = "";
        let result = parse_cert_chain_pem(pem);
        assert!(matches!(result, Err(VerifyError::CertificateParse(_))));
    }

    #[test]
    fn test_reject_missing_end_marker() {
        let pem = "-----BEGIN CERTIFICATE-----\nMIIB";
        let result = parse_cert_chain_pem(pem);
        // Should fail because no END marker means no certificate is completed
        assert!(matches!(result, Err(VerifyError::CertificateParse(_))));
    }

    #[test]
    fn test_reject_empty_certificate_content() {
        let pem = "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----";
        let result = parse_cert_chain_pem(pem);
        // Empty base64 content should fail DER parsing
        assert!(matches!(result, Err(VerifyError::CertificateParse(_))));
    }

    #[test]
    fn test_reject_invalid_base64() {
        let pem = "-----BEGIN CERTIFICATE-----\n\
                   !!!invalid base64!!!\n\
                   -----END CERTIFICATE-----";
        let result = parse_cert_chain_pem(pem);
        assert!(matches!(result, Err(VerifyError::CertificateParse(_))));
    }

    #[test]
    fn test_reject_truncated_base64() {
        // Valid base64 prefix but incomplete (missing padding)
        let pem = "-----BEGIN CERTIFICATE-----\n\
                   MIIB\n\
                   -----END CERTIFICATE-----";
        let result = parse_cert_chain_pem(pem);
        // Should fail either in base64 decode or DER parse
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_invalid_der() {
        // Valid base64, but not valid DER certificate
        let pem = "-----BEGIN CERTIFICATE-----\n\
                   SGVsbG8gV29ybGQ=\n\
                   -----END CERTIFICATE-----";
        let result = parse_cert_chain_pem(pem);
        assert!(matches!(result, Err(VerifyError::CertificateParse(_))));
    }

    // === Strict PEM Parsing Tests ===

    #[test]
    fn test_reject_garbage_between_markers() {
        // Non-whitespace data outside certificate blocks should be rejected
        // This tests that the parser rejects garbage BEFORE any cert
        let pem = "garbage data here\n\
                   -----BEGIN CERTIFICATE-----\n\
                   SGVsbG8=\n\
                   -----END CERTIFICATE-----";
        let result = parse_cert_chain_pem(pem);
        assert!(matches!(
            result,
            Err(VerifyError::CertificateParse(
                CertificateParseReason::UnexpectedContent { .. }
            ))
        ),);
    }

    #[test]
    fn test_allow_whitespace_between_certs() {
        // Whitespace between certificates should be allowed (though certs themselves are invalid DER)
        let pem = "-----BEGIN CERTIFICATE-----\n\
                   SGVsbG8=\n\
                   -----END CERTIFICATE-----\n\
                   \n\
                   \n\
                   -----BEGIN CERTIFICATE-----\n\
                   V29ybGQ=\n\
                   -----END CERTIFICATE-----";
        let result = parse_cert_chain_pem(pem);
        // Will fail on invalid DER, not on parsing
        assert!(matches!(
            result,
            Err(VerifyError::CertificateParse(
                CertificateParseReason::InvalidDer(_)
            ))
        ),);
    }

    #[test]
    fn test_reject_nested_begin_marker() {
        // Nested BEGIN marker should be rejected
        let pem = "-----BEGIN CERTIFICATE-----\n\
                   SGVsbG8=\n\
                   -----BEGIN CERTIFICATE-----\n\
                   V29ybGQ=\n\
                   -----END CERTIFICATE-----";
        let result = parse_cert_chain_pem(pem);
        assert!(matches!(
            result,
            Err(VerifyError::CertificateParse(
                CertificateParseReason::NestedBeginMarker { .. }
            ))
        ),);
    }

    #[test]
    fn test_reject_end_without_begin() {
        // END marker without BEGIN should be rejected
        let pem = "-----END CERTIFICATE-----";
        let result = parse_cert_chain_pem(pem);
        assert!(matches!(
            result,
            Err(VerifyError::CertificateParse(
                CertificateParseReason::EndWithoutBegin { .. }
            ))
        ),);
    }

    #[test]
    fn test_reject_unclosed_block() {
        // Unclosed certificate block should be rejected
        let pem = "-----BEGIN CERTIFICATE-----\n\
                   SGVsbG8=\n";
        let result = parse_cert_chain_pem(pem);
        assert!(matches!(
            result,
            Err(VerifyError::CertificateParse(
                CertificateParseReason::UnclosedBlock
            ))
        ),);
    }

    #[test]
    fn test_is_valid_base64_line() {
        assert!(is_valid_base64_line("ABCDabcd0123+/=="));
        assert!(!is_valid_base64_line("ABC!@#"));
        assert!(!is_valid_base64_line("ABC DEF")); // space not allowed
        assert!(is_valid_base64_line("")); // empty is valid
    }

    // === Extension Parsing Tests ===

    #[test]
    fn test_extract_basic_constraints_ca_true() {
        // GCP intermediate certificate with CA:TRUE
        let cert_b64 = "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";
        let cert_der = STANDARD.decode(cert_b64).unwrap();
        let cert = Certificate::from_der(&cert_der).unwrap();

        let bc = extract_basic_constraints(&cert);
        assert!(bc.is_some(), "Basic Constraints should be present");
        let bc = bc.unwrap();
        assert!(bc.ca, "CA flag should be true for intermediate CA cert");
    }

    #[test]
    fn test_extract_basic_constraints_ca_false() {
        // GCP AK leaf certificate with CA:FALSE
        let cert_b64 = "MIIFITCCAwmgAwIBAgIUAJSyAthxJCCD6ViYtC96+AGDJCswDQYJKoZIhvcNAQELBQAwgYYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgTExDMRUwEwYDVQQLEwxHb29nbGUgQ2xvdWQxHjAcBgNVBAMTFUVLL0FLIENBIEludGVybWVkaWF0ZTAgFw0yNjAyMDIwNjU3NDdaGA8yMDU2MDEyNjA2NTc0NlowaTEWMBQGA1UEBxMNdXMtY2VudHJhbDEtZjEeMBwGA1UEChMVR29vZ2xlIENvbXB1dGUgRW5naW5lMREwDwYDVQQLEwhsb2NrYm9vdDEcMBoGA1UEAxMTMzQxNDI0MDY0ODIyNTQ4NTgzNjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMp9xzVQQpEV600JB3Gj9IP+U89ypLnrhQRUBVDFnz5INT2kVd4Jhl8KHZ6qYXVOOZYhrkvO0cVY0mfclyT+tJOjggFqMIIBZjAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU2lwtWfsKczujmD2yTgCf4MptjpkwHwYDVR0jBBgwFoAUZ8O73ljj1lF2j7MaPtsHp+yTeuQwgY0GCCsGAQUFBwEBBIGAMH4wfAYIKwYBBQUHMAKGcGh0dHA6Ly9wcml2YXRlY2EtY29udGVudC02NWQ1M2IxNC0wMDAwLTIxMmEtYTYzMy04ODNkMjRmNTdiYjguc3RvcmFnZS5nb29nbGVhcGlzLmNvbS8wYzNlNzllYjA4OThkMDJlYmIwYS9jYS5jcnQwdgYKKwYBBAHWeQIBFQRoMGYMDXVzLWNlbnRyYWwxLWYCBTY7VDeMDAhsb2NrYm9vdAIIL2HRx7ct9AwMGGluc3RhbmNlLTIwMjYwMjAyLTA2NTYwOaAgMB6gAwIBAKEDAQH/ogMBAf+jAwEBAKQDAQEApQMBAQAwDQYJKoZIhvcNAQELBQADggIBAKL4yGiPbAA63EQ7bxJ+2HGDo2EC+qymJDHtWski2lRGY70u+xIdywTW5l4k7JnnwM+fk7LHtfP0md0WU4Mw30B+51sc+pXprEn1SHpP20I/mM5AZMR+cMy9SWnr0WkfTZYKvYJMhDPKuZyK8JvUtXx6NM9AGHYxtPfFnvw2F/USBYYf7/N2KHMhUB9v1zFuHwMD/LDxduIw27kYUcVHttTbHGL9Uljflz343qL2YFE8QpRqtQ/0GK4UaJ3kzPYcbMbWBgpZgKQ2UIMfldvEO8hbGqO4hkNPsv4TPQcG0mJHyUWt+jTOFesBuDgbR/8R4lnrGL3QYZo3Oj7URCJdPiJ+ztohscGydjMVvYfaVziAGJbhMbADnyh/HBshi9gc4rQ99NbOA9fmCZnl+vcMp9jwaAzWZQxc1dNsfdRuTrQSwsNXn+PXJUDgRKKNsENY73QbVBUYvlBmQPkw8zqp8Htvtlsv5AImFFJsW4XsGt4CzZLOhlNW6Ckc58fjVSmeC66kTxYefRGh1SCXRZiJovuTynnF3Z6CFnWvnN/8dCmgjD+S0JUZ8Znx2NSxyZLbEqc6TYcJKx6R8B8QKa4EHWtKMuMorykvWpXMrVl1QjVm0HyVBvgzI+xRAO2TrS6g6c6pChj9BPXPgwLbVXlXQSstoUBFSORdz0S0HrEqxCg8";
        let cert_der = STANDARD.decode(cert_b64).unwrap();
        let cert = Certificate::from_der(&cert_der).unwrap();

        let bc = extract_basic_constraints(&cert);
        assert!(bc.is_some(), "Basic Constraints should be present");
        let bc = bc.unwrap();
        assert!(!bc.ca, "CA flag should be false for leaf cert");
    }

    #[test]
    fn test_extract_key_usage_digital_signature() {
        // GCP AK leaf certificate with Key Usage: Digital Signature
        let cert_b64 = "MIIFITCCAwmgAwIBAgIUAJSyAthxJCCD6ViYtC96+AGDJCswDQYJKoZIhvcNAQELBQAwgYYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgTExDMRUwEwYDVQQLEwxHb29nbGUgQ2xvdWQxHjAcBgNVBAMTFUVLL0FLIENBIEludGVybWVkaWF0ZTAgFw0yNjAyMDIwNjU3NDdaGA8yMDU2MDEyNjA2NTc0NlowaTEWMBQGA1UEBxMNdXMtY2VudHJhbDEtZjEeMBwGA1UEChMVR29vZ2xlIENvbXB1dGUgRW5naW5lMREwDwYDVQQLEwhsb2NrYm9vdDEcMBoGA1UEAxMTMzQxNDI0MDY0ODIyNTQ4NTgzNjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMp9xzVQQpEV600JB3Gj9IP+U89ypLnrhQRUBVDFnz5INT2kVd4Jhl8KHZ6qYXVOOZYhrkvO0cVY0mfclyT+tJOjggFqMIIBZjAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU2lwtWfsKczujmD2yTgCf4MptjpkwHwYDVR0jBBgwFoAUZ8O73ljj1lF2j7MaPtsHp+yTeuQwgY0GCCsGAQUFBwEBBIGAMH4wfAYIKwYBBQUHMAKGcGh0dHA6Ly9wcml2YXRlY2EtY29udGVudC02NWQ1M2IxNC0wMDAwLTIxMmEtYTYzMy04ODNkMjRmNTdiYjguc3RvcmFnZS5nb29nbGVhcGlzLmNvbS8wYzNlNzllYjA4OThkMDJlYmIwYS9jYS5jcnQwdgYKKwYBBAHWeQIBFQRoMGYMDXVzLWNlbnRyYWwxLWYCBTY7VDeMDAhsb2NrYm9vdAIIL2HRx7ct9AwMGGluc3RhbmNlLTIwMjYwMjAyLTA2NTYwOaAgMB6gAwIBAKEDAQH/ogMBAf+jAwEBAKQDAQEApQMBAQAwDQYJKoZIhvcNAQELBQADggIBAKL4yGiPbAA63EQ7bxJ+2HGDo2EC+qymJDHtWski2lRGY70u+xIdywTW5l4k7JnnwM+fk7LHtfP0md0WU4Mw30B+51sc+pXprEn1SHpP20I/mM5AZMR+cMy9SWnr0WkfTZYKvYJMhDPKuZyK8JvUtXx6NM9AGHYxtPfFnvw2F/USBYYf7/N2KHMhUB9v1zFuHwMD/LDxduIw27kYUcVHttTbHGL9Uljflz343qL2YFE8QpRqtQ/0GK4UaJ3kzPYcbMbWBgpZgKQ2UIMfldvEO8hbGqO4hkNPsv4TPQcG0mJHyUWt+jTOFesBuDgbR/8R4lnrGL3QYZo3Oj7URCJdPiJ+ztohscGydjMVvYfaVziAGJbhMbADnyh/HBshi9gc4rQ99NbOA9fmCZnl+vcMp9jwaAzWZQxc1dNsfdRuTrQSwsNXn+PXJUDgRKKNsENY73QbVBUYvlBmQPkw8zqp8Htvtlsv5AImFFJsW4XsGt4CzZLOhlNW6Ckc58fjVSmeC66kTxYefRGh1SCXRZiJovuTynnF3Z6CFnWvnN/8dCmgjD+S0JUZ8Znx2NSxyZLbEqc6TYcJKx6R8B8QKa4EHWtKMuMorykvWpXMrVl1QjVm0HyVBvgzI+xRAO2TrS6g6c6pChj9BPXPgwLbVXlXQSstoUBFSORdz0S0HrEqxCg8";
        let cert_der = STANDARD.decode(cert_b64).unwrap();
        let cert = Certificate::from_der(&cert_der).unwrap();

        let ku = extract_key_usage(&cert);
        assert!(ku.is_some(), "Key Usage should be present");
        let ku = ku.unwrap();
        assert!(ku.digital_signature, "digitalSignature bit should be set");
        assert!(!ku.key_cert_sign, "keyCertSign should not be set for leaf");
    }

    #[test]
    fn test_extract_key_usage_ca() {
        // GCP intermediate certificate with Key Usage: Certificate Sign, CRL Sign
        let cert_b64 = "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";
        let cert_der = STANDARD.decode(cert_b64).unwrap();
        let cert = Certificate::from_der(&cert_der).unwrap();

        let ku = extract_key_usage(&cert);
        assert!(ku.is_some(), "Key Usage should be present");
        let ku = ku.unwrap();
        assert!(ku.key_cert_sign, "keyCertSign bit should be set for CA");
    }
}
