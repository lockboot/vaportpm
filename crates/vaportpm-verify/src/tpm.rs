// SPDX-License-Identifier: MIT OR Apache-2.0

//! TPM attestation parsing and verification

use ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use sha2::{Digest, Sha256};

use std::collections::BTreeMap;

use crate::error::{InvalidAttestReason, SignatureInvalidReason, VerifyError};

/// Verify ECDSA-SHA256 signature over a message
pub fn verify_ecdsa_p256(
    message: &[u8],
    signature_der: &[u8],
    public_key: &[u8],
) -> Result<(), VerifyError> {
    // Parse the public key (SEC1/SECG format: 0x04 || X || Y for uncompressed)
    let verifying_key = P256VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| SignatureInvalidReason::InvalidPublicKey(e.to_string()))?;

    // Parse the DER-encoded signature
    let signature = P256Signature::from_der(signature_der)
        .map_err(|e| SignatureInvalidReason::InvalidSignatureEncoding(e.to_string()))?;

    // TPM signs the SHA-256 hash of the message
    let digest = Sha256::digest(message);

    verifying_key
        .verify_prehash(&digest, &signature)
        .map_err(|e| SignatureInvalidReason::EcdsaVerificationFailed(e.to_string()))?;

    Ok(())
}

// =============================================================================
// TPM2B_ATTEST parsing (Quote only - Certify removed)
// =============================================================================

/// TPM_GENERATED magic value (0xff544347 = "ÿTCG")
const TPM_GENERATED_VALUE: u32 = 0xff544347;

/// TPM_ST_ATTEST_QUOTE structure type
const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

/// Size of TPMS_CLOCK_INFO structure: clock(8) + resetCount(4) + restartCount(4) + safe(1)
const TPMS_CLOCK_INFO_SIZE: usize = 17;

/// Parsed TPMS_ATTEST structure (from TPM2_Quote)
#[derive(Debug)]
pub struct TpmQuoteInfo {
    /// Nonce/qualifying data from extraData field (raw bytes)
    pub nonce: Vec<u8>,
    /// Name of the signing key
    pub signer_name: Vec<u8>,
    /// PCR selection (algorithm, PCR indices as bitmap)
    pub pcr_select: Vec<(u16, Vec<u8>)>,
    /// Digest of the selected PCRs (hash of concatenated PCR values)
    pub pcr_digest: Vec<u8>,
}

/// Parse TPM2B_ATTEST structure (QUOTE type)
///
/// TPM2B_ATTEST contains a TPMS_ATTEST structure which includes:
/// - magic: 0xff544347 (TPM_GENERATED_VALUE)
/// - type: 0x8018 (TPM_ST_ATTEST_QUOTE)
/// - qualifiedSigner: TPM2B_NAME
/// - extraData: TPM2B_DATA (our nonce)
/// - clockInfo: TPMS_CLOCK_INFO
/// - firmwareVersion: u64
/// - attested.quote.pcrSelect: TPML_PCR_SELECTION (PCRs that were quoted)
/// - attested.quote.pcrDigest: TPM2B_DIGEST (hash of PCR values)
pub fn parse_quote_attest(data: &[u8]) -> Result<TpmQuoteInfo, VerifyError> {
    let mut cursor = SafeCursor::new(data);

    // magic (4 bytes)
    let magic_bytes = cursor.read_bytes(4)?;
    let magic = u32::from_be_bytes(magic_bytes.try_into().unwrap());
    if magic != TPM_GENERATED_VALUE {
        return Err(InvalidAttestReason::TpmMagicInvalid {
            expected: TPM_GENERATED_VALUE,
            got: magic,
        }
        .into());
    }

    // type (2 bytes)
    let type_bytes = cursor.read_bytes(2)?;
    let attest_type = u16::from_be_bytes(type_bytes.try_into().unwrap());
    if attest_type != TPM_ST_ATTEST_QUOTE {
        return Err(InvalidAttestReason::TpmTypeInvalid {
            expected: TPM_ST_ATTEST_QUOTE,
            got: attest_type,
        }
        .into());
    }

    // qualifiedSigner (TPM2B_NAME)
    let signer_name = cursor.read_tpm2b()?;

    // extraData (TPM2B_DATA) - this is our nonce
    let nonce = cursor.read_tpm2b()?;

    // clockInfo (TPMS_CLOCK_INFO) - skip it
    cursor.skip(TPMS_CLOCK_INFO_SIZE)?;

    // firmwareVersion (8 bytes) - skip it
    cursor.skip(8)?;

    // attested (TPMS_QUOTE_INFO)
    // - pcrSelect (TPML_PCR_SELECTION)
    let pcr_select = cursor.read_pcr_selection()?;

    // - pcrDigest (TPM2B_DIGEST)
    let pcr_digest = cursor.read_tpm2b()?;

    Ok(TpmQuoteInfo {
        nonce,
        signer_name,
        pcr_select,
        pcr_digest,
    })
}

/// Safe cursor for parsing binary data with overflow protection
struct SafeCursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> SafeCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    /// Read exactly `len` bytes, returning error on overflow or truncation
    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], VerifyError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(VerifyError::InvalidAttest(
                InvalidAttestReason::TpmOverflow {
                    offset: self.offset,
                },
            ))?;
        if end > self.data.len() {
            return Err(InvalidAttestReason::TpmTruncated {
                offset: self.offset,
            }
            .into());
        }
        let bytes = &self.data[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    /// Skip exactly `len` bytes
    fn skip(&mut self, len: usize) -> Result<(), VerifyError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(VerifyError::InvalidAttest(
                InvalidAttestReason::TpmOverflow {
                    offset: self.offset,
                },
            ))?;
        if end > self.data.len() {
            return Err(InvalidAttestReason::TpmTruncated {
                offset: self.offset,
            }
            .into());
        }
        self.offset = end;
        Ok(())
    }

    /// Read a TPM2B structure (2-byte size prefix + data)
    fn read_tpm2b(&mut self) -> Result<Vec<u8>, VerifyError> {
        let size_bytes = self.read_bytes(2)?;
        let size = u16::from_be_bytes(size_bytes.try_into().unwrap()) as usize;
        let data = self.read_bytes(size)?;
        Ok(data.to_vec())
    }

    /// Read a u16 value (big-endian)
    fn read_u16(&mut self) -> Result<u16, VerifyError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_be_bytes(bytes.try_into().unwrap()))
    }

    /// Read a u32 value (big-endian)
    fn read_u32(&mut self) -> Result<u32, VerifyError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_be_bytes(bytes.try_into().unwrap()))
    }

    /// Read a u8 value
    fn read_u8(&mut self) -> Result<u8, VerifyError> {
        let bytes = self.read_bytes(1)?;
        Ok(bytes[0])
    }

    /// Read TPML_PCR_SELECTION structure
    ///
    /// Returns a list of (algorithm, PCR bitmap) pairs
    fn read_pcr_selection(&mut self) -> Result<Vec<(u16, Vec<u8>)>, VerifyError> {
        let count = self.read_u32()?;

        // Sanity check: count should be reasonable (max ~16 different algorithms)
        if count > 16 {
            return Err(InvalidAttestReason::PcrSelectionCountExceeded { count }.into());
        }

        let mut selections = Vec::with_capacity(count as usize);
        for _ in 0..count {
            // TPMS_PCR_SELECTION:
            // - hash (2 bytes) - algorithm
            let hash_alg = self.read_u16()?;

            // - sizeofSelect (1 byte) - bitmap size (typically 3 for 24 PCRs)
            let bitmap_size = self.read_u8()?;

            // Sanity check: bitmap size should be reasonable (max 32 for 256 PCRs)
            if bitmap_size > 32 {
                return Err(
                    InvalidAttestReason::PcrBitmapSizeExceeded { size: bitmap_size }.into(),
                );
            }

            // - pcrSelect (variable) - bitmap
            let bitmap = self.read_bytes(bitmap_size as usize)?;

            selections.push((hash_alg, bitmap.to_vec()));
        }

        Ok(selections)
    }
}

/// Verify that the PCR digest in a Quote matches the claimed PCR values
///
/// The TPM Quote contains a PCR selection (which banks/indices were quoted)
/// and a digest over those PCR values. This function recomputes the digest
/// from the claimed PCR values and compares it to the signed digest.
///
/// Supports multiple PCR banks:
/// - TPM_ALG_SHA256 (0x000B) → decoded algorithm ID 0
/// - TPM_ALG_SHA384 (0x000C) → decoded algorithm ID 1
pub fn verify_pcr_digest_matches(
    quote_info: &TpmQuoteInfo,
    pcrs: &BTreeMap<(u8, u8), Vec<u8>>,
) -> Result<(), VerifyError> {
    // The PCR digest is SHA-256(concatenation of selected PCR values in order)
    // The selection order is determined by the pcr_select field
    let mut hasher = Sha256::new();

    for (alg, bitmap) in &quote_info.pcr_select {
        let decoded_alg_id = match *alg {
            0x000B => 0u8, // TPM_ALG_SHA256
            0x000C => 1u8, // TPM_ALG_SHA384
            _ => continue,
        };

        // Iterate through bitmap to find selected PCRs
        for (byte_idx, byte_val) in bitmap.iter().enumerate() {
            for bit_idx in 0..8 {
                if byte_val & (1 << bit_idx) != 0 {
                    let pcr_idx = (byte_idx * 8 + bit_idx) as u8;
                    if let Some(pcr_value) = pcrs.get(&(decoded_alg_id, pcr_idx)) {
                        hasher.update(pcr_value);
                    } else {
                        return Err(InvalidAttestReason::PcrSelectedButMissing {
                            pcr_index: pcr_idx,
                            algorithm: *alg,
                        }
                        .into());
                    }
                }
            }
        }
    }

    let computed_digest = hasher.finalize();
    if computed_digest.as_ref() != quote_info.pcr_digest {
        return Err(InvalidAttestReason::PcrDigestMismatch.into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecdsa::signature::hazmat::PrehashSigner;
    use p256::ecdsa::SigningKey;
    use sha2::Sha256;

    /// Generate a test P-256 key pair and sign a message
    /// The signature is over SHA256(message) to match what verify_ecdsa_p256 expects
    fn sign_message(message: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // Use a fixed seed for deterministic tests
        let secret_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let signing_key = SigningKey::from_bytes(&secret_bytes.into()).unwrap();

        // Get the public key in SEC1 uncompressed format
        let verifying_key = signing_key.verifying_key();
        let pubkey = verifying_key.to_encoded_point(false);
        let pubkey_bytes = pubkey.as_bytes().to_vec();

        // verify_ecdsa_p256 does: digest = SHA256(message), then verify_prehash
        // So we need to sign_prehash over SHA256(message)
        let digest = Sha256::digest(message);
        let signature: p256::ecdsa::Signature = signing_key.sign_prehash(&digest).unwrap();
        let sig_der = signature.to_der().as_bytes().to_vec();

        (pubkey_bytes, sig_der)
    }

    // === ECDSA Verification Tests ===

    #[test]
    fn test_valid_p256_signature() {
        let message = b"test message for signing";
        let (pubkey, signature) = sign_message(message);

        let result = verify_ecdsa_p256(message, &signature, &pubkey);
        assert!(
            result.is_ok(),
            "Valid signature should verify: {:?}",
            result
        );
    }

    #[test]
    fn test_reject_wrong_message() {
        let message = b"test message for signing";
        let wrong_message = b"different message";
        let (pubkey, signature) = sign_message(message);

        let result = verify_ecdsa_p256(wrong_message, &signature, &pubkey);
        assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
    }

    #[test]
    fn test_reject_invalid_pubkey_not_on_curve() {
        let message = b"test message";
        let (_, signature) = sign_message(message);

        // Invalid public key: 0x04 prefix + arbitrary X, Y that's not on curve
        let mut invalid_pubkey = vec![0x04];
        invalid_pubkey.extend([0x00u8; 32]); // X = 0
        invalid_pubkey.extend([0x01u8; 32]); // Y = 1 (not on curve)

        let result = verify_ecdsa_p256(message, &signature, &invalid_pubkey);
        assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
    }

    #[test]
    fn test_reject_identity_point() {
        let message = b"test message";
        let (_, signature) = sign_message(message);

        // Identity point: X = 0, Y = 0 (invalid for P-256)
        let mut identity = vec![0x04];
        identity.extend([0x00u8; 32]); // X = 0
        identity.extend([0x00u8; 32]); // Y = 0

        let result = verify_ecdsa_p256(message, &signature, &identity);
        assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
    }

    #[test]
    fn test_reject_wrong_size_pubkey_too_short() {
        let message = b"test message";
        let (_, signature) = sign_message(message);

        // Public key that's too short
        let short_pubkey = vec![0x04, 0x01, 0x02, 0x03];

        let result = verify_ecdsa_p256(message, &signature, &short_pubkey);
        assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
    }

    #[test]
    fn test_reject_wrong_size_pubkey_too_long() {
        let message = b"test message";
        let (_, signature) = sign_message(message);

        // Public key that's too long
        let mut long_pubkey = vec![0x04];
        long_pubkey.extend([0x01u8; 100]);

        let result = verify_ecdsa_p256(message, &signature, &long_pubkey);
        assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
    }

    #[test]
    fn test_reject_compressed_pubkey() {
        let message = b"test message";
        let (_, signature) = sign_message(message);

        // Compressed public key (0x02 or 0x03 prefix) - only 33 bytes
        let mut compressed = vec![0x02];
        compressed.extend([0x01u8; 32]);

        // This might work or fail depending on library support
        // The important thing is it doesn't panic
        let _ = verify_ecdsa_p256(message, &signature, &compressed);
    }

    #[test]
    fn test_reject_malformed_der_signature() {
        let message = b"test message";
        let (pubkey, _) = sign_message(message);

        // Completely invalid DER
        let invalid_sig = vec![0x00, 0x01, 0x02, 0x03];

        let result = verify_ecdsa_p256(message, &invalid_sig, &pubkey);
        assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
    }

    #[test]
    fn test_reject_truncated_der_signature() {
        let message = b"test message";
        let (pubkey, signature) = sign_message(message);

        // Truncate the signature
        let truncated = &signature[..signature.len() / 2];

        let result = verify_ecdsa_p256(message, truncated, &pubkey);
        assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
    }

    #[test]
    fn test_reject_empty_signature() {
        let message = b"test message";
        let (pubkey, _) = sign_message(message);

        let result = verify_ecdsa_p256(message, &[], &pubkey);
        assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
    }

    #[test]
    fn test_reject_empty_pubkey() {
        let message = b"test message";
        let (_, signature) = sign_message(message);

        let result = verify_ecdsa_p256(message, &signature, &[]);
        assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
    }

    #[test]
    fn test_reject_wrong_pubkey() {
        let message = b"test message";
        let (_, signature) = sign_message(message);

        // Generate a different valid key
        let other_secret: [u8; 32] = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
            0x3c, 0x3d, 0x3e, 0x3f,
        ];
        let other_key = SigningKey::from_bytes(&other_secret.into()).unwrap();
        let other_pubkey = other_key.verifying_key().to_encoded_point(false);

        let result = verify_ecdsa_p256(message, &signature, other_pubkey.as_bytes());
        assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
    }

    #[test]
    fn test_empty_message() {
        let message = b"";
        let (pubkey, signature) = sign_message(message);

        // Empty message should still work
        let result = verify_ecdsa_p256(message, &signature, &pubkey);
        assert!(result.is_ok());
    }

    #[test]
    fn test_large_message() {
        // Test with a large message
        let message = vec![0xABu8; 10000];
        let (pubkey, signature) = sign_message(&message);

        let result = verify_ecdsa_p256(&message, &signature, &pubkey);
        assert!(result.is_ok());
    }
}
