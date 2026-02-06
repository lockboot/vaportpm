// SPDX-License-Identifier: MIT OR Apache-2.0

//! Verification error types

use thiserror::Error;

use crate::CloudProvider;

/// Errors that can occur during verification
#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("Invalid hex encoding: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("Invalid attestation structure: {0}")]
    InvalidAttest(#[from] InvalidAttestReason),

    #[error("Signature verification failed: {0}")]
    SignatureInvalid(#[from] SignatureInvalidReason),

    #[error("Certificate parsing failed: {0}")]
    CertificateParse(#[from] CertificateParseReason),

    #[error("Certificate chain validation failed: {0}")]
    ChainValidation(#[from] ChainValidationReason),

    #[error("CBOR parsing failed: {0}")]
    CborParse(#[from] CborParseReason),

    #[error("COSE signature verification failed: {0}")]
    CoseVerify(#[from] CoseVerifyReason),

    #[error("PCR index out of bounds: {0}")]
    PcrIndexOutOfBounds(#[from] PcrIndexOutOfBoundsReason),

    #[error("No attestations could be verified: {0}")]
    NoValidAttestation(#[from] NoValidAttestationReason),
}

// =============================================================================
// InvalidAttestReason
// =============================================================================

#[derive(Debug, Error)]
pub enum InvalidAttestReason {
    // TPM binary structure (tpm.rs SafeCursor)
    #[error("Invalid TPM magic: expected 0x{expected:08x}, got 0x{got:08x}")]
    TpmMagicInvalid { expected: u32, got: u32 },

    #[error("Invalid attest type: expected 0x{expected:04x} (QUOTE), got 0x{got:04x}")]
    TpmTypeInvalid { expected: u16, got: u16 },

    #[error("Truncated TPM structure at offset {offset}")]
    TpmTruncated { offset: usize },

    #[error("Integer overflow at offset {offset}")]
    TpmOverflow { offset: usize },

    #[error("PCR selection count {count} exceeds reasonable maximum")]
    PcrSelectionCountExceeded { count: u32 },

    #[error("PCR bitmap size {size} exceeds maximum")]
    PcrBitmapSizeExceeded { size: u8 },

    // PCR validation (shared gcp.rs + nitro.rs)
    #[error("Requires exactly one PCR bank selection, got {count}")]
    MultiplePcrBanks { count: usize },

    #[error("Requires TPM Quote to select {expected}, got algorithm 0x{got:04X}")]
    WrongPcrAlgorithm {
        expected: crate::pcr::PcrAlgorithm,
        got: u16,
    },

    #[error("Requires all 24 PCRs selected in Quote bitmap")]
    PartialPcrBitmap,

    #[error("Nonce does not match Quote")]
    NonceMismatch,

    #[error("Nonce is not 32 bytes")]
    NonceLengthInvalid,

    #[error("Missing PCR {index} - all 24 PCRs (0-23) are required")]
    MissingPcr { index: u8 },

    // PCR bank validation (pcr.rs)
    #[error("PCR bank is empty")]
    PcrBankEmpty,

    #[error("PCR bank contains mixed algorithms")]
    PcrBankMixedAlgorithms,

    #[error("PCR bank has {got} entries, expected {expected}")]
    PcrBankWrongCount { expected: usize, got: usize },

    #[error("PCR {index} value has wrong length: expected {expected}, got {got}")]
    PcrValueWrongLength {
        index: u8,
        expected: usize,
        got: usize,
    },

    #[error("Unknown PCR algorithm: 0x{alg_id:04X}")]
    UnknownPcrAlgorithm { alg_id: u16 },

    #[error("Wrong PCR bank algorithm: expected {expected}, got {got}")]
    WrongPcrBankAlgorithm {
        expected: crate::pcr::PcrAlgorithm,
        got: crate::pcr::PcrAlgorithm,
    },

    #[error("Invalid AK public key format")]
    InvalidAkPubkeyFormat,

    #[error("Nitro document contains no signed PCRs")]
    EmptySignedPcrs,

    #[error("PCR {pcr_index} in attestation but not signed by Nitro document")]
    PcrNotSigned { pcr_index: u8 },

    #[error("PCR digest mismatch")]
    PcrDigestMismatch,

    #[error("Unexpected Nitro digest algorithm: expected SHA384, got {got}")]
    WrongDigestAlgorithm { got: String },

    // Flat binary format (flat.rs)
    #[error("Input too short: {actual} < {minimum}")]
    InputTooShort { actual: usize, minimum: usize },

    #[error("Failed to parse flat header")]
    FlatHeaderInvalid,

    #[error("Truncated flat field: {field}")]
    FlatTruncated { field: &'static str },

    #[error("Unknown platform type: {platform_type}")]
    UnknownPlatformType { platform_type: u8 },

    // JSON
    #[error("JSON parse error: {0}")]
    JsonParse(#[from] serde_json::Error),
}

// =============================================================================
// SignatureInvalidReason
// =============================================================================

#[derive(Debug, Error)]
pub enum SignatureInvalidReason {
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid signature DER: {0}")]
    InvalidSignatureEncoding(String),

    #[error("Signature verification failed: {0}")]
    EcdsaVerificationFailed(String),

    #[error("AK public key mismatch between certificate and decoded input")]
    AkPublicKeyMismatch,

    #[error("TPM nonce does not match Nitro nonce")]
    NitroNonceMismatch,

    #[error("PCR {index} SHA-384 mismatch between claimed and signed value")]
    PcrValueMismatch { index: u8 },
}

// =============================================================================
// CertificateParseReason
// =============================================================================

#[derive(Debug, Error)]
pub enum CertificateParseReason {
    #[error("Line {line}: Unexpected BEGIN marker inside certificate block")]
    NestedBeginMarker { line: usize },

    #[error("Line {line}: END marker without matching BEGIN")]
    EndWithoutBegin { line: usize },

    #[error("Line {line}: Empty certificate content")]
    EmptyCertContent { line: usize },

    #[error("Line {line}: Invalid base64 character in certificate")]
    InvalidBase64 { line: usize },

    #[error("Line {line}: Unexpected content outside certificate block")]
    UnexpectedContent { line: usize },

    #[error("Unclosed certificate block (missing END marker)")]
    UnclosedBlock,

    #[error("No certificates found in PEM")]
    NoCertificates,

    #[error("Invalid DER: {0}")]
    InvalidDer(String),

    #[error("Public key has unused bits")]
    PublicKeyUnusedBits,

    #[error("Failed to encode cert as DER: {0}")]
    DerEncodeFailed(String),
}

// =============================================================================
// ChainValidationReason
// =============================================================================

#[derive(Debug, Error)]
pub enum ChainValidationReason {
    #[error("Empty certificate chain")]
    EmptyChain,

    #[error("Certificate chain too deep: {depth} certificates (max {max})")]
    ChainTooDeep { depth: usize, max: usize },

    #[error("Leaf certificate has CA:TRUE - must be CA:FALSE")]
    LeafIsCa,

    #[error("Certificate {index} (intermediate/root) must have CA:TRUE")]
    CaMissingCaFlag { index: usize },

    #[error("Certificate {index} pathLenConstraint violated: allows {allowed} CAs below, but {actual} exist")]
    PathLenViolated {
        index: usize,
        allowed: u8,
        actual: usize,
    },

    #[error("Certificate {index} (intermediate/root) missing Basic Constraints extension")]
    MissingBasicConstraints { index: usize },

    #[error("Leaf certificate missing digitalSignature key usage")]
    LeafMissingDigitalSignature,

    #[error("Certificate {index} (CA) missing keyCertSign key usage")]
    CaMissingKeyCertSign { index: usize },

    #[error("Leaf certificate missing Key Usage extension")]
    LeafMissingKeyUsage,

    #[error("Certificate {index} issuer does not match parent subject")]
    IssuerMismatch { index: usize },

    #[error("Certificate {index} signature verification failed")]
    SignatureVerificationFailed { index: usize },

    #[error("Unsupported signature algorithm: {oid}")]
    UnsupportedAlgorithm { oid: String },

    #[error("Certificate {index} is not yet valid")]
    CertNotYetValid { index: usize },

    #[error("Certificate {index} has expired")]
    CertExpired { index: usize },

    #[error("Unknown root CA: {hash}")]
    UnknownRootCa { hash: String },

    #[error("Verification path requires {expected:?} root CA, got {got:?}")]
    WrongProvider {
        expected: CloudProvider,
        got: CloudProvider,
    },

    #[error("{0}")]
    CryptoError(String),
}

// =============================================================================
// CborParseReason
// =============================================================================

#[derive(Debug, Error)]
pub enum CborParseReason {
    #[error("Failed to parse payload: {0}")]
    DeserializeFailed(String),

    #[error("Payload is not a map")]
    PayloadNotMap,

    #[error("Missing field: {field}")]
    MissingField { field: &'static str },

    #[error("Missing pcrs or nitrotpm_pcrs field")]
    MissingPcrs,
}

// =============================================================================
// CoseVerifyReason
// =============================================================================

#[derive(Debug, Error)]
pub enum CoseVerifyReason {
    #[error("Failed to parse COSE Sign1: {0}")]
    CoseSign1ParseFailed(String),

    #[error("Missing payload")]
    MissingPayload,

    #[error("Failed to serialize protected header: {0}")]
    ProtectedHeaderSerializeFailed(String),

    #[error("Failed to encode Sig_structure: {0}")]
    SigStructureEncodeFailed(String),

    #[error("Invalid P-384 key: {0}")]
    InvalidP384Key(String),

    #[error("Invalid ES384 signature length: expected {expected}, got {got}")]
    InvalidSignatureLength { expected: usize, got: usize },

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("COSE signature verification failed: {0}")]
    SignatureVerificationFailed(String),
}

// =============================================================================
// PcrIndexOutOfBoundsReason
// =============================================================================

#[derive(Debug, Error)]
pub enum PcrIndexOutOfBoundsReason {
    #[error("Negative PCR index: {index}")]
    Negative { index: i128 },

    #[error("PCR index {index} exceeds maximum {maximum}")]
    ExceedsMaximum { index: i128, maximum: u8 },
}

// =============================================================================
// NoValidAttestationReason
// =============================================================================

#[derive(Debug, Error)]
pub enum NoValidAttestationReason {
    #[error("Missing ecc_p256 AK public key")]
    MissingAkPublicKey,

    #[error("Missing ecc_p256 TPM attestation")]
    MissingTpmAttestation,

    #[error("No platform attestation")]
    NoPlatform,
}
