// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal TPM 2.0 protocol implementation
//!
//! TPM 2.0 command/response marshalling without any C dependencies.
//!
//! TPM I/O is abstracted behind the [`TpmTransport`] trait. With the default
//! `std` feature, [`Tpm::open`] talks to a Linux TPM device (`/dev/tpmrm0`).
//! With `--no-default-features` the crate is `no_std` (requires `alloc`) and
//! exposes only the transport-agnostic core (command marshalling + PCR ops),
//! letting a UEFI caller supply a transport over `EFI_TCG2_PROTOCOL`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use anyhow::{bail, Result};

#[cfg(feature = "std")]
use anyhow::Context;
#[cfg(feature = "std")]
use std::fs::{File, OpenOptions};
#[cfg(feature = "std")]
use std::io::{Read, Write};

// Attestation surface (quote + cert chain + JSON). no_std + alloc; gated by `attest`.
#[cfg(feature = "attest")]
pub mod a9n;
#[cfg(feature = "attest")]
pub mod cert;
pub mod derive;
pub mod ek;
// NSM (AWS Nitro) attestation is reached via a TPM vendor command, so it is
// no_std-capable and part of the attest surface (not std).
#[cfg(feature = "attest")]
pub mod nsm;
pub mod nv;
pub mod pcr;
#[cfg(feature = "attest")]
pub mod roots;
pub(crate) mod session;

// Re-export extension traits for convenience
pub use derive::DeriveOps;
pub use ek::KeyOps;
pub use nv::NvOps;
pub use pcr::PcrOps;

#[cfg(feature = "attest")]
pub use nsm::NsmOps;

// Attestation core: attest_with takes a &mut Tpm and a CertFetcher, so it works in
// no_std/UEFI with a caller-supplied transport + fetcher.
#[cfg(feature = "attest")]
pub use a9n::attest_with;
#[cfg(feature = "attest")]
pub use cert::{der_to_pem, extract_aki, extract_ski, pem_to_der, CertFetcher};

// Convenience std entrypoint: opens /dev/tpm0 and uses the built-in HTTP fetcher.
#[cfg(feature = "http-fetch")]
pub use a9n::attest;
#[cfg(feature = "http-fetch")]
pub use cert::StdHttpFetcher;

/// TPM 2.0 command codes
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum TpmCc {
    PcrRead = 0x0000017E,
    PcrExtend = 0x00000182,
    Hmac = 0x00000155,
    GetCapability = 0x0000017A,
    CreatePrimary = 0x00000131,
    Sign = 0x0000015D,
    Quote = 0x00000158,
    FlushContext = 0x00000165,
    NvRead = 0x0000014E,
    NvReadPublic = 0x00000169,
    NvDefineSpace = 0x0000012A,
    NvWrite = 0x00000137,
    NvUndefineSpace = 0x00000122,
    PolicyPCR = 0x0000017F,
    PolicySecret = 0x00000151,
    PolicyGetDigest = 0x00000189,
    Certify = 0x00000148,
    ActivateCredential = 0x00000147,
    MakeCredential = 0x00000168,
    StartAuthSession = 0x00000176,
    ReadPublic = 0x00000173,
}

/// TPM 2.0 structure tags
#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum TpmSt {
    NoSessions = 0x8001,
    Sessions = 0x8002,
}

/// TPM 2.0 return codes
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TpmRc {
    Success = 0x000,
}

/// TPM 2.0 algorithm identifiers
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmAlg {
    Rsa = 0x0001,
    Sha1 = 0x0004,
    Sha256 = 0x000B,
    Sha384 = 0x000C,
    Sha512 = 0x000D,
    Aes = 0x0006,
    Cfb = 0x0043,
    Ecc = 0x0023,
    EcDsa = 0x0018,
    RsaSsa = 0x0014,
    Null = 0x0010,
}

impl TpmAlg {
    /// Get the digest size in bytes for hash algorithms
    pub fn digest_size(&self) -> Option<usize> {
        match self {
            TpmAlg::Sha1 => Some(20),
            TpmAlg::Sha256 => Some(32),
            TpmAlg::Sha384 => Some(48),
            TpmAlg::Sha512 => Some(64),
            _ => None,
        }
    }

    /// Get the algorithm name as a string
    pub fn name(&self) -> &'static str {
        match self {
            TpmAlg::Rsa => "rsa",
            TpmAlg::Sha1 => "sha1",
            TpmAlg::Sha256 => "sha256",
            TpmAlg::Sha384 => "sha384",
            TpmAlg::Sha512 => "sha512",
            TpmAlg::Aes => "aes",
            TpmAlg::Cfb => "cfb",
            TpmAlg::Ecc => "ecc",
            TpmAlg::EcDsa => "ecdsa",
            TpmAlg::RsaSsa => "rsassa",
            TpmAlg::Null => "null",
        }
    }

    /// Try to convert a u16 to a TpmAlg
    pub fn from_u16(val: u16) -> Option<Self> {
        match val {
            0x0001 => Some(TpmAlg::Rsa),
            0x0004 => Some(TpmAlg::Sha1),
            0x000B => Some(TpmAlg::Sha256),
            0x000C => Some(TpmAlg::Sha384),
            0x000D => Some(TpmAlg::Sha512),
            0x0023 => Some(TpmAlg::Ecc),
            0x0018 => Some(TpmAlg::EcDsa),
            0x0014 => Some(TpmAlg::RsaSsa),
            0x0010 => Some(TpmAlg::Null),
            _ => None,
        }
    }
}

impl TryFrom<u16> for TpmAlg {
    type Error = ();

    fn try_from(val: u16) -> Result<Self, Self::Error> {
        Self::from_u16(val).ok_or(())
    }
}

/// TPM handle for the owner hierarchy
pub const TPM_RH_OWNER: u32 = 0x40000001;

/// TPM handle for the endorsement hierarchy
pub const TPM_RH_ENDORSEMENT: u32 = 0x4000000B;

/// TPM handle representing a null handle
pub const TPM_RH_NULL: u32 = 0x40000007;

/// Password authorization session handle
pub const TPM_RS_PW: u32 = 0x40000009;

/// NV index for RSA-2048 EK certificate (standard location)
pub const NV_INDEX_RSA_2048_EK_CERT: u32 = 0x01C00002;

/// NV index for ECC-P256 EK certificate (standard location)
pub const NV_INDEX_ECC_P256_EK_CERT: u32 = 0x01C0000A;

/// NV index for ECC-P384 EK certificate (standard location)
pub const NV_INDEX_ECC_P384_EK_CERT: u32 = 0x01C00016;

/// TPM capability types
pub const TPM_CAP_HANDLES: u32 = 0x00000001;
pub const TPM_CAP_PCRS: u32 = 0x00000005;
pub const TPM_CAP_TPM_PROPERTIES: u32 = 0x00000006;

/// TPM fixed property identifiers (TPM_PT)
pub const TPM_PT_VENDOR_STRING_1: u32 = 0x00000106;
pub const TPM_PT_VENDOR_STRING_2: u32 = 0x00000107;

/// Session types
pub const TPM_SE_HMAC: u8 = 0x00;
pub const TPM_SE_POLICY: u8 = 0x01;
pub const TPM_SE_TRIAL: u8 = 0x03;

/// Algorithm IDs
pub const TPM_ALG_NULL: u16 = 0x0010;
pub const TPM_ALG_SHA256: u16 = 0x000B;
pub const TPM_ALG_SHA512: u16 = 0x000D;

/// ECC curve identifiers
#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum TpmEccCurve {
    NistP256 = 0x0003,
}

/// Object attributes
pub struct ObjectAttributes(u32);

impl Default for ObjectAttributes {
    fn default() -> Self {
        Self::new()
    }
}

impl ObjectAttributes {
    pub fn new() -> Self {
        Self(0)
    }

    pub fn fixed_tpm(mut self) -> Self {
        self.0 |= 1 << 1;
        self
    }

    pub fn fixed_parent(mut self) -> Self {
        self.0 |= 1 << 4;
        self
    }

    pub fn sensitive_data_origin(mut self) -> Self {
        self.0 |= 1 << 5;
        self
    }

    pub fn user_with_auth(mut self) -> Self {
        self.0 |= 1 << 6;
        self
    }

    pub fn decrypt(mut self) -> Self {
        self.0 |= 1 << 17;
        self
    }

    pub fn sign_encrypt(mut self) -> Self {
        self.0 |= 1 << 18;
        self
    }

    pub fn admin_with_policy(mut self) -> Self {
        self.0 |= 1 << 7;
        self
    }

    pub fn restricted(mut self) -> Self {
        self.0 |= 1 << 16;
        self
    }

    pub fn value(&self) -> u32 {
        self.0
    }
}

/// TPM 2.0 command header
#[derive(Debug)]
struct TpmCommandHeader {
    tag: TpmSt,
    size: u32,
    code: TpmCc,
}

impl TpmCommandHeader {
    /// Create a new command header
    fn new(tag: TpmSt, size: u32, code: TpmCc) -> Self {
        Self { tag, size, code }
    }

    /// Serialize to bytes
    fn to_bytes(&self) -> [u8; 10] {
        let mut bytes = [0u8; 10];
        bytes[0..2].copy_from_slice(&(self.tag as u16).to_be_bytes());
        bytes[2..6].copy_from_slice(&self.size.to_be_bytes());
        bytes[6..10].copy_from_slice(&(self.code as u32).to_be_bytes());
        bytes
    }
}

/// TPM 2.0 response header
#[derive(Debug)]
pub struct TpmResponseHeader {
    pub tag: u16,
    pub size: u32,
    pub code: u32,
}

impl TpmResponseHeader {
    /// Parse a response header from a 10-byte buffer
    fn from_bytes(bytes: &[u8; 10]) -> Self {
        let tag = u16::from_be_bytes([bytes[0], bytes[1]]);
        let size = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        let code = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
        Self { tag, size, code }
    }
}

/// Helper for building TPM commands with big-endian serialization
pub(crate) struct CommandBuffer {
    data: Vec<u8>,
}

impl CommandBuffer {
    fn new() -> Self {
        Self { data: Vec::new() }
    }

    fn write_u8(mut self, val: u8) -> Self {
        self.data.push(val);
        self
    }

    fn write_u16(mut self, val: u16) -> Self {
        self.data.extend_from_slice(&val.to_be_bytes());
        self
    }

    fn write_u32(mut self, val: u32) -> Self {
        self.data.extend_from_slice(&val.to_be_bytes());
        self
    }

    fn write_bytes(mut self, bytes: &[u8]) -> Self {
        self.data.extend_from_slice(bytes);
        self
    }

    /// Write a TPM2B (size-prefixed buffer)
    fn write_tpm2b(mut self, bytes: &[u8]) -> Self {
        self.data
            .extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        self.data.extend_from_slice(bytes);
        self
    }

    fn write_auth_empty_pw(self) -> Self {
        // Authorization area (password session with empty password)
        // Size = 4 (sessionHandle) + 2 (nonce) + 1 (attributes) + 2 (password) = 9 bytes
        self.write_u32(9) // authorizationSize
            .write_u32(TPM_RS_PW) // sessionHandle - password session
            .write_u16(0) // nonce - empty
            .write_u8(0) // sessionAttributes - continue session
            .write_u16(0) // password/hmac - empty
    }

    /// Authorization area referencing a policy `session` (empty nonce, continueSession,
    /// empty caller HMAC). Same 9-byte shape as the password area, with the policy
    /// session handle in place of `TPM_RS_PW`.
    #[allow(dead_code)]
    fn write_auth_policy_session(self, session: u32) -> Self {
        self.write_u32(9) // authorizationSize
            .write_u32(session) // sessionHandle - policy session
            .write_u16(0) // nonceCaller - empty
            .write_u8(0x01) // sessionAttributes - continueSession
            .write_u16(0) // hmac - empty
    }

    fn finalize(mut self, tag: TpmSt, code: TpmCc) -> Vec<u8> {
        let total_size = 10 + self.data.len(); // header is 10 bytes
        let header = TpmCommandHeader::new(tag, total_size as u32, code);
        let mut result = Vec::new();
        result.extend_from_slice(&header.to_bytes());
        result.append(&mut self.data);
        result
    }

    /// Finalize command with a vendor-specific command code (e.g. AWS NSM request)
    #[cfg(feature = "attest")]
    fn finalize_vendor(mut self, tag: TpmSt, vendor_code: u32) -> Vec<u8> {
        let total_size = 10 + self.data.len(); // header is 10 bytes
        let mut result = Vec::new();
        result.extend_from_slice(&(tag as u16).to_be_bytes());
        result.extend_from_slice(&(total_size as u32).to_be_bytes());
        result.extend_from_slice(&vendor_code.to_be_bytes());
        result.append(&mut self.data);
        result
    }

    /// Convert to raw bytes without finalizing as a command
    ///
    /// Use this when building non-command data structures like TPM2B_PUBLIC
    fn into_vec(self) -> Vec<u8> {
        self.data
    }
}

/// Helper for parsing TPM responses
pub struct ResponseBuffer {
    data: Vec<u8>,
    offset: usize,
}

impl ResponseBuffer {
    fn new(data: Vec<u8>) -> Self {
        Self { data, offset: 0 }
    }

    fn read_u8(&mut self) -> Result<u8> {
        if self.offset >= self.data.len() {
            bail!("Response buffer underflow");
        }
        let val = self.data[self.offset];
        self.offset += 1;
        Ok(val)
    }

    fn read_u16(&mut self) -> Result<u16> {
        if self.offset + 2 > self.data.len() {
            bail!("Response buffer underflow");
        }
        let val = u16::from_be_bytes([self.data[self.offset], self.data[self.offset + 1]]);
        self.offset += 2;
        Ok(val)
    }

    fn read_u32(&mut self) -> Result<u32> {
        if self.offset + 4 > self.data.len() {
            bail!("Response buffer underflow");
        }
        let val = u32::from_be_bytes([
            self.data[self.offset],
            self.data[self.offset + 1],
            self.data[self.offset + 2],
            self.data[self.offset + 3],
        ]);
        self.offset += 4;
        Ok(val)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&[u8]> {
        if self.offset + len > self.data.len() {
            bail!("Response buffer underflow: trying to read {} bytes at offset {}, but only {} bytes total (remaining: {})",
                  len, self.offset, self.data.len(), self.remaining());
        }
        let bytes = &self.data[self.offset..self.offset + len];
        self.offset += len;
        Ok(bytes)
    }

    /// Read a TPM2B (size-prefixed buffer)
    fn read_tpm2b(&mut self) -> Result<Vec<u8>> {
        let size = self.read_u16()? as usize;
        Ok(self.read_bytes(size)?.to_vec())
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.offset
    }

    fn offset(&self) -> usize {
        self.offset
    }
}

/// Transport for exchanging raw, fully-framed TPM 2.0 messages.
///
/// Implementors move bytes to/from the TPM by whatever mechanism is available:
/// a Linux device file (see [`FileTransport`]) under `std`, or
/// `EFI_TCG2_PROTOCOL.SubmitCommand` in a UEFI environment. The implementor is
/// responsible only for delivering the command and returning the complete
/// response (10-byte header + body); header validation and response-code
/// checking are handled by the [`Tpm`] wrapper.
pub trait TpmTransport {
    /// Send a fully-framed TPM command and return the complete response bytes
    /// (TPM response header followed by its body).
    fn transmit_raw(&mut self, command: &[u8]) -> Result<Vec<u8>>;
}

/// Linux TPM device-file transport (`/dev/tpmrm0` or `/dev/tpm0`).
#[cfg(feature = "std")]
pub struct FileTransport {
    device: File,
}

#[cfg(feature = "std")]
impl FileTransport {
    /// Open a specific TPM device path
    pub fn open_path(path: &str) -> Result<Self> {
        let device = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .context(format!("Failed to open TPM device at {}", path))?;

        Ok(Self { device })
    }
}

#[cfg(feature = "std")]
impl TpmTransport for FileTransport {
    fn transmit_raw(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        // Write command
        self.device
            .write_all(command)
            .context("Failed to write TPM command")?;

        // Read response header first (10 bytes)
        let mut header_buf = [0u8; 10];
        self.device
            .read_exact(&mut header_buf)
            .context("Failed to read TPM response header")?;

        let header = TpmResponseHeader::from_bytes(&header_buf);
        if header.size < 10 {
            bail!("Invalid TPM response size: {}", header.size);
        }

        // Read response body (excluding header) and return the full response
        let body_size = header.size as usize - 10;
        let mut response = Vec::with_capacity(header.size as usize);
        response.extend_from_slice(&header_buf);
        let mut body = alloc::vec![0u8; body_size];
        self.device
            .read_exact(&mut body)
            .context("Failed to read TPM response body")?;
        response.extend_from_slice(&body);

        Ok(response)
    }
}

/// TPM 2.0 context — marshals commands and dispatches them over a [`TpmTransport`].
pub struct Tpm {
    transport: Box<dyn TpmTransport>,
}

impl Tpm {
    /// Open the TPM device (defaults to /dev/tpmrm0)
    #[cfg(feature = "std")]
    pub fn open() -> Result<Self> {
        Self::open_path("/dev/tpmrm0")
    }

    /// Open a specific TPM device path
    #[cfg(feature = "std")]
    pub fn open_path(path: &str) -> Result<Self> {
        Ok(Self::with_transport(Box::new(FileTransport::open_path(
            path,
        )?)))
    }

    /// Open direct TPM device (/dev/tpm0) - required for vendor commands
    #[cfg(feature = "std")]
    pub fn open_direct() -> Result<Self> {
        Self::open_path("/dev/tpm0")
    }

    /// Build a TPM context over an arbitrary transport (e.g. UEFI TCG2).
    pub fn with_transport(transport: Box<dyn TpmTransport>) -> Self {
        Self { transport }
    }

    /// Send a command and receive response
    ///
    /// Returns a ResponseBuffer containing the response body (without the header)
    pub(crate) fn transmit(&mut self, command: &[u8]) -> Result<ResponseBuffer> {
        let response = self.transport.transmit_raw(command)?;

        if response.len() < 10 {
            bail!(
                "Invalid TPM response: {} bytes (need at least 10)",
                response.len()
            );
        }

        // Parse response header (first 10 bytes)
        let mut header_buf = [0u8; 10];
        header_buf.copy_from_slice(&response[..10]);
        let header = TpmResponseHeader::from_bytes(&header_buf);

        if (header.size as usize) < 10 || header.size as usize > response.len() {
            bail!("Invalid TPM response size: {}", header.size);
        }

        // Check response code
        if header.code != TpmRc::Success as u32 {
            bail!("TPM command failed with code: 0x{:08X}", header.code);
        }

        // Return the response body (excluding the 10-byte header)
        Ok(ResponseBuffer::new(
            response[10..header.size as usize].to_vec(),
        ))
    }

    /// Flush a context (close a handle)
    pub fn flush_context(&mut self, handle: u32) -> Result<()> {
        let command = CommandBuffer::new()
            .write_u32(handle)
            .finalize(TpmSt::NoSessions, TpmCc::FlushContext);
        self.transmit(&command)?;

        Ok(())
    }

    /// Execute TPM2_GetCapability command (internal helper)
    ///
    /// Returns (more_data, ResponseBuffer) positioned after capability verification.
    /// The ResponseBuffer is ready to parse capability-specific data.
    pub fn get_capability(
        &mut self,
        capability: u32,
        property: u32,
        property_count: u32,
    ) -> Result<(bool, ResponseBuffer)> {
        let command = CommandBuffer::new()
            .write_u32(capability)
            .write_u32(property)
            .write_u32(property_count)
            .finalize(TpmSt::NoSessions, TpmCc::GetCapability);
        let mut resp = self.transmit(&command)?;

        // Parse common response fields
        let more_data = resp.read_u8()? != 0;
        let returned_capability = resp.read_u32()?;
        if returned_capability != capability {
            bail!(
                "Unexpected capability type: 0x{:08X} (expected 0x{:08X})",
                returned_capability,
                capability
            );
        }

        Ok((more_data, resp))
    }

    /// Get TPM fixed properties
    ///
    /// Query a specific TPM property value
    pub fn get_property(&mut self, property: u32) -> Result<u32> {
        let (_more_data, mut resp) = self.get_capability(TPM_CAP_TPM_PROPERTIES, property, 1)?;

        // Parse capability-specific data: TPML_TAGGED_TPM_PROPERTY
        let count = resp.read_u32()?;
        if count == 0 {
            bail!("Property 0x{:08X} not found", property);
        }

        // TPMS_TAGGED_PROPERTY
        let returned_property = resp.read_u32()?;
        if returned_property != property {
            bail!(
                "Unexpected property type: 0x{:08X} (expected 0x{:08X})",
                returned_property,
                property
            );
        }

        resp.read_u32()
    }

    /// Check if this is an AWS Nitro TPM
    ///
    /// Returns true if the vendor string matches "NitroTPM*"
    pub fn is_nitro_tpm(&mut self) -> Result<bool> {
        // Expected vendor string parts: "Nitr" + "oTPM"
        const NITRO_VENDOR_STRING_1: u32 = 0x4E697472; // "Nitr"
        const NITRO_VENDOR_STRING_2: u32 = 0x6F54504D; // "oTPM"

        let vendor_str_1 = self.get_property(TPM_PT_VENDOR_STRING_1)?;
        let vendor_str_2 = self.get_property(TPM_PT_VENDOR_STRING_2)?;

        Ok(vendor_str_1 == NITRO_VENDOR_STRING_1 && vendor_str_2 == NITRO_VENDOR_STRING_2)
    }
}

/// ECC public key information parsed from TPMT_PUBLIC
#[derive(Debug, Clone)]
pub struct EccPublicKey {
    pub key_type: u16,
    pub name_alg: u16,
    pub object_attributes: u32,
    pub auth_policy: Vec<u8>,
    pub symmetric: u16,
    pub scheme: u16,
    pub curve_id: u16,
    pub kdf: u16,
    pub x: Vec<u8>,
    pub y: Vec<u8>,
}

/// RSA public key information parsed from TPMT_PUBLIC
#[derive(Debug, Clone)]
pub struct RsaPublicKey {
    pub key_type: u16,
    pub name_alg: u16,
    pub object_attributes: u32,
    pub auth_policy: Vec<u8>,
    pub symmetric: u16,
    pub scheme: u16,
    pub key_bits: u16,
    pub exponent: u32,
    pub modulus: Vec<u8>,
}

/// Generic public key that can be either RSA or ECC
#[derive(Debug, Clone)]
pub enum PublicKey {
    Rsa(RsaPublicKey),
    Ecc(EccPublicKey),
}

/// Result from creating a primary key
pub struct PrimaryKeyResult {
    pub handle: u32,
    pub public_key: EccPublicKey,
}

/// Result from creating a primary key from a template (may be RSA or ECC)
pub struct TemplateKeyResult {
    pub handle: u32,
    pub public_key: PublicKey,
    /// The raw TPM2B_PUBLIC bytes returned by the TPM
    pub public_bytes: Vec<u8>,
}

/// Result from TPM2_Quote
#[derive(Debug)]
pub struct QuoteResult {
    pub attest_data: Vec<u8>, // TPMS_ATTEST structure (type=QUOTE)
    pub signature: Vec<u8>,   // DER-encoded ECDSA signature
}
