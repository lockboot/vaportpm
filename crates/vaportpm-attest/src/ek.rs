// SPDX-License-Identifier: MIT OR Apache-2.0

//! Key operations
//!
//! Provides TPM key management operations including:
//! - Creating ECC primary keys
//! - Creating keys from templates (GCP AK)
//! - TPM2_Quote for PCR attestation

use anyhow::{bail, Result};

use crate::{
    CommandBuffer, EccPublicKey, ObjectAttributes, PrimaryKeyResult, PublicKey, QuoteResult,
    ResponseBuffer, RsaPublicKey, TemplateKeyResult, Tpm, TpmAlg, TpmCc, TpmEccCurve, TpmSt,
};

/// Key operations extension trait
pub trait KeyOps {
    /// Create a primary ECC P-256 signing key in the specified hierarchy
    fn create_primary_ecc_key(&mut self, hierarchy: u32) -> Result<PrimaryKeyResult>;

    /// Create a restricted ECC P-256 Attestation Key (TCG-compliant AK profile)
    ///
    /// Creates a key with attributes: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign
    /// This matches the TCG AK profile and GCP's AK template.
    fn create_restricted_ak(&mut self, hierarchy: u32) -> Result<PrimaryKeyResult>;

    /// Create a primary key from a raw TPMT_PUBLIC template
    ///
    /// This takes template bytes (as stored in NV RAM by cloud providers like GCP)
    /// and creates a primary key in the specified hierarchy.
    fn create_primary_from_template(
        &mut self,
        hierarchy: u32,
        template: &[u8],
    ) -> Result<TemplateKeyResult>;

    /// TPM2_Quote - sign current PCR values with a signing key
    ///
    /// This command generates a signed attestation over the selected PCRs.
    /// The quote includes:
    /// - The current PCR values (hashed into a digest)
    /// - A nonce/qualifying data (for freshness)
    /// - Signed by the specified key (typically an AK)
    ///
    /// # Arguments
    /// * `sign_handle` - Handle of the signing key (AK)
    /// * `qualifying_data` - Nonce/challenge data (becomes extraData in TPMS_ATTEST)
    /// * `pcr_selection` - List of (algorithm, PCR indices) to include
    ///
    /// # Returns
    /// QuoteResult containing the TPMS_ATTEST structure (type=QUOTE) and signature
    fn quote(
        &mut self,
        sign_handle: u32,
        qualifying_data: &[u8],
        pcr_selection: &[(TpmAlg, &[u8])],
    ) -> Result<QuoteResult>;
}

impl KeyOps for Tpm {
    fn create_restricted_ak(&mut self, hierarchy: u32) -> Result<PrimaryKeyResult> {
        let public_area = build_restricted_ak_public_area();

        let command = CommandBuffer::new()
            .write_u32(hierarchy)
            .write_auth_empty_pw()
            // inSensitive (TPM2B_SENSITIVE_CREATE)
            .write_u16(4)
            .write_u16(0) // userAuth size = 0
            .write_u16(0) // data size = 0
            // inPublic (TPM2B_PUBLIC)
            .write_tpm2b(&public_area)
            // outsideInfo (TPM2B_DATA) - empty
            .write_u16(0)
            // creationPCR (TPML_PCR_SELECTION) - empty
            .write_u32(0)
            .finalize(TpmSt::Sessions, TpmCc::CreatePrimary);
        let mut resp = self.transmit(&command)?;

        // Parse response
        let handle = resp.read_u32()?;
        let parameter_size = resp.read_u32()?;

        // Track where parameters start
        let param_start = resp.offset();

        // Read outPublic (TPM2B_PUBLIC)
        let public_size = resp.read_u16()? as usize;
        let public_data = resp.read_bytes(public_size)?;

        // Parse the public key from the public area
        let public_key = parse_ecc_public_key(public_data)?;

        // Skip remaining CreatePrimary output parameters
        let bytes_read = resp.offset() - param_start;
        if bytes_read < parameter_size as usize {
            let remaining = parameter_size as usize - bytes_read;
            resp.read_bytes(remaining)?;
        }

        // Verify we read exactly parameter_size bytes
        let final_bytes_read = resp.offset() - param_start;
        if final_bytes_read != parameter_size as usize {
            bail!(
                "Parameter size mismatch: TPM said {} bytes, we read {} bytes",
                parameter_size,
                final_bytes_read
            );
        }

        Ok(PrimaryKeyResult { handle, public_key })
    }

    fn create_primary_ecc_key(&mut self, hierarchy: u32) -> Result<PrimaryKeyResult> {
        let public_area = build_ecc_public_area();

        let command = CommandBuffer::new()
            .write_u32(hierarchy)
            .write_auth_empty_pw()
            // inSensitive (TPM2B_SENSITIVE_CREATE)
            .write_u16(4)
            .write_u16(0) // userAuth size = 0
            .write_u16(0) // data size = 0
            // inPublic (TPM2B_PUBLIC)
            .write_tpm2b(&public_area)
            // outsideInfo (TPM2B_DATA) - empty
            .write_u16(0)
            // creationPCR (TPML_PCR_SELECTION) - empty
            .write_u32(0)
            .finalize(TpmSt::Sessions, TpmCc::CreatePrimary);
        let mut resp = self.transmit(&command)?;

        // Parse response
        let handle = resp.read_u32()?;
        let parameter_size = resp.read_u32()?;

        // Track where parameters start
        let param_start = resp.offset();

        // Read outPublic (TPM2B_PUBLIC)
        let public_size = resp.read_u16()? as usize;
        let public_data = resp.read_bytes(public_size)?;

        // Parse the public key from the public area
        let public_key = parse_ecc_public_key(public_data)?;

        // Skip remaining CreatePrimary output parameters
        let bytes_read = resp.offset() - param_start;
        if bytes_read < parameter_size as usize {
            let remaining = parameter_size as usize - bytes_read;
            resp.read_bytes(remaining)?;
        }

        // Verify we read exactly parameter_size bytes
        let final_bytes_read = resp.offset() - param_start;
        if final_bytes_read != parameter_size as usize {
            bail!(
                "Parameter size mismatch: TPM said {} bytes, we read {} bytes",
                parameter_size,
                final_bytes_read
            );
        }

        Ok(PrimaryKeyResult { handle, public_key })
    }

    fn create_primary_from_template(
        &mut self,
        hierarchy: u32,
        template: &[u8],
    ) -> Result<TemplateKeyResult> {
        let command = CommandBuffer::new()
            .write_u32(hierarchy)
            .write_auth_empty_pw()
            // inSensitive (TPM2B_SENSITIVE_CREATE)
            .write_u16(4)
            .write_u16(0) // userAuth size = 0
            .write_u16(0) // data size = 0
            // inPublic (TPM2B_PUBLIC) - the raw template from NV RAM
            .write_tpm2b(template)
            // outsideInfo (TPM2B_DATA) - empty
            .write_u16(0)
            // creationPCR (TPML_PCR_SELECTION) - empty
            .write_u32(0)
            .finalize(TpmSt::Sessions, TpmCc::CreatePrimary);
        let mut resp = self.transmit(&command)?;

        // Parse response
        let handle = resp.read_u32()?;
        let parameter_size = resp.read_u32()?;

        // Track where parameters start
        let param_start = resp.offset();

        // Read outPublic (TPM2B_PUBLIC)
        let public_size = resp.read_u16()? as usize;
        let public_data = resp.read_bytes(public_size)?;

        // Parse the public key based on algorithm type
        let public_key = parse_public_key(public_data)?;

        // Save the raw public bytes for later use
        let public_bytes = public_data.to_vec();

        // Skip remaining CreatePrimary output parameters
        let bytes_read = resp.offset() - param_start;
        if bytes_read < parameter_size as usize {
            let remaining = parameter_size as usize - bytes_read;
            resp.read_bytes(remaining)?;
        }

        // Verify we read exactly parameter_size bytes
        let final_bytes_read = resp.offset() - param_start;
        if final_bytes_read != parameter_size as usize {
            bail!(
                "Parameter size mismatch: TPM said {} bytes, we read {} bytes",
                parameter_size,
                final_bytes_read
            );
        }

        Ok(TemplateKeyResult {
            handle,
            public_key,
            public_bytes,
        })
    }

    fn quote(
        &mut self,
        sign_handle: u32,
        qualifying_data: &[u8],
        pcr_selection: &[(TpmAlg, &[u8])],
    ) -> Result<QuoteResult> {
        // Build TPML_PCR_SELECTION
        let pcr_select = build_pcr_selection(pcr_selection);

        let command = CommandBuffer::new()
            .write_u32(sign_handle)
            .write_auth_empty_pw()
            // qualifyingData (TPM2B_DATA)
            .write_tpm2b(qualifying_data)
            // inScheme (TPMT_SIG_SCHEME) - ECDSA with SHA256
            .write_u16(TpmAlg::EcDsa as u16)
            .write_u16(TpmAlg::Sha256 as u16)
            // PCR selection (TPML_PCR_SELECTION)
            .write_bytes(&pcr_select)
            .finalize(TpmSt::Sessions, TpmCc::Quote);
        let mut resp = self.transmit(&command)?;

        // Parse response
        let parameter_size = resp.read_u32()?;
        let param_start = resp.offset();

        // quoted (TPM2B_ATTEST)
        let attest_data = resp.read_tpm2b()?;

        // signature (TPMT_SIGNATURE)
        let sig_alg = resp.read_u16()?;
        if sig_alg != TpmAlg::EcDsa as u16 {
            bail!("Unexpected signature algorithm: 0x{:04X}", sig_alg);
        }

        let hash_alg = resp.read_u16()?;
        if hash_alg != TpmAlg::Sha256 as u16 {
            bail!("Unexpected hash algorithm: 0x{:04X}", hash_alg);
        }

        // TPMS_SIGNATURE_ECC
        let r = resp.read_tpm2b()?;
        let s = resp.read_tpm2b()?;

        // Verify we read exactly parameter_size bytes
        let bytes_read = resp.offset() - param_start;
        if bytes_read != parameter_size as usize {
            bail!(
                "Parameter size mismatch in Quote: TPM said {} bytes, we read {} bytes",
                parameter_size,
                bytes_read
            );
        }

        let signature = encode_ecdsa_der_signature(&r, &s);

        Ok(QuoteResult {
            attest_data: attest_data.to_vec(),
            signature,
        })
    }
}

/// Build TPML_PCR_SELECTION structure
///
/// # Arguments
/// * `selections` - List of (algorithm, PCR bitmap) pairs
///   PCR bitmap is a byte array where bit N of byte M indicates PCR (M*8 + N)
fn build_pcr_selection(selections: &[(TpmAlg, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();

    // count (4 bytes)
    buf.extend_from_slice(&(selections.len() as u32).to_be_bytes());

    for (alg, pcr_bitmap) in selections {
        // TPMS_PCR_SELECTION:
        // hash (2 bytes) - algorithm
        buf.extend_from_slice(&(*alg as u16).to_be_bytes());
        // sizeofSelect (1 byte) - typically 3 for 24 PCRs
        let size = pcr_bitmap.len().min(255) as u8;
        buf.push(size);
        // pcrSelect (variable) - bitmap
        buf.extend_from_slice(pcr_bitmap);
    }

    buf
}

/// Build a TPM2B_PUBLIC structure for a restricted ECC P-256 Attestation Key
///
/// Attributes: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign (0x50072)
/// This matches the TCG AK profile and GCP's AK template structure.
fn build_restricted_ak_public_area() -> Vec<u8> {
    let attrs = ObjectAttributes::new()
        .fixed_tpm()
        .fixed_parent()
        .sensitive_data_origin()
        .user_with_auth()
        .restricted()
        .sign_encrypt();

    CommandBuffer::new()
        // TPMT_PUBLIC
        .write_u16(TpmAlg::Ecc as u16) // type
        .write_u16(TpmAlg::Sha256 as u16) // nameAlg
        .write_u32(attrs.value()) // objectAttributes
        .write_u16(0) // authPolicy (empty)
        // parameters (TPMS_ECC_PARMS)
        .write_u16(TpmAlg::Null as u16) // symmetric
        .write_u16(TpmAlg::EcDsa as u16) // scheme = ECDSA (required for restricted signing key)
        .write_u16(TpmAlg::Sha256 as u16) // scheme hash = SHA256
        .write_u16(TpmEccCurve::NistP256 as u16) // curveID
        .write_u16(TpmAlg::Null as u16) // kdf
        // unique (TPMS_ECC_POINT) - empty, TPM will generate
        .write_u16(0) // x size
        .write_u16(0) // y size
        .into_vec()
}

/// Build a TPM2B_PUBLIC structure for an ECC P-256 signing key (unrestricted)
fn build_ecc_public_area() -> Vec<u8> {
    let attrs = ObjectAttributes::new()
        .fixed_tpm()
        .fixed_parent()
        .sensitive_data_origin()
        .user_with_auth()
        .decrypt()
        .sign_encrypt();

    CommandBuffer::new()
        // TPMT_PUBLIC
        .write_u16(TpmAlg::Ecc as u16) // type
        .write_u16(TpmAlg::Sha256 as u16) // nameAlg
        .write_u32(attrs.value()) // objectAttributes
        .write_u16(0) // authPolicy (empty)
        // parameters (TPMS_ECC_PARMS)
        .write_u16(TpmAlg::Null as u16) // symmetric
        .write_u16(TpmAlg::Null as u16) // scheme
        .write_u16(TpmEccCurve::NistP256 as u16) // curveID
        .write_u16(TpmAlg::Null as u16) // kdf
        // unique (TPMS_ECC_POINT) - empty
        .write_u16(0) // x size
        .write_u16(0) // y size
        .into_vec()
}

/// Parse public key from TPMT_PUBLIC structure (RSA or ECC)
pub(crate) fn parse_public_key(data: &[u8]) -> Result<PublicKey> {
    let mut resp = ResponseBuffer::new(data.to_vec());

    // Peek at key type to determine parsing strategy
    let key_type = resp.read_u16()?;
    let name_alg = resp.read_u16()?;
    let object_attributes = resp.read_u32()?;
    let auth_policy = resp.read_tpm2b()?;

    match key_type {
        0x0001 => {
            // RSA key (TPM_ALG_RSA)
            // Parse TPMS_RSA_PARMS
            let symmetric = resp.read_u16()?;

            // If symmetric is not NULL, read symmetric details
            if symmetric != TpmAlg::Null as u16 {
                let _key_bits = resp.read_u16()?;
                let _mode = resp.read_u16()?;
            }

            let scheme = resp.read_u16()?;

            // If scheme is not NULL, read scheme details
            if scheme != TpmAlg::Null as u16 {
                let _scheme_detail = resp.read_u16()?;
            }

            let key_bits = resp.read_u16()?;
            let exponent = resp.read_u32()?;

            // Read unique (TPM2B_PUBLIC_KEY_RSA = TPM2B containing modulus)
            let modulus = resp.read_tpm2b()?;

            Ok(PublicKey::Rsa(RsaPublicKey {
                key_type,
                name_alg,
                object_attributes,
                auth_policy,
                symmetric,
                scheme,
                key_bits,
                exponent,
                modulus,
            }))
        }
        0x0023 => {
            // ECC key (TPM_ALG_ECC)
            // Parse TPMS_ECC_PARMS
            let symmetric = resp.read_u16()?;

            // If symmetric is not NULL, read symmetric details
            if symmetric != TpmAlg::Null as u16 {
                let _key_bits = resp.read_u16()?;
                let _mode = resp.read_u16()?;
            }

            let scheme = resp.read_u16()?;

            // Only read scheme details if scheme is not NULL
            if scheme != TpmAlg::Null as u16 {
                let _scheme_detail = resp.read_u16()?;
            }

            let curve_id = resp.read_u16()?;
            let kdf = resp.read_u16()?;

            // Read unique (TPMS_ECC_POINT)
            let x = resp.read_tpm2b()?;
            let y = resp.read_tpm2b()?;

            Ok(PublicKey::Ecc(EccPublicKey {
                key_type,
                name_alg,
                object_attributes,
                auth_policy,
                symmetric,
                scheme,
                curve_id,
                kdf,
                x,
                y,
            }))
        }
        _ => bail!("Unsupported key type: 0x{:04X}", key_type),
    }
}

/// Parse ECC public key from TPMT_PUBLIC structure
pub(crate) fn parse_ecc_public_key(data: &[u8]) -> Result<EccPublicKey> {
    let mut resp = ResponseBuffer::new(data.to_vec());

    // Parse TPMT_PUBLIC structure
    let key_type = resp.read_u16()?;
    let name_alg = resp.read_u16()?;
    let object_attributes = resp.read_u32()?;
    let auth_policy = resp.read_tpm2b()?;

    // Parse parameters (TPMS_ECC_PARMS for ECC keys)
    let symmetric = resp.read_u16()?;

    // If symmetric is not NULL, read symmetric details
    if symmetric != TpmAlg::Null as u16 {
        let _key_bits = resp.read_u16()?;
        let _mode = resp.read_u16()?;
    }

    let scheme = resp.read_u16()?;

    // Only read scheme details if scheme is not NULL
    if scheme != TpmAlg::Null as u16 {
        let _scheme_detail = resp.read_u16()?;
    }

    let curve_id = resp.read_u16()?;
    let kdf = resp.read_u16()?;

    // Read unique (TPMS_ECC_POINT)
    let x = resp.read_tpm2b()?;
    let y = resp.read_tpm2b()?;

    Ok(EccPublicKey {
        key_type,
        name_alg,
        object_attributes,
        auth_policy,
        symmetric,
        scheme,
        curve_id,
        kdf,
        x,
        y,
    })
}

/// Encode ECDSA signature as DER
pub(crate) fn encode_ecdsa_der_signature(r: &[u8], s: &[u8]) -> Vec<u8> {
    fn encode_integer(value: &[u8]) -> Vec<u8> {
        let mut result = vec![0x02]; // INTEGER tag

        // Remove leading zeros
        let trimmed: Vec<u8> = value.iter().skip_while(|&&b| b == 0).copied().collect();

        let bytes = if trimmed.is_empty() {
            vec![0x00]
        } else if trimmed[0] & 0x80 != 0 {
            // Add padding byte if high bit is set
            let mut v = vec![0x00];
            v.extend_from_slice(&trimmed);
            v
        } else {
            trimmed
        };

        result.push(bytes.len() as u8);
        result.extend_from_slice(&bytes);
        result
    }

    let r_encoded = encode_integer(r);
    let s_encoded = encode_integer(s);

    let mut signature = vec![0x30]; // SEQUENCE tag
    let content_len = r_encoded.len() + s_encoded.len();
    signature.push(content_len as u8);
    signature.extend_from_slice(&r_encoded);
    signature.extend_from_slice(&s_encoded);
    signature
}
