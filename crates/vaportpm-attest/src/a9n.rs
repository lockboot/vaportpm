// SPDX-License-Identifier: MIT OR Apache-2.0

//! TPM attestation functionality
//!
//! Provides high-level attestation operations including:
//! - Creating and certifying attestation keys (AK)
//! - Reading PCR values
//! - Generating attestation documents

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

use crate::cert::{der_to_pem, fetch_cert_chain, DER_SEQUENCE_LONG};
use crate::{KeyOps, NsmOps, NvOps, PcrOps, PublicKey, Tpm, TPM_RH_ENDORSEMENT, TPM_RH_OWNER};

/// GCP AK template NV index (RSA) - used for GCP detection
const GCP_AK_TEMPLATE_NV_INDEX_RSA: u32 = 0x01c10001;
/// GCP AK certificate NV index (ECC)
const GCP_AK_CERT_NV_INDEX_ECC: u32 = 0x01c10002;
/// GCP AK template NV index (ECC)
const GCP_AK_TEMPLATE_NV_INDEX_ECC: u32 = 0x01c10003;
/// GCP TPM manufacturer ID: "GOOG"
const GCP_MANUFACTURER_GOOG: u32 = 0x474F4F47;
/// TPM property: manufacturer
const TPM_PT_MANUFACTURER: u32 = 0x00000105;

/// Result type for attestation helper functions
/// Contains: (ak_pubkeys, attestation_data, gcp_attestation, ak_handle)
type AttestResult = (
    HashMap<String, EccPublicKeyCoords>,
    AttestationData,
    Option<GcpAttestationData>,
    Option<u32>,
);

/// Complete attestation output containing all TPM attestation data
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationOutput {
    /// Nonce/challenge used for this attestation (hex-encoded)
    pub nonce: String,
    pub pcrs: HashMap<String, BTreeMap<u8, String>>,
    /// Attestation Key public keys (hex-encoded ECC coordinates)
    pub ak_pubkeys: HashMap<String, EccPublicKeyCoords>,
    pub attestation: AttestationContainer,
}

/// ECC public key coordinates
#[derive(Debug, Serialize, Deserialize)]
pub struct EccPublicKeyCoords {
    pub x: String,
    pub y: String,
}

/// Container for both TPM and optional platform-specific attestations
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationContainer {
    pub tpm: HashMap<String, AttestationData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nitro: Option<NitroAttestationData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gcp: Option<GcpAttestationData>,
}

/// GCP Shielded VM attestation data
///
/// Contains the AK certificate chain from NV RAM.
/// The AK is a long-term key provisioned by Google (not PCR-bound).
/// The Quote data and signature are in `attestation.tpm`.
#[derive(Debug, Serialize, Deserialize)]
pub struct GcpAttestationData {
    /// AK certificate chain in PEM format (leaf first, root last)
    pub ak_cert_chain: String,
}

/// TPM attestation data (Quote response)
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationData {
    /// TPM2B_ATTEST structure from TPM2_Quote (hex-encoded)
    pub attest_data: String,
    /// ECDSA signature over attest_data (DER, hex-encoded)
    pub signature: String,
}

/// Nitro Enclave attestation data
///
/// The AK public key and nonce are inside the signed document,
/// and also available at the top level of AttestationOutput.
#[derive(Debug, Serialize, Deserialize)]
pub struct NitroAttestationData {
    /// COSE Sign1 NSM document (hex-encoded)
    pub document: String,
}

/// Detect if running on GCP Shielded VM
///
/// Detection based on:
/// 1. TPM manufacturer ID is "GOOG"
/// 2. GCP AK template NV index exists
fn is_gcp_tpm(tpm: &mut Tpm) -> bool {
    // Check manufacturer
    if let Ok(manufacturer) = tpm.get_property(TPM_PT_MANUFACTURER) {
        if manufacturer == GCP_MANUFACTURER_GOOG {
            // Verify AK template exists
            if tpm.nv_readpublic(GCP_AK_TEMPLATE_NV_INDEX_RSA).is_ok() {
                return true;
            }
        }
    }
    false
}

/// Generate a complete TPM attestation document
///
/// This function performs platform-specific TPM2_Quote attestation:
///
/// 1. Detects platform (Nitro or GCP)
/// 2. Reads PCR values
/// 3. Creates or retrieves AK (Attestation Key):
///    - Nitro: Creates long-term AK (bound via Nitro NSM document)
///    - GCP: Recreates AK from Google's template (bound via certificate chain)
/// 4. Signs PCRs with TPM2_Quote
/// 5. Includes platform-specific attestation:
///    - Nitro: COSE Sign1 document binding AK public key
///    - GCP: AK certificate chain from NV RAM
///
/// # Arguments
/// * `nonce` - User-provided nonce/challenge to include in attestation
///
/// # Returns
/// JSON-encoded attestation document containing all attestation data
///
/// # Errors
/// Returns an error if the platform is not recognized (only AWS Nitro and GCP are supported)
pub fn attest(nonce: &[u8]) -> Result<String> {
    let mut tpm = Tpm::open_direct()?;

    // Step 1: Detect platform
    // GCP detection is cheap - just checks for NV index existence
    let is_nitro = tpm.is_nitro_tpm()?;
    let is_gcp = !is_nitro && is_gcp_tpm(&mut tpm);

    // Step 2: Read all allocated PCRs from all banks
    let all_pcrs = tpm.read_all_allocated_pcrs()?;

    // Choose PCR bank based on platform
    // Nitro uses SHA-384 for signed PCRs, others use SHA-256
    let pcr_alg = if is_nitro {
        crate::TpmAlg::Sha384
    } else {
        crate::TpmAlg::Sha256
    };

    // Get PCR values for the chosen bank
    let pcr_values: Vec<(u8, Vec<u8>)> = all_pcrs
        .iter()
        .filter(|(_, alg, _)| *alg == pcr_alg)
        .map(|(idx, _, val)| (*idx, val.clone()))
        .collect();

    if pcr_values.is_empty() {
        return Err(anyhow!("No {:?} PCRs allocated on this TPM", pcr_alg));
    }

    // Build PCRs output
    let mut pcrs_by_alg: HashMap<String, BTreeMap<u8, String>> = HashMap::new();
    let pcr_map = pcrs_by_alg.entry(pcr_alg.name().to_string()).or_default();
    for (idx, value) in &pcr_values {
        pcr_map.insert(*idx, hex::encode(value));
    }

    // Step 5: Create or retrieve AK and sign PCRs with TPM2_Quote
    let (signing_key_public_keys, attestation_data, gcp_attestation, ak_handle) = if is_gcp {
        // GCP path: recreate AK from Google's template
        attest_gcp(&mut tpm, nonce, &pcr_values, pcr_alg)?
    } else if is_nitro {
        // Nitro path: create long-term AK, use TPM2_Quote
        attest_nitro(&mut tpm, nonce, &pcr_values, pcr_alg)?
    } else {
        return Err(anyhow!(
            "Unknown platform - only AWS Nitro and GCP Shielded VM are supported"
        ));
    };

    let mut tpm_attestations = HashMap::new();
    tpm_attestations.insert("ecc_p256".to_string(), attestation_data);

    // Step 6: Get Nitro attestation if on AWS
    let nitro_attestation = if is_nitro {
        if let Some(pk) = signing_key_public_keys.get("ecc_p256") {
            let public_key_hex = format!("04{}{}", pk.x, pk.y);
            let public_key_bytes = hex::decode(&public_key_hex)?;

            match tpm.nsm_attest(
                None,                   // user_data
                Some(nonce.to_vec()),   // nonce
                Some(public_key_bytes), // public_key
            ) {
                Ok(document) => Some(NitroAttestationData {
                    document: hex::encode(&document),
                }),
                Err(_e) => None,
            }
        } else {
            None
        }
    } else {
        None
    };

    let attestation = AttestationContainer {
        tpm: tpm_attestations,
        nitro: nitro_attestation,
        gcp: gcp_attestation,
    };

    // Cleanup TPM handles
    if let Some(handle) = ak_handle {
        tpm.flush_context(handle)?;
    }

    // Step 5: Build and output JSON
    let output = AttestationOutput {
        nonce: hex::encode(nonce),
        pcrs: pcrs_by_alg,
        ak_pubkeys: signing_key_public_keys,
        attestation,
    };

    let json = serde_json::to_string_pretty(&output)?;

    Ok(json)
}

/// Nitro attestation path: create long-term AK and use TPM2_Quote
///
/// Creates an AK without PCR binding (long-term key), then uses TPM2_Quote
/// to sign the PCR values. The AK is bound to the Nitro NSM document instead.
fn attest_nitro(
    tpm: &mut Tpm,
    nonce: &[u8],
    pcr_values: &[(u8, Vec<u8>)],
    pcr_alg: crate::TpmAlg,
) -> Result<AttestResult> {
    // Create long-term AK (no PCR binding - trust comes from Nitro NSM document)
    let signing_key = tpm.create_primary_ecc_key(TPM_RH_OWNER)?;

    let mut signing_key_public_keys = HashMap::new();
    signing_key_public_keys.insert(
        "ecc_p256".to_string(),
        EccPublicKeyCoords {
            x: hex::encode(&signing_key.public_key.x),
            y: hex::encode(&signing_key.public_key.y),
        },
    );

    // Build PCR selection bitmap for Quote
    let pcr_bitmap = build_pcr_bitmap(pcr_values);
    let pcr_selection = vec![(pcr_alg, pcr_bitmap.as_slice())];

    // Perform TPM2_Quote - signs PCR values with AK
    let quote_result = tpm.quote(signing_key.handle, nonce, &pcr_selection)?;

    let attestation_data = AttestationData {
        attest_data: hex::encode(&quote_result.attest_data),
        signature: hex::encode(&quote_result.signature),
    };

    Ok((
        signing_key_public_keys,
        attestation_data,
        None,
        Some(signing_key.handle),
    ))
}

/// GCP attestation path: recreate AK from template and use TPM2_Quote
fn attest_gcp(
    tpm: &mut Tpm,
    nonce: &[u8],
    pcr_values: &[(u8, Vec<u8>)],
    pcr_alg: crate::TpmAlg,
) -> Result<AttestResult> {
    // Read ECC AK template from NV RAM (prefer ECC over RSA for ECDSA signing)
    let ak_template = tpm.nv_read(GCP_AK_TEMPLATE_NV_INDEX_ECC)?;

    // Recreate AK from template in endorsement hierarchy
    let ak_result = tpm.create_primary_from_template(TPM_RH_ENDORSEMENT, &ak_template)?;

    // Extract ECC public key coordinates
    let signing_key_public_keys = match &ak_result.public_key {
        PublicKey::Ecc(ecc) => {
            let mut pks = HashMap::new();
            pks.insert(
                "ecc_p256".to_string(),
                EccPublicKeyCoords {
                    x: hex::encode(&ecc.x),
                    y: hex::encode(&ecc.y),
                },
            );
            pks
        }
        PublicKey::Rsa(_) => {
            return Err(anyhow!(
                "GCP ECC AK template unexpectedly created an RSA key"
            ));
        }
    };

    // Build PCR selection bitmap for Quote
    // Include all PCRs from pcr_values
    let pcr_bitmap = build_pcr_bitmap(pcr_values);
    let pcr_selection = vec![(pcr_alg, pcr_bitmap.as_slice())];

    // Perform TPM2_Quote - signs PCR values with AK
    let quote_result = tpm.quote(ak_result.handle, nonce, &pcr_selection)?;

    // Read AK certificate chain from NV RAM
    let ak_cert_chain = read_gcp_ak_cert_chain(tpm)?;

    let attestation_data = AttestationData {
        attest_data: hex::encode(&quote_result.attest_data),
        signature: hex::encode(&quote_result.signature),
    };

    let gcp_attestation = Some(GcpAttestationData { ak_cert_chain });

    Ok((
        signing_key_public_keys,
        attestation_data,
        gcp_attestation,
        Some(ak_result.handle),
    ))
}

/// Build PCR bitmap from list of (index, value) pairs
fn build_pcr_bitmap(pcr_values: &[(u8, Vec<u8>)]) -> Vec<u8> {
    // TPM uses 3 bytes for PCR selection (24 PCRs max)
    let mut bitmap = vec![0u8; 3];
    for (idx, _) in pcr_values {
        if *idx < 24 {
            let byte_idx = (*idx / 8) as usize;
            let bit_idx = *idx % 8;
            bitmap[byte_idx] |= 1 << bit_idx;
        }
    }
    bitmap
}

/// Read GCP ECC AK certificate chain from NV RAM and fetch issuer certs
fn read_gcp_ak_cert_chain(tpm: &mut Tpm) -> Result<String> {
    // Read ECC AK certificate (matches the ECC AK template we use)
    let ak_cert = tpm.nv_read(GCP_AK_CERT_NV_INDEX_ECC)?;

    if !ak_cert.starts_with(&DER_SEQUENCE_LONG) {
        return Err(anyhow!(
            "GCP AK certificate is not in DER format (got {:02x?})",
            &ak_cert[..ak_cert.len().min(4)]
        ));
    }

    // Build full chain by fetching issuer certs via AIA
    let chain = fetch_cert_chain(&ak_cert)?;

    // Convert all certs to PEM and concatenate
    let pem_chain: String = chain
        .iter()
        .map(|cert| der_to_pem(cert, "CERTIFICATE"))
        .collect::<Vec<_>>()
        .join("");

    Ok(pem_chain)
}
