// SPDX-License-Identifier: MIT OR Apache-2.0

//! Flat binary format for zkVM input - uses zerocopy for zero-copy parsing
//!
//! Use `flat::to_bytes()` on host, `flat::from_bytes()` in guest with `env::read_slice()`.

use std::collections::BTreeMap;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::{DecodedAttestationOutput, DecodedPlatformAttestation, VerifyError};

/// Platform type constants
pub const PLATFORM_GCP: u8 = 0;
pub const PLATFORM_NITRO: u8 = 1;

/// Fixed-size header - zerocopy will map this directly from bytes
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, packed)]
pub struct FlatHeader {
    pub nonce: [u8; 32],
    pub ak_pubkey: [u8; 65],
    pub platform_type: u8,
    pub quote_attest_len: u16,
    pub quote_signature_len: u16,
    pub pcr_count: u8,
    pub platform_data_len: u16,
}

/// Size of the fixed header
pub const HEADER_SIZE: usize = core::mem::size_of::<FlatHeader>();

/// Serialize DecodedAttestationOutput to flat binary format
pub fn to_bytes(decoded: &DecodedAttestationOutput) -> Vec<u8> {
    let platform_type = match &decoded.platform {
        DecodedPlatformAttestation::Gcp { .. } => PLATFORM_GCP,
        DecodedPlatformAttestation::Nitro { .. } => PLATFORM_NITRO,
    };

    // Build platform data
    let platform_data = match &decoded.platform {
        DecodedPlatformAttestation::Gcp { cert_chain_der } => {
            let mut data = Vec::new();
            data.push(cert_chain_der.len() as u8);
            for cert in cert_chain_der {
                data.extend_from_slice(&(cert.len() as u16).to_le_bytes());
            }
            for cert in cert_chain_der {
                data.extend_from_slice(cert);
            }
            data
        }
        DecodedPlatformAttestation::Nitro { document } => document.clone(),
    };

    let header = FlatHeader {
        nonce: decoded.nonce,
        ak_pubkey: decoded.ak_pubkey,
        platform_type,
        quote_attest_len: decoded.quote_attest.len() as u16,
        quote_signature_len: decoded.quote_signature.len() as u16,
        pcr_count: decoded.pcrs.len() as u8,
        platform_data_len: platform_data.len() as u16,
    };

    let mut buf = Vec::with_capacity(HEADER_SIZE + 2048 + platform_data.len());

    // Write header as bytes (zerocopy ensures correct layout)
    buf.extend_from_slice(header.as_bytes());

    // Write PCRs: [alg_id, pcr_idx, len, value...]
    for ((alg_id, pcr_idx), value) in &decoded.pcrs {
        buf.push(*alg_id);
        buf.push(*pcr_idx);
        buf.push(value.len() as u8);
        buf.extend_from_slice(value);
    }

    // Write quote data
    buf.extend_from_slice(&decoded.quote_attest);
    buf.extend_from_slice(&decoded.quote_signature);

    // Write platform data
    buf.extend_from_slice(&platform_data);

    buf
}

/// Parse flat binary format using zerocopy for header
pub fn from_bytes(data: &[u8]) -> Result<DecodedAttestationOutput, VerifyError> {
    if data.len() < HEADER_SIZE {
        return Err(VerifyError::InvalidAttest(format!(
            "input too short: {} < {}",
            data.len(),
            HEADER_SIZE
        )));
    }

    // Zero-copy header parsing!
    let (header, _suffix) = FlatHeader::ref_from_prefix(data)
        .map_err(|_| VerifyError::InvalidAttest("failed to parse header".into()))?;

    let quote_attest_len = header.quote_attest_len as usize;
    let quote_signature_len = header.quote_signature_len as usize;
    let pcr_count = header.pcr_count as usize;
    let platform_data_len = header.platform_data_len as usize;

    let mut offset = HEADER_SIZE;

    // Parse PCRs
    let mut pcrs = BTreeMap::new();
    for _ in 0..pcr_count {
        if offset + 3 > data.len() {
            return Err(VerifyError::InvalidAttest("truncated PCR header".into()));
        }
        let alg_id = data[offset];
        let pcr_idx = data[offset + 1];
        let value_len = data[offset + 2] as usize;
        offset += 3;

        if offset + value_len > data.len() {
            return Err(VerifyError::InvalidAttest("truncated PCR value".into()));
        }
        pcrs.insert((alg_id, pcr_idx), data[offset..offset + value_len].to_vec());
        offset += value_len;
    }

    // Parse quote data
    if offset + quote_attest_len > data.len() {
        return Err(VerifyError::InvalidAttest("truncated quote_attest".into()));
    }
    let quote_attest = data[offset..offset + quote_attest_len].to_vec();
    offset += quote_attest_len;

    if offset + quote_signature_len > data.len() {
        return Err(VerifyError::InvalidAttest(
            "truncated quote_signature".into(),
        ));
    }
    let quote_signature = data[offset..offset + quote_signature_len].to_vec();
    offset += quote_signature_len;

    // Parse platform data
    if offset + platform_data_len > data.len() {
        return Err(VerifyError::InvalidAttest("truncated platform data".into()));
    }
    let platform_bytes = &data[offset..offset + platform_data_len];

    let platform = match header.platform_type {
        PLATFORM_GCP => {
            if platform_bytes.is_empty() {
                return Err(VerifyError::InvalidAttest("empty GCP platform data".into()));
            }
            let cert_count = platform_bytes[0] as usize;
            let mut poffset = 1;

            let mut cert_lens = Vec::with_capacity(cert_count);
            for _ in 0..cert_count {
                if poffset + 2 > platform_bytes.len() {
                    return Err(VerifyError::InvalidAttest("truncated cert length".into()));
                }
                let len =
                    u16::from_le_bytes(platform_bytes[poffset..poffset + 2].try_into().unwrap())
                        as usize;
                cert_lens.push(len);
                poffset += 2;
            }

            let mut cert_chain_der = Vec::with_capacity(cert_count);
            for len in cert_lens {
                if poffset + len > platform_bytes.len() {
                    return Err(VerifyError::InvalidAttest("truncated cert data".into()));
                }
                cert_chain_der.push(platform_bytes[poffset..poffset + len].to_vec());
                poffset += len;
            }

            DecodedPlatformAttestation::Gcp { cert_chain_der }
        }
        PLATFORM_NITRO => DecodedPlatformAttestation::Nitro {
            document: platform_bytes.to_vec(),
        },
        _ => {
            return Err(VerifyError::InvalidAttest(format!(
                "unknown platform type: {}",
                header.platform_type
            )))
        }
    };

    Ok(DecodedAttestationOutput {
        nonce: header.nonce,
        pcrs,
        ak_pubkey: header.ak_pubkey,
        quote_attest,
        quote_signature,
        platform,
    })
}
