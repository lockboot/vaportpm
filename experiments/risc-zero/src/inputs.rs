// SPDX-License-Identifier: MIT OR Apache-2.0

//! ZK public inputs for attestation verification

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Public inputs committed by the ZK circuit
///
/// These values are revealed to the verifier and represent the
/// verified attestation claims.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZkPublicInputs {
    /// SHA256 of canonically-serialized PCRs
    pub pcr_hash: [u8; 32],
    /// P-256 uncompressed public key: 0x04 || x || y
    #[serde(with = "BigArray")]
    pub ak_pubkey: [u8; 65],
    /// Freshness nonce
    pub nonce: [u8; 32],
    /// Cloud provider: 0 = AWS, 1 = GCP
    pub provider: u8,
    /// SHA256 of root CA public key
    pub root_pubkey_hash: [u8; 32],
}

impl ZkPublicInputs {
    /// Provider constant for AWS
    pub const PROVIDER_AWS: u8 = 0;
    /// Provider constant for GCP
    pub const PROVIDER_GCP: u8 = 1;
}
