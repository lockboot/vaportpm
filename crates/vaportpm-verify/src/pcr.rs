// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validated PCR bank type and supporting types.

use std::collections::BTreeMap;

use crate::error::{InvalidAttestReason, VerifyError};

/// Number of PCRs in a complete bank.
pub const PCR_COUNT: usize = 24;

/// PCR hash algorithm.
///
/// Discriminant values are the TPM algorithm IDs (TPMI_ALG_HASH).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum PcrAlgorithm {
    Sha256 = 0x000B,
    Sha384 = 0x000C,
}

impl PcrAlgorithm {
    /// Digest length in bytes.
    pub fn digest_len(self) -> usize {
        match self {
            PcrAlgorithm::Sha256 => 32,
            PcrAlgorithm::Sha384 => 48,
        }
    }
}

impl TryFrom<u16> for PcrAlgorithm {
    type Error = u16;
    fn try_from(value: u16) -> Result<Self, u16> {
        match value {
            0x000B => Ok(PcrAlgorithm::Sha256),
            0x000C => Ok(PcrAlgorithm::Sha384),
            other => Err(other),
        }
    }
}

impl std::fmt::Display for PcrAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PcrAlgorithm::Sha256 => write!(f, "SHA-256"),
            PcrAlgorithm::Sha384 => write!(f, "SHA-384"),
        }
    }
}

/// A complete, validated PCR bank.
///
/// Invariants guaranteed by construction:
/// - Single algorithm (SHA-256 or SHA-384)
/// - Exactly 24 PCR values, indexed 0-23
/// - Each value has the correct length for the algorithm
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)] // Intentional: avoid heap allocation in zkVM
pub enum PcrBank {
    Sha256([[u8; 32]; PCR_COUNT]),
    Sha384([[u8; 48]; PCR_COUNT]),
}

impl PcrBank {
    /// Construct from a `BTreeMap<(u16, u8), Vec<u8>>` keyed by `(tpm_alg_id, pcr_index)`.
    ///
    /// Validates: single algorithm, all 24 indices present, correct value lengths.
    pub fn from_btree_map(pcrs: &BTreeMap<(u16, u8), Vec<u8>>) -> Result<Self, VerifyError> {
        if pcrs.is_empty() {
            return Err(InvalidAttestReason::PcrBankEmpty.into());
        }

        // Determine the single algorithm
        let first_alg = pcrs.keys().next().unwrap().0;
        for (alg_id, _) in pcrs.keys() {
            if *alg_id != first_alg {
                return Err(InvalidAttestReason::PcrBankMixedAlgorithms.into());
            }
        }

        let algorithm = PcrAlgorithm::try_from(first_alg)
            .map_err(|alg_id| InvalidAttestReason::UnknownPcrAlgorithm { alg_id })?;

        // Check count
        if pcrs.len() != PCR_COUNT {
            return Err(InvalidAttestReason::PcrBankWrongCount {
                expected: PCR_COUNT,
                got: pcrs.len(),
            }
            .into());
        }

        let alg_key = algorithm as u16;
        match algorithm {
            PcrAlgorithm::Sha256 => {
                let mut values = [[0u8; 32]; PCR_COUNT];
                for idx in 0..PCR_COUNT as u8 {
                    let value = pcrs
                        .get(&(alg_key, idx))
                        .ok_or(InvalidAttestReason::MissingPcr { index: idx })?;
                    if value.len() != 32 {
                        return Err(InvalidAttestReason::PcrValueWrongLength {
                            index: idx,
                            expected: 32,
                            got: value.len(),
                        }
                        .into());
                    }
                    values[idx as usize].copy_from_slice(value);
                }
                Ok(PcrBank::Sha256(values))
            }
            PcrAlgorithm::Sha384 => {
                let mut values = [[0u8; 48]; PCR_COUNT];
                for idx in 0..PCR_COUNT as u8 {
                    let value = pcrs
                        .get(&(alg_key, idx))
                        .ok_or(InvalidAttestReason::MissingPcr { index: idx })?;
                    if value.len() != 48 {
                        return Err(InvalidAttestReason::PcrValueWrongLength {
                            index: idx,
                            expected: 48,
                            got: value.len(),
                        }
                        .into());
                    }
                    values[idx as usize].copy_from_slice(value);
                }
                Ok(PcrBank::Sha384(values))
            }
        }
    }

    /// Which algorithm this bank uses.
    pub fn algorithm(&self) -> PcrAlgorithm {
        match self {
            PcrBank::Sha256(_) => PcrAlgorithm::Sha256,
            PcrBank::Sha384(_) => PcrAlgorithm::Sha384,
        }
    }

    /// Get a single PCR value by index. Panics if `index >= 24`.
    pub fn get(&self, index: usize) -> &[u8] {
        match self {
            PcrBank::Sha256(v) => &v[index],
            PcrBank::Sha384(v) => &v[index],
        }
    }

    /// Iterate all 24 PCR values in index order as `&[u8]` slices.
    pub fn values(&self) -> PcrIter<'_> {
        PcrIter { bank: self, idx: 0 }
    }

    /// Convert back to `BTreeMap<(u16, u8), Vec<u8>>` keyed by `(tpm_alg_id, pcr_index)`.
    pub fn to_btree_map(&self) -> BTreeMap<(u16, u8), Vec<u8>> {
        let alg_key = self.algorithm() as u16;
        let mut map = BTreeMap::new();
        for idx in 0..PCR_COUNT {
            map.insert((alg_key, idx as u8), self.get(idx).to_vec());
        }
        map
    }
}

/// Iterator over PCR values as `&[u8]` slices.
pub struct PcrIter<'a> {
    bank: &'a PcrBank,
    idx: usize,
}

impl<'a> Iterator for PcrIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= PCR_COUNT {
            return None;
        }
        let val = self.bank.get(self.idx);
        self.idx += 1;
        Some(val)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = PCR_COUNT - self.idx;
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for PcrIter<'a> {}

/// ECDSA P-256 public key as raw x/y coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct P256PublicKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

impl P256PublicKey {
    /// Parse from SEC1 uncompressed format (`0x04 || x || y`, 65 bytes).
    pub fn from_sec1_uncompressed(bytes: &[u8]) -> Result<Self, VerifyError> {
        if bytes.len() != 65 || bytes[0] != 0x04 {
            return Err(InvalidAttestReason::InvalidAkPubkeyFormat.into());
        }
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&bytes[1..33]);
        y.copy_from_slice(&bytes[33..65]);
        Ok(P256PublicKey { x, y })
    }

    /// Construct from raw x and y coordinates.
    pub fn from_coords(x: &[u8], y: &[u8]) -> Result<Self, VerifyError> {
        if x.len() != 32 || y.len() != 32 {
            return Err(InvalidAttestReason::InvalidAkPubkeyFormat.into());
        }
        let mut xb = [0u8; 32];
        let mut yb = [0u8; 32];
        xb.copy_from_slice(x);
        yb.copy_from_slice(y);
        Ok(P256PublicKey { x: xb, y: yb })
    }

    /// Reconstruct SEC1 uncompressed format (`0x04 || x || y`, 65 bytes).
    pub fn to_sec1_uncompressed(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[0] = 0x04;
        out[1..33].copy_from_slice(&self.x);
        out[33..65].copy_from_slice(&self.y);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sha256_btree() -> BTreeMap<(u16, u8), Vec<u8>> {
        let mut m = BTreeMap::new();
        for idx in 0..24u8 {
            m.insert((PcrAlgorithm::Sha256 as u16, idx), vec![idx; 32]);
        }
        m
    }

    fn make_sha384_btree() -> BTreeMap<(u16, u8), Vec<u8>> {
        let mut m = BTreeMap::new();
        for idx in 0..24u8 {
            m.insert((PcrAlgorithm::Sha384 as u16, idx), vec![idx; 48]);
        }
        m
    }

    #[test]
    fn test_from_btree_map_sha256() {
        let m = make_sha256_btree();
        let bank = PcrBank::from_btree_map(&m).unwrap();
        assert_eq!(bank.algorithm(), PcrAlgorithm::Sha256);
        assert_eq!(bank.get(0), &[0u8; 32]);
        assert_eq!(bank.get(23), &[23u8; 32]);
        assert_eq!(bank.values().count(), 24);
    }

    #[test]
    fn test_from_btree_map_sha384() {
        let m = make_sha384_btree();
        let bank = PcrBank::from_btree_map(&m).unwrap();
        assert_eq!(bank.algorithm(), PcrAlgorithm::Sha384);
        assert_eq!(bank.get(0), &[0u8; 48]);
        assert_eq!(bank.get(23), &[23u8; 48]);
    }

    #[test]
    fn test_reject_empty() {
        let m = BTreeMap::new();
        let err = PcrBank::from_btree_map(&m).unwrap_err();
        assert!(matches!(
            err,
            VerifyError::InvalidAttest(InvalidAttestReason::PcrBankEmpty)
        ));
    }

    #[test]
    fn test_reject_mixed_algorithms() {
        let mut m = BTreeMap::new();
        for idx in 0..23u8 {
            m.insert((PcrAlgorithm::Sha256 as u16, idx), vec![idx; 32]);
        }
        m.insert((PcrAlgorithm::Sha384 as u16, 23), vec![23; 48]); // wrong algorithm
        let err = PcrBank::from_btree_map(&m).unwrap_err();
        assert!(matches!(
            err,
            VerifyError::InvalidAttest(InvalidAttestReason::PcrBankMixedAlgorithms)
        ));
    }

    #[test]
    fn test_reject_wrong_count() {
        let mut m = BTreeMap::new();
        for idx in 0..23u8 {
            // only 23
            m.insert((PcrAlgorithm::Sha256 as u16, idx), vec![idx; 32]);
        }
        let err = PcrBank::from_btree_map(&m).unwrap_err();
        assert!(matches!(
            err,
            VerifyError::InvalidAttest(InvalidAttestReason::PcrBankWrongCount { .. })
        ));
    }

    #[test]
    fn test_reject_wrong_value_length() {
        let mut m = BTreeMap::new();
        for idx in 0..24u8 {
            if idx == 5 {
                m.insert((PcrAlgorithm::Sha256 as u16, idx), vec![idx; 48]); // wrong length for SHA-256
            } else {
                m.insert((PcrAlgorithm::Sha256 as u16, idx), vec![idx; 32]);
            }
        }
        let err = PcrBank::from_btree_map(&m).unwrap_err();
        assert!(matches!(
            err,
            VerifyError::InvalidAttest(InvalidAttestReason::PcrValueWrongLength {
                index: 5,
                expected: 32,
                got: 48
            })
        ));
    }

    #[test]
    fn test_reject_unknown_algorithm() {
        let mut m = BTreeMap::new();
        for idx in 0..24u8 {
            m.insert((0x9999, idx), vec![idx; 32]); // unknown TPM algorithm
        }
        let err = PcrBank::from_btree_map(&m).unwrap_err();
        assert!(matches!(
            err,
            VerifyError::InvalidAttest(InvalidAttestReason::UnknownPcrAlgorithm { alg_id: 0x9999 })
        ));
    }

    #[test]
    fn test_reject_index_out_of_range() {
        let mut m = BTreeMap::new();
        for idx in 0..23u8 {
            m.insert((PcrAlgorithm::Sha256 as u16, idx), vec![idx; 32]);
        }
        m.insert((PcrAlgorithm::Sha256 as u16, 24), vec![24; 32]); // out of range
                                                                   // This has 24 entries but index 23 is missing and 24 is present
        let err = PcrBank::from_btree_map(&m).unwrap_err();
        assert!(matches!(
            err,
            VerifyError::InvalidAttest(InvalidAttestReason::MissingPcr { index: 23 })
        ));
    }

    #[test]
    fn test_to_btree_map_roundtrip() {
        let m = make_sha256_btree();
        let bank = PcrBank::from_btree_map(&m).unwrap();
        let m2 = bank.to_btree_map();
        assert_eq!(m, m2);
    }

    #[test]
    fn test_pcr_algorithm_properties() {
        assert_eq!(PcrAlgorithm::Sha256 as u16, 0x000B);
        assert_eq!(PcrAlgorithm::Sha384 as u16, 0x000C);
        assert_eq!(PcrAlgorithm::Sha256.digest_len(), 32);
        assert_eq!(PcrAlgorithm::Sha384.digest_len(), 48);
        assert_eq!(PcrAlgorithm::try_from(0x000Bu16), Ok(PcrAlgorithm::Sha256));
        assert_eq!(PcrAlgorithm::try_from(0x000Cu16), Ok(PcrAlgorithm::Sha384));
        assert_eq!(PcrAlgorithm::try_from(0x9999u16), Err(0x9999));
    }

    #[test]
    fn test_p256_public_key_from_sec1() {
        let mut bytes = [0u8; 65];
        bytes[0] = 0x04;
        for i in 0..32 {
            bytes[1 + i] = i as u8;
            bytes[33 + i] = (32 + i) as u8;
        }
        let pk = P256PublicKey::from_sec1_uncompressed(&bytes).unwrap();
        assert_eq!(pk.to_sec1_uncompressed(), bytes);
    }

    #[test]
    fn test_p256_public_key_reject_wrong_prefix() {
        let mut bytes = [0u8; 65];
        bytes[0] = 0x02; // compressed, not uncompressed
        assert!(P256PublicKey::from_sec1_uncompressed(&bytes).is_err());
    }

    #[test]
    fn test_p256_public_key_reject_wrong_length() {
        let bytes = [0x04; 33]; // too short
        assert!(P256PublicKey::from_sec1_uncompressed(&bytes).is_err());
    }

    #[test]
    fn test_p256_from_coords() {
        let x = [1u8; 32];
        let y = [2u8; 32];
        let pk = P256PublicKey::from_coords(&x, &y).unwrap();
        assert_eq!(pk.x, x);
        assert_eq!(pk.y, y);

        let sec1 = pk.to_sec1_uncompressed();
        assert_eq!(sec1[0], 0x04);
        assert_eq!(&sec1[1..33], &x);
        assert_eq!(&sec1[33..65], &y);
    }

    #[test]
    fn test_p256_from_coords_reject_wrong_length() {
        let x = [1u8; 31]; // too short
        let y = [2u8; 32];
        assert!(P256PublicKey::from_coords(&x, &y).is_err());
    }
}
