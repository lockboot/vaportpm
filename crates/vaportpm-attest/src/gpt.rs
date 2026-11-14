// SPDX-License-Identifier: MIT OR Apache-2.0

//! The firmware's `EV_EFI_GPT_EVENT`, computed from the disk instead of the event log.
//!
//! UEFI firmware measures the boot disk's partition table as `H(UEFI_GPT_DATA)`: the primary
//! GPT header (`sizeof(EFI_PARTITION_TABLE_HEADER)` = 92 bytes), the number of non-empty entries
//! as a UINTN (8 bytes on x86_64 and aarch64), then every entry whose PartitionTypeGUID is not
//! zero, `SizeOfPartitionEntry` bytes each (EDK2 `Tcg2MeasureGptTable`, MdePkg
//! `UefiTcgPlatform.h`). The disk's GPT can change after the firmware measured it, so these
//! digests are replay input, not a measurement: a verifier replays the PCR the firmware
//! extended with them and compares with the quoted value.

use alloc::vec;
use alloc::vec::Vec;
use anyhow::{bail, Result};
use sha2::{Digest, Sha256, Sha384};

/// `sizeof(EFI_PARTITION_TABLE_HEADER)`: what EDK2 copies into `UEFI_GPT_DATA`.
const GPT_HEADER_SIZE: usize = 92;

/// `H(UEFI_GPT_DATA)` in each bank an attestation may quote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GptDigests {
    pub sha256: [u8; 32],
    pub sha384: [u8; 48],
}

impl GptDigests {
    pub fn of(gpt_data: &[u8]) -> Self {
        GptDigests {
            sha256: Sha256::digest(gpt_data).into(),
            sha384: Sha384::digest(gpt_data).into(),
        }
    }

    /// Read the disk's primary GPT through `read_at(byte_offset, buf)` (filling `buf`
    /// exactly) and digest its `UEFI_GPT_DATA`. `sector` is the logical block size.
    pub fn read(
        read_at: &mut dyn FnMut(u64, &mut [u8]) -> Result<()>,
        sector: u64,
    ) -> Result<Self> {
        Ok(Self::of(&uefi_gpt_data(read_at, sector)?))
    }

    /// [`GptDigests::read`] over a block device or disk image ([`uefi_gpt_data_device`]).
    #[cfg(feature = "std")]
    pub fn read_device(path: &std::path::Path) -> Result<Self> {
        Ok(Self::of(&uefi_gpt_data_device(path)?))
    }
}

/// `UEFI_GPT_DATA` of a block device (its logical block size from
/// `/sys/class/block/<name>/queue/logical_block_size`) or a disk image file (512).
#[cfg(feature = "std")]
pub fn uefi_gpt_data_device(path: &std::path::Path) -> Result<Vec<u8>> {
    use anyhow::Context;
    use std::os::unix::fs::FileExt;
    let f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let sector = if f.metadata()?.is_file() {
        512
    } else {
        let name = path
            .file_name()
            .with_context(|| format!("{}: no device name", path.display()))?;
        let sysfs = std::path::Path::new("/sys/class/block")
            .join(name)
            .join("queue/logical_block_size");
        std::fs::read_to_string(&sysfs)
            .with_context(|| format!("read {}", sysfs.display()))?
            .trim()
            .parse()
            .with_context(|| format!("parse {}", sysfs.display()))?
    };
    uefi_gpt_data(
        &mut |off, buf| {
            f.read_exact_at(buf, off)
                .with_context(|| format!("read {} at {off}", path.display()))
        },
        sector,
    )
}

/// `UEFI_GPT_DATA` of the disk behind `read_at`.
pub fn uefi_gpt_data(
    read_at: &mut dyn FnMut(u64, &mut [u8]) -> Result<()>,
    sector: u64,
) -> Result<Vec<u8>> {
    let mut hdr = [0u8; GPT_HEADER_SIZE];
    read_at(sector, &mut hdr)?;
    if &hdr[..8] != b"EFI PART" {
        bail!("no GPT header at LBA 1");
    }
    let entry_lba = u64::from_le_bytes(hdr[72..80].try_into().unwrap());
    let count = u32::from_le_bytes(hdr[80..84].try_into().unwrap()) as usize;
    let size = u32::from_le_bytes(hdr[84..88].try_into().unwrap()) as usize;
    if size < 16 {
        bail!("GPT SizeOfPartitionEntry {size} is too small");
    }
    let mut entries = vec![0u8; count * size];
    read_at(entry_lba * sector, &mut entries)?;
    let used: Vec<&[u8]> = entries
        .chunks_exact(size)
        .filter(|e| e[..16] != [0u8; 16])
        .collect();
    let mut out = Vec::with_capacity(GPT_HEADER_SIZE + 8 + used.len() * size);
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&(used.len() as u64).to_le_bytes());
    for e in used {
        out.extend_from_slice(e);
    }
    Ok(out)
}

/// JSON form: `{"sha256": "<hex>", "sha384": "<hex>"}`; both required, each its bank's length.
#[cfg(feature = "attest")]
mod json {
    use super::GptDigests;
    use alloc::string::String;
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Hex {
        sha256: String,
        sha384: String,
    }

    impl Serialize for GptDigests {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            Hex {
                sha256: hex::encode(self.sha256),
                sha384: hex::encode(self.sha384),
            }
            .serialize(s)
        }
    }

    impl<'de> Deserialize<'de> for GptDigests {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let h = Hex::deserialize(d)?;
            let mut out = GptDigests {
                sha256: [0; 32],
                sha384: [0; 48],
            };
            hex::decode_to_slice(&h.sha256, &mut out.sha256)
                .map_err(|e| D::Error::custom(alloc::format!("gpt.sha256: {e}")))?;
            hex::decode_to_slice(&h.sha384, &mut out.sha384)
                .map_err(|e| D::Error::custom(alloc::format!("gpt.sha384: {e}")))?;
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A disk with a GPT at LBA 1 (filler past HeaderSize, which must not be measured) and
    /// four 128-byte entries at LBA 2: types 0x11.., zero, 0x22.., zero (with a non-zero
    /// body, still unused).
    fn disk(sector: usize) -> Vec<u8> {
        let mut d = vec![0u8; sector * 8];
        let h = &mut d[sector..2 * sector];
        h[..8].copy_from_slice(b"EFI PART");
        h[8..12].copy_from_slice(&0x10000u32.to_le_bytes());
        h[12..16].copy_from_slice(&92u32.to_le_bytes());
        h[16..20].copy_from_slice(&0xdeadbeefu32.to_le_bytes());
        for (i, b) in h.iter_mut().enumerate().take(72).skip(24) {
            *b = i as u8;
        }
        h[72..80].copy_from_slice(&2u64.to_le_bytes());
        h[80..84].copy_from_slice(&4u32.to_le_bytes());
        h[84..88].copy_from_slice(&128u32.to_le_bytes());
        h[88..92].copy_from_slice(&0x12345678u32.to_le_bytes());
        h[92..].fill(0xee);
        for (n, t) in [(0usize, 0x11u8), (2, 0x22)] {
            let o = 2 * sector + n * 128;
            d[o..o + 16].fill(t);
            d[o + 16..o + 128].fill(t + 1);
        }
        let o = 2 * sector + 3 * 128;
        d[o + 16..o + 128].fill(0x33);
        d
    }

    fn read(d: &[u8], sector: u64) -> Result<GptDigests> {
        GptDigests::read(
            &mut |off, buf| {
                let o = off as usize;
                buf.copy_from_slice(&d[o..o + buf.len()]);
                Ok(())
            },
            sector,
        )
    }

    /// Expected values from workspace tools/pcr-replay `gpt_data()` on the same disk.
    #[test]
    fn matches_pcr_replay() {
        for sector in [512usize, 4096] {
            let g = read(&disk(sector), sector as u64).unwrap();
            assert_eq!(
                hex::encode(g.sha256),
                "f1476898d3c3d3c8d2f6d7cf345b78c7b5b44ebf3dec2bae65e3db4cc9f8e49f"
            );
            assert_eq!(
                hex::encode(g.sha384),
                "f864a6e329e796fca17b56352761c61c87261fe302e0bfedf3d2b74f4379f961\
                 37fd3f4092336183b47fdb639842bfa3"
            );
        }
    }

    #[test]
    fn rejects_missing_header() {
        let mut d = disk(512);
        d[512] = 0;
        assert!(read(&d, 512).is_err());
    }
}
