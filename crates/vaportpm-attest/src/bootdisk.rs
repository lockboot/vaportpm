// SPDX-License-Identifier: MIT OR Apache-2.0

//! Finding the boot disk, whose GPT the firmware measured: the one whole disk whose GPT has
//! an EFI System Partition.
//!
//! Best effort. A wrong pick is not a trust problem: the GPT digests are replay input, so a
//! digest of the wrong disk fails the PCR comparison. It is an availability problem, so
//! zero or several candidates is an error and the caller names the disk instead.

use crate::gpt::uefi_gpt_data_device;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

/// EFI System Partition type GUID c12a7328-f81f-11d2-ba4b-00a0c93ec93b, on-disk byte order.
const ESP_TYPE: [u8; 16] = [
    0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
];

/// The boot disk (module doc).
pub fn boot_disk() -> Result<PathBuf> {
    let mut esp = Vec::new();
    for dev in whole_disks()? {
        let Ok(gpt) = uefi_gpt_data_device(&dev) else {
            continue;
        };
        if entries(&gpt).any(|e| e[..16] == ESP_TYPE) {
            esp.push(dev);
        }
    }
    match esp.len() {
        1 => Ok(esp.remove(0)),
        0 => bail!("no disk has an EFI System Partition"),
        n => bail!("{n} disks have an EFI System Partition"),
    }
}

/// Whole disks under /sys/block, less the kinds that are never the boot disk.
fn whole_disks() -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir("/sys/block").context("read /sys/block")? {
        let name = entry?.file_name();
        let n = name.to_string_lossy();
        if ["loop", "ram", "sr", "dm-", "md", "zram", "fd", "nbd"]
            .iter()
            .any(|p| n.starts_with(p))
        {
            continue;
        }
        out.push(Path::new("/dev").join(&*n));
    }
    Ok(out)
}

/// The partition entries of a `UEFI_GPT_DATA` (header, UINT64 count, entries).
fn entries(gpt: &[u8]) -> impl Iterator<Item = &[u8]> {
    let size = u32::from_le_bytes(gpt[84..88].try_into().unwrap()) as usize;
    gpt[100..].chunks_exact(size)
}
