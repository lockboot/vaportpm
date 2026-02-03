# vaportpm-attest

Produces a self-contained attestation document from a cloud vTPM. The output can be verified offline using [`vaportpm-verify`](../vaportpm-verify/).

```rust
use vaportpm_attest::attest;

let json = attest(nonce)?;
// Send json to verifier
```

The library auto-detects the cloud platform (AWS Nitro, GCP Confidential VM) and produces a JSON document containing:
- TPM2_Quote (signed PCR values)
- Platform-specific trust chain (Nitro document or GCP AK certificate)
- PCR values and nonce for verification

---

Implements the TPM 2.0 wire protocol in pure Rust—no `tss2` or C dependencies. While low-level TPM operations are exposed via extension traits, the primary interface is `attest()`.

## Low-Level TPM Operations

The following traits are available for direct TPM interaction:

| Trait | Operations |
|-------|------------|
| `PcrOps` | Read/extend PCRs across all hash banks |
| `NvOps` | Read/write NV RAM, enumerate indices |
| `KeyOps` | Create signing keys, TPM2_Quote |
| `NsmOps` | AWS Nitro Security Module attestation |

## Quick Start

### Basic TPM Operations

```rust
use vaportpm_attest::{Tpm, PcrOps, TPM_RH_OWNER};

fn main() -> anyhow::Result<()> {
    // Open the TPM
    let mut tpm = Tpm::open()?;

    // Read PCR 0 from all banks
    let pcrs = tpm.pcr_read_all_banks(&[0])?;
    for (index, alg, value) in pcrs {
        println!("PCR {} [{}]: {:02x?}", index, alg.name(), value);
    }

    // Extend PCR 23 with data (extends all allocated banks automatically)
    tpm.pcr_extend(23, b"measurement data")?;

    // Create a signing key
    let key = tpm.create_primary_ecc_key(TPM_RH_OWNER)?;
    println!("Key handle: 0x{:08X}", key.handle);

    // Sign some data
    let digest = sha256(b"Hello, TPM!");
    let signature = tpm.sign(key.handle, &digest)?;

    // Clean up
    tpm.flush_context(key.handle)?;

    Ok(())
}
```

### NV RAM Operations

```rust
use vaportpm_attest::{Tpm, NvOps, TPM_ALG_SHA256};
use vaportpm_attest::nv::{NV_INDEX_USER_START, NV_INDEX_USER_END};
use vaportpm_attest::nv::{TPMA_NV_AUTHWRITE, TPMA_NV_AUTHREAD};

fn main() -> anyhow::Result<()> {
    let mut tpm = Tpm::open()?;

    // Find a free NV index
    let nv_index = tpm.nv_find_free_index(NV_INDEX_USER_START, NV_INDEX_USER_END)?;

    // Define a new NV space (1024 bytes)
    let attrs = TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD;
    tpm.nv_define_space(nv_index, 1024, attrs, TPM_ALG_SHA256)?;

    // Write data
    tpm.nv_write(nv_index, b"Hello from NV RAM!")?;

    // Read it back
    let data = tpm.nv_read(nv_index)?;
    println!("Read: {:?}", String::from_utf8_lossy(&data));

    // Clean up
    tpm.nv_undefine_space(nv_index)?;

    Ok(())
}
```

### AWS Nitro TPM Support

```rust
use vaportpm_attest::{Tpm, NsmOps};

fn main() -> anyhow::Result<()> {
    let mut tpm = Tpm::open()?;

    // Check if this is a Nitro TPM
    if tpm.is_nitro_tpm()? {
        println!("Running on AWS Nitro TPM!");

        // Get NSM attestation document (requires /dev/tpm0)
        let mut tpm_direct = Tpm::open_direct()?;
        let doc = tpm_direct.nsm_attest(
            Some(b"user data".to_vec()),
            Some(b"nonce".to_vec()),
            None // Optional: public key
        )?;

        println!("Attestation document: {} bytes", doc.len());
    }

    Ok(())
}
```

## Requirements

- Linux with TPM 2.0 support
- `/dev/tpmrm0` accessible (TPM Resource Manager) - for most operations
- `/dev/tpm0` accessible (Direct TPM access) - for NSM vendor commands
- Rust

**Note:** Most operations use `/dev/tpmrm0` (TPM Resource Manager), which handles context management automatically. AWS Nitro NSM vendor commands require direct access via `/dev/tpm0` and should use `Tpm::open_direct()`.

## Technical Details

### Protocol Implementation

The library implements the TPM 2.0 command/response protocol as specified in the [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/):

- Big-endian serialization for all multi-byte values
- TPM2B (size-prefixed buffer) structures
- Command headers with proper sizing
- Response parsing with error handling
- Session-based authorization (password sessions)

### Supported Commands

**Standard TPM 2.0 Commands:**
- `TPM2_PCR_Read` - Read PCR values
- `TPM2_PCR_Extend` - Extend PCRs with measurements
- `TPM2_GetCapability` - Query TPM capabilities and properties
- `TPM2_CreatePrimary` - Create primary keys
- `TPM2_Sign` - Sign data with TPM keys
- `TPM2_FlushContext` - Release handles
- `TPM2_NV_Read` - Read NV storage
- `TPM2_NV_ReadPublic` - Get NV index info
- `TPM2_NV_DefineSpace` - Create NV indices
- `TPM2_NV_Write` - Write to NV storage
- `TPM2_NV_UndefineSpace` - Delete NV indices
- `TPM2_PolicyPCR` - PCR policy operations
- `TPM2_Quote` - PCR attestation

**Vendor-Specific Commands:**
- `TPM2_CC_VENDOR_AWS_NSM_REQUEST` (0x20000001) - AWS Nitro Security Module attestation

### Extension Traits

The library uses extension traits to organize functionality:

- **`PcrOps`** - PCR read/extend operations
- **`NvOps`** - NV RAM read/write operations
- **`NsmOps`** - AWS Nitro Security Module operations
- **`KeyOps`** - Key operations (create signing keys, TPM2_Quote)

Import the traits you need:
```rust
use vaportpm_attest::{Tpm, PcrOps, NvOps, NsmOps, KeyOps};
```

### Hash Algorithms

Supports multiple PCR banks:
- SHA-1 (20 bytes)
- SHA-256 (32 bytes)
- SHA-384 (48 bytes)
- SHA-512 (64 bytes)

## Architecture

### Attestation Model

The library generates TPM2_Quote attestations signed by a long-lived Attestation Key (AK). The AK's authenticity is proven via platform-specific trust anchors:

- **AWS Nitro**: The AK public key is embedded in a Nitro attestation document (via `nsm_attest`), which is signed by Amazon's Nitro CA chain.
- **GCP Confidential VM**: The AK has a certificate stored in TPM NV RAM, signed by Google's CA chain.

Both paths produce a TPM2_Quote (signed PCR values + nonce) that can be verified against the platform's root of trust.

See [AWS-NITRO.md](./AWS-NITRO.md) for detailed AWS Nitro attestation documentation.
