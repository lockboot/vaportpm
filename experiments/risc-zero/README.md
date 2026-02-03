# RISC Zero ZK Verification Experiment

This experiment runs `verify_attestation_output` inside RISC Zero zkVM to measure cycle counts and understand complexity.

## Prerequisites

1. Install the RISC Zero toolchain:
   ```bash
   # Install rzup (RISC Zero's toolchain manager)
   curl -L https://risczero.com/install | bash

   # Restart shell or source profile, then install toolchain
   rzup install
   ```

## Usage

### Run Cycle Count Tests

```bash
cd experiments/risc-zero

# Enable dev mode (fast execution, no real proofs)
export RISC0_DEV_MODE=1

# Run all cycle count tests
make cycles
```

Or run tests directly:
```bash
RISC0_DEV_MODE=1 cargo test -- --nocapture
```

### Expected Output

```
=== GCP Attestation Verification ===
Total cycles: 1993676
Segments: 3

=== Nitro Attestation Verification ===
Total cycles: 315958121
Segments: 318
```

## Public Inputs

The ZK circuit commits the following public inputs:

| Field | Size | Description |
|-------|------|-------------|
| `pcr_hash` | 32 bytes | SHA256 of canonically-serialized PCRs |
| `ak_pubkey` | 65 bytes | P-256 uncompressed: `0x04 \|\| x \|\| y` |
| `nonce` | 32 bytes | Freshness nonce |
| `provider` | 1 byte | 0 = AWS, 1 = GCP |
| `root_pubkey_hash` | 32 bytes | SHA256 of root CA public key |

## Structure

```
experiments/risc-zero/
├── Cargo.toml              # Host crate (standalone workspace)
├── Makefile                # Build/test commands
├── src/
│   ├── lib.rs              # Library root
│   ├── host.rs             # Host utilities
│   └── inputs.rs           # ZkPublicInputs type
├── tests/
│   └── cycle_count.rs      # Integration tests
└── methods/
    ├── Cargo.toml          # Methods crate
    ├── build.rs            # Embeds guest ELF
    ├── src/lib.rs          # Re-exports generated constants
    └── guest/
        ├── Cargo.toml      # Guest deps + crypto patches
        └── src/main.rs     # Guest circuit
```

## How It Works

1. The **guest program** (`methods/guest/src/main.rs`) runs inside the zkVM:
   - Reads attestation JSON and timestamp from host
   - Calls `verify_attestation_output()` (same verification as native)
   - Computes canonical PCR hash
   - Commits public inputs to the journal

2. The **host** (`tests/cycle_count.rs`) provides inputs and measures cycles:
   - Loads test fixtures (GCP AMD and Nitro attestations)
   - Builds executor environment with inputs
   - Runs guest in dev mode (no real proofs)
   - Reports cycle counts per segment

## Accelerated Cryptography

The guest uses RISC Zero's patched crypto crates for hardware-accelerated precompiles:

| Crate | Precompile | Notes |
|-------|------------|-------|
| `sha2` | SHA-256/SHA-384 | Used extensively in cert validation |
| `p256` | P-256 ECDSA | GCP uses P-256 for signatures |
| `rsa` | RSA | GCP uses RSA-4096 certificates |
| `crypto-bigint` | Modular arithmetic | Accelerates bigint operations |

These patches are applied via `[patch.crates-io]` in the guest Cargo.toml.

### P-384 Support (Nitro)

AWS Nitro uses **P-384 ECDSA** for its certificate chain, which currently lacks a dedicated RISC Zero precompile. This explains the ~160x cycle difference between GCP (~2M) and Nitro (~316M).

The `risc0-bigint2` crate (v1.4.x) includes P-384 field support, suggesting the team is aware and working on it. The `k256` precompile uses `modmul_u256_denormalized` intrinsics, and `p256` uses `risc0_bigint2::field` - a similar approach for P-384 would dramatically reduce Nitro verification cycles.

For reference, GCP verification with RSA-4096 (3 certificates) achieves ~2M cycles, demonstrating the effectiveness of the RSA precompile.

## Notes

- This is a **research experiment** to evaluate ZK attestation verification feasibility
- Uses dev mode for fast iteration (no real proofs generated)
- The main project is completely unchanged
- Cycle counts give rough indication of proving cost
- GCP verification is production-viable at ~2M cycles
- Nitro verification awaits P-384 precompile support for practical use
