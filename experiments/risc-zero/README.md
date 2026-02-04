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
Total cycles: 1998559
Segments: 3

=== Nitro Attestation Verification ===
Total cycles: 5027644
Segments: 6
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
├── rustcrypto-elliptic-curves/  # Git submodule (P-384 fork)
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
| `p256` | P-256 ECDSA | GCP uses P-256 for AK signatures |
| `p384` | P-384 ECDSA | Nitro uses P-384 for all signatures (via fork) |
| `rsa` | RSA | GCP uses RSA-4096 certificates |
| `crypto-bigint` | Modular arithmetic | Accelerates bigint operations |

These patches are applied via `[patch.crates-io]` in the guest Cargo.toml. The P-384 acceleration requires the `elliptic-curves` submodule.

### P-384 Support (Nitro)

AWS Nitro uses **P-384 ECDSA** exclusively for its certificate chain. This experiment uses a patched version of `elliptic-curves` with P-384 acceleration via `risc0-bigint2`.

**Upstream PR:** https://github.com/risc0/RustCrypto-elliptic-curves/pull/15

The P-384 patch is included as a git submodule at `rustcrypto-elliptic-curves/`, tracking the `risc0-p256-p384-unified` branch from the fork.

#### Why Nitro is ~2.5x slower than GCP

Nitro attestation requires **5 P-384 ECDSA verifications**:
- 1 COSE signature verification (attestation document)
- 4 certificate chain verifications (leaf → instance → zonal → regional → root)

Each P-384 verification costs ~400-500k cycles. The breakdown from profiling:
- P-384 EC scalar multiplication: ~30% of total cycles
- SHA-512 (used by SHA-384): ~15% of total cycles
- Bigint operations: ~29% of total cycles

GCP uses RSA-4096 (which has a dedicated precompile) and P-256, requiring fewer expensive operations.

## Notes

- This is a **research experiment** to evaluate ZK attestation verification feasibility
- Uses dev mode for fast iteration (no real proofs generated)
- The main project is completely unchanged
- Cycle counts give rough indication of proving cost
- GCP verification is production-viable at ~2M cycles
- Nitro verification is viable at ~5M cycles with P-384 acceleration (pending upstream merge)

## Dependencies

This experiment requires the P-384 accelerated elliptic-curves fork. After cloning, initialize the submodule:

```bash
git submodule update --init --recursive
```
