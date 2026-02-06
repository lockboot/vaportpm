# RISC Zero ZK Verification Experiment

This experiment runs `verify_decoded_attestation_output` inside RISC Zero zkVM to measure cycle counts and understand complexity.

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
=== GCP Attestation Verification (Optimized + zerocopy) ===
Flat input size: 5792 bytes
Total cycles: 882866
Segments: 2

=== Nitro Attestation Verification (Optimized + zerocopy) ===
Flat input size: 6446 bytes
Total cycles: 4177180
Segments: 5
```

## Host-to-Guest Communication

Attestation data is passed from host to guest using an internal flat binary format (`vaportpm_verify::flat`). This avoids JSON parsing and hex decoding inside the zkVM, which would waste cycles on string manipulation rather than cryptographic verification.

The host performs all text parsing (JSON, hex, PEM) upfront, converts to `DecodedAttestationOutput`, then serializes via `flat::to_bytes()`. The guest deserializes with `flat::from_bytes()` and calls `verify_decoded_attestation_output()` — the same verification function used by the native path. The flat format uses a zerocopy header for zero-allocation parsing of fixed fields.

## Public Inputs

The ZK circuit commits the following public inputs to the journal:

| Field | Type | Description |
|-------|------|-------------|
| `pcr_hash` | `[u8; 32]` | SHA-256 of canonically-serialized PCR bank |
| `ak_pubkey` | `P256PublicKey` | AK public key (P-256 x/y coordinates) |
| `nonce` | `[u8; 32]` | Freshness nonce from TPM Quote |
| `provider` | `u8` | 0 = AWS, 1 = GCP |
| `verified_at` | `u64` | Verification timestamp (Unix seconds) |

The `pcr_hash` is computed inside the guest as `SHA256(alg_u16_le || count || idx0 || value0 || idx1 || value1 || ...)` over the validated PCR bank, providing a compact commitment to all 24 PCR values.

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
│   ├── cycle_count.rs      # Integration tests (cycle measurement)
│   └── ec_benchmarks.rs    # EC operation benchmarks
└── methods/
    ├── Cargo.toml          # Methods crate
    ├── build.rs            # Embeds guest ELF
    ├── src/lib.rs          # Re-exports generated constants
    └── guest/
        ├── Cargo.toml      # Guest deps + crypto patches
        └── src/main.rs     # Guest circuit
```

## How It Works

1. The **host** (`tests/cycle_count.rs`) prepares inputs and measures cycles:
   - Loads test fixtures (GCP AMD and Nitro attestations)
   - Parses JSON and decodes hex/PEM on the host side
   - Serializes to flat binary format via `flat::to_bytes()` with appended timestamp
   - Runs the guest in dev mode (no real proofs) and reports cycle counts

2. The **guest program** (`methods/guest/src/main.rs`) runs inside the zkVM:
   - Reads flat binary input via `env::stdin()`
   - Parses with `flat::from_bytes()` (zerocopy header, no allocations for fixed fields)
   - Calls `verify_decoded_attestation_output()` (identical verification to native)
   - Computes canonical PCR hash over the validated bank
   - Commits public inputs to the journal

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

### Why Nitro is ~4.7x slower than GCP

Both P-256 and P-384 have precompile acceleration, but the cost difference comes from volume. Nitro requires **5 P-384 ECDSA verifications**:
- 1 COSE signature verification (~1M cycles: ~400k P-384 verify + ~570k SHA-512 over COSE document)
- 4 certificate chain verifications (~400k cycles each)

GCP uses RSA-4096 (cheap with dedicated precompile) and a single P-256 ECDSA verification (~250k cycles), keeping the total well under 1M cycles.

Batch multi-scalar multiplication could theoretically help, but ECDSA verify requires independent scalar muls per signature (different messages and keys), and the RISC Zero precompile interface doesn't expose batching. This is effectively the floor for Nitro's chain structure.

## Notes

- This is a **research experiment** to evaluate ZK attestation verification feasibility
- Uses dev mode for fast iteration (no real proofs generated)
- The main project is completely unchanged
- Cycle counts give rough indication of proving cost
- GCP verification is production-viable at ~883K cycles (2 segments)
- Nitro verification is viable at ~4.2M cycles with P-384 acceleration (pending upstream merge)

## Dependencies

This experiment requires the P-384 accelerated elliptic-curves fork which hasn't yet been upstreamed to RISC-Zero. After cloning, initialize the submodule:

```bash
git submodule update --init --recursive
```
