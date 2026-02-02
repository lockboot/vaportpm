# v[apor]TPM

> What does the "v" in vTPM stand for?

Cloud vTPM attestation library for Rust. Zero C dependencies.

## The Name

```
vTPM      →  v[apor]TPM
lockboot  →  [g]lockboot
```

Physical TPM trust is vapor. It evaporates under scrutiny - supply chain attacks, firmware vulnerabilities, the whole theater. The only meaningful TPM trust lives in cloud vTPMs, where the hypervisor **is** the root of trust.

The "v" always stood for vapor. Everyone just forgot.

## Crates

| Crate | Description |
|-------|-------------|
| [vaportpm-attest](./crates/vaportpm-attest/) | Generate attestations - talks to TPM |
| [vaportpm-verify](./crates/vaportpm-verify/) | Verify attestations - no TPM needed |

## Trust Model

The verifier handles **cryptographic verification**:
- Validates signatures and certificate chains
- Returns the SHA-256 hash of the trust anchor's public key

You handle **policy decisions**:
- Is this trust root acceptable?
- Do the PCR values match known-good measurements?

## Supported Platforms

| Platform | Status | Trust Anchor |
|----------|--------|--------------|
| AWS Nitro | ✅ Working | Nitro Root CA |
| GCP Shielded VM | 🔜 Planned | Google AK certificate |
| Azure Trusted Launch | 🔜 Planned | Microsoft AK certificate |

## Quick Start

### Generate Attestation (on cloud instance)

```rust
use vaportpm_attest::attest;

let json = attest(b"challenge-nonce")?;
// Send json to verifier
```

### Verify Attestation (anywhere)

```rust
use vaportpm_verify::{verify_attestation_json, VerificationResult};

let result = verify_attestation_json(&json)?;

// Check the trust root is acceptable
if result.root_pubkey_hash == KNOWN_AWS_NITRO_ROOT_HASH {
    println!("Verified via: {:?}", result.method);
    println!("Nonce: {}", result.nonce);
}
```

## License

MIT OR Apache-2.0
