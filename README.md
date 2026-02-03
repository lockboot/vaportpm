# v[apor]TPM

**Cloud vTPM attestation library for Rust. Zero C dependencies.**

> What does the "v" in vTPM stand for?

Physical TPM trust is vapor. It evaporates under scrutiny - supply chain attacks, firmware vulnerabilities, the whole theater. The only meaningful TPM trust lives in cloud vTPMs, where the hypervisor **is** the root of trust. The "v" always stood for vapor. Everyone just forgot.

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
| AWS EC2 with Nitro v4+ | ✅ Working | Nitro Root CA |
| GCP Confidential VM | ✅ Working | Google AK certificate |
| Azure Trusted Launch | 🔜 Planned | Microsoft AK certificate |

Please note that GCP 'Shielded VM' with vTPM isn't enough, a 'Confidential VM' is necessary as Google doesn't provision AK certificates without that feature enabled (be it Intel TDX or AMD SEV)

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
    println!("Verified via: {:?}", result.provider);
    println!("Nonce: {}", result.nonce);
}
```

## License

MIT OR Apache-2.0
