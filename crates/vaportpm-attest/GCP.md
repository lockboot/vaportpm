# GCP Confidential VM Attestation

This document describes how GCP Confidential VMs perform TPM-based attestation using
Attestation Key (AK) certificates.

## Overview

**Important**: Only GCP Confidential VMs receive AK certificates from Google's CA
hierarchy. Standard Shielded VMs (with Secure Boot enabled but no confidential
computing) have a vTPM but do NOT receive Google-signed AK certificates.

GCP Confidential VMs have a virtual TPM (vTPM) with an Attestation Key (AK) that is
certified by Google's EK/AK CA hierarchy. The attestation flow is:

1. VM requests an AK certificate from Google's metadata service
2. Google issues a certificate binding the AK public key to the VM's identity
3. The VM uses the AK to sign TPM2_Quote attestations
4. Verifiers validate the quote signature using the certificate chain

## Certificate Chain Structure

```
EK/AK CA Root (self-signed, offline)
    │
    └── EK/AK CA Intermediate (online issuer)
            │
            └── AK Certificate (per-VM, short-lived)
```

### Root CA Certificate

- **Subject/Issuer**: `CN=EK/AK CA Root, OU=Google Cloud, O=Google LLC, L=Mountain View, ST=California, C=US`
- **Validity**: ~100 years (July 2022 - July 2122)
- **Key Type**: RSA 4096-bit
- **Basic Constraints**: `CA:TRUE`
- **Key Usage**: `Certificate Sign, CRL Sign`
- **Extended Key Usage**: TPM EK Certificate (`2.23.133.8.1`)

### Intermediate CA Certificate

- **Subject**: `CN=EK/AK CA Intermediate, OU=Google Cloud, O=Google LLC, L=Mountain View, ST=California, C=US`
- **Issuer**: Root CA
- **Validity**: ~98 years
- **Key Type**: RSA 4096-bit
- **Basic Constraints**: `CA:TRUE`
- **Key Usage**: `Certificate Sign, CRL Sign`
- **Extended Key Usage**: TPM EK Certificate (`2.23.133.8.1`)

### AK Leaf Certificate

- **Subject**: `CN=<instance_id>, OU=<project_id>, O=Google Compute Engine, L=<zone>`
- **Issuer**: Intermediate CA
- **Validity**: 30 years (per-instance)
- **Key Type**: ECDSA P-256
- **Basic Constraints**: `CA:FALSE` (critical)
- **Key Usage**: `Digital Signature` (critical)
- **Extended Key Usage**: None (only Key Usage is present)

## GCP Instance Identity Extension

AK certificates include a custom extension that binds the certificate to the VM:

**OID**: `1.3.6.1.4.1.11129.2.1.21`

This extension contains a DER-encoded structure with:

| Field | Type | Description |
|-------|------|-------------|
| `zone` | UTF8String | GCP zone (e.g., `us-central1-f`) |
| `project` | UTF8String | GCP project ID |
| `instance_id` | INTEGER | Numeric instance ID |
| `instance_name` | UTF8String | Instance name |
| Additional fields | Various | Confidential Computing flags |

Example from a real certificate:
```
zone: us-central1-f
project: lockboot
instance_id: 3414240648225485836
instance_name: instance-20260202-065609
```

## TPM Quote Structure

The TPM2_Quote structure signed by the AK contains:

```
TPM2B_ATTEST {
    magic: 0xFF544347 ("TCG\xFF")
    type: TPM_ST_ATTEST_QUOTE (0x8018)
    qualifiedSigner: Hash of signing key name
    extraData: Nonce (challenge from verifier)
    clockInfo: TPM clock values
    firmwareVersion: TPM firmware version
    attested: TPMS_QUOTE_INFO {
        pcrSelect: Which PCRs are included
        pcrDigest: SHA-256 of concatenated PCR values
    }
}
```

The signature is ECDSA over the DER-encoded attest structure.

## Verification Process

1. **Parse certificate chain** from AK cert PEM (leaf → intermediate → root)

2. **Validate X.509 extensions**:
   - Leaf: `CA:FALSE`, `digitalSignature` key usage
   - Intermediate/Root: `CA:TRUE`, `keyCertSign` key usage
   - Intermediates: TPM EK Certificate EKU (`2.23.133.8.1`)

3. **Verify certificate signatures**: Each cert signed by the next in chain

4. **Check validity dates**: All certs must be valid at verification time

5. **Verify issuer/subject chaining**: Each cert's Issuer matches parent's Subject

6. **Extract AK public key** from leaf certificate

7. **Verify TPM Quote signature** using AK public key

8. **Validate nonce** in Quote.extraData matches expected challenge

9. **Verify PCR digest**: Recompute digest from claimed PCR values, compare to Quote

10. **Check root CA**: Hash root's public key and verify it matches known GCP root

## Security Considerations

### What This Validates

- The AK was created on a GCP Confidential VM vTPM certified by Google
- The Quote was signed by that specific AK
- PCR values were selected by the Quote at signing time
- The nonce proves freshness (replay protection)

### What This Does NOT Validate

- The PCR values themselves are correct for the expected software state
- The VM is actually running the software you expect
- No malware modified memory after boot (vTPM measures boot, not runtime)

### Trust Assumptions

- Google's EK/AK CA infrastructure is not compromised
- The embedded root CA public key hash is authentic
- Time source is accurate for certificate validation

## Differences from AWS Nitro

| Aspect | GCP Confidential VM | AWS Nitro |
|--------|---------------------|-----------|
| Trust Root | X.509 certificate chain | COSE-signed NSM document |
| Key Binding | AK certificate includes VM identity | NSM document has public_key field |
| PCR Source | TPM2_Quote | Nitro document + TPM2_Quote |
| Algorithm | ECDSA P-256 | ECDSA P-384 |

## References

- [TCG TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [GCP Confidential VM Documentation](https://cloud.google.com/confidential-computing/confidential-vm/docs)
- [RFC 5280 - X.509 PKI Certificate Profile](https://tools.ietf.org/html/rfc5280)
