// SPDX-License-Identifier: MIT OR Apache-2.0

//! Test support: ephemeral key generation and attestation builders.
//!
//! Gated behind `#[cfg(any(test, feature = "test-support"))]` — stripped
//! from production builds unless explicitly opted in.

use std::collections::BTreeMap;
use std::time::Duration;

use ciborium::Value as CborValue;
use coset::{iana, CborSerializable, CoseSign1, HeaderBuilder};
use der::Decode;
use ecdsa::signature::hazmat::PrehashSigner;
use p256::pkcs8::DecodePrivateKey as _;
use sha2::{Digest, Sha256, Sha384};

use crate::pcr::{P256PublicKey, PcrAlgorithm, PcrBank};
use crate::roots::{register_test_root, TestRootGuard};
use crate::x509::hash_public_key;
use crate::{CloudProvider, DecodedAttestationOutput, DecodedPlatformAttestation};
use pki_types::UnixTime;

// Pure-Rust test certificate factory (x509-cert `builder` + p256/p384 signers) -- replaces rcgen,
// so no `ring`/C toolchain enters the tree. See `define_certgen!` below.
use std::str::FromStr;

use der::asn1::{GeneralizedTime, UtcTime};
use der::Encode as _;
use p256::pkcs8::EncodePrivateKey as _;
use rand_core::OsRng;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};

// ============================================================================
// TPM Quote builder
// ============================================================================

/// TPM_GENERATED magic
const TPM_GENERATED_VALUE: u32 = 0xff544347;
/// TPM_ST_ATTEST_QUOTE
const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

/// Build a raw TPM2B_ATTEST (Quote) structure.
///
/// `pcr_select`: list of `(alg_u16, bitmap_bytes)` — e.g. `(PcrAlgorithm::Sha384 as u16, vec![0xFF, 0xFF, 0xFF])`.
/// `pcr_digest`: the SHA-256 of concatenated selected PCR values.
pub fn build_tpm_quote_attest(
    nonce: &[u8; 32],
    pcr_select: &[(u16, Vec<u8>)],
    pcr_digest: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    // magic
    buf.extend_from_slice(&TPM_GENERATED_VALUE.to_be_bytes());
    // type
    buf.extend_from_slice(&TPM_ST_ATTEST_QUOTE.to_be_bytes());

    // qualifiedSigner (TPM2B_NAME) — minimal: 34 bytes of zeros
    let signer_name = [0u8; 34];
    buf.extend_from_slice(&(signer_name.len() as u16).to_be_bytes());
    buf.extend_from_slice(&signer_name);

    // extraData (TPM2B_DATA) — our nonce
    buf.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
    buf.extend_from_slice(nonce);

    // clockInfo (TPMS_CLOCK_INFO) — 17 bytes of zeros
    buf.extend_from_slice(&[0u8; 17]);

    // firmwareVersion — 8 bytes
    buf.extend_from_slice(&[0u8; 8]);

    // attested.quote.pcrSelect (TPML_PCR_SELECTION)
    buf.extend_from_slice(&(pcr_select.len() as u32).to_be_bytes());
    for (alg, bitmap) in pcr_select {
        buf.extend_from_slice(&alg.to_be_bytes());
        buf.push(bitmap.len() as u8);
        buf.extend_from_slice(bitmap);
    }

    // attested.quote.pcrDigest (TPM2B_DIGEST)
    buf.extend_from_slice(&(pcr_digest.len() as u16).to_be_bytes());
    buf.extend_from_slice(pcr_digest);

    buf
}

/// Compute the PCR digest (SHA-256 of concatenated PCR values in index order).
pub fn compute_pcr_digest(pcrs: &PcrBank) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for value in pcrs.values() {
        hasher.update(value);
    }
    hasher.finalize().to_vec()
}

/// Sign a TPM Quote with a P-256 key (PKCS8 DER).
///
/// The TPM signs SHA-256(attest_data) using prehash ECDSA.
/// Returns the DER-encoded ECDSA signature.
pub fn sign_tpm_quote(attest_data: &[u8], ak_signing_key_pkcs8: &[u8]) -> Vec<u8> {
    let signing_key = p256::ecdsa::SigningKey::from_pkcs8_der(ak_signing_key_pkcs8).unwrap();
    let digest = Sha256::digest(attest_data);
    let signature: p256::ecdsa::Signature = signing_key.sign_prehash(&digest).unwrap();
    signature.to_der().as_bytes().to_vec()
}

// ============================================================================
// COSE Sign1 builder (Nitro)
// ============================================================================

/// Build a COSE Sign1 document for Nitro attestation.
///
/// `leaf_der`: DER-encoded leaf certificate
/// `cabundle`: list of DER-encoded CA certificates (root last, will be reversed in CBOR)
/// `pcrs`: PCR index → SHA-384 value
/// `public_key`: optional AK public key bytes
/// `nonce`: optional nonce bytes
/// `signing_key_pkcs8`: P-384 private key in PKCS8 DER (signs the COSE envelope)
pub fn build_nitro_cose_doc(
    leaf_der: &[u8],
    cabundle: &[Vec<u8>],
    pcrs: &BTreeMap<u8, Vec<u8>>,
    public_key: Option<&[u8]>,
    nonce: Option<&[u8]>,
    signing_key_pkcs8: &[u8],
) -> Vec<u8> {
    // Build CBOR payload map
    let pcr_map: Vec<(CborValue, CborValue)> = pcrs
        .iter()
        .map(|(idx, val)| {
            (
                CborValue::Integer((*idx as i64).into()),
                CborValue::Bytes(val.clone()),
            )
        })
        .collect();

    let cabundle_cbor: Vec<CborValue> = cabundle
        .iter()
        .rev() // Nitro stores root-first in cabundle array, reversed from chain order
        .map(|der| CborValue::Bytes(der.clone()))
        .collect();

    let mut payload_map: Vec<(CborValue, CborValue)> = vec![
        (
            CborValue::Text("module_id".to_string()),
            CborValue::Text("test-module".to_string()),
        ),
        (
            CborValue::Text("timestamp".to_string()),
            CborValue::Integer(1770116400i64.into()),
        ),
        (
            CborValue::Text("digest".to_string()),
            CborValue::Text("SHA384".to_string()),
        ),
        (
            CborValue::Text("nitrotpm_pcrs".to_string()),
            CborValue::Map(pcr_map),
        ),
        (
            CborValue::Text("certificate".to_string()),
            CborValue::Bytes(leaf_der.to_vec()),
        ),
        (
            CborValue::Text("cabundle".to_string()),
            CborValue::Array(cabundle_cbor),
        ),
    ];

    // public_key
    match public_key {
        Some(pk) => payload_map.push((
            CborValue::Text("public_key".to_string()),
            CborValue::Bytes(pk.to_vec()),
        )),
        None => payload_map.push((CborValue::Text("public_key".to_string()), CborValue::Null)),
    }

    // nonce
    match nonce {
        Some(n) => payload_map.push((
            CborValue::Text("nonce".to_string()),
            CborValue::Bytes(n.to_vec()),
        )),
        None => payload_map.push((CborValue::Text("nonce".to_string()), CborValue::Null)),
    }

    let payload_cbor = CborValue::Map(payload_map);
    let mut payload_bytes = Vec::new();
    ciborium::into_writer(&payload_cbor, &mut payload_bytes).unwrap();

    // Build protected header: alg = ES384 (-35)
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES384)
        .build();

    let protected_bytes = coset::ProtectedHeader {
        original_data: None,
        header: protected,
    }
    .to_vec()
    .unwrap();

    // Build Sig_structure
    let sig_structure = CborValue::Array(vec![
        CborValue::Text("Signature1".to_string()),
        CborValue::Bytes(protected_bytes.clone()),
        CborValue::Bytes(vec![]), // external_aad
        CborValue::Bytes(payload_bytes.clone()),
    ]);

    let mut sig_structure_bytes = Vec::new();
    ciborium::into_writer(&sig_structure, &mut sig_structure_bytes).unwrap();

    // Hash and sign
    let digest = Sha384::digest(&sig_structure_bytes);
    let signing_key = p384::ecdsa::SigningKey::from_pkcs8_der(signing_key_pkcs8).unwrap();
    let signature: p384::ecdsa::Signature = signing_key.sign_prehash(&digest).unwrap();

    // COSE uses raw r||s (96 bytes for P-384)
    let sig_raw = signature.to_bytes();

    // Construct CoseSign1
    let cose = CoseSign1 {
        protected: coset::ProtectedHeader {
            original_data: None,
            header: HeaderBuilder::new()
                .algorithm(iana::Algorithm::ES384)
                .build(),
        },
        unprotected: Default::default(),
        payload: Some(payload_bytes),
        signature: sig_raw.to_vec(),
    };

    cose.to_vec().unwrap()
}

// ============================================================================
// Certificate chain generation
// ============================================================================

/// Validity window wide enough to cover both the fixed test verification time
/// (`EPHEMERAL_TIMESTAMP_SECS`, Feb 2026) and the real build clock. rcgen defaulted to a similarly
/// wide window (1975..4096), which these tests relied on; `Validity::from_now` would set
/// `not_before = now` and reject the fixed-timestamp verification.
fn wide_validity() -> Validity {
    Validity {
        not_before: Time::UtcTime(
            UtcTime::from_unix_duration(Duration::from_secs(946_684_800)).unwrap(), // 2000-01-01
        ),
        not_after: Time::GeneralTime(
            GeneralizedTime::from_unix_duration(Duration::from_secs(4_102_444_800)).unwrap(), // 2100-01-01
        ),
    }
}

/// Generate a self-signed CA and a CA-signed leaf builder for one ECDSA curve. The CA gets
/// `Profile::Root` (BasicConstraints CA + KeyUsage keyCertSign) and the leaf `Profile::Leaf`
/// (CA:FALSE + KeyUsage digitalSignature) -- exactly what `validate_tpm_cert_chain` requires.
macro_rules! define_certgen {
    ($curve:ident, $ca_fn:ident, $leaf_fn:ident) => {
        /// Self-signed CA cert (DER) with subject/issuer `CN=cn`, signed by `ca`.
        pub(crate) fn $ca_fn(cn: &str, ca: &$curve::ecdsa::SigningKey) -> Vec<u8> {
            let subject = Name::from_str(&format!("CN={cn}")).unwrap();
            let spki = SubjectPublicKeyInfoOwned::from_key(*ca.verifying_key()).unwrap();
            CertificateBuilder::new(
                Profile::Root,
                SerialNumber::from(1u32),
                wide_validity(),
                subject,
                spki,
                ca,
            )
            .unwrap()
            .build::<$curve::ecdsa::DerSignature>()
            .unwrap()
            .to_der()
            .unwrap()
        }

        /// Leaf cert (DER) `CN=cn`, subject key `leaf`, signed by `ca` (issuer `CN=issuer_cn`).
        pub(crate) fn $leaf_fn(
            cn: &str,
            leaf: &$curve::ecdsa::SigningKey,
            issuer_cn: &str,
            ca: &$curve::ecdsa::SigningKey,
        ) -> Vec<u8> {
            let subject = Name::from_str(&format!("CN={cn}")).unwrap();
            let issuer = Name::from_str(&format!("CN={issuer_cn}")).unwrap();
            let spki = SubjectPublicKeyInfoOwned::from_key(*leaf.verifying_key()).unwrap();
            CertificateBuilder::new(
                Profile::Leaf {
                    issuer,
                    enable_key_agreement: false,
                    enable_key_encipherment: false,
                    include_subject_key_identifier: true,
                },
                SerialNumber::from(2u32),
                wide_validity(),
                subject,
                spki,
                ca,
            )
            .unwrap()
            .build::<$curve::ecdsa::DerSignature>()
            .unwrap()
            .to_der()
            .unwrap()
        }
    };
}
define_certgen!(p256, mk_p256_ca, mk_p256_leaf);
define_certgen!(p384, mk_p384_ca, mk_p384_leaf);

/// A self-signed P-256 CA with BasicConstraints CA:TRUE but NO KeyUsage extension. Used to verify
/// the chain validator rejects a CA lacking Key Usage. `Profile::Manual` opts out of the builder's
/// default extensions, so we add only BasicConstraints.
pub(crate) fn mk_p256_ca_no_keyusage(cn: &str, ca: &p256::ecdsa::SigningKey) -> Vec<u8> {
    let subject = Name::from_str(&format!("CN={cn}")).unwrap();
    let spki = SubjectPublicKeyInfoOwned::from_key(*ca.verifying_key()).unwrap();
    let mut builder = CertificateBuilder::new(
        Profile::Manual { issuer: None },
        SerialNumber::from(1u32),
        wide_validity(),
        subject,
        spki,
        ca,
    )
    .unwrap();
    builder
        .add_extension(&x509_cert::ext::pkix::BasicConstraints {
            ca: true,
            path_len_constraint: None,
        })
        .unwrap();
    builder
        .build::<p256::ecdsa::DerSignature>()
        .unwrap()
        .to_der()
        .unwrap()
}

/// Generated key material for a P-384 Nitro-style cert chain.
pub struct NitroChainKeys {
    /// Root CA cert DER
    pub root_der: Vec<u8>,
    /// Leaf cert DER
    pub leaf_der: Vec<u8>,
    /// COSE signing key (P-384, PKCS8 DER) — from the leaf cert
    pub cose_signing_key: Vec<u8>,
    /// Root public key hash (SHA-256)
    pub root_pubkey_hash: [u8; 32],
}

/// Generate a P-384 cert chain for Nitro tests (leaf + root).
///
/// Returns key material needed to build COSE documents and register the test root.
pub fn generate_nitro_chain() -> NitroChainKeys {
    // Root CA (self-signed, P-384) + leaf signed by it.
    let ca_key = p384::ecdsa::SigningKey::random(&mut OsRng);
    let leaf_key = p384::ecdsa::SigningKey::random(&mut OsRng);
    let root_der = mk_p384_ca("AWS Nitro Test Root", &ca_key);
    let leaf_der = mk_p384_leaf("Nitro Test Leaf", &leaf_key, "AWS Nitro Test Root", &ca_key);

    // Compute root pubkey hash
    let root_x509 = x509_cert::Certificate::from_der(&root_der).expect("root cert should parse");
    let root_pubkey = crate::x509::extract_public_key(&root_x509).unwrap();
    let root_pubkey_hash = hash_public_key(&root_pubkey);

    NitroChainKeys {
        root_der,
        leaf_der,
        cose_signing_key: leaf_key.to_pkcs8_der().unwrap().as_bytes().to_vec(),
        root_pubkey_hash,
    }
}

/// Generated key material for a P-256 GCP-style cert chain.
pub struct GcpChainKeys {
    /// Root CA cert DER
    pub root_der: Vec<u8>,
    /// Leaf cert DER
    pub leaf_der: Vec<u8>,
    /// AK signing key (P-256, PKCS8 DER) — from the leaf cert
    pub ak_signing_key: Vec<u8>,
    /// AK public key (P-256)
    pub ak_pubkey: P256PublicKey,
    /// Root public key hash (SHA-256)
    pub root_pubkey_hash: [u8; 32],
}

/// Generate a P-256 cert chain for GCP tests (leaf + root).
pub fn generate_gcp_chain() -> GcpChainKeys {
    // Root CA (self-signed, P-256) + leaf signed by it.
    let ca_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let leaf_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let root_der = mk_p256_ca("GCP EK/AK Test Root", &ca_key);
    let leaf_der = mk_p256_leaf(
        "GCP AK Test Leaf",
        &leaf_key,
        "GCP EK/AK Test Root",
        &ca_key,
    );

    // Extract AK pubkey from leaf cert
    let leaf_x509 = x509_cert::Certificate::from_der(&leaf_der).expect("leaf cert should parse");
    let ak_pubkey_vec = crate::x509::extract_public_key(&leaf_x509).unwrap();
    let ak_pubkey = P256PublicKey::from_sec1_uncompressed(&ak_pubkey_vec).unwrap();

    // Compute root pubkey hash
    let root_x509 = x509_cert::Certificate::from_der(&root_der).expect("root cert should parse");
    let root_pubkey = crate::x509::extract_public_key(&root_x509).unwrap();
    let root_pubkey_hash = hash_public_key(&root_pubkey);

    GcpChainKeys {
        root_der,
        leaf_der,
        ak_signing_key: leaf_key.to_pkcs8_der().unwrap().as_bytes().to_vec(),
        ak_pubkey,
        root_pubkey_hash,
    }
}

// ============================================================================
// High-level convenience builders
// ============================================================================

/// Default verification timestamp for ephemeral tests.
/// Feb 3, 2026 11:00:00 UTC — same as Nitro fixture.
pub const EPHEMERAL_TIMESTAMP_SECS: u64 = 1770116400;

pub fn ephemeral_time() -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(EPHEMERAL_TIMESTAMP_SECS))
}

/// Build 24 SHA-384 PCR values (for Nitro).
pub fn make_nitro_pcrs() -> PcrBank {
    PcrBank::from_values(PcrAlgorithm::Sha384, (0u8..24).map(|i| (i, vec![i; 48]))).unwrap()
}

/// Build 24 SHA-256 PCR values (for GCP).
pub fn make_gcp_pcrs() -> PcrBank {
    PcrBank::from_values(PcrAlgorithm::Sha256, (0u8..24).map(|i| (i, vec![i; 32]))).unwrap()
}

/// Build a complete, cryptographically valid Nitro attestation.
///
/// Returns `(DecodedAttestationOutput, UnixTime, TestRootGuard)`.
/// The guard must be held alive for the duration of the test.
pub fn build_valid_nitro(
    nonce: &[u8; 32],
    pcrs: &PcrBank,
) -> (DecodedAttestationOutput, UnixTime, TestRootGuard) {
    let chain = generate_nitro_chain();

    // Register test root
    let guard = register_test_root(chain.root_pubkey_hash, CloudProvider::Aws);

    // Generate AK key pair (P-256 for TPM Quote signing)
    let ak_signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
    let ak_signing_key_pkcs8 = ak_signing_key.to_pkcs8_der().unwrap().as_bytes().to_vec();

    // Extract AK public key (SEC1 uncompressed)
    let ak_verifying_key = ak_signing_key.verifying_key();
    let ak_point = ak_verifying_key.to_encoded_point(false);
    let ak_pubkey = P256PublicKey::from_sec1_uncompressed(ak_point.as_bytes()).unwrap();

    // Build TPM Quote
    let pcr_digest = compute_pcr_digest(pcrs);
    let pcr_select = vec![(PcrAlgorithm::Sha384 as u16, vec![0xFF, 0xFF, 0xFF])];
    let quote_attest = build_tpm_quote_attest(nonce, &pcr_select, &pcr_digest);
    let quote_signature = sign_tpm_quote(&quote_attest, &ak_signing_key_pkcs8);

    // Build Nitro PCR map (index → value) for COSE document
    let mut nitro_pcrs = BTreeMap::new();
    for (idx, val) in pcrs.values().enumerate() {
        nitro_pcrs.insert(idx as u8, val.to_vec());
    }

    let ak_sec1 = ak_pubkey.to_sec1_uncompressed();

    // Build COSE document
    let cose_doc = build_nitro_cose_doc(
        &chain.leaf_der,
        std::slice::from_ref(&chain.root_der),
        &nitro_pcrs,
        Some(&ak_sec1),
        Some(nonce),
        &chain.cose_signing_key,
    );

    let decoded = DecodedAttestationOutput {
        nonce: *nonce,
        pcrs: pcrs.clone(),
        ak_pubkey,
        quote_attest,
        quote_signature,
        platform: DecodedPlatformAttestation::Nitro { document: cose_doc },
    };

    (decoded, ephemeral_time(), guard)
}

/// Build a complete, cryptographically valid GCP attestation.
///
/// Returns `(DecodedAttestationOutput, UnixTime, TestRootGuard)`.
pub fn build_valid_gcp(
    nonce: &[u8; 32],
    pcrs: &PcrBank,
) -> (DecodedAttestationOutput, UnixTime, TestRootGuard) {
    let chain = generate_gcp_chain();

    // Register test root
    let guard = register_test_root(chain.root_pubkey_hash, CloudProvider::Gcp);

    // Build TPM Quote
    let pcr_digest = compute_pcr_digest(pcrs);
    let pcr_select = vec![(PcrAlgorithm::Sha256 as u16, vec![0xFF, 0xFF, 0xFF])];
    let quote_attest = build_tpm_quote_attest(nonce, &pcr_select, &pcr_digest);
    let quote_signature = sign_tpm_quote(&quote_attest, &chain.ak_signing_key);

    let decoded = DecodedAttestationOutput {
        nonce: *nonce,
        pcrs: pcrs.clone(),
        ak_pubkey: chain.ak_pubkey,
        quote_attest,
        quote_signature,
        platform: DecodedPlatformAttestation::Gcp {
            cert_chain_der: vec![chain.leaf_der, chain.root_der],
        },
    };

    (decoded, ephemeral_time(), guard)
}
