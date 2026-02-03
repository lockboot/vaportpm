// SPDX-License-Identifier: MIT OR Apache-2.0

//! Embedded trust anchor certificates
//!
//! These certificates are the canonical trust anchors for cloud provider
//! attestation verification. Hashes are derived from the certificate data,
//! not hardcoded separately.

use crate::cert::{extract_ski, pem_to_der};
use std::sync::OnceLock;

// ============================================================================
// Embedded certificate PEMs
// ============================================================================

/// AWS Nitro Enclave Root CA certificate (P-384/ES384)
///
/// Subject: CN=aws.nitro-enclaves, OU=AWS, O=Amazon, C=US
/// Valid: 2019-10-28 to 2049-10-28
pub const AWS_NITRO_ROOT_PEM: &str = include_str!("../certs/aws-nitro-root.pem");

/// GCP EK/AK CA Root certificate (RSA-4096)
///
/// This is the shared root CA for all GCP Shielded VMs (both Intel TDX and AMD SEV).
/// Intermediate certificates are project-specific and must be fetched by the attestor.
/// Subject: CN=EK/AK CA Root, OU=Google Cloud, O=Google LLC, L=Mountain View, ST=California, C=US
/// Valid: 2022-07-08 to 2122-07-08
pub const GCP_EKAK_ROOT_PEM: &str = include_str!("../certs/gcp-ekak-root.pem");

// ============================================================================
// Certificate metadata
// ============================================================================

/// Certificate metadata extracted from PEM
#[derive(Debug, Clone)]
pub struct CertInfo {
    /// PEM-encoded certificate
    pub pem: &'static str,
    /// Subject Key Identifier (typically SHA-1 of public key)
    pub ski: Vec<u8>,
}

/// Lazily-initialized certificate info cache
static CERT_INFOS: OnceLock<Vec<CertInfo>> = OnceLock::new();

/// Get all embedded certificate infos, initializing on first call
fn get_cert_infos() -> &'static [CertInfo] {
    CERT_INFOS.get_or_init(|| {
        // These are compile-time embedded certs - panic if they fail to parse
        vec![
            extract_cert_info(AWS_NITRO_ROOT_PEM, "AWS Nitro root"),
            extract_cert_info(GCP_EKAK_ROOT_PEM, "GCP EK/AK root"),
        ]
    })
}

/// Extract certificate info from PEM
///
/// Panics if the certificate cannot be parsed - these are embedded constants
/// that must always be valid.
fn extract_cert_info(pem: &'static str, name: &str) -> CertInfo {
    let der = pem_to_der(pem).unwrap_or_else(|e| panic!("{name} cert: invalid PEM: {e}"));
    let ski = extract_ski(&der).unwrap_or_else(|| panic!("{name} cert: missing SKI extension"));

    CertInfo { pem, ski }
}

// ============================================================================
// Lookup functions
// ============================================================================

/// Find an issuer certificate by matching a child certificate's AKI to a parent's SKI
///
/// Returns the PEM-encoded certificate if found.
pub fn find_issuer_by_aki(aki: &[u8]) -> Option<&'static str> {
    for info in get_cert_infos() {
        if info.ski == aki {
            return Some(info.pem);
        }
    }
    None
}

/// Get the SKI for an embedded certificate
///
/// Returns the Subject Key Identifier bytes.
pub fn get_ski(pem: &str) -> Option<Vec<u8>> {
    for info in get_cert_infos() {
        if info.pem == pem {
            return Some(info.ski.clone());
        }
    }
    None
}

/// Check if a certificate (by PEM) is a known trust anchor
pub fn is_known_root(pem: &str) -> bool {
    pem == AWS_NITRO_ROOT_PEM || pem == GCP_EKAK_ROOT_PEM
}

/// Get all embedded root certificate PEMs
pub fn get_all_roots() -> &'static [&'static str] {
    &[AWS_NITRO_ROOT_PEM, GCP_EKAK_ROOT_PEM]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_nitro_root_has_ski() {
        let der = pem_to_der(AWS_NITRO_ROOT_PEM).expect("Valid PEM");
        let ski = extract_ski(&der);
        assert!(ski.is_some(), "AWS Nitro root should have SKI");
        let ski = ski.unwrap();
        assert_eq!(ski.len(), 20, "SKI should be 20 bytes (SHA-1)");
    }

    #[test]
    fn test_gcp_root_has_ski() {
        let der = pem_to_der(GCP_EKAK_ROOT_PEM).expect("Valid PEM");
        let ski = extract_ski(&der);
        assert!(ski.is_some(), "GCP root should have SKI");
    }

    #[test]
    fn test_is_known_root() {
        assert!(is_known_root(AWS_NITRO_ROOT_PEM));
        assert!(is_known_root(GCP_EKAK_ROOT_PEM));
        assert!(!is_known_root("some random pem"));
    }

    #[test]
    fn test_get_all_roots() {
        let roots = get_all_roots();
        assert_eq!(roots.len(), 2);
        assert!(roots.contains(&AWS_NITRO_ROOT_PEM));
        assert!(roots.contains(&GCP_EKAK_ROOT_PEM));
    }

    #[test]
    fn test_get_ski() {
        let ski = get_ski(AWS_NITRO_ROOT_PEM);
        assert!(ski.is_some());
        assert_eq!(ski.unwrap().len(), 20);
    }
}
