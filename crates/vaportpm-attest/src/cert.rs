// SPDX-License-Identifier: MIT OR Apache-2.0

//! X.509 certificate parsing and chain fetching
//!
//! Provides utilities for working with X.509 certificates:
//! - PEM/DER conversion
//! - Certificate chain fetching via AIA (Authority Information Access) URLs
//! - Extension extraction (SKI, AKI, AIA)

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use der::oid::ObjectIdentifier;
use der::Decode;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{AuthorityInfoAccessSyntax, AuthorityKeyIdentifier};
use x509_cert::Certificate;

/// DER SEQUENCE tag with 2-byte length (0x30 0x82)
/// Used to detect valid X.509 certificates in DER format
pub const DER_SEQUENCE_LONG: [u8; 2] = [0x30, 0x82];

// X.509 extension OIDs
const OID_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const OID_AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");
const OID_AUTHORITY_INFO_ACCESS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");

// AIA access method OID for caIssuers
const OID_CA_ISSUERS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.2");

/// Convert DER-encoded data to PEM format
pub fn der_to_pem(der: &[u8], label: &str) -> String {
    let base64_encoded = STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {}-----\n", label);
    for chunk in base64_encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----\n", label));
    pem
}

/// Convert PEM-encoded certificate to DER
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let mut in_cert = false;
    let mut base64_data = String::new();

    for line in pem.lines() {
        if line.contains("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
        } else if line.contains("-----END CERTIFICATE-----") {
            break;
        } else if in_cert {
            base64_data.push_str(line.trim());
        }
    }

    if base64_data.is_empty() {
        return Err(anyhow!("No certificate found in PEM data"));
    }

    STANDARD
        .decode(&base64_data)
        .map_err(|e| anyhow!("Base64 decode error: {}", e))
}

/// Parse a DER-encoded certificate
fn parse_certificate(cert_der: &[u8]) -> Option<Certificate> {
    Certificate::from_der(cert_der).ok()
}

/// Check if a certificate is self-signed (issuer == subject)
pub fn is_self_signed(cert_der: &[u8]) -> bool {
    let cert = match parse_certificate(cert_der) {
        Some(c) => c,
        None => return false,
    };
    cert.tbs_certificate.issuer == cert.tbs_certificate.subject
}

/// Extract Subject Key Identifier (SKI) from a DER certificate
///
/// SKI is in extension OID 2.5.29.14
/// Returns the raw key identifier bytes (typically 20 bytes SHA-1)
pub fn extract_ski(cert_der: &[u8]) -> Option<Vec<u8>> {
    let cert = parse_certificate(cert_der)?;
    let extensions = cert.tbs_certificate.extensions.as_ref()?;

    for ext in extensions.iter() {
        if ext.extn_id == OID_SUBJECT_KEY_IDENTIFIER {
            // SubjectKeyIdentifier ::= KeyIdentifier
            // KeyIdentifier ::= OCTET STRING
            // The extn_value is already an OctetString, containing the DER-encoded OCTET STRING
            let inner = der::asn1::OctetString::from_der(ext.extn_value.as_bytes()).ok()?;
            return Some(inner.as_bytes().to_vec());
        }
    }
    None
}

/// Extract Authority Key Identifier (AKI) from a DER certificate
///
/// AKI is in extension OID 2.5.29.35
/// Returns the keyIdentifier field (typically 20 bytes SHA-1)
pub fn extract_aki(cert_der: &[u8]) -> Option<Vec<u8>> {
    let cert = parse_certificate(cert_der)?;
    let extensions = cert.tbs_certificate.extensions.as_ref()?;

    for ext in extensions.iter() {
        if ext.extn_id == OID_AUTHORITY_KEY_IDENTIFIER {
            let aki = AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes()).ok()?;
            return aki.key_identifier.map(|ki| ki.as_bytes().to_vec());
        }
    }
    None
}

/// Extract Authority Information Access URL (caIssuers) from a DER certificate
pub fn extract_aia_url(cert_der: &[u8]) -> Option<String> {
    let cert = parse_certificate(cert_der)?;
    let extensions = cert.tbs_certificate.extensions.as_ref()?;

    for ext in extensions.iter() {
        if ext.extn_id == OID_AUTHORITY_INFO_ACCESS {
            let aia = AuthorityInfoAccessSyntax::from_der(ext.extn_value.as_bytes()).ok()?;
            for access_desc in aia.0.iter() {
                if access_desc.access_method == OID_CA_ISSUERS {
                    if let GeneralName::UniformResourceIdentifier(uri) =
                        &access_desc.access_location
                    {
                        return Some(uri.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Fetch the complete certificate chain by following AKI/SKI or AIA URLs
///
/// First attempts to find issuer certificates from embedded trust anchors
/// using AKI/SKI matching. Falls back to AIA URL fetching if no embedded
/// cert matches.
pub fn fetch_cert_chain(leaf_cert: &[u8]) -> Result<Vec<Vec<u8>>> {
    use crate::roots;

    let mut chain = vec![leaf_cert.to_vec()];
    let mut current_cert = leaf_cert.to_vec();

    // Follow chain up to 10 levels (more than enough for any chain)
    for _ in 0..10 {
        // Check if current cert is self-signed (root)
        if is_self_signed(&current_cert) {
            break;
        }

        // First, try to find issuer from embedded certs using AKI/SKI
        if let Some(aki) = extract_aki(&current_cert) {
            if let Some(issuer_pem) = roots::find_issuer_by_aki(&aki) {
                let issuer_der = pem_to_der(issuer_pem)?;
                chain.push(issuer_der.clone());
                current_cert = issuer_der;
                continue;
            }
        }

        // Fallback: Extract AIA URL from current certificate
        let aia_url = match extract_aia_url(&current_cert) {
            Some(url) => url,
            None => {
                // No AIA URL and no embedded cert - can't fetch more certs
                break;
            }
        };

        // Fetch issuer certificate via HTTP
        let issuer_cert = fetch_certificate(&aia_url)?;

        if !issuer_cert.starts_with(&DER_SEQUENCE_LONG) {
            return Err(anyhow!(
                "Fetched certificate is not in DER format from {}",
                aia_url
            ));
        }

        chain.push(issuer_cert.clone());
        current_cert = issuer_cert;
    }

    Ok(chain)
}

/// Fetch a certificate from an HTTP URL (no TLS support - AIA URLs are HTTP)
pub fn fetch_certificate(url: &str) -> Result<Vec<u8>> {
    // Parse URL - only support http://
    if !url.starts_with("http://") {
        return Err(anyhow!("Only HTTP URLs are supported: {}", url));
    }

    let url_without_scheme = &url[7..]; // Skip "http://"
    let (host_port, path) = match url_without_scheme.find('/') {
        Some(idx) => (&url_without_scheme[..idx], &url_without_scheme[idx..]),
        None => (url_without_scheme, "/"),
    };

    let (host, port) = match host_port.find(':') {
        Some(idx) => (
            &host_port[..idx],
            host_port[idx + 1..].parse::<u16>().unwrap_or(80),
        ),
        None => (host_port, 80u16),
    };

    // Connect with timeout
    let addr = format!("{}:{}", host, port);
    let mut stream =
        TcpStream::connect(&addr).map_err(|e| anyhow!("Failed to connect to {}: {}", addr, e))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    // Send HTTP/1.1 GET request
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: vaportpm-attest\r\n\r\n",
        path, host
    );
    stream.write_all(request.as_bytes())?;

    // Read response
    let mut reader = BufReader::new(stream);

    // Parse status line
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    if !status_line.starts_with("HTTP/1.1 200") && !status_line.starts_with("HTTP/1.0 200") {
        return Err(anyhow!("HTTP request failed: {}", status_line.trim()));
    }

    // Parse headers to find Content-Length or chunked transfer
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header)?;
        if header == "\r\n" || header == "\n" {
            break;
        }
        let header_lower = header.to_lowercase();
        if header_lower.starts_with("content-length:") {
            if let Some(len_str) = header.split(':').nth(1) {
                content_length = len_str.trim().parse().ok();
            }
        } else if header_lower.starts_with("transfer-encoding:") && header_lower.contains("chunked")
        {
            chunked = true;
        }
    }

    // Read body
    let mut body = Vec::new();
    if chunked {
        // Read chunked encoding
        loop {
            let mut chunk_size_line = String::new();
            reader.read_line(&mut chunk_size_line)?;
            let chunk_size = usize::from_str_radix(chunk_size_line.trim(), 16).unwrap_or(0);
            if chunk_size == 0 {
                break;
            }
            let mut chunk = vec![0u8; chunk_size];
            reader.read_exact(&mut chunk)?;
            body.extend(chunk);
            // Read trailing \r\n
            let mut trailing = [0u8; 2];
            let _ = reader.read_exact(&mut trailing);
        }
    } else if let Some(len) = content_length {
        body.resize(len, 0);
        reader.read_exact(&mut body)?;
    } else {
        // Read until connection closes
        reader.read_to_end(&mut body)?;
    }

    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_aia_url_gcp_cert() {
        // GCP AK leaf certificate with AIA extension
        let pem = r#"-----BEGIN CERTIFICATE-----
MIIFITCCAwmgAwIBAgIUAL1/11uaGzgty7zfCO9n8DJu4+AwDQYJKoZIhvcNAQEL
BQAwgYYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH
Ew1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgTExDMRUwEwYDVQQLEwxH
b29nbGUgQ2xvdWQxHjAcBgNVBAMTFUVLL0FLIENBIEludGVybWVkaWF0ZTAgFw0y
NjAyMDMwOTQyMzJaGA8yMDU2MDEyNzA5NDIzMVowaTEWMBQGA1UEBxMNdXMtY2Vu
dHJhbDEtZjEeMBwGA1UEChMVR29vZ2xlIENvbXB1dGUgRW5naW5lMREwDwYDVQQL
Ewhsb2NrYm9vdDEcMBoGA1UEAxMTMTUzNTM5ODk5NjkwNzY4NjkyOTBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABIr5m4cMPky5JjeOObhO+mxaAcGpJ+hctqM9ubgu
sFyZR1agN7FCfYOW2anqx8PSpm+WXjDmzzl2GDm78mBLbn+jggFqMIIBZjAOBgNV
HQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU4sCEt4Oo4yYWVjKM
xeblb7eXu7EwHwYDVR0jBBgwFoAUZ8O73ljj1lF2j7MaPtsHp+yTeuQwgY0GCCsG
AQUFBwEBBIGAMH4wfAYIKwYBBQUHMAKGcGh0dHA6Ly9wcml2YXRlY2EtY29udGVu
dC02NWQ1M2IxNC0wMDAwLTIxMmEtYTYzMy04ODNkMjRmNTdiYjguc3RvcmFnZS5n
b29nbGVhcGlzLmNvbS8wYzNlNzllYjA4OThkMDJlYmIwYS9jYS5jcnQwdgYKKwYB
BAHWeQIBFQRoMGYMDXVzLWNlbnRyYWwxLWYCBTY7VDeMDAhsb2NrYm9vdAIIFU7V
QLcsfBEMGGluc3RhbmNlLTIwMjYwMjAzLTA5Mzk0OaAgMB6gAwIBAKEDAQH/ogMB
Af+jAwEBAKQDAQEApQMBAQAwDQYJKoZIhvcNAQELBQADggIBACCm1YXV1f22GVPl
IVL4JoNg1QCq+g5PzgPY9/afjriE8sAM/+Ebj/M96rUS+nFxYHpfzsxfW+4Y7Ko2
O8BGQ4U5Og7Rt5rMyCe/g3qXrZhQIcXIJouXvOsI1G5njXI03kXac8I//IvyMzMr
pxy2SxVQ1djFFQoRA6MF1R3F4cZ1OUcgTPFWAuYuF6rN+F9RSTDuzFpKlWVPfPHX
K0s/eGv+zvlpzBXfX/ES7OAIomfVrmeXqdQYC+ZEJo8tG8eJlxBo8c8Y4GNQpo2I
9O/kYiOdcjzz8F3OeGH6b1dp10uur02nfz/vH0vpkVLNKllm9swZ42i1sQkl0g7u
/p6jSUwBEej54fDEOKj8yRvbuMd36w1bYFBtnkvQlKBCT1hStaAtbFilHuSqlMRm
xVcyunIlN6udQJTKCWPgFsLHgxlUBASm1k0zWsoFjIH9SFHu+GglzK2v1RoHZA5P
33xcxKVzw52TAuPJc4Za/iKmFiA647VXYbiCaKNPn/oi7rLHTUAQ2tj7SJRbJcSu
/q4xg60z8JOX7rtSxCrXFOp9ys2WzxSCqx1aXnUU+Ng+TtImheoUue+Zk3v7Olen
HysTF1gLzHRLvONeErG6mUoxbkFhVsbGfbBDoe3jojNMISreY9IsY2UgMVIdKqLH
bPF0Yysi72AJB6iorXKFwC9f61s0
-----END CERTIFICATE-----"#;

        let der = pem_to_der(pem).expect("PEM decode should work");
        let aia_url = extract_aia_url(&der);

        assert!(aia_url.is_some(), "Should extract AIA URL from GCP cert");
        let url = aia_url.unwrap();
        assert!(
            url.starts_with("http://privateca-content-"),
            "URL should be GCP privateca URL"
        );
        assert!(url.ends_with("/ca.crt"), "URL should end with /ca.crt");
    }
}
