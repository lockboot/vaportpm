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
            // AuthorityKeyIdentifier ::= SEQUENCE {
            //   keyIdentifier [0] KeyIdentifier OPTIONAL,
            //   authorityCertIssuer [1] GeneralNames OPTIONAL,
            //   authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL
            // }
            let bytes = ext.extn_value.as_bytes();
            return parse_aki_extension(bytes);
        }
    }
    None
}

/// Parse the AuthorityKeyIdentifier extension value
fn parse_aki_extension(bytes: &[u8]) -> Option<Vec<u8>> {
    // AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] IMPLICIT OCTET STRING, ... }
    // bytes is the raw extension value

    // Skip SEQUENCE header
    if bytes.first()? != &0x30 {
        return None;
    }
    let (seq_len, seq_start) = parse_der_length(&bytes[1..])?;
    let seq_bytes = bytes.get(1 + seq_start..1 + seq_start + seq_len)?;

    if seq_bytes.is_empty() {
        return None;
    }

    // keyIdentifier is [0] IMPLICIT OCTET STRING
    // Tag 0x80 = context-specific, primitive, tag 0
    if seq_bytes[0] == 0x80 {
        let (len, value_start) = parse_der_length(&seq_bytes[1..])?;
        return Some(
            seq_bytes
                .get(1 + value_start..1 + value_start + len)?
                .to_vec(),
        );
    }
    None
}

/// Parse DER length encoding, returns (length, bytes_consumed)
fn parse_der_length(bytes: &[u8]) -> Option<(usize, usize)> {
    let len_byte = *bytes.first()?;
    if len_byte & 0x80 == 0 {
        // Short form
        Some((len_byte as usize, 1))
    } else {
        // Long form
        let num_bytes = (len_byte & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | (*bytes.get(1 + i)? as usize);
        }
        Some((len, 1 + num_bytes))
    }
}

/// Extract Authority Information Access URL (caIssuers) from a DER certificate
pub fn extract_aia_url(cert_der: &[u8]) -> Option<String> {
    let cert = parse_certificate(cert_der)?;
    let extensions = cert.tbs_certificate.extensions.as_ref()?;

    for ext in extensions.iter() {
        if ext.extn_id == OID_AUTHORITY_INFO_ACCESS {
            return parse_aia_extension(ext.extn_value.as_bytes());
        }
    }
    None
}

/// Parse the AuthorityInfoAccessSyntax extension to find caIssuers URL
fn parse_aia_extension(bytes: &[u8]) -> Option<String> {
    // AuthorityInfoAccessSyntax ::= SEQUENCE OF AccessDescription
    // AccessDescription ::= SEQUENCE { accessMethod OID, accessLocation GeneralName }

    // Skip outer SEQUENCE header
    if bytes.first()? != &0x30 {
        return None;
    }
    let (seq_len, seq_start) = parse_der_length(&bytes[1..])?;
    let mut pos = 1 + seq_start;
    let seq_end = pos + seq_len;

    while pos < seq_end && pos < bytes.len() {
        // Each AccessDescription is a SEQUENCE
        if bytes.get(pos)? != &0x30 {
            break;
        }
        let (desc_len, desc_header) = parse_der_length(&bytes[pos + 1..])?;
        let desc_start = pos + 1 + desc_header;
        let desc_end = desc_start + desc_len;

        // Parse the OID at the start of the description
        if let Ok(oid) = ObjectIdentifier::from_der(&bytes[desc_start..desc_end]) {
            if oid == OID_CA_ISSUERS {
                // Skip past the OID to get the GeneralName
                let oid_encoded_len = oid.as_bytes().len() + 2; // +2 for tag and length
                let gn_start = desc_start + oid_encoded_len;

                // GeneralName uniformResourceIdentifier [6] IA5String
                // Tag 0x86 = context-specific, primitive, tag 6
                if bytes.get(gn_start)? == &0x86 {
                    let (url_len, url_header) = parse_der_length(&bytes[gn_start + 1..])?;
                    let url_start = gn_start + 1 + url_header;
                    let url_bytes = bytes.get(url_start..url_start + url_len)?;
                    return String::from_utf8(url_bytes.to_vec()).ok();
                }
            }
        }

        // Move to next AccessDescription
        pos = desc_end;
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
