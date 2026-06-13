use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use crate::error::SslCheckError;
use crate::types::{CertRole, ParsedCert};

/// Parses a vector of raw DER-encoded certificates into structured ParsedCert objects.
pub fn parse_certificates(raw_certs: &[Vec<u8>]) -> Result<Vec<ParsedCert>, SslCheckError> {
    let total = raw_certs.len();
    let mut parsed = Vec::with_capacity(total);

    for (i, der_bytes) in raw_certs.iter().enumerate() {
        let cert = parse_single_cert(der_bytes, i, total)?;
        parsed.push(cert);
    }

    Ok(parsed)
}

fn parse_single_cert(
    der_bytes: &[u8],
    index: usize,
    total: usize,
) -> Result<ParsedCert, SslCheckError> {
    let (_, cert) = X509Certificate::from_der(der_bytes)
        .map_err(|e| SslCheckError::CertParse(format!("Failed to parse certificate {}: {}", index, e)))?;

    let subject_cn = extract_cn(cert.subject())
        .unwrap_or_else(|| cert.subject().to_string());

    let issuer_cn = extract_cn(cert.issuer())
        .unwrap_or_else(|| cert.issuer().to_string());

    let issuer_org = extract_org(cert.issuer()).unwrap_or_default();

    // Extract SANs
    let sans = extract_sans(&cert);

    // Validity dates
    let not_before = asn1_time_to_chrono(cert.validity().not_before);
    let not_after = asn1_time_to_chrono(cert.validity().not_after);

    // Self-signed detection
    let is_self_signed = cert.subject() == cert.issuer();

    // SHA-256 fingerprint
    let fingerprint = compute_sha256_fingerprint(der_bytes);

    // Determine role in chain
    let role = if index == 0 {
        CertRole::Leaf
    } else if index == total - 1 && is_self_signed {
        CertRole::Root
    } else if index == total - 1 {
        // Last cert but not self-signed — likely root sent by server
        CertRole::Root
    } else {
        CertRole::Intermediate
    };

    Ok(ParsedCert {
        subject_cn,
        issuer_cn,
        issuer_org,
        sans,
        not_before,
        not_after,
        is_self_signed,
        fingerprint_sha256: fingerprint,
        role,
    })
}

/// Extracts the Common Name (CN) from an X.500 distinguished name.
fn extract_cn(name: &x509_parser::x509::X509Name) -> Option<String> {
    for rdn in name.iter() {
        for attr in rdn.iter() {
            if attr.attr_type() == &x509_parser::oid_registry::OID_X509_COMMON_NAME {
                if let Ok(val) = attr.attr_value().as_str() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

/// Extracts the Organization (O) from an X.500 distinguished name.
fn extract_org(name: &x509_parser::x509::X509Name) -> Option<String> {
    for rdn in name.iter() {
        for attr in rdn.iter() {
            if attr.attr_type() == &x509_parser::oid_registry::OID_X509_ORGANIZATION_NAME {
                if let Ok(val) = attr.attr_value().as_str() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

/// Extracts Subject Alternative Names from the certificate.
fn extract_sans(cert: &X509Certificate) -> Vec<String> {
    let mut sans = Vec::new();

    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            match name {
                GeneralName::DNSName(dns) => sans.push(dns.to_string()),
                GeneralName::IPAddress(ip_bytes) => {
                    if ip_bytes.len() == 4 {
                        sans.push(format!("{}.{}.{}.{}", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]));
                    } else if ip_bytes.len() == 16 {
                        // IPv6 — format as hex
                        let parts: Vec<String> = ip_bytes
                            .chunks(2)
                            .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                            .collect();
                        sans.push(parts.join(":"));
                    }
                }
                _ => {}
            }
        }
    }

    sans
}

/// Converts an ASN.1 time to a chrono DateTime<Utc>.
fn asn1_time_to_chrono(time: x509_parser::time::ASN1Time) -> DateTime<Utc> {
    DateTime::from_timestamp(time.timestamp(), 0).unwrap_or_default()
}

/// Computes the SHA-256 fingerprint of raw DER bytes.
fn compute_sha256_fingerprint(der_bytes: &[u8]) -> String {
    let hash = Sha256::digest(der_bytes);
    let hex_str = hex::encode_upper(hash);
    // Format as colon-separated pairs: AA:BB:CC:...
    hex_str
        .as_bytes()
        .chunks(2)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
        .collect::<Vec<&str>>()
        .join(":")
}
