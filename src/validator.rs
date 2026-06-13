use chrono::Utc;

use crate::error::CertStatus;
use crate::types::{CertReport, ChainEntry, CheckConfig, ParsedCert, TlsInfo};

/// Validates parsed certificates and produces a CertReport.
pub fn validate(
    certs: &[ParsedCert],
    tls_info: &TlsInfo,
    config: &CheckConfig,
    hsts_present: bool,
) -> CertReport {
    let now = Utc::now();
    let leaf = &certs[0];

    // Calculate days until expiry
    let duration = leaf.not_after.signed_duration_since(now);
    let days_until_expiry = duration.num_days();

    // Determine status
    let status = if days_until_expiry < 0 {
        CertStatus::Expired
    } else if days_until_expiry <= config.warn_days as i64 {
        CertStatus::ExpiringSoon
    } else {
        CertStatus::Healthy
    };

    // Build chain entries
    let chain: Vec<ChainEntry> = certs
        .iter()
        .map(|c| ChainEntry {
            cn: c.subject_cn.clone(),
            issuer: c.issuer_cn.clone(),
            role: c.role.clone(),
        })
        .collect();

    CertReport {
        schema_version: "1.0".to_string(),
        domain: tls_info.domain.clone(),
        ip_address: tls_info.ip_address.clone(),
        port: tls_info.port,
        checked_at: now,
        status,
        days_until_expiry: if days_until_expiry >= 0 {
            Some(days_until_expiry)
        } else {
            None
        },
        not_before: Some(leaf.not_before),
        not_after: Some(leaf.not_after),
        subject_cn: leaf.subject_cn.clone(),
        issuer_cn: leaf.issuer_cn.clone(),
        issuer_org: leaf.issuer_org.clone(),
        sans: leaf.sans.clone(),
        chain_length: certs.len(),
        chain,
        is_self_signed: leaf.is_self_signed,
        tls_version: tls_info.tls_version.clone(),
        hsts_present,
        fingerprint_sha256: leaf.fingerprint_sha256.clone(),
        error: None,
    }
}

/// Creates an error CertReport when the check itself fails.
pub fn error_report(domain: &str, port: u16, error_msg: &str) -> CertReport {
    CertReport {
        schema_version: "1.0".to_string(),
        domain: domain.to_string(),
        ip_address: "unknown".to_string(),
        port,
        checked_at: Utc::now(),
        status: CertStatus::Error,
        days_until_expiry: None,
        not_before: None,
        not_after: None,
        subject_cn: String::new(),
        issuer_cn: String::new(),
        issuer_org: String::new(),
        sans: Vec::new(),
        chain_length: 0,
        chain: Vec::new(),
        is_self_signed: false,
        tls_version: String::new(),
        hsts_present: false,
        fingerprint_sha256: String::new(),
        error: Some(error_msg.to_string()),
    }
}
