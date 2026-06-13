use std::io::Write;

use crate::error::SslCheckError;
use crate::types::CertReport;

/// Exports a single CertReport as versioned JSON (PRD Section 7 schema).
pub fn export_json_single(report: &CertReport) -> Result<String, SslCheckError> {
    serde_json::to_string_pretty(report)
        .map_err(|e| SslCheckError::Export(format!("JSON serialization failed: {}", e)))
}

/// Exports multiple CertReports as a JSON array.
pub fn export_json_batch(reports: &[CertReport]) -> Result<String, SslCheckError> {
    serde_json::to_string_pretty(reports)
        .map_err(|e| SslCheckError::Export(format!("JSON serialization failed: {}", e)))
}

/// Exports CertReports as CSV to the given writer.
pub fn export_csv<W: Write>(reports: &[CertReport], writer: W) -> Result<(), SslCheckError> {
    let mut wtr = csv::Writer::from_writer(writer);

    // Write header
    wtr.write_record([
        "domain",
        "ip_address",
        "port",
        "checked_at",
        "status",
        "days_until_expiry",
        "not_before",
        "not_after",
        "subject_cn",
        "issuer_cn",
        "issuer_org",
        "sans",
        "chain_length",
        "is_self_signed",
        "tls_version",
        "hsts_present",
        "fingerprint_sha256",
        "error",
    ])
    .map_err(|e| SslCheckError::Export(format!("CSV header write failed: {}", e)))?;

    for report in reports {
        let days = report
            .days_until_expiry
            .map(|d| d.to_string())
            .unwrap_or_default();

        let not_before = report
            .not_before
            .map(|d| d.to_rfc3339())
            .unwrap_or_default();

        let not_after = report
            .not_after
            .map(|d| d.to_rfc3339())
            .unwrap_or_default();

        let sans = report.sans.join("; ");
        let error = report.error.clone().unwrap_or_default();

        wtr.write_record([
            &report.domain,
            &report.ip_address,
            &report.port.to_string(),
            &report.checked_at.to_rfc3339(),
            &report.status.to_string(),
            &days,
            &not_before,
            &not_after,
            &report.subject_cn,
            &report.issuer_cn,
            &report.issuer_org,
            &sans,
            &report.chain_length.to_string(),
            &report.is_self_signed.to_string(),
            &report.tls_version,
            &report.hsts_present.to_string(),
            &report.fingerprint_sha256,
            &error,
        ])
        .map_err(|e| SslCheckError::Export(format!("CSV row write failed: {}", e)))?;
    }

    wtr.flush()
        .map_err(|e| SslCheckError::Export(format!("CSV flush failed: {}", e)))?;

    Ok(())
}
