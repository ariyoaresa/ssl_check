use chrono::{DateTime, Utc};
use serde::Serialize;

/// Parsed certificate information from a single X.509 certificate.
#[derive(Debug, Clone, Serialize)]
pub struct ParsedCert {
    pub subject_cn: String,
    pub issuer_cn: String,
    pub issuer_org: String,
    pub sans: Vec<String>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub is_self_signed: bool,
    pub fingerprint_sha256: String,
    pub role: CertRole,
}

/// The role of a certificate in the chain.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CertRole {
    Leaf,
    Intermediate,
    Root,
}

impl std::fmt::Display for CertRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertRole::Leaf => write!(f, "leaf"),
            CertRole::Intermediate => write!(f, "intermediate"),
            CertRole::Root => write!(f, "root"),
        }
    }
}

/// TLS connection metadata.
#[derive(Debug, Clone, Serialize)]
pub struct TlsInfo {
    pub tls_version: String,
    pub ip_address: String,
    pub port: u16,
    pub domain: String,
}

/// Full certificate report combining parsed certs, validation, and connection info.
#[derive(Debug, Clone, Serialize)]
pub struct CertReport {
    pub schema_version: String,
    pub domain: String,
    pub ip_address: String,
    pub port: u16,
    pub checked_at: DateTime<Utc>,
    pub status: crate::error::CertStatus,
    pub days_until_expiry: Option<i64>,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub subject_cn: String,
    pub issuer_cn: String,
    pub issuer_org: String,
    pub sans: Vec<String>,
    pub chain_length: usize,
    pub chain: Vec<ChainEntry>,
    pub is_self_signed: bool,
    pub tls_version: String,
    pub hsts_present: bool,
    pub fingerprint_sha256: String,
    pub error: Option<String>,
}

/// A single entry in the certificate chain for display/export.
#[derive(Debug, Clone, Serialize)]
pub struct ChainEntry {
    pub cn: String,
    pub issuer: String,
    pub role: CertRole,
}

/// Configuration for a check run.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct CheckConfig {
    pub port: u16,
    pub warn_days: u32,
    pub timeout_secs: u64,
    pub output_format: OutputFormat,
    pub no_color: bool,
    pub verbose: bool,
    pub concurrency: usize,
    pub watch: bool,
    pub interval_secs: u64,
    pub webhook_url: Option<String>,
}

/// Output format selection.
#[derive(Debug, Clone, PartialEq)]
pub enum OutputFormat {
    Terminal,
    Json,
    Csv,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "terminal" => Ok(OutputFormat::Terminal),
            "json" => Ok(OutputFormat::Json),
            "csv" => Ok(OutputFormat::Csv),
            _ => Err(format!("Unknown output format: '{}'. Expected: terminal, json, csv", s)),
        }
    }
}
