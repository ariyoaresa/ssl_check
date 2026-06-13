use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::checker;
use crate::error::SslCheckError;
use crate::parser;
use crate::types::{CertReport, CheckConfig};
use crate::validator;

/// Reads a domain list file and returns lines (trimmed, non-empty, non-comment).
pub fn read_domain_file(path: &str) -> Result<Vec<String>, SslCheckError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| SslCheckError::FileRead(format!("Cannot read '{}': {}", path, e)))?;

    let domains: Vec<String> = content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    if domains.is_empty() {
        return Err(SslCheckError::FileRead(format!(
            "No domains found in '{}'",
            path
        )));
    }

    Ok(domains)
}

/// Runs batch checks on multiple domains concurrently.
pub async fn run_batch(domains: Vec<String>, config: &CheckConfig) -> Vec<CertReport> {
    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let config = Arc::new(config.clone());
    let mut handles = Vec::new();

    for domain in domains {
        let permit = semaphore.clone();
        let cfg = config.clone();
        let domain = domain.clone();

        let handle = tokio::spawn(async move {
            let _permit = permit.acquire().await.unwrap();
            eprintln!("  ⏳ Checking {}...", domain);
            check_single_domain(&domain, &cfg).await
        });

        handles.push(handle);
    }

    let mut reports = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(report) => reports.push(report),
            Err(e) => {
                eprintln!("  ❌ Task join error: {}", e);
            }
        }
    }

    reports
}

/// Performs a single domain check and returns a CertReport.
pub async fn check_single_domain(domain: &str, config: &CheckConfig) -> CertReport {
    // Strip protocol prefix if present
    let domain = domain
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');

    match checker::check_domain(domain, config.port, config.timeout_secs).await {
        Ok((tls_info, raw_certs)) => {
            match parser::parse_certificates(&raw_certs) {
                Ok(parsed_certs) => {
                    // Check HSTS in parallel — don't fail the whole check if this errors
                    let hsts = checker::check_hsts(domain).await;
                    validator::validate(&parsed_certs, &tls_info, config, hsts)
                }
                Err(e) => validator::error_report(domain, config.port, &e.to_string()),
            }
        }
        Err(e) => validator::error_report(domain, config.port, &e.to_string()),
    }
}
