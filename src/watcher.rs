use std::time::Duration;

use colored::*;
use tokio::time;

use crate::batch::check_single_domain;
use crate::cache;
use crate::error::CertStatus;
use crate::reporter;
use crate::types::CheckConfig;

/// Runs the watch mode loop — re-checks a domain on an interval.
pub async fn run_watch(domain: &str, config: &CheckConfig) -> ! {
    let mut interval = time::interval(Duration::from_secs(config.interval_secs));
    let mut last_fingerprint: Option<String> = None;

    // Load cached fingerprint if available
    if let Ok(cache_map) = cache::load_cache() {
        if let Some(entry) = cache_map.get(domain) {
            last_fingerprint = Some(entry.fingerprint_sha256.clone());
        }
    }

    println!(
        "\n{}",
        format!(
            "👁  Watch mode started for {} (interval: {}s)",
            domain, config.interval_secs
        )
        .bright_blue()
        .bold()
    );
    println!(
        "{}",
        "    Press Ctrl+C to stop.\n".dimmed()
    );

    loop {
        interval.tick().await;

        let report = check_single_domain(domain, config).await;

        // Check for fingerprint change
        let fingerprint_changed = match (&last_fingerprint, &report.fingerprint_sha256) {
            (Some(old), new) if !new.is_empty() && old != new => {
                println!(
                    "  {} {} — certificate fingerprint CHANGED!",
                    "🔄".yellow(),
                    domain.bold()
                );
                println!(
                    "     Old: {}",
                    old.dimmed()
                );
                println!(
                    "     New: {}",
                    new.bright_yellow()
                );
                true
            }
            _ => false,
        };

        // Update cached fingerprint
        if !report.fingerprint_sha256.is_empty() {
            last_fingerprint = Some(report.fingerprint_sha256.clone());
            // Save to cache
            let _ = cache::update_cache(domain, &report.fingerprint_sha256);
        }

        // Print status line
        let status_line = match report.status {
            CertStatus::Healthy => {
                format!(
                    "  {} {} — healthy, {} days remaining",
                    "✅",
                    domain,
                    report.days_until_expiry.unwrap_or(0)
                )
                .green()
                .to_string()
            }
            CertStatus::ExpiringSoon => {
                format!(
                    "  {} {} — EXPIRING SOON, {} days remaining",
                    "⚠️",
                    domain,
                    report.days_until_expiry.unwrap_or(0)
                )
                .yellow()
                .bold()
                .to_string()
            }
            CertStatus::Expired => {
                format!("  {} {} — EXPIRED!", "❌", domain)
                    .red()
                    .bold()
                    .to_string()
            }
            CertStatus::Error => {
                format!(
                    "  {} {} — ERROR: {}",
                    "❌",
                    domain,
                    report.error.as_deref().unwrap_or("unknown")
                )
                .red()
                .to_string()
            }
        };

        let timestamp = report.checked_at.format("%H:%M:%S UTC");
        println!("[{}] {}", timestamp.to_string().dimmed(), status_line);

        // Send webhook if configured and there's an alert condition
        if let Some(ref webhook_url) = config.webhook_url {
            let should_notify = report.status == CertStatus::ExpiringSoon
                || report.status == CertStatus::Expired
                || fingerprint_changed;

            if should_notify {
                send_webhook(webhook_url, &report, fingerprint_changed).await;
            }
        }
    }
}

/// Sends a webhook POST notification.
async fn send_webhook(
    url: &str,
    report: &crate::types::CertReport,
    fingerprint_changed: bool,
) {
    let payload = serde_json::json!({
        "text": format!(
            "🔒 sslcheck alert for {}: status={}, days_left={}, fingerprint_changed={}",
            report.domain,
            report.status,
            report.days_until_expiry.unwrap_or(-1),
            fingerprint_changed
        ),
        "domain": report.domain,
        "status": report.status.to_string(),
        "days_until_expiry": report.days_until_expiry,
        "fingerprint_changed": fingerprint_changed,
        "checked_at": report.checked_at.to_rfc3339(),
    });

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  {} Webhook client error: {}", "⚠".yellow(), e);
            return;
        }
    };

    match client.post(url).json(&payload).send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                println!("  {} Webhook notification sent", "📤".green());
            } else {
                eprintln!(
                    "  {} Webhook returned status {}",
                    "⚠".yellow(),
                    resp.status()
                );
            }
        }
        Err(e) => {
            eprintln!("  {} Webhook POST failed: {}", "⚠".yellow(), e);
        }
    }
}

// Suppress unused import warning — reporter is used by print_report in verbose watch
#[allow(unused_imports)]
use reporter::print_report;
