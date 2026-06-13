use colored::*;
use comfy_table::{Cell, CellAlignment, Color as TableColor, Table};

use crate::error::CertStatus;
use crate::types::CertReport;

/// Prints a rich, color-coded terminal report for a single domain check.
pub fn print_report(report: &CertReport, verbose: bool) {
    println!();
    println!(
        "{}",
        "═══════════════════════════════════════════════════════════════"
            .bright_blue()
    );
    println!(
        "  {}  {}",
        "🔒 SSL Certificate Report".bold().bright_white(),
        format!("({})", report.domain).dimmed()
    );
    println!(
        "{}",
        "═══════════════════════════════════════════════════════════════"
            .bright_blue()
    );
    println!();

    // --- Connection Info ---
    print_section_header("Connection");
    print_field("Domain", &report.domain);
    print_field("IP Address", &report.ip_address);
    print_field("Port", &report.port.to_string());
    print_field("TLS Version", &format_tls_version(&report.tls_version));
    let hsts_val = if report.hsts_present {
        "Enabled ✓".green().to_string()
    } else {
        "Not Found ✗".yellow().to_string()
    };
    print_field("HSTS", &hsts_val);
    println!();

    // --- Certificate Details ---
    print_section_header("Certificate");
    print_field("Subject (CN)", &report.subject_cn);
    print_field("Issuer (CN)", &report.issuer_cn);
    if !report.issuer_org.is_empty() {
        print_field("Issuer Org", &report.issuer_org);
    }
    let self_signed_val = if report.is_self_signed {
        "Yes ⚠".yellow().to_string()
    } else {
        "No".to_string()
    };
    print_field("Self-Signed", &self_signed_val);
    println!();

    // --- Validity ---
    print_section_header("Validity");
    if let Some(nb) = report.not_before {
        print_field("Valid From", &nb.format("%Y-%m-%d %H:%M:%S UTC").to_string());
    }
    if let Some(na) = report.not_after {
        print_field("Valid Until", &na.format("%Y-%m-%d %H:%M:%S UTC").to_string());
    }

    // Expiry status with color coding
    let expiry_display = format_expiry(&report.status, report.days_until_expiry);
    print_field("Status", &expiry_display);
    println!();

    // --- SANs ---
    if !report.sans.is_empty() {
        print_section_header("Subject Alternative Names");
        for san in &report.sans {
            println!("    {} {}", "•".dimmed(), san);
        }
        println!();
    }

    // --- Chain ---
    if !report.chain.is_empty() {
        print_section_header("Certificate Chain");
        let mut table = Table::new();
        table.set_header(vec![
            Cell::new("#").set_alignment(CellAlignment::Center),
            Cell::new("CN"),
            Cell::new("Issuer"),
            Cell::new("Role"),
        ]);

        for (i, entry) in report.chain.iter().enumerate() {
            let role_color = match entry.role {
                crate::types::CertRole::Leaf => TableColor::Green,
                crate::types::CertRole::Intermediate => TableColor::Yellow,
                crate::types::CertRole::Root => TableColor::Cyan,
            };
            table.add_row(vec![
                Cell::new(i.to_string()).set_alignment(CellAlignment::Center),
                Cell::new(&entry.cn),
                Cell::new(&entry.issuer),
                Cell::new(entry.role.to_string()).fg(role_color),
            ]);
        }

        println!("{}", table);
        println!();
    }

    // --- Fingerprint ---
    if verbose {
        print_section_header("Fingerprint");
        print_field("SHA-256", &report.fingerprint_sha256);
        print_field("Checked At", &report.checked_at.format("%Y-%m-%d %H:%M:%S UTC").to_string());
        println!();
    }

    // --- Final Status Banner ---
    print_status_banner(&report.status, report.days_until_expiry);

    println!(
        "{}",
        "═══════════════════════════════════════════════════════════════"
            .bright_blue()
    );
    println!();
}

/// Prints a batch summary table.
pub fn print_batch_summary(reports: &[CertReport]) {
    println!();
    println!(
        "{}",
        "═══════════════════════════════════════════════════════════════"
            .bright_blue()
    );
    println!("  {}", "📋 Batch Summary".bold().bright_white());
    println!(
        "{}",
        "═══════════════════════════════════════════════════════════════"
            .bright_blue()
    );
    println!();

    let mut table = Table::new();
    table.set_header(vec![
        Cell::new("Domain"),
        Cell::new("Status"),
        Cell::new("Days Left"),
        Cell::new("Issuer"),
        Cell::new("TLS"),
    ]);

    for report in reports {
        let status_color = match report.status {
            CertStatus::Healthy => TableColor::Green,
            CertStatus::ExpiringSoon => TableColor::Yellow,
            CertStatus::Expired => TableColor::Red,
            CertStatus::Error => TableColor::Red,
        };

        let days_str = match report.days_until_expiry {
            Some(d) => d.to_string(),
            None => "N/A".to_string(),
        };

        table.add_row(vec![
            Cell::new(&report.domain),
            Cell::new(report.status.to_string()).fg(status_color),
            Cell::new(&days_str),
            Cell::new(&report.issuer_org),
            Cell::new(&report.tls_version),
        ]);
    }

    println!("{}", table);

    // Summary counts
    let healthy = reports.iter().filter(|r| r.status == CertStatus::Healthy).count();
    let warning = reports.iter().filter(|r| r.status == CertStatus::ExpiringSoon).count();
    let expired = reports.iter().filter(|r| r.status == CertStatus::Expired).count();
    let errors = reports.iter().filter(|r| r.status == CertStatus::Error).count();

    println!();
    println!(
        "  {} {} healthy  {} {} warning  {} {} expired  {} {} errors",
        "●".green(), healthy,
        "●".yellow(), warning,
        "●".red(), expired,
        "●".red().bold(), errors,
    );
    println!();
}

// --- Helper functions ---

fn print_section_header(title: &str) {
    println!("  {} {}", "▸".bright_blue(), title.bold().bright_white());
    println!(
        "  {}",
        "───────────────────────────────────────────────────────────"
            .dimmed()
    );
}

fn print_field(label: &str, value: &str) {
    println!("    {:<16} {}", format!("{}:", label).dimmed(), value);
}

fn format_tls_version(version: &str) -> String {
    match version {
        "TLSv1.3" => format!("{}", version.green()),
        "TLSv1.2" => format!("{}", version.green()),
        "TLSv1.1" => format!("{} {}", version.red(), "(deprecated)".red().dimmed()),
        "TLSv1.0" => format!("{} {}", version.red().bold(), "(deprecated)".red().dimmed()),
        _ => version.to_string(),
    }
}

fn format_expiry(status: &CertStatus, days: Option<i64>) -> String {
    match status {
        CertStatus::Healthy => {
            let d = days.unwrap_or(0);
            format!("{}", format!("✓ Valid — {} days remaining", d).green())
        }
        CertStatus::ExpiringSoon => {
            let d = days.unwrap_or(0);
            format!(
                "{}",
                format!("⚠ Expiring Soon — {} days remaining", d).yellow().bold()
            )
        }
        CertStatus::Expired => {
            format!("{}", "✗ EXPIRED".red().bold())
        }
        CertStatus::Error => {
            format!("{}", "✗ ERROR".red().bold())
        }
    }
}

fn print_status_banner(status: &CertStatus, days: Option<i64>) {
    let banner = match status {
        CertStatus::Healthy => {
            let d = days.unwrap_or(0);
            format!(
                "  {}  Certificate is healthy — {} days until expiry",
                "✅", d
            )
            .green()
            .to_string()
        }
        CertStatus::ExpiringSoon => {
            let d = days.unwrap_or(0);
            format!(
                "  {}  Certificate expiring soon — only {} days left!",
                "⚠️", d
            )
            .yellow()
            .bold()
            .to_string()
        }
        CertStatus::Expired => {
            "  ❌  Certificate has EXPIRED!".red().bold().to_string()
        }
        CertStatus::Error => {
            "  ❌  Certificate check failed — see error above"
                .red()
                .bold()
                .to_string()
        }
    };

    println!();
    println!("{}", banner);
    println!();
}
