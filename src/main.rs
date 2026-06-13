mod batch;
mod cache;
mod checker;
mod error;
mod exporter;
mod parser;
mod reporter;
mod types;
mod validator;
mod watcher;

use std::process;

use clap::Parser;
use colored::control;

use error::{error_exit_code, exit_code};
use types::{CheckConfig, OutputFormat};

/// sslcheck — SSL/TLS Certificate Auditing Tool
///
/// Connect to any domain, extract the full certificate chain, and get a
/// rich, color-coded report with expiry countdown, issuer hierarchy,
/// SANs, and HSTS status.
#[derive(Parser, Debug)]
#[command(name = "sslcheck", version, about, long_about = None)]
struct Cli {
    /// Domain to check (e.g., google.com)
    #[arg(value_name = "DOMAIN")]
    domain: Option<String>,

    /// Custom port to connect on
    #[arg(short, long, default_value = "443")]
    port: u16,

    /// Days before expiry to trigger exit code 1
    #[arg(short = 'w', long = "warn-days", default_value = "30")]
    warn_days: u32,

    /// Path to file with list of domains (one per line)
    #[arg(short, long = "file")]
    file: Option<String>,

    /// Output format: terminal, json, csv
    #[arg(short, long, default_value = "terminal")]
    output: String,

    /// Max parallel checks in batch mode
    #[arg(short, long, default_value = "5")]
    concurrency: usize,

    /// Enable watch mode (re-check on interval)
    #[arg(long)]
    watch: bool,

    /// Watch mode interval in seconds
    #[arg(long, default_value = "3600")]
    interval: u64,

    /// Webhook URL for watch mode notifications
    #[arg(long)]
    webhook: Option<String>,

    /// Disable ANSI color output (for log piping)
    #[arg(long = "no-color")]
    no_color: bool,

    /// Show raw cert fields and debug info
    #[arg(short, long)]
    verbose: bool,

    /// TCP connection timeout in seconds
    #[arg(short, long, default_value = "10")]
    timeout: u64,
}

#[tokio::main]
async fn main() {
    // Install ring as the default crypto provider for rustls
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cli = Cli::parse();

    // Handle --no-color
    if cli.no_color {
        control::set_override(false);
    }

    // Parse output format
    let output_format: OutputFormat = cli.output.parse().unwrap_or_else(|e: String| {
        eprintln!("Error: {}", e);
        process::exit(2);
    });

    let config = CheckConfig {
        port: cli.port,
        warn_days: cli.warn_days,
        timeout_secs: cli.timeout,
        output_format: output_format.clone(),
        no_color: cli.no_color,
        verbose: cli.verbose,
        concurrency: cli.concurrency,
        watch: cli.watch,
        interval_secs: cli.interval,
        webhook_url: cli.webhook,
    };

    // Determine mode: batch file, watch, or single domain
    if let Some(ref file_path) = cli.file {
        // --- Batch Mode ---
        let domains = match batch::read_domain_file(file_path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error: {}", e);
                process::exit(error_exit_code(&e));
            }
        };

        let reports = batch::run_batch(domains, &config).await;

        match config.output_format {
            OutputFormat::Terminal => {
                reporter::print_batch_summary(&reports);
            }
            OutputFormat::Json => {
                match exporter::export_json_batch(&reports) {
                    Ok(json) => println!("{}", json),
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        process::exit(2);
                    }
                }
            }
            OutputFormat::Csv => {
                if let Err(e) = exporter::export_csv(&reports, std::io::stdout()) {
                    eprintln!("Error: {}", e);
                    process::exit(2);
                }
            }
        }

        // Update cache with latest fingerprints for all domains
        for report in &reports {
            if !report.fingerprint_sha256.is_empty() {
                let _ = cache::update_cache(&report.domain, &report.fingerprint_sha256);
            }
        }

        // Exit with worst status across all reports
        let worst_code = reports
            .iter()
            .map(|r| exit_code(&r.status))
            .max()
            .unwrap_or(0);
        process::exit(worst_code);
    }

    // Single domain required from here
    let domain = match cli.domain {
        Some(d) => d,
        None => {
            eprintln!("Error: No domain specified. Usage: sslcheck <DOMAIN>");
            eprintln!("       Or use --file <path> for batch mode.");
            process::exit(2);
        }
    };

    if cli.watch {
        // --- Watch Mode ---
        watcher::run_watch(&domain, &config).await;
    } else {
        // --- Single Domain Check ---
        let report = batch::check_single_domain(&domain, &config).await;

        match config.output_format {
            OutputFormat::Terminal => {
                reporter::print_report(&report, config.verbose);
            }
            OutputFormat::Json => {
                match exporter::export_json_single(&report) {
                    Ok(json) => println!("{}", json),
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        process::exit(2);
                    }
                }
            }
            OutputFormat::Csv => {
                if let Err(e) = exporter::export_csv(&[report.clone()], std::io::stdout()) {
                    eprintln!("Error: {}", e);
                    process::exit(2);
                }
            }
        }

        // Update cache with latest fingerprint
        if !report.fingerprint_sha256.is_empty() {
            let _ = cache::update_cache(&domain, &report.fingerprint_sha256);
        }

        process::exit(exit_code(&report.status));
    }
}
