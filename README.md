# sslcheck

[![Crates.io](https://img.shields.io/crates/v/sslcheck)](https://crates.io/crates/sslcheck)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

`sslcheck` is an open-source, terminal-based SSL/TLS certificate auditing tool. It connects to any domain over a TLS handshake, extracts the full certificate chain, and presents a rich, color-coded report covering expiry countdowns, issuer hierarchy, Subject Alternative Names (SANs), cipher suite hygiene, and HSTS status. 

It is designed for developers, DevOps engineers, and security teams who need fast, scriptable certificate visibility without leaving the terminal or relying on web-based GUIs.

---

## 🌟 Features

*   **⚡ Fast & Direct:** Connects via TCP and initiates a TLS handshake to extract peer certificates directly—no HTTP round-trips needed.
*   **🎨 Rich Terminal UI:** Beautiful color-coded reports using `comfy-table` and `colored`, providing instant visual feedback on certificate health.
*   **🔄 Full Chain Inspection:** Decodes and maps the entire certificate chain (Leaf → Intermediate → Root).
*   **🤖 CI/CD Ready:** Predictable exit codes (0 = healthy, 1 = warning, 2+ = error/expired) for seamless pipeline integration.
*   **📦 Batch Mode:** Check dozens of domains concurrently from a file.
*   **📊 JSON & CSV Export:** Output structured machine-readable data for ingestion into dashboards or scripts.
*   **⏱️ Watch Mode & Webhooks:** Continuously monitor certificates on a set interval, detect fingerprint changes (MITM detection), and fire Slack/Discord webhooks on changes or upcoming expirations.
*   **🛡️ Pure Rust:** Built on `rustls`—no OpenSSL system dependency required.

---

## 🚀 Installation

Ensure you have [Rust](https://www.rust-lang.org/tools/install) (1.75+) installed on your system.

### From Source
```bash
git clone https://github.com/yourusername/sslcheck.git
cd sslcheck
cargo build --release
# The binary will be located at target/release/sslcheck
```

*(Note: In the future, this will be publishable directly via `cargo install sslcheck`)*

---

## 📖 Usage

### Basic Single Domain Check
Get a full, color-coded report for a domain:
```bash
sslcheck google.com
```

### Custom Port & Expiry Warnings
Connect to a custom port (e.g., SMTPS on 465) and set the expiry warning threshold to 14 days (defaults to 30):
```bash
sslcheck mail.example.com --port 465 --warn-days 14
```

### Batch Mode
Provide a newline-delimited `.txt` file of domains. Checks run concurrently.
```bash
sslcheck --file domains.txt
```

### JSON / CSV Export
Ideal for scripting or sending data to jq/monitoring tools. (Tip: use `-q` with `cargo run` or disable colored output with `--no-color` if piping).
```bash
sslcheck myapp.com --output json > report.json
sslcheck --file domains.txt --output csv > summary.csv
```

### Watch Mode & Webhooks
Run continuously, re-checking every hour (3600 seconds). If the certificate fingerprint changes or enters the expiry window, trigger a webhook.
```bash
sslcheck myapp.com --watch --interval 3600 --webhook https://hooks.slack.com/services/...
```

---

## ⚙️ CLI Reference

```text
Usage: sslcheck [OPTIONS] [DOMAIN]

Arguments:
  [DOMAIN]  Domain to check (e.g., google.com)

Options:
  -p, --port <PORT>               Custom port to connect on [default: 443]
  -w, --warn-days <WARN_DAYS>     Days before expiry to trigger exit code 1 [default: 30]
  -f, --file <FILE>               Path to file with list of domains (one per line)
  -o, --output <OUTPUT>           Output format: terminal, json, csv [default: terminal]
  -c, --concurrency <CONCURRENCY> Max parallel checks in batch mode [default: 5]
      --watch                     Enable watch mode (re-check on interval)
      --interval <INTERVAL>       Watch mode interval in seconds [default: 3600]
      --webhook <WEBHOOK>         Webhook URL for watch mode notifications
      --no-color                  Disable ANSI color output (for log piping)
  -v, --verbose                   Show raw cert fields and debug info
  -t, --timeout <TIMEOUT>         TCP connection timeout in seconds [default: 10]
  -h, --help                      Print help
  -V, --version                   Print version
```

---

## 🚪 Exit Codes

`sslcheck` is designed to be used in scripts and CI/CD pipelines (like GitHub Actions or GitLab CI). 

| Exit Code | Meaning | Use Case |
| :---: | :--- | :--- |
| **0** | **Healthy** - Certificate is valid and not expiring soon. | Pipeline passes. |
| **1** | **Warning** - Certificate is valid, but expiring within `--warn-days` (default 30). | Trigger an alert, pipeline continues. |
| **2** | **Error/Expired** - Certificate is expired, self-signed, invalid, or could not be parsed. | Pipeline fails hard. |
| **3** | **Network Error** - DNS resolution failed, or connection timed out. | Infrastructure issue, not a cert issue. |

*Example CI Pipeline check:*
```bash
# Fails the pipeline if the cert expires in less than 7 days
sslcheck api.mycompany.com --warn-days 7 || exit 1
```

---

## 🏗️ Architecture & Tech Stack

*   **Primary Language:** Rust (MSRV 1.75)
*   **Async Runtime:** `tokio` (for concurrent batch domain checks)
*   **TLS Engine:** `rustls` (pure Rust, memory safe)
*   **Cert Parsing:** `x509-parser` (strict DER extraction)
*   **CLI Parsing:** `clap`
*   **Output Formatting:** `comfy-table`, `colored`
*   **Serialization:** `serde`, `serde_json`, `csv`
*   **HTTP/Webhooks:** `reqwest`

## 🔒 Security & Privacy
`sslcheck` does not send your domain data to any third-party servers (unless you explicitly configure a `--webhook`). All TLS handshakes, certificate parsing, and validation happen locally on your machine.

---
*Created per the sslcheck v1.0 PRD.*
