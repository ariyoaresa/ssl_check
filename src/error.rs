use std::fmt;

/// Unified error type for sslcheck.
#[allow(dead_code)]
#[derive(Debug)]
pub enum SslCheckError {
    /// DNS resolution failed.
    Dns(String),
    /// TCP connection timed out or was refused.
    ConnectionTimeout(String),
    /// TLS handshake failed.
    TlsHandshake(String),
    /// X.509 certificate parsing failed.
    CertParse(String),
    /// Generic I/O error.
    Io(std::io::Error),
    /// Export serialization error.
    Export(String),
    /// Webhook POST failed.
    Webhook(String),
    /// File reading error (batch mode).
    FileRead(String),
}

impl fmt::Display for SslCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SslCheckError::Dns(msg) => write!(f, "DNS resolution failed: {}", msg),
            SslCheckError::ConnectionTimeout(msg) => write!(f, "Connection failed: {}", msg),
            SslCheckError::TlsHandshake(msg) => write!(f, "TLS handshake failed: {}", msg),
            SslCheckError::CertParse(msg) => write!(f, "Certificate parse error: {}", msg),
            SslCheckError::Io(err) => write!(f, "I/O error: {}", err),
            SslCheckError::Export(msg) => write!(f, "Export error: {}", msg),
            SslCheckError::Webhook(msg) => write!(f, "Webhook error: {}", msg),
            SslCheckError::FileRead(msg) => write!(f, "File read error: {}", msg),
        }
    }
}

impl std::error::Error for SslCheckError {}

impl From<std::io::Error> for SslCheckError {
    fn from(err: std::io::Error) -> Self {
        SslCheckError::Io(err)
    }
}

/// The health status of a certificate.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertStatus {
    Healthy,
    ExpiringSoon,
    Expired,
    Error,
}

impl fmt::Display for CertStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertStatus::Healthy => write!(f, "healthy"),
            CertStatus::ExpiringSoon => write!(f, "expiring_soon"),
            CertStatus::Expired => write!(f, "expired"),
            CertStatus::Error => write!(f, "error"),
        }
    }
}

/// Maps a CertStatus to a process exit code.
pub fn exit_code(status: &CertStatus) -> i32 {
    match status {
        CertStatus::Healthy => 0,
        CertStatus::ExpiringSoon => 1,
        CertStatus::Expired => 2,
        CertStatus::Error => 2,
    }
}

/// Maps an SslCheckError to an exit code.
pub fn error_exit_code(err: &SslCheckError) -> i32 {
    match err {
        SslCheckError::Dns(_) | SslCheckError::ConnectionTimeout(_) => 3,
        SslCheckError::TlsHandshake(_) => 2,
        SslCheckError::CertParse(_) => 2,
        _ => 2,
    }
}
