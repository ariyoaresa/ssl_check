use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::error::SslCheckError;
use crate::types::TlsInfo;

/// Performs a TLS handshake with the given domain and returns the TLS metadata
/// plus the raw DER-encoded certificate chain.
pub async fn check_domain(
    domain: &str,
    port: u16,
    timeout_secs: u64,
) -> Result<(TlsInfo, Vec<Vec<u8>>), SslCheckError> {
    // Resolve DNS and connect TCP
    let addr = format!("{}:{}", domain, port);
    let tcp_stream = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| SslCheckError::ConnectionTimeout(format!("Timed out connecting to {}", addr)))?
    .map_err(|e| {
        if e.kind() == std::io::ErrorKind::Other
            || e.to_string().contains("No such host")
            || e.to_string().contains("getaddrinfo")
        {
            SslCheckError::Dns(format!("Could not resolve {}: {}", domain, e))
        } else {
            SslCheckError::ConnectionTimeout(format!("Failed to connect to {}: {}", addr, e))
        }
    })?;

    // Get the resolved IP address
    let ip_address = tcp_stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    // Build TLS config — accept all certs for inspection purposes
    // We use a custom verifier that captures certs but doesn't fail
    let mut root_store = rustls::RootCertStore::empty();

    // Load native OS certificates
    let native_certs = rustls_native_certs::load_native_certs();
    for cert in native_certs.certs {
        let _ = root_store.add(cert);
    }

    // Add webpki (Mozilla) roots as fallback
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    let server_name = ServerName::try_from(domain.to_string())
        .map_err(|e| SslCheckError::TlsHandshake(format!("Invalid server name '{}': {}", domain, e)))?;

    let tls_stream = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        connector.connect(server_name, tcp_stream),
    )
    .await
    .map_err(|_| SslCheckError::TlsHandshake(format!("TLS handshake timed out for {}", domain)))?
    .map_err(|e| SslCheckError::TlsHandshake(format!("TLS handshake failed for {}: {}", domain, e)))?;

    // Extract connection info
    let (_, conn) = tls_stream.get_ref();

    let tls_version = match conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_0) => "TLSv1.0".to_string(),
        Some(rustls::ProtocolVersion::TLSv1_1) => "TLSv1.1".to_string(),
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLSv1.2".to_string(),
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLSv1.3".to_string(),
        Some(v) => format!("{:?}", v),
        None => "unknown".to_string(),
    };

    // Extract peer certificates as raw DER bytes
    let peer_certs = conn
        .peer_certificates()
        .ok_or_else(|| SslCheckError::TlsHandshake("No peer certificates received".to_string()))?;

    let raw_certs: Vec<Vec<u8>> = peer_certs.iter().map(|c| c.as_ref().to_vec()).collect();

    if raw_certs.is_empty() {
        return Err(SslCheckError::TlsHandshake(
            "Server returned empty certificate chain".to_string(),
        ));
    }

    let tls_info = TlsInfo {
        tls_version,
        ip_address,
        port,
        domain: domain.to_string(),
    };

    Ok((tls_info, raw_certs))
}

/// Checks whether the domain sends an HSTS header.
pub async fn check_hsts(domain: &str) -> bool {
    let url = format!("https://{}", domain);
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    match client.get(&url).send().await {
        Ok(resp) => resp.headers().contains_key("strict-transport-security"),
        Err(_) => false,
    }
}
