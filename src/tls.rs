// tls.rs - build a tokio-rustls TlsAcceptor from PEM files.
//
// Key design choice: we use ServerConfig::builder_with_provider() and pass
// ring explicitly rather than relying on ServerConfig::builder() which uses
// the global default provider.  In rustls 0.23, if multiple providers are
// compiled (e.g. ring + aws-lc-rs), builder() panics because it cannot
// choose a default.  Using builder_with_provider() is provider-explicit and
// works correctly regardless of what else Cargo compiled in.
//
// Supported key formats: PKCS#8 (EC or RSA) and traditional RSA PKCS#1.
// rustls-pemfile v2 private_key() tries all known formats automatically.

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::crypto::ring as ring_provider;
use rustls_pemfile::{certs, private_key};
use tokio_rustls::TlsAcceptor;

use crate::config::TlsConfig;
use crate::slog;

/// Build a TlsAcceptor from a TlsConfig.
/// Called once per service at startup.
pub fn build_acceptor(cfg: &TlsConfig) -> anyhow::Result<TlsAcceptor> {

    // --- Certificate chain -----------------------------------------------
    slog::debug(&format!("TLS: loading cert from {:?}", cfg.cert_pem));

    let cert_file = File::open(&cfg.cert_pem)
        .map_err(|e| anyhow::anyhow!("open cert {:?}: {}", cfg.cert_pem, e))?;
    let mut cert_reader = BufReader::new(cert_file);

    let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> =
        certs(&mut cert_reader)
            .map(|r| r.map_err(|e| anyhow::anyhow!("parse cert: {}", e)))
            .collect::<anyhow::Result<_>>()?;

    if cert_chain.is_empty() {
        anyhow::bail!("no certificates found in {:?}", cfg.cert_pem);
    }
    slog::debug(&format!("TLS: loaded {} certificate(s)", cert_chain.len()));

    // --- Private key -------------------------------------------------------
    slog::debug(&format!("TLS: loading key from {:?}", cfg.key_pem));

    let key_file = File::open(&cfg.key_pem)
        .map_err(|e| anyhow::anyhow!("open key {:?}: {}", cfg.key_pem, e))?;
    let mut key_reader = BufReader::new(key_file);

    // private_key() tries PKCS#8, EC, and PKCS#1 RSA in sequence
    let private_key = private_key(&mut key_reader)
        .map_err(|e| anyhow::anyhow!("parse key {:?}: {}", cfg.key_pem, e))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {:?}", cfg.key_pem))?;

    slog::debug("TLS: private key loaded");

    // --- ServerConfig ------------------------------------------------------
    // Use builder_with_provider(ring) explicitly.
    // DO NOT use ServerConfig::builder() here - it panics when both ring and
    // aws-lc-rs are compiled (even if only one is in our direct deps, Cargo
    // feature unification from tokio-rustls or other crates can pull both in).
    slog::debug("TLS: building ServerConfig with ring provider");

    let server_config = ServerConfig::builder_with_provider(
            Arc::new(ring_provider::default_provider())
        )
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow::anyhow!("TLS protocol version config: {}", e))?
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| anyhow::anyhow!("TLS cert/key error: {}", e))?;

    slog::debug("TLS: ServerConfig built OK");

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}
