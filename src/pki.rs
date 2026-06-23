//! Benchmark PKI helpers (WP2.1 / WP2.5).
//!
//! TLS scenarios need an on-disk certificate + key for the gateway's decrypt
//! (TLS server) side. Rather than pull in a Rust crypto stack, SESHAT shells out
//! to the system `openssl` CLI — certificates are a one-time setup artefact, not
//! a hot-path concern, and the gateway itself is built against OpenSSL.
#![allow(dead_code)] // PKI surface is consumed across Phase 2 work packages.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A leaf identity: PEM certificate plus its private key.
#[derive(Debug, Clone)]
pub struct Identity {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// A CA plus the server/client leaf identities it signs (for mutual-TLS paths).
#[derive(Debug, Clone)]
pub struct CaBundle {
    pub ca_cert: PathBuf,
    pub server: Identity,
    pub client: Identity,
}

/// Whether the `openssl` CLI is usable (TLS scenarios require it).
pub fn openssl_available() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Generate a self-signed EC (P-256) server certificate with SAN
/// `DNS:localhost, IP:127.0.0.1`, valid for `days`, written under `dir`.
///
/// Suitable for one-way TLS where the client uses `verify=none` or trusts this
/// certificate directly.
pub fn generate_self_signed(dir: &Path, days: u32) -> io::Result<Identity> {
    std::fs::create_dir_all(dir)?;
    let cert = dir.join("server.crt");
    let key = dir.join("server.key");
    let days = days.to_string();
    run_openssl(&[
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-nodes",
        "-keyout",
        path_arg(&key)?,
        "-out",
        path_arg(&cert)?,
        "-days",
        &days,
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ])?;
    Ok(Identity { cert, key })
}

/// Generate a mutual-TLS bundle under `dir`: a self-signed EC (P-256) CA plus a
/// server identity and a client identity, both signed by that CA. The server
/// leaf carries SAN `DNS:localhost, IP:127.0.0.1` and `serverAuth` EKU; the
/// client leaf carries `clientAuth` EKU. Valid for `days`.
///
/// Used for the mTLS path where the decrypt side runs `verify=mutual` against
/// the CA and the encrypt side presents the client identity.
pub fn generate_mtls_bundle(dir: &Path, days: u32) -> io::Result<CaBundle> {
    std::fs::create_dir_all(dir)?;
    let days = days.to_string();
    let ca_cert = dir.join("ca.crt");
    let ca_key = dir.join("ca.key");
    run_openssl(&[
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-nodes",
        "-keyout",
        path_arg(&ca_key)?,
        "-out",
        path_arg(&ca_cert)?,
        "-days",
        &days,
        "-subj",
        "/CN=SESHAT Test CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    ])?;

    let server = sign_leaf(
        dir,
        "server",
        "localhost",
        &ca_cert,
        &ca_key,
        "serverAuth",
        &days,
    )?;
    let client = sign_leaf(
        dir,
        "client",
        "seshat-client",
        &ca_cert,
        &ca_key,
        "clientAuth",
        &days,
    )?;
    Ok(CaBundle {
        ca_cert,
        server,
        client,
    })
}

/// Generate an EC leaf key + CSR and sign it with the CA, attaching a SAN and
/// the given extended-key-usage (`serverAuth` or `clientAuth`).
fn sign_leaf(
    dir: &Path,
    name: &str,
    cn: &str,
    ca_cert: &Path,
    ca_key: &Path,
    eku: &str,
    days: &str,
) -> io::Result<Identity> {
    let key = dir.join(format!("{name}.key"));
    let csr = dir.join(format!("{name}.csr"));
    let cert = dir.join(format!("{name}.crt"));
    let ext = dir.join(format!("{name}.ext"));
    std::fs::write(
        &ext,
        format!(
            "basicConstraints=CA:FALSE\n\
             subjectAltName=DNS:localhost,IP:127.0.0.1\n\
             keyUsage=digitalSignature\n\
             extendedKeyUsage={eku}\n"
        ),
    )?;
    let subj = format!("/CN={cn}");
    run_openssl(&[
        "req",
        "-new",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-nodes",
        "-keyout",
        path_arg(&key)?,
        "-subj",
        &subj,
        "-out",
        path_arg(&csr)?,
    ])?;
    run_openssl(&[
        "x509",
        "-req",
        "-in",
        path_arg(&csr)?,
        "-CA",
        path_arg(ca_cert)?,
        "-CAkey",
        path_arg(ca_key)?,
        "-CAcreateserial",
        "-days",
        days,
        "-extfile",
        path_arg(&ext)?,
        "-out",
        path_arg(&cert)?,
    ])?;
    Ok(Identity { cert, key })
}
fn run_openssl(args: &[&str]) -> io::Result<()> {
    let output = Command::new("openssl")
        .args(args)
        .output()
        .map_err(|e| io::Error::new(e.kind(), format!("failed to run openssl CLI: {e}")))?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "openssl {} failed: {}",
            args.first().copied().unwrap_or_default(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// Borrow a path as a UTF-8 CLI argument, or fail loudly on non-UTF-8 paths.
fn path_arg(p: &Path) -> io::Result<&str> {
    p.to_str()
        .ok_or_else(|| io::Error::other("non-UTF8 certificate path"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signed_cert_is_generated() {
        if !openssl_available() {
            eprintln!("skip: openssl CLI not available");
            return;
        }
        let dir = std::env::temp_dir().join(format!("seshat-pki-{}", std::process::id()));
        let id = generate_self_signed(&dir, 2).unwrap();
        assert!(id.cert.is_file());
        assert!(id.key.is_file());
        let pem = std::fs::read_to_string(&id.cert).unwrap();
        assert!(pem.contains("BEGIN CERTIFICATE"));
        let key = std::fs::read_to_string(&id.key).unwrap();
        assert!(key.contains("PRIVATE KEY"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mtls_bundle_is_generated_and_chains() {
        if !openssl_available() {
            eprintln!("skip: openssl CLI not available");
            return;
        }
        let dir = std::env::temp_dir().join(format!("seshat-pki-mtls-{}", std::process::id()));
        let bundle = generate_mtls_bundle(&dir, 2).unwrap();
        for p in [
            &bundle.ca_cert,
            &bundle.server.cert,
            &bundle.server.key,
            &bundle.client.cert,
            &bundle.client.key,
        ] {
            assert!(p.is_file(), "missing {}", p.display());
        }
        // Both leaves must verify against the CA.
        for leaf in [&bundle.server.cert, &bundle.client.cert] {
            let out = Command::new("openssl")
                .args([
                    "verify",
                    "-CAfile",
                    bundle.ca_cert.to_str().unwrap(),
                    leaf.to_str().unwrap(),
                ])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "verify failed for {}: {}",
                leaf.display(),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
