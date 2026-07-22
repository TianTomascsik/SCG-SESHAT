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

/// Server-certificate key algorithm.
///
/// The cert's key type must match the cipher suite's authentication algorithm:
/// an `ECDHE-RSA` (TLS 1.2) suite needs an RSA cert, while `ECDHE-ECDSA` and the
/// auth-agnostic TLS 1.3 suites use an EC cert. Mismatches surface as OpenSSL
/// `no shared cipher` handshake failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// NIST P-256 elliptic curve (ECDSA auth). The default for TLS 1.3 and
    /// `ECDHE-ECDSA` suites.
    EcP256,
    /// RSA 2048-bit (RSA auth). Required by `ECDHE-RSA` TLS 1.2 suites.
    Rsa2048,
}

impl KeyType {
    /// The `openssl req`/`genpkey` `-newkey` arguments that select this key type.
    fn newkey_args(self) -> &'static [&'static str] {
        match self {
            KeyType::EcP256 => &["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"],
            KeyType::Rsa2048 => &["-newkey", "rsa:2048"],
        }
    }
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
/// certificate directly. Use [`generate_self_signed_with`] to select an RSA key
/// for `ECDHE-RSA` cipher scenarios.
pub fn generate_self_signed(dir: &Path, days: u32) -> io::Result<Identity> {
    generate_self_signed_with(dir, days, KeyType::EcP256)
}

/// Generate a self-signed server certificate with the given key algorithm and
/// SAN `DNS:localhost, IP:127.0.0.1`, valid for `days`, written under `dir`.
///
/// The key type must match the negotiated cipher suite's authentication: RSA
/// for `ECDHE-RSA` (TLS 1.2) suites, EC for `ECDHE-ECDSA` and TLS 1.3.
pub fn generate_self_signed_with(dir: &Path, days: u32, key_type: KeyType) -> io::Result<Identity> {
    std::fs::create_dir_all(dir)?;
    let cert = dir.join("server.crt");
    let key = dir.join("server.key");
    let days = days.to_string();
    let key_path = path_arg(&key)?;
    let cert_path = path_arg(&cert)?;
    let mut args: Vec<&str> = vec!["req", "-x509"];
    args.extend_from_slice(key_type.newkey_args());
    args.extend_from_slice(&[
        "-nodes",
        "-keyout",
        key_path,
        "-out",
        cert_path,
        "-days",
        &days,
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ]);
    run_openssl(&args)?;
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

/// Issue an additional CA-signed server leaf (`<name>.crt` / `<name>.key`)
/// under `dir`, chained to the `generate_mtls_bundle` CA already present there
/// (`ca.crt` / `ca.key`). Used by the hot-reload cert swap to stage a second,
/// distinct server identity that the encrypt side's trust anchor already
/// accepts.
pub fn issue_server_leaf(dir: &Path, name: &str, days: u32) -> io::Result<Identity> {
    let ca_cert = dir.join("ca.crt");
    let ca_key = dir.join("ca.key");
    if !ca_cert.exists() || !ca_key.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no ca.crt/ca.key under dir (generate_mtls_bundle must run first)",
        ));
    }
    let days = days.to_string();
    sign_leaf(
        dir,
        name,
        "localhost",
        &ca_cert,
        &ca_key,
        "serverAuth",
        &days,
    )
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

    /// The `Public Key Algorithm` line of a PEM certificate, via the openssl CLI.
    fn cert_pubkey_algorithm(cert: &Path) -> String {
        let out = Command::new("openssl")
            .args(["x509", "-in", cert.to_str().unwrap(), "-noout", "-text"])
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|l| l.trim().strip_prefix("Public Key Algorithm:"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    }

    #[test]
    fn self_signed_key_type_matches_request() {
        if !openssl_available() {
            eprintln!("skip: openssl CLI not available");
            return;
        }
        let base = std::env::temp_dir().join(format!("seshat-pki-kt-{}", std::process::id()));
        let ec_dir = base.join("ec");
        let rsa_dir = base.join("rsa");
        let ec = generate_self_signed_with(&ec_dir, 2, KeyType::EcP256).unwrap();
        let rsa = generate_self_signed_with(&rsa_dir, 2, KeyType::Rsa2048).unwrap();
        assert_eq!(cert_pubkey_algorithm(&ec.cert), "id-ecPublicKey");
        assert_eq!(cert_pubkey_algorithm(&rsa.cert), "rsaEncryption");
        let _ = std::fs::remove_dir_all(&base);
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
