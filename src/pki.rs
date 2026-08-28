//! Benchmark PKI helpers.
//!
//! TLS scenarios need an on-disk certificate + key for the gateway's decrypt
//! (TLS server) side. Rather than pull in a Rust crypto stack, SESHAT shells out
//! to the system `openssl` CLI — certificates are a one-time setup artefact, not
//! a hot-path concern, and the gateway itself is built against OpenSSL.
#![allow(dead_code)] // Parts of the PKI builder surface are used only by specific suites/tests.

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
/// `DNS:localhost, IP:127.0.0.1, IP:::1`, valid for `days`, written under `dir`.
///
/// Suitable for one-way TLS where the client uses `verify=none` or trusts this
/// certificate directly. Use [`generate_self_signed_with`] to select an RSA key
/// for `ECDHE-RSA` cipher scenarios.
pub fn generate_self_signed(dir: &Path, days: u32) -> io::Result<Identity> {
    generate_self_signed_with(dir, days, KeyType::EcP256)
}

/// Generate a self-signed server certificate with the given key algorithm and
/// SAN `DNS:localhost, IP:127.0.0.1, IP:::1`, valid for `days`, written under `dir`.
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
        "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1",
    ]);
    run_openssl(&args)?;
    Ok(Identity { cert, key })
}

/// Generate a mutual-TLS bundle under `dir`: a self-signed EC (P-256) CA plus a
/// server identity and a client identity, both signed by that CA. The server
/// leaf carries SAN `DNS:localhost, IP:127.0.0.1, IP:::1` and `serverAuth` EKU; the
/// client leaf carries `clientAuth` EKU. Valid for `days`.
///
/// Used for the mTLS path where the decrypt side runs `verify=mutual` against
/// the CA and the encrypt side presents the client identity.
pub fn generate_mtls_bundle(dir: &Path, days: u32) -> io::Result<CaBundle> {
    generate_mtls_bundle_with_sans(dir, days, &[])
}

/// As [`generate_mtls_bundle`], but the **server** leaf additionally carries
/// `server_extra_sans` (entries in `TYPE:value` form, e.g. `IP:10.9.0.2`).
///
/// Needed by the two-host wire benchmark: the gateway's own validator makes
/// `verify: mutual` mandatory on a non-loopback decrypt listener, and the
/// encrypt side dials the peer by IP literal, so the peer's server certificate
/// must carry an `IP:` SAN for that address. Only the server leaf is
/// name-verified (the decrypt side checks the client's chain and EKU, not a
/// hostname), so the client leaf keeps the loopback-only SAN list.
pub fn generate_mtls_bundle_with_sans(
    dir: &Path,
    days: u32,
    server_extra_sans: &[String],
) -> io::Result<CaBundle> {
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
        server_extra_sans,
    )?;
    let client = sign_leaf(
        dir,
        "client",
        "seshat-client",
        &ca_cert,
        &ca_key,
        "clientAuth",
        &days,
        &[],
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
        &[],
    )
}

/// The SAN list every leaf carries, covering the single-host loopback paths.
const LOOPBACK_SANS: &str = "DNS:localhost,IP:127.0.0.1,IP:::1";

/// Build a `subjectAltName` value: the loopback SANs plus any caller-supplied
/// entries (already in `TYPE:value` form, e.g. `IP:10.9.0.2`).
///
/// With an empty `extra`, this returns exactly [`LOOPBACK_SANS`], which is what
/// keeps a no-extra-SAN leaf byte-identical to the pre-existing behaviour.
fn san_list(extra: &[String]) -> String {
    let mut san = String::from(LOOPBACK_SANS);
    for entry in extra {
        san.push(',');
        san.push_str(entry);
    }
    san
}

/// Generate an EC leaf key + CSR and sign it with the CA, attaching a SAN and
/// the given extended-key-usage (`serverAuth` or `clientAuth`).
///
/// `extra_sans` appends to the default loopback SAN list; pass `&[]` for the
/// loopback-only behaviour.
// The CA pair, the naming, the EKU and the validity are all independent inputs
// to one openssl invocation; grouping them into a struct would add a type that
// exists solely to satisfy the lint on a private helper.
#[allow(clippy::too_many_arguments)]
fn sign_leaf(
    dir: &Path,
    name: &str,
    cn: &str,
    ca_cert: &Path,
    ca_key: &Path,
    eku: &str,
    days: &str,
    extra_sans: &[String],
) -> io::Result<Identity> {
    let key = dir.join(format!("{name}.key"));
    let csr = dir.join(format!("{name}.csr"));
    let cert = dir.join(format!("{name}.crt"));
    let ext = dir.join(format!("{name}.ext"));
    let san = san_list(extra_sans);
    std::fs::write(
        &ext,
        format!(
            "basicConstraints=CA:FALSE\n\
             subjectAltName={san}\n\
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

    /// Full `openssl x509 -text` rendering of a PEM certificate.
    fn cert_text(cert: &Path) -> String {
        let out = Command::new("openssl")
            .args(["x509", "-in", cert.to_str().unwrap(), "-noout", "-text"])
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// The `Public Key Algorithm` line of a PEM certificate, via the openssl CLI.
    fn cert_pubkey_algorithm(cert: &Path) -> String {
        cert_text(cert)
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

    #[test]
    fn san_list_appends_extras_to_the_loopback_list() {
        assert_eq!(san_list(&[]), LOOPBACK_SANS);
        assert_eq!(
            san_list(&["IP:10.9.0.2".to_string()]),
            format!("{LOOPBACK_SANS},IP:10.9.0.2")
        );
        assert_eq!(
            san_list(&["IP:10.9.0.1".to_string(), "IP:10.9.0.2".to_string()]),
            format!("{LOOPBACK_SANS},IP:10.9.0.1,IP:10.9.0.2")
        );
    }

    /// Adding the extra-SAN parameter must not perturb any pre-existing bundle:
    /// with no extras the emitted openssl extension file stays byte-identical.
    #[test]
    fn empty_extra_sans_emit_a_byte_identical_extension_file() {
        if !openssl_available() {
            eprintln!("skip: openssl CLI not available");
            return;
        }
        let base = std::env::temp_dir().join(format!("seshat-pki-san-{}", std::process::id()));
        let plain = base.join("plain");
        let empty = base.join("empty");
        generate_mtls_bundle(&plain, 2).unwrap();
        generate_mtls_bundle_with_sans(&empty, 2, &[]).unwrap();
        for leaf in ["server", "client"] {
            let a = std::fs::read(plain.join(format!("{leaf}.ext"))).unwrap();
            let b = std::fs::read(empty.join(format!("{leaf}.ext"))).unwrap();
            assert_eq!(a, b, "{leaf}.ext differs when extra SANs are empty");
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The wire benchmark dials the peer by IP literal, so the server leaf must
    /// carry an `IP:` SAN for it. The client leaf is not name-verified and keeps
    /// the loopback-only list.
    #[test]
    fn server_leaf_carries_extra_ip_sans_and_client_leaf_does_not() {
        if !openssl_available() {
            eprintln!("skip: openssl CLI not available");
            return;
        }
        let dir = std::env::temp_dir().join(format!("seshat-pki-wire-{}", std::process::id()));
        let bundle = generate_mtls_bundle_with_sans(&dir, 2, &["IP:10.9.0.2".to_string()]).unwrap();
        let server = cert_text(&bundle.server.cert);
        assert!(
            server.contains("IP Address:10.9.0.2"),
            "server leaf is missing the extra IP SAN:\n{server}"
        );
        assert!(
            server.contains("DNS:localhost"),
            "server leaf lost the loopback SANs:\n{server}"
        );
        let client = cert_text(&bundle.client.cert);
        assert!(
            !client.contains("IP Address:10.9.0.2"),
            "client leaf unexpectedly carries the extra IP SAN:\n{client}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
