use axum_server::tls_rustls::RustlsConfig;
use rcgen::{CertificateParams, KeyPair};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

fn default_cert_dir() -> PathBuf {
    std::env::temp_dir().join("sikrypt-tls")
}

fn ensure_parent_dir(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn generate_self_signed_pem() -> io::Result<(String, String)> {
    let params = CertificateParams::new(vec!["localhost".to_string()])
        .map_err(|err| io::Error::other(format!("failed to prepare TLS certificate: {err}")))?;
    let signing_key = KeyPair::generate()
        .map_err(|err| io::Error::other(format!("failed to generate TLS key pair: {err}")))?;
    let cert = params
        .self_signed(&signing_key)
        .map_err(|err| io::Error::other(format!("failed to self-sign TLS certificate: {err}")))?;

    Ok((cert.pem(), signing_key.serialize_pem()))
}

fn material_paths() -> io::Result<(PathBuf, PathBuf)> {
    let cert_path = std::env::var("SIKRYPT_TLS_CERT_PATH")
        .ok()
        .map(PathBuf::from);
    let key_path = std::env::var("SIKRYPT_TLS_KEY_PATH")
        .ok()
        .map(PathBuf::from);

    match (cert_path, key_path) {
        (Some(cert), Some(key)) => Ok((cert, key)),
        (None, None) => {
            let dir = default_cert_dir();
            let cert = dir.join("cert.pem");
            let key = dir.join("key.pem");
            if !cert.exists() || !key.exists() {
                let (cert_pem, key_pem) = generate_self_signed_pem()?;
                ensure_parent_dir(&cert)?;
                ensure_parent_dir(&key)?;
                fs::write(&cert, cert_pem)?;
                fs::write(&key, key_pem)?;
            }
            Ok((cert, key))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SIKRYPT_TLS_CERT_PATH and SIKRYPT_TLS_KEY_PATH must both be set",
        )),
    }
}

pub async fn load_tls_config() -> io::Result<RustlsConfig> {
    let (cert_path, key_path) = material_paths()?;
    RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .map_err(|err| io::Error::other(format!("failed to load TLS config: {err}")))
}
