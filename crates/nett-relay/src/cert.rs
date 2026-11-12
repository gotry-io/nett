//! The relay's own TLS certificate (design/mesh.md section 5.3): an Ed25519 key and a self-signed
//! certificate created the first time the relay starts, kept in its state directory. Clients check the
//! certificate by its SHA-256 fingerprint, so its names and validity carry no meaning; the certificate
//! is still well-formed X.509 so that TLS libraries accept it.

use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use nett_core::transport::CertFingerprint;
use ring::rand::{SecureRandom as _, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair as _};

/// File names in the state directory.
pub const CERT_FILE: &str = "tls-cert.der";
pub const KEY_FILE: &str = "tls-key.pk8";

/// The certificate (DER) and its private key (PKCS#8 DER). `Debug` does not print the key (hard rule
/// 10).
pub struct RelayCert {
    pub cert: Vec<u8>,
    key: zeroize::Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for RelayCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayCert")
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("{what} {path}: {source}")]
    Io {
        what: &'static str,
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "the TLS key in {0} is not a valid Ed25519 key; delete it and the certificate to create new ones"
    )]
    BadKey(String),
    #[error("the system random number generator failed")]
    Random,
}

impl RelayCert {
    pub fn fingerprint(&self) -> CertFingerprint {
        let digest = ring::digest::digest(&ring::digest::SHA256, &self.cert);
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        CertFingerprint(out)
    }

    pub fn key_der(&self) -> &[u8] {
        &self.key
    }

    /// Loads the certificate from `dir`, creating the key and certificate when there are none. The key
    /// file is `0600`.
    pub fn load_or_create(dir: &Path) -> Result<Self, CertError> {
        let (cert_path, key_path) = (dir.join(CERT_FILE), dir.join(KEY_FILE));
        let io = |what, path: &Path| {
            let path = path.display().to_string();
            move |source| CertError::Io { what, path, source }
        };
        if key_path.exists() && cert_path.exists() {
            let key = zeroize::Zeroizing::new(
                std::fs::read(&key_path).map_err(io("reading", &key_path))?,
            );
            Ed25519KeyPair::from_pkcs8(&key)
                .map_err(|_| CertError::BadKey(key_path.display().to_string()))?;
            let cert = std::fs::read(&cert_path).map_err(io("reading", &cert_path))?;
            return Ok(Self { cert, key });
        }
        let rng = SystemRandom::new();
        let key = zeroize::Zeroizing::new(
            Ed25519KeyPair::generate_pkcs8(&rng)
                .map_err(|_| CertError::Random)?
                .as_ref()
                .to_vec(),
        );
        let pair = Ed25519KeyPair::from_pkcs8(&key)
            .map_err(|_| CertError::BadKey(key_path.display().to_string()))?;
        let mut serial = [0u8; 16];
        rng.fill(&mut serial).map_err(|_| CertError::Random)?;
        let cert = self_signed(&pair, serial);
        std::fs::create_dir_all(dir).map_err(io("creating", dir))?;
        write_new(&key_path, &key).map_err(io("writing", &key_path))?;
        write_new(&cert_path, &cert).map_err(io("writing", &cert_path))?;
        Ok(Self { cert, key })
    }
}

/// Writes a new file with mode `0600` through a temporary name.
fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)
}

/// DER: a tag, its length and the content.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

fn sequence(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

/// A self-signed X.509 v3 certificate for the Ed25519 key, named `nett-relay`, valid from 2020 to the
/// end of 9999 (RFC 5280 section 4.1.2.5: no well-defined expiry).
fn self_signed(pair: &Ed25519KeyPair, mut serial: [u8; 16]) -> Vec<u8> {
    // A positive serial number in its shortest form: the first byte is non-zero and below 0x80
    serial[0] = (serial[0] & 0x7f) | 0x01;
    let ed25519 = sequence(&[&tlv(0x06, &[0x2b, 0x65, 0x70])]);
    let name = sequence(&[&tlv(
        0x31,
        &sequence(&[&tlv(0x06, &[0x55, 0x04, 0x03]), &tlv(0x0c, b"nett-relay")]),
    )]);
    let validity = sequence(&[&tlv(0x17, b"200101000000Z"), &tlv(0x18, b"99991231235959Z")]);
    let mut key_bits = vec![0u8];
    key_bits.extend_from_slice(pair.public_key().as_ref());
    let spki = sequence(&[&ed25519, &tlv(0x03, &key_bits)]);
    let version = tlv(0xa0, &tlv(0x02, &[0x02]));
    let tbs = sequence(&[
        &version,
        &tlv(0x02, &serial),
        &ed25519,
        &name,
        &validity,
        &name,
        &spki,
    ]);
    let mut signature = vec![0u8];
    signature.extend_from_slice(pair.sign(&tbs).as_ref());
    sequence(&[&tbs, &ed25519, &tlv(0x03, &signature)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn the_certificate_is_created_once_and_kept() {
        let dir_tmp = tempfile::Builder::new()
            .prefix("nett-relay-cert-")
            .tempdir()
            .expect("temp dir");
        let dir = dir_tmp.path().join("dir");
        let _ = std::fs::remove_dir_all(&dir);
        let first = RelayCert::load_or_create(&dir).expect("created");
        let mode = std::fs::metadata(dir.join(KEY_FILE))
            .expect("key")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let again = RelayCert::load_or_create(&dir).expect("loaded");
        assert_eq!(first.fingerprint(), again.fingerprint());
        assert!(
            !format!("{first:?}").contains("key:"),
            "the key is not printed"
        );

        // rustls accepts the key and certificate for a TLS 1.3 server
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(again.cert.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(again.key_der().to_vec())),
            )
            .expect("rustls accepts the certificate");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The transport adapter's client, which trusts only the fingerprint, completes a TLS handshake
    /// with the relay's own certificate.
    #[test]
    fn the_transport_adapter_accepts_the_certificate_by_fingerprint() {
        let dir_tmp = tempfile::Builder::new()
            .prefix("nett-relay-tls-")
            .tempdir()
            .expect("temp dir");
        let dir = dir_tmp.path().join("dir");
        let _ = std::fs::remove_dir_all(&dir);
        let cert = RelayCert::load_or_create(&dir).expect("created");
        let acceptor = crate::server::cert_acceptor(&cert).expect("acceptor");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("addr");
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.expect("accept");
                acceptor.accept(stream).await.map(|_| ())
            });
            let connector =
                nett_transport::client::connector(cert.fingerprint()).expect("connector");
            let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
            let name = rustls::pki_types::ServerName::IpAddress(addr.ip().into());
            connector
                .connect(name, stream)
                .await
                .expect("handshake with the pinned certificate");
            server.await.expect("joined").expect("server side");

            let other = [9u8; 32];
            let wrong =
                nett_transport::client::connector(CertFingerprint(other)).expect("connector");
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("addr");
            let acceptor = crate::server::cert_acceptor(&cert).expect("acceptor");
            tokio::spawn(async move {
                if let Ok((stream, _)) = listener.accept().await {
                    let _ = acceptor.accept(stream).await;
                }
            });
            let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
            let name = rustls::pki_types::ServerName::IpAddress(addr.ip().into());
            assert!(
                wrong.connect(name, stream).await.is_err(),
                "another fingerprint is refused"
            );
        });
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn der_lengths_use_the_long_form_from_128_bytes() {
        assert_eq!(tlv(0x04, &[0; 3])[..2], [0x04, 3]);
        assert_eq!(tlv(0x04, &[0; 200])[..3], [0x04, 0x81, 200]);
        assert_eq!(tlv(0x04, &[0; 300])[..4], [0x04, 0x82, 0x01, 0x2c]);
    }
}
