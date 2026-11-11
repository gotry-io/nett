//! Mesh private key (WireGuard). Generated on this machine and never leaves the node; file mode `0600`,
//! `zeroize` in memory (hard rule 10).

use std::fmt;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum KeyFileError {
    #[error("reading mesh private key {path}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("mesh private key {path} is readable by group or others; it must be mode 0600")]
    Permissions { path: String },
    #[error("mesh private key {path} is not a base64 WireGuard key")]
    Format { path: String },
    #[error("writing private key {path}")]
    Write {
        path: String,
        source: std::io::Error,
    },
    #[error("generating a private key: the system random number generator failed")]
    Random,
}

/// Mesh private key. `Debug` does not print the contents.
pub struct PrivateKey(Zeroizing<[u8; 32]>);

impl PrivateKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Generates a new private key (X25519) from the system random number generator.
    pub fn generate() -> Result<Self, KeyFileError> {
        use ring::rand::{SecureRandom as _, SystemRandom};
        let mut bytes = Zeroizing::new([0u8; 32]);
        SystemRandom::new()
            .fill(bytes.as_mut())
            .map_err(|_| KeyFileError::Random)?;
        Ok(Self(bytes))
    }

    pub fn public_key(&self) -> nett_trust::keys::X25519PublicKey {
        let secret = x25519_dalek::StaticSecret::from(*self.0);
        nett_trust::keys::X25519PublicKey::from_bytes(
            x25519_dalek::PublicKey::from(&secret).to_bytes(),
        )
    }

    /// Writes to a new file (mode `0600`, same format as `wg genkey`). Fails if the file already exists;
    /// never overwrites.
    pub fn save_new(&self, path: &Path) -> Result<(), KeyFileError> {
        use std::io::Write as _;
        let write_err = |source| KeyFileError::Write {
            path: path.display().to_string(),
            source,
        };
        let mut options = std::fs::File::options();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(path).map_err(write_err)?;
        let text = Zeroizing::new(format!("{}\n", STANDARD.encode(*self.0)));
        file.write_all(text.as_bytes()).map_err(write_err)
    }

    /// Reads a private key file in WireGuard format (standard base64, same as `wg genkey`).
    pub fn load(path: &Path) -> Result<Self, KeyFileError> {
        let display = path.display().to_string();
        let read_err = |source| KeyFileError::Read {
            path: display.clone(),
            source,
        };
        let credentials = std::env::var_os("CREDENTIALS_DIRECTORY").map(std::path::PathBuf::from);
        check_permissions(path, credentials.as_deref()).map_err(|e| match e {
            PermissionCheck::Io(source) => read_err(source),
            PermissionCheck::TooOpen => KeyFileError::Permissions {
                path: display.clone(),
            },
        })?;
        let text = Zeroizing::new(std::fs::read_to_string(path).map_err(read_err)?);
        let decoded =
            Zeroizing::new(
                STANDARD
                    .decode(text.trim())
                    .map_err(|_| KeyFileError::Format {
                        path: display.clone(),
                    })?,
            );
        let bytes: [u8; 32] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| KeyFileError::Format { path: display })?;
        Ok(Self::from_bytes(bytes))
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(<redacted>)")
    }
}

enum PermissionCheck {
    Io(std::io::Error),
    TooOpen,
}

#[cfg(unix)]
/// A key file must be readable by its owner only. systemd hands the key to the mesh service as a
/// credential (`LoadCredential=`): the file there is group-readable, and the credentials directory
/// is what keeps everyone else out, so a key inside `credentials` (the service's
/// `$CREDENTIALS_DIRECTORY`, which others cannot enter) is accepted.
fn check_permissions(path: &Path, credentials: Option<&Path>) -> Result<(), PermissionCheck> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(path)
        .map_err(PermissionCheck::Io)?
        .permissions()
        .mode();
    if mode & 0o077 == 0 || in_credentials(path, credentials)? {
        Ok(())
    } else {
        Err(PermissionCheck::TooOpen)
    }
}

fn in_credentials(path: &Path, credentials: Option<&Path>) -> Result<bool, PermissionCheck> {
    use std::os::unix::fs::PermissionsExt as _;
    let Some(dir) = credentials else {
        return Ok(false);
    };
    let (Ok(dir), Some(parent)) = (dir.canonicalize(), path.parent()) else {
        return Ok(false);
    };
    let parent = parent.canonicalize().map_err(PermissionCheck::Io)?;
    let closed = std::fs::metadata(&dir)
        .map_err(PermissionCheck::Io)?
        .permissions()
        .mode()
        & 0o007
        == 0;
    Ok(parent == dir && closed)
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path, _credentials: Option<&Path>) -> Result<(), PermissionCheck> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn write(dir: &Path, name: &str, content: &str, mode: u32) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, content).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        path
    }

    #[test]
    fn loads_wireguard_keys_with_strict_permissions() {
        let dir = std::env::temp_dir().join(format!("nett-key-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let key = STANDARD.encode([7u8; 32]);

        let ok = write(&dir, "ok.key", &format!("{key}\n"), 0o600);
        assert_eq!(PrivateKey::load(&ok).expect("load").as_bytes(), &[7u8; 32]);

        let open = write(&dir, "open.key", &key, 0o644);
        assert!(matches!(
            PrivateKey::load(&open),
            Err(KeyFileError::Permissions { .. })
        ));

        let short = write(&dir, "short.key", &STANDARD.encode([7u8; 31]), 0o600);
        assert!(matches!(
            PrivateKey::load(&short),
            Err(KeyFileError::Format { .. })
        ));

        assert_eq!(
            format!("{:?}", PrivateKey::from_bytes([1; 32])),
            "PrivateKey(<redacted>)"
        );
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn a_group_readable_key_passes_only_in_the_services_credentials_directory() {
        // systemd's LoadCredential= leaves the key group-readable inside a directory others
        // cannot enter; the same file anywhere else is refused
        let dir = std::env::temp_dir().join(format!("nett-key-cred-{}", std::process::id()));
        let creds = dir.join("credentials");
        std::fs::create_dir_all(&creds).expect("dir");
        std::fs::set_permissions(&creds, std::fs::Permissions::from_mode(0o750)).expect("chmod");
        let key = STANDARD.encode([3u8; 32]);
        let inside = write(&creds, "mesh.key", &key, 0o440);
        let outside = write(&dir, "mesh.key", &key, 0o440);
        assert!(check_permissions(&inside, Some(&creds)).is_ok());
        assert!(matches!(
            check_permissions(&inside, None),
            Err(PermissionCheck::TooOpen)
        ));
        assert!(matches!(
            check_permissions(&outside, Some(&creds)),
            Err(PermissionCheck::TooOpen)
        ));
        // a directory others can enter is not a credentials directory
        std::fs::set_permissions(&creds, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        assert!(matches!(
            check_permissions(&inside, Some(&creds)),
            Err(PermissionCheck::TooOpen)
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn generated_keys_round_trip_and_are_never_overwritten() {
        let dir = std::env::temp_dir().join(format!("nett-keygen-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let key = PrivateKey::generate().expect("generate");
        assert_ne!(
            key.as_bytes(),
            PrivateKey::generate().expect("generate").as_bytes()
        );
        let path = dir.join("mesh.key");
        key.save_new(&path).expect("save");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let loaded = PrivateKey::load(&path).expect("load");
        assert_eq!(loaded.public_key(), key.public_key());
        assert!(matches!(
            PrivateKey::generate().expect("generate").save_new(&path),
            Err(KeyFileError::Write { .. })
        ));
        assert_eq!(
            PrivateKey::load(&path).expect("load").as_bytes(),
            key.as_bytes()
        );
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
