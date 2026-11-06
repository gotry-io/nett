//! 组网私钥（WireGuard）。本机生成，不离开节点；文件权限 `0600`，内存中使用 `zeroize`（硬性规则 10）。

use std::fmt;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum KeyFileError {
    #[error("reading mesh private key {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("mesh private key {path} is readable by group or others; it must be mode 0600")]
    Permissions { path: String },
    #[error("mesh private key {path} is not a base64 WireGuard key")]
    Format { path: String },
}

/// 组网私钥。`Debug` 不输出内容。
pub struct PrivateKey(Zeroizing<[u8; 32]>);

impl PrivateKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 读取 WireGuard 格式（标准 base64，与 `wg genkey` 相同）的私钥文件。
    pub fn load(path: &Path) -> Result<Self, KeyFileError> {
        let display = path.display().to_string();
        let read_err = |source| KeyFileError::Read {
            path: display.clone(),
            source,
        };
        check_permissions(path).map_err(|e| match e {
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
fn check_permissions(path: &Path) -> Result<(), PermissionCheck> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(path)
        .map_err(PermissionCheck::Io)?
        .permissions()
        .mode();
    if mode & 0o077 == 0 {
        Ok(())
    } else {
        Err(PermissionCheck::TooOpen)
    }
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> Result<(), PermissionCheck> {
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
}
