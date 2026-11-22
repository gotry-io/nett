//! nett's directory on Linux (design/release.md section 8): `/etc/nett`, root only, with the trust
//! store (`state/`) and the relay's certificate (`relay/`) in it. Every call is blocking: async
//! callers use a blocking thread.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

/// Creates `dir` when it does not exist and makes it root only (`0700`).
pub fn ensure_private_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir)
        .and_then(|()| std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)))
        .map_err(|e| format!("creating {}: {e}", dir.display()))
}

/// Creates the relay's certificate in `dir` when it has none (design/mesh.md section 5.3): systemd
/// hands it to the relay, which runs as a user it allocates.
pub fn ensure_relay_cert(dir: &Path) -> Result<(), String> {
    ensure_private_dir(dir)?;
    nett_relay::cert::RelayCert::load_or_create(dir)
        .map(drop)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The relay's certificate is created once, in a root-only directory, and kept afterwards
    #[test]
    fn the_relay_certificate_is_created_once_root_only() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let dir = tmp.path().join("relay");
        ensure_relay_cert(&dir).expect("created");
        let mode = std::fs::metadata(&dir).expect("dir").permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        let key = dir.join(nett_relay::cert::KEY_FILE);
        let first = std::fs::read(&key).expect("key");
        ensure_relay_cert(&dir).expect("kept");
        assert_eq!(std::fs::read(&key).expect("key"), first);
    }
}
