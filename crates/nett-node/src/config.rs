//! This machine's Hub configuration (design/hub.md section 7): written by `sudo nett install
//! <token>` and read by nett-node. It holds no secrets, but decides which Hub this machine connects
//! to, so it is root-only (`0600`).

use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use nett_proto::token::Bytes32;
use serde::{Deserialize, Serialize};

pub const HUB_FILE: &str = "hub.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HubConfig {
    pub url: String,
    pub hub_key: Bytes32,
    pub node_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_fingerprint: Option<Bytes32>,
}

impl HubConfig {
    pub fn load(dir: &Path) -> Result<Option<Self>, String> {
        let path = dir.join(HUB_FILE);
        match nett_mesh::config::read_bounded(&path, 64 * 1024) {
            Ok(None) => Ok(None),
            Ok(Some(bytes)) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| format!("{}: {e}", path.display())),
            Err(e) => Err(format!("reading {}: {e}", path.display())),
        }
    }

    pub fn save(&self, dir: &Path) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        write_private(&dir.join(HUB_FILE), &json)
    }
}

/// Writes a file readable and writable only by its owner (`0600`): write a temporary file in the
/// same directory, sync to disk, then rename; does not follow symbolic links.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let io = |e: std::io::Error| format!("writing {}: {e}", path.display());
    let name = path
        .file_name()
        .ok_or_else(|| format!("{} is not a file path", path.display()))?;
    let tmp = path.with_file_name(format!(".{}.tmp", name.to_string_lossy()));
    std::fs::remove_file(&tmp).ok();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .map_err(io)?;
    file.write_all(bytes).map_err(io)?;
    file.sync_all().map_err(io)?;
    std::fs::rename(&tmp, path).map_err(io)
}
