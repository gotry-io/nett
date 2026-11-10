//! 本机的 Hub 配置（design/hub.md 第 7 节）：`sudo nett install <token>` 写入，nett-node 读取。没有秘密，但
//! 决定这台机器连哪个 Hub，只给 root（`0600`）。

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

/// 写一个只给所有者读写（`0600`）的文件：先写同一目录中的临时文件、落盘，再改名；不跟随符号链接。
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
