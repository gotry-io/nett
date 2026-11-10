//! 站点目录（design/site.md 第 8 节）：恢复密钥 `recovery.pk8`、站点状态 `state.json`，不接 Hub 时还有各台
//! 机器的期望状态 `nodes/<机器>/desired.json`。目录 `0700`，文件 `0600`，先写临时文件再改名；同一时间
//! 只有一个修改命令在运行。

use std::fs::File;
use std::io::Write as _;
use std::net::Ipv6Addr;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use nett_core::name::NodeName;
use nett_core::prefix::IpPrefix;
use nett_mesh::config::{DesiredMeshDoc, MAX_DESIRED_BYTES, MeshPrefixes, read_bounded};
use nett_trust::anchors::{TrustAnchors, TrustAnchorsDoc};
use nett_trust::signing::RecoveryKeyPair;

use crate::SiteError;
use crate::state::State;

pub const STATE_FILE: &str = "state.json";
pub const RECOVERY_FILE: &str = "recovery.pk8";
pub const NODES_DIR: &str = "nodes";
pub const DESIRED_FILE: &str = "desired.json";
const LOCK_FILE: &str = ".lock";
/// 组网的 IPv4 网段（design/mesh.md 第 3 节）。
const MESH_IPV4: &str = "100.88.0.0/16";

/// 一个打开的站点目录：持有它的锁。
pub struct SiteDir {
    path: PathBuf,
    _lock: File,
}

impl SiteDir {
    /// 建立站点：恢复密钥、只含它的信任锚清单、组网网段（IPv6 为随机的 ULA `/48`）。
    pub fn init(path: &Path, origin: &str) -> Result<(), SiteError> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(|e| SiteError::io(format!("creating {}", path.display()), e))?;
        // 目录已经存在时也收紧：其中有恢复密钥
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| SiteError::io(format!("setting permissions of {}", path.display()), e))?;
        for name in [STATE_FILE, RECOVERY_FILE] {
            if path.join(name).exists() {
                return Err(SiteError::invalid(format!(
                    "{} already exists; this directory already holds a site",
                    path.join(name).display()
                )));
            }
        }
        let rp_id = origin
            .strip_prefix("https://")
            .filter(|h| !h.is_empty() && !h.contains('/'))
            .ok_or_else(|| {
                SiteError::invalid(format!(
                    "--origin must look like https://<host>, got {origin}"
                ))
            })?;
        let recovery = RecoveryKeyPair::generate().map_err(SiteError::sign)?;
        let trust_anchors = TrustAnchorsDoc {
            v: 1,
            version: 1,
            rp_id: rp_id.to_owned(),
            origin: origin.to_owned(),
            passkeys: vec![],
            recovery_key: recovery.doc(),
        };
        TrustAnchors::from_doc(&trust_anchors)
            .map_err(|e| SiteError::invalid(format!("building the trust anchor list: {e}")))?;
        let prefixes = MeshPrefixes {
            ipv4: MESH_IPV4.parse().expect("built-in prefix"),
            ipv6: random_ula()?,
        };
        write_file(path, RECOVERY_FILE, recovery.pkcs8(), true)?;
        let state = State::new(trust_anchors, prefixes);
        write_file(path, STATE_FILE, &to_json(&state)?, true)?;
        Ok(())
    }

    /// 打开站点目录并加锁：另一个修改命令正在运行时报错。
    pub fn open(path: &Path) -> Result<Self, SiteError> {
        if !path.join(STATE_FILE).exists() {
            return Err(SiteError::invalid(format!(
                "{} holds no site; `nett site init` creates one",
                path.display()
            )));
        }
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(path.join(LOCK_FILE))
            .map_err(|e| SiteError::io(format!("opening {}", path.join(LOCK_FILE).display()), e))?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
            |_| {
                SiteError::invalid(format!(
                    "another nett site command is changing {}; try again when it is done",
                    path.display()
                ))
            },
        )?;
        Ok(Self {
            path: path.to_owned(),
            _lock: lock,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<State, SiteError> {
        let path = self.path.join(STATE_FILE);
        let bytes = read_bounded(&path, MAX_DESIRED_BYTES)
            .map_err(|e| SiteError::io(format!("reading {}", path.display()), e))?
            .ok_or_else(|| SiteError::invalid(format!("{} does not exist", path.display())))?;
        State::from_json(&bytes)
    }

    pub fn save(&self, state: &State) -> Result<(), SiteError> {
        write_file(&self.path, STATE_FILE, &to_json(state)?, false)
    }

    /// 恢复密钥：只在签名时读取，用完即从内存中清除。
    pub fn recovery(&self) -> Result<RecoveryKeyPair, SiteError> {
        let path = self.path.join(RECOVERY_FILE);
        let pkcs8 = zeroize::Zeroizing::new(
            read_bounded(&path, 4096)
                .map_err(|e| SiteError::io(format!("reading {}", path.display()), e))?
                .ok_or_else(|| SiteError::invalid(format!("{} does not exist", path.display())))?,
        );
        RecoveryKeyPair::from_pkcs8(&pkcs8).map_err(SiteError::sign)
    }

    pub fn desired_path(&self, name: &NodeName) -> PathBuf {
        self.path
            .join(NODES_DIR)
            .join(name.to_string())
            .join(DESIRED_FILE)
    }

    /// 写一台机器的期望状态；内容与已有的相同时不写，返回 `false`。
    pub fn write_desired(&self, name: &NodeName, doc: &DesiredMeshDoc) -> Result<bool, SiteError> {
        let bytes =
            serde_json::to_vec_pretty(doc).map_err(|e| SiteError::invalid(e.to_string()))?;
        let path = self.desired_path(name);
        if read_bounded(&path, MAX_DESIRED_BYTES)
            .ok()
            .flatten()
            .as_deref()
            == Some(&bytes[..])
        {
            return Ok(false);
        }
        let dir = path.parent().expect("the path has a parent");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| SiteError::io(format!("creating {}", dir.display()), e))?;
        write_file(dir, DESIRED_FILE, &bytes, false)?;
        Ok(true)
    }

    /// 移除的机器不再有期望状态文件。
    pub fn remove_desired(&self, name: &NodeName) -> Result<(), SiteError> {
        let dir = self.path.join(NODES_DIR).join(name.to_string());
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(SiteError::io(format!("removing {}", dir.display()), e)),
        }
    }
}

fn to_json(state: &State) -> Result<Vec<u8>, SiteError> {
    let mut bytes =
        serde_json::to_vec_pretty(state).map_err(|e| SiteError::invalid(e.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// 先写临时文件、落盘，再改名；`new` 时目标已存在就报错。文件 `0600`。
fn write_file(dir: &Path, name: &str, bytes: &[u8], new: bool) -> Result<(), SiteError> {
    let target = dir.join(name);
    if new && target.exists() {
        return Err(SiteError::invalid(format!(
            "{} already exists",
            target.display()
        )));
    }
    let tmp = dir.join(format!(".{name}.tmp"));
    let io = |what: &str, e| SiteError::io(format!("{what} {}", tmp.display()), e);
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io("removing", e)),
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| io("creating", e))?;
    file.write_all(bytes).map_err(|e| io("writing", e))?;
    file.sync_all().map_err(|e| io("writing", e))?;
    drop(file);
    std::fs::rename(&tmp, &target)
        .map_err(|e| SiteError::io(format!("replacing {}", target.display()), e))
}

fn random_ula() -> Result<IpPrefix, SiteError> {
    use ring::rand::{SecureRandom as _, SystemRandom};
    let mut r = [0u8; 5];
    SystemRandom::new()
        .fill(&mut r)
        .map_err(|_| SiteError::invalid("the system random number generator failed"))?;
    let addr = Ipv6Addr::new(
        0xfd00 | u16::from(r[0]),
        u16::from_be_bytes([r[1], r[2]]),
        u16::from_be_bytes([r[3], r[4]]),
        0,
        0,
        0,
        0,
        0,
    );
    IpPrefix::new(addr.into(), 48).ok_or_else(|| SiteError::invalid("ULA prefix"))
}

/// 新机器的节点 ID：毫秒时间加 80 位随机数（ULID 的形式）。
pub fn new_node_id() -> Result<nett_core::id::NodeId, SiteError> {
    use ring::rand::{SecureRandom as _, SystemRandom};
    let mut r = [0u8; 10];
    SystemRandom::new()
        .fill(&mut r)
        .map_err(|_| SiteError::invalid("the system random number generator failed"))?;
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    Ok(nett_core::id::NodeId::from_parts(ms, r))
}
