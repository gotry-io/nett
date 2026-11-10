//! 本机的信任存储（design/mesh.md 第 4.2 节）：固定的节点 ID 与信任锚、撤销记录、各签名产物已生效的
//! 版本与哈希，以及最近一次整份接受的期望状态。验证以它为基准，期望状态文件只是输入：改写文件、重启
//! 进程，都不能换掉信任锚，也不能让旧版本的产物或被撤销的成员重新生效。

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use nett_core::id::NodeId;
use nett_trust::admission::AppliedRecord;
use nett_trust::anchors::TrustAnchorsDoc;
use nett_trust::encoding::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::config::{DesiredMeshDoc, MAX_DESIRED_BYTES, read_bounded};

/// 信任存储的默认位置（design/mesh.md 第 4.2 节）。Linux 上由 systemd 单元的 `StateDirectory` 建立；
/// macOS 上在 `sudo nett install` 建立的 root 专属目录中。容器镜像用 `--state` 放进挂载目录。
#[cfg(target_os = "macos")]
pub const DEFAULT_STATE_DIR: &str = "/Library/Application Support/nett/state";
#[cfg(not(target_os = "macos"))]
pub const DEFAULT_STATE_DIR: &str = "/var/lib/nett";

pub const TRUST_FILE: &str = "trust.json";
pub const ACCEPTED_FILE: &str = "accepted.json";
const FORMAT_V1: u32 = 1;

/// 保存的内容。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saved {
    pub v: u32,
    pub node_id: NodeId,
    pub trust_anchors: TrustAnchorsDoc,
    #[serde(default)]
    pub revoked: BTreeSet<NodeId>,
    #[serde(default)]
    pub members: BTreeMap<NodeId, AppliedRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_rules: Option<VersionRecord>,
    #[serde(default)]
    pub routes: BTreeMap<NodeId, VersionRecord>,
}

impl Saved {
    pub fn new(node_id: NodeId, trust_anchors: TrustAnchorsDoc) -> Self {
        Self {
            v: FORMAT_V1,
            node_id,
            trust_anchors,
            revoked: BTreeSet::new(),
            members: BTreeMap::new(),
            access_rules: None,
            routes: BTreeMap::new(),
        }
    }
}

/// 一份带版本号的签名产物已生效的版本与哈希。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionRecord {
    pub version: u64,
    pub hash: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FloorError {
    #[error("version {offered} is older than version {accepted}, which this node already accepted")]
    Older { offered: u64, accepted: u64 },
    #[error("version {0} differs from the version {0} this node already accepted")]
    Conflict(u64),
}

impl VersionRecord {
    /// 一份产物与本机接受过的这一份相比：版本更高，或版本与内容都相同，才可以生效。
    pub fn admits(&self, version: u64, hash: &Sha256Digest) -> Result<(), FloorError> {
        if version > self.version || (version == self.version && *hash == self.hash) {
            Ok(())
        } else if version < self.version {
            Err(FloorError::Older {
                offered: version,
                accepted: self.version,
            })
        } else {
            Err(FloorError::Conflict(version))
        }
    }
}

/// 信任存储放在哪里：本机目录（[`DirBackend`]），或内存（[`MemoryBackend`]，测试与实验中用）。
pub trait Backend: Send {
    /// 读一个文件；不存在时为 `Ok(None)`。
    fn read(&mut self, name: &str) -> std::io::Result<Option<Vec<u8>>>;
    /// 整个替换一个文件：中途失败时原来的内容不变。
    fn write(&mut self, name: &str, bytes: &[u8]) -> std::io::Result<()>;
    /// 把读不懂的文件挪到 `<name>.bad`，留给人查看。
    fn quarantine(&mut self, name: &str) -> std::io::Result<()>;
}

/// 本机目录：目录 `0700`，文件 `0600`，先写临时文件、落盘，再改名。
pub struct DirBackend {
    dir: PathBuf,
}

impl DirBackend {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }
}

impl Backend for DirBackend {
    fn read(&mut self, name: &str) -> std::io::Result<Option<Vec<u8>>> {
        read_bounded(&self.dir.join(name), MAX_DESIRED_BYTES)
    }

    fn write(&mut self, name: &str, bytes: &[u8]) -> std::io::Result<()> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)?;
        let tmp = self.dir.join(format!(".{name}.tmp"));
        // 临时文件名固定：只有组网进程写这个目录，不跟随符号链接
        match std::fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, self.dir.join(name))?;
        std::fs::File::open(&self.dir)?.sync_all()
    }

    fn quarantine(&mut self, name: &str) -> std::io::Result<()> {
        std::fs::rename(self.dir.join(name), self.dir.join(format!("{name}.bad")))
    }
}

/// 内存中的信任存储。克隆共享同一份内容，测试据此模拟重启；`fail_writes` 模拟磁盘写不进。
#[derive(Debug, Clone, Default)]
pub struct MemoryBackend {
    files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    fail_writes: Arc<Mutex<bool>>,
}

impl MemoryBackend {
    pub fn set_fail_writes(&self, fail: bool) {
        *self.fail_writes.lock().expect("lock is never poisoned") = fail;
    }

    pub fn put(&self, name: &str, bytes: Vec<u8>) {
        self.files
            .lock()
            .expect("lock is never poisoned")
            .insert(name.to_owned(), bytes);
    }

    pub fn get(&self, name: &str) -> Option<Vec<u8>> {
        self.files
            .lock()
            .expect("lock is never poisoned")
            .get(name)
            .cloned()
    }
}

impl Backend for MemoryBackend {
    fn read(&mut self, name: &str) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self.get(name))
    }

    fn write(&mut self, name: &str, bytes: &[u8]) -> std::io::Result<()> {
        if *self.fail_writes.lock().expect("lock is never poisoned") {
            return Err(std::io::Error::other("simulated write failure"));
        }
        self.put(name, bytes.to_vec());
        Ok(())
    }

    fn quarantine(&mut self, name: &str) -> std::io::Result<()> {
        let mut files = self.files.lock().expect("lock is never poisoned");
        if let Some(bytes) = files.remove(name) {
            files.insert(format!("{name}.bad"), bytes);
        }
        Ok(())
    }
}

/// 信任存储：打开时读出保存的内容，每次整份接受期望状态之后写入。
pub struct TrustStore {
    backend: Box<dyn Backend>,
    saved: Option<Saved>,
    /// 最近一次写入的期望状态的哈希：期望状态中不签名的部分（路径、节点名）变了也要重写。
    accepted_hash: Option<Sha256Digest>,
    /// 上一次写入失败：内容即使没变也要重写。
    dirty: bool,
    /// 打开时遇到的问题。这时还没有事件出口，在第一次应用期望状态时报告。
    problem: Option<String>,
}

impl TrustStore {
    pub fn open(mut backend: Box<dyn Backend>) -> Self {
        let mut problem = None;
        let saved = match backend.read(TRUST_FILE) {
            Ok(None) => None,
            Ok(Some(bytes)) => match parse(&bytes) {
                Ok(saved) => Some(saved),
                Err(e) => {
                    problem = Some(match backend.quarantine(TRUST_FILE) {
                        Ok(()) => format!(
                            "the trust store was damaged ({e}); kept it as {TRUST_FILE}.bad and \
                             rebuilt it from the desired state"
                        ),
                        Err(q) => format!(
                            "the trust store was damaged ({e}) and could not be moved aside ({q}); \
                             rebuilt it from the desired state"
                        ),
                    });
                    None
                }
            },
            Err(e) => {
                problem = Some(format!(
                    "reading the trust store: {e}; using the desired state as the baseline"
                ));
                None
            }
        };
        Self {
            backend,
            saved,
            accepted_hash: None,
            dirty: false,
            problem,
        }
    }

    /// 只在内存中、不落盘的信任存储。
    pub fn in_memory() -> Self {
        Self::open(Box::new(MemoryBackend::default()))
    }

    pub fn saved(&self) -> Option<&Saved> {
        self.saved.as_ref()
    }

    pub fn node_id(&self) -> Option<&NodeId> {
        self.saved.as_ref().map(|s| &s.node_id)
    }

    pub fn take_problem(&mut self) -> Option<String> {
        self.problem.take()
    }

    /// 最近一次整份接受的期望状态。
    pub fn accepted(&mut self) -> Result<Option<DesiredMeshDoc>, String> {
        let Some(bytes) = self
            .backend
            .read(ACCEPTED_FILE)
            .map_err(|e| format!("reading {ACCEPTED_FILE}: {e}"))?
        else {
            return Ok(None);
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| format!("parsing {ACCEPTED_FILE}: {e}"))
    }

    /// 记下新的内容和这份整份接受的期望状态。内存中的基准总是更新；写不进磁盘时返回原因，下一次重试。
    /// 先写期望状态再写版本记录：两者之间中断时，保存的期望状态不会落后于版本记录。
    pub fn save(&mut self, saved: Saved, accepted: &DesiredMeshDoc) -> Result<(), String> {
        let accepted = serde_json::to_vec(accepted).map_err(|e| e.to_string())?;
        let hash = Sha256Digest::of(&accepted);
        if !self.dirty && self.saved.as_ref() == Some(&saved) && self.accepted_hash == Some(hash) {
            return Ok(());
        }
        self.saved = Some(saved);
        let result = self.write(&accepted);
        self.dirty = result.is_err();
        if result.is_ok() {
            self.accepted_hash = Some(hash);
        }
        result
    }

    fn write(&mut self, accepted: &[u8]) -> Result<(), String> {
        let saved = self.saved.as_ref().expect("set by the caller");
        let trust = serde_json::to_vec_pretty(saved).map_err(|e| e.to_string())?;
        for (name, bytes) in [(ACCEPTED_FILE, accepted), (TRUST_FILE, trust.as_slice())] {
            if bytes.len() as u64 > MAX_DESIRED_BYTES {
                return Err(format!(
                    "{name} would be larger than {MAX_DESIRED_BYTES} bytes"
                ));
            }
            self.backend
                .write(name, bytes)
                .map_err(|e| format!("writing {name}: {e}"))?;
        }
        Ok(())
    }
}

fn parse(bytes: &[u8]) -> Result<Saved, String> {
    let saved: Saved = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if saved.v != FORMAT_V1 {
        return Err(format!("unsupported format version {}", saved.v));
    }
    Ok(saved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Mesh, node_id};

    fn saved() -> Saved {
        let mesh = Mesh::new(&[1]);
        Saved::new(node_id(1), mesh.desired(1, vec![]).trust_anchors)
    }

    #[test]
    fn version_records_admit_only_newer_or_identical_artifacts() {
        let r = VersionRecord {
            version: 3,
            hash: Sha256Digest::of(b"three"),
        };
        assert_eq!(r.admits(4, &Sha256Digest::of(b"four")), Ok(()));
        assert_eq!(r.admits(3, &Sha256Digest::of(b"three")), Ok(()));
        assert_eq!(
            r.admits(2, &Sha256Digest::of(b"two")),
            Err(FloorError::Older {
                offered: 2,
                accepted: 3
            })
        );
        assert_eq!(
            r.admits(3, &Sha256Digest::of(b"other")),
            Err(FloorError::Conflict(3))
        );
    }

    #[test]
    fn saved_content_survives_reopening() {
        let backend = MemoryBackend::default();
        let mut store = TrustStore::open(Box::new(backend.clone()));
        assert!(store.saved().is_none());
        let mesh = Mesh::new(&[1]);
        store
            .save(saved(), &mesh.desired(1, vec![]))
            .expect("saved");
        let mut reopened = TrustStore::open(Box::new(backend));
        assert_eq!(reopened.node_id(), Some(&node_id(1)));
        assert!(reopened.take_problem().is_none());
        assert_eq!(
            reopened.accepted().expect("readable").map(|d| d.node_id),
            Some(node_id(1))
        );
    }

    #[test]
    fn a_changed_desired_state_is_saved_even_when_the_versions_are_the_same() {
        let backend = MemoryBackend::default();
        let mut store = TrustStore::open(Box::new(backend.clone()));
        let mesh = Mesh::new(&[1, 2]);
        let mut doc = mesh.desired(1, vec![]);
        store.save(saved(), &doc).expect("saved");
        // 只改了不签名的部分（节点名）
        doc.names.clear();
        store.save(saved(), &doc).expect("saved");
        let stored: DesiredMeshDoc =
            serde_json::from_slice(&backend.get(ACCEPTED_FILE).expect("written")).expect("json");
        assert!(stored.names.is_empty());
    }

    #[test]
    fn a_damaged_store_is_moved_aside_and_reported() {
        let backend = MemoryBackend::default();
        backend.put(TRUST_FILE, b"{not json".to_vec());
        let mut store = TrustStore::open(Box::new(backend.clone()));
        assert!(store.saved().is_none());
        assert!(store.take_problem().is_some_and(|p| p.contains("damaged")));
        assert!(backend.get(TRUST_FILE).is_none());
        assert_eq!(backend.get("trust.json.bad"), Some(b"{not json".to_vec()));
    }

    #[test]
    fn a_failed_write_is_retried_even_without_changes() {
        let backend = MemoryBackend::default();
        let mut store = TrustStore::open(Box::new(backend.clone()));
        let mesh = Mesh::new(&[1]);
        let doc = mesh.desired(1, vec![]);
        backend.set_fail_writes(true);
        assert!(store.save(saved(), &doc).is_err());
        // 内存中的基准照样更新
        assert_eq!(store.node_id(), Some(&node_id(1)));
        backend.set_fail_writes(false);
        store.save(saved(), &doc).expect("retried");
        assert!(backend.get(TRUST_FILE).is_some());
    }

    #[test]
    fn the_directory_backend_writes_private_files() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("nett-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut backend = DirBackend::new(dir.join("state"));
        assert_eq!(backend.read(TRUST_FILE).expect("readable"), None);
        backend.write(TRUST_FILE, b"{}").expect("written");
        let mode = |p: PathBuf| std::fs::metadata(p).expect("exists").permissions().mode() & 0o777;
        assert_eq!(mode(dir.join("state")), 0o700);
        assert_eq!(mode(dir.join("state").join(TRUST_FILE)), 0o600);
        assert_eq!(
            backend.read(TRUST_FILE).expect("readable"),
            Some(b"{}".to_vec())
        );
        backend.quarantine(TRUST_FILE).expect("moved");
        assert!(dir.join("state").join("trust.json.bad").exists());
        std::fs::remove_dir_all(&dir).expect("cleaned up");
    }
}
