//! This machine's trust store (design/mesh.md section 4.2): the pinned node ID and trust anchors,
//! revocations, the version and hash in effect for each signed artifact, and the desired state most
//! recently accepted as a whole. Verification takes it as the baseline and the desired state file is only
//! input: rewriting the file or restarting the process cannot replace the trust anchors, nor make an
//! artifact of an older version or a revoked member take effect again.

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

/// Default location of the trust store (design/mesh.md section 4.2). On Linux it is created by the
/// systemd unit's `StateDirectory`; on macOS it is in the root-only directory created by
/// `sudo nett install`. Container images put it in a mounted directory with `--state`.
#[cfg(target_os = "macos")]
pub const DEFAULT_STATE_DIR: &str = "/Library/Application Support/nett/state";
#[cfg(not(target_os = "macos"))]
pub const DEFAULT_STATE_DIR: &str = "/var/lib/nett";

pub const TRUST_FILE: &str = "trust.json";
pub const ACCEPTED_FILE: &str = "accepted.json";
const FORMAT_V1: u32 = 1;

/// The saved content.
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

/// The version and hash in effect for a versioned signed artifact.
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
    /// An artifact compared with the one this machine has accepted: it may take effect only if the version is
    /// higher, or both version and content are identical.
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

/// Where the trust store lives: a local directory ([`DirBackend`]), or memory ([`MemoryBackend`], used in
/// tests and lab scenarios).
pub trait Backend: Send {
    /// Reads a file; `Ok(None)` when it does not exist.
    fn read(&mut self, name: &str) -> std::io::Result<Option<Vec<u8>>>;
    /// Replaces a whole file: if it fails midway the original content is unchanged.
    fn write(&mut self, name: &str, bytes: &[u8]) -> std::io::Result<()>;
    /// Moves an unreadable file to `<name>.bad` for a person to inspect.
    fn quarantine(&mut self, name: &str) -> std::io::Result<()>;
}

/// Local directory: directory `0700`, files `0600`; writes a temporary file first, syncs to disk, then
/// renames.
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
        // The temporary file name is fixed: only the mesh process writes this directory, and symlinks are not
        // followed
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

/// In-memory trust store. Clones share the same content, which tests use to simulate a restart;
/// `fail_writes` simulates a disk that cannot be written.
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

/// Trust store: reads the saved content when opened, and writes after every whole desired state accepted.
pub struct TrustStore {
    backend: Box<dyn Backend>,
    saved: Option<Saved>,
    /// Hash of the desired state most recently written: it must be rewritten when the unsigned parts of the
    /// desired state (paths, node names) change too.
    accepted_hash: Option<Sha256Digest>,
    /// The previous write failed: rewrite even if the content has not changed.
    dirty: bool,
    /// Problems met when opening. There is no event sink yet at that point; reported when the first desired
    /// state is applied.
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

    /// A trust store that is only in memory and not written to disk.
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

    /// The desired state most recently accepted as a whole.
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

    /// Records the new content and this whole accepted desired state. The in-memory baseline is always
    /// updated; when it cannot be written to disk the reason is returned and it is retried next time.
    /// The desired state is written before the version record: if interrupted between the two, the saved
    /// desired state is never behind the version record.
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
        // Only the unsigned part (node names) changed
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
        // The in-memory baseline is updated all the same
        assert_eq!(store.node_id(), Some(&node_id(1)));
        backend.set_fail_writes(false);
        store.save(saved(), &doc).expect("retried");
        assert!(backend.get(TRUST_FILE).is_some());
    }

    #[test]
    fn the_directory_backend_writes_private_files() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir_tmp = tempfile::Builder::new()
            .prefix("nett-store-")
            .tempdir()
            .expect("temp dir");
        let dir = dir_tmp.path().join("dir");
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
