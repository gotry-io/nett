//! Site directory (design/site.md section 8): the recovery key `recovery.pk8`, the site state
//! `state.json`, and, without a Hub, each machine's desired state `nodes/<machine>/desired.json`.
//! The directory is `0700` and files are `0600`, written to a temporary file first and then
//! renamed; only one modifying command runs at a time.

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
/// How long a command waits for the site directory's lock.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(2);
/// IPv4 prefix of the mesh (design/mesh.md section 3).
const MESH_IPV4: &str = "100.88.0.0/16";

/// An open site directory: holds its lock.
pub struct SiteDir {
    path: PathBuf,
    _lock: File,
}

impl SiteDir {
    /// Creates a site: the recovery key, a trust anchor list containing only it, and the mesh
    /// prefixes (the IPv6 one is a random ULA `/48`).
    pub fn init(path: &Path, origin: &str) -> Result<(), SiteError> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(|e| SiteError::io(format!("creating {}", path.display()), e))?;
        // Tightened even if the directory already exists: it holds the recovery key
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

    /// Opens the site directory and locks it: an error when another modifying command is running.
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
        // The lock can be held for a moment by something that is not another command (a child
        // process that inherited it before exec), so wait briefly before reporting a conflict
        let deadline = std::time::Instant::now() + LOCK_WAIT;
        loop {
            match rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => break,
                Err(rustix::io::Errno::WOULDBLOCK) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(rustix::io::Errno::WOULDBLOCK) => {
                    return Err(SiteError::invalid(format!(
                        "another nett site command is changing {}; try again when it is done",
                        path.display()
                    )));
                }
                Err(e) => {
                    return Err(SiteError::io(
                        format!("locking {}", path.join(LOCK_FILE).display()),
                        e.into(),
                    ));
                }
            }
        }
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

    /// Recovery key: read only when signing, cleared from memory right after use.
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

    /// Writes a machine's desired state; does not write when the content equals the existing one
    /// and returns `false`.
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

    /// Removed machines no longer have a desired state file.
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

/// Writes a temporary file and syncs it to disk, then renames; with `new`, an error if the target
/// already exists. File `0600`.
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

/// A new relay key for the site (design/site.md section 4.1).
pub fn new_relay_key() -> Result<crate::state::RelayKey, SiteError> {
    use ring::rand::{SecureRandom as _, SystemRandom};
    let mut key = [0u8; 32];
    SystemRandom::new()
        .fill(&mut key)
        .map_err(|_| SiteError::invalid("the system random number generator failed"))?;
    Ok(crate::state::RelayKey(key))
}

/// Node ID of a new machine: millisecond time plus 80 random bits (ULID form).
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
