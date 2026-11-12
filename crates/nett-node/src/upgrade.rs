//! Automatic upgrades (design/release.md section 7, ADR 0020): the Hub relays the release
//! manifest; nett-node downloads the program for its target, verifies it against the release
//! keys built into `nett`, installs only a higher version, restarts the mesh service and rolls
//! back when it does not come up. The replaced program is kept as `nett.previous`, the only
//! version a machine rolls back to. Nothing here trusts the Hub: the signature decides.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use nett_trust::release::{
    MAX_PROGRAM_BYTES, Manifest, Program, ReleaseKeys, Version, verify_program,
};
use serde::{Deserialize, Serialize};

/// How long the mesh service has to answer on its local interface after a restart.
pub const MESH_START: Duration = Duration::from_secs(60);
/// A new nett-node that starts this many times without connecting to the Hub (and without
/// running for `SETTLED`) is rolled back.
const MAX_STARTS: u32 = 3;
/// After running this long, a new nett-node counts as working even while the Hub is away.
pub const SETTLED: Duration = Duration::from_secs(5 * 60);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const SERVICE_TIMEOUT: Duration = Duration::from_secs(30);
/// Failed versions remembered so that they are not tried again.
const MAX_FAILED: usize = 16;

pub const STATE_FILE: &str = "upgrade.json";
pub const MARKER_FILE: &str = "upgrade-pending.json";

/// Restarting the mesh service and checking that it answers; the service manager on a real
/// machine, a double in tests.
pub trait Services: Send + Sync {
    fn restart_mesh(&self) -> Result<(), String>;
    fn mesh_answers(&self) -> bool;
}

/// The platform's service manager (design/release.md sections 4 and 5).
pub struct ServiceManager {
    /// The mesh process's local socket (design/status.md section 3).
    pub socket: PathBuf,
}

impl Services for ServiceManager {
    fn restart_mesh(&self) -> Result<(), String> {
        let ok = if cfg!(target_os = "macos") {
            let target = format!("system/{}", crate::platform::macos::MESH_LABEL);
            crate::platform::run(
                crate::platform::macos::LAUNCHCTL,
                &["kickstart", "-k", &target],
                SERVICE_TIMEOUT,
            )?
        } else {
            let systemctl = crate::platform::linux::systemctl()
                .ok_or_else(|| "systemctl is not on this machine".to_owned())?;
            crate::platform::run(
                systemctl,
                &["restart", crate::platform::linux::MESH_UNIT],
                SERVICE_TIMEOUT,
            )?
        };
        if ok {
            Ok(())
        } else {
            Err("the service manager could not restart the mesh service".into())
        }
    }

    fn mesh_answers(&self) -> bool {
        nett_mesh::status::query_raw(&self.socket).is_ok()
    }
}

/// What to do with a release manifest.
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    /// This version or a newer one is running.
    Current,
    /// The manifest has no program for this machine's target.
    NoProgram,
    /// This version failed before; it is not tried again.
    Failed(String),
    Upgrade {
        version: Version,
        program: Program,
    },
}

/// The result of a start-up check.
#[derive(Debug, PartialEq, Eq)]
pub enum Start {
    Continue,
    /// The new version kept exiting; the previous program is back and this process should exit
    /// so that the service manager starts it.
    RolledBack(String),
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    /// Version → why it was not installed or was rolled back.
    #[serde(default)]
    failed: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    version: String,
    previous: String,
    starts: u32,
}

pub struct Upgrader {
    pub keys: ReleaseKeys,
    pub target: String,
    pub current: Version,
    /// The program the services run.
    pub program: PathBuf,
    /// Another copy of the command to keep in step (macOS: the install script's copy).
    pub command: Option<PathBuf>,
    /// Where `upgrade.json` and the pending marker live (the configuration directory).
    pub dir: PathBuf,
    pub services: Arc<dyn Services>,
    /// How long the restarted mesh service has to answer ([`MESH_START`]).
    pub mesh_start: Duration,
}

impl Upgrader {
    /// Decides what a release manifest from the Hub means for this machine.
    pub fn plan(&self, manifest: &[u8]) -> Result<Plan, String> {
        let manifest = Manifest::parse(manifest).map_err(|e| e.to_string())?;
        let version = manifest.version().map_err(|e| e.to_string())?;
        if version <= self.current {
            return Ok(Plan::Current);
        }
        if let Some(reason) = self.state().failed.get(&manifest.version) {
            return Ok(Plan::Failed(reason.clone()));
        }
        Ok(match manifest.programs.get(&self.target) {
            Some(program) => Plan::Upgrade {
                version,
                program: program.clone(),
            },
            None => Plan::NoProgram,
        })
    }

    /// Downloads, verifies and installs `version`, then restarts the mesh service. On success the
    /// caller exits so that the service manager starts nett-node from the new program. A failure
    /// is recorded and not retried for this version.
    pub async fn upgrade(&self, version: Version, program: &Program) -> Result<(), String> {
        let result = self.try_upgrade(version, program).await;
        if let Err(reason) = &result {
            tracing::warn!(%version, %reason, "upgrade not installed");
            self.record_failure(version, reason);
        }
        result
    }

    async fn try_upgrade(&self, version: Version, program: &Program) -> Result<(), String> {
        tracing::info!(%version, url = %program.url, "downloading the new version");
        let bytes = crate::http::get(&program.url, MAX_PROGRAM_BYTES, DOWNLOAD_TIMEOUT)
            .await
            .map_err(|e| format!("downloading it: {e}"))?;
        verify_program(&self.keys, version, &self.target, program, &bytes)
            .map_err(|e| e.to_string())?;
        let this = self.clone_paths();
        let services = self.services.clone();
        let current = self.current;
        tokio::task::spawn_blocking(move || this.install(&bytes, version, current, &*services))
            .await
            .map_err(|e| e.to_string())?
    }

    /// The paths, for the blocking part.
    fn clone_paths(&self) -> Paths {
        Paths {
            program: self.program.clone(),
            command: self.command.clone(),
            dir: self.dir.clone(),
            mesh_start: self.mesh_start,
        }
    }

    /// At start: counts starts of a newly installed version and rolls it back when it keeps
    /// exiting before it settles.
    pub fn on_start(&self) -> Start {
        let paths = self.clone_paths();
        let Some(mut marker) = paths.marker() else {
            return Start::Continue;
        };
        if marker.version != self.current.to_string() {
            paths.clear_marker();
            return Start::Continue;
        }
        marker.starts += 1;
        if marker.starts <= MAX_STARTS {
            paths.write_marker(&marker).ok();
            return Start::Continue;
        }
        let reason = format!(
            "nett-node {} exited {MAX_STARTS} times before it settled; restored {}",
            marker.version, marker.previous
        );
        if let Err(e) = paths.restore() {
            tracing::error!(error = %e, "restoring the previous program");
            return Start::Continue;
        }
        self.services.restart_mesh().ok();
        if let Ok(version) = marker.version.parse() {
            self.record_failure(version, &reason);
        }
        paths.clear_marker();
        Start::RolledBack(reason)
    }

    /// The new version works: it connected to the Hub or ran long enough.
    pub fn settled(&self) {
        let paths = self.clone_paths();
        if paths
            .marker()
            .is_some_and(|m| m.version == self.current.to_string())
        {
            tracing::info!(version = %self.current, "upgrade complete");
            paths.clear_marker();
        }
    }

    fn state(&self) -> State {
        std::fs::read(self.dir.join(STATE_FILE))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn record_failure(&self, version: Version, reason: &str) {
        let mut state = self.state();
        state.failed.insert(version.to_string(), reason.to_owned());
        while state.failed.len() > MAX_FAILED {
            let Some(oldest) = state.failed.keys().next().cloned() else {
                break;
            };
            state.failed.remove(&oldest);
        }
        if let Ok(json) = serde_json::to_vec_pretty(&state)
            && let Err(e) = crate::config::write_private(&self.dir.join(STATE_FILE), &json)
        {
            tracing::warn!(error = %e, "recording the failed upgrade");
        }
    }
}

struct Paths {
    program: PathBuf,
    command: Option<PathBuf>,
    dir: PathBuf,
    mesh_start: Duration,
}

impl Paths {
    fn previous(&self) -> PathBuf {
        self.program.with_file_name("nett.previous")
    }

    /// Installs the verified program, restarts the mesh service and checks it; rolls back when
    /// it does not answer.
    fn install(
        &self,
        bytes: &[u8],
        version: Version,
        current: Version,
        services: &dyn Services,
    ) -> Result<(), String> {
        let new = self.program.with_file_name("nett.new");
        write_program(&new, bytes)?;
        if self.program.exists() {
            std::fs::rename(&self.program, self.previous())
                .map_err(|e| format!("keeping {}: {e}", self.program.display()))?;
        }
        std::fs::rename(&new, &self.program)
            .map_err(|e| format!("installing {}: {e}", self.program.display()))?;
        if let Some(command) = &self.command
            && let Err(e) = replace_command(command, bytes)
        {
            tracing::warn!(error = %e, "updating the command copy");
        }
        let started = services.restart_mesh().and_then(|()| {
            wait_for(|| services.mesh_answers(), self.mesh_start)
                .then_some(())
                .ok_or_else(|| "the mesh service did not answer".to_owned())
        });
        if let Err(reason) = started {
            self.restore()?;
            services.restart_mesh().ok();
            return Err(format!("{reason} with {version}; restored {current}"));
        }
        self.write_marker(&Marker {
            version: version.to_string(),
            previous: current.to_string(),
            starts: 0,
        })?;
        tracing::info!(%version, "installed; restarting nett-node");
        Ok(())
    }

    fn restore(&self) -> Result<(), String> {
        std::fs::rename(self.previous(), &self.program)
            .map_err(|e| format!("restoring {}: {e}", self.previous().display()))
    }

    fn marker(&self) -> Option<Marker> {
        std::fs::read(self.dir.join(MARKER_FILE))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
    }

    fn write_marker(&self, marker: &Marker) -> Result<(), String> {
        let json = serde_json::to_vec(marker).map_err(|e| e.to_string())?;
        crate::config::write_private(&self.dir.join(MARKER_FILE), &json)
    }

    fn clear_marker(&self) {
        std::fs::remove_file(self.dir.join(MARKER_FILE)).ok();
    }
}

fn wait_for(mut ok: impl FnMut() -> bool, within: Duration) -> bool {
    let deadline = std::time::Instant::now() + within;
    loop {
        if ok() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Writes an executable owned by the caller (root), mode `0755`, without following links.
fn write_program(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let io = |e: std::io::Error| format!("writing {}: {e}", path.display());
    std::fs::remove_file(path).ok();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(io)?;
    file.write_all(bytes).map_err(io)?;
    file.sync_all().map_err(io)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).map_err(io)
}

/// Replaces the command copy when it is a regular file owned by root in a directory owned by
/// root: a copy in a directory the user can write (Homebrew) is the user's to upgrade.
fn replace_command(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Ok(());
    };
    let dir = path.parent().ok_or("no directory")?;
    let dir_meta = std::fs::metadata(dir).map_err(|e| e.to_string())?;
    if !meta.file_type().is_file()
        || meta.uid() != 0
        || dir_meta.uid() != 0
        || dir_meta.mode() & 0o022 != 0
    {
        return Ok(());
    }
    let new = path.with_file_name(".nett.new");
    write_program(&new, bytes)?;
    std::fs::rename(&new, path).map_err(|e| format!("replacing {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};

    use super::*;

    struct FakeServices {
        restarts: AtomicUsize,
        healthy: AtomicBool,
        /// What the program file held at each restart.
        seen: Mutex<Vec<Vec<u8>>>,
        program: PathBuf,
    }

    impl Services for FakeServices {
        fn restart_mesh(&self) -> Result<(), String> {
            self.restarts.fetch_add(1, Ordering::SeqCst);
            self.seen
                .lock()
                .expect("lock")
                .push(std::fs::read(&self.program).unwrap_or_default());
            Ok(())
        }
        fn mesh_answers(&self) -> bool {
            self.healthy.load(Ordering::SeqCst)
        }
    }

    /// A directory removed with everything in it when the returned guard is dropped; keep the
    /// guard for as long as the path is used.
    fn temp(name: &str) -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::Builder::new()
            .prefix(&format!("nett-upgrade-{name}-"))
            .tempdir()
            .expect("temp dir");
        let dir = tmp.path().to_path_buf();
        (tmp, dir)
    }

    /// A release key and a manifest for `version` whose program is `bytes`.
    fn release(version: &str, target: &str, bytes: &[u8]) -> (ReleaseKeys, Vec<u8>) {
        use blake2::digest::Digest as _;
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("key");
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("key");
        let id = [7u8; 8];
        let mut public = b"Ed".to_vec();
        public.extend_from_slice(&id);
        public.extend_from_slice(pair.public_key().as_ref());
        let keys = ReleaseKeys::parse(&STANDARD.encode(public)).expect("keys");
        let comment = format!("nett v{version} nett-{version}-{target}");
        let signature = pair.sign(blake2::Blake2b512::digest(bytes).as_slice());
        let mut sig = b"ED".to_vec();
        sig.extend_from_slice(&id);
        sig.extend_from_slice(signature.as_ref());
        let mut global = signature.as_ref().to_vec();
        global.extend_from_slice(comment.as_bytes());
        let minisig = format!(
            "untrusted comment: t\n{}\ntrusted comment: {comment}\n{}\n",
            STANDARD.encode(sig),
            STANDARD.encode(pair.sign(&global).as_ref())
        );
        let sha256: String = ring::digest::digest(&ring::digest::SHA256, bytes)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let manifest = serde_json::json!({
            "version": version,
            "programs": { target: {
                "url": format!("https://nett.example.com/dl/nett-{version}-{target}"),
                "sha256": sha256,
                "minisig": minisig,
            }}
        });
        (keys, manifest.to_string().into_bytes())
    }

    fn upgrader(dir: &Path, keys: ReleaseKeys, healthy: bool) -> (Upgrader, Arc<FakeServices>) {
        let program = dir.join("nett");
        std::fs::write(&program, b"old program").expect("write");
        let services = Arc::new(FakeServices {
            restarts: AtomicUsize::new(0),
            healthy: AtomicBool::new(healthy),
            seen: Mutex::new(Vec::new()),
            program: program.clone(),
        });
        (
            Upgrader {
                keys,
                target: "x86_64-unknown-linux-musl".into(),
                current: "0.1.5".parse().expect("version"),
                program,
                command: None,
                dir: dir.to_path_buf(),
                services: services.clone(),
                mesh_start: Duration::from_millis(600),
            },
            services,
        )
    }

    #[test]
    fn only_higher_versions_for_this_target_are_planned() {
        let (_dir_tmp, dir) = temp("plan");
        let (keys, manifest) = release("0.2.0", "x86_64-unknown-linux-musl", b"new");
        let (up, _) = upgrader(&dir, keys.clone(), true);
        assert!(matches!(up.plan(&manifest), Ok(Plan::Upgrade { .. })));
        let (_, same) = release("0.1.5", "x86_64-unknown-linux-musl", b"new");
        assert_eq!(up.plan(&same), Ok(Plan::Current));
        let (_, older) = release("0.1.4", "x86_64-unknown-linux-musl", b"new");
        assert_eq!(up.plan(&older), Ok(Plan::Current));
        let (_, other) = release("0.2.0", "aarch64-apple-darwin", b"new");
        assert_eq!(up.plan(&other), Ok(Plan::NoProgram));
        assert!(up.plan(b"{not json").is_err());
        up.record_failure("0.2.0".parse().expect("v"), "it broke");
        assert_eq!(up.plan(&manifest), Ok(Plan::Failed("it broke".into())));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_verified_program_is_installed_and_the_old_one_kept() {
        let (_dir_tmp, dir) = temp("install");
        let (keys, _) = release("0.2.0", "x86_64-unknown-linux-musl", b"new program");
        let (up, services) = upgrader(&dir, keys, true);
        up.clone_paths()
            .install(
                b"new program",
                "0.2.0".parse().expect("v"),
                up.current,
                &*services,
            )
            .expect("installed");
        assert_eq!(std::fs::read(&up.program).expect("program"), b"new program");
        assert_eq!(
            std::fs::read(dir.join("nett.previous")).expect("previous"),
            b"old program"
        );
        assert_eq!(
            *services.seen.lock().expect("lock"),
            vec![b"new program".to_vec()],
            "the mesh restarted on the new program"
        );
        assert!(up.clone_paths().marker().is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_mesh_that_does_not_come_up_is_rolled_back() {
        let (_dir_tmp, dir) = temp("rollback");
        let (keys, _) = release("0.2.0", "x86_64-unknown-linux-musl", b"bad program");
        let (up, services) = upgrader(&dir, keys, false);
        let paths = up.clone_paths();
        let err = paths
            .install(
                b"bad program",
                "0.2.0".parse().expect("v"),
                up.current,
                &*services,
            )
            .expect_err("rolled back");
        assert!(err.contains("restored 0.1.5"), "{err}");
        assert_eq!(std::fs::read(&up.program).expect("program"), b"old program");
        assert_eq!(services.restarts.load(Ordering::SeqCst), 2);
        assert!(paths.marker().is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_new_node_that_keeps_exiting_is_rolled_back() {
        let (_dir_tmp, dir) = temp("starts");
        let (keys, _) = release("0.2.0", "x86_64-unknown-linux-musl", b"x");
        let (mut up, services) = upgrader(&dir, keys, true);
        // as installed: the new program in place, the old one kept, the marker written
        std::fs::write(dir.join("nett.previous"), b"old program").expect("previous");
        std::fs::write(&up.program, b"new program").expect("program");
        up.current = "0.2.0".parse().expect("v");
        up.clone_paths()
            .write_marker(&Marker {
                version: "0.2.0".into(),
                previous: "0.1.5".into(),
                starts: 0,
            })
            .expect("marker");
        for _ in 0..MAX_STARTS {
            assert_eq!(up.on_start(), Start::Continue);
        }
        assert!(matches!(up.on_start(), Start::RolledBack(_)));
        assert_eq!(std::fs::read(&up.program).expect("program"), b"old program");
        assert_eq!(services.restarts.load(Ordering::SeqCst), 1);
        // the failed version is not offered again
        up.current = "0.1.5".parse().expect("v");
        let (_, manifest) = release("0.2.0", "x86_64-unknown-linux-musl", b"x");
        assert!(matches!(up.plan(&manifest), Ok(Plan::Failed(_))));

        // a version that settles clears its marker
        up.clone_paths()
            .write_marker(&Marker {
                version: "0.1.5".into(),
                previous: "0.1.4".into(),
                starts: 1,
            })
            .expect("marker");
        up.settled();
        assert!(up.clone_paths().marker().is_none());
        assert_eq!(up.on_start(), Start::Continue);
        std::fs::remove_dir_all(&dir).ok();
    }
}
