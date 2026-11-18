//! Automatic upgrades (design/release.md section 7, ADR 0020, ADR 0025): the Hub relays the
//! release manifest; nett-node fetches the program for its target from the Hub, or from the URL in
//! the manifest, verifies it against the release keys built into `nett`, installs only a higher
//! version, restarts the mesh service and rolls back when it does not come up. The replaced program
//! is kept as `nett.previous`, the only version a machine rolls back to. Nothing here trusts the
//! Hub: the signature decides.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use nett_trust::release::{
    Manifest, Program, ReleaseError, ReleaseKeys, Version, verify_program_digests,
};
use serde::{Deserialize, Serialize};

use crate::fetch::{FetchError, HubLink, ProgramFile};

/// How long the mesh service has to answer on its local interface after a restart.
pub const MESH_START: Duration = Duration::from_secs(60);
/// A new nett-node that starts this many times without connecting to the Hub (and without
/// running for `SETTLED`) is rolled back.
const MAX_STARTS: u32 = 3;
/// After running this long, a new nett-node counts as working even while the Hub is away.
pub const SETTLED: Duration = Duration::from_secs(5 * 60);
/// After the program of a release could not be fetched, it is fetched again after this long, then
/// after twice as long each time up to [`RETRY_MAX`] (design/release.md section 7).
const RETRY_FIRST: Duration = Duration::from_secs(60);
const RETRY_MAX: Duration = Duration::from_secs(60 * 60);
const SERVICE_TIMEOUT: Duration = Duration::from_secs(30);
/// Failed versions remembered so that they are not tried again.
const MAX_FAILED: usize = 16;

pub const STATE_FILE: &str = "upgrade.json";
pub const MARKER_FILE: &str = "upgrade-pending.json";

/// Restarting the services that run this program and checking that the mesh process answers; the
/// service manager on a real machine, a double in tests (design/release.md section 7).
pub trait Services: Send + Sync {
    fn restart_mesh(&self) -> Result<(), String>;
    fn mesh_answers(&self) -> bool;
    /// nett-relay and the transport adapter, when they run: they move to the new program once it
    /// has settled.
    fn restart_helpers(&self);
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

    fn restart_helpers(&self) {
        // macOS runs neither helper
        let Some(systemctl) =
            crate::platform::linux::systemctl().filter(|_| cfg!(target_os = "linux"))
        else {
            return;
        };
        // They run the same program and, unrestarted, keep the old one until the machine reboots;
        // try-restart leaves helpers that are not running alone. Only installed units are named:
        // systemctl fails on one that does not exist
        let units: Vec<&str> = crate::platform::linux::installed_optional()
            .iter()
            .map(|u| u.name)
            .collect();
        if !units.is_empty() {
            let mut args = vec!["try-restart"];
            args.extend(&units);
            if !crate::platform::run(systemctl, &args, SERVICE_TIMEOUT).unwrap_or(false) {
                tracing::warn!(
                    ?units,
                    "restarting the helper services on the new program failed"
                );
            }
        }
        // What the layout of 0.3.13 left goes in the privileged start step of nett-node's unit,
        // which runs once the upgrade has settled (design/release.md section 8)
        #[cfg(target_os = "linux")]
        if crate::layout::old_remains(&crate::layout::Layout::system()) {
            tracing::info!("restarting nett-node to remove what nett 0.3.13 left");
            let args = ["--no-block", "restart", crate::platform::linux::NODE_UNIT];
            if !crate::platform::run(systemctl, &args, SERVICE_TIMEOUT).unwrap_or(false) {
                tracing::warn!("restarting nett-node to tidy up failed");
            }
        }
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

    /// Fetches, verifies and installs `version`, then restarts the mesh service. On success the
    /// caller exits so that the service manager starts nett-node from the new program. A program
    /// that could not be fetched is fetched again later, and `progress` says why it is still
    /// waiting; a program that fails verification from every source, or fails to install or to
    /// start, is recorded and not tried again for this version.
    pub async fn upgrade(
        &self,
        version: Version,
        program: &Program,
        link: Option<&HubLink>,
        progress: &tokio::sync::watch::Sender<Progress>,
    ) -> Result<(), String> {
        let mut wait = RETRY_FIRST;
        loop {
            match self.fetch(version, program, link).await {
                Fetched::Verified => break,
                Fetched::Unavailable(reason) => {
                    let reason = format!(
                        "not fetched yet ({reason}); trying again in {} min",
                        wait.as_secs() / 60
                    );
                    tracing::warn!(%version, %reason, "fetching the new version");
                    progress.send_replace(Progress::Waiting(reason));
                    tokio::time::sleep(wait).await;
                    wait = (wait * 2).min(RETRY_MAX);
                }
                Fetched::Rejected(reason) => return Err(self.failed(version, reason)),
            }
        }
        // From here the upgrade finishes even when a newer release arrives: the install runs on its
        // own thread and replaces files
        progress.send_replace(Progress::Installing);
        let this = self.clone_paths();
        let services = self.services.clone();
        let current = self.current;
        tokio::task::spawn_blocking(move || this.install(version, current, &*services))
            .await
            .map_err(|e| e.to_string())
            .and_then(|installed| installed)
            .map_err(|reason| self.failed(version, reason))
    }

    fn failed(&self, version: Version, reason: String) -> String {
        tracing::warn!(%version, %reason, "upgrade not installed");
        self.record_failure(version, &reason);
        reason
    }

    /// Fetches the program into `nett.new` next to the installed one, from the Hub and then from its
    /// URL, until one source delivers a program that verifies.
    async fn fetch(&self, version: Version, program: &Program, link: Option<&HubLink>) -> Fetched {
        let path = self.program.with_file_name("nett.new");
        let mut unavailable = Vec::new();
        let mut rejected = Vec::new();
        for from_hub in [true, false] {
            if from_hub && link.is_none() {
                continue;
            }
            let source = if from_hub { "the Hub" } else { "its URL" };
            let mut file = match ProgramFile::create(&path) {
                Ok(file) => file,
                Err(e) => {
                    unavailable.push(e);
                    continue;
                }
            };
            let fetched = match link.filter(|_| from_hub) {
                Some(link) => {
                    crate::fetch::from_hub(link, &version.to_string(), &self.target, &mut file)
                        .await
                }
                None => crate::fetch::from_url(&program.url, &mut file).await,
            };
            let received = file.len();
            let digests = match fetched.map(|()| file.finish()) {
                Ok(Ok(digests)) => digests,
                Ok(Err(e)) => {
                    unavailable.push(e);
                    continue;
                }
                // The Hub holds the program and was sending it: it is fetched from the Hub again
                // once the session is back, rather than over the website's path
                Err(FetchError::Unavailable(e)) if from_hub && received > 0 => {
                    unavailable.push(e);
                    break;
                }
                Err(FetchError::Unavailable(e)) => {
                    unavailable.push(e);
                    continue;
                }
                Err(FetchError::Refused(e)) => {
                    rejected.push(e);
                    continue;
                }
            };
            match verify_program_digests(&self.keys, version, &self.target, program, &digests) {
                Ok(()) => {
                    tracing::info!(%version, from = source, "fetched and verified the new version");
                    return Fetched::Verified;
                }
                Err(ReleaseError::Digest) => {
                    rejected.push(format!(
                        "the program from {source}: {}",
                        ReleaseError::Digest
                    ));
                }
                // These are the bytes the manifest names, and every source delivers the same:
                // their signature does not hold anywhere
                Err(e) => {
                    std::fs::remove_file(&path).ok();
                    return Fetched::Rejected(format!("the program from {source}: {e}"));
                }
            }
        }
        std::fs::remove_file(&path).ok();
        if unavailable.is_empty() {
            Fetched::Rejected(rejected.join("; "))
        } else {
            unavailable.extend(rejected);
            Fetched::Unavailable(unavailable.join("; "))
        }
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
            self.services.restart_helpers();
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

/// Where a running upgrade is, reported to the Hub as it changes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Progress {
    #[default]
    Fetching,
    /// No source delivered the program yet, and why; it is fetched again later.
    Waiting(String),
    /// Verified and being installed.
    Installing,
}

/// What fetching the program of a release came to.
#[derive(Debug, PartialEq, Eq)]
enum Fetched {
    /// `nett.new` holds the verified program.
    Verified,
    /// No source delivered it; it is fetched again later.
    Unavailable(String),
    /// Every source delivered something that is not this release's program.
    Rejected(String),
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

    /// Installs the verified program waiting in `nett.new`, restarts the mesh service and checks
    /// it; rolls back when it does not answer.
    fn install(
        &self,
        version: Version,
        current: Version,
        services: &dyn Services,
    ) -> Result<(), String> {
        let new = self.program.with_file_name("nett.new");
        if self.program.exists() {
            std::fs::rename(&self.program, self.previous())
                .map_err(|e| format!("keeping {}: {e}", self.program.display()))?;
        }
        std::fs::rename(&new, &self.program)
            .map_err(|e| format!("installing {}: {e}", self.program.display()))?;
        if let Some(command) = &self.command
            && let Err(e) = replace_command(command, &self.program)
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

/// Whether the command at `path` is nett's own copy: a regular file owned by root in a directory
/// owned by root that others cannot write. A link, or a copy in a directory the user can write
/// (Homebrew), belongs to another installer.
pub fn own_command(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    let (Ok(meta), Some(Ok(dir))) = (
        std::fs::symlink_metadata(path),
        path.parent().map(std::fs::metadata),
    ) else {
        return false;
    };
    meta.file_type().is_file() && meta.uid() == 0 && dir.uid() == 0 && dir.mode() & 0o022 == 0
}

/// Replaces the command copy with the installed `program` when it is nett's own
/// ([`own_command`]): another installer's is the user's to upgrade.
fn replace_command(path: &Path, program: &Path) -> Result<(), String> {
    if !own_command(path) {
        return Ok(());
    }
    let new = path.with_file_name(".nett.new");
    let io = |e: std::io::Error| format!("writing {}: {e}", new.display());
    std::fs::remove_file(&new).ok();
    std::fs::copy(program, &new).map_err(io)?;
    std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755)).map_err(io)?;
    std::fs::rename(&new, path).map_err(|e| format!("replacing {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::*;

    struct FakeServices {
        restarts: AtomicUsize,
        helper_restarts: AtomicUsize,
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
        fn restart_helpers(&self) {
            self.helper_restarts.fetch_add(1, Ordering::SeqCst);
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
        let pair = nett_trust::signing::ReleaseKeyPair::generate().expect("key");
        let keys = ReleaseKeys::parse(&pair.public_key()).expect("keys");
        let version: Version = version.parse().expect("version");
        let url = format!("https://nett.example.com/dl/nett-{version}-{target}");
        (keys, pair.manifest(version, target, &url, bytes))
    }

    fn upgrader(dir: &Path, keys: ReleaseKeys, healthy: bool) -> (Upgrader, Arc<FakeServices>) {
        let program = dir.join("nett");
        std::fs::write(&program, b"old program").expect("write");
        let services = Arc::new(FakeServices {
            restarts: AtomicUsize::new(0),
            helper_restarts: AtomicUsize::new(0),
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
        std::fs::write(dir.join("nett.new"), b"new program").expect("fetched");
        up.clone_paths()
            .install("0.2.0".parse().expect("v"), up.current, &*services)
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
        std::fs::write(dir.join("nett.new"), b"bad program").expect("fetched");
        let err = paths
            .install("0.2.0".parse().expect("v"), up.current, &*services)
            .expect_err("rolled back");
        assert!(err.contains("restored 0.1.5"), "{err}");
        assert_eq!(std::fs::read(&up.program).expect("program"), b"old program");
        assert_eq!(services.restarts.load(Ordering::SeqCst), 2);
        assert!(paths.marker().is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The manifest entry of `manifest` for the test target.
    fn entry(manifest: &[u8]) -> (Version, Program) {
        let manifest = Manifest::parse(manifest).expect("manifest");
        let program = manifest.programs["x86_64-unknown-linux-musl"].clone();
        (manifest.version().expect("v"), program)
    }

    fn reason(progress: &Progress) -> String {
        match progress {
            Progress::Waiting(reason) => reason.clone(),
            other => panic!("not waiting: {other:?}"),
        }
    }

    /// Answers the next fetch on `link` with `bytes`, as a session passes the Hub's parts on.
    async fn serve(link: &HubLink, bytes: &[u8]) {
        let request = link.pending.lock().await.recv().await.expect("request");
        request
            .parts
            .send(crate::fetch::Part::Data {
                offset: 0,
                size: bytes.len() as u64,
                data: bytes.to_vec(),
            })
            .await
            .expect("send");
    }

    /// The program comes from the Hub over the session, is verified there, and installed
    #[tokio::test]
    async fn the_program_from_the_hub_is_verified_and_installed() {
        let (_dir_tmp, dir) = temp("hub");
        let (keys, manifest) = release("0.2.0", "x86_64-unknown-linux-musl", b"new program");
        let (up, services) = upgrader(&dir, keys, true);
        let (version, program) = entry(&manifest);
        let link = HubLink::new();
        let (progress, _) = tokio::sync::watch::channel(Progress::default());
        let (installed, ()) = tokio::join!(
            up.upgrade(version, &program, Some(&link), &progress),
            serve(&link, b"new program")
        );
        installed.expect("installed");
        assert_eq!(std::fs::read(&up.program).expect("program"), b"new program");
        assert_eq!(services.restarts.load(Ordering::SeqCst), 1);
    }

    /// A program that cannot be fetched, or that fails verification while another source is
    /// unreachable, is fetched again later: after 1 minute, then 2, then 4, and the version is not
    /// marked failed (on a NAS whose path to the website delivered 1–5 KB/s, a download limit
    /// marked the release failed for good)
    #[tokio::test(start_paused = true)]
    async fn a_program_not_fetched_yet_is_fetched_again_later() {
        let (_dir_tmp, dir) = temp("retry");
        let (keys, manifest) = release("0.2.0", "x86_64-unknown-linux-musl", b"new program");
        let (up, _services) = upgrader(&dir, keys, true);
        let (version, mut program) = entry(&manifest);
        // Nothing listens there: the website is unreachable
        program.url = "https://127.0.0.1:9/nett".into();
        let link = HubLink::new();
        let (progress, mut waiting) = tokio::sync::watch::channel(Progress::default());
        let upgrade = up.upgrade(version, &program, Some(&link), &progress);
        tokio::pin!(upgrade);
        let mut seen = Vec::new();
        for answer in [Some(b"tampered".as_slice()), None, None] {
            let hub = async {
                if let Some(bytes) = answer {
                    serve(&link, bytes).await;
                }
                waiting.changed().await.expect("waiting");
                seen.push(reason(&waiting.borrow_and_update()));
            };
            tokio::select! {
                _ = &mut upgrade => panic!("the upgrade ended"),
                () = hub => {}
            }
        }
        assert!(seen[0].contains("the program from the Hub"), "{}", seen[0]);
        let waits: Vec<&str> = seen
            .iter()
            .map(|s| s.rsplit("trying again in ").next().unwrap_or_default())
            .collect();
        assert_eq!(waits, ["1 min", "2 min", "4 min"]);
        assert!(up.state().failed.is_empty(), "nothing marked failed");
    }

    /// A transfer from the Hub that breaks off is taken up from the Hub again later, not from the
    /// website: the Hub holds the program, and the website may be the slow path
    #[tokio::test(start_paused = true)]
    async fn a_transfer_from_the_hub_that_breaks_off_is_fetched_from_the_hub_again() {
        let (_dir_tmp, dir) = temp("cut");
        let (keys, manifest) = release("0.2.0", "x86_64-unknown-linux-musl", b"new program");
        let (up, services) = upgrader(&dir, keys, true);
        let (version, mut program) = entry(&manifest);
        // A URL the upgrade must not use: it would fail and say so
        program.url = "https://127.0.0.1:9/nett".into();
        let link = HubLink::new();
        let (progress, mut waiting) = tokio::sync::watch::channel(Progress::default());
        let upgrade = up.upgrade(version, &program, Some(&link), &progress);
        tokio::pin!(upgrade);
        let cut = async {
            let request = link.pending.lock().await.recv().await.expect("request");
            request
                .parts
                .send(crate::fetch::Part::Data {
                    offset: 0,
                    size: 11,
                    data: b"new ".to_vec(),
                })
                .await
                .expect("send");
            // the session ends
            drop(request);
            waiting.changed().await.expect("waiting");
            reason(&waiting.borrow_and_update())
        };
        let reason = tokio::select! {
            _ = &mut upgrade => panic!("the upgrade ended"),
            reason = cut => reason,
        };
        assert!(reason.contains("the connection ended after"), "{reason}");
        assert!(
            !reason.contains("127.0.0.1:9"),
            "the website was not tried: {reason}"
        );
        let (installed, ()) = tokio::join!(upgrade, serve(&link, b"new program"));
        installed.expect("installed");
        assert_eq!(services.restarts.load(Ordering::SeqCst), 1);
    }

    /// A program that matches the manifest but whose signature does not hold is the same from every
    /// source: the version is marked failed at once, without waiting for the website
    #[tokio::test(start_paused = true)]
    async fn a_program_whose_signature_does_not_hold_is_marked_failed() {
        let (_dir_tmp, dir) = temp("untrusted");
        let (_, manifest) = release("0.2.0", "x86_64-unknown-linux-musl", b"new program");
        let (other, _) = release("0.2.0", "x86_64-unknown-linux-musl", b"x");
        let (up, services) = upgrader(&dir, other, true);
        let (version, mut program) = entry(&manifest);
        program.url = "https://127.0.0.1:9/nett".into();
        let link = HubLink::new();
        let (progress, _) = tokio::sync::watch::channel(Progress::default());
        let (result, ()) = tokio::join!(
            up.upgrade(version, &program, Some(&link), &progress),
            serve(&link, b"new program")
        );
        let reason = result.expect_err("refused");
        assert!(reason.contains("does not trust"), "{reason}");
        assert!(up.state().failed.contains_key("0.2.0"));
        assert_eq!(services.restarts.load(Ordering::SeqCst), 0);
        assert!(!dir.join("nett.new").exists());
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
        // the helpers move to the settled program, once
        assert_eq!(services.helper_restarts.load(Ordering::SeqCst), 1);
        up.settled();
        assert_eq!(services.helper_restarts.load(Ordering::SeqCst), 1);
        assert_eq!(up.on_start(), Start::Continue);
        std::fs::remove_dir_all(&dir).ok();
    }
}
