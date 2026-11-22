//! Automatic upgrades (design/release.md section 7, ADR 0020, ADR 0025): the Hub relays the
//! release manifest; nett-node fetches the program for its target from the Hub, or from the URL in
//! the manifest, verifies it against the release keys built into `nett`, and installs only a higher
//! version; the service then exits, and the new program, started by the service manager, rolls
//! back when it does not come up. The replaced program is kept as `nett.previous`, the only version a
//! machine rolls back to. Nothing here trusts the Hub: the signature decides.

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

/// How long a new program's mesh has to answer once it has started.
pub const MESH_START: Duration = Duration::from_secs(60);
/// A new version that starts this many times without connecting to the Hub (and without running
/// for `SETTLED`) is rolled back.
pub(crate) const MAX_STARTS: u32 = 3;
/// After running this long, a new version counts as working even while the Hub is away.
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

/// What the upgrade checks and restarts besides the program: the mesh in this process, and the
/// relay on Linux (design/release.md section 7); the service manager on a real machine, a double in
/// tests.
pub trait Services: Send + Sync {
    /// Whether the mesh answers: its worker hands over its status.
    fn mesh_answers(&self) -> bool;
    /// The relay, when it runs: it runs the same program, and moves to the new one once it has
    /// settled.
    fn restart_helpers(&self);
}

/// The platform's service manager and the mesh in this process (design/release.md sections 4, 5
/// and 7). The upgrade counts the starts of a new program before the mesh starts; the mesh is
/// attached once it runs.
#[derive(Default)]
pub struct ServiceManager {
    mesh: std::sync::OnceLock<Arc<dyn nett_mesh::status::StatusSource + Sync>>,
}

impl ServiceManager {
    /// The mesh has started.
    pub fn attach(&self, mesh: Arc<dyn nett_mesh::status::StatusSource + Sync>) {
        let _ = self.mesh.set(mesh);
    }
}

impl Services for ServiceManager {
    fn mesh_answers(&self) -> bool {
        self.mesh
            .get()
            .is_some_and(|mesh| mesh.snapshot().is_some())
    }

    fn restart_helpers(&self) {
        // macOS runs no relay
        let Some(systemctl) =
            crate::platform::linux::systemctl().filter(|_| cfg!(target_os = "linux"))
        else {
            return;
        };
        // Unrestarted, it keeps the old program until the machine reboots; try-restart leaves a
        // relay that is not running alone. Only an installed unit is named: systemctl fails on one
        // that does not exist
        let units: Vec<&str> = crate::platform::linux::installed_optional()
            .iter()
            .map(|u| u.name)
            .collect();
        if !units.is_empty() {
            let mut args = vec!["try-restart"];
            args.extend(&units);
            if !crate::platform::run(systemctl, &args, SERVICE_TIMEOUT).unwrap_or(false) {
                tracing::warn!(?units, "restarting the relay on the new program failed");
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

/// The upgrade marker: a new version that has not settled yet, and how often it started.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Marker {
    pub(crate) version: String,
    pub(crate) previous: String,
    pub(crate) starts: u32,
}

/// The versions in `dir`'s `upgrade.json` that were not installed or were rolled back, with why.
pub fn failed(dir: &Path) -> BTreeMap<String, String> {
    std::fs::read(dir.join(STATE_FILE))
        .ok()
        .and_then(|b| serde_json::from_slice::<State>(&b).ok())
        .unwrap_or_default()
        .failed
}

/// The highest version that was not installed or was rolled back, with why.
pub fn last_failure(dir: &Path) -> Option<(Version, String)> {
    failed(dir)
        .into_iter()
        .filter_map(|(v, reason)| Some((v.parse().ok()?, reason)))
        .max_by_key(|(v, _)| *v)
}

pub(crate) fn record_failure(dir: &Path, version: Version, reason: &str) {
    let mut state = State {
        failed: failed(dir),
    };
    state.failed.insert(version.to_string(), reason.to_owned());
    while state.failed.len() > MAX_FAILED {
        let Some(oldest) = state.failed.keys().next().cloned() else {
            break;
        };
        state.failed.remove(&oldest);
    }
    if let Ok(json) = serde_json::to_vec_pretty(&state)
        && let Err(e) = crate::config::write_private(&dir.join(STATE_FILE), &json)
    {
        tracing::warn!(error = %e, "recording the failed upgrade");
    }
}

pub(crate) fn read_marker(dir: &Path) -> Option<Marker> {
    std::fs::read(dir.join(MARKER_FILE))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
}

pub(crate) fn write_marker(dir: &Path, marker: &Marker) -> Result<(), String> {
    let json = serde_json::to_vec(marker).map_err(|e| e.to_string())?;
    crate::config::write_private(&dir.join(MARKER_FILE), &json)
}

pub(crate) fn clear_marker(dir: &Path) {
    std::fs::remove_file(dir.join(MARKER_FILE)).ok();
}

pub struct Upgrader {
    pub keys: ReleaseKeys,
    pub target: String,
    pub current: Version,
    /// The program the services run, or, in the container, the one in its volume.
    pub program: PathBuf,
    /// Where `upgrade.json` and the pending marker live (the configuration directory).
    pub dir: PathBuf,
    pub install: Install,
}

/// How a verified program is installed.
#[derive(Clone)]
pub enum Install {
    /// Replaces the program the service runs; the service then exits, and the service manager
    /// starts it from the new program, which checks itself (machines, design/release.md section 7).
    Replace {
        /// Another copy of the command to keep in step (macOS: the install script's copy).
        command: Option<PathBuf>,
        services: Arc<dyn Services>,
        /// How long the new program's mesh has to answer ([`MESH_START`]).
        mesh_start: Duration,
    },
    /// Places it in the state directory, where the installed program's check runs it (the
    /// container, ADR 0026).
    Stage(Arc<crate::launch::Staged>),
}

impl Upgrader {
    /// Decides what a release manifest from the Hub means for this machine.
    pub fn plan(&self, manifest: &[u8]) -> Result<Plan, String> {
        let manifest = Manifest::parse(manifest).map_err(|e| e.to_string())?;
        let version = manifest.version().map_err(|e| e.to_string())?;
        if version <= self.current {
            return Ok(Plan::Current);
        }
        if let Some(reason) = failed(&self.dir).get(&manifest.version) {
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

    /// Fetches, verifies and installs `version`. On success the service exits so that the service
    /// manager starts it from the new program. A program
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
        let current = self.current;
        let minisig = program.minisig.clone();
        let installed = match self.install.clone() {
            Install::Replace { .. } => {
                tokio::task::spawn_blocking(move || this.install(version, current))
            }
            Install::Stage(staged) => {
                tokio::task::spawn_blocking(move || staged.place(version, &minisig))
            }
        };
        installed
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
        let (command, mesh_start) = match &self.install {
            Install::Replace {
                command,
                mesh_start,
                ..
            } => (command.clone(), *mesh_start),
            Install::Stage(_) => (None, MESH_START),
        };
        Paths {
            program: self.program.clone(),
            command,
            dir: self.dir.clone(),
            mesh_start,
        }
    }

    /// At start, before the mesh comes up: counts starts of a newly installed version and rolls it
    /// back when it keeps exiting before it settles, the mesh's exits included. In the container the
    /// installed program's check counts them.
    pub fn on_start(&self) -> Start {
        let Install::Replace { .. } = &self.install else {
            return Start::Continue;
        };
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
            "nett {} exited {MAX_STARTS} times before it settled; restored {}",
            marker.version, marker.previous
        );
        self.roll_back(&paths, &marker, reason)
    }

    /// Once the mesh of this process has started: a newly installed version's mesh answers within
    /// [`MESH_START`], or the previous program goes back. Blocks while it waits.
    pub fn check_started(&self) -> Start {
        let Install::Replace { services, .. } = &self.install else {
            return Start::Continue;
        };
        let paths = self.clone_paths();
        let Some(marker) = paths
            .marker()
            .filter(|m| m.version == self.current.to_string())
        else {
            return Start::Continue;
        };
        if wait_for(|| services.mesh_answers(), paths.mesh_start) {
            return Start::Continue;
        }
        let reason = format!(
            "the mesh did not answer with {}; restored {}",
            marker.version, marker.previous
        );
        self.roll_back(&paths, &marker, reason)
    }

    /// Puts the previous program back and records why; the caller exits so that the service
    /// manager starts it.
    fn roll_back(&self, paths: &Paths, marker: &Marker, reason: String) -> Start {
        if let Err(e) = paths.restore() {
            tracing::error!(error = %e, "restoring the previous program");
            return Start::Continue;
        }
        if let Ok(version) = marker.version.parse() {
            self.record_failure(version, &reason);
        }
        paths.clear_marker();
        Start::RolledBack(reason)
    }

    /// The new version works: it connected to the Hub or ran long enough.
    pub fn settled(&self) {
        match &self.install {
            Install::Replace { services, .. } => {
                let paths = self.clone_paths();
                if paths
                    .marker()
                    .is_some_and(|m| m.version == self.current.to_string())
                {
                    tracing::info!(version = %self.current, "upgrade complete");
                    paths.clear_marker();
                    services.restart_helpers();
                }
            }
            Install::Stage(staged) => {
                if staged.settled() {
                    tracing::info!(version = %self.current, "upgrade complete");
                }
            }
        }
    }

    fn record_failure(&self, version: Version, reason: &str) {
        record_failure(&self.dir, version, reason);
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

    /// Installs the verified program waiting in `nett.new` and records the upgrade marker; the
    /// service exits next, and the new program checks itself when it starts.
    fn install(&self, version: Version, current: Version) -> Result<(), String> {
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
        self.write_marker(&Marker {
            version: version.to_string(),
            previous: current.to_string(),
            starts: 0,
        })?;
        tracing::info!(%version, "installed; the service restarts on it");
        Ok(())
    }

    fn restore(&self) -> Result<(), String> {
        std::fs::rename(self.previous(), &self.program)
            .map_err(|e| format!("restoring {}: {e}", self.previous().display()))
    }

    fn marker(&self) -> Option<Marker> {
        read_marker(&self.dir)
    }

    fn write_marker(&self, marker: &Marker) -> Result<(), String> {
        write_marker(&self.dir, marker)
    }

    fn clear_marker(&self) {
        clear_marker(&self.dir);
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
/// owned by root that others cannot write. A link, or a copy in a directory the user can write,
/// belongs to another installer.
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::*;

    struct FakeServices {
        helper_restarts: AtomicUsize,
        healthy: AtomicBool,
    }

    impl Services for FakeServices {
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
            helper_restarts: AtomicUsize::new(0),
            healthy: AtomicBool::new(healthy),
        });
        (
            Upgrader {
                keys,
                target: "x86_64-unknown-linux-musl".into(),
                current: "0.1.5".parse().expect("version"),
                program,
                dir: dir.to_path_buf(),
                install: Install::Replace {
                    command: None,
                    services: services.clone(),
                    mesh_start: Duration::from_millis(600),
                },
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

    /// Installing replaces the program, keeps the old one and records the marker; the restart is
    /// the service's exit (design/release.md section 7)
    #[test]
    fn a_verified_program_is_installed_and_the_old_one_kept() {
        let (_dir_tmp, dir) = temp("install");
        let (keys, _) = release("0.2.0", "x86_64-unknown-linux-musl", b"new program");
        let (up, _) = upgrader(&dir, keys, true);
        std::fs::write(dir.join("nett.new"), b"new program").expect("fetched");
        up.clone_paths()
            .install("0.2.0".parse().expect("v"), up.current)
            .expect("installed");
        assert_eq!(std::fs::read(&up.program).expect("program"), b"new program");
        assert_eq!(
            std::fs::read(dir.join("nett.previous")).expect("previous"),
            b"old program"
        );
        assert_eq!(up.clone_paths().marker().map(|m| m.starts), Some(0));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The new program starts, and its mesh does not answer: the previous one goes back and the
    /// version is not offered again; one whose mesh answers keeps running until it settles
    #[test]
    fn a_mesh_that_does_not_come_up_is_rolled_back() {
        let (_dir_tmp, dir) = temp("rollback");
        let (keys, _) = release("0.2.0", "x86_64-unknown-linux-musl", b"bad program");
        let (mut up, services) = upgrader(&dir, keys, false);
        let paths = up.clone_paths();
        std::fs::write(dir.join("nett.new"), b"bad program").expect("fetched");
        paths
            .install("0.2.0".parse().expect("v"), up.current)
            .expect("installed");
        up.current = "0.2.0".parse().expect("v");
        assert_eq!(up.on_start(), Start::Continue);
        let Start::RolledBack(reason) = up.check_started() else {
            panic!("rolled back");
        };
        assert!(reason.contains("restored 0.1.5"), "{reason}");
        assert_eq!(std::fs::read(&up.program).expect("program"), b"old program");
        assert!(paths.marker().is_none());
        up.current = "0.1.5".parse().expect("v");
        let (_, manifest) = release("0.2.0", "x86_64-unknown-linux-musl", b"x");
        assert!(matches!(up.plan(&manifest), Ok(Plan::Failed(_))));

        std::fs::write(dir.join("nett.new"), b"good program").expect("fetched");
        paths
            .install("0.3.0".parse().expect("v"), up.current)
            .expect("installed");
        up.current = "0.3.0".parse().expect("v");
        services.healthy.store(true, Ordering::SeqCst);
        assert_eq!(up.on_start(), Start::Continue);
        assert_eq!(up.check_started(), Start::Continue);
        assert!(paths.marker().is_some());
        up.settled();
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
        let (up, _) = upgrader(&dir, keys, true);
        let (version, program) = entry(&manifest);
        let link = HubLink::new();
        let (progress, _) = tokio::sync::watch::channel(Progress::default());
        let (installed, ()) = tokio::join!(
            up.upgrade(version, &program, Some(&link), &progress),
            serve(&link, b"new program")
        );
        installed.expect("installed");
        assert_eq!(std::fs::read(&up.program).expect("program"), b"new program");
        assert!(up.clone_paths().marker().is_some());
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
        assert!(failed(&up.dir).is_empty(), "nothing marked failed");
    }

    /// A transfer from the Hub that breaks off is taken up from the Hub again later, not from the
    /// website: the Hub holds the program, and the website may be the slow path
    #[tokio::test(start_paused = true)]
    async fn a_transfer_from_the_hub_that_breaks_off_is_fetched_from_the_hub_again() {
        let (_dir_tmp, dir) = temp("cut");
        let (keys, manifest) = release("0.2.0", "x86_64-unknown-linux-musl", b"new program");
        let (up, _) = upgrader(&dir, keys, true);
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
        assert_eq!(std::fs::read(&up.program).expect("program"), b"new program");
    }

    /// A program that matches the manifest but whose signature does not hold is the same from every
    /// source: the version is marked failed at once, without waiting for the website
    #[tokio::test(start_paused = true)]
    async fn a_program_whose_signature_does_not_hold_is_marked_failed() {
        let (_dir_tmp, dir) = temp("untrusted");
        let (_, manifest) = release("0.2.0", "x86_64-unknown-linux-musl", b"new program");
        let (other, _) = release("0.2.0", "x86_64-unknown-linux-musl", b"x");
        let (up, _) = upgrader(&dir, other, true);
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
        assert!(failed(&up.dir).contains_key("0.2.0"));
        assert_eq!(std::fs::read(&up.program).expect("program"), b"old program");
        assert!(!dir.join("nett.new").exists());
    }

    /// A new version that keeps exiting before it settles, its mesh included, goes back to the
    /// previous program
    #[test]
    fn a_new_version_that_keeps_exiting_is_rolled_back() {
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
        let Start::RolledBack(reason) = up.on_start() else {
            panic!("rolled back");
        };
        assert!(reason.contains("nett 0.2.0 exited 3 times"), "{reason}");
        assert_eq!(std::fs::read(&up.program).expect("program"), b"old program");
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
