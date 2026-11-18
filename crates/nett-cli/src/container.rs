//! `nett container`: the first process of nett's image (design/container.md, ADR 0016). It joins the
//! site on the first start, runs the mesh process and nett-node with only the capabilities each
//! uses, restarts one that exits, and runs a new version in this process when nett-node has placed
//! one in the volume (ADR 0026). It reads nothing from the network and runs nothing but this
//! program.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use nett_node::launch::{Check, Staged};
use rustix::process::{Pid, Signal, WaitOptions};
use rustix::thread::CapabilitySet;
use tokio::signal::unix::{SignalKind, signal};

/// Set by the image: the container's state volume. Every `nett` command run with it runs the
/// newest verified program there (design/container.md section 6).
pub const STATE_ENV: &str = "NETT_STATE_DIR";
/// The token from `nett site add`, read on the first start only.
pub const TOKEN_ENV: &str = "NETT_TOKEN";
/// The program's name in the volume.
const PROGRAM: &str = "nett";
/// How long `nett join` has to enroll at the first start.
const JOIN_TIMEOUT: Duration = Duration::from_secs(120);
/// A process that exits is started again after this long, doubling up to `RESTART_MAX`; one that
/// ran for `RAN_LONG` starts from the beginning again.
const RESTART_FIRST: Duration = Duration::from_secs(2);
const RESTART_MAX: Duration = Duration::from_secs(30);
const RAN_LONG: Duration = Duration::from_secs(60);
/// How long a new version's mesh process has to answer on its local interface.
const MESH_START: Duration = nett_node::upgrade::MESH_START;
/// How long each process has to stop after `SIGTERM`, within Docker's stop timeout of 10 seconds.
const STOP_GRACE: Duration = Duration::from_secs(4);

pub const USAGE: &str = "usage: nett container\n\n\
The first process of nett's image: joins the site with NETT_TOKEN on the first start, then runs the\n\
mesh process and nett-node, and keeps them running. The state lives in NETT_STATE_DIR, which the\n\
image sets to the volume /var/lib/nett.";

/// The container's state directory, when this program runs in nett's image.
pub fn state_dir() -> Option<PathBuf> {
    std::env::var_os(STATE_ENV)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

/// The program in the volume that this one upgrades to.
pub fn staged(dir: &Path) -> Option<Staged> {
    Some(Staged {
        keys: nett_trust::release::ReleaseKeys::built_in().ok()?,
        target: nett_trust::release::current_target()?.to_owned(),
        current: env!("CARGO_PKG_VERSION").parse().ok()?,
        dir: dir.to_path_buf(),
        name: PROGRAM,
    })
}

/// In the container every command runs the newest verified program in the volume, so the command
/// matches the services; `nett container` also counts the starts of a new version and goes back
/// from one that does not settle (ADR 0026).
pub fn run_newest(command: &str) {
    let Some(staged) = state_dir().as_deref().and_then(staged) else {
        return;
    };
    let start = command == "container";
    // Logs of the check go to the container's output; the command sets up its own after it
    let logs = tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::INFO)
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::with_default(logs, || {
        if let Check::Newer { version, file } = staged.check(start, &|| {}) {
            let error = nett_node::launch::exec(&file);
            tracing::error!(%version, %error, "running the version in the volume; this one continues");
            if start {
                staged.refuse(version, &format!("it does not run: {error}"), &|| {});
            }
        }
    });
}

/// The capabilities each process keeps (design/container.md section 4).
fn mesh_caps() -> CapabilitySet {
    CapabilitySet::NET_ADMIN | CapabilitySet::NET_RAW | CapabilitySet::NET_BIND_SERVICE
}

pub fn run(mut parser: lexopt::Parser) -> anyhow::Result<()> {
    if let Some(arg) = parser.next()? {
        return Err(arg.unexpected().into());
    }
    crate::mesh::init_logging();
    let state = state_dir().with_context(|| {
        format!("{STATE_ENV} is not set: `nett container` is the entry point of nett's image")
    })?;
    // It keeps what the mesh process needs, and the right to drop capabilities for each process
    keep_only(mesh_caps() | CapabilitySet::SETPCAP);
    let runtime_dir = Path::new(nett_mesh::status::DEFAULT_SOCKET)
        .parent()
        .context("the local socket's directory")?;
    std::fs::create_dir_all(runtime_dir)
        .with_context(|| format!("creating {}", runtime_dir.display()))?;
    if !state.join(nett_node::config::HUB_FILE).exists() {
        join(&state)?;
    }
    let staged = staged(&state).context("the release keys built into nett")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    let outcome = runtime.block_on(Supervisor::new(&state, &staged).run())?;
    drop(runtime);
    match outcome {
        Outcome::Stopped => Ok(()),
        Outcome::Relaunch(why) => {
            tracing::info!(%why, "starting again through the installed program");
            let error = nett_node::launch::relaunch();
            Err(anyhow::Error::new(error).context(format!(
                "running {} again",
                nett_node::launch::installed().display()
            )))
        }
    }
}

/// The first start: enrolls with the token from the environment, in a process without
/// capabilities (design/container.md section 5).
fn join(state: &Path) -> anyhow::Result<()> {
    if std::env::var_os(TOKEN_ENV).is_none() {
        bail!(
            "{} holds no Hub configuration yet: set {TOKEN_ENV} to the token `nett site add <name>` \
             prints on the computer that holds the site",
            state.display()
        );
    }
    tracing::info!("joining the site with {TOKEN_ENV}");
    let mut child = spawn(
        &["join", "--dir", &state.to_string_lossy()],
        CapabilitySet::empty(),
        true,
    )?;
    let deadline = Instant::now() + JOIN_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().context("waiting for `nett join`")? {
            if status.success() {
                return Ok(());
            }
            bail!("`nett join` failed ({status}); its output above says why");
        }
        if Instant::now() >= deadline {
            child.kill().ok();
            child.wait().ok();
            bail!(
                "`nett join` did not finish within {} seconds",
                JOIN_TIMEOUT.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Starts this program with `args`, keeping only `keep` of the capabilities; the token stays in the
/// environment only of the process that joins.
fn spawn(args: &[&str], keep: CapabilitySet, token: bool) -> anyhow::Result<std::process::Child> {
    use std::os::unix::process::CommandExt as _;
    let mut command = std::process::Command::new("/proc/self/exe");
    command.arg0("nett").args(args);
    if !token {
        command.env_remove(TOKEN_ENV);
    }
    bounded(&mut command, keep);
    command
        .spawn()
        .with_context(|| format!("starting `nett {}`", args.join(" ")))
}

/// Limits what the started process can hold to `keep`: the bounding set caps what root gains at
/// exec, and no-new-privileges keeps it from gaining more later.
#[allow(unsafe_code)]
fn bounded(command: &mut std::process::Command, keep: CapabilitySet) {
    use std::os::unix::process::CommandExt as _;
    // SAFETY: the closure runs in the child between fork and exec, where only async-signal-safe
    // calls are allowed: it makes raw prctl system calls through rustix, and does not allocate,
    // lock or touch state shared with the parent
    unsafe {
        command.pre_exec(move || {
            for cap in CapabilitySet::all().iter() {
                if !keep.contains(cap) {
                    match rustix::thread::remove_capability_from_bounding_set(cap) {
                        // Capabilities this kernel does not know
                        Ok(()) | Err(rustix::io::Errno::INVAL) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            rustix::thread::set_no_new_privs(true)?;
            Ok(())
        });
    }
}

/// Drops every capability of this process but `keep`.
fn keep_only(keep: CapabilitySet) {
    for cap in CapabilitySet::all().iter() {
        if !keep.contains(cap) {
            match rustix::thread::remove_capability_from_bounding_set(cap) {
                Ok(()) | Err(rustix::io::Errno::INVAL) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "dropping capabilities; the processes keep what the container was given");
                    return;
                }
            }
        }
    }
    let held = rustix::thread::capabilities(None).map(|c| c.permitted & keep);
    if let Err(e) = held.and_then(|held| {
        rustix::thread::set_capabilities(
            None,
            rustix::thread::CapabilitySets {
                effective: held,
                permitted: held,
                inheritable: CapabilitySet::empty(),
            },
        )
    }) {
        tracing::warn!(error = %e, "dropping capabilities of the first process");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Mesh,
    Node,
}

impl Role {
    fn name(self) -> &'static str {
        match self {
            Self::Mesh => "the mesh process",
            Self::Node => "nett-node",
        }
    }
}

struct Process {
    role: Role,
    pid: Option<Pid>,
    started: Instant,
    backoff: Duration,
    restart_at: Option<Instant>,
}

enum Outcome {
    Stopped,
    /// Every process has stopped; the installed program's check runs next, and why.
    Relaunch(String),
}

struct Supervisor<'a> {
    state: &'a Path,
    staged: &'a Staged,
    processes: Vec<Process>,
}

impl<'a> Supervisor<'a> {
    fn new(state: &'a Path, staged: &'a Staged) -> Self {
        let process = |role| Process {
            role,
            pid: None,
            started: Instant::now(),
            backoff: RESTART_FIRST,
            restart_at: Some(Instant::now()),
        };
        Self {
            state,
            staged,
            processes: vec![process(Role::Mesh), process(Role::Node)],
        }
    }

    fn args(&self, role: Role) -> Vec<String> {
        let at = |name: &str| self.state.join(name).to_string_lossy().into_owned();
        match role {
            Role::Mesh => vec![
                "mesh".into(),
                "--config".into(),
                at("desired.json"),
                "--key".into(),
                at("mesh.key"),
                "--state".into(),
                at("state"),
            ],
            Role::Node => vec![
                "node".into(),
                "--dir".into(),
                self.state.to_string_lossy().into_owned(),
            ],
        }
    }

    fn start(&mut self, i: usize) -> anyhow::Result<()> {
        let role = self.processes[i].role;
        let args = self.args(role);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let keep = match role {
            Role::Mesh => mesh_caps(),
            Role::Node => CapabilitySet::empty(),
        };
        let child = spawn(&args, keep, false)?;
        let p = &mut self.processes[i];
        p.pid = Some(Pid::from_child(&child));
        p.started = Instant::now();
        p.restart_at = None;
        Ok(())
    }

    async fn run(mut self) -> anyhow::Result<Outcome> {
        let mut term = signal(SignalKind::terminate()).context("installing the SIGTERM handler")?;
        let mut interrupt =
            signal(SignalKind::interrupt()).context("installing the SIGINT handler")?;
        let mut child = signal(SignalKind::child()).context("installing the SIGCHLD handler")?;
        let current = self.staged.current;
        // A new version proves itself before its processes are restarted one by one
        let mut mesh_check =
            (self.staged.pending() == Some(current)).then(|| Instant::now() + MESH_START);
        loop {
            let now = Instant::now();
            for i in 0..self.processes.len() {
                if self.processes[i].restart_at.is_some_and(|at| at <= now) {
                    self.start(i)?;
                }
            }
            if mesh_check.is_some_and(|at| at <= now) {
                mesh_check = None;
                if self.staged.pending() == Some(current) && !mesh_answers().await {
                    return Ok(self
                        .stop(format!(
                            "the mesh process of {current} did not answer within {} seconds",
                            MESH_START.as_secs()
                        ))
                        .await);
                }
            }
            let next = self
                .processes
                .iter()
                .filter_map(|p| p.restart_at)
                .chain(mesh_check)
                .min()
                .unwrap_or_else(|| now + Duration::from_secs(3600));
            tokio::select! {
                _ = term.recv() => return Ok(self.stop_all().await),
                _ = interrupt.recv() => return Ok(self.stop_all().await),
                _ = child.recv() => {}
                () = tokio::time::sleep_until(next.into()) => {}
            }
            for (pid, status) in reap() {
                let Some(i) = self.processes.iter().position(|p| p.pid == Some(pid)) else {
                    continue;
                };
                let role = self.processes[i].role;
                self.processes[i].pid = None;
                match self.staged.pending() {
                    Some(placed) if placed > current => {
                        return Ok(self.stop(format!("{placed} is in place")).await);
                    }
                    Some(placed) if placed == current => {
                        return Ok(self
                            .stop(format!(
                                "{} of {current} exited ({status:?}) before it settled",
                                role.name()
                            ))
                            .await);
                    }
                    _ => {}
                }
                let p = &mut self.processes[i];
                p.backoff = if p.started.elapsed() >= RAN_LONG {
                    RESTART_FIRST
                } else {
                    (p.backoff * 2).min(RESTART_MAX)
                };
                tracing::warn!(
                    process = role.name(),
                    ?status,
                    restart_secs = p.backoff.as_secs(),
                    "exited; starting it again"
                );
                p.restart_at = Some(Instant::now() + p.backoff);
            }
        }
    }

    /// Stops every process for the installed program's check.
    async fn stop(&mut self, why: String) -> Outcome {
        tracing::info!(%why, "stopping to run the version in place");
        self.stop_processes().await;
        Outcome::Relaunch(why)
    }

    async fn stop_all(&mut self) -> Outcome {
        tracing::info!("stopping");
        self.stop_processes().await;
        Outcome::Stopped
    }

    /// nett-node first, then the mesh process; then, as the container's first process, every
    /// other process in the container, so that nothing runs while the next version is checked.
    async fn stop_processes(&mut self) {
        for role in [Role::Node, Role::Mesh] {
            let Some(p) = self.processes.iter_mut().find(|p| p.role == role) else {
                continue;
            };
            p.restart_at = None;
            if let Some(pid) = p.pid.take() {
                end(pid, STOP_GRACE).await;
            }
        }
        if rustix::process::getpid().is_init() {
            for pid in others() {
                rustix::process::kill_process(pid, Signal::KILL).ok();
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline && !others().is_empty() {
                reap();
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            reap();
        }
    }
}

/// Sends `SIGTERM` and waits up to `grace` for the process to exit, then kills it.
async fn end(pid: Pid, grace: Duration) {
    rustix::process::kill_process(pid, Signal::TERM).ok();
    let deadline = Instant::now() + grace;
    loop {
        match rustix::process::waitpid(Some(pid), WaitOptions::NOHANG) {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) if Instant::now() >= deadline => {
                rustix::process::kill_process(pid, Signal::KILL).ok();
                rustix::process::waitpid(Some(pid), WaitOptions::empty()).ok();
                return;
            }
            Ok(None) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
}

/// Every child that has exited, reaped; as the container's first process this includes processes
/// whose parent exited before them.
fn reap() -> Vec<(Pid, rustix::process::WaitStatus)> {
    let mut exited = Vec::new();
    while let Ok(Some((pid, status))) = rustix::process::waitpid(None, WaitOptions::NOHANG) {
        exited.push((pid, status));
    }
    exited
}

/// The other processes in the container.
fn others() -> Vec<Pid> {
    let me = rustix::process::getpid();
    std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
        .filter_map(Pid::from_raw)
        .filter(|pid| *pid != me)
        .collect()
}

async fn mesh_answers() -> bool {
    tokio::task::spawn_blocking(|| {
        nett_mesh::status::query_raw(Path::new(nett_mesh::status::DEFAULT_SOCKET)).is_ok()
    })
    .await
    .unwrap_or(false)
}
