//! `nett daemon`: the nett service, one process per machine run by the service manager (ADR 0013).
//! It runs the mesh, whose desired state comes from a local file and is re-read on `SIGHUP` or a
//! `reload` on the local interface (design/local-signing.md section 5, status.md section 4.1), the
//! relay on a machine that relays (ADR 0032) and the transports; with a Hub configuration in its
//! directory it also runs nett-node, which
//! connects the machine to its Hub, on a thread of its own. `nett keys` generates the mesh private
//! key and the identity private key on this machine (local-signing.md section 3). The event file
//! and simulated clock skew exist only in the lab build (the `lab` feature).

#[cfg(target_os = "macos")]
use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, bail};
use nett_core::id::NodeId;
use nett_mesh::engine::Engine;
use nett_mesh::event::{EventSink, LogSink};
#[cfg(target_os = "linux")]
use nett_mesh::helper::HelperServer;
use nett_mesh::key::PrivateKey;
#[cfg(feature = "lab")]
use nett_mesh::lab::{JsonLinesSink, LabClock};
#[cfg(target_os = "linux")]
use nett_mesh::linux::tun::LinuxTun;
#[cfg(target_os = "linux")]
use nett_mesh::linux::{KernelWireGuard, SystemClock};
#[cfg(target_os = "macos")]
use nett_mesh::macos::{MacTun, SystemClock};
use nett_mesh::runtime::Runtime;
use nett_mesh::source::FileSource;
use nett_mesh::status::StatusServer;
use nett_mesh::store::{DirBackend, STATE_DIR, TrustStore};
use nett_mesh::userspace::UserspaceDataPlane;
use nett_node::daemon::Ended;
use nett_trust::keys::X25519PublicKey;
use tokio::signal::unix::{SignalKind, signal};

/// The files in the daemon's directory (design/release.md section 8).
pub const DESIRED_FILE: &str = "desired.json";
pub const MESH_KEY_FILE: &str = "mesh.key";
pub const IDENTITY_KEY_FILE: &str = "identity.key";
/// The relay's saved bindings, next to the daemon's sockets (design/mesh.md section 5.2).
#[cfg(target_os = "linux")]
const RELAY_STATE: &str = "relay-state.json";

struct Args {
    /// The keys, the desired state, the Hub configuration and the trust store.
    dir: PathBuf,
    /// Local status socket (design/status.md section 3).
    socket: PathBuf,
    #[cfg(feature = "lab")]
    lab: LabArgs,
}

/// Options of the lab build.
#[cfg(feature = "lab")]
#[derive(Default)]
struct LabArgs {
    events: Option<PathBuf>,
    /// Simulated clock skew (design/prototype.md scenario 17).
    clock_offset_ms: i64,
    clock_trusted: Option<bool>,
    /// Uses the userspace data plane instead of kernel WireGuard (design/userspace.md section 8).
    userspace: bool,
}

pub const USAGE: &str = "usage: nett daemon --dir <directory> [--socket <path>]\n\n\
The nett service: the mesh, the relay, the transports and, with hub.json in the directory, the connection\n\
to the Hub. Started by systemd, launchd or `nett container`; `sudo nett install` installs it. The\n\
directory holds mesh.key, identity.key, desired.json, hub.json and the trust store (state/).";
pub const KEYS_USAGE: &str = "usage: nett keys --dir <directory>\n\n\
Existing keys are kept and the same line is printed again. On macOS, `sudo nett install` does this.";
#[cfg(feature = "lab")]
const LAB_USAGE: &str = "lab options: [--events <events.jsonl>] [--clock-offset-ms <ms>] \
[--clock-trusted <yes|no>] [--userspace]";

fn parse(mut parser: lexopt::Parser) -> anyhow::Result<Args> {
    let mut dir = None;
    let mut socket = PathBuf::from(nett_mesh::status::DEFAULT_SOCKET);
    #[cfg(feature = "lab")]
    let mut lab = LabArgs::default();
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Long("dir") => dir = Some(PathBuf::from(parser.value()?)),
            lexopt::Arg::Long("socket") => socket = PathBuf::from(parser.value()?),
            #[cfg(feature = "lab")]
            lexopt::Arg::Long(name) => {
                let name = name.to_owned();
                if !parse_lab(&mut lab, &name, &mut parser)? {
                    bail!("unexpected option --{name}\n{USAGE}\n{LAB_USAGE}");
                }
            }
            other => return Err(other.unexpected().into()),
        }
    }
    let Some(dir) = dir else {
        #[cfg(feature = "lab")]
        bail!("{USAGE}\n{LAB_USAGE}");
        #[cfg(not(feature = "lab"))]
        bail!(USAGE);
    };
    Ok(Args {
        dir,
        socket,
        #[cfg(feature = "lab")]
        lab,
    })
}

/// One option of the lab build; returns `false` if it is not recognized.
#[cfg(feature = "lab")]
fn parse_lab(lab: &mut LabArgs, name: &str, parser: &mut lexopt::Parser) -> anyhow::Result<bool> {
    use lexopt::ValueExt as _;
    match name {
        "events" => lab.events = Some(PathBuf::from(parser.value()?)),
        "userspace" => lab.userspace = true,
        "clock-offset-ms" => lab.clock_offset_ms = parser.value()?.parse()?,
        "clock-trusted" => {
            lab.clock_trusted = Some(match parser.value()?.string()?.as_str() {
                "yes" => true,
                "no" => false,
                _ => bail!("--clock-trusted takes yes or no"),
            });
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// `nett keys --dir <directory>`: generates the mesh private key and the identity private key (one
/// new file each, not overwritten if they exist) and prints the one line of public keys to write
/// into the site description.
pub fn keys(mut parser: lexopt::Parser) -> anyhow::Result<()> {
    let mut dir = None;
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Long("dir") => dir = Some(PathBuf::from(parser.value()?)),
            other => return Err(other.unexpected().into()),
        }
    }
    let dir = dir.context(KEYS_USAGE)?;
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    print_keys(&dir, node_keys(&dir)?);
    Ok(())
}

/// This machine's mesh public key and identity public key. Generated when neither private key
/// exists yet (`0600`, never leaves the machine); reused when both exist; an error when only one
/// exists, and neither is overwritten.
pub(crate) fn node_keys(
    dir: &std::path::Path,
) -> anyhow::Result<(X25519PublicKey, X25519PublicKey)> {
    let (mesh, identity) = (dir.join(MESH_KEY_FILE), dir.join(IDENTITY_KEY_FILE));
    match (mesh.exists(), identity.exists()) {
        (true, true) => Ok((
            PrivateKey::load(&mesh)?.public_key(),
            PrivateKey::load(&identity)?.public_key(),
        )),
        (false, false) => {
            let (m, i) = (PrivateKey::generate()?, PrivateKey::generate()?);
            m.save_new(&mesh)?;
            i.save_new(&identity)?;
            Ok((m.public_key(), i.public_key()))
        }
        _ => bail!(
            "only one of mesh.key and identity.key exists in {}; move it away to generate both again",
            dir.display()
        ),
    }
}

/// Prints the one line of public keys to write into the site description.
pub(crate) fn print_keys(
    dir: &std::path::Path,
    (mesh, identity): (X25519PublicKey, X25519PublicKey),
) {
    outln!(
        "Private keys are in {} (mode 0600) and stay on this machine.",
        dir.display()
    );
    outln!("On the computer that holds the site, add this machine with:");
    outln!("  nett site add <name> --keys \"{mesh} {identity}\"");
    outln!("(with --public --ipv4 <address> when other machines connect to it)");
}

/// Logs go to standard error (collected into the journal by systemd on Linux). When running as a
/// launchd service on macOS (standard error is not a terminal), they go to the system log: the
/// standard error file only records startup failures, and launchd reopens it each time it starts
/// the process, so rotation works.
pub(crate) fn init_logging() {
    let builder =
        tracing_subscriber::fmt().with_max_level(tracing_subscriber::filter::LevelFilter::INFO);
    #[cfg(target_os = "macos")]
    if !std::io::stderr().is_terminal() {
        builder
            .without_time()
            .with_writer(syslog::Syslog(std::sync::Arc::new(
                nett_mesh::macos::SystemLog::open(),
            )))
            .init();
        return;
    }
    builder.with_writer(std::io::stderr).init();
}

#[cfg(target_os = "macos")]
mod syslog {
    use std::sync::Arc;

    use nett_mesh::macos::SystemLog;
    use tracing_subscriber::fmt::MakeWriter;

    /// One writer per log record; when dropped, it is written out as one system log entry.
    pub struct Syslog(pub Arc<SystemLog>);

    pub struct Line {
        log: Arc<SystemLog>,
        level: tracing::Level,
        buf: Vec<u8>,
    }

    impl std::io::Write for Line {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.buf.extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Drop for Line {
        fn drop(&mut self) {
            if !self.buf.is_empty() {
                self.log
                    .write(self.level, &String::from_utf8_lossy(&self.buf));
            }
        }
    }

    impl<'a> MakeWriter<'a> for Syslog {
        type Writer = Line;

        fn make_writer(&'a self) -> Line {
            Line {
                log: Arc::clone(&self.0),
                level: tracing::Level::INFO,
                buf: Vec::new(),
            }
        }

        fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Line {
            Line {
                log: Arc::clone(&self.0),
                level: *meta.level(),
                buf: Vec::new(),
            }
        }
    }
}

/// When there is no trust store yet, this machine's node ID is taken from the desired state file:
/// the engine uses it to confirm that every desired state is meant for this machine.
fn node_id(config: &Path) -> anyhow::Result<NodeId> {
    let bytes = nett_mesh::config::read_bounded(config, nett_mesh::config::MAX_DESIRED_BYTES)
        .with_context(|| format!("reading {}", config.display()))?
        .with_context(|| {
            format!(
                "{} does not exist and there is no trust store yet",
                config.display()
            )
        })?;
    let doc: serde_json::Value = serde_json::from_slice(&bytes).context("parsing desired state")?;
    doc.get("node_id")
        .and_then(|v| v.as_str())
        .context("desired state has no node_id")?
        .parse()
        .context("desired state node_id")
}

pub fn run(parser: lexopt::Parser) -> anyhow::Result<()> {
    let args = parse(parser)?;
    init_logging();
    let config = args.dir.join(DESIRED_FILE);
    // nett-node in this process, with a Hub: a newly installed version counts its starts before the
    // mesh comes up, so that one whose mesh exits goes back too (design/release.md section 7)
    let node = crate::node::InDaemon::prepare(&args.dir)?;

    // Read the trust store first, then the desired state (design/mesh.md section 4.2)
    let trust = TrustStore::open(Box::new(DirBackend::new(args.dir.join(STATE_DIR))));
    let node_id = match trust.node_id() {
        Some(id) => id.clone(),
        None => node_id(&config)?,
    };
    let key = PrivateKey::load(&args.dir.join(MESH_KEY_FILE))?;
    // Install the signal handlers first: a SIGHUP (for example `systemctl reload`) at any later
    // moment only triggers a re-read and does not end the process
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    let (reload_tx, reload_rx) = tokio::sync::mpsc::channel(nett_mesh::status::MAX_PENDING_RELOADS);
    let (source, mut terminate, mut interrupt) = {
        let _context = runtime.enter();
        (
            FileSource::new(config.clone(), reload_rx).context("installing the SIGHUP handler")?,
            signal(SignalKind::terminate()).context("installing the SIGTERM handler")?,
            signal(SignalKind::interrupt()).context("installing the SIGINT handler")?,
        )
    };
    #[cfg(feature = "lab")]
    let sink: Box<dyn EventSink + Send> = match &args.lab.events {
        Some(path) => Box::new(
            JsonLinesSink::create(path).with_context(|| format!("opening {}", path.display()))?,
        ),
        None => Box::new(LogSink),
    };
    #[cfg(not(feature = "lab"))]
    let sink: Box<dyn EventSink + Send> = Box::new(LogSink);
    #[cfg(feature = "lab")]
    let clock = LabClock {
        inner: SystemClock,
        offset_ms: args.lab.clock_offset_ms,
        trusted: args.lab.clock_trusted,
    };
    #[cfg(not(feature = "lab"))]
    let clock = SystemClock;
    // Linux uses kernel WireGuard when the kernel has it and the userspace data plane otherwise
    // (Synology DSM, old kernels; design/dsm.md section 5); macOS is a native member and uses the
    // userspace data plane (design/userspace.md)
    #[cfg(all(target_os = "linux", feature = "lab"))]
    let userspace = args.lab.userspace;
    #[cfg(all(target_os = "linux", not(feature = "lab")))]
    let userspace = false;
    #[cfg(target_os = "linux")]
    let kernel = if userspace {
        None
    } else {
        match KernelWireGuard::open() {
            Ok(dataplane) => Some(dataplane),
            Err(nett_mesh::dataplane::DataPlaneError::Unsupported(what)) => {
                tracing::info!("{what} is not in this kernel; using the userspace data plane");
                None
            }
            Err(e) => return Err(e.into()),
        }
    };
    #[cfg(target_os = "linux")]
    let worker = match kernel {
        Some(dataplane) => Runtime::spawn(
            Engine::new(node_id, key, dataplane).with_trust_store(trust),
            sink,
            clock,
            nett_mesh::dns::PORT,
            runtime.handle().clone(),
        ),
        None => Runtime::spawn(
            Engine::new(node_id, key, UserspaceDataPlane::new(LinuxTun::open()?))
                .with_trust_store(trust),
            sink,
            clock,
            nett_mesh::dns::PORT,
            runtime.handle().clone(),
        ),
    };
    #[cfg(target_os = "macos")]
    let worker = Runtime::spawn(
        Engine::new(node_id, key, UserspaceDataPlane::new(MacTun::open()?)).with_trust_store(trust),
        sink,
        clock,
        nett_mesh::dns::PORT,
        runtime.handle().clone(),
    );
    let worker = worker.context("starting the mesh worker thread")?;
    // The relay's hand-off port, which nett-relay hands TLS connections to (ADR 0032)
    #[cfg(target_os = "linux")]
    let handoff = Arc::new(std::sync::atomic::AtomicU16::new(0));
    // The local interface is for people and the relay's TLS entry: if a socket cannot be created,
    // record it and continue meshing as usual (hard rule 8)
    #[cfg(target_os = "linux")]
    let helpers_path = nett_mesh::helper::socket_path(&args.socket);
    #[cfg(target_os = "linux")]
    let helpers = match HelperServer::spawn(
        &helpers_path,
        worker.status_source(reload_tx.clone()),
        handoff.clone(),
    ) {
        Ok(server) => Some(server),
        Err(e) => {
            tracing::warn!(socket = %helpers_path.display(), error = %e, "helper socket unavailable; the relay's TLS entry cannot start");
            None
        }
    };
    // This process carries the relay and the transports and asks its worker thread for their
    // configuration (ADR 0013, ADR 0032)
    let transport: Arc<dyn nett_mesh::helper::HelperSource + Sync> =
        Arc::new(worker.status_source(reload_tx.clone()));
    // Relays run on Linux (design/site.md section 4.1)
    #[cfg(target_os = "linux")]
    let relay_mesh: Arc<dyn nett_mesh::helper::HelperSource + Sync> =
        Arc::new(worker.status_source(reload_tx.clone()));
    // Kept while the service restarts (`RuntimeDirectoryPreserve=restart`), gone with a reboot
    #[cfg(target_os = "linux")]
    let relay_state = args.socket.with_file_name(RELAY_STATE);
    let mesh: Arc<dyn nett_mesh::status::StatusSource + Sync> =
        Arc::new(worker.status_source(reload_tx.clone()));
    let status = match StatusServer::spawn(&args.socket, worker.status_source(reload_tx)) {
        Ok(server) => Some(server),
        Err(e) => {
            tracing::warn!(socket = %args.socket.display(), error = %e, "status socket unavailable; `nett status` will not work");
            None
        }
    };
    // The mesh runs: nett-node starts beside it, and the service exits when nett-node has a new
    // program in place, put the previous one back, or found its own unit changed
    let (ended, node_ended) = tokio::sync::oneshot::channel();
    let node = node.and_then(|n| match n.spawn(mesh, ended) {
        Ok(thread) => Some(thread),
        Err(e) => {
            tracing::error!(error = %e, "starting nett-node's thread; this machine is not connected to its Hub");
            None
        }
    });
    let restart = async move {
        match node_ended.await {
            Ok(Ended::Upgraded) => tracing::info!("nett exits to run the new version"),
            Ok(Ended::RolledBack(reason)) => {
                tracing::error!(%reason, "nett exits to run the previous version");
            }
            Ok(Ended::UnitChanged) => {
                tracing::info!(
                    "nett's unit changed; it exits so that systemd starts it with the new one"
                );
            }
            // nett-node ends on its own only for these; it stops when the service does
            Ok(Ended::Stopped) | Err(_) => std::future::pending::<()>().await,
        }
    };

    runtime.block_on(async move {
        let shutdown = async move {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = interrupt.recv() => {}
                () = restart => {}
            }
        };
        let (stop_transport, stopped) = tokio::sync::oneshot::channel::<()>();
        let transport = tokio::spawn(async move {
            let stopped = async {
                let _ = stopped.await;
            };
            if let Err(error) = nett_transport::forward::run(transport, stopped).await {
                tracing::error!(%error, "the TLS transport stopped; paths over TLS stay down until nett restarts");
            }
        });
        #[cfg(target_os = "linux")]
        let (stop_relay, relay_stopped) = tokio::sync::oneshot::channel::<()>();
        #[cfg(target_os = "linux")]
        let relay = tokio::spawn(nett_relay::service::run_in_daemon(
            relay_mesh,
            relay_state,
            handoff,
            async {
                let _ = relay_stopped.await;
            },
        ));
        let worker = nett_mesh::run::run(source, worker, shutdown).await?;
        if let Some(node) = node {
            let stopped =
                tokio::task::spawn_blocking(move || node.stop(nett_node::daemon::STOP_WAIT))
                    .await
                    .unwrap_or(false);
            if !stopped {
                tracing::warn!("nett-node did not stop in time");
            }
        }
        drop(stop_transport);
        let _ = transport.await;
        // A local socket's server joins its thread as it goes, which waits out the thread's poll:
        // on a blocking thread, so the relay on this runtime keeps forwarding meanwhile
        #[cfg(target_os = "linux")]
        let servers = (status, helpers);
        #[cfg(not(target_os = "linux"))]
        let servers = status;
        let _ = tokio::task::spawn_blocking(move || drop(servers)).await;
        let stopped = tokio::task::spawn_blocking(move || worker.shutdown())
            .await
            .context("stopping the mesh worker")?
            .map_err(anyhow::Error::msg);
        // The relay forwards for others until the process is about to exit, and saves its
        // bindings as it stops, so a restart interrupts the connections through it only for the
        // moment the daemon takes to start again
        #[cfg(target_os = "linux")]
        {
            drop(stop_relay);
            let _ = relay.await;
        }
        stopped?;
        tracing::info!("nett stopped");
        anyhow::Ok(())
    })
}
