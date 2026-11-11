//! `nett mesh`: the mesh process, run by the service manager. The desired state comes from a
//! local file and is re-read on `SIGHUP` or a `reload` on the local interface
//! (design/local-signing.md section 5, status.md section 4.1). `nett keys` generates the mesh
//! private key and the identity private key on this machine (local-signing.md section 3). The event
//! file, simulated clock skew and transport adapter configuration exist only in the lab build (the
//! `lab` feature).

use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use nett_core::id::NodeId;
use nett_mesh::engine::Engine;
use nett_mesh::event::{EventSink, LogSink};
use nett_mesh::helper::HelperServer;
use nett_mesh::key::PrivateKey;
#[cfg(feature = "lab")]
use nett_mesh::lab::{JsonLinesSink, LabClock, TransportConfigWriter};
#[cfg(target_os = "linux")]
use nett_mesh::linux::tun::LinuxTun;
#[cfg(target_os = "linux")]
use nett_mesh::linux::{KernelWireGuard, SystemClock};
#[cfg(target_os = "macos")]
use nett_mesh::macos::{MacTun, SystemClock};
use nett_mesh::runtime::Runtime;
use nett_mesh::source::FileSource;
use nett_mesh::status::StatusServer;
use nett_mesh::store::{DirBackend, TrustStore};
use nett_mesh::userspace::UserspaceDataPlane;
use nett_trust::keys::X25519PublicKey;
use tokio::signal::unix::{SignalKind, signal};

struct Args {
    config: PathBuf,
    key: PathBuf,
    /// Local status socket (design/status.md section 3).
    socket: PathBuf,
    /// Directory of the trust store (design/mesh.md section 4.2).
    state: PathBuf,
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
    /// The transport adapter configuration is written here (design/mesh.md section 5.3).
    transport_config: Option<PathBuf>,
    /// Uses the userspace data plane instead of kernel WireGuard (design/userspace.md section 8).
    userspace: bool,
}

pub const USAGE: &str = "usage: nett mesh --config <desired-state.json> --key <mesh.key> [--socket <path>] [--state <dir>]\n\n\
Started by systemd, launchd or a container; to install the service on macOS, use `sudo nett install`.";
pub const KEYS_USAGE: &str = "usage: nett keys --dir <directory>\n\n\
Existing keys are kept and the same line is printed again. On macOS, `sudo nett install` does this.";
#[cfg(feature = "lab")]
const LAB_USAGE: &str = "lab options: [--events <events.jsonl>] [--transport-config <transport.json>] \
[--clock-offset-ms <ms>] [--clock-trusted <yes|no>] [--userspace]";

fn parse(mut parser: lexopt::Parser) -> anyhow::Result<Args> {
    let (mut config, mut key) = (None, None);
    let mut socket = PathBuf::from(nett_mesh::status::DEFAULT_SOCKET);
    let mut state = PathBuf::from(nett_mesh::store::DEFAULT_STATE_DIR);
    #[cfg(feature = "lab")]
    let mut lab = LabArgs::default();
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Long("config") => config = Some(PathBuf::from(parser.value()?)),
            lexopt::Arg::Long("key") => key = Some(PathBuf::from(parser.value()?)),
            lexopt::Arg::Long("socket") => socket = PathBuf::from(parser.value()?),
            lexopt::Arg::Long("state") => state = PathBuf::from(parser.value()?),
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
    match (config, key) {
        (Some(config), Some(key)) => Ok(Args {
            config,
            key,
            socket,
            state,
            #[cfg(feature = "lab")]
            lab,
        }),
        #[cfg(feature = "lab")]
        _ => bail!("{USAGE}\n{LAB_USAGE}"),
        #[cfg(not(feature = "lab"))]
        _ => bail!(USAGE),
    }
}

/// One option of the lab build; returns `false` if it is not recognized.
#[cfg(feature = "lab")]
fn parse_lab(lab: &mut LabArgs, name: &str, parser: &mut lexopt::Parser) -> anyhow::Result<bool> {
    use lexopt::ValueExt as _;
    match name {
        "events" => lab.events = Some(PathBuf::from(parser.value()?)),
        "transport-config" => lab.transport_config = Some(PathBuf::from(parser.value()?)),
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
    let (mesh, identity) = (dir.join("mesh.key"), dir.join("identity.key"));
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
    println!(
        "Private keys are in {} (mode 0600) and stay on this machine.",
        dir.display()
    );
    println!("On the computer that holds the site, add this machine with:");
    println!("  nett site add <name> --keys \"{mesh} {identity}\"");
    println!("(with --public --ipv4 <address> when other machines connect to it)");
}

/// Logs go to standard error (collected into the journal by systemd on Linux). When running as a
/// launchd service on macOS (standard error is not a terminal), they go to the system log: the
/// standard error file only records startup failures, and launchd reopens it each time it starts
/// the process, so rotation works.
pub(crate) fn init_logging() {
    let builder = tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::INFO)
        .with_ansi(std::io::stderr().is_terminal());
    #[cfg(target_os = "macos")]
    if !std::io::stderr().is_terminal() {
        builder
            .without_time()
            .with_ansi(false)
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

    // Read the trust store first, then the desired state (design/mesh.md section 4.2)
    let trust = TrustStore::open(Box::new(DirBackend::new(args.state.clone())));
    let node_id = match trust.node_id() {
        Some(id) => id.clone(),
        None => node_id(&args.config)?,
    };
    let key = PrivateKey::load(&args.key)?;
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
            FileSource::new(args.config.clone(), reload_rx)
                .context("installing the SIGHUP handler")?,
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
    #[cfg(feature = "lab")]
    let sink: Box<dyn EventSink + Send> = match args.lab.transport_config.clone() {
        Some(path) => Box::new(TransportConfigWriter::new(sink, path)),
        None => sink,
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
    // Linux uses kernel WireGuard by default; macOS is a native member and uses the userspace data
    // plane (design/userspace.md)
    #[cfg(all(target_os = "linux", feature = "lab"))]
    let userspace = args.lab.userspace;
    #[cfg(all(target_os = "linux", not(feature = "lab")))]
    let userspace = false;
    #[cfg(target_os = "linux")]
    let worker = if userspace {
        let dataplane = UserspaceDataPlane::new(LinuxTun::open()?);
        Runtime::spawn(
            Engine::new(node_id, key, dataplane).with_trust_store(trust),
            sink,
            clock,
            nett_mesh::dns::PORT,
        )
    } else {
        let dataplane = KernelWireGuard::open()?;
        Runtime::spawn(
            Engine::new(node_id, key, dataplane).with_trust_store(trust),
            sink,
            clock,
            nett_mesh::dns::PORT,
        )
    };
    #[cfg(target_os = "macos")]
    let worker = Runtime::spawn(
        Engine::new(node_id, key, UserspaceDataPlane::new(MacTun::open()?)).with_trust_store(trust),
        sink,
        clock,
        nett_mesh::dns::PORT,
    );
    let worker = worker.context("starting the mesh worker thread")?;
    // The local interface is only for people and nett-node: if the socket cannot be created, record
    // it and continue meshing as usual (hard rule 8)
    let helpers_path = nett_mesh::helper::socket_path(&args.socket);
    let helpers = match HelperServer::spawn(&helpers_path, worker.status_source(reload_tx.clone()))
    {
        Ok(server) => Some(server),
        Err(e) => {
            tracing::warn!(socket = %helpers_path.display(), error = %e, "helper socket unavailable; nett-relay and the transport adapter cannot fetch their configuration");
            None
        }
    };
    let status = match StatusServer::spawn(&args.socket, worker.status_source(reload_tx)) {
        Ok(server) => Some(server),
        Err(e) => {
            tracing::warn!(socket = %args.socket.display(), error = %e, "status socket unavailable; `nett status` will not work");
            None
        }
    };

    runtime.block_on(async move {
        let shutdown = async move {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = interrupt.recv() => {}
            }
        };
        let worker = nett_mesh::run::run(source, worker, shutdown).await?;
        drop(status);
        drop(helpers);
        tokio::task::spawn_blocking(move || worker.shutdown())
            .await
            .context("stopping the mesh worker")?
            .map_err(anyhow::Error::msg)?;
        tracing::info!("mesh process stopped; the interface stays up");
        anyhow::Ok(())
    })
}
