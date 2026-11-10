//! `nett mesh`：组网进程，由服务管理器运行。期望状态来自本地文件，收到 `SIGHUP` 或本机接口的 `reload`
//! 时重新读取（design/local-signing.md 第 5 节、status.md 第 4.1 节）。`nett keys` 在本机生成组网私钥和
//! 身份私钥（local-signing.md 第 3 节）。事件文件、模拟时钟误差和传输适配进程的配置只在实验构建中（`lab` 特性）。

use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use nett_core::id::NodeId;
use nett_mesh::engine::Engine;
use nett_mesh::event::{EventSink, LogSink};
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
    /// 本机状态的套接字（design/status.md 第 3 节）。
    socket: PathBuf,
    /// 信任存储的目录（design/mesh.md 第 4.2 节）。
    state: PathBuf,
    #[cfg(feature = "lab")]
    lab: LabArgs,
}

/// 实验构建的选项。
#[cfg(feature = "lab")]
#[derive(Default)]
struct LabArgs {
    events: Option<PathBuf>,
    /// 模拟时钟误差（design/prototype.md 场景 17）。
    clock_offset_ms: i64,
    clock_trusted: Option<bool>,
    /// 传输适配进程的配置写到这里（design/mesh.md 第 5.3 节）。
    transport_config: Option<PathBuf>,
    /// 用用户态数据面代替内核 WireGuard（design/userspace.md 第 8 节）。
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

/// 实验构建的一个选项；不认识时返回 `false`。
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

/// `nett keys --dir <目录>`：生成组网私钥和身份私钥（各一个新文件，已存在时不覆盖），输出写进站点描述的
/// 一行公钥。
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

/// 本机的组网公钥与身份公钥。两把私钥都还没有时生成（`0600`，不离开本机）；已有时沿用；只有一把时报错，
/// 不覆盖任何一把。
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

/// 打印写进站点描述的一行公钥。
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

/// 日志写到标准错误（Linux 上由 systemd 收进日志）。macOS 上以 launchd 服务运行时（标准错误不是终端）
/// 写进系统日志：标准错误的文件只记录启动失败，launchd 每次启动进程时重新打开它，轮转才有效。
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

    /// 每条日志一个写入器，丢弃时作为一条系统日志写出。
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

/// 还没有信任存储时，本机的节点 ID 取自期望状态文件：引擎据此确认每份期望状态都是给本机的。
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

    // 先读信任存储，再读期望状态（design/mesh.md 第 4.2 节）
    let trust = TrustStore::open(Box::new(DirBackend::new(args.state.clone())));
    let node_id = match trust.node_id() {
        Some(id) => id.clone(),
        None => node_id(&args.config)?,
    };
    let key = PrivateKey::load(&args.key)?;
    // 先装好信号处理：之后的任何时刻收到 SIGHUP（例如 `systemctl reload`）都只是重新读取，不会结束进程
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
    // Linux 默认用内核 WireGuard；macOS 是原生成员，用用户态数据面（design/userspace.md）
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
        )
    } else {
        let dataplane = KernelWireGuard::open()?;
        Runtime::spawn(
            Engine::new(node_id, key, dataplane).with_trust_store(trust),
            sink,
            clock,
        )
    };
    #[cfg(target_os = "macos")]
    let worker = Runtime::spawn(
        Engine::new(node_id, key, UserspaceDataPlane::new(MacTun::open()?)).with_trust_store(trust),
        sink,
        clock,
    );
    let worker = worker.context("starting the mesh worker thread")?;
    // 本机接口只是给人和 nett-node 用的：套接字建不起来时记录下来，组网照常（硬性规则 8）
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
        tokio::task::spawn_blocking(move || worker.shutdown())
            .await
            .context("stopping the mesh worker")?
            .map_err(anyhow::Error::msg)?;
        tracing::info!("mesh process stopped; the interface stays up");
        anyhow::Ok(())
    })
}
