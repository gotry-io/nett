//! `nett mesh`：组网进程，期望状态来自本地文件，收到 `SIGHUP` 时重新读取（design/local-signing.md 第 5 节）。
//! `nett mesh keys` 在本机生成组网私钥和身份私钥（第 3 节）。事件文件、模拟时钟误差和传输适配进程的配置
//! 只在实验构建中（`lab` 特性）。

use std::io::IsTerminal as _;
use std::path::PathBuf;

use anyhow::{Context as _, bail};
use nett_core::id::NodeId;
use nett_mesh::engine::Engine;
use nett_mesh::event::{EventSink, LogSink};
use nett_mesh::key::PrivateKey;
#[cfg(feature = "lab")]
use nett_mesh::lab::{JsonLinesSink, LabClock, TransportConfigWriter};
use nett_mesh::linux::{KernelWireGuard, SystemClock};
use nett_mesh::runtime::Runtime;
use nett_mesh::source::FileSource;
use tokio::signal::unix::{SignalKind, signal};

struct Args {
    config: PathBuf,
    key: PathBuf,
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
}

const USAGE: &str = "usage: nett mesh --config <desired-state.json> --key <mesh.key>\n       \
nett mesh keys --dir <directory>";
#[cfg(feature = "lab")]
const LAB_USAGE: &str = "lab options: [--events <events.jsonl>] [--transport-config <transport.json>] \
[--clock-offset-ms <ms>] [--clock-trusted <yes|no>]";

fn parse(mut parser: lexopt::Parser) -> anyhow::Result<Args> {
    let (mut config, mut key) = (None, None);
    #[cfg(feature = "lab")]
    let mut lab = LabArgs::default();
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Long("config") => config = Some(PathBuf::from(parser.value()?)),
            lexopt::Arg::Long("key") => key = Some(PathBuf::from(parser.value()?)),
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

/// `nett mesh keys --dir <目录>`：生成组网私钥和身份私钥（各一个新文件，已存在时不覆盖），输出写进站点描述的
/// 一行公钥。
fn keys(mut parser: lexopt::Parser) -> anyhow::Result<()> {
    let mut dir = None;
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Long("dir") => dir = Some(PathBuf::from(parser.value()?)),
            other => return Err(other.unexpected().into()),
        }
    }
    let dir = dir.context(USAGE)?;
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let mesh = PrivateKey::generate()?;
    let identity = PrivateKey::generate()?;
    mesh.save_new(&dir.join("mesh.key"))?;
    identity.save_new(&dir.join("identity.key"))?;
    println!(
        "{}",
        crate::text::KEYS_WRITTEN
            .get()
            .replace("{dir}", &dir.display().to_string())
    );
    println!("keys = \"{} {}\"", mesh.public_key(), identity.public_key());
    Ok(())
}

/// 本机的节点 ID：引擎据此确认每份期望状态都是给本机的。
fn node_id(config: &PathBuf) -> anyhow::Result<NodeId> {
    let bytes = std::fs::read(config).with_context(|| format!("reading {}", config.display()))?;
    let doc: serde_json::Value = serde_json::from_slice(&bytes).context("parsing desired state")?;
    doc.get("node_id")
        .and_then(|v| v.as_str())
        .context("desired state has no node_id")?
        .parse()
        .context("desired state node_id")
}

pub fn run(mut parser: lexopt::Parser) -> anyhow::Result<()> {
    let is_keys = parser
        .try_raw_args()
        .is_some_and(|mut raw| raw.next_if(|a| a == "keys").is_some());
    if is_keys {
        return keys(parser);
    }
    let args = parse(parser)?;
    tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::INFO)
        .with_ansi(std::io::stderr().is_terminal())
        .with_writer(std::io::stderr)
        .init();

    let node_id = node_id(&args.config)?;
    let key = PrivateKey::load(&args.key)?;
    let dataplane = KernelWireGuard::open()?;
    #[cfg(feature = "lab")]
    let sink: Box<dyn EventSink + Send> = match &args.lab.events {
        Some(path) => Box::new(
            JsonLinesSink::create(path).with_context(|| format!("opening {}", path.display()))?,
        ),
        None => Box::new(LogSink),
    };
    #[cfg(not(feature = "lab"))]
    let sink: Box<dyn EventSink + Send> = Box::new(LogSink);
    let engine = Engine::new(node_id, key, dataplane);
    #[cfg(feature = "lab")]
    let clock = LabClock {
        inner: SystemClock,
        offset_ms: args.lab.clock_offset_ms,
        trusted: args.lab.clock_trusted,
    };
    #[cfg(not(feature = "lab"))]
    let clock = SystemClock;
    let worker = Runtime::spawn(engine, sink, clock).context("starting the mesh worker thread")?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    runtime.block_on(async move {
        let source = FileSource::new(args.config).context("installing the SIGHUP handler")?;
        let mut terminate =
            signal(SignalKind::terminate()).context("installing the SIGTERM handler")?;
        let mut interrupt =
            signal(SignalKind::interrupt()).context("installing the SIGINT handler")?;
        let shutdown = async move {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = interrupt.recv() => {}
            }
        };
        #[cfg(feature = "lab")]
        let worker = match args.lab.transport_config {
            Some(path) => {
                let writer = TransportConfigWriter::new(worker, path);
                nett_mesh::run::run(source, writer, shutdown)
                    .await?
                    .into_inner()
            }
            None => nett_mesh::run::run(source, worker, shutdown).await?,
        };
        #[cfg(not(feature = "lab"))]
        let worker = nett_mesh::run::run(source, worker, shutdown).await?;
        tokio::task::spawn_blocking(move || worker.shutdown())
            .await
            .context("stopping the mesh worker")?
            .map_err(anyhow::Error::msg)?;
        tracing::info!("mesh process stopped; the interface stays up");
        anyhow::Ok(())
    })
}
