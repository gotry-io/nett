//! `nett mesh`（实验构建）：组网进程，期望状态来自本地文件，收到 `SIGHUP` 时重新读取。

use std::io::IsTerminal as _;
use std::path::PathBuf;

use anyhow::{Context as _, bail};
use nett_core::id::NodeId;
use nett_mesh::engine::Engine;
use nett_mesh::event::{EventSink, LogSink};
use nett_mesh::key::PrivateKey;
use nett_mesh::lab::{FileSource, JsonLinesSink};
use nett_mesh::linux::KernelWireGuard;
use nett_mesh::linux::runtime::Runtime;
use tokio::signal::unix::{SignalKind, signal};

struct Args {
    config: PathBuf,
    key: PathBuf,
    events: Option<PathBuf>,
}

fn parse(mut parser: lexopt::Parser) -> anyhow::Result<Args> {
    let (mut config, mut key, mut events) = (None, None, None);
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Long("config") => config = Some(PathBuf::from(parser.value()?)),
            lexopt::Arg::Long("key") => key = Some(PathBuf::from(parser.value()?)),
            lexopt::Arg::Long("events") => events = Some(PathBuf::from(parser.value()?)),
            other => return Err(other.unexpected().into()),
        }
    }
    match (config, key) {
        (Some(config), Some(key)) => Ok(Args {
            config,
            key,
            events,
        }),
        _ => bail!(
            "usage: nett mesh --config <desired-state.json> --key <mesh.key> [--events <events.jsonl>]"
        ),
    }
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

pub fn run(parser: lexopt::Parser) -> anyhow::Result<()> {
    let args = parse(parser)?;
    tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::INFO)
        .with_ansi(std::io::stderr().is_terminal())
        .with_writer(std::io::stderr)
        .init();

    let node_id = node_id(&args.config)?;
    let key = PrivateKey::load(&args.key)?;
    let dataplane = KernelWireGuard::open()?;
    let sink: Box<dyn EventSink + Send> = match &args.events {
        Some(path) => Box::new(
            JsonLinesSink::create(path).with_context(|| format!("opening {}", path.display()))?,
        ),
        None => Box::new(LogSink),
    };
    let engine = Engine::new(node_id, key, dataplane);
    let worker = Runtime::spawn(engine, sink).context("starting the mesh worker thread")?;

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
        let worker = nett_mesh::run::run(source, worker, shutdown).await?;
        tokio::task::spawn_blocking(move || worker.shutdown())
            .await
            .context("stopping the mesh worker")?
            .map_err(anyhow::Error::msg)?;
        tracing::info!("mesh process stopped; the interface stays up");
        anyhow::Ok(())
    })
}
