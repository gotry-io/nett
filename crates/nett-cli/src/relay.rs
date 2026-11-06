//! `nett relay`（实验构建）：中继分配读自本地文件，收到 `SIGTERM` 或 `SIGINT` 时退出。

use std::io::IsTerminal as _;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context as _, bail};
use nett_relay::lab::RelayConfig;
use tokio::signal::unix::{SignalKind, signal};

pub fn run(mut parser: lexopt::Parser) -> anyhow::Result<()> {
    let mut config = None;
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Long("config") => config = Some(PathBuf::from(parser.value()?)),
            other => return Err(other.unexpected().into()),
        }
    }
    let Some(config) = config else {
        bail!("usage: nett relay --config <relay.json>");
    };
    tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::INFO)
        .with_ansi(std::io::stderr().is_terminal())
        .with_writer(std::io::stderr)
        .init();

    let text = std::fs::read(&config).with_context(|| format!("reading {}", config.display()))?;
    let config: RelayConfig =
        serde_json::from_slice(&text).context("parsing the relay assignment")?;
    let relay = config.relay().context("relay assignment")?;
    let socket =
        UdpSocket::bind(config.listen).with_context(|| format!("binding {}", config.listen))?;
    tracing::info!(listen = %config.listen, members = config.members.len(), "relay started");

    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = stop.clone();
    let worker = std::thread::Builder::new()
        .name("nett-relay".into())
        .spawn(move || nett_relay::server::serve(&socket, relay, &worker_stop))
        .context("starting the relay thread")?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    runtime.block_on(async {
        let mut terminate =
            signal(SignalKind::terminate()).context("installing the SIGTERM handler")?;
        let mut interrupt =
            signal(SignalKind::interrupt()).context("installing the SIGINT handler")?;
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
        anyhow::Ok(())
    })?;
    stop.store(true, Ordering::Relaxed);
    match worker.join() {
        Ok(result) => result.context("relay socket"),
        Err(_) => bail!("the relay thread panicked; this is a bug"),
    }
}
