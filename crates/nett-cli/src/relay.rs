//! `nett relay`（实验构建）：中继分配读自本地文件，收到 `SIGTERM` 或 `SIGINT` 时退出。

use std::io::IsTerminal as _;
use std::path::PathBuf;

use anyhow::{Context as _, bail};
use nett_relay::lab::RelayConfig;
use nett_relay::server::{TlsIngress, serve, tls_acceptor, tls_listener};
use tokio::signal::unix::{SignalKind, signal};

pub const USAGE: &str = "usage: nett relay --config <relay.json> [--state <relay-state.json>]";

pub fn run(mut parser: lexopt::Parser) -> anyhow::Result<()> {
    let (mut config, mut state) = (None, None);
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Long("config") => config = Some(PathBuf::from(parser.value()?)),
            lexopt::Arg::Long("state") => state = Some(PathBuf::from(parser.value()?)),
            other => return Err(other.unexpected().into()),
        }
    }
    let Some(config) = config else {
        bail!(USAGE);
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

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    runtime.block_on(async move {
        let udp = tokio::net::UdpSocket::bind(config.listen)
            .await
            .with_context(|| format!("binding {}", config.listen))?;
        let tls = match &config.tls {
            Some(doc) => {
                let acceptor = tls_acceptor(&doc.cert, &doc.key).context("TLS ingress")?;
                let listener =
                    tls_listener(doc.listen).with_context(|| format!("binding {}", doc.listen))?;
                Some(TlsIngress { listener, acceptor })
            }
            None => None,
        };
        tracing::info!(
            listen = %config.listen,
            tls = ?config.tls.as_ref().map(|t| t.listen),
            members = config.members.len(),
            "relay started"
        );
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
        serve(udp, tls, relay, state, shutdown)
            .await
            .context("relay socket")
    })
}
