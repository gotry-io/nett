//! `nett transport` (lab build): the transport adapter; its configuration is read from the local
//! file written by the mesh process (ADR 0013); exits on `SIGTERM` or `SIGINT`.

use std::io::IsTerminal as _;
use std::path::PathBuf;

use anyhow::{Context as _, bail};
use tokio::signal::unix::{SignalKind, signal};

pub const USAGE: &str = "usage: nett transport --config <transport.json>";

pub fn run(mut parser: lexopt::Parser) -> anyhow::Result<()> {
    let mut config = None;
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Long("config") => config = Some(PathBuf::from(parser.value()?)),
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
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    runtime.block_on(async move {
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
        nett_transport::forward::run(&config, shutdown)
            .await
            .context("transport")
    })
}
