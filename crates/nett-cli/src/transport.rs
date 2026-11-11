//! `nett transport`: the transport adapter (design/mesh.md section 5.3). It fetches its configuration
//! from the mesh process over the helper socket; the lab build can instead read a local file the mesh
//! process writes (`--config`). Exits on `SIGTERM` or `SIGINT`.

use std::io::IsTerminal as _;
use std::path::PathBuf;

use anyhow::Context as _;
use nett_transport::forward::ConfigSource;
use tokio::signal::unix::{SignalKind, signal};

pub const USAGE: &str = "usage: nett transport [--socket <helpers.sock>]\n\n\
Started by systemd while this machine has a path over TLS.";

pub fn run(mut parser: lexopt::Parser) -> anyhow::Result<()> {
    let mut source = ConfigSource::Helper(nett_mesh::helper::socket_path(std::path::Path::new(
        nett_mesh::status::DEFAULT_SOCKET,
    )));
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Long("socket") => {
                source = ConfigSource::Helper(PathBuf::from(parser.value()?));
            }
            #[cfg(feature = "lab")]
            lexopt::Arg::Long("config") => {
                source = ConfigSource::File(PathBuf::from(parser.value()?));
            }
            other => return Err(other.unexpected().into()),
        }
    }
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
        nett_transport::forward::run(source, shutdown)
            .await
            .context("transport")
    })
}
