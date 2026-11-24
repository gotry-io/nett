//! `nett relay`: nett-relay, the relay's public TCP entry (ADR 0032, design/mesh.md section 5.3). It
//! asks the nett daemon over the helper socket for the relay's TLS port and hand-off port, takes
//! its TLS certificate from `--cert` (systemd's credentials), and hands each TLS connection to the
//! relay in the daemon. Exits on `SIGTERM` or `SIGINT`, and when its ports change (the service
//! manager starts it again).

use std::path::PathBuf;

use anyhow::Context as _;
use tokio::signal::unix::{SignalKind, signal};

pub const USAGE: &str = "usage: nett relay --cert <dir> [--socket <helpers.sock>]\n\n\
Started by systemd on a machine whose relay serves TLS (`nett site relay --tls`).";

pub fn run(mut parser: lexopt::Parser) -> anyhow::Result<()> {
    let mut socket =
        nett_mesh::helper::socket_path(std::path::Path::new(nett_mesh::status::DEFAULT_SOCKET));
    let mut cert = None;
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Long("socket") => socket = PathBuf::from(parser.value()?),
            lexopt::Arg::Long("cert") => cert = Some(PathBuf::from(parser.value()?)),
            other => return Err(other.unexpected().into()),
        }
    }
    let Some(cert) = cert else {
        anyhow::bail!(USAGE);
    };
    tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::INFO)
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
        let cert =
            nett_relay::cert::RelayCert::load(&cert).context("the relay's TLS certificate")?;
        let ended = nett_relay::service::run_entry(socket, cert, shutdown)
            .await
            .context("relay TLS entry")?;
        if ended == nett_relay::service::Ended::PortsChanged {
            tracing::info!("relay TLS entry stopped to listen on its new ports");
        }
        Ok(())
    })
}
