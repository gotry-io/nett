//! `nett relay`: the relay service (design/mesh.md section 5.2). It fetches its assignment from the
//! mesh process over the helper socket and keeps its TLS certificate in its state directory; the lab
//! build can instead read the assignment from a local file (`--config`). Exits on `SIGTERM` or
//! `SIGINT`, and when the assignment changes its ports (the service manager starts it again).

use std::io::IsTerminal as _;
use std::path::PathBuf;

use anyhow::Context as _;
use tokio::signal::unix::{SignalKind, signal};

/// The state directory of the relay service (`StateDirectory=nett-relay`).
const STATE_DIR: &str = "/var/lib/nett-relay";

pub const USAGE: &str = "usage: nett relay [--socket <helpers.sock>] [--state <dir>]\n\n\
Started by systemd on a machine that runs a relay (`nett site relay`).";
#[cfg(feature = "lab")]
const LAB_USAGE: &str = "lab: nett relay --config <relay.json> [--state <relay-state.json>] reads its assignment from a file";

pub fn run(mut parser: lexopt::Parser) -> anyhow::Result<()> {
    let mut socket =
        nett_mesh::helper::socket_path(std::path::Path::new(nett_mesh::status::DEFAULT_SOCKET));
    let mut state = None;
    #[cfg(feature = "lab")]
    let mut config = None;
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Long("socket") => socket = PathBuf::from(parser.value()?),
            lexopt::Arg::Long("state") => state = Some(PathBuf::from(parser.value()?)),
            #[cfg(feature = "lab")]
            lexopt::Arg::Long("config") => config = Some(PathBuf::from(parser.value()?)),
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
        #[cfg(feature = "lab")]
        if let Some(config) = config {
            return lab(config, state, shutdown).await;
        }
        let state = state.unwrap_or_else(|| PathBuf::from(STATE_DIR));
        let ended = nett_relay::service::run(socket, state, shutdown)
            .await
            .context("relay")?;
        if ended == nett_relay::service::Ended::PortsChanged {
            tracing::info!("relay stopped to bind its new ports");
        }
        Ok(())
    })
}

/// The lab build: the assignment comes from a file written by `nett-lab` (design/prototype.md
/// section 3).
#[cfg(feature = "lab")]
async fn lab(
    config: PathBuf,
    state: Option<PathBuf>,
    shutdown: impl std::future::Future<Output = ()>,
) -> anyhow::Result<()> {
    use nett_relay::lab::RelayConfig;
    use nett_relay::server::{TlsIngress, serve, tls_acceptor, tls_listener};
    let text = std::fs::read(&config).with_context(|| format!("reading {}", config.display()))?;
    let config: RelayConfig =
        serde_json::from_slice(&text).context("parsing the relay assignment")?;
    let relay = config.relay().context("relay assignment")?;
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
        "relay started ({LAB_USAGE})"
    );
    serve(udp, tls, relay, state, None, shutdown)
        .await
        .context("relay socket")
}
