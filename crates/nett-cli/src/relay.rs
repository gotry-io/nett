//! `nett relay`: the relay service (design/mesh.md section 5.2). It fetches its assignment from the
//! mesh process over the helper socket, takes its TLS certificate from `--cert` (systemd's
//! credentials) and saves its bindings to `--state`; the lab build can instead read the assignment
//! from a local file (`--config`). Exits on `SIGTERM` or `SIGINT`, and when the assignment changes its
//! ports (the service manager starts it again).

use std::io::IsTerminal as _;
use std::path::PathBuf;

use anyhow::Context as _;
use tokio::signal::unix::{SignalKind, signal};

/// Where the units of 0.3.13 and earlier kept the certificate and the bindings, which they start the
/// relay without paths for (design/release.md section 8); there the certificate is created when
/// missing.
const OLD_DIR: &str = nett_node::platform::linux::OLD_RELAY_DIR;

pub const USAGE: &str = "usage: nett relay [--socket <helpers.sock>] [--cert <dir>] [--state <file>]\n\n\
Started by systemd on a machine that runs a relay (`nett site relay`).";
#[cfg(feature = "lab")]
const LAB_USAGE: &str = "lab: nett relay --config <relay.json> [--state <relay-state.json>] reads its assignment from a file";

pub fn run(mut parser: lexopt::Parser) -> anyhow::Result<()> {
    let mut socket =
        nett_mesh::helper::socket_path(std::path::Path::new(nett_mesh::status::DEFAULT_SOCKET));
    let (mut cert, mut state) = (None, None);
    #[cfg(feature = "lab")]
    let mut config = None;
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Long("socket") => socket = PathBuf::from(parser.value()?),
            lexopt::Arg::Long("cert") => cert = Some(PathBuf::from(parser.value()?)),
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
        let cert = match cert {
            Some(dir) => nett_relay::cert::RelayCert::load(&dir),
            None => nett_relay::cert::RelayCert::load_or_create(std::path::Path::new(OLD_DIR)),
        }
        .context("the relay's TLS certificate")?;
        let state = state
            .unwrap_or_else(|| std::path::Path::new(OLD_DIR).join(nett_relay::service::STATE_FILE));
        let ended = nett_relay::service::run(socket, cert, state, shutdown)
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
