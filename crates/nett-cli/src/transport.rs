//! `nett transport`: the transport adapter (design/mesh.md section 5.3). It fetches its configuration
//! from the mesh process over the helper socket; the lab build can instead read a local file the mesh
//! process writes (`--config`). On macOS launchd starts it as root, and it switches to its own account
//! before anything else (design/userspace.md section 6.3). Exits on `SIGTERM` or `SIGINT`.

use std::path::PathBuf;

use anyhow::Context as _;
use nett_transport::forward::ConfigSource;
use tokio::signal::unix::{SignalKind, signal};

pub const USAGE: &str = "usage: nett transport [--socket <helpers.sock>]\n\n\
Started by the service manager while this machine has a path over TLS.";

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
    // Before any thread exists, so that every thread runs as the account
    #[cfg(target_os = "macos")]
    if rustix::process::geteuid().is_root() {
        nett_mesh::macos::switch_to_account(nett_mesh::helper::TRANSPORT_USER).with_context(
            || {
                format!(
                    "switching to the account {}",
                    nett_mesh::helper::TRANSPORT_USER
                )
            },
        )?;
    }
    crate::mesh::init_logging();
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
