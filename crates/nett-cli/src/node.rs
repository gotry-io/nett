//! `nett node`: the control agent nett-node (design/hub.md sections 5 and 7), run as root by
//! systemd or launchd. Reads this machine's Hub configuration and identity key, connects to the
//! Hub, hands the desired state to the mesh process, reports status and installs new releases
//! (design/release.md section 7). Tokio single-threaded runtime.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context as _;
use nett_mesh::key::PrivateKey;
use nett_node::config::{HUB_FILE, HubConfig};
use nett_node::session::{Exit, Node};
use nett_node::upgrade::{ServiceManager, Start, Upgrader};
use tokio::signal::unix::{SignalKind, signal};

/// This machine's configuration directory: Hub configuration, identity key and desired state.
#[cfg(target_os = "linux")]
pub const DEFAULT_DIR: &str = "/etc/nett";
#[cfg(target_os = "macos")]
pub const DEFAULT_DIR: &str = "/Library/Application Support/nett";

pub const USAGE: &str = "usage: nett node [--dir <directory>] [--socket <path>]\n\n\
Connects this machine to its Hub and hands the desired state to the mesh service. Started by\n\
systemd or launchd after `sudo nett install <token>`. The directory holds hub.json,\n\
identity.key and desired.json; it defaults to /etc/nett on Linux and\n\
/Library/Application Support/nett on macOS.";

pub fn run(mut parser: lexopt::Parser) -> anyhow::Result<()> {
    let mut dir = PathBuf::from(DEFAULT_DIR);
    let mut socket = PathBuf::from(nett_mesh::status::DEFAULT_SOCKET);
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Long("dir") => dir = PathBuf::from(parser.value()?),
            lexopt::Arg::Long("socket") => socket = PathBuf::from(parser.value()?),
            other => return Err(other.unexpected().into()),
        }
    }
    crate::mesh::init_logging();
    let config = HubConfig::load(&dir)
        .map_err(anyhow::Error::msg)?
        .with_context(|| {
            format!(
                "{} does not exist; `sudo nett install <token>` connects this machine to a Hub",
                dir.join(HUB_FILE).display()
            )
        })?;
    let identity = PrivateKey::load(&dir.join("identity.key"))?;
    let upgrader = upgrader(&dir, &socket).map(Arc::new);
    if let Some(upgrader) = &upgrader
        && let Start::RolledBack(reason) = upgrader.on_start()
    {
        // Exit so that the service manager starts the restored program
        anyhow::bail!("{reason}");
    }
    let node = Node {
        config,
        identity: x25519_dalek::StaticSecret::from(*identity.as_bytes()),
        desired: dir.join("desired.json"),
        socket,
        upgrader,
    };
    drop(identity);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    runtime.block_on(async {
        let mut term = signal(SignalKind::terminate()).context("installing the SIGTERM handler")?;
        let shutdown = async move {
            tokio::select! {
                _ = term.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
        };
        tracing::info!(version = env!("CARGO_PKG_VERSION"), "nett-node starting");
        match nett_node::session::run(node, shutdown).await {
            Exit::Shutdown => tracing::info!("nett-node stopped"),
            // The service manager starts nett-node again from the new program
            Exit::Upgraded => tracing::info!("nett-node exits to run the new version"),
        }
        anyhow::Ok(())
    })
}

/// The upgrader for this machine's layout (design/release.md section 7); `None` when this build
/// has no release target or its release keys do not parse.
fn upgrader(dir: &std::path::Path, socket: &std::path::Path) -> Option<Upgrader> {
    let target = nett_trust::release::current_target()?;
    let keys = match nett_trust::release::ReleaseKeys::built_in() {
        Ok(keys) => keys,
        Err(e) => {
            tracing::error!(error = %e, "the release keys built into nett; upgrades are off");
            return None;
        }
    };
    let current = env!("CARGO_PKG_VERSION").parse().ok()?;
    let (program, command) = if cfg!(target_os = "macos") {
        (
            nett_node::platform::macos::PROGRAM,
            Some(PathBuf::from(nett_node::platform::macos::COMMAND)),
        )
    } else {
        (nett_node::platform::linux::PROGRAM, None)
    };
    Some(Upgrader {
        keys,
        target: target.to_owned(),
        current,
        program: PathBuf::from(program),
        command,
        dir: dir.to_path_buf(),
        services: Arc::new(ServiceManager {
            socket: socket.to_path_buf(),
        }),
        mesh_start: nett_node::upgrade::MESH_START,
    })
}
