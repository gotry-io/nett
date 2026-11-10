//! `nett node`：控制代理 nett-node（design/hub.md 第 5、7 节），由 systemd 或 launchd 以 root 运行。读本机的
//! Hub 配置和身份密钥，连接 Hub，把期望状态交给组网进程，上报状态。tokio 单线程运行时。

use std::path::PathBuf;

use anyhow::Context as _;
use nett_mesh::key::PrivateKey;
use nett_node::config::{HUB_FILE, HubConfig};
use nett_node::session::Node;
use tokio::signal::unix::{SignalKind, signal};

/// 本机的配置目录：Hub 配置、身份密钥与期望状态。
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
    let node = Node {
        config,
        identity: x25519_dalek::StaticSecret::from(*identity.as_bytes()),
        desired: dir.join("desired.json"),
        socket,
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
        nett_node::session::run(node, shutdown).await;
        tracing::info!("nett-node stopped");
        anyhow::Ok(())
    })
}
