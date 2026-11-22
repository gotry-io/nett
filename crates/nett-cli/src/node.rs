//! nett-node inside the nett daemon (design/hub.md sections 5 and 7, ADR 0013): with a Hub
//! configuration in the daemon's directory it connects this machine to its Hub, hands the desired
//! state to the mesh in the same process, reports status and installs new releases
//! (design/release.md section 7), on a thread of its own with a single-threaded runtime.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;
use nett_mesh::key::PrivateKey;
use nett_mesh::status::StatusSource;
use nett_node::config::{HUB_FILE, HubConfig};
use nett_node::daemon::{Ended, NodeThread};
use nett_node::session::{Exit, Node};
use nett_node::upgrade::{Install, ServiceManager, Start, Upgrader};

use crate::daemon::{DESIRED_FILE, IDENTITY_KEY_FILE};

/// This machine's directory where `sudo nett install` puts it: keys, desired state, Hub
/// configuration and trust store.
#[cfg(target_os = "linux")]
pub const DEFAULT_DIR: &str = nett_node::platform::linux::CONFIG_DIR;
#[cfg(target_os = "macos")]
pub const DEFAULT_DIR: &str = nett_node::platform::macos::DIR;

/// nett-node in the daemon, before and after the mesh starts.
pub(crate) struct InDaemon {
    dir: PathBuf,
    services: Arc<ServiceManager>,
    upgrader: Option<Arc<Upgrader>>,
}

impl InDaemon {
    /// Before the mesh starts: `None` without a Hub configuration in `dir`; otherwise the start of a
    /// newly installed version is counted, so that one whose mesh exits goes back too. An error is
    /// a rollback: the service exits so that the service manager starts the restored program.
    pub(crate) fn prepare(dir: &Path) -> anyhow::Result<Option<Self>> {
        if !dir.join(HUB_FILE).exists() {
            return Ok(None);
        }
        let services = Arc::new(ServiceManager::default());
        let upgrader = upgrader(dir, Arc::clone(&services)).map(Arc::new);
        if let Some(upgrader) = &upgrader
            && let Start::RolledBack(reason) = upgrader.on_start()
        {
            anyhow::bail!("{reason}");
        }
        Ok(Some(Self {
            dir: dir.to_path_buf(),
            services,
            upgrader,
        }))
    }

    /// Once the mesh runs: nett-node on its own thread; `ended` hears when the service is to exit.
    pub(crate) fn spawn(
        self,
        mesh: Arc<dyn StatusSource + Sync>,
        ended: tokio::sync::oneshot::Sender<Ended>,
    ) -> std::io::Result<NodeThread> {
        self.services.attach(Arc::clone(&mesh));
        NodeThread::spawn(
            move |stop| {
                self.run_once(Arc::clone(&mesh), stop)
                    .map_err(|e| format!("{e:#}"))
            },
            nett_node::daemon::RESTART_AFTER,
            ended,
        )
    }

    fn run_once(
        &self,
        mesh: Arc<dyn StatusSource + Sync>,
        mut stop: tokio::sync::watch::Receiver<bool>,
    ) -> anyhow::Result<Ended> {
        if let Some(upgrader) = &self.upgrader
            && let Start::RolledBack(reason) = upgrader.check_started()
        {
            return Ok(Ended::RolledBack(reason));
        }
        // The units follow the program (design/release.md section 7)
        let managed = nett_node::services::managed();
        if managed {
            match nett_node::services::refresh_units() {
                Ok(true) => return Ok(Ended::UnitChanged),
                Ok(false) => {}
                Err(e) => tracing::warn!(error = %e, "refreshing nett's units"),
            }
        }
        let node = load(&self.dir, mesh, self.upgrader.clone(), managed)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("starting nett-node's runtime")?;
        tracing::info!(version = env!("CARGO_PKG_VERSION"), "nett-node starting");
        let exit = runtime.block_on(nett_node::session::run(node, async move {
            let _ = stop.wait_for(|stop| *stop).await;
        }));
        // An upgrade's install runs on a blocking thread and finishes before the service exits
        runtime.shutdown_timeout(nett_node::daemon::STOP_WAIT);
        Ok(match exit {
            Exit::Shutdown => Ended::Stopped,
            Exit::Upgraded => Ended::Upgraded,
        })
    }
}

/// nett-node from this machine's Hub configuration and identity key in `dir`.
fn load(
    dir: &Path,
    mesh: Arc<dyn StatusSource + Sync>,
    upgrader: Option<Arc<Upgrader>>,
    managed: bool,
) -> anyhow::Result<Node> {
    let config = HubConfig::load(dir)
        .map_err(anyhow::Error::msg)?
        .with_context(|| {
            format!(
                "{} does not exist; `sudo nett install <token>` connects this machine to a Hub",
                dir.join(HUB_FILE).display()
            )
        })?;
    let identity = PrivateKey::load(&dir.join(IDENTITY_KEY_FILE))?;
    Ok(Node {
        config,
        identity: x25519_dalek::StaticSecret::from(*identity.as_bytes()),
        desired: dir.join(DESIRED_FILE),
        mesh,
        upgrader,
        link: Arc::new(nett_node::fetch::HubLink::new()),
        services: managed.then(|| std::sync::Mutex::new(None)),
    })
}

/// The upgrader for this machine's layout (design/release.md section 7); `None` where nett did not
/// install the services (a lab, another service manager), or when this build has no release
/// target or its release keys do not parse. In the container it places the new version in the
/// volume (design/container.md section 6).
fn upgrader(dir: &Path, services: Arc<ServiceManager>) -> Option<Upgrader> {
    #[cfg(target_os = "linux")]
    if let Some(state) = crate::container::state_dir()
        && state == dir
    {
        let staged = crate::container::staged(&state)?;
        return Some(Upgrader {
            keys: staged.keys.clone(),
            target: staged.target.clone(),
            current: staged.current,
            program: staged.program(),
            dir: state,
            install: Install::Stage(Arc::new(staged)),
        });
    }
    let installed = if cfg!(target_os = "macos") {
        Path::new(nett_node::platform::macos::PROGRAM).exists()
    } else {
        Path::new(nett_node::platform::linux::PROGRAM).exists()
            && nett_node::platform::linux::systemctl().is_some()
    };
    if !installed {
        return None;
    }
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
        dir: dir.to_path_buf(),
        install: Install::Replace {
            command,
            services,
            mesh_start: nett_node::upgrade::MESH_START,
        },
    })
}
