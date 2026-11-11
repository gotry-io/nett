//! Main loop of the mesh process: takes the desired state from the configuration source, hands it to the
//! background thread to apply, until an exit signal is received.
//!
//! On exit the mesh interface is not deleted: WireGuard in the kernel keeps working, and connections in
//! progress are not interrupted while the mesh process restarts.

use std::future::Future;

use crate::config::{ConfigError, DesiredMesh};
use crate::status::ReloadReply;

/// A delivered desired state. `reply` is the party waiting for the apply result when a re-read was
/// requested through the local interface (`nett reload`) (design/status.md section 4.1); the read at
/// startup and `SIGHUP` have none.
pub struct Delivery {
    pub desired: Result<DesiredMesh, ConfigError>,
    pub reply: Option<ReloadReply>,
}

/// Source of the desired state. Lab builds read from a local file; once joined to the Hub, nett-node
/// provides it through the local interface (design/prototype.md section 3).
pub trait ConfigSource {
    /// The next desired state; `None` means the source is closed.
    fn next(&mut self) -> impl Future<Output = Option<Delivery>> + Send;
}

/// The party that receives the desired state (the mesh process's background thread). A call may block and
/// is run by [`run`] on the blocking thread pool.
pub trait Applier: Send + 'static {
    fn apply(&mut self, delivery: Delivery);
}

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("handing over the desired state panicked; this is a bug: {0}")]
    Panicked(String),
}

/// Hands the desired states delivered by the configuration source to `applier` one by one, until the
/// source is closed or an exit signal is received.
pub async fn run<S, A>(
    mut source: S,
    mut applier: A,
    shutdown: impl Future<Output = ()>,
) -> Result<A, RunError>
where
    S: ConfigSource,
    A: Applier,
{
    tokio::pin!(shutdown);
    loop {
        let next = tokio::select! {
            () = &mut shutdown => return Ok(applier),
            next = source.next() => next,
        };
        let Some(next) = next else {
            return Ok(applier);
        };
        applier = tokio::task::spawn_blocking(move || {
            applier.apply(next);
            applier
        })
        .await
        .map_err(|e| RunError::Panicked(e.to_string()))?;
    }
}
