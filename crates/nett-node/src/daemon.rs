//! nett-node inside the nett daemon (ADR 0013): it runs on a thread of its own, with its own
//! single-threaded runtime, and calls the mesh in the same process directly. A run that panics or
//! cannot start ends that run only: the mesh keeps working as while the Hub is away, and nett-node
//! starts again after [`RESTART_AFTER`].

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::watch;

/// As a service manager restarts a service, at most every 5 seconds.
pub const RESTART_AFTER: Duration = Duration::from_secs(5);
/// How long the daemon waits for nett-node to stop when the service stops.
pub const STOP_WAIT: Duration = Duration::from_secs(3);
/// How often the wait between runs looks whether nett-node is to stop.
const STOP_POLL: Duration = Duration::from_millis(100);

/// How nett-node ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Ended {
    /// It was asked to stop.
    Stopped,
    /// A new version is installed: the service exits so that the service manager starts it.
    Upgraded,
    /// The new version did not come up and the previous program is back, for this reason: the
    /// service exits so that the service manager starts it.
    RolledBack(String),
    /// The service's own unit changed with the program: the service exits so that systemd starts
    /// it with the new one (design/release.md section 7).
    UnitChanged,
}

/// nett-node's thread, owned by the daemon.
pub struct NodeThread {
    stop: watch::Sender<bool>,
    done: std::sync::mpsc::Receiver<()>,
}

impl NodeThread {
    /// Starts nett-node's thread. `run` runs nett-node once, until the receiver it gets turns `true`:
    /// `Ok` says how it ended, `Err` why it could not start. A run that panics or could not start
    /// is tried again after `restart_after`. `ended` hears how nett-node ended for good.
    pub fn spawn<F>(
        run: F,
        restart_after: Duration,
        ended: tokio::sync::oneshot::Sender<Ended>,
    ) -> std::io::Result<Self>
    where
        F: Fn(watch::Receiver<bool>) -> Result<Ended, String> + Send + Sync + 'static,
    {
        let (stop, stopped) = watch::channel(false);
        let (finished, done) = std::sync::mpsc::sync_channel(1);
        let run = Arc::new(run);
        std::thread::Builder::new()
            .name("nett-node".into())
            .spawn(move || {
                let ended_as = supervise(&*run, &stopped, restart_after);
                let _ = ended.send(ended_as);
                let _ = finished.send(());
            })?;
        Ok(Self { stop, done })
    }

    /// Asks nett-node to stop and waits for it, at most `within`; returns whether it stopped.
    pub fn stop(self, within: Duration) -> bool {
        let _ = self.stop.send(true);
        self.done.recv_timeout(within).is_ok()
    }
}

fn supervise<F>(run: &F, stopped: &watch::Receiver<bool>, restart_after: Duration) -> Ended
where
    F: Fn(watch::Receiver<bool>) -> Result<Ended, String>,
{
    loop {
        // Each run builds nett-node anew from its files, so nothing a panicked run left half done
        // is used again
        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(stopped.clone())));
        let why = match outcome {
            Ok(Ok(ended)) => return ended,
            Ok(Err(e)) => format!("nett-node could not start: {e}"),
            Err(_) => "nett-node panicked".to_owned(),
        };
        tracing::error!(
            %why,
            after_secs = restart_after.as_secs(),
            "nett-node starts again; the mesh keeps working meanwhile"
        );
        let until = Instant::now() + restart_after;
        loop {
            if *stopped.borrow() {
                return Ended::Stopped;
            }
            let now = Instant::now();
            if now >= until {
                break;
            }
            std::thread::sleep(STOP_POLL.min(until - now));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// A run that panics ends that run only, and nett-node runs again; an ending is passed on
    #[test]
    fn a_panicking_run_starts_again() {
        let runs = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&runs);
        let (ended_tx, ended_rx) = tokio::sync::oneshot::channel();
        let thread = NodeThread::spawn(
            move |_stop| match counted.fetch_add(1, Ordering::SeqCst) {
                0 => panic!("a bug in nett-node"),
                1 => Err("hub.json does not parse".to_owned()),
                _ => Ok(Ended::Upgraded),
            },
            Duration::from_millis(10),
            ended_tx,
        )
        .expect("thread");
        assert_eq!(ended_rx.blocking_recv().expect("ended"), Ended::Upgraded);
        assert_eq!(runs.load(Ordering::SeqCst), 3);
        assert!(thread.stop(Duration::from_secs(1)));
    }

    /// Stopping ends a running nett-node, and the wait before a run that would start again
    #[test]
    fn stopping_ends_a_run_and_the_wait_before_the_next() {
        let (ended_tx, ended_rx) = tokio::sync::oneshot::channel();
        let thread = NodeThread::spawn(
            |mut stop: watch::Receiver<bool>| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .build()
                    .map_err(|e| e.to_string())?;
                runtime.block_on(async {
                    let _ = stop.wait_for(|stop| *stop).await;
                });
                Ok(Ended::Stopped)
            },
            Duration::from_secs(60),
            ended_tx,
        )
        .expect("thread");
        assert!(thread.stop(Duration::from_secs(1)));
        assert_eq!(ended_rx.blocking_recv().expect("ended"), Ended::Stopped);

        let (ended_tx, ended_rx) = tokio::sync::oneshot::channel();
        let thread = NodeThread::spawn(
            |_stop| Err("cannot start".to_owned()),
            Duration::from_secs(60),
            ended_tx,
        )
        .expect("thread");
        std::thread::sleep(Duration::from_millis(50));
        assert!(thread.stop(Duration::from_secs(1)));
        assert_eq!(ended_rx.blocking_recv().expect("ended"), Ended::Stopped);
    }
}
