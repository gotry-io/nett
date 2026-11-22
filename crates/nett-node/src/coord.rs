//! The coordination connection to the mesh in the same process (design/status.md section 4.2):
//! nett-node keeps it open, tells the mesh whether the Hub session is up, and passes switch messages
//! between it and the Hub (design/mesh.md section 8.4). It is a socket pair whose other end the mesh
//! reads on a thread of its own; it outlives Hub sessions, and a new one replaces it when nett-node
//! starts again.

use std::sync::Arc;
use std::time::Duration;

use nett_mesh::coord::{Line, MAX_LINE, PathSwitchLine};
use nett_mesh::status::StatusSource;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, watch};

/// Bound of the queues in each direction (design/status.md section 4.2).
pub const QUEUE: usize = 16;
/// Wait before connecting again after the connection ended or could not be made.
const RETRY: Duration = Duration::from_secs(5);

/// nett-node's end: what goes to the mesh and what comes from it.
pub struct Coordination {
    /// Whether the Hub session is up; the mesh gets it on every change and every new connection.
    pub hub: watch::Sender<bool>,
    /// Switch messages from the Hub for the mesh.
    pub to_mesh: mpsc::Sender<PathSwitchLine>,
    /// Switch messages from the mesh for the Hub.
    pub from_mesh: tokio::sync::Mutex<mpsc::Receiver<PathSwitchLine>>,
}

impl Coordination {
    pub fn start(mesh: Arc<dyn StatusSource + Sync>) -> Self {
        let (hub, hub_rx) = watch::channel(false);
        let (to_mesh, to_mesh_rx) = mpsc::channel(QUEUE);
        let (from_mesh_tx, from_mesh) = mpsc::channel(QUEUE);
        tokio::spawn(keep(mesh, hub_rx, to_mesh_rx, from_mesh_tx));
        Self {
            hub,
            to_mesh,
            from_mesh: tokio::sync::Mutex::new(from_mesh),
        }
    }
}

async fn keep(
    mesh: Arc<dyn StatusSource + Sync>,
    mut hub: watch::Receiver<bool>,
    mut to_mesh: mpsc::Receiver<PathSwitchLine>,
    from_mesh: mpsc::Sender<PathSwitchLine>,
) {
    loop {
        match connect(&*mesh) {
            Ok(connected) => {
                tracing::debug!("coordinating with the mesh");
                if let Err(e) = serve(connected, &mut hub, &mut to_mesh, &from_mesh).await {
                    tracing::debug!(error = %e, "coordination with the mesh ended");
                }
            }
            Err(e) => tracing::warn!(error = %e, "coordination with the mesh"),
        }
        if from_mesh.is_closed() {
            return;
        }
        tokio::time::sleep(RETRY).await;
    }
}

struct Connected {
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: tokio::net::unix::OwnedWriteHalf,
}

/// A socket pair: the mesh takes one end, this end is nett-node's.
fn connect(mesh: &dyn StatusSource) -> std::io::Result<Connected> {
    let (ours, theirs) = std::os::unix::net::UnixStream::pair()?;
    mesh.coordinate(theirs)?;
    ours.set_nonblocking(true)?;
    let (read, writer) = UnixStream::from_std(ours)?.into_split();
    Ok(Connected {
        reader: BufReader::new(read),
        writer,
    })
}

async fn serve(
    connected: Connected,
    hub: &mut watch::Receiver<bool>,
    to_mesh: &mut mpsc::Receiver<PathSwitchLine>,
    from_mesh: &mpsc::Sender<PathSwitchLine>,
) -> std::io::Result<()> {
    let Connected {
        mut reader,
        mut writer,
    } = connected;
    // The lines from the mesh are read on their own task, so that a partly read line is never
    // dropped by the writes below
    let forward = from_mesh.clone();
    let mut reading = tokio::spawn(async move {
        let mut line = String::new();
        loop {
            line.clear();
            match (&mut reader)
                .take(MAX_LINE as u64 + 1)
                .read_line(&mut line)
                .await
            {
                Ok(0) | Err(_) => return,
                Ok(n) if n > MAX_LINE => return,
                Ok(_) => {}
            }
            if let Some(p) = Line::decode(&line).and_then(|l| l.path_switch) {
                // Dropped when the Hub session does not keep up: the mesh resends
                let _ = forward.try_send(p);
            }
        }
    });
    let up = *hub.borrow_and_update();
    let result = async {
        writer.write_all(&Line::hub(up).encode()).await?;
        loop {
            tokio::select! {
                _ = &mut reading => return Ok(()),
                changed = hub.changed() => {
                    if changed.is_err() {
                        return Ok(());
                    }
                    let up = *hub.borrow_and_update();
                    writer.write_all(&Line::hub(up).encode()).await?;
                }
                message = to_mesh.recv() => {
                    let Some(p) = message else { return Ok(()) };
                    writer.write_all(&Line::path_switch(p.peer, p.message).encode()).await?;
                }
            }
        }
    }
    .await;
    reading.abort();
    result
}
