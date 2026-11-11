//! The coordination connection to the mesh process (design/status.md section 4.2): nett-node keeps it
//! open, tells the mesh process whether the Hub session is up, and passes switch messages between it and
//! the Hub (design/mesh.md section 8.4). The connection is local and outlives Hub sessions; it reconnects
//! when the mesh process restarts.

use std::path::PathBuf;
use std::time::Duration;

use nett_mesh::coord::{ACCEPTED, Line, MAX_LINE, PathSwitchLine};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, watch};

/// Bound of the queues in each direction (design/status.md section 4.2).
pub const QUEUE: usize = 16;
/// Wait before connecting again after the mesh process could not be reached.
const RETRY: Duration = Duration::from_secs(5);
/// Time limit for the mesh process to accept the connection.
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(2);

/// nett-node's end: what goes to the mesh process and what comes from it.
pub struct Coordination {
    /// Whether the Hub session is up; the mesh process gets it on every change and every reconnect.
    pub hub: watch::Sender<bool>,
    /// Switch messages from the Hub for the mesh process.
    pub to_mesh: mpsc::Sender<PathSwitchLine>,
    /// Switch messages from the mesh process for the Hub.
    pub from_mesh: tokio::sync::Mutex<mpsc::Receiver<PathSwitchLine>>,
}

impl Coordination {
    /// Starts the task that keeps the connection to the mesh process at `socket`.
    pub fn start(socket: PathBuf) -> Self {
        let (hub, hub_rx) = watch::channel(false);
        let (to_mesh, to_mesh_rx) = mpsc::channel(QUEUE);
        let (from_mesh_tx, from_mesh) = mpsc::channel(QUEUE);
        tokio::spawn(keep(socket, hub_rx, to_mesh_rx, from_mesh_tx));
        Self {
            hub,
            to_mesh,
            from_mesh: tokio::sync::Mutex::new(from_mesh),
        }
    }
}

async fn keep(
    socket: PathBuf,
    mut hub: watch::Receiver<bool>,
    mut to_mesh: mpsc::Receiver<PathSwitchLine>,
    from_mesh: mpsc::Sender<PathSwitchLine>,
) {
    loop {
        match connect(&socket).await {
            Ok(connected) => {
                tracing::debug!("coordinating with the mesh process");
                if let Err(e) = serve(connected, &mut hub, &mut to_mesh, &from_mesh).await {
                    tracing::debug!(error = %e, "coordination with the mesh process ended");
                }
            }
            Err(e) => tracing::debug!(error = %e, "coordination with the mesh process"),
        }
        // The task ends with the runtime; nothing else owns it
        if from_mesh.is_closed() {
            return;
        }
        tokio::time::sleep(RETRY).await;
    }
}

/// A connection the mesh process accepted: the reader of its lines and the writer.
struct Connected {
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: tokio::net::unix::OwnedWriteHalf,
}

async fn connect(socket: &std::path::Path) -> std::io::Result<Connected> {
    let (read, mut writer) = UnixStream::connect(socket).await?.into_split();
    writer
        .write_all(b"{\"v\":1,\"query\":\"coordinate\"}\n")
        .await?;
    let mut reader = BufReader::new(read);
    let mut line = String::new();
    tokio::time::timeout(
        ACCEPT_TIMEOUT,
        (&mut reader).take(MAX_LINE as u64).read_line(&mut line),
    )
    .await
    .map_err(|_| std::io::Error::other("the mesh process did not accept in time"))??;
    if line.trim_end() != ACCEPTED {
        // An older mesh process without coordination answers with an error
        return Err(std::io::Error::other(format!(
            "the mesh process does not coordinate: {}",
            line.trim_end().chars().take(200).collect::<String>()
        )));
    }
    Ok(Connected { reader, writer })
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
    // The lines from the mesh process are read on their own task, so that a partly read line is never
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
                // Dropped when the Hub session does not keep up: the mesh process resends
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
