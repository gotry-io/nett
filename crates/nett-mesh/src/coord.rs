//! The coordination connection with nett-node (design/status.md section 4.2): nett-node keeps it open
//! and passes switch proposals and confirmations between this mesh process and the Hub, so the mesh
//! process never connects to the Hub (design/mesh.md section 8.4). One JSON object per line in each
//! direction; the messages themselves are authenticated end to end by the two mesh processes.

use std::io::{BufRead as _, BufReader, Read as _};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use nett_core::id::NodeId;
use serde::{Deserialize, Serialize};

/// Longest line in either direction.
pub const MAX_LINE: usize = 1024;
/// Longest switch message (design/protocol.md section 5).
pub const MAX_MESSAGE: usize = 64;
/// The first line the mesh process sends after accepting a `coordinate` query.
pub const ACCEPTED: &str = "{\"v\":1,\"coordinating\":true}";
/// Stack of the thread that reads a coordination connection: it only parses short lines.
const READER_STACK: usize = 64 * 1024;

/// One line on the connection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Line {
    /// From nett-node: whether its Hub session is up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hub: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_switch: Option<PathSwitchLine>,
}

/// A switch message: from the mesh process, the peer it is for; from nett-node, the peer it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathSwitchLine {
    pub peer: NodeId,
    #[serde(with = "nett_trust::encoding::b64")]
    pub message: Vec<u8>,
}

impl Line {
    pub fn path_switch(peer: NodeId, message: Vec<u8>) -> Self {
        Self {
            hub: None,
            path_switch: Some(PathSwitchLine { peer, message }),
        }
    }

    pub fn hub(up: bool) -> Self {
        Self {
            hub: Some(up),
            path_switch: None,
        }
    }

    /// The line with its newline.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(self).unwrap_or_default();
        bytes.push(b'\n');
        bytes
    }

    /// Parses one line from the other side: untrusted input (hard rule 13).
    pub fn decode(line: &str) -> Option<Self> {
        let line: Self = serde_json::from_str(line.trim_end()).ok()?;
        if line
            .path_switch
            .as_ref()
            .is_some_and(|p| p.message.len() > MAX_MESSAGE)
        {
            return None;
        }
        Some(line)
    }
}

/// What nett-node tells the mesh process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inbound {
    Hub(bool),
    PathSwitch { peer: NodeId, message: Vec<u8> },
}

/// The current coordination connection, if nett-node holds one.
#[derive(Default)]
pub struct Coordinator {
    current: Mutex<Option<(u64, UnixStream)>>,
    next: AtomicU64,
}

impl Coordinator {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Sends a switch message to nett-node without waiting: it is dropped when no coordinator is
    /// connected or its buffer is full, and the sender tries again.
    pub fn send(&self, peer: &NodeId, message: &[u8]) {
        let line = Line::path_switch(peer.clone(), message.to_vec()).encode();
        let Ok(mut current) = self.current.lock() else {
            return;
        };
        let Some((_, stream)) = current.as_ref() else {
            return;
        };
        match rustix::net::send(stream, &line, rustix::net::SendFlags::DONTWAIT) {
            Ok(n) if n == line.len() => {}
            // A partial line would corrupt the stream: drop the connection, nett-node opens a new one
            Ok(_) => {
                if let Some((_, stream)) = current.take() {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                }
            }
            Err(e) => tracing::debug!(error = %e, "switch message to nett-node dropped"),
        }
    }

    /// Takes over a `coordinate` connection: the previous one is closed, and this one is read on a thread of
    /// its own until nett-node closes it. Each line read is handed to `inbound`; when the connection ends,
    /// the Hub path is gone with it.
    pub fn attach(
        self: &Arc<Self>,
        stream: UnixStream,
        inbound: impl Fn(Inbound) + Send + 'static,
    ) -> std::io::Result<()> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let reader = stream.try_clone()?;
        reader.set_read_timeout(None)?;
        if let Ok(mut current) = self.current.lock()
            && let Some((_, old)) = current.replace((id, stream))
        {
            let _ = old.shutdown(std::net::Shutdown::Both);
        }
        let me = Arc::clone(self);
        std::thread::Builder::new()
            .name("nett-coordinate".into())
            .stack_size(READER_STACK)
            .spawn(move || {
                read_lines(reader, &inbound);
                let ours = me.current.lock().is_ok_and(|mut c| {
                    let ours = c.as_ref().is_some_and(|(i, _)| *i == id);
                    if ours {
                        *c = None;
                    }
                    ours
                });
                if ours {
                    inbound(Inbound::Hub(false));
                }
            })?;
        Ok(())
    }
}

/// Reads lines until the connection ends or a line is too long; lines that do not parse are dropped.
fn read_lines(stream: UnixStream, inbound: &impl Fn(Inbound)) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        match (&mut reader).take(MAX_LINE as u64 + 1).read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(n) if n > MAX_LINE => return,
            Ok(_) => {}
        }
        let Some(parsed) = Line::decode(&line) else {
            continue;
        };
        if let Some(up) = parsed.hub {
            inbound(Inbound::Hub(up));
        }
        if let Some(p) = parsed.path_switch {
            inbound(Inbound::PathSwitch {
                peer: p.peer,
                message: p.message,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::sync::mpsc;

    fn node(n: u8) -> NodeId {
        crate::testutil::node_id(n)
    }

    #[test]
    fn lines_pass_both_ways_and_a_new_connection_replaces_the_old() {
        let coordinator = Coordinator::new();
        let (tx, rx) = mpsc::channel();
        let (mesh_end, mut node_end) = UnixStream::pair().expect("pair");
        let sink = tx.clone();
        coordinator
            .attach(mesh_end, move |i| drop(sink.send(i)))
            .expect("attached");
        node_end
            .write_all(&Line::hub(true).encode())
            .expect("written");
        node_end
            .write_all(&Line::path_switch(node(2), vec![1, 2, 3]).encode())
            .expect("written");
        node_end.write_all(b"not json\n").expect("written");
        let too_long = Line::path_switch(node(2), vec![0; MAX_MESSAGE + 1]).encode();
        node_end.write_all(&too_long).expect("written");
        let timeout = std::time::Duration::from_secs(2);
        assert_eq!(rx.recv_timeout(timeout).expect("hub"), Inbound::Hub(true));
        assert_eq!(
            rx.recv_timeout(timeout).expect("switch"),
            Inbound::PathSwitch {
                peer: node(2),
                message: vec![1, 2, 3]
            }
        );

        coordinator.send(&node(3), &[9, 9]);
        let mut reader = BufReader::new(node_end.try_clone().expect("clone"));
        let mut line = String::new();
        reader.read_line(&mut line).expect("read");
        assert_eq!(
            Line::decode(&line),
            Some(Line::path_switch(node(3), vec![9, 9]))
        );

        // A second coordinator replaces the first: the first connection is closed, and its end does not
        // report the Hub down for the new one
        let (second, _keep) = UnixStream::pair().expect("pair");
        coordinator
            .attach(second, move |i| drop(tx.send(i)))
            .expect("attached");
        line.clear();
        assert_eq!(reader.read_line(&mut line).expect("read"), 0, "closed");
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(300))
                .is_err(),
            "the replaced connection reports nothing"
        );
    }
}
