//! Reads the desired state from a local file (design/local-signing.md section 5): read once at startup,
//! and re-read on every `SIGHUP`, or on every `reload` request received through the local interface
//! (design/status.md section 4.1). Once joined to the Hub, nett-node writes the desired state into this
//! file and then uses `reload` to make the mesh process apply it (design/hub.md section 5).

use std::path::PathBuf;

use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::mpsc::Receiver;

use crate::config::{ConfigError, DesiredMesh, MAX_DESIRED_BYTES, read_bounded};
use crate::run::{ConfigSource, Delivery};
use crate::status::ReloadReply;

/// Read once at startup, then re-read on every `SIGHUP` or `reload` request.
pub struct FileSource {
    path: PathBuf,
    started: bool,
    hangup: Signal,
    /// `reload` requests forwarded by the local interface; once the interface is closed only `SIGHUP` remains.
    reloads: Option<Receiver<ReloadReply>>,
}

impl FileSource {
    pub fn new(path: PathBuf, reloads: Receiver<ReloadReply>) -> std::io::Result<Self> {
        Ok(Self {
            path,
            started: false,
            hangup: signal(SignalKind::hangup())?,
            reloads: Some(reloads),
        })
    }

    /// Waits for the next re-read trigger: on `SIGHUP` there is no party waiting for the result. `None` when
    /// the signal stream is closed.
    async fn trigger(&mut self) -> Option<Option<ReloadReply>> {
        loop {
            let Some(reloads) = self.reloads.as_mut() else {
                return self.hangup.recv().await.map(|()| None);
            };
            tokio::select! {
                hup = self.hangup.recv() => return hup.map(|()| None),
                reload = reloads.recv() => match reload {
                    Some(reply) => return Some(Some(reply)),
                    None => self.reloads = None,
                },
            }
        }
    }
}

impl ConfigSource for FileSource {
    async fn next(&mut self) -> Option<Delivery> {
        let reply = if self.started {
            self.trigger().await?
        } else {
            None
        };
        self.started = true;
        let path = self.path.clone();
        let read =
            tokio::task::spawn_blocking(move || read_bounded(&path, MAX_DESIRED_BYTES)).await;
        let desired = match read {
            Ok(Ok(Some(bytes))) => DesiredMesh::from_json(&bytes),
            Ok(Ok(None)) => Err(ConfigError::Document(format!(
                "{} does not exist",
                self.path.display()
            ))),
            Ok(Err(e)) => Err(ConfigError::Document(format!(
                "reading {}: {e}",
                self.path.display()
            ))),
            Err(e) => Err(ConfigError::Document(format!("reading config: {e}"))),
        };
        Some(Delivery { desired, reply })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn a_reload_request_rereads_and_carries_its_reply() {
        let dir = std::env::temp_dir().join(format!("nett-source-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("desired.json");
        std::fs::write(&path, b"not json").expect("write");
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let mut source = FileSource::new(path, rx).expect("source");

        // Read once at startup, with no party waiting for the result; when the content is wrong, what is handed
        // out is the reason for rejection
        let first = source.next().await.expect("first read");
        assert!(first.reply.is_none());
        assert!(matches!(first.desired, Err(ConfigError::Document(_))));

        let (reply, answer) = std::sync::mpsc::sync_channel(1);
        tx.send(reply).await.expect("send");
        let second = source.next().await.expect("reload");
        let reply = second.reply.expect("reply");
        reply
            .try_send(crate::status::ReloadOutcome::Applied { problems: vec![] })
            .expect("answer");
        assert!(answer.try_recv().is_ok());

        // After the local interface is closed, keep waiting for SIGHUP as usual and do not treat the source as
        // closed
        drop(tx);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), source.next())
                .await
                .is_err()
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
