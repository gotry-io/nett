//! 从本地文件读取期望状态（design/local-signing.md 第 5 节）：启动时读一次，之后每收到一次 `SIGHUP`、
//! 或经本机接口收到一次 `reload` 请求（design/status.md 第 4.1 节）重新读取。接入 Hub 之后，nett-node
//! 把期望状态写进这个文件，再用 `reload` 让组网进程应用它（design/hub.md 第 5 节）。

use std::path::PathBuf;

use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::mpsc::Receiver;

use crate::config::{ConfigError, DesiredMesh};
use crate::run::{ConfigSource, Delivery};
use crate::status::ReloadReply;

/// 启动时读一次，之后每收到一次 `SIGHUP` 或 `reload` 请求重新读取。
pub struct FileSource {
    path: PathBuf,
    started: bool,
    hangup: Signal,
    /// 本机接口转来的 `reload` 请求；接口关闭之后只剩 `SIGHUP`。
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

    /// 等下一次重新读取的触发：`SIGHUP` 时没有等结果的一方。信号流关闭时为 `None`。
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
        let read = tokio::task::spawn_blocking(move || std::fs::read(path)).await;
        let desired = match read {
            Ok(Ok(bytes)) => DesiredMesh::from_json(&bytes),
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

        // 启动时读一次，没有等结果的一方；内容不对时交出的是拒绝的原因
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

        // 本机接口关闭之后照常等 SIGHUP，不当作来源关闭
        drop(tx);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), source.next())
                .await
                .is_err()
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
