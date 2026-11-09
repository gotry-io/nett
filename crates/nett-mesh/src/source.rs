//! 从本地文件读取期望状态（design/local-signing.md 第 5 节）：启动时读一次，之后每收到一次 `SIGHUP`
//! 重新读取。接入 Hub 之后，nett-node 用同一种格式把期望状态写给组网进程。

use std::path::PathBuf;

use tokio::signal::unix::{Signal, SignalKind, signal};

use crate::config::{ConfigError, DesiredMesh};
use crate::run::ConfigSource;

/// 启动时读一次，之后每收到一次 `SIGHUP` 重新读取。
pub struct FileSource {
    path: PathBuf,
    started: bool,
    hangup: Signal,
}

impl FileSource {
    pub fn new(path: PathBuf) -> std::io::Result<Self> {
        Ok(Self {
            path,
            started: false,
            hangup: signal(SignalKind::hangup())?,
        })
    }
}

impl ConfigSource for FileSource {
    async fn next(&mut self) -> Option<Result<DesiredMesh, ConfigError>> {
        if self.started {
            self.hangup.recv().await?;
        }
        self.started = true;
        let path = self.path.clone();
        let read = tokio::task::spawn_blocking(move || std::fs::read(path)).await;
        Some(match read {
            Ok(Ok(bytes)) => DesiredMesh::from_json(&bytes),
            Ok(Err(e)) => Err(ConfigError::Document(format!(
                "reading {}: {e}",
                self.path.display()
            ))),
            Err(e) => Err(ConfigError::Document(format!("reading config: {e}"))),
        })
    }
}
