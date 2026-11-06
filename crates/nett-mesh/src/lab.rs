//! 实验构建（`lab` 特性）：从本地文件读取期望状态，事件另写一份 JSON 行供 `nett-lab` 采集
//! （design/prototype.md 第 3、7 节）。官方构建不含这个模块。

use std::fs::File;
use std::io::Write as _;
use std::path::PathBuf;

use tokio::signal::unix::{Signal, SignalKind, signal};

use crate::config::{ConfigError, DesiredMesh};
use crate::event::{Event, EventSink, log_event};
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

/// 每个事件写一行 JSON，同时写日志。写文件失败只记日志，不影响组网。
pub struct JsonLinesSink {
    file: File,
}

impl JsonLinesSink {
    pub fn create(path: &std::path::Path) -> std::io::Result<Self> {
        Ok(Self {
            file: File::options().create(true).append(true).open(path)?,
        })
    }
}

impl EventSink for JsonLinesSink {
    fn emit(&mut self, event: Event) {
        log_event(&event);
        let line = serde_json::to_string(&event).map(|mut s| {
            s.push('\n');
            s
        });
        let written = match line {
            Ok(line) => self.file.write_all(line.as_bytes()),
            Err(e) => Err(std::io::Error::other(e)),
        };
        if let Err(error) = written {
            tracing::warn!(%error, "writing event file failed");
        }
    }
}
