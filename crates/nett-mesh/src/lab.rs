//! 实验构建（`lab` 特性）：事件另写一份 JSON 行供 `nett-lab` 采集，模拟时钟误差，以及传输适配进程的
//! 配置文件（design/prototype.md 第 7 节）。官方构建不含这个模块。

use std::fs::File;
use std::io::Write as _;
use std::path::PathBuf;

use crate::clock::Clock;
use crate::event::{Event, EventSink, log_event};

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
        // 每行带上发生时刻（Unix 毫秒），供 nett-lab 与底层网络的测量对齐
        let line = serde_json::to_value(&event).and_then(|mut v| {
            if let Some(obj) = v.as_object_mut() {
                obj.insert(
                    "at_ms".into(),
                    serde_json::Value::from(crate::clock::system_now_ms()),
                );
            }
            serde_json::to_string(&v).map(|mut s| {
                s.push('\n');
                s
            })
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

/// 实验中模拟时钟误差（design/prototype.md 第 6.2 节场景 17）：在真实时钟上加偏移，并可指定本机
/// 认为自己的时钟是否可信。
pub struct LabClock<C> {
    pub inner: C,
    pub offset_ms: i64,
    pub trusted: Option<bool>,
}

impl<C: Clock> Clock for LabClock<C> {
    fn now_ms(&self) -> u64 {
        self.inner.now_ms().saturating_add_signed(self.offset_ms)
    }

    fn trusted(&self) -> bool {
        self.trusted.unwrap_or_else(|| self.inner.trusted())
    }
}

/// 组网进程交出传输适配进程的配置时（[`Event::TransportConfigChanged`]，在配置对端之前），写到本机文件
/// （design/mesh.md 第 5.3 节）：原型中代替组网进程与传输适配进程之间的本机接口（ADR 0013）。
pub struct TransportConfigWriter<E> {
    inner: E,
    path: PathBuf,
}

impl<E> TransportConfigWriter<E> {
    pub fn new(inner: E, path: PathBuf) -> Self {
        Self { inner, path }
    }
}

impl<E: EventSink> EventSink for TransportConfigWriter<E> {
    fn emit(&mut self, event: Event) {
        if let Event::TransportConfigChanged { config } = &event {
            // 先写临时文件再改名：传输适配进程读到的总是一份完整的配置
            let tmp = self.path.with_extension("tmp");
            let result = serde_json::to_vec_pretty(config)
                .map_err(std::io::Error::other)
                .and_then(|bytes| std::fs::write(&tmp, bytes))
                .and_then(|()| std::fs::rename(&tmp, &self.path));
            if let Err(error) = result {
                tracing::warn!(
                    %error,
                    path = %self.path.display(),
                    "writing the transport config failed"
                );
            }
        }
        self.inner.emit(event);
    }
}
