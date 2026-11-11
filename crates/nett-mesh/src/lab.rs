//! Lab build (`lab` feature): events are also written as JSON lines for `nett-lab` to collect, simulated
//! clock error, and the transport adapter's config file (design/prototype.md section 7). Official builds
//! do not include this module.

use std::fs::File;
use std::io::Write as _;
use std::path::PathBuf;

use crate::clock::Clock;
use crate::event::{Event, EventSink, log_event};

/// Writes each event as one JSON line, and also writes the log. A failure to write the file is only
/// logged and does not affect the mesh.
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
        // Each line carries the time it occurred (Unix milliseconds), for nett-lab to align with its
        // measurements of the underlying network
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

/// Simulates clock error in lab scenarios (design/prototype.md section 6.2, scenario 17): adds an offset
/// to the real clock, and can specify whether this machine considers its clock trustworthy.
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

/// When the mesh process hands out the transport adapter's configuration ([`Event::TransportConfigChanged`],
/// before the peers are configured), it is written to a local file (design/mesh.md section 5.3): in the
/// prototype this stands in for the local interface between the mesh process and the transport adapter
/// (ADR 0013).
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
            // Write a temporary file first, then rename: the transport adapter always reads a complete configuration
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
