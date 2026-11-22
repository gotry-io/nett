//! Lab build (`lab` feature): events are also written as JSON lines for `nett-lab` to collect, and
//! simulated clock error (design/prototype.md section 7). Official builds do not include this
//! module.

use std::fs::File;
use std::io::Write as _;

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
