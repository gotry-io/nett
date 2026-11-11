//! Mesh process: platform-independent core (admission, measurement, path selection, switchover) plus
//! per-platform data plane backends (ADR 0013, 0018, design/mesh.md).

pub mod access;
pub mod clock;
pub mod config;
pub mod coord;
pub mod dataplane;
pub mod engine;
pub mod event;
pub mod helper;
pub mod key;
#[cfg(feature = "lab")]
pub mod lab;
#[allow(unsafe_code)]
pub mod lan;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
pub mod members;
pub mod path;
pub mod probe;
pub mod prober;
pub mod punch;
pub mod routes;
pub mod run;
pub mod runtime;
pub mod source;
pub mod status;
pub mod store;
#[cfg(test)]
mod testutil;
pub mod userspace;
