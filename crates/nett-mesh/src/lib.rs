//! 组网进程：与平台无关的核心（准入、测量、选路、切换）+ 各平台的数据面后端（ADR 0013、0018，design/mesh.md）。

pub mod access;
pub mod clock;
pub mod config;
pub mod dataplane;
pub mod engine;
pub mod event;
pub mod key;
#[cfg(feature = "lab")]
pub mod lab;
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
#[cfg(test)]
mod testutil;
pub mod userspace;
