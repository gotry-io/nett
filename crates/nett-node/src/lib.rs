//! nett-node, the part of the nett daemon that connects a machine to its Hub (design/hub.md section
//! 5, ADR 0013): it hands the desired state to the mesh in the same process, reports status and
//! installs new releases. It also provides the client the signing tool uses to call the Hub API.

pub mod config;
pub mod coord;
pub mod daemon;
pub mod fetch;
pub mod http;
pub mod join;
pub mod launch;
#[cfg(target_os = "macos")]
pub mod launchd;
#[cfg(target_os = "linux")]
pub mod layout;
pub mod platform;
pub mod services;
pub mod session;
pub mod tls;
pub mod upgrade;
pub mod url;
