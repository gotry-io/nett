//! The control agent nett-node on each machine (design/hub.md section 5): connects to the Hub,
//! hands the desired state to the mesh process, and reports status. It also provides the client the
//! signing tool uses to call the Hub API.

pub mod config;
pub mod http;
pub mod join;
pub mod session;
pub mod tls;
pub mod url;
