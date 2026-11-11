//! Requests and replies of the Hub's external API (design/hub.md section 4): the signing tool `nett
//! site` and the Hub share these types.

use serde::{Deserialize, Serialize};

use crate::token::Bytes32;

pub const LINK_PATH: &str = "/api/v1/link";
pub const SITE_PATH: &str = "/api/v1/site";
pub const STATUS_PATH: &str = "/api/v1/site/status";
/// Hub-side enrollment, leave and learned addresses (design/hub.md section 4); the reply is
/// `nett_site::updates::Updates`.
pub const UPDATES_PATH: &str = "/api/v1/site/updates";
/// A machine's recent events (design/hub.md section 8): `?node=<node ID>&limit=<1..=100>`.
pub const EVENTS_PATH: &str = "/api/v1/site/events";
pub const CONNECT_PATH: &str = "/node/v1/connect";

/// `POST /api/v1/link`: the random secret in the link code, plus the site's trust anchor list (JSON
/// as is).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkRequest {
    pub secret: Bytes32,
    pub trust_anchors: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkResponse {
    /// The site's `owner` token (auth.md section 6), which appears only here, once.
    pub token: String,
}

/// Reply of `PUT /api/v1/site`: the generation after the Hub accepts it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushResponse {
    pub generation: u64,
}

/// `GET /api/v1/site/status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub hub_version: String,
    pub url: String,
    pub generation: u64,
    pub machines: Vec<MachineStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineStatus {
    pub name: String,
    pub node_id: String,
    pub address: String,
    pub online: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nett_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// The generation and result the machine last acknowledged (`applied`, `rejected`, `pending`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The mesh process's local status (design/status.md section 6), and the time it was reported
    /// (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_at: Option<i64>,
    /// The machine's answer to the release manifest (`applied`, `pending`, `rejected`) and its
    /// reason (design/release.md section 7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upgrade_result: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upgrade_reason: Option<String>,
}

/// API errors (design/api-resources.md section 2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Problem {
    pub title: String,
    #[serde(default)]
    pub detail: String,
}

/// One event of a machine, newest first in `GET /api/v1/site/events`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Unix seconds.
    pub at: i64,
    /// `connected`, `disconnected`, `joined`, `left`, `config`, `upgrade`.
    pub kind: String,
    pub detail: String,
}
