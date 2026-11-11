//! Hub 对外 API 的请求与回复（design/hub.md 第 4 节）：签名工具 `nett site` 与 Hub 共用这些类型。

use serde::{Deserialize, Serialize};

use crate::token::Bytes32;

pub const LINK_PATH: &str = "/api/v1/link";
pub const SITE_PATH: &str = "/api/v1/site";
pub const STATUS_PATH: &str = "/api/v1/site/status";
/// Hub 一侧的入网、退出与得知的地址（design/hub.md 第 4 节），回复是 `nett_site::updates::Updates`。
pub const UPDATES_PATH: &str = "/api/v1/site/updates";
pub const CONNECT_PATH: &str = "/node/v1/connect";

/// `POST /api/v1/link`：关联码中的随机密钥，加上站点的信任锚清单（JSON 原样）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkRequest {
    pub secret: Bytes32,
    pub trust_anchors: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkResponse {
    /// 站点的 `owner` token（auth.md 第 6 节），只在这里出现一次。
    pub token: String,
}

/// `PUT /api/v1/site` 的回复：Hub 接受之后的代数。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushResponse {
    pub generation: u64,
}

/// `GET /api/v1/site/status`。
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
    /// 机器最近一次确认的代数与结果（`applied`、`rejected`、`pending`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// 组网进程的本机状态（design/status.md 第 6 节），以及它报告的时间（Unix 秒）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_at: Option<i64>,
}

/// API 的错误（design/api-resources.md 第 2 节）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Problem {
    pub title: String,
    #[serde(default)]
    pub detail: String,
}
