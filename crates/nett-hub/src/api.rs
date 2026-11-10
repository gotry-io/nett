//! Hub 的 HTTP 接口（design/hub.md 第 4 节）：关联、接收站点、状态；`/node/v1/connect` 是节点网关。

use std::sync::Arc;

use axum::Json;
use axum::extract::{DefaultBodyLimit, State as AxumState};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Router, body::Bytes};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nett_mesh::config::MAX_DESIRED_BYTES;
use nett_proto::api::{
    CONNECT_PATH, LINK_PATH, LinkRequest, LinkResponse, MachineStatus, Problem, PushResponse,
    SITE_PATH, STATUS_PATH, StatusResponse,
};
use nett_site::state::State;
use nett_trust::anchors::{TrustAnchors, TrustAnchorsDoc};

use crate::hub::{Hub, PushError};
use crate::{now, random, sha256};

pub fn router(hub: Arc<Hub>) -> Router {
    Router::new()
        .route(LINK_PATH, post(link))
        .route(SITE_PATH, put(push))
        .route(STATUS_PATH, get(status))
        .route(CONNECT_PATH, get(crate::gateway::connect))
        .layer(DefaultBodyLimit::max(
            usize::try_from(MAX_DESIRED_BYTES).unwrap_or(usize::MAX),
        ))
        .with_state(hub)
}

fn problem(status: StatusCode, title: &str, detail: impl Into<String>) -> Response {
    let body = Problem {
        title: title.to_owned(),
        detail: detail.into(),
    };
    (
        status,
        [(header::CONTENT_TYPE, "application/problem+json")],
        serde_json::to_vec(&body).unwrap_or_default(),
    )
        .into_response()
}

fn internal(e: impl std::fmt::Display) -> Response {
    tracing::error!(error = %e, "request failed");
    problem(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Internal error",
        "the Hub could not complete the request",
    )
}

/// 两个字节串在常量时间内比较（硬性规则 10）。
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// 请求没有带着站点的 owner token 时，返回拒绝它的回复。
async fn unauthorized(hub: &Hub, headers: &HeaderMap) -> Option<Response> {
    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return Some(problem(
            StatusCode::UNAUTHORIZED,
            "Unauthorized",
            "a site token is needed",
        ));
    };
    let stored = match hub.db.hub().await {
        Ok(row) => row.and_then(|h| h.owner_token_hash),
        Err(e) => return Some(internal(e)),
    };
    match stored {
        Some(hash) if same(&hash, &sha256(token.as_bytes())) => None,
        _ => Some(problem(
            StatusCode::UNAUTHORIZED,
            "Unauthorized",
            "the site token is not valid",
        )),
    }
}

async fn link(AxumState(hub): AxumState<Arc<Hub>>, Json(req): Json<LinkRequest>) -> Response {
    let anchors: TrustAnchorsDoc = match serde_json::from_value(req.trust_anchors) {
        Ok(a) => a,
        Err(e) => return problem(StatusCode::BAD_REQUEST, "Bad trust anchors", e.to_string()),
    };
    if let Err(e) = TrustAnchors::from_doc(&anchors) {
        return problem(StatusCode::BAD_REQUEST, "Bad trust anchors", e.to_string());
    }
    let (id, secret) = match (random::<13>(), random::<32>()) {
        (Ok(id), Ok(secret)) => (id, secret),
        _ => return internal("the system random number generator failed"),
    };
    let id: String = id.iter().map(|b| format!("{b:02x}")).collect();
    let token = format!("nett_tok_{id}_{}", URL_SAFE_NO_PAD.encode(secret));
    let anchors_json = match serde_json::to_string(&anchors) {
        Ok(j) => j,
        Err(e) => return internal(e),
    };
    match hub
        .db
        .link(
            &sha256(&req.secret.0),
            now(),
            &anchors_json,
            &id,
            &sha256(token.as_bytes()),
        )
        .await
    {
        Ok(true) => {
            tracing::info!(token_id = %id, "site linked");
            Json(LinkResponse { token }).into_response()
        }
        Ok(false) => problem(
            StatusCode::FORBIDDEN,
            "Link code not accepted",
            "the link code is wrong, expired or used; run `nett-hub init` on the Hub for a new one",
        ),
        Err(e) => internal(e),
    }
}

async fn push(AxumState(hub): AxumState<Arc<Hub>>, headers: HeaderMap, body: Bytes) -> Response {
    if let Some(r) = unauthorized(&hub, &headers).await {
        return r;
    }
    let state = match State::from_json(&body) {
        Ok(s) => s,
        Err(e) => return problem(StatusCode::BAD_REQUEST, "Site not accepted", e.to_string()),
    };
    match hub.push(state, now()).await {
        Ok(generation) => {
            tracing::info!(generation, "site pushed");
            Json(PushResponse { generation }).into_response()
        }
        Err(PushError::Rejected(reason)) => {
            tracing::warn!(%reason, "site push rejected");
            problem(StatusCode::CONFLICT, "Site not accepted", reason)
        }
        Err(PushError::NotLinked) => problem(
            StatusCode::CONFLICT,
            "Not linked",
            "the Hub is not linked to a site",
        ),
        Err(PushError::Db(e)) => internal(e),
    }
}

async fn status(AxumState(hub): AxumState<Arc<Hub>>, headers: HeaderMap) -> Response {
    if let Some(r) = unauthorized(&hub, &headers).await {
        return r;
    }
    let rows = match hub.db.nodes().await {
        Ok(rows) => rows,
        Err(e) => return internal(e),
    };
    let online = hub.online().await;
    let site = hub.site().await;
    let mut machines = Vec::new();
    if let Some(site) = &site {
        for (name, m) in &site.state.machines {
            let row = rows.iter().find(|r| r.node_id == m.node_id.as_str());
            machines.push(MachineStatus {
                name: name.to_string(),
                node_id: m.node_id.to_string(),
                address: m.mesh.ipv4.to_string(),
                online: online.contains(&m.node_id),
                last_seen: row.map(|r| r.last_seen),
                nett_version: row.and_then(|r| r.nett_version.clone()),
                platform: row.and_then(|r| r.platform.clone()),
                applied_generation: row
                    .and_then(|r| r.applied_generation)
                    .and_then(|g| u64::try_from(g).ok()),
                result: row.and_then(|r| r.ack_result.clone()),
                reason: row
                    .and_then(|r| r.ack_reason.clone())
                    .filter(|r| !r.is_empty()),
                status: row
                    .and_then(|r| r.status.as_deref())
                    .and_then(|s| serde_json::from_str(s).ok()),
                status_at: row.and_then(|r| r.status_at),
            });
        }
    }
    Json(StatusResponse {
        hub_version: env!("CARGO_PKG_VERSION").to_owned(),
        url: hub.url.clone(),
        generation: site.map_or(0, |s| s.generation),
        machines,
    })
    .into_response()
}
