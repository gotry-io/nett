//! The HTTPS client the signing tool uses to call the Hub API (design/hub.md section 4): one
//! connection per request, HTTP/1.1, with timeouts, and the reply size is capped.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::Request;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, HOST};
use hyper_util::rt::TokioIo;
use nett_mesh::config::MAX_DESIRED_BYTES;
use tokio::net::TcpStream;

use crate::tls::connector;
use crate::url::HubUrl;

const TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("{0}")]
    Connect(String),
    #[error("the Hub at {url} answered {status}: {title}{detail}")]
    Status {
        url: String,
        status: u16,
        title: String,
        detail: String,
    },
    #[error("the Hub's answer is not valid: {0}")]
    Reply(String),
}

/// A Hub: its address, and for a self-signed certificate the certificate's fingerprint.
#[derive(Debug, Clone)]
pub struct Target {
    pub url: String,
    pub tls_fingerprint: Option<[u8; 32]>,
}

/// Sends a JSON request and returns the reply on success.
pub async fn call(
    target: &Target,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Vec<u8>>,
) -> Result<Vec<u8>, HttpError> {
    tokio::time::timeout(TIMEOUT, call_inner(target, method, path, token, body))
        .await
        .map_err(|_| HttpError::Connect(format!("{}: no answer within {TIMEOUT:?}", target.url)))?
}

async fn call_inner(
    target: &Target,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Vec<u8>>,
) -> Result<Vec<u8>, HttpError> {
    let url = HubUrl::parse(&target.url).map_err(HttpError::Connect)?;
    let connect = |e: &dyn std::fmt::Display| {
        HttpError::Connect(format!("connecting to {}: {e}", target.url))
    };
    let tcp = TcpStream::connect(url.authority())
        .await
        .map_err(|e| connect(&e))?;
    let tls = connector(target.tls_fingerprint)
        .map_err(|e| connect(&e))?
        .connect(url.server_name().map_err(HttpError::Connect)?, tcp)
        .await
        .map_err(|e| connect(&e))?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(|e| connect(&e))?;
    tokio::spawn(async move {
        conn.await.ok();
    });
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header(HOST, url.host_header())
        .header(CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        req = req.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    let req = req
        .body(Full::new(Bytes::from(body.unwrap_or_default())))
        .map_err(|e| HttpError::Connect(e.to_string()))?;
    let res = sender.send_request(req).await.map_err(|e| connect(&e))?;
    let status = res.status();
    let limit = usize::try_from(MAX_DESIRED_BYTES).unwrap_or(usize::MAX);
    let bytes = Limited::new(res.into_body(), limit)
        .collect()
        .await
        .map_err(|e| HttpError::Reply(e.to_string()))?
        .to_bytes()
        .to_vec();
    if status.is_success() {
        return Ok(bytes);
    }
    let problem: Option<nett_proto::api::Problem> = serde_json::from_slice(&bytes).ok();
    Err(HttpError::Status {
        url: target.url.clone(),
        status: status.as_u16(),
        title: problem
            .as_ref()
            .map_or_else(String::new, |p| p.title.clone()),
        detail: problem
            .map(|p| p.detail)
            .filter(|d| !d.is_empty())
            .map_or_else(String::new, |d| format!(": {d}")),
    })
}
