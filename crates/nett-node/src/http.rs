//! The HTTPS client the signing tool uses to call the Hub API (design/hub.md section 4), and that
//! the Hub and nett-node use to fetch releases (design/release.md section 7): one connection per
//! request, HTTP/1.1, with timeouts, and the reply size is capped. A release program is handed on
//! as it arrives, so it is never held whole.

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
    #[error("{url} answered {status}")]
    Fetch { url: String, status: u16 },
    #[error("{url}: the answer is larger than {limit} bytes")]
    TooLarge { url: String, limit: usize },
    #[error("{url}: nothing arrived for {idle:?} after {received} bytes")]
    Stalled {
        url: String,
        idle: Duration,
        received: u64,
    },
    #[error("{url}: {reason} after {received} bytes")]
    Stopped {
        url: String,
        reason: String,
        received: u64,
    },
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

/// GETs an `https://` URL, the certificate verified by the operating system: at most `limit`
/// bytes, within `timeout`. Redirects are not followed.
pub async fn get(url: &str, limit: usize, timeout: Duration) -> Result<Vec<u8>, HttpError> {
    let (target, path) = split_https(url)?;
    let (status, bytes) =
        tokio::time::timeout(timeout, send(&target, "GET", &path, None, None, limit))
            .await
            .map_err(|_| HttpError::Connect(format!("{url}: no answer within {timeout:?}")))??;
    if status.is_success() {
        Ok(bytes)
    } else {
        Err(HttpError::Fetch {
            url: url.to_owned(),
            status: status.as_u16(),
        })
    }
}

/// GETs an `https://` URL like [`get`], handing the reply's body to `sink` as it arrives: at most
/// `limit` bytes, and the download is abandoned when nothing arrives for `idle`. `sink` refusing a
/// part stops the download with its reason.
pub async fn get_streaming(
    url: &str,
    limit: u64,
    idle: Duration,
    mut sink: impl FnMut(&[u8]) -> Result<(), String>,
) -> Result<(), HttpError> {
    let (target, path) = split_https(url)?;
    let res = tokio::time::timeout(TIMEOUT, open(&target, "GET", &path, None, None))
        .await
        .map_err(|_| HttpError::Connect(format!("{url}: no answer within {TIMEOUT:?}")))??;
    if !res.status().is_success() {
        return Err(HttpError::Fetch {
            url: url.to_owned(),
            status: res.status().as_u16(),
        });
    }
    let mut body = res.into_body();
    let mut received = 0u64;
    loop {
        let frame = match tokio::time::timeout(idle, body.frame()).await {
            Err(_) => {
                return Err(HttpError::Stalled {
                    url: url.to_owned(),
                    idle,
                    received,
                });
            }
            Ok(None) => return Ok(()),
            Ok(Some(frame)) => frame.map_err(|e| HttpError::Stopped {
                url: url.to_owned(),
                reason: e.to_string(),
                received,
            })?,
        };
        let Ok(data) = frame.into_data() else {
            continue;
        };
        received += data.len() as u64;
        if received > limit {
            return Err(HttpError::TooLarge {
                url: url.to_owned(),
                limit: usize::try_from(limit).unwrap_or(usize::MAX),
            });
        }
        sink(&data).map_err(|reason| HttpError::Stopped {
            url: url.to_owned(),
            reason,
            received,
        })?;
    }
}

/// The server and path of an `https://` URL.
fn split_https(url: &str) -> Result<(Target, String), HttpError> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| HttpError::Connect(format!("{url}: only https:// URLs are fetched")))?;
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let target = Target {
        url: format!("https://{authority}"),
        tls_fingerprint: None,
    };
    Ok((target, if path.is_empty() { "/" } else { path }.to_owned()))
}

async fn call_inner(
    target: &Target,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Vec<u8>>,
) -> Result<Vec<u8>, HttpError> {
    let limit = usize::try_from(MAX_DESIRED_BYTES).unwrap_or(usize::MAX);
    let (status, bytes) = send(target, method, path, token, body, limit).await?;
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

/// One request on its own connection; the body of the reply is capped at `limit` bytes.
async fn send(
    target: &Target,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Vec<u8>>,
    limit: usize,
) -> Result<(hyper::StatusCode, Vec<u8>), HttpError> {
    let res = open(target, method, path, token, body).await?;
    let status = res.status();
    let bytes = Limited::new(res.into_body(), limit)
        .collect()
        .await
        .map_err(|e| {
            if e.is::<http_body_util::LengthLimitError>() {
                HttpError::TooLarge {
                    url: format!("{}{path}", target.url),
                    limit,
                }
            } else {
                HttpError::Reply(e.to_string())
            }
        })?
        .to_bytes()
        .to_vec();
    Ok((status, bytes))
}

/// Opens a connection, sends one request and returns the reply with its body still to be read.
async fn open(
    target: &Target,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Vec<u8>>,
) -> Result<hyper::Response<hyper::body::Incoming>, HttpError> {
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
    sender.send_request(req).await.map_err(|e| connect(&e))
}
