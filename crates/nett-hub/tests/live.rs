//! The live view's stream (design/top.md section 6) over real routes: it needs the owner token;
//! while it is open a connected machine is asked for samples and they arrive on it; a fifth stream
//! is refused, and a closed stream stops counting.

mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use nett_node::config::HubConfig;
use nett_node::session::Node;
use nett_proto::api::{LINKS_STREAM_PATH, LiveSample};
use nett_proto::token::Bytes32;
use tower::ServiceExt as _;

use common::*;

const PEER: &str = "node_01JD7M3XQ4W8N2K5R9T6V3B7C2";

/// A mesh whose status has one peer with traffic.
struct OnePeer;

impl nett_mesh::status::StatusSource for OnePeer {
    fn snapshot(&self) -> Option<nett_mesh::status::StatusDoc> {
        serde_json::from_value(serde_json::json!({
            "v": 1, "version": "0.12.0",
            "node": {"id": "node_01JD7M3XQ4W8N2K5R9T6V3B7C1", "name": "mac", "admitted": true,
                     "mesh": [], "edge": [], "routes": [], "reachability": "dial-only",
                     "dataplane": "userspace", "listen_port": 53557, "nat": null,
                     "clock_trusted": true, "started_at": "2026-11-25T00:00:00Z"},
            "config": {"applied_at": "2026-11-25T00:00:00Z", "access_rules_version": 1},
            "peers": [{
                "id": PEER, "name": "edge-vps", "mesh": [], "edge": [], "routes": [],
                "state": "connected", "role": "decider",
                "path": {"kind": "direct", "relay": null, "endpoint": "198.51.100.2:41820",
                         "punched": false, "since": null, "reason": null},
                "rtt_ms": 9.4, "loss": 0.0, "jitter_ms": 0.3, "last_handshake": null,
                "last_received": null, "rx_bytes": 1000, "tx_bytes": 2000, "candidates": []
            }],
            "problems": [], "events": []
        }))
        .ok()
    }
    fn reload(&self) -> Option<nett_mesh::status::ReloadOutcome> {
        None
    }
    fn coordinate(&self, _: std::os::unix::net::UnixStream) -> std::io::Result<()> {
        Err(std::io::Error::other("no coordination in this test"))
    }
    fn whois(&self, _: std::net::IpAddr) -> Option<nett_mesh::status::Whois> {
        None
    }
    fn probe(&self, _: nett_core::id::NodeId) -> Option<Option<usize>> {
        None
    }
}

async fn open_stream(app: &axum::Router, token: Option<&str>) -> axum::response::Response {
    let mut req = Request::builder().method("GET").uri(LINKS_STREAM_PATH);
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    app.clone()
        .oneshot(req.body(Body::empty()).expect("request"))
        .await
        .expect("response")
}

#[tokio::test]
async fn an_open_stream_brings_the_machines_samples() {
    let (hub, app, token, _site, state, _linked_tmp) = linked("live", "https://127.0.0.1").await;
    let (status, _) = push(&app, &token, &state).await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(
        open_stream(&app, None).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let res = open_stream(&app, Some(&token)).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get("content-type").map(|v| v.as_bytes()),
        Some(&b"text/event-stream"[..])
    );

    // The machine connects while the stream is open: it is asked for samples at once
    let url = serve(hub.clone()).await;
    let mac = state
        .machine(&name("mac"))
        .expect("mac")
        .node_id
        .to_string();
    let (_dir_tmp, dir) = temp_dir("live-mac");
    let agent = Node {
        config: HubConfig {
            url,
            hub_key: hub_key(),
            node_id: mac.clone(),
            tls_fingerprint: Some(Bytes32(cert_fingerprint())),
        },
        identity: identity(2),
        desired: dir.join("desired.json"),
        mesh: Arc::new(OnePeer),
        upgrader: None,
        link: Arc::new(nett_node::fetch::HubLink::new()),
        services: None,
    };
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(nett_node::session::run(agent, async move {
        stopped.await.ok();
    }));

    let mut body = res.into_body();
    let mut text = String::new();
    let sample = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let frame = body.frame().await.expect("open").expect("frame");
            if let Ok(data) = frame.into_data() {
                text.push_str(&String::from_utf8_lossy(&data));
            }
            if let Some(at) = text.find("event: sample\ndata: ") {
                let rest = &text[at + "event: sample\ndata: ".len()..];
                if let Some(end) = rest.find('\n') {
                    return serde_json::from_str::<LiveSample>(&rest[..end]).expect("sample");
                }
            }
        }
    })
    .await
    .expect("a sample within 10 seconds");
    assert_eq!(
        (sample.name.as_str(), sample.node_id.as_str()),
        ("mac", mac.as_str())
    );
    assert_eq!(sample.peers.len(), 1);
    assert_eq!(sample.peers[0].id, PEER);
    assert_eq!(
        (sample.peers[0].rx_bytes, sample.peers[0].rtt_ms),
        (1000, Some(9.4))
    );

    // Four streams at a time; a closed one stops counting
    let more: Vec<_> =
        futures_util::future::join_all((0..3).map(|_| open_stream(&app, Some(&token)))).await;
    assert!(more.iter().all(|r| r.status() == StatusCode::OK));
    assert_eq!(
        open_stream(&app, Some(&token)).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    drop(more);
    drop(body);
    assert_eq!(*hub.views.watch().borrow(), 0);

    stop.send(()).ok();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the node stops")
        .expect("joined");
}
