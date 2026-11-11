//! 节点网关的端到端测试（design/hub.md 第 5 节）：Hub 在 127.0.0.1 上自己终止 TLS（测试证书，按指纹校验），
//! 一个真实的 nett-node 会话连上来：收到期望状态、写成期望状态文件、确认；站点变化之后收到新的一份。站点里
//! 没有的身份、对不上的节点 ID、错误的 Hub 公钥都连不上。

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use axum::http::StatusCode;
use nett_hub::hub::Hub;
use nett_mesh::config::DesiredMeshDoc;
use nett_node::config::HubConfig;
use nett_node::session::{Node, SessionError};
use nett_proto::token::Bytes32;
use nett_proto::v1::ErrorCode;
use x25519_dalek::{PublicKey, StaticSecret};

use common::*;

fn node(url: &str, node_id: &str, identity: StaticSecret, dir: &Path) -> Node {
    Node {
        config: HubConfig {
            url: url.to_owned(),
            hub_key: Bytes32(PublicKey::from(&StaticSecret::from([200; 32])).to_bytes()),
            node_id: node_id.to_owned(),
            tls_fingerprint: Some(Bytes32(cert_fingerprint())),
        },
        identity,
        desired: dir.join("desired.json"),
        // 没有组网进程：期望状态写好之后确认为 pending
        socket: dir.join("mesh.sock"),
    }
}

/// 等到 Hub 记下这台机器确认了 `generation`。
async fn acked(hub: &Hub, node_id: &str, generation: i64) -> nett_hub::db::NodeRow {
    for _ in 0..200 {
        if let Some(row) = hub
            .db
            .nodes()
            .await
            .expect("nodes")
            .into_iter()
            .find(|r| r.node_id == node_id && r.applied_generation == Some(generation))
        {
            return row;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{node_id} did not acknowledge generation {generation}");
}

fn written(path: &PathBuf) -> DesiredMeshDoc {
    serde_json::from_slice(&std::fs::read(path).expect("desired state written")).expect("valid")
}

#[tokio::test]
async fn nodes_receive_apply_and_acknowledge_the_desired_state() {
    // Hub 的地址在 linked 之前就要定下：先占一个端口
    let (hub, app, token, site, mut state) = linked("gateway", "https://127.0.0.1").await;
    let (status, _) = push(&app, &token, &state).await;
    assert_eq!(status, StatusCode::OK);
    let url = serve(hub.clone()).await;
    let dir = temp_dir("gateway-mac");
    let mac = state
        .machine(&name("mac"))
        .expect("mac")
        .node_id
        .to_string();

    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let agent = node(&url, &mac, identity(2), &dir);
    let task = tokio::spawn(nett_node::session::run(agent, async move {
        stopped.await.ok();
    }));

    let row = acked(&hub, &mac, 1).await;
    assert_eq!(
        row.ack_result.as_deref(),
        Some("pending"),
        "no mesh process here"
    );
    assert_eq!(row.platform.as_deref().map(|p| p.contains('-')), Some(true));
    let expected = nett_site::compose::desired(&state, &name("mac"))
        .expect("composed")
        .expect("signed");
    assert_eq!(written(&dir.join("desired.json")), expected);

    // 站点变化：Hub 下发新的一份
    state
        .allow(&["mac".into()], &["nas".into()], vec![tcp(22)], None)
        .expect("allow");
    resign(&site, &mut state);
    let (status, _) = push(&app, &token, &state).await;
    assert_eq!(status, StatusCode::OK);
    acked(&hub, &mac, 2).await;
    let doc = written(&dir.join("desired.json"));
    assert!(doc.access_rules.is_some());
    assert_eq!(
        doc,
        nett_site::compose::desired(&state, &name("mac"))
            .expect("composed")
            .expect("signed")
    );
    assert!(hub.online().await.iter().any(|n| n.as_str() == mac));

    stop.send(()).ok();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the node stops")
        .expect("no panic");
}

#[tokio::test]
async fn unknown_or_mismatched_machines_are_refused() {
    let (hub, app, token, _site, state) = linked("gateway-refuse", "https://127.0.0.1").await;
    let (status, _) = push(&app, &token, &state).await;
    assert_eq!(status, StatusCode::OK);
    let url = serve(hub.clone()).await;
    let dir = temp_dir("gateway-refuse-node");
    let mac = state
        .machine(&name("mac"))
        .expect("mac")
        .node_id
        .to_string();
    let nas = state
        .machine(&name("nas"))
        .expect("nas")
        .node_id
        .to_string();

    let refused = |r: Result<(), SessionError>| match r {
        Err(SessionError::Refused { code, .. }) => code,
        other => panic!("expected a refusal, got {other:?}"),
    };
    // 站点里没有的身份
    assert_eq!(
        refused(node(&url, &mac, identity(9), &dir).session().await),
        ErrorCode::NodeUnknown
    );
    // mac 的身份冒充 nas
    assert_eq!(
        refused(node(&url, &nas, identity(2), &dir).session().await),
        ErrorCode::NodeUnknown
    );
    // 错误的 Hub 公钥：握手失败
    let mut wrong = node(&url, &mac, identity(2), &dir);
    wrong.config.hub_key = Bytes32([7; 32]);
    assert!(matches!(
        wrong.session().await,
        Err(SessionError::Connect(_))
    ));
    // 证书指纹不对：TLS 失败
    let mut wrong = node(&url, &mac, identity(2), &dir);
    wrong.config.tls_fingerprint = Some(Bytes32([1; 32]));
    assert!(matches!(
        wrong.session().await,
        Err(SessionError::Connect(_))
    ));
    assert!(!dir.join("desired.json").exists());
}
