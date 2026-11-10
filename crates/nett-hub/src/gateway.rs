//! 节点网关（design/protocol.md、design/hub.md 第 5 节）：WebSocket 上的 Noise IK，Hub 是响应方。节点用自己的
//! 身份密钥握手，Hub 按站点中登记的身份公钥认出它；之后下发期望状态，记下确认、清单与本机状态。

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State as AxumState;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use nett_core::id::NodeId;
use nett_proto::frame::{self, Reassembler};
use nett_proto::noise::{MAX_MESSAGE, Responder, Transport};
use nett_proto::v1::envelope::Body;
use nett_proto::v1::{
    AckResult, DesiredState, Envelope, Error as ProtoError, ErrorCode, Hello, Partition,
    PartitionKind, Pong, Welcome,
};
use prost::Message as _;

use crate::hub::Hub;
use crate::now;

/// 握手的时限。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// 节点每 25 秒发一次 Ping（protocol.md 第 8 节）；这么久没有任何消息就关闭连接。
const KEEPALIVE_SECS: u32 = 25;
const IDLE: Duration = Duration::from_secs(KEEPALIVE_SECS as u64 * 3);
/// 本机状态报告的上限。
const MAX_STATUS: usize = 512 * 1024;

pub async fn connect(ws: WebSocketUpgrade, AxumState(hub): AxumState<Arc<Hub>>) -> Response {
    ws.max_message_size(MAX_MESSAGE)
        .max_frame_size(MAX_MESSAGE)
        .on_upgrade(move |socket| async move {
            if let Err(e) = session(hub, socket).await {
                tracing::debug!(error = %e, "node session ended");
            }
        })
}

fn envelope(id: u64, body: Body) -> Envelope {
    Envelope {
        id,
        reply_to: 0,
        sent_at: Some(timestamp()),
        body: Some(body),
    }
}

fn timestamp() -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: now(),
        nanos: 0,
    }
}

/// 发出去的消息：编号、分片流与 Noise 加密。
struct Outbox {
    transport: Transport,
    next_id: u64,
    next_stream: u64,
}

impl Outbox {
    async fn send(&mut self, socket: &mut WebSocket, body: Body) -> Result<(), String> {
        self.next_id += 1;
        self.next_stream += 1;
        let env = envelope(self.next_id, body);
        for message in
            frame::encode(&env, &mut self.next_id, self.next_stream).map_err(|e| e.to_string())?
        {
            let ct = self
                .transport
                .encrypt(&message)
                .map_err(|e| e.to_string())?;
            socket
                .send(Message::Binary(ct.into()))
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

async fn session(hub: Arc<Hub>, mut socket: WebSocket) -> Result<(), String> {
    let first = tokio::time::timeout(HANDSHAKE_TIMEOUT, socket.recv())
        .await
        .map_err(|_| "no handshake")?
        .ok_or("closed before the handshake")?
        .map_err(|e| e.to_string())?;
    let Message::Binary(m1) = first else {
        return Err("the handshake is not a binary message".into());
    };
    let mut responder = Responder::new(&hub.key);
    let (payload, remote) = responder.read_message(&m1).map_err(|e| e.to_string())?;
    let hello = match Envelope::decode(payload.as_slice()).map(|e| e.body) {
        Ok(Some(Body::Hello(h))) => h,
        _ => return Err("the first message is not a Hello".into()),
    };
    let node = match identify(&hub, &remote, &hello).await {
        Ok(node) => node,
        Err((code, message)) => {
            let refusal = envelope(
                1,
                Body::Error(ProtoError {
                    code: code as i32,
                    message: message.clone(),
                    related_id: 0,
                }),
            );
            let (m2, _) = responder
                .write_message(&refusal.encode_to_vec())
                .map_err(|e| e.to_string())?;
            socket.send(Message::Binary(m2.into())).await.ok();
            return Err(message);
        }
    };
    let welcome = envelope(
        1,
        Body::Welcome(Welcome {
            protocol_version: nett_proto::PROTOCOL_VERSION.to_owned(),
            hub_version: env!("CARGO_PKG_VERSION").to_owned(),
            session_id: String::new(),
            server_time: Some(timestamp()),
            keepalive_secs: KEEPALIVE_SECS,
        }),
    );
    let (m2, transport) = responder
        .write_message(&welcome.encode_to_vec())
        .map_err(|e| e.to_string())?;
    socket
        .send(Message::Binary(m2.into()))
        .await
        .map_err(|e| e.to_string())?;
    tracing::info!(node_id = %node, version = %hello.node_version, "node connected");
    hub.db
        .seen(node.as_str(), now(), &hello.node_version)
        .await
        .map_err(|e| e.to_string())?;
    let replaced = hub.connected(&node).await;
    let result = serve(&hub, &node, &mut socket, transport, &replaced).await;
    hub.disconnected(&node, &replaced).await;
    hub.db
        .seen(node.as_str(), now(), &hello.node_version)
        .await
        .ok();
    tracing::info!(node_id = %node, "node disconnected");
    result
}

/// 按身份公钥认出节点：站点中没有这把公钥、节点 ID 对不上、已经撤销的都拒绝。
async fn identify(
    hub: &Hub,
    remote: &[u8; 32],
    hello: &Hello,
) -> Result<NodeId, (ErrorCode, String)> {
    let site = hub.site().await.ok_or((
        ErrorCode::NodeUnknown,
        "this Hub has no site yet".to_owned(),
    ))?;
    let node = site.by_identity.get(remote).cloned().ok_or((
        ErrorCode::NodeUnknown,
        "this machine is not in the site".to_owned(),
    ))?;
    if site.revoked.contains(&node) {
        return Err((
            ErrorCode::NodeRevoked,
            "this machine was removed from the site".to_owned(),
        ));
    }
    if hello.node_id != node.as_str() {
        return Err((
            ErrorCode::NodeUnknown,
            "the node ID does not belong to this identity key".to_owned(),
        ));
    }
    Ok(node)
}

async fn serve(
    hub: &Hub,
    node: &NodeId,
    socket: &mut WebSocket,
    transport: Transport,
    replaced: &tokio::sync::Notify,
) -> Result<(), String> {
    let mut out = Outbox {
        transport,
        next_id: 1,
        next_stream: 0,
    };
    let mut changes = hub.subscribe();
    send_desired(hub, node, socket, &mut out).await?;
    let mut reassembler = Reassembler::default();
    let idle = tokio::time::sleep(IDLE);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            message = socket.recv() => {
                let Some(message) = message else { return Ok(()) };
                match message.map_err(|e| e.to_string())? {
                    Message::Binary(ct) => {
                        idle.as_mut().reset(tokio::time::Instant::now() + IDLE);
                        let pt = out.transport.decrypt(&ct).map_err(|e| e.to_string())?;
                        if let Some(env) = reassembler.push(&pt).map_err(|e| e.to_string())?
                            && !handle(hub, node, socket, &mut out, env).await?
                        {
                            return Ok(());
                        }
                    }
                    Message::Close(_) => return Ok(()),
                    _ => {}
                }
            }
            changed = changes.changed() => {
                if changed.is_err() {
                    return Ok(());
                }
                send_desired(hub, node, socket, &mut out).await?;
            }
            () = replaced.notified() => return Ok(()),
            () = &mut idle => return Err("no message within the keepalive window".into()),
        }
    }
}

/// 处理节点发来的一条消息；`Goodbye` 时返回 `false`。
async fn handle(
    hub: &Hub,
    node: &NodeId,
    socket: &mut WebSocket,
    out: &mut Outbox,
    env: Envelope,
) -> Result<bool, String> {
    match env.body {
        Some(Body::Ping(_)) => {
            out.send(
                socket,
                Body::Pong(Pong {
                    server_time: Some(timestamp()),
                }),
            )
            .await?;
        }
        Some(Body::StateAck(ack)) => {
            if let Some(p) = ack
                .partitions
                .iter()
                .find(|p| p.kind == PartitionKind::Mesh as i32)
            {
                let result = match AckResult::try_from(p.result) {
                    Ok(AckResult::Applied) => "applied",
                    Ok(AckResult::Rejected) => "rejected",
                    Ok(AckResult::Pending) => "pending",
                    _ => "unknown",
                };
                hub.db
                    .set_ack(
                        node.as_str(),
                        i64::try_from(ack.generation).unwrap_or(i64::MAX),
                        result,
                        &p.reason,
                    )
                    .await
                    .map_err(|e| e.to_string())?;
            }
        }
        Some(Body::Inventory(inv)) => {
            hub.db
                .set_platform(node.as_str(), &inv.platform)
                .await
                .map_err(|e| e.to_string())?;
        }
        Some(Body::LinkReport(report)) => {
            // 只存合法的 JSON，大小有上限：它是节点提供的数据（硬性规则 13）
            if report.status.len() <= MAX_STATUS
                && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&report.status)
            {
                hub.db
                    .set_status(node.as_str(), &value.to_string(), now())
                    .await
                    .map_err(|e| e.to_string())?;
            }
        }
        Some(Body::Goodbye(_)) => return Ok(false),
        _ => {}
    }
    Ok(true)
}

/// 下发这台机器当前的期望状态：mesh 分区（期望状态文件的 JSON）与 hub_endpoints 分区。
async fn send_desired(
    hub: &Hub,
    node: &NodeId,
    socket: &mut WebSocket,
    out: &mut Outbox,
) -> Result<(), String> {
    let Some(site) = hub.site().await else {
        return Ok(());
    };
    let Some(mesh) = site.desired.get(node) else {
        return Ok(());
    };
    let endpoints = serde_json::to_vec(&[&hub.url]).map_err(|e| e.to_string())?;
    out.send(
        socket,
        Body::DesiredState(DesiredState {
            generation: site.generation,
            base_generation: 0,
            partitions: vec![
                Partition {
                    kind: PartitionKind::Mesh as i32,
                    content: mesh.clone(),
                },
                Partition {
                    kind: PartitionKind::HubEndpoints as i32,
                    content: endpoints,
                },
            ],
        }),
    )
    .await
}
