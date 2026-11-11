//! 节点网关（design/protocol.md、design/hub.md 第 5、6 节）：WebSocket 上的 Noise IK，Hub 是响应方。节点用自己的
//! 身份密钥握手，Hub 按站点中登记的身份公钥认出它；不认识的身份带着准入证明来时按入网处理。之后下发期望
//! 状态，记下确认、清单、本机状态与得知的公网地址。

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Extension;
use axum::extract::connect_info::Connected;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State as AxumState};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::serve::IncomingStream;
use nett_core::id::NodeId;
use nett_proto::frame::{self, Reassembler};
use nett_proto::noise::{MAX_MESSAGE, Responder, Transport};
use nett_proto::v1::envelope::Body;
use nett_proto::v1::{
    AckResult, DesiredState, Envelope, Error as ProtoError, ErrorCode, Hello, Partition,
    PartitionKind, Pong, Welcome,
};
use nett_site::state::{AddressSource, Learned, LearnedIp};
use prost::Message as _;

use crate::hub::{EnrollError, Hub};
use crate::now;
use crate::tls::TlsListener;

/// 握手的时限。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// 节点每 25 秒发一次 Ping（protocol.md 第 8 节）；这么久没有任何消息就关闭连接。
const KEEPALIVE_SECS: u32 = 25;
const IDLE: Duration = Duration::from_secs(KEEPALIVE_SECS as u64 * 3);
/// 本机状态报告的上限。
const MAX_STATUS: usize = 512 * 1024;
/// `Inventory` 中采用的地址数。
const MAX_ADDRESSES: usize = 8;

/// 连接的对端地址：`serve` 用 `into_make_service_with_connect_info::<Peer>()` 时由 axum 记下。
#[derive(Debug, Clone, Copy)]
pub struct Peer(pub SocketAddr);

impl Connected<IncomingStream<'_, tokio::net::TcpListener>> for Peer {
    fn connect_info(stream: IncomingStream<'_, tokio::net::TcpListener>) -> Self {
        Self(*stream.remote_addr())
    }
}

impl Connected<IncomingStream<'_, TlsListener>> for Peer {
    fn connect_info(stream: IncomingStream<'_, TlsListener>) -> Self {
        Self(*stream.remote_addr())
    }
}

pub async fn connect(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<Peer>>>,
    AxumState(hub): AxumState<Arc<Hub>>,
) -> Response {
    let observed = observed(peer.map(|Extension(ConnectInfo(Peer(a)))| a), &headers);
    ws.max_message_size(MAX_MESSAGE)
        .max_frame_size(MAX_MESSAGE)
        .on_upgrade(move |socket| async move {
            if let Err(e) = session(hub, socket, observed).await {
                tracing::debug!(error = %e, "node session ended");
            }
        })
}

/// Hub 看到的来源地址（design/hub.md 第 5 节）：TCP 对端是回环或私有地址时它是 Hub 前的代理，取
/// `X-Forwarded-For` 的最后一项（最近的代理加上的那一项）；否则就是对端自己。
pub fn observed(peer: Option<SocketAddr>, headers: &HeaderMap) -> Option<IpAddr> {
    let peer = peer?.ip();
    if peer.is_loopback() || is_private(peer) {
        let forwarded = headers
            .get_all("x-forwarded-for")
            .iter()
            .next_back()
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse().ok());
        if forwarded.is_some() {
            return forwarded;
        }
    }
    Some(peer)
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || is_shared(v4),
        IpAddr::V6(v6) => v6.is_unique_local(),
    }
}

/// `100.64.0.0/10`（运营商级 NAT，组网地址也在其中）。
fn is_shared(v4: std::net::Ipv4Addr) -> bool {
    let [a, b, ..] = v4.octets();
    a == 100 && (64..128).contains(&b)
}

/// 全局单播地址：机器报告的地址只有这种才能直接当作公网地址。
fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || is_shared(v4))
        }
        IpAddr::V6(v6) => {
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local())
        }
    }
}

/// 每个地址族：机器报告的是全局单播地址时用它，否则用 Hub 看到的地址；回环地址不用。
pub fn learn(reported: &[String], observed: Option<IpAddr>) -> Learned {
    let reported: Vec<IpAddr> = reported.iter().filter_map(|a| a.parse().ok()).collect();
    let pick = |v4: bool| {
        let family = |ip: &IpAddr| ip.is_ipv4() == v4;
        reported
            .iter()
            .find(|ip| family(ip) && is_global(**ip))
            .map(|ip| (*ip, AddressSource::Machine))
            .or_else(|| {
                observed
                    .filter(|ip| family(ip) && !ip.is_loopback() && !ip.is_unspecified())
                    .map(|ip| (ip, AddressSource::Hub))
            })
    };
    Learned {
        ipv4: pick(true).and_then(|(ip, from)| match ip {
            IpAddr::V4(ip) => Some(LearnedIp { ip, from }),
            IpAddr::V6(_) => None,
        }),
        ipv6: pick(false).and_then(|(ip, from)| match ip {
            IpAddr::V6(ip) => Some(LearnedIp { ip, from }),
            IpAddr::V4(_) => None,
        }),
    }
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

async fn session(
    hub: Arc<Hub>,
    mut socket: WebSocket,
    observed: Option<IpAddr>,
) -> Result<(), String> {
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
    let result = serve(&hub, &node, &mut socket, transport, &replaced, observed).await;
    hub.disconnected(&node, &replaced).await;
    hub.db
        .seen(node.as_str(), now(), &hello.node_version)
        .await
        .ok();
    tracing::info!(node_id = %node, "node disconnected");
    result
}

/// 按身份公钥认出节点：站点中没有这把公钥、节点 ID 对不上、已经撤销的都拒绝。不认识的身份带着准入证明来时
/// 按入网处理（design/hub.md 第 6 节）。
async fn identify(
    hub: &Hub,
    remote: &[u8; 32],
    hello: &Hello,
) -> Result<NodeId, (ErrorCode, String)> {
    let site = hub.site().await.ok_or((
        ErrorCode::NodeUnknown,
        "this Hub has no site yet".to_owned(),
    ))?;
    let Some(node) = site.by_identity.get(remote).cloned() else {
        if hello.admission_proof.is_empty() {
            return Err((
                ErrorCode::NodeUnknown,
                "this machine is not in the site".to_owned(),
            ));
        }
        return hub
            .enroll(&hello.node_id, remote, &hello.admission_proof, now())
            .await
            .map_err(|e| match e {
                EnrollError::Refused(m) => (ErrorCode::EnrollmentRefused, m),
                EnrollError::Db(e) => {
                    tracing::error!(error = %e, "recording an enrollment");
                    (
                        ErrorCode::EnrollmentRefused,
                        "the Hub could not record the enrollment; try again".to_owned(),
                    )
                }
            });
    };
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
    observed: Option<IpAddr>,
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
                            && !handle(hub, node, socket, &mut out, env, observed).await?
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

/// 处理节点发来的一条消息；`Goodbye` 与 `Leave` 时返回 `false`。
async fn handle(
    hub: &Hub,
    node: &NodeId,
    socket: &mut WebSocket,
    out: &mut Outbox,
    env: Envelope,
    observed: Option<IpAddr>,
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
            // 地址只取前几项：它是节点提供的数据（硬性规则 13）
            let reported: Vec<String> = inv.addresses.into_iter().take(MAX_ADDRESSES).collect();
            if let Err(e) = hub.learned(node, learn(&reported, observed), now()).await {
                tracing::warn!(node_id = %node, error = %e, "recording the public address");
            }
        }
        Some(Body::Leave(_)) => {
            hub.leave(node, now()).await.map_err(|e| e.to_string())?;
            return Ok(false);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(xff: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in xff {
            h.append("x-forwarded-for", v.parse().expect("header"));
        }
        h
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    #[test]
    fn the_observed_address_trusts_only_the_proxy_in_front() {
        let peer = |s: &str| Some(s.parse::<SocketAddr>().expect("addr"));
        // 本机的代理：取它加上的最后一项
        assert_eq!(
            observed(
                peer("127.0.0.1:50000"),
                &headers(&["192.0.2.9, 198.51.100.7"])
            ),
            Some(ip("198.51.100.7"))
        );
        assert_eq!(
            observed(
                peer("172.18.0.2:50000"),
                &headers(&["192.0.2.9", "198.51.100.7"])
            ),
            Some(ip("198.51.100.7"))
        );
        // 公网上的对端自己写的头不算数
        assert_eq!(
            observed(peer("203.0.113.5:50000"), &headers(&["192.0.2.9"])),
            Some(ip("203.0.113.5"))
        );
        // 没有代理（实验拓扑、局域网）：对端自己
        assert_eq!(
            observed(peer("10.0.0.2:50000"), &headers(&[])),
            Some(ip("10.0.0.2"))
        );
        assert_eq!(observed(None, &headers(&["192.0.2.9"])), None);
    }

    #[test]
    fn the_machine_address_counts_only_when_it_is_global() {
        let one = |l: Learned| l.ipv4.map(|i| (i.ip.to_string(), i.from));
        // 多数 VPS：网卡上就是公网地址
        assert_eq!(
            one(learn(&["203.0.113.5".into()], Some(ip("203.0.113.5")))),
            Some(("203.0.113.5".into(), AddressSource::Machine))
        );
        // 1:1 NAT 的云主机：网卡上是私有地址，用 Hub 看到的
        assert_eq!(
            one(learn(&["172.16.0.5".into()], Some(ip("198.51.100.7")))),
            Some(("198.51.100.7".into(), AddressSource::Hub))
        );
        // 组网地址与运营商级 NAT 都不是公网地址
        assert_eq!(
            one(learn(&["100.88.0.3".into()], Some(ip("198.51.100.7")))),
            Some(("198.51.100.7".into(), AddressSource::Hub))
        );
        // 回环（Hub 主机自己的成员经本机连接）：不知道
        assert_eq!(
            learn(&["127.0.0.1".into()], Some(ip("127.0.0.1"))),
            Learned::default()
        );
        // 两个地址族分别取
        let both = learn(&["2001:db8::5".into()], Some(ip("198.51.100.7")));
        assert_eq!(both.ipv4.map(|i| i.from), Some(AddressSource::Hub));
        assert_eq!(
            both.ipv6.map(|i| (i.ip.to_string(), i.from)),
            Some(("2001:db8::5".into(), AddressSource::Machine))
        );
        assert_eq!(
            learn(&["fd00::5".into(), "not an address".into()], None),
            Learned::default()
        );
    }
}
