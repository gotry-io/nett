//! The node gateway (design/protocol.md, design/hub.md sections 5, 6): Noise IK over WebSocket,
//! with the Hub as the responder. A node handshakes with its own identity key and the Hub
//! recognizes it by the identity public key registered in the site; an unknown identity that
//! arrives with an admission proof is handled as enrollment. After that it sends down the desired
//! state, and records acknowledgments, the inventory, local status and the learned public address.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Extension;
use axum::extract::connect_info::Connected;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State as AxumState};
use axum::http::HeaderMap;
use axum::response::{IntoResponse as _, Response};
use axum::serve::IncomingStream;
use nett_core::id::NodeId;
use nett_proto::frame::{self, Reassembler};
use nett_proto::noise::{MAX_MESSAGE, Responder, Transport};
use nett_proto::v1::envelope::Body;
use nett_proto::v1::{
    AckResult, DesiredState, Envelope, Error as ProtoError, ErrorCode, Hello, Partition,
    PartitionKind, PathSwitch, Pong, Welcome,
};
use nett_site::state::{AddressSource, Learned, LearnedIp};
use prost::Message as _;

use crate::hub::{EnrollError, Hub};
use crate::now;
use crate::tls::TlsListener;

/// Handshake time limit.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// A node sends a Ping every 25 seconds (protocol.md section 8); the connection is closed after
/// this long with no message at all.
const KEEPALIVE_SECS: u32 = 25;
const IDLE: Duration = Duration::from_secs(KEEPALIVE_SECS as u64 * 3);
/// Upper limit on a local status report.
const MAX_STATUS: usize = 512 * 1024;
/// Number of addresses taken in `Inventory`.
const MAX_ADDRESSES: usize = 8;
/// Longest reason kept from an acknowledgement.
const MAX_REASON: usize = 1024;
/// Messages a node may send per second on average, and in a burst (protocol.md section 11).
const MESSAGES_PER_SECOND: f64 = 50.0;
const MESSAGE_BURST: f64 = 200.0;

/// A token bucket over the messages of one session.
struct Budget {
    tokens: f64,
    at: tokio::time::Instant,
}

impl Budget {
    fn new() -> Self {
        Self {
            tokens: MESSAGE_BURST,
            at: tokio::time::Instant::now(),
        }
    }

    /// Takes one message's worth; `false` when the node is over its budget.
    fn take(&mut self, now: tokio::time::Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        self.at = now;
        self.tokens = (self.tokens + elapsed * MESSAGES_PER_SECOND).min(MESSAGE_BURST);
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

/// The peer address of a connection: recorded by axum when `serve` uses
/// `into_make_service_with_connect_info::<Peer>()`.
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

/// The node gateway (design/protocol.md): a WebSocket carrying Noise IK and Protobuf messages.
/// Nodes authenticate with their identity key inside the Noise handshake, not with a token.
#[utoipa::path(
    get, path = "/node/v1/connect", tag = "nodes",
    responses(
        (status = 101, description = "Switching to the WebSocket protocol"),
        (status = 503, description = "Too many node connections"),
    ),
    extensions(("x-nett-scope" = json!("node identity (Noise IK)")), ("x-nett-risk" = json!("low"))),
)]
pub async fn connect(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<Peer>>>,
    AxumState(hub): AxumState<Arc<Hub>>,
) -> Response {
    let observed = observed(peer.map(|Extension(ConnectInfo(Peer(a)))| a), &headers);
    // Bounded before the upgrade (protocol.md section 11): the permit lives as long as the session
    let Ok(permit) = hub.connections.clone().try_acquire_owned() else {
        tracing::warn!("node connection refused: too many connections");
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "too many node connections",
        )
            .into_response();
    };
    ws.max_message_size(MAX_MESSAGE)
        .max_frame_size(MAX_MESSAGE)
        .on_upgrade(move |socket| async move {
            if let Err(e) = session(hub, socket, observed).await {
                tracing::debug!(error = %e, "node session ended");
            }
            drop(permit);
        })
}

/// The source address the Hub sees (design/hub.md section 5): when the TCP peer is loopback or a
/// private address it is a proxy in front of the Hub, and the last entry of `X-Forwarded-For` is
/// taken (the one added by the nearest proxy); otherwise it is the peer itself.
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

/// `100.64.0.0/10` (carrier-grade NAT, which also contains the mesh addresses).
fn is_shared(v4: std::net::Ipv4Addr) -> bool {
    let [a, b, ..] = v4.octets();
    a == 100 && (64..128).contains(&b)
}

/// Global unicast address: only this kind of address reported by a machine can be used directly as
/// a public address.
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

/// The public addresses of a machine, per address family: the machine's report when it is a global
/// unicast address, otherwise the address the Hub sees; loopback addresses are not used.
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
        ..Learned::default()
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

/// An outgoing message: numbering, fragment stream and Noise encryption.
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
    let handshake = hub
        .handshakes
        .clone()
        .try_acquire_owned()
        .map_err(|_| "too many handshakes in progress")?;
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
    drop(handshake);
    tracing::info!(node_id = %node, version = %hello.node_version, "node connected");
    hub.event(&node, "connected", &format!("nett {}", hello.node_version))
        .await;
    hub.db
        .seen(node.as_str(), now(), &hello.node_version)
        .await
        .map_err(|e| e.to_string())?;
    let (replaced, switches) = hub.connected(&node).await;
    let result = serve(
        &hub,
        &node,
        &mut socket,
        transport,
        &replaced,
        switches,
        observed,
    )
    .await;
    hub.disconnected(&node, &replaced).await;
    hub.db
        .seen(node.as_str(), now(), &hello.node_version)
        .await
        .ok();
    tracing::info!(node_id = %node, "node disconnected");
    let why = match &result {
        Ok(()) => "closed".to_owned(),
        Err(e) => e.chars().take(MAX_REASON).collect(),
    };
    hub.event(&node, "disconnected", &why).await;
    result
}

/// Recognizes a node by identity public key: it is rejected if the site does not have this public
/// key, the node ID does not match, or it is revoked. An unknown identity that arrives with an
/// admission proof is handled as enrollment (design/hub.md section 6).
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
    mut switches: tokio::sync::mpsc::Receiver<(NodeId, Vec<u8>)>,
    observed: Option<IpAddr>,
) -> Result<(), String> {
    let mut out = Outbox {
        transport,
        next_id: 1,
        next_stream: 0,
    };
    let mut changes = hub.subscribe();
    let mut releases = hub.subscribe_release();
    releases.mark_unchanged();
    send_desired(hub, node, socket, &mut out).await?;
    let mut reassembler = Reassembler::default();
    let mut budget = Budget::new();
    let idle = tokio::time::sleep(IDLE);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            message = socket.recv() => {
                let Some(message) = message else { return Ok(()) };
                match message.map_err(|e| e.to_string())? {
                    Message::Binary(ct) => {
                        idle.as_mut().reset(tokio::time::Instant::now() + IDLE);
                        if !budget.take(tokio::time::Instant::now()) {
                            out.send(
                                socket,
                                Body::Error(ProtoError {
                                    code: ErrorCode::RateLimited as i32,
                                    message: "too many messages".to_owned(),
                                    related_id: 0,
                                }),
                            )
                            .await
                            .ok();
                            return Err("the node sent too many messages".into());
                        }
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
            changed = releases.changed() => {
                if changed.is_err() {
                    return Ok(());
                }
                send_release(hub, socket, &mut out).await?;
            }
            Some((from, message)) = switches.recv() => {
                out.send(socket, Body::PathSwitch(PathSwitch {
                    node_id: from.to_string(),
                    message,
                }))
                .await?;
            }
            () = replaced.notified() => return Ok(()),
            () = &mut idle => return Err("no message within the keepalive window".into()),
        }
    }
}

/// Handles one message from a node; returns `false` on `Goodbye` and `Leave`.
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
            let result = |p: &nett_proto::v1::PartitionAck| match AckResult::try_from(p.result) {
                Ok(AckResult::Applied) => "applied",
                Ok(AckResult::Rejected) => "rejected",
                Ok(AckResult::Pending) => "pending",
                _ => "unknown",
            };
            // The reasons are the node's text: stored bounded (hard rule 13)
            let reason = |p: &nett_proto::v1::PartitionAck| -> String {
                p.reason.chars().take(MAX_REASON).collect()
            };
            for p in &ack.partitions {
                let detail = |what: String| {
                    let reason = reason(p);
                    if reason.is_empty() {
                        what
                    } else {
                        format!("{what}: {reason}")
                    }
                };
                if p.kind == PartitionKind::Mesh as i32 {
                    hub.db
                        .set_ack(
                            node.as_str(),
                            i64::try_from(ack.generation).unwrap_or(i64::MAX),
                            result(p),
                            &reason(p),
                        )
                        .await
                        .map_err(|e| e.to_string())?;
                    hub.event(
                        node,
                        "config",
                        &detail(format!("generation {} {}", ack.generation, result(p))),
                    )
                    .await;
                } else if p.kind == PartitionKind::Release as i32 {
                    hub.db
                        .set_upgrade(node.as_str(), result(p), &reason(p))
                        .await
                        .map_err(|e| e.to_string())?;
                    // An answer that says nothing new is not an event
                    if result(p) != "applied" {
                        hub.event(node, "upgrade", &detail(result(p).to_owned()))
                            .await;
                    }
                }
            }
        }
        Some(Body::Inventory(inv)) => {
            hub.db
                .set_platform(node.as_str(), &inv.platform)
                .await
                .map_err(|e| e.to_string())?;
            // Only the first few addresses are taken: they are data supplied by the node (hard rule
            // 13)
            let reported: Vec<String> = inv.addresses.into_iter().take(MAX_ADDRESSES).collect();
            let addresses = learn(&reported, observed);
            let change = |l: &mut Learned| {
                l.ipv4 = addresses.ipv4;
                l.ipv6 = addresses.ipv6;
            };
            if let Err(e) = hub.learn(node, change, now()).await {
                tracing::warn!(node_id = %node, error = %e, "recording the public address");
            }
        }
        Some(Body::Leave(_)) => {
            hub.leave(node, now()).await.map_err(|e| e.to_string())?;
            return Ok(false);
        }
        Some(Body::LinkReport(report)) => {
            // Only valid JSON is stored, with a size limit: it is data supplied by the node (hard
            // rule 13)
            if report.status.len() <= MAX_STATUS
                && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&report.status)
            {
                hub.db
                    .set_status(node.as_str(), &value.to_string(), now())
                    .await
                    .map_err(|e| e.to_string())?;
                // From the status the Hub learns the relay's certificate (design/mesh.md section 5.3),
                // the LAN addresses and the WireGuard port (section 6)
                let fingerprint = value
                    .pointer("/relay/fingerprint")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|f| f.parse().ok());
                let mut lan: Vec<nett_mesh::lan::LanAddress> = value
                    .pointer("/node/lan")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|a| a.as_str()?.parse().ok())
                    .take(nett_mesh::lan::MAX_LAN_ADDRESSES)
                    .collect();
                lan.sort();
                lan.dedup();
                let listen_port = value
                    .pointer("/node/listen_port")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|p| u16::try_from(p).ok())
                    .filter(|p| *p != 0);
                let change = |l: &mut Learned| {
                    l.relay_fingerprint = fingerprint;
                    l.lan = lan;
                    l.listen_port = listen_port;
                };
                if let Err(e) = hub.learn(node, change, now()).await {
                    tracing::warn!(node_id = %node, error = %e, "recording what the status tells");
                }
            }
        }
        // Opaque to the Hub: authenticated end to end by the two mesh processes (design/mesh.md section
        // 8.4); checked here only for size and that the pair is connected
        Some(Body::PathSwitch(p)) => {
            if let Ok(to) = p.node_id.parse::<NodeId>()
                && p.message.len() <= nett_mesh::coord::MAX_MESSAGE
                && !hub.path_switch(node, &to, p.message).await
            {
                tracing::debug!(node_id = %node, to = %to, "switch message not passed on");
            }
        }
        Some(Body::Goodbye(_)) => return Ok(false),
        _ => {}
    }
    Ok(true)
}

/// Sends down this machine's current desired state: the mesh partition (JSON of the desired state
/// file) and the hub_endpoints partition.
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
    let mut partitions = vec![
        Partition {
            kind: PartitionKind::Mesh as i32,
            content: mesh.clone(),
        },
        Partition {
            kind: PartitionKind::HubEndpoints as i32,
            content: endpoints,
        },
    ];
    if let Some(manifest) = hub.release() {
        partitions.push(Partition {
            kind: PartitionKind::Release as i32,
            content: manifest.to_vec(),
        });
    }
    out.send(
        socket,
        Body::DesiredState(DesiredState {
            generation: site.generation,
            base_generation: 0,
            partitions,
        }),
    )
    .await
}

/// A new release manifest alone, as an increment on the current generation (protocol.md
/// section 6.1).
async fn send_release(hub: &Hub, socket: &mut WebSocket, out: &mut Outbox) -> Result<(), String> {
    let (Some(site), Some(manifest)) = (hub.site().await, hub.release()) else {
        return Ok(());
    };
    out.send(
        socket,
        Body::DesiredState(DesiredState {
            generation: site.generation,
            base_generation: site.generation,
            partitions: vec![Partition {
                kind: PartitionKind::Release as i32,
                content: manifest.to_vec(),
            }],
        }),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_gets_a_burst_and_then_its_average_rate() {
        let mut budget = Budget::new();
        let start = budget.at;
        let burst = (0..1000).take_while(|_| budget.take(start)).count();
        assert_eq!(burst, MESSAGE_BURST as usize);
        // a second later, 50 more
        let later = start + std::time::Duration::from_secs(1);
        let refill = (0..1000).take_while(|_| budget.take(later)).count();
        assert_eq!(refill, MESSAGES_PER_SECOND as usize);
    }

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
        // A local proxy: take the last entry it added
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
        // A header written by a peer on the public internet does not count
        assert_eq!(
            observed(peer("203.0.113.5:50000"), &headers(&["192.0.2.9"])),
            Some(ip("203.0.113.5"))
        );
        // No proxy (lab topology, LAN): the peer itself
        assert_eq!(
            observed(peer("10.0.0.2:50000"), &headers(&[])),
            Some(ip("10.0.0.2"))
        );
        assert_eq!(observed(None, &headers(&["192.0.2.9"])), None);
    }

    #[test]
    fn the_machine_address_counts_only_when_it_is_global() {
        let one = |l: Learned| l.ipv4.map(|i| (i.ip.to_string(), i.from));
        // Most VPSes: the network interface has the public address
        assert_eq!(
            one(learn(&["203.0.113.5".into()], Some(ip("203.0.113.5")))),
            Some(("203.0.113.5".into(), AddressSource::Machine))
        );
        // A cloud host with 1:1 NAT: the interface has a private address, so use the one the Hub
        // sees
        assert_eq!(
            one(learn(&["172.16.0.5".into()], Some(ip("198.51.100.7")))),
            Some(("198.51.100.7".into(), AddressSource::Hub))
        );
        // Mesh addresses and carrier-grade NAT are not public addresses
        assert_eq!(
            one(learn(&["100.88.0.3".into()], Some(ip("198.51.100.7")))),
            Some(("198.51.100.7".into(), AddressSource::Hub))
        );
        // Loopback (a member on the Hub host connecting through the local machine): unknown
        assert_eq!(
            learn(&["127.0.0.1".into()], Some(ip("127.0.0.1"))),
            Learned::default()
        );
        // The two address families are taken separately
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
