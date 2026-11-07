//! 中继的收发循环（design/mesh.md 第 5.1–5.3 节）：一个 tokio 单线程任务持有 [`Relay`]，收 UDP 包和
//! TLS（WebSocket）连接上的消息，按结果转发或应答。每条 TLS 连接一个任务，与主循环之间只经有上限的通道
//! 传递消息；队列满时丢包（WireGuard 自己会重传），不阻塞主循环。

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt as _, StreamExt as _};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::relay::{ConnId, Outcome, PeerAddr, Relay, RelayState};

const EXPIRE_INTERVAL: Duration = Duration::from_secs(1);
/// 外层包最大约 1360 字节（design/mesh.md 第 4 节），留出余量。
const MAX_DATAGRAM: usize = 2048;
/// 保存状态的间隔（design/mesh.md 第 5.2 节）。
const SAVE_INTERVAL: Duration = Duration::from_secs(1);
/// TLS 连接数的上限，以及其中等待认证的连接数的上限。
const MAX_TLS_CONNECTIONS: usize = 1024;
const MAX_UNAUTHENTICATED: usize = 64;
/// TLS 与 WebSocket 握手的时限；连接建立后多久内必须收到带认证的探测（design/mesh.md 第 5.3 节）。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const AUTH_TIMEOUT: Duration = Duration::from_secs(30);
/// 每条 TLS 连接的发送队列，以及各连接交给主循环的消息队列。
const CONN_QUEUE: usize = 256;
const EVENT_QUEUE: usize = 4096;

/// 在 `addr` 上监听 TLS 入口。
pub fn tls_listener(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(1024)
}

/// 中继端口上的 TLS 入口。
pub struct TlsIngress {
    pub listener: TcpListener,
    pub acceptor: TlsAcceptor,
}

enum Event {
    Opened(ConnId, mpsc::Sender<Vec<u8>>),
    Packet(ConnId, Vec<u8>),
    Closed(ConnId),
}

struct Conn {
    tx: mpsc::Sender<Vec<u8>>,
    opened: Instant,
    authenticated: bool,
}

/// 一直运行到 `shutdown` 完成。`udp` 是双栈的中继端口。`state` 为保存索引表的文件：启动时恢复，每秒
/// 一次、以及退出之前写入，重启时经它的连接不中断。
pub async fn serve(
    udp: UdpSocket,
    tls: Option<TlsIngress>,
    mut relay: Relay,
    state: Option<PathBuf>,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    if let Some(path) = &state {
        match load(path) {
            Ok(Some(saved)) => {
                relay.restore(&saved, Instant::now());
                let (_, sessions) = relay.table_sizes();
                tracing::info!(sessions, "relay state restored");
            }
            Ok(None) => {}
            // 状态文件损坏只影响恢复：经它的连接按 design/mesh.md 第 8.4 节重新握手
            Err(error) => tracing::warn!(%error, "relay state not restored"),
        }
    }
    let (events_tx, mut events) = mpsc::channel(EVENT_QUEUE);
    let mut conns: HashMap<ConnId, Conn> = HashMap::new();
    let mut next_conn = 0u64;
    let mut buf = vec![0u8; MAX_DATAGRAM];
    let mut tick = tokio::time::interval(EXPIRE_INTERVAL);
    let mut last_save = Instant::now();
    // 写盘可能因磁盘忙卡住几百毫秒（例如 ext4 每 5 秒提交日志时），放在阻塞线程里，不挡住转发；
    // 同一时间只有一次保存，上一次还没写完时跳过，下一秒保存最新的
    let mut saving: Option<tokio::task::JoinHandle<()>> = None;
    let mut dropped: u64 = 0;
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            received = udp.recv_from(&mut buf) => {
                let (len, from) = received?;
                let from = PeerAddr::Udp(unmap(from));
                let packet = &buf[..len];
                let outcome = relay.handle(from, packet, Instant::now(), now_ms());
                dispatch(&udp, &conns, from, packet, outcome, &mut dropped);
            }
            accepted = accept(tls.as_ref()) => {
                let Ok((stream, peer)) = accepted else { continue };
                let unauthenticated = conns.values().filter(|c| !c.authenticated).count();
                if conns.len() >= MAX_TLS_CONNECTIONS || unauthenticated >= MAX_UNAUTHENTICATED {
                    tracing::debug!(%peer, "too many TLS connections; closing");
                    continue;
                }
                let Some(ingress) = tls.as_ref() else { continue };
                next_conn += 1;
                let id = ConnId(next_conn);
                tokio::spawn(connection(id, stream, ingress.acceptor.clone(), events_tx.clone()));
            }
            Some(event) = events.recv() => match event {
                Event::Opened(id, tx) => {
                    conns.insert(id, Conn { tx, opened: Instant::now(), authenticated: false });
                }
                Event::Packet(id, packet) => {
                    let Some(conn) = conns.get_mut(&id) else { continue };
                    if conn.authenticated {
                        let from = PeerAddr::Tls(id);
                        let outcome = relay.handle(from, &packet, Instant::now(), now_ms());
                        dispatch(&udp, &conns, from, &packet, outcome, &mut dropped);
                    } else if let Some(reply) = relay.authenticate(id, &packet, now_ms()) {
                        conn.authenticated = true;
                        tracing::info!(conn = id.0, "TLS connection authenticated");
                        drop(conn.tx.try_send(reply));
                    } else {
                        // 第一条消息不是带认证的探测：关闭连接，不作任何应答
                        conns.remove(&id);
                    }
                }
                Event::Closed(id) => {
                    if conns.remove(&id).is_some_and(|c| c.authenticated) {
                        tracing::info!(conn = id.0, "TLS connection closed");
                    }
                    relay.closed(id);
                }
            },
            _ = tick.tick() => {
                let now = Instant::now();
                relay.expire(now);
                // 迟迟没有认证的连接：丢掉发送端，连接任务随之结束
                conns.retain(|_, c| c.authenticated || now.saturating_duration_since(c.opened) < AUTH_TIMEOUT);
                if let Some(path) = &state
                    && now.saturating_duration_since(last_save) >= SAVE_INTERVAL
                    && saving.as_ref().is_none_or(tokio::task::JoinHandle::is_finished)
                {
                    last_save = now;
                    saving = Some(save_in_background(path, relay.snapshot(now)));
                }
            }
        }
    }
    if let Some(path) = &state {
        if let Some(previous) = saving.take() {
            drop(previous.await);
        }
        drop(save_in_background(path, relay.snapshot(Instant::now())).await);
    }
    Ok(())
}

async fn accept(tls: Option<&TlsIngress>) -> std::io::Result<(TcpStream, SocketAddr)> {
    match tls {
        Some(ingress) => ingress.listener.accept().await,
        None => std::future::pending().await,
    }
}

/// 执行 [`Relay::handle`] 的结果。发送失败（例如对方暂时没有路由、连接的队列已满）只丢这一个包。
fn dispatch(
    udp: &UdpSocket,
    conns: &HashMap<ConnId, Conn>,
    from: PeerAddr,
    packet: &[u8],
    outcome: Outcome,
    dropped: &mut u64,
) {
    let send = |to: PeerAddr, data: &[u8]| match to {
        PeerAddr::Udp(addr) => drop(udp.try_send_to(data, map_v6(addr))),
        PeerAddr::Tls(id) => {
            if let Some(conn) = conns.get(&id) {
                drop(conn.tx.try_send(data.to_vec()));
            }
        }
    };
    match outcome {
        Outcome::Forward(to) => send(to, packet),
        Outcome::ForwardEach(targets) => {
            for to in targets {
                send(to, packet);
            }
        }
        Outcome::Reply(reply) => send(from, &reply),
        Outcome::Drop(reason) => {
            *dropped += 1;
            tracing::debug!(?reason, ?from, dropped, "relay dropped a packet");
        }
    }
}

/// 一条 TLS 连接：TLS 与 WebSocket 握手，之后每个二进制消息是一个 WireGuard 包或中继探测。
async fn connection(
    id: ConnId,
    stream: TcpStream,
    acceptor: TlsAcceptor,
    events: mpsc::Sender<Event>,
) {
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_DATAGRAM))
        .max_frame_size(Some(MAX_DATAGRAM));
    let handshake = async {
        let tls = acceptor.accept(stream).await.ok()?;
        tokio_tungstenite::accept_async_with_config(tls, Some(config))
            .await
            .ok()
    };
    let Ok(Some(ws)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake).await else {
        return;
    };
    let (tx, mut rx) = mpsc::channel(CONN_QUEUE);
    if events.send(Event::Opened(id, tx)).await.is_err() {
        return;
    }
    let (mut sink, mut source) = ws.split();
    loop {
        tokio::select! {
            incoming = source.next() => match incoming {
                Some(Ok(Message::Binary(data))) => {
                    if data.len() <= MAX_DATAGRAM
                        && events.send(Event::Packet(id, data.to_vec())).await.is_err()
                    {
                        break;
                    }
                }
                // 保活由 WebSocket 库自动应答
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                _ => break,
            },
            outgoing = rx.recv() => match outgoing {
                Some(data) => {
                    if sink.send(Message::binary(data)).await.is_err() {
                        break;
                    }
                }
                // 主循环不再需要这条连接（认证失败或超时）
                None => break,
            },
        }
    }
    drop(sink.close().await);
    drop(events.send(Event::Closed(id)).await);
}

fn load(path: &Path) -> std::io::Result<Option<RelayState>> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(std::io::Error::other),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn save_in_background(path: &Path, snapshot: RelayState) -> tokio::task::JoinHandle<()> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || save_or_warn(&path, &snapshot))
}

/// 先写临时文件再改名：重启时读到的总是一份完整的状态。
fn save(path: &Path, snapshot: &RelayState) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let bytes = serde_json::to_vec(snapshot).map_err(std::io::Error::other)?;
    let tmp = path.with_extension("tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(&bytes)?;
    std::fs::rename(&tmp, path)
}

fn save_or_warn(path: &Path, snapshot: &RelayState) {
    if let Err(error) = save(path, snapshot) {
        tracing::warn!(%error, path = %path.display(), "saving relay state failed");
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn unmap(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(a) => match a.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), a.port()),
            None => addr,
        },
        SocketAddr::V4(_) => addr,
    }
}

fn map_v6(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(a) => SocketAddr::new(IpAddr::V6(a.ip().to_ipv6_mapped()), a.port()),
        SocketAddr::V6(_) => addr,
    }
}

/// 从 PEM 文件建立 TLS 入口的服务端配置：只用 TLS 1.3，加密后端为 ring。
pub fn tls_acceptor(cert: &Path, key: &Path) -> Result<TlsAcceptor, TlsSetupError> {
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let chain = CertificateDer::pem_file_iter(cert)
        .and_then(|certs| certs.collect::<Result<Vec<_>, _>>())
        .map_err(|e| TlsSetupError::Certificate(e.to_string()))?;
    // 错误信息不包含私钥内容（硬性规则 10）
    let key = PrivateKeyDer::from_pem_file(key).map_err(|_| TlsSetupError::Key)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsSetupError::Config(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| TlsSetupError::Config(e.to_string()))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[derive(Debug, thiserror::Error)]
pub enum TlsSetupError {
    #[error("reading the TLS certificate chain: {0}")]
    Certificate(String),
    #[error("reading the TLS private key failed (file missing, unreadable, or not PEM)")]
    Key,
    #[error("building the TLS configuration: {0}")]
    Config(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::AssignedMember;
    use nett_mesh::probe::{KeyId, OuterProbe, OuterReply, ProbeKey, RELAY_PROBE};
    use nett_trust::keys::X25519PublicKey;

    /// 保存状态的写入卡住时（这里用一个没有读者的命名管道代替忙碌的磁盘），中继照常应答和转发。
    #[test]
    fn a_stuck_state_write_does_not_hold_up_forwarding() {
        let dir = std::env::temp_dir().join(format!("nett-relay-save-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let state = dir.join("relay-state.json");
        // 保存时先写的临时文件是一个管道：打开它写入会一直等到有人来读
        let fifo = state.with_extension("tmp");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo");
        assert!(made.success(), "mkfifo failed");

        let (a, b) = ([1; 32], [2; 32]);
        let member = |k: [u8; 32], address| AssignedMember {
            public_key: X25519PublicKey::from_bytes(k),
            address,
            token: [k[0]; 32],
        };
        let relay = Relay::new(
            &[
                member(a, Some("198.51.100.1:41820".parse().expect("addr"))),
                member(b, None),
            ],
            &[(
                X25519PublicKey::from_bytes(a),
                X25519PublicKey::from_bytes(b),
            )],
        )
        .expect("assignment");

        // 中继端口是双栈的：应答按 IPv6 映射地址发出
        let socket = std::net::UdpSocket::bind("[::]:0").expect("relay socket");
        socket.set_nonblocking(true).expect("nonblocking");
        let relay_addr =
            SocketAddr::from(([127, 0, 0, 1], socket.local_addr().expect("addr").port()));
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server_state = state.clone();
        // 与 `nett relay` 一样跑在单线程运行时上
        let server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(async move {
                let udp = UdpSocket::from_std(socket).expect("tokio socket");
                serve(udp, None, relay, Some(server_state), async {
                    drop(stopped.await);
                })
                .await
            })
        });

        // 第一次保存在启动约 1 秒后，此后它一直卡在管道上
        std::thread::sleep(SAVE_INTERVAL + Duration::from_millis(1_500));
        let client = std::net::UdpSocket::bind("127.0.0.1:0").expect("client socket");
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("timeout");
        let key = ProbeKey::from_token(&[2; 32]);
        let probe = OuterProbe {
            kind: RELAY_PROBE,
            key_id: KeyId::of(&b),
            seq: 1,
            sent_ms: now_ms(),
        };
        client
            .send_to(&probe.encode(&key), relay_addr)
            .expect("send probe");
        let mut buf = [0u8; MAX_DATAGRAM];
        let replied = client
            .recv_from(&mut buf)
            .map(|(len, _)| OuterReply::verify(&buf[..len], &key).is_some());

        // 放开卡住的写入，中继退出前的保存才能完成
        let reader = std::thread::spawn(move || std::fs::read(&fifo));
        stop.send(()).expect("relay still running");
        server.join().expect("server thread").expect("serve");
        reader
            .join()
            .expect("reader thread")
            .expect("read the pipe");
        let saved = load(&state).expect("load");
        std::fs::remove_dir_all(&dir).expect("clean up");

        assert!(
            matches!(replied, Ok(true)),
            "relay did not answer while saving was stuck: {replied:?}"
        );
        assert!(saved.is_some(), "state saved on exit");
    }
}
