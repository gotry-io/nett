//! nett-node 的主循环（design/hub.md 第 5 节，design/protocol.md 第 6、8 节）：连接 Hub，收到期望状态时写成组网
//! 进程的期望状态文件、经本机接口请它重新加载，把结果作为 `StateAck` 报给 Hub；定时读组网进程的本机状态，
//! 有变化时上报；断线后按指数退避重连。Hub 不在时组网照常（硬性规则 8），这里只是送达和汇报。

use std::future::Future;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::PathBuf;
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use nett_mesh::config::{DesiredMeshDoc, MAX_DESIRED_BYTES, read_bounded};
use nett_mesh::status::{QueryError, ReloadOutcome};
use nett_proto::api::CONNECT_PATH;
use nett_proto::frame::{self, Reassembler};
use nett_proto::noise::{Initiator, MAX_MESSAGE, Transport};
use nett_proto::v1::envelope::Body;
use nett_proto::v1::{
    AckResult, DesiredState, Envelope, ErrorCode, Hello, Inventory, LinkReport, PartitionAck,
    PartitionKind, Ping, StateAck,
};
use prost::Message as _;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use x25519_dalek::StaticSecret;

use crate::config::HubConfig;
use crate::tls::connector;
use crate::url::HubUrl;

/// 读一次组网进程本机状态的间隔（design/hub.md 第 5 节）。
pub const STATUS_EVERY: Duration = Duration::from_secs(15);
/// 保活（protocol.md 第 8 节）：每 25 秒一次 Ping，连续 3 次没有回音视为断开。
const PING_EVERY: Duration = Duration::from_secs(25);
const MISSED_PINGS: u32 = 3;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// 重连的退避：起始 1 秒，上限 60 秒，带随机抖动。
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("{0}")]
    Connect(String),
    #[error("the Hub refused this machine ({code:?}): {message}")]
    Refused { code: ErrorCode, message: String },
    #[error("the connection to the Hub broke: {0}")]
    Broken(String),
}

/// 一台机器上的 nett-node。
pub struct Node {
    pub config: HubConfig,
    pub identity: StaticSecret,
    /// 组网进程读的期望状态文件。
    pub desired: PathBuf,
    /// 组网进程的本机套接字（design/status.md 第 3 节）。
    pub socket: PathBuf,
}

type Ws = tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

/// 一直运行，直到 `shutdown` 完成。
pub async fn run(node: Node, shutdown: impl Future<Output = ()>) {
    tokio::pin!(shutdown);
    let mut backoff = BACKOFF_MIN;
    loop {
        let result = tokio::select! {
            r = node.session() => r,
            () = &mut shutdown => return,
        };
        match result {
            Ok(()) => backoff = BACKOFF_MIN,
            Err(SessionError::Refused { code, message }) => {
                tracing::error!(?code, %message, "the Hub refused this machine");
                backoff = BACKOFF_MAX;
            }
            Err(e) => tracing::warn!(error = %e, "Hub connection"),
        }
        tokio::select! {
            () = tokio::time::sleep(jitter(backoff)) => {}
            () = &mut shutdown => return,
        }
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}

fn jitter(d: Duration) -> Duration {
    use ring::rand::{SecureRandom as _, SystemRandom};
    let mut b = [0u8; 1];
    SystemRandom::new().fill(&mut b).ok();
    d + d * u32::from(b[0]) / 512
}

fn envelope(id: u64, body: Body) -> Envelope {
    Envelope {
        id,
        reply_to: 0,
        sent_at: None,
        body: Some(body),
    }
}

/// 发出去的消息：编号、分片流与 Noise 加密。
struct Outbox {
    transport: Transport,
    next_id: u64,
    next_stream: u64,
}

impl Outbox {
    async fn send(&mut self, ws: &mut Ws, body: Body) -> Result<(), SessionError> {
        self.next_id += 1;
        self.next_stream += 1;
        let env = envelope(self.next_id, body);
        let broken = |e: &dyn std::fmt::Display| SessionError::Broken(e.to_string());
        for message in
            frame::encode(&env, &mut self.next_id, self.next_stream).map_err(|e| broken(&e))?
        {
            let ct = self.transport.encrypt(&message).map_err(|e| broken(&e))?;
            ws.send(Message::Binary(ct.into()))
                .await
                .map_err(|e| broken(&e))?;
        }
        Ok(())
    }
}

impl Node {
    async fn connect(&self) -> Result<(Ws, Transport), SessionError> {
        let fail =
            |e: &dyn std::fmt::Display| SessionError::Connect(format!("{}: {e}", self.config.url));
        let url = HubUrl::parse(&self.config.url).map_err(SessionError::Connect)?;
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(url.authority()))
            .await
            .map_err(|_| fail(&"connecting timed out"))?
            .map_err(|e| fail(&e))?;
        tcp.set_nodelay(true).ok();
        let server = url.server_name().map_err(SessionError::Connect)?;
        let tls = tokio::time::timeout(
            CONNECT_TIMEOUT,
            connector(self.config.tls_fingerprint.map(|f| f.0))
                .map_err(|e| fail(&e))?
                .connect(server, tcp),
        )
        .await
        .map_err(|_| fail(&"TLS handshake timed out"))?
        .map_err(|e| fail(&e))?;
        let ws_config = WebSocketConfig::default()
            .max_message_size(Some(MAX_MESSAGE))
            .max_frame_size(Some(MAX_MESSAGE));
        let target = format!("wss://{}{CONNECT_PATH}", url.authority());
        let (mut ws, _) = tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio_tungstenite::client_async_with_config(target, tls, Some(ws_config)),
        )
        .await
        .map_err(|_| fail(&"WebSocket handshake timed out"))?
        .map_err(|e| fail(&e))?;

        let mut initiator =
            Initiator::new(&self.identity, self.config.hub_key.0).map_err(|e| fail(&e))?;
        let boot = boot_id();
        let hello = envelope(
            1,
            Body::Hello(Hello {
                protocol_versions: vec![nett_proto::PROTOCOL_VERSION.to_owned()],
                node_version: env!("CARGO_PKG_VERSION").to_owned(),
                node_id: self.config.node_id.clone(),
                boot_id: boot.to_vec(),
                applied_generation: 0,
                capabilities: vec!["chunked_state".to_owned()],
            }),
        );
        let m1 = initiator
            .write_message(&hello.encode_to_vec())
            .map_err(|e| fail(&e))?;
        ws.send(Message::Binary(m1.into()))
            .await
            .map_err(|e| fail(&e))?;
        let m2 = loop {
            match tokio::time::timeout(CONNECT_TIMEOUT, ws.next())
                .await
                .map_err(|_| fail(&"no handshake reply"))?
            {
                Some(Ok(Message::Binary(m))) => break m,
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(_)) | None => {
                    return Err(fail(&"the Hub closed the connection during the handshake"));
                }
                Some(Err(e)) => return Err(fail(&e)),
            }
        };
        let (payload, transport) = initiator.read_message(&m2).map_err(|e| {
            fail(&format!(
                "handshake: {e}; is the Hub key in hub.json right?"
            ))
        })?;
        match Envelope::decode(payload.as_slice()).map(|e| e.body) {
            Ok(Some(Body::Welcome(_))) => Ok((ws, transport)),
            Ok(Some(Body::Error(e))) => Err(SessionError::Refused {
                code: ErrorCode::try_from(e.code).unwrap_or(ErrorCode::Unspecified),
                message: e.message,
            }),
            _ => Err(fail(&"the Hub's handshake reply is not a Welcome")),
        }
    }

    /// 一次连接，直到断开。
    pub async fn session(&self) -> Result<(), SessionError> {
        let (mut ws, transport) = self.connect().await?;
        tracing::info!(url = %self.config.url, "connected to the Hub");
        let mut out = Outbox {
            transport,
            next_id: 1,
            next_stream: 0,
        };
        out.send(
            &mut ws,
            Body::Inventory(Inventory {
                nett_version: env!("CARGO_PKG_VERSION").to_owned(),
                platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
                addresses: Vec::new(),
            }),
        )
        .await?;
        let mut reassembler = Reassembler::default();
        let mut ping = tokio::time::interval(PING_EVERY);
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut status = tokio::time::interval(STATUS_EVERY);
        status.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut missed = 0u32;
        let mut reported: Option<Vec<u8>> = None;
        // 写好了文件、组网进程还没给出结果的代数：读状态时再请它重新读取一次
        let mut pending: Option<u64> = None;
        loop {
            tokio::select! {
                message = ws.next() => {
                    let message = match message {
                        Some(Ok(m)) => m,
                        Some(Err(e)) => return Err(SessionError::Broken(e.to_string())),
                        None => return Err(SessionError::Broken("the Hub closed the connection".into())),
                    };
                    let Message::Binary(ct) = message else {
                        if matches!(message, Message::Close(_)) {
                            return Err(SessionError::Broken("the Hub closed the connection".into()));
                        }
                        continue;
                    };
                    missed = 0;
                    let pt = out.transport.decrypt(&ct).map_err(|e| SessionError::Broken(e.to_string()))?;
                    let Some(env) = reassembler.push(&pt).map_err(|e| SessionError::Broken(e.to_string()))? else {
                        continue;
                    };
                    match env.body {
                        Some(Body::DesiredState(desired)) => {
                            let ack = self.apply(desired).await;
                            pending = is_pending(&ack).then_some(ack.generation);
                            out.send(&mut ws, Body::StateAck(ack)).await?;
                            // 应用之后立即报一次状态
                            status.reset_immediately();
                        }
                        Some(Body::Error(e)) => {
                            return Err(SessionError::Refused {
                                code: ErrorCode::try_from(e.code).unwrap_or(ErrorCode::Unspecified),
                                message: e.message,
                            });
                        }
                        Some(Body::Goodbye(g)) => {
                            tracing::info!(reason = %g.reason, "the Hub closed the session");
                            return Ok(());
                        }
                        _ => {}
                    }
                }
                _ = ping.tick() => {
                    if missed >= MISSED_PINGS {
                        return Err(SessionError::Broken("no answer from the Hub".into()));
                    }
                    missed += 1;
                    out.send(&mut ws, Body::Ping(Ping {})).await?;
                }
                _ = status.tick() => {
                    if let Some(generation) = pending {
                        let (result, reason) = self.reload().await;
                        if result != AckResult::Pending {
                            pending = None;
                            let ack = StateAck {
                                generation,
                                partitions: vec![PartitionAck {
                                    kind: PartitionKind::Mesh as i32,
                                    result: result as i32,
                                    reason,
                                }],
                            };
                            out.send(&mut ws, Body::StateAck(ack)).await?;
                        }
                    }
                    if let Some(bytes) = self.read_status().await
                        && reported.as_ref() != Some(&bytes)
                    {
                        out.send(&mut ws, Body::LinkReport(LinkReport { status: bytes.clone() })).await?;
                        reported = Some(bytes);
                    }
                }
            }
        }
    }

    async fn read_status(&self) -> Option<Vec<u8>> {
        let socket = self.socket.clone();
        let value = tokio::task::spawn_blocking(move || nett_mesh::status::query_raw(&socket))
            .await
            .ok()?
            .ok()?;
        serde_json::to_vec(&value).ok()
    }

    /// 应用一份期望状态，按分区确认（protocol.md 第 6.2 节）。
    async fn apply(&self, desired: DesiredState) -> StateAck {
        let mut partitions = Vec::new();
        for p in desired.partitions {
            let (result, reason) = match PartitionKind::try_from(p.kind) {
                Ok(PartitionKind::Mesh) => self.apply_mesh(&p.content).await,
                // 只有一个 Hub 地址时不需要做什么（design/hub.md 第 5 节）
                Ok(PartitionKind::HubEndpoints) => (AckResult::Applied, String::new()),
                _ => (
                    AckResult::Rejected,
                    "this node does not know this partition".to_owned(),
                ),
            };
            partitions.push(PartitionAck {
                kind: p.kind,
                result: result as i32,
                reason,
            });
        }
        StateAck {
            generation: desired.generation,
            partitions,
        }
    }

    /// 写成组网进程的期望状态文件（先写临时文件再改名），经本机接口请它重新读取，结果映射到 `StateAck`：
    /// `applied`（附问题）→ applied，`rejected` → rejected，`busy` 或组网进程没有应答 → pending
    /// （design/hub.md 第 5 节）。
    async fn apply_mesh(&self, content: &[u8]) -> (AckResult, String) {
        if content.len() as u64 > MAX_DESIRED_BYTES {
            return (AckResult::Rejected, "the desired state is too large".into());
        }
        let doc: DesiredMeshDoc = match serde_json::from_slice(content) {
            Ok(d) => d,
            Err(e) => {
                return (
                    AckResult::Rejected,
                    format!("the desired state is not valid: {e}"),
                );
            }
        };
        if doc.node_id.as_str() != self.config.node_id {
            return (
                AckResult::Rejected,
                format!("the desired state is for {}", doc.node_id),
            );
        }
        let current: Option<DesiredMeshDoc> = read_bounded(&self.desired, MAX_DESIRED_BYTES)
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice(&b).ok());
        // 文件已经是这一份时不重写，但照样请组网进程重新读取：它可能拒绝过这一份，重连之后 Hub 再发来时，
        // 确认要是组网进程给出的结果
        if current.as_ref() != Some(&doc) {
            let json = match serde_json::to_vec_pretty(&doc) {
                Ok(j) => j,
                Err(e) => return (AckResult::Rejected, e.to_string()),
            };
            if let Err(e) = write_desired(&self.desired, &json) {
                return (AckResult::Pending, e);
            }
        }
        self.reload().await
    }

    /// 请组网进程重新读取期望状态文件。
    async fn reload(&self) -> (AckResult, String) {
        let socket = self.socket.clone();
        match tokio::task::spawn_blocking(move || nett_mesh::status::reload(&socket)).await {
            Ok(outcome) => ack_for(outcome),
            Err(e) => (AckResult::Pending, e.to_string()),
        }
    }
}

/// 重新读取的结果对应的确认（design/hub.md 第 5 节）：`applied`（附问题）→ applied，`rejected` →
/// rejected；`busy`、组网进程没有应答 → pending，文件已经写好，组网进程启动时或下一次请求时读它。
pub fn ack_for(outcome: Result<ReloadOutcome, QueryError>) -> (AckResult, String) {
    match outcome {
        Ok(ReloadOutcome::Applied { problems }) => {
            tracing::info!(problems = problems.len(), "desired state applied");
            let reason = problems
                .iter()
                .take(3)
                .map(|p| p.reason.as_str())
                .collect::<Vec<_>>()
                .join("; ");
            (AckResult::Applied, reason)
        }
        Ok(ReloadOutcome::Rejected { reason }) => {
            tracing::warn!(%reason, "desired state rejected by the mesh process");
            (AckResult::Rejected, reason)
        }
        Err(QueryError::Refused { code, message }) if code == "busy" => {
            (AckResult::Pending, message)
        }
        Err(e) => (
            AckResult::Pending,
            format!("written; the mesh process loads it when it starts: {e}"),
        ),
    }
}

fn is_pending(ack: &StateAck) -> bool {
    ack.partitions
        .iter()
        .any(|p| p.kind == PartitionKind::Mesh as i32 && p.result == AckResult::Pending as i32)
}

/// 期望状态文件：先写临时文件、落盘，再改名。沿用原来的权限；没有时 `0644`，组网进程以专用的身份读它。
fn write_desired(path: &std::path::Path, json: &[u8]) -> Result<(), String> {
    let io = |e: std::io::Error| format!("writing {}: {e}", path.display());
    let mode = std::fs::metadata(path).map_or(0o644, |m| m.permissions().mode() & 0o777);
    let tmp = path.with_extension("json.new");
    std::fs::remove_file(&tmp).ok();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .map_err(io)?;
    file.write_all(json).map_err(io)?;
    file.sync_all().map_err(io)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)).map_err(io)?;
    std::fs::rename(&tmp, path).map_err(io)
}

fn boot_id() -> [u8; 16] {
    use ring::rand::{SecureRandom as _, SystemRandom};
    let mut b = [0u8; 16];
    SystemRandom::new().fill(&mut b).ok();
    b
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use nett_mesh::status::{Problem, ProblemKind};
    use nett_trust::encoding::Timestamp;

    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nett-node-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn reload_results_map_to_acknowledgements() {
        let problem = Problem {
            kind: ProblemKind::MemberRejected,
            node: None,
            at: Timestamp::from_unix_seconds(0),
            reason: "node nas: the policy has expired".into(),
        };
        assert_eq!(
            ack_for(Ok(ReloadOutcome::Applied { problems: vec![] })),
            (AckResult::Applied, String::new())
        );
        assert_eq!(
            ack_for(Ok(ReloadOutcome::Applied {
                problems: vec![problem]
            })),
            (
                AckResult::Applied,
                "node nas: the policy has expired".into()
            )
        );
        assert_eq!(
            ack_for(Ok(ReloadOutcome::Rejected {
                reason: "version 3 is older than 4".into()
            })),
            (AckResult::Rejected, "version 3 is older than 4".into())
        );
        let busy = QueryError::Refused {
            code: "busy".into(),
            message: "applying the previous desired state".into(),
        };
        assert_eq!(ack_for(Err(busy)).0, AckResult::Pending);
        let down = QueryError::Connect {
            path: "/run/nett/mesh.sock".into(),
            source: std::io::Error::from(std::io::ErrorKind::NotFound),
        };
        let (result, reason) = ack_for(Err(down));
        assert_eq!(result, AckResult::Pending);
        assert!(reason.starts_with("written;"), "{reason}");
    }

    #[test]
    fn pending_is_about_the_mesh_partition() {
        let ack = |kind: PartitionKind, result: AckResult| StateAck {
            generation: 3,
            partitions: vec![PartitionAck {
                kind: kind as i32,
                result: result as i32,
                reason: String::new(),
            }],
        };
        assert!(is_pending(&ack(PartitionKind::Mesh, AckResult::Pending)));
        assert!(!is_pending(&ack(PartitionKind::Mesh, AckResult::Applied)));
        assert!(!is_pending(&ack(
            PartitionKind::HubEndpoints,
            AckResult::Pending
        )));
    }

    #[test]
    fn desired_state_is_replaced_whole_and_keeps_its_mode() {
        let dir = temp_dir("write");
        let path = dir.join("desired.json");
        let doc = b"{}";
        write_desired(&path, doc).expect("first write");
        assert_eq!(
            std::fs::metadata(&path)
                .expect("written")
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        write_desired(&path, doc).expect("second write");
        assert_eq!(
            std::fs::metadata(&path)
                .expect("written")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(!dir.join("desired.json.new").exists());
        // 不跟随指向别处的符号链接
        let elsewhere = dir.join("elsewhere");
        std::os::unix::fs::symlink(&elsewhere, dir.join("desired.json.new")).expect("symlink");
        write_desired(&path, doc).expect("the stale link is removed first");
        assert!(!elsewhere.exists());
    }
}

#[cfg(test)]
mod apply_tests {
    use std::path::Path;

    use nett_proto::token::Bytes32;
    use nett_site::dir::{SiteDir, new_node_id};
    use nett_site::ops::MachineOptions;
    use nett_site::state::NodeKeys;
    use nett_trust::encoding::Timestamp;
    use nett_trust::keys::X25519PublicKey;

    use super::*;

    fn member(site_dir: &Path) -> DesiredMeshDoc {
        SiteDir::init(site_dir, "https://nett.invalid").expect("init");
        let site = SiteDir::open(site_dir).expect("open");
        let mut state = site.load().expect("load");
        state
            .add(
                "nas".parse().expect("name"),
                MachineOptions {
                    keys: Some(NodeKeys {
                        mesh: X25519PublicKey::from_bytes([1; 32]),
                        identity: X25519PublicKey::from_bytes([2; 32]),
                    }),
                    ..MachineOptions::default()
                },
                new_node_id().expect("id"),
            )
            .expect("add");
        nett_site::sign::sign(
            &mut state,
            &site.recovery().expect("key"),
            Timestamp::now(),
            &[],
        )
        .expect("sign");
        nett_site::compose::desired(&state, &"nas".parse().expect("name"))
            .expect("compose")
            .expect("signed")
    }

    /// 文件已经是这一份时也要问组网进程：它可能拒绝过这一份，重连之后不能报成已应用。
    #[tokio::test]
    async fn an_unchanged_file_is_still_confirmed_by_the_mesh_process() {
        let dir = std::env::temp_dir().join(format!("nett-node-apply-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).expect("dir");
        let doc = member(&dir.join("site"));
        let node = Node {
            config: HubConfig {
                url: "https://hub.example.com".into(),
                hub_key: Bytes32([5; 32]),
                node_id: doc.node_id.to_string(),
                tls_fingerprint: None,
            },
            identity: StaticSecret::from([9; 32]),
            desired: dir.join("desired.json"),
            // 没有组网进程在这里应答
            socket: dir.join("mesh.sock"),
        };
        let content = serde_json::to_vec(&doc).expect("json");
        assert_eq!(node.apply_mesh(&content).await.0, AckResult::Pending);
        assert!(dir.join("desired.json").exists());
        let written = std::fs::metadata(dir.join("desired.json"))
            .expect("written")
            .modified()
            .expect("mtime");
        assert_eq!(node.apply_mesh(&content).await.0, AckResult::Pending);
        let again = std::fs::metadata(dir.join("desired.json"))
            .expect("written")
            .modified()
            .expect("mtime");
        assert_eq!(written, again, "the same content is not written again");

        // 给另一台机器的期望状态
        let mut other = doc.clone();
        other.node_id = new_node_id().expect("id");
        let (result, reason) = node
            .apply_mesh(&serde_json::to_vec(&other).expect("json"))
            .await;
        assert_eq!(result, AckResult::Rejected, "{reason}");
    }
}
