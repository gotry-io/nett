//! The nett-node main loop (design/hub.md section 5, design/protocol.md sections 6, 8): connects to
//! the Hub, and when it receives the desired state writes it as the mesh process's desired state
//! file, asks the mesh process to reload it over the local interface, and reports the result to the
//! Hub as `StateAck`; periodically reads the mesh process's local status and reports it when it
//! changes; after a disconnect it reconnects with exponential backoff. The mesh keeps working while
//! the Hub is away (hard rule 8); this loop only delivers and reports.

use std::future::Future;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use nett_mesh::config::{DesiredMeshDoc, MAX_DESIRED_BYTES, read_bounded};
use nett_mesh::status::{QueryError, ReloadOutcome};
use nett_proto::api::CONNECT_PATH;
use nett_proto::frame::{self, Reassembler};
use nett_proto::noise::{Initiator, MAX_MESSAGE, Transport};
use nett_proto::v1::envelope::Body;
use nett_proto::v1::{
    AckResult, BackupFetch, DesiredState, Envelope, ErrorCode, Hello, Inventory, Leave, LinkReport,
    PartitionAck, PartitionKind, PathSwitch, Ping, StateAck,
};
use prost::Message as _;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use x25519_dalek::StaticSecret;

use crate::config::HubConfig;
use crate::tls::connector;
use crate::upgrade::{Plan, Upgrader};
use crate::url::HubUrl;

/// Interval for reading the mesh process's local status once (design/hub.md section 5).
pub const STATUS_EVERY: Duration = Duration::from_secs(15);
/// Keepalive (protocol.md section 8): one Ping every 25 seconds; 3 consecutive missed replies count
/// as a disconnect.
const PING_EVERY: Duration = Duration::from_secs(25);
/// How often the node asks for the Hub's latest backup (design/hub.md section 8.2).
const BACKUP_EVERY: Duration = Duration::from_secs(6 * 3600);
/// The Hub backup this machine keeps, next to the desired state.
pub const BACKUP_FILE: &str = "hub-backup.enc";
const MISSED_PINGS: u32 = 3;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper limit on waiting for the first desired state at enrollment.
const ENROLL_TIMEOUT: Duration = Duration::from_secs(20);
/// Reconnect backoff: starts at 1 second, capped at 60 seconds, with random jitter.
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

/// The nett-node on one machine.
pub struct Node {
    pub config: HubConfig,
    pub identity: StaticSecret,
    /// The desired state file read by the mesh process.
    pub desired: PathBuf,
    /// The mesh process's local socket (design/status.md section 3).
    pub socket: PathBuf,
    /// Installs new releases (design/release.md section 7); `None` where this machine does not
    /// upgrade itself.
    pub upgrader: Option<Arc<Upgrader>>,
    /// Starts and stops the relay and the transport adapter with the desired state (design/hub.md
    /// section 5); `None` where nett did not install the services. Holds what was last set up.
    pub services: Option<std::sync::Mutex<Option<crate::services::Wants>>>,
}

/// Why [`run`] returned.
#[derive(Debug, PartialEq, Eq)]
pub enum Exit {
    Shutdown,
    /// A new version is installed: exit so that the service manager starts it.
    Upgraded,
}

/// An upgrade running in the background, and the generation that carried its manifest.
type Upgrading = Option<(u64, tokio::task::JoinHandle<Result<(), String>>)>;

type Ws = tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

/// Runs until `shutdown` completes or a new version is installed.
pub async fn run(node: Node, shutdown: impl Future<Output = ()>) -> Exit {
    tokio::pin!(shutdown);
    if let Some(upgrader) = node.upgrader.clone() {
        // A new version that keeps running counts as working even while the Hub is away
        tokio::spawn(async move {
            tokio::time::sleep(crate::upgrade::SETTLED).await;
            upgrader.settled();
        });
    }
    let mut upgrading: Upgrading = None;
    let mut backoff = BACKOFF_MIN;
    let coordination = crate::coord::Coordination::start(node.socket.clone());
    loop {
        let result = tokio::select! {
            r = node.session(&mut upgrading, &coordination) => r,
            () = &mut shutdown => return Exit::Shutdown,
        };
        match result {
            Ok(Exit::Upgraded) => return Exit::Upgraded,
            Ok(Exit::Shutdown) => backoff = BACKOFF_MIN,
            Err(SessionError::Refused { code, message }) => {
                tracing::error!(?code, %message, "the Hub refused this machine");
                backoff = BACKOFF_MAX;
            }
            Err(e) => tracing::warn!(error = %e, "Hub connection"),
        }
        // An upgrade keeps going while the connection is down
        let finished = async {
            match upgrading.as_mut() {
                Some((_, task)) => task.await.ok(),
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            () = tokio::time::sleep(jitter(backoff)) => {}
            done = finished => {
                upgrading = None;
                if done == Some(Ok(())) {
                    return Exit::Upgraded;
                }
            }
            () = &mut shutdown => return Exit::Shutdown,
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

/// An outgoing message: numbering, fragment stream and Noise encryption.
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

/// Connects to the Hub: TCP, TLS (verified by certificate or pinned fingerprint, hard rule 11),
/// WebSocket, then a Noise IK handshake with the identity key. At enrollment `admission_proof` is
/// the JSON of the admission proof (design/hub.md section 6), and is empty otherwise. Returns this
/// machine's own address: from it the Hub learns the public address of a `public` machine (section
/// 5).
async fn connect(
    config: &HubConfig,
    identity: &StaticSecret,
    admission_proof: Vec<u8>,
) -> Result<(Ws, Transport, Option<std::net::SocketAddr>), SessionError> {
    let fail = |e: &dyn std::fmt::Display| SessionError::Connect(format!("{}: {e}", config.url));
    let url = HubUrl::parse(&config.url).map_err(SessionError::Connect)?;
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(url.authority()))
        .await
        .map_err(|_| fail(&"connecting timed out"))?
        .map_err(|e| fail(&e))?;
    tcp.set_nodelay(true).ok();
    let local = tcp.local_addr().ok();
    let server = url.server_name().map_err(SessionError::Connect)?;
    let tls = tokio::time::timeout(
        CONNECT_TIMEOUT,
        connector(config.tls_fingerprint.map(|f| f.0))
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

    let mut initiator = Initiator::new(identity, config.hub_key.0).map_err(|e| fail(&e))?;
    let boot = boot_id();
    let hello = envelope(
        1,
        Body::Hello(Hello {
            protocol_versions: vec![nett_proto::PROTOCOL_VERSION.to_owned()],
            node_version: env!("CARGO_PKG_VERSION").to_owned(),
            node_id: config.node_id.clone(),
            boot_id: boot.to_vec(),
            applied_generation: 0,
            capabilities: vec!["chunked_state".to_owned()],
            admission_proof,
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
        Ok(Some(Body::Welcome(_))) => Ok((ws, transport, local)),
        Ok(Some(Body::Error(e))) => Err(SessionError::Refused {
            code: ErrorCode::try_from(e.code).unwrap_or(ErrorCode::Unspecified),
            message: e.message,
        }),
        _ => Err(fail(&"the Hub's handshake reply is not a Welcome")),
    }
}

/// The first message after connecting: version, platform and this machine's own address.
fn inventory(local: Option<std::net::SocketAddr>) -> Body {
    Body::Inventory(Inventory {
        nett_version: env!("CARGO_PKG_VERSION").to_owned(),
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        addresses: local.map(|a| a.ip().to_string()).into_iter().collect(),
    })
}

/// Waits for the next message from the Hub, until `deadline`.
async fn next_envelope(
    ws: &mut Ws,
    out: &mut Outbox,
    reassembler: &mut Reassembler,
    deadline: tokio::time::Instant,
) -> Result<Option<Envelope>, SessionError> {
    loop {
        let message = match tokio::time::timeout_at(deadline, ws.next()).await {
            Err(_) => return Ok(None),
            Ok(Some(Ok(m))) => m,
            Ok(Some(Err(e))) => return Err(SessionError::Broken(e.to_string())),
            Ok(None) => return Err(SessionError::Broken("the Hub closed the connection".into())),
        };
        match message {
            Message::Binary(ct) => {
                let pt = out
                    .transport
                    .decrypt(&ct)
                    .map_err(|e| SessionError::Broken(e.to_string()))?;
                if let Some(env) = reassembler
                    .push(&pt)
                    .map_err(|e| SessionError::Broken(e.to_string()))?
                {
                    return Ok(Some(env));
                }
            }
            Message::Close(_) => {
                return Err(SessionError::Broken("the Hub closed the connection".into()));
            }
            _ => {}
        }
    }
}

/// The connection used for enrollment (design/hub.md section 6): `Hello` carries the admission
/// proof, and it returns the mesh partition of the first desired state sent by the Hub. Checking it
/// is the job of `join::enroll`.
pub async fn enroll(
    config: &HubConfig,
    identity: &StaticSecret,
    admission_proof: Vec<u8>,
) -> Result<Vec<u8>, SessionError> {
    let (mut ws, transport, local) = connect(config, identity, admission_proof).await?;
    let mut out = Outbox {
        transport,
        next_id: 1,
        next_stream: 0,
    };
    out.send(&mut ws, inventory(local)).await?;
    let mut reassembler = Reassembler::default();
    let deadline = tokio::time::Instant::now() + ENROLL_TIMEOUT;
    while let Some(env) = next_envelope(&mut ws, &mut out, &mut reassembler, deadline).await? {
        match env.body {
            Some(Body::DesiredState(desired)) => {
                let mesh = desired
                    .partitions
                    .into_iter()
                    .find(|p| p.kind == PartitionKind::Mesh as i32)
                    .map(|p| p.content);
                ws.close(None).await.ok();
                return mesh.ok_or_else(|| {
                    SessionError::Broken("the Hub sent no desired state for this machine".into())
                });
            }
            Some(Body::Error(e)) => {
                return Err(SessionError::Refused {
                    code: ErrorCode::try_from(e.code).unwrap_or(ErrorCode::Unspecified),
                    message: e.message,
                });
            }
            _ => {}
        }
    }
    Err(SessionError::Broken(
        "the Hub sent no desired state in time".into(),
    ))
}

/// Tells the Hub this machine is leaving (`nett leave`, auth.md section 8.3), and waits for the Hub
/// to finish and close the connection.
pub async fn leave(config: &HubConfig, identity: &StaticSecret) -> Result<(), SessionError> {
    let (mut ws, transport, _) = connect(config, identity, Vec::new()).await?;
    let mut out = Outbox {
        transport,
        next_id: 1,
        next_stream: 0,
    };
    out.send(&mut ws, Body::Leave(Leave {})).await?;
    let mut reassembler = Reassembler::default();
    let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
    // The Hub closes the connection after recording the departure; desired state it sends before
    // that can be ignored
    loop {
        match next_envelope(&mut ws, &mut out, &mut reassembler, deadline).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return Err(SessionError::Broken(
                    "the Hub did not confirm in time".into(),
                ));
            }
            Err(SessionError::Broken(_)) => return Ok(()),
            Err(e) => return Err(e),
        }
    }
}

impl Node {
    /// One connection, until it ends. `upgrading` outlives the connection; `coordination` passes switch
    /// messages between the mesh process and the Hub (design/mesh.md section 8.4).
    pub async fn session(
        &self,
        upgrading: &mut Upgrading,
        coordination: &crate::coord::Coordination,
    ) -> Result<Exit, SessionError> {
        let (mut ws, transport, local) = connect(&self.config, &self.identity, Vec::new()).await?;
        tracing::info!(url = %self.config.url, "connected to the Hub");
        // The mesh process may relay switch messages through the Hub while this session lasts
        let _hub_up = HubUp::new(&coordination.hub);
        let mut from_mesh = coordination.from_mesh.lock().await;
        // Messages from before this session are stale: their rounds have passed
        while from_mesh.try_recv().is_ok() {}
        if let Some(upgrader) = &self.upgrader {
            upgrader.settled();
        }
        let mut out = Outbox {
            transport,
            next_id: 1,
            next_stream: 0,
        };
        out.send(&mut ws, inventory(local)).await?;
        let mut backups = tokio::time::interval(BACKUP_EVERY);
        backups.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut reassembler = Reassembler::default();
        let mut ping = tokio::time::interval(PING_EVERY);
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut status = tokio::time::interval(STATUS_EVERY);
        status.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut missed = 0u32;
        let mut reported: Option<Vec<u8>> = None;
        // A generation whose file is written but for which the mesh process has not yet given a
        // result: ask it to read again when reading status
        let mut pending: Option<u64> = None;
        loop {
            let finished = async {
                match upgrading.as_mut() {
                    Some((generation, task)) => (*generation, task.await),
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                (generation, done) = finished => {
                    *upgrading = None;
                    match done {
                        Ok(Ok(())) => return Ok(Exit::Upgraded),
                        Ok(Err(reason)) => {
                            let ack = StateAck {
                                generation,
                                partitions: vec![PartitionAck {
                                    kind: PartitionKind::Release as i32,
                                    result: AckResult::Rejected as i32,
                                    reason,
                                }],
                            };
                            out.send(&mut ws, Body::StateAck(ack)).await?;
                        }
                        Err(e) => tracing::error!(error = %e, "the upgrade task failed"),
                    }
                }
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
                            let ack = self.apply(desired, upgrading).await;
                            pending = is_pending(&ack).then_some(ack.generation);
                            out.send(&mut ws, Body::StateAck(ack)).await?;
                            // Report status immediately after applying
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
                            return Ok(Exit::Shutdown);
                        }
                        Some(Body::Backup(backup)) => {
                            if let Some(have) = self.keep_backup(&backup) {
                                // Tells the Hub this machine holds it now
                                out.send(&mut ws, Body::BackupFetch(BackupFetch { have })).await?;
                            }
                        }
                        // From another member's mesh process: checked and handed over as data; only the mesh
                        // process can authenticate it (hard rule 13)
                        Some(Body::PathSwitch(p)) => {
                            if let Ok(peer) = p.node_id.parse()
                                && p.message.len() <= nett_mesh::coord::MAX_MESSAGE
                            {
                                let _ = coordination.to_mesh.try_send(nett_mesh::coord::PathSwitchLine {
                                    peer,
                                    message: p.message,
                                });
                            }
                        }
                        _ => {}
                    }
                }
                _ = backups.tick() => {
                    out.send(&mut ws, Body::BackupFetch(BackupFetch { have: self.backup_held() })).await?;
                }
                Some(p) = from_mesh.recv() => {
                    out.send(&mut ws, Body::PathSwitch(PathSwitch {
                        node_id: p.peer.to_string(),
                        message: p.message,
                    })).await?;
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

    /// The SHA-256 of the Hub backup this machine holds; empty when it has none.
    fn backup_held(&self) -> Vec<u8> {
        let path = self.backup_path();
        match nett_mesh::config::read_bounded(&path, nett_trust::MAX_BACKUP_BYTES as u64) {
            Ok(Some(bytes)) => ring::digest::digest(&ring::digest::SHA256, &bytes)
                .as_ref()
                .to_vec(),
            _ => Vec::new(),
        }
    }

    /// Keeps the Hub's backup next to the desired state (`0600`, design/hub.md section 8.2). It is
    /// opaque here: only the site's backup key opens it. Returns its hash once written.
    fn keep_backup(&self, backup: &nett_proto::v1::Backup) -> Option<Vec<u8>> {
        let digest = ring::digest::digest(&ring::digest::SHA256, &backup.data);
        if backup.data.len() as u64 > nett_trust::MAX_BACKUP_BYTES as u64
            || digest.as_ref() != backup.sha256
        {
            tracing::warn!("the Hub sent a backup that does not match its hash or is too large");
            return None;
        }
        match crate::config::write_private(&self.backup_path(), &backup.data) {
            Ok(()) => {
                tracing::info!(bytes = backup.data.len(), "Hub backup kept");
                Some(backup.sha256.clone())
            }
            Err(e) => {
                tracing::warn!(error = %e, "keeping the Hub backup");
                None
            }
        }
    }

    fn backup_path(&self) -> std::path::PathBuf {
        self.desired.with_file_name(BACKUP_FILE)
    }

    async fn read_status(&self) -> Option<Vec<u8>> {
        let socket = self.socket.clone();
        let value = tokio::task::spawn_blocking(move || nett_mesh::status::query_raw(&socket))
            .await
            .ok()?
            .ok()?;
        serde_json::to_vec(&value).ok()
    }

    /// Applies a desired state and acknowledges it per partition (protocol.md section 6.2).
    async fn apply(&self, desired: DesiredState, upgrading: &mut Upgrading) -> StateAck {
        let mut partitions = Vec::new();
        for p in desired.partitions {
            let (result, reason) = match PartitionKind::try_from(p.kind) {
                Ok(PartitionKind::Mesh) => self.apply_mesh(&p.content).await,
                // Nothing to do when there is only one Hub address (design/hub.md section 5)
                Ok(PartitionKind::HubEndpoints) => (AckResult::Applied, String::new()),
                Ok(PartitionKind::Release) => {
                    self.apply_release(&p.content, desired.generation, upgrading)
                }
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

    /// The release manifest (design/release.md section 7): nothing to do, a known failure, or an
    /// upgrade started in the background and acknowledged as pending.
    fn apply_release(
        &self,
        manifest: &[u8],
        generation: u64,
        upgrading: &mut Upgrading,
    ) -> (AckResult, String) {
        let Some(upgrader) = &self.upgrader else {
            return release_without_upgrader(manifest);
        };
        match upgrader.plan(manifest) {
            Err(e) => (AckResult::Rejected, e),
            Ok(Plan::Current) => (AckResult::Applied, String::new()),
            Ok(Plan::NoProgram) => (
                AckResult::Rejected,
                format!("the release has no program for {}", upgrader.target),
            ),
            Ok(Plan::Failed(reason)) => (AckResult::Rejected, reason),
            Ok(Plan::Upgrade { version, program }) => {
                if upgrading.is_none() {
                    let task = upgrader.clone();
                    *upgrading = Some((
                        generation,
                        tokio::spawn(async move { task.upgrade(version, &program).await }),
                    ));
                }
                (AckResult::Pending, format!("upgrading to {version}"))
            }
        }
    }

    /// Writes the mesh process's desired state file (a temporary file first, then rename), asks it
    /// over the local interface to read again, and maps the result to `StateAck`: `applied` (with
    /// issues) → applied, `rejected` → rejected, `busy` or no answer from the mesh process →
    /// pending (design/hub.md section 5).
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
        // When the file already holds this version it is not rewritten, but the mesh process is
        // still asked to read again: it may have rejected this version, and when the Hub sends it
        // again after a reconnect, the acknowledgment must be the result the mesh process gives
        if current.as_ref() != Some(&doc) {
            let json = match serde_json::to_vec_pretty(&doc) {
                Ok(j) => j,
                Err(e) => return (AckResult::Rejected, e.to_string()),
            };
            if let Err(e) = write_desired(&self.desired, &json) {
                return (AckResult::Pending, e);
            }
        }
        let ack = self.reload().await;
        self.follow_services(&doc).await;
        ack
    }

    /// Enables or disables the relay and the transport adapter when what the desired state needs
    /// changed.
    async fn follow_services(&self, doc: &DesiredMeshDoc) {
        let Some(last) = &self.services else {
            return;
        };
        let wants = crate::services::Wants::of(doc);
        if last.lock().ok().is_some_and(|l| *l == Some(wants)) {
            return;
        }
        let problems = tokio::task::spawn_blocking(move || crate::services::reconcile(wants))
            .await
            .unwrap_or_else(|e| vec![e.to_string()]);
        // When something failed, the next desired state tries again
        if problems.is_empty()
            && let Ok(mut l) = last.lock()
        {
            *l = Some(wants);
        }
    }

    /// Asks the mesh process to read the desired state file again.
    async fn reload(&self) -> (AckResult, String) {
        let socket = self.socket.clone();
        match tokio::task::spawn_blocking(move || nett_mesh::status::reload(&socket)).await {
            Ok(outcome) => ack_for(outcome),
            Err(e) => (AckResult::Pending, e.to_string()),
        }
    }
}

/// Tells the mesh process the Hub session is up for as long as this lives.
struct HubUp<'a>(&'a tokio::sync::watch::Sender<bool>);

impl<'a> HubUp<'a> {
    fn new(hub: &'a tokio::sync::watch::Sender<bool>) -> Self {
        hub.send_replace(true);
        Self(hub)
    }
}

impl Drop for HubUp<'_> {
    fn drop(&mut self) {
        self.0.send_replace(false);
    }
}

/// The acknowledgment corresponding to the result of the re-read (design/hub.md section 5):
/// `applied` (with issues) → applied, `rejected` → rejected; `busy`, or no answer from the mesh
/// process → pending: the file is already written, and the mesh process reads it at startup or on
/// the next request.
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

/// The desired state file: write a temporary file, sync to disk, then rename. Keeps the existing
/// permissions; `0640` if there are none (on Linux the directory hands its `nett` group to new files,
/// and the mesh service reads it as that group).
fn write_desired(path: &std::path::Path, json: &[u8]) -> Result<(), String> {
    let io = |e: std::io::Error| format!("writing {}: {e}", path.display());
    let mode = std::fs::metadata(path).map_or(0o640, |m| m.permissions().mode() & 0o777);
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

/// A machine whose program nett-node does not install (a container image, a program installed by
/// hand): the release it already runs counts as applied, and a newer one is reported for whoever
/// maintains it to upgrade.
fn release_without_upgrader(manifest: &[u8]) -> (AckResult, String) {
    let released = match nett_trust::release::Manifest::parse(manifest).and_then(|m| m.version()) {
        Ok(version) => version,
        Err(e) => return (AckResult::Rejected, e.to_string()),
    };
    let running: Option<nett_trust::release::Version> = env!("CARGO_PKG_VERSION").parse().ok();
    if running.is_some_and(|running| released <= running) {
        (AckResult::Applied, String::new())
    } else {
        (
            AckResult::Rejected,
            format!("{released} is available; this machine does not upgrade itself"),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use nett_mesh::status::{Problem, ProblemKind};
    use nett_trust::encoding::Timestamp;

    use super::*;

    fn manifest(version: &str) -> Vec<u8> {
        serde_json::json!({
            "version": version,
            "programs": { "x86_64-unknown-linux-musl": {
                "url": format!("https://nett.example.com/dl/nett-{version}-x86_64-unknown-linux-musl"),
                "sha256": "ab".repeat(32),
                "minisig": include_str!("../../nett-trust/tests/data/SHA256SUMS.minisig"),
            }}
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn a_machine_without_an_upgrader_reports_only_a_newer_release() {
        let current = release_without_upgrader(&manifest(env!("CARGO_PKG_VERSION")));
        assert_eq!(current, (AckResult::Applied, String::new()));
        let newer = release_without_upgrader(&manifest("999.0.0"));
        assert_eq!(
            newer,
            (
                AckResult::Rejected,
                "999.0.0 is available; this machine does not upgrade itself".to_owned()
            )
        );
    }

    /// A directory removed with everything in it when the returned guard is dropped; keep the
    /// guard for as long as the path is used.
    fn temp_dir(name: &str) -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::Builder::new()
            .prefix(&format!("nett-node-{name}-"))
            .tempdir()
            .expect("temp dir");
        let dir = tmp.path().to_path_buf();
        (tmp, dir)
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
        let (_dir_tmp, dir) = temp_dir("write");
        let path = dir.join("desired.json");
        let doc = b"{}";
        write_desired(&path, doc).expect("first write");
        assert_eq!(
            std::fs::metadata(&path)
                .expect("written")
                .permissions()
                .mode()
                & 0o777,
            0o640
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
        // Do not follow symbolic links that point elsewhere
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

    /// Also ask the mesh process when the file already holds this version: it may have rejected it,
    /// and after a reconnect it must not be reported as applied.
    #[tokio::test]
    async fn an_unchanged_file_is_still_confirmed_by_the_mesh_process() {
        let dir_tmp = tempfile::Builder::new()
            .prefix("nett-node-apply-")
            .tempdir()
            .expect("temp dir");
        let dir = dir_tmp.path().join("dir");
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
            // No mesh process answers here
            socket: dir.join("mesh.sock"),
            upgrader: None,
            services: None,
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

        // Desired state for another machine
        let mut other = doc.clone();
        other.node_id = new_node_id().expect("id");
        let (result, reason) = node
            .apply_mesh(&serde_json::to_vec(&other).expect("json"))
            .await;
        assert_eq!(result, AckResult::Rejected, "{reason}");
    }
}
