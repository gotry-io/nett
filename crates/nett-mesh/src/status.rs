//! 本机状态（design/status.md）：组网进程在本机套接字上回答只读的状态查询。
//!
//! - [`StatusDoc`] 是回复的格式，`nett status`（以后还有 nett-node）读它。同一主版本内只增加字段：读的一方
//!   忽略不认识的字段，以后增加的字段带默认值；
//! - [`Recorder`] 包在事件出口外，记下最近的事件、需要处理的问题和每个对端最近一次切换；
//! - [`StatusServer`] 接受连接：一个连接一次查询，回复后关闭；[`query`] 是对应的客户端。

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{DirBuilderExt as _, FileTypeExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nett_core::id::NodeId;
use nett_core::name::NodeName;
use nett_core::prefix::IpPrefix;
use nett_trust::encoding::Timestamp;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use serde::{Deserialize, Serialize};

use crate::config::Reachability;
use crate::event::{Event, EventSink};

/// 接口的主版本（design/status.md 第 4 节）。
pub const VERSION: u32 = 1;

/// 默认的套接字路径（design/status.md 第 3 节）。
#[cfg(target_os = "macos")]
pub const DEFAULT_SOCKET: &str = "/var/run/nett/mesh.sock";
#[cfg(not(target_os = "macos"))]
pub const DEFAULT_SOCKET: &str = "/run/nett/mesh.sock";

/// 请求的长度上限。
const MAX_REQUEST: u64 = 1024;
/// 回复之后最多丢弃这么多对方没被读走的输入。
const MAX_DRAIN: u64 = 64 * 1024;
/// 回复的长度上限：按成员上限估算的数倍。
pub const MAX_REPLY: u64 = 4 << 20;
/// 套接字读写的超时。
const IO_TIMEOUT: Duration = Duration::from_secs(1);
/// 等后台线程交出快照的上限：期望状态应用期间它可能忙于数据面操作。
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
/// 等一份重新读取的期望状态应用完的上限（design/status.md 第 4.1 节）。
pub const RELOAD_TIMEOUT: Duration = Duration::from_secs(10);
/// 同时进行的 `reload` 的上限：读取期望状态的一方逐个处理。
pub const MAX_PENDING_RELOADS: usize = 4;
/// 保留的最近事件数。
const MAX_EVENTS: usize = 32;
/// 按节点记的问题（成员、宣告网段被拒绝）最多保留的项数。
const MAX_NODE_PROBLEMS: usize = 32;
/// 数据面操作失败后，在这段时间内列为问题：失败的操作会自动重试，持续失败时一直在列。
const DATA_PLANE_WINDOW: Duration = Duration::from_secs(300);
/// 接受连接的线程的栈：只做小块的读写和序列化。
const SERVER_STACK: usize = 256 * 1024;
/// 等连接的超时：据此定期检查是否该退出，不依赖套接字文件还在。
const ACCEPT_POLL: Duration = Duration::from_millis(500);

// ---- 状态文档（design/status.md 第 6 节） ----

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusDoc {
    pub v: u32,
    /// 组网进程的 `nett` 版本。
    pub version: String,
    pub node: NodeStatus,
    pub config: ConfigStatus,
    pub peers: Vec<PeerStatus>,
    pub problems: Vec<Problem>,
    pub events: Vec<EventRecord>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeStatus {
    pub id: NodeId,
    pub name: Option<NodeName>,
    /// 本机在已准入的成员中；不在时没有地址，也不与任何对端通信。
    pub admitted: bool,
    pub mesh: Vec<IpAddr>,
    /// 有 `edge` 角色时的 Edge 专用地址。
    pub edge: Vec<IpAddr>,
    /// 本机宣告的网段。
    pub routes: Vec<IpPrefix>,
    pub reachability: Reachability,
    pub dataplane: DataPlaneKind,
    /// WireGuard 实际监听的端口；接口还没有就绪时为空。
    pub listen_port: Option<u16>,
    /// `dial-only` 节点的 NAT 类型与映射地址（design/mesh.md 第 6.1 节）。
    pub nat: Option<NatStatus>,
    /// 时钟误差在 2 秒以内（design/mesh.md 第 8.4 节）。
    pub clock_trusted: bool,
    pub started_at: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataPlaneKind {
    Kernel,
    Userspace,
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NatStatus {
    #[serde(rename = "type")]
    pub kind: NatKind,
    pub ipv4: Option<SocketAddr>,
    pub ipv6: Option<SocketAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NatKind {
    Cone,
    Symmetric,
    /// 还没有两个 `public` 节点的观察，或是新版本才有的类型。
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigStatus {
    /// 生效的期望状态最近一次被接受的时间。
    pub applied_at: Option<Timestamp>,
    pub access_rules_version: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerStatus {
    pub id: NodeId,
    pub name: Option<NodeName>,
    pub mesh: Vec<IpAddr>,
    pub edge: Vec<IpAddr>,
    pub routes: Vec<IpPrefix>,
    pub state: PeerState,
    /// 期望状态中没有到它的路径时为空。
    pub role: Option<PeerRole>,
    pub path: Option<PathStatus>,
    /// 当前路径上隧道内探测的测量；本机不测量（经漫游跟随）时为空。
    pub rtt_ms: Option<f64>,
    pub loss: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub last_handshake: Option<Timestamp>,
    pub last_received: Option<Timestamp>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// 本机选路时的各候选路径，当前路径在内。
    pub candidates: Vec<CandidateStatus>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerState {
    /// 最近 30 秒内收到过对端的包。
    Connected,
    /// 在向它发送，还没有收到过。
    Connecting,
    /// 在向它发送，曾经收到过，最近 30 秒内没有。
    Unreachable,
    /// 两个方向最近 30 秒内都没有包：没有流量时不探测，无从判断。
    Idle,
    /// 期望状态中没有到它的路径。
    NoPath,
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerRole {
    /// 本机决定路径（design/mesh.md 第 8.3 节）。
    Decider,
    /// 本机跟随对端的选择。
    Follower,
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathStatus {
    pub kind: PathKindDoc,
    pub relay: Option<NodeRef>,
    /// 直连时是对端的地址；经中继时是中继的地址（TLS 时是中继的 TLS 地址）。
    pub endpoint: Option<SocketAddr>,
    pub punched: bool,
    /// 切到这条路径的时间与原因；本机跟随对端，或启动以来还没有切换过时为空。
    pub since: Option<Timestamp>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathKindDoc {
    Lan,
    Direct,
    Relay,
    RelayTls,
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRef {
    pub id: NodeId,
    pub name: Option<NodeName>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CandidateStatus {
    pub kind: PathKindDoc,
    pub relay: Option<NodeRef>,
    pub endpoint: SocketAddr,
    pub punched: bool,
    pub rtt_ms: Option<f64>,
    pub loss: Option<f64>,
    pub state: CandidateStateDoc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateStateDoc {
    Current,
    Ok,
    Failing,
    Untested,
    #[serde(other)]
    Other,
}

/// 需要处理的情况（design/status.md 第 6 节）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Problem {
    pub kind: ProblemKind,
    /// 与某个节点有关时是这个节点（读不出节点 ID 时为空）。
    pub node: Option<NodeRef>,
    pub at: Timestamp,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProblemKind {
    /// 期望状态整份被拒绝，继续使用上一份。
    ConfigRejected,
    /// 本机不在已准入的成员中。
    NotAdmitted,
    MemberRejected,
    AccessRulesRejected,
    RoutesRejected,
    DataPlaneFailed,
    #[serde(other)]
    Other,
}

/// 一个事件：时间，加上与日志相同的事件字段（`event` 是事件名）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventRecord {
    pub at: Timestamp,
    #[serde(flatten)]
    pub fields: serde_json::Map<String, serde_json::Value>,
}

impl EventRecord {
    pub fn name(&self) -> &str {
        self.fields
            .get("event")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
    }
}

/// 一次 `reload` 的结果（design/status.md 第 4.1 节）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum ReloadOutcome {
    /// 已经生效；`problems` 是应用之后仍需处理的情况。
    Applied { problems: Vec<Problem> },
    /// 整份被拒绝，继续使用上一份。
    Rejected { reason: String },
}

/// 等一次 `reload` 应用完的一方：后台线程应用之后把结果交到这里。
pub type ReloadReply = std::sync::mpsc::SyncSender<ReloadOutcome>;

pub fn timestamp(t: SystemTime) -> Timestamp {
    Timestamp::from_unix_seconds(
        t.duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX)),
    )
}

/// 单调时钟上的时刻换成墙上时钟：`now` 与 `wall` 是同一时刻。
pub fn wall_time(now: Instant, wall: SystemTime, t: Instant) -> Timestamp {
    timestamp(
        wall.checked_sub(now.saturating_duration_since(t))
            .unwrap_or(UNIX_EPOCH),
    )
}

// ---- 事件记录 ----

/// 包在事件出口外：照常交出每个事件，同时记下状态查询要用的部分。
pub struct Recorder<E> {
    inner: E,
    started_at: Timestamp,
    events: VecDeque<EventRecord>,
    problems: Problems,
    /// 每个对端最近一次切换的时间与原因。
    switches: HashMap<NodeId, (Timestamp, String)>,
}

#[derive(Debug, Default)]
struct Problems {
    config: Option<(Timestamp, String)>,
    not_admitted: Option<Timestamp>,
    members: BTreeMap<Option<NodeId>, (Timestamp, String)>,
    access: Option<(Timestamp, String)>,
    routes: BTreeMap<Option<NodeId>, (Timestamp, String)>,
    data_plane: Option<(Instant, Timestamp, String)>,
}

impl<E: EventSink> Recorder<E> {
    pub fn new(inner: E) -> Self {
        Self {
            inner,
            started_at: Timestamp::now(),
            events: VecDeque::new(),
            problems: Problems::default(),
            switches: HashMap::new(),
        }
    }

    /// 一份新的期望状态通过了格式校验、即将应用：上一份留下的问题作废，应用过程中仍存在的会重新报告
    /// （验证失败的材料每次应用都会报告）。
    pub fn begin_apply(&mut self) {
        let data_plane = self.problems.data_plane.take();
        self.problems = Problems {
            data_plane,
            ..Problems::default()
        };
    }

    pub fn started_at(&self) -> Timestamp {
        self.started_at
    }

    /// 把记下的问题、最近的事件和切换的时间与原因填进快照。`names` 用来给问题中的节点配上名字。
    pub fn fill(&self, doc: &mut StatusDoc, names: &BTreeMap<NodeId, NodeName>, now: Instant) {
        doc.problems = self.problems(&doc.node.id, names, now);
        doc.events = self.events.iter().cloned().collect();
        for peer in &mut doc.peers {
            if let (Some(path), Some((at, reason))) = (&mut peer.path, self.switches.get(&peer.id))
                && peer.role == Some(PeerRole::Decider)
            {
                path.since = Some(*at);
                path.reason = Some(reason.clone());
            }
        }
    }

    /// 现在需要处理的情况（design/status.md 第 6 节）。`own` 是本机的节点 ID。
    pub fn problems(
        &self,
        own: &NodeId,
        names: &BTreeMap<NodeId, NodeName>,
        now: Instant,
    ) -> Vec<Problem> {
        let node_ref = |id: &Option<NodeId>| {
            id.as_ref().map(|id| NodeRef {
                id: id.clone(),
                name: names.get(id).cloned(),
            })
        };
        let p = &self.problems;
        let mut problems = Vec::new();
        let mut push = |kind, node: Option<NodeRef>, (at, reason): &(Timestamp, String)| {
            problems.push(Problem {
                kind,
                node,
                at: *at,
                reason: reason.clone(),
            });
        };
        if let Some(c) = &p.config {
            push(ProblemKind::ConfigRejected, None, c);
        }
        if let Some(at) = p.not_admitted {
            push(
                ProblemKind::NotAdmitted,
                node_ref(&Some(own.clone())),
                &(at, "this node is not among the admitted members".into()),
            );
        }
        for (id, r) in &p.members {
            push(ProblemKind::MemberRejected, node_ref(id), r);
        }
        if let Some(a) = &p.access {
            push(ProblemKind::AccessRulesRejected, None, a);
        }
        for (id, r) in &p.routes {
            push(ProblemKind::RoutesRejected, node_ref(id), r);
        }
        if let Some((seen, at, reason)) = &p.data_plane
            && now.saturating_duration_since(*seen) < DATA_PLANE_WINDOW
        {
            push(ProblemKind::DataPlaneFailed, None, &(*at, reason.clone()));
        }
        problems
    }

    fn record(&mut self, event: &Event) {
        let now = Timestamp::now();
        let bounded_insert =
            |map: &mut BTreeMap<Option<NodeId>, (Timestamp, String)>, id: &Option<NodeId>, r| {
                if map.len() < MAX_NODE_PROBLEMS || map.contains_key(id) {
                    map.insert(id.clone(), (now, r));
                }
            };
        match event {
            Event::ConfigRejected { reason } => self.problems.config = Some((now, reason.clone())),
            Event::SelfNotAdmitted { .. } => self.problems.not_admitted = Some(now),
            Event::MemberRejected { node_id, reason } => {
                bounded_insert(&mut self.problems.members, node_id, reason.clone());
            }
            Event::AccessRulesRejected { reason } => {
                self.problems.access = Some((now, reason.clone()));
            }
            Event::RoutesRejected { node_id, reason } => {
                bounded_insert(&mut self.problems.routes, node_id, reason.clone());
            }
            Event::DataPlaneFailed { reason } => {
                self.problems.data_plane = Some((Instant::now(), now, reason.clone()));
            }
            Event::PathSwitched {
                node_id, reason, ..
            } => {
                let reason = serde_json::to_value(reason)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default();
                self.switches.insert(node_id.clone(), (now, reason));
            }
            Event::MemberRemoved { node_id } => {
                self.switches.remove(node_id);
            }
            _ => {}
        }
        // 每次应用都会出现、或内容很长的事件不进最近事件：它们说明不了"刚才发生了什么"
        if matches!(
            event,
            Event::PeersApplied { .. } | Event::TransportConfigChanged { .. }
        ) {
            return;
        }
        if let Ok(serde_json::Value::Object(fields)) = serde_json::to_value(event) {
            if self.events.len() == MAX_EVENTS {
                self.events.pop_front();
            }
            self.events.push_back(EventRecord { at: now, fields });
        }
    }
}

impl<E: EventSink> EventSink for Recorder<E> {
    fn emit(&mut self, event: Event) {
        self.record(&event);
        self.inner.emit(event);
    }
}

// ---- 本机套接字（design/status.md 第 3、4 节） ----

#[derive(Debug, Deserialize)]
struct Request {
    v: u32,
    query: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReloadReplyDoc {
    v: u32,
    reload: ReloadOutcome,
}

#[derive(Debug, Serialize, Deserialize)]
struct ErrorReply {
    v: u32,
    error: ErrorBody,
}

#[derive(Debug, Serialize, Deserialize)]
struct ErrorBody {
    code: String,
    message: String,
}

/// 接口背后的组网进程。
pub trait StatusSource: Send + 'static {
    /// 当前的快照；后台线程忙、在 [`QUERY_TIMEOUT`] 内交不出时为 `None`。
    fn snapshot(&self) -> Option<StatusDoc>;
    /// 重新读取期望状态文件并等它应用完；已有太多在等、或 [`RELOAD_TIMEOUT`] 内没应用完时为 `None`。
    fn reload(&self) -> Option<ReloadOutcome>;
}

/// 接受状态查询的线程。丢弃时停止线程并删除套接字。
pub struct StatusServer {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl StatusServer {
    /// 在 `path` 建立套接字并开始接受连接。目录不存在时以 `0700` 建立；套接字为 `0600`。
    pub fn spawn(path: &Path, source: impl StatusSource) -> std::io::Result<Self> {
        let listener = bind(path)?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("nett-status".into())
            .stack_size(SERVER_STACK)
            .spawn(move || {
                let timeout = Timespec::try_from(ACCEPT_POLL).unwrap_or(Timespec {
                    tv_sec: 0,
                    tv_nsec: 500_000_000,
                });
                while !thread_stop.load(Ordering::Relaxed) {
                    let mut fds = [PollFd::new(&listener, PollFlags::IN)];
                    match poll(&mut fds, Some(&timeout)) {
                        Ok(0) | Err(rustix::io::Errno::INTR) => continue,
                        Ok(_) => {}
                        Err(e) => {
                            tracing::debug!(error = %e, "waiting for a status connection");
                            std::thread::sleep(ACCEPT_POLL);
                            continue;
                        }
                    }
                    match listener.accept() {
                        // macOS 上接受的连接继承监听套接字的非阻塞标志；查询用阻塞读写加超时
                        Ok((stream, _)) => {
                            let result = stream
                                .set_nonblocking(false)
                                .and_then(|()| handle(stream, &source));
                            if let Err(e) = result {
                                tracing::debug!(error = %e, "status query failed");
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(e) => tracing::debug!(error = %e, "accepting a status connection"),
                    }
                }
            })?;
        Ok(Self {
            path: path.to_owned(),
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for StatusServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

fn bind(path: &Path) -> std::io::Result<UnixListener> {
    use std::io::{Error, ErrorKind};
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty())
        && !dir.exists()
    {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            if UnixStream::connect(path).is_ok() {
                return Err(Error::new(
                    ErrorKind::AddrInUse,
                    format!("another process is serving {}", path.display()),
                ));
            }
            // 上一次异常退出留下的套接字
            std::fs::remove_file(path)?;
        }
        Ok(_) => {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    // 先在临时名字上建立并设好权限，再改名：套接字一出现在约定的路径上就是 0600
    let tmp = path.with_extension(format!("sock.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let listener = UnixListener::bind(&tmp)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, path)?;
    Ok(listener)
}

/// 只接受 root 和组网进程自己的运行身份（套接字的权限之外再检查一次）。
fn peer_allowed(stream: &UnixStream) -> std::io::Result<bool> {
    let uid = peer_uid(stream)?;
    Ok(uid == 0 || uid == rustix::process::geteuid().as_raw())
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    Ok(rustix::net::sockopt::socket_peercred(stream)?.uid.as_raw())
}

#[cfg(target_os = "macos")]
fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    use std::os::fd::AsFd as _;
    crate::macos::peer_uid(stream.as_fd())
}

/// 处理一个连接。回复之后关闭写方向，再丢弃对方没被读走的输入（最多 [`MAX_DRAIN`]）：带着未读数据关闭
/// 时，Linux 向对方发送复位，对方可能还没读到回复。
fn handle(stream: UnixStream, source: &impl StatusSource) -> std::io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let result = answer(&stream, source);
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let _ = std::io::copy(&mut (&stream).take(MAX_DRAIN), &mut std::io::sink());
    result
}

fn answer(stream: &UnixStream, source: &impl StatusSource) -> std::io::Result<()> {
    if !peer_allowed(stream)? {
        return reply_error(
            stream,
            "permission_denied",
            "only root can query the status",
        );
    }
    let mut line = String::new();
    BufReader::new(stream.take(MAX_REQUEST)).read_line(&mut line)?;
    let request: Request = match serde_json::from_str(line.trim_end()) {
        Ok(r) => r,
        Err(_) => return reply_error(stream, "bad_request", "the request is not valid JSON"),
    };
    if request.v != VERSION {
        return reply_error(
            stream,
            "unsupported_version",
            &format!(
                "interface version {} is not supported; this process speaks {VERSION}",
                request.v
            ),
        );
    }
    if request.query == "reload" {
        let Some(outcome) = source.reload() else {
            return reply_error(
                stream,
                "busy",
                "the mesh process did not finish applying in time; check again with nett status",
            );
        };
        let mut bytes = serde_json::to_vec(&ReloadReplyDoc {
            v: VERSION,
            reload: outcome,
        })
        .map_err(std::io::Error::other)?;
        bytes.push(b'\n');
        let mut out = stream;
        return out.write_all(&bytes);
    }
    if request.query != "status" {
        let query: String = request.query.chars().take(32).collect();
        return reply_error(stream, "unknown_query", &format!("unknown query `{query}`"));
    }
    let Some(doc) = source.snapshot() else {
        return reply_error(stream, "busy", "the mesh process is busy; try again");
    };
    let mut bytes = serde_json::to_vec(&doc).map_err(std::io::Error::other)?;
    if bytes.len() as u64 > MAX_REPLY {
        return reply_error(
            stream,
            "too_large",
            "the status is larger than the reply limit",
        );
    }
    bytes.push(b'\n');
    let mut out = stream;
    out.write_all(&bytes)
}

fn reply_error(stream: &UnixStream, code: &str, message: &str) -> std::io::Result<()> {
    let reply = ErrorReply {
        v: VERSION,
        error: ErrorBody {
            code: code.into(),
            message: message.into(),
        },
    };
    let mut bytes = serde_json::to_vec(&reply).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    let mut stream = stream;
    stream.write_all(&bytes)
}

// ---- 客户端 ----

#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("cannot reach the mesh service at {}: {source}", path.display())]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("talking to the mesh service at {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("the mesh service answered {code}: {message}")]
    Refused { code: String, message: String },
    #[error("the mesh service sent a reply this version cannot read: {0}")]
    Reply(String),
}

/// 向 `path` 上的组网进程查询状态。
pub fn query(path: &Path) -> Result<StatusDoc, QueryError> {
    let value = query_raw(path)?;
    serde_json::from_value(value).map_err(|e| QueryError::Reply(e.to_string()))
}

/// 与 [`query`] 相同，返回未经解析的回复：其中可能有这个版本不认识的字段（`nett status --json` 原样输出）。
pub fn query_raw(path: &Path) -> Result<serde_json::Value, QueryError> {
    request(path, "status", QUERY_TIMEOUT)
}

/// 请 `path` 上的组网进程重新读取期望状态文件，等它应用完（design/status.md 第 4.1 节）。
pub fn reload(path: &Path) -> Result<ReloadOutcome, QueryError> {
    let value = request(path, "reload", RELOAD_TIMEOUT)?;
    let doc: ReloadReplyDoc =
        serde_json::from_value(value).map_err(|e| QueryError::Reply(e.to_string()))?;
    Ok(doc.reload)
}

/// 发一个请求，读回回复；组网进程那一侧最多用 `wait` 处理它。
fn request(path: &Path, query: &str, wait: Duration) -> Result<serde_json::Value, QueryError> {
    let io = |source| QueryError::Io {
        path: path.to_owned(),
        source,
    };
    let stream = UnixStream::connect(path).map_err(|source| QueryError::Connect {
        path: path.to_owned(),
        source,
    })?;
    stream
        .set_read_timeout(Some(wait + IO_TIMEOUT))
        .map_err(io)?;
    stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(io)?;
    (&stream)
        .write_all(format!("{{\"v\":{VERSION},\"query\":\"{query}\"}}\n").as_bytes())
        .map_err(io)?;
    let mut bytes = Vec::new();
    (&stream)
        .take(MAX_REPLY + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| QueryError::Reply(e.to_string()))?;
    if let Some(error) = value.get("error") {
        let body: ErrorBody =
            serde_json::from_value(error.clone()).map_err(|e| QueryError::Reply(e.to_string()))?;
        return Err(QueryError::Refused {
            code: body.code,
            message: body.message,
        });
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::VecSink;
    use crate::path::SwitchReason;
    use std::sync::atomic::AtomicUsize;

    fn node(n: u8) -> NodeId {
        crate::testutil::node_id(n)
    }

    fn sample() -> StatusDoc {
        StatusDoc {
            v: VERSION,
            version: "0.0.0".into(),
            node: NodeStatus {
                id: node(1),
                name: Some("edge-vps".parse().expect("name")),
                admitted: true,
                mesh: vec!["100.88.0.1".parse().expect("addr")],
                edge: vec![],
                routes: vec![],
                reachability: Reachability::Public,
                dataplane: DataPlaneKind::Kernel,
                listen_port: Some(41820),
                nat: None,
                clock_trusted: true,
                started_at: Timestamp::from_unix_seconds(1_700_000_000),
            },
            config: ConfigStatus {
                applied_at: None,
                access_rules_version: Some(3),
            },
            peers: vec![PeerStatus {
                id: node(2),
                name: None,
                mesh: vec![],
                edge: vec![],
                routes: vec![],
                state: PeerState::Connected,
                role: Some(PeerRole::Decider),
                path: Some(PathStatus {
                    kind: PathKindDoc::Direct,
                    relay: None,
                    endpoint: None,
                    punched: false,
                    since: None,
                    reason: None,
                }),
                rtt_ms: Some(9.4),
                loss: Some(0.0),
                jitter_ms: None,
                last_handshake: None,
                last_received: None,
                rx_bytes: 0,
                tx_bytes: 0,
                candidates: vec![],
            }],
            problems: vec![],
            events: vec![],
        }
    }

    struct Fixed(Option<StatusDoc>);

    impl StatusSource for Fixed {
        fn snapshot(&self) -> Option<StatusDoc> {
            self.0.clone()
        }

        fn reload(&self) -> Option<ReloadOutcome> {
            self.0.as_ref().map(|_| ReloadOutcome::Rejected {
                reason: "bad json".into(),
            })
        }
    }

    /// 测试用的短路径（macOS 上 Unix 套接字路径最长 104 字节）。
    fn temp_dir() -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "nst{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn raw(path: &Path, request: &[u8]) -> serde_json::Value {
        let mut stream = UnixStream::connect(path).expect("connect");
        stream.write_all(request).expect("write");
        let mut out = Vec::new();
        stream.read_to_end(&mut out).expect("read");
        serde_json::from_slice(&out).expect("json reply")
    }

    #[test]
    fn answers_a_status_query_over_a_private_socket() {
        let dir = temp_dir();
        let path = dir.join("mesh.sock");
        let server = StatusServer::spawn(&path, Fixed(Some(sample()))).expect("spawn");
        let mode = |p: &Path| std::fs::metadata(p).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&path), 0o600);
        assert_eq!(query(&path).expect("query"), sample());
        // 读的一方忽略不认识的字段：新版本多出的字段不影响旧版本的 nett
        let mut newer = serde_json::to_value(sample()).expect("value");
        newer["future_field"] = serde_json::json!({"x": 1});
        newer["peers"][0]["state"] = "something_new".into();
        let parsed: StatusDoc = serde_json::from_value(newer).expect("tolerant");
        assert_eq!(parsed.peers[0].state, PeerState::Other);

        drop(server);
        assert!(!path.exists(), "socket removed on shutdown");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_bad_requests() {
        let dir = temp_dir();
        let path = dir.join("mesh.sock");
        let _server = StatusServer::spawn(&path, Fixed(Some(sample()))).expect("spawn");
        let code = |request: &[u8]| raw(&path, request)["error"]["code"].clone();
        assert_eq!(code(b"hello\n"), "bad_request");
        assert_eq!(
            code(b"{\"v\":2,\"query\":\"status\"}\n"),
            "unsupported_version"
        );
        assert_eq!(code(b"{\"v\":1,\"query\":\"stats\"}\n"), "unknown_query");
        // 超过长度上限的请求不读完
        let mut long = vec![b' '; 4096];
        long.push(b'\n');
        assert_eq!(code(&long), "bad_request");
        drop(_server);

        let _busy = StatusServer::spawn(&path, Fixed(None)).expect("spawn");
        assert!(matches!(
            query(&path),
            Err(QueryError::Refused { code, .. }) if code == "busy"
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reload_reports_the_outcome_or_busy() {
        let dir = temp_dir();
        let path = dir.join("mesh.sock");
        let server = StatusServer::spawn(&path, Fixed(Some(sample()))).expect("spawn");
        assert_eq!(
            reload(&path).expect("reload"),
            ReloadOutcome::Rejected {
                reason: "bad json".into()
            }
        );
        // 线上的形式（design/status.md 第 4.1 节）
        assert_eq!(
            raw(&path, b"{\"v\":1,\"query\":\"reload\"}\n"),
            serde_json::json!({"v": 1, "reload": {"result": "rejected", "reason": "bad json"}})
        );
        drop(server);
        let _busy = StatusServer::spawn(&path, Fixed(None)).expect("spawn");
        assert!(matches!(
            reload(&path),
            Err(QueryError::Refused { code, .. }) if code == "busy"
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn takes_over_a_stale_socket_but_not_a_live_one_or_a_file() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("mesh.sock");
        // 上一次异常退出留下的套接字：文件还在，没有进程在听
        drop(UnixListener::bind(&path).expect("bind"));
        assert!(path.exists());
        let live = StatusServer::spawn(&path, Fixed(Some(sample()))).expect("takes over");
        let second = StatusServer::spawn(&path, Fixed(Some(sample())));
        assert_eq!(
            second.err().map(|e| e.kind()),
            Some(std::io::ErrorKind::AddrInUse)
        );
        assert!(query(&path).is_ok(), "the first server keeps serving");
        drop(live);

        std::fs::write(&path, b"not a socket").expect("file");
        assert!(StatusServer::spawn(&path, Fixed(Some(sample()))).is_err());
        assert_eq!(std::fs::read(&path).expect("kept"), b"not a socket");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reports_a_missing_service() {
        let dir = temp_dir();
        let err = query(&dir.join("mesh.sock")).expect_err("no service");
        assert!(matches!(
            err,
            QueryError::Connect { ref source, .. } if source.kind() == std::io::ErrorKind::NotFound
        ));
    }

    #[test]
    fn records_problems_until_the_next_desired_state() {
        let mut r = Recorder::new(VecSink::default());
        r.emit(Event::ConfigRejected {
            reason: "bad json".into(),
        });
        r.emit(Event::MemberRejected {
            node_id: Some(node(3)),
            reason: "signature".into(),
        });
        r.emit(Event::DataPlaneFailed {
            reason: "netlink".into(),
        });
        // 事件照常交给原来的出口
        assert_eq!(r.inner.0.len(), 3);
        let names = BTreeMap::from([(node(3), "nas".parse().expect("name"))]);
        let mut doc = sample();
        let now = Instant::now();
        r.fill(&mut doc, &names, now);
        let kinds: Vec<ProblemKind> = doc.problems.iter().map(|p| p.kind).collect();
        assert_eq!(
            kinds,
            [
                ProblemKind::ConfigRejected,
                ProblemKind::MemberRejected,
                ProblemKind::DataPlaneFailed
            ]
        );
        assert_eq!(
            doc.problems[1].node.as_ref().and_then(|n| n.name.clone()),
            names.get(&node(3)).cloned()
        );
        // 下一份期望状态被接受：上一份留下的问题作废；数据面的失败按时间窗口，过后消失
        r.begin_apply();
        r.fill(&mut doc, &names, now);
        assert_eq!(doc.problems.len(), 1);
        r.fill(&mut doc, &names, now + DATA_PLANE_WINDOW);
        assert!(doc.problems.is_empty());
    }

    #[test]
    fn keeps_recent_events_and_the_last_switch_of_a_decider() {
        let mut r = Recorder::new(VecSink::default());
        for _ in 0..(MAX_EVENTS + 5) {
            r.emit(Event::PeersApplied { peers: 1 });
            r.emit(Event::PathSwitched {
                node_id: node(2),
                to: "direct 192.0.2.2:41820".into(),
                reason: SwitchReason::BetterType,
                rehandshake: false,
            });
        }
        let mut doc = sample();
        r.fill(&mut doc, &BTreeMap::new(), Instant::now());
        assert_eq!(doc.events.len(), MAX_EVENTS);
        assert!(doc.events.iter().all(|e| e.name() == "path_switched"));
        let path = doc.peers[0].path.as_ref().expect("path");
        assert_eq!(path.reason.as_deref(), Some("better_type"));
        assert!(path.since.is_some());
        // 跟随的一方不写切换原因：路径是对端选的
        let mut doc = sample();
        doc.peers[0].role = Some(PeerRole::Follower);
        r.fill(&mut doc, &BTreeMap::new(), Instant::now());
        assert_eq!(
            doc.peers[0].path.as_ref().and_then(|p| p.reason.clone()),
            None
        );
    }
}
