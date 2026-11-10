//! 每个对端的选路状态机（design/mesh.md 第 7、8 节，ADR 0021）。在决定方运行（第 8.3 节）；双方都是
//! `dial-only` 时跟随方也运行，只检测中断（第 8.4 节）。
//!
//! 纯逻辑：时间由调用方传入，发送探测和切换 endpoint 以 [`Action`] 交给调用方执行，测试中可以精确模拟时间。

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::probe::KeyId;

/// 有流量时隧道内探测的间隔。
pub const TUNNEL_INTERVAL: Duration = Duration::from_secs(1);
/// 隧道内连续这么多次没有应答，进入疑似故障。
const SUSPECT_AFTER_LOSSES: u32 = 2;
/// 疑似故障时在当前路径上加探的次数与间隔。
const BURST_COUNT: u32 = 3;
const BURST_SPACING: Duration = Duration::from_millis(200);
/// 丢包率超过这个比例并持续 [`LOSS_FAILURE_HOLD`]，也判为故障。
const LOSS_FAILURE_RATE: f64 = 0.30;
const LOSS_FAILURE_HOLD: Duration = Duration::from_secs(3);
/// 更优类型的候选连续这么多次有应答，切过去。
const BETTER_TYPE_SUCCESSES: u32 = 2;
/// 故障过的路径恢复时的等待时间：10 分钟内第二次故障起，10 秒起按故障次数加倍，最长 5 分钟；
/// 第一次故障后的恢复不等待（ADR 0021）。
const BACKOFF_BASE: Duration = Duration::from_secs(10);
const BACKOFF_MAX: Duration = Duration::from_secs(300);
const FAILURE_MEMORY: Duration = Duration::from_secs(600);
/// 同类型的更优路径：得分优于当前至少 15% 且至少 10 毫秒，并持续 30 秒。
const SAME_TYPE_RATIO: f64 = 0.85;
const SAME_TYPE_MIN_MS: f64 = 10.0;
const SAME_TYPE_HOLD: Duration = Duration::from_secs(30);
/// 当前路径丢包明显（最近 [`LOSS_WINDOW`] 次隧道内探测丢失这么多次以上）、候选连续有应答时，
/// 同类型的更优路径只需持续 [`LOSSY_HOLD`]（ADR 0021）。
const LOSSY_LOSSES: usize = 2;
const LOSSY_HOLD: Duration = Duration::from_secs(5);
/// 候选的探测间隔：有流量时每 15 秒；当前路径不是最优类型时，更优类型每 1 秒；当前路径明显变差时，
/// 同类候选每 3 秒；空闲时每 5 分钟。
const CANDIDATE_INTERVAL: Duration = Duration::from_secs(15);
const BETTER_TYPE_INTERVAL: Duration = Duration::from_secs(1);
const DEGRADED_INTERVAL: Duration = Duration::from_secs(3);
/// 从未应答过的候选，第一次探测后的这段时间内与更优类型一样每 1 秒探测：启动时对端可能还没起来，
/// 不必等 15 秒才得知它能不能通、本机的映射地址是什么（design/mesh.md 第 6.1、7 节）。
const DISCOVERY_WINDOW: Duration = Duration::from_secs(60);
/// 刚因第一次故障从一条更优类型的路径切走时，这么久之内每 [`FAST_RECOVERY_INTERVAL`] 探测它一次，
/// 恢复后很快切回（ADR 0021）。
const FAST_RECOVERY_WINDOW: Duration = Duration::from_secs(15);
pub const FAST_RECOVERY_INTERVAL: Duration = Duration::from_millis(50);
/// 重新握手之后等它完成：旧路径的往返时间与新路径往返时间的两倍中较大的一个，加上这个余量，最长
/// 1 秒（第 8.4 节）；新路径还没有测量时按这个往返时间估计。
const HANDSHAKE_MARGIN: Duration = Duration::from_millis(20);
const HANDSHAKE_WAIT_MAX: Duration = Duration::from_secs(1);
const HANDSHAKE_UNKNOWN_RTT_MS: f64 = 150.0;
/// WireGuard 收到 cookie 应答后带着它重试的时间：`REKEY_TIMEOUT` 5 秒，加最多 1/3 秒的抖动。期间
/// 不再重新握手、不按疑似故障切走；每换到一条路径最多等这么多轮（第 8.4 节）。
const COOKIE_RETRY: Duration = Duration::from_millis(5_400);
const COOKIE_ROUNDS: u32 = 2;
/// 一个候选最多同时等待应答的探测数：高频探测时，上一个探测还没超时就发下一个。
const MAX_CANDIDATE_OUTSTANDING: usize = 32;
const IDLE_CANDIDATE_INTERVAL: Duration = Duration::from_secs(300);
/// 判断当前路径"明显变慢"的往返时间最小增量（毫秒）。
const DEGRADED_MIN_MS: f64 = 10.0;
/// 更优类型的候选第一次有应答之后，确认探测的间隔。
const CONFIRM_INTERVAL: Duration = Duration::from_millis(200);
/// 候选探测等待应答的上限。
const CANDIDATE_TIMEOUT: Duration = Duration::from_secs(1);
/// 超时的隧道内探测再等这么久：迟到的应答说明路径通、只是在排队，照常计入往返时间；对端的包仍在到达、
/// 这么久却没有任何应答（只有一个方向通），照常判为故障（design/mesh.md 第 7、8.2 节）。
pub const LATE_HORIZON: Duration = Duration::from_secs(10);
/// 同时等待迟到应答的隧道内探测数上限：每秒一个加上加探，10 秒内不到 20 个。
const MAX_LATE: usize = 32;
/// 丢包率的滑动窗口（探测次数）。
const LOSS_WINDOW: usize = 10;
/// 往返时间指数滑动平均的权重。
const RTT_ALPHA: f64 = 0.25;
/// 得分中的丢包惩罚：每 1% 丢包相当于 5 毫秒。
const LOSS_PENALTY_MS: f64 = 500.0;
/// 路径类型偏好与传输惩罚（毫秒），越小越优（第 8.1 节）：TLS 在经中继的偏好之上再加 20 毫秒。
const RELAY_PENALTY_MS: f64 = 10.0;
const TLS_PENALTY_MS: f64 = 20.0;

/// 路径类型，从优到劣（第 8.2 节）：同一路径上 UDP 优于 TLS。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    Lan,
    Direct,
    Relay,
    /// 经中继的 TLS 传输（design/mesh.md 第 5.3 节）。
    RelayTls,
}

impl PathKind {
    pub fn via_relay(self) -> bool {
        matches!(self, PathKind::Relay | PathKind::RelayTls)
    }
}

/// 一条路径在 WireGuard 中对应的 endpoint。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Direct(SocketAddr),
    Relay { relay: KeyId, endpoint: SocketAddr },
}

impl Route {
    pub fn endpoint(&self) -> SocketAddr {
        match self {
            Route::Direct(e) | Route::Relay { endpoint: e, .. } => *e,
        }
    }
}

/// 往返时间、丢包率与抖动。
#[derive(Debug, Clone, Default)]
pub struct PathStats {
    rtt_ms: Option<f64>,
    jitter_ms: f64,
    window: VecDeque<bool>,
    consecutive_losses: u32,
    consecutive_successes: u32,
}

impl PathStats {
    /// 只带往返时间估计的新统计。
    fn seeded(rtt_ms: Option<f64>) -> Self {
        Self {
            rtt_ms,
            ..Self::default()
        }
    }

    pub fn record_reply(&mut self, rtt: Duration) {
        let ms = rtt.as_secs_f64() * 1000.0;
        self.rtt_ms = Some(match self.rtt_ms {
            // 与平均值相差一倍以上：路径变了，直接采用新值，不等平均值慢慢跟上
            Some(prev) if ms >= 2.0 * prev || ms <= prev / 2.0 => ms,
            Some(prev) => {
                self.jitter_ms += RTT_ALPHA * ((ms - prev).abs() - self.jitter_ms);
                prev + RTT_ALPHA * (ms - prev)
            }
            None => ms,
        });
        self.push(true);
        self.consecutive_losses = 0;
        self.consecutive_successes += 1;
    }

    pub fn record_loss(&mut self) {
        self.push(false);
        self.record_miss();
    }

    /// 超时未应答：计入连续丢失（用来进入疑似故障），丢包率等确定丢失后再计（design/mesh.md 第 7 节）。
    fn record_miss(&mut self) {
        self.consecutive_losses += 1;
        self.consecutive_successes = 0;
    }

    fn push(&mut self, ok: bool) {
        if self.window.len() == LOSS_WINDOW {
            self.window.pop_front();
        }
        self.window.push_back(ok);
    }

    pub fn loss_rate(&self) -> f64 {
        if self.window.is_empty() {
            return 0.0;
        }
        let lost = self.window.iter().filter(|ok| !**ok).count();
        lost as f64 / self.window.len() as f64
    }

    pub fn rtt_ms(&self) -> Option<f64> {
        self.rtt_ms
    }

    pub fn jitter_ms(&self) -> f64 {
        self.jitter_ms
    }

    /// 还没有任何一次探测有结果时为 `None`。
    pub fn measured_loss(&self) -> Option<f64> {
        (!self.window.is_empty()).then(|| self.loss_rate())
    }

    /// 得分（毫秒，越小越好）：往返时间 + 丢包惩罚 + 抖动 + 路径类型偏好（第 8.1 节）。
    pub fn score(&self, kind: PathKind) -> Option<f64> {
        let type_penalty = match kind {
            PathKind::Lan | PathKind::Direct => 0.0,
            PathKind::Relay => RELAY_PENALTY_MS,
            PathKind::RelayTls => RELAY_PENALTY_MS + TLS_PENALTY_MS,
        };
        self.rtt_ms
            .map(|rtt| rtt + self.loss_rate() * LOSS_PENALTY_MS + self.jitter_ms + type_penalty)
    }

    /// 等待应答的上限：往返时间的两倍加 100 毫秒，限制在 300 毫秒到 1 秒之间。
    fn timeout(&self) -> Duration {
        let ms = self
            .rtt_ms
            .map_or(1000.0, |rtt| 2.0 * rtt + 100.0)
            .clamp(300.0, 1000.0);
        Duration::from_secs_f64(ms / 1000.0)
    }
}

#[derive(Debug, Clone)]
struct Candidate {
    route: Route,
    kind: PathKind,
    stats: PathStats,
    /// 等待应答的探测，按发出的先后排列。
    outstanding: VecDeque<(u32, Instant)>,
    last_probe: Option<Instant>,
    last_reply: Option<Instant>,
    /// 作为当前路径时故障的时刻，用于恢复时的退避。
    failures: VecDeque<Instant>,
    /// 最近一次作为当前路径故障而被切走的时刻（不论是否计入退避）。
    left_at: Option<Instant>,
    /// 第一次探测的时刻。
    first_probe: Option<Instant>,
    /// 最近一次连续有应答的开始时刻。
    healthy_since: Option<Instant>,
    /// 已经用过一次"从未连通过就失败不算故障"。
    grace_used: bool,
}

impl Candidate {
    fn new(route: Route, kind: PathKind) -> Self {
        Self {
            route,
            kind,
            stats: PathStats::default(),
            outstanding: VecDeque::new(),
            last_probe: None,
            last_reply: None,
            failures: VecDeque::new(),
            left_at: None,
            first_probe: None,
            healthy_since: None,
            grace_used: false,
        }
    }
}

/// 切换的原因，写入路径切换事件。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwitchReason {
    /// 疑似故障后加探全部丢失。
    Unreachable,
    /// 丢包率持续过高。
    HighLoss,
    /// 更优类型的路径恢复。
    BetterType,
    /// 同类型的更优路径。
    BetterScore,
    /// 当前中继仍能应答探测而隧道不通：它丢了这条连接的索引，在同一中继上重新握手（第 8.4 节）。
    RelayLostSession,
    /// 重新握手之后到期仍没有完成（例如对端的应答被旧路径上迟到的包带去了旧中继）：在同一中继上
    /// 再重新握手一次（第 8.4 节）。
    HandshakeIncomplete,
    /// 双方都是 `dial-only`：跟随方按决定方经隧道发来的提议切换（第 8.4 节）。
    Proposed,
    /// 双方都是 `dial-only`、当前路径中断：按时间片（时钟不可信时按随机间隔）轮换中继（第 8.4 节）。
    Rotation,
}

/// 一条候选路径在本机状态中的样子（design/status.md 第 6 节）。
#[derive(Debug, Clone, PartialEq)]
pub struct CandidateView {
    pub route: Route,
    pub kind: PathKind,
    pub rtt_ms: Option<f64>,
    pub loss: Option<f64>,
    pub state: CandidateState,
    /// 打洞打通的直连（design/mesh.md 第 6.1 节）。
    pub punched: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateState {
    Current,
    /// 最近的探测有应答。
    Ok,
    /// 最近的探测丢失，或故障之后还在退避。
    Failing,
    /// 还没有探测结果。
    Untested,
}

/// 这一端在这一对成员中的角色（第 8.3、8.4 节）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// 决定方，对端经漫游跟随。
    Decide,
    /// 双方都是 `dial-only` 时的决定方：择优的切换先经隧道提议（[`Action::Propose`]），中断时报告
    /// [`Action::Lost`]。
    DecideTogether,
    /// 双方都是 `dial-only` 时的跟随方：只检测中断，不择优、不探测候选。
    FollowTogether,
}

impl Role {
    pub fn together(self) -> bool {
        self != Role::Decide
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// 经当前隧道发一个隧道内探测。
    TunnelProbe { seq: u32 },
    /// 探测一个候选（直连：从 WireGuard 端口；中继：发往中继）。
    CandidateProbe {
        index: usize,
        route: Route,
        seq: u32,
    },
    /// 把对端的 endpoint 改为 `to`；切换到中继时先删除对端再加回，触发经新中继的握手（第 8.4 节）。
    Switch {
        to: Route,
        rehandshake: bool,
        reason: SwitchReason,
    },
    /// 双方都是 `dial-only` 时的决定方：要切到第 `index` 个候选，先经隧道提议，对端确认后由调用方
    /// [`PeerPaths::adopt`]（第 8.4 节）。在此之前不再另行择优。
    Propose { index: usize, reason: SwitchReason },
    /// 双方都是 `dial-only`：当前路径中断，要两端一起恢复（第 8.4 节），由调用方决定去哪里。
    Lost,
}

/// 重新握手之后等待它完成（第 8.4 节）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HandshakeCheck {
    deadline: Instant,
    /// 已经因为没完成而再握手过一次。
    retried: bool,
    /// 对端回了 cookie 应答，在等 WireGuard 带着它重试。
    cookie: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Normal,
    /// 疑似故障：已经发出的加探次数，下一次加探的时刻，开始时刻。
    Suspect {
        sent: u32,
        next: Instant,
        since: Instant,
    },
}

/// 一个对端的选路状态。
#[derive(Debug, Clone)]
pub struct PeerPaths {
    role: Role,
    candidates: Vec<Candidate>,
    current: usize,
    tunnel: PathStats,
    tunnel_outstanding: VecDeque<(u32, Instant)>,
    /// 已经超时、还在等迟到应答的隧道内探测（[`LATE_HORIZON`]）。
    tunnel_late: VecDeque<(u32, Instant)>,
    /// 当前路径上最近一次收到隧道内应答（包括迟到的）。
    last_tunnel_reply: Option<Instant>,
    /// 当前路径上最近一次收到迟到的隧道内应答：在排队。
    last_late_reply: Option<Instant>,
    /// 最近一次看到对端的包到达（WireGuard 对它的接收字节数有变化）。
    last_rx: Option<Instant>,
    last_tunnel_probe: Option<Instant>,
    phase: Phase,
    /// 当前路径切换以来收到过隧道内应答。
    tunnel_established: bool,
    /// 切到当前路径以来隧道内往返时间的最好值（毫秒），用来判断它是否明显变慢。
    best_rtt_ms: Option<f64>,
    /// 这次故障中已经在同一中继上重新握手过一次。
    rehandshake_tried: bool,
    /// 重新握手之后，等待确认它完成。
    handshake: Option<HandshakeCheck>,
    /// 换到当前路径以来，因 cookie 应答等过几轮。
    cookie_rounds: u32,
    high_loss_since: Option<Instant>,
    better_since: Option<(usize, Instant)>,
    /// 两端一起切换的过程中（等待确认、轮换中）：只检测中断，不另行择优。
    hold: bool,
    /// 打洞打通的直连候选（design/mesh.md 第 6.1 节），排在配置的候选之后。
    punched: Option<usize>,
    seq: u32,
}

impl PeerPaths {
    /// `routes` 按 Hub 给出的顺序排列；初始路径取第一条。
    pub fn new(routes: Vec<(Route, PathKind)>, role: Role) -> Option<Self> {
        if routes.is_empty() {
            return None;
        }
        Some(Self {
            role,
            candidates: routes
                .into_iter()
                .map(|(route, kind)| Candidate::new(route, kind))
                .collect(),
            current: 0,
            tunnel: PathStats::default(),
            tunnel_outstanding: VecDeque::new(),
            tunnel_late: VecDeque::new(),
            last_tunnel_reply: None,
            last_late_reply: None,
            last_rx: None,
            last_tunnel_probe: None,
            phase: Phase::Normal,
            tunnel_established: false,
            best_rtt_ms: None,
            rehandshake_tried: false,
            handshake: None,
            cookie_rounds: 0,
            high_loss_since: None,
            better_since: None,
            hold: false,
            punched: None,
            seq: 0,
        })
        .map(|mut paths| {
            // 两端一起切换时，两端从同一个中继开始
            if role.together()
                && let Some(first) = paths.relays_in_order().first()
            {
                paths.current = *first;
            }
            paths
        })
    }

    pub fn current(&self) -> Route {
        self.candidates[self.current].route
    }

    pub fn current_kind(&self) -> PathKind {
        self.candidates[self.current].kind
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// 切到当前路径以来收到过隧道内应答：本端发出的探测得到了对端的应答，双向都通。
    pub fn tunnel_established(&self) -> bool {
        self.tunnel_established
    }

    /// 打洞打通的直连：作为一条直连候选加入（已有时换成新的地址，测量从头开始），返回它的序号。
    pub fn set_punched(&mut self, endpoint: SocketAddr) -> usize {
        let route = Route::Direct(endpoint);
        if let Some(i) = self.punched {
            let c = &mut self.candidates[i];
            if c.route != route {
                *c = Candidate::new(route, PathKind::Direct);
            }
            return i;
        }
        self.candidates
            .push(Candidate::new(route, PathKind::Direct));
        let i = self.candidates.len() - 1;
        self.punched = Some(i);
        i
    }

    pub fn punched_index(&self) -> Option<usize> {
        self.punched
    }

    /// 各候选路径的测量与状态，当前路径在内（design/status.md 第 6 节）。
    pub fn candidate_views(&self, now: Instant) -> Vec<CandidateView> {
        self.candidates
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let state = if i == self.current {
                    CandidateState::Current
                } else if c.first_probe.is_none() {
                    CandidateState::Untested
                } else if c.stats.consecutive_losses > 0 || !backoff(&c.failures, now).is_zero() {
                    CandidateState::Failing
                } else if c.stats.consecutive_successes > 0 {
                    CandidateState::Ok
                } else {
                    CandidateState::Untested
                };
                CandidateView {
                    route: c.route,
                    kind: c.kind,
                    rtt_ms: c.stats.rtt_ms(),
                    loss: c.stats.measured_loss(),
                    state,
                    punched: self.punched == Some(i),
                }
            })
            .collect()
    }

    /// 经中继 `relay` 的候选。
    pub fn relay_index(&self, relay: KeyId) -> Option<usize> {
        self.candidates
            .iter()
            .position(|c| matches!(c.route, Route::Relay { relay: r, .. } if r == relay))
    }

    /// 经中继的候选按中继编号排序：两端各自的候选列表顺序可能不同，排序后是同一份（第 8.4 节）。
    pub fn relays_in_order(&self) -> Vec<usize> {
        let mut relays: Vec<(KeyId, usize)> = self
            .candidates
            .iter()
            .enumerate()
            .filter_map(|(i, c)| match c.route {
                Route::Relay { relay, .. } => Some((relay, i)),
                Route::Direct(_) => None,
            })
            .collect();
        relays.sort();
        relays.into_iter().map(|(_, i)| i).collect()
    }

    /// 由调用方决定的切换（两端一起切换时）：切到第 `index` 个候选；经中继时总是重新握手，
    /// 即使仍是当前中继，好让两端都在它上面发起新的握手。
    pub fn adopt(&mut self, index: usize, reason: SwitchReason, now: Instant) -> Option<Action> {
        self.candidates.get(index)?;
        let old_rtt_ms = self.tunnel.rtt_ms();
        let Action::Switch { to, .. } = self.switch_to(index, reason, now) else {
            return None;
        };
        // 立即发一个隧道内探测：它触发新的握手，也尽快确认新路径
        self.last_tunnel_probe = None;
        let rehandshake = matches!(to, Route::Relay { .. });
        if rehandshake {
            self.expect_handshake(now, old_rtt_ms);
        }
        Some(Action::Switch {
            to,
            rehandshake,
            reason,
        })
    }

    /// WireGuard 报告这个对端在重新握手之后完成了握手（调用方每次读取状态都会报告，只有在等待确认时才
    /// 起作用）。等待期间隧道内探测必然丢失，不算作这条路径的故障：从头检测，并立即探测一次确认新路径。
    pub fn on_handshake(&mut self) {
        if self.handshake.take().is_none() {
            return;
        }
        self.cookie_rounds = 0;
        let rtt_ms = self.tunnel.rtt_ms();
        self.tunnel = PathStats::seeded(rtt_ms);
        self.clear_tunnel_probes();
        self.phase = Phase::Normal;
        self.last_tunnel_probe = None;
    }

    /// WireGuard 对这个对端的接收字节数有变化：对端的包到达了（调用方每次读取状态时报告）。
    pub fn on_receive(&mut self, now: Instant) {
        self.last_rx = Some(now);
    }

    /// 从当前路径收到了对端的 cookie 应答，而隧道还没建立：对端处于负载状态，WireGuard 会在约 5 秒后
    /// 带着 cookie 重试。重新握手会丢掉 cookie，所以等这次重试，期间也不按疑似故障切走（第 8.4 节）。
    pub fn on_cookie(&mut self, now: Instant) {
        if self.tunnel_established || self.cookie_rounds >= COOKIE_ROUNDS {
            return;
        }
        self.cookie_rounds += 1;
        let new_ms = self.tunnel.rtt_ms().unwrap_or(HANDSHAKE_UNKNOWN_RTT_MS);
        let wait = COOKIE_RETRY + Duration::from_secs_f64(2.0 * new_ms / 1000.0) + HANDSHAKE_MARGIN;
        self.handshake = Some(HandshakeCheck {
            deadline: now + wait,
            retried: true,
            cookie: true,
        });
    }

    /// 在等 WireGuard 带着 cookie 重试。
    fn awaiting_cookie_retry(&self, now: Instant) -> bool {
        self.handshake.is_some_and(|h| h.cookie && now < h.deadline)
    }

    /// 重新握手之后等待确认的期限已到：调用方先读取 WireGuard 的握手状态（[`Self::on_handshake`]），
    /// 再推进。
    pub fn handshake_due(&self, now: Instant) -> bool {
        self.handshake.is_some_and(|h| now >= h.deadline)
    }

    /// 刚重新握手（`old_rtt_ms` 是切换之前那条路径的往返时间）：等旧路径上的包都到达、新路径完成一次
    /// 握手往返之后确认（第 8.4 节）。
    fn expect_handshake(&mut self, now: Instant, old_rtt_ms: Option<f64>) {
        let new_ms = self.tunnel.rtt_ms().unwrap_or(HANDSHAKE_UNKNOWN_RTT_MS);
        let wait_ms = old_rtt_ms.unwrap_or(0.0).max(2.0 * new_ms);
        let wait =
            (Duration::from_secs_f64(wait_ms / 1000.0) + HANDSHAKE_MARGIN).min(HANDSHAKE_WAIT_MAX);
        self.handshake = Some(HandshakeCheck {
            deadline: now + wait,
            retried: false,
            cookie: false,
        });
    }

    /// 重新握手到期还没完成：这个对端有流量时在同一中继上再握手一次，这时旧路径上的包已经到完；
    /// 再不成就交给疑似故障的检测（第 8.4 节）。
    fn check_handshake(&mut self, now: Instant, active: bool) -> Option<Action> {
        let check = self.handshake?;
        if now < check.deadline {
            return None;
        }
        if check.retried || !active {
            self.handshake = None;
            return None;
        }
        let route = self.current();
        let rtt_ms = self.tunnel.rtt_ms();
        self.tunnel = PathStats::seeded(rtt_ms);
        self.clear_tunnel_probes();
        self.last_tunnel_probe = None;
        self.expect_handshake(now, None);
        if let Some(h) = self.handshake.as_mut() {
            h.retried = true;
        }
        Some(Action::Switch {
            to: route,
            rehandshake: true,
            reason: SwitchReason::HandshakeIncomplete,
        })
    }

    /// 两端一起切换的过程中暂停择优（[`Action::Propose`] 之后自动暂停）。
    pub fn set_hold(&mut self, hold: bool) {
        self.hold = hold;
    }

    pub fn tunnel_stats(&self) -> &PathStats {
        &self.tunnel
    }

    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }

    pub fn on_tunnel_reply(&mut self, seq: u32, now: Instant) {
        // 更早发出、还没有应答的探测（包括超时之后还在等的）已经被这个应答越过，算作丢失
        let sent = if let Some(pos) = self.tunnel_outstanding.iter().position(|(s, _)| *s == seq) {
            for _ in 0..self.tunnel_late.len() {
                self.tunnel.push(false);
            }
            self.tunnel_late.clear();
            for _ in 0..pos {
                self.tunnel_outstanding.pop_front();
                self.tunnel.record_loss();
            }
            self.tunnel_outstanding.pop_front()
        } else if let Some(pos) = self.tunnel_late.iter().position(|(s, _)| *s == seq) {
            // 迟到的应答：路径通，只是在排队（design/mesh.md 第 7 节）
            for _ in 0..pos {
                self.tunnel_late.pop_front();
                self.tunnel.push(false);
            }
            self.last_late_reply = Some(now);
            self.tunnel_late.pop_front()
        } else {
            return;
        };
        let Some((_, sent)) = sent else {
            return;
        };
        self.last_tunnel_reply = Some(now);
        let rtt = now.saturating_duration_since(sent);
        self.tunnel.record_reply(rtt);
        let ms = rtt.as_secs_f64() * 1000.0;
        self.best_rtt_ms = Some(self.best_rtt_ms.map_or(ms, |b| b.min(ms)));
        self.tunnel_established = true;
        self.rehandshake_tried = false;
        // 隧道内应答说明握手已经完成
        self.handshake = None;
        self.cookie_rounds = 0;
        self.phase = Phase::Normal;
    }

    /// 候选的探测结果；`extra` 是经中继路径另一段的往返时间与丢包率（对端在隧道内应答中带来的）。
    pub fn on_candidate_reply(
        &mut self,
        index: usize,
        seq: u32,
        now: Instant,
        extra: Option<(Duration, f64)>,
    ) {
        let Some(c) = self.candidates.get_mut(index) else {
            return;
        };
        let Some(pos) = c.outstanding.iter().position(|(s, _)| *s == seq) else {
            return;
        };
        // 更早发出、还没有应答的探测已经被这个应答越过，算作丢失；之后不会再超时打断连续的应答
        for _ in 0..pos {
            c.outstanding.pop_front();
            c.stats.record_loss();
        }
        let (_, sent) = c.outstanding.pop_front().expect("position is in range");
        let (extra_rtt, extra_loss) = extra.unwrap_or((Duration::ZERO, 0.0));
        if extra_loss >= 1.0 {
            // 另一段不通：这条经中继的路径整体不通
            c.stats.record_loss();
            c.healthy_since = None;
            return;
        }
        c.stats
            .record_reply(now.saturating_duration_since(sent) + extra_rtt);
        c.last_reply = Some(now);
        c.healthy_since.get_or_insert(now);
    }

    /// 每 100 毫秒左右调用一次。`active` 表示最近 30 秒内这个对端有流量。
    pub fn tick(&mut self, now: Instant, active: bool) -> Vec<Action> {
        let mut actions = Vec::new();
        self.expire(now);

        if let Some(action) = self.check_handshake(now, active) {
            actions.push(action);
            return actions;
        }
        if let Some(action) = self.check_failure(now) {
            actions.push(action);
            return actions;
        }

        match self.phase {
            Phase::Suspect { sent, next, since } if sent < BURST_COUNT && now >= next => {
                let seq = self.send_tunnel(now);
                actions.push(Action::TunnelProbe { seq });
                self.phase = Phase::Suspect {
                    sent: sent + 1,
                    next: now + BURST_SPACING,
                    since,
                };
            }
            Phase::Suspect { .. } => {}
            Phase::Normal => {
                if self.tunnel.consecutive_losses >= SUSPECT_AFTER_LOSSES {
                    // 疑似故障：立即加探，同时探测全部候选
                    let seq = self.send_tunnel(now);
                    actions.push(Action::TunnelProbe { seq });
                    self.phase = Phase::Suspect {
                        sent: 1,
                        next: now + BURST_SPACING,
                        since: now,
                    };
                    // 当前路径经中继时也探测这个中继：它若还能应答，说明是它丢了这条连接的索引
                    let current_is_relay = self.current_kind().via_relay();
                    for index in 0..self.candidates.len() {
                        if self.role != Role::FollowTogether
                            && (index != self.current || current_is_relay)
                        {
                            actions.extend(self.probe_candidate(index, now, false));
                        }
                    }
                    return actions;
                }
                let due = active
                    && self
                        .last_tunnel_probe
                        .is_none_or(|t| now.saturating_duration_since(t) >= TUNNEL_INTERVAL);
                if due {
                    let seq = self.send_tunnel(now);
                    actions.push(Action::TunnelProbe { seq });
                }
                if self.role == Role::FollowTogether {
                    return actions;
                }
                // 丢包率刚开始过高时，同疑似故障一样立即探测全部候选
                let lossy = self.high_loss_since == Some(now);
                for index in 0..self.candidates.len() {
                    if index != self.current && (lossy || self.candidate_due(index, now, active)) {
                        let stack = self.fast_recovery(index, now);
                        actions.extend(self.probe_candidate(index, now, stack));
                    }
                }
                // 当前路径是直连时也从 WireGuard 端口探测它：应答带回本机的映射地址（design/mesh.md 第 6.1 节）
                if matches!(self.current_kind(), PathKind::Lan | PathKind::Direct)
                    && self.candidate_due(self.current, now, active)
                {
                    actions.extend(self.probe_candidate(self.current, now, false));
                }
                if !self.hold
                    && let Some(action) = self.check_improvement(now)
                {
                    actions.push(action);
                }
            }
        }
        actions
    }

    fn send_tunnel(&mut self, now: Instant) -> u32 {
        let seq = self.next_seq();
        self.tunnel_outstanding.push_back((seq, now));
        self.last_tunnel_probe = Some(now);
        seq
    }

    /// `stack`：上一个探测还在等待应答时也发出（高频探测）。
    fn probe_candidate(&mut self, index: usize, now: Instant, stack: bool) -> Option<Action> {
        let seq = self.next_seq();
        let c = &mut self.candidates[index];
        if c.outstanding.len() >= MAX_CANDIDATE_OUTSTANDING || (!stack && !c.outstanding.is_empty())
        {
            return None;
        }
        c.outstanding.push_back((seq, now));
        c.last_probe = Some(now);
        c.first_probe.get_or_insert(now);
        Some(Action::CandidateProbe {
            index,
            route: c.route,
            seq,
        })
    }

    /// 当前路径明显变差：往返时间比切到它以来的最好值翻倍且至少多 10 毫秒，或丢包明显
    /// （design/mesh.md 第 7 节）。
    fn degraded(&self) -> bool {
        let slower = match (self.tunnel.rtt_ms(), self.best_rtt_ms) {
            (Some(rtt), Some(best)) => rtt >= 2.0 * best && rtt >= best + DEGRADED_MIN_MS,
            _ => false,
        };
        slower || self.lossy()
    }

    /// 最近 10 次隧道内探测丢失 2 次以上：低于判为故障的丢包率，但已经明显（ADR 0021）。
    fn lossy(&self) -> bool {
        self.tunnel.window.iter().filter(|ok| !**ok).count() >= LOSSY_LOSSES
    }

    /// 刚因第一次故障从这条更优类型的路径切走，还在高频探测的时间内（ADR 0021）。
    fn fast_recovery(&self, index: usize, now: Instant) -> bool {
        let c = &self.candidates[index];
        c.kind < self.current_kind()
            && c.left_at
                .is_some_and(|t| now.saturating_duration_since(t) < FAST_RECOVERY_WINDOW)
            && backoff(&c.failures, now).is_zero()
    }

    /// 有候选在高频探测，或在等待重新握手完成（等 cookie 重试的几秒不算）：调用方要推进得比
    /// [`FAST_RECOVERY_INTERVAL`] 更密。
    pub fn needs_fine_ticks(&self, now: Instant) -> bool {
        self.handshake.is_some_and(|h| !h.cookie)
            || (0..self.candidates.len()).any(|i| i != self.current && self.fast_recovery(i, now))
    }

    fn candidate_due(&self, index: usize, now: Instant, active: bool) -> bool {
        let c = &self.candidates[index];
        let better = c.kind < self.current_kind();
        let first_reply = c.stats.consecutive_successes == 1;
        let interval = if !active {
            IDLE_CANDIDATE_INTERVAL
        } else if self.fast_recovery(index, now) {
            // 第一次应答之后立即确认：应答晚于最近一次探测，说明确认还没有发出
            if first_reply && c.last_reply >= c.last_probe {
                Duration::ZERO
            } else {
                FAST_RECOVERY_INTERVAL
            }
        } else if better && first_reply {
            // 更优类型的候选刚有一次应答：很快再探测一次确认，不等下一个间隔
            CONFIRM_INTERVAL
        } else if better
            || (c.last_reply.is_none()
                && c.first_probe
                    .is_some_and(|t| now.saturating_duration_since(t) < DISCOVERY_WINDOW))
        {
            BETTER_TYPE_INTERVAL
        } else if c.kind == self.current_kind() && self.degraded() {
            DEGRADED_INTERVAL
        } else {
            CANDIDATE_INTERVAL
        };
        c.last_probe
            .is_none_or(|t| now.saturating_duration_since(t) >= interval)
    }

    /// 超时未应答的候选探测记为丢失。隧道内探测超时只计入连续丢失（用来进入疑似故障），再等
    /// [`LATE_HORIZON`] 仍没有应答才记为丢失（design/mesh.md 第 7 节）。
    fn expire(&mut self, now: Instant) {
        let timeout = self.tunnel.timeout();
        while let Some(&(seq, sent)) = self.tunnel_outstanding.front() {
            if now.saturating_duration_since(sent) < timeout {
                break;
            }
            self.tunnel_outstanding.pop_front();
            self.tunnel.record_miss();
            if self.tunnel_late.len() >= MAX_LATE {
                self.tunnel_late.pop_front();
                self.tunnel.push(false);
            }
            self.tunnel_late.push_back((seq, sent));
        }
        while let Some((_, sent)) = self.tunnel_late.front() {
            if now.saturating_duration_since(*sent) < LATE_HORIZON {
                break;
            }
            self.tunnel_late.pop_front();
            self.tunnel.push(false);
        }
        for c in &mut self.candidates {
            while let Some((_, sent)) = c.outstanding.front() {
                if now.saturating_duration_since(*sent) < CANDIDATE_TIMEOUT {
                    break;
                }
                c.outstanding.pop_front();
                c.stats.record_loss();
                c.healthy_since = None;
            }
        }
    }

    fn check_failure(&mut self, now: Instant) -> Option<Action> {
        // 对端回了 cookie：路径是通的，等 WireGuard 带着 cookie 重试（第 8.4 节）
        if self.awaiting_cookie_retry(now) {
            return None;
        }
        // 加探全部丢失：最后一次加探也已超时，且期间没有任何应答
        if let Phase::Suspect { sent, since, .. } = self.phase
            && sent >= BURST_COUNT
            && self.tunnel_outstanding.is_empty()
        {
            if self.queueing(since, now) {
                // 路径通，只是在排队：所有路径都要过同一个瓶颈，切换和重新握手都无济于事（第 8.2 节）
                self.phase = Phase::Normal;
                self.tunnel.consecutive_losses = 0;
                return None;
            }
            if self.role.together() {
                // 两端一起恢复：记下这次故障，交给调用方；之后重新开始一轮检测
                self.record_failure(now);
                self.reset_tunnel(self.tunnel.rtt_ms);
                return Some(Action::Lost);
            }
            let current = &self.candidates[self.current];
            if current.kind.via_relay()
                && !self.rehandshake_tried
                && current.last_reply.is_some_and(|t| t >= since)
            {
                self.rehandshake_tried = true;
                let route = current.route;
                let rtt_ms = self.tunnel.rtt_ms;
                self.tunnel = PathStats::seeded(rtt_ms);
                self.clear_tunnel_probes();
                self.phase = Phase::Normal;
                self.high_loss_since = None;
                self.expect_handshake(now, rtt_ms);
                return Some(Action::Switch {
                    to: route,
                    rehandshake: true,
                    reason: SwitchReason::RelayLostSession,
                });
            }
            let action = self.fail_over(now, since, SwitchReason::Unreachable);
            if action.is_none() {
                // 没有刚测通的候选：保持现状，重新开始一轮疑似故障，再探测全部候选
                self.phase = Phase::Normal;
                self.tunnel.consecutive_losses = SUSPECT_AFTER_LOSSES;
            }
            return action;
        }
        // 丢包率持续过高：从开始过高时起测到的候选里选（跟随方交给决定方）
        if self.role == Role::FollowTogether || self.hold {
            return None;
        }
        // 排队时的丢包是队列满了被丢弃：换一条要过同一瓶颈的路径无济于事；没有共享瓶颈的路径往返时间
        // 短得多，按得分切过去（第 8.2 节）
        let queueing = self
            .last_late_reply
            .is_some_and(|t| now.saturating_duration_since(t) < LATE_HORIZON);
        if !queueing
            && self.tunnel.window.len() >= LOSS_WINDOW / 2
            && self.tunnel.loss_rate() > LOSS_FAILURE_RATE
        {
            let since = *self.high_loss_since.get_or_insert(now);
            if now.saturating_duration_since(since) >= LOSS_FAILURE_HOLD {
                return self.fail_over(now, since, SwitchReason::HighLoss);
            }
        } else {
            self.high_loss_since = None;
        }
        None
    }

    /// 疑似故障以来对端的包仍在到达，且 [`LATE_HORIZON`] 内收到过隧道内应答（包括迟到的）：路径通，
    /// 只是在排队。完全断开时对端的包也到不了；只有一个方向通时，最多晚这么久判为故障。
    fn queueing(&self, since: Instant, now: Instant) -> bool {
        self.last_rx.is_some_and(|t| t > since)
            && self
                .last_tunnel_reply
                .is_some_and(|t| now.saturating_duration_since(t) < LATE_HORIZON)
    }

    /// 当前路径故障：切到 `fresh_since` 之后测通、得分最好的候选；没有时返回 `None`，保持现状。
    fn fail_over(
        &mut self,
        now: Instant,
        fresh_since: Instant,
        reason: SwitchReason,
    ) -> Option<Action> {
        let current = self.current;
        let best = self
            .candidates
            .iter()
            .enumerate()
            .filter(|(i, c)| *i != current && c.last_reply.is_some_and(|t| t >= fresh_since))
            .filter_map(|(i, c)| c.stats.score(c.kind).map(|s| (i, s)))
            .min_by(|a, b| a.1.total_cmp(&b.1))
            .map(|(i, _)| i);
        let target = best?;
        self.record_failure(now);
        // 疑似故障以来没有应答的候选，之前的连续应答已经作废：否则还没超时的探测会让一条刚刚不通的
        // 更优路径看起来仍然健康，切走之后立刻又被切回
        for c in &mut self.candidates {
            if !c.last_reply.is_some_and(|t| t >= fresh_since) {
                c.stats.consecutive_successes = 0;
                c.healthy_since = None;
            }
        }
        Some(self.decide(target, reason, now))
    }

    /// 决定切到第 `target` 个候选：两端一起切换时先提议。
    fn decide(&mut self, target: usize, reason: SwitchReason, now: Instant) -> Action {
        if self.role == Role::DecideTogether {
            self.hold = true;
            return Action::Propose {
                index: target,
                reason,
            };
        }
        self.switch_to(target, reason, now)
    }

    /// 当前路径故障，记入恢复时的退避。从未连通过就失败（例如首次握手还没完成）的第一次不算故障；
    /// 再次这样失败就照常计入，避免在探测能通而 WireGuard 不通的路径上来回切。
    fn record_failure(&mut self, now: Instant) {
        let established = self.tunnel_established;
        let c = &mut self.candidates[self.current];
        c.left_at = Some(now);
        if established || c.grace_used {
            c.failures.push_back(now);
        } else {
            c.grace_used = true;
        }
        c.healthy_since = None;
    }

    /// 当前路径正常时，检查是否有更优的路径。
    fn check_improvement(&mut self, now: Instant) -> Option<Action> {
        let current_kind = self.current_kind();
        // 更优类型：连续 2 次有应答，并满足故障后的退避
        let better_type = self.candidates.iter().enumerate().find(|(i, c)| {
            *i != self.current
                && c.kind < current_kind
                && c.stats.consecutive_successes >= BETTER_TYPE_SUCCESSES
                && c.healthy_since
                    .is_some_and(|t| now.saturating_duration_since(t) >= backoff(&c.failures, now))
        });
        if let Some((i, _)) = better_type {
            return Some(self.decide(i, SwitchReason::BetterType, now));
        }
        // 同类型的更优路径：持续 30 秒才切换
        let current_score = self.tunnel.score(current_kind)?;
        let better = self
            .candidates
            .iter()
            .enumerate()
            .filter(|(i, c)| {
                *i != self.current
                    && c.kind == current_kind
                    && c.last_reply
                        .is_some_and(|t| now.saturating_duration_since(t) <= 2 * CANDIDATE_INTERVAL)
            })
            .filter_map(|(i, c)| c.stats.score(c.kind).map(|s| (i, s)))
            .filter(|(_, s)| {
                *s <= current_score * SAME_TYPE_RATIO && current_score - s >= SAME_TYPE_MIN_MS
            })
            .min_by(|a, b| a.1.total_cmp(&b.1))
            .map(|(i, _)| i);
        match (better, self.better_since) {
            (Some(i), Some((j, since))) if i == j => {
                // 当前路径丢包明显、候选连续有应答：不必等 30 秒
                let hold = if self.lossy()
                    && self.candidates[i].stats.consecutive_successes >= BETTER_TYPE_SUCCESSES
                {
                    LOSSY_HOLD
                } else {
                    SAME_TYPE_HOLD
                };
                if now.saturating_duration_since(since) >= hold {
                    return Some(self.decide(i, SwitchReason::BetterScore, now));
                }
            }
            (Some(i), _) => self.better_since = Some((i, now)),
            (None, _) => self.better_since = None,
        }
        None
    }

    fn switch_to(&mut self, target: usize, reason: SwitchReason, now: Instant) -> Action {
        let from = self.candidates[self.current].route;
        let to = self.candidates[target].route;
        let old_rtt_ms = self.tunnel.rtt_ms();
        self.current = target;
        // 新路径的丢包从头统计：候选的窗口里可能还留着它故障期间的丢包；往返时间沿用候选的测量作为起点
        self.reset_tunnel(self.candidates[target].stats.rtt_ms);
        let rehandshake = matches!(to, Route::Relay { .. }) && from != to;
        self.handshake = None;
        self.cookie_rounds = 0;
        if rehandshake {
            self.expect_handshake(now, old_rtt_ms);
        }
        Action::Switch {
            to,
            rehandshake,
            reason,
        }
    }
}

impl PeerPaths {
    fn reset_tunnel(&mut self, rtt_ms: Option<f64>) {
        self.tunnel = PathStats::seeded(rtt_ms);
        self.clear_tunnel_probes();
        self.last_tunnel_reply = None;
        self.last_late_reply = None;
        self.tunnel_established = false;
        self.best_rtt_ms = None;
        self.phase = Phase::Normal;
        self.high_loss_since = None;
        self.better_since = None;
    }

    /// 丢弃等待应答的隧道内探测：统计从头开始之后，它们的结果不再计入。
    fn clear_tunnel_probes(&mut self) {
        self.tunnel_outstanding.clear();
        self.tunnel_late.clear();
    }
}

/// 10 分钟内故障过 n 次的路径，恢复时等待：n ≤ 1 时不等待，之后 10 秒 × 2^(n-2)，最长 5 分钟。
fn backoff(failures: &VecDeque<Instant>, now: Instant) -> Duration {
    let recent = failures
        .iter()
        .filter(|t| now.saturating_duration_since(**t) < FAILURE_MEMORY)
        .count();
    if recent <= 1 {
        return Duration::ZERO;
    }
    let factor = 1u32 << (recent - 2).min(5);
    (BACKOFF_BASE * factor).min(BACKOFF_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);
    const TICK: Duration = Duration::from_millis(100);

    fn direct() -> Route {
        Route::Direct("198.51.100.2:41820".parse().expect("addr"))
    }

    fn relay(n: u8) -> Route {
        Route::Relay {
            relay: KeyId([n; 8]),
            endpoint: format!("198.51.100.{}:41900", 100 + n)
                .parse()
                .expect("addr"),
        }
    }

    /// 模拟网络：每条路径是否通、往返时间多少；按 tick 推进时间，自动应答探测。
    struct Sim {
        paths: PeerPaths,
        now: Instant,
        up: Vec<bool>,
        rtt: Vec<Duration>,
        /// 隧道内的包另外排队这么久（对端的上行被自己的流量塞满、队列很深）；隧道外的候选探测不受影响。
        queue: Vec<Duration>,
        /// 本端发出的包到不了对端，对端的包仍在到达（只有一个方向通）。
        one_way: Vec<bool>,
        /// 隧道内探测与候选探测各自每 n 个丢 1 个（0 表示不丢）。
        drop_every: Vec<u32>,
        sent: Vec<u32>,
        /// 各路径上隧道内探测与候选探测各自的计数，用于按 `drop_every` 丢包。
        sent_by_kind: Vec<[u32; 2]>,
        /// 候选探测能通，但隧道内的流量不通（例如 WireGuard 握手失败）。
        tunnel_broken: Vec<bool>,
        /// 在这条路径上重新握手后隧道恢复（中继丢了索引的情形）。
        fix_on_rehandshake: bool,
        /// 接下来这么多次重新握手没有完成（例如对端的应答被旧路径上迟到的包带去了旧中继）。
        lose_handshakes: u32,
        /// WireGuard 报告握手完成的时刻。
        handshakes: Vec<Instant>,
        /// 对端处于负载状态：每次握手先回 cookie，最后一次重新握手 5 秒之后 WireGuard 带着 cookie 重试才
        /// 完成（`None` 表示那次重试也不成）。
        under_load: Option<Duration>,
        cookies: Vec<Instant>,
        load_completion: Option<(Instant, usize)>,
        /// (送达时刻, 是否隧道内, 下标, 序号)
        inflight: Vec<(Instant, bool, usize, u32)>,
        switches: Vec<(Instant, Route, bool, SwitchReason)>,
        lost: Vec<Instant>,
        proposals: Vec<(Instant, usize, SwitchReason)>,
        candidate_probes: usize,
    }

    impl Sim {
        fn new(routes: Vec<(Route, PathKind)>) -> Self {
            Self::with_role(routes, Role::Decide)
        }

        fn with_role(routes: Vec<(Route, PathKind)>, role: Role) -> Self {
            let n = routes.len();
            Self {
                paths: PeerPaths::new(routes, role).expect("routes"),
                now: Instant::now(),
                up: vec![true; n],
                rtt: vec![2 * MS; n],
                queue: vec![Duration::ZERO; n],
                one_way: vec![false; n],
                drop_every: vec![0; n],
                sent: vec![0; n],
                sent_by_kind: vec![[0; 2]; n],
                tunnel_broken: vec![false; n],
                fix_on_rehandshake: true,
                lose_handshakes: 0,
                handshakes: Vec::new(),
                under_load: None,
                cookies: Vec::new(),
                load_completion: None,
                inflight: Vec::new(),
                switches: Vec::new(),
                lost: Vec::new(),
                proposals: Vec::new(),
                candidate_probes: 0,
            }
        }

        fn run(&mut self, d: Duration) {
            let end = self.now + d;
            while self.now < end {
                self.now += TICK;
                let now = self.now;
                let mut due: Vec<_> = self
                    .inflight
                    .iter()
                    .filter(|f| f.0 <= now)
                    .copied()
                    .collect();
                self.inflight.retain(|f| f.0 > now);
                due.sort_by_key(|f| f.0);
                for (at, tunnel, index, seq) in due {
                    if tunnel {
                        self.paths.on_tunnel_reply(seq, at);
                    } else {
                        self.paths.on_candidate_reply(index, seq, at, None);
                    }
                }
                if self.handshakes.iter().any(|t| *t <= now) {
                    self.handshakes.retain(|t| *t > now);
                    self.paths.on_handshake();
                }
                if self.cookies.iter().any(|t| *t <= now) {
                    self.cookies.retain(|t| *t > now);
                    self.paths.on_cookie(now);
                }
                if let Some((at, i)) = self.load_completion
                    && at <= now
                {
                    self.load_completion = None;
                    self.tunnel_broken[i] = false;
                    self.paths.on_handshake();
                }
                // 有流量：当前路径通时对端的包一直在到达
                let i = self.paths.current;
                if self.up[i] && !self.tunnel_broken[i] {
                    self.paths.on_receive(now);
                }
                for action in self.paths.tick(now, true) {
                    match action {
                        Action::TunnelProbe { seq } => {
                            let i = self.paths.current;
                            if !self.tunnel_broken[i] && !self.one_way[i] && self.delivers(i, true)
                            {
                                self.inflight.push((
                                    now + self.rtt[i] + self.queue[i],
                                    true,
                                    i,
                                    seq,
                                ));
                            }
                        }
                        Action::CandidateProbe { index, seq, .. } => {
                            self.candidate_probes += 1;
                            if self.delivers(index, false) {
                                self.inflight
                                    .push((now + self.rtt[index], false, index, seq));
                            }
                        }
                        Action::Switch {
                            to,
                            rehandshake,
                            reason,
                        } => {
                            self.switches.push((now, to, rehandshake, reason));
                            let i = self.paths.current;
                            if rehandshake && let Some(retry) = self.under_load {
                                // 删除再加回对端丢掉了之前的 cookie：从这一次重新算。WireGuard 每 5 秒
                                // 重试一次，重试不成时每次又换来一个 cookie
                                self.tunnel_broken[i] = true;
                                self.cookies.clear();
                                self.cookies.push(now + self.rtt[i]);
                                if retry == Duration::MAX {
                                    for k in 1..4u32 {
                                        self.cookies
                                            .push(now + Duration::from_secs(5) * k + self.rtt[i]);
                                    }
                                }
                                self.load_completion =
                                    (retry < Duration::MAX).then(|| (now + retry + self.rtt[i], i));
                            } else if rehandshake && self.lose_handshakes > 0 {
                                self.lose_handshakes -= 1;
                                self.tunnel_broken[i] = true;
                            } else if rehandshake {
                                if self.fix_on_rehandshake {
                                    self.tunnel_broken[i] = false;
                                }
                                if self.up[i] && !self.tunnel_broken[i] {
                                    self.handshakes.push(now + self.rtt[i]);
                                }
                            }
                            // 切换后，尚在途中的旧路径探测作废
                            self.inflight.retain(|f| !f.1);
                        }
                        Action::Lost => self.lost.push(now),
                        Action::Propose { index, reason } => {
                            self.proposals.push((now, index, reason));
                        }
                    }
                }
            }
        }
    }

    impl Sim {
        fn delivers(&mut self, i: usize, tunnel: bool) -> bool {
            self.sent[i] += 1;
            let n = &mut self.sent_by_kind[i][usize::from(tunnel)];
            *n += 1;
            self.up[i] && (self.drop_every[i] == 0 || !n.is_multiple_of(self.drop_every[i]))
        }
    }

    #[test]
    fn sustained_high_loss_switches() {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay(1), PathKind::Relay),
        ]);
        sim.run(Duration::from_secs(20));
        let lossy = sim.now;
        // 隔一个丢一个：不会连续丢两个，靠丢包率判定
        sim.drop_every[0] = 2;
        sim.run(Duration::from_secs(15));
        let (at, to, _, reason) = sim.switches[0];
        assert_eq!((to, reason), (relay(1), SwitchReason::HighLoss));
        // 丢包率按最近 10 次隧道内探测（每秒一次）统计：旧样本挤出窗口约 7 秒，再持续 3 秒
        let took = at.saturating_duration_since(lossy);
        assert!(took <= Duration::from_secs(12), "took {took:?}");
    }

    #[test]
    fn moderate_loss_does_not_switch() {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay(1), PathKind::Relay),
        ]);
        sim.drop_every[0] = 10;
        sim.run(Duration::from_secs(120));
        assert!(sim.switches.is_empty(), "{:?}", sim.switches);
    }

    #[test]
    fn stays_on_a_healthy_path() {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay(1), PathKind::Relay),
        ]);
        sim.run(Duration::from_secs(120));
        assert!(sim.switches.is_empty());
        assert!(sim.paths.tunnel_stats().loss_rate() < 0.01);
    }

    #[test]
    fn stays_on_a_congested_relay_path() {
        // 对端的上行被自己的流量塞满：隧道内的应答迟到 4 秒，中继本身照常应答
        let mut sim = Sim::new(vec![(relay(1), PathKind::Relay)]);
        sim.run(Duration::from_secs(20));
        sim.queue[0] = Duration::from_secs(4);
        sim.run(Duration::from_secs(120));
        assert!(sim.switches.is_empty(), "{:?}", sim.switches);
    }

    #[test]
    fn stays_on_a_congested_direct_path() {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay(1), PathKind::Relay),
        ]);
        sim.run(Duration::from_secs(20));
        sim.queue[0] = Duration::from_secs(4);
        sim.run(Duration::from_secs(120));
        assert!(sim.switches.is_empty(), "{:?}", sim.switches);
        assert!(
            sim.paths.tunnel_stats().loss_rate() < 0.01,
            "late replies are not losses"
        );
    }

    #[test]
    fn tail_drops_while_queueing_do_not_switch() {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay(1), PathKind::Relay),
        ]);
        sim.run(Duration::from_secs(20));
        // 队列满了：应答迟到 4 秒，一半被丢弃。中继也要过同一个瓶颈，换过去无济于事
        sim.queue[0] = Duration::from_secs(4);
        sim.drop_every[0] = 2;
        sim.run(Duration::from_secs(120));
        assert!(sim.switches.is_empty(), "{:?}", sim.switches);
        assert!(sim.paths.tunnel_stats().loss_rate() > LOSS_FAILURE_RATE);
    }

    #[test]
    fn fails_over_when_only_the_peers_packets_arrive() {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay(1), PathKind::Relay),
        ]);
        sim.run(Duration::from_secs(20));
        let broke = sim.now;
        sim.one_way[0] = true;
        sim.run(Duration::from_secs(20));
        let (at, to, _, reason) = sim.switches[0];
        assert_eq!((to, reason), (relay(1), SwitchReason::Unreachable));
        let took = at.saturating_duration_since(broke);
        assert!(
            took <= LATE_HORIZON + Duration::from_secs(4),
            "detection took {took:?}"
        );
    }

    #[test]
    fn fails_over_to_relay_in_about_three_seconds() {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay(1), PathKind::Relay),
        ]);
        sim.run(Duration::from_secs(20));
        let broke = sim.now;
        sim.up[0] = false;
        sim.run(Duration::from_secs(6));
        let (at, to, rehandshake, reason) = sim.switches[0];
        assert_eq!(to, relay(1));
        assert!(
            rehandshake,
            "a relay that has not seen the session needs a new handshake"
        );
        assert_eq!(reason, SwitchReason::Unreachable);
        let took = at.saturating_duration_since(broke);
        assert!(
            took <= Duration::from_millis(3600),
            "detection took {took:?}"
        );
    }

    #[test]
    fn returns_to_direct_after_two_good_probes() {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay(1), PathKind::Relay),
        ]);
        sim.run(Duration::from_secs(10));
        sim.up[0] = false;
        sim.run(Duration::from_secs(10));
        assert_eq!(sim.paths.current(), relay(1));
        // 直连恢复：第一次故障不退避；切走后的 15 秒内高频探测，第一次应答后立即再确认
        let restored = sim.now;
        sim.up[0] = true;
        sim.run(Duration::from_secs(30));
        let back = sim
            .switches
            .iter()
            .find(|s| s.1 == direct())
            .expect("switched back");
        assert_eq!(back.3, SwitchReason::BetterType);
        assert!(!back.2, "switching to direct needs no new handshake");
        let took = back.0.saturating_duration_since(restored);
        // 模拟按 100 毫秒推进，应答在下一次推进时处理
        assert!(took <= Duration::from_millis(300), "recovery took {took:?}");
    }

    #[test]
    fn returns_to_direct_within_a_second_after_a_long_outage() {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay(1), PathKind::Relay),
        ]);
        sim.run(Duration::from_secs(10));
        sim.up[0] = false;
        sim.run(Duration::from_secs(40));
        let restored = sim.now;
        sim.up[0] = true;
        sim.run(Duration::from_secs(10));
        let back = sim
            .switches
            .iter()
            .find(|s| s.1 == direct())
            .expect("switched back");
        let took = back.0.saturating_duration_since(restored);
        assert!(
            took <= Duration::from_millis(1300),
            "recovery took {took:?}"
        );
    }

    #[test]
    fn probes_fast_only_after_the_first_failure() {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay(1), PathKind::Relay),
        ]);
        sim.run(Duration::from_secs(10));
        // 第一次故障：切走后高频探测直连
        sim.up[0] = false;
        sim.run(Duration::from_secs(5));
        let before = sim.sent[0];
        sim.run(Duration::from_secs(5));
        assert!(
            sim.sent[0] - before >= 40,
            "{} probes",
            sim.sent[0] - before
        );
        sim.up[0] = true;
        sim.run(Duration::from_secs(5));
        assert_eq!(sim.paths.current(), direct());
        // 10 分钟内第二次故障：恢复要退避，不再高频探测
        sim.up[0] = false;
        sim.run(Duration::from_secs(5));
        let before = sim.sent[0];
        sim.run(Duration::from_secs(5));
        assert!(sim.sent[0] - before <= 6, "{} probes", sim.sent[0] - before);
    }

    #[test]
    fn stale_losses_do_not_follow_a_recovered_path() {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay(1), PathKind::Relay),
        ]);
        sim.run(Duration::from_secs(10));
        sim.up[0] = false;
        sim.run(Duration::from_secs(15));
        sim.up[0] = true;
        sim.run(Duration::from_secs(60));
        let reasons: Vec<_> = sim.switches.iter().map(|s| s.3).collect();
        assert_eq!(
            reasons,
            [SwitchReason::Unreachable, SwitchReason::BetterType],
            "{:?}",
            sim.switches
        );
        assert_eq!(sim.paths.current(), direct());
    }

    #[test]
    fn a_path_that_never_carries_traffic_does_not_flap_forever() {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay(1), PathKind::Relay),
        ]);
        sim.tunnel_broken[0] = true;
        sim.run(Duration::from_secs(300));
        // 第一次失败不计，之后每次回到直连前的等待按 10、20、40、80 秒加倍
        let returns: Vec<Instant> = sim
            .switches
            .iter()
            .filter(|s| s.1 == direct())
            .map(|s| s.0)
            .collect();
        let waits: Vec<Duration> = returns
            .windows(2)
            .map(|w| w[1].saturating_duration_since(w[0]))
            .collect();
        assert!(returns.len() <= 7, "{} returns in 5 minutes", returns.len());
        assert!(
            waits.windows(2).skip(1).all(|w| w[1] > w[0]),
            "waits must grow: {waits:?}"
        );
        assert!(
            waits.last().is_some_and(|w| *w >= Duration::from_secs(40)),
            "{waits:?}"
        );
    }

    #[test]
    fn rehandshakes_on_a_relay_that_lost_the_session() {
        let mut sim = Sim::new(vec![
            (relay(1), PathKind::Relay),
            (relay(2), PathKind::Relay),
        ]);
        sim.run(Duration::from_secs(10));
        // 中继 1 重启后丢了索引：探测照常应答，隧道不通，直到重新握手
        sim.tunnel_broken[0] = true;
        let lost = sim.now;
        sim.run(Duration::from_secs(6));
        let (at, to, rehandshake, reason) = sim.switches[0];
        assert_eq!(
            (to, rehandshake, reason),
            (relay(1), true, SwitchReason::RelayLostSession)
        );
        assert!(at.saturating_duration_since(lost) <= Duration::from_millis(3600));
        // 重新握手之后中继 1 又通了，留在中继 1
        sim.switches.clear();
        sim.run(Duration::from_secs(30));
        assert!(sim.switches.is_empty(), "{:?}", sim.switches);
        assert_eq!(sim.paths.current(), relay(1));
    }

    /// 换到更快的中继时，旧中继上迟到的包让对端把握手应答发去了旧中继：握手没有完成。等旧路径上的
    /// 包到完之后在新中继上再握手一次，不等 2 秒多之后的故障检测（第 8.4 节）。
    #[test]
    fn retries_a_rehandshake_that_did_not_complete() {
        let mut sim = Sim::new(vec![
            (relay(1), PathKind::Relay),
            (relay(2), PathKind::Relay),
        ]);
        sim.rtt[0] = 42 * MS;
        sim.lose_handshakes = 1;
        sim.run(Duration::from_secs(60));
        let reasons: Vec<_> = sim.switches.iter().map(|s| (s.1, s.2, s.3)).collect();
        assert_eq!(
            reasons,
            [
                (relay(2), true, SwitchReason::BetterScore),
                (relay(2), true, SwitchReason::HandshakeIncomplete)
            ]
        );
        // 旧路径的往返时间之后、下一次推进时再握手
        let waited = sim.switches[1]
            .0
            .saturating_duration_since(sim.switches[0].0);
        assert!(
            waited >= 42 * MS && waited <= 2 * TICK,
            "retried after {waited:?}"
        );
        assert!(sim.paths.tunnel_established());
        assert_eq!(sim.paths.current(), relay(2));
    }

    /// 对端处于负载状态：换到更快的中继时，握手先换来 cookie，WireGuard 5 秒后带着它重试才完成。期间
    /// 不再重新握手（会丢掉 cookie），也不按疑似故障来回切换（第 8.4 节）。
    #[test]
    fn waits_for_the_cookie_retry_when_the_peer_is_under_load() {
        let mut sim = Sim::new(vec![
            (relay(1), PathKind::Relay),
            (relay(2), PathKind::Relay),
        ]);
        sim.rtt[0] = 42 * MS;
        sim.under_load = Some(Duration::from_secs(5));
        sim.run(Duration::from_secs(60));
        let reasons: Vec<_> = sim.switches.iter().map(|s| (s.1, s.3)).collect();
        assert_eq!(reasons, [(relay(2), SwitchReason::BetterScore)]);
        assert!(sim.paths.tunnel_established());
        // 当前中继失效、另一个中继可用：同样只切一次
        sim.switches.clear();
        sim.up[1] = false;
        sim.run(Duration::from_secs(30));
        let reasons: Vec<_> = sim.switches.iter().map(|s| (s.1, s.3)).collect();
        assert_eq!(reasons, [(relay(1), SwitchReason::Unreachable)]);
        assert!(sim.paths.tunnel_established());
    }

    #[test]
    fn waits_for_at_most_two_cookie_rounds() {
        let mut sim = Sim::new(vec![
            (relay(1), PathKind::Relay),
            (relay(2), PathKind::Relay),
        ]);
        sim.rtt[0] = 42 * MS;
        // 带着 cookie 的重试也不成（例如 cookie 是伪造的）：两轮之后照常处理故障
        sim.under_load = Some(Duration::MAX);
        sim.run(Duration::from_secs(60));
        let (first, _, _, reason) = sim.switches[0];
        assert_eq!(reason, SwitchReason::BetterScore);
        let next = sim.switches.get(1).expect("failure handling resumes");
        let waited = next.0.saturating_duration_since(first);
        // 第二个 cookie 在第一轮结束前到达（WireGuard 5 秒后的重试），再等一轮；第三个不再延长
        assert!(
            waited >= Duration::from_secs(5) + COOKIE_RETRY
                && waited <= 2 * COOKIE_RETRY + Duration::from_secs(1),
            "resumed after {waited:?}: {:?}",
            sim.switches
        );
    }

    #[test]
    fn retries_an_incomplete_rehandshake_only_once() {
        let mut sim = Sim::new(vec![
            (relay(1), PathKind::Relay),
            (relay(2), PathKind::Relay),
        ]);
        sim.rtt[0] = 42 * MS;
        sim.lose_handshakes = 2;
        sim.run(Duration::from_secs(60));
        let reasons: Vec<_> = sim.switches.iter().map(|s| s.3).collect();
        // 第二次也没成：交给疑似故障的检测，它发现中继能应答而隧道不通，再在同一中继上握手
        assert_eq!(
            reasons,
            [
                SwitchReason::BetterScore,
                SwitchReason::HandshakeIncomplete,
                SwitchReason::RelayLostSession
            ]
        );
        assert!(
            sim.switches[2]
                .0
                .saturating_duration_since(sim.switches[1].0)
                >= Duration::from_secs(1)
        );
        assert_eq!(sim.paths.current(), relay(2));
    }

    #[test]
    fn a_completed_or_idle_rehandshake_is_not_repeated() {
        let routes = vec![(relay(1), PathKind::Relay), (relay(2), PathKind::Relay)];
        let now = Instant::now();
        // WireGuard 报告握手完成
        let mut paths = PeerPaths::new(routes.clone(), Role::DecideTogether).expect("routes");
        assert!(paths.adopt(1, SwitchReason::Rotation, now).is_some());
        assert!(paths.needs_fine_ticks(now));
        paths.on_handshake();
        assert!(!paths.handshake_due(now + Duration::from_secs(1)));
        let later = paths.tick(now + Duration::from_secs(1), true);
        assert!(
            !later.iter().any(|a| matches!(a, Action::Switch { .. })),
            "{later:?}"
        );
        // 没有流量：没有包触发握手，不算没完成
        let mut idle = PeerPaths::new(routes, Role::DecideTogether).expect("routes");
        assert!(idle.adopt(1, SwitchReason::Rotation, now).is_some());
        assert!(idle.handshake_due(now + Duration::from_secs(1)));
        let later = idle.tick(now + Duration::from_secs(1), false);
        assert!(
            !later.iter().any(|a| matches!(a, Action::Switch { .. })),
            "{later:?}"
        );
        assert!(!idle.needs_fine_ticks(now + Duration::from_secs(1)));
    }

    #[test]
    fn moves_on_when_rehandshaking_the_same_relay_does_not_help() {
        let mut sim = Sim::new(vec![
            (relay(1), PathKind::Relay),
            (relay(2), PathKind::Relay),
        ]);
        sim.run(Duration::from_secs(10));
        // 中继 1 到对端的那一段坏了：中继本身能应答，重新握手也无济于事
        sim.tunnel_broken[0] = true;
        sim.fix_on_rehandshake = false;
        sim.run(Duration::from_secs(10));
        let reasons: Vec<_> = sim.switches.iter().map(|s| (s.1, s.3)).collect();
        assert_eq!(
            reasons,
            [
                (relay(1), SwitchReason::RelayLostSession),
                (relay(1), SwitchReason::HandshakeIncomplete),
                (relay(2), SwitchReason::Unreachable)
            ]
        );
    }

    #[test]
    fn flapping_direct_path_waits_longer_each_time() {
        assert_eq!(backoff(&VecDeque::new(), Instant::now()), Duration::ZERO);
        let now = Instant::now() + Duration::from_secs(3600);
        let failures: VecDeque<_> = (0..3).map(|i| now - Duration::from_secs(60 * i)).collect();
        assert_eq!(backoff(&failures, now), Duration::from_secs(20));
        let once: VecDeque<_> = [now - Duration::from_secs(60)].into();
        assert_eq!(
            backoff(&once, now),
            Duration::ZERO,
            "the first failure does not delay recovery"
        );
        let many: VecDeque<_> = (0..9).map(|i| now - Duration::from_secs(30 * i)).collect();
        assert_eq!(backoff(&many, now), BACKOFF_MAX);
        let old: VecDeque<_> = [now - Duration::from_secs(700)].into();
        assert_eq!(backoff(&old, now), Duration::ZERO);
    }

    #[test]
    fn switches_between_relays_only_after_sustained_improvement() {
        let mut sim = Sim::new(vec![
            (relay(1), PathKind::Relay),
            (relay(2), PathKind::Relay),
        ]);
        sim.rtt = vec![60 * MS, 20 * MS];
        sim.run(Duration::from_secs(25));
        assert!(
            sim.switches.is_empty(),
            "must hold for 30 s first: {:?}",
            sim.switches
        );
        sim.run(Duration::from_secs(30));
        let (_, to, rehandshake, reason) = sim.switches[0];
        assert_eq!((to, reason), (relay(2), SwitchReason::BetterScore));
        assert!(rehandshake);
    }

    #[test]
    fn follows_the_faster_relay_when_latencies_alternate() {
        let mut sim = Sim::new(vec![
            (relay(1), PathKind::Relay),
            (relay(2), PathKind::Relay),
        ]);
        sim.run(Duration::from_secs(20));
        // 前半程中继 1 变慢：切到中继 2
        sim.rtt = vec![80 * MS, 2 * MS];
        let first = sim.now;
        sim.run(Duration::from_secs(60));
        let (at, to, _, _) = sim.switches[0];
        assert_eq!(to, relay(2));
        assert!(
            at.saturating_duration_since(first) <= Duration::from_secs(40),
            "{:?}",
            at.saturating_duration_since(first)
        );
        // 后半程中继 2 变慢、中继 1 恢复：一分钟内切回中继 1
        sim.rtt = vec![2 * MS, 80 * MS];
        let second = sim.now;
        sim.run(Duration::from_secs(60));
        let (at, to, _, _) = *sim.switches.last().expect("switched back");
        assert_eq!(to, relay(1));
        assert!(
            at.saturating_duration_since(second) <= Duration::from_secs(60),
            "{:?}",
            at.saturating_duration_since(second)
        );
        assert_eq!(sim.switches.len(), 2);
    }

    #[test]
    fn small_improvements_do_not_switch() {
        let mut sim = Sim::new(vec![
            (relay(1), PathKind::Relay),
            (relay(2), PathKind::Relay),
        ]);
        // 优于 15% 但不到 10 毫秒
        sim.rtt = vec![30 * MS, 22 * MS];
        sim.run(Duration::from_secs(120));
        assert!(sim.switches.is_empty());
    }

    #[test]
    fn short_outage_does_not_switch() {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay(1), PathKind::Relay),
        ]);
        sim.run(Duration::from_secs(10));
        sim.up[0] = false;
        sim.run(Duration::from_millis(900));
        sim.up[0] = true;
        sim.run(Duration::from_secs(10));
        assert!(sim.switches.is_empty(), "{:?}", sim.switches);
    }

    #[test]
    fn stays_put_when_nothing_else_answers() {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay(1), PathKind::Relay),
        ]);
        sim.run(Duration::from_secs(10));
        sim.up = vec![false, false];
        sim.run(Duration::from_secs(10));
        assert!(sim.switches.is_empty());
        // 中继先恢复：切过去
        sim.up[1] = true;
        sim.run(Duration::from_secs(5));
        assert_eq!(sim.paths.current(), relay(1));
    }

    #[test]
    fn relay_path_with_dead_far_segment_is_not_used() {
        let mut paths = PeerPaths::new(
            vec![(direct(), PathKind::Direct), (relay(1), PathKind::Relay)],
            Role::Decide,
        )
        .expect("routes");
        let now = Instant::now();
        let actions = paths.tick(now, true);
        let seq = actions
            .iter()
            .find_map(|a| match a {
                Action::CandidateProbe { index: 1, seq, .. } => Some(*seq),
                _ => None,
            })
            .expect("relay probed");
        paths.on_candidate_reply(1, seq, now + 5 * MS, Some((Duration::from_millis(5), 1.0)));
        assert_eq!(paths.candidates[1].last_reply, None);
    }

    #[test]
    fn together_roles_report_loss_instead_of_choosing() {
        for role in [Role::DecideTogether, Role::FollowTogether] {
            let mut sim = Sim::with_role(
                vec![(relay(1), PathKind::Relay), (relay(2), PathKind::Relay)],
                role,
            );
            sim.run(Duration::from_secs(5));
            sim.up[0] = false;
            let down = sim.now;
            sim.run(Duration::from_secs(5));
            assert!(sim.switches.is_empty(), "{role:?}: {:?}", sim.switches);
            let took = sim.lost[0].saturating_duration_since(down);
            assert!(took <= Duration::from_secs(4), "{role:?}: took {took:?}");
        }
    }

    #[test]
    fn follower_together_neither_probes_candidates_nor_improves() {
        let mut sim = Sim::with_role(
            vec![(relay(1), PathKind::Relay), (relay(2), PathKind::Relay)],
            Role::FollowTogether,
        );
        sim.rtt[0] = 80 * MS;
        sim.rtt[1] = 5 * MS;
        // 丢包率持续过高也交给决定方
        sim.drop_every[0] = 2;
        sim.run(Duration::from_secs(90));
        assert_eq!(sim.candidate_probes, 0);
        assert!(sim.switches.is_empty() && sim.lost.is_empty());
    }

    #[test]
    fn adopting_the_current_relay_still_rehandshakes() {
        let mut paths = PeerPaths::new(
            vec![(relay(2), PathKind::Relay), (relay(1), PathKind::Relay)],
            Role::DecideTogether,
        )
        .expect("routes");
        // 按中继编号排序，与候选列表的顺序无关
        assert_eq!(paths.relays_in_order(), vec![1, 0]);
        assert_eq!(paths.relay_index(KeyId([1; 8])), Some(1));
        assert_eq!(
            paths.adopt(0, SwitchReason::Rotation, Instant::now()),
            Some(Action::Switch {
                to: relay(2),
                rehandshake: true,
                reason: SwitchReason::Rotation,
            })
        );
        assert_eq!(paths.adopt(5, SwitchReason::Rotation, Instant::now()), None);
    }

    #[test]
    fn decider_together_proposes_instead_of_switching() {
        let mut sim = Sim::with_role(
            vec![(relay(1), PathKind::Relay), (relay(2), PathKind::Relay)],
            Role::DecideTogether,
        );
        sim.rtt[0] = 80 * MS;
        sim.rtt[1] = 5 * MS;
        sim.run(Duration::from_secs(60));
        assert!(sim.switches.is_empty());
        assert_eq!(sim.proposals.len(), 1, "{:?}", sim.proposals);
        let (_, index, reason) = sim.proposals[0];
        assert_eq!((index, reason), (1, SwitchReason::BetterScore));
        // 在确认之前不再另行提议；确认后切换，之后照常择优
        sim.run(Duration::from_secs(60));
        assert_eq!(sim.proposals.len(), 1);
        let switched = sim.paths.adopt(index, reason, sim.now);
        assert!(matches!(
            switched,
            Some(Action::Switch {
                rehandshake: true,
                ..
            })
        ));
        sim.paths.set_hold(false);
        assert_eq!(sim.paths.current(), relay(2));
    }

    #[test]
    fn leaves_a_moderately_lossy_path_quickly() {
        let mut sim = Sim::new(vec![
            (relay(1), PathKind::Relay),
            (relay(2), PathKind::Relay),
        ]);
        sim.run(Duration::from_secs(20));
        // 当前中继每 5 个包丢 1 个：低于判为故障的 30%
        sim.drop_every[0] = 5;
        let lossy = sim.now;
        sim.run(Duration::from_secs(25));
        let (at, to, _, reason) = *sim.switches.first().expect("left the lossy relay");
        assert_eq!((to, reason), (relay(2), SwitchReason::BetterScore));
        let took = at.saturating_duration_since(lossy);
        assert!(took <= Duration::from_secs(20), "took {took:?}");
        // 之后不再回到受损的中继
        sim.run(Duration::from_secs(120));
        assert_eq!(sim.switches.len(), 1, "{:?}", sim.switches);
    }

    #[test]
    fn a_single_lost_probe_does_not_switch() {
        let mut sim = Sim::new(vec![
            (relay(1), PathKind::Relay),
            (relay(2), PathKind::Relay),
        ]);
        sim.run(Duration::from_secs(20));
        sim.up[0] = false;
        sim.run(Duration::from_millis(1000));
        sim.up[0] = true;
        sim.run(Duration::from_secs(60));
        assert!(sim.switches.is_empty(), "{:?}", sim.switches);
    }

    fn relay_tls(n: u8) -> Route {
        Route::Relay {
            relay: KeyId([n; 8]),
            endpoint: format!("127.0.0.1:{}", 41830 + u16::from(n))
                .parse()
                .expect("addr"),
        }
    }

    #[test]
    fn falls_back_to_tls_and_stays_while_udp_is_blocked() {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay(1), PathKind::Relay),
            (relay_tls(1), PathKind::RelayTls),
        ]);
        sim.run(Duration::from_secs(40));
        // UDP 全部被拦：直连和 UDP 中继都不通，只剩 TLS
        sim.up[0] = false;
        sim.up[1] = false;
        sim.run(Duration::from_secs(10));
        let after: Vec<(Route, SwitchReason)> = sim.switches.iter().map(|s| (s.1, s.3)).collect();
        assert_eq!(
            after,
            vec![(relay_tls(1), SwitchReason::Unreachable)],
            "{after:?}"
        );
    }
}
