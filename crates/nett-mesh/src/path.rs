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
/// 一个候选最多同时等待应答的探测数：高频探测时，上一个探测还没超时就发下一个。
const MAX_CANDIDATE_OUTSTANDING: usize = 32;
const IDLE_CANDIDATE_INTERVAL: Duration = Duration::from_secs(300);
/// 判断当前路径"明显变慢"的往返时间最小增量（毫秒）。
const DEGRADED_MIN_MS: f64 = 10.0;
/// 更优类型的候选第一次有应答之后，确认探测的间隔。
const CONFIRM_INTERVAL: Duration = Duration::from_millis(200);
/// 候选探测等待应答的上限。
const CANDIDATE_TIMEOUT: Duration = Duration::from_secs(1);
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
    /// 双方都是 `dial-only`：跟随方按决定方经隧道发来的提议切换（第 8.4 节）。
    Proposed,
    /// 双方都是 `dial-only`、当前路径中断：按时间片（时钟不可信时按随机间隔）轮换中继（第 8.4 节）。
    Rotation,
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
    last_tunnel_probe: Option<Instant>,
    phase: Phase,
    /// 当前路径切换以来收到过隧道内应答。
    tunnel_established: bool,
    /// 切到当前路径以来隧道内往返时间的最好值（毫秒），用来判断它是否明显变慢。
    best_rtt_ms: Option<f64>,
    /// 这次故障中已经在同一中继上重新握手过一次。
    rehandshake_tried: bool,
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
            last_tunnel_probe: None,
            phase: Phase::Normal,
            tunnel_established: false,
            best_rtt_ms: None,
            rehandshake_tried: false,
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
    pub fn adopt(&mut self, index: usize, reason: SwitchReason) -> Option<Action> {
        self.candidates.get(index)?;
        let Action::Switch { to, .. } = self.switch_to(index, reason) else {
            return None;
        };
        // 立即发一个隧道内探测：它触发新的握手，也尽快确认新路径
        self.last_tunnel_probe = None;
        Some(Action::Switch {
            to,
            rehandshake: matches!(to, Route::Relay { .. }),
            reason,
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
        let Some(pos) = self.tunnel_outstanding.iter().position(|(s, _)| *s == seq) else {
            return;
        };
        let (_, sent) = self
            .tunnel_outstanding
            .remove(pos)
            .expect("position is in range");
        // 更早发出、还没有应答的探测已经被这个应答越过，算作丢失
        for _ in 0..pos {
            self.tunnel_outstanding.pop_front();
            self.tunnel.record_loss();
        }
        let rtt = now.saturating_duration_since(sent);
        self.tunnel.record_reply(rtt);
        let ms = rtt.as_secs_f64() * 1000.0;
        self.best_rtt_ms = Some(self.best_rtt_ms.map_or(ms, |b| b.min(ms)));
        self.tunnel_established = true;
        self.rehandshake_tried = false;
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

    /// 有候选在高频探测：调用方要推进得比 [`FAST_RECOVERY_INTERVAL`] 更密。
    pub fn fast_recovering(&self, now: Instant) -> bool {
        (0..self.candidates.len()).any(|i| i != self.current && self.fast_recovery(i, now))
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

    /// 超时未应答的探测记为丢失。
    fn expire(&mut self, now: Instant) {
        let timeout = self.tunnel.timeout();
        while let Some((_, sent)) = self.tunnel_outstanding.front() {
            if now.saturating_duration_since(*sent) < timeout {
                break;
            }
            self.tunnel_outstanding.pop_front();
            self.tunnel.record_loss();
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
        // 加探全部丢失：最后一次加探也已超时，且期间没有任何应答
        if let Phase::Suspect { sent, since, .. } = self.phase
            && sent >= BURST_COUNT
            && self.tunnel_outstanding.is_empty()
        {
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
                self.tunnel = PathStats::seeded(self.tunnel.rtt_ms);
                self.tunnel_outstanding.clear();
                self.phase = Phase::Normal;
                self.high_loss_since = None;
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
        if self.tunnel.window.len() >= LOSS_WINDOW / 2
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
        Some(self.decide(target, reason))
    }

    /// 决定切到第 `target` 个候选：两端一起切换时先提议。
    fn decide(&mut self, target: usize, reason: SwitchReason) -> Action {
        if self.role == Role::DecideTogether {
            self.hold = true;
            return Action::Propose {
                index: target,
                reason,
            };
        }
        self.switch_to(target, reason)
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
            return Some(self.decide(i, SwitchReason::BetterType));
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
                    return Some(self.decide(i, SwitchReason::BetterScore));
                }
            }
            (Some(i), _) => self.better_since = Some((i, now)),
            (None, _) => self.better_since = None,
        }
        None
    }

    fn switch_to(&mut self, target: usize, reason: SwitchReason) -> Action {
        let from = self.candidates[self.current].route;
        let to = self.candidates[target].route;
        self.current = target;
        // 新路径的丢包从头统计：候选的窗口里可能还留着它故障期间的丢包；往返时间沿用候选的测量作为起点
        self.reset_tunnel(self.candidates[target].stats.rtt_ms);
        Action::Switch {
            to,
            rehandshake: matches!(to, Route::Relay { .. }) && from != to,
            reason,
        }
    }
}

impl PeerPaths {
    fn reset_tunnel(&mut self, rtt_ms: Option<f64>) {
        self.tunnel = PathStats::seeded(rtt_ms);
        self.tunnel_outstanding.clear();
        self.tunnel_established = false;
        self.best_rtt_ms = None;
        self.phase = Phase::Normal;
        self.high_loss_since = None;
        self.better_since = None;
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
        /// 每 n 个探测丢 1 个（0 表示不丢）。
        drop_every: Vec<u32>,
        sent: Vec<u32>,
        /// 候选探测能通，但隧道内的流量不通（例如 WireGuard 握手失败）。
        tunnel_broken: Vec<bool>,
        /// 在这条路径上重新握手后隧道恢复（中继丢了索引的情形）。
        fix_on_rehandshake: bool,
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
                drop_every: vec![0; n],
                sent: vec![0; n],
                tunnel_broken: vec![false; n],
                fix_on_rehandshake: true,
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
                for action in self.paths.tick(now, true) {
                    match action {
                        Action::TunnelProbe { seq } => {
                            let i = self.paths.current;
                            if !self.tunnel_broken[i] && self.delivers(i) {
                                self.inflight.push((now + self.rtt[i], true, i, seq));
                            }
                        }
                        Action::CandidateProbe { index, seq, .. } => {
                            self.candidate_probes += 1;
                            if self.delivers(index) {
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
                            if rehandshake && self.fix_on_rehandshake {
                                let i = self.paths.current;
                                self.tunnel_broken[i] = false;
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
        fn delivers(&mut self, i: usize) -> bool {
            self.sent[i] += 1;
            self.up[i]
                && (self.drop_every[i] == 0 || !self.sent[i].is_multiple_of(self.drop_every[i]))
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
            paths.adopt(0, SwitchReason::Rotation),
            Some(Action::Switch {
                to: relay(2),
                rehandshake: true,
                reason: SwitchReason::Rotation,
            })
        );
        assert_eq!(paths.adopt(5, SwitchReason::Rotation), None);
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
        let switched = sim.paths.adopt(index, reason);
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
