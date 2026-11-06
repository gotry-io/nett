//! 每个对端的选路状态机（design/mesh.md 第 7、8 节，ADR 0021）。只在决定方运行（第 8.3 节）。
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
/// 候选的探测间隔：有流量时每 15 秒；当前路径不是最优类型时，更优类型每 3 秒；空闲时每 5 分钟。
const CANDIDATE_INTERVAL: Duration = Duration::from_secs(15);
const BETTER_TYPE_INTERVAL: Duration = Duration::from_secs(3);
const IDLE_CANDIDATE_INTERVAL: Duration = Duration::from_secs(300);
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
/// 路径类型偏好（毫秒），越小越优（第 8.1 节）。
const RELAY_PENALTY_MS: f64 = 10.0;

/// 路径类型，从优到劣（第 8.2 节）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    Lan,
    Direct,
    Relay,
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
        let type_penalty = if kind == PathKind::Relay {
            RELAY_PENALTY_MS
        } else {
            0.0
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
    outstanding: Option<(u32, Instant)>,
    last_probe: Option<Instant>,
    last_reply: Option<Instant>,
    /// 作为当前路径时故障的时刻，用于恢复时的退避。
    failures: VecDeque<Instant>,
    /// 最近一次连续有应答的开始时刻。
    healthy_since: Option<Instant>,
    /// 已经用过一次"从未连通过就失败不算故障"。
    grace_used: bool,
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
    candidates: Vec<Candidate>,
    current: usize,
    tunnel: PathStats,
    tunnel_outstanding: VecDeque<(u32, Instant)>,
    last_tunnel_probe: Option<Instant>,
    phase: Phase,
    /// 当前路径切换以来收到过隧道内应答。
    tunnel_established: bool,
    high_loss_since: Option<Instant>,
    better_since: Option<(usize, Instant)>,
    seq: u32,
}

impl PeerPaths {
    /// `routes` 按 Hub 给出的顺序排列；初始路径取第一条。
    pub fn new(routes: Vec<(Route, PathKind)>) -> Option<Self> {
        if routes.is_empty() {
            return None;
        }
        Some(Self {
            candidates: routes
                .into_iter()
                .map(|(route, kind)| Candidate {
                    route,
                    kind,
                    stats: PathStats::default(),
                    outstanding: None,
                    last_probe: None,
                    last_reply: None,
                    failures: VecDeque::new(),
                    healthy_since: None,
                    grace_used: false,
                })
                .collect(),
            current: 0,
            tunnel: PathStats::default(),
            tunnel_outstanding: VecDeque::new(),
            last_tunnel_probe: None,
            phase: Phase::Normal,
            tunnel_established: false,
            high_loss_since: None,
            better_since: None,
            seq: 0,
        })
    }

    pub fn current(&self) -> Route {
        self.candidates[self.current].route
    }

    pub fn current_kind(&self) -> PathKind {
        self.candidates[self.current].kind
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
        self.tunnel
            .record_reply(now.saturating_duration_since(sent));
        self.tunnel_established = true;
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
        let Some((expected, sent)) = c.outstanding else {
            return;
        };
        if expected != seq {
            return;
        }
        c.outstanding = None;
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
                    for index in 0..self.candidates.len() {
                        if index != self.current {
                            actions.extend(self.probe_candidate(index, now));
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
                // 丢包率刚开始过高时，同疑似故障一样立即探测全部候选
                let lossy = self.high_loss_since == Some(now);
                for index in 0..self.candidates.len() {
                    if index != self.current && (lossy || self.candidate_due(index, now, active)) {
                        actions.extend(self.probe_candidate(index, now));
                    }
                }
                if let Some(action) = self.check_improvement(now) {
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

    fn probe_candidate(&mut self, index: usize, now: Instant) -> Option<Action> {
        let seq = self.next_seq();
        let c = &mut self.candidates[index];
        if c.outstanding.is_some() {
            return None;
        }
        c.outstanding = Some((seq, now));
        c.last_probe = Some(now);
        Some(Action::CandidateProbe {
            index,
            route: c.route,
            seq,
        })
    }

    fn candidate_due(&self, index: usize, now: Instant, active: bool) -> bool {
        let c = &self.candidates[index];
        let better = c.kind < self.current_kind();
        let interval = if !active {
            IDLE_CANDIDATE_INTERVAL
        } else if better && c.stats.consecutive_successes == 1 {
            // 更优类型的候选刚有一次应答：立即再探测一次确认，不等下一个 5 秒
            CONFIRM_INTERVAL
        } else if better {
            BETTER_TYPE_INTERVAL
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
            if let Some((_, sent)) = c.outstanding
                && now.saturating_duration_since(sent) >= CANDIDATE_TIMEOUT
            {
                c.outstanding = None;
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
            let action = self.fail_over(now, since, SwitchReason::Unreachable);
            if action.is_none() {
                // 没有刚测通的候选：保持现状，重新开始一轮疑似故障，再探测全部候选
                self.phase = Phase::Normal;
                self.tunnel.consecutive_losses = SUSPECT_AFTER_LOSSES;
            }
            return action;
        }
        // 丢包率持续过高：从开始过高时起测到的候选里选
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
        let c = &mut self.candidates[current];
        // 从未连通过就失败（例如首次握手还没完成）的第一次不算故障，不参与恢复时的退避；
        // 再次这样失败就照常计入，避免在探测能通而 WireGuard 不通的路径上来回切
        if self.tunnel_established || c.grace_used {
            c.failures.push_back(now);
        } else {
            c.grace_used = true;
        }
        c.healthy_since = None;
        Some(self.switch_to(target, reason))
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
            return Some(self.switch_to(i, SwitchReason::BetterType));
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
                if now.saturating_duration_since(since) >= SAME_TYPE_HOLD {
                    return Some(self.switch_to(i, SwitchReason::BetterScore));
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
        self.tunnel = PathStats::seeded(self.candidates[target].stats.rtt_ms);
        self.tunnel_outstanding.clear();
        self.tunnel_established = false;
        self.phase = Phase::Normal;
        self.high_loss_since = None;
        self.better_since = None;
        Action::Switch {
            to,
            rehandshake: matches!(to, Route::Relay { .. }) && from != to,
            reason,
        }
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
        /// (送达时刻, 是否隧道内, 下标, 序号)
        inflight: Vec<(Instant, bool, usize, u32)>,
        switches: Vec<(Instant, Route, bool, SwitchReason)>,
    }

    impl Sim {
        fn new(routes: Vec<(Route, PathKind)>) -> Self {
            let n = routes.len();
            Self {
                paths: PeerPaths::new(routes).expect("routes"),
                now: Instant::now(),
                up: vec![true; n],
                rtt: vec![2 * MS; n],
                drop_every: vec![0; n],
                sent: vec![0; n],
                tunnel_broken: vec![false; n],
                inflight: Vec::new(),
                switches: Vec::new(),
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
                            // 切换后，尚在途中的旧路径探测作废
                            self.inflight.retain(|f| !f.1);
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
        // 直连恢复：第一次故障不退避；更优类型每 3 秒探测，第一次应答后 200 毫秒再确认
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
        assert!(
            took <= Duration::from_millis(3600),
            "recovery took {took:?}"
        );
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
        let mut paths = PeerPaths::new(vec![
            (direct(), PathKind::Direct),
            (relay(1), PathKind::Relay),
        ])
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
}
