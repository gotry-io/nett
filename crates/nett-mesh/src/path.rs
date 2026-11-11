//! Per-peer path selection state machine (design/mesh.md sections 7 and 8, ADR 0021). Runs on the decider
//! (section 8.3); when both sides are `dial-only` the follower runs it too, only detecting outages
//! (section 8.4).
//!
//! Pure logic: the caller passes in the time, and sending probes and switching the endpoint are handed to
//! the caller as [`Action`]s, so tests can simulate time precisely.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::probe::KeyId;

/// Interval of in-tunnel probes when there is traffic.
pub const TUNNEL_INTERVAL: Duration = Duration::from_secs(1);
/// After this many consecutive in-tunnel probes without a reply, enter suspected failure.
const SUSPECT_AFTER_LOSSES: u32 = 2;
/// Number and interval of extra probes on the current path during suspected failure.
const BURST_COUNT: u32 = 3;
const BURST_SPACING: Duration = Duration::from_millis(200);
/// A loss rate above this ratio that lasts [`LOSS_FAILURE_HOLD`] is also judged a failure.
const LOSS_FAILURE_RATE: f64 = 0.30;
const LOSS_FAILURE_HOLD: Duration = Duration::from_secs(3);
/// A candidate of a better type that replies this many consecutive times is switched to.
const BETTER_TYPE_SUCCESSES: u32 = 2;
/// Wait time when a path that has failed recovers: from the second failure within 10 minutes, starts at
/// 10 seconds and doubles with the number of failures, up to 5 minutes; recovery after the first
/// failure does not wait (ADR 0021).
const BACKOFF_BASE: Duration = Duration::from_secs(10);
const BACKOFF_MAX: Duration = Duration::from_secs(300);
const FAILURE_MEMORY: Duration = Duration::from_secs(600);
/// A better path of the same type: score better than the current one by at least 15% and at least 10 ms,
/// sustained for 30 seconds.
const SAME_TYPE_RATIO: f64 = 0.85;
const SAME_TYPE_MIN_MS: f64 = 10.0;
const SAME_TYPE_HOLD: Duration = Duration::from_secs(30);
/// When the current path has noticeable loss (at least this many of the last [`LOSS_WINDOW`] in-tunnel
/// probes were lost) and the candidate replies consecutively, a better path of the same type only needs
/// to be sustained for [`LOSSY_HOLD`] (ADR 0021).
const LOSSY_LOSSES: usize = 2;
const LOSSY_HOLD: Duration = Duration::from_secs(5);
/// Probe interval of candidates: every 15 seconds when there is traffic; when the current path is not of
/// the best type, every 1 second for better types; when the current path has clearly degraded, every 3
/// seconds for candidates of the same type; every 5 minutes when idle.
const CANDIDATE_INTERVAL: Duration = Duration::from_secs(15);
const BETTER_TYPE_INTERVAL: Duration = Duration::from_secs(1);
const DEGRADED_INTERVAL: Duration = Duration::from_secs(3);
/// A candidate that has never replied is probed every 1 second, like a better type, for this long after
/// its first probe: at startup the peer may not be up yet, and there is no need to wait 15 seconds to
/// learn whether it can connect and what this machine's mapped address is (design/mesh.md sections 6.1
/// and 7).
const DISCOVERY_WINDOW: Duration = Duration::from_secs(60);
/// Right after switching away from a better-type path because of a first failure, probe it once every
/// [`FAST_RECOVERY_INTERVAL`] for this long, so that it switches back quickly after recovery (ADR 0021).
const FAST_RECOVERY_WINDOW: Duration = Duration::from_secs(15);
pub const FAST_RECOVERY_INTERVAL: Duration = Duration::from_millis(50);
/// Waiting for a re-handshake to complete: the larger of the old path's round-trip time and twice the
/// new path's round-trip time, plus this margin, at most 1 second (section 8.4); when the new path has
/// not been measured yet, this round-trip time is used as the estimate.
const HANDSHAKE_MARGIN: Duration = Duration::from_millis(20);
const HANDSHAKE_WAIT_MAX: Duration = Duration::from_secs(1);
const HANDSHAKE_UNKNOWN_RTT_MS: f64 = 150.0;
/// How long WireGuard takes to retry with the cookie after receiving a cookie reply: `REKEY_TIMEOUT` of 5
/// seconds, plus up to 1/3 second of jitter. During this time no re-handshake is made and no switch
/// away for suspected failure; after switching to a path, wait at most this many rounds (section 8.4).
const COOKIE_RETRY: Duration = Duration::from_millis(5_400);
const COOKIE_ROUNDS: u32 = 2;
/// The maximum number of probes of one candidate awaiting replies at the same time: during high-frequency
/// probing the next probe is sent before the previous one times out.
const MAX_CANDIDATE_OUTSTANDING: usize = 32;
const IDLE_CANDIDATE_INTERVAL: Duration = Duration::from_secs(300);
/// Minimum increase in round-trip time (milliseconds) for judging the current path "clearly slower".
const DEGRADED_MIN_MS: f64 = 10.0;
/// Interval of confirmation probes after a better-type candidate replies for the first time.
const CONFIRM_INTERVAL: Duration = Duration::from_millis(200);
/// Upper limit on how long a candidate probe waits for a reply.
const CANDIDATE_TIMEOUT: Duration = Duration::from_secs(1);
/// An in-tunnel probe that timed out waits this long again: a late reply means the path works and is only
/// queueing, and is counted in the round-trip time as usual; if the peer's packets are still arriving
/// but there has been no reply at all for this long (only one direction works), it is judged a failure
/// as usual (design/mesh.md sections 7 and 8.2).
pub const LATE_HORIZON: Duration = Duration::from_secs(10);
/// Upper limit on in-tunnel probes waiting for late replies at the same time: one per second plus extra
/// probes, fewer than 20 within 10 seconds.
const MAX_LATE: usize = 32;
/// Sliding window of the loss rate (number of probes).
const LOSS_WINDOW: usize = 10;
/// Weight of the exponential moving average of the round-trip time.
const RTT_ALPHA: f64 = 0.25;
/// Loss penalty in the score: every 1% of loss is equivalent to 5 ms.
const LOSS_PENALTY_MS: f64 = 500.0;
/// Path type preference and transport penalty (milliseconds), smaller is better (section 8.1): TLS adds
/// another 20 ms on top of the relay preference.
const RELAY_PENALTY_MS: f64 = 10.0;
const TLS_PENALTY_MS: f64 = 20.0;

/// Path types, from best to worst (section 8.2): on the same path UDP is better than TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    Lan,
    Direct,
    Relay,
    /// TLS transport via a relay (design/mesh.md section 5.3).
    RelayTls,
}

impl PathKind {
    pub fn via_relay(self) -> bool {
        matches!(self, PathKind::Relay | PathKind::RelayTls)
    }
}

/// The endpoint in WireGuard that corresponds to a path.
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

/// Round-trip time, loss rate and jitter.
#[derive(Debug, Clone, Default)]
pub struct PathStats {
    rtt_ms: Option<f64>,
    jitter_ms: f64,
    window: VecDeque<bool>,
    consecutive_losses: u32,
    consecutive_successes: u32,
}

impl PathStats {
    /// New statistics that carry only a round-trip time estimate.
    fn seeded(rtt_ms: Option<f64>) -> Self {
        Self {
            rtt_ms,
            ..Self::default()
        }
    }

    pub fn record_reply(&mut self, rtt: Duration) {
        let ms = rtt.as_secs_f64() * 1000.0;
        self.rtt_ms = Some(match self.rtt_ms {
            // Differs from the average by more than a factor of two: the path has changed, so adopt the new value
            // directly instead of waiting for the average to catch up slowly
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

    /// Timed out without a reply: counted into consecutive losses (used to enter suspected failure); the
    /// loss rate counts it only once the loss is certain (design/mesh.md section 7).
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

    /// `None` when no probe has produced a result yet.
    pub fn measured_loss(&self) -> Option<f64> {
        (!self.window.is_empty()).then(|| self.loss_rate())
    }

    /// Score (milliseconds, smaller is better): round-trip time + loss penalty + jitter + path type
    /// preference (section 8.1).
    pub fn score(&self, kind: PathKind) -> Option<f64> {
        let type_penalty = match kind {
            PathKind::Lan | PathKind::Direct => 0.0,
            PathKind::Relay => RELAY_PENALTY_MS,
            PathKind::RelayTls => RELAY_PENALTY_MS + TLS_PENALTY_MS,
        };
        self.rtt_ms
            .map(|rtt| rtt + self.loss_rate() * LOSS_PENALTY_MS + self.jitter_ms + type_penalty)
    }

    /// Upper limit of waiting for a reply: twice the round-trip time plus 100 ms, limited to between 300 ms
    /// and 1 second.
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
    /// Probes awaiting replies, in the order they were sent.
    outstanding: VecDeque<(u32, Instant)>,
    last_probe: Option<Instant>,
    last_reply: Option<Instant>,
    /// The moment of failure while this was the current path, used for recovery backoff.
    failures: VecDeque<Instant>,
    /// The moment this was most recently switched away from after failing as the current path (whether or
    /// not it counted toward backoff).
    left_at: Option<Instant>,
    /// The moment of the first probe.
    first_probe: Option<Instant>,
    /// The moment the most recent run of consecutive replies began.
    healthy_since: Option<Instant>,
    /// The "failure without ever having connected does not count as a failure" allowance has already been
    /// used once.
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

/// Reason for a switch, written into the path switch event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwitchReason {
    /// All extra probes were lost after suspected failure.
    Unreachable,
    /// The loss rate stayed too high.
    HighLoss,
    /// A path of a better type recovered.
    BetterType,
    /// A better path of the same type.
    BetterScore,
    /// The current relay still replies to probes but the tunnel is down: it lost the index of this connection,
    /// so re-handshake on the same relay (section 8.4).
    RelayLostSession,
    /// The handshake still has not completed when due after a re-handshake (for example the peer's reply was
    /// carried to the old relay by a late packet on the old path): re-handshake once more on the same
    /// relay (section 8.4).
    HandshakeIncomplete,
    /// Both sides are `dial-only`: the follower switches according to the proposal the decider sent through
    /// the tunnel (section 8.4).
    Proposed,
    /// Both sides are `dial-only` and the current path is broken: relays are rotated by time slice (by random
    /// interval when the clock is not trusted) (section 8.4).
    Rotation,
}

/// How a candidate path appears in local status (design/status.md section 6).
#[derive(Debug, Clone, PartialEq)]
pub struct CandidateView {
    pub route: Route,
    pub kind: PathKind,
    pub rtt_ms: Option<f64>,
    pub loss: Option<f64>,
    pub state: CandidateState,
    /// A direct path established by hole punching (design/mesh.md section 6.1).
    pub punched: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateState {
    Current,
    /// The most recent probe was answered.
    Ok,
    /// The most recent probe was lost, or it is still in backoff after a failure.
    Failing,
    /// No probe result yet.
    Untested,
}

/// The role of this side in this pair of members (sections 8.3 and 8.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The decider; the peer follows through roaming.
    Decide,
    /// The decider when both sides are `dial-only`: a switch chosen for being better is first proposed
    /// through the tunnel ([`Action::Propose`]); on an outage it reports
    /// [`Action::Lost`].
    DecideTogether,
    /// The follower when both sides are `dial-only`: only detects outages, does not choose a better path or
    /// probe candidates.
    FollowTogether,
}

impl Role {
    pub fn together(self) -> bool {
        self != Role::Decide
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Sends an in-tunnel probe through the current tunnel.
    TunnelProbe { seq: u32 },
    /// Probes a candidate (direct: from the WireGuard port; relay: sent to the relay).
    CandidateProbe {
        index: usize,
        route: Route,
        seq: u32,
    },
    /// Changes the peer's endpoint to `to`; when switching to a relay, the peer is deleted and added back,
    /// triggering a handshake through the new relay (section 8.4).
    Switch {
        to: Route,
        rehandshake: bool,
        reason: SwitchReason,
    },
    /// The decider when both sides are `dial-only`: switch to candidate `index`; first proposed through the
    /// tunnel, and after the peer confirms the caller calls
    /// [`PeerPaths::adopt`] (section 8.4). No other better-path selection happens before that.
    Propose { index: usize, reason: SwitchReason },
    /// Both sides are `dial-only`: the current path is broken and both ends must recover together (section
    /// 8.4); the caller decides where to go.
    Lost,
}

/// Waiting for a re-handshake to complete (section 8.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HandshakeCheck {
    deadline: Instant,
    /// Has already re-handshaked once because it did not complete.
    retried: bool,
    /// The peer replied with a cookie reply; waiting for WireGuard to retry with it.
    cookie: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Normal,
    /// Suspected failure: the number of extra probes already sent, the time of the next extra probe, and the
    /// start time.
    Suspect {
        sent: u32,
        next: Instant,
        since: Instant,
    },
}

/// Path selection state of one peer.
#[derive(Debug, Clone)]
pub struct PeerPaths {
    role: Role,
    candidates: Vec<Candidate>,
    current: usize,
    tunnel: PathStats,
    tunnel_outstanding: VecDeque<(u32, Instant)>,
    /// In-tunnel probes that have timed out and are still waiting for late replies ([`LATE_HORIZON`]).
    tunnel_late: VecDeque<(u32, Instant)>,
    /// The most recent in-tunnel reply received on the current path (including late ones).
    last_tunnel_reply: Option<Instant>,
    /// The most recent late in-tunnel reply received on the current path: it is queueing.
    last_late_reply: Option<Instant>,
    /// The most recent time a packet from the peer was seen arriving (WireGuard's received byte count for it
    /// changed).
    last_rx: Option<Instant>,
    last_tunnel_probe: Option<Instant>,
    phase: Phase,
    /// An in-tunnel reply has been received since switching to the current path.
    tunnel_established: bool,
    /// The best in-tunnel round-trip time (milliseconds) since switching to the current path, used to judge
    /// whether it has become clearly slower.
    best_rtt_ms: Option<f64>,
    /// A re-handshake on the same relay has already been made during this failure.
    rehandshake_tried: bool,
    /// After a re-handshake, waiting to confirm that it completes.
    handshake: Option<HandshakeCheck>,
    /// The number of rounds waited because of a cookie reply since switching to the current path.
    cookie_rounds: u32,
    high_loss_since: Option<Instant>,
    better_since: Option<(usize, Instant)>,
    /// During a two-ended switchover (waiting for confirmation, rotating): only detects outages, does not
    /// choose a better path separately.
    hold: bool,
    /// The direct candidate established by hole punching (design/mesh.md section 6.1), ordered after the
    /// configured candidates.
    punched: Option<usize>,
    seq: u32,
}

impl PeerPaths {
    /// `routes` is ordered as given by the Hub; the initial path is the first one.
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
            // During a two-ended switchover, both ends start from the same relay
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

    /// An in-tunnel reply has been received since switching to the current path: a probe sent by this end got
    /// a reply from the peer, so both directions work.
    pub fn tunnel_established(&self) -> bool {
        self.tunnel_established
    }

    /// A direct path established by hole punching: added as a direct candidate (when one already exists it is
    /// replaced with the new address and measurement starts over), returns its index.
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

    /// Measurements and state of each candidate path, including the current one (design/status.md section 6).
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

    /// Candidates via relay `relay`.
    pub fn relay_index(&self, relay: KeyId) -> Option<usize> {
        self.candidates
            .iter()
            .position(|c| matches!(c.route, Route::Relay { relay: r, .. } if r == relay))
    }

    /// Candidates via relays are sorted by relay number: the two ends' candidate lists may be in different
    /// orders, and after sorting they are the same (section 8.4).
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

    /// A switch decided by the caller (during a two-ended switchover): switch to candidate `index`; via a
    /// relay it always re-handshakes, even if it is still the current relay, so that both ends initiate a
    /// new handshake on it.
    pub fn adopt(&mut self, index: usize, reason: SwitchReason, now: Instant) -> Option<Action> {
        self.candidates.get(index)?;
        let old_rtt_ms = self.tunnel.rtt_ms();
        let Action::Switch { to, .. } = self.switch_to(index, reason, now) else {
            return None;
        };
        // Send an in-tunnel probe immediately: it triggers a new handshake and also confirms the new path as
        // soon as possible
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

    /// WireGuard reports that this peer completed a handshake after the re-handshake (the caller reports it
    /// on every status read, and it only takes effect while waiting for confirmation). In-tunnel probes are
    /// bound to be lost during the wait and do not count as a failure of this path: detection starts over,
    /// and one probe is sent immediately to confirm the new path.
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

    /// WireGuard's received byte count for this peer changed: a packet from the peer arrived (the caller
    /// reports it on every status read).
    pub fn on_receive(&mut self, now: Instant) {
        self.last_rx = Some(now);
    }

    /// A cookie reply from the peer was received on the current path while the tunnel is not yet established:
    /// the peer is under load, and WireGuard will retry with the cookie after about 5 seconds. A
    /// re-handshake would discard the cookie, so wait for this retry, and during that time do not switch
    /// away for suspected failure (section 8.4).
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

    /// Waiting for WireGuard to retry with the cookie.
    fn awaiting_cookie_retry(&self, now: Instant) -> bool {
        self.handshake.is_some_and(|h| h.cookie && now < h.deadline)
    }

    /// The deadline for waiting for confirmation after a re-handshake has arrived: the caller first reads
    /// WireGuard's handshake state ([`Self::on_handshake`]), then advances.
    pub fn handshake_due(&self, now: Instant) -> bool {
        self.handshake.is_some_and(|h| now >= h.deadline)
    }

    /// Just re-handshaked (`old_rtt_ms` is the round-trip time of the path before the switch): confirm once
    /// packets on the old path have all arrived and the new path has completed one handshake round trip
    /// (section 8.4).
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

    /// The re-handshake is due and has not completed: when this peer has traffic, re-handshake once more on
    /// the same relay, by which time the packets on the old path have all arrived; if that still does not
    /// work, leave it to suspected failure detection (section 8.4).
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

    /// Pauses better-path selection during a two-ended switchover (paused automatically after
    /// [`Action::Propose`]).
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
        // Probes sent earlier that have no reply yet (including those still waited for after timing out) have
        // been overtaken by this reply and count as lost
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
            // A late reply: the path works and is only queueing (design/mesh.md section 7)
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
        // An in-tunnel reply means the handshake has completed
        self.handshake = None;
        self.cookie_rounds = 0;
        self.phase = Phase::Normal;
    }

    /// Result of a candidate probe; `extra` is the round-trip time and loss rate of the other leg of a relay
    /// path (carried by the peer in the in-tunnel reply).
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
        // Probes sent earlier that have no reply yet have been overtaken by this reply and count as lost; they
        // will not later time out and interrupt the run of consecutive replies
        for _ in 0..pos {
            c.outstanding.pop_front();
            c.stats.record_loss();
        }
        let (_, sent) = c.outstanding.pop_front().expect("position is in range");
        let (extra_rtt, extra_loss) = extra.unwrap_or((Duration::ZERO, 0.0));
        if extra_loss >= 1.0 {
            // The other leg is down: the relay path as a whole is down
            c.stats.record_loss();
            c.healthy_since = None;
            return;
        }
        c.stats
            .record_reply(now.saturating_duration_since(sent) + extra_rtt);
        c.last_reply = Some(now);
        c.healthy_since.get_or_insert(now);
    }

    /// Called about every 100 ms. `active` means this peer has had traffic in the last 30 seconds.
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
                    // Suspected failure: send extra probes immediately and probe all candidates at the same time
                    let seq = self.send_tunnel(now);
                    actions.push(Action::TunnelProbe { seq });
                    self.phase = Phase::Suspect {
                        sent: 1,
                        next: now + BURST_SPACING,
                        since: now,
                    };
                    // When the current path is via a relay, also probe that relay: if it can still reply, it lost the index
                    // of this connection
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
                // When the loss rate has just become too high, probe all candidates immediately, as with suspected
                // failure
                let lossy = self.high_loss_since == Some(now);
                for index in 0..self.candidates.len() {
                    if index != self.current && (lossy || self.candidate_due(index, now, active)) {
                        let stack = self.fast_recovery(index, now);
                        actions.extend(self.probe_candidate(index, now, stack));
                    }
                }
                // When the current path is direct, also probe it from the WireGuard port: the reply carries back this
                // machine's mapped address (design/mesh.md section 6.1)
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

    /// `stack`: also send when the previous probe is still waiting for a reply (high-frequency probing).
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

    /// The current path has clearly degraded: the round-trip time has doubled relative to the best value
    /// since switching to it and is at least 10 ms more, or the loss is noticeable
    /// (design/mesh.md section 7).
    fn degraded(&self) -> bool {
        let slower = match (self.tunnel.rtt_ms(), self.best_rtt_ms) {
            (Some(rtt), Some(best)) => rtt >= 2.0 * best && rtt >= best + DEGRADED_MIN_MS,
            _ => false,
        };
        slower || self.lossy()
    }

    /// At least 2 of the last 10 in-tunnel probes were lost: below the loss rate judged a failure, but
    /// already noticeable (ADR 0021).
    fn lossy(&self) -> bool {
        self.tunnel.window.iter().filter(|ok| !**ok).count() >= LOSSY_LOSSES
    }

    /// Just switched away from this better-type path because of a first failure, and still within the
    /// high-frequency probing time (ADR 0021).
    fn fast_recovery(&self, index: usize, now: Instant) -> bool {
        let c = &self.candidates[index];
        c.kind < self.current_kind()
            && c.left_at
                .is_some_and(|t| now.saturating_duration_since(t) < FAST_RECOVERY_WINDOW)
            && backoff(&c.failures, now).is_zero()
    }

    /// A candidate is being probed at high frequency, or waiting for a re-handshake to complete (the few
    /// seconds of waiting for the cookie retry do not count): the caller must advance more densely than
    /// [`FAST_RECOVERY_INTERVAL`].
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
            // Confirm immediately after the first reply: the reply is later than the most recent probe, which means
            // the confirmation has not been sent yet
            if first_reply && c.last_reply >= c.last_probe {
                Duration::ZERO
            } else {
                FAST_RECOVERY_INTERVAL
            }
        } else if better && first_reply {
            // A better-type candidate just got a reply: probe once more soon to confirm, without waiting for the
            // next interval
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

    /// A candidate probe that timed out without a reply is recorded as lost. An in-tunnel probe timeout only
    /// counts toward consecutive losses (used to enter suspected failure), and is recorded as lost only if
    /// there is still no reply after another [`LATE_HORIZON`] (design/mesh.md section 7).
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
        // The peer replied with a cookie: the path works; wait for WireGuard to retry with the cookie
        // (section 8.4)
        if self.awaiting_cookie_retry(now) {
            return None;
        }
        // All extra probes were lost: the last extra probe has also timed out, and there was no reply at all
        // during that time
        if let Phase::Suspect { sent, since, .. } = self.phase
            && sent >= BURST_COUNT
            && self.tunnel_outstanding.is_empty()
        {
            if self.queueing(since, now) {
                // The path works and is only queueing: all paths pass through the same bottleneck, so neither
                // switching nor re-handshaking helps (section 8.2)
                self.phase = Phase::Normal;
                self.tunnel.consecutive_losses = 0;
                return None;
            }
            if self.role.together() {
                // Recover together at both ends: record this failure and hand it to the caller; afterwards start a new
                // round of detection
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
                // No candidate has just been confirmed working: keep the current state, start a new round of suspected
                // failure, and probe all candidates again
                self.phase = Phase::Normal;
                self.tunnel.consecutive_losses = SUSPECT_AFTER_LOSSES;
            }
            return action;
        }
        // The loss rate stayed too high: choose from the candidates measured since it began to be too high (the
        // follower hands it to the decider)
        if self.role == Role::FollowTogether || self.hold {
            return None;
        }
        // Loss while queueing is the queue being full and dropping: switching to a path that passes through the
        // same bottleneck does not help; a path without a shared bottleneck has a much shorter round-trip
        // time, and is switched to by score (section 8.2)
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

    /// Since suspected failure the peer's packets are still arriving, and an in-tunnel reply (including late
    /// ones) was received within [`LATE_HORIZON`]: the path works and is only queueing. When completely
    /// down, the peer's packets cannot arrive either; when only one direction works, it is judged a failure
    /// at most this much later.
    fn queueing(&self, since: Instant, now: Instant) -> bool {
        self.last_rx.is_some_and(|t| t > since)
            && self
                .last_tunnel_reply
                .is_some_and(|t| now.saturating_duration_since(t) < LATE_HORIZON)
    }

    /// The current path failed: switch to the candidate that has been confirmed working since `fresh_since`
    /// and has the best score; when there is none, returns `None` and keeps the current state.
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
        // A candidate with no reply since suspected failure has its earlier run of consecutive replies voided:
        // otherwise probes that have not yet timed out would make a better path that has just gone down look
        // still healthy, and after switching away it would immediately be switched back
        for c in &mut self.candidates {
            if !c.last_reply.is_some_and(|t| t >= fresh_since) {
                c.stats.consecutive_successes = 0;
                c.healthy_since = None;
            }
        }
        Some(self.decide(target, reason, now))
    }

    /// Decides to switch to candidate `target`: for a two-ended switchover, propose first.
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

    /// The current path failed; record it in the recovery backoff. A first failure without ever having
    /// connected (for example the first handshake has not completed) does not count as a failure; a repeat
    /// of such a failure is counted as usual, to avoid switching back and forth on a path where probes get
    /// through but WireGuard does not.
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

    /// When the current path is healthy, checks whether there is a better path.
    fn check_improvement(&mut self, now: Instant) -> Option<Action> {
        let current_kind = self.current_kind();
        // Better type: 2 consecutive replies, and the backoff after failure is satisfied
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
        // A better path of the same type: switch only after it holds for 30 seconds
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
                // The current path has noticeable loss and the candidate replies consecutively: no need to wait 30
                // seconds
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
        // The new path's loss is counted from scratch: the candidate's window may still hold the loss from
        // during its failure; the round-trip time carries over from the candidate's measurement as the
        // starting point
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

    /// Drops in-tunnel probes awaiting replies: after statistics start over, their results are no longer
    /// counted.
    fn clear_tunnel_probes(&mut self) {
        self.tunnel_outstanding.clear();
        self.tunnel_late.clear();
    }
}

/// For a path that failed n times within 10 minutes, the wait on recovery: no wait when n <= 1, after that
/// 10 seconds x 2^(n-2), at most 5 minutes.
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

    /// Simulated network: whether each path works and its round-trip time; time advances by tick and probes
    /// are answered automatically.
    struct Sim {
        paths: PeerPaths,
        now: Instant,
        up: Vec<bool>,
        rtt: Vec<Duration>,
        /// In-tunnel packets are additionally queued for this long (the peer's uplink is filled by its own
        /// traffic, so the queue is deep); candidate probes outside the tunnel are not affected.
        queue: Vec<Duration>,
        /// Packets sent by this end cannot reach the peer, while the peer's packets still arrive (only one
        /// direction works).
        one_way: Vec<bool>,
        /// In-tunnel probes and candidate probes each drop 1 in every n (0 means no drops).
        drop_every: Vec<u32>,
        sent: Vec<u32>,
        /// Counts of in-tunnel probes and candidate probes on each path, used to drop packets per `drop_every`.
        sent_by_kind: Vec<[u32; 2]>,
        /// Candidate probes get through but in-tunnel traffic does not (for example the WireGuard handshake
        /// fails).
        tunnel_broken: Vec<bool>,
        /// The tunnel recovers after a re-handshake on this path (the case where the relay lost the index).
        fix_on_rehandshake: bool,
        /// For the next this-many re-handshakes, none completes (for example the peer's reply was carried to the
        /// old relay by a late packet on the old path).
        lose_handshakes: u32,
        /// The moment WireGuard reports the handshake as complete.
        handshakes: Vec<Instant>,
        /// The peer is under load: every handshake first gets a cookie, and only the retry WireGuard makes with
        /// the cookie 5 seconds after the last re-handshake completes (`None` means that retry does not
        /// succeed either).
        under_load: Option<Duration>,
        cookies: Vec<Instant>,
        load_completion: Option<(Instant, usize)>,
        /// (delivery time, whether in-tunnel, index, sequence number)
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
                // With traffic: while the current path works, the peer's packets keep arriving
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
                                // Deleting and re-adding the peer discarded the earlier cookie: count from this one. WireGuard retries
                                // every 5 seconds, and each failed retry brings another cookie
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
                            // After a switch, probes still in flight on the old path are voided
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
        // Drop every other one: never two in a row, decided by the loss rate
        sim.drop_every[0] = 2;
        sim.run(Duration::from_secs(15));
        let (at, to, _, reason) = sim.switches[0];
        assert_eq!((to, reason), (relay(1), SwitchReason::HighLoss));
        // The loss rate is counted over the last 10 in-tunnel probes (one per second): old samples leave the
        // window after about 7 seconds, then another 3 seconds
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
        // The peer's uplink is filled by its own traffic: in-tunnel replies are 4 seconds late, and the relay
        // itself answers as usual
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
        // Queue full: replies are 4 seconds late and half are dropped. The relay also passes through the same
        // bottleneck, so switching does not help
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
        // Direct recovers: the first failure has no backoff; for 15 seconds after switching away, probe at high
        // frequency, and confirm again right after the first reply
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
        // The simulation advances by 100 ms, and the reply is handled on the next advance
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
        // First failure: after switching away, probe direct at high frequency
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
        // Second failure within 10 minutes: recovery must back off, and no more high-frequency probing
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
        // The first failure does not count; after that, the wait before each return to direct doubles: 10, 20, 40,
        // 80 seconds
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
        // Relay 1 restarted and lost the index: probes are still answered, the tunnel is down, until a
        // re-handshake
        sim.tunnel_broken[0] = true;
        let lost = sim.now;
        sim.run(Duration::from_secs(6));
        let (at, to, rehandshake, reason) = sim.switches[0];
        assert_eq!(
            (to, rehandshake, reason),
            (relay(1), true, SwitchReason::RelayLostSession)
        );
        assert!(at.saturating_duration_since(lost) <= Duration::from_millis(3600));
        // After the re-handshake relay 1 works again, and it stays on relay 1
        sim.switches.clear();
        sim.run(Duration::from_secs(30));
        assert!(sim.switches.is_empty(), "{:?}", sim.switches);
        assert_eq!(sim.paths.current(), relay(1));
    }

    /// When switching to a faster relay, late packets on the old relay made the peer send the handshake reply
    /// to the old relay: the handshake did not complete. After the packets on the old path have all
    /// arrived, re-handshake on the new relay once more, without waiting for failure detection a little
    /// over 2 seconds later (section 8.4).
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
        // Re-handshake after the old path's round-trip time, on the next advance
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

    /// The peer is under load: when switching to a faster relay, the handshake first gets a cookie, and the
    /// handshake completes only when WireGuard retries with it 5 seconds later. During that time no
    /// re-handshake (it would discard the cookie), and no switching back and forth for suspected failure
    /// (section 8.4).
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
        // The current relay failed and another relay is usable: likewise switch only once
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
        // A retry with the cookie also fails (for example the cookie is forged): after two rounds handle the
        // failure as usual
        sim.under_load = Some(Duration::MAX);
        sim.run(Duration::from_secs(60));
        let (first, _, _, reason) = sim.switches[0];
        assert_eq!(reason, SwitchReason::BetterScore);
        let next = sim.switches.get(1).expect("failure handling resumes");
        let waited = next.0.saturating_duration_since(first);
        // The second cookie arrives before the first round ends (WireGuard's retry after 5 seconds), wait one
        // more round; a third does not extend it
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
        // The second attempt also failed: leave it to suspected failure detection, which finds that the relay
        // answers while the tunnel is down, and re-handshakes once more on the same relay
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
        // WireGuard reports the handshake as complete
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
        // No traffic: no packet triggers a handshake, so it does not count as not completed
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
        // The leg from relay 1 to the peer is broken: the relay itself answers, and a re-handshake does not help
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
        // First half: relay 1 slows down; switch to relay 2
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
        // Second half: relay 2 slows down and relay 1 recovers; switch back to relay 1 within a minute
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
        // Better than 15% but under 10 ms
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
        // Relay recovers first: switch to it
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
        // A loss rate that stays too high is also handed to the decider
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
        // Sorted by relay number, independent of the order of the candidate list
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
        // No further proposals before confirmation; after confirmation, switch, and then select better paths as
        // usual
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
        // The current relay drops 1 in every 5 packets: below the 30% judged a failure
        sim.drop_every[0] = 5;
        let lossy = sim.now;
        sim.run(Duration::from_secs(25));
        let (at, to, _, reason) = *sim.switches.first().expect("left the lossy relay");
        assert_eq!((to, reason), (relay(2), SwitchReason::BetterScore));
        let took = at.saturating_duration_since(lossy);
        assert!(took <= Duration::from_secs(20), "took {took:?}");
        // After that, never return to the damaged relay
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
        // All UDP is blocked: direct and UDP relay both fail, leaving only TLS
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
