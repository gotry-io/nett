//! Per-peer path selection state machine (design/mesh.md sections 7 and 8, ADR 0021). Runs on the decider
//! (section 8.3); when both sides are `dial-only` the follower runs it too, only detecting outages
//! (section 8.4).
//!
//! Pure logic: the caller passes in the time, and sending probes and switching the endpoint are handed to
//! the caller as [`Action`]s, so tests can simulate time precisely.

use std::collections::{BTreeSet, VecDeque};
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
/// A UDP relay replaces a working direct path only when it is much faster (section 8.2): its score is
/// at most this share of the current path's and at least this much lower, for this long, while the pair
/// is not busy.
const FASTER_RELAY_RATIO: f64 = 0.7;
const FASTER_RELAY_MIN_MS: f64 = 20.0;
const FASTER_RELAY_HOLD: Duration = Duration::from_secs(30);
/// Back to direct from a relay chosen for being faster once the direct score is within this share of the
/// relay's.
const DIRECT_RETURN_RATIO: f64 = 0.85;
/// When the current path has noticeable loss (at least this many of the last [`LOSS_WINDOW`] in-tunnel
/// probes were lost) and the candidate replies consecutively, a better path of the same type only needs
/// to be sustained for [`LOSSY_HOLD`] (ADR 0021).
const LOSSY_LOSSES: usize = 2;
const LOSSY_HOLD: Duration = Duration::from_secs(5);
/// A path of a better type left while losing packets is taken back once at least this many of its
/// probes since then have results, with at most [`LOSS_RETURN_LOSSES`] lost among the latest of
/// them: about a minute at one probe a second (section 8.2).
const LOSS_RETURN_PROBES: u32 = 60;
const LOSS_RETURN_LOSSES: u32 = 2;
/// Before a candidate's score decides a switch, a loss check probes each candidate and the current
/// path this many times this often (section 8.2). A candidate's few probes at its usual interval
/// can show a loss it had by chance, or miss a loss at one end of the pair or on a link every path
/// shares, which shows in all of these. A candidate that lost at most [`LOSS_CHECK_LOSSES`] is
/// clean, a path that helps against the current path's loss: at 15% loss a candidate passes about
/// one check in 80, a clean one always and one losing 2% four in five.
const LOSS_CHECK_PROBES: u32 = 40;
const LOSS_CHECK_INTERVAL: Duration = Duration::from_millis(50);
const LOSS_CHECK_LOSSES: u32 = 1;
/// A candidate that lost at most this many more of the check's probes than the current path, which
/// is probed the same way at the same time, loses alike: the loss is shared, and the two compare
/// without it (section 8.2). At 15% on both, nine checks in ten find them alike.
const LOSS_ALIKE_MARGIN: u32 = 4;
/// A loss check starts at most this often while the pair loses packets, and at most every
/// [`LOSS_CHECK_QUIET`] otherwise; its results stand until the next check can renew them.
const LOSS_CHECK_EVERY: Duration = Duration::from_secs(10);
const LOSS_CHECK_QUIET: Duration = Duration::from_secs(60);
const LOSS_RESULTS_STAND: Duration = Duration::from_secs(70);
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
/// After its first minute, a better-type candidate that has never replied is probed on Tailscale's
/// schedule for an address it has had no reply from (ADR 0021): every 5 seconds while the current path
/// goes through a relay, every minute while it is direct, and not at all while that direct path's
/// round-trip time is at most 5 milliseconds.
const UNANSWERED_ON_RELAY: Duration = Duration::from_secs(5);
const UNANSWERED_ON_DIRECT: Duration = Duration::from_secs(60);
const GOOD_ENOUGH_MS: f64 = 5.0;
/// A LAN address learned from where the peer's probes come from stays a candidate this long after the
/// last of them, as in Tailscale (design/mesh.md section 6).
pub const LEARNED_TTL: Duration = Duration::from_secs(45);
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
/// How long after a break beyond a relay the peer's report of its leg to that relay covers the time
/// since: the peer probes the relay again within this and waits for the reply.
const REPORT_LAG: Duration =
    crate::prober::RELAY_MONITOR_INTERVAL.saturating_add(crate::prober::OUTSTANDING_TTL);
/// Weight of the exponential moving average of the round-trip time.
const RTT_ALPHA: f64 = 0.25;
/// Loss penalty in the score: every 1% of loss is equivalent to 5 ms.
const LOSS_PENALTY_MS: f64 = 500.0;
/// Path type preference and transport penalty (milliseconds), smaller is better (section 8.1): TLS adds
/// another 20 ms on top of the relay preference.
const RELAY_PENALTY_MS: f64 = 10.0;
/// Obfuscated UDP through a relay comes before plain UDP through it (design/obfuscation.md
/// section 5).
const OBFS_PREFERENCE_MS: f64 = 5.0;
/// A plain endpoint left for obfuscated UDP is recorded as blocked once it has answered no probe for
/// this long while obfuscated UDP carries the connection (design/obfuscation.md section 5).
const BLOCK_SILENCE: Duration = Duration::from_secs(5 * 60);
/// ...or once it fails again this soon after it was left; past this the suspicion lapses.
const BLOCK_WINDOW: Duration = Duration::from_secs(60 * 60);
const TLS_PENALTY_MS: f64 = 20.0;

/// Path types, from best to worst (section 8.2): obfuscated UDP to the peer's own obfuscated port
/// before the plain direct path, and through a relay obfuscated UDP before UDP before TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    Lan,
    /// Obfuscated UDP to the peer's own obfuscated port (design/obfuscation.md section 5).
    DirectObfs,
    Direct,
    /// Obfuscated UDP via a relay (design/obfuscation.md section 5).
    RelayObfs,
    Relay,
    /// TLS transport via a relay (design/mesh.md section 5.3).
    RelayTls,
}

impl PathKind {
    pub fn via_relay(self) -> bool {
        matches!(
            self,
            PathKind::Relay | PathKind::RelayObfs | PathKind::RelayTls
        )
    }

    /// Obfuscated UDP, to the peer's own obfuscated port or through a relay.
    pub fn obfuscated(self) -> bool {
        matches!(self, PathKind::DirectObfs | PathKind::RelayObfs)
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
        self.score_without_loss(kind)
            .map(|s| s + self.loss_rate() * LOSS_PENALTY_MS)
    }

    /// The score without the loss penalty: what tells two paths apart when they lose alike.
    fn score_without_loss(&self, kind: PathKind) -> Option<f64> {
        let type_penalty = match kind {
            PathKind::Lan | PathKind::DirectObfs | PathKind::Direct => 0.0,
            PathKind::RelayObfs => RELAY_PENALTY_MS - OBFS_PREFERENCE_MS,
            PathKind::Relay => RELAY_PENALTY_MS,
            PathKind::RelayTls => RELAY_PENALTY_MS + TLS_PENALTY_MS,
        };
        self.rtt_ms.map(|rtt| rtt + self.jitter_ms + type_penalty)
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
    /// For a relay: the latest reply carried the peer's leg, so the round-trip time covers the whole path.
    far_leg: bool,
    /// For a relay: when a path through it last broke beyond it, on its leg to the peer. This end's probes
    /// of the relay say nothing about that leg, so until the peer reports it working the relay is not taken
    /// as recovered (section 8.2).
    beyond: Option<Instant>,
    /// Left while losing packets: the results of its probes since. A lossy path still answers most
    /// probes, so a run of replies says nothing about its loss rate (section 8.2).
    left_for_loss: Option<LossRecord>,
    /// Its probes in the loss check under way, and the results of the latest one it completed.
    checked: Option<LossCheck>,
    measured: Option<LossCheck>,
    /// Plain UDP to an endpoint recorded as blocked (design/obfuscation.md section 5): not probed, and
    /// its replies are not counted, so no rule takes it back.
    blocked: bool,
    /// When this plain path stopped working and was left for obfuscated UDP: a block is suspected until
    /// the failure is shown to last, or the suspicion lapses.
    suspected: Option<Instant>,
}

/// Results of a candidate's probes, the latest in the lowest bit (set: lost).
#[derive(Debug, Clone, Copy, Default)]
struct LossRecord {
    lost: u64,
    results: u32,
}

impl LossRecord {
    fn push(&mut self, ok: bool) {
        self.lost = (self.lost << 1) | u64::from(!ok);
        self.results = self.results.saturating_add(1);
    }

    /// Enough results, and few of the latest lost.
    fn low(&self) -> bool {
        let latest = self.lost & ((1u64 << LOSS_RETURN_PROBES) - 1);
        self.results >= LOSS_RETURN_PROBES && latest.count_ones() <= LOSS_RETURN_LOSSES
    }
}

/// A candidate's probes in a loss check: when it began, how many were sent, and their results.
#[derive(Debug, Clone, Copy)]
struct LossCheck {
    began: Instant,
    sent: u32,
    results: LossRecord,
}

impl LossCheck {
    fn new(began: Instant) -> Self {
        Self {
            began,
            sent: 0,
            results: LossRecord::default(),
        }
    }

    fn done(&self) -> bool {
        self.results.results >= LOSS_CHECK_PROBES
    }

    fn lost(&self) -> u32 {
        self.results.lost.count_ones()
    }

    fn clean(&self) -> bool {
        self.done() && self.lost() <= LOSS_CHECK_LOSSES
    }

    fn loss_rate(&self) -> f64 {
        f64::from(self.lost()) / f64::from(self.results.results.clamp(1, 64))
    }
}

/// What a candidate's score is compared with the current path's on (section 8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Judge {
    /// The full scores, loss included.
    Full,
    /// The scores without loss.
    Plain,
    /// As the loss check found them: a candidate's loss is what the check measured, with the
    /// current path's own loss included; a candidate that lost about as much as the current path,
    /// both losing, compares without loss, which is shared.
    Checked,
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
            far_leg: false,
            beyond: None,
            left_for_loss: None,
            checked: None,
            measured: None,
            blocked: false,
            suspected: None,
        }
    }

    fn record_reply(&mut self, rtt: Duration, now: Instant) {
        self.stats.record_reply(rtt);
        self.last_reply = Some(now);
        self.healthy_since.get_or_insert(now);
        self.record_result(true);
    }

    fn record_loss(&mut self) {
        self.stats.record_loss();
        self.record_result(false);
    }

    fn record_result(&mut self, ok: bool) {
        if let Some(r) = &mut self.left_for_loss {
            r.push(ok);
        }
        // A check holds the results of its own probes only, as every path in it is probed the same
        if let Some(check) = self.checked.as_mut().filter(|check| !check.done()) {
            check.results.push(ok);
            if check.done() {
                self.measured = Some(*check);
            }
        }
    }

    /// Not left while losing packets, or its loss has been measured low since.
    fn loss_recovered(&self) -> bool {
        self.left_for_loss.is_none_or(|r| r.low())
    }

    /// A path through this relay broke beyond it within [`FAILURE_MEMORY`], and the peer has not
    /// reported its leg to the relay working since.
    fn broken_beyond(&self, now: Instant) -> bool {
        self.beyond
            .is_some_and(|t| now.saturating_duration_since(t) < FAILURE_MEMORY)
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
    /// The current path still answers probes but the tunnel is down: the session was lost, as when a
    /// relay lost the index of this connection or the peer restarted, so handshake again on the same
    /// path (section 8.4).
    SessionLost,
    /// The peer said through the Hub that it restarted, losing its sessions: handshake again on the
    /// same path at once (section 8.4).
    PeerRestarted,
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
    /// Plain UDP to its endpoint is recorded as blocked, and it is not probed (design/obfuscation.md
    /// section 5).
    Blocked,
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
    /// 8.4); the caller decides where to go, from the candidates that answered since `since`, when the
    /// failure was first suspected ([`PeerPaths::best_other_relay`]).
    Lost { since: Instant },
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
    /// When the latest loss check began (section 8.2).
    loss_check: Option<Instant>,
    /// Since when a better path of the same type has existed without a break (section 8.2).
    better_since: Option<Instant>,
    /// Since when a UDP relay much faster than the current direct path has existed without a break
    /// (section 8.2).
    faster_since: Option<Instant>,
    /// The current relay was chosen for being much faster than direct: it returns to direct by its own
    /// rule, not as soon as direct answers.
    on_faster_relay: bool,
    /// The pair carries more than [`crate::prober::BUSY_RATE`]: it stays on, or returns to, direct.
    busy: bool,
    /// During a two-ended switchover (waiting for confirmation, rotating): only detects outages, does not
    /// choose a better path separately.
    hold: bool,
    /// The direct candidate established by hole punching (design/mesh.md section 6.1), ordered after the
    /// configured candidates.
    punched: Option<usize>,
    /// The LAN direct candidate learned from where the peer's probes come from (design/mesh.md section
    /// 6), ordered after the configured candidates, and when the latest of those probes arrived.
    learned: Option<(usize, Instant)>,
    /// Probe every candidate this end probes at the next tick, outside the schedule (design/status.md
    /// section 4.3).
    probe_now: bool,
    /// The relay on the peer's own machine: its leg to the peer is the peer's loopback, so this end's
    /// probes of it cover the whole path (design/mesh.md section 7.2).
    peer_relay: Option<KeyId>,
    /// The endpoint of a plain UDP path that failed while obfuscated UDP took over, for the caller to
    /// record as blocked.
    newly_blocked: Option<SocketAddr>,
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
            loss_check: None,
            better_since: None,
            faster_since: None,
            on_faster_relay: false,
            busy: false,
            hold: false,
            punched: None,
            learned: None,
            probe_now: false,
            peer_relay: None,
            newly_blocked: None,
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

    /// The same pair's state for a changed candidate list from a new desired state (design/mesh.md
    /// section 8.3): candidates that remain keep their measurements, the punched and learned direct
    /// paths stay after the configured ones, and the pair stays on the path it uses, with the tunnel's
    /// state, when that path remains. Starting over would move it to where a new pair starts, while the
    /// other end of a two-ended pair stays where both were: the tunnel breaks until they meet again.
    /// When the path in use is gone, the pair starts over as a new one. A two-ended switchover that was
    /// waiting for its confirmation is dropped with the caller's proposal.
    pub fn reconfigured(&self, routes: Vec<(Route, PathKind)>) -> Option<Self> {
        let in_use = self.candidates.get(self.current).map(|c| (c.route, c.kind));
        let mut next = self.clone();
        let old = std::mem::take(&mut next.candidates);
        next.candidates = routes
            .iter()
            .map(|&(route, kind)| {
                old.iter()
                    .find(|c| c.route == route && c.kind == kind)
                    .cloned()
                    .unwrap_or_else(|| Candidate::new(route, kind))
            })
            .collect();
        // The extra paths, in the order they were added, which is the order the caller keeps them in
        let mut extras: Vec<usize> = self
            .punched
            .into_iter()
            .chain(self.learned.map(|(i, _)| i))
            .collect();
        extras.sort_unstable();
        next.punched = None;
        next.learned = None;
        for i in extras {
            next.candidates.push(old[i].clone());
            let at = next.candidates.len() - 1;
            if self.punched == Some(i) {
                next.punched = Some(at);
            }
            if let Some((_, seen)) = self.learned.filter(|(l, _)| *l == i) {
                next.learned = Some((at, seen));
            }
        }
        let current = in_use.and_then(|(route, kind)| {
            next.candidates
                .iter()
                .position(|c| c.route == route && c.kind == kind)
        });
        let Some(current) = current else {
            return Self::new(routes, self.role);
        };
        next.current = current;
        next.hold = false;
        next.better_since = None;
        next.faster_since = None;
        Some(next)
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

    /// Number of candidates, the configured ones and the punched and learned direct paths after them.
    pub fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    pub fn punched_index(&self) -> Option<usize> {
        self.punched
    }

    /// A LAN address the peer's probes came from at `now` that no candidate has (design/mesh.md section
    /// 6): added as a LAN direct candidate, or kept alive when it is the one learned before; a new address
    /// replaces it and measurement starts over, except while it carries the tunnel. Returns its index.
    pub fn learn_lan(&mut self, endpoint: SocketAddr, now: Instant) -> usize {
        let route = Route::Direct(endpoint);
        if let Some((i, seen)) = &mut self.learned {
            let i = *i;
            if self.candidates[i].route == route {
                *seen = now;
            } else if i != self.current {
                self.candidates[i] = Candidate::new(route, PathKind::Lan);
                *seen = now;
            }
            return i;
        }
        self.candidates.push(Candidate::new(route, PathKind::Lan));
        let i = self.candidates.len() - 1;
        self.learned = Some((i, now));
        i
    }

    /// The learned LAN address has heard nothing from the peer for [`LEARNED_TTL`]: it is no longer
    /// probed, and starts over when the peer's probes come from it again. Not while it carries the tunnel:
    /// a break there is a failure like any other.
    fn learned_lapsed(&self, index: usize, now: Instant) -> bool {
        self.learned.is_some_and(|(i, seen)| {
            i == index && i != self.current && now.saturating_duration_since(seen) >= LEARNED_TTL
        })
    }

    /// Forgets the measurement of a learned LAN address that lapsed, so nothing chooses it on old replies.
    fn reset_lapsed(&mut self, now: Instant) {
        if let Some((i, _)) = self.learned
            && self.learned_lapsed(i, now)
            && self.candidates[i].last_probe.is_some()
        {
            let route = self.candidates[i].route;
            self.candidates[i] = Candidate::new(route, PathKind::Lan);
        }
    }

    /// Probes every candidate this end probes at the next tick, outside the schedule, as `tailscale ping`
    /// does (design/status.md section 4.3).
    pub fn probe_now(&mut self) {
        self.probe_now = true;
    }

    /// How many candidates [`Self::probe_now`] probes: the follower of two `dial-only` ends probes only the
    /// LAN paths, like its scheduled probes.
    pub fn probe_count(&self) -> usize {
        (0..self.candidates.len())
            .filter(|&i| match self.role {
                Role::FollowTogether => self.candidates[i].kind == PathKind::Lan,
                _ => i != self.current || !self.candidates[i].kind.via_relay(),
            })
            .count()
    }

    /// Plain UDP candidates to these endpoints are blocked (design/obfuscation.md section 5); LAN
    /// paths never are.
    pub fn set_blocked(&mut self, blocked: &BTreeSet<SocketAddr>) {
        for c in &mut self.candidates {
            c.blocked = matches!(c.kind, PathKind::Direct | PathKind::Relay)
                && blocked.contains(&c.route.endpoint());
        }
    }

    /// A new connection starts on its first candidate that is not blocked, as after a restart, rather
    /// than waiting out a blocked one. A two-ended pair starts where both ends do (section 8.4).
    pub fn start_unblocked(&mut self) {
        if self.role.together() || !self.candidates[self.current].blocked {
            return;
        }
        if let Some(first) = self.candidates.iter().position(|c| !c.blocked) {
            self.current = first;
        }
    }

    /// A plain UDP candidate leads to `endpoint`.
    pub fn leads_to_plain(&self, endpoint: &SocketAddr) -> bool {
        self.candidates.iter().any(|c| {
            matches!(c.kind, PathKind::Direct | PathKind::Relay) && c.route.endpoint() == *endpoint
        })
    }

    /// A suspected endpoint that has answered no probe since it was left, for [`BLOCK_SILENCE`] while
    /// obfuscated UDP carries the connection, is recorded as blocked; a suspicion lapses after
    /// [`BLOCK_WINDOW`].
    fn confirm_blocks(&mut self, now: Instant) {
        let obfuscated = self.current_kind().obfuscated();
        for c in &mut self.candidates {
            let Some(since) = c.suspected else { continue };
            let elapsed = now.saturating_duration_since(since);
            let silent = c.last_reply.is_none_or(|t| t < since);
            if obfuscated && silent && elapsed >= BLOCK_SILENCE && self.newly_blocked.is_none() {
                c.suspected = None;
                self.newly_blocked = Some(c.route.endpoint());
            } else if elapsed >= BLOCK_WINDOW {
                c.suspected = None;
            }
        }
    }

    /// The endpoint just recorded as blocked, once.
    pub fn take_newly_blocked(&mut self) -> Option<SocketAddr> {
        self.newly_blocked.take()
    }

    /// The relay that runs on the peer's own machine, when it runs one.
    pub fn set_peer_relay(&mut self, relay: KeyId) {
        self.peer_relay = Some(relay);
    }

    /// The candidate's measurement covers its whole path (design/mesh.md section 7.2): a direct path's
    /// probes do; a path through a relay does once its replies carry the peer's leg, or when the relay
    /// runs on the peer's own machine. Until then this end's probes show only that the relay answers.
    fn whole(&self, c: &Candidate) -> bool {
        match c.route {
            Route::Direct(_) => true,
            Route::Relay { relay, .. } => c.far_leg || self.peer_relay == Some(relay),
        }
    }

    /// The LAN direct candidate the follower takes when both ends move to a LAN path together (design/mesh.md
    /// section 7.2): of those answering now, the one with the best score; the first one when none is.
    pub fn lan_index(&self) -> Option<usize> {
        let lan =
            || (0..self.candidates.len()).filter(|&i| self.candidates[i].kind == PathKind::Lan);
        lan()
            .filter_map(|i| {
                let c = &self.candidates[i];
                (c.stats.consecutive_successes > 0)
                    .then(|| c.stats.score(c.kind))
                    .flatten()
                    .map(|score| (score, i))
            })
            .min_by(|a, b| a.0.total_cmp(&b.0))
            .map(|(_, i)| i)
            .or_else(|| lan().next())
    }

    /// Measurements and state of each candidate path, including the current one (design/status.md section 6).
    /// The current one shows the tunnel's measurement: a relay carrying the tunnel is no longer probed as a
    /// candidate.
    pub fn candidate_views(&self, now: Instant) -> Vec<CandidateView> {
        self.candidates
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let stats = if i == self.current {
                    &self.tunnel
                } else {
                    &c.stats
                };
                let state = if i == self.current {
                    CandidateState::Current
                } else if c.blocked {
                    CandidateState::Blocked
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
                    rtt_ms: stats.rtt_ms(),
                    loss: stats.measured_loss(),
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

    /// The relay path to move to when the current path is down and the Hub relays the proposal (section
    /// 8.4): of those that answered since the failure was suspected (`since`, from [`Action::Lost`]), the
    /// one a failover would take; otherwise the first other one in relay-number order.
    pub fn best_other_relay(&self, since: Instant, now: Instant) -> Option<usize> {
        self.failover_target(since, now, true, false).or_else(|| {
            self.relays_in_order()
                .into_iter()
                .find(|&i| i != self.current)
        })
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

    /// Whether the pair carries more than [`crate::prober::BUSY_RATE`] at the moment (section 8.2).
    pub fn set_busy(&mut self, busy: bool) {
        self.busy = busy;
    }

    /// The peer's measurement of its leg to `relay`, arrived at `at` with an in-tunnel reply. It is over a
    /// window of probes, so it shows the leg working since a break beyond that relay only when it has no
    /// loss and came at least [`REPORT_LAG`] after the break.
    pub fn on_relay_report(&mut self, relay: KeyId, loss: f64, at: Instant) {
        if loss > 0.0 {
            return;
        }
        for c in &mut self.candidates {
            if matches!(c.route, Route::Relay { relay: r, .. } if r == relay)
                && c.beyond
                    .is_some_and(|t| at.saturating_duration_since(t) >= REPORT_LAG)
            {
                c.beyond = None;
            }
        }
    }

    /// The paths through `relay` may be broken beyond it (section 8.2): its through probes stopped
    /// coming back while it answers this end (ADR 0029). Held off until the peer reports its leg to the
    /// relay working, as after a path through it broke while it answered.
    pub fn hold_beyond(&mut self, relay: KeyId, now: Instant) {
        for c in &mut self.candidates {
            if matches!(c.route, Route::Relay { relay: r, .. } if r == relay) {
                c.beyond = Some(now);
            }
        }
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
        if c.blocked {
            return;
        }
        let Some(pos) = c.outstanding.iter().position(|(s, _)| *s == seq) else {
            return;
        };
        // Probes sent earlier that have no reply yet have been overtaken by this reply and count as lost; they
        // will not later time out and interrupt the run of consecutive replies
        for _ in 0..pos {
            c.outstanding.pop_front();
            c.record_loss();
        }
        let (_, sent) = c.outstanding.pop_front().expect("position is in range");
        c.far_leg = extra.is_some();
        let (extra_rtt, extra_loss) = extra.unwrap_or((Duration::ZERO, 0.0));
        if extra_loss >= 1.0 {
            // The other leg is down: the relay path as a whole is down
            c.record_loss();
            c.healthy_since = None;
            return;
        }
        c.record_reply(now.saturating_duration_since(sent) + extra_rtt, now);
    }

    /// Called about every 100 ms. `active` means this peer has had traffic in the last 30 seconds.
    pub fn tick(&mut self, now: Instant, active: bool) -> Vec<Action> {
        let mut actions = Vec::new();
        self.expire(now);
        self.reset_lapsed(now);
        self.confirm_blocks(now);

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
                    // The current path is probed too: if it still answers, the session was lost, as when a
                    // relay lost the index of this connection or the peer restarted
                    for index in 0..self.candidates.len() {
                        if self.role != Role::FollowTogether {
                            actions.extend(self.probe_candidate(index, now, false));
                        }
                    }
                    return actions;
                }
                let all = std::mem::take(&mut self.probe_now);
                let due = active
                    && self
                        .last_tunnel_probe
                        .is_none_or(|t| now.saturating_duration_since(t) >= TUNNEL_INTERVAL);
                if due {
                    let seq = self.send_tunnel(now);
                    actions.push(Action::TunnelProbe { seq });
                }
                if self.role == Role::FollowTogether {
                    // The follower probes the LAN paths too, as both ends ping in Tailscale: each end then
                    // learns where the other can be reached when another NAT sits inside the LAN, and the
                    // follower knows which LAN path to take (design/mesh.md section 6)
                    for index in 0..self.candidates.len() {
                        if self.candidates[index].kind == PathKind::Lan
                            && (all || self.candidate_due(index, now, active))
                        {
                            actions.extend(self.probe_candidate(index, now, false));
                        }
                    }
                    return actions;
                }
                // When the loss rate has just become too high, probe all candidates immediately, as with suspected
                // failure
                let lossy = self.high_loss_since == Some(now);
                for index in 0..self.candidates.len() {
                    if index != self.current
                        && (lossy || all || self.candidate_due(index, now, active))
                    {
                        let stack = self.fast_recovery(index, now) || self.checking(index, now);
                        actions.extend(self.probe_candidate(index, now, stack));
                    }
                }
                // When the current path is direct, also probe it from the WireGuard port: the reply carries back this
                // machine's mapped address (design/mesh.md section 6.1). A loss check measures it as it
                // measures the candidates (section 8.2)
                let checking = self.checking(self.current, now);
                if (checking || matches!(self.current_kind(), PathKind::Lan | PathKind::Direct))
                    && (all || self.candidate_due(self.current, now, active))
                {
                    actions.extend(self.probe_candidate(self.current, now, checking));
                }
                // Both ends switch together on a proposal through the tunnel: while the pair has traffic and the
                // tunnel has not answered since it moved onto this path, the proposal could not arrive and the
                // decider would switch alone; an outage there is reported and the choice goes through the Hub
                // (section 8.4)
                let proposable =
                    self.role != Role::DecideTogether || self.tunnel_established || !active;
                if !self.hold
                    && proposable
                    && let Some(action) = self.check_improvement(now, active)
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
        if let Some(check) = &mut c.checked {
            check.sent += 1;
        }
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
            && c.left_for_loss.is_none()
            && c.left_at
                .is_some_and(|t| now.saturating_duration_since(t) < FAST_RECOVERY_WINDOW)
            && backoff(&c.failures, now).is_zero()
    }

    /// A candidate is being probed at high frequency, or waiting for a re-handshake to complete (the few
    /// seconds of waiting for the cookie retry do not count): the caller must advance more densely than
    /// [`FAST_RECOVERY_INTERVAL`].
    pub fn needs_fine_ticks(&self, now: Instant) -> bool {
        self.handshake.is_some_and(|h| !h.cookie)
            || (0..self.candidates.len())
                .any(|i| self.checking(i, now) || (i != self.current && self.fast_recovery(i, now)))
    }

    /// Starts a loss check (section 8.2) unless one began within `every`: each candidate that is
    /// probed at all, the current path's included, gets [`LOSS_CHECK_PROBES`] probes, one every
    /// [`LOSS_CHECK_INTERVAL`].
    fn start_loss_check(&mut self, now: Instant, every: Duration) {
        if self
            .loss_check
            .is_some_and(|t| now.saturating_duration_since(t) < every)
        {
            return;
        }
        self.loss_check = Some(now);
        for i in 0..self.candidates.len() {
            let probed = !self.candidates[i].blocked && !self.learned_lapsed(i, now);
            self.candidates[i].checked = probed.then(|| LossCheck::new(now));
        }
    }

    fn loss_check_recent(&self, now: Instant) -> bool {
        self.loss_check
            .is_some_and(|t| now.saturating_duration_since(t) < LOSS_CHECK_EVERY)
    }

    /// The loss check under way still waits for results.
    fn loss_check_pending(&self, now: Instant) -> bool {
        self.loss_check_recent(now)
            && self
                .candidates
                .iter()
                .any(|c| c.checked.is_some_and(|check| !check.done()))
    }

    /// Candidate `index` still has probes of the loss check to send.
    fn checking(&self, index: usize, now: Instant) -> bool {
        self.loss_check_recent(now)
            && self.candidates[index]
                .checked
                .is_some_and(|c| c.sent < LOSS_CHECK_PROBES)
    }

    /// The latest completed loss check of candidate `index`, while its results stand.
    fn measurement(&self, index: usize, now: Instant) -> Option<LossCheck> {
        self.candidates[index]
            .measured
            .filter(|m| now.saturating_duration_since(m.began) < LOSS_RESULTS_STAND)
    }

    /// A loss check that began at most [`LOSS_CHECK_EVERY`] before `since` measured candidate
    /// `index` losing almost nothing: a path that helps against a loss that began then, wherever
    /// that loss lies (section 8.2).
    fn measured_clean(&self, index: usize, since: Instant) -> bool {
        self.candidates[index]
            .measured
            .is_some_and(|m| m.began + LOSS_CHECK_EVERY >= since && m.clean())
    }

    /// Candidate `index`'s score and the current path's to compare it with, as `judge` says, and
    /// whether the loss check measured it clean.
    fn judged_scores(&self, index: usize, judge: Judge, now: Instant) -> Option<(f64, f64, bool)> {
        let c = &self.candidates[index];
        let kind = self.current_kind();
        let full = || Some((c.stats.score(c.kind)?, self.tunnel.score(kind)?));
        let plain = || {
            Some((
                c.stats.score_without_loss(c.kind)?,
                self.tunnel.score_without_loss(kind)?,
            ))
        };
        let (s, current) = match judge {
            Judge::Full => full()?,
            Judge::Plain => plain()?,
            Judge::Checked => {
                let theirs = self.measurement(index, now)?;
                let alike = self.measurement(self.current, now).is_some_and(|ours| {
                    !ours.clean() && theirs.lost() <= ours.lost() + LOSS_ALIKE_MARGIN
                });
                if alike && !theirs.clean() {
                    plain()?
                } else {
                    let s =
                        c.stats.score_without_loss(c.kind)? + theirs.loss_rate() * LOSS_PENALTY_MS;
                    return Some((s, self.tunnel.score(kind)?, theirs.clean()));
                }
            }
        };
        Some((s, current, false))
    }

    /// The candidate `qualifies` lets through that beats the current path by `ratio` and `min_ms`
    /// with the best score, as `judge` compares them, and whether the loss check measured it clean.
    fn improvement(
        &self,
        now: Instant,
        judge: Judge,
        (ratio, min_ms): (f64, f64),
        qualifies: &dyn Fn(&Self, usize, &Candidate) -> bool,
    ) -> Option<(usize, bool)> {
        self.candidates
            .iter()
            .enumerate()
            .filter(|(i, c)| *i != self.current && qualifies(self, *i, c))
            .filter_map(|(i, _)| {
                let (s, current, clean) = self.judged_scores(i, judge, now)?;
                (s <= current * ratio && current - s >= min_ms).then_some((i, s, clean))
            })
            .min_by(|a, b| a.1.total_cmp(&b.1))
            .map(|(i, _, clean)| (i, clean))
    }

    /// The candidate a switch for a better score is held for (section 8.2), whether the loss check
    /// measured it clean, and since when the hold runs: while some candidate qualifies. A
    /// candidate's few probes can show a loss it had by chance, or miss one every path shares, so
    /// while the pair has traffic a loss check measures the candidates and the current path the
    /// same way before a candidate's score decides, and the candidates compare as it found them.
    fn held_improvement(
        &mut self,
        now: Instant,
        active: bool,
        limits: (f64, f64),
        qualifies: &dyn Fn(&Self, usize, &Candidate) -> bool,
        since: fn(&mut Self) -> &mut Option<Instant>,
    ) -> Option<(usize, bool, Instant)> {
        let full = self.improvement(now, Judge::Full, limits, qualifies);
        let plain = self.improvement(now, Judge::Plain, limits, qualifies);
        let measured = self.measurement(self.current, now).is_some();
        if active && (full.is_some() || plain.is_some()) {
            // Renewed every 10 seconds while the tunnel still loses probes
            let losing = self.lossy() || (measured && self.tunnel.loss_rate() > 0.0);
            let every = if losing {
                LOSS_CHECK_EVERY
            } else {
                LOSS_CHECK_QUIET
            };
            self.start_loss_check(now, every);
        }
        let pending = self.loss_check_pending(now);
        let found = if self.lossy() || measured || pending {
            self.improvement(now, Judge::Checked, limits, qualifies)
        } else {
            full
        };
        let Some((i, clean)) = found else {
            // The hold goes on while the check measures a candidate that qualifies
            if pending && (full.is_some() || plain.is_some()) {
                since(self).get_or_insert(now);
            } else {
                *since(self) = None;
            }
            return None;
        };
        let at = *since(self).get_or_insert(now);
        Some((i, clean, at))
    }

    fn candidate_due(&self, index: usize, now: Instant, active: bool) -> bool {
        if self.learned_lapsed(index, now) || self.candidates[index].blocked {
            return false;
        }
        let c = &self.candidates[index];
        let better = c.kind < self.current_kind();
        let first_reply = c.stats.consecutive_successes == 1;
        // A candidate never tried, as one a new desired state adds, starts its minute of discovery
        let discovering = c.last_reply.is_none()
            && c.first_probe
                .is_none_or(|t| now.saturating_duration_since(t) < DISCOVERY_WINDOW);
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
        } else if self.checking(index, now) {
            LOSS_CHECK_INTERVAL
        } else if better && first_reply && c.left_for_loss.is_none() {
            // A better-type candidate just got a reply: probe once more soon to confirm, without waiting for the
            // next interval
            CONFIRM_INTERVAL
        } else if discovering {
            BETTER_TYPE_INTERVAL
        } else if better && c.last_reply.is_none() {
            if self.current_kind().via_relay() {
                UNANSWERED_ON_RELAY
            } else if self
                .tunnel
                .rtt_ms()
                .is_some_and(|rtt| rtt <= GOOD_ENOUGH_MS)
            {
                return false;
            } else {
                UNANSWERED_ON_DIRECT
            }
        } else if better || c.left_for_loss.is_some() {
            // A path left for its loss returns on a minute of its probes (section 8.2)
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
                c.record_loss();
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
                // round of detection. The decider learns from it what a failover does, as it chooses where both go
                if self.role == Role::DecideTogether {
                    self.mark_broken_beyond(since, now);
                    self.void_unanswered(since);
                }
                self.record_failure(now);
                self.reset_tunnel(self.tunnel.rtt_ms);
                return Some(Action::Lost { since });
            }
            let current = &self.candidates[self.current];
            if !self.rehandshake_tried && current.last_reply.is_some_and(|t| t >= since) {
                return Some(self.handshake_again(SwitchReason::SessionLost, now));
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
        // The loss rate stayed too high: leave for a candidate the loss check measured clean since it
        // began to be too high (the follower hands it to the decider)
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
            self.start_loss_check(now, LOSS_CHECK_EVERY);
            if now.saturating_duration_since(since) >= LOSS_FAILURE_HOLD {
                return self.fail_over(now, since, SwitchReason::HighLoss);
            }
        } else {
            self.high_loss_since = None;
        }
        None
    }

    /// Handshakes again on the path the pair is on, once until the tunnel answers: its session was
    /// lost (section 8.4).
    pub fn handshake_again(&mut self, reason: SwitchReason, now: Instant) -> Action {
        self.rehandshake_tried = true;
        let route = self.candidates[self.current].route;
        let rtt_ms = self.tunnel.rtt_ms;
        self.tunnel = PathStats::seeded(rtt_ms);
        self.clear_tunnel_probes();
        self.phase = Phase::Normal;
        self.high_loss_since = None;
        self.expect_handshake(now, rtt_ms);
        Action::Switch {
            to: route,
            rehandshake: true,
            reason,
        }
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
    /// and has the best score; when there is none, returns `None` and keeps the current state. For its
    /// loss, only to a candidate the loss check measured clean: a loss, unlike a break, can lie at the
    /// peer's end or on a link every path shares, and a path that helps is one measured not to have
    /// it; when none was, every path loses alike and the pair stays (section 8.2).
    fn fail_over(
        &mut self,
        now: Instant,
        fresh_since: Instant,
        reason: SwitchReason,
    ) -> Option<Action> {
        let for_loss = reason == SwitchReason::HighLoss;
        if !for_loss {
            self.mark_broken_beyond(fresh_since, now);
        }
        let target = self.failover_target(fresh_since, now, false, for_loss)?;
        self.record_failure(now);
        self.void_unanswered(fresh_since);
        Some(self.decide(target, reason, now))
    }

    /// A candidate with no reply since suspected failure has its earlier run of consecutive replies voided:
    /// otherwise probes that have not yet timed out would make a better path that has just gone down look
    /// still healthy, and after switching away it would immediately be switched back.
    fn void_unanswered(&mut self, fresh_since: Instant) {
        for c in &mut self.candidates {
            if !c.last_reply.is_some_and(|t| t >= fresh_since) {
                c.stats.consecutive_successes = 0;
                c.healthy_since = None;
            }
        }
    }

    /// The current path failed and its relay still answered this end since the failure began: the break
    /// lies beyond it, on its leg to the peer, which every path through it shares.
    fn mark_broken_beyond(&mut self, fresh_since: Instant, now: Instant) {
        let current = &self.candidates[self.current];
        if let Route::Relay { relay, .. } = current.route
            && current.last_reply.is_some_and(|t| t >= fresh_since)
        {
            for c in &mut self.candidates {
                if matches!(c.route, Route::Relay { relay: r, .. } if r == relay) {
                    c.beyond = Some(now);
                }
            }
        }
    }

    /// Where a failure of the current path moves (section 8.2): of the other candidates (only those via
    /// relays with `relays_only`, only those the loss check measured clean with `clean`) that answered
    /// since `fresh_since`, a path measured end to end before one
    /// measured only to its relay (section 7.2), then the best score; a path through a relay broken beyond
    /// it only when nothing else answered. A candidate whose last reply came before the failure began is
    /// not a target: it may have failed with the current path, and its probe since not yet timed out.
    fn failover_target(
        &self,
        fresh_since: Instant,
        now: Instant,
        relays_only: bool,
        clean: bool,
    ) -> Option<usize> {
        let best = |others: bool| {
            self.candidates
                .iter()
                .enumerate()
                .filter(|(i, c)| {
                    *i != self.current && c.last_reply.is_some_and(|t| t >= fresh_since)
                })
                .filter(|(i, _)| !clean || self.measured_clean(*i, fresh_since))
                .filter(|(_, c)| !relays_only || matches!(c.route, Route::Relay { .. }))
                .filter(|(_, c)| !others || !c.broken_beyond(now))
                .filter_map(|(i, c)| c.stats.score(c.kind).map(|s| (i, !self.whole(c), s)))
                .min_by(|a, b| a.1.cmp(&b.1).then(a.2.total_cmp(&b.2)))
                .map(|(i, _, _)| i)
        };
        best(true).or_else(|| best(false))
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
    fn check_improvement(&mut self, now: Instant, active: bool) -> Option<Action> {
        let current_kind = self.current_kind();
        let current_score = self.tunnel.score(current_kind);
        // A relay chosen for being faster gives way to direct only when the pair is busy or direct has
        // come close again (section 8.2)
        let returns = |c: &Candidate| {
            !self.on_faster_relay
                || self.busy
                || c.stats
                    .score(c.kind)
                    .zip(current_score)
                    .is_some_and(|(direct, relay)| direct * DIRECT_RETURN_RATIO <= relay)
        };
        // Better type: 2 consecutive replies, the backoff after failure is satisfied, and a path left
        // while losing packets has measured low loss since; the best type of those, the first listed
        // among equals
        let better_type = self
            .candidates
            .iter()
            .enumerate()
            .filter(|(i, c)| {
                *i != self.current
                    && c.kind < current_kind
                    && self.whole(c)
                    && !c.broken_beyond(now)
                    && c.stats.consecutive_successes >= BETTER_TYPE_SUCCESSES
                    && c.healthy_since.is_some_and(|t| {
                        now.saturating_duration_since(t) >= backoff(&c.failures, now)
                    })
                    && c.loss_recovered()
                    && returns(c)
            })
            .min_by_key(|(_, c)| c.kind);
        if let Some((i, _)) = better_type {
            return Some(self.decide(i, SwitchReason::BetterType, now));
        }
        if let Some(action) = self.check_faster_relay(now, active, current_kind) {
            return Some(action);
        }
        // A better path of the same type: switch only after it holds for 30 seconds. A path left while
        // losing packets is not better until its loss is measured low
        let same_type = |paths: &Self, _: usize, c: &Candidate| {
            c.kind == current_kind
                && paths.whole(c)
                && !c.broken_beyond(now)
                && c.loss_recovered()
                && c.last_reply
                    .is_some_and(|t| now.saturating_duration_since(t) <= 2 * CANDIDATE_INTERVAL)
        };
        // The hold is on the improvement: candidates of the same quality take turns at being the best, and the
        // switch goes to the best one when the hold ends
        let (i, clean, since) = self.held_improvement(
            now,
            active,
            (SAME_TYPE_RATIO, SAME_TYPE_MIN_MS),
            &same_type,
            |paths| &mut paths.better_since,
        )?;
        // The current path has noticeable loss of its own and the candidate replies consecutively: no
        // need to wait 30 seconds
        let hold = if clean
            && self.lossy()
            && self.candidates[i].stats.consecutive_successes >= BETTER_TYPE_SUCCESSES
        {
            LOSSY_HOLD
        } else {
            SAME_TYPE_HOLD
        };
        if now.saturating_duration_since(since) >= hold {
            let faster = self.on_faster_relay;
            let action = self.decide(i, SwitchReason::BetterScore, now);
            self.on_faster_relay = faster;
            return Some(action);
        }
        None
    }

    /// A UDP relay much faster than the current direct path, held for [`FASTER_RELAY_HOLD`] while the
    /// pair is not busy and the path is not queuing (section 8.2). From the obfuscated path to the
    /// peer's own port only an obfuscated relay counts, so being faster never gives up obfuscation.
    /// Pairs that switch together keep the order of path types.
    fn check_faster_relay(
        &mut self,
        now: Instant,
        active: bool,
        current_kind: PathKind,
    ) -> Option<Action> {
        // A queue on the way (late in-tunnel replies) slows every path alike: no relay is faster then
        let queuing = self
            .last_late_reply
            .is_some_and(|t| now.saturating_duration_since(t) < LATE_HORIZON);
        let eligible = self.role == Role::Decide
            && matches!(current_kind, PathKind::Direct | PathKind::DirectObfs)
            && !self.busy
            && !queuing;
        let relay_kind = |kind: PathKind| match current_kind {
            PathKind::DirectObfs => kind == PathKind::RelayObfs,
            _ => matches!(kind, PathKind::Relay | PathKind::RelayObfs),
        };
        if !eligible {
            self.faster_since = None;
            return None;
        }
        let faster = |_: &Self, _: usize, c: &Candidate| {
            relay_kind(c.kind)
                && c.far_leg
                && !c.broken_beyond(now)
                && c.loss_recovered()
                && c.stats.consecutive_successes >= BETTER_TYPE_SUCCESSES
                && c.last_reply
                    .is_some_and(|t| now.saturating_duration_since(t) <= 2 * CANDIDATE_INTERVAL)
        };
        // Held while some relay qualifies, whichever is the fastest at the moment (relays of the same quality
        // take turns); the switch goes to the fastest when the hold ends
        let (i, _, since) = self.held_improvement(
            now,
            active,
            (FASTER_RELAY_RATIO, FASTER_RELAY_MIN_MS),
            &faster,
            |paths| &mut paths.faster_since,
        )?;
        if now.saturating_duration_since(since) < FASTER_RELAY_HOLD {
            return None;
        }
        let action = self.decide(i, SwitchReason::BetterScore, now);
        self.on_faster_relay = true;
        Some(action)
    }

    fn switch_to(&mut self, target: usize, reason: SwitchReason, now: Instant) -> Action {
        self.on_faster_relay = false;
        self.faster_since = None;
        let from = self.candidates[self.current].route;
        let to = self.candidates[target].route;
        // Plain UDP failed and obfuscated UDP took over: a block of the endpoint lost is suspected, and
        // recorded when it fails so again while suspected (design/obfuscation.md section 5)
        let failed = matches!(
            reason,
            SwitchReason::Unreachable | SwitchReason::HandshakeIncomplete
        );
        // Obfuscated UDP failed as well: the peer or the network was down, and a plain path that
        // failed meanwhile did not fail for being plain
        if failed && self.candidates[self.current].kind.obfuscated() {
            for c in &mut self.candidates {
                c.suspected = None;
            }
        }
        if failed
            && matches!(
                self.candidates[self.current].kind,
                PathKind::Direct | PathKind::Relay
            )
            && self.candidates[target].kind.obfuscated()
        {
            let left = &mut self.candidates[self.current];
            if left
                .suspected
                .is_some_and(|t| now.saturating_duration_since(t) < BLOCK_WINDOW)
            {
                left.suspected = None;
                self.newly_blocked = Some(from.endpoint());
            } else {
                left.suspected = Some(now);
            }
        }
        let old_rtt_ms = self.tunnel.rtt_ms();
        // Left because of its loss, whichever rule chose the new path: a better score held on a path
        // losing probes includes their penalty
        let losing = self.tunnel.loss_rate() > 0.0;
        if reason == SwitchReason::HighLoss || (reason == SwitchReason::BetterScore && losing) {
            self.candidates[self.current].left_for_loss = Some(LossRecord::default());
        }
        self.current = target;
        // Its loss is measured in the tunnel from here on
        self.candidates[target].left_for_loss = None;
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

    fn lan(ip: &str) -> Route {
        Route::Direct(format!("{ip}:50002").parse().expect("addr"))
    }

    /// The peer's own obfuscated port, beside its WireGuard port.
    fn direct_obfs() -> Route {
        Route::Direct("198.51.100.2:30000".parse().expect("addr"))
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
        /// The round trip through the whole path, where it is longer than what a candidate probe
        /// measures: a relay's probe covers only this end's leg to the relay.
        path_rtt: Vec<Option<Duration>>,
        /// In-tunnel packets are additionally queued for this long (the peer's uplink is filled by its own
        /// traffic, so the queue is deep); candidate probes outside the tunnel are not affected.
        queue: Vec<Duration>,
        /// Packets sent by this end cannot reach the peer, while the peer's packets still arrive (only one
        /// direction works).
        one_way: Vec<bool>,
        /// In-tunnel probes and candidate probes each drop 1 in every n (0 means no drops).
        drop_every: Vec<u32>,
        /// Probes of both kinds are lost at random with this probability, from a fixed seed.
        loss: Vec<f64>,
        rng: u64,
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
        /// When each outage was reported, and since when it was suspected.
        lost: Vec<(Instant, Instant)>,
        proposals: Vec<(Instant, usize, SwitchReason)>,
        candidate_probes: usize,
        /// The peer's leg of each relay path, carried with candidate replies (`None`: not reported).
        far_leg: Vec<Option<Duration>>,
        /// The peer's measurement of its leg to each relay (loss rate), carried with every in-tunnel reply,
        /// and what this end last heard of it.
        peer_reports: Vec<(KeyId, f64)>,
        heard: std::collections::HashMap<KeyId, f64>,
        /// The pair carries more than the busy rate.
        busy: bool,
    }

    impl Sim {
        fn new(routes: Vec<(Route, PathKind)>) -> Self {
            Self::with_role(routes, Role::Decide)
        }

        fn with_role(routes: Vec<(Route, PathKind)>, role: Role) -> Self {
            let n = routes.len();
            // With the tunnel up the peer reports its leg to each relay; a test of the time before
            // that clears it
            let far_leg = routes
                .iter()
                .map(|(r, _)| matches!(r, Route::Relay { .. }).then_some(Duration::ZERO))
                .collect();
            Self {
                paths: PeerPaths::new(routes, role).expect("routes"),
                now: Instant::now(),
                up: vec![true; n],
                rtt: vec![2 * MS; n],
                path_rtt: vec![None; n],
                queue: vec![Duration::ZERO; n],
                one_way: vec![false; n],
                drop_every: vec![0; n],
                loss: vec![0.0; n],
                rng: 0x9e37_79b9_7f4a_7c15,
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
                far_leg,
                peer_reports: Vec::new(),
                heard: std::collections::HashMap::new(),
                busy: false,
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
                        for (relay, loss) in self.peer_reports.clone() {
                            self.heard.insert(relay, loss);
                            self.paths.on_relay_report(relay, loss, at);
                        }
                        self.paths.on_tunnel_reply(seq, at);
                    } else {
                        let heard = match self.paths.candidates[index].route {
                            Route::Relay { relay, .. } => self.heard.get(&relay).copied(),
                            Route::Direct(_) => None,
                        };
                        let extra = match heard {
                            Some(loss) if loss >= 1.0 => Some((Duration::ZERO, 1.0)),
                            _ => self.far_leg[index].map(|d| (d, 0.0)),
                        };
                        self.paths.on_candidate_reply(index, seq, at, extra);
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
                self.paths.set_busy(self.busy);
                for action in self.paths.tick(now, true) {
                    match action {
                        Action::TunnelProbe { seq } => {
                            let i = self.paths.current;
                            if !self.tunnel_broken[i] && !self.one_way[i] && self.delivers(i, true)
                            {
                                self.inflight.push((
                                    now + self.whole(i) + self.queue[i],
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
                                // Removing and adding the peer again voids a handshake still in
                                // flight: its response finds no initiation waiting for it
                                self.handshakes.clear();
                                if self.up[i] && !self.tunnel_broken[i] {
                                    self.handshakes.push(now + self.whole(i));
                                }
                            }
                            // After a switch, probes still in flight on the old path are voided
                            self.inflight.retain(|f| !f.1);
                        }
                        Action::Lost { since } => self.lost.push((now, since)),
                        Action::Propose { index, reason } => {
                            self.proposals.push((now, index, reason));
                        }
                    }
                }
            }
        }
    }

    impl Sim {
        /// The round trip through the whole of path `i`.
        fn whole(&self, i: usize) -> Duration {
            self.path_rtt[i].unwrap_or(self.rtt[i])
        }

        /// Room for a candidate added while running (a learned LAN address), working by default.
        fn grow(&mut self) {
            self.up.push(true);
            self.rtt.push(2 * MS);
            self.path_rtt.push(None);
            self.queue.push(Duration::ZERO);
            self.one_way.push(false);
            self.drop_every.push(0);
            self.loss.push(0.0);
            self.sent.push(0);
            self.sent_by_kind.push([0; 2]);
            self.tunnel_broken.push(false);
            self.far_leg.push(None);
        }

        fn delivers(&mut self, i: usize, tunnel: bool) -> bool {
            self.sent[i] += 1;
            let n = &mut self.sent_by_kind[i][usize::from(tunnel)];
            *n += 1;
            let dropped = self.drop_every[i] != 0 && n.is_multiple_of(self.drop_every[i]);
            self.up[i] && !dropped && !(self.loss[i] > 0.0 && self.random() < self.loss[i])
        }

        /// xorshift64: uniform in [0, 1).
        fn random(&mut self) -> f64 {
            self.rng ^= self.rng << 13;
            self.rng ^= self.rng >> 7;
            self.rng ^= self.rng << 17;
            (self.rng >> 11) as f64 / (1u64 << 53) as f64
        }
    }

    /// A relay still answers this end's probes but its leg to the peer is down: the relay's other
    /// transport shares that leg, so the switch goes to another relay even when it is much slower, and
    /// the peer's report of the leg through the new tunnel keeps the pair there (design/mesh.md
    /// section 8.2).
    /// The current path's row in status shows what the tunnel measures on it now: a relay is no
    /// longer probed as a candidate once it carries the tunnel, so its candidate measurement would
    /// stay at the value from before the switch (design/status.md section 6).
    #[test]
    fn the_current_candidate_shows_the_tunnels_measurement() {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay(1), PathKind::Relay),
        ]);
        sim.rtt = vec![10 * MS, 50 * MS];
        sim.run(Duration::from_secs(5));
        sim.up[0] = false;
        sim.run(Duration::from_secs(10));
        assert_eq!(sim.paths.current, 1, "{:?}", sim.switches);
        sim.rtt[1] = 150 * MS;
        sim.run(Duration::from_secs(30));
        let view = &sim.paths.candidate_views(sim.now)[1];
        assert_eq!(view.state, CandidateState::Current);
        let rtt = view.rtt_ms.expect("measured");
        assert!((140.0..=170.0).contains(&rtt), "{rtt}");
        assert_eq!(view.loss, Some(0.0));
    }

    #[test]
    fn a_break_beyond_a_relay_moves_to_another_relay() {
        let tls = |n: u8| Route::Relay {
            relay: KeyId([n; 8]),
            endpoint: SocketAddr::new([127, 0, 0, 1].into(), 41829 + u16::from(n)),
        };
        let mut sim = Sim::new(vec![
            (relay(1), PathKind::Relay),
            (tls(1), PathKind::RelayTls),
            (tls(2), PathKind::RelayTls),
        ]);
        sim.rtt = vec![6 * MS, 6 * MS, 200 * MS];
        sim.run(Duration::from_secs(5));
        assert_eq!(sim.paths.current, 0);
        sim.tunnel_broken[0] = true;
        sim.tunnel_broken[1] = true;
        sim.fix_on_rehandshake = false;
        // The peer probes the relay every 5 seconds: its first reports still show the leg as it was
        // before the break, then its window fills with losses
        sim.peer_reports = vec![(KeyId([1; 8]), 0.0)];
        sim.run(Duration::from_secs(6));
        sim.peer_reports = vec![(KeyId([1; 8]), 0.3)];
        sim.run(Duration::from_secs(54));
        assert!(
            sim.switches.iter().all(|s| s.1 != tls(1)),
            "{:?}",
            sim.switches
        );
        assert_eq!(sim.paths.current, 2, "{:?}", sim.switches);
        // The leg comes back, and the peer's report through the tunnel brings the pair back to UDP
        sim.tunnel_broken[0] = false;
        sim.tunnel_broken[1] = false;
        sim.peer_reports = vec![(KeyId([1; 8]), 0.0)];
        sim.run(Duration::from_secs(30));
        assert_eq!(sim.paths.current, 0, "{:?}", sim.switches);
        assert_eq!(
            sim.switches.last().map(|s| s.3),
            Some(SwitchReason::BetterType)
        );
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

    /// A direct path losing 15% at random goes over the failure rate now and then. It still answers
    /// most probes, so it is taken back only once its loss has been low for a minute of probes, not
    /// after two replies in a row (design/mesh.md section 8.2).
    #[test]
    fn a_path_left_for_loss_returns_once_its_loss_is_low() {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay(1), PathKind::Relay),
        ]);
        // Only this end's leg of the relay is known, which keeps the rule for a much faster relay out
        // of it (a_path_left_for_a_faster_relay_while_lossy_is_held_too covers that rule with loss)
        sim.far_leg[1] = None;
        sim.run(Duration::from_secs(10));
        sim.loss[0] = 0.15;
        sim.run(Duration::from_secs(20 * 60));
        let reasons: Vec<_> = sim.switches.iter().map(|s| (s.1, s.3)).collect();
        assert_eq!(
            reasons,
            [(relay(1), SwitchReason::HighLoss)],
            "{:?}",
            sim.switches
        );
        let clean = sim.now;
        sim.loss[0] = 0.0;
        sim.run(Duration::from_secs(120));
        let back = sim.switches.last().expect("switches");
        assert_eq!((back.1, back.3), (direct(), SwitchReason::BetterType));
        let took = back.0.saturating_duration_since(clean);
        assert!(took <= Duration::from_secs(70), "took {took:?}");
    }

    /// With both legs of the relay reported, the loss also makes direct score far worse than the
    /// relay, and the rule for a much faster relay may leave it first; the way back is held the same.
    /// A relay is probed every 15 seconds while the pair is direct, so one probe it lost by chance
    /// stays in its loss for minutes and costs it 50 ms of score: when direct then becomes slow, a
    /// loss check measures the relay before that loss decides, and the pair moves to it after the
    /// usual hold (design/mesh.md section 8.2, design/prototype.md scenario 25).
    #[test]
    fn a_chance_loss_on_a_sparsely_probed_relay_does_not_hold_it_back() {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay(1), PathKind::Relay),
        ]);
        sim.rtt[1] = 50 * MS;
        sim.far_leg[1] = Some(Duration::ZERO);
        sim.run(Duration::from_secs(90));
        // One relay probe is lost, then the relay answers again
        sim.up[1] = false;
        sim.run(Duration::from_secs(15));
        sim.up[1] = true;
        sim.run(Duration::from_secs(40));
        assert!(sim.switches.is_empty(), "{:?}", sim.switches);
        assert!(sim.paths.candidates[1].stats.loss_rate() > 0.0);
        let slow = sim.now;
        sim.rtt[0] = 151 * MS;
        sim.run(Duration::from_secs(60));
        let (at, to, _, reason) = *sim.switches.first().expect("moved to the relay");
        assert_eq!((to, reason), (relay(1), SwitchReason::BetterScore));
        let took = at.saturating_duration_since(slow);
        assert!(took <= Duration::from_secs(40), "took {took:?}");
    }

    /// A much faster relay that does lose packets is measured once a minute at most, and its
    /// measured loss keeps it from being taken.
    #[test]
    fn a_faster_relay_that_loses_is_measured_once_a_minute() {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay(1), PathKind::Relay),
        ]);
        sim.rtt[1] = 50 * MS;
        sim.far_leg[1] = Some(Duration::ZERO);
        sim.run(Duration::from_secs(90));
        sim.loss[1] = 0.2;
        sim.rtt[0] = 151 * MS;
        let probes = sim.candidate_probes;
        sim.run(Duration::from_secs(5 * 60));
        assert!(sim.switches.is_empty(), "{:?}", sim.switches);
        // Five checks of both paths and the usual probes, where a check every 10 seconds would send
        // about 2,400
        let sent = sim.candidate_probes - probes;
        assert!(sent <= 600, "sent {sent}");
    }

    #[test]
    fn a_path_left_for_a_faster_relay_while_lossy_is_held_too() {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay(1), PathKind::Relay),
        ]);
        sim.far_leg[1] = Some(Duration::ZERO);
        sim.run(Duration::from_secs(10));
        sim.loss[0] = 0.15;
        sim.run(Duration::from_secs(20 * 60));
        let left = sim.switches.first().expect("left direct");
        assert_eq!(left.1, relay(1), "{:?}", sim.switches);
        assert!(
            !sim.switches.iter().any(|s| s.1 == direct()),
            "{:?}",
            sim.switches
        );
    }

    /// A loss at the peer's end, its receive queue overflowing under a flood, is the same on every
    /// path. Leaving the current path for it moves the pair onto a path just as lossy and slower
    /// besides, and a better score then moves it back: no path can help, so the pair stays
    /// (design/mesh.md section 8.2).
    #[test]
    fn a_loss_every_path_shares_does_not_move_the_pair() {
        let mut sim = Sim::new(vec![
            (relay(1), PathKind::Relay),
            (relay(2), PathKind::Relay),
        ]);
        sim.rtt[1] = 42 * MS;
        sim.run(Duration::from_secs(20));
        assert!(sim.switches.is_empty(), "{:?}", sim.switches);
        sim.loss = vec![0.15, 0.15];
        sim.run(Duration::from_secs(5 * 60));
        assert!(sim.switches.is_empty(), "{:?}", sim.switches);
    }

    /// A loss every path shares drops out of the comparison: when the current relay then becomes
    /// much slower, the pair still moves, once, to the other relay, which loses as much
    /// (design/mesh.md section 8.2, design/prototype.md scenario 20(c)).
    #[test]
    fn a_loss_every_path_shares_leaves_the_comparison_to_latency() {
        let mut sim = Sim::new(vec![
            (relay(1), PathKind::Relay),
            (relay(2), PathKind::Relay),
        ]);
        sim.run(Duration::from_secs(20));
        sim.loss = vec![0.15, 0.15];
        sim.run(Duration::from_secs(60));
        assert!(sim.switches.is_empty(), "{:?}", sim.switches);
        let slow = sim.now;
        sim.rtt[0] = 42 * MS;
        sim.run(Duration::from_secs(5 * 60));
        let routes: Vec<_> = sim.switches.iter().map(|s| s.1).collect();
        assert_eq!(routes, [relay(2)], "{:?}", sim.switches);
        let took = sim.switches[0].0.saturating_duration_since(slow);
        assert!(took <= Duration::from_secs(90), "took {took:?}");
    }

    /// A relay left for its loss still answers most probes, and a few of them can look clean: a
    /// better score takes it back only once its loss is measured low, as for a better type, and that
    /// takes about a minute once the loss ends (design/mesh.md section 8.2).
    #[test]
    fn a_relay_left_for_loss_returns_only_once_its_loss_is_low() {
        let mut sim = Sim::new(vec![
            (relay(1), PathKind::Relay),
            (relay(2), PathKind::Relay),
        ]);
        sim.rtt[1] = 22 * MS;
        sim.run(Duration::from_secs(20));
        sim.loss[0] = 0.2;
        sim.run(Duration::from_secs(10 * 60));
        let routes: Vec<_> = sim.switches.iter().map(|s| s.1).collect();
        assert_eq!(routes, [relay(2)], "{:?}", sim.switches);
        let clean = sim.now;
        sim.loss[0] = 0.0;
        sim.run(Duration::from_secs(120));
        let back = sim.switches.last().expect("switches");
        assert_eq!(back.1, relay(1), "{:?}", sim.switches);
        let took = back.0.saturating_duration_since(clean);
        assert!(took <= Duration::from_secs(100), "took {took:?}");
    }

    #[test]
    fn moderate_loss_does_not_switch() {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay(1), PathKind::Relay),
        ]);
        // Only this end's leg of the relay is known, which keeps the rule for a much faster relay out
        // of it (a_path_left_for_a_faster_relay_while_lossy_is_held_too covers that rule with loss)
        sim.far_leg[1] = None;
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
        // Direct still answers probes, so a handshake on it is tried first (section 8.4)
        assert_eq!(
            (sim.switches[0].1, sim.switches[0].3),
            (direct(), SwitchReason::SessionLost),
            "{:?}",
            sim.switches
        );
        let (at, to, _, reason) = sim.switches[1];
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
        // Probes get through and WireGuard does not: a handshake does not help
        sim.tunnel_broken[0] = true;
        sim.fix_on_rehandshake = false;
        sim.run(Duration::from_secs(300));
        // The first failure does not count; after that, the wait before each return to direct doubles: 10, 20, 40,
        // 80 seconds. A handshake again on direct is not a return to it
        let returns: Vec<Instant> = sim
            .switches
            .iter()
            .filter(|s| s.1 == direct() && s.3 == SwitchReason::BetterType)
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

    /// A candidate of a better type that a new desired state adds, as when the peer starts offering
    /// its own obfuscated port, is probed and taken although the direct path in use is within 5 ms:
    /// the rule that leaves a fast direct path alone is for addresses that were tried and never
    /// answered, and this one was never tried (design/mesh.md section 7, ADR 0021).
    #[test]
    fn a_better_candidate_added_while_direct_is_fast_is_tried() {
        let mut sim = Sim::new(vec![(direct(), PathKind::Direct)]);
        sim.run(Duration::from_secs(90));
        assert!(sim.switches.is_empty(), "{:?}", sim.switches);
        sim.paths = sim
            .paths
            .reconfigured(vec![
                (direct_obfs(), PathKind::DirectObfs),
                (direct(), PathKind::Direct),
            ])
            .expect("paths");
        sim.grow();
        let added = sim.now;
        sim.run(Duration::from_secs(10));
        let (at, to, _, reason) = *sim.switches.first().expect("moved to the new candidate");
        assert_eq!((to, reason), (direct_obfs(), SwitchReason::BetterType));
        assert!(at.saturating_duration_since(added) <= Duration::from_secs(3));
    }

    /// A peer that restarts loses its sessions: once it is back its probes answer on every path and
    /// no tunnel works until a handshake. The pair handshakes again on the path it is on as soon as
    /// that path answers, rather than moving to another direct path that has no session either,
    /// where WireGuard alone would handshake again only after 15 seconds (design/mesh.md section
    /// 8.2, design/prototype.md scenario 34).
    #[test]
    fn a_peer_that_restarts_is_handshaken_again_as_soon_as_it_answers() {
        let mut sim = Sim::new(vec![
            (direct_obfs(), PathKind::DirectObfs),
            (direct(), PathKind::Direct),
            (relay_obfs(1), PathKind::RelayObfs),
        ]);
        sim.run(Duration::from_secs(40));
        assert!(sim.switches.is_empty(), "{:?}", sim.switches);
        sim.up = vec![false; 3];
        sim.tunnel_broken = vec![true; 3];
        sim.run(Duration::from_secs(2));
        sim.up = vec![true; 3];
        let back = sim.now;
        sim.run(Duration::from_secs(30));
        let (at, to, rehandshake, reason) = *sim.switches.first().expect("handshook again");
        assert_eq!(
            (to, rehandshake, reason),
            (direct_obfs(), true, SwitchReason::SessionLost),
            "{:?}",
            sim.switches
        );
        let took = at.saturating_duration_since(back);
        assert!(took <= Duration::from_millis(1500), "took {took:?}");
        assert_eq!(sim.switches.len(), 1, "{:?}", sim.switches);
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
            (relay(1), true, SwitchReason::SessionLost)
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
                SwitchReason::SessionLost
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
                (relay(1), SwitchReason::SessionLost),
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

    /// A long direct path and a relay path with both legs reported: 250 ms against 145 ms.
    fn slow_direct_fast_relay() -> Sim {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay(1), PathKind::Relay),
        ]);
        sim.rtt = vec![250 * MS, 145 * MS];
        sim.far_leg = vec![None, Some(Duration::ZERO)];
        sim
    }

    #[test]
    fn moves_a_quiet_pair_to_a_much_faster_relay_and_stays() {
        let mut sim = slow_direct_fast_relay();
        sim.run(Duration::from_secs(25));
        assert!(
            sim.switches.is_empty(),
            "holds for 30 s first: {:?}",
            sim.switches
        );
        sim.run(Duration::from_secs(40));
        let (_, to, _, reason) = sim.switches[0];
        assert_eq!((to, reason), (relay(1), SwitchReason::BetterScore));
        // Direct still answers, but it is not close enough to win back the pair
        sim.run(Duration::from_secs(60));
        assert_eq!(sim.switches.len(), 1, "{:?}", sim.switches);
    }

    /// Two relays of the same quality take turns at being the fastest by a fraction of a millisecond:
    /// the hold is on the condition, so the pair still moves after it, to whichever is fastest then
    /// (design/prototype.md scenario 25, which two equal relays failed now and then).
    #[test]
    fn two_equally_fast_relays_do_not_restart_the_hold() {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay(1), PathKind::Relay),
            (relay(2), PathKind::Relay),
        ]);
        sim.rtt = vec![250 * MS, 146 * MS, 144 * MS];
        sim.far_leg = vec![None, Some(Duration::ZERO), Some(Duration::ZERO)];
        // Relay candidates are probed every 15 seconds, and each round the two averages cross, with
        // the same jitter: 146 / 144 ms, then 144 / 146, then 146 / 144 ...
        for second in 0..90 {
            let (a, b) = match second / 15 {
                0 => (146, 144),
                w if w % 2 == 1 => (138, 152),
                _ => (152, 138),
            };
            sim.rtt[1] = a * MS;
            sim.rtt[2] = b * MS;
            sim.run(Duration::from_secs(1));
        }
        let (_, to, _, reason) = *sim.switches.first().expect("moved to a relay");
        assert!(to == relay(1) || to == relay(2), "{to:?}");
        assert_eq!(reason, SwitchReason::BetterScore);
    }

    /// Two candidates of the current type are both much better and take turns at being the best:
    /// the 30-second hold is on the improvement, not on one of them.
    #[test]
    fn two_equally_better_paths_do_not_restart_the_hold() {
        let mut sim = Sim::new(vec![
            (relay(1), PathKind::Relay),
            (relay(2), PathKind::Relay),
            (relay(3), PathKind::Relay),
        ]);
        sim.run(Duration::from_secs(20));
        sim.rtt[0] = 80 * MS;
        for second in 0..90 {
            let (a, b) = if second % 2 == 0 { (2, 3) } else { (3, 2) };
            sim.rtt[1] = a * MS;
            sim.rtt[2] = b * MS;
            sim.run(Duration::from_secs(1));
        }
        let (_, to, _, reason) = *sim.switches.first().expect("moved to a better relay");
        assert!(to == relay(2) || to == relay(3), "{to:?}");
        assert_eq!(reason, SwitchReason::BetterScore);
    }

    /// On the obfuscated path to the peer's own port, a much faster relay is taken only over
    /// obfuscated UDP: a faster plain relay would give up obfuscation (design/obfuscation.md section
    /// 5). Back on the peer's port once it comes close again.
    #[test]
    fn a_faster_relay_from_the_obfuscated_direct_path_is_an_obfuscated_one() {
        let mut sim = Sim::new(vec![
            (direct_obfs(), PathKind::DirectObfs),
            (relay(1), PathKind::Relay),
        ]);
        sim.rtt = vec![250 * MS, 130 * MS];
        sim.far_leg = vec![None, Some(Duration::ZERO)];
        sim.run(Duration::from_secs(90));
        assert!(
            sim.switches.is_empty(),
            "not onto plain UDP: {:?}",
            sim.switches
        );

        let mut sim = Sim::new(vec![
            (direct_obfs(), PathKind::DirectObfs),
            (relay(1), PathKind::Relay),
            (relay_obfs(1), PathKind::RelayObfs),
        ]);
        sim.rtt = vec![250 * MS, 130 * MS, 140 * MS];
        sim.far_leg = vec![None, Some(Duration::ZERO), Some(Duration::ZERO)];
        sim.run(Duration::from_secs(70));
        let moves: Vec<(Route, SwitchReason)> = sim.switches.iter().map(|s| (s.1, s.3)).collect();
        assert_eq!(moves, [(relay_obfs(1), SwitchReason::BetterScore)]);
        sim.rtt[0] = 130 * MS;
        sim.run(Duration::from_secs(20));
        let (_, to, _, reason) = sim.switches[1];
        assert_eq!((to, reason), (direct_obfs(), SwitchReason::BetterType));
    }

    #[test]
    fn a_busy_pair_stays_on_its_direct_path() {
        let mut sim = slow_direct_fast_relay();
        sim.busy = true;
        sim.run(Duration::from_secs(90));
        assert!(sim.switches.is_empty(), "{:?}", sim.switches);
    }

    #[test]
    fn a_relay_without_the_peers_leg_is_not_taken_for_faster() {
        let mut sim = slow_direct_fast_relay();
        // Only this end's leg is known: 5 ms looks much faster, but says nothing about the whole path
        sim.rtt[1] = 5 * MS;
        sim.far_leg[1] = None;
        sim.run(Duration::from_secs(90));
        assert!(sim.switches.is_empty(), "{:?}", sim.switches);
    }

    #[test]
    fn leaves_a_faster_relay_when_the_pair_gets_busy() {
        let mut sim = slow_direct_fast_relay();
        sim.run(Duration::from_secs(65));
        assert_eq!(sim.switches.len(), 1, "{:?}", sim.switches);
        sim.busy = true;
        sim.run(Duration::from_secs(5));
        let (_, to, _, reason) = sim.switches[1];
        assert_eq!((to, reason), (direct(), SwitchReason::BetterType));
    }

    #[test]
    fn leaves_a_faster_relay_when_direct_comes_close_again() {
        let mut sim = slow_direct_fast_relay();
        sim.run(Duration::from_secs(65));
        assert_eq!(sim.switches.len(), 1, "{:?}", sim.switches);
        // 120 ms direct against 155 for the relay (145 ms plus the relay preference)
        sim.rtt[0] = 120 * MS;
        sim.run(Duration::from_secs(20));
        let (_, to, _, reason) = sim.switches[1];
        assert_eq!((to, reason), (direct(), SwitchReason::BetterType));
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
            let took = sim.lost[0].0.saturating_duration_since(down);
            assert!(took <= Duration::from_secs(4), "{role:?}: took {took:?}");
        }
    }

    /// Both ends `dial-only` and the relay in use stops: the relay the decider proposes through the Hub
    /// is one that answered since the failure was suspected, not the stopped relay's other transport,
    /// whose last reply came before the relay stopped and whose probe has not timed out yet
    /// (design/mesh.md section 8.4).
    #[test]
    fn a_lost_pair_moves_to_a_relay_that_answered_since_the_failure() {
        let tls = Route::Relay {
            relay: KeyId([1; 8]),
            endpoint: SocketAddr::new([127, 0, 0, 1].into(), 41830),
        };
        let mut sim = Sim::with_role(
            vec![
                (relay(1), PathKind::Relay),
                (tls, PathKind::RelayTls),
                (relay(2), PathKind::Relay),
            ],
            Role::DecideTogether,
        );
        sim.rtt = vec![2 * MS, 2 * MS, 20 * MS];
        sim.run(Duration::from_secs(20));
        assert_eq!(sim.paths.current, 0);
        sim.up[0] = false;
        sim.up[1] = false;
        while sim.lost.is_empty() {
            sim.run(TICK);
        }
        let (_, since) = sim.lost[0];
        assert_eq!(sim.paths.best_other_relay(since, sim.now), Some(2));
    }

    /// Both ends `dial-only` and all of this end's UDP stops: the pair moves to a relay over TLS, and a
    /// relay over UDP whose replies came before the outage is not proposed as a better type right
    /// after, while its probe since has not timed out yet (design/mesh.md section 8.2).
    #[test]
    fn a_lost_pair_does_not_return_to_a_path_that_went_down_with_it() {
        let tls = Route::Relay {
            relay: KeyId([2; 8]),
            endpoint: SocketAddr::new([127, 0, 0, 1].into(), 41831),
        };
        let mut sim = Sim::with_role(
            vec![
                (relay(1), PathKind::Relay),
                (tls, PathKind::RelayTls),
                (relay(2), PathKind::Relay),
            ],
            Role::DecideTogether,
        );
        sim.run(Duration::from_secs(20));
        assert_eq!(sim.paths.current, 0);
        sim.up[0] = false;
        sim.up[2] = false;
        while sim.lost.is_empty() {
            sim.run(TICK);
        }
        let (_, since) = sim.lost[0];
        assert_eq!(sim.paths.best_other_relay(since, sim.now), Some(1));
        // The peer is reached over the new path within milliseconds (its WireGuard roams to where the
        // packets now come from): the handshake completes at once
        sim.paths.adopt(1, SwitchReason::Unreachable, sim.now);
        sim.paths.set_hold(false);
        sim.paths.on_handshake();
        let moved = sim.now;
        sim.run(Duration::from_secs(5));
        assert!(
            sim.proposals.iter().all(|p| p.0 < moved),
            "{:?}",
            sim.proposals
        );
        assert_eq!(sim.paths.current, 1);
    }

    /// Both ends `dial-only`, with traffic, on a path whose tunnel has not answered since the pair moved
    /// onto it: a better path is not proposed through that tunnel, where the proposal could not arrive
    /// and the decider would end up switching alone; the outage is reported instead, and the choice goes
    /// through the Hub (design/mesh.md section 8.4).
    #[test]
    fn a_pair_proposes_through_the_tunnel_only_once_it_answers() {
        let tls = Route::Relay {
            relay: KeyId([1; 8]),
            endpoint: SocketAddr::new([127, 0, 0, 1].into(), 41830),
        };
        let mut sim = Sim::with_role(
            vec![(tls, PathKind::RelayTls), (relay(2), PathKind::Relay)],
            Role::DecideTogether,
        );
        assert_eq!(sim.paths.current, 0);
        sim.tunnel_broken[0] = true;
        sim.fix_on_rehandshake = false;
        sim.run(Duration::from_secs(10));
        assert!(sim.proposals.is_empty(), "{:?}", sim.proposals);
        assert!(!sim.lost.is_empty());
        // Once the tunnel answers, the better path is proposed through it
        sim.tunnel_broken[0] = false;
        sim.run(Duration::from_secs(10));
        assert_eq!(
            sim.proposals.first().map(|p| (p.1, p.2)),
            Some((1, SwitchReason::BetterType))
        );
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

    fn relay_obfs(n: u8) -> Route {
        Route::Relay {
            relay: KeyId([n; 8]),
            endpoint: format!("127.0.0.1:{}", 41850 + u16::from(n))
                .parse()
                .expect("addr"),
        }
    }

    /// Plain UDP through a relay is lost while obfuscated UDP answers: the pair moves to obfuscated
    /// UDP, the plain endpoint is reported as blocked, and once recorded it is neither probed nor taken
    /// back when it answers again (design/obfuscation.md section 5).
    #[test]
    fn a_plain_endpoint_lost_to_obfuscated_udp_stays_avoided() {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay_obfs(1), PathKind::RelayObfs),
            (relay_tls(1), PathKind::RelayTls),
        ]);
        sim.run(Duration::from_secs(40));
        assert!(sim.switches.is_empty(), "{:?}", sim.switches);
        sim.up[0] = false;
        sim.run(Duration::from_secs(10));
        let moves: Vec<(Route, SwitchReason)> = sim.switches.iter().map(|s| (s.1, s.3)).collect();
        assert_eq!(moves, vec![(relay_obfs(1), SwitchReason::Unreachable)]);
        assert_eq!(
            sim.paths.take_newly_blocked(),
            None,
            "one failure is a suspicion"
        );
        // Silent for the whole time obfuscated UDP carries the connection
        sim.run(BLOCK_SILENCE);
        let blocked = sim.paths.take_newly_blocked().expect("the plain endpoint");
        assert_eq!(blocked, direct().endpoint());
        assert_eq!(sim.paths.take_newly_blocked(), None, "reported once");

        sim.paths.set_blocked(&[blocked].into());
        let probes = sim.sent[0];
        sim.up[0] = true;
        sim.run(Duration::from_secs(120));
        assert_eq!(sim.switches.len(), 1, "{:?}", sim.switches);
        assert_eq!(sim.sent[0], probes, "the blocked endpoint is not probed");
    }

    /// A plain path that fails once and answers again, as a handshake lost at start-up or a short
    /// outage, is taken back and never recorded as blocked.
    #[test]
    fn one_failure_that_recovers_records_no_block() {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay_obfs(1), PathKind::RelayObfs),
        ]);
        sim.run(Duration::from_secs(40));
        sim.up[0] = false;
        sim.run(Duration::from_secs(10));
        sim.up[0] = true;
        sim.run(BLOCK_WINDOW + BLOCK_SILENCE);
        let moves: Vec<(Route, SwitchReason)> = sim.switches.iter().map(|s| (s.1, s.3)).collect();
        assert_eq!(
            moves,
            vec![
                (relay_obfs(1), SwitchReason::Unreachable),
                (direct(), SwitchReason::BetterType)
            ]
        );
        assert_eq!(sim.paths.take_newly_blocked(), None);
    }

    /// A plain path taken back after a failure that fails again within the hour is recorded: probes
    /// pass and WireGuard does not.
    #[test]
    fn a_second_failure_within_the_hour_records_the_block() {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay_obfs(1), PathKind::RelayObfs),
        ]);
        sim.run(Duration::from_secs(40));
        sim.up[0] = false;
        sim.run(Duration::from_secs(10));
        sim.up[0] = true;
        sim.run(Duration::from_secs(60));
        assert_eq!(sim.paths.take_newly_blocked(), None);
        assert_eq!(sim.switches.len(), 2, "taken back: {:?}", sim.switches);
        sim.up[0] = false;
        sim.run(Duration::from_secs(10));
        assert_eq!(sim.paths.take_newly_blocked(), Some(direct().endpoint()));
    }

    /// While a peer restarts, its paths come and go, the obfuscated ones too: the pair moves from
    /// obfuscated UDP to plain and back, and plain fails more than once within the hour. A plain path
    /// that failed while obfuscated UDP failed as well did not fail for being plain, so no block is
    /// recorded, as when both ends of a pair upgrade together (design/obfuscation.md section 5).
    #[test]
    fn a_peer_that_restarts_records_no_block() {
        let mut sim = Sim::new(vec![
            (direct_obfs(), PathKind::DirectObfs),
            (direct(), PathKind::Direct),
            (relay_obfs(1), PathKind::RelayObfs),
        ]);
        sim.run(Duration::from_secs(40));
        let mut blocked = None;
        for _ in 0..3 {
            // Obfuscated UDP fails and the pair moves to plain; its backoff keeps the pair there
            sim.up[0] = false;
            sim.run(Duration::from_secs(5));
            sim.up[0] = true;
            sim.run(Duration::from_millis(500));
            // Then plain fails too, and the pair moves back to obfuscated UDP
            sim.up[1] = false;
            sim.run(Duration::from_secs(5));
            sim.up[1] = true;
            sim.run(Duration::from_secs(5));
            blocked = blocked.or(sim.paths.take_newly_blocked());
        }
        let plain_failures = sim
            .switches
            .windows(2)
            .filter(|w| w[0].1 == direct() && w[1].3 == SwitchReason::Unreachable)
            .count();
        assert!(plain_failures >= 2, "{:?}", sim.switches);
        sim.run(BLOCK_WINDOW + BLOCK_SILENCE);
        blocked = blocked.or(sim.paths.take_newly_blocked());
        assert_eq!(blocked, None, "{:?}", sim.switches);
    }

    /// Through a relay, obfuscated UDP is taken over plain UDP; to the peer's own obfuscated port,
    /// over the plain direct path too (design/obfuscation.md section 5).
    #[test]
    fn obfuscated_udp_comes_first_where_it_adds_no_hop() {
        let mut sim = Sim::new(vec![
            (relay(1), PathKind::Relay),
            (relay_obfs(1), PathKind::RelayObfs),
        ]);
        sim.run(Duration::from_secs(40));
        let moves: Vec<(Route, SwitchReason)> = sim.switches.iter().map(|s| (s.1, s.3)).collect();
        assert_eq!(moves, vec![(relay_obfs(1), SwitchReason::BetterType)]);

        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (direct_obfs(), PathKind::DirectObfs),
        ]);
        sim.run(Duration::from_secs(40));
        let moves: Vec<(Route, SwitchReason)> = sim.switches.iter().map(|s| (s.1, s.3)).collect();
        assert_eq!(moves, vec![(direct_obfs(), SwitchReason::BetterType)]);
        sim.run(Duration::from_secs(120));
        assert_eq!(sim.switches.len(), 1, "stays: {:?}", sim.switches);
    }

    /// When several paths of better types answer, the switch goes to the best of them at once rather
    /// than to the first listed and then again.
    #[test]
    fn a_recovery_goes_to_the_best_type_that_answers() {
        let mut sim = Sim::new(vec![
            (relay_tls(1), PathKind::RelayTls),
            (direct(), PathKind::Direct),
            (direct_obfs(), PathKind::DirectObfs),
        ]);
        sim.run(Duration::from_secs(40));
        let moves: Vec<(Route, SwitchReason)> = sim.switches.iter().map(|s| (s.1, s.3)).collect();
        assert_eq!(moves, vec![(direct_obfs(), SwitchReason::BetterType)]);
    }

    /// Leaving plain UDP for TLS, or obfuscated UDP for anything, records no block.
    #[test]
    fn only_plain_udp_given_up_for_obfuscated_udp_counts_as_blocked() {
        let mut sim = Sim::new(vec![
            (relay(1), PathKind::Relay),
            (relay_tls(1), PathKind::RelayTls),
        ]);
        sim.run(Duration::from_secs(40));
        sim.up[0] = false;
        sim.run(Duration::from_secs(10));
        assert_eq!(sim.switches.len(), 1, "{:?}", sim.switches);
        assert_eq!(sim.paths.take_newly_blocked(), None);

        let mut sim = Sim::new(vec![
            (relay_obfs(1), PathKind::RelayObfs),
            (relay_tls(1), PathKind::RelayTls),
        ]);
        sim.run(Duration::from_secs(40));
        sim.up[0] = false;
        sim.run(Duration::from_secs(10));
        assert_eq!(sim.switches.len(), 1, "{:?}", sim.switches);
        assert_eq!(sim.paths.take_newly_blocked(), None);
    }

    /// A better path that has never answered is probed every second in its first minute, then on
    /// Tailscale's schedule (ADR 0021): every 5 seconds while on a relay, every minute while on a direct
    /// path, not at all while that direct path is within 5 ms.
    #[test]
    fn a_better_path_that_never_answers_is_probed_on_tailscales_schedule() {
        let mut sim = Sim::new(vec![
            (relay(1), PathKind::Relay),
            (lan("192.168.1.20"), PathKind::Lan),
        ]);
        sim.up[1] = false;
        sim.run(Duration::from_secs(60));
        let first = sim.sent[1];
        assert!(first >= 30, "{first} probes in the first minute");
        sim.run(Duration::from_secs(60));
        let next = sim.sent[1] - first;
        assert!(
            (10..=13).contains(&next),
            "{next} probes in the next minute on a relay"
        );

        for (rtt, expected) in [(20 * MS, 2..=4), (2 * MS, 0..=0)] {
            let mut sim = Sim::new(vec![
                (direct(), PathKind::Direct),
                (lan("192.168.1.20"), PathKind::Lan),
            ]);
            sim.up[1] = false;
            sim.rtt[0] = rtt;
            sim.run(Duration::from_secs(61));
            let first = sim.sent[1];
            sim.run(Duration::from_secs(180));
            let later = sim.sent[1] - first;
            assert!(
                expected.contains(&later),
                "{later} probes in three minutes on a direct path of {rtt:?}"
            );
        }
    }

    /// The follower of two dial-only ends probes its LAN paths too, and takes the one that answers when
    /// both move to a LAN path (design/mesh.md section 7.2).
    #[test]
    fn the_follower_takes_the_lan_path_that_answers() {
        let mut sim = Sim::with_role(
            vec![
                (relay(1), PathKind::Relay),
                (lan("172.20.0.3"), PathKind::Lan),
                (lan("10.1.2.10"), PathKind::Lan),
            ],
            Role::FollowTogether,
        );
        sim.up[1] = false;
        sim.run(Duration::from_secs(5));
        assert!(sim.sent[2] > 0, "the follower probes its LAN paths");
        assert_eq!(sim.paths.lan_index(), Some(2));
    }

    /// A LAN address learned from where the peer's probes come from is probed while they keep coming
    /// from it, and no longer [`LEARNED_TTL`] after the last of them (design/mesh.md section 6).
    #[test]
    fn a_learned_lan_address_lapses_without_the_peers_probes() {
        let mut sim = Sim::with_role(vec![(relay(1), PathKind::Relay)], Role::DecideTogether);
        sim.run(Duration::from_secs(2));
        let address = "10.1.3.6:61000".parse().expect("addr");
        let i = sim.paths.learn_lan(address, sim.now);
        sim.grow();
        sim.up[i] = false;
        sim.run(Duration::from_secs(30));
        assert!(sim.sent[i] > 0, "probed after it is learned");
        sim.run(LEARNED_TTL);
        let lapsed = sim.sent[i];
        sim.run(Duration::from_secs(60));
        assert_eq!(sim.sent[i], lapsed, "not probed once it lapsed");
        assert_eq!(sim.paths.learn_lan(address, sim.now), i, "the same slot");
        sim.run(Duration::from_secs(5));
        assert!(
            sim.sent[i] > lapsed,
            "probed again once the peer's probes come from it"
        );
    }

    /// Both ends started at once: there is no tunnel yet, and the peer has reported none of its legs,
    /// so a relay's probes cover only this end's leg to it (4 ms) while the round trip through it is
    /// 330 ms. The direct path is down; the peer's own relay over TLS is measured end to end. The pair
    /// connects and stays connected (design/mesh.md section 8.4).
    #[test]
    fn a_relay_measured_only_to_itself_connects_over_its_whole_round_trip() {
        let mut sim = Sim::new(vec![
            (direct(), PathKind::Direct),
            (relay_tls(1), PathKind::RelayTls),
            (relay(2), PathKind::Relay),
            (relay_tls(2), PathKind::RelayTls),
        ]);
        sim.up[0] = false;
        sim.rtt = vec![2 * MS, 185 * MS, 4 * MS, 6 * MS];
        sim.path_rtt = vec![None, None, Some(330 * MS), Some(332 * MS)];
        sim.far_leg = vec![None; 4];
        sim.paths.set_peer_relay(KeyId([1; 8]));
        sim.run(Duration::from_secs(30));
        assert!(sim.paths.tunnel_established(), "{:?}", sim.switches);
        let settled = sim.switches.len();
        sim.run(Duration::from_secs(30));
        assert_eq!(sim.switches.len(), settled, "{:?}", sim.switches);
    }

    /// A new candidate list keeps the pair on the path it uses, with what was measured of the paths that
    /// remain; when that path is gone, the pair starts over as a new one does (design/mesh.md section
    /// 8.3).
    #[test]
    fn a_new_candidate_list_keeps_the_path_in_use() {
        let mut sim = Sim::with_role(
            vec![(relay(1), PathKind::Relay), (relay(2), PathKind::Relay)],
            Role::DecideTogether,
        );
        sim.run(Duration::from_secs(10));
        let first = sim.paths.current();
        let other = if first == relay(1) {
            relay(2)
        } else {
            relay(1)
        };
        let i = sim
            .paths
            .candidates
            .iter()
            .position(|c| c.route == other)
            .expect("other relay");
        sim.paths.adopt(i, SwitchReason::Proposed, sim.now);
        sim.run(Duration::from_secs(5));
        let measured = sim.paths.candidates[i].stats.rtt_ms();
        assert!(measured.is_some());

        // The peer reports a LAN address: a new candidate, the relays stay
        let lan = (lan("192.168.1.20"), PathKind::Lan);
        let next = sim
            .paths
            .reconfigured(vec![
                lan,
                (relay(2), PathKind::Relay),
                (relay(1), PathKind::Relay),
            ])
            .expect("paths");
        assert_eq!(next.current(), other);
        assert!(next.tunnel_established());
        let kept = next
            .candidates
            .iter()
            .find(|c| c.route == other)
            .expect("kept");
        assert_eq!(kept.stats.rtt_ms(), measured);

        // The relay in use is gone: the pair starts over on the first relay, as a new pair does
        let gone = sim
            .paths
            .reconfigured(vec![lan, (first, PathKind::Relay)])
            .expect("paths");
        assert_eq!(gone.current(), first);
        assert!(!gone.tunnel_established());
    }

    /// The peer restarts while the pair is on the peer's own relay over TLS: that path fails for a
    /// moment, and the other relay answers this end while the path through it does not work. The
    /// pair is back on the peer's own relay as soon as it works again, not once the failure is old
    /// enough to be forgotten.
    #[test]
    fn a_relay_that_failed_while_its_peer_restarted_is_taken_back_once_it_works() {
        let mut sim = Sim::new(vec![
            (relay_tls(1), PathKind::RelayTls),
            (direct(), PathKind::Direct),
            (relay(2), PathKind::Relay),
            (relay_tls(2), PathKind::RelayTls),
        ]);
        sim.rtt = vec![185 * MS, 2 * MS, 4 * MS, 6 * MS];
        // No tunnel yet, so no leg reported: only the peer's own relay is known end to end
        sim.far_leg = vec![None; 4];
        sim.paths.set_peer_relay(KeyId([1; 8]));
        sim.up[1] = false;
        sim.tunnel_broken[2] = true;
        sim.tunnel_broken[3] = true;
        sim.fix_on_rehandshake = false;
        sim.run(Duration::from_secs(5));
        // The peer restarts: its relay answers again before its mesh does
        sim.tunnel_broken[0] = true;
        sim.run(Duration::from_secs(5));
        sim.tunnel_broken[0] = false;
        sim.run(Duration::from_secs(60));
        assert_eq!(sim.paths.current, 0, "{:?}", sim.switches);
        assert!(sim.paths.tunnel_established());
    }
}
