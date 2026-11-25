//! What the live views show (design/top.md sections 3-5): rates from WireGuard's counts, short
//! histories, and the screen built from them.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, Instant};

use nett_mesh::status::{EventRecord, PeerStatus, StatusDoc};
use nett_proto::api::{LivePeer, LiveSample, LiveStatus, StatusResponse};
use nett_site::state::State;
use nett_trust::encoding::Timestamp;

use crate::hub::{
    Pair, hub_state, machine_problems, measured, rules_text, site_pairs, status_docs,
};
use crate::status;

/// Points kept per series: 5 minutes at 1 second, 10 minutes at 2 seconds (hard rule 14).
pub const HISTORY: usize = 300;
/// A machine whose last sample is older than this shows its latest status instead (top.md
/// section 5).
pub const STALE: Duration = Duration::from_secs(10);
/// Events kept for the list.
const EVENTS: usize = 50;

/// The views' state that the keys change.
#[derive(Debug, Default, Clone, Copy)]
pub struct Ui {
    pub selected: usize,
    pub detail: bool,
    pub traffic: bool,
}

/// One series of a chart; a gap where there was no value.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct History(VecDeque<Option<f64>>);

impl History {
    pub fn push(&mut self, v: Option<f64>) {
        if self.0.len() == HISTORY {
            self.0.pop_front();
        }
        self.0.push_back(v);
    }

    /// The sum of two series point by point, for the traffic of both directions.
    fn plus(&self, other: &Self) -> Self {
        Self(
            self.0
                .iter()
                .zip(&other.0)
                .map(|(a, b)| match (a, b) {
                    (None, None) => None,
                    _ => Some(a.unwrap_or(0.0) + b.unwrap_or(0.0)),
                })
                .collect(),
        )
    }

    /// The series in `width` block characters, each the highest of its share of the points; the
    /// scale runs from 0 (`from_zero`) or from the lowest point, to the highest. A gap is a space.
    pub fn spark(&self, width: usize, from_zero: bool) -> String {
        const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
        if width == 0 || self.0.is_empty() {
            return String::new();
        }
        let n = self.0.len();
        let per = n.div_ceil(width);
        let cells: Vec<Option<f64>> = (0..n.div_ceil(per))
            .map(|i| {
                self.0
                    .iter()
                    .skip(i * per)
                    .take(per)
                    .flatten()
                    .copied()
                    .reduce(f64::max)
            })
            .collect();
        let values = || cells.iter().flatten().copied();
        let (Some(max), Some(low)) = (values().reduce(f64::max), values().reduce(f64::min)) else {
            return " ".repeat(cells.len());
        };
        let min = if from_zero { 0.0_f64.min(low) } else { low };
        cells
            .iter()
            .map(|c| match c {
                None => ' ',
                Some(_) if max <= min => BARS[0],
                Some(v) => {
                    let level = ((v - min) / (max - min) * 7.0).round().clamp(0.0, 7.0);
                    BARS[level as usize]
                }
            })
            .collect()
    }

    pub fn max(&self) -> Option<f64> {
        self.0.iter().flatten().copied().reduce(f64::max)
    }
}

/// Rates from two readings of WireGuard's counts (top.md section 3).
#[derive(Debug, Default, Clone, Copy)]
pub struct Counter {
    last: Option<(u64, u64, f64)>,
}

impl Counter {
    /// Bits per second received and sent since the last reading, at `at` seconds on the clock the
    /// counts were read by; none at the first reading, or when a count went down (the peer was set
    /// up again) or the clock did not move (it started again).
    pub fn read(&mut self, rx: u64, tx: u64, at: f64) -> Option<(f64, f64)> {
        let rates = self.last.and_then(|(rx0, tx0, at0)| {
            let secs = at - at0;
            (secs > 0.0 && rx >= rx0 && tx >= tx0)
                .then(|| (bits(rx - rx0) / secs, bits(tx - tx0) / secs))
        });
        self.last = Some((rx, tx, at));
        rates
    }
}

fn bits(bytes: u64) -> f64 {
    // Counts stay far below 2^53, where f64 starts to round
    bytes as f64 * 8.0
}

/// A rate as the command line writes values (architecture.md section 14.3): `12 kbit/s`,
/// `9.6 Mbit/s`.
pub fn rate(bps: f64) -> String {
    let (v, unit) = match bps {
        b if b >= 1e9 => (b / 1e9, "Gbit/s"),
        b if b >= 1e6 => (b / 1e6, "Mbit/s"),
        b if b >= 1e3 => (b / 1e3, "kbit/s"),
        b => (b, "bit/s"),
    };
    if v < 10.0 && unit != "bit/s" {
        format!("{v:.1} {unit}")
    } else {
        format!("{v:.0} {unit}")
    }
}

fn opt(v: Option<f64>, f: impl Fn(f64) -> String) -> String {
    v.map_or_else(|| "-".to_owned(), f)
}

/// What a view draws (screen.rs).
#[derive(Debug, Default)]
pub struct Screen {
    pub title: String,
    pub status: String,
    /// The site's machines, the header row first; empty in `nett top`.
    pub machines: Vec<Vec<String>>,
    /// The peers or links, the header row first.
    pub rows: Vec<Vec<String>>,
    /// The chart of each row after the header.
    pub charts: Vec<Chart>,
    pub chart_title: &'static str,
    pub events: Vec<String>,
    pub detail: Option<Detail>,
}

#[derive(Debug, Clone)]
pub struct Chart {
    pub history: History,
    pub from_zero: bool,
}

#[derive(Debug)]
pub struct Detail {
    pub title: String,
    /// Each chart's label, its series and its highest value written out.
    pub charts: Vec<(String, Chart, String)>,
    pub text: String,
}

/// The three series of one peer or link.
#[derive(Debug, Default, Clone)]
struct Series {
    rtt: History,
    /// Received and sent for a peer; A to B and B to A for a link.
    first: History,
    second: History,
}

impl Series {
    fn push(&mut self, rtt: Option<f64>, first: Option<f64>, second: Option<f64>) {
        self.rtt.push(rtt);
        self.first.push(first);
        self.second.push(second);
    }

    fn chart(&self, ui: Ui) -> Chart {
        if ui.traffic {
            Chart {
                history: self.first.plus(&self.second),
                from_zero: true,
            }
        } else {
            Chart {
                history: self.rtt.clone(),
                from_zero: false,
            }
        }
    }

    fn detail(&self, labels: [String; 2]) -> Vec<(String, Chart, String)> {
        let [first, second] = labels;
        let chart = |h: &History, from_zero| Chart {
            history: h.clone(),
            from_zero,
        };
        vec![
            (
                "rtt".to_owned(),
                chart(&self.rtt, false),
                opt(self.rtt.max(), |v| format!("up to {}", status::ms(v))),
            ),
            (
                first,
                chart(&self.first, true),
                opt(self.first.max(), |v| format!("up to {}", rate(v))),
            ),
            (
                second,
                chart(&self.second, true),
                opt(self.second.max(), |v| format!("up to {}", rate(v))),
            ),
        ]
    }
}

fn chart_title(ui: Ui) -> &'static str {
    if ui.traffic { "TRAFFIC" } else { "RTT" }
}

/// An event with the peer it is about, when its text does not name it.
fn event_line(
    e: &EventRecord,
    names: &HashMap<String, String>,
    machine: Option<&str>,
    now: Timestamp,
) -> String {
    let text = status::event_text(e, names);
    let names_peer = e.name().starts_with("member_") || e.name().starts_with("routes_");
    let peer = e
        .fields
        .get("node_id")
        .and_then(serde_json::Value::as_str)
        .filter(|_| !names_peer)
        .map(|id| names.get(id).cloned().unwrap_or_else(|| id.to_owned()));
    let text = match peer {
        Some(peer) => format!("{peer}: {text}"),
        None => text,
    };
    let when = status::ago(e.at, now);
    match machine {
        Some(m) => format!("{when}  {m}  {text}"),
        None => format!("{when}  {text}"),
    }
}

// ---- nett top ----

/// `nett top`: this machine's status, read every second (top.md section 4).
#[derive(Default)]
pub struct Local {
    doc: Option<StatusDoc>,
    error: Option<String>,
    counters: HashMap<String, Counter>,
    series: HashMap<String, Series>,
    rates: HashMap<String, (Option<f64>, Option<f64>)>,
}

impl Local {
    /// A reading of the status, at `at` seconds on the view's monotonic clock.
    pub fn status(&mut self, doc: StatusDoc, at: f64) {
        for p in &doc.peers {
            let id = p.id.to_string();
            let rates = self
                .counters
                .entry(id.clone())
                .or_default()
                .read(p.rx_bytes, p.tx_bytes, at)
                // A peer the site gives no path has no link to measure
                .filter(|_| p.state != nett_mesh::status::PeerState::NoPath);
            let (rx, tx) = (rates.map(|r| r.0), rates.map(|r| r.1));
            self.series
                .entry(id.clone())
                .or_default()
                .push(p.rtt_ms, rx, tx);
            self.rates.insert(id, (rx, tx));
        }
        let ids: Vec<String> = doc.peers.iter().map(|p| p.id.to_string()).collect();
        self.series.retain(|id, _| ids.contains(id));
        self.counters.retain(|id, _| ids.contains(id));
        self.doc = Some(doc);
        self.error = None;
    }

    pub fn failed(&mut self, error: String) {
        self.error = Some(error);
    }

    /// The peers in the order `nett status` lists them.
    fn peers(&self) -> Vec<&PeerStatus> {
        let mut peers: Vec<&PeerStatus> = self.doc.iter().flat_map(|d| &d.peers).collect();
        peers.sort_unstable_by(|a, b| status::sort_key(a).cmp(status::sort_key(b)));
        peers
    }

    pub fn rows(&self) -> usize {
        self.peers().len()
    }

    pub fn screen(&self, now: Timestamp, ui: Ui) -> Screen {
        let status = self.error.clone().unwrap_or_else(|| "live".to_owned());
        let Some(doc) = &self.doc else {
            return Screen {
                title: "nett top".into(),
                status,
                ..Screen::default()
            };
        };
        let node = &doc.node;
        let title = format!(
            "nett top  {}  {}  {}",
            status::labelled(node.name.as_ref().map(|n| n.as_str()), node.id.as_str()),
            node.mesh
                .first()
                .map_or_else(|| "not admitted".to_owned(), ToString::to_string),
            status::network_text(node)
        );
        let mut rows = vec![
            [
                "PEER", "ADDRESS", "STATE", "PATH", "RTT", "LOSS", "IN", "OUT",
            ]
            .map(str::to_owned)
            .to_vec(),
        ];
        let mut charts = Vec::new();
        let empty = Series::default();
        let peers = self.peers();
        for p in &peers {
            let id = p.id.to_string();
            let (rx, tx) = self.rates.get(&id).copied().unwrap_or_default();
            rows.push(vec![
                status::peer_label(p),
                p.mesh
                    .first()
                    .map_or_else(|| "-".into(), ToString::to_string),
                status::state(p.state).to_owned(),
                p.path
                    .as_ref()
                    .map_or_else(|| "-".into(), status::path_label),
                opt(p.rtt_ms, status::ms),
                opt(p.loss, status::loss),
                opt(rx, rate),
                opt(tx, rate),
            ]);
            charts.push(self.series.get(&id).unwrap_or(&empty).chart(ui));
        }
        let names = status::names(doc);
        let events = doc
            .events
            .iter()
            .rev()
            .take(EVENTS)
            .map(|e| event_line(e, &names, None, now))
            .collect();
        let detail = ui
            .detail
            .then(|| peers.get(ui.selected))
            .flatten()
            .map(|p| Detail {
                title: status::peer_label(p),
                charts: self
                    .series
                    .get(p.id.as_str())
                    .unwrap_or(&empty)
                    .detail(["in".into(), "out".into()]),
                text: status::peer_detail(doc, p, now),
            });
        Screen {
            title,
            status,
            machines: Vec::new(),
            rows,
            charts,
            chart_title: chart_title(ui),
            events,
            detail,
        }
    }
}

// ---- nett site top ----

/// A link's latest numbers from a sample of the end that measures it.
#[derive(Debug, Clone, Copy)]
struct Latest {
    rtt: Option<f64>,
    loss: Option<f64>,
    jitter: Option<f64>,
    a_to_b: Option<f64>,
    b_to_a: Option<f64>,
    at: Instant,
}

struct Link {
    pair: Pair,
    series: Series,
    latest: Option<Latest>,
}

/// `nett site top`: every machine and link through the Hub (top.md section 5).
pub struct Site {
    state: State,
    host: String,
    reply: Option<StatusResponse>,
    docs: BTreeMap<String, StatusDoc>,
    connection: String,
    /// When each machine's last sample came, and its counts by peer.
    sampled: HashMap<String, (Instant, HashMap<String, Counter>)>,
    links: Vec<Link>,
}

impl Site {
    pub fn new(state: State, url: &str) -> Self {
        let host = url
            .strip_prefix("https://")
            .unwrap_or(url)
            .trim_end_matches('/')
            .to_owned();
        let links = site_pairs(&state)
            .into_iter()
            .map(|pair| Link {
                pair,
                series: Series::default(),
                latest: None,
            })
            .collect();
        Self {
            state,
            host,
            reply: None,
            docs: BTreeMap::new(),
            connection: "connecting".to_owned(),
            sampled: HashMap::new(),
            links,
        }
    }

    pub fn connection(&mut self, text: String) {
        self.connection = text;
    }

    pub fn reply(&mut self, reply: StatusResponse) {
        self.docs = status_docs(&reply);
        self.reply = Some(reply);
    }

    /// A machine's status report: taken unless the one held is newer.
    pub fn status(&mut self, live: LiveStatus) {
        let Some(reply) = &mut self.reply else { return };
        let Some(m) = reply
            .machines
            .iter_mut()
            .find(|m| m.node_id == live.node_id)
        else {
            return;
        };
        if m.status_at.is_some_and(|at| at > live.status_at) {
            return;
        }
        if let Ok(doc) = serde_json::from_value(live.status.clone()) {
            self.docs.insert(live.node_id.clone(), doc);
        }
        m.status = Some(live.status);
        m.status_at = Some(live.status_at);
    }

    /// A machine's sample, arrived at `now`: it gives a link its numbers when the machine
    /// measures the link, or when the end that measures sends no samples (top.md section 3).
    pub fn sample(&mut self, sample: LiveSample, now: Instant) {
        let at = sample.at_ms as f64 / 1000.0;
        let (when, counters) = self
            .sampled
            .entry(sample.node_id.clone())
            .or_insert_with(|| (now, HashMap::new()));
        *when = now;
        let read: Vec<(LivePeer, Option<(f64, f64)>)> = sample
            .peers
            .into_iter()
            .map(|p| {
                let rates = counters
                    .entry(p.id.clone())
                    .or_default()
                    .read(p.rx_bytes, p.tx_bytes, at);
                (p, rates)
            })
            .collect();
        for (peer, rates) in read {
            let Some(link) = self.links.iter_mut().find(|l| {
                let ids = [l.pair.ids[0].as_str(), l.pair.ids[1].as_str()];
                ids == [sample.node_id.as_str(), peer.id.as_str()]
                    || ids == [peer.id.as_str(), sample.node_id.as_str()]
            }) else {
                continue;
            };
            let end = usize::from(link.pair.ids[1].as_str() == sample.node_id);
            let measuring = measured(&self.docs, &link.pair).map_or(end, |(e, _)| e);
            let measurer_fresh = self
                .sampled
                .get(link.pair.ids[measuring].as_str())
                .is_some_and(|(t, _)| now.duration_since(*t) < STALE);
            if end != measuring && measurer_fresh {
                continue;
            }
            // This end received rx from the other and sent tx to it
            let (a_to_b, b_to_a) = match (end, rates) {
                (0, Some((rx, tx))) => (Some(tx), Some(rx)),
                (_, Some((rx, tx))) => (Some(rx), Some(tx)),
                (_, None) => (None, None),
            };
            link.series.push(peer.rtt_ms, a_to_b, b_to_a);
            link.latest = Some(Latest {
                rtt: peer.rtt_ms,
                loss: peer.loss,
                jitter: peer.jitter_ms,
                a_to_b,
                b_to_a,
                at: now,
            });
        }
    }

    pub fn rows(&self) -> usize {
        self.links.len()
    }

    fn names(&self) -> HashMap<String, String> {
        self.state
            .machines
            .iter()
            .map(|(name, m)| (m.node_id.to_string(), name.to_string()))
            .collect()
    }

    pub fn screen(&self, now: Timestamp, at: Instant, ui: Ui) -> Screen {
        let title = format!(
            "nett site top  {}  {} machines  {}",
            self.host,
            self.state.machines.len(),
            rules_text(&self.state)
        );
        let mut machines = vec![
            ["MACHINE", "HUB", "VERSION", "NETWORK", "RELAY", "PROBLEMS"]
                .map(str::to_owned)
                .to_vec(),
        ];
        match &self.reply {
            Some(reply) => {
                let problems = machine_problems(&self.state, reply, &self.docs, now);
                for m in &reply.machines {
                    let doc = self.docs.get(&m.node_id);
                    machines.push(vec![
                        m.name.clone(),
                        hub_state(m).to_owned(),
                        m.nett_version.clone().unwrap_or_else(|| "-".into()),
                        doc.map_or_else(
                            || "-".into(),
                            |d| {
                                let plane = match d.node.dataplane {
                                    nett_mesh::status::DataPlaneKind::Kernel => "kernel",
                                    _ => "userspace",
                                };
                                format!("{}, {plane}", status::reachability(d.node.reachability))
                            },
                        ),
                        doc.and_then(|d| d.relay.as_ref()).map_or_else(
                            || "-".into(),
                            |r| format!("{} members, {} links", r.members, r.links),
                        ),
                        problems
                            .get(&m.node_id)
                            .cloned()
                            .unwrap_or_else(|| "-".into()),
                    ]);
                }
            }
            None => {
                for name in self.state.machines.keys() {
                    let mut row = vec!["-".to_owned(); 6];
                    row[0] = name.to_string();
                    machines.push(row);
                }
            }
        }

        let mut rows = vec![
            [
                "LINK", "STATE", "PATH", "RTT", "LOSS", "JITTER", "A→B", "B→A",
            ]
            .map(str::to_owned)
            .to_vec(),
        ];
        let mut charts = Vec::new();
        for link in &self.links {
            let view = measured(&self.docs, &link.pair);
            let peer = view.map(|(_, p)| p);
            let fresh = link.latest.filter(|l| at.duration_since(l.at) < STALE);
            let (rtt, loss, jitter) = match fresh {
                Some(l) => (l.rtt, l.loss, l.jitter),
                None => (
                    peer.and_then(|p| p.rtt_ms),
                    peer.and_then(|p| p.loss),
                    peer.and_then(|p| p.jitter_ms),
                ),
            };
            rows.push(vec![
                format!("{} - {}", link.pair.names[0], link.pair.names[1]),
                peer.map_or_else(|| "-".into(), |p| status::state(p.state).to_owned()),
                peer.and_then(|p| p.path.as_ref())
                    .map_or_else(|| "-".into(), status::path_label),
                opt(rtt, status::ms),
                opt(loss, status::loss),
                opt(jitter, status::ms),
                opt(fresh.and_then(|l| l.a_to_b), rate),
                opt(fresh.and_then(|l| l.b_to_a), rate),
            ]);
            charts.push(link.series.chart(ui));
        }

        let names = self.names();
        let mut events: Vec<(Timestamp, String)> = self
            .docs
            .iter()
            .flat_map(|(id, doc)| {
                let machine = names.get(id).map_or(id.as_str(), String::as_str);
                doc.events.iter().map(move |e| (e.at, (e, machine)))
            })
            .map(|(t, (e, machine))| (t, event_line(e, &names, Some(machine), now)))
            .collect();
        events.sort_by_key(|e| std::cmp::Reverse(e.0));
        events.truncate(EVENTS);

        let detail = ui
            .detail
            .then(|| self.links.get(ui.selected))
            .flatten()
            .map(|link| {
                let [a, b] = &link.pair.names;
                let view = measured(&self.docs, &link.pair);
                let by = view.map(|(end, _)| link.pair.names[end].clone());
                Detail {
                    title: match &by {
                        Some(by) => format!("{a} - {b}, measured by {by}"),
                        None => format!("{a} - {b}"),
                    },
                    charts: link.series.detail([format!("{a}→{b}"), format!("{b}→{a}")]),
                    text: match view {
                        Some((end, p)) => self
                            .docs
                            .get(link.pair.ids[end].as_str())
                            .map(|doc| status::peer_detail(doc, p, now))
                            .unwrap_or_default(),
                        None => "Neither end has reported its status yet.\n".to_owned(),
                    },
                }
            });
        Screen {
            title,
            status: self.connection.clone(),
            machines,
            rows,
            charts,
            chart_title: chart_title(ui),
            events: events.into_iter().map(|(_, e)| e).collect(),
            detail,
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use nett_proto::api::MachineStatus;
    use nett_site::dir::{SiteDir, new_node_id};
    use nett_site::ops::MachineOptions;

    use super::*;

    /// A status of `me` with one peer seen as `role`, its round-trip time and counts.
    pub fn doc(
        me: (&str, &str),
        peer: (&str, &str),
        role: &str,
        rtt: Option<f64>,
        rx: u64,
        tx: u64,
    ) -> StatusDoc {
        serde_json::from_value(serde_json::json!({
            "v": 1, "version": "0.12.0",
            "node": {"id": me.0, "name": me.1, "admitted": true, "mesh": ["100.88.0.4"],
                     "edge": [], "routes": [], "reachability": "dial-only",
                     "dataplane": "userspace", "listen_port": 53557, "nat": null,
                     "clock_trusted": true, "started_at": "2026-11-25T00:00:00Z"},
            "config": {"applied_at": "2026-11-25T00:00:00Z", "access_rules_version": 3},
            "peers": [{
                "id": peer.0, "name": peer.1, "mesh": ["100.88.0.1"], "edge": [], "routes": [],
                "state": "connected", "role": role,
                "path": {"kind": "direct_obfs", "relay": null, "endpoint": "198.51.100.2:42001",
                         "punched": false, "since": null, "reason": null},
                "rtt_ms": rtt, "loss": rtt.map(|_| 0.0), "jitter_ms": rtt.map(|r| r / 20.0),
                "last_handshake": null, "last_received": null, "rx_bytes": rx, "tx_bytes": tx,
                "candidates": []
            }],
            "problems": [],
            "events": [{"at": "2026-11-25T00:01:00Z", "event": "path_switched", "node_id": peer.0,
                        "to": "direct (obfs) 198.51.100.2:42001", "reason": "peer_restarted"}]
        }))
        .expect("fixture")
    }

    #[test]
    fn rates_come_from_two_readings_of_the_counts() {
        let mut c = Counter::default();
        assert_eq!(c.read(1000, 0, 1.0), None);
        assert_eq!(c.read(2000, 500, 3.0), Some((4000.0, 2000.0)));
        assert_eq!(c.read(100, 600, 4.0), None, "a count that went down");
        assert_eq!(c.read(200, 700, 4.0), None, "a clock that did not move");
        assert_eq!(
            [0.0, 999.0, 12_000.0, 9_600_000.0, 1.2e9].map(rate),
            [
                "0 bit/s",
                "999 bit/s",
                "12 kbit/s",
                "9.6 Mbit/s",
                "1.2 Gbit/s"
            ]
        );
    }

    /// A chart fits its width, each character the highest of its points; gaps are spaces; the
    /// round-trip time is scaled from its lowest point and traffic from zero; the history is
    /// bounded.
    #[test]
    fn charts_fit_their_width() {
        let mut h = History::default();
        for v in [10.0, 10.0, 20.0, 20.0] {
            h.push(Some(v));
        }
        h.push(None);
        h.push(None);
        assert_eq!(h.spark(3, false), "▁█ ");
        assert_eq!(h.spark(6, true), "▅▅██  ");
        assert_eq!(h.spark(10, false).chars().count(), 6);
        for _ in 0..HISTORY * 2 {
            h.push(Some(1.0));
        }
        assert_eq!(h.0.len(), HISTORY);
    }

    fn machine(name: &str, id: &str, doc: &StatusDoc) -> MachineStatus {
        MachineStatus {
            name: name.into(),
            node_id: id.into(),
            address: "100.88.0.1".into(),
            online: true,
            last_seen: None,
            nett_version: Some("0.12.0".into()),
            platform: None,
            applied_generation: Some(1),
            result: Some("applied".into()),
            reason: None,
            status: Some(serde_json::to_value(doc).expect("json")),
            status_at: Some(1),
            upgrade_result: None,
            upgrade_reason: None,
            backup_at: None,
        }
    }

    /// Two machines `a` and `b` the site connects, `a` measuring the link.
    pub fn site() -> (tempfile::TempDir, Site, [String; 2]) {
        let tmp = tempfile::Builder::new()
            .prefix("nett-cli-top-")
            .tempdir()
            .expect("temp dir");
        SiteDir::init(tmp.path(), "https://nett.invalid").expect("init");
        let mut state = SiteDir::open(tmp.path())
            .expect("open")
            .load()
            .expect("load");
        for n in ["a", "b"] {
            state
                .add(
                    n.parse().expect("name"),
                    MachineOptions::default(),
                    new_node_id().expect("id"),
                )
                .expect("add");
        }
        state
            .allow(&["a".into()], &["b".into()], vec![], None)
            .expect("rule");
        let id = |n: &str| {
            state
                .machine(&n.parse().expect("name"))
                .expect("machine")
                .node_id
                .to_string()
        };
        let ids = [id("a"), id("b")];
        let mut site = Site::new(state, "https://hub.example.com");
        let a = doc((&ids[0], "a"), (&ids[1], "b"), "decider", Some(9.4), 0, 0);
        let b = doc((&ids[1], "b"), (&ids[0], "a"), "follower", None, 0, 0);
        site.reply(StatusResponse {
            hub_version: "0.12.0".into(),
            hub_upgrade: None,
            release: None,
            url: "https://hub.example.com".into(),
            generation: 1,
            machines: vec![machine("a", &ids[0], &a), machine("b", &ids[1], &b)],
            backup: None,
        });
        (tmp, site, ids)
    }

    pub fn sample(
        of: &str,
        peer: &str,
        at_ms: u64,
        rx: u64,
        tx: u64,
        rtt: Option<f64>,
    ) -> LiveSample {
        LiveSample {
            name: String::new(),
            node_id: of.into(),
            at_ms,
            peers: vec![LivePeer {
                id: peer.into(),
                rx_bytes: rx,
                tx_bytes: tx,
                rtt_ms: rtt,
                loss: rtt.map(|_| 0.0),
                jitter_ms: None,
            }],
        }
    }

    /// A link takes the numbers of the end that measures it, its sent bytes as A to B; the other
    /// end's samples count only while the measuring end sends none, and then for both directions
    /// (design/top.md section 3).
    #[test]
    fn a_link_takes_the_numbers_of_the_end_that_measures_it() {
        let (_tmp, mut site, [a, b]) = site();
        let t0 = Instant::now();
        let row = |site: &Site, at: Instant| {
            site.screen(Timestamp::now(), at, Ui::default()).rows[1].clone()
        };
        site.sample(sample(&a, &b, 0, 0, 0, Some(9.4)), t0);
        site.sample(sample(&b, &a, 0, 0, 0, None), t0);
        let t1 = t0 + Duration::from_secs(2);
        // a sent 1000 bytes to b in 2 s, received 250; b's view is not taken while a's is fresh
        site.sample(sample(&a, &b, 2000, 250, 1000, Some(9.4)), t1);
        site.sample(sample(&b, &a, 2000, 9999, 9999, None), t1);
        let r = row(&site, t1);
        assert_eq!(r[0], "a - b");
        assert_eq!(
            (r[3].as_str(), r[6].as_str(), r[7].as_str()),
            ("9.4 ms", "4.0 kbit/s", "1.0 kbit/s")
        );
        // a stops sampling: once its samples are stale, b's counts give the rates
        let t2 = t1 + STALE + Duration::from_secs(1);
        site.sample(
            sample(&b, &a, 2000 + 11_000 + 2000, 9999 + 2750, 9999 + 1375, None),
            t2 - Duration::from_secs(2),
        );
        site.sample(
            sample(&b, &a, 2000 + 13_000 + 2000, 9999 + 5500, 9999 + 2750, None),
            t2,
        );
        let r = row(&site, t2);
        assert_eq!((r[6].as_str(), r[7].as_str()), ("11 kbit/s", "5.5 kbit/s"));
        // With no fresh sample at all, the rates are unknown and the status's numbers show
        let r = row(&site, t2 + STALE * 2);
        assert_eq!((r[3].as_str(), r[6].as_str()), ("9.4 ms", "-"));
    }

    /// A newer status replaces the one held, an older one does not.
    #[test]
    fn a_status_report_replaces_an_older_one() {
        let (_tmp, mut site, [a, b]) = site();
        let report = |at, rtt| LiveStatus {
            name: "a".into(),
            node_id: a.clone(),
            status_at: at,
            status: serde_json::to_value(doc((&a, "a"), (&b, "b"), "decider", Some(rtt), 0, 0))
                .expect("json"),
        };
        let rtt = |site: &Site| {
            site.screen(Timestamp::now(), Instant::now() + STALE * 2, Ui::default())
                .rows[1][3]
                .clone()
        };
        site.status(report(5, 30.0));
        assert_eq!(rtt(&site), "30 ms");
        site.status(report(4, 50.0));
        assert_eq!(rtt(&site), "30 ms");
    }

    /// `nett top` lists the peers with their rates in and out, and the events name the peer.
    #[test]
    fn the_local_view_shows_rates_and_events() {
        let mut local = Local::default();
        let me = ("node_01JD7M3XQ4W8N2K5R9T6V3B7C1", "mac");
        let peer = ("node_01JD7M3XQ4W8N2K5R9T6V3B7C2", "edge-vps");
        local.status(doc(me, peer, "decider", Some(9.2), 0, 0), 0.0);
        local.status(doc(me, peer, "decider", Some(9.2), 150_000, 6_000), 1.0);
        let s = local.screen(Timestamp::from_unix_seconds(1_795_560_120), Ui::default());
        assert!(
            s.title.starts_with(
                "nett top  mac (node_01JD7M3XQ4W8N2K5R9T6V3B7C1)  100.88.0.4  dial-only"
            ),
            "{}",
            s.title
        );
        assert_eq!(s.rows[1][0], "edge-vps");
        assert_eq!(
            (s.rows[1][6].as_str(), s.rows[1][7].as_str()),
            ("1.2 Mbit/s", "48 kbit/s")
        );
        assert_eq!(s.events.len(), 1);
        assert!(
            s.events[0].contains("edge-vps: path switched"),
            "{}",
            s.events[0]
        );
        let ui = Ui {
            detail: true,
            ..Ui::default()
        };
        let detail = local.screen(Timestamp::now(), ui).detail.expect("detail");
        assert_eq!(detail.charts.len(), 3);
        assert!(detail.text.contains("peer"), "{}", detail.text);
    }
}
