//! `nett status`：本机组网的状态（design/status.md 第 7 节）。只读，经组网进程的本机套接字查询。

use std::fmt::Write as _;
use std::io::ErrorKind;
use std::path::PathBuf;

use anyhow::{Context as _, bail};
use lexopt::ValueExt as _;
use nett_mesh::config::Reachability;
use nett_mesh::status::{
    self, CandidateStateDoc, DataPlaneKind, EventRecord, NatKind, NodeRef, PathKindDoc, PathStatus,
    PeerRole, PeerState, PeerStatus, Problem, ProblemKind, QueryError, StatusDoc,
};
use nett_trust::encoding::Timestamp;

const USAGE: &str = "usage: nett status [<peer>] [--json] [--socket <path>]";

pub fn run(mut parser: lexopt::Parser) -> anyhow::Result<()> {
    let mut peer = None;
    let mut json = false;
    let mut socket = PathBuf::from(status::DEFAULT_SOCKET);
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Long("json") => json = true,
            lexopt::Arg::Long("socket") => socket = PathBuf::from(parser.value()?),
            lexopt::Arg::Value(v) if peer.is_none() => peer = Some(v.string()?),
            lexopt::Arg::Long("help") | lexopt::Arg::Short('h') => {
                println!("{USAGE}");
                return Ok(());
            }
            _ => bail!("{USAGE}"),
        }
    }
    let raw = status::query_raw(&socket).map_err(|e| explain(e, &socket))?;
    let doc: StatusDoc = serde_json::from_value(raw.clone())
        .context("the mesh service sent a status this version cannot read")?;
    let now = Timestamp::now();
    match (peer, json) {
        (None, true) => println!("{}", serde_json::to_string_pretty(&raw)?),
        (None, false) => print!("{}", overview(&doc, now)),
        (Some(wanted), json) => {
            let index = find_peer(&doc, &wanted)?;
            if json {
                let peer = &raw["peers"][index];
                println!("{}", serde_json::to_string_pretty(peer)?);
            } else {
                print!("{}", peer_detail(&doc, &doc.peers[index], now));
            }
        }
    }
    Ok(())
}

/// 连不上时说清楚是没有运行、还是权限不够。
fn explain(e: QueryError, socket: &std::path::Path) -> anyhow::Error {
    let path = socket.display();
    match &e {
        QueryError::Connect { source, .. } => match source.kind() {
            ErrorKind::NotFound => {
                anyhow::anyhow!("the mesh service is not running (no socket at {path})")
            }
            ErrorKind::ConnectionRefused => anyhow::anyhow!(
                "the mesh service is not running ({path} does not accept connections)"
            ),
            ErrorKind::PermissionDenied => {
                anyhow::anyhow!("permission denied for {path}; run with sudo")
            }
            _ => e.into(),
        },
        QueryError::Refused { code, .. } if code == "permission_denied" => {
            anyhow::anyhow!("permission denied for {path}; run with sudo")
        }
        _ => e.into(),
    }
}

fn find_peer(doc: &StatusDoc, wanted: &str) -> anyhow::Result<usize> {
    if let Some(i) = doc.peers.iter().position(|p| {
        p.name.as_ref().is_some_and(|n| n.as_str() == wanted) || p.id.as_str() == wanted
    }) {
        return Ok(i);
    }
    let mut known: Vec<&str> = doc.peers.iter().map(sort_key).collect();
    known.sort_unstable();
    if known.is_empty() {
        bail!("no peer `{wanted}`; this node has no peers");
    }
    bail!("no peer `{wanted}`; peers: {}", known.join(", "))
}

// ---- 总览（第 7.1 节） ----

fn overview(doc: &StatusDoc, now: Timestamp) -> String {
    let mut out = String::new();
    let mut head = Vec::new();
    let node = &doc.node;
    head.push((
        "node",
        labelled(node.name.as_ref().map(|n| n.as_str()), node.id.as_str()),
    ));
    head.push(("version", format!("nett {}", doc.version)));
    if node.admitted {
        head.push(("mesh", addresses(&node.mesh)));
    } else {
        head.push(("mesh", "not admitted".into()));
    }
    if !node.edge.is_empty() {
        head.push(("edge", addresses(&node.edge)));
    }
    if !node.routes.is_empty() {
        head.push(("routes", join(&node.routes)));
    }
    let mut network = vec![
        reachability(node.reachability).to_owned(),
        match node.dataplane {
            DataPlaneKind::Kernel => "kernel WireGuard".to_owned(),
            DataPlaneKind::Userspace => "userspace WireGuard".to_owned(),
            DataPlaneKind::Other => "WireGuard".to_owned(),
        },
    ];
    if let Some(port) = node.listen_port {
        network.push(format!("port {port}"));
    }
    head.push(("network", network.join(", ")));
    if let Some(nat) = &node.nat {
        let mut parts = vec![
            match nat.kind {
                NatKind::Cone => "cone",
                NatKind::Symmetric => "symmetric",
                NatKind::Unknown => "unknown",
            }
            .to_owned(),
        ];
        parts.extend(nat.ipv4.iter().chain(&nat.ipv6).map(ToString::to_string));
        head.push(("nat", parts.join(", ")));
    }
    if !node.clock_trusted {
        head.push(("clock", "not synchronized".into()));
    }
    let mut config = vec![match doc.config.applied_at {
        Some(t) => format!("applied {}", ago(t, now)),
        None => "not applied yet".to_owned(),
    }];
    if let Some(v) = doc.config.access_rules_version {
        config.push(format!("access rules v{v}"));
    }
    head.push(("config", config.join(", ")));
    out.push_str(&key_values(&head));

    out.push('\n');
    let mut peers: Vec<&PeerStatus> = doc.peers.iter().collect();
    peers.sort_unstable_by(|a, b| sort_key(a).cmp(sort_key(b)));
    if peers.is_empty() {
        out.push_str("No peers.\n");
    } else {
        let mut rows = vec![
            [
                "PEER",
                "ADDRESS",
                "STATE",
                "PATH",
                "RTT",
                "LOSS",
                "HANDSHAKE",
            ]
            .map(str::to_owned),
        ];
        for p in peers {
            rows.push([
                peer_label(p),
                p.mesh.first().map_or_else(dash, ToString::to_string),
                state(p.state).to_owned(),
                p.path.as_ref().map_or_else(dash, path_label),
                p.rtt_ms.map_or_else(dash, ms),
                p.loss.map_or_else(dash, loss),
                p.last_handshake.map_or_else(dash, |t| ago(t, now)),
            ]);
        }
        out.push_str(&table(&rows));
    }

    if !doc.problems.is_empty() {
        out.push_str("\nPROBLEMS\n");
        let mut rows = Vec::new();
        for problem in &doc.problems {
            rows.push([ago(problem.at, now), problem_text(problem)]);
        }
        out.push_str(&table(&rows));
    }
    out
}

// ---- 一个对端（第 7.2 节） ----

fn peer_detail(doc: &StatusDoc, p: &PeerStatus, now: Timestamp) -> String {
    let mut head = vec![(
        "peer",
        labelled(p.name.as_ref().map(|n| n.as_str()), p.id.as_str()),
    )];
    head.push(("mesh", addresses(&p.mesh)));
    if !p.edge.is_empty() {
        head.push(("edge", addresses(&p.edge)));
    }
    if !p.routes.is_empty() {
        head.push(("routes", join(&p.routes)));
    }
    head.push(("state", state(p.state).to_owned()));
    if let Some(path) = &p.path {
        let mut text = path_label(path);
        if let Some(endpoint) = path.endpoint {
            write!(text, " {endpoint}").ok();
        }
        if let Some(since) = path.since {
            write!(text, ", since {}", ago(since, now)).ok();
        }
        if let Some(reason) = &path.reason {
            write!(text, " ({})", switch_reason(reason)).ok();
        }
        head.push(("path", text));
    }
    if let Some(rtt) = p.rtt_ms {
        let mut quality = format!("rtt {}", ms(rtt));
        if let Some(l) = p.loss {
            write!(quality, ", loss {}", loss(l)).ok();
        }
        if let Some(j) = p.jitter_ms {
            write!(quality, ", jitter {}", ms(j)).ok();
        }
        head.push(("quality", quality));
    }
    head.push((
        "handshake",
        p.last_handshake.map_or_else(dash, |t| ago(t, now)),
    ));
    head.push((
        "received",
        p.last_received.map_or_else(dash, |t| ago(t, now)),
    ));
    head.push((
        "traffic",
        format!("{} in, {} out", bytes(p.rx_bytes), bytes(p.tx_bytes)),
    ));
    if let Some(role) = p.role {
        head.push((
            "role",
            match role {
                PeerRole::Decider => "decider".to_owned(),
                PeerRole::Follower => {
                    format!("follower ({} measures and chooses the path)", peer_label(p))
                }
                PeerRole::Other => "-".to_owned(),
            },
        ));
    }
    let mut out = key_values(&head);

    if !p.candidates.is_empty() {
        out.push('\n');
        let mut rows = vec![["CANDIDATE", "ADDRESS", "RTT", "LOSS", "STATE"].map(str::to_owned)];
        for c in &p.candidates {
            rows.push([
                kind_label(c.kind, c.relay.as_ref(), c.punched),
                c.endpoint.to_string(),
                c.rtt_ms.map_or_else(dash, ms),
                c.loss.map_or_else(dash, loss),
                match c.state {
                    CandidateStateDoc::Current => "current",
                    CandidateStateDoc::Ok => "ok",
                    CandidateStateDoc::Failing => "failing",
                    CandidateStateDoc::Untested => "untested",
                    CandidateStateDoc::Other => "-",
                }
                .to_owned(),
            ]);
        }
        out.push_str(&table(&rows));
    }

    let events: Vec<&EventRecord> = doc
        .events
        .iter()
        .filter(|e| e.fields.get("node_id").and_then(|v| v.as_str()) == Some(p.id.as_str()))
        .collect();
    if !events.is_empty() {
        out.push_str("\nEVENTS\n");
        let names = names(doc);
        let rows: Vec<[String; 2]> = events
            .iter()
            .rev()
            .map(|e| [ago(e.at, now), event_text(e, &names)])
            .collect();
        out.push_str(&table(&rows));
    }
    out
}

// ---- 文案 ----

fn dash() -> String {
    "-".to_owned()
}

fn labelled(name: Option<&str>, id: &str) -> String {
    match name {
        Some(name) => format!("{name} ({id})"),
        None => id.to_owned(),
    }
}

/// 按名字排序，没有名字的按节点 ID。
fn sort_key(p: &PeerStatus) -> &str {
    p.name.as_ref().map_or(p.id.as_str(), |n| n.as_str())
}

fn peer_label(p: &PeerStatus) -> String {
    p.name
        .as_ref()
        .map_or_else(|| p.id.to_string(), ToString::to_string)
}

fn node_label(node: &NodeRef) -> String {
    node.name
        .as_ref()
        .map_or_else(|| node.id.to_string(), ToString::to_string)
}

/// `what` 后面跟上节点名；没有节点（读不出 ID、中继不是成员）时只写 `what`。
fn with_node(what: &str, node: Option<&NodeRef>) -> String {
    match node {
        Some(node) => format!("{what} {}", node_label(node)),
        None => what.to_owned(),
    }
}

fn reachability(r: Reachability) -> &'static str {
    match r {
        Reachability::Public => "public",
        Reachability::DialOnly => "dial-only",
    }
}

fn state(s: PeerState) -> &'static str {
    match s {
        PeerState::Connected => "connected",
        PeerState::Connecting => "connecting",
        PeerState::Unreachable => "unreachable",
        PeerState::Idle => "idle",
        PeerState::NoPath => "no path",
        PeerState::Other => "-",
    }
}

fn path_label(path: &PathStatus) -> String {
    kind_label(path.kind, path.relay.as_ref(), path.punched)
}

fn kind_label(kind: PathKindDoc, relay: Option<&NodeRef>, punched: bool) -> String {
    match kind {
        PathKindDoc::Lan => "lan".to_owned(),
        PathKindDoc::Direct if punched => "direct (punched)".to_owned(),
        PathKindDoc::Direct => "direct".to_owned(),
        PathKindDoc::Relay => with_node("relay", relay),
        PathKindDoc::RelayTls => format!("{} (tls)", with_node("relay", relay)),
        PathKindDoc::Other => "-".to_owned(),
    }
}

/// 切换原因（`SwitchReason`）的说法；新版本才有的原因按名字显示。
fn switch_reason(reason: &str) -> String {
    match reason {
        "unreachable" => "unreachable".to_owned(),
        "high_loss" => "high loss".to_owned(),
        "better_type" => "better path type".to_owned(),
        "better_score" => "faster path".to_owned(),
        "relay_lost_session" => "relay lost the session".to_owned(),
        "handshake_incomplete" => "handshake did not complete".to_owned(),
        "proposed" => "proposed by the peer".to_owned(),
        "rotation" => "relay rotation".to_owned(),
        other => other.replace('_', " "),
    }
}

fn problem_text(p: &Problem) -> String {
    let reason = &p.reason;
    match p.kind {
        ProblemKind::ConfigRejected => {
            format!("desired state rejected, still using the previous one: {reason}")
        }
        ProblemKind::NotAdmitted => {
            "this node is not an admitted member and talks to no peers".to_owned()
        }
        ProblemKind::MemberRejected => {
            format!(
                "{} rejected: {reason}",
                with_node("member", p.node.as_ref())
            )
        }
        ProblemKind::AccessRulesRejected => format!("access rules rejected: {reason}"),
        ProblemKind::RoutesRejected => match &p.node {
            Some(node) => format!("routes of {} rejected: {reason}", node_label(node)),
            None => format!("routes rejected: {reason}"),
        },
        ProblemKind::DataPlaneFailed => format!("data plane error: {reason}"),
        ProblemKind::Other => reason.clone(),
    }
}

fn names(doc: &StatusDoc) -> std::collections::HashMap<String, String> {
    doc.peers
        .iter()
        .filter_map(|p| Some((p.id.to_string(), p.name.as_ref()?.to_string())))
        .chain(
            doc.node
                .name
                .as_ref()
                .map(|n| (doc.node.id.to_string(), n.to_string())),
        )
        .collect()
}

/// 一个事件的说法；新版本才有的事件按名字显示。
fn event_text(e: &EventRecord, names: &std::collections::HashMap<String, String>) -> String {
    let field = |k: &str| match e.fields.get(k) {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Null) | None => String::new(),
        Some(v) => v.to_string(),
    };
    let node = || {
        let id = field("node_id");
        names.get(&id).cloned().unwrap_or(id)
    };
    match e.name() {
        "path_switched" => format!(
            "path switched to {} ({})",
            field("to"),
            switch_reason(&field("reason"))
        ),
        "endpoint_corrected" => format!("endpoint corrected to {}", field("to")),
        "punch_started" => format!("hole punching started, round {}", field("round")),
        "punch_succeeded" => format!("hole punching succeeded: {}", field("address")),
        "punch_failed" => format!("hole punching failed: {}", field("reason")),
        "member_admitted" => format!(
            "member {} admitted, policy v{}",
            node(),
            field("policy_version")
        ),
        "member_rejected" => format!("member {} rejected: {}", node(), field("reason")),
        "member_removed" => format!("member {} removed", node()),
        "routes_applied" => format!("routes of {} v{} applied", node(), field("version")),
        "routes_rejected" => format!("routes of {} rejected: {}", node(), field("reason")),
        other => other.replace('_', " "),
    }
}

// ---- 格式 ----

fn addresses(addrs: &[std::net::IpAddr]) -> String {
    if addrs.is_empty() {
        return dash();
    }
    join(addrs)
}

fn join<T: ToString>(items: &[T]) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// 往返时间：不到 10 毫秒保留一位小数，其余取整。
fn ms(v: f64) -> String {
    if v < 10.0 {
        format!("{v:.1} ms")
    } else {
        format!("{v:.0} ms")
    }
}

/// 丢包率取整；不到 1% 但不为 0 时写 `<1%`。
fn loss(v: f64) -> String {
    let pct = v * 100.0;
    if pct > 0.0 && pct < 1.0 {
        "<1%".to_owned()
    } else {
        format!("{pct:.0}%")
    }
}

/// 十进制单位。
fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["kB", "MB", "GB", "TB", "PB"];
    if n < 1000 {
        return format!("{n} B");
    }
    let mut v = n as f64 / 1000.0;
    let mut unit = UNITS[0];
    for next in &UNITS[1..] {
        if v < 1000.0 {
            break;
        }
        v /= 1000.0;
        unit = next;
    }
    format!("{v:.1} {unit}")
}

fn ago(t: Timestamp, now: Timestamp) -> String {
    let s = (now.unix_seconds() - t.unix_seconds()).max(0);
    match s {
        0..60 => format!("{s}s ago"),
        60..3_600 => format!("{}m ago", s / 60),
        3_600..86_400 => format!("{}h ago", s / 3_600),
        _ => format!("{}d ago", s / 86_400),
    }
}

/// 键值两列，键按最长的对齐。
fn key_values(rows: &[(&str, String)]) -> String {
    let width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    rows.iter()
        .map(|(k, v)| format!("{k:width$}  {v}\n"))
        .collect()
}

/// 按列对齐，列之间两个空格，最后一列不补空格。
fn table<const N: usize>(rows: &[[String; N]]) -> String {
    let mut widths = [0usize; N];
    for row in rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let mut out = String::new();
    for row in rows {
        let mut line = String::new();
        for (i, cell) in row.iter().enumerate() {
            if i + 1 == N {
                line.push_str(cell);
            } else {
                let pad = widths[i] - cell.chars().count();
                write!(line, "{cell}{}  ", " ".repeat(pad)).ok();
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn at(seconds_ago: i64) -> String {
        Timestamp::from_unix_seconds(NOW - seconds_ago).to_string()
    }

    /// design/status.md 第 7 节示例中的那台 Mac。
    fn doc() -> StatusDoc {
        let id = |c: char| format!("node_01JD7M3XQ4W8N2K5R9T6V3B7C{c}");
        serde_json::from_value(serde_json::json!({
            "v": 1,
            "version": "0.2.0",
            "node": {
                "id": id('1'), "name": "mac", "admitted": true,
                "mesh": ["100.88.0.4", "fd00:88::4"], "edge": [], "routes": [],
                "reachability": "dial-only", "dataplane": "userspace", "listen_port": 53557,
                "nat": {"type": "cone", "ipv4": "198.51.100.7:53557", "ipv6": null},
                "clock_trusted": true, "started_at": at(86_400)
            },
            "config": {"applied_at": at(3 * 3_600), "access_rules_version": 3},
            "peers": [
                {
                    "id": id('2'), "name": "vps-02", "mesh": ["100.88.0.6", "fd00:88::6"],
                    "edge": [], "routes": [], "state": "connected", "role": "decider",
                    "path": {"kind": "direct", "relay": null, "endpoint": "198.51.100.20:41820",
                             "punched": false, "since": null, "reason": null},
                    "rtt_ms": 31.2, "loss": 0.004, "jitter_ms": 1.0,
                    "last_handshake": at(12), "last_received": at(0),
                    "rx_bytes": 1200, "tx_bytes": 800, "candidates": []
                },
                {
                    "id": id('3'), "name": "edge-vps", "mesh": ["100.88.0.1", "fd00:88::1"],
                    "edge": ["100.88.0.2", "fd00:88::2"], "routes": [], "state": "connected",
                    "role": "decider",
                    "path": {"kind": "direct", "relay": null, "endpoint": "203.0.113.10:41820",
                             "punched": false, "since": at(7_200), "reason": "better_type"},
                    "rtt_ms": 9.43, "loss": 0.0, "jitter_ms": 0.31,
                    "last_handshake": at(41), "last_received": at(1),
                    "rx_bytes": 13_200_000, "tx_bytes": 10_100_000,
                    "candidates": [
                        {"kind": "direct", "relay": null, "endpoint": "203.0.113.10:41820",
                         "punched": false, "rtt_ms": 9.43, "loss": 0.0, "state": "current"},
                        {"kind": "relay", "relay": {"id": id('2'), "name": "vps-02"},
                         "endpoint": "198.51.100.20:41822", "punched": false,
                         "rtt_ms": 12.0, "loss": 0.0, "state": "ok"}
                    ]
                },
                {
                    "id": id('4'), "name": "mac-app", "mesh": ["100.88.0.3", "fd00:88::3"],
                    "edge": [], "routes": ["192.168.147.202/32"], "state": "no_path", "role": null,
                    "path": null, "rtt_ms": null, "loss": null, "jitter_ms": null,
                    "last_handshake": null, "last_received": null,
                    "rx_bytes": 0, "tx_bytes": 0, "candidates": []
                },
                {
                    "id": id('5'), "name": "laptop", "mesh": ["100.88.0.5", "fd00:88::5"],
                    "edge": [], "routes": [], "state": "unreachable", "role": "decider",
                    "path": {"kind": "relay_tls", "relay": {"id": id('2'), "name": "vps-02"},
                             "endpoint": "198.51.100.20:443", "punched": false,
                             "since": null, "reason": null},
                    "rtt_ms": null, "loss": null, "jitter_ms": null,
                    "last_handshake": at(7_300), "last_received": at(7_300),
                    "rx_bytes": 5, "tx_bytes": 9, "candidates": []
                }
            ],
            "problems": [
                {"kind": "config_rejected", "node": null, "at": at(120),
                 "reason": "listen port 41821 is one nett itself uses"}
            ],
            "events": [
                {"at": at(7_300), "event": "path_switched", "node_id": id('3'),
                 "to": "relay 198.51.100.20:41822", "reason": "unreachable", "rehandshake": true},
                {"at": at(7_200), "event": "path_switched", "node_id": id('3'),
                 "to": "direct 203.0.113.10:41820", "reason": "better_type", "rehandshake": false},
                {"at": at(60), "event": "member_admitted", "node_id": id('5'), "policy_version": 2}
            ]
        }))
        .expect("fixture")
    }

    #[test]
    fn overview_matches_the_design() {
        let out = overview(&doc(), Timestamp::from_unix_seconds(NOW));
        assert_eq!(
            out,
            "\
node     mac (node_01JD7M3XQ4W8N2K5R9T6V3B7C1)
version  nett 0.2.0
mesh     100.88.0.4, fd00:88::4
network  dial-only, userspace WireGuard, port 53557
nat      cone, 198.51.100.7:53557
config   applied 3h ago, access rules v3

PEER      ADDRESS     STATE        PATH                RTT     LOSS  HANDSHAKE
edge-vps  100.88.0.1  connected    direct              9.4 ms  0%    41s ago
laptop    100.88.0.5  unreachable  relay vps-02 (tls)  -       -     2h ago
mac-app   100.88.0.3  no path      -                   -       -     -
vps-02    100.88.0.6  connected    direct              31 ms   <1%   12s ago

PROBLEMS
2m ago  desired state rejected, still using the previous one: listen port 41821 is one nett itself uses
"
        );
    }

    #[test]
    fn peer_detail_matches_the_design() {
        let d = doc();
        let i = find_peer(&d, "edge-vps").expect("peer");
        let out = peer_detail(&d, &d.peers[i], Timestamp::from_unix_seconds(NOW));
        assert_eq!(
            out,
            "\
peer       edge-vps (node_01JD7M3XQ4W8N2K5R9T6V3B7C3)
mesh       100.88.0.1, fd00:88::1
edge       100.88.0.2, fd00:88::2
state      connected
path       direct 203.0.113.10:41820, since 2h ago (better path type)
quality    rtt 9.4 ms, loss 0%, jitter 0.3 ms
handshake  41s ago
received   1s ago
traffic    13.2 MB in, 10.1 MB out
role       decider

CANDIDATE     ADDRESS              RTT     LOSS  STATE
direct        203.0.113.10:41820   9.4 ms  0%    current
relay vps-02  198.51.100.20:41822  12 ms   0%    ok

EVENTS
2h ago  path switched to direct 203.0.113.10:41820 (better path type)
2h ago  path switched to relay 198.51.100.20:41822 (unreachable)
"
        );
    }

    #[test]
    fn finds_peers_by_name_or_id_and_lists_them_otherwise() {
        let d = doc();
        assert_eq!(
            find_peer(&d, "node_01JD7M3XQ4W8N2K5R9T6V3B7C4").ok(),
            Some(2)
        );
        let err = find_peer(&d, "nas").expect_err("unknown").to_string();
        assert_eq!(
            err,
            "no peer `nas`; peers: edge-vps, laptop, mac-app, vps-02"
        );
    }

    #[test]
    fn formats_numbers_for_reading() {
        assert_eq!(ms(0.42), "0.4 ms");
        assert_eq!(ms(9.96), "10.0 ms");
        assert_eq!(ms(152.6), "153 ms");
        assert_eq!(loss(0.0), "0%");
        assert_eq!(loss(0.003), "<1%");
        assert_eq!(loss(0.3), "30%");
        assert_eq!(bytes(999), "999 B");
        assert_eq!(bytes(13_200_000), "13.2 MB");
        assert_eq!(bytes(2_500_000_000_000), "2.5 TB");
        let now = Timestamp::from_unix_seconds(NOW);
        let ago_s = |s| ago(Timestamp::from_unix_seconds(NOW - s), now);
        assert_eq!(ago_s(0), "0s ago");
        assert_eq!(ago_s(59), "59s ago");
        assert_eq!(ago_s(60), "1m ago");
        assert_eq!(ago_s(3 * 86_400 + 5), "3d ago");
        // 时钟回拨时不出现负数
        assert_eq!(ago_s(-5), "0s ago");
    }

    #[test]
    fn a_public_node_without_peers() {
        let mut d = doc();
        d.peers.clear();
        d.problems.clear();
        d.node.reachability = Reachability::Public;
        d.node.nat = None;
        d.node.dataplane = DataPlaneKind::Kernel;
        d.node.listen_port = Some(41820);
        let out = overview(&d, Timestamp::from_unix_seconds(NOW));
        assert!(out.contains("network  public, kernel WireGuard, port 41820\n"));
        assert!(!out.contains("nat"));
        assert!(out.ends_with("\nNo peers.\n"));
    }
}
