//! `nett whois`, `nett ping` and `nett doctor` (design/names-and-diagnostics.md sections 4–6): who an
//! address belongs to, whether a peer answers and over which path, and what is wrong on this machine
//! with what to do about it. They only read: nothing on the machine changes.

use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs as _, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use lexopt::ValueExt as _;
use nett_mesh::status::{
    self, CandidateStateDoc, PathKindDoc, PeerState, PeerStatus, StatusDoc, WhoisKind,
};

pub const WHOIS_USAGE: &str = "usage: nett whois <address> [--json] [--socket <path>]\n\n\
Who a mesh, Edge or routed address belongs to, from what this machine has verified. Run it with sudo.";
pub const PING_USAGE: &str = "usage: nett ping <peer or address> [-c <count>] [--socket <path>]\n\n\
Sends probes through the tunnel and shows each reply's round-trip time; with sudo, also the path.";
pub const DOCTOR_USAGE: &str = "usage: nett doctor [--socket <path>]\n\n\
Checks this machine and says what to do about each problem. Run it with sudo.";

/// How long `nett ping` waits for each reply, and the time between probes.
const PING_WAIT: Duration = Duration::from_secs(2);
const PING_EVERY: Duration = Duration::from_secs(1);
/// The relay counts as fetching when it asked within this long.
const RELAY_FRESH_SECS: i64 = 60;

pub fn whois(mut parser: lexopt::Parser) -> anyhow::Result<()> {
    let (mut address, mut json) = (None, false);
    let mut socket = PathBuf::from(status::DEFAULT_SOCKET);
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Long("json") => json = true,
            lexopt::Arg::Long("socket") => socket = PathBuf::from(parser.value()?),
            lexopt::Arg::Value(v) if address.is_none() => address = Some(v.string()?),
            _ => bail!("{WHOIS_USAGE}"),
        }
    }
    let address: IpAddr = address
        .context(WHOIS_USAGE)?
        .parse()
        .context("an IPv4 or IPv6 address")?;
    let who = status::whois(&socket, address).map_err(|e| crate::status::explain(e, &socket))?;
    if json {
        println!("{}", serde_json::to_string_pretty(&who)?);
        return Ok(());
    }
    // The name is a label; the node ID is the identity (mesh.md section 11)
    let node = who
        .node
        .as_ref()
        .map(|n| crate::status::labelled(n.name.as_ref().map(|n| n.as_str()), n.id.as_str()));
    let roles: Vec<String> = who
        .roles
        .iter()
        .filter_map(|r| serde_json::to_value(r).ok()?.as_str().map(str::to_owned))
        .collect();
    let line = match (who.kind, node) {
        (WhoisKind::Member, Some(node)) => format!("{address} is {node}"),
        (WhoisKind::Edge, Some(node)) => format!("{address} is the Edge address of {node}"),
        (WhoisKind::Route, Some(node)) => format!(
            "{address} is behind {node}, in the prefix {} it advertises",
            who.prefix.map_or_else(|| "-".to_owned(), |p| p.to_string())
        ),
        _ => format!("{address} belongs to no member this machine has verified"),
    };
    println!("{line}");
    if !who.mesh.is_empty() {
        println!("  mesh   {}", crate::status::addresses(&who.mesh));
    }
    if !roles.is_empty() {
        println!("  roles  {}", roles.join(", "));
    }
    Ok(())
}

pub fn ping(mut parser: lexopt::Parser) -> anyhow::Result<()> {
    let (mut target, mut count) = (None, 4u32);
    let mut socket = PathBuf::from(status::DEFAULT_SOCKET);
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Short('c') | lexopt::Arg::Long("count") => {
                count = parser.value()?.parse().context("-c takes a number")?;
            }
            lexopt::Arg::Long("socket") => socket = PathBuf::from(parser.value()?),
            lexopt::Arg::Value(v) if target.is_none() => target = Some(v.string()?),
            _ => bail!("{PING_USAGE}"),
        }
    }
    let target = target.context(PING_USAGE)?;
    // The status gives names and paths when this user may read it; the probes need no privileges
    let doc = status::query(&socket).ok();
    let (address, label) = resolve(&target, doc.as_ref())?;
    let peer_id = doc
        .as_ref()
        .and_then(|d| d.peers.iter().find(|p| p.mesh.contains(&address)))
        .map(|p| p.id.clone());
    let udp = UdpSocket::bind(if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .context("opening a UDP socket")?;
    udp.set_read_timeout(Some(PING_WAIT))?;
    let to = SocketAddr::new(address, nett_mesh::probe::TUNNEL_PROBE_PORT);
    println!("PING {label} ({address}) through the tunnel");
    let mut rtts = Vec::new();
    let seed = (std::process::id() & 0xffff) << 16;
    for i in 0..count {
        let seq = seed | i;
        let sent = Instant::now();
        udp.send_to(&nett_mesh::probe::encode_tunnel_probe(seq), to)
            .with_context(|| format!("sending to {to}; is {label} reachable through nett0?"))?;
        match wait_reply(&udp, seq, sent) {
            Some(rtt) => {
                let path = peer_id
                    .as_ref()
                    .and_then(|id| current_path(&socket, id))
                    .map(|p| format!(", via {p}"))
                    .unwrap_or_default();
                println!(
                    "reply from {label}: {:.1} ms{path}",
                    rtt.as_secs_f64() * 1000.0
                );
                rtts.push(rtt);
            }
            None => println!("no reply from {label} within {} s", PING_WAIT.as_secs()),
        }
        if i + 1 < count {
            std::thread::sleep(PING_EVERY.saturating_sub(sent.elapsed()));
        }
    }
    print!("{}", ping_summary(count, &rtts));
    if let Some(note) = doc
        .as_ref()
        .and_then(|d| d.peers.iter().find(|p| p.mesh.contains(&address)))
        .filter(|p| p.state == PeerState::NoPath)
        .map(|_| "no access rule connects this machine and the peer; the probes test the tunnel only")
    {
        println!("{note}");
    }
    if rtts.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}

/// The address to probe: an address as given, a peer's name from the status, or the name through the
/// system resolver (`<name>.nett.internal`).
fn resolve(target: &str, doc: Option<&StatusDoc>) -> anyhow::Result<(IpAddr, String)> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        let label = doc
            .and_then(|d| d.peers.iter().find(|p| p.mesh.contains(&ip)))
            .map_or_else(|| ip.to_string(), crate::status::peer_label);
        return Ok((ip, label));
    }
    let short = target
        .strip_suffix(&format!(".{}", nett_mesh::dns::SUFFIX))
        .unwrap_or(target);
    if let Some(doc) = doc {
        let peer = &doc.peers[crate::status::find_peer(doc, short)?];
        let ip = peer
            .mesh
            .iter()
            .copied()
            .find(IpAddr::is_ipv4)
            .context("the peer has no mesh address")?;
        return Ok((ip, short.to_owned()));
    }
    let name = format!("{short}.{}:0", nett_mesh::dns::SUFFIX);
    let ip = name
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .map(|a| a.ip())
        .with_context(|| {
            format!("{short}: not an address, and {name} does not resolve; with sudo the status names it")
        })?;
    Ok((ip, short.to_owned()))
}

fn wait_reply(udp: &UdpSocket, seq: u32, sent: Instant) -> Option<Duration> {
    let mut buf = [0u8; 512];
    while sent.elapsed() < PING_WAIT {
        match udp.recv_from(&mut buf) {
            Ok((len, _)) => {
                if nett_mesh::probe::decode_tunnel_reply(&buf[..len]).is_some_and(|(s, _)| s == seq)
                {
                    return Some(sent.elapsed());
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return None;
            }
            Err(_) => return None,
        }
    }
    None
}

fn current_path(socket: &Path, id: &nett_core::id::NodeId) -> Option<String> {
    let doc = status::query(socket).ok()?;
    let peer = doc.peers.iter().find(|p| &p.id == id)?;
    peer.path.as_ref().map(crate::status::path_label)
}

fn ping_summary(sent: u32, rtts: &[Duration]) -> String {
    let received = rtts.len();
    let lost = f64::from(sent - u32::try_from(received).unwrap_or(sent)) / f64::from(sent.max(1));
    let mut out = format!(
        "{sent} sent, {received} received, {:.0}% lost\n",
        lost * 100.0
    );
    if !rtts.is_empty() {
        let ms: Vec<f64> = rtts.iter().map(|d| d.as_secs_f64() * 1000.0).collect();
        let min = ms.iter().copied().fold(f64::INFINITY, f64::min);
        let max = ms.iter().copied().fold(0.0, f64::max);
        let avg = ms.iter().sum::<f64>() / ms.len() as f64;
        out.push_str(&format!(
            "round trip min/avg/max {min:.1}/{avg:.1}/{max:.1} ms\n"
        ));
    }
    out
}

/// One finding of `nett doctor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub level: Level,
    pub what: String,
    pub found: String,
    /// What to do; empty when nothing is wrong.
    pub advice: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Ok,
    Warning,
    Problem,
}

impl Finding {
    fn ok(what: &str, found: impl Into<String>) -> Self {
        Self {
            level: Level::Ok,
            what: what.to_owned(),
            found: found.into(),
            advice: String::new(),
        }
    }

    fn warn(what: &str, found: impl Into<String>, advice: impl Into<String>) -> Self {
        Self {
            level: Level::Warning,
            what: what.to_owned(),
            found: found.into(),
            advice: advice.into(),
        }
    }

    fn problem(what: &str, found: impl Into<String>, advice: impl Into<String>) -> Self {
        Self {
            level: Level::Problem,
            what: what.to_owned(),
            found: found.into(),
            advice: advice.into(),
        }
    }
}

pub fn doctor(mut parser: lexopt::Parser) -> anyhow::Result<()> {
    let mut socket = PathBuf::from(status::DEFAULT_SOCKET);
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Long("socket") => socket = PathBuf::from(parser.value()?),
            _ => bail!("{DOCTOR_USAGE}"),
        }
    }
    let mut findings = Vec::new();
    match status::query(&socket) {
        Ok(doc) => {
            findings.extend(check_status(&doc, nett_trust::encoding::Timestamp::now()));
            findings.push(check_names(&doc));
            findings.extend(check_services(&doc));
        }
        Err(e) => findings.push(Finding::problem(
            "mesh service",
            crate::status::explain(e, &socket).to_string(),
            service_log_hint("nett-mesh", "io.gotry.nett.mesh"),
        )),
    }
    findings.extend(check_install());
    if cfg!(target_os = "linux") {
        findings.extend(check_host_firewall());
    }
    print!("{}", report(&findings));
    if findings.iter().any(|f| f.level == Level::Problem) {
        std::process::exit(1);
    }
    Ok(())
}

/// What the status itself says (design/names-and-diagnostics.md section 6).
pub fn check_status(doc: &StatusDoc, now: nett_trust::encoding::Timestamp) -> Vec<Finding> {
    let mut out = Vec::new();
    if doc.node.admitted {
        out.push(Finding::ok(
            "mesh service",
            format!(
                "nett {}, {} peers, {} connected",
                doc.version,
                doc.peers.len(),
                doc.peers
                    .iter()
                    .filter(|p| p.state == PeerState::Connected)
                    .count()
            ),
        ));
    } else {
        out.push(Finding::problem(
            "admission",
            "this machine is not an admitted member",
            "check that the site has this machine and that its desired state was delivered: \
             `nett site status` on the computer that holds the site",
        ));
    }
    for p in &doc.problems {
        out.push(Finding::problem(
            "desired state",
            crate::status::problem_text(p),
            "`sudo nett status` lists the problems with their time",
        ));
    }
    for peer in &doc.peers {
        if let Some(f) = check_peer(peer) {
            out.push(f);
        }
    }
    if !doc.node.clock_trusted {
        out.push(Finding::warn(
            "clock",
            "the clock is not synchronized",
            "enable time synchronization (for example systemd-timesyncd or chrony); two dial-only \
             machines meet on a relay by the clock when their path breaks",
        ));
    }
    if let Some(relay) = &doc.relay {
        let fresh = relay
            .fetched_at
            .is_some_and(|t| now.unix_seconds() - t.unix_seconds() <= RELAY_FRESH_SECS);
        if fresh {
            out.push(Finding::ok(
                "relay",
                format!("{} links, {} members", relay.links, relay.members),
            ));
        } else {
            out.push(Finding::problem(
                "relay",
                "nett-relay has not fetched its assignment in the last minute",
                service_log_hint("nett-relay", "-"),
            ));
        }
    }
    out
}

fn check_peer(peer: &PeerStatus) -> Option<Finding> {
    let label = crate::status::peer_label(peer);
    let what = format!("peer {label}");
    match peer.state {
        PeerState::Unreachable | PeerState::Connecting => {}
        _ => return None,
    }
    let path = peer
        .path
        .as_ref()
        .map_or_else(|| "-".to_owned(), crate::status::path_label);
    let failing = |kinds: &[PathKindDoc]| {
        let of_kind: Vec<_> = peer
            .candidates
            .iter()
            .filter(|c| kinds.contains(&c.kind))
            .collect();
        !of_kind.is_empty()
            && of_kind
                .iter()
                .all(|c| c.state == CandidateStateDoc::Failing)
    };
    let advice = if failing(&[PathKindDoc::Relay, PathKindDoc::RelayTls])
        && failing(&[PathKindDoc::Direct, PathKindDoc::Lan])
    {
        "every path fails: check that this machine can send UDP at all, and that the relays' ports \
         (UDP 41822, TCP 443 or the one set with nett site relay) are open"
            .to_owned()
    } else if failing(&[PathKindDoc::Direct]) {
        format!(
            "the direct path fails: check that {label}'s WireGuard port (UDP 41820 unless set) is \
             open in its firewall and its cloud's security group"
        )
    } else if failing(&[PathKindDoc::Relay]) {
        "the UDP relays fail: check that their relay port (UDP 41822 unless set) is open".to_owned()
    } else {
        format!("`sudo nett status {label}` shows its candidates and recent switches")
    };
    let state = if peer.state == PeerState::Connecting {
        "never answered"
    } else {
        "unreachable"
    };
    Some(Finding::problem(
        &what,
        format!("{state}, path {path}"),
        advice,
    ))
}

/// The responder answers this machine's own name, and the system resolver sends the suffix to it.
fn check_names(doc: &StatusDoc) -> Finding {
    let Some(name) = &doc.node.name else {
        return Finding::ok("names", "this machine has no name in the site");
    };
    let full = format!("{name}.{}", nett_mesh::dns::SUFFIX);
    let resolved = format!("{full}:0")
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next());
    match resolved {
        Some(a) if doc.node.mesh.contains(&a.ip()) => {
            Finding::ok("names", format!("{full} resolves to {}", a.ip()))
        }
        _ if doc
            .problems
            .iter()
            .any(|p| p.kind == status::ProblemKind::Names) =>
        {
            Finding::problem(
                "names",
                "the DNS responder is not running",
                "see the names problem above",
            )
        }
        _ if cfg!(target_os = "linux") => Finding::warn(
            "names",
            format!("{full} does not resolve through the system resolver"),
            "with systemd-resolved, restart the mesh service (it routes nett.internal to nett0); \
             without it, use `dig @<mesh address> <name>.nett.internal` or the mesh address",
        ),
        _ => Finding::warn(
            "names",
            format!("{full} does not resolve through the system resolver"),
            "restart the mesh service: it writes /etc/resolver/nett.internal",
        ),
    }
}

/// The services this status needs are running (Linux; macOS runs only the mesh and node services).
fn check_services(doc: &StatusDoc) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(systemctl) =
        nett_node::platform::linux::systemctl().filter(|_| cfg!(target_os = "linux"))
    else {
        return out;
    };
    let active = |unit: &str| {
        crate::install::run(systemctl, &["is-active", "--quiet", unit]).unwrap_or(false)
    };
    let tls = doc
        .peers
        .iter()
        .flat_map(|p| &p.candidates)
        .any(|c| c.kind == PathKindDoc::RelayTls);
    if tls && !active("nett-transport.service") {
        out.push(Finding::problem(
            "TLS transport",
            "there are paths over TLS but the transport adapter is not running",
            service_log_hint("nett-transport", "-"),
        ));
    }
    if Path::new(&format!("{}/hub.json", crate::node::DEFAULT_DIR)).exists()
        && !active("nett-node.service")
    {
        out.push(Finding::problem(
            "Hub connection",
            "this machine is connected to a Hub but nett-node is not running",
            service_log_hint("nett-node", "io.gotry.nett.node"),
        ));
    }
    out
}

/// Leftovers that keep an older setup running, and upgrades that failed.
fn check_install() -> Vec<Finding> {
    let mut out = Vec::new();
    if cfg!(target_os = "linux") {
        let overrides: Vec<String> = ["nett-mesh", "nett-node", "nett-relay", "nett-transport"]
            .iter()
            .map(|u| format!("/etc/systemd/system/{u}.service"))
            .filter(|p| Path::new(p).exists())
            .collect();
        if !overrides.is_empty() {
            out.push(Finding::problem(
                "units",
                format!("{} overrides nett's unit", overrides.join(" and ")),
                "move it away (for example to /root), run `systemctl daemon-reload`, then \
                 `sudo nett install`",
            ));
        }
    }
    let upgrade = Path::new(crate::node::DEFAULT_DIR).join(nett_node::upgrade::STATE_FILE);
    if let Ok(bytes) = std::fs::read(&upgrade)
        && let Ok(state) = serde_json::from_slice::<serde_json::Value>(&bytes)
        && let Some(failed) = state.get("failed").and_then(|f| f.as_object())
        && let Some((version, reason)) = failed.iter().next_back()
    {
        out.push(Finding::warn(
            "upgrade",
            format!(
                "version {version} was not installed: {}",
                reason.as_str().unwrap_or("-")
            ),
            "the next higher release is tried on its own; the reason above says what to fix",
        ));
    }
    out
}

/// A host firewall that drops what nett's own filter lets in on the mesh interface
/// (design/names-and-diagnostics.md section 6): ufw on, incoming denied, no rule for `nett0`.
pub fn check_host_firewall() -> Option<Finding> {
    let read = |path: &str| std::fs::read_to_string(path).unwrap_or_default();
    let rules = [read("/etc/ufw/user.rules"), read("/etc/ufw/user6.rules")];
    ufw_drops_the_mesh(
        &read("/etc/ufw/ufw.conf"),
        &read("/etc/default/ufw"),
        &rules,
    )
    .then(|| {
        Finding::problem(
            "host firewall",
            "ufw denies incoming connections and has no rule for nett0: it drops what the mesh \
             lets in, so other machines see this one as unreachable",
            "run `sudo ufw allow in on nett0`; nett filters nett0 itself, so this opens nothing \
             the access rules do not allow",
        )
    })
}

fn ufw_drops_the_mesh(conf: &str, defaults: &str, rules: &[String]) -> bool {
    let enabled = conf.lines().any(|l| l.trim() == "ENABLED=yes");
    let denies = defaults
        .lines()
        .find_map(|l| l.trim().strip_prefix("DEFAULT_INPUT_POLICY="))
        .is_some_and(|v| matches!(v.trim_matches('"'), "DROP" | "REJECT"));
    let allows_nett0 = rules
        .iter()
        .flat_map(|r| r.lines())
        .any(|l| l.contains(" -i nett0 ") && l.ends_with("-j ACCEPT"));
    enabled && denies && !allows_nett0
}

fn service_log_hint(systemd: &str, launchd: &str) -> String {
    if cfg!(target_os = "macos") && launchd != "-" {
        format!("see `sudo launchctl print system/{launchd}` and /var/log/nett/")
    } else {
        format!("see `journalctl -u {systemd}` and `systemctl status {systemd}`")
    }
}

/// The findings, one line each, worst first, with advice under the ones that are not ok.
pub fn report(findings: &[Finding]) -> String {
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by_key(|f| std::cmp::Reverse(f.level));
    let width = sorted.iter().map(|f| f.what.len()).max().unwrap_or(0);
    let mut out = String::new();
    for f in &sorted {
        let word = match f.level {
            Level::Ok => "ok",
            Level::Warning => "warning",
            Level::Problem => "problem",
        };
        out.push_str(&format!("{word:<8} {:<width$}  {}\n", f.what, f.found));
        if !f.advice.is_empty() {
            out.push_str(&format!("{:<8} {:<width$}  → {}\n", "", "", f.advice));
        }
    }
    let problems = findings
        .iter()
        .filter(|f| f.level == Level::Problem)
        .count();
    out.push_str(&match problems {
        0 => "No problems found.\n".to_owned(),
        1 => "1 problem found.\n".to_owned(),
        n => format!("{n} problems found.\n"),
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ufw_that_denies_incoming_drops_the_mesh_until_nett0_is_allowed() {
        let on = "# /etc/ufw/ufw.conf\nENABLED=yes\nLOGLEVEL=low\n";
        let deny = "IPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\n";
        let ssh_only =
            "*filter\n-A ufw-user-input -p tcp --dport 22 -j ACCEPT\nCOMMIT\n".to_owned();
        let with_nett0 = format!(
            "{ssh_only}### tuple ### allow any any 0.0.0.0/0 any 0.0.0.0/0 in_nett0\n\
             -A ufw-user-input -i nett0 -j ACCEPT\n"
        );
        assert!(ufw_drops_the_mesh(
            on,
            deny,
            std::slice::from_ref(&ssh_only)
        ));
        assert!(!ufw_drops_the_mesh(
            on,
            deny,
            &[ssh_only.clone(), with_nett0]
        ));
        assert!(!ufw_drops_the_mesh(
            "ENABLED=no\n",
            deny,
            std::slice::from_ref(&ssh_only)
        ));
        assert!(!ufw_drops_the_mesh(
            on,
            "DEFAULT_INPUT_POLICY=\"ACCEPT\"\n",
            std::slice::from_ref(&ssh_only)
        ));
        // No ufw on this machine
        assert!(!ufw_drops_the_mesh("", "", &[String::new(), String::new()]));
    }

    fn doc() -> StatusDoc {
        serde_json::from_value(serde_json::json!({
            "v": 1, "version": "0.2.0",
            "node": {"id": "node_01J00000000000000000000001", "name": "mac", "admitted": true,
                "mesh": ["100.88.0.4", "fd00:88::4"], "edge": [], "routes": [], "reachability": "dial-only",
                "dataplane": "userspace", "listen_port": 53557, "nat": null, "clock_trusted": true,
                "started_at": "2026-11-11T00:00:00Z"},
            "config": {"applied_at": null, "access_rules_version": 3},
            "peers": [{
                "id": "node_01J00000000000000000000002", "name": "nas", "mesh": ["100.88.0.6"],
                "edge": [], "routes": [], "state": "unreachable", "role": "decider",
                "path": {"kind": "relay", "relay": {"id": "node_01J00000000000000000000003", "name": "edge-vps"},
                         "endpoint": "198.51.100.1:41822", "punched": false, "since": null, "reason": null},
                "rtt_ms": null, "loss": null, "jitter_ms": null, "last_handshake": null,
                "last_received": null, "rx_bytes": 0, "tx_bytes": 0,
                "candidates": [
                    {"kind": "relay", "relay": {"id": "node_01J00000000000000000000003", "name": "edge-vps"},
                     "endpoint": "198.51.100.1:41822", "punched": false, "rtt_ms": null, "loss": null,
                     "state": "failing"},
                    {"kind": "direct", "relay": null, "endpoint": "203.0.113.6:41820", "punched": false,
                     "rtt_ms": null, "loss": null, "state": "failing"}]
            }],
            "problems": [], "events": []
        }))
        .expect("status")
    }

    #[test]
    fn an_unreachable_peer_is_a_problem_with_its_likely_cause() {
        let findings = check_status(&doc(), nett_trust::encoding::Timestamp::now());
        let peer = findings
            .iter()
            .find(|f| f.what == "peer nas")
            .expect("the peer is checked");
        assert_eq!(peer.level, Level::Problem);
        assert!(
            peer.found.contains("unreachable, path relay edge-vps"),
            "{}",
            peer.found
        );
        assert!(peer.advice.contains("every path fails"), "{}", peer.advice);
        let text = report(&findings);
        assert!(text.starts_with("problem"), "worst first: {text}");
        assert!(text.ends_with("1 problem found.\n"), "{text}");
    }

    #[test]
    fn a_healthy_status_has_no_problems() {
        let mut d = doc();
        d.peers[0].state = PeerState::Connected;
        let findings = check_status(&d, nett_trust::encoding::Timestamp::now());
        assert!(
            findings.iter().all(|f| f.level == Level::Ok),
            "{findings:?}"
        );
        assert!(report(&findings).ends_with("No problems found.\n"));
    }

    #[test]
    fn a_stale_relay_and_an_unsynchronized_clock_are_reported() {
        let mut d = doc();
        d.peers.clear();
        d.node.clock_trusted = false;
        d.relay = Some(status::RelayStatus {
            port: 41822,
            tls_port: Some(443),
            members: 2,
            links: 1,
            fingerprint: None,
            fetched_at: Some(nett_trust::encoding::Timestamp::from_unix_seconds(1)),
        });
        let findings = check_status(&d, nett_trust::encoding::Timestamp::now());
        let level = |what: &str| findings.iter().find(|f| f.what == what).map(|f| f.level);
        assert_eq!(level("relay"), Some(Level::Problem));
        assert_eq!(level("clock"), Some(Level::Warning));
    }

    #[test]
    fn the_ping_summary_counts_losses() {
        let text = ping_summary(
            4,
            &[
                Duration::from_millis(10),
                Duration::from_millis(30),
                Duration::from_millis(20),
            ],
        );
        assert_eq!(
            text,
            "4 sent, 3 received, 25% lost\nround trip min/avg/max 10.0/20.0/30.0 ms\n"
        );
        assert_eq!(ping_summary(2, &[]), "2 sent, 0 received, 100% lost\n");
    }
}
