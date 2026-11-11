//! Relays through the Hub (design/hub.md section 9 H4, design/mesh.md sections 5.2, 5.3 and 8.4):
//! the site and the Hub run in h; r1, r2, a and b join through the Hub with `nett join`; `nett site
//! relay` makes r1 and r2 relays. nett-relay and the transport adapter run in service mode and fetch
//! their configuration from the mesh process's helper socket. Checks:
//!
//! - Each relay fetches its assignment and reports its certificate; the Hub learns the fingerprint and
//!   the members then get TLS candidates;
//! - a and b, both behind symmetric NATs, reach each other through a relay over UDP;
//! - The relay process they use is killed: the decider proposes the other relay through the Hub, both
//!   move there together without rotating by time slot, and the pair stays reachable;
//! - c, on a's LAN behind the same NAT, gets a LAN direct candidate from the addresses both report, and
//!   the pair moves onto the LAN;
//! - With all of a's UDP blocked upstream, the pair moves to TLS and stays reachable;
//! - `nett site relay <relay> --off` takes the relay out of every connection.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use nett_mesh::config::Candidate;
use nett_mesh::key::PrivateKey;
use nett_site::state::State;

use super::hub::{HUB_PORT, HubLab, desired};
use super::{Lab, LabNode, Report, memory, nett_status, ping};
use crate::cmd::{run, run_in, spawn_in};
use crate::net::Underlay;
use crate::topology::Topology;

/// Upper bound for the Hub to learn the relay's fingerprint and deliver TLS candidates: the relay
/// fetches every 5 seconds, nett-node reports status every 15 seconds.
const LEARN: Duration = Duration::from_secs(60);
/// Upper bound for the pair to move to TLS after UDP is blocked.
const FALLBACK: Duration = Duration::from_secs(30);
/// Upper bound for both ends to move to the other relay through the Hub after theirs stops: about 3
/// seconds to detect the outage, then one round trip through the Hub (design/mesh.md section 8.4).
const THROUGH_HUB: Duration = Duration::from_secs(8);
const RELAYS: [&str; 2] = ["r1", "r2"];

pub fn hub_relay(topology: &Path, nett: &Path, out: &Path) -> anyhow::Result<Report> {
    let topo = Topology::load(topology)?;
    let underlay = Underlay::plan(&topo)?;
    let mut namespaces = std::collections::BTreeMap::new();
    for name in ["h", "r1", "r2", "a", "b", "c"] {
        let net = underlay
            .node(name)
            .with_context(|| format!("the hub-relay scenario needs a node `{name}`"))?;
        namespaces.insert(name, net.netns.clone());
    }
    let ns = |name: &str| -> anyhow::Result<String> {
        namespaces.get(name).cloned().context("planned node")
    };
    let net_h = underlay.node("h").context("planned node")?;
    let hub_ip = net_h.public_ipv4.unwrap_or(net_h.ipv4);
    let ns_h = ns("h")?;
    underlay.down()?;
    let mut report = Report::new("hub-relay");
    std::fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;
    underlay.up(&topo)?;
    let mut lab = Lab {
        underlay,
        processes: Vec::new(),
        relays: Vec::new(),
        helpers: Vec::new(),
    };

    // The site and the Hub, both in h
    let site = out.join("site");
    std::fs::remove_dir_all(&site).ok();
    let hub_dir = out.join("hub");
    std::fs::remove_dir_all(&hub_dir).ok();
    std::fs::create_dir_all(&hub_dir)?;
    run(
        &nett.display().to_string(),
        ["site", "init", "--dir", &site.to_string_lossy()],
    )?;
    crate::material::self_signed(hub_ip, &hub_dir)?;
    let mut h = HubLab {
        nett,
        hub_bin: nett.with_file_name("nett-hub"),
        site: site.clone(),
        hub_dir: hub_dir.clone(),
        hub_ns: ns_h.clone(),
        hub_ip,
        site_ns: ns_h.clone(),
        members: vec!["r1".into(), "r2".into(), "a".into(), "b".into(), "c".into()],
        hub: None,
    };
    let init = run_in(
        &ns_h,
        &h.hub_bin.display().to_string(),
        [
            "init",
            "--data",
            &hub_dir.to_string_lossy(),
            "--url",
            &format!("https://{hub_ip}:{HUB_PORT}"),
            "--tls-cert",
            &hub_dir.join("tls-cert.pem").to_string_lossy(),
        ],
    )?;
    let code = init
        .split_whitespace()
        .find(|w| w.starts_with("nett_lnk_"))
        .context("nett-hub init printed no link code")?
        .to_owned();
    h.start_hub()?;
    h.site_cmd(&["link", &code])?;

    // r, a and b join through the Hub: one command on the computer, one on the machine
    let mut nodes = Vec::new();
    for (name, public) in [
        ("r1", true),
        ("r2", true),
        ("a", false),
        ("b", false),
        ("c", false),
    ] {
        let mut args = vec!["add", name, "--yes"];
        if public {
            args.push("--public");
        }
        let added = h.site_cmd(&args)?;
        let token = added
            .split_whitespace()
            .find(|w| w.starts_with("nett_enr_"))
            .context("nett site add printed no token")?
            .to_owned();
        let dir = out.join(name);
        std::fs::remove_dir_all(&dir).ok();
        run(
            &nett.display().to_string(),
            ["keys", "--dir", &dir.to_string_lossy()],
        )?;
        run_in(
            &ns(name)?,
            &nett.display().to_string(),
            ["join", &token, "--dir", &dir.to_string_lossy()],
        )?;
        let doc = desired(&dir.join("desired.json"))?;
        let state = State::from_json(&std::fs::read(site.join("state.json"))?)?;
        let m = state.machine(&name.parse()?)?;
        let node = LabNode {
            name: name.to_owned(),
            node_id: doc.node_id.clone(),
            mesh_public_key: PrivateKey::load(&dir.join("mesh.key"))?.public_key(),
            mesh_ipv4: m.mesh.ipv4,
            mesh_ipv6: m.mesh.ipv6,
            edge_ipv4: None,
            dir: dir.clone(),
            tls: false,
            userspace: false,
        };
        lab.spawn(&node, nett)?;
        let child = spawn_in(
            &ns(name)?,
            nett,
            [
                "node".as_ref(),
                "--dir".as_ref(),
                dir.as_os_str(),
                "--socket".as_ref(),
                dir.join("mesh.sock").as_os_str(),
            ],
            &dir.join("node.log"),
        )?;
        lab.processes.push((format!("node:{name}"), child));
        nodes.push(node);
    }
    let (a, b, c) = (&nodes[2], &nodes[3], &nodes[4]);
    let relay_node = |name: &str| -> anyhow::Result<&LabNode> {
        nodes.iter().find(|n| n.name == name).context("relay node")
    };

    // nett-relay and the transport adapter in service mode: they fetch their configuration from the
    // helper socket next to each mesh process's status socket
    for name in RELAYS {
        let r = relay_node(name)?;
        let relay = spawn_relay(nett, &ns(name)?, r)?;
        lab.relays.push((name.into(), relay));
    }
    for node in [a, b] {
        let child = spawn_in(
            &ns(&node.name)?,
            nett,
            [
                "transport".as_ref(),
                "--socket".as_ref(),
                node.dir.join("helpers.sock").as_os_str(),
            ],
            &node.dir.join("transport.log"),
        )?;
        lab.helpers.push(child);
    }

    for name in RELAYS {
        let relayed = h.site_cmd(&["relay", name, "--yes"]);
        report.check(
            &format!("relay:{name}:listed"),
            relayed
                .as_ref()
                .is_ok_and(|o| o.contains(&format!("~ {name} runs a relay: UDP 41822, TLS 443"))),
            relayed
                .as_ref()
                .map_or_else(|e| format!("{e:#}"), Clone::clone),
        );
    }
    let allowed = h.site_cmd(&["allow", "a", "b", "--yes"]);
    report.check(
        "allow:through-the-relays",
        allowed
            .as_ref()
            .is_ok_and(|o| o.contains("+ a - b  punch, relay r1 (udp), relay r2 (udp)")),
        allowed
            .as_ref()
            .map_or_else(|e| format!("{e:#}"), Clone::clone),
    );

    // The relays fetch their assignments and report their certificates; the Hub learns the
    // fingerprints and the members get TLS candidates through both
    let deadline = Instant::now() + LEARN;
    let tls_candidates = loop {
        let doc = desired(&a.dir.join("desired.json"))?;
        let found = doc
            .paths
            .iter()
            .flat_map(|p| &p.candidates)
            .filter(|c| matches!(c, Candidate::RelayTls { .. }))
            .count();
        if found >= 2 || Instant::now() >= deadline {
            break found;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    for name in RELAYS {
        let relay_status = nett_status(nett, relay_node(name)?)?.relay;
        report.check(
            &format!("relay:{name}:fetched-and-reported"),
            relay_status
                .as_ref()
                .is_some_and(|s| s.fetched_at.is_some() && s.fingerprint.is_some() && s.links >= 1),
            format!("{relay_status:?}"),
        );
    }
    report.check(
        "relay:fingerprints-learned",
        tls_candidates >= 2,
        format!("a's desired state has {tls_candidates} TLS candidates"),
    );
    let status = h.site_cmd(&["status"]).unwrap_or_else(|e| format!("{e:#}"));
    report.record("site-status", status);

    // Behind symmetric NATs a and b cannot punch through: they connect through a relay
    let reachable = ping(&ns("a")?, &b.mesh_ipv4.to_string());
    report.check(
        "relay:a-reaches-b",
        reachable.is_ok(),
        reachable.unwrap_or_else(|e| format!("{e:#}")),
    );
    let path = |node: &LabNode, peer: &LabNode| -> Option<nett_mesh::status::PathStatus> {
        nett_status(nett, node)
            .ok()?
            .peers
            .into_iter()
            .find(|p| p.id == peer.node_id)?
            .path
    };
    let kind = |node: &LabNode, peer: &LabNode| -> String {
        path(node, peer).map_or_else(|| "-".to_owned(), |p| format!("{:?}", p.kind))
    };
    let via = |node: &LabNode, peer: &LabNode| -> Option<String> {
        path(node, peer)?.relay?.name.map(|n| n.to_string())
    };
    report.check(
        "relay:path-through-a-relay",
        kind(a, b) == "Relay",
        format!("a -> b: {} via {:?}", kind(a, b), via(a, b)),
    );

    // The relay in use stops: the decider proposes the other one through the Hub, and both ends move
    // there together without waiting for a time slot
    let used = via(a, b).context("a's path to b names its relay")?;
    let other = RELAYS
        .into_iter()
        .find(|r| *r != used)
        .context("the other relay")?;
    let events = |node: &LabNode| -> Vec<serde_json::Value> {
        std::fs::read_to_string(node.dir.join("events.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    };
    let before = (events(a).len(), events(b).len());
    let stopped = Instant::now();
    if let Some((_, mut child)) = lab
        .relays
        .iter()
        .position(|(n, _)| *n == used)
        .map(|i| lab.relays.remove(i))
    {
        child.kill().ok();
        child.wait().ok();
    }
    while (via(a, b).as_deref() != Some(other) || via(b, a).as_deref() != Some(other))
        && stopped.elapsed() < THROUGH_HUB
    {
        std::thread::sleep(Duration::from_millis(200));
    }
    let moved = stopped.elapsed();
    let reasons = |node: &LabNode, skip: usize| -> Vec<String> {
        events(node)
            .into_iter()
            .skip(skip)
            .filter(|e| e["event"] == "path_switched")
            .filter_map(|e| e["reason"].as_str().map(str::to_owned))
            .collect()
    };
    let (ra, rb) = (reasons(a, before.0), reasons(b, before.1));
    let reachable = ping(&ns("a")?, &b.mesh_ipv4.to_string());
    report.check(
        "hub-switch:both-moved",
        via(a, b).as_deref() == Some(other)
            && via(b, a).as_deref() == Some(other)
            && reachable.is_ok(),
        format!(
            "{used} stopped; after {} ms a -> b via {:?}, b -> a via {:?}; {}",
            moved.as_millis(),
            via(a, b),
            via(b, a),
            reachable.unwrap_or_else(|e| format!("{e:#}"))
        ),
    );
    report.check(
        "hub-switch:proposed-not-rotated",
        !ra.iter().chain(&rb).any(|r| r == "rotation")
            && (ra.iter().chain(&rb).any(|r| r == "proposed")),
        format!("a switched for {ra:?}, b for {rb:?}"),
    );
    // Bring the stopped relay back for what follows
    let r = relay_node(&used)?;
    let relay = spawn_relay(nett, &ns(&used)?, r)?;
    lab.relays.push((used.clone(), relay));

    // c is on a's LAN: the Hub composes a LAN direct candidate from the addresses both report, and the
    // pair moves onto it (both dial-only: the decider proposes it through the tunnel)
    h.site_cmd(&["allow", "a", "c", "--yes"])?;
    let deadline = Instant::now() + LEARN;
    let lan = loop {
        let doc = desired(&a.dir.join("desired.json"))?;
        let found = doc
            .paths
            .iter()
            .filter(|p| p.peer == c.node_id)
            .flat_map(|p| &p.candidates)
            .find_map(|c| match c {
                Candidate::Lan { endpoint } => Some(*endpoint),
                _ => None,
            });
        if found.is_some() || Instant::now() >= deadline {
            break found;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    let net_c = lab.underlay.node("c").context("planned node")?;
    report.check(
        "lan:candidate",
        lan.is_some_and(|e| e.ip() == std::net::IpAddr::V4(net_c.ipv4)),
        format!("a's LAN candidate to c: {lan:?}, c is at {}", net_c.ipv4),
    );
    let deadline = Instant::now() + FALLBACK;
    while (kind(a, c) != "Lan" || kind(c, a) != "Lan") && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
    }
    let reachable = ping(&ns("a")?, &c.mesh_ipv4.to_string());
    report.check(
        "lan:path",
        kind(a, c) == "Lan" && kind(c, a) == "Lan" && reachable.is_ok(),
        format!(
            "a -> c: {}, c -> a: {}; {}",
            kind(a, c),
            kind(c, a),
            reachable.unwrap_or_else(|e| format!("{e:#}"))
        ),
    );

    // Names and diagnostics (design/names-and-diagnostics.md): a asks its own responder for b's name,
    // pings b through the tunnel with the path shown, and the doctor finds nothing wrong
    let a_mesh = a.mesh_ipv4.to_string();
    let looked_up = run_in(&ns("a")?, "nslookup", ["b.nett.internal", &a_mesh]);
    report.check(
        "names:resolve",
        looked_up
            .as_ref()
            .is_ok_and(|o| o.contains(&b.mesh_ipv4.to_string())),
        looked_up
            .as_ref()
            .map_or_else(|e| format!("{e:#}"), Clone::clone),
    );
    let refused = run_in(&ns("a")?, "nslookup", ["example.com", &a_mesh]);
    report.check(
        "names:not-a-forwarder",
        refused
            .as_ref()
            .map_or(true, |o| !o.contains("Address: ") || o.contains("REFUSED")),
        refused.unwrap_or_else(|e| format!("{e:#}")),
    );
    let socket_a = a.dir.join("mesh.sock");
    let pinged = run_in(
        &ns("a")?,
        &nett.display().to_string(),
        [
            "ping".as_ref(),
            "b".as_ref(),
            "-c".as_ref(),
            "3".as_ref(),
            "--socket".as_ref(),
            socket_a.as_os_str(),
        ],
    );
    report.check(
        "ping:through-the-tunnel",
        pinged
            .as_ref()
            .is_ok_and(|o| o.contains("3 received") && o.contains("via relay")),
        pinged
            .as_ref()
            .map_or_else(|e| format!("{e:#}"), Clone::clone),
    );
    let whois = run_in(
        &ns("a")?,
        &nett.display().to_string(),
        [
            "whois".as_ref(),
            b.mesh_ipv4.to_string().as_ref(),
            "--socket".as_ref(),
            socket_a.as_os_str(),
        ],
    );
    report.check(
        "whois:member",
        whois.as_ref().is_ok_and(|o| o.contains("is b (")),
        whois
            .as_ref()
            .map_or_else(|e| format!("{e:#}"), Clone::clone),
    );
    let doctor = run_in(
        &ns("a")?,
        &nett.display().to_string(),
        ["doctor".as_ref(), "--socket".as_ref(), socket_a.as_os_str()],
    );
    report.check(
        "doctor:healthy",
        doctor
            .as_ref()
            .is_ok_and(|o| o.contains("No problems found")),
        doctor
            .as_ref()
            .map_or_else(|e| format!("{e:#}"), Clone::clone),
    );

    // All of a's UDP blocked upstream: the pair moves to TLS
    crate::fault::block_udp_upstream(&lab.underlay, "a")?;
    let deadline = Instant::now() + FALLBACK;
    while kind(a, b) != "RelayTls" && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
    }
    let over_tls = kind(a, b);
    let reachable = ping(&ns("a")?, &b.mesh_ipv4.to_string());
    report.check(
        "tls:fallback",
        over_tls == "RelayTls" && reachable.is_ok(),
        format!(
            "a -> b: {over_tls}; {}",
            reachable.unwrap_or_else(|e| format!("{e:#}"))
        ),
    );
    crate::fault::unblock_udp_upstream(&lab.underlay, "a")?;
    for (name, child) in &lab.relays {
        report.record(&format!("memory:relay:{name}"), memory(child.id()));
    }
    for child in &lab.helpers {
        report.record("memory:transport", memory(child.id()));
    }

    // Both relays stop: they leave every connection, and the dial-only pair is back to punching only
    h.site_cmd(&["relay", "r2", "--off", "--yes"])?;
    let off = h.site_cmd(&["relay", "r1", "--off", "--yes"]);
    report.check(
        "relay:off",
        off.as_ref().is_ok_and(|o| {
            o.contains("~ r1 stops its relay") && o.contains("~ a - b  punch only; may not connect")
        }),
        off.as_ref().map_or_else(|e| format!("{e:#}"), Clone::clone),
    );
    let current = h.wait_acked("applied", Duration::from_secs(30));
    let relay_gone = nett_status(nett, relay_node("r1")?).map(|s| s.relay.is_none());
    report.check(
        "relay:off-applied",
        current.is_ok() && relay_gone.as_ref().is_ok_and(|g| *g),
        format!("{:?}", relay_gone),
    );
    Ok(report)
}

/// nett-relay in service mode on a relay node.
fn spawn_relay(nett: &Path, ns: &str, node: &LabNode) -> anyhow::Result<std::process::Child> {
    spawn_in(
        ns,
        nett,
        [
            "relay".as_ref(),
            "--socket".as_ref(),
            node.dir.join("helpers.sock").as_os_str(),
            "--state".as_ref(),
            node.dir.join("relay").as_os_str(),
        ],
        &node.dir.join("relay.log"),
    )
}
