//! Relays through the Hub (design/hub.md section 9 H4, design/mesh.md sections 5.2 and 5.3): the
//! site and the Hub run in h; r, a and b join through the Hub with `nett join`; `nett site relay r`
//! makes r a relay. nett-relay and the transport adapter run in service mode and fetch their
//! configuration from the mesh process's helper socket. Checks:
//!
//! - The relay fetches its assignment and reports its certificate; the Hub learns the fingerprint and
//!   the members then get TLS candidates through r;
//! - a and b, both behind symmetric NATs, reach each other through r over UDP;
//! - With all of a's UDP blocked upstream, the pair moves to TLS through r and stays reachable;
//! - `nett site relay r --off` takes r out of every connection.

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

pub fn hub_relay(topology: &Path, nett: &Path, out: &Path) -> anyhow::Result<Report> {
    let topo = Topology::load(topology)?;
    let underlay = Underlay::plan(&topo)?;
    let mut namespaces = std::collections::BTreeMap::new();
    for name in ["h", "r", "a", "b"] {
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
        members: vec!["r".into(), "a".into(), "b".into()],
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
    for (name, public) in [("r", true), ("a", false), ("b", false)] {
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
    let (r, a, b) = (&nodes[0], &nodes[1], &nodes[2]);

    // nett-relay and the transport adapter in service mode: they fetch their configuration from the
    // helper socket next to each mesh process's status socket
    let relay = spawn_in(
        &ns("r")?,
        nett,
        [
            "relay".as_ref(),
            "--socket".as_ref(),
            r.dir.join("helpers.sock").as_os_str(),
            "--state".as_ref(),
            r.dir.join("relay").as_os_str(),
        ],
        &r.dir.join("relay.log"),
    )?;
    lab.relays.push(("r".into(), relay));
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

    let relayed = h.site_cmd(&["relay", "r", "--yes"]);
    report.check(
        "relay:listed",
        relayed
            .as_ref()
            .is_ok_and(|o| o.contains("~ r runs a relay: UDP 41822, TLS 443")),
        relayed
            .as_ref()
            .map_or_else(|e| format!("{e:#}"), Clone::clone),
    );
    let allowed = h.site_cmd(&["allow", "a", "b", "--yes"]);
    report.check(
        "allow:through-the-relay",
        allowed
            .as_ref()
            .is_ok_and(|o| o.contains("+ a - b  punch, relay r (udp)")),
        allowed
            .as_ref()
            .map_or_else(|e| format!("{e:#}"), Clone::clone),
    );

    // The relay fetches its assignment and reports its certificate; the Hub learns the fingerprint
    // and the members get a TLS candidate through r
    let deadline = Instant::now() + LEARN;
    let tls_candidate = loop {
        let doc = desired(&a.dir.join("desired.json"))?;
        let found = doc
            .paths
            .iter()
            .flat_map(|p| &p.candidates)
            .any(|c| matches!(c, Candidate::RelayTls { .. }));
        if found || Instant::now() >= deadline {
            break found;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    let relay_status = nett_status(nett, r)?.relay;
    report.check(
        "relay:fetched-and-reported",
        relay_status
            .as_ref()
            .is_some_and(|s| s.fetched_at.is_some() && s.fingerprint.is_some() && s.links >= 1),
        format!("{relay_status:?}"),
    );
    report.check(
        "relay:fingerprint-learned",
        tls_candidate,
        "a's desired state has a TLS candidate through r",
    );
    let status = h.site_cmd(&["status"]).unwrap_or_else(|e| format!("{e:#}"));
    report.record("site-status", status);

    // Behind symmetric NATs a and b cannot punch through: they connect through r
    let reachable = ping(&ns("a")?, &b.mesh_ipv4.to_string());
    report.check(
        "relay:a-reaches-b",
        reachable.is_ok(),
        reachable.unwrap_or_else(|e| format!("{e:#}")),
    );
    let kind = |node: &LabNode, peer: &LabNode| -> String {
        nett_status(nett, node)
            .ok()
            .and_then(|s| {
                s.peers
                    .into_iter()
                    .find(|p| p.id == peer.node_id)
                    .and_then(|p| p.path)
            })
            .map_or_else(|| "-".to_owned(), |p| format!("{:?}", p.kind))
    };
    report.check(
        "relay:path-through-r",
        kind(a, b) == "Relay",
        format!("a -> b: {}", kind(a, b)),
    );

    // All of a's UDP blocked upstream: the pair moves to TLS through r
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

    // The relay stops: r leaves every connection, and the dial-only pair is back to punching only
    let off = h.site_cmd(&["relay", "r", "--off", "--yes"]);
    report.check(
        "relay:off",
        off.as_ref().is_ok_and(|o| {
            o.contains("~ r stops its relay") && o.contains("~ a - b  punch only; may not connect")
        }),
        off.as_ref().map_or_else(|e| format!("{e:#}"), Clone::clone),
    );
    let current = h.wait_acked("applied", Duration::from_secs(30));
    let relay_gone = nett_status(nett, r).map(|s| s.relay.is_none());
    report.check(
        "relay:off-applied",
        current.is_ok() && relay_gone.as_ref().is_ok_and(|g| *g),
        format!("{:?}", relay_gone),
    );
    Ok(report)
}
