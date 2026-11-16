//! A relay the peer's WireGuard port cannot reach (design/mesh.md section 7.1, design/prototype.md
//! scenario 27): the network drops what leaves b's WireGuard port toward r1, while b's other ports
//! reach r1. Every path through r1 needs that leg, so a settles on r2 over TLS and stays there.

use std::path::Path;
use std::time::Duration;

use anyhow::Context as _;

use super::{
    LabNode, PathMonitor, Report, count, diagnose, events, settle_on_relay, start, start_workload,
    wait_for, write_report,
};
use crate::material;
use crate::measure::{now_ms, probe_stats, tcp_stats};
use crate::net::Underlay;
use crate::topology::Topology;

/// How long the pair is watched once it has settled. A relay path that WireGuard cannot cross but
/// that looks healthy is tried again within seconds of leaving it, and more slowly after each
/// failure; this window holds several such attempts.
const WATCH: Duration = Duration::from_secs(90);

/// The path switches a reported from `from_ms` on: `(to, reason)`.
fn switches_since(node: &LabNode, from_ms: u64) -> Vec<(String, String)> {
    events(node)
        .into_iter()
        .filter(|e| e["event"] == "path_switched" && e["at_ms"].as_u64() >= Some(from_ms))
        .map(|e| {
            let text = |key: &str| e[key].as_str().unwrap_or_default().to_owned();
            (text("to"), text("reason"))
        })
        .collect()
}

pub fn relay_port_block(topology: &Path, nett: &Path, out: &Path) -> anyhow::Result<Report> {
    let topo = Topology::load(topology)?;
    let underlay = Underlay::plan(&topo)?;
    underlay.down()?;
    let generated = material::generate(&topo, &underlay, out, false)?;
    let mut lab = start(&topo, &generated, underlay, nett)?;
    let mut report = Report::new("27-relay-port-block");
    for node in &generated.nodes {
        wait_for(node, "peers_applied", |ev| count(ev, "peers_applied") > 0)?;
    }
    let node = |name: &str| {
        generated
            .nodes
            .iter()
            .find(|n| n.name == name)
            .with_context(|| format!("node {name}"))
    };
    let (a, b) = (node("a")?, node("b")?);
    let r1 = lab.underlay.public_ipv4("r1").context("r1's address")?;
    crate::fault::block_udp_port_toward("b", material::LISTEN_PORT, r1.into())?;

    let relays = ["r1", "r2"];
    let links = relays
        .iter()
        .map(|r| {
            lab.underlay
                .node(r)
                .map(|n| (n.netns.clone(), "eth0".to_owned()))
                .with_context(|| format!("relay {r}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let monitor = PathMonitor::start(links);
    let (probe_file, tcp_file) = start_workload(&mut lab, "a", "b", b.mesh_ipv4.into(), out)?;
    let settled = settle_on_relay(&monitor, &probe_file, "nett")
        .map_err(|e| e.context(diagnose(&lab, &generated.nodes)))?;
    report.check(
        "settles-on-r2",
        relays[settled] == "r2",
        format!("traffic through {}", relays[settled]),
    );

    let from = now_ms();
    std::thread::sleep(WATCH);
    let to = now_ms();
    let later = switches_since(a, from);
    report.check(
        "stays-off-r1",
        later.is_empty(),
        format!("switches in {WATCH:?}: {later:?}"),
    );
    let probes = probe_stats(&probe_file, from, to)?;
    report.check(
        "no-interruption",
        probes.max_gap_ms < 1000,
        format!("longest gap {} ms", probes.max_gap_ms),
    );
    let tcp = tcp_stats(&tcp_file, from, to)?;
    report.check(
        "long-connection-never-reset",
        tcp.ended.is_none(),
        format!("{tcp:?}"),
    );
    if !report.passed {
        report.record("diagnosis", diagnose(&lab, &generated.nodes));
    }
    write_report(out, &report)?;
    Ok(report)
}
