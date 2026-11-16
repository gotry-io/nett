//! A `public` member's WireGuard port changes while it runs (design/mesh.md sections 5.2 and 5.5,
//! design/prototype.md scenario 29): every desired state and every relay's assignment move b from
//! the lab port to another, and every node and relay reloads. During an outage on the direct path
//! a goes through a relay, which forwards to b's new port; b's probes on the WireGuard port move
//! with it, so its direct path still answers probes and a returns to it on the new port.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use serde_json::Value;

use super::{
    LabNode, Report, count, diagnose, start, start_workload, switches_since, wait_for, write_report,
};
use crate::cmd::run;
use crate::material::{self, LISTEN_PORT};
use crate::measure::{now_ms, probe_stats, tcp_stats};
use crate::net::Underlay;
use crate::topology::Topology;

/// Outside the ports nett uses itself on the host (41821, 41830-41845).
const NEW_PORT: u16 = 41850;
/// Long enough for every peer to reload and for a's candidates to be probed on the new address.
const SETTLE: Duration = Duration::from_secs(20);
/// About 3 seconds to leave, as in scenario 1.
const LEAVE_LIMIT: Duration = Duration::from_secs(10);
/// How long the outage lasts after a leaves direct; the probe stream is measured from
/// [`RELAY_SETTLE`] after the switch, once the handshake through the relay has completed.
const RELAY_HOLD: Duration = Duration::from_secs(10);
const RELAY_SETTLE: Duration = Duration::from_secs(3);
/// The first failure is followed by fast probing, as in scenario 8.
const RETURN_LIMIT: Duration = Duration::from_secs(10);

/// Points every address of b's WireGuard port at the new port.
fn retarget(value: &mut Value, ip: IpAddr) {
    match value {
        Value::String(text) => {
            if let Ok(addr) = text.parse::<SocketAddr>()
                && addr.ip() == ip
                && addr.port() == LISTEN_PORT
            {
                *text = SocketAddr::new(ip, NEW_PORT).to_string();
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|v| retarget(v, ip)),
        Value::Object(map) => map.values_mut().for_each(|v| retarget(v, ip)),
        _ => {}
    }
}

/// How long it took until `node` switched to a path that satisfies `want`, if it did within `limit`.
fn wait_switch(
    node: &LabNode,
    from_ms: u64,
    limit: Duration,
    want: impl Fn(&str) -> bool,
) -> Option<Duration> {
    let started = Instant::now();
    while started.elapsed() < limit {
        if switches_since(node, from_ms).iter().any(|(to, _)| want(to)) {
            return Some(started.elapsed());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

fn read_json(file: &Path) -> anyhow::Result<Value> {
    let text = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    serde_json::from_slice(&text).with_context(|| format!("parsing {}", file.display()))
}

fn write_json(file: &Path, doc: &Value) -> anyhow::Result<()> {
    std::fs::write(file, serde_json::to_vec_pretty(doc)?)
        .with_context(|| format!("writing {}", file.display()))
}

pub fn port_change(topology: &Path, nett: &Path, out: &Path) -> anyhow::Result<Report> {
    let topo = Topology::load(topology)?;
    let underlay = Underlay::plan(&topo)?;
    underlay.down()?;
    let generated = material::generate(&topo, &underlay, out, false)?;
    let mut lab = start(&topo, &generated, underlay, nett)?;
    let mut report = Report::new("29-port-change");
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
    let b_public = lab
        .underlay
        .public_ipv4("b")
        .context("b's public address")?;
    let (probe_file, tcp_file) = start_workload(&mut lab, "a", "b", b.mesh_ipv4.into(), out)?;
    std::thread::sleep(Duration::from_secs(10));
    let before = switches_since(a, 0);
    report.check(
        "start:direct",
        before.last().is_none_or(|(to, _)| to.starts_with("direct")),
        format!("{before:?}"),
    );

    let changed_at = now_ms();
    for n in &generated.nodes {
        let file = n.dir.join("desired.json");
        let mut doc = read_json(&file)?;
        retarget(&mut doc, b_public.into());
        if n.name == "b" {
            doc["listen_port"] = NEW_PORT.into();
        }
        write_json(&file, &doc)?;
        let pid = lab
            .pid(&n.name)
            .with_context(|| format!("process of {}", n.name))?;
        run("kill", ["-HUP", &pid.to_string()])?;
    }
    // A relay keeps running and applies its changed assignment in place
    for (name, relay) in &lab.relays {
        let file = node(name)?.dir.join("relay.json");
        let mut doc = read_json(&file)?;
        retarget(&mut doc, b_public.into());
        write_json(&file, &doc)?;
        run("kill", ["-HUP", &relay.id().to_string()])?;
    }
    let moved = wait_for(b, "its interface on the new port", |ev| {
        ev.iter()
            .any(|e| e["event"] == "interface_ready" && e["listen_port"] == NEW_PORT)
    });
    report.check("b:listens-on-new-port", moved.is_ok(), format!("{moved:?}"));
    std::thread::sleep(SETTLE);

    // A short outage on the direct path: a leaves it, and comes back only if b still answers
    // probes on its WireGuard port
    let cut_at = now_ms();
    crate::fault::prepare_delay("a", &["loss".into(), "100%".into()])?;
    crate::fault::route_delay("a", b_public)?;
    let left = wait_switch(a, cut_at, LEAVE_LIMIT, |to| to.starts_with("relay"));
    report.check(
        "outage:leaves-direct",
        left.is_some(),
        format!("{:?}", switches_since(a, cut_at)),
    );
    let left_at = now_ms();
    std::thread::sleep(RELAY_HOLD);
    let relayed = probe_stats(
        &probe_file,
        left_at + u64::try_from(RELAY_SETTLE.as_millis())?,
        now_ms(),
    )?;
    report.check(
        "outage:relay-carries-tunnel",
        relayed.received > 0 && relayed.max_gap_ms < 1000,
        format!(
            "{} probes, longest gap {} ms: {:?}",
            relayed.received,
            relayed.max_gap_ms,
            switches_since(a, cut_at)
        ),
    );
    let restored_at = now_ms();
    crate::fault::clear_eth0("a")?;
    let new_direct = format!("direct {}", SocketAddr::new(b_public.into(), NEW_PORT));
    let back = wait_switch(a, restored_at, RETURN_LIMIT, |to| to == new_direct);
    report.check(
        "outage:returns-to-direct-on-new-port",
        back.is_some(),
        format!("after {back:?}: {:?}", switches_since(a, changed_at)),
    );
    let tcp = tcp_stats(&tcp_file, changed_at, now_ms())?;
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
