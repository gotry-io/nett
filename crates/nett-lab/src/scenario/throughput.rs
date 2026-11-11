//! Throughput (design/prototype.md scenario 22): iperf3 between the first two nodes of the topology,
//! over the underlying network and through the mesh, one stream and four, both directions. Run it once
//! as is (kernel WireGuard on Linux) and once with `--userspace` on both nodes to compare the data
//! planes on the same machine; with `relay-only.toml` the mesh path goes through the relay. Without rate
//! limits the numbers measure how fast each data plane handles packets on this CPU.

use std::path::Path;
use std::time::Duration;

use anyhow::Context as _;

use super::{Report, count, start, wait_for};
use crate::cmd::run_with_input;
use crate::material;
use crate::net::Underlay;
use crate::topology::Topology;

/// iperf3's port on the receiving node.
const PORT: &str = "5201";

pub fn throughput(
    topology: &Path,
    nett: &Path,
    out: &Path,
    seconds: u64,
) -> anyhow::Result<Report> {
    let topo = Topology::load(topology)?;
    let underlay = Underlay::plan(&topo)?;
    underlay.down()?;
    let generated = material::generate(&topo, &underlay, out, false)?;
    let mut lab = start(&topo, &generated, underlay, nett)?;
    let mut report = Report::new("throughput");
    let (a, b) = (&generated.nodes[0], &generated.nodes[1]);
    for node in &generated.nodes {
        wait_for(node, "peers_applied", |ev| count(ev, "peers_applied") > 0)?;
    }
    let ns_a = lab.underlay.node(&a.name).context("node a")?.netns.clone();
    let ns_b = lab.underlay.node(&b.name).context("node b")?.netns.clone();
    let under_b = lab.underlay.node(&b.name).context("node b")?.ipv4;
    let reachable = super::ping(&ns_a, &b.mesh_ipv4.to_string());
    report.check(
        "connected",
        reachable.is_ok(),
        reachable.unwrap_or_else(|e| format!("{e:#}")),
    );
    lab.tool(
        &ns_b,
        "iperf3",
        &["-s", "-p", PORT],
        &out.join("iperf3-server.log"),
    )?;
    std::thread::sleep(Duration::from_millis(500));
    let plane = if a.userspace { "userspace" } else { "kernel" };
    report.record("data plane", plane.to_owned());
    for (path, target) in [
        ("underlay", under_b.to_string()),
        ("mesh", b.mesh_ipv4.to_string()),
    ] {
        for streams in ["1", "4"] {
            for reverse in [false, true] {
                let mut args = vec![
                    "netns".to_owned(),
                    "exec".to_owned(),
                    ns_a.clone(),
                    "iperf3".to_owned(),
                    "-c".to_owned(),
                    target.clone(),
                    "-p".to_owned(),
                    PORT.to_owned(),
                    "-t".to_owned(),
                    seconds.to_string(),
                    "-P".to_owned(),
                    streams.to_owned(),
                    "-J".to_owned(),
                ];
                if reverse {
                    args.push("-R".to_owned());
                }
                let direction = if reverse { "b->a" } else { "a->b" };
                let name = format!("{path}:{streams}-stream:{direction}");
                let result = run_with_input("ip", &args, None, Duration::from_secs(seconds + 30))
                    .and_then(|json| rate(&json));
                match result {
                    Ok((mbit, Some(retransmits))) => report.record(
                        &name,
                        format!("{mbit:.0} Mbit/s, {retransmits} retransmits"),
                    ),
                    Ok((mbit, None)) => report.record(&name, format!("{mbit:.0} Mbit/s")),
                    Err(e) => report.check(&name, false, format!("{e:#}")),
                }
            }
        }
    }
    Ok(report)
}

/// The received rate (Mbit/s) and the sender's TCP retransmissions in an iperf3 JSON report:
/// retransmissions show loss in the data plane that the rate alone hides.
fn rate(json: &str) -> anyhow::Result<(f64, Option<u64>)> {
    let value: serde_json::Value = serde_json::from_str(json).context("iperf3 JSON")?;
    let mbit = value
        .pointer("/end/sum_received/bits_per_second")
        .and_then(serde_json::Value::as_f64)
        .map(|b| b / 1e6)
        .context("iperf3 reported no received rate")?;
    let retransmits = value
        .pointer("/end/sum_sent/retransmits")
        .and_then(serde_json::Value::as_u64);
    Ok((mbit, retransmits))
}
