//! Throughput (design/prototype.md scenario 22): iperf3 between the first two nodes of the topology,
//! over the underlying network and through the mesh, one stream and four, both directions, with the
//! round trip and the whole machine's CPU at a fixed rate. Run it once as is (kernel WireGuard on
//! Linux) and once with `--userspace` on both nodes to compare the data planes on the same machine;
//! with `relay-only.toml` the mesh path goes through the relay, and with `relay-obfs-only.toml`
//! through it over obfuscated UDP (design/obfuscation.md section 9). Without rate limits the numbers
//! measure how fast each data plane handles packets on this CPU; every namespace shares the kernel,
//! so the CPU counts both ends and the relay.

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
/// Round trips sampled on each path, and how far apart.
const PINGS: &str = "500";
const PING_INTERVAL: &str = "0.01";
/// The rate at which the CPU is compared: one every path here carries.
const FIXED_RATE: &str = "200M";

pub fn throughput(
    topology: &Path,
    nett: &Path,
    out: &Path,
    seconds: u64,
    rate_mbit: Option<u32>,
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
    if let Some(mbit) = rate_mbit {
        let netem = crate::fault::Netem {
            rate_kbit: Some(mbit.saturating_mul(1000)),
            ..crate::fault::Netem::default()
        };
        crate::fault::set_link(&lab.underlay, &a.name, &netem)?;
        report.record(
            "link",
            format!("{mbit} Mbit/s each way on {}'s link", a.name),
        );
    }
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
        match rtt(&ns_a, &target) {
            Ok(text) => report.record(&format!("{path}:round-trip"), text),
            Err(e) => report.check(&format!("{path}:round-trip"), false, format!("{e:#}")),
        }
        match cpu_at_fixed_rate(&ns_a, &target, seconds) {
            Ok(text) => report.record(&format!("{path}:cpu-at-{FIXED_RATE}bit/s"), text),
            Err(e) => report.check(&format!("{path}:cpu"), false, format!("{e:#}")),
        }
    }
    Ok(report)
}

/// The median and 99th percentile of the round trip, in milliseconds.
fn rtt(ns: &str, target: &str) -> anyhow::Result<String> {
    let out = run_with_input(
        "ip",
        [
            "netns",
            "exec",
            ns,
            "ping",
            "-n",
            "-c",
            PINGS,
            "-i",
            PING_INTERVAL,
            "-W",
            "1",
            target,
        ],
        None,
        Duration::from_secs(60),
    )?;
    let mut times: Vec<f64> = out
        .lines()
        .filter_map(|l| l.split("time=").nth(1)?.split(' ').next()?.parse().ok())
        .collect();
    anyhow::ensure!(!times.is_empty(), "no replies");
    times.sort_by(f64::total_cmp);
    let at = |p: f64| {
        let i = ((times.len() - 1) as f64 * p).round() as usize;
        times[i]
    };
    Ok(format!(
        "median {:.3} ms, p99 {:.3} ms, {} of {PINGS} replies",
        at(0.5),
        at(0.99),
        times.len()
    ))
}

/// The whole machine's CPU while iperf3 sends at [`FIXED_RATE`], in cores busy.
fn cpu_at_fixed_rate(ns: &str, target: &str, seconds: u64) -> anyhow::Result<String> {
    let args = [
        "netns",
        "exec",
        ns,
        "iperf3",
        "-c",
        target,
        "-p",
        PORT,
        "-t",
        &seconds.to_string(),
        "-b",
        FIXED_RATE,
        "-J",
    ];
    let before = cpu_jiffies()?;
    let json = run_with_input("ip", args, None, Duration::from_secs(seconds + 30))?;
    let after = cpu_jiffies()?;
    let (mbit, _) = rate(&json)?;
    let busy = (after.0 - before.0) as f64;
    let total = (after.1 - before.1) as f64;
    Ok(format!(
        "{:.2} cores busy at {mbit:.0} Mbit/s",
        busy / total.max(1.0) * after.2 as f64
    ))
}

/// Busy and total jiffies of all CPUs, and how many CPUs the kernel counts, from `/proc/stat`: the
/// machine's, whatever CPUs this process may use.
fn cpu_jiffies() -> anyhow::Result<(u64, u64, usize)> {
    let stat = std::fs::read_to_string("/proc/stat").context("reading /proc/stat")?;
    let cpus = stat
        .lines()
        .filter(|l| {
            l.strip_prefix("cpu")
                .is_some_and(|n| n.starts_with(|c: char| c.is_ascii_digit()))
        })
        .count();
    let line = stat.lines().next().context("an empty /proc/stat")?;
    let fields: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|f| f.parse().ok())
        .collect();
    // user nice system idle iowait irq softirq steal
    anyhow::ensure!(fields.len() >= 8, "unexpected /proc/stat: {line}");
    let idle = fields[3] + fields[4];
    let total: u64 = fields[..8].iter().sum();
    Ok((total - idle, total, cpus.max(1)))
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
