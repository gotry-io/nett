//! A lossy direct path (design/mesh.md section 8.2, design/prototype.md scenario 28): a's packets
//! to b's public address lose 20% for five minutes while the relays stay clean. a leaves direct,
//! as a failure when the loss goes over the failure rate or for a relay that scores far better;
//! direct still answers most probes, so a stays on a relay while the loss lasts and returns once it
//! ends.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Context as _;

use super::{
    Report, count, diagnose, start, start_workload, switches_since, wait_for, write_report,
};
use crate::material;
use crate::measure::{PROBE_INTERVAL, now_ms, probe_stats, tcp_stats};
use crate::net::Underlay;
use crate::topology::Topology;

const LOSS: &str = "20%";
const LOSSY: Duration = Duration::from_secs(300);
/// A minute of direct probes with little loss, and room for the probe interval.
const RETURN_LIMIT: Duration = Duration::from_secs(90);

pub fn lossy_direct(topology: &Path, nett: &Path, out: &Path) -> anyhow::Result<Report> {
    let topo = Topology::load(topology)?;
    let underlay = Underlay::plan(&topo)?;
    underlay.down()?;
    let generated = material::generate(&topo, &underlay, out, false)?;
    let mut lab = start(&topo, &generated, underlay, nett)?;
    let mut report = Report::new("28-lossy-direct");
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
    crate::fault::prepare_delay("a", &["loss".into(), LOSS.into()])?;
    std::thread::sleep(Duration::from_secs(10));
    let before = switches_since(a, 0);
    report.check(
        "start:direct",
        before.last().is_none_or(|(to, _)| to.starts_with("direct")),
        format!("{before:?}"),
    );

    // Only the direct path loses packets
    let lossy_at = now_ms();
    crate::fault::route_delay("a", b_public)?;
    std::thread::sleep(LOSSY);
    let clean_at = now_ms();
    crate::fault::clear_eth0("a")?;
    let during = switches_since(a, lossy_at);
    report.check(
        "lossy:leaves-direct",
        during.first().is_some_and(|(to, reason)| {
            // The loss also makes direct score far worse than the relays
            to.starts_with("relay") && (reason == "high_loss" || reason == "better_score")
        }),
        format!("{during:?}"),
    );
    report.check(
        "lossy:stays-on-relay",
        !during.iter().any(|(to, _)| to.starts_with("direct")),
        format!("{} switches: {during:?}", during.len()),
    );
    let probes = probe_stats(&probe_file, lossy_at, clean_at)?;
    let expected = (clean_at - lossy_at) / u64::try_from(PROBE_INTERVAL.as_millis())?;
    report.record(
        "lossy:probe-delivery",
        format!(
            "{} of {expected} probes, longest gap {} ms",
            probes.received, probes.max_gap_ms
        ),
    );

    let started = Instant::now();
    let back = loop {
        let back = switches_since(a, clean_at)
            .into_iter()
            .find(|(to, _)| to.starts_with("direct"));
        if back.is_some() || started.elapsed() >= RETURN_LIMIT {
            break back.map(|s| (started.elapsed(), s));
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    report.check(
        "clean:returns-to-direct",
        back.as_ref()
            .is_some_and(|(_, (_, reason))| reason == "better_type"),
        format!("{back:?}"),
    );
    let tcp = tcp_stats(&tcp_file, lossy_at, now_ms())?;
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
