//! WireGuard identified and blocked (design/prototype.md scenario 32, design/obfuscation.md
//! section 5): a censor upstream of a drops everything a sends to an address and port once it sees
//! a WireGuard message go there. The pair moves to obfuscated UDP through r1 and stays there, a
//! records the endpoint it lost, and after a restart it starts off that endpoint.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use nett_mesh::status::{CandidateStateDoc, PathKindDoc, StatusDoc};

use super::{
    Report, count, diagnose, events, nett_status, start, start_workload, switches_since, wait_for,
    write_report,
};
use crate::material::{self, LabNode, RELAY_PORT};
use crate::measure::{now_ms, probe_stats, tcp_stats};
use crate::net::Underlay;
use crate::topology::Topology;

/// How long a has to settle on obfuscated UDP once the censor acts: it loses direct, may try r1
/// over plain UDP, which the censor then flags too, and moves on.
const SETTLE: Duration = Duration::from_secs(90);
/// How long the pair is watched once it has settled.
const WATCH: Duration = Duration::from_secs(60);

pub fn wireguard_block(topology: &Path, nett: &Path, out: &Path) -> anyhow::Result<Report> {
    let topo = Topology::load(topology)?;
    let underlay = Underlay::plan(&topo)?;
    underlay.down()?;
    let generated = material::generate(&topo, &underlay, out, false)?;
    let mut lab = start(&topo, &generated, underlay, nett)?;
    let mut report = Report::new("32-wireguard-block");
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
    let r1_udp = format!("relay {r1}:{RELAY_PORT}");
    let (probe_file, tcp_file) = start_workload(&mut lab, "a", "b", b.mesh_ipv4.into(), out)?;
    let before = wait_path(nett, a, b, Duration::from_secs(30), |k| {
        k == PathKindDoc::Direct
    });
    report.check(
        "starts-direct",
        before.is_ok(),
        before.err().map(|e| format!("{e:#}")).unwrap_or_default(),
    );

    let fault_at = now_ms();
    crate::fault::block_wireguard_upstream(&lab.underlay, "a")?;
    let settled = wait_path(nett, a, b, SETTLE, |k| k == PathKindDoc::RelayObfs);
    let settled_at = now_ms();
    report.check(
        "settles-on-obfuscated-udp",
        settled.is_ok(),
        format!(
            "after {} ms; switches {:?}",
            settled_at - fault_at,
            switches_since(a, fault_at)
        ),
    );
    if let Ok(status) = &settled {
        let r1_plain = candidate_state(status, b, PathKindDoc::Relay);
        report.check(
            "plain-relay-recorded-blocked",
            r1_plain == Some(CandidateStateDoc::Blocked),
            format!("r1 over UDP: {r1_plain:?}"),
        );
        report.record(
            "direct",
            format!("{:?}", candidate_state(status, b, PathKindDoc::Direct)),
        );
    }
    let outage = probe_stats(&probe_file, fault_at, settled_at)?;
    report.record("outage", format!("longest gap {} ms", outage.max_gap_ms));

    let from = now_ms();
    std::thread::sleep(WATCH);
    let to = now_ms();
    let later = switches_since(a, from);
    report.check(
        "stays-on-obfuscated-udp",
        later.is_empty(),
        format!("switches in {WATCH:?}: {later:?}"),
    );
    let probes = probe_stats(&probe_file, from, to)?;
    report.check(
        "no-interruption",
        probes.max_gap_ms < 1000,
        format!("longest gap {} ms", probes.max_gap_ms),
    );
    let tcp = tcp_stats(&tcp_file, fault_at, to)?;
    report.check(
        "long-connection-never-reset",
        tcp.ended.is_none(),
        format!("{tcp:?}"),
    );

    // The record survives a restart: a does not go back to r1 over plain UDP
    let applied = count(&events(a), "peers_applied");
    lab.stop("a")?;
    let restarted_at = now_ms();
    lab.spawn(a, nett)?;
    wait_for(a, "peers_applied after the restart", |ev| {
        count(ev, "peers_applied") > applied
    })?;
    let back = wait_path(nett, a, b, SETTLE, |k| k == PathKindDoc::RelayObfs);
    let back_at = now_ms();
    report.check(
        "restart:back-on-obfuscated-udp",
        back.is_ok(),
        format!(
            "after {} ms; switches {:?}",
            back_at - restarted_at,
            switches_since(a, restarted_at)
        ),
    );
    let onto_plain: Vec<_> = switches_since(a, restarted_at)
        .into_iter()
        .filter(|(to, _)| *to == r1_udp)
        .collect();
    let r1_plain = back
        .as_ref()
        .ok()
        .and_then(|s| candidate_state(s, b, PathKindDoc::Relay));
    report.check(
        "restart:plain-relay-still-avoided",
        onto_plain.is_empty() && r1_plain == Some(CandidateStateDoc::Blocked),
        format!("switches onto r1 over UDP {onto_plain:?}; r1 over UDP: {r1_plain:?}"),
    );
    let after = probe_stats(&probe_file, restarted_at, back_at)?;
    report.record(
        "restart:outage",
        format!("longest gap {} ms", after.max_gap_ms),
    );
    if !report.passed {
        report.record("diagnosis", diagnose(&lab, &generated.nodes));
    }
    write_report(out, &report)?;
    Ok(report)
}

/// Waits until a's path to b is of a kind `want` accepts, and returns the status that shows it.
fn wait_path(
    nett: &Path,
    a: &LabNode,
    b: &LabNode,
    within: Duration,
    want: impl Fn(PathKindDoc) -> bool,
) -> anyhow::Result<StatusDoc> {
    let deadline = Instant::now() + within;
    loop {
        let status = nett_status(nett, a);
        let kind = status.as_ref().ok().and_then(|s| {
            s.peers
                .iter()
                .find(|p| p.id == b.node_id)
                .and_then(|p| p.path.as_ref())
                .map(|p| p.kind)
        });
        if let (Ok(status), Some(kind)) = (status, kind)
            && want(kind)
        {
            return Ok(status);
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "a's path to b is {kind:?} after {within:?}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// The state of a's candidate of `kind` toward b.
fn candidate_state(
    status: &StatusDoc,
    b: &LabNode,
    kind: PathKindDoc,
) -> Option<CandidateStateDoc> {
    status
        .peers
        .iter()
        .find(|p| p.id == b.node_id)?
        .candidates
        .iter()
        .find(|c| c.kind == kind)
        .map(|c| c.state)
}
