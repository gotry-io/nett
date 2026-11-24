//! A machine's own obfuscated port (design/prototype.md scenario 33, ADR 0031): b is public and
//! offers one, and a fault on b drops every plain WireGuard message to and from it, as a censor that
//! identified its WireGuard traffic would. a reaches b's port through the obfuscated transport's
//! loopback port on kernel WireGuard, c from its WireGuard socket on the userspace data plane; both
//! connect directly, with the first handshake already obfuscated, and stay there. With direct UDP to
//! b cut, both reach it through r1, whose leg to b goes to b's obfuscated port. When b's desired
//! state drops the port, its nett daemon starts again on kernel WireGuard, and when it gives the port
//! back, on the userspace data plane.

use std::path::Path;
use std::time::Duration;

use anyhow::Context as _;
use nett_mesh::status::{DataPlaneKind, PathKindDoc};
use serde_json::Value;

use super::wireguard_block::{candidates, wait_path};
use super::{
    Lab, Report, count, diagnose, events, nett_status, start, start_workload, switches_since,
    wait_for, write_report,
};
use crate::cmd::run;
use crate::material::{self, LabNode};
use crate::measure::{now_ms, probe_stats};
use crate::net::Underlay;
use crate::topology::Topology;

/// How long a pair has to reach the path a step expects.
const SETTLE: Duration = Duration::from_secs(60);
/// How long the pairs are watched once on b's obfuscated port.
const WATCH: Duration = Duration::from_secs(30);
/// How long b's nett daemon has to exit once its desired state needs the other data plane.
const EXIT_WITHIN: Duration = Duration::from_secs(10);
/// Between the restart of b and c together and b's second one, as two machines upgraded at once
/// restart a few seconds apart.
const RESTART_GAP: Duration = Duration::from_secs(5);
/// The longest a probe stream may stop when b restarts without a Hub to tell its peers: the probes
/// find the path answering while the tunnel does not and the handshake is redone, about 3 seconds,
/// where WireGuard alone takes 15 (design/mesh.md section 8.2).
const RESTART_GAP_LIMIT_MS: u64 = 5_000;
/// What a nett daemon logs as it records an endpoint as blocked.
const BLOCK_LOGGED: &str = "plain UDP to this endpoint is blocked";

pub fn machine_obfs(topology: &Path, nett: &Path, out: &Path) -> anyhow::Result<Report> {
    let topo = Topology::load(topology)?;
    let underlay = Underlay::plan(&topo)?;
    underlay.down()?;
    let generated = material::generate(&topo, &underlay, out, false)?;
    let mut lab = start(&topo, &generated, underlay, nett)?;
    let mut report = Report::new("33-machine-obfs");
    // Before any handshake: the first one has to go to b's obfuscated port
    crate::fault::drop_plain_wireguard("b")?;
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
    let (a, b, c) = (node("a")?, node("b")?, node("c")?);
    let data_plane = |n: &LabNode| nett_status(nett, n).map(|s| s.node.dataplane);
    report.check(
        "b:userspace-for-its-port",
        matches!(data_plane(b), Ok(DataPlaneKind::Userspace)),
        format!("{:?}", data_plane(b)),
    );
    let on = |kind: PathKindDoc| move |k: PathKindDoc| k == kind;
    let started = now_ms();
    let (probe_file, _) = start_workload(&mut lab, "a", "b", b.mesh_ipv4.into(), out)?;
    for (name, client) in [("a", a), ("c", c)] {
        let reached = wait_tunnel(nett, client, b, SETTLE, PathKindDoc::DirectObfs);
        report.check(
            &format!("{name}:direct-to-the-obfuscated-port"),
            reached.is_ok(),
            reached
                .as_ref()
                .map(|s| candidates(s, b))
                .unwrap_or_else(|e| format!("{e:#}")),
        );
        report.record(
            &format!("{name}:connected"),
            format!("{} ms after the workload started", now_ms() - started),
        );
    }
    let from = now_ms();
    std::thread::sleep(WATCH);
    let to = now_ms();
    for (name, client) in [("a", a), ("c", c)] {
        let moved = switches_since(client, from);
        report.check(
            &format!("{name}:stays"),
            moved.is_empty(),
            format!("switches in {WATCH:?}: {moved:?}"),
        );
    }
    let probes = probe_stats(&probe_file, from, to)?;
    report.check(
        "a:no-interruption",
        probes.received > 0 && probes.max_gap_ms < 1000,
        format!("{probes:?}"),
    );

    // Direct UDP to b cut: through r1, whose leg to b has to be obfuscated too
    let b_addrs: Vec<std::net::IpAddr> = lab
        .underlay
        .node("b")
        .into_iter()
        .flat_map(|n| {
            n.public_ipv4
                .map(Into::into)
                .into_iter()
                .chain(n.ipv6.map(Into::into))
        })
        .collect();
    let cut_at = now_ms();
    for name in ["a", "c"] {
        crate::fault::block_udp_with(name, &b_addrs)?;
    }
    let through_r1 = |k: PathKindDoc| matches!(k, PathKindDoc::RelayObfs | PathKindDoc::Relay);
    for (name, client) in [("a", a), ("c", c)] {
        let reached = wait_path(nett, client, b, SETTLE, through_r1);
        report.check(
            &format!("{name}:through-r1-to-the-obfuscated-port"),
            reached.is_ok(),
            reached
                .as_ref()
                .map(|s| candidates(s, b))
                .unwrap_or_else(|e| format!("{e:#}")),
        );
    }
    let settled = now_ms();
    std::thread::sleep(Duration::from_secs(10));
    let relayed = probe_stats(&probe_file, settled, now_ms())?;
    report.check(
        "a:carried-through-r1",
        relayed.received > 0 && relayed.max_gap_ms < 1000,
        format!("{relayed:?}; cut at {cut_at}"),
    );
    for name in ["a", "b", "c"] {
        crate::fault::unblock_udp(name)?;
    }

    // b's port goes away: its nett daemon starts again on kernel WireGuard, and a goes direct
    let saved: Vec<(&LabNode, Vec<u8>)> = generated
        .nodes
        .iter()
        .map(|n| Ok((n, std::fs::read(n.dir.join("desired.json"))?)))
        .collect::<std::io::Result<_>>()?;
    let changes = count(&events(b), "data_plane_changes");
    for (n, bytes) in &saved {
        let mut doc: Value = serde_json::from_slice(bytes)?;
        without_obfs_port(&mut doc);
        deliver(&lab, n, &serde_json::to_vec_pretty(&doc)?)?;
    }
    if !report_restart(
        changes,
        &mut lab,
        &mut report,
        nett,
        b,
        "kernel",
        DataPlaneKind::Kernel,
    )? {
        return finish(&lab, out, report, &generated.nodes);
    }
    let direct = wait_path(nett, a, b, SETTLE, on(PathKindDoc::Direct));
    report.check(
        "kernel:a-direct",
        direct.is_ok(),
        direct.err().map(|e| format!("{e:#}")).unwrap_or_default(),
    );

    // And back: the userspace data plane takes the kernel's interface over
    let changes = count(&events(b), "data_plane_changes");
    for (n, bytes) in &saved {
        deliver(&lab, n, bytes)?;
    }
    if !report_restart(
        changes,
        &mut lab,
        &mut report,
        nett,
        b,
        "userspace",
        DataPlaneKind::Userspace,
    )? {
        return finish(&lab, out, report, &generated.nodes);
    }
    let back = wait_path(nett, a, b, SETTLE, on(PathKindDoc::DirectObfs));
    report.check(
        "userspace:a-back-on-the-obfuscated-port",
        back.is_ok(),
        back.err().map(|e| format!("{e:#}")).unwrap_or_default(),
    );
    finish(&lab, out, report, &generated.nodes)
}

/// Both ends restart together (design/prototype.md scenario 34, design/obfuscation.md section 5),
/// as when both are upgraded at once: b, which offers its own obfuscated port, and c, which reaches
/// it there on the userspace data plane, stop and start again, and b once more a few seconds later.
/// Plain WireGuard to b passes, so a plain path that fails meanwhile fails because b is down, not
/// because it is plain: no endpoint is recorded as blocked, and both pairs return to b's port.
pub fn obfs_restart(
    topology: &Path,
    nett: &Path,
    out: &Path,
    with_tailscale: bool,
) -> anyhow::Result<Report> {
    let mut report = nett_restart(topology, nett, out)?;
    if with_tailscale {
        let topo = Topology::load(topology)?;
        let gaps = tailscale_restart(&topo, &out.join("tailscale"))?;
        for (name, gap) in ["a", "c"].into_iter().zip(gaps) {
            report.record(
                &format!("tailscale:{name}:longest-gap-since-the-restart"),
                format!("{gap} ms"),
            );
        }
        write_report(out, &report)?;
    }
    Ok(report)
}

/// Probe streams from a and c to `target`, port 7000 and 7100: the files they write.
pub(super) fn probe_streams(
    lab: &mut Lab,
    target: std::net::IpAddr,
    out: &Path,
) -> anyhow::Result<[std::path::PathBuf; 2]> {
    let mut files = Vec::new();
    for (from, port) in [("a", 7000u16), ("c", 7100)] {
        let addr = std::net::SocketAddr::new(target, port).to_string();
        let file = out.join(format!("probe-{from}.txt"));
        lab.helper(
            "b",
            &[
                "probe-recv",
                "--listen",
                &addr,
                "--out",
                &file.to_string_lossy(),
            ],
            &out.join(format!("probe-recv-{from}.log")),
        )?;
        std::thread::sleep(Duration::from_millis(300));
        lab.helper(
            from,
            &["probe-send", "--to", &addr],
            &out.join(format!("probe-send-{from}.log")),
        )?;
        files.push(file);
    }
    Ok([files[0].clone(), files[1].clone()])
}

/// The longest gap in a probe stream from `from_ms` until now.
pub(super) fn longest_gap(file: &Path, from_ms: u64) -> anyhow::Result<u64> {
    Ok(probe_stats(file, from_ms, now_ms())?.max_gap_ms)
}

/// Scenario 34 with Tailscale in nett's place, in the same topology: b's and c's tailscaled stop
/// and start again together, and b's once more [`RESTART_GAP`] later; the longest gaps in a's and
/// c's probe streams to b since.
fn tailscale_restart(topo: &Topology, out: &Path) -> anyhow::Result<[u64; 2]> {
    use crate::tailscale::TailscaleLab;
    let underlay = Underlay::plan(topo)?;
    underlay.down()?;
    std::fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;
    underlay.up(topo)?;
    let mut lab = Lab {
        underlay,
        processes: Vec::new(),
        relays: Vec::new(),
        helpers: Vec::new(),
    };
    let mut ts = TailscaleLab::up(out, &["a", "b", "c"])?;
    let ip_b = ts.ipv4("b")?;
    // tailscale ping stops at the first direct reply
    for from in ["a", "c"] {
        ts.cli(from, &["ping", "-c", "20", &ip_b.to_string()]).ok();
    }
    let files = probe_streams(&mut lab, ip_b.into(), out)?;
    std::thread::sleep(WATCH);
    let restarted = now_ms();
    ts.stop_node("b");
    ts.stop_node("c");
    ts.start_node("b")?;
    ts.start_node("c")?;
    std::thread::sleep(RESTART_GAP);
    ts.stop_node("b");
    ts.start_node("b")?;
    std::thread::sleep(SETTLE + WATCH);
    let gaps = [
        longest_gap(&files[0], restarted)?,
        longest_gap(&files[1], restarted)?,
    ];
    drop(ts);
    drop(lab);
    Ok(gaps)
}

fn nett_restart(topology: &Path, nett: &Path, out: &Path) -> anyhow::Result<Report> {
    let topo = Topology::load(topology)?;
    let underlay = Underlay::plan(&topo)?;
    underlay.down()?;
    let generated = material::generate(&topo, &underlay, out, false)?;
    let mut lab = start(&topo, &generated, underlay, nett)?;
    let mut report = Report::new("34-obfs-restart");
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
    let (a, b, c) = (node("a")?, node("b")?, node("c")?);
    // Traffic from both keeps both pairs measuring their paths
    let files = probe_streams(&mut lab, b.mesh_ipv4.into(), out)?;
    for (name, client) in [("a", a), ("c", c)] {
        let reached = wait_tunnel(nett, client, b, SETTLE, PathKindDoc::DirectObfs);
        report.check(
            &format!("{name}:on-the-obfuscated-port"),
            reached.is_ok(),
            reached
                .as_ref()
                .map(|s| candidates(s, b))
                .unwrap_or_else(|e| format!("{e:#}")),
        );
    }
    std::thread::sleep(WATCH);
    let logged = |n: &LabNode| {
        std::fs::read_to_string(n.dir.join("nett.log"))
            .unwrap_or_default()
            .matches(BLOCK_LOGGED)
            .count()
    };
    let before = [logged(a), logged(c)];
    let restarted = now_ms();
    lab.stop("b")?;
    lab.stop("c")?;
    lab.spawn(b, nett)?;
    lab.spawn(c, nett)?;
    std::thread::sleep(RESTART_GAP);
    lab.stop("b")?;
    lab.spawn(b, nett)?;
    for (name, client) in [("a", a), ("c", c)] {
        let back = wait_tunnel(nett, client, b, SETTLE, PathKindDoc::DirectObfs);
        report.check(
            &format!("{name}:back-on-the-obfuscated-port"),
            back.is_ok(),
            back.as_ref()
                .map(|s| candidates(s, b))
                .unwrap_or_else(|e| format!("{e:#}")),
        );
    }
    std::thread::sleep(WATCH);
    for (((name, client), before), file) in [("a", a), ("c", c)].into_iter().zip(before).zip(&files)
    {
        let gap = longest_gap(file, restarted)?;
        report.check(
            &format!("{name}:longest-gap-since-the-restart"),
            gap <= RESTART_GAP_LIMIT_MS,
            format!("{gap} ms"),
        );
        let recorded = logged(client) - before;
        report.check(
            &format!("{name}:no-block-recorded"),
            recorded == 0,
            format!("{recorded} endpoints recorded as blocked since the restart"),
        );
        report.record(
            &format!("{name}:switches-since-the-restart"),
            format!("{:?}", switches_since(client, restarted)),
        );
    }
    finish(&lab, out, report, &generated.nodes)
}

fn finish(lab: &Lab, out: &Path, mut report: Report, nodes: &[LabNode]) -> anyhow::Result<Report> {
    if !report.passed {
        report.record("diagnosis", diagnose(lab, nodes));
    }
    write_report(out, &report)?;
    Ok(report)
}

/// Waits until a's path to b is of `kind` and its tunnel has completed a handshake.
pub(super) fn wait_tunnel(
    nett: &Path,
    a: &LabNode,
    b: &LabNode,
    within: Duration,
    kind: PathKindDoc,
) -> anyhow::Result<nett_mesh::status::StatusDoc> {
    let deadline = std::time::Instant::now() + within;
    loop {
        let status = wait_path(nett, a, b, within, |k| k == kind)?;
        let up = status
            .peers
            .iter()
            .find(|p| p.id == b.node_id)
            .is_some_and(|p| p.last_handshake.is_some());
        if up {
            return Ok(status);
        }
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "{}'s tunnel to b over {kind:?} has no handshake after {within:?}",
            a.name
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// What the site writes once b's obfuscated port is removed: no port in b's desired state, no
/// candidate to it, and no port of b in the relay's section.
fn without_obfs_port(doc: &mut Value) {
    // Read with `get_mut`: indexing a missing key would add it
    let Some(map) = doc.as_object_mut() else {
        return;
    };
    map.remove("obfs");
    let paths = map.get_mut("paths").and_then(Value::as_array_mut);
    for path in paths.into_iter().flatten() {
        if let Some(candidates) = path.get_mut("candidates").and_then(Value::as_array_mut) {
            candidates.retain(|c| c.get("kind").and_then(Value::as_str) != Some("direct_obfs"));
        }
    }
    let members = map
        .get_mut("relay")
        .and_then(|r| r.get_mut("members"))
        .and_then(Value::as_array_mut);
    for member in members.into_iter().flatten() {
        if let Some(member) = member.as_object_mut() {
            member.remove("obfs");
        }
    }
}

/// Writes a node's desired state and has its nett daemon read it.
fn deliver(lab: &Lab, node: &LabNode, bytes: &[u8]) -> anyhow::Result<()> {
    std::fs::write(node.dir.join("desired.json"), bytes)
        .with_context(|| format!("writing {}'s desired state", node.name))?;
    let pid = lab
        .pid(&node.name)
        .with_context(|| format!("process of {}", node.name))?;
    run("kill", ["-HUP", &pid.to_string()])?;
    Ok(())
}

/// b's nett daemon exits on the desired state that needs the other data plane, and comes up on it;
/// `false` when it did not exit, and the scenario cannot go on. `changes` is how many changes b had
/// reported before the desired state was delivered.
fn report_restart(
    changes: usize,
    lab: &mut Lab,
    report: &mut Report,
    nett: &Path,
    b: &LabNode,
    step: &str,
    want: DataPlaneKind,
) -> anyhow::Result<bool> {
    let asked = wait_for(b, "data_plane_changes", |ev| {
        count(ev, "data_plane_changes") > changes
    });
    let exited = asked.and_then(|()| lab.wait_exit("b", EXIT_WITHIN));
    let done = exited.is_ok();
    report.check(
        &format!("{step}:b-exits-to-change"),
        done,
        exited.err().map(|e| format!("{e:#}")).unwrap_or_default(),
    );
    if !done {
        return Ok(false);
    }
    let applied = count(&events(b), "peers_applied");
    lab.spawn(b, nett)?;
    wait_for(b, "peers_applied after the restart", |ev| {
        count(ev, "peers_applied") > applied
    })?;
    let running = nett_status(nett, b).map(|s| s.node.dataplane);
    report.check(
        &format!("{step}:b-on-{step}"),
        matches!(&running, Ok(kind) if *kind == want),
        format!("{running:?}"),
    );
    Ok(true)
}
