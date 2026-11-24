//! A machine that restarted tells its peers through the Hub (design/prototype.md scenario 35,
//! design/mesh.md section 8.4): the site and the Hub run in h; a, b and c join through the Hub, and
//! `nett site set b --obfs` gives b its own obfuscated port, which a (kernel WireGuard) and c (the
//! userspace data plane) reach. b's nett daemon restarts, then c's: each restart loses the sessions
//! of the userspace data plane. b's notice through the Hub has a and c, which decide their pairs,
//! handshake again at once, where the probes alone take about 3 seconds (scenario 34); c handshakes
//! as soon as it sends again.

use std::path::Path;
use std::time::Duration;

use anyhow::Context as _;
use nett_mesh::key::PrivateKey;
use nett_mesh::status::PathKindDoc;
use nett_site::state::State;

use super::hub::{HUB_PORT, HubLab, desired};
use super::machine_obfs::{longest_gap, probe_streams, wait_tunnel};
use super::wireguard_block::candidates;
use super::{
    Lab, LabNode, Report, count, events, nett_status, switches_since, wait_for, write_report,
};
use crate::cmd::{run, run_in};
use crate::measure::now_ms;
use crate::net::Underlay;
use crate::topology::Topology;

/// How long a pair has to reach the path a step expects.
const SETTLE: Duration = Duration::from_secs(60);
/// How long the pairs are watched before and after a restart.
const WATCH: Duration = Duration::from_secs(20);
/// How long b's nett daemon has to exit once its port needs the userspace data plane.
const EXIT_WITHIN: Duration = Duration::from_secs(10);
/// The longest a probe stream may stop when its peer restarts: the daemon starting, its Hub session
/// coming up, one trip through the Hub and a handshake. The probes alone take about 3 seconds, and
/// WireGuard alone 15.
const RESTART_GAP_LIMIT_MS: u64 = 2_000;
const OBFS_PORT: &str = "41920";

pub fn hub_restart(
    topology: &Path,
    nett: &Path,
    out: &Path,
    with_tailscale: bool,
) -> anyhow::Result<Report> {
    let topo = Topology::load(topology)?;
    let underlay = Underlay::plan(&topo)?;
    let ns = |name: &str| -> anyhow::Result<String> {
        Ok(underlay
            .node(name)
            .with_context(|| format!("the hub-restart scenario needs a node `{name}`"))?
            .netns
            .clone())
    };
    let net_h = underlay.node("h").context("planned node")?;
    let hub_ip = net_h.public_ipv4.unwrap_or(net_h.ipv4);
    let ns_h = ns("h")?;
    let names: Vec<(String, String)> = ["b", "a", "c"]
        .into_iter()
        .map(|n| Ok((n.to_owned(), ns(n)?)))
        .collect::<anyhow::Result<_>>()?;
    underlay.down()?;
    let mut report = Report::new("35-hub-restart");
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
        members: vec!["a".into(), "b".into(), "c".into()],
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

    let mut nodes = Vec::new();
    for (name, netns) in &names {
        let mut args = vec!["add", name.as_str(), "--yes"];
        if name == "b" {
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
            netns,
            &nett.display().to_string(),
            ["join", &token, "--dir", &dir.to_string_lossy()],
        )?;
        let doc = desired(&dir.join("desired.json"))?;
        let state = State::from_json(&std::fs::read(site.join("state.json"))?)?;
        let m = state.machine(&name.parse()?)?;
        let node = LabNode {
            name: name.clone(),
            node_id: doc.node_id.clone(),
            mesh_public_key: PrivateKey::load(&dir.join("mesh.key"))?.public_key(),
            mesh_ipv4: m.mesh.ipv4,
            mesh_ipv6: m.mesh.ipv6,
            edge_ipv4: None,
            dir: dir.clone(),
            tls: false,
            userspace: topo.node(name).is_some_and(|n| n.userspace),
        };
        // Joined: the daemon also connects to the Hub (ADR 0013)
        lab.spawn(&node, nett)?;
        nodes.push(node);
    }
    let (b, a, c) = (&nodes[0], &nodes[1], &nodes[2]);
    h.site_cmd(&["allow", "a", "b", "--yes"])?;
    h.site_cmd(&["allow", "c", "b", "--yes"])?;

    // b's own obfuscated port: its daemon starts again on the userspace data plane
    let changes = count(&events(b), "data_plane_changes");
    let set = h.site_cmd(&["set", "b", "--obfs", "--obfs-port", OBFS_PORT, "--yes"]);
    report.check(
        "b:offers-its-port",
        set.is_ok(),
        set.unwrap_or_else(|e| format!("{e:#}")),
    );
    wait_for(b, "data_plane_changes", |ev| {
        count(ev, "data_plane_changes") > changes
    })?;
    lab.wait_exit("b", EXIT_WITHIN)?;
    lab.spawn(b, nett)?;
    for (name, client) in [("a", a), ("c", c)] {
        let reached = wait_tunnel(nett, client, b, SETTLE, PathKindDoc::DirectObfs);
        report.check(
            &format!("{name}:on-the-obfuscated-port"),
            reached.is_ok(),
            match reached {
                Ok(s) => candidates(&s, b),
                Err(e) => format!(
                    "{e:#}; {}",
                    nett_status(nett, client)
                        .map_or_else(|e| format!("{e:#}"), |s| candidates(&s, b))
                ),
            },
        );
    }
    let files = probe_streams(&mut lab, b.mesh_ipv4.into(), out)?;
    std::thread::sleep(WATCH);

    // b restarts: a and c, which decide their pairs, handshake again on their paths
    let restarted = now_ms();
    lab.stop("b")?;
    lab.spawn(b, nett)?;
    let gaps = back(
        nett,
        &mut report,
        "b",
        [("a", a), ("c", c)],
        b,
        &files,
        restarted,
    )?;
    // c restarts: b, which follows in that pair, handshakes again on its endpoint
    let restarted = now_ms();
    lab.stop("c")?;
    lab.spawn(c, nett)?;
    let c_gap = back(
        nett,
        &mut report,
        "c",
        [("c", c)],
        b,
        &files[1..],
        restarted,
    )?;
    // c handshakes as soon as it sends again, often before its Hub session is up: b then has a new
    // session already and no notice to act on
    report.record(
        "c:b-switches-since-the-restart",
        format!("{:?}", switches_since(b, restarted)),
    );
    if with_tailscale {
        let ts = tailscale_restart(&topo, &out.join("tailscale"))?;
        report.record(
            "tailscale:longest-gaps",
            format!(
                "b restarts: a {} ms, c {} ms; c restarts: c {} ms",
                ts[0], ts[1], ts[2]
            ),
        );
        report.check(
            "not-worse-than-tailscale",
            gaps[0] <= ts[0].max(RESTART_GAP_LIMIT_MS)
                && gaps
                    .get(1)
                    .is_none_or(|g| *g <= ts[1].max(RESTART_GAP_LIMIT_MS))
                && c_gap[0] <= ts[2].max(RESTART_GAP_LIMIT_MS),
            format!("nett: {gaps:?}, {c_gap:?}; tailscale: {ts:?}"),
        );
    }
    if !report.passed {
        report.record("diagnosis", super::diagnose(&lab, &nodes));
    }
    write_report(out, &report)?;
    drop(h);
    Ok(report)
}

/// After `restarted` restarted at `from_ms`: each client is back on b's obfuscated port, its probe
/// stream stopped no longer than [`RESTART_GAP_LIMIT_MS`], and a client that decides its pair
/// handshook again on the notice; the longest gaps.
fn back<const N: usize>(
    nett: &Path,
    report: &mut Report,
    restarted: &str,
    clients: [(&str, &LabNode); N],
    b: &LabNode,
    files: &[std::path::PathBuf],
    from_ms: u64,
) -> anyhow::Result<Vec<u64>> {
    let mut gaps = Vec::new();
    for (name, client) in clients {
        let back = wait_tunnel(nett, client, b, SETTLE, PathKindDoc::DirectObfs);
        report.check(
            &format!("{restarted}:{name}-back-on-the-obfuscated-port"),
            back.is_ok(),
            back.err().map(|e| format!("{e:#}")).unwrap_or_default(),
        );
    }
    std::thread::sleep(WATCH);
    for ((name, client), file) in clients.into_iter().zip(files) {
        let gap = longest_gap(file, from_ms)?;
        report.check(
            &format!("{restarted}:{name}-longest-gap"),
            gap <= RESTART_GAP_LIMIT_MS,
            format!("{gap} ms"),
        );
        if name != restarted {
            let switches = switches_since(client, from_ms);
            report.check(
                &format!("{restarted}:{name}-handshook-again-on-the-notice"),
                switches
                    .iter()
                    .any(|(_, reason)| reason == "peer_restarted"),
                format!("{switches:?}"),
            );
        }
        gaps.push(gap);
    }
    Ok(gaps)
}

/// Scenario 35 with Tailscale in nett's place: b's tailscaled restarts, then c's; the longest gaps
/// in a's and c's probe streams when b restarts and in c's when c does.
fn tailscale_restart(topo: &Topology, out: &Path) -> anyhow::Result<[u64; 3]> {
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
    for from in ["a", "c"] {
        ts.cli(from, &["ping", "-c", "20", &ip_b.to_string()]).ok();
    }
    let files = probe_streams(&mut lab, ip_b.into(), out)?;
    std::thread::sleep(WATCH);
    let restarted = now_ms();
    ts.stop_node("b");
    ts.start_node("b")?;
    std::thread::sleep(SETTLE);
    let b_gaps = [
        longest_gap(&files[0], restarted)?,
        longest_gap(&files[1], restarted)?,
    ];
    let restarted = now_ms();
    ts.stop_node("c");
    ts.start_node("c")?;
    std::thread::sleep(SETTLE);
    let c_gap = longest_gap(&files[1], restarted)?;
    drop(ts);
    drop(lab);
    Ok([b_gaps[0], b_gaps[1], c_gap])
}
