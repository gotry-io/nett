//! A relay much faster than direct (design/mesh.md section 8.2, design/prototype.md scenario 25):
//! with 150 ms added to the direct path only, a quiet pair moves to a relay after the hold without
//! interrupting its traffic and stays there; a bulk transfer moves it back to direct.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use serde_json::Value;

use super::{LabNode, Report, count, diagnose, events, start, wait_for};
use crate::material;
use crate::measure::{now_ms, probe_stats};
use crate::net::Underlay;
use crate::topology::Topology;

/// Delay added to a's packets for b's public address: the direct path only.
const DIRECT_DELAY_MS: u32 = 150;
/// The rule holds for 30 seconds once relay candidates have been measured (every 15 seconds while
/// there is traffic); this leaves room for both.
const MOVE_LIMIT: Duration = Duration::from_secs(90);
const STAY: Duration = Duration::from_secs(60);
const RETURN_LIMIT: Duration = Duration::from_secs(20);
/// Enough to keep the pair busy for longer than [`RETURN_LIMIT`] even through the delayed direct
/// path.
const BULK_BYTES: &str = "4000000000";

/// The path switches a reported after the first `skip` of them: `(to, reason)`.
fn switches(node: &LabNode, skip: usize) -> Vec<(String, String)> {
    events(node)
        .into_iter()
        .filter(|e| e["event"] == "path_switched")
        .skip(skip)
        .map(|e| {
            let text = |v: &Value| v.as_str().unwrap_or_default().to_owned();
            (text(&e["to"]), text(&e["reason"]))
        })
        .collect()
}

fn wait_switch(
    node: &LabNode,
    skip: usize,
    limit: Duration,
    want: impl Fn(&(String, String)) -> bool,
) -> Option<(Duration, (String, String))> {
    let started = Instant::now();
    while started.elapsed() < limit {
        if let Some(s) = switches(node, skip).into_iter().find(&want) {
            return Some((started.elapsed(), s));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    None
}

pub fn faster_relay(topology: &Path, nett: &Path, out: &Path) -> anyhow::Result<Report> {
    let topo = Topology::load(topology)?;
    let underlay = Underlay::plan(&topo)?;
    underlay.down()?;
    let generated = material::generate(&topo, &underlay, out, false)?;
    let mut lab = start(&topo, &generated, underlay, nett)?;
    let mut report = Report::new("25-faster-relay");
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

    // A light probe stream measures interruptions; it keeps the pair active but far from busy
    let probe_file = out.join("probe.txt");
    let probe_addr = std::net::SocketAddr::new(b.mesh_ipv4.into(), 7000).to_string();
    lab.helper(
        "b",
        &[
            "probe-recv",
            "--listen",
            &probe_addr,
            "--out",
            &probe_file.to_string_lossy(),
        ],
        &out.join("probe-recv.log"),
    )?;
    std::thread::sleep(Duration::from_millis(300));
    lab.helper(
        "a",
        &["probe-send", "--to", &probe_addr],
        &out.join("probe-send.log"),
    )?;
    // A long queue: the bulk transfer later must not push probes out of it
    crate::fault::prepare_delay(
        "a",
        &[
            "delay".into(),
            format!("{DIRECT_DELAY_MS}ms"),
            "limit".into(),
            "100000".into(),
        ],
    )?;
    std::thread::sleep(Duration::from_secs(10));
    let before = switches(a, 0);
    report.check(
        "start:direct",
        before.last().is_none_or(|(to, _)| to.starts_with("direct")),
        format!("{before:?}"),
    );

    // The direct path gets slow; the relays do not
    let delayed_at = now_ms();
    crate::fault::route_delay("a", b_public)?;
    let moved = wait_switch(a, before.len(), MOVE_LIMIT, |(to, _)| {
        to.starts_with("relay")
    });
    report.check(
        "slow-direct:moves-to-relay",
        moved
            .as_ref()
            .is_some_and(|(_, (_, reason))| reason == "better_score"),
        format!("{moved:?}"),
    );
    if moved.is_none() {
        anyhow::bail!(
            "a stayed on the direct path: {}",
            diagnose(&lab, &generated.nodes)
        );
    }
    let gaps = probe_stats(&probe_file, delayed_at, now_ms())?;
    report.check(
        "slow-direct:no-interruption",
        gaps.max_gap_ms < 1000,
        format!("longest gap {} ms", gaps.max_gap_ms),
    );

    // Direct answers all along, but it is not close enough to win back a quiet pair
    let on_relay = switches(a, 0).len();
    std::thread::sleep(STAY);
    let later = switches(a, on_relay);
    report.check(
        "slow-direct:stays-on-relay",
        later.is_empty(),
        format!("{later:?}"),
    );

    // A bulk transfer makes the pair busy: back to the direct path, which has more room
    let bulk_addr = std::net::SocketAddr::new(b.mesh_ipv4.into(), 7100).to_string();
    lab.helper(
        "b",
        &[
            "bulk-recv",
            "--listen",
            &bulk_addr,
            "--bytes",
            BULK_BYTES,
            "--out",
            &out.join("bulk.json").to_string_lossy(),
        ],
        &out.join("bulk-recv.log"),
    )?;
    std::thread::sleep(Duration::from_millis(300));
    let busy_at = now_ms();
    lab.helper(
        "a",
        &["bulk-send", "--to", &bulk_addr, "--bytes", BULK_BYTES],
        &out.join("bulk-send.log"),
    )?;
    let back = wait_switch(a, on_relay, RETURN_LIMIT, |(to, _)| {
        to.starts_with("direct")
    });
    report.check(
        "busy:returns-to-direct",
        back.as_ref()
            .is_some_and(|(_, (_, reason))| reason == "better_type"),
        format!("{back:?}"),
    );
    let gaps = probe_stats(&probe_file, busy_at, now_ms())?;
    report.check(
        "busy:no-interruption",
        gaps.max_gap_ms < 1000,
        format!("longest gap {} ms", gaps.max_gap_ms),
    );
    crate::fault::clear_eth0("a")?;
    Ok(report)
}
