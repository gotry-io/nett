//! Served ports (design/mesh.md section 12.1, ADR 0028, design/prototype.md section 9): a service
//! on web's loopback is reached through the port web serves by the member a rule allows, sees
//! `127.0.0.1`, and is reached neither by a member without the rule nor from outside the mesh.

use std::path::Path;
use std::time::Duration;

use anyhow::Context as _;

use super::{Report, count, events, start, wait_for, write_report};
use crate::cmd::run_in;
use crate::material;
use crate::net::Underlay;
use crate::topology::Topology;

const PORT: u16 = 8080;

pub fn serve(topology: &Path, nett: &Path, out: &Path) -> anyhow::Result<Report> {
    let topo = Topology::load(topology)?;
    let underlay = Underlay::plan(&topo)?;
    underlay.down()?;
    let generated = material::generate(&topo, &underlay, out, false)?;
    let mut lab = start(&topo, &generated, underlay, nett)?;
    let mut report = Report::new("serve");
    let node = |name: &str| {
        generated
            .nodes
            .iter()
            .find(|n| n.name == name)
            .with_context(|| format!("node `{name}` in the serve topology"))
    };
    let web = node("web")?;
    let ns = |name: &str| -> anyhow::Result<String> {
        Ok(lab
            .underlay
            .node(name)
            .context("planned node")?
            .netns
            .clone())
    };
    let (ns_web, ns_client, ns_other) = (ns("web")?, ns("client")?, ns("other")?);
    let web_public = lab.underlay.public_ipv4("web").context("web's address")?;
    for n in &generated.nodes {
        wait_for(n, "peers_applied", |ev| count(ev, "peers_applied") > 0)?;
    }
    wait_for(web, "serving", |ev| count(ev, "serving") > 0)?;

    // The service listens on web's loopback only, and records the address of every connection
    let log = out.join(format!("accept-127.0.0.1-{PORT}.txt"));
    lab.helper_in(
        &ns_web,
        &[
            "accept-log",
            "--listen",
            &format!("127.0.0.1:{PORT}"),
            "--out",
            &log.to_string_lossy(),
        ],
        &out.join("accept.log"),
    )?;
    std::thread::sleep(Duration::from_millis(500));
    let me = std::env::current_exe().context("locating nett-lab")?;
    let connect = |netns: &str| -> String {
        let to = format!("{}:{PORT}", web.mesh_ipv4);
        run_in(
            netns,
            &me.to_string_lossy(),
            ["connect", "--to", to.as_str(), "--duration", "3"],
        )
        .map_or_else(|e| format!("error {e:#}"), |o| o.trim().to_owned())
    };
    let seen = || -> Vec<String> {
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    };

    // Waits for the tunnel the same way a first connection would
    let mut result = connect(&ns_client);
    for _ in 0..3 {
        if result == "connected" {
            break;
        }
        result = connect(&ns_client);
    }
    std::thread::sleep(Duration::from_millis(300));
    let reached = seen();
    report.check(
        "allowed-member-reaches-the-loopback-service",
        result == "connected" && !reached.is_empty(),
        format!("{result}; the service saw {reached:?}"),
    );
    report.check(
        "the-service-sees-loopback",
        !reached.is_empty() && reached.iter().all(|a| a == "127.0.0.1"),
        format!("{reached:?}"),
    );

    let before = seen().len();
    let result = connect(&ns_other);
    report.check(
        "member-without-a-rule-denied",
        result.starts_with("blocked") && seen().len() == before,
        result,
    );

    // From outside the mesh: other addresses web's mesh address through the public network, which
    // web's kernel would accept as one of its local addresses
    let host = format!("{}/32", web.mesh_ipv4);
    run_in(
        &ns_other,
        "ip",
        ["route", "replace", &host, "via", &web_public.to_string()],
    )?;
    let result = connect(&ns_other);
    run_in(&ns_other, "ip", ["route", "del", &host]).ok();
    report.check(
        "outside-the-mesh-never-reaches-loopback",
        result != "connected" && seen().len() == before,
        format!("{result}; the service saw {:?}", seen()),
    );

    // Recorded, not judged: the serving node's daemon next to those that serve nothing
    for (name, pid, _) in lab.measured() {
        if let Some(m) = super::memory_kib(pid) {
            report.record(
                &name,
                format!(
                    "anonymous {} KiB, PSS {} KiB, {} threads",
                    m.anon, m.pss, m.threads
                ),
            );
        }
    }

    let ev = events(web);
    report.check(
        "served-once-without-failures",
        count(&ev, "serving") == 1 && count(&ev, "serve_unavailable") == 0,
        format!(
            "serving {}, unavailable {}",
            count(&ev, "serving"),
            count(&ev, "serve_unavailable")
        ),
    );
    write_report(out, &report)?;
    Ok(report)
}
