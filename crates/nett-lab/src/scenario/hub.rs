//! Hub scenario (design/hub.md section 10, roadmap M1 acceptance): builds a site with real
//! commands (`nett keys`, `nett site add`, `allow`), and the members run from the locally signed
//! desired state; then `nett-hub` runs in one member's namespace (self-signed certificate, verified
//! by fingerprint), `nett site link` links it, `nett site invite` lets existing members attach, and
//! each member runs `nett node`. Checks:
//!
//! - After a push the members apply it, the desired state the Hub composes is identical to what is
//!   written in the site directory, file by file, and `nett site status` lists all machines;
//! - When the Hub stops the mesh keeps working, and changes cannot be pushed; after the Hub
//!   recovers the members reconnect and the next push catches up;
//! - Simulating a compromised Hub (editing its database directly): it delivers a member signed by
//!   another site, and the members reject that member while the rest continue as usual; it delivers
//!   an older version of the access rules, and the members reject that rule set, keep using the
//!   version in effect, and report it as a problem, without affecting connectivity;
//! - Leaving and re-enrolling (H2): a member leaves, the Hub removes it on the spot, the other
//!   members delete it, and its mesh interface is torn down; the same name enrolls through the Hub
//!   as a new machine (no public address written, learned by the Hub), gets a new node ID and
//!   address, and connects with the other members; the token can only be used once.
//!
//! Enrollment runs in the node's namespace with `nett join`, which is `sudo nett install <token>`
//! without the services; leaving runs `nett-lab leave`, which calls the library code of
//! `sudo nett leave` and also removes the mesh interface in the lab's namespace.

use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use nett_mesh::config::DesiredMeshDoc;
use nett_mesh::key::PrivateKey;
use nett_node::config::HubConfig;
use nett_proto::api::StatusResponse;
use nett_proto::token::JoinToken;
use nett_site::state::State;

use super::{Lab, LabNode, Report, memory, ping, wait_for, wg_peers};
use crate::cmd::{run, run_in, spawn_in};
use crate::net::Underlay;
use crate::topology::Topology;

pub(super) const HUB_PORT: u16 = 8443;
/// Upper bound for members to reconnect after the Hub recovers: nett-node's backoff is at most 60
/// seconds.
const RECONNECT: Duration = Duration::from_secs(90);

pub(super) struct HubLab<'a> {
    pub(super) nett: &'a Path,
    pub(super) hub_bin: PathBuf,
    pub(super) site: PathBuf,
    pub(super) hub_dir: PathBuf,
    /// The namespace running the Hub and its address.
    pub(super) hub_ns: String,
    pub(super) hub_ip: std::net::Ipv4Addr,
    /// The namespace running `nett site` (the user's computer).
    pub(super) site_ns: String,
    /// The members in the site (not including machines added during the simulated attack).
    pub(super) members: Vec<String>,
    pub(super) hub: Option<Child>,
}

impl HubLab<'_> {
    pub(super) fn site_cmd(&self, args: &[&str]) -> anyhow::Result<String> {
        let mut full: Vec<std::ffi::OsString> = vec!["site".into()];
        full.extend(args.iter().map(Into::into));
        full.push("--dir".into());
        full.push(self.site.clone().into());
        run_in(&self.site_ns, &self.nett.display().to_string(), full)
    }

    pub(super) fn start_hub(&mut self) -> anyhow::Result<()> {
        let listen = format!("{}:{HUB_PORT}", self.hub_ip);
        let child = spawn_in(
            &self.hub_ns,
            &self.hub_bin,
            [
                "serve".as_ref(),
                "--data".as_ref(),
                self.hub_dir.as_os_str(),
                "--listen".as_ref(),
                listen.as_ref(),
                "--tls-cert".as_ref(),
                self.hub_dir.join("tls-cert.pem").as_os_str(),
                "--tls-key".as_ref(),
                self.hub_dir.join("tls-key.pem").as_os_str(),
                // The lab has no internet; upgrades are tested in CI on Linux with systemd
                "--releases".as_ref(),
                "off".as_ref(),
            ],
            &self.hub_dir.join("hub.log"),
        )?;
        self.hub = Some(child);
        // Wait for it to start listening: each start writes its log from the beginning
        let log = self.hub_dir.join("hub.log");
        let deadline = Instant::now() + Duration::from_secs(10);
        while !std::fs::read_to_string(&log).is_ok_and(|t| t.contains("Hub listening")) {
            if Instant::now() >= deadline {
                bail!("nett-hub did not start listening; see {}", log.display());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    }

    pub(super) fn stop_hub(&mut self) {
        if let Some(mut child) = self.hub.take() {
            run("kill", ["-TERM", &child.id().to_string()]).ok();
            child.wait().ok();
        }
    }

    pub(super) fn status(&self) -> anyhow::Result<StatusResponse> {
        let out = self.site_cmd(&["status", "--json"])?;
        serde_json::from_str(&out).context("parsing nett site status --json")
    }

    /// Waits until every machine has given `result` for the current generation.
    pub(super) fn wait_acked(
        &self,
        result: &str,
        within: Duration,
    ) -> anyhow::Result<StatusResponse> {
        let deadline = Instant::now() + within;
        loop {
            let status = self.status();
            if let Ok(s) = &status
                && s.machines
                    .iter()
                    .filter(|m| self.members.contains(&m.name))
                    .all(|m| {
                        m.online
                            && m.applied_generation == Some(s.generation)
                            && m.result.as_deref() == Some(result)
                    })
            {
                return status;
            }
            if Instant::now() >= deadline {
                bail!("not every machine reported `{result}` in time: {status:?}");
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// Simulates a compromised Hub: stops it, edits the site in the database directly (bypassing
    /// the validation done on push), then starts it.
    fn tamper(&mut self, change: impl FnOnce(&mut State)) -> anyhow::Result<()> {
        self.stop_hub();
        let path = self.hub_dir.join("hub.db");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let db = nett_hub::db::Db::open(&path).await?;
            let (generation, json) = db.site().await?.context("the Hub has no site")?;
            let mut state = State::from_json(json.as_bytes())?;
            change(&mut state);
            db.put_site(
                generation + 1,
                &serde_json::to_string(&state)?,
                nett_hub::now(),
            )
            .await?;
            anyhow::Ok(())
        })?;
        self.start_hub()
    }
}

impl Drop for HubLab<'_> {
    fn drop(&mut self) {
        self.stop_hub();
    }
}

/// The public keys in the `--keys "..."` line printed by `nett keys`.
fn keys_line(out: &str) -> anyhow::Result<String> {
    let start = out.find("--keys \"").context("nett keys printed no keys")? + "--keys \"".len();
    let end = out[start..]
        .find('"')
        .context("nett keys printed no keys")?;
    Ok(out[start..start + end].to_owned())
}

pub(super) fn desired(path: &Path) -> anyhow::Result<DesiredMeshDoc> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

pub fn hub(topology: &Path, nett: &Path, out: &Path, soak: Option<u64>) -> anyhow::Result<Report> {
    let topo = Topology::load(topology)?;
    let underlay = Underlay::plan(&topo)?;
    underlay.down()?;
    let mut report = Report::new("hub");
    let names: Vec<String> = topo.nodes.iter().map(|n| n.name.clone()).collect();
    if names.len() < 2 {
        bail!("the hub scenario needs at least two nodes");
    }
    std::fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;
    let site = out.join("site");
    std::fs::remove_dir_all(&site).ok();

    // Site: real commands, the same as what the user does on their own computer
    run(
        &nett.display().to_string(),
        ["site", "init", "--dir", &site.to_string_lossy()],
    )?;
    let mut nodes = Vec::new();
    for name in &names {
        let dir = out.join(name);
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir)?;
        let keys = keys_line(&run(
            &nett.display().to_string(),
            ["keys", "--dir", &dir.to_string_lossy()],
        )?)?;
        let net = underlay.node(name).context("planned node")?;
        let ip = net.public_ipv4.unwrap_or(net.ipv4).to_string();
        run(
            &nett.display().to_string(),
            [
                "site",
                "add",
                name,
                "--keys",
                &keys,
                "--public",
                "--ipv4",
                &ip,
                "--yes",
                "--dir",
                &site.to_string_lossy(),
            ],
        )?;
        nodes.push(dir);
    }
    let all = names.join(",");
    run(
        &nett.display().to_string(),
        [
            "site",
            "allow",
            &all,
            &all,
            "--yes",
            "--dir",
            &site.to_string_lossy(),
        ],
    )?;
    let state: State = State::from_json(&std::fs::read(site.join("state.json"))?)?;
    let mut lab_nodes = Vec::new();
    for (name, dir) in names.iter().zip(&nodes) {
        std::fs::copy(
            site.join("nodes").join(name).join("desired.json"),
            dir.join("desired.json"),
        )?;
        let m = state.machine(&name.parse()?)?;
        lab_nodes.push(LabNode {
            name: name.clone(),
            node_id: m.node_id.clone(),
            mesh_public_key: m.keys.context("keys")?.mesh,
            mesh_ipv4: m.mesh.ipv4,
            mesh_ipv6: m.mesh.ipv6,
            edge_ipv4: None,
            dir: dir.clone(),
            tls: false,
            userspace: false,
        });
    }

    underlay.up(&topo)?;
    let mut lab = Lab {
        underlay,
        processes: Vec::new(),
        relays: Vec::new(),
        helpers: Vec::new(),
    };
    for node in &lab_nodes {
        lab.spawn(node, nett)?;
    }
    for node in &lab_nodes {
        wait_for(node, "peers_applied", |ev| {
            super::count(ev, "peers_applied") > 0
        })?;
    }
    let (a, b) = (&lab_nodes[0], &lab_nodes[1]);
    let namespaces: std::collections::BTreeMap<String, String> = names
        .iter()
        .map(|n| {
            Ok((
                n.clone(),
                lab.underlay.node(n).context("planned node")?.netns.clone(),
            ))
        })
        .collect::<anyhow::Result<_>>()?;
    let ns = |name: &str| -> anyhow::Result<String> {
        namespaces.get(name).cloned().context("planned node")
    };
    let (ns_a, ns_b) = (ns(&a.name)?, ns(&b.name)?);
    let net_a = lab.underlay.node(&a.name).context("planned node")?;
    let hub_ip = net_a.public_ipv4.unwrap_or(net_a.ipv4);

    // Hub: in a's namespace, with a self-signed certificate; the user's computer is in b's
    // namespace
    let hub_dir = out.join("hub");
    std::fs::remove_dir_all(&hub_dir).ok();
    std::fs::create_dir_all(&hub_dir)?;
    crate::material::self_signed(hub_ip, &hub_dir)?;
    let mut h = HubLab {
        nett,
        hub_bin: nett.with_file_name("nett-hub"),
        site: site.clone(),
        hub_dir: hub_dir.clone(),
        hub_ns: ns_a.clone(),
        hub_ip,
        site_ns: ns_b,
        members: names.clone(),
        hub: None,
    };
    if !h.hub_bin.exists() {
        bail!(
            "{} not found; build it with `cargo build -p nett-hub`",
            h.hub_bin.display()
        );
    }
    let init = run_in(
        &ns_a,
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
    let linked = h.site_cmd(&["link", &code]);
    report.check(
        "site-linked",
        linked.as_ref().is_ok_and(|o| o.contains("Linked to")),
        linked
            .as_ref()
            .map_or_else(|e| format!("{e:#}"), Clone::clone),
    );
    linked?;

    // Existing members attach: the token printed by invite is given to each machine (what install
    // writes is this configuration), and each runs nett node
    for node in &lab_nodes {
        let invite = h.site_cmd(&["invite", &node.name])?;
        let token = invite
            .split_whitespace()
            .find(|w| w.starts_with("nett_enr_"))
            .context("nett site invite printed no token")?;
        let token = JoinToken::decode(token)?;
        report.check(
            &format!("invite:{}:token-has-no-secret", node.name),
            token.node_id == node.node_id.as_str(),
            format!("token for {}", token.node_id),
        );
        HubConfig {
            url: token.url,
            hub_key: token.hub_key,
            node_id: token.node_id,
            tls_fingerprint: token.tls_fingerprint,
        }
        .save(&node.dir)
        .map_err(anyhow::Error::msg)?;
        let child = spawn_in(
            &ns(&node.name)?,
            nett,
            [
                "node".as_ref(),
                "--dir".as_ref(),
                node.dir.as_os_str(),
                "--socket".as_ref(),
                node.dir.join("mesh.sock").as_os_str(),
            ],
            &node.dir.join("node.log"),
        )?;
        lab.processes.push((format!("node:{}", node.name), child));
    }
    let connected = h.wait_acked("applied", Duration::from_secs(30));
    report.check(
        "members-connected-and-current",
        connected.is_ok(),
        connected.as_ref().map_or_else(
            |e| format!("{e:#}"),
            |s| format!("generation {}", s.generation),
        ),
    );

    // The change is delivered through the Hub: members apply it, and the desired state the Hub
    // composes equals what is written in the site directory
    let pushed = h.site_cmd(&["allow", &a.name, &b.name, "22/tcp", "--yes"]);
    report.check(
        "push:applied-by-all",
        pushed
            .as_ref()
            .is_ok_and(|o| o.contains(&format!("{n} of {n} machines applied", n = names.len()))),
        pushed
            .as_ref()
            .map_or_else(|e| format!("{e:#}"), Clone::clone),
    );
    for node in &lab_nodes {
        let same = desired(&node.dir.join("desired.json"))?
            == desired(&site.join("nodes").join(&node.name).join("desired.json"))?;
        report.check(
            &format!("push:{}:same-as-site", node.name),
            same,
            "the desired state from the Hub equals the one the site wrote",
        );
    }
    report.record(
        "site-status",
        h.site_cmd(&["status"]).unwrap_or_else(|e| format!("{e:#}")),
    );
    // Right after nett-node connects and applies, it reports the local status
    std::thread::sleep(Duration::from_secs(3));
    let status = h.status()?;
    report.check(
        "status:links-reported",
        status
            .machines
            .iter()
            .filter(|m| names.contains(&m.name))
            .all(|m| m.status.is_some()),
        format!(
            "{} of {} machines reported their mesh status",
            status
                .machines
                .iter()
                .filter(|m| m.status.is_some())
                .count(),
            status.machines.len()
        ),
    );
    for (name, pid) in lab
        .processes
        .iter()
        .filter(|(n, _)| n.starts_with("node:"))
        .map(|(n, c)| (n.clone(), c.id()))
    {
        report.record(&format!("memory:{name}"), memory(pid));
    }
    if let Some(hub) = &h.hub {
        report.record("memory:nett-hub", memory(hub.id()));
    }

    // Hub stops: the mesh keeps working, and changes cannot be pushed (signing and saving still
    // work)
    h.stop_hub();
    let reachable = ping(&ns_a, &b.mesh_ipv4.to_string());
    report.check(
        "hub-down:mesh-continues",
        reachable.is_ok(),
        reachable.unwrap_or_else(|e| format!("{e:#}")),
    );
    let refused = h.site_cmd(&["allow", &b.name, &a.name, "80/tcp", "--yes"]);
    report.check(
        "hub-down:push-fails",
        refused.is_err(),
        refused.map_or_else(|e| format!("{e:#}"), |o| format!("unexpected success: {o}")),
    );

    // Hub recovers: members reconnect, and the next push delivers both changes together
    h.start_hub()?;
    let catch_up = h.site_cmd(&["allow", &b.name, &a.name, "81/tcp", "--yes"]);
    report.record(
        "hub-back:push",
        catch_up.unwrap_or_else(|e| format!("{e:#}")),
    );
    let caught_up = h.wait_acked("applied", RECONNECT);
    report.check(
        "hub-back:caught-up",
        caught_up.is_ok(),
        caught_up.as_ref().map_or_else(
            |e| format!("{e:#}"),
            |s| format!("generation {}", s.generation),
        ),
    );
    for node in &lab_nodes {
        let same = desired(&node.dir.join("desired.json"))?
            == desired(&site.join("nodes").join(&node.name).join("desired.json"))?;
        report.check(
            &format!("hub-back:{}:same-as-site", node.name),
            same,
            "both changes made while the Hub was down arrived",
        );
    }

    // The Hub host is lost (design/hub.md section 8.2): the Hub is rebuilt in a new data directory
    // from the backup a member keeps, with the site's backup key; members connect to it on their own
    // and the next push reaches them
    let kept = lab_nodes[0].dir.join(nett_node::session::BACKUP_FILE);
    report.check(
        "rebuild:backup-kept",
        kept.exists(),
        format!("{} keeps {}", lab_nodes[0].name, kept.display()),
    );
    h.stop_hub();
    let lost = out.join("hub-lost");
    std::fs::remove_dir_all(&lost).ok();
    std::fs::rename(&h.hub_dir, &lost)?;
    std::fs::create_dir_all(&h.hub_dir)?;
    // The reverse proxy's certificate is not part of the Hub; the lab's self-signed one moves along
    for file in ["tls-cert.pem", "tls-key.pem"] {
        std::fs::copy(lost.join(file), h.hub_dir.join(file))?;
    }
    let key_line = std::fs::read(site.join("backup.key"))?;
    let restored = crate::cmd::run_with_input(
        &h.hub_bin.display().to_string(),
        [
            "restore".as_ref(),
            "--data".as_ref(),
            h.hub_dir.as_os_str(),
            kept.as_os_str(),
        ],
        Some(&key_line),
        Duration::from_secs(30),
    );
    report.check(
        "rebuild:restored",
        restored
            .as_ref()
            .is_ok_and(|o| o.contains("Restored the Hub")),
        restored
            .as_ref()
            .map_or_else(|e| format!("{e:#}"), Clone::clone),
    );
    h.start_hub()?;
    let pushed = h.site_cmd(&["allow", &b.name, &a.name, "82/tcp", "--yes"]);
    report.record("rebuild:push", pushed.unwrap_or_else(|e| format!("{e:#}")));
    let current = h.wait_acked("applied", RECONNECT);
    report.check(
        "rebuild:members-current",
        current.is_ok(),
        current.as_ref().map_or_else(
            |e| format!("{e:#}"),
            |s| format!("generation {}", s.generation),
        ),
    );

    // The compromised Hub delivers a member signed by another site: members reject it, the rest
    // continue as usual
    let other = out.join("other-site");
    std::fs::remove_dir_all(&other).ok();
    run(
        &nett.display().to_string(),
        ["site", "init", "--dir", &other.to_string_lossy()],
    )?;
    let evil_dir = out.join("evil");
    std::fs::remove_dir_all(&evil_dir).ok();
    let evil_keys = keys_line(&run(
        &nett.display().to_string(),
        ["keys", "--dir", &evil_dir.to_string_lossy()],
    )?)?;
    run(
        &nett.display().to_string(),
        [
            "site",
            "add",
            "evil",
            "--keys",
            &evil_keys,
            "--yes",
            "--dir",
            &other.to_string_lossy(),
        ],
    )?;
    let foreign = State::from_json(&std::fs::read(other.join("state.json"))?)?;
    let evil = foreign.machine(&"evil".parse()?)?.clone();
    let evil_mesh_key = evil.keys.context("keys")?.mesh.to_string();
    h.tamper(|s| {
        s.machines.insert("evil".parse().expect("valid name"), evil);
    })?;
    let applied = h.wait_acked("applied", RECONNECT);
    report.check(
        "forged-member:rest-applied",
        applied.is_ok(),
        applied
            .as_ref()
            .map_or_else(|e| format!("{e:#}"), |_| String::new()),
    );
    let reasons: Vec<Option<String>> = applied
        .as_ref()
        .map(|s| {
            s.machines
                .iter()
                .filter(|m| names.contains(&m.name))
                .map(|m| m.reason.clone())
                .collect()
        })
        .unwrap_or_default();
    report.check(
        "forged-member:reported-as-problem",
        !reasons.is_empty()
            && reasons
                .iter()
                .all(|r| r.as_deref().is_some_and(|r| !r.is_empty())),
        format!("{reasons:?}"),
    );
    let peers = wg_peers(&ns_a)?;
    report.check(
        "forged-member:not-configured",
        !peers.contains(&evil_mesh_key),
        format!("wg peers on {}: {peers:?}", a.name),
    );

    // The compromised Hub delivers an older version of the access rules: members reject this rule
    // set and keep using the version in effect (design/mesh.md section 4.2), reporting it as a
    // problem; connectivity is not affected
    let older = state.access_rules.clone();
    let older_version = older.as_ref().map_or(0, |r| r.version);
    h.tamper(|s| {
        s.machines.remove(&"evil".parse().expect("valid name"));
        s.access_rules = older;
    })?;
    let answered = h.wait_acked("applied", RECONNECT);
    let kept: Vec<(String, Option<u64>, Option<String>)> = answered
        .as_ref()
        .map(|s| {
            s.machines
                .iter()
                .filter(|m| names.contains(&m.name))
                .map(|m| {
                    let version = m
                        .status
                        .as_ref()
                        .and_then(|v| v["config"]["access_rules_version"].as_u64());
                    (m.name.clone(), version, m.reason.clone())
                })
                .collect()
        })
        .unwrap_or_default();
    report.check(
        "older-rules:rejected-and-reported",
        !kept.is_empty()
            && kept.iter().all(|(_, version, reason)| {
                version.is_some_and(|v| v > older_version)
                    && reason.as_deref().is_some_and(|r| r.contains("not newer"))
            }),
        format!("offered version {older_version}; (machine, version in effect, reason): {kept:?}"),
    );
    let reachable = ping(&ns_a, &b.mesh_ipv4.to_string());
    report.check(
        "older-rules:mesh-continues",
        reachable.is_ok(),
        reachable.unwrap_or_else(|e| format!("{e:#}")),
    );

    // Leave: first stop b's processes (`nett leave` deletes the services first), then tell the Hub
    // and tear down the interface
    let lab_bin = std::env::current_exe().context("locating nett-lab")?;
    let ns_b = ns(&b.name)?;
    for process in [b.name.clone(), format!("node:{}", b.name)] {
        if let Some(i) = lab.processes.iter().position(|(n, _)| *n == process) {
            let (_, mut child) = lab.processes.remove(i);
            run("kill", ["-TERM", &child.id().to_string()]).ok();
            child.wait().ok();
        }
    }
    let left = run_in(
        &ns_b,
        &lab_bin.display().to_string(),
        ["leave", "--out", &b.dir.to_string_lossy()],
    );
    report.check(
        "leave:told-the-hub",
        left.is_ok(),
        left.as_ref()
            .map_or_else(|e| format!("{e:#}"), Clone::clone),
    );
    let gone = run_in(
        &ns_b,
        "ip",
        ["link", "show", nett_mesh::dataplane::INTERFACE_NAME],
    );
    report.check(
        "leave:interface-removed",
        gone.is_err(),
        gone.map_or_else(
            |_| "no mesh interface".to_owned(),
            |o| format!("still there: {o}"),
        ),
    );
    let old_key = b.mesh_public_key.to_string();
    let deadline = Instant::now() + Duration::from_secs(20);
    let dropped = loop {
        let peers = wg_peers(&ns_a)?;
        if !peers.contains(&old_key) || Instant::now() >= deadline {
            break peers;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    report.check(
        "leave:dropped-by-members",
        !dropped.contains(&old_key),
        format!("wg peers on {}: {dropped:?}", a.name),
    );
    let synced = h.site_cmd(&["status"]);
    report.check(
        "leave:removed-from-the-site",
        synced
            .as_ref()
            .is_ok_and(|o| o.contains(&format!("- {} left the site", b.name))),
        synced
            .as_ref()
            .map_or_else(|e| format!("{e:#}"), Clone::clone),
    );

    // The same name enrolls as a new machine: one command on the computer, one on the machine (here
    // nett-lab enroll); the public address is learned by the Hub
    let added = h.site_cmd(&["add", &b.name, "--public", "--yes"])?;
    report.check(
        "join:one-line-printed",
        added.contains(
            "curl -fsSL https://nett.gotry.io/install.sh | sh && sudo nett install nett_enr_",
        ),
        added.clone(),
    );
    let token = added
        .split_whitespace()
        .find(|w| w.starts_with("nett_enr_"))
        .context("nett site add printed no token")?
        .to_owned();
    let new_dir = out.join(format!("{}-new", b.name));
    std::fs::remove_dir_all(&new_dir).ok();
    run(
        &nett.display().to_string(),
        ["keys", "--dir", &new_dir.to_string_lossy()],
    )?;
    // `nett join`: what `sudo nett install <token>` does, without installing services
    let joined = run_in(
        &ns_b,
        &nett.display().to_string(),
        ["join", &token, "--dir", &new_dir.to_string_lossy()],
    );
    report.check(
        "join:enrolled",
        joined.is_ok(),
        joined
            .as_ref()
            .map_or_else(|e| format!("{e:#}"), Clone::clone),
    );
    joined?;
    let doc = desired(&new_dir.join("desired.json"))?;
    report.check(
        "join:new-node-id",
        doc.node_id != b.node_id,
        format!("{} -> {}", b.node_id, doc.node_id),
    );
    let reused = {
        let other = out.join(format!("{}-other", b.name));
        std::fs::remove_dir_all(&other).ok();
        run(
            &nett.display().to_string(),
            ["keys", "--dir", &other.to_string_lossy()],
        )?;
        run_in(
            &ns_b,
            &nett.display().to_string(),
            ["join", &token, "--dir", &other.to_string_lossy()],
        )
    };
    report.check(
        "join:token-used-once",
        reused
            .as_ref()
            .is_err_and(|e| format!("{e:#}").contains("already joined")),
        reused.map_or_else(|e| format!("{e:#}"), |o| format!("unexpected success: {o}")),
    );
    let state_now = State::from_json(&std::fs::read(site.join("state.json"))?)?;
    let m = state_now.machine(&b.name.parse()?)?;
    let rejoined = LabNode {
        name: b.name.clone(),
        node_id: doc.node_id.clone(),
        mesh_public_key: PrivateKey::load(&new_dir.join("mesh.key"))?.public_key(),
        mesh_ipv4: m.mesh.ipv4,
        mesh_ipv6: m.mesh.ipv6,
        edge_ipv4: None,
        dir: new_dir.clone(),
        tls: false,
        userspace: false,
    };
    lab.spawn(&rejoined, nett)?;
    let child = spawn_in(
        &ns_b,
        nett,
        [
            "node".as_ref(),
            "--dir".as_ref(),
            new_dir.as_os_str(),
            "--socket".as_ref(),
            new_dir.join("mesh.sock").as_os_str(),
        ],
        &new_dir.join("node.log"),
    )?;
    lab.processes.push((format!("node:{}", b.name), child));
    // The new machine does not have the old rules (design/site.md section 4): it can only connect
    // after they are allowed
    let allowed = h.site_cmd(&["allow", &all, &all, "--yes"]);
    report.record("join:allow", allowed.unwrap_or_else(|e| format!("{e:#}")));
    let current = h.wait_acked("applied", Duration::from_secs(30));
    report.check(
        "join:members-current",
        current.is_ok(),
        current.as_ref().map_or_else(
            |e| format!("{e:#}"),
            |s| format!("generation {}", s.generation),
        ),
    );
    let reachable = ping(&ns_a, &rejoined.mesh_ipv4.to_string());
    report.check(
        "join:mesh-connected",
        reachable.is_ok(),
        reachable.unwrap_or_else(|e| format!("{e:#}")),
    );
    // The site fetches the result of the enrollment and the learned address
    h.site_cmd(&["status"])?;
    let state_now = State::from_json(&std::fs::read(site.join("state.json"))?)?;
    let m = state_now.machine(&b.name.parse()?)?;
    report.check(
        "join:recorded-in-the-site",
        m.keys.map(|k| k.mesh) == Some(rejoined.mesh_public_key) && m.enrollment.is_none(),
        format!("keys {:?}", m.keys),
    );
    let net_b = lab.underlay.node(&b.name).context("planned node")?;
    let expected = net_b.public_ipv4.unwrap_or(net_b.ipv4);
    report.check(
        "join:public-address-learned",
        m.ipv4.is_none() && m.learned.ipv4.map(|l| l.ip) == Some(expected),
        format!("learned {:?}, expected {expected}", m.learned),
    );
    if let Some(seconds) = soak {
        soak_phase(
            &h,
            &lab,
            &ns_a,
            &rejoined.mesh_ipv4.to_string(),
            seconds,
            out,
            &mut report,
        )?;
    }
    drop(h);
    Ok(report)
}

/// Rest after the load before the idle measurement (CLAUDE.md "Resource discipline").
const SOAK_REST: Duration = Duration::from_secs(600);
const SOAK_EVERY: Duration = Duration::from_secs(60);
/// Allowed growth of anonymous memory from the first sample after the warm-up to the idle
/// measurement. Anonymous memory is what a leak grows; RSS also counts code pages, which the kernel
/// may reclaim while the lab rests.
const SOAK_GROWTH_KIB: u64 = 512;
/// Idle budget of nett-node and the mesh process (hard rule 14); meaningful for release builds.
const NODE_BUDGET_KIB: u64 = 5 * 1024;

/// One memory sample of each process: RSS, PSS and anonymous memory in KiB.
type Samples = Vec<(String, super::Memory)>;

/// The soak (CLAUDE.md "Resource discipline", roadmap M1): for `seconds`, every minute a rule is
/// added or removed again, pushed through the Hub, and one member pings the other; the memory of
/// every nett process is sampled into `soak.csv`. Then the lab rests for 10 minutes and the idle
/// memory is measured: anonymous memory must be flat against the first sample after a 10-minute
/// warm-up, and nett-node and the mesh process must stay within their budget, judged by the
/// largest RSS sampled.
fn soak_phase(
    h: &HubLab<'_>,
    lab: &Lab,
    ns_a: &str,
    b_mesh: &str,
    seconds: u64,
    out: &Path,
    report: &mut Report,
) -> anyhow::Result<()> {
    use std::io::Write as _;
    let mut pids: Vec<(String, u32)> = lab
        .processes
        .iter()
        .map(|(name, child)| {
            let name = if name.starts_with("node:") {
                name.clone()
            } else {
                format!("mesh:{name}")
            };
            (name, child.id())
        })
        .collect();
    if let Some(hub) = &h.hub {
        pids.push(("nett-hub".to_owned(), hub.id()));
    }
    let csv_path = out.join("soak.csv");
    let mut csv = std::fs::File::create(&csv_path)?;
    writeln!(csv, "seconds,process,rss_kib,pss_kib,anon_kib,threads")?;
    let mut peak: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let mut sample = |csv: &mut std::fs::File, at: u64| -> anyhow::Result<Samples> {
        let mut all = Vec::new();
        for (name, pid) in &pids {
            if let Some(m) = super::memory_kib(*pid) {
                writeln!(
                    csv,
                    "{at},{name},{},{},{},{}",
                    m.rss, m.pss, m.anon, m.threads
                )?;
                let top = peak.entry(name.clone()).or_default();
                *top = (*top).max(m.rss);
                all.push((name.clone(), m));
            }
        }
        Ok(all)
    };
    let started = Instant::now();
    let warm_up = Duration::from_secs(600).min(Duration::from_secs(seconds / 2));
    let mut baseline: Option<Samples> = None;
    let (mut pushes, mut failed_pushes, mut pings, mut failed_pings) = (0u64, 0u64, 0u64, 0u64);
    let mut round = 0u64;
    while started.elapsed() < Duration::from_secs(seconds) {
        let pushed = if round.is_multiple_of(2) {
            h.site_cmd(&["allow", "a", "b", "9000/tcp", "--note", "soak", "--yes"])
        } else {
            let rules = h.site_cmd(&["rules", "--json"])?;
            let rules: serde_json::Value = serde_json::from_str(&rules)?;
            let id = rules
                .as_object()
                .and_then(|r| {
                    r.iter()
                        .find(|(_, rule)| rule["note"] == "soak")
                        .map(|(id, _)| id.clone())
                })
                .context("the soak rule")?;
            h.site_cmd(&["rules", "remove", &id, "--yes"])
        };
        pushes += 1;
        if pushed.is_err() {
            failed_pushes += 1;
        }
        pings += 1;
        if ping(ns_a, b_mesh).is_err() {
            failed_pings += 1;
        }
        let now = sample(&mut csv, started.elapsed().as_secs())?;
        if baseline.is_none() && started.elapsed() >= warm_up {
            baseline = Some(now);
        }
        round += 1;
        std::thread::sleep(SOAK_EVERY);
    }
    std::thread::sleep(SOAK_REST);
    let idle = sample(&mut csv, started.elapsed().as_secs())?;
    report.record(
        "soak:load",
        format!(
            "{seconds} s, {pushes} pushes ({failed_pushes} failed), {pings} pings ({failed_pings} failed); samples in {}",
            csv_path.display()
        ),
    );
    report.check(
        "soak:changes-and-pings",
        failed_pushes == 0 && failed_pings == 0,
        format!("{failed_pushes} failed pushes, {failed_pings} failed pings"),
    );
    let baseline = baseline.unwrap_or_default();
    for (name, m) in &idle {
        let first = baseline
            .iter()
            .find(|(n, _)| n == name)
            .map_or(m.anon, |(_, b)| b.anon);
        report.check(
            &format!("soak:{name}:flat"),
            m.anon <= first + SOAK_GROWTH_KIB,
            format!(
                "anonymous {first} KiB after the warm-up, {} KiB idle at the end",
                m.anon
            ),
        );
        let top = peak.get(name).copied().unwrap_or(m.rss);
        let detail = format!(
            "idle RSS {} KiB, PSS {} KiB, anonymous {} KiB; largest RSS {top} KiB",
            m.rss, m.pss, m.anon
        );
        if name.starts_with("node:") || name.starts_with("mesh:") {
            report.check(
                &format!("soak:{name}:budget"),
                top <= NODE_BUDGET_KIB,
                format!("{detail}; budget {NODE_BUDGET_KIB} KiB"),
            );
        } else {
            report.record(&format!("soak:{name}:memory"), detail);
        }
    }
    Ok(())
}

/// `nett-lab leave`: tells the Hub this machine is leaving, and tears down the mesh interface and
/// filter rules (the same library code as `sudo nett leave`). The mesh process must be stopped
/// first.
pub fn leave_here(dir: &Path) -> anyhow::Result<()> {
    let config = HubConfig::load(dir)
        .map_err(anyhow::Error::msg)?
        .context("no hub.json")?;
    let identity = PrivateKey::load(&dir.join("identity.key"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(nett_node::session::leave(
        &config,
        &x25519_dalek::StaticSecret::from(*identity.as_bytes()),
    ))?;
    nett_mesh::linux::teardown()?;
    println!("left");
    Ok(())
}
