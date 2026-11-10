//! 场景。每个场景输出一份 JSON 报告（design/prototype.md 第 7 节）。

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use serde::Serialize;
use serde_json::Value;

use crate::cmd::{run, run_in, spawn_in};
use crate::material::{self, Generated, LabNode, key_from_wg_text};
use crate::net::Underlay;
use crate::topology::Topology;

mod hub;
pub use hub::hub;

/// 连通性检查的最长等待时间。
const CONNECT_DEADLINE: Duration = Duration::from_secs(12);

/// 等待组网进程应用期望状态的上限。
const APPLY_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Serialize)]
pub struct Check {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub scenario: String,
    pub kernel: String,
    pub passed: bool,
    pub checks: Vec<Check>,
}

impl Report {
    fn new(scenario: &str) -> Self {
        Self {
            scenario: scenario.to_owned(),
            kernel: run("uname", ["-r"])
                .map(|s| s.trim().to_owned())
                .unwrap_or_default(),
            passed: true,
            checks: Vec::new(),
        }
    }

    /// 只记录、不判定的数据。
    fn record(&mut self, name: &str, detail: impl Into<String>) {
        self.checks.push(Check {
            name: name.to_owned(),
            passed: true,
            detail: detail.into(),
        });
    }

    fn check(&mut self, name: &str, passed: bool, detail: impl Into<String>) {
        self.passed &= passed;
        self.checks.push(Check {
            name: name.to_owned(),
            passed,
            detail: detail.into(),
        });
    }
}

/// 实验期间运行的组网进程；结束时（包括出错返回时）一并结束并拆除网络。
struct Lab {
    underlay: Underlay,
    processes: Vec<(String, Child)>,
    /// 中继节点上的 nett-relay。
    relays: Vec<(String, Child)>,
    /// 测量用的辅助进程（探测流、长连接）。
    helpers: Vec<Child>,
}

impl Drop for Lab {
    fn drop(&mut self) {
        for (_, child) in &mut self.relays {
            run("kill", ["-TERM", &child.id().to_string()]).ok();
            child.wait().ok();
        }
        for child in &mut self.helpers {
            child.kill().ok();
            child.wait().ok();
        }
        for (_, child) in &mut self.processes {
            run("kill", ["-TERM", &child.id().to_string()]).ok();
        }
        for (_, child) in &mut self.processes {
            child.wait().ok();
        }
        if let Err(e) = self.underlay.down() {
            eprintln!("nett-lab: tearing down the lab network failed: {e:#}");
        }
    }
}

impl Lab {
    fn pid(&self, name: &str) -> Option<u32> {
        self.processes
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, c)| c.id())
    }
}

fn events(node: &LabNode) -> Vec<Value> {
    std::fs::read_to_string(node.dir.join("events.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

/// 出错时的现场：各节点最近的事件与日志、WireGuard 对端的状态（endpoint、最近一次握手、收发字节），
/// 附在错误信息里，CI 的日志中就能看到。
fn diagnose(lab: &Lab, nodes: &[LabNode]) -> String {
    let tail = |path: &Path, n: usize| -> String {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(n)..].join("\n    ")
    };
    let mut out = String::from("lab state:");
    for node in nodes {
        out.push_str(&format!("\n  [{}]", node.name));
        for (file, n) in [
            ("events.jsonl", 8),
            ("mesh.log", 4),
            ("relay.log", 4),
            ("transport.log", 4),
        ] {
            let path = node.dir.join(file);
            if path.exists() {
                out.push_str(&format!("\n   {file}:\n    {}", tail(&path, n)));
            }
        }
        // 本机状态：用户态成员没有内核 WireGuard 接口，`wg show` 读不到它的对端（design/status.md 第 9 节）
        if let Ok(doc) = nett_mesh::status::query(&node.dir.join("mesh.sock")) {
            out.push_str("\n   status:");
            for p in &doc.peers {
                let path = p.path.as_ref().map(|path| {
                    format!(
                        "{:?} via {:?} {:?}",
                        path.kind,
                        path.relay.as_ref().map(|r| r.id.to_string()),
                        path.endpoint
                    )
                });
                out.push_str(&format!(
                    "\n    {}: {:?} {:?} rtt {:?} handshake {:?}",
                    p.name
                        .as_ref()
                        .map_or_else(|| p.id.to_string(), ToString::to_string),
                    p.state,
                    path,
                    p.rtt_ms,
                    p.last_handshake.map(|t| t.to_string())
                ));
            }
            for problem in &doc.problems {
                out.push_str(&format!(
                    "\n    problem {:?}: {}",
                    problem.kind, problem.reason
                ));
            }
        }
        // 只读不含密钥的字段：`wg show ... dump` 的第一行有接口私钥（硬性规则 10）
        if let Some(net) = lab.underlay.node(&node.name) {
            for field in ["endpoints", "latest-handshakes", "transfer"] {
                if let Ok(text) = run(
                    "ip",
                    ["netns", "exec", &net.netns, "wg", "show", "nett0", field],
                ) {
                    out.push_str(&format!(
                        "\n   wg {field}:\n    {}",
                        text.trim().replace('\n', "\n    ")
                    ));
                }
            }
        }
    }
    out
}

fn count(events: &[Value], kind: &str) -> usize {
    events.iter().filter(|e| e["event"] == kind).count()
}

/// 等到某个节点的事件满足条件。
fn wait_for(
    node: &LabNode,
    what: &str,
    mut done: impl FnMut(&[Value]) -> bool,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + APPLY_TIMEOUT;
    loop {
        if done(&events(node)) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "node {} did not report {what} within {APPLY_TIMEOUT:?}",
                node.name
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// 经 `nett status --json` 读一个节点的本机状态（design/status.md）。套接字按路径连接，不受网络命名空间限制。
fn nett_status(nett: &Path, node: &LabNode) -> anyhow::Result<nett_mesh::status::StatusDoc> {
    let socket = node.dir.join("mesh.sock");
    let out = run(
        &nett.display().to_string(),
        [
            "status".as_ref(),
            "--json".as_ref(),
            "--socket".as_ref(),
            socket.as_os_str(),
        ],
    )?;
    serde_json::from_str(&out).context("parsing nett status --json")
}

fn wg_peers(netns: &str) -> anyhow::Result<BTreeSet<String>> {
    let out = run_in(netns, "wg", ["show", "nett0", "peers"])?;
    out.lines()
        .map(|l| key_from_wg_text(l).map(|k| k.to_string()))
        .collect()
}

/// 进程的 RSS 与 PSS（KiB）。多个进程共享同一个可执行文件的代码页，PSS 按共享份数分摊。
fn memory(pid: u32) -> String {
    let field = |file: &str, key: &str| -> Option<String> {
        std::fs::read_to_string(format!("/proc/{pid}/{file}"))
            .ok()?
            .lines()
            .find(|l| l.starts_with(key))
            .map(|l| l[key.len()..].trim().to_owned())
    };
    format!(
        "VmRSS {}, Pss {}",
        field("status", "VmRSS:").unwrap_or_else(|| "?".into()),
        field("smaps_rollup", "Pss:").unwrap_or_else(|| "?".into())
    )
}

/// 先等到能连通（最多 [`CONNECT_DEADLINE`]），再连续 ping 3 次。对端在 NAT 之后时，它的第一次握手
/// 可能早于本机配置好它而被丢弃，WireGuard 5 秒后重试（场景 20 实测这段时间）；没有 endpoint 时
/// `ping` 遇到发送错误会立即退出，所以由这里反复尝试。
fn ping(netns: &str, target: &str) -> anyhow::Result<String> {
    let started = Instant::now();
    while run_in(netns, "ping", ["-c", "1", "-W", "1", target]).is_err() {
        if started.elapsed() >= CONNECT_DEADLINE {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let reachable_after = started.elapsed();
    let out = run_in(netns, "ping", ["-c", "3", "-i", "0.2", "-W", "2", target])?;
    let rtt = out.lines().last().unwrap_or_default();
    Ok(format!(
        "{rtt}; reachable after {} ms",
        reachable_after.as_millis()
    ))
}

fn start(
    topo: &Topology,
    generated: &Generated,
    underlay: Underlay,
    nett: &Path,
) -> anyhow::Result<Lab> {
    start_with(topo, generated, underlay, nett, |_| Vec::new())
}

/// `extra(节点名)` 是这个节点的组网进程额外的命令行参数。
fn start_with(
    topo: &Topology,
    generated: &Generated,
    underlay: Underlay,
    nett: &Path,
    extra: impl Fn(&str) -> Vec<String>,
) -> anyhow::Result<Lab> {
    underlay.up(topo)?;
    let mut lab = Lab {
        underlay,
        processes: Vec::new(),
        relays: Vec::new(),
        helpers: Vec::new(),
    };
    for node in &generated.nodes {
        // 每次实验重新生成密钥与信任锚：上一次留下的信任存储会让新的期望状态被拒绝（design/mesh.md
        // 第 4.2 节）。同一次实验中重启组网进程不经过这里，信任存储保留
        let state = node.dir.join("state");
        match std::fs::remove_dir_all(&state) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {}", state.display())),
        }
        lab.spawn_with(node, nett, &extra(&node.name))?;
        if topo
            .node(&node.name)
            .is_some_and(|n| n.roles.iter().any(|r| r == "relay"))
        {
            lab.spawn_relay(node, nett)?;
        }
    }
    Ok(lab)
}

impl Lab {
    fn spawn(&mut self, node: &LabNode, nett: &Path) -> anyhow::Result<()> {
        self.spawn_with(node, nett, &[])
    }

    fn spawn_with(&mut self, node: &LabNode, nett: &Path, extra: &[String]) -> anyhow::Result<()> {
        let net = self.underlay.node(&node.name).context("planned node")?;
        let dir = &node.dir;
        let transport_config = dir.join("transport.json");
        let mut args: Vec<std::ffi::OsString> = vec![
            "mesh".into(),
            "--config".into(),
            dir.join("desired.json").into(),
            "--key".into(),
            dir.join("mesh.key").into(),
            "--events".into(),
            dir.join("events.jsonl").into(),
            "--transport-config".into(),
            transport_config.clone().into(),
            "--socket".into(),
            dir.join("mesh.sock").into(),
            "--state".into(),
            dir.join("state").into(),
        ];
        if node.userspace {
            args.push("--userspace".into());
        }
        args.extend(extra.iter().map(Into::into));
        let child = spawn_in(&net.netns, nett, &args, &dir.join("mesh.log"))?;
        self.processes.push((node.name.clone(), child));
        // 传输适配进程读组网进程写出的配置（design/mesh.md 第 5.3 节）
        if node.tls {
            let child = spawn_in(
                &net.netns,
                nett,
                [
                    "transport".as_ref(),
                    "--config".as_ref(),
                    transport_config.as_os_str(),
                ],
                &dir.join("transport.log"),
            )?;
            self.helpers.push(child);
        }
        Ok(())
    }

    /// 在节点的命名空间中启动一个测量辅助进程（`nett-lab` 自己的子命令）。
    /// 在任意一个命名空间中运行测量子命令（例如节点背后的服务）。
    fn helper_in(&mut self, netns: &str, args: &[&str], log: &Path) -> anyhow::Result<()> {
        let me = std::env::current_exe().context("locating nett-lab")?;
        let child = spawn_in(netns, &me, args, log)?;
        self.helpers.push(child);
        Ok(())
    }

    fn helper(&mut self, name: &str, args: &[&str], log: &Path) -> anyhow::Result<()> {
        let net = self.underlay.node(name).context("planned node")?;
        let me = std::env::current_exe().context("locating nett-lab")?;
        let child = spawn_in(&net.netns, &me, args, log)?;
        self.helpers.push(child);
        Ok(())
    }

    fn spawn_relay(&mut self, node: &LabNode, nett: &Path) -> anyhow::Result<()> {
        let net = self.underlay.node(&node.name).context("planned node")?;
        let child = spawn_in(
            &net.netns,
            nett,
            [
                "relay".as_ref(),
                "--config".as_ref(),
                node.dir.join("relay.json").as_os_str(),
                "--state".as_ref(),
                node.dir.join("relay-state.json").as_os_str(),
            ],
            &node.dir.join("relay.log"),
        )?;
        self.relays.push((node.name.clone(), child));
        Ok(())
    }

    /// 在命名空间中启动一个外部工具（例如 tcpdump），结束时一并结束。
    fn tool(
        &mut self,
        netns: &str,
        program: &str,
        args: &[&str],
        log: &Path,
    ) -> anyhow::Result<()> {
        let child = spawn_in(netns, Path::new(program), args, log)?;
        self.helpers.push(child);
        Ok(())
    }

    /// 重启一个中继节点上的 nett-relay（场景 3）。
    fn restart_relay(&mut self, node: &LabNode, nett: &Path) -> anyhow::Result<()> {
        if let Some(pos) = self.relays.iter().position(|(n, _)| *n == node.name) {
            let (_, mut child) = self.relays.remove(pos);
            child.kill().ok();
            child.wait().ok();
        }
        self.spawn_relay(node, nett)
    }

    /// 结束一个节点的组网进程并等它退出。
    fn stop(&mut self, name: &str) -> anyhow::Result<()> {
        let i = self
            .processes
            .iter()
            .position(|(n, _)| n == name)
            .context("no such process")?;
        let (_, mut child) = self.processes.remove(i);
        run("kill", ["-TERM", &child.id().to_string()])?;
        child.wait().context("waiting for the mesh process")?;
        Ok(())
    }
}

/// 场景 14：准入验证；同时验证两个节点经直连通信（G1）。
pub fn admission(topology: &Path, nett: &Path, out: &Path) -> anyhow::Result<Report> {
    let topo = Topology::load(topology)?;
    let underlay = Underlay::plan(&topo)?;
    // 上一次异常退出留下的网络
    underlay.down()?;
    let generated = material::generate(&topo, &underlay, out, true)?;
    let mut lab = start(&topo, &generated, underlay, nett)?;
    let mut report = Report::new("14-admission");

    let (a, b) = (&generated.nodes[0], &generated.nodes[1]);
    for node in &generated.nodes {
        wait_for(node, "peers_applied", |ev| count(ev, "peers_applied") > 0)?;
    }

    // 合法的对端被配置，反例都不被配置
    let ns_a = lab.underlay.node(&a.name).context("node a")?.netns.clone();
    let peers = wg_peers(&ns_a)?;
    let expected: BTreeSet<String> = generated.nodes[1..]
        .iter()
        .map(|n| n.mesh_public_key.to_string())
        .collect();
    report.check(
        "only-valid-peers-configured",
        peers == expected,
        format!("wg peers on {}: {peers:?}; expected {expected:?}", a.name),
    );

    // 每个反例各有一条拒绝事件
    let ev = events(a);
    let rejected: Vec<Option<String>> = ev
        .iter()
        .filter(|e| e["event"] == "member_rejected")
        .map(|e| e["node_id"].as_str().map(str::to_owned))
        .collect();
    for negative in &generated.negatives {
        let want = negative.node_id.as_ref().map(ToString::to_string);
        let found = rejected.iter().filter(|r| **r == want).count();
        report.check(
            &format!("rejected:{}", negative.case),
            found >= 1,
            format!("{found} member_rejected event(s) for {want:?}"),
        );
    }
    report.check(
        "no-unexpected-rejections",
        rejected.len() == generated.negatives.len(),
        format!(
            "{} rejections for {} negative cases",
            rejected.len(),
            generated.negatives.len()
        ),
    );

    // 两个节点经直连通信
    for target in [b.mesh_ipv4.to_string(), b.mesh_ipv6.to_string()] {
        let result = ping(&ns_a, &target);
        report.check(
            &format!("ping:{}->{}:{target}", a.name, b.name),
            result.is_ok(),
            result.map_or_else(
                |e| format!("{e:#}"),
                |o| o.lines().last().unwrap_or_default().to_owned(),
            ),
        );
    }

    // 本机状态（design/status.md 第 9 节）：每个成员列出其他成员和它们的名字；刚 ping 过的一对已连通、
    // 有路径；反例在 a 上列为问题。用户态成员（`--userspace`）上同样可读
    for node in &generated.nodes {
        let status = nett_status(nett, node);
        let (listed, connected) = match &status {
            Ok(doc) => {
                let listed: BTreeSet<(String, Option<String>)> = doc
                    .peers
                    .iter()
                    .map(|p| (p.id.to_string(), p.name.as_ref().map(ToString::to_string)))
                    .collect();
                let other = if node.name == a.name { b } else { a };
                let connected = doc.peers.iter().any(|p| {
                    p.id == other.node_id
                        && p.state == nett_mesh::status::PeerState::Connected
                        && p.path.is_some()
                });
                (listed, connected)
            }
            Err(_) => (BTreeSet::new(), false),
        };
        let expected: BTreeSet<(String, Option<String>)> = generated
            .nodes
            .iter()
            .filter(|n| n.name != node.name)
            .map(|n| (n.node_id.to_string(), Some(n.name.clone())))
            .collect();
        report.check(
            &format!("status:{}:peers-listed", node.name),
            listed == expected,
            format!(
                "{listed:?}; expected {expected:?}; {:?}",
                status.as_ref().err()
            ),
        );
        if node.name == a.name || node.name == b.name {
            report.check(
                &format!("status:{}:connected", node.name),
                connected,
                format!("{:?}", status.as_ref().map(|d| &d.peers)),
            );
        }
        if node.name == a.name {
            let problems: Vec<String> = status
                .iter()
                .flat_map(|d| &d.problems)
                .filter(|p| p.kind == nett_mesh::status::ProblemKind::MemberRejected)
                .filter_map(|p| p.node.as_ref().map(|n| n.id.to_string()))
                .collect();
            let missing: Vec<String> = generated
                .negatives
                .iter()
                .filter_map(|n| n.node_id.as_ref().map(ToString::to_string))
                .filter(|id| !problems.contains(id))
                .collect();
            report.check(
                "status:a:rejections-listed",
                status.is_ok() && missing.is_empty(),
                format!("member_rejected problems {problems:?}; missing {missing:?}"),
            );
            let text = run(
                &nett.display().to_string(),
                [
                    "status".as_ref(),
                    "--socket".as_ref(),
                    node.dir.join("mesh.sock").as_os_str(),
                ],
            );
            report.record("status:a", text.unwrap_or_else(|e| format!("{e:#}")));
        }
    }

    // 重新加载一份只带低版本材料的期望状态：被拒绝，已生效的对端保持不变
    let desired_a = a.dir.join("desired.json");
    let original = std::fs::read(&desired_a).context("reading desired state of a")?;
    let downgraded = match &generated.lower_version_of_second {
        Some(lower) => {
            let mut doc = generated.first_desired.clone();
            doc.members = vec![generated.materials[&a.name].clone(), lower.clone()];
            doc.revocations.clear();
            Some(serde_json::to_vec_pretty(&doc).context("serializing desired state")?)
        }
        None => None,
    };
    if let Some(text) = &downgraded {
        std::fs::write(&desired_a, text).context("rewriting desired state")?;
        let before = count(&ev, "member_rejected");
        let pid = lab.pid(&a.name).context("process of node a")?;
        run("kill", ["-HUP", &pid.to_string()])?;
        let waited = wait_for(a, "a rejection after reload", |ev| {
            count(ev, "member_rejected") > before
        });
        let peers_after = wg_peers(&ns_a)?;
        report.check(
            "reload:lower-version-rejected",
            waited.is_ok() && peers_after == expected,
            format!("after SIGHUP: {waited:?}; peers {peers_after:?}"),
        );
        let result = ping(&ns_a, &b.mesh_ipv4.to_string());
        report.check(
            "reload:still-connected",
            result.is_ok(),
            result.err().map(|e| format!("{e:#}")).unwrap_or_default(),
        );
        // 经本机接口重新加载同一份文件：报告已生效，并列出被拒绝的低版本材料（design/status.md 第 4.1 节）
        let reloaded = run(
            &nett.display().to_string(),
            [
                "reload".as_ref(),
                "--socket".as_ref(),
                a.dir.join("mesh.sock").as_os_str(),
            ],
        );
        let peers_after = wg_peers(&ns_a)?;
        report.check(
            "reload:reports-rejection",
            reloaded.as_ref().is_ok_and(|out| {
                out.starts_with("Reloaded the desired state, with problems:")
                    && out.contains(&format!("member {} rejected", b.name))
            }) && peers_after == expected,
            format!("{reloaded:?}; peers {peers_after:?}"),
        );
        std::fs::write(&desired_a, &original).context("restoring desired state")?;
    }

    // 组网进程停止期间，内核中的 WireGuard 照常工作；重启后沿用已有的接口和对端
    lab.stop(&a.name)?;
    let while_stopped = ping(&ns_a, &b.mesh_ipv4.to_string());
    report.check(
        "restart:connected-while-stopped",
        while_stopped.is_ok(),
        while_stopped
            .err()
            .map(|e| format!("{e:#}"))
            .unwrap_or_default(),
    );
    let applied_before = count(&events(a), "peers_applied");
    lab.spawn(a, nett)?;
    let waited = wait_for(a, "peers_applied after restart", |ev| {
        count(ev, "peers_applied") > applied_before
    });
    let peers_after = wg_peers(&ns_a)?;
    let after_restart = ping(&ns_a, &b.mesh_ipv4.to_string());
    report.check(
        "restart:reuses-interface",
        waited.is_ok() && peers_after == expected && after_restart.is_ok(),
        format!(
            "{waited:?}; peers {peers_after:?}; ping {:?}",
            after_restart.err()
        ),
    );

    // 重启之后再拿到低版本材料：以信任存储中已生效的版本为基准，照样拒绝（design/mesh.md 第 4.2 节）
    if let Some(text) = &downgraded {
        std::fs::write(&desired_a, text).context("rewriting desired state")?;
        lab.stop(&a.name)?;
        let before = count(&events(a), "member_rejected");
        lab.spawn(a, nett)?;
        let waited = wait_for(a, "a rejection after restart", |ev| {
            count(ev, "member_rejected") > before
        });
        let peers_after = wg_peers(&ns_a)?;
        let b_configured = peers_after.contains(&b.mesh_public_key.to_string());
        report.check(
            "restart:lower-version-still-rejected",
            waited.is_ok() && !b_configured,
            format!("{waited:?}; peers {peers_after:?}"),
        );
        std::fs::write(&desired_a, &original).context("restoring desired state")?;
    }

    // 各节点 WireGuard 的现场，供排查
    for node in &generated.nodes {
        if let Some(net) = lab.underlay.node(&node.name) {
            let dump =
                run_in(&net.netns, "wg", ["show", "nett0"]).unwrap_or_else(|e| format!("{e:#}"));
            report.record(&format!("wg:{}", node.name), dump);
        }
    }

    // 资源占用只记录（场景 21 在 G6 按"负载后静置 10 分钟"的方法正式测量）
    for (name, child) in &lab.processes {
        report.record(&format!("memory:{name}"), memory(child.id()));
    }

    write_report(out, &report)?;
    drop(lab);
    Ok(report)
}

pub fn write_report(out: &Path, report: &Report) -> anyhow::Result<PathBuf> {
    let path = out.join("report.json");
    let text = serde_json::to_vec_pretty(report).context("serializing report")?;
    std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// 实验工具自检：在已知的故障上确认测量和故障注入本身是准的。不是 nett 的验收场景。
pub fn selftest(topology: &Path, nett: &Path, out: &Path) -> anyhow::Result<Report> {
    use crate::fault::{self, Netem};
    use crate::measure::{now_ms, probe_stats, tcp_stats};

    let topo = Topology::load(topology)?;
    let underlay = Underlay::plan(&topo)?;
    underlay.down()?;
    let generated = material::generate(&topo, &underlay, out, false)?;
    let mut lab = start(&topo, &generated, underlay, nett)?;
    let mut report = Report::new("lab-selftest");
    let (a, b) = (&generated.nodes[0], &generated.nodes[1]);
    for node in &generated.nodes {
        wait_for(node, "peers_applied", |ev| count(ev, "peers_applied") > 0)?;
    }

    let probe_file = out.join("probe.txt");
    let tcp_file = out.join("tcp.txt");
    let probe_addr = format!("{}:7000", b.mesh_ipv4);
    let tcp_addr = format!("{}:7001", b.mesh_ipv4);
    lab.helper(
        &b.name,
        &[
            "probe-recv",
            "--listen",
            &probe_addr,
            "--out",
            &probe_file.to_string_lossy(),
        ],
        &out.join("probe-recv.log"),
    )?;
    lab.helper(
        &b.name,
        &[
            "tcp-sink",
            "--listen",
            &tcp_addr,
            "--out",
            &tcp_file.to_string_lossy(),
        ],
        &out.join("tcp-sink.log"),
    )?;
    std::thread::sleep(Duration::from_millis(300));
    lab.helper(
        &a.name,
        &["probe-send", "--to", &probe_addr],
        &out.join("probe-send.log"),
    )?;
    lab.helper(
        &a.name,
        &["tcp-source", "--to", &tcp_addr],
        &out.join("tcp-source.log"),
    )?;

    // 2 秒的双向 100% 丢包
    std::thread::sleep(Duration::from_secs(3));
    let net_b = lab.underlay.node(&b.name).context("node b")?.netns.clone();
    let before = fault::counters(&net_b, "eth0")?;
    let start_ms = now_ms();
    fault::set_link(&lab.underlay, &b.name, &Netem::loss(100.0))?;
    std::thread::sleep(Duration::from_secs(2));
    fault::clear_link(&lab.underlay, &b.name)?;
    std::thread::sleep(Duration::from_secs(3));

    // 1 秒的 UDP 拦截（WireGuard 的外层是 UDP）
    let block_ms = now_ms();
    fault::block_udp(&b.name)?;
    std::thread::sleep(Duration::from_secs(1));
    fault::unblock_udp(&b.name)?;
    std::thread::sleep(Duration::from_secs(3));
    let end_ms = now_ms();
    let after = fault::counters(&net_b, "eth0")?;

    let loss = probe_stats(&probe_file, start_ms - 2000, block_ms - 500)?;
    report.check(
        "probe:2s-loss-measured",
        (1800..=2600).contains(&loss.max_gap_ms) && loss.gaps.len() == 1,
        format!("{loss:?}"),
    );
    let block = probe_stats(&probe_file, block_ms - 500, end_ms)?;
    report.check(
        "probe:1s-udp-block-measured",
        (800..=1600).contains(&block.max_gap_ms) && block.gaps.len() == 1,
        format!("{block:?}"),
    );
    let tcp = tcp_stats(&tcp_file, start_ms - 2000, end_ms)?;
    report.check(
        "tcp:long-connection-survives",
        tcp.ended.is_none() && tcp.kbps > 0,
        format!("{tcp:?}"),
    );
    report.check(
        "counters:underlay-traffic-seen",
        after.0 > before.0 && after.1 > before.1,
        format!(
            "eth0 of {} rx {} -> {}, tx {} -> {}",
            b.name, before.0, after.0, before.1, after.1
        ),
    );

    write_report(out, &report)?;
    drop(lab);
    Ok(report)
}

/// 在同一拓扑中部署 Tailscale，确认对比对象可用：直连、直连被拦时经 DERP 回退，测量工具在它上面同样可用。
/// 中断时间只记录，与 nett 的对比在 G2 的场景中进行。
pub fn tailscale(topology: &Path, out: &Path) -> anyhow::Result<Report> {
    use crate::fault::{self, Netem};
    use crate::measure::{now_ms, probe_stats, tcp_stats};
    use crate::tailscale::{TailscaleLab, versions};

    let topo = Topology::load(topology)?;
    let underlay = Underlay::plan(&topo)?;
    underlay.down()?;
    std::fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;
    underlay.up(&topo)?;
    let mut lab = Lab {
        underlay,
        processes: Vec::new(),
        relays: Vec::new(),
        helpers: Vec::new(),
    };
    let names: Vec<&str> = topo.nodes.iter().map(|n| n.name.as_str()).collect();
    // 在 lab 之后声明：先于 lab 析构，进程结束之后再拆网络
    let ts = TailscaleLab::up(out, &names)?;
    let mut report = Report::new("tailscale-baseline");
    report.record("versions", versions());

    let (a, b) = (names[0], names[1]);
    let ip_b = ts.ipv4(b)?;
    let b_underlay = lab
        .underlay
        .public_ipv4(b)
        .context("b has a public address")?;
    // 直连走 IPv4 或 IPv6 都算
    let net_b = lab.underlay.node(b).context("node b")?;
    let mut b_addrs = vec![std::net::IpAddr::V4(b_underlay)];
    b_addrs.extend(net_b.ipv6.map(std::net::IpAddr::V6));
    let direct_markers: Vec<String> = b_addrs
        .iter()
        .map(|addr| match addr {
            std::net::IpAddr::V4(a) => format!("via {a}:"),
            std::net::IpAddr::V6(a) => format!("via [{a}]:"),
        })
        .collect();
    let direct = ts.cli(a, &["ping", "-c", "10", &ip_b.to_string()]);
    report.check(
        "tailscale:direct-path",
        direct
            .as_ref()
            .is_ok_and(|o| direct_markers.iter().any(|m| o.contains(m.as_str()))),
        direct.map_or_else(
            |e| format!("{e:#}"),
            |o| o.lines().last().unwrap_or_default().to_owned(),
        ),
    );
    let icmp = ping(&crate::net::netns(a), &ip_b.to_string());
    report.check(
        "tailscale:icmp",
        icmp.is_ok(),
        icmp.err().map(|e| format!("{e:#}")).unwrap_or_default(),
    );

    // 测量工具在 Tailscale 上同样可用；2 秒双向丢包后的中断时间只记录
    let probe_file = out.join("probe.txt");
    let tcp_file = out.join("tcp.txt");
    let probe_addr = format!("{ip_b}:7000");
    let tcp_addr = format!("{ip_b}:7001");
    lab.helper(
        b,
        &[
            "probe-recv",
            "--listen",
            &probe_addr,
            "--out",
            &probe_file.to_string_lossy(),
        ],
        &out.join("probe-recv.log"),
    )?;
    lab.helper(
        b,
        &[
            "tcp-sink",
            "--listen",
            &tcp_addr,
            "--out",
            &tcp_file.to_string_lossy(),
        ],
        &out.join("tcp-sink.log"),
    )?;
    std::thread::sleep(Duration::from_millis(300));
    lab.helper(
        a,
        &["probe-send", "--to", &probe_addr],
        &out.join("probe-send.log"),
    )?;
    lab.helper(
        a,
        &["tcp-source", "--to", &tcp_addr],
        &out.join("tcp-source.log"),
    )?;
    std::thread::sleep(Duration::from_secs(3));
    let start_ms = now_ms();
    fault::set_link(&lab.underlay, b, &Netem::loss(100.0))?;
    std::thread::sleep(Duration::from_secs(2));
    fault::clear_link(&lab.underlay, b)?;
    std::thread::sleep(Duration::from_secs(5));
    let end_ms = now_ms();
    let outage = probe_stats(&probe_file, start_ms - 2000, end_ms)?;
    report.check(
        "probe:measured-over-tailscale",
        outage.received > 0,
        format!("{outage:?}"),
    );
    let tcp = tcp_stats(&tcp_file, start_ms - 2000, end_ms)?;
    report.check(
        "tcp:long-connection-over-tailscale",
        tcp.ended.is_none() && tcp.kbps > 0,
        format!("{tcp:?}"),
    );

    // 拦掉 a 到 b 的直连 UDP（IPv4 与 IPv6）：Tailscale 应回退到 DERP
    fault::block_udp_with(a, &b_addrs)?;
    std::thread::sleep(Duration::from_secs(8));
    let via_derp = ts.cli(
        a,
        &["ping", "-c", "3", "--until-direct=false", &ip_b.to_string()],
    );
    fault::unblock_udp(a)?;
    report.check(
        "tailscale:derp-fallback",
        via_derp.as_ref().is_ok_and(|o| o.contains("via DERP(lab)")),
        via_derp.map_or_else(
            |e| format!("{e:#}"),
            |o| o.lines().last().unwrap_or_default().to_owned(),
        ),
    );

    write_report(out, &report)?;
    drop(ts);
    drop(lab);
    Ok(report)
}

/// 中继冒烟测试：两个成员之间只有经中继的候选，确认真实的 WireGuard 握手和数据经 nett-relay 转发。
pub fn relay_smoke(topology: &Path, nett: &Path, out: &Path) -> anyhow::Result<Report> {
    let topo = Topology::load(topology)?;
    let underlay = Underlay::plan(&topo)?;
    underlay.down()?;
    let generated = material::generate(&topo, &underlay, out, false)?;
    let lab = start(&topo, &generated, underlay, nett)?;
    let mut report = Report::new("relay-smoke");
    let (a, b) = (&generated.nodes[0], &generated.nodes[1]);
    let relay = topo
        .nodes
        .iter()
        .find(|n| n.roles.iter().any(|r| r == "relay"))
        .context("topology has a relay")?;
    for node in &generated.nodes {
        wait_for(node, "peers_applied", |ev| count(ev, "peers_applied") > 0)?;
    }
    let ns_a = lab.underlay.node(&a.name).context("node a")?.netns.clone();
    let ns_r = lab
        .underlay
        .node(&relay.name)
        .context("relay")?
        .netns
        .clone();
    let before = crate::fault::counters(&ns_r, "eth0")?;
    for target in [b.mesh_ipv4.to_string(), b.mesh_ipv6.to_string()] {
        let result = ping(&ns_a, &target);
        report.check(
            &format!("ping-via-relay:{}->{}:{target}", a.name, b.name),
            result.is_ok(),
            result.unwrap_or_else(|e| format!("{e:#}")),
        );
    }
    let after = crate::fault::counters(&ns_r, "eth0")?;
    report.check(
        "relay-carried-traffic",
        after.0 > before.0 && after.1 > before.1,
        format!(
            "relay eth0 rx {} -> {}, tx {} -> {}",
            before.0, after.0, before.1, after.1
        ),
    );
    for node in &generated.nodes {
        if let Some(net) = lab.underlay.node(&node.name) {
            let dump =
                run_in(&net.netns, "wg", ["show", "nett0"]).unwrap_or_else(|e| format!("{e:#}"));
            report.record(&format!("wg:{}", node.name), dump);
        }
    }
    write_report(out, &report)?;
    drop(lab);
    Ok(report)
}

/// 按底层链路的流量判断当前路径（design/prototype.md 第 6.1 节）：每 [`SAMPLE_INTERVAL`] 读一次各接口的
/// 接收字节数。
/// 一次采样：时刻（Unix 毫秒）与各接口的累计接收字节数。
type Sample = (u64, Vec<u64>);

/// 采样间隔：恢复时间要分辨到几十毫秒；一次读取不到 1 毫秒。
const SAMPLE_INTERVAL: Duration = Duration::from_millis(20);
/// 判定流量已经离开一组链路：从某一刻起持续这么久低于阈值。
const QUIET_HOLD_MS: u64 = 200;

struct PathMonitor {
    samples: std::sync::Arc<std::sync::Mutex<Vec<Sample>>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl PathMonitor {
    fn start(watched: Vec<(String, String)>) -> Self {
        use std::sync::atomic::Ordering;
        let samples = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (s, st) = (samples.clone(), stop.clone());
        let handle = std::thread::spawn(move || {
            while !st.load(Ordering::Relaxed) {
                let now = crate::measure::now_ms();
                let rx: Vec<u64> = watched
                    .iter()
                    .map(|(ns, dev)| crate::fault::counters(ns, dev).map(|c| c.0).unwrap_or(0))
                    .collect();
                if let Ok(mut v) = s.lock() {
                    v.push((now, rx));
                }
                std::thread::sleep(SAMPLE_INTERVAL);
            }
        });
        Self {
            samples,
            stop,
            handle: Some(handle),
        }
    }

    /// 最近 `window` 内每个采样间隔的合计接收速率都低于 `bytes_per_s`。
    fn quiet_for(&self, window: Duration, bytes_per_s: u64) -> bool {
        let Ok(v) = self.samples.lock() else {
            return false;
        };
        let Some(last) = v.last().map(|s| s.0) else {
            return false;
        };
        let since = last.saturating_sub(u64::try_from(window.as_millis()).unwrap_or(u64::MAX));
        let recent: Vec<_> = v.iter().filter(|s| s.0 >= since).collect();
        recent.len() >= 2
            && v.first().is_some_and(|s| s.0 <= since)
            && recent.windows(2).all(|w| {
                let dt = w[1].0.saturating_sub(w[0].0).max(1);
                let bytes: u64 = w[1]
                    .1
                    .iter()
                    .zip(&w[0].1)
                    .map(|(b, a)| b.saturating_sub(*a))
                    .sum();
                bytes * 1000 / dt < bytes_per_s
            })
    }

    /// 最近 `window` 内各接口的平均接收速率（字节/秒）。
    fn rates(&self, window: Duration) -> Vec<u64> {
        let Ok(v) = self.samples.lock() else {
            return vec![];
        };
        let (Some(last), Some(n)) = (v.last(), v.last().map(|s| s.1.len())) else {
            return vec![];
        };
        let since = last
            .0
            .saturating_sub(u64::try_from(window.as_millis()).unwrap_or(u64::MAX));
        let Some(first) = v.iter().find(|s| s.0 >= since) else {
            return vec![0; n];
        };
        let dt = last.0.saturating_sub(first.0).max(1);
        last.1
            .iter()
            .zip(&first.1)
            .map(|(b, a)| b.saturating_sub(*a) * 1000 / dt)
            .collect()
    }

    /// `[from_ms, to_ms]` 内每秒承载流量最多的接口（低于 `bytes_per_s` 时为空）。
    fn busiest_per_second(&self, from_ms: u64, to_ms: u64, bytes_per_s: u64) -> Vec<Option<usize>> {
        let Ok(v) = self.samples.lock() else {
            return vec![];
        };
        let mut out = Vec::new();
        let mut t = from_ms;
        while t + 1000 <= to_ms {
            let first = v.iter().find(|s| s.0 >= t);
            let last = v.iter().rev().find(|s| s.0 <= t + 1000);
            let busiest = match (first, last) {
                (Some(a), Some(b)) if b.0 > a.0 => {
                    let dt = b.0 - a.0;
                    b.1.iter()
                        .zip(&a.1)
                        .map(|(y, x)| y.saturating_sub(*x) * 1000 / dt)
                        .enumerate()
                        .max_by_key(|(_, r)| *r)
                        .filter(|(_, r)| *r >= bytes_per_s)
                        .map(|(i, _)| i)
                }
                _ => None,
            };
            out.push(busiest);
            t += 1000;
        }
        out
    }

    /// `after_ms` 之后，被观察的接口合计接收速率从哪一刻起持续 [`QUIET_HOLD_MS`] 低于 `bytes_per_s`。
    fn first_quiet(&self, after_ms: u64, bytes_per_s: u64) -> Option<u64> {
        let v = self.samples.lock().ok()?;
        let quiet = |w: &[Sample]| {
            let dt = w[1].0.saturating_sub(w[0].0).max(1);
            let bytes: u64 = w[1]
                .1
                .iter()
                .zip(&w[0].1)
                .map(|(b, a)| b.saturating_sub(*a))
                .sum();
            bytes * 1000 / dt < bytes_per_s
        };
        let windows: Vec<&[Sample]> = v.windows(2).filter(|w| w[0].0 >= after_ms).collect();
        (0..windows.len()).find_map(|i| {
            let start = windows[i][0].0;
            let stretch: Vec<&&[Sample]> = windows[i..]
                .iter()
                .take_while(|w| w[0].0 < start + QUIET_HOLD_MS)
                .collect();
            let covered = stretch
                .last()
                .is_some_and(|w| w[1].0 >= start + QUIET_HOLD_MS);
            (covered && stretch.iter().all(|w| quiet(w))).then_some(start)
        })
    }
}

impl Drop for PathMonitor {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// 故障切换一次运行的结果。
#[derive(Debug, Clone, Serialize)]
pub struct FailoverRun {
    pub system: String,
    /// 从开始传输到流量稳定在直连上（毫秒）。
    pub settled_after_ms: u64,
    /// 探测流最长的中断（毫秒）。
    pub outage_ms: u64,
    /// 从故障解除到流量回到直连（毫秒），按底层链路判断（每 200 毫秒采样一次）。
    pub recovery_ms: Option<u64>,
    /// nett：从故障解除到决定方切回直连的事件（毫秒），用来区分决定的快慢与测量的粒度。
    pub switched_back_ms: Option<u64>,
    /// nett：故障之后第一次切换去了哪里（场景 7 应当是 TLS 传输的回环端口）。
    pub fell_back_to: Option<String>,
    /// 长连接是否被重置。
    pub tcp_ended: Option<String>,
    pub tcp_kbps: u64,
    #[serde(skip)]
    fault_at_ms: u64,
    #[serde(skip)]
    restored_at_ms: u64,
}

/// 时间的比较中，差距小于这个值视为相同：接收端时间戳的抖动（design/prototype.md 第 6.1 节）。
const COMPARE_TOLERANCE_MS: u64 = 10;

/// nett 的时间不比 Tailscale 长（容差之内）。
fn not_worse(nett: Option<u64>, tailscale: Option<u64>) -> bool {
    matches!((nett, tailscale), (Some(n), Some(t)) if n < t + COMPARE_TOLERANCE_MS)
}

/// 恢复时间不超过这个值，也算不比 Tailscale 差（design/prototype.md 第 6.1 节）。
const RECOVERY_FLOOR_MS: u64 = 200;
/// 中继链路上的流量低于这个速率，视为流量已经不走中继（长连接约 13 Mbit/s）。
const RELAY_QUIET_BYTES_PER_S: u64 = 100_000;
const WARMUP: Duration = Duration::from_secs(3);
/// 等待流量稳定在直连上的上限。
const SETTLE_TIMEOUT: Duration = Duration::from_secs(90);
const FAULT_HOLD: Duration = Duration::from_secs(12);
const RECOVERY_WAIT: Duration = Duration::from_secs(30);

fn start_workload(
    lab: &mut Lab,
    a: &str,
    b: &str,
    target: std::net::IpAddr,
    out: &Path,
) -> anyhow::Result<(PathBuf, PathBuf)> {
    let probe_file = out.join("probe.txt");
    let tcp_file = out.join("tcp.txt");
    let probe_addr = std::net::SocketAddr::new(target, 7000).to_string();
    let tcp_addr = std::net::SocketAddr::new(target, 7001).to_string();
    lab.helper(
        b,
        &[
            "probe-recv",
            "--listen",
            &probe_addr,
            "--out",
            &probe_file.to_string_lossy(),
        ],
        &out.join("probe-recv.log"),
    )?;
    lab.helper(
        b,
        &[
            "tcp-sink",
            "--listen",
            &tcp_addr,
            "--out",
            &tcp_file.to_string_lossy(),
        ],
        &out.join("tcp-sink.log"),
    )?;
    std::thread::sleep(Duration::from_millis(300));
    lab.helper(
        a,
        &["probe-send", "--to", &probe_addr],
        &out.join("probe-send.log"),
    )?;
    lab.helper(
        a,
        &["tcp-source", "--to", &tcp_addr],
        &out.join("tcp-source.log"),
    )?;
    Ok((probe_file, tcp_file))
}

/// 故障切掉什么（design/prototype.md 第 6.2 节）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cut {
    /// 场景 1 与 8：a 与 b 之间的直连 UDP。
    Direct,
    /// 场景 7 与 9：a 的全部 UDP，在它的上游拦截。
    AllUdp,
}

/// 场景 1 与 8、7 与 9：切断之后 12 秒恢复。`relay_links` 是较差路径（中继或 DERP）经过的接口。
fn failover_run(
    lab: &mut Lab,
    out: &Path,
    system: &str,
    target: std::net::IpAddr,
    relay_links: Vec<(String, String)>,
    cut: Cut,
) -> anyhow::Result<FailoverRun> {
    use crate::fault;
    use crate::measure::{now_ms, probe_stats, tcp_stats};
    let start_ms = now_ms();
    let monitor = PathMonitor::start(relay_links);
    let (probe_file, tcp_file) = start_workload(lab, "a", "b", target, out)?;
    std::thread::sleep(WARMUP);
    // 故障之前流量必须已经稳定在直连上：探测流持续收到（最近 3 秒至少 25 个），而中继链路没有流量
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    let flowing = || {
        let now = now_ms();
        probe_stats(&probe_file, now.saturating_sub(3000), now).is_ok_and(|p| p.received >= 25)
    };
    while !(flowing() && monitor.quiet_for(Duration::from_secs(3), RELAY_QUIET_BYTES_PER_S)) {
        if Instant::now() >= deadline {
            anyhow::bail!(
                "{system}: traffic did not settle on the direct path within {SETTLE_TIMEOUT:?}"
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let settled_ms = now_ms();
    let a_egress = lab.underlay.egress_ipv4("a").context("a egress")?;
    let fault_ms = now_ms();
    match cut {
        Cut::Direct => fault::block_udp_with("b", &[a_egress.into()])?,
        Cut::AllUdp => fault::block_udp_upstream(&lab.underlay, "a")?,
    }
    std::thread::sleep(FAULT_HOLD);
    let restore_ms = now_ms();
    match cut {
        Cut::Direct => fault::unblock_udp("b")?,
        Cut::AllUdp => fault::unblock_udp_upstream(&lab.underlay, "a")?,
    }
    std::thread::sleep(RECOVERY_WAIT);
    let end_ms = now_ms();
    let outage = probe_stats(&probe_file, fault_ms - 1000, restore_ms)?;
    let tcp = tcp_stats(&tcp_file, fault_ms - 2000, end_ms)?;
    let recovery_ms = monitor
        .first_quiet(restore_ms, RELAY_QUIET_BYTES_PER_S)
        .map(|t| t.saturating_sub(restore_ms));
    drop(monitor);
    Ok(FailoverRun {
        system: system.to_owned(),
        settled_after_ms: settled_ms.saturating_sub(start_ms),
        outage_ms: outage.max_gap_ms,
        recovery_ms,
        switched_back_ms: None,
        fell_back_to: None,
        tcp_ended: tcp.ended,
        tcp_kbps: tcp.kbps,
        fault_at_ms: fault_ms,
        restored_at_ms: restore_ms,
    })
}

fn nett_failover_once(
    topo: &Topology,
    nett: &Path,
    out: &Path,
    cut: Cut,
) -> anyhow::Result<FailoverRun> {
    let underlay = Underlay::plan(topo)?;
    underlay.down()?;
    let generated = material::generate(topo, &underlay, out, false)?;
    let mut lab = start(topo, &generated, underlay, nett)?;
    for node in &generated.nodes {
        wait_for(node, "peers_applied", |ev| count(ev, "peers_applied") > 0)?;
    }
    let b = generated
        .nodes
        .iter()
        .find(|n| n.name == "b")
        .context("node b")?;
    let links = ["r1", "r2"]
        .iter()
        .filter_map(|r| {
            lab.underlay
                .node(r)
                .map(|n| (n.netns.clone(), "eth0".to_owned()))
        })
        .collect();
    let mut run = failover_run(&mut lab, out, "nett", b.mesh_ipv4.into(), links, cut)
        .map_err(|e| e.context(diagnose(&lab, &generated.nodes)))?;
    let a = generated
        .nodes
        .iter()
        .find(|n| n.name == "a")
        .context("node a")?;
    run.switched_back_ms = events(a).iter().find_map(|e| {
        let at = e["at_ms"].as_u64()?;
        (e["event"] == "path_switched"
            && at >= run.restored_at_ms
            && e["to"].as_str().is_some_and(|t| t.starts_with("direct")))
        .then(|| at - run.restored_at_ms)
    });
    run.fell_back_to = events(a).iter().find_map(|e| {
        let at = e["at_ms"].as_u64()?;
        (e["event"] == "path_switched" && at >= run.fault_at_ms && at < run.restored_at_ms)
            .then(|| e["to"].as_str().unwrap_or_default().to_owned())
    });
    drop(lab);
    Ok(run)
}

fn tailscale_failover_once(topo: &Topology, out: &Path, cut: Cut) -> anyhow::Result<FailoverRun> {
    use crate::tailscale::{CONTROL_NETNS, TailscaleLab};
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
    let ts = TailscaleLab::up(out, &["a", "b"])?;
    let ip_b = ts.ipv4("b")?;
    // 等到直连：tailscale ping 在拿到直连应答后停止
    ts.cli("a", &["ping", "-c", "20", &ip_b.to_string()]).ok();
    let links = vec![(CONTROL_NETNS.to_owned(), "eth0".to_owned())];
    let run = failover_run(&mut lab, out, "tailscale", ip_b.into(), links, cut)?;
    drop(ts);
    drop(lab);
    Ok(run)
}

fn percentile(values: &mut [u64], p: f64) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let rank = ((p * values.len() as f64).ceil() as usize).clamp(1, values.len());
    Some(values[rank - 1])
}

/// 场景 1、8 与 Tailscale 对比：中断时间、恢复时间的 p95 与最大值不超过 Tailscale，长连接不断
/// （design/prototype.md 第 6.1、6.2 节）。
pub fn failover(
    topology: &Path,
    nett: &Path,
    out: &Path,
    repeat: usize,
    with_tailscale: bool,
    cut: Cut,
) -> anyhow::Result<Report> {
    let topo = Topology::load(topology)?;
    let mut report = Report::new(match cut {
        Cut::Direct => "1-8-failover",
        Cut::AllUdp => "7-9-fallback",
    });
    let mut runs = Vec::new();
    for i in 0..repeat {
        runs.push(nett_failover_once(
            &topo,
            nett,
            &out.join(format!("nett-{i}")),
            cut,
        )?);
        if with_tailscale {
            runs.push(tailscale_failover_once(
                &topo,
                &out.join(format!("tailscale-{i}")),
                cut,
            )?);
        }
    }
    for r in &runs {
        report.record(&format!("run:{}", r.system), format!("{r:?}"));
    }
    let summary = |system: &str| {
        let mine: Vec<&FailoverRun> = runs.iter().filter(|r| r.system == system).collect();
        let mut outage: Vec<u64> = mine.iter().map(|r| r.outage_ms).collect();
        let mut recovery: Vec<u64> = mine.iter().filter_map(|r| r.recovery_ms).collect();
        let unrecovered = mine.iter().filter(|r| r.recovery_ms.is_none()).count();
        let resets = mine.iter().filter(|r| r.tcp_ended.is_some()).count();
        (
            percentile(&mut outage, 0.95),
            outage.iter().max().copied(),
            percentile(&mut recovery, 0.95),
            recovery.iter().max().copied(),
            unrecovered,
            resets,
        )
    };
    let nett_s = summary("nett");
    if cut == Cut::AllUdp {
        // UDP 全部被拦：直接改用 TLS，不逐个尝试 UDP 中继（design/mesh.md 第 8.2 节）
        let fell_back = runs
            .iter()
            .filter(|r| r.system == "nett")
            .filter(|r| {
                r.fell_back_to
                    .as_deref()
                    .is_some_and(|to| to.contains("127.0.0.1"))
            })
            .count();
        report.check(
            "nett:fell-back-to-tls-directly",
            fell_back == repeat,
            format!("{fell_back} of {repeat} runs switched straight to TLS"),
        );
    }
    report.check(
        "nett:long-connection-never-reset",
        nett_s.5 == 0,
        format!("{} of {repeat} runs reset the connection", nett_s.5),
    );
    report.check(
        "nett:recovered-to-direct",
        nett_s.4 == 0,
        format!(
            "{} of {repeat} runs did not return to direct within {RECOVERY_WAIT:?}",
            nett_s.4
        ),
    );
    report.record(
        "nett:summary",
        format!(
            "outage p95 {:?} max {:?} ms; recovery p95 {:?} max {:?} ms",
            nett_s.0, nett_s.1, nett_s.2, nett_s.3
        ),
    );
    if with_tailscale {
        let ts_s = summary("tailscale");
        report.record(
            "tailscale:summary",
            format!(
                "outage p95 {:?} max {:?} ms; recovery p95 {:?} max {:?} ms; resets {}",
                ts_s.0, ts_s.1, ts_s.2, ts_s.3, ts_s.5
            ),
        );
        report.check(
            "outage:not-worse-than-tailscale",
            not_worse(nett_s.0, ts_s.0) && not_worse(nett_s.1, ts_s.1),
            "p95 and max",
        );
        // 恢复期间流量照常经较差的路径：不超过绝对下限也算不比 Tailscale 差（design/prototype.md 第 6.1 节）
        let within_floor = |n: Option<u64>| n.is_some_and(|n| n <= RECOVERY_FLOOR_MS);
        report.check(
            "recovery:not-worse-than-tailscale",
            (not_worse(nett_s.2, ts_s.2) || within_floor(nett_s.2))
                && (not_worse(nett_s.3, ts_s.3) || within_floor(nett_s.3)),
            format!("p95 and max, or within {RECOVERY_FLOOR_MS} ms"),
        );
    }
    write_report(out, &report)?;
    Ok(report)
}

/// 场景 2、3 的故障：当前中继的链路 100% 丢包，或重启当前中继的进程。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayFault {
    Loss,
    Restart,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayRun {
    pub system: String,
    pub faulted: String,
    /// 故障之后流量所在的中继；没有流量时为空。
    pub after: Option<String>,
    pub outage_ms: u64,
    pub tcp_ended: Option<String>,
}

/// 故障持续多久之后统计。
const RELAY_FAULT_HOLD: Duration = Duration::from_secs(20);

/// 最近 2 秒承载流量最多的中继链路（低于 [`RELAY_QUIET_BYTES_PER_S`] 时为空）。
fn busiest(monitor: &PathMonitor) -> Option<usize> {
    let rates = monitor.rates(Duration::from_secs(2));
    let (i, r) = rates.iter().enumerate().max_by_key(|(_, r)| **r)?;
    (*r >= RELAY_QUIET_BYTES_PER_S).then_some(i)
}

/// 等流量稳定在某一个中继上：探测流持续收到，且有一条中继链路承载流量。返回它的序号。
fn settle_on_relay(
    monitor: &PathMonitor,
    probe_file: &Path,
    system: &str,
) -> anyhow::Result<usize> {
    use crate::measure::{now_ms, probe_stats};
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let now = now_ms();
        let flowing =
            probe_stats(probe_file, now.saturating_sub(3000), now).is_ok_and(|p| p.received >= 25);
        if let (true, Some(i)) = (flowing, busiest(monitor)) {
            return Ok(i);
        }
        if Instant::now() >= deadline {
            anyhow::bail!("{system}: traffic did not settle on a relay within {SETTLE_TIMEOUT:?}");
        }
    }
}

/// `links`：每个中继（或 DERP）的名称与它的链路。`fault` 对第 i 个中继执行故障。
fn relay_fault_run(
    lab: &mut Lab,
    out: &Path,
    system: &str,
    target: std::net::IpAddr,
    links: &[(String, String, String)],
    mut fault: impl FnMut(&mut Lab, usize) -> anyhow::Result<()>,
) -> anyhow::Result<RelayRun> {
    use crate::measure::{now_ms, probe_stats, tcp_stats};
    let monitor = PathMonitor::start(
        links
            .iter()
            .map(|(_, ns, dev)| (ns.clone(), dev.clone()))
            .collect(),
    );
    let (probe_file, tcp_file) = start_workload(lab, "a", "b", target, out)?;
    let current = settle_on_relay(&monitor, &probe_file, system)?;
    let fault_ms = now_ms();
    fault(lab, current)?;
    std::thread::sleep(RELAY_FAULT_HOLD);
    let end_ms = now_ms();
    let after = busiest(&monitor).map(|i| links[i].0.clone());
    let outage = probe_stats(&probe_file, fault_ms - 1000, end_ms)?;
    let tcp = tcp_stats(&tcp_file, fault_ms - 2000, end_ms)?;
    Ok(RelayRun {
        system: system.to_owned(),
        faulted: links[current].0.clone(),
        after,
        outage_ms: outage.max_gap_ms,
        tcp_ended: tcp.ended,
    })
}

fn nett_relay_fault_once(
    topo: &Topology,
    nett: &Path,
    out: &Path,
    kind: RelayFault,
) -> anyhow::Result<RelayRun> {
    let underlay = Underlay::plan(topo)?;
    underlay.down()?;
    let generated = material::generate(topo, &underlay, out, false)?;
    let mut lab = start(topo, &generated, underlay, nett)?;
    for node in &generated.nodes {
        wait_for(node, "peers_applied", |ev| count(ev, "peers_applied") > 0)?;
    }
    let b = generated
        .nodes
        .iter()
        .find(|n| n.name == "b")
        .context("node b")?;
    let relays: Vec<&LabNode> = ["r1", "r2"]
        .iter()
        .filter_map(|r| generated.nodes.iter().find(|n| n.name == *r))
        .collect();
    let links: Vec<(String, String, String)> = relays
        .iter()
        .filter_map(|r| {
            lab.underlay
                .node(&r.name)
                .map(|n| (r.name.clone(), n.netns.clone(), "eth0".to_owned()))
        })
        .collect();
    let run = relay_fault_run(
        &mut lab,
        out,
        "nett",
        b.mesh_ipv4.into(),
        &links,
        |lab, i| match kind {
            RelayFault::Loss => crate::fault::set_link(
                &lab.underlay,
                &relays[i].name,
                &crate::fault::Netem::loss(100.0),
            ),
            RelayFault::Restart => lab.restart_relay(relays[i], nett),
        },
    );
    let run = run.map_err(|e| e.context(diagnose(&lab, &generated.nodes)))?;
    drop(lab);
    Ok(run)
}

fn tailscale_relay_fault_once(
    topo: &Topology,
    out: &Path,
    kind: RelayFault,
) -> anyhow::Result<RelayRun> {
    use crate::tailscale::{TailscaleLab, derp_netns};
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
    // 两端之间没有直连：只能经 DERP
    let a_egress = lab.underlay.egress_ipv4("a").context("a egress")?;
    crate::fault::block_udp_with("b", &[a_egress.into()])?;
    let ts = std::cell::RefCell::new(TailscaleLab::up_with(out, &["a", "b"], 2)?);
    let ip_b = ts.borrow().ipv4("b")?;
    ts.borrow()
        .cli(
            "a",
            &["ping", "-c", "5", "--until-direct=false", &ip_b.to_string()],
        )
        .ok();
    let links: Vec<(String, String, String)> = (1..=2)
        .map(|i| (format!("derp{i}"), derp_netns(i), "eth0".to_owned()))
        .collect();
    let run = relay_fault_run(
        &mut lab,
        out,
        "tailscale",
        ip_b.into(),
        &links,
        |lab, i| match kind {
            RelayFault::Loss => {
                // DERP 的链路接在"公网"网桥上，两端都加 netem
                let (ns, port) = (derp_netns(i + 1), format!("v-derp{}", i + 1));
                for (n, dev) in [
                    (ns.as_str(), "eth0"),
                    (crate::net::INET_NETNS, port.as_str()),
                ] {
                    run(
                        "tc",
                        [
                            "-n", n, "qdisc", "replace", "dev", dev, "root", "netem", "loss",
                            "100%",
                        ],
                    )?;
                }
                let _ = lab;
                Ok(())
            }
            RelayFault::Restart => ts.borrow_mut().restart_derp(i + 1),
        },
    )?;
    drop(ts);
    drop(lab);
    Ok(run)
}

/// 场景 2（中继失效）、3（中继进程重启）与 Tailscale 对比：中断时间的 p95 与最大值不超过 Tailscale，
/// 长连接不断（design/prototype.md 第 6.2 节）。
pub fn relay_fault(
    topology: &Path,
    nett: &Path,
    out: &Path,
    repeat: usize,
    with_tailscale: bool,
    kind: RelayFault,
) -> anyhow::Result<Report> {
    let topo = Topology::load(topology)?;
    let name = match kind {
        RelayFault::Loss => "2-relay-loss",
        RelayFault::Restart => "3-relay-restart",
    };
    let mut report = Report::new(name);
    let mut runs = Vec::new();
    for i in 0..repeat {
        runs.push(nett_relay_fault_once(
            &topo,
            nett,
            &out.join(format!("nett-{i}")),
            kind,
        )?);
        if with_tailscale {
            runs.push(tailscale_relay_fault_once(
                &topo,
                &out.join(format!("tailscale-{i}")),
                kind,
            )?);
        }
    }
    for r in &runs {
        report.record(&format!("run:{}", r.system), format!("{r:?}"));
    }
    let stats = |system: &str| {
        let mut outage: Vec<u64> = runs
            .iter()
            .filter(|r| r.system == system)
            .map(|r| r.outage_ms)
            .collect();
        let resets = runs
            .iter()
            .filter(|r| r.system == system && r.tcp_ended.is_some())
            .count();
        (
            percentile(&mut outage, 0.95),
            outage.iter().max().copied(),
            resets,
        )
    };
    let n = stats("nett");
    report.check(
        "nett:long-connection-never-reset",
        n.2 == 0,
        format!("{} of {repeat} runs reset the connection", n.2),
    );
    if kind == RelayFault::Loss {
        let moved = runs
            .iter()
            .filter(|r| r.system == "nett")
            .all(|r| r.after.as_ref().is_some_and(|a| *a != r.faulted));
        report.check(
            "nett:moved-to-the-other-relay",
            moved,
            "traffic left the failed relay",
        );
    }
    report.record(
        "nett:summary",
        format!("outage p95 {:?} max {:?} ms", n.0, n.1),
    );
    if with_tailscale {
        let t = stats("tailscale");
        report.record(
            "tailscale:summary",
            format!("outage p95 {:?} max {:?} ms; resets {}", t.0, t.1, t.2),
        );
        report.check(
            "outage:not-worse-than-tailscale",
            not_worse(n.0, t.0) && not_worse(n.1, t.1),
            "p95 and max",
        );
    }
    write_report(out, &report)?;
    Ok(report)
}

/// 场景 4–6 的路径质量波动（design/prototype.md 第 6.2 节）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Wave {
    /// 持续的随机丢包（百分比）。
    Loss(f32),
    /// 延迟抖动：平均延迟与抖动（毫秒）。
    Jitter(u32),
    /// 间歇断开：断 2 秒、通 8 秒。
    Flap,
    /// 两条路径的延迟交替变好：前半程当前中继加这么多毫秒的延迟，后半程换成另一个中继加。
    Alternate(u32),
}

#[derive(Debug, Clone, Serialize)]
pub struct WaveRun {
    pub system: String,
    /// 期间流量在中继之间换了几次。
    pub switches: usize,
    /// 是否回到过之前离开的路径（来回切换）。
    pub returned: bool,
    /// 交替变好时，每个半程开始后跟随到更快路径所用的秒数。
    pub follow_s: Vec<Option<usize>>,
    pub tcp_kbps: u64,
    pub tcp_ended: Option<String>,
    /// 探测流的送达率（千分比）与最长中断。
    pub delivered_permille: u64,
    pub max_gap_ms: u64,
    /// 最长的几段中断：（距损伤开始的毫秒数，时长），用于判断中断发生在切换时还是损伤变化时。
    pub longest_gaps: Vec<(u64, u64)>,
}

/// `impair(lab, i, wave)` 在第 i 个中继的链路上施加（`Some`）或解除（`None`）损伤。
fn wave_run(
    lab: &mut Lab,
    out: &Path,
    system: &str,
    target: std::net::IpAddr,
    links: &[(String, String, String)],
    (wave, duration, relay_ips): (Wave, Duration, Option<[std::net::Ipv4Addr; 2]>),
    mut impair: impl FnMut(&mut Lab, usize, Option<&crate::fault::Netem>) -> anyhow::Result<()>,
) -> anyhow::Result<WaveRun> {
    use crate::fault::Netem;
    use crate::measure::{PROBE_INTERVAL, now_ms, probe_stats, tcp_stats};
    let monitor = PathMonitor::start(
        links
            .iter()
            .map(|(_, ns, dev)| (ns.clone(), dev.clone()))
            .collect(),
    );
    if let Wave::Alternate(ms) = wave {
        // 排队规则在开始传输之前建好，之后只改过滤器：替换排队规则会丢掉正在排队的包
        crate::fault::prepare_delay("a", &["delay".into(), format!("{ms}ms")])?;
    }
    let (probe_file, tcp_file) = start_workload(lab, "a", "b", target, out)?;
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    let current = loop {
        std::thread::sleep(Duration::from_secs(1));
        let now = now_ms();
        let flowing =
            probe_stats(&probe_file, now.saturating_sub(3000), now).is_ok_and(|p| p.received >= 25);
        let rates = monitor.rates(Duration::from_secs(2));
        let busiest = rates
            .iter()
            .enumerate()
            .max_by_key(|(_, r)| **r)
            .filter(|(_, r)| **r >= RELAY_QUIET_BYTES_PER_S)
            .map(|(i, _)| i);
        if let (true, Some(i)) = (flowing, busiest) {
            break i;
        }
        if Instant::now() >= deadline {
            anyhow::bail!("{system}: traffic did not settle on a relay within {SETTLE_TIMEOUT:?}");
        }
    };
    let start_ms = now_ms();
    match wave {
        Wave::Loss(p) => {
            impair(lab, current, Some(&Netem::loss(p)))?;
            std::thread::sleep(duration);
        }
        Wave::Jitter(ms) => {
            let netem = Netem {
                delay_ms: Some(ms),
                jitter_ms: Some(ms),
                ..Netem::default()
            };
            impair(lab, current, Some(&netem))?;
            std::thread::sleep(duration);
        }
        Wave::Alternate(_) => {
            // 延迟加在数据方向上：发送方 a 到中继（或 DERP）那一段，两种系统的往返时间都只增加一次延迟
            let ips = relay_ips.context("alternating needs the relay addresses")?;
            crate::fault::route_delay("a", ips[current])?;
            std::thread::sleep(duration / 2);
            crate::fault::route_delay("a", ips[1 - current])?;
            std::thread::sleep(duration / 2);
        }
        Wave::Flap => {
            let end = Instant::now() + duration;
            while Instant::now() < end {
                impair(lab, current, Some(&Netem::loss(100.0)))?;
                std::thread::sleep(Duration::from_secs(2));
                impair(lab, current, None)?;
                std::thread::sleep(Duration::from_secs(8));
            }
        }
    }
    let end_ms = now_ms();
    impair(lab, current, None)?;
    if matches!(wave, Wave::Alternate(_)) {
        crate::fault::clear_eth0("a")?;
    }
    let busiest = monitor.busiest_per_second(start_ms, end_ms, RELAY_QUIET_BYTES_PER_S);
    // 交替变好：每个半程开始后，流量换到更快的那个中继用了多少秒
    let follow_s: Vec<Option<usize>> = if matches!(wave, Wave::Alternate(_)) {
        let half = busiest.len() / 2;
        [(0, 1 - current), (half, current)]
            .iter()
            .map(|(from, faster)| busiest[*from..].iter().position(|b| *b == Some(*faster)))
            .collect()
    } else {
        Vec::new()
    };
    // 注入损伤之前所在的中继是起点：损伤开始后第一秒内就离开，也算一次切换
    let mut switches = 0;
    let mut last = Some(current);
    let mut visited = vec![current];
    let mut returned = false;
    for b in busiest.into_iter().flatten() {
        if last.is_some_and(|l| l != b) {
            switches += 1;
            // 回到之前离开过的路径：来回切换
            returned |= visited.contains(&b);
            visited.push(b);
        }
        last = Some(b);
    }
    let probe = probe_stats(&probe_file, start_ms, end_ms)?;
    let expected = (end_ms - start_ms) / u64::try_from(PROBE_INTERVAL.as_millis()).unwrap_or(100);
    let tcp = tcp_stats(&tcp_file, start_ms, end_ms)?;
    let mut longest = probe.gaps.clone();
    longest.sort_by_key(|g| std::cmp::Reverse(g.1));
    longest.truncate(5);
    Ok(WaveRun {
        system: system.to_owned(),
        switches,
        returned,
        follow_s,
        tcp_kbps: tcp.kbps,
        tcp_ended: tcp.ended,
        delivered_permille: (probe.received as u64 * 1000 / expected.max(1)).min(1000),
        max_gap_ms: probe.max_gap_ms,
        longest_gaps: longest
            .into_iter()
            .map(|(at, len)| (at.saturating_sub(start_ms), len))
            .collect(),
    })
}

fn derp_impair(i: usize, netem: Option<&crate::fault::Netem>) -> anyhow::Result<()> {
    let ns = crate::tailscale::derp_netns(i + 1);
    let port = format!("v-derp{}", i + 1);
    for (n, dev) in [
        (ns.as_str(), "eth0"),
        (crate::net::INET_NETNS, port.as_str()),
    ] {
        match netem {
            Some(netem) => {
                let mut args: Vec<String> =
                    ["-n", n, "qdisc", "replace", "dev", dev, "root", "netem"]
                        .iter()
                        .map(|s| (*s).to_owned())
                        .collect();
                args.extend(netem.args());
                run("tc", &args)?;
            }
            None => {
                run("tc", ["-n", n, "qdisc", "del", "dev", dev, "root"]).ok();
            }
        }
    }
    Ok(())
}

/// 场景 4–6 与 Tailscale 对比：切换次数不多于 Tailscale，吞吐不低于它的 95%，最长中断不超过它，长连接不断。
pub fn wave(
    topology: &Path,
    nett: &Path,
    out: &Path,
    repeat: usize,
    with_tailscale: bool,
    wave: Wave,
    duration: Duration,
) -> anyhow::Result<Report> {
    use crate::tailscale::{TailscaleLab, derp_netns};
    let topo = Topology::load(topology)?;
    let name = match wave {
        Wave::Loss(p) => format!("4-loss-{p}"),
        Wave::Jitter(ms) => format!("5-jitter-{ms}ms"),
        Wave::Flap => "6-flap".to_owned(),
        Wave::Alternate(ms) => format!("5-alternate-{ms}ms"),
    };
    let mut report = Report::new(&name);
    let mut runs = Vec::new();
    for i in 0..repeat {
        // nett
        let dir = out.join(format!("nett-{i}"));
        let underlay = Underlay::plan(&topo)?;
        underlay.down()?;
        let generated = material::generate(&topo, &underlay, &dir, false)?;
        let mut lab = start(&topo, &generated, underlay, nett)?;
        for node in &generated.nodes {
            wait_for(node, "peers_applied", |ev| count(ev, "peers_applied") > 0)?;
        }
        let b = generated
            .nodes
            .iter()
            .find(|n| n.name == "b")
            .context("node b")?;
        let relays = ["r1", "r2"];
        let links: Vec<(String, String, String)> = relays
            .iter()
            .filter_map(|r| {
                lab.underlay
                    .node(r)
                    .map(|n| ((*r).to_owned(), n.netns.clone(), "eth0".to_owned()))
            })
            .collect();
        let relay_addrs = match (
            lab.underlay.public_ipv4("r1"),
            lab.underlay.public_ipv4("r2"),
        ) {
            (Some(a), Some(b)) => Some([a, b]),
            _ => None,
        };
        runs.push(
            wave_run(
                &mut lab,
                &dir,
                "nett",
                b.mesh_ipv4.into(),
                &links,
                (wave, duration, relay_addrs),
                |lab, i, netem| match netem {
                    Some(n) => crate::fault::set_link(&lab.underlay, relays[i], n),
                    None => crate::fault::clear_link(&lab.underlay, relays[i]),
                },
            )
            .map_err(|e| e.context(diagnose(&lab, &generated.nodes)))?,
        );
        drop(lab);
        if !with_tailscale {
            continue;
        }
        // Tailscale：两个 DERP 区域，两端之间没有直连
        let dir = out.join(format!("tailscale-{i}"));
        let underlay = Underlay::plan(&topo)?;
        underlay.down()?;
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        underlay.up(&topo)?;
        let mut lab = Lab {
            underlay,
            processes: Vec::new(),
            relays: Vec::new(),
            helpers: Vec::new(),
        };
        let a_egress = lab.underlay.egress_ipv4("a").context("a egress")?;
        crate::fault::block_udp_with("b", &[a_egress.into()])?;
        let ts = TailscaleLab::up_with(&dir, &["a", "b"], 2)?;
        let ip_b = ts.ipv4("b")?;
        ts.cli(
            "a",
            &["ping", "-c", "5", "--until-direct=false", &ip_b.to_string()],
        )
        .ok();
        let links: Vec<(String, String, String)> = (1..=2)
            .map(|i| (format!("derp{i}"), derp_netns(i), "eth0".to_owned()))
            .collect();
        runs.push(wave_run(
            &mut lab,
            &dir,
            "tailscale",
            ip_b.into(),
            &links,
            (
                wave,
                duration,
                Some([
                    crate::tailscale::derp_ipv4(1),
                    crate::tailscale::derp_ipv4(2),
                ]),
            ),
            |_, i, netem| derp_impair(i, netem),
        )?);
        drop(ts);
        drop(lab);
    }
    for r in &runs {
        report.record(&format!("run:{}", r.system), format!("{r:?}"));
    }
    let of = |system: &str| {
        runs.iter()
            .filter(|r| r.system == system)
            .collect::<Vec<_>>()
    };
    let n = of("nett");
    report.check(
        "nett:long-connection-never-reset",
        n.iter().all(|r| r.tcp_ended.is_none()),
        "",
    );
    if matches!(wave, Wave::Alternate(_)) {
        report.check(
            "nett:follows-within-a-minute",
            n.iter().all(|r| {
                r.follow_s.len() == 2 && r.follow_s.iter().all(|f| f.is_some_and(|s| s <= 60))
            }),
            format!(
                "seconds to follow each half {:?}",
                n.iter().map(|r| r.follow_s.clone()).collect::<Vec<_>>()
            ),
        );
    }
    // 交替变好时每个半程跟随一次更优的路径；其他波动离开受损路径至多一次、不往返
    let allowed = if matches!(wave, Wave::Alternate(_)) {
        2
    } else {
        1
    };
    report.check(
        "nett:no-flapping",
        n.iter()
            .all(|r| r.switches <= allowed && (allowed > 1 || !r.returned)),
        format!(
            "switches per run {:?}",
            n.iter().map(|r| r.switches).collect::<Vec<_>>()
        ),
    );
    if with_tailscale {
        let t = of("tailscale");
        let max =
            |v: &[&WaveRun], f: fn(&WaveRun) -> u64| v.iter().map(|r| f(r)).max().unwrap_or(0);
        let min =
            |v: &[&WaveRun], f: fn(&WaveRun) -> u64| v.iter().map(|r| f(r)).min().unwrap_or(0);
        report.check(
            "throughput:at-least-95-percent",
            min(&n, |r| r.tcp_kbps) * 100 >= min(&t, |r| r.tcp_kbps) * 95,
            format!(
                "nett min {} kbit/s, tailscale min {}",
                min(&n, |r| r.tcp_kbps),
                min(&t, |r| r.tcp_kbps)
            ),
        );
        report.check(
            "outage:not-worse-than-tailscale",
            not_worse(
                Some(max(&n, |r| r.max_gap_ms)),
                Some(max(&t, |r| r.max_gap_ms)),
            ),
            format!(
                "nett max {} ms, tailscale max {} ms",
                max(&n, |r| r.max_gap_ms),
                max(&t, |r| r.max_gap_ms)
            ),
        );
    }
    write_report(out, &report)?;
    Ok(report)
}

/// 场景 15 中旧路径送来一串迟到包的间隔（design/prototype.md 第 6.3 节）。
const ROAMING_KICK_INTERVAL: Duration = Duration::from_secs(60);

/// 场景 15：漫游纠正（只对 nett）。切换到中继之后，旧的直连路径每分钟送来一串延迟 3 秒、乱序的包；
/// 决定方的 endpoint 每次被改回旧路径后 1.5 秒内纠正，长连接不断；偏离的总时长只记录。
pub fn roaming(
    topology: &Path,
    nett: &Path,
    out: &Path,
    duration: Duration,
) -> anyhow::Result<Report> {
    use crate::measure::{now_ms, probe_stats, tcp_stats};
    let topo = Topology::load(topology)?;
    let underlay = Underlay::plan(&topo)?;
    underlay.down()?;
    let generated = material::generate(&topo, &underlay, out, false)?;
    let mut lab = start(&topo, &generated, underlay, nett)?;
    let mut report = Report::new("15-roaming");
    for node in &generated.nodes {
        wait_for(node, "peers_applied", |ev| count(ev, "peers_applied") > 0)?;
    }
    let a = generated
        .nodes
        .iter()
        .find(|n| n.name == "a")
        .context("node a")?;
    let b = generated
        .nodes
        .iter()
        .find(|n| n.name == "b")
        .context("node b")?;
    let (ns_a, ns_b) = (crate::net::netns("a"), crate::net::netns("b"));
    // b 是发送方：每次被拨回直连后，b 在收到 a 的下一个包之前会经直连发出若干个包，3 秒后迟到地到达 a
    let (probe_file, tcp_file) = start_workload(&mut lab, "b", "a", a.mesh_ipv4.into(), out)?;
    let b_direct = format!(
        "{}:{}",
        lab.underlay.public_ipv4("b").context("b address")?,
        material::LISTEN_PORT
    );
    let endpoint_of = |ns: &str, key: &str| -> Option<String> {
        run_in(ns, "wg", ["show", "nett0", "endpoints"])
            .ok()?
            .lines()
            .find_map(|l| {
                l.split_once('\t')
                    .filter(|(k, _)| *k == key)
                    .map(|(_, e)| e.trim().to_owned())
            })
    };
    let a_key = crate::material::wg_text(&a.mesh_public_key);
    let b_key = crate::material::wg_text(&b.mesh_public_key);
    let a_egress = lab.underlay.egress_ipv4("a").context("a egress")?;
    // 等到两端都经直连：a 的 endpoint 是 b 的直连地址，b 看到的 a 的地址是 a 的出口地址（映射地址）
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    let a_mapped = loop {
        std::thread::sleep(Duration::from_secs(1));
        if let (Some(e), Some(m)) = (endpoint_of(&ns_a, &b_key), endpoint_of(&ns_b, &a_key))
            && e == b_direct
            && m.starts_with(&format!("{a_egress}:"))
        {
            break m;
        }
        if Instant::now() >= deadline {
            anyhow::bail!("a did not settle on the direct path within {SETTLE_TIMEOUT:?}");
        }
    };
    // 只拦 a → b 的直连：a 切到中继；b → a 的直连仍然通，但加上 3 秒延迟与乱序
    crate::fault::block_udp_from("b", a_egress)?;
    crate::fault::delay_to("b", a_egress, 3000, 500)?;
    wait_for(a, "a switch to a relay", |ev| {
        ev.iter().any(|e| e["event"] == "path_switched")
    })?;
    std::thread::sleep(Duration::from_secs(3));

    // 抓包留作现场：b 发出的直连包，以及它们是否到达 a
    let b_ip = lab
        .underlay
        .public_ipv4("b")
        .context("b address")?
        .to_string();
    lab.tool(
        &ns_b,
        "tcpdump",
        &[
            "-n",
            "-l",
            "-i",
            "eth0",
            "udp",
            "and",
            "dst",
            "host",
            &a_egress.to_string(),
        ],
        &out.join("cap-b-direct-out.txt"),
    )?;
    lab.tool(
        &ns_a,
        "tcpdump",
        &["-n", "-l", "-i", "eth0", "udp", "and", "src", "host", &b_ip],
        &out.join("cap-a-direct-in.txt"),
    )?;
    // 每分钟把 b 的 endpoint 拨回直连一次：b 发出的一串直连包 3 秒后迟到、乱序地到达 a，把 a 的 endpoint 改回旧路径
    let start_ms = now_ms();
    let end = Instant::now() + duration;
    let mut last_kick = Instant::now() - ROAMING_KICK_INTERVAL;
    let mut samples: Vec<(u64, bool)> = Vec::new();
    let mut kick_error: Option<String> = None;
    while Instant::now() < end {
        if last_kick.elapsed() >= ROAMING_KICK_INTERVAL {
            last_kick = Instant::now();
            if let Err(e) = run_in(
                &ns_b,
                "wg",
                ["set", "nett0", "peer", &a_key, "endpoint", &a_mapped],
            ) {
                kick_error.get_or_insert_with(|| format!("{e:#}"));
            }
        }
        let deviated = endpoint_of(&ns_a, &b_key).is_some_and(|e| e == b_direct);
        samples.push((now_ms(), deviated));
        std::thread::sleep(Duration::from_millis(100));
    }
    let end_ms = now_ms();
    // 偏离的每一段：开始到结束
    let mut episodes = Vec::new();
    let mut since = None;
    for (t, deviated) in &samples {
        match (deviated, since) {
            (true, None) => since = Some(*t),
            (false, Some(s)) => {
                episodes.push(t - s);
                since = None;
            }
            _ => {}
        }
    }
    if let Some(s) = since {
        episodes.push(end_ms - s);
    }
    let total: u64 = episodes.iter().sum();
    let longest = episodes.iter().max().copied().unwrap_or(0);
    let window = end_ms - start_ms;
    report.check(
        "roaming:deviations-observed",
        !episodes.is_empty(),
        format!(
            "{} episodes; mapped {a_mapped}; kick error {kick_error:?}",
            episodes.len()
        ),
    );
    report.check(
        "roaming:each-corrected-within-1.5s",
        longest <= 1500,
        format!("longest {longest} ms"),
    );
    report.record(
        "roaming:total-deviation",
        format!(
            "{total} ms of {window} ms ({:.2}%)",
            total as f64 * 100.0 / window.max(1) as f64
        ),
    );
    let tcp = tcp_stats(&tcp_file, start_ms, end_ms)?;
    report.check(
        "roaming:long-connection-survives",
        tcp.ended.is_none(),
        format!("{tcp:?}"),
    );
    let probe = probe_stats(&probe_file, start_ms, end_ms)?;
    report.record(
        "roaming:probe-stream",
        format!("{probe:?}").chars().take(200).collect::<String>(),
    );
    write_report(out, &report)?;
    drop(lab);
    Ok(report)
}

fn lines(path: &Path) -> usize {
    std::fs::read_to_string(path)
        .map(|t| {
            t.lines()
                .filter(|l| l.contains(" > ") || l.contains("UDP"))
                .count()
        })
        .unwrap_or(0)
}

fn iperf(lab: &mut Lab, target: std::net::Ipv4Addr, out: &Path, tag: &str) -> anyhow::Result<u64> {
    let ns_a = crate::net::netns("a");
    let json = run_in(
        &ns_a,
        "iperf3",
        ["-c", &target.to_string(), "-t", "8", "-J"],
    )?;
    let v: Value = serde_json::from_str(&json).context("iperf3 json")?;
    std::fs::write(out.join(format!("iperf-{tag}.json")), &json).ok();
    let bps = v["end"]["sum_received"]["bits_per_second"]
        .as_f64()
        .context("iperf3 result")?;
    let _ = lab;
    Ok((bps / 1000.0) as u64)
}

/// 场景 18：在 WireGuard 端口上探测（design/mesh.md 第 7.1 节）。IPv4、IPv6 的直连探测收发正常；主机上另有
/// 连接跟踪与 NAT 规则时照常；未认证的探测得不到任何响应；WireGuard 流量的吞吐与不开探测时没有可测出的差异。
pub fn wg_port(topology: &Path, nett: &Path, out: &Path) -> anyhow::Result<Report> {
    use crate::net::{INET_NETNS, OUTSIDER_NETNS, add_netns, attach, netns};
    let topo = Topology::load(topology)?;
    let underlay = Underlay::plan(&topo)?;
    underlay.down()?;
    let generated = material::generate(&topo, &underlay, out, false)?;
    let mut lab = start(&topo, &generated, underlay, nett)?;
    let mut report = Report::new("18-wg-port");
    let ns_b = netns("b");
    // 抓包：探测与应答（IPv4 在 UDP 头之后第 1 个字节；IPv6 在第 48 个字节），以及发给陌生人的任何 UDP
    let captures = [
        (
            "v4-probes",
            "udp dst port 41820 and udp[8] = 0x82 and not src host 198.51.100.99",
        ),
        ("v4-replies", "udp src port 41820 and udp[8] = 0x83"),
        (
            "v6-probes",
            "ip6 and udp dst port 41820 and ip6[48] = 0x82 and not src host 2001:db8:100::99",
        ),
        (
            "v6-replies",
            "ip6 and udp src port 41820 and ip6[48] = 0x83",
        ),
        (
            "to-outsider",
            "udp and (dst host 198.51.100.99 or dst host 2001:db8:100::99)",
        ),
    ];
    for (name, filter) in captures {
        let file = out.join(format!("cap-{name}.txt"));
        lab.tool(&ns_b, "tcpdump", &["-n", "-l", "-i", "eth0", filter], &file)?;
    }
    // 类似 Docker 的连接跟踪与 NAT 规则
    run(
        "ip",
        ["-n", &ns_b, "link", "add", "docker0", "type", "dummy"],
    )?;
    run(
        "ip",
        [
            "-n",
            &ns_b,
            "addr",
            "add",
            "172.17.0.1/16",
            "dev",
            "docker0",
        ],
    )?;
    run("ip", ["-n", &ns_b, "link", "set", "docker0", "up"])?;
    let rules = "table ip nat {\n\
        chain prerouting { type nat hook prerouting priority -100; tcp dport 8080 dnat to 172.17.0.2:80; }\n\
        chain postrouting { type nat hook postrouting priority 100; ip saddr 172.17.0.0/16 oifname != \"docker0\" masquerade; }\n\
        }\n\
        table ip filter {\n\
        chain forward { type filter hook forward priority 0; policy drop; ct state established,related accept; }\n\
        }\n";
    crate::cmd::run_with_input(
        "ip",
        ["netns", "exec", &ns_b, "nft", "-f", "-"],
        Some(rules.as_bytes()),
        crate::cmd::COMMAND_TIMEOUT,
    )?;

    for node in &generated.nodes {
        wait_for(node, "peers_applied", |ev| count(ev, "peers_applied") > 0)?;
    }
    let b = generated
        .nodes
        .iter()
        .find(|n| n.name == "b")
        .context("node b")?;
    let (_probe, _tcp) = start_workload(&mut lab, "a", "b", b.mesh_ipv4.into(), out)?;

    // 陌生人：向 b 的 WireGuard 端口发伪造的探测和随机握手
    add_netns(OUTSIDER_NETNS)?;
    attach(OUTSIDER_NETNS, INET_NETNS, "v-x", "br0")?;
    run(
        "ip",
        [
            "-n",
            OUTSIDER_NETNS,
            "addr",
            "add",
            "198.51.100.99/24",
            "dev",
            "eth0",
        ],
    )?;
    run(
        "ip",
        [
            "-n",
            OUTSIDER_NETNS,
            "-6",
            "addr",
            "add",
            "2001:db8:100::99/64",
            "dev",
            "eth0",
            "nodad",
        ],
    )?;
    let me = std::env::current_exe().context("locating nett-lab")?;
    let b_v4 = lab.underlay.public_ipv4("b").context("b v4")?;
    let b_v6 = lab
        .underlay
        .node("b")
        .and_then(|n| n.ipv6)
        .context("b v6")?;
    for target in [format!("{b_v4}:41820"), format!("[{b_v6}]:41820")] {
        let child = spawn_in(
            OUTSIDER_NETNS,
            &me,
            ["forge", "--to", &target],
            &out.join("forge.log"),
        )?;
        lab.helpers.push(child);
    }
    // 两轮以上的候选探测（更优类型每 3 秒，同类每 15 秒）
    std::thread::sleep(Duration::from_secs(35));

    let count_of = |name: &str| lines(&out.join(format!("cap-{name}.txt")));
    for name in ["v4-probes", "v4-replies", "v6-probes", "v6-replies"] {
        let n = count_of(name);
        report.check(&format!("wgport:{name}"), n > 0, format!("{n} packets"));
    }
    let leaked = count_of("to-outsider");
    report.check(
        "wgport:no-response-to-unauthenticated",
        leaked == 0,
        format!("{leaked} packets sent to the outsider"),
    );

    // 吞吐：组网进程在运行（原始套接字与过滤器在工作）与停掉之后（内核 WireGuard 照常工作）
    let server = spawn_in(
        &ns_b,
        Path::new("iperf3"),
        ["-s", "-B", &b.mesh_ipv4.to_string()],
        &out.join("iperf-server.log"),
    )?;
    lab.helpers.push(server);
    std::thread::sleep(Duration::from_millis(500));
    let mut with: Vec<u64> = Vec::new();
    for i in 0..3 {
        with.push(iperf(&mut lab, b.mesh_ipv4, out, &format!("with-{i}"))?);
    }
    for name in ["a", "b", "r1"] {
        lab.stop(name).ok();
    }
    let mut without: Vec<u64> = Vec::new();
    for i in 0..3 {
        without.push(iperf(&mut lab, b.mesh_ipv4, out, &format!("without-{i}"))?);
    }
    let median = |v: &mut Vec<u64>| {
        v.sort_unstable();
        v[v.len() / 2]
    };
    let (w, wo) = (median(&mut with), median(&mut without));
    report.check(
        "wgport:throughput-unaffected",
        w * 100 >= wo * 95,
        format!("median {w} kbit/s with probing, {wo} kbit/s without ({with:?} / {without:?})"),
    );
    write_report(out, &report)?;
    drop(lab);
    Ok(report)
}

/// 场景 16：当前中继变慢时，经隧道提议的延迟（毫秒，加在中继链路的两端）。
const PAIR_SLOW_MS: u32 = 40;
/// 场景 16：等待流量换到另一个中继的上限（同类更优路径要持续 30 秒）。
const PAIR_SWITCH_WAIT: Duration = Duration::from_secs(90);
/// 场景 17：故障之后观察的时长。
const PAIR_OUTAGE_WATCH: Duration = Duration::from_secs(60);
/// 场景 17 的通过标准：在三个时间片（45 秒）内恢复。
const PAIR_RECOVERY_LIMIT_MS: u64 = 45_000;
/// 场景 16 的通过标准：中断不超过 1 秒。
const PAIR_SWITCH_OUTAGE_LIMIT_MS: u64 = 1_000;

/// 双方都是 `dial-only` 的一次运行（design/prototype.md 第 6.2 节场景 16、17）。
#[derive(Debug, Clone, Serialize)]
pub struct PairRun {
    pub system: String,
    pub from: String,
    pub after: Option<String>,
    /// 场景 16：探测流最长的中断；场景 17：从故障到探测流恢复（观察期内没有恢复为空）。
    pub outage_ms: Option<u64>,
    /// 两端各自执行切换的时刻之差（毫秒）。
    pub sides_apart_ms: Option<u64>,
    pub tcp_ended: Option<String>,
}

/// 场景 16 或 17。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairFault {
    /// 当前中继变慢：经隧道提议与确认，两端一起切换。
    Slow,
    /// 当前中继失效、没有 Hub：靠时间片汇合。`skew_ms` 是 b 的时钟偏差。
    Outage { skew_ms: i64 },
}

/// 某个节点在 `after_ms` 之后第一次切换路径的时刻与原因。
fn first_switch(node: &LabNode, after_ms: u64) -> Option<(u64, String)> {
    events(node).iter().find_map(|e| {
        let at = e["at_ms"].as_u64()?;
        (e["event"] == "path_switched" && at >= after_ms)
            .then(|| (at, e["reason"].as_str().unwrap_or_default().to_owned()))
    })
}

/// 故障开始后，探测流在什么时刻恢复（最长的一段中断结束时）；到 `to_ms` 仍未恢复为空。
fn resumed_at(probe_file: &Path, from_ms: u64, to_ms: u64) -> anyhow::Result<Option<u64>> {
    let stats = crate::measure::probe_stats(probe_file, from_ms, to_ms)?;
    let Some((start, len)) = stats.gaps.iter().max_by_key(|g| g.1).copied() else {
        return Ok(Some(from_ms));
    };
    Ok((start + len + 200 < to_ms).then_some(start + len))
}

fn nett_pair_once(
    topo: &Topology,
    nett: &Path,
    out: &Path,
    fault: PairFault,
) -> anyhow::Result<PairRun> {
    use crate::measure::{now_ms, probe_stats, tcp_stats};
    let underlay = Underlay::plan(topo)?;
    underlay.down()?;
    let generated = material::generate(topo, &underlay, out, false)?;
    let extra = |name: &str| -> Vec<String> {
        let PairFault::Outage { skew_ms } = fault else {
            return Vec::new();
        };
        // 双方各自认为的时钟误差：b 偏差不超过 2 秒时双方都按时间片，否则都改用随机间隔
        let trusted = if skew_ms.unsigned_abs() <= 2_000 {
            "yes"
        } else {
            "no"
        };
        let mut args = vec!["--clock-trusted".to_owned(), trusted.to_owned()];
        if name == "b" {
            args.extend(["--clock-offset-ms".to_owned(), skew_ms.to_string()]);
        }
        args
    };
    let mut lab = start_with(topo, &generated, underlay, nett, extra)?;
    for node in &generated.nodes {
        wait_for(node, "peers_applied", |ev| count(ev, "peers_applied") > 0)?;
    }
    let node = |name: &str| generated.nodes.iter().find(|n| n.name == name);
    let (a, b) = (node("a").context("node a")?, node("b").context("node b")?);
    let relays: Vec<&LabNode> = ["r1", "r2"].iter().filter_map(|r| node(r)).collect();
    let links: Vec<(String, String)> = relays
        .iter()
        .filter_map(|r| {
            lab.underlay
                .node(&r.name)
                .map(|n| (n.netns.clone(), "eth0".to_owned()))
        })
        .collect();
    let monitor = PathMonitor::start(links);
    let (probe_file, tcp_file) = start_workload(&mut lab, "a", "b", b.mesh_ipv4.into(), out)?;
    let current = settle_on_relay(&monitor, &probe_file, "nett")
        .map_err(|e| e.context(diagnose(&lab, &generated.nodes)))?;
    let fault_ms = now_ms();
    let (watch, netem) = match fault {
        PairFault::Slow => (
            PAIR_SWITCH_WAIT,
            crate::fault::Netem {
                delay_ms: Some(PAIR_SLOW_MS),
                ..Default::default()
            },
        ),
        PairFault::Outage { .. } => (PAIR_OUTAGE_WATCH, crate::fault::Netem::loss(100.0)),
    };
    crate::fault::set_link(&lab.underlay, &relays[current].name, &netem)?;
    // 流量换到另一个中继、探测流持续 5 秒之后提前结束
    let deadline = Instant::now() + watch;
    let mut stable_since = None;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
        let now = now_ms();
        let flowing =
            probe_stats(&probe_file, now.saturating_sub(1000), now).is_ok_and(|p| p.received >= 8);
        let moved = busiest(&monitor).is_some_and(|i| i != current);
        if flowing && moved {
            let since = *stable_since.get_or_insert(now);
            if now.saturating_sub(since) >= 5_000 {
                break;
            }
        } else {
            stable_since = None;
        }
    }
    let end_ms = now_ms();
    let after = busiest(&monitor).map(|i| relays[i].name.clone());
    let outage_ms = match fault {
        PairFault::Slow => Some(probe_stats(&probe_file, fault_ms, end_ms)?.max_gap_ms),
        PairFault::Outage { .. } => {
            resumed_at(&probe_file, fault_ms, end_ms)?.map(|t| t.saturating_sub(fault_ms))
        }
    };
    let tcp = tcp_stats(&tcp_file, fault_ms - 2000, end_ms)?;
    let sides_apart_ms = match (first_switch(a, fault_ms), first_switch(b, fault_ms)) {
        (Some((x, _)), Some((y, _))) => Some(x.abs_diff(y)),
        _ => None,
    };
    drop(monitor);
    drop(lab);
    Ok(PairRun {
        system: "nett".to_owned(),
        from: relays[current].name.clone(),
        after,
        outage_ms,
        sides_apart_ms,
        tcp_ended: tcp.ended,
    })
}

/// Tailscale 一组（场景 17，结果只记录）：两端之间没有直连，流量经 DERP；同时停掉 Headscale 和当前 DERP。
fn tailscale_pair_once(topo: &Topology, out: &Path) -> anyhow::Result<PairRun> {
    use crate::measure::{now_ms, tcp_stats};
    use crate::tailscale::{TailscaleLab, derp_netns};
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
    let (a_egress, b_egress) = (
        lab.underlay.egress_ipv4("a").context("a egress")?,
        lab.underlay.egress_ipv4("b").context("b egress")?,
    );
    crate::fault::block_udp_with("a", &[b_egress.into()])?;
    crate::fault::block_udp_with("b", &[a_egress.into()])?;
    let mut ts = TailscaleLab::up_with(out, &["a", "b"], 2)?;
    let ip_b = ts.ipv4("b")?;
    ts.cli(
        "a",
        &["ping", "-c", "5", "--until-direct=false", &ip_b.to_string()],
    )
    .ok();
    let links: Vec<(String, String)> = (1..=2)
        .map(|i| (derp_netns(i), "eth0".to_owned()))
        .collect();
    let monitor = PathMonitor::start(links);
    let (probe_file, tcp_file) = start_workload(&mut lab, "a", "b", ip_b.into(), out)?;
    let current = settle_on_relay(&monitor, &probe_file, "tailscale")?;
    let fault_ms = now_ms();
    ts.stop_control();
    ts.stop_derp(current + 1);
    std::thread::sleep(PAIR_OUTAGE_WATCH);
    let end_ms = now_ms();
    let after = busiest(&monitor).map(|i| format!("derp{}", i + 1));
    let outage_ms = resumed_at(&probe_file, fault_ms, end_ms)?.map(|t| t.saturating_sub(fault_ms));
    let tcp = tcp_stats(&tcp_file, fault_ms - 2000, end_ms)?;
    drop(monitor);
    drop(ts);
    drop(lab);
    Ok(PairRun {
        system: "tailscale".to_owned(),
        from: format!("derp{}", current + 1),
        after,
        outage_ms,
        sides_apart_ms: None,
        tcp_ended: tcp.ended,
    })
}

/// 场景 16（当前路径可用，经隧道提议与确认后两端一起切换）与 17（当前路径断开、没有 Hub，靠时间片
/// 汇合），design/prototype.md 第 6.2 节。
pub fn dial_only_pair(
    topology: &Path,
    nett: &Path,
    out: &Path,
    repeat: usize,
    with_tailscale: bool,
    fault: PairFault,
) -> anyhow::Result<Report> {
    let topo = Topology::load(topology)?;
    let name = match fault {
        PairFault::Slow => "16-dial-only-switch",
        PairFault::Outage { .. } => "17-dial-only-outage",
    };
    let mut report = Report::new(name);
    let mut runs = Vec::new();
    for i in 0..repeat {
        runs.push(nett_pair_once(
            &topo,
            nett,
            &out.join(format!("nett-{i}")),
            fault,
        )?);
        if with_tailscale && matches!(fault, PairFault::Outage { .. }) {
            runs.push(tailscale_pair_once(
                &topo,
                &out.join(format!("tailscale-{i}")),
            )?);
        }
    }
    for r in &runs {
        report.record(&format!("run:{}", r.system), format!("{r:?}"));
    }
    let nett_runs: Vec<&PairRun> = runs.iter().filter(|r| r.system == "nett").collect();
    let moved = nett_runs
        .iter()
        .filter(|r| r.after.as_ref().is_some_and(|a| *a != r.from))
        .count();
    let mut outages: Vec<u64> = nett_runs.iter().filter_map(|r| r.outage_ms).collect();
    let summary = format!(
        "moved {moved}/{repeat}; outage p50 {:?} p95 {:?} max {:?} ms",
        percentile(&mut outages.clone(), 0.5),
        percentile(&mut outages.clone(), 0.95),
        outages.iter().max()
    );
    outages.sort_unstable();
    match fault {
        PairFault::Slow => {
            report.check("nett:moved-to-the-faster-relay", moved == repeat, &summary);
            let within = nett_runs
                .iter()
                .filter(|r| {
                    r.outage_ms
                        .is_some_and(|o| o <= PAIR_SWITCH_OUTAGE_LIMIT_MS)
                })
                .count();
            report.check(
                "nett:outage-within-1s",
                within == repeat,
                format!("{within} of {repeat} runs"),
            );
            let resets = nett_runs.iter().filter(|r| r.tcp_ended.is_some()).count();
            report.check(
                "nett:long-connection-never-reset",
                resets == 0,
                format!("{resets} of {repeat} runs reset the connection"),
            );
        }
        PairFault::Outage { skew_ms } => {
            let within = nett_runs
                .iter()
                .filter(|r| r.outage_ms.is_some_and(|o| o <= PAIR_RECOVERY_LIMIT_MS))
                .count();
            if skew_ms.unsigned_abs() <= 2_000 {
                // 20 次中至少 18 次
                let needed = (repeat * 9).div_ceil(10);
                report.check(
                    "nett:recovered-within-45s",
                    within >= needed,
                    format!("{within} of {repeat} runs (need {needed}); {summary}"),
                );
            } else {
                report.record(
                    "nett:random-retry",
                    format!(
                        "clock skew {skew_ms} ms: {within} of {repeat} runs within 45 s; {summary}"
                    ),
                );
            }
        }
    }
    let t: Vec<&PairRun> = runs.iter().filter(|r| r.system == "tailscale").collect();
    if !t.is_empty() {
        report.record(
            "tailscale:summary",
            format!(
                "recovered {} of {}: {:?}",
                t.iter().filter(|r| r.outage_ms.is_some()).count(),
                t.len(),
                t.iter().map(|r| r.outage_ms).collect::<Vec<_>>()
            ),
        );
    }
    write_report(out, &report)?;
    Ok(report)
}

/// 场景 10–13：等待打通直连的时长。
const PUNCH_WATCH: Duration = Duration::from_secs(40);
/// 流量离开中继的判定：中继链路持续空闲这么久。
const PUNCH_QUIET: Duration = Duration::from_secs(3);
/// 打洞期间不中断：探测流没有丢包，最长的空档小于两个正常间隔（丢一个包就是 200 毫秒；没有丢包时
/// 调度的抖动也能让空档到 140 毫秒上下）。
const PUNCH_MAX_GAP_MS: u64 = 190;

/// 打洞一次运行的结果（design/prototype.md 第 6.2 节场景 10–13）。
#[derive(Debug, Clone, Serialize)]
pub struct PunchRun {
    pub system: String,
    /// 从探测流稳定到流量离开中继（中继链路开始持续空闲）的毫秒数；没有离开为空。
    pub direct_after_ms: Option<u64>,
    /// 探测流稳定之后最长的中断。
    pub max_gap_ms: u64,
    /// nett：打洞事件。
    pub punch: Vec<String>,
    pub tcp_ended: Option<String>,
}

/// 按拓扑决定的通过标准。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PunchExpect {
    /// 两端锥形，或两端都有全局 IPv6：每次都打通，且不中断。
    Direct,
    /// 一端对称型：成功率不低于 Tailscale。
    AtLeastTailscale,
    /// 两端都是对称型：不尝试打洞，连接不受影响。
    Stay,
}

fn punch_expect(topo: &Topology) -> PunchExpect {
    use crate::topology::Nat;
    let nats: Vec<Nat> = topo.routers.iter().map(|r| r.nat).collect();
    let symmetric = nats.iter().filter(|n| **n == Nat::Symmetric).count();
    match symmetric {
        0 => PunchExpect::Direct,
        1 => PunchExpect::AtLeastTailscale,
        _ => PunchExpect::Stay,
    }
}

/// 开始传输后等探测流稳定，再等流量离开 `relay_links`（打通直连）。
fn punch_watch(
    lab: &mut Lab,
    out: &Path,
    system: &str,
    target: std::net::IpAddr,
    relay_links: Vec<(String, String)>,
) -> anyhow::Result<PunchRun> {
    use crate::measure::{now_ms, probe_stats, tcp_stats};
    let monitor = PathMonitor::start(relay_links);
    let (probe_file, tcp_file) = start_workload(lab, "a", "b", target, out)?;
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    let flowing = || {
        let now = now_ms();
        probe_stats(&probe_file, now.saturating_sub(1000), now).is_ok_and(|p| p.received >= 8)
    };
    while !flowing() {
        if Instant::now() >= deadline {
            anyhow::bail!("{system}: the probe stream did not start within {SETTLE_TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let start_ms = now_ms();
    let end = Instant::now() + PUNCH_WATCH;
    let mut direct_after_ms = None;
    while Instant::now() < end {
        std::thread::sleep(Duration::from_millis(500));
        if monitor.quiet_for(PUNCH_QUIET, RELAY_QUIET_BYTES_PER_S) {
            let quiet_since =
                now_ms().saturating_sub(u64::try_from(PUNCH_QUIET.as_millis()).unwrap_or(0));
            direct_after_ms = Some(quiet_since.saturating_sub(start_ms));
            break;
        }
    }
    let end_ms = now_ms();
    let probe = probe_stats(&probe_file, start_ms, end_ms)?;
    let tcp = tcp_stats(&tcp_file, start_ms, end_ms)?;
    drop(monitor);
    Ok(PunchRun {
        system: system.to_owned(),
        direct_after_ms,
        max_gap_ms: probe.max_gap_ms,
        punch: Vec::new(),
        tcp_ended: tcp.ended,
    })
}

fn nett_punch_once(topo: &Topology, nett: &Path, out: &Path) -> anyhow::Result<PunchRun> {
    let underlay = Underlay::plan(topo)?;
    underlay.down()?;
    let generated = material::generate(topo, &underlay, out, false)?;
    let mut lab = start(topo, &generated, underlay, nett)?;
    for node in &generated.nodes {
        wait_for(node, "peers_applied", |ev| count(ev, "peers_applied") > 0)?;
    }
    let node = |name: &str| generated.nodes.iter().find(|n| n.name == name);
    let (a, b) = (node("a").context("node a")?, node("b").context("node b")?);
    let links = ["r1", "r2"]
        .iter()
        .filter_map(|r| {
            lab.underlay
                .node(r)
                .map(|n| (n.netns.clone(), "eth0".to_owned()))
        })
        .collect();
    let mut run = punch_watch(&mut lab, out, "nett", b.mesh_ipv4.into(), links)
        .map_err(|e| e.context(diagnose(&lab, &generated.nodes)))?;
    run.punch = events(a)
        .iter()
        .filter(|e| e["event"].as_str().is_some_and(|k| k.starts_with("punch_")))
        .map(|e| {
            let mut e = e.clone();
            if let Some(obj) = e.as_object_mut() {
                obj.remove("at_ms");
                obj.remove("node_id");
            }
            e.to_string()
        })
        .collect();
    drop(lab);
    Ok(run)
}

fn tailscale_punch_once(topo: &Topology, out: &Path) -> anyhow::Result<PunchRun> {
    use crate::tailscale::{TailscaleLab, derp_netns};
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
    let ts = TailscaleLab::up_with(out, &["a", "b"], 2)?;
    let ip_b = ts.ipv4("b")?;
    let links = (1..=2)
        .map(|i| (derp_netns(i), "eth0".to_owned()))
        .collect();
    let run = punch_watch(&mut lab, out, "tailscale", ip_b.into(), links)?;
    drop(ts);
    drop(lab);
    Ok(run)
}

/// 场景 10–13：两端都在 NAT（或 IPv6 有状态防火墙）之后，开始经中继，看能否打通直连、打洞期间是否
/// 中断（design/prototype.md 第 6.2 节）。通过标准按拓扑决定。
pub fn punch(
    topology: &Path,
    nett: &Path,
    out: &Path,
    repeat: usize,
    with_tailscale: bool,
) -> anyhow::Result<Report> {
    let topo = Topology::load(topology)?;
    let expect = punch_expect(&topo);
    let stem = topology
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("punch");
    let mut report = Report::new(stem);
    let mut runs = Vec::new();
    for i in 0..repeat {
        runs.push(nett_punch_once(
            &topo,
            nett,
            &out.join(format!("nett-{i}")),
        )?);
        if with_tailscale {
            runs.push(tailscale_punch_once(
                &topo,
                &out.join(format!("tailscale-{i}")),
            )?);
        }
    }
    for r in &runs {
        report.record(&format!("run:{}", r.system), format!("{r:?}"));
    }
    let of =
        |system: &str| -> Vec<&PunchRun> { runs.iter().filter(|r| r.system == system).collect() };
    let (n, t) = (of("nett"), of("tailscale"));
    let direct = |v: &[&PunchRun]| v.iter().filter(|r| r.direct_after_ms.is_some()).count();
    let mut after: Vec<u64> = n.iter().filter_map(|r| r.direct_after_ms).collect();
    let summary = format!(
        "nett direct in {} of {repeat} runs, p50 {:?} p95 {:?} ms after the stream started; longest gap {:?} ms",
        direct(&n),
        percentile(&mut after.clone(), 0.5),
        percentile(&mut after, 0.95),
        n.iter().map(|r| r.max_gap_ms).max()
    );
    report.record("nett:summary", summary);
    let resets = n.iter().filter(|r| r.tcp_ended.is_some()).count();
    report.check(
        "nett:long-connection-never-reset",
        resets == 0,
        format!("{resets} of {repeat} runs reset the connection"),
    );
    let gaps_ok = n.iter().all(|r| r.max_gap_ms <= PUNCH_MAX_GAP_MS);
    match expect {
        PunchExpect::Direct => {
            report.check(
                "nett:punched-every-run",
                direct(&n) == repeat,
                format!("{} of {repeat}", direct(&n)),
            );
            report.check(
                "nett:no-interruption-while-punching",
                gaps_ok,
                format!("longest gap must stay within {PUNCH_MAX_GAP_MS} ms"),
            );
        }
        PunchExpect::AtLeastTailscale => {
            if with_tailscale {
                report.check(
                    "nett:success-rate-not-below-tailscale",
                    direct(&n) >= direct(&t),
                    format!(
                        "nett {} of {repeat}, tailscale {} of {repeat}",
                        direct(&n),
                        direct(&t)
                    ),
                );
            }
            report.check(
                "nett:no-interruption-while-punching",
                gaps_ok,
                format!("longest gap must stay within {PUNCH_MAX_GAP_MS} ms"),
            );
        }
        PunchExpect::Stay => {
            let tried = n
                .iter()
                .filter(|r| r.punch.iter().any(|e| e.contains("punch_succeeded")))
                .count();
            report.check(
                "nett:does-not-punch",
                tried == 0 && direct(&n) == 0,
                format!("{tried} runs punched, {} left the relay", direct(&n)),
            );
            report.check(
                "nett:connection-unaffected",
                gaps_ok,
                format!("longest gap must stay within {PUNCH_MAX_GAP_MS} ms"),
            );
        }
    }
    if with_tailscale {
        let mut ta: Vec<u64> = t.iter().filter_map(|r| r.direct_after_ms).collect();
        report.record(
            "tailscale:summary",
            format!(
                "direct in {} of {repeat} runs, p50 {:?} p95 {:?} ms; longest gap {:?} ms",
                direct(&t),
                percentile(&mut ta.clone(), 0.5),
                percentile(&mut ta, 0.95),
                t.iter().map(|r| r.max_gap_ms).max()
            ),
        );
    }
    write_report(out, &report)?;
    Ok(report)
}

/// 分片的计数（各命名空间 `/proc/net/snmp`、`/proc/net/snmp6` 之和）：生成的分片，以及为重组收到的分片。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Fragments {
    created: u64,
    reassembly: u64,
}

fn fragments(netns: &[String]) -> anyhow::Result<Fragments> {
    let mut total = Fragments::default();
    for ns in netns {
        // `Ip:` 一行字段名、一行数值
        let snmp = run_in(ns, "cat", ["/proc/net/snmp"])?;
        let ip: Vec<&str> = snmp.lines().filter(|l| l.starts_with("Ip:")).collect();
        if let [names, values] = ip.as_slice() {
            for (name, value) in names.split_whitespace().zip(values.split_whitespace()) {
                let value: u64 = value.parse().unwrap_or(0);
                match name {
                    "FragCreates" => total.created += value,
                    "ReasmReqds" => total.reassembly += value,
                    _ => {}
                }
            }
        }
        let snmp6 = run_in(ns, "cat", ["/proc/net/snmp6"])?;
        for line in snmp6.lines() {
            let mut parts = line.split_whitespace();
            let (Some(name), Some(value)) = (parts.next(), parts.next()) else {
                continue;
            };
            let value: u64 = value.parse().unwrap_or(0);
            match name {
                "Ip6FragCreates" => total.created += value,
                "Ip6ReasmReqds" => total.reassembly += value,
                _ => {}
            }
        }
    }
    Ok(total)
}

/// 大块传输最慢的速率（字节/秒）：低于它就算传不完，按它定出等待的上限。
const BULK_MIN_RATE: u64 = 4 * 1024 * 1024;

/// 经隧道从 `from` 向 `to` 传 `bytes` 个字节并校验内容（`port` 区分每一次传输）。
fn bulk_transfer(
    lab: &mut Lab,
    from: &LabNode,
    to: &LabNode,
    bytes: u64,
    port: u16,
    out: &Path,
) -> anyhow::Result<crate::measure::BulkResult> {
    let addr = std::net::SocketAddr::new(to.mesh_ipv4.into(), port).to_string();
    let result_file = out.join(format!("bulk-{port}.json"));
    let bytes_arg = bytes.to_string();
    lab.helper(
        &to.name,
        &[
            "bulk-recv",
            "--listen",
            &addr,
            "--bytes",
            &bytes_arg,
            "--out",
            &result_file.to_string_lossy(),
        ],
        &out.join(format!("bulk-{port}-recv.log")),
    )?;
    std::thread::sleep(Duration::from_millis(300));
    lab.helper(
        &from.name,
        &["bulk-send", "--to", &addr, "--bytes", &bytes_arg],
        &out.join(format!("bulk-{port}-send.log")),
    )?;
    let deadline = Instant::now() + Duration::from_secs(bytes / BULK_MIN_RATE + 60);
    loop {
        if let Ok(text) = std::fs::read(&result_file) {
            return serde_json::from_slice(&text).context("parsing the bulk transfer result");
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "bulk transfer {} -> {} did not finish within the deadline",
                from.name,
                to.name
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// 场景 19（design/prototype.md 第 6.3 节）：外层路径的 MTU 依次为 1500、1360、1300，经直连在两个方向
/// 上各传 `bytes` 个字节并校验内容，统计期间外层的分片。`nett0` 的 MTU 固定为 1280：外层包 IPv4 为
/// 1340 字节，IPv6 为 1360 字节。
pub fn mtu(topology: &Path, nett: &Path, out: &Path, bytes: u64) -> anyhow::Result<Report> {
    let topo = Topology::load(topology)?;
    let ipv6 = topo
        .links
        .iter()
        .any(|l| l.candidates.iter().any(|c| c == "direct6"));
    let underlay = Underlay::plan(&topo)?;
    underlay.down()?;
    let generated = material::generate(&topo, &underlay, out, false)?;
    let mut lab = start(&topo, &generated, underlay, nett)?;
    let mut report = Report::new(if ipv6 { "19-mtu-ipv6" } else { "19-mtu-ipv4" });
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
    let ns_a = lab.underlay.node("a").context("node a")?.netns.clone();
    report.record("tunnel", ping(&ns_a, &b.mesh_ipv4.to_string())?);
    let netns = lab.underlay.ip_netns();
    let mut port = 7100u16;
    for mtu in [1500u16, 1360, 1300] {
        lab.underlay.set_internet_mtu(mtu)?;
        for (from, to) in [(a, b), (b, a)] {
            let before = fragments(&netns)?;
            let result = bulk_transfer(&mut lab, from, to, bytes, port, out)
                .map_err(|e| e.context(diagnose(&lab, &generated.nodes)))?;
            port += 1;
            let after = fragments(&netns)?;
            let detail = format!(
                "{result:?}; {} Mbit/s; outer fragments created {}, received for reassembly {}",
                result.mbps(),
                after.created - before.created,
                after.reassembly - before.reassembly
            );
            let name = format!("mtu-{mtu}:{}-to-{}", from.name, to.name);
            let unfragmented = after == before;
            match (mtu, ipv6) {
                // 外层包装得下：完整，且没有分片
                (1500 | 1360, _) => report.check(&name, result.complete() && unfragmented, detail),
                // IPv4 的 1300：靠分片传输完整
                (_, false) => report.check(&name, result.complete(), detail),
                // IPv6 的 1300：记录（design/prototype.md 第 6.3 节）
                (_, true) => report.record(&name, detail),
            }
        }
    }
    lab.underlay.set_internet_mtu(1500)?;
    write_report(out, &report)?;
    Ok(report)
}

/// 场景 20 中 a 抓到的一个 WireGuard 握手消息。
#[derive(Debug, Clone, Copy, Serialize)]
struct Handshake {
    at_ms: u64,
    /// 1 握手发起、2 握手应答、3 cookie 应答（按长度区分：148、92、64 字节）。
    kind: u8,
    /// a 发出的（否则是 a 收到的）。
    outgoing: bool,
    /// 另一端的地址（中继）。
    remote: std::net::IpAddr,
}

/// 解析 `tcpdump -n -tt` 的输出：`1794049442.233309 IP 192.168.1.11.41820 > 198.51.100.4.41900: UDP, length 148`。
fn handshakes(capture: &Path, own: std::net::Ipv4Addr) -> Vec<Handshake> {
    let host = |s: &str| -> Option<std::net::IpAddr> {
        let s = s.trim_end_matches(':');
        s.rsplit_once('.')?.0.parse().ok()
    };
    std::fs::read_to_string(capture)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let [time, "IP", src, ">", dst, .., "length", len] = parts.as_slice() else {
                return None;
            };
            let at_ms = (time.parse::<f64>().ok()? * 1000.0) as u64;
            let kind = match *len {
                "148" => 1,
                "92" => 2,
                "64" => 3,
                _ => return None,
            };
            let (src, dst) = (host(src)?, host(dst)?);
            let outgoing = src == std::net::IpAddr::V4(own);
            Some(Handshake {
                at_ms,
                kind,
                outgoing,
                remote: if outgoing { dst } else { src },
            })
        })
        .collect()
}

/// 场景 20 的公共部分：relays.toml 的拓扑，a 经中继向 b 发探测流和长连接，在 a 上抓握手消息。
struct WgRun {
    lab: Lab,
    generated: Generated,
    probe_file: PathBuf,
    tcp_file: PathBuf,
    capture: PathBuf,
    a_ipv4: std::net::Ipv4Addr,
}

impl WgRun {
    /// `delay`：先在 a 上建好延迟队列（[`crate::fault::prepare_delay`]），之后只改过滤器。
    fn start(topology: &Path, nett: &Path, out: &Path, delay: bool) -> anyhow::Result<Self> {
        let topo = Topology::load(topology)?;
        let underlay = Underlay::plan(&topo)?;
        underlay.down()?;
        let generated = material::generate(&topo, &underlay, out, false)?;
        let mut lab = start(&topo, &generated, underlay, nett)?;
        for node in &generated.nodes {
            wait_for(node, "peers_applied", |ev| count(ev, "peers_applied") > 0)?;
        }
        let a_net = lab.underlay.node("a").context("node a")?.clone();
        let capture = out.join("cap-a-handshakes.txt");
        lab.tool(
            &a_net.netns,
            "tcpdump",
            &[
                "-n",
                "-tt",
                "-l",
                "-i",
                "eth0",
                "udp and (udp[8] = 1 or udp[8] = 2 or udp[8] = 3)",
            ],
            &capture,
        )?;
        let b = generated
            .nodes
            .iter()
            .find(|n| n.name == "b")
            .context("node b")?
            .clone();
        if delay {
            crate::fault::prepare_delay("a", &["delay".into(), "40ms".into()])?;
        }
        let (probe_file, tcp_file) = start_workload(&mut lab, "a", "b", b.mesh_ipv4.into(), out)?;
        let run = Self {
            lab,
            generated,
            probe_file,
            tcp_file,
            capture,
            a_ipv4: a_net.ipv4,
        };
        run.wait_flowing(SETTLE_TIMEOUT)
            .map_err(|e| e.context(diagnose(&run.lab, &run.generated.nodes)))?;
        Ok(run)
    }

    fn node(&self, name: &str) -> anyhow::Result<&LabNode> {
        self.generated
            .nodes
            .iter()
            .find(|n| n.name == name)
            .with_context(|| format!("node {name}"))
    }

    /// 等到探测流连续 3 秒正常。
    fn wait_flowing(&self, limit: Duration) -> anyhow::Result<()> {
        let deadline = Instant::now() + limit;
        loop {
            let now = crate::measure::now_ms();
            if crate::measure::probe_stats(&self.probe_file, now.saturating_sub(3000), now)
                .is_ok_and(|p| p.received >= 25)
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                anyhow::bail!("the probe stream did not flow within {limit:?}");
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// a 当前经哪个中继：最近一次路径切换的目标，还没有切换过时是第一个候选。
    fn current_relay(&self) -> anyhow::Result<String> {
        let a = self.node("a")?;
        let to = events(a)
            .iter()
            .rev()
            .find(|e| e["event"] == "path_switched")
            .and_then(|e| e["to"].as_str().map(str::to_owned));
        let Some(to) = to else {
            return Ok("r1".to_owned());
        };
        ["r1", "r2"]
            .into_iter()
            .find(|r| {
                self.lab
                    .underlay
                    .public_ipv4(r)
                    .is_some_and(|ip| to.contains(&format!("{ip}:")))
            })
            .map(str::to_owned)
            .with_context(|| format!("path `{to}` is not via r1 or r2"))
    }

    /// 让当前中继失效，等 a 切到另一个中继、探测流恢复，再恢复这个中继。返回失效的时刻。
    fn fail_current_relay(&self, limit: Duration) -> anyhow::Result<(u64, Option<u64>)> {
        let relay = self.current_relay()?;
        let at = crate::measure::now_ms();
        crate::fault::set_link(
            &self.lab.underlay,
            &relay,
            &crate::fault::Netem::loss(100.0),
        )?;
        let deadline = Instant::now() + limit;
        let resumed = loop {
            std::thread::sleep(Duration::from_millis(200));
            let now = crate::measure::now_ms();
            if let Some(t) = resumed_at(&self.probe_file, at, now)?
                && t > at
            {
                break Some(t);
            }
            if Instant::now() >= deadline {
                break None;
            }
        };
        crate::fault::clear_link(&self.lab.underlay, &relay)?;
        Ok((at, resumed))
    }

    /// a 在 `from_ms` 之后的路径切换：（时刻，原因，目标）。
    fn switches_since(&self, from_ms: u64) -> anyhow::Result<Vec<(u64, String, String)>> {
        Ok(events(self.node("a")?)
            .iter()
            .filter_map(|e| {
                let at = e["at_ms"].as_u64()?;
                (e["event"] == "path_switched" && at >= from_ms).then(|| {
                    (
                        at,
                        e["reason"].as_str().unwrap_or_default().to_owned(),
                        e["to"].as_str().unwrap_or_default().to_owned(),
                    )
                })
            })
            .collect())
    }
}

impl WgRun {
    /// 中继保存的会话索引数（它每秒写一次状态文件）。
    fn relay_sessions(&self, relay: &str) -> anyhow::Result<usize> {
        let path = self.node(relay)?.dir.join("relay-state.json");
        let text = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let state: nett_relay::relay::RelayState =
            serde_json::from_slice(&text).context("parsing the relay state")?;
        Ok(state.sessions.len())
    }

    /// 在中继上丢掉接下来一个来自 a 的握手发起（代替中继因索引冲突丢弃一次握手，design/mesh.md 第 5.1 节）。
    fn drop_next_initiation(&self, relay: &str) -> anyhow::Result<()> {
        let from = self
            .lab
            .underlay
            .egress_ipv4("a")
            .context("a egress address")?;
        let rules = format!(
            "table inet drop_once {{\n chain input {{\n  type filter hook input priority -10;\n  ip saddr {from} udp dport 41900 @th,64,8 1 quota until 200 bytes counter drop\n }}\n}}\n"
        );
        let ns = crate::net::netns(relay);
        run_in(&ns, "nft", ["delete", "table", "inet", "drop_once"]).ok();
        crate::cmd::run_with_input(
            "ip",
            ["netns", "exec", &ns, "nft", "-f", "-"],
            Some(rules.as_bytes()),
            crate::cmd::COMMAND_TIMEOUT,
        )?;
        Ok(())
    }

    /// a 在 `from_ms` 之后发出的握手发起与收到的应答。
    fn handshakes_since(&self, from_ms: u64) -> Vec<Handshake> {
        handshakes(&self.capture, self.a_ipv4)
            .into_iter()
            .filter(|h| h.at_ms >= from_ms)
            .collect()
    }
}

/// 场景 20(a)、(b)：删除再添加对端之后的握手时间，以及新中继丢掉第一个握手发起时的重试。每次让当前中继
/// 失效，a 切到另一个中继并重新握手。
pub fn wg_rehandshake(
    topology: &Path,
    nett: &Path,
    out: &Path,
    repeat: usize,
) -> anyhow::Result<Report> {
    let run_ = WgRun::start(topology, nett, out, false)?;
    let mut report = Report::new("20ab-wg-rehandshake");
    let mut timings = Vec::new();
    for i in 0..repeat + 1 {
        // 最后一次在目标中继上丢掉第一个握手发起
        let dropped = i == repeat;
        let relay = run_.current_relay()?;
        let target = if relay == "r1" { "r2" } else { "r1" };
        if dropped {
            run_.drop_next_initiation(target)?;
        }
        let (failed_at, resumed) = run_
            .fail_current_relay(Duration::from_secs(30))
            .map_err(|e| e.context(diagnose(&run_.lab, &run_.generated.nodes)))?;
        let switched = run_.switches_since(failed_at)?;
        let Some((switch_at, _, _)) = switched.first().cloned() else {
            anyhow::bail!("a did not switch away from {relay}");
        };
        // 内核在加回对端时立即发出握手发起，可能比组网进程记下切换事件早一毫秒
        let seen = run_.handshakes_since(switch_at.saturating_sub(100));
        let inits: Vec<u64> = seen
            .iter()
            .filter(|h| h.kind == 1 && h.outgoing)
            .map(|h| h.at_ms)
            .collect();
        let response = seen
            .iter()
            .find(|h| h.kind == 2 && !h.outgoing)
            .map(|h| h.at_ms);
        let first_init = inits.first().copied();
        let detail = format!(
            "switch -> first initiation {:?} ms; first initiation -> response {:?} ms; initiations {}; probe stream back {:?} ms after the switch; switches {:?}",
            first_init.map(|t| t.saturating_sub(switch_at)),
            response.zip(first_init).map(|(r, f)| r.saturating_sub(f)),
            inits.len(),
            resumed.map(|t| t.saturating_sub(switch_at)),
            switched
                .iter()
                .map(|(t, r, _)| (t - switch_at, r.as_str()))
                .collect::<Vec<_>>()
        );
        if dropped {
            let retry = inits.get(1).zip(first_init).map(|(b, a)| b - a);
            report.check(
                "b:dropped-initiation-is-retried",
                retry.is_some() && response.is_some() && resumed.is_some(),
                format!("retried after {retry:?} ms; {detail}"),
            );
        } else {
            report.record(&format!("a:run-{}", i + 1), detail);
            if let (Some(f), Some(r)) = (first_init, response) {
                timings.push((f.saturating_sub(switch_at), r.saturating_sub(f)));
            }
        }
        std::thread::sleep(Duration::from_secs(3));
    }
    report.check(
        "a:handshake-after-readding",
        timings.len() == repeat,
        format!("(switch -> initiation, initiation -> response) ms: {timings:?}"),
    );
    let tcp = crate::measure::tcp_stats(&run_.tcp_file, 0, crate::measure::now_ms())?;
    report.check(
        "long-connection-never-reset",
        tcp.ended.is_none(),
        format!("{tcp:?}"),
    );
    drop(run_);
    write_report(out, &report)?;
    Ok(report)
}

/// 场景 20(b)、(d)：经中继连续运行 `duration`，跨过多次密钥轮换（发起方每 2 分钟一次）。第一次轮换的握手
/// 发起在中继上被丢掉，WireGuard 约 5 秒后自己重试，期间旧会话照常使用。每分钟记录中继的会话索引数。
pub fn wg_rekey(
    topology: &Path,
    nett: &Path,
    out: &Path,
    duration: Duration,
) -> anyhow::Result<Report> {
    let run_ = WgRun::start(topology, nett, out, false)?;
    let mut report = Report::new("20bd-wg-rekey");
    let relay = run_.current_relay()?;
    let started = crate::measure::now_ms();
    run_.drop_next_initiation(&relay)?;
    let mut sessions = Vec::new();
    let end = Instant::now() + duration;
    while Instant::now() < end {
        std::thread::sleep(
            Duration::from_secs(60).min(end.saturating_duration_since(Instant::now())),
        );
        sessions.push(run_.relay_sessions(&relay)?);
    }
    let finished = crate::measure::now_ms();
    let inits: Vec<u64> = run_
        .handshakes_since(started)
        .iter()
        .filter(|h| h.kind == 1 && h.outgoing)
        .map(|h| h.at_ms - started)
        .collect();
    let switches = run_.switches_since(started)?;
    let probe = crate::measure::probe_stats(&run_.probe_file, started, finished)?;
    let tcp = crate::measure::tcp_stats(&run_.tcp_file, started, finished)?;
    let retry = inits.get(1).zip(inits.first()).map(|(b, a)| b - a);
    report.check(
        "b:dropped-rekey-is-retried",
        retry.is_some_and(|ms| (4_000..=7_000).contains(&ms)),
        format!("initiation times (ms since start): {inits:?}; retry after {retry:?} ms"),
    );
    let rekeys = inits.len();
    report.check(
        "d:rekeys-happen",
        u64::try_from(rekeys).unwrap_or(0) >= duration.as_secs() / 150,
        format!("{rekeys} initiations in {} s", duration.as_secs()),
    );
    report.check(
        "d:traffic-never-interrupted",
        switches.is_empty()
            && probe.max_gap_ms < 2 * crate::measure::PROBE_INTERVAL.as_millis() as u64
            && tcp.ended.is_none(),
        format!(
            "switches {switches:?}; longest probe gap {} ms; {tcp:?}",
            probe.max_gap_ms
        ),
    );
    let half = sessions.len() / 2;
    let early = sessions[..half].iter().max().copied().unwrap_or(0);
    let late = sessions[half..].iter().max().copied().unwrap_or(0);
    // 每次握手留下两个索引，空闲 180 秒后删除；每 2 分钟轮换一次时最多三次握手的索引同时在表中
    report.check(
        "d:relay-index-table-stable",
        late <= early.max(6),
        format!("sessions at {relay} each minute: {sessions:?}"),
    );
    drop(run_);
    write_report(out, &report)?;
    Ok(report)
}

/// 把"陌生人"命名空间接到"公网"上（198.51.100.99）。
fn add_outsider() -> anyhow::Result<()> {
    use crate::net::{INET_NETNS, OUTSIDER_NETNS, add_netns, attach};
    add_netns(OUTSIDER_NETNS)?;
    attach(OUTSIDER_NETNS, INET_NETNS, "v-x", "br0")?;
    run(
        "ip",
        [
            "-n",
            OUTSIDER_NETNS,
            "addr",
            "add",
            "198.51.100.99/24",
            "dev",
            "eth0",
        ],
    )?;
    Ok(())
}

/// 一个命名空间中 nft 计数器的包数（`nft list table` 输出中第一个 `packets N`）。
fn nft_packets(ns: &str, table: &str) -> anyhow::Result<u64> {
    let text = run_in(ns, "nft", ["list", "table", table])?;
    let n = text
        .split_whitespace()
        .skip_while(|w| *w != "packets")
        .nth(1)
        .and_then(|n| n.parse().ok())
        .unwrap_or(0);
    Ok(n)
}

/// 洪泛持续的时间：足够 a 换中继（计划内的切换要等同类更优路径持续 30 秒），并让 WireGuard 带着 cookie
/// 重试几轮。
const COOKIE_FLOOD: Duration = Duration::from_secs(90);

/// a 换中继的方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CookieCase {
    /// 当前中继失效。
    Failover,
    /// 当前中继变慢（加 40 毫秒延迟），旧中继仍然可用。
    Planned,
}

/// 场景 20(c) 的一次运行：b 被大量握手发起压到负载状态，a 换到另一个中继、重新握手。
fn cookie_once(
    topology: &Path,
    nett: &Path,
    out: &Path,
    case: CookieCase,
    report: &mut Report,
) -> anyhow::Result<(usize, bool)> {
    let label = match case {
        CookieCase::Failover => "failover",
        CookieCase::Planned => "planned",
    };
    let run_ = WgRun::start(topology, nett, out, case == CookieCase::Planned)?;
    let b = run_.node("b")?.clone();
    let b_wg = std::net::SocketAddr::new(
        run_.lab
            .underlay
            .public_ipv4("b")
            .context("b address")?
            .into(),
        material::LISTEN_PORT,
    );
    let ns_b = crate::net::netns("b");
    let counter = "table inet cookies {\n chain out {\n  type filter hook output priority 0;\n  udp sport 41820 @th,64,8 3 counter\n }\n}\n";
    crate::cmd::run_with_input(
        "ip",
        ["netns", "exec", &ns_b, "nft", "-f", "-"],
        Some(counter.as_bytes()),
        crate::cmd::COMMAND_TIMEOUT,
    )?;
    add_outsider()?;
    let key_hex: String = b
        .mesh_public_key
        .as_bytes()
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect();
    let flood_s = COOKIE_FLOOD.as_secs().to_string();
    let flood_until = crate::measure::now_ms() + COOKIE_FLOOD.as_millis() as u64;
    let me = std::env::current_exe().context("locating nett-lab")?;
    let mut run_ = run_;
    let flooder = crate::cmd::spawn_in(
        crate::net::OUTSIDER_NETNS,
        &me,
        [
            "flood",
            "--to",
            &b_wg.to_string(),
            "--key",
            &key_hex,
            "--duration",
            &flood_s,
        ],
        &out.join("flood.log"),
    )?;
    run_.lab.helpers.push(flooder);
    std::thread::sleep(Duration::from_secs(3));
    let cookies = nft_packets(&ns_b, "inet cookies")?;
    report.check(
        &format!("{label}:peer-under-load"),
        cookies > 0,
        format!("b answered {cookies} flooded initiations with cookies in 3 s"),
    );
    let relay = run_.current_relay()?;
    let changed_at = crate::measure::now_ms();
    match case {
        CookieCase::Failover => crate::fault::set_link(
            &run_.lab.underlay,
            &relay,
            &crate::fault::Netem::loss(100.0),
        )?,
        CookieCase::Planned => {
            let ip = run_
                .lab
                .underlay
                .public_ipv4(&relay)
                .context("relay address")?;
            crate::fault::route_delay("a", ip)?;
        }
    }
    // 看完整个洪泛期：换中继之后是否来回切换、隧道是否恢复
    std::thread::sleep(Duration::from_millis(
        flood_until.saturating_sub(crate::measure::now_ms()),
    ));
    match case {
        CookieCase::Failover => crate::fault::clear_link(&run_.lab.underlay, &relay)?,
        CookieCase::Planned => crate::fault::clear_eth0("a")?,
    }
    let switches = run_.switches_since(changed_at)?;
    let first_switch = switches.first().map(|s| s.0);
    let seen: Vec<Handshake> = handshakes(&run_.capture, run_.a_ipv4)
        .into_iter()
        .filter(|h| first_switch.is_some_and(|t| h.at_ms >= t))
        .collect();
    let cookies_to_a = seen.iter().filter(|h| h.kind == 3 && !h.outgoing).count();
    let initiations = seen.iter().filter(|h| h.kind == 1 && h.outgoing).count();
    let completed = seen
        .iter()
        .find(|h| h.kind == 2 && !h.outgoing)
        .map(|h| h.at_ms);
    report.record(
        &format!("{label}:switches"),
        format!(
            "{:?}",
            switches
                .iter()
                .map(|(t, r, to)| (t.saturating_sub(changed_at), r.as_str(), to.as_str()))
                .collect::<Vec<_>>()
        ),
    );
    report.record(
        &format!("{label}:handshakes"),
        format!(
            "after the first switch: {initiations} initiations sent, {cookies_to_a} cookie replies received, first response after {:?} ms",
            completed.zip(first_switch).map(|(c, s)| c - s)
        ),
    );
    // 用户态数据面按来源限额（design/userspace.md 第 4.1 节），被洪水的一方只要求洪水的来源带 cookie，
    // a 经中继的握手直接得到应答；内核成员的 cookie 在两个用例合计检查（wg_cookie）
    if b.userspace {
        report.check(
            &format!("{label}:handshake-answered-without-cookie"),
            cookies_to_a == 0 && completed.is_some_and(|c| c < flood_until),
            format!("{cookies_to_a} cookie replies, response at {completed:?}"),
        );
    }
    // 来回切换：回到了之前离开过的中继
    let mut visited: Vec<&str> = vec![];
    let mut returned = false;
    for (_, _, to) in &switches {
        if visited.last() != Some(&to.as_str()) {
            returned |= visited.contains(&to.as_str());
            visited.push(to);
        }
    }
    report.check(
        &format!("{label}:no-flapping"),
        !returned && first_switch.is_some(),
        format!("relays in order: {visited:?}"),
    );
    let probe = crate::measure::probe_stats(
        &run_.probe_file,
        first_switch.unwrap_or(changed_at),
        flood_until,
    )?;
    let tail = crate::measure::probe_stats(
        &run_.probe_file,
        flood_until.saturating_sub(5_000),
        flood_until,
    )?;
    report.check(
        &format!("{label}:tunnel-recovers-under-load"),
        completed.is_some_and(|c| c < flood_until) && tail.received >= 40,
        format!(
            "longest gap after the first switch {} ms; {} probes in the last 5 s of the flood",
            probe.max_gap_ms, tail.received
        ),
    );
    let tcp = crate::measure::tcp_stats(&run_.tcp_file, changed_at, crate::measure::now_ms())?;
    report.check(
        &format!("{label}:long-connection-never-reset"),
        tcp.ended.is_none(),
        format!("{tcp:?}"),
    );
    std::fs::write(
        out.join(format!("handshakes-{label}.json")),
        serde_json::to_vec_pretty(&seen)?,
    )?;
    Ok((cookies_to_a, b.userspace))
}

/// 场景 20(c)：b 被大量握手发起压到负载状态时，a 换中继、重新握手。经中继送回的 cookie 应答要能到达 a，
/// 握手要在负载持续期间完成。分两种：当前中继失效；当前中继变慢、旧中继仍然可用（计划内的切换）。
pub fn wg_cookie(topology: &Path, nett: &Path, out: &Path) -> anyhow::Result<Report> {
    let mut report = Report::new("20c-wg-cookie");
    let mut cookies = Vec::new();
    let mut userspace = false;
    for (case, dir) in [
        (CookieCase::Failover, "failover"),
        (CookieCase::Planned, "planned"),
    ] {
        let out = out.join(dir);
        std::fs::create_dir_all(&out)?;
        let (n, b_userspace) = cookie_once(topology, nett, &out, case, &mut report)?;
        cookies.push((dir, n));
        userspace = b_userspace;
    }
    // 内核 WireGuard 按握手队列的瞬时积压判断负载：a 的握手到达时队列恰好没满，b 就直接应答，不要 cookie
    // （握手更快完成）。cookie 经中继送达只需在两个用例中出现一次（design/prototype.md 场景 20(c)）；握手
    // 完成、隧道恢复、不来回切换在每个用例中都要满足
    if !userspace {
        report.check(
            "cookie-reaches-a-through-the-relay",
            cookies.iter().any(|(_, n)| *n > 0),
            format!("cookie replies at a after the first switch: {cookies:?}"),
        );
    }
    write_report(out, &report)?;
    Ok(report)
}

/// 测量用的辅助子命令：静置之前结束它们，组网和中继的进程照常运行。
const LOAD_HELPERS: [&str; 6] = [
    "probe-send",
    "probe-recv",
    "tcp-source",
    "tcp-sink",
    "bulk-send",
    "bulk-recv",
];

fn cmdline(pid: u32) -> Vec<String> {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .unwrap_or_default()
        .split(|b| *b == 0)
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

impl Lab {
    /// 结束探测流、长连接和大块传输的辅助进程。
    fn stop_load(&mut self) {
        for child in &mut self.helpers {
            let args = cmdline(child.id());
            if args.iter().any(|a| LOAD_HELPERS.contains(&a.as_str())) {
                child.kill().ok();
                child.wait().ok();
            }
        }
    }

    /// 要测内存的进程：（名称，pid）。
    fn measured(&self) -> Vec<(String, u32)> {
        let mut out: Vec<(String, u32)> = self
            .processes
            .iter()
            .map(|(n, c)| (format!("mesh@{n}"), c.id()))
            .chain(
                self.relays
                    .iter()
                    .map(|(n, c)| (format!("relay@{n}"), c.id())),
            )
            .collect();
        for child in &self.helpers {
            if cmdline(child.id()).iter().any(|a| a == "transport") {
                out.push(("transport".to_owned(), child.id()));
            }
        }
        out
    }
}

/// 进程的内存（KiB）：RSS 及其中的匿名页与文件页（可执行文件的代码页等，多个进程共享），PSS，线程数。
struct Memory {
    rss: u64,
    anon: u64,
    file: u64,
    pss: u64,
    threads: u64,
}

fn memory_kib(pid: u32) -> Option<Memory> {
    let field = |file: &str, key: &str| -> Option<u64> {
        std::fs::read_to_string(format!("/proc/{pid}/{file}"))
            .ok()?
            .lines()
            .find(|l| l.starts_with(key))?[key.len()..]
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    };
    Some(Memory {
        rss: field("status", "VmRSS:")?,
        anon: field("status", "RssAnon:")?,
        file: field("status", "RssFile:")?,
        pss: field("smaps_rollup", "Pss:")?,
        threads: field("status", "Threads:")?,
    })
}

fn mem_available_kib() -> Option<u64> {
    std::fs::read_to_string("/proc/meminfo")
        .ok()?
        .lines()
        .find(|l| l.starts_with("MemAvailable:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// 空闲预算（硬性规则 14）：组网进程、传输适配进程、nett-relay 各 5 MB。
const IDLE_BUDGET_KIB: u64 = 5 * 1024;
/// 每段负载传输的数据量。
const RESOURCE_BULK: u64 = 128 * 1024 * 1024;

/// 场景 21（design/prototype.md 第 6.3 节）：先有负载地运行——直连、切到 UDP 中继、再切到 TLS，经中继和
/// TLS 各传一块数据，再回到直连——然后停掉负载、静置 `idle`，测各进程的 RSS 与 PSS。用 release 构建。
pub fn resources(
    topology: &Path,
    nett: &Path,
    out: &Path,
    idle: Duration,
) -> anyhow::Result<Report> {
    use crate::fault;
    let topo = Topology::load(topology)?;
    let underlay = Underlay::plan(&topo)?;
    underlay.down()?;
    let available_before = mem_available_kib();
    let generated = material::generate(&topo, &underlay, out, false)?;
    let mut lab = start(&topo, &generated, underlay, nett)?;
    let mut report = Report::new("21-resources");
    for node in &generated.nodes {
        wait_for(node, "peers_applied", |ev| count(ev, "peers_applied") > 0)?;
    }
    let node = |name: &str| {
        generated
            .nodes
            .iter()
            .find(|n| n.name == name)
            .cloned()
            .with_context(|| format!("node {name}"))
    };
    let (a, b) = (node("a")?, node("b")?);
    let (_probe, _tcp) = start_workload(&mut lab, "a", "b", b.mesh_ipv4.into(), out)?;
    let a_egress = lab.underlay.egress_ipv4("a").context("a egress address")?;
    let mut port = 7200u16;
    let mut load = |lab: &mut Lab, what: &str| -> anyhow::Result<()> {
        // 让切换完成，再传一块数据
        std::thread::sleep(Duration::from_secs(8));
        let result = bulk_transfer(lab, &a, &b, RESOURCE_BULK, port, out)
            .map_err(|e| e.context(diagnose(lab, &generated.nodes)))?;
        port += 1;
        report.record(
            &format!("load:{what}"),
            format!("{result:?}; {} Mbit/s", result.mbps()),
        );
        Ok(())
    };
    load(&mut lab, "direct")?;
    fault::block_udp_with("b", &[a_egress.into()])?;
    load(&mut lab, "relay")?;
    fault::block_udp_upstream(&lab.underlay, "a")?;
    load(&mut lab, "tls")?;
    fault::unblock_udp_upstream(&lab.underlay, "a")?;
    fault::unblock_udp("b")?;
    load(&mut lab, "direct-again")?;
    lab.stop_load();
    std::thread::sleep(idle);
    let mut over = Vec::new();
    for (name, pid) in lab.measured() {
        let Some(m) = memory_kib(pid) else {
            report.check(
                &format!("{name}:measured"),
                false,
                format!("pid {pid} is gone"),
            );
            continue;
        };
        if m.rss > IDLE_BUDGET_KIB {
            over.push(name.clone());
        }
        report.record(
            &name,
            format!(
                "RSS {} KiB (anonymous {}, file {}), PSS {} KiB, {} threads after {} s idle",
                m.rss,
                m.anon,
                m.file,
                m.pss,
                m.threads,
                idle.as_secs()
            ),
        );
    }
    report.record(
        "machine",
        format!(
            "MemAvailable before {:?} KiB, after {:?} KiB",
            available_before,
            mem_available_kib()
        ),
    );
    // 超过预算的进入下一阶段之前要查明原因（design/prototype.md 第 6.3 节）
    report.check(
        "idle-rss-within-5-mb",
        over.is_empty(),
        format!("over budget: {over:?}"),
    );
    drop(lab);
    write_report(out, &report)?;
    Ok(report)
}

/// 拥塞场景中 b 的上行队列长度（包）：2 Mbit/s 时约 5 秒，相当于限速的 VPS 或上传缓冲很深的家庭宽带。
const CONGESTION_QUEUE_PACKETS: u32 = 1000;
/// 拥塞开始之前，等路径稳定的时间。
const CONGESTION_SETTLE: Duration = Duration::from_secs(10);
/// 解除限速之后继续观察的时间：队列排空、迟到的应答回来。
const CONGESTION_DRAIN: Duration = Duration::from_secs(8);

/// 拥塞一次运行的结果。
#[derive(Debug, Clone, Serialize)]
pub struct CongestionRun {
    pub system: String,
    /// 期间的路径变化：nett 为切换事件，Tailscale 为 `tailscale status` 中对端地址的变化（每秒采样）。
    pub changes: Vec<String>,
    pub tcp_kbps: u64,
    pub tcp_ended: Option<String>,
    /// 探测流（b 到 a）最长的中断。
    pub max_gap_ms: u64,
}

/// b 的上行限速到 `rate_kbit`、队列很深，b 向 a 的 `target` 持续发送长连接与探测流 `duration`。
/// `sample` 每秒调用一次，返回当前路径的描述（nett 用事件，不需要采样）。
fn congestion_run(
    lab: &mut Lab,
    out: &Path,
    system: &str,
    target: std::net::IpAddr,
    (rate_kbit, duration): (u32, Duration),
    mut sample: impl FnMut() -> Option<String>,
) -> anyhow::Result<(CongestionRun, u64, u64)> {
    use crate::measure::{now_ms, probe_stats, tcp_stats};
    let ns_b = lab.underlay.node("b").context("node b")?.netns.clone();
    let (probe_file, tcp_file) = start_workload(lab, "b", "a", target, out)?;
    std::thread::sleep(WARMUP);
    let rate = format!("{rate_kbit}kbit");
    let limit = CONGESTION_QUEUE_PACKETS.to_string();
    run(
        "tc",
        [
            "-n", &ns_b, "qdisc", "replace", "dev", "eth0", "root", "netem", "rate", &rate,
            "limit", &limit,
        ],
    )?;
    let start_ms = now_ms();
    let mut changes = Vec::new();
    let mut last = sample();
    let mut watch = |until: Instant, changes: &mut Vec<String>| {
        while Instant::now() < until {
            std::thread::sleep(Duration::from_secs(1));
            let now = sample();
            if now.is_some() && now != last {
                changes.push(format!(
                    "@{:.1}s {}",
                    now_ms().saturating_sub(start_ms) as f64 / 1000.0,
                    now.as_deref().unwrap_or("?")
                ));
                last = now;
            }
        }
    };
    watch(Instant::now() + duration, &mut changes);
    let end_ms = now_ms();
    run("tc", ["-n", &ns_b, "qdisc", "del", "dev", "eth0", "root"]).ok();
    watch(Instant::now() + CONGESTION_DRAIN, &mut changes);
    lab.stop_load();
    let tcp = tcp_stats(&tcp_file, start_ms, end_ms)?;
    let probe = probe_stats(&probe_file, start_ms, end_ms)?;
    Ok((
        CongestionRun {
            system: system.to_owned(),
            changes,
            tcp_kbps: tcp.kbps,
            tcp_ended: tcp.ended,
            max_gap_ms: probe.max_gap_ms,
        },
        start_ms,
        end_ms,
    ))
}

/// Tailscale 当前到 `peer` 的路径：直连的地址，或经 DERP。
fn tailscale_path(ts: &crate::tailscale::TailscaleLab, peer: std::net::Ipv4Addr) -> Option<String> {
    let status: Value = serde_json::from_str(&ts.cli("a", &["status", "--json"]).ok()?).ok()?;
    let ip = peer.to_string();
    status["Peer"].as_object()?.values().find_map(|p| {
        p["TailscaleIPs"]
            .as_array()?
            .iter()
            .any(|a| a.as_str() == Some(ip.as_str()))
            .then(|| match p["CurAddr"].as_str() {
                Some(addr) if !addr.is_empty() => format!("direct {addr}"),
                _ => "derp".to_owned(),
            })
    })
}

/// 场景 24 的 nett 一次运行：期间的路径变化取各节点的切换事件。
fn nett_congestion_once(
    topo: &Topology,
    nett: &Path,
    out: &Path,
    shape: (u32, Duration),
) -> anyhow::Result<CongestionRun> {
    let underlay = Underlay::plan(topo)?;
    underlay.down()?;
    let generated = material::generate(topo, &underlay, out, false)?;
    let mut lab = start(topo, &generated, underlay, nett)?;
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
    let ns_a = lab.underlay.node("a").context("node a")?.netns.clone();
    ping(&ns_a, &b.mesh_ipv4.to_string())?;
    std::thread::sleep(CONGESTION_SETTLE);
    let (mut run, start_ms, end_ms) =
        congestion_run(&mut lab, out, "nett", a.mesh_ipv4.into(), shape, || None)
            .map_err(|e| e.context(diagnose(&lab, &generated.nodes)))?;
    let until_ms = end_ms + u64::try_from(CONGESTION_DRAIN.as_millis()).unwrap_or(u64::MAX);
    run.changes = generated
        .nodes
        .iter()
        .flat_map(|node| {
            events(node).into_iter().filter_map(move |e| {
                let at = e["at_ms"].as_u64()?;
                (e["event"] == "path_switched" && (start_ms..=until_ms).contains(&at)).then(|| {
                    format!(
                        "{}@{:.1}s {} {}",
                        node.name,
                        at.saturating_sub(start_ms) as f64 / 1000.0,
                        e["reason"].as_str().unwrap_or("?"),
                        e["to"].as_str().unwrap_or("?")
                    )
                })
            })
        })
        .collect();
    Ok(run)
}

/// 场景 24 的 Tailscale 一次运行。没有直连候选的拓扑拦掉两端之间的直连 UDP，经 DERP。
fn tailscale_congestion_once(
    topo: &Topology,
    out: &Path,
    direct: bool,
    shape: (u32, Duration),
) -> anyhow::Result<CongestionRun> {
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
    if !direct {
        let (a_egress, b_egress) = (
            lab.underlay.egress_ipv4("a").context("a egress")?,
            lab.underlay.egress_ipv4("b").context("b egress")?,
        );
        crate::fault::block_udp_with("a", &[b_egress.into()])?;
        crate::fault::block_udp_with("b", &[a_egress.into()])?;
    }
    let ts = TailscaleLab::up_with(out, &["a", "b"], 1)?;
    let (ip_a, ip_b) = (ts.ipv4("a")?, ts.ipv4("b")?);
    ts.cli(
        "a",
        &["ping", "-c", "5", "--until-direct=false", &ip_b.to_string()],
    )
    .ok();
    std::thread::sleep(CONGESTION_SETTLE);
    let (run, _, _) = congestion_run(&mut lab, out, "tailscale", ip_a.into(), shape, || {
        tailscale_path(&ts, ip_b)
    })?;
    Ok(run)
}

/// 场景 24（design/prototype.md 第 6.2 节）：拥塞。路径没有断，只是排队：nett 不切换、不重新握手，
/// 长连接不断；吞吐与最长中断不比 Tailscale 差。
pub fn congestion(
    topology: &Path,
    nett: &Path,
    out: &Path,
    (repeat, with_tailscale): (usize, bool),
    rate_kbit: u32,
    duration: Duration,
) -> anyhow::Result<Report> {
    let topo = Topology::load(topology)?;
    let direct = topo
        .links
        .iter()
        .any(|l| l.candidates.iter().any(|c| c.starts_with("direct")));
    let mut report = Report::new(if direct {
        "24-congestion-direct"
    } else {
        "24-congestion-relay"
    });
    let shape = (rate_kbit, duration);
    let (mut n, mut t) = (Vec::new(), Vec::new());
    for i in 0..repeat {
        n.push(nett_congestion_once(
            &topo,
            nett,
            &out.join(format!("nett-{i}")),
            shape,
        )?);
        if with_tailscale {
            let dir = out.join(format!("tailscale-{i}"));
            t.push(tailscale_congestion_once(&topo, &dir, direct, shape)?);
        }
    }
    for r in n.iter().chain(&t) {
        report.record(&format!("run:{}", r.system), format!("{r:?}"));
    }
    report.check(
        "nett:steady-path",
        n.iter().all(|r| r.changes.is_empty()),
        format!(
            "switches per run {:?}",
            n.iter().map(|r| r.changes.len()).collect::<Vec<_>>()
        ),
    );
    report.check(
        "nett:long-connection-never-reset",
        n.iter().all(|r| r.tcp_ended.is_none()),
        format!(
            "kbit/s on a {rate_kbit} kbit/s uplink {:?}",
            n.iter().map(|r| r.tcp_kbps).collect::<Vec<_>>()
        ),
    );
    if with_tailscale {
        let min = |v: &[CongestionRun]| v.iter().map(|r| r.tcp_kbps).min().unwrap_or(0);
        let max_gap = |v: &[CongestionRun]| v.iter().map(|r| r.max_gap_ms).max().unwrap_or(0);
        report.check(
            "throughput:at-least-95-percent",
            min(&n) * 100 >= min(&t) * 95,
            format!("nett min {} kbit/s, tailscale min {}", min(&n), min(&t)),
        );
        report.check(
            "outage:not-worse-than-tailscale",
            not_worse(Some(max_gap(&n)), Some(max_gap(&t))),
            format!(
                "nett max {} ms, tailscale max {} ms",
                max_gap(&n),
                max_gap(&t)
            ),
        );
    }
    write_report(out, &report)?;
    Ok(report)
}

/// 访问控制、Edge 专用地址与容器内成员（design/local-signing.md 第 6、8 节，ADR 0015、0016）。拓扑中 `edge`
/// 运行 Edge（背后有一个"容器"，节点像 Docker 一样对它做源地址伪装），`app` 是容器内成员（背后有一个服务，
/// 宣告服务的地址），只放行 `edge` 的 Edge 访问服务的 8686；`other` 是普通成员。
pub fn access(topology: &Path, nett: &Path, out: &Path) -> anyhow::Result<Report> {
    let topo = Topology::load(topology)?;
    let underlay = Underlay::plan(&topo)?;
    underlay.down()?;
    let generated = material::generate(&topo, &underlay, out, false)?;
    let mut lab = start(&topo, &generated, underlay, nett)?;
    let mut report = Report::new("access");
    let node = |name: &str| {
        generated
            .nodes
            .iter()
            .find(|n| n.name == name)
            .with_context(|| format!("node `{name}` in the access topology"))
    };
    let (edge, app, other) = (node("edge")?, node("app")?, node("other")?);
    let ns = |name: &str| -> anyhow::Result<String> {
        Ok(lab
            .underlay
            .node(name)
            .context("planned node")?
            .netns
            .clone())
    };
    let (ns_edge, ns_app, ns_other) = (ns("edge")?, ns("app")?, ns("other")?);
    let container = crate::net::edge_netns("edge");
    let edge_ip = edge.edge_ipv4.context("edge address of node `edge`")?;
    for n in &generated.nodes {
        wait_for(n, "peers_applied", |ev| count(ev, "peers_applied") > 0)?;
    }
    // 容器内成员在 NAT 之后、只接受它自己发起的连接：从它出发等隧道通（规则放行 app 访问另外两个）
    for target in [edge.mesh_ipv4, other.mesh_ipv4] {
        let r = ping(&ns_app, &target.to_string());
        report.check(
            &format!("app-reaches:{target}"),
            r.is_ok(),
            r.err().map(|e| format!("{e:#}")).unwrap_or_default(),
        );
    }

    // app 背后的服务：宣告的地址上监听 8686、2222；同一网络中另一个没有宣告的地址上也监听 8686
    let svc_ns = crate::net::service_netns("app");
    let (svc, ingress) = topo
        .node("app")
        .and_then(|n| n.service.as_ref())
        .map(|s| (s.address, s.ingress))
        .context("node `app` needs a service")?;
    let hidden = std::net::Ipv4Addr::from(u32::from(svc) + 1);
    run_in(
        &svc_ns,
        "ip",
        ["addr", "add", &format!("{hidden}/24"), "dev", "eth0"],
    )?;
    let listeners = [(svc, 8686u16), (svc, 2222), (hidden, 8686)];
    let logs: Vec<PathBuf> = listeners
        .iter()
        .map(|(ip, port)| out.join(format!("accept-{ip}-{port}.txt")))
        .collect();
    for ((ip, port), log) in listeners.iter().zip(&logs) {
        lab.helper_in(
            &svc_ns,
            &[
                "accept-log",
                "--listen",
                &format!("{ip}:{port}"),
                "--out",
                &log.to_string_lossy(),
            ],
            &out.join(format!("accept-{ip}-{port}.log")),
        )?;
    }
    std::thread::sleep(Duration::from_millis(500));
    let me = std::env::current_exe().context("locating nett-lab")?;
    let connect = |netns: &str, ip: std::net::Ipv4Addr, port: u16| -> String {
        let to = format!("{ip}:{port}");
        run_in(
            netns,
            &me.to_string_lossy(),
            ["connect", "--to", to.as_str(), "--duration", "3"],
        )
        .map_or_else(|e| format!("error {e:#}"), |o| o.trim().to_owned())
    };
    let routes_on_edge = run_in(&ns_edge, "ip", ["route", "show", "dev", "nett0"])?;
    report.check(
        "route-to-the-advertised-service",
        routes_on_edge.contains(&svc.to_string()),
        routes_on_edge.trim().replace('\n', "; "),
    );

    // Edge 访问服务放行的端口：连上；服务看到的来源是 app 在服务网络中的地址（Edge 的源地址转换在 Docker 的
    // 伪装之前生效，app 转发时换成自己的地址）
    let result = connect(&container, svc, 8686);
    std::thread::sleep(Duration::from_millis(300));
    let seen = std::fs::read_to_string(&logs[0]).unwrap_or_default();
    report.check(
        "edge-to-allowed-service-port",
        result == "connected" && seen.lines().all(|l| l == ingress.to_string()) && !seen.is_empty(),
        format!(
            "{result}; service saw {:?}",
            seen.lines().collect::<Vec<_>>()
        ),
    );
    for (name, netns, port) in [
        ("edge-to-other-port-denied", container.as_str(), 2222),
        ("edge-node-itself-denied", ns_edge.as_str(), 8686),
        ("other-member-denied", ns_other.as_str(), 8686),
    ] {
        let result = connect(netns, svc, port);
        report.check(name, result.starts_with("blocked"), result);
    }
    let unexpected = std::fs::read_to_string(&logs[1]).unwrap_or_default();
    report.check(
        "nothing-reached-the-closed-port",
        unexpected.is_empty(),
        format!("{:?}", unexpected.lines().collect::<Vec<_>>()),
    );

    // 模拟 other 被攻破：它在自己这一端给 app 的对端加上没有宣告的地址和路由，把包发过去。app 必须丢弃
    let peers = run_in(&ns_other, "wg", ["show", "nett0", "allowed-ips"])?;
    // 按组网地址找到 app 的对端，公钥用 wg 自己的写法
    let app_mesh = format!("{}/32", app.mesh_ipv4);
    let app_line = peers
        .lines()
        .find(|l| l.split_whitespace().any(|f| f == app_mesh))
        .context("app's peer on other")?;
    let mut fields = app_line.split_whitespace();
    let app_key = fields.next().context("peer key")?.to_owned();
    let mut allowed: Vec<String> = fields.map(str::to_owned).collect();
    allowed.push(format!("{hidden}/32"));
    run_in(
        &ns_other,
        "wg",
        [
            "set",
            "nett0",
            "peer",
            &app_key,
            "allowed-ips",
            &allowed.join(","),
        ],
    )?;
    run_in(
        &ns_other,
        "ip",
        ["route", "replace", &format!("{hidden}/32"), "dev", "nett0"],
    )?;
    let result = connect(&ns_other, hidden, 8686);
    let reached = std::fs::read_to_string(&logs[2]).unwrap_or_default();
    report.check(
        "forged-route-to-unadvertised-address-dropped",
        result.starts_with("blocked") && reached.is_empty(),
        format!(
            "{result}; the unadvertised address saw {:?}",
            reached.lines().collect::<Vec<_>>()
        ),
    );

    // 成员之间默认拒绝（ADR 0023）：同一条隧道上，规则放行 edge 访问 other，反方向没有规则
    let r = ping(&ns_edge, &other.mesh_ipv4.to_string());
    report.check(
        "member-allowed-by-rule",
        r.is_ok(),
        r.err().map(|e| format!("{e:#}")).unwrap_or_default(),
    );
    let r = ping(&ns_other, &edge.mesh_ipv4.to_string());
    report.check(
        "member-denied-without-rule",
        r.is_err(),
        if r.is_ok() {
            "other reached edge".into()
        } else {
            String::new()
        },
    );

    // 防冒用：edge 节点上以 Edge 专用地址为源发出的包不离开本机。在 other 上计数从组网接口进来的包：
    // 以 Edge 专用地址为源的应为 0，以 edge 的组网地址为源的（对照）大于 0
    let rules = format!(
        "table inet lab_count {{\n chain c {{\n  type filter hook prerouting priority -300;\n  \
         iifname \"nett0\" ip saddr {edge_ip} counter\n  \
         iifname \"nett0\" ip saddr {} counter\n }}\n}}\n",
        edge.mesh_ipv4
    );
    crate::cmd::run_with_input(
        "ip",
        ["netns", "exec", &ns_other, "nft", "-f", "-"],
        Some(rules.as_bytes()),
        crate::cmd::COMMAND_TIMEOUT,
    )?;
    let host = format!("{edge_ip}/32");
    run_in(&ns_edge, "ip", ["addr", "add", &host, "dev", "lo"])?;
    let target = other.mesh_ipv4.to_string();
    let edge_src = edge_ip.to_string();
    run_in(
        &ns_edge,
        "ping",
        ["-c", "3", "-i", "0.2", "-W", "1", "-I", &edge_src, &target],
    )
    .ok();
    run_in(
        &ns_edge,
        "ping",
        ["-c", "3", "-i", "0.2", "-W", "1", &target],
    )
    .ok();
    run_in(&ns_edge, "ip", ["addr", "del", &host, "dev", "lo"])?;
    let listing = run_in(&ns_other, "nft", ["list", "table", "inet", "lab_count"])?;
    let counts: Vec<u64> = listing
        .lines()
        .filter_map(|l| l.split("packets ").nth(1))
        .filter_map(|r| r.split_whitespace().next()?.parse().ok())
        .collect();
    report.check(
        "edge-address-not-spoofable",
        counts.len() == 2 && counts[0] == 0 && counts[1] > 0,
        format!("packets from the edge address, from the edge node's mesh address: {counts:?}"),
    );

    for n in &generated.nodes {
        let ev = events(n);
        report.check(
            &format!("rules-applied:{}", n.name),
            count(&ev, "access_rules_applied") >= 1
                && count(&ev, "routes_applied") >= 1
                && count(&ev, "access_rules_rejected") == 0
                && count(&ev, "routes_rejected") == 0
                && count(&ev, "data_plane_failed") == 0,
            format!(
                "rules applied {}, routes applied {}, rejected {} / {}, data plane failures {}",
                count(&ev, "access_rules_applied"),
                count(&ev, "routes_applied"),
                count(&ev, "access_rules_rejected"),
                count(&ev, "routes_rejected"),
                count(&ev, "data_plane_failed")
            ),
        );
    }
    Ok(report)
}
