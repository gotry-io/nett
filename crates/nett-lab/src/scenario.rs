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
}

impl Drop for Lab {
    fn drop(&mut self) {
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

fn ping(netns: &str, target: &str) -> anyhow::Result<String> {
    run_in(netns, "ping", ["-c", "3", "-i", "0.2", "-W", "2", target])
}

fn start(
    topo: &Topology,
    generated: &Generated,
    underlay: Underlay,
    nett: &Path,
) -> anyhow::Result<Lab> {
    underlay.up(topo)?;
    let mut lab = Lab {
        underlay,
        processes: Vec::new(),
    };
    for node in &generated.nodes {
        lab.spawn(node, nett)?;
    }
    Ok(lab)
}

impl Lab {
    fn spawn(&mut self, node: &LabNode, nett: &Path) -> anyhow::Result<()> {
        let net = self.underlay.node(&node.name).context("planned node")?;
        let dir = &node.dir;
        let child = spawn_in(
            &net.netns,
            nett,
            [
                "mesh".as_ref(),
                "--config".as_ref(),
                dir.join("desired.json").as_os_str(),
                "--key".as_ref(),
                dir.join("mesh.key").as_os_str(),
                "--events".as_ref(),
                dir.join("events.jsonl").as_os_str(),
            ],
            &dir.join("mesh.log"),
        )?;
        self.processes.push((node.name.clone(), child));
        Ok(())
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

    // 重新加载一份只带低版本材料的期望状态：被拒绝，已生效的对端保持不变
    if let Some(lower) = &generated.lower_version_of_second {
        let mut doc = generated.first_desired.clone();
        doc.members = vec![generated.materials[&a.name].clone(), lower.clone()];
        doc.revocations.clear();
        let text = serde_json::to_vec_pretty(&doc).context("serializing desired state")?;
        std::fs::write(a.dir.join("desired.json"), text).context("rewriting desired state")?;
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
