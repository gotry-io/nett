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
    underlay.up(topo)?;
    let mut lab = Lab {
        underlay,
        processes: Vec::new(),
        relays: Vec::new(),
        helpers: Vec::new(),
    };
    for node in &generated.nodes {
        lab.spawn(node, nett)?;
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

    /// 在节点的命名空间中启动一个测量辅助进程（`nett-lab` 自己的子命令）。
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
            ],
            &node.dir.join("relay.log"),
        )?;
        self.relays.push((node.name.clone(), child));
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

/// 按底层链路的流量判断当前路径（design/prototype.md 第 6.1 节）：每 200 毫秒读一次各接口的接收字节数。
/// 一次采样：时刻（Unix 毫秒）与各接口的累计接收字节数。
type Sample = (u64, Vec<u64>);

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
                std::thread::sleep(Duration::from_millis(200));
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

    /// `after_ms` 之后，被观察的接口合计接收速率第一次低于 `bytes_per_s` 的时刻。
    fn first_quiet(&self, after_ms: u64, bytes_per_s: u64) -> Option<u64> {
        let v = self.samples.lock().ok()?;
        v.windows(2)
            .filter(|w| w[0].0 >= after_ms)
            .find(|w| {
                let dt = w[1].0.saturating_sub(w[0].0).max(1);
                let bytes: u64 = w[1]
                    .1
                    .iter()
                    .zip(&w[0].1)
                    .map(|(b, a)| b.saturating_sub(*a))
                    .sum();
                bytes * 1000 / dt < bytes_per_s
            })
            .map(|w| w[1].0)
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
    /// 从故障解除到流量回到直连（毫秒），按底层链路判断。
    pub recovery_ms: Option<u64>,
    /// 长连接是否被重置。
    pub tcp_ended: Option<String>,
    pub tcp_kbps: u64,
}

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

/// 场景 1 与 8：切断 a 与 b 之间的直连 UDP，12 秒后恢复。`relay_links` 是中继路径经过的接口。
fn failover_run(
    lab: &mut Lab,
    out: &Path,
    system: &str,
    target: std::net::IpAddr,
    relay_links: Vec<(String, String)>,
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
    fault::block_udp_with("b", &[a_egress.into()])?;
    std::thread::sleep(FAULT_HOLD);
    let restore_ms = now_ms();
    fault::unblock_udp("b")?;
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
        tcp_ended: tcp.ended,
        tcp_kbps: tcp.kbps,
    })
}

fn nett_failover_once(topo: &Topology, nett: &Path, out: &Path) -> anyhow::Result<FailoverRun> {
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
    let run = failover_run(&mut lab, out, "nett", b.mesh_ipv4.into(), links)?;
    drop(lab);
    Ok(run)
}

fn tailscale_failover_once(topo: &Topology, out: &Path) -> anyhow::Result<FailoverRun> {
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
    let run = failover_run(&mut lab, out, "tailscale", ip_b.into(), links)?;
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
) -> anyhow::Result<Report> {
    let topo = Topology::load(topology)?;
    let mut report = Report::new("1-8-failover");
    let mut runs = Vec::new();
    for i in 0..repeat {
        runs.push(nett_failover_once(
            &topo,
            nett,
            &out.join(format!("nett-{i}")),
        )?);
        if with_tailscale {
            runs.push(tailscale_failover_once(
                &topo,
                &out.join(format!("tailscale-{i}")),
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
        let not_worse =
            |n: Option<u64>, t: Option<u64>| matches!((n, t), (Some(n), Some(t)) if n <= t);
        report.check(
            "outage:not-worse-than-tailscale",
            not_worse(nett_s.0, ts_s.0) && not_worse(nett_s.1, ts_s.1),
            "p95 and max",
        );
        report.check(
            "recovery:not-worse-than-tailscale",
            not_worse(nett_s.2, ts_s.2) && not_worse(nett_s.3, ts_s.3),
            "p95 and max",
        );
    }
    write_report(out, &report)?;
    Ok(report)
}
