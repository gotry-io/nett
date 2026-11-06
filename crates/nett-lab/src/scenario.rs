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
    let busiest = |m: &PathMonitor| -> Option<usize> {
        let rates = m.rates(Duration::from_secs(2));
        let (i, r) = rates.iter().enumerate().max_by_key(|(_, r)| **r)?;
        (*r >= RELAY_QUIET_BYTES_PER_S).then_some(i)
    };
    // 先等流量稳定在某一个中继上
    let deadline = Instant::now() + SETTLE_TIMEOUT;
    let current = loop {
        std::thread::sleep(Duration::from_secs(1));
        let now = now_ms();
        let flowing =
            probe_stats(&probe_file, now.saturating_sub(3000), now).is_ok_and(|p| p.received >= 25);
        if let (true, Some(i)) = (flowing, busiest(&monitor)) {
            break i;
        }
        if Instant::now() >= deadline {
            anyhow::bail!("{system}: traffic did not settle on a relay within {SETTLE_TIMEOUT:?}");
        }
    };
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
    )?;
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
        let not_worse =
            |a: Option<u64>, b: Option<u64>| matches!((a, b), (Some(a), Some(b)) if a <= b);
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
}

#[derive(Debug, Clone, Serialize)]
pub struct WaveRun {
    pub system: String,
    /// 期间流量在中继之间换了几次。
    pub switches: usize,
    /// 是否回到过之前离开的路径（来回切换）。
    pub returned: bool,
    pub tcp_kbps: u64,
    pub tcp_ended: Option<String>,
    /// 探测流的送达率（千分比）与最长中断。
    pub delivered_permille: u64,
    pub max_gap_ms: u64,
}

/// `impair(lab, i, wave)` 在第 i 个中继的链路上施加（`Some`）或解除（`None`）损伤。
fn wave_run(
    lab: &mut Lab,
    out: &Path,
    system: &str,
    target: std::net::IpAddr,
    links: &[(String, String, String)],
    (wave, duration): (Wave, Duration),
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
    let busiest = monitor.busiest_per_second(start_ms, end_ms, RELAY_QUIET_BYTES_PER_S);
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
    Ok(WaveRun {
        system: system.to_owned(),
        switches,
        returned,
        tcp_kbps: tcp.kbps,
        tcp_ended: tcp.ended,
        delivered_permille: (probe.received as u64 * 1000 / expected.max(1)).min(1000),
        max_gap_ms: probe.max_gap_ms,
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
        runs.push(wave_run(
            &mut lab,
            &dir,
            "nett",
            b.mesh_ipv4.into(),
            &links,
            (wave, duration),
            |lab, i, netem| match netem {
                Some(n) => crate::fault::set_link(&lab.underlay, relays[i], n),
                None => crate::fault::clear_link(&lab.underlay, relays[i]),
            },
        )?);
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
            (wave, duration),
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
    report.check(
        "nett:no-flapping",
        n.iter().all(|r| r.switches <= 1 && !r.returned),
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
            max(&n, |r| r.max_gap_ms) <= max(&t, |r| r.max_gap_ms),
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
    // 对照：组网进程仍停着，只在 b 上单独打开接收探测用的原始套接字与过滤器
    let me = std::env::current_exe().context("locating nett-lab")?;
    let raw = spawn_in(&ns_b, &me, ["raw-listen"], &out.join("raw-listen.log"))?;
    lab.helpers.push(raw);
    std::thread::sleep(Duration::from_millis(300));
    let mut raw_only: Vec<u64> = Vec::new();
    for i in 0..3 {
        raw_only.push(iperf(&mut lab, b.mesh_ipv4, out, &format!("raw-only-{i}"))?);
    }
    report.record(
        "wgport:throughput-raw-socket-only",
        format!(
            "median {} kbit/s ({raw_only:?})",
            median(&mut raw_only.clone())
        ),
    );
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
