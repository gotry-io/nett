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
    /// 测量用的辅助进程（探测流、长连接）。
    helpers: Vec<Child>,
}

impl Drop for Lab {
    fn drop(&mut self) {
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
        helpers: Vec::new(),
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

    /// 在节点的命名空间中启动一个测量辅助进程（`nett-lab` 自己的子命令）。
    fn helper(&mut self, name: &str, args: &[&str], log: &Path) -> anyhow::Result<()> {
        let net = self.underlay.node(name).context("planned node")?;
        let me = std::env::current_exe().context("locating nett-lab")?;
        let child = spawn_in(&net.netns, &me, args, log)?;
        self.helpers.push(child);
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
    fault::block_udp_to(a, &b_addrs)?;
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
