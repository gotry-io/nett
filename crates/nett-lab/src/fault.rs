//! 故障注入（design/prototype.md 第 5.1 节）：链路质量（`tc netem`）、拦截 UDP（nftables）。
//!
//! 故障加在底层网络上，nett 和 Tailscale 遇到的是同一种故障。

use anyhow::Context as _;
use serde_json::Value;

use crate::cmd::{COMMAND_TIMEOUT, run, run_with_input};
use crate::net::Underlay;

/// 拦截规则所在的 nftables 表，与 NAT 规则分开，解除时整表删除。
const FAULT_TABLE: &str = "nettlab_fault";

/// 一条链路的质量。各项为空时不设置。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Netem {
    pub loss_percent: Option<f32>,
    pub delay_ms: Option<u32>,
    pub jitter_ms: Option<u32>,
    pub rate_kbit: Option<u32>,
}

impl Netem {
    pub fn loss(percent: f32) -> Self {
        Self {
            loss_percent: Some(percent),
            ..Self::default()
        }
    }

    pub fn args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(delay) = self.delay_ms {
            args.extend(["delay".into(), format!("{delay}ms")]);
            if let Some(jitter) = self.jitter_ms {
                args.push(format!("{jitter}ms"));
            }
        }
        if let Some(loss) = self.loss_percent {
            args.extend(["loss".into(), format!("{loss}%")]);
        }
        if let Some(rate) = self.rate_kbit {
            args.extend(["rate".into(), format!("{rate}kbit")]);
        }
        args
    }
}

/// 链路的两端：节点（或路由器）命名空间中的 `eth0`，以及交换侧命名空间中的端口。
fn link_ends(underlay: &Underlay, name: &str) -> anyhow::Result<[(String, String); 2]> {
    let (switch_ns, port) = underlay
        .switch_port(name)
        .with_context(|| format!("no link for `{name}`"))?;
    Ok([
        (crate::net::netns(name), "eth0".to_owned()),
        (switch_ns, port),
    ])
}

/// 设置 `name` 接入链路的质量，两个方向都生效。
pub fn set_link(underlay: &Underlay, name: &str, netem: &Netem) -> anyhow::Result<()> {
    for (ns, dev) in link_ends(underlay, name)? {
        let mut args: Vec<String> = ["-n", &ns, "qdisc", "replace", "dev", &dev, "root", "netem"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        args.extend(netem.args());
        run("tc", &args)?;
    }
    Ok(())
}

/// 恢复链路的默认质量。
pub fn clear_link(underlay: &Underlay, name: &str) -> anyhow::Result<()> {
    for (ns, dev) in link_ends(underlay, name)? {
        // 没有设置过 netem 时删除会失败，忽略
        run("tc", ["-n", &ns, "qdisc", "del", "dev", &dev, "root"]).ok();
    }
    Ok(())
}

/// 拦截节点的全部出站与入站 UDP（TCP 不受影响）。
pub fn block_udp(name: &str) -> anyhow::Result<()> {
    let ns = crate::net::netns(name);
    let rules = format!(
        "table inet {FAULT_TABLE} {{\n\
         chain out {{ type filter hook output priority 0; meta l4proto udp drop; }}\n\
         chain in {{ type filter hook input priority 0; meta l4proto udp drop; }}\n\
         }}\n"
    );
    run_with_input(
        "ip",
        ["netns", "exec", &ns, "nft", "-f", "-"],
        Some(rules.as_bytes()),
        COMMAND_TIMEOUT,
    )?;
    Ok(())
}

/// 拦截节点与 `peers` 之间双向的 UDP（IPv4 与 IPv6 地址都要列出）：切断两个节点之间的直连，
/// 经其他地址的路径（例如中继）不受影响。
pub fn block_udp_with(name: &str, peers: &[std::net::IpAddr]) -> anyhow::Result<()> {
    let ns = crate::net::netns(name);
    let rule = |dir: &str| -> String {
        peers
            .iter()
            .map(|ip| {
                let family = if ip.is_ipv4() { "ip" } else { "ip6" };
                format!("{family} {dir} {ip} meta l4proto udp drop; ")
            })
            .collect()
    };
    let rules = format!(
        "table inet {FAULT_TABLE} {{\n\
         chain out {{ type filter hook output priority 0; {}}}\n\
         chain in {{ type filter hook input priority 0; {}}}\n\
         }}\n",
        rule("daddr"),
        rule("saddr")
    );
    run_with_input(
        "ip",
        ["netns", "exec", &ns, "nft", "-f", "-"],
        Some(rules.as_bytes()),
        COMMAND_TIMEOUT,
    )?;
    Ok(())
}

/// 解除 [`block_udp`] 或 [`block_udp_with`]。
pub fn unblock_udp(name: &str) -> anyhow::Result<()> {
    let ns = crate::net::netns(name);
    run(
        "ip",
        [
            "netns",
            "exec",
            &ns,
            "nft",
            "delete",
            "table",
            "inet",
            FAULT_TABLE,
        ],
    )
    .ok();
    Ok(())
}

/// 节点发往 `dst` 的包加上延迟与乱序（场景 15：旧路径上迟到、乱序的包），其他流量不受影响。
pub fn delay_to(
    name: &str,
    dst: std::net::Ipv4Addr,
    delay_ms: u32,
    jitter_ms: u32,
) -> anyhow::Result<()> {
    prepare_delay(
        name,
        &[
            "delay".into(),
            format!("{delay_ms}ms"),
            format!("{jitter_ms}ms"),
            "reorder".into(),
            "25%".into(),
            "50%".into(),
        ],
    )?;
    route_delay(name, dst)
}

/// 在节点的 `eth0` 上建好"按目的地址加延迟"的排队规则：四个优先级队列，平时全部流量走第一个，第四个
/// 挂 netem；由 [`route_delay`] 决定发往哪个地址的包进入第四个。替换根排队规则会丢掉正在排队的包，
/// 所以在开始传输之前调用（场景 5 交替变好）。
pub fn prepare_delay(name: &str, netem: &[String]) -> anyhow::Result<()> {
    let ns = crate::net::netns(name);
    let mut root: Vec<String> = [
        "-n", &ns, "qdisc", "replace", "dev", "eth0", "root", "handle", "1:", "prio", "bands", "4",
        "priomap",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    root.extend(std::iter::repeat_n("0".to_owned(), 16));
    run("tc", &root)?;
    let mut leaf: Vec<String> = [
        "-n", &ns, "qdisc", "replace", "dev", "eth0", "parent", "1:4", "handle", "40:", "netem",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    leaf.extend(netem.iter().cloned());
    run("tc", &leaf)?;
    Ok(())
}

/// 让发往 `dst` 的包进入 [`prepare_delay`] 建好的延迟队列，替换之前的选择。只改过滤器，不动排队规则，
/// 正在排队的包不受影响。
pub fn route_delay(name: &str, dst: std::net::Ipv4Addr) -> anyhow::Result<()> {
    let ns = crate::net::netns(name);
    // 还没有过滤器时删除会失败，忽略
    run(
        "tc",
        [
            "-n", &ns, "filter", "del", "dev", "eth0", "parent", "1:", "prio", "1",
        ],
    )
    .ok();
    run(
        "tc",
        [
            "-n",
            &ns,
            "filter",
            "add",
            "dev",
            "eth0",
            "parent",
            "1:",
            "protocol",
            "ip",
            "prio",
            "1",
            "u32",
            "match",
            "ip",
            "dst",
            &format!("{dst}/32"),
            "flowid",
            "1:4",
        ],
    )?;
    Ok(())
}

/// 去掉节点 `eth0` 上的全部排队规则与过滤器。
pub fn clear_eth0(name: &str) -> anyhow::Result<()> {
    let ns = crate::net::netns(name);
    run("tc", ["-n", &ns, "qdisc", "del", "dev", "eth0", "root"]).ok();
    Ok(())
}

/// 只拦截从 `src` 发来的 UDP（单方向）。
pub fn block_udp_from(name: &str, src: std::net::Ipv4Addr) -> anyhow::Result<()> {
    let ns = crate::net::netns(name);
    let rules = format!(
        "table inet {FAULT_TABLE} {{\n\
         chain in {{ type filter hook input priority 0; ip saddr {src} meta l4proto udp drop; }}\n\
         }}\n"
    );
    run_with_input(
        "ip",
        ["netns", "exec", &ns, "nft", "-f", "-"],
        Some(rules.as_bytes()),
        COMMAND_TIMEOUT,
    )?;
    Ok(())
}

/// 接口的累计收发字节数 `(rx, tx)`，用来从底层网络判断流量走哪条链路（design/prototype.md 第 6.1 节）。
pub fn counters(ns: &str, dev: &str) -> anyhow::Result<(u64, u64)> {
    let out = run("ip", ["-n", ns, "-s", "-j", "link", "show", "dev", dev])?;
    let v: Value = serde_json::from_str(&out).context("parsing `ip -j` output")?;
    let stats = &v[0]["stats64"];
    let rx = stats["rx"]["bytes"].as_u64().context("rx bytes")?;
    let tx = stats["tx"]["bytes"].as_u64().context("tx bytes")?;
    Ok((rx, tx))
}
