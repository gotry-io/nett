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

    fn args(&self) -> Vec<String> {
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

/// 解除 [`block_udp`]。
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

/// 接口的累计收发字节数 `(rx, tx)`，用来从底层网络判断流量走哪条链路（design/prototype.md 第 6.1 节）。
pub fn counters(ns: &str, dev: &str) -> anyhow::Result<(u64, u64)> {
    let out = run("ip", ["-n", ns, "-s", "-j", "link", "show", "dev", dev])?;
    let v: Value = serde_json::from_str(&out).context("parsing `ip -j` output")?;
    let stats = &v[0]["stats64"];
    let rx = stats["rx"]["bytes"].as_u64().context("rx bytes")?;
    let tx = stats["tx"]["bytes"].as_u64().context("tx bytes")?;
    Ok((rx, tx))
}
