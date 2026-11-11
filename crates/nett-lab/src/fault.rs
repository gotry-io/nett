//! Fault injection (design/prototype.md section 5.1): link quality (`tc netem`) and UDP blocking
//! (nftables).
//!
//! Faults are applied to the underlay network, so nett and Tailscale meet the same fault.

use anyhow::Context as _;
use serde_json::Value;

use crate::cmd::{COMMAND_TIMEOUT, run, run_with_input};
use crate::net::Underlay;

/// The nftables table holding the blocking rules, kept apart from the NAT rules and deleted as a
/// whole when lifted.
const FAULT_TABLE: &str = "nettlab_fault";
// Inbound blocking hooks prerouting at priority -300: before connection tracking, and before the
// rule with which the mesh process copies probe packets (input, -150). Hooked on input, a blocked
// probe would still be copied to the mesh process and get a reply, which does not match "the packet
// did not arrive".

/// Quality of a link. Items that are empty are not set.
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

/// The two ends of a link: `eth0` in the node's (or router's) namespace, and the port in the
/// switch-side namespace.
fn link_ends(underlay: &Underlay, name: &str) -> anyhow::Result<[(String, String); 2]> {
    let (switch_ns, port) = underlay
        .switch_port(name)
        .with_context(|| format!("no link for `{name}`"))?;
    Ok([
        (crate::net::netns(name), "eth0".to_owned()),
        (switch_ns, port),
    ])
}

/// Sets the quality of the link `name` attaches through, effective in both directions.
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

/// Restores the default quality of the link.
pub fn clear_link(underlay: &Underlay, name: &str) -> anyhow::Result<()> {
    for (ns, dev) in link_ends(underlay, name)? {
        // Deleting fails when netem was never set; ignored
        run("tc", ["-n", &ns, "qdisc", "del", "dev", &dev, "root"]).ok();
    }
    Ok(())
}

/// Blocks all outbound and inbound UDP of the node (TCP is not affected).
pub fn block_udp(name: &str) -> anyhow::Result<()> {
    let ns = crate::net::netns(name);
    let rules = format!(
        "table inet {FAULT_TABLE} {{\n\
         chain out {{ type filter hook output priority 0; meta l4proto udp drop; }}\n\
         chain in {{ type filter hook prerouting priority -300; meta l4proto udp drop; }}\n\
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

/// Blocks all of a node's UDP upstream of it (scenario 7: all UDP blocked): on the NAT router when
/// the node is behind NAT, otherwise on the "public network" bridge port it attaches to. In reality
/// UDP is mostly dropped silently by an upstream firewall, so sending on the machine itself does
/// not fail; blocking on the node itself makes sending fail immediately, some implementations
/// switch path right away because of that, and the real situation is not measured.
pub fn block_udp_upstream(underlay: &Underlay, name: &str) -> anyhow::Result<()> {
    let (ns, port) = underlay
        .switch_port(name)
        .with_context(|| format!("no link for `{name}`"))?;
    let rules = if ns == crate::net::INET_NETNS {
        // Packets on the "public network" bridge are bridged: match by bridge port
        format!(
            "table bridge {FAULT_TABLE} {{\n\
             chain drop_udp {{\n\
             type filter hook forward priority 0;\n\
             iifname \"{port}\" meta l4proto udp drop\n\
             oifname \"{port}\" meta l4proto udp drop\n\
             }}\n\
             }}\n"
        )
    } else {
        // Packets on the NAT router are routed, and the incoming interface is the LAN bridge: match
        // by the node's LAN address (before address translation and after restoration)
        let ip = underlay.node(name).context("planned node")?.ipv4;
        format!(
            "table inet {FAULT_TABLE} {{\n\
             chain drop_udp {{\n\
             type filter hook forward priority 0;\n\
             ip saddr {ip} meta l4proto udp drop\n\
             ip daddr {ip} meta l4proto udp drop\n\
             }}\n\
             }}\n"
        )
    };
    run_with_input(
        "ip",
        ["netns", "exec", &ns, "nft", "-f", "-"],
        Some(rules.as_bytes()),
        COMMAND_TIMEOUT,
    )?;
    Ok(())
}

/// Lifts [`block_udp_upstream`].
pub fn unblock_udp_upstream(underlay: &Underlay, name: &str) -> anyhow::Result<()> {
    let (ns, _) = underlay
        .switch_port(name)
        .with_context(|| format!("no link for `{name}`"))?;
    let family = if ns == crate::net::INET_NETNS {
        "bridge"
    } else {
        "inet"
    };
    run(
        "ip",
        [
            "netns",
            "exec",
            &ns,
            "nft",
            "delete",
            "table",
            family,
            FAULT_TABLE,
        ],
    )?;
    Ok(())
}

/// Blocks UDP in both directions between the node and `peers` (both IPv4 and IPv6 addresses must be
/// listed): cuts the direct connection between two nodes, while paths through other addresses (for
/// example a relay) are not affected.
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
         chain in {{ type filter hook prerouting priority -300; {}}}\n\
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

/// Lifts [`block_udp`] or [`block_udp_with`].
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

/// Adds delay and reordering to the node's packets sent to `dst` (scenario 15: late, reordered
/// packets on the old path); other traffic is not affected.
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

/// Sets up the "delay by destination address" queueing discipline on the node's `eth0`: four
/// priority queues, all traffic normally goes through the first, and netem is attached to the
/// fourth; [`route_delay`] decides which address's packets enter the fourth. Replacing the root
/// queueing discipline drops packets being queued, so call it before the transfer starts (scenario
/// 5, alternating improvement).
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

/// Makes packets sent to `dst` enter the delay queue set up by [`prepare_delay`], replacing the
/// earlier choice. Only the filter changes and the queueing discipline is untouched, so packets
/// being queued are not affected.
pub fn route_delay(name: &str, dst: std::net::Ipv4Addr) -> anyhow::Result<()> {
    let ns = crate::net::netns(name);
    // Deleting fails when there is no filter yet; ignored
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

/// Removes all queueing disciplines and filters on the node's `eth0`.
pub fn clear_eth0(name: &str) -> anyhow::Result<()> {
    let ns = crate::net::netns(name);
    run("tc", ["-n", &ns, "qdisc", "del", "dev", "eth0", "root"]).ok();
    Ok(())
}

/// Only blocks UDP coming from `src` (one direction).
pub fn block_udp_from(name: &str, src: std::net::Ipv4Addr) -> anyhow::Result<()> {
    let ns = crate::net::netns(name);
    let rules = format!(
        "table inet {FAULT_TABLE} {{\n\
         chain in {{ type filter hook prerouting priority -300; ip saddr {src} meta l4proto udp drop; }}\n\
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

/// Cumulative received and sent bytes of an interface `(rx, tx)`, used to tell from the underlay
/// which link the traffic takes (design/prototype.md section 6.1).
pub fn counters(ns: &str, dev: &str) -> anyhow::Result<(u64, u64)> {
    let out = run("ip", ["-n", ns, "-s", "-j", "link", "show", "dev", dev])?;
    let v: Value = serde_json::from_str(&out).context("parsing `ip -j` output")?;
    let stats = &v[0]["stats64"];
    let rx = stats["rx"]["bytes"].as_u64().context("rx bytes")?;
    let tx = stats["tx"]["bytes"].as_u64().context("tx bytes")?;
    Ok((rx, tx))
}
