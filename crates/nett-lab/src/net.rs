//! 底层网络：每个节点和路由器一个网络命名空间，"公网"是 `nl-inet` 中的一个网桥（design/prototype.md 第 5.1 节）。
//!
//! 地址使用文档保留的网段：公网 `198.51.100.0/24`、`2001:db8:100::/64`；路由器 `k` 之后的局域网 `192.168.k.0/24`。

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Context as _;

use crate::cmd::{COMMAND_TIMEOUT, run, run_in, run_with_input};
use crate::topology::{Nat, Topology};

pub const INET_NETNS: &str = "nl-inet";
const NETNS_PREFIX: &str = "nl-";

#[derive(Debug, Clone)]
pub struct NodeNet {
    pub netns: String,
    /// 节点自己网卡上的 IPv4 地址。
    pub ipv4: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
    /// 在"公网"上可以直接访问的地址；在 NAT 之后的节点没有。
    pub public_ipv4: Option<Ipv4Addr>,
    /// 节点接入的交换机所在的命名空间：公网节点是 `nl-inet`，NAT 之后的节点是路由器。
    pub switch_ns: String,
}

#[derive(Debug, Clone)]
pub struct Underlay {
    nodes: BTreeMap<String, NodeNet>,
    routers: Vec<(String, u8, Nat)>,
}

pub fn netns(name: &str) -> String {
    format!("{NETNS_PREFIX}{name}")
}

impl Underlay {
    pub fn plan(topo: &Topology) -> anyhow::Result<Self> {
        let mut nodes = BTreeMap::new();
        let routers: Vec<(String, u8, Nat)> = topo
            .routers
            .iter()
            .enumerate()
            .map(|(k, r)| {
                Ok((
                    r.name.clone(),
                    u8::try_from(k + 1).context("too many routers")?,
                    r.nat,
                ))
            })
            .collect::<anyhow::Result<_>>()?;
        for node in &topo.nodes {
            let index = topo.index(&node.name).context("node index")?;
            let net = match &node.behind {
                None => NodeNet {
                    netns: netns(&node.name),
                    ipv4: Ipv4Addr::new(198, 51, 100, index),
                    ipv6: Some(Ipv6Addr::new(
                        0x2001,
                        0xdb8,
                        0x100,
                        0,
                        0,
                        0,
                        0,
                        u16::from(index),
                    )),
                    public_ipv4: Some(Ipv4Addr::new(198, 51, 100, index)),
                    switch_ns: INET_NETNS.to_owned(),
                },
                Some(router) => {
                    let (_, k, _) = routers
                        .iter()
                        .find(|(name, _, _)| name == router)
                        .context("router")?;
                    NodeNet {
                        netns: netns(&node.name),
                        ipv4: Ipv4Addr::new(192, 168, *k, 10 + index),
                        ipv6: None,
                        public_ipv4: None,
                        switch_ns: netns(router),
                    }
                }
            };
            nodes.insert(node.name.clone(), net);
        }
        Ok(Self { nodes, routers })
    }

    pub fn node(&self, name: &str) -> Option<&NodeNet> {
        self.nodes.get(name)
    }

    /// 节点在"公网"上的出口地址：公网节点是自己的地址，NAT 之后的节点是路由器的外网地址。
    pub fn egress_ipv4(&self, name: &str) -> Option<Ipv4Addr> {
        let node = self.nodes.get(name)?;
        if node.public_ipv4.is_some() {
            return node.public_ipv4;
        }
        let router = node.switch_ns.strip_prefix(NETNS_PREFIX)?;
        let (_, k, _) = self.routers.iter().find(|(r, _, _)| r == router)?;
        Some(Ipv4Addr::new(198, 51, 100, 200 + k))
    }

    /// 节点或路由器接入链路在交换侧的一端：`(命名空间, 接口名)`。
    pub fn switch_port(&self, name: &str) -> Option<(String, String)> {
        let switch_ns = match self.nodes.get(name) {
            Some(node) => node.switch_ns.clone(),
            None if self.routers.iter().any(|(r, _, _)| r == name) => INET_NETNS.to_owned(),
            None => return None,
        };
        Some((switch_ns, format!("v-{name}")))
    }

    pub fn public_ipv4(&self, name: &str) -> Option<Ipv4Addr> {
        self.nodes.get(name).and_then(|n| n.public_ipv4)
    }

    fn all_netns(&self) -> Vec<String> {
        let mut all = vec![
            INET_NETNS.to_owned(),
            crate::tailscale::CONTROL_NETNS.to_owned(),
        ];
        all.extend(self.routers.iter().map(|(name, _, _)| netns(name)));
        all.extend(self.nodes.values().map(|n| n.netns.clone()));
        all
    }

    /// 搭建底层网络。
    pub fn up(&self, topo: &Topology) -> anyhow::Result<()> {
        add_netns(INET_NETNS)?;
        run(
            "ip",
            ["-n", INET_NETNS, "link", "add", "br0", "type", "bridge"],
        )?;
        run("ip", ["-n", INET_NETNS, "link", "set", "br0", "up"])?;

        for (name, k, nat) in &self.routers {
            let ns = netns(name);
            add_netns(&ns)?;
            let wan = Ipv4Addr::new(198, 51, 100, 200 + k);
            attach(&ns, INET_NETNS, &format!("v-{name}"), "br0")?;
            run(
                "ip",
                [
                    "-n",
                    &ns,
                    "addr",
                    "add",
                    &format!("{wan}/24"),
                    "dev",
                    "eth0",
                ],
            )?;
            run("ip", ["-n", &ns, "link", "add", "lan", "type", "bridge"])?;
            run("ip", ["-n", &ns, "link", "set", "lan", "up"])?;
            run(
                "ip",
                [
                    "-n",
                    &ns,
                    "addr",
                    "add",
                    &format!("192.168.{k}.1/24"),
                    "dev",
                    "lan",
                ],
            )?;
            run_in(&ns, "sysctl", ["-qw", "net.ipv4.ip_forward=1"])?;
            let masquerade = match nat {
                Nat::Cone => "masquerade",
                Nat::Symmetric => "masquerade random-fully",
                Nat::Ipv6Firewall => anyhow::bail!("ipv6-firewall routers are not supported yet"),
            };
            let rules = format!(
                "table ip nat {{\n\
                 chain post {{ type nat hook postrouting priority 100; oifname \"eth0\" {masquerade}; }}\n\
                 }}\n"
            );
            run_with_input(
                "ip",
                ["netns", "exec", &ns, "nft", "-f", "-"],
                Some(rules.as_bytes()),
                COMMAND_TIMEOUT,
            )?;
        }

        for node in &topo.nodes {
            let net = self.node(&node.name).context("planned node")?;
            add_netns(&net.netns)?;
            match &node.behind {
                None => attach(&net.netns, INET_NETNS, &format!("v-{}", node.name), "br0")?,
                Some(router) => attach(
                    &net.netns,
                    &netns(router),
                    &format!("v-{}", node.name),
                    "lan",
                )?,
            }
            run(
                "ip",
                [
                    "-n",
                    &net.netns,
                    "addr",
                    "add",
                    &format!("{}/24", net.ipv4),
                    "dev",
                    "eth0",
                ],
            )?;
            if let Some(v6) = net.ipv6 {
                run(
                    "ip",
                    [
                        "-n",
                        &net.netns,
                        "-6",
                        "addr",
                        "add",
                        &format!("{v6}/64"),
                        "dev",
                        "eth0",
                        "nodad",
                    ],
                )?;
            }
            if let Some(router) = &node.behind {
                let (_, k, _) = self
                    .routers
                    .iter()
                    .find(|(name, _, _)| name == router)
                    .context("router")?;
                run(
                    "ip",
                    [
                        "-n",
                        &net.netns,
                        "route",
                        "add",
                        "default",
                        "via",
                        &format!("192.168.{k}.1"),
                    ],
                )?;
            }
        }
        Ok(())
    }

    /// 拆除底层网络：先结束命名空间中的进程，再删除命名空间。命名空间不存在时跳过。
    pub fn down(&self) -> anyhow::Result<()> {
        let existing = run("ip", ["netns", "list"])?;
        for ns in self.all_netns().iter().rev() {
            if !existing
                .lines()
                .any(|l| l.split_whitespace().next() == Some(ns))
            {
                continue;
            }
            let pids = run("ip", ["netns", "pids", ns])?;
            for pid in pids.split_whitespace() {
                run("kill", ["-TERM", pid]).ok();
            }
            run("ip", ["netns", "del", ns])?;
        }
        Ok(())
    }
}

pub(crate) fn add_netns(ns: &str) -> anyhow::Result<()> {
    run("ip", ["netns", "add", ns])?;
    run("ip", ["-n", ns, "link", "set", "lo", "up"])?;
    Ok(())
}

/// 用一对 veth 把 `ns` 接到 `switch_ns` 的网桥上：`ns` 中的一端叫 `eth0`。
pub(crate) fn attach(ns: &str, switch_ns: &str, port: &str, bridge: &str) -> anyhow::Result<()> {
    run(
        "ip",
        [
            "link", "add", port, "netns", switch_ns, "type", "veth", "peer", "name", "eth0",
            "netns", ns,
        ],
    )?;
    run(
        "ip",
        ["-n", switch_ns, "link", "set", port, "master", bridge, "up"],
    )?;
    run("ip", ["-n", ns, "link", "set", "eth0", "up"])?;
    Ok(())
}
