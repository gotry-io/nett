//! 底层网络：每个节点和路由器一个网络命名空间，"公网"是 `nl-inet` 中的一个网桥（design/prototype.md 第 5.1 节）。
//!
//! 地址使用文档保留的网段：公网 `198.51.100.0/24`、`2001:db8:100::/64`；路由器 `k` 之后的局域网 `192.168.k.0/24`。

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Context as _;

use crate::cmd::{COMMAND_TIMEOUT, run, run_in, run_with_input};
use crate::topology::{Nat, Topology};

pub const INET_NETNS: &str = "nl-inet";
/// 场景 18 中发送未认证探测的"陌生人"，接在"公网"上，不是成员。
pub const OUTSIDER_NETNS: &str = "nl-x";
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
    /// 运行 Edge 的节点背后的"容器"（ADR 0015）：它的地址。
    pub edge_container: Option<Ipv4Addr>,
    /// 智能入口背后的服务（design/mesh.md 第 10 节）：服务的地址与节点在服务网络中的地址。
    pub service: Option<(Ipv4Addr, Ipv4Addr)>,
}

#[derive(Debug, Clone)]
pub struct Underlay {
    nodes: BTreeMap<String, NodeNet>,
    routers: Vec<(String, u8, Nat)>,
}

/// IPv6 有状态防火墙路由器的局域网网段 `2001:db8:<200+k>::/64` 中的地址。
fn lan_ipv6(router: u8, host: u16) -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0xdb8, 200 + u16::from(router), 0, 0, 0, 0, host)
}

/// 路由器在"公网"一侧的 IPv6 地址。
fn wan_ipv6(router: u8) -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0xdb8, 0x100, 0, 0, 0, 0, 200 + u16::from(router))
}

pub fn netns(name: &str) -> String {
    format!("{NETNS_PREFIX}{name}")
}

/// 运行 Edge 的节点背后的"容器"所在的命名空间。
pub fn edge_netns(name: &str) -> String {
    format!("{NETNS_PREFIX}{name}-edge")
}

/// 智能入口背后的服务所在的命名空间。
pub fn service_netns(name: &str) -> String {
    format!("{NETNS_PREFIX}{name}-svc")
}

/// 节点一侧连接 Edge 容器的地址（点对点，容器以它为默认网关）。
const EDGE_GATEWAY: &str = "169.254.0.1";

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
                    edge_container: None,
                    service: None,
                },
                Some(router) => {
                    let (_, k, nat) = routers
                        .iter()
                        .find(|(name, _, _)| name == router)
                        .context("router")?;
                    NodeNet {
                        netns: netns(&node.name),
                        ipv4: Ipv4Addr::new(192, 168, *k, 10 + index),
                        // IPv6 有状态防火墙之后的节点有全局 IPv6 地址
                        ipv6: (*nat == Nat::Ipv6Firewall)
                            .then(|| lan_ipv6(*k, 10 + u16::from(index))),
                        public_ipv4: None,
                        switch_ns: netns(router),
                        edge_container: None,
                        service: None,
                    }
                }
            };
            let edge_container = node
                .edge
                .as_ref()
                .and_then(|e| match e.containers[0].addr() {
                    std::net::IpAddr::V4(a) => Some(a),
                    std::net::IpAddr::V6(_) => None,
                });
            nodes.insert(
                node.name.clone(),
                NodeNet {
                    edge_container,
                    service: node.service.as_ref().map(|s| (s.address, s.ingress)),
                    ..net
                },
            );
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
            crate::tailscale::derp_netns(1),
            crate::tailscale::derp_netns(2),
            OUTSIDER_NETNS.to_owned(),
        ];
        all.extend(self.routers.iter().map(|(name, _, _)| netns(name)));
        all.extend(self.nodes.values().map(|n| n.netns.clone()));
        all.extend(
            self.nodes
                .iter()
                .filter(|(_, n)| n.edge_container.is_some())
                .map(|(name, _)| edge_netns(name)),
        );
        all.extend(
            self.nodes
                .iter()
                .filter(|(_, n)| n.service.is_some())
                .map(|(name, _)| service_netns(name)),
        );
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
                // IPv6 有状态防火墙之后的 IPv4 用对称型 NAT：这样只能经 IPv6 打通（场景 11）
                Nat::Symmetric | Nat::Ipv6Firewall => "masquerade fully-random",
            };
            if *nat == Nat::Ipv6Firewall {
                let lan = lan_ipv6(*k, 1);
                for (dev, addr) in [("eth0", wan_ipv6(*k)), ("lan", lan)] {
                    run(
                        "ip",
                        [
                            "-n",
                            &ns,
                            "-6",
                            "addr",
                            "add",
                            &format!("{addr}/64"),
                            "dev",
                            dev,
                            "nodad",
                        ],
                    )?;
                }
                run_in(&ns, "sysctl", ["-qw", "net.ipv6.conf.all.forwarding=1"])?;
                // 只放行内部发起的连接与已建立连接的回包；从外面新发起的一律丢弃
                let rules = "table ip6 firewall {\n\
                     chain forward {\n\
                     type filter hook forward priority 0; policy drop;\n\
                     ct state established,related accept\n\
                     iifname \"lan\" oifname \"eth0\" accept\n\
                     }\n\
                     }\n";
                run_with_input(
                    "ip",
                    ["netns", "exec", &ns, "nft", "-f", "-"],
                    Some(rules.as_bytes()),
                    COMMAND_TIMEOUT,
                )?;
            }
            // 外网口丢弃从外面新发起、发给路由器自己的连接，与家用路由器一样：被丢弃的包不在连接跟踪表里
            // 留下记录。没有这一条时，对方先到的打洞包会留下一条记录，与本端随后的地址转换冲突，路由器只好
            // 换一个端口，两端都打不通（Tailscale 也是如此）
            let rules = format!(
                "table ip nat {{\n\
                 chain post {{ type nat hook postrouting priority 100; oifname \"eth0\" {masquerade}; }}\n\
                 }}\n\
                 table inet router_input {{\n\
                 chain input {{\n\
                 type filter hook input priority 0;\n\
                 iifname \"eth0\" ct state new drop\n\
                 }}\n\
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
                if net.ipv6.is_some() {
                    run(
                        "ip",
                        [
                            "-n",
                            &net.netns,
                            "-6",
                            "route",
                            "add",
                            "default",
                            "via",
                            &lan_ipv6(*k, 1).to_string(),
                        ],
                    )?;
                }
            }
        }
        for (name, net) in &self.nodes {
            if let Some(container) = net.edge_container {
                edge_container(name, &net.netns, container)?;
            }
            if let Some((address, ingress)) = net.service {
                service(name, &net.netns, address, ingress)?;
            }
        }
        // "公网"上的节点和其他路由器经路由器的外网地址到达它的局域网 IPv6 网段
        for (name, k, nat) in &self.routers {
            if *nat != Nat::Ipv6Firewall {
                continue;
            }
            let prefix = format!("{}/64", lan_ipv6(*k, 0));
            let via = wan_ipv6(*k).to_string();
            let public = self
                .nodes
                .values()
                .filter(|n| n.switch_ns == INET_NETNS)
                .map(|n| n.netns.clone());
            // 只有 IPv6 有状态防火墙路由器在"公网"一侧有 IPv6 地址
            let routers = self
                .routers
                .iter()
                .filter(|(other, _, n)| other != name && *n == Nat::Ipv6Firewall)
                .map(|(other, _, _)| netns(other));
            for ns in public.chain(routers) {
                run(
                    "ip",
                    ["-n", &ns, "-6", "route", "add", &prefix, "via", &via],
                )?;
            }
        }
        Ok(())
    }

    /// 把"公网"这一段的 MTU 设为 `mtu`（场景 19）：网桥、它的各个端口，以及接在上面的成员和路由器的
    /// `eth0`。veth 收到超过本端 MTU 的帧时直接丢弃，所以一条链路的两端一起设置；瓶颈落在路由器转发
    /// 进"公网"的那一跳（IPv4 分片，IPv6 回 ICMPv6"包太大"），"公网"上的成员按自己接口的 MTU 发送。
    pub fn set_internet_mtu(&self, mtu: u16) -> anyhow::Result<()> {
        let mtu = mtu.to_string();
        let attached = self
            .nodes
            .iter()
            .filter(|(_, n)| n.switch_ns == INET_NETNS)
            .map(|(name, n)| (name.clone(), n.netns.clone()))
            .chain(
                self.routers
                    .iter()
                    .map(|(name, _, _)| (name.clone(), netns(name))),
            );
        for (name, ns) in attached {
            let port = format!("v-{name}");
            run("ip", ["-n", INET_NETNS, "link", "set", &port, "mtu", &mtu])?;
            run("ip", ["-n", &ns, "link", "set", "eth0", "mtu", &mtu])?;
        }
        run("ip", ["-n", INET_NETNS, "link", "set", "br0", "mtu", &mtu])?;
        Ok(())
    }

    /// 成员与路由器的命名空间：做 IP 处理（分片、重组）的地方。
    pub fn ip_netns(&self) -> Vec<String> {
        self.nodes
            .values()
            .map(|n| n.netns.clone())
            .chain(self.routers.iter().map(|(name, _, _)| netns(name)))
            .collect()
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

/// 在运行 Edge 的节点背后接一个"容器"：一对 veth，节点一侧开启转发，并像 Docker 一样对容器发往其他接口的
/// 流量做源地址伪装（优先级 100）。组网进程的 Edge 源地址转换必须在它之前生效（ADR 0015）。
fn edge_container(name: &str, node_ns: &str, container: Ipv4Addr) -> anyhow::Result<()> {
    let ns = edge_netns(name);
    add_netns(&ns)?;
    run(
        "ip",
        [
            "link", "add", "edge0", "netns", node_ns, "type", "veth", "peer", "name", "eth0",
            "netns", &ns,
        ],
    )?;
    let host = format!("{container}/32");
    for args in [
        vec!["-n", &ns, "addr", "add", &host, "dev", "eth0"],
        vec!["-n", &ns, "link", "set", "eth0", "up"],
        vec!["-n", &ns, "route", "add", EDGE_GATEWAY, "dev", "eth0"],
        vec![
            "-n",
            &ns,
            "route",
            "add",
            "default",
            "via",
            EDGE_GATEWAY,
            "dev",
            "eth0",
        ],
        vec![
            "-n",
            node_ns,
            "addr",
            "add",
            &format!("{EDGE_GATEWAY}/32"),
            "dev",
            "edge0",
        ],
        vec!["-n", node_ns, "link", "set", "edge0", "up"],
        vec!["-n", node_ns, "route", "add", &host, "dev", "edge0"],
    ] {
        run("ip", args)?;
    }
    run_in(node_ns, "sysctl", ["-qw", "net.ipv4.ip_forward=1"])?;
    let rules = format!(
        "table ip lab_docker {{\n chain post {{\n  type nat hook postrouting priority 100;\n  \
         ip saddr {container} oifname != \"edge0\" masquerade\n }}\n}}\n"
    );
    run_with_input(
        "ip",
        ["netns", "exec", node_ns, "nft", "-f", "-"],
        Some(rules.as_bytes()),
        COMMAND_TIMEOUT,
    )?;
    Ok(())
}

/// 在智能入口背后接一个服务（相当于 Docker 网络中固定地址的容器）：同一个 `/24`，服务以节点为默认网关，
/// 节点开启转发（容器中由 Compose 的 sysctls 开启）。
fn service(name: &str, node_ns: &str, address: Ipv4Addr, ingress: Ipv4Addr) -> anyhow::Result<()> {
    let ns = service_netns(name);
    add_netns(&ns)?;
    run(
        "ip",
        [
            "link", "add", "svc0", "netns", node_ns, "type", "veth", "peer", "name", "eth0",
            "netns", &ns,
        ],
    )?;
    let (svc, gw) = (format!("{address}/24"), format!("{ingress}/24"));
    let via = ingress.to_string();
    for args in [
        vec!["-n", &ns, "addr", "add", &svc, "dev", "eth0"],
        vec!["-n", &ns, "link", "set", "eth0", "up"],
        vec!["-n", &ns, "route", "add", "default", "via", &via],
        vec!["-n", node_ns, "addr", "add", &gw, "dev", "svc0"],
        vec!["-n", node_ns, "link", "set", "svc0", "up"],
    ] {
        run("ip", args)?;
    }
    run_in(node_ns, "sysctl", ["-qw", "net.ipv4.ip_forward=1"])?;
    Ok(())
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
