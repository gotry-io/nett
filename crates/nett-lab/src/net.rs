//! Underlay network: one network namespace per node and router; the "public network" is a bridge in
//! `nl-inet` (design/prototype.md section 5.1).
//!
//! Addresses use documentation-reserved prefixes: public `198.51.100.0/24`, `2001:db8:100::/64`;
//! the LAN behind router `k` is `192.168.k.0/24`.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Context as _;

use crate::cmd::{COMMAND_TIMEOUT, run, run_in, run_with_input};
use crate::topology::{Nat, Topology};

pub const INET_NETNS: &str = "nl-inet";
/// The "stranger" that sends unauthenticated probes in scenario 18: attached to the "public
/// network" and not a member.
pub const OUTSIDER_NETNS: &str = "nl-x";
const NETNS_PREFIX: &str = "nl-";

#[derive(Debug, Clone)]
pub struct NodeNet {
    pub netns: String,
    /// IPv4 address on the node's own network interface.
    pub ipv4: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
    /// Address reachable directly on the "public network"; nodes behind NAT do not have one.
    pub public_ipv4: Option<Ipv4Addr>,
    /// Namespace of the switch the node attaches to: `nl-inet` for public nodes, the router for
    /// nodes behind NAT.
    pub switch_ns: String,
    /// The "container" behind a node running Edge (ADR 0015): its address.
    pub edge_container: Option<Ipv4Addr>,
    /// The service behind a smart gateway (design/mesh.md section 10): the service's address and
    /// the node's address in the service network.
    pub service: Option<(Ipv4Addr, Ipv4Addr)>,
}

#[derive(Debug, Clone)]
pub struct Underlay {
    nodes: BTreeMap<String, NodeNet>,
    routers: Vec<(String, u8, Nat)>,
}

/// Address in the LAN prefix `2001:db8:<200+k>::/64` of an IPv6 stateful firewall router.
fn lan_ipv6(router: u8, host: u16) -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0xdb8, 200 + u16::from(router), 0, 0, 0, 0, host)
}

/// The router's IPv6 address on the "public network" side.
fn wan_ipv6(router: u8) -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0xdb8, 0x100, 0, 0, 0, 0, 200 + u16::from(router))
}

pub fn netns(name: &str) -> String {
    format!("{NETNS_PREFIX}{name}")
}

/// Namespace of the "container" behind a node running Edge.
pub fn edge_netns(name: &str) -> String {
    format!("{NETNS_PREFIX}{name}-edge")
}

/// Namespace of the service behind a smart gateway.
pub fn service_netns(name: &str) -> String {
    format!("{NETNS_PREFIX}{name}-svc")
}

/// The node-side address connecting to the Edge container (point to point; the container uses it as
/// its default gateway).
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
                        // A node behind an IPv6 stateful firewall has a global IPv6 address
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

    /// The node's egress address on the "public network": a public node's own address, or the
    /// router's external address for a node behind NAT.
    pub fn egress_ipv4(&self, name: &str) -> Option<Ipv4Addr> {
        let node = self.nodes.get(name)?;
        if node.public_ipv4.is_some() {
            return node.public_ipv4;
        }
        let router = node.switch_ns.strip_prefix(NETNS_PREFIX)?;
        let (_, k, _) = self.routers.iter().find(|(r, _, _)| r == router)?;
        Some(Ipv4Addr::new(198, 51, 100, 200 + k))
    }

    /// The end of a node's or router's uplink on the switch side: `(namespace, interface name)`.
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

    /// Builds the underlay network.
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
                // IPv4 behind an IPv6 stateful firewall uses symmetric NAT: so connectivity is only
                // possible over IPv6 (scenario 11)
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
                // Only connections initiated from the inside and replies of established connections
                // are allowed; anything newly initiated from outside is dropped
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
            // The external interface drops connections newly initiated from outside and addressed
            // to the router itself, like a home router: dropped packets leave no entry in the
            // connection tracking table. Without this rule, a hole punching packet that arrives
            // first from the other side leaves an entry that conflicts with this side's address
            // translation afterwards, so the router has to pick another port and neither end can
            // get through (Tailscale behaves the same way)
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
        // Nodes on the "public network" and other routers reach its LAN IPv6 prefix via the
        // router's external address
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
            // Only IPv6 stateful firewall routers have an IPv6 address on the "public network" side
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

    /// Sets the MTU of the "public network" segment to `mtu` (scenario 19): the bridge, its ports,
    /// and the `eth0` of the members and routers attached to it. A veth drops frames larger than
    /// its own MTU, so both ends of a link are set together; the bottleneck falls at the hop where
    /// the router forwards into the "public network" (IPv4 fragments, IPv6 replies with ICMPv6
    /// "packet too big"), and members on the "public network" send according to their own interface
    /// MTU.
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

    /// Namespaces of members and routers: where IP processing (fragmentation, reassembly) happens.
    pub fn ip_netns(&self) -> Vec<String> {
        self.nodes
            .values()
            .map(|n| n.netns.clone())
            .chain(self.routers.iter().map(|(name, _, _)| netns(name)))
            .collect()
    }

    /// Tears down the underlay network: first ends the processes in the namespaces, then deletes
    /// the namespaces. Skipped when a namespace does not exist.
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

/// Attaches a "container" behind a node running Edge: a veth pair; the node side enables forwarding
/// and, like Docker, masquerades the container's traffic to other interfaces (priority 100). The
/// mesh process's Edge source NAT must take effect before it (ADR 0015).
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

/// Attaches a service behind a smart gateway (equivalent to a container with a fixed address in a
/// Docker network): the same `/24`, with the service using the node as default gateway, and the
/// node enabling forwarding (in a container, Compose sysctls enable it).
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

/// Attaches `ns` to the bridge of `switch_ns` with a veth pair: the end in `ns` is called `eth0`.
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
