//! Topology description (design/prototype.md section 4).

use std::collections::BTreeSet;

use anyhow::{Context as _, bail, ensure};
use nett_core::prefix::IpPrefix;
use nett_mesh::config::Reachability;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Topology {
    pub mesh: MeshRanges,
    #[serde(rename = "node")]
    pub nodes: Vec<Node>,
    #[serde(rename = "router", default)]
    pub routers: Vec<Router>,
    #[serde(rename = "link", default)]
    pub links: Vec<Link>,
    /// Access rules (design/mesh.md section 12), expanded in order into one signed rule set.
    #[serde(rename = "allow", default)]
    pub allows: Vec<Allow>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshRanges {
    pub ipv4: IpPrefix,
    pub ipv6: IpPrefix,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub name: String,
    pub reachability: Reachability,
    /// The router it is behind; when absent, it attaches directly to the "public network".
    pub behind: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    /// Userspace data plane (design/userspace.md): `nett mesh --userspace`. Kernel WireGuard by
    /// default.
    #[serde(default)]
    pub userspace: bool,
    /// Lab B (real machines, design/prototype.md section 5.2): SSH host name, plus public IPv4
    /// (`public` nodes) and global IPv6 address. Lab A's addresses are decided by this machine's
    /// network plan, so these items are not written.
    pub ssh: Option<String>,
    pub ipv4: Option<std::net::Ipv4Addr>,
    pub ipv6: Option<std::net::Ipv6Addr>,
    /// The node runs Edge (ADR 0015): the prefix of the container Edge runs in. Lab A builds a
    /// "container" namespace behind this node, whose address is the single IPv4 address (`/32`)
    /// written here.
    pub edge: Option<EdgeSources>,
    /// Advertised routes (design/mesh.md section 10): the node therefore carries the
    /// `subnet_router` role.
    #[serde(default)]
    pub routes: Vec<IpPrefix>,
    /// Lab A: builds a "service" namespace behind this node; `address` is the service's address and
    /// `ingress` is the node's address in the service network (the same `/24`).
    pub service: Option<Service>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub address: std::net::Ipv4Addr,
    pub ingress: std::net::Ipv4Addr,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeSources {
    pub containers: Vec<IpPrefix>,
}

/// An allow rule: `from` and `to` are node names, and `<node>.edge` means that node's Edge address;
/// `ports` is written as `8686/tcp` or `1000-2000/udp`, and empty means all protocols and ports.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allow {
    pub from: Vec<String>,
    pub to: Vec<String>,
    #[serde(default)]
    pub ports: Vec<String>,
}

/// Parses port ranges of the form `8686/tcp`, `1000-2000/udp`.
pub fn parse_ports(s: &str) -> anyhow::Result<nett_trust::payload::PortRange> {
    use nett_trust::payload::{PortRange, Protocol};
    let (range, proto) = s
        .split_once('/')
        .with_context(|| format!("port `{s}` must be <port>[-<port>]/<tcp|udp>"))?;
    let protocol = match proto {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        _ => bail!("port `{s}`: protocol must be tcp or udp"),
    };
    let (first, last) = range.split_once('-').unwrap_or((range, range));
    let first: u16 = first.parse().with_context(|| format!("port `{s}`"))?;
    let last: u16 = last.parse().with_context(|| format!("port `{s}`"))?;
    ensure!(
        first >= 1 && first <= last,
        "port `{s}`: need 1 <= first <= last"
    );
    Ok(PortRange {
        protocol,
        first,
        last,
    })
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Router {
    pub name: String,
    pub nat: Nat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Nat {
    /// Port preserved, mapping independent of destination address (`masquerade`).
    Cone,
    /// One random port per destination address (`masquerade fully-random`).
    Symmetric,
    /// Global IPv6 address; inbound only allows established connections.
    Ipv6Firewall,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Link {
    pub peers: [String; 2],
    pub candidates: Vec<String>,
}

/// A copy of the topology in which the nodes in `names` switch to the userspace data plane
/// (`userspace = true`), written to `dir`; returns its path.
pub fn with_userspace(
    path: &std::path::Path,
    names: &[String],
    dir: &std::path::Path,
) -> anyhow::Result<std::path::PathBuf> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut out = String::with_capacity(text.len());
    let mut in_node = false;
    let mut found = BTreeSet::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_node = trimmed == "[[node]]";
        }
        out.push_str(line);
        out.push('\n');
        if in_node && let Some(name) = names.iter().find(|n| trimmed == format!("name = \"{n}\"")) {
            out.push_str("userspace = true\n");
            found.insert(name.clone());
        }
    }
    for name in names {
        anyhow::ensure!(
            found.contains(name),
            "--userspace names unknown node `{name}`"
        );
    }
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    // Keep the original file name: some scenarios name their reports after it
    let copy = dir.join(path.file_name().context("topology file name")?);
    std::fs::write(&copy, out).with_context(|| format!("writing {}", copy.display()))?;
    Topology::load(&copy)?;
    Ok(copy)
}

impl Topology {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let topo: Topology =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        topo.validate()?;
        Ok(topo)
    }

    fn validate(&self) -> anyhow::Result<()> {
        let mut names = BTreeSet::new();
        for name in self
            .nodes
            .iter()
            .map(|n| &n.name)
            .chain(self.routers.iter().map(|r| &r.name))
        {
            // The name is used for network namespaces and interface names, and an interface name is
            // at most 15 bytes
            ensure!(
                !name.is_empty()
                    && name.len() <= 8
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "name `{name}` must be 1-8 lower-case letters, digits or `-`"
            );
            ensure!(names.insert(name.clone()), "duplicate name `{name}`");
        }
        for node in &self.nodes {
            if let Some(router) = &node.behind {
                ensure!(
                    self.routers.iter().any(|r| &r.name == router),
                    "node `{}` is behind unknown router `{router}`",
                    node.name
                );
            }
            for role in &node.roles {
                ensure!(
                    role == "relay",
                    "node `{}`: unknown role `{role}`",
                    node.name
                );
            }
            if let Some(edge) = &node.edge {
                ensure!(
                    !edge.containers.is_empty(),
                    "node `{}`: edge needs at least one container prefix",
                    node.name
                );
                // Lab A uses this address to build the "container"
                ensure!(
                    node.ssh.is_some()
                        || (edge.containers.len() == 1
                            && edge.containers[0].is_ipv4()
                            && edge.containers[0].prefix_len() == 32),
                    "node `{}`: in the namespace lab, edge.containers is the container's single IPv4 /32",
                    node.name
                );
            }
        }
        for node in &self.nodes {
            if let Some(service) = &node.service {
                ensure!(
                    node.routes
                        .contains(&IpPrefix::host(service.address.into())),
                    "node `{}`: the service address must be one of its routes",
                    node.name
                );
            }
        }
        for allow in &self.allows {
            for selector in allow.from.iter().chain(&allow.to) {
                let (name, suffix) = selector
                    .split_once('.')
                    .map_or((selector.as_str(), ""), |(n, s)| (n, s));
                let node = self
                    .node(name)
                    .with_context(|| format!("allow names unknown node `{name}`"))?;
                ensure!(
                    match suffix {
                        "" => true,
                        "edge" => node.edge.is_some(),
                        "routes" => !node.routes.is_empty(),
                        _ => false,
                    },
                    "allow names `{selector}`, which `{name}` does not have"
                );
            }
            ensure!(
                !allow.from.is_empty() && !allow.to.is_empty(),
                "allow needs `from` and `to`"
            );
            for port in &allow.ports {
                parse_ports(port)?;
            }
        }
        for link in &self.links {
            for peer in &link.peers {
                ensure!(
                    self.nodes.iter().any(|n| &n.name == peer),
                    "link names unknown node `{peer}`"
                );
            }
            for candidate in &link.candidates {
                match crate::material::relay_of(candidate) {
                    None if candidate == "direct" || candidate == "direct6" => {}
                    // Hole punching: both ends are dial-only (design/mesh.md section 6.1)
                    None if candidate == "punch" => ensure!(
                        link.peers
                            .iter()
                            .all(|p| self.nodes.iter().any(|n| &n.name == p
                                && n.reachability == nett_mesh::config::Reachability::DialOnly)),
                        "candidate `punch` needs both peers to be dial-only"
                    ),
                    Some((relay, _)) => ensure!(
                        self.nodes.iter().any(|n| n.name == relay
                            && n.behind.is_none()
                            && n.roles.iter().any(|r| r == "relay")),
                        "candidate `{candidate}` names no public node with the relay role"
                    ),
                    None => bail!("candidate `{candidate}` is not supported yet"),
                }
            }
        }
        Ok(())
    }

    pub fn node(&self, name: &str) -> Option<&Node> {
        self.nodes.iter().find(|n| n.name == name)
    }

    /// The node's index in the topology, starting at 1; used to allocate addresses.
    pub fn index(&self, name: &str) -> Option<u8> {
        self.nodes
            .iter()
            .position(|n| n.name == name)
            .and_then(|i| u8::try_from(i + 1).ok())
    }
}
