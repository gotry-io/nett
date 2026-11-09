//! 拓扑描述（design/prototype.md 第 4 节）。

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
    /// 访问规则（design/mesh.md 第 12 节），按顺序展开成一份签名的规则集。
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
    /// 所在的路由器；缺省时直接接在"公网"上。
    pub behind: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    /// 用户态数据面（design/userspace.md）：`nett mesh --userspace`。缺省用内核 WireGuard。
    #[serde(default)]
    pub userspace: bool,
    /// 实验 B（真实机器，design/prototype.md 第 5.2 节）：SSH 主机名，以及公网 IPv4（`public` 节点）与
    /// 全局 IPv6 地址。实验 A 的地址由本机的网络规划决定，不写这几项。
    pub ssh: Option<String>,
    pub ipv4: Option<std::net::Ipv4Addr>,
    pub ipv6: Option<std::net::Ipv6Addr>,
    /// 节点运行 Edge（ADR 0015）：Edge 所在容器的网段。实验 A 在这个节点背后建一个"容器"命名空间，
    /// 地址就是这里写的唯一一个 IPv4 地址（`/32`）。
    pub edge: Option<EdgeSources>,
    /// 宣告的网段（design/mesh.md 第 10 节）：节点因此带 `subnet_router` 角色。
    #[serde(default)]
    pub routes: Vec<IpPrefix>,
    /// 实验 A：在这个节点背后建一个"服务"命名空间，`address` 是服务的地址，`ingress` 是节点在服务网络中的
    /// 地址（同一个 `/24`）。
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

/// 一条放行规则：`from`、`to` 写节点名，`<节点>.edge` 表示该节点的 Edge 专用地址；`ports` 写成
/// `8686/tcp` 或 `1000-2000/udp`，为空表示所有协议和端口。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allow {
    pub from: Vec<String>,
    pub to: Vec<String>,
    #[serde(default)]
    pub ports: Vec<String>,
}

/// 解析 `8686/tcp`、`1000-2000/udp` 形式的端口范围。
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
    /// 端口保持、映射与目的地址无关（`masquerade`）。
    Cone,
    /// 每个目的地址一个随机端口（`masquerade fully-random`）。
    Symmetric,
    /// 全局 IPv6 地址，入方向只放行已建立的连接。
    Ipv6Firewall,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Link {
    pub peers: [String; 2],
    pub candidates: Vec<String>,
}

/// 拓扑的一份副本，其中 `names` 这些节点改用用户态数据面（`userspace = true`），写到 `dir` 中，返回它的路径。
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
    // 沿用原来的文件名：有的场景以它命名报告
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
            // 名称用于网络命名空间和接口名，接口名最长 15 个字节
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
                // 实验 A 用这个地址建"容器"
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
                    // 打洞：两端都是 dial-only（design/mesh.md 第 6.1 节）
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

    /// 节点在拓扑中的序号，从 1 开始；用于分配地址。
    pub fn index(&self, name: &str) -> Option<u8> {
        self.nodes
            .iter()
            .position(|n| n.name == name)
            .and_then(|i| u8::try_from(i + 1).ok())
    }
}
