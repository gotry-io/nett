//! 拓扑描述（design/prototype.md 第 4 节）。

use std::collections::BTreeSet;

use anyhow::{Context as _, bail, ensure};
use nett_mesh::config::Reachability;
use nett_mesh::prefix::IpPrefix;
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
    /// 每个目的地址一个随机端口（`masquerade random-fully`）。
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
