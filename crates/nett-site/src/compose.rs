//! 按站点组成各台机器的期望状态（design/site.md 第 6 节、design/hub.md 第 4 节）：签名工具不接 Hub 时写成
//! 文件，接了 Hub 时由 Hub 用同一份逻辑组成。

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};

use nett_core::id::NodeId;
use nett_core::name::NodeName;
use nett_mesh::config::{Candidate, DesiredMesh, DesiredMeshDoc, PathDoc, Reachability};
use nett_trust::revocation::Revocation;

use crate::SiteError;
use crate::state::{Machine, State};

/// 一对需要连接的机器，按节点 ID 排序。
pub type Pair = (NodeId, NodeId);

/// 哪些机器之间建立连接：访问规则涉及的每一对，加上每个 `dial-only` 成员与全部 `public` 成员（判断 NAT
/// 类型与映射地址，也是故障时的冗余，design/mesh.md 第 6.1 节、architecture.md 第 12.3 节）。
pub fn connections(state: &State) -> BTreeSet<Pair> {
    let mut pairs = BTreeSet::new();
    let mut add = |a: &NodeId, b: &NodeId| {
        if a != b {
            pairs.insert(if a < b {
                (a.clone(), b.clone())
            } else {
                (b.clone(), a.clone())
            });
        }
    };
    for rule in state.rules.values() {
        for f in &rule.from {
            for t in &rule.to {
                add(&f.node, &t.node);
            }
        }
    }
    let public: Vec<&Machine> = state
        .machines
        .values()
        .filter(|m| m.reachability == Reachability::Public)
        .collect();
    for d in state
        .machines
        .values()
        .filter(|m| m.reachability == Reachability::DialOnly)
    {
        for p in &public {
            add(&d.node_id, &p.node_id);
        }
    }
    pairs
}

/// 本机到一个对端的候选路径（design/mesh.md 第 6 节）：对端是 `public` 时直连它的公网地址（有 IPv4、IPv6
/// 时分别一条）；两端都是 `dial-only` 时打洞；本机是 `public`、对端是 `dial-only` 时没有候选，由对端连过来
/// （WireGuard 的漫游）。
pub fn candidates(state: &State, me: &Machine, peer: &Machine) -> Vec<Candidate> {
    match (me.reachability, peer.reachability) {
        (_, Reachability::Public) => {
            let port = peer
                .listen_port(state.listen_port)
                .unwrap_or(state.listen_port);
            [peer.ipv4.map(IpAddr::V4), peer.ipv6.map(IpAddr::V6)]
                .into_iter()
                .flatten()
                .map(|ip| Candidate::Direct {
                    endpoint: SocketAddr::new(ip, port),
                })
                .collect()
        }
        (Reachability::DialOnly, Reachability::DialOnly) => vec![Candidate::Punch],
        (Reachability::Public, Reachability::DialOnly) => Vec::new(),
    }
}

/// 一台机器的期望状态。机器还没有签过的节点策略时（经 Hub 入网之前）返回 `None`。
pub fn desired(state: &State, name: &NodeName) -> Result<Option<DesiredMeshDoc>, SiteError> {
    let me = state.machine(name)?;
    if me.policy.is_none() {
        return Ok(None);
    }
    let paths: Vec<PathDoc> = connections(state)
        .into_iter()
        .filter_map(|(a, b)| {
            let other = if a == me.node_id {
                b
            } else if b == me.node_id {
                a
            } else {
                return None;
            };
            let peer = state.by_id(&other)?;
            Some(PathDoc {
                peer: other,
                peer_reachability: peer.reachability,
                candidates: candidates(state, me, peer),
            })
        })
        .collect();
    let names: BTreeMap<NodeId, NodeName> = state
        .machines
        .iter()
        .map(|(n, m)| (m.node_id.clone(), n.clone()))
        .collect();
    let doc = DesiredMeshDoc {
        node_id: me.node_id.clone(),
        reachability: me.reachability,
        listen_port: me.listen_port(state.listen_port),
        prefixes: state.prefixes,
        trust_anchors: state.trust_anchors.clone(),
        members: state
            .machines
            .values()
            .filter_map(|m| m.policy.as_ref().map(|p| p.material.clone()))
            .collect(),
        revocations: state
            .revoked
            .iter()
            .map(|r| Revocation::Node {
                node_id: r.node_id.clone(),
            })
            .collect(),
        paths,
        access_rules: state.access_rules.as_ref().map(|r| r.signed.clone()),
        advertised_routes: state
            .machines
            .values()
            .filter_map(|m| m.routes_signed.as_ref().map(|r| r.signed.clone()))
            .collect(),
        names,
    };
    // 生成的期望状态必须能被组网进程接受
    DesiredMesh::from_doc(doc.clone()).map_err(|e| {
        SiteError::invalid(format!("machine `{name}`: generated desired state: {e}"))
    })?;
    Ok(Some(doc))
}
