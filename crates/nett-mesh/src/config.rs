//! 组网进程的期望状态：期望状态 `trust` 与 `mesh` 分区中组网进程用到的部分（design/protocol.md 第 6 节）。
//!
//! 来源只负责交付文档（[`crate::source`]）；这里在边界处校验一次，之后只传递已校验的类型。
//! 签名产物在这里只解析格式，签名和准入由 [`crate::members`] 逐项验证，不因来源而跳过。

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use nett_core::id::NodeId;
use nett_core::name::NodeName;
use nett_core::transport::{CertFingerprint, MAX_TARGETS, TlsTarget, TransportConfig};
use nett_trust::admission::AdmissionMaterial;
use nett_trust::anchors::{AnchorsError, TrustAnchors, TrustAnchorsDoc};
use nett_trust::revocation::Revocation;
use nett_trust::signed::SignedPayload;
use serde::{Deserialize, Serialize};

use nett_core::prefix::IpPrefix;

use crate::probe::TUNNEL_PROBE_PORT;

/// 期望状态的文档形式。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredMeshDoc {
    pub node_id: NodeId,
    pub reachability: Reachability,
    /// WireGuard 端口。`public` 节点必须有；`dial-only` 节点不带时由系统分配（design/mesh.md 第 5.5 节）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    pub prefixes: MeshPrefixes,
    pub trust_anchors: TrustAnchorsDoc,
    pub members: Vec<AdmissionMaterial>,
    pub revocations: Vec<Revocation>,
    pub paths: Vec<PathDoc>,
    /// 签名的访问规则集（design/mesh.md 第 12 节）；没有时按默认值匹配。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_rules: Option<SignedPayload>,
    /// 智能入口宣告的网段，每份是一个签名载荷（design/mesh.md 第 10 节）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub advertised_routes: Vec<SignedPayload>,
    /// 节点名，不签名，只用于显示（design/status.md 第 5 节）。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub names: BTreeMap<NodeId, NodeName>,
}

/// 节点的网络可达性（design/architecture.md 第 6.5 节）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reachability {
    Public,
    DialOnly,
}

/// 组网网段（design/mesh.md 第 3 节）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshPrefixes {
    pub ipv4: IpPrefix,
    pub ipv6: IpPrefix,
}

/// 到一个对端的候选路径，相当于 Hub 的计算结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathDoc {
    pub peer: NodeId,
    /// 对端的可达性：据此确定这一对由谁决定路径（design/mesh.md 第 8.3 节）。
    pub peer_reachability: Reachability,
    /// 按 Hub 给出的顺序排列，初始路径取第一条。
    pub candidates: Vec<Candidate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Candidate {
    /// 公网直连：对端 WireGuard 端口的地址。
    Direct { endpoint: SocketAddr },
    /// 经中继：中继的节点 ID、中继端口的地址，以及本机与这个中继之间的探测令牌（design/mesh.md 第 5.2 节）。
    Relay {
        relay: NodeId,
        endpoint: SocketAddr,
        token: ProbeToken,
    },
    /// 经中继的 TLS 传输（design/mesh.md 第 5.3 节）：中继的 TLS 地址与证书指纹；令牌与 UDP 中继相同，
    /// 用来认证 WebSocket 连接上的第一条探测。WireGuard 中的 endpoint 是传输适配进程的回环端口。
    RelayTls {
        relay: NodeId,
        address: SocketAddr,
        fingerprint: CertFingerprint,
        token: ProbeToken,
    },
    /// 尝试打洞直连（design/mesh.md 第 6.1 节）：双方都是 `dial-only`。地址在打洞时交换，不在这里。
    Punch,
}

/// 传输适配进程的回环端口从这里起，按中继的节点 ID 排序依次分配（ADR 0013：由组网进程分配）。
pub const TLS_LOOPBACK_BASE: u16 = 41830;
const TLS_LOOPBACK_LAST: u16 = TLS_LOOPBACK_BASE + MAX_TARGETS as u16 - 1;

/// 组网进程和传输适配进程自己在本机用的端口：组网地址上的探测端口与 TLS 中继的回环端口。WireGuard 的
/// 套接字绑定本机全部地址，用了其中一个时后绑定的一方失败（design/site.md 第 4 节）。
pub fn is_reserved_port(port: u16) -> bool {
    port == TUNNEL_PROBE_PORT || (TLS_LOOPBACK_BASE..=TLS_LOOPBACK_LAST).contains(&port)
}

/// 成员与中继之间的探测令牌。`Debug` 不输出内容（硬性规则 10）。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProbeToken(#[serde(with = "nett_trust::encoding::b64_fixed")] pub [u8; 32]);

impl std::fmt::Debug for ProbeToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProbeToken(<redacted>)")
    }
}

/// 一个对端的路径配置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPathConfig {
    pub reachability: Reachability,
    pub candidates: Vec<Candidate>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("desired state is not valid: {0}")]
    Document(String),
    #[error(transparent)]
    Anchors(#[from] AnchorsError),
    #[error("listen port must not be 0; leave it out to have the system pick one")]
    ListenPort,
    #[error("a public node needs a listen port: other members dial it")]
    PublicWithoutPort,
    #[error(
        "listen port {0} is one nett itself uses on this host: {TUNNEL_PROBE_PORT} for probes on mesh \
         addresses and {TLS_LOOPBACK_BASE}-{last} for TLS relays on loopback; pick another WireGuard port",
        last = TLS_LOOPBACK_LAST
    )]
    ListenPortInUse(u16),
    #[error("mesh prefix {0} is not a private-use range of a sensible size")]
    Prefix(IpPrefix),
    #[error("paths list peer {0} more than once")]
    DuplicatePath(NodeId),
    #[error("TLS relay {0} is listed with different addresses or fingerprints")]
    TlsTargetConflict(NodeId),
    #[error("paths list more than {MAX_TARGETS} TLS relays")]
    TooManyTlsRelays,
}

/// 已校验的期望状态。
#[derive(Debug, Clone)]
pub struct DesiredMesh {
    pub node_id: NodeId,
    pub reachability: Reachability,
    pub listen_port: Option<u16>,
    pub prefixes: MeshPrefixes,
    pub anchors: TrustAnchors,
    pub members: Vec<AdmissionMaterial>,
    pub revocations: Vec<Revocation>,
    pub paths: BTreeMap<NodeId, PeerPathConfig>,
    pub access_rules: Option<SignedPayload>,
    pub advertised_routes: Vec<SignedPayload>,
    pub names: BTreeMap<NodeId, NodeName>,
    /// 传输适配进程的 TLS 目标，与 [`DesiredMesh::tls_endpoints`] 同出一处。
    tls_targets: Vec<TlsTarget>,
    tls_endpoints: BTreeMap<NodeId, SocketAddr>,
}

impl DesiredMesh {
    /// 各 TLS 中继在 WireGuard 中的 endpoint：传输适配进程为它开的回环端口。
    pub fn tls_endpoints(&self) -> &BTreeMap<NodeId, SocketAddr> {
        &self.tls_endpoints
    }

    /// 传输适配进程的 TLS 目标：回环端口与中继的 TLS 地址。
    pub fn tls_targets(&self) -> &[TlsTarget] {
        &self.tls_targets
    }

    /// 交给传输适配进程的配置：WireGuard 端口取接口实际监听的端口（可能由系统分配）。
    pub fn transport(&self, wireguard_port: u16) -> TransportConfig {
        TransportConfig {
            wireguard_port,
            targets: self.tls_targets.clone(),
        }
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, ConfigError> {
        let doc: DesiredMeshDoc =
            serde_json::from_slice(bytes).map_err(|e| ConfigError::Document(e.to_string()))?;
        Self::from_doc(doc)
    }

    pub fn from_doc(doc: DesiredMeshDoc) -> Result<Self, ConfigError> {
        match doc.listen_port {
            Some(0) => return Err(ConfigError::ListenPort),
            Some(port) if is_reserved_port(port) => {
                return Err(ConfigError::ListenPortInUse(port));
            }
            None if doc.reachability == Reachability::Public => {
                return Err(ConfigError::PublicWithoutPort);
            }
            _ => {}
        }
        for prefix in [doc.prefixes.ipv4, doc.prefixes.ipv6] {
            if !is_sensible_mesh_prefix(&prefix) {
                return Err(ConfigError::Prefix(prefix));
            }
        }
        let mut tls: BTreeMap<NodeId, (SocketAddr, CertFingerprint)> = BTreeMap::new();
        for c in doc.paths.iter().flat_map(|p| &p.candidates) {
            if let Candidate::RelayTls {
                relay,
                address,
                fingerprint,
                ..
            } = c
                && tls
                    .insert(relay.clone(), (*address, *fingerprint))
                    .is_some_and(|prev| prev != (*address, *fingerprint))
            {
                return Err(ConfigError::TlsTargetConflict(relay.clone()));
            }
        }
        if tls.len() > MAX_TARGETS {
            return Err(ConfigError::TooManyTlsRelays);
        }
        let mut tls_endpoints = BTreeMap::new();
        let mut targets = Vec::new();
        for (port, (relay, (connect, fingerprint))) in (TLS_LOOPBACK_BASE..).zip(tls) {
            let listen = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);
            tls_endpoints.insert(relay, listen);
            targets.push(TlsTarget {
                listen,
                connect,
                fingerprint,
            });
        }
        let mut paths = BTreeMap::new();
        for path in doc.paths {
            let config = PeerPathConfig {
                reachability: path.peer_reachability,
                candidates: path.candidates,
            };
            if paths.insert(path.peer.clone(), config).is_some() {
                return Err(ConfigError::DuplicatePath(path.peer));
            }
        }
        Ok(Self {
            node_id: doc.node_id,
            reachability: doc.reachability,
            listen_port: doc.listen_port,
            prefixes: doc.prefixes,
            anchors: TrustAnchors::from_doc(&doc.trust_anchors)?,
            members: doc.members,
            revocations: doc.revocations,
            paths,
            access_rules: doc.access_rules,
            advertised_routes: doc.advertised_routes,
            names: doc.names,
            tls_targets: targets,
            tls_endpoints,
        })
    }
}

/// 组网网段只能取私有地址范围，大小合理：发往组网网段的流量都进入 `nett0`，
/// 一个过大的网段（例如 `0.0.0.0/0`）会把本机的其他流量（包括连接 Hub 的流量）一起吞掉。
fn is_sensible_mesh_prefix(prefix: &IpPrefix) -> bool {
    let private: &[(&str, u8)] = if prefix.is_ipv4() {
        &[
            ("10.0.0.0/8", 30),
            ("172.16.0.0/12", 30),
            ("192.168.0.0/16", 30),
            ("100.64.0.0/10", 30),
        ]
    } else {
        // ULA；Hub 初始化时生成一个 /48
        &[("fc00::/7", 120)]
    };
    private.iter().any(|(range, max_len)| {
        let range: IpPrefix = range.parse().expect("built-in prefix is valid");
        range.covers(prefix)
            && prefix.prefix_len() <= *max_len
            && prefix.prefix_len() >= min_len(prefix.addr())
    })
}

fn min_len(addr: IpAddr) -> u8 {
    if addr.is_ipv4() { 8 } else { 48 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mesh_prefixes_must_be_private_and_sized() {
        for (s, ok) in [
            ("100.88.0.0/16", true),
            ("10.0.0.0/8", true),
            ("100.0.0.0/8", false),
            ("0.0.0.0/0", false),
            ("8.8.0.0/16", false),
            ("100.88.0.0/31", false),
            ("fd00:88::/48", true),
            ("fd00::/8", false),
            ("2001:db8::/48", false),
        ] {
            let p: IpPrefix = s.parse().expect(s);
            assert_eq!(is_sensible_mesh_prefix(&p), ok, "{s}");
        }
    }

    #[test]
    fn listen_port_avoids_the_ports_nett_uses_itself() {
        use crate::testutil::Mesh;
        let mesh = Mesh::new(&[1]);
        let with_port = |reachability, port| {
            let mut doc = mesh.desired(1, vec![]);
            doc.reachability = reachability;
            doc.listen_port = port;
            DesiredMesh::from_doc(doc).map(|d| d.listen_port)
        };
        for reachability in [Reachability::Public, Reachability::DialOnly] {
            assert_eq!(
                with_port(reachability, Some(0)).err(),
                Some(ConfigError::ListenPort)
            );
            for port in [TUNNEL_PROBE_PORT, TLS_LOOPBACK_BASE, TLS_LOOPBACK_LAST] {
                assert_eq!(
                    with_port(reachability, Some(port)).err(),
                    Some(ConfigError::ListenPortInUse(port))
                );
            }
            for port in [41820, 41822, TLS_LOOPBACK_BASE - 1, TLS_LOOPBACK_LAST + 1] {
                assert_eq!(with_port(reachability, Some(port)), Ok(Some(port)));
            }
        }
        // 没有端口：dial-only 由系统分配，public 不行（别人按端口连它）
        assert_eq!(with_port(Reachability::DialOnly, None), Ok(None));
        assert_eq!(
            with_port(Reachability::Public, None).err(),
            Some(ConfigError::PublicWithoutPort)
        );
    }

    #[test]
    fn tls_relays_get_loopback_ports_in_relay_order() {
        use crate::testutil::{Mesh, node_id};
        let tls = |relay: u8, fp: u8| Candidate::RelayTls {
            relay: node_id(relay),
            address: format!("198.51.100.{relay}:443").parse().expect("addr"),
            fingerprint: CertFingerprint([fp; 32]),
            token: ProbeToken([relay; 32]),
        };
        let mesh = Mesh::new(&[1]);
        let mut doc = mesh.desired(1, vec![]);
        doc.paths = vec![
            PathDoc {
                peer: node_id(2),
                peer_reachability: Reachability::Public,
                candidates: vec![tls(9, 1), tls(8, 2)],
            },
            PathDoc {
                peer: node_id(3),
                peer_reachability: Reachability::Public,
                candidates: vec![tls(9, 1)],
            },
        ];
        let desired = DesiredMesh::from_doc(doc.clone()).expect("valid");
        let port = |relay: u8| desired.tls_endpoints()[&node_id(relay)].port();
        assert_eq!(
            (port(8), port(9)),
            (TLS_LOOPBACK_BASE, TLS_LOOPBACK_BASE + 1)
        );
        let transport = desired.transport(51000);
        assert_eq!(transport.targets.len(), 2);
        assert_eq!(transport.wireguard_port, 51000);
        assert_eq!(transport.validate(), Ok(()));
        // 同一个中继给了两个不同的指纹
        doc.paths[1].candidates = vec![tls(9, 7)];
        assert!(matches!(
            DesiredMesh::from_doc(doc),
            Err(ConfigError::TlsTargetConflict(_))
        ));
    }
}
