//! 组网进程上报的事件。每个事件同时写入日志；实验构建另写一份 JSON 行供 `nett-lab` 采集。

use nett_core::id::NodeId;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// 期望状态整份被拒绝，继续使用上一份。
    ConfigRejected {
        reason: String,
    },
    /// 启动时期望状态文件整份被拒绝，改用信任存储中最近一次整份接受的期望状态（design/mesh.md 第 4.2 节）。
    AcceptedStateRestored,
    /// 信任存储读写失败：照常运行，以内存中的状态验证，这期间重启可能接受旧版本的产物。
    TrustStoreFailed {
        reason: String,
    },
    /// 信任存储写入成功。
    TrustStoreSaved,
    /// 本机不在已准入的成员中，组网接口不启用。
    SelfNotAdmitted {
        node_id: NodeId,
    },
    MemberAdmitted {
        node_id: NodeId,
        policy_version: u64,
    },
    /// 成员的准入材料验证失败，不配置这个对端（design/mesh.md 第 4.1 节）。格式错误到读不出节点 ID 时为空。
    MemberRejected {
        node_id: Option<NodeId>,
        reason: String,
    },
    /// 因撤销记录删除成员。
    MemberRemoved {
        node_id: NodeId,
    },
    /// WireGuard 对端已与已准入的成员一致。
    PeersApplied {
        peers: usize,
    },
    /// 组网接口就绪，或 WireGuard 端口变了：期望状态不带端口时由系统分配（design/mesh.md 第 5.5 节）。
    InterfaceReady {
        listen_port: u16,
    },
    /// 交给传输适配进程的配置变了（design/mesh.md 第 5.3 节；实验构建写到本机文件）。
    TransportConfigChanged {
        config: nett_core::transport::TransportConfig,
    },
    /// 数据面操作失败，保持现状并在下一份期望状态时重试。
    DataPlaneFailed {
        reason: String,
    },
    /// 新版本的访问规则集已通过验证（design/mesh.md 第 12 节）。
    AccessRulesApplied {
        version: u64,
    },
    /// 访问规则集验证失败或无法展开，继续执行已生效的规则；无法展开时入方向全部拒绝。
    AccessRulesRejected {
        reason: String,
    },
    /// 一个智能入口宣告的网段已通过验证（design/mesh.md 第 10 节）。
    RoutesApplied {
        node_id: NodeId,
        version: u64,
    },
    /// 宣告的网段验证失败，继续使用已生效的那一份。读不出节点 ID 时为空。
    RoutesRejected {
        node_id: Option<NodeId>,
        reason: String,
    },
    /// 决定方切换了到某个对端的路径（design/mesh.md 第 8.2 节）。
    PathSwitched {
        node_id: NodeId,
        to: String,
        reason: crate::path::SwitchReason,
        rehandshake: bool,
    },
    /// 开始一次打洞（design/mesh.md 第 6.1 节）：双方的 NAT 类型。
    PunchStarted {
        node_id: NodeId,
        round: u32,
        nat: crate::probe::NatType,
        peer_nat: crate::probe::NatType,
        /// 要发探测的对方地址。
        targets: Vec<std::net::SocketAddr>,
    },
    /// 打洞打通：对方的地址。
    PunchSucceeded {
        node_id: NodeId,
        address: std::net::SocketAddr,
    },
    PunchFailed {
        node_id: NodeId,
        reason: String,
    },
    /// endpoint 被 WireGuard 的漫游改回了旧路径，决定方把它改回期望的路径（第 8.3 节）。
    EndpointCorrected {
        node_id: NodeId,
        from: Option<std::net::SocketAddr>,
        to: std::net::SocketAddr,
    },
}

pub trait EventSink {
    fn emit(&mut self, event: Event);
}

impl<T: EventSink + ?Sized> EventSink for Box<T> {
    fn emit(&mut self, event: Event) {
        (**self).emit(event);
    }
}

/// 只写日志。
#[derive(Debug, Default)]
pub struct LogSink;

impl EventSink for LogSink {
    fn emit(&mut self, event: Event) {
        log_event(&event);
    }
}

pub fn log_event(event: &Event) {
    match event {
        Event::ConfigRejected { reason } => tracing::warn!(%reason, "desired state rejected"),
        Event::AcceptedStateRestored => {
            tracing::warn!("using the last accepted desired state from the trust store")
        }
        Event::TrustStoreFailed { reason } => tracing::error!(%reason, "trust store unavailable"),
        Event::TrustStoreSaved => tracing::debug!("trust store saved"),
        Event::SelfNotAdmitted { node_id } => {
            tracing::error!(%node_id, "this node is not an admitted member")
        }
        Event::MemberAdmitted {
            node_id,
            policy_version,
        } => tracing::info!(%node_id, policy_version, "member admitted"),
        Event::MemberRejected { node_id, reason } => match node_id {
            Some(node_id) => tracing::warn!(%node_id, %reason, "member rejected"),
            None => tracing::warn!(%reason, "member rejected"),
        },
        Event::MemberRemoved { node_id } => tracing::info!(%node_id, "member removed"),
        Event::PeersApplied { peers } => tracing::info!(peers, "peers applied"),
        Event::InterfaceReady { listen_port } => {
            tracing::info!(listen_port, "mesh interface ready")
        }
        Event::TransportConfigChanged { config } => tracing::debug!(
            wireguard_port = config.wireguard_port,
            targets = config.targets.len(),
            "transport config changed"
        ),
        Event::DataPlaneFailed { reason } => tracing::warn!(%reason, "data plane update failed"),
        Event::AccessRulesApplied { version } => tracing::info!(version, "access rules applied"),
        Event::AccessRulesRejected { reason } => {
            tracing::warn!(%reason, "access rules rejected")
        }
        Event::RoutesApplied { node_id, version } => {
            tracing::info!(%node_id, version, "advertised routes applied")
        }
        Event::RoutesRejected { node_id, reason } => match node_id {
            Some(node_id) => tracing::warn!(%node_id, %reason, "advertised routes rejected"),
            None => tracing::warn!(%reason, "advertised routes rejected"),
        },
        Event::PathSwitched {
            node_id,
            to,
            reason,
            rehandshake,
        } => tracing::info!(%node_id, %to, ?reason, rehandshake, "path switched"),
        Event::PunchStarted {
            node_id,
            round,
            nat,
            peer_nat,
            targets,
        } => tracing::info!(%node_id, round, ?nat, ?peer_nat, ?targets, "hole punching started"),
        Event::PunchSucceeded { node_id, address } => {
            tracing::info!(%node_id, %address, "hole punched")
        }
        Event::PunchFailed { node_id, reason } => {
            tracing::info!(%node_id, %reason, "hole punching failed")
        }
        Event::EndpointCorrected { node_id, from, to } => {
            tracing::debug!(%node_id, ?from, %to, "endpoint corrected")
        }
    }
}

/// 测试与实验中收集事件。
#[derive(Debug, Default)]
pub struct VecSink(pub Vec<Event>);

impl EventSink for VecSink {
    fn emit(&mut self, event: Event) {
        self.0.push(event);
    }
}
