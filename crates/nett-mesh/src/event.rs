//! 组网进程上报的事件。每个事件同时写入日志；实验构建另写一份 JSON 行供 `nett-lab` 采集。

use nett_core::id::NodeId;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// 期望状态整份被拒绝，继续使用上一份。
    ConfigRejected { reason: String },
    /// 本机不在已准入的成员中，组网接口不启用。
    SelfNotAdmitted { node_id: NodeId },
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
    MemberRemoved { node_id: NodeId },
    /// WireGuard 对端已与已准入的成员一致。
    PeersApplied { peers: usize },
    /// 数据面操作失败，保持现状并在下一份期望状态时重试。
    DataPlaneFailed { reason: String },
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
        Event::DataPlaneFailed { reason } => tracing::warn!(%reason, "data plane update failed"),
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
