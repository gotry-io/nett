//! 数据面接口：WireGuard 接口、对端、地址与路由由各平台的后端实现（ADR 0018）。
//! 核心逻辑只通过这个接口操作数据面，测试中使用替身。

use std::net::SocketAddr;

use nett_trust::keys::X25519PublicKey;

use crate::key::PrivateKey;
use crate::prefix::IpPrefix;

/// `nett0` 的 MTU 固定为 1280（design/mesh.md 第 4 节）。
pub const MESH_MTU: u32 = 1280;

/// 组网接口的名称。
pub const INTERFACE_NAME: &str = "nett0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceSpec {
    pub name: String,
    pub listen_port: u16,
    pub mtu: u32,
    /// 本机的组网地址，前缀长度取组网网段的长度：发往整个组网网段的流量都进入这个接口。
    pub addresses: Vec<InterfaceAddress>,
}

/// 接口上的一个地址及其前缀长度。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceAddress {
    pub addr: std::net::IpAddr,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSpec {
    pub public_key: X25519PublicKey,
    pub allowed_ips: Vec<IpPrefix>,
    pub endpoint: Option<SocketAddr>,
    /// 持久保活间隔（秒）；`dial-only` 成员设为 25 秒，维持 NAT 映射。
    pub persistent_keepalive: Option<u16>,
}

#[derive(Debug, thiserror::Error)]
pub enum DataPlaneError {
    #[error("{op}: {source}")]
    Os {
        op: &'static str,
        source: std::io::Error,
    },
    #[error("{op}: kernel rejected the request: {source}")]
    Kernel {
        op: &'static str,
        source: std::io::Error,
    },
    #[error("{op}: unexpected reply from the kernel: {detail}")]
    Protocol { op: &'static str, detail: String },
    #[error("interface {0} exists but is not a WireGuard interface")]
    NotWireGuard(String),
}

/// 接口上一个对端的当前状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerStat {
    pub public_key: X25519PublicKey,
    pub endpoint: Option<SocketAddr>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

pub trait DataPlane: Send {
    /// 创建或沿用组网接口，设置私钥、监听端口、MTU 和地址并启用。返回接口实际使用的公钥。
    /// 已有的对端保持不变：组网进程重启时，进行中的连接不中断。
    fn ensure_interface(
        &mut self,
        spec: &InterfaceSpec,
        private_key: &PrivateKey,
    ) -> Result<X25519PublicKey, DataPlaneError>;

    /// 让接口上的对端恰好是 `peers`：增加缺少的、更新变化的、删除多余的。`endpoint` 为空的对端保留
    /// 内核当前的 endpoint。
    fn sync_peers(&mut self, peers: &[PeerSpec]) -> Result<(), DataPlaneError>;

    /// 各对端的 endpoint 与收发字节数。
    fn peer_stats(&mut self) -> Result<Vec<PeerStat>, DataPlaneError>;

    /// 只修改一个对端的 endpoint，会话不受影响（design/mesh.md 第 4 节）。
    fn set_endpoint(
        &mut self,
        public_key: &X25519PublicKey,
        endpoint: SocketAddr,
    ) -> Result<(), DataPlaneError>;

    /// 删除对端再按 `peer` 加回：下一个数据包触发新的握手，让新中继建立索引（design/mesh.md 第 8.4 节）。
    fn rehandshake(&mut self, peer: &PeerSpec) -> Result<(), DataPlaneError>;
}
