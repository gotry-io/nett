//! 数据面接口：WireGuard 接口、对端、地址与路由由各平台的后端实现（ADR 0018）。
//! 核心逻辑只通过这个接口操作数据面，测试中使用替身。

use std::net::{SocketAddr, UdpSocket};
use std::time::SystemTime;

use nett_trust::keys::X25519PublicKey;

use crate::access::{EdgeSpec, FilterSpec, IngressSpec};
use crate::key::PrivateKey;
use nett_core::prefix::IpPrefix;

/// `nett0` 的 MTU 固定为 1280（design/mesh.md 第 4 节）。
pub const MESH_MTU: u32 = 1280;

/// 组网接口的名称。
pub const INTERFACE_NAME: &str = "nett0";

/// 系统分配的端口是保留端口（[`crate::config::is_reserved_port`]）时，最多重新分配几次。
const PORT_ATTEMPTS: usize = 8;

/// 期望状态不带端口时由系统分配 WireGuard 端口（design/mesh.md 第 5.5 节）。`assign` 取得一个端口与持有
/// 它的句柄；分到组网进程自己用的端口（Linux 的临时端口范围包含它们）时再取一次。分到保留端口的句柄留到
/// 选定之后再释放，系统不会把同一个端口再分一次。
pub(crate) fn automatic_port<T>(
    mut assign: impl FnMut() -> Result<(T, u16), DataPlaneError>,
) -> Result<(T, u16), DataPlaneError> {
    let mut reserved = Vec::new();
    for _ in 0..=PORT_ATTEMPTS {
        let (handle, port) = assign()?;
        if !crate::config::is_reserved_port(port) {
            return Ok((handle, port));
        }
        reserved.push((handle, port));
    }
    Err(DataPlaneError::Protocol {
        op: "pick a WireGuard port",
        detail: format!(
            "the system kept assigning ports nett uses itself: {:?}",
            reserved.iter().map(|(_, p)| p).collect::<Vec<_>>()
        ),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceSpec {
    pub name: String,
    /// WireGuard 端口。为空时沿用接口当前的端口，新建的接口由系统分配（design/mesh.md 第 5.5 节）。
    pub listen_port: Option<u16>,
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
    #[error("{0} is not available on this platform")]
    Unsupported(&'static str),
    #[error("data plane thread: {0}")]
    Worker(&'static str),
}

/// 以 WireGuard 端口为源端口发出直连探测（design/mesh.md 第 7.1 节），走的就是 WireGuard 自己的 NAT 映射。
pub trait DirectSend: Send {
    fn send(&self, to: SocketAddr, data: &[u8]) -> std::io::Result<()>;
}

/// WireGuard 端口上收到的直连探测与 cookie 应答的副本。
pub trait DirectRecv: Send {
    /// 一批（来源地址，UDP 负载）。最多等待半秒，超时返回空：调用方据此定期检查是否该退出。
    fn recv(&mut self) -> std::io::Result<Vec<(SocketAddr, Vec<u8>)>>;
}

/// WireGuard 端口上的直连探测：发送的一端交给引擎所在的线程，接收的一端交给接收线程。
pub struct DirectProbes {
    pub send: Box<dyn DirectSend>,
    pub recv: Box<dyn DirectRecv>,
}

/// 接口上一个对端的当前状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerStat {
    pub public_key: X25519PublicKey,
    pub endpoint: Option<SocketAddr>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// 最近一次完成握手的时刻（墙上时钟）。对端加入以来、以及 [`DataPlane::rehandshake`] 重新加入以来
    /// 还没有完成握手时为空。
    pub last_handshake: Option<SystemTime>,
}

/// 接口就绪后实际使用的公钥与 WireGuard 端口。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceState {
    pub public_key: X25519PublicKey,
    pub listen_port: u16,
}

pub trait DataPlane: Send {
    /// 内核还是用户态的 WireGuard（本机状态中显示，design/status.md 第 6 节）。
    fn kind(&self) -> crate::status::DataPlaneKind;

    /// 创建或沿用组网接口，设置私钥、监听端口、MTU 和地址并启用。已有的对端保持不变：组网进程重启时，
    /// 进行中的连接不中断。
    fn ensure_interface(
        &mut self,
        spec: &InterfaceSpec,
        private_key: &PrivateKey,
    ) -> Result<InterfaceState, DataPlaneError>;

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
    /// 之后这个对端的 [`PeerStat::last_handshake`] 为空，直到新的握手完成。
    fn rehandshake(&mut self, peer: &PeerSpec) -> Result<(), DataPlaneError>;

    /// 丢弃从这些闲置的 TLS 回环端口进入 WireGuard 端口的包（design/mesh.md 第 5.3 节），替换之前的设置。
    fn guard_tls_ports(&mut self, wg_port: u16, idle: &[u16]) -> Result<(), DataPlaneError>;

    /// 安装组网接口入方向的过滤规则（design/mesh.md 第 12 节），整体替换之前的规则：替换要么完整生效，
    /// 要么保持原状，中间不出现没有过滤的时刻。
    fn apply_filter(&mut self, filter: &FilterSpec) -> Result<(), DataPlaneError>;

    /// 设置或清除本机 Edge 的源地址转换与防冒用规则（ADR 0015），整体替换之前的设置。
    fn apply_edge(&mut self, edge: Option<&EdgeSpec>) -> Result<(), DataPlaneError>;

    /// 设置或清除本机作为智能入口的转发规则（design/mesh.md 第 10 节），整体替换之前的设置。本机宣告了网段
    /// 而转发没有开启时返回错误（规则照常安装）。
    fn apply_ingress(&mut self, ingress: Option<&IngressSpec>) -> Result<(), DataPlaneError>;

    /// 让组网接口上的路由恰好是 `routes`：其他成员宣告的网段（design/mesh.md 第 10 节）。
    fn sync_routes(&mut self, routes: &[IpPrefix]) -> Result<(), DataPlaneError>;

    /// 打开 WireGuard 端口上的直连探测收发。接口就绪之后调用一次。
    fn direct_probes(&mut self, listen_port: u16) -> Result<DirectProbes, DataPlaneError>;

    /// 绑定到本机组网地址、只收发经组网接口的套接字（隧道内探测，design/mesh.md 第 7 节）。
    fn bind_tunnel(&self, addr: SocketAddr) -> std::io::Result<UdpSocket>;

    /// 发往底层网络的双栈套接字（发往中继的探测）。macOS 上绑定承载默认路由的物理接口，不经过代理应用的
    /// TUN（design/userspace.md 第 6.2 节）。
    fn bind_underlay(&self, port: u16) -> std::io::Result<UdpSocket>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TLS_LOOPBACK_BASE;
    use crate::probe::TUNNEL_PROBE_PORT;

    #[test]
    fn automatic_port_skips_the_ports_nett_uses_itself() {
        let mut ports = vec![TUNNEL_PROBE_PORT, TLS_LOOPBACK_BASE, 50_000].into_iter();
        let mut calls = 0;
        let got = automatic_port(|| {
            calls += 1;
            Ok(((), ports.next().expect("port")))
        });
        assert_eq!(got.expect("picked").1, 50_000);
        assert_eq!(calls, 3);

        let mut calls = 0;
        let stuck = automatic_port(|| {
            calls += 1;
            Ok(((), TUNNEL_PROBE_PORT))
        });
        assert!(matches!(stuck, Err(DataPlaneError::Protocol { .. })));
        assert_eq!(calls, PORT_ATTEMPTS + 1);
    }
}
