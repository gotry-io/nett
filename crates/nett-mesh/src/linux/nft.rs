//! 经 netlink 管理 nftables（`include/uapi/linux/netfilter/nf_tables.h`），以及经 nfnetlink_log 接收
//! 规则拷贝出来的包。组网进程不调用 `nft` 命令（硬性规则 1）。
//!
//! 这里有两条链：一条把发往 WireGuard 端口、负载首字节为直连探测类型的 UDP 包的副本交给组网进程
//! （design/mesh.md 第 7.1 节），其他包只多一次规则匹配，不复制；`log` 只是拷贝，不影响连接跟踪。另一条
//! 丢弃从闲置的 TLS 回环端口进入 WireGuard 端口的包（第 5.3 节）。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use rustix::net::netlink::NETFILTER;

use super::netlink::{Message, NLM_F_ACK, NLM_F_CREATE, NlError, Socket, attrs, split_message};
use crate::probe::{DIRECT_PROBE, DIRECT_REPLY, WG_COOKIE_LEN, WG_COOKIE_REPLY};

/// 探测规则所在的表，与访问控制的规则分开，可以整表重建。
const TABLE: &str = "nett_probe";
const CHAIN: &str = "probe_in";

const NFNL_SUBSYS_ULOG: u16 = 4;
const NFNL_SUBSYS_NFTABLES: u16 = 10;
pub(super) const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
pub(super) const NFNL_MSG_BATCH_END: u16 = 0x11;
pub(super) const NFT_MSG_NEWTABLE: u16 = 0;
pub(super) const NFT_MSG_DELTABLE: u16 = 2;
pub(super) const NFT_MSG_NEWCHAIN: u16 = 3;
pub(super) const NFT_MSG_NEWRULE: u16 = 6;
const NFT_MSG_DELRULE: u16 = 8;
pub(super) const NLM_F_APPEND: u16 = 0x800;

pub(super) const NFPROTO_INET: u8 = 1;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

pub(super) const NFTA_TABLE_NAME: u16 = 1;
pub(super) const NFTA_CHAIN_TABLE: u16 = 1;
pub(super) const NFTA_CHAIN_NAME: u16 = 3;
pub(super) const NFTA_CHAIN_HOOK: u16 = 4;
pub(super) const NFTA_CHAIN_POLICY: u16 = 5;
pub(super) const NFTA_CHAIN_TYPE: u16 = 7;
pub(super) const NFTA_HOOK_HOOKNUM: u16 = 1;
pub(super) const NFTA_HOOK_PRIORITY: u16 = 2;
const NF_INET_LOCAL_IN: u32 = 1;
pub(super) const NF_ACCEPT: u32 = 1;
pub(super) const NFTA_RULE_TABLE: u16 = 1;
pub(super) const NFTA_RULE_CHAIN: u16 = 2;
pub(super) const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_LIST_ELEM: u16 = 1;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;
pub(super) const NFTA_META_DREG: u16 = 1;
pub(super) const NFTA_META_KEY: u16 = 2;
pub(super) const NFT_META_L4PROTO: u32 = 16;
const NFT_META_IIF: u32 = 4;
pub(super) const NFTA_IMMEDIATE_DREG: u16 = 1;
pub(super) const NFTA_IMMEDIATE_DATA: u16 = 2;
pub(super) const NFTA_DATA_VERDICT: u16 = 2;
pub(super) const NFTA_VERDICT_CODE: u16 = 1;
pub(super) const NFT_REG_VERDICT: u32 = 0;
pub(super) const NF_DROP: u32 = 0;
/// 网络命名空间中回环接口的编号总是 1。
const LOOPBACK_IFINDEX: u32 = 1;
const GUARD_CHAIN: &str = "tls_guard";
const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;
pub(super) const NFTA_DATA_VALUE: u16 = 1;
pub(super) const NFT_CMP_EQ: u32 = 0;
pub(super) const NFT_CMP_LTE: u32 = 3;
pub(super) const NFT_CMP_GTE: u32 = 5;
pub(super) const NFTA_PAYLOAD_DREG: u16 = 1;
pub(super) const NFTA_PAYLOAD_BASE: u16 = 2;
pub(super) const NFTA_PAYLOAD_OFFSET: u16 = 3;
pub(super) const NFTA_PAYLOAD_LEN: u16 = 4;
const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;
const NFTA_LOG_GROUP: u16 = 1;
const NFTA_LOG_SNAPLEN: u16 = 3;
pub(super) const NFT_REG_1: u32 = 1;
const IPPROTO_UDP: u8 = 17;
const ENOENT: i32 = 2;

const NFULNL_MSG_PACKET: u16 = 0;
const NFULNL_MSG_CONFIG: u16 = 1;
const NFULA_PAYLOAD: u16 = 9;
const NFULA_CFG_CMD: u16 = 1;
const NFULA_CFG_MODE: u16 = 2;
const NFULA_CFG_QTHRESH: u16 = 4;
const NFULNL_CFG_CMD_BIND: u8 = 1;
const NFULNL_COPY_PACKET: u8 = 2;

/// 拷贝的长度：IPv6 头 40 字节 + UDP 头 8 字节 + 探测 64 字节，留出余量。
const SNAPLEN: u32 = 256;
/// 接收超时：接收线程据此定期检查是否该退出。
const RECV_TIMEOUT: Duration = Duration::from_millis(500);

pub(super) fn nfgen(family: u8, res_id: u16) -> [u8; 4] {
    let id = res_id.to_be_bytes();
    [family, 0, id[0], id[1]]
}

pub(super) fn nft_type(msg: u16) -> u16 {
    (NFNL_SUBSYS_NFTABLES << 8) | msg
}

pub(super) fn batch(ty: u16) -> Message {
    let mut m = Message::new(ty, 0);
    m.fixed(&nfgen(0, NFNL_SUBSYS_NFTABLES));
    m
}

/// 一个表达式：名称加数据（嵌套属性）。
pub(super) fn expr(m: &mut Message, name: &str, data: impl FnOnce(&mut Message)) {
    let elem = m.begin_nested(NFTA_LIST_ELEM);
    m.attr_str(NFTA_EXPR_NAME, name);
    let d = m.begin_nested(NFTA_EXPR_DATA);
    data(m);
    m.end_nested(d);
    m.end_nested(elem);
}

pub(super) fn cmp(m: &mut Message, op: u32, value: &[u8]) {
    expr(m, "cmp", |m| {
        m.attr(NFTA_CMP_SREG, &NFT_REG_1.to_be_bytes());
        m.attr(NFTA_CMP_OP, &op.to_be_bytes());
        let data = m.begin_nested(NFTA_CMP_DATA);
        m.attr(NFTA_DATA_VALUE, value);
        m.end_nested(data);
    });
}

pub(super) fn load_transport(m: &mut Message, offset: u32, len: u32) {
    expr(m, "payload", |m| {
        m.attr(NFTA_PAYLOAD_DREG, &NFT_REG_1.to_be_bytes());
        m.attr(
            NFTA_PAYLOAD_BASE,
            &NFT_PAYLOAD_TRANSPORT_HEADER.to_be_bytes(),
        );
        m.attr(NFTA_PAYLOAD_OFFSET, &offset.to_be_bytes());
        m.attr(NFTA_PAYLOAD_LEN, &len.to_be_bytes());
    });
}

/// 重建探测规则（IPv4 与 IPv6）：`udp dport <port> @th,64,8 0x82-0x83 log group <group>`，以及 WireGuard 的
/// cookie 应答 `udp dport <port> udp length 72 @th,64,8 3 log group <group>`（design/mesh.md 第 7.1 节）。
pub(crate) fn install_probe_copy(port: u16, group: u16) -> Result<(), NlError> {
    let mut sock = Socket::open(Some(NETFILTER))?;
    // 先删除旧表（不存在时忽略），再在一个事务中重建
    let mut del = Message::new(nft_type(NFT_MSG_DELTABLE), NLM_F_ACK);
    del.fixed(&nfgen(NFPROTO_INET, 0));
    del.attr_str(NFTA_TABLE_NAME, TABLE);
    match sock.request_batch(vec![
        batch(NFNL_MSG_BATCH_BEGIN),
        del,
        batch(NFNL_MSG_BATCH_END),
    ]) {
        Ok(()) => {}
        Err(e) if e.errno() == Some(ENOENT) => {}
        Err(e) => return Err(e),
    }

    let mut table = Message::new(nft_type(NFT_MSG_NEWTABLE), NLM_F_ACK | NLM_F_CREATE);
    table.fixed(&nfgen(NFPROTO_INET, 0));
    table.attr_str(NFTA_TABLE_NAME, TABLE);

    let mut chain = Message::new(nft_type(NFT_MSG_NEWCHAIN), NLM_F_ACK | NLM_F_CREATE);
    chain.fixed(&nfgen(NFPROTO_INET, 0));
    chain.attr_str(NFTA_CHAIN_TABLE, TABLE);
    chain.attr_str(NFTA_CHAIN_NAME, CHAIN);
    let hook = chain.begin_nested(NFTA_CHAIN_HOOK);
    chain.attr(NFTA_HOOK_HOOKNUM, &NF_INET_LOCAL_IN.to_be_bytes());
    // 优先级取值不影响结果：log 不终结规则，包照常交给后面的链和 WireGuard
    chain.attr(NFTA_HOOK_PRIORITY, &(-150i32).to_be_bytes());
    chain.end_nested(hook);
    chain.attr(NFTA_CHAIN_POLICY, &NF_ACCEPT.to_be_bytes());
    chain.attr_str(NFTA_CHAIN_TYPE, "filter");

    // UDP 头 8 字节之后的第一个字节是消息类型
    let probes = copy_rule(port, group, |rule| {
        load_transport(rule, 8, 1);
        cmp(rule, NFT_CMP_GTE, &[DIRECT_PROBE]);
        cmp(rule, NFT_CMP_LTE, &[DIRECT_REPLY]);
    });
    let udp_len = u16::try_from(8 + WG_COOKIE_LEN).expect("cookie reply fits in a UDP datagram");
    let cookies = copy_rule(port, group, |rule| {
        load_transport(rule, 4, 2);
        cmp(rule, NFT_CMP_EQ, &udp_len.to_be_bytes());
        load_transport(rule, 8, 1);
        cmp(rule, NFT_CMP_EQ, &[WG_COOKIE_REPLY]);
    });

    sock.request_batch(vec![
        batch(NFNL_MSG_BATCH_BEGIN),
        table,
        chain,
        probes,
        cookies,
        batch(NFNL_MSG_BATCH_END),
    ])
}

/// 发往 WireGuard 端口、再满足 `matches` 的 UDP 包，副本交给日志组 `group`。
fn copy_rule(port: u16, group: u16, matches: impl FnOnce(&mut Message)) -> Message {
    let mut rule = Message::new(
        nft_type(NFT_MSG_NEWRULE),
        NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
    );
    rule.fixed(&nfgen(NFPROTO_INET, 0));
    rule.attr_str(NFTA_RULE_TABLE, TABLE);
    rule.attr_str(NFTA_RULE_CHAIN, CHAIN);
    let exprs = rule.begin_nested(NFTA_RULE_EXPRESSIONS);
    expr(&mut rule, "meta", |m| {
        m.attr(NFTA_META_KEY, &NFT_META_L4PROTO.to_be_bytes());
        m.attr(NFTA_META_DREG, &NFT_REG_1.to_be_bytes());
    });
    cmp(&mut rule, NFT_CMP_EQ, &[IPPROTO_UDP]);
    load_transport(&mut rule, 2, 2);
    cmp(&mut rule, NFT_CMP_EQ, &port.to_be_bytes());
    matches(&mut rule);
    expr(&mut rule, "log", |m| {
        m.attr(NFTA_LOG_GROUP, &group.to_be_bytes());
        m.attr(NFTA_LOG_SNAPLEN, &SNAPLEN.to_be_bytes());
    });
    rule.end_nested(exprs);
    rule
}

/// 重建 TLS 保护链（design/mesh.md 第 5.3 节）：对每个闲置的回环端口，丢弃
/// `iif lo udp sport <端口> udp dport <WireGuard 端口>` 的包。一个事务中清空旧规则、写入新规则。
pub(crate) fn set_tls_guard(wg_port: u16, idle: &[u16]) -> Result<(), NlError> {
    let mut sock = Socket::open(Some(NETFILTER))?;
    let mut table = Message::new(nft_type(NFT_MSG_NEWTABLE), NLM_F_ACK | NLM_F_CREATE);
    table.fixed(&nfgen(NFPROTO_INET, 0));
    table.attr_str(NFTA_TABLE_NAME, TABLE);

    let mut chain = Message::new(nft_type(NFT_MSG_NEWCHAIN), NLM_F_ACK | NLM_F_CREATE);
    chain.fixed(&nfgen(NFPROTO_INET, 0));
    chain.attr_str(NFTA_CHAIN_TABLE, TABLE);
    chain.attr_str(NFTA_CHAIN_NAME, GUARD_CHAIN);
    let hook = chain.begin_nested(NFTA_CHAIN_HOOK);
    chain.attr(NFTA_HOOK_HOOKNUM, &NF_INET_LOCAL_IN.to_be_bytes());
    chain.attr(NFTA_HOOK_PRIORITY, &0i32.to_be_bytes());
    chain.end_nested(hook);
    chain.attr(NFTA_CHAIN_POLICY, &NF_ACCEPT.to_be_bytes());
    chain.attr_str(NFTA_CHAIN_TYPE, "filter");

    // 不带规则编号的删除：清空这条链
    let mut flush = Message::new(nft_type(NFT_MSG_DELRULE), NLM_F_ACK);
    flush.fixed(&nfgen(NFPROTO_INET, 0));
    flush.attr_str(NFTA_RULE_TABLE, TABLE);
    flush.attr_str(NFTA_RULE_CHAIN, GUARD_CHAIN);

    let mut messages = vec![batch(NFNL_MSG_BATCH_BEGIN), table, chain, flush];
    for port in idle {
        let mut rule = Message::new(
            nft_type(NFT_MSG_NEWRULE),
            NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
        );
        rule.fixed(&nfgen(NFPROTO_INET, 0));
        rule.attr_str(NFTA_RULE_TABLE, TABLE);
        rule.attr_str(NFTA_RULE_CHAIN, GUARD_CHAIN);
        let exprs = rule.begin_nested(NFTA_RULE_EXPRESSIONS);
        expr(&mut rule, "meta", |m| {
            m.attr(NFTA_META_KEY, &NFT_META_IIF.to_be_bytes());
            m.attr(NFTA_META_DREG, &NFT_REG_1.to_be_bytes());
        });
        // 接口编号以主机字节序比较
        cmp(&mut rule, NFT_CMP_EQ, &LOOPBACK_IFINDEX.to_ne_bytes());
        expr(&mut rule, "meta", |m| {
            m.attr(NFTA_META_KEY, &NFT_META_L4PROTO.to_be_bytes());
            m.attr(NFTA_META_DREG, &NFT_REG_1.to_be_bytes());
        });
        cmp(&mut rule, NFT_CMP_EQ, &[IPPROTO_UDP]);
        load_transport(&mut rule, 0, 2);
        cmp(&mut rule, NFT_CMP_EQ, &port.to_be_bytes());
        load_transport(&mut rule, 2, 2);
        cmp(&mut rule, NFT_CMP_EQ, &wg_port.to_be_bytes());
        expr(&mut rule, "immediate", |m| {
            m.attr(NFTA_IMMEDIATE_DREG, &NFT_REG_VERDICT.to_be_bytes());
            let data = m.begin_nested(NFTA_IMMEDIATE_DATA);
            let verdict = m.begin_nested(NFTA_DATA_VERDICT);
            m.attr(NFTA_VERDICT_CODE, &NF_DROP.to_be_bytes());
            m.end_nested(verdict);
            m.end_nested(data);
        });
        rule.end_nested(exprs);
        messages.push(rule);
    }
    messages.push(batch(NFNL_MSG_BATCH_END));
    sock.request_batch(messages)
}

/// nfnetlink_log 的订阅：接收探测规则拷贝出来的包。
pub(crate) struct ProbeLog {
    sock: Socket,
    port: u16,
}

impl ProbeLog {
    pub(crate) fn bind(group: u16, port: u16) -> Result<Self, NlError> {
        let mut sock = Socket::open(Some(NETFILTER))?;
        let mut m = Message::new((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG, NLM_F_ACK);
        m.fixed(&nfgen(0, group));
        m.attr(NFULA_CFG_CMD, &[NFULNL_CFG_CMD_BIND]);
        let mut mode = SNAPLEN.to_be_bytes().to_vec();
        mode.extend_from_slice(&[NFULNL_COPY_PACKET, 0]);
        m.attr(NFULA_CFG_MODE, &mode);
        // 每个包立即交付：默认要攒满 100 个包或等 1 秒，探测的应答会因此迟到
        m.attr(NFULA_CFG_QTHRESH, &1u32.to_be_bytes());
        sock.request(m)?;
        sock.set_recv_timeout(RECV_TIMEOUT)?;
        Ok(Self { sock, port })
    }

    /// 接收一批拷贝出来的探测：每个为（来源地址，UDP 负载）。超时返回空。
    pub(crate) fn recv(&mut self) -> Result<Vec<(SocketAddr, Vec<u8>)>, NlError> {
        let port = self.port;
        let Some(mut rest) = self.sock.recv_datagram()? else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        while !rest.is_empty() {
            let (header, payload, next) = split_message(rest)?;
            rest = next;
            if header.ty != (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET || payload.len() < 4 {
                continue;
            }
            let family = payload[0];
            for attr in attrs(&payload[4..]) {
                let (ty, packet) = attr?;
                if ty == NFULA_PAYLOAD
                    && let Some(probe) = parse_packet(family, packet, port)
                {
                    out.push(probe);
                }
            }
        }
        Ok(out)
    }
}

/// 从网络层头开始的包中取出来源地址和 UDP 负载。
fn parse_packet(family: u8, p: &[u8], port: u16) -> Option<(SocketAddr, Vec<u8>)> {
    let (src, udp) = match family {
        AF_INET if p.len() >= 20 && p[0] >> 4 == 4 && p[9] == IPPROTO_UDP => {
            let ihl = usize::from(p[0] & 0x0f) * 4;
            (
                IpAddr::V4(Ipv4Addr::new(p[12], p[13], p[14], p[15])),
                p.get(ihl..)?,
            )
        }
        AF_INET6 if p.len() >= 40 && p[0] >> 4 == 6 && p[6] == IPPROTO_UDP => {
            let src: [u8; 16] = p[8..24].try_into().ok()?;
            (IpAddr::V6(Ipv6Addr::from(src)), &p[40..])
        }
        _ => return None,
    };
    if udp.len() < 8 || u16::from_be_bytes([udp[2], udp[3]]) != port {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    let sport = u16::from_be_bytes([udp[0], udp[1]]);
    let data = udp.get(8..len.max(8))?;
    Some((SocketAddr::new(src, sport), data.to_vec()))
}
