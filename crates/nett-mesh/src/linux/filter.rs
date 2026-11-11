//! 访问控制与 Edge 的 nftables 规则（design/mesh.md 第 12 节，ADR 0015），经 netlink 安装（硬性规则 1）。
//!
//! 两张表，各自在一个事务中整表替换，替换要么完整生效、要么保持原状：
//! - `nett_access`：从组网接口进入、新建连接的过滤。挂在 `prerouting`，优先级在 Docker 的目的地址转换
//!   （-100）之前，发往本机、发往 Docker 发布端口和需要转发的流量都经过它；
//! - `nett_edge`：Edge 的源地址转换挂在 `postrouting`，优先级在 Docker 的源地址伪装（100）之前；本机输出与
//!   转发两个方向上丢弃使用 Edge 专用地址、但不是来自 Edge 的包；
//! - `nett_ingress`：本机作为智能入口时，从组网接口进来、转发出去的连接只放行 Edge 来源，来源换成出接口
//!   上的地址；其他来源的转发丢弃（design/mesh.md 第 10 节）。

use std::net::IpAddr;

use nett_core::prefix::IpPrefix;
use nett_trust::payload::{PortRange, Protocol};
use rustix::net::netlink::NETFILTER;

use super::netlink::{Message, NLM_F_ACK, NLM_F_CREATE, NlError, Socket};
use super::nft::{
    NF_ACCEPT, NF_DROP, NFNL_MSG_BATCH_BEGIN, NFNL_MSG_BATCH_END, NFPROTO_INET, NFT_CMP_EQ,
    NFT_CMP_GTE, NFT_CMP_LTE, NFT_META_L4PROTO, NFT_MSG_DELTABLE, NFT_MSG_NEWCHAIN,
    NFT_MSG_NEWRULE, NFT_MSG_NEWTABLE, NFT_REG_1, NFT_REG_VERDICT, NFTA_CHAIN_HOOK,
    NFTA_CHAIN_NAME, NFTA_CHAIN_POLICY, NFTA_CHAIN_TABLE, NFTA_CHAIN_TYPE, NFTA_DATA_VALUE,
    NFTA_DATA_VERDICT, NFTA_HOOK_HOOKNUM, NFTA_HOOK_PRIORITY, NFTA_IMMEDIATE_DATA,
    NFTA_IMMEDIATE_DREG, NFTA_META_DREG, NFTA_META_KEY, NFTA_PAYLOAD_BASE, NFTA_PAYLOAD_DREG,
    NFTA_PAYLOAD_LEN, NFTA_PAYLOAD_OFFSET, NFTA_RULE_CHAIN, NFTA_RULE_EXPRESSIONS, NFTA_RULE_TABLE,
    NFTA_TABLE_NAME, NFTA_VERDICT_CODE, NLM_F_APPEND, batch, cmp, expr, load_transport, nfgen,
    nft_type,
};
use crate::access::{EdgeSpec, FilterSpec, IngressSpec, Match};
use crate::dataplane::INTERFACE_NAME;

pub(super) const ACCESS_TABLE: &str = "nett_access";
pub(super) const EDGE_TABLE: &str = "nett_edge";
pub(super) const INGRESS_TABLE: &str = "nett_ingress";
/// 源地址转换的标准优先级（`srcnat`）。
const SRCNAT_PRIORITY: i32 = 100;

const NF_INET_PRE_ROUTING: u32 = 0;
const NF_INET_FORWARD: u32 = 2;
const NF_INET_LOCAL_OUT: u32 = 3;
const NF_INET_POST_ROUTING: u32 = 4;
/// 在连接跟踪（-200）之后、Docker 的目的地址转换（-100）之前。
const ACCESS_PRIORITY: i32 = -150;
/// 在 Docker 的源地址伪装（`srcnat`，100）之前：先换成 Edge 专用地址，Docker 的规则不再处理这条连接。
const EDGE_SNAT_PRIORITY: i32 = 90;

const NFT_CMP_NEQ: u32 = 1;
const NFT_META_IIFNAME: u32 = 6;
const NFT_META_OIFNAME: u32 = 7;
const NFT_META_NFPROTO: u32 = 15;
const NFPROTO_IPV4: u8 = 2;
const NFPROTO_IPV6: u8 = 10;
const NFT_PAYLOAD_NETWORK_HEADER: u32 = 1;
const NFTA_CT_DREG: u16 = 1;
const NFTA_CT_KEY: u16 = 2;
const NFT_CT_STATE: u32 = 0;
/// `ct state established,related`：`NF_CT_STATE_BIT(IP_CT_ESTABLISHED) | NF_CT_STATE_BIT(IP_CT_RELATED)`。
const CT_ESTABLISHED_OR_RELATED: u32 = (1 << 1) | (1 << 2);
const NFTA_BITWISE_SREG: u16 = 1;
const NFTA_BITWISE_DREG: u16 = 2;
const NFTA_BITWISE_LEN: u16 = 3;
const NFTA_BITWISE_MASK: u16 = 4;
const NFTA_BITWISE_XOR: u16 = 5;
const NFTA_NAT_TYPE: u16 = 1;
const NFTA_NAT_FAMILY: u16 = 2;
const NFTA_NAT_REG_ADDR_MIN: u16 = 3;
const NFT_NAT_SNAT: u32 = 0;
const IFNAMSIZ: usize = 16;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// 整表替换 `nett_access`：不是从组网接口进入的、已建立的连接和与它相关的包放行，之后按 `filter` 的顺序
/// 匹配，都不匹配时丢弃（ADR 0023）。
pub(crate) fn install_access(filter: &FilterSpec) -> Result<(), NlError> {
    let mut messages = replace_table(ACCESS_TABLE);
    messages.push(base_chain(
        ACCESS_TABLE,
        "in",
        NF_INET_PRE_ROUTING,
        ACCESS_PRIORITY,
        "filter",
    ));
    messages.push(rule(ACCESS_TABLE, "in", |m| {
        ifname(m, NFT_META_IIFNAME, NFT_CMP_NEQ);
        verdict(m, NF_ACCEPT);
    }));
    messages.push(rule(ACCESS_TABLE, "in", |m| {
        expr(m, "ct", |m| {
            m.attr(NFTA_CT_KEY, &NFT_CT_STATE.to_be_bytes());
            m.attr(NFTA_CT_DREG, &NFT_REG_1.to_be_bytes());
        });
        // 连接跟踪的状态以主机字节序保存
        bitwise(m, &CT_ESTABLISHED_OR_RELATED.to_ne_bytes());
        cmp(m, NFT_CMP_NEQ, &[0; 4]);
        verdict(m, NF_ACCEPT);
    }));
    for r in &filter.rules {
        messages.push(rule(ACCESS_TABLE, "in", |m| {
            ifname(m, NFT_META_IIFNAME, NFT_CMP_EQ);
            if let Some(v4) = r.matches.iter().find_map(|x| match x {
                Match::Source(p) | Match::Destination(p) => Some(p.is_ipv4()),
                Match::Port(_) => None,
            }) {
                family(m, v4);
            }
            for x in &r.matches {
                match x {
                    Match::Source(p) => address(m, *p, true),
                    Match::Destination(p) => address(m, *p, false),
                    Match::Port(range) => port(m, *range),
                }
            }
            verdict(m, if r.accept { NF_ACCEPT } else { NF_DROP });
        }));
    }
    // 链的默认策略是放行（其他接口的流量不归这张表管），组网接口上没有规则放行的新建连接在这里丢弃
    messages.push(rule(ACCESS_TABLE, "in", |m| {
        ifname(m, NFT_META_IIFNAME, NFT_CMP_EQ);
        verdict(m, NF_DROP);
    }));
    messages.push(batch(NFNL_MSG_BATCH_END));
    Socket::open(Some(NETFILTER))?.request_batch(messages)
}

/// 整表替换 `nett_edge`；`edge` 为空时删除这张表。
pub(crate) fn install_edge(edge: Option<&EdgeSpec>) -> Result<(), NlError> {
    let mut messages = replace_table(EDGE_TABLE);
    let Some(edge) = edge else {
        // `replace_table` 先建后删，表不存在时也不会报错；不再重建
        let end = messages.len() - 1;
        messages.truncate(end);
        messages.push(batch(NFNL_MSG_BATCH_END));
        return Socket::open(Some(NETFILTER))?.request_batch(messages);
    };
    messages.push(base_chain(
        EDGE_TABLE,
        "snat",
        NF_INET_POST_ROUTING,
        EDGE_SNAT_PRIORITY,
        "nat",
    ));
    let addrs = [
        IpAddr::V4(edge.addresses.ipv4),
        IpAddr::V6(edge.addresses.ipv6),
    ];
    for container in &edge.containers {
        let to = if container.is_ipv4() {
            addrs[0]
        } else {
            addrs[1]
        };
        messages.push(rule(EDGE_TABLE, "snat", |m| {
            ifname(m, NFT_META_OIFNAME, NFT_CMP_EQ);
            family(m, container.is_ipv4());
            address(m, *container, true);
            snat(m, to);
        }));
    }
    for (chain, hook) in [
        ("guard_out", NF_INET_LOCAL_OUT),
        ("guard_fwd", NF_INET_FORWARD),
    ] {
        messages.push(base_chain(EDGE_TABLE, chain, hook, 0, "filter"));
        for addr in addrs {
            messages.push(rule(EDGE_TABLE, chain, |m| {
                ifname(m, NFT_META_OIFNAME, NFT_CMP_EQ);
                family(m, addr.is_ipv4());
                address(m, IpPrefix::host(addr), true);
                verdict(m, NF_DROP);
            }));
        }
    }
    messages.push(batch(NFNL_MSG_BATCH_END));
    Socket::open(Some(NETFILTER))?.request_batch(messages)
}

/// 整表替换 `nett_ingress`；`ingress` 为空时删除这张表。
pub(crate) fn install_ingress(ingress: Option<&IngressSpec>) -> Result<(), NlError> {
    let mut messages = replace_table(INGRESS_TABLE);
    let Some(ingress) = ingress else {
        let end = messages.len() - 1;
        messages.truncate(end);
        messages.push(batch(NFNL_MSG_BATCH_END));
        return Socket::open(Some(NETFILTER))?.request_batch(messages);
    };
    messages.push(base_chain(
        INGRESS_TABLE,
        "fwd",
        NF_INET_FORWARD,
        0,
        "filter",
    ));
    for source in &ingress.edge_sources {
        messages.push(rule(INGRESS_TABLE, "fwd", |m| {
            ifname(m, NFT_META_IIFNAME, NFT_CMP_EQ);
            family(m, source.is_ipv4());
            address(m, IpPrefix::host(*source), true);
            verdict(m, NF_ACCEPT);
        }));
    }
    messages.push(rule(INGRESS_TABLE, "fwd", |m| {
        ifname(m, NFT_META_IIFNAME, NFT_CMP_EQ);
        verdict(m, NF_DROP);
    }));
    messages.push(base_chain(
        INGRESS_TABLE,
        "snat",
        NF_INET_POST_ROUTING,
        SRCNAT_PRIORITY,
        "nat",
    ));
    for source in &ingress.edge_sources {
        messages.push(rule(INGRESS_TABLE, "snat", |m| {
            ifname(m, NFT_META_IIFNAME, NFT_CMP_EQ);
            ifname(m, NFT_META_OIFNAME, NFT_CMP_NEQ);
            family(m, source.is_ipv4());
            address(m, IpPrefix::host(*source), true);
            expr(m, "masq", |_| {});
        }));
    }
    messages.push(batch(NFNL_MSG_BATCH_END));
    Socket::open(Some(NETFILTER))?.request_batch(messages)
}

/// 一个事务的开头：建表（已有时不报错）、删表、再建表。之后追加链和规则，最后是事务的结尾。
fn replace_table(table: &str) -> Vec<Message> {
    let new_table = || {
        let mut m = Message::new(nft_type(NFT_MSG_NEWTABLE), NLM_F_ACK | NLM_F_CREATE);
        m.fixed(&nfgen(NFPROTO_INET, 0));
        m.attr_str(NFTA_TABLE_NAME, table);
        m
    };
    let mut del = Message::new(nft_type(NFT_MSG_DELTABLE), NLM_F_ACK);
    del.fixed(&nfgen(NFPROTO_INET, 0));
    del.attr_str(NFTA_TABLE_NAME, table);
    vec![batch(NFNL_MSG_BATCH_BEGIN), new_table(), del, new_table()]
}

fn base_chain(table: &str, name: &str, hook: u32, priority: i32, ty: &str) -> Message {
    let mut chain = Message::new(nft_type(NFT_MSG_NEWCHAIN), NLM_F_ACK | NLM_F_CREATE);
    chain.fixed(&nfgen(NFPROTO_INET, 0));
    chain.attr_str(NFTA_CHAIN_TABLE, table);
    chain.attr_str(NFTA_CHAIN_NAME, name);
    let h = chain.begin_nested(NFTA_CHAIN_HOOK);
    chain.attr(NFTA_HOOK_HOOKNUM, &hook.to_be_bytes());
    chain.attr(NFTA_HOOK_PRIORITY, &priority.to_be_bytes());
    chain.end_nested(h);
    chain.attr(NFTA_CHAIN_POLICY, &NF_ACCEPT.to_be_bytes());
    chain.attr_str(NFTA_CHAIN_TYPE, ty);
    chain
}

fn rule(table: &str, chain: &str, build: impl FnOnce(&mut Message)) -> Message {
    let mut rule = Message::new(
        nft_type(NFT_MSG_NEWRULE),
        NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
    );
    rule.fixed(&nfgen(NFPROTO_INET, 0));
    rule.attr_str(NFTA_RULE_TABLE, table);
    rule.attr_str(NFTA_RULE_CHAIN, chain);
    let exprs = rule.begin_nested(NFTA_RULE_EXPRESSIONS);
    build(&mut rule);
    rule.end_nested(exprs);
    rule
}

fn meta(m: &mut Message, key: u32) {
    expr(m, "meta", |m| {
        m.attr(NFTA_META_KEY, &key.to_be_bytes());
        m.attr(NFTA_META_DREG, &NFT_REG_1.to_be_bytes());
    });
}

/// 进入（`iifname`）或发出（`oifname`）的接口是否为组网接口。接口名按 16 字节、以 0 补齐比较。
fn ifname(m: &mut Message, key: u32, op: u32) {
    meta(m, key);
    let mut name = [0u8; IFNAMSIZ];
    name[..INTERFACE_NAME.len()].copy_from_slice(INTERFACE_NAME.as_bytes());
    cmp(m, op, &name);
}

fn family(m: &mut Message, v4: bool) {
    meta(m, NFT_META_NFPROTO);
    cmp(
        m,
        NFT_CMP_EQ,
        &[if v4 { NFPROTO_IPV4 } else { NFPROTO_IPV6 }],
    );
}

fn bitwise(m: &mut Message, mask: &[u8]) {
    let len = u32::try_from(mask.len()).expect("mask is at most 16 bytes");
    expr(m, "bitwise", |m| {
        m.attr(NFTA_BITWISE_SREG, &NFT_REG_1.to_be_bytes());
        m.attr(NFTA_BITWISE_DREG, &NFT_REG_1.to_be_bytes());
        m.attr(NFTA_BITWISE_LEN, &len.to_be_bytes());
        let d = m.begin_nested(NFTA_BITWISE_MASK);
        m.attr(NFTA_DATA_VALUE, mask);
        m.end_nested(d);
        let d = m.begin_nested(NFTA_BITWISE_XOR);
        m.attr(NFTA_DATA_VALUE, &vec![0u8; mask.len()]);
        m.end_nested(d);
    });
}

/// 来源或目标地址落在网段内：IPv4 头的第 12、16 字节，IPv6 头的第 8、24 字节。
fn address(m: &mut Message, prefix: IpPrefix, source: bool) {
    let (offset, bytes): (u32, Vec<u8>) = match (prefix.addr(), source) {
        (IpAddr::V4(a), true) => (12, a.octets().to_vec()),
        (IpAddr::V4(a), false) => (16, a.octets().to_vec()),
        (IpAddr::V6(a), true) => (8, a.octets().to_vec()),
        (IpAddr::V6(a), false) => (24, a.octets().to_vec()),
    };
    let len = u32::try_from(bytes.len()).expect("an address is 4 or 16 bytes");
    expr(m, "payload", |m| {
        m.attr(NFTA_PAYLOAD_DREG, &NFT_REG_1.to_be_bytes());
        m.attr(NFTA_PAYLOAD_BASE, &NFT_PAYLOAD_NETWORK_HEADER.to_be_bytes());
        m.attr(NFTA_PAYLOAD_OFFSET, &offset.to_be_bytes());
        m.attr(NFTA_PAYLOAD_LEN, &len.to_be_bytes());
    });
    let full = u8::try_from(bytes.len() * 8).expect("an address is at most 128 bits");
    if prefix.prefix_len() < full {
        bitwise(m, &prefix_mask(bytes.len(), prefix.prefix_len()));
    }
    cmp(m, NFT_CMP_EQ, &bytes);
}

fn prefix_mask(len: usize, prefix_len: u8) -> Vec<u8> {
    (0..len)
        .map(|i| {
            let bits = usize::from(prefix_len).saturating_sub(i * 8).min(8);
            u8::try_from((0xff00u16 >> bits) & 0xff).expect("one byte")
        })
        .collect()
}

fn port(m: &mut Message, range: PortRange) {
    meta(m, NFT_META_L4PROTO);
    let proto = match range.protocol {
        Protocol::Tcp => IPPROTO_TCP,
        Protocol::Udp => IPPROTO_UDP,
    };
    cmp(m, NFT_CMP_EQ, &[proto]);
    load_transport(m, 2, 2);
    if range.first == range.last {
        cmp(m, NFT_CMP_EQ, &range.first.to_be_bytes());
    } else {
        cmp(m, NFT_CMP_GTE, &range.first.to_be_bytes());
        cmp(m, NFT_CMP_LTE, &range.last.to_be_bytes());
    }
}

fn verdict(m: &mut Message, code: u32) {
    expr(m, "immediate", |m| {
        m.attr(NFTA_IMMEDIATE_DREG, &NFT_REG_VERDICT.to_be_bytes());
        let data = m.begin_nested(NFTA_IMMEDIATE_DATA);
        let v = m.begin_nested(NFTA_DATA_VERDICT);
        m.attr(NFTA_VERDICT_CODE, &code.to_be_bytes());
        m.end_nested(v);
        m.end_nested(data);
    });
}

/// 把来源换成 `to`：地址先装进寄存器，再交给 `nat` 表达式。
fn snat(m: &mut Message, to: IpAddr) {
    let (family, bytes) = match to {
        IpAddr::V4(a) => (NFPROTO_IPV4, a.octets().to_vec()),
        IpAddr::V6(a) => (NFPROTO_IPV6, a.octets().to_vec()),
    };
    expr(m, "immediate", |m| {
        m.attr(NFTA_IMMEDIATE_DREG, &NFT_REG_1.to_be_bytes());
        let data = m.begin_nested(NFTA_IMMEDIATE_DATA);
        m.attr(NFTA_DATA_VALUE, &bytes);
        m.end_nested(data);
    });
    expr(m, "nat", |m| {
        m.attr(NFTA_NAT_TYPE, &NFT_NAT_SNAT.to_be_bytes());
        m.attr(NFTA_NAT_FAMILY, &u32::from(family).to_be_bytes());
        m.attr(NFTA_NAT_REG_ADDR_MIN, &NFT_REG_1.to_be_bytes());
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_masks() {
        assert_eq!(prefix_mask(4, 16), vec![0xff, 0xff, 0, 0]);
        assert_eq!(prefix_mask(4, 20), vec![0xff, 0xff, 0xf0, 0]);
        assert_eq!(prefix_mask(4, 0), vec![0, 0, 0, 0]);
        assert_eq!(
            prefix_mask(16, 48)[..7],
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]
        );
    }
}
