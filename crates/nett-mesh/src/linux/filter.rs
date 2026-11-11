//! nftables rules for access control and the Edge (design/mesh.md section 12, ADR 0015), installed through
//! netlink (hard rule 1).
//!
//! Two tables, each replaced as a whole in one transaction; the replacement either takes full effect or
//! leaves things as they were:
//! - `nett_access`: filtering of new connections entering from the mesh interface. Hooked at
//!   `prerouting`, with priority before Docker's destination NAT (-100); traffic to this machine, to
//!   Docker published ports, and traffic that needs forwarding all pass through it;
//! - `nett_edge`: the Edge's source NAT is hooked at `postrouting`, with priority before Docker's source
//!   masquerading (100); in both the local output and forwarding directions it drops packets that use
//!   the Edge address but do not come from the Edge;
//! - `nett_ingress`: when this machine is a smart gateway, connections coming in from the mesh interface
//!   and forwarded out allow only Edge sources, with the source replaced by the address on the outgoing
//!   interface; forwarding from other sources is dropped (design/mesh.md section 10).

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
/// Standard priority of source NAT (`srcnat`).
const SRCNAT_PRIORITY: i32 = 100;

const NF_INET_PRE_ROUTING: u32 = 0;
const NF_INET_FORWARD: u32 = 2;
const NF_INET_LOCAL_OUT: u32 = 3;
const NF_INET_POST_ROUTING: u32 = 4;
/// After connection tracking (-200) and before Docker's destination NAT (-100).
const ACCESS_PRIORITY: i32 = -150;
/// Before Docker's source masquerading (`srcnat`, 100): first replace with the Edge address, so Docker's
/// rules no longer handle this connection.
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
/// `ct state established,related`: `NF_CT_STATE_BIT(IP_CT_ESTABLISHED) | NF_CT_STATE_BIT(IP_CT_RELATED)`.
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

/// Replaces `nett_access` as a whole: established connections not entering from the mesh interface, and
/// related packets, are allowed; after that, matched in the order of `filter`, and dropped when none
/// match (ADR 0023).
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
        // The connection tracking state is stored in host byte order
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
    // The chain's default policy is accept (traffic on other interfaces is not this table's business); new
    // connections on the mesh interface that no rule allows are dropped here
    messages.push(rule(ACCESS_TABLE, "in", |m| {
        ifname(m, NFT_META_IIFNAME, NFT_CMP_EQ);
        verdict(m, NF_DROP);
    }));
    messages.push(batch(NFNL_MSG_BATCH_END));
    Socket::open(Some(NETFILTER))?.request_batch(messages)
}

/// Replaces `nett_edge` as a whole; when `edge` is empty, deletes this table.
pub(crate) fn install_edge(edge: Option<&EdgeSpec>) -> Result<(), NlError> {
    let mut messages = replace_table(EDGE_TABLE);
    let Some(edge) = edge else {
        // `replace_table` creates before deleting and does not error when the table does not exist; no
        // rebuild
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

/// Replaces `nett_ingress` as a whole; when `ingress` is empty, deletes this table.
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

/// The start of a transaction: create the table (no error if it exists), delete the table, then create it
/// again. After that chains and rules are appended, and finally the end of the transaction.
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

/// Whether the incoming (`iifname`) or outgoing (`oifname`) interface is the mesh interface. The
/// interface name is compared as 16 bytes, padded with 0.
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

/// The source or destination address falls within the prefix: bytes 12 and 16 of the IPv4 header, bytes 8
/// and 24 of the IPv6 header.
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

/// Replaces the source with `to`: the address is first loaded into a register, then handed to the `nat`
/// expression.
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
