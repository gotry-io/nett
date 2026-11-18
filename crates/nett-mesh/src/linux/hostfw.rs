//! The system's forwarding chain on a mobile gateway (design/devices.md section 6).
//!
//! Docker, and firewalls such as ufw, set the policy of the `filter FORWARD` chain to drop. An accept in
//! nett's own table does not get past a drop in another table, so while this machine carries devices,
//! one rule at the top of that chain accepts traffic from the mesh interface back out of it. The rule is
//! written the way `iptables-nft` writes `-i nett0 -o nett0 -j ACCEPT`, so iptables, and Docker through
//! it, keep reading the chain; nett's own forwarding chain still decides which of that traffic passes.
//! It carries a comment nett finds it by, and goes when the machine stops carrying devices and with the
//! mesh interface. Other base chains on the forward hook that drop by default are reported, not changed.

use rustix::net::netlink::NETFILTER;

use super::netlink::{Message, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NlError, Socket, attrs};
use super::nft::{
    NF_ACCEPT, NF_DROP, NFNL_MSG_BATCH_BEGIN, NFNL_MSG_BATCH_END, NFT_CMP_EQ, NFT_MSG_NEWRULE,
    NFT_REG_1, NFT_REG_VERDICT, NFTA_CHAIN_HOOK, NFTA_CHAIN_NAME, NFTA_CHAIN_POLICY,
    NFTA_CHAIN_TABLE, NFTA_DATA_VERDICT, NFTA_HOOK_HOOKNUM, NFTA_IMMEDIATE_DATA,
    NFTA_IMMEDIATE_DREG, NFTA_META_DREG, NFTA_META_KEY, NFTA_RULE_CHAIN, NFTA_RULE_EXPRESSIONS,
    NFTA_RULE_TABLE, NFTA_VERDICT_CODE, batch, cmp, expr, nfgen, nft_type,
};
use crate::dataplane::INTERFACE_NAME;

const TABLE: &str = "filter";
const CHAIN: &str = "FORWARD";
const COMMENT: &str = "nett: devices through this mobile gateway";

const NFT_MSG_GETCHAIN: u16 = 4;
const NFT_MSG_GETRULE: u16 = 7;
const NFT_MSG_DELRULE: u16 = 8;
const NFTA_RULE_HANDLE: u16 = 3;
const NFTA_RULE_USERDATA: u16 = 7;
/// The comment's type in nftables' rule userdata (`NFTNL_UDATA_RULE_COMMENT`).
const UDATA_RULE_COMMENT: u8 = 0;
const NFPROTO_UNSPEC: u8 = 0;
const NFPROTO_IPV4: u8 = 2;
const NFPROTO_IPV6: u8 = 10;
const NF_INET_FORWARD: u32 = 2;
const NFT_META_IIFNAME: u32 = 6;
const NFT_META_OIFNAME: u32 = 7;
const ENOENT: i32 = 2;

/// A base chain on the forward hook.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Chain {
    family: u8,
    table: String,
    name: String,
    drops: bool,
}

/// Makes the rule present while `carry` and the chain drops by default, absent otherwise. Returns the
/// other forward chains that drop by default, as `<family> <table> <chain>`, for the problem the gateway
/// lists while it carries devices.
pub(crate) fn reconcile(carry: bool) -> Result<Vec<String>, NlError> {
    let chains = forward_chains()?;
    for family in [NFPROTO_IPV4, NFPROTO_IPV6] {
        let drops = chains
            .iter()
            .any(|c| c.family == family && c.table == TABLE && c.name == CHAIN && c.drops);
        let ours = our_rules(family)?;
        if carry && drops {
            if ours.is_empty() {
                insert(family)?;
            }
        } else {
            for handle in ours {
                delete(family, handle)?;
            }
        }
    }
    if !carry {
        return Ok(Vec::new());
    }
    Ok(chains
        .into_iter()
        .filter(|c| c.drops && !(c.table == TABLE && c.name == CHAIN))
        .filter(|c| !c.table.starts_with("nett_"))
        .map(|c| format!("{} {} {}", family_name(c.family), c.table, c.name))
        .collect())
}

/// Removes the rule from both families, with the mesh interface.
pub(crate) fn remove() -> Result<(), NlError> {
    reconcile(false).map(|_| ())
}

fn family_name(family: u8) -> &'static str {
    match family {
        NFPROTO_IPV4 => "ip",
        NFPROTO_IPV6 => "ip6",
        1 => "inet",
        _ => "other",
    }
}

fn forward_chains() -> Result<Vec<Chain>, NlError> {
    let mut m = Message::new(nft_type(NFT_MSG_GETCHAIN), NLM_F_DUMP);
    m.fixed(&nfgen(NFPROTO_UNSPEC, 0));
    let replies = Socket::open(Some(NETFILTER))?.request(m)?;
    let mut chains = Vec::new();
    for reply in replies {
        let Some((&family, body)) = reply.split_first() else {
            continue;
        };
        let body = body.get(3..).unwrap_or_default();
        let (mut table, mut name, mut hook, mut policy) = (None, None, None, None);
        for attr in attrs(body) {
            let (ty, payload) = attr?;
            match ty {
                NFTA_CHAIN_TABLE => table = Some(text(payload)),
                NFTA_CHAIN_NAME => name = Some(text(payload)),
                NFTA_CHAIN_POLICY => policy = be_u32(payload),
                NFTA_CHAIN_HOOK => {
                    for inner in attrs(payload) {
                        let (ty, payload) = inner?;
                        if ty == NFTA_HOOK_HOOKNUM {
                            hook = be_u32(payload);
                        }
                    }
                }
                _ => {}
            }
        }
        if let (Some(table), Some(name), Some(NF_INET_FORWARD)) = (table, name, hook) {
            chains.push(Chain {
                family,
                table,
                name,
                drops: policy == Some(NF_DROP),
            });
        }
    }
    Ok(chains)
}

/// Handles of the rules in this family's `filter FORWARD` that carry nett's comment.
fn our_rules(family: u8) -> Result<Vec<u64>, NlError> {
    let mut m = Message::new(nft_type(NFT_MSG_GETRULE), NLM_F_DUMP);
    m.fixed(&nfgen(family, 0));
    m.attr_str(NFTA_RULE_TABLE, TABLE);
    m.attr_str(NFTA_RULE_CHAIN, CHAIN);
    let replies = match Socket::open(Some(NETFILTER))?.request(m) {
        Ok(r) => r,
        Err(e) if e.errno() == Some(ENOENT) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let comment = userdata();
    let mut handles = Vec::new();
    for reply in replies {
        let body = reply.get(4..).unwrap_or_default();
        let (mut handle, mut ours) = (None, false);
        for attr in attrs(body) {
            let (ty, payload) = attr?;
            match ty {
                NFTA_RULE_HANDLE => {
                    handle = payload.try_into().ok().map(u64::from_be_bytes);
                }
                NFTA_RULE_USERDATA => ours = payload == comment.as_slice(),
                _ => {}
            }
        }
        if let (Some(handle), true) = (handle, ours) {
            handles.push(handle);
        }
    }
    Ok(handles)
}

fn insert(family: u8) -> Result<(), NlError> {
    // Without NLM_F_APPEND the rule goes to the top of the chain
    let mut rule = Message::new(nft_type(NFT_MSG_NEWRULE), NLM_F_ACK | NLM_F_CREATE);
    rule.fixed(&nfgen(family, 0));
    rule.attr_str(NFTA_RULE_TABLE, TABLE);
    rule.attr_str(NFTA_RULE_CHAIN, CHAIN);
    let exprs = rule.begin_nested(NFTA_RULE_EXPRESSIONS);
    interface(&mut rule, NFT_META_IIFNAME);
    interface(&mut rule, NFT_META_OIFNAME);
    expr(&mut rule, "immediate", |m| {
        m.attr(NFTA_IMMEDIATE_DREG, &NFT_REG_VERDICT.to_be_bytes());
        let data = m.begin_nested(NFTA_IMMEDIATE_DATA);
        let v = m.begin_nested(NFTA_DATA_VERDICT);
        m.attr(NFTA_VERDICT_CODE, &NF_ACCEPT.to_be_bytes());
        m.end_nested(v);
        m.end_nested(data);
    });
    rule.end_nested(exprs);
    rule.attr(NFTA_RULE_USERDATA, &userdata());
    Socket::open(Some(NETFILTER))?.request_batch(vec![
        batch(NFNL_MSG_BATCH_BEGIN),
        rule,
        batch(NFNL_MSG_BATCH_END),
    ])
}

fn delete(family: u8, handle: u64) -> Result<(), NlError> {
    let mut del = Message::new(nft_type(NFT_MSG_DELRULE), NLM_F_ACK);
    del.fixed(&nfgen(family, 0));
    del.attr_str(NFTA_RULE_TABLE, TABLE);
    del.attr_str(NFTA_RULE_CHAIN, CHAIN);
    del.attr(NFTA_RULE_HANDLE, &handle.to_be_bytes());
    match Socket::open(Some(NETFILTER))?.request_batch(vec![
        batch(NFNL_MSG_BATCH_BEGIN),
        del,
        batch(NFNL_MSG_BATCH_END),
    ]) {
        Err(e) if e.errno() == Some(ENOENT) => Ok(()),
        other => other,
    }
}

/// `meta iifname` (or `oifname`) equal to the mesh interface, compared with the name and its NUL as
/// iptables-nft compares an exact interface name.
fn interface(m: &mut Message, key: u32) {
    expr(m, "meta", |m| {
        m.attr(NFTA_META_KEY, &key.to_be_bytes());
        m.attr(NFTA_META_DREG, &NFT_REG_1.to_be_bytes());
    });
    let mut name = INTERFACE_NAME.as_bytes().to_vec();
    name.push(0);
    cmp(m, NFT_CMP_EQ, &name);
}

/// The comment as nftables stores it in rule userdata: type, length, then the text with its NUL.
fn userdata() -> Vec<u8> {
    let mut out = vec![UDATA_RULE_COMMENT, 0];
    out.extend_from_slice(COMMENT.as_bytes());
    out.push(0);
    out[1] = u8::try_from(COMMENT.len() + 1).unwrap_or(u8::MAX);
    out
}

fn text(payload: &[u8]) -> String {
    String::from_utf8_lossy(payload.strip_suffix(&[0]).unwrap_or(payload)).into_owned()
}

fn be_u32(payload: &[u8]) -> Option<u32> {
    payload.try_into().ok().map(u32::from_be_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_comment_is_one_nftables_userdata_entry() {
        let data = userdata();
        assert_eq!(data[0], UDATA_RULE_COMMENT);
        assert_eq!(usize::from(data[1]), data.len() - 2);
        assert_eq!(&data[2..data.len() - 1], COMMENT.as_bytes());
        assert_eq!(data.last(), Some(&0));
    }
}
