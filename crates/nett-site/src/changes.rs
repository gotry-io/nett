//! 列出一次修改的变化（design/site.md 第 7 节）：列出的就是要签名的内容，选择器展开后的地址和端口、产物的
//! 版本变化、增减的连接与成员；放宽的以 `+` 标出，收窄的以 `-` 标出，其余的变化以 `~` 标出。

use std::collections::BTreeSet;

use nett_core::id::NodeId;
use nett_mesh::config::Reachability;
use nett_trust::payload::{PortRange, Protocol};

use crate::compose::{Pair, connections};
use crate::state::{Machine, Part, Rule, Selector, State};

/// 两份站点状态之间的变化，每项一行；没有变化时为空。
pub fn describe(old: &State, new: &State) -> Vec<String> {
    let mut lines = Vec::new();
    for (name, m) in &new.machines {
        match old.machines.get(name) {
            None => lines.push(format!("+ {name} ({}), {}", reach(new, m), m.mesh.ipv4)),
            Some(o) if o.node_id != m.node_id => {
                lines.push(format!(
                    "+ {name} ({}), {} (a new machine)",
                    reach(new, m),
                    m.mesh.ipv4
                ));
            }
            Some(o) => {
                if reach(old, o) != reach(new, m) {
                    lines.push(format!("~ {name}: {}", reach(new, m)));
                }
                match (&o.edge, &m.edge) {
                    (None, Some(e)) => lines.push(format!(
                        "+ {name}.edge ({}) for Edge containers {}",
                        e.addresses.ipv4,
                        list(&e.containers)
                    )),
                    (Some(_), None) => lines.push(format!("- {name}.edge")),
                    (Some(a), Some(b)) if a.containers != b.containers => lines.push(format!(
                        "~ {name}.edge for Edge containers {}",
                        list(&b.containers)
                    )),
                    _ => {}
                }
                if o.routes != m.routes {
                    if m.routes.is_empty() {
                        lines.push(format!("- {name}.routes"));
                    } else {
                        let sign = if o.routes.iter().all(|r| m.routes.contains(r)) {
                            '+'
                        } else {
                            '~'
                        };
                        lines.push(format!("{sign} {name}.routes {}", list(&m.routes)));
                    }
                }
                if let (Some(a), Some(b)) = (&o.enrollment, &m.enrollment)
                    && a.public_key != b.public_key
                {
                    lines.push(format!(
                        "~ {name}: a new token to join; the earlier one stops working"
                    ));
                }
                if let (Some(a), Some(b)) = (&o.policy, &m.policy)
                    && a.version != b.version
                    && a.input == b.input
                {
                    lines.push(format!(
                        "~ {name}: node policy v{} -> v{}, signed again before it expires",
                        a.version, b.version
                    ));
                }
            }
        }
    }
    for (name, o) in &old.machines {
        if new
            .machines
            .get(name)
            .is_none_or(|m| m.node_id != o.node_id)
        {
            lines.push(format!("- {name} ({}): every member drops it", o.node_id));
        }
    }

    let mut rules = Vec::new();
    for (id, r) in &new.rules {
        match old.rules.get(id) {
            None => rules.push(format!("  + {id}  {}", rule_text(new, r))),
            Some(o) if o != r => rules.push(format!("  ~ {id}  {}", rule_text(new, r))),
            _ => {}
        }
    }
    for (id, o) in &old.rules {
        if !new.rules.contains_key(id) {
            rules.push(format!("  - {id}  {}", rule_text(old, o)));
        }
    }
    let version = |s: &State| s.access_rules.as_ref().map(|r| r.version);
    if !rules.is_empty() || version(old) != version(new) {
        lines.push(match (version(old), version(new)) {
            (Some(a), Some(b)) if a != b => format!("Access rules v{a} -> v{b}:"),
            (None, Some(b)) => format!("Access rules v{b}:"),
            _ => "Access rules:".to_owned(),
        });
        lines.extend(rules);
    }

    let (before, after) = (connections(old), connections(new));
    let added: Vec<&Pair> = after.difference(&before).collect();
    let removed: Vec<&Pair> = before.difference(&after).collect();
    if !added.is_empty() || !removed.is_empty() {
        lines.push("Connections:".to_owned());
        for (a, b) in added {
            lines.push(format!(
                "  + {}  {}",
                pair_text(new, a, b),
                path_kind(new, a, b)
            ));
        }
        for (a, b) in removed {
            lines.push(format!("  - {}", pair_text(old, a, b)));
        }
    }
    lines
}

fn reach(state: &State, m: &Machine) -> String {
    match m.reachability {
        Reachability::DialOnly => "dial-only".to_owned(),
        Reachability::Public => {
            let port = m
                .listen_port(state.listen_port)
                .unwrap_or(state.listen_port);
            let learned = |written: bool| if written { "" } else { " (learned)" };
            let addrs: Vec<String> = [
                m.public_ipv4()
                    .map(|a| format!("{a}:{port}{}", learned(m.ipv4.is_some()))),
                m.public_ipv6()
                    .map(|a| format!("[{a}]:{port}{}", learned(m.ipv6.is_some()))),
            ]
            .into_iter()
            .flatten()
            .collect();
            if addrs.is_empty() {
                format!("public, port {port}, address not known yet")
            } else {
                format!("public, {}", addrs.join(", "))
            }
        }
    }
}

fn list(items: &[impl ToString]) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// `edge-vps.edge (100.88.0.130) -> mac-app.routes (172.30.0.10/32)  8686/tcp  web app`
pub fn rule_text(state: &State, r: &Rule) -> String {
    let side = |sel: &[Selector]| {
        sel.iter()
            .map(|s| format!("{} ({})", state.selector_text(s), addresses(state, s)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut text = format!(
        "{} -> {}  {}",
        side(&r.from),
        side(&r.to),
        ports_text(&r.ports)
    );
    if let Some(note) = &r.note {
        text.push_str("  ");
        text.push_str(note);
    }
    text
}

fn addresses(state: &State, s: &Selector) -> String {
    let Some(m) = state.by_id(&s.node) else {
        return "?".to_owned();
    };
    match s.part {
        Part::Mesh => m.mesh.ipv4.to_string(),
        Part::Edge => m
            .edge
            .as_ref()
            .map_or_else(|| "?".to_owned(), |e| e.addresses.ipv4.to_string()),
        Part::Routes => list(&m.routes),
    }
}

pub fn ports_text(ports: &[PortRange]) -> String {
    if ports.is_empty() {
        return "all ports".to_owned();
    }
    ports
        .iter()
        .map(|p| {
            let proto = match p.protocol {
                Protocol::Tcp => "tcp",
                Protocol::Udp => "udp",
            };
            if p.first == p.last {
                format!("{}/{proto}", p.first)
            } else {
                format!("{}-{}/{proto}", p.first, p.last)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn pair_text(state: &State, a: &NodeId, b: &NodeId) -> String {
    let name = |id: &NodeId| {
        state
            .name_of(id)
            .map_or_else(|| id.to_string(), ToString::to_string)
    };
    let mut names = [name(a), name(b)];
    names.sort();
    format!("{} - {}", names[0], names[1])
}

/// 一对机器之间的路径种类：有一端是 `public` 时直连，两端都是 `dial-only` 时只能打洞（design/site.md
/// 第 6 节）。
pub fn path_kind(state: &State, a: &NodeId, b: &NodeId) -> &'static str {
    let public = |id: &NodeId| {
        state
            .by_id(id)
            .is_some_and(|m| m.reachability == Reachability::Public)
    };
    if public(a) || public(b) {
        "direct"
    } else {
        "punch only; may not connect"
    }
}

/// 期望状态有变化的机器（按名字）：用来告诉用户要把哪些文件拷过去。
pub fn names_of(state: &State, ids: &BTreeSet<NodeId>) -> Vec<String> {
    ids.iter()
        .filter_map(|id| state.name_of(id).map(ToString::to_string))
        .collect()
}
