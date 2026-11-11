//! Lists the changes of one modification (design/site.md section 7): what is listed is what gets
//! signed: addresses and ports after selector expansion, artifact version changes, connections and
//! members added or removed; widened items are marked with `+`, narrowed items with `-`, other
//! changes with `~`.

use std::collections::BTreeSet;

use nett_core::id::NodeId;
use nett_mesh::config::Reachability;
use nett_trust::payload::{PortRange, Protocol};

use crate::compose::{Pair, connections, relay_paths};
use crate::state::{Machine, Part, Rule, Selector, State};

/// The changes between two site states, one line per item; empty when nothing changed.
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
                if o.relay != m.relay {
                    lines.push(match m.relay {
                        Some(r) => format!(
                            "~ {name} runs a relay: UDP {}, {}",
                            r.port,
                            r.tls_port
                                .map_or_else(|| "no TLS".to_owned(), |p| format!("TLS {p}"))
                        ),
                        None => format!("~ {name} stops its relay"),
                    });
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
    let changed: Vec<&Pair> = after
        .intersection(&before)
        .filter(|(a, b)| path_kind(old, a, b) != path_kind(new, a, b))
        .collect();
    if !added.is_empty() || !removed.is_empty() || !changed.is_empty() {
        lines.push("Connections:".to_owned());
        for (a, b) in added {
            lines.push(format!(
                "  + {}  {}",
                pair_text(new, a, b),
                path_kind(new, a, b)
            ));
        }
        for (a, b) in changed {
            lines.push(format!(
                "  ~ {}  {}",
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

/// The kinds of path between a pair of machines (design/site.md section 6): direct when either end
/// is `public`, hole punching when both ends are `dial-only`, and the relays it goes through, for
/// example `punch, relay edge-vps (udp, tls)`. Only hole punching may not connect.
pub fn path_kind(state: &State, a: &NodeId, b: &NodeId) -> String {
    let (Some(ma), Some(mb)) = (state.by_id(a), state.by_id(b)) else {
        return "-".to_owned();
    };
    let public = |m: &Machine| m.reachability == Reachability::Public;
    let mut parts = Vec::new();
    if crate::compose::candidates(state, ma, mb)
        .iter()
        .any(|c| matches!(c, nett_mesh::config::Candidate::Lan { .. }))
    {
        parts.push("lan".to_owned());
    }
    parts.push(if public(ma) || public(mb) {
        "direct".to_owned()
    } else {
        "punch".to_owned()
    });
    let paths = relay_paths(state, ma, mb);
    let mut relays: Vec<&NodeId> = Vec::new();
    for p in &paths {
        if !relays.contains(&&p.relay.node_id) {
            relays.push(&p.relay.node_id);
        }
    }
    for relay in relays {
        let ways: Vec<&str> = paths
            .iter()
            .filter(|p| &p.relay.node_id == relay)
            .map(|p| if p.tls.is_some() { "tls" } else { "udp" })
            .collect();
        let name = state
            .name_of(relay)
            .map_or_else(|| relay.to_string(), ToString::to_string);
        parts.push(format!("relay {name} ({})", ways.join(", ")));
    }
    if parts == ["punch"] {
        return "punch only; may not connect".to_owned();
    }
    parts.join(", ")
}

/// Machines whose desired state changed (by name): used to tell the user which files to copy over.
pub fn names_of(state: &State, ids: &BTreeSet<NodeId>) -> Vec<String> {
    ids.iter()
        .filter_map(|id| state.name_of(id).map(ToString::to_string))
        .collect()
}
