//! Lists the changes of one modification (design/site.md section 7): what is listed is what gets
//! signed: addresses and ports after selector expansion, artifact version changes, connections and
//! members added or removed; widened items are marked with `+`, narrowed items with `-`, other
//! changes with `~`.

use std::collections::{BTreeMap, BTreeSet};

use nett_core::id::NodeId;
use nett_core::name::NodeName;
use nett_mesh::config::Reachability;
use nett_trust::payload::{PortRange, Protocol, ServedPort};

use crate::compose::{Pair, connections, relay_paths};
use crate::state::{Learned, Machine, Part, Rule, Selector, State};

/// The changes between two site states, one line per item; empty when nothing changed.
pub fn describe(old: &State, new: &State) -> Vec<String> {
    let mut lines = Vec::new();
    if old.hub_upgrade_to != new.hub_upgrade_to
        && let Some(v) = new.hub_upgrade_to
    {
        lines.push(format!("~ the Hub: upgrade to {v} approved"));
    }
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
                let reach_changed = reach(old, o) != reach(new, m);
                if reach_changed {
                    lines.push(format!("~ {name}: {}", reach(new, m)));
                }
                if let Some(text) = learned_text(&o.learned, &m.learned, reach_changed) {
                    lines.push(format!("~ {name}: learned {text}"));
                }
                if o.obfs_port != m.obfs_port {
                    lines.push(match m.obfs_port {
                        Some(p) => format!(
                            "~ {name}: obfuscated UDP on port {p}, which its firewall must let in; on \
                             Linux nett moves to the userspace data plane, and its connections pause \
                             while nett restarts"
                        ),
                        None => format!(
                            "~ {name}: no obfuscated port; on Linux nett moves back to kernel \
                             WireGuard, and its connections pause while nett restarts"
                        ),
                    });
                }
                if o.relay != m.relay {
                    lines.push(match m.relay {
                        Some(r) => format!(
                            "~ {name} runs a relay: UDP {}, {}{}",
                            r.port,
                            r.tls_port
                                .map_or_else(|| "no TLS".to_owned(), |p| format!("TLS {p}")),
                            r.obfs_port
                                .map_or_else(String::new, |p| format!(", obfuscated UDP {p}"))
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
                if o.serve != m.serve {
                    lines.extend(serve_lines(new, name, &o.serve, m));
                }
                if o.upgrade_to != m.upgrade_to
                    && let Some(v) = m.upgrade_to
                {
                    lines.push(format!("~ {name}: upgrade to {v} approved"));
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
    for (name, m) in &new.machines {
        let (was, is) = (old.is_gateway(&m.node_id), new.is_gateway(&m.node_id));
        if is && !was {
            lines.push(format!("~ {name}: mobile gateway for devices"));
        } else if was && !is {
            lines.push(format!("~ {name}: no longer a mobile gateway"));
        }
    }
    for (name, d) in &new.devices {
        if old
            .devices
            .get(name)
            .is_none_or(|o| o.device_id != d.device_id)
        {
            let gateway = new
                .name_of(&d.gateway)
                .map_or_else(|| d.gateway.to_string(), ToString::to_string);
            let access = if d.limited { ", limited" } else { "" };
            lines.push(format!(
                "+ {name} (device{access}), {}, through {gateway}",
                d.credential.addresses.ipv4
            ));
        }
    }
    for (name, o) in &old.devices {
        if new
            .devices
            .get(name)
            .is_none_or(|d| d.device_id != o.device_id)
        {
            lines.push(format!(
                "- {name} (device {}): its credential is revoked",
                o.device_id
            ));
        }
    }

    let mut rules = Vec::new();
    // Devices that are not limited reach every machine through one expanded rule (design/devices.md
    // section 5): list who joins or leaves it
    let own = |s: &State| -> BTreeMap<NodeName, String> {
        s.devices
            .iter()
            .filter(|(_, d)| !d.limited)
            .map(|(n, d)| (n.clone(), d.credential.addresses.ipv4.to_string()))
            .collect()
    };
    let (own_old, own_new) = (own(old), own(new));
    for (name, address) in &own_new {
        if !own_old.contains_key(name) {
            rules.push(format!(
                "  + {name} ({address}) -> every machine and route  all ports"
            ));
        }
    }
    for (name, address) in &own_old {
        if !own_new.contains_key(name) {
            rules.push(format!(
                "  - {name} ({address}) -> every machine and route  all ports"
            ));
        }
    }
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

/// A machine's served ports changed (ADR 0028): what it serves now, and who reaches each port it
/// newly serves, since every one of them gets the trust the service gives to `127.0.0.1`.
fn serve_lines(state: &State, name: &NodeName, old: &[ServedPort], m: &Machine) -> Vec<String> {
    if m.serve.is_empty() {
        return vec![format!("- {name} serves nothing on loopback")];
    }
    let sign = if old.iter().all(|p| m.serve.contains(p)) {
        '+'
    } else {
        '~'
    };
    let mut lines = vec![format!(
        "{sign} {name} serves {} to 127.0.0.1",
        list(&m.serve)
    )];
    for port in m.serve.iter().filter(|p| !old.contains(p)) {
        lines.push(format!(
            "    {port} is reached by {}; the service sees 127.0.0.1",
            reached_by(state, m, *port)
        ));
    }
    lines
}

/// Who reaches a port a machine serves: the rules that allow it, and the devices that reach every
/// machine (design/devices.md section 5), for example `edge-vps.edge (r4) and the devices`.
pub fn reached_by(state: &State, m: &Machine, port: ServedPort) -> String {
    let covers = |ports: &[PortRange]| {
        ports.is_empty()
            || ports
                .iter()
                .any(|r| r.protocol == Protocol::Tcp && (r.first..=r.last).contains(&port.port))
    };
    let mut who: Vec<String> = state
        .rules
        .iter()
        .filter(|(_, r)| {
            covers(&r.ports)
                && r.to.iter().any(|s| {
                    matches!(s, Selector::Machine(t) if t.node == m.node_id && t.part == Part::Mesh)
                })
        })
        .map(|(id, r)| {
            let from: Vec<String> = r.from.iter().map(|s| state.selector_text(s)).collect();
            format!("{} ({id})", from.join(", "))
        })
        .collect();
    if state.devices.values().any(|d| !d.limited) {
        who.push("the devices".to_owned());
    }
    let name = state
        .name_of(&m.node_id)
        .map_or_else(|| m.node_id.to_string(), ToString::to_string);
    match who.as_slice() {
        [] => format!("nothing yet: nett site allow <from> {name} {port}"),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
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

/// What changed in what the Hub learned about a machine, the public addresses only when its
/// reachability line does not already show them; `None` when nothing else changed.
fn learned_text(old: &Learned, new: &Learned, reach_shown: bool) -> Option<String> {
    let mut parts = Vec::new();
    if !reach_shown {
        for (was, is, family) in [
            (
                old.ipv4.as_ref().map(|a| a.ip.to_string()),
                new.ipv4.as_ref().map(|a| a.ip.to_string()),
                "IPv4",
            ),
            (
                old.ipv6.as_ref().map(|a| a.ip.to_string()),
                new.ipv6.as_ref().map(|a| a.ip.to_string()),
                "IPv6",
            ),
        ] {
            if was != is {
                parts.push(is.map_or_else(
                    || format!("no public {family} address"),
                    |ip| format!("public address {ip}"),
                ));
            }
        }
    }
    if old.listen_port != new.listen_port {
        parts.push(new.listen_port.map_or_else(
            || "no WireGuard port".to_owned(),
            |p| format!("WireGuard port {p}"),
        ));
    }
    if old.lan != new.lan {
        parts.push(if new.lan.is_empty() {
            "no LAN addresses".to_owned()
        } else {
            format!("LAN {}", list(&new.lan))
        });
    }
    if old.relay_fingerprint != new.relay_fingerprint {
        parts.push(new.relay_fingerprint.as_ref().map_or_else(
            || "no relay certificate".to_owned(),
            |f| format!("relay certificate {f}"),
        ));
    }
    (!parts.is_empty()).then(|| parts.join(", "))
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
    let (node, part) = match s {
        Selector::Machine(m) => (&m.node, m.part),
        Selector::Device(d) => {
            return state.device_by_id(&d.device).map_or_else(
                || "?".to_owned(),
                |(_, d)| d.credential.addresses.ipv4.to_string(),
            );
        }
    };
    let Some(m) = state.by_id(node) else {
        return "?".to_owned();
    };
    match part {
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
/// example `punch, relay edge-vps (udp, tls)`. LAN paths are tried between every pair and are not
/// listed (design/mesh.md section 6). Hole punching starts through a tunnel over a relay (section
/// 6.1), so without a relay a pair of `dial-only` machines connects only over a LAN.
pub fn path_kind(state: &State, a: &NodeId, b: &NodeId) -> String {
    let (Some(ma), Some(mb)) = (state.by_id(a), state.by_id(b)) else {
        return "-".to_owned();
    };
    let public = |m: &Machine| m.reachability == Reachability::Public;
    let mut parts = Vec::new();
    // The end that decides reaches the other's obfuscated port
    let obfs = [(ma, mb), (mb, ma)].into_iter().any(|(me, peer)| {
        peer.obfs_port.is_some()
            && nett_mesh::prober::is_decider(
                &me.node_id,
                me.reachability,
                &peer.node_id,
                peer.reachability,
            )
    });
    if obfs {
        parts.push("direct (obfs)".to_owned());
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
            .map(|p| p.via.label())
            .collect();
        let name = state
            .name_of(relay)
            .map_or_else(|| relay.to_string(), ToString::to_string);
        parts.push(format!("relay {name} ({})", ways.join(", ")));
    }
    if parts == ["punch"] {
        return "punch only; connects over a LAN, or once a relay is added: nett site relay <machine>".to_owned();
    }
    parts.join(", ")
}

/// Machines whose desired state changed (by name): used to tell the user which files to copy over.
pub fn names_of(state: &State, ids: &BTreeSet<NodeId>) -> Vec<String> {
    ids.iter()
        .filter_map(|id| state.name_of(id).map(ToString::to_string))
        .collect()
}
