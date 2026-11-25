//! `nett site`: the signing tool on the user's own computer (design/site.md). The site directory
//! (default `~/.config/nett`) holds the recovery key `recovery.pk8` (permissions `0600`, read only
//! when signing) and the site state `state.json`; every modifying command lists what will be
//! signed, signs after confirmation, and rewrites `nodes/<machine>/desired.json` for machines whose
//! desired state changed. The site model, signing and composition live in `nett-site`; this module
//! is only the command line.

use std::ffi::OsString;
use std::io::{BufRead as _, IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail, ensure};
use lexopt::ValueExt as _;
use nett_core::id::NodeId;
use nett_core::name::NodeName;
use nett_core::prefix::IpPrefix;
use nett_core::transport::CertFingerprint;
use nett_mesh::config::{DesiredMeshDoc, MAX_MEMBERS, Reachability};
use nett_site::changes::{describe, path_kind, ports_text};
use nett_site::compose::{connections, desired};
use nett_site::dir::{
    DESIRED_FILE, NODES_DIR, SiteDir, new_device_ids, new_node_id, new_obfs_padding, new_obfs_port,
    new_relay_key,
};
use nett_site::ops::{MachineChange, MachineOptions, NewDevice};
use nett_site::sign::sign;
use nett_site::state::{
    DEFAULT_RELAY_PORT, DEFAULT_RELAY_TLS_PORT, NodeKeys, RelayRole, RuleId, Selector, State,
};
use nett_trust::encoding::Timestamp;
use nett_trust::keys::X25519PublicKey;
use nett_trust::payload::{PortRange, Protocol, ServedPort};
use nett_trust::signing::EnrollmentKeyPair;

use crate::hub::SiteHub;
use crate::layout::{key_values, table};

/// The first release that knows obfuscated UDP through relays (design/obfuscation.md section 5).
const OBFS_SINCE: &str = "0.10.0";
/// The first release that knows a machine's own obfuscated port (ADR 0031).
const MACHINE_OBFS_SINCE: &str = "0.11.0";
const DEFAULT_ORIGIN: &str = "https://nett.invalid";

pub const USAGE: &str = "usage: nett site <command> [--dir <site>]

  init [--origin https://<host>]       create a site: recovery key and mesh prefixes
  link <link code>                     link the site to a Hub; printed by `nett-hub init`
  add <name> [--keys \"<mesh key> <identity key>\"] [--public] [--ipv4 <address>]
             [--ipv6 <address>] [--port <port>]
                                       add a machine. With a Hub it prints the one line that
                                       joins the new machine, and the Hub learns the address
                                       of a --public machine; without one, --keys is the line
                                       printed on it by `nett keys` or `sudo nett install`
  set <name> [--public | --dial-only] [--ipv4 <address>|none] [--ipv6 <address>|none]
             [--port <port>|default] [--obfs [--obfs-port <udp port>] | --no-obfs]
                                       change how other machines reach it. --obfs gives a
                                       public machine an obfuscated UDP port beside its
                                       WireGuard port, on a random port unless given, for
                                       networks that block WireGuard
  relay <name> [--port <udp port>] [--tls <tcp port> | --no-tls] [--fingerprint <sha256:…>]
             [--obfs [--obfs-port <udp port>] | --no-obfs]
                                       run a relay on this public Linux machine (UDP 41822 and
                                       TLS 443 unless given); --off stops it. Without a Hub, give
                                       the TLS fingerprint `nett status` shows on the machine.
                                       --obfs also offers obfuscated UDP, on a random port unless
                                       given, for networks that block WireGuard
  remove <name>                        remove a machine; rules that name it go with it
  invite <name>                        with a Hub: print the command that connects it to the Hub
                                       (a new token for a machine that has not joined yet);
                                       without: sign its node policy again, rewrite its desired state
  edge <name> <prefix>... | --none     the Edge containers on this machine
  routes <name> <prefix>... | --none   the routes this machine advertises
  serve <name> <port>/tcp... | --none  forward these ports on its mesh address to the same port
                                       on 127.0.0.1, for services that listen only there; access
                                       rules decide who reaches them, and the service sees every
                                       connection come from 127.0.0.1
  upgrade [<name>...] [--hub]          approve the release the Hub holds: for the Hub and every
                                       machine, for the machines named, or with --hub for the Hub;
                                       nothing upgrades before it is approved
  device add <name> [--gateway <machine>] [--limited] [--out <dir>]
                                       add a phone or computer that runs no nett, and write its
                                       WireGuard configuration. It joins through the
                                       public Linux machine --gateway names, which the first
                                       device needs and later ones reuse; it reaches every
                                       machine, or with --limited only what rules allow
  device remove <name>                 revoke a device; rules that name it go with it, and its
                                       gateway stops being one when no device is left on it
  devices [--json]                     list the devices
  allow <from> <to> [<ports>] [--note <text>]
                                       allow connections: <machine>, <machine>.edge,
                                       <machine>.routes or a device, several joined by commas;
                                       ports such as 22/tcp or 60000-61000/udp, all ports when
                                       left out
  rules [--json]                       list the access rules
  rules remove <id>                    remove an access rule, for example r2
  status [<name>] [--json]             list the machines and their connections; with a Hub, also
                                       whether each one is online and applied the latest change
  top                                  the machines and the links between them, live through the
                                       Hub: state, path, traffic, round-trip time and loss

Changes are listed before they are signed; --yes signs without asking (needed when not on a terminal).
With a Hub, signed changes are pushed to it and reach the machines from there.
The site directory defaults to $XDG_CONFIG_HOME/nett, or ~/.config/nett when it is not set.";

/// One modification: made on a copy of the site state.
type Change = Box<dyn FnOnce(&mut State) -> anyhow::Result<()>>;
/// What to do once the change is saved, or after a successful push (print the one line to run on the
/// new machine).
type After<'a> = &'a dyn Fn(&State) -> anyhow::Result<()>;

pub fn run(mut parser: lexopt::Parser) -> anyhow::Result<()> {
    let mut words: Vec<String> = Vec::new();
    let mut dir = None;
    let mut origin = None;
    let (mut yes, mut json, mut none) = (false, false, false);
    let mut public = None;
    let (mut ipv4, mut ipv6, mut port): (Option<String>, Option<String>, Option<String>) =
        (None, None, None);
    let (mut keys, mut note) = (None, None);
    let (mut tls, mut no_tls, mut off, mut fingerprint) = (None::<String>, false, false, None);
    let (mut obfs, mut no_obfs, mut obfs_port) = (false, false, None::<String>);
    let (mut limited, mut gateway, mut out) = (false, None::<String>, None::<PathBuf>);
    let mut hub_only = false;
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Value(v) => words.push(v.string()?),
            lexopt::Arg::Long("dir") => dir = Some(PathBuf::from(parser.value()?)),
            lexopt::Arg::Long("origin") => origin = Some(parser.value()?.string()?),
            lexopt::Arg::Long("yes") => yes = true,
            lexopt::Arg::Long("json") => json = true,
            lexopt::Arg::Long("none") => none = true,
            lexopt::Arg::Long("public") => public = Some(true),
            lexopt::Arg::Long("dial-only") => public = Some(false),
            lexopt::Arg::Long("ipv4") => ipv4 = Some(parser.value()?.string()?),
            lexopt::Arg::Long("ipv6") => ipv6 = Some(parser.value()?.string()?),
            lexopt::Arg::Long("port") => port = Some(parser.value()?.string()?),
            lexopt::Arg::Long("keys") => keys = Some(parser.value()?.string()?),
            lexopt::Arg::Long("note") => note = Some(parser.value()?.string()?),
            lexopt::Arg::Long("tls") => tls = Some(parser.value()?.string()?),
            lexopt::Arg::Long("no-tls") => no_tls = true,
            lexopt::Arg::Long("obfs") => obfs = true,
            lexopt::Arg::Long("no-obfs") => no_obfs = true,
            lexopt::Arg::Long("obfs-port") => obfs_port = Some(parser.value()?.string()?),
            lexopt::Arg::Long("off") => off = true,
            lexopt::Arg::Long("fingerprint") => fingerprint = Some(parser.value()?.string()?),
            lexopt::Arg::Long("limited") => limited = true,
            lexopt::Arg::Long("gateway") => gateway = Some(parser.value()?.string()?),
            lexopt::Arg::Long("out") => out = Some(PathBuf::from(parser.value()?)),
            lexopt::Arg::Long("hub") => hub_only = true,
            other => return Err(other.unexpected().into()),
        }
    }
    let dir = match dir {
        Some(dir) => dir,
        None => default_dir()?,
    };
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    let machine = |s: &str| -> anyhow::Result<NodeName> { Ok(s.parse()?) };
    // When linked to a Hub, every command first fetches what happened on the Hub side
    // (design/hub.md section 4)
    if !matches!(words.as_slice(), ["init"] | ["link", _])
        && let Some(hub) = SiteHub::load(&dir)?
    {
        sync(&dir, &hub, json)?;
    }
    let change: Change = match words.as_slice() {
        ["init"] => return init(&dir, origin.as_deref().unwrap_or(DEFAULT_ORIGIN)),
        ["link", code] => return crate::hub::link(&dir, code),
        ["status"] => return status(&dir, None, json),
        ["status", name] => return status(&dir, Some(&machine(name)?), json),
        ["top"] => return crate::top::site(&dir),
        ["rules"] => return rules(&dir, json),
        ["devices"] => return devices(&dir, json),
        ["device", "add", name] => {
            let gateway = gateway.as_deref().map(machine).transpose()?;
            let out = out.unwrap_or_else(|| PathBuf::from("."));
            return device_add(&dir, machine(name)?, limited, gateway, &out, yes);
        }
        ["device", "remove", name] => {
            let name = machine(name)?;
            Box::new(move |s| Ok(s.remove_device(&name)?))
        }

        ["invite", name] => return invite(&dir, &machine(name)?, yes),
        ["upgrade", names @ ..] => {
            let names = names
                .iter()
                .map(|n| machine(n))
                .collect::<anyhow::Result<Vec<_>>>()?;
            return upgrade(&dir, names, hub_only, yes);
        }
        ["add", name] => {
            let name = machine(name)?;
            let opts = MachineOptions {
                public: public.unwrap_or(false),
                ipv4: ipv4
                    .as_deref()
                    .map(str::parse)
                    .transpose()
                    .context("--ipv4")?,
                ipv6: ipv6
                    .as_deref()
                    .map(str::parse)
                    .transpose()
                    .context("--ipv6")?,
                port: port
                    .as_deref()
                    .map(str::parse)
                    .transpose()
                    .context("--port")?,
                keys: keys.as_deref().map(str::parse::<NodeKeys>).transpose()?,
            };
            let id = new_node_id()?;
            if opts.keys.is_none() {
                // Linked to a Hub: sign the node policy; the new machine joins through the Hub
                // (design/hub.md sections 3.3 and 6)
                let Some(hub) = SiteHub::load(&dir)? else {
                    bail!(
                        "--keys is needed: run `nett keys` or `sudo nett install` on the machine and \
                         pass the line it prints; with a Hub (`nett site link`), new machines join \
                         without it"
                    );
                };
                return enroll(
                    &dir,
                    &hub,
                    yes,
                    &name.clone(),
                    Box::new(move |s| Ok(s.add(name, opts, id)?)),
                );
            }
            Box::new(move |s| Ok(s.add(name, opts, id)?))
        }
        ["set", name] => {
            let name = machine(name)?;
            let change = MachineChange {
                reachability: public.map(|p| {
                    if p {
                        Reachability::Public
                    } else {
                        Reachability::DialOnly
                    }
                }),
                ipv4: ipv4
                    .map(|v| (v != "none").then(|| v.parse()).transpose())
                    .transpose()
                    .context("--ipv4")?,
                ipv6: ipv6
                    .map(|v| (v != "none").then(|| v.parse()).transpose())
                    .transpose()
                    .context("--ipv6")?,
                port: port
                    .map(|p| (p != "default").then(|| p.parse()).transpose())
                    .transpose()
                    .context("--port")?,
            };
            if no_obfs && (obfs || obfs_port.is_some()) {
                bail!("--obfs and --no-obfs do not go together");
            }
            let obfs_port: Option<u16> = obfs_port
                .as_deref()
                .map(str::parse)
                .transpose()
                .context("--obfs-port")?;
            let enabling_obfs = obfs || obfs_port.is_some();
            if enabling_obfs {
                require_release(
                    &dir,
                    MACHINE_OBFS_SINCE,
                    "a machine offers an obfuscated port",
                )?;
            }
            let (key, padding) = (new_relay_key()?, new_obfs_padding()?);
            Box::new(move |s| {
                // The port goes before a change to dial-only, and comes after one to public
                if no_obfs {
                    s.set_obfs(&name, None, key, padding)?;
                }
                s.set(&name, change)?;
                if enabling_obfs {
                    let machine = s.machine(&name)?;
                    let port = match obfs_port.or(machine.obfs_port) {
                        Some(p) => p,
                        None => new_obfs_port(|p| machine.obfs_port_free(s.listen_port, p))?,
                    };
                    s.set_obfs(&name, Some(port), key, padding)?;
                }
                Ok(())
            })
        }
        ["relay", name] => {
            let name = machine(name)?;
            if off
                && (port.is_some()
                    || tls.is_some()
                    || no_tls
                    || fingerprint.is_some()
                    || obfs
                    || no_obfs
                    || obfs_port.is_some())
            {
                bail!("--off takes no other options");
            }
            if no_tls && tls.is_some() {
                bail!("--tls and --no-tls do not go together");
            }
            if no_obfs && (obfs || obfs_port.is_some()) {
                bail!("--obfs and --no-obfs do not go together");
            }
            let obfs_port: Option<u16> = obfs_port
                .as_deref()
                .map(str::parse)
                .transpose()
                .context("--obfs-port")?;
            let enabling_obfs = obfs || obfs_port.is_some();
            if enabling_obfs {
                require_release(&dir, OBFS_SINCE, "a relay offers obfuscated UDP")?;
            }
            let padding = new_obfs_padding()?;
            let port: Option<u16> = port
                .as_deref()
                .map(str::parse)
                .transpose()
                .context("--port")?;
            let tls: Option<u16> = tls
                .as_deref()
                .map(str::parse)
                .transpose()
                .context("--tls")?;
            let fingerprint: Option<CertFingerprint> = fingerprint
                .as_deref()
                .map(str::parse)
                .transpose()
                .context("--fingerprint")?;
            let key = new_relay_key()?;
            Box::new(move |s| {
                let role = if off {
                    None
                } else {
                    // Options not given keep the relay's current value, or the default
                    let machine = s.machine(&name)?;
                    let now = machine.relay;
                    let port = port.or(now.map(|r| r.port)).unwrap_or(DEFAULT_RELAY_PORT);
                    let obfs_port = if no_obfs {
                        None
                    } else if enabling_obfs {
                        match obfs_port.or(now.and_then(|r| r.obfs_port)) {
                            Some(p) => Some(p),
                            None => Some(new_obfs_port(|p| {
                                machine.relay_obfs_port_free(s.listen_port, port, p)
                            })?),
                        }
                    } else {
                        now.and_then(|r| r.obfs_port)
                    };
                    Some(RelayRole {
                        port,
                        tls_port: if no_tls {
                            None
                        } else {
                            tls.or(now.map_or(Some(DEFAULT_RELAY_TLS_PORT), |r| r.tls_port))
                        },
                        fingerprint: fingerprint.or(now.and_then(|r| r.fingerprint)),
                        obfs_port,
                    })
                };
                Ok(s.set_relay(&name, role, key, padding)?)
            })
        }
        ["remove", name] => {
            let name = machine(name)?;
            Box::new(move |s| Ok(s.remove(&name)?))
        }
        ["edge", name, prefixes @ ..] => {
            let name = machine(name)?;
            let containers = list_or_none(prefixes, none, "edge")?;
            Box::new(move |s| Ok(s.set_edge(&name, containers)?))
        }
        ["routes", name, prefixes @ ..] => {
            let name = machine(name)?;
            let routes = list_or_none(prefixes, none, "routes")?.unwrap_or_default();
            Box::new(move |s| Ok(s.set_routes(&name, routes)?))
        }
        ["serve", name, ports @ ..] => {
            let name = machine(name)?;
            let ports = served_ports(ports, none)?;
            Box::new(move |s| Ok(s.set_serve(&name, ports)?))
        }
        ["allow", from, to, rest @ ..] if rest.len() <= 1 => {
            let split = |s: &str| s.split(',').map(str::to_owned).collect::<Vec<_>>();
            let (from, to) = (split(from), split(to));
            let ports = rest.first().map_or(Ok(Vec::new()), |p| parse_ports(p))?;
            Box::new(move |s| {
                s.allow(&from, &to, ports, note)?;
                Ok(())
            })
        }
        ["rules", "remove", id] => {
            let id: RuleId = id.parse()?;
            Box::new(move |s| Ok(s.remove_rule(id)?))
        }
        _ => bail!(USAGE),
    };
    modify(&dir, yes, &[], change, None, None)
}

/// With a Hub, stops unless the Hub and every machine run `since` or later: a release that does not
/// know a candidate kind rejects the whole desired state that carries one (design/obfuscation.md
/// section 5). Without a Hub, every machine is upgraded first.
fn require_release(dir: &Path, since: &str, what: &str) -> anyhow::Result<()> {
    let Some(hub) = SiteHub::load(dir)? else {
        return Ok(());
    };
    let older = crate::hub::older_than(&hub, since)?;
    if !older.is_empty() {
        bail!(
            "the Hub and every machine need nett {since} or later before {what}; older: {}. \
             Approve the upgrade with `nett site upgrade` first",
            older.join(", ")
        );
    }
    Ok(())
}

/// `nett site upgrade` (design/release.md section 7, ADR 0027): approves the release the Hub holds
/// for the Hub and every machine, for the named machines, or with `--hub` for the Hub alone. The
/// approval signs nothing and changes no desired state, so it is pushed without waiting for the
/// machines: the Hub may be on its way to the new version already.
fn upgrade(dir: &Path, names: Vec<NodeName>, hub_only: bool, yes: bool) -> anyhow::Result<()> {
    let Some(hub) = SiteHub::load(dir)? else {
        bail!(
            "upgrades go through the Hub; without one, run the install script and `sudo nett \
             install` on each machine"
        );
    };
    let plan = crate::hub::upgrade_plan(&hub)?;
    let release = plan.release;
    let site = SiteDir::open(dir)?;
    let old = site.load()?;
    let all = names.is_empty() && !hub_only;
    let named = if all {
        old.machines.keys().cloned().collect()
    } else {
        names
    };
    for name in &named {
        old.machine(name)?;
    }
    let behind: Vec<NodeName> = named
        .into_iter()
        .filter(|n| plan.behind(n.as_str()))
        .collect();
    let hub_too = (all || hub_only) && plan.hub_behind();
    if behind.is_empty() && !hub_too {
        outln!("Nothing to approve: they run {release} already.");
        return Ok(());
    }
    let mut new = old.clone();
    new.approve_upgrade(release, &behind, hub_too)?;
    let lines = describe(&old, &new);
    if lines.is_empty() {
        outln!(
            "The upgrade to {release} is approved already; `nett site status` shows how far it got."
        );
        return Ok(());
    }
    for line in &lines {
        outln!("{line}");
    }
    outln!("Release notes: https://github.com/gotry-io/nett/releases/tag/v{release}");
    confirm(yes, "Approve and push?")?;
    save_with_outputs(&site, &old, &new, &outputs(&new)?)?;
    crate::hub::push(&hub, &new).with_context(|| {
        "the approval is saved, but pushing it to the Hub failed; the next nett site command \
         pushes it again"
    })?;
    if hub_too {
        outln!(
            "Pushed. The Hub upgrades to {release} now, then the machines approved with it; \
             `nett site status` shows their versions."
        );
    } else {
        outln!(
            "Pushed. The approved machines upgrade to {release} now; `nett site status` shows \
             their versions."
        );
    }
    Ok(())
}

/// `nett site device add` (design/devices.md section 3): the key pair is generated here, the
/// configuration is written once the signed change is saved, and the private key is kept nowhere
/// else.
fn device_add(
    dir: &Path,
    name: NodeName,
    limited: bool,
    gateway: Option<NodeName>,
    out: &Path,
    yes: bool,
) -> anyhow::Result<()> {
    {
        let state = SiteDir::open(dir)?.load()?;
        crate::device::gateway_for(&state, gateway.as_ref())?;
    }
    let files = crate::device::Files::new(out, &name)?;
    let key = nett_mesh::key::PrivateKey::generate()?;
    let (device_id, credential_id) = new_device_ids()?;
    let new = NewDevice {
        device_id,
        credential_id,
        public_key: key.public_key(),
        limited,
        gateway,
    };
    let target = name.clone();
    let terminal = std::io::stdout().is_terminal();
    let saved = |state: &State| crate::device::export(state, &name, &key, &files, terminal);
    modify(
        dir,
        yes,
        &[],
        Box::new(move |s| {
            s.add_device(target, new)?;
            Ok(())
        }),
        Some(&saved),
        None,
    )
}

fn devices(dir: &Path, json: bool) -> anyhow::Result<()> {
    let state = SiteDir::open(dir)?.load()?;
    if json {
        let list: Vec<serde_json::Value> = state
            .devices
            .iter()
            .map(|(name, d)| {
                serde_json::json!({
                    "name": name,
                    "device_id": d.device_id,
                    "credential_id": d.credential.id,
                    "addresses": d.credential.addresses,
                    "gateway": state.name_of(&d.gateway),
                    "limited": d.limited,
                })
            })
            .collect();
        outln!("{}", serde_json::to_string_pretty(&list)?);
        return Ok(());
    }
    if state.devices.is_empty() {
        outln!("No devices. `nett site device add <name>` adds one.");
        return Ok(());
    }
    let mut rows = vec![["NAME", "ADDRESS", "GATEWAY", "ACCESS"].map(String::from)];
    for (name, d) in &state.devices {
        rows.push([
            name.to_string(),
            d.credential.addresses.ipv4.to_string(),
            state
                .name_of(&d.gateway)
                .map_or_else(|| d.gateway.to_string(), ToString::to_string),
            if d.limited {
                "rules only".to_owned()
            } else {
                "every machine".to_owned()
            },
        ]);
    }
    out!("{}", table(&rows));
    Ok(())
}

/// Fetches what happened on the Hub side and records it in the site directory (design/hub.md
/// section 4): machines that joined have their public keys and admission material recorded,
/// machines that left are removed, their rules are cleaned up and re-signed with a new version
/// (narrowing), and learned public addresses are recorded. These are only recording and narrowing,
/// so no confirmation is needed. Skipped when the Hub is unreachable: the push after the command
/// reports it.
fn sync(dir: &Path, hub: &SiteHub, json: bool) -> anyhow::Result<()> {
    // With --json the report goes to standard error, so that standard output stays JSON
    let say = |line: String| {
        if json {
            errln!("{line}");
        } else {
            outln!("{line}");
        }
    };
    let Ok(updates) = crate::hub::fetch_updates(hub) else {
        return Ok(());
    };
    let site = SiteDir::open(dir)?;
    let stored = site.load()?;
    let mut next = stored.clone();
    let applied = updates
        .apply(&mut next)
        .context("recording what happened on the Hub")?;
    if next == stored {
        return Ok(());
    }
    sign(&mut next, &site.recovery()?, Timestamp::now(), &[])?;
    say("From the Hub:".to_owned());
    for name in &applied.joined {
        say(format!("  + {name} joined through the Hub"));
    }
    for name in &applied.left {
        say(format!(
            "  - {name} left the site (`nett leave` on the machine)"
        ));
    }
    for line in describe(&stored, &next) {
        say(format!("  {line}"));
    }
    save_with_outputs(&site, &stored, &next, &outputs(&next)?)?;
    // If it cannot be delivered, the next command pushes again
    if let Err(e) = crate::hub::push(hub, &next) {
        say(format!("  (pushing this to the Hub failed: {e:#})"));
    }
    say(String::new());
    Ok(())
}

/// The desired state of every machine; if composition fails (the generated desired state is not
/// accepted by the mesh), the whole command fails.
fn outputs(state: &State) -> anyhow::Result<Vec<(NodeName, DesiredMeshDoc)>> {
    let mut outputs = Vec::new();
    for name in state.machines.keys() {
        if let Some(doc) = desired(state, name)? {
            outputs.push((name.clone(), doc));
        }
    }
    Ok(outputs)
}

/// Saves the site state, rewrites each machine's desired state file and deletes the files of
/// removed machines. Returns the machines whose files were written.
fn save_with_outputs(
    site: &SiteDir,
    old: &State,
    new: &State,
    outputs: &[(NodeName, DesiredMeshDoc)],
) -> anyhow::Result<Vec<NodeName>> {
    let written = write_outputs(site, outputs)?;
    for name in old
        .machines
        .keys()
        .filter(|n| !new.machines.contains_key(*n))
    {
        site.remove_desired(name)?;
    }
    site.save(new)?;
    Ok(written)
}

/// Lets a machine join through the Hub: after `change`, gives it a new enrollment key
/// (design/hub.md section 6), signs, pushes, then prints the one line to run on the new machine.
/// The enrollment private key appears only in this line.
fn enroll(
    dir: &Path,
    hub: &SiteHub,
    yes: bool,
    name: &NodeName,
    change: Change,
) -> anyhow::Result<()> {
    let key = EnrollmentKeyPair::generate().map_err(|e| anyhow::anyhow!("{e}"))?;
    let public_key = key.public_key();
    let expires_at = Timestamp::now().unix_seconds() + crate::hub::ENROLL_VALIDITY_SECS;
    let target = name.clone();
    let after = |state: &State| -> anyhow::Result<()> {
        let token = crate::hub::enrollment_token(hub, state, name, key.seed())?;
        crate::hub::print_enrollment(name, &token);
        Ok(())
    };
    modify(
        dir,
        yes,
        &[],
        Box::new(move |s| {
            change(s)?;
            Ok(s.await_enrollment(&target, public_key, expires_at)?)
        }),
        None,
        Some(&after),
    )
}

fn list_or_none(items: &[&str], none: bool, what: &str) -> anyhow::Result<Option<Vec<IpPrefix>>> {
    match (items.is_empty(), none) {
        (true, true) => Ok(None),
        (false, false) => Ok(Some(
            items
                .iter()
                .map(|p| p.parse().with_context(|| format!("`{p}` is not a prefix")))
                .collect::<anyhow::Result<_>>()?,
        )),
        _ => bail!("nett site {what} takes prefixes, or --none to remove them"),
    }
}

/// One modifying command (design/site.md section 7): modify, sign, list the changes, confirm, write
/// the desired state, save the site state. Machines in `force` get their node policy re-signed even
/// if nothing changed (`invite`). `saved` runs once the change is saved; when linked to a Hub,
/// `after` runs after a successful push.
fn modify(
    dir: &Path,
    yes: bool,
    force: &[NodeId],
    change: Change,
    saved: Option<After<'_>>,
    after: Option<After<'_>>,
) -> anyhow::Result<()> {
    let site = SiteDir::open(dir)?;
    let old = site.load()?;
    let mut new = old.clone();
    change(&mut new)?;
    let hub = SiteHub::load(dir)?;
    // Without a Hub, nobody can tell the site a public address (design/site.md section 4)
    if hub.is_none()
        && let Some(name) = new.unknown_public_addresses().first()
    {
        bail!("public machine `{name}` needs --ipv4 or --ipv6: other members dial it there");
    }
    sign(&mut new, &site.recovery()?, Timestamp::now(), force)?;
    let lines = describe(&old, &new);
    let outputs = outputs(&new)?;
    if lines.is_empty() {
        // Nothing to sign: only fill in missing or inconsistent desired state files; when linked to
        // a Hub, push once more (the last push may not have been delivered; the Hub does not change
        // the generation when the content is the same)
        let written = write_outputs(&site, &outputs)?;
        if written.is_empty() {
            outln!("Nothing changed.");
        }
        match &hub {
            Some(hub) => {
                crate::hub::push(hub, &new)?;
            }
            None => print_written(&site, &written),
        }
        return Ok(());
    }
    for line in &lines {
        outln!("{line}");
    }
    confirm(
        yes,
        if hub.is_some() {
            "Sign and push?"
        } else {
            "Sign?"
        },
    )?;
    let written = save_with_outputs(&site, &old, &new, &outputs)?;
    if let Some(saved) = saved {
        saved(&new)?;
    }
    let Some(hub) = hub else {
        print_written(&site, &written);
        return Ok(());
    };
    let (status, failed) = crate::hub::push_and_wait(&hub, &new).with_context(|| {
        "the change is signed and saved, but pushing it to the Hub failed; the next nett site \
         command pushes it again"
    })?;
    // Machines that have not connected to the Hub yet are still applied from files
    let offline: Vec<NodeName> = written
        .into_iter()
        .filter(|n| {
            status
                .machines
                .iter()
                .any(|m| m.name == n.as_str() && m.last_seen.is_none())
        })
        .collect();
    print_written(&site, &offline);
    if let Some(after) = after {
        after(&new)?;
    }
    ensure!(!failed, "some machines did not apply the change cleanly");
    Ok(())
}

fn write_outputs(
    site: &SiteDir,
    outputs: &[(NodeName, DesiredMeshDoc)],
) -> anyhow::Result<Vec<NodeName>> {
    let mut written = Vec::new();
    for (name, doc) in outputs {
        if site.write_desired(name, doc)? {
            written.push(name.clone());
        }
    }
    Ok(written)
}

/// Machines whose desired state changed and how to apply it (design/local-signing.md section 5).
fn print_written(site: &SiteDir, written: &[NodeName]) {
    if written.is_empty() {
        return;
    }
    let names: Vec<String> = written.iter().map(ToString::to_string).collect();
    outln!(
        "Wrote the desired state for {} in {}/<machine>/desired.json.
The files contain no private keys. To apply one on its machine:
  Linux      copy it to /etc/nett/desired.json, then run `sudo nett reload`
  macOS      sudo nett install, or with --config <desired.json> when the site is elsewhere",
        names.join(", "),
        site.path().join(NODES_DIR).display()
    );
}

/// Confirmation before signing: `--yes` is required when not on a terminal.
fn confirm(yes: bool, question: &str) -> anyhow::Result<()> {
    if yes {
        return Ok(());
    }
    ensure!(
        std::io::stdin().is_terminal(),
        "not signing: this is not a terminal; pass --yes to sign without asking"
    );
    out!("{question} [y/N] ");
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    ensure!(
        matches!(answer.trim(), "y" | "Y" | "yes"),
        "nothing was signed or changed"
    );
    Ok(())
}

fn init(dir: &Path, origin: &str) -> anyhow::Result<()> {
    SiteDir::init(dir, origin)?;
    outln!(
        "Created a site in {}.
recovery.pk8 signs everything in this network. Back it up offline now:
without it, every machine has to leave and join again.

Next, for each machine:
  1. On the machine, create its keys:
       macOS  sudo nett install
       Linux  sudo nett keys --dir /etc/nett
  2. Here: nett site add <name> --keys \"<the printed line>\"
     (with --public --ipv4 <address> when other machines connect to it)
  3. Allow what may connect: nett site allow <from> <to> <ports>",
        dir.display()
    );
    Ok(())
}

/// `nett site invite` (no Hub): re-signs this machine's node policy and rewrites its desired state
/// (design/site.md section 3).
fn invite(dir: &Path, name: &NodeName, yes: bool) -> anyhow::Result<()> {
    if let Some(hub) = SiteHub::load(dir)? {
        let state = SiteDir::open(dir)?.load()?;
        if state.machine(name)?.keys.is_none() {
            // Not enrolled yet: switch to a new enrollment key, and the old token is invalidated
            // (design/hub.md section 3.3)
            return enroll(dir, &hub, yes, name, Box::new(|_| Ok(())));
        }
        // A machine that is already a member connects to the Hub with its own identity key and
        // receives its desired state from there (design/hub.md section 3.5)
        crate::hub::push(&hub, &state)?;
        let token = crate::hub::join_token(&hub, &state, name)?;
        outln!("{name} is already a member. On {name}, run:\n  sudo nett install {token}");
        return Ok(());
    }
    let node = {
        let site = SiteDir::open(dir)?;
        site.load()?.machine(name)?.node_id.clone()
    };
    modify(dir, yes, &[node], Box::new(|_| Ok(())), None, None)
}

fn status(dir: &Path, machine: Option<&NodeName>, json: bool) -> anyhow::Result<()> {
    let state = SiteDir::open(dir)?.load()?;
    match SiteHub::load(dir)? {
        Some(hub) => match crate::hub::status(&hub, &state, machine, json) {
            Ok(()) => return Ok(()),
            // When the Hub is unreachable, the machines in the site are still listed
            Err(e) if machine.is_none() => {
                errln!("Cannot reach the Hub: {e:#}\nShowing the site only.\n")
            }
            Err(e) => return Err(e),
        },
        None if machine.is_some() => {
            bail!("the site is not linked to a Hub; run `nett status` on the machine to see it")
        }
        None => {}
    }
    if json {
        outln!("{}", serde_json::to_string_pretty(&state.machines)?);
        return Ok(());
    }
    let rules = match &state.access_rules {
        Some(r) => format!("access rules v{} ({} rules)", r.version, state.rules.len()),
        None => "no access rules".to_owned(),
    };
    out!(
        "{}",
        key_values(&[(
            "site",
            format!("{} machines, {rules}", state.machines.len())
        )])
    );
    if state.machines.is_empty() {
        outln!("\nNo machines. `nett site add <name> --keys \"…\"` adds one.");
        return Ok(());
    }
    let mut rows = vec![["MACHINE", "ADDRESS", "REACH", "EDGE", "ROUTES"].map(String::from)];
    for (name, m) in &state.machines {
        let reach = match m.reachability {
            Reachability::DialOnly => "dial-only".to_owned(),
            Reachability::Public => {
                let port = m
                    .listen_port(state.listen_port)
                    .unwrap_or(state.listen_port);
                let addrs: Vec<String> = [
                    m.ipv4.map(|a| format!("{a}:{port}")),
                    m.ipv6.map(|a| format!("[{a}]:{port}")),
                ]
                .into_iter()
                .flatten()
                .collect();
                format!("public {}", addrs.join(" "))
            }
        };
        let routes: Vec<String> = m.routes.iter().map(ToString::to_string).collect();
        rows.push([
            name.to_string(),
            m.mesh.ipv4.to_string(),
            reach,
            m.edge
                .as_ref()
                .map_or_else(|| "-".to_owned(), |e| e.addresses.ipv4.to_string()),
            if routes.is_empty() {
                "-".to_owned()
            } else {
                routes.join(", ")
            },
        ]);
    }
    outln!("\n{}", table(&rows).trim_end());
    let name = |id: &NodeId| {
        state
            .name_of(id)
            .map_or_else(|| id.to_string(), ToString::to_string)
    };
    let mut listed: Vec<[String; 2]> = connections(&state)
        .iter()
        .map(|(a, b)| {
            let mut names = [name(a), name(b)];
            names.sort();
            [
                format!("{} - {}", names[0], names[1]),
                path_kind(&state, a, b),
            ]
        })
        .collect();
    if !listed.is_empty() {
        listed.sort();
        let mut rows = vec![["CONNECTION", "PATH"].map(String::from)];
        rows.extend(listed);
        outln!("\n{}", table(&rows).trim_end());
    }
    Ok(())
}

fn rules(dir: &Path, json: bool) -> anyhow::Result<()> {
    let state = SiteDir::open(dir)?.load()?;
    if json {
        outln!("{}", serde_json::to_string_pretty(&state.rules)?);
        return Ok(());
    }
    let own: Vec<String> = state
        .devices
        .iter()
        .filter(|(_, d)| !d.limited)
        .map(|(n, _)| n.to_string())
        .collect();
    if state.rules.is_empty() && own.is_empty() {
        outln!(
            "No access rules: no connection is allowed. `nett site allow <from> <to> <ports>` adds one."
        );
        return Ok(());
    }
    let side = |sel: &[Selector]| {
        sel.iter()
            .map(|s| state.selector_text(s))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut rows = vec![["ID", "FROM", "TO", "PORTS", "NOTE"].map(String::from)];
    // What devices that are not limited reach is part of the signed rule set (design/devices.md
    // section 5)
    if !own.is_empty() {
        rows.push([
            "-".to_owned(),
            own.join(", "),
            "every machine and route".to_owned(),
            "all ports".to_owned(),
            "devices that are not limited".to_owned(),
        ]);
    }
    for (id, r) in &state.rules {
        rows.push([
            id.to_string(),
            side(&r.from),
            side(&r.to),
            ports_text(&r.ports),
            r.note.clone().unwrap_or_default(),
        ]);
    }
    out!("{}", table(&rows));
    Ok(())
}

/// `22/tcp`, `3425/tcp,3430/tcp`, `60000-61000/udp`.
/// `nett site serve <machine> <port>/tcp... | --none` (design/site.md section 5.3).
fn served_ports(items: &[&str], none: bool) -> anyhow::Result<Vec<ServedPort>> {
    match (items.is_empty(), none) {
        (true, true) => Ok(Vec::new()),
        (false, false) => items
            .iter()
            .map(|item| {
                let port = item.strip_suffix("/tcp").with_context(|| {
                    format!("`{item}`: serve takes TCP ports, such as 8080/tcp")
                })?;
                let port: u16 = port.parse().with_context(|| format!("port `{item}`"))?;
                ensure!(port != 0, "port `{item}`: need 1 or more");
                Ok(ServedPort::tcp(port))
            })
            .collect(),
        _ => bail!("nett site serve takes ports such as 8080/tcp, or --none to remove them"),
    }
}

fn parse_ports(s: &str) -> anyhow::Result<Vec<PortRange>> {
    s.split(',').map(parse_port_range).collect()
}

fn parse_port_range(s: &str) -> anyhow::Result<PortRange> {
    let (range, proto) = s
        .split_once('/')
        .with_context(|| format!("port `{s}` must be <port>[-<port>]/<tcp|udp>"))?;
    let protocol = match proto {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        _ => bail!("port `{s}`: protocol must be tcp or udp"),
    };
    let (first, last) = range.split_once('-').unwrap_or((range, range));
    let (first, last): (u16, u16) = (
        first.parse().with_context(|| format!("port `{s}`"))?,
        last.parse().with_context(|| format!("port `{s}`"))?,
    );
    ensure!(
        first >= 1 && first <= last,
        "port `{s}`: need 1 <= first <= last"
    );
    Ok(PortRange {
        protocol,
        first,
        last,
    })
}

/// Default location of the site directory (design/site.md section 3).
fn default_dir() -> anyhow::Result<PathBuf> {
    site_dir(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    )
}

/// Default site directory for a given `XDG_CONFIG_HOME` and home directory.
pub(crate) fn site_dir(xdg: Option<OsString>, home: Option<OsString>) -> anyhow::Result<PathBuf> {
    Ok(config_home(xdg, home)?.join("nett"))
}

/// `$XDG_CONFIG_HOME`, or `~/.config` when unset; per the XDG specification, a relative
/// `XDG_CONFIG_HOME` is ignored.
fn config_home(xdg: Option<OsString>, home: Option<OsString>) -> anyhow::Result<PathBuf> {
    if let Some(xdg) = xdg.map(PathBuf::from).filter(|p| p.is_absolute()) {
        return Ok(xdg);
    }
    let home = home
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .context("HOME is not set to an absolute path; give the site directory with --dir")?;
    Ok(home.join(".config"))
}

/// Whether the desired state generated by the signing tool is for this machine: the mesh public key
/// in this node's admission material must be `mesh_public` (`sudo nett install --config`,
/// design/release.md section 4). If the file was copied from the wrong machine, it fails before
/// copying.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn check_desired_for(
    bytes: &[u8],
    mesh_public: &X25519PublicKey,
) -> anyhow::Result<NodeId> {
    let desired =
        nett_mesh::config::DesiredMesh::from_json(bytes).context("not a valid desired state")?;
    let mut members = nett_mesh::members::MemberSet::default();
    // This only catches a wrong file before copying: the baseline for verification is the mesh
    // process's own trust store (design/mesh.md section 4.2)
    let own = nett_mesh::members::OwnPolicy {
        node_id: &desired.node_id,
        now: None,
    };
    members.apply(&desired, &own, &mut nett_mesh::event::VecSink::default());
    let me = members
        .get(&desired.node_id)
        .context("the desired state does not admit its own node")?;
    ensure!(
        me.mesh_public_key == *mesh_public,
        "this desired state is for node {} (mesh key {}), not for this machine (mesh key {}); \
         use the desired.json the site wrote for this machine",
        desired.node_id,
        me.mesh_public_key,
        mesh_public
    );
    Ok(desired.node_id.clone())
}

/// The desired state for this machine in the site directory (`sudo nett install`, design/release.md
/// section 4): under `nodes/`, the one whose node mesh public key is `mesh_public`; returns its
/// path and content. Returns `None` when there is no `nodes/` yet.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn find_desired_for(
    site: &Path,
    mesh_public: &X25519PublicKey,
) -> anyhow::Result<Option<(PathBuf, Vec<u8>)>> {
    let nodes = site.join(NODES_DIR);
    let entries = match std::fs::read_dir(&nodes) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", nodes.display())),
    };
    let mut found = Vec::new();
    // A site has at most this many machines; extra entries were not written by the signing tool
    for entry in entries.take(MAX_MEMBERS) {
        let path = entry
            .with_context(|| format!("reading {}", nodes.display()))?
            .path()
            .join(DESIRED_FILE);
        if let Some(bytes) = read_desired(&path)?
            && check_desired_for(&bytes, mesh_public).is_ok()
        {
            found.push((path, bytes));
        }
    }
    if found.len() > 1 {
        let paths: Vec<String> = found.iter().map(|(p, _)| p.display().to_string()).collect();
        bail!(
            "several desired states are for this machine ({}); give one with --config",
            paths.join(", ")
        );
    }
    Ok(found.pop())
}

/// Reads a desired state file: only regular files (no devices or pipes, symlinks are not followed),
/// with a size limit. Returns `None` if it does not exist or is not a regular file. `sudo nett
/// install` reads it as root from a user-writable directory: it opens first and then checks the
/// opened file, so the file cannot be swapped between the check and the read; it opens without
/// blocking, so replacing it with a pipe does not make it hang.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn read_desired(path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
    use nett_mesh::config::MAX_DESIRED_BYTES;
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        // Symlink: opening with O_NOFOLLOW fails (ELOOP)
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    if !file
        .metadata()
        .with_context(|| format!("reading {}", path.display()))?
        .is_file()
    {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    file.take(MAX_DESIRED_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    ensure!(
        bytes.len() as u64 <= MAX_DESIRED_BYTES,
        "{} is larger than {MAX_DESIRED_BYTES} bytes; it is not a desired state",
        path.display()
    );
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nett_mesh::key::PrivateKey;

    /// A directory removed with everything in it when the returned guard is dropped; keep the
    /// guard for as long as the path is used.
    fn temp_dir(name: &str) -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::Builder::new()
            .prefix(&format!("nett-cli-site-{name}-"))
            .tempdir()
            .expect("temp dir");
        let dir = tmp.path().join("site");
        (tmp, dir)
    }

    fn keys() -> (X25519PublicKey, String) {
        let (mesh, identity) = (
            PrivateKey::generate().expect("key"),
            PrivateKey::generate().expect("key"),
        );
        (
            mesh.public_key(),
            format!("{} {}", mesh.public_key(), identity.public_key()),
        )
    }

    /// Runs a `nett site` command with `--yes`.
    fn site(dir: &Path, args: &[&str]) -> anyhow::Result<()> {
        let mut argv: Vec<OsString> = args.iter().map(OsString::from).collect();
        argv.extend(["--dir".into(), dir.as_os_str().to_owned(), "--yes".into()]);
        run(lexopt::Parser::from_args(argv))
    }

    fn name(s: &str) -> NodeName {
        s.parse().expect("name")
    }

    /// Approvals are for the Hub to act on (design/release.md section 7): without one, the command
    /// says how machines are upgraded instead
    #[test]
    fn upgrades_are_approved_through_the_hub_only() {
        let (_tmp, dir) = temp_dir("upgrade");
        site(&dir, &["init"]).expect("init");
        let (_, mac) = keys();
        site(&dir, &["add", "mac", "--keys", &mac]).expect("add mac");
        let error = site(&dir, &["upgrade"]).expect_err("no Hub");
        assert!(
            error.to_string().contains("upgrades go through the Hub"),
            "{error:#}"
        );
    }

    #[test]
    fn a_device_is_added_exported_and_removed() {
        let (dir_tmp, dir) = temp_dir("devices");
        site(&dir, &["init"]).expect("init");
        let (_, gw_keys) = keys();
        site(
            &dir,
            &[
                "add",
                "gw",
                "--keys",
                &gw_keys,
                "--public",
                "--ipv4",
                "203.0.113.10",
            ],
        )
        .expect("add gw");
        let (_, mac_keys) = keys();
        site(&dir, &["add", "mac", "--keys", &mac_keys]).expect("add mac");
        // The first device names its gateway, which is a public machine
        let out = dir_tmp.path().join("out");
        std::fs::create_dir(&out).expect("out");
        let out_arg = out.to_str().expect("utf-8");
        assert!(site(&dir, &["device", "add", "work", "--out", out_arg]).is_err());
        assert!(
            site(
                &dir,
                &[
                    "device",
                    "add",
                    "work",
                    "--gateway",
                    "mac",
                    "--out",
                    out_arg
                ]
            )
            .is_err()
        );
        site(
            &dir,
            &[
                "device",
                "add",
                "work",
                "--gateway",
                "gw",
                "--limited",
                "--out",
                out_arg,
            ],
        )
        .expect("device add");

        let state = SiteDir::open(&dir).expect("open").load().expect("load");
        let work = &state.devices[&name("work")];
        assert!(work.limited);
        let conf = std::fs::read_to_string(out.join("work.conf")).expect("conf");
        let private = conf
            .lines()
            .find_map(|l| l.strip_prefix("PrivateKey = "))
            .expect("private key line");
        use base64::Engine as _;
        let bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(private)
            .expect("base64")
            .try_into()
            .expect("32 bytes");
        assert_eq!(
            PrivateKey::from_bytes(bytes).public_key(),
            work.credential.public_key
        );
        assert!(conf.contains("Endpoint = 203.0.113.10:41820"));
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(out.join("work.conf"))
            .expect("file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(
            std::fs::read_dir(&out).expect("out").count(),
            1,
            "the WireGuard configuration alone"
        );
        // The site keeps no private key
        let saved = std::fs::read_to_string(dir.join("state.json")).expect("state");
        assert!(!saved.contains(private));
        // The gateway's desired state carries the device; the same name again is refused, as is
        // writing over the exported files
        let doc: DesiredMeshDoc = serde_json::from_slice(
            &std::fs::read(dir.join(NODES_DIR).join("gw").join(DESIRED_FILE)).expect("desired"),
        )
        .expect("doc");
        assert_eq!(doc.devices.len(), 1);
        assert!(site(&dir, &["device", "add", "work", "--out", out_arg]).is_err());

        site(&dir, &["allow", "work", "gw", "8081/tcp"]).expect("allow");
        // The gateway cannot go while a device comes through it
        assert!(site(&dir, &["remove", "gw"]).is_err());
        site(&dir, &["device", "remove", "work"]).expect("remove");
        let state = SiteDir::open(&dir).expect("open").load().expect("load");
        assert!(state.devices.is_empty());
        assert!(state.rules.is_empty());
        assert_eq!(state.revoked_credentials.len(), 1);
        assert!(!state.is_gateway(&state.machines[&name("gw")].node_id));
    }

    #[test]
    fn site_directory_defaults_to_the_xdg_config_home() {
        let os = |s: &str| Some(OsString::from(s));
        assert_eq!(
            config_home(os("/x/config"), os("/home/u")).expect("xdg"),
            Path::new("/x/config")
        );
        assert_eq!(
            config_home(None, os("/home/u")).expect("home"),
            Path::new("/home/u/.config")
        );
        // A relative XDG_CONFIG_HOME is ignored (XDG specification)
        assert_eq!(
            config_home(os("relative"), os("/home/u")).expect("home"),
            Path::new("/home/u/.config")
        );
        assert!(config_home(None, None).is_err());
    }

    #[test]
    fn commands_change_the_site_and_write_desired_states() {
        let (_dir_tmp, dir) = temp_dir("commands");
        site(&dir, &["init"]).expect("init");
        let (_, vps) = keys();
        let (mac_key, mac) = keys();
        site(
            &dir,
            &[
                "add",
                "vps",
                "--public",
                "--ipv4",
                "203.0.113.10",
                "--keys",
                &vps,
            ],
        )
        .expect("vps");
        site(&dir, &["add", "mac", "--keys", &mac]).expect("mac");
        site(&dir, &["routes", "mac", "172.30.0.10/32"]).expect("routes");
        site(
            &dir,
            &[
                "allow",
                "vps",
                "mac.routes",
                "22/tcp,8080/tcp",
                "--note",
                "ssh",
            ],
        )
        .expect("allow");
        let state = SiteDir::open(&dir).expect("open").load().expect("load");
        assert_eq!(state.rules.len(), 1);
        assert_eq!(state.rules[&RuleId(1)].ports.len(), 2);
        assert_eq!(state.access_rules.as_ref().map(|r| r.version), Some(1));
        // No --keys: no change
        // Without a Hub, both the public keys and the addresses of public machines must be given
        let e = site(&dir, &["add", "nas"]).expect_err("needs keys");
        assert!(e.to_string().contains("--keys is needed"), "{e}");
        let (_, line) = keys();
        let e = site(
            &dir,
            &["add", "relay", "--public", "--keys", &line, "--yes"],
        )
        .expect_err("needs an address");
        assert!(e.to_string().contains("needs --ipv4 or --ipv6"), "{e}");
        let mac_file = dir.join(NODES_DIR).join("mac").join(DESIRED_FILE);
        let bytes = std::fs::read(&mac_file).expect("written");
        assert_eq!(
            check_desired_for(&bytes, &mac_key).expect("mine"),
            state.machines[&name("mac")].node_id
        );
        // Serve TCP ports to loopback: written in order into the node policy, removed with --none
        let policy = |s: &State| s.machines[&name("mac")].policy.as_ref().map(|p| p.version);
        let unserved = policy(&state);
        site(&dir, &["serve", "mac", "8080/tcp", "3000/tcp"]).expect("serve");
        let state = SiteDir::open(&dir).expect("open").load().expect("load");
        assert_eq!(
            state.machines[&name("mac")].serve,
            [ServedPort::tcp(3000), ServedPort::tcp(8080)]
        );
        assert_eq!(policy(&state), unserved.map(|v| v + 1));
        for bad in [
            &["serve", "mac", "53/udp"][..],
            &["serve", "mac", "0/tcp"],
            &["serve", "mac"],
        ] {
            assert!(site(&dir, bad).is_err(), "{bad:?}");
        }
        site(&dir, &["serve", "mac", "--none"]).expect("no ports");
        let state = SiteDir::open(&dir).expect("open").load().expect("load");
        assert!(state.machines[&name("mac")].serve.is_empty());
        // Remove a prefix: the rules that reference it are deleted with it
        site(&dir, &["routes", "mac", "--none"]).expect("no routes");
        let state = SiteDir::open(&dir).expect("open").load().expect("load");
        assert!(state.rules.is_empty());
        assert_eq!(state.access_rules.as_ref().map(|r| r.version), Some(2));
        site(&dir, &["remove", "mac"]).expect("removed");
        assert!(!mac_file.exists());
        let state = SiteDir::open(&dir).expect("open").load().expect("load");
        assert_eq!(state.revoked.len(), 1);
        // invite re-signs the node policy
        let before = state.machines[&name("vps")]
            .policy
            .as_ref()
            .map(|p| p.version);
        site(&dir, &["invite", "vps"]).expect("invited");
        let state = SiteDir::open(&dir).expect("open").load().expect("load");
        assert_eq!(
            state.machines[&name("vps")]
                .policy
                .as_ref()
                .map(|p| p.version),
            before.map(|v| v + 1)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reads_only_regular_files_without_following_links_or_blocking() {
        let (_dir_tmp, dir) = temp_dir("read-desired");
        std::fs::create_dir_all(&dir).expect("dir");
        let file = dir.join("desired.json");
        std::fs::write(&file, b"{}").expect("written");
        assert_eq!(read_desired(&file).expect("readable"), Some(b"{}".to_vec()));
        assert_eq!(read_desired(&dir.join("missing")).expect("no error"), None);
        let link = dir.join("link.json");
        std::os::unix::fs::symlink(&file, &link).expect("symlink");
        assert_eq!(read_desired(&link).expect("no error"), None);
        // Replaced with a pipe: opened without blocking, it is immediately found not to be a
        // regular file, without waiting for a writer
        let fifo = dir.join("fifo.json");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo");
        assert!(made.success());
        assert_eq!(read_desired(&fifo).expect("no error"), None);
        assert_eq!(read_desired(&dir).expect("no error"), None);
        std::fs::remove_dir_all(&dir).expect("cleaned up");
    }

    #[test]
    fn desired_state_must_belong_to_this_machine() {
        let (_dir_tmp, dir) = temp_dir("owner");
        site(&dir, &["init"]).expect("init");
        let (vps_key, vps) = keys();
        let (mac_key, mac) = keys();
        site(
            &dir,
            &[
                "add",
                "vps",
                "--public",
                "--ipv4",
                "203.0.113.10",
                "--keys",
                &vps,
            ],
        )
        .expect("vps");
        site(&dir, &["add", "mac", "--keys", &mac]).expect("mac");
        let mac_file =
            std::fs::read(dir.join(NODES_DIR).join("mac").join(DESIRED_FILE)).expect("out");
        assert!(check_desired_for(&mac_file, &mac_key).is_ok());
        // A file from another machine, or a file that is not a desired state, is rejected before
        // copying
        assert!(check_desired_for(&mac_file, &vps_key).is_err());
        assert!(check_desired_for(b"{}", &mac_key).is_err());

        // install without --config finds this machine's file in the site directory by mesh public
        // key; other entries are skipped
        std::fs::create_dir_all(dir.join(NODES_DIR).join("stray").join(DESIRED_FILE)).expect("dir");
        std::fs::create_dir_all(dir.join(NODES_DIR).join("junk")).expect("dir");
        std::fs::write(dir.join(NODES_DIR).join("junk").join(DESIRED_FILE), b"{}").expect("junk");
        let (path, bytes) = find_desired_for(&dir, &mac_key)
            .expect("search")
            .expect("found");
        assert_eq!(path, dir.join(NODES_DIR).join("mac").join(DESIRED_FILE));
        assert_eq!(bytes, mac_file);
        let (other, _) = keys();
        assert!(find_desired_for(&dir, &other).expect("search").is_none());
        // Both are for this machine (copies): no guessing, --config is required
        std::fs::create_dir_all(dir.join(NODES_DIR).join("copy")).expect("dir");
        std::fs::write(
            dir.join(NODES_DIR).join("copy").join(DESIRED_FILE),
            &mac_file,
        )
        .expect("copy");
        assert!(find_desired_for(&dir, &mac_key).is_err());
        assert!(
            find_desired_for(&dir.join("absent"), &mac_key)
                .expect("search")
                .is_none()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ports_parse_strictly() {
        assert_eq!(parse_ports("22/tcp").expect("ok").len(), 1);
        assert_eq!(parse_ports("3425/tcp,3430/tcp").expect("ok").len(), 2);
        let range = parse_ports("60000-61000/udp").expect("ok");
        assert_eq!((range[0].first, range[0].last), (60000, 61000));
        for bad in ["22", "22/icmp", "0/tcp", "9-1/tcp", "x/tcp"] {
            assert!(parse_ports(bad).is_err(), "{bad}");
        }
    }
}
