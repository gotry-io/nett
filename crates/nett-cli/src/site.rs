//! `nett site`：用户自己电脑上的签名工具（design/site.md）。站点目录（默认 `~/.config/nett`）中有恢复密钥
//! `recovery.pk8`（权限 `0600`，只在签名时读取）和站点状态 `state.json`；每条修改命令列出要签名的内容，
//! 确认后签名，为期望状态有变化的机器重写 `nodes/<机器>/desired.json`。站点的模型、签名与组成在
//! `nett-site` 中，这里只是命令行。

use std::ffi::OsString;
use std::io::{BufRead as _, IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail, ensure};
use lexopt::ValueExt as _;
use nett_core::id::NodeId;
use nett_core::name::NodeName;
use nett_core::prefix::IpPrefix;
use nett_mesh::config::{DesiredMeshDoc, MAX_MEMBERS, Reachability};
use nett_site::changes::{describe, path_kind, ports_text};
use nett_site::compose::{connections, desired};
use nett_site::dir::{DESIRED_FILE, NODES_DIR, SiteDir, new_node_id};
use nett_site::ops::{MachineChange, MachineOptions};
use nett_site::sign::sign;
use nett_site::state::{NodeKeys, RuleId, Selector, State};
use nett_trust::encoding::Timestamp;
use nett_trust::keys::X25519PublicKey;
use nett_trust::payload::{PortRange, Protocol};
use nett_trust::signing::EnrollmentKeyPair;

use crate::hub::SiteHub;
use crate::layout::{key_values, table};

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
             [--port <port>|default]   change how other machines reach it
  remove <name>                        remove a machine; rules that name it go with it
  invite <name>                        with a Hub: print the command that connects it to the Hub
                                       (a new token for a machine that has not joined yet);
                                       without: sign its node policy again, rewrite its desired state
  edge <name> <prefix>... | --none     the Edge containers on this machine
  routes <name> <prefix>... | --none   the routes this machine advertises
  allow <from> <to> [<ports>] [--note <text>]
                                       allow connections: <machine>, <machine>.edge or
                                       <machine>.routes, several joined by commas; ports such as
                                       22/tcp or 60000-61000/udp, all ports when left out
  rules [--json]                       list the access rules
  rules remove <id>                    remove an access rule, for example r2
  status [<name>] [--json]             list the machines and their connections; with a Hub, also
                                       whether each one is online and applied the latest change

Changes are listed before they are signed; --yes signs without asking (needed when not on a terminal).
With a Hub, signed changes are pushed to it and reach the machines from there.
The site directory defaults to $XDG_CONFIG_HOME/nett, or ~/.config/nett when it is not set.";

/// 一次修改：在站点状态的副本上进行。
type Change = Box<dyn FnOnce(&mut State) -> anyhow::Result<()>>;
/// 推送成功之后要做的事（打印新机器上要运行的一行）。
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
            other => return Err(other.unexpected().into()),
        }
    }
    let dir = match dir {
        Some(dir) => dir,
        None => default_dir()?,
    };
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    let machine = |s: &str| -> anyhow::Result<NodeName> { Ok(s.parse()?) };
    // 接了 Hub 时每条命令先取回 Hub 一侧发生的事（design/hub.md 第 4 节）
    if !matches!(words.as_slice(), ["init"] | ["link", _])
        && let Some(hub) = SiteHub::load(&dir)?
    {
        sync(&dir, &hub)?;
    }
    let change: Change = match words.as_slice() {
        ["init"] => return init(&dir, origin.as_deref().unwrap_or(DEFAULT_ORIGIN)),
        ["link", code] => return crate::hub::link(&dir, code),
        ["status"] => return status(&dir, None, json),
        ["status", name] => return status(&dir, Some(&machine(name)?), json),
        ["rules"] => return rules(&dir, json),
        ["invite", name] => return invite(&dir, &machine(name)?, yes),
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
                // 接了 Hub：签好节点策略，新机器经 Hub 入网（design/hub.md 第 3.3、6 节）
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
            Box::new(move |s| Ok(s.set(&name, change)?))
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
    modify(&dir, yes, &[], change, None)
}

/// 取回 Hub 一侧发生的事，记进站点目录（design/hub.md 第 4 节）：入网的机器记下公钥与准入材料，退出的机器
/// 移除、规则随之清理并以新的版本重签（收窄），得知的公网地址记下。只有记录与收窄，不用确认。Hub 不在时
/// 跳过：命令之后的推送会报告。
fn sync(dir: &Path, hub: &SiteHub) -> anyhow::Result<()> {
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
    println!("From the Hub:");
    for name in &applied.joined {
        println!("  + {name} joined through the Hub");
    }
    for name in &applied.left {
        println!("  - {name} left the site (`nett leave` on the machine)");
    }
    for line in describe(&stored, &next) {
        println!("  {line}");
    }
    save_with_outputs(&site, &stored, &next, &outputs(&next)?)?;
    // 送不到时下一条命令再推
    if let Err(e) = crate::hub::push(hub, &next) {
        println!("  (pushing this to the Hub failed: {e:#})");
    }
    println!();
    Ok(())
}

/// 各台机器的期望状态；组成失败（生成的期望状态组网进程不接受）时整条命令失败。
fn outputs(state: &State) -> anyhow::Result<Vec<(NodeName, DesiredMeshDoc)>> {
    let mut outputs = Vec::new();
    for name in state.machines.keys() {
        if let Some(doc) = desired(state, name)? {
            outputs.push((name.clone(), doc));
        }
    }
    Ok(outputs)
}

/// 保存站点状态，重写各台机器的期望状态文件，删除已移除的机器的文件。返回写了文件的机器。
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

/// 让一台机器经 Hub 入网：`change` 之后给它一把新的入网密钥（design/hub.md 第 6 节），签名、推送，再打印
/// 新机器上要运行的一行。入网私钥只在这一行里。
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

/// 一条修改命令（design/site.md 第 7 节）：修改 → 签名 → 列出变化 → 确认 → 写期望状态 → 保存站点状态。
/// `force` 中的机器即使没有变化也重签节点策略（`invite`）。接了 Hub 时 `after` 在推送成功之后运行。
fn modify(
    dir: &Path,
    yes: bool,
    force: &[NodeId],
    change: Change,
    after: Option<After<'_>>,
) -> anyhow::Result<()> {
    let site = SiteDir::open(dir)?;
    let old = site.load()?;
    let mut new = old.clone();
    change(&mut new)?;
    let hub = SiteHub::load(dir)?;
    // 不接 Hub 时没有人能告诉站点公网地址（design/site.md 第 4 节）
    if hub.is_none()
        && let Some(name) = new.unknown_public_addresses().first()
    {
        bail!("public machine `{name}` needs --ipv4 or --ipv6: other members dial it there");
    }
    sign(&mut new, &site.recovery()?, Timestamp::now(), force)?;
    let lines = describe(&old, &new);
    let outputs = outputs(&new)?;
    if lines.is_empty() {
        // 没有要签的：只补上缺少或不一致的期望状态文件；接了 Hub 时再推一次（上一次可能没有送到，
        // 内容相同时 Hub 不换代数）
        let written = write_outputs(&site, &outputs)?;
        if written.is_empty() {
            println!("Nothing changed.");
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
        println!("{line}");
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
    let Some(hub) = hub else {
        print_written(&site, &written);
        return Ok(());
    };
    let (status, failed) = crate::hub::push_and_wait(&hub, &new).with_context(|| {
        "the change is signed and saved, but pushing it to the Hub failed; the next nett site \
         command pushes it again"
    })?;
    // 还没有连过 Hub 的机器仍按文件应用
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

/// 期望状态有变化的机器和应用的方法（design/local-signing.md 第 5 节）。
fn print_written(site: &SiteDir, written: &[NodeName]) {
    if written.is_empty() {
        return;
    }
    let names: Vec<String> = written.iter().map(ToString::to_string).collect();
    println!(
        "Wrote the desired state for {} in {}/<machine>/desired.json.
The files contain no private keys. To apply one on its machine:
  Linux      copy it to /etc/nett/desired.json, then run `sudo nett reload`
  macOS      sudo nett install, or with --config <desired.json> when the site is elsewhere
  container  replace the mounted desired.json, then run `docker exec <container> /nett reload`",
        names.join(", "),
        site.path().join(NODES_DIR).display()
    );
}

/// 签名之前确认：不是终端时要 `--yes`。
fn confirm(yes: bool, question: &str) -> anyhow::Result<()> {
    if yes {
        return Ok(());
    }
    ensure!(
        std::io::stdin().is_terminal(),
        "not signing: this is not a terminal; pass --yes to sign without asking"
    );
    print!("{question} [y/N] ");
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
    println!(
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

/// `nett site invite`（不接 Hub）：重签这台机器的节点策略，重写它的期望状态（design/site.md 第 3 节）。
fn invite(dir: &Path, name: &NodeName, yes: bool) -> anyhow::Result<()> {
    if let Some(hub) = SiteHub::load(dir)? {
        let state = SiteDir::open(dir)?.load()?;
        if state.machine(name)?.keys.is_none() {
            // 还没有入网：换一把入网密钥，原来的 token 随之作废（design/hub.md 第 3.3 节）
            return enroll(dir, &hub, yes, name, Box::new(|_| Ok(())));
        }
        // 已是成员的机器用自己的身份密钥连接 Hub，从那里接收期望状态（design/hub.md 第 3.5 节）
        crate::hub::push(&hub, &state)?;
        let token = crate::hub::join_token(&hub, &state, name)?;
        println!("{name} is already a member. On {name}, run:\n  sudo nett install {token}");
        return Ok(());
    }
    let node = {
        let site = SiteDir::open(dir)?;
        site.load()?.machine(name)?.node_id.clone()
    };
    modify(dir, yes, &[node], Box::new(|_| Ok(())), None)
}

fn status(dir: &Path, machine: Option<&NodeName>, json: bool) -> anyhow::Result<()> {
    let state = SiteDir::open(dir)?.load()?;
    match SiteHub::load(dir)? {
        Some(hub) => match crate::hub::status(&hub, &state, machine, json) {
            Ok(()) => return Ok(()),
            // Hub 不在时照样列出站点中的机器
            Err(e) if machine.is_none() => {
                eprintln!("Cannot reach the Hub: {e:#}\nShowing the site only.\n")
            }
            Err(e) => return Err(e),
        },
        None if machine.is_some() => {
            bail!("the site is not linked to a Hub; run `nett status` on the machine to see it")
        }
        None => {}
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&state.machines)?);
        return Ok(());
    }
    let rules = match &state.access_rules {
        Some(r) => format!("access rules v{} ({} rules)", r.version, state.rules.len()),
        None => "no access rules".to_owned(),
    };
    print!(
        "{}",
        key_values(&[(
            "site",
            format!("{} machines, {rules}", state.machines.len())
        )])
    );
    if state.machines.is_empty() {
        println!("\nNo machines. `nett site add <name> --keys \"…\"` adds one.");
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
    println!("\n{}", table(&rows).trim_end());
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
                path_kind(&state, a, b).to_owned(),
            ]
        })
        .collect();
    if !listed.is_empty() {
        listed.sort();
        let mut rows = vec![["CONNECTION", "PATH"].map(String::from)];
        rows.extend(listed);
        println!("\n{}", table(&rows).trim_end());
    }
    Ok(())
}

fn rules(dir: &Path, json: bool) -> anyhow::Result<()> {
    let state = SiteDir::open(dir)?.load()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&state.rules)?);
        return Ok(());
    }
    if state.rules.is_empty() {
        println!(
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
    for (id, r) in &state.rules {
        rows.push([
            id.to_string(),
            side(&r.from),
            side(&r.to),
            ports_text(&r.ports),
            r.note.clone().unwrap_or_default(),
        ]);
    }
    print!("{}", table(&rows));
    Ok(())
}

/// `22/tcp`、`3425/tcp,3430/tcp`、`60000-61000/udp`。
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

/// 站点目录的默认位置（design/site.md 第 3 节）。
fn default_dir() -> anyhow::Result<PathBuf> {
    site_dir(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    )
}

/// 给定 `XDG_CONFIG_HOME` 与家目录时的默认站点目录。
pub(crate) fn site_dir(xdg: Option<OsString>, home: Option<OsString>) -> anyhow::Result<PathBuf> {
    Ok(config_home(xdg, home)?.join("nett"))
}

/// `$XDG_CONFIG_HOME`，没有设置时 `~/.config`；按 XDG 规范，相对路径的 `XDG_CONFIG_HOME` 不用。
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

/// 签名工具生成的期望状态是不是给这台机器的：其中本节点准入材料的组网公钥必须是 `mesh_public`
/// （`sudo nett install --config`，design/release.md 第 4 节）。拷错了机器的文件时在复制之前就报错。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn check_desired_for(
    bytes: &[u8],
    mesh_public: &X25519PublicKey,
) -> anyhow::Result<NodeId> {
    let desired =
        nett_mesh::config::DesiredMesh::from_json(bytes).context("not a valid desired state")?;
    let mut members = nett_mesh::members::MemberSet::default();
    // 只是在复制之前发现拷错了文件：验证的基准是组网进程自己的信任存储（design/mesh.md 第 4.2 节）
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

/// 站点目录中给这台机器的期望状态（`sudo nett install`，design/release.md 第 4 节）：`nodes/` 下
/// 本节点的组网公钥是 `mesh_public` 的那一份，返回它的路径和内容。还没有 `nodes/` 时返回 `None`。
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
    // 一个站点最多这么多台机器，多出的条目不是签名工具写的
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

/// 读一份期望状态文件：只读普通文件（不读设备、管道，不跟随符号链接），大小有上限。不存在或不是普通
/// 文件时返回 `None`。`sudo nett install` 以 root 从用户可写的目录读它：先打开再检查打开的文件，检查与
/// 读取之间换不了文件；以非阻塞方式打开，换成管道也不会让它卡住。
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
        // 符号链接：O_NOFOLLOW 打开失败（ELOOP）
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

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nett-site-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        dir
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

    /// 以 `--yes` 运行一条 `nett site` 命令。
    fn site(dir: &Path, args: &[&str]) -> anyhow::Result<()> {
        let mut argv: Vec<OsString> = args.iter().map(OsString::from).collect();
        argv.extend(["--dir".into(), dir.as_os_str().to_owned(), "--yes".into()]);
        run(lexopt::Parser::from_args(argv))
    }

    fn name(s: &str) -> NodeName {
        s.parse().expect("name")
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
        // 相对路径的 XDG_CONFIG_HOME 不用（XDG 规范）
        assert_eq!(
            config_home(os("relative"), os("/home/u")).expect("home"),
            Path::new("/home/u/.config")
        );
        assert!(config_home(None, None).is_err());
    }

    #[test]
    fn commands_change_the_site_and_write_desired_states() {
        let dir = temp_dir("commands");
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
        // 没有 --keys：不改
        // 不接 Hub 时公钥与 public 机器的地址都要写明
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
        // 去掉网段：引用它的规则一起删除
        site(&dir, &["routes", "mac", "--none"]).expect("no routes");
        let state = SiteDir::open(&dir).expect("open").load().expect("load");
        assert!(state.rules.is_empty());
        assert_eq!(state.access_rules.as_ref().map(|r| r.version), Some(2));
        site(&dir, &["remove", "mac"]).expect("removed");
        assert!(!mac_file.exists());
        let state = SiteDir::open(&dir).expect("open").load().expect("load");
        assert_eq!(state.revoked.len(), 1);
        // invite 重签节点策略
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
        let dir = temp_dir("read-desired");
        std::fs::create_dir_all(&dir).expect("dir");
        let file = dir.join("desired.json");
        std::fs::write(&file, b"{}").expect("written");
        assert_eq!(read_desired(&file).expect("readable"), Some(b"{}".to_vec()));
        assert_eq!(read_desired(&dir.join("missing")).expect("no error"), None);
        let link = dir.join("link.json");
        std::os::unix::fs::symlink(&file, &link).expect("symlink");
        assert_eq!(read_desired(&link).expect("no error"), None);
        // 换成管道：以非阻塞方式打开，立刻发现不是普通文件，不等写入方
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
        let dir = temp_dir("owner");
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
        // 另一台机器的文件、不是期望状态的文件都在复制之前被拒绝
        assert!(check_desired_for(&mac_file, &vps_key).is_err());
        assert!(check_desired_for(b"{}", &mac_key).is_err());

        // install 不带 --config 时在站点目录中按组网公钥找到本机的那一份，其他条目跳过
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
        // 两份都是给本机的（拷贝出来的副本）：不猜，要求 --config
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
