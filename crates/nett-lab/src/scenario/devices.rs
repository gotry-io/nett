//! Devices through a mobile gateway (design/devices.md): h runs the Hub and the site, g is the public
//! member the first device names as its gateway, m a member behind NAT with services on ports 8080
//! and 2222. Two
//! namespaces on the public network act as devices with plain `wg` and the exported configuration:
//! phone, which reaches every machine, and work, limited to one rule. g's namespace has a
//! `filter FORWARD` chain that drops forwarded traffic, as Docker sets it. Checks:
//!
//! - nett adds its accept at the top of the `FORWARD` chain, and iptables still reads the chain;
//! - phone reaches m's services and g; work reaches the allowed port on m and nothing else;
//! - m cannot open a connection to phone, which no rule allows;
//! - g's status lists both devices with a handshake;
//! - With IPv4 forwarding turned off on g, g lists the problem within its next check, and the
//!   problem goes once forwarding is back on;
//! - After `nett site device remove phone`, phone no longer reaches m;
//! - Once work is removed too, g is no longer a gateway and the rule in `FORWARD` is gone.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use nett_mesh::key::PrivateKey;
use nett_site::state::State;

use super::hub::{HUB_PORT, HubLab, desired};
use super::{Lab, LabNode, Report, nett_status};
use crate::cmd::{run, run_in};
use crate::net::{DEVICE_NETNS, INET_NETNS, Underlay, add_netns, attach};
use crate::topology::Topology;

/// Upper bound for a device's first connection through the gateway: the gateway's path to m comes
/// up after the change is delivered.
const REACH: Duration = Duration::from_secs(45);
/// Upper bound for a change to show on the gateway: the forwarding is installed again every 60 s.
const RETRY: Duration = Duration::from_secs(90);
/// How long a connection attempt that should be blocked is given.
const BLOCKED: Duration = Duration::from_secs(3);
const COMMENT: &str = "nett: devices through this mobile gateway";

pub fn devices(topology: &Path, nett: &Path, out: &Path) -> anyhow::Result<Report> {
    let topo = Topology::load(topology)?;
    let underlay = Underlay::plan(&topo)?;
    let mut namespaces = std::collections::BTreeMap::new();
    for name in ["h", "g", "m"] {
        let net = underlay
            .node(name)
            .with_context(|| format!("the devices scenario needs a node `{name}`"))?;
        namespaces.insert(name, net.netns.clone());
    }
    let ns = |name: &str| -> anyhow::Result<String> {
        namespaces.get(name).cloned().context("planned node")
    };
    let (ns_h, ns_g, ns_m) = (ns("h")?, ns("g")?, ns("m")?);
    let net_h = underlay.node("h").context("planned node")?;
    let hub_ip = net_h.public_ipv4.unwrap_or(net_h.ipv4);
    underlay.down()?;
    let mut report = Report::new("devices");
    std::fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;
    underlay.up(&topo)?;
    let mut lab = Lab {
        underlay,
        processes: Vec::new(),
        relays: Vec::new(),
        helpers: Vec::new(),
    };

    // g forwards, and drops forwarded traffic by default, as a Docker host does
    run_in(&ns_g, "sysctl", ["-w", "net.ipv4.ip_forward=1"])?;
    run_in(&ns_g, "nft", ["add", "table", "ip", "filter"])?;
    run_in(
        &ns_g,
        "nft",
        ["add chain ip filter FORWARD { type filter hook forward priority 0 ; policy drop ; }"],
    )?;

    // The site and the Hub in h; g and m join through the Hub
    let site = out.join("site");
    std::fs::remove_dir_all(&site).ok();
    let hub_dir = out.join("hub");
    std::fs::remove_dir_all(&hub_dir).ok();
    std::fs::create_dir_all(&hub_dir)?;
    run(
        &nett.display().to_string(),
        ["site", "init", "--dir", &site.to_string_lossy()],
    )?;
    crate::material::self_signed(hub_ip, &hub_dir)?;
    let mut h = HubLab {
        nett,
        hub_bin: nett.with_file_name("nett-hub"),
        site: site.clone(),
        hub_dir: hub_dir.clone(),
        hub_ns: ns_h.clone(),
        hub_ip,
        site_ns: ns_h.clone(),
        members: vec!["g".into(), "m".into()],
        hub: None,
    };
    let init = run_in(
        &ns_h,
        &h.hub_bin.display().to_string(),
        [
            "init",
            "--data",
            &hub_dir.to_string_lossy(),
            "--url",
            &format!("https://{hub_ip}:{HUB_PORT}"),
            "--tls-cert",
            &hub_dir.join("tls-cert.pem").to_string_lossy(),
        ],
    )?;
    let code = init
        .split_whitespace()
        .find(|w| w.starts_with("nett_lnk_"))
        .context("nett-hub init printed no link code")?
        .to_owned();
    h.start_hub()?;
    h.site_cmd(&["link", &code])?;
    let mut nodes = Vec::new();
    for (name, public) in [("g", true), ("m", false)] {
        let mut args = vec!["add", name, "--yes"];
        if public {
            args.push("--public");
        }
        let added = h.site_cmd(&args)?;
        let token = added
            .split_whitespace()
            .find(|w| w.starts_with("nett_enr_"))
            .context("nett site add printed no token")?
            .to_owned();
        let dir = out.join(name);
        std::fs::remove_dir_all(&dir).ok();
        run(
            &nett.display().to_string(),
            ["keys", "--dir", &dir.to_string_lossy()],
        )?;
        run_in(
            &ns(name)?,
            &nett.display().to_string(),
            ["join", &token, "--dir", &dir.to_string_lossy()],
        )?;
        let doc = desired(&dir.join("desired.json"))?;
        let state = State::from_json(&std::fs::read(site.join("state.json"))?)?;
        let m = state.machine(&name.parse()?)?;
        let node = LabNode {
            name: name.to_owned(),
            node_id: doc.node_id.clone(),
            mesh_public_key: PrivateKey::load(&dir.join("mesh.key"))?.public_key(),
            mesh_ipv4: m.mesh.ipv4,
            mesh_ipv6: m.mesh.ipv6,
            edge_ipv4: None,
            dir: dir.clone(),
            tls: false,
            userspace: false,
        };
        // Joined: the daemon also connects to the Hub (ADR 0013)
        lab.spawn(&node, nett)?;
        nodes.push(node);
    }
    let (g, m) = (&nodes[0], &nodes[1]);
    for port in [8080u16, 2222] {
        lab.helper_in(
            &ns_m,
            &[
                "accept-log",
                "--listen",
                &format!("0.0.0.0:{port}"),
                "--out",
                &out.join(format!("accept-m-{port}.txt")).to_string_lossy(),
            ],
            &out.join(format!("accept-m-{port}.log")),
        )?;
    }

    let configs = out.join("devices");
    std::fs::remove_dir_all(&configs).ok();
    std::fs::create_dir_all(&configs)?;
    let configs_arg = configs.to_string_lossy().into_owned();
    for (name, limited) in [("phone", false), ("work", true)] {
        let mut args = vec!["device", "add", name, "--out", &configs_arg, "--yes"];
        if limited {
            args.push("--limited");
        } else {
            // The first device names its gateway; the second comes through the same one
            args.extend(["--gateway", "g"]);
        }
        let deadline = Instant::now() + REACH;
        let added = loop {
            match h.site_cmd(&args) {
                Ok(o) => break Ok(o),
                // The site needs g's address, which the Hub learns once g connects
                Err(e)
                    if Instant::now() < deadline
                        && format!("{e:#}").contains("no known public address") =>
                {
                    std::thread::sleep(Duration::from_secs(1));
                }
                Err(e) => break Err(e),
            }
        };
        report.check(
            &format!("device:{name}:added"),
            added.as_ref().is_ok_and(|o| {
                o.contains(&format!("+ {name} (device"))
                    && o.contains("through g")
                    && (limited || o.contains("~ g: mobile gateway for devices"))
            }),
            added
                .as_ref()
                .map_or_else(|e| format!("{e:#}"), Clone::clone),
        );
    }
    let allowed = h.site_cmd(&["allow", "work", "m", "8080/tcp", "--yes"]);
    report.check(
        "allow:work-to-m",
        allowed.is_ok(),
        allowed.unwrap_or_else(|e| format!("{e:#}")),
    );

    // The devices: plain WireGuard from the exported configurations
    let mut addresses = Vec::new();
    for (i, name) in ["phone", "work"].into_iter().enumerate() {
        let conf = configs.join(format!("{name}.conf"));
        if !conf.exists() {
            report.check(
                &format!("device:{name}:configuration"),
                false,
                format!("{} was not written", conf.display()),
            );
            return Ok(report);
        }
        let netns = DEVICE_NETNS[i];
        add_netns(netns)?;
        attach(netns, INET_NETNS, &format!("v-dev{i}"), "br0")?;
        run(
            "ip",
            [
                "-n",
                netns,
                "addr",
                "add",
                &format!("198.51.100.{}/24", 90 + i),
                "dev",
                "eth0",
            ],
        )?;
        addresses.push(wireguard_device(netns, &conf, out)?);
    }
    let (phone_ns, work_ns) = (DEVICE_NETNS[0], DEVICE_NETNS[1]);
    lab.helper_in(
        phone_ns,
        &[
            "accept-log",
            "--listen",
            "0.0.0.0:2222",
            "--out",
            &out.join("accept-phone.txt").to_string_lossy(),
        ],
        &out.join("accept-phone.log"),
    )?;

    let status = || nett_status(nett, g);
    let chain = || run_in(&ns_g, "nft", ["list", "chain", "ip", "filter", "FORWARD"]);
    let added = until(RETRY, || chain().is_ok_and(|c| c.contains(COMMENT)));
    report.check(
        "forward-chain:accept-added",
        added,
        chain()
            .unwrap_or_else(|e| format!("{e:#}"))
            .replace('\n', "; "),
    );
    let iptables = run_in(&ns_g, "iptables", ["-S", "FORWARD"]);
    report.check(
        "forward-chain:iptables-reads-it",
        iptables
            .as_ref()
            .is_ok_and(|o| o.contains("-A FORWARD -i nett0 -o nett0") && o.contains("-j ACCEPT")),
        iptables.map_or_else(|e| format!("{e:#}"), |o| o.replace('\n', "; ")),
    );

    let me = std::env::current_exe().context("locating nett-lab")?;
    let connect = |netns: &str, to: SocketAddr, secs: u64| -> String {
        run_in(
            netns,
            &me.to_string_lossy(),
            [
                "connect",
                "--to",
                to.to_string().as_str(),
                "--duration",
                secs.to_string().as_str(),
            ],
        )
        .map_or_else(|e| format!("error {e:#}"), |o| o.trim().to_owned())
    };
    let reaches =
        |netns: &str, to: SocketAddr| until(REACH, || connect(netns, to, 2) == "connected");
    let m_ip = std::net::IpAddr::V4(m.mesh_ipv4);
    report.check(
        "phone:reaches-m",
        reaches(phone_ns, SocketAddr::new(m_ip, 8080)),
        "phone connects to m:8080",
    );
    report.check(
        "phone:reaches-m-other-port",
        connect(phone_ns, SocketAddr::new(m_ip, 2222), 3) == "connected",
        "phone connects to m:2222",
    );
    let ping_g = run_in(
        phone_ns,
        "ping",
        ["-c", "2", "-W", "2", &g.mesh_ipv4.to_string()],
    );
    report.check(
        "phone:reaches-g",
        ping_g.is_ok(),
        ping_g.map_or_else(
            |e| format!("{e:#}"),
            |o| o.lines().last().unwrap_or_default().to_owned(),
        ),
    );
    report.check(
        "work:reaches-allowed-port",
        reaches(work_ns, SocketAddr::new(m_ip, 8080)),
        "work connects to m:8080",
    );
    let other = connect(work_ns, SocketAddr::new(m_ip, 2222), BLOCKED.as_secs());
    report.check(
        "work:other-port-blocked",
        other.starts_with("blocked"),
        format!("work to m:2222: {other}"),
    );
    let to_g = run_in(
        work_ns,
        "ping",
        ["-c", "1", "-W", "2", &g.mesh_ipv4.to_string()],
    );
    report.check("work:g-blocked", to_g.is_err(), "work cannot ping g");
    let back = connect(
        &ns_m,
        SocketAddr::new(std::net::IpAddr::V4(addresses[0]), 2222),
        BLOCKED.as_secs(),
    );
    report.check(
        "m-to-phone:blocked",
        back.starts_with("blocked"),
        format!("m to phone:2222: {back}"),
    );
    let listed = status().ok().and_then(|s| s.gateway);
    report.check(
        "gateway:status-lists-devices",
        listed.as_ref().is_some_and(|gw| {
            gw.devices.len() == 2 && gw.devices.iter().all(|d| d.last_handshake.is_some())
        }),
        format!("{listed:?}"),
    );

    // Forwarding turned off: the gateway lists it at its next check
    run_in(&ns_g, "sysctl", ["-w", "net.ipv4.ip_forward=0"])?;
    let problem = until(RETRY, || {
        status().is_ok_and(|s| {
            s.problems
                .iter()
                .any(|p| p.reason.contains("carries devices but does not forward"))
        })
    });
    report.check(
        "forwarding-off:listed",
        problem,
        "the gateway lists IPv4 forwarding off",
    );
    run_in(&ns_g, "sysctl", ["-w", "net.ipv4.ip_forward=1"])?;
    let recovered = until(RETRY, || {
        status().is_ok_and(|s| {
            !s.problems
                .iter()
                .any(|p| p.reason.contains("does not forward"))
        })
    });
    report.check(
        "forwarding-on:recovered",
        recovered,
        "the problem goes once forwarding is back on",
    );

    // Removing phone revokes it; removing work and the gateway takes the rule out of FORWARD
    let removed = h.site_cmd(&["device", "remove", "phone", "--yes"]);
    report.check(
        "phone:removed",
        removed.is_ok(),
        removed.unwrap_or_else(|e| format!("{e:#}")),
    );
    let stopped = until(RETRY, || {
        connect(phone_ns, SocketAddr::new(m_ip, 8080), 2).starts_with("blocked")
    });
    report.check("phone:stopped", stopped, "phone no longer reaches m");
    let last = h.site_cmd(&["device", "remove", "work", "--yes"]);
    report.check(
        "gateway:gone-with-the-last-device",
        last.as_ref()
            .is_ok_and(|o| o.contains("~ g: no longer a mobile gateway")),
        last.unwrap_or_else(|e| format!("{e:#}")),
    );
    let gone = until(RETRY, || chain().is_ok_and(|c| !c.contains(COMMENT)));
    report.check(
        "forward-chain:accept-removed",
        gone,
        chain()
            .unwrap_or_else(|e| format!("{e:#}"))
            .replace('\n', "; "),
    );

    // The device namespaces go with the lab's other namespaces when it is dropped
    drop(lab);
    Ok(report)
}

/// Sets up `wg0` in `netns` from an exported WireGuard configuration, as a WireGuard client would,
/// and returns the device's IPv4 address.
fn wireguard_device(netns: &str, conf: &Path, out: &Path) -> anyhow::Result<Ipv4Addr> {
    let text =
        std::fs::read_to_string(conf).with_context(|| format!("reading {}", conf.display()))?;
    let field = |key: &str| -> anyhow::Result<String> {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{key} = ")))
            .map(str::to_owned)
            .with_context(|| format!("{} has no {key}", conf.display()))
    };
    let key_file: PathBuf = out.join(format!("{netns}.key"));
    std::fs::write(&key_file, format!("{}\n", field("PrivateKey")?))?;
    let address: Ipv4Addr = field("Address")?
        .split(',')
        .next()
        .and_then(|a| a.trim().split('/').next())
        .context("an IPv4 address")?
        .parse()?;
    run(
        "ip",
        ["-n", netns, "link", "add", "wg0", "type", "wireguard"],
    )?;
    let allowed = field("AllowedIPs")?.replace(' ', "");
    run_in(
        netns,
        "wg",
        [
            "set",
            "wg0",
            "private-key",
            &key_file.to_string_lossy(),
            "peer",
            &field("PublicKey")?,
            "endpoint",
            &field("Endpoint")?,
            "allowed-ips",
            &allowed,
            "persistent-keepalive",
            "25",
        ],
    )?;
    run(
        "ip",
        [
            "-n",
            netns,
            "addr",
            "add",
            &format!("{address}/32"),
            "dev",
            "wg0",
        ],
    )?;
    run(
        "ip",
        ["-n", netns, "link", "set", "wg0", "mtu", "1280", "up"],
    )?;
    for prefix in allowed.split(',') {
        if prefix.contains('.') {
            run("ip", ["-n", netns, "route", "add", prefix, "dev", "wg0"])?;
        }
    }
    Ok(address)
}

/// Whether `ok` holds within `limit`, checked every half second.
fn until(limit: Duration, mut ok: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    loop {
        if ok() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}
