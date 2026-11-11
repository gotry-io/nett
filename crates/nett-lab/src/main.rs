//! `nett-lab`: lab tool, used only for development and testing, not included in release packages
//! (design/prototype.md).
//!
//! It calls external commands such as `ip`, `nft`, `tc` and `wg` to build the lab network; it needs
//! root and runs only on Linux. The `nett` under test is built with the `lab` feature: `cargo build
//! -p nett-cli --features lab`.

#[cfg(target_os = "linux")]
mod cmd;
#[cfg(target_os = "linux")]
mod fault;
#[cfg(target_os = "linux")]
mod material;
#[cfg(target_os = "linux")]
mod measure;
#[cfg(target_os = "linux")]
mod net;
#[cfg(target_os = "linux")]
mod scenario;
#[cfg(target_os = "linux")]
mod tailscale;
#[cfg(target_os = "linux")]
mod topology;

use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(2),
        Err(e) => {
            eprintln!("nett-lab: {e:#}");
            ExitCode::FAILURE
        }
    }
}

const USAGE: &str = "usage:
  every `run` also takes [--userspace <node>] (repeatable): that node uses the userspace data plane
  nett-lab run <admission|selftest|relay-smoke> --topology <file.toml> --nett <path/to/nett> --out <dir>
  nett-lab run tailscale --topology <file.toml> --out <dir>
  nett-lab run wgport --topology <file.toml> --nett <path/to/nett> --out <dir>
  nett-lab run roaming --topology <file.toml> --nett <path/to/nett> --out <dir> [--duration SECONDS]
  nett-lab run <loss|jitter|flap|alternate> --topology <file.toml> --nett <path/to/nett> --out <dir> [--level N] [--duration SECONDS] [--repeat N] [--with-tailscale]
  nett-lab run <failover|fallback|relay-loss|relay-restart> --topology <file.toml> --nett <path/to/nett> --out <dir> [--repeat N] [--with-tailscale]
  nett-lab run punch --topology <punch-*.toml> --nett <path/to/nett> --out <dir> [--repeat N] [--with-tailscale]
  nett-lab run mtu --topology <mtu4.toml|mtu6.toml> --nett <path/to/nett> --out <dir> [--bytes N]
  nett-lab run <wg-rehandshake|wg-cookie|wg-rekey> --topology relays.toml --nett <path/to/nett> --out <dir> [--repeat N] [--duration SECONDS]
  nett-lab run congestion --topology <relay-only.toml|fallback.toml> --nett <path/to/nett> --out <dir> [--level KBIT] [--duration SECONDS] [--repeat N] [--with-tailscale]
  nett-lab run resources --topology fallback.toml --nett <path/to/release/nett> --out <dir> [--duration IDLE_SECONDS]
  nett-lab run dial-only-switch --topology <file.toml> --nett <path/to/nett> --out <dir> [--repeat N]
  nett-lab run dial-only-outage --topology <file.toml> --nett <path/to/nett> --out <dir> [--clock-skew MS] [--repeat N] [--with-tailscale]
  nett-lab run access --topology access.toml --nett <path/to/nett> --out <dir>
  nett-lab run hub --topology direct.toml --nett <path/to/nett> --out <dir> [--soak SECONDS]
      (nett-hub next to nett; --soak then keeps changing and pinging, samples memory into
      soak.csv, rests 10 minutes and checks that memory stayed flat)
  nett-lab run throughput --topology <direct.toml|relay-only.toml> --nett <path/to/release/nett> --out <dir> [--duration SECONDS]
      (iperf3 over the underlying network and the mesh; add --userspace a --userspace b to compare)
  nett-lab run hub-relay --topology hub-relay.toml --nett <path/to/nett> --out <dir>
      (members join through the Hub; a relay, its TLS fingerprint learned, and TLS fallback)
  nett-lab down --topology <file.toml>
  nett-lab material --topology <real-machines.toml> --out <dir>   (lab B: configs for real machines)
measurement helpers (started by the scenarios inside a node's network namespace):
  nett-lab probe-send --to <addr:port>
  nett-lab probe-recv --listen <addr:port> --out <file>
  nett-lab tcp-source --to <addr:port>
  nett-lab tcp-sink --listen <addr:port> --out <file>
  nett-lab accept-log --listen <addr:port> --out <file>
  nett-lab connect --to <addr:port> --duration SECONDS
  nett-lab bulk-send --to <addr:port> --bytes N
  nett-lab bulk-recv --listen <addr:port> --bytes N --out <file>
  nett-lab forge --to <addr:port>
  nett-lab flood --to <addr:port> --key <hex public key> [--duration SECONDS]
Hub helpers (started by the hub scenario inside a node's network namespace):
  nett-lab leave --out <node dir>                         tell the Hub, remove the mesh interface";

#[cfg(not(target_os = "linux"))]
fn run() -> anyhow::Result<bool> {
    anyhow::bail!(
        "nett-lab builds lab networks with Linux network namespaces; run it on Linux\n{USAGE}"
    )
}

#[cfg(target_os = "linux")]
fn run() -> anyhow::Result<bool> {
    use std::path::PathBuf;

    use anyhow::Context as _;
    use lexopt::Arg::{Long, Value};
    use lexopt::ValueExt as _;

    let mut parser = lexopt::Parser::from_env();
    let mut words = Vec::new();
    let (mut topology, mut nett, mut out) = (None, None, None);
    let (mut to, mut listen) = (None, None);
    let (mut repeat, mut with_tailscale) = (1usize, false);
    let (mut level, mut duration_s) = (None::<u64>, 300u64);
    let mut clock_skew_ms = 0i64;
    let mut bytes = None::<u64>;
    let mut key = None::<String>;
    let mut userspace = Vec::new();
    let mut soak = None::<u64>;
    while let Some(arg) = parser.next()? {
        match arg {
            Value(v) => words.push(v.string()?),
            Long("to") => to = Some(parser.value()?.string()?.parse::<std::net::SocketAddr>()?),
            Long("listen") => {
                listen = Some(parser.value()?.string()?.parse::<std::net::SocketAddr>()?)
            }
            Long("topology") => topology = Some(PathBuf::from(parser.value()?)),
            Long("nett") => nett = Some(PathBuf::from(parser.value()?)),
            Long("out") => out = Some(PathBuf::from(parser.value()?)),
            Long("repeat") => repeat = parser.value()?.string()?.parse()?,
            Long("with-tailscale") => with_tailscale = true,
            Long("level") => level = Some(parser.value()?.string()?.parse()?),
            Long("duration") => duration_s = parser.value()?.string()?.parse()?,
            Long("clock-skew") => clock_skew_ms = parser.value()?.string()?.parse()?,
            Long("bytes") => bytes = Some(parser.value()?.string()?.parse()?),
            Long("key") => key = Some(parser.value()?.string()?),
            Long("userspace") => userspace.push(parser.value()?.string()?),
            Long("soak") => soak = Some(parser.value()?.string()?.parse()?),
            Long("help") => {
                println!("{USAGE}");
                return Ok(true);
            }
            other => return Err(other.unexpected().into()),
        }
    }
    // Switch the specified nodes to the userspace data plane: write a modified topology into the
    // output directory, which the scenario reads
    if !userspace.is_empty() {
        let (path, out) = (topology.context(USAGE)?, out.as_ref().context(USAGE)?);
        topology = Some(topology::with_userspace(&path, &userspace, out)?);
    }
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["probe-send"] => measure::probe_send(to.context(USAGE)?).map(|()| true),
        ["leave"] => scenario::leave_here(&out.context(USAGE)?).map(|()| true),
        ["probe-recv"] => {
            measure::probe_recv(listen.context(USAGE)?, &out.context(USAGE)?).map(|()| true)
        }
        ["tcp-source"] => measure::tcp_source(to.context(USAGE)?).map(|()| true),
        ["accept-log"] => {
            measure::accept_log(listen.context(USAGE)?, &out.context(USAGE)?).map(|()| true)
        }
        ["connect"] => measure::connect(
            to.context(USAGE)?,
            std::time::Duration::from_secs(duration_s),
        )
        .map(|()| true),
        ["forge"] => measure::forge(to.context(USAGE)?, 300).map(|()| true),
        ["flood"] => {
            let hex = key.context(USAGE)?;
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| {
                    hex.get(i..i + 2)
                        .and_then(|h| u8::from_str_radix(h, 16).ok())
                })
                .collect::<Option<_>>()
                .context("--key must be 64 hex digits")?;
            let key: [u8; 32] = bytes
                .try_into()
                .ok()
                .context("--key must be 64 hex digits")?;
            measure::flood(to.context(USAGE)?, &key, duration_s).map(|()| true)
        }
        ["bulk-send"] => {
            measure::bulk_send(to.context(USAGE)?, bytes.context(USAGE)?).map(|()| true)
        }
        ["bulk-recv"] => measure::bulk_recv(
            listen.context(USAGE)?,
            bytes.context(USAGE)?,
            &out.context(USAGE)?,
        )
        .map(|()| true),
        ["tcp-sink"] => {
            measure::tcp_sink(listen.context(USAGE)?, &out.context(USAGE)?).map(|()| true)
        }
        ["run", name] => {
            let topology = topology.context(USAGE)?;
            let out = out.context(USAGE)?;
            let nett = || nett.clone().context(USAGE);
            let report = match *name {
                "admission" => scenario::admission(&topology, &nett()?, &out)?,
                "selftest" => scenario::selftest(&topology, &nett()?, &out)?,
                "relay-smoke" => scenario::relay_smoke(&topology, &nett()?, &out)?,
                "failover" | "fallback" => {
                    let cut = if *name == "failover" {
                        scenario::Cut::Direct
                    } else {
                        scenario::Cut::AllUdp
                    };
                    scenario::failover(&topology, &nett()?, &out, repeat, with_tailscale, cut)?
                }
                "wgport" => scenario::wg_port(&topology, &nett()?, &out)?,
                "access" => scenario::access(&topology, &nett()?, &out)?,
                "hub" => scenario::hub(&topology, &nett()?, &out, soak)?,
                "hub-relay" => scenario::hub_relay(&topology, &nett()?, &out)?,
                "throughput" => scenario::throughput(&topology, &nett()?, &out, duration_s)?,
                "roaming" => scenario::roaming(
                    &topology,
                    &nett()?,
                    &out,
                    std::time::Duration::from_secs(duration_s),
                )?,
                "loss" | "jitter" | "flap" | "alternate" => {
                    let wave = match *name {
                        "loss" => scenario::Wave::Loss(level.context("--level <percent>")? as f32),
                        "jitter" => scenario::Wave::Jitter(level.context("--level <ms>")? as u32),
                        "alternate" => {
                            scenario::Wave::Alternate(level.context("--level <ms>")? as u32)
                        }
                        _ => scenario::Wave::Flap,
                    };
                    let duration = std::time::Duration::from_secs(duration_s);
                    scenario::wave(
                        &topology,
                        &nett()?,
                        &out,
                        repeat,
                        with_tailscale,
                        wave,
                        duration,
                    )?
                }
                "relay-loss" | "relay-restart" => {
                    let kind = if *name == "relay-loss" {
                        scenario::RelayFault::Loss
                    } else {
                        scenario::RelayFault::Restart
                    };
                    scenario::relay_fault(&topology, &nett()?, &out, repeat, with_tailscale, kind)?
                }
                "dial-only-switch" | "dial-only-outage" => {
                    let fault = if *name == "dial-only-switch" {
                        scenario::PairFault::Slow
                    } else {
                        scenario::PairFault::Outage {
                            skew_ms: clock_skew_ms,
                        }
                    };
                    scenario::dial_only_pair(
                        &topology,
                        &nett()?,
                        &out,
                        repeat,
                        with_tailscale,
                        fault,
                    )?
                }
                "punch" => scenario::punch(&topology, &nett()?, &out, repeat, with_tailscale)?,
                "mtu" => scenario::mtu(&topology, &nett()?, &out, bytes.unwrap_or(1 << 30))?,
                "wg-cookie" => scenario::wg_cookie(&topology, &nett()?, &out)?,
                "wg-rehandshake" => scenario::wg_rehandshake(&topology, &nett()?, &out, repeat)?,
                "resources" => scenario::resources(
                    &topology,
                    &nett()?,
                    &out,
                    std::time::Duration::from_secs(duration_s),
                )?,
                "wg-rekey" => scenario::wg_rekey(
                    &topology,
                    &nett()?,
                    &out,
                    std::time::Duration::from_secs(duration_s),
                )?,
                "congestion" => scenario::congestion(
                    &topology,
                    &nett()?,
                    &out,
                    (repeat, with_tailscale),
                    level.map_or(2000, |l| l as u32),
                    std::time::Duration::from_secs(duration_s),
                )?,
                "tailscale" => scenario::tailscale(&topology, &out)?,
                _ => anyhow::bail!("unknown scenario `{name}`\n{USAGE}"),
            };
            for check in &report.checks {
                println!(
                    "{} {} {}",
                    if check.passed { "PASS" } else { "FAIL" },
                    check.name,
                    check.detail
                );
            }
            println!(
                "{}: {}",
                report.scenario,
                if report.passed { "PASS" } else { "FAIL" }
            );
            Ok(report.passed)
        }
        ["material"] => {
            let topo = topology::Topology::load(&topology.context(USAGE)?)?;
            let out = out.context(USAGE)?;
            let generated = material::generate_remote(&topo, &out)?;
            for node in &generated.nodes {
                let ssh = topo
                    .node(&node.name)
                    .and_then(|n| n.ssh.clone())
                    .unwrap_or_default();
                println!(
                    "{} {ssh} {} {}",
                    node.name,
                    node.mesh_ipv4,
                    node.dir.display()
                );
            }
            Ok(true)
        }
        ["down"] => {
            let topo = topology::Topology::load(&topology.context(USAGE)?)?;
            net::Underlay::plan(&topo)?.down()?;
            Ok(true)
        }
        _ => anyhow::bail!("{USAGE}"),
    }
}
