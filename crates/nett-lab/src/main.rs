//! `nett-lab`：实验工具，只用于开发和测试，不进发布包（design/prototype.md）。
//!
//! 它调用 `ip`、`nft`、`tc`、`wg` 等外部命令搭建实验网络，需要 root，只能在 Linux 上运行。
//! 被测的 `nett` 用 `lab` 特性构建：`cargo build -p nett-cli --features lab`。

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
  nett-lab run <admission|selftest|relay-smoke> --topology <file.toml> --nett <path/to/nett> --out <dir>
  nett-lab run tailscale --topology <file.toml> --out <dir>
  nett-lab run wgport --topology <file.toml> --nett <path/to/nett> --out <dir>
  nett-lab run roaming --topology <file.toml> --nett <path/to/nett> --out <dir> [--duration SECONDS]
  nett-lab run <loss|jitter|flap|alternate> --topology <file.toml> --nett <path/to/nett> --out <dir> [--level N] [--duration SECONDS] [--repeat N] [--with-tailscale]
  nett-lab run <failover|relay-loss|relay-restart> --topology <file.toml> --nett <path/to/nett> --out <dir> [--repeat N] [--with-tailscale]
  nett-lab run dial-only-switch --topology <file.toml> --nett <path/to/nett> --out <dir> [--repeat N]
  nett-lab run dial-only-outage --topology <file.toml> --nett <path/to/nett> --out <dir> [--clock-skew MS] [--repeat N] [--with-tailscale]
  nett-lab down --topology <file.toml>
measurement helpers (started by the scenarios inside a node's network namespace):
  nett-lab probe-send --to <addr:port>
  nett-lab probe-recv --listen <addr:port> --out <file>
  nett-lab tcp-source --to <addr:port>
  nett-lab tcp-sink --listen <addr:port> --out <file>
  nett-lab forge --to <addr:port>";

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
            Long("help") => {
                println!("{USAGE}");
                return Ok(true);
            }
            other => return Err(other.unexpected().into()),
        }
    }
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["probe-send"] => measure::probe_send(to.context(USAGE)?).map(|()| true),
        ["probe-recv"] => {
            measure::probe_recv(listen.context(USAGE)?, &out.context(USAGE)?).map(|()| true)
        }
        ["tcp-source"] => measure::tcp_source(to.context(USAGE)?).map(|()| true),
        ["forge"] => measure::forge(to.context(USAGE)?, 300).map(|()| true),
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
                "failover" => {
                    scenario::failover(&topology, &nett()?, &out, repeat, with_tailscale)?
                }
                "wgport" => scenario::wg_port(&topology, &nett()?, &out)?,
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
        ["down"] => {
            let topo = topology::Topology::load(&topology.context(USAGE)?)?;
            net::Underlay::plan(&topo)?.down()?;
            Ok(true)
        }
        _ => anyhow::bail!("{USAGE}"),
    }
}
