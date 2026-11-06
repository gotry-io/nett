//! `nett-lab`：实验工具，只用于开发和测试，不进发布包（design/prototype.md）。
//!
//! 它调用 `ip`、`nft`、`tc`、`wg` 等外部命令搭建实验网络，需要 root，只能在 Linux 上运行。
//! 被测的 `nett` 用 `lab` 特性构建：`cargo build -p nett-cli --features lab`。

#[cfg(target_os = "linux")]
mod cmd;
#[cfg(target_os = "linux")]
mod material;
#[cfg(target_os = "linux")]
mod net;
#[cfg(target_os = "linux")]
mod scenario;
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
  nett-lab run admission --topology <file.toml> --nett <path/to/nett> --out <dir>
  nett-lab down --topology <file.toml>";

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
    while let Some(arg) = parser.next()? {
        match arg {
            Value(v) => words.push(v.string()?),
            Long("topology") => topology = Some(PathBuf::from(parser.value()?)),
            Long("nett") => nett = Some(PathBuf::from(parser.value()?)),
            Long("out") => out = Some(PathBuf::from(parser.value()?)),
            Long("help") => {
                println!("{USAGE}");
                return Ok(true);
            }
            other => return Err(other.unexpected().into()),
        }
    }
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    let topology = topology.context(USAGE)?;
    match words.as_slice() {
        ["run", "admission"] => {
            let nett = nett.context(USAGE)?;
            let out = out.context(USAGE)?;
            let report = scenario::admission(&topology, &nett, &out)?;
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
            let topo = topology::Topology::load(&topology)?;
            net::Underlay::plan(&topo)?.down()?;
            Ok(true)
        }
        _ => anyhow::bail!("{USAGE}"),
    }
}
