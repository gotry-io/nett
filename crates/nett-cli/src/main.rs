//! `nett` 可执行文件：命令行，以及 `nett node`、`nett mesh`、`nett transport`、`nett relay` 各进程的入口（ADR 0012）。

use std::process::ExitCode;

#[cfg(all(feature = "lab", target_os = "linux"))]
mod mesh;
#[cfg(all(feature = "lab", target_os = "linux"))]
mod relay;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("nett: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> anyhow::Result<()> {
    let mut parser = lexopt::Parser::from_env();
    let Some(arg) = parser.next()? else {
        println!("nett {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    };
    match arg {
        #[cfg(all(feature = "lab", target_os = "linux"))]
        lexopt::Arg::Value(cmd) if cmd == "mesh" => mesh::run(parser),
        #[cfg(all(feature = "lab", target_os = "linux"))]
        lexopt::Arg::Value(cmd) if cmd == "relay" => relay::run(parser),
        lexopt::Arg::Long("version") => {
            println!("nett {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        other => Err(other.unexpected().into()),
    }
}
