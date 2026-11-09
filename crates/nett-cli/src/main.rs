//! `nett` 可执行文件：命令行（包括接入 Hub 之前的签名工具 `nett site`），以及 `nett node`、`nett mesh`、
//! `nett transport`、`nett relay` 各进程的入口（ADR 0012）。

use std::process::ExitCode;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod mesh;
#[cfg(all(feature = "lab", target_os = "linux"))]
mod relay;
mod site;
mod text;
#[cfg(all(feature = "lab", target_os = "linux"))]
mod transport;

fn main() -> ExitCode {
    // 各进程的内存都很小，用不上透明大页。系统设为 always 时（例如 Linux 6.1），一个线程栈会被整块换成
    // 2 MB 的大页，RSS 随之多出 2 MB（architecture.md 第 13.1 节）。在启动任何线程之前关闭；不支持时
    // 只是内存多一些
    #[cfg(target_os = "linux")]
    rustix::thread::disable_transparent_huge_pages(true).ok();
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
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        lexopt::Arg::Value(cmd) if cmd == "mesh" => mesh::run(parser),
        lexopt::Arg::Value(cmd) if cmd == "site" => site::run(parser),
        #[cfg(all(feature = "lab", target_os = "linux"))]
        lexopt::Arg::Value(cmd) if cmd == "relay" => relay::run(parser),
        #[cfg(all(feature = "lab", target_os = "linux"))]
        lexopt::Arg::Value(cmd) if cmd == "transport" => transport::run(parser),
        lexopt::Arg::Long("version") => {
            println!("nett {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        other => Err(other.unexpected().into()),
    }
}
