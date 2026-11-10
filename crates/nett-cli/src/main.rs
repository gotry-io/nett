//! `nett` 可执行文件：命令行（包括接入 Hub 之前的签名工具 `nett site`），以及 `nett mesh`、`nett transport`、
//! `nett relay` 各进程的入口（ADR 0012）。命令按作用范围分三组：整张网、这台机器、服务进程
//! （architecture.md 第 13.4 节）。

use std::ffi::OsString;
use std::process::ExitCode;

mod layout;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod mesh;
#[cfg(all(feature = "lab", target_os = "linux"))]
mod relay;
#[cfg(target_os = "macos")]
mod service;
mod site;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod status;
#[cfg(all(feature = "lab", target_os = "linux"))]
mod transport;

/// 一个命令：名字、在帮助中的分组、一句话说明和用法。用法写在实现它的模块里。
struct Command {
    name: &'static str,
    group: Group,
    summary: &'static str,
    usage: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Group {
    Network,
    Machine,
    Service,
}

const COMMANDS: &[Command] = &[
    Command {
        name: "site",
        group: Group::Network,
        summary: "Create a site, sign changes and write each node's desired state",
        usage: site::USAGE,
    },
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Command {
        name: "status",
        group: Group::Machine,
        summary: "Show this node and its peers",
        usage: status::USAGE,
    },
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Command {
        name: "reload",
        group: Group::Machine,
        summary: "Re-read the desired state and show whether it was accepted",
        usage: status::RELOAD_USAGE,
    },
    #[cfg(target_os = "macos")]
    Command {
        name: "install",
        group: Group::Machine,
        summary: "Install or update the mesh service",
        usage: service::INSTALL_USAGE,
    },
    #[cfg(target_os = "macos")]
    Command {
        name: "uninstall",
        group: Group::Machine,
        summary: "Remove the mesh service; keys and desired state stay",
        usage: service::UNINSTALL_USAGE,
    },
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Command {
        name: "keys",
        group: Group::Machine,
        summary: "Create this node's keys and print the line for the site description",
        usage: mesh::KEYS_USAGE,
    },
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Command {
        name: "mesh",
        group: Group::Service,
        summary: "The mesh process",
        usage: mesh::USAGE,
    },
    #[cfg(all(feature = "lab", target_os = "linux"))]
    Command {
        name: "relay",
        group: Group::Service,
        summary: "The relay process (lab build)",
        usage: relay::USAGE,
    },
    #[cfg(all(feature = "lab", target_os = "linux"))]
    Command {
        name: "transport",
        group: Group::Service,
        summary: "The transport adapter process (lab build)",
        usage: transport::USAGE,
    },
];

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
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let Some(first) = args.first().and_then(|a| a.to_str()) else {
        print!("{}", help());
        return Ok(());
    };
    match first {
        "help" | "--help" | "-h" => {
            match args.get(1).and_then(|a| a.to_str()) {
                Some(name) => print!("{}", command_help(find(name)?)),
                None => print!("{}", help()),
            }
            return Ok(());
        }
        "--version" | "-V" => {
            println!("nett {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        _ => {}
    }
    let command = find(first)?;
    if args[1..].iter().any(|a| a == "--help" || a == "-h") {
        print!("{}", command_help(command));
        return Ok(());
    }
    let parser = lexopt::Parser::from_args(args[1..].iter().cloned());
    match command.name {
        "site" => site::run(parser),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        "status" => status::run(parser),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        "reload" => status::reload(parser),
        #[cfg(target_os = "macos")]
        "install" => service::install_command(parser),
        #[cfg(target_os = "macos")]
        "uninstall" => service::uninstall_command(parser),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        "keys" => mesh::keys(parser),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        "mesh" => mesh::run(parser),
        #[cfg(all(feature = "lab", target_os = "linux"))]
        "relay" => relay::run(parser),
        #[cfg(all(feature = "lab", target_os = "linux"))]
        "transport" => transport::run(parser),
        _ => unreachable!("every listed command is dispatched"),
    }
}

fn find(name: &str) -> anyhow::Result<&'static Command> {
    if let Some(command) = COMMANDS.iter().find(|c| c.name == name) {
        return Ok(command);
    }
    // 服务只在 macOS 上由 nett 安装；Linux 上用项目提供的 systemd 单元（README）
    if cfg!(not(target_os = "macos")) && matches!(name, "install" | "uninstall") {
        anyhow::bail!(
            "`nett {name}` manages the macOS service; on Linux, use the systemd unit nett-mesh.service from the project's packaging/systemd directory"
        );
    }
    anyhow::bail!("unknown command `{name}`; run `nett help` to list the commands")
}

fn help() -> String {
    let mut out = format!(
        "nett {}\n\nUsage: nett <command> [options]\n",
        env!("CARGO_PKG_VERSION")
    );
    let width = COMMANDS.iter().map(|c| c.name.len()).max().unwrap_or(0);
    for (group, title) in [
        (
            Group::Network,
            "The network, on the computer that holds the site:",
        ),
        (Group::Machine, "This machine:"),
        (
            Group::Service,
            "Service processes, run by systemd, launchd or a container:",
        ),
    ] {
        out.push('\n');
        out.push_str(title);
        out.push('\n');
        for c in COMMANDS.iter().filter(|c| c.group == group) {
            out.push_str(&format!("  {:width$}  {}\n", c.name, c.summary));
        }
    }
    out.push_str("\nRun `nett <command> --help` for its options.\n");
    out
}

fn command_help(command: &Command) -> String {
    format!("{}\n\n{}\n", command.summary, command.usage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_lists_every_command_once_in_its_group() {
        let text = help();
        for c in COMMANDS {
            assert_eq!(
                text.matches(&format!("\n  {} ", c.name)).count(),
                1,
                "{}",
                c.name
            );
            assert!(c.usage.starts_with("usage: "), "{}", c.name);
        }
        assert!(text.starts_with(&format!("nett {}\n", env!("CARGO_PKG_VERSION"))));
    }

    #[test]
    fn unknown_commands_point_to_help() {
        let err = find("enroll").err().expect("unknown").to_string();
        assert_eq!(
            err,
            "unknown command `enroll`; run `nett help` to list the commands"
        );
    }
}
