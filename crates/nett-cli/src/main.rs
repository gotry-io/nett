//! `nett` executable: the command line (including the signing tool `nett site`) and the entry
//! points of the `nett mesh`, `nett node`, `nett transport` and `nett relay` processes (ADR 0012),
//! and of the container (`nett container`, ADR 0016).
//! Commands fall into three groups by scope: the whole mesh, this machine, service processes
//! (architecture.md section 13.4).

use std::ffi::OsString;
use std::process::ExitCode;

#[cfg(target_os = "linux")]
mod container;
mod device;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod diagnose;
#[cfg(target_os = "linux")]
mod dsm;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod hub;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod install;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod join;
mod layout;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod mesh;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod node;
#[cfg(target_os = "linux")]
mod relay;
#[cfg(target_os = "linux")]
mod resolver;
#[cfg(target_os = "macos")]
mod service;
#[cfg(target_os = "linux")]
mod service_linux;
mod site;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod status;
#[cfg(target_os = "linux")]
mod transport;

/// One command: name, group in the help, one-line description and usage. The usage text lives in
/// the module that implements it.
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
        name: "ping",
        group: Group::Machine,
        summary: "Probe a peer through the tunnel and show the path",
        usage: diagnose::PING_USAGE,
    },
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Command {
        name: "whois",
        group: Group::Machine,
        summary: "Show who a mesh address belongs to",
        usage: diagnose::WHOIS_USAGE,
    },
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Command {
        name: "doctor",
        group: Group::Machine,
        summary: "Check this machine and say what to fix",
        usage: diagnose::DOCTOR_USAGE,
    },
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Command {
        name: "reload",
        group: Group::Machine,
        summary: "Re-read the desired state and show whether it was accepted",
        usage: status::RELOAD_USAGE,
    },
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Command {
        name: "install",
        group: Group::Machine,
        summary: "Install or update the services; with a token, connect to the Hub",
        usage: install::INSTALL_USAGE,
    },
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Command {
        name: "uninstall",
        group: Group::Machine,
        summary: "Remove the services; keys and desired state stay",
        usage: install::UNINSTALL_USAGE,
    },
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Command {
        name: "join",
        group: Group::Machine,
        summary: "Join the site through the Hub without installing services",
        usage: install::JOIN_USAGE,
    },
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Command {
        name: "leave",
        group: Group::Machine,
        summary: "Leave the site: tell the Hub, remove the services and delete the keys",
        usage: install::LEAVE_USAGE,
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
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Command {
        name: "node",
        group: Group::Service,
        summary: "The control agent that connects this machine to its Hub",
        usage: node::USAGE,
    },
    #[cfg(target_os = "linux")]
    Command {
        name: "relay",
        group: Group::Service,
        summary: "The relay that forwards ciphertext between members",
        usage: relay::USAGE,
    },
    #[cfg(target_os = "linux")]
    Command {
        name: "resolver",
        group: Group::Service,
        summary: "Points names under nett.internal at this machine's responder",
        usage: resolver::USAGE,
    },
    #[cfg(target_os = "linux")]
    Command {
        name: "transport",
        group: Group::Service,
        summary: "The transport adapter that carries WireGuard over TLS",
        usage: transport::USAGE,
    },
    #[cfg(target_os = "linux")]
    Command {
        name: "container",
        group: Group::Service,
        summary: "The first process of nett's container image",
        usage: container::USAGE,
    },
];

fn main() -> ExitCode {
    // Each process uses very little memory, so transparent huge pages are not needed. When the
    // system is set to always (for example Linux 6.1), a thread stack is replaced as a whole by a 2
    // MB huge page and RSS grows by 2 MB (architecture.md section 13.1). Disabled before any thread
    // starts; where unsupported, memory is only a bit higher
    #[cfg(target_os = "linux")]
    rustix::thread::disable_transparent_huge_pages(true).ok();
    #[cfg(target_os = "macos")]
    let service = system_log::for_service();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("nett: {e:#}");
            #[cfg(target_os = "macos")]
            if service {
                system_log::error(&format!("nett: {e:#}"));
            }
            ExitCode::FAILURE
        }
    }
}

/// On macOS launchd gives the services no standard error, so what ends one, an error or a panic,
/// goes to the system log as everything else they log does (design/userspace.md section 6.3).
#[cfg(target_os = "macos")]
mod system_log {
    use std::io::IsTerminal as _;

    /// Whether this process is one of the services, run by launchd; when it is, panics are sent to
    /// the system log from here on.
    pub fn for_service() -> bool {
        let service = matches!(
            std::env::args_os()
                .nth(1)
                .as_deref()
                .and_then(|a| a.to_str()),
            Some("mesh" | "node")
        ) && !std::io::stderr().is_terminal();
        if service {
            let default = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                error(&format!("nett: {info}"));
                default(info);
            }));
        }
        service
    }

    pub fn error(line: &str) {
        nett_mesh::macos::SystemLog::open().write(tracing::Level::ERROR, line);
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
    #[cfg(target_os = "linux")]
    container::run_newest(command.name);
    let parser = lexopt::Parser::from_args(args[1..].iter().cloned());
    match command.name {
        "site" => site::run(parser),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        "status" => status::run(parser),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        "ping" => diagnose::ping(parser),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        "whois" => diagnose::whois(parser),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        "doctor" => diagnose::doctor(parser),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        "reload" => status::reload(parser),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        "install" => install::install_command(parser),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        "uninstall" => install::uninstall_command(parser),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        "leave" => install::leave_command(parser),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        "join" => install::join_command(parser),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        "keys" => mesh::keys(parser),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        "mesh" => mesh::run(parser),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        "node" => node::run(parser),
        #[cfg(target_os = "linux")]
        "relay" => relay::run(parser),
        #[cfg(target_os = "linux")]
        "transport" => transport::run(parser),
        #[cfg(target_os = "linux")]
        "resolver" => resolver::run(parser),
        #[cfg(target_os = "linux")]
        "container" => container::run(parser),
        _ => unreachable!("every listed command is dispatched"),
    }
}

fn find(name: &str) -> anyhow::Result<&'static Command> {
    if let Some(command) = COMMANDS.iter().find(|c| c.name == name) {
        return Ok(command);
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
