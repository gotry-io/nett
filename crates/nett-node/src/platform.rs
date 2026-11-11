//! Where nett's services live on each platform (design/release.md sections 4, 5 and 7), and the
//! way their service managers are called. `sudo nett install` writes this layout and nett-node
//! upgrades the program in it, so both read the paths and names from here.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Linux: the program in its own root-owned directory, linked from the command path; systemd
/// units run it from there.
pub mod linux {
    pub const CONFIG_DIR: &str = "/etc/nett";
    pub const PROGRAM_DIR: &str = "/usr/local/lib/nett";
    pub const PROGRAM: &str = "/usr/local/lib/nett/nett";
    pub const LINK: &str = "/usr/local/bin/nett";
    pub const MESH_UNIT: &str = "nett-mesh.service";
    pub const NODE_UNIT: &str = "nett-node.service";
    pub const RELAY_UNIT: &str = "nett-relay.service";
    pub const TRANSPORT_UNIT: &str = "nett-transport.service";
    /// Where `sudo nett install` writes the units and nett-node refreshes them after an upgrade:
    /// the directory for units of locally installed software (files of the same name in
    /// `/etc/systemd/system` override them).
    pub const UNIT_DIR: &str = "/usr/local/lib/systemd/system";

    /// A systemd unit of nett: the file in `packaging/systemd/`, embedded at compile time so that
    /// its content has a single source and follows the program through upgrades.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Unit {
        pub name: &'static str,
        pub content: &'static str,
        /// What it is, for messages.
        pub what: &'static str,
    }

    impl Unit {
        pub fn path(&self) -> String {
            format!("{UNIT_DIR}/{}", self.name)
        }
    }

    pub const MESH: Unit = Unit {
        name: MESH_UNIT,
        content: include_str!("../../../packaging/systemd/nett-mesh.service"),
        what: "the mesh service",
    };
    pub const NODE: Unit = Unit {
        name: NODE_UNIT,
        content: include_str!("../../../packaging/systemd/nett-node.service"),
        what: "nett-node",
    };
    pub const RELAY: Unit = Unit {
        name: RELAY_UNIT,
        content: include_str!("../../../packaging/systemd/nett-relay.service"),
        what: "the relay",
    };
    pub const TRANSPORT: Unit = Unit {
        name: TRANSPORT_UNIT,
        content: include_str!("../../../packaging/systemd/nett-transport.service"),
        what: "the transport adapter",
    };
    pub const UNITS: [Unit; 4] = [MESH, NODE, RELAY, TRANSPORT];
    /// Fixed locations of systemctl (hard rule 9): most distributions use the former, older ones
    /// the latter.
    pub const SYSTEMCTL: [&str; 2] = ["/usr/bin/systemctl", "/bin/systemctl"];

    /// The systemctl on this machine.
    pub fn systemctl() -> Option<&'static str> {
        SYSTEMCTL
            .into_iter()
            .find(|p| std::path::Path::new(p).exists())
    }
}

/// macOS: a root-only copy of the program next to the keys, run by launchd; the command line
/// installed by the install script is a separate copy.
pub mod macos {
    pub const DIR: &str = "/Library/Application Support/nett";
    pub const PROGRAM: &str = "/Library/Application Support/nett/nett";
    pub const COMMAND: &str = "/usr/local/bin/nett";
    pub const LAUNCHCTL: &str = "/bin/launchctl";
    pub const MESH_LABEL: &str = "io.gotry.nett.mesh";
    pub const NODE_LABEL: &str = "io.gotry.nett.node";
}

/// Runs a service manager command (hard rule 9: a fixed absolute path, arguments as an array, no
/// shell) with a time limit (hard rule 14). Returns whether it succeeded.
pub fn run(program: &str, args: &[&str], timeout: Duration) -> Result<bool, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("running {program} {}: {e}", args.join(" ")))?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("waiting for {program}: {e}"))?
        {
            return Ok(status.success());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "{program} {} did not finish in time",
                args.join(" ")
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
