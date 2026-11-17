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
    pub const RELAY_UNIT: &str = nett_mesh::helper::RELAY_UNIT;
    pub const TRANSPORT_UNIT: &str = nett_mesh::helper::TRANSPORT_UNIT;
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
    /// The units whose files exist only while the desired state needs them (design/release.md
    /// section 8).
    pub const OPTIONAL: [Unit; 2] = [RELAY, TRANSPORT];

    /// The units on Synology DSM (design/dsm.md section 6): same names, written for its systemd 219,
    /// running as root with bounded capabilities and started by the boot task.
    pub const DSM_MESH: Unit = Unit {
        name: MESH_UNIT,
        content: include_str!("../../../packaging/systemd/dsm/nett-mesh.service"),
        what: "the mesh service",
    };
    pub const DSM_NODE: Unit = Unit {
        name: NODE_UNIT,
        content: include_str!("../../../packaging/systemd/dsm/nett-node.service"),
        what: "nett-node",
    };
    /// Files that exist on Synology DSM and nowhere else; `os_name` and the other keys have moved
    /// between DSM versions, the files have not.
    pub const DSM_MARKERS: [&str; 2] = ["/etc.defaults/VERSION", "/etc.defaults/synoinfo.conf"];

    /// Which systemd nett's units are written for.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Flavor {
        /// systemd as current distributions ship it (design/release.md section 5).
        Systemd,
        /// Synology DSM: systemd 219, no system accounts, a boot task (design/dsm.md section 6).
        Dsm,
    }

    impl Flavor {
        pub fn detect() -> Self {
            if DSM_MARKERS.iter().all(|p| std::path::Path::new(p).exists()) {
                Self::Dsm
            } else {
                Self::Systemd
            }
        }

        pub fn mesh(self) -> Unit {
            match self {
                Self::Systemd => MESH,
                Self::Dsm => DSM_MESH,
            }
        }

        pub fn node(self) -> Unit {
            match self {
                Self::Systemd => NODE,
                Self::Dsm => DSM_NODE,
            }
        }

        /// Every unit this flavor installs.
        pub fn units(self) -> &'static [Unit] {
            match self {
                Self::Systemd => &UNITS,
                Self::Dsm => &[DSM_MESH, DSM_NODE],
            }
        }

        /// The units that follow the desired state. DSM has none: the mesh process carries the TLS
        /// transport there, and relays run elsewhere (design/dsm.md sections 2 and 7).
        pub fn optional(self) -> &'static [Unit] {
            match self {
                Self::Systemd => &OPTIONAL,
                Self::Dsm => &[],
            }
        }

        /// Whether the mesh process carries the TLS transport itself (ADR 0013).
        pub fn mesh_carries_tls(self) -> bool {
            self == Self::Dsm
        }
    }
    /// The trust store, in the identity directory; the mesh service writes it (design/release.md
    /// section 8).
    pub const STATE_DIR: &str = "/etc/nett/state";
    /// The relay's TLS certificate, root only: systemd hands it to the relay.
    pub const RELAY_CERT_DIR: &str = "/etc/nett/relay";
    /// Where 0.3.13 and earlier kept the trust store and the relay's certificate and bindings, and
    /// the system users the relay and the transport adapter ran as (design/release.md section 8).
    pub const OLD_STATE_DIR: &str = "/var/lib/nett";
    pub const OLD_RELAY_DIR: &str = "/var/lib/nett-relay";
    pub const OLD_ACCOUNTS: [&str; 2] = ["nett-relay", "nett-transport"];

    /// The optional units installed now.
    pub fn installed_optional() -> Vec<Unit> {
        Flavor::detect()
            .optional()
            .iter()
            .copied()
            .filter(|u| std::path::Path::new(&u.path()).exists())
            .collect()
    }
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

/// The most of a command's standard output nett reads (hard rule 14).
const OUTPUT_LIMIT: u64 = 256 * 1024;

/// Like [`run`], and also returns what the program wrote to standard output, up to
/// [`OUTPUT_LIMIT`]; the rest is read and dropped, so the program never blocks on a full pipe.
pub fn run_output(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<(bool, String), String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("running {program} {}: {e}", args.join(" ")))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("reading the output of {program}"))?;
    let reader = std::thread::spawn(move || {
        use std::io::Read as _;
        let mut out = Vec::new();
        let _ = (&mut stdout).take(OUTPUT_LIMIT).read_to_end(&mut out);
        let _ = std::io::copy(&mut stdout, &mut std::io::sink());
        out
    });
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("waiting for {program}: {e}"))?
        {
            let out = reader.join().unwrap_or_default();
            return Ok((status.success(), String::from_utf8_lossy(&out).into_owned()));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            return Err(format!(
                "{program} {} did not finish in time",
                args.join(" ")
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
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

#[cfg(test)]
mod tests {
    use super::linux::{DSM_MESH, DSM_NODE, Flavor, MESH, NODE, PROGRAM, Unit};

    /// `Section.Directive` for each setting in a unit file.
    fn directives(unit: &Unit) -> Vec<String> {
        let mut section = String::new();
        let mut found = Vec::new();
        for line in unit.content.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                section = name.to_owned();
                continue;
            }
            let key = line.split('=').next().unwrap_or_default().trim();
            found.push(format!("{section}.{key}"));
        }
        found
    }

    /// DSM's systemd accepts a directive it does not implement with only a warning, so a unit
    /// could look confined and not be (design/dsm.md section 3)
    #[test]
    fn dsm_units_use_only_what_systemd_219_implements() {
        let known: Vec<&str> = include_str!("systemd-219.txt")
            .lines()
            .filter(|l| !l.starts_with('#'))
            .collect();
        for unit in [&DSM_MESH, &DSM_NODE] {
            for directive in directives(unit) {
                assert!(
                    known.contains(&directive.as_str()),
                    "{}: {directive} is not implemented by systemd 219",
                    unit.name
                );
            }
        }
        // The check bites: the unit for current systemd uses what 219 lacks
        assert!(
            directives(&MESH)
                .iter()
                .any(|d| !known.contains(&d.as_str()))
        );
        for missing in [
            "Service.AmbientCapabilities",
            "Service.DynamicUser",
            "Service.LoadCredential",
            "Service.ReadWritePaths",
            "Service.MemoryMax",
            "Service.RestrictAddressFamilies",
        ] {
            assert!(!known.contains(&missing), "{missing}");
        }
    }

    /// The boot task starts them, root with bounded capabilities, the file system read-only but for
    /// their own directories (design/dsm.md section 6.1)
    #[test]
    fn dsm_units_are_root_with_bounded_capabilities() {
        for unit in [&DSM_MESH, &DSM_NODE] {
            assert!(!unit.content.contains("[Install]"), "{}", unit.name);
            assert!(!unit.content.contains("\nUser="), "{}", unit.name);
            assert!(
                unit.content.contains("\nNoNewPrivileges=yes\n"),
                "{}",
                unit.name
            );
            assert!(
                unit.content.contains("\nReadOnlyDirectories=/\n"),
                "{}",
                unit.name
            );
            assert!(
                unit.content.contains(&format!("\nExecStart={PROGRAM} ")),
                "{}",
                unit.name
            );
        }
        assert!(
            DSM_MESH.content.contains(
                "\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE\n"
            )
        );
        assert!(DSM_MESH.content.contains("--key /etc/nett/mesh.key"));
        assert!(
            DSM_MESH
                .content
                .contains("\nReadWriteDirectories=/etc/nett/state /run/nett\n")
        );
        assert!(
            DSM_NODE
                .content
                .contains("\nCapabilityBoundingSet=CAP_DAC_OVERRIDE\n")
        );
    }

    #[test]
    fn flavors_share_unit_names() {
        for flavor in [Flavor::Systemd, Flavor::Dsm] {
            assert_eq!(flavor.mesh().name, MESH.name);
            assert_eq!(flavor.node().name, NODE.name);
        }
        assert!(Flavor::Dsm.optional().is_empty());
        assert_eq!(Flavor::Dsm.units(), &[DSM_MESH, DSM_NODE]);
        assert!(Flavor::Dsm.mesh_carries_tls() && !Flavor::Systemd.mesh_carries_tls());
    }
}
