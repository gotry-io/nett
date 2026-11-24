//! Where nett's services live on each platform (design/release.md sections 4, 5 and 7), and the
//! way their service managers are called. `sudo nett install` writes this layout and the nett
//! service upgrades the program in it, so both read the paths and names from here.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Linux: the program in its own root-owned directory, linked from the command path; systemd
/// units run it from there.
pub mod linux {
    pub const CONFIG_DIR: &str = "/etc/nett";
    pub const PROGRAM_DIR: &str = "/usr/local/lib/nett";
    pub const PROGRAM: &str = "/usr/local/lib/nett/nett";
    pub const LINK: &str = "/usr/local/bin/nett";
    pub const DAEMON_UNIT: &str = "nett.service";
    pub const RELAY_UNIT: &str = nett_mesh::helper::RELAY_UNIT;
    /// Where `sudo nett install` writes the units and the nett service refreshes them after an
    /// upgrade: the directory for units of locally installed software (files of the same name in
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

    pub const DAEMON: Unit = Unit {
        name: DAEMON_UNIT,
        content: include_str!("../../../packaging/systemd/nett.service"),
        what: "the nett service",
    };
    pub const RELAY: Unit = Unit {
        name: RELAY_UNIT,
        content: include_str!("../../../packaging/systemd/nett-relay.service"),
        what: "the relay's TLS entry",
    };
    pub const UNITS: [Unit; 2] = [DAEMON, RELAY];
    /// The units whose files exist only while the desired state needs them (design/release.md
    /// section 8).
    pub const OPTIONAL: [Unit; 1] = [RELAY];

    /// The unit on Synology DSM (design/dsm.md section 6): the same name, written for its systemd
    /// 219, running as root with bounded capabilities and started by the boot task.
    pub const DSM_DAEMON: Unit = Unit {
        name: DAEMON_UNIT,
        content: include_str!("../../../packaging/systemd/dsm/nett.service"),
        what: "the nett service",
    };
    /// Files that exist on Synology DSM and nowhere else; `os_name` and the other keys have moved
    /// between DSM versions, the files have not.
    pub const DSM_MARKERS: [&str; 2] = ["/etc.defaults/VERSION", "/etc.defaults/synoinfo.conf"];

    /// Which systemd nett's units are written for.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Flavor {
        /// systemd as current distributions ship it (design/release.md section 5).
        Systemd,
        /// Synology DSM: systemd 219, a boot task (design/dsm.md section 6).
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

        pub fn daemon(self) -> Unit {
            match self {
                Self::Systemd => DAEMON,
                Self::Dsm => DSM_DAEMON,
            }
        }

        /// Every unit this flavor installs.
        pub fn units(self) -> &'static [Unit] {
            match self {
                Self::Systemd => &UNITS,
                Self::Dsm => &[DSM_DAEMON],
            }
        }

        /// The units that follow the desired state. DSM has none: relays run elsewhere
        /// (design/dsm.md section 2).
        pub fn optional(self) -> &'static [Unit] {
            match self {
                Self::Systemd => &OPTIONAL,
                Self::Dsm => &[],
            }
        }
    }
    /// The relay's TLS certificate, root only: systemd hands it to the relay.
    pub const RELAY_CERT_DIR: &str = "/etc/nett/relay";

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
    /// The launchd service that runs `nett daemon` (ADR 0013).
    pub const LABEL: &str = "io.gotry.nett";
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
    use super::linux::{DAEMON, DSM_DAEMON, Flavor, PROGRAM, RELAY, Unit};

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
    fn the_dsm_unit_uses_only_what_systemd_219_implements() {
        let known: Vec<&str> = include_str!("systemd-219.txt")
            .lines()
            .filter(|l| !l.starts_with('#'))
            .collect();
        for directive in directives(&DSM_DAEMON) {
            assert!(
                known.contains(&directive.as_str()),
                "{directive} is not implemented by systemd 219"
            );
        }
        // The check bites: the unit for current systemd uses what 219 lacks
        assert!(
            directives(&DAEMON)
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

    /// The nett service runs as root with only the network capabilities it uses, the file system
    /// read-only but for its own directories, and starts again after it exits to run a new release
    /// (ADR 0013, design/release.md section 7, design/dsm.md section 6.1)
    #[test]
    fn the_nett_service_is_root_with_bounded_capabilities() {
        for unit in [&DAEMON, &DSM_DAEMON] {
            assert!(!unit.content.contains("\nUser="), "{}", unit.name);
            assert!(
                unit.content.contains(
                    "\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE\n"
                ),
                "{}",
                unit.name
            );
            assert!(
                unit.content.contains("\nNoNewPrivileges=yes\n"),
                "{}",
                unit.name
            );
            assert!(unit.content.contains("\nRestart=always\n"), "{}", unit.name);
            assert!(
                unit.content
                    .contains(&format!("\nExecStart={PROGRAM} daemon --dir /etc/nett\n")),
                "{}",
                unit.name
            );
        }
        assert!(DAEMON.content.contains("\nProtectSystem=strict\n"));
        assert!(DAEMON.content.contains(
            "\nReadWritePaths=/etc/nett /usr/local/lib/nett /usr/local/lib/systemd/system\n"
        ));
        assert!(!DSM_DAEMON.content.contains("[Install]"));
        assert!(DSM_DAEMON.content.contains("\nReadOnlyDirectories=/\n"));
        assert!(DSM_DAEMON.content.contains(
            "\nReadWriteDirectories=/etc/nett /usr/local/lib/nett /usr/local/lib/systemd/system /run/nett\n"
        ));
        // The relay is the one service that listens publicly: a user of its own, no root
        assert!(RELAY.content.contains("\nDynamicUser=yes\n"));
        assert!(
            RELAY
                .content
                .contains("\nAfter=network-online.target nett.service\n")
        );
    }

    #[test]
    fn flavors_share_unit_names() {
        for flavor in [Flavor::Systemd, Flavor::Dsm] {
            assert_eq!(flavor.daemon().name, DAEMON.name);
        }
        assert!(Flavor::Dsm.optional().is_empty());
        assert_eq!(Flavor::Dsm.units(), &[DSM_DAEMON]);
    }
}
