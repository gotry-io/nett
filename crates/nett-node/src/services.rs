//! nett's services on a machine set up by `sudo nett install` (design/hub.md section 5, design/
//! release.md section 7): the nett service itself and, on Linux, the relay, which runs only while
//! the desired state needs it; the units follow the program through upgrades. Every call is
//! blocking (it runs systemctl or launchctl): async callers use a blocking thread.

use std::path::Path;

use nett_mesh::config::DesiredMeshDoc;

#[cfg(not(target_os = "macos"))]
pub use systemd::{reconcile, refresh_units};

/// The optional services a desired state needs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Wants {
    /// This machine runs a relay.
    pub relay: bool,
}

impl Wants {
    pub fn of(doc: &DesiredMeshDoc) -> Self {
        Self {
            relay: doc.relay.is_some(),
        }
    }
}

/// Whether nett's services on this machine are the ones `sudo nett install` set up: systemd units
/// on Linux, the launchd service on macOS.
pub fn managed() -> bool {
    #[cfg(target_os = "macos")]
    return Path::new(crate::platform::macos::PROGRAM).exists()
        && Path::new(crate::launchd::DAEMON.plist).exists();
    #[cfg(not(target_os = "macos"))]
    {
        use crate::platform::linux;
        cfg!(target_os = "linux")
            && Path::new(linux::PROGRAM).exists()
            && Path::new(&linux::DAEMON.path()).exists()
            && linux::systemctl().is_some()
    }
}

/// macOS has no optional services to follow the desired state.
#[cfg(target_os = "macos")]
pub fn reconcile(_wants: Wants) -> Vec<String> {
    Vec::new()
}

/// After an upgrade the launchd configuration follows the program (design/release.md section 7);
/// launchd reads it the next time it loads the service. Returns `false`: the service keeps
/// running.
#[cfg(target_os = "macos")]
pub fn refresh_units() -> Result<bool, String> {
    crate::launchd::refresh()?;
    Ok(false)
}

/// systemd units on Linux.
#[cfg(not(target_os = "macos"))]
mod systemd {
    use std::time::Duration;

    use std::path::Path;

    use super::Wants;
    use crate::platform::linux::{self, Flavor, RELAY, Unit};

    /// Time limit of one systemctl call (hard rule 14).
    const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(30);

    fn systemctl(args: &[&str]) -> Result<bool, String> {
        let program = linux::systemctl().ok_or("systemctl is not on this machine")?;
        crate::platform::run(program, args, SYSTEMCTL_TIMEOUT)
    }

    /// Runs the relay to match `wants`: wanted, it gets its unit and is enabled and started;
    /// otherwise it is stopped and disabled, and its unit deleted (design/release.md section 8).
    /// Returns what it could not do.
    pub fn reconcile(wants: Wants) -> Vec<String> {
        let optional = Flavor::detect().optional();
        let mut problems = Vec::new();
        // Nothing runs a relay on DSM (design/dsm.md section 2)
        if !optional.contains(&RELAY) {
            if wants.relay {
                problems.push(
                    "this machine's desired state runs a relay, which nett does not run on Synology DSM"
                        .to_owned(),
                );
            }
            return problems;
        }
        if let Err(e) = set_running(RELAY, wants.relay) {
            tracing::warn!(unit = RELAY.name, error = %e, "changing the relay service");
            problems.push(e);
        }
        problems
    }

    fn set_running(unit: Unit, want: bool) -> Result<(), String> {
        let path = unit.path();
        #[cfg(target_os = "linux")]
        if want && unit == RELAY {
            crate::layout::ensure_relay_cert(Path::new(linux::RELAY_CERT_DIR))?;
        }
        if want {
            if std::fs::read(&path).ok().as_deref() != Some(unit.content.as_bytes()) {
                write_unit(&path, unit.content).map_err(|e| format!("writing {path}: {e}"))?;
                daemon_reload()?;
            }
        } else if !Path::new(&path).exists() {
            return Ok(());
        }
        let active = systemctl(&["is-active", "--quiet", unit.name])?;
        let enabled = systemctl(&["is-enabled", "--quiet", unit.name])?;
        let action = match (want, active && enabled, active || enabled) {
            (true, false, _) => Some("enable"),
            (false, _, true) => Some("disable"),
            _ => None,
        };
        if let Some(action) = action {
            if !systemctl(&[action, "--now", unit.name])? {
                return Err(format!(
                    "systemctl could not {action} {}; see `journalctl -u {}`",
                    unit.what, unit.name
                ));
            }
            tracing::info!(unit = unit.name, action, "relay service changed");
        }
        if !want {
            std::fs::remove_file(&path).map_err(|e| format!("removing {path}: {e}"))?;
            daemon_reload()?;
        }
        Ok(())
    }

    fn daemon_reload() -> Result<(), String> {
        if systemctl(&["daemon-reload"])? {
            Ok(())
        } else {
            Err("systemctl daemon-reload failed".into())
        }
    }

    /// After an upgrade the units may have changed with the program (design/release.md section 7):
    /// rewrites the ones that differ from the embedded copies, reloads systemd, and restarts the relay
    /// when its unit changed and it runs; the relay's is only rewritten while it exists. Returns
    /// whether the nett service's own unit changed: it then exits, and systemd starts it again with
    /// the new unit.
    pub fn refresh_units() -> Result<bool, String> {
        let flavor = Flavor::detect();
        let mut changed = Vec::new();
        for &unit in flavor.units() {
            let path = unit.path();
            if flavor.optional().contains(&unit) && !Path::new(&path).exists() {
                continue;
            }
            if std::fs::read(&path).ok().as_deref() == Some(unit.content.as_bytes()) {
                continue;
            }
            write_unit(&path, unit.content).map_err(|e| format!("writing {path}: {e}"))?;
            changed.push(unit);
        }
        if changed.is_empty() {
            return Ok(false);
        }
        daemon_reload()?;
        let mut own = false;
        for unit in changed {
            tracing::info!(unit = unit.name, "unit updated with the program");
            if unit.name == linux::DAEMON_UNIT {
                own = true;
            } else if !systemctl(&["try-restart", unit.name])? {
                tracing::warn!(
                    unit = unit.name,
                    "restarting a service with its new unit failed"
                );
            }
        }
        Ok(own)
    }

    /// Writes a unit through a temporary file, mode `0644`.
    fn write_unit(path: &str, content: &str) -> std::io::Result<()> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let tmp = format!("{path}.new");
        let _ = std::fs::remove_file(&tmp);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&tmp)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::linux::{RELAY, UNITS};

    #[test]
    fn services_follow_the_desired_state() {
        use nett_site::dir::{SiteDir, new_node_id};
        use nett_site::ops::MachineOptions;
        use nett_site::state::{NodeKeys, RelayKey, RelayRole};
        use nett_trust::keys::X25519PublicKey;
        let dir_tmp = tempfile::Builder::new()
            .prefix("nett-node-wants-")
            .tempdir()
            .expect("temp dir");
        let dir = dir_tmp.path().join("dir");
        let _ = std::fs::remove_dir_all(&dir);
        SiteDir::init(&dir, "https://nett.invalid").expect("init");
        let site = SiteDir::open(&dir).expect("open");
        let mut state = site.load().expect("load");
        let name = |s: &str| s.parse().expect("name");
        for (n, k, public) in [("vps", 1u8, true), ("mac", 3, false), ("nas", 5, false)] {
            state
                .add(
                    name(n),
                    MachineOptions {
                        public,
                        ipv4: public.then(|| "203.0.113.10".parse().expect("ip")),
                        keys: Some(NodeKeys {
                            mesh: X25519PublicKey::from_bytes([k; 32]),
                            identity: X25519PublicKey::from_bytes([k + 1; 32]),
                        }),
                        ..MachineOptions::default()
                    },
                    new_node_id().expect("id"),
                )
                .expect("add");
        }
        state
            .allow(&["mac".into()], &["nas".into()], vec![], None)
            .expect("allow");
        let desired = |state: &nett_site::state::State, n: &str| {
            nett_site::compose::desired(state, &name(n))
                .expect("composed")
                .expect("signed")
        };
        let sign = |state: &mut nett_site::state::State| {
            nett_site::sign::sign(
                state,
                &site.recovery().expect("key"),
                nett_trust::encoding::Timestamp::now(),
                &[],
            )
            .expect("signed");
        };
        sign(&mut state);
        assert_eq!(Wants::of(&desired(&state, "vps")), Wants::default());
        let role = |fingerprint| RelayRole {
            port: 41822,
            tls_port: Some(443),
            fingerprint,
            obfs_port: None,
        };
        state
            .set_relay(
                &name("vps"),
                Some(role(None)),
                RelayKey([9; 32]),
                nett_mesh::config::ObfsPadding { min: 16, max: 200 },
            )
            .expect("relay");
        sign(&mut state);
        assert_eq!(Wants::of(&desired(&state, "vps")), Wants { relay: true });
        assert_eq!(Wants::of(&desired(&state, "mac")), Wants::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_unit_runs_the_installed_program() {
        for unit in UNITS {
            assert!(
                unit.content.contains("ExecStart=/usr/local/lib/nett/nett "),
                "{}",
                unit.name
            );
        }
        // The relay runs as a user systemd allocates while it runs (design/release.md section 8)
        assert!(RELAY.content.contains("\nDynamicUser=yes\n"));
        assert!(
            crate::platform::linux::DAEMON
                .content
                .contains(crate::platform::linux::UNIT_DIR),
            "the nett service may write the unit directory"
        );
    }
}
