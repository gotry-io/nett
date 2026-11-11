//! nett's services on a Linux machine set up by `sudo nett install` (design/hub.md section 5,
//! design/release.md section 7): the relay and the transport adapter run only while the desired state
//! needs them, and the units follow the program through upgrades. Every call is blocking (it runs
//! systemctl): async callers use a blocking thread.

use std::path::Path;
use std::time::Duration;

use nett_mesh::config::{Candidate, DesiredMeshDoc};

use crate::platform::linux::{self, MESH, RELAY, TRANSPORT, UNITS, Unit};

/// Time limit of one systemctl call (hard rule 14).
const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(30);

/// The optional services a desired state needs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Wants {
    /// This machine runs a relay.
    pub relay: bool,
    /// This machine has a path over TLS.
    pub transport: bool,
}

impl Wants {
    pub fn of(doc: &DesiredMeshDoc) -> Self {
        Self {
            relay: doc.relay.is_some(),
            transport: doc
                .paths
                .iter()
                .flat_map(|p| &p.candidates)
                .any(|c| matches!(c, Candidate::RelayTls { .. })),
        }
    }
}

/// Whether nett's services on this machine are systemd units that `sudo nett install` wrote.
pub fn managed() -> bool {
    cfg!(target_os = "linux")
        && Path::new(linux::PROGRAM).exists()
        && Path::new(&MESH.path()).exists()
        && linux::systemctl().is_some()
}

fn systemctl(args: &[&str]) -> Result<bool, String> {
    let program = linux::systemctl().ok_or("systemctl is not on this machine")?;
    crate::platform::run(program, args, SYSTEMCTL_TIMEOUT)
}

/// Enables and starts, or stops and disables, the relay and the transport adapter to match `wants`.
/// Returns what it could not do.
pub fn reconcile(wants: Wants) -> Vec<String> {
    let mut problems = Vec::new();
    for (unit, want) in [(RELAY, wants.relay), (TRANSPORT, wants.transport)] {
        if let Err(e) = set_running(unit, want) {
            tracing::warn!(unit = unit.name, error = %e, "changing an optional service");
            problems.push(e);
        }
    }
    problems
}

fn set_running(unit: Unit, want: bool) -> Result<(), String> {
    let active = systemctl(&["is-active", "--quiet", unit.name])?;
    let enabled = systemctl(&["is-enabled", "--quiet", unit.name])?;
    let action = match (want, active && enabled, active || enabled) {
        (true, false, _) => "enable",
        (false, _, true) => "disable",
        _ => return Ok(()),
    };
    if systemctl(&[action, "--now", unit.name])? {
        tracing::info!(unit = unit.name, action, "optional service changed");
        Ok(())
    } else {
        Err(format!(
            "systemctl could not {action} {}; see `journalctl -u {}`",
            unit.what, unit.name
        ))
    }
}

/// After an upgrade the units may have changed with the program (design/release.md section 7):
/// rewrites the ones that differ from the embedded copies, reloads systemd, and restarts the changed
/// services that are running. Returns whether nett-node's own unit changed: it then exits, and
/// systemd starts it again with the new unit.
pub fn refresh_units() -> Result<bool, String> {
    let mut changed = Vec::new();
    for unit in UNITS {
        let path = unit.path();
        if std::fs::read(&path).ok().as_deref() == Some(unit.content.as_bytes()) {
            continue;
        }
        write_unit(&path, unit.content).map_err(|e| format!("writing {path}: {e}"))?;
        changed.push(unit);
    }
    if changed.is_empty() {
        return Ok(false);
    }
    if !systemctl(&["daemon-reload"])? {
        return Err("systemctl daemon-reload failed".into());
    }
    let mut own = false;
    for unit in changed {
        tracing::info!(unit = unit.name, "unit updated with the program");
        if unit.name == linux::NODE_UNIT {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn services_follow_the_desired_state() {
        use nett_site::dir::{SiteDir, new_node_id};
        use nett_site::ops::MachineOptions;
        use nett_site::state::{NodeKeys, RelayKey, RelayRole};
        use nett_trust::keys::X25519PublicKey;
        let dir = std::env::temp_dir().join(format!("nett-node-wants-{}", std::process::id()));
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
        };
        state
            .set_relay(&name("vps"), Some(role(None)), RelayKey([9; 32]))
            .expect("relay");
        sign(&mut state);
        let relay_only = Wants {
            relay: true,
            transport: false,
        };
        assert_eq!(Wants::of(&desired(&state, "vps")), relay_only);
        assert_eq!(
            Wants::of(&desired(&state, "mac")),
            Wants::default(),
            "no TLS path before the relay's fingerprint is known"
        );
        let fingerprint = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            .parse()
            .expect("fingerprint");
        state
            .set_relay(
                &name("vps"),
                Some(role(Some(fingerprint))),
                RelayKey([9; 32]),
            )
            .expect("relay");
        sign(&mut state);
        assert_eq!(
            Wants::of(&desired(&state, "mac")),
            Wants {
                relay: false,
                transport: true
            }
        );
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
        assert!(RELAY.content.contains("\nUser=nett-relay\n"));
        assert!(TRANSPORT.content.contains("\nUser=nett-transport\n"));
        assert!(TRANSPORT.content.contains("\nCapabilityBoundingSet=\n"));
        assert!(
            crate::platform::linux::NODE
                .content
                .contains(crate::platform::linux::UNIT_DIR),
            "nett-node may write the unit directory"
        );
    }
}
