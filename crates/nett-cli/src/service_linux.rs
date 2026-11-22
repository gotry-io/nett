//! Service installation on Linux (design/hub.md section 7): `sudo nett install` generates or reuses
//! the keys in `/etc/nett`, copies the running `nett` to `/usr/local/lib/nett/nett` with the link
//! `/usr/local/bin/nett` (design/release.md section 5), writes the systemd unit of the nett service
//! and starts it. The units are the files in `packaging/systemd/`, embedded at compile time, so their
//! content has a single source. Without a Hub, the desired state is imported with `--config`; with a
//! Hub (a token, or an existing Hub configuration) only the nett service writes it. `sudo nett
//! uninstall` removes everything but the identity, and `sudo nett leave` the identity
//! (design/release.md section 8).

use std::fs;
use std::path::Path;

use anyhow::{Context as _, bail};
use nett_node::config::HubConfig;

use crate::install::{
    InstallArgs, apply_token, copy_self, ensure_dir, replace_if_changed, require_root,
};

use nett_node::platform::linux::{
    CONFIG_DIR as DIR, DAEMON, Flavor, LINK, PROGRAM as BINARY, PROGRAM_DIR, RELAY, RELAY_CERT_DIR,
    Unit,
};

/// Where units of the same name override the ones nett installs.
const OVERRIDE_DIR: &str = "/etc/systemd/system";

fn systemctl(args: &[&str]) -> anyhow::Result<bool> {
    let Some(program) = nett_node::platform::linux::systemctl() else {
        bail!(
            "systemctl is not on this machine; without systemd, run `nett daemon --dir /etc/nett` with \
             your own service manager"
        );
    };
    crate::install::run(program, args)
}

/// Makes the service run with the new unit and program: starts it when not running (enabling it,
/// except on DSM, where the boot task starts it), restarts it when the unit or program changed.
/// Returns a one-sentence report.
fn ensure_running(unit: &Unit, restart: bool, flavor: Flavor) -> anyhow::Result<Option<String>> {
    let start: &[&str] = match flavor {
        Flavor::Systemd => &["enable", "--now", unit.name],
        Flavor::Dsm => &["start", unit.name],
    };
    let (ok, message) = if !systemctl(&["is-active", "--quiet", unit.name])? {
        (
            systemctl(start)?,
            format!("Started {} ({}).", unit.what, unit.name),
        )
    } else if restart {
        (
            systemctl(&["restart", unit.name])?,
            format!("Restarted {}.", unit.what),
        )
    } else {
        return Ok(None);
    };
    if !ok {
        bail!(
            "systemctl could not start {}; see `journalctl -u {}`",
            unit.name,
            unit.name
        );
    }
    Ok(Some(message))
}

pub fn install(args: &InstallArgs) -> anyhow::Result<()> {
    require_root()?;
    // A unit of the same name in /etc/systemd/system overrides the one nett installs, and would run an
    // older program with older settings: the administrator removes it
    let overrides: Vec<String> = [&DAEMON, &RELAY]
        .iter()
        .map(|u| format!("{OVERRIDE_DIR}/{}", u.name))
        .filter(|p| Path::new(p).exists())
        .collect();
    if !overrides.is_empty() {
        bail!(
            "{} overrides the unit nett installs in {}; move it away (for example to /root) and run \
             `systemctl daemon-reload`, then run this again",
            overrides.join(" and "),
            nett_node::platform::linux::UNIT_DIR
        );
    }
    let flavor = Flavor::detect();
    let unit = flavor.daemon();
    // The nett service runs as root, and the identity is root's alone
    ensure_dir(DIR, 0o700)?;
    std::os::unix::fs::chown(DIR, Some(0), Some(0))
        .with_context(|| format!("giving {DIR} to root"))?;
    let desired = Path::new(DIR).join(crate::daemon::DESIRED_FILE);
    let keys = crate::daemon::node_keys(Path::new(DIR))?;
    let token = apply_token(DIR, args.token.as_deref(), &keys.0)?;
    let hub_changed = token.hub_changed;
    let linked = HubConfig::load(Path::new(DIR))
        .map_err(anyhow::Error::msg)?
        .is_some();
    let desired_changed = match (token.desired, &args.config, linked) {
        // The first one the Hub sends when a new machine joins (design/hub.md section 6);
        // afterwards only the nett service writes it
        (Some(bytes), _, _) => replace_if_changed(&desired, &bytes, 0o600)?,
        (None, Some(_), true) => {
            bail!("this machine receives its desired state from its Hub; --config is not used")
        }
        (None, Some(path), false) => {
            let bytes = crate::site::read_desired(path)?
                .with_context(|| format!("{} is not a regular file", path.display()))?;
            crate::site::check_desired_for(&bytes, &keys.0)?;
            replace_if_changed(&desired, &bytes, 0o600)?
        }
        (None, None, _) => false,
    };
    ensure_dir(PROGRAM_DIR, 0o755)?;
    let binary_changed = copy_self(BINARY)?;
    if !ensure_link(LINK, BINARY)? {
        outln!("{LINK} belongs to another installer; the service runs {BINARY}.");
    }
    ensure_dir(nett_node::platform::linux::UNIT_DIR, 0o755)?;
    // The relay's unit is written only while the desired state needs it (design/release.md
    // section 8)
    let unit_changed = replace_if_changed(Path::new(&unit.path()), unit.content.as_bytes(), 0o644)?;
    if unit_changed && !systemctl(&["daemon-reload"])? {
        bail!("systemctl daemon-reload failed");
    }

    if !desired.exists() {
        crate::daemon::print_keys(Path::new(DIR), keys);
        outln!(
            "Installed {BINARY} and {}. Not started: {} does not exist yet.",
            unit.name,
            desired.display()
        );
        outln!(
            "Once the machine is in the site, copy its desired state here and run \
             `sudo nett install --config <desired.json>`."
        );
        return Ok(());
    }
    let mut messages = Vec::new();
    if flavor == Flavor::Dsm {
        messages.extend(crate::dsm::prepare_tun()?);
        messages.extend(crate::dsm::ensure_boot_task()?);
    }
    // With a new Hub configuration, the service starts nett-node afresh
    let restart = unit_changed || binary_changed || (linked && hub_changed);
    match ensure_running(&unit, restart, flavor)? {
        Some(m) => messages.push(m),
        None if desired_changed => out!(
            "{}",
            crate::status::reload_at(Path::new(nett_mesh::status::DEFAULT_SOCKET))?
        ),
        None => {}
    }
    // Without a Hub the relay follows the imported desired state; with one, the nett service starts
    // and stops it
    if !linked && let Some(doc) = read_doc(&desired) {
        let wants = nett_node::services::Wants::of(&doc);
        for problem in nett_node::services::reconcile(wants) {
            messages.push(problem);
        }
        if wants.relay {
            messages.push(format!(
                "{} runs; `nett status` shows its TLS fingerprint for `nett site relay --fingerprint`.",
                RELAY.what
            ));
        }
    }
    // A running relay keeps the old program until it restarts; try-restart leaves a stopped one
    // alone
    let helpers: Vec<Unit> = nett_node::platform::linux::installed_optional();
    if binary_changed && !helpers.is_empty() {
        let mut args = vec!["try-restart"];
        args.extend(helpers.iter().map(|u| u.name));
        if !systemctl(&args)? {
            messages.push(format!(
                "Restarting {} on the new program failed.",
                RELAY.what
            ));
        }
    }
    if messages.is_empty() && !desired_changed {
        messages.push("The service is running. Nothing changed.".to_owned());
    }
    if let Some(firewall) = crate::diagnose::check_host_firewall() {
        messages.push(format!(
            "Warning: {}.\n  → {}",
            firewall.found, firewall.advice
        ));
    }
    for m in messages {
        outln!("{m}");
    }
    if unit_changed || binary_changed {
        outln!("Logs: journalctl -u nett");
    }
    Ok(())
}

/// `sudo nett uninstall` (design/release.md section 8): removes the services, the mesh interface and
/// filter rules, the program and the upgrade records, and keeps this machine's identity.
pub fn uninstall() -> anyhow::Result<()> {
    require_root()?;
    remove_boot_task()?;
    remove_services()?;
    nett_mesh::linux::teardown().context("removing the mesh interface and filter rules")?;
    for name in ["nett", "nett.previous", "nett.new"] {
        crate::install::remove_file(&format!("{PROGRAM_DIR}/{name}"))?;
    }
    crate::install::remove_if_empty(PROGRAM_DIR)?;
    if fs::read_link(LINK).is_ok_and(|t| t == Path::new(BINARY)) {
        crate::install::remove_file(LINK)?;
    }
    crate::install::forget_upgrades(DIR)?;
    if crate::install::remove_if_empty(DIR)? {
        outln!("Removed nett. Nothing of it remains on this machine.");
    } else {
        outln!(
            "Removed nett. This machine's identity stays in {DIR}: `sudo nett install` brings it back \
             as the same member, and `sudo rm -r {DIR}` deletes it."
        );
    }
    Ok(())
}

/// `sudo nett leave` (design/hub.md section 7): tells the Hub, deletes the services, tears down the
/// mesh interface and filter rules, deletes the keys and configuration.
pub fn leave() -> anyhow::Result<()> {
    require_root()?;
    crate::install::tell_hub(DIR)?;
    remove_boot_task()?;
    remove_services()?;
    nett_mesh::linux::teardown().context("removing the mesh interface and filter rules")?;
    crate::install::forget(DIR)?;
    // The relay's certificate is part of this machine's identity
    crate::install::remove_tree(RELAY_CERT_DIR)?;
    crate::install::remove_if_empty(DIR)?;
    outln!(
        "Left the site: removed the services and the mesh interface, deleted the keys, the desired \
         state, the trust store and the Hub configuration. {BINARY} stays; `sudo nett uninstall` \
         removes it."
    );
    Ok(())
}

/// The desired state in effect, when it can be read.
fn read_doc(path: &Path) -> Option<nett_mesh::config::DesiredMeshDoc> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// On DSM, the boot task goes first, so that a restart in the middle does not start nett again.
fn remove_boot_task() -> anyhow::Result<()> {
    if Flavor::detect() == Flavor::Dsm
        && let Some(m) = crate::dsm::remove_boot_task()?
    {
        outln!("{m}");
    }
    Ok(())
}

fn remove_services() -> anyhow::Result<()> {
    // DSM's unit is not enabled: the boot task starts it
    let dsm = Flavor::detect() == Flavor::Dsm;
    for unit in [&RELAY, &DAEMON] {
        let path = unit.path();
        if !Path::new(&path).exists() {
            continue;
        }
        let stop: &[&str] = if dsm {
            &["stop", unit.name]
        } else {
            &["disable", "--now", unit.name]
        };
        // If stopping fails, the unit is not deleted: it stays so the user can still handle it with
        // systemctl
        if !systemctl(stop)? {
            bail!("systemctl could not stop {}", unit.name);
        }
        fs::remove_file(&path).with_context(|| format!("removing {path}"))?;
    }
    systemctl(&["daemon-reload"])?;
    Ok(())
}

/// Makes `link` a symbolic link to `target` (Linux: `/usr/local/bin/nett`, design/release.md
/// section 5). A regular file there is replaced; a link to somewhere else is left alone, since
/// another installer owns it. Returns whether the link points at `target` afterwards.
pub fn ensure_link(link: &str, target: &str) -> anyhow::Result<bool> {
    match fs::symlink_metadata(link) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Ok(fs::read_link(link).is_ok_and(|t| t == Path::new(target)));
        }
        Ok(_) => fs::remove_file(link).with_context(|| format!("replacing {link}"))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("reading {link}")),
    }
    if let Some(dir) = Path::new(link).parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    std::os::unix::fs::symlink(target, link).with_context(|| format!("linking {link}"))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The nett service runs the installed program as root on the identity directory; the relay
    /// as a user systemd allocates, with its certificate from the identity directory
    #[test]
    fn the_units_run_the_installed_program() {
        assert!(
            DAEMON
                .content
                .contains(&format!("\nExecStart={BINARY} daemon --dir {DIR}\n"))
        );
        assert!(!DAEMON.content.contains("\nUser="));
        assert!(DAEMON.content.contains(&format!("ReadWritePaths={DIR} ")));
        assert!(
            RELAY
                .content
                .contains(&format!("\nExecStart={BINARY} relay "))
        );
        assert!(RELAY.content.contains("\nDynamicUser=yes\n"));
        assert!(
            RELAY
                .content
                .contains(&format!("{RELAY_CERT_DIR}/tls-key.pk8"))
        );
    }
}
