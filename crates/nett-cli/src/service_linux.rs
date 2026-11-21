//! Service installation on Linux (design/hub.md section 7): `sudo nett install` generates or reuses
//! the keys in `/etc/nett`, copies the running `nett` to `/usr/local/lib/nett/nett` with the link
//! `/usr/local/bin/nett` (design/release.md section 5), writes the systemd
//! units and starts them. The units are the files in `packaging/systemd/`, embedded at compile
//! time, so their content has a single source. Without a Hub, the desired state is imported with
//! `--config`; with a Hub (a token, or an existing Hub configuration) only nett-node writes it.
//! `sudo nett uninstall` removes everything but the identity, and `sudo nett leave` the identity
//! (design/release.md section 8).

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use anyhow::{Context as _, bail};
use nett_node::config::HubConfig;

use crate::install::{
    InstallArgs, apply_token, copy_self, ensure_dir, replace_if_changed, require_root,
};

use nett_node::layout::{Layout, SYSUSERS, SYSUSERS_CONF, group_in};
use nett_node::platform::linux::{
    CONFIG_DIR as DIR, Flavor, LINK, MESH, NODE, OLD_ACCOUNTS, PROGRAM as BINARY, PROGRAM_DIR,
    RELAY, RELAY_CERT_DIR, STATE_DIR, TRANSPORT, Unit,
};

const DESIRED: &str = "/etc/nett/desired.json";
/// Where units of the same name override the ones nett installs.
const OVERRIDE_DIR: &str = "/etc/systemd/system";

fn systemctl(args: &[&str]) -> anyhow::Result<bool> {
    let Some(program) = nett_node::platform::linux::systemctl() else {
        bail!(
            "systemctl is not on this machine; without systemd, run `nett mesh` (and `nett node`) with \
             your own service manager"
        );
    };
    crate::install::run(program, args)
}

/// Makes the service run with the new units and program: starts it when not running (enabling it,
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
    // older program with older settings: the administrator removes it (from an earlier manual setup)
    let overrides: Vec<String> = [&MESH, &NODE, &RELAY, &TRANSPORT]
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
    let (mesh, node) = (flavor.mesh(), flavor.node());
    let gid = match flavor {
        // The mesh service runs as the system user nett, reads the desired state and writes the
        // trust store through the directory's group; other users cannot enter it. setgid hands the
        // group to new files
        Flavor::Systemd => {
            let gid = ensure_user()?;
            ensure_dir(DIR, 0o2750)?;
            Some(gid)
        }
        // Every service runs as root there, so the identity is root's alone (design/dsm.md
        // section 6.1)
        Flavor::Dsm => {
            ensure_dir(DIR, 0o700)?;
            None
        }
    };
    std::os::unix::fs::chown(DIR, Some(0), Some(gid.unwrap_or(0)))
        .with_context(|| format!("changing the group of {DIR}"))?;
    let desired_mode = if gid.is_some() { 0o640 } else { 0o600 };
    // The trust store belongs to the mesh service's user, and the one of 0.3.13 and earlier moves
    // here before the token is checked against it (design/release.md section 8)
    let layout = Layout::system();
    layout
        .prepare_state(nett_node::layout::mesh_owner())
        .map_err(anyhow::Error::msg)?;
    layout.copy_old_relay().map_err(anyhow::Error::msg)?;
    let keys = crate::mesh::node_keys(Path::new(DIR))?;
    let token = apply_token(DIR, STATE_DIR, args.token.as_deref(), &keys.0)?;
    let hub_changed = token.hub_changed;
    let linked = HubConfig::load(Path::new(DIR))
        .map_err(anyhow::Error::msg)?
        .is_some();
    let desired_changed = match (token.desired, &args.config, linked) {
        // The first one the Hub sends when a new machine joins (design/hub.md section 6);
        // afterwards only nett-node writes it
        (Some(bytes), _, _) => replace_if_changed(Path::new(DESIRED), &bytes, desired_mode)?,
        (None, Some(_), true) => {
            bail!("this machine receives its desired state from its Hub; --config is not used")
        }
        (None, Some(path), false) => {
            let bytes = crate::site::read_desired(path)?
                .with_context(|| format!("{} is not a regular file", path.display()))?;
            crate::site::check_desired_for(&bytes, &keys.0)?;
            replace_if_changed(Path::new(DESIRED), &bytes, desired_mode)?
        }
        (None, None, _) => false,
    };
    // A desired state written before the directory had its group keeps working and stops being
    // readable by everyone
    if Path::new(DESIRED).exists() {
        std::os::unix::fs::chown(DESIRED, Some(0), Some(gid.unwrap_or(0)))
            .with_context(|| format!("changing the group of {DESIRED}"))?;
        fs::set_permissions(DESIRED, fs::Permissions::from_mode(desired_mode))
            .with_context(|| format!("setting permissions of {DESIRED}"))?;
    }
    ensure_dir(PROGRAM_DIR, 0o755)?;
    let binary_changed = copy_self(BINARY)?;
    if !ensure_link(LINK, BINARY)? {
        outln!("{LINK} belongs to another installer; the services run {BINARY}.");
    }
    ensure_dir(nett_node::platform::linux::UNIT_DIR, 0o755)?;
    let write =
        |unit: &Unit| replace_if_changed(Path::new(&unit.path()), unit.content.as_bytes(), 0o644);
    let mesh_unit_changed = write(&mesh)?;
    let node_unit_changed = linked && write(&node)?;
    // The relay's and the transport adapter's are written only while the desired state needs them
    // (design/release.md section 8)
    if (mesh_unit_changed || node_unit_changed) && !systemctl(&["daemon-reload"])? {
        bail!("systemctl daemon-reload failed");
    }

    if !Path::new(DESIRED).exists() {
        crate::mesh::print_keys(Path::new(DIR), keys);
        outln!(
            "Installed {BINARY} and {}. Not started: {DESIRED} does not exist yet.",
            mesh.name
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
    match ensure_running(&mesh, mesh_unit_changed || binary_changed, flavor)? {
        Some(m) => messages.push(m),
        None if desired_changed => out!(
            "{}",
            crate::status::reload_at(Path::new(nett_mesh::status::DEFAULT_SOCKET))?
        ),
        None => {}
    }
    if linked
        && let Some(m) = ensure_running(
            &node,
            node_unit_changed || binary_changed || hub_changed,
            flavor,
        )?
    {
        messages.push(m);
    }
    // Without a Hub the relay and the transport adapter follow the imported desired state; with one,
    // nett-node starts and stops them
    if !linked && let Some(doc) = read_doc() {
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
    // Running helpers keep the old program until they restart; try-restart leaves stopped ones alone
    let helpers: Vec<Unit> = nett_node::platform::linux::installed_optional();
    if binary_changed && !helpers.is_empty() {
        let mut args = vec!["try-restart"];
        args.extend(helpers.iter().map(|u| u.name));
        if !systemctl(&args)? {
            let what: Vec<&str> = helpers.iter().map(|u| u.what).collect();
            messages.push(format!(
                "Restarting {} on the new program failed.",
                what.join(" and ")
            ));
        }
    }
    for what in nett_node::layout::tidy(&layout).map_err(anyhow::Error::msg)? {
        messages.push(format!("Moved from the layout of nett 0.3.13: {what}."));
    }
    if messages.is_empty() && !desired_changed {
        messages.push("The services are running. Nothing changed.".to_owned());
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
    if mesh_unit_changed || node_unit_changed || binary_changed {
        outln!("Logs: journalctl -u nett-mesh -u nett-node");
    }
    Ok(())
}

/// `sudo nett uninstall` (design/release.md section 8): removes the services, the mesh interface and
/// filter rules, the program, the accounts and the upgrade records, and keeps this machine's
/// identity, given to root so that no account created later inherits it.
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
    remove_old_layout(true)?;
    let kept = !crate::install::remove_if_empty(DIR)?;
    if kept {
        give_to_root(Path::new(DIR))?;
    }
    remove_accounts()?;
    if kept {
        outln!(
            "Removed nett. This machine's identity stays in {DIR}: `sudo nett install` brings it back \
             as the same member, and `sudo rm -r {DIR}` deletes it."
        );
    } else {
        outln!("Removed nett. Nothing of it remains on this machine.");
    }
    Ok(())
}

/// What the layout of 0.3.13 and earlier placed besides the identity directory (design/release.md
/// section 8); with `keep`, its contents are copied there first.
fn remove_old_layout(keep: bool) -> anyhow::Result<()> {
    let layout = Layout::system();
    if keep {
        if layout.old_state.join(nett_mesh::store::TRUST_FILE).exists() {
            layout.prepare_state(None).map_err(anyhow::Error::msg)?;
        }
        layout.copy_old_relay().map_err(anyhow::Error::msg)?;
    }
    crate::install::remove_tree(&layout.old_state.to_string_lossy())?;
    crate::install::remove_tree(&layout.old_relay.to_string_lossy())
}

/// Gives a directory and everything in it to root, without following links.
fn give_to_root(path: &Path) -> anyhow::Result<()> {
    std::os::unix::fs::lchown(path, Some(0), Some(0))
        .with_context(|| format!("giving {} to root", path.display()))?;
    if fs::symlink_metadata(path)
        .with_context(|| format!("reading {}", path.display()))?
        .is_dir()
    {
        for entry in fs::read_dir(path).with_context(|| format!("reading {}", path.display()))? {
            give_to_root(&entry?.path())?;
        }
    }
    Ok(())
}

/// Deletes the system user `sudo nett install` created and the ones of 0.3.13 and earlier, their
/// groups, and their declaration.
fn remove_accounts() -> anyhow::Result<()> {
    for name in nett_node::layout::accounts().chain(OLD_ACCOUNTS) {
        nett_node::layout::delete_account(name).map_err(anyhow::Error::msg)?;
    }
    crate::install::remove_file(SYSUSERS_CONF)
}

/// `sudo nett leave` (design/hub.md section 7): tells the Hub, deletes the services, tears down the
/// mesh interface and filter rules, deletes the keys and configuration.
pub fn leave() -> anyhow::Result<()> {
    require_root()?;
    crate::install::tell_hub(DIR)?;
    remove_boot_task()?;
    remove_services()?;
    nett_mesh::linux::teardown().context("removing the mesh interface and filter rules")?;
    crate::install::forget(DIR, STATE_DIR)?;
    // The relay's certificate is part of this machine's identity
    crate::install::remove_tree(RELAY_CERT_DIR)?;
    remove_old_layout(false)?;
    crate::install::remove_if_empty(DIR)?;
    outln!(
        "Left the site: removed the services and the mesh interface, deleted the keys, the desired \
         state, the trust store and the Hub configuration. {BINARY} stays; `sudo nett uninstall` \
         removes it."
    );
    Ok(())
}

/// The desired state in effect, when it can be read.
fn read_doc() -> Option<nett_mesh::config::DesiredMeshDoc> {
    let bytes = std::fs::read(DESIRED).ok()?;
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
    // DSM's units are not enabled: the boot task starts them
    let dsm = Flavor::detect() == Flavor::Dsm;
    for unit in [&TRANSPORT, &RELAY, &NODE, &MESH] {
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

/// The system user the mesh service runs as (`packaging/systemd/nett.sysusers`), created with
/// systemd-sysusers. Returns the group ID of its group.
fn ensure_user() -> anyhow::Result<u32> {
    const PROGRAMS: [&str; 2] = ["/usr/bin/systemd-sysusers", "/bin/systemd-sysusers"];
    ensure_dir("/etc/sysusers.d", 0o755)?;
    replace_if_changed(Path::new(SYSUSERS_CONF), SYSUSERS.as_bytes(), 0o644)?;
    let program = PROGRAMS
        .into_iter()
        .find(|p| Path::new(p).exists())
        .context("systemd-sysusers is not on this machine")?;
    if !crate::install::run(program, &[SYSUSERS_CONF])? {
        bail!("systemd-sysusers could not create the user nett");
    }
    group_id("nett")?.context("systemd-sysusers did not create the group nett")
}

/// A group's ID from /etc/group (the standard library has no getgrnam).
fn group_id(name: &str) -> anyhow::Result<Option<u32>> {
    let groups = fs::read_to_string("/etc/group").context("reading /etc/group")?;
    Ok(group_in(&groups, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mesh service runs as the one system user; the relay and the transport adapter as users
    /// systemd allocates, and the relay gets its certificate from the identity directory
    #[test]
    fn only_the_mesh_service_has_an_account() {
        assert!(MESH.content.contains("\nUser=nett\n"));
        assert!(!MESH.content.contains("DynamicUser"));
        assert!(MESH.content.contains(&format!("--state {STATE_DIR}")));
        assert!(
            MESH.content
                .contains(&format!("ReadWritePaths={STATE_DIR}"))
        );
        for unit in [&RELAY, &TRANSPORT] {
            assert!(
                unit.content.contains("\nDynamicUser=yes\n"),
                "{}",
                unit.name
            );
            assert!(!unit.content.contains("\nUser="), "{}", unit.name);
        }
        assert!(
            RELAY
                .content
                .contains(&format!("{RELAY_CERT_DIR}/tls-key.pk8"))
        );
        assert!(
            NODE.content
                .contains(&format!("ExecStartPre=-+{BINARY} node --dir {DIR} --tidy"))
        );
        assert!(!SYSUSERS.contains("nett-relay") && !SYSUSERS.contains("nett-transport"));
    }

    #[test]
    fn units_run_the_installed_binary_from_the_config_directory() {
        for unit in [&MESH, &NODE] {
            assert!(
                unit.content.contains(&format!("ExecStart={BINARY} ")),
                "{}",
                unit.name
            );
        }
        assert!(MESH.content.contains(&format!("--config {DESIRED}")));
        assert!(NODE.content.contains(&format!("node --dir {DIR}")));
        assert!(NODE.content.contains(&format!("ReadWritePaths={DIR}")));
    }
}
