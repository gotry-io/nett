//! Service installation on Linux (design/hub.md section 7): `sudo nett install` generates or reuses
//! the keys in `/etc/nett`, copies the running `nett` to `/usr/local/lib/nett/nett` with the link
//! `/usr/local/bin/nett` (design/release.md section 5), writes the systemd
//! units and starts them. The units are the files in `packaging/systemd/`, embedded at compile
//! time, so their content has a single source. Without a Hub, the desired state is imported with
//! `--config`; with a Hub (a token, or an existing Hub configuration) only nett-node writes it.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use anyhow::{Context as _, bail};
use nett_node::config::HubConfig;

use crate::install::{
    InstallArgs, apply_token, copy_self, ensure_dir, replace_if_changed, require_root,
};

use nett_node::platform::linux::{
    CONFIG_DIR as DIR, LINK, MESH, NODE, PROGRAM as BINARY, PROGRAM_DIR, RELAY, TRANSPORT, Unit,
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

/// Makes the service run with the new units and program: enables and starts it when not running,
/// restarts it when the unit or program changed. Returns a one-sentence report.
fn ensure_running(unit: &Unit, restart: bool) -> anyhow::Result<Option<String>> {
    let (ok, message) = if !systemctl(&["is-active", "--quiet", unit.name])? {
        (
            systemctl(&["enable", "--now", unit.name])?,
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
    // The mesh service runs as the system user nett and reads the desired state through the
    // directory's group; other users cannot enter it. setgid hands the group to new files
    let gid = ensure_user()?;
    ensure_dir(DIR, 0o2750)?;
    std::os::unix::fs::chown(DIR, Some(0), Some(gid))
        .with_context(|| format!("changing the group of {DIR}"))?;
    let keys = crate::mesh::node_keys(Path::new(DIR))?;
    let token = apply_token(
        DIR,
        nett_mesh::store::DEFAULT_STATE_DIR,
        args.token.as_deref(),
        &keys.0,
    )?;
    let hub_changed = token.hub_changed;
    let linked = HubConfig::load(Path::new(DIR))
        .map_err(anyhow::Error::msg)?
        .is_some();
    let desired_changed = match (token.desired, &args.config, linked) {
        // The first one the Hub sends when a new machine joins (design/hub.md section 6);
        // afterwards only nett-node writes it
        (Some(bytes), _, _) => replace_if_changed(Path::new(DESIRED), &bytes, 0o640)?,
        (None, Some(_), true) => {
            bail!("this machine receives its desired state from its Hub; --config is not used")
        }
        (None, Some(path), false) => {
            let bytes = crate::site::read_desired(path)?
                .with_context(|| format!("{} is not a regular file", path.display()))?;
            crate::site::check_desired_for(&bytes, &keys.0)?;
            replace_if_changed(Path::new(DESIRED), &bytes, 0o640)?
        }
        (None, None, _) => false,
    };
    // A desired state written before the directory had its group keeps working and stops being
    // readable by everyone
    if Path::new(DESIRED).exists() {
        std::os::unix::fs::chown(DESIRED, Some(0), Some(gid))
            .with_context(|| format!("changing the group of {DESIRED}"))?;
        fs::set_permissions(DESIRED, fs::Permissions::from_mode(0o640))
            .with_context(|| format!("setting permissions of {DESIRED}"))?;
    }
    ensure_dir(PROGRAM_DIR, 0o755)?;
    let binary_changed = copy_self(BINARY)?;
    if !ensure_link(LINK, BINARY)? {
        println!("{LINK} belongs to another installer; the services run {BINARY}.");
    }
    ensure_dir(nett_node::platform::linux::UNIT_DIR, 0o755)?;
    let write =
        |unit: &Unit| replace_if_changed(Path::new(&unit.path()), unit.content.as_bytes(), 0o644);
    let mesh_unit_changed = write(&MESH)?;
    let node_unit_changed = linked && write(&NODE)?;
    // Enabled only while the desired state needs them (design/hub.md section 5)
    let optional_changed = write(&RELAY)? | write(&TRANSPORT)?;
    if (mesh_unit_changed || node_unit_changed || optional_changed)
        && !systemctl(&["daemon-reload"])?
    {
        bail!("systemctl daemon-reload failed");
    }

    if !Path::new(DESIRED).exists() {
        crate::mesh::print_keys(Path::new(DIR), keys);
        println!(
            "Installed {BINARY} and {}. Not started: {DESIRED} does not exist yet.",
            MESH.name
        );
        println!(
            "Once the machine is in the site, copy its desired state here and run \
             `sudo nett install --config <desired.json>`."
        );
        return Ok(());
    }
    let mut messages = Vec::new();
    match ensure_running(&MESH, mesh_unit_changed || binary_changed)? {
        Some(m) => messages.push(m),
        None if desired_changed => print!(
            "{}",
            crate::status::reload_at(Path::new(nett_mesh::status::DEFAULT_SOCKET))?
        ),
        None => {}
    }
    if linked
        && let Some(m) = ensure_running(&NODE, node_unit_changed || binary_changed || hub_changed)?
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
                "{} runs; `sudo nett status` shows its TLS fingerprint for `nett site relay --fingerprint`.",
                RELAY.what
            ));
        }
    }
    if messages.is_empty() && !desired_changed {
        messages.push("The services are running. Nothing changed.".to_owned());
    }
    for m in messages {
        println!("{m}");
    }
    if mesh_unit_changed || node_unit_changed || binary_changed {
        println!("Logs: journalctl -u nett-mesh -u nett-node");
    }
    Ok(())
}

pub fn uninstall() -> anyhow::Result<()> {
    require_root()?;
    remove_services()?;
    println!(
        "Removed the services. {BINARY}, the keys, the desired state, the trust store and the Hub \
         configuration remain."
    );
    Ok(())
}

/// `sudo nett leave` (design/hub.md section 7): tells the Hub, deletes the services, tears down the
/// mesh interface and filter rules, deletes the keys and configuration.
pub fn leave() -> anyhow::Result<()> {
    require_root()?;
    crate::install::tell_hub(DIR)?;
    remove_services()?;
    nett_mesh::linux::teardown().context("removing the mesh interface and filter rules")?;
    crate::install::forget(DIR, nett_mesh::store::DEFAULT_STATE_DIR)?;
    println!(
        "Left the site: removed the services and the mesh interface, deleted the keys, the desired \
         state, the trust store and the Hub configuration. {BINARY} stays."
    );
    Ok(())
}

/// The desired state in effect, when it can be read.
fn read_doc() -> Option<nett_mesh::config::DesiredMeshDoc> {
    let bytes = std::fs::read(DESIRED).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn remove_services() -> anyhow::Result<()> {
    for unit in [&TRANSPORT, &RELAY, &NODE, &MESH] {
        let path = unit.path();
        if !Path::new(&path).exists() {
            continue;
        }
        // If stopping fails, the unit is not deleted: it stays so the user can still handle it with
        // systemctl
        if !systemctl(&["disable", "--now", unit.name])? {
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
    const SYSUSERS: &str = include_str!("../../../packaging/systemd/nett.sysusers");
    const CONF: &str = "/etc/sysusers.d/nett.conf";
    const PROGRAMS: [&str; 2] = ["/usr/bin/systemd-sysusers", "/bin/systemd-sysusers"];
    ensure_dir("/etc/sysusers.d", 0o755)?;
    replace_if_changed(Path::new(CONF), SYSUSERS.as_bytes(), 0o644)?;
    let program = PROGRAMS
        .into_iter()
        .find(|p| Path::new(p).exists())
        .context("systemd-sysusers is not on this machine")?;
    if !crate::install::run(program, &[CONF])? {
        bail!("systemd-sysusers could not create the user nett");
    }
    group_id("nett")?.context("systemd-sysusers did not create the group nett")
}

/// A group's ID from /etc/group (the standard library has no getgrnam).
fn group_id(name: &str) -> anyhow::Result<Option<u32>> {
    let groups = fs::read_to_string("/etc/group").context("reading /etc/group")?;
    Ok(group_in(&groups, name))
}

fn group_in(groups: &str, name: &str) -> Option<u32> {
    groups.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next() == Some(name))
            .then(|| fields.nth(1).and_then(|gid| gid.parse().ok()))
            .flatten()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mesh_service_runs_as_the_nett_user_from_the_group_file() {
        assert!(MESH.content.contains("\nUser=nett\n"));
        assert!(!MESH.content.contains("DynamicUser"));
        let groups = "root:x:0:\nnetty:x:998:\nnett:x:997:\n";
        assert_eq!(group_in(groups, "nett"), Some(997));
        assert_eq!(group_in(groups, "nobody"), None);
        assert_eq!(group_in("nett:x:notanumber:\n", "nett"), None);
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
