//! Service installation on Linux (design/hub.md section 7): `sudo nett install` generates or reuses
//! the keys in `/etc/nett`, copies the running `nett` to `/usr/local/bin/nett`, writes the systemd
//! units and starts them. The units are the files in `packaging/systemd/`, embedded at compile
//! time, so their content has a single source. Without a Hub, the desired state is imported with
//! `--config`; with a Hub (a token, or an existing Hub configuration) only nett-node writes it.

use std::fs;
use std::path::Path;

use anyhow::{Context as _, bail};
use nett_node::config::HubConfig;

use crate::install::{
    InstallArgs, apply_token, copy_self, ensure_dir, replace_if_changed, require_root,
};

const DIR: &str = "/etc/nett";
const DESIRED: &str = "/etc/nett/desired.json";
const BINARY: &str = "/usr/local/bin/nett";
const UNIT_DIR: &str = "/etc/systemd/system";
/// Fixed locations of systemctl (hard rule 9): most distributions use the former, older ones the
/// latter.
const SYSTEMCTL: [&str; 2] = ["/usr/bin/systemctl", "/bin/systemctl"];

struct Unit {
    name: &'static str,
    content: &'static str,
    what: &'static str,
}

const MESH: Unit = Unit {
    name: "nett-mesh.service",
    content: include_str!("../../../packaging/systemd/nett-mesh.service"),
    what: "the mesh service",
};

const NODE: Unit = Unit {
    name: "nett-node.service",
    content: include_str!("../../../packaging/systemd/nett-node.service"),
    what: "nett-node",
};

fn systemctl(args: &[&str]) -> anyhow::Result<bool> {
    let Some(program) = SYSTEMCTL.iter().find(|p| Path::new(p).exists()) else {
        bail!(
            "systemctl is not on this machine; without systemd, run `nett mesh` (and `nett node`) with \
             your own service manager"
        );
    };
    crate::install::run(program, args)
}

fn unit_path(unit: &Unit) -> String {
    format!("{UNIT_DIR}/{}", unit.name)
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
    // The mesh process runs under a dedicated systemd identity and must be able to enter this
    // directory to read the desired state; the private key file itself is 0600
    ensure_dir(DIR, 0o755)?;
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
        (Some(bytes), _, _) => replace_if_changed(Path::new(DESIRED), &bytes, 0o644)?,
        (None, Some(_), true) => {
            bail!("this machine receives its desired state from its Hub; --config is not used")
        }
        (None, Some(path), false) => {
            let bytes = crate::site::read_desired(path)?
                .with_context(|| format!("{} is not a regular file", path.display()))?;
            crate::site::check_desired_for(&bytes, &keys.0)?;
            replace_if_changed(Path::new(DESIRED), &bytes, 0o644)?
        }
        (None, None, _) => false,
    };
    let binary_changed = copy_self(BINARY)?;
    let mesh_unit_changed =
        replace_if_changed(Path::new(&unit_path(&MESH)), MESH.content.as_bytes(), 0o644)?;
    let node_unit_changed =
        linked && replace_if_changed(Path::new(&unit_path(&NODE)), NODE.content.as_bytes(), 0o644)?;
    if (mesh_unit_changed || node_unit_changed) && !systemctl(&["daemon-reload"])? {
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

fn remove_services() -> anyhow::Result<()> {
    for unit in [&NODE, &MESH] {
        let path = unit_path(unit);
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

#[cfg(test)]
mod tests {
    use super::*;

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
