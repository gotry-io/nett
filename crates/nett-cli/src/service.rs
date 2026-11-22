//! Service installation on macOS (design/release.md sections 4 and 8, hub.md section 7): `sudo nett
//! install` generates the keys in a root-only directory, places a copy of the program, writes the
//! launchd configuration and starts the service; without a Hub, it finds the desired state for this
//! machine in the site directory of the user who ran sudo; with a Hub (a token, or an existing Hub
//! configuration) the service also runs nett-node, which receives the desired state from the Hub
//! (ADR 0013).
//! `sudo nett uninstall` removes everything but the identity, and `sudo nett leave` the identity.
//! The program `sudo nett install` runs from may lie where ordinary users can write, so the root
//! service only runs this copy.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use nett_node::config::HubConfig;

use crate::install::{
    InstallArgs, apply_token, copy_self, ensure_dir, replace_if_changed, require_root,
};

use nett_node::launchd::{self, DAEMON, Service, plist};
use nett_node::platform::macos::{COMMAND, DIR, PROGRAM as BINARY};

fn loaded(service: &Service) -> anyhow::Result<bool> {
    launchd::loaded(service).map_err(anyhow::Error::msg)
}

fn stop(service: &Service) -> anyhow::Result<()> {
    launchd::stop(service).map_err(anyhow::Error::msg)
}

fn launchctl(args: &[&str]) -> anyhow::Result<bool> {
    launchd::launchctl(args).map_err(anyhow::Error::msg)
}

/// Makes the service run with the new configuration and program: loads it when not loaded; when the
/// configuration changed, unloads and reloads (launchd keeps the configuration from load time, and
/// kickstart would only restart with the old arguments); restarts when the program or the
/// configuration it reads changed. Returns a one-sentence report, empty when nothing changed.
fn ensure_running(
    service: &Service,
    plist_changed: bool,
    restart: bool,
) -> anyhow::Result<Option<String>> {
    let target = format!("system/{}", service.label);
    let (ok, message) = if !loaded(service)? {
        (
            launchctl(&["bootstrap", "system", service.plist])?,
            format!("Started {}.", service.what),
        )
    } else if plist_changed {
        stop(service)?;
        (
            launchctl(&["bootstrap", "system", service.plist])?,
            format!("Restarted {} with the new configuration.", service.what),
        )
    } else if restart {
        (
            launchctl(&["kickstart", "-k", &target])?,
            format!("Restarted {}.", service.what),
        )
    } else {
        return Ok(None);
    };
    if !ok {
        bail!(
            "launchctl could not start {}; see `log show --last 10m --predicate 'process == \"nett\"'`",
            service.label
        );
    }
    Ok(Some(message))
}

/// Completes the installation in one command (design/release.md section 4, hub.md section 7): keys,
/// program copy, service configuration; without a Hub, imports the desired state; starts the
/// service when there is a desired state, and when it is already running, restarts or reloads
/// according to what changed.
pub fn install(args: &InstallArgs) -> anyhow::Result<()> {
    require_root()?;
    ensure_dir(DIR, 0o700)?;
    let keys = crate::daemon::node_keys(Path::new(DIR))?;
    let desired = Path::new(DIR).join(crate::daemon::DESIRED_FILE);
    let token = apply_token(DIR, args.token.as_deref(), &keys.0)?;
    let hub_changed = token.hub_changed;
    let linked = HubConfig::load(Path::new(DIR))
        .map_err(anyhow::Error::msg)?
        .is_some();

    // On a machine linked to a Hub, the desired state is written only by nett-node (design/hub.md
    // section 5)
    let site = invoking_site_dir();
    let imported = match (&args.config, linked) {
        // The first one the Hub sends when a new machine joins (design/hub.md section 6);
        // afterwards only nett-node writes it
        _ if token.desired.is_some() => token.desired,
        (Some(_), true) => {
            bail!("this machine receives its desired state from its Hub; --config is not used")
        }
        (Some(path), false) => {
            let bytes = crate::site::read_desired(path)?
                .with_context(|| format!("{} is not a regular file", path.display()))?;
            crate::site::check_desired_for(&bytes, &keys.0)?;
            Some(bytes)
        }
        (None, false) => match &site {
            Some(site) => crate::site::find_desired_for(site, &keys.0)?.map(|(path, bytes)| {
                outln!("Using {}", path.display());
                bytes
            }),
            None => None,
        },
        (None, true) => None,
    };
    let desired_changed = match imported {
        Some(bytes) => replace_if_changed(&desired, &bytes, 0o600)?,
        None => false,
    };
    let binary_changed = copy_self(BINARY)?;
    let plist_changed =
        replace_if_changed(Path::new(DAEMON.plist), plist(&DAEMON).as_bytes(), 0o644)?;

    // The public key line is only needed when this machine has not been added to the site yet
    if !desired.exists() {
        crate::daemon::print_keys(Path::new(DIR), keys);
        let site = site.map_or_else(|| "~/.config/nett".to_owned(), |s| s.display().to_string());
        outln!("Installed to {DIR}. Not started: {site} has no desired state for this machine.");
        outln!(
            "Once the machine is in the site, run `sudo nett install` again: it imports its desired state."
        );
        outln!(
            "If the site is on another machine, use `sudo nett install --config <desired.json>`."
        );
        return Ok(());
    }
    let mut messages = Vec::new();
    // With a new Hub configuration, the service starts nett-node afresh
    let restart = binary_changed || (linked && hub_changed);
    match ensure_running(&DAEMON, plist_changed, restart)? {
        Some(m) => messages.push(m),
        None if desired_changed => {
            // Only the desired state changed: re-read through the local interface, without restart
            // or connection interruption, and show whether it was accepted (design/status.md
            // section 4.1)
            out!(
                "{}",
                crate::status::reload_at(Path::new(nett_mesh::status::DEFAULT_SOCKET))?
            );
        }
        None => {}
    }
    if messages.is_empty() && !desired_changed {
        messages.push("The service is running. Nothing changed.".to_owned());
    }
    for m in messages {
        outln!("{m}");
    }
    if plist_changed || binary_changed {
        outln!("Logs: log show --last 1h --predicate 'process == \"nett\"'");
        if linked {
            outln!("Run `sudo nett install` again after upgrading nett.");
        } else {
            outln!("Run `sudo nett install` again after the site changes or nett is upgraded.");
        }
    }
    Ok(())
}

/// The site directory of the user who ran `sudo` (design/site.md section 8). sudo may replace
/// `HOME` with root's, so the home directory is looked up in the user database by `SUDO_UID`;
/// without sudo, `HOME` is used.
fn invoking_site_dir() -> Option<PathBuf> {
    let home = match std::env::var("SUDO_UID").ok().and_then(|u| u.parse().ok()) {
        Some(uid) => passwd::home(uid)?.into_os_string(),
        None => std::env::var_os("HOME")?,
    };
    crate::site::site_dir(std::env::var_os("XDG_CONFIG_HOME"), Some(home)).ok()
}

/// User database lookup: neither the standard library nor rustix has getpwuid_r.
#[allow(unsafe_code)]
mod passwd {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::PathBuf;

    /// Far larger than a user record on macOS; returns `None` if it does not fit (ERANGE).
    const BUFFER: usize = 4096;

    pub fn home(uid: libc::uid_t) -> Option<PathBuf> {
        let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut buffer = vec![0 as libc::c_char; BUFFER];
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: entry, buffer and result are valid memory held by this function, and the real
        // length of buffer is passed in.
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                entry.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        if rc != 0 || result.is_null() {
            return None;
        }
        // SAFETY: when the return value is 0 and result is non-null, entry is filled in; pw_dir is
        // a NUL-terminated string in buffer, and buffer stays valid until this function ends; it is
        // copied out before use ends.
        let dir = unsafe { CStr::from_ptr((*result).pw_dir) };
        let path = PathBuf::from(OsStr::from_bytes(dir.to_bytes()));
        path.is_absolute().then_some(path)
    }
}

/// `sudo nett uninstall` (design/release.md section 8): removes the services, the program and
/// everything else nett placed, and keeps this machine's identity.
pub fn uninstall() -> anyhow::Result<()> {
    require_root()?;
    remove_installation()?;
    // Only nett's own copy: a link or another installer's file stays (design/release.md section 6)
    if nett_node::upgrade::own_command(Path::new(COMMAND)) {
        crate::install::remove_file(COMMAND)?;
    }
    if crate::install::remove_if_empty(DIR)? {
        outln!("Removed nett. Nothing of it remains on this machine.");
    } else {
        outln!(
            "Removed nett. This machine's identity stays in {DIR}: `sudo nett install` brings it back \
             as the same member, and `sudo rm -r '{DIR}'` deletes it."
        );
    }
    Ok(())
}

/// `sudo nett leave` (design/hub.md section 7): tells the Hub, removes the services and the
/// identity. The utun interface belongs to the mesh and disappears when it exits; the `nett`
/// command stays.
pub fn leave() -> anyhow::Result<()> {
    require_root()?;
    crate::install::tell_hub(DIR)?;
    remove_installation()?;
    crate::install::forget(DIR)?;
    crate::install::remove_if_empty(DIR)?;
    outln!(
        "Left the site: removed the services, deleted the keys, the desired state, the trust store \
         and the Hub configuration. `sudo nett uninstall` removes the nett command too."
    );
    Ok(())
}

/// Everything `sudo nett install` and the service placed, except the identity and the command: the
/// service and its copy of the program, the files of the running mesh and the upgrade records.
fn remove_installation() -> anyhow::Result<()> {
    stop(&DAEMON)?;
    let previous = Path::new(BINARY).with_file_name("nett.previous");
    let new = Path::new(BINARY).with_file_name("nett.new");
    for path in [
        DAEMON.plist,
        BINARY,
        &previous.to_string_lossy(),
        &new.to_string_lossy(),
        // The names of this site no longer resolve here
        nett_mesh::macos::RESOLVER_FILE,
    ] {
        crate::install::remove_file(path)?;
    }
    if let Some(run) = Path::new(nett_mesh::status::DEFAULT_SOCKET).parent() {
        crate::install::remove_tree(&run.to_string_lossy())?;
    }
    crate::install::forget_upgrades(DIR)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_home_of_a_user() {
        let home = passwd::home(rustix::process::getuid().as_raw()).expect("own entry");
        assert!(home.is_dir(), "{}", home.display());
        // nobody on macOS is -2 (uid_t::MAX - 1); pick an unassigned uid
        assert!(passwd::home(3_999_999).is_none());
    }
}
