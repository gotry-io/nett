//! Service installation on macOS (design/release.md section 4, hub.md section 7): `sudo nett
//! install` generates the keys in a root-only directory, places a copy of the program, writes the
//! launchd and log rotation configuration and starts the mesh service; without a Hub, it finds the
//! desired state for this machine in the site directory of the user who ran sudo; with a Hub (a
//! token, or an existing Hub configuration) it also starts nett-node, which receives the desired
//! state from the Hub. `sudo nett uninstall` stops the services and deletes the copy and
//! configuration. The Homebrew directory is writable by ordinary users, so the root service only
//! runs this copy.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use nett_node::config::HubConfig;

use crate::install::{
    InstallArgs, apply_token, copy_self, ensure_dir, replace_if_changed, require_root,
};

use nett_node::launchd::{
    self, DESIRED, LOG_DIR, MESH, NEWSYSLOG, NODE, Service, TRANSPORT, newsyslog, plist,
};
use nett_node::platform::macos::{DIR, PROGRAM as BINARY};

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
            "launchctl could not start {}; see {LOG_DIR}/{}",
            service.label,
            service.log
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
    ensure_dir(LOG_DIR, 0o700)?;
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
                println!("Using {}", path.display());
                bytes
            }),
            None => None,
        },
        (None, true) => None,
    };
    let desired_changed = match imported {
        Some(bytes) => replace_if_changed(Path::new(DESIRED), &bytes, 0o600)?,
        None => false,
    };
    let binary_changed = copy_self(BINARY)?;
    let mesh_plist_changed =
        replace_if_changed(Path::new(MESH.plist), plist(&MESH).as_bytes(), 0o644)?;
    let node_plist_changed =
        linked && replace_if_changed(Path::new(NODE.plist), plist(&NODE).as_bytes(), 0o644)?;
    replace_if_changed(Path::new(NEWSYSLOG), newsyslog().as_bytes(), 0o644)?;

    // The public key line is only needed when this machine has not been added to the site yet
    if !Path::new(DESIRED).exists() {
        crate::mesh::print_keys(Path::new(DIR), keys);
        let site = site.map_or_else(|| "~/.config/nett".to_owned(), |s| s.display().to_string());
        println!("Installed to {DIR}. Not started: {site} has no desired state for this machine.");
        println!(
            "Once the machine is in the site, run `sudo nett install` again: it imports its desired state."
        );
        println!(
            "If the site is on another machine, use `sudo nett install --config <desired.json>`."
        );
        return Ok(());
    }
    let mut messages = Vec::new();
    match ensure_running(&MESH, mesh_plist_changed, binary_changed)? {
        Some(m) => messages.push(m),
        None if desired_changed => {
            // Only the desired state changed: re-read through the local interface, without restart
            // or connection interruption, and show whether it was accepted (design/status.md
            // section 4.1)
            print!(
                "{}",
                crate::status::reload_at(Path::new(nett_mesh::status::DEFAULT_SOCKET))?
            );
        }
        None => {}
    }
    if linked
        && let Some(m) = ensure_running(&NODE, node_plist_changed, binary_changed || hub_changed)?
    {
        messages.push(m);
    }
    // Without a Hub the transport adapter follows the imported desired state; with one, nett-node
    // starts and stops it
    if !linked && let Some(doc) = read_doc() {
        messages.extend(nett_node::services::reconcile(
            nett_node::services::Wants::of(&doc),
        ));
    }
    // A running adapter keeps the old program until it restarts
    if binary_changed {
        launchd::restart(&TRANSPORT).map_err(anyhow::Error::msg)?;
    }
    if messages.is_empty() && !desired_changed {
        messages.push("The services are running. Nothing changed.".to_owned());
    }
    for m in messages {
        println!("{m}");
    }
    if mesh_plist_changed || node_plist_changed || binary_changed {
        println!("Logs: log show --last 1h --predicate 'process == \"nett\"'");
        if linked {
            println!("Run `sudo nett install` again after upgrading nett.");
        } else {
            println!("Run `sudo nett install` again after the site changes or nett is upgraded.");
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

pub fn uninstall() -> anyhow::Result<()> {
    require_root()?;
    remove_services()?;
    println!(
        "Removed the services. Keys, the desired state, the trust store and the Hub configuration remain in {DIR}."
    );
    Ok(())
}

/// `sudo nett leave` (design/hub.md section 7): tells the Hub, deletes the services, deletes the
/// keys and configuration. The utun interface belongs to the mesh process and disappears when it
/// exits.
pub fn leave() -> anyhow::Result<()> {
    require_root()?;
    crate::install::tell_hub(DIR)?;
    remove_services()?;
    crate::install::forget(DIR, nett_mesh::store::DEFAULT_STATE_DIR)?;
    // The names of this site no longer resolve here
    match std::fs::remove_file(nett_mesh::macos::RESOLVER_FILE) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(e).with_context(|| format!("removing {}", nett_mesh::macos::RESOLVER_FILE));
        }
    }
    println!(
        "Left the site: removed the services, deleted the keys, the desired state, the trust store \
         and the Hub configuration."
    );
    Ok(())
}

fn read_doc() -> Option<nett_mesh::config::DesiredMeshDoc> {
    let bytes = std::fs::read(DESIRED).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn remove_services() -> anyhow::Result<()> {
    stop(&TRANSPORT)?;
    stop(&NODE)?;
    stop(&MESH)?;
    for path in [TRANSPORT.plist, NODE.plist, MESH.plist, NEWSYSLOG, BINARY] {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {path}")),
        }
    }
    Ok(())
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
