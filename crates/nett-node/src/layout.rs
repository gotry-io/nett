//! nett's files and accounts on Linux (design/release.md section 8): the identity directory
//! `/etc/nett` with the trust store (`state/`) and the relay's certificate (`relay/`) in it, the one
//! system user the mesh service runs as, and the move from the layout of 0.3.13 and earlier. Every
//! call is blocking: async callers use a blocking thread.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use nett_relay::cert::{CERT_FILE, KEY_FILE};

use crate::platform::linux::{
    OLD_ACCOUNTS, OLD_RELAY_DIR, OLD_STATE_DIR, RELAY_CERT_DIR, RELAY_UNIT, STATE_DIR,
    TRANSPORT_UNIT,
};

/// The system user the mesh service runs as and its group (`packaging/systemd/nett.sysusers`).
pub const SYSUSERS: &str = include_str!("../../../packaging/systemd/nett.sysusers");
pub const SYSUSERS_CONF: &str = "/etc/sysusers.d/nett.conf";
/// The trust store's directory, which belongs to the user the mesh service runs as.
pub const STATE_DIR_MODE: u32 = 0o700;
/// Fixed locations of the account tools (hard rule 9).
const USERDEL: [&str; 2] = ["/usr/sbin/userdel", "/sbin/userdel"];
const GROUPDEL: [&str; 2] = ["/usr/sbin/groupdel", "/sbin/groupdel"];
/// Time limit of one account or systemctl call (hard rule 14).
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Where the identity and the old layout are; [`Layout::system`] on a machine, a temporary
/// directory in tests.
#[derive(Debug, Clone)]
pub struct Layout {
    pub state: PathBuf,
    pub relay_cert: PathBuf,
    pub old_state: PathBuf,
    pub old_relay: PathBuf,
}

impl Layout {
    pub fn system() -> Self {
        Self {
            state: PathBuf::from(STATE_DIR),
            relay_cert: PathBuf::from(RELAY_CERT_DIR),
            old_state: PathBuf::from(OLD_STATE_DIR),
            old_relay: PathBuf::from(OLD_RELAY_DIR),
        }
    }

    /// Readies the trust store's directory for the mesh service (design/release.md section 8), with
    /// full privileges: the privileged start step of its unit, and `sudo nett install`. Makes it
    /// `0700` and gives it and its files to `owner` (the user the mesh service runs as), and copies the
    /// trust store of 0.3.13 into it, a file only when the old one is newer than its copy, keeping
    /// the old files: safe to repeat and to roll back from.
    pub fn prepare_state(&self, owner: Option<(u32, u32)>) -> Result<(), String> {
        let io = |e: std::io::Error| format!("preparing {}: {e}", self.state.display());
        std::fs::create_dir_all(&self.state).map_err(io)?;
        std::fs::set_permissions(&self.state, std::fs::Permissions::from_mode(STATE_DIR_MODE))
            .map_err(io)?;
        if self.old_state.join(nett_mesh::store::TRUST_FILE).exists() {
            for from in regular_files(&self.old_state)? {
                let Some(name) = from.file_name() else {
                    continue;
                };
                let to = self.state.join(name);
                if newer(&from, &to) {
                    copy(&from, &to, 0o600)?;
                }
            }
        }
        if let Some((uid, gid)) = owner {
            let own = |p: &Path| {
                std::os::unix::fs::lchown(p, Some(uid), Some(gid))
                    .map_err(|e| format!("giving {} to the mesh service: {e}", p.display()))
            };
            own(&self.state)?;
            for file in regular_files(&self.state)? {
                own(&file)?;
            }
        }
        Ok(())
    }

    /// Copies the relay's certificate of 0.3.13 into `relay/` when it has none, keeping the old one
    /// (design/release.md section 8). Returns whether it did.
    pub fn copy_old_relay(&self) -> Result<bool, String> {
        let old_key = self.old_relay.join(KEY_FILE);
        if old_key.exists() && !self.relay_cert.join(KEY_FILE).exists() {
            ensure_private_dir(&self.relay_cert)?;
            // The key last: its presence marks a complete copy
            copy(
                &self.old_relay.join(CERT_FILE),
                &self.relay_cert.join(CERT_FILE),
                0o600,
            )?;
            copy(&old_key, &self.relay_cert.join(KEY_FILE), 0o600)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// The old directories whose contents are in the identity directory, so deleting them loses
    /// nothing.
    fn copied_old_dirs(&self) -> Vec<&Path> {
        let mut out = Vec::new();
        if self.old_state.exists()
            && (self.state.join(nett_mesh::store::TRUST_FILE).exists()
                || !self.old_state.join(nett_mesh::store::TRUST_FILE).exists())
        {
            out.push(self.old_state.as_path());
        }
        if self.old_relay.exists()
            && (self.relay_cert.join(KEY_FILE).exists() || !self.old_relay.join(KEY_FILE).exists())
        {
            out.push(self.old_relay.as_path());
        }
        out
    }
}

/// The regular files directly in `dir`.
fn regular_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("reading {}: {e}", dir.display()))?;
    let mut out = Vec::new();
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        if std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_file()) {
            out.push(path);
        }
    }
    Ok(out)
}

/// The user and group IDs of the user the mesh service runs as, from `/etc/passwd`. None where it
/// runs as root: on Synology DSM, whose accounts in `/etc/passwd` are people's DSM accounts
/// (design/dsm.md section 6.1).
pub fn mesh_owner() -> Option<(u32, u32)> {
    if crate::platform::linux::Flavor::detect() == crate::platform::linux::Flavor::Dsm {
        return None;
    }
    let passwd = read("/etc/passwd")?;
    let name = accounts().next()?;
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == name).then(|| {
            let uid = fields.nth(1)?.parse().ok()?;
            let gid = fields.next()?.parse().ok()?;
            Some((uid, gid))
        })?
    })
}

/// Whether `from` should be copied over `to`: `to` is missing or older.
fn newer(from: &Path, to: &Path) -> bool {
    let modified = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    match (modified(from), modified(to)) {
        (Some(f), Some(t)) => f > t,
        (_, None) => true,
        (None, Some(_)) => false,
    }
}

/// Copies a file through a temporary name, with `mode`.
fn copy(from: &Path, to: &Path, mode: u32) -> Result<(), String> {
    let tmp = to.with_extension("copy");
    let io = |e: std::io::Error| format!("copying {} to {}: {e}", from.display(), to.display());
    let _ = std::fs::remove_file(&tmp);
    std::fs::copy(from, &tmp).map_err(io)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)).map_err(io)?;
    std::fs::rename(&tmp, to).map_err(io)
}

fn ensure_private_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir)
        .and_then(|()| std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)))
        .map_err(|e| format!("creating {}: {e}", dir.display()))
}

/// Creates the relay's certificate in the identity directory when it has none (design/mesh.md
/// section 5.3): systemd hands it to the relay, which runs as a user it allocates.
pub fn ensure_relay_cert(layout: &Layout) -> Result<(), String> {
    ensure_private_dir(&layout.relay_cert)?;
    nett_relay::cert::RelayCert::load_or_create(&layout.relay_cert)
        .map(drop)
        .map_err(|e| e.to_string())
}

/// Whether the layout of 0.3.13 is still on the machine: its directories, the users the relay and
/// the transport adapter ran as, or their declaration.
pub fn old_remains(layout: &Layout) -> bool {
    layout.old_state.exists()
        || layout.old_relay.exists()
        || read("/etc/passwd").is_some_and(|p| OLD_ACCOUNTS.iter().any(|a| user_in(&p, a)))
        || read(SYSUSERS_CONF).is_some_and(|c| c != SYSUSERS)
}

fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// The second step of the move (design/release.md section 8), with full privileges: the start step of
/// nett-node's unit once an upgrade has settled, and `sudo nett install`. Copies what the first step
/// did not, deletes the old directories whose contents are copied, deletes the users the relay and the
/// transport adapter ran as (stopping and starting their running services around it, so that they
/// come back as users systemd allocates), and writes the account declaration again. Returns what it
/// did.
pub fn tidy(layout: &Layout) -> Result<Vec<String>, String> {
    let mut done = Vec::new();
    layout.prepare_state(mesh_owner())?;
    layout.copy_old_relay()?;
    for dir in layout.copied_old_dirs() {
        std::fs::remove_dir_all(dir).map_err(|e| format!("removing {}: {e}", dir.display()))?;
        done.push(format!("removed {}", dir.display()));
    }
    let passwd = read("/etc/passwd").ok_or("reading /etc/passwd")?;
    for (account, unit) in OLD_ACCOUNTS.into_iter().zip([RELAY_UNIT, TRANSPORT_UNIT]) {
        if !user_in(&passwd, account) {
            continue;
        }
        let systemctl = crate::platform::linux::systemctl().ok_or("systemctl is not here")?;
        let call = |args: &[&str]| crate::platform::run(systemctl, args, CALL_TIMEOUT);
        let running = call(&["is-active", "--quiet", unit])?;
        if running && !call(&["stop", unit])? {
            return Err(format!("systemctl could not stop {unit}"));
        }
        delete_account(account)?;
        if running && !call(&["start", unit])? {
            return Err(format!("systemctl could not start {unit} again"));
        }
        done.push(format!("removed the user {account}"));
    }
    if read(SYSUSERS_CONF).is_some_and(|c| c != SYSUSERS) {
        std::fs::write(SYSUSERS_CONF, SYSUSERS)
            .map_err(|e| format!("writing {SYSUSERS_CONF}: {e}"))?;
        done.push(format!("rewrote {SYSUSERS_CONF}"));
    }
    Ok(done)
}

/// The users declared in `nett.sysusers`; each has a group of the same name.
pub fn accounts() -> impl Iterator<Item = &'static str> {
    SYSUSERS
        .lines()
        .filter_map(|line| line.strip_prefix("u "))
        .filter_map(|rest| rest.split_whitespace().next())
}

/// Deletes a system user and its group of the same name where they exist (userdel removes the group
/// only on some systems).
pub fn delete_account(name: &str) -> Result<(), String> {
    let tool = |paths: [&'static str; 2]| paths.into_iter().find(|p| Path::new(p).exists());
    if read("/etc/passwd").is_some_and(|p| user_in(&p, name)) {
        let userdel = tool(USERDEL).ok_or("userdel is not on this machine")?;
        if !crate::platform::run(userdel, &[name], CALL_TIMEOUT)? {
            return Err(format!("userdel could not delete the user {name}"));
        }
    }
    if read("/etc/group").is_some_and(|g| group_in(&g, name).is_some()) {
        let groupdel = tool(GROUPDEL).ok_or("groupdel is not on this machine")?;
        if !crate::platform::run(groupdel, &[name], CALL_TIMEOUT)? {
            return Err(format!("groupdel could not delete the group {name}"));
        }
    }
    Ok(())
}

/// Whether `/etc/passwd` content names the user.
pub fn user_in(passwd: &str, name: &str) -> bool {
    passwd
        .lines()
        .any(|line| line.split(':').next() == Some(name))
}

/// A group's ID in `/etc/group` content.
pub fn group_in(groups: &str, name: &str) -> Option<u32> {
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

    fn layout(root: &Path) -> Layout {
        Layout {
            state: root.join("etc/state"),
            relay_cert: root.join("etc/relay"),
            old_state: root.join("lib/nett"),
            old_relay: root.join("lib/nett-relay"),
        }
    }

    /// Moving from 0.3.13 copies the trust store and the relay's certificate and keeps the old files
    /// until the second step, which removes only what was copied
    #[test]
    fn the_old_layout_is_copied_then_removed() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let l = layout(tmp.path());
        assert!(!l.copy_old_relay().expect("nothing to copy"));
        std::fs::create_dir_all(&l.old_state).expect("dir");
        std::fs::create_dir_all(&l.old_relay).expect("dir");
        std::fs::write(l.old_state.join("trust.json"), b"old trust").expect("write");
        std::fs::write(l.old_state.join("accepted.json"), b"old accepted").expect("write");
        std::fs::write(l.old_relay.join(CERT_FILE), b"cert").expect("write");
        std::fs::write(l.old_relay.join(KEY_FILE), b"key").expect("write");
        std::fs::write(l.old_relay.join("relay-state.json"), b"{}").expect("write");
        l.prepare_state(None).expect("prepared");
        assert!(l.copy_old_relay().expect("copied"));
        let read = |p: PathBuf| std::fs::read(p).expect("read");
        assert_eq!(read(l.state.join("trust.json")), b"old trust");
        assert_eq!(read(l.relay_cert.join(KEY_FILE)), b"key");
        assert!(
            !l.relay_cert.join("relay-state.json").exists(),
            "bindings are not identity"
        );
        let mode = |p: &Path| std::fs::metadata(p).expect("meta").permissions().mode() & 0o7777;
        assert_eq!(mode(&l.state), STATE_DIR_MODE);
        assert_eq!(mode(&l.state.join("trust.json")), 0o600);
        assert_eq!(mode(&l.relay_cert.join(KEY_FILE)), 0o600);
        assert!(
            l.old_state.join("trust.json").exists(),
            "the old files stay"
        );

        // The mesh writes its copy; copying again leaves it, until the old one is newer
        std::fs::write(l.state.join("trust.json"), b"new trust").expect("write");
        l.prepare_state(None).expect("prepared again");
        assert_eq!(read(l.state.join("trust.json")), b"new trust");
        let later = std::time::SystemTime::now() + Duration::from_secs(60);
        std::fs::File::options()
            .write(true)
            .open(l.old_state.join("trust.json"))
            .and_then(|f| f.set_modified(later))
            .expect("touch");
        l.prepare_state(None).expect("prepared again");
        assert_eq!(read(l.state.join("trust.json")), b"old trust");

        assert_eq!(
            l.copied_old_dirs(),
            [l.old_state.as_path(), l.old_relay.as_path()]
        );
    }

    /// An old directory whose contents did not reach the identity directory is not removed
    #[test]
    fn an_uncopied_old_directory_stays() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let l = layout(tmp.path());
        std::fs::create_dir_all(&l.old_relay).expect("dir");
        std::fs::write(l.old_relay.join(KEY_FILE), b"key").expect("write");
        assert!(l.copied_old_dirs().is_empty());
        std::fs::remove_file(l.old_relay.join(KEY_FILE)).expect("remove");
        assert_eq!(
            l.copied_old_dirs(),
            [l.old_relay.as_path()],
            "nothing in it to keep"
        );
    }

    #[test]
    fn the_accounts_are_the_declared_users() {
        assert_eq!(accounts().collect::<Vec<_>>(), ["nett"]);
        let passwd = "root:x:0:0::/root:/bin/sh\nnett-relay:x:996:996::/var/lib/nett-relay:-\n";
        assert!(user_in(passwd, "nett-relay"));
        assert!(!user_in(passwd, "nett"));
        let groups = "root:x:0:\nnetty:x:998:\nnett:x:997:\n";
        assert_eq!(group_in(groups, "nett"), Some(997));
        assert_eq!(group_in(groups, "nobody"), None);
        assert_eq!(group_in("nett:x:notanumber:\n", "nett"), None);
    }
}
