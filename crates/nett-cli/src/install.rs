//! `sudo nett install [<token>]` and `sudo nett uninstall` (design/hub.md section 7, release.md
//! section 4): both platforms do the same things with different service managers (launchd on macOS,
//! systemd on Linux). This module holds the command line and the file and subprocess operations
//! shared by both platforms; the per-platform steps are in `service` (macOS) and `service_linux`.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, bail};
use lexopt::ValueExt as _;
use nett_mesh::key::PrivateKey;
use nett_node::config::HubConfig;
use nett_proto::token::JoinToken;
use nett_trust::keys::X25519PublicKey;

#[cfg(target_os = "macos")]
use crate::service as platform;
#[cfg(target_os = "linux")]
use crate::service_linux as platform;

/// Upper bound for waiting on service manager commands to return (hard rule 14).
#[cfg(target_os = "linux")]
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
/// Upper bound for `nett leave` waiting for the Hub to confirm: if the Hub is unreachable, it exits
/// as usual (design/hub.md section 7).
const LEAVE_TIMEOUT: Duration = Duration::from_secs(10);

pub const INSTALL_USAGE: &str = "usage: sudo nett install [<token>] [--config <desired-state.json>]\n\n\
Creates this machine's keys (or keeps them), installs nett and starts the nett service.\n\
With a token from `nett site add <name>` or `nett site invite <name>`, it also connects this\n\
machine to the Hub (a new machine joins the site through it): the desired state then comes\n\
from the Hub, through the nett service.\n\
Without a Hub, the desired state comes from --config or, on macOS, from the site directory of\n\
the user running sudo. Run it again after upgrading nett.";
pub const UNINSTALL_USAGE: &str = "usage: sudo nett uninstall\n\n\
Stops and removes the nett service. Keys, the desired state and the Hub configuration stay;\n\
`sudo nett install` brings it back.";
pub const LEAVE_USAGE: &str = "usage: sudo nett leave [--dir <directory>]\n\n\
Leaves the site: tells the Hub, which removes this machine from every member, stops and\n\
removes the services, removes the mesh interface, and deletes the keys, the desired state,\n\
the trust store and the Hub configuration. The machine can then join any site. Without a Hub,\n\
remove it on the computer that holds the site with `nett site remove <name>`.\n\n\
With --dir, for a machine set up with `nett join`: tells the Hub and deletes the keys and\n\
configuration in that directory, and leaves the services to you.";
pub const JOIN_USAGE: &str = "usage: nett join [<token>] [--dir <directory>]\n\n\
Joins this machine to the site through the Hub without installing services, for service managers\n\
other than systemd and launchd. Creates the keys in the directory (or keeps them), joins with the\n\
token from `nett site add` or `nett site invite` (from NETT_TOKEN when it is not given), and\n\
writes hub.json and desired.json there; then run `nett daemon --dir` with that directory.\n\
The directory defaults to /etc/nett, and in the container to its volume.";

pub struct InstallArgs {
    pub token: Option<String>,
    pub config: Option<PathBuf>,
}

pub fn install_command(mut parser: lexopt::Parser) -> anyhow::Result<()> {
    let mut args = InstallArgs {
        token: None,
        config: None,
    };
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Long("config") => args.config = Some(PathBuf::from(parser.value()?)),
            lexopt::Arg::Value(v) if args.token.is_none() => args.token = Some(v.string()?),
            other => return Err(other.unexpected().into()),
        }
    }
    if args.token.is_some() && args.config.is_some() {
        bail!("with a token the desired state comes from the Hub; --config is not used");
    }
    platform::install(&args)
}

pub fn uninstall_command(mut parser: lexopt::Parser) -> anyhow::Result<()> {
    if let Some(arg) = parser.next()? {
        return Err(arg.unexpected().into());
    }
    platform::uninstall()
}

pub fn leave_command(mut parser: lexopt::Parser) -> anyhow::Result<()> {
    let mut dir = None;
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Long("dir") => dir = Some(parser.value()?.string()?),
            other => return Err(other.unexpected().into()),
        }
    }
    let Some(dir) = dir else {
        return platform::leave();
    };
    // A machine set up with `nett join`: its services are not nett's to remove
    tell_hub(&dir)?;
    forget(&dir)?;
    outln!(
        "Left the site: deleted the keys and configuration in {dir}. Stop its `nett daemon` yourself."
    );
    Ok(())
}

/// `nett join <token> [--dir]` (design/hub.md section 7): what `sudo nett install <token>` does,
/// without the services.
pub fn join_command(mut parser: lexopt::Parser) -> anyhow::Result<()> {
    let (mut token, mut dir) = (None, default_join_dir());
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Long("dir") => dir = parser.value()?.string()?,
            lexopt::Arg::Value(v) if token.is_none() => token = Some(v.string()?),
            other => return Err(other.unexpected().into()),
        }
    }
    // The container passes it in the environment, which other users cannot read
    let token = token
        .or_else(|| std::env::var("NETT_TOKEN").ok())
        .ok_or_else(|| anyhow::anyhow!(JOIN_USAGE))?;
    ensure_dir(&dir, 0o700)?;
    let keys = crate::daemon::node_keys(Path::new(&dir))?;
    let outcome = apply_token(&dir, Some(&token), &keys.0)?;
    if let Some(bytes) = outcome.desired {
        replace_if_changed(
            &Path::new(&dir).join(crate::daemon::DESIRED_FILE),
            &bytes,
            0o600,
        )?;
    }
    outln!("Ready in {dir}: run `nett daemon --dir {dir}`.");
    Ok(())
}

/// Where `nett join` writes: the volume in the container, `/etc/nett` elsewhere.
fn default_join_dir() -> String {
    #[cfg(target_os = "linux")]
    if let Some(dir) = crate::container::state_dir() {
        return dir.to_string_lossy().into_owned();
    }
    "/etc/nett".to_owned()
}

pub fn require_root() -> anyhow::Result<()> {
    if !rustix::process::geteuid().is_root() {
        bail!("the nett service runs as root; run this command with sudo");
    }
    Ok(())
}

/// Writes a temporary file in the same directory and renames it: a reader never sees a half-written
/// file.
pub fn write_atomic(path: &Path, content: &[u8], mode: u32) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::remove_file(&tmp).ok();
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .with_context(|| format!("writing {}", tmp.display()))?;
    file.write_all(content)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("writing {}", tmp.display()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting permissions of {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
}

/// Writes `path`; leaves it untouched when the content equals the existing content; returns whether
/// it wrote.
pub fn replace_if_changed(path: &Path, content: &[u8], mode: u32) -> anyhow::Result<bool> {
    if fs::read(path).is_ok_and(|old| old == content) {
        return Ok(false);
    }
    write_atomic(path, content, mode)?;
    Ok(true)
}

pub fn ensure_dir(path: &str, mode: u32) -> anyhow::Result<()> {
    fs::create_dir_all(path).with_context(|| format!("creating {path}"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting permissions of {path}"))
}

/// Copies the running `nett` to `target`; no copy when already running from there. Returns whether
/// it replaced the file.
pub fn copy_self(target: &str) -> anyhow::Result<bool> {
    let exe = std::env::current_exe().context("locating the running nett")?;
    let exe = fs::canonicalize(&exe).unwrap_or(exe);
    if exe == Path::new(target) {
        return Ok(false);
    }
    let bytes = fs::read(&exe).with_context(|| format!("reading {}", exe.display()))?;
    replace_if_changed(Path::new(target), &bytes, 0o755)
}

/// Runs a service manager command with an argument array (hard rule 9: the program is a fixed
/// absolute path, no shell), with a timeout; returns whether it succeeded.
#[cfg(target_os = "linux")]
pub fn run(program: &str, args: &[&str]) -> anyhow::Result<bool> {
    nett_node::platform::run(program, args, COMMAND_TIMEOUT).map_err(anyhow::Error::msg)
}

/// Result when there is a token.
#[derive(Default)]
pub struct TokenOutcome {
    /// The Hub configuration changed: the nett service restarts to connect with it.
    pub hub_changed: bool,
    /// The first desired state the Hub sends when a new machine joins; the caller writes it as the
    /// desired state file.
    pub desired: Option<Vec<u8>>,
}

/// Checks the token when there is one, writes the Hub configuration and reports the result. An
/// enrollment token (design/hub.md section 6) enrolls through the Hub first; a join token (section
/// 3.5) only checks that this machine is already a member.
pub fn apply_token(
    dir: &str,
    token: Option<&str>,
    mesh_public: &X25519PublicKey,
) -> anyhow::Result<TokenOutcome> {
    let state_dir = Path::new(dir).join(nett_mesh::store::STATE_DIR);
    let Some(text) = token else {
        return Ok(TokenOutcome::default());
    };
    let token = JoinToken::decode(text)?;
    if token.enroll.is_some() {
        return enroll(dir, &state_dir, &token, mesh_public);
    }
    let hub_changed = match crate::join::join(Path::new(dir), &state_dir, text)? {
        crate::join::Joined::New(url) => {
            outln!("Connecting this machine to the Hub at {url}.");
            true
        }
        crate::join::Joined::Switched { from, to } => {
            outln!("Switching this machine from the Hub at {from} to {to}.");
            true
        }
        crate::join::Joined::Unchanged => false,
    };
    Ok(TokenOutcome {
        hub_changed,
        desired: None,
    })
}

/// A new machine joins through the Hub. Refused if it is already a member of a site; when the same
/// machine retries the same token, it completes as usual.
fn enroll(
    dir: &str,
    state_dir: &Path,
    token: &JoinToken,
    mesh_public: &X25519PublicKey,
) -> anyhow::Result<TokenOutcome> {
    let dir = Path::new(dir);
    let member =
        state_dir.join(nett_mesh::store::TRUST_FILE).exists() || dir.join("desired.json").exists();
    if member {
        if HubConfig::load(dir)
            .map_err(anyhow::Error::msg)?
            .is_some_and(|c| c.node_id == token.node_id)
        {
            outln!("This machine has already joined the site through the Hub.");
            return Ok(TokenOutcome::default());
        }
        bail!(
            "this machine is already a member of a site; `sudo nett leave` first, then run this \
             command again"
        );
    }
    outln!("Joining the site through the Hub at {}.", token.url);
    let enrolled = runtime()?.block_on(nett_node::join::enroll(dir, token, unix_now()))?;
    crate::site::check_desired_for(&enrolled.desired, mesh_public)
        .context("the Hub's desired state for this machine")?;
    enrolled.config.save(dir).map_err(anyhow::Error::msg)?;
    Ok(TokenOutcome {
        hub_changed: true,
        desired: Some(enrolled.desired),
    })
}

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// First step of `nett leave`: tells the Hub when there is a Hub configuration. If the Hub is
/// unreachable, explains what to do on the computer afterwards and continues as usual.
pub fn tell_hub(dir: &str) -> anyhow::Result<()> {
    let Some(config) = HubConfig::load(Path::new(dir)).map_err(anyhow::Error::msg)? else {
        outln!(
            "This machine has no Hub. On the computer that holds the site, remove it with \
             `nett site remove <name>`."
        );
        return Ok(());
    };
    let identity = PrivateKey::load(&Path::new(dir).join("identity.key"))?;
    let secret = x25519_dalek::StaticSecret::from(*identity.as_bytes());
    drop(identity);
    let told = runtime()?.block_on(async {
        tokio::time::timeout(LEAVE_TIMEOUT, nett_node::session::leave(&config, &secret)).await
    });
    match told {
        Ok(Ok(())) => outln!(
            "Told the Hub at {}: every member drops this machine.",
            config.url
        ),
        Ok(Err(e)) => outln!(
            "Could not tell the Hub at {} ({e}). On the computer that holds the site, remove this \
             machine with `nett site remove <name>`.",
            config.url
        ),
        Err(_) => outln!(
            "The Hub at {} did not answer in time. On the computer that holds the site, remove this \
             machine with `nett site remove <name>`.",
            config.url
        ),
    }
    Ok(())
}

/// Last step of `nett leave`: deletes the keys, the desired state, the Hub configuration and the
/// copy of the Hub's backup, the upgrade records and the trust store (design/auth.md section 8.3).
pub fn forget(dir: &str) -> anyhow::Result<()> {
    remove_files(
        dir,
        &[
            "mesh.key",
            "identity.key",
            "desired.json",
            nett_node::config::HUB_FILE,
            nett_node::session::BACKUP_FILE,
        ],
    )?;
    forget_upgrades(dir)?;
    remove_tree(
        &Path::new(dir)
            .join(nett_mesh::store::STATE_DIR)
            .to_string_lossy(),
    )
}

/// Deletes the upgrade records next to the identity (design/release.md section 8).
pub fn forget_upgrades(dir: &str) -> anyhow::Result<()> {
    remove_files(
        dir,
        &[
            nett_node::upgrade::STATE_FILE,
            nett_node::upgrade::MARKER_FILE,
        ],
    )
}

/// Deletes the named files in `dir`; a missing one is fine.
pub fn remove_files(dir: &str, names: &[&str]) -> anyhow::Result<()> {
    for name in names {
        remove_file(&Path::new(dir).join(name).to_string_lossy())?;
    }
    Ok(())
}

/// Deletes a file; a missing one is fine.
pub fn remove_file(path: &str) -> anyhow::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {path}")),
    }
}

/// Deletes a directory with everything in it; a missing one is fine.
pub fn remove_tree(path: &str) -> anyhow::Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {path}")),
    }
}

/// Deletes a directory when it is empty; returns whether it is gone.
pub fn remove_if_empty(path: &str) -> anyhow::Result<bool> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => Ok(false),
        Err(e) => Err(e).with_context(|| format!("removing {path}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Leaving deletes the identity and the upgrade records and nothing else; a directory goes only
    /// when nothing is left in it
    #[test]
    fn forgetting_deletes_the_identity_and_leaves_empty_directories_to_go() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let dir = tmp.path().join("nett");
        let state = dir.join("state");
        fs::create_dir_all(&state).expect("dirs");
        for name in [
            "mesh.key",
            "identity.key",
            "desired.json",
            nett_node::config::HUB_FILE,
            nett_node::session::BACKUP_FILE,
            nett_node::upgrade::STATE_FILE,
            "nett",
        ] {
            fs::write(dir.join(name), b"x").expect("write");
        }
        fs::write(state.join("trust.json"), b"{}").expect("write");
        let dir_s = dir.to_string_lossy();
        forget(&dir_s).expect("forget");
        assert!(!state.exists());
        let left: Vec<_> = fs::read_dir(&dir)
            .expect("read")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(left, ["nett"], "the program is not part of the identity");
        assert!(!remove_if_empty(&dir_s).expect("not empty"));
        remove_file(&dir.join("nett").to_string_lossy()).expect("remove");
        remove_file(&dir.join("nett").to_string_lossy()).expect("a missing file is fine");
        assert!(remove_if_empty(&dir_s).expect("empty"));
        assert!(!dir.exists());
        assert!(remove_if_empty(&dir_s).expect("a missing directory is gone"));
    }
}
