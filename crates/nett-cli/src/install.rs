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
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
/// Upper bound for `nett leave` waiting for the Hub to confirm: if the Hub is unreachable, it exits
/// as usual (design/hub.md section 7).
const LEAVE_TIMEOUT: Duration = Duration::from_secs(10);

pub const INSTALL_USAGE: &str = "usage: sudo nett install [<token>] [--config <desired-state.json>]\n\n\
Creates this machine's keys (or keeps them), installs nett and starts the mesh service.\n\
With a token from `nett site add <name>` or `nett site invite <name>`, it also connects this\n\
machine to the Hub (a new machine joins the site through it): the desired state then comes\n\
from the Hub, and the nett-node service runs next to the mesh service.\n\
Without a Hub, the desired state comes from --config or, on macOS, from the site directory of\n\
the user running sudo. Run it again after upgrading nett.";
pub const UNINSTALL_USAGE: &str = "usage: sudo nett uninstall\n\n\
Stops and removes the services. Keys, the desired state and the Hub configuration stay;\n\
`sudo nett install` brings the services back.";
pub const LEAVE_USAGE: &str = "usage: sudo nett leave\n\n\
Leaves the site: tells the Hub, which removes this machine from every member, stops and\n\
removes the services, removes the mesh interface, and deletes the keys, the desired state,\n\
the trust store and the Hub configuration. The machine can then join any site. Without a Hub,\n\
remove it on the computer that holds the site with `nett site remove <name>`.";

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
    if let Some(arg) = parser.next()? {
        return Err(arg.unexpected().into());
    }
    platform::leave()
}

pub fn require_root() -> anyhow::Result<()> {
    if !rustix::process::geteuid().is_root() {
        bail!("the services run as root; run this command with sudo");
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
pub fn run(program: &str, args: &[&str]) -> anyhow::Result<bool> {
    nett_node::platform::run(program, args, COMMAND_TIMEOUT).map_err(anyhow::Error::msg)
}

/// Result when there is a token.
#[derive(Default)]
pub struct TokenOutcome {
    /// The Hub configuration changed: nett-node must restart.
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
    state_dir: &str,
    token: Option<&str>,
    mesh_public: &X25519PublicKey,
) -> anyhow::Result<TokenOutcome> {
    let Some(text) = token else {
        return Ok(TokenOutcome::default());
    };
    let token = JoinToken::decode(text)?;
    if token.enroll.is_some() {
        return enroll(dir, state_dir, &token, mesh_public);
    }
    let hub_changed = match crate::join::join(Path::new(dir), Path::new(state_dir), text)? {
        crate::join::Joined::New(url) => {
            println!("Connecting this machine to the Hub at {url}.");
            true
        }
        crate::join::Joined::Switched { from, to } => {
            println!("Switching this machine from the Hub at {from} to {to}.");
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
    state_dir: &str,
    token: &JoinToken,
    mesh_public: &X25519PublicKey,
) -> anyhow::Result<TokenOutcome> {
    let dir = Path::new(dir);
    let member = Path::new(state_dir)
        .join(nett_mesh::store::TRUST_FILE)
        .exists()
        || dir.join("desired.json").exists();
    if member {
        if HubConfig::load(dir)
            .map_err(anyhow::Error::msg)?
            .is_some_and(|c| c.node_id == token.node_id)
        {
            println!("This machine has already joined the site through the Hub.");
            return Ok(TokenOutcome::default());
        }
        bail!(
            "this machine is already a member of a site; `sudo nett leave` first, then run this \
             command again"
        );
    }
    println!("Joining the site through the Hub at {}.", token.url);
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
        println!(
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
        Ok(Ok(())) => println!(
            "Told the Hub at {}: every member drops this machine.",
            config.url
        ),
        Ok(Err(e)) => println!(
            "Could not tell the Hub at {} ({e}). On the computer that holds the site, remove this \
             machine with `nett site remove <name>`.",
            config.url
        ),
        Err(_) => println!(
            "The Hub at {} did not answer in time. On the computer that holds the site, remove this \
             machine with `nett site remove <name>`.",
            config.url
        ),
    }
    Ok(())
}

/// Last step of `nett leave`: deletes the keys, the desired state, the Hub configuration and the
/// trust store (design/auth.md section 8.3).
pub fn forget(dir: &str, state_dir: &str) -> anyhow::Result<()> {
    for name in [
        "mesh.key",
        "identity.key",
        "desired.json",
        nett_node::config::HUB_FILE,
        nett_node::upgrade::STATE_FILE,
        nett_node::upgrade::MARKER_FILE,
    ] {
        let path = Path::new(dir).join(name);
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {}", path.display())),
        }
    }
    match fs::remove_dir_all(state_dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {state_dir}")),
    }
}
