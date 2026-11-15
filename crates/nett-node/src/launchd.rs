//! nett's launchd services on macOS (design/userspace.md section 6.3, design/release.md section 4):
//! their configuration, which `sudo nett install` writes and nett-node keeps for the transport
//! adapter, the launchctl calls that start and stop them, and the transport adapter's account. Every
//! call is blocking: async callers use a blocking thread.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::platform::macos::{DIR, LAUNCHCTL, MESH_LABEL, NODE_LABEL, PROGRAM, TRANSPORT_LABEL};

pub const LOG_DIR: &str = "/Library/Logs/nett";
pub const NEWSYSLOG: &str = "/etc/newsyslog.d/nett.conf";
pub const DESIRED: &str = "/Library/Application Support/nett/desired.json";
pub const KEY: &str = "/Library/Application Support/nett/mesh.key";
/// Fixed location of the directory service tool (hard rule 9).
const DSCL: &str = "/usr/bin/dscl";
/// Time limit of one launchctl or dscl call (hard rule 14).
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Upper bound for waiting for launchd to unload a service.
const UNLOAD_TIMEOUT: Duration = Duration::from_secs(15);
/// Upper bound for the directory service to show an account it just created.
const ACCOUNT_TIMEOUT: Duration = Duration::from_secs(10);
/// The account's ID: the highest one in this range free as both a user and a group ID.
const ACCOUNT_IDS: std::ops::Range<u32> = 300..400;

/// A launchd service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Service {
    pub label: &'static str,
    pub plist: &'static str,
    /// Which `nett` command to run.
    pub args: &'static [&'static str],
    pub log: &'static str,
    /// How it is referred to in help and reports.
    pub what: &'static str,
}

pub const MESH: Service = Service {
    label: MESH_LABEL,
    plist: "/Library/LaunchDaemons/io.gotry.nett.mesh.plist",
    args: &["mesh", "--config", DESIRED, "--key", KEY],
    log: "mesh.log",
    what: "the mesh service",
};

pub const NODE: Service = Service {
    label: NODE_LABEL,
    plist: "/Library/LaunchDaemons/io.gotry.nett.node.plist",
    args: &["node", "--dir", DIR],
    log: "node.log",
    what: "nett-node",
};

/// Started as root like the others: the copy is in the root-only directory, and the adapter switches
/// to its own account before anything else.
pub const TRANSPORT: Service = Service {
    label: TRANSPORT_LABEL,
    plist: "/Library/LaunchDaemons/io.gotry.nett.transport.plist",
    args: &["transport"],
    log: "transport.log",
    what: "the transport adapter",
};

/// launchd configuration: root runs the copy, starts at boot, restarts after exit
/// (design/userspace.md section 6.3).
pub fn plist(service: &Service) -> String {
    let args: String = service
        .args
        .iter()
        .map(|a| format!("\n    <string>{a}</string>"))
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Written by nett; changes here are replaced. -->
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{PROGRAM}</string>{args}
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <!-- After a crash, restart at most every 5 seconds -->
  <key>ThrottleInterval</key>
  <integer>5</integer>
  <!-- No timer coalescing: path switching runs on a 100 ms tick -->
  <key>ProcessType</key>
  <string>Interactive</string>
  <!-- 077: files the service creates are readable by root only -->
  <key>Umask</key>
  <integer>63</integer>
  <!-- Logs go to the system log; this file records only start-up failures -->
  <key>StandardErrorPath</key>
  <string>{LOG_DIR}/{log}</string>
</dict>
</plist>
"#,
        label = service.label,
        log = service.log,
    )
}

/// Rotation of the start-up failure records: rotates above 1 MB, keeps 5 copies, compresses the old
/// ones.
pub fn newsyslog() -> String {
    let lines: String = [MESH, NODE, TRANSPORT]
        .iter()
        .map(|s| {
            format!(
                "{LOG_DIR}/{:<14} root:wheel     600   5      1024      *     JN\n",
                s.log
            )
        })
        .collect();
    format!(
        "# Written by nett: rotation of the services' start-up failure logs.\n\
         # logfilename                            [owner:group]  mode  count  size(KB)  when  flags\n\
         {lines}"
    )
}

pub fn launchctl(args: &[&str]) -> Result<bool, String> {
    crate::platform::run(LAUNCHCTL, args, CALL_TIMEOUT)
}

pub fn loaded(service: &Service) -> Result<bool, String> {
    launchctl(&["print", &format!("system/{}", service.label)])
}

/// Loads the service from its configuration file.
pub fn start(service: &Service) -> Result<(), String> {
    if launchctl(&["bootstrap", "system", service.plist])? {
        Ok(())
    } else {
        Err(format!(
            "launchctl could not start {}; see {LOG_DIR}/{}",
            service.what, service.log
        ))
    }
}

/// Unloads the service, and waits until launchd no longer has it: when bootout returns, the process
/// may still be exiting, and a start right after would meet it.
pub fn stop(service: &Service) -> Result<(), String> {
    if !loaded(service)? {
        return Ok(());
    }
    if !launchctl(&["bootout", &format!("system/{}", service.label)])? {
        return Err(format!("launchctl could not stop {}", service.what));
    }
    let deadline = Instant::now() + UNLOAD_TIMEOUT;
    while loaded(service)? {
        if Instant::now() >= deadline {
            return Err(format!(
                "{} did not stop within {} seconds",
                service.what,
                UNLOAD_TIMEOUT.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

/// Restarts a loaded service, on the program as it is now; one that is not loaded stays so.
pub fn restart(service: &Service) -> Result<(), String> {
    if !loaded(service)? {
        return Ok(());
    }
    let target = format!("system/{}", service.label);
    if launchctl(&["kickstart", "-k", &target])? {
        Ok(())
    } else {
        Err(format!("launchctl could not restart {}", service.what))
    }
}

/// Writes a service's configuration file when it differs; returns whether it changed.
pub fn write_plist(service: &Service) -> Result<bool, String> {
    let content = plist(service);
    if std::fs::read(service.plist).ok().as_deref() == Some(content.as_bytes()) {
        return Ok(false);
    }
    write_file(service.plist, content.as_bytes())
        .map_err(|e| format!("writing {}: {e}", service.plist))?;
    Ok(true)
}

/// Runs the transport adapter while `want` (design/userspace.md section 6.3): makes its account
/// first, and reloads it when its configuration changed (launchd keeps the configuration it loaded).
/// When not wanted, unloads it and deletes its configuration.
pub fn set_transport(want: bool) -> Result<(), String> {
    if !want {
        stop(&TRANSPORT)?;
        return match std::fs::remove_file(TRANSPORT.plist) {
            Ok(()) => {
                tracing::info!("the transport adapter stopped");
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("removing {}: {e}", TRANSPORT.plist)),
        };
    }
    ensure_account()?;
    if write_plist(&TRANSPORT)? {
        stop(&TRANSPORT)?;
    }
    if !loaded(&TRANSPORT)? {
        start(&TRANSPORT)?;
        tracing::info!("the transport adapter started");
    }
    Ok(())
}

/// Makes the transport adapter's account and its group of the same name when they are missing
/// (design/userspace.md section 6.3): hidden, no password, no shell, no home.
pub fn ensure_account() -> Result<(), String> {
    let name = nett_mesh::helper::TRANSPORT_USER;
    if nett_mesh::macos::account_ids(name)
        .map_err(|e| format!("looking up the account {name}: {e}"))?
        .is_some()
    {
        return Ok(());
    }
    let id = ACCOUNT_IDS
        .rev()
        .find(|id| !nett_mesh::macos::id_in_use(*id))
        .ok_or_else(|| {
            format!(
                "no ID from {} to {} is free for the account {name}",
                ACCOUNT_IDS.start,
                ACCOUNT_IDS.end - 1
            )
        })?
        .to_string();
    let (group, user) = (format!("/Groups/{name}"), format!("/Users/{name}"));
    let what = "nett transport adapter";
    let steps: [&[&str]; 12] = [
        &[".", "-create", &group],
        &[".", "-create", &group, "PrimaryGroupID", &id],
        &[".", "-create", &group, "RealName", what],
        &[".", "-create", &group, "Password", "*"],
        &[".", "-create", &user],
        &[".", "-create", &user, "UniqueID", &id],
        &[".", "-create", &user, "PrimaryGroupID", &id],
        &[".", "-create", &user, "UserShell", "/usr/bin/false"],
        &[".", "-create", &user, "NFSHomeDirectory", "/var/empty"],
        &[".", "-create", &user, "RealName", what],
        &[".", "-create", &user, "Password", "*"],
        &[".", "-create", &user, "IsHidden", "1"],
    ];
    for args in steps {
        if !crate::platform::run(DSCL, args, CALL_TIMEOUT)? {
            return Err(format!("dscl {} failed", args.join(" ")));
        }
    }
    // The directory service caches lookups: the new account appears shortly after
    let deadline = Instant::now() + ACCOUNT_TIMEOUT;
    loop {
        if let Ok(Some(_)) = nett_mesh::macos::account_ids(name) {
            tracing::info!(account = name, id = %id, "account created for the transport adapter");
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "the account {name} did not appear after it was created"
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Writes a configuration file through a temporary file, mode `0644`.
fn write_file(path: &str, content: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let tmp = format!("{path}.new");
    let _ = std::fs::remove_file(&tmp);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&tmp)?;
    file.write_all(content)?;
    file.sync_all()?;
    std::fs::rename(&tmp, Path::new(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The configuration files are valid property lists, and run the root-only copy
    #[test]
    fn plists_are_valid_and_run_the_copy() {
        let dir = tempfile::tempdir().expect("temp dir");
        for service in [MESH, NODE, TRANSPORT] {
            let text = plist(&service);
            assert!(text.contains(&format!("<string>{PROGRAM}</string>")));
            assert!(text.contains(&format!("<string>{}</string>", service.label)));
            assert!(text.contains(&format!("{LOG_DIR}/{}", service.log)));
            assert!(!text.contains("UserName"), "every service starts as root");
            let path = dir.path().join(format!("{}.plist", service.label));
            std::fs::write(&path, &text).expect("write");
            let lint = std::process::Command::new("/usr/bin/plutil")
                .arg("-lint")
                .arg(&path)
                .output()
                .expect("plutil");
            assert!(
                lint.status.success(),
                "{}",
                String::from_utf8_lossy(&lint.stdout)
            );
        }
        assert!(plist(&TRANSPORT).contains("<string>transport</string>"));
        assert!(plist(&NODE).contains("<string>node</string>"));
        let mesh = plist(&MESH);
        assert!(mesh.contains(&format!("<string>{DESIRED}</string>")));
        assert!(
            !mesh.contains("homebrew"),
            "the service never runs the Homebrew copy"
        );
    }

    #[test]
    fn every_log_is_rotated() {
        let conf = newsyslog();
        for service in [MESH, NODE, TRANSPORT] {
            assert!(
                conf.contains(&format!("{LOG_DIR}/{}", service.log)),
                "{conf}"
            );
        }
    }
}
