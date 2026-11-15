//! nett's launchd services on macOS (design/userspace.md section 6.3, design/release.md sections 4
//! and 7): their configuration, which `sudo nett install` writes and nett-node keeps up with the
//! program, the launchctl calls that start and stop them, and the removal of what earlier releases
//! placed. Every call is blocking: async callers use a blocking thread.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::platform::macos::{DIR, LAUNCHCTL, MESH_LABEL, NODE_LABEL, PROGRAM};

pub const DESIRED: &str = "/Library/Application Support/nett/desired.json";
pub const KEY: &str = "/Library/Application Support/nett/mesh.key";
/// Fixed location of the directory service tool (hard rule 9).
const DSCL: &str = "/usr/bin/dscl";
/// Time limit of one launchctl or dscl call (hard rule 14).
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Upper bound for waiting for launchd to unload a service.
const UNLOAD_TIMEOUT: Duration = Duration::from_secs(15);

/// A launchd service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Service {
    pub label: &'static str,
    pub plist: &'static str,
    /// Which `nett` command to run.
    pub args: &'static [&'static str],
    /// How it is referred to in help and reports.
    pub what: &'static str,
}

pub const MESH: Service = Service {
    label: MESH_LABEL,
    plist: "/Library/LaunchDaemons/io.gotry.nett.mesh.plist",
    args: &["mesh", "--config", DESIRED, "--key", KEY],
    what: "the mesh service",
};

pub const NODE: Service = Service {
    label: NODE_LABEL,
    plist: "/Library/LaunchDaemons/io.gotry.nett.node.plist",
    args: &["node", "--dir", DIR],
    what: "nett-node",
};

/// The separate transport service release 0.3.11 ran, under the hidden account `_nett-transport`;
/// the mesh process carries the TLS transport itself (ADR 0013). [`remove_transport_service`]
/// removes both.
const OLD_TRANSPORT: Service = Service {
    label: "io.gotry.nett.transport",
    plist: "/Library/LaunchDaemons/io.gotry.nett.transport.plist",
    args: &["transport"],
    what: "the transport service of nett 0.3.11",
};
const OLD_TRANSPORT_ACCOUNT: &str = "_nett-transport";
/// Earlier releases had launchd write each service's start-up failures to a file here, rotated by
/// [`OLD_NEWSYSLOG`]; the services log only to the system log. [`remove_old_logs`] removes both.
const OLD_LOG_DIR: &str = "/Library/Logs/nett";
const OLD_NEWSYSLOG: &str = "/etc/newsyslog.d/nett.conf";

/// launchd configuration: root runs the copy, starts at boot, restarts after exit
/// (design/userspace.md section 6.3). Logs go to the system log, start-up failures included.
pub fn plist(service: &Service) -> String {
    let args: String = service
        .args
        .iter()
        .map(|a| format!("\n    <string>{a}</string>"))
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Written by nett; it rewrites this file when nett is installed or upgraded. -->
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
</dict>
</plist>
"#,
        label = service.label,
    )
}

pub fn launchctl(args: &[&str]) -> Result<bool, String> {
    crate::platform::run(LAUNCHCTL, args, CALL_TIMEOUT)
}

pub fn loaded(service: &Service) -> Result<bool, String> {
    launchctl(&["print", &format!("system/{}", service.label)])
}

/// Loads the service from its configuration file.
pub fn bootstrap(service: &Service) -> Result<(), String> {
    if launchctl(&["bootstrap", "system", service.plist])? {
        Ok(())
    } else {
        Err(format!(
            "launchctl could not start {}; see `log show --last 10m --predicate 'process == \"nett\"'`",
            service.what
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

/// Writes a service's configuration file through a temporary file, mode `0644` whatever the umask
/// (launchd refuses a file others can write).
pub fn write_plist(service: &Service, content: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    let io = |e: std::io::Error| format!("writing {}: {e}", service.plist);
    let tmp = format!("{}.new", service.plist);
    let _ = std::fs::remove_file(&tmp);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(io)?;
    file.write_all(content).map_err(io)?;
    file.sync_all().map_err(io)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).map_err(io)?;
    std::fs::rename(&tmp, service.plist).map_err(io)
}

/// The configuration file's content when it exists and differs from this program's.
fn outdated(service: &Service) -> Option<Vec<u8>> {
    let on_disk = std::fs::read(service.plist).ok()?;
    (on_disk != plist(service).as_bytes()).then_some(on_disk)
}

/// After an upgrade the launchd configuration may have changed with the program (design/release.md
/// section 7). Rewrites the mesh service's and reloads the service with it; when the new one does
/// not load, the previous one goes back, so the mesh keeps running. Rewrites nett-node's own, which
/// launchd reads the next time it loads nett-node. Then removes the start-up failure logs of earlier
/// releases once no loaded service writes them.
pub fn refresh() -> Result<(), String> {
    if let Some(previous) = outdated(&MESH) {
        write_plist(&MESH, plist(&MESH).as_bytes())?;
        if let Err(e) = stop(&MESH).and_then(|()| bootstrap(&MESH)) {
            write_plist(&MESH, &previous)?;
            if !loaded(&MESH)? {
                bootstrap(&MESH)?;
            }
            return Err(format!("{e}; kept the previous configuration"));
        }
        tracing::info!("the mesh service runs with its configuration from this program");
    }
    if outdated(&NODE).is_some() {
        write_plist(&NODE, plist(&NODE).as_bytes())?;
        tracing::info!("nett-node's configuration updated; launchd reads it when it next loads it");
    }
    if !writes_old_log() {
        remove_old_logs()?;
    }
    Ok(())
}

/// Whether this process's standard error is the start-up failure log of an earlier release: launchd
/// still has nett-node's earlier configuration loaded.
fn writes_old_log() -> bool {
    use std::os::unix::fs::MetadataExt as _;
    let (Ok(stderr), Ok(log)) = (
        std::fs::metadata("/dev/fd/2"),
        std::fs::metadata(format!("{OLD_LOG_DIR}/node.log")),
    ) else {
        return false;
    };
    stderr.is_file() && stderr.ino() == log.ino()
}

/// Removes the start-up failure logs of earlier releases and their rotation configuration. Only once
/// the services are loaded with this program's configuration, which has no log file.
pub fn remove_old_logs() -> Result<(), String> {
    match std::fs::remove_file(OLD_NEWSYSLOG) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("removing {OLD_NEWSYSLOG}: {e}")),
    }
    match std::fs::remove_dir_all(OLD_LOG_DIR) {
        Ok(()) => {
            tracing::info!(
                dir = OLD_LOG_DIR,
                "removed the log files of earlier releases"
            );
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("removing {OLD_LOG_DIR}: {e}")),
    }
}

/// Removes the transport service of nett 0.3.11 and its account and group where they exist: stops
/// the service, deletes the account and the group, then its log and its configuration. The
/// configuration goes last, so a step that fails is tried again the next time. Returns whether there
/// was anything to remove.
pub fn remove_transport_service() -> Result<bool, String> {
    let plist = Path::new(OLD_TRANSPORT.plist);
    if !plist.exists() {
        return Ok(false);
    }
    stop(&OLD_TRANSPORT)?;
    for record in [
        format!("/Users/{OLD_TRANSPORT_ACCOUNT}"),
        format!("/Groups/{OLD_TRANSPORT_ACCOUNT}"),
    ] {
        if crate::platform::run(DSCL, &[".", "-read", &record, "RecordName"], CALL_TIMEOUT)?
            && !crate::platform::run(DSCL, &[".", "-delete", &record], CALL_TIMEOUT)?
        {
            return Err(format!("dscl could not delete {record}"));
        }
    }
    for path in [
        format!("{OLD_LOG_DIR}/transport.log"),
        OLD_TRANSPORT.plist.to_owned(),
    ] {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("removing {path}: {e}")),
        }
    }
    tracing::info!(
        account = OLD_TRANSPORT_ACCOUNT,
        "removed the transport service of nett 0.3.11 and its account"
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The configuration files are valid property lists, and run the root-only copy
    #[test]
    fn plists_are_valid_and_run_the_copy() {
        let dir = tempfile::tempdir().expect("temp dir");
        for service in [MESH, NODE] {
            let text = plist(&service);
            assert!(text.contains(&format!("<string>{PROGRAM}</string>")));
            assert!(text.contains(&format!("<string>{}</string>", service.label)));
            assert!(!text.contains("UserName"), "every service starts as root");
            assert!(
                !text.contains("StandardErrorPath"),
                "logs go to the system log only"
            );
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
        assert!(plist(&NODE).contains("<string>node</string>"));
        let mesh = plist(&MESH);
        assert!(mesh.contains(&format!("<string>{DESIRED}</string>")));
        assert!(
            !mesh.contains("homebrew"),
            "the service never runs the Homebrew copy"
        );
    }
}
