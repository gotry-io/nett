//! nett's launchd services on macOS (design/userspace.md section 6.3, design/release.md section 4):
//! their configuration, which `sudo nett install` writes, and the launchctl calls that start and stop
//! them. Every call is blocking: async callers use a blocking thread.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::platform::macos::{DIR, LAUNCHCTL, MESH_LABEL, NODE_LABEL, PROGRAM};

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

/// The separate transport service release 0.3.11 ran, under the hidden account `_nett-transport`;
/// the mesh process carries the TLS transport itself (ADR 0013). [`remove_transport_service`]
/// removes both.
const OLD_TRANSPORT: Service = Service {
    label: "io.gotry.nett.transport",
    plist: "/Library/LaunchDaemons/io.gotry.nett.transport.plist",
    args: &["transport"],
    log: "transport.log",
    what: "the transport service of nett 0.3.11",
};
const OLD_TRANSPORT_ACCOUNT: &str = "_nett-transport";

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
<!-- Written by `sudo nett install`; it rewrites this file on the next run. -->
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
    format!(
        "# Written by `sudo nett install`: rotation of the services' start-up failure logs.\n\
         # logfilename              [owner:group]  mode  count  size(KB)  when  flags\n\
         {LOG_DIR}/mesh.log    root:wheel     600   5      1024      *     JN\n\
         {LOG_DIR}/node.log    root:wheel     600   5      1024      *     JN\n"
    )
}

pub fn launchctl(args: &[&str]) -> Result<bool, String> {
    crate::platform::run(LAUNCHCTL, args, CALL_TIMEOUT)
}

pub fn loaded(service: &Service) -> Result<bool, String> {
    launchctl(&["print", &format!("system/{}", service.label)])
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
        format!("{LOG_DIR}/{}", OLD_TRANSPORT.log),
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
        for service in [MESH, NODE] {
            assert!(
                conf.contains(&format!("{LOG_DIR}/{}", service.log)),
                "{conf}"
            );
        }
    }
}
