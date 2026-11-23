//! nett's launchd service on macOS (design/userspace.md section 6.3, design/release.md sections 4
//! and 7): its configuration, which `sudo nett install` writes and the service keeps up with the
//! program, and the launchctl calls that start and stop it. The service runs `nett daemon`, which
//! with a Hub also runs nett-node (ADR 0013). Every call is blocking: async callers use a blocking
//! thread.

use std::time::{Duration, Instant};

use crate::platform::macos::{DIR, LABEL, LAUNCHCTL, PROGRAM};

/// Time limit of one launchctl call (hard rule 14).
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

pub const DAEMON: Service = Service {
    label: LABEL,
    plist: "/Library/LaunchDaemons/io.gotry.nett.plist",
    args: &["daemon", "--dir", DIR],
    what: "the nett service",
};

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
  <!-- Small allocations share the tiny zone: the nano zone keeps a page per size and CPU it has
       used, megabytes for a service whose small objects take kilobytes -->
  <key>EnvironmentVariables</key>
  <dict>
    <key>MallocNanoZone</key>
    <string>0</string>
  </dict>
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
/// section 7): rewrites it, and launchd reads it the next time it loads the service, at the latest
/// when the machine starts. This runs in the service itself, which cannot load itself again.
pub fn refresh() -> Result<(), String> {
    if outdated(&DAEMON).is_some() {
        write_plist(&DAEMON, plist(&DAEMON).as_bytes())?;
        tracing::info!(
            "the service's configuration updated; launchd reads it when it next loads the service"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The configuration file is a valid property list and runs the root-only copy as `nett daemon`
    #[test]
    fn the_plist_is_valid_and_runs_the_copy() {
        let dir = tempfile::tempdir().expect("temp dir");
        let text = plist(&DAEMON);
        assert!(text.contains(&format!("<string>{PROGRAM}</string>")));
        assert!(text.contains("<string>io.gotry.nett</string>"));
        assert!(text.contains("<string>daemon</string>"));
        assert!(text.contains(&format!("<string>{DIR}</string>")));
        assert!(!text.contains("UserName"), "the service starts as root");
        assert!(
            text.contains("<key>MallocNanoZone</key>\n    <string>0</string>"),
            "small allocations stay out of the nano zone"
        );
        let path = dir.path().join("io.gotry.nett.plist");
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
}
