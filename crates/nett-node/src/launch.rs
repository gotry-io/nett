//! The installed program's check (ADR 0026, design/release.md section 7). The Hub and the container
//! cannot replace the program they are started from: the version they upgrade to waits in their
//! state directory with its release signature, and the installed program runs it once it has
//! verified it. The check counts the starts of a new version and goes back to the previous one when
//! it does not settle. Nothing here trusts the state directory: the signature decides.

use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use nett_trust::release::{MAX_PROGRAM_BYTES, ProgramDigest, ReleaseKeys, Version, verify_signed};

use crate::upgrade::{MAX_STARTS, Marker, clear_marker, read_marker, record_failure, write_marker};

/// Largest signature file read.
const MAX_SIGNATURE_BYTES: u64 = 4096;
const READ_CHUNK: usize = 64 * 1024;

/// A program that upgrades from its state directory.
pub struct Staged {
    pub keys: ReleaseKeys,
    /// Its release target.
    pub target: String,
    /// The version running now.
    pub current: Version,
    /// The state directory.
    pub dir: PathBuf,
    /// The program's file name there.
    pub name: &'static str,
}

/// What the check decided.
#[derive(Debug)]
pub enum Check {
    /// Continue with the program running now.
    Itself,
    /// Run this verified program.
    Newer { version: Version, file: File },
}

impl Staged {
    /// The program in the state directory.
    pub fn program(&self) -> PathBuf {
        self.dir.join(self.name)
    }

    /// Where the next version is written, verified, before [`Staged::place`].
    pub fn incoming(&self) -> PathBuf {
        self.dir.join(format!("{}.new", self.name))
    }

    fn previous(&self) -> PathBuf {
        self.dir.join(format!("{}.previous", self.name))
    }

    /// Moves the verified program waiting in [`Staged::incoming`] into place with its signature,
    /// keeps the one it replaces as the previous version, and records the upgrade marker.
    pub fn place(&self, version: Version, minisig: &str) -> Result<(), String> {
        let (incoming, program, previous) = (self.incoming(), self.program(), self.previous());
        crate::config::write_private(&signature(&incoming), minisig.as_bytes())?;
        let rename = |from: &Path, to: &Path| {
            std::fs::rename(from, to)
                .map_err(|e| format!("moving {} to {}: {e}", from.display(), to.display()))
        };
        // A program moves away before its signature and into place after it, so whoever reads the
        // directory meanwhile finds no program, or a program with its own signature
        if program.exists() {
            rename(&program, &previous)?;
            if signature(&program).exists() {
                rename(&signature(&program), &signature(&previous))?;
            }
        }
        rename(&signature(&incoming), &signature(&program))?;
        rename(&incoming, &program)?;
        write_marker(
            &self.dir,
            &Marker {
                version: version.to_string(),
                previous: self.current.to_string(),
                starts: 0,
            },
        )?;
        tracing::info!(%version, path = %program.display(), "placed the new version");
        Ok(())
    }

    /// The version a recorded upgrade marker names, when it has not settled yet.
    pub fn pending(&self) -> Option<Version> {
        read_marker(&self.dir).and_then(|m| m.version.parse().ok())
    }

    /// The version running now has settled: ends the counting of its starts. Returns whether it
    /// had not settled before.
    pub fn settled(&self) -> bool {
        if self.pending() == Some(self.current) {
            clear_marker(&self.dir);
            return true;
        }
        false
    }

    /// The installed program's check. At a start of the service (`start`) it also counts the
    /// starts of a new version, goes back from one that started [`MAX_STARTS`] times without
    /// settling (calling `rollback`, which restores what that version changed), and deletes the
    /// programs this one supersedes; any other command only runs the newest verified program.
    pub fn check(&self, start: bool, rollback: &dyn Fn()) -> Check {
        // The program, then at most the previous one, then this one
        for _ in 0..3 {
            let path = self.program();
            let file = match File::open(&path) {
                Ok(file) => file,
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        tracing::warn!(path = %path.display(), error = %e, "opening the program in the state directory");
                    }
                    if start {
                        self.forget_marker();
                    }
                    return Check::Itself;
                }
            };
            if runs_from(&file) {
                return Check::Itself;
            }
            let version = match self.verify(&path, &file) {
                Ok(version) => version,
                Err(reason) if start => {
                    tracing::warn!(path = %path.display(), %reason, "the program in the state directory does not verify; going back to the one before it");
                    self.restore();
                    continue;
                }
                Err(_) => return Check::Itself,
            };
            if version <= self.current {
                if start {
                    self.remove_all();
                    self.forget_marker();
                }
                return Check::Itself;
            }
            if start
                && let Some(mut marker) = read_marker(&self.dir)
                && marker.version == version.to_string()
            {
                if marker.starts >= MAX_STARTS {
                    let reason = format!(
                        "{} {version} started {MAX_STARTS} times without settling; back to {}",
                        self.name, marker.previous
                    );
                    tracing::warn!(%version, %reason, "rolling back the new version");
                    record_failure(&self.dir, version, &reason);
                    self.restore();
                    rollback();
                    continue;
                }
                marker.starts += 1;
                if let Err(e) = write_marker(&self.dir, &marker) {
                    tracing::warn!(error = %e, "counting the start of the new version");
                }
            }
            return Check::Newer { version, file };
        }
        Check::Itself
    }

    /// A verified new version that could not be run at a start of the service: it is recorded
    /// and the one before it goes back in place, as after starts that did not settle.
    pub fn refuse(&self, version: Version, reason: &str, rollback: &dyn Fn()) {
        tracing::warn!(%version, %reason, "the new version does not run; going back to the one before");
        record_failure(&self.dir, version, reason);
        self.restore();
        rollback();
    }

    /// The release version of the program at `path`, from its signature next to it.
    fn verify(&self, path: &Path, file: &File) -> Result<Version, String> {
        let mut digest = ProgramDigest::new();
        let mut reader = file.take(MAX_PROGRAM_BYTES as u64 + 1);
        let mut buf = vec![0u8; READ_CHUNK];
        loop {
            let n = reader
                .read(&mut buf)
                .map_err(|e| format!("reading {}: {e}", path.display()))?;
            if n == 0 {
                break;
            }
            digest.update(&buf[..n]);
        }
        if digest.len() > MAX_PROGRAM_BYTES as u64 {
            return Err(format!("{} is too large", path.display()));
        }
        let sig = signature(path);
        let mut minisig = String::new();
        File::open(&sig)
            .and_then(|f| f.take(MAX_SIGNATURE_BYTES).read_to_string(&mut minisig))
            .map_err(|e| format!("reading {}: {e}", sig.display()))?;
        verify_signed(&self.keys, &self.target, &digest.finish().blake2b, &minisig)
            .map_err(|e| e.to_string())
    }

    /// Puts the previous version back in place, or, without one, leaves the installed program. The
    /// version put back ran before, so nothing is counted for it.
    fn restore(&self) {
        clear_marker(&self.dir);
        let (program, previous) = (self.program(), self.previous());
        std::fs::remove_file(&program).ok();
        std::fs::remove_file(signature(&program)).ok();
        if previous.exists() {
            let moved = std::fs::rename(signature(&previous), signature(&program))
                .and_then(|()| std::fs::rename(&previous, &program));
            if let Err(e) = moved {
                tracing::warn!(error = %e, "restoring the previous version");
                std::fs::remove_file(&program).ok();
            }
        }
    }

    /// Deletes the programs in the state directory: the installed program supersedes them.
    fn remove_all(&self) {
        for path in [self.program(), self.previous(), self.incoming()] {
            std::fs::remove_file(signature(&path)).ok();
            if std::fs::remove_file(&path).is_ok() {
                tracing::info!(path = %path.display(), "removed a program older than the installed one");
            }
        }
    }

    /// A marker means something only while the version it names is in the state directory.
    fn forget_marker(&self) {
        if self.pending().is_some_and(|v| v > self.current) {
            clear_marker(&self.dir);
        }
    }
}

/// The signature file of a program.
fn signature(program: &Path) -> PathBuf {
    let mut name = program.as_os_str().to_owned();
    name.push(".minisig");
    PathBuf::from(name)
}

/// Whether this process runs `file`.
fn runs_from(file: &File) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    let exe = if cfg!(target_os = "linux") {
        std::fs::metadata("/proc/self/exe")
    } else {
        std::env::current_exe().and_then(std::fs::metadata)
    };
    match (exe, file.metadata()) {
        (Ok(exe), Ok(file)) => exe.dev() == file.dev() && exe.ino() == file.ino(),
        _ => false,
    }
}

/// The installed program: the first argument of a program the check runs (it passes its own path
/// there), this program otherwise.
pub fn installed() -> PathBuf {
    std::env::args_os()
        .next()
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::current_exe().ok())
        .unwrap_or_default()
}

/// Runs the verified `file` in this process with this process's arguments, through the open file
/// so that what runs is what was verified. Returns only when that fails.
#[cfg(target_os = "linux")]
pub fn exec(file: &File) -> std::io::Error {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::process::CommandExt as _;
    let installed = installed();
    std::process::Command::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .arg0(&installed)
        .args(std::env::args_os().skip(1))
        .exec()
}

/// Runs the installed program again in this process with the same arguments: its check decides
/// which version runs. Returns only when that fails.
pub fn relaunch() -> std::io::Error {
    use std::os::unix::process::CommandExt as _;
    let installed = installed();
    std::process::Command::new(&installed)
        .arg0(&installed)
        .args(std::env::args_os().skip(1))
        .exec()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use nett_trust::signing::ReleaseKeyPair;

    use super::*;

    const TARGET: &str = "hub-x86_64-unknown-linux-musl";

    struct Dir {
        _tmp: tempfile::TempDir,
        pair: ReleaseKeyPair,
        staged: Staged,
    }

    fn dir(current: &str) -> Dir {
        let tmp = tempfile::Builder::new()
            .prefix("nett-launch-")
            .tempdir()
            .expect("temp dir");
        let pair = ReleaseKeyPair::generate().expect("key");
        let staged = Staged {
            keys: ReleaseKeys::parse(&pair.public_key()).expect("keys"),
            target: TARGET.into(),
            current: current.parse().expect("version"),
            dir: tmp.path().to_path_buf(),
            name: "nett-hub",
        };
        Dir {
            _tmp: tmp,
            pair,
            staged,
        }
    }

    impl Dir {
        /// Places `bytes`, signed as `version` for `target`, as the next program.
        fn offer(&self, version: &str, target: &str, bytes: &[u8]) {
            let version: Version = version.parse().expect("version");
            std::fs::write(self.staged.incoming(), bytes).expect("write");
            let minisig = self.pair.sign_program(version, target, bytes);
            self.staged.place(version, &minisig).expect("place");
        }

        fn check(&self, start: bool) -> Option<Version> {
            match self.staged.check(start, &|| {}) {
                Check::Itself => None,
                Check::Newer { version, .. } => Some(version),
            }
        }

        fn has(&self, name: &str) -> bool {
            self.staged.dir.join(name).exists()
        }
    }

    fn v(s: &str) -> Option<Version> {
        Some(s.parse().expect("version"))
    }

    #[test]
    fn a_newer_signed_program_for_this_target_runs() {
        let d = dir("0.5.0");
        assert_eq!(d.check(true), None, "nothing placed yet");
        d.offer("0.5.1", TARGET, b"program 0.5.1");
        assert_eq!(d.check(false), v("0.5.1"));
        assert_eq!(d.check(true), v("0.5.1"));
        assert!(d.has("nett-hub") && d.has("nett-hub.minisig"));
        assert!(!d.has("nett-hub.new") && !d.has("nett-hub.new.minisig"));
    }

    #[test]
    fn a_program_that_does_not_verify_does_not_run() {
        // Another target's program
        let d = dir("0.5.0");
        d.offer("0.5.1", "x86_64-unknown-linux-musl", b"node program");
        assert_eq!(d.check(false), None);
        assert!(
            d.has("nett-hub"),
            "a command other than the service's start leaves it"
        );
        assert_eq!(d.check(true), None);
        assert!(!d.has("nett-hub"), "the service's start removes it");

        // Changed after it was signed, with the version before it back in its place
        let d = dir("0.5.0");
        d.offer("0.5.1", TARGET, b"program 0.5.1");
        d.offer("0.5.2", TARGET, b"program 0.5.2");
        std::fs::write(d.staged.program(), b"something else").expect("write");
        assert_eq!(d.check(true), v("0.5.1"));
        assert!(!d.has("nett-hub.previous"));

        // Signed by a key this program does not trust
        let d = dir("0.5.0");
        let other = ReleaseKeyPair::generate().expect("key");
        std::fs::write(d.staged.incoming(), b"program").expect("write");
        let version = "0.5.1".parse().expect("version");
        d.staged
            .place(version, &other.sign_program(version, TARGET, b"program"))
            .expect("place");
        assert_eq!(d.check(true), None);
        assert!(!d.has("nett-hub"));
    }

    #[test]
    fn an_installed_program_as_new_or_newer_wins() {
        let d = dir("0.5.0");
        d.offer("0.5.1", TARGET, b"program 0.5.1");
        d.offer("0.5.2", TARGET, b"program 0.5.2");
        let newer = Staged {
            current: "0.5.2".parse().expect("version"),
            keys: d.staged.keys.clone(),
            target: TARGET.into(),
            dir: d.staged.dir.clone(),
            name: "nett-hub",
        };
        assert!(matches!(newer.check(false, &|| {}), Check::Itself));
        assert!(d.has("nett-hub"), "only the service's start deletes");
        assert!(matches!(newer.check(true, &|| {}), Check::Itself));
        for name in [
            "nett-hub",
            "nett-hub.minisig",
            "nett-hub.previous",
            "nett-hub.previous.minisig",
        ] {
            assert!(!d.has(name), "{name}");
        }
    }

    #[test]
    fn a_new_version_that_does_not_settle_goes_back_to_the_one_before() {
        let d = dir("0.5.0");
        d.offer("0.5.1", TARGET, b"program 0.5.1");
        d.offer("0.5.2", TARGET, b"program 0.5.2");
        let rolled_back = Cell::new(0);
        let check = || match d
            .staged
            .check(true, &|| rolled_back.set(rolled_back.get() + 1))
        {
            Check::Itself => None,
            Check::Newer { version, .. } => Some(version),
        };
        for _ in 0..MAX_STARTS {
            assert_eq!(check(), v("0.5.2"));
        }
        assert_eq!(check(), v("0.5.1"), "the fourth start runs the one before");
        assert_eq!(rolled_back.get(), 1);
        assert_eq!(
            d.staged.pending(),
            None,
            "the version before has settled already"
        );
        let failed = crate::upgrade::failed(&d.staged.dir);
        assert!(
            failed["0.5.2"].contains("started 3 times without settling"),
            "{failed:?}"
        );
        assert_eq!(check(), v("0.5.1"), "and keeps running it");
        assert_eq!(
            std::fs::read(d.staged.program()).expect("read"),
            b"program 0.5.1"
        );
    }

    #[test]
    fn without_a_version_before_it_the_installed_program_runs_again() {
        let d = dir("0.5.0");
        d.offer("0.5.1", TARGET, b"program 0.5.1");
        for _ in 0..MAX_STARTS {
            assert_eq!(d.check(true), v("0.5.1"));
        }
        assert_eq!(d.check(true), None);
        assert!(!d.has("nett-hub") && !d.has("nett-hub.minisig"));
    }

    #[test]
    fn a_version_that_settles_is_no_longer_counted() {
        let d = dir("0.5.0");
        d.offer("0.5.1", TARGET, b"program 0.5.1");
        assert_eq!(d.check(true), v("0.5.1"));
        let running = Staged {
            current: "0.5.1".parse().expect("version"),
            keys: d.staged.keys.clone(),
            target: TARGET.into(),
            dir: d.staged.dir.clone(),
            name: "nett-hub",
        };
        assert_eq!(running.pending(), v("0.5.1"));
        assert!(running.settled());
        assert!(!running.settled(), "once");
        for _ in 0..MAX_STARTS + 2 {
            assert_eq!(d.check(true), v("0.5.1"));
        }
    }
}
