//! Synology DSM's part of `nett install` (design/dsm.md section 6.2): the TUN driver, and the boot
//! task.
//!
//! DSM loads the kernel's TUN driver only for the packages that need it, so at boot it can come after
//! nett or never; `nett install` loads it itself before it starts the services.
//!
//! The boot task is one Task Scheduler task, run as root at boot, whose command is `nett install`. It
//! is the only thing that starts nett's services there, so a DSM update that drops the units does not
//! keep nett down. DSM's `esynoscheduler` manages it; Synology does not document that tool, so
//! whenever it is missing or does not do what was asked, the steps to do the same in Control Panel
//! are printed.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context as _, bail};
use nett_node::platform::linux::PROGRAM;

/// The TUN driver, a module in DSM's flat module directory.
const TUN_MODULE: &str = "/lib/modules/tun.ko";
const TUN_DEVICE: &str = "/dev/net/tun";
/// The character device the TUN driver registers: a misc device (major 10), minor 200.
const TUN_MAJOR: u32 = 10;
const TUN_MINOR: u32 = 200;

/// What preparing TUN needs from the system, so the decisions can be tested without a kernel.
trait TunHost {
    /// Whether the TUN device opens for reading and writing.
    fn opens(&self) -> bool;
    /// Loads the TUN driver; already loaded counts as loaded.
    fn load_driver(&self) -> io::Result<()>;
    fn device_exists(&self) -> bool;
    fn make_device(&self) -> io::Result<()>;
}

struct Kernel;

impl TunHost for Kernel {
    fn opens(&self) -> bool {
        OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(TUN_DEVICE)
            .is_ok()
    }

    fn load_driver(&self) -> io::Result<()> {
        let module = File::open(TUN_MODULE)?;
        match rustix::system::finit_module(&module, c"", 0) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn device_exists(&self) -> bool {
        Path::new(TUN_DEVICE).exists()
    }

    fn make_device(&self) -> io::Result<()> {
        std::fs::create_dir_all("/dev/net")?;
        rustix::fs::mknodat(
            rustix::fs::CWD,
            TUN_DEVICE,
            rustix::fs::FileType::CharacterDevice,
            rustix::fs::Mode::from_raw_mode(0o600),
            rustix::fs::makedev(TUN_MAJOR, TUN_MINOR),
        )?;
        Ok(())
    }
}

/// Makes sure the TUN device opens before the mesh service starts: loads the driver when it does not,
/// and creates the device when loading the driver did not (the kernel normally does). Returns a
/// sentence for the user when it loaded the driver.
pub fn prepare_tun() -> anyhow::Result<Option<String>> {
    prepare_tun_on(&Kernel)
}

fn prepare_tun_on(host: &impl TunHost) -> anyhow::Result<Option<String>> {
    if host.opens() {
        return Ok(None);
    }
    host.load_driver()
        .with_context(|| format!("loading the kernel's TUN driver from {TUN_MODULE}"))?;
    if !host.device_exists() {
        host.make_device()
            .with_context(|| format!("creating {TUN_DEVICE}"))?;
    }
    if !host.opens() {
        bail!(
            "{TUN_DEVICE} does not open after loading {TUN_MODULE}; the mesh service needs it for \
             its interface, so nothing was started"
        );
    }
    Ok(Some(format!(
        "Loaded the kernel's TUN driver ({TUN_MODULE}); it stays loaded until the next restart."
    )))
}

const ESYNOSCHEDULER: &str = "/usr/syno/sbin/esynoscheduler";
/// The task's name in Task Scheduler.
pub const TASK: &str = "nett";
/// Time limit of one call (hard rule 14).
const TIMEOUT: Duration = Duration::from_secs(30);

fn esynoscheduler(args: &[&str]) -> anyhow::Result<(bool, String)> {
    nett_node::platform::run_output(ESYNOSCHEDULER, args, TIMEOUT).map_err(anyhow::Error::msg)
}

/// What the task runs: the command that writes missing units and starts the services.
fn command() -> String {
    format!("{PROGRAM} install")
}

/// Whether a task list names nett's task. The tool prints the tasks as JSON objects, each with a
/// `task_name`; spacing aside, the field must be exactly this name.
fn listed(list: &str) -> bool {
    let compact: String = list.chars().filter(|c| !c.is_whitespace()).collect();
    compact.contains(&format!("\"task_name\":\"{TASK}\""))
}

fn create_by_hand() -> String {
    format!(
        "create it in Control Panel → Task Scheduler → Create → Triggered Task → User-defined script: \
         task name {TASK}, user root, event Boot-up, and on Task Settings the command `{}`",
        command()
    )
}

/// Makes sure the boot task exists. Returns a sentence for the user when it had to be created, or
/// when it cannot be checked. Fails, before anything starts, when creating it did not work.
pub fn ensure_boot_task() -> anyhow::Result<Option<String>> {
    if !Path::new(ESYNOSCHEDULER).exists() {
        return Ok(Some(format!(
            "Warning: {ESYNOSCHEDULER} is not on this machine, so the boot task that starts nett at \
             boot cannot be checked.\n  → If Task Scheduler has no task {TASK} yet, {}.",
            create_by_hand()
        )));
    }
    if listed(&esynoscheduler(&["--list"])?.1) {
        return Ok(None);
    }
    let name = format!("task_name={TASK}");
    let operation = format!("operation={}", command());
    let (ok, out) = esynoscheduler(&[
        "--create",
        &name,
        "event=bootup",
        "enable=true",
        "operation_type=script",
        &operation,
        "description=Starts the nett services at boot",
        r#"owner={"0":"root"}"#,
    ])?;
    if !ok || !out.contains("save ok") || !listed(&esynoscheduler(&["--list"])?.1) {
        bail!(
            "creating the boot task with {ESYNOSCHEDULER} did not work, and nothing was started; {}, \
             then run `sudo nett install` again",
            create_by_hand()
        );
    }
    Ok(Some(format!(
        "Created the boot task {TASK} in Task Scheduler; it starts nett at boot."
    )))
}

/// Deletes the boot task. Returns a sentence for the user when it cannot be checked. Fails, before
/// anything else is removed, when deleting it did not work.
pub fn remove_boot_task() -> anyhow::Result<Option<String>> {
    if !Path::new(ESYNOSCHEDULER).exists() {
        return Ok(Some(format!(
            "{ESYNOSCHEDULER} is not on this machine: if Task Scheduler has a task {TASK}, delete it \
             in Control Panel → Task Scheduler."
        )));
    }
    if !listed(&esynoscheduler(&["--list"])?.1) {
        return Ok(None);
    }
    let name = format!("task_name={TASK}");
    let (ok, out) = esynoscheduler(&["--delete", &name])?;
    if !ok || !out.contains("delete task ok") || listed(&esynoscheduler(&["--list"])?.1) {
        bail!(
            "deleting the boot task with {ESYNOSCHEDULER} did not work, and nothing was removed; \
             delete the task {TASK} in Control Panel → Task Scheduler, then run this again"
        );
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use super::*;

    /// A system whose TUN device opens once the driver is loaded (and, when `devtmpfs` is false, the
    /// device created), recording what was done.
    #[derive(Default)]
    struct FakeHost {
        loaded: Cell<bool>,
        device: Cell<bool>,
        devtmpfs: bool,
        broken: bool,
        done: RefCell<Vec<&'static str>>,
    }

    impl TunHost for FakeHost {
        fn opens(&self) -> bool {
            !self.broken && self.loaded.get() && self.device.get()
        }
        fn load_driver(&self) -> io::Result<()> {
            self.done.borrow_mut().push("load");
            self.loaded.set(true);
            if self.devtmpfs {
                self.device.set(true);
            }
            Ok(())
        }
        fn device_exists(&self) -> bool {
            self.device.get()
        }
        fn make_device(&self) -> io::Result<()> {
            self.done.borrow_mut().push("mknod");
            self.device.set(true);
            Ok(())
        }
    }

    /// At boot on DSM the TUN device came 32 seconds after the mesh service: the driver is loaded
    /// before the services start, and nothing is done where TUN already works
    #[test]
    fn tun_is_prepared_before_the_services_start() {
        let ready = FakeHost {
            loaded: Cell::new(true),
            device: Cell::new(true),
            ..FakeHost::default()
        };
        assert_eq!(prepare_tun_on(&ready).expect("ready"), None);
        assert!(ready.done.borrow().is_empty());

        let not_loaded = FakeHost {
            devtmpfs: true,
            ..FakeHost::default()
        };
        assert!(prepare_tun_on(&not_loaded).expect("loaded").is_some());
        assert_eq!(*not_loaded.done.borrow(), ["load"]);

        let no_device = FakeHost::default();
        prepare_tun_on(&no_device).expect("created");
        assert_eq!(*no_device.done.borrow(), ["load", "mknod"]);

        let broken = FakeHost {
            devtmpfs: true,
            broken: true,
            ..FakeHost::default()
        };
        let error = prepare_tun_on(&broken).expect_err("still does not open");
        assert!(error.to_string().contains("nothing was started"));
    }

    #[test]
    fn the_task_runs_install_from_the_program_directory() {
        assert_eq!(command(), "/usr/local/lib/nett/nett install");
        assert!(create_by_hand().contains("user root, event Boot-up"));
    }

    /// The shape `esynoscheduler --list` prints on DSM 7.4.1
    #[test]
    fn only_a_task_with_this_exact_name_counts() {
        let list = r#"(27971) esynoscheduler.cpp:272 jOut=[
   {
      "description" : "nett",
      "enable" : true,
      "event" : "bootup",
      "operation" : "/usr/local/lib/nett/nett install",
      "task_name" : "backup"
   }
]"#;
        assert!(!listed(list), "a description or command is not the name");
        assert!(listed(&list.replace(r#""backup""#, r#""nett""#)));
        assert!(!listed(&list.replace(r#""backup""#, r#""nett-backup""#)));
        assert!(!listed(""));
    }
}
