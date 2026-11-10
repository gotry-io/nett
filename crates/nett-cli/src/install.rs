//! `sudo nett install [<token>]` 与 `sudo nett uninstall`（design/hub.md 第 7 节，release.md 第 4 节）：两个平台
//! 做同样的事，服务管理器不同（macOS 上 launchd，Linux 上 systemd）。这里是命令行与两个平台共用的文件和
//! 子进程操作；各平台的步骤在 `service`（macOS）与 `service_linux` 中。

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use lexopt::ValueExt as _;

#[cfg(target_os = "macos")]
use crate::service as platform;
#[cfg(target_os = "linux")]
use crate::service_linux as platform;

/// 等服务管理器的命令返回的上限（硬性规则 14）。
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

pub const INSTALL_USAGE: &str = "usage: sudo nett install [<token>] [--config <desired-state.json>]\n\n\
Creates this machine's keys (or keeps them), installs nett and starts the mesh service.\n\
With a token from `nett site invite <name>`, it also connects this machine to the Hub: the\n\
desired state then comes from the Hub, and the nett-node service runs next to the mesh service.\n\
Without a Hub, the desired state comes from --config or, on macOS, from the site directory of\n\
the user running sudo. Run it again after upgrading nett.";
pub const UNINSTALL_USAGE: &str = "usage: sudo nett uninstall\n\n\
Stops and removes the services. Keys, the desired state and the Hub configuration stay;\n\
`sudo nett install` brings the services back.";

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

pub fn require_root() -> anyhow::Result<()> {
    if !rustix::process::geteuid().is_root() {
        bail!("the services run as root; run this command with sudo");
    }
    Ok(())
}

/// 写到同一目录的临时文件再改名：读的一方不会看到写了一半的文件。
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

/// 写入 `path`，内容与现有的相同时不动；返回是否写了。
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

/// 把正在运行的 `nett` 复制到 `target`；从那里运行时不复制。返回是否换了。
pub fn copy_self(target: &str) -> anyhow::Result<bool> {
    let exe = std::env::current_exe().context("locating the running nett")?;
    let exe = fs::canonicalize(&exe).unwrap_or(exe);
    if exe == Path::new(target) {
        return Ok(false);
    }
    let bytes = fs::read(&exe).with_context(|| format!("reading {}", exe.display()))?;
    replace_if_changed(Path::new(target), &bytes, 0o755)
}

/// 以参数数组运行服务管理器的命令（硬性规则 9：程序是固定的绝对路径，不经 shell），带超时；返回它是否成功。
pub fn run(program: &str, args: &[&str]) -> anyhow::Result<bool> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("running {program} {}", args.join(" ")))?;
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    loop {
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("waiting for {program}"))?
        {
            return Ok(status.success());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{program} {} did not finish in time", args.join(" "));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// 有 token 时核对它、写入 Hub 的配置，报告结果；返回 Hub 的配置是否变了。
pub fn apply_token(dir: &str, state_dir: &str, token: Option<&str>) -> anyhow::Result<bool> {
    let Some(token) = token else {
        return Ok(false);
    };
    Ok(
        match crate::join::join(Path::new(dir), Path::new(state_dir), token)? {
            crate::join::Joined::New(url) => {
                println!("Connecting this machine to the Hub at {url}.");
                true
            }
            crate::join::Joined::Switched { from, to } => {
                println!("Switching this machine from the Hub at {from} to {to}.");
                true
            }
            crate::join::Joined::Unchanged => false,
        },
    )
}
