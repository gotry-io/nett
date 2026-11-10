//! macOS 上组网服务的安装（design/release.md 第 4 节）：`sudo nett install` 在 root 专属的目录中生成密钥、
//! 放入程序的副本和期望状态（从运行 sudo 的用户的站点目录中找到给本机的那一份），写入 launchd 与日志轮转的
//! 配置并启动服务；`sudo nett uninstall` 停止服务并删除副本与配置。Homebrew 的目录普通用户可写，root 服务
//! 只运行这份副本。

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};

const DIR: &str = "/Library/Application Support/nett";
const BINARY: &str = "/Library/Application Support/nett/nett";
const DESIRED: &str = "/Library/Application Support/nett/desired.json";
const KEY: &str = "/Library/Application Support/nett/mesh.key";
const LOG_DIR: &str = "/Library/Logs/nett";
const PLIST: &str = "/Library/LaunchDaemons/io.gotry.nett.mesh.plist";
const NEWSYSLOG: &str = "/etc/newsyslog.d/nett.conf";
const LABEL: &str = "io.gotry.nett.mesh";
const LAUNCHCTL: &str = "/bin/launchctl";
/// 等 launchctl 返回的上限（硬性规则 14）。
const LAUNCHCTL_TIMEOUT: Duration = Duration::from_secs(15);

/// launchd 配置：root 运行副本，开机启动，退出后重启（design/userspace.md 第 6.3 节）。
fn plist() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- 由 nett install 生成（design/release.md 第 4 节） -->
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{BINARY}</string>
    <string>mesh</string>
    <string>--config</string>
    <string>{DESIRED}</string>
    <string>--key</string>
    <string>{KEY}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <!-- 连续崩溃时最快 5 秒重启一次 -->
  <key>ThrottleInterval</key>
  <integer>5</integer>
  <!-- 不合并定时器：路径层按 100 毫秒推进，切换时间取决于它 -->
  <key>ProcessType</key>
  <string>Interactive</string>
  <!-- 077：进程创建的文件只有 root 能读 -->
  <key>Umask</key>
  <integer>63</integer>
  <!-- 运行日志写进系统日志；这个文件只记录启动失败，launchd 每次启动进程时重新打开它 -->
  <key>StandardErrorPath</key>
  <string>{LOG_DIR}/mesh.log</string>
</dict>
</plist>
"#
    )
}

/// 启动失败记录的轮转：超过 1 MB 时轮转，保留 5 份，压缩旧的。
fn newsyslog() -> String {
    format!(
        "# 由 nett install 生成：组网服务启动失败记录的轮转（运行日志在系统日志中）\n\
         # logfilename              [owner:group]  mode  count  size(KB)  when  flags\n\
         {LOG_DIR}/mesh.log    root:wheel     600   5      1024      *     JN\n"
    )
}

fn require_root() -> anyhow::Result<()> {
    if !rustix::process::geteuid().is_root() {
        bail!("the mesh service runs as root; run this command with sudo");
    }
    Ok(())
}

/// 写到同一目录的临时文件再改名：读的一方不会看到写了一半的文件。
fn write_atomic(path: &Path, content: &[u8], mode: u32) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp)
        .with_context(|| format!("writing {}", tmp.display()))?;
    file.write_all(content)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("writing {}", tmp.display()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting permissions of {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
}

fn ensure_dir(path: &str, mode: u32) -> anyhow::Result<()> {
    fs::create_dir_all(path).with_context(|| format!("creating {path}"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting permissions of {path}"))
}

/// 以参数数组调用 launchctl，带超时；返回它是否成功。
fn launchctl(args: &[&str]) -> anyhow::Result<bool> {
    let mut child = Command::new(LAUNCHCTL)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("running {LAUNCHCTL} {}", args.join(" ")))?;
    let deadline = Instant::now() + LAUNCHCTL_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().context("waiting for launchctl")? {
            return Ok(status.success());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{LAUNCHCTL} {} did not finish in time", args.join(" "));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn loaded() -> anyhow::Result<bool> {
    launchctl(&["print", &format!("system/{LABEL}")])
}

/// bootout 返回时进程可能还在退出（launchctl print 显示 `SIGTERMed`）。等到 launchd 中没有这个服务，
/// 再删副本、报告已停止；紧接着重新安装时也不会遇到还没退出的旧服务。
fn wait_unloaded() -> anyhow::Result<()> {
    let deadline = Instant::now() + LAUNCHCTL_TIMEOUT;
    while loaded()? {
        if Instant::now() >= deadline {
            bail!(
                "{LABEL} did not stop within {} seconds",
                LAUNCHCTL_TIMEOUT.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

/// 写入 `path`，内容与现有的相同时不动；返回是否写了。
fn replace_if_changed(path: &Path, content: &[u8], mode: u32) -> anyhow::Result<bool> {
    if fs::read(path).is_ok_and(|old| old == content) {
        return Ok(false);
    }
    write_atomic(path, content, mode)?;
    Ok(true)
}

/// 一个命令完成安装（design/release.md 第 4 节）：密钥、程序的副本、两份配置，`config` 给出时导入期望
/// 状态；有期望状态时启动服务，已在运行时按变化重启或重新加载。
fn install(config: Option<&Path>) -> anyhow::Result<()> {
    require_root()?;
    ensure_dir(DIR, 0o700)?;
    ensure_dir(LOG_DIR, 0o700)?;
    let keys = crate::mesh::node_keys(Path::new(DIR))?;

    let site = invoking_site_dir();
    let imported = match config {
        Some(path) => {
            let bytes = crate::site::read_desired(path)?
                .with_context(|| format!("{} is not a regular file", path.display()))?;
            crate::site::check_desired_for(&bytes, &keys.0)?;
            Some(bytes)
        }
        None => match &site {
            Some(site) => crate::site::find_desired_for(site, &keys.0)?.map(|(path, bytes)| {
                println!("Using {}", path.display());
                bytes
            }),
            None => None,
        },
    };
    let desired_changed = match imported {
        Some(bytes) => replace_if_changed(Path::new(DESIRED), &bytes, 0o600)?,
        None => false,
    };
    let exe = std::env::current_exe().context("locating the running nett")?;
    let exe = fs::canonicalize(&exe).unwrap_or(exe);
    // 从副本自己运行时（重新写配置）不用复制
    let binary_changed = if exe == Path::new(BINARY) {
        false
    } else {
        let bytes = fs::read(&exe).with_context(|| format!("reading {}", exe.display()))?;
        replace_if_changed(Path::new(BINARY), &bytes, 0o755)?
    };
    let plist_changed = replace_if_changed(Path::new(PLIST), plist().as_bytes(), 0o644)?;
    replace_if_changed(Path::new(NEWSYSLOG), newsyslog().as_bytes(), 0o644)?;

    // 公钥那一行只在本机还没有加进站点时需要
    if !Path::new(DESIRED).exists() {
        crate::mesh::print_keys(Path::new(DIR), keys);
        let site = site.map_or_else(|| "~/.config/nett".to_owned(), |s| s.display().to_string());
        println!("Installed to {DIR}. Not started: {site} has no desired state for this machine.");
        println!(
            "Add the keys line above to site.toml, run `nett site apply`, then run `sudo nett install` again."
        );
        println!(
            "If the site is on another machine, use `sudo nett install --config <desired.json>`."
        );
        return Ok(());
    }
    let target = format!("system/{LABEL}");
    let (ok, message) = if !loaded()? {
        (
            launchctl(&["bootstrap", "system", PLIST])?,
            concat!(
                "Started the mesh service.\n",
                "Logs: log show --last 1h --predicate 'process == \"nett\"'\n",
                "Run `sudo nett install` again after `nett site apply` or `brew upgrade nett`."
            ),
        )
    } else if plist_changed {
        // launchd 保留的是载入时的配置：配置变了要卸下再载入，kickstart 只会按旧的参数重启
        if !launchctl(&["bootout", &target])? {
            bail!("launchctl could not stop {LABEL}");
        }
        wait_unloaded()?;
        (
            launchctl(&["bootstrap", "system", PLIST])?,
            "Restarted the mesh service with the new configuration.",
        )
    } else if binary_changed {
        // 换用新的副本：重启
        (
            launchctl(&["kickstart", "-k", &target])?,
            "Restarted the mesh service with the new binary.",
        )
    } else if desired_changed {
        // 只有期望状态变了：经本机接口重新读取，不重启、连接不中断，并显示它是否被接受（design/status.md
        // 第 4.1 节）。程序没变，正在运行的就是这一版
        print!(
            "{}",
            crate::status::reload_at(Path::new(nett_mesh::status::DEFAULT_SOCKET))?
        );
        return Ok(());
    } else {
        (true, "The mesh service is running. Nothing changed.")
    };
    if !ok {
        bail!("launchctl could not start {LABEL}; see {LOG_DIR}/mesh.log");
    }
    println!("{message}");
    Ok(())
}

/// 运行 `sudo` 的用户的站点目录（design/site.md 第 8 节）。sudo 可能把 `HOME` 换成 root 的，
/// 所以按 `SUDO_UID` 从用户数据库查家目录；不经 sudo 运行时用 `HOME`。
fn invoking_site_dir() -> Option<PathBuf> {
    let home = match std::env::var("SUDO_UID").ok().and_then(|u| u.parse().ok()) {
        Some(uid) => passwd::home(uid)?.into_os_string(),
        None => std::env::var_os("HOME")?,
    };
    crate::site::site_dir(std::env::var_os("XDG_CONFIG_HOME"), Some(home)).ok()
}

/// 用户数据库的查询：标准库和 rustix 都没有 getpwuid_r。
#[allow(unsafe_code)]
mod passwd {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::PathBuf;

    /// 远大于 macOS 上一条用户记录的长度；放不下（ERANGE）时返回 `None`。
    const BUFFER: usize = 4096;

    pub fn home(uid: libc::uid_t) -> Option<PathBuf> {
        let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut buffer = vec![0 as libc::c_char; BUFFER];
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: entry、buffer、result 都是本函数持有的有效内存，传入的是 buffer 的真实长度。
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                entry.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        if rc != 0 || result.is_null() {
            return None;
        }
        // SAFETY: 返回 0 且 result 非空时 entry 已填好，pw_dir 是 buffer 中以 NUL 结尾的字符串，
        // buffer 在本函数结束前一直有效；用完之前就复制出来。
        let dir = unsafe { CStr::from_ptr((*result).pw_dir) };
        let path = PathBuf::from(OsStr::from_bytes(dir.to_bytes()));
        path.is_absolute().then_some(path)
    }
}

pub const INSTALL_USAGE: &str = "usage: sudo nett install [--config <desired-state.json>]\n\n\
Creates this machine's keys, copies nett into a root-only directory, imports this machine's\n\
desired state from the site directory (or --config) and starts the service.\n\
Run it again after `nett site apply` or `brew upgrade nett`.";
pub const UNINSTALL_USAGE: &str = "usage: sudo nett uninstall";

/// `sudo nett install [--config <期望状态>]`。
pub fn install_command(mut parser: lexopt::Parser) -> anyhow::Result<()> {
    let mut config = None;
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Long("config") => config = Some(PathBuf::from(parser.value()?)),
            other => return Err(other.unexpected().into()),
        }
    }
    install(config.as_deref())
}

/// `sudo nett uninstall`。
pub fn uninstall_command(mut parser: lexopt::Parser) -> anyhow::Result<()> {
    if let Some(arg) = parser.next()? {
        return Err(arg.unexpected().into());
    }
    uninstall()
}

fn uninstall() -> anyhow::Result<()> {
    require_root()?;
    if loaded()? {
        if !launchctl(&["bootout", &format!("system/{LABEL}")])? {
            bail!("launchctl could not stop {LABEL}");
        }
        wait_unloaded()?;
    }
    for path in [PLIST, NEWSYSLOG, BINARY] {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {path}")),
        }
    }
    println!("Removed the mesh service. Keys, desired state and the trust store remain in {DIR}.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_configuration_names_the_root_copy() {
        let p = plist();
        assert!(p.contains(&format!("<string>{BINARY}</string>")));
        assert!(p.contains(&format!("<string>{DESIRED}</string>")));
        assert!(
            !p.contains("homebrew"),
            "the service never runs the Homebrew copy"
        );
        assert!(newsyslog().contains(&format!("{LOG_DIR}/mesh.log")));
    }

    #[test]
    fn finds_the_home_of_a_user() {
        let home = passwd::home(rustix::process::getuid().as_raw()).expect("own entry");
        assert!(home.is_dir(), "{}", home.display());
        // macOS 的 nobody 是 -2（uid_t::MAX - 1），取一个没有分配的 uid
        assert!(passwd::home(3_999_999).is_none());
    }

    #[test]
    fn plist_is_valid() {
        let dir = std::env::temp_dir().join(format!("nett-plist-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("dir");
        let file = dir.join("p.plist");
        fs::write(&file, plist()).expect("write");
        let status = Command::new("/usr/bin/plutil")
            .args(["-lint", "-s"])
            .arg(&file)
            .status()
            .expect("plutil");
        let _ = fs::remove_dir_all(&dir);
        assert!(status.success());
    }
}
