//! macOS 上组网服务的安装（design/release.md 第 4 节）：`sudo nett mesh install` 把正在运行的 `nett` 复制到
//! root 专属的目录，写入 launchd 与日志轮转的配置并启动服务；`sudo nett mesh uninstall` 停止并删除它们。
//! Homebrew 的目录普通用户可写，root 服务只运行这份副本。

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};

use crate::text;

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
<!-- 由 nett mesh install 生成（design/release.md 第 4 节） -->
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
        "# 由 nett mesh install 生成：组网服务启动失败记录的轮转（运行日志在系统日志中）\n\
         # logfilename              [owner:group]  mode  count  size(KB)  when  flags\n\
         {LOG_DIR}/mesh.log    root:wheel     600   5      1024      *     JN\n"
    )
}

fn require_root() -> anyhow::Result<()> {
    if !rustix::process::geteuid().is_root() {
        bail!("{}", text::SERVICE_NEEDS_ROOT.get());
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

pub fn install() -> anyhow::Result<()> {
    require_root()?;
    ensure_dir(DIR, 0o700)?;
    ensure_dir(LOG_DIR, 0o700)?;
    let exe = std::env::current_exe().context("locating the running nett")?;
    let exe = fs::canonicalize(&exe).unwrap_or(exe);
    // 从副本自己运行时（重新写配置）不用复制
    if exe != Path::new(BINARY) {
        let bytes = fs::read(&exe).with_context(|| format!("reading {}", exe.display()))?;
        write_atomic(Path::new(BINARY), &bytes, 0o755)?;
    }
    write_atomic(Path::new(PLIST), plist().as_bytes(), 0o644)?;
    write_atomic(Path::new(NEWSYSLOG), newsyslog().as_bytes(), 0o644)?;

    let missing: Vec<&str> = [DESIRED, KEY]
        .into_iter()
        .filter(|p| !Path::new(p).exists())
        .collect();
    if !missing.is_empty() {
        println!(
            "{}",
            text::SERVICE_INSTALLED_NOT_STARTED
                .get()
                .replace("{dir}", DIR)
                .replace("{missing}", &missing.join(", "))
        );
        return Ok(());
    }
    let (ok, message) = if loaded()? {
        // 已在运行：重启，换用新的副本
        let target = format!("system/{LABEL}");
        (
            launchctl(&["kickstart", "-k", &target])?,
            &text::SERVICE_RESTARTED,
        )
    } else {
        (
            launchctl(&["bootstrap", "system", PLIST])?,
            &text::SERVICE_STARTED,
        )
    };
    if !ok {
        bail!("launchctl could not start {LABEL}; see {LOG_DIR}/mesh.log");
    }
    println!(
        "{}",
        message
            .get()
            .replace("{label}", LABEL)
            .replace("{binary}", BINARY)
    );
    Ok(())
}

pub fn uninstall() -> anyhow::Result<()> {
    require_root()?;
    if loaded()? && !launchctl(&["bootout", &format!("system/{LABEL}")])? {
        bail!("launchctl could not stop {LABEL}");
    }
    for path in [PLIST, NEWSYSLOG, BINARY] {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {path}")),
        }
    }
    println!("{}", text::SERVICE_UNINSTALLED.get().replace("{dir}", DIR));
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
