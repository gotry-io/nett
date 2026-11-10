//! macOS 上服务的安装（design/release.md 第 4 节，hub.md 第 7 节）：`sudo nett install` 在 root 专属的目录中生成
//! 密钥、放入程序的副本，写入 launchd 与日志轮转的配置并启动组网服务；不接 Hub 时从运行 sudo 的用户的站点
//! 目录中找到给本机的期望状态，接了 Hub 时（有 token，或已有 Hub 的配置）再启动 nett-node，期望状态由它从
//! Hub 接收。`sudo nett uninstall` 停止服务并删除副本与配置。Homebrew 的目录普通用户可写，root 服务只运行
//! 这份副本。

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use nett_node::config::HubConfig;

use crate::install::{
    InstallArgs, apply_token, copy_self, ensure_dir, replace_if_changed, require_root,
};

const DIR: &str = "/Library/Application Support/nett";
const BINARY: &str = "/Library/Application Support/nett/nett";
const DESIRED: &str = "/Library/Application Support/nett/desired.json";
const KEY: &str = "/Library/Application Support/nett/mesh.key";
const LOG_DIR: &str = "/Library/Logs/nett";
const NEWSYSLOG: &str = "/etc/newsyslog.d/nett.conf";
const LAUNCHCTL: &str = "/bin/launchctl";
/// 等 launchctl 卸下服务的上限。
const UNLOAD_TIMEOUT: Duration = Duration::from_secs(15);

/// 一个 launchd 服务。
struct Service {
    label: &'static str,
    plist: &'static str,
    /// 运行 `nett` 的哪个命令。
    args: &'static [&'static str],
    log: &'static str,
    /// 在帮助与报告中的说法。
    what: &'static str,
}

const MESH: Service = Service {
    label: "io.gotry.nett.mesh",
    plist: "/Library/LaunchDaemons/io.gotry.nett.mesh.plist",
    args: &["mesh", "--config", DESIRED, "--key", KEY],
    log: "mesh.log",
    what: "the mesh service",
};

const NODE: Service = Service {
    label: "io.gotry.nett.node",
    plist: "/Library/LaunchDaemons/io.gotry.nett.node.plist",
    args: &["node", "--dir", DIR],
    log: "node.log",
    what: "nett-node",
};

/// launchd 配置：root 运行副本，开机启动，退出后重启（design/userspace.md 第 6.3 节）。
fn plist(service: &Service) -> String {
    let args: String = service
        .args
        .iter()
        .map(|a| format!("\n    <string>{a}</string>"))
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- 由 nett install 生成（design/release.md 第 4 节） -->
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{BINARY}</string>{args}
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
  <string>{LOG_DIR}/{log}</string>
</dict>
</plist>
"#,
        label = service.label,
        log = service.log,
    )
}

/// 启动失败记录的轮转：超过 1 MB 时轮转，保留 5 份，压缩旧的。
fn newsyslog() -> String {
    format!(
        "# 由 nett install 生成：服务启动失败记录的轮转（运行日志在系统日志中）\n\
         # logfilename              [owner:group]  mode  count  size(KB)  when  flags\n\
         {LOG_DIR}/mesh.log    root:wheel     600   5      1024      *     JN\n\
         {LOG_DIR}/node.log    root:wheel     600   5      1024      *     JN\n"
    )
}

fn launchctl(args: &[&str]) -> anyhow::Result<bool> {
    crate::install::run(LAUNCHCTL, args)
}

fn loaded(service: &Service) -> anyhow::Result<bool> {
    launchctl(&["print", &format!("system/{}", service.label)])
}

/// bootout 返回时进程可能还在退出（launchctl print 显示 `SIGTERMed`）。等到 launchd 中没有这个服务，
/// 再删副本、报告已停止；紧接着重新安装时也不会遇到还没退出的旧服务。
fn wait_unloaded(service: &Service) -> anyhow::Result<()> {
    let deadline = Instant::now() + UNLOAD_TIMEOUT;
    while loaded(service)? {
        if Instant::now() >= deadline {
            bail!(
                "{} did not stop within {} seconds",
                service.label,
                UNLOAD_TIMEOUT.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

fn stop(service: &Service) -> anyhow::Result<()> {
    if loaded(service)? {
        if !launchctl(&["bootout", &format!("system/{}", service.label)])? {
            bail!("launchctl could not stop {}", service.label);
        }
        wait_unloaded(service)?;
    }
    Ok(())
}

/// 让服务按新的配置、程序运行：没载入时载入；配置变了卸下再载入（launchd 保留的是载入时的配置，
/// kickstart 只会按旧的参数重启）；程序或它读的配置变了时重启。返回报告的一句话，没有变化时为空。
fn ensure_running(
    service: &Service,
    plist_changed: bool,
    restart: bool,
) -> anyhow::Result<Option<String>> {
    let target = format!("system/{}", service.label);
    let (ok, message) = if !loaded(service)? {
        (
            launchctl(&["bootstrap", "system", service.plist])?,
            format!("Started {}.", service.what),
        )
    } else if plist_changed {
        stop(service)?;
        (
            launchctl(&["bootstrap", "system", service.plist])?,
            format!("Restarted {} with the new configuration.", service.what),
        )
    } else if restart {
        (
            launchctl(&["kickstart", "-k", &target])?,
            format!("Restarted {}.", service.what),
        )
    } else {
        return Ok(None);
    };
    if !ok {
        bail!(
            "launchctl could not start {}; see {LOG_DIR}/{}",
            service.label,
            service.log
        );
    }
    Ok(Some(message))
}

/// 一个命令完成安装（design/release.md 第 4 节、hub.md 第 7 节）：密钥、程序的副本、服务配置；不接 Hub 时
/// 导入期望状态；有期望状态时启动服务，已在运行时按变化重启或重新加载。
pub fn install(args: &InstallArgs) -> anyhow::Result<()> {
    require_root()?;
    ensure_dir(DIR, 0o700)?;
    ensure_dir(LOG_DIR, 0o700)?;
    let keys = crate::mesh::node_keys(Path::new(DIR))?;
    let hub_changed = apply_token(
        DIR,
        nett_mesh::store::DEFAULT_STATE_DIR,
        args.token.as_deref(),
    )?;
    let linked = HubConfig::load(Path::new(DIR))
        .map_err(anyhow::Error::msg)?
        .is_some();

    // 接了 Hub 的机器上期望状态只由 nett-node 写（design/hub.md 第 5 节）
    let site = invoking_site_dir();
    let imported = match (&args.config, linked) {
        (Some(_), true) => {
            bail!("this machine receives its desired state from its Hub; --config is not used")
        }
        (Some(path), false) => {
            let bytes = crate::site::read_desired(path)?
                .with_context(|| format!("{} is not a regular file", path.display()))?;
            crate::site::check_desired_for(&bytes, &keys.0)?;
            Some(bytes)
        }
        (None, false) => match &site {
            Some(site) => crate::site::find_desired_for(site, &keys.0)?.map(|(path, bytes)| {
                println!("Using {}", path.display());
                bytes
            }),
            None => None,
        },
        (None, true) => None,
    };
    let desired_changed = match imported {
        Some(bytes) => replace_if_changed(Path::new(DESIRED), &bytes, 0o600)?,
        None => false,
    };
    let binary_changed = copy_self(BINARY)?;
    let mesh_plist_changed =
        replace_if_changed(Path::new(MESH.plist), plist(&MESH).as_bytes(), 0o644)?;
    let node_plist_changed =
        linked && replace_if_changed(Path::new(NODE.plist), plist(&NODE).as_bytes(), 0o644)?;
    replace_if_changed(Path::new(NEWSYSLOG), newsyslog().as_bytes(), 0o644)?;

    // 公钥那一行只在本机还没有加进站点时需要
    if !Path::new(DESIRED).exists() {
        crate::mesh::print_keys(Path::new(DIR), keys);
        let site = site.map_or_else(|| "~/.config/nett".to_owned(), |s| s.display().to_string());
        println!("Installed to {DIR}. Not started: {site} has no desired state for this machine.");
        println!(
            "Once the machine is in the site, run `sudo nett install` again: it imports its desired state."
        );
        println!(
            "If the site is on another machine, use `sudo nett install --config <desired.json>`."
        );
        return Ok(());
    }
    let mut messages = Vec::new();
    match ensure_running(&MESH, mesh_plist_changed, binary_changed)? {
        Some(m) => messages.push(m),
        None if desired_changed => {
            // 只有期望状态变了：经本机接口重新读取，不重启、连接不中断，并显示它是否被接受（design/status.md
            // 第 4.1 节）
            print!(
                "{}",
                crate::status::reload_at(Path::new(nett_mesh::status::DEFAULT_SOCKET))?
            );
        }
        None => {}
    }
    if linked
        && let Some(m) = ensure_running(&NODE, node_plist_changed, binary_changed || hub_changed)?
    {
        messages.push(m);
    }
    if messages.is_empty() && !desired_changed {
        messages.push("The services are running. Nothing changed.".to_owned());
    }
    for m in messages {
        println!("{m}");
    }
    if mesh_plist_changed || node_plist_changed || binary_changed {
        println!("Logs: log show --last 1h --predicate 'process == \"nett\"'");
        if linked {
            println!("Run `sudo nett install` again after `brew upgrade nett`.");
        } else {
            println!(
                "Run `sudo nett install` again after the site changes or `brew upgrade nett`."
            );
        }
    }
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

pub fn uninstall() -> anyhow::Result<()> {
    require_root()?;
    stop(&NODE)?;
    stop(&MESH)?;
    for path in [NODE.plist, MESH.plist, NEWSYSLOG, BINARY] {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {path}")),
        }
    }
    println!(
        "Removed the services. Keys, the desired state, the trust store and the Hub configuration remain in {DIR}."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_configuration_names_the_root_copy() {
        let p = plist(&MESH);
        assert!(p.contains(&format!("<string>{BINARY}</string>")));
        assert!(p.contains(&format!("<string>{DESIRED}</string>")));
        assert!(plist(&NODE).contains("<string>node</string>"));
        assert!(
            !p.contains("homebrew"),
            "the service never runs the Homebrew copy"
        );
        assert!(newsyslog().contains(&format!("{LOG_DIR}/mesh.log")));
        assert!(newsyslog().contains(&format!("{LOG_DIR}/node.log")));
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
        for service in [&MESH, &NODE] {
            fs::write(&file, plist(service)).expect("write");
            let status = std::process::Command::new("/usr/bin/plutil")
                .args(["-lint", "-s"])
                .arg(&file)
                .status()
                .expect("plutil");
            assert!(status.success(), "{}", service.label);
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
