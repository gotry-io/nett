//! 调用外部命令（`ip`、`nft`、`tc`、`wg`、`ping` 等）：参数数组传参，不经过 shell，都有超时。

use std::ffi::OsStr;
use std::fs::File;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};

/// 单条命令的默认超时。
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// 运行命令并返回标准输出；退出码非 0 时返回带标准错误的错误。
pub fn run<I, S>(program: &str, args: I) -> anyhow::Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    run_with_input(program, args, None, COMMAND_TIMEOUT)
}

/// 在网络命名空间中运行。
pub fn run_in<I, S>(netns: &str, program: &str, args: I) -> anyhow::Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut full: Vec<std::ffi::OsString> =
        vec!["netns".into(), "exec".into(), netns.into(), program.into()];
    full.extend(args.into_iter().map(|a| a.as_ref().to_owned()));
    run("ip", full)
}

pub fn run_with_input<I, S>(
    program: &str,
    args: I,
    input: Option<&[u8]>,
    timeout: Duration,
) -> anyhow::Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args: Vec<_> = args.into_iter().map(|a| a.as_ref().to_owned()).collect();
    let shown = format!(
        "{program} {}",
        args.iter()
            .map(|a| a.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );
    let mut child = Command::new(program)
        .args(&args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting `{shown}`"))?;
    if let (Some(input), Some(mut stdin)) = (input, child.stdin.take()) {
        use std::io::Write as _;
        stdin
            .write_all(input)
            .with_context(|| format!("writing to `{shown}`"))?;
    }
    // 边运行边读取输出：输出超过管道缓冲时，子进程才不会卡在写入上
    let stdout = child.stdout.take().map(drain);
    let stderr = child.stderr.take().map(drain);
    let status =
        wait_timeout(&mut child, timeout).with_context(|| format!("waiting for `{shown}`"))?;
    let stdout = stdout.and_then(|h| h.join().ok()).unwrap_or_default();
    let stderr = stderr.and_then(|h| h.join().ok()).unwrap_or_default();
    match status {
        Some(status) if status.success() => Ok(stdout),
        Some(status) => bail!("`{shown}` failed ({status}): {}", stderr.trim()),
        None => bail!("`{shown}` did not finish within {timeout:?}"),
    }
}

fn drain(mut pipe: impl std::io::Read + Send + 'static) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut out = String::new();
        pipe.read_to_string(&mut out).ok();
        out
    })
}

fn wait_timeout(
    child: &mut Child,
    timeout: Duration,
) -> std::io::Result<Option<std::process::ExitStatus>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            child.kill().ok();
            child.wait().ok();
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// 在网络命名空间中启动一个长期运行的进程，输出写入日志文件。
pub fn spawn_in<I, S>(netns: &str, program: &Path, args: I, log: &Path) -> anyhow::Result<Child>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    // 追加：同一个节点的进程重启后，日志接在后面
    let log_file = File::options()
        .create(true)
        .append(true)
        .open(log)
        .with_context(|| format!("opening {}", log.display()))?;
    let err_file = log_file.try_clone().context("duplicating log handle")?;
    Command::new("ip")
        .args(["netns", "exec", netns])
        .arg(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(log_file)
        .stderr(err_file)
        .spawn()
        .with_context(|| format!("starting {} in {netns}", program.display()))
}
