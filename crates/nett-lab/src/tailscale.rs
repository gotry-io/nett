//! 对比对象 Tailscale（design/prototype.md 第 5.1 节）：在同一拓扑中，`nl-ctl` 运行 Headscale 和它内置的
//! DERP 服务器（自签证书，不连接外部服务），每个节点的命名空间运行 `tailscaled`。
//!
//! `tailscale`、`tailscaled`、`headscale` 从 `PATH` 中查找，版本写入报告。自签证书只经 `SSL_CERT_FILE`
//! 交给 `tailscaled`，不改动系统的信任库。

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};

use crate::cmd::{run, run_in, spawn_in};
use crate::net::{INET_NETNS, add_netns, attach, netns};

/// Headscale 与 DERP 所在的命名空间，接在"公网"网桥上。
pub const CONTROL_NETNS: &str = "nl-ctl";
const CONTROL_NAME: &str = "ctl";
pub const CONTROL_IPV4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 250);
/// Tailscale 的地址池；与 nett 的组网网段（100.88.0.0/16）不重叠（ADR 0007）。
const TAILNET_V4: &str = "100.72.0.0/16";
/// tailscaled 的 WireGuard 端口。
const TAILSCALED_PORT: u16 = 41641;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

pub struct TailscaleLab {
    sockets: BTreeMap<String, PathBuf>,
    children: Vec<Child>,
}

impl Drop for TailscaleLab {
    fn drop(&mut self) {
        for child in &mut self.children {
            child.kill().ok();
            child.wait().ok();
        }
    }
}

fn wait_until(what: &str, mut ready: impl FnMut() -> bool) -> anyhow::Result<()> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    while !ready() {
        if Instant::now() >= deadline {
            bail!("{what} did not become ready within {STARTUP_TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(())
}

/// 记录到报告中的版本。
pub fn versions() -> String {
    let ts = run("tailscale", ["version"]).map(|s| s.lines().next().unwrap_or_default().to_owned());
    let hs = run("headscale", ["version"]).map(|s| s.lines().next().unwrap_or_default().to_owned());
    format!(
        "tailscale {}; {}",
        ts.unwrap_or_else(|e| format!("unavailable: {e:#}")),
        hs.unwrap_or_else(|e| format!("headscale unavailable: {e:#}"))
    )
}

impl TailscaleLab {
    /// 启动 Headscale 与 DERP，再让 `nodes` 中的每个节点登录。底层网络必须已经搭好。
    pub fn up(out: &Path, nodes: &[&str]) -> anyhow::Result<Self> {
        let dir = out.join("tailscale");
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let mut lab = Self {
            sockets: BTreeMap::new(),
            children: Vec::new(),
        };

        add_netns(CONTROL_NETNS)?;
        attach(
            CONTROL_NETNS,
            INET_NETNS,
            &format!("v-{CONTROL_NAME}"),
            "br0",
        )?;
        run(
            "ip",
            [
                "-n",
                CONTROL_NETNS,
                "addr",
                "add",
                &format!("{CONTROL_IPV4}/24"),
                "dev",
                "eth0",
            ],
        )?;

        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        run(
            "openssl",
            [
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-days",
                "7",
                "-subj",
                "/CN=nett-lab",
                "-addext",
                &format!("subjectAltName=IP:{CONTROL_IPV4}"),
                "-keyout",
                &key.to_string_lossy(),
                "-out",
                &cert.to_string_lossy(),
            ],
        )?;
        let config = dir.join("headscale.yaml");
        std::fs::write(&config, headscale_config(&dir, &cert, &key))
            .with_context(|| format!("writing {}", config.display()))?;
        let child = spawn_in(
            CONTROL_NETNS,
            Path::new("headscale"),
            ["-c".as_ref(), config.as_os_str(), "serve".as_ref()],
            &dir.join("headscale.log"),
        )?;
        lab.children.push(child);
        let socket = dir.join("headscale.sock");
        wait_until("headscale", || socket.exists())?;

        let hs = |args: &[&str]| -> anyhow::Result<String> {
            let mut full = vec!["-c", config.to_str().context("config path")?];
            full.extend_from_slice(args);
            run("headscale", full)
        };
        hs(&["users", "create", "lab"])?;
        let created = hs(&[
            "preauthkeys",
            "create",
            "--user",
            "1",
            "--reusable",
            "--expiration",
            "1h",
            "-o",
            "json",
        ])?;
        let auth_key = serde_json::from_str::<serde_json::Value>(&created)
            .ok()
            .and_then(|v| v["key"].as_str().map(str::to_owned))
            .context("headscale did not return a pre-auth key")?;

        for name in nodes {
            let node_dir = dir.join(name);
            std::fs::create_dir_all(&node_dir)
                .with_context(|| format!("creating {}", node_dir.display()))?;
            let sock = node_dir.join("tailscaled.sock");
            let child = spawn_in(
                &netns(name),
                Path::new("env"),
                [
                    format!("SSL_CERT_FILE={}", cert.display()),
                    // 不向 Tailscale 的日志服务上报
                    "TS_NO_LOGS_NO_SUPPORT=true".to_owned(),
                    "tailscaled".to_owned(),
                    format!("--state={}", node_dir.join("tailscaled.state").display()),
                    format!("--statedir={}", node_dir.display()),
                    format!("--socket={}", sock.display()),
                    "--tun=tailscale0".to_owned(),
                    format!("--port={TAILSCALED_PORT}"),
                ],
                &node_dir.join("tailscaled.log"),
            )?;
            lab.children.push(child);
            wait_until(&format!("tailscaled on {name}"), || sock.exists())?;
            lab.sockets.insert((*name).to_owned(), sock);
            lab.cli(
                name,
                &[
                    "up",
                    &format!("--login-server=https://{CONTROL_IPV4}"),
                    &format!("--authkey={auth_key}"),
                    &format!("--hostname={name}"),
                    "--accept-dns=false",
                    "--timeout=30s",
                ],
            )?;
        }
        Ok(lab)
    }

    /// 在节点的命名空间中运行 `tailscale` 命令。
    pub fn cli(&self, name: &str, args: &[&str]) -> anyhow::Result<String> {
        let sock = self
            .sockets
            .get(name)
            .with_context(|| format!("no tailscaled on {name}"))?;
        let mut full = vec![format!("--socket={}", sock.display())];
        full.extend(args.iter().map(|a| (*a).to_owned()));
        run_in(&netns(name), "tailscale", full)
    }

    pub fn ipv4(&self, name: &str) -> anyhow::Result<Ipv4Addr> {
        self.cli(name, &["ip", "-4"])?
            .trim()
            .parse()
            .context("parsing the tailscale address")
    }
}

fn headscale_config(dir: &Path, cert: &Path, key: &Path) -> String {
    let d = dir.display();
    format!(
        "server_url: https://{CONTROL_IPV4}
listen_addr: {CONTROL_IPV4}:443
metrics_listen_addr: 127.0.0.1:9090
grpc_listen_addr: 127.0.0.1:50443
grpc_allow_insecure: false
noise:
  private_key_path: {d}/noise_private.key
prefixes:
  v4: {TAILNET_V4}
  v6: fd7a:115c:a1e0::/48
  allocation: sequential
derp:
  server:
    enabled: true
    region_id: 999
    region_code: lab
    region_name: lab
    verify_clients: true
    stun_listen_addr: {CONTROL_IPV4}:3478
    private_key_path: {d}/derp_server_private.key
    automatically_add_embedded_derp_region: true
    ipv4: {CONTROL_IPV4}
  urls: []
  paths: []
  auto_update_enabled: false
disable_check_updates: true
database:
  type: sqlite
  sqlite:
    path: {d}/db.sqlite
tls_cert_path: {}
tls_key_path: {}
log:
  level: info
policy:
  mode: file
  path: \"\"
dns:
  magic_dns: false
  override_local_dns: false
unix_socket: {d}/headscale.sock
unix_socket_permission: \"0770\"
logtail:
  enabled: false
taildrop:
  enabled: false
",
        cert.display(),
        key.display()
    )
}
