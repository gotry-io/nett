//! Tailscale, the comparison target (design/prototype.md section 5.1): in the same topology,
//! `nl-ctl` runs Headscale and its built-in DERP server (self-signed certificate, no connection to
//! external services), and the namespace of each node runs `tailscaled`.
//!
//! `tailscale`, `tailscaled` and `headscale` are looked up in `PATH`, and the versions are written
//! to the report. The self-signed certificate is handed to `tailscaled` only via `SSL_CERT_FILE`,
//! and the system trust store is not modified.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};

use crate::cmd::{run, run_in, spawn_in};
use crate::net::{INET_NETNS, add_netns, attach, netns};

/// Namespace of Headscale and DERP, attached to the "public network" bridge.
pub const CONTROL_NETNS: &str = "nl-ctl";
const CONTROL_NAME: &str = "ctl";
pub const CONTROL_IPV4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 250);
/// Address pool of Tailscale; does not overlap nett's mesh prefixes (100.88.0.0/16) (ADR 0007).
const TAILNET_V4: &str = "100.72.0.0/16";
/// WireGuard port of tailscaled.
const TAILSCALED_PORT: u16 = 41641;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

pub struct TailscaleLab {
    sockets: BTreeMap<String, PathBuf>,
    /// Headscale.
    control: Option<Child>,
    children: Vec<Child>,
    /// Number and certificate directory of a standalone DERP, used on restart.
    derp_args: Vec<(usize, PathBuf)>,
    derps: Vec<(usize, Child)>,
}

impl Drop for TailscaleLab {
    fn drop(&mut self) {
        self.stop_control();
        for (_, child) in &mut self.derps {
            child.kill().ok();
            child.wait().ok();
        }
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

/// Version recorded in the report.
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
    /// Starts Headscale and the built-in DERP, then logs in every node in `nodes`. The underlay
    /// network must already be built.
    pub fn up(out: &Path, nodes: &[&str]) -> anyhow::Result<Self> {
        Self::up_with(out, nodes, 0)
    }

    /// When `derps` is 0, the DERP built into Headscale is used; otherwise that many standalone
    /// DERP regions are started (`derper`, the same version as Tailscale), and Headscale only acts
    /// as the control plane, so breaking a DERP does not affect the control plane.
    pub fn up_with(out: &Path, nodes: &[&str], derps: usize) -> anyhow::Result<Self> {
        let dir = out.join("tailscale");
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let mut lab = Self {
            sockets: BTreeMap::new(),
            control: None,
            children: Vec::new(),
            derp_args: Vec::new(),
            derps: Vec::new(),
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
        self_signed(CONTROL_IPV4, &cert, &key)?;

        // Standalone DERP nodes: one namespace each, with certificates named <host name>.crt/.key
        // following derper's manual mode
        let mut bundle = std::fs::read(&cert).context("reading the control certificate")?;
        let mut derp_map = None;
        if derps > 0 {
            let mut regions = String::from("regions:\n");
            for i in 1..=derps {
                let ns = derp_netns(i);
                let ip = derp_ipv4(i);
                add_netns(&ns)?;
                attach(&ns, INET_NETNS, &format!("v-derp{i}"), "br0")?;
                run(
                    "ip",
                    ["-n", &ns, "addr", "add", &format!("{ip}/24"), "dev", "eth0"],
                )?;
                let certdir = dir.join(format!("derp{i}"));
                std::fs::create_dir_all(&certdir)
                    .with_context(|| format!("creating {}", certdir.display()))?;
                let crt = certdir.join(format!("{ip}.crt"));
                self_signed(ip, &crt, &certdir.join(format!("{ip}.key")))?;
                bundle.extend(std::fs::read(&crt).context("reading a DERP certificate")?);
                let region = 900 + i;
                regions.push_str(&format!(
                    "  {region}:\n    regionid: {region}\n    regioncode: lab{i}\n    regionname: lab{i}\n    nodes:\n      - name: {region}a\n        regionid: {region}\n        hostname: {ip}\n        ipv4: {ip}\n        stunport: 3478\n        derpport: 443\n"
                ));
                lab.derp_args.push((i, certdir));
                lab.start_derp(i)?;
            }
            let map = dir.join("derpmap.yaml");
            std::fs::write(&map, regions).with_context(|| format!("writing {}", map.display()))?;
            derp_map = Some(map);
        }
        let bundle_path = dir.join("ca-bundle.pem");
        std::fs::write(&bundle_path, bundle).context("writing the certificate bundle")?;

        let config = dir.join("headscale.yaml");
        std::fs::write(
            &config,
            headscale_config(&dir, &cert, &key, derp_map.as_deref()),
        )
        .with_context(|| format!("writing {}", config.display()))?;
        let child = spawn_in(
            CONTROL_NETNS,
            Path::new("headscale"),
            ["-c".as_ref(), config.as_os_str(), "serve".as_ref()],
            &dir.join("headscale.log"),
        )?;
        lab.control = Some(child);
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
                    format!("SSL_CERT_FILE={}", bundle_path.display()),
                    // Do not report to Tailscale's logging service
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

    fn start_derp(&mut self, i: usize) -> anyhow::Result<()> {
        let (_, certdir) = self
            .derp_args
            .iter()
            .find(|(n, _)| *n == i)
            .context("unknown DERP")?;
        let ip = derp_ipv4(i);
        let child = spawn_in(
            &derp_netns(i),
            Path::new("derper"),
            [
                format!("-a={ip}:443"),
                format!("-hostname={ip}"),
                "-certmode=manual".to_owned(),
                format!("-certdir={}", certdir.display()),
                "-http-port=-1".to_owned(),
                "-stun-port=3478".to_owned(),
            ],
            &certdir.join("derper.log"),
        )?;
        self.derps.push((i, child));
        Ok(())
    }

    /// Stops Headscale (scenario 17).
    pub fn stop_control(&mut self) {
        if let Some(mut child) = self.control.take() {
            child.kill().ok();
            child.wait().ok();
        }
    }

    /// Stops the `i`-th DERP process (scenario 17).
    pub fn stop_derp(&mut self, i: usize) {
        if let Some(pos) = self.derps.iter().position(|(n, _)| *n == i) {
            let (_, mut child) = self.derps.remove(pos);
            child.kill().ok();
            child.wait().ok();
        }
    }

    /// Restarts the `i`-th DERP process (scenario 3).
    pub fn restart_derp(&mut self, i: usize) -> anyhow::Result<()> {
        self.stop_derp(i);
        self.start_derp(i)
    }

    /// Runs a `tailscale` command in the node's namespace.
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

/// Namespace and address of the `i`-th standalone DERP.
pub fn derp_netns(i: usize) -> String {
    format!("nl-derp{i}")
}

pub fn derp_ipv4(i: usize) -> Ipv4Addr {
    Ipv4Addr::new(198, 51, 100, 240 + u8::try_from(i).unwrap_or(0))
}

/// Generates a self-signed certificate for an IP address.
fn self_signed(ip: Ipv4Addr, cert: &Path, key: &Path) -> anyhow::Result<()> {
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
            &format!("subjectAltName=IP:{ip}"),
            "-keyout",
            &key.to_string_lossy(),
            "-out",
            &cert.to_string_lossy(),
        ],
    )?;
    Ok(())
}

fn headscale_config(dir: &Path, cert: &Path, key: &Path, derp_map: Option<&Path>) -> String {
    let d = dir.display();
    let (embedded, paths) = match derp_map {
        Some(map) => ("false", format!("[{}]", map.display())),
        None => ("true", "[]".to_owned()),
    };
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
    enabled: {embedded}
    region_id: 999
    region_code: lab
    region_name: lab
    verify_clients: true
    stun_listen_addr: {CONTROL_IPV4}:3478
    private_key_path: {d}/derp_server_private.key
    automatically_add_embedded_derp_region: true
    ipv4: {CONTROL_IPV4}
  urls: []
  paths: {paths}
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
