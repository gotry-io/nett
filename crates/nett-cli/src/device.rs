//! What `nett site device add` exports (design/devices.md section 8): a standard WireGuard
//! configuration, written with mode `0600` without overwriting a file, and its QR code on a terminal.
//! The device's private key exists only in these, and in memory, where it is zeroed.

use std::io::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use nett_core::name::NodeName;
use nett_core::prefix::IpPrefix;
use nett_mesh::dataplane::MESH_MTU;
use nett_mesh::key::PrivateKey;
use nett_site::state::{Machine, State};
use zeroize::Zeroizing;

/// Keepalive the device sends, so the NAT in front of a phone keeps its mapping.
const KEEPALIVE_SECS: u16 = 25;

/// The gateway a new device comes through, chosen as `nett site device add` chooses it and checked
/// before anything is signed: it has joined, so its key is known, and has a public address.
pub fn gateway_for<'a>(
    state: &'a State,
    chosen: Option<&NodeName>,
) -> anyhow::Result<(&'a NodeName, &'a Machine)> {
    let in_use: std::collections::BTreeSet<&nett_core::id::NodeId> =
        state.devices.values().map(|d| &d.gateway).collect();
    let (name, m) = match (chosen, in_use.len()) {
        (Some(c), _) => state
            .machines
            .get_key_value(c)
            .with_context(|| format!("there is no machine `{c}`"))?,
        (None, 1) => state
            .machines
            .iter()
            .find(|(_, m)| in_use.contains(&m.node_id))
            .context("the gateway in use is not in the site")?,
        (None, 0) => {
            bail!("name the public machine the first device joins through with --gateway <machine>")
        }
        (None, _) => bail!("devices come through more than one gateway; choose one with --gateway"),
    };
    if m.keys.is_none() {
        bail!("gateway `{name}` has not joined yet, so its key is not known");
    }
    endpoint(m, state.listen_port).with_context(|| {
        format!("gateway `{name}` has no known public address; give it with `nett site set {name} --ipv4 <address>`")
    })?;
    Ok((name, m))
}

/// The file the configuration goes into, refused when it exists already.
pub struct Files {
    pub wireguard: PathBuf,
}

impl Files {
    pub fn new(out: &Path, name: &NodeName) -> anyhow::Result<Self> {
        let wireguard = out.join(format!("{name}.conf"));
        if wireguard.exists() {
            bail!(
                "{} exists already; move it away or choose another directory with --out",
                wireguard.display()
            );
        }
        Ok(Self { wireguard })
    }
}

/// Writes the configurations of device `name`, already added to `state`, and prints where they went
/// and, on a terminal, the QR code.
pub fn export(
    state: &State,
    name: &NodeName,
    key: &PrivateKey,
    files: &Files,
    terminal: bool,
) -> anyhow::Result<()> {
    let device = state
        .devices
        .get(name)
        .with_context(|| format!("there is no device `{name}`"))?;
    let gateway = state
        .by_id(&device.gateway)
        .context("the device's gateway is not in the site")?;
    let gateway_key = gateway.keys.context("the gateway has not joined yet")?.mesh;
    let endpoint =
        endpoint(gateway, state.listen_port).context("the gateway has no known public address")?;
    let config = Config {
        private_key: Zeroizing::new(STANDARD.encode(key.as_bytes())),
        ipv4: device.credential.addresses.ipv4.into(),
        ipv6: device.credential.addresses.ipv6.into(),
        gateway_key: STANDARD.encode(gateway_key.as_bytes()),
        endpoint,
        allowed: allowed_ips(state),
    };
    let wireguard = config.wireguard();
    write_new(&files.wireguard, &wireguard)?;
    println!("Wrote {} (WireGuard).", files.wireguard.display());
    println!(
        "It holds the device's private key, and nett keeps no copy: import it, then delete it."
    );
    if terminal {
        print!("{}", qr(&wireguard)?.as_str());
    }
    Ok(())
}

/// Where a device connects to its gateway: the public IPv4 address when there is one, which more
/// networks reach, otherwise the IPv6 one.
fn endpoint(m: &Machine, default_port: u16) -> Option<SocketAddr> {
    let port = m.listen_port(default_port)?;
    let ip = m
        .public_ipv4()
        .map(IpAddr::V4)
        .or_else(|| m.public_ipv6().map(IpAddr::V6))?;
    Some(SocketAddr::new(ip, port))
}

/// The mesh prefixes and every advertised route: the rule set decides what passes, so the
/// configuration stays valid when rules change (design/devices.md section 8).
fn allowed_ips(state: &State) -> Vec<IpPrefix> {
    [state.prefixes.ipv4, state.prefixes.ipv6]
        .into_iter()
        .chain(
            state
                .machines
                .values()
                .flat_map(|m| m.routes.iter().copied()),
        )
        .collect()
}

struct Config {
    private_key: Zeroizing<String>,
    ipv4: IpAddr,
    ipv6: IpAddr,
    gateway_key: String,
    endpoint: SocketAddr,
    allowed: Vec<IpPrefix>,
}

impl Config {
    fn allowed_list(&self) -> String {
        self.allowed
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn wireguard(&self) -> Zeroizing<String> {
        Zeroizing::new(format!(
            "[Interface]\nPrivateKey = {}\nAddress = {}/32, {}/128\nMTU = {MESH_MTU}\n\n\
             [Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = {}\nPersistentKeepalive = {KEEPALIVE_SECS}\n",
            self.private_key.as_str(),
            self.ipv4,
            self.ipv6,
            self.gateway_key,
            self.endpoint,
            self.allowed_list(),
        ))
    }
}

/// A new file with mode `0600`; fails when it exists.
fn write_new(path: &Path, text: &str) -> anyhow::Result<()> {
    let mut options = std::fs::File::options();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(text.as_bytes())
        .with_context(|| format!("writing {}", path.display()))
}

/// The QR code of `text` in half blocks, two modules per character cell. Light modules are drawn,
/// as `qrencode -t UTF8` does, for a terminal with light text on a dark background.
fn qr(text: &str) -> anyhow::Result<Zeroizing<String>> {
    use qrcodegen::{QrCode, QrCodeEcc};
    const QUIET: i32 = 2;
    let code = QrCode::encode_text(text, QrCodeEcc::Low)
        .map_err(|e| anyhow::anyhow!("the configuration does not fit a QR code: {e:?}"))?;
    let size = code.size();
    let light = |x: i32, y: i32| {
        !(0..size).contains(&x) || !(0..size).contains(&y) || !code.get_module(x, y)
    };
    let mut out = Zeroizing::new(String::new());
    let mut y = -QUIET;
    while y < size + QUIET {
        for x in -QUIET..size + QUIET {
            out.push(match (light(x, y), light(x, y + 1)) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        out.push('\n');
        y += 2;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            private_key: Zeroizing::new(STANDARD.encode([7u8; 32])),
            ipv4: "100.88.0.9".parse().expect("ip"),
            ipv6: "fd00:88::9".parse().expect("ip"),
            gateway_key: STANDARD.encode([1u8; 32]),
            endpoint: "203.0.113.10:41820".parse().expect("endpoint"),
            allowed: vec![
                "100.88.0.0/16".parse().expect("prefix"),
                "fd00:88::/48".parse().expect("prefix"),
            ],
        }
    }

    #[test]
    fn the_wireguard_configuration_names_the_device_and_its_gateway() {
        let text = config().wireguard();
        assert!(text.contains(&format!("PrivateKey = {}\n", STANDARD.encode([7u8; 32]))));
        assert!(text.contains("Address = 100.88.0.9/32, fd00:88::9/128\n"));
        assert!(text.contains("MTU = 1280\n"));
        assert!(text.contains(&format!("PublicKey = {}\n", STANDARD.encode([1u8; 32]))));
        assert!(text.contains("Endpoint = 203.0.113.10:41820\n"));
        assert!(text.contains("AllowedIPs = 100.88.0.0/16, fd00:88::/48\n"));
        assert!(text.contains("PersistentKeepalive = 25\n"));
    }

    #[test]
    fn files_are_private_and_never_overwritten() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("x.conf");
        write_new(&path, "secret").expect("written");
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path)
            .expect("exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(write_new(&path, "again").is_err());
        let name: NodeName = "x".parse().expect("name");
        assert!(Files::new(dir.path(), &name).is_err());
    }

    #[test]
    fn the_qr_code_is_square_with_a_quiet_zone() {
        let code = qr(&config().wireguard()).expect("qr");
        let lines: Vec<&str> = code.lines().collect();
        let width = lines[0].chars().count();
        assert!(lines.iter().all(|l| l.chars().count() == width));
        assert!(lines[0].chars().all(|c| c == '█'));
    }
}
