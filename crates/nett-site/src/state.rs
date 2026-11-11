//! Site state (design/site.md section 8): machines, permissions, access rules, and the signed
//! artifacts with their versions. It holds no private key: the recovery key is stored in a separate
//! file in the site directory and read only when signing.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use nett_core::id::NodeId;
use nett_core::name::NodeName;
use nett_core::prefix::IpPrefix;
use nett_core::transport::CertFingerprint;
use nett_mesh::config::{MAX_MEMBERS, MeshPrefixes, Reachability, is_reserved_port};
use nett_mesh::lan::LanAddress;
use nett_trust::admission::AdmissionMaterial;
use nett_trust::anchors::TrustAnchorsDoc;
use nett_trust::encoding::Sha256Digest;
use nett_trust::keys::{Ed25519PublicKey, X25519PublicKey};
use nett_trust::payload::{MeshAddresses, PortRange};
use nett_trust::signed::SignedPayload;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::SiteError;

/// Format version of the site state.
pub const FORMAT_V1: u32 = 1;
/// Default WireGuard port of `public` machines.
pub const DEFAULT_LISTEN_PORT: u16 = 41820;
/// Default UDP port of a relay (design/site.md section 4.1).
pub const DEFAULT_RELAY_PORT: u16 = 41822;
/// Default TCP port of a relay's TLS transport.
pub const DEFAULT_RELAY_TLS_PORT: u16 = 443;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub v: u32,
    pub trust_anchors: TrustAnchorsDoc,
    /// Mesh prefixes: fixed when the site is created, cannot change afterwards.
    pub prefixes: MeshPrefixes,
    /// Default WireGuard port of `public` machines.
    pub listen_port: u16,
    /// Which address in the mesh prefixes is allocated next. Addresses are not reclaimed
    /// (design/mesh.md section 3).
    pub next_host: u32,
    /// Number of the next rule. Numbers are not reused (design/site.md section 5.1).
    pub next_rule: u32,
    #[serde(default)]
    pub machines: BTreeMap<NodeName, Machine>,
    #[serde(default)]
    pub rules: BTreeMap<RuleId, Rule>,
    /// Removed machines: revocation takes effect permanently, and the addresses are not allocated
    /// again.
    #[serde(default)]
    pub revoked: Vec<Revoked>,
    /// The signed access rule set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_rules: Option<SignedVersion>,
    /// Key the probe tokens between members and relays are derived from (design/site.md section
    /// 4.1); created with the first relay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_key: Option<RelayKey>,
    /// Public key the Hub seals its backups to; the private key is `backup.key` in the site
    /// directory (design/hub.md section 8.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_key: Option<X25519PublicKey>,
}

/// The site's relay key. `Debug` does not print it (hard rule 10).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RelayKey(#[serde(with = "nett_trust::encoding::b64_fixed")] pub [u8; 32]);

impl fmt::Debug for RelayKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RelayKey(<redacted>)")
    }
}

/// A relay on a `public` machine (design/site.md section 4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayRole {
    /// UDP relay port.
    pub port: u16,
    /// TCP port of the TLS transport; absent when the relay serves UDP only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_port: Option<u16>,
    /// Certificate fingerprint given with `--fingerprint`; with a Hub it is learned instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<CertFingerprint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Machine {
    pub node_id: NodeId,
    pub reachability: Reachability,
    /// Public address of a `public` machine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<Ipv6Addr>,
    /// WireGuard port of a `public` machine itself; the site default port when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// The machine's public key: without a Hub, given by `add --keys`; for a machine that joined
    /// through the Hub, taken from its admission proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<NodeKeys>,
    /// Waiting to join through the Hub (design/hub.md section 6): enrollment public key, token
    /// expiry time and the signed initial node policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment: Option<Enrollment>,
    /// Public address learned by the Hub (design/hub.md section 5): used when a `public` machine
    /// has no address given.
    #[serde(default, skip_serializing_if = "Learned::is_empty")]
    pub learned: Learned,
    /// Mesh addresses.
    pub mesh: MeshAddresses,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<RelayRole>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge: Option<Edge>,
    /// Advertised routes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<IpPrefix>,
    /// Signed node policy and admission proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<SignedPolicy>,
    /// Signed advertised routes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routes_signed: Option<SignedVersion>,
    /// Highest version of advertised routes ever signed. When all routes are removed, the signed
    /// artifact is removed with them, but the version stays here: advertising again continues to
    /// increase it, and the mesh process only accepts higher versions (design/mesh.md section 4.2).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub routes_version: u64,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

impl Machine {
    /// WireGuard port of a `public` machine.
    pub fn listen_port(&self, default: u16) -> Option<u16> {
        (self.reachability == Reachability::Public).then(|| self.port.unwrap_or(default))
    }

    /// Address other members use to connect to it: the one given takes precedence, otherwise the
    /// one learned by the Hub (taken per address family).
    pub fn public_ipv4(&self) -> Option<Ipv4Addr> {
        self.ipv4.or(self.learned.ipv4.map(|l| l.ip))
    }

    pub fn public_ipv6(&self) -> Option<Ipv6Addr> {
        self.ipv6.or(self.learned.ipv6.map(|l| l.ip))
    }

    /// Fingerprint of the relay's TLS certificate: the one given takes precedence, otherwise the
    /// one learned by the Hub.
    pub fn relay_fingerprint(&self) -> Option<CertFingerprint> {
        self.relay
            .and_then(|r| r.fingerprint)
            .or(self.learned.relay_fingerprint)
    }
}

/// A machine waiting to join (design/hub.md section 6). The enrollment private key appears only in
/// the printed token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enrollment {
    pub public_key: Ed25519PublicKey,
    /// Expiry time of the token (Unix seconds).
    pub expires_at: i64,
    /// The signed initial node policy: exists only after signing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<SignedVersion>,
}

/// What the Hub learned about a machine (design/hub.md section 5): its public addresses and their
/// source, and from its status its LAN addresses, WireGuard port and relay certificate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Learned {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<LearnedIp<Ipv4Addr>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<LearnedIp<Ipv6Addr>>,
    /// Fingerprint of the TLS certificate of the relay on this machine, from its status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_fingerprint: Option<CertFingerprint>,
    /// LAN addresses, from its status (design/mesh.md section 6).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lan: Vec<LanAddress>,
    /// The port WireGuard actually listens on, from its status: a `dial-only` machine's is assigned by
    /// the system.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
}

impl Learned {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearnedIp<T> {
    pub ip: T,
    pub from: AddressSource,
}

/// Where a learned address comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressSource {
    /// The global address this machine used when connecting to the Hub.
    Machine,
    /// The source address the Hub saw.
    Hub,
}

impl fmt::Display for AddressSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Machine => "reported by the machine",
            Self::Hub => "seen by the Hub",
        })
    }
}

/// The line printed by `nett keys` (or `sudo nett install`) on a machine: mesh public key and
/// identity public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeKeys {
    pub mesh: X25519PublicKey,
    pub identity: X25519PublicKey,
}

impl FromStr for NodeKeys {
    type Err = SiteError;

    fn from_str(s: &str) -> Result<Self, SiteError> {
        let mut parts = s.split_whitespace();
        let (Some(mesh), Some(identity), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(SiteError::invalid(
                "--keys takes the two public keys printed by `nett keys` or `sudo nett install`, \
                 separated by a space",
            ));
        };
        let key = |k: &str| {
            k.parse::<X25519PublicKey>()
                .map_err(|e| SiteError::invalid(format!("--keys: {e}")))
        };
        Ok(Self {
            mesh: key(mesh)?,
            identity: key(identity)?,
        })
    }
}

/// Edge on a machine: the address of the container Edge runs in, and the Edge address assigned to
/// it (ADR 0015).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edge {
    pub containers: Vec<IpPrefix>,
    pub addresses: MeshAddresses,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicy {
    pub version: u64,
    /// Hash of the inputs that generate the node policy and admission proof: when unchanged, the
    /// existing signature is reused.
    pub input: Sha256Digest,
    pub material: AdmissionMaterial,
}

/// A versioned signed artifact: version, hash of the inputs and the signed payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedVersion {
    pub version: u64,
    pub input: Sha256Digest,
    pub signed: SignedPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revoked {
    pub name: NodeName,
    pub node_id: NodeId,
}

/// An access rule: allow only (design/site.md section 5.1). Both sides are recorded by machine ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub from: Vec<Selector>,
    pub to: Vec<Selector>,
    /// All ports when absent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<PortRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Part {
    /// The machine's mesh address.
    Mesh,
    /// The machine's Edge address.
    Edge,
    /// The routes the machine advertises.
    Routes,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selector {
    pub node: NodeId,
    pub part: Part,
}

/// Rule number: `r1`, `r2`, ...
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleId(pub u32);

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "r{}", self.0)
    }
}

impl FromStr for RuleId {
    type Err = SiteError;

    fn from_str(s: &str) -> Result<Self, SiteError> {
        s.strip_prefix('r')
            .and_then(|n| n.parse().ok())
            .map(Self)
            .ok_or_else(|| SiteError::invalid(format!("`{s}` is not a rule ID such as r3")))
    }
}

impl Serialize for RuleId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for RuleId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl State {
    pub fn new(trust_anchors: TrustAnchorsDoc, prefixes: MeshPrefixes) -> Self {
        Self {
            v: FORMAT_V1,
            trust_anchors,
            prefixes,
            listen_port: DEFAULT_LISTEN_PORT,
            next_host: 1,
            next_rule: 1,
            machines: BTreeMap::new(),
            rules: BTreeMap::new(),
            revoked: Vec::new(),
            access_rules: None,
            relay_key: None,
            backup_key: None,
        }
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, SiteError> {
        let state: Self = serde_json::from_slice(bytes)
            .map_err(|e| SiteError::invalid(format!("state.json: {e}")))?;
        if state.v != FORMAT_V1 {
            return Err(SiteError::invalid(format!(
                "state.json: unsupported format version {}",
                state.v
            )));
        }
        state.check()?;
        Ok(state)
    }

    pub fn machine(&self, name: &NodeName) -> Result<&Machine, SiteError> {
        self.machines
            .get(name)
            .ok_or_else(|| SiteError::invalid(format!("there is no machine `{name}`")))
    }

    pub fn machine_mut(&mut self, name: &NodeName) -> Result<&mut Machine, SiteError> {
        self.machines
            .get_mut(name)
            .ok_or_else(|| SiteError::invalid(format!("there is no machine `{name}`")))
    }

    /// The machine name for a node ID.
    pub fn name_of(&self, node: &NodeId) -> Option<&NodeName> {
        self.machines
            .iter()
            .find(|(_, m)| m.node_id == *node)
            .map(|(name, _)| name)
    }

    pub fn by_id(&self, node: &NodeId) -> Option<&Machine> {
        self.machines.values().find(|m| m.node_id == *node)
    }

    /// Text form of a selector: `mac`, `edge-vps.edge`, `mac-app.routes`.
    pub fn selector_text(&self, s: &Selector) -> String {
        let name = self
            .name_of(&s.node)
            .map_or_else(|| s.node.to_string(), ToString::to_string);
        match s.part {
            Part::Mesh => name,
            Part::Edge => format!("{name}.edge"),
            Part::Routes => format!("{name}.routes"),
        }
    }

    /// A `public` machine whose public address is not known yet: without a Hub the command requires
    /// it to be given; with a Hub, the Hub learns it.
    pub fn unknown_public_addresses(&self) -> Vec<&NodeName> {
        self.machines
            .iter()
            .filter(|(_, m)| {
                m.reachability == Reachability::Public
                    && m.public_ipv4().is_none()
                    && m.public_ipv6().is_none()
            })
            .map(|(name, _)| name)
            .collect()
    }

    /// Internal consistency of the site: checked after every modifying command and after reading
    /// the site state (design/site.md section 7).
    pub fn check(&self) -> Result<(), SiteError> {
        if self.machines.len() > MAX_MEMBERS {
            return Err(SiteError::invalid(format!(
                "a site holds at most {MAX_MEMBERS} machines"
            )));
        }
        for (name, m) in &self.machines {
            // A `public` machine may not know its address yet: with a Hub, the Hub learns it;
            // without a Hub, the command requires it to be given
            // (unknown_public_addresses)
            match m.reachability {
                Reachability::DialOnly
                    if m.ipv4.is_some() || m.ipv6.is_some() || m.port.is_some() =>
                {
                    return Err(SiteError::invalid(format!(
                        "dial-only machine `{name}` takes no public address or port: nobody dials it, \
                         and the system picks its WireGuard port; a machine others connect to is --public"
                    )));
                }
                _ => {}
            }
            if let Some(port) = m.listen_port(self.listen_port)
                && (port == 0 || is_reserved_port(port))
            {
                return Err(SiteError::invalid(format!(
                    "machine `{name}`: WireGuard port {port} is 0 or one nett itself uses on the host; \
                     pick another with --port"
                )));
            }
            if let Some(relay) = &m.relay {
                if m.reachability != Reachability::Public {
                    return Err(SiteError::invalid(format!(
                        "machine `{name}` runs a relay, which needs a machine others connect to: \
                         keep it --public, or stop the relay with `nett site relay {name} --off`"
                    )));
                }
                if relay.port == 0
                    || is_reserved_port(relay.port)
                    || Some(relay.port) == m.listen_port(self.listen_port)
                {
                    return Err(SiteError::invalid(format!(
                        "machine `{name}`: relay port {} is 0, the WireGuard port, or one nett \
                         itself uses on the host; pick another with --port",
                        relay.port
                    )));
                }
                if relay.tls_port == Some(0) {
                    return Err(SiteError::invalid(format!(
                        "machine `{name}`: the relay's TLS port must not be 0"
                    )));
                }
                if self.relay_key.is_none() {
                    return Err(SiteError::invalid(
                        "the site has a relay but no relay key".to_owned(),
                    ));
                }
            }
            if m.keys.is_some() && m.enrollment.is_some() {
                return Err(SiteError::invalid(format!(
                    "machine `{name}` has keys and is still waiting to join"
                )));
            }
            if let Some(keys) = m.keys
                && let Some((other, _)) = self.machines.iter().find(|(o, other)| {
                    *o != name && other.keys.is_some_and(|k| k.identity == keys.identity)
                })
            {
                return Err(SiteError::invalid(format!(
                    "`{name}` and `{other}` have the same identity key"
                )));
            }
            if let Some(edge) = &m.edge
                && edge.containers.is_empty()
            {
                return Err(SiteError::invalid(format!(
                    "machine `{name}`: an Edge needs the address of its container"
                )));
            }
            let overlaps = |a: &IpPrefix, b: &IpPrefix| a.covers(b) || b.covers(a);
            for route in &m.routes {
                if overlaps(route, &self.prefixes.ipv4) || overlaps(route, &self.prefixes.ipv6) {
                    return Err(SiteError::invalid(format!(
                        "machine `{name}`: route {route} overlaps the mesh prefixes"
                    )));
                }
                if let Some((other, _)) = self.machines.iter().find(|(o, other)| {
                    *o != name && other.routes.iter().any(|r| overlaps(r, route))
                }) {
                    return Err(SiteError::invalid(format!(
                        "machine `{name}`: route {route} overlaps a route of `{other}`"
                    )));
                }
            }
        }
        // Public address plus port is where other members connect to it; two machines cannot have
        // the same one
        let mut endpoints = BTreeMap::new();
        for (name, m) in &self.machines {
            let Some(port) = m.listen_port(self.listen_port) else {
                continue;
            };
            for ip in [
                m.ipv4.map(std::net::IpAddr::V4),
                m.ipv6.map(std::net::IpAddr::V6),
            ]
            .into_iter()
            .flatten()
            {
                if let Some(other) = endpoints.insert((ip, port), name) {
                    return Err(SiteError::invalid(format!(
                        "`{other}` and `{name}` both listen on {ip} port {port}; give one of them \
                         another --port"
                    )));
                }
            }
        }
        for (id, rule) in &self.rules {
            if rule.from.is_empty() || rule.to.is_empty() {
                return Err(SiteError::invalid(format!("rule {id} has an empty side")));
            }
            for s in rule.from.iter().chain(&rule.to) {
                let Some(m) = self.by_id(&s.node) else {
                    return Err(SiteError::invalid(format!(
                        "rule {id} names node {}, which is not in the site",
                        s.node
                    )));
                };
                let ok = match s.part {
                    Part::Mesh => true,
                    Part::Edge => m.edge.is_some(),
                    Part::Routes => !m.routes.is_empty(),
                };
                if !ok {
                    return Err(SiteError::invalid(format!(
                        "rule {id} names {}, which does not exist",
                        self.selector_text(s)
                    )));
                }
            }
        }
        Ok(())
    }
}
