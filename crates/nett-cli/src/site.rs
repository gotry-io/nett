//! `nett site`：用户自己电脑上的签名工具（design/local-signing.md）。站点目录（默认 `~/.config/nett`）中有
//! 站点描述 `site.toml`、恢复密钥 `recovery.pk8`（权限 `0600`，只在签名时读取）和签名工具的状态
//! `state.json`；`nett site build` 为每个节点生成 `nodes/<名称>/desired.json`，文件不含私钥。

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail, ensure};
use nett_core::id::NodeId;
use nett_core::name::NodeName;
use nett_core::prefix::IpPrefix;
use nett_mesh::config::{Candidate, DesiredMeshDoc, MeshPrefixes, PathDoc, Reachability};
use nett_trust::admission::{AdmissionMaterial, AdmissionProofDoc, AdmissionProofKind};
use nett_trust::anchors::{TrustAnchors, TrustAnchorsDoc};
use nett_trust::encoding::{Sha256Digest, Timestamp};
use nett_trust::keys::X25519PublicKey;
use nett_trust::payload::{
    AccessRule, AccessRuleSet, AdvertisedRoutes, Artifact, EdgeSources, MeshAddresses, Module,
    NodeAddresses, NodePolicy, PayloadDoc, PortRange, Protocol, Role, RuleAction,
};
use nett_trust::revocation::Revocation;
use nett_trust::signed::SignedPayload;
use nett_trust::signing::{EnrollmentKeyPair, RecoveryKeyPair};
use serde::{Deserialize, Serialize};

const SITE_FILE: &str = "site.toml";
const STATE_FILE: &str = "state.json";
const RECOVERY_FILE: &str = "recovery.pk8";
const NODES_DIR: &str = "nodes";
const DESIRED_FILE: &str = "desired.json";
/// 读入的期望状态文件的上限：256 个节点的准入材料和规则集远小于它（硬性规则 14）。
const MAX_DESIRED_BYTES: u64 = 4 << 20;
const DEFAULT_LISTEN_PORT: u16 = 41820;
const DEFAULT_ORIGIN: &str = "https://nett.invalid";
/// 签名载荷的有效期：节点首次接受自己的节点策略时检查（design/auth.md 第 10.2 节）。
const PAYLOAD_VALIDITY_SECS: i64 = 30 * 24 * 3600;
/// 已签的节点策略离过期不到这么久时，生成时换一个新版本重签。
const RESIGN_BEFORE_SECS: i64 = 7 * 24 * 3600;
/// 一个站点最多的节点数（硬性规则 14）。
const MAX_NODES: usize = 256;

const USAGE: &str = "usage: nett site init [--dir <site>] [--origin https://<console host>]\n       \
nett site build [--dir <site>]\n\
The site directory defaults to $XDG_CONFIG_HOME/nett, or ~/.config/nett when it is not set.";

// ---- 站点描述（design/local-signing.md 第 4 节） ----

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Site {
    mesh: SiteMesh,
    #[serde(rename = "node", default)]
    nodes: Vec<SiteNode>,
    #[serde(rename = "link", default)]
    links: Vec<SiteLink>,
    #[serde(rename = "allow", default)]
    allows: Vec<SiteAllow>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SiteMesh {
    ipv4: IpPrefix,
    ipv6: IpPrefix,
    /// `public` 节点的 WireGuard 端口（design/local-signing.md 第 4 节）。
    #[serde(default = "default_listen_port")]
    listen_port: u16,
}

fn default_listen_port() -> u16 {
    DEFAULT_LISTEN_PORT
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SiteNode {
    name: String,
    reachability: Reachability,
    /// 节点上 `nett mesh keys` 输出的一行：组网公钥与身份公钥。
    keys: String,
    /// `public` 节点的公网地址。
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    edge: Option<SiteEdge>,
    /// `public` 节点自己的 WireGuard 端口，不写时用 `[mesh]` 中的；`dial-only` 节点的端口由系统分配
    /// （design/local-signing.md 第 4 节）。
    listen_port: Option<u16>,
    /// 宣告的网段（design/mesh.md 第 10 节）：节点因此带 `subnet_router` 角色。
    #[serde(default)]
    routes: Vec<IpPrefix>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SiteEdge {
    containers: Vec<IpPrefix>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SiteLink {
    peers: [String; 2],
    candidates: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SiteAllow {
    from: Vec<String>,
    to: Vec<String>,
    #[serde(default)]
    ports: Vec<String>,
}

// ---- 签名工具的状态 ----

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    trust_anchors: TrustAnchorsDoc,
    prefixes: MeshPrefixes,
    /// 下一个分配的地址是组网网段中的第几个。地址不回收（design/mesh.md 第 3 节）。
    next_host: u32,
    nodes: BTreeMap<String, NodeState>,
    revoked: Vec<RevokedNode>,
    access_rules: Option<RulesState>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeState {
    node_id: NodeId,
    mesh: MeshAddresses,
    edge: Option<MeshAddresses>,
    policy_version: u64,
    /// 生成节点策略和准入证明的输入（公钥、角色、Edge）的哈希：不变时沿用原来的签名。
    input: Sha256Digest,
    material: AdmissionMaterial,
    /// 宣告的网段：版本、网段列表的哈希与签名的产物。
    routes: Option<RulesState>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokedNode {
    name: String,
    node_id: NodeId,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesState {
    version: u64,
    input: Sha256Digest,
    signed: SignedPayload,
}

pub fn run(mut parser: lexopt::Parser) -> anyhow::Result<()> {
    use lexopt::ValueExt as _;
    let mut words = Vec::new();
    let (mut dir, mut origin) = (None, None);
    while let Some(arg) = parser.next()? {
        match arg {
            lexopt::Arg::Value(v) => words.push(v.string()?),
            lexopt::Arg::Long("dir") => dir = Some(PathBuf::from(parser.value()?)),
            lexopt::Arg::Long("origin") => origin = Some(parser.value()?.string()?),
            other => return Err(other.unexpected().into()),
        }
    }
    let build_command = match &dir {
        Some(dir) => format!("nett site build --dir {}", dir.display()),
        None => "nett site build".to_owned(),
    };
    let dir = match dir {
        Some(dir) => dir,
        None => default_dir()?,
    };
    match words
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["init"] => {
            init(&dir, origin.as_deref().unwrap_or(DEFAULT_ORIGIN))?;
            println!(
                "Created a site in {}.

recovery.pk8 is the recovery key, the site's only trust anchor. Keep an offline copy:
without it, the site has to be created again and every node enrolled again.

Next:
  1. On each node, create its keys:
       macOS  sudo nett mesh install
       Linux  nett mesh keys --dir <directory>
  2. Add the printed keys line to that node's entry in site.toml.
  3. Run `{build_command}`.",
                dir.display()
            );
            Ok(())
        }
        ["build"] => build(&dir),
        _ => bail!(USAGE),
    }
}

/// 站点目录的默认位置（design/local-signing.md 第 4 节）。
fn default_dir() -> anyhow::Result<PathBuf> {
    site_dir(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    )
}

/// 给定 `XDG_CONFIG_HOME` 与家目录时的默认站点目录。
pub(crate) fn site_dir(xdg: Option<OsString>, home: Option<OsString>) -> anyhow::Result<PathBuf> {
    Ok(config_home(xdg, home)?.join("nett"))
}

/// `$XDG_CONFIG_HOME`，没有设置时 `~/.config`；按 XDG 规范，相对路径的 `XDG_CONFIG_HOME` 不用。
fn config_home(xdg: Option<OsString>, home: Option<OsString>) -> anyhow::Result<PathBuf> {
    if let Some(xdg) = xdg.map(PathBuf::from).filter(|p| p.is_absolute()) {
        return Ok(xdg);
    }
    let home = home
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .context("HOME is not set to an absolute path; give the site directory with --dir")?;
    Ok(home.join(".config"))
}

/// 建立站点目录：恢复密钥、只含它的信任锚清单、随机的 IPv6 组网网段，以及一份站点描述的开头。目录中
/// 有恢复密钥，只有本人能进（`0700`）。
fn init(dir: &Path, origin: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    for name in [SITE_FILE, STATE_FILE, RECOVERY_FILE] {
        ensure!(
            !dir.join(name).exists(),
            "{} already exists; this directory already holds a site",
            dir.join(name).display()
        );
    }
    let rp_id = origin
        .strip_prefix("https://")
        .filter(|h| !h.is_empty() && !h.contains('/'))
        .with_context(|| format!("--origin must look like https://<host>, got {origin}"))?;
    let recovery = RecoveryKeyPair::generate()?;
    let trust_anchors = TrustAnchorsDoc {
        v: 1,
        version: 1,
        rp_id: rp_id.to_owned(),
        origin: origin.to_owned(),
        passkeys: vec![],
        recovery_key: recovery.doc(),
    };
    TrustAnchors::from_doc(&trust_anchors).context("building the trust anchor list")?;
    let prefixes = MeshPrefixes {
        ipv4: "100.88.0.0/16".parse().expect("built-in prefix"),
        ipv6: random_ula()?,
    };
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("setting permissions of {}", dir.display()))?;
    write_new(&dir.join(RECOVERY_FILE), recovery.pkcs8(), 0o600)?;
    let state = State {
        trust_anchors,
        prefixes,
        next_host: 1,
        nodes: BTreeMap::new(),
        revoked: vec![],
        access_rules: None,
    };
    write_new(
        &dir.join(STATE_FILE),
        &serde_json::to_vec_pretty(&state)?,
        0o644,
    )?;
    let site = format!(
        "# nett site. The mesh prefixes cannot change after the site is created.\n[mesh]\nipv4 = \"{}\"\nipv6 = \"{}\"\nlisten_port = {DEFAULT_LISTEN_PORT}\n",
        prefixes.ipv4, prefixes.ipv6
    );
    write_new(&dir.join(SITE_FILE), site.as_bytes(), 0o644)?;
    Ok(())
}

/// `nett site build` 生成的期望状态是不是给这台机器的：其中本节点准入材料的组网公钥必须是 `mesh_public`
/// （`sudo nett mesh install --config`，design/release.md 第 4 节）。拷错了节点的文件时在复制之前就报错。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn check_desired_for(
    bytes: &[u8],
    mesh_public: &X25519PublicKey,
) -> anyhow::Result<NodeId> {
    let desired =
        nett_mesh::config::DesiredMesh::from_json(bytes).context("not a valid desired state")?;
    let mut members = nett_mesh::members::MemberSet::default();
    members.apply(&desired, &mut nett_mesh::event::VecSink::default());
    let me = members
        .get(&desired.node_id)
        .context("the desired state does not admit its own node")?;
    ensure!(
        me.mesh_public_key == *mesh_public,
        "this desired state is for node {} (mesh key {}), not for this machine (mesh key {}); \
         use the desired.json that nett site build wrote for this machine's node",
        desired.node_id,
        me.mesh_public_key,
        mesh_public
    );
    Ok(desired.node_id.clone())
}

/// 站点目录中给这台机器的期望状态（`sudo nett mesh install`，design/release.md 第 4 节）：`nodes/` 下
/// 本节点的组网公钥是 `mesh_public` 的那一份，返回它的路径和内容。还没有 `nodes/` 时返回 `None`。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn find_desired_for(
    site: &Path,
    mesh_public: &X25519PublicKey,
) -> anyhow::Result<Option<(PathBuf, Vec<u8>)>> {
    let nodes = site.join(NODES_DIR);
    let entries = match std::fs::read_dir(&nodes) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", nodes.display())),
    };
    let mut found = Vec::new();
    // 一个站点最多 MAX_NODES 个节点，多出的条目不是签名工具写的
    for entry in entries.take(MAX_NODES) {
        let path = entry
            .with_context(|| format!("reading {}", nodes.display()))?
            .path()
            .join(DESIRED_FILE);
        if let Some(bytes) = read_desired(&path)?
            && check_desired_for(&bytes, mesh_public).is_ok()
        {
            found.push((path, bytes));
        }
    }
    if found.len() > 1 {
        let paths: Vec<String> = found.iter().map(|(p, _)| p.display().to_string()).collect();
        bail!(
            "several desired states are for this machine ({}); give one with --config",
            paths.join(", ")
        );
    }
    Ok(found.pop())
}

/// 读一份期望状态文件：只读普通文件（不读设备、管道），大小有上限。不存在或不是普通文件时返回 `None`。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn read_desired(path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
    use std::io::Read as _;
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() => {}
        Ok(_) => return Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(MAX_DESIRED_BYTES + 1).read_to_end(&mut bytes))
        .with_context(|| format!("reading {}", path.display()))?;
    ensure!(
        bytes.len() as u64 <= MAX_DESIRED_BYTES,
        "{} is larger than {MAX_DESIRED_BYTES} bytes; it is not a desired state",
        path.display()
    );
    Ok(Some(bytes))
}

/// 为站点描述中的每个节点生成期望状态（design/local-signing.md 第 4、5 节）。
fn build(dir: &Path) -> anyhow::Result<()> {
    let site: Site = toml::from_str(
        &std::fs::read_to_string(dir.join(SITE_FILE))
            .with_context(|| format!("reading {}", dir.join(SITE_FILE).display()))?,
    )
    .context("parsing site.toml")?;
    let state_path = dir.join(STATE_FILE);
    let mut state: State = serde_json::from_slice(
        &std::fs::read(&state_path).with_context(|| format!("reading {}", state_path.display()))?,
    )
    .context("parsing state.json")?;
    let pkcs8 = zeroize::Zeroizing::new(
        std::fs::read(dir.join(RECOVERY_FILE))
            .with_context(|| format!("reading {}", dir.join(RECOVERY_FILE).display()))?,
    );
    let recovery = RecoveryKeyPair::from_pkcs8(&pkcs8)?;
    ensure!(
        recovery.doc() == state.trust_anchors.recovery_key,
        "recovery.pk8 does not match the trust anchor list in state.json"
    );
    ensure!(
        site.mesh.ipv4 == state.prefixes.ipv4 && site.mesh.ipv6 == state.prefixes.ipv6,
        "the mesh prefixes in site.toml differ from the ones this site was created with ({}, {})",
        state.prefixes.ipv4,
        state.prefixes.ipv6
    );
    validate(&site)?;
    let expires_at =
        Timestamp::from_unix_seconds(Timestamp::now().unix_seconds() + PAYLOAD_VALIDITY_SECS);

    // 站点描述中不再有的节点：撤销，永久生效，地址不再分配
    let names: BTreeSet<&str> = site.nodes.iter().map(|n| n.name.as_str()).collect();
    let gone: Vec<String> = state
        .nodes
        .keys()
        .filter(|n| !names.contains(n.as_str()))
        .cloned()
        .collect();
    for name in gone {
        if let Some(node) = state.nodes.remove(&name) {
            state.revoked.push(RevokedNode {
                name,
                node_id: node.node_id,
            });
        }
    }

    for node in &site.nodes {
        let (mesh_key, identity_key) =
            parse_keys(&node.keys).with_context(|| format!("node `{}`: keys", node.name))?;
        let (node_id, mesh, old_edge, old, old_routes) = match state.nodes.remove(&node.name) {
            Some(n) => (
                n.node_id,
                n.mesh,
                n.edge,
                Some((n.policy_version, n.input, n.material)),
                n.routes,
            ),
            None => (
                NodeId::from_parts(unix_ms(), random()?),
                allocate(&mut state)?,
                None,
                None,
                None,
            ),
        };
        let edge = match (&node.edge, old_edge) {
            (Some(_), Some(existing)) => Some(existing),
            (Some(_), None) => Some(allocate(&mut state)?),
            (None, _) => None,
        };
        let policy = PolicyInput {
            mesh_key,
            identity_key,
            roles: node
                .edge
                .iter()
                .map(|_| Role::Edge)
                .chain((!node.routes.is_empty()).then_some(Role::SubnetRouter))
                .collect(),
            edge_sources: node.edge.as_ref().map(|e| EdgeSources {
                containers: e.containers.clone(),
            }),
            mesh,
            edge,
        };
        let input = Sha256Digest::of(serde_json::to_string(&policy)?.as_bytes());
        let (policy_version, material) = match old {
            Some((version, old_input, material))
                if old_input == input && !expiring(&material, RESIGN_BEFORE_SECS) =>
            {
                (version, material)
            }
            old => {
                let version = old.map_or(1, |(v, _, _)| v + 1);
                (
                    version,
                    sign_node(&recovery, &node_id, version, policy, expires_at)?,
                )
            }
        };
        let routes = sign_routes(&recovery, &node_id, &node.routes, old_routes, expires_at)?;
        state.nodes.insert(
            node.name.clone(),
            NodeState {
                node_id,
                mesh,
                edge,
                policy_version,
                input,
                material,
                routes,
            },
        );
    }

    let rules = expand_rules(&site, &state)?;
    let input = Sha256Digest::of(serde_json::to_string(&rules)?.as_bytes());
    let changed = state.access_rules.as_ref().is_none_or(|r| r.input != input);
    if changed && !(rules.is_empty() && state.access_rules.is_none()) {
        let version = state.access_rules.as_ref().map_or(1, |r| r.version + 1);
        let payload = PayloadDoc::EnrollmentPolicy {
            v: 1,
            artifacts: vec![Artifact::AccessRuleSet(AccessRuleSet { version, rules })],
            expires_at,
        }
        .to_canonical()?;
        state.access_rules = Some(RulesState {
            version,
            input,
            signed: recovery.sign(payload)?,
        });
    }

    let out = dir.join(NODES_DIR);
    let revocations: Vec<Revocation> = state
        .revoked
        .iter()
        .map(|r| Revocation::Node {
            node_id: r.node_id.clone(),
        })
        .collect();
    let members: Vec<AdmissionMaterial> =
        state.nodes.values().map(|n| n.material.clone()).collect();
    let names: BTreeMap<NodeId, NodeName> = site
        .nodes
        .iter()
        .map(|n| Ok((state.nodes[&n.name].node_id.clone(), n.name.parse()?)))
        .collect::<anyhow::Result<_>>()?;
    for node in &site.nodes {
        let me = &state.nodes[&node.name];
        let doc = DesiredMeshDoc {
            node_id: me.node_id.clone(),
            reachability: node.reachability,
            listen_port: match node.reachability {
                Reachability::Public => Some(node.listen_port.unwrap_or(site.mesh.listen_port)),
                Reachability::DialOnly => None,
            },
            prefixes: state.prefixes,
            trust_anchors: state.trust_anchors.clone(),
            members: members.clone(),
            revocations: revocations.clone(),
            paths: paths(&site, &state, node)?,
            access_rules: state.access_rules.as_ref().map(|r| r.signed.clone()),
            advertised_routes: state
                .nodes
                .values()
                .filter_map(|n| n.routes.as_ref().map(|r| r.signed.clone()))
                .collect(),
            names: names.clone(),
        };
        // 生成的期望状态必须能被组网进程接受
        nett_mesh::config::DesiredMesh::from_doc(doc.clone())
            .with_context(|| format!("node `{}`: generated desired state", node.name))?;
        let node_dir = out.join(&node.name);
        std::fs::create_dir_all(&node_dir)
            .with_context(|| format!("creating {}", node_dir.display()))?;
        std::fs::write(
            node_dir.join(DESIRED_FILE),
            serde_json::to_vec_pretty(&doc)?,
        )
        .with_context(|| format!("writing {}", node_dir.display()))?;
    }
    // 先写各节点的文件，再更新状态：中途失败时下一次重新生成，版本号不会白白增加两次
    let tmp = state_path.with_extension("json.new");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&state)?)
        .with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, &state_path)
        .with_context(|| format!("updating {}", state_path.display()))?;
    println!(
        "Built the desired state for {} in {}/<node>/desired.json.
The files contain no private keys. To apply one on its node:
  Linux      copy it to /etc/nett/desired.json, then run `systemctl reload nett-mesh`
  macOS      sudo nett mesh install --config <desired.json>
  container  replace the mounted desired.json, then run `docker kill -s HUP <container>`",
        match site.nodes.len() {
            1 => "1 node".to_owned(),
            n => format!("{n} nodes"),
        },
        out.display()
    );
    Ok(())
}

fn validate(site: &Site) -> anyhow::Result<()> {
    ensure!(
        site.nodes.len() <= MAX_NODES,
        "a site holds at most {MAX_NODES} nodes"
    );
    let mut names = BTreeSet::new();
    for node in &site.nodes {
        node.name.parse::<NodeName>()?;
        ensure!(
            names.insert(node.name.as_str()),
            "duplicate node `{}`",
            node.name
        );
        ensure!(
            node.reachability != Reachability::Public || node.ipv4.is_some() || node.ipv6.is_some(),
            "public node `{}` needs ipv4 or ipv6",
            node.name
        );
        // 没有人按地址连 dial-only 节点，端口由系统分配；能被连入的节点写成 public
        ensure!(
            node.reachability != Reachability::DialOnly
                || (node.ipv4.is_none() && node.ipv6.is_none() && node.listen_port.is_none()),
            "dial-only node `{}` takes no ipv4, ipv6 or listen_port: nobody dials it and the system \
             picks its WireGuard port; a node others connect to is public",
            node.name
        );
        if let Some(edge) = &node.edge {
            ensure!(
                !edge.containers.is_empty(),
                "node `{}`: edge needs the Edge container's address",
                node.name
            );
        }
        let overlaps = |a: &IpPrefix, b: &IpPrefix| a.covers(b) || b.covers(a);
        for route in &node.routes {
            ensure!(
                !overlaps(route, &site.mesh.ipv4) && !overlaps(route, &site.mesh.ipv6),
                "node `{}`: route {route} overlaps the mesh prefixes",
                node.name
            );
            if let Some(other) = site
                .nodes
                .iter()
                .filter(|o| o.name != node.name)
                .find(|o| o.routes.iter().any(|r| overlaps(r, route)))
            {
                bail!(
                    "node `{}`: route {route} overlaps a route of `{}`",
                    node.name,
                    other.name
                );
            }
        }
    }
    for link in &site.links {
        for peer in &link.peers {
            ensure!(
                names.contains(peer.as_str()),
                "link names unknown node `{peer}`"
            );
        }
        ensure!(
            link.peers[0] != link.peers[1],
            "a link needs two different nodes"
        );
        for c in &link.candidates {
            ensure!(
                matches!(c.as_str(), "direct" | "direct6" | "punch"),
                "candidate `{c}` is not supported by nett site yet (direct, direct6, punch)"
            );
        }
    }
    for allow in &site.allows {
        ensure!(
            !allow.from.is_empty() && !allow.to.is_empty(),
            "allow needs `from` and `to`"
        );
        for selector in allow.from.iter().chain(&allow.to) {
            let (name, kind) = split_selector(selector);
            let node = site
                .nodes
                .iter()
                .find(|n| n.name == name)
                .with_context(|| format!("allow names unknown node `{name}`"))?;
            ensure!(
                kind != Selector::Edge || node.edge.is_some(),
                "allow names `{selector}` but `{name}` runs no Edge"
            );
            ensure!(
                kind != Selector::Routes || !node.routes.is_empty(),
                "allow names `{selector}` but `{name}` advertises no routes"
            );
        }
        for p in &allow.ports {
            parse_ports(p)?;
        }
    }
    Ok(())
}

/// 生成节点策略和准入证明的输入；它的哈希不变时沿用原来的签名。
#[derive(Serialize)]
struct PolicyInput {
    mesh_key: X25519PublicKey,
    identity_key: X25519PublicKey,
    roles: Vec<Role>,
    edge_sources: Option<EdgeSources>,
    mesh: MeshAddresses,
    edge: Option<MeshAddresses>,
}

/// 用恢复密钥签节点策略，用一把只用这一次的入网密钥签准入证明（design/local-signing.md 第 3 节）。
fn sign_node(
    recovery: &RecoveryKeyPair,
    node_id: &NodeId,
    version: u64,
    input: PolicyInput,
    expires_at: Timestamp,
) -> anyhow::Result<AdmissionMaterial> {
    let enrollment = EnrollmentKeyPair::generate()?;
    let policy = NodePolicy {
        node_id: node_id.clone(),
        policy_version: version,
        modules: vec![Module::Mesh],
        roles: input.roles,
        edge: input.edge_sources,
        addresses: NodeAddresses {
            mesh: input.mesh,
            edge: input.edge,
        },
        enrollment_public_key: enrollment.public_key(),
    };
    let payload = PayloadDoc::EnrollmentPolicy {
        v: 1,
        artifacts: vec![Artifact::NodePolicy(policy)],
        expires_at,
    }
    .to_canonical()?;
    Ok(AdmissionMaterial {
        policy: recovery.sign(payload)?,
        proof: enrollment.sign_proof(&AdmissionProofDoc {
            v: 1,
            kind: AdmissionProofKind::AdmissionProof,
            node_id: node_id.clone(),
            identity_public_key: input.identity_key,
            mesh_public_key: input.mesh_key,
        })?,
    })
}

/// 已签的节点策略在 `within` 秒内过期（或读不出过期时间）。
fn expiring(material: &AdmissionMaterial, within: i64) -> bool {
    nett_trust::payload::Payload::parse(&material.policy.payload).map_or(true, |p| {
        p.expires_at().unix_seconds() < Timestamp::now().unix_seconds() + within
    })
}

/// 宣告的网段：变了就换一个新版本重签；没有网段时不签（节点策略同时去掉 `subnet_router` 角色，
/// 成员随之作废它已生效的宣告）。
fn sign_routes(
    recovery: &RecoveryKeyPair,
    node_id: &NodeId,
    routes: &[IpPrefix],
    old: Option<RulesState>,
    expires_at: Timestamp,
) -> anyhow::Result<Option<RulesState>> {
    if routes.is_empty() {
        return Ok(None);
    }
    let input = Sha256Digest::of(serde_json::to_string(routes)?.as_bytes());
    if let Some(old) = old.as_ref().filter(|o| o.input == input) {
        return Ok(Some(RulesState {
            version: old.version,
            input,
            signed: old.signed.clone(),
        }));
    }
    let version = old.map_or(1, |o| o.version + 1);
    let payload = PayloadDoc::EnrollmentPolicy {
        v: 1,
        artifacts: vec![Artifact::AdvertisedRoutes(AdvertisedRoutes {
            node_id: node_id.clone(),
            version,
            routes: routes.to_vec(),
        })],
        expires_at,
    }
    .to_canonical()?;
    Ok(Some(RulesState {
        version,
        input,
        signed: recovery.sign(payload)?,
    }))
}

/// 节点上 `nett mesh keys` 输出的一行：`<组网公钥> <身份公钥>`。
fn parse_keys(s: &str) -> anyhow::Result<(X25519PublicKey, X25519PublicKey)> {
    let mut parts = s.split_whitespace();
    let (Some(mesh), Some(identity), None) = (parts.next(), parts.next(), parts.next()) else {
        bail!("expected two public keys separated by a space, as printed by `nett mesh keys`");
    };
    Ok((mesh.parse()?, identity.parse()?))
}

/// 分配下一对地址：组网网段中的第 `next_host` 个。
fn allocate(state: &mut State) -> anyhow::Result<MeshAddresses> {
    let (IpAddr::V4(v4), IpAddr::V6(v6)) = (state.prefixes.ipv4.addr(), state.prefixes.ipv6.addr())
    else {
        bail!("mesh prefixes must be one IPv4 and one IPv6 prefix");
    };
    let n = state.next_host;
    let addrs = MeshAddresses {
        ipv4: Ipv4Addr::from(u32::from(v4) + n),
        ipv6: Ipv6Addr::from(u128::from(v6) + u128::from(n)),
    };
    ensure!(
        state.prefixes.ipv4.contains(addrs.ipv4.into()) && !addrs.ipv4.is_broadcast(),
        "the IPv4 mesh prefix {} has no addresses left",
        state.prefixes.ipv4
    );
    state.next_host = n.checked_add(1).context("address counter overflow")?;
    Ok(addrs)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Selector {
    Mesh,
    Edge,
    Routes,
}

/// `<节点>`、`<节点>.edge`、`<节点>.routes`。
fn split_selector(s: &str) -> (&str, Selector) {
    if let Some(name) = s.strip_suffix(".edge") {
        (name, Selector::Edge)
    } else if let Some(name) = s.strip_suffix(".routes") {
        (name, Selector::Routes)
    } else {
        (s, Selector::Mesh)
    }
}

/// 访问规则展开成网段（design/mesh.md 第 12 节）：节点名是它的组网地址，`<节点>.edge` 是它的 Edge 专用地址，
/// `<节点>.routes` 是它宣告的网段。
fn expand_rules(site: &Site, state: &State) -> anyhow::Result<Vec<AccessRule>> {
    let prefixes = |selector: &str| -> anyhow::Result<Vec<IpPrefix>> {
        let (name, kind) = split_selector(selector);
        let host =
            |a: MeshAddresses| vec![IpPrefix::host(a.ipv4.into()), IpPrefix::host(a.ipv6.into())];
        Ok(match kind {
            Selector::Mesh => host(state.nodes[name].mesh),
            Selector::Edge => host(state.nodes[name].edge.context("edge addresses")?),
            Selector::Routes => site
                .nodes
                .iter()
                .find(|n| n.name == name)
                .context("node")?
                .routes
                .clone(),
        })
    };
    let mut rules = Vec::new();
    for allow in &site.allows {
        let mut from = Vec::new();
        for s in &allow.from {
            from.extend(prefixes(s)?);
        }
        let mut to = Vec::new();
        for s in &allow.to {
            to.extend(prefixes(s)?);
        }
        rules.push(AccessRule {
            action: RuleAction::Allow,
            from,
            to,
            ports: allow
                .ports
                .iter()
                .map(|p| parse_ports(p))
                .collect::<anyhow::Result<_>>()?,
        });
    }
    Ok(rules)
}

/// 本机到各对端的候选路径：对端是 `public` 时直连它的公网地址；对端是 `dial-only` 时没有直连候选，
/// 由它主动连过来（WireGuard 的漫游）。
fn paths(site: &Site, state: &State, node: &SiteNode) -> anyhow::Result<Vec<PathDoc>> {
    let mut out = Vec::new();
    for link in &site.links {
        let other = if link.peers[0] == node.name {
            &link.peers[1]
        } else if link.peers[1] == node.name {
            &link.peers[0]
        } else {
            continue;
        };
        let peer = site
            .nodes
            .iter()
            .find(|n| &n.name == other)
            .context("peer")?;
        let port = peer.listen_port.unwrap_or(site.mesh.listen_port);
        let mut candidates = Vec::new();
        for c in &link.candidates {
            match c.as_str() {
                "punch" => candidates.push(Candidate::Punch),
                "direct" => {
                    if let Some(ip) = peer.ipv4 {
                        candidates.push(Candidate::Direct {
                            endpoint: SocketAddr::new(ip.into(), port),
                        });
                    }
                }
                "direct6" => {
                    if let Some(ip) = peer.ipv6 {
                        candidates.push(Candidate::Direct {
                            endpoint: SocketAddr::new(ip.into(), port),
                        });
                    }
                }
                _ => bail!("candidate `{c}`"),
            }
        }
        out.push(PathDoc {
            peer: state.nodes[other].node_id.clone(),
            peer_reachability: peer.reachability,
            candidates,
        });
    }
    Ok(out)
}

/// `8686/tcp`、`1000-2000/udp`。
fn parse_ports(s: &str) -> anyhow::Result<PortRange> {
    let (range, proto) = s
        .split_once('/')
        .with_context(|| format!("port `{s}` must be <port>[-<port>]/<tcp|udp>"))?;
    let protocol = match proto {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        _ => bail!("port `{s}`: protocol must be tcp or udp"),
    };
    let (first, last) = range.split_once('-').unwrap_or((range, range));
    let (first, last): (u16, u16) = (first.parse()?, last.parse()?);
    ensure!(
        first >= 1 && first <= last,
        "port `{s}`: need 1 <= first <= last"
    );
    Ok(PortRange {
        protocol,
        first,
        last,
    })
}

fn random_ula() -> anyhow::Result<IpPrefix> {
    let r = random()?;
    let addr = Ipv6Addr::new(
        0xfd00 | u16::from(r[0]),
        u16::from_be_bytes([r[1], r[2]]),
        u16::from_be_bytes([r[3], r[4]]),
        0,
        0,
        0,
        0,
        0,
    );
    IpPrefix::new(addr.into(), 48).context("ULA prefix")
}

fn random() -> anyhow::Result<[u8; 10]> {
    use ring::rand::{SecureRandom as _, SystemRandom};
    let mut bytes = [0u8; 10];
    SystemRandom::new()
        .fill(&mut bytes)
        .ok()
        .context("the system random number generator failed")?;
    Ok(bytes)
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// 写一个新文件，已存在时报错。
fn write_new(path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::File::options();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nett_mesh::access::AccessRules;
    use nett_mesh::config::DesiredMesh;
    use nett_mesh::event::VecSink;
    use nett_mesh::key::PrivateKey;
    use nett_mesh::members::MemberSet;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nett-site-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        dir
    }

    fn keys() -> String {
        let (mesh, identity) = (
            PrivateKey::generate().expect("key"),
            PrivateKey::generate().expect("key"),
        );
        format!("{} {}", mesh.public_key(), identity.public_key())
    }

    fn write_site(dir: &Path, nodes: &str) {
        let head: String = std::fs::read_to_string(dir.join(SITE_FILE))
            .expect("site")
            .lines()
            .take(5)
            .map(|l| format!("{l}\n"))
            .collect();
        std::fs::write(dir.join(SITE_FILE), format!("{head}{nodes}")).expect("write site");
    }

    fn state(dir: &Path) -> State {
        serde_json::from_slice(&std::fs::read(dir.join(STATE_FILE)).expect("state")).expect("parse")
    }

    #[test]
    fn site_directory_defaults_to_the_xdg_config_home() {
        let os = |s: &str| Some(OsString::from(s));
        assert_eq!(
            config_home(os("/x/config"), os("/home/u")).expect("xdg"),
            Path::new("/x/config")
        );
        assert_eq!(
            config_home(None, os("/home/u")).expect("home"),
            Path::new("/home/u/.config")
        );
        // 相对路径的 XDG_CONFIG_HOME 不用（XDG 规范）
        assert_eq!(
            config_home(os("relative"), os("/home/u")).expect("home"),
            Path::new("/home/u/.config")
        );
        assert!(config_home(None, None).is_err());
    }

    #[test]
    fn init_keeps_the_site_directory_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = temp_dir("private");
        init(&dir, DEFAULT_ORIGIN).expect("init");
        let mode = |p: &Path| std::fs::metadata(p).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join(RECOVERY_FILE)), 0o600);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn desired_state_must_belong_to_this_machine() {
        let dir = temp_dir("owner");
        init(&dir, DEFAULT_ORIGIN).expect("init");
        let (ka, kb) = (keys(), keys());
        write_site(
            &dir,
            &format!(
                "[[node]]\nname = \"vps\"\nreachability = \"public\"\nipv4 = \"203.0.113.10\"\nkeys = \"{ka}\"\n\
                 [[node]]\nname = \"mac\"\nreachability = \"dial-only\"\nkeys = \"{kb}\"\n\
                 [[link]]\npeers = [\"vps\", \"mac\"]\ncandidates = [\"direct\"]\n"
            ),
        );
        build(&dir).expect("build");
        let mesh_key = |k: &str| -> X25519PublicKey {
            k.split_whitespace()
                .next()
                .expect("mesh key")
                .parse()
                .expect("key")
        };
        let mac = std::fs::read(dir.join(NODES_DIR).join("mac").join("desired.json")).expect("out");
        assert_eq!(
            check_desired_for(&mac, &mesh_key(&kb)).expect("mine"),
            state(&dir).nodes["mac"].node_id
        );
        // 另一个节点的文件、不是期望状态的文件都在复制之前被拒绝
        assert!(check_desired_for(&mac, &mesh_key(&ka)).is_err());
        assert!(check_desired_for(b"{}", &mesh_key(&kb)).is_err());

        // install 不带 --config 时在站点目录中按组网公钥找到本机的那一份，其他条目跳过
        std::fs::create_dir_all(dir.join(NODES_DIR).join("stray").join(DESIRED_FILE)).expect("dir");
        std::fs::create_dir_all(dir.join(NODES_DIR).join("junk")).expect("dir");
        std::fs::write(dir.join(NODES_DIR).join("junk").join(DESIRED_FILE), b"{}").expect("junk");
        let (path, bytes) = find_desired_for(&dir, &mesh_key(&kb))
            .expect("search")
            .expect("found");
        assert_eq!(path, dir.join(NODES_DIR).join("mac").join(DESIRED_FILE));
        assert_eq!(bytes, mac);
        let other = keys();
        assert!(
            find_desired_for(&dir, &mesh_key(&other))
                .expect("search")
                .is_none()
        );
        // 两份都是给本机的（拷贝出来的副本）：不猜，要求 --config
        std::fs::create_dir_all(dir.join(NODES_DIR).join("copy")).expect("dir");
        std::fs::write(dir.join(NODES_DIR).join("copy").join(DESIRED_FILE), &mac).expect("copy");
        assert!(find_desired_for(&dir, &mesh_key(&kb)).is_err());
        // 还没有生成过：没有 nodes/
        assert!(
            find_desired_for(&dir.join("absent"), &mesh_key(&kb))
                .expect("search")
                .is_none()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    fn desired(dir: &Path, node: &str) -> DesiredMesh {
        DesiredMesh::from_json(
            &std::fs::read(dir.join(NODES_DIR).join(node).join("desired.json")).expect("desired"),
        )
        .expect("valid desired state")
    }

    #[test]
    fn public_nodes_have_fixed_ports_and_dial_only_nodes_automatic_ones() {
        let dir = temp_dir("port");
        init(&dir, DEFAULT_ORIGIN).expect("init");
        let nodes = format!(
            "[[node]]\nname = \"vps\"\nreachability = \"public\"\nipv4 = \"203.0.113.10\"\nlisten_port = 51000\nkeys = \"{}\"\n\
             [[node]]\nname = \"vps2\"\nreachability = \"public\"\nipv4 = \"203.0.113.11\"\nkeys = \"{}\"\n\
             [[node]]\nname = \"app\"\nreachability = \"dial-only\"\nkeys = \"{}\"\n\
             [[node]]\nname = \"mac\"\nreachability = \"dial-only\"\nkeys = \"{}\"\n\
             [[link]]\npeers = [\"vps\", \"app\"]\ncandidates = [\"direct\"]\n\
             [[link]]\npeers = [\"vps2\", \"app\"]\ncandidates = [\"direct\"]\n\
             [[link]]\npeers = [\"vps\", \"mac\"]\ncandidates = [\"direct\"]\n",
            keys(),
            keys(),
            keys(),
            keys()
        );
        write_site(&dir, &nodes);
        build(&dir).expect("build");
        assert_eq!(desired(&dir, "vps").listen_port, Some(51000));
        assert_eq!(desired(&dir, "vps2").listen_port, Some(DEFAULT_LISTEN_PORT));
        // dial-only：系统分配，同一台主机上的几个成员不争用端口
        assert_eq!(desired(&dir, "app").listen_port, None);
        assert_eq!(desired(&dir, "mac").listen_port, None);
        let id = |name: &str| state(&dir).nodes[name].node_id.clone();
        let direct = |endpoint: &str| {
            vec![Candidate::Direct {
                endpoint: endpoint.parse().expect("endpoint"),
            }]
        };
        let (app, mac) = (desired(&dir, "app"), desired(&dir, "mac"));
        assert_eq!(
            app.paths[&id("vps")].candidates,
            direct("203.0.113.10:51000")
        );
        assert_eq!(
            app.paths[&id("vps2")].candidates,
            direct("203.0.113.11:41820")
        );
        assert_eq!(
            mac.paths[&id("vps")].candidates,
            direct("203.0.113.10:51000")
        );

        let refused = |nodes: String| {
            format!("{:#}", {
                write_site(&dir, &nodes);
                build(&dir).expect_err("refused")
            })
        };
        // 组网进程自己用的端口在生成时就拒绝，不等到节点上绑定失败
        let err = refused(nodes.replace("51000", "41821"));
        assert!(err.contains("node `vps`") && err.contains("41821"), "{err}");
        // dial-only 节点不写端口和地址：没有人按地址连它
        for extra in [
            "listen_port = 41822",
            "ipv4 = \"203.0.113.20\"",
            "ipv6 = \"2001:db8::20\"",
        ] {
            let err = refused(nodes.replace(
                "name = \"mac\"\nreachability = \"dial-only\"\n",
                &format!("name = \"mac\"\nreachability = \"dial-only\"\n{extra}\n"),
            ));
            assert!(err.contains("dial-only node `mac`"), "{extra}: {err}");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn builds_admissible_state_and_keeps_signatures_until_inputs_change() {
        let dir = temp_dir("build");
        init(&dir, DEFAULT_ORIGIN).expect("init");
        assert!(
            init(&dir, DEFAULT_ORIGIN).is_err(),
            "init must not overwrite a site"
        );
        let (ka, kb, kc) = (keys(), keys(), keys());
        let nodes = |edge: bool, with_c: bool| {
            let mut s = format!(
                "[[node]]\nname = \"vps\"\nreachability = \"public\"\nipv4 = \"203.0.113.10\"\nkeys = \"{ka}\"\n{}\
                 [[node]]\nname = \"app\"\nreachability = \"dial-only\"\nkeys = \"{kb}\"\n\
                 [[link]]\npeers = [\"vps\", \"app\"]\ncandidates = [\"direct\"]\n",
                if edge {
                    "edge = { containers = [\"172.17.0.2/32\"] }\n"
                } else {
                    ""
                }
            );
            if edge {
                s.push_str(
                    "[[allow]]\nfrom = [\"vps.edge\"]\nto = [\"app\"]\nports = [\"8686/tcp\"]\n",
                );
            }
            if with_c {
                s.push_str(&format!(
                    "[[node]]\nname = \"c\"\nreachability = \"dial-only\"\nkeys = \"{kc}\"\n"
                ));
            }
            s
        };
        write_site(&dir, &nodes(true, true));
        build(&dir).expect("build");
        let first =
            std::fs::read(dir.join(NODES_DIR).join("app").join("desired.json")).expect("out");
        let s1 = state(&dir);
        assert_eq!(s1.nodes["vps"].policy_version, 1);
        assert_eq!(s1.access_rules.as_ref().map(|r| r.version), Some(1));

        // 生成的期望状态通过组网进程的准入与规则集验证
        let app = desired(&dir, "app");
        let mut members = MemberSet::default();
        let mut events = VecSink::default();
        members.apply(&app, &mut events);
        assert_eq!(members.members().len(), 3, "{:?}", events.0);
        let vps = members.get(&s1.nodes["vps"].node_id).expect("vps admitted");
        assert_eq!(vps.edge.as_ref().map(|e| e.addresses), s1.nodes["vps"].edge);
        let mut rules = AccessRules::default();
        rules.apply(&app, &mut events);
        assert_eq!(rules.version(), Some(1), "{:?}", events.0);
        // dial-only 一端有直连候选，public 一端没有（等对方连过来）
        let to_vps = app.paths.get(&s1.nodes["vps"].node_id).expect("path");
        assert_eq!(to_vps.candidates.len(), 1);
        let vps_side = desired(&dir, "vps");
        assert!(
            vps_side.paths[&s1.nodes["app"].node_id]
                .candidates
                .is_empty()
        );

        // 输入不变：同样的签名与文件
        build(&dir).expect("rebuild");
        let again =
            std::fs::read(dir.join(NODES_DIR).join("app").join("desired.json")).expect("out");
        assert_eq!(first, again);

        // 去掉一个节点：撤销，地址不再分配；去掉 Edge：版本加一，规则集换成空的新版本
        write_site(&dir, &nodes(false, false));
        build(&dir).expect("build without c");
        let s2 = state(&dir);
        assert_eq!(s2.revoked.len(), 1);
        assert_eq!(s2.revoked[0].node_id, s1.nodes["c"].node_id);
        assert_eq!(s2.nodes["vps"].policy_version, 2);
        assert_eq!(s2.nodes["vps"].edge, None);
        assert_eq!(s2.access_rules.as_ref().map(|r| r.version), Some(2));
        assert_eq!(s2.next_host, s1.next_host);
        let app = desired(&dir, "app");
        assert_eq!(app.revocations.len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn signs_and_expands_advertised_routes() {
        use nett_mesh::routes::Routes;
        let dir = temp_dir("routes");
        init(&dir, DEFAULT_ORIGIN).expect("init");
        let (ka, kb) = (keys(), keys());
        let site = |routes: &str| {
            format!(
                "[[node]]\nname = \"vps\"\nreachability = \"public\"\nipv4 = \"203.0.113.10\"\nkeys = \"{ka}\"\n\
                 edge = {{ containers = [\"172.17.0.2/32\"] }}\n\
                 [[node]]\nname = \"app\"\nreachability = \"dial-only\"\nkeys = \"{kb}\"\n{routes}\
                 [[link]]\npeers = [\"vps\", \"app\"]\ncandidates = [\"direct\"]\n"
            )
        };
        write_site(
            &dir,
            &format!(
                "{}[[allow]]\nfrom = [\"vps.edge\"]\nto = [\"app.routes\"]\nports = [\"8686/tcp\"]\n",
                site("routes = [\"172.30.0.10/32\"]\n")
            ),
        );
        build(&dir).expect("build");
        let s1 = state(&dir);
        assert_eq!(s1.nodes["app"].routes.as_ref().map(|r| r.version), Some(1));
        let vps = desired(&dir, "vps");
        assert_eq!(vps.advertised_routes.len(), 1);
        let mut members = MemberSet::default();
        members.apply(&vps, &mut VecSink::default());
        let mut routes = Routes::default();
        let mut events = VecSink::default();
        routes.apply(&vps, members.members(), &mut events);
        let app_id = &s1.nodes["app"].node_id;
        assert_eq!(
            routes.of(app_id),
            ["172.30.0.10/32".parse::<IpPrefix>().expect("prefix")],
            "{:?}",
            events.0
        );
        // 规则展开成宣告的网段
        let mut rules = AccessRules::default();
        rules.apply(&vps, &mut events);
        assert_eq!(rules.version(), Some(1));
        // 去掉 routes：不再宣告，节点策略去掉 subnet_router 角色，成员作废已生效的宣告
        write_site(&dir, &site(""));
        build(&dir).expect("rebuild");
        let s2 = state(&dir);
        assert!(s2.nodes["app"].routes.is_none());
        assert_eq!(
            s2.nodes["app"].policy_version,
            s1.nodes["app"].policy_version + 1
        );
        let vps = desired(&dir, "vps");
        assert!(vps.advertised_routes.is_empty());
        members.apply(&vps, &mut VecSink::default());
        routes.apply(&vps, members.members(), &mut VecSink::default());
        assert!(routes.of(app_id).is_empty());
        // 不存在的宣告
        write_site(
            &dir,
            &format!(
                "{}[[allow]]\nfrom = [\"vps\"]\nto = [\"app.routes\"]\n",
                site("")
            ),
        );
        assert!(build(&dir).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn re_signs_policies_close_to_expiry() {
        let dir = temp_dir("expiry");
        init(&dir, DEFAULT_ORIGIN).expect("init");
        write_site(
            &dir,
            &format!(
                "[[node]]\nname = \"a\"\nreachability = \"dial-only\"\nkeys = \"{}\"\n",
                keys()
            ),
        );
        build(&dir).expect("build");
        let material = &state(&dir).nodes["a"].material;
        assert!(!expiring(material, RESIGN_BEFORE_SECS));
        assert!(expiring(material, PAYLOAD_VALIDITY_SECS + 60));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_inconsistent_sites() {
        let dir = temp_dir("bad");
        init(&dir, DEFAULT_ORIGIN).expect("init");
        let k = keys();
        for (case, body) in [
            (
                "public without address",
                format!("[[node]]\nname = \"a\"\nreachability = \"public\"\nkeys = \"{k}\"\n"),
            ),
            (
                "unknown allow target",
                format!(
                    "[[node]]\nname = \"a\"\nreachability = \"dial-only\"\nkeys = \"{k}\"\n[[allow]]\nfrom = [\"a\"]\nto = [\"b\"]\n"
                ),
            ),
            (
                "edge selector without edge",
                format!(
                    "[[node]]\nname = \"a\"\nreachability = \"dial-only\"\nkeys = \"{k}\"\n[[allow]]\nfrom = [\"a.edge\"]\nto = [\"a\"]\n"
                ),
            ),
            (
                "relay candidates not yet",
                format!(
                    "[[node]]\nname = \"a\"\nreachability = \"dial-only\"\nkeys = \"{k}\"\n[[node]]\nname = \"b\"\nreachability = \"dial-only\"\nkeys = \"{k}\"\n[[link]]\npeers = [\"a\", \"b\"]\ncandidates = [\"relay:a\"]\n"
                ),
            ),
            (
                "bad keys",
                "[[node]]\nname = \"a\"\nreachability = \"dial-only\"\nkeys = \"x\"\n".to_owned(),
            ),
        ] {
            write_site(&dir, &body);
            assert!(build(&dir).is_err(), "{case}");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ports_and_keys_parse_strictly() {
        assert_eq!(
            parse_ports("1000-2000/udp").expect("range"),
            PortRange {
                protocol: Protocol::Udp,
                first: 1000,
                last: 2000
            }
        );
        for bad in ["8686", "0/tcp", "9-8/tcp", "80/icmp"] {
            assert!(parse_ports(bad).is_err(), "{bad}");
        }
        assert!(parse_keys(&keys()).is_ok());
        assert!(parse_keys("one").is_err());
    }
}
