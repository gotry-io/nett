//! 签名工具与 Hub（design/hub.md 第 3、4 节）：`nett site link` 关联站点；每条命令先取回 Hub 一侧发生的事；
//! 每条修改命令签名之后把站点推给 Hub，等各台机器确认；`nett site status` 显示 Hub 汇总的状态；`nett site
//! add`、`invite` 生成新机器入网和已有的机器接入用的 token。站点目录中的 `hub.json`（`0600`）记着 Hub 的
//! 地址、身份公钥和站点的 token。

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use nett_core::name::NodeName;
use nett_mesh::status::StatusDoc;
use nett_node::http::{Target, call};
use nett_proto::api::{
    LINK_PATH, LinkRequest, LinkResponse, MachineStatus, PushResponse, SITE_PATH, STATUS_PATH,
    StatusResponse, UPDATES_PATH,
};
use nett_proto::token::{Bytes32, Enroll, JoinToken, LinkCode, Secret32};
use nett_site::changes::path_kind;
use nett_site::compose::connections;
use nett_site::dir::SiteDir;
use nett_site::state::State;
use nett_site::updates::Updates;
use nett_trust::anchors::TrustAnchors;
use nett_trust::encoding::Timestamp;
use serde::{Deserialize, Serialize};

use crate::layout::{key_values, table};

pub const SITE_HUB_FILE: &str = "hub.json";
/// 新机器上安装 `nett` 的脚本（design/release.md 第 6 节）：只安装程序，不读 token。
pub const INSTALL_SCRIPT: &str = "curl -fsSL https://nett.gotry.io/install.sh | sh";
/// 入网 token 的有效期（design/auth.md 第 8.1 节）。
pub const ENROLL_VALIDITY_SECS: i64 = 30 * 60;
/// 推送之后等各台机器确认的上限（design/hub.md 第 3.2 节）。
const WAIT_APPLIED: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(300);

/// 站点关联的 Hub。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteHub {
    pub url: String,
    pub hub_key: Bytes32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_fingerprint: Option<Bytes32>,
    /// 站点的 owner token：能推送签名产物，批准不了任何提升权限的变更（硬性规则 3）。
    pub token: String,
}

impl SiteHub {
    pub fn load(dir: &Path) -> anyhow::Result<Option<Self>> {
        let path = dir.join(SITE_HUB_FILE);
        match nett_mesh::config::read_bounded(&path, 64 * 1024)
            .with_context(|| format!("reading {}", path.display()))?
        {
            None => Ok(None),
            Some(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .with_context(|| format!("{} is not valid", path.display())),
        }
    }

    fn save(&self, dir: &Path) -> anyhow::Result<()> {
        let json = serde_json::to_vec_pretty(self)?;
        nett_node::config::write_private(&dir.join(SITE_HUB_FILE), &json)
            .map_err(anyhow::Error::msg)
    }

    fn target(&self) -> Target {
        Target {
            url: self.url.clone(),
            tls_fingerprint: self.tls_fingerprint.map(|f| f.0),
        }
    }
}

/// 命令行的一次 Hub 请求：单线程运行时，请求本身带超时。
fn block_on<F: std::future::Future>(f: F) -> anyhow::Result<F::Output> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    Ok(runtime.block_on(f))
}

fn request<T: for<'de> Deserialize<'de>>(
    target: &Target,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Vec<u8>>,
) -> anyhow::Result<T> {
    let bytes = block_on(call(target, method, path, token, body))??;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("the Hub's answer to {method} {path} is not valid"))
}

fn rules_text(state: &State) -> String {
    state.access_rules.as_ref().map_or_else(
        || "no access rules".to_owned(),
        |r| format!("access rules v{}", r.version),
    )
}

/// `nett site link <关联码>`（design/hub.md 第 3.1 节）。
pub fn link(dir: &Path, code: &str) -> anyhow::Result<()> {
    let code = LinkCode::decode(code)?;
    let site = SiteDir::open(dir)?;
    let state = site.load()?;
    if let Some(old) = SiteHub::load(dir)?
        && old.url != code.url
    {
        println!("Replacing the link to {}.", old.url);
    }
    let target = Target {
        url: code.url.clone(),
        tls_fingerprint: code.tls_fingerprint.map(|f| f.0),
    };
    let body = serde_json::to_vec(&LinkRequest {
        secret: code.secret,
        trust_anchors: serde_json::to_value(&state.trust_anchors)?,
    })?;
    let reply: LinkResponse = request(&target, "POST", LINK_PATH, None, Some(body))?;
    let hub = SiteHub {
        url: code.url,
        hub_key: code.hub_key,
        tls_fingerprint: code.tls_fingerprint,
        token: reply.token,
    };
    hub.save(dir)?;
    push(&hub, &state)?;
    println!(
        "Linked to {}. Pushed {} machines, {}.\nConnect each existing machine with `nett site invite <name>`.",
        hub.url,
        state.machines.len(),
        rules_text(&state)
    );
    Ok(())
}

pub fn push(hub: &SiteHub, state: &State) -> anyhow::Result<u64> {
    let reply: PushResponse = request(
        &hub.target(),
        "PUT",
        SITE_PATH,
        Some(&hub.token),
        Some(serde_json::to_vec(state)?),
    )?;
    Ok(reply.generation)
}

/// Hub 一侧发生、站点还没有取回的事（design/hub.md 第 4 节）。
pub fn fetch_updates(hub: &SiteHub) -> anyhow::Result<Updates> {
    request(&hub.target(), "GET", UPDATES_PATH, Some(&hub.token), None)
}

fn fetch_status(hub: &SiteHub) -> anyhow::Result<StatusResponse> {
    request(&hub.target(), "GET", STATUS_PATH, Some(&hub.token), None)
}

/// 一台机器对 `generation` 的确认。
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Applied,
    Problems(String),
    Rejected(String),
    Pending(String),
    /// 在线，还没有确认。
    Waiting,
    NeverConnected,
    Offline(i64),
}

fn outcome(m: &MachineStatus, generation: u64) -> Outcome {
    let reason = || m.reason.clone().unwrap_or_default();
    if m.applied_generation.is_some_and(|g| g >= generation) {
        return match m.result.as_deref() {
            Some("applied") if m.reason.is_none() => Outcome::Applied,
            Some("applied") => Outcome::Problems(reason()),
            Some("rejected") => Outcome::Rejected(reason()),
            _ => Outcome::Pending(reason()),
        };
    }
    match (m.online, m.last_seen) {
        (true, _) => Outcome::Waiting,
        (false, None) => Outcome::NeverConnected,
        (false, Some(t)) => Outcome::Offline(t),
    }
}

/// 推送之后等各台机器确认，最多 10 秒（design/hub.md 第 3.2 节）。返回 Hub 的状态，以及有没有机器拒绝或
/// 应用之后仍有问题。
pub fn push_and_wait(hub: &SiteHub, state: &State) -> anyhow::Result<(StatusResponse, bool)> {
    let generation = push(hub, state)?;
    let deadline = Instant::now() + WAIT_APPLIED;
    let wanted = |s: &StatusResponse| {
        s.machines
            .iter()
            .filter(|m| has_desired(state, &m.name))
            .map(|m| outcome(m, generation))
            .collect::<Vec<_>>()
    };
    let status = loop {
        let status = fetch_status(hub)?;
        if Instant::now() >= deadline
            || !wanted(&status)
                .iter()
                .any(|o| matches!(o, Outcome::Waiting | Outcome::Pending(_)))
        {
            break status;
        }
        std::thread::sleep(POLL);
    };
    let now = Timestamp::now().unix_seconds();
    let mut applied = 0;
    let mut total = 0;
    let mut notes = Vec::new();
    let mut failed = false;
    for m in status
        .machines
        .iter()
        .filter(|m| has_desired(state, &m.name))
    {
        total += 1;
        match outcome(m, generation) {
            Outcome::Applied => applied += 1,
            Outcome::Problems(reason) => {
                applied += 1;
                failed = true;
                notes.push(format!("{} applied it with problems: {reason}", m.name));
            }
            Outcome::Rejected(reason) => {
                failed = true;
                notes.push(format!("{} rejected it: {reason}", m.name));
            }
            Outcome::Pending(reason) => {
                notes.push(format!("{} has it, not applied yet: {reason}", m.name))
            }
            Outcome::Waiting => notes.push(format!("{} has not answered yet", m.name)),
            Outcome::NeverConnected => notes.push(format!(
                "{} has not connected yet; `nett site invite {}` connects it",
                m.name, m.name
            )),
            Outcome::Offline(t) => notes.push(format!(
                "{} is offline (last seen {}); it gets the change when it connects",
                m.name,
                crate::status::ago(
                    Timestamp::from_unix_seconds(t),
                    Timestamp::from_unix_seconds(now)
                )
            )),
        }
    }
    println!("Pushed. {applied} of {total} machines applied.");
    for note in notes {
        println!("  {note}");
    }
    Ok((status, failed))
}

fn has_desired(state: &State, name: &str) -> bool {
    name.parse::<NodeName>()
        .ok()
        .and_then(|n| state.machines.get(&n))
        .is_some_and(|m| m.policy.is_some())
}

/// 已是成员的机器接入 Hub 的 token（design/hub.md 第 3.5 节）：没有秘密，机器用自己的身份密钥连接。
pub fn join_token(hub: &SiteHub, state: &State, name: &NodeName) -> anyhow::Result<String> {
    let m = state.machine(name)?;
    if m.keys.is_none() {
        bail!("{name} has no keys in the site; joining new machines through the Hub comes later");
    }
    let anchors = TrustAnchors::from_doc(&state.trust_anchors)
        .map_err(|e| anyhow::anyhow!("the site's trust anchors: {e}"))?;
    use base64::Engine as _;
    Ok(JoinToken {
        url: hub.url.clone(),
        hub_key: hub.hub_key,
        node_id: m.node_id.to_string(),
        anchors: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(anchors.fingerprint()),
        tls_fingerprint: hub.tls_fingerprint,
        enroll: None,
    }
    .encode())
}

/// 新机器的入网 token（design/hub.md 第 6 节）：多了入网私钥与过期时间，30 分钟内有效，只能用一次。
pub fn enrollment_token(
    hub: &SiteHub,
    state: &State,
    name: &NodeName,
    seed: &[u8; 32],
) -> anyhow::Result<String> {
    let m = state.machine(name)?;
    let pending = m
        .enrollment
        .as_ref()
        .with_context(|| format!("{name} is not waiting to join"))?;
    let anchors = TrustAnchors::from_doc(&state.trust_anchors)
        .map_err(|e| anyhow::anyhow!("the site's trust anchors: {e}"))?;
    use base64::Engine as _;
    Ok(JoinToken {
        url: hub.url.clone(),
        hub_key: hub.hub_key,
        node_id: m.node_id.to_string(),
        anchors: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(anchors.fingerprint()),
        tls_fingerprint: hub.tls_fingerprint,
        enroll: Some(Enroll {
            key: Secret32::new(*seed),
            expires_at: pending.expires_at,
        }),
    }
    .encode())
}

/// 新机器上要运行的一行（design/hub.md 第 3.3 节）：所有平台相同。
pub fn print_enrollment(name: &NodeName, token: &str) {
    println!(
        "On {name}, run within 30 minutes (once):\n  {INSTALL_SCRIPT} && sudo nett install {token}"
    );
}

/// `nett site status` 接了 Hub 时（design/hub.md 第 3.4 节）。
pub fn status(
    hub: &SiteHub,
    state: &State,
    machine: Option<&NodeName>,
    json: bool,
) -> anyhow::Result<()> {
    let reply = fetch_status(hub)?;
    let now = Timestamp::now();
    if let Some(name) = machine {
        let m = reply
            .machines
            .iter()
            .find(|m| m.name == name.as_str())
            .with_context(|| format!("the Hub has no machine named {name}"))?;
        if json {
            println!("{}", serde_json::to_string_pretty(m)?);
            return Ok(());
        }
        let mut lines = vec![
            ("hub", hub_line(m, now)),
            ("config", config_text(m, reply.generation)),
        ];
        if let Some(public) = public_text(state, name) {
            lines.push(("public", public));
        }
        if let Some(pending) = pending_text(state, name, now) {
            lines.push(("joining", pending));
        }
        print!("{}", key_values(&lines));
        match m.status.clone().map(serde_json::from_value::<StatusDoc>) {
            Some(Ok(doc)) => print!("\n{}", crate::status::overview(&doc, now)),
            Some(Err(_)) => {
                println!("\nIts status is in a format this version cannot read; see --json.")
            }
            None => println!("\nIt has not reported its status yet."),
        }
        return Ok(());
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&reply)?);
        return Ok(());
    }
    print!(
        "{}",
        key_values(&[
            (
                "hub",
                format!("{}, nett-hub {}", reply.url, reply.hub_version)
            ),
            (
                "site",
                format!("{} machines, {}", state.machines.len(), rules_text(state))
            ),
        ])
    );
    let mut rows =
        vec![["MACHINE", "ADDRESS", "HUB", "VERSION", "CONFIG", "PROBLEMS"].map(String::from)];
    for m in &reply.machines {
        let hub_state = if m.online {
            "online".to_owned()
        } else if m.last_seen.is_some() {
            "offline".to_owned()
        } else {
            "never".to_owned()
        };
        let problems = m
            .name
            .parse::<NodeName>()
            .ok()
            .and_then(|n| pending_text(state, &n, now))
            .unwrap_or_else(|| problems_text(m, now));
        rows.push([
            m.name.clone(),
            m.address.clone(),
            hub_state,
            m.nett_version.clone().unwrap_or_else(|| "-".into()),
            config_text(m, reply.generation),
            problems,
        ]);
    }
    println!("\n{}", table(&rows).trim_end());

    let docs: BTreeMap<String, StatusDoc> = reply
        .machines
        .iter()
        .filter_map(|m| {
            let doc = serde_json::from_value(m.status.clone()?).ok()?;
            Some((m.node_id.clone(), doc))
        })
        .collect();
    let mut pairs = Vec::new();
    for (a, b) in connections(state) {
        let (Some(na), Some(nb)) = (state.name_of(&a), state.name_of(&b)) else {
            continue;
        };
        let mut names = [na.to_string(), nb.to_string()];
        let mut ids = [a.to_string(), b.to_string()];
        if names[0] > names[1] {
            names.swap(0, 1);
            ids.swap(0, 1);
        }
        // 两端都报告了时取有测量的一端（mesh.md 第 8.3 节：路径由决定方测量）
        let view = |from: &str, to: &str| {
            docs.get(from)
                .and_then(|d| d.peers.iter().find(|p| p.id.as_str() == to))
        };
        let peer = [view(&ids[0], &ids[1]), view(&ids[1], &ids[0])]
            .into_iter()
            .flatten()
            .max_by_key(|p| p.rtt_ms.is_some());
        let (st, path, rtt) = match peer {
            Some(p) => (
                crate::status::state(p.state).to_owned(),
                p.path
                    .as_ref()
                    .map_or_else(|| "-".to_owned(), crate::status::path_label),
                p.rtt_ms.map_or_else(|| "-".to_owned(), crate::status::ms),
            ),
            None => (
                "-".to_owned(),
                path_kind(state, &a, &b).to_owned(),
                "-".to_owned(),
            ),
        };
        pairs.push([names[0].clone(), names[1].clone(), st, path, rtt]);
    }
    if !pairs.is_empty() {
        pairs.sort();
        let mut rows = vec![["PEER A", "PEER B", "STATE", "PATH", "RTT"].map(String::from)];
        rows.extend(pairs);
        println!("\n{}", table(&rows).trim_end());
    }
    Ok(())
}

fn hub_line(m: &MachineStatus, now: Timestamp) -> String {
    match (m.online, m.last_seen) {
        (true, _) => "online".to_owned(),
        (false, Some(t)) => format!(
            "offline, last seen {}",
            crate::status::ago(Timestamp::from_unix_seconds(t), now)
        ),
        (false, None) => "has not connected yet".to_owned(),
    }
}

fn config_text(m: &MachineStatus, generation: u64) -> String {
    match outcome(m, generation) {
        Outcome::Applied | Outcome::Problems(_) => "current".to_owned(),
        Outcome::Rejected(_) => "rejected".to_owned(),
        Outcome::Pending(_) => "pending".to_owned(),
        Outcome::Waiting | Outcome::Offline(_) => "behind".to_owned(),
        Outcome::NeverConnected => "-".to_owned(),
    }
}

/// 等待入网的机器：token 还有多久过期（design/hub.md 第 3.3 节）。
fn pending_text(state: &State, name: &NodeName, now: Timestamp) -> Option<String> {
    let pending = state.machines.get(name)?.enrollment.as_ref()?;
    let left = pending.expires_at - now.unix_seconds();
    Some(if left > 0 {
        format!(
            "waiting to join; the token expires in {} min",
            (left + 59) / 60
        )
    } else {
        format!("waiting to join; the token expired, `nett site invite {name}` prints a new one")
    })
}

/// `public` 机器的公网地址与来源（design/hub.md 第 5 节）。
fn public_text(state: &State, name: &NodeName) -> Option<String> {
    let m = state.machines.get(name)?;
    let port = m.listen_port(state.listen_port)?;
    let one = |written: Option<String>, learned: Option<(String, String)>| {
        written
            .map(|ip| format!("{ip} (written in the site)"))
            .or_else(|| learned.map(|(ip, from)| format!("{ip} ({from})")))
    };
    let parts: Vec<String> = [
        one(
            m.ipv4.map(|ip| format!("{ip}:{port}")),
            m.learned
                .ipv4
                .map(|l| (format!("{}:{port}", l.ip), l.from.to_string())),
        ),
        one(
            m.ipv6.map(|ip| format!("[{ip}]:{port}")),
            m.learned
                .ipv6
                .map(|l| (format!("[{}]:{port}", l.ip), l.from.to_string())),
        ),
    ]
    .into_iter()
    .flatten()
    .collect();
    Some(if parts.is_empty() {
        "address not known yet; the Hub learns it when the machine connects".to_owned()
    } else {
        parts.join(", ")
    })
}

fn problems_text(m: &MachineStatus, now: Timestamp) -> String {
    let mut out = Vec::new();
    if let Some(reason) = &m.reason {
        out.push(reason.clone());
    }
    if let Some(Ok(doc)) = m.status.clone().map(serde_json::from_value::<StatusDoc>) {
        let n = doc.problems.len();
        if n > 0 && m.reason.is_none() {
            out.push(format!("{n} problem{}", if n == 1 { "" } else { "s" }));
        }
    }
    if !m.online
        && let Some(t) = m.last_seen
    {
        out.push(format!(
            "last seen {}",
            crate::status::ago(Timestamp::from_unix_seconds(t), now)
        ));
    }
    if out.is_empty() {
        "-".to_owned()
    } else {
        out.join("; ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine(
        online: bool,
        last_seen: Option<i64>,
        ack: Option<(u64, &str, Option<&str>)>,
    ) -> MachineStatus {
        MachineStatus {
            name: "nas".into(),
            node_id: "node_01J9Z3K8Q2T7V4X6Y8A0B2C401".into(),
            address: "100.88.0.6".into(),
            online,
            last_seen,
            nett_version: None,
            platform: None,
            applied_generation: ack.map(|a| a.0),
            result: ack.map(|a| a.1.to_owned()),
            reason: ack.and_then(|a| a.2.map(str::to_owned)),
            status: None,
            status_at: None,
        }
    }

    #[test]
    fn acknowledgements_read_as_outcomes() {
        assert_eq!(
            outcome(&machine(true, Some(1), Some((3, "applied", None))), 3),
            Outcome::Applied
        );
        assert_eq!(
            outcome(
                &machine(
                    true,
                    Some(1),
                    Some((3, "applied", Some("member x rejected")))
                ),
                3
            ),
            Outcome::Problems("member x rejected".into())
        );
        assert_eq!(
            outcome(
                &machine(true, Some(1), Some((4, "rejected", Some("older")))),
                3
            ),
            Outcome::Rejected("older".into())
        );
        assert_eq!(
            outcome(&machine(true, Some(1), Some((2, "applied", None))), 3),
            Outcome::Waiting
        );
        assert_eq!(
            outcome(&machine(false, None, None), 3),
            Outcome::NeverConnected
        );
        assert_eq!(
            outcome(&machine(false, Some(9), Some((2, "applied", None))), 3),
            Outcome::Offline(9)
        );
        assert_eq!(
            outcome(
                &machine(true, Some(1), Some((3, "pending", Some("busy")))),
                3
            ),
            Outcome::Pending("busy".into())
        );
    }

    #[test]
    fn site_hub_file_is_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("nett-cli-site-hub-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).expect("dir");
        let hub = SiteHub {
            url: "https://hub.example.com".into(),
            hub_key: Bytes32([3; 32]),
            tls_fingerprint: None,
            token: "nett_tok_00_x".into(),
        };
        hub.save(&dir).expect("save");
        let mode = std::fs::metadata(dir.join(SITE_HUB_FILE))
            .expect("saved")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(
            SiteHub::load(&dir).expect("load").map(|h| h.token),
            Some(hub.token)
        );
    }
}
