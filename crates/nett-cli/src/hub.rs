//! The signing tool and the Hub (design/hub.md sections 3 and 4): `nett site link` links the
//! site; every command first fetches what happened on the Hub side; every modifying command pushes
//! the site to the Hub after signing and waits for the machines to confirm; `nett site status`
//! shows the status the Hub aggregates; `nett site add` and `invite` generate the tokens for a new
//! machine to join and for an existing machine to attach. `hub.json` (`0600`) in the site directory
//! records the Hub's address, identity public key and the site's token.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use nett_core::id::NodeId;
use nett_core::name::NodeName;
use nett_mesh::status::{CandidateStateDoc, PathKindDoc, PeerState, StatusDoc};
use nett_node::http::{Target, call};
use nett_proto::api::{
    BackupStatus, EVENTS_PATH, Event, LINK_PATH, LinkRequest, LinkResponse, MachineStatus,
    PushResponse, SITE_PATH, STATUS_PATH, StatusResponse, UPDATES_PATH,
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
/// Script that installs `nett` on a new machine (design/release.md section 6): installs the program
/// only, does not read the token.
pub const INSTALL_SCRIPT: &str = "curl -fsSL https://nett.gotry.io/install.sh | sh";
/// Validity period of an enrollment token (design/auth.md section 8.1).
pub const ENROLL_VALIDITY_SECS: i64 = 30 * 60;
/// Upper bound for waiting for the machines to confirm after a push (design/hub.md section 3.2).
const WAIT_APPLIED: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(300);
/// Events shown by `nett site status <name>`.
const RECENT_EVENTS: usize = 10;

/// The Hub a site is linked to.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteHub {
    pub url: String,
    pub hub_key: Bytes32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_fingerprint: Option<Bytes32>,
    /// The site's owner token: can push signed artifacts, cannot approve any change that raises
    /// privileges (hard rule 3).
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

/// One Hub request from the command line: single-threaded runtime, the request itself has a
/// timeout.
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

/// `nett site link <link code>` (design/hub.md section 3.1).
pub fn link(dir: &Path, code: &str) -> anyhow::Result<()> {
    let code = LinkCode::decode(code)?;
    let site = SiteDir::open(dir)?;
    let mut state = site.load()?;
    // The Hub seals its backups to this key; the private half stays in the site directory
    if site.ensure_backup_key(&mut state)? {
        site.save(&state)?;
        outln!(
            "Created {}: the Hub's backups open only with it. Keep a copy offline with {}.",
            site.path().join(nett_site::dir::BACKUP_FILE).display(),
            nett_site::dir::RECOVERY_FILE
        );
    }
    if let Some(old) = SiteHub::load(dir)?
        && old.url != code.url
    {
        outln!("Replacing the link to {}.", old.url);
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
    outln!(
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

/// What happened on the Hub side that the site has not fetched yet (design/hub.md section 4).
pub fn fetch_updates(hub: &SiteHub) -> anyhow::Result<Updates> {
    request(&hub.target(), "GET", UPDATES_PATH, Some(&hub.token), None)
}

fn fetch_status(hub: &SiteHub) -> anyhow::Result<StatusResponse> {
    request(&hub.target(), "GET", STATUS_PATH, Some(&hub.token), None)
}

/// The Hub and the machines that run a release older than `version`, as the Hub reports them.
pub fn older_than(hub: &SiteHub, version: &str) -> anyhow::Result<Vec<String>> {
    let wanted = version.parse().context("a release version")?;
    Ok(running_older(&fetch_status(hub)?, &wanted))
}

/// A machine that has not reported a release counts as older: it may join with any.
fn running_older(reply: &StatusResponse, wanted: &nett_trust::release::Version) -> Vec<String> {
    use nett_trust::release::Version;
    let older = |v: Option<&str>| v.is_none_or(|v| v.parse::<Version>().is_ok_and(|v| v < *wanted));
    let hub = older(Some(&reply.hub_version)).then(|| "the Hub".to_owned());
    hub.into_iter()
        .chain(
            reply
                .machines
                .iter()
                .filter(|m| older(m.nett_version.as_deref()))
                .map(|m| m.name.clone()),
        )
        .collect()
}

/// The release the Hub holds, when the Hub or a machine runs an older one, and the command that
/// approves it (design/hub.md section 3.4).
fn available(reply: &StatusResponse) -> Option<String> {
    use nett_trust::release::Version;
    let release: Version = reply.release.as_deref()?.parse().ok()?;
    let older = |v: &str| v.parse::<Version>().is_ok_and(|v| v < release);
    let hub = older(&reply.hub_version);
    let machines = reply
        .machines
        .iter()
        .filter(|m| m.nett_version.as_deref().is_some_and(older))
        .count();
    let plural = if machines == 1 { "" } else { "s" };
    let who = match (hub, machines) {
        (false, 0) => return None,
        (true, 0) => "the Hub".to_owned(),
        (false, n) => format!("{n} machine{plural}"),
        (true, n) => format!("the Hub and {n} machine{plural}"),
    };
    Some(format!("{release} available for {who}: nett site upgrade"))
}

/// What `nett site upgrade` approves: the release the Hub holds, and who runs an older one.
pub struct UpgradePlan {
    pub release: nett_trust::release::Version,
    hub: Option<nett_trust::release::Version>,
    machines: std::collections::HashMap<String, Option<nett_trust::release::Version>>,
}

impl UpgradePlan {
    pub fn hub_behind(&self) -> bool {
        self.hub.is_none_or(|v| v < self.release)
    }

    /// Whether `machine` runs an older release, or has not reported one.
    pub fn behind(&self, machine: &str) -> bool {
        self.machines
            .get(machine)
            .copied()
            .flatten()
            .is_none_or(|v| v < self.release)
    }
}

/// The release the Hub holds and the versions it knows (design/release.md section 7).
pub fn upgrade_plan(hub: &SiteHub) -> anyhow::Result<UpgradePlan> {
    use nett_trust::release::Version;
    let status = fetch_status(hub).context("reading the release the Hub holds")?;
    let hub_version = status.hub_version.parse::<Version>().ok();
    let release: Version = status
        .release
        .as_deref()
        .context("the Hub holds no release yet; it fetches one when it starts and every 6 hours")?
        .parse()
        .context("the release the Hub holds")?;
    Ok(UpgradePlan {
        release,
        hub: hub_version,
        machines: status
            .machines
            .iter()
            .map(|m| {
                (
                    m.name.clone(),
                    m.nett_version.as_deref().and_then(|v| v.parse().ok()),
                )
            })
            .collect(),
    })
}

/// One machine's confirmation of `generation`.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Applied,
    Problems(String),
    Rejected(String),
    Pending(String),
    /// Online, not confirmed yet.
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

/// After a push, waits for the machines to confirm, at most 10 seconds (design/hub.md section 3.2).
/// Returns the Hub's status, and whether any machine rejected it or still has a problem after
/// applying it.
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
    outln!("Pushed. {applied} of {total} machines applied.");
    for note in notes {
        outln!("  {note}");
    }
    Ok((status, failed))
}

fn has_desired(state: &State, name: &str) -> bool {
    name.parse::<NodeName>()
        .ok()
        .and_then(|n| state.machines.get(&n))
        .is_some_and(|m| m.policy.is_some())
}

/// Token for an existing member machine to attach to the Hub (design/hub.md section 3.5): no
/// secret, the machine connects with its own identity key.
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

/// Enrollment token for a new machine (design/hub.md section 6): adds the enrollment private key
/// and an expiry time, valid for 30 minutes, usable once.
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

/// The one line to run on the new machine (design/hub.md section 3.3): the same on all platforms.
pub fn print_enrollment(name: &NodeName, token: &str) {
    outln!(
        "On {name}, run within 30 minutes (once):\n  {INSTALL_SCRIPT} && sudo nett install {token}"
    );
}

/// `nett site status` when linked to a Hub (design/hub.md section 3.4).
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
            outln!("{}", serde_json::to_string_pretty(m)?);
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
        if let Some(upgrade) = upgrade_text(m) {
            lines.push(("upgrade", upgrade));
        }
        out!("{}", key_values(&lines));
        match m.status.clone().map(serde_json::from_value::<StatusDoc>) {
            Some(Ok(doc)) => out!("\n{}", crate::status::overview(&doc, now)),
            Some(Err(_)) => {
                outln!("\nIts status is in a format this version cannot read; see --json.")
            }
            None => outln!("\nIt has not reported its status yet."),
        }
        let events: Vec<Event> = request(
            &hub.target(),
            "GET",
            &format!("{EVENTS_PATH}?node={}&limit={RECENT_EVENTS}", m.node_id),
            Some(&hub.token),
            None,
        )?;
        if !events.is_empty() {
            let mut rows = vec![["WHEN", "EVENT", "DETAIL"].map(String::from)];
            rows.extend(events.iter().map(|e| {
                [
                    crate::status::ago(Timestamp::from_unix_seconds(e.at), now),
                    e.kind.clone(),
                    e.detail.clone(),
                ]
            }));
            outln!("\nRecent events:\n{}", table(&rows).trim_end());
        }
        return Ok(());
    }
    if json {
        outln!("{}", serde_json::to_string_pretty(&reply)?);
        return Ok(());
    }
    let backup = match (&reply.backup, state.backup_key) {
        (Some(b), _) => backup_text(b, &reply.machines, Timestamp::now()),
        (None, Some(_)) => "none yet: machines ask for it when they connect".to_owned(),
        (None, None) => "no backup key: the Hub makes backups after `nett site link`".to_owned(),
    };
    let mut lines = vec![(
        "hub",
        format!("{}, nett-hub {}", reply.url, reply.hub_version),
    )];
    if let Some(problem) = &reply.hub_upgrade {
        lines.push(("hub upgrade", format!("not installed: {problem}")));
    }
    if let Some(available) = available(&reply) {
        lines.push(("release", available));
    }
    lines.push((
        "site",
        format!("{} machines, {}", state.machines.len(), rules_text(state)),
    ));
    lines.push(("backup", backup));
    out!("{}", key_values(&lines));
    let docs: BTreeMap<String, StatusDoc> = reply
        .machines
        .iter()
        .filter_map(|m| {
            let doc = serde_json::from_value(m.status.clone()?).ok()?;
            Some((m.node_id.clone(), doc))
        })
        .collect();
    let owners: Vec<PortOwner> = state
        .machines
        .iter()
        .filter_map(|(name, m)| {
            Some(PortOwner {
                name: name.to_string(),
                id: m.node_id.clone(),
                port: m.listen_port(state.listen_port)?,
                obfs: m.obfs_port,
            })
        })
        .collect();
    let unanswered = unanswered_ports(&owners, &docs);
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
        let problems = match (problems.as_str(), unanswered.get(&m.node_id)) {
            (_, None) => problems,
            ("-", Some(port)) => port.clone(),
            (_, Some(port)) => format!("{problems}; {port}"),
        };
        rows.push([
            m.name.clone(),
            m.address.clone(),
            hub_state,
            m.nett_version.clone().unwrap_or_else(|| "-".into()),
            config_text(m, reply.generation),
            problems,
        ]);
    }
    outln!("\n{}", table(&rows).trim_end());

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
        // When both ends report, takes the end that has measurements (mesh.md section 8.3: the
        // decider measures the path)
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
            None => ("-".to_owned(), path_kind(state, &a, &b), "-".to_owned()),
        };
        pairs.push([names[0].clone(), names[1].clone(), st, path, rtt]);
    }
    if !pairs.is_empty() {
        pairs.sort();
        let mut rows = vec![["PEER A", "PEER B", "STATE", "PATH", "RTT"].map(String::from)];
        rows.extend(pairs);
        outln!("\n{}", table(&rows).trim_end());
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

/// The machine's last answer to the release manifest (design/release.md section 7).
fn upgrade_text(m: &MachineStatus) -> Option<String> {
    let reason = m.upgrade_reason.as_deref().unwrap_or("");
    match m.upgrade_result.as_deref()? {
        "rejected" => Some(format!("not upgraded: {reason}")),
        "pending" => Some(reason.to_owned()),
        _ => None,
    }
}

/// A machine waiting to join: how long until its token expires (design/hub.md section 3.3).
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

/// Public address of a `public` machine and its source (design/hub.md section 5).
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

/// How many machines hold a Hub backup and how current the oldest copy is (design/hub.md section
/// 8.2): a machine's copy holds the site as of the time it last confirmed it held the latest one.
fn backup_text(backup: &BackupStatus, machines: &[MachineStatus], now: Timestamp) -> String {
    let made = crate::status::ago(Timestamp::from_unix_seconds(backup.made_at), now);
    let total = machines.len();
    // A Hub of the release before sends no confirmation times, only who holds the latest backup
    if machines.iter().all(|m| m.backup_at.is_none()) {
        return format!(
            "made {made}, kept by {} of {total} machines",
            backup.held_by.len()
        );
    }
    let mut none: Vec<&str> = machines
        .iter()
        .filter(|m| m.backup_at.is_none())
        .map(|m| m.name.as_str())
        .collect();
    none.sort_unstable();
    let kept = if none.is_empty() {
        format!("kept by all {total} machines")
    } else {
        format!(
            "kept by {} of {total} machines (none on {})",
            total - none.len(),
            none.join(", ")
        )
    };
    let oldest = machines
        .iter()
        .filter_map(|m| Some((m.backup_at?, m.name.as_str())))
        .min()
        .map(|(at, name)| {
            format!(
                ", the oldest current as of {} ({name})",
                crate::status::ago(Timestamp::from_unix_seconds(at), now)
            )
        })
        .unwrap_or_default();
    format!("made {made}, {kept}{oldest}")
}

/// What needs attention on a machine (design/hub.md section 3.4). Problems left after applying a
/// push are taken from the status the machine reports every 15 seconds, which shows whether they
/// have healed since; the reason it gave when it applied describes that moment only. A push it
/// rejected or left pending keeps its reason.
/// Machines that must see a public machine's WireGuard port fail before it is named.
const UNANSWERED_FROM: usize = 2;

/// A `public` machine's WireGuard port.
struct PortOwner {
    name: String,
    id: NodeId,
    port: u16,
    /// The obfuscated port it offers.
    obfs: Option<u16>,
}

/// Each `public` machine whose WireGuard port answers no probe from at least [`UNANSWERED_FROM`]
/// machines that reach it over another path and not over its obfuscated port, by node ID
/// (design/hub.md section 3.4). This is their own measurement, from the status they report; the
/// machines it does answer show that the port is open to some sources, which rules out opening it
/// as the fix.
fn unanswered_ports(
    owners: &[PortOwner],
    docs: &BTreeMap<String, StatusDoc>,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for PortOwner {
        name,
        id,
        port,
        obfs,
    } in owners
    {
        let (port, obfs) = (*port, *obfs);
        let mut from = Vec::new();
        let mut answers = Vec::new();
        for doc in docs.values().filter(|doc| doc.node.id != *id) {
            let Some(peer) = doc.peers.iter().find(|p| p.id == *id) else {
                continue;
            };
            let on = |kind: PathKindDoc, port: u16, states: &[CandidateStateDoc]| {
                peer.candidates.iter().any(|c| {
                    c.kind == kind && c.endpoint.port() == port && states.contains(&c.state)
                })
            };
            const WORKS: &[CandidateStateDoc] =
                &[CandidateStateDoc::Current, CandidateStateDoc::Ok];
            const FAILS: &[CandidateStateDoc] =
                &[CandidateStateDoc::Failing, CandidateStateDoc::Blocked];
            let reporter = doc
                .node
                .name
                .as_ref()
                .map_or_else(|| doc.node.id.to_string(), ToString::to_string);
            if on(PathKindDoc::Direct, port, WORKS) {
                answers.push(reporter);
            } else if peer.state == PeerState::Connected
                && on(PathKindDoc::Direct, port, FAILS)
                && !obfs.is_some_and(|obfs| on(PathKindDoc::DirectObfs, obfs, WORKS))
            {
                from.push(reporter);
            }
        }
        if from.len() < UNANSWERED_FROM {
            continue;
        }
        from.sort();
        answers.sort();
        let measured = format!(
            "WireGuard port {port} answers no probe from {}, which reach it otherwise",
            from.join(", ")
        );
        let line = match (answers.is_empty(), obfs.is_some()) {
            (true, false) => format!(
                "{measured}; open UDP {port} to it, or give it an obfuscated port: \
                 nett site set {name} --obfs"
            ),
            (true, true) => measured,
            (false, false) => format!(
                "{measured}, but answers {}; give it an obfuscated port: nett site set {name} --obfs",
                answers.join(", ")
            ),
            (false, true) => format!("{measured}, but answers {}", answers.join(", ")),
        };
        out.insert(id.to_string(), line);
    }
    out
}

fn problems_text(m: &MachineStatus, now: Timestamp) -> String {
    let mut out = Vec::new();
    let status = m
        .status
        .clone()
        .and_then(|s| serde_json::from_value::<StatusDoc>(s).ok());
    let applied = m.result.as_deref() == Some("applied");
    let reason = m.reason.as_ref().filter(|_| !applied || status.is_none());
    if let Some(reason) = reason {
        out.push(reason.clone());
    }
    if let Some(upgrade) = upgrade_text(m)
        && m.upgrade_result.as_deref() == Some("rejected")
    {
        out.push(upgrade);
    }
    if let Some(doc) = &status
        && reason.is_none()
    {
        match doc.problems.as_slice() {
            [] => {}
            [one] => out.push(crate::status::problem_text(one)),
            many => out.push(format!("{} problems", many.len())),
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
            upgrade_result: None,
            upgrade_reason: None,
            backup_at: None,
        }
    }

    /// The backup line counts every machine that holds a copy and names how current the oldest
    /// one is, from the time each machine last confirmed it held the latest backup, and the
    /// machines that hold none (design/hub.md section 8.2). A machine that took the latest one first
    /// does not make the others' copies count as missing.
    #[test]
    fn the_backup_line_counts_every_copy_and_names_the_oldest() {
        let now = Timestamp::from_unix_seconds(1_795_570_000);
        let held = |name: &str, hours_ago: Option<i64>| MachineStatus {
            name: name.into(),
            backup_at: hours_ago.map(|h| now.unix_seconds() - h * 3600),
            ..machine(true, None, None)
        };
        let backup = BackupStatus {
            made_at: now.unix_seconds() - 3600,
            bytes: 267_766,
            held_by: vec!["edge-vps".into()],
        };
        let all = [
            held("edge-vps", Some(1)),
            held("vps-02", Some(2)),
            held("mac", Some(1)),
        ];
        assert_eq!(
            backup_text(&backup, &all, now),
            "made 1h ago, kept by all 3 machines, the oldest current as of 2h ago (vps-02)"
        );
        let some = [
            held("edge-vps", Some(1)),
            held("vps-03", None),
            held("nas", None),
        ];
        assert_eq!(
            backup_text(&backup, &some, now),
            "made 1h ago, kept by 1 of 3 machines (none on nas, vps-03), the oldest current as of \
             1h ago (edge-vps)"
        );
        let older_hub = [held("edge-vps", None), held("vps-02", None)];
        assert_eq!(
            backup_text(&backup, &older_hub, now),
            "made 1h ago, kept by 1 of 2 machines"
        );
    }

    /// A machine's reported status with these problems.
    fn reporting(mut m: MachineStatus, problems: serde_json::Value) -> MachineStatus {
        m.status = Some(serde_json::json!({
            "v": 1, "version": "0.8.0",
            "node": {
                "id": m.node_id, "name": m.name, "admitted": true,
                "mesh": ["100.88.0.6", "fd00:88::6"], "edge": [], "routes": [],
                "reachability": "dial-only", "dataplane": "userspace", "listen_port": 53557,
                "nat": null, "clock_trusted": true, "started_at": "2026-11-22T07:00:00Z"
            },
            "config": {"applied_at": "2026-11-22T07:48:00Z", "access_rules_version": 18},
            "peers": [], "problems": problems, "events": []
        }));
        m
    }

    /// What a feature that needs every end on a release checks (design/obfuscation.md section 5).
    #[test]
    fn the_hub_and_machines_on_an_older_release_are_named() {
        let at = |name: &str, version: Option<&str>| MachineStatus {
            name: name.into(),
            nett_version: version.map(str::to_owned),
            ..machine(true, None, None)
        };
        let reply = |hub: &str| StatusResponse {
            hub_version: hub.into(),
            hub_upgrade: None,
            release: None,
            url: "https://hub.example.com".into(),
            generation: 1,
            machines: vec![
                at("nas", Some("0.10.0")),
                at("mac", Some("0.9.5")),
                at("new", None),
                at("vps", Some("0.10.1")),
            ],
            backup: None,
        };
        let wanted = "0.10.0".parse().expect("version");
        assert_eq!(running_older(&reply("0.10.0"), &wanted), ["mac", "new"]);
        assert_eq!(
            running_older(&reply("0.9.5"), &wanted),
            ["the Hub", "mac", "new"]
        );
    }

    #[test]
    fn problems_after_applying_follow_the_reported_status() {
        let now = Timestamp::from_unix_seconds(1_795_300_000);
        let bind = "port 8080/tcp: binding TCP 100.88.0.6:8080: Address already in use";
        let applied = machine(true, Some(1), Some((3, "applied", Some(bind))));
        // The port was bound on a retry: the status reported since lists nothing
        assert_eq!(
            problems_text(&reporting(applied.clone(), serde_json::json!([])), now),
            "-"
        );
        // Still failing: the status lists it
        let still = serde_json::json!([
            {"kind": "serve", "node": null, "at": "2026-11-22T07:48:08Z", "reason": bind}
        ]);
        assert_eq!(
            problems_text(&reporting(applied.clone(), still.clone()), now),
            format!("a served port is not forwarded: {bind}")
        );
        let two = serde_json::json!([
            {"kind": "serve", "node": null, "at": "2026-11-22T07:48:08Z", "reason": bind},
            {"kind": "names", "node": null, "at": "2026-11-22T07:48:08Z", "reason": "port 53"}
        ]);
        assert_eq!(
            problems_text(&reporting(applied.clone(), two), now),
            "2 problems"
        );
        // Before any status arrives, the reason given when applying is all there is
        assert_eq!(problems_text(&applied, now), bind);
        // A rejected push keeps its reason, whatever the status lists
        let rejected = machine(true, Some(1), Some((3, "rejected", Some("older"))));
        assert_eq!(
            problems_text(&reporting(rejected, serde_json::json!([])), now),
            "older"
        );
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

    /// A reporting machine's view of one peer, `peer`, reached over a relay while its WireGuard
    /// port's candidate is in `direct` and, when it lists one, its obfuscated port's in `obfs`.
    fn view(
        me: (&str, char),
        peer: char,
        state: &str,
        direct: &str,
        obfs: Option<&str>,
    ) -> StatusDoc {
        let id = |c: char| format!("node_01JD7M3XQ4W8N2K5R9T6V3B7C{c}");
        let mut candidates = vec![
            serde_json::json!({"kind": "direct", "relay": null, "endpoint": "198.51.100.9:41820",
                               "punched": false, "rtt_ms": null, "loss": 1.0, "state": direct}),
            serde_json::json!({"kind": "relay", "relay": null, "endpoint": "198.51.100.9:41822",
                               "punched": false, "rtt_ms": 150.0, "loss": 0.0, "state": "current"}),
        ];
        if let Some(obfs) = obfs {
            candidates.push(serde_json::json!({
                "kind": "direct_obfs", "relay": null, "endpoint": "198.51.100.9:42001",
                "punched": false, "rtt_ms": 150.0, "loss": 0.0, "state": obfs
            }));
        }
        serde_json::from_value(serde_json::json!({
            "v": 1, "version": "0.11.0",
            "node": {"id": id(me.1), "name": me.0, "admitted": true, "mesh": [], "edge": [],
                     "routes": [], "reachability": "public", "dataplane": "kernel",
                     "listen_port": 41820, "nat": null, "clock_trusted": true,
                     "started_at": "2026-11-24T00:00:00Z"},
            "config": {"applied_at": "2026-11-24T00:00:00Z", "access_rules_version": 1},
            "peers": [{
                "id": id(peer), "name": "far", "mesh": [], "edge": [], "routes": [],
                "state": state, "role": "decider", "path": null, "rtt_ms": null, "loss": null,
                "jitter_ms": null, "last_handshake": null, "last_received": null,
                "rx_bytes": 0, "tx_bytes": 0,
                "candidates": candidates
            }],
            "problems": [], "events": []
        }))
        .expect("fixture")
    }

    fn docs(views: Vec<StatusDoc>) -> BTreeMap<String, StatusDoc> {
        views
            .into_iter()
            .map(|d| (d.node.id.to_string(), d))
            .collect()
    }

    fn far(obfs: Option<u16>) -> PortOwner {
        PortOwner {
            name: "far".into(),
            id: "node_01JD7M3XQ4W8N2K5R9T6V3B7C9".parse().expect("id"),
            port: 41820,
            obfs,
        }
    }

    fn named(owner: &PortOwner, views: Vec<StatusDoc>) -> Option<String> {
        unanswered_ports(std::slice::from_ref(owner), &docs(views)).remove(owner.id.as_str())
    }

    /// A public machine's WireGuard port that two machines reaching it otherwise cannot probe is
    /// named, with the machines that measured it and those it answers (design/hub.md section 3.4):
    /// with none answering, opening the port is advised; with one answering, the port is open to
    /// some sources and only an obfuscated port is; a machine with one gets no advice to add one.
    /// One such machine, or machines that do not reach it at all, are not enough.
    #[test]
    fn a_wireguard_port_others_cannot_reach_is_named() {
        let both = || {
            vec![
                view(("a", '1'), '9', "connected", "failing", None),
                view(("b", '2'), '9', "connected", "blocked", None),
            ]
        };
        assert_eq!(
            named(&far(None), both()).as_deref(),
            Some(
                "WireGuard port 41820 answers no probe from a, b, which reach it otherwise; open \
                 UDP 41820 to it, or give it an obfuscated port: nett site set far --obfs"
            )
        );
        let mut answered = both();
        answered.push(view(("c", '3'), '9', "connected", "ok", None));
        assert_eq!(
            named(&far(None), answered.clone()).as_deref(),
            Some(
                "WireGuard port 41820 answers no probe from a, b, which reach it otherwise, but \
                 answers c; give it an obfuscated port: nett site set far --obfs"
            )
        );
        assert_eq!(
            named(&far(Some(42001)), both()).as_deref(),
            Some("WireGuard port 41820 answers no probe from a, b, which reach it otherwise")
        );
        assert_eq!(
            named(&far(Some(42001)), answered).as_deref(),
            Some(
                "WireGuard port 41820 answers no probe from a, b, which reach it otherwise, but \
                 answers c"
            )
        );

        for views in [
            vec![view(("a", '1'), '9', "connected", "failing", None)],
            vec![
                view(("a", '1'), '9', "connected", "failing", None),
                view(("b", '2'), '9', "unreachable", "failing", None),
            ],
            vec![
                view(("a", '1'), '9', "connected", "failing", None),
                view(("b", '2'), '9', "connected", "ok", None),
            ],
        ] {
            assert_eq!(named(&far(Some(42001)), views), None);
        }
    }

    /// Machines that cannot probe a WireGuard port but reach the machine's obfuscated port are
    /// carried by it, as obfuscation is meant to carry them, so they are not counted (design/hub.md
    /// section 3.4): with all of them on it the port is not named, and with some of them on it only
    /// the others are. An obfuscated candidate to another port does not count.
    #[test]
    fn a_wireguard_port_obfuscation_carries_is_not_named() {
        let carried = |obfs: &str| {
            vec![
                view(("a", '1'), '9', "connected", "failing", Some(obfs)),
                view(("b", '2'), '9', "connected", "blocked", Some("ok")),
                view(("c", '3'), '9', "connected", "ok", None),
            ]
        };
        assert_eq!(named(&far(Some(42001)), carried("current")), None);
        assert_eq!(
            named(&far(Some(42046)), carried("current")).as_deref(),
            Some(
                "WireGuard port 41820 answers no probe from a, b, which reach it otherwise, but \
                 answers c"
            )
        );
        let mut some = carried("failing");
        some.push(view(
            ("d", '4'),
            '9',
            "connected",
            "failing",
            Some("untested"),
        ));
        assert_eq!(
            named(&far(Some(42001)), some).as_deref(),
            Some(
                "WireGuard port 41820 answers no probe from a, d, which reach it otherwise, but \
                 answers c"
            )
        );
    }

    #[test]
    fn site_hub_file_is_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir_tmp = tempfile::Builder::new()
            .prefix("nett-cli-site-hub-")
            .tempdir()
            .expect("temp dir");
        let dir = dir_tmp.path().join("dir");
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
