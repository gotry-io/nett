//! Hub 的核心（design/hub.md 第 4 节）：保存推送的站点，按 nett-site 的同一份逻辑为每台机器组成期望状态，
//! 站点变化时通知各条节点连接。Hub 没有能签名的钥匙：推送的签名产物逐份按关联时固定的信任锚验证。

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use nett_core::id::NodeId;
use nett_site::state::State;
use nett_trust::anchors::{TrustAnchors, TrustAnchorsDoc};
use nett_trust::revocation::{Revocation, Revocations};
use tokio::sync::{Mutex, Notify, RwLock, watch};
use x25519_dalek::StaticSecret;

use crate::db::{Db, DbError};

#[derive(Debug, thiserror::Error)]
pub enum PushError {
    #[error("the Hub is not linked to a site yet")]
    NotLinked,
    #[error("{0}")]
    Rejected(String),
    #[error(transparent)]
    Db(#[from] DbError),
}

/// 当前的站点：代数、站点状态，以及组成好的各台机器的期望状态（mesh 分区的内容）。
pub struct Site {
    pub generation: u64,
    pub state: State,
    pub desired: HashMap<NodeId, Vec<u8>>,
    /// 机器的身份公钥 → 节点 ID：节点连接时据此认出它。
    pub by_identity: HashMap<[u8; 32], NodeId>,
    pub revoked: HashSet<NodeId>,
}

impl Site {
    fn build(generation: u64, state: State) -> Result<Self, String> {
        let mut desired = HashMap::new();
        let mut by_identity = HashMap::new();
        for (name, m) in &state.machines {
            if let Some(doc) =
                nett_site::compose::desired(&state, name).map_err(|e| e.to_string())?
            {
                let bytes = serde_json::to_vec(&doc).map_err(|e| e.to_string())?;
                desired.insert(m.node_id.clone(), bytes);
            }
            if let Some(keys) = m.keys {
                by_identity.insert(*keys.identity.as_bytes(), m.node_id.clone());
            }
        }
        let revoked = state.revoked.iter().map(|r| r.node_id.clone()).collect();
        Ok(Self {
            generation,
            state,
            desired,
            by_identity,
            revoked,
        })
    }
}

pub struct Hub {
    pub db: Db,
    pub key: StaticSecret,
    pub url: String,
    site: RwLock<Option<Arc<Site>>>,
    changes: watch::Sender<u64>,
    /// 每台机器当前的连接：新的连接接替旧的。
    live: Mutex<HashMap<NodeId, Arc<Notify>>>,
}

impl Hub {
    pub async fn load(db: Db, key: StaticSecret, url: String) -> Result<Arc<Self>, String> {
        let site = match db.site().await.map_err(|e| e.to_string())? {
            Some((generation, json)) => {
                let state = State::from_json(json.as_bytes()).map_err(|e| e.to_string())?;
                Some(Arc::new(Site::build(
                    generation.try_into().unwrap_or(0),
                    state,
                )?))
            }
            None => None,
        };
        let generation = site.as_ref().map_or(0, |s| s.generation);
        Ok(Arc::new(Self {
            db,
            key,
            url,
            site: RwLock::new(site),
            changes: watch::channel(generation).0,
            live: Mutex::new(HashMap::new()),
        }))
    }

    pub async fn site(&self) -> Option<Arc<Site>> {
        self.site.read().await.clone()
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    /// 登记一条节点连接，返回它被接替时的通知；同一台机器原来的连接随之结束。
    pub async fn connected(&self, node: &NodeId) -> Arc<Notify> {
        let notify = Arc::new(Notify::new());
        if let Some(old) = self.live.lock().await.insert(node.clone(), notify.clone()) {
            old.notify_one();
        }
        notify
    }

    pub async fn disconnected(&self, node: &NodeId, notify: &Arc<Notify>) {
        let mut live = self.live.lock().await;
        if live.get(node).is_some_and(|n| Arc::ptr_eq(n, notify)) {
            live.remove(node);
        }
    }

    pub async fn online(&self) -> HashSet<NodeId> {
        self.live.lock().await.keys().cloned().collect()
    }

    /// 接收一份推送的站点状态（design/hub.md 第 4 节）：信任锚必须是关联时固定的那一份；每份签名产物按它
    /// 验证；版本低于已保存的、或与已保存的版本相同而内容不同的整份拒绝；已撤销的不能恢复。
    pub async fn push(&self, state: State, now: i64) -> Result<u64, PushError> {
        let hub = self.db.hub().await?.ok_or(PushError::NotLinked)?;
        let anchors_json = hub.trust_anchors.ok_or(PushError::NotLinked)?;
        let anchors: TrustAnchorsDoc = serde_json::from_str(&anchors_json)
            .map_err(|e| PushError::Rejected(format!("stored trust anchors: {e}")))?;
        let mut current = self.site.write().await;
        // 同一份站点再推一次（例如上一次推送之后没有收到回复）：不换代数，各台机器不用重新应用
        if let Some(site) = current.as_ref()
            && site.state == state
        {
            return Ok(site.generation);
        }
        verify(&anchors, current.as_ref().map(|s| &s.state), &state)
            .map_err(PushError::Rejected)?;
        let generation = current.as_ref().map_or(0, |s| s.generation) + 1;
        let site = Site::build(generation, state).map_err(PushError::Rejected)?;
        let json =
            serde_json::to_string(&site.state).map_err(|e| PushError::Rejected(e.to_string()))?;
        self.db
            .put_site(i64::try_from(generation).unwrap_or(i64::MAX), &json, now)
            .await?;
        let keep: Vec<String> = site
            .state
            .machines
            .values()
            .map(|m| m.node_id.to_string())
            .collect();
        self.db.prune(&keep).await?;
        *current = Some(Arc::new(site));
        drop(current);
        self.changes.send_replace(generation);
        Ok(generation)
    }
}

/// 推送的站点状态能不能接受。
pub fn verify(anchors: &TrustAnchorsDoc, old: Option<&State>, new: &State) -> Result<(), String> {
    if new.trust_anchors != *anchors {
        return Err("the site's trust anchors differ from the ones linked to this Hub".into());
    }
    new.check().map_err(|e| e.to_string())?;
    let trusted = TrustAnchors::from_doc(anchors).map_err(|e| e.to_string())?;
    let mut revocations = Revocations::default();
    for r in &new.revoked {
        revocations.apply(&Revocation::Node {
            node_id: r.node_id.clone(),
        });
    }
    for (name, m) in &new.machines {
        let Some(policy) = &m.policy else {
            continue;
        };
        let member = nett_trust::admission::admit(&policy.material, &trusted, &revocations)
            .map_err(|e| format!("machine `{name}`: {e}"))?;
        if member.node_id != m.node_id || member.policy_version != policy.version {
            return Err(format!(
                "machine `{name}`: the signed policy is for another node or version"
            ));
        }
        if let Some(keys) = m.keys
            && (member.mesh_public_key != keys.mesh || member.identity_public_key != keys.identity)
        {
            return Err(format!(
                "machine `{name}`: the signed keys differ from the machine's"
            ));
        }
        if let Some(routes) = &m.routes_signed {
            routes
                .signed
                .verify(&trusted)
                .map_err(|e| format!("machine `{name}`: advertised routes: {e}"))?;
        }
    }
    if let Some(rules) = &new.access_rules {
        let verified = rules
            .signed
            .verify(&trusted)
            .map_err(|e| format!("access rules: {e}"))?;
        let (_, set) = verified
            .payload
            .access_rule_set()
            .ok_or("access rules: the signed payload carries no rule set")?;
        if set.version != rules.version {
            return Err("access rules: the signed version differs from the site's".into());
        }
    }
    let Some(old) = old else {
        return Ok(());
    };
    for r in &old.revoked {
        if !new.revoked.iter().any(|n| n.node_id == r.node_id) {
            return Err(format!(
                "node {} was revoked and cannot come back",
                r.node_id
            ));
        }
    }
    for (name, o) in &old.machines {
        let Some(n) = new.machines.values().find(|n| n.node_id == o.node_id) else {
            if !new.revoked.iter().any(|r| r.node_id == o.node_id) {
                return Err(format!("machine `{name}` is gone without a revocation"));
            }
            continue;
        };
        match (&o.policy, &n.policy) {
            (Some(_), None) => {
                return Err(format!("machine `{name}`: the signed node policy is gone"));
            }
            (Some(a), Some(b))
                if b.version < a.version
                    || (b.version == a.version && b.material != a.material) =>
            {
                return Err(format!(
                    "machine `{name}`: node policy version {} does not follow version {}",
                    b.version, a.version
                ));
            }
            _ => {}
        }
        // 去掉全部宣告网段只是收窄：产物可以没有，但签过的最高版本不能变小
        let highest = |m: &nett_site::state::Machine| {
            m.routes_version
                .max(m.routes_signed.as_ref().map_or(0, |r| r.version))
        };
        if highest(n) < highest(o) {
            return Err(format!(
                "machine `{name}`: advertised routes go back in version"
            ));
        }
        if let (Some(a), Some(b)) = (&o.routes_signed, &n.routes_signed)
            && b.version == a.version
            && b.signed != a.signed
        {
            return Err(format!(
                "machine `{name}`: advertised routes changed without a new version"
            ));
        }
    }
    match (&old.access_rules, &new.access_rules) {
        (Some(_), None) => Err("the signed access rules are gone".into()),
        (Some(a), Some(b))
            if b.version < a.version || (b.version == a.version && b.signed != a.signed) =>
        {
            Err(format!(
                "access rules version {} does not follow version {}",
                b.version, a.version
            ))
        }
        _ => Ok(()),
    }
}
