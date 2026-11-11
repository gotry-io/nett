//! The Hub core (design/hub.md section 4): stores the pushed site, composes each machine's desired
//! state using the same nett-site logic, and notifies node connections when the site changes. The
//! Hub has no key that can sign: each pushed signed artifact is verified against the trust anchor
//! pinned at link time.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use nett_core::id::NodeId;
use nett_site::state::{Learned, NodeKeys, State};
use nett_site::updates::{LearnedFor, Updates};
use nett_trust::admission::{AdmissionMaterial, AdmissionProof, AdmissionProofDoc};
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

/// The current site: generation, site state, and the composed desired state of each machine (the
/// content of the mesh partition).
pub struct Site {
    pub generation: u64,
    pub state: State,
    pub desired: HashMap<NodeId, Vec<u8>>,
    /// A machine's identity public key → node ID: used to recognize a node when it connects.
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
    /// The current connection of each machine: a new connection replaces the old one.
    live: Mutex<HashMap<NodeId, Arc<Notify>>>,
    /// The latest release manifest (design/release.md section 7), sent to every node as the
    /// `release` partition.
    release: watch::Sender<Option<Arc<Vec<u8>>>>,
}

/// The reason an enrollment is rejected, told to that machine as is (protocol.md section 4.3).
#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    #[error("{0}")]
    Refused(String),
    #[error(transparent)]
    Db(#[from] DbError),
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
            release: watch::channel(None).0,
        }))
    }

    /// The latest release manifest, already checked.
    pub fn release(&self) -> Option<Arc<Vec<u8>>> {
        self.release.borrow().clone()
    }

    pub fn subscribe_release(&self) -> watch::Receiver<Option<Arc<Vec<u8>>>> {
        self.release.subscribe()
    }

    /// Takes a newly fetched release manifest; connected nodes get it when it changed.
    pub fn set_release(&self, manifest: Vec<u8>) -> Result<(), String> {
        nett_trust::release::Manifest::parse(&manifest).map_err(|e| e.to_string())?;
        self.release.send_if_modified(|current| {
            if current.as_deref().map(Vec::as_slice) == Some(manifest.as_slice()) {
                return false;
            }
            *current = Some(Arc::new(manifest));
            true
        });
        Ok(())
    }

    pub async fn site(&self) -> Option<Arc<Site>> {
        self.site.read().await.clone()
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    /// Registers a node connection and returns the notification for when it is replaced; the same
    /// machine's previous connection ends with it.
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

    async fn anchors(&self) -> Result<TrustAnchorsDoc, PushError> {
        let hub = self.db.hub().await?.ok_or(PushError::NotLinked)?;
        let anchors_json = hub.trust_anchors.ok_or(PushError::NotLinked)?;
        serde_json::from_str(&anchors_json)
            .map_err(|e| PushError::Rejected(format!("stored trust anchors: {e}")))
    }

    /// Events that happen on the Hub side and that the site has not yet fetched (design/hub.md
    /// section 4).
    pub async fn updates(&self) -> Result<Updates, PushError> {
        let mut updates = Updates::default();
        for row in self.db.updates().await? {
            if let Some(json) = &row.enrolled {
                updates.enrolled.push(
                    serde_json::from_str::<AdmissionMaterial>(json).map_err(|e| {
                        PushError::Rejected(format!("stored admission material: {e}"))
                    })?,
                );
            }
            if row.left_at.is_some()
                && let Ok(node) = row.node_id.parse::<NodeId>()
            {
                updates.left.push(node);
            }
        }
        for row in self.db.nodes().await? {
            if let (Some(json), Ok(node_id)) = (&row.learned, row.node_id.parse::<NodeId>())
                && let Ok(learned) = serde_json::from_str::<Learned>(json)
            {
                updates.learned.push(LearnedFor { node_id, learned });
            }
        }
        Ok(updates)
    }

    /// Accepts a pushed site state (design/hub.md section 4): the trust anchor must be the one
    /// pinned at link time; first apply what happened on the Hub
    /// side, then verify the signed artifacts one by one; a version lower than the stored one, or the
    /// same version as the stored one with different content, is rejected as a whole; a revoked machine
    /// cannot be restored.
    pub async fn push(&self, pushed: State, now: i64) -> Result<u64, PushError> {
        let anchors = self.anchors().await?;
        let mut current = self.site.write().await;
        // Events already contained in the pushed state are no longer kept
        for row in self.db.updates().await? {
            let machine = row
                .node_id
                .parse::<NodeId>()
                .ok()
                .and_then(|id| pushed.by_id(&id).cloned());
            let enrolled = row.enrolled.is_some()
                && machine.as_ref().is_none_or(|m| {
                    m.keys.is_some_and(|k| {
                        serde_json::from_str::<AdmissionMaterial>(
                            row.enrolled.as_deref().unwrap_or(""),
                        )
                        .ok()
                        .and_then(|a| proof_keys(&a))
                        .is_some_and(|keys| keys == k)
                    })
                });
            let left = row.left_at.is_some() && machine.is_none();
            if enrolled || left {
                self.db.acknowledge(&row.node_id, enrolled, left).await?;
            }
        }
        let mut state = pushed;
        self.updates()
            .await?
            .apply(&mut state)
            .map_err(|e| PushError::Rejected(e.to_string()))?;
        // The same site pushed again (for example no reply was received after the last push): the
        // generation does not change and machines do not need to apply again
        if let Some(site) = current.as_ref()
            && site.state == state
        {
            return Ok(site.generation);
        }
        verify(&anchors, current.as_ref().map(|s| &s.state), &state)
            .map_err(PushError::Rejected)?;
        self.commit(&mut current, state, now).await
    }

    /// Saves with a new generation and distributes it.
    async fn commit(
        &self,
        current: &mut Option<Arc<Site>>,
        state: State,
        now: i64,
    ) -> Result<u64, PushError> {
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
        self.changes.send_replace(generation);
        Ok(generation)
    }

    /// Applies a Hub-side event to the current site; when the site changes as a result, a new
    /// generation is distributed.
    async fn apply(&self, updates: &Updates, now: i64) -> Result<(), PushError> {
        let anchors = self.anchors().await?;
        let mut current = self.site.write().await;
        self.apply_locked(&mut current, &anchors, updates, now)
            .await
    }

    async fn apply_locked(
        &self,
        current: &mut Option<Arc<Site>>,
        anchors: &TrustAnchorsDoc,
        updates: &Updates,
        now: i64,
    ) -> Result<(), PushError> {
        let Some(site) = current.as_ref() else {
            return Ok(());
        };
        let mut state = site.state.clone();
        updates
            .apply(&mut state)
            .map_err(|e| PushError::Rejected(e.to_string()))?;
        if state == site.state {
            return Ok(());
        }
        verify(anchors, Some(&site.state), &state).map_err(PushError::Rejected)?;
        self.commit(current, state, now).await.map(|_| ())
    }

    /// A new machine joins (design/hub.md section 6): the machine with this node ID in the site is
    /// waiting to join, the token has not expired, and the admission
    /// proof verifies with the enrollment public key in its node policy, and the identity public key in
    /// the proof is the one used for the handshake.
    pub async fn enroll(
        &self,
        node_id: &str,
        identity: &[u8; 32],
        proof: &[u8],
        now: i64,
    ) -> Result<NodeId, EnrollError> {
        let refuse = |m: String| EnrollError::Refused(m);
        let proof: AdmissionProof = serde_json::from_slice(proof)
            .map_err(|_| refuse("the admission proof is not valid".into()))?;
        let node: NodeId = node_id
            .parse()
            .map_err(|_| refuse("the node ID is not valid".into()))?;
        let anchors = self.anchors().await.map_err(|e| match e {
            PushError::Db(e) => EnrollError::Db(e),
            other => refuse(other.to_string()),
        })?;
        // The check and the save are under the same lock: when two machines use the same token at
        // once only one succeeds
        let mut current = self.site.write().await;
        let site = current
            .clone()
            .ok_or_else(|| refuse("this Hub has no site yet".into()))?;
        let name = site
            .state
            .name_of(&node)
            .ok_or_else(|| refuse("this machine is not in the site".into()))?;
        let m = site
            .state
            .machine(name)
            .map_err(|e| refuse(e.to_string()))?;
        if m.keys.is_some() {
            return Err(refuse(format!(
                "`{name}` has already joined with another machine; on the computer that holds the \
                 site, `nett site remove {name}` and add it again"
            )));
        }
        let pending = m
            .enrollment
            .as_ref()
            .ok_or_else(|| refuse(format!("`{name}` is not waiting to join")))?;
        if now > pending.expires_at {
            return Err(refuse(format!(
                "the token for `{name}` expired; `nett site invite {name}` prints a new one"
            )));
        }
        let policy = pending
            .policy
            .as_ref()
            .ok_or_else(|| refuse(format!("`{name}` has no signed node policy yet")))?;
        let material = AdmissionMaterial {
            policy: policy.signed.clone(),
            proof,
        };
        // The handshake's identity public key is the one in the proof: even if the token falls into
        // someone else's hands, it cannot impersonate any identity other than this machine's
        if proof_keys(&material).is_none_or(|k| k.identity.as_bytes() != identity) {
            return Err(refuse(
                "the admission proof is not for the identity key of this connection".into(),
            ));
        }
        let mut check = site.state.clone();
        nett_site::updates::record_enrollment(&mut check, &material)
            .map_err(|e| refuse(e.to_string()))?;
        let json = serde_json::to_string(&material).map_err(|e| refuse(e.to_string()))?;
        self.db.put_enrolled(node.as_str(), &json).await?;
        let updates = Updates {
            enrolled: vec![material],
            ..Updates::default()
        };
        self.apply_locked(&mut current, &anchors, &updates, now)
            .await
            .map_err(|e| match e {
                PushError::Db(e) => EnrollError::Db(e),
                other => refuse(other.to_string()),
            })?;
        tracing::info!(node_id = %node, machine = %name, "machine joined");
        Ok(node)
    }

    /// A machine leaves on its own (`nett leave`, auth.md section 8.3): lowers privileges,
    /// effective immediately.
    pub async fn leave(&self, node: &NodeId, now: i64) -> Result<(), PushError> {
        self.db.put_left(node.as_str(), now).await?;
        let updates = Updates {
            left: vec![node.clone()],
            ..Updates::default()
        };
        self.apply(&updates, now).await?;
        tracing::info!(node_id = %node, "machine left");
        Ok(())
    }

    /// Records the public address learned by the Hub (design/hub.md section 5); when it changes, a
    /// new generation is distributed.
    pub async fn learned(
        &self,
        node: &NodeId,
        learned: Learned,
        now: i64,
    ) -> Result<(), PushError> {
        let unchanged = self
            .site()
            .await
            .and_then(|s| s.state.by_id(node).map(|m| m.learned == learned))
            .unwrap_or(true);
        if unchanged {
            return Ok(());
        }
        let json =
            serde_json::to_string(&learned).map_err(|e| PushError::Rejected(e.to_string()))?;
        self.db.set_learned(node.as_str(), &json).await?;
        let updates = Updates {
            learned: vec![LearnedFor {
                node_id: node.clone(),
                learned,
            }],
            ..Updates::default()
        };
        self.apply(&updates, now).await
    }
}

/// The public key in the admission proof (the signature is not verified: verification is in
/// `record_enrollment`).
fn proof_keys(material: &AdmissionMaterial) -> Option<NodeKeys> {
    let value = nett_trust::canonical::parse_canonical(&material.proof.payload).ok()?;
    let doc: AdmissionProofDoc = serde::Deserialize::deserialize(&value).ok()?;
    Some(NodeKeys {
        mesh: doc.mesh_public_key,
        identity: doc.identity_public_key,
    })
}

/// Whether a pushed site state can be accepted.
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
        // Removing all advertised routes is only a narrowing: the artifact may be absent, but the
        // highest signed version cannot decrease
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
