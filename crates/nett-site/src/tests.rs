use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use nett_core::name::NodeName;
use nett_mesh::config::{Candidate, DesiredMesh, Reachability};
use nett_mesh::event::VecSink;
use nett_mesh::members::{MemberSet, OwnPolicy};
use nett_trust::encoding::Timestamp;
use nett_trust::keys::X25519PublicKey;
use nett_trust::payload::{PortRange, Protocol};

use crate::changes::describe;
use crate::compose::{connections, desired};
use crate::dir::{SiteDir, new_node_id};
use crate::ops::{MachineChange, MachineOptions};
use crate::sign::{RESIGN_BEFORE_SECS, expand_rules, sign};
use crate::state::{NodeKeys, Part, RuleId, State};

/// A directory removed with everything in it when the returned guard is dropped; keep the
/// guard for as long as the path is used.
fn temp_dir(name: &str) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::Builder::new()
        .prefix(&format!("nett-site-lib-{name}-"))
        .tempdir()
        .expect("temp dir");
    let dir = tmp.path().join("site");
    (tmp, dir)
}

fn name(s: &str) -> NodeName {
    s.parse().expect("valid name")
}

fn keys(n: u8) -> NodeKeys {
    NodeKeys {
        mesh: X25519PublicKey::from_bytes([n; 32]),
        identity: X25519PublicKey::from_bytes([n ^ 0xff; 32]),
    }
}

fn tcp(port: u16) -> PortRange {
    PortRange {
        protocol: Protocol::Tcp,
        first: port,
        last: port,
    }
}

/// A site: public edge-vps, dial-only mac and nas.
fn site(dir: &Path) -> (SiteDir, State) {
    SiteDir::init(dir, "https://nett.invalid").expect("init");
    let site = SiteDir::open(dir).expect("open");
    let mut state = site.load().expect("load");
    state
        .add(
            name("edge-vps"),
            MachineOptions {
                public: true,
                ipv4: Some("203.0.113.10".parse().expect("ip")),
                keys: Some(keys(1)),
                ..MachineOptions::default()
            },
            new_node_id().expect("id"),
        )
        .expect("add edge-vps");
    for (n, k) in [("mac", 2), ("nas", 3)] {
        state
            .add(
                name(n),
                MachineOptions {
                    keys: Some(keys(k)),
                    ..MachineOptions::default()
                },
                new_node_id().expect("id"),
            )
            .expect("add");
    }
    (site, state)
}

fn signed(site: &SiteDir, state: &mut State) {
    sign(
        state,
        &site.recovery().expect("recovery"),
        Timestamp::now(),
        &[],
    )
    .expect("signed");
}

/// A machine's desired state is accepted by the mesh process, and all its members can be verified.
fn admitted(state: &State, n: &str) -> MemberSet {
    let doc = desired(state, &name(n)).expect("composed").expect("signed");
    let desired = DesiredMesh::from_doc(doc).expect("valid");
    let mut members = MemberSet::default();
    let own = OwnPolicy {
        node_id: &desired.node_id,
        now: None,
    };
    let mut events = VecSink::default();
    members.apply(&desired, &own, &mut events);
    assert!(
        !events
            .0
            .iter()
            .any(|e| matches!(e, nett_mesh::event::Event::MemberRejected { .. })),
        "{:?}",
        events.0
    );
    members
}

#[test]
fn a_new_site_is_private() {
    let (_dir_tmp, dir) = temp_dir("init");
    SiteDir::init(&dir, "https://nett.invalid").expect("init");
    let mode = |p: PathBuf| std::fs::metadata(p).expect("exists").permissions().mode() & 0o777;
    assert_eq!(mode(dir.clone()), 0o700);
    assert_eq!(mode(dir.join("recovery.pk8")), 0o600);
    assert_eq!(mode(dir.join("state.json")), 0o600);
    assert!(SiteDir::init(&dir, "https://nett.invalid").is_err());
    let site = SiteDir::open(&dir).expect("open");
    assert!(
        SiteDir::open(&dir).is_err(),
        "a second command waits for the lock"
    );
    drop(site);
    assert!(SiteDir::open(&dir).is_ok());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn machines_get_admissible_desired_states() {
    let (_dir_tmp, dir) = temp_dir("add");
    let (site, mut state) = site(&dir);
    signed(&site, &mut state);
    site.save(&state).expect("saved");
    assert_eq!(site.load().expect("load"), state);
    for n in ["edge-vps", "mac", "nas"] {
        assert_eq!(admitted(&state, n).members().len(), 3);
    }
    let edge = desired(&state, &name("edge-vps"))
        .expect("ok")
        .expect("signed");
    assert_eq!(edge.listen_port, Some(41820));
    // The public end has no candidate; the dial-only machine connects in
    assert!(edge.paths.iter().all(|p| p.candidates.is_empty()));
    let mac = desired(&state, &name("mac")).expect("ok").expect("signed");
    assert_eq!(mac.listen_port, None);
    let to_edge = mac
        .paths
        .iter()
        .find(|p| p.peer_reachability == Reachability::Public)
        .expect("mac connects to edge-vps");
    assert_eq!(
        to_edge.candidates,
        [Candidate::Direct {
            endpoint: "203.0.113.10:41820".parse().expect("endpoint")
        }]
    );
    // No rule involves mac and nas: there is no connection between two dial-only machines
    assert_eq!(mac.paths.len(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn signatures_stay_until_their_inputs_change() {
    let (_dir_tmp, dir) = temp_dir("keep");
    let (site, mut state) = site(&dir);
    signed(&site, &mut state);
    let before = state.clone();
    signed(&site, &mut state);
    assert_eq!(state, before, "nothing changed, nothing signed again");
    state
        .set_edge(
            &name("edge-vps"),
            Some(vec!["172.17.0.2/32".parse().expect("prefix")]),
        )
        .expect("edge");
    signed(&site, &mut state);
    let version = |s: &State, n: &str| s.machines[&name(n)].policy.as_ref().map(|p| p.version);
    assert_eq!(version(&state, "edge-vps"), Some(2));
    assert_eq!(version(&state, "mac"), Some(1));
    let lines = describe(&before, &state);
    assert!(
        lines.iter().any(|l| l.starts_with("+ edge-vps.edge")),
        "{lines:?}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn rules_expand_to_addresses_and_bring_connections() {
    let (_dir_tmp, dir) = temp_dir("rules");
    let (site, mut state) = site(&dir);
    signed(&site, &mut state);
    let before = state.clone();
    let id = state
        .allow(
            &["mac".into()],
            &["nas".into()],
            vec![tcp(22)],
            Some("ssh".into()),
        )
        .expect("allowed");
    assert_eq!(id, RuleId(1));
    signed(&site, &mut state);
    let rules = expand_rules(&state).expect("expanded");
    assert_eq!(rules.len(), 1);
    assert!(
        rules[0]
            .from
            .iter()
            .any(|p| p.to_string() == "100.88.0.2/32")
    );
    assert!(rules[0].to.iter().any(|p| p.to_string() == "100.88.0.3/32"));
    let (mac, nas) = (&state.machines[&name("mac")], &state.machines[&name("nas")]);
    let pair = if mac.node_id < nas.node_id {
        (mac.node_id.clone(), nas.node_id.clone())
    } else {
        (nas.node_id.clone(), mac.node_id.clone())
    };
    assert!(connections(&state).contains(&pair));
    let doc = desired(&state, &name("mac")).expect("ok").expect("signed");
    let to_nas = doc
        .paths
        .iter()
        .find(|p| p.peer == nas.node_id)
        .expect("path");
    assert_eq!(to_nas.candidates, [Candidate::Punch]);
    let lines = describe(&before, &state);
    assert!(lines.contains(&"Access rules v1:".to_owned()), "{lines:?}");
    assert!(
        lines
            .iter()
            .any(|l| l.contains("+ r1  mac (100.88.0.2) -> nas (100.88.0.3)  22/tcp  ssh"))
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("mac - nas  punch only; may not connect"))
    );
    // The same rule is not added a second time; numbers are not reused
    assert!(
        state
            .allow(
                &["mac".into()],
                &["nas".into()],
                vec![tcp(22)],
                Some("ssh".into())
            )
            .is_err()
    );
    state.remove_rule(RuleId(1)).expect("removed");
    let next = state
        .allow(&["mac".into()], &["nas".into()], vec![], None)
        .expect("allowed");
    assert_eq!(next, RuleId(2));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn removing_a_machine_revokes_it_and_cleans_up_its_rules() {
    let (_dir_tmp, dir) = temp_dir("remove");
    let (site, mut state) = site(&dir);
    state
        .allow(
            &["mac".into()],
            &["nas".into(), "edge-vps".into()],
            vec![],
            None,
        )
        .expect("r1");
    state
        .allow(&["edge-vps".into()], &["nas".into()], vec![tcp(80)], None)
        .expect("r2");
    signed(&site, &mut state);
    let nas = state.machines[&name("nas")].node_id.clone();
    let before = state.clone();
    state.remove(&name("nas")).expect("removed");
    signed(&site, &mut state);
    assert_eq!(state.revoked.len(), 1);
    assert_eq!(state.revoked[0].node_id, nas);
    // r1 is left with only mac -> edge-vps; r2 is deleted entirely
    assert_eq!(state.rules.len(), 1);
    assert_eq!(state.rules[&RuleId(1)].to.len(), 1);
    let lines = describe(&before, &state);
    assert!(lines.iter().any(|l| l.starts_with("- nas (")), "{lines:?}");
    assert!(lines.iter().any(|l| l.starts_with("  ~ r1")), "{lines:?}");
    assert!(lines.iter().any(|l| l.starts_with("  - r2")), "{lines:?}");
    let doc = desired(&state, &name("mac")).expect("ok").expect("signed");
    assert_eq!(doc.revocations.len(), 1);

    // Adding the same name again: a new node ID and address, without the old rules
    state
        .add(
            name("nas"),
            MachineOptions {
                keys: Some(keys(9)),
                ..MachineOptions::default()
            },
            new_node_id().expect("id"),
        )
        .expect("added again");
    let again = &state.machines[&name("nas")];
    assert_ne!(again.node_id, nas);
    assert_eq!(again.mesh.ipv4.to_string(), "100.88.0.4");
    assert!(
        state
            .rules
            .values()
            .all(|r| r.to.iter().all(|s| s.node != again.node_id))
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn edge_and_routes_selectors_need_their_part_and_go_with_it() {
    let (_dir_tmp, dir) = temp_dir("parts");
    let (site, mut state) = site(&dir);
    assert!(
        state
            .allow(&["edge-vps.edge".into()], &["mac".into()], vec![], None)
            .is_err()
    );
    assert!(
        state
            .allow(&["edge-vps".into()], &["mac.routes".into()], vec![], None)
            .is_err()
    );
    state
        .set_edge(
            &name("edge-vps"),
            Some(vec!["172.17.0.2/32".parse().expect("prefix")]),
        )
        .expect("edge");
    state
        .set_routes(
            &name("mac"),
            vec!["172.30.0.10/32".parse().expect("prefix")],
        )
        .expect("routes");
    state
        .allow(
            &["edge-vps.edge".into()],
            &["mac.routes".into()],
            vec![tcp(8686)],
            None,
        )
        .expect("allowed");
    signed(&site, &mut state);
    assert_eq!(admitted(&state, "mac").members().len(), 3);
    let doc = desired(&state, &name("nas")).expect("ok").expect("signed");
    assert_eq!(doc.advertised_routes.len(), 1);
    let rules = expand_rules(&state).expect("expanded");
    assert_eq!(rules[0].to[0].to_string(), "172.30.0.10/32");
    // Advertised routes cannot overlap the mesh prefixes or other machines' routes
    assert!(
        state
            .set_routes(&name("nas"), vec!["172.30.0.0/24".parse().expect("prefix")])
            .is_err()
    );
    assert!(
        state
            .set_routes(&name("nas"), vec!["100.88.1.0/24".parse().expect("prefix")])
            .is_err()
    );
    // Remove Edge: the rules referencing it are deleted with it
    let mut s = state.clone();
    s.set_edge(&name("edge-vps"), None).expect("removed");
    assert!(s.rules.is_empty());
    // Remove routes: the same
    let mut s = state.clone();
    s.set_routes(&name("mac"), vec![]).expect("removed");
    assert!(s.rules.is_empty());
    assert!(
        state
            .rules
            .values()
            .all(|r| r.from.iter().all(|s| s.part == Part::Edge))
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn policies_close_to_expiry_are_signed_again() {
    let (_dir_tmp, dir) = temp_dir("expiry");
    let (site, mut state) = site(&dir);
    let recovery = site.recovery().expect("recovery");
    let now = Timestamp::now();
    sign(&mut state, &recovery, now, &[]).expect("signed");
    let later =
        Timestamp::from_unix_seconds(now.unix_seconds() + 30 * 24 * 3600 - RESIGN_BEFORE_SECS + 60);
    sign(&mut state, &recovery, later, &[]).expect("signed");
    assert!(
        state
            .machines
            .values()
            .all(|m| m.policy.as_ref().map(|p| p.version) == Some(2))
    );
    // invite: this machine is re-signed even if the time has not come
    let mac = state.machines[&name("mac")].node_id.clone();
    sign(&mut state, &recovery, later, &[mac]).expect("signed");
    assert_eq!(
        state.machines[&name("mac")]
            .policy
            .as_ref()
            .map(|p| p.version),
        Some(3)
    );
    assert_eq!(
        state.machines[&name("nas")]
            .policy
            .as_ref()
            .map(|p| p.version),
        Some(2)
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn inconsistent_machines_are_refused() {
    let (_dir_tmp, dir) = temp_dir("check");
    let (_site, mut state) = site(&dir);
    let add = |state: &mut State, n: &str, opts: MachineOptions| {
        state.add(name(n), opts, new_node_id().expect("id"))
    };
    assert!(
        add(&mut state, "mac", MachineOptions::default()).is_err(),
        "duplicate name"
    );
    // A `public` machine may not know its address yet: with a Hub, the Hub learns it; without a
    // Hub, the command requires it to be given
    add(
        &mut state,
        "pub",
        MachineOptions {
            public: true,
            ..MachineOptions::default()
        },
    )
    .expect("a public machine without an address yet");
    assert_eq!(state.unknown_public_addresses(), vec![&name("pub")]);
    assert!(
        add(
            &mut state,
            "dial",
            MachineOptions {
                port: Some(41900),
                ..MachineOptions::default()
            }
        )
        .is_err()
    );
    // Port 41821 is the probe port on the mesh address
    assert!(
        add(
            &mut state,
            "probe",
            MachineOptions {
                public: true,
                ipv4: Some("203.0.113.20".parse().expect("ip")),
                port: Some(41821),
                ..MachineOptions::default()
            }
        )
        .is_err()
    );
    // Two public machines on the same address and port
    assert!(
        add(
            &mut state,
            "twin",
            MachineOptions {
                public: true,
                ipv4: Some("203.0.113.10".parse().expect("ip")),
                ..MachineOptions::default()
            }
        )
        .is_err()
    );
    assert!(
        add(
            &mut state,
            "twin",
            MachineOptions {
                public: true,
                ipv4: Some("203.0.113.10".parse().expect("ip")),
                port: Some(41822),
                ..MachineOptions::default()
            }
        )
        .is_ok()
    );
    // Changed to dial-only: the public address and port are removed together
    state
        .set(
            &name("twin"),
            MachineChange {
                reachability: Some(Reachability::DialOnly),
                ..MachineChange::default()
            },
        )
        .expect("changed");
    assert!(state.machines[&name("twin")].ipv4.is_none());
    assert!("not a key".parse::<NodeKeys>().is_err());
    assert!("r0x".parse::<RuleId>().is_err());
    assert_eq!("r12".parse::<RuleId>().expect("id"), RuleId(12));
    std::fs::remove_dir_all(&dir).ok();
}

/// Advertising again after all advertised routes were removed: the version keeps increasing. The
/// mesh process remembers the highest version it has seen and only accepts higher ones
/// (design/mesh.md section 4.2).
#[test]
fn advertised_routes_keep_counting_after_they_are_removed() {
    let (_dir_tmp, dir) = temp_dir("routes-version");
    let (site, mut state) = site(&dir);
    let nas = name("nas");
    let version = |s: &State| {
        s.machine(&nas)
            .expect("nas")
            .routes_signed
            .as_ref()
            .map(|r| r.version)
    };
    state
        .set_routes(&nas, vec!["192.168.1.0/24".parse().expect("prefix")])
        .expect("routes");
    signed(&site, &mut state);
    assert_eq!(version(&state), Some(1));
    state.set_routes(&nas, vec![]).expect("no routes");
    signed(&site, &mut state);
    assert_eq!(version(&state), None);
    state
        .set_routes(&nas, vec!["192.168.2.0/24".parse().expect("prefix")])
        .expect("routes again");
    signed(&site, &mut state);
    assert_eq!(version(&state), Some(2));
}

/// Makes `name` wait to join and returns the enrollment key.
fn awaiting(state: &mut State, n: &str) -> nett_trust::signing::EnrollmentKeyPair {
    let key = nett_trust::signing::EnrollmentKeyPair::generate().expect("enrollment key");
    state
        .await_enrollment(&name(n), key.public_key(), 1_900_000_000)
        .expect("await");
    key
}

/// Admission material signed by a new machine with the enrollment private key from the token
/// (design/hub.md section 6).
fn joined(
    state: &State,
    n: &str,
    key: &nett_trust::signing::EnrollmentKeyPair,
    k: NodeKeys,
) -> nett_trust::admission::AdmissionMaterial {
    let m = state.machine(&name(n)).expect("machine");
    let policy = m
        .enrollment
        .as_ref()
        .and_then(|e| e.policy.as_ref())
        .expect("signed policy");
    nett_trust::admission::AdmissionMaterial {
        policy: policy.signed.clone(),
        proof: key
            .sign_proof(&nett_trust::admission::AdmissionProofDoc {
                v: nett_trust::admission::PROOF_V1,
                kind: nett_trust::admission::AdmissionProofKind::AdmissionProof,
                node_id: m.node_id.clone(),
                identity_public_key: k.identity,
                mesh_public_key: k.mesh,
            })
            .expect("proof"),
    }
}

#[test]
fn a_machine_waiting_to_join_gets_a_policy_with_its_enrollment_key() {
    let (_dir_tmp, dir) = temp_dir("pending");
    let (site, mut state) = site(&dir);
    let recovery = site.recovery().expect("recovery");
    state
        .add(
            name("box"),
            MachineOptions::default(),
            new_node_id().expect("id"),
        )
        .expect("add");
    let first = awaiting(&mut state, "box");
    sign(&mut state, &recovery, Timestamp::now(), &[]).expect("sign");
    let version = |s: &State| {
        s.machine(&name("box"))
            .expect("box")
            .enrollment
            .as_ref()
            .and_then(|e| e.policy.as_ref())
            .map(|p| p.version)
    };
    assert_eq!(version(&state), Some(1));
    // Before joining it is not a member: it has no desired state of its own, and other members do
    // not configure it either
    assert!(desired(&state, &name("box")).expect("compose").is_none());
    let mac = desired(&state, &name("mac"))
        .expect("compose")
        .expect("mac");
    assert_eq!(mac.members.len(), 3);
    // Reused when nothing changed; when Edge changed, re-signed with the same enrollment public
    // key; when the token is replaced, a new key is used
    let unchanged = state.clone();
    sign(&mut state, &recovery, Timestamp::now(), &[]).expect("sign");
    assert_eq!(state, unchanged);
    state
        .set_edge(
            &name("box"),
            Some(vec!["172.30.0.2/32".parse().expect("prefix")]),
        )
        .expect("edge");
    sign(&mut state, &recovery, Timestamp::now(), &[]).expect("sign");
    assert_eq!(version(&state), Some(2));
    let old = state.clone();
    let second = awaiting(&mut state, "box");
    sign(&mut state, &recovery, Timestamp::now(), &[]).expect("sign");
    assert_eq!(version(&state), Some(3));
    assert!(
        describe(&old, &state)
            .iter()
            .any(|l| l.contains("a new token to join"))
    );
    // After the replacement, a proof signed by the old enrollment key is not accepted, and the new
    // one is
    assert!(
        crate::updates::record_enrollment(
            &mut state.clone(),
            &joined(&state, "box", &first, keys(7))
        )
        .is_err()
    );
    let material = joined(&state, "box", &second, keys(7));
    assert_eq!(
        crate::updates::record_enrollment(&mut state, &material).expect("recorded"),
        Some(name("box"))
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_recorded_enrollment_makes_the_machine_a_member_without_signing_again() {
    let (_dir_tmp, dir) = temp_dir("enrolled");
    let (this_site, mut state) = site(&dir);
    let recovery = this_site.recovery().expect("recovery");
    state
        .add(
            name("box"),
            MachineOptions::default(),
            new_node_id().expect("id"),
        )
        .expect("add");
    state
        .allow(&["mac".into()], &["box".into()], vec![tcp(22)], None)
        .expect("allow");
    let key = awaiting(&mut state, "box");
    sign(&mut state, &recovery, Timestamp::now(), &[]).expect("sign");
    let material = joined(&state, "box", &key, keys(7));

    let updates = crate::updates::Updates {
        enrolled: vec![material.clone()],
        ..Default::default()
    };
    // The Hub and the site use the same logic: same result, and nothing changes the second time
    let (mut on_hub, mut on_site) = (state.clone(), state.clone());
    assert_eq!(
        updates.apply(&mut on_hub).expect("hub").joined,
        vec![name("box")]
    );
    updates.apply(&mut on_site).expect("site");
    assert_eq!(on_hub, on_site);
    assert_eq!(
        updates.apply(&mut on_site).expect("again"),
        crate::updates::Applied::default()
    );
    let m = on_site.machine(&name("box")).expect("box").clone();
    assert_eq!(m.keys, Some(keys(7)));
    assert!(m.enrollment.is_none());
    // The signing tool does not need to re-sign: the admission material is the one in the token
    let before = on_site.clone();
    sign(&mut on_site, &recovery, Timestamp::now(), &[]).expect("sign");
    assert_eq!(on_site, before);
    // Members accept it
    let mac = desired(&on_site, &name("mac"))
        .expect("compose")
        .expect("mac");
    let mac = DesiredMesh::from_doc(mac).expect("valid");
    let mut members = MemberSet::default();
    let own = OwnPolicy {
        node_id: &mac.node_id,
        now: None,
    };
    members.apply(&mac, &own, &mut VecSink::default());
    assert!(members.get(&m.node_id).is_some());

    // Material signed by another site, or meant for another node, is not accepted
    let (_other_dir_tmp, other_dir) = temp_dir("enrolled-other");
    let (other_site, mut other) = site(&other_dir);
    other
        .add(name("box"), MachineOptions::default(), m.node_id.clone())
        .expect("add");
    let other_key = awaiting(&mut other, "box");
    sign(
        &mut other,
        &other_site.recovery().expect("recovery"),
        Timestamp::now(),
        &[],
    )
    .expect("sign");
    let forged = joined(&other, "box", &other_key, keys(8));
    assert!(crate::updates::record_enrollment(&mut state.clone(), &forged).is_err());
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&other_dir).ok();
}

#[test]
fn learned_addresses_fill_in_for_public_machines_without_one() {
    let (_dir_tmp, dir) = temp_dir("learned");
    let (_site, mut state) = site(&dir);
    state
        .add(
            name("vps"),
            MachineOptions {
                public: true,
                keys: Some(keys(9)),
                ..MachineOptions::default()
            },
            new_node_id().expect("id"),
        )
        .expect("add");
    let vps = state.machine(&name("vps")).expect("vps").clone();
    let mac = state.machine(&name("mac")).expect("mac").clone();
    assert!(crate::compose::candidates(&state, &mac, &vps).is_empty());
    let learned = crate::state::Learned {
        ipv4: Some(crate::state::LearnedIp {
            ip: "198.51.100.7".parse().expect("ip"),
            from: crate::state::AddressSource::Hub,
        }),
        ..crate::state::Learned::default()
    };
    crate::updates::Updates {
        learned: vec![crate::updates::LearnedFor {
            node_id: vps.node_id.clone(),
            learned,
        }],
        ..Default::default()
    }
    .apply(&mut state)
    .expect("applied");
    let vps = state.machine(&name("vps")).expect("vps").clone();
    assert_eq!(
        crate::compose::candidates(&state, &mac, &vps),
        vec![Candidate::Direct {
            endpoint: "198.51.100.7:41820".parse().expect("endpoint")
        }]
    );
    assert!(state.unknown_public_addresses().is_empty());
    std::fs::remove_dir_all(&dir).ok();
}

/// The site of [`site`] with two more public relays, r2 and r1 (r1 gets the smaller node ID), and a
/// rule that connects mac and nas.
fn relay_site(dir: &Path) -> (SiteDir, State) {
    let (site, mut state) = site(dir);
    let mut ids = [new_node_id().expect("id"), new_node_id().expect("id")];
    ids.sort();
    for (n, k, id, ip) in [
        ("r1", 4, ids[0].clone(), "198.51.100.1"),
        ("r2", 5, ids[1].clone(), "198.51.100.2"),
    ] {
        state
            .add(
                name(n),
                MachineOptions {
                    public: true,
                    ipv4: Some(ip.parse().expect("ip")),
                    keys: Some(keys(k)),
                    ..MachineOptions::default()
                },
                id,
            )
            .expect("add relay");
    }
    let key = crate::state::RelayKey([7; 32]);
    let role = |tls: Option<u16>| crate::state::RelayRole {
        port: 41822,
        tls_port: tls,
        fingerprint: tls.map(|_| {
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .parse()
                .expect("fingerprint")
        }),
    };
    state
        .set_relay(&name("r2"), Some(role(Some(443))), key)
        .expect("r2 relays");
    state
        .set_relay(
            &name("r1"),
            Some(role(None)),
            crate::state::RelayKey([8; 32]),
        )
        .expect("r1 relays");
    assert_eq!(
        state.relay_key,
        Some(key),
        "the first relay creates the key"
    );
    state
        .allow(&["mac".into()], &["nas".into()], vec![tcp(22)], None)
        .expect("allow");
    signed(&site, &mut state);
    (site, state)
}

fn path<'a>(
    doc: &'a nett_mesh::config::DesiredMeshDoc,
    state: &State,
    peer: &str,
) -> &'a [Candidate] {
    let id = &state.machine(&name(peer)).expect("peer").node_id;
    &doc.paths
        .iter()
        .find(|p| &p.peer == id)
        .expect("a path to the peer")
        .candidates
}

#[test]
fn connections_go_through_every_relay_udp_first() {
    let (_dir_tmp, dir) = temp_dir("relay-candidates");
    let (_site, state) = relay_site(&dir);
    let id = |n: &str| state.machine(&name(n)).expect("machine").node_id.clone();
    let mac = desired(&state, &name("mac")).expect("ok").expect("signed");
    let nas = desired(&state, &name("nas")).expect("ok").expect("signed");
    let kinds = |c: &[Candidate]| -> Vec<String> {
        c.iter()
            .map(|c| match c {
                Candidate::Direct { endpoint } => format!("direct {endpoint}"),
                Candidate::Lan { endpoint } => format!("lan {endpoint}"),
                Candidate::Punch => "punch".into(),
                Candidate::Relay {
                    relay, endpoint, ..
                } => {
                    format!("udp {} {endpoint}", state.name_of(relay).expect("name"))
                }
                Candidate::RelayTls { relay, address, .. } => {
                    format!("tls {} {address}", state.name_of(relay).expect("name"))
                }
            })
            .collect()
    };
    let expected = [
        "punch",
        "udp r1 198.51.100.1:41822",
        "udp r2 198.51.100.2:41822",
        "tls r2 198.51.100.2:443",
    ];
    assert_eq!(kinds(path(&mac, &state, "nas")), expected);
    assert_eq!(
        kinds(path(&nas, &state, "mac")),
        expected,
        "both ends get the same relays"
    );
    // A relay is never a path to itself; a connection to a relay goes through the other one
    assert_eq!(
        kinds(path(&mac, &state, "r1")),
        [
            "direct 198.51.100.1:41820",
            "udp r2 198.51.100.2:41822",
            "tls r2 198.51.100.2:443"
        ]
    );

    // The relay gets the connections that list it, and the same token as the member
    let r2 = desired(&state, &name("r2")).expect("ok").expect("signed");
    let relay = r2.relay.expect("r2 runs a relay");
    assert_eq!((relay.port, relay.tls_port), (41822, Some(443)));
    let mut pair = [id("mac"), id("nas")];
    pair.sort();
    assert!(relay.links.contains(&pair));
    assert!(
        relay.links.iter().all(|l| !l.contains(&id("r2"))),
        "no link through a relay to itself"
    );
    let mac_on_r2 = relay
        .members
        .iter()
        .find(|m| m.node == id("mac"))
        .expect("mac is a member of the relay");
    assert_eq!(
        mac_on_r2.address, None,
        "a dial-only member binds by its handshake"
    );
    let token_in_candidate = path(&mac, &state, "nas")
        .iter()
        .find_map(|c| match c {
            Candidate::Relay { relay, token, .. } if *relay == id("r2") => Some(token.clone()),
            _ => None,
        })
        .expect("mac's candidate through r2");
    assert_eq!(mac_on_r2.token, token_in_candidate);
    let edge_on_r2 = relay
        .members
        .iter()
        .find(|m| m.node == id("edge-vps"))
        .expect("edge-vps is on r2's links");
    assert_eq!(
        edge_on_r2.address,
        Some("203.0.113.10:41820".parse().expect("address")),
        "a public member is bound to its address"
    );
    // Tokens differ per member and per relay
    let other = relay
        .members
        .iter()
        .find(|m| m.node == id("nas"))
        .expect("nas");
    assert_ne!(other.token, mac_on_r2.token);
    for n in ["mac", "nas", "r1", "r2", "edge-vps"] {
        admitted(&state, n);
    }
    assert!(
        desired(&state, &name("mac"))
            .expect("ok")
            .expect("signed")
            .relay
            .is_none()
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn relays_need_a_public_machine_and_their_own_port() {
    let (_dir_tmp, dir) = temp_dir("relay-checks");
    let (_site, mut state) = site(&dir);
    let role = |port| crate::state::RelayRole {
        port,
        tls_port: Some(443),
        fingerprint: None,
    };
    let key = crate::state::RelayKey([1; 32]);
    assert!(
        state
            .set_relay(&name("mac"), Some(role(41822)), key)
            .is_err()
    );
    assert!(
        state
            .set_relay(&name("edge-vps"), Some(role(41820)), key)
            .is_err()
    );
    assert!(
        state
            .set_relay(&name("edge-vps"), Some(role(41821)), key)
            .is_err()
    );
    assert_eq!(
        state.relay_key, None,
        "a refused change leaves the site as it was"
    );
    state
        .set_relay(&name("edge-vps"), Some(role(41822)), key)
        .expect("relay");
    let to_dial_only = MachineChange {
        reachability: Some(Reachability::DialOnly),
        ipv4: Some(None),
        ..MachineChange::default()
    };
    assert!(
        state.set(&name("edge-vps"), to_dial_only).is_err(),
        "a relay keeps its machine public"
    );
    // Without a fingerprint there is no TLS path yet
    state
        .allow(&["mac".into()], &["nas".into()], vec![tcp(22)], None)
        .expect("allow");
    signed(&_site, &mut state);
    let mac = desired(&state, &name("mac")).expect("ok").expect("signed");
    assert!(
        path(&mac, &state, "nas")
            .iter()
            .all(|c| !matches!(c, Candidate::RelayTls { .. }))
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn relay_changes_are_listed_with_the_paths_they_change() {
    let (_dir_tmp, dir) = temp_dir("relay-describe");
    let (site, mut old) = site(&dir);
    old.allow(&["mac".into()], &["nas".into()], vec![tcp(22)], None)
        .expect("allow");
    signed(&site, &mut old);
    let mut new = old.clone();
    new.set_relay(
        &name("edge-vps"),
        Some(crate::state::RelayRole {
            port: 41822,
            tls_port: Some(8443),
            fingerprint: Some(
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .parse()
                    .expect("fingerprint"),
            ),
        }),
        crate::state::RelayKey([2; 32]),
    )
    .expect("relay");
    let lines = describe(&old, &new);
    assert!(
        lines.contains(&"~ edge-vps runs a relay: UDP 41822, TLS 8443".to_owned()),
        "{lines:?}"
    );
    assert!(
        lines.contains(&"  ~ mac - nas  punch, relay edge-vps (udp, tls)".to_owned()),
        "{lines:?}"
    );
    let mut off = new.clone();
    off.set_relay(&name("edge-vps"), None, crate::state::RelayKey([2; 32]))
        .expect("off");
    let lines = describe(&new, &off);
    assert!(
        lines.contains(&"~ edge-vps stops its relay".to_owned()),
        "{lines:?}"
    );
    assert!(
        lines.contains(&"  ~ mac - nas  punch only; may not connect".to_owned()),
        "{lines:?}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn machines_behind_the_same_nat_connect_over_their_lan() {
    let (_dir_tmp, dir) = temp_dir("lan");
    let (site, mut state) = site(&dir);
    state
        .allow(&["mac".into()], &["nas".into()], vec![tcp(22)], None)
        .expect("allow");
    signed(&site, &mut state);
    let home = crate::state::LearnedIp {
        ip: "198.51.100.7".parse().expect("ip"),
        from: crate::state::AddressSource::Hub,
    };
    let learn =
        |state: &mut State, n: &str, lan: &str, port: u16, nat: crate::state::LearnedIp<_>| {
            let m = state.machine_mut(&name(n)).expect("machine");
            m.learned.ipv4 = Some(nat);
            m.learned.lan = vec![
                lan.parse().expect("lan"),
                "172.17.0.1/16".parse().expect("lan"),
            ];
            m.learned.listen_port = Some(port);
        };
    learn(&mut state, "mac", "192.168.1.10/24", 50001, home);
    learn(&mut state, "nas", "192.168.1.20/24", 50002, home);
    let lan_of = |state: &State, me: &str, peer: &str| {
        let doc = desired(state, &name(me)).expect("ok").expect("signed");
        let id = &state.machine(&name(peer)).expect("peer").node_id;
        doc.paths
            .iter()
            .find(|p| &p.peer == id)
            .and_then(|p| p.candidates.first().cloned())
    };
    assert_eq!(
        lan_of(&state, "mac", "nas"),
        Some(Candidate::Lan {
            endpoint: "192.168.1.20:50002".parse().expect("endpoint")
        }),
        "the LAN path comes first, at the peer's reported port"
    );
    assert_eq!(
        lan_of(&state, "nas", "mac"),
        Some(Candidate::Lan {
            endpoint: "192.168.1.10:50001".parse().expect("endpoint")
        })
    );
    // The same Docker bridge address on both machines is not a LAN between them
    assert!(
        desired(&state, &name("mac"))
            .expect("ok")
            .expect("signed")
            .paths
            .iter()
            .flat_map(|p| &p.candidates)
            .all(|c| !matches!(c, Candidate::Lan { endpoint } if endpoint.ip().to_string() == "172.17.0.1"))
    );
    let line = crate::changes::path_kind(
        &state,
        &state.machine(&name("mac")).expect("mac").node_id,
        &state.machine(&name("nas")).expect("nas").node_id,
    );
    assert_eq!(line, "lan, punch");
    // Behind different NATs the same private network is someone else's
    let elsewhere = crate::state::LearnedIp {
        ip: "203.0.113.99".parse().expect("ip"),
        from: crate::state::AddressSource::Hub,
    };
    learn(&mut state, "nas", "192.168.1.20/24", 50002, elsewhere);
    assert_eq!(lan_of(&state, "mac", "nas"), Some(Candidate::Punch));
    std::fs::remove_dir_all(&dir).ok();
}
