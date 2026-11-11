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

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("nett-site-lib-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    dir
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

/// 一个站点：public 的 edge-vps，dial-only 的 mac 与 nas。
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

/// 一台机器的期望状态能被组网进程接受，它的成员都能验证。
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
    let dir = temp_dir("init");
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
    let dir = temp_dir("add");
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
    // public 一端没有候选，由 dial-only 的机器连过来
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
    // 没有规则涉及 mac 与 nas：两台 dial-only 之间没有连接
    assert_eq!(mac.paths.len(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn signatures_stay_until_their_inputs_change() {
    let dir = temp_dir("keep");
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
    let dir = temp_dir("rules");
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
    // 同样的规则不加第二遍；编号不复用
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
    let dir = temp_dir("remove");
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
    // r1 只剩 mac -> edge-vps；r2 整条删除
    assert_eq!(state.rules.len(), 1);
    assert_eq!(state.rules[&RuleId(1)].to.len(), 1);
    let lines = describe(&before, &state);
    assert!(lines.iter().any(|l| l.starts_with("- nas (")), "{lines:?}");
    assert!(lines.iter().any(|l| l.starts_with("  ~ r1")), "{lines:?}");
    assert!(lines.iter().any(|l| l.starts_with("  - r2")), "{lines:?}");
    let doc = desired(&state, &name("mac")).expect("ok").expect("signed");
    assert_eq!(doc.revocations.len(), 1);

    // 同一个名字再加入：新的节点 ID 和地址，没有原来的规则
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
    let dir = temp_dir("parts");
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
    // 宣告的网段不能与组网网段或其他机器的网段重叠
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
    // 去掉 Edge：引用它的规则随之删除
    let mut s = state.clone();
    s.set_edge(&name("edge-vps"), None).expect("removed");
    assert!(s.rules.is_empty());
    // 去掉网段：同样
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
    let dir = temp_dir("expiry");
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
    // invite：没到时间也重签这一台
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
    let dir = temp_dir("check");
    let (_site, mut state) = site(&dir);
    let add = |state: &mut State, n: &str, opts: MachineOptions| {
        state.add(name(n), opts, new_node_id().expect("id"))
    };
    assert!(
        add(&mut state, "mac", MachineOptions::default()).is_err(),
        "duplicate name"
    );
    // `public` 机器可以还不知道地址：接了 Hub 时由 Hub 得知，不接 Hub 时命令要求写明
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
    // 端口 41821 是组网地址上的探测端口
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
    // 同一个地址和端口上的两台 public 机器
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
    // 改成 dial-only：公网地址与端口一起去掉
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

/// 宣告网段全部去掉之后再宣告：版本接着增加。组网进程记着见过的最高版本，只接受更高的
/// （design/mesh.md 第 4.2 节）。
#[test]
fn advertised_routes_keep_counting_after_they_are_removed() {
    let dir = temp_dir("routes-version");
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

/// 让 `name` 等待入网，返回入网密钥。
fn awaiting(state: &mut State, n: &str) -> nett_trust::signing::EnrollmentKeyPair {
    let key = nett_trust::signing::EnrollmentKeyPair::generate().expect("enrollment key");
    state
        .await_enrollment(&name(n), key.public_key(), 1_900_000_000)
        .expect("await");
    key
}

/// 新机器用 token 中的入网私钥签的准入材料（design/hub.md 第 6 节）。
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
    let dir = temp_dir("pending");
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
    // 入网之前它不是成员：没有自己的期望状态，别的成员也不配置它
    assert!(desired(&state, &name("box")).expect("compose").is_none());
    let mac = desired(&state, &name("mac"))
        .expect("compose")
        .expect("mac");
    assert_eq!(mac.members.len(), 3);
    // 没有变化时沿用；Edge 变了用同一把入网公钥重签；换 token 时换一把
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
    // 换过之后原来的入网密钥签的证明不被接受，新的可以
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
    let dir = temp_dir("enrolled");
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
    // Hub 与站点用同一份逻辑：结果相同，第二次什么都不变
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
    // 签名工具不用重签：准入材料就是 token 那一份
    let before = on_site.clone();
    sign(&mut on_site, &recovery, Timestamp::now(), &[]).expect("sign");
    assert_eq!(on_site, before);
    // 成员都接受它
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

    // 别的站点签的材料、给别的节点的材料都不接受
    let other_dir = temp_dir("enrolled-other");
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
    let dir = temp_dir("learned");
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
        ipv6: None,
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
