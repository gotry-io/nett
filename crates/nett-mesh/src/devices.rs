//! Device credentials (design/devices.md section 4). Each credential in the desired state is verified on
//! its own before it is used: the signature, the ID not revoked, the addresses inside the mesh prefixes
//! and taken by no member or other credential, the key used by no member or other credential, and the
//! gateway an admitted member with the `gateway` role. A credential that fails is not used and is
//! reported; the others are not affected.
//!
//! The desired state lists every credential in use: one it no longer lists stops being configured, which
//! only narrows access.

use std::collections::BTreeMap;
use std::net::IpAddr;

use nett_core::id::{CredentialId, DeviceId, NodeId};
use nett_core::name::NodeName;
use nett_trust::admission::Member;
use nett_trust::keys::X25519PublicKey;
use nett_trust::payload::{MeshAddresses, Role};
use nett_trust::revocation::Revocations;

use crate::config::DesiredMesh;
use crate::event::{Event, EventSink};
use crate::members::addresses;

/// A verified device credential and the gateway that carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub credential_id: CredentialId,
    pub device_id: DeviceId,
    pub name: Option<NodeName>,
    pub public_key: X25519PublicKey,
    pub addresses: MeshAddresses,
    pub gateway: NodeId,
}

impl Device {
    pub fn addrs(&self) -> [IpAddr; 2] {
        [
            IpAddr::V4(self.addresses.ipv4),
            IpAddr::V6(self.addresses.ipv6),
        ]
    }
}

/// The device credentials in effect, by credential ID.
#[derive(Debug, Default)]
pub struct Devices {
    devices: BTreeMap<CredentialId, Device>,
}

impl Devices {
    /// Applies the credentials in the desired state; `members` are the admitted members and
    /// `revocations` those in effect, both already updated from the same desired state.
    pub fn apply(
        &mut self,
        desired: &DesiredMesh,
        members: &BTreeMap<NodeId, Member>,
        revocations: &Revocations,
        events: &mut impl EventSink,
    ) {
        let mut devices: BTreeMap<CredentialId, Device> = BTreeMap::new();
        for doc in &desired.devices {
            let verified = match doc.credential.verify(&desired.anchors) {
                Ok(v) => v,
                Err(e) => {
                    events.emit(Event::DeviceRejected {
                        credential_id: None,
                        reason: format!("signature: {e}"),
                    });
                    continue;
                }
            };
            let mut artifacts = verified.payload.artifacts();
            let credential = match (artifacts.next(), artifacts.next()) {
                (Some((_, nett_trust::payload::Artifact::DeviceCredential(c))), None) => c,
                _ => {
                    events.emit(Event::DeviceRejected {
                        credential_id: None,
                        reason: "the signed payload must carry exactly one device credential"
                            .into(),
                    });
                    continue;
                }
            };
            let reject = |reason: String| Event::DeviceRejected {
                credential_id: Some(credential.credential_id.clone()),
                reason,
            };
            if revocations.is_credential_revoked(&credential.credential_id) {
                events.emit(reject("the credential is revoked".into()));
                continue;
            }
            let device = Device {
                credential_id: credential.credential_id.clone(),
                device_id: credential.device_id.clone(),
                name: doc.name.clone(),
                public_key: credential.public_key,
                addresses: credential.addresses,
                gateway: doc.gateway.clone(),
            };
            let in_prefixes = device.addrs().iter().all(|a| match a {
                IpAddr::V4(_) => desired.prefixes.ipv4.contains(*a),
                IpAddr::V6(_) => desired.prefixes.ipv6.contains(*a),
            });
            if !in_prefixes {
                events.emit(reject("the addresses are outside the mesh prefixes".into()));
                continue;
            }
            match members.get(&device.gateway) {
                Some(m) if m.roles.contains(&Role::Gateway) => {}
                Some(_) => {
                    events.emit(reject(format!(
                        "its gateway {} has no gateway role in its node policy",
                        device.gateway
                    )));
                    continue;
                }
                None => {
                    events.emit(reject(format!(
                        "its gateway {} is not an admitted member",
                        device.gateway
                    )));
                    continue;
                }
            }
            // WireGuard allows each key one peer and each address one peer's AllowedIPs
            let taken = device.addrs();
            let member = members.values().find(|m| {
                m.mesh_public_key == device.public_key
                    || addresses(m).iter().any(|a| taken.contains(a))
            });
            if let Some(m) = member {
                events.emit(reject(format!(
                    "its key or addresses already belong to member {}",
                    m.node_id
                )));
                continue;
            }
            let other = devices.values().find(|d| {
                d.credential_id == device.credential_id
                    || d.public_key == device.public_key
                    || d.addrs().iter().any(|a| taken.contains(a))
            });
            if let Some(d) = other {
                events.emit(reject(format!(
                    "its ID, key or addresses already belong to credential {}",
                    d.credential_id
                )));
                continue;
            }
            devices.insert(device.credential_id.clone(), device);
        }
        for (id, device) in &devices {
            if !self.devices.contains_key(id) {
                events.emit(Event::DeviceAdded {
                    credential_id: id.clone(),
                    gateway: device.gateway.clone(),
                });
            }
        }
        for id in self.devices.keys() {
            if !devices.contains_key(id) {
                events.emit(Event::DeviceRemoved {
                    credential_id: id.clone(),
                });
            }
        }
        self.devices = devices;
    }

    pub fn all(&self) -> impl Iterator<Item = &Device> {
        self.devices.values()
    }

    /// The credentials a gateway carries.
    pub fn served_by<'a>(&'a self, gateway: &'a NodeId) -> impl Iterator<Item = &'a Device> + 'a {
        self.devices.values().filter(move |d| d.gateway == *gateway)
    }

    /// The credential an address belongs to.
    pub fn find(&self, address: IpAddr) -> Option<&Device> {
        self.devices.values().find(|d| d.addrs().contains(&address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DesiredMeshDoc;
    use crate::event::VecSink;
    use crate::members::MemberSet;
    use crate::testutil::{self, Mesh, credential_id, device_addresses, node_id};
    use nett_trust::revocation::Revocation;

    fn apply_to(devices: &mut Devices, doc: DesiredMeshDoc, events: &mut VecSink) {
        let desired = testutil::validated(doc);
        let mut members = MemberSet::default();
        members.apply(&desired, &testutil::no_expiry(&desired), events);
        devices.apply(&desired, members.members(), members.revocations(), events);
    }

    fn rejected(events: &VecSink) -> Vec<String> {
        events
            .0
            .iter()
            .filter_map(|e| match e {
                Event::DeviceRejected { reason, .. } => Some(reason.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_credential_carried_by_a_gateway_is_used() {
        let mesh = Mesh::new(&[1, 2]);
        let mut doc = mesh.desired(1, vec![mesh.material(1, 1), mesh.gateway_material(2, 1)]);
        doc.devices = vec![mesh.device(9, 2)];
        let (mut devices, mut events) = (Devices::default(), VecSink::default());
        apply_to(&mut devices, doc, &mut events);
        assert!(rejected(&events).is_empty(), "{:?}", events.0);
        let gateway = node_id(2);
        let served: Vec<_> = devices.served_by(&gateway).collect();
        assert_eq!(served.len(), 1);
        assert_eq!(served[0].addresses, device_addresses(9));
        assert!(devices.find(IpAddr::V4(device_addresses(9).ipv4)).is_some());
    }

    #[test]
    fn each_failing_credential_is_rejected_alone() {
        let mesh = Mesh::new(&[1, 2, 3]);
        let mut doc = mesh.desired(
            1,
            vec![
                mesh.material(1, 1),
                mesh.gateway_material(2, 1),
                mesh.material(3, 1),
            ],
        );
        doc.devices = vec![
            mesh.device(9, 2),
            // its gateway has no gateway role
            mesh.device(10, 3),
            // its gateway is not a member
            mesh.device(11, 4),
            // the addresses of member 3
            mesh.device_at(12, 2, device_addresses(3)),
            // the addresses of the first credential
            mesh.device_at(13, 2, device_addresses(9)),
            // signed with another key
            mesh.forged_device(14, 2),
            // revoked
            mesh.device(15, 2),
        ];
        doc.revocations.push(Revocation::DeviceCredential {
            credential_id: credential_id(15),
        });
        let (mut devices, mut events) = (Devices::default(), VecSink::default());
        apply_to(&mut devices, doc, &mut events);
        assert_eq!(devices.all().count(), 1, "{:?}", events.0);
        assert_eq!(rejected(&events).len(), 6, "{:?}", events.0);
    }

    #[test]
    fn a_credential_dropped_from_the_desired_state_stops_being_used() {
        let mesh = Mesh::new(&[1, 2]);
        let mut doc = mesh.desired(1, vec![mesh.material(1, 1), mesh.gateway_material(2, 1)]);
        doc.devices = vec![mesh.device(9, 2)];
        let (mut devices, mut events) = (Devices::default(), VecSink::default());
        apply_to(&mut devices, doc.clone(), &mut events);
        doc.devices.clear();
        apply_to(&mut devices, doc, &mut events);
        assert_eq!(devices.all().count(), 0);
        assert!(
            events
                .0
                .iter()
                .any(|e| matches!(e, Event::DeviceRemoved { .. }))
        );
    }
}
