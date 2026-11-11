# 0014. The mesh member table is built from signed artifacts

- Status: accepted
- Date: 2026-11-04

## Context

ADR 0006 states that raising privileges must be signed by the user, nodes verify independently, and the Hub is only an intermediary. If the public keys of mesh members, advertised routes and access rules were delivered by the Hub through the desired state without members verifying them, a compromised Hub could add an attacker's public key as a new member, or point a LAN prefix at the attacker; under default-allow access rules, the attacker could reach all members and the home LAN. This is the same problem as with Headscale, where "a compromised control server can add nodes and change the ACL", and it is exactly what ADR 0006 sets out to avoid.

Two related requirements: the enrollment handshake uses Noise IK, which needs the full Hub public key rather than a fingerprint; and a one-time key that the Hub could see would not prove that "this node is really the one the user authorized".

## Decision

**A member establishes WireGuard sessions only with peers whose signature chain it can verify; the Hub carries signed artifacts and cannot produce them itself.**

Enrollment:

1. The signing tool on the user's computer allocates a node ID and a mesh address and generates a one-time enrollment signing key pair (Ed25519) (ADR 0024, design/hub.md section 6);
2. The initial node policy contains the node ID, mesh address, modules and the enrollment public key, signed with the recovery key;
3. The token carries: the Hub address, the **full Hub identity public key**, the trust anchor list fingerprint, and the enrollment private key. The Hub sees only the enrollment public key;
4. At enrollment the node generates an identity key and a mesh key, signs `{node ID, identity public key, mesh public key}` with the enrollment private key to form the **admission proof**, and then discards the enrollment private key;
5. The Hub verifies the admission proof with the enrollment public key in the policy, then distributes "signed policy + admission proof" to the other members as this member's admission material.

The chain a member verifies:

| Peer attribute | Proven by |
|---|---|
| A node's mesh public key and mesh address | trust anchor → signed node policy containing the mesh module → admission proof |
| A device's mesh public key and mesh address | trust anchor → signed artifact of `device.add` or `device_credential.create` |
| LAN prefixes in `AllowedIPs` | trust anchor → signed artifact of `node.advertise_routes` |
| Edge address (ADR 0015) | trust anchor → the `edge` role and address assignment in the signed node policy |
| Access rules | trust anchor → signed artifact of the whole rule set (members, addresses and ports after selector expansion), with a version number that only increases |

- Removing a member, revoking a prefix and narrowing rules all lower privileges; the Hub may deliver them directly without a signature. Members persist them as **revocations**: removed nodes and revoked credentials are rejected permanently by ID; a narrowing can only be superseded by a signed artifact with a higher version; a replayed old signed artifact from the Hub cannot restore privileges. Members delete a peer only because of a revocation; a member missing from a full snapshot is not treated as revoked (auth.md section 10.4);
- Admission material may be distributed to a newly joined member long after approval. When a member verifies another member's admission material, it does not check the approval's expiry time, only the signature, the version and the revocations; approvals that were cancelled or expired without execution are invalidated by revocations (auth.md section 10.2);
- Candidate paths, relay assignments and hostnames involve no privileges and are still delivered directly by the Hub; the worst case is a broken connection or detoured traffic, and the content is always encrypted. Hostnames and the Hub's `whois` interface are only claims by the Hub and cannot serve as proof of identity; when the peer's identity must be confirmed, the local machine answers from the verified admission material (mesh.md section 11).

## Rationale

- All a compromised Hub can do to the mesh is "disconnect it": it cannot add members, widen access or hijack prefixes, consistent with ADR 0006. This assumes the user's signing device is not compromised (auth.md section 2);
- The enrollment private key appears only in the token and on the node, so the Hub cannot replace the node's public key;
- Once the token carries the full Hub public key, both enrollment and routine connections can use IK, needing a single round trip.

## Alternatives considered

- **The user signs each node public key one by one after enrollment** (similar to Tailnet Lock): the same security, but every new node needs an extra passkey operation, and a node cannot join the mesh before it is signed.
- **Switch to Noise XX at enrollment**: a fingerprint alone would suffice, but it only solves the handshake problem and not the member admission problem.
- **Keep trusting the member table delivered by the Hub**: simplest to implement, but signed authorization would be meaningless on the mesh.

## Consequences

- The enrollment token gets longer (about 52 more characters for the public key);
- Each member stores and verifies the admission material of all peers. For 50 members this is about tens of KiB, counted toward the memory limit for mesh state;
- When the Hub is rebuilt from a backup, admission material is restored with the database and members do not need to re-enroll; when the backup is behind the nodes, nodes send back the signed artifacts and revocations already in effect (protocol.md section 6.4);
- A revocation takes effect only on members that received it. A compromised Hub can withhold a revocation from members that never received it (for example members that join later);
- Device credentials (`device_credential.create`), advertised routes and access rules must all be delivered as signed artifacts, and the action catalog in changes.md is adjusted accordingly.
