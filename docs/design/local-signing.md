# Local Signing

- Status: draft
- Phase: M1, after the prototype gate and before joining the Hub (roadmap M1, ADR 0022)

## 1. Goals

Replace the WireGuard tunnels the user configured by hand with nett, without waiting for the Hub, nett-node and the console. A typical example: the Edge on a VPS reaches back through a tunnel to a container service on a Mac at home (ADR 0015, 0016).

Signing, verification and mesh behavior are the same as after joining the Hub: the user signs and nodes verify independently. The Hub is only a forwarder of signed artifacts (auth.md section 2); here the signing tool on the user's own computer generates the artifacts, and the user copies the files to the nodes.

## 2. Scope

| Included | Not included |
|---|---|
| The signing tool `nett site`, running on the user's own computer: generates the recovery key and the trust anchor list, assigns addresses, signs node policy, advertised routes and access rule sets, generates a desired state file for each node; maintains the site with commands (site.md) | Hub, nett-node, console, passkey, automatic upgrade |
| `nett mesh --config` in the official build: reads the local desired state file and reloads on `SIGHUP` | Device credentials, mobile gateway, hostnames and DNS, CONNECT |
| `nett keys`, which generates keys on the node (on macOS done by `sudo nett install`) | Native macOS member, DSM, Home Assistant OS |
| Access control (mesh.md section 12), the Edge address (ADR 0015), a container member acting as the smart gateway of the container network it lives in (mesh.md section 10, ADR 0016) | |
| Deployment: the systemd unit on Linux (`packaging/systemd/nett-mesh.service`); the container image and Compose example for container members (`packaging/container/`) | |

Candidate paths, relays and transports are the same as in the prototype (mesh.md sections 5-9).

## 3. Trust and keys

| Key | Where generated | Storage |
|---|---|---|
| Recovery key (ECDSA P-256), the only trust anchor | `nett site init`, the user's own computer | Private key file in the site directory, mode `0600`, read only when signing; keep an offline backup |
| The node's mesh private key (X25519) and identity private key (X25519) | `nett keys`, on the node itself | On the node itself, mode `0600`, never leaving the node (hard rule 10); only the public keys are given to the signing tool |
| Enrollment key (Ed25519, auth.md section 8) | `nett site add`, one per node | Not stored: discarded after the admission proof is signed |

- The trust anchor list (auth.md section 11.1) contains only the recovery key, with no passkey. The console address (`origin`) can be set with `nett site init --origin`; when it is not yet known it is `https://nett.invalid`, and when joining the Hub the recovery key signs one trust anchor update that changes it to the console address (auth.md section 11.2);
- The recovery key is equivalent to the console's recovery key: leaking it hands over all control; losing it means no new authorizations can be issued, the trust anchor can only be rebuilt, and all nodes must enroll again. Keep the site directory on an encrypted volume and keep an offline backup of the private key file;
- The admission proof is signed by the enrollment private key over the node ID, identity public key and mesh public key; the node policy is bound to the enrollment public key and signed by the recovery key. The artifact formats are the same as when enrolling through the Hub, and other members verify along the same chain (mesh.md section 4.1).

## 4. Site

The site is maintained with the signing tool's commands (site.md): machines, Edge, advertised routes and access rules, with connections derived from the access rules. Without the Hub:

- When adding a machine, give the public keys with `--keys`, that is, the line printed by `nett keys` on the machine (`sudo nett install` on macOS); for a `public` machine, give the public address (site.md section 4);
- Each modifying command rewrites `nodes/<machine>/desired.json` for the machines whose desired state changed, and the user copies it to the machine (section 5).

## 5. Distribution and updates

- Each modifying command rewrites the desired state file of the nodes whose desired state changed (site.md section 7); its format is the same as the `mesh` partition that nett-node hands to the mesh process after joining the Hub (protocol.md section 6). The file contains no private keys. A machine's first desired state fixes its trust anchor (mesh.md section 4.2) and must be delivered over a trusted channel; later updates carry signatures, and the mesh process verifies them against the pinned trust anchor and the effective version, so they can travel over untrusted channels;
- The user copies the file to the node, replaces the old one, runs `nett reload` and sees whether it was accepted (status.md section 4.1); a container member uses `docker exec <container> /nett reload`; on macOS `sudo nett install` imports and reloads (release.md section 4);
- The expiry of a signed payload is 30 days after generation: the node checks it when it first accepts its own node policy (auth.md section 10.2), so copy it to the node within 30 days of generation; when it has passed, `nett site invite <machine>` re-signs its node policy and rewrites its file. A node policy that was signed at generation and is less than 7 days from expiry is re-signed with a new version;
- The mesh process verifies signatures, versions and revocations as usual. Parts that fail verification are not applied, the effective state stays unchanged, and an event is recorded (hard rules 3-6).

## 6. Access control, Edge and container members

Implemented according to mesh.md section 12 and ADR 0015, 0016. The approach in this phase:

- **Filtering**: nftables on Linux, attached to `prerouting` with a priority before Docker's destination NAT, matching traffic entering from `nett0`. Rules are installed first, then peers are added; when a rule update fails, access stays denied;
- **Edge**: `nett site edge` specifies the subnet of the container where the Edge runs (site.md section 5.2). For traffic from these sources to the mesh, the source address is replaced with the Edge address, and this translation takes effect before Docker's source masquerading. In both directions, local output and container forwarding, packets whose source is the Edge address but which do not come from the Edge are dropped. Every container in this subnet is treated as the Edge, so specify only the Edge container's own address, or a container network used only by the Edge;
- **Advertised routes**: other members add them to the `AllowedIPs` of this node's peer and add routes on the mesh interface;
- **Container member**: it is the smart gateway of the container network it lives in (ADR 0016). The container uses a fixed address in the network, enables forwarding in its own network namespace (`sysctls` in Compose), and advertises the fixed addresses of the services. It forwards only connections that come from the Edge address and are allowed by the access rules, replacing the source with its own address on the outgoing interface, that is, its fixed address in the container network; a service that needs the real IP configures this address as a trusted proxy. Forwarding from other sources is dropped (the "ordinary address" that the smart gateway prepares for other sources, ADR 0015, is left to be implemented when the LAN is connected). The container runs with `NET_ADMIN` and `NET_RAW`; the service keeps its own network, and restarting the container member does not affect the service. A fixed address belongs only to the running container: when `docker compose run` is used to run a one-off task for the container member or the service (generating keys, pre-deployment checks, migrations), the temporary container inherits the same address and conflicts with the running container (Docker reports the address is already in use), so such tasks run in a temporary container with no network (`docker run --network none`, or override `network_mode: none` for that run only).

## 7. Replacing an existing tunnel

- **Prepare in parallel**: the new mesh uses its own port and prefix (`41820`, `100.88.0.0/16`), so it does not interfere with the old tunnel; confirm that both ends connect and the access rules take effect before switching;
- **Switch**: pin the service to its address in the container network, change the trusted proxy to the container member's address, and change the Edge upstream to the service's address;
- **Roll back**: change the Edge upstream back to the old address. Keep the old tunnel's configuration until verification passes;
- Before executing anything on the user's machines, list the commands and the rollback method and get the user's confirmation (CLAUDE.md "Privacy and operating boundaries").

## 8. Verification

The scenario `nett-lab run access` of experiment A (`crates/nett-lab/topologies/access.toml`, run in CI on every push): a member running the Edge (with a "container" behind it, which the member source-masquerades like Docker), a container member behind a cone NAT (with a service behind it, advertising its address), and an ordinary member; the access rules allow only the Edge to reach one port of this service. Pass criteria:

- The Edge can connect to the allowed port of the service, and the source the service sees is the container member's address;
- The Edge reaching other ports, the member hosting the Edge itself, and the ordinary member reaching this service are all denied;
- A member that forges routes and `AllowedIPs` and sends packets to an address not advertised behind the container member has them dropped by the container member (simulating a compromised member);
- Members with no allowing rule cannot reach each other, and those with an allowing rule can; in-tunnel probes are not affected by the access rules;
- Packets sent from the member hosting the Edge with the Edge address as source do not appear on other members' mesh interfaces;
- The rule sets of all members are in effect, with no data plane failures.

## 9. When joining the Hub

When joining the Hub, the same recovery key, trust anchor version, assigned addresses and artifact versions are kept, and nodes do not enroll again (hub.md section 3.5).

## 10. Open questions

| Question | Notes |
|---|---|
| Protection of the recovery key | Beyond file permissions, whether to encrypt it with a passphrase or put it in a hardware key (auth.md section 14) |
| Advertised routes overlapping the local network | Before a member adds a route on the mesh interface, whether to check that it does not overlap a network directly connected to the machine (when it overlaps, the machine's traffic to that network would be drawn into the mesh); currently the signing tool only checks overlap with the mesh prefixes and with other nodes' routes |
