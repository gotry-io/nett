# Devices and the Mobile Gateway

- Status: draft
- Phase: M1, stage 7 (roadmap)
- Related: ADR [0008](../adr/0008-phones-through-mobile-gateway.md), [0018](../adr/0018-client-platforms.md); mesh.md sections 4, 12 and 13; auth.md sections 9 and 10; site.md

## 1. Goal

A phone or a computer that does not run nett joins the mesh with a standard WireGuard client or a proxy client such as Surge: the user adds it on the computer that holds the site, imports the configuration on the device, and from then on the device reaches the machines its permissions allow through one mobile gateway (ADR 0008). Nothing of nett is installed on the device, and the device's private key exists only in the configuration it imports.

## 2. Scope

| Included | Not included |
|---|---|
| Devices with one WireGuard credential each, added and removed with `nett site device` | More than one credential per device; CONNECT credentials (mesh.md section 5.4) |
| The `gateway` role on a public Linux machine with kernel WireGuard | A gateway on the userspace data plane (DSM, macOS), and a second gateway a credential moves to (mesh.md section 13) |
| Devices that reach every machine, and limited devices that reach only what rules allow (section 5) | Names for devices: the exported configuration carries no DNS server, and devices use mesh addresses |
| Export of a standard WireGuard configuration (file and QR code) and a Surge configuration | mihomo and sing-box configurations |
| The devices a gateway serves, with their last handshake, in that gateway's status | Devices in `nett site status` |

## 3. Commands

```
$ nett site gateway tcloud
~ tcloud: mobile gateway for devices
Sign and push? [y/N] y

$ nett site device add work --limited
+ work (device, limited), 100.88.0.9, through tcloud
Sign and push? [y/N] y
Pushed. 7 of 7 machines applied.
Wrote ./work.conf (WireGuard) and ./work.surge.conf (Surge).
They hold the device's private key, and nett keeps no copy: import one, then delete both.
<QR code of work.conf>

$ nett site allow work tcloud 8081/tcp --note "argus console"
Access rules v14 -> v15:
  + r11  work (100.88.0.9) -> tcloud (100.88.0.5)  8081/tcp  argus console

$ nett site devices
NAME   ADDRESS      GATEWAY  ACCESS
phone  100.88.0.10  tcloud   every machine
work   100.88.0.9   tcloud   rules only

$ nett site device remove work
```

- `nett site gateway <machine>` gives a `public` machine the `gateway` role in its node policy; `--off` takes it away, and is refused while devices use that gateway;
- `nett site device add <name>` adds a device with one credential: the signing tool generates the key pair, assigns the next mesh address pair (mesh.md section 3), signs the credential, and writes the exported configuration (section 8). `--limited` makes it reach only what rules allow (section 5). `--gateway <machine>` chooses the gateway, required only when the site has more than one; the gateway of a credential is fixed when it is created;
- `nett site device remove <name>` revokes the device's credential (identity revocation, auth.md section 10.4) and deletes the rules that name it, as `remove` does for a machine (site.md section 5.1);
- `nett site devices` lists the devices; `--json` gives the full content;
- Devices and machines share one namespace of names, so rules name either: `nett site allow work tcloud 8081/tcp`, `nett site allow mac phone 22/tcp`;
- These are modifying commands like the others (site.md section 7): changes are listed, confirmed, signed and delivered.

## 4. Signed material and the desired state

- **Artifact `device_credential`** (auth.md section 10.1), signed with the recovery key in an `enrollment_policy` payload like the site's other artifacts:

  ```json
  {
    "kind": "device_credential",
    "device_id": "dev_…",
    "credential_id": "dcr_…",
    "public_key": "…",
    "addresses": { "ipv4": "100.88.0.9", "ipv6": "fd…::9" }
  }
  ```

  A credential has no version: it is created once and revoked for good. A new configuration for a device is a new credential with a new ID and a new address;
- **Role `gateway`** in the node policy (auth.md section 10.1). It is the trust that lets a machine send traffic from the addresses of the devices it serves (auth.md section 2);
- **Revocation `device_credential`** by credential ID, kept permanently like a node revocation;
- **Desired state**: a new list `devices`, one entry per credential: the signed credential, the gateway it belongs to and the device's name. The gateway is not signed: it says which `gateway` machine carries the credential, which the Hub may later move between gateways (mesh.md section 13). The name is for display only;
- **Every machine verifies each credential** before using it: the signature, the ID not revoked, the addresses inside the mesh prefixes and overlapping no member or other credential, and the named gateway an admitted member with the `gateway` role. A credential that fails is rejected alone and listed, as a member is;
- **Limits**: at most 256 credentials in a desired state, like members.

## 5. Access

- **Devices that reach every machine** (the default; mesh.md section 12): the signing tool expands them into one allow rule of the signed rule set, from the addresses of these devices to the mesh prefixes and every advertised route, on all ports. Machines enforce the signed rule set as they do now and need no notion of the user's devices;
- **Limited devices** (`--limited`) get no such rule: like a member, a limited device reaches only what a rule names it in;
- **Towards devices**: connections to a device are denied unless a rule allows them, from members and from other devices alike;
- `nett site rules` lists the expanded rule for devices first, without a number, so what devices reach is visible in the same list;
- The rule set is installed on every machine (mesh.md section 12), so the gateway filters the device traffic it forwards and the machine it reaches filters it again.

## 6. The gateway

- **Peers**: each credential assigned to this gateway is a WireGuard peer on `nett0` with the credential's addresses as `AllowedIPs`, no endpoint (the device connects, and the kernel keeps the address it connects from) and no keepalive. Device peers are not members: the path layer does not probe them, switch their paths or ask them to handshake again. Filter rules are installed before peers are added, as for members (hard rule 6);
- **Port**: devices use the machine's WireGuard port; the gateway listens on nothing new. A handshake from a key that is not a configured peer gets no answer;
- **Forwarding**: nett's forwarding chain on `nett0` accepts traffic from `nett0` to `nett0` whose source or destination is a device this gateway serves, and drops the rest of the traffic from `nett0` to `nett0`. Traffic from `nett0` to the machine's own containers (published ports) is not affected;
- **Kernel forwarding**: the gateway needs IPv4 forwarding (`net.ipv4.ip_forward`). nett checks it and does not change it: while it is off, the gateway lists a problem, as a node with advertised routes does (status.md section 6). IPv6 forwarding (`net.ipv6.conf.all.forwarding`) is checked the same way; while it is off, devices reach other machines over IPv4 only, and the gateway's status says so;
- **Host firewalls that drop forwarded traffic**: Docker, and firewalls such as ufw, set the policy of the system's `filter FORWARD` chain to drop. An accept in nett's own table does not get past a drop in another table, so the gateway adds one rule at the top of that chain, accepting traffic from `nett0` to `nett0`, when the chain exists in nftables (`iptables-nft`) and drops by default. The rule carries a mark nett recognizes; nett removes it when the machine stops being a gateway and with the mesh interface. nett's own forwarding chain still decides which of that traffic passes. Where the drop cannot be reached (`iptables-legacy`, a firewall in another table), the gateway lists a problem that names the chain. Tailscale, as a subnet router, inserts its rules into the system's forwarding chain the same way; the rule is listed in release.md section 8;
- **Status**: `sudo nett status` on the gateway lists the devices it serves: name, address, last handshake, bytes received and sent.

## 7. Other machines

- The gateway's peer gets the addresses of the credentials assigned to it in its `AllowedIPs` (mesh.md section 4), on the kernel and the userspace data plane alike; packets from a device's address are accepted only from its gateway, and replies to it go to the gateway;
- The site composes a connection between the gateway and every machine a device reaches or that may reach a device (site.md section 6), so the gateway has a path to it;
- `nett whois <address>` answers for a device address from the verified credential: the device's name and the gateway it comes through.

## 8. Exported configuration

The signing tool writes both files with mode `0600`, refusing to overwrite an existing file, in the current directory or `--out <dir>`, and prints the QR code of the WireGuard configuration when its output is a terminal. The private key is generated in memory, written only into these files and the QR code, and never stored in the site or sent to the Hub (auth.md section 9).

```ini
# work.conf
[Interface]
PrivateKey = …
Address = 100.88.0.9/32, fd…::9/128
MTU = 1280

[Peer]
PublicKey = <the gateway's mesh public key>
Endpoint = <the gateway's public address>:<port>
AllowedIPs = 100.88.0.0/16, fd…::/48, <advertised routes>
PersistentKeepalive = 25
```

```ini
# work.surge.conf: sections to add to a Surge profile
[Proxy]
nett = wireguard, section-name = nett

[WireGuard nett]
private-key = …
self-ip = 100.88.0.9
self-ip-v6 = fd…::9
mtu = 1280
peer = (public-key = …, allowed-ips = "100.88.0.0/16, fd…::/48", endpoint = <address>:<port>, keepalive = 25)

[Rule]
IP-CIDR,100.88.0.0/16,nett,no-resolve
IP-CIDR6,fd…::/48,nett,no-resolve
```

- `AllowedIPs` covers the mesh prefixes and the advertised routes, whatever the device may reach: the rule set decides what passes, and the configuration stays valid when rules change;
- The MTU equals the mesh interface's (1280), so the packets a device sends fit `nett0` when the gateway forwards them;
- The QR code is generated by `qrcodegen` (MIT), a new dependency of the signing tool's path in `nett`, with no dependencies of its own; its size is measured when it is added.

## 9. Compatibility and rollout

- Signed payloads, the pushed site and the desired state reject content they do not recognize (auth.md section 10.5). The new fields appear only once a gateway or a device exists, so upgrading changes nothing by itself;
- Before signing the first `gateway` role or device, the Hub and every machine run the release that adds devices: with a Hub, `nett site gateway` and `nett site device add` read each machine's version from the Hub and refuse while the Hub or any machine runs an older release or has not reported one, naming them. Without a Hub they print which release every machine needs;
- Machines that upgrade themselves get there on their own; container members and the Hub are upgraded by hand (release.md section 7).

## 10. Verification

| Level | Content |
|---|---|
| Unit tests | Signing and verifying a credential; a revoked, overlapping or unsigned credential and one whose gateway lacks the role are rejected alone; the expanded rule for devices covers the mesh prefixes and the routes and leaves limited devices out; removing a device revokes it and strips its rules; the exported files hold the right keys, addresses and endpoint and are written `0600`; the version check before signing |
| Hub integration tests | A push with a device verifies the credential; a revoked credential never comes back; a device disappears only with a revocation |
| Lab scenario `devices` | A network namespace with plain `wg` as the phone, a gateway with a Docker-style `filter FORWARD` chain that drops, and a member behind NAT: the device reaches the member and the gateway; a limited device reaches only its allowed port; the member cannot open a connection to the device; after `device remove` the device's traffic stops; with IPv4 forwarding off the gateway lists the problem; the rule added to the `FORWARD` chain goes when the gateway stops being one |
| Real machines | tcloud as the gateway; the work computer with Surge reaches the argus console on tcloud and nothing else; the iPhone with the WireGuard app reaches services at home and the other machines |

## 11. Open questions

- The Surge syntax in section 8 is checked against the current Surge on iOS and macOS when the export is written.
