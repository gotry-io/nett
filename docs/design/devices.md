# Devices and the Mobile Gateway

- Status: draft
- Phase: M1, stage 7 (roadmap)
- Related: ADR [0008](../adr/0008-phones-through-mobile-gateway.md), [0018](../adr/0018-client-platforms.md); mesh.md sections 4, 12 and 13; auth.md sections 9 and 10; site.md

## 1. Goal

A phone or a computer that does not run nett joins the mesh with a standard WireGuard client: the user adds it on the computer that holds the site, imports the configuration on the device, and from then on the device reaches the machines its permissions allow through one mobile gateway (ADR 0008). Nothing of nett is installed on the device, and the device's private key exists only in the configuration it imports.

## 2. Scope

| Included | Not included |
|---|---|
| Devices with one WireGuard credential each, added and removed with `nett site device` | More than one credential per device; CONNECT credentials (mesh.md section 5.4) |
| The `gateway` role on a public Linux machine with kernel WireGuard | A gateway on the userspace data plane (DSM, macOS), and a second gateway a credential moves to (mesh.md section 13) |
| Devices that reach every machine, and limited devices that reach only what rules allow (section 5) | Names for devices: the exported configuration carries no DNS server, and devices use mesh addresses |
| Export of a standard WireGuard configuration (file and QR code) | Configurations in the formats of particular apps: a client that takes WireGuard settings in a format of its own, such as a proxy app's WireGuard outbound, is set up from the same fields |
| The devices a gateway serves, with their last handshake, in that gateway's status | Devices in `nett site status` |

## 3. Commands

```
$ nett site device add work --gateway gw --limited
~ gw: mobile gateway for devices
+ work (device, limited), 100.88.0.9, through gw
Sign and push? [y/N] y
Pushed. 7 of 7 machines applied.
Wrote ./work.conf (WireGuard).
It holds the device's private key, and nett keeps no copy: import it, then delete it.
<QR code of work.conf>

$ nett site allow work gw 8081/tcp --note "admin console"
Access rules v14 -> v15:
  + r11  work (100.88.0.9) -> gw (100.88.0.2)  8081/tcp  admin console

$ nett site device add phone
+ phone (device), 100.88.0.10, through gw
Access rules v15 -> v16:
  + phone (100.88.0.10) -> every machine and route  all ports

$ nett site devices
NAME   ADDRESS      GATEWAY  ACCESS
phone  100.88.0.10  gw       every machine
work   100.88.0.9   gw       rules only

$ nett site device remove work
```

- `nett site device add <name>` adds a device with one credential: the signing tool generates the key pair, assigns the next mesh address pair (mesh.md section 3), signs the credential, and writes the exported configuration (section 8). `--limited` makes it reach only what rules allow (section 5);
- **The gateway is chosen with the device**: `--gateway <machine>` names the `public` machine the device joins through. The first device names one; later ones come through the same one unless they name another, and need to name one once devices come through more than one. A credential's gateway is fixed when it is created;
- **A machine is a mobile gateway while devices come through it**: its node policy has the `gateway` role from the first device that names it, signed in the same change, until its last device is removed, when the role goes with it and nett's rule in the system's forwarding chain too (section 6). Machines do not go through gateways. A gateway cannot be removed, or become `dial-only`, while devices come through it;
- `nett site device remove <name>` revokes the device's credential (identity revocation, auth.md section 10.4) and deletes the rules that name it, as `remove` does for a machine (site.md section 5.1);
- `nett site devices` lists the devices with their gateways; `--json` gives the full content;
- Devices and machines share one namespace of names, so rules name either: `nett site allow work gw 8081/tcp`, `nett site allow mac phone 22/tcp`;
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
- **Host firewalls that drop forwarded traffic**: Docker, and firewalls such as ufw, set the policy of the system's `filter FORWARD` chain to drop. An accept in nett's own table does not get past a drop in another table, so the gateway adds one rule at the top of that chain, accepting traffic from `nett0` to `nett0`, when the chain exists in nftables (`iptables-nft`) and drops by default. The rule is written as `iptables-nft` writes `-i nett0 -o nett0 -j ACCEPT`, so iptables, and Docker through it, keep reading the chain, and carries a comment nett finds it by; nett removes it with the gateway's last device and with the mesh interface. nett's own forwarding chain still decides which of that traffic passes. The gateway installs its forwarding again every minute, so a firewall that starts after it (Docker at boot) is covered. A base chain in another nftables table that drops forwarded traffic by default is listed as a problem that names it; `iptables-legacy`, which nett cannot read, is covered in the troubleshooting guide. Tailscale, as a subnet router, inserts its rules into the system's forwarding chain the same way; the rule is listed in release.md section 8;
- **Status**: `nett status` on the gateway lists the devices it serves: name, address, where it last connected from, last handshake, bytes received and sent.

## 7. Other machines

- The gateway's peer gets the addresses of the credentials assigned to it in its `AllowedIPs` (mesh.md section 4), on the kernel and the userspace data plane alike; packets from a device's address are accepted only from its gateway, and replies to it go to the gateway;
- The site composes a connection between the gateway and every machine a device reaches or that may reach a device (site.md section 6), so the gateway has a path to it;
- `nett whois <address>` answers for a device address from the verified credential: the device's name and the gateway it comes through.

## 8. Exported configuration

The signing tool writes the file with mode `0600`, refusing to overwrite an existing file, in the current directory or `--out <dir>`, and prints the QR code of the WireGuard configuration when its output is a terminal. The private key is generated in memory, written only into this file and the QR code, and never stored in the site or sent to the Hub (auth.md section 9).

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

- `AllowedIPs` covers the mesh prefixes and the advertised routes, whatever the device may reach: the rule set decides what passes, and the configuration stays valid when rules change;
- The MTU equals the mesh interface's (1280), so the packets a device sends fit `nett0` when the gateway forwards them;
- The QR code is generated by `qrcodegen` (MIT), with no dependencies of its own, 17 KiB of code in `nett`. It is drawn with light modules as blocks, as `qrencode -t UTF8` does, for a terminal with light text on a dark background; the file imports the same configuration where the code does not scan.

## 9. Compatibility and rollout

- Signed payloads, the pushed site and the desired state reject content they do not recognize (auth.md section 10.5). The new fields appear only once a device exists, so upgrading changes nothing by itself;
- Before signing the first device, the Hub and every machine run the release that adds devices: with a Hub, `nett site device add` reads each machine's version from the Hub and refuse while the Hub or any machine runs an older release, or than the signing tool when that is older still (a machine on the tool's own release knows everything it signs), or has not reported one, naming them. A machine that has never connected joins with the current release. Without a Hub they print which release every machine needs;
- Machines, containers and the Hub get there with `nett site upgrade` (release.md section 7).

## 10. Verification

| Level | Content |
|---|---|
| Unit tests | Signing and verifying a credential; a revoked, overlapping or unsigned credential and one whose gateway lacks the role are rejected alone; the expanded rule for devices covers the mesh prefixes and the routes and leaves limited devices out; removing a device revokes it and strips its rules, and the last one takes its gateway's role; the exported files hold the right keys, addresses and endpoint and are written `0600`; the version check before signing |
| Hub integration tests | A push with a device verifies the credential; a revoked credential never comes back; a device disappears only with a revocation |
| Lab scenario `devices` | Network namespaces with plain `wg` as the devices, a gateway with a Docker-style `filter FORWARD` chain that drops, and a member behind NAT: the device reaches the member and the gateway; a limited device reaches only its allowed port; the member cannot open a connection to the device; after `device remove` the device's traffic stops; with IPv4 forwarding off the gateway lists the problem; the rule added to the `FORWARD` chain goes with the gateway's last device |
| Real machines | gw as the gateway; the work computer reaches the admin console on gw and nothing else; the iPhone with the WireGuard app reaches services at home and the other machines |
