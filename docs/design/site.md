# Site: Maintaining the Whole Network with Commands

- Status: draft
- Phase: M1, together with H1 of joining the Hub (hub.md section 9); sites without a Hub use it the same way

## 1. Goals

The user maintains the whole network on their own computer with the `nett site` commands: add and remove machines, set the Edge and advertised routes, add and delete access rules. The command line is the only operating interface (ADR 0024), modeled on ufw: rules are added one at a time, listed with numbers, and deleted by number.

- Each modifying command validates on the spot, lists what will be signed (the addresses and ports after selector expansion), and after confirmation signs and delivers: with a Hub it pushes to the Hub (hub.md section 3.2), without one it writes the desired state file of each node (local-signing.md section 5);
- With or without a Hub, the same commands and the same site state are used;
- Which machines connect to each other is derived from the access rules, and the user does not specify it pair by pair (section 6).

## 2. Division of work

| Content | How maintained | Signing |
|---|---|---|
| Machines: name, reachability, public address and port, relay | `add`, `set`, `relay`, `remove` | Not signed; removal generates a revocation |
| A machine's public keys | Without a Hub, `add --keys`; with a Hub, given to the Hub by the machine when it enrolls (hub.md section 6) | Written into the admission material |
| Permissions: Edge, advertised routes, access rules | `edge`, `routes`, `allow`, `rules remove` | Both widening and narrowing are signed with a new version (section 7) |
| Connections and candidate paths | Derived from the access rules (section 6) | Not signed |

All site content is stored by the tool in the site directory (section 8), and there are no files to edit by hand. Rules are recorded by machine ID: when a machine is removed, the rules that reference it are cleaned up with it, and a machine that later joins with the same name does not inherit them (section 4).

## 3. Commands

| Command | Purpose |
|---|---|
| `nett site init` | Create the site: recovery key, trust anchor list, mesh prefixes (section 8) |
| `nett site add <machine>` | Add a machine (section 4) |
| `nett site set <machine>` | Change a machine's reachability, public address and port |
| `nett site relay <machine>` | Run a relay on a `public` machine, or stop it with `--off` (section 4.1) |
| `nett site remove <machine>` | Remove a machine, cleaning up the rules that reference it |
| `nett site invite <machine>` | Prepare what an added machine needs to enroll: with a Hub, prints the enrollment command (hub.md sections 3.3 and 3.5); without one, re-signs and rewrites its desired state file |
| `nett site edge <machine>` | Set this machine's Edge sources (section 5.2) |
| `nett site routes <machine>` | Set the routes this machine advertises (section 5.2) |
| `nett site allow` | Add an access rule (section 5.1) |
| `nett site rules` | List access rules; `nett site rules remove <number>` deletes one |
| `nett site status` | List all machines; with a Hub, adds each one's online status and the path between each pair of machines (hub.md section 3.4) |
| `nett site link` | Link with the Hub (hub.md section 3.1) |

- Run only on the computer that holds the site, as an ordinary user, without `sudo`; the site directory defaults to `$XDG_CONFIG_HOME/nett` (`~/.config/nett` when unset), and `--dir` can place it elsewhere;
- Modifying commands (`add`, `set`, `relay`, `remove`, `edge`, `routes`, `allow`, `rules remove`) list the changes, confirm, sign and deliver according to section 7; when not on a terminal, `--yes` is required;
- Viewing commands (`rules`, `status`) output the full content with `--json`.

## 4. Machines

```
$ nett site add edge-vps --public --ipv4 203.0.113.10 --keys "…"
+ edge-vps (public, 203.0.113.10:41820), 100.88.0.1
Sign? [y/N] y
Wrote the desired state for edge-vps in ~/.config/nett/nodes/<machine>/desired.json.
```

- **Name**: lowercase letters, digits and `-`, at most 63 characters (status.md section 5), unique within the site. The name is used for display and to refer to the machine in commands, and is not used as the basis of identity;
- **Reachability**: `--public` means it can be reached from outside, and other members connect to it at its public address; when omitted it is `dial-only`, which only connects outward (mesh.md section 2). A `public` machine states its public addresses with `--ipv4` and `--ipv6`; with a Hub they can be omitted and the Hub learns them (hub.md section 5), the site records the learned address and its source, and once an address is stated the stated one takes precedence;
- **Port**: the WireGuard port of a `public` machine defaults to `41820`, and `--port` uses another one (for example when the same host has two `public` members). The port cannot be one the mesh process itself uses on the machine: the probe port `41821` on the mesh address (mesh.md section 7.2) and the loopback ports of the TLS relay (`41830`-`41845`, mesh.md section 5.3); the WireGuard socket binds all local addresses, and when they coincide the one that binds later fails. The port of a `dial-only` machine is assigned by the system (mesh.md section 5.5), and no port or public address is given;
- **Public keys**: without a Hub, `--keys` is required and is the line printed by `nett keys` on the machine (`sudo nett install` on macOS). With a Hub it is omitted: the command signs the node policy and prints the line to run on the new machine (hub.md section 3.3), the public keys are given to the Hub by the machine when it enrolls, and the signing tool fetches them afterwards (hub.md sections 4 and 6). Until it enrolls, the machine is in the waiting to join state: `invite` replaces the token with a new one, and `remove` removes it as usual;
- **Adding** assigns a node ID and a mesh address and signs its node policy; addresses are not reclaimed (mesh.md section 3). `set` changes reachability, public address and port; these are not signed, and are likewise listed and confirmed first, then delivered;
- **Removal** (`remove`) lowers privileges and is never blocked for any other reason: when a machine is compromised, removal must take effect immediately. The tool generates an identity revocation, all members delete this machine, and no version of a signed artifact can restore it (auth.md section 10.4); the parts of rules that reference it are deleted with it (section 5.1) and listed in the output:

  ```
  $ nett site remove nas
  - nas (node_01JD…): every member drops it
  Access rules v5 -> v6:
    - r5  mac (100.88.0.4) -> nas (100.88.0.6)  22/tcp
  Connections:
    - mac - nas
  Sign? [y/N] y
  ```

- Running `add` again later with the same name creates a new machine: a new node ID and address, without the earlier rules, Edge and routes. When a machine leaves by itself (`nett leave`, auth.md section 8.3), it is handled the same way (hub.md section 4).

### 4.1 Relays

```
$ nett site relay edge-vps --tls 8443
~ edge-vps runs a relay: UDP 41822, TLS 8443
Connections:
  ~ mac - nas  punch, relay edge-vps (udp, tls)
Sign and push? [y/N] y
```

- A relay forwards ciphertext between members that cannot reach each other directly, or when the direct path is worse (mesh.md section 5). It runs on a `public` Linux machine as the separate service nett-relay, which holds no mesh key and has no management privileges (hard rule 1);
- `--port` sets the UDP relay port (default `41822`); `--tls <port>` also serves the TLS transport on that TCP port (default `443`, mesh.md section 5.3), `--no-tls` serves UDP only. When a reverse proxy already holds 443 on the machine, pick another port (mesh.md section 5.3). `--off` stops the relay; the paths through it go away from every connection;
- The relay creates its own TLS certificate the first time it starts; the members check it by fingerprint. With a Hub, the Hub learns the fingerprint from the machine's status, and the TLS candidates appear after that; without a Hub, give it with `--fingerprint` from `sudo nett status` on that machine;
- Being a relay is not signed: a relay sees only ciphertext, and a wrong relay affects connectivity, not privileges. The probe token between each member and each relay (mesh.md section 7.2) is derived from the site's relay key (section 8), so the site and the Hub compute the same tokens and store none of them.

## 5. Permissions

### 5.1 Access rules

```
$ nett site allow edge-vps.edge mac-app.routes 8686/tcp --note "web app"
Access rules v3 -> v4:
  + r4  edge-vps.edge (100.88.0.130) -> mac-app.routes (172.30.0.10/32)  8686/tcp  web app
Sign? [y/N] y

$ nett site rules
ID  FROM           TO              PORTS     NOTE
r2  edge-vps.edge  mac             3000/tcp
r4  edge-vps.edge  mac-app.routes  8686/tcp  web app

$ nett site rules remove r2
```

- **Selectors**: `<machine>` is its mesh address, `<machine>.edge` is its Edge address, and `<machine>.routes` is the routes it advertises; when one side has several, separate them with commas, for example `mac,nas`. Selectors are expanded in the signing tool, and the signed artifact contains the expanded addresses and ports (mesh.md section 12);
- **Ports**: `<port>[-<port>]/<tcp|udp>`, several separated by commas; when omitted it means all ports, and the change listing says `all ports`;
- **Note**: `--note` describes what the rule is for; it is stored only in the site and does not go into the signed artifact;
- **Number**: `r1`, `r2`, ... assigned in the order of addition and not reused after deletion, so a number always refers to the same rule;
- **Allow only, no order**: a rule that matches allows the connection, rules do not affect each other, and adding or deleting one does not require considering position. The signed artifact format supports deny rules and ordered matching (mesh.md section 12); the signing tool generates only allow rules, arranged by number;
- **Referenced things disappear**: when a machine referenced by a rule is removed, or its Edge or routes are removed, the selectors in the rule that reference it are deleted with it; when one side is left empty, the whole rule is deleted. These are all narrowing and are listed in the same change;
- Deleting a rule is narrowing and is signed with a new version (section 7); it is likewise listed and confirmed first: deleting the wrong rule would cut off a service in use.

### 5.2 Edge and advertised routes

```
$ nett site edge edge-vps 172.17.0.2/32
$ nett site routes mac-app 172.30.0.10/32
```

- **Edge**: give the address of the container where the Edge runs (ADR 0015, local-signing.md section 6). This machine's node policy gets the `edge` role, and a pair of Edge addresses is assigned;
- **Advertised routes**: this machine's node policy gets the `subnet_router` role, and the routes are signed separately as a versioned artifact (auth.md section 10.5). Routes cannot overlap the mesh prefixes or the routes advertised by other machines;
- Each time, the machine's complete list is written; `--none` removes it. The node policy and the advertised routes are then signed with a new version (section 7), and when removed, the rules that reference it are cleaned up according to section 5.1.

## 6. Connections

When the desired state is composed (with a Hub, the Hub composes it with the same logic, hub.md section 4), the following rules decide which machines connect to each other:

1. **Every pair of machines involved in an access rule**: each selector on either side of a rule corresponds to one machine (`<machine>`, `<machine>.edge` and `<machine>.routes` all correspond to the machine itself), a connection is established between each pair across the two sides, except a machine with itself;
2. **Every `dial-only` member with all `public` members**: used to determine the NAT type and mapped address (mesh.md section 6.1), and also redundancy on failure (architecture.md section 12.3);
3. The candidate paths of each connection are generated per mesh.md section 6: when one end is `public`, the other end connects directly to its public address (generated separately when there are IPv4 and IPv6 addresses); when both ends are `dial-only`, hole punching is used for a direct connection; with a Hub, a LAN direct path when both ends report addresses in the same LAN prefix behind the same public address; and through every relay other than the two ends (section 4.1), in the order of the relays' node IDs, UDP before TLS, until the connection has 6 candidates. Both ends get the same relays, and each relay gets the connections that list it.

- A connection is only a channel: access is still decided by the rules, denied by default (ADR 0023). There is no connection between two machines that no rule involves, and in `nett status` this pair is `no path`;
- A connection with both ends `dial-only` and no relay in the site has only hole punching candidates: when both ends are behind symmetric NAT it cannot be punched through (mesh.md section 6.1). The change listing says `punch only; may not connect` for such a connection, and suggests `nett site relay`;
- When rules change, connections are added or removed accordingly and listed in the same change:

  ```
  $ nett site allow mac nas 22/tcp
  Access rules v4 -> v5:
    + r5  mac (100.88.0.4) -> nas (100.88.0.6)  22/tcp
  Connections:
    + mac - nas  punch only; may not connect
  Sign? [y/N] y
  ```

## 7. Changing, signing and delivery

Each modifying command: read the site state → compute the state after the change and validate → list the changes → confirm → sign → deliver → save the site state.

- **What is listed is what is signed**: the addresses and ports after selector expansion, the artifact version changes, and the connections and members added or removed; widened items are marked with `+`, narrowed ones with `-`, and other changes with `~`;
- **Signing**: artifacts whose content changed get their version incremented by one and are re-signed; unchanged ones keep their original signature, which nodes treat as idempotent (auth.md section 10.2); a signed node policy less than 7 days from expiry is re-signed with a new version (local-signing.md section 5);
- **Narrowing**: removing a machine generates an identity revocation (auth.md section 10.4); deleting a rule or removing an Edge or routes re-signs with a higher version. Nodes only increase versions (mesh.md section 4.2), and replaying an old signed artifact cannot restore narrowed permissions;
- **Delivery**: with a Hub, push to the Hub and wait for the machines to apply it (hub.md section 3.2); without one, rewrite `nodes/<machine>/desired.json` for every machine whose desired state changed, and list these machines and how to apply it (local-signing.md section 5);
- When validation fails, the whole command makes no change and says what is wrong;
- The site directory is locked, and only one modifying command runs at a time.

## 8. Site directory

```
$ nett site init
Created a site in ~/.config/nett.
recovery.pk8 signs everything in this network. Back it up offline now:
without it, every machine has to leave and join again.

Next, for each machine:
  1. On the machine, create its keys:
       macOS  sudo nett install
       Linux  sudo nett keys --dir /etc/nett
  2. Here: nett site add <name> --keys "<the printed line>"
     (with --public --ipv4 <address> when other machines connect to it)
  3. Allow what may connect: nett site allow <from> <to> <ports>
```

- When `init` creates the directory, its mode is set to `0700`. The mesh prefixes are fixed at creation and cannot be changed later: IPv4 is `100.88.0.0/16`, and IPv6 is a randomly generated ULA `/48` (mesh.md section 3);
- The directory contains: the recovery key `recovery.pk8` (`0600`, read only when signing); the site state `state.json`: the trust anchor list, mesh prefixes, the machines (node ID, name, reachability, address and port, public keys, Edge, routes, signed artifacts and versions), access rules (number, selectors, ports, note, plus the expanded signed rule set and version), revocations, assigned addresses, and the relay key (32 random bytes, created with the first relay, from which the probe tokens are derived, section 4.1); without a Hub there are also the generated desired states `nodes/<machine>/desired.json`;
- Backing up this directory is enough, and the recovery key gets a separate offline backup (local-signing.md section 3). With a Hub, the Hub keeps a copy of the most recent push, and the admission proofs of machines that enrolled through the Hub are also fetched and stored here (hub.md section 4); the site state is whatever this directory holds.

## 9. Verification

| Level | Content |
|---|---|
| Unit tests | The change each modifying command makes to the site state and the listed changes; no change when validation fails; numbers are not reused; when a machine is removed or an Edge or routes are removed, the rules that reference it are cleaned up, and a new machine with the same name gets a new node ID and address and none of the old rules; derivation of connections (every pair involved in a rule, `dial-only` to all `public`, candidate paths); the split between widening and narrowing; unchanged artifacts keep their original signature; no modification when not on a terminal and without `--yes`; the generated desired state is accepted by the mesh process |
| CI | The macOS install flow (release.md section 4) adds the local machine with `nett site add` |
| Real machines | After an existing site is switched to command-based maintenance, the versions of signed artifacts, the addresses and the connections in each member's desired state stay the same |
