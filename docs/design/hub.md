# Joining the Hub: Resident Distribution and Coordination

- Status: draft
- Phase: M1, after local signing (roadmap M1, ADR 0022, 0024)

## 1. Goals

In local signing, the user maintains and signs the whole network on their own computer with `nett site`, and copies the desired state to each machine (local-signing.md). After joining the Hub:

- **Signing still happens on the user's own computer**, and the command line is the only operating interface (ADR 0024, site.md);
- After one change, **each machine automatically receives and applies it**; machines that were offline catch up automatically when they return;
- A new machine **enrolls with one command**, with no copying of public keys or files;
- The user sees **all machines in one place** on their computer;
- The next steps: automatic upgrades, automatically following address changes, relay scheduling, multiple signing devices (section 9).

The root of the manual steps is that there is no channel between the user's computer and each machine, and no resident agent on each machine. The Hub is the end that all machines can reach and that is always online, and nett-node is the agent on each machine.

## 2. Roles

| Role | Where | What it does | Keys held |
|---|---|---|---|
| Signing tool `nett site` | The user's own computer, run on demand | Maintains the site with commands (site.md): assigns addresses and version numbers, computes, displays and signs artifacts locally, pushes them to the Hub; views the status of all machines; generates the enrollment command for new machines | Recovery key (the only trust anchor), the Hub's API token |
| Hub (`nett-hub`) | A `public` host, behind a reverse proxy | Stores signed artifacts and the site model, composes the desired state for each machine and delivers it through the node gateway; aggregates status | Hub identity key (Noise, used only to authenticate the channel), **no key that can sign** |
| nett-node (`nett node`) | Every machine | Enrolls; connects to the Hub; hands the desired state to the mesh process; reports status | Node identity key (Noise) |
| Mesh process (`nett mesh`) | Every member | Unchanged: verifies signatures, versions and revocations, and runs the mesh (mesh.md) | Mesh private key |

The trust relationships are the same as in auth.md section 2: the Hub is a man in the middle, not a root of trust; nodes accept only authorizations that can be verified with the trust anchor. The difference is that the signed payload is computed from the local site state and displayed by the signing tool on the user's computer, not through a page provided by the Hub (ADR 0024).

## 3. How the user uses it

### 3.1 Once: install the Hub and link it with the site

Run the Hub on the Hub host according to section 8 (by default with Compose, together with Caddy), then:

```
# On the Hub host
nett-hub init --url https://hub.example.com
Hub initialized. Link your site from the computer that holds it, within 1 hour:
  nett site link nett_lnk_…

# On the user's computer
nett site link nett_lnk_…
Linked to https://hub.example.com. Pushed 3 machines, access rules v3.
Connect each existing machine with `nett site invite <name>`.
```

The link code contains the Hub address, the Hub identity public key and a one-time random secret (valid for 1 hour, usable once, the same as the initialization link in auth.md section 4.1). `nett site link` validates the Hub's TLS certificate (hard rule 11), proves itself with the one-time secret, hands the trust anchor list to the Hub, and receives in return an API token that belongs to the site, stored in the site directory (`0600`). From then on the Hub accepts only artifacts that can be verified with this trust anchor. Machines already in the site join according to section 3.5.

### 3.2 Changing

Change with the site commands (site.md). With a Hub, push after confirmation:

```
nett site allow mac nas 22/tcp
Access rules v4 -> v5:
  + r5  mac (100.88.0.4) -> nas (100.88.0.6)  22/tcp
Connections:
  + mac - nas  punch only; may not connect
Sign and push? [y/N] y
Pushed. 1 of 2 machines applied.
  nas has not connected yet; `nett site invite nas` connects it
```

- After the push, the Hub composes the desired state of each machine and delivers it, and each machine reports back after applying; the command waits up to 10 seconds and reports the machines that applied, and machines that are not connected catch up automatically once they connect. When a machine rejects the desired state, or problems remain after applying (for example a member's admission material is rejected, `problems` in status.md section 4.1), the reasons are listed machine by machine and the exit code is 1, the same as `nett reload`;
- When the push fails (the Hub is down), the change is still signed and saved in the site directory, and the command reports the push failure with exit code 1; any later modifying command pushes the whole site, delivering the missed changes together. When the same site is pushed again, the Hub does not change the generation;
- The site directory still writes out each machine's desired state file; only for machines that have not yet connected to the Hub does the command suggest copying the file over;
- Without a Hub, the same commands write desired state files, which the user copies to each machine (site.md section 7).

### 3.3 Enrolling a new machine

```
nett site add nas
+ nas (dial-only), 100.88.0.6
Sign and push? [y/N] y
Pushed. 3 of 3 machines applied.
On nas, run within 30 minutes (once):
  curl -fsSL https://nett.gotry.io/install.sh | sh && sudo nett install nett_enr_…
```

- It is one line on every platform. The install script in the first half installs only `nett`: it detects the system and architecture, downloads this version's archive from the project website, verifies it against the SHA-256 written in the script, and installs it so that `nett` is on the path (release.md section 6). The script does not read the token and does not go through the Hub: a compromised Hub cannot change the program that gets installed. The first installation therefore trusts the project website, the same as Homebrew trusting its formula; later upgrades have the node verify the release signature (ADR 0020, section 9 H3). A machine that already has `nett` installed runs only the second half;
- The second half, `sudo nett install <token>`, generates keys on the machine (private keys never leave it), completes enrollment through the Hub, and installs and starts the services of nett-node and the mesh process (sections 6 and 7). Other members then receive its admission material. The user does not copy public keys or sign again: the node policy was already signed at `add`;
- The token contains the enrollment private key, is valid for 30 minutes and usable once. If it has expired or is lost, `nett site invite nas` replaces the enrollment key and prints a new line, and the old one becomes void;
- A machine that can be reached from outside gets `--public`, and the public address can be omitted, to be learned by the Hub (section 5);
- Before enrollment, this machine's `HUB` in `nett site status` is `never`, and `PROBLEMS` states the token's expiry time.

### 3.4 Viewing

```
nett site status
hub     https://hub.example.com, nett-hub 0.3.0
site    4 nodes, access rules v5

MACHINE   ADDRESS     HUB      VERSION  CONFIG   PROBLEMS
edge-vps  100.88.0.1  online   0.3.0    current  -
mac       100.88.0.4  online   0.3.0    current  -
mac-app   100.88.0.3  online   0.3.0    current  -
nas       100.88.0.6  offline  0.3.0    behind   last seen 3h ago

PEER A    PEER B   STATE        PATH                  RTT
edge-vps  mac      connected    direct                9.0 ms
edge-vps  mac-app  connected    direct                8.6 ms
mac       nas      unreachable  relay edge-vps (tls)  -
```

- `HUB` is this machine's connection to the Hub: `online`, `offline`, and `never` when it has never connected; `CONFIG` is its acknowledgment of the latest push: `current` (applied), `pending` (written, but the mesh process has not yet given a result), `rejected`, `behind` (not yet received or not yet acknowledged);
- `nett site status <machine>` shows the details of one machine, the same content as running `nett status` (status.md) on that machine, plus the time it last connected to the Hub;
- When the Hub is down, `nett site status` says it cannot connect, and still lists the machines in the site;
- The listed machine pairs are the connections derived by the site (site.md section 6); each pair's path and round-trip time come from the decider's measurement (mesh.md section 8.3);
- Layout follows architecture.md section 14.3; `--json` outputs the full content.

### 3.5 Machines already running join

Machines from local signing keep their existing keys, addresses and artifact versions, and do not enroll again:

```
nett site invite edge-vps
edge-vps is already a member. On edge-vps, run:
  sudo nett install nett_enr_…
```

The token that a machine that is already a member receives contains no enrollment private key, only the Hub address, the Hub identity public key, the node ID, the fingerprint of the trust anchor list, and, when the Hub uses a self-signed certificate, the certificate's fingerprint: this machine connects to the Hub with its own identity key, and the Hub recognizes it by the identity public key pushed with the site. The token contains no secret, so it has no validity period and can be used repeatedly; all it can do is make a machine that is already a member switch to a different Hub connection, and that step must be run on that machine as root, checking the node ID and the trust anchor (section 7). After that its desired state is received by nett-node from the Hub (section 5), with no manual copying.

## 4. Site and Hub

- **The site state is whatever the user's computer holds**: machines, permissions, address assignments and artifact versions are stored in the site directory (site.md section 8). The Hub keeps a copy of the most recent push;
- **The site directory holds all the signed content of the whole network**: for machines that enrolled through the Hub, the signing tool fetches their admission proofs from the Hub (which contain the identity public key and mesh public key) and records them in the site state. When the Hub is lost, a new Hub gets all machines and permissions with one `nett site link` (section 8.1);
- **Events that happen on the Hub side**: there are three kinds, which the Hub records and applies immediately to its own copy of the site (changing the generation and delivering, without waiting for the site); every later push also applies them to the pushed site first, so a push that has not yet fetched them does not erase them:
  - **Enrollment**: the admission proof a machine hands in (section 6);
  - **Leaving**: when `nett leave` runs on a node, the Hub receives `Leave` and handles this machine as `nett site remove` does: it generates an identity revocation and all members delete it (lowering privileges needs no signature, auth.md sections 8.3 and 10.4); the parts of rules that reference it are deleted from the site, and the signed access rule set is re-signed when the site is (its address is no longer assigned, so staying in the rule set cannot allow any machine);
  - **Learned public addresses** (section 5);

  Each `nett site` command first fetches these from the Hub (`GET /api/v1/site/updates`) and records them into the site state with the same logic (`nett-site`); the signing tool verifies the admission proofs again itself, and lists them in its output. A machine that left is deleted from the site, the rules that reference it are cleaned up, and the access rule set is re-signed with a new version (narrowing, site.md section 4); when the same name is `add`ed again it is a new machine: a new node ID and address, without the earlier rules. The admission material is recorded as the one the machine actually used: if it enrolls after the fetch and before the push, and the site has meanwhile given it a different enrollment key, the enrollment result is still kept, and the new token is then of no use;
- **Contents of a push**: the signed artifacts (node policy, access rule set, advertised routes), revocations, and the unsigned parts (machine name, reachability, public address and port). Connections and candidate paths are derived by the Hub when it composes the desired state (site.md section 6). The Hub verifies the signature and version of each signed artifact, and rejects the whole push when a version is lower than the stored one, or equal to the stored one with different content;
- **Composing the desired state**: the Hub composes the `mesh` partition for each machine from the site model, in the same format as the desired state file of local signing (protocol.md section 6). The composition logic exists only once: the site model and composition move from `nett site` into a library crate (`nett-site`), shared by the signing tool without a Hub and by the Hub;
- **API**: REST + JSON over HTTPS, with OpenAPI (ADR 0003). The resources used in this step are `hub`, `trust`, `nodes`, `enrollment-tokens`, `node-policies`, `access-rules`, `links`, `events` from api-resources.md, and a new `site` (the pushed site model);
- **Endpoints**: `POST /api/v1/link` (the one-time secret from the link code and the trust anchor list, in exchange for the owner token), `PUT /api/v1/site` (push the site state, replying with the generation after the Hub accepts it), `GET /api/v1/site/status` (each machine's connection, version, acknowledgment and local status), `GET /api/v1/site/updates` (enrollments, departures and learned addresses on the Hub side); the node gateway is a WebSocket on `GET /node/v1/connect` (protocol.md). The link code is `nett_lnk_` plus base64url-encoded JSON (Hub address, Hub identity public key, one-time secret, fingerprint of the self-signed certificate), and the join token is `nett_enr_` plus JSON encoded the same way (section 3.5); the enrollment token is the same format with the addition of the enrollment private key (the 32-byte seed of Ed25519) and the expiry time (auth.md section 8.1). When the Hub uses a self-signed certificate (deployments without a reverse proxy, lab topologies), `nett-hub serve --tls-cert --tls-key` terminates TLS itself, and the signing tool and nodes validate the certificate against the fingerprint in the link code and token (hard rule 11);
- **API token**: the token issued to the site at link time, with `kind` `owner`, has all operations on the site. It can push signed artifacts, but the pushed artifacts must still pass signature verification: the token itself cannot approve any change that raises privileges (hard rule 3). The unsigned things it can do are the same as what the Hub can do: revocation (lowering privileges), changing a machine's name, reachability and public address, which affect availability, not privileges.

## 5. Node and Hub

The protocol follows protocol.md: Noise IK over WebSocket, Protobuf messages, desired state delivered by partition and generation. The partitions used in this step are `trust`, `mesh` and `hub_endpoints`; the messages are `Hello`/`Welcome`, `DesiredState`/`StateAck`, `Inventory`, `LinkReport`, `NodeEvent`, `Leave`, `Ping`/`Pong`.

- **Handing to the mesh process**: nett-node writes the `mesh` partition as the mesh process's desired state file (write a temporary file, then rename), then sends a reload request through the local interface (the same request as `nett reload`, status.md section 4.1) and takes back the result: `applied` (with `problems`), `rejected` (with a reason), `busy`, reported to the Hub as `applied`, `rejected` and `pending` of `StateAck` respectively (protocol.md section 5). `problems` is reported with the status; for `busy`, or when the mesh process gives no response (the file is written and it reads it at startup), `pending` is reported, and nett-node asks it to reload once more at the next status read, and reports the result afterwards. The mesh process keeps the authorizations it has accepted and the most recent desired state it accepted whole in its own trust store (mesh.md section 4.2), and applies them first on restart without waiting for nett-node and the Hub (hard rule 8); the desired state file is only input, a rejected file does not become the baseline for verification, and does not restore revoked permissions;
- **The desired state file has one writer**: on a machine that has joined the Hub, only nett-node writes it, and `sudo nett install` does not import from the site directory (section 7); when the user runs `nett reload` it only makes the mesh process reread the same file;
- **Status reporting**: every 15 seconds, and after the desired state is applied, nett-node reads the status once through the local status interface, and when it has changed sends `LinkReport` (each peer's state, path and round-trip time) and `Inventory` (version, platform, addresses). The Hub keeps only the latest one per machine, and events keep the most recent several (section 8);
- **Public addresses**: when a `public` machine has no address stated in the site, the Hub learns it. nett-node reports in `Inventory` the address the machine uses when connecting to the Hub; the Hub also records the source address it sees: behind a reverse proxy it takes the last item of `X-Forwarded-For` (the item added by the nearest proxy), adopted only when the TCP peer is a loopback or private address (that is, the proxy); when terminating TLS itself it takes the TCP peer's address. For each address family: when the one the machine reports is a global unicast address it is used (most VPSes), otherwise the address the Hub sees is used (1:1 NAT cloud hosts whose public address is not on the network card); loopback addresses are not used. When an address changes, the Hub changes the generation and delivers. A stated address always takes precedence; when a member on the Hub host itself connects through a local proxy the Hub cannot see its public address, so it must be stated. Public addresses are not signed, and a wrong one affects only connectivity and does not widen privileges; `nett site status` lists the address used and its source;
- **Offline**: when the Hub or nett-node is down, the mesh runs as usual (architecture.md section 12.2); nett-node reconnects per protocol.md section 8, and catches up by generation after connecting;
- **Hub endpoints**: the address in the enrollment token is a public address that does not go through the mesh; backup endpoints added later also keep at least one that does not go through the mesh (hard rule 8).

## 6. Enrollment

According to auth.md section 8, the signing tool generates the enrollment token in place of the browser:

1. **Signing tool**: `nett site add <machine>` (with a Hub, without `--keys`) assigns a node ID and a mesh address, generates an enrollment key (Ed25519), signs this node's initial policy (which contains the enrollment public key) with the recovery key, pushes it to the Hub together with the token's expiry time, and then prints the token: Hub address, Hub identity public key, node ID, trust anchor list fingerprint, enrollment private key, expiry time, plus the certificate fingerprint when the Hub uses a self-signed certificate. The enrollment private key exists only in the token, and neither the signing tool nor the Hub stores it. `nett site invite <machine>` replaces it with a new enrollment key and increments the policy version; if this machine's Edge or routes are changed before enrollment, the node policy is re-signed with the same enrollment public key and a new version, and the token still works;
2. **Node**: `sudo nett install <token>` generates the identity key and mesh key (existing ones are reused, and are not replaced on retry), signs the admission proof with the enrollment private key, performs the Noise IK handshake with the identity key and the Hub public key in the token, and carries the admission proof in `Hello` (protocol.md section 3.3);
3. **Hub**: when the identity public key in the handshake is unknown and `Hello` carries an admission proof, it is handled as enrollment. The machine with this node ID in the site must be waiting to join and the token must not have expired; the admission proof must be verifiable with the enrollment public key in its node policy, and the identity public key in the proof must be the one used in the handshake. After this passes, the Hub records the admission proof (section 4) and from then on recognizes this machine by its identity public key: when the same machine retries it is recognized directly, and another machine using the token again is rejected, so the token can be used only once; it changes the generation and delivers the admission material (policy + admission proof) to the other members. When it does not pass, it refuses with `ENROLLMENT_REFUSED` and states the reason;
4. **Node**: after receiving the first desired state, it checks that the fingerprint of the trust anchor list in it equals the one in the token and that the node ID is its own, writes the desired state and the Hub configuration, discards the enrollment private key, and installs and starts the services (section 7). After that the mesh process verifies all content against the trust anchor as usual.

Machines that were already members before joining keep the public keys registered in the site (section 3.5); for machines enrolled through the Hub, the public keys are in the admission proof, fetched from the Hub by the signing tool (section 4).

## 7. Processes and privileges on the node

| Process | Identity | Notes |
|---|---|---|
| nett-node | root | Writes the mesh process's desired state file and asks it to reload; later also replaces the executable (upgrade). Listens on no port, executes no shell, does not access Docker (hard rules 1, 2, 9); tokio single thread; idle RSS ≤ 5 MB |
| Mesh process | Unchanged (a dedicated identity on Linux, root on macOS) | Trusts only the desired state it has verified itself; the local status interface accepts only root and itself (status.md section 3), and nett-node connects as root |

- `sudo nett install <token>` does the same thing on both platforms: generates or reuses keys, enrolls first according to section 6 when the token carries an enrollment private key, copies the running `nett` to the fixed location (it does not copy when already running from there), writes the configuration of the two services, saves the Hub configuration (address and Hub identity public key), and starts the services. A machine that is already a member of some site (has a trust store or desired state) does not accept an enrollment token and must first `nett leave`; when the same machine retries the same token it completes as usual. The content of the service configuration has a single source: the macOS launchd configuration is defined in code (release.md section 4), and the Linux unit is a file in `packaging/systemd/`, embedded at compile time;
- Linux: the program is at `/usr/local/lib/nett/nett`, linked from `/usr/local/bin/nett` (release.md section 5); `nett-node.service` starts after `nett-mesh.service`, both are restarted by systemd, and neither depends on the other;
- macOS: the two launchd services `io.gotry.nett.node` and `io.gotry.nett.mesh`, both running the copy in the root-only directory (release.md section 4);
- **Without a Hub**, `sudo nett install` without a token follows release.md section 4 on both platforms: generates keys and prints the line needed by `nett site add --keys`, imports the desired state (on Linux the site directory is usually not on this machine, so use `--config`), writes the mesh process's service and starts it. On Linux this replaces copying the systemd unit by hand;
- **Switching to another Hub**: when a machine that has already joined some Hub runs `sudo nett install <token>`, the trust anchor fingerprint in the token must equal the trust anchor pinned in the local trust store (mesh.md section 4.2): when equal, it switches to the Hub address and identity public key in the token; when different, it refuses, and `nett leave` must come first. This step can be executed only locally as root, and a compromised Hub cannot do it (section 8.1);
- **When the machine has a Hub configuration**, `sudo nett install` without a token only updates the program copy and the service configuration, and restarts the two services when the program changed; it does not import the desired state from the site directory and does not accept `--config` (section 5). Upgrades before H3: run the install script again (the first half of section 3.3), then `sudo nett install`; a computer installed with Homebrew runs `sudo nett install` after `brew upgrade nett`;
- `sudo nett uninstall` stops and deletes the two services, keeping the keys, desired state and Hub configuration, and running `install` again restores it;
- `sudo nett leave` leaves according to auth.md section 8.3: with a Hub configuration it sends `Leave` to the Hub (when it cannot connect within 10 seconds it continues as usual and says that `nett site remove` must be run on the computer); stops and deletes the two services; tears down the mesh interface and filter rules (on Linux, deletes the `nett0` interface and nett's nftables table; on macOS the utun interface disappears when the mesh process exits); deletes the keys, trust store, desired state and Hub configuration. The `nett` program is kept, and this machine can join any network again;
- **Machines without nett's services** (container members, other service managers): `nett join <token> [--dir <directory>]` does what `sudo nett install <token>` does without the services: it creates or keeps the keys, joins or checks the token, and writes `hub.json` and `desired.json` in the directory; `nett mesh` and `nett node` then run with that directory. A container member runs nett-node as a second container from the same image, sharing the configuration directory and the directory of the local socket (`packaging/container/`): one process per container, and nett-node needs no capabilities and no access to Docker (hard rule 1). It does not upgrade the image (release.md section 7): nett-node upgrades only programs installed by `sudo nett install`. `nett leave --dir <directory>` tells the Hub and deletes the keys and configuration there.

## 8. Running the Hub

- A single executable `nett-hub` (ADR 0012): axum, SQLite + sqlx (architecture.md section 10); this step has no frontend (rust-embed and webauthn-rs are not needed);
- **Release and installation**: the `nett-hub` executable (Linux x86_64, aarch64, statically linked) and container image are released together with `nett` and signed the same way (release.md). By default nett-hub and Caddy run with Compose, with Caddy obtaining the certificate; when the Hub host already has a reverse proxy, `nett-hub init` prints the configuration snippet to add (forwarding `/api/v1/` and the WebSocket of `/node/v1/connect` to the Hub), and does not change the user's own configuration;
- When run natively it runs as a dedicated low-privilege user, and it can also run in a container (the Hub does not need access to the host); it listens only locally and is exposed by the reverse proxy (architecture.md section 4);
- Storage: the site model and signed artifacts, each node's identity public key and generation, each machine's latest status, recent events (100 per machine, kept for 30 days), one-time tokens (hashes only). SQLite explicitly sets cache and mmap limits;
- Resources: stable operation ≤ 30-50 MB (hard rule 14); each node's connections, messages and queues have limits (protocol.md section 11);
- Backup and rebuild are in H5 of section 9.

Commands on the Hub host (command line conventions as in architecture.md section 14.3):

| Command | Purpose |
|---|---|
| `nett-hub serve` | The Hub service itself, run by Compose or systemd |
| `nett-hub init --url <address>` | First-time initialization: generates the Hub identity key and prints a one-time link code (section 3.1); when the Hub host already has a reverse proxy, prints the configuration snippet to add |
| `nett-hub reset` | Voids the link with the site: deletes the site, each node's data and tokens, keeps the Hub identity key, so machines that have already joined can still connect afterwards; run `nett-hub init` again to print a new link code |

### 8.1 Replacing the Hub host

Each machine trusts the Hub's address and the Hub's identity public key (pinned at enrollment, auth.md section 8.3). The mesh is not affected; during the host change, only changes cannot be delivered for the time being.

| Situation | Approach |
|---|---|
| The old Hub still works | Stop the old Hub, move its data directory (database and Hub identity private key) to the new host, and point the domain name to the new host: the Hub's identity is unchanged and each machine connects automatically. When the address must change, first add the new address to each machine's `hub_endpoints` through the old Hub (protocol.md section 6), and move it after delivery |
| The old Hub is broken, no backup (before H5) | Run `nett-hub init` on the new host and `nett site link` on the computer: the site directory has all machines and permissions (section 4). Each machine still trusts the old Hub's identity, so run `nett site invite <name>` machine by machine, and run the printed `sudo nett install <token>` on the machine to switch over (section 7); the machine keeps its existing keys and does not enroll again |
| After H5 | Rebuild on the new host from the encrypted backup, and each machine connects automatically (protocol.md section 6.4) |

## 9. Steps

Each step is usable on its own once done.

| Step | Content | After it is done |
|---|---|---|
| **H1 Distribution and status** | Prerequisite: the mesh process's trust store (mesh.md section 4.2), so that what the Hub delivers does not change the baseline of verification. `nett-hub` and the node gateway, release and installation (section 8); the site commands and the `nett-site` library (site.md); `nett site link`, `status`, `invite` (existing machines); `sudo nett install` on both platforms, with or without a token (section 7); nett-node receives the desired state, hands it to the mesh process and reports status | Existing machines join the Hub; changes are delivered automatically; all machines are visible in one place |
| **H2 Enrollment and leaving** | `add` and enrollment of new machines (sections 3.3 and 6); the same one-line enrollment command on all platforms, the install script placed on the project website by the release workflow (release.md section 6); the public address of `public` machines learned by the Hub (section 5); Hub-side enrollments, departures and addresses fetched into the site (section 4); `nett leave` (section 7) | A new machine enrolls with one command on the computer and one on the machine, without copying public keys; a machine that left can enroll again |
| **H3 Upgrade** | The `release` partition: the Hub relays the release manifest from the project website, nett-node downloads the program, verifies the release signature, installs only higher versions, and rolls back on failure (release.md section 7, auth.md section 11.3, ADR 0020) | No need to download and replace machine by machine |
| **H4 Runtime coordination** | Addresses reported by nodes are used for candidate paths (address changes are followed automatically); relay allocation; when both ends are `dial-only`, the switch is relayed through the Hub (`PathSwitch`, mesh.md section 8.4) | A change of home broadband IP or a laptop changing networks does not require regenerating configuration; failed relays are bypassed faster |
| **H5 Availability and multiple devices** | The Hub's encrypted backup pulled by nodes, rebuild manual (architecture.md section 12.3, protocol.md section 6.4); the site state moves to the Hub, and multiple signing devices each use their own key (trust anchor update, auth.md section 11.2) | A broken Hub host can be rebuilt; more than one computer can sign |

Later: the web console and passkeys (ADR 0024), after the site state moves to the Hub (H5), as another frontend on the same API, modifying the same site data as the command line; phone configuration after device credentials and the mobile gateway are implemented (mesh.md section 13), with the `nett site` commands generating the configuration file and QR code (ADR 0008).

## 10. Verification

| Level | Content |
|---|---|
| Unit tests | Composition of the site model (byte-for-byte identical to the desired state file written without a Hub); the Hub's verification of artifacts (wrong signature, version going backward, same version with different content); a token usable once, expiry; enrollment: refused when the admission proof is wrongly signed, when the identity public key differs from the handshake's, and when the machine is not waiting to join; applying Hub-side enrollments, departures and addresses to a pushed site gives the same result as applying them to the site directory; the choice of public address (stated, the machine's global address, the one the Hub sees, loopback); the results of reload (`applied` with problems, `rejected`, `busy`) map to `StateAck`; `install` does not modify the desired state file on a machine with a Hub configuration |
| Hub integration tests | Temporary SQLite, real routes called over HTTP: link, push, permission checks (no token, wrong token) |
| Lab scenarios | Run the Hub in a lab topology: after a push each member applies, and `nett site status` lists all machines and links; when the Hub stops the mesh runs as usual and catches up after changes resume; when the Hub delivers a peer without admission material or an artifact of an old version, all members reject it (roadmap M1 acceptance); enrollment; after one member runs `nett leave` the other members delete it, the site deletes it and cleans up the rules that reference it, and the same name joining again gets a new node ID |
| Resources | nett-node idle RSS ≤ 5 MB; the Hub's steady memory in the lab topology |
| Real machines | One of the user's own `public` hosts as the Hub host; existing members join; then new machines enroll |

## 11. Open questions

| Question | Notes |
|---|---|
| Read permission of the desired state file on Linux (H1) | The mesh process runs with systemd's `DynamicUser` and reads `/etc/nett/desired.json` directly, so this file must be world-readable, and the structure of the whole network is visible to ordinary users on the machine (status.md section 3 deliberately lets only root see it). Options: the mesh process uses a fixed system user and only it can read the file; or nett-node hands the desired state to the mesh process through the local interface, without a file |
| How to confirm a `public` machine can be reached from outside | The learned public address (section 5) is not necessarily reachable from outside (firewall, security group). Option: judge from another member's measurements and show a hint in `nett site status` |
| Choice of Hub host | Needs a `public`, long-term stable host that can use the Hub domain name (architecture.md section 13.5); this is also where it becomes a single point, see H5 |
