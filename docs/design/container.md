# The Container

- Status: draft
- Related: ADR 0016 (one image, one container), ADR 0026 (upgrades from the state directory), release.md sections 3 and 7, hub.md section 7

## 1. Goals

A machine that runs only containers, or a service in a container that should be a member of its own, joins the mesh with one image and one service in its Compose file, the way users of other mesh products expect: the image from the registry, a token in the environment, a volume for its state, and the service sharing the container's network. The container upgrades itself like every machine, without being recreated.

## 2. The image

- `ghcr.io/gotry-io/nett:<version>` and `:latest`, for `linux/amd64` and `linux/arm64`, published by the release workflow (release.md section 3);
- It holds the statically linked `nett` of the release (the signed bare program for `x86_64-unknown-linux-musl` or `aarch64-unknown-linux-musl`) at `/usr/local/bin/nett`, and the CA certificates nett-node uses to fetch the program from the project website; nothing else;
- The entry point is `nett container`; `/var/lib/nett` is a volume.

## 3. Running it

```yaml
services:
  nett:
    image: ghcr.io/gotry-io/nett:latest
    environment:
      # From `nett site add <name>` on the computer that holds the site; read on the first start only
      NETT_TOKEN: nett_enr_…
    volumes:
      - nett-state:/var/lib/nett
    cap_add: [NET_ADMIN, NET_RAW]
    # Only when the host kernel has no WireGuard
    devices: ["/dev/net/tun:/dev/net/tun"]
    restart: unless-stopped

  app:
    image: example/app
    # The service shares the member's network: it listens on the member's mesh address
    network_mode: service:nett
    depends_on: [nett]

volumes:
  nett-state:
```

- The member is the machine named in `nett site add`; its access rules, Edge and routes are set with `nett site` like any other member's (site.md);
- The service listens in the container's network namespace, so members reach it at the member's mesh address, as the access rules allow, and it sees the mesh source address of each connection, an Edge address included (ADR 0015), whether the host is Linux or macOS;
- The service's own published ports keep working beside the mesh, on the host's addresses;
- `docker compose exec nett nett status` shows the member as `nett status` does on a machine (status.md), and `nett diagnose` works the same way.

## 4. Processes

`nett container` is the container's first process (the supervisor). It runs no shell and executes nothing but the program it verified (section 6) with fixed subcommands:

| Process | Capabilities | Notes |
|---|---|---|
| Supervisor (`nett container`) | Keeps only what the mesh process needs, drops the rest when it starts | Starts the others, restarts one that exits after 2 seconds, doubling to at most 30 seconds, reaps every process in the container, and on `SIGTERM` stops them in order (nett-node, then the mesh process) within Docker's stop timeout. Reads nothing from the network |
| Mesh process (`nett mesh`) | `NET_ADMIN`, `NET_RAW`, `NET_BIND_SERVICE` | As on Linux, in the container's network namespace: kernel WireGuard, or the userspace data plane over the TUN device when the kernel has no WireGuard (userspace.md). It carries the TLS transport itself, as on macOS and Synology DSM (ADR 0013): every process in the container runs as root, so an adapter in a process of its own would separate nothing from the mesh private key in the volume |
| nett-node (`nett node`) | None | As on a machine: receives the desired state from the Hub, hands it to the mesh process and upgrades (section 6). It starts no services: there are no relays or adapters to start in the container |

- Every process logs to the container's output, which `docker logs` shows;
- The container does not run nett-relay: a relay runs on a machine (site.md section 4.1);
- The container does not change name resolution: services reach other members by mesh address. The mesh's DNS responder answers on the member's mesh address as on a machine (names-and-diagnostics.md).

## 5. Joining

- **First start**: when the volume holds no Hub configuration, the supervisor runs `nett join` with `NETT_TOKEN` (hub.md section 7) as a process without capabilities: it creates the identity and mesh keys in the volume, enrolls through the Hub and writes the Hub configuration and the desired state. Then it starts the mesh process and nett-node. Without `NETT_TOKEN` it stops and says where the token comes from;
- **Later starts** use the volume alone, before connecting to the Hub (hard rule 8): the mesh process applies the saved desired state while the Hub is away. `NETT_TOKEN` can stay in the Compose file; it is used once, and a used token is refused by the Hub anyway;
- **Switching to another Hub of the same site**: `docker compose exec nett nett join <token>` with the token from `nett site invite <name>` (hub.md section 7), then restart the container together with the services that share its network (`docker compose restart`);
- **Removing the member**: `nett site remove <name>` on the computer, then `docker compose down -v` removes the container and its volume, which is everything the container placed.

## 6. Upgrades

The container upgrades as ADR 0026 decides, in the same container and the same network namespace:

- **Starting**: the image's `nett` looks in `/var/lib/nett` for `nett` and `nett.minisig`. When the signature holds for the release keys built into the image's program and the signed comment names its target and a higher version (release.md section 7), it runs that file, through the open file, as `nett container`; otherwise it runs itself, and deletes the programs in the volume when they are not newer than itself (a newer image was pulled). Every `nett` command in the container (`docker compose exec nett nett status`) runs the same program, so the command matches the services: the image sets `NETT_STATE_DIR=/var/lib/nett`, which tells `nett` where to look;
- **Placing**: once the user has approved a higher release for this member (release.md section 7), nett-node fetches and verifies its program from the Hub or the website as on a machine, writes it to `nett.new` with its signature, keeps the program it replaces as `nett.previous` (with its signature), renames the new one into place and records the upgrade marker. Then it tells the supervisor, which stops nett-node and the mesh process, waits until no other process runs in the container, and runs the image program's check, which runs the new version as the container's first process. WireGuard sessions in the kernel stay up while the mesh process restarts, as on a machine (release.md section 7);
- **Settling**: the new version has settled when nett-node has connected to the Hub, or after five minutes of running. Until then, a process that exits, or a mesh process that does not answer on its local interface within 60 seconds, sends the container through the check again, which counts it as a start; so does the container itself exiting and being started by Docker. After three starts without settling, the check restores `nett.previous` (or, when there is none, runs the image's program), records the version with its reason in `upgrade.json` in the volume, and does not try it again; the next higher version is;
- `nett site status` shows the member's version and its last upgrade problem like any machine's.

## 7. The volume

| File | Contents |
|---|---|
| `identity.key`, `mesh.key` | The member's private keys (`0600`), created at the first start; they never leave the volume |
| `hub.json`, `desired.json`, `state/` | The Hub configuration, the desired state and the mesh process's trust store, as on a machine (release.md section 8) |
| `hub-backup.enc` | The copy of the Hub's encrypted backup (hub.md section 8.2) |
| `nett`, `nett.minisig`, `nett.previous`, `nett.previous.minisig` | The programs the container upgraded to (section 6), only after an upgrade |
| `upgrade.json`, `upgrade-pending.json` | Upgrades that were not installed, and the marker of one that has not settled |

Runtime files (the local sockets in `/run/nett/`) live in the container and go with it.

## 8. Verification

| Level | Content |
|---|---|
| Unit tests | The check: runs the newer verified program; runs itself for a missing, unsigned, wrongly signed, other-target, equal or older program, and deletes those not newer; counts starts and restores `nett.previous` (or itself) after three; a newer installed program deletes the older ones. The supervisor: restarts an exited process with the backoff; before settling, sends the container through the check instead; stops in order on `SIGTERM`; starts `nett join` only without a Hub configuration |
| CI (`container` job, Docker on Linux) | Built from this version and 99.0.0, with a release key generated for the test: the Hub and two containers; each container joins with `NETT_TOKEN`, runs the mesh process and nett-node with only their own capabilities, and a service in one container's network is reached from the other at its mesh address and sees the caller's mesh address; the Hub upgrades itself to 99.0.0 before it relays it, then both containers move to it without being restarted, and the service stays reachable; a signed 99.1.0 that exits at start is rolled back to 99.0.0 after three starts, which `nett site status` shows |
| Real machines | The same on macOS (OrbStack) before the release that ships it; then the Hub host upgrading itself |
