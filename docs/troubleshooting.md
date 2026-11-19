# Troubleshooting

Start on the machine that misbehaves:

```
sudo nett doctor            # checks this machine and says what to do about each finding
nett status                 # every peer: connected or not, the path, round-trip time and loss
nett status <peer>          # one peer's candidate paths and its recent switches
nett ping <peer>            # probes every path now, then through the tunnel; works whatever the access rules allow
```

On the computer that holds the site, `nett site status` shows every machine as the Hub sees it: online or not, its version, whether it applied the latest change, and any problem it reported.

## A machine is unreachable, or its paths keep switching

- **Cloud security groups**: nett cannot open ports in a provider's console. A `public` machine needs UDP 41820 (WireGuard) open; a relay needs its UDP port (41822 by default) and its TLS port. The list per role is in [design/mesh.md](design/mesh.md) section 5.5. `nett doctor` on a machine that cannot connect points at the port that does not answer.
- **A host firewall that denies incoming connections** (ufw with `default deny incoming`, and similar setups) drops what arrives on `nett0` after nett's own filter lets it in, in-tunnel probes included. The other end then sees this machine as unreachable and keeps switching between direct and relay paths. Allow the interface:

  ```
  sudo ufw allow in on nett0
  ```

  nett filters `nett0` itself and denies everything the access rules do not allow, so this opens nothing more. `nett doctor` and `sudo nett install` say when ufw is in the way.
- **DSM's firewall** on a Synology NAS applies to `nett0` too. When it denies what no rule allows, add an allow rule for the mesh prefixes in Control Panel → Security → Firewall; as with ufw, nett's own filter still decides what gets through. `nett doctor` and `sudo nett install` say when DSM's firewall is in the way ([design/dsm.md](design/dsm.md) section 9).

## Names under nett.internal do not resolve

Every machine answers `<name>.nett.internal` for the machines in the site, on its own mesh address ([design/names-and-diagnostics.md](design/names-and-diagnostics.md)). First ask the responder directly; this works on every platform:

```
dig @<this machine's mesh IPv4> <name>.nett.internal
```

If that answers and programs still do not resolve the name, the system resolver does not send the suffix to it:

- **macOS**: `/etc/resolver/nett.internal` should hold `nameserver <mesh IPv4>`; the mesh service writes it. Check with `scutil --dns | grep -A3 nett.internal`.
- **Linux with systemd-resolved**: `resolvectl status nett0` should list the mesh IPv4 as its DNS server and `~nett.internal` as its domain. Programs reach these settings only when `/etc/resolv.conf` points at systemd-resolved's stub (`nameserver 127.0.0.53`). Some images point it at the upstream servers instead; then only `resolvectl query <name>.nett.internal` resolves the names. To use them everywhere, point the file at the stub (this sends every program's queries through systemd-resolved):

  ```
  sudo ln -sf ../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
  ```

- **Linux without systemd-resolved**: nothing routes the suffix; use `dig @<mesh address>` or the mesh addresses.

## A Mac with a proxy app in its enhanced (TUN) mode

- **The native member** binds its sockets to the physical interface, so its WireGuard and probe traffic does not enter the proxy app's tunnel; it works with the enhanced mode on.
- **nett's container on that Mac** (Docker, OrbStack) sends its traffic through the Mac's network stack, where the proxy app's tunnel takes it. Its direct paths to other machines then fail, and it falls back to relays. Exclude the public addresses of the machines it connects to from the proxy app's tunnel (in Surge, `tun-excluded-routes`), then reload the proxy app's configuration: the container moves back to its direct paths.

## Devices through a mobile gateway

- **IPv4 forwarding**: a gateway forwards its devices' traffic, so `net.ipv4.ip_forward` has to be 1; nett checks it and does not change it, and `nett status` on the gateway lists the problem while it is 0 (Docker turns it on when it starts). Without IPv6 forwarding (`net.ipv6.conf.all.forwarding`), devices reach other machines over IPv4 only, and the status says so.
- **A firewall that drops forwarded traffic**: nett adds its accept to the system's `filter FORWARD` chain in nftables, which is where Docker and ufw put theirs. A chain in another nftables table that drops forwarded traffic by default is listed as a problem that names it; accept traffic from `nett0` to `nett0` there. With `iptables-legacy`, which nett cannot read, add `iptables -I FORWARD -i nett0 -o nett0 -j ACCEPT` and keep it across reboots.
- **A device does not connect**: `nett status` on the gateway lists each device with where it last connected from and its last handshake. No handshake means the device does not reach the gateway's WireGuard port (check the cloud security group) or uses a removed configuration.

## The container

nett's image runs as one container ([packaging/container/compose.example.yaml](../packaging/container/compose.example.yaml), [design/container.md](design/container.md)); `docker compose exec nett nett status` and `nett doctor` work there as on a machine, and `docker logs` shows what its processes log.

- **It stops at the first start**: the volume holds no Hub configuration and `NETT_TOKEN` is missing or already used. `nett site invite <name>` prints a new token.
- **The service beside it is not reachable**: the service has to share the container's network (`network_mode: service:nett`) and listen on all addresses or the mesh address, and an access rule has to allow the caller (`nett site allow`). When the nett container is recreated or restarted (Docker restarts it when its first process exits), restart the service too, so that it joins the new network; an upgrade does neither.
- **The mesh interface does not come up**: the container needs `NET_ADMIN` and `NET_RAW`, and `/dev/net/tun` when the host kernel has no WireGuard.

## Upgrades

Machines installed with `sudo nett install`, containers and the Hub upgrade themselves to a release once you approve it with `nett site upgrade` (all of them, or `nett site upgrade <machine>` to try one first), after checking its signature ([design/release.md](design/release.md) section 7); the Hub upgrades first. Until then `nett site status` shows the release as available. When an upgrade fails, `nett site status` shows the reason (for the Hub on its `hub upgrade` line) and `nett doctor` on the machine repeats it; that version is not tried again, and the next release is. A container or Hub whose new version does not settle goes back to the version before it after three starts, without being recreated.

## What to collect for a report

- `nett status --json` and `sudo nett doctor` on the machines involved;
- the logs: `journalctl -u nett-mesh -u nett-node` on Linux, `log show --last 1h --predicate 'process == "nett"'` on macOS (with sudo);
- `nett site status --json` from the computer that holds the site.

None of these contain keys or tokens.
