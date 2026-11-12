# Troubleshooting

Start on the machine that misbehaves:

```
sudo nett doctor            # checks this machine and says what to do about each finding
sudo nett status            # every peer: connected or not, the path, round-trip time and loss
sudo nett status <peer>     # one peer's candidate paths and its recent switches
nett ping <peer>            # probes through the tunnel; works whatever the access rules allow
```

On the computer that holds the site, `nett site status` shows every machine as the Hub sees it: online or not, its version, whether it applied the latest change, and any problem it reported.

## A machine is unreachable, or its paths keep switching

- **Cloud security groups**: nett cannot open ports in a provider's console. A `public` machine needs UDP 41820 (WireGuard) open; a relay needs its UDP port (41822 by default) and its TLS port. The list per role is in [design/mesh.md](design/mesh.md) section 5.5. `nett doctor` on a machine that cannot connect points at the port that does not answer.
- **A host firewall that denies incoming connections** (ufw with `default deny incoming`, and similar setups) drops what arrives on `nett0` after nett's own filter lets it in, in-tunnel probes included. The other end then sees this machine as unreachable and keeps switching between direct and relay paths. Allow the interface:

  ```
  sudo ufw allow in on nett0
  ```

  nett filters `nett0` itself and denies everything the access rules do not allow, so this opens nothing more. `nett doctor` and `sudo nett install` say when ufw is in the way.

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
- **A container member on that Mac** (Docker, OrbStack) sends its traffic through the Mac's network stack, where the proxy app's tunnel takes it. Its direct paths to other machines then fail, and it falls back to relays. Exclude the public addresses of the machines it connects to from the proxy app's tunnel (in Surge, `tun-excluded-routes`), then reload the proxy app's configuration: the container member moves back to its direct paths.

## Container members

A container member runs three containers from the same image ([packaging/container/compose.example.yaml](../packaging/container/compose.example.yaml)): the mesh process, nett-node next to it, and the transport adapter in the mesh container's network namespace for paths over TLS. Without the transport container, the member has no TLS fallback when UDP is blocked. A container member does not upgrade itself: `nett site status` reports a newer release as available, and the image is upgraded by pulling or building a new one.

## Upgrades

Machines installed with `sudo nett install` upgrade themselves to a release the Hub announces, after checking its signature ([design/release.md](design/release.md) section 7). When an upgrade fails, `nett site status` shows the reason and `nett doctor` on the machine repeats it; that version is not tried again, and the next release is.

## What to collect for a report

- `sudo nett status --json` and `sudo nett doctor` on the machines involved;
- the logs: `journalctl -u nett-mesh -u nett-node` on Linux, `log show --last 1h --predicate 'process == "nett"'` on macOS (with sudo);
- `nett site status --json` from the computer that holds the site.

None of these contain keys or tokens.
