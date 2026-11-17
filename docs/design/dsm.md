# Synology DSM Member

- Status: draft
- Phase: M1, stage 6 (roadmap)

## 1. Goal

A Synology NAS on DSM 7 joins the mesh as a member, installed natively, upgraded by nett-node, started at boot and removed without leftovers. Other members reach the services on the NAS at its mesh address according to the access rules; an Edge that forwards origin traffic to a service on the NAS listening on a wildcard address is seen by the service as the Edge address, not a loopback address (hard rule 7).

## 2. Scope

| Included | Not included |
|---|---|
| The userspace data plane on Linux, chosen when the kernel has no WireGuard (DSM, old kernels) | The smart gateway on DSM: advertised LAN prefixes, source NAT by source class (mesh.md section 10, roadmap stage 8) |
| Service management on DSM: units that systemd 219 understands and a boot task | nett-relay on DSM, and batched I/O in the userspace data plane, which comes before a userspace member is reachable from outside (userspace.md section 9) |
| Installation, upgrades, uninstall and leave on DSM | Names under `nett.internal` on the NAS itself: DSM has no systemd-resolved, so `nett resolver` does nothing there |
| The TLS transport on DSM (section 7) | |

## 3. What DSM 7 allows

The design rests on these properties of DSM 7 (7.4 is the reference; section 10 checks the ones marked there):

- The kernel is old (4.4 on many models) and has no WireGuard module; the `tun` module is present, and `/dev/net/tun` is recreated as `root` `0600` at every boot;
- systemd is version 219. It has no `AmbientCapabilities`, `DynamicUser`, `LoadCredential`, `ProtectSystem=strict`, `ReadWritePaths` (it has the older `ReadWriteDirectories`), `MemoryMax` (it has `MemoryLimit`), `StateDirectory`, `RuntimeDirectoryPreserve` or the `+` prefix for privileged start steps, and it is built without seccomp. It accepts a directive it does not know with only a warning, so a unit can look confined and not be;
- Third-party packages run as a package user, never as root, and DSM refuses capabilities a package requests unless Synology signs it. Package services are one-shot wrappers that systemd does not restart;
- There is no `useradd`; the accounts DSM can create are DSM accounts that show in the control panel;
- Tasks in Task Scheduler survive DSM updates; a boot-up task runs from a one-shot unit and must return. `/usr/syno/sbin/esynoscheduler` creates, lists and deletes tasks from the command line; it is not documented by Synology;
- DSM's firewall filters traffic on every interface, a TUN interface included, and DSM rewrites the whole iptables filter table when its settings change and when containers start or stop;
- DSM loads the kernel's TUN driver (`/lib/modules/tun.ko`) only for packages that need it, such as Virtual Machine Manager, so at boot it can come after nett, or never;
- The journal is kept in memory only (`Storage=volatile`) and is small: the log of a boot is gone within minutes. A data plane failure stays visible in `nett status` and `nett site status` while it lasts (mesh.md section 15);
- Volumes survive DSM updates; for custom files under `/etc` and `/usr/local`, section 10 measures it.

## 4. Installation

The same two steps as on other Linux machines (hub.md section 3.3): the install script puts the program in `/usr/local/lib/nett/nett` with the link `/usr/local/bin/nett` (release.md section 6), then `sudo nett install <token>`. SSH has to be enabled in DSM, and the user has to be in the `administrators` group to use `sudo`.

`nett` recognizes DSM by `/etc.defaults/VERSION` and then uses the DSM layout below; the rest is the Linux code. There is no DSM package: a package cannot run as root or hold the capabilities a TUN needs, so it would need the boot task of section 6 anyway and add a package user and a Package Center entry on top. Comparable products need the same root step: Tailscale's package asks the user to add a root boot task, NetBird installs with its Linux install script and a boot task.

## 5. Data plane

- The mesh process uses kernel WireGuard when the kernel provides it, and otherwise the userspace data plane with the Linux TUN backend (userspace.md). It decides when it starts: a kernel that has no WireGuard family and no module to load for it gets the userspace data plane, and any other failure stays an error. The log records the choice and `nett status` shows it ("userspace WireGuard"). The same rule serves Linux with old kernels;
- Filtering happens in the mesh process before a packet reaches the TUN (userspace.md section 5), so it also comes before any destination NAT the system does, for example Docker's published ports (hard rule 6). nett adds no iptables rules on DSM: DSM rewrites the filter table at any time, so rules there would not hold. Nor are there nftables tables, which only the kernel data plane makes: `nett uninstall` and `nett leave` do not touch nftables where kernel WireGuard is missing, and DSM's kernel, which has no nftables, does not even answer such a request;
- The TUN interface `nett0` belongs to the mesh process and goes away when it exits: a restart of the mesh process interrupts mesh traffic until it is up again, as on macOS.

## 6. Services

### 6.1 Units and identities

Two units, `nett-mesh.service` and `nett-node.service`, DSM variants of the Linux ones in `packaging/systemd/dsm/`, written to `/usr/local/lib/systemd/system` by `sudo nett install` and refreshed by nett-node after upgrades (release.md section 7). They use only directives systemd 219 knows; a test checks this against the list from that version (section 10).

Both run as root with a bounded capability set, and nett creates no accounts on DSM:

- the mesh process keeps `CAP_NET_ADMIN` (TUN, addresses, routes), `CAP_NET_RAW` (binding the in-tunnel probe socket to `nett0`, which needs it before Linux 5.7) and `CAP_NET_BIND_SERVICE` (the DNS responder on UDP 53 of the mesh address); nett-node keeps `CAP_DAC_OVERRIDE`, as on Linux;
- each sees the file system read-only except its own directories (`ReadOnlyDirectories=/` with `ReadWriteDirectories=`): a root process without `CAP_DAC_OVERRIDE` can still write any file root owns, so the read-only view is what confines it. The mesh process writes the trust store and `/run/nett`; nett-node writes `/etc/nett`, the program directory and the unit directory;
- a non-root service with `CAP_NET_ADMIN` would need a system account, which DSM cannot create; capabilities set on the program file would reach every `nett` command any user runs, since nett is one program, and replacing the program in an upgrade would drop them;
- the mesh private key is read from `/etc/nett/mesh.key` directly; `/etc/nett` is owned by root with mode `0700`.

The units have no `[Install]` section and no ordering on `network-online.target`: the boot task starts them (section 6.2), and both processes already wait for the network themselves (the mesh process applies its saved configuration first, nett-node retries the Hub).

### 6.2 Starting at boot

- `sudo nett install` creates one boot-up task in Task Scheduler named `nett`, run as root, whose command is `/usr/local/lib/nett/nett install`. That is the command a machine with a Hub configuration already runs to repair itself (hub.md section 7): it writes the units that are missing or differ from the program's copies and starts the services, and then returns. systemd owns and restarts the services; the task holds nothing;
- The task is the only way the services start at boot, so a DSM update that drops custom units does not keep nett down: the next boot writes them again;
- Before starting the services, `nett install` makes sure the TUN device opens. When it does not, nett loads `/lib/modules/tun.ko` with the `finit_module` system call, creates `/dev/net/tun` (root, `0600`) when the kernel did not, and stops before starting anything when the device still does not open; no package and no external program is involved. The driver stays loaded until the next restart, since other software may use it too. Should the device appear late anyway, the mesh process creates its interface on a retry (mesh.md section 15);
- nett calls `esynoscheduler` by absolute path, with arguments as an array and a timeout (hard rule 9), and checks the task list after each change. When creating the task does not work, `sudo nett install` stops before starting anything and prints the steps to create it in Control Panel → Task Scheduler; once it exists, the next `sudo nett install` finds it. When the tool is missing, nett cannot check, and prints the same steps as a warning. `sudo nett uninstall` and `sudo nett leave` delete the task first, so a restart in the middle does not start nett again.

## 7. TLS transport

The mesh process carries the TLS transport on DSM, as on macOS (mesh.md section 5.3, ADR 0013). On Linux the transport adapter runs as a user systemd allocates for it, which systemd 219 cannot do, and an adapter running as root would share its user with the mesh process and could read that process's memory, so it would separate nothing. The forwarding is the transport adapter's code, configured from the mesh process's worker, the same as on macOS.

## 8. Upgrades

As on Linux (release.md section 7): nett-node verifies the release, replaces `/usr/local/lib/nett/nett`, restarts the mesh service with `systemctl` and refreshes the units from its own copies. Nothing depends on file capabilities, so replacing the program loses no permission. The boot task names the program path, which stays the same across versions.

## 9. DSM's firewall

DSM's firewall applies to `nett0`. When it drops what the mesh process lets in, other members see the NAS as unreachable, the same as a host firewall on Linux that denies incoming connections (troubleshooting.md). nett does not change DSM's firewall settings: `nett doctor` and `sudo nett install` read them from `/usr/syno/etc/firewall.d/` and say when they are in the way and which rule to add in Control Panel → Security → Firewall.

## 10. Verification

| Level | Content | Where |
|---|---|---|
| Unit tests | Preparing TUN (nothing to do, load the driver, create the device, stop when it still does not open); the choice of data plane (a missing WireGuard family means userspace, any other failure stays an error); the DSM units contain only directives systemd 219 implements, from a list taken from its source, and the units for current systemd fail that check; the DSM units' capability sets and read-only view; the boot task's command and how the task list is read | CI |
| Lab scenarios | The userspace data plane runs the lab scenarios (userspace.md section 8) | Linux, CI |
| Virtual DSM | Install from a published release; reboot; the bounded capability sets in `/proc/<pid>/status`; routes on `nett0` stay after setup; DSM's firewall with and without an allow rule; two upgrades in a row; a DSM update: what remains of the program, the units, the boot task and `/etc/nett`; uninstall, then leave, leaves nothing; idle private memory and PSS of both services (hard rule 14); throughput to another member | A Virtual DSM on Synology hardware |

## 11. Open questions

| Question | Notes |
|---|---|
| Where the identity lives | `/etc/nett`, as on Linux, unless the DSM update in section 10 removes it; then it moves to a volume, which DSM updates leave alone |
