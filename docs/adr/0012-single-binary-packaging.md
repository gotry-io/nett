# 0012. Single node-side executable, run as multiple processes by subcommand

- Status: accepted; the install script part is in 0024
- Date: 2026-10-12

## Context

A node needs the command-line tool, the high-privilege nett-node, and the low-privilege nett-relay. ADR 0001 and 0011 require node and relay to be separate processes with separated privileges. The question is whether they should also be separate install packages.

## Decision

- Only one executable, `nett`, is released for the node side, and it runs as the command line, `nett node`, `nett mesh` (mesh process), `nett transport` (transport adapter), or `nett relay` depending on the subcommand (ADR 0013);
- The Hub is released separately as `nett-hub` and is installed only on the Hub host;
- node, the mesh process, the transport adapter, and relay run as separate system services, each with a different system user and privileges;
- Whether relay runs is decided by the Hub based on node reachability and signed policy, and relay is started and stopped by nett-node, not decided by the installation process;
- The install script and binaries are distributed by the user's own Hub, the script has the Hub public key fingerprint preset, and release packages must carry signatures;
- **The release signing key belongs to the project, not to the user's Hub**. The public keys are embedded into `nett` at build time (two keys, primary and backup, ADR 0020), and nodes use them to verify every release package. The install script itself is provided by the Hub and cannot serve as an independent trust anchor; on first installation, the user can check against the fingerprint published on the project home page;
- **Downgrade protection**: a node automatically accepts only higher versions; a rollback can only go to the version last installed on this machine; other downgrades need a passkey signature;
- On Home Assistant OS it is provided as an add-on: a container image plus an add-on repository (ADR 0017), and the image is signed as well. The add-on is upgraded by HA, not through the `release` partition; downgrade protection is checked at startup.

## Rationale

- One installation and one upgrade, so processes cannot have mismatched versions; when the mesh process has not changed, an upgrade does not restart it (ADR 0013);
- Shared dependencies are stored once, and multiple processes share the code pages of the same file, so disk and memory usage are lower;
- A node changing from `dial-only` to `public` needs no reinstallation;
- Privilege isolation is guaranteed by the running user and privileges, regardless of whether the files are the same;
- Distribution by the Hub keeps nodes from depending on public code hosting platforms, which is more reliable in regions with restricted networks.

## Alternatives considered

- **node and relay as two install packages**: one more installation and upgrade, risk of version mismatch, duplicated dependencies.
- **Merge the Hub into the same file too**: the Hub includes the Web frontend, database, authentication and other code that nodes do not need, which would noticeably enlarge the file on every node.

## Consequences

- The relay process's file contains node code that does not execute; the security boundary relies on the low-privilege user and on not holding the mesh private key;
- The release process needs to sign the executable, and the Hub needs to cache and serve release packages.
