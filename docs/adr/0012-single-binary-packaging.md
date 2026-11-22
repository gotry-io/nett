# 0012. Single node-side executable, run as multiple processes by subcommand

- Status: accepted; the install script part is in 0024
- Date: 2026-10-12

## Context

A node needs the command-line tool, the high-privilege nett daemon (the mesh and nett-node, ADR 0013), and the low-privilege nett-relay. ADR 0001 and 0011 require the daemon and the relay to be separate processes with separated privileges. The question is whether they should also be separate install packages.

## Decision

- Only one executable, `nett`, is released for the node side, and it runs as the command line, `nett daemon` (the nett daemon: the mesh, the TLS transport and nett-node, ADR 0013), `nett relay`, or `nett container` (the first process of nett's image, ADR 0016) depending on the subcommand;
- The Hub is released separately as `nett-hub` and is installed only on the Hub host;
- the nett daemon and the relay run as separate system services, each with its own identity and privileges (ADR 0013);
- Whether relay runs is decided by the Hub based on node reachability and signed policy, and relay is started and stopped by nett-node, not decided by the installation process;
- New machines install from the project website (ADR 0020), and machines upgrade with programs fetched through their Hub (ADR 0025); release packages carry signatures;
- **The release signing key belongs to the project, not to the user's Hub**. The public keys are embedded into `nett` at build time (two keys, primary and backup, ADR 0020), and nodes use them to verify every release package, wherever it came from;
- **Downgrade protection**: a node automatically accepts only higher versions; a rollback can only go to the version last installed on this machine; other downgrades need a passkey signature;
- On Home Assistant OS it is provided as an add-on: a container image plus an add-on repository (ADR 0017), and the image is signed as well. The add-on is upgraded by HA, not through the `release` partition; downgrade protection is checked at startup.

## Rationale

- One installation and one upgrade, so processes cannot have mismatched versions;
- Shared dependencies are stored once, and multiple processes share the code pages of the same file, so disk and memory usage are lower;
- A node changing from `dial-only` to `public` needs no reinstallation;
- Privilege isolation is guaranteed by the running user and privileges, regardless of whether the files are the same;
- Distribution by the Hub keeps nodes from depending on public code hosting platforms, which is more reliable in regions with restricted networks.

## Alternatives considered

- **node and relay as two install packages**: one more installation and upgrade, risk of version mismatch, duplicated dependencies.
- **Merge the Hub into the same file too**: the Hub includes the Web frontend, database, authentication and other code that nodes do not need, which would noticeably enlarge the file on every node.

## Consequences

- The relay process's file contains node code that does not execute; the security boundary relies on the low-privilege user and on not holding the mesh private key;
- The release process needs to sign the executable, and the Hub caches and serves the programs of the current release (ADR 0025).
