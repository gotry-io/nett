# 0026. Programs that cannot replace themselves upgrade from their state directory

- Status: accepted
- Date: 2026-11-18

## Context

On a machine, nett-node runs as root and replaces the installed program when it upgrades (design/release.md section 7). Two programs cannot do that:

- **The Hub** runs as a user without privileges (design/hub.md section 8), and its program is owned by root: a Hub that could replace its own program would let a compromised Hub keep its code across restarts;
- **The container** runs the program from its image, which is read-only and replaced only when the user pulls a new image and recreates the container, cutting off the services that share its network (ADR 0016).

Both have a directory of their own that persists: the Hub's data directory and the container's state volume. The release signature decides what a node installs, wherever the bytes came from (hard rule 12, ADR 0025).

## Decision

- **The installed program runs the newest verified release in the state directory**: the program the Hub or the container is started from (the installed program) looks, every time it starts, for a program in its state directory, with that program's release signature next to it. It runs it only when the signature holds for the release keys built into the installed program and the signed comment names this program's target and a higher version than its own; otherwise it runs itself. It runs the file it verified, through the open file, with the same arguments;
- **The running version places the next one**: the Hub, from its mirror of the release (ADR 0025); the container's nett-node, as nett-node does on a machine. The program is verified before it is placed, placed with a rename, and the one it replaces is kept as the previous version, the only version to roll back to;
- **The new version runs in the same process**: the running version stops its work and executes the installed program's check on the new one, so the Hub keeps its service and the container its network namespace;
- **A new version that does not settle is rolled back**: the installed program's check counts each start of a new version; one that starts three times without settling (for the Hub: a node's session or five minutes of running; for the container: nett-node connected to the Hub, or five minutes of running) is replaced by the previous version and recorded, and not tried again. The Hub also returns to the copy of its database taken before the new version started;
- **A newer installed program wins**: when the user installs a newer program (a new image, a newer `nett-hub`), it runs itself and deletes the older programs in the state directory.

## Rationale

- The installed program stays owned by root and read-only; what a compromised Hub or container can write into its state directory is run only when it is a genuine release newer than the installed one, so nothing gains privileges or survives a restart without the release signature;
- One mechanism for both, with the verification nodes already use, and no command for the user: the Hub and the container upgrade like every machine;
- Running the new version in the same process keeps the service and the network namespace, so the services behind a container are not cut off by an upgrade.

## Alternatives considered

- **An upgrade command run with sudo on the Hub host** (`nett-hub upgrade`): every release needs the user on each Hub host, and the Hub falls behind the nodes it serves;
- **The Hub replaces its own program**: the program would have to be writable by the Hub's user, so a compromised Hub could change it permanently;
- **The container is upgraded by pulling a new image** (a tool such as Watchtower watching the registry): another component with access to Docker, and every upgrade recreates the container and cuts off the services that share its network;
- **Check the program once when it is placed, and trust the state directory afterwards**: anything that can write the state directory could then run code at the next start.

## Consequences

- The Hub's data directory and the container's state volume hold up to two programs of about 8 MB each, with their signatures;
- The installed program is the floor: when every newer version fails, the Hub and the container run the version they were installed with;
- A check that runs between verifying and running a file is safe only while nothing else can write the file: the Hub's service manager starts it with no other process of the service running, and the container's first process runs a new version only after every other process in the container has exited;
- The Hub's systemd unit and Compose file are not changed by an upgrade; a release that needs them changed says so in its notes.
