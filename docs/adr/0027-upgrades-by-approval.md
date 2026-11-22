# 0027. Upgrades start when the user approves them

- Status: accepted
- Date: 2026-11-18

## Context

Machines, containers and the Hub upgrade themselves from signed releases (ADR 0020, 0025, 0026). The Hub learned of a release every 6 hours, upgraded itself, and relayed the release to every machine at once, so each release reached the whole site within minutes of the Hub's next check, at a time no one chose:

- A release that starts and settles but carries a bug (a path that is never chosen, memory that grows) reaches every machine and the Hub together; the rollback covers only a version that does not start or settle;
- The user cannot choose when, try one machine first, or stay on a version; the only switch, `--releases off`, stops the whole site;
- An upgrade restarts the nett daemon and its mesh, which interrupts traffic briefly on the userspace data plane (macOS, Synology DSM).

Comparable products leave the decision to the administrator: automatic updates are a setting the administrator turns on, and servers are upgraded by their operator.

## Decision

- **The Hub holds a release, and relays it only as the user approves**: it fetches the release manifest and mirrors the programs as before (ADR 0025), so an approved upgrade starts at once from its copy, and shows the release as available. It relays the release to a machine, and upgrades itself, only up to the version the user approved for that machine and for the Hub;
- **The user approves from the computer that holds the site**: `nett site upgrade` approves the release the Hub holds for the Hub and every machine, `nett site upgrade <machine>...` for those machines only, and `nett site upgrade --hub` for the Hub alone. The Hub upgrades before the machines approved with it; then each machine upgrades as before, verifying the release signature and rolling back a version that does not settle (release.md section 7);
- **Approvals are part of the site**, pushed to the Hub with it, as the version each machine and the Hub may be upgraded to. They are not signed: they decide when a genuine release is installed, never what is installed, which the release signature decides on every machine;
- **Nothing is approved by default**: a site whose user approves nothing stays on the versions it runs, and `nett site status` says which release is available and the command that approves it.

## Rationale

- One bad release reaches only what the user chose, when the user chose, and the user can try it on one machine first;
- The mechanism stays the one machines already use: the Hub decides only whether to relay, so machines need nothing new, and the Hub keeps holding the programs so that an approval does not wait for a download;
- An upgrade that the Hub could start without the user would bring back the risk this removes; a compromised Hub could still relay a genuine newer release early, not install anything else.

## Alternatives considered

- **Automatic upgrades by default, staged** (one machine first, the rest after it settles): limits how far a bad release reaches, but still at a time no one chose; it can be added as a setting the user turns on, when one is wanted;
- **Signed approvals that machines check themselves**: protects against a Hub that relays a genuine release early, which installs nothing the release signature does not allow; the cost is a signed artifact and a check on every machine for no gain in what can run;
- **Only `--releases off` on the Hub**: all or nothing for the whole site, on the Hub host instead of the computer that holds the site.

## Consequences

- After each release the user runs `nett site upgrade`, or upgrades one machine first; until then `nett site status` shows the release as available.
