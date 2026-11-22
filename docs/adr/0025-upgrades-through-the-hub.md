# 0025. Upgrades fetch the program through the Hub

- Status: accepted
- Date: 2026-11-17

## Context

A node learns about a new release from the manifest the Hub relays (design/release.md section 7) and downloaded the program itself from the URL in it, the project website. Some networks reach the website only very slowly: from a home connection whose direct path to the website's CDN delivered 1–5 KB/s, an 8 MB program could not finish within the download limit, and the failure was recorded so that the version was never tried again. The machine had just received the manifest without trouble over its connection to the Hub.

What a node installs is decided by the release signature, which binds the version and the target, not by where the bytes came from (hard rule 12). Every node already holds an authenticated connection to the Hub, with the Hub's public key pinned at enrollment.

## Decision

- **The Hub mirrors the programs of the current release**: when the manifest changes, it fetches each target's program, verifies the SHA-256 and the release signature with release public keys built into it like those nodes use, and keeps the programs of the current version in its data directory. It relays the new manifest only after that, so nodes find the programs at the Hub when they learn of the release, and serves only programs it has verified;
- **Nodes fetch the program over their session with the Hub** (`ProgramFetch` and `ProgramPart`, design/protocol.md section 5), and from the URL in the manifest when the Hub does not have it or does not answer. Whatever the source, the node writes the program to disk as it arrives and verifies it before installing (release.md section 7);
- **A program that cannot be fetched is fetched again later**: unreachable sources, a download that stops making progress, a Hub that does not hold the program yet, and bytes that differ from the manifest do not mark the version as failed. A version is marked failed, and not tried again, when its program matches the manifest but its signature does not hold (every source delivers those same bytes), when every source delivers bytes that differ from the manifest, or when it fails to install or to start.

## Rationale

- Every node has already proven the path: the manifest arrived over it. The Hub host usually sits where the website is fast to reach, and fetches each program once for the whole site;
- Nothing new runs on members: no listening port, no process, no access rule. The Hub only forwards signed artifacts (hard rule 3), and nodes keep verifying everything they install, so a compromised Hub can withhold an upgrade but cannot make a node install anything else;
- Writing to disk while hashing bounds a node's memory during an upgrade to a few buffers instead of the whole program.

## Alternatives considered

- **Members serve their program to each other over the mesh**: every member would need a listening port in a privileged process (hard rules 1 and 2) and a built-in exception to denying connections between members (ADR 0023, hard rule 5), and a member holds only the program of its own target;
- **A public download endpoint on the Hub**: needs a route through the Hub's reverse proxy and turns the Hub into a public mirror whose bandwidth anyone can use, while the session already authenticates exactly the machines of the site;
- **Only longer timeouts and retries against the website**: on such a link an upgrade still takes hours, and a site whose machines all sit behind a slow path never upgrades in reasonable time.

## Consequences

- The Hub host keeps one program per target of the current release, about 8 MB each, and the Hub holds the release public keys like nodes do. A Hub whose keys do not cover a release, as after a key rotation before the Hub is upgraded, does not mirror it, and nodes fetch that release from the website;
- The protocol gains two messages; when the Hub does not hold the program or sends nothing for 10 seconds, the node fetches it from the URL (release.md section 7);
- An upgrade costs the Hub host's uplink one program per machine, about 20–30 seconds at 3 Mbit/s;
- ADR 0012's statement that the Hub caches and serves release packages holds for upgrades; new machines install from the project website (ADR 0020).
