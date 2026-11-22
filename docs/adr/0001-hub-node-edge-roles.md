# 0001. Hub / node / public-facing processes are separate; management and traffic are separate

- Status: accepted
- Date: 2026-10-12

## Context

The system has to do management (enrollment, mesh configuration, upgrades) and carry traffic (relay, public transport entry point, reverse proxy). The most direct approach is to let one process on each machine do both, but management components need high privileges, while a public entry point has to parse requests from the entire Internet.

## Decision

The system is split into these roles:

- **Hub**: makes decisions, stores the desired state, aggregates status, and serves the API; it does not operate machines directly.
- **nett-node**: the control agent; it applies the desired state issued by the Hub on the local machine; it **does not listen on any port**, does not handle business traffic, does not execute arbitrary commands, and does not access Docker. It runs on a thread of its own in the nett daemon (ADR 0013).
- **Edge**: a reverse proxy the user runs on an entry node, any implementation will do; it handles public traffic and has no management privileges. Edge is not part of nett, and nett neither generates nor manages its configuration (ADR 0019).
- **nett-relay**: a low-privilege process running on nodes that are reachable from outside; it handles mesh relay forwarding and the public transport entry point (see ADR 0011).
- **The nett daemon**: one process per machine that carries all mesh work (WireGuard, path layer, DNS, filtering and address translation) and the TLS transport, and runs nett-node beside it; the mesh keeps working while nett-node or the Hub is away (see ADR 0013).

A node does not "act as" an Edge and does not manage an Edge.

## Rationale

- Putting the most privileged component in the position with the largest exposure means a single parsing vulnerability can compromise the whole machine; separation keeps the two from stacking.
- With management and traffic separated, websites are unaffected when the Hub or a node stops or is upgraded, and the mesh keeps working while the Hub or nett-node is away (ADR 0013).
- Mature reverse proxies have accumulated years of work on HTTP protocol details and certificate management; implementing one ourselves would gain very little.

## Alternatives considered

- A reverse proxy built into node: saves the memory of one process, but violates privilege separation, and every node upgrade would interrupt all websites.

## Consequences

- The user runs and configures Edge; nett only generates the two configuration sections for the reverse proxy on the Hub host, for the Hub and nett-relay (ADR 0009).
- All public-facing components (Edge, nett-relay) run as independent low-privilege processes.
- The WireGuard UDP port is listened on by the kernel or the mesh in the nett daemon (ADR 0013) and does not respond to unauthenticated packets; it is not considered the nett daemon listening on a public port.
