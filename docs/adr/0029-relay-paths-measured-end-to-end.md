# 0029. Relay paths are measured end to end

- Status: accepted
- Date: 2026-11-22

## Context

A member measures a path A -> R -> B in two halves: A probes R, and B reports its own measurement of the leg B <-> R in the in-tunnel replies (mesh.md section 7.2). B's report is the loss over its last 10 probes of R, one every 5 seconds, and a loss below 100% does not count against the path. When B's leg breaks, for example when a firewall upstream of B starts dropping UDP, B's report still shows the leg working for several seconds and then only 10%, 20% loss. Meanwhile R keeps answering A, so A sees a healthy path, moves onto it, loses every packet for about 4 seconds, and moves back. The lab scenario `hub-relay` shows it: a pair on the relay on B's own machine over TLS, B's UDP blocked, A moves to the other relay over UDP within seconds.

How comparable products do it:

- **Tailscale** (v1.104.7) peer relays (`net/udprelay/server.go`): the relay allocates an endpoint for a pair; each side binds to it with a three-way handshake, and the relay then forwards everything between the two bound addresses. A client takes a relay path only once a disco ping sent through it has come back as a pong from the peer (`udpRelayEndpointReady` in `wgengine/magicsock/endpoint.go`, called by `relaymanager.go` after pong reception), and keeps validating it with the same end-to-end pings as any path. DERP is kept as a fallback that always works.
- **NetBird** (v0.83.2) checks each client's leg to its relay with health-check messages (`shared/relay/healthcheck`), and a relayed connection end to end by watching WireGuard's handshakes: a handshake that times out closes the connection (`client/internal/peer/conn.go`). It does not judge a relayed path from the halves.

## Decision

1. **Through probes**: for a candidate through relay R, a member sends, besides its probe of R, a through probe that R forwards to the peer. The peer answers it, and R forwards the answer back. The round trip is the whole path, measured on the addresses WireGuard uses: R forwards the probe to the peer's bound address (section 5.2), where it forwards WireGuard's data.
2. **Authentication**: the through probe carries two checksums: one with the sender's relay token, which R checks before forwarding, and one with the pair's direct probe key, which only the two members can compute and the peer checks. R forwards only between the two ends of a link assigned to it, and only a reply from the peer's bound address that matches a probe it forwarded in the last 2 seconds, once, back to where the probe came from. A message is 64 bytes in each direction, so R cannot be used to amplify traffic.
3. **Use**: once a through reply has come back through R, the path through R is measured by through probes alone: its round trip, loss and freshness are the whole path's, and R answering this end's probe no longer counts as the path working. 30 seconds without a through reply through R while R answers, the path through R goes back to the halves and is held off as broken beyond R until B reports its leg to R without loss, as after a path through R fails while R answers (mesh.md section 8.2): a broken leg stays avoided, and a peer or relay gone back to an older release, which never answers through probes, reports its leg working and R is taken again.
4. Every relay candidate is probed this way, the relay on the peer's own machine included: a through probe there also shows that the peer's mesh process and WireGuard answer, not only its relay.

## Rationale

- **What is measured is what is used**: the path is taken because its whole round trip answered within the last probe interval, as Tailscale takes a relay path on a pong from the peer. Neither a stale report nor a relay that answers for its own leg can make a broken path look good.
- **No new state on the relay beyond 2 seconds**: R keeps, for each forwarded probe, where it came from, and forgets it after 2 seconds; it holds no keys beyond the tokens it already has.
- **Older releases keep working**: a relay before this release drops the unknown message type, and a member before it gets the forwarded probe on its WireGuard port, where kernel WireGuard or the userspace data plane drops it. Through probes are used only where they come back, and the halves stay as the way for everything else.
- **The legs stay reported**: B still reports its legs, for paths through relays that do not forward through probes and for estimating a relay's quality before switching to it.

## Alternatives considered

- **Fresher leg reports** (B reports a leg fully lost while its latest probe of the relay is unanswered, and probes relays every second): no new message on the relay, but a leg that breaks between two of B's probes still looks good to A for up to a probe interval plus the reply timeout, and probe traffic grows with every relay B can reach.
- **Per-pair relay endpoints, as in Tailscale**: the relay allocates a port or identifier per pair and both ends bind to it. nett's relay already knows each link and each member's bound address from the assignment and WireGuard's handshakes, so it can forward a probe by its receiver without allocations.
- **Hold relays off after any failure until the peer reports their legs again**: tried; it covers a failover, but not a better path chosen while the current one keeps working, which is the case above.

## Consequences

- New probe types `0x92` (through probe) and `0x93` (through reply) (mesh.md sections 5.1, 7.1 and 7.2); the Linux rule that copies probe packets from the WireGuard port and the userspace data plane hand both to the mesh process;
- nett-relay forwards through probes and their replies (mesh.md section 5.2) and keeps at most 4096 forwarded probes for 2 seconds;
- Probe traffic toward relays doubles: one through probe with each probe of a relay candidate, 64 bytes each way, within the budget of mesh.md section 7;
- The lab scenario `hub-relay` checks the case above, and the mesh simulator and nett-relay have tests for the forwarding, the authentication and going back to the halves.
