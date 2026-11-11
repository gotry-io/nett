# 0023. Access is default deny

- Status: accepted
- Date: 2026-11-09

## Context

The default of the access rules determines how far a compromised machine can go. The macOS native member (ADR 0018) brings the Mac itself into the mesh, and a Mac often has many services listening on wildcard addresses. If members can reach each other by default, any member that is compromised (for example a VPS that serves traffic externally) can reach those ports.

The Edge address, advertised prefixes and the container member are already default deny (ADR 0015, 0016). Of these, the container member expresses "inbound default deny" through an unsigned local switch in the desired state.

## Decision

1. **A new connection that no rule allows is always denied**: connections between nodes, to advertised prefixes, to container members and from the Edge address are all treated the same, with no exception switches;
2. **The user's devices** (phones and laptops with device credentials) can access all members and the advertised LAN prefixes by default (ADR 0015);
3. The mesh's own in-tunnel probes are not affected by access rules; return packets and related packets of established connections are allowed (mesh.md section 12). When there is no rule set, only this rule is in effect.

## Rationale

- When a machine is compromised, the impact is limited to the targets the rules allow it to reach;
- In a single-user mesh, the access needed (Edge origin traffic, SSH from one's own computer to servers) is very limited. In local signing a rule is only a few lines, and after joining the Hub it is written in the console;
- One default is easier to understand and verify than defaults that differ by target, and it also needs no unsigned switch on the node to decide the inbound default.

## Alternatives considered

- **Members allow each other by default, with deny rules for members that have many local services**: miss one rule and that member is open to all members;
- **The node policy declares "accept only connections allowed by rules"**: the signed node policy needs an extra field, while the default is still open, and a newly joined node must remember to set it.

## Consequences

- The access needed between nodes is written into the access rules one by one, for example SSH from a Mac to a VPS;
- The container member switch in the desired state is deleted, and the container member uses the same default as other members;
- Lab topologies state explicitly the access rules between members that a scenario needs.
