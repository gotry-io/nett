# 0010. nett has no AI logic; AI uses nett only through the Hub API

- Status: accepted
- Date: 2026-10-12

## Context

nett only does mesh networking (ADR 0019), but AI agents may need to use nett, for example to query node and link status or propose mesh changes. AI output cannot be fully trusted: it can be wrong, and it can be affected by prompt injection.

## Decision

- nett has no AI logic: no AI runs in the Hub, nett-node, or any other component;
- AI, like any other external program, uses nett only through the Hub API (API tokens of type `script`).

## Rationale

- AI and other external programs use the same API and the same permissions, so the security mechanism only has to be built once;
- nett's components stay small and deterministic, which makes it easier to verify resource usage and security.

## Alternatives considered

- **Implementing an MCP adapter layer and an operations agent in nett**: this is AI operations, outside nett's scope (ADR 0019).
- **Letting AI execute commands**: powerful, but cannot be constrained or audited.

## Consequences

- The API design must cover all UI capabilities and label every operation with a risk level;
- API tokens have only one type, `script`, and tokens used by AI are the same as those of other scripts (design/auth.md section 6.2).
