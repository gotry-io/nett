# 0003. REST + OpenAPI externally, WebSocket + Protobuf internally

- Status: accepted
- Date: 2026-10-12

## Context

The Hub has two kinds of counterparts: clients for users and tools (Web, scripts, a future mobile app), and a large number of resident nodes.

## Decision

- **External API**: REST + JSON with a resource-oriented design; real-time push of events and status uses SSE; OpenAPI 3.1 is generated from the Hub's Rust code (utoipa) as the single source, and clients are generated from it.
- **node <-> Hub**: the node actively establishes a long-lived WebSocket over TLS connection, with Protobuf (prost) messages.

## Rationale

- REST + OpenAPI is universal across clients and can generate TypeScript and Swift clients.
- All clients share one API, so whatever the UI can do, the API can do; observability and management projects built separately later also integrate through the API (ADR 0019).
- The node connects outward, so nodes do not need to open inbound ports; Protobuf messages are compact and safe to evolve.
- Keeping the internal and external protocols separate lets the internal protocol evolve freely without affecting the public API.

## Alternatives considered

- **gRPC / Connect as the external API**: one definition can generate clients for many platforms, but Rust server support for Connect is not yet mature, and browsers need extra adaptation.
- **JSON for the internal protocol too**: simple to implement, but higher bandwidth and parsing cost, and no explicit schema evolution rules.

## Consequences

- CI must check that the generated OpenAPI document and client code are up to date.
- Two protocol definitions (OpenAPI and Protobuf) have to be maintained.
