# 0004. Hub uses SQLite storage

- Status: accepted
- Date: 2026-10-12

## Context

The Hub needs to store the desired state, identities, and audit records. The target scale is a single user with several to a few dozen nodes.

## Decision

- Use SQLite (WAL mode), accessed through sqlx.

## Rationale

- No extra database process is needed, and deployment remains a single binary;
- sqlx checks SQL at compile time, catching a common class of errors;
- At the target scale the data volume is tiny, and SQLite is more than sufficient.

## Alternatives considered

- A standalone relational database: one more process and more operational burden.

## Consequences

- The SQLite cache and mmap must be limited explicitly.
