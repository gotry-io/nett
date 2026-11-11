# 0009. The reverse proxy in front of the Hub defaults to Caddy

- Status: accepted
- Date: 2026-10-12

## Context

The Hub's console, external API, and node connections are all served over HTTPS on 443, so the Hub host needs a reverse proxy for TLS termination; the same 443 port must also hand nett-relay traffic over to nett-relay (ADR 0011).

Edge means a reverse proxy the user runs on an entry node, any implementation will do; nett neither generates nor manages its configuration (ADR 0019). This ADR decides only the one in front of the Hub.

The candidates differ markedly in resources and features. Measured with HTTPS termination + reverse proxy, limited to 1 CPU / 256 MB, 50 concurrent connections for 20 seconds:

| | Caddy 2.11 | Nginx 1.31 | Traefik 3.7 |
|---|---|---|---|
| Idle memory | 38–56 MB | 4.4 MB | 13.3 MB |
| Peak memory under load | 67.6 MB | 7.3 MB | 132.4 MB |
| Requests/second | 18,025 | 66,989 | 21,777 |
| p99 latency | 10.3 ms | 2.3 ms | 41.2 ms |

## Decision

- The Hub install script generates the reverse proxy configuration for the Hub's own console domain, using Caddy by default;
- On the same 443 port, traffic for nett-relay's domain is handed over to nett-relay by SNI (for the handover method see ADR 0011);
- This reverse proxy can also be the user's Edge at the same time, but nett generates only the two configuration sections for the Hub and nett-relay.

## Rationale

- At the target scale, the throughput of all three far exceeds the need, so **the performance difference has no practical meaning**;
- Caddy has built-in automatic certificate issuance and renewal, so the Hub's console domain needs no separate certificate component.

## Alternatives considered

- **Nginx**: the most frugal in resources, but certificate management needs an extra component.
- **Traefik**: its strength is label-based discovery of containers on the same machine, which the reverse proxy in front of the Hub does not need; it has the highest peak memory under load.
- **Self-built**: see ADR 0001.

## Consequences

- On the Hub host, Caddy's peak memory can be constrained with `GOMEMLIMIT`.
