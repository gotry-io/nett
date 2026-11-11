# 0005. Web console is a React SPA embedded in the Hub binary

- Status: accepted; the Web console is deferred, see 0024
- Date: 2026-10-12

## Context

The Web is the primary interaction entry point. The console is a single-user mesh console with dense data (tables, topology graphs, forms, approval flows) and calls only the external API.

## Decision

- React + Vite build a purely static SPA, with no server-side rendering;
- TanStack Router / Query / Table, shadcn/ui + Tailwind, xyflow (topology graph);
- The API client is generated from OpenAPI (openapi-typescript + openapi-fetch);
- Build artifacts are pre-compressed at build time and embedded into the Hub binary with rust-embed.

## Rationale

- React has the largest ecosystem, mature implementations exist for every component a data-dense console needs, and generated and maintained code is the most reliable;
- A pure SPA calls only the external API, which continuously verifies that the API is complete;
- The frontend runs in the browser, so its only effect on the Hub is about 1 MB of extra binary size; static assets carry content hashes and are cached permanently, so they consume almost no CPU or memory at runtime;
- Deployment is still a single file.

## Alternatives considered

- **Svelte / SvelteKit**: smaller size, but a smaller component ecosystem.
- **HTMX + server-side templates**: page endpoints and the JSON API would each have to be written separately, which conflicts with API-first; WebAuthn interaction is awkward.
- **Rust compiled to WASM (Leptos, Dioxus)**: one language across the stack, but the ecosystem is immature, WASM size is large, and iteration is slow.

## Consequences

- The repository contains a Node.js build environment (needed only at build time).
