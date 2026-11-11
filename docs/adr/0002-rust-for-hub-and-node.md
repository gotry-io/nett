# 0002. Hub and node use Rust

- Status: accepted
- Date: 2026-10-12

## Context

The node must stay resident on machines of about 1 vCPU / 1 GB, so resource usage is a hard constraint.

## Decision

Both Hub and node are written in Rust. The node uses the tokio single-threaded runtime.

## Rationale

Idle resident memory under the same workload (sample CPU and memory once per second, plus one local HTTP request concurrently), Linux arm64, container limited to 1 CPU / 1 GB, 60-second run:

| Implementation | VmRSS |
|---|---|
| Rust (tokio + reqwest/rustls + sysinfo) | 1.9 MB |
| C++ (libcurl static, including TLS) | 4.9 MB |
| Go (net/http + gopsutil) | 7.5–8.6 MB |
| Swift (SwiftNIO or Foundation) | 28–35 MB |

- Rust has the lowest memory and is memory-safe;
- Strong typing and compile-time checks catch many errors, which is a layer of protection for a review-centered development style;
- The same Rust code can later also serve the private transport and the mobile tunnel core (iOS network extensions have strict memory limits).

## Alternatives considered

- **Go**: the richest ecosystem (Tailscale can be embedded), but memory is about 4 times that of Rust. Under this project's architecture (own mesh), most of Go's unique advantages go unused.
- **C++**: memory comparable to Rust, but no memory safety; the risk is too high for a component that runs as root and parses network data.
- **Swift**: on Linux, Foundation is large and depends on many system libraries.

## Consequences

- Development is slower than with Go; cross-compilation needs a musl toolchain or cargo-zigbuild.
