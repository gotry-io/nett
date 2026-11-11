# Contributing to nett

Thanks for your interest. nett is mesh networking infrastructure: a mistake can cut off the path you would use to fix it, or let one compromised machine reach every other. Changes are therefore designed before they are built, and the security boundaries in [CLAUDE.md](CLAUDE.md) apply to every contribution.

## Before you start

- **Bugs**: open an issue with the version (`nett --version`), the platform, what you did, what you expected and what happened. Include `sudo nett status --json` output where it helps; it contains no private keys.
- **Security issues**: do not open a public issue; see [SECURITY.md](SECURITY.md).
- **Features and design changes**: open an issue first. A feature without a design document gets one in [docs/design/](docs/design/README.md) before code; an architectural change gets an [ADR](docs/adr/README.md). The scope is networking only (ADR 0019).

## Development

The toolchain is pinned in `rust-toolchain.toml`. The checks CI runs:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo deny --locked check
```

- The Hub's SQL queries are checked at compile time against the offline data in `.sqlx/`. After changing a query or a migration, regenerate it with `cargo sqlx prepare --workspace` against a database created from `crates/nett-hub/migrations/`.
- Protobuf types are generated from `proto/`: `cargo run -p nett-proto-gen`, and commit the result.
- Mesh behavior is tested in lab scenarios built from Linux network namespaces (root required): see `nett-lab --help` and [docs/design/prototype.md](docs/design/prototype.md). For example:

  ```bash
  cargo build --locked -p nett-cli -p nett-lab -p nett-hub --features nett-cli/lab
  sudo ./target/debug/nett-lab run hub --topology crates/nett-lab/topologies/direct.toml \
    --nett ./target/debug/nett --out /tmp/lab-hub
  ```

## Pull requests

- One change per pull request, with tests for changed behavior; a bug fix starts with a test that reproduces the bug.
- Commit messages: `type(scope): description` (types `feat`, `fix`, `refactor`, `perf`, `test`, `docs`, `build`, `ci`, `chore`; scopes such as `hub`, `node`, `mesh`, `cli`, `proto`).
- New dependencies need a reason, a note on binary size and, for code that runs on nodes, memory use. Allowed licenses are listed in `deny.toml`.
- Everything in the repository is written in English.

By contributing you agree that your contributions are licensed under the project's terms: MIT or Apache-2.0, at the user's option.
