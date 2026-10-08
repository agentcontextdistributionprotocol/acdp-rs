# Contributing to acdp-rs

Thanks for your interest in contributing! This document covers the dev workflow,
quality bars, and conventions for `acdp-rs`.

## Prerequisites

- Rust **1.86** or newer (MSRV — verified in CI).
- `cargo fmt`, `cargo clippy`, `cargo test` (the rust-toolchain components are
  installed by `rustup`).

## Local checks

Before opening a pull request, please run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo clippy -p acdp --no-default-features --all-targets -- -D warnings
cargo test --workspace --all-features
cargo test -p acdp --no-default-features
RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo +nightly doc --workspace --all-features --no-deps
# Spec-fixture conformance (needs a spec checkout; skips silently without one)
ACDP_SPEC_DIR=../agentcontextdistributionprotocol cargo test --test conformance
```

This repository is a Cargo **workspace**: the umbrella `acdp` crate is a thin
facade re-exporting the fine-grained crates under `crates/`. `--workspace` runs
the checks across every crate; `--no-default-features` is scoped to `-p acdp`
because the pure-core feature matrix lives on the facade.

CI runs these on every PR, plus jobs you don't need to reproduce locally: the
spec-fixture conformance run against a pinned spec checkout (with
`ACDP_REQUIRE_CONFORMANCE=1`, so a missing fixture fails), MSRV, `cargo deny`,
`cargo vet`, `cargo semver-checks` (advisory), and coverage. See
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) and
[`docs/conformance.md`](docs/conformance.md).

Optional but recommended for crypto-sensitive changes:

```bash
cargo install cargo-deny cargo-audit
cargo deny check
cargo audit
```

If you add or bump a dependency, `cargo vet --locked` must stay green. Bumping a
crate listed in `scripts/crypto-critical.txt` needs a real audit, not an
exemption. See
[`docs/supply-chain.md`, "Upgrading a crypto-critical crate"](docs/supply-chain.md#upgrading-a-crypto-critical-crate).

## Branching and commits

- Target the `main` branch.
- Use [Conventional Commits](https://www.conventionalcommits.org/) — the
  `release-plz` workflow uses commit prefixes (`feat:`, `fix:`, `docs:`,
  `refactor:`, `test:`, `chore:`, `BREAKING CHANGE:`) to derive changelog
  entries and version bumps.

## Spec changes

This crate implements **RFC-ACDP-0001–0008 and 0010–0016** (0009 is reserved;
see the spec's [RFC index](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/README.md)). Any change that
affects the wire format, hash preimage, signature input, or DID resolution
behavior MUST:

1. Cite the specific RFC section in the PR description.
2. Update or extend the golden vectors in `tests/golden_vector.rs`.
3. Pass against the canonical conformance vectors in the
   [spec repo](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol):
   [`schemas/conformance/sig-001-ed25519-golden.json`](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/schemas/conformance/sig-001-ed25519-golden.json) and
   [`schemas/conformance/can-001-jcs-vector.json`](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/schemas/conformance/can-001-jcs-vector.json).

## Adding tests

- Unit tests live alongside the code in `#[cfg(test)] mod tests`.
- Integration tests go in `tests/`.
- HTTP-mocked tests use [`wiremock`](https://docs.rs/wiremock).
- Property tests use [`proptest`](https://docs.rs/proptest).
- Rust snippets in `README.md` and the `docs/*.md` guides are doctests: the
  `#[cfg(doctest)] mod doc_guides` harness at the bottom of `src/lib.rs`
  pulls each guide in with `include_str!`, so `cargo test --doc` compiles
  them. Make a snippet self-contained with hidden `# ` setup lines; fence it
  `rust,no_run` only when it needs the network, and diagrams or pseudo-code
  `text` (a bare fence is compiled as Rust). Gate feature-specific snippets
  with a hidden `# #[cfg(feature = "...")]`. A new guide with Rust snippets
  must be added to `doc_guides`.

## Adding a new wire error code

When ACDP adds a new error code (e.g. `unsupported_media_type`), wire it
through the library in three places:

1. **`crates/acdp-primitives/src/error.rs` `AcdpError`** — add a typed
   variant with the appropriate documentation citing the RFC section.
2. **`AcdpError::from_wire_error`** — add a `match` arm that converts
   the wire string into the new typed variant.
3. **`crates/acdp-primitives/src/error.rs` tests
   `all_26_wire_codes_round_trip`** — extend the exhaustive map so the
   count and the round-trip assertion stay accurate (rename the test to
   match the new count). The spec-driven backstop
   `wire_error_codes_cover_the_spec_enum` in `tests/conformance.rs` fails
   if the spec's error-code enum gains a code this crate does not map.

Also update `AcdpError::is_transient` if the new code is retryable, and
`SupersessionReason` if the code uses a `details.reason` sub-vocabulary.

`AcdpError` is `#[non_exhaustive]`, so adding a variant here is no longer a
semver-breaking change for downstream crates that match on it.

## Reporting security issues

Please **do not** open a public GitHub issue for security vulnerabilities.
See [SECURITY.md](./SECURITY.md) for the responsible-disclosure process.

## License

By contributing, you agree that your contributions will be licensed under the
project's dual MIT / Apache-2.0 license.
