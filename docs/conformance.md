# Conformance & Testing

This crate is the reference implementation, so "do the tests pass" and "does it
conform to the spec" are two different questions. This page explains the test
layers, the golden vectors that pin the wire format, and the `ACDP_SPEC_DIR`
switch that turns on full conformance.

The conformance fixtures and profiles are defined in the spec repo
([`schemas/conformance/`](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/tree/main/schemas/conformance)
and [`registries/profiles.md`](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/registries/profiles.md)).

## The test layers

| File | Layer | What it pins |
|---|---|---|
| `tests/golden_vector.rs` | **Wire format** | `sig-001` (Ed25519 signature) and `can-001` (JCS canonicalization) — byte-exact against the spec vectors. |
| `tests/proptest_jcs.rs` | **Canonicalization** | Property tests for RFC 8785 JCS, including the `-0.0` edge case. |
| `tests/wire_serialization.rs` | **Serde** | Round-trip JSON serialization and the absent-vs-null convention. |
| `tests/conformance.rs` | **Behavior** | The spec conformance fixtures (see below). |
| `tests/tls_conformance.rs` | **Network/SSRF** | `fed-*` and `did-ssrf-*` fixtures against an in-process TLS server. |
| `tests/registry_client.rs` | **HTTP client** | `RegistryClient` / `WebResolver` against `wiremock`. |
| `tests/cli.rs` | **CLI** | The `acdp` binary as a subprocess. |

## The golden vectors are non-negotiable

`sig-001` and `can-001` are the protocol's anchor points. Any change to the wire
format, the hash preimage, the signature input, or DID resolution **must** keep
these passing:

```bash
cargo test --all-features golden_vector::sig_001
cargo test --all-features golden_vector::can_001
```

The binding test suites pin the same `sig-001` constants
(`content_hash = "sha256:f170150d…"`, `signature.value = "ErkbV+FU…"`) — see
[Language bindings](bindings.md#golden-vector-parity). If these drift, the
protocol is broken, not just the test.

## ACDP_SPEC_DIR — the conformance switch

`tests/conformance.rs` parses the canonical spec fixtures: `sig-001`, `can-001`,
all 16 conformance files, and every `examples/**/*.json`. It locates the spec
checkout via the **`ACDP_SPEC_DIR`** environment variable, falling back to a
sibling-directory path, and **skips gracefully** if neither is found.

> ⚠️ **A green local `cargo test` does not prove conformance** unless
> `ACDP_SPEC_DIR` points at a real spec checkout. Without it, the conformance
> tests skip silently. Always run the full conformance pass with the variable
> set before claiming conformance:

```bash
ACDP_SPEC_DIR=../agentcontextdistributionprotocol cargo test --test conformance
```

(Adjust the path to wherever you've checked out the spec repo.)

## The full pre-PR check set

This mirrors CI exactly:

```bash
cargo fmt --all -- --check
cargo clippy --all-features --all-targets -- -D warnings
cargo clippy --no-default-features --all-targets -- -D warnings
cargo test --all-features
cargo test --no-default-features
RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo +nightly doc --all-features --no-deps
ACDP_SPEC_DIR=../agentcontextdistributionprotocol cargo test --test conformance
```

`cargo deny check` runs in CI (the sole RustSec advisory gate); `cargo audit`
is optional and local-only — install them when touching dependencies or crypto.

## Running a subset

```bash
cargo test --all-features golden_vector::sig_001   # one golden vector
cargo test --test conformance                      # one integration file
cargo test -- --nocapture some_test                # with stdout
cargo test --no-default-features                    # core only, no HTTP
```

## Which profile does this crate claim?

This crate implements the **`acdp-consumer`** profile (RFC-ACDP-0001 §9.1) —
end-to-end signature verification, cross-registry resolution with SSRF defenses,
client-side visibility, and forward-compatible field tolerance. The typed
vocabulary is in `acdp::profile`; `CapabilitiesDocument::claims_profile` and
`supports_required` help registries check what a peer advertises.

Registry implementers built on the `server` feature claim
`acdp-registry-core` / `-discovery` / `-federated` instead, and must pass the
corresponding fixture subsets — see [Implementing a registry](registry.md) and
the spec's [`registries/profiles.md`](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/registries/profiles.md).
