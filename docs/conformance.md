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
| `tests/tls_conformance.rs` | **Network/TLS** | `fed-001..006` and `pub-001/003/006` against an in-process TLS registry. The other `fed-*` fixtures run elsewhere: `fed-007`/`fed-008` (with the `did-ssrf-*` / `data-ref-ssrf-*` families) in `tests/conformance.rs`, `fed-009`/`fed-011` in `tests/receipts.rs`. |
| `tests/registry_client.rs` | **HTTP client** | `RegistryClient` / `WebResolver` against `wiremock`. |
| `tests/verify_algorithm.rs` | **Verification** | The RFC-ACDP-0001 §5.11 algorithm, per step. |
| `tests/ed25519_strict.rs` | **Verification** | Strict Ed25519 (RFC-ACDP-0001 §5.10, `sig-004`): the small-order forgery is rejected at every entry point (publish, did:key, historical, lifecycle, receipt, checkpoint, cosignature). |
| `tests/receipts.rs` | **0.2.0** | Registry receipts (RFC-ACDP-0010), `rcpt-*` / `rot-001`. |
| `tests/lineage_head_receipts.rs` | **0.3.0** | Lineage-head receipts (RFC-ACDP-0011); the `lhr-001..004` fixtures themselves run in `tests/conformance.rs`. |
| `tests/transparency_log.rs` | **0.3.0** | Transparency log (RFC-ACDP-0012), `log-001..004`. |
| `tests/lifecycle.rs` | **0.3.0** | Lifecycle events & retraction (RFC-ACDP-0013), `lc-001..003`. |
| `tests/key_revocation.rs` | **0.3.0** | Key-revocation signal (RFC-ACDP-0014), `rev-001..004` / `rot-001`. |
| `tests/key_revocation_publish_gate.rs` | **0.3.0** | RFC-ACDP-0014 §5 step 2 on the `did:web` publish path. |
| `tests/witness_cosigning.rs` | **0.4.0** | Witness cosigning (RFC-ACDP-0015), `wit-001..004`. |
| `tests/anchors.rs` | **0.5.0 Draft** | Typed external anchors (RFC-ACDP-0016), `anc-001..005`. |
| `tests/store_contract.rs` | **Server** | Concurrency contract of the atomic publish commit. |
| `tests/send_futures.rs` | **API** | Compile-only check that the affected public async entry points return `Send` futures. |
| `tests/body_materialization.rs` | **Server** | Field-transfer guard: every `PublishRequest` field survives `Body::from_publish_request`. |
| `tests/negative_inputs.rs` | **API** | Error-path coverage: malformed identifiers, builder rule violations, oversize fields. |
| `tests/facade_reexports.rs` | **API** | Locks in the umbrella crate's re-export surface. |
| `crates/acdp-cli/tests/cli.rs` | **CLI** | The `acdp` binary as a subprocess. |

## The golden vectors are non-negotiable

`sig-001` and `can-001` are the protocol's anchor points. Any change to the wire
format, the hash preimage, the signature input, or DID resolution **must** keep
these passing:

```bash
cargo test --test golden_vector                              # the whole file
cargo test --test golden_vector signature_matches_spec      # sig-001
cargo test --test golden_vector canonical_form_matches_spec # can-001
```

The binding test suites pin the same `sig-001` constants
(`content_hash = "sha256:f170150d…"`, `signature.value = "ErkbV+FU…"`) — see
[Language bindings](bindings.md#golden-vector-parity). If these drift, the
protocol is broken, not just the test.

`sig-004` is the negative counterpart — a small-order forgery that only a
strict verifier rejects ([RFC-ACDP-0001 §5.10](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0001-core.md#510-signature-algorithms));
`tests/conformance.rs` executes it and rejects it with `invalid_signature`.

## ACDP_SPEC_DIR — the conformance switch

`tests/conformance.rs` parses the canonical spec fixtures: `sig-001`, `can-001`,
every fixture family in `schemas/conformance/` (140+ files), and every
`examples/**/*.json`. It locates the spec
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

What each fixture family covers is described in the spec's
[`schemas/conformance/README.md`](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/schemas/conformance/README.md) —
including the newer `rev-003` (revocation publish rejections, executed in
`tests/key_revocation_publish_gate.rs`) and `rev-004` (interim-form retrieval
unaffected, executed in `tests/key_revocation.rs`).

### Fixtures not executed here

A few fixtures describe obligations that sit outside this library, so
`tests/conformance.rs` only accounts for their family:

- `err-002` (`unsupported_media_type`) — an HTTP-layer check that belongs to
  the registry host, not to `PublishValidator`.
- `fed-010` (truncated walk reported) — not bound to a behavioral test.

Set **`ACDP_REQUIRE_CONFORMANCE=1`** to turn the silent skip into a hard
failure: a missing spec checkout, or any fixture a test references but cannot
find, then fails the run. The dedicated CI conformance job sets it.

### The pinned spec ref

CI does not test against the spec's moving `main`: the conformance job
(`.github/workflows/ci.yml`) and the bindings conformance job
(`.github/workflows/bindings.yml`) check out the spec at a pinned commit — the
`ref:` of the "Check out the ACDP spec" step in
[`ci.yml`](../.github/workflows/ci.yml) is the authority. The pin can lag
the spec's `main` when later spec commits change no fixtures. To reproduce CI
locally, check out that commit. How the
pin is bumped when the spec moves is described in `acdp-ci`'s
[Spec propagation](https://github.com/agentcontextdistributionprotocol/acdp-ci/blob/main/DELIVERY-STANDARD.md#spec-propagation-a-new-spec-revision--its-sha-pinners)
section.

## The full pre-PR check set

This mirrors CI (canonical copy:
[CONTRIBUTING.md § Local checks](../CONTRIBUTING.md#local-checks)):

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo clippy -p acdp --no-default-features --all-targets -- -D warnings
cargo test --workspace --all-features
cargo test -p acdp --no-default-features
RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo +nightly doc --workspace --all-features --no-deps
ACDP_SPEC_DIR=../agentcontextdistributionprotocol cargo test --test conformance
```

`cargo deny check` runs in CI (the sole RustSec advisory gate); `cargo audit`
is optional and local-only — install them when touching dependencies or crypto.

## Running a subset

```bash
cargo test --test golden_vector signature_matches_spec   # one golden vector
cargo test --test conformance                      # one integration file
cargo test -- --nocapture some_test                # with stdout
cargo test -p acdp --no-default-features             # core only, no HTTP
```

## Which profile does this crate claim?

This crate implements the **`acdp-consumer`** profile (RFC-ACDP-0001 §9.1) —
end-to-end signature verification, cross-registry resolution with SSRF defenses,
strict search-response parsing (a `results` key instead of `matches` is
rejected, `vis-003`), and forward-compatible field tolerance. The typed
vocabulary is in `acdp::profile`; `CapabilitiesDocument::claims_profile` and
`supports_required` help registries check what a peer advertises.

Registry implementers built on the `server` feature claim
`acdp-registry-core` / `-discovery` / `-federated` instead, and must pass the
corresponding fixture subsets — see [Implementing a registry](registry.md) and
the spec's [`registries/profiles.md`](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/registries/profiles.md).
