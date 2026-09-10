# acdp-rs

[![CI](https://github.com/agentcontextdistributionprotocol/acdp-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/agentcontextdistributionprotocol/acdp-rs/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/acdp.svg)](https://crates.io/crates/acdp)
[![docs.rs](https://img.shields.io/docsrs/acdp)](https://docs.rs/acdp)
[![License](https://img.shields.io/crates/l/acdp.svg)](#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.86-blue)](https://blog.rust-lang.org/2025/04/03/Rust-1.86.0.html)

Reference Rust library for the **Agent Context Distribution Protocol** —
ACDP v0.1.0 Final, the v0.2.0 Trust & Hardening layer, v0.3.0 (lineage-head
receipts, transparency log, lifecycle/retraction, key revocation), and
v0.4.0 (witness cosigning, RFC-ACDP-0015, promoted to Final 2026-08) —
all wire-frozen (`ACDP_VERSION` is `0.4.0`).

ACDP lets agents publish immutable, producer-signed context descriptors,
retrieve and verify them locally, discover them by keyword, and follow signed
`acdp://` references across registries. The Trust & Hardening layer adds
registry receipts, offline `did:key` verification, a transparency log,
witness cosigning, key revocation, and lifecycle/retraction events.

> Spec: [agentcontextdistributionprotocol/spec](https://github.com/agentcontextdistributionprotocol)
> — RFC-ACDP-0001 through 0015 (0009 reserved). This crate implements 0001–0008
> (core + retrieval/lineage/search), 0010 (registry receipts), 0011 (lineage-head
> receipts), 0012 (transparency log), 0013 (lifecycle/retraction), 0014 (key
> revocation), and 0015 (witness cosigning).

This is a **Cargo workspace**: the umbrella `acdp` crate is a thin facade that
re-exports a fine-grained set of crates under [`crates/`](./crates/)
(`acdp-primitives` → `acdp-jcs`/`acdp-safe-http` → `acdp-did` → `acdp-crypto` →
`acdp-types` → `acdp-validation` → `acdp-verify` → `acdp-producer` →
`acdp-client`/`acdp-server` → `acdp-cli`), preserving the historical
`acdp::{error, types, crypto, did, validation, verify, producer, client,
registry, …}` paths. Language bindings live under [`bindings/`](./bindings/)
(Python, Node.js, and a browser/edge WebAssembly verifier core published to npm).

## Documentation

Guides that complement the [rustdoc](https://docs.rs/acdp) live in [`docs/`](./docs/):

- [Getting Started](./docs/getting-started.md) — install, features, first publish/verify.
- [Architecture](./docs/architecture.md) — the hash/sign/state layering and module map.
- [Producing contexts](./docs/producing.md) · [Consuming & verifying](./docs/consuming.md) · [Errors & retries](./docs/errors.md)
- [Security model](./docs/security.md) — the SSRF/HTTPS/size defenses applied by default.
- [Implementing a registry](./docs/registry.md) · [CLI reference](./docs/cli.md) · [Language bindings](./docs/bindings.md) · [Conformance & testing](./docs/conformance.md)

These docs are additive to the [specification](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol) and cite the relevant RFC sections rather than restating them.

## Install

```bash
cargo add acdp                          # client (default)
cargo add acdp --no-default-features    # types/crypto only, no HTTP
cargo add acdp --features server        # add the publish validator
```

## Conformance

This crate implements the **`acdp-consumer`** profile (RFC-ACDP-0001 §9.1):

- Verifies producer signatures end-to-end on every retrieved context.
- Resolves cross-registry `acdp://` references with cycle detection,
  depth caps, SSRF defenses, and registry-DID web-binding verification.
- Applies visibility rules client-side and tolerates unknown fields for
  forward compatibility.

The library also ships the building blocks (`PublishValidator`,
`SsrfPolicy`, `validate_publish_request`, `compute_embedded_hash`) that
registry implementers compose into `acdp-registry-core` /
`acdp-registry-discovery` / `acdp-registry-federated` services. See
`acdp::profile` for the typed profile vocabulary.

## Glossary

- **Body** — the immutable JSON object representing a context.
- **ProducerContent** — the Body with the §5.7 exclusion set removed
  (everything except the producer-controlled fields). The producer
  signs ProducerContent; the SHA-256 of its JCS-canonicalized bytes
  is the body's `content_hash`.
- **RegistryState** — the mutable, registry-derived state (`status`, and
  in 0.2.0 the optional registry receipt) returned alongside the Body on
  retrieval.
- **Lineage** — a chain of contexts representing successive versions of
  the same logical work, identified by a stable `lineage_id` derived
  from the v1 ctx_id.
- **JCS** — JSON Canonicalization Scheme (RFC 8785). The deterministic
  serialization used as the SHA-256 input for `content_hash`.
- **DID** — Decentralized Identifier (W3C). `did:web` producers resolve
  their keys over HTTPS; 0.2.0 adds offline `did:key` (Ed25519 + P-256,
  no network) resolved purely from the identifier.
- **Registry receipt** — a registry's signed attestation that it stored a
  context (RFC-ACDP-0010), verified by recomputing the ProducerContent
  hash rather than trusting the echoed value.

## Features

| Feature          | Default | Description                                                                  |
|------------------|---------|------------------------------------------------------------------------------|
| `client`         | ✓       | `RegistryClient`, `VerifiedContext`, `WebResolver`, `CrossRegistryResolver`  |
| `server`         | ✗       | `PublishValidator`, `RegistryServer`, `InMemoryStore` for registry impls     |
| `tracing`        | ✗       | `#[instrument]` spans on async ops; pulls in `tracing` (no subscriber)       |
| `test-transport` | ✗       | Test-only permissive HTTP transport for in-process mock registries           |

The `acdp` binary is its own crate (`cargo run -p acdp-cli -- …`). Offline
`did:key` verification and the receipt types work under
`--no-default-features` (no HTTP stack).

## Security defaults

The library applies these defenses out of the box (RFC-ACDP-0006 §7,
RFC-ACDP-0008):

- **HTTPS-only** for all outbound requests; HTTP is rejected.
- **IP-literal rejection** in `SsrfPolicy` (forces DNS resolution).
- **Private-range blocking**: RFC 1918, loopback, link-local,
  multicast, IMDS (`169.254.169.254`), IPv6 equivalents.
- **Response-size caps**: 1 MB for context retrievals, 64 KB for
  capabilities and DID documents.
- **Redirect cap**: max 3 follows, same-authority only.
- **Algorithm-downgrade rejection**: signatures are checked against
  the algorithm declared by the resolved DID verification method.
- **Ed25519 mandatory** (RFC-ACDP-0001 §5.10).

DNS-rebinding protection (§7.6) is **active**: `SafeDnsResolver` is wired into
every HTTP client's `dns_resolver` hook, so resolved IPs are filtered through
the `SsrfPolicy` at DNS time, before any TCP connect. See
[`docs/security.md`](./docs/security.md).

## Quick start

### Producer — build and sign a request

```rust
use acdp::{
    crypto::SigningKey,
    producer::Producer,
    types::{AgentDid, ContextType, Visibility},
};

let seed = [/* your 32-byte key seed */ 0u8; 32];
let key  = SigningKey::from_bytes(&seed);

let producer = Producer::new(
    key,
    AgentDid::new("did:web:agents.example.com:my-agent"),
    "did:web:agents.example.com:my-agent#key-1",
);

let req = producer
    .publish_request()
    .title("Q1 2026 revenue snapshot")
    .context_type(ContextType::DataSnapshot)
    .visibility(Visibility::Public)
    .build()
    .expect("build failed");

// req.content_hash and req.signature are computed automatically
println!("content_hash: {}", req.content_hash);
```

#### `acdp_version` field

Since 0.2.0 the builder **emits `acdp_version` explicitly by default**
(`"0.4.0"`, the value of `acdp::ACDP_VERSION`) — the omission default is closed
for 0.2.0+ builders. Consumers still treat an absent field as `"0.1.0"`
(RFC-ACDP-0001 §6). To reproduce the 0.1.x omitted form, opt out:

```rust,ignore
builder.omit_acdp_version() // drops the field, matching the 0.1.x wire form
```

**Note:** absent and explicit forms produce **different `content_hash` values**
(the JCS byte sequences differ). Pick one and stay consistent within a lineage.
The `sig-001` golden vector was signed without the field, so its tests use
`omit_acdp_version()` to stay byte-stable.

### Consumer — retrieve and verify

```rust,no_run
# #[cfg(feature = "client")]
# async fn run() -> Result<(), acdp::AcdpError> {
use acdp::{
    client::{RegistryClient, VerifiedContext},
    did::WebResolver,
    types::CtxId,
};

let client   = RegistryClient::new("https://registry.example.com")?;
let resolver = WebResolver::new();
let ctx_id   = CtxId::parse("acdp://registry.example.com/a1b2c3d4-e5f6-4789-8abc-def012345678")?;

// Fetches, recomputes hash, resolves DID, verifies signature
let ctx = VerifiedContext::fetch(&client, &resolver, &ctx_id).await?;
println!("title: {}", ctx.body().title);
println!("status: {:?}", ctx.registry_state().status);
# Ok(()) }
```

### Server — verify and publish a context (RFC-ACDP-0003 §2.1)

```rust,no_run
# #[cfg(feature = "server")]
# async fn run(
#     server: &acdp::registry::RegistryServer<acdp::registry::InMemoryStore>,
#     resolver: &acdp::did::WebResolver,
#     req: &acdp::PublishRequest,
# ) -> Result<acdp::types::PublishResponse, acdp::AcdpError> {
// `publish_verified` runs the full §2.1 pipeline: schema validation →
// hash recomputation → DID resolution → signature verification → and
// only then assigns a `ctx_id` and persists. This is the ONLY
// conformant server path — never persist before signature verification.
let response = server.publish_verified(req, None, resolver).await?;
# Ok(response) }
```

> `RegistryServer::publish_unverified_for_tests` is provided for unit tests
> that cannot run a live DID resolver. It MUST NOT be used in production —
> it skips DID resolution and signature verification, which is a protocol
> violation (RFC-ACDP-0003 §2.1). The tenant/idempotency-capable sibling
> `publish_unverified_in_tenant_for_tests` carries the same restriction; use
> it when a test needs to drive an idempotency-key replay or tenant
> stamping through the unverified path.

## Cryptographic design

The library implements three protocol-critical operations exactly:

| Operation             | Spec reference        | Rust impl                                              |
|-----------------------|-----------------------|--------------------------------------------------------|
| JCS canonicalization  | RFC 8785              | `crates/acdp-jcs/src/lib.rs` (inline, handles `-0.0`)  |
| `content_hash`        | RFC-ACDP-0001 §5.7    | `crates/acdp-crypto/src/hash.rs`                       |
| Ed25519 / P-256 sign/verify | RFC-ACDP-0001 §5.8/11 | `crates/acdp-crypto/src/{sign,verify}.rs`        |

The signature input is the ASCII bytes of the full `"sha256:<hex>"` string —
**not** the raw 32-byte digest. See `crates/acdp-crypto/src/sign.rs` for details.

## Examples

```bash
cargo run --example producer                       # build a signed request
cargo run --example consumer --features client     # verify the golden vector
cargo run --example supersession                   # build a v2 that supersedes v1
cargo run --example end_to_end --features client,test-transport  # publish→retrieve→verify
```

## Testing

```bash
cargo test --all-features                          # full suite
cargo test --no-default-features                   # core (no HTTP)
```

The suite includes:
- Spec golden vectors (`tests/golden_vector.rs` — `sig-001`, `can-001`).
- The fixture-driven conformance suite (`tests/conformance.rs`, plus the
  TLS-backed `tests/tls_conformance.rs` and the receipt/lifecycle/
  revocation/witness suites). Point `ACDP_SPEC_DIR` at a spec checkout to
  run it (see [`docs/conformance.md`](./docs/conformance.md)).
- The RFC-ACDP-0001 §5.11 verification algorithm, covered per-step
  (`tests/verify_algorithm.rs` + the offline module in `acdp-verify`).
- Property tests for JCS canonicalization (`proptest`) and `cargo-fuzz`
  targets under `fuzz/`.
- HTTP-mocked tests for `RegistryClient` and `WebResolver` (`wiremock`).
- Unit tests in every crate.

```bash
# Conformance against a spec checkout
ACDP_SPEC_DIR=../agentcontextdistributionprotocol cargo test --test conformance
```

## Building docs

```bash
RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo +nightly doc --all-features --no-deps --open
```

## Dependencies

| Crate            | Purpose                                          |
|------------------|--------------------------------------------------|
| `ed25519-dalek`  | Ed25519 signing and verification                 |
| `sha2`           | SHA-256                                          |
| `serde`/`serde_json` | JSON                                         |
| `reqwest`/`rustls` | HTTPS (client feature, no OpenSSL)             |
| `zeroize`        | zeroes signing-key bytes on drop                 |

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the dev workflow and quality bars.
Security issues should follow [SECURITY.md](./SECURITY.md).

## License

Licensed under either of [Apache License, Version 2.0](./LICENSE) or
[MIT license](https://opensource.org/license/mit/) at your option.
