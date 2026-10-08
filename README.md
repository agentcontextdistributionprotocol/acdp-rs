# acdp-rs

[![CI](https://github.com/agentcontextdistributionprotocol/acdp-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/agentcontextdistributionprotocol/acdp-rs/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/acdp.svg)](https://crates.io/crates/acdp)
[![docs.rs](https://img.shields.io/docsrs/acdp)](https://docs.rs/acdp)
[![License](https://img.shields.io/crates/l/acdp.svg)](#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.86-blue)](https://blog.rust-lang.org/2025/04/03/Rust-1.86.0.html)

Reference Rust library for the **Agent Context Distribution Protocol**.
`acdp::ACDP_VERSION` is the newest Final wire line the builder emits; some
Draft-line surfaces are implemented ahead of promotion. For which wire lines
and RFCs are Final or Draft, see the spec's
[`VERSIONING.md`](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/VERSIONING.md) and
[version matrix](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/docs/version-matrix.md).

ACDP lets agents publish immutable, producer-signed context descriptors,
retrieve and verify them locally, discover them by keyword, and follow signed
`acdp://` references across registries. The Trust & Hardening layer adds
registry receipts, offline `did:key` verification, a transparency log,
witness cosigning, key revocation, and lifecycle/retraction events.

> Spec: [agentcontextdistributionprotocol/agentcontextdistributionprotocol](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol)
> — RFC-ACDP-0001 through 0016 (0009 reserved; see the spec's
> [RFC index](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/README.md)).
> This crate implements 0001–0008 (core + retrieval/lineage/search), 0010
> (registry receipts), 0011 (lineage-head receipts), 0012 (transparency log),
> 0013 (lifecycle/retraction), 0014 (key revocation), 0015 (witness
> cosigning), and 0016 (typed external anchors, on the Draft line).

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
For a language-neutral producer/consumer walkthrough, read the spec's
[integration guide](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/docs/integration-guide.md). Ecosystem-wide notes
across the sibling repositories live in
[acdp-docs](https://github.com/agentcontextdistributionprotocol/acdp-docs); a production registry built on this crate is
[acdp-registry-rs](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs).

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
- Tolerates unknown fields for forward compatibility.

The library also ships the building blocks (`PublishValidator`,
`SsrfPolicy`, `validate_publish_request`, `compute_embedded_hash`) that
registry implementations compose to claim the registry profiles
(`acdp-registry-core`, `acdp-registry-discovery`, `acdp-registry-federated`,
…; see the spec's [profiles registry](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/registries/profiles.md)).
[acdp-registry-rs](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs) is one such implementation. See
`acdp::profile` for the typed profile vocabulary.

Read authentication is **not implemented client-side**: `RegistryClient` sends
no authentication header, and `CapabilitiesDocument::read_authentication_methods`
is surfaced as opaque strings. For the provisional `bearer_jwt` method
([RFC-ACDP-0008 §6.2](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0008-security.md#62-read-authentication),
[auth-methods registry](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/registries/auth-methods.md)), the crate provides
only the producer half — `SigningKey::sign_string` to sign a registry
challenge; obtaining and presenting the token is up to the host.

## Glossary

Normative definitions are in
[RFC-ACDP-0001 §2](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0001-core.md#2-conventions-and-terminology);
in this crate:

- **Body** (`types::Body`) — the immutable stored context.
- **ProducerContent** — the Body minus the §5.7 exclusion set; its JCS SHA-256 is `content_hash`, and that string is what the producer signs.
- **RegistryState** (`types::RegistryState`) — mutable registry-derived state (`status`, `lifecycle_events`, `extensions`); receipts and log proofs sit beside it on `types::FullContext`.
- **Lineage** — successive versions of one logical work, keyed by `lineage_id`.
- **JCS** — RFC 8785 canonical JSON (in-house in `acdp-jcs`).
- **DID** — `did:web` (resolved over HTTPS by `did::WebResolver`) or `did:key` (resolved offline by `did::key`).
- **Registry receipt** (`types::RegistryReceipt`) — a registry's signed attestation that it stored a context (RFC-ACDP-0010).

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

The public client APIs apply the RFC-ACDP-0006 §7 / RFC-ACDP-0008 defenses
automatically:

- **Transport:** HTTPS-only; IP-literal URLs refused; private, loopback,
  link-local/IMDS, and multicast addresses refused at DNS time (so DNS
  rebinding is blocked); response-size and same-authority redirect caps.
- **Signatures:** Ed25519 is mandatory and verified strictly
  ([RFC-ACDP-0001 §5.10](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0001-core.md#510-signature-algorithms));
  the signature algorithm must match the resolved verification method.
- **Binding:** the served body's `ctx_id` must equal the one requested.

Full list, error mapping, and test escape hatches:
[`docs/security.md`](./docs/security.md#defenses-applied-by-default).

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

The builder **emits `acdp_version` explicitly by default** (the value of
`acdp::ACDP_VERSION`) — the omission default is closed for 0.2.0+ builders. Consumers still treat an absent field as `"0.1.0"`
(RFC-ACDP-0001 §6). To reproduce the 0.1.x omitted form, opt out:

```rust
# fn opt_out(builder: acdp::producer::RequestBuilder<'_>) -> acdp::producer::RequestBuilder<'_> {
builder.omit_acdp_version() // drops the field, matching the 0.1.x wire form
# }
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
| Ed25519 / P-256 sign/verify | RFC-ACDP-0001 §5.8/§5.10/§5.11 | `crates/acdp-crypto/src/{sign,verify}.rs` |

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
cargo test --workspace --all-features              # full suite
cargo test -p acdp --no-default-features           # core (no HTTP)
```

The full CI-equivalent pre-PR check set is in
[CONTRIBUTING.md § Local checks](./CONTRIBUTING.md#local-checks).

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
RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo +nightly doc --workspace --all-features --no-deps --open
```

## Dependencies

| Crate            | Purpose                                          |
|------------------|--------------------------------------------------|
| `ed25519-dalek`  | Ed25519 signing and verification (`verify_strict`) |
| `p256`           | ECDSA-P256 signing and verification              |
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
