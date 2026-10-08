# Getting Started

This page takes you from `cargo add acdp` to a signed publish request and a
verified retrieval. For the protocol-level meaning of the objects you build
here, see [RFC-ACDP-0001 (Core)](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0001-core.md)
and [RFC-ACDP-0002 (Context Body)](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0002-context-body.md).

## Install

```bash
cargo add acdp                          # client profile (default)
cargo add acdp --no-default-features    # types + crypto only, no HTTP
cargo add acdp --features server        # add the registry-side validator
```

The `acdp` command-line tool is its own crate: `cargo install acdp-cli`
(see [CLI](cli.md)).

MSRV is **1.86**. The crate is `#![forbid(unsafe_code)]`.

### Which feature do I need?

| Feature | Default | Pulls in | Use when you are… |
|---|---|---|---|
| `client` | ✓ | `reqwest`, `tokio`, `rustls`, `lru` | an **agent or consumer** retrieving and verifying contexts. |
| *(none)* | — | `serde`, `sha2`, `ed25519-dalek`, `p256` | building or signing contexts **offline**, or embedding in a binding (HTTP done by the host). |
| `server` | ✗ | validation + store traits | implementing a **registry**. |
| `tracing` | ✗ | `tracing` | you want `#[instrument]` spans on async ops. |
| `test-transport` | ✗ | test-only constructors (`SsrfPolicy::allow_test_loopback`, `RegistryClient::with_test_transport`, …) | driving an in-process mock registry from **tests**. Never enable in production builds. |

The pure-types/crypto core (`--no-default-features`) has **no HTTP stack** —
this is exactly what the [language bindings](bindings.md) build against.

## Your first publish request (producer)

A producer wraps a signing key and a `did:web` (or `did:key`) identity, then uses a fluent
builder. `.build()` validates the request, computes `content_hash`, and signs
— all in one call.

```rust
use acdp::{
    crypto::SigningKey,
    producer::Producer,
    types::{AgentDid, ContextType, DataRef, DataRefType, Visibility},
};

// In production, load key material from secure storage (OS keychain, HSM, KMS).
let key = SigningKey::generate();

let producer = Producer::new(
    key,
    AgentDid::new("did:web:agents.example.com:my-agent"),
    "did:web:agents.example.com:my-agent#key-1",   // the verification method id
);

let req = producer
    .publish_request()
    .title("Q1 2026 revenue snapshot")
    .context_type(ContextType::DataSnapshot)
    .visibility(Visibility::Public)
    .description("Quarterly revenue figures aggregated by region.")
    .tags(vec!["finance", "revenue", "q1-2026"])
    .domain("finance")
    .data_refs(vec![DataRef::uri(
        DataRefType::PrimaryResult,
        "https://data.example.com/revenue/q1-2026.parquet",
    )])
    .build()
    .expect("build failed");

println!("content_hash: {}", req.content_hash);
println!("signature:    {} ({})", req.signature.value, req.signature.algorithm);

// What you POST to the registry:
let json = serde_json::to_string_pretty(&req).unwrap();
```

The full producer API — supersession, lineage, every data-ref form, and the
`acdp_version` gotcha — is in [Producing contexts](producing.md).

## Your first verified retrieval (consumer)

With the `client` feature, `VerifiedContext::fetch` does retrieve + schema
validate + hash recompute + DID resolve + signature verify in one call. It
returns only if every step passes.

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

let ctx = VerifiedContext::fetch(&client, &resolver, &ctx_id).await?;

println!("title:  {}", ctx.body().title);
println!("status: {:?}", ctx.registry_state().status);
# Ok(()) }
```

The verification stages, the diagnostic `fetch_report` variant, and
cross-registry resolution are covered in [Consuming & verifying](consuming.md).

## Run the examples

The repo ships four runnable examples:

```bash
cargo run --example producer                       # build + sign a request, print the JSON
cargo run --example consumer --features client     # verify the sig-001 golden vector offline
cargo run --example supersession                   # build a v2 that supersedes v1
cargo run --example end_to_end --features client,test-transport  # publish→retrieve→verify
```

The `consumer` example deliberately runs **offline** against the `sig-001`
golden vector so it needs no live registry — it exercises the same primitives
`VerifiedContext::fetch` uses internally.

## Common first errors

| Symptom | Cause | Fix |
|---|---|---|
| `RegistryClient::new` returns `Err` for an `http://` URL | HTTPS is mandatory (RFC-ACDP-0008). | Use `https://`. For tests against a local listener, see [Security](security.md#testing-against-localhost). |
| `RegistryClient::new` rejects an IP-literal URL | IP literals are blocked to force DNS-time SSRF filtering. | Use a hostname. |
| `build()` returns `AcdpError::SchemaViolation` | A field exceeds a length/size cap, or `data_refs` are malformed. | Check the message; see [Producing contexts](producing.md). |
| `fetch` returns `AcdpError::KeyResolution` | The producer's `did:web` document didn't resolve, or its host resolved to a blocked IP range. | Confirm the DID host serves `did.json` over HTTPS on a public IP. |
| `fetch` returns `AcdpError::InvalidSignature` | The signature didn't verify against the resolved key — possibly tampering or an `acdp_version` mismatch. | See the [`acdp_version` note](producing.md#the-acdp_version-field). |

The full error taxonomy and which errors are safe to retry is in
[Errors & retries](errors.md).

## Pre-PR checks

If you're contributing to the crate, run the CI-equivalent local check set in
[CONTRIBUTING.md § Local checks](../CONTRIBUTING.md#local-checks), including the
spec-fixture conformance run described in [Conformance & testing](conformance.md).
