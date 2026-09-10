# Implementing a Registry

This page is for people building an ACDP **registry** — a service that accepts
publishes, stores contexts, and serves retrieval/search. It covers the `server`
feature's building blocks. The normative registry behavior is specified in
[RFC-ACDP-0003 (Publish)](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0003-publish.md),
[RFC-ACDP-0004 (Retrieval)](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0004-retrieval.md),
[RFC-ACDP-0005 (Discovery)](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0005-discovery.md),
and [RFC-ACDP-0007 (Capabilities & Errors)](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0007-capabilities.md).

```bash
cargo add acdp --features server
```

> **This crate does not host a real server.** It ships the *validation and
> storage building blocks* that separate `acdp-registry-*` crates compose into
> a production service (with their own HTTP framework, database, auth, and rate
> limiting). `InMemoryStore` is for tests and reference, not production.

## The publish pipeline — the one rule

The single most important invariant: **never persist a context before its
signature is verified** (RFC-ACDP-0003 §2.1). `RegistryServer::publish_verified`
encodes the full, ordered pipeline:

```
publish_verified(req, idempotency_key, resolver):
  1. rate-limit gate           ← before any expensive work (RFC-ACDP-0008 §4.3)
  2. schema + size validation  ← PublishValidator::validate_post_schema
  3. content_hash recompute     ┐
  4. algorithm check            │ verify_publish_request_signature
  5. did:web key resolution     │   (steps 7–8 of §2.1)
  6. signature verification     ┘
  7. atomic commit via store   ← idempotency lookup, predecessor check,
                                  insert, supersession marking — one critical section
```

```rust,no_run
# #[cfg(feature = "server")]
# async fn run(
#     server: &acdp::registry::RegistryServer<acdp::registry::InMemoryStore>,
#     resolver: &acdp::did::WebResolver,
#     req: &acdp::PublishRequest,
# ) -> Result<(), acdp::AcdpError> {
let resp = server.publish_verified(req, None, resolver).await?;
println!("assigned {} v{}", resp.ctx_id, resp.version);
# Ok(()) }
```

> `RegistryServer::publish_unverified_for_tests` exists for integration tests
> that can't run a live DID resolver. It is `#[doc(hidden)]`, skips §2.1 steps
> 7–8, and is **a protocol violation in production**. Never call it from a real
> service. `publish_unverified_in_tenant_for_tests` is the same test-only
> bypass with an added idempotency key and tenant argument, for tests that
> need to exercise idempotent replay or tenant stamping without a live
> resolver.

## RegistryServer

```rust,no_run
# #[cfg(feature = "server")]
# fn build(caps: acdp::CapabilitiesDocument) {
use acdp::registry::{RegistryServer, InMemoryStore};

let server = RegistryServer::new(
    InMemoryStore::default(),         // your RegistryStore impl
    caps,                             // this registry's CapabilitiesDocument
    "registry.example.com",           // this registry's authority (host)
);
# }
```

| Method | Role |
|---|---|
| `new(store, caps, authority)` | Construct. Also `try_new` (validates caps) and `try_new_for_test_authority`. |
| `with_rate_limiter(limiter)` | Swap in a `RateLimiter` (default `NoopRateLimiter`). |
| `publish_verified(req, idem, resolver)` | The conformant publish path (above). |
| `publish_verified_in_tenant(req, idem, resolver, tenant)` | Same, binding the row to a tenant id for multi-tenant stores. |
| `retrieve` / `retrieve_body` / `lineage` / `current` | Read paths (RFC-ACDP-0004). |
| `search` | Discovery (RFC-ACDP-0005). |
| `store()` / `capabilities()` | Accessors. |

The publish pipeline is `async` (it resolves DIDs over the network, requiring
the `client` feature transitively); the read paths are synchronous.

## PublishValidator — validation without a server

If you have your own storage/transaction layer and only want the validation
half, use `PublishValidator` directly:

```rust,no_run
# #[cfg(feature = "server")]
# fn run(caps: &acdp::CapabilitiesDocument, req: &acdp::PublishRequest, raw_len: usize) -> Result<(), acdp::AcdpError> {
use acdp::registry::PublishValidator;

let validator = PublishValidator::for_authority(caps, "registry.example.com");
let validated = validator.validate_post_schema(req, raw_len)?;   // schema + size + structure
// ... then you run signature verification and persist atomically yourself.
# let _ = validated; Ok(()) }
```

- `validate_post_schema(req, raw_bytes)` — schema, payload size, embedded size,
  and structural checks; returns a `ValidatedPublish`.
- `validate_structural(...)` — the structural subset.
- `assign_identifiers(...)` — derive `ctx_id`, `lineage_id`, `created_at`
  (RFC-ACDP-0003 §3.1).

`PublishValidator` does **not** verify the signature — call
`crate::crypto::verify::verify_publish_request_signature(req, resolver)` for
that. `RegistryServer` wires the two together in the correct order; if you
compose them yourself, keep that order.

## RegistryStore — pluggable persistence

`RegistryStore` is the trait you implement to back the server with a real
database. The critical method is `commit_publish`, which the server calls to
perform the **entire post-verification commit as one atomic critical section**:

| Method | Purpose |
|---|---|
| `put` / `get` | basic context storage |
| `lineage` / `current` / `first_version_ctx_id` | lineage navigation |
| `mark_superseded` | flip a predecessor's status |
| `search` | discovery query |
| `idempotency_lookup` / `idempotency_record` / `idempotency_evict_expired` | `Idempotency-Key` handling (RFC-ACDP-0003 §6) |
| **`commit_publish`** | idempotency lookup + predecessor verification + insert + supersession marking, **atomically** |

> **Why `commit_publish` is atomic.** Two concurrent publishes against the same
> `supersedes` target (or the same `Idempotency-Key`) must not both succeed.
> `InMemoryStore` does this under a single mutex; a SQL-backed store should do
> it in one transaction with the right isolation level. Splitting the steps
> (insert, then a separate "mark superseded" UPDATE) reopens the supersession
> race in RFC-ACDP-0008's threat model.

`InMemoryStore` is a complete reference implementation — read
`crates/acdp-server/src/registry/store.rs` to see exactly what `commit_publish` must guarantee.

## Rate limiting

Rate limiting is a registry responsibility (RFC-ACDP-0008 §4.3). The server
gates **before** any expensive work via the `RateLimiter` trait:

```rust,no_run
# #[cfg(feature = "server")]
# fn run() {
use acdp::registry::{RegistryServer, InMemoryStore, NoopRateLimiter};
# let caps = unimplemented!();
let server = RegistryServer::new(InMemoryStore::default(), caps, "registry.example.com")
    .with_rate_limiter(NoopRateLimiter);   // replace with a real per-agent limiter
# let _: RegistryServer<_, NoopRateLimiter> = server;
# }
```

The default is `NoopRateLimiter`. A production registry MUST supply a real
implementation keyed per producing agent.

## Capabilities & profiles

Your registry advertises what it supports via a `CapabilitiesDocument` served at
`GET /.well-known/acdp.json` (RFC-ACDP-0007). It MUST include `ed25519` in
`supported_signature_algorithms` and `did:web` in `supported_did_methods`.

The conformance profile your registry claims (`acdp-registry-core`,
`-discovery`, `-federated`) determines which fixture set you must pass — see
`acdp::profile` for the typed vocabulary and
[Conformance & testing](conformance.md) for running the fixtures.
