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

```text
publish_verified(req, idempotency_key, resolver):
  1. rate-limit gate           ← before any expensive work (RFC-ACDP-0008 §4.3)
  2. schema + size validation  ← PublishValidator::validate_post_schema
  3. content_hash recompute     ┐
  4. algorithm check            │ verify_publish_request_signature
  5. did:web key resolution     │   (steps 7–8 of §2.1)
  6. signature verification     ┘
  7. self-revocation check     ← RFC-ACDP-0014 §5 step 2: a key-revocation body
                                  must not be signed by the key it revokes
                                  (acdp_version >= 0.3.0)
  8. atomic commit via store   ← idempotency lookup, predecessor check
                                  (incl. the RFC-0014 §4 admission hook),
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
| `with_receipt_signer(signer)` | Mint an RFC-ACDP-0010 registry receipt atomically with each commit (`acdp-registry-receipts`). The signer's `registry_did` must match the capabilities. |
| `with_lineage_head_receipts()` | Enable RFC-ACDP-0011 lineage-head receipts. Requires `with_receipt_signer` first. |
| `with_lifecycle()` | Enable RFC-ACDP-0013 lifecycle events (`acdp-registry-lifecycle`, `acdp_version` ≥ 0.3.0). Needs a store that implements `commit_lifecycle_event`. |
| `publish_verified(req, idem, resolver)` | The conformant publish path (above). |
| `publish_verified_in_tenant(req, idem, resolver, tenant)` | Same, binding the row to a tenant id for multi-tenant stores. |
| `publish_verified_did_key(req, idem)` / `publish_verified_did_key_in_tenant(...)` | The same pipeline for `did:key` producers. Synchronous: key resolution is offline. |
| `publish_pinned_verified_in_tenant(...)` | The same pipeline against a caller-supplied, already-verified public key and algorithm. |
| `publish_verified_in_tenant_with_outcome(...)` / `publish_verified_did_key_in_tenant_with_outcome(...)` / `publish_pinned_verified_in_tenant_with_outcome(...)` | The three tenant publish forms, returning `PublishCommitOutcome` instead of a bare `PublishResponse` (see [below](#insert-vs-idempotent-replay)). Use these when answering `POST /contexts`. |
| `prove_publish_identity(req, resolver)` / `_did_key(req)` / `_pinned(req, key, alg)` | Split half of the publish pipeline — §2.1 steps 1–8 (identity; diagram steps 1–7) without persisting. Pairs with `commit_proven`. |
| `commit_proven(proven, idem, tenant)` | The other half — the atomic store commit, given a `Proven`. |
| `retract_verified(event, requester, resolver)` / `republish_verified(...)` (and `_did_key` twins) | RFC-ACDP-0013 lifecycle transitions on a signed `LifecycleEvent`. Require `with_lifecycle()`. |
| `retrieve` / `retrieve_body` / `lineage` / `current` | Read paths (RFC-ACDP-0004). |
| `search` | Discovery (RFC-ACDP-0005). |
| `store()` / `capabilities()` | Accessors. |

The `did:web` publish pipeline is `async` (it resolves DIDs over the network,
requiring the `client` feature transitively); the `did:key` and pinned forms
and the read paths are synchronous.

### Insert vs. idempotent replay

`PublishCommitOutcome` tells a front-end which HTTP status to send:

| Variant | Meaning | Respond with |
|---|---|---|
| `Inserted(PublishResponse)` | a fresh publish was persisted | `201 Created` + `Location` |
| `IdempotentReplay(PublishResponse)` | the same `(agent_id, Idempotency-Key)` and `content_hash` was already committed; this is the original response | `200 OK` — never `201` (RFC-ACDP-0003 `idem-002`) |

`is_replay()`, `response()`, and `into_response()` read it. The publish entry
points without `_with_outcome` return `into_response()`, so they cannot make
this distinction.

### Splitting prove from commit

`publish_verified_in_tenant_with_outcome` (and its `_did_key`/`_pinned`
siblings) are each a one-line composition of a `prove_publish_identity*` call
followed by `commit_proven` — the split is published, not just an internal
implementation detail, for callers that need to know identity was
cryptographically established *before* doing something else that shouldn't
happen for an unverified request (e.g. arming a rate-limit charge that's only
correct to apply once the producer is known to control the signing key) but
that also shouldn't happen twice if persistence is later skipped:

```rust,no_run
# #[cfg(all(feature = "server", feature = "client"))]
# async fn run(
#     server: &acdp::registry::RegistryServer<acdp::registry::InMemoryStore>,
#     resolver: &acdp::did::WebResolver,
#     req: &acdp::PublishRequest,
# ) -> Result<(), acdp::AcdpError> {
let proven = server.prove_publish_identity(req, resolver).await?;
// ... identity is now established; safe to arm a side effect here ...
let outcome = server.commit_proven(proven, None, None)?;
# let _ = outcome; Ok(()) }
```

`Proven` has no public constructor and is not `Clone` — the only way to get
one is a successful `prove_publish_identity*` call, and it's a move-only
value consumed by `commit_proven`: one proof commits once, by construction,
not by a runtime check rejecting a second attempt (the type system makes
a second attempt inexpressible — there's no second `Proven` to move).
`commit_proven` also rejects a `Proven` established against a
differently-configured `RegistryServer`, even one sharing the same
`authority` string — e.g. proving against an instance with no receipt
signer configured and committing on one that requires receipts — so a
"prove against server A, commit on server B" mixup fails loudly instead
of silently persisting under the wrong configuration.

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
`acdp::verify::verify_publish_request_signature(req, resolver)` for
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
| `commit_lifecycle_event` | persist an RFC-ACDP-0013 lifecycle event. The default returns `NotImplemented`; a store backing a `with_lifecycle()` server must implement it. |

> **`PublishCommit::predecessor_admission`.** When the RFC-ACDP-0014 version
> gate applies and the publish sets `supersedes`, the server passes a hook in
> `PublishCommit::predecessor_admission`. `commit_publish` must call it with the
> predecessor's stored `Body`, inside the same critical section, and only
> **after** its producer-continuity and tenant checks (calling it earlier leaks
> the predecessor's existence and type across tenants). An `Err` must abort the
> commit. A store that ignores the hook fails an RFC-ACDP-0014 §4 MUST.

> **Why `commit_publish` is atomic.** Two concurrent publishes against the same
> `supersedes` target (or the same `Idempotency-Key`) must not both succeed.
> `InMemoryStore` does this under a single mutex; a SQL-backed store should do
> it in one transaction with the right isolation level. Splitting the steps
> (insert, then a separate "mark superseded" UPDATE) reopens the supersession
> race in RFC-ACDP-0008's threat model.

`InMemoryStore` is a complete reference implementation — read
`crates/acdp-server/src/registry/store.rs` to see exactly what `commit_publish` must guarantee.

## Key-revocation publish gates (RFC-ACDP-0014)

`PublishValidator` and `RegistryServer` gate key-revocation publishes on the
`acdp_version` the registry **advertises** in its capabilities:

| Advertised `acdp_version` | Behavior |
|---|---|
| < 0.3.0 | No RFC-ACDP-0014 checks. |
| [0.3.0, 0.5.0) | Full §4 validation of standard `key-revocation` bodies, plus the §4 rule that a revocation is superseded only by a revocation (rejected as `SchemaViolation`). The interim `acdp:key-revocation` form is not §4-validated, but it still gets the §5 not-self-signed and controller checks. |
| ≥ 0.5.0 (Draft) | As above, except a non-revocation superseding a revocation is rejected as `SupersededTarget` with reason `RevocationTypeMismatch` (`details.reason: revocation_type_mismatch`), and a **new** publish of the interim `acdp:key-revocation` form is rejected as `SchemaViolation`. Already-stored interim bodies are still served. |

A malformed advertised version turns the gates on, not off.
`acdp::registry::validator::key_revocation_gate_applies` and
`check_revocation_supersession` are public for registries that compose the
pipeline themselves. The normative text is RFC-ACDP-0014
[§4](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0014-key-revocation.md#4-the-key-revocation-context-type)
and
[§10](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0014-key-revocation.md#10-capabilities-profile-errors-and-compatibility),
with the 0.5.0 amendments summarized in the spec's
[`VERSIONING.md`](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/VERSIONING.md).

For a production registry built on these pieces, including adoption of the
`prove_publish_identity*` / `commit_proven` split, see `acdp-registry-rs`'s
[`docs/ENGINEERING-LOG.md`](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/blob/main/docs/ENGINEERING-LOG.md)
and
[`docs/ARCHITECTURE.md`](https://github.com/agentcontextdistributionprotocol/acdp-registry-rs/blob/main/docs/ARCHITECTURE.md).

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
