# Consuming & Verifying Contexts

This page covers the consumer side: fetching contexts, verifying them
end-to-end, following `acdp://` references, and fetching data refs. Everything
here requires the **`client`** feature (the default).

This crate implements the **`acdp-consumer`** profile. The verification
algorithm is specified in
[RFC-ACDP-0001 §5.11](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0001-core.md);
retrieval semantics in
[RFC-ACDP-0004](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0004-retrieval.md);
cross-registry resolution in
[RFC-ACDP-0006](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0006-cross-registry.md).

## Two layers: transport and verification

The crate separates *getting bytes* from *trusting them*:

- **`RegistryClient`** — the HTTP driver. Talks to one registry. Returns wire
  objects (`FullContext`, `CapabilitiesDocument`, `SearchResponse`) **without**
  verifying signatures.
- **`VerifiedContext`** — the trust layer. Wraps a fetch with the full
  verification pipeline and only hands you back a context that passed.

**Use `VerifiedContext` unless you have a specific reason not to.** A raw
`RegistryClient::retrieve` gives you a structurally-parsed body, but a registry
is not a trusted party — only the producer's signature is.

## RegistryClient

```rust,no_run
# #[cfg(feature = "client")]
# async fn run() -> Result<(), acdp::AcdpError> {
use acdp::client::RegistryClient;

let client = RegistryClient::new("https://registry.example.com")?;   // HTTPS-only
# Ok(()) }
```

`new` applies the [security defaults](security.md) automatically: HTTPS-only,
IP-literal rejection, DNS-time SSRF filtering, 1 MB body cap, 3-redirect
same-authority limit, 5 s connect / 30 s total timeouts.

| Method | Endpoint | Returns |
|---|---|---|
| `capabilities()` | `GET /.well-known/acdp.json` | `CapabilitiesDocument` |
| `retrieve(ctx_id)` | `GET /contexts/{ctx_id}` | `FullContext` (body + registry_state) |
| `retrieve_body(ctx_id)` | `GET /contexts/{ctx_id}/body` | body only |
| `lineage(lineage_id)` | `GET /lineages/{lineage_id}` | `Vec<FullContext>` (all versions) |
| `current(lineage_id)` | `GET /lineages/{lineage_id}/current` | latest active version |
| `search(&params)` | `GET /contexts/search` | `SearchResponse` |
| `publish(&req)` | `POST /contexts` | `PublishResponse` |

Conditional and idempotent variants exist too: `retrieve_with_metadata`,
`retrieve_if_none_match` (ETag), `capabilities_with_ttl`, `publish_idempotent`,
and `publish_with_retry`. The client is `Clone` (cheap — an inner `Arc`).

### Searching

Use the builder for ergonomic queries:

```rust,no_run
# #[cfg(feature = "client")]
# async fn run(client: &acdp::client::RegistryClient) -> Result<(), acdp::AcdpError> {
let results = client
    .search_builder()
    .q("revenue")
    .context_type("data_snapshot")
    .domain("finance")
    .tag("q1-2026")
    .limit(50)
    .send()
    .await?;

for m in &results.matches {
    println!("{}", m.ctx_id);
}
if let Some(cursor) = results.next_cursor {
    // pass `.cursor(cursor)` on the next page
}
# Ok(()) }
```

Search ranking is registry-defined (RFC-ACDP-0005); the crate does not re-rank.
See [Discovery in the spec](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0005-discovery.md).

## VerifiedContext — the verification pipeline

`VerifiedContext::fetch` runs the whole pipeline and returns only on full
success:

```rust,no_run
# #[cfg(feature = "client")]
# async fn run() -> Result<(), acdp::AcdpError> {
use acdp::{client::{RegistryClient, VerifiedContext}, did::WebResolver, types::CtxId};

let client   = RegistryClient::new("https://registry.example.com")?;
let resolver = WebResolver::new();
let ctx_id   = CtxId::parse("acdp://registry.example.com/a1b2c3d4-e5f6-4789-8abc-def012345678")?;

let ctx = VerifiedContext::fetch(&client, &resolver, &ctx_id).await?;
println!("{} — {:?}", ctx.body().title, ctx.registry_state().status);
# Ok(()) }
```

The stages, in order (it returns on the **first** failure):

| # | Stage | Failure error |
|---|---|---|
| 0 | **Identifier binding** — the served body's `ctx_id` must equal the one requested, per RFC-ACDP-0006 §4.1 step 7 (NORMATIVE); see RFC-ACDP-0008 §9.1 for the threat rationale | `ContextIdMismatch` |
| 1 | **Schema validation** (`validate_body`) — structural + embedded `data_ref` hashes | `SchemaViolation`, `DataRefHashMismatch` |
| 2 | **`content_hash` recompute** — `sha256(JCS(ProducerContent))` vs declared | `HashMismatch` |
| 3 | **`did:web` key resolution** via `WebResolver` | `KeyResolution`, `KeyResolutionUnreachable` |
| 4 | **Signature verification** against the resolved key (algorithm must match) | `InvalidSignature`, `UnsupportedAlgorithm` |
| 5 | **Status check** per policy | — |

Stage 0 is the client-side form of the check: §4.1 step 7 permits "an
equivalent typed error" in place of the registry-side
`cross_registry_resolution_failed` wire code, and `ContextIdMismatch` is
that typed error. It does not close RFC-ACDP-0008 §9.1 in full — a registry
that genuinely republishes the same content under a new `ctx_id` still
passes; only serve-time substitution (a different id claimed to be the one
requested) is caught.

`VerifiedContext::fetch` is specific to the Rust `client` feature; a
caller building an equivalent pipeline outside Rust (or outside
`VerifiedContext` — e.g. the Python/Node/WASM bindings, or a bare
`RegistryClient` caller who skips `VerifiedContext`) must perform this
same comparison itself. `acdp::verify::verify_ctx_id_binding` is the
standalone function this stage wraps; the bindings expose it directly as
`verify_ctx_id_binding` (Python) / `verifyCtxIdBinding` (Node, WASM) — see
[`docs/bindings.md`](bindings.md).

This is exactly what the offline `cargo run --example consumer` demonstrates,
step by step.

### Verification policy

`VerificationPolicy` tunes the pipeline. The default **is** the strict v0.1.0
profile — `VerificationPolicy::strict_v0_1_0()` is an alias for `Default`.

```rust
use acdp::client::VerificationPolicy;

let policy = VerificationPolicy::strict_v0_1_0();   // == VerificationPolicy::default()
```

| Field | Default | Effect |
|---|---|---|
| `validate_body_schema` | `true` | Run stage 1. Set `false` only in diagnostics that want to attempt signature checks on a body known to fail structural checks. |
| `allow_unknown_status` | `true` | Accept `Status::Other` and degrade to active (RFC-ACDP-0004 §4.1). `false` rejects unknown statuses. |
| `verify_registry_receipt` | `false` | Reserved for v0.1+ (RFC-ACDP-0009 §2.7); no-op today. |

> There is no "relaxed `did:web`" or "skip-hash" mode in v0.1.0. The strict
> profile is the only one the `acdp-consumer` conformance suite covers. To
> apply a custom policy use `fetch_with_policy(&client, &resolver, &ctx_id, &policy)`.

### Diagnostics: fetch_report

When you need to know *which* stage failed rather than just that it did, use
`fetch_report`. It runs the same authorization pipeline as
`fetch_with_policy` — receipt (RFC-ACDP-0010), revocation (RFC-ACDP-0014
§7), signature with the historical-key fallback, and the unknown-status
check all honor the caller's `VerificationPolicy` identically — and
additionally returns a structured `VerificationReport` alongside the
context. The one deliberate difference is schema/embedded-hash handling:
`fetch_report` runs structural validation only and records each
`DataRef`'s embedded-hash outcome in the report instead of treating a
mismatch as fatal (see `data_ref_embedded` below).

```rust,no_run
# #[cfg(feature = "client")]
# async fn run(client: &acdp::client::RegistryClient, resolver: &acdp::did::WebResolver, ctx_id: &acdp::types::CtxId) -> Result<(), acdp::AcdpError> {
use acdp::client::VerificationPolicy;

let policy = VerificationPolicy::strict_v0_1_0();
let (verified, report) =
    VerifiedContext::fetch_report(client, resolver, ctx_id, &policy).await?;

assert!(report.schema_ok && report.body_hash_ok && report.signature_ok);
# Ok(()) }
```

`VerificationReport` fields:

| Field | Meaning |
|---|---|
| `schema_ok` | `validate_body_structural` passed (or was disabled by policy) — the structural half only; embedded-`DataRef` hashes are recorded separately, below. |
| `body_hash_ok` | recomputed `content_hash` matched the declared one. |
| `signature_ok` | producer signature verified against the resolved DID key. |
| `data_ref_embedded` | per-`DataRef` embedded-hash outcome, in `body.data_refs` order. |
| `data_ref_external` | per-`DataRef` external-fetch outcome; `None` = not attempted. |
| `ctx_id_ok` | the served body's `ctx_id` matched the one requested (RFC-ACDP-0006 §4.1 step 7, NORMATIVE). |
| `key_status` | the real `KeyAuthorization` verdict once the receipt/revocation/signature phases ran and passed; `None` if a top-level probe failed first (so those phases never ran) or one of them failed. |
| `policy_phase_error` | which of the receipt/revocation/signature/unknown-status phases failed, if one did; `None` when every phase passed or none ran. |

`fetch_report_with_fetcher` additionally fetches and verifies external
`data_ref` locations (see below).

`fetch_report` and `fetch_report_with_fetcher` return
`AcdpError::ContextIdMismatch` on a mismatch, while `fetch_report_diagnose`
— which reports rather than short-circuits — returns `Ok((None, report))`
with `ctx_id_ok == false`, i.e. it withholds the `VerifiedContext` handle.
`ctx_id_ok == false` is not the only cause of a withheld handle, though:
once the top-level probes (schema, body hash, signature, ctx_id) all pass,
`fetch_report_diagnose` also runs the receipt/revocation/signature/
unknown-status phases, and withholds the handle — recording the cause in
`policy_phase_error` — if any of those fails too, all while still
returning `Ok`.

## Fetching data references

A verified context tells you *where* its data lives; fetching that data is a
separate, SSRF-guarded step. `HttpsDataRefFetcher` applies the same network
defenses as the registry client.

```rust,no_run
# #[cfg(feature = "client")]
# async fn run(data_ref: &acdp::types::DataRef) -> Result<(), acdp::AcdpError> {
use acdp::client::{fetch_and_verify_data_ref, HttpsDataRefFetcher};

let fetcher = HttpsDataRefFetcher::default();
let bytes = fetch_and_verify_data_ref(&fetcher, data_ref).await?;
# Ok(()) }
```

If the `data_ref` carries a `content_hash`, the fetched bytes are verified
against it — a mismatch is `DataRefHashMismatch`. Fetches are size-capped
(`DEFAULT_MAX_BYTES`). `DataRefFetcher` is a trait, so you can supply your own
transport (e.g. for `s3://` or authenticated origins).

## Cross-registry resolution

`CrossRegistryResolver` walks `derived_from` provenance edges across registries,
following the eight-step algorithm in RFC-ACDP-0006 §4.1 with cycle detection,
depth/node/fan-out caps, and a wall-clock budget.

```rust,no_run
# #[cfg(feature = "client")]
# async fn run() -> Result<(), acdp::AcdpError> {
use acdp::client::CrossRegistryResolver;

let resolver = CrossRegistryResolver::new()
    .with_max_depth(5);                    // tighten the default 10

// (resolution methods walk the derived_from graph from a starting context,
//  verifying each hop's signature and registry-DID web binding)
# Ok(()) }
```

`ResolverOptions` (via `.with_options(...)`) bounds the walk:

| Option | Default | Purpose |
|---|---|---|
| `max_depth` | 10 | per-edge depth limit |
| `max_nodes` | 100 | hard ceiling on total contexts verified |
| `max_fanout` | 32 | max `derived_from` entries on any single context (reject hostile fan-out) |
| `total_timeout` | 30 s | wall-clock budget for the whole walk |
| `capabilities_ttl` | 5 min | how long to cache each foreign registry's `/.well-known/acdp.json` |

Use `.with_allowlist([...])` to restrict which authorities the resolver will
contact, and `.seed_client(authority, client)` to pre-wire a configured client
(e.g. with a custom CA) for a known authority. Every URL the resolver builds is
checked against its `SsrfPolicy` — see [Security](security.md).

## Publishing from the client

The producer ([Producing contexts](producing.md)) builds the request; the
client transmits it:

```rust,no_run
# #[cfg(feature = "client")]
# async fn run(client: &acdp::client::RegistryClient, req: &acdp::PublishRequest) -> Result<(), acdp::AcdpError> {
let resp = client.publish(req).await?;
println!("assigned ctx_id: {}", resp.ctx_id);

// or, idempotent / with retry on transient failures:
// client.publish_idempotent(req, "my-idempotency-key").await?;
// client.publish_with_retry(req, "my-idempotency-key", 4).await?;  // bounded backoff
# Ok(()) }
```

`publish_with_retry` retries only **transient** errors — see
[Errors & retries](errors.md#retryability).
