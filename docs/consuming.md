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

### Revocation auto-discovery

By default `VerificationPolicy::revocations.known` is caller-supplied: you
look up revocations yourself and hand the list to the policy, and
verification enforces them but issues no network calls of its own for
this phase. `RevocationPolicy::with_discovery` opts a policy into having
verification look revocations up itself (RFC-ACDP-0014 §8), in addition
to (not instead of) whatever `known` already carries:

```rust,no_run
# #[cfg(feature = "client")]
# fn build() -> acdp::client::VerificationPolicy {
use acdp::client::{RevocationDiscovery, RevocationPolicy, VerificationPolicy};

let policy = VerificationPolicy {
    revocations: RevocationPolicy::new(vec![])
        .with_discovery(RevocationDiscovery::producer_signed_only()),
    ..VerificationPolicy::strict_v0_1_0()
};
# policy
# }
```

`RevocationDiscovery` has no `Default` — construct it via
`producer_signed_only()` or `all_trust_classes()`. The two searches are
distinct trust classes: producer-signed revocations are always searched
once discovery is on, while registry-attested revocations (the §6
"producer lost every key" fallback) are searched only when
`include_registry_attested` is `true` (`all_trust_classes()`), because
that search unconditionally fetches the registry's capabilities
document and roughly doubles worst-case discovery cost — a
cost/availability default, not a claim that registry-attested
revocations matter less.

**`on_failure`: `FailClosed` vs `ProceedWithKnown`.** When discovery
itself fails — a transport error, the search-safety-cap error
`AcdpError::SearchTruncated`, or (issue #258) the budget error
`AcdpError::RevocationDiscoveryBudgetExceeded` covered below —
`DiscoveryFailurePolicy::FailClosed` (the default) fails verification.
`ProceedWithKnown` instead proceeds using `known` alone and records the
failure, retrievable via both
`VerifiedContext::revocation_discovery_failure()` and
`VerificationReport::revocation_discovery`. Choose `ProceedWithKnown`
with open eyes: a transport error (e.g. a 503) is an ordinary
availability blip, but `SearchTruncated` and
`RevocationDiscoveryBudgetExceeded` are **not** equivalent to it, even
though all three take this same path. `SearchTruncated` means "this
producer has more revocations than we will page through" — a hostile
producer or registry can pad the search result set specifically to
exhaust the page cap, hiding a real revocation from discovery — an
attacker-inducible security downgrade. `RevocationDiscoveryBudgetExceeded`
is attacker-inducible the same way: a hostile registry that learns a
caller's `max_requests`/`max_bytes` budget can pad harmless-looking
traffic specifically to exhaust it before a real revocation is found.
`ProceedWithKnown` waives all three, not just transient unavailability.

**`total_timeout` requires a Tokio time driver.** Discovery wraps both
searches in a single `tokio::time::timeout(discover.total_timeout, ..)`,
which requires the executing runtime to have its time driver enabled
(`enable_time`, on by default under `#[tokio::main]` / `#[tokio::test]`,
but not under a hand-built `Builder::new_current_thread()` runtime
unless `.enable_time()` / `.enable_all()` is called). Calling any
`_with_policy` or `fetch_report*` entry point with `discover: Some(..)`
from a runtime without the time driver **panics**, it does not return
`Err`.

**Bounding request count and bytes (issue #258).** `total_timeout` bounds
wall clock only — a hostile-but-fast registry can still drive a large
number of requests and a large volume of parsed bytes well inside the
timeout. `RevocationDiscovery::max_requests` (an `Option<NonZeroUsize>`)
and `RevocationDiscovery::max_bytes` (an `Option<u64>`) close that gap:

```rust,no_run
# #[cfg(feature = "client")]
# fn build_budgeted_discovery() -> acdp::client::RevocationDiscovery {
use acdp::client::RevocationDiscovery;
use std::num::NonZeroUsize;

let mut discovery = RevocationDiscovery::producer_signed_only();
discovery.max_requests = Some(NonZeroUsize::new(200).unwrap());
discovery.max_bytes = Some(10 * 1024 * 1024); // 10 MB
# discovery
# }
```

Both default to `None` (unbounded) from both named constructors, so
adding either knob is opt-in and changes nothing for an existing caller.
When set, the two knobs bound the **combined** total across both trust-
class searches — enabling `include_registry_attested` does not double
the ceiling — and are checked **before** each request is issued, so a
request that would exceed the budget is never sent. Exhaustion raises
`AcdpError::RevocationDiscoveryBudgetExceeded`, wrapped the same way a
`SearchTruncated` failure is (`AcdpError::RevocationDiscoveryFailed`,
dispatched through `on_failure` exactly like the case above) and is
**never** transient.

Two honesty caveats:

- **Registry traffic only.** The budget counts requests issued through
  `RegistryClient` (`capabilities`, `retrieve`, `lineage`, `search`).
  DID-document fetches issued via `WebResolver` during discovery are
  not counted — they are LRU-cached (1000 entries) but unbounded in
  count.
- **Successfully-parsed bodies only — for `max_bytes`.** The byte
  budget counts bytes read from a *successful* response. A non-success
  response's small error-envelope read (capped at 64 KB) is never
  charged, and the size of an in-flight request cannot be reserved in
  advance — since the two trust-class lookups run concurrently, **up
  to two** requests can push the running total past `max_bytes` before
  the *next* check observes the overrun. `max_requests` has no such
  exemption: its slot is reserved *before* the request is issued, so a
  503, a parse failure, or a `PayloadTooLarge` still consumes it.

Without a `RevocationCache` attached, every call still re-discovers from
scratch, budgeted or not — see the next section for the opt-in cache.

### Caching discovered revocations (issue #257)

`RegistryClient::with_revocation_cache` attaches a `RevocationCache` —
`RevocationCache::new()`, cheap to `Clone` (an `Arc` handle) — to a client.
Reuse the returned client across many `VerifiedContext::fetch*` calls
against the same producer(s) to amortize discovery.

**The cache is two objects, and the difference matters.** Read this before
reaching for the `freshness` knob:

- **Facts** — verified `KeyRevocation`s discovery finds. RFC-ACDP-0014
  §7:114 licenses caching these *indefinitely* ("the statement is
  permanent"), and they are **always** unioned into classification —
  never used to replace or subset a discovery result, and **never gated
  behind `freshness`**. A revocation is monotone (more revocations ⇒ an
  earlier effective compromise boundary ⇒ strictly more fail-closed
  verdicts), so seeding from cached facts can only *tighten* a verdict,
  never loosen one. This is what makes the fact store an **anti-rollback
  security control**, not a performance feature: a registry that serves a
  revocation on one call and hides it on the next (or simply goes offline)
  cannot make an already-warmed client forget it. Attaching a cache is
  itself the opt-in for this protection — a call made with
  `RevocationPolicy::discover: None` still seeds cached **producer-signed**
  facts (never registry-attested ones — see below), which is what extends
  anti-rollback to `VerifiedContext::fetch`/`fetch_current`, the two entry
  points that can never set `discover` at all.
- **Freshness markers** — "vantage V completed a full, untruncated
  discovery for this producer/trust-class at time T." This is a cached
  *absence*, which §7:114 does **not** license and which §8 warns about
  directly ("a malicious registry can hide a revocation … absence of
  search results is not evidence of absence"). A marker is bounded by
  `RevocationDiscovery::freshness` (a `Duration`), per vantage
  (`RegistryClient::authority()`), per trust class, and minted **only**
  when discovery completes fully and successfully — a transport error, a
  `SearchTruncated`, a budget exhaustion, or a `total_timeout` trip never
  mints one, so a transient blip can never turn into a silent
  window-long downgrade. A candidate that fails RFC-ACDP-0014 §5
  verification (bad signature, wrong scope, self-signed) is simply
  dropped from the result and does **not** prevent a marker from being
  minted — "completes fully and successfully" describes the *lookup*
  reaching its natural end within its page/lineage/budget caps, not every
  candidate it examined turning out to be valid. This grants no new
  power to a hostile vantage: the marker is per-vantage already, and that
  vantage already controls what it serves.

**`freshness` defaults to `Duration::ZERO` (off) from both
`producer_signed_only()` and `all_trust_classes()`.** Attaching a cache at
the default changes nothing observable except anti-rollback — **the
default cache saves zero requests.** Set `freshness` above zero (a
recommended ceiling: 3600 s, matching `WebResolver`'s own DID-document
cache TTL cap) to additionally let a fresh marker skip a repeat lookup
entirely:

```rust,no_run
# #[cfg(feature = "client")]
# fn build_cached_client(client: &acdp::client::RegistryClient) -> acdp::client::RegistryClient {
use acdp::client::RevocationCache;

let cache = RevocationCache::new();
client.with_revocation_cache(cache)
# }
```

```rust,no_run
# #[cfg(feature = "client")]
# fn build_discovery_with_freshness() -> acdp::client::RevocationDiscovery {
use acdp::client::RevocationDiscovery;
use std::time::Duration;

let mut discovery = RevocationDiscovery::producer_signed_only();
discovery.freshness = Duration::from_secs(300); // opt in to skipping repeat lookups
# discovery
# }
```

A caller sharing one cache across producers or across a whole
`CrossRegistryResolver` walk shares that cache's exposure too — but two
independent filters bound it:

- **Trust class.** A registry-attested fact is read back filtered to the
  classes the CURRENT call's discovery configuration opted into
  (`producer_signed_only()` never applies a cached registry-attested
  fact, even one warmed by an earlier `all_trust_classes()` call against
  the same producer).
- **Origin (RFC-ACDP-0014 §6).** A registry-attested fact is *additionally*
  tagged with the vantage (`RegistryClient::authority()`) that minted it
  and is applied only when reading through a client talking to that SAME
  authority — never merely because its `trust_class` matches. §6 licenses
  a registry-attested claim only "for contexts served by or receipted by
  that same registry"; storing `trust_class` alone answers a different
  question ("did this caller opt into the class") than "was this claim
  made by the registry now serving this context," so both are tracked. A
  caller sharing one cache across clients for two *different* registries
  never has registry A's attestation apply to a context served by
  registry B.

A **producer-signed** fact, once verified, is unconditionally
self-contained (RFC-ACDP-0014 §5/§8) and applies regardless of which
registry served it — it is filtered by neither trust class (once opted
into `known`/discovery at all) nor origin.

Facts are deduplicated on insert and capped per producer; once the cap is
reached an entry stops accepting new facts and drops its markers,
degrading to plain pass-through rather than false completeness. The cache
itself is capacity-bounded (oldest-is-not-tracked; a plain
capacity-triggered eviction, since losing an entry can only cost a future
re-discovery, never safety).

**Where discovery is, and is not, reachable.** All five
policy-taking entry points — `fetch_with_policy`,
`fetch_current_with_policy`, `fetch_report`, `fetch_report_diagnose`,
and `fetch_report_with_fetcher` — honor `discover` through the shared
verification pipeline. `CrossRegistryResolver` (issue #260) now does
too: `CrossRegistryResolver::with_revocation_policy` injects a
`RevocationPolicy` into every node the resolver verifies, and
`CrossRegistryResolver::with_revocation_cache` shares one
`RevocationCache` across the walk. One path still structurally cannot
carry it:

- `fetch` and `fetch_current` hardcode `VerificationPolicy::default()`
  and take no policy argument at all; use the `_with_policy` forms if
  you need discovery. This is a known limitation, not an oversight —
  see the issue #248 plan's LIM-2. (LIM-1, the `CrossRegistryResolver`
  gap, was closed by issue #260.)

**`CrossRegistryResolver` and revocation discovery (issue #260).**
`with_revocation_policy` takes a `RevocationPolicy`, never a full
`VerificationPolicy` — the resolver derives `receipts` itself, per
node, from that node's own advertised capabilities (`Require` iff the
upstream claims `acdp-registry-receipts`), a capability-dependent
escalation a caller cannot express statically for a walk whose
authorities are not known in advance. `known` still travels with the
policy, so a caller can enforce a pre-discovered revocation set across
a whole walk without enabling live discovery at all.

```rust,no_run
# #[cfg(feature = "client")]
# fn build_resolver() -> acdp::client::CrossRegistryResolver {
use acdp::client::{CrossRegistryResolver, RevocationDiscovery, RevocationPolicy};

CrossRegistryResolver::new().with_revocation_policy(
    RevocationPolicy::new(vec![]).with_discovery(RevocationDiscovery::producer_signed_only()),
)
# }
```

**The cache is walk-scoped by default.** Unless
`with_revocation_cache` is called, `CrossRegistryResolver` creates a
FRESH `RevocationCache` for each `walk_derived_from` call and shares it
across every node that walk visits — so discovery for a given
`(authority, trust class)` runs at most once per walk, not once per
node, regardless of `max_nodes`. No cached absence outlives the call, so
suppression is safe without a long-lived cache to manage — a caller who
wants discovery to stay warm ACROSS separate walks opts in explicitly
via `with_revocation_cache`. A nonzero `RevocationDiscovery::freshness`
is still required for a marker to ever suppress a repeat lookup — merely
sharing a cache object does not, on its own, skip anything (the same
rule as the direct, non-resolver path above).

Two caveats:

- **The 30s / 30s default collision.** `RevocationDiscovery::total_timeout`
  and `ResolverOptions::total_timeout` both default to 30s, but they
  nest: a discovery-enabled walk on all defaults can have its entire
  walk budget consumed by one node's discovery. This fails closed (the
  walk simply times out), so it is safe, but surprising — set
  `discovery.total_timeout` well below `ResolverOptions::total_timeout`,
  or raise the latter, when enabling discovery here. The walk-scoped
  cache substantially mitigates this by collapsing repeat discoveries.
- **A bare `resolve()` call, outside `walk_derived_from`, is bounded
  only by the discovery timeout** — `ResolverOptions::total_timeout`
  wraps `walk_derived_from`, not `resolve` on its own — and gets the
  walk-scoped cache's benefit only if `with_revocation_cache` was
  called explicitly.

`CrossRegistryResolver` does not add its own request/byte budget on top
of this — issue #258's `RevocationDiscovery::max_requests`/`max_bytes`
already bound the per-node discovery cost; a duplicate resolver-level
knob would be redundant.

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
| `revocation_discovery` | `Some(Ok(DiscoveryOutcome))` / `Some(Err(AcdpError))` when `policy.revocations.discover` was `Some`, else `None`. Counts *discovered* revocations only — never `policy.revocations.known` — so it stays meaningful when discovery is off. See "Revocation auto-discovery" above. |

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

`.with_revocation_policy(...)` and `.with_revocation_cache(...)` (issue #260)
let the resolver carry RFC-ACDP-0014 revocation discovery into every node it
verifies — see "Caching discovered revocations" above for the full model,
including the walk-scoped cache default and the 30s/30s timeout caveat.
`seed_client` is fill-if-absent for the cache too: a seeded client with no
`RevocationCache` of its own is given the resolver's (or the current walk's);
one that already carries its own keeps it.

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
