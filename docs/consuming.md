# Consuming & Verifying Contexts

This page covers the consumer side: fetching contexts, verifying them
end-to-end, following `acdp://` references, and fetching data refs. Everything
here requires the **`client`** feature (the default).

This crate implements the **`acdp-consumer`** profile. The verification
algorithm is specified in
[RFC-ACDP-0001 §5.11](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0001-core.md#511-key-resolution);
retrieval semantics in
[RFC-ACDP-0004](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0004-retrieval.md);
cross-registry resolution in
[RFC-ACDP-0006](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0006-cross-registry.md).
For the language-neutral consumer walkthrough, see the spec's
[integration guide](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/docs/integration-guide.md#consumer-flow).

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
same-authority limit, 5 s connect / 30 s total timeouts. For a non-default
connection posture (a private root certificate, a custom `SsrfPolicy`, timeout
overrides, pin-once DNS resolution, or a read-auth provider) use
`RegistryClient::builder(base_url)`; its defaults are identical to `new`.

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

### Read authentication

A registry that sets `anonymous_public_reads: false`, or serves non-public
contexts, refuses an anonymous read with `not_authorized` (RFC-ACDP-0008
§6.2). Revocation discovery against it then reports `unknown`
(`unanswerable`), never not-revoked. Attach an `AuthProvider` to present a
`bearer_jwt` token:

```rust,no_run
# #[cfg(feature = "client")]
# fn build(client: acdp::client::RegistryClient, jwt: String) -> Result<acdp::client::RegistryClient, acdp::AcdpError> {
use std::sync::Arc;
use acdp::client::{BearerToken, StaticBearerToken};

let client = client.with_auth_provider(Arc::new(StaticBearerToken::new(
    "registry.example.com",
    BearerToken::new(jwt)?,
)));
# Ok(client) }
```

| Type | Use |
|---|---|
| `StaticBearerToken` | One token for exactly one authority. |
| `PerAuthorityTokens` | A token per authority, replaceable at runtime (`set` / `remove`). Clones share one table, so a background task can refresh tokens while readers use them. |
| `impl AuthProvider` | Your own source. `bearer_token(authority)` returns the token (or `Ok(None)` to read anonymously). `token_rejected(authority)` is called after a 401/403 to a request that carried your token, so you can drop it and mint a new one. |

The rules:
- **Per authority.** The provider is asked by authority (host plus a
  non-default port). One registry's token is never presented to another,
  including on a cross-registry walk.
- **Reads only.** Tokens go on `retrieve*`, `lineage`, `current` and
  `search`. They never go on `publish*`, because a bearer token never
  replaces a producer signature, and never on the public `capabilities()`
  fetch.
- **Over `https` only.**
- **No retry.** A rejected read fails with `not_authorized` and is not
  retried.
- **No leaks.** `BearerToken` refuses anything that is not an RFC 6750
  `b64token`, so a token cannot inject a header, and its `Debug` output is
  redacted.

Minting the token (the signed-challenge exchange) is deployment-defined, so
it is the provider's job.

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
| 0b | **Registry-assigned bindings** (RFC-ACDP-0004 §2.1, 0.5.0) — a first version's (`supersedes: null`) `lineage_id` must be the offline derivation from its `ctx_id`, and `origin_registry` must equal the `ctx_id` authority, unconditionally (no receipt needed). Standalone: `acdp::verify::verify_registry_assigned_bindings` | `SchemaViolation` |
| 1 | **Schema validation** (`validate_body`) — structural + embedded `data_ref` hashes | `SchemaViolation`, `DataRefHashMismatch` |
| 2 | **`content_hash` recompute** — `sha256(JCS(ProducerContent))` vs declared | `HashMismatch` |
| 3 | **Registry receipt** (RFC-ACDP-0010) per `policy.receipts` — verified by recomputing the ProducerContent hash, before the signature stage because the historical-key path depends on it. The receipt key's status (current = in `assertionMethod`, historical = `verificationMethod` only) is recorded; a stale "historical" answer triggers one rate-limited forced DID refresh first | `InvalidReceipt` (under `VerifyAndReport`: recorded, not returned) |
| 4 | **Revocation** (RFC-ACDP-0014 §7/§8) — `policy.revocations.known`, plus discovered or cached revocations when configured. Strict profile: only a receipt under a *current* receipt key places a revoked-key context before its boundary | `KeyRevoked` (attributed `RevocationRefusal`; wire code `key_not_authorized`); `RevocationUnknown { reason, .. }` under `on_failure: FailClosed` |
| 5 | **Key resolution and signature verification** — `did:web` via `WebResolver` or `did:key` offline; the algorithm must match the key; historical-key fallback per `policy.historical_keys` | `KeyResolution`, `KeyResolutionUnreachable`, `InvalidSignature`, `UnsupportedAlgorithm`, `KeyNotAuthorized` |
| 6 | **Status check** per policy | `SchemaViolation` if `allow_unknown_status` is `false` |

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

On success the handle also tells you *how* it verified:
`VerifiedContext::key_status()` returns the `KeyAuthorization` verdict
(currently authorized, receipt-attested historical, or receipt-attested
pre-compromise), and `VerifiedContext::verified_receipt()` returns the
registry receipt when one was present and the policy verified it (`None`
under `ReceiptPolicy::Ignore` or when the registry minted none).

0.15.0 adds three more verdicts, each reported separately from the body
verdict (and mirrored as `VerificationReport` fields):

| Accessor | Meaning |
|---|---|
| `receipt_key_status() -> Option<ReceiptKeyStatus>` | `Current` / `Historical` for the key that signed the verified receipt (RFC-ACDP-0010 §8 step 1); `None` exactly when `verified_receipt()` is. |
| `receipt_verdict() -> Option<&Result<(), AcdpError>>` | `Some(Ok(()))` when the receipt verified; `Some(Err(_))` only under `ReceiptPolicy::VerifyAndReport`; `None` when no receipt was evaluated. `head_receipt_verdict()` is the `/current` twin. |
| `lineage_binding() -> LineageBinding` | `Derived` (v1, checked offline), `ReceiptAttested` (v2+, the verified receipt binds `lineage_id`), or `Unbound` (v2+, registry-asserted only). |

**Receipt-key status and revoked keys (RFC-ACDP-0014 §7 step 1).** A
historical receipt key is not a currently-authorized registry attestation.
Under the strict profile it cannot place a revoked-key context before the
compromise boundary — such a context is unplaceable and fails closed with
`KeyRevoked` (effect `Unplaceable`, detail "historical receipt key"). Plain rotation with no
revocation is unaffected: the RFC-ACDP-0010 §10 historical-key rule
still accepts a historical receipt key. A deployment that accepts the
risk opts in with
`RevocationPolicy::new(known).accept_historical_receipt_key_for_pre_t()`;
that mode is **non-conformant with the strict profile**.

**`ReceiptPolicy::VerifyAndReport`.** Verifies a present receipt but does
not fail retrieval when it is invalid: the error lands in
`receipt_verdict()` and the receipt is then treated as absent everywhere —
no historical-key rule, revoked-key contexts are unplaceable (fail closed),
`lineage_binding()` is `Unbound` for v2+, and `verified_receipt()` is
`None`. `CrossRegistryResolver` still escalates to `Require`.

### Verification policy

`VerificationPolicy` tunes the pipeline. `VerificationPolicy::default()` is
the strict, receipt-aware policy below. `VerificationPolicy::strict_v0_1_0()`
is **not** the same: it is a named profile that keeps receipts inert
(`ReceiptPolicy::Ignore`) and refuses historical keys
(`HistoricalKeyPolicy::Reject`), for callers pinned to the original
receipt-less behavior.

```rust
use acdp::client::VerificationPolicy;

let policy = VerificationPolicy::default();
```

| Field | Default | Effect |
|---|---|---|
| `validate_body_schema` | `true` | Run stage 1. Set `false` only in diagnostics that want to attempt signature checks on a body known to fail structural checks. |
| `allow_unknown_status` | `true` | Accept `Status::Other` and degrade to active (RFC-ACDP-0004 §4.1). `false` rejects unknown statuses. |
| `receipts` | `ReceiptPolicy::VerifyIfPresent` | Registry-receipt handling (RFC-ACDP-0010). `Ignore` skips receipts; `Require` fails a context that has no valid receipt; `VerifyAndReport` records an invalid receipt's verdict instead of failing (see above). The enum is `#[non_exhaustive]` since 0.15.0. |
| `historical_keys` | `HistoricalKeyPolicy::AcceptWithReceipt` | Whether a signature by a key no longer in the DID document is accepted when a verified receipt places the publish while the key was authorized. `Reject` refuses it. |
| `lineage_head` | `LineageHeadPolicy::default()` | Lineage-head receipt handling (RFC-ACDP-0011). Consulted only by `fetch_current_with_policy`. |
| `revocations` | `RevocationPolicy::default()` (no known revocations, no discovery) | Key-revocation enforcement (RFC-ACDP-0014 §7): `known` revocations plus optional `discover`. See [below](#revocation-auto-discovery). |
| `require_did_web_for_v0_1_0` | `true` | RFC-ACDP-0001 §5.11 v0.1.0 strict profile: a body without `acdp_version` (or `0.1.0`) must be signed under `did:web`. |
| `log_inclusion` | `LogInclusionPolicy::Ignore` | Transparency-log inclusion (RFC-ACDP-0012 §9): `VerifyIfPresent` reports a verdict, `Require` fails without a valid proof. See [below](#transparency-log-and-witnesses). |
| `witness_quorum` | `None` | Witness cosignature quorum over the log checkpoint (RFC-ACDP-0015 §8). See [below](#transparency-log-and-witnesses). |

> There is no "relaxed `did:web`" or "skip-hash" mode. The strict profile is
> the only one the `acdp-consumer` conformance suite covers. To
> apply a custom policy use `fetch_with_policy(&client, &resolver, &ctx_id, &policy)`.

### Revocation auto-discovery

How a consumer must assemble and fold a revocation lineage (which endpoint,
which boundary wins, and what retraction or supersession does and does not
change) is normative in
[RFC-ACDP-0014 §7](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0014-key-revocation.md#7-consumer-semantics-normative);
discovery here walks the full `GET /lineages/{lineage_id}` of every
revocation it finds.

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
    ..VerificationPolicy::default()
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
`AcdpError::SearchTruncated`, or the budget error
`AcdpError::RevocationDiscoveryBudgetExceeded` covered below —
`DiscoveryFailurePolicy::FailClosed` (the default) fails verification
with `AcdpError::RevocationUnknown { reason, .. }`.
`ProceedWithKnown` instead proceeds using `known` and cached facts alone,
reports the verdict as `RevocationVerdict::Unknown`, and records the
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

**Bounding request count and bytes.** `total_timeout` bounds
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
`SearchTruncated` failure is (`AcdpError::RevocationUnknown` with reason
`truncated`, dispatched through `on_failure` exactly like the case
above) and is **never** transient.

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

**Candidate outcome classes (0.15.0, RFC-ACDP-0014 §8).** Every
revocation candidate discovery finds is classified as exactly one of:

| Class | When | Effect on discovery |
|---|---|---|
| verified | strict verification passes, or the **historical arm** passes (below) | counted |
| permanently invalid | hash/schema failure, bad signature, §4 shape, self-signed, foreign `key_id`, or signing key absent from a **freshly fetched** `verificationMethod` | dropped (logged with `tracing`) |
| unverifiable | signing key rotated out of `assertionMethod` and no `registry_receipt` (or one that fails) can place it | `AcdpError::RevocationCandidateUnverifiable` → discovery fails (*unknown*) |
| undecided | transient lookup failure (DID host non-2xx/timeout, registry 5xx), or a budget refusal while checking it | discovery fails (*unknown*) |

The **historical arm** covers a producer that rotated after revoking: the
candidate's signing key is still in `verificationMethod` but no longer in
`assertionMethod`. Discovery verifies the candidate's `registry_receipt`
under the RFC-ACDP-0010 §10 rule and then the signature against the
retained key. A lineage-walk member served without a receipt is
re-retrieved by `ctx_id` (full-retrieval endpoint, charged to the
discovery budget). `verify_revocation_candidate` exposes this
classification directly.

**DID-cache refresh (RFC-ACDP-0001 §5.11 "Caching").** Before reporting
"key not in `verificationMethod`" or `key_not_authorized` against a
*cached* DID document, the verifier re-fetches it once, bypassing the
cache, and re-runs the check (rot-002). A whole operation — one
`fetch`, one discovery run — shares one freshness scope, so the same DID
is force-fetched at most once per operation. Forced re-fetches are also
rate-limited per DID, at most once per
`acdp::did::DEFAULT_FORCED_REFRESH_INTERVAL` (one hour); tune it with
`WebResolver::with_forced_refresh_interval`. When the limit refuses a
re-fetch, a key **absent** from the stale copy is reported as the
transient `KeyResolutionUnreachable`, never as the permanent
`KeyResolution`. Otherwise an attacker could spend the refresh slot with
bogus-fragment bodies just before a producer adds a new key and revokes
an old one, and so make discovery silently drop that revocation.

### Revocation verdicts

0.15.0 reports every revocation decision as a typed, attributable
verdict (RFC-ACDP-0014 §7 "Attribution" and "Producer scope", §8
"Discovery outcome classes"). It is available from
`VerifiedContext::revocation_verdict()` and
`VerificationReport::revocation_verdict`:

| `RevocationVerdict` | Meaning | Verification |
|---|---|---|
| `Revoked { effect: PreCompromise, .. }` | a verified receipt places the context strictly before the boundary T (§7 step 2) | accepted under the historical-key rule |
| `Revoked { effect: Revoked, .. }` | placed at or after T (§7 step 3) | `AcdpError::KeyRevoked` |
| `Revoked { effect: Unplaceable, .. }` | no verified receipt, or (strict profile) one under a historical receipt key (§7 step 4) | `AcdpError::KeyRevoked` |
| `NotRevoked { complete, registry_attested_checked, observed_at }` | no verified, in-scope revocation names the key; `complete` is `true` only when discovery ran and every configured lookup finished untruncated; `observed_at` is set when a cached absence answered | accepted |
| `Unknown { reason, detail }` | discovery could not decide: `truncated`, `unanswerable` (`not_authorized`, `not_implemented`, malformed response), `transient`, or `unverifiable_candidate` | `RevocationUnknown` under `FailClosed`; accepted under `ProceedWithKnown` |

Precedence is refusal, then `Unknown`, then pre-compromise, then
not-revoked. A verified revocation therefore refuses the context even
when another lookup in the same call failed. `Unknown` is never folded
into not-revoked and never cached.

Every `Revoked` verdict, and every `KeyRevoked` error (through
`AcdpError::revocation_refusal()`), carries a `SourcedRevocation`: the
revocation's `ctx_id`, `issuer`, `revoked_key_controller`,
`trust_class`, boundary, and `source` (`Known`, `Discovered { authority }`,
or `Cached { origin }`). The boundary is the earliest
`compromised_since` across every in-scope revocation naming the key.

**Producer scope.** A revocation changes a producer's verdict only if it
speaks for that producer: a producer-signed revocation whose `issuer`
is the producer, or a registry-attested one whose
`revoked_key_controller` is the producer. Any other verified revocation
naming the key is reported in `revocation_hints()` and never applied.

**Re-checking a context you already hold.**
`VerifiedContext::recheck_revocation(&client, &resolver, &policy)`
re-assesses the context's signing key without refetching it. The free
function `find_revocations_verdict(client, resolver, agent_id,
signing_key_fingerprint, receipt_placement, policy)` does the same from
raw inputs. Both return a `RevocationAssessment` and never fail on a
verdict; call `.enforce()` to turn a refusal into `KeyRevoked` and a
fail-closed `Unknown` into `RevocationUnknown`:

```rust,no_run
# #[cfg(feature = "client")]
# async fn run(
#     v: &acdp::client::VerifiedContext,
#     client: &acdp::client::RegistryClient,
#     resolver: &acdp::did::WebResolver,
# ) -> Result<(), acdp::AcdpError> {
use acdp::client::{RevocationDiscovery, RevocationPolicy, RevocationVerdict};

let policy =
    RevocationPolicy::default().with_discovery(RevocationDiscovery::producer_signed_only());
let assessment = v.recheck_revocation(client, resolver, &policy).await?;
if let RevocationVerdict::Unknown { reason, .. } = &assessment.verdict {
    eprintln!("revocation status unknown: {reason}");
}
assessment.enforce()?;
# Ok(()) }
```

### Caching discovered revocations

`RegistryClient::with_revocation_cache` attaches a `RevocationCache` —
`RevocationCache::new()`, cheap to `Clone` (an `Arc` handle) — to a client.
Reuse the returned client across many `VerifiedContext::fetch*` calls
against the same producer(s) to amortize discovery.

**The cache is two objects, and the difference matters.** Read this before
reaching for the `freshness` knob:

- **Facts** — verified `KeyRevocation`s discovery finds. RFC-ACDP-0014
  §7 licenses caching these *indefinitely* ("the statement is
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
  *absence*, which §7 does **not** license and which §8 warns about
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

**`freshness` defaults to 300 s
(`acdp::client::RECOMMENDED_NEGATIVE_FRESHNESS`, RFC-ACDP-0014 §8's
RECOMMENDED bound) from both `producer_signed_only()` and
`all_trust_classes()`** (0.15.0; it was `Duration::ZERO` through 0.14).
Within that window a fresh marker skips a repeat lookup entirely, and the
verdict says so: `RevocationVerdict::NotRevoked { observed_at: Some(t), .. }`
reports when the cached absence was observed. Set `freshness` to
`Duration::ZERO` to re-discover on every call, or lower it; raising it
widens the window in which a newly published revocation goes unseen:

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
discovery.freshness = Duration::ZERO; // re-discover on every call
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

**Facts and markers are stored separately and have different
lifetimes** (0.15.0). Verified facts are **never evicted** — a fact
leaves only with the cache itself. Admission is deduplicated and capped
per producer (`MAX_FACTS_PER_CLASS` per trust class, and per origin for
the registry-attested class); a fact refused at the cap still applies to
the call that found it, and the capped slot stops minting markers, so
that lookup runs in full every time instead of claiming a completeness
the cache can no longer track. Markers live in a bounded map
(`MAX_MARKERS`) that evicts its oldest entry at capacity, since losing a
marker only costs a re-discovery. An `unknown` outcome never mints a
marker.

**Where discovery is, and is not, reachable.** All five
policy-taking entry points — `fetch_with_policy`,
`fetch_current_with_policy`, `fetch_report`, `fetch_report_diagnose`,
and `fetch_report_with_fetcher` — honor `discover` through the shared
verification pipeline. `CrossRegistryResolver` does too: `CrossRegistryResolver::with_revocation_policy` injects a
`RevocationPolicy` into every node the resolver verifies, and
`CrossRegistryResolver::with_revocation_cache` shares one
`RevocationCache` across the walk. One path still structurally cannot
carry it:

- `fetch` and `fetch_current` hardcode `VerificationPolicy::default()`
  and take no policy argument at all; use the `_with_policy` forms if
  you need discovery. This is a deliberate limitation — see the
  `RevocationPolicy` rustdoc.

**`CrossRegistryResolver` and revocation discovery.**
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
node, regardless of `max_nodes`, **on genuine default configuration**.
For this resolver-built cache, the effective `RevocationDiscovery::freshness`
is derived internally from `ResolverOptions::total_timeout` — a caller
using `RevocationDiscovery::producer_signed_only()`/`all_trust_classes()`
completely untouched still gets suppression, with no `freshness` knob to
set. This is safe because no cached absence outlives the call, and the
call's own duration is already bounded by `total_timeout`.

A **caller-supplied** cache (`with_revocation_cache`) does not get this
derived value: its own `freshness` governs unmodified, so
`Duration::ZERO` (the type default) still suppresses nothing there —
merely sharing a cache object is not, on its own, what skips a lookup
for that path (the same rule as the direct, non-resolver path above). A
caller who wants discovery to stay warm ACROSS separate walks opts in
explicitly via `with_revocation_cache` and picks that cache's own
`freshness` (and so its staleness exposure) themselves.

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
of this — `RevocationDiscovery::max_requests`/`max_bytes`
already bound the per-node discovery cost; a duplicate resolver-level
knob would be redundant *per node*. Composed across a walk, though, that
per-node bound is not the whole story: `DiscoveryBudget` is enforced once
per `verify_retrieved` call, i.e. once per node the walk visits. Under
the default `DiscoveryFailurePolicy::FailClosed`, the first node to
exhaust its budget aborts the whole walk, so the aggregate cost stays
bounded by one node's budget. Under `ProceedWithKnown`, a budget
exhaustion at one node no longer stops the walk — so the effective
walk-wide ceiling becomes `max_requests` (or `max_bytes`) **times**
`ResolverOptions::max_nodes`, since every node can independently spend up
to its own budget before falling back to `known`.

### Transparency log and witnesses

A registry with the `acdp-registry-transparency-log` profile can serve a
`log_inclusion` proof with a context (RFC-ACDP-0012). Witnesses can
cosign the log checkpoint, served as `witness_signatures` (RFC-ACDP-0015).
Both are corroboration: a failing proof "invalidates nothing else"
(RFC-ACDP-0012 §9.3). Their verdicts are reported on their own, separate
from the body, receipt and revocation verdicts. They fail verification
only when you opt in.

```rust
# #[cfg(feature = "client")]
# fn build() -> acdp::client::VerificationPolicy {
use acdp::client::{
    LogInclusionPolicy, VerificationPolicy, WitnessEnforcement, WitnessQuorumPolicy,
};

let policy = VerificationPolicy {
    log_inclusion: LogInclusionPolicy::VerifyIfPresent,
    witness_quorum: Some(
        WitnessQuorumPolicy::new(["did:web:witness-a.example", "did:web:witness-b.example"])
            .with_min_witnesses(2)
            .enforce(WitnessEnforcement::RequireQuorum),
    ),
    ..VerificationPolicy::default()
};
# policy
# }
```

| `LogInclusionPolicy` | Effect |
|---|---|
| `Ignore` (default) | The proof is preserved verbatim and not evaluated. |
| `VerifyIfPresent` | A present proof is verified and the verdict reported. A failure never fails verification. |
| `Require` | Fails unless the proof is present and verifies: `invalid_log_proof` when it is absent or fails, `invalid_receipt` when it is cannot-verify. A registry with the profile MAY still leave a proof off a response (§10), so use this only with registries known to serve it. |

How the proof is verified (§9.1 step 1):
- **The leaf is rebuilt from verified material only.** The consumer
  reconstructs it from the body, the recomputed `content_hash`, the
  receipt's verified producer-key fingerprint, and the receipt's
  preimage hash. It never uses a leaf the registry supplies.
- **A verified receipt is required.** Without one, the proof cannot be
  checked, and the verdict is `LogInclusionVerdict::CannotVerify` with a
  `CannotVerifyReason`: `ReceiptAbsent`, `ReceiptInvalid` (the failure is
  in `receipt_verdict()`, under `ReceiptPolicy::VerifyAndReport`) or
  `ReceiptNotVerified` (`ReceiptPolicy::Ignore`). Cannot-verify is not
  "logged" and not `invalid_log_proof`: the log has not been shown to
  misbehave. A `leaf` member echoed by the registry never stands in for
  the receipt, even when it matches.
- **The checkpoint is bound to the registry.** It must be signed by the
  registry's receipt key and its `log_id` must name the serving authority
  and `capabilities.registry_did`. That costs one capabilities fetch when
  a proof is present.

The leaf builder is public as `LogLeaf::for_publish`, so a registry can
use it at append time and both sides hash the same bytes.

How the witness quorum works:
- **Trust.** Only the witnesses in `WitnessQuorumPolicy::new` count.
- **Documents.** A `did:key` witness is resolved offline. A `did:web`
  witness is resolved through the verification's `WebResolver`, with the
  usual SSRF protections, unless you pin its document with
  `with_document`.
- **Checkpoint.** Setting `witness_quorum` verifies the checkpoint even
  under `LogInclusionPolicy::Ignore`. A cosignature only means something
  over a checkpoint you verified yourself. The checkpoint is verified on
  its own, so a cannot-verify inclusion still gets a quorum verdict over
  a checkpoint that verifies.

| `WitnessEnforcement` | Effect |
|---|---|
| `Report` (default) | The quorum is reported and never fails verification. |
| `RequireQuorum` | Fails with `invalid_witness_cosignature` unless `min_witnesses` distinct trusted witnesses cosigned. This is the split-view and anti-rewrite use, where a cosignature never expires. |
| `RequireFreshQuorum` | As above, and the cosignatures must be within `max_age_seconds` (default 300 s). Use it for decisions that need a current checkpoint (§8.1). |

The verdicts:

| Accessor / report field | Meaning |
|---|---|
| `log_inclusion_verdict()` / `log_inclusion_verdict` | A `LogInclusionVerdict`, or `None` when not evaluated (policy `Ignore` with no witness policy, or no proof served). `Included` means the proof verified; `CannotVerify(reason)` means there was no verified receipt to check it against; `Invalid(err)` means it was checked and failed (`invalid_log_proof`). `as_str()` gives the report token: `included`, `cannot_verify`, `invalid_log_proof`, or `error` for a transport failure. |
| `verified_log_inclusion()` | The verified proof and signed checkpoint. Keep the checkpoint to check consistency with later ones (§9.2). |
| `witness_quorum()` / `witness_quorum` | `None` when no witness policy was set. `Some(Err(_))` (`invalid_log_proof`) when there was no verified checkpoint to corroborate. `Some(Ok(WitnessQuorumReport))` otherwise: `meets_quorum`, `meets_fresh_quorum`, the verified `witnesses`, and per-cosignature `failures`. |

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
use acdp::client::{VerificationPolicy, VerifiedContext};

let policy = VerificationPolicy::default();
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
| `receipt_key_status`, `receipt_verdict`, `lineage_binding` | the receipt and lineage verdicts; see the accessor table [above](#verifiedcontext--the-verification-pipeline). |
| `revocation_verdict`, `revocation_hints` | the typed revocation verdict and out-of-scope hints; see [Revocation verdicts](#revocation-verdicts). |
| `log_inclusion_verdict`, `witness_quorum` | the transparency verdicts; see [above](#transparency-log-and-witnesses). |
| `revocation_discovery` | What auto-discovery did, when `policy.revocations.discover` was `Some` and the policy phases were reached: `Some(Ok(DiscoveryOutcome))` on success; `Some(Err(_))` when `ProceedWithKnown` swallowed a discovery failure. `None` when discovery is off, when a top-level probe failed first, or when a `FailClosed` discovery failure ended verification (that one surfaces in `policy_phase_error`). `DiscoveryOutcome` counts *discovered* revocations only (`producer_signed`, and `registry_attested` or `None` if that class was not queried) — never `known`. See "Revocation auto-discovery" above. |

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

### Standalone verifiers

`VerifiedContext` runs these for you; they are also exported from
`acdp::client` for callers that hold a trust artifact as raw JSON and want
to check it outside the pipeline:

| Function | Verifies | Spec |
|---|---|---|
| `verify_receipt_value` | a registry receipt against the body and its recomputed hash | [RFC-ACDP-0010](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0010-registry-receipts.md) |
| `verify_lineage_head_receipt_value` | a lineage-head receipt against the served head | [RFC-ACDP-0011](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0011-lineage-head-receipts.md) |
| `verify_log_checkpoint_value`, `verify_log_inclusion_value` | a transparency-log checkpoint, and a leaf's inclusion proof | [RFC-ACDP-0012](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0012-transparency-log.md) |
| `verify_witness_cosignature_value`, `evaluate_witness_quorum` | one witness cosignature, and a quorum over a trusted witness set | [RFC-ACDP-0015](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0015-witness-cosigning.md) |
| `verify_revocation_body`, `classify_under_revocation` | a key-revocation context, and a verdict under a set of revocations | [RFC-ACDP-0014](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0014-key-revocation.md) |

## Retraction recall (RFC-ACDP-0018, Draft)

A consumer that relied on a context needs to hear when it is retracted,
superseded, or signed by a key later revoked. A registry claiming
`acdp-registry-changes` serves that as a feed, `GET /changes`. The
`acdp::client::recall` module is the `acdp-consumer-recall` side:

- `RegistryClient::changes(since, filter, limit)` reads one page.
  `Since::Start` replays retained history, `Since::Head` starts at the
  present, and `Since::Cursor` resumes from a persisted `next_cursor`.
  The response is checked against the closed schema
  (`acdp::types::change::ChangesResponse`) but **not verified**.
- `ChangeFeed` holds the filter and the position. `fetch` reads the next
  page without moving the cursor, and `advance` moves past a page once
  every entry in it is processed. Persist `position()` after `advance`
  (§7 "Cursor persistence").
- `verify_change` is the §7 procedure. It returns
  `ChangeVerdict::Verified(effect)` or `ChangeVerdict::Rejected(reason)`.
  A rejected entry MUST NOT change any reliance decision. `Err` means the
  entry could not be decided (a transient failure), so leave it
  unprocessed and retry.
- `SeenChanges` deduplicates by (registry authority, `seq`), because
  delivery is at-least-once.

```rust,no_run
# #[cfg(feature = "client")]
# async fn run(
#     client: &acdp::client::RegistryClient,
#     resolver: &acdp::did::WebResolver,
#     relied_on: acdp::types::CtxId,
# ) -> Result<(), acdp::AcdpError> {
use acdp::client::recall::{verify_change, ChangeEffect, ChangeFeed, ChangeVerdict, Since};
use acdp::client::VerificationPolicy;
use acdp::types::change::WatchFilter;

// A ctx_id watch also hears key revocations for that context's producer (§6).
let mut feed = ChangeFeed::new(client, WatchFilter::new().ctx_id(relied_on))
    .since(Since::Head);
let page = feed.fetch().await?;
for change in &page.changes {
    match verify_change(client, resolver, change, None, &VerificationPolicy::default()).await? {
        ChangeVerdict::Verified(ChangeEffect::Lifecycle { retracted: true, .. }) => {
            // Stop relying on it.
        }
        ChangeVerdict::Verified(_) => { /* re-evaluate under your policy */ }
        ChangeVerdict::Rejected(_) => { /* no change; re-verify the context directly */ }
        _ => {}
    }
}
feed.advance(&page);
# Ok(()) }
```

What `verify_change` checks, by kind:

| Kind | Verification |
|---|---|
| all | `recorded_at` and `ctx_id` agree with the evidence (`Change::check_consistency`), before any fetch. |
| `lifecycle` | The event (RFC-ACDP-0013 §5) and its event receipt (RFC-ACDP-0017 §10.3, `verify_event_receipt_value`) both verify. The retraction state is re-derived over the **full** event list. A `HeldContext` stands in for re-retrieval only when it holds every earlier event. Otherwise the context is re-retrieved, and `lifecycle_events[index]` must equal the entry's event under JCS. |
| `superseded` | `superseded_by` is retrieved and verified with its receipt required. It must originate at the registry serving the feed (§7 origin binding). Its `supersedes`, `lineage_id` and `agent_id` must be the entry's, and its verified receipt must equal the entry's under JCS. |
| `key_revocation` | The revocation is retrieved and verified under RFC-ACDP-0014 §5/§6, including the historical-key arm. A registry-attested revocation must be published by this registry. The served receipt must verify under RFC-ACDP-0010 §8 and equal the entry's under JCS. The revocation must also speak for the entry's `agent_id` (§7 producer scope). |

On `AcdpError::CursorExpired`, the consumer has missed an unknown set of
entries. It must re-verify every watched context directly and then call
`ChangeFeed::reset_to_head` (§7 "Resync"). The feed is a notification
channel, not a completeness proof, so high-stakes reliance should also be
re-verified on a schedule.

**Change hints (§8).** A registry claiming `acdp-registry-events` POSTs a
contentless `acdp-change-hint/1` to a subscriber's callback. The registry
signs it with `ACDP-Signature: t=<unix>,v1=<hex HMAC-SHA-256>`. The HMAC
key is the UTF-8 bytes of the subscription `secret` string exactly as
served, **not** its base64 decoding. Verify the header over the raw body
bytes with `acdp::types::change::verify_hint_signature(secret, header,
body, now)`, which compares in constant time and rejects a `t` more than
300 s from `now`. Then call `ChangeFeed::on_hint`, which reads from the
feed's **own** cursor and never the hint's `head_cursor`. Registries sign
with `sign_hint`. `SubscriptionRequest`, `Subscription` and `ChangeHint`
are the closed wire types.

## Registry trust lists (RFC-ACDP-0020, Draft)

A trust list is a signed body of type `acdp:trust-list`. Its issuer is a DID
the consumer pins in configuration. The list names the registries the
consumer relies on, the receipt keys and profiles each must have, and which
bodies each is trusted for. Only the `trusted` outcome permits reliance. The
pure logic is in `acdp::types::trust_list` and has three parts, run in this
order:

1. **Version validity (§5.2).** `TrustList::from_metadata` parses and checks
   the closed `acdp-trust-list/1` object. That includes `registry_did` being
   exactly `did:web:` followed by `origin`, which invalidates the whole
   version if it fails. `validate_list_version` adds the pin checks: issuer,
   `list_id`, the optional `issuer_key_fingerprints`, and a revoked issuer
   key.
2. **Selection (§5.4).** `select_version` applies a fixed check order:
   `no_valid_version`, then `rollback`, `equivocation`, `retracted` and
   `list_window`. The floor (`advance_floor`) counts retracted versions. In
   the as-of pass, only versions issued by T are held.
3. **Evaluation (§6.2).** `evaluate` checks the body and returns an outcome:
   - The `ctx_id` authority must equal `origin_registry`.
   - Each entry is checked in this order: the receipt's registry DID, the
     receipt requirement, the pinned receipt key, the profiles, the window,
     then the scope.
   - When several lists apply, the best outcome wins (lists in the usable,
     expired and invalid states compete). Ties go to the lower
     `(issuer, list_id)`.

The receipt input is the RFC-ACDP-0010 §6 fingerprint of the **registry key
that signed the receipt**. `VerifiedContext::receipt_registry_key_fingerprint`
returns it. It is not the receipt's `key_fingerprint` member, which names the
producer's key.

Three places run it:

| Where | Entry point | Notes |
|---|---|---|
| Online | `client::trust::TrustLists` | `add_verified` takes a list fetched with `VerifiedContext::fetch`; issuer-signed retractions are read from `registry_state`. `add_offline` takes a did:key list carried out of band. `evaluate` / `report` cover the latest pass. Persist `floors()`. `BlockingClient::add_trust_list` does the fetch and the add in one call. |
| Out of band | `verify::trust::verify_list_offline` | A did:key list, as a retrieved body or a signed publish request (§7). |
| Evidence bundle | `chain::verify_chain_with_trust` | Reads lists from the bundle's `contexts`. Each pass verifies them with its own evidence: as-of DID documents, admitted issuer retractions and applied revocations. Each pass yields one `acdp-trust-report/1`, bound by `verdict_digest`. The verdict is identical to `verify_chain`'s. A node's receipt counts only when that pass's `registry_receipt` stage is `ok`. |

The `TrustReport` (§8) is deterministic:

- `lists` is sorted by `(issuer, list_id)`; `nodes` is sorted by `ctx_id`.
- `serial` and `content_hash` appear only for `used` and `expired` lists.
- `issuer`, `list_id` and `entry_index` appear only when an entry decided.
- `report_digest` is SHA-256 over the JCS of the report without it.

Step 5 of §5.2 refuses a list only on an applied revocation of the issuer's
key, meaning `revoked` or `unplaceable` (spec 25f8d3a). An `unknown` status
(no discovery evidence, the usual offline case) does not refuse it. Refusing
`unknown` is local policy, and both entry points support it:
`TrustLists::refuse_unknown_issuer_revocation(true)` online, and
`verify_chain_with_trust_policy` with
`TrustPolicy::default().refuse_unknown_issuer_revocation(true)` for bundles.

The trust step never changes the chain verdict. Refusing a chain because of
an untrusted node is consumer policy, for example `TrustReport::all_trusted`.

## Keyless-signed bodies (RFC-ACDP-0021, Draft)

A keyless body is signed by a short-lived key that a registry attested
for a workload identity (an OIDC token or a SPIFFE SVID). The key id is
`<controller>#acdp-kl-<hex>`, and the body pins the attestation by
`key_attestation: {ctx_id, content_hash}`. The attestation itself is an
ordinary registry-signed context of type `acdp:key-attestation`.

Support is behind the **`keyless`** feature. Every build fails closed:

- `DidDocument::find_by_fragment` never returns an `acdp-kl-` method, and
  the RFC-ACDP-0001 §5.11 verifiers (`acdp::verify`) refuse a keyless key
  id with `KeyResolution`.
- Without the feature, `VerifiedContext::fetch` refuses a keyless body the
  same way, and `acdp-chain` reports `key: unresolvable` and
  `signature: unresolvable`, so the node is refused (`kl-007`, `kl-008` E).

With the feature, `VerifiedContext` verifies a keyless body by RFC-ACDP-0021
§8.1 instead of §5.11. The attestation is fetched from the serving
registry, and the body's own receipt is required whatever `ReceiptPolicy`
says, because it is the only time that places the signature in the
attestation window. The client module docs (`acdp::client::keyless`) list
the order of the checks.

**Which attesters you accept (§11).** The default accepts none, so a
default policy refuses every keyless body with `untrusted_attester`
(`kl-006` A). Accept registries by name, by a trust list, or both:

```rust,ignore
use acdp::client::{KeylessPolicy, KeylessTrust, VerificationPolicy};

let policy = VerificationPolicy {
    keyless: KeylessPolicy::attesters(["did:web:registry.example.com"])
        // optional: also accept any attester a trust list makes `trusted`
        .with_trust_lists(KeylessTrust::at(&trust_lists, chrono::Utc::now(), None)),
    ..VerificationPolicy::default()
};
```

**Outcomes.** A keyless body that verifies gets one of the three existing
`KeyAuthorization` values:

| Outcome | When |
|---|---|
| `CurrentlyAuthorized` | The controller's current DID document lists the identity in its `AcdpKeylessSigning` service. |
| `HistoricallyAuthorized` | It no longer lists it. Removing an identity does not reach back (§9.1). |
| `HistoricallyAuthorizedPreCompromise` | An RFC-ACDP-0014 revocation of the attested fingerprint is dated after the receipt. |

`KeyAuthorization`, `RevocationTrustClass` and `AcdpError` gain no
variants. A refusal reuses an existing error variant, and its §8.1 reason
token rides on the message. Read it with `KeylessReason::of(&err)`:

| Token | Variant |
|---|---|
| `attestation_invalid` | `KeyResolution` |
| `attestation_mismatch`, `untrusted_attester`, `unplaceable`, `outside_attestation_window` | `KeyNotAuthorized` |
| `attestation_withdrawn` | `KeyNotAuthorized` (a retracted attestation counts as a revocation from `not_before`, §9.2) |
| `invalid_signature` | `InvalidSignature` |
| `revoked` | `KeyRevoked` |
| `controller_unreachable` | `KeyResolutionUnreachable` (transient) |

The registry-side tokens of `POST /key-attestations` (`issuer_not_accepted`,
`pop_invalid`, …) come back on the wire error and parse the same way. Only
`issuer_unreachable` is transient: the registry could not fetch the token
issuer's keys (`KeyResolutionUnreachable`), so a publishing client may retry.
`KeylessReason` is `#[non_exhaustive]` and `KeylessReason::ALL` is a slice,
so a new spec token is an additive change.

**Attester key rotation (§8.1 step 1).** The attestation's own signature
gets the RFC-ACDP-0010 §10 historical arm through its receipt. Suppose the
attester rotated the signing key out of `assertionMethod` but kept it in
`verificationMethod`. Then the attestation still verifies when its receipt
verifies with that key's fingerprint (`kl-005` M), and the body's status is
unchanged. A key removed from `verificationMethod` entirely is the
attester's compromise signal and gives `attestation_invalid` (`kl-005` N).
The same holds for keyless-signed revocations and in `acdp-chain`, where
the node's `key` and `signature` stages are then `unresolvable`.

**Presence rules (§6.2).** A keyless key id with no `key_attestation` fails
with `attestation_invalid`. A `key_attestation` on a body whose key id is
not keyless fails with `attestation_mismatch`, even with the key in the DID
document.

**Lifecycle events (§6.3).** A keyless key never signs an RFC-ACDP-0013
event: `LifecycleEvent::sign_with` refuses a keyless key id
(`keyless_event_unsupported`), and a hand-signed one is not admitted.

**Keyless-signed revocations (§9.3).** Revocation discovery sets aside a
candidate signed by a keyless key. It then verifies that key through §8.1,
steps 1–7, using the same `VerificationPolicy.keyless` attesters as for
bodies. The outcome depends on the attestation:

- **Org-wide:** the revocation counts as producer-signed and applies.
- **Not org-wide:** it never applies, and is reported in
  `revocation_hints()` (`kl-005` G).
- **Cannot be evaluated** (built without the `keyless` feature, the
  attester is not accepted, or the evidence is *unavailable*): the verdict
  for the key it names is `unknown` (`unverifiable_candidate`), never
  not-revoked. Under `FailClosed` this is `RevocationUnknown`. Evidence is
  unavailable when it cannot be obtained: the attestation, its receipt or
  the attester's DID document, or the wrong attestation was served.
- **Definitively invalid** (the obtained attestation fails its hash,
  signature, receipt or §5.3 checks, steps 3–6 fail, or the attestation is
  withdrawn): the revocation is ignored, as is any revocation whose
  signature fails (`kl-005` L).

`find_revocations_verdict` accepts no keyless attester. So does the
standalone `find_revocations` family, which returns
`RevocationCandidateUnverifiable` for such a candidate. `acdp-chain`
applies the same rules: when it cannot evaluate such a revocation, the
`key_revocation` stage is `{value: unknown, revocation_ctx_id}` (the lowest
such ctx_id), with no basis or evidence_time (`kl-008` F). `revoked` and
`unplaceable` still win over it.

**Chains (§10).** `acdp-chain` with the `keyless` feature reads the
attestation from the bundle's `contexts`, like a revocation body. The
accepted attesters come only from `pinned.keyless_attesters`, so
`options_digest` covers them; `Options::with_keyless_attesters` sets it.
No trust list is consulted inside `verify_chain`: evaluate the lists first
and pin the registry DIDs they accept. (The `Options::keyless_attesters`
field is deprecated and a non-empty value is refused.) The `key` stage is
`current` or `historical_receipt_attested` with basis `registry` and
`evidence_time` = the body receipt's `created_at`. A forged signature is
`signature: invalid` with the key stage as located.

An attestation missing from the bundle, not admitted at T, or with no
controller DID-document snapshot selectable at T gives `unresolvable` in
the latest pass and `unknown` (`no_evidence_at_as_of`) in the as-of pass.
Any other failure, including a `key_attestation` that breaks the presence
rules, gives `key` and `signature` `unresolvable`. An admitted retraction
of the attestation (signed by the attester or admitted on its event
receipt) shows up in the `key_revocation` stage as `revoked`.

## Fetching data references

A verified context tells you *where* its data lives; fetching that data is a
separate, SSRF-guarded step. `HttpsDataRefFetcher` applies the same network
defenses as the registry client.

```rust,no_run
# #[cfg(feature = "client")]
# async fn run(data_ref: &acdp::types::DataRef) -> Result<(), acdp::AcdpError> {
use acdp::client::{fetch_and_verify_data_ref, HttpsDataRefFetcher};

let fetcher = HttpsDataRefFetcher::default();
let bytes = fetch_and_verify_data_ref(data_ref, &fetcher).await?;
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

`.with_revocation_policy(...)` and `.with_revocation_cache(...)` let the resolver carry RFC-ACDP-0014 revocation discovery into every node it
verifies — see "Caching discovered revocations" above for the full model,
including the walk-scoped cache default and the 30s/30s timeout caveat.
`seed_client` is fill-if-absent for the cache too: a seeded client with no
`RevocationCache` of its own is given the resolver's (or the current walk's);
one that already carries its own keeps it.

`.with_auth_provider(...)` presents [read credentials](#read-authentication)
on every hop. The provider is asked per hop authority, so a
`PerAuthorityTokens` table gives each registry only its own token. It is
fill-if-absent like the cache: a seeded client that carries its own
provider keeps it.

**Per-authority clients.** The resolver builds one `RegistryClient` per
foreign authority and reuses it. Each client filters DNS answers through
the `SsrfPolicy` at resolution time, on every connection. It does not pin
the first IP, so an authority whose addresses change is never stranded on
a stale one, and a rebinding answer is refused at connect time. The cache
holds at most `MAX_CACHED_CLIENTS` (256) built clients and evicts the
oldest first. Clients passed to `seed_client` are never evicted.

## Calling from synchronous code

With the `blocking` feature, `acdp::client::blocking::BlockingClient` runs
the async client on its own small tokio runtime and gives every call a hard
deadline. It is for code that cannot be async: a sync trait impl, a plugin
host, a thread pool.

```rust,ignore
use std::time::{Duration, Instant};
use acdp::client::blocking::BlockingClient;

let c = BlockingClient::new(RegistryClient::new(url)?, WebResolver::new())?;
let deadline = Instant::now() + Duration::from_millis(500);
let ctx = c.fetch_verified(&ctx_id, &VerificationPolicy::default(), deadline)?;
```

| Method | Wraps |
|---|---|
| `retrieve` | `RegistryClient::retrieve` (unverified) |
| `fetch_verified` / `fetch_current_verified` | `VerifiedContext::fetch_with_policy` / `fetch_current_with_policy` |
| `resolve` | `CrossRegistryResolver::resolve` (after `with_cross_registry`) |
| `changes` | `RegistryClient::changes` (one feed page; entries are hints) |
| `verify_change` | `recall::verify_change`; `held` is copied |
| `run` | any other async call, as `|c| async move { … }` |

- **Deadline.** Each method takes a `std::time::Instant`. When it passes,
  the call returns `AcdpError::DeadlineExceeded` and the in-flight work is
  cancelled. No partial result is returned. A deadline already in the past
  fails before any request. `DeadlineExceeded` is transient: for
  `verify_change` it means *not decided*, so leave the entry unprocessed
  and retry.
- **Inside a runtime.** Calling from a tokio runtime does not panic. On a
  multi-threaded runtime the facade uses `block_in_place` while it waits.
  On a current-thread runtime it blocks that thread; the work itself runs
  on the facade's own threads, so it cannot deadlock. Async code should
  still call the async API directly.
- **Threads.** `BlockingClient` is `Clone + Send + Sync`. Clones share one
  runtime (default 2 workers; `with_worker_threads` to change). The
  runtime shuts down on its own thread when the last clone is dropped,
  so dropping it inside async code is safe.
- **Own clients.** Give the facade its own `RegistryClient`,
  `WebResolver` and `CrossRegistryResolver`. Don't share instances that
  another runtime also uses: pooled connections belong to the runtime that
  opened them.

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
