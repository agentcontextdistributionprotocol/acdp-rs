# Migrating to 0.15.0

0.15.0 is a breaking release. It carries the consumer-side work behind
spec PR [#77](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/pull/77)
(RFC-ACDP-0001 / 0004 / 0010 / 0014 amendments on the 0.5.0 Draft line) and
[acdp-rs#385](https://github.com/agentcontextdistributionprotocol/acdp-rs/issues/385).
There was no 0.14.6, so the already-normative fixes are listed here too.

Most of the changes either make the client fail closed where it used to
answer, or report a verdict where it used to stay silent. This page is in
three parts: what can break your build, what changes at runtime, and what
is new.

## Upgrade registries together

From 0.15.0, producers emit the RFC-ACDP-0001 §5.3 canonical `.mmmZ` form
for `expires_at` and `data_period`. For a whole-second instant that is
`2026-10-16T00:00:00.000Z`, not `…:00Z`. A registry built on acdp-rs
≤ 0.14.5 recomputes the hash from its typed body and rejects such a publish
with `hash_mismatch`. Upgrade the registry (`acdp-registry-rs`) to an
acdp 0.15 build before or together with your producers.

The reverse direction is safe. A 0.15 consumer still verifies bodies that
≤ 0.14.5 producers wrote, because typed-only paths try the canonical
rendering first and then the legacy whole-second one.

## Compile-time changes

| Before (0.14.x) | 0.15.0 | What to do |
|---|---|---|
| `AcdpError::RevocationDiscoveryFailed { source }` | `AcdpError::RevocationUnknown { reason, source, detail }` | Match the new variant. `reason` is an `UnknownReason` (`Truncated`, `Unanswerable`, `Transient`, `UnverifiableCandidate`). Only `Transient` is retryable (`is_transient()`). |
| A revocation refusal was `AcdpError::KeyNotAuthorized(String)` | `AcdpError::KeyRevoked(Box<RevocationRefusal>)` | The wire code is still `key_not_authorized`. Use `err.is_key_not_authorized()` to match both, and `err.revocation_refusal()` for the effect, boundary and attributed revocation. |
| — | `AcdpError::RevocationCandidateUnverifiable(String)` | New variant; `AcdpError` is `#[non_exhaustive]`, so a wildcard arm already covers it. |
| `FullContext { body, state, … }` literals | `FullContext` has a `raw_body` field and a hand-written `Deserialize` | Deserialize `FullContext` from the wire rather than building it by hand. If you must build one, set `raw_body: None`. |
| `VerificationPolicy { … }` literals | New fields: `require_did_web_for_v0_1_0`, `log_inclusion`, `witness_quorum` | Use `..VerificationPolicy::default()` in struct literals. |
| `VerificationReport { … }` literals | New fields: `receipt_key_status`, `receipt_verdict`, `lineage_binding`, `revocation_verdict`, `revocation_hints`, `log_inclusion_verdict`, `witness_quorum` | Read the report; don't construct it. |
| exhaustive `match` on `ReceiptPolicy` | `ReceiptPolicy` is `#[non_exhaustive]` and gains `VerifyAndReport` | Add a wildcard arm. |
| `KeyRevocation { … }` literals | New `ctx_id: Option<CtxId>` (attribution; `Some` when parsed from a `Body`) | Parse with `KeyRevocation::from_body` / `from_publish_request` or add `ctx_id: None`. |
| `RegistryClientBuilder: UnwindSafe + RefUnwindSafe` | No longer auto-implemented, because the builder can hold an `Arc<dyn AuthProvider>` | Wrap the builder in `AssertUnwindSafe` if you move it into `catch_unwind`. `RegistryClient` itself is unchanged. |
| `acdp_types::revocation::RevocationTrustClass` | Defined in `acdp-primitives` and re-exported at the same paths | Nothing. `cargo semver-checks` reports it as removed because it does not follow re-exports across crates. |

## Runtime changes

**DID resolution (did-001, RFC-ACDP-0001 §5.11 "Caching")**
- A non-2xx DID-document response, or a timeout, is now
  `KeyResolutionUnreachable` (transient, retryable). It was a permanent
  `KeyResolution`. A response that is not JSON stays permanent.
- Before the resolver reports "no such verification method" or
  `key_not_authorized` against a *cached* document, it re-fetches the
  document once, bypassing the cache, and re-runs the check. The re-fetch
  is rate-limited to once per DID per `DEFAULT_FORCED_REFRESH_INTERVAL`
  (1 h). Tune it with `WebResolver::with_forced_refresh_interval`.
- `WebResolver::resolve_fresh` is the public form of that re-fetch.
- A key absent from a stale copy whose re-fetch was rate-limited is
  reported as transient `KeyResolutionUnreachable`, never as a permanent
  absence.

**Hashing (can-013, RFC-ACDP-0001 §5.7)**
- `content_hash` is recomputed over the received raw `body` JSON
  (`FullContext::raw_body`), no longer over a re-serialization of the typed
  struct. A body carrying members this crate does not model now verifies
  where it used to fail `hash_mismatch`.
- `PublishValidator::validate_post_schema_raw` is the registry-side
  equivalent.

**Registry-assigned bindings (RFC-ACDP-0004 §2.1, P7)**
- Every fetch path now checks that a v1 `lineage_id` equals its offline
  derivation, and that `origin_registry` equals the `ctx_id` authority.
- A context that fails either check is a `SchemaViolation`.
- Fixtures that used placeholder lineage IDs need real derivations
  (`acdp::crypto::hash::derive_lineage_id`).
- `VerifiedContext::lineage_binding()` reports `Derived`,
  `ReceiptAttested` or `Unbound`.

**Revocation (RFC-ACDP-0014 §7/§8)**
- **`unknown` is a verdict, not a pass.**
  - An unanswerable, truncated or transient lookup, or a candidate that
    cannot be placed, used to be dropped or folded into not-revoked.
  - It now yields `RevocationVerdict::Unknown`.
  - Under enforcement, the refusal is `AcdpError::RevocationUnknown`.
- **Precedence.** A verified revocation now refuses even if another
  lookup came back unknown. The order is refusal > unknown >
  pre-compromise > not-revoked.
- **Producer scope is a MUST.**
  - A revocation applies only if its issuer is in scope for the producer.
  - Out-of-scope revocations are surfaced as `revocation_hints()` and
    never applied.
- **Strict placement (P5).**
  - A context dated before the compromise boundary is placed there only
    by a receipt verified under the registry's *current* receipt key.
  - A historical key yields "unplaceable", which fails closed.
  - Opt out with
    `RevocationPolicy::default().accept_historical_receipt_key_for_pre_t()`.
- **Historical arm.**
  - Discovery now places a rotated-out signer by its `registry_receipt`.
  - Lineage members without a receipt are re-retrieved by `ctx_id`, and
    that retrieval is charged to the budget.
- **Freshness.**
  - `RevocationDiscovery::freshness` defaults to 300 s
    (`RECOMMENDED_NEGATIVE_FRESHNESS`). It used to be zero.
  - It governs only cached *negative* markers.
  - Verified revocations in a `RevocationCache` are never evicted, and
    they are stored apart from those markers.
- **`find_revocations`** is producer-signed-only, and has been since 0.9.0.
  For the full trust-class view, use `find_revocations_verdict`.

**Transport**
- Every `RegistryClient` request sends
  `Accept: application/acdp+json, application/json;q=0.9` (`ACDP_ACCEPT`).
- `CrossRegistryResolver` no longer pins the first DNS answer per
  authority. Each hop's client filters DNS answers through the
  `SsrfPolicy` on every resolution.
- The per-authority client cache is bounded at `MAX_CACHED_CLIENTS` (256).
  Seeded clients are never evicted.

**v0.1.0 strict profile (RFC-ACDP-0001 §5.11)**
- `VerificationPolicy::require_did_web_for_v0_1_0` defaults to `true`. It
  rejects a body with `acdp_version` absent or `"0.1.0"` unless its signer
  uses `did:web`.
- Set it to `false` only for legacy corpora.

## New

| API | Purpose | Docs |
|---|---|---|
| `VerifiedContext::revocation_verdict()`, `revocation_hints()`, `recheck_revocation()`, `find_revocations_verdict` | Typed, attributable revocation verdicts (`Revoked` / `NotRevoked` / `Unknown`), and re-checking a held context without a refetch. | [Consuming § Revocation verdicts](consuming.md#revocation-verdicts) |
| `VerifiedContext::receipt_key_status()`, `receipt_verdict()`, `head_receipt_verdict()`; `ReceiptPolicy::VerifyAndReport` | Whether the receipt verified under the current or a historical key, with the receipt verdict reported separately from the body's. | [Consuming](consuming.md#verifiedcontext--the-verification-pipeline) |
| `AuthProvider`, `BearerToken`, `StaticBearerToken`, `PerAuthorityTokens`; `RegistryClient::with_auth_provider`, `CrossRegistryResolver::with_auth_provider` | `bearer_jwt` read authentication (RFC-ACDP-0008 §6.2), scoped per authority, sent on reads only. | [Consuming § Read authentication](consuming.md#read-authentication) |
| `VerificationPolicy::{log_inclusion, witness_quorum}`, `LogInclusionPolicy`, `WitnessQuorumPolicy`, `WitnessEnforcement`; `verified_log_inclusion()`, `witness_quorum()` | Transparency-log inclusion (RFC-ACDP-0012 §9) and witness quorum (RFC-ACDP-0015 §8), opt-in. | [Consuming § Transparency](consuming.md#transparency-log-and-witnesses) |
| `LogLeaf::for_publish` | Builds the RFC-ACDP-0012 leaf from verified material. Registries use it at append time. | rustdoc |
| `acdp::did::did_key_document` | Synthesizes a `did:key` DID document offline. | rustdoc |
| `WitnessQuorumReport: Clone + Debug` | — | — |

## Recommended consumer configuration

```rust,ignore
use acdp::client::{
    CrossRegistryResolver, RevocationCache, RevocationDiscovery, RevocationPolicy,
    RECOMMENDED_NEGATIVE_FRESHNESS,
};

let resolver = CrossRegistryResolver::new()
    .with_revocation_policy(
        RevocationPolicy::default().with_discovery(RevocationDiscovery::all_trust_classes()),
    )
    .with_revocation_cache(RevocationCache::new());
// RevocationDiscovery's freshness already defaults to
// RECOMMENDED_NEGATIVE_FRESHNESS (300 s); set max_requests / max_bytes
// to your latency budget.
```
