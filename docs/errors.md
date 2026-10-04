# Errors & Retries

Everything fallible in the crate returns `Result<_, acdp::AcdpError>`.
`AcdpError` is a typed mapping of every RFC-ACDP-0007 §5 wire error code
(plus the codes later RFCs added) and a handful of local/transport errors. It is
`#[non_exhaustive]`, so new variants can be added without a breaking release. This page explains the variants,
how registry wire errors round-trip into them, and which are safe to retry.

The wire error envelope is specified in
[RFC-ACDP-0007 (Capabilities & Errors)](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/rfcs/RFC-ACDP-0007-capabilities.md).
The canonical code registry, including which wire line introduced each code, is
the spec's
[`registries/error-codes.md`](https://github.com/agentcontextdistributionprotocol/agentcontextdistributionprotocol/blob/main/registries/error-codes.md).
The table below only adds this crate's Rust variant for each code.

## Wire errors round-trip into typed variants

When a registry returns an error envelope, the client maps it via
`AcdpError::from_wire_error`. Each canonical code becomes a specific variant;
**unknown/future codes pass through as `AcdpError::Registry(WireError)`** so a
newer registry never breaks an older client.

| Wire code | `AcdpError` variant |
|---|---|
| `invalid_signature` | `InvalidSignature` |
| `hash_mismatch` | `RemoteHashMismatch` |
| `data_ref_hash_mismatch` | `DataRefHashMismatch` |
| `schema_violation` | `SchemaViolation` |
| `not_authorized` | `NotAuthorized` |
| `not_found` | `NotFound` |
| `rate_limited` | `RateLimited` |
| `payload_too_large` | `PayloadTooLarge` |
| `embedded_too_large` | `EmbeddedTooLarge` |
| `key_resolution_failed` | `KeyResolution` |
| `key_resolution_unreachable` | `KeyResolutionUnreachable` |
| `key_not_authorized` | `KeyNotAuthorized` |
| `unsupported_algorithm` | `UnsupportedAlgorithm` |
| `unsupported_media_type` | `UnsupportedMediaType` |
| `not_implemented` | `NotImplemented` |
| `cursor_expired` | `CursorExpired` |
| `invalid_cursor` | `InvalidCursor` |
| `duplicate_publish` | `DuplicatePublish` |
| `cross_registry_resolution_failed` | `CrossRegistryResolutionFailed` |
| `invalid_receipt` | `InvalidReceipt` |
| `invalid_log_proof` | `InvalidLogProof` |
| `invalid_witness_cosignature` | `InvalidWitnessCosignature` |
| `immutable_field` | `ImmutableField` |
| `invalid_lifecycle_transition` | `InvalidLifecycleTransition` |
| `internal_error` | `RegistryInternal` |
| `superseded_target` | `SupersededTarget { reason, message }` |
| *(unknown)* | `Registry(WireError)` |

> This round-trip is exhaustively pinned by the `all_26_wire_codes_round_trip`
> test in `crates/acdp-primitives/src/error.rs`. Adding a new code is a coordinated three-edit change —
> see [below](#adding-a-new-wire-error-code).

## Local vs. remote hash mismatches

Two distinct variants exist deliberately:

- **`HashMismatch { stored, recomputed }`** — *you* detected it. The
  `content_hash` you recomputed locally doesn't match the one in the body. This
  is the tamper-detection path in the verification pipeline.
- **`RemoteHashMismatch`** — the *registry* rejected your publish with
  `hash_mismatch`. The hash you sent didn't match the body you sent.

The same split applies to signatures (local verification failure vs. a
registry's `invalid_signature` rejection — both map to `InvalidSignature`).

## Supersession failures

A `superseded_target` wire error carries a `details.reason` sub-vocabulary,
decoded into `SupersessionReason`:

| `SupersessionReason` | Meaning |
|---|---|
| `NotFound` | the `supersedes` target doesn't exist on this registry |
| `LineageMismatch` | the target's `lineage_id` differs from the new publication's |
| `VersionMismatch` | the new version isn't exactly `previous.version + 1` |
| `AlreadySuperseded` | the target was already superseded by another version |
| `CrossRegistrySupersessionUnsupported` | v0.1.0 only allows same-registry supersession |
| `LineageWalkFailed` | an intermediate context in the `supersedes` chain couldn't be retrieved |
| `RevocationTypeMismatch` | a non-revocation context superseded a `key-revocation` target (RFC-ACDP-0014 §4/§10) — only emitted by registries advertising `acdp_version >= 0.5.0`; below that version this rejection is `SchemaViolation` instead |
| `Other` | a reason this library version doesn't recognize (forward-compat) |

`SupersessionReason` is `#[non_exhaustive]` — match it with a wildcard arm, not
exhaustively, so a future variant addition isn't a breaking change for callers.

Most of these are prevented up front by using
[`supersede_body`](producing.md#supersession), which sets `version`,
`supersedes`, and `expected_lineage_id` consistently.

## Retryability

`AcdpError::is_transient()` tells you whether retrying the *same* request body
(with the same `Idempotency-Key`, if any) is worthwhile. It returns `true` only
for the variants the spec marks retryable:

| Transient (`is_transient() == true`) | Why |
|---|---|
| `KeyResolutionUnreachable` | the DID host was temporarily unreachable (RFC-ACDP-0001 §5.11) |
| `RateLimited` | back off and retry (RFC-ACDP-0008 §4.3) |
| `CrossRegistryResolutionFailed` | a foreign hop failed transiently (RFC-ACDP-0006 §7) |
| `RegistryInternal` | the registry hit an internal error (HTTP 5xx) |
| `Http` | a connect/timeout/transport error — **including** a DNS-rebinding refusal on the `RegistryClient` path (see the note below) |
| `RevocationDiscoveryFailed { source }` | a wrapper, not a wire code: it delegates to `source.is_transient()` |

Everything else — `InvalidSignature`, `SchemaViolation`, `HashMismatch`,
`KeyResolution` (permanent resolution failure: a DNS-rebinding refusal while
resolving a `did:web` document, and also a `did:key` resolver fault raised by
publish-request validation, which surfaces as `KeyResolution` rather than
`SchemaViolation`), `NotAuthorized`, `NotFound`, `PayloadTooLarge`,
`ContextIdMismatch` (locally detected context substitution — RFC-ACDP-0008
§9.1; a misbehaving registry will serve the same wrong body on retry),
`RevocationDiscoveryBudgetExceeded` (a caller-configured discovery
request/byte budget ran out; retrying reproduces it) — is
**permanent**. Retrying won't help; fix the request or the key.

> **DNS-rebinding refusals map differently per path.** `SafeDnsResolver`
> refuses a hostname that resolves into a forbidden range at DNS time. On the
> `WebResolver` (`did:web`) path that refusal is classified as
> `KeyResolution`, which is permanent. On `RegistryClient` (which goes through
> `From<reqwest::Error>`), the same refusal arrives as
> `Http("connection failed: … SSRF policy … forbidden …")`, which is
> **transient**, so `publish_with_retry` will retry it until `max_attempts`.
> See [security.md](security.md#dns-rebinding-protection-is-active).

`RegistryClient::publish_with_retry(req, idempotency_key, max_attempts)` uses
exactly this predicate, with bounded backoff (250 ms → 500 ms → 1 s → 2 s):

```rust,no_run
# #[cfg(feature = "client")]
# async fn run(client: &acdp::client::RegistryClient, req: &acdp::PublishRequest) -> Result<(), acdp::AcdpError> {
let resp = client.publish_with_retry(req, "publish-2026-06-10-abc", 4).await?;
# let _ = resp; Ok(()) }
```

## Handling errors

`AcdpError` is `#[non_exhaustive]`: `match` on the variants you care about, but
always keep a wildcard arm (here, `other`), or use the convenience predicates:

```rust
# fn handle(err: acdp::AcdpError) {
use acdp::AcdpError;

match &err {
    AcdpError::InvalidSignature(msg) => eprintln!("untrusted context: {msg}"),
    AcdpError::NotFound(_)            => { /* 404 — nothing to retry */ }
    e if e.is_transient()            => { /* back off and retry */ }
    other                            => eprintln!("permanent failure: {other}"),
}
# }
```

`From` conversions are provided for `serde_json::Error` (→ `Serialization`),
`std::io::Error` (→ `Http`), and `reqwest::Error` (→ `Http`, prefixed
`connection failed:` for connect/timeout errors), so `?` works naturally in
client code. The `reqwest::Error` conversion appends the error's whole
`source()` chain to the message. Without that, reqwest's own `Display` would
hide the underlying cause, such as a `SafeDnsResolver` SSRF refusal.

## Adding a new wire error code

If you contribute a new code (per CONTRIBUTING.md), it's three coordinated edits:

1. A new variant in `crates/acdp-primitives/src/error.rs::AcdpError`, with the RFC citation.
2. A `match` arm in `AcdpError::from_wire_error`.
3. Extend the `all_26_wire_codes_round_trip` test (and bump its count).

Also revisit `is_transient` (is the new code retryable?) and
`SupersessionReason` (if the code uses a `details.reason` sub-vocabulary).
