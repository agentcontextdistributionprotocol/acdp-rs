//! Error types for the ACDP library.
//!
//! Error variants align with the wire vocabulary defined by
//! `acdp-error.schema.json` and RFC-ACDP-0007 §5. The
//! [`AcdpError::from_wire_error`] helper converts a
//! [`crate::wire_error::WireError`] (HTTP response body shape) into a typed
//! variant.

use crate::primitives::ContentHash;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Top-level error type.
///
/// `#[non_exhaustive]`: the wire vocabulary (RFC-ACDP-0007 §5) keeps growing
/// as new RFCs land — 25 wire codes now, up from 21 not long ago, with
/// RFC-ACDP-0009 reserved and still unimplemented. Without this attribute,
/// every new variant is a semver-breaking change for any downstream crate
/// that matches on `AcdpError` exhaustively. Same rationale as
/// `SsrfReason` in `crates/acdp-safe-http/src/lib.rs` ("future spec
/// revisions may add ranges"); match with a wildcard arm.
/// `Clone` (added for issue #248 Phase 4): `VerifiedContext` and
/// `VerificationReport` each need an independently-owned copy of a
/// `ProceedWithKnown`-swallowed revocation-discovery failure — one via
/// `VerifiedContext::revocation_discovery_failure()`, the other via
/// `VerificationReport::revocation_discovery` — so both surfaces stay
/// non-silent from a single call. Every variant field (`String`,
/// `&'static str`, `ContentHash`, `WireError`, `SupersessionReason`,
/// and the recursive `Box<AcdpError>` in `RevocationDiscoveryFailed`)
/// is already `Clone`, so this is a free addition with no wire-format
/// or matching impact.
///
/// This is a standing constraint on every future variant, not just the
/// ones that exist today: every future variant's payloads must remain
/// `Clone`. A variant that needs a structured source should hold
/// `Arc<dyn std::error::Error + Send + Sync>` (which is `Clone`
/// regardless of the inner type, and still preserves `source()`
/// chaining), never `Box<dyn Error>` or a bare `io::Error` (neither is
/// `Clone`). This is not a new tradeoff introduced by adding `Clone`
/// here — `From<std::io::Error>` and `From<reqwest::Error>` already
/// stringify into `Http(String)` rather than carry the error value, so
/// value semantics over reference/source-chain semantics was already
/// the twice-exercised choice for this type; `Clone` just makes it a
/// documented rule instead of an implicit pattern.
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum AcdpError {
    // ── Cryptography ─────────────────────────────────────────────────────────
    /// JCS canonicalization failed (input not serializable).
    #[error("JCS canonicalization failed: {0}")]
    Canonicalization(String),

    /// Stored `content_hash` did not match the recomputed value
    /// (locally detected during signature verification).
    #[error("content_hash mismatch\n  stored:     {stored}\n  recomputed: {recomputed}")]
    HashMismatch {
        /// The hash claimed by the body or request.
        stored: ContentHash,
        /// The hash recomputed by the verifier.
        recomputed: ContentHash,
    },

    /// Locally detected: the registry returned a body whose `ctx_id` is not
    /// the one that was requested (context substitution). Not a wire code —
    /// the client detects it. Permanent; fail closed.
    ///
    /// Implements RFC-ACDP-0006 §4.1 step 7 (NORMATIVE, "Bind the resolved
    /// identity"): step 7 requires exactly this comparison — `body.ctx_id`
    /// against the `ctx_id` used to construct the request — and permits a
    /// consumer to surface "an equivalent typed error" in place of the
    /// registry-side `cross_registry_resolution_failed` wire code; this
    /// variant is that typed error. See RFC-ACDP-0008 §9.1 for the threat
    /// this closes: without it, a registry can serve any other
    /// validly-signed body by the same producer under the requested
    /// context's URL, and both signature verification and `content_hash`
    /// recomputation still pass. It does **not** close §9.1 in full: a
    /// registry that genuinely republishes the same content under a new
    /// `ctx_id` still passes; only serve-time substitution — a different
    /// id claimed to be the one requested — is caught.
    #[error("context substitution: requested {requested}, registry served {served}")]
    ContextIdMismatch {
        /// The `ctx_id` the caller requested.
        requested: String,
        /// The `ctx_id` actually present on the body the registry served.
        served: String,
    },

    /// Locally detected: `GET /lineages/{id}` (RFC-ACDP-0013 §8.1) did not
    /// serve a lineage the caller could accept — either it came back with
    /// no members at all, or (when `ctx_id` is `Some`) its members did not
    /// include the `ctx_id` a live search match named for that lineage.
    /// Not a wire code — RFC-ACDP-0014 §10 ("No new wire error code"):
    /// this is a locally-detected consumer-side binding failure, exactly
    /// the same kind of thing as [`AcdpError::ContextIdMismatch`] (issue
    /// #189) but for the lineage-walk path added for issue #226. Permanent;
    /// fail closed — never added to [`AcdpError::is_transient`].
    #[error(
        "incomplete lineage {lineage_id}: registry-served members did not satisfy the \
         expected membership (expected ctx_id: {ctx_id:?})"
    )]
    IncompleteLineage {
        /// The lineage id that was walked (`GET /lineages/{id}`).
        lineage_id: String,
        /// The `ctx_id` a live search match named for this lineage, when
        /// the walk was invoked with a specific member to check for.
        /// `None` when the walk was invoked directly with no particular
        /// member to verify (e.g. via `find_revocations_in_lineage`),
        /// in which case only the empty-lineage case can produce this
        /// variant.
        ctx_id: Option<String>,
    },

    /// Locally detected: a revocation-discovery search helper
    /// (`find_revocations`, `find_registry_attested_revocations` in
    /// `acdp-client`) exhausted its pagination safety cap
    /// (`MAX_SEARCH_PAGES`) with a search cursor still remaining, or
    /// named more candidate revocation-lineage ids than its lineage-walk
    /// safety cap (`MAX_LINEAGE_WALKS`) allows to fetch. Not a wire code
    /// — RFC-ACDP-0014 §10 ("No new wire error code"): this is a
    /// client-local safety-limit signal the registry cannot express, the
    /// same rationale as [`AcdpError::ContextIdMismatch`] and
    /// [`AcdpError::IncompleteLineage`]. Permanent for the same request
    /// shape — never added to [`AcdpError::is_transient`]; retrying an
    /// identical query reproduces the same truncation.
    ///
    /// Both caps exist as hostile-registry DoS protection
    /// (`MAX_SEARCH_PAGES` bounds search round-trips; `MAX_LINEAGE_WALKS`
    /// bounds the `GET /lineages/{id}` fetches a search result can
    /// trigger, each capped at 1 MB). Search results are ordered
    /// `created_at DESC`, so hitting a cap sheds the OLDEST — most
    /// likely earliest-`compromised_since` — members first: a silently
    /// truncated revocation set narrows a compromise window, which is
    /// precisely the outcome RFC-ACDP-0014 §4 ("earliest T across a
    /// revocation lineage is effective") forbids. A knowingly-partial
    /// answer from these discovery helpers is strictly worse than a
    /// loud refusal, so exhausting either cap with more results
    /// remaining on the registry is a hard error, never a silently
    /// partial `Vec`.
    #[error("search truncated: {0}")]
    SearchTruncated(String),

    /// Locally detected (issue #258): RFC-ACDP-0014 §8 revocation
    /// auto-discovery (`RevocationDiscovery::max_requests` /
    /// `RevocationDiscovery::max_bytes` in `acdp-client`) exhausted its
    /// caller-configured request-count or cumulative-byte budget before
    /// both trust-class lookups finished. Not a wire code — RFC-ACDP-0014
    /// §10 ("No new wire error code") forbids one, and this is
    /// client-side only, the same rationale as
    /// [`AcdpError::SearchTruncated`]. Permanent for the same request
    /// shape — never added to [`AcdpError::is_transient`] — exhausting a
    /// budget is closer to `SearchTruncated` ("we did not see
    /// everything") than to a transport error, and carries the same
    /// attacker-inducible-downgrade warning: a hostile registry that
    /// learns a caller's budget can pad harmless-looking traffic to
    /// exhaust it before a real revocation is found.
    ///
    /// The two budgets are combined across BOTH lookups
    /// (`find_revocations` and, when opted in,
    /// `find_registry_attested_revocations`), not one ceiling each —
    /// enabling the registry-attested trust class does not double the
    /// allowance. The request count is enforced exactly: the slot is
    /// reserved *before* the request is issued, so a request is never
    /// issued once the budget is reserved out, and — unlike the byte
    /// count below — a 503, a parse failure, or a `PayloadTooLarge` on
    /// an already-reserved request still consumes its slot. The byte
    /// count is enforced on a check-before-issue basis using the running
    /// total from completed requests, so up to TWO in-flight requests
    /// (one per concurrently-running trust-class lookup) can push the
    /// total over `max_bytes` before the NEXT request observes the
    /// overrun. Counts registry traffic only (`acdp-client`'s
    /// `RegistryClient::{capabilities, retrieve, lineage, search}`) —
    /// DID-document fetches issued via `WebResolver` are not counted.
    /// Only the byte count is scoped to successfully-parsed response
    /// bodies: the capped error-envelope read on a non-success response
    /// is never charged to `max_bytes`, but IS charged to `max_requests`
    /// (the slot was already reserved before the response arrived).
    #[error("revocation discovery budget exceeded: {0}")]
    RevocationDiscoveryBudgetExceeded(String),

    /// Locally detected: RFC-ACDP-0014 §8 revocation auto-discovery
    /// (`RevocationPolicy::discover` in `acdp-client`) failed under
    /// `DiscoveryFailurePolicy::FailClosed`. Not a wire code — the same
    /// rationale as [`AcdpError::ContextIdMismatch`],
    /// [`AcdpError::IncompleteLineage`], and [`AcdpError::SearchTruncated`]:
    /// this is a client-local decision about how to react to a failure
    /// the registry already reported some other way, so it wraps that
    /// failure rather than inventing a new wire vocabulary entry for it.
    /// `source` is boxed rather than inline: this variant recurses
    /// (`AcdpError` containing `AcdpError`), and an unboxed recursive
    /// field would make the enum infinite-sized. `Box<AcdpError>` still
    /// gets `Clone` for free from [`AcdpError`]'s own derive (added for
    /// issue #248 Phase 4 — see the enum's doc), which is what lets a
    /// `ProceedWithKnown`-swallowed discovery failure be independently
    /// owned by both `VerifiedContext::revocation_discovery_failure`
    /// and `VerificationReport::revocation_discovery` from one call.
    /// `AcdpError` still has no `PartialEq`.
    #[error("revocation auto-discovery failed: {source}")]
    RevocationDiscoveryFailed {
        /// The underlying error discovery hit — typically a transport
        /// failure from the search or lineage-walk requests
        /// (`AcdpError::KeyResolutionUnreachable`, `AcdpError::Http`,
        /// …) or `AcdpError::SearchTruncated` from exhausting a
        /// discovery safety cap. [`AcdpError::is_transient`] delegates
        /// to this field, so a retry-aware caller still gets a correct
        /// answer through the wrapper.
        source: Box<AcdpError>,
    },

    /// Wire code: `hash_mismatch`. The remote registry rejected a
    /// publish request because its independent hash recomputation did
    /// not match the producer-supplied `content_hash`. Distinct from
    /// the local [`AcdpError::HashMismatch`] variant: this one carries
    /// the registry's message verbatim and indicates a *producer-side*
    /// bug (most often canonicalization divergence — see RFC-ACDP-0001
    /// §5.7 and the `can-001` conformance fixture).
    #[error("registry rejected hash_mismatch: {0}")]
    RemoteHashMismatch(String),

    /// Wire code: `data_ref_hash_mismatch`. A DataRef's fetched or decoded
    /// bytes do not match the producer-declared `data_ref.content_hash`.
    /// The body itself remains cryptographically valid — only the
    /// referenced data has diverged. Distinct from
    /// [`AcdpError::RemoteHashMismatch`] / [`AcdpError::HashMismatch`]
    /// (body-level ProducerContent failure — the whole body is untrusted)
    /// and [`AcdpError::InvalidSignature`] (a key / key-binding problem).
    /// RFC-ACDP-0002 §6.5–6.6, RFC-ACDP-0007 §5.
    #[error("data_ref hash mismatch: {0}")]
    DataRefHashMismatch(String),

    /// Signature verification failed or signature was malformed.
    /// Wire code: `invalid_signature`.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    // ── DID / key resolution ─────────────────────────────────────────────
    /// Wire code: `key_resolution_failed` (HTTP 400).
    #[error("key resolution failed: {0}")]
    KeyResolution(String),

    /// Wire code: `key_resolution_unreachable` (HTTP 502) — transient, may retry.
    #[error("key resolution unreachable (transient): {0}")]
    KeyResolutionUnreachable(String),

    /// Wire code: `key_not_authorized` (HTTP 403).
    #[error("key not authorized: {0}")]
    KeyNotAuthorized(String),

    // ── Input validation ─────────────────────────────────────────────────
    /// Producer body could not be parsed.
    #[error("invalid body: {0}")]
    InvalidBody(String),

    /// A required field was missing.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Schema validation failed (string length, array uniqueness, oneOf, etc).
    /// Wire code: `schema_violation`.
    #[error("schema violation: {0}")]
    SchemaViolation(String),

    /// Wire code: `payload_too_large` — request body exceeds the registry limit.
    #[error("payload too large: {0}")]
    PayloadTooLarge(String),

    /// Wire code: `embedded_too_large` — a single `DataRef.embedded.content`
    /// exceeds the 64 KB cap.
    #[error("embedded data reference too large: {0}")]
    EmbeddedTooLarge(String),

    /// Wire code: `unsupported_algorithm` — the producer used a signature
    /// algorithm the registry does not accept.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Wire code: `unsupported_media_type` — the request carried a body whose
    /// `Content-Type` is outside the registry's accept-set (RFC-ACDP-0007 §4.1,
    /// §5; HTTP 415). Added on the 0.5.0 line.
    ///
    /// Distinct from [`AcdpError::SchemaViolation`] on purpose: the body is
    /// rejected *unparsed*, so no structural claim about it is made. A registry
    /// answering `schema_violation` here would be asserting a validation that
    /// never ran — and that code is pinned to HTTP 400. Registries advertising
    /// `acdp_version` below 0.5.0 MUST NOT emit this code.
    #[error("unsupported media type: {0}")]
    UnsupportedMediaType(String),

    /// Wire code: `not_implemented` — endpoint or feature not supported by
    /// this registry.
    #[error("not implemented: {0}")]
    NotImplemented(String),

    // ── Retrieval / authorization ────────────────────────────────────────
    /// Wire code: `not_found`.
    #[error("not found: {0}")]
    NotFound(String),

    /// Wire code: `not_authorized` — the caller is not permitted to access
    /// this resource.
    #[error("not authorized: {0}")]
    NotAuthorized(String),

    /// Wire code: `rate_limited`.
    #[error("rate limited: {0}")]
    RateLimited(String),

    // ── Pagination ───────────────────────────────────────────────────────
    /// Wire code: `cursor_expired`.
    #[error("search cursor expired")]
    CursorExpired,

    /// Wire code: `invalid_cursor`.
    #[error("invalid cursor: {0}")]
    InvalidCursor(String),

    // ── Publication ──────────────────────────────────────────────────────
    /// Wire code: `superseded_target`. The supersession target was rejected;
    /// the [`SupersessionReason`] disambiguates the cause.
    #[error("superseded target rejected ({reason:?}): {message}")]
    SupersededTarget {
        /// Why the target was rejected.
        reason: SupersessionReason,
        /// Human-readable message from the registry.
        message: String,
    },

    /// Wire code: `duplicate_publish` — an Idempotency-Key replay produced
    /// a different request body than the original.
    #[error("duplicate publish: {0}")]
    DuplicatePublish(String),

    // ── Cross-registry ───────────────────────────────────────────────────
    /// Wire code: `cross_registry_resolution_failed`.
    #[error("cross-registry resolution failed: {0}")]
    CrossRegistryResolutionFailed(String),

    // ── Registry receipts (ACDP 0.2, RFC-ACDP-0010) ─────────────────────
    /// Wire code: `invalid_receipt`. A `registry_receipt` failed
    /// verification: bad signature, a cross-check mismatch (`ctx_id`,
    /// `content_hash`, `key_fingerprint`, serving authority), a
    /// malformed shape, or a receipt required by policy but absent.
    /// Permanent — the receipt will not verify on retry.
    #[error("invalid registry receipt: {0}")]
    InvalidReceipt(String),

    /// Wire code: `invalid_log_proof` (RFC-ACDP-0012 §9, §11 — 0.3.0).
    /// A transparency-log artifact failed verification: an inclusion
    /// proof that does not fold to the checkpoint's root, a failed
    /// consistency proof between tree sizes, or a checkpoint whose
    /// signature does not verify. Permanent — a bad proof will not
    /// verify on retry (HTTP 502 on the wire: the upstream log is at
    /// fault when a federated resolver emits it).
    #[error("invalid transparency-log proof: {0}")]
    InvalidLogProof(String),

    /// Wire code: `invalid_witness_cosignature` (RFC-ACDP-0015 §8,
    /// §10 — 0.4.0). A transparency-log **witness cosignature** failed
    /// the §8 verification procedure: closed parse, the witness-key
    /// signature, witness binding (`signature.key_id` DID ≠
    /// `witness_id`), checkpoint binding (`witnessed_checkpoint` ≠ the
    /// checkpoint being evaluated), or the `witnessed_at` skew check.
    /// Deliberately **distinct** from [`AcdpError::InvalidLogProof`]:
    /// that indicts the *log* (tree membership, history consistency,
    /// the registry's checkpoint signature); this indicts a *witness's*
    /// attestation — an independent verdict over an independent signer
    /// (RFC-ACDP-0015 §10). Permanent — a bad cosignature will not
    /// verify on retry (HTTP 502 on the wire: the cosignature came from
    /// an upstream party — a registry aggregating on a caller's behalf
    /// or a resolver validating a witness's cosignatures). A cosignature
    /// that verifies but is merely *stale* is consumer freshness policy
    /// (§8.1), never this code.
    #[error("invalid witness cosignature: {0}")]
    InvalidWitnessCosignature(String),

    /// Wire code: `immutable_field` (RFC-ACDP-0013 §6, §10 — 0.3.0;
    /// activated from the v0.1.0 reservation). A lifecycle (or future
    /// mutation) endpoint request attempted to supply or alter
    /// immutable body content. Bodies are immutable; lifecycle
    /// endpoints mutate registry state only. Permanent (HTTP 400).
    #[error("immutable field: {0}")]
    ImmutableField(String),

    /// Wire code: `invalid_lifecycle_transition` (RFC-ACDP-0013 §6
    /// step 4, §10 — 0.3.0). The requested lifecycle transition
    /// conflicts with the context's current retraction state (retract
    /// of an already-retracted context; republish of a never-retracted
    /// one). A state conflict like the 409 arm of `superseded_target`;
    /// retryable only after the state changes (HTTP 409).
    #[error("invalid lifecycle transition: {0}")]
    InvalidLifecycleTransition(String),

    // ── Wire / transport ─────────────────────────────────────────────────
    /// Wire code: `internal_error`.
    #[error("registry internal error: {0}")]
    RegistryInternal(String),

    /// Catch-all for `WireError` codes that have no typed variant in this
    /// version of the library. Forward-compatible: registries may emit
    /// reserved codes (`unsupported_embedding_model`)
    /// that future ACDP versions add.
    #[error("registry returned error: {0:?}")]
    Registry(crate::wire_error::WireError),

    /// JSON (de)serialization failed.
    #[error("serialization failed: {0}")]
    Serialization(String),

    /// HTTP transport error.
    #[error("HTTP error: {0}")]
    Http(String),
}

/// Sub-reason for [`AcdpError::SupersededTarget`]. Mirrors the
/// `details.reason` values defined by `acdp-error.schema.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupersessionReason {
    /// The supersedes target context does not exist on this registry.
    NotFound,
    /// The target's lineage_id differs from the new publication's lineage.
    LineageMismatch,
    /// The new version is not exactly `previous.version + 1`.
    VersionMismatch,
    /// The target has already been superseded by a different version.
    AlreadySuperseded,
    /// The target lives on a different registry; v0.1.0 only allows
    /// same-registry supersession.
    CrossRegistrySupersessionUnsupported,
    /// The lineage walk through `supersedes` failed because an
    /// intermediate context could not be retrieved (RFC-ACDP-0001 §5.6.1).
    LineageWalkFailed,
    /// A reason this version of the library does not recognize.
    #[serde(other)]
    Other,
}

impl AcdpError {
    /// Whether this error is plausibly transient and worth retrying
    /// with the same request body (and, if applicable, the same
    /// `Idempotency-Key`).
    ///
    /// Returned by [`AcdpError::is_transient`] only for variants whose
    /// wire codes the spec marks retryable: `key_resolution_unreachable`
    /// (RFC-ACDP-0001 §5.11), `rate_limited` (RFC-ACDP-0008 §4.3),
    /// `cross_registry_resolution_failed` (RFC-ACDP-0006 §7), and
    /// `internal_error` (RFC-ACDP-0007 §5). Generic `Http` transport
    /// errors are conservatively treated as transient since they
    /// usually mean DNS or TCP-level glitches.
    ///
    /// All cryptographic, schema, and authorization errors are NOT
    /// transient: a malformed body or invalid signature will not
    /// magically validate on retry.
    ///
    /// [`AcdpError::RevocationDiscoveryFailed`] is a wrapper, not a
    /// wire code, so it is exempted from the list above and instead
    /// delegates to its own `source` — a retry-aware caller unwrapping
    /// the wrapper still gets the right answer.
    pub fn is_transient(&self) -> bool {
        if let AcdpError::RevocationDiscoveryFailed { source } = self {
            return source.is_transient();
        }
        matches!(
            self,
            AcdpError::KeyResolutionUnreachable(_)
                | AcdpError::RateLimited(_)
                | AcdpError::CrossRegistryResolutionFailed(_)
                | AcdpError::RegistryInternal(_)
                | AcdpError::Http(_)
        )
    }

    /// Map a wire-protocol [`crate::wire_error::WireError`] into a typed
    /// [`AcdpError`].
    ///
    /// Codes the library does not yet recognize are returned as
    /// [`AcdpError::Registry`] for forward compatibility.
    pub fn from_wire_error(wire: crate::wire_error::WireError) -> Self {
        let code = wire.error.code.as_str();
        let msg = wire.error.message.clone();

        match code {
            "invalid_signature" => AcdpError::InvalidSignature(msg),
            "hash_mismatch" => AcdpError::RemoteHashMismatch(msg),
            "data_ref_hash_mismatch" => AcdpError::DataRefHashMismatch(msg),
            "schema_violation" => AcdpError::SchemaViolation(msg),
            "not_authorized" => AcdpError::NotAuthorized(msg),
            "not_found" => AcdpError::NotFound(msg),
            "rate_limited" => AcdpError::RateLimited(msg),
            "payload_too_large" => AcdpError::PayloadTooLarge(msg),
            "embedded_too_large" => AcdpError::EmbeddedTooLarge(msg),
            "key_resolution_failed" => AcdpError::KeyResolution(msg),
            "key_resolution_unreachable" => AcdpError::KeyResolutionUnreachable(msg),
            "key_not_authorized" => AcdpError::KeyNotAuthorized(msg),
            "unsupported_algorithm" => AcdpError::UnsupportedAlgorithm(msg),
            "unsupported_media_type" => AcdpError::UnsupportedMediaType(msg),
            "not_implemented" => AcdpError::NotImplemented(msg),
            "cursor_expired" => AcdpError::CursorExpired,
            "invalid_cursor" => AcdpError::InvalidCursor(msg),
            "duplicate_publish" => AcdpError::DuplicatePublish(msg),
            "cross_registry_resolution_failed" => AcdpError::CrossRegistryResolutionFailed(msg),
            "invalid_receipt" => AcdpError::InvalidReceipt(msg),
            "invalid_log_proof" => AcdpError::InvalidLogProof(msg),
            "invalid_witness_cosignature" => AcdpError::InvalidWitnessCosignature(msg),
            "immutable_field" => AcdpError::ImmutableField(msg),
            "invalid_lifecycle_transition" => AcdpError::InvalidLifecycleTransition(msg),
            "internal_error" => AcdpError::RegistryInternal(msg),
            "superseded_target" => {
                let reason = wire
                    .error
                    .details
                    .as_ref()
                    .and_then(|d| d.get("reason"))
                    .and_then(|v| serde_json::from_value::<SupersessionReason>(v.clone()).ok())
                    .unwrap_or(SupersessionReason::Other);
                AcdpError::SupersededTarget {
                    reason,
                    message: msg,
                }
            }
            // Unknown / future codes pass through as the catch-all variant
            _ => AcdpError::Registry(wire),
        }
    }
}

impl From<serde_json::Error> for AcdpError {
    fn from(e: serde_json::Error) -> Self {
        AcdpError::Serialization(e.to_string())
    }
}

impl From<std::io::Error> for AcdpError {
    fn from(e: std::io::Error) -> Self {
        AcdpError::Http(format!("io error: {e}"))
    }
}

#[cfg(feature = "reqwest")]
impl From<reqwest::Error> for AcdpError {
    fn from(e: reqwest::Error) -> Self {
        if e.is_connect() || e.is_timeout() {
            AcdpError::Http(format!("connection failed: {e}"))
        } else {
            AcdpError::Http(e.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire_error::{WireError, WireErrorBody};
    use serde_json::json;

    fn wire(code: &str, message: &str, details: Option<serde_json::Value>) -> WireError {
        WireError {
            error: WireErrorBody {
                code: code.into(),
                message: message.into(),
                details,
            },
        }
    }

    #[test]
    fn all_26_wire_codes_round_trip() {
        // Test-coverage matrix entry: "All 26 error codes parse from WireError".
        // Every code enumerated by acdp-error.schema.json's enum MUST map to a
        // typed AcdpError variant (or, for `superseded_target` with details,
        // produce the right SupersessionReason).
        type Check = fn(&AcdpError) -> bool;
        let cases: &[(&str, Check)] = &[
            ("invalid_signature", |e| {
                matches!(e, AcdpError::InvalidSignature(_))
            }),
            ("hash_mismatch", |e| {
                matches!(e, AcdpError::RemoteHashMismatch(_))
            }),
            ("data_ref_hash_mismatch", |e| {
                matches!(e, AcdpError::DataRefHashMismatch(_))
            }),
            ("schema_violation", |e| {
                matches!(e, AcdpError::SchemaViolation(_))
            }),
            ("not_authorized", |e| {
                matches!(e, AcdpError::NotAuthorized(_))
            }),
            ("not_found", |e| matches!(e, AcdpError::NotFound(_))),
            ("superseded_target", |e| {
                matches!(e, AcdpError::SupersededTarget { .. })
            }),
            ("unsupported_algorithm", |e| {
                matches!(e, AcdpError::UnsupportedAlgorithm(_))
            }),
            ("rate_limited", |e| matches!(e, AcdpError::RateLimited(_))),
            ("payload_too_large", |e| {
                matches!(e, AcdpError::PayloadTooLarge(_))
            }),
            ("embedded_too_large", |e| {
                matches!(e, AcdpError::EmbeddedTooLarge(_))
            }),
            ("key_resolution_failed", |e| {
                matches!(e, AcdpError::KeyResolution(_))
            }),
            ("key_resolution_unreachable", |e| {
                matches!(e, AcdpError::KeyResolutionUnreachable(_))
            }),
            ("key_not_authorized", |e| {
                matches!(e, AcdpError::KeyNotAuthorized(_))
            }),
            ("not_implemented", |e| {
                matches!(e, AcdpError::NotImplemented(_))
            }),
            ("unsupported_media_type", |e| {
                matches!(e, AcdpError::UnsupportedMediaType(_))
            }),
            ("cursor_expired", |e| matches!(e, AcdpError::CursorExpired)),
            ("invalid_cursor", |e| {
                matches!(e, AcdpError::InvalidCursor(_))
            }),
            ("duplicate_publish", |e| {
                matches!(e, AcdpError::DuplicatePublish(_))
            }),
            ("cross_registry_resolution_failed", |e| {
                matches!(e, AcdpError::CrossRegistryResolutionFailed(_))
            }),
            ("invalid_receipt", |e| {
                matches!(e, AcdpError::InvalidReceipt(_))
            }),
            ("invalid_log_proof", |e| {
                matches!(e, AcdpError::InvalidLogProof(_))
            }),
            ("invalid_witness_cosignature", |e| {
                matches!(e, AcdpError::InvalidWitnessCosignature(_))
            }),
            ("immutable_field", |e| {
                matches!(e, AcdpError::ImmutableField(_))
            }),
            ("invalid_lifecycle_transition", |e| {
                matches!(e, AcdpError::InvalidLifecycleTransition(_))
            }),
            ("internal_error", |e| {
                matches!(e, AcdpError::RegistryInternal(_))
            }),
        ];
        // Schema enumerates exactly 26 codes (RFC-ACDP-0007 §5 + the
        // RFC-ACDP-0010 `invalid_receipt` addition + the 0.3.0 codes:
        // `invalid_log_proof` (RFC-0012), `immutable_field` and
        // `invalid_lifecycle_transition` (RFC-0013) + the 0.4.0 code
        // `invalid_witness_cosignature` (RFC-0015) + the 0.5.0 code
        // `unsupported_media_type` (RFC-0007 §4.1, spec #68)).
        //
        // This count is hand-maintained and therefore only catches a code this
        // repo forgot to *add*. The forcing function that catches the spec
        // growing underneath us is `wire_error_codes_cover_the_spec_enum` in
        // `tests/conformance.rs`, which reads the enum out of
        // `acdp-error.schema.json` itself.
        assert_eq!(cases.len(), 26);
        for (code, expected) in cases {
            let err = AcdpError::from_wire_error(wire(code, "msg", None));
            assert!(
                expected(&err),
                "code '{code}' did not map to its typed variant: got {err:?}"
            );
        }
    }

    #[test]
    fn superseded_target_with_reason_details() {
        let w = wire(
            "superseded_target",
            "lineage mismatch",
            Some(json!({"reason": "lineage_mismatch"})),
        );
        match AcdpError::from_wire_error(w) {
            AcdpError::SupersededTarget { reason, .. } => {
                assert_eq!(reason, SupersessionReason::LineageMismatch);
            }
            other => panic!("expected SupersededTarget, got {other:?}"),
        }
    }

    #[test]
    fn superseded_target_without_details_falls_back_to_other() {
        let w = wire("superseded_target", "?", None);
        match AcdpError::from_wire_error(w) {
            AcdpError::SupersededTarget { reason, .. } => {
                assert_eq!(reason, SupersessionReason::Other);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn unknown_code_passes_through_as_registry() {
        let w = wire("unsupported_embedding_model", "reserved future code", None);
        assert!(matches!(
            AcdpError::from_wire_error(w),
            AcdpError::Registry(_)
        ));
    }

    /// T4 — `lineage_walk_failed` reason round-trips via WireError
    /// (RFC-ACDP-0001 §5.6.1).
    #[test]
    fn lineage_walk_failed_reason_roundtrip() {
        let w = wire(
            "superseded_target",
            "intermediate not retrievable",
            Some(json!({
                "reason": "lineage_walk_failed",
                "unreachable_ctx_id":
                    "acdp://r.example.com/12345678-1234-4321-8123-123456781234"
            })),
        );
        match AcdpError::from_wire_error(w) {
            AcdpError::SupersededTarget { reason, .. } => {
                assert_eq!(reason, SupersessionReason::LineageWalkFailed);
            }
            other => panic!("got {other:?}"),
        }
    }

    /// `is_transient` covers the wire codes the spec marks retryable.
    #[test]
    fn is_transient_for_known_retryables() {
        assert!(AcdpError::KeyResolutionUnreachable("x".into()).is_transient());
        assert!(AcdpError::RateLimited("x".into()).is_transient());
        assert!(AcdpError::CrossRegistryResolutionFailed("x".into()).is_transient());
        assert!(AcdpError::RegistryInternal("x".into()).is_transient());
        assert!(AcdpError::Http("x".into()).is_transient());
        assert!(!AcdpError::SchemaViolation("x".into()).is_transient());
        assert!(!AcdpError::InvalidSignature("x".into()).is_transient());
        assert!(!AcdpError::NotFound("x".into()).is_transient());
        // BUG-02: data-ref hash mismatch is a data-integrity failure;
        // retrying the SAME publish/fetch will return the same answer.
        // The spec marks it permanent, not retryable.
        assert!(!AcdpError::DataRefHashMismatch("x".into()).is_transient());
        // RFC-ACDP-0010: a failed receipt will not verify on retry.
        assert!(!AcdpError::InvalidReceipt("x".into()).is_transient());
        assert!(!AcdpError::InvalidLogProof("x".into()).is_transient());
        // RFC-ACDP-0015: a bad witness cosignature will not verify on retry.
        assert!(!AcdpError::InvalidWitnessCosignature("x".into()).is_transient());
        // RFC-ACDP-0007 §4.1: retrying with the same Content-Type gets the
        // same 415. The fix is a different request, not a later one.
        assert!(!AcdpError::UnsupportedMediaType("x".into()).is_transient());
        assert!(!AcdpError::ImmutableField("x".into()).is_transient());
        assert!(!AcdpError::InvalidLifecycleTransition("x".into()).is_transient());
        // Issue #189: context substitution is locally detected and permanent;
        // retrying against the same misbehaving registry will not fix it.
        assert!(!AcdpError::ContextIdMismatch {
            requested: "a".into(),
            served: "b".into(),
        }
        .is_transient());
        // Issue #226 Phase 3: an incomplete/mismatched lineage is a
        // locally-detected consumer-side binding failure, not a
        // transport hiccup — retrying will not change what the
        // registry serves for the same lineage_id.
        assert!(!AcdpError::IncompleteLineage {
            lineage_id: "lin:sha256:aa".into(),
            ctx_id: Some("acdp://r.example.com/x".into()),
        }
        .is_transient());
        // Issue #226 Phase 4: exhausting the search-page or lineage-walk
        // safety cap is a client-local safety-limit signal, not a
        // transport hiccup — retrying the identical query reproduces the
        // same truncation.
        assert!(!AcdpError::SearchTruncated("x".into()).is_transient());
        // Issue #258: exhausting a caller-configured discovery request/byte
        // budget is a client-local safety-limit signal, like
        // `SearchTruncated` above — never transient, and deliberately NOT
        // added to the `matches!` list in `is_transient`.
        assert!(!AcdpError::RevocationDiscoveryBudgetExceeded("x".into()).is_transient());
    }
}
