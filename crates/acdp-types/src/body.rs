use crate::anchor::AnchorEntry;
use crate::data_ref::DataRef;
use crate::serde_helpers::de_present;
use acdp_primitives::error::AcdpError;
use acdp_primitives::primitives::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Body ─────────────────────────────────────────────────────────────────────

/// The immutable stored body of an ACDP context (RFC-ACDP-0002).
///
/// Contains producer-controlled fields (covered by the producer signature)
/// plus registry-assigned identity fields (`ctx_id`, `lineage_id`,
/// `origin_registry`, `created_at`) which rely on registry honesty in v0.1.0.
///
/// The hash/signature preimage is ProducerContent: the Body with
/// `content_hash`, `signature`, and the registry-assigned identity fields
/// removed.  See RFC-ACDP-0001 §5.7.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Body {
    // ── Registry-assigned identity fields (NOT in ProducerContent) ──────
    pub ctx_id: CtxId,
    pub lineage_id: LineageId,
    pub origin_registry: String,
    #[serde(with = "acdp_primitives::time::canonical_rfc3339")]
    pub created_at: DateTime<Utc>,

    // ── Integrity fields (NOT in ProducerContent) ────────────────────────
    pub content_hash: ContentHash,
    pub signature: Signature,

    // ── Producer-controlled required fields ──────────────────────────────
    pub version: u32,
    pub supersedes: Option<CtxId>,
    pub agent_id: AgentDid,
    pub contributors: Vec<AgentDid>,
    pub title: String,
    #[serde(rename = "type")]
    pub context_type: ContextType,
    pub data_refs: Vec<DataRef>,
    pub derived_from: Vec<CtxId>,
    pub visibility: Visibility,

    // ── Producer-controlled optional fields ──────────────────────────────
    //
    // Optional bare-typed fields use the absent-vs-null convention
    // (RFC-ACDP-0005 §2.2.1, schema-005/006/007): an absent key is
    // tolerated, a present-but-`null` key is rejected at deserialize.
    // [`crate::serde_helpers::de_present`] implements this.
    // `supersedes` is the one v0.1.0 field whose schema is
    // `["string","null"]` (RFC-ACDP-0002 §3.1) — it is legitimately
    // nullable and intentionally NOT routed through `de_present`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Vec<AgentDid>>,
    #[serde(
        default,
        deserialize_with = "de_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub acdp_version: Option<String>,
    #[serde(
        default,
        deserialize_with = "de_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    /// Producer-supplied summary for search results (≤ 1000 chars).
    /// Part of ProducerContent — included in the content_hash preimage.
    #[serde(
        default,
        deserialize_with = "de_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub summary: Option<String>,
    #[serde(
        default,
        deserialize_with = "de_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub tags: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "de_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub domain: Option<String>,
    /// Canonical emission (RFC-ACDP-0001 §5.3): a whole-second instant
    /// serializes as `…:SS.000Z`, never chrono's default `…:SSZ`.
    #[serde(
        default,
        with = "acdp_primitives::time::canonical_rfc3339_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_period: Option<DataPeriod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(
        default,
        deserialize_with = "de_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub schema_uri: Option<String>,
    /// Typed, content-addressed references to external (non-ACDP)
    /// artifacts this body genesis-links to (RFC-ACDP-0016, 0.5.0).
    /// Absent-when-empty: a producer with no anchors MUST omit this
    /// field entirely, never send `[]` — enforced at runtime by
    /// `acdp-validation`, not by this type (an empty `Some(vec![])` is
    /// representable so validation can reject it with a clear error
    /// rather than the type silently normalizing it away).
    #[serde(
        default,
        deserialize_with = "de_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub anchors: Option<Vec<AnchorEntry>>,

    /// Forward-compatible carry-through of unknown producer-controlled
    /// fields (e.g. v0.1's `priority`). Including these in the typed
    /// model is required for `serde_json::to_value(body)` → JCS → SHA-256
    /// to reproduce the original `content_hash`. Without `flatten`, a
    /// v0.1.0 consumer reading a v0.1 body would silently drop the new
    /// field and compute a different hash, falsely rejecting the body.
    #[serde(flatten)]
    pub extensions: serde_json::Map<String, serde_json::Value>,
}

impl Body {
    /// Materialize the stored [`Body`] from a **validated**
    /// [`PublishRequest`](crate::publish::PublishRequest) plus the four
    /// registry-assigned identity fields (RFC-ACDP-0003 §2.1 step 8;
    /// the RFC-ACDP-0001 §5.7 exclusion set).
    ///
    /// This is the single `PublishRequest → Body` materialization point.
    /// Store backends MUST use it instead of hand-copying fields: three
    /// independent copies existed before this constructor (the
    /// in-memory store plus both SQL backends), and a producer field
    /// added to `PublishRequest` but missed in one copy is a silent
    /// data-loss bug that changes the recomputed `content_hash` of the
    /// stored body. The field-transfer guard test at
    /// `tests/body_materialization.rs` fails if a new `PublishRequest`
    /// field is not mapped here.
    ///
    /// `created_at` is millisecond-truncated internally (RFC-ACDP-0001
    /// §5.3) — callers may pass an untruncated `now`.
    ///
    /// The caller is responsible for having validated the request
    /// (schema, hash recomputation, signature) and for deriving
    /// `ctx_id` / `lineage_id` per RFC-ACDP-0003; this constructor only
    /// transfers fields.
    pub fn from_publish_request(
        req: &crate::publish::PublishRequest,
        ctx_id: CtxId,
        lineage_id: LineageId,
        origin_registry: impl Into<String>,
        created_at: DateTime<Utc>,
    ) -> Self {
        Body {
            // Registry-assigned (the §5.7 exclusion set, minus the two
            // integrity fields echoed from the request below).
            ctx_id,
            lineage_id,
            origin_registry: origin_registry.into(),
            created_at: acdp_primitives::time::trunc_ms(created_at),
            // Integrity fields — echoed verbatim from the validated
            // request.
            content_hash: req.content_hash.clone(),
            signature: req.signature.clone(),
            // Producer-controlled content — copied verbatim, one line
            // per field so a missed mapping is visible in review and
            // caught by the guard test.
            version: req.version,
            supersedes: req.supersedes.clone(),
            agent_id: req.agent_id.clone(),
            contributors: req.contributors.clone(),
            title: req.title.clone(),
            context_type: req.context_type.clone(),
            data_refs: req.data_refs.clone(),
            derived_from: req.derived_from.clone(),
            visibility: req.visibility.clone(),
            audience: req.audience.clone(),
            acdp_version: req.acdp_version.clone(),
            description: req.description.clone(),
            summary: req.summary.clone(),
            tags: req.tags.clone(),
            domain: req.domain.clone(),
            expires_at: req.expires_at,
            data_period: req.data_period.clone(),
            metadata: req.metadata.clone(),
            schema_uri: req.schema_uri.clone(),
            anchors: req.anchors.clone(),
            // The publish schema is CLOSED (deny_unknown_fields), so a
            // fresh body starts with no extension fields.
            extensions: Default::default(),
        }
    }
}

/// Time window the underlying data covers.
///
/// Per `acdp-common.schema.json#/$defs/data_period`, both `start` and `end`
/// are required (additionalProperties: false). The schema does not compare
/// timestamps; producers SHOULD ensure `start <= end` and registries
/// SHOULD reject `start > end` as `schema_violation` at runtime.
///
/// `data_period` is a CLOSED two-field wire shape and part of
/// ProducerContent — an unknown field would silently change the
/// `content_hash` preimage, so `deny_unknown_fields` rejects it
/// (RFC-ACDP-0007 §3.3.1, conformance fixture schema-009).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataPeriod {
    /// Inclusive start of the data period.
    #[serde(with = "acdp_primitives::time::canonical_rfc3339")]
    pub start: DateTime<Utc>,
    /// Inclusive end of the data period.
    #[serde(with = "acdp_primitives::time::canonical_rfc3339")]
    pub end: DateTime<Utc>,
}

/// Detached Ed25519 signature over the body's `content_hash` field value.
///
/// The `value` bytes are a signature over the ASCII bytes of the full
/// `content_hash` string (e.g. `"sha256:5f8d…"`) — NOT the raw 32-byte
/// digest.  See RFC-ACDP-0001 §5.8.
///
/// The `signature` object is a CLOSED wire shape — exactly `algorithm`,
/// `key_id`, `value` (`additionalProperties: false`). Future signature
/// variants (proof chains, threshold attestations) require an explicit
/// schema bump, not field-level extensibility, so `deny_unknown_fields`
/// rejects an unknown field (RFC-ACDP-0007 §3.3.1, fixture schema-008).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    /// Algorithm identifier.  Only `"ed25519"` is required in v0.1.0.
    pub algorithm: String,
    /// DID URL identifying the signing key (e.g. `did:web:…#key-1`).
    pub key_id: String,
    /// Standard base64-encoded signature bytes.
    pub value: String,
}

// ── Registry state ────────────────────────────────────────────────────────────

/// Mutable, registry-derived state returned alongside the Body on retrieval.
///
/// v0.1.0 contained only `status`; ACDP 0.3 adds the typed
/// [`lifecycle_events`](Self::lifecycle_events) array (RFC-ACDP-0013,
/// promoting the RFC-ACDP-0009 §2.1 reservation). Registry state is
/// NEVER part of any hash or signature preimage — typing a formerly
/// opaque member is safe — but individual lifecycle events carry their
/// own signatures, so the event OBJECT parse is closed while unknown
/// `event_type` VALUES are tolerated (RFC-ACDP-0013 §7.3). Other
/// unknown fields are preserved verbatim in [`Self::extensions`] so
/// consumers can surface them to operators (RFC-ACDP-0004 §3
/// forward-compat) and re-serialize the state unchanged.
///
/// # Reserved extension field names (RFC-ACDP-0009 §2.1)
///
/// The following keys remain reserved for future RFCs. Until the
/// relevant RFC ships normative text, consumers see them in
/// [`Self::extensions`] (the `#[serde(flatten)]` map below).
///
/// | Name              | RFC                           | Purpose                                                       |
/// |-------------------|-------------------------------|---------------------------------------------------------------|
/// | `relationships`   | RFC-ACDP-0009 §2.1 (reserved) | Post-publication `builds_on` / `disputes` etc.                 |
/// | `attestations`    | RFC-ACDP-0009 §2.1 (reserved) | Third-party `reproduced` / `audit` markers.                    |
/// | `subscriptions`   | RFC-ACDP-0009 §2.1 (reserved) | Push-subscription receipts.                                    |
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryState {
    pub status: Status,
    /// Append-only lifecycle event history (RFC-ACDP-0013 §4.1): events
    /// in registry-accepted order; never removed, reordered, or
    /// mutated. Omitted entirely (never `[]`) when no events exist, per
    /// the absent-vs-null wire convention (RFC-ACDP-0005 §2.2.1).
    /// Emitted only by registries advertising `acdp-registry-lifecycle`.
    ///
    /// The typed parse preserves round-trip fidelity: every event field
    /// re-serializes byte-identically (strict canonical `occurred_at`,
    /// verbatim unknown `event_type` values), so persisted registry
    /// state — and the signed bytes inside each event — survive a parse
    /// → re-serialize cycle unchanged. An event violating the closed
    /// object schema is malformed registry state and fails the parse
    /// (RFC-ACDP-0013 §7.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_events: Option<Vec<crate::lifecycle::LifecycleEvent>>,
    /// Registry-signed acceptance receipts parallel to
    /// [`Self::lifecycle_events`] (RFC-ACDP-0017 §10.2): element *i*
    /// receipts event *i*. Omitted entirely (never `[]`) when there are
    /// none. Each element is parsed with the closed
    /// [`EventReceipt::from_value`](crate::EventReceipt::from_value), so
    /// a receipt violating its schema is malformed registry state and
    /// fails the parse, as a malformed lifecycle event does. A receipt
    /// that parses but fails verification is the verifier's business
    /// (RFC-ACDP-0017 §10.3: treated as absent).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de_event_receipts"
    )]
    pub event_receipts: Option<Vec<crate::EventReceipt>>,
    /// Forward-compatible passthrough for fields added in future versions
    /// (e.g. the reserved `relationships`, `attestations`,
    /// `subscriptions` — see the type docs for the reserved set).
    #[serde(flatten)]
    pub extensions: serde_json::Map<String, serde_json::Value>,
}

impl RegistryState {
    /// Retraction as a consumer can know it (RFC-ACDP-0013 §4.1, §7.1):
    /// `Some(true)` retracted, `Some(false)` not retracted, `None`
    /// unknown.
    ///
    /// A registry advertising `acdp-registry-lifecycle` MUST omit
    /// `lifecycle_events` when there are none, so for such a registry an
    /// absent member means no events: not retracted. Only a registry
    /// that does not advertise lifecycle leaves the state unknown.
    pub fn retraction(&self, registry_advertises_lifecycle: bool) -> Option<bool> {
        if self.status.is_retracted() {
            return Some(true);
        }
        match &self.lifecycle_events {
            Some(_) => Some(self.is_retracted()),
            None if registry_advertises_lifecycle => Some(false),
            None => None,
        }
    }

    /// The context's **retraction state** (RFC-ACDP-0013 §7.1), derived
    /// from [`Self::lifecycle_events`]: retracted iff the last
    /// `retracted`/`republished` event in array order is `retracted`.
    /// Unknown event types have no effect (§7.3).
    pub fn is_retracted(&self) -> bool {
        self.lifecycle_events
            .as_deref()
            .is_some_and(crate::lifecycle::retraction_state)
    }
}

/// `registry_state.event_receipts`: present means a non-null array, each
/// element parsed with the closed [`crate::EventReceipt::from_value`].
fn de_event_receipts<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Vec<crate::EventReceipt>>, D::Error> {
    let items = Vec::<serde_json::Value>::deserialize(d)?;
    items
        .iter()
        .map(crate::EventReceipt::from_value)
        .collect::<Result<Vec<_>, AcdpError>>()
        .map(Some)
        .map_err(serde::de::Error::custom)
}

// ── Full retrieval envelope ───────────────────────────────────────────────────

/// The full context object returned by `GET /contexts/{ctx_id}`.
///
/// `acdp-context.schema.json` is `additionalProperties: true`: future
/// ACDP versions may add top-level keys without a schema bump, and
/// v0.1.0 consumers MUST tolerate unknown top-level keys. `body`,
/// `registry_state`, and the reserved `registry_receipt` are modelled
/// explicitly; any other top-level field is preserved verbatim in
/// [`Self::extensions`]. These top-level fields are NOT part of
/// `ProducerContent`, so unlike [`Body::extensions`] this carry-through
/// is a forward-compatibility contract, not a hash-stability one.
///
/// **Raw body retention (RFC-ACDP-0001 §5.7 "Hash verification over raw
/// JSON").** Deserializing a `FullContext` also keeps the `body` object
/// exactly as received in [`Self::raw_body`], so verifiers recompute
/// `content_hash` over the producer's bytes rather than over a typed
/// re-serialization (which can respell a valid timestamp — `can-013`).
#[derive(Debug, Clone, Serialize)]
pub struct FullContext {
    /// Producer-signed body.
    pub body: Body,
    /// Mutable registry-derived state (status etc).
    pub registry_state: RegistryState,
    /// Optional registry receipt — reserved for RFC-ACDP-0009 §2.7. Opaque
    /// to the library; preserved verbatim if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_receipt: Option<serde_json::Value>,
    /// Optional lineage-head receipt (ACDP 0.3, RFC-ACDP-0011): the
    /// registry's signed serve-time attestation of the current head of
    /// the lineage. REQUIRED on `GET /lineages/{id}/current` responses
    /// from registries advertising `acdp-registry-head-receipts`; MAY
    /// appear on full retrieval; tolerated (and preserved verbatim)
    /// when absent — non-advertising registries never emit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lineage_head_receipt: Option<serde_json::Value>,
    /// Optional transparency-log inclusion proof (ACDP 0.3,
    /// RFC-ACDP-0012 §10): the RFC 6962 audit path plus signed
    /// checkpoint proving this context is committed by the registry's
    /// append-only log. MAY be carried on full retrieval by registries
    /// advertising `acdp-registry-transparency-log`; never on the
    /// body-only endpoint and never on the publish response. A
    /// top-level **sibling** of `registry_receipt` — deliberately NOT a
    /// member of it (the receipt is closed, fully signed, and
    /// byte-immutable). Parse with
    /// [`crate::log::LogInclusion::from_value`]; verify per
    /// RFC-ACDP-0012 §9 — the log verdict is independent of the body
    /// and receipt verdicts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_inclusion: Option<serde_json::Value>,

    /// Unknown top-level context fields, preserved per
    /// `acdp-context.schema.json` `additionalProperties: true`. Retained
    /// for forward compatibility with future ACDP versions that add
    /// top-level registry fields.
    #[serde(flatten)]
    pub extensions: serde_json::Map<String, serde_json::Value>,

    /// The `body` object exactly as received on the wire — populated by
    /// `Deserialize`, `None` for a hand-built context. Never serialized
    /// (the typed [`Self::body`] is). Verifiers hash this when it still
    /// describes [`Self::body`] (see `acdp_verify::verify_context_hash`);
    /// a caller that mutates `body` after parsing gets the typed path,
    /// so the mutation is detected, not masked.
    #[serde(skip)]
    pub raw_body: Option<serde_json::Value>,
}

impl<'de> Deserialize<'de> for FullContext {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            body: serde_json::Value,
            registry_state: RegistryState,
            #[serde(default)]
            registry_receipt: Option<serde_json::Value>,
            #[serde(default)]
            lineage_head_receipt: Option<serde_json::Value>,
            #[serde(default)]
            log_inclusion: Option<serde_json::Value>,
            #[serde(flatten)]
            extensions: serde_json::Map<String, serde_json::Value>,
        }
        let w = Wire::deserialize(d)?;
        let body = Body::deserialize(&w.body)
            .map_err(|e| serde::de::Error::custom(format!("body: {e}")))?;
        Ok(FullContext {
            body,
            registry_state: w.registry_state,
            registry_receipt: w.registry_receipt,
            lineage_head_receipt: w.lineage_head_receipt,
            log_inclusion: w.log_inclusion,
            extensions: w.extensions,
            raw_body: Some(w.body),
        })
    }
}
